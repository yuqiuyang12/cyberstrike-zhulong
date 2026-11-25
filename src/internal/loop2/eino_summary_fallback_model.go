package loop2

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// [2026-11-01] 摘要模型兜底包装（根因修复）。
//
// 背景：摘要（上下文压缩）调用与主模型共用通道。当通道返回 EOF/超时/限流时，
// 摘要错误会被上抛成 [NodeRunError]，再被判为 transient → 整条 ADK Run 重启；
// 重启后上下文未被压缩，立刻又越过 trigger → 再摘要 → 再失败，形成单轮无上限的死循环
// （实测单会话 466 次 eino_run_retry，72%~86% 的墙钟时间耗在此处）。
//
// 修复原则：摘要只是“尽力而为”的优化，失败绝不能连累整轮任务。
// 因此在本层截断错误，返回宿主确定性兜底摘要（指向 transcript 文件），让压缩流程正常收尾。
// 用户取消 / deadline 仍按原语义上抛，不吞掉中断信号。

const summaryFallbackTranscriptHint = "eino summarization model 调用失败，已降级为宿主兜底摘要"

// summaryFallbackCooldown：一次失败后在该窗口内直接走兜底，不再重投模型。
// 目的：失败调用本身也要耗时（实测单次 EOF 数秒~数十秒），
// 压缩收尾阶段的"空摘要补发"会再打 3 次，无冷却会把卡顿放大数倍。
const summaryFallbackCooldown = 90 * time.Second

// inCooldown 报告是否处于失败冷却窗口。
func summaryFallbackInCooldown(lastFailUnixNano int64) bool {
	if lastFailUnixNano <= 0 {
		return false
	}
	return time.Since(time.Unix(0, lastFailUnixNano)) < summaryFallbackCooldown
}

// summaryFallbackModel 包装经典的 *schema.Message 摘要模型。
type summaryFallbackModel struct {
	inner          model.BaseModel[*schema.Message]
	transcriptPath string
	conversationID string
	logger         *zap.Logger
	fallbacks      atomic.Int64
	lastFailAt     atomic.Int64
	memo           *schema.Message
}

func newSummaryFallbackModel(
	inner model.BaseModel[*schema.Message],
	transcriptPath, conversationID string,
	logger *zap.Logger,
) model.BaseModel[*schema.Message] {
	if inner == nil {
		return nil
	}
	return &summaryFallbackModel{
		inner:          inner,
		transcriptPath: transcriptPath,
		conversationID: conversationID,
		logger:         logger,
	}
}

func (m *summaryFallbackModel) fallbackMessage() *schema.Message {
	if m.memo != nil {
		return m.memo
	}
	m.memo = buildHostFallbackSummaryMessage(m.transcriptPath)
	return m.memo
}

func (m *summaryFallbackModel) logFallback(err error) {
	n := m.fallbacks.Add(1)
	if m.logger != nil {
		m.logger.Warn(summaryFallbackTranscriptHint,
			zap.Error(err),
			zap.String("conversation_id", m.conversationID),
			zap.Int64("fallback_count", n),
			zap.String("transcript_file", m.transcriptPath),
		)
	}
}

func (m *summaryFallbackModel) Generate(
	ctx context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.Message, error) {
	if summaryFallbackInCooldown(m.lastFailAt.Load()) {
		return m.fallbackMessage(), nil
	}
	out, err := m.inner.Generate(ctx, input, opts...)
	if err == nil && out != nil {
		return out, nil
	}
	if ctx.Err() != nil {
		// 用户取消 / 整任务 deadline：保持原语义，由上层收尾。
		return nil, err
	}
	m.lastFailAt.Store(time.Now().UnixNano())
	m.logFallback(err)
	return m.fallbackMessage(), nil
}

func (m *summaryFallbackModel) Stream(
	ctx context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	sr, err := m.inner.Stream(ctx, input, opts...)
	if err == nil && sr != nil {
		return sr, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	m.logFallback(err)
	return schema.StreamReaderFromArray([]*schema.Message{m.fallbackMessage()}), nil
}

// summaryFallbackAgenticModel 包装 AgenticMessage 版本摘要模型（eino_single / deep / supervisor 主路径）。
type summaryFallbackAgenticModel struct {
	inner          model.BaseModel[*schema.AgenticMessage]
	transcriptPath string
	conversationID string
	logger         *zap.Logger
	fallbacks      atomic.Int64
	lastFailAt     atomic.Int64
	memo           *schema.AgenticMessage
}

func newSummaryFallbackAgenticModel(
	inner model.BaseModel[*schema.AgenticMessage],
	transcriptPath, conversationID string,
	logger *zap.Logger,
) model.BaseModel[*schema.AgenticMessage] {
	if inner == nil {
		return nil
	}
	return &summaryFallbackAgenticModel{
		inner:          inner,
		transcriptPath: transcriptPath,
		conversationID: conversationID,
		logger:         logger,
	}
}

func (m *summaryFallbackAgenticModel) fallbackMessage() *schema.AgenticMessage {
	if m.memo != nil {
		return m.memo
	}
	classic := buildHostFallbackSummaryMessage(m.transcriptPath)
	converted := EinoMessagesToAgentic([]*schema.Message{classic})
	if len(converted) > 0 {
		m.memo = converted[0]
		return m.memo
	}
	m.memo = &schema.AgenticMessage{
		Role: schema.AgenticRoleTypeUser,
		ContentBlocks: []*schema.ContentBlock{
			{UserInputText: &schema.UserInputText{Text: classic.Content}},
		},
	}
	return m.memo
}

func (m *summaryFallbackAgenticModel) logFallback(err error) {
	n := m.fallbacks.Add(1)
	if m.logger != nil {
		m.logger.Warn(summaryFallbackTranscriptHint,
			zap.Error(err),
			zap.String("conversation_id", m.conversationID),
			zap.Int64("fallback_count", n),
			zap.String("transcript_file", m.transcriptPath),
		)
	}
}

func (m *summaryFallbackAgenticModel) Generate(
	ctx context.Context,
	input []*schema.AgenticMessage,
	opts ...model.Option,
) (*schema.AgenticMessage, error) {
	if summaryFallbackInCooldown(m.lastFailAt.Load()) {
		return m.fallbackMessage(), nil
	}
	out, err := m.inner.Generate(ctx, input, opts...)
	if err == nil && out != nil {
		return out, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	m.lastFailAt.Store(time.Now().UnixNano())
	m.logFallback(err)
	return m.fallbackMessage(), nil
}

func (m *summaryFallbackAgenticModel) Stream(
	ctx context.Context,
	input []*schema.AgenticMessage,
	opts ...model.Option,
) (*schema.StreamReader[*schema.AgenticMessage], error) {
	sr, err := m.inner.Stream(ctx, input, opts...)
	if err == nil && sr != nil {
		return sr, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	m.logFallback(err)
	return schema.StreamReaderFromArray([]*schema.AgenticMessage{m.fallbackMessage()}), nil
}
