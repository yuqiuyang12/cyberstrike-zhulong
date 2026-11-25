package loop2

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/summarization"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// 摘要模型偶发返回「HTTP 200 + 空正文」响应（供应商侧 content_filter 命中、
// 仅输出 tool_calls 无文本、或网关静默截断）。Eino 原生 summarization 的
// Retry.ShouldRetry 只检查 error，对「成功但内容为空」不重试，随后
// DefaultFinalize -> postProcessSummary 直接抛出
// "summary content is empty" 并使整个用户回合硬失败（dh 项目 2026-09-24 故障）。
//
// 本文件在 Finalize 层兜底：
//  1. 先判定摘要是否真的无可用文本；
//  2. 用同一摘要模型补发若干次（携带强约束指令、适度退避）；
//  3. 仍失败则生成宿主侧确定性占位摘要（保留系统消息 + 最近轨迹 + transcript 路径），
//     绝不把空摘要错误冒泡成整回合失败。

const (
	emptySummaryFallbackMaxRetries = 3
	emptySummaryFallbackMinChars   = 24
)

var summarizationTagOnlyRegex = regexp.MustCompile(`(?is)</?(?:analysis|summary)[^>]*>`)

// emptySummaryRepromptInstruction 追加在补发请求末尾的强约束指令。
const emptySummaryRepromptInstruction = `【系统提醒：上一次回复正文为空】
你上一条响应没有任何可用于压缩历史的纯文本内容（可能被安全过滤或仅输出了结构化字段）。
请立即重新完成摘要任务：禁止调用任何工具，直接输出 <analysis> 与 <summary> 纯文本块，
即使内容敏感也必须以中立、描述性语言概括；不得输出空消息、不得只输出工具调用。`

// summaryMessageHasUsableContent 判断模型返回的摘要消息是否含可用文本。
// 与 summarization.getAssistantTextContent 口径一致：assistant 角色的多模态文本块或 Content。
func summaryMessageHasUsableContent(msg adk.Message) bool {
	if msg == nil {
		return false
	}
	var text string
	if msg.Role == schema.Assistant {
		var parts []string
		for _, part := range msg.AssistantGenMultiContent {
			if part.Type == schema.ChatMessagePartTypeText && strings.TrimSpace(part.Text) != "" {
				parts = append(parts, part.Text)
			}
		}
		text = strings.Join(parts, "\n")
	}
	if strings.TrimSpace(text) == "" {
		text = msg.Content
	}
	if len([]rune(strings.TrimSpace(text))) < emptySummaryFallbackMinChars {
		return false
	}
	// 纯标签/空白（如只有 <summary></summary>）视为不可用。
	stripped := strings.TrimSpace(summarizationTagOnlyRegex.ReplaceAllString(text, ""))
	return stripped != ""
}

// regenerateEmptySummary 在原输入基础上补发摘要 Generate，直到拿到可用文本或次数用尽。
// rebuildInput 由调用方闭包提供（复用本次 GenModelInput 的预算/transcript 逻辑），
// 因为 Eino 不导出 ctxKeyModelInput，Finalize 无法从 ctx 取回原始输入。
func regenerateEmptySummary(
	ctx context.Context,
	chatModel model.BaseChatModel,
	rebuildInput func() ([]adk.Message, error),
	opts []model.Option,
) (adk.Message, bool) {
	if chatModel == nil || rebuildInput == nil {
		return nil, false
	}
	base, err := rebuildInput()
	if err != nil || len(base) == 0 {
		return nil, false
	}
	input := append([]adk.Message(nil), base...)
	// 追加强约束提醒（作为最后一条 user 消息）。
	input = append(input, schema.UserMessage(emptySummaryRepromptInstruction))

	for attempt := 1; attempt <= emptySummaryFallbackMaxRetries; attempt++ {
		resp, gerr := chatModel.Generate(ctx, input, opts...)
		if gerr == nil && resp != nil && summaryMessageHasUsableContent(resp) {
			return resp, true
		}
		// 退避后再试；取消则立即放弃。
		if attempt < emptySummaryFallbackMaxRetries {
			backoff := einoTransientRetryBackoff(attempt-1, defaultEinoRunRetryMaxBackoff)
			select {
			case <-ctx.Done():
				return nil, false
			case <-time.After(backoff):
			}
		}
	}
	return nil, false
}

// summarizationInstructions 构造摘要请求的 system/user 指令消息（classic 路径）。
func summarizationInstructions(userInstruction string) (adk.Message, adk.Message) {
	return schema.SystemMessage(summarizationSystemInstruction()),
		schema.UserMessage(userInstruction)
}

// summarizationSystemInstruction 与 Eino summarization 内部默认中文系统指令
// （getSystemInstruction）逐字对齐，保证补发输入与首轮请求结构一致。
func summarizationSystemInstruction() string {
	return `你是一个负责总结对话的 AI 助手。`
}

// finalizeWithHostFallbackSummary 使用宿主兜底摘要走完与正常路径等价的 Finalize 后处理：
// 保留最近 assistant/tool 轨迹、合并用户意图账本、刷新黑板索引。
func finalizeWithHostFallbackSummary(
	ctx context.Context,
	compactionMessages []adk.Message,
	fallbackSummary adk.Message,
	tokenCounter summarization.TokenCounterFunc,
	recentTrailMax int,
	originalMessages []adk.Message,
	userLedgerMaxRunes, userLedgerEntryMaxRunes int,
	db *database.DB,
	projectID string,
	appCfg *config.Config,
	logger *zap.Logger,
) ([]adk.Message, error) {
	out, ferr := summarizeFinalizeWithRecentAssistantToolTrail(
		ctx, compactionMessages, fallbackSummary, tokenCounter, recentTrailMax)
	if ferr != nil {
		return nil, ferr
	}
	userLedger := buildOriginalUserIntentLedgerMessage(originalMessages, userLedgerMaxRunes, userLedgerEntryMaxRunes)
	out = mergeMessageIntoLeadingSystem(out, userLedger)
	if appCfg != nil {
		out = refreshFactIndexInMessages(out, db, projectID, appCfg.Project, logger)
	}
	return out, nil
}

// regenerateAgenticEmptySummary 是 agentic（AgenticMessage）路径的空摘要补发。
func regenerateAgenticEmptySummary(
	ctx context.Context,
	chatModel model.BaseModel[*schema.AgenticMessage],
	rebuildInput func() ([]*schema.AgenticMessage, error),
) (*schema.AgenticMessage, bool) {
	if chatModel == nil || rebuildInput == nil {
		return nil, false
	}
	base, err := rebuildInput()
	if err != nil || len(base) == 0 {
		return nil, false
	}
	input := append([]*schema.AgenticMessage(nil), base...)
	input = append(input, &schema.AgenticMessage{
		Role: schema.AgenticRoleTypeUser,
		ContentBlocks: []*schema.ContentBlock{
			{UserInputText: &schema.UserInputText{Text: emptySummaryRepromptInstruction}},
		},
	})

	for attempt := 1; attempt <= emptySummaryFallbackMaxRetries; attempt++ {
		resp, gerr := chatModel.Generate(ctx, input)
		classic := agenticSummaryToClassicMessage(resp)
		if gerr == nil && classic != nil && summaryMessageHasUsableContent(classic) {
			return resp, true
		}
		if attempt < emptySummaryFallbackMaxRetries {
			backoff := einoTransientRetryBackoff(attempt-1, defaultEinoRunRetryMaxBackoff)
			select {
			case <-ctx.Done():
				return nil, false
			case <-time.After(backoff):
			}
		}
	}
	return nil, false
}

// buildHostFallbackSummaryMessage 构造宿主侧确定性摘要消息（user 角色），
// 内容不依赖模型：显式标注压缩未成功、指向 transcript、并提示继续任务。
func buildHostFallbackSummaryMessage(transcriptPath string) adk.Message {
	var b strings.Builder
	b.WriteString("【上下文压缩未完成 · 宿主兜底】\n")
	b.WriteString("摘要模型本次未返回可用文本，系统保留此占位以保证任务不中断。\n")
	b.WriteString("继续作业时请遵循：1) 以系统提示中的授权范围与约束为准；")
	b.WriteString("2) 参考下方最近工具/对话轨迹恢复进度；3) 不要重复已完成的步骤。")
	if p := strings.TrimSpace(transcriptPath); p != "" {
		b.WriteString(fmt.Sprintf("\n\n压缩前完整对话记录位于：%s（可用 read_file 读取后再继续）", p))
	}
	return schema.UserMessage(b.String())
}
