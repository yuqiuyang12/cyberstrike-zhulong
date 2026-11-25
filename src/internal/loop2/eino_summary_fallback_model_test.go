package loop2

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// failingSummaryModel 模拟通道不稳定：Generate 直接返回 EOF（与 tokenrhythm.studio 现场一致）。
type failingSummaryModel struct {
	calls int
}

func (f *failingSummaryModel) Generate(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	f.calls++
	return nil, errors.New(`failed to create chat completion: Post "https://tokenrhythm.studio/v1/chat/completions": EOF`)
}

func (f *failingSummaryModel) Stream(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	f.calls++
	return nil, errors.New("failed to receive stream chunk: unexpected EOF")
}

// TestSummaryFallbackModelDegrades 摘要模型失败时必须降级为宿主兜底摘要，不得把错误冒泡成整轮失败。
func TestSummaryFallbackModelDegrades(t *testing.T) {
	inner := &failingSummaryModel{}
	wrapped := newSummaryFallbackModel(inner, "/tmp/transcript.txt", "conv-test", nil)
	if wrapped == nil {
		t.Fatal("wrapper is nil")
	}
	msg, err := wrapped.Generate(context.Background(), []*schema.Message{schema.UserMessage("compress this")})
	if err != nil {
		t.Fatalf("Generate must not surface summarization error, got %v", err)
	}
	if msg == nil || !strings.Contains(msg.Content, "宿主兜底") {
		t.Fatalf("fallback message content unexpected: %+v", msg)
	}
	if inner.calls != 1 {
		t.Fatalf("inner model calls = %d, want 1", inner.calls)
	}
	// 冷却窗口内不应再打上游模型（失败调用本身也要耗时）。
	if _, err := wrapped.Generate(context.Background(), []*schema.Message{schema.UserMessage("compress again")}); err != nil {
		t.Fatalf("second Generate error: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("cooldown not applied: inner calls = %d, want 1", inner.calls)
	}
}

// TestSummaryFallbackModelCancelPropagates 用户取消必须原样上抛，不能被兜底吞掉。
func TestSummaryFallbackModelCancelPropagates(t *testing.T) {
	inner := &failingSummaryModel{}
	wrapped := newSummaryFallbackModel(inner, "", "conv-test", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := wrapped.Generate(ctx, []*schema.Message{schema.UserMessage("x")}); err == nil {
		t.Fatal("canceled context must return error")
	}
}

// TestSummaryErrorNotTransient 摘要失败不得被判为 transient（否则整轮重启 → 死循环）。
func TestSummaryErrorNotTransient(t *testing.T) {
	summaryErr := errors.New(`[NodeRunError] failed to generate summary: exceeds max retries: ` +
		`failed to create chat completion: Post "https://tokenrhythm.studio/v1/chat/completions": EOF`)
	if isEinoTransientRunError(summaryErr) {
		t.Fatal("summarization failure must not be treated as transient run error")
	}
	// 普通网络抖动仍要可重试。
	networkErr := errors.New(`Post "https://api.example.com/v1/chat/completions": EOF`)
	if !isEinoTransientRunError(networkErr) {
		t.Fatal("plain EOF should stay retryable")
	}
}

// TestRestartTotalBudget 单轮重启总预算必须生效（attempts 会被 ConfirmRecovery 清零）。
func TestRestartTotalBudget(t *testing.T) {
	policy := einoTransientRunRetryPolicy{maxAttempts: 2, maxBackoff: time.Millisecond, maxTotalAttempts: 3}
	r := newEinoTransientRunRetrier(policy)
	runErr := errors.New(`Post "https://api.example.com/v1/chat/completions": EOF`)
	args := &einoADKRunLoopArgs{}
	restarts := 0
	var fatal error
	for i := 0; i < 20; i++ {
		restarted, _, _, _, err := r.tryRetry(context.Background(), runErr, args, nil, nil, 0)
		if err != nil {
			fatal = err
			break
		}
		if restarted {
			restarts++
			r.reset() // 模拟 ConfirmRecovery：单次计数清零，但总预算不清零
		}
	}
	if fatal == nil {
		t.Fatalf("restart budget not enforced: restarts=%d", restarts)
	}
	if !strings.Contains(fatal.Error(), "重启") {
		t.Fatalf("fatal message not user-readable: %v", fatal)
	}
	if restarts != policy.maxTotalAttempts {
		t.Fatalf("restarts = %d, want %d", restarts, policy.maxTotalAttempts)
	}
}

var _ adk.Message = (*schema.Message)(nil)

// healthySummaryModel 模拟通道正常：应当原样返回模型结果，不被兜底替换。
type healthySummaryModel struct {
	calls int
}

func (h *healthySummaryModel) Generate(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	h.calls++
	return &schema.Message{Role: schema.Assistant, Content: "<summary>正常压缩结果</summary>"}, nil
}

func (h *healthySummaryModel) Stream(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return schema.StreamReaderFromArray([]*schema.Message{{Role: schema.Assistant, Content: "ok"}}), nil
}

// TestSummaryFallbackModelPassthrough 通道正常时必须透传，不得改写真实摘要（防回归）。
func TestSummaryFallbackModelPassthrough(t *testing.T) {
	inner := &healthySummaryModel{}
	wrapped := newSummaryFallbackModel(inner, "", "conv-test", nil)
	msg, err := wrapped.Generate(context.Background(), []*schema.Message{schema.UserMessage("compress")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg == nil || !strings.Contains(msg.Content, "正常压缩结果") {
		t.Fatalf("passthrough broken: %+v", msg)
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d, want 1", inner.calls)
	}
}
