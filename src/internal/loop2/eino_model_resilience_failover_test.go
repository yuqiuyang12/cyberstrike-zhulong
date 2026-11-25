package loop2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// ---------------------------------------------------------------------------
// 测试替身
// ---------------------------------------------------------------------------

// fakeAgenticModel 模拟一个通道上的 Agentic 模型：首个调用返回预设错误，之后成功。
type fakeAgenticModel struct {
	modelTag string
	err      error
	calls    *int
}

func (m *fakeAgenticModel) Generate(_ context.Context, _ []*schema.AgenticMessage, _ ...model.Option) (*schema.AgenticMessage, error) {
	if m.calls != nil {
		*m.calls++
	}
	if m.err != nil {
		return nil, m.err
	}
	return &schema.AgenticMessage{ContentBlocks: []*schema.ContentBlock{{AssistantGenText: &schema.AssistantGenText{Text: m.modelTag}}}}, nil
}

func (m *fakeAgenticModel) Stream(_ context.Context, _ []*schema.AgenticMessage, _ ...model.Option) (*schema.StreamReader[*schema.AgenticMessage], error) {
	if m.err != nil {
		return nil, m.err
	}
	return schema.StreamReaderFromArray([]*schema.AgenticMessage{{ContentBlocks: []*schema.ContentBlock{{AssistantGenText: &schema.AssistantGenText{Text: m.modelTag}}}}}), nil
}

// fakeChatModel 模拟 planner 用的 ToolCallingChatModel。
type fakeChatModel struct {
	modelTag string
	err      error
	calls    *int
}

func (m *fakeChatModel) Generate(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	if m.calls != nil {
		*m.calls++
	}
	if m.err != nil {
		return nil, m.err
	}
	return schema.AssistantMessage(m.modelTag, nil), nil
}

func (m *fakeChatModel) Stream(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	if m.err != nil {
		return nil, m.err
	}
	return schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage(m.modelTag, nil)}), nil
}

func (m *fakeChatModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

// unreachableErr 复刻会话 6d915e54 11:28 的真实错误形态（阿里云通道 dial 无路由）。
func unreachableErr() error {
	return errors.New(`Post "https://ws-8rp8nl0oj8qry7up.cn-beijing.maas.aliyuncs.com/compatible-mode/v1/chat/completions": dial tcp 47.98.1.1:443: connect: no route to host`)
}

// failoverTestConfig 复刻生产通道布局：
//   - default      = deepseek（api.deepseek.com）
//   - default-2/-5 = 阿里云 MaaS 两个 workspace（同供应商！）
//
// 基线主通道取 default-2（= 会话 6d915e54 11:28 报 "no route to host" 的那条），
// 备用里才有跨供应商的 default。
func failoverTestConfig() *config.Config {
	cfg := &config.Config{
		AI: config.AIConfig{
			DefaultChannel: "default-2",
			Channels: map[string]config.AIChannelConfig{
				"default": {
					Provider: "openai_compatible", APIKey: "k-primary",
					BaseURL: "https://api.deepseek.com", Model: "deepseek-flash",
				},
				"default-2": {
					Provider: "openai_compatible", APIKey: "k-aliyun-a",
					BaseURL: "https://ws-8rp8nl0oj8qry7up.cn-beijing.maas.aliyuncs.com/compatible-mode/v1", Model: "qwen-max",
				},
				"default-5": {
					Provider: "openai_compatible", APIKey: "k-aliyun-b",
					BaseURL: "https://ws-mkpetz30kb4s6m57.cn-beijing.maas.aliyuncs.com/compatible-mode/v1", Model: "qwen-plus",
				},
			},
		},
	}
	cfg.OpenAI = cfg.AI.Channels[cfg.AI.DefaultChannel].ToOpenAIConfig()
	return cfg
}

func failoverMiddleware(channels ...string) *config.MultiAgentEinoMiddlewareConfig {
	return &config.MultiAgentEinoMiddlewareConfig{ModelFailoverChannels: channels}
}

type capturedEvent struct {
	eventType string
	message   string
	data      map[string]interface{}
}

func eventCollector() (func(string, string, interface{}), *[]capturedEvent) {
	events := &[]capturedEvent{}
	fn := func(eventType, message string, data interface{}) {
		payload, _ := data.(map[string]interface{})
		*events = append(*events, capturedEvent{eventType: eventType, message: message, data: payload})
	}
	return fn, events
}

func findEvents(events []capturedEvent, eventType string) []capturedEvent {
	out := make([]capturedEvent, 0, len(events))
	for _, e := range events {
		if e.eventType == eventType {
			out = append(out, e)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// ① 审计：供应方归一 / 假冗余 / 顺序
// ---------------------------------------------------------------------------

func TestEinoModelVendorNormalization(t *testing.T) {
	t.Parallel()
	cases := []struct {
		baseURL string
		want    string
	}{
		{"https://api.deepseek.com", "deepseek"},
		{"https://api.deepseek.com/v1", "deepseek"},
		{"https://ws-8rp8nl0oj8qry7up.cn-beijing.maas.aliyuncs.com/compatible-mode/v1", "aliyun"},
		{"https://dashscope.aliyuncs.com/compatible-mode/v1", "aliyun"},
		{"https://api.anthropic.com", "anthropic"},
		{"https://api.moonshot.cn/v1", "moonshot"},
		{"https://open.bigmodel.cn/api/paas/v4", "zhipu"},
		{"https://ark.cn-beijing.volces.com/api/v3", "volcengine"},
		{"https://api.example.com/v1", "example.com"}, // 兜底：域名后两段
		{"http://127.0.0.1:8080/v1", "local"},
		{"", "unknown:chan-x"},
	}
	for _, tc := range cases {
		if got := einoModelVendor(tc.baseURL, "chan-x"); got != tc.want {
			t.Errorf("einoModelVendor(%q) = %q, want %q", tc.baseURL, got, tc.want)
		}
	}
}

// 生产配置里 default-2 / default-5 同为阿里云（假冗余）：必须被识别为同 vendor，
// 且跨供应商的候选要排在前面。
func TestResolveEinoFailoverChannelsDetectsDegradedRedundancy(t *testing.T) {
	t.Parallel()
	appCfg := failoverTestConfig()
	// 场景一：主 = 阿里云(default-2)，备用只剩同供应商的 default-5 → 假冗余(degraded)
	resolved := resolveEinoFailoverChannels(appCfg, failoverMiddleware("default-2", "default-5"))
	if len(resolved) != 1 {
		t.Fatalf("resolved = %d, want 1（跳过与主通道同端点的 default-2）", len(resolved))
	}
	// 两个备用都是阿里云 workspace → 同供应商，应判 degraded（真·假冗余）
	ordered := orderEinoFailoverCandidates(resolved)
	for _, ch := range ordered {
		if ch.crossVendor {
			t.Fatalf("同为阿里云 workspace 不应判为跨供应商: %+v", ch)
		}
	}
	tr := newEinoModelFailoverTracker("multiagent", "deep", "conv-1", appCfg.OpenAI)
	tr.describeCandidates(ordered)
	snap := tr.Snapshot()
	if !snap.Degraded || snap.CrossVendorAvailable {
		t.Fatalf("同供应商候选应判 degraded: %+v", snap)
	}

	// 场景二：主 = 阿里云，备用含 deepseek → 跨供应商可用，且跨供应商排第一
	appCfg2 := failoverTestConfig()
	resolved2 := resolveEinoFailoverChannels(appCfg2, failoverMiddleware("default-2", "default-5", "default"))
	if len(resolved2) != 2 {
		t.Fatalf("resolved2 = %d, want 2", len(resolved2))
	}
	ordered2 := orderEinoFailoverCandidates(resolved2)
	if ordered2[0].id != "default" || !ordered2[0].crossVendor {
		t.Fatalf("跨供应商候选应排第一，实际 %+v", ordered2)
	}
	tr2 := newEinoModelFailoverTracker("multiagent", "deep", "conv-1", appCfg2.OpenAI)
	tr2.describeCandidates(ordered2)
	if snap2 := tr2.Snapshot(); snap2.Degraded || !snap2.CrossVendorAvailable {
		t.Fatalf("有跨供应商候选时不应判 degraded: %+v", snap2)
	}
}

func TestResolveEinoFailoverChannelsSkipsHalfConfigured(t *testing.T) {
	t.Parallel()
	appCfg := failoverTestConfig()
	appCfg.AI.Channels["broken"] = config.AIChannelConfig{Provider: "openai_compatible", APIKey: "k", BaseURL: "", Model: "x"}
	appCfg.AI.Channels["nomodel"] = config.AIChannelConfig{Provider: "openai_compatible", APIKey: "k", BaseURL: "https://api.other.com", Model: ""}
	resolved := resolveEinoFailoverChannels(appCfg, failoverMiddleware("broken", "nomodel", "default"))
	if len(resolved) != 1 || resolved[0].id != "default" {
		t.Fatalf("半配置通道应被跳过: %+v", resolved)
	}
}

// model_failover_max_retries = 0 的语义：用满全部候选（不是"不切"）。
func TestFailoverMaxRetriesZeroMeansAllCandidates(t *testing.T) {
	t.Parallel()
	channels := make([]resolvedEinoFailoverChannel, 0, 3)
	for i := 0; i < 3; i++ {
		channels = append(channels, resolvedEinoFailoverChannel{id: fmt.Sprintf("c%d", i)})
	}
	if got := capEinoFailoverChannels(channels, &config.MultiAgentEinoMiddlewareConfig{ModelFailoverMaxRetries: 0}); len(got) != 3 {
		t.Fatalf("0 应表示用满全部候选，实际 %d", len(got))
	}
	if got := capEinoFailoverChannels(channels, &config.MultiAgentEinoMiddlewareConfig{ModelFailoverMaxRetries: 1}); len(got) != 1 {
		t.Fatalf("上限 1 应只留 1 个，实际 %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// ② 硬不可达判据 + 重试/切换联动
// ---------------------------------------------------------------------------

func TestIsEinoHardUnreachableError(t *testing.T) {
	t.Parallel()
	hard := []error{
		unreachableErr(),
		errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
		errors.New("dial tcp: lookup api.example.com: no such host"),
		errors.New("read tcp 10.1.1.1:443: i/o timeout"),
		errors.New("net/http: TLS handshake timeout"),
		&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("network is unreachable")},
	}
	for _, err := range hard {
		if !isEinoHardUnreachableError(err) {
			t.Errorf("应判硬不可达: %v", err)
		}
	}
	soft := []error{
		errors.New("upstream returned 503: service unavailable"),
		errors.New("too many requests"),
		errors.New("invalid api key"),
		context.Canceled,
		context.DeadlineExceeded,
		&adk.RetryExhaustedError{LastErr: errors.New("dial tcp 1.2.3.4:443: connect: no route to host"), TotalRetries: 4},
	}
	if isEinoHardUnreachableError(soft[5]) != true {
		t.Errorf("RetryExhaustedError 应被解包后判定为硬不可达")
	}
	for _, err := range soft[:5] {
		if isEinoHardUnreachableError(err) {
			t.Errorf("不应判硬不可达: %v", err)
		}
	}
}

// 有 failover 时：硬不可达不烧重试（直接交给切换）；429/5xx 仍照旧重试。
func TestRetryConfigSkipsRetriesWhenFailoverActive(t *testing.T) {
	t.Parallel()
	mw := failoverMiddleware("default-2")
	retryWith := newEinoAgenticModelRetryConfigWithFailover(mw, nil, "test", true)
	retryWithout := newEinoAgenticModelRetryConfigWithFailover(mw, nil, "test", false)

	ctx := context.Background()
	unreachable := &adk.TypedRetryContext[*schema.AgenticMessage]{RetryAttempt: 1, Err: unreachableErr()}
	if d := retryWith.ShouldRetry(ctx, unreachable); d.Retry {
		t.Fatalf("有 failover 时硬不可达应放弃原地重试，实际 %+v", d)
	}
	if d := retryWithout.ShouldRetry(ctx, unreachable); !d.Retry {
		t.Fatalf("无 failover 时硬不可达应沿用旧重试行为（否则单通道场景失去韧性）")
	}

	transient := &adk.TypedRetryContext[*schema.AgenticMessage]{RetryAttempt: 1, Err: errors.New("upstream returned 503")}
	if d := retryWith.ShouldRetry(ctx, transient); !d.Retry {
		t.Fatalf("503 仍应重试（同通道通常能恢复）")
	}
	if d := retryWith.ShouldRetry(ctx, &adk.TypedRetryContext[*schema.AgenticMessage]{RetryAttempt: 1, Err: errors.New("invalid api key")}); d.Retry {
		t.Fatalf("鉴权错误不应重试")
	}
}

// ---------------------------------------------------------------------------
// ③ 四模式：主通道不可达 → 切到备用 + 事件发出（每模式至少 1 条）
// ---------------------------------------------------------------------------

// modeFailoverCase 描述一个编排模式下 runner 实际使用的 failover 装配方式。
var modeFailoverCases = []struct {
	mode string
	// planner 模式下还要额外验证 planner ChatModel 包壳（plan_execute 专用）
	checkPlanner bool
}{
	{mode: "eino_single"},
	{mode: "deep"},
	{mode: "supervisor"},
	{mode: "plan_execute", checkPlanner: true},
}

func TestFailoverSwitchesToCrossVendorBackupPerMode(t *testing.T) {
	for _, tc := range modeFailoverCases {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			appCfg := failoverTestConfig()
			progress, events := eventCollector()

			// 备用通道模型：alibaba 系的会失败，deepseek 的成功（模拟"阿里云整体不可达"）。
			var builtChannels []string
			factory := func(_ context.Context, oa config.OpenAIConfig, _ einoModelMode) (model.AgenticModel, error) {
				builtChannels = append(builtChannels, oa.Model)
				if strings.Contains(oa.BaseURL, "aliyuncs.com") {
					return &fakeAgenticModel{modelTag: oa.Model, err: unreachableErr()}, nil
				}
				return &fakeAgenticModel{modelTag: oa.Model}, nil
			}

			// 与 runner 完全一致的装配顺序：failover → retry(failoverActive)
			cfg, tracker, err := newEinoAgenticModelFailoverConfigWithTracker(
				context.Background(), appCfg, failoverMiddleware("default-2", "default-5", "default"),
				einoModelModeNormal, factory, nil, tc.mode, progress, tc.mode, "conv-"+tc.mode,
			)
			if err != nil {
				t.Fatalf("build failover: %v", err)
			}
			if cfg == nil || tracker == nil {
				t.Fatalf("%s 模式未挂 failover", tc.mode)
			}
			if cfg.MaxRetries < 2 {
				t.Fatalf("%s 模式 failover 次数 = %d, want >=2", tc.mode, cfg.MaxRetries)
			}
			retry := newEinoAgenticModelRetryConfigWithFailover(failoverMiddleware("default-2", "default-5", "default"), nil, tc.mode, cfg != nil)
			if d := retry.ShouldRetry(context.Background(), &adk.TypedRetryContext[*schema.AgenticMessage]{RetryAttempt: 1, Err: unreachableErr()}); d.Retry {
				t.Fatalf("%s: 硬不可达不应原地重试", tc.mode)
			}
			if !cfg.ShouldFailover(context.Background(), nil, unreachableErr()) {
				t.Fatalf("%s: 硬不可达应触发 failover", tc.mode)
			}

			// 逐次 failover：第一次 attempt 应命中跨供应商的 default（deepseek）
			attempt := uint(1)
			var modelBase model.BaseModel[*schema.AgenticMessage]
			for attempt <= cfg.MaxRetries {
				modelBase, _, err = cfg.GetFailoverModel(context.Background(), &adk.FailoverContext[*schema.AgenticMessage]{
					FailoverAttempt: attempt,
					LastErr:         unreachableErr(),
				})
				if err != nil {
					t.Fatalf("%s: attempt %d GetFailoverModel: %v", tc.mode, attempt, err)
				}
				if modelBase == nil {
					t.Fatalf("%s: attempt %d 返回空模型", tc.mode, attempt)
				}
				if builtChannels[len(builtChannels)-1] == "deepseek-flash" {
					break // 已切到跨供应商通道
				}
				attempt++
			}
			if builtChannels[len(builtChannels)-1] != "deepseek-flash" {
				t.Fatalf("%s: 未切到跨供应商通道，实际顺序 %v", tc.mode, builtChannels)
			}

			// 备用通道调用成功 → tracker 应记为该通道为最终通道
			out, callErr := modelBase.Generate(context.Background(), nil)
			if callErr != nil || out == nil {
				t.Fatalf("%s: 备用通道调用失败: %v", tc.mode, callErr)
			}
			tracker.EmitFinal(progress, "completed")

			switchEvents := findEvents(*events, "eino_model_failover")
			if len(switchEvents) == 0 {
				t.Fatalf("%s: 未发出 eino_model_failover 事件", tc.mode)
			}
			first := switchEvents[0].data
			required := []string{"conversationId", "runId", "fromChannel", "fromVendor", "toChannel", "toVendor", "provider", "reason", "attempt"}
			for _, key := range required {
				if v, ok := first[key]; !ok || strings.TrimSpace(fmt.Sprint(v)) == "" {
					t.Errorf("%s: 切换事件缺字段 %q (payload=%v)", tc.mode, key, first)
				}
			}
			if first["conversationId"] != "conv-"+tc.mode {
				t.Errorf("%s: conversationId = %v", tc.mode, first["conversationId"])
			}
			if first["crossVendor"] != true {
				t.Errorf("%s: 应标记跨供应商切换, payload=%v", tc.mode, first)
			}
			if first["toVendor"] != "deepseek" {
				t.Errorf("%s: toVendor = %v, want deepseek", tc.mode, first["toVendor"])
			}
			if !strings.Contains(fmt.Sprint(first["reason"]), "no route to host") {
				t.Errorf("%s: reason 应包含真实错误摘要, got %v", tc.mode, first["reason"])
			}

			finalEvents := findEvents(*events, "eino_model_channel_final")
			if len(finalEvents) != 1 {
				t.Fatalf("%s: 应发 1 条 eino_model_channel_final，实际 %d", tc.mode, len(finalEvents))
			}
			final := finalEvents[0].data
			if final["finalChannel"] != "default" || final["finalVendor"] != "deepseek" {
				t.Errorf("%s: 最终通道错误 payload=%v", tc.mode, final)
			}
			if final["outcome"] != "completed" || final["switched"] != true {
				t.Errorf("%s: 收尾字段错误 payload=%v", tc.mode, final)
			}
			if final["runId"] == nil || final["runId"] != first["runId"] {
				t.Errorf("%s: 切换事件与收尾事件的 runId 必须一致", tc.mode)
			}
		})
	}
}

// plan_execute 的 planner/replanner 走自建包壳（planexecute 不支持 adk failover）。
func TestPlannerFailoverChatModelSwitchesAndSticks(t *testing.T) {
	t.Parallel()
	appCfg := failoverTestConfig()
	progress, events := eventCollector()

	primaryCalls, aliyunCalls, deepseekCalls := 0, 0, 0
	primary := &fakeChatModel{modelTag: "qwen-max", err: unreachableErr(), calls: &primaryCalls}
	factory := func(_ context.Context, oa config.OpenAIConfig, _ einoModelMode) (model.ToolCallingChatModel, error) {
		if strings.Contains(oa.BaseURL, "aliyuncs.com") {
			return &fakeChatModel{modelTag: oa.Model, err: unreachableErr(), calls: &aliyunCalls}, nil
		}
		return &fakeChatModel{modelTag: oa.Model, calls: &deepseekCalls}, nil
	}

	wrapped, tracker := newEinoPlannerFailoverChatModel(primary, appCfg, failoverMiddleware("default-2", "default-5", "default"), factory, nil, progress, "plan_execute_planner", "plan_execute", "conv-planner")
	if wrapped == nil || tracker == nil {
		t.Fatalf("planner 包壳未生效")
	}

	out, err := wrapped.Generate(context.Background(), []*schema.Message{schema.UserMessage("plan")})
	if err != nil {
		t.Fatalf("planner 切换后应成功: %v", err)
	}
	if out == nil || out.Content != "deepseek-flash" {
		t.Fatalf("应由跨供应商备用通道完成，实际 %+v", out)
	}
	if primaryCalls != 1 || deepseekCalls != 1 {
		t.Fatalf("调用次数 primary=%d deepseek=%d", primaryCalls, deepseekCalls)
	}
	if len(findEvents(*events, "eino_model_failover")) == 0 {
		t.Fatalf("planner 切换未发事件")
	}

	// 粘性：第二次调用应直接走已成功的备用通道（不再拨号已判死的 primary）
	if _, err := wrapped.Generate(context.Background(), []*schema.Message{schema.UserMessage("next step")}); err != nil {
		t.Fatalf("第二次调用失败: %v", err)
	}
	if primaryCalls != 1 {
		t.Fatalf("粘性失效：primary 又被拨号 %d 次", primaryCalls)
	}
	if deepseekCalls != 2 {
		t.Fatalf("deepseek 通道调用次数 = %d, want 2", deepseekCalls)
	}
	tracker.EmitFinal(progress, "completed")
	final := findEvents(*events, "eino_model_channel_final")
	if len(final) != 1 || final[0].data["finalVendor"] != "deepseek" {
		t.Fatalf("planner 收尾事件错误: %+v", final)
	}
}

// 无备用通道时：行为完全不变（返回原模型、无 tracker、不发事件）。
func TestPlannerFailoverNoChannelsKeepsOriginal(t *testing.T) {
	t.Parallel()
	appCfg := failoverTestConfig()
	primary := &fakeChatModel{modelTag: "deepseek-flash"}
	progress, events := eventCollector()
	wrapped, tracker := newEinoPlannerFailoverChatModel(primary, appCfg, failoverMiddleware(), func(_ context.Context, oa config.OpenAIConfig, _ einoModelMode) (model.ToolCallingChatModel, error) {
		return &fakeChatModel{modelTag: oa.Model}, nil
	}, nil, progress, "plan_execute_planner", "plan_execute", "conv-none")
	if wrapped != primary {
		t.Fatalf("无候选通道时必须原样返回 primary")
	}
	if tracker != nil {
		t.Fatalf("无候选通道时不应产生 tracker")
	}
	if len(*events) != 0 {
		t.Fatalf("无候选通道时不应发事件: %+v", *events)
	}
}

// 兜底：ShouldFailover 对"无路由"这类硬不可达必须为 true（即使 transient 标记表漏词）。
func TestShouldFailoverCoversHardUnreachable(t *testing.T) {
	t.Parallel()
	appCfg := failoverTestConfig()
	cfg, _, err := newEinoAgenticModelFailoverConfigWithTracker(
		context.Background(), appCfg, failoverMiddleware("default"),
		einoModelModeNormal,
		func(_ context.Context, oa config.OpenAIConfig, _ einoModelMode) (model.AgenticModel, error) {
			return &fakeAgenticModel{modelTag: oa.Model}, nil
		},
		nil, "deep", nil, "deep", "conv-hard",
	)
	if err != nil || cfg == nil {
		t.Fatalf("build failover: cfg=%v err=%v", cfg, err)
	}
	if !cfg.ShouldFailover(context.Background(), nil, errors.New("connect: no route to host")) {
		t.Fatal("no route to host 必须触发 failover")
	}
	if cfg.ShouldFailover(context.Background(), nil, errors.New("invalid api key")) {
		t.Fatal("鉴权错误不应触发 failover")
	}
	if cfg.ShouldFailover(context.Background(), nil, context.Canceled) {
		t.Fatal("用户取消不应触发 failover")
	}
}

// 生产配置实测口径（2026-10-22）：ai.default_channel=default(deepseek)、
// model_failover_channels=[default, default-2, default-5]，其中 default-2/-5 同为阿里云。
// 结论：主通道为 deepseek 时**没有任何跨供应商备份**（degraded=true）；
// 主通道为阿里云时 deepseek 才是唯一跨供应商备份（crossVendorAvailable=true）。
func TestProductionChannelLayoutResolution(t *testing.T) {
	t.Parallel()

	// 场景 A：主 = default(deepseek) → 候选 [default-2, default-5]（都是阿里云）
	cfgA := failoverTestConfig()
	cfgA.AI.DefaultChannel = "default"
	cfgA.OpenAI = cfgA.AI.Channels["default"].ToOpenAIConfig()
	resolvedA := orderEinoFailoverCandidates(resolveEinoFailoverChannels(cfgA, failoverMiddleware("default", "default-2", "default-5")))
	if len(resolvedA) != 2 {
		t.Fatalf("场景A 候选数 = %d, want 2", len(resolvedA))
	}
	trA := newEinoModelFailoverTracker("multiagent", "deep", "conv-prod-a", cfgA.OpenAI)
	trA.describeCandidates(resolvedA)
	snapA := trA.Snapshot()
	// 候选只有阿里云一家（两个 workspace）= 假冗余：阿里云整体不可达时无路可走。
	if !snapA.Degraded || snapA.Vendors != 1 {
		t.Fatalf("主=deepseek 时备用只有阿里云一家，应判 degraded(vendors=1): %+v", snapA)
	}
	if !snapA.CrossVendorAvailable {
		t.Fatalf("候选与主通道不同供应商，crossVendorAvailable 应为 true: %+v", snapA)
	}

	// 场景 B：主 = default-2(阿里云) → 候选 [default(deepseek) 跨供应商优先, default-5(阿里云)]
	cfgB := failoverTestConfig()
	resolvedB := orderEinoFailoverCandidates(resolveEinoFailoverChannels(cfgB, failoverMiddleware("default", "default-2", "default-5")))
	if len(resolvedB) != 2 {
		t.Fatalf("场景B 候选数 = %d, want 2", len(resolvedB))
	}
	if resolvedB[0].id != "default" || !resolvedB[0].crossVendor {
		t.Fatalf("场景B 跨供应商候选应排第一: %+v", resolvedB)
	}
	trB := newEinoModelFailoverTracker("multiagent", "deep", "conv-prod-b", cfgB.OpenAI)
	trB.describeCandidates(resolvedB)
	snapB := trB.Snapshot()
	if snapB.Degraded || !snapB.CrossVendorAvailable {
		t.Fatalf("主=阿里云 时 deepseek 可作跨供应商备份: %+v", snapB)
	}
}
