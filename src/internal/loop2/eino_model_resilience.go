package loop2

import (
	"context"
	"cyberstrike-ai/internal/netx"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/llm"
	"cyberstrike-ai/internal/openai"
	"cyberstrike-ai/internal/reasoning"

	agenticopenai "github.com/cloudwego/eino-ext/components/model/agenticopenai"
	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// 本文件是四模式（eino_single / deep / supervisor / plan_execute）共用的模型层韧性设施：
//  1. 原生重试（ModelRetryConfig）：429/5xx/网络抖动重试，**硬不可达不再烧重试**；
//  2. 通道路由（ModelFailoverConfig）：一个通道彻底不可达时切到**跨供应商**的备用通道；
//  3. 切换 provenance（einoModelFailoverTracker）：每次切换记录 from/to/vendor/原因/runId/会话，
//     并在轮次结束时回答"本轮最终由哪个通道完成"（复用既有 progress/process_details 通道，不新增表）。
//
// 审计要点（2026-10-22，实证见报告）：
//   - 本平台所有通道的 `provider` 都是协议名（openai_compatible），**不能**当供应方判据；
//     真正的供应方来自 base_url 域名（api.deepseek.com→deepseek，*.aliyuncs.com→aliyun）。
//   - 因此"跨供应商切换"按 vendor 归一（见 einoModelVendor），并把跨 vendor 的候选排在前面；
//     多个同 vendor 通道（如两个阿里云 workspace）保留但降序，避免"假冗余"占满尝试位。

type einoModelMode string

const (
	einoModelModeNormal  einoModelMode = "normal"
	einoModelModePlanner einoModelMode = "planner"
)

type einoModelFactory func(ctx context.Context, oa config.OpenAIConfig, mode einoModelMode) (model.ToolCallingChatModel, error)
type einoAgenticModelConfigFactory func(ctx context.Context, oa config.OpenAIConfig, mode einoModelMode) (model.AgenticModel, error)

// newEinoBaseHTTPClient 构造平台调用模型 API 的 HTTP 客户端。
//
// [2026-10-29 修订] 原值为 Timeout 30min / DialContext 300s / ResponseHeaderTimeout 60min。
// 问题(2026-10-29 19:1x 实测): 宿主机切换网络出口导致 vmnat 静默挂死,旧连接不被 RST,
// 这些超时里最长的一个要 30 分钟才生效,期间 agent 表现为"卡住不动"(实测卡 9 分 24 秒)。
// 现改为: 建连 10s / 首字节 120s / 整体 600s。
// 长任务(深度推理、大输出流式)应由调用方用 context.WithTimeout 显式给更长 deadline,
// 不在此抬高全局默认值。
// 回滚: cp -p ~/data/backup/eino_model_resilience.go-<TS>.bak <本文件> 后重新编译。
func newEinoBaseHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 600 * time.Second,
		Transport: &http.Transport{
			// 只把模型域名交给宿主机逃逸代理(:3128),其余直连;不回落
			Proxy: netx.ModelProxyFunc(),
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 300 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 30 * time.Second,
			// 300s:桥的上游预算是 15s->502(桥自己会快失败),但长上下文/长思考的
			// 首字节可能远超 120s;此处只负责"服务端慢",不负责"网络死"。
			// 同一个 Client.Timeout(600s)不设成 300s,否则会掐断长流式生成。
			ResponseHeaderTimeout: 300 * time.Second,
		},
	}
}

func newEinoToolCallingChatModelFactory(
	baseHTTPClient *http.Client,
	reasoningClient *reasoning.ClientIntent,
	logger *zap.Logger,
) einoModelFactory {
	if baseHTTPClient == nil {
		baseHTTPClient = newEinoBaseHTTPClient()
	}
	return func(ctx context.Context, oa config.OpenAIConfig, mode einoModelMode) (model.ToolCallingChatModel, error) {
		if isEinoAgenticClaudeProvider(oa.Provider) {
			nativeModel, err := newEinoClaudeAgenticChatModel(ctx, oa, mode, baseHTTPClient, reasoningClient)
			if err != nil {
				return nil, err
			}
			return newAgenticToolCallingChatModelAdapter(nativeModel), nil
		}
		httpClient := openai.NewEinoHTTPClient(&oa, baseHTTPClient)
		openai.AttachSummarizationDiagTransport(httpClient, logger)
		maxCompletionTokens := oa.MaxCompletionTokensEffective()
		modelCfg := &einoopenai.ChatModelConfig{
			APIKey:              oa.APIKey,
			BaseURL:             strings.TrimSuffix(oa.BaseURL, "/"),
			Model:               oa.Model,
			HTTPClient:          httpClient,
			MaxCompletionTokens: &maxCompletionTokens,
		}
		if mode == einoModelModePlanner {
			reasoning.ApplyPlanExecutePlannerModelConfig(modelCfg, &oa)
		} else {
			reasoning.ApplyToEinoChatModelConfig(modelCfg, &oa, reasoningClient)
		}
		baseModel, err := einoopenai.NewChatModel(ctx, modelCfg)
		if err != nil {
			return nil, err
		}
		return newStreamToolCallIndexRepairModel(baseModel), nil
	}
}

func newEinoAgenticChatModelFactory(
	baseHTTPClient *http.Client,
	reasoningClient *reasoning.ClientIntent,
	logger *zap.Logger,
) einoAgenticModelConfigFactory {
	if baseHTTPClient == nil {
		baseHTTPClient = newEinoBaseHTTPClient()
	}
	return func(ctx context.Context, oa config.OpenAIConfig, mode einoModelMode) (model.AgenticModel, error) {
		if !supportsEinoAgenticBackend(oa) {
			return nil, fmt.Errorf("eino agentic model: provider %q is not supported", strings.TrimSpace(oa.Provider))
		}
		if isEinoAgenticClaudeProvider(oa.Provider) {
			return newEinoClaudeAgenticChatModel(ctx, oa, mode, baseHTTPClient, reasoningClient)
		}
		httpClient := openai.NewEinoHTTPClient(&oa, baseHTTPClient)
		openai.AttachSummarizationDiagTransport(httpClient, logger)
		maxCompletionTokens := oa.MaxCompletionTokensEffective()
		modelCfg := &agenticopenai.ChatConfig{
			APIKey:              oa.APIKey,
			BaseURL:             strings.TrimSuffix(oa.BaseURL, "/"),
			Model:               oa.Model,
			HTTPClient:          httpClient,
			MaxCompletionTokens: &maxCompletionTokens,
			ExtraFields:         reasoning.AgenticOpenAIExtraFields(&oa, reasoningClient),
		}
		if mode == einoModelModePlanner {
			modelCfg.ExtraFields = reasoning.AgenticOpenAIPlannerExtraFields(&oa)
		}
		return agenticopenai.NewChatModel(ctx, modelCfg)
	}
}

func newEinoClaudeAgenticChatModel(
	ctx context.Context,
	oa config.OpenAIConfig,
	mode einoModelMode,
	httpClient *http.Client,
	reasoningClient *reasoning.ClientIntent,
) (model.AgenticModel, error) {
	extraFields := reasoning.AgenticOpenAIExtraFields(&oa, reasoningClient)
	if mode == einoModelModePlanner {
		extraFields = reasoning.AgenticOpenAIPlannerExtraFields(&oa)
	}
	return llm.NewClaudeAgenticModel(
		ctx,
		oa,
		httpClient,
		oa.MaxCompletionTokensEffective(),
		extraFields,
	)
}

func supportsEinoAgenticBackend(oa config.OpenAIConfig) bool {
	provider := strings.ToLower(strings.TrimSpace(oa.Provider))
	return provider == "" ||
		provider == "openai" ||
		provider == "openai_compatible" ||
		isEinoAgenticClaudeProvider(provider)
}

func isEinoAgenticClaudeProvider(provider string) bool {
	return llm.IsClaudeProvider(provider)
}

func agenticModelGateFactory(factory einoAgenticModelConfigFactory, oa config.OpenAIConfig, mode einoModelMode) einoAgenticModelFactory {
	if factory == nil {
		return nil
	}
	return func(ctx context.Context) (model.AgenticModel, error) {
		return factory(ctx, oa, mode)
	}
}

// ---------------------------------------------------------------------------
// 供应方/端点识别
// ---------------------------------------------------------------------------

// einoModelEndpoint 描述"一个通道实际打到的端点"，用于切换 provenance 与跨供应方判定。
type einoModelEndpoint struct {
	Channel  string `json:"channel"`
	Provider string `json:"provider"` // 协议名（本平台恒 openai_compatible），不是供应商
	Vendor   string `json:"vendor"`   // 归一后的供应方（来自 base_url 域名）
	Host     string `json:"host"`
	Model    string `json:"model"`
}

func (e einoModelEndpoint) isZero() bool {
	return strings.TrimSpace(e.Channel) == "" && strings.TrimSpace(e.Host) == "" && strings.TrimSpace(e.Model) == ""
}

// einoVendorSuffixes 域名后缀 → 供应方。刻意只放"能确定"的：命中不了就走兜底（域名的后两段）。
var einoVendorSuffixes = []struct {
	suffix string
	vendor string
}{
	{"deepseek.com", "deepseek"},
	{"aliyuncs.com", "aliyun"}, // dashscope / MaaS workspace 均在其中
	{"openai.com", "openai"},
	{"openai.azure.com", "azure-openai"},
	{"anthropic.com", "anthropic"},
	{"moonshot.cn", "moonshot"},
	{"bigmodel.cn", "zhipu"},
	{"zhipuai.cn", "zhipu"},
	{"volces.com", "volcengine"},
	{"volcengine.com", "volcengine"},
	{"siliconflow.cn", "siliconflow"},
	{"siliconflow.com", "siliconflow"},
	{"baichuan-ai.com", "baichuan"},
	{"minimaxi.com", "minimax"},
	{"minimax.chat", "minimax"},
	{"tencentcloudapi.com", "tencent"},
	{"xf-yun.com", "xfyun"},
	{"sensetime.com", "sensetime"},
	{"stepfun.com", "stepfun"},
	{"01.ai", "01ai"},
	{"deepinfra.com", "deepinfra"},
	{"together.xyz", "together"},
	{"groq.com", "groq"},
	{"fireworks.ai", "fireworks"},
	{"openrouter.ai", "openrouter"},
	{"googleapis.com", "google"},
	{"githubusercontent.com", "github"},
}

// einoModelHost 取 base_url 的主机名（小写、去端口）。
func einoModelHost(baseURL string) string {
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

// einoModelVendor 把 base_url 归一成"供应方"。空 base_url 视为独立未知供应方（按通道名区分），
// 避免把两个都没配地址的通道误判成同供应方。
func einoModelVendor(baseURL, channelID string) string {
	host := einoModelHost(baseURL)
	if host == "" {
		id := strings.TrimSpace(channelID)
		if id == "" {
			id = "unknown"
		}
		return "unknown:" + id
	}
	for _, item := range einoVendorSuffixes {
		if host == item.suffix || strings.HasSuffix(host, "."+item.suffix) {
			return item.vendor
		}
	}
	if host == "localhost" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "10.") {
		return "local"
	}
	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return host
}

// newEinoModelEndpointForChannel 依据通道配置构造端点描述。
func newEinoModelEndpointForChannel(channelID string, oa config.OpenAIConfig) einoModelEndpoint {
	return einoModelEndpoint{
		Channel:  strings.TrimSpace(channelID),
		Provider: strings.TrimSpace(oa.Provider),
		Vendor:   einoModelVendor(oa.BaseURL, channelID),
		Host:     einoModelHost(oa.BaseURL),
		Model:    strings.TrimSpace(oa.Model),
	}
}

// ---------------------------------------------------------------------------
// 切换 provenance（tracker）
// ---------------------------------------------------------------------------

// einoModelFailoverSwitch 一次通道切换。
type einoModelFailoverSwitch struct {
	From        einoModelEndpoint `json:"from"`
	To          einoModelEndpoint `json:"to"`
	CrossVendor bool              `json:"crossVendor"`
	Reason      string            `json:"reason"`
	ErrorKind   string            `json:"errorKind"`
	Attempt     uint              `json:"attempt"`
	At          time.Time         `json:"at"`
}

// einoModelFailoverSnapshot 运行期只读快照（供收尾事件/日志/单测使用）。
type einoModelFailoverSnapshot struct {
	RunID                string                    `json:"runId"`
	ConversationID       string                    `json:"conversationId"`
	Orchestration        string                    `json:"orchestration"`
	Scope                string                    `json:"scope"`
	Primary              einoModelEndpoint         `json:"primary"`
	Final                einoModelEndpoint         `json:"final"`
	SwitchCount          int                       `json:"switchCount"`
	CrossVendorAvailable bool                      `json:"crossVendorAvailable"`
	Candidates           int                       `json:"candidates"`
	Vendors              int                       `json:"vendors"`
	Degraded             bool                      `json:"degraded"`
	Switches             []einoModelFailoverSwitch `json:"switches,omitempty"`
	StartedAt            time.Time                 `json:"startedAt"`
}

// einoModelFailoverTracker 记录一次运行内的模型切换与最终归属。
//
// 并发：adk 的 failover 回调可能被并发调用（多子代理），全部读写走互斥锁。
type einoModelFailoverTracker struct {
	mu sync.Mutex

	runID          string
	conversationID string
	orchestration  string
	scope          string

	primary einoModelEndpoint
	// current 最近一次"被选中并成功建立调用"的通道（初始 = 主通道）。
	current einoModelEndpoint
	// lastSuccess 最近一次真正成功的模型调用所在通道。
	lastSuccess einoModelEndpoint

	switches    []einoModelFailoverSwitch
	candidates  int
	vendors     int
	crossVendor bool
	degraded    bool
	startedAt   time.Time
}

func newEinoModelFailoverTracker(scope, orchestration, conversationID string, primary config.OpenAIConfig) *einoModelFailoverTracker {
	return &einoModelFailoverTracker{
		runID:          newEinoRunID(),
		conversationID: strings.TrimSpace(conversationID),
		orchestration:  strings.TrimSpace(orchestration),
		scope:          strings.TrimSpace(scope),
		primary:        newEinoModelEndpointForChannel("", primary),
		current:        newEinoModelEndpointForChannel("", primary),
		startedAt:      time.Now(),
	}
}

// setPrimaryChannelID 在主通道 id 已知时补齐 primary/current 的通道名。
func (t *einoModelFailoverTracker) setPrimaryChannelID(channelID string) {
	if t == nil {
		return
	}
	channelID = strings.TrimSpace(channelID)
	if channelID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.primary.Channel = channelID
	if t.current.Channel == "" {
		t.current.Channel = channelID
	}
	if t.lastSuccess.isZero() {
		t.lastSuccess = t.primary
	}
}

// describeCandidates 记录候选规模与"是否存在跨供应方备份"（假冗余判据）。
func (t *einoModelFailoverTracker) describeCandidates(channels []resolvedEinoFailoverChannel) {
	if t == nil {
		return
	}
	unique := map[string]struct{}{}
	cross := false
	for _, ch := range channels {
		unique[ch.endpoint.Vendor] = struct{}{}
		if ch.endpoint.Vendor != t.primary.Vendor {
			cross = true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.candidates = len(channels)
	t.vendors = len(unique)
	t.crossVendor = cross
	// degraded = 候选里只有 1 家供应商（哪怕与主通道不同）：该供应商整体不可达时无路可走。
	// 典型现场：default-2 / default-5 同为阿里云两个 workspace。
	t.degraded = len(channels) > 0 && len(unique) <= 1
}

// recordSwitch 记录一次切换（返回切换序号）。
func (t *einoModelFailoverTracker) recordSwitch(from, to einoModelEndpoint, cause error, attempt uint) int {
	if t == nil {
		return 0
	}
	kind, summary := einoTransientRunErrorUserDetail(unwrapEinoRetryExhausted(cause))
	if strings.TrimSpace(summary) == "" && cause != nil {
		summary = cause.Error()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.switches = append(t.switches, einoModelFailoverSwitch{
		From:        from,
		To:          to,
		CrossVendor: from.Vendor != to.Vendor,
		Reason:      strings.TrimSpace(summary),
		ErrorKind:   strings.TrimSpace(kind),
		Attempt:     attempt,
		At:          time.Now(),
	})
	t.current = to
	return len(t.switches)
}

// markSuccess 记录一次成功的模型调用所在通道。
func (t *einoModelFailoverTracker) markSuccess(ep einoModelEndpoint) {
	if t == nil || ep.isZero() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current = ep
	t.lastSuccess = ep
}

// Snapshot 只读快照；"最终通道"取最近一次成功调用的通道，若从未成功则取最近一次被选中的通道。
func (t *einoModelFailoverTracker) Snapshot() einoModelFailoverSnapshot {
	if t == nil {
		return einoModelFailoverSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	final := t.lastSuccess
	if final.isZero() {
		final = t.current
	}
	if final.isZero() {
		final = t.primary
	}
	switches := make([]einoModelFailoverSwitch, len(t.switches))
	copy(switches, t.switches)
	return einoModelFailoverSnapshot{
		RunID:                t.runID,
		ConversationID:       t.conversationID,
		Orchestration:        t.orchestration,
		Scope:                t.scope,
		Primary:              t.primary,
		Final:                final,
		SwitchCount:          len(t.switches),
		CrossVendorAvailable: t.crossVendor,
		Candidates:           t.candidates,
		Vendors:              t.vendors,
		Degraded:             t.degraded,
		Switches:             switches,
		StartedAt:            t.startedAt,
	}
}

// EmitFinal 在轮次收尾时回答"本轮最终由哪个通道/模型完成"。
// outcome 取 "completed" / "failed" / "cancelled" 等调用方口径；空则按 completed 记。
func (t *einoModelFailoverTracker) EmitFinal(progress func(eventType, message string, data interface{}), outcome string) {
	if t == nil || progress == nil {
		return
	}
	snap := t.Snapshot()
	outcome = strings.TrimSpace(outcome)
	if outcome == "" {
		outcome = "completed"
	}
	switched := snap.SwitchCount > 0
	msg := fmt.Sprintf("本轮模型调用最终由通道 %s(%s/%s) 完成，切换 %d 次。",
		fallbackString(snap.Final.Channel, "主通道"), fallbackString(snap.Final.Vendor, "-"), fallbackString(snap.Final.Model, "-"), snap.SwitchCount)
	progress("eino_model_channel_final", msg, map[string]interface{}{
		"conversationId":       snap.ConversationID,
		"source":               "eino",
		"orchestration":        snap.Orchestration,
		"scope":                snap.Scope,
		"runId":                snap.RunID,
		"outcome":              outcome,
		"finalChannel":         snap.Final.Channel,
		"finalVendor":          snap.Final.Vendor,
		"finalModel":           snap.Final.Model,
		"finalHost":            snap.Final.Host,
		"primaryChannel":       snap.Primary.Channel,
		"primaryVendor":        snap.Primary.Vendor,
		"primaryModel":         snap.Primary.Model,
		"switched":             switched,
		"switchCount":          snap.SwitchCount,
		"crossVendorAvailable": snap.CrossVendorAvailable,
		"degraded":             snap.Degraded,
		"candidates":           snap.Candidates,
		"vendors":              snap.Vendors,
		"elapsedMs":            time.Since(snap.StartedAt).Milliseconds(),
	})
}

func fallbackString(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// ---------------------------------------------------------------------------
// 重试配置（新增：有 failover 时，硬不可达不再烧重试，直接交给通道切换）
// ---------------------------------------------------------------------------

func newEinoModelRetryConfig(
	mw *config.MultiAgentEinoMiddlewareConfig,
	logger *zap.Logger,
	scope string,
) *adk.ModelRetryConfig {
	return newEinoModelRetryConfigWithFailover(mw, logger, scope, false)
}

// newEinoModelRetryConfigWithFailover 构造经典消息模型的重试策略。
//
// failoverActive=true 时：**硬不可达**（dial/DNS/refused/no route to host/超时）不再按次数重试，
// 立即把错误上抛给 adk 的 ModelFailoverConfig 去做跨通道切换
// —— 这正是"一个通道彻底不可达却重试 4 次后失败"的根因修法。
func newEinoModelRetryConfigWithFailover(
	mw *config.MultiAgentEinoMiddlewareConfig,
	logger *zap.Logger,
	scope string,
	failoverActive bool,
) *adk.ModelRetryConfig {
	maxRetries := RunRetryMaxAttemptsFromConfig(mw)
	maxBackoff := einoRunRetryMaxBackoffFromConfig(mw)
	return &adk.ModelRetryConfig{
		MaxRetries: maxRetries,
		BackoffFunc: func(_ context.Context, attempt int) time.Duration {
			return einoTransientRetryBackoff(attempt-1, maxBackoff)
		},
		ShouldRetry: func(ctx context.Context, retryCtx *adk.RetryContext) *adk.RetryDecision {
			if retryCtx == nil || ctx.Err() != nil {
				return &adk.RetryDecision{}
			}
			if retryCtx.Err != nil {
				if failoverActive && isEinoHardUnreachableError(retryCtx.Err) {
					if logger != nil {
						kind, summary := einoTransientRunErrorUserDetail(retryCtx.Err)
						logger.Warn("eino native model retry skipped: channel unreachable, handing over to failover",
							zap.String("scope", scope),
							zap.Int("attempt", retryCtx.RetryAttempt),
							zap.String("errorKind", kind),
							zap.String("errorSummary", summary),
						)
					}
					return &adk.RetryDecision{RejectReason: "hard_unreachable_failover"}
				}
				if !isEinoTransientRunError(retryCtx.Err) {
					return &adk.RetryDecision{}
				}
				if logger != nil {
					kind, summary := einoTransientRunErrorUserDetail(retryCtx.Err)
					logger.Warn("eino native model retry",
						zap.String("scope", scope),
						zap.Int("attempt", retryCtx.RetryAttempt),
						zap.Int("maxRetries", maxRetries),
						zap.String("errorKind", kind),
						zap.String("errorSummary", summary),
					)
				}
				return &adk.RetryDecision{Retry: true, RejectReason: "transient_model_error"}
			}
			if isRetryableEmptyModelOutput(retryCtx.OutputMessage) {
				if logger != nil {
					logger.Warn("eino native model retry: empty model output",
						zap.String("scope", scope),
						zap.Int("attempt", retryCtx.RetryAttempt),
						zap.Int("maxRetries", maxRetries),
					)
				}
				return &adk.RetryDecision{Retry: true, RejectReason: "empty_model_output"}
			}
			return &adk.RetryDecision{}
		},
	}
}

func newEinoAgenticModelRetryConfig(
	mw *config.MultiAgentEinoMiddlewareConfig,
	logger *zap.Logger,
	scope string,
) *adk.TypedModelRetryConfig[*schema.AgenticMessage] {
	return newEinoAgenticModelRetryConfigWithFailover(mw, logger, scope, false)
}

// newEinoAgenticModelRetryConfigWithFailover 见 newEinoModelRetryConfigWithFailover（agentic 版）。
func newEinoAgenticModelRetryConfigWithFailover(
	mw *config.MultiAgentEinoMiddlewareConfig,
	logger *zap.Logger,
	scope string,
	failoverActive bool,
) *adk.TypedModelRetryConfig[*schema.AgenticMessage] {
	maxRetries := RunRetryMaxAttemptsFromConfig(mw)
	maxBackoff := einoRunRetryMaxBackoffFromConfig(mw)
	return &adk.TypedModelRetryConfig[*schema.AgenticMessage]{
		MaxRetries: maxRetries,
		BackoffFunc: func(_ context.Context, attempt int) time.Duration {
			return einoTransientRetryBackoff(attempt-1, maxBackoff)
		},
		ShouldRetry: func(ctx context.Context, retryCtx *adk.TypedRetryContext[*schema.AgenticMessage]) *adk.TypedRetryDecision[*schema.AgenticMessage] {
			if retryCtx == nil || ctx.Err() != nil {
				return &adk.TypedRetryDecision[*schema.AgenticMessage]{}
			}
			if retryCtx.Err != nil {
				if failoverActive && isEinoHardUnreachableError(retryCtx.Err) {
					if logger != nil {
						kind, summary := einoTransientRunErrorUserDetail(retryCtx.Err)
						logger.Warn("eino native agentic model retry skipped: channel unreachable, handing over to failover",
							zap.String("scope", scope),
							zap.Int("attempt", retryCtx.RetryAttempt),
							zap.String("errorKind", kind),
							zap.String("errorSummary", summary),
						)
					}
					return &adk.TypedRetryDecision[*schema.AgenticMessage]{RejectReason: "hard_unreachable_failover"}
				}
				if !isEinoTransientRunError(retryCtx.Err) {
					return &adk.TypedRetryDecision[*schema.AgenticMessage]{}
				}
				if logger != nil {
					kind, summary := einoTransientRunErrorUserDetail(retryCtx.Err)
					logger.Warn("eino native agentic model retry",
						zap.String("scope", scope),
						zap.Int("attempt", retryCtx.RetryAttempt),
						zap.Int("maxRetries", maxRetries),
						zap.String("errorKind", kind),
						zap.String("errorSummary", summary),
					)
				}
				return &adk.TypedRetryDecision[*schema.AgenticMessage]{Retry: true, RejectReason: "transient_model_error"}
			}
			if isRetryableEmptyAgenticModelOutput(retryCtx.OutputMessage) {
				if logger != nil {
					logger.Warn("eino native agentic model retry: empty model output",
						zap.String("scope", scope),
						zap.Int("attempt", retryCtx.RetryAttempt),
						zap.Int("maxRetries", maxRetries),
					)
				}
				return &adk.TypedRetryDecision[*schema.AgenticMessage]{Retry: true, RejectReason: "empty_model_output"}
			}
			return &adk.TypedRetryDecision[*schema.AgenticMessage]{}
		},
	}
}

// isEinoHardUnreachableError 判定"通道彻底不可达"（语义：换通道有用、原地重试无用）。
//
// 覆盖：拨号失败/无路由/网络不可达/连接被拒/域名解析失败/建连与 TLS 超时/连接被重置。
// 不覆盖：429/5xx（同通道重试常能恢复）、鉴权失败、上下文取消（由调用方处理）。
func isEinoHardUnreachableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	err = unwrapEinoRetryExhausted(err)
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	markers := []string{
		"no route to host",
		"network is unreachable",
		"host is unreachable",
		"connection refused",
		"connection reset by peer",
		"no such host",
		"i/o timeout",
		"tls handshake timeout",
		"server misbehaving",
		"cannot assign requested address",
		"dial tcp",
		"connect: network is down",
	}
	for _, m := range markers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 通道路由（failover）
// ---------------------------------------------------------------------------

func newEinoModelFailoverConfig(
	ctx context.Context,
	appCfg *config.Config,
	mw *config.MultiAgentEinoMiddlewareConfig,
	mode einoModelMode,
	factory einoModelFactory,
	logger *zap.Logger,
	scope string,
	progress func(eventType, message string, data interface{}),
	orchestration string,
	conversationID string,
) (*adk.ModelFailoverConfig[*schema.Message], error) {
	cfg, _, err := newEinoModelFailoverConfigWithTracker(ctx, appCfg, mw, mode, factory, logger, scope, progress, orchestration, conversationID)
	return cfg, err
}

// newEinoModelFailoverConfigWithTracker 额外返回 tracker（供轮次收尾回答"最终通道"）。
func newEinoModelFailoverConfigWithTracker(
	ctx context.Context,
	appCfg *config.Config,
	mw *config.MultiAgentEinoMiddlewareConfig,
	mode einoModelMode,
	factory einoModelFactory,
	logger *zap.Logger,
	scope string,
	progress func(eventType, message string, data interface{}),
	orchestration string,
	conversationID string,
) (*adk.ModelFailoverConfig[*schema.Message], *einoModelFailoverTracker, error) {
	resolved := resolveEinoFailoverChannels(appCfg, mw)
	if len(resolved) == 0 {
		return nil, nil, nil
	}
	if factory == nil {
		return nil, nil, fmt.Errorf("eino model failover: 模型工厂为空")
	}

	channels := orderEinoFailoverCandidates(capEinoFailoverChannels(resolved, mw))
	tracker := newEinoModelFailoverTracker(scope, orchestration, conversationID, appCfg.OpenAI)
	tracker.setPrimaryChannelID(primaryEinoChannelID(appCfg))
	tracker.describeCandidates(channels)
	emitEinoFailoverPlan(progress, logger, tracker)

	cache := make(map[string]model.BaseModel[*schema.Message], len(channels))
	var mu sync.Mutex
	return &adk.ModelFailoverConfig[*schema.Message]{
		MaxRetries: uint(len(channels)),
		ShouldFailover: func(ctx context.Context, _ *schema.Message, err error) bool {
			if ctx.Err() != nil || err == nil {
				return false
			}
			err = unwrapEinoRetryExhausted(err)
			if isEinoHardUnreachableError(err) {
				return true
			}
			return isEinoTransientRunError(err)
		},
		GetFailoverModel: func(ctx context.Context, failoverCtx *adk.FailoverContext[*schema.Message]) (model.BaseModel[*schema.Message], []*schema.Message, error) {
			if failoverCtx == nil || failoverCtx.FailoverAttempt == 0 {
				return nil, nil, fmt.Errorf("eino model failover: invalid failover attempt")
			}
			idx := int(failoverCtx.FailoverAttempt) - 1
			if idx < 0 || idx >= len(channels) {
				return nil, nil, fmt.Errorf("eino model failover: no channel for attempt %d", failoverCtx.FailoverAttempt)
			}
			ch := channels[idx]

			mu.Lock()
			cached := cache[ch.id]
			mu.Unlock()
			modelBase := cached
			if modelBase == nil {
				built, err := factory(ctx, ch.cfg, mode)
				if err != nil {
					return nil, nil, fmt.Errorf("eino model failover channel %q: %w", ch.id, err)
				}
				modelBase = built
				mu.Lock()
				cache[ch.id] = modelBase
				mu.Unlock()
			}

			from := tracker.currentEndpoint()
			idxSwitched := tracker.recordSwitch(from, ch.endpoint, failoverCtx.LastErr, failoverCtx.FailoverAttempt)
			emitEinoModelFailoverEvent(progress, logger, tracker, from, ch.endpoint, failoverCtx.LastErr, failoverCtx.FailoverAttempt, idxSwitched)
			if logger != nil {
				logger.Warn("eino native model failover",
					zap.String("scope", scope),
					zap.String("runId", tracker.runID),
					zap.String("fromChannel", from.Channel),
					zap.String("fromVendor", from.Vendor),
					zap.String("channel", ch.id),
					zap.String("vendor", ch.endpoint.Vendor),
					zap.String("model", ch.cfg.Model),
					zap.Bool("crossVendor", from.Vendor != ch.endpoint.Vendor),
					zap.Uint("attempt", failoverCtx.FailoverAttempt),
				)
			}
			return newEinoTrackedMessageModel(modelBase, tracker, ch.endpoint), nil, nil
		},
	}, tracker, nil
}

func newEinoAgenticModelFailoverConfig(
	ctx context.Context,
	appCfg *config.Config,
	mw *config.MultiAgentEinoMiddlewareConfig,
	mode einoModelMode,
	factory einoAgenticModelConfigFactory,
	logger *zap.Logger,
	scope string,
	progress func(eventType, message string, data interface{}),
	orchestration string,
	conversationID string,
) (*adk.ModelFailoverConfig[*schema.AgenticMessage], error) {
	cfg, _, err := newEinoAgenticModelFailoverConfigWithTracker(ctx, appCfg, mw, mode, factory, logger, scope, progress, orchestration, conversationID)
	return cfg, err
}

// newEinoAgenticModelFailoverConfigWithTracker 额外返回 tracker（供轮次收尾回答"最终通道"）。
func newEinoAgenticModelFailoverConfigWithTracker(
	ctx context.Context,
	appCfg *config.Config,
	mw *config.MultiAgentEinoMiddlewareConfig,
	mode einoModelMode,
	factory einoAgenticModelConfigFactory,
	logger *zap.Logger,
	scope string,
	progress func(eventType, message string, data interface{}),
	orchestration string,
	conversationID string,
) (*adk.ModelFailoverConfig[*schema.AgenticMessage], *einoModelFailoverTracker, error) {
	resolved := resolveEinoFailoverChannels(appCfg, mw)
	if len(resolved) == 0 {
		return nil, nil, nil
	}
	if factory == nil {
		return nil, nil, fmt.Errorf("eino agentic model failover: 模型工厂为空")
	}

	channels := orderEinoFailoverCandidates(capEinoFailoverChannels(resolved, mw))
	tracker := newEinoModelFailoverTracker(scope, orchestration, conversationID, appCfg.OpenAI)
	tracker.setPrimaryChannelID(primaryEinoChannelID(appCfg))
	tracker.describeCandidates(channels)
	emitEinoFailoverPlan(progress, logger, tracker)

	cache := make(map[string]model.BaseModel[*schema.AgenticMessage], len(channels))
	var mu sync.Mutex
	return &adk.ModelFailoverConfig[*schema.AgenticMessage]{
		MaxRetries: uint(len(channels)),
		ShouldFailover: func(ctx context.Context, _ *schema.AgenticMessage, err error) bool {
			if ctx.Err() != nil || err == nil {
				return false
			}
			err = unwrapEinoRetryExhausted(err)
			if isEinoHardUnreachableError(err) {
				return true
			}
			return isEinoTransientRunError(err)
		},
		GetFailoverModel: func(ctx context.Context, failoverCtx *adk.FailoverContext[*schema.AgenticMessage]) (model.BaseModel[*schema.AgenticMessage], []*schema.AgenticMessage, error) {
			if failoverCtx == nil || failoverCtx.FailoverAttempt == 0 {
				return nil, nil, fmt.Errorf("eino agentic model failover: invalid failover attempt")
			}
			idx := int(failoverCtx.FailoverAttempt) - 1
			if idx < 0 || idx >= len(channels) {
				return nil, nil, fmt.Errorf("eino agentic model failover: no channel for attempt %d", failoverCtx.FailoverAttempt)
			}
			ch := channels[idx]

			mu.Lock()
			cached := cache[ch.id]
			mu.Unlock()
			modelBase := cached
			if modelBase == nil {
				built, err := factory(ctx, ch.cfg, mode)
				if err != nil {
					return nil, nil, fmt.Errorf("eino agentic model failover channel %q: %w", ch.id, err)
				}
				modelBase = built
				mu.Lock()
				cache[ch.id] = modelBase
				mu.Unlock()
			}

			from := tracker.currentEndpoint()
			idxSwitched := tracker.recordSwitch(from, ch.endpoint, failoverCtx.LastErr, failoverCtx.FailoverAttempt)
			emitEinoModelFailoverEvent(progress, logger, tracker, from, ch.endpoint, failoverCtx.LastErr, failoverCtx.FailoverAttempt, idxSwitched)
			if logger != nil {
				logger.Warn("eino native agentic model failover",
					zap.String("scope", scope),
					zap.String("runId", tracker.runID),
					zap.String("fromChannel", from.Channel),
					zap.String("fromVendor", from.Vendor),
					zap.String("channel", ch.id),
					zap.String("vendor", ch.endpoint.Vendor),
					zap.String("model", ch.cfg.Model),
					zap.Bool("crossVendor", from.Vendor != ch.endpoint.Vendor),
					zap.Uint("attempt", failoverCtx.FailoverAttempt),
				)
			}
			return newEinoTrackedAgenticModel(modelBase, tracker, ch.endpoint), nil, nil
		},
	}, tracker, nil
}

// capEinoFailoverChannels 应用 model_failover_max_retries 上限（语义见报告：0 = 用满全部候选）。
func capEinoFailoverChannels(channels []resolvedEinoFailoverChannel, mw *config.MultiAgentEinoMiddlewareConfig) []resolvedEinoFailoverChannel {
	if len(channels) == 0 {
		return channels
	}
	maxRetries := len(channels)
	if mw != nil && mw.ModelFailoverMaxRetries > 0 && mw.ModelFailoverMaxRetries < maxRetries {
		maxRetries = mw.ModelFailoverMaxRetries
	}
	if maxRetries < 1 {
		maxRetries = 1
	}
	return channels[:maxRetries]
}

// currentEndpoint 读取"当前所在通道"（并发安全）。
func (t *einoModelFailoverTracker) currentEndpoint() einoModelEndpoint {
	if t == nil {
		return einoModelEndpoint{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current.isZero() {
		return t.primary
	}
	return t.current
}

// primaryEinoChannelID 取当前主通道的通道 id（ai.default_channel），失败返回空。
func primaryEinoChannelID(appCfg *config.Config) string {
	if appCfg == nil {
		return ""
	}
	id := config.NormalizeAIChannelID(strings.TrimSpace(appCfg.AI.DefaultChannel))
	if id == "" {
		return ""
	}
	return id
}

// emitEinoFailoverPlan 候选清单一次性上抛（便于发现"假冗余"：候选全是同一供应方）。
func emitEinoFailoverPlan(progress func(eventType, message string, data interface{}), logger *zap.Logger, t *einoModelFailoverTracker) {
	if t == nil {
		return
	}
	snap := t.Snapshot()
	if logger != nil {
		logger.Info("eino model failover candidates resolved",
			zap.String("runId", snap.RunID),
			zap.String("scope", snap.Scope),
			zap.String("orchestration", snap.Orchestration),
			zap.Int("candidates", snap.Candidates),
			zap.Int("vendors", snap.Vendors),
			zap.Bool("crossVendorAvailable", snap.CrossVendorAvailable),
			zap.Bool("degraded", snap.Degraded),
		)
		if snap.Degraded {
			logger.Warn("eino model failover candidates are all from the same vendor (degraded redundancy)",
				zap.String("runId", snap.RunID),
				zap.String("primaryVendor", snap.Primary.Vendor),
				zap.Int("candidates", snap.Candidates),
				zap.String("hint", "建议在 ai.channels 增加不同供应商(不同 base_url 域名)的通道，否则该供应商整体不可达时无法切换"),
			)
		}
	}
	// 说明：这里**不**额外发 progress 事件，只打 warn —— degraded 信息会随
	// eino_model_failover（crossVendor=false）与 eino_model_channel_final（degraded=true）上抛，
	// 避免每个 run 多一条噪声事件。
	_ = progress
}

// resolveEinoFailoverChannels 解析备用通道：
//   - 去重（通道 id / 归一 id）；
//   - 跳过未知通道（ResolveChannel 失败）；
//   - 跳过与主通道"端点完全相同"的通道（同 provider+base_url+key+model）；
//   - 跳过缺 base_url / model 的半配置通道（否则会白占一次 failover 尝试）；
//   - 跳过 (host,model) 完全重复的通道；
//   - 记录 vendor 与是否跨供应方。
//
// **不在此处重排**：候选顺序保持配置顺序（便于人工预期），跨供应方优先由
// orderEinoFailoverCandidates 在构建 failover 配置时执行。
func resolveEinoFailoverChannels(appCfg *config.Config, mw *config.MultiAgentEinoMiddlewareConfig) []resolvedEinoFailoverChannel {
	if appCfg == nil || mw == nil || len(mw.ModelFailoverChannels) == 0 {
		return nil
	}
	primary := appCfg.OpenAI
	primaryEndpoint := newEinoModelEndpointForChannel(primaryEinoChannelID(appCfg), primary)
	seen := map[string]struct{}{}
	seenEndpoint := map[string]struct{}{}
	out := make([]resolvedEinoFailoverChannel, 0, len(mw.ModelFailoverChannels))
	for _, raw := range mw.ModelFailoverChannels {
		id := config.NormalizeAIChannelID(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		oa, resolvedID, ok := appCfg.AI.ResolveChannel(id)
		if !ok {
			continue
		}
		if sameOpenAIModelEndpoint(primary, oa) {
			continue
		}
		ep := newEinoModelEndpointForChannel(resolvedID, oa)
		if strings.TrimSpace(oa.BaseURL) == "" || strings.TrimSpace(oa.Model) == "" {
			continue
		}
		endpointKey := ep.Host + "|" + ep.Model
		if _, dup := seenEndpoint[endpointKey]; dup {
			continue
		}
		seenEndpoint[endpointKey] = struct{}{}
		seen[resolvedID] = struct{}{}
		out = append(out, resolvedEinoFailoverChannel{
			id:          resolvedID,
			cfg:         oa,
			endpoint:    ep,
			crossVendor: ep.Vendor != primaryEndpoint.Vendor,
		})
	}
	return out
}

// orderEinoFailoverCandidates 稳定排序：跨供应方候选在前（配置顺序内保持稳定），
// 同供应方候选在后。这样"整家供应商不可达"时会先跳到另一家，而不是在自己的两个
// workspace 之间来回撞（实测背景：default-2/default-5 同为阿里云）。
func orderEinoFailoverCandidates(channels []resolvedEinoFailoverChannel) []resolvedEinoFailoverChannel {
	if len(channels) < 2 {
		return channels
	}
	out := make([]resolvedEinoFailoverChannel, 0, len(channels))
	for _, ch := range channels {
		if ch.crossVendor {
			out = append(out, ch)
		}
	}
	for _, ch := range channels {
		if !ch.crossVendor {
			out = append(out, ch)
		}
	}
	return out
}

// einoNormalizeProvider 归一 provider：本平台里 ""/"openai_compatible" 与 "openai" 是同一协议族。
// 必须归一后再比较——否则 ai.channels 经 ToOpenAIConfig 会把 openai_compatible 改写成 openai，
// 而 appCfg.OpenAI 仍保留原值，导致"主通道自己的副本"被当成备用通道（切换到自己）。
func einoNormalizeProvider(provider string) string {
	v := strings.ToLower(strings.TrimSpace(provider))
	switch v {
	case "", "openai_compatible", "openai-compatible":
		return "openai"
	}
	return v
}

func sameOpenAIModelEndpoint(a, b config.OpenAIConfig) bool {
	return einoNormalizeProvider(a.Provider) == einoNormalizeProvider(b.Provider) &&
		strings.TrimRight(strings.TrimSpace(a.BaseURL), "/") == strings.TrimRight(strings.TrimSpace(b.BaseURL), "/") &&
		strings.TrimSpace(a.APIKey) == strings.TrimSpace(b.APIKey) &&
		strings.TrimSpace(a.Model) == strings.TrimSpace(b.Model)
}

// resolvedEinoFailoverChannel 解析后的备用通道。
type resolvedEinoFailoverChannel struct {
	id          string
	cfg         config.OpenAIConfig
	endpoint    einoModelEndpoint
	crossVendor bool
}

// ---------------------------------------------------------------------------
// 成功归属追踪包装（回答"本轮由哪个通道真正完成"）
// ---------------------------------------------------------------------------

// einoTrackedMessageModel / einoTrackedAgenticModel 只在成功时打点，不改变任何调用语义。
// （eino 的 model.BaseModel[M] 约束是包内私有 messageType，无法用泛型约束复刻，故按消息类型各写一份。）
type einoTrackedMessageModel struct {
	inner   model.BaseModel[*schema.Message]
	tracker *einoModelFailoverTracker
	ep      einoModelEndpoint
}

func newEinoTrackedMessageModel(inner model.BaseModel[*schema.Message], tracker *einoModelFailoverTracker, ep einoModelEndpoint) model.BaseModel[*schema.Message] {
	if inner == nil {
		return nil
	}
	if tracker == nil {
		return inner
	}
	return &einoTrackedMessageModel{inner: inner, tracker: tracker, ep: ep}
}

func (m *einoTrackedMessageModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	out, err := m.inner.Generate(ctx, input, opts...)
	if err == nil {
		m.tracker.markSuccess(m.ep)
	}
	return out, err
}

func (m *einoTrackedMessageModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	out, err := m.inner.Stream(ctx, input, opts...)
	if err == nil {
		m.tracker.markSuccess(m.ep)
	}
	return out, err
}

type einoTrackedAgenticModel struct {
	inner   model.BaseModel[*schema.AgenticMessage]
	tracker *einoModelFailoverTracker
	ep      einoModelEndpoint
}

func newEinoTrackedAgenticModel(inner model.BaseModel[*schema.AgenticMessage], tracker *einoModelFailoverTracker, ep einoModelEndpoint) model.BaseModel[*schema.AgenticMessage] {
	if inner == nil {
		return nil
	}
	if tracker == nil {
		return inner
	}
	return &einoTrackedAgenticModel{inner: inner, tracker: tracker, ep: ep}
}

func (m *einoTrackedAgenticModel) Generate(ctx context.Context, input []*schema.AgenticMessage, opts ...model.Option) (*schema.AgenticMessage, error) {
	out, err := m.inner.Generate(ctx, input, opts...)
	if err == nil {
		m.tracker.markSuccess(m.ep)
	}
	return out, err
}

func (m *einoTrackedAgenticModel) Stream(ctx context.Context, input []*schema.AgenticMessage, opts ...model.Option) (*schema.StreamReader[*schema.AgenticMessage], error) {
	out, err := m.inner.Stream(ctx, input, opts...)
	if err == nil {
		m.tracker.markSuccess(m.ep)
	}
	return out, err
}

// ---------------------------------------------------------------------------
// plan_execute 的 planner/replanner 模型：自建通道切换（eino 的 planexecute 不接受
// ModelFailoverConfig，只能包一层 ToolCallingChatModel）
// ---------------------------------------------------------------------------

// einoFailoverChatModel 给"没有 adk failover 挂载点"的 ChatModel 提供同等的切通道能力。
type einoFailoverChatModel struct {
	primary  model.ToolCallingChatModel
	channels []resolvedEinoFailoverChannel
	factory  einoModelFactory
	mode     einoModelMode
	tracker  *einoModelFailoverTracker
	logger   *zap.Logger
	progress func(eventType, message string, data interface{})
	mu       sync.Mutex
	built    map[string]model.ToolCallingChatModel
	stickyID string
}

// newEinoPlannerFailoverChatModel 为 planner/replanner 构造带跨供应商切换的 ChatModel。
// 无候选通道时原样返回 primary（行为完全不变），tracker 为 nil。
func newEinoPlannerFailoverChatModel(
	primary model.ToolCallingChatModel,
	appCfg *config.Config,
	mw *config.MultiAgentEinoMiddlewareConfig,
	factory einoModelFactory,
	logger *zap.Logger,
	progress func(eventType, message string, data interface{}),
	scope, orchestration, conversationID string,
) (model.ToolCallingChatModel, *einoModelFailoverTracker) {
	resolved := resolveEinoFailoverChannels(appCfg, mw)
	if primary == nil || len(resolved) == 0 || factory == nil {
		return primary, nil
	}
	channels := orderEinoFailoverCandidates(capEinoFailoverChannels(resolved, mw))
	tracker := newEinoModelFailoverTracker(scope, orchestration, conversationID, appCfg.OpenAI)
	tracker.setPrimaryChannelID(primaryEinoChannelID(appCfg))
	tracker.describeCandidates(channels)
	emitEinoFailoverPlan(progress, logger, tracker)
	return &einoFailoverChatModel{
		primary:  primary,
		channels: channels,
		factory:  factory,
		mode:     einoModelModePlanner,
		tracker:  tracker,
		logger:   logger,
		progress: progress,
		built:    make(map[string]model.ToolCallingChatModel, len(channels)),
	}, tracker
}

// einoPlannerAttempt 一次候选尝试（primary 或某个备用通道）。
type einoPlannerAttempt struct {
	id        string
	endpoint  einoModelEndpoint
	model     model.ToolCallingChatModel
	isPrimary bool
}

// attemptOrder 计算本轮尝试顺序：粘性通道(上次成功切换到的) → 主通道 → 其余候选。
// 粘性可避免"已判定不可达的主通道"在每个 planner 步骤都被重新拨号（黑洞地址上单次
// dial 最长可挂 300s），同时保留"主通道恢复后优先回主"的能力（每次 run 重新计算）。
func (m *einoFailoverChatModel) attemptOrder() []einoPlannerAttempt {
	m.mu.Lock()
	stickyID := m.stickyID
	cached := make(map[string]model.ToolCallingChatModel, len(m.built))
	for k, v := range m.built {
		cached[k] = v
	}
	m.mu.Unlock()

	out := make([]einoPlannerAttempt, 0, len(m.channels)+1)
	seen := map[string]bool{}
	if stickyID != "" {
		for _, ch := range m.channels {
			if ch.id == stickyID {
				if built := cached[ch.id]; built != nil {
					out = append(out, einoPlannerAttempt{id: ch.id, endpoint: ch.endpoint, model: built})
					seen[ch.id] = true
				}
				break
			}
		}
	}
	out = append(out, einoPlannerAttempt{endpoint: m.tracker.primaryEndpoint(), model: m.primary, isPrimary: true})
	for _, ch := range m.channels {
		if seen[ch.id] {
			continue
		}
		// 未构建的候选也要进列表（model 为 nil，由调用方懒加载）。
		out = append(out, einoPlannerAttempt{id: ch.id, endpoint: ch.endpoint, model: cached[ch.id]})
	}
	return out
}

func (m *einoFailoverChatModel) setSticky(id string) {
	m.mu.Lock()
	m.stickyID = id
	m.mu.Unlock()
}

func (m *einoFailoverChatModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	var lastErr error
	attempt := 0
	for _, cand := range m.attemptOrder() {
		modelImpl := cand.model
		if modelImpl == nil {
			built, err := m.candidateByID(ctx, cand.id)
			if err != nil {
				lastErr = err
				continue
			}
			modelImpl = built
		}
		// 切换事件在"调用候选之前"发出：语义是"已从 X 切到 Y"，而不是"Y 也失败了"。
		if !cand.isPrimary {
			attempt++
			from := m.tracker.currentEndpoint()
			idx := m.tracker.recordSwitch(from, cand.endpoint, lastErr, uint(attempt))
			emitEinoModelFailoverEvent(m.progress, m.logger, m.tracker, from, cand.endpoint, lastErr, uint(attempt), idx)
		}
		out, err := modelImpl.Generate(ctx, input, opts...)
		if err == nil {
			m.markAttemptSuccess(cand)
			return out, nil
		}
		lastErr = err
		if !m.shouldFailover(ctx, err) {
			return out, err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (m *einoFailoverChatModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	var lastErr error
	attempt := 0
	for _, cand := range m.attemptOrder() {
		modelImpl := cand.model
		if modelImpl == nil {
			built, err := m.candidateByID(ctx, cand.id)
			if err != nil {
				lastErr = err
				continue
			}
			modelImpl = built
		}
		if !cand.isPrimary {
			attempt++
			from := m.tracker.currentEndpoint()
			idx := m.tracker.recordSwitch(from, cand.endpoint, lastErr, uint(attempt))
			emitEinoModelFailoverEvent(m.progress, m.logger, m.tracker, from, cand.endpoint, lastErr, uint(attempt), idx)
		}
		stream, err := modelImpl.Stream(ctx, input, opts...)
		if err == nil {
			m.markAttemptSuccess(cand)
			return stream, nil
		}
		lastErr = err
		if !m.shouldFailover(ctx, err) {
			return stream, err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (m *einoFailoverChatModel) markAttemptSuccess(cand einoPlannerAttempt) {
	m.tracker.markSuccess(cand.endpoint)
	if cand.isPrimary {
		m.setSticky("")
		return
	}
	m.setSticky(cand.id)
}

func (m *einoFailoverChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	withTools, err := m.primary.WithTools(tools)
	if err != nil {
		return nil, err
	}
	clone := &einoFailoverChatModel{
		primary:  withTools,
		channels: m.channels,
		factory:  m.factory,
		mode:     m.mode,
		tracker:  m.tracker,
		logger:   m.logger,
		progress: m.progress,
		built:    make(map[string]model.ToolCallingChatModel, len(m.channels)),
	}
	return clone, nil
}

func (m *einoFailoverChatModel) shouldFailover(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if isEinoHardUnreachableError(err) {
		return true
	}
	return isEinoTransientRunError(err)
}

func (m *einoFailoverChatModel) candidateByID(ctx context.Context, id string) (model.ToolCallingChatModel, error) {
	for _, ch := range m.channels {
		if ch.id != id {
			continue
		}
		return m.candidate(ctx, ch)
	}
	return nil, fmt.Errorf("planner failover: unknown channel %q", id)
}

func (m *einoFailoverChatModel) candidate(ctx context.Context, ch resolvedEinoFailoverChannel) (model.ToolCallingChatModel, error) {
	m.mu.Lock()
	cached := m.built[ch.id]
	m.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	built, err := m.factory(ctx, ch.cfg, m.mode)
	if err != nil {
		return nil, fmt.Errorf("planner failover channel %q: %w", ch.id, err)
	}
	m.mu.Lock()
	m.built[ch.id] = built
	m.mu.Unlock()
	return built, nil
}

// primaryEndpoint 主通道端点（用于成功打点）。
func (t *einoModelFailoverTracker) primaryEndpoint() einoModelEndpoint {
	if t == nil {
		return einoModelEndpoint{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.primary.isZero() {
		return einoModelEndpoint{}
	}
	return t.primary
}

// ---------------------------------------------------------------------------
// 轻量判据
// ---------------------------------------------------------------------------

func isRetryableEmptyModelOutput(msg *schema.Message) bool {
	if msg == nil {
		return true
	}
	return strings.TrimSpace(msg.Content) == "" &&
		strings.TrimSpace(msg.ReasoningContent) == "" &&
		len(msg.ToolCalls) == 0 &&
		len(msg.MultiContent) == 0 &&
		len(msg.UserInputMultiContent) == 0 &&
		len(msg.AssistantGenMultiContent) == 0
}

func isRetryableEmptyAgenticModelOutput(msg *schema.AgenticMessage) bool {
	if msg == nil {
		return true
	}
	for _, block := range msg.ContentBlocks {
		if block == nil {
			continue
		}
		switch {
		case block.Reasoning != nil:
			if strings.TrimSpace(block.Reasoning.Text) != "" {
				return false
			}
		case block.UserInputText != nil:
			if strings.TrimSpace(block.UserInputText.Text) != "" {
				return false
			}
		case block.AssistantGenText != nil:
			if strings.TrimSpace(block.AssistantGenText.Text) != "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func unwrapEinoRetryExhausted(err error) error {
	var retryErr *adk.RetryExhaustedError
	if errors.As(err, &retryErr) && retryErr.LastErr != nil {
		return retryErr.LastErr
	}
	return err
}

func isEinoNativeWillRetry(err error) (*adk.WillRetryError, bool) {
	var willRetry *adk.WillRetryError
	if errors.As(err, &willRetry) {
		return willRetry, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// 事件（复用既有 progress/process_details 通道，不新增表）
// ---------------------------------------------------------------------------

// emitEinoModelFailoverEvent 发出一次通道切换事件。
//
// 兼容性：保留旧字段 channel/model/attempt/conversationId/orchestration/scope/source，
// 新增 from/to 全量端点、provider、vendor、原因、runId、切换序号与候选规模。
func emitEinoModelFailoverEvent(
	progress func(eventType, message string, data interface{}),
	logger *zap.Logger,
	tracker *einoModelFailoverTracker,
	from, to einoModelEndpoint,
	cause error,
	attempt uint,
	switchIndex int,
) {
	_ = logger
	if progress == nil || tracker == nil {
		return
	}
	kind, summary := einoTransientRunErrorUserDetail(unwrapEinoRetryExhausted(cause))
	if strings.TrimSpace(summary) == "" && cause != nil {
		summary = cause.Error()
	}
	crossVendor := from.Vendor != to.Vendor
	msg := fmt.Sprintf("主模型不可用，已切换备用通道 %s（供应商 %s，模型 %s）。",
		fallbackString(to.Channel, "-"), fallbackString(to.Vendor, "-"), fallbackString(to.Model, "-"))
	progress("eino_model_failover", msg, map[string]interface{}{
		"conversationId": tracker.conversationID,
		"source":         "eino",
		"orchestration":  tracker.orchestration,
		"scope":          tracker.scope,
		"runId":          tracker.runID,
		// 旧字段（兼容既有看板/记录）
		"channel": to.Channel,
		"model":   to.Model,
		"attempt": attempt,
		// 新增：切换两端 + 供应方 + 原因
		"fromChannel": from.Channel,
		"fromVendor":  from.Vendor,
		"fromModel":   from.Model,
		"fromHost":    from.Host,
		"toChannel":   to.Channel,
		"toVendor":    to.Vendor,
		"toModel":     to.Model,
		"toHost":      to.Host,
		"provider":    to.Provider,
		"crossVendor": crossVendor,
		"reason":      strings.TrimSpace(summary),
		"errorKind":   strings.TrimSpace(kind),
		"switchIndex": switchIndex,
	})
}
