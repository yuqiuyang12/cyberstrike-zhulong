package loop2

import (
	"encoding/json"
	"strings"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

type einoRunResultBuilderConfig struct {
	OrchMode         string
	EmptyHint        string
	RunMessages      *einoRunMessageAccumulator
	AssistantOutput  *einoAssistantOutputAccumulator
	SnapshotMCPIDs   func() []string
	ModelFacingTrace func() []adk.Message
}

type einoRunResultBuilder struct {
	cfg einoRunResultBuilderConfig
}

func newEinoRunResultBuilder(cfg einoRunResultBuilderConfig) *einoRunResultBuilder {
	return &einoRunResultBuilder{cfg: cfg}
}

func (b *einoRunResultBuilder) BuildPartial(runErr error) (*RunResult, error) {
	if b == nil || b.cfg.RunMessages == nil || !b.cfg.RunMessages.HasNewMessages() {
		return nil, runErr
	}
	return b.build(true), runErr
}

func (b *einoRunResultBuilder) BuildFinal() *RunResult {
	if b == nil {
		return &RunResult{}
	}
	return b.build(false)
}

func (b *einoRunResultBuilder) build(partial bool) *RunResult {
	var runMsgs []adk.Message
	if b.cfg.RunMessages != nil {
		runMsgs = b.cfg.RunMessages.NewMessages()
	}
	var lastAssistant string
	var lastPlanExecuteExecutor string
	if b.cfg.AssistantOutput != nil {
		lastAssistant = b.cfg.AssistantOutput.LastAssistant()
		lastPlanExecuteExecutor = b.cfg.AssistantOutput.LastPlanExecuteExecutor()
	}
	var modelFacing []adk.Message
	if b.cfg.ModelFacingTrace != nil {
		modelFacing = b.cfg.ModelFacingTrace()
	}
	var ids []string
	if b.cfg.SnapshotMCPIDs != nil {
		ids = b.cfg.SnapshotMCPIDs()
	}
	return buildEinoRunResultFromAccumulated(
		b.cfg.OrchMode,
		runMsgs,
		modelFacing,
		lastAssistant,
		lastPlanExecuteExecutor,
		b.cfg.EmptyHint,
		ids,
		partial,
	)
}

func einoPartialRunLastOutputHint() string {
	return "[执行未正常结束（用户停止、超时或异常）。续跑时请基于上文已产生的工具与结果继续，勿重复已完成步骤。]\n" +
		"[Run ended abnormally; continue from the trace above without repeating completed steps.]"
}

func buildEinoRunResultFromAccumulated(
	orchMode string,
	runAccumulatedMsgs []adk.Message,
	persistMsgs []adk.Message,
	lastAssistant string,
	lastPlanExecuteExecutor string,
	emptyHint string,
	mcpIDs []string,
	partial bool,
) *RunResult {
	traceForJSON := persistMsgs
	traceJSON := ""
	if len(traceForJSON) > 0 {
		traceForJSON = markModelFacingTraceForPersistence(traceForJSON)
		if histJSON, err := json.Marshal(traceForJSON); err == nil {
			traceJSON = string(histJSON)
		}
	}
	cleaned := strings.TrimSpace(lastAssistant)
	if orchMode == "plan_execute" {
		if e := strings.TrimSpace(lastPlanExecuteExecutor); e != "" {
			cleaned = e
		} else {
			cleaned = UnwrapPlanExecuteUserText(cleaned)
		}
	}
	if cleaned == "" {
		if fb := strings.TrimSpace(einoExtractFallbackAssistantFromMsgs(runAccumulatedMsgs)); fb != "" {
			cleaned = fb
			if orchMode == "plan_execute" {
				cleaned = UnwrapPlanExecuteUserText(cleaned)
			}
		}
	}
	cleaned = dedupeRepeatedParagraphs(cleaned, 80)
	cleaned = dedupeParagraphsByLineFingerprint(cleaned, 100)
	const maxResponseRunes = 100000
	if rs := []rune(cleaned); len(rs) > maxResponseRunes {
		cleaned = string(rs[:maxResponseRunes]) + "\n\n... (response truncated / 响应已截断)"
	}
	lastOut := cleaned
	resp := cleaned
	if partial && cleaned == "" {
		lastOut = einoPartialRunLastOutputHint()
		resp = emptyHint
	}
	out := &RunResult{
		Response:             resp,
		MCPExecutionIDs:      mcpIDs,
		LastAgentTraceInput:  traceJSON,
		LastAgentTraceOutput: lastOut,
	}
	if !partial && out.Response == "" {
		out.Response = emptyHint
		out.LastAgentTraceOutput = out.Response
	}
	return out
}

func markModelFacingTraceForPersistence(msgs []adk.Message) []adk.Message {
	out := cloneADKMessagesForTrace(msgs)
	if len(out) == 0 || out[0] == nil {
		return out
	}
	if out[0].Extra == nil {
		out[0].Extra = make(map[string]any, 1)
	}
	out[0].Extra[agent.ModelFacingTraceVersionKey] = 1
	return out
}

// toolResultErrorPrefixes 工具结果里的"错误文案"前缀：平台软错误（中/英）与内部 MCP 错误前缀。
// 错误文案不是可交付终态（2026-10-21 修复 S3：supervisor 的 exit 软错误曾被当成最终答复交付）。
var toolResultErrorPrefixes = []string{
	ToolErrorSoftPrefixEn,
	ToolErrorSoftPrefixZh,
	einomcp.ToolErrorPrefix,
}

// isToolResultErrorMessage 判断工具结果是否为错误文案。
func isToolResultErrorMessage(content string) bool {
	c := strings.TrimSpace(content)
	if c == "" {
		return false
	}
	for _, p := range toolResultErrorPrefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

// einoExtractFallbackAssistantFromMsgs 在「主通道未产出助手正文」时，从 Eino ADK
// 原生消息轨迹中回填用户可见回复。这里保持克制：只采纳倒序最近的可交付终态，
// 避免把工具调用前的过渡语或子任务过程误升为最终回复。
//
// 可交付终态：
// - exit 工具输出（且不是错误文案）；
// - assistant 调用 exit 时 arguments.final_result；
// - 没有后续普通工具结果截断的纯 assistant 正文。
func einoExtractFallbackAssistantFromMsgs(msgs []adk.Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		if m == nil {
			continue
		}
		switch m.Role {
		case schema.Tool:
			content := strings.TrimSpace(m.Content)
			if strings.EqualFold(strings.TrimSpace(m.ToolName), adk.ToolInfoExit.Name) {
				if content != "" && !isToolResultErrorMessage(content) {
					return content
				}
			}
			if isToolResultErrorMessage(content) {
				// 错误结果不是交付物：继续向前找 assistant 的 final_result / 纯正文，
				// 而不是把 〔Tool Error〕 串当最终答复返回（旧实现此处 return "" 会让
				// 下面的 final_result 解析分支不可达）。
				continue
			}
			return ""
		case schema.Assistant:
			if s := einoExtractExitFinalFromAssistantToolCalls(m); s != "" {
				return s
			}
			if len(m.ToolCalls) == 0 {
				if content := strings.TrimSpace(m.Content); content != "" {
					return content
				}
			}
		}
	}
	return ""
}

func einoExtractExitFinalFromAssistantToolCalls(msg *schema.Message) string {
	if msg == nil || len(msg.ToolCalls) == 0 {
		return ""
	}
	for i := len(msg.ToolCalls) - 1; i >= 0; i-- {
		tc := msg.ToolCalls[i]
		if !strings.EqualFold(strings.TrimSpace(tc.Function.Name), adk.ToolInfoExit.Name) {
			continue
		}
		if s := einoParseExitFinalResultArguments(tc.Function.Arguments); s != "" {
			return s
		}
	}
	return ""
}

func einoParseExitFinalResultArguments(arguments string) string {
	arguments = strings.TrimSpace(arguments)
	if arguments == "" {
		return ""
	}
	var wrap struct {
		FinalResult json.RawMessage `json:"final_result"`
	}
	if err := json.Unmarshal([]byte(arguments), &wrap); err != nil || len(wrap.FinalResult) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(wrap.FinalResult, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var anyVal interface{}
	if err := json.Unmarshal(wrap.FinalResult, &anyVal); err != nil {
		return ""
	}
	b, err := json.Marshal(anyVal)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
