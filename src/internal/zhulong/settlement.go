package zhulong

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SettlementPrompt 是"预算耗尽/触顶"后的收尾指令。
//
// 目的：一轮被预算打断时，不让它烂尾——用尽可能少的一两次模型调用，把
// 已完成的结论、证据路径、未完成项榨成一份合法回执（对齐 ARTEX 的 settlement 阶段）。
const SettlementPrompt = `## 收尾阶段（本轮预算已耗尽）

本轮因预算（步数/时长）结束，**不再允许调用任何工具**，也不会再给你新的工具结果。
请只根据上面已经发生过的内容，输出一份回执：

1. 先写 3–8 行「本轮已完成」，每条必须能指到上文出现过的命令/路径/数据；没有就写「无」。
2. 再写 2–5 行「未完成与建议下一步」（这些会作为下一轮的输入）。
3. 最后在消息末尾交一个 ` + "```zhulong" + ` 回执块。

判定口径：
- 本轮把某条链往前推了一个台阶（有 payload + 原始报文）→ outcome=continue（**不是 done**：交付要等链归零）
- 本轮真的构成交付（open 链已归零、至少一条链锚定目标自身、deliver_gate=GATE=PASS）→ outcome=done
  （evidence_refs 必须是上文出现过的绝对路径或 URL；系统会用链台账与闸门复核，不符的 done 会被打回 continue）
- 本轮没有任何新证据 → outcome=nothing
- 卡在需要人拍板的地方 → outcome=blocked（用 asks 提问）
- 连结论都拼不出来 → outcome=failed

铁律：**不得编造上文没出现过的证据**；只输出正文与一个回执块，不要再申请工具。`

// ToolSnippet 是一条工具输出的摘要视图（原文已截断，仅供收尾模型引用证据）。
type ToolSnippet struct {
	Tool    string
	Content string
}

// ExtractToolSnippets 从 RunResult.LastAgentTraceInput 的消息带 JSON 里抽取最近若干条工具输出。
//
// 目的：收尾阶段如果只看助手自述，模型会因为"看不到真实返回值"而一律判 failed；
// 把最近几条工具输出（截断）喂进去，它才能引用真实证据给出 done。
//
// 容错优先：格式不认识、解析失败一律返回 nil（收尾退回只用目标+末段文本），不报错。
func ExtractToolSnippets(traceJSON string, maxItems, maxRunesPerItem int) []ToolSnippet {
	if maxItems <= 0 {
		maxItems = 8
	}
	if maxRunesPerItem <= 0 {
		maxRunesPerItem = 1200
	}
	raw := strings.TrimSpace(traceJSON)
	if raw == "" || raw == "[]" || raw == "null" {
		return nil
	}
	var msgs []map[string]any
	if err := json.Unmarshal([]byte(raw), &msgs); err != nil {
		return nil
	}
	var out []ToolSnippet
	for _, m := range msgs {
		role := strings.ToLower(strings.TrimSpace(asString(m["role"])))
		name := strings.TrimSpace(asString(m["name"]))
		if name == "" {
			name = strings.TrimSpace(asString(m["tool_name"]))
		}
		content := asString(m["content"])
		isTool := role == "tool" || role == "tool_result" || role == "function" || strings.EqualFold(role, "toolResponse")
		if !isTool {
			// 有的消息带把工具结果挂在 "tool_calls" 的结果字段上：只在有 content 且带 name 时收
			if name == "" || content == "" {
				continue
			}
		}
		if strings.TrimSpace(content) == "" {
			continue
		}
		if name == "" {
			name = "tool"
		}
		out = append(out, ToolSnippet{Tool: name, Content: headTailText(content, maxRunesPerItem)})
	}
	if len(out) > maxItems {
		out = out[len(out)-maxItems:]
	}
	return out
}

func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// BuildSettlementDigest 把本轮状态压成收尾模型的输入（不塞全量历史）。
//   - goal：目标一句话
//   - lastText：本轮助手最后一段可见文本（可能为空）
//   - steps：结构化步骤摘要（工具名 + 摘要），已按时间排好
//   - maxRunes：整体上限，超出时保留头部目标与尾部最近步骤（头尾各半）
func BuildSettlementDigest(goal, lastText string, steps []Step, tools []ToolSnippet, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 12000
	}
	var sb strings.Builder
	sb.WriteString("## 本轮目标\n")
	sb.WriteString(oneLineText(goal, 400))
	sb.WriteString("\n\n## 已执行的步骤（工具 + 摘要，旧→新）\n")
	if len(steps) == 0 {
		sb.WriteString("（无记录）\n")
	} else {
		for _, st := range steps {
			line := fmt.Sprintf("- [%02d] %s", st.StepNo, st.ToolName)
			if s := strings.TrimSpace(st.Summary); s != "" {
				line += "：" + oneLineText(s, 160)
			}
			if r := strings.TrimSpace(st.EvidenceRef); r != "" {
				line += "（证据：" + oneLineText(r, 200) + "）"
			}
			sb.WriteString(line + "\n")
		}
	}
	if len(tools) > 0 {
		sb.WriteString("\n## 最近的工具输出（原始节选，可直接作为 evidence_refs 的依据）\n")
		for _, t := range tools {
			sb.WriteString("- [`" + t.Tool + "`] " + t.Content + "\n")
		}
	}
	if t := strings.TrimSpace(lastText); t != "" {
		sb.WriteString("\n## 本轮最后一段可见输出\n")
		sb.WriteString(headTailText(t, maxRunes/3))
		sb.WriteString("\n")
	}
	return clipHeadTail(sb.String(), maxRunes)
}

func oneLineText(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

// headTailText 保留头尾各半，中间用省略标记（长日志不整段塞进收尾模型）。
func headTailText(s string, budget int) string {
	if budget <= 0 {
		budget = 4000
	}
	r := []rune(s)
	if len(r) <= budget {
		return s
	}
	half := budget / 2
	return string(r[:half]) + "\n…（中间省略 " + fmt.Sprint(len(r)-budget) + " 字）…\n" + string(r[len(r)-half:])
}

func clipHeadTail(s string, max int) string {
	return headTailText(s, max)
}

// ============================================================================
// C4（2026-11-05 M1）：每步落库
//
// 背景（实测 bug）：AppendStep 原先只在收尾阶段调一次，于是"一轮跑了 6.5 分钟、
// 调了几十个工具"，zhulong_steps 里本轮 0 行——事后既无法复盘打了什么，
// 也无法把"这一轮的证据路径"回注给下一轮。
//
// 现在的口径：
//   - 每个 tool_call 立刻落一行（step_no 单调递增），先把"发起"记下来；
//   - 对应的 tool_result 到达时，用**同一个 step_no** 覆盖写入（AppendStep 自带 upsert），
//     补上结果摘要与证据落盘路径；
//   - 写库失败只记日志，绝不阻塞本轮（台账服务于复盘，不是执行前提）。
// ============================================================================

const (
	// maxRecordedSteps 是单轮最多落多少行（防御：模型死循环刷工具时别把库灌满）。
	maxRecordedSteps = 2000
	// stepEvidenceMaxRunes 是单条 evidence_ref 的长度上限。
	stepEvidenceMaxRunes = 400
	// stepPreviewRunes 是结果摘要截断长度。
	stepPreviewRunes = 240
	// touchRunThrottle 是 StepRecorder 心跳的最小间隔（工具事件密集时不重复打库）。
	touchRunThrottle = time.Second
)

// DefaultHeartbeatInterval 是租约心跳的默认间隔。
// 45s 是折中：一轮最长 60 分钟，模型长时间思考期间只能靠 ticker 刷 seen_at，
// 间隔再大就可能被判 unknown；再小则对 SQLite 是无意义的写放大。
const DefaultHeartbeatInterval = 45 * time.Second

var (
	// stepEvidencePathPattern 只认"看着像落盘文件"的绝对路径（扩展名白名单），
	// 避免把 payload 里的 `/etc/passwd`、`/api/v1/user` 当证据。
	stepEvidencePathPattern = regexp.MustCompile(`(?:/(?:[\w.@+-]+/)*[\w.@+-]+\.(?:jsonl|json|txt|log|md|html|htm|xml|csv|pcap|pcapng|har|png|jpg|jpeg|gif|pdf|ya?ml))`)
	// stepEvidenceURLPattern 是 http(s) URL（可复核的远端引用）。
	stepEvidenceURLPattern = regexp.MustCompile(`https?://[^\s"'<>()\[\]{}]+`)
)

// StepRecorder 把一轮里的工具调用落成 zhulong_steps 行（并发安全：工具可能并行）。
type StepRecorder struct {
	store  *Store
	runID  string
	base   context.Context
	logger *zap.Logger

	mu   sync.Mutex
	seq  int
	open map[string]int // toolCallId → step_no（等结果回来时覆盖同一行）

	// lastTouch 是租约心跳的节流时间戳（C5：WrapProgress 每个事件都 touchRun，
	// 但工具事件密集时不重复打库；与 mu 共用一把锁，不引入新锁）。
	lastTouch time.Time
}

// NewStepRecorder 构造一个 recorder；store/runID 任一为空时所有方法都是 no-op。
func NewStepRecorder(base context.Context, store *Store, runID string, logger *zap.Logger) *StepRecorder {
	if base == nil {
		base = context.Background()
	}
	return &StepRecorder{store: store, runID: runID, base: base, logger: logger, open: map[string]int{}}
}

// WrapProgress 返回包装后的 progress 回调：先按事件落库，再原样转发给下游。
//
// 下游为 nil 时只落库（不影响调用方判断 nil）。
func (r *StepRecorder) WrapProgress(next func(eventType, message string, data interface{})) func(eventType, message string, data interface{}) {
	if r == nil {
		return next
	}
	return func(eventType, message string, data interface{}) {
		// C5（2026-11-06 P0）：先刷租约再落库/转发。没有任何生产代码调用 TouchRun 时，
		// 60 分钟预算的轮会在第 10 分钟左右被判 unknown；这里每个事件都补一次心跳（1s 节流）。
		r.touchRun()
		switch eventType {
		case "tool_call":
			r.recordToolCall(message, data)
		case "tool_result":
			r.recordToolResult(message, data)
		}
		if next != nil {
			next(eventType, message, data)
		}
	}
}

// touchRun 刷新 run 租约（zhulong_runs.seen_at）。
//
// 口径（C5）：
//   - 1 秒节流：工具事件可能成串到达，没必要每个事件都打一次库（用既有 mu + lastTouch）；
//   - 失败只记 debug，绝不阻塞本轮（心跳是兜底，不是执行前提）；
//   - store/runID 为空时直接返回（no-op recorder 场景）；
//   - ctx 从 base 派生并剥离取消（WithoutCancel）：本轮 ctx 到点取消时，
//     心跳本身仍要能写一次，否则收尾阶段又掉租约。
func (r *StepRecorder) touchRun() {
	if r == nil || r.store == nil || r.runID == "" {
		return
	}
	r.mu.Lock()
	if !r.lastTouch.IsZero() && time.Since(r.lastTouch) < touchRunThrottle {
		r.mu.Unlock()
		return
	}
	r.lastTouch = time.Now()
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.base), 3*time.Second)
	defer cancel()
	if err := r.store.TouchRun(ctx, r.runID); err != nil && r.logger != nil {
		r.logger.Debug("zhulong: 租约心跳失败（不阻塞本轮）", zap.String("runId", r.runID), zap.Error(err))
	}
}

// StartHeartbeat 起一个租约心跳 goroutine：每 interval 用 3s 超时 ctx 调一次 store.TouchRun。
//
// 为什么需要独立 ticker（C5）：StepRecorder 只在 tool_call/tool_result 事件上打心跳，
// 模型长时间思考（一轮最长 60 分钟）时没有工具事件 → seen_at 停滞 → lease 把 run 判成 unknown。
//
// 语义：
//   - interval <= 0 时用 DefaultHeartbeatInterval(45s)；
//   - ctx 只为调用方对称保留：心跳从 context.Background() 派生，**刻意不受 runCtx 取消影响**，
//     否则预算到点取消后收尾阶段又掉租约；
//   - 返回的 stop 幂等（重复调用安全），并阻塞到 goroutine 退出；
//   - store/runID 为空时返回空操作 stop；
//   - 单拍失败只记 debug，不终止心跳。
func StartHeartbeat(ctx context.Context, store *Store, runID string, interval time.Duration, logger *zap.Logger) (stop func()) {
	if store == nil || strings.TrimSpace(runID) == "" {
		return func() {}
	}
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	_ = ctx // 见上：心跳刻意与调用方 ctx 的生命周期解耦

	beatCtx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-beatCtx.Done():
				return
			case <-ticker.C:
				touchCtx, cancelTouch := context.WithTimeout(context.Background(), 3*time.Second)
				err := store.TouchRun(touchCtx, runID)
				cancelTouch()
				if err != nil && logger != nil {
					logger.Debug("zhulong: 租约心跳失败（不阻塞本轮）", zap.String("runId", runID), zap.Error(err))
				}
			}
		}
	}()
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// Record 手工落一行（收尾调用等没有 tool_call/tool_result 事件的步骤）。
func (r *StepRecorder) Record(tool, summary, evidenceRef, outcomeSoFar string) int {
	if r == nil || r.store == nil || r.runID == "" {
		return 0
	}
	r.mu.Lock()
	no := r.nextLocked()
	r.mu.Unlock()
	r.write(&Step{
		RunID:        r.runID,
		StepNo:       no,
		ToolName:     oneLineText(tool, 80),
		Summary:      oneLineText(summary, stepPreviewRunes),
		EvidenceRef:  clipEvidenceRef(evidenceRef),
		OutcomeSoFar: outcomeSoFar,
	})
	return no
}

// NextStepNo 返回下一个 step_no（只读观测用；不占用序号）。
func (r *StepRecorder) NextStepNo() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seq
}

func (r *StepRecorder) nextLocked() int {
	r.seq++
	if r.seq > maxRecordedSteps {
		r.seq = maxRecordedSteps
	}
	return r.seq
}

func (r *StepRecorder) recordToolCall(message string, data interface{}) {
	if r == nil || r.store == nil || r.runID == "" {
		return
	}
	m := toMap(data)
	tool := firstNonEmpty(asText(m["toolName"]), toolNameFromMessage(message), "tool")
	args := firstNonEmpty(asText(m["arguments"]), mustJSON(m["argumentsObj"]))
	id := asText(m["toolCallId"])

	r.mu.Lock()
	no := r.nextLocked()
	if id != "" {
		r.open[id] = no
	}
	r.mu.Unlock()

	r.write(&Step{
		RunID:        r.runID,
		StepNo:       no,
		ToolName:     oneLineText(tool, 80),
		ArgsHash:     shortHash(args),
		Summary:      oneLineText(tool+" "+compactArgSummary(args), stepPreviewRunes),
		OutcomeSoFar: "running",
	})
}

func (r *StepRecorder) recordToolResult(message string, data interface{}) {
	if r == nil || r.store == nil || r.runID == "" {
		return
	}
	m := toMap(data)
	tool := firstNonEmpty(asText(m["toolName"]), toolNameFromMessage(message), "tool")
	id := asText(m["toolCallId"])
	result := firstNonEmpty(asText(m["result"]), asText(m["resultPreview"]), asText(m["output"]))
	evidence := ExtractEvidenceRefForTool(tool, result)

	r.mu.Lock()
	no, ok := r.open[id]
	if !ok || id == "" {
		no = r.nextLocked()
		if id != "" {
			r.open[id] = no
		}
	}
	delete(r.open, id)
	r.mu.Unlock()

	summary := tool + " ← " + oneLineText(result, stepPreviewRunes)
	if strings.TrimSpace(result) == "" {
		summary = tool + " ← （无输出）"
	}
	r.write(&Step{
		RunID:        r.runID,
		StepNo:       no,
		ToolName:     oneLineText(tool, 80),
		Summary:      summary,
		EvidenceRef:  clipEvidenceRef(evidence),
		OutcomeSoFar: "ok",
	})
}

func (r *StepRecorder) write(st *Step) {
	if st == nil || r.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.base), 5*time.Second)
	defer cancel()
	if err := r.store.AppendStep(ctx, st); err != nil {
		if r.logger != nil {
			r.logger.Warn("zhulong: 步骤落库失败（不阻塞本轮）",
				zap.String("runId", r.runID), zap.Int("stepNo", st.StepNo), zap.Error(err))
		}
	}
}

// DefaultSkillRoot 是技能根目录的兜底（平台 skills_dir 的生产取值）。
const DefaultSkillRoot = "/home/kali/work/skills"

// skillDirHintPattern 匹配 skill 工具输出里的目录自述行（适配器/Load 的稳定文案）。
var skillDirHintPattern = regexp.MustCompile(`此 ?Skill 的目录[:：]\s*([^\s"'<>()（）]+)`)

// skillMDPattern 匹配 `<...>/<name>/SKILL.md` 形态（取技能目录名）。
var skillMDPattern = regexp.MustCompile(`(?:^|[\s/"'(:：])((?:/[\w.@+-]+)*(?:/[\w.@+-]+)?/SKILL\.md)`)

// ExtractEvidenceRefForTool 按工具类型取证据引用。
//
// skill 的失败模式（2026-11-06 实测）：技能正文/文件树里满是 `references/xxx.md` 这类
// **相对片段**，通用的"从输出猜最后一个路径"会挑出 `/skill-as-boost.md` 这种不存在的碎片，
// 4 条 skill 步的 evidence_ref 全部失真。所以 skill 一律用「技能目录」做 ref：
//  1. 输出里的「此 Skill 的目录：<path>」自述行（真实目录，且 SKILL.md 存在）；
//  2. 否则 `<skillsRoot>/<name>`（name 取自 .../<name>/SKILL.md 形态），目录存在才算；
//  3. 都不成立 → 空（宁可不给 ref，也不写假路径）。
func ExtractEvidenceRefForTool(tool, text string) string {
	if strings.EqualFold(strings.TrimSpace(tool), "skill") {
		if ref := ExtractSkillDirRef(text); ref != "" {
			return ref
		}
		return ""
	}
	return ExtractEvidenceRef(text)
}

// ExtractSkillDirRef 从 skill 工具输出里解析出**真实存在**的技能目录。
func ExtractSkillDirRef(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if m := skillDirHintPattern.FindAllStringSubmatch(text, 16); len(m) > 0 {
		for i := len(m) - 1; i >= 0; i-- {
			if dir := strings.TrimSpace(strings.TrimRight(m[i][1], "。,.；;、)")); dir != "" && dirIsSkill(dir) {
				return dir
			}
		}
	}
	for _, m := range skillMDPattern.FindAllStringSubmatch(text, 16) {
		p := strings.TrimSpace(m[1])
		dir := strings.TrimSuffix(p, "/SKILL.md")
		if dirIsSkill(dir) {
			return dir
		}
		// 相对形态（references/…/SKILL.md）也可能出现：只在技能根下试解析。
		if !strings.HasPrefix(dir, "/") {
			if cand := DefaultSkillRoot + "/" + strings.TrimSuffix(strings.TrimPrefix(dir, "/"), "/"); dirIsSkill(cand) {
				return cand
			}
		}
	}
	return ""
}

// dirIsSkill 报告 path 是真实存在的技能目录（含 SKILL.md）。
func dirIsSkill(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	if err != nil || !st.IsDir() {
		return false
	}
	if _, err := os.Stat(filepath.Join(path, "SKILL.md")); err != nil {
		return false
	}
	return true
}

// ExtractEvidenceRef 从工具输出里挑一条"可复核的证据引用"：优先落盘绝对路径，其次 http(s) URL。
//
// 取**最后一个**匹配：工具通常把本轮产物路径打在末尾（stdout 尾部 / 落盘提示）。
// skill 工具有专门的取法（见 ExtractEvidenceRefForTool）：先认「此 Skill 的目录」自述行。
func ExtractEvidenceRef(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if ref := ExtractSkillDirRef(text); ref != "" {
		return ref
	}
	if m := stepEvidencePathPattern.FindAllString(text, 32); len(m) > 0 {
		return m[len(m)-1]
	}
	if m := stepEvidenceURLPattern.FindAllString(text, 32); len(m) > 0 {
		return strings.TrimRight(m[len(m)-1], ".,;:")
	}
	return ""
}

func clipEvidenceRef(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) > stepEvidenceMaxRunes {
		return string(r[:stepEvidenceMaxRunes])
	}
	return s
}

func compactArgSummary(args string) string {
	args = strings.Join(strings.Fields(args), " ")
	args = strings.ReplaceAll(args, `"`, "")
	if args == "" {
		return ""
	}
	return oneLineText(args, 160)
}

func toolNameFromMessage(message string) string {
	// 形如 "正在调用工具: forecast" / "工具结果 (forecast)"
	if i := strings.LastIndex(message, ":"); i >= 0 && strings.Contains(message, "调用工具") {
		return strings.TrimSpace(message[i+1:])
	}
	if i, j := strings.Index(message, "("), strings.LastIndex(message, ")"); i >= 0 && j > i {
		return strings.TrimSpace(message[i+1 : j])
	}
	return ""
}

func toMap(v interface{}) map[string]interface{} {
	switch t := v.(type) {
	case nil:
		return map[string]interface{}{}
	case map[string]interface{}:
		return t
	}
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]interface{}{}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]interface{}{}
	}
	return m
}

func asText(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return mustJSON(t)
	}
}

func mustJSON(v interface{}) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	if string(b) == "null" || string(b) == "{}" {
		return ""
	}
	return string(b)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func shortHash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}
