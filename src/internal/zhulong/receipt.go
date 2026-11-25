package zhulong

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ReceiptLangTag 是回执代码块的语言标记（```zhulong）。
const ReceiptLangTag = "zhulong"

var (
	// ErrMissingReceipt 表示整段输出里找不到回执块。
	ErrMissingReceipt = errors.New("zhulong: 缺少回执块")
	// ErrInvalidReceipt 表示回执块存在但内容不合法（外层用 %w 包装）。
	ErrInvalidReceipt = errors.New("zhulong: 回执不合法")

	askKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	fencePattern  = regexp.MustCompile("(?s)```([A-Za-z0-9_-]*)[ \t]*\r?\n(.*?)```")
)

// ValidationError 描述回执里具体哪个字段不合法。
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("回执字段 %s 不合法: %s", e.Field, e.Reason)
}

func (e *ValidationError) Unwrap() error { return ErrInvalidReceipt }

// 回执长度上限，防止模型把整段报告塞进 summary。
const (
	maxSummaryRunes  = 4000
	maxEvidenceRefs  = 50
	maxRefRunes      = 500
	maxAsks          = 8
	maxAskOptions    = 8
	maxNextActions   = 20
	maxFacts         = 50
	maxReceiptBlocks = 64 // 只用于限制扫描量
)

// ParseReceipt 从模型最后一条回复里取"最后一个" ```zhulong 代码块并解析。
//
// 取最后一个的原因：模型常在正文里先复述一遍模板；最后一个才是本轮真正的回执。
// 若没有 ```zhulong 块，则退而取"最后一个含 outcome 字段的 ```json 块"，兼容模型改标记。
func ParseReceipt(text string) (*Receipt, error) {
	block, ok := lastFencedBlock(text, ReceiptLangTag)
	if !ok {
		block, ok = lastJSONBlockWithOutcome(text)
	}
	if !ok {
		return nil, ErrMissingReceipt
	}
	return decodeReceipt(block)
}

// ParseReceiptAgainstChains 解析回执并**立刻**做链台账硬校验（严格入口）。
//
// 与 ParseReceipt 的区别：ParseReceipt 只看回执自身是否自洽（schema + 语义），
// 而这里还要求 outcome=done 时 open 链为 0 且至少一条链锚定目标自身。
//
// 注意：烛龙 loop 的收口路径刻意**不用**这个严格入口——它把"不够交付"当成
// continue（继续跑）而不是 failed（停止跑）；本函数给需要"直接拒收"的调用方
// （离线验收、单测、外部审计）使用。
func ParseReceiptAgainstChains(text string, f ChainFacts) (*Receipt, error) {
	r, err := ParseReceipt(text)
	if err != nil {
		return nil, err
	}
	if verr := r.ValidateAgainstChains(f); verr != nil {
		return nil, verr
	}
	return r, nil
}

// lastFencedBlock 返回最后一个语言标记匹配（大小写不敏感）的代码块内容。
func lastFencedBlock(text, lang string) (string, bool) {
	matches := fencePattern.FindAllStringSubmatch(text, maxReceiptBlocks)
	var out string
	found := false
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(m[1]), lang) {
			continue
		}
		out = m[2]
		found = true
	}
	return out, found
}

// lastJSONBlockWithOutcome 是标记写错时的兜底：最后一个含 "outcome" 的 json 块。
func lastJSONBlockWithOutcome(text string) (string, bool) {
	matches := fencePattern.FindAllStringSubmatch(text, maxReceiptBlocks)
	var out string
	found := false
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		tag := strings.ToLower(strings.TrimSpace(m[1]))
		if tag != "json" && tag != "" {
			continue
		}
		if !strings.Contains(m[2], `"outcome"`) {
			continue
		}
		out = m[2]
		found = true
	}
	return out, found
}

func decodeReceipt(block string) (*Receipt, error) {
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(block)))
	dec.DisallowUnknownFields()
	var r Receipt
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: JSON 解析失败: %v", ErrInvalidReceipt, err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Validate 按字段白名单与语义规则校验回执。
func (r *Receipt) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: 空回执", ErrInvalidReceipt)
	}
	if !r.Outcome.Valid() {
		return &ValidationError{Field: "outcome", Reason: fmt.Sprintf("必须是 done/nothing/blocked/failed/continue 之一，实际 %q", string(r.Outcome))}
	}
	r.Summary = strings.TrimSpace(r.Summary)
	if r.Summary == "" {
		return &ValidationError{Field: "summary", Reason: "不能为空"}
	}
	if utf8.RuneCountInString(r.Summary) > maxSummaryRunes {
		return &ValidationError{Field: "summary", Reason: fmt.Sprintf("超过 %d 字符", maxSummaryRunes)}
	}
	if len(r.EvidenceRefs) > maxEvidenceRefs {
		return &ValidationError{Field: "evidence_refs", Reason: fmt.Sprintf("超过 %d 条", maxEvidenceRefs)}
	}
	for i, ref := range r.EvidenceRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return &ValidationError{Field: fmt.Sprintf("evidence_refs[%d]", i), Reason: "为空"}
		}
		if utf8.RuneCountInString(ref) > maxRefRunes {
			return &ValidationError{Field: fmt.Sprintf("evidence_refs[%d]", i), Reason: "过长"}
		}
		if !looksLikeEvidenceRef(ref) {
			return &ValidationError{Field: fmt.Sprintf("evidence_refs[%d]", i),
				Reason: "必须是绝对路径（/...）、http(s) URL 或带 scheme 的 URI；不接受一句话当证据"}
		}
		r.EvidenceRefs[i] = ref
	}
	if len(r.NextActions) > maxNextActions {
		return &ValidationError{Field: "next_actions", Reason: fmt.Sprintf("超过 %d 条", maxNextActions)}
	}
	if len(r.Facts) > maxFacts {
		return &ValidationError{Field: "facts", Reason: fmt.Sprintf("超过 %d 条", maxFacts)}
	}
	// 语义约束：done 必须有证据；blocked 必须有 ask；failed 只是失败，不得带副作用。
	switch r.Outcome {
	case OutcomeDone:
		if len(r.EvidenceRefs) == 0 {
			return &ValidationError{Field: "evidence_refs", Reason: "outcome=done 时必须给出至少一条证据引用"}
		}
	case OutcomeBlocked:
		if len(r.Asks) == 0 {
			return &ValidationError{Field: "asks", Reason: "outcome=blocked 时必须至少提出一个问题"}
		}
	case OutcomeFailed:
		if len(r.Asks) > 0 {
			return &ValidationError{Field: "asks", Reason: "outcome=failed 时不得提问（失败域隔离：只允许通知）"}
		}
		if len(r.Facts) > 0 {
			return &ValidationError{Field: "facts", Reason: "outcome=failed 时不得写事实（失败域隔离）"}
		}
	}
	if len(r.Asks) > maxAsks {
		return &ValidationError{Field: "asks", Reason: fmt.Sprintf("超过 %d 条", maxAsks)}
	}
	for i := range r.Asks {
		a := &r.Asks[i]
		a.Title = strings.TrimSpace(a.Title)
		if a.Title == "" {
			return &ValidationError{Field: fmt.Sprintf("asks[%d].title", i), Reason: "不能为空"}
		}
		if len(a.Options) > maxAskOptions {
			return &ValidationError{Field: fmt.Sprintf("asks[%d].options", i), Reason: fmt.Sprintf("超过 %d 个选项", maxAskOptions)}
		}
		if len(a.Options) > 0 && len(a.Options) < 2 {
			return &ValidationError{Field: fmt.Sprintf("asks[%d].options", i), Reason: "要么不给选项，要么至少两个"}
		}
		key := strings.TrimSpace(a.Key)
		if key == "" {
			return &ValidationError{Field: fmt.Sprintf("asks[%d].key", i), Reason: "不能为空（回答要靠它唤醒同一目标）"}
		}
		if !askKeyPattern.MatchString(key) {
			return &ValidationError{Field: fmt.Sprintf("asks[%d].key", i), Reason: "只允许字母数字与 . _ -，且以字母数字开头"}
		}
		a.Key = key
	}
	return nil
}

// MarshalReceipt 把回执序列化成落库用的紧凑 JSON。
func MarshalReceipt(r *Receipt) (string, error) {
	if r == nil {
		return "", nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ReceiptContract 是写进系统提示的回执契约正文（对所有模型统一口径，短句优先）。
//
// 2026-11-05 M1 改口径：done 不再是"本轮有可交付结论"（那是老 bug 的根因：
// 交委实测 4 次闸门 CONTINUE 仍判 done），而是"构成交付"——open 链归零、
// 至少一条链锚定到目标自身、闸门 PASS，三者缺一就交 continue。
const ReceiptContract = `## 本轮必须交回执（硬要求）

本模式是「目标特定的短轮闭环」：一轮 = 把一条链推进一个台阶，**必须**在最后一条回复里交一个回执，否则本轮判失败。

格式：正文照常写给用户看的结论，然后**另起一行**，在消息最末尾放一个 ` + "```zhulong" + ` 代码块：

` + "```zhulong" + `
{"outcome":"continue","summary":"一句话结论","evidence_refs":["/绝对/证据路径"],"next_actions":["推进链 zl-chain-xx（rung=1→2）：<目标自己的接口/参数>"],"asks":[],"facts":["fact/key"]}
` + "```" + `

字段（只允许这几个，写别的字段整份回执作废）：
- outcome：必填，只能是 done / continue / nothing / blocked / failed
  - done：**构成交付**才可用。必须同时满足四条：①至少 1 条 evidence_refs；②open 链 = 0；
    ③至少一条链锚定到目标自身（target_model_ref 非空，或 hypothesis_type 属 business-logic / own-code /
    own-contract / diff-probe）；④deliver_gate 首行 GATE=PASS。任一不满足请直接交 continue——
    系统会按台账与闸门**用代码复核**，不符合的 done 会被打回成 continue（不算你的失败，但浪费一轮）。
  - continue：本轮有进展但未构成交付（链推到一半、闸门非 PASS、假设待验）→ 不是失败，
    系统会接着排下一轮；next_actions 写清下一轮推哪条链的哪个台阶。
  - nothing：本轮确认无事可做（合法结论，不会打扰人）
  - blocked：卡住了要人拍板 → **必须**给 asks
  - failed：本轮没干成 → **不得**带 asks，**不得**写 facts
- summary：必填，一句话（不超过 4000 字，不要长篇报告）
- evidence_refs：证据的绝对路径或 URL（req/resp/截图/日志落盘文件）
- next_actions：下一轮做什么（数组，可为空）。**每一项都必须是目标特定的**：写清该目标自己的
  路径/参数/业务对象/代码位置；不要写"补覆盖""扫剩下的面"这类通用项（会被判据打回）。
- asks：需要人拍板的问题，每项 {"title","text","options":["A","B"],"key":"stable-key"}
- facts：本轮写入的项目事实键（数组，可为空）

铁律：
1. 不要为了凑回执而编造证据；没有证据就报 nothing 或 blocked。
2. 回执块只写一个，放在消息最末尾。
3. 写错字段名会被直接拒绝，本轮不算完成。
4. open 链 > 0 时交 done 一律作废：先把链推到 exploited，或用拦截原始报文 zl_chain_close(state=blocked) 证伪。
5. 只有"通用 n-day / 清单式"线索、没有一条锚定目标自身时，也算没交付——去建目标模型再开链。`

// ChainFacts 是"能不能交卷"所需的链台账事实，由 ChainStore 采集后注入。
//
// 单独定义成纯数据：回执校验不依赖具体存储实现，可离线单测（这是"确定性判据下沉到代码"的前提）。
type ChainFacts struct {
	Total     int // 该会话的链总数
	Open      int // state=open
	Exploited int // state=exploited
	Depth     int // 全部链的最大 rung（0..6）
	// Anchored 是"锚定到目标自身"的链数：target_model_ref 非空，或 hypothesis_type 属
	// business-logic / own-code / own-contract / diff-probe。通用 n-day/清单不算。
	// 现场采集直接取 ChainStore.Stats 的第 5 个返回值（specific），口径只有一处实现。
	Anchored int
	// ConfirmedVulns 是该会话已确认的中/高危漏洞数（severity ∈ critical/high/medium 且 status<>fixed）。
	// 它是锚定规则的**防死锁开关**：干净目标（0 洞 0 链）根本不可能有锚定链，
	// 硬要求会把它永久卡在 continue；有洞却不肯按目标业务推链时才拦。
	ConfirmedVulns int
}

// needsAnchoredChain 报告本轮是否必须"有至少一条锚定目标自身的链"才能交 done。
//
// 防死锁：既没有链、也没有确认漏洞 → 这是一次纯侦察交付，交给覆盖率闸门判；
// 只要有链（说明确实做过链的工作）或有洞（说明有该深挖的东西），就必须有锚定链。
func (f ChainFacts) needsAnchoredChain() bool {
	return f.Total > 0 || f.ConfirmedVulns > 0
}

// GateVerdictPass 与 internal/app 的同名常量对齐（multiagent 不能 import app，避免循环依赖）。
const GateVerdictPass = "PASS"

// ValidateAgainstChains 在回执解析之后做**确定性交叉校验**（不信模型自报）：
// outcome==done 时 open 链必须为 0，且至少一条链锚定目标自身。任一不满足即回执非法。
//
// 错误文案是给模型看的下一步指令，不写"校验失败"这种空话。
func (r *Receipt) ValidateAgainstChains(f ChainFacts) error {
	if r == nil || r.Outcome != OutcomeDone {
		return nil
	}
	if f.Open > 0 {
		return &ValidationError{Field: "outcome",
			Reason: fmt.Sprintf("仍有 %d 条 open 链（total=%d exploited=%d 最深 rung=%d/6），先推进或证伪再交 done",
				f.Open, f.Total, f.Exploited, f.Depth)}
	}
	if f.Anchored == 0 && f.needsAnchoredChain() {
		return &ValidationError{Field: "outcome",
			Reason: "本轮没有一条链锚定到目标自身模型，通用 n-day/清单不算交付：" +
				"先建目标模型（target/<asset>-model）并用 zl_chain_open 开一条带 target_model_ref 或 " +
				"hypothesis_type∈{business-logic,own-code,own-contract,diff-probe} 的链"}
	}
	return nil
}

// NextActionsTargetSpecific 用字符串启发式判断 next_actions 是否"目标特定"：
// 至少一项包含给定锚点（该目标的资产名/主机名/URL 片段，长度 ≥3）。
//
// 锚点为空 = 无法判断 → 返回 true（宁可不错判，也不误伤）。
// 刻意不做关键词表匹配：关键词表会误伤，也会被模型学会绕过。
func (r *Receipt) NextActionsTargetSpecific(anchors []string) bool {
	if r == nil || len(r.NextActions) == 0 {
		return true
	}
	var valid []string
	for _, a := range anchors {
		a = strings.ToLower(strings.TrimSpace(a))
		if len(a) >= 3 {
			valid = append(valid, a)
		}
	}
	if len(valid) == 0 {
		return true
	}
	for _, act := range r.NextActions {
		low := strings.ToLower(act)
		for _, a := range valid {
			if strings.Contains(low, a) {
				return true
			}
		}
	}
	return false
}

// DeliveryReason 是一条"不能交 done"的确定性理由（会写进回执 next_actions 与 run summary）。
type DeliveryReason struct {
	Code string // open-chains | no-anchored-chain | gate-not-pass | unwired-gate | generic-next-actions
	Text string
}

// DecideDelivery 是"本轮 done 能不能成立"的**唯一定性判据**（纯函数，可单测）。
//
// 输入：回执 + 链台账事实 + 闸门结论（gateVerdict 为空 = 闸门未接线）+ 目标锚点。
// 输出：最终 outcome（done 或 continue）+ 打回理由（按优先级排序，供 next_actions 用）。
//
// 规则（顺序即优先级，命中即打回）：
//  1. 非 done 回执原样返回（nothing/blocked/failed/continue 不做交付判定）
//  2. open 链 > 0                        → continue open-chains
//  3. 没有一条锚定目标自身的链            → continue no-anchored-chain
//  4. 闸门未接线（gateVerdict==""）        → continue unwired-gate（保守：无闸门不交卷）
//  5. 闸门非 PASS                        → continue gate-not-pass
//  6. next_actions 全部不含目标锚点        → continue generic-next-actions
//
// RoundWindow 是本轮的时长窗口（最短轮时长规则用）。
type RoundWindow struct {
	ElapsedMin float64 // 本轮已跑分钟数
	MinMin     float64 // 最少分钟数（<=0 表示不限制）
}

// HoldContinueDecision 报告「模型自主 continue 是否应被最短轮拦板 hold 回同一轮」（P3 前置）。
//
// 口径（配置门控，默认关闭；关闭时**恒 false** —— 这是 hold=off 逐字节回归的锚点）：
//   - hold 关 / minDuration<=0 → false；
//   - 只有 outcome=continue 才可能被 hold：done/nothing/blocked/failed 各有自己的语义，
//     一律不 hold（done 的「未到最短轮」拦板在 DecideDelivery 里，别在这里重复）；
//   - elapsed >= minDuration → false（已经跑满最短轮，正常收口）。
//
// 触顶（步数/墙钟）、取消、坏回执都在调用方（orchestrator 的 holdContinuePlan）先短路，
// 本函数只表达"continue + 未到最短轮"这一条。
func HoldContinueDecision(hold bool, outcome Outcome, elapsed, minDuration time.Duration) bool {
	if !hold || minDuration <= 0 {
		return false
	}
	if outcome != OutcomeContinue {
		return false
	}
	return elapsed < minDuration
}

func DecideDelivery(r *Receipt, f ChainFacts, gateVerdict, gateReason, gateNext string, anchors []string, win ...RoundWindow) (Outcome, []DeliveryReason) {
	if r == nil {
		return OutcomeFailed, []DeliveryReason{{Code: "empty-receipt", Text: "空回执"}}
	}
	// 最短轮时长（用户 2026-11-05 裁定：烛龙一轮至少 30 分钟、最多 60 分钟）。
	// 只对 done/nothing 生效：blocked(带 asks=人工待办) 与 failed 不受此限。
	if len(win) > 0 && win[0].MinMin > 0 && win[0].ElapsedMin < win[0].MinMin && r.Outcome == OutcomeNothing && f.Open > 0 {
		return OutcomeContinue, []DeliveryReason{{Code: "nothing-with-open-chains",
			Text: fmt.Sprintf("本轮只跑了 %.0f 分钟(<最少 %.0f 分钟)且仍有 %d 条 open 链：nothing 不是合法收口，继续推进链",
				win[0].ElapsedMin, win[0].MinMin, f.Open)}}
	}
	if r.Outcome != OutcomeDone {
		return r.Outcome, nil
	}
	var reasons []DeliveryReason
	if f.Open > 0 {
		reasons = append(reasons, DeliveryReason{Code: "open-chains",
			Text: fmt.Sprintf("仍有 %d 条 open 链，本轮不算交付：逐条推进到 exploited 或带拦截报文 close(blocked)（最深 rung=%d/6）", f.Open, f.Depth)})
	}
	if f.Anchored == 0 && f.needsAnchoredChain() {
		reasons = append(reasons, DeliveryReason{Code: "no-anchored-chain",
			Text: "没有一条链锚定到目标自身模型，通用 n-day/清单不算交付：先建目标模型（target/<asset>-model），再开一条带 target_model_ref / business-logic / own-code / own-contract / diff-probe 的链"})
	}
	v := strings.ToUpper(strings.TrimSpace(gateVerdict))
	switch {
	case v == "":
		reasons = append(reasons, DeliveryReason{Code: "unwired-gate",
			Text: "确定性闸门未接线，本轮不判 done（保守）：先推进链，闸门接线后由 GATE=PASS 放行"})
	case v != GateVerdictPass:
		text := "deliver_gate=" + v
		if s := strings.TrimSpace(gateReason); s != "" {
			text += " reason=" + s
		}
		if s := strings.TrimSpace(gateNext); s != "" {
			text += " → " + s
		}
		reasons = append(reasons, DeliveryReason{Code: "gate-not-pass", Text: text})
	}
	if len(win) > 0 && win[0].MinMin > 0 && win[0].ElapsedMin < win[0].MinMin {
		// 例外：真的做完了（闸门 PASS + 无 open 链 + 有锚定链）允许提前收口，不强行烧满 30 分钟。
		finishedForReal := f.Open == 0 && strings.EqualFold(strings.TrimSpace(gateVerdict), GateVerdictPass) && f.Anchored > 0
		if !finishedForReal {
			reasons = append(reasons, DeliveryReason{Code: "min-round-not-reached",
				Text: fmt.Sprintf("本轮只跑了 %.0f 分钟(<最少 %.0f 分钟)：本轮不算交付，继续推进链/补证据（真的做完需 GATE=PASS + open 链=0 + 锚定链≥1 才可提前收口）",
					win[0].ElapsedMin, win[0].MinMin)})
		}
	}
	if !r.NextActionsTargetSpecific(anchors) {
		reasons = append(reasons, DeliveryReason{Code: "generic-next-actions",
			Text: "next_actions 没有一条指向目标自身的路径/参数/业务对象，下一轮请写到具体端点与参数上"})
	}
	if len(reasons) > 0 {
		return OutcomeContinue, reasons
	}
	return OutcomeDone, nil
}

var evidenceSchemePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// looksLikeEvidenceRef 判断"证据引用"是否可复核：
// 绝对路径、http(s) URL、或带 scheme 的 URI（如 exec://、file://）。
// 目的：拦住模型把"nmap 输出看起来正常"这类自述当成证据。
func looksLikeEvidenceRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "~/") {
		return true
	}
	return evidenceSchemePattern.MatchString(ref)
}

// UnresolvableEvidenceRefs 返回**无法复核**的证据引用（本地路径不存在或不可读）。
//
// 口径（ARTEX evidence/store.go 的移植）：解析阶段只校验形状（绝对路径/URL/带 scheme URI），
// 本函数补上"真实存在"这一层：
//   - 绝对路径、./ 相对路径、~/ 路径、file:// URI → 必须 os.Stat 成功，否则判不可复核；
//   - http(s):// 与其它 scheme URI → 离线无法核验，视为可复核（不误伤）。
//
// 目的：把"看起来像证据"的编造路径挡在 done 之外（打回 continue 让模型补真实落盘证据）。
func UnresolvableEvidenceRefs(refs []string) []string {
	var bad []string
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		path := ""
		switch {
		case strings.HasPrefix(ref, "file://"):
			path = strings.TrimPrefix(ref, "file://")
		case strings.HasPrefix(ref, "~/"):
			home, err := os.UserHomeDir()
			if err != nil {
				bad = append(bad, ref)
				continue
			}
			path = filepath.Join(home, strings.TrimPrefix(ref, "~/"))
		case strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "./"):
			path = ref
		default:
			// scheme:// URL 等：格式已在解析阶段校验，离线不判。
			continue
		}
		if _, err := os.Stat(path); err != nil {
			bad = append(bad, ref)
		}
	}
	return bad
}
