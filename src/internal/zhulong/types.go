// Package zhulong 实现「烛龙（Zhulong）」闭环模式的内核：目标驱动、短轮执行、
// 状态外置（存表，不存聊天历史）、每轮以结构化回执收口。
//
// 本包刻意不 import internal/loop2：执行层通过 RunTurn 注入的闭包调用，
// 保证方向为 multiagent → zhulong 单向依赖，避免循环引用。
package zhulong

import "time"

// Outcome 是一轮 run 的最终结论，写在回执的 outcome 字段里。
type Outcome string

const (
	// OutcomeDone 本轮产出了可交付结论（必须带 evidence_refs），
	// 且必须同时满足交付前置：open 链=0、至少一条链锚定目标自身、闸门 PASS。
	// 前置由代码判定（见 Receipt.ValidateAgainstChains / DecideDelivery），不信模型自报。
	OutcomeDone Outcome = "done"
	// OutcomeNothing 本轮确认无事可做——合法结论，不打扰人。
	OutcomeNothing Outcome = "nothing"
	// OutcomeBlocked 卡在需要人/外部条件的地方，已通过 asks 提出（必须带 asks）。
	OutcomeBlocked Outcome = "blocked"
	// OutcomeFailed 本轮失败，可按退避重试（不产生任何业务副作用）。
	OutcomeFailed Outcome = "failed"
	// OutcomeContinue 本轮有进展但**不构成交付**：链还没推完 / 闸门非 PASS /
	// 或 done 被判据打回。它是"接着跑"的信号（run 状态 continue_pending），
	// 不是失败也不是完成，自动续轮据此排下一轮（2026-11-05 M1 新增）。
	OutcomeContinue Outcome = "continue"
)

// Valid 报告 outcome 是否属于合法取值（五个：done/nothing/blocked/failed/continue）。
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeDone, OutcomeNothing, OutcomeBlocked, OutcomeFailed, OutcomeContinue:
		return true
	}
	return false
}

// RunState 是 run 在状态机里的位置。
type RunState string

const (
	StateQueued    RunState = "queued"
	StateRunning   RunState = "running"
	StateDone      RunState = "done"
	StateNothing   RunState = "nothing"
	StateBlocked   RunState = "blocked"
	StateFailed    RunState = "failed"
	StateCancelled RunState = "cancelled"
	// StateUnknown 心跳超时但进程可能还活着：只标记，不自动重派。
	StateUnknown RunState = "unknown"
	// StateContinuePending 本轮没交卷（done 被确定性判据打回 / 链还没推完）：
	// 不是终态，自动续轮（autocontinue）会接着排下一轮。
	StateContinuePending RunState = "continue_pending"
)

// Terminal 报告该状态是否已终结（不再占用目标槽位）。
//
// continue_pending 刻意**不**算终态：它是"还没完，系统会接着跑"。
func (s RunState) Terminal() bool {
	switch s {
	case StateDone, StateNothing, StateFailed, StateCancelled:
		return true
	}
	return false
}

// Ask 是回执里向人提出的问题；落成卡片等待回答，回答变成新事件再派发。
type Ask struct {
	Title   string   `json:"title"`
	Text    string   `json:"text,omitempty"`
	Options []string `json:"options,omitempty"`
	Key     string   `json:"key"`
}

// Receipt 是每一轮必须交回的窄接口（字段白名单，未知字段即拒）。
type Receipt struct {
	Outcome      Outcome  `json:"outcome"`
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	NextActions  []string `json:"next_actions,omitempty"`
	Asks         []Ask    `json:"asks,omitempty"`
	Facts        []string `json:"facts,omitempty"`
}

// Goal 是一次闭环的目标与操作约束（约束里的指代词必须已还原成具体值）。
type Goal struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversation_id"`
	Objective      string    `json:"objective"`
	Constraints    []string  `json:"constraints,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Run 是一轮闭环执行的记录。
type Run struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversation_id"`
	GoalID         string    `json:"goal_id"`
	State          RunState  `json:"state"`
	Attempt        int       `json:"attempt"`
	StepBudget     int       `json:"step_budget"`
	MinuteBudget   int       `json:"minute_budget"`
	Summary        string    `json:"summary,omitempty"`
	ReceiptJSON    string    `json:"receipt_json,omitempty"`
	ResultHash     string    `json:"result_hash,omitempty"`
	NotBefore      time.Time `json:"not_before,omitempty"`
	SeenAt         time.Time `json:"seen_at,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	FinishedAt     time.Time `json:"finished_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// Step 是一条结构化进度（状态的一部分，压缩后仍在）。
type Step struct {
	RunID        string `json:"run_id"`
	StepNo       int    `json:"step_no"`
	ToolName     string `json:"tool_name"`
	ArgsHash     string `json:"args_hash,omitempty"`
	Summary      string `json:"summary,omitempty"`
	EvidenceRef  string `json:"evidence_ref,omitempty"`
	OutcomeSoFar string `json:"outcome_so_far,omitempty"`
}

// DefaultStepBudget / DefaultMinuteBudget 是 M0 的轮预算默认值（可被配置覆盖）。
const (
	DefaultStepBudget   = 60
	DefaultMinuteBudget = 25
)
