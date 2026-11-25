package zhulong

import (
	"fmt"
	"strings"
)

// StateBlockInput 是组装"本轮起始状态"所需的全部输入。
// 这块内容每轮开头注入系统提示，让目标/待办/上一轮结论在上下文被压缩后依然在场。
type StateBlockInput struct {
	Objective    string
	Constraints  []string
	Budget       Run
	LastOutcome  string   // 上一轮的 outcome（done/nothing/blocked/failed）
	LastSummary  string   // 上一轮 summary
	Todos        []Todo   // 未完成待办
	RecentSteps  []Step   // 上一轮最近步骤
	OpenAsks     int      // 尚未回答的提问数（有则本轮先别重复问）
	EvidenceRefs []string // 上一轮证据
}

// BuildStateBlock 组装"本轮状态"，并做长度裁剪（默认 6000 字）。
//
// 设计要点（对齐 Claude Code 的"压缩后从磁盘回注"）：
//   - 只放"下一轮真的要用"的东西，不放全量历史；
//   - 结构固定（目标/约束/上一轮/待办/步骤/证据），模型每轮看到同样的形状；
//   - 超长时先砍步骤、再砍证据，**目标与待办永不裁剪**。
func BuildStateBlock(in StateBlockInput, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 6000
	}
	var head, body strings.Builder

	head.WriteString("## 本轮状态（平台状态表，不是聊天历史）\n")
	head.WriteString("- 目标：" + oneLineText(in.Objective, 500) + "\n")
	if len(in.Constraints) > 0 {
		head.WriteString("- 约束（不可违背）：\n")
		for _, c := range in.Constraints {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			head.WriteString("  - " + oneLineText(c, 300) + "\n")
		}
	}
	head.WriteString(fmt.Sprintf("- 本轮预算：%d 步 / %d 分钟\n", in.Budget.StepBudget, in.Budget.MinuteBudget))
	if in.LastOutcome != "" {
		head.WriteString(fmt.Sprintf("- 上一轮结论：%s —— %s\n", in.LastOutcome, oneLineText(in.LastSummary, 300)))
	}
	if in.OpenAsks > 0 {
		head.WriteString(fmt.Sprintf("- 待回答提问：%d 条（同一问题不要重复问，先看能否绕过）\n", in.OpenAsks))
	}

	if len(in.Todos) > 0 {
		body.WriteString("\n## 未完成待办（来自上一轮，按出现顺序）\n")
		for i, t := range in.Todos {
			body.WriteString(fmt.Sprintf("%d. %s\n", i+1, oneLineText(t.Text, 300)))
		}
	}

	tail := strings.Builder{}
	if len(in.RecentSteps) > 0 {
		tail.WriteString("\n## 上一轮步骤（旧→新，可直接引用其中的证据路径）\n")
		for _, st := range in.RecentSteps {
			line := fmt.Sprintf("- [%02d] %s", st.StepNo, st.ToolName)
			if s := strings.TrimSpace(st.Summary); s != "" {
				line += "：" + oneLineText(s, 160)
			}
			if r := strings.TrimSpace(st.EvidenceRef); r != "" {
				line += "（证据：" + oneLineText(r, 200) + "）"
			}
			tail.WriteString(line + "\n")
		}
	}
	if len(in.EvidenceRefs) > 0 {
		tail.WriteString("\n## 上一轮证据引用\n")
		for _, r := range in.EvidenceRefs {
			tail.WriteString("- " + oneLineText(r, 300) + "\n")
		}
	}

	out := head.String() + body.String() + tail.String()
	// 只对整体做头尾裁剪（头和待办在前，不会被砍掉）
	return clipHeadTail(out, maxRunes)
}
