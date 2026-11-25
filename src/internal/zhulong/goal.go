package zhulong

// goal.go —— 目标保持（移植自 ARTEX agent/goals.go 的目标不漂移语义）。
//
// 背景：烛龙按会话维护一个持久 Goal（zhulong_goals），每轮会用最新用户消息刷新 objective。
// 但"刷新"在两类场景下会把目标写成无信息量的内容：
//   - 用户只回「继续 / 接着 / 继续推进」；
//   - auto-continue / hold 等系统续轮把生成式提示词当 userMessage 传入。
// 一旦 objective 被"继续"覆盖，下一轮的状态块、边界解析、回执的 next_actions 全部跟着漂移。
//
// 口径：**只有带新信息量的指令才覆盖目标**；纯继续类短消息保留上一轮目标。

import (
	"strings"
)

// continuationWords 是"纯继续"类指令的识别词（先整词替换，再看剩余内容）。
var continuationWords = []string{
	"继续推进", "继续", "接着", "往下", "保持推进", "下一步",
	"continue", "go on", "go ahead",
}

// IsContinuationMessage 报告 s 是否只是"继续"类指令（不含新的目标信息）。
//
// 判定：把继续词与标点/空白全部去掉后为空 → 只是"继续"。
// 「继续深入这个 SQL 注入点」→ 剩余"深入这个 sql 注入点"非空 → 不算纯继续（有信息量的新指令）。
func IsContinuationMessage(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return true
	}
	// 先去掉句末标点，再整词替换继续词。
	t = strings.TrimRight(t, "。.!！?？~～,，;；")
	rest := strings.ToLower(t)
	for _, w := range continuationWords {
		rest = strings.ReplaceAll(rest, strings.ToLower(w), "")
	}
	rest = strings.TrimFunc(rest, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '，', ',', '。', '.', '!', '！', '?', '？',
			'~', '～', ';', '；', ':', '：', '、', '/', '|':
			return true
		}
		return false
	})
	return rest == ""
}

// ObjectiveForNextRound 返回本轮应持久化的目标：
//   - 纯"继续"类消息 → 保留上一轮目标（防目标漂移）；
//   - 为空且没有上一轮目标 → "（空目标）"；
//   - 其它（带新信息量的指令）→ 用本轮消息覆盖。
func ObjectiveForNextRound(prevObjective, incoming string) string {
	in := strings.TrimSpace(incoming)
	if IsContinuationMessage(in) {
		if p := strings.TrimSpace(prevObjective); p != "" {
			return p
		}
		if in == "" {
			return "（空目标）"
		}
		return in
	}
	return in
}
