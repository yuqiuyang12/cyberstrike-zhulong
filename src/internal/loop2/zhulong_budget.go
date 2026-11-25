package loop2

// zhulong_budget.go —— 轮预算"触顶"的纯判定（P1 契约⑥：触顶必进 settlement）。
//
// 为什么单独抽出来：wrapper 引擎在 runEinoSingleChatModelAgentNamed 返回后只能靠
// "错误长什么样"推断预算是否耗尽；native turnloop 引擎需要同一判据（否则两套引擎
// 对"触顶"的理解会漂移，契约⑥ 就只在 wrapper 下成立）。抽成纯函数后：
//   - 不依赖 store / agent / 配置，可单测穷举三类触顶源；
//   - settleZhulongRun 直接调用它，行为与抽取前等价（2026-11-06 P0 现役路径）。

import (
	"context"
	"errors"
)

// isZhulongBudgetExhausted 报告本轮是否因预算触顶而结束（步数触顶 / 墙钟到点）。
//
// 三个来源（与 settleZhulongRun 抽取前的判定逐条对应）：
//  1. Eino 迭代上限错误（isEinoIterationLimitError）：step 预算被 maxIterations 卡住，
//     错误文案带 "maximum iterations" / "达到最大迭代" 等；
//  2. runErr 错误链里含 context.DeadlineExceeded：模型/工具调用被单次 deadline 打断，
//     外层再把错误原样带回；
//  3. ctx 的 context.Cause 是 context.DeadlineExceeded：外层 60 分钟墙钟到点
//     （此时 runErr 常常为 nil 或只有 "canceled"，只能看 ctx 的因）。
//
// 注意：context.Canceled（用户点停止）**不算**触顶 —— 取消不进收尾，直接按 cancelled 收口。
func isZhulongBudgetExhausted(runErr error, ctx context.Context) bool {
	if isEinoIterationLimitError(runErr) {
		return true
	}
	if errors.Is(runErr, context.DeadlineExceeded) {
		return true
	}
	if ctx != nil && errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return true
	}
	return false
}
