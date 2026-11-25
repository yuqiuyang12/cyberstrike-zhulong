package loop2

// zhulong_hold_test.go —— P3 前置：hold_continue_until_min 的接线判据（task-10，2026-11-06）。
//
// 五组验收（对应 task-10 的单测要求）：
//  1. hold=off → 计划恒为 false（逐字节回归锚点，循环体只跑一次）；
//  2. hold=on + continue@5min → hold=true（同一 run 续跑一段）；
//  3. hold=on + continue@31min → hold=false（跑满最短轮，正常收口）；
//  4. hold=on + blocked@5min → hold=false（阻塞不逼空转）；
//  5. hold=on + 步数触顶 → hold=false（触顶优先 settlement）；
// 另加：取消/墙钟到点、inner run 报错、坏回执、hold 上限都不 hold。

import (
	"context"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/zhulong"
)

func rc(outcome zhulong.Outcome, summary string, next ...string) *zhulong.Receipt {
	return &zhulong.Receipt{Outcome: outcome, Summary: summary, NextActions: next}
}

func TestHoldContinuePlan(t *testing.T) {
	const min = 30 * time.Minute
	cases := []struct {
		name      string
		hold      bool
		receipt   *zhulong.Receipt
		elapsed   time.Duration
		stepsUsed int
		stepMax   int
		ctxErr    error
		runErr    error
		round     int
		want      bool
		wantWhy   string
	}{
		// ① hold=off 回归：任何输入都不 hold（循环体只跑一次 = 与历史行为逐字节一致）
		{name: "off-continue-5min", hold: false, receipt: rc(zhulong.OutcomeContinue, "下一台阶"), elapsed: 5 * time.Minute, want: false, wantWhy: "disabled"},
		{name: "off-done-1min", hold: false, receipt: rc(zhulong.OutcomeDone, "交付"), elapsed: time.Minute, want: false, wantWhy: "disabled"},

		// ② continue@5min → hold
		{name: "on-continue-5min", hold: true, receipt: rc(zhulong.OutcomeContinue, "下一台阶", "试 rung=2"), elapsed: 5 * time.Minute, want: true, wantWhy: "hold"},
		// ③ continue@31min → 正常收口
		{name: "on-continue-31min", hold: true, receipt: rc(zhulong.OutcomeContinue, "下一台阶"), elapsed: 31 * time.Minute, want: false, wantWhy: "min_reached"},
		// ④ blocked@5min → 正常收口（不逼模型空转）
		{name: "on-blocked-5min", hold: true, receipt: rc(zhulong.OutcomeBlocked, "要账号"), elapsed: 5 * time.Minute, want: false, wantWhy: "outcome"},
		{name: "on-failed-5min", hold: true, receipt: rc(zhulong.OutcomeFailed, "执行失败"), elapsed: 5 * time.Minute, want: false, wantWhy: "outcome"},
		{name: "on-done-5min", hold: true, receipt: rc(zhulong.OutcomeDone, "交付"), elapsed: 5 * time.Minute, want: false, wantWhy: "outcome"},
		// ⑤ 步数触顶优先 settlement
		{name: "on-continue-step-budget", hold: true, receipt: rc(zhulong.OutcomeContinue, "还想继续"), elapsed: 5 * time.Minute, stepsUsed: 400, stepMax: 400, want: false, wantWhy: "step_budget"},
		// 其它短路
		{name: "on-continue-ctx-done", hold: true, receipt: rc(zhulong.OutcomeContinue, "继续"), elapsed: 5 * time.Minute, ctxErr: context.DeadlineExceeded, want: false, wantWhy: "ctx_done"},
		{name: "on-continue-run-error", hold: true, receipt: rc(zhulong.OutcomeContinue, "继续"), elapsed: 5 * time.Minute, runErr: context.Canceled, want: false, wantWhy: "run_error"},
		{name: "on-bad-receipt", hold: true, receipt: nil, elapsed: 5 * time.Minute, want: false, wantWhy: "no_receipt"},
		{name: "on-max-holds", hold: true, receipt: rc(zhulong.OutcomeContinue, "继续"), elapsed: 5 * time.Minute, round: 4, want: false, wantWhy: "max_holds"},
		{name: "on-no-min-round", hold: true, receipt: rc(zhulong.OutcomeContinue, "继续"), elapsed: 5 * time.Minute, wantWhy: "hold"}, // 由调用方传入 min；见下方单独断言
	}
	for _, c := range cases[:len(cases)-1] {
		got, why := holdContinuePlan(c.hold, c.receipt, c.elapsed, min, c.stepsUsed, c.stepMax, c.ctxErr, c.runErr, c.round, 4)
		if got != c.want || why != c.wantWhy {
			t.Fatalf("%s: hold=%v why=%q, want %v/%q", c.name, got, why, c.want, c.wantWhy)
		}
	}

	// 未配最短轮（min=0）→ 不 hold，理由 no_min_round。
	if got, why := holdContinuePlan(true, rc(zhulong.OutcomeContinue, "继续"), 5*time.Minute, 0, 0, 400, nil, nil, 0, 4); got || why != "no_min_round" {
		t.Fatalf("min=0 应不 hold (no_min_round), 实际 %v/%q", got, why)
	}
}

// hold=off 的"逐字节回归"锚点：计划恒 false，且续跑提示不会被构造出来（无副作用）。
func TestHoldOffNoContinuationPrompt(t *testing.T) {
	// 关掉配置时，判据对所有 outcome/时长组合都返回 false。
	for _, outcome := range []zhulong.Outcome{zhulong.OutcomeContinue, zhulong.OutcomeDone, zhulong.OutcomeBlocked, zhulong.OutcomeFailed, zhulong.OutcomeNothing} {
		for _, elapsed := range []time.Duration{0, time.Minute, 31 * time.Minute} {
			if got, why := holdContinuePlan(false, rc(outcome, "x"), elapsed, 30*time.Minute, 1, 400, nil, nil, 0, 4); got || why != "disabled" {
				t.Fatalf("hold=off 必须 disabled: outcome=%s elapsed=%s → %v/%q", outcome, elapsed, got, why)
			}
		}
	}
}

// 续跑提示的要点：禁止交回执 + 带上上一段 summary/next_actions + 剩余时间。
func TestBuildHoldContinuePrompt(t *testing.T) {
	prompt := buildHoldContinuePrompt(
		rc(zhulong.OutcomeContinue, "已确认 rung=1 泄露，准备推 rung=2", "试 /api/order/export", "换编码试 id"),
		18*time.Minute)
	for _, want := range []string{"hold_continue_until_min", "不要交回执", "不要写 zhulong 回执块", "18", "试 /api/order/export", "同一条链"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("续跑提示缺 %q:\n%s", want, prompt)
		}
	}
	// nil 回执也要能出提示（不 panic）。
	if p := buildHoldContinuePrompt(nil, -time.Minute); !strings.Contains(p, "不要交回执") {
		t.Fatalf("nil 回执提示异常: %q", p)
	}
}

// config 门控默认关闭：零值 ZhulongConfig 必须关（否则 P3 一上线就改默认行为）。
func TestHoldContinueConfigDefaultOff(t *testing.T) {
	var cfg config.ZhulongConfig
	if cfg.HoldContinueUntilMin {
		t.Fatal("ZhulongConfig 零值必须 hold_continue_until_min=false")
	}
}
