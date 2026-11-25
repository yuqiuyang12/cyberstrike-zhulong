package zhulong

// hold_continue_test.go —— P3 前置：continue 纳入最短轮的纯判据（task-10，2026-11-06）。
//
// 防的失败方式：
//  1. hold 默认关时必须**恒 false**（关闭路径要与历史版本逐字节一致）；
//  2. 把 done/nothing/blocked/failed 也 hold 住 → 逼模型空转、把交付/阻塞卡在最短轮里；
//  3. elapsed 已经跑满最短轮还 hold → 轮次永远收不了尾。

import (
	"testing"
	"time"
)

func TestHoldContinueDecision(t *testing.T) {
	const min = 30 * time.Minute
	cases := []struct {
		name    string
		hold    bool
		outcome Outcome
		elapsed time.Duration
		min     time.Duration
		want    bool
	}{
		// hold=off 回归锚点：任何 outcome/elapsed 都不得 hold（逐字节一致的前提）
		{"off-continue-5min", false, OutcomeContinue, 5 * time.Minute, min, false},
		{"off-continue-31min", false, OutcomeContinue, 31 * time.Minute, min, false},
		{"off-done-5min", false, OutcomeDone, 5 * time.Minute, min, false},
		// hold=on
		{"on-continue-5min", true, OutcomeContinue, 5 * time.Minute, min, true},
		{"on-continue-29m59s", true, OutcomeContinue, min - time.Second, min, true},
		{"on-continue-31min", true, OutcomeContinue, 31 * time.Minute, min, false},
		{"on-continue-exactly-min", true, OutcomeContinue, min, min, false},
		{"on-blocked-5min", true, OutcomeBlocked, 5 * time.Minute, min, false},
		{"on-failed-5min", true, OutcomeFailed, 5 * time.Minute, min, false},
		{"on-done-5min", true, OutcomeDone, 5 * time.Minute, min, false},
		{"on-nothing-5min", true, OutcomeNothing, 5 * time.Minute, min, false},
		// 未配最短轮
		{"on-continue-no-min", true, OutcomeContinue, 5 * time.Minute, 0, false},
		{"on-continue-negative-min", true, OutcomeContinue, 5 * time.Minute, -time.Minute, false},
	}
	for _, c := range cases {
		if got := HoldContinueDecision(c.hold, c.outcome, c.elapsed, c.min); got != c.want {
			t.Fatalf("%s: HoldContinueDecision=%v, want %v", c.name, got, c.want)
		}
	}
}
