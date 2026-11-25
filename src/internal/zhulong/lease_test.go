package zhulong

import (
	"context"
	"testing"
	"time"
)

// 防的失败方式：
//  1. 失联的 run 永远卡在 running（cnvd 会话实证：4 轮里 2 轮卡死）
//  2. 清扫把还在跑的 run 误标（重派 → 双跑）
//  3. 清扫把已收口的 run 改掉
func TestSweepStale(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// 三条 run：stale(running, 心跳很旧) / fresh(running, 心跳新鲜) / done(已收口)
	for _, id := range []string{"stale", "fresh", "done"} {
		if err := s.CreateRun(ctx, &Run{ID: id, ConversationID: "c", GoalID: "g"}); err != nil {
			t.Fatal(err)
		}
		if err := s.StartRun(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	// 手工把 stale 的心跳改到 1 小时前，done 收口
	old := time.Now().UTC().Add(-time.Hour).Format(tsLayout)
	if _, err := s.db.Exec(`UPDATE zhulong_runs SET seen_at=? WHERE id='stale'`, old); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, "done", StateDone, "{}", "ok", "h1"); err != nil {
		t.Fatal(err)
	}

	marked, err := s.SweepStale(ctx, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(marked) != 1 || marked[0] != "stale" {
		t.Fatalf("只应标记 stale，实际 %v", marked)
	}
	for id, want := range map[string]RunState{"stale": StateUnknown, "fresh": StateRunning, "done": StateDone} {
		got, _ := s.GetRun(ctx, id)
		if got.State != want {
			t.Fatalf("%s 状态应为 %s，实际 %s", id, want, got.State)
		}
	}
}

func TestSweepStaleFallsBackToStartedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateRun(ctx, &Run{ID: "nohb", ConversationID: "c", GoalID: "g"}); err != nil {
		t.Fatal(err)
	}
	// running 但从未上报心跳：seen_at='' ，应回落到 started_at
	if err := s.StartRun(ctx, "nohb"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-time.Hour).Format(tsLayout)
	if _, err := s.db.Exec(`UPDATE zhulong_runs SET seen_at='', started_at=? WHERE id='nohb'`, old); err != nil {
		t.Fatal(err)
	}
	marked, err := s.SweepStale(ctx, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(marked) != 1 {
		t.Fatalf("seen_at 为空时应回落到 started_at，实际标记 %v", marked)
	}
}

// 防的失败方式：拒绝过的收口再次生效（终态不允许被清扫改回去）
func TestSweepDoesNotTouchTerminal(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateRun(ctx, &Run{ID: "r", ConversationID: "c", GoalID: "g"}); err != nil {
		t.Fatal(err)
	}
	if err := s.StartRun(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, "r", StateCancelled, "", "用户停止", ""); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-time.Hour).Format(tsLayout)
	if _, err := s.db.Exec(`UPDATE zhulong_runs SET seen_at=? WHERE id='r'`, old); err != nil {
		t.Fatal(err)
	}
	marked, err := s.SweepStale(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(marked) != 0 {
		t.Fatalf("终态不应被清扫，实际 %v", marked)
	}
}
