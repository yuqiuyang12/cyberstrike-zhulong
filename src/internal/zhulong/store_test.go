package zhulong

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// 防的失败方式：
//  1. 建表不幂等 → 重复启动即报错
//  2. run 状态迁移写错 → 库里的状态与进程状态不一致
//  3. 幂等键重复时不报错 → 同一结果被记两次
//  4. 只加自己的表却改了父表 → 破坏平台既有数据
func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "z.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	ctx := context.Background()
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	// 幂等：第二次必须成功
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema 不幂等: %v", err)
	}
	return s
}

func TestStoreRunLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	g := &Goal{ID: "g1", ConversationID: "c1", Objective: "测 example.com 的 80", Constraints: []string{"只测 443 与 80"}}
	if err := s.SaveGoal(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetGoal(ctx, "g1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Objective != g.Objective || len(got.Constraints) != 1 {
		t.Fatalf("goal 回读不一致: %+v", got)
	}

	r := &Run{ID: "r1", ConversationID: "c1", GoalID: "g1"}
	if err := s.CreateRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.StartRun(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	cur, err := s.GetRun(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if cur.State != StateRunning {
		t.Fatalf("应为 running，实际 %s", cur.State)
	}
	if cur.StepBudget != DefaultStepBudget {
		t.Fatalf("默认步数预算未生效: %d", cur.StepBudget)
	}

	if err := s.TouchRun(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, "r1", StateDone, `{"outcome":"done"}`, "结论", "hash-1"); err != nil {
		t.Fatal(err)
	}
	cur, _ = s.GetRun(ctx, "r1")
	if cur.State != StateDone || cur.ResultHash != "hash-1" || cur.FinishedAt.IsZero() {
		t.Fatalf("收口未写全: %+v", cur)
	}
}

func TestStoreResultHashUnique(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"a", "b"} {
		if err := s.CreateRun(ctx, &Run{ID: id, ConversationID: "c", GoalID: "g"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.FinishRun(ctx, "a", StateDone, "{}", "s", "same-hash"); err != nil {
		t.Fatal(err)
	}
	// 第二个同 hash 必须被唯一索引拦下（幂等键）
	if err := s.FinishRun(ctx, "b", StateDone, "{}", "s", "same-hash"); err == nil {
		t.Fatal("重复 result_hash 应被拒")
	}
}

func TestStoreMarkUnknownOnlyFromRunning(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateRun(ctx, &Run{ID: "r", ConversationID: "c", GoalID: "g"}); err != nil {
		t.Fatal(err)
	}
	// queued 不应被标 unknown
	if err := s.MarkUnknown(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.GetRun(ctx, "r")
	if cur.State != StateQueued {
		t.Fatalf("queued 被误标: %s", cur.State)
	}
	_ = s.StartRun(ctx, "r")
	if err := s.MarkUnknown(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	cur, _ = s.GetRun(ctx, "r")
	if cur.State != StateUnknown {
		t.Fatalf("running 应可标 unknown，实际 %s", cur.State)
	}
}

func TestStoreAppendStepIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateRun(ctx, &Run{ID: "r", ConversationID: "c", GoalID: "g"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.AppendStep(ctx, &Step{RunID: "r", StepNo: 1, ToolName: "exec", Summary: "第一次"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AppendStep(ctx, &Step{RunID: "r", StepNo: 1, ToolName: "exec", Summary: "覆盖"}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM zhulong_steps WHERE run_id='r'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("同 step_no 应 upsert 成 1 行，实际 %d", n)
	}
}
