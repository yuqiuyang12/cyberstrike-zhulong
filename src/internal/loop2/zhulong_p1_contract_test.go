package loop2

// zhulong_p1_contract_test.go —— 目标槽位契约的 orchestrator 级验收。
//
// 覆盖目标槽位契约（store 层已在 internal/zhulong/contract_s4_test.go 验过，这里验"接线后"的行为）：
//   ① 同 (conversation, goal) 的第二个请求被拒：发 failed 语义 progress + 正常返回 +
//     **不产生 run 行**（自己刚建的 queued 行必须回滚，不能留孤儿）。
//   ⑫ engine 分流用例随 native 引擎退役归档（_archive/zhulong-turnloop-2026-11-06）。

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/zhulong"

	_ "github.com/mattn/go-sqlite3"
)

// newZhulongTestDB 建一个带 zhulong schema 的临时库（不连平台现网 DB）。
func newZhulongTestDB(t *testing.T) (*database.DB, *zhulong.Store) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "zl-p1.db")+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	st, err := zhulong.NewStore(sqlDB)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := st.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return &database.DB{DB: sqlDB}, st
}

func countSQL(t *testing.T, db *database.DB, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count(%s): %v", query, err)
	}
	return n
}

func zhulongMA(engine string) *config.MultiAgentConfig {
	return &config.MultiAgentConfig{Zhulong: config.ZhulongConfig{Enabled: true, Engine: engine}}
}

// ①：目标槽位被占 → 第二个请求被拒且不产生 run 行。
func TestP1GoalBusyRejectedNoRunRow(t *testing.T) {
	db, store := newZhulongTestDB(t)
	ctx := context.Background()
	const conv = "conv-busy"
	goalID := zhulongGoalID(conv)

	// 预置"第一个请求正在跑"：goal + 一条 running run。
	if err := store.SaveGoal(ctx, &zhulong.Goal{ID: goalID, ConversationID: conv, Objective: "测 pile-bi"}); err != nil {
		t.Fatalf("save goal: %v", err)
	}
	if err := store.CreateRun(ctx, &zhulong.Run{ID: "zl-run-first", ConversationID: conv, GoalID: goalID}); err != nil {
		t.Fatalf("create first run: %v", err)
	}
	if err := store.StartRun(ctx, "zl-run-first"); err != nil {
		t.Fatalf("start first run: %v", err)
	}

	var (
		gotType string
		gotMsg  string
		gotData map[string]interface{}
		events  int
	)
	progress := func(eventType, message string, data interface{}) {
		events++
		gotType, gotMsg = eventType, message
		if m, ok := data.(map[string]interface{}); ok {
			gotData = m
		}
	}

	res, err := runZhulongAgent(ctx, nil, zhulongMA(config.ZhulongEngineWrapper), nil, db, nil,
		conv, "", "再来一轮", nil, nil, progress, nil, "", zhulongOrchMode)
	if err != nil {
		t.Fatalf("目标被占时应正常返回（不是 500）, 实际错误: %v", err)
	}
	if res == nil || !strings.Contains(res.Response, "被拒") {
		t.Fatalf("返回文本要说清被拒, 实际: %+v", res)
	}
	if res.CompletionReason != "zhulong:goal_busy" {
		t.Fatalf("CompletionReason=%q, want zhulong:goal_busy", res.CompletionReason)
	}

	// progress：必须有且仅有一条 failed 语义事件，且声明零副作用。
	if events != 1 || gotType != "zhulong_run_end" {
		t.Fatalf("应发 1 条 zhulong_run_end 事件, 实际 events=%d type=%q msg=%q", events, gotType, gotMsg)
	}
	if gotData["outcome"] != "failed" || gotData["reason"] != "goal_busy" || gotData["sideEffect"] != "none" {
		t.Fatalf("progress data 语义不对: %+v", gotData)
	}

	// 核心断言：没有产生第二条 run 行（自己刚建的 queued 行已回滚）。
	if n := countSQL(t, db, `SELECT COUNT(*) FROM zhulong_runs WHERE conversation_id=?`, conv); n != 1 {
		t.Fatalf("被拒请求不得产生 run 行, 实际该会话 run 数=%d", n)
	}
	if n := countSQL(t, db, `SELECT COUNT(*) FROM zhulong_runs WHERE state=?`, string(zhulong.StateQueued)); n != 0 {
		t.Fatalf("不得残留 queued 行, 实际 %d", n)
	}
	// 第一个 run 不受影响（仍在 running，槽位仍归它）。
	first, err := store.GetRun(ctx, "zl-run-first")
	if err != nil {
		t.Fatalf("get first run: %v", err)
	}
	if first.State != zhulong.StateRunning {
		t.Fatalf("第一个 run 不应被影响, 实际 state=%s", first.State)
	}
}
