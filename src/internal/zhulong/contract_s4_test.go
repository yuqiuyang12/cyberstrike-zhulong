package zhulong

// contract_s4_test.go —— P1 契约测试 S4 批次：①③⑦⑩⑬（store 层，不依赖 eino，2026-11-06）。
//
// 契约原文（PLAN-v2.1 §九）：
//   ① 同 (conversation, goal) 并发只允许一个 running
//   ③ 非法回执拒绝且零副作用
//   ⑦ 心跳断 → unknown + 一次通知、不重派
//   ⑩ result_hash 幂等（重放拒绝，不改返缓存）
//   ⑬ >10min 的 run 全程无 unknown
//
// 这些契约的共同点：**都在 store 层可判定**，不需要模型、不需要 eino。
// 写成先失败的测试（红）→ 再补 store 支撑代码（绿），避免"新引擎重写一遍才发现契约丢了"。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// countTable 返回三表之一的行数（契约③ 的快照口径）。
func countTable(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// mustRun 建一条 queued run（可选立即 running）。
func mustRun(t *testing.T, s *Store, id, conv, goal string, running bool) {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateRun(ctx, &Run{ID: id, ConversationID: conv, GoalID: goal}); err != nil {
		t.Fatalf("create run %s: %v", id, err)
	}
	if running {
		if err := s.StartRun(ctx, id); err != nil {
			t.Fatalf("start run %s: %v", id, err)
		}
	}
}

// 契约①：同 (conv, goal) 并发抢占，只有一条能进 running；其余拿 ErrGoalBusy。
func TestContractS4_1SingleRunningPerGoal(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	const conv, goal = "conv-c1", "zl-goal-conv-c1"

	const n = 6
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = "zl-run-c1-" + string(rune('a'+i))
		mustRun(t, store, ids[i], conv, goal, false)
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		okIDs   []string
		busyCnt int
		other   []error
	)
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			err := store.AcquireGoalSlot(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				okIDs = append(okIDs, id)
			case errors.Is(err, ErrGoalBusy):
				busyCnt++
			default:
				other = append(other, err)
			}
		}(id)
	}
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("并发抢占出现意外错误（应是 ErrGoalBusy 或成功）: %v", other)
	}
	if len(okIDs) != 1 {
		t.Fatalf("同目标并发只允许 1 条 running, 实际成功 %d: %v", len(okIDs), okIDs)
	}
	if busyCnt != n-1 {
		t.Fatalf("其余 %d 条应拿到 ErrGoalBusy, 实际 %d", n-1, busyCnt)
	}
	var running int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM zhulong_runs WHERE conversation_id=? AND goal_id=? AND state=?`,
		conv, goal, string(StateRunning)).Scan(&running); err != nil {
		t.Fatalf("count running: %v", err)
	}
	if running != 1 {
		t.Fatalf("库里 running 应只有 1 条, 实际 %d", running)
	}

	// 不同目标互不影响（不能把槽位做成全局锁）。
	mustRun(t, store, "zl-run-c1-other", conv, "zl-goal-other", false)
	if err := store.AcquireGoalSlot(ctx, "zl-run-c1-other"); err != nil {
		t.Fatalf("不同 goal 不应被占位拦住: %v", err)
	}

	// 槽位释放后可再抢：前一条收口 → 下一条可进 running。
	if err := store.FinishRun(ctx, okIDs[0], StateDone, `{"outcome":"done"}`, "收口", "hash-c1"); err != nil {
		t.Fatalf("finish winner: %v", err)
	}
	var loser string
	for _, id := range ids {
		if id != okIDs[0] {
			loser = id
			break
		}
	}
	if err := store.AcquireGoalSlot(ctx, loser); err != nil {
		t.Fatalf("前一条收口后槽位应释放, 实际: %v", err)
	}

	// 已 running 的 run 再抢 = 状态错误（不是 ErrGoalBusy，避免调用方误判成"目标被别人占"）。
	if err := store.AcquireGoalSlot(ctx, loser); err == nil || errors.Is(err, ErrGoalBusy) {
		t.Fatalf("非 queued 状态应报状态错误而非 ErrGoalBusy, 实际: %v", err)
	}
}

// 契约③：非法回执被拒 → 三表（steps/todos/cards）零写入，run 只落终态、不落垃圾回执。
func TestContractS4_3InvalidReceiptZeroSideEffects(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	const conv, goal, runID = "conv-c3", "zl-goal-conv-c3", "zl-run-c3"

	if err := store.SaveGoal(ctx, &Goal{ID: goal, ConversationID: conv, Objective: "测 example.com"}); err != nil {
		t.Fatalf("save goal: %v", err)
	}
	mustRun(t, store, runID, conv, goal, true)
	// 让三表基线非零：否则"计数不变"可能只是因为表本来就是空的。
	if err := store.AppendStep(ctx, &Step{RunID: runID, StepNo: 1, ToolName: "exec", Summary: "curl 一发"}); err != nil {
		t.Fatalf("append step: %v", err)
	}
	if _, err := store.AddTodos(ctx, goal, runID, []string{"推进链 A"}); err != nil {
		t.Fatalf("add todos: %v", err)
	}
	if _, err := store.db.Exec(`
INSERT INTO zhulong_cards(id, run_id, goal_id, ask_key, title, created_at) VALUES(?,?,?,?,?,?)`,
		"card-c3", runID, goal, "ask-1", "要我继续吗", ts(time.Now().UTC())); err != nil {
		t.Fatalf("seed card: %v", err)
	}

	stepsBefore := countTable(t, store, "zhulong_steps")
	todosBefore := countTable(t, store, "zhulong_todos")
	cardsBefore := countTable(t, store, "zhulong_cards")

	invalid := []string{
		"本轮没交回执，只有正文。",                                                     // 无回执块
		"```zhulong\n{\"outcome\":\"almost_done\",\"summary\":\"x\"}\n```", // outcome 非法
		"```zhulong\n{\"outcome\":\"done\"}\n```",                          // done 缺 summary/证据
	}
	for i, text := range invalid {
		r, err := ParseReceipt(text)
		if err == nil {
			t.Fatalf("第 %d 条非法回执应被拒, 实际解析成功: %+v", i, r)
		}
		if !errors.Is(err, ErrInvalidReceipt) && !errors.Is(err, ErrMissingReceipt) {
			t.Fatalf("第 %d 条应是 ErrInvalidReceipt/ErrMissingReceipt 族, 实际: %v", i, err)
		}
		// 生产收口路径（multiagent.finalizeZhulongRunWithReceipt 的 perr 分支）：
		// 只写 run 终态，receipt_json 留空，不动 steps/todos/cards。
		if ferr := store.FinishRun(ctx, runID, StateFailed, "", "回执缺失或非法: "+oneLineText(err.Error(), 200), ""); ferr != nil {
			t.Fatalf("拒绝路径落终态失败: %v", ferr)
		}
	}

	if got := countTable(t, store, "zhulong_steps"); got != stepsBefore {
		t.Fatalf("非法回执后 steps 不应变化: before=%d after=%d", stepsBefore, got)
	}
	if got := countTable(t, store, "zhulong_todos"); got != todosBefore {
		t.Fatalf("非法回执后 todos 不应变化: before=%d after=%d", todosBefore, got)
	}
	if got := countTable(t, store, "zhulong_cards"); got != cardsBefore {
		t.Fatalf("非法回执后 cards 不应变化: before=%d after=%d", cardsBefore, got)
	}
	got, err := store.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if got.State != StateFailed {
		t.Fatalf("非法回执应收口为 failed, 实际 %s", got.State)
	}
	if got.ReceiptJSON != "" {
		t.Fatalf("非法回执不得写进 receipt_json, 实际: %q", got.ReceiptJSON)
	}
	if strings.Contains(got.Summary, "```") {
		t.Fatalf("summary 不应把回执块原文抄进库: %q", got.Summary)
	}
	// 待办仍然 open（失败域隔离：不替模型勾掉它没做完的活）。
	if left, lerr := store.ListOpenTodos(ctx, goal, 10); lerr != nil || len(left) != 1 {
		t.Fatalf("open 待办应保持 1 条, 实际 %d (%v)", len(left), lerr)
	}
}

// 契约⑦：心跳断 → 标 unknown 且**只通知一次**，不重派。
func TestContractS4_7UnknownNotifiedOnce(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	const conv, goal, runID = "conv-c7", "zl-goal-conv-c7", "zl-run-c7"
	mustRun(t, store, runID, conv, goal, true)

	// 模拟心跳早停：seen_at 回拨 1 小时。
	old := time.Now().UTC().Add(-time.Hour)
	if _, err := store.db.Exec(`UPDATE zhulong_runs SET seen_at=? WHERE id=?`, ts(old), runID); err != nil {
		t.Fatalf("seed seen_at: %v", err)
	}

	var (
		calls int
		seen  []string
		mu    sync.Mutex
	)
	hook := func(_ context.Context, ids []string) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		seen = append(seen, ids...)
	}

	marked, err := store.SweepStaleWithNotify(ctx, time.Second, hook)
	if err != nil {
		t.Fatalf("sweep #1: %v", err)
	}
	if len(marked) != 1 || marked[0] != runID {
		t.Fatalf("第一次清扫应标记该 run, 实际 %v", marked)
	}
	if calls != 1 || len(seen) != 1 || seen[0] != runID {
		t.Fatalf("应恰好通知一次且点名该 run, 实际 calls=%d seen=%v", calls, seen)
	}

	// 第二次清扫：它已不是 running → 不重复标记、不重复通知（契约⑦「一次通知」）。
	marked2, err := store.SweepStaleWithNotify(ctx, time.Second, hook)
	if err != nil {
		t.Fatalf("sweep #2: %v", err)
	}
	if len(marked2) != 0 {
		t.Fatalf("第二次清扫不应再标记: %v", marked2)
	}
	if calls != 1 {
		t.Fatalf("unknown 通知必须只发一次, 实际 %d", calls)
	}

	got, _ := store.GetRun(ctx, runID)
	if got.State != StateUnknown {
		t.Fatalf("应标 unknown, 实际 %s", got.State)
	}
	// 不重派：仍是同一条 run，没有新 run 被创建（CountRuns 只数终态行，这里直接数全表）。
	var all int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM zhulong_runs WHERE conversation_id=?`, conv).Scan(&all); err != nil {
		t.Fatalf("count runs: %v", err)
	}
	if all != 1 {
		t.Fatalf("unknown 不应自动重派（该会话 run 总数=%d, want 1）", all)
	}
	// 迟到的结果仍然生效（FinishRun 不看前置状态），不会被 unknown 卡死。
	if err := store.FinishRun(ctx, runID, StateDone, `{"outcome":"done"}`, "迟到结果", "hash-c7"); err != nil {
		t.Fatalf("迟到结果应可收口: %v", err)
	}
}

// 契约⑩：result_hash 重放被拒（哨兵 ErrDuplicateResult），且被拒方零副作用。
func TestContractS4_10DuplicateResultRejected(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"zl-run-c10-a", "zl-run-c10-b", "zl-run-c10-c"} {
		mustRun(t, store, id, "conv-c10", "zl-goal-conv-c10", true)
	}
	if err := store.FinishRun(ctx, "zl-run-c10-a", StateDone, `{"outcome":"done"}`, "首写", "hash-c10"); err != nil {
		t.Fatalf("首写应成功: %v", err)
	}

	err := store.FinishRun(ctx, "zl-run-c10-b", StateDone, `{"outcome":"done"}`, "重放", "hash-c10")
	if !errors.Is(err, ErrDuplicateResult) {
		t.Fatalf("重放应返回 ErrDuplicateResult, 实际: %v", err)
	}
	// 语义保留"拒绝"：不返回缓存、不改写被拒行。
	b, _ := store.GetRun(ctx, "zl-run-c10-b")
	if b.State != StateRunning || b.ReceiptJSON != "" || b.ResultHash != "" {
		t.Fatalf("被拒的 run 应保持原样（零副作用）, 实际: state=%s receipt=%q hash=%q", b.State, b.ReceiptJSON, b.ResultHash)
	}
	if !b.FinishedAt.IsZero() {
		t.Fatalf("被拒的 run 不应有 finished_at: %s", b.FinishedAt)
	}
	// 首写行不受影响。
	a, _ := store.GetRun(ctx, "zl-run-c10-a")
	if a.State != StateDone || a.ResultHash != "hash-c10" {
		t.Fatalf("首写行被改动: %+v", a)
	}

	// 空 result_hash 不受部分唯一索引约束（失败收口/无结果场景可多次写）。
	for _, id := range []string{"zl-run-c10-b", "zl-run-c10-c"} {
		if ferr := store.FinishRun(ctx, id, StateFailed, "", "执行失败", ""); ferr != nil {
			t.Fatalf("空 result_hash 不应被幂等键拦下 (%s): %v", id, ferr)
		}
	}
}

// 契约⑬：有心跳的 run 长时间跑（SweepStale 反复扫）全程不掉 unknown；反例证明清扫本环境确实生效。
//
// 说明「排除重启窗口」：本测试在同一进程内跑，不覆盖"进程被杀后重启"的窗口——
// 那个窗口由 lease 语义保证（只标 unknown、不重派，见契约⑦）。
func TestContractS4_13HeartbeatKeepsRunAlive(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	const conv, goal, runID = "conv-c13", "zl-goal-conv-c13", "zl-run-c13"

	// 反例先证清扫可用：无心跳 + seen_at 回拨 → 200ms 内必被标 unknown。
	mustRun(t, store, "zl-run-c13-dead", conv, "zl-goal-dead", true)
	if _, err := store.db.Exec(`UPDATE zhulong_runs SET seen_at=? WHERE id=?`,
		ts(time.Now().UTC().Add(-time.Hour)), "zl-run-c13-dead"); err != nil {
		t.Fatalf("seed dead run: %v", err)
	}
	if marked, err := store.SweepStale(ctx, 200*time.Millisecond); err != nil || len(marked) != 1 {
		t.Fatalf("反例: 无心跳应被标记, marked=%v err=%v", marked, err)
	}

	// 正例：50ms 心跳 + 200ms staleAfter，跑 ~800ms，反复清扫，全程不得 unknown。
	mustRun(t, store, runID, conv, goal, true)
	stop := StartHeartbeat(context.Background(), store, runID, 50*time.Millisecond, nil)
	defer stop()
	for i := 0; i < 8; i++ {
		time.Sleep(100 * time.Millisecond)
		marked, err := store.SweepStale(ctx, 200*time.Millisecond)
		if err != nil {
			t.Fatalf("sweep #%d: %v", i, err)
		}
		for _, id := range marked {
			if id == runID {
				t.Fatalf("第 %d 拍：有心跳的 run 被误标 unknown", i)
			}
		}
		cur, err := store.GetRun(ctx, runID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if cur.State != StateRunning {
			t.Fatalf("第 %d 拍：心跳期间状态应保持 running, 实际 %s", i, cur.State)
		}
	}
	stop() // 幂等
	cur, _ := store.GetRun(ctx, runID)
	if cur.State != StateRunning {
		t.Fatalf("stop 之后也不应被标 unknown（stop 只是停心跳）, 实际 %s", cur.State)
	}
}

// ① 的准入回滚：DropQueuedRun 只删 queued 行，绝不碰 running/终态行。
func TestContractS4_1bDropQueuedRunOnlyQueued(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	const conv, goal = "conv-c1b", "zl-goal-conv-c1b"

	mustRun(t, store, "zl-run-c1b-keep", conv, goal, true) // running：绝不能被删
	mustRun(t, store, "zl-run-c1b-drop", conv, goal, false)
	if err := store.DropQueuedRun(ctx, "zl-run-c1b-drop"); err != nil {
		t.Fatalf("drop queued: %v", err)
	}
	if _, err := store.GetRun(ctx, "zl-run-c1b-drop"); err == nil {
		t.Fatal("queued 行应已回滚")
	}
	if err := store.DropQueuedRun(ctx, "zl-run-c1b-keep"); err != nil {
		t.Fatalf("drop running 应静默无操作: %v", err)
	}
	if _, err := store.GetRun(ctx, "zl-run-c1b-keep"); err != nil {
		t.Fatalf("running 行不得被删: %v", err)
	}
	// 空 id 直接拒绝（防守：不给"删错行"留缝隙）。
	if err := store.DropQueuedRun(ctx, "  "); err == nil {
		t.Fatal("空 id 应报错")
	}
}
