package zhulong

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Store 是 zhulong 的持久化入口。它只新增自己的表，从不改动平台既有表
// （conversations / messages / vulnerabilities 等），因此可在同一 SQLite 库中共存。
//
// 写库纪律沿用平台 C20：调用方负责在部署前备份；本包只做幂等的 CREATE TABLE IF NOT EXISTS。
type Store struct {
	db *sql.DB
}

// NewStore 用平台已有的 *sql.DB 构造。
func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("zhulong: db 为空")
	}
	return &Store{db: db}, nil
}

// SchemaSQL 是 zhulong 的全部建表语句（幂等）。导出以便运维单独执行与审计。
const SchemaSQL = `
CREATE TABLE IF NOT EXISTS zhulong_goals (
  id              TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL,
  objective       TEXT NOT NULL,
  constraints_json TEXT NOT NULL DEFAULT '[]',
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zhulong_runs (
  id              TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL,
  goal_id         TEXT NOT NULL,
  state           TEXT NOT NULL,
  attempt         INTEGER NOT NULL DEFAULT 0,
  step_budget     INTEGER NOT NULL DEFAULT 60,
  minute_budget   INTEGER NOT NULL DEFAULT 25,
  summary         TEXT NOT NULL DEFAULT '',
  receipt_json    TEXT NOT NULL DEFAULT '',
  result_hash     TEXT NOT NULL DEFAULT '',
  not_before      TEXT NOT NULL DEFAULT '',
  seen_at         TEXT NOT NULL DEFAULT '',
  started_at      TEXT NOT NULL DEFAULT '',
  finished_at     TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_zhulong_runs_result_hash
  ON zhulong_runs(result_hash) WHERE result_hash <> '';

CREATE INDEX IF NOT EXISTS ix_zhulong_runs_conv
  ON zhulong_runs(conversation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_zhulong_runs_state
  ON zhulong_runs(state);

CREATE TABLE IF NOT EXISTS zhulong_steps (
  run_id       TEXT NOT NULL,
  step_no      INTEGER NOT NULL,
  tool_name    TEXT NOT NULL DEFAULT '',
  args_hash    TEXT NOT NULL DEFAULT '',
  summary      TEXT NOT NULL DEFAULT '',
  evidence_ref TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  PRIMARY KEY (run_id, step_no)
);

CREATE TABLE IF NOT EXISTS zhulong_cards (
  id              TEXT PRIMARY KEY,
  run_id          TEXT NOT NULL DEFAULT '',
  goal_id         TEXT NOT NULL DEFAULT '',
  ask_key         TEXT NOT NULL,
  title           TEXT NOT NULL DEFAULT '',
  text            TEXT NOT NULL DEFAULT '',
  options_json    TEXT NOT NULL DEFAULT '[]',
  state           TEXT NOT NULL DEFAULT 'open',
  answer          TEXT NOT NULL DEFAULT '',
  answer_event_id TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL,
  decided_at      TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_zhulong_cards_open_key
  ON zhulong_cards(goal_id, ask_key) WHERE state = 'open';

CREATE TABLE IF NOT EXISTS zhulong_timers (
  id         TEXT PRIMARY KEY,
  goal_id    TEXT NOT NULL,
  timer_key  TEXT NOT NULL,
  at         TEXT NOT NULL,
  about      TEXT NOT NULL DEFAULT '',
  state      TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_zhulong_timers_due
  ON zhulong_timers(state, at);

-- 待办：上一轮回执里的 next_actions 落成台账，下一轮开头回注（状态驱动上下文）
CREATE TABLE IF NOT EXISTS zhulong_todos (
  id         TEXT PRIMARY KEY,
  goal_id    TEXT NOT NULL,
  run_id     TEXT NOT NULL DEFAULT '',
  seq        INTEGER NOT NULL DEFAULT 0,
  text       TEXT NOT NULL,
  state      TEXT NOT NULL DEFAULT 'open',   -- open | done | dropped
  created_at TEXT NOT NULL,
  done_at    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ix_zhulong_todos_goal
  ON zhulong_todos(goal_id, state, seq);
`

// EnsureSchema 幂等建表。
func (s *Store) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("zhulong: store 未初始化")
	}
	if _, err := s.db.ExecContext(ctx, SchemaSQL); err != nil {
		return fmt.Errorf("zhulong: 建表失败: %w", err)
	}
	return nil
}

const tsLayout = time.RFC3339Nano

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(tsLayout)
}

func parseTS(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if t, err := time.Parse(tsLayout, v); err == nil {
		return t
	}
	return time.Time{}
}

// SaveGoal 写入（或覆盖）一个目标。
func (s *Store) SaveGoal(ctx context.Context, g *Goal) error {
	if g == nil || strings.TrimSpace(g.ID) == "" {
		return fmt.Errorf("zhulong: goal id 为空")
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now().UTC()
	}
	cj, err := marshalStrings(g.Constraints)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO zhulong_goals(id, conversation_id, objective, constraints_json, created_at)
VALUES(?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET objective=excluded.objective, constraints_json=excluded.constraints_json`,
		g.ID, g.ConversationID, g.Objective, cj, ts(g.CreatedAt))
	if err != nil {
		return fmt.Errorf("zhulong: 保存目标失败: %w", err)
	}
	return nil
}

// GetGoal 读取目标。
func (s *Store) GetGoal(ctx context.Context, id string) (*Goal, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, conversation_id, objective, constraints_json, created_at FROM zhulong_goals WHERE id=?`, id)
	var g Goal
	var cj, createdAt string
	if err := row.Scan(&g.ID, &g.ConversationID, &g.Objective, &cj, &createdAt); err != nil {
		return nil, err
	}
	g.Constraints = unmarshalStrings(cj)
	g.CreatedAt = parseTS(createdAt)
	return &g, nil
}

// CreateRun 插入一条 queued 的 run。
func (s *Store) CreateRun(ctx context.Context, r *Run) error {
	if r == nil || strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("zhulong: run id 为空")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if r.State == "" {
		r.State = StateQueued
	}
	if r.StepBudget <= 0 {
		r.StepBudget = DefaultStepBudget
	}
	if r.MinuteBudget <= 0 {
		r.MinuteBudget = DefaultMinuteBudget
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO zhulong_runs(id, conversation_id, goal_id, state, attempt, step_budget, minute_budget,
                         summary, receipt_json, result_hash, not_before, seen_at, started_at, finished_at, created_at)
VALUES(?,?,?,?,?,?,?,'','','','','','','',?)`,
		r.ID, r.ConversationID, r.GoalID, string(r.State), r.Attempt, r.StepBudget, r.MinuteBudget, ts(r.CreatedAt))
	if err != nil {
		return fmt.Errorf("zhulong: 创建 run 失败: %w", err)
	}
	return nil
}

// StartRun 把 run 置为 running 并记开始时间。
func (s *Store) StartRun(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE zhulong_runs SET state=?, started_at=?, seen_at=? WHERE id=?`,
		string(StateRunning), ts(time.Now().UTC()), ts(time.Now().UTC()), id)
	return err
}

// ErrGoalBusy 表示同 (conversation_id, goal_id) 已经有 running run：拒绝再开第二条（契约①）。
//
// 语义（P1）：**拒绝**，不排队、不覆盖、不重派 —— 双跑会让两个执行体同时打同一目标，
// 证据链与台账都会互相污染，比"少跑一轮"更贵。
var ErrGoalBusy = errors.New("zhulong: 该目标已有 running run")

// AcquireGoalSlot 把 queued run 抢占为 running，同 (conversation_id, goal_id) 只允许一条 running。
//
// 为什么不加 DB 索引：zhulong_runs 现网已有历史行，加部分唯一索引
// （UNIQUE(conversation_id, goal_id) WHERE state='running'）属于 DDL 迁移，要走 C20 手术；
// 这里用**一条**带 NOT EXISTS 的条件 UPDATE 收敛：SQLite 串行化写事务，
// 两个并发调用里只有一条 RowsAffected=1，另一条拿到 0 → 返回 ErrGoalBusy。
//
// 返回 ErrGoalBusy = 目标槽位被别的 running 占着；其他 error = run 不存在或状态不是 queued。
func (s *Store) AcquireGoalSlot(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("zhulong: store 未初始化")
	}
	now := ts(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE zhulong_runs SET state=?, started_at=?, seen_at=?
WHERE id=? AND state=?
  AND NOT EXISTS (
    SELECT 1 FROM zhulong_runs AS other
    WHERE other.conversation_id = zhulong_runs.conversation_id
      AND other.goal_id = zhulong_runs.goal_id
      AND other.state = ?
      AND other.id <> zhulong_runs.id
  )`,
		string(StateRunning), now, now, id, string(StateQueued), string(StateRunning))
	if err != nil {
		return fmt.Errorf("zhulong: 抢占目标槽位失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	// 诊断：区分"目标被占"（ErrGoalBusy）与"run 不存在/状态不对"。
	var busy int
	if qerr := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM zhulong_runs AS other
JOIN zhulong_runs AS me ON me.id = ?
WHERE other.conversation_id = me.conversation_id
  AND other.goal_id = me.goal_id
  AND other.state = ? AND other.id <> me.id`,
		id, string(StateRunning)).Scan(&busy); qerr == nil && busy > 0 {
		return ErrGoalBusy
	}
	return fmt.Errorf("zhulong: run %s 不存在或不是 queued 状态", id)
}

// TouchRun 刷新心跳（每条事件调用一次）。
func (s *Store) TouchRun(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE zhulong_runs SET seen_at=? WHERE id=?`, ts(time.Now().UTC()), id)
	return err
}

// ErrDuplicateResult 表示 result_hash 与既有 run 重复：**拒绝重放**（契约⑩）。
//
// 语义（P1 明确保留"拒绝"，不改"返回上次缓存结果"）：幂等键重复说明同一份结果被写第二次，
// 要么是重复消费事件、要么是双跑；返回缓存会让上层误以为"这次真写成功了"。
var ErrDuplicateResult = errors.New("zhulong: result_hash 已存在（拒绝重放）")

// DropQueuedRun 删除一条**仍是 queued** 的 run 行（准入被拒时的回滚，契约①）。
//
// 只删 state='queued' 且 id 精确匹配的单行：绝不碰 running / 终态行，
// 不做任何批量、通配或启发式删除（C20）。被拒的请求因此不留下"孤儿 queued run"。
func (s *Store) DropQueuedRun(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("zhulong: store 未初始化")
	}
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("zhulong: run id 为空")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM zhulong_runs WHERE id=? AND state=?`,
		id, string(StateQueued)); err != nil {
		return fmt.Errorf("zhulong: 回滚 queued run 失败: %w", err)
	}
	return nil
}

// FinishRun 写入终态与回执。若 resultHash 与既有行冲突（幂等键重复），返回 ErrDuplicateResult。
//
// 唯一索引 ux_zhulong_runs_result_hash 保证冲突时整条 UPDATE 失败，本行不留半成品
// （state/receipt/summary 都不会被改）——这就是"拒绝重放且零副作用"。
func (s *Store) FinishRun(ctx context.Context, id string, state RunState, receiptJSON, summary, resultHash string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE zhulong_runs SET state=?, receipt_json=?, summary=?, result_hash=?, finished_at=?, seen_at=?
WHERE id=?`,
		string(state), receiptJSON, summary, resultHash, ts(time.Now().UTC()), ts(time.Now().UTC()), id)
	if err != nil {
		if isResultHashConflict(err) {
			return fmt.Errorf("%w（run=%s）", ErrDuplicateResult, id)
		}
		return fmt.Errorf("zhulong: 收口失败: %w", err)
	}
	return nil
}

// isResultHashConflict 识别 result_hash 唯一索引冲突。
// SQLite 文案：UNIQUE constraint failed: zhulong_runs.result_hash。
func isResultHashConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") && strings.Contains(msg, "result_hash")
}

// MarkUnknown 用于心跳超时：只标记，不重派。
func (s *Store) MarkUnknown(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE zhulong_runs SET state=? WHERE id=? AND state=?`,
		string(StateUnknown), id, string(StateRunning))
	return err
}

// MarkContinuePending 把 run 标为 continue_pending，并把理由追加进 summary。
//
// 语义（2026-11-05 M1）：continue 有**两个来源**，事后必须能分开（2026-11-06 修）：
//   - 模型自主交 continue（reason 为空，无 DeliveryReason codes）→ 「continue（模型自主，无 codes）」；
//   - done 被 DecideDelivery 判据打回（reason = codes）→ 「打回: <codes>」。
//
// 旧实现把空 reason 兜底成「未通过交付判据」、又被统一拼成「｜打回: …」，
// 于是"模型觉得自己还没做完"和"系统判定它交不了卷"在台账里长得一模一样。
func (s *Store) MarkContinuePending(ctx context.Context, id, reason string) error {
	note := "continue（模型自主，无 codes）"
	if r := strings.TrimSpace(reason); r != "" {
		note = "打回: " + r
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE zhulong_runs SET state=?, seen_at=?,
  summary = CASE WHEN summary='' THEN ? ELSE summary || ' ｜' || ? END
WHERE id=?`,
		string(StateContinuePending), ts(time.Now().UTC()), note, note, id)
	if err != nil {
		return fmt.Errorf("zhulong: 标记 continue_pending 失败: %w", err)
	}
	return nil
}

// AppendStep 追加一条结构化进度。
func (s *Store) AppendStep(ctx context.Context, st *Step) error {
	if st == nil || st.RunID == "" {
		return fmt.Errorf("zhulong: step run id 为空")
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO zhulong_steps(run_id, step_no, tool_name, args_hash, summary, evidence_ref, created_at)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(run_id, step_no) DO UPDATE SET summary=excluded.summary, evidence_ref=excluded.evidence_ref`,
		st.RunID, st.StepNo, st.ToolName, st.ArgsHash, st.Summary, st.EvidenceRef, ts(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("zhulong: 追加步骤失败: %w", err)
	}
	return nil
}

// GetRun 读取单条 run。
func (s *Store) GetRun(ctx context.Context, id string) (*Run, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, conversation_id, goal_id, state, attempt, step_budget, minute_budget,
       summary, receipt_json, result_hash, not_before, seen_at, started_at, finished_at, created_at
FROM zhulong_runs WHERE id=?`, id)
	return scanRun(row)
}

// LatestRunForGoal 取某目标最新一条 run（续跑用）。
func (s *Store) LatestRunForGoal(ctx context.Context, goalID string) (*Run, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, conversation_id, goal_id, state, attempt, step_budget, minute_budget,
       summary, receipt_json, result_hash, not_before, seen_at, started_at, finished_at, created_at
FROM zhulong_runs WHERE goal_id=? ORDER BY created_at DESC LIMIT 1`, goalID)
	return scanRun(row)
}

type rowScanner interface{ Scan(dest ...any) error }

func scanRun(row rowScanner) (*Run, error) {
	var r Run
	var state, notBefore, seenAt, startedAt, finishedAt, createdAt string
	err := row.Scan(&r.ID, &r.ConversationID, &r.GoalID, &state, &r.Attempt, &r.StepBudget, &r.MinuteBudget,
		&r.Summary, &r.ReceiptJSON, &r.ResultHash, &notBefore, &seenAt, &startedAt, &finishedAt, &createdAt)
	if err != nil {
		return nil, err
	}
	r.State = RunState(state)
	r.NotBefore = parseTS(notBefore)
	r.SeenAt = parseTS(seenAt)
	r.StartedAt = parseTS(startedAt)
	r.FinishedAt = parseTS(finishedAt)
	r.CreatedAt = parseTS(createdAt)
	return &r, nil
}

// Todo 是一条跨轮待办（来自上一轮回执的 next_actions）。
type Todo struct {
	ID        string    `json:"id"`
	GoalID    string    `json:"goal_id"`
	RunID     string    `json:"run_id"`
	Seq       int       `json:"seq"`
	Text      string    `json:"text"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	DoneAt    time.Time `json:"done_at"`
}

const (
	TodoOpen    = "open"
	TodoDone    = "done"
	TodoDropped = "dropped"
	// TodoStale 是"goal 已交付(done)时仍未结清的待办"：不再回注、也不再算欠账
	// （2026-11-05 实证：9 条 todo 全 open 从不结清，每轮都被重新回注成噪声）。
	TodoStale = "stale"
	// MaxOpenTodos 是回注与保留上限，防止台账无限膨胀。
	MaxOpenTodos = 20
)

// AddTodos 把一轮回执里的 next_actions 落成待办（去重：同 goal 下文本相同的 open 不重复插）。
func (s *Store) AddTodos(ctx context.Context, goalID, runID string, texts []string) (int, error) {
	if len(texts) == 0 {
		return 0, nil
	}
	existing := map[string]struct{}{}
	rows, err := s.db.QueryContext(ctx, `SELECT text FROM zhulong_todos WHERE goal_id=? AND state=?`, goalID, TodoOpen)
	if err != nil {
		return 0, fmt.Errorf("zhulong: 读取待办失败: %w", err)
	}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return 0, err
		}
		existing[normalizeTodoText(t)] = struct{}{}
	}
	_ = rows.Close()

	added := 0
	for i, raw := range texts {
		text := strings.TrimSpace(raw)
		if text == "" {
			continue
		}
		key := normalizeTodoText(text)
		if _, ok := existing[key]; ok {
			continue
		}
		existing[key] = struct{}{}
		id := fmt.Sprintf("zl-todo-%s-%d", runID, i)
		_, ierr := s.db.ExecContext(ctx, `
INSERT INTO zhulong_todos(id, goal_id, run_id, seq, text, state, created_at)
VALUES(?,?,?,?,?,?,?)`,
			id, goalID, runID, i, text, TodoOpen, ts(time.Now().UTC()))
		if ierr != nil {
			return added, fmt.Errorf("zhulong: 写待办失败: %w", ierr)
		}
		added++
	}
	return added, nil
}

// ListOpenTodos 取某目标最近的未完成待办（最多 MaxOpenTodos 条）。
func (s *Store) ListOpenTodos(ctx context.Context, goalID string, limit int) ([]Todo, error) {
	if limit <= 0 || limit > MaxOpenTodos {
		limit = MaxOpenTodos
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, goal_id, run_id, seq, text, state, created_at FROM zhulong_todos
WHERE goal_id=? AND state=? ORDER BY created_at DESC LIMIT ?`, goalID, TodoOpen, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Todo
	for rows.Next() {
		var t Todo
		var createdAt string
		if err := rows.Scan(&t.ID, &t.GoalID, &t.RunID, &t.Seq, &t.Text, &t.State, &createdAt); err != nil {
			return nil, err
		}
		t.CreatedAt = parseTS(createdAt)
		out = append(out, t)
	}
	return out, rows.Err()
}

// CloseTodos 把某目标的全部 open 待办置为 done（一轮收口后重置台账）。
func (s *Store) CloseTodos(ctx context.Context, goalID string) (int, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE zhulong_todos SET state=?, done_at=? WHERE goal_id=? AND state=?`,
		TodoDone, ts(time.Now().UTC()), goalID, TodoOpen)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkOpenTodosStale 在 goal 交付（outcome=done）时把仍未结清的 open 待办标 stale。
//
// 为什么不是 CloseTodos(done)：这些待办**没有真的做完**，标 done 是造假；
// 标 stale 表示"随本轮交付一起作废"，既不回注也不冒充已完成。用 UPDATE，不改表结构。
func (s *Store) MarkOpenTodosStale(ctx context.Context, goalID string) (int, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE zhulong_todos SET state=?, done_at=? WHERE goal_id=? AND state=?`,
		TodoStale, ts(time.Now().UTC()), goalID, TodoOpen)
	if err != nil {
		return 0, fmt.Errorf("zhulong: 结清待办失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// PruneOpenTodos 在 open 待办超过 keep 条时，把**最旧的**多余部分标 stale（保留最新 keep 条）。
//
// 为什么需要：continue 轮次每轮都会把 next_actions 落成 todo，虽然 AddTodos 会按文本去重，
// 但不同轮次的措辞不同 → 台账只进不出，越跑越脏（2026-11-05 实证：9 条全 open）。
// 修剪只动"最旧的 open"，不删行、不改父表；与 MarkOpenTodosStale 同口径（stale 不回注）。
func (s *Store) PruneOpenTodos(ctx context.Context, goalID string, keep int) (int, error) {
	if keep <= 0 {
		keep = MaxOpenTodos
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE zhulong_todos SET state=?, done_at=?
WHERE goal_id=? AND state=? AND id NOT IN (
  SELECT id FROM zhulong_todos WHERE goal_id=? AND state=? ORDER BY created_at DESC, seq DESC LIMIT ?
)`,
		TodoStale, ts(time.Now().UTC()), goalID, TodoOpen, goalID, TodoOpen, keep)
	if err != nil {
		return 0, fmt.Errorf("zhulong: 修剪待办失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// RecentSteps 取某 run 最近的步骤摘要（旧→新）。
func (s *Store) RecentSteps(ctx context.Context, runID string, limit int) ([]Step, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT run_id, step_no, tool_name, args_hash, summary, evidence_ref FROM zhulong_steps
WHERE run_id=? ORDER BY step_no DESC LIMIT ?`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Step
	for rows.Next() {
		var st Step
		if err := rows.Scan(&st.RunID, &st.StepNo, &st.ToolName, &st.ArgsHash, &st.Summary, &st.EvidenceRef); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	// 反转为旧→新
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

func normalizeTodoText(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// CountRuns 返回某会话已收口的轮数（用于报告里的"第 N 轮"编号）。
func (s *Store) CountRuns(ctx context.Context, conversationID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zhulong_runs WHERE conversation_id=? AND state NOT IN ('running','queued','unknown')`, conversationID).Scan(&n)
	return n, err
}
