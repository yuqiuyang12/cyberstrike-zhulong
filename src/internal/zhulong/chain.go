package zhulong

// chain.go —— 利用链账本(烛龙 M1 · 任务 B / 2026-11-05,spec v2 锚定修正同日)
//
// 背景:平台过去的判据全长在「覆盖面」上(assets × faces),没有任何「链」的承载物:
// attack_chain_nodes/edges 全库 0 行、停止条件靠模型自报、run 说 done 就 done。
// 本文件提供两表 + 一个 store,把「一条链推进到第几个台阶」变成可查的事实:
//
//	zl_chains         一条「可利用性假设」的生命周期:open → exploited | blocked,rung = 已推进到的台阶
//	zl_chain_attempts 每一次尝试(payload + 证据引用 + 判定),链推进的原子事实
//
// 设计约束(spec §0 + v2):
//   - 只 CREATE TABLE IF NOT EXISTS,不改任何既有表;
//   - 不可绕:state=blocked 必须带 blocker_evidence/enumeration_space/unverified_space 三件;
//     state=exploited 必须 rung>=1 且至少有证据(拦截证据或 attempt 的 evidence_ref);
//     除 rejected 外每次尝试必须带 evidence_ref(绝对路径或 URL);
//   - 链必须锚在「这个目标自己的模型」上:target_asset + hypothesis_type 必填,
//     business-logic / own-code / own-contract / diff-probe 四类还须 target_model_ref(point 到目标模型条目);
//   - 确定性判据下沉到代码:rung 只由 attempt 抬高(max),不信模型自报。
//
// 本包只写自己的两张表;平台写库纪律(C20:先备份、停服)由调用方/运维负责。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 链状态。open=还没走到终点;exploited=已实证击穿;blocked=同台阶连续变体无增量且带拦截证据。
const (
	ChainOpen      = "open"
	ChainExploited = "exploited"
	ChainBlocked   = "blocked"
)

// rung 台阶阶梯(0..6)。数字越大越接近「真被利用」。
//
//	0 confirmed        漏洞已确认(能复现现象)
//	1 sensitive-read   读到敏感数据
//	2 auth-bypass      认证/授权绕过
//	3 write            写入(数据/配置)
//	4 upload           上传落地
//	5 execute          命令/代码执行
//	6 lateral          横向到下一跳
const (
	ChainRungConfirmed     = 0
	ChainRungSensitiveRead = 1
	ChainRungAuthBypass    = 2
	ChainRungWrite         = 3
	ChainRungUpload        = 4
	ChainRungExecute       = 5
	ChainRungLateral       = 6
	// ChainRungMax 是合法 rung 上限;越界一律夹到 [0, ChainRungMax]。
	ChainRungMax = 6
)

// 一次尝试的判定。
const (
	// AttemptVerdictProgress 本变体有增量(拿到新信息/新台阶),链继续。
	AttemptVerdictProgress = "progress"
	// AttemptVerdictExploited 本变体已实证击穿(仍需 zl_chain_close 显式收口)。
	AttemptVerdictExploited = "exploited"
	// AttemptVerdictRejected 本变体被拒(唯一允许不带 evidence_ref 的判定:什么都没发生)。
	AttemptVerdictRejected = "rejected"
	// AttemptVerdictBlocked 本变体被挡住(带拦截证据),用于累计「同台阶多变体无增量」。
	AttemptVerdictBlocked = "blocked"
)

// 链的假设类型(spec v2)。决定这条链是「针对这个目标自己的东西」还是「通用清单式试错」。
const (
	// HypBusinessLogic 目标自己的业务流程/状态机(越权/改价/并发/审批绕过)。
	HypBusinessLogic = "business-logic"
	// HypOwnCode 目标自己的代码(自研接口、自研 Web 应用)。
	HypOwnCode = "own-code"
	// HypOwnContract 目标自己的智能合约。
	HypOwnContract = "own-contract"
	// HypComponentKnown 已知组件的公开 n-day(必须再叠加目标现场证据,不能只报版本号)。
	HypComponentKnown = "component-known"
	// HypDiffProbe 差分/对照探测(改一个参数看行为差异)。
	HypDiffProbe = "diff-probe"
	// HypOther 其他;也承接「说不清锚在哪」的兜底(不算 specific)。
	HypOther = "other"
)

// ChainHypothesisTypes 是全部合法假设类型(用于工具 schema enum 与错误提示)。
var ChainHypothesisTypes = []string{
	HypBusinessLogic, HypOwnCode, HypOwnContract, HypComponentKnown, HypDiffProbe, HypOther,
}

// anchoredHypothesisTypes 是「必须锚到目标模型条目」的四类。
var anchoredHypothesisTypes = map[string]bool{
	HypBusinessLogic: true,
	HypOwnCode:       true,
	HypOwnContract:   true,
	HypDiffProbe:     true,
}

// NormalizeHypothesisType 归一化假设类型:去空白、转小写,
// 并把 "generic"(loop-dev 早期口径/旧提示词)视为 "other" 的别名,避免一处口径漂移就整条链打不开。
func NormalizeHypothesisType(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "generic" {
		return HypOther
	}
	return v
}

// ValidHypothesisType 报告是否为合法假设类型。
func ValidHypothesisType(s string) bool {
	switch NormalizeHypothesisType(s) {
	case HypBusinessLogic, HypOwnCode, HypOwnContract, HypComponentKnown, HypDiffProbe, HypOther:
		return true
	}
	return false
}

// RequiresTargetModel 报告该假设类型是否必须带 target_model_ref。
func RequiresTargetModel(hyp string) bool {
	return anchoredHypothesisTypes[NormalizeHypothesisType(hyp)]
}

// ChainIsSpecific 报告这条链是否「锚定在目标自己的模型上」。
//
// 口径(spec v2,闸门与回执共用):target_model_ref 非空,或 hypothesis_type ∈ 四类锚定类型。
func ChainIsSpecific(c Chain) bool {
	if strings.TrimSpace(c.TargetModelRef) != "" {
		return true
	}
	return anchoredHypothesisTypes[NormalizeHypothesisType(c.HypothesisType)]
}

// chainSpecificSQLCase 是 Stats 里 specific 计数的 SQL 表达式(与 ChainIsSpecific 同口径)。
const chainSpecificSQLCase = `(CASE WHEN TRIM(target_model_ref) <> '' OR hypothesis_type IN (` +
	`'` + HypBusinessLogic + `','` + HypOwnCode + `','` + HypOwnContract + `','` + HypDiffProbe + `')` +
	` THEN 1 ELSE 0 END)`

// Chain 是一条利用链(账本行)。
type Chain struct {
	ID              string
	ConversationID  string
	GoalID          string
	RunID           string
	FindingKey      string
	Title           string
	Rung            int
	State           string
	Hypothesis      string
	BlockerEvidence string
	Note            string

	// ---- v2 锚定字段 ----
	// TargetAsset 这条链针对的具体资产(host[:port]),须落在本项目 assets 里。
	TargetAsset string
	// HypothesisType 见 Hyp* 常量;空值非法。
	HypothesisType string
	// TargetModelRef 指向 project_facts.fact_key(该目标自己的模型条目,如 target/www.example.com-model)。
	TargetModelRef string
	// EnumerationSpace 关链时填:试过哪些变体/多少个/什么方法(判死三要素之一)。
	EnumerationSpace string
	// UnverifiedSpace 关链时填:还有哪一类没试、为什么(判死三要素之三)。
	UnverifiedSpace string
	// MaxReachableRung 是该链的"最大可及台阶"(2026-11-05 M1.1):在目标模型里穷尽"下一阶前置"后
	// 能到的最高 rung。缺省 -1 表示未声明(按当前 rung 处理)。
	MaxReachableRung int
	// NextRungBlocker 说明"为什么下一阶到不了"(前置缺失的具体证据/原因),blocked 在 rung<6 时必填。
	NextRungBlocker string

	CreatedAt string
	UpdatedAt string
}

// ChainAttempt 是一次尝试(账本行)。
type ChainAttempt struct {
	ID          string
	ChainID     string
	AttemptNo   int
	Rung        int
	Payload     string
	EvidenceRef string
	Verdict     string
	Summary     string
	CreatedAt   string
}

// ChainClose 是收口一条链所需的全部输入。
//
// 收口规则(确定性,不可绕):
//   - state ∈ exploited|blocked;
//   - state=blocked 必须同时给 BlockerEvidence + EnumerationSpace + UnverifiedSpace;
//   - state=exploited 必须 rung>=1,且至少有证据(BlockerEvidence 或任一条 attempt 的 evidence_ref)。
type ChainClose struct {
	State            string
	BlockerEvidence  string
	Note             string
	EnumerationSpace string
	UnverifiedSpace  string
	// MaxReachableRung 声明"这条链最高能到哪一阶"(<=当前 rung);> 当前 rung 视为谎报,直接拒。
	MaxReachableRung int
	// NextRungBlocker 说明下一阶为什么到不了;blocked 且 rung<6 时必填。
	NextRungBlocker string
}

// ChainSchemaSQL 是链账本的全部建表语句(幂等)。导出以便运维单独执行与审计。
//
// 注意:
//   - zl_chains 不挂 conversations 外键:链是「会话内的工作账本」,
//     允许在会话行尚未落库时先记账(单测/离线执行器也用得上);会话删除由平台侧自行清理。
//   - zl_chain_attempts 挂 zl_chains 外键 ON DELETE CASCADE:删链即清尝试,不留孤儿。
//   - ux_zl_chains_open_finding 保证「同 conversation+goal+finding_key 至多一条 open 链」,
//     并发 Open 时由唯一索引兜底(第二个 INSERT 失败 → 回读已有 id)。
const ChainSchemaSQL = `
CREATE TABLE IF NOT EXISTS zl_chains (
  id               TEXT PRIMARY KEY,
  conversation_id  TEXT NOT NULL,
  goal_id          TEXT NOT NULL DEFAULT '',
  run_id           TEXT NOT NULL DEFAULT '',
  finding_key      TEXT NOT NULL,
  title            TEXT NOT NULL DEFAULT '',
  rung             INTEGER NOT NULL DEFAULT 0,
  state            TEXT NOT NULL DEFAULT 'open',
  hypothesis       TEXT NOT NULL DEFAULT '',
  blocker_evidence TEXT NOT NULL DEFAULT '',
  note             TEXT NOT NULL DEFAULT '',
  target_asset      TEXT NOT NULL DEFAULT '',
  hypothesis_type   TEXT NOT NULL DEFAULT '',
  target_model_ref  TEXT NOT NULL DEFAULT '',
  enumeration_space TEXT NOT NULL DEFAULT '',
  unverified_space  TEXT NOT NULL DEFAULT '',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_zl_chains_open_finding
  ON zl_chains(conversation_id, goal_id, finding_key) WHERE state = 'open';

CREATE INDEX IF NOT EXISTS ix_zl_chains_conv
  ON zl_chains(conversation_id, state, rung DESC);

CREATE INDEX IF NOT EXISTS ix_zl_chains_state
  ON zl_chains(state, rung DESC);

CREATE INDEX IF NOT EXISTS ix_zl_chains_asset
  ON zl_chains(target_asset, state);

CREATE TABLE IF NOT EXISTS zl_chain_attempts (
  id           TEXT PRIMARY KEY,
  chain_id     TEXT NOT NULL,
  attempt_no   INTEGER NOT NULL,
  rung         INTEGER NOT NULL DEFAULT 0,
  payload      TEXT NOT NULL DEFAULT '',
  evidence_ref TEXT NOT NULL DEFAULT '',
  verdict      TEXT NOT NULL,
  summary      TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  FOREIGN KEY (chain_id) REFERENCES zl_chains(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_zl_chain_attempts_no
  ON zl_chain_attempts(chain_id, attempt_no);

CREATE INDEX IF NOT EXISTS ix_zl_chain_attempts_chain
  ON zl_chain_attempts(chain_id, attempt_no);
`

// chainSelectColumns 是 Chain 的读列清单(Get/List 共用,防止两处漂移)。
const chainSelectColumns = `id, conversation_id, goal_id, run_id, finding_key, title, rung, state,
       hypothesis, blocker_evidence, note,
       target_asset, hypothesis_type, target_model_ref, enumeration_space, unverified_space,
       max_reachable_rung, next_rung_blocker,
       created_at, updated_at`

// scanChain 把一行按 chainSelectColumns 的顺序读进 Chain。
func scanChain(sc interface{ Scan(...interface{}) error }) (Chain, error) {
	var c Chain
	err := sc.Scan(&c.ID, &c.ConversationID, &c.GoalID, &c.RunID, &c.FindingKey, &c.Title,
		&c.Rung, &c.State, &c.Hypothesis, &c.BlockerEvidence, &c.Note,
		&c.TargetAsset, &c.HypothesisType, &c.TargetModelRef, &c.EnumerationSpace, &c.UnverifiedSpace,
		&c.MaxReachableRung, &c.NextRungBlocker,
		&c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// ChainStore 是链账本的持久化入口。与 Store 一样只新增自己的表,从不改平台既有表。
type ChainStore struct {
	db *sql.DB
}

// NewChainStore 用平台已有的 *sql.DB 构造。
func NewChainStore(db *sql.DB) (*ChainStore, error) {
	if db == nil {
		return nil, fmt.Errorf("zhulong: chain db 为空")
	}
	return &ChainStore{db: db}, nil
}

// EnsureSchema 幂等建表。
func (s *ChainStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("zhulong: chain store 未初始化")
	}
	if _, err := s.db.ExecContext(ctx, ChainSchemaSQL); err != nil {
		return fmt.Errorf("zhulong: 链账本建表失败: %w", err)
	}
	// M1.1(2026-11-05):老库的 zl_chains 没有 max_reachable_rung/next_rung_blocker,
	// CREATE TABLE IF NOT EXISTS 不会补列,这里做幂等 ALTER(逐列检查,已存在则跳过)。
	for _, col := range []struct{ name, ddl string }{
		{"max_reachable_rung", "ALTER TABLE zl_chains ADD COLUMN max_reachable_rung INTEGER NOT NULL DEFAULT -1"},
		{"next_rung_blocker", "ALTER TABLE zl_chains ADD COLUMN next_rung_blocker TEXT NOT NULL DEFAULT ''"},
	} {
		ok, cerr := s.columnExists(ctx, "zl_chains", col.name)
		if cerr != nil {
			return fmt.Errorf("zhulong: 检查列 %s 失败: %w", col.name, cerr)
		}
		if ok {
			continue
		}
		if _, aerr := s.db.ExecContext(ctx, col.ddl); aerr != nil {
			return fmt.Errorf("zhulong: 补列 %s 失败: %w", col.name, aerr)
		}
	}
	return nil
}

// columnExists 判断表里是否已有某列(用于幂等迁移)。
func (s *ChainStore) columnExists(ctx context.Context, table, column string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// clampRung 把 rung 夹进 [0, ChainRungMax]。
func clampRung(n int) int {
	if n < 0 {
		return 0
	}
	if n > ChainRungMax {
		return ChainRungMax
	}
	return n
}

// Open 开一条链。同 conversation(+goal,当 goal 非空)+finding_key 且 state=open 时复用已有链,
// 返回已有 id(不新建、不覆盖已有 rung)。
//
// goal_id 为空表示「不区分目标轮次」——此时只按 conversation+finding_key 复用,
// 避免 record_vulnerability 自动挂链(zl_chain_open 之外的路径)与工具手动开链产生重复。
//
// v2 硬校验:hypothesis_type 必填且合法;target_asset 必填;
// 四类锚定假设(business-logic/own-code/own-contract/diff-probe)必须带 target_model_ref
// (该 fact_key 在 project_facts 里的存在性由 app 层校验——本包只写自己的表)。
func (s *ChainStore) Open(ctx context.Context, c *Chain) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("zhulong: chain store 未初始化")
	}
	if c == nil {
		return "", fmt.Errorf("zhulong: chain 为空")
	}
	convID := strings.TrimSpace(c.ConversationID)
	if convID == "" {
		return "", fmt.Errorf("zhulong: chain conversation_id 为空")
	}
	findingKey := strings.TrimSpace(c.FindingKey)
	if findingKey == "" {
		return "", fmt.Errorf("zhulong: chain finding_key 为空(用 vuln:<id> / asset:port:path 这类稳定键)")
	}
	hyp := NormalizeHypothesisType(c.HypothesisType)
	if hyp == "" {
		return "", fmt.Errorf("zhulong: chain hypothesis_type 为空——必须是 %s 之一"+
			"(通用 n-day/清单式没有锚定对象,不算交付)", strings.Join(ChainHypothesisTypes, "|"))
	}
	if !ValidHypothesisType(hyp) {
		return "", fmt.Errorf("zhulong: chain hypothesis_type=%q 非法,必须是 %s 之一",
			c.HypothesisType, strings.Join(ChainHypothesisTypes, "|"))
	}
	asset := strings.TrimSpace(c.TargetAsset)
	if asset == "" {
		return "", fmt.Errorf("zhulong: chain target_asset 为空——链必须针对一个具体资产(host[:port])")
	}
	ref := strings.TrimSpace(c.TargetModelRef)
	if RequiresTargetModel(hyp) && ref == "" {
		return "", fmt.Errorf("zhulong: hypothesis_type=%s 必须带 target_model_ref"+
			"(先 upsert_project_fact 建目标模型条目 target/%s-model,再开链)", hyp, asset)
	}
	c.HypothesisType = hyp
	c.TargetAsset = asset
	c.TargetModelRef = ref

	goalID := strings.TrimSpace(c.GoalID)

	existing, err := s.findOpenChainID(ctx, convID, goalID, findingKey)
	if err != nil {
		return "", err
	}
	if existing != "" {
		c.ID = existing
		return existing, nil
	}

	c.ID = strings.TrimSpace(c.ID)
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	c.State = ChainOpen
	c.Rung = clampRung(c.Rung)
	now := ts(time.Now().UTC())
	if strings.TrimSpace(c.CreatedAt) == "" {
		c.CreatedAt = now
	}
	c.UpdatedAt = now

	_, err = s.db.ExecContext(ctx, `
INSERT INTO zl_chains(id, conversation_id, goal_id, run_id, finding_key, title, rung, state,
                      hypothesis, blocker_evidence, note,
                      target_asset, hypothesis_type, target_model_ref, enumeration_space, unverified_space,
                      max_reachable_rung, next_rung_blocker,
                      created_at, updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, convID, goalID, strings.TrimSpace(c.RunID), findingKey, strings.TrimSpace(c.Title),
		c.Rung, ChainOpen, c.Hypothesis, "", strings.TrimSpace(c.Note),
		c.TargetAsset, c.HypothesisType, c.TargetModelRef,
		strings.TrimSpace(c.EnumerationSpace), strings.TrimSpace(c.UnverifiedSpace),
		c.MaxReachableRung, strings.TrimSpace(c.NextRungBlocker),
		c.CreatedAt, c.UpdatedAt)
	if err != nil {
		// 并发 Open:唯一索引拦下第二个 INSERT → 回读已有 id,不报错给调用方。
		if again, ferr := s.findOpenChainID(ctx, convID, goalID, findingKey); ferr == nil && again != "" {
			c.ID = again
			return again, nil
		}
		return "", fmt.Errorf("zhulong: 开链失败: %w", err)
	}
	return c.ID, nil
}

// findOpenChainID 查同 conversation(+goal)+finding_key 的 open 链 id(没有则空串)。
func (s *ChainStore) findOpenChainID(ctx context.Context, convID, goalID, findingKey string) (string, error) {
	query := `SELECT id FROM zl_chains WHERE conversation_id=? AND finding_key=? AND state=?`
	args := []interface{}{convID, findingKey, ChainOpen}
	if goalID != "" {
		query += ` AND goal_id=?`
		args = append(args, goalID)
	}
	query += ` ORDER BY created_at ASC, rowid ASC LIMIT 1`

	var id string
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("zhulong: 查询 open 链失败: %w", err)
	}
	return id, nil
}

// AddAttempt 追加一次尝试,并把链的 rung 抬到 max(旧 rung, 本次 rung)。
//
// 硬校验(不满足直接拒绝,错误信息写清缺什么):
//   - chain_id 必须存在;
//   - verdict ∈ progress|exploited|rejected|blocked;
//   - 除 rejected 外 evidence_ref 必填,且必须是绝对路径 / URL / 带 scheme 的 URI(复用 looksLikeEvidenceRef 口径);
//   - rung 夹进 [0, ChainRungMax]。
//
// 注意:verdict=exploited 只是「本变体打穿了」的事实,链要收口仍须显式 Close(exploited)。
func (s *ChainStore) AddAttempt(ctx context.Context, a *ChainAttempt) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("zhulong: chain store 未初始化")
	}
	if a == nil {
		return "", fmt.Errorf("zhulong: attempt 为空")
	}
	chainID := strings.TrimSpace(a.ChainID)
	if chainID == "" {
		return "", fmt.Errorf("zhulong: attempt chain_id 为空")
	}
	verdict := strings.TrimSpace(a.Verdict)
	switch verdict {
	case AttemptVerdictProgress, AttemptVerdictExploited, AttemptVerdictRejected, AttemptVerdictBlocked:
	default:
		return "", fmt.Errorf("zhulong: attempt verdict=%q 非法,只能是 progress|exploited|rejected|blocked", a.Verdict)
	}
	evidenceRef := strings.TrimSpace(a.EvidenceRef)
	if verdict == AttemptVerdictRejected {
		if evidenceRef != "" && !looksLikeEvidenceRef(evidenceRef) {
			return "", fmt.Errorf("zhulong: evidence_ref 必须是绝对路径或 URL,当前 %q", evidenceRef)
		}
	} else if evidenceRef == "" {
		return "", fmt.Errorf("zhulong: verdict=%s 必须带 evidence_ref(原始报文/截图/日志的绝对路径或 URL);"+
			"只有 rejected(什么都没发生)才允许省略", verdict)
	} else if !looksLikeEvidenceRef(evidenceRef) {
		return "", fmt.Errorf("zhulong: evidence_ref 必须是绝对路径或 URL,当前 %q;"+
			"「nmap 输出看起来正常」这类自述不算证据", evidenceRef)
	}
	a.Rung = clampRung(a.Rung)

	var curRung int
	var curState string
	err := s.db.QueryRowContext(ctx, `SELECT rung, state FROM zl_chains WHERE id=?`, chainID).Scan(&curRung, &curState)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("zhulong: 链 %s 不存在(先用 zl_chain_open 开链或用 zl_chain_list 查 id)", chainID)
	}
	if err != nil {
		return "", fmt.Errorf("zhulong: 读取链失败: %w", err)
	}

	now := ts(time.Now().UTC())
	if strings.TrimSpace(a.ID) == "" {
		a.ID = uuid.NewString()
	}
	if strings.TrimSpace(a.CreatedAt) == "" {
		a.CreatedAt = now
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("zhulong: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if a.AttemptNo <= 0 {
		var maxNo int
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(attempt_no),0) FROM zl_chain_attempts WHERE chain_id=?`, chainID).Scan(&maxNo); err != nil {
			return "", fmt.Errorf("zhulong: 读取 attempt_no 失败: %w", err)
		}
		a.AttemptNo = maxNo + 1
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO zl_chain_attempts(id, chain_id, attempt_no, rung, payload, evidence_ref, verdict, summary, created_at)
VALUES(?,?,?,?,?,?,?,?,?)`,
		a.ID, chainID, a.AttemptNo, a.Rung, a.Payload, evidenceRef, verdict, a.Summary, a.CreatedAt); err != nil {
		return "", fmt.Errorf("zhulong: 写入 attempt 失败: %w", err)
	}

	if a.Rung > curRung {
		if _, err := tx.ExecContext(ctx,
			`UPDATE zl_chains SET rung=?, updated_at=? WHERE id=?`, a.Rung, now, chainID); err != nil {
			return "", fmt.Errorf("zhulong: 抬高 rung 失败: %w", err)
		}
	} else if _, err := tx.ExecContext(ctx,
		`UPDATE zl_chains SET updated_at=? WHERE id=?`, now, chainID); err != nil {
		return "", fmt.Errorf("zhulong: 更新链时间失败: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("zhulong: 提交 attempt 失败: %w", err)
	}
	return a.ID, nil
}

// Close 收口一条链。规则见 ChainClose。
//
// 语义:
//   - 只允许从 open 走向终态;重复 Close 成同一终态是幂等的(返回 nil,不覆盖原证据);
//   - 试图把已收口的链改成另一个终态 → 报错(账本不可回改,要重推就新开一条);
//   - exploited 会清空 blocker_evidence(避免两种语义混在一行)。
func (s *ChainStore) Close(ctx context.Context, id string, in ChainClose) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("zhulong: chain store 未初始化")
	}
	chainID := strings.TrimSpace(id)
	if chainID == "" {
		return fmt.Errorf("zhulong: chain_id 为空")
	}
	state := strings.TrimSpace(in.State)
	switch state {
	case ChainExploited, ChainBlocked:
	default:
		return fmt.Errorf("zhulong: state=%q 非法,只能是 exploited(已实证击穿) 或 blocked(带拦截证据判死)", in.State)
	}

	evidence := strings.TrimSpace(in.BlockerEvidence)
	enumeration := strings.TrimSpace(in.EnumerationSpace)
	unverified := strings.TrimSpace(in.UnverifiedSpace)

	if state == ChainBlocked {
		var missing []string
		if evidence == "" {
			missing = append(missing, "blocker_evidence(拦截原始报文/日志的绝对路径或 URL)")
		}
		if enumeration == "" {
			missing = append(missing, "enumeration_space(试过哪些变体/多少个/什么方法)")
		}
		if unverified == "" {
			missing = append(missing, "unverified_space(还有哪一类没试、为什么)")
		}
		if len(missing) > 0 {
			return fmt.Errorf("zhulong: state=blocked 缺 %s;判死必须三件齐全,无证据的「打不动」只是模型自述",
				strings.Join(missing, " + "))
		}
	}

	c, err := s.Get(ctx, chainID)
	if err != nil {
		return err
	}
	if c.State == state {
		return nil // 幂等:重复收口成同一终态
	}
	if c.State != ChainOpen {
		return fmt.Errorf("zhulong: 链 %s 已收口(state=%s),不能改写成 %s;要重新推进请新开一条链", chainID, c.State, state)
	}
	if state == ChainBlocked && c.Rung < ChainRungMax {
		// M1.1(2026-11-05):blocked 不再"三件齐全就行"——必须证明"试够了"且"下一阶前置确实没有"。
		if strings.TrimSpace(in.NextRungBlocker) == "" {
			return fmt.Errorf("zhulong: 链 %s 当前 rung=%d,state=blocked 必须给 next_rung_blocker"+
				"(说明「再上一阶需要什么前置、在目标模型里搜过什么、为什么没有」),否则只是「没试」不是「打不动」",
				chainID, c.Rung)
		}
		if in.MaxReachableRung > c.Rung {
			return fmt.Errorf("zhulong: 链 %s 的 max_reachable_rung=%d 大于当前 rung=%d;最大可及台阶不能高于已打到的台阶"+
				"(先 zl_chain_attempt 真的打到再声明)", chainID, in.MaxReachableRung, c.Rung)
		}
		variants, verr := s.countVariantsAtRung(ctx, chainID, c.Rung)
		if verr != nil {
			return fmt.Errorf("zhulong: 统计链 %s 的变体数失败: %w", chainID, verr)
		}
		if variants < chainMinVariantsToBlock {
			return fmt.Errorf("zhulong: 链 %s 在 rung=%d 只试了 %d 个不同变体,blocked 至少要 %d 个"+
				"(同一台阶换编码/位置/方法/头各算一个;少于此数 = 没打够,不是打不动)",
				chainID, c.Rung, variants, chainMinVariantsToBlock)
		}
	}

	if state == ChainExploited {
		if c.Rung < ChainRungSensitiveRead {
			return fmt.Errorf("zhulong: 链 %s 的 rung=0(仅确认漏洞现象),state=exploited 需要至少推进到 rung>=1"+
				"(读到敏感数据/认证绕过/写入/上传/执行/横向);先用 zl_chain_attempt 记录真实推进", chainID)
		}
		attEvidence, aerr := s.countAttemptEvidence(ctx, chainID)
		if aerr != nil {
			return aerr
		}
		if evidence == "" && attEvidence == 0 {
			return fmt.Errorf("zhulong: 链 %s 无证据,state=exploited 至少要一条 attempt 的 evidence_ref 或 blocker_evidence;"+
				"没有原始报文不算击穿", chainID)
		}
		evidence = ""
	}

	now := ts(time.Now().UTC())
	maxReach := in.MaxReachableRung
	if maxReach < 0 {
		maxReach = c.Rung
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE zl_chains
SET state=?, blocker_evidence=?, note=?, enumeration_space=?, unverified_space=?,
    max_reachable_rung=?, next_rung_blocker=?, updated_at=?
WHERE id=? AND state=?`,
		state, evidence, strings.TrimSpace(in.Note), enumeration, unverified,
		maxReach, strings.TrimSpace(in.NextRungBlocker), now, chainID, ChainOpen)
	if err != nil {
		return fmt.Errorf("zhulong: 收口链失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("zhulong: 链 %s 状态在收口过程中被改动,请重新查询", chainID)
	}
	return nil
}

// chainMinVariantsToBlock 是 blocked 前"同一台阶至少要试几个不同变体"的硬下限。
//
// 判据来自红队手册「穷尽标准」与 KB-BB-05:同一手法换编码/位置/方法/头各算一个变体;
// 1-2 个变体就收口 = 没打够。用 distinct payload 计数,避免同一发重放刷数。
const chainMinVariantsToBlock = 3

// countVariantsAtRung 数该链在指定台阶上有多少个"不同 payload"的尝试。
func (s *ChainStore) countVariantsAtRung(ctx context.Context, chainID string, rung int) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT payload) FROM zl_chain_attempts WHERE chain_id=? AND rung=?`,
		chainID, rung).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// countAttemptEvidence 数该链有多少条带 evidence_ref 的 attempt。
func (s *ChainStore) countAttemptEvidence(ctx context.Context, chainID string) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM zl_chain_attempts WHERE chain_id=? AND TRIM(evidence_ref) <> ''`,
		chainID).Scan(&n); err != nil {
		return 0, fmt.Errorf("zhulong: 统计 attempt 证据失败: %w", err)
	}
	return n, nil
}

// Get 读一条链(收口/落攻击链时需要 finding_key、title、rung、target_asset)。
func (s *ChainStore) Get(ctx context.Context, id string) (*Chain, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("zhulong: chain store 未初始化")
	}
	chainID := strings.TrimSpace(id)
	if chainID == "" {
		return nil, fmt.Errorf("zhulong: chain_id 为空")
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+chainSelectColumns+` FROM zl_chains WHERE id=?`, chainID)
	c, err := scanChain(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("zhulong: 链 %s 不存在", chainID)
	}
	if err != nil {
		return nil, fmt.Errorf("zhulong: 读取链失败: %w", err)
	}
	return &c, nil
}

// List 列链。convID 为空表示不按会话过滤(供跨会话扫 open 链的自动续轮使用);
// state 为空表示不过滤状态。按 rung 降序(最深的链排前面)。
func (s *ChainStore) List(ctx context.Context, convID string, state string) ([]Chain, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("zhulong: chain store 未初始化")
	}
	query := `SELECT ` + chainSelectColumns + ` FROM zl_chains WHERE 1=1`
	var args []interface{}
	if cid := strings.TrimSpace(convID); cid != "" {
		query += ` AND conversation_id=?`
		args = append(args, cid)
	}
	if st := strings.TrimSpace(state); st != "" {
		query += ` AND state=?`
		args = append(args, st)
	}
	query += ` ORDER BY rung DESC, updated_at DESC, rowid DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("zhulong: 列链失败: %w", err)
	}
	defer rows.Close()

	var out []Chain
	for rows.Next() {
		c, serr := scanChain(rows)
		if serr != nil {
			return nil, fmt.Errorf("zhulong: 扫描链失败: %w", serr)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("zhulong: 遍历链失败: %w", err)
	}
	return out, nil
}

// ErrNoOpenChain 表示该会话当前没有 open 链(自动续轮据此停止,不算错误)。
var ErrNoOpenChain = errors.New("zhulong: 没有 open 链")

// DeepestOpen 返回某会话「最深」的 open 链(rung 最大;并列时取最近更新的一条)。
// 没有 open 链时返回 (nil, ErrNoOpenChain),调用方可据此停轮。
func (s *ChainStore) DeepestOpen(ctx context.Context, convID string) (*Chain, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("zhulong: chain store 未初始化")
	}
	cid := strings.TrimSpace(convID)
	if cid == "" {
		return nil, fmt.Errorf("zhulong: conversation_id 为空")
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+chainSelectColumns+` FROM zl_chains
WHERE conversation_id=? AND state=? ORDER BY rung DESC, updated_at DESC, rowid DESC LIMIT 1`,
		cid, ChainOpen)
	c, err := scanChain(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoOpenChain
	}
	if err != nil {
		return nil, fmt.Errorf("zhulong: 读取最深 open 链失败: %w", err)
	}
	return &c, nil
}

// Stats 汇总某会话的链规模:总数 / open / exploited / 最深 rung(0..6) / specific(锚定口径)。
//
// specific 口径 = target_model_ref 非空,或 hypothesis_type ∈ 四类锚定类型
// (business-logic/own-code/own-contract/diff-probe);通用清单式试错不计入。
// 表为空时返回全 0(不报错),供闸门降级使用。
func (s *ChainStore) Stats(ctx context.Context, convID string) (total, open, exploited, depth, specific int, err error) {
	if s == nil || s.db == nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("zhulong: chain store 未初始化")
	}
	query := `SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN state='` + ChainOpen + `' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN state='` + ChainExploited + `' THEN 1 ELSE 0 END), 0),
       COALESCE(MAX(rung), 0),
       COALESCE(SUM(` + chainSpecificSQLCase + `), 0)
FROM zl_chains`
	var args []interface{}
	if cid := strings.TrimSpace(convID); cid != "" {
		query += ` WHERE conversation_id=?`
		args = append(args, cid)
	}
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&total, &open, &exploited, &depth, &specific); err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("zhulong: 统计链失败: %w", err)
	}
	return total, open, exploited, depth, specific, nil
}
