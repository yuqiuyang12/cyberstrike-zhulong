package zhulong

// chain_test.go —— 利用链账本的确定性判据测试(烛龙 M1 · 任务 B)。
//
// 防的失败方式(每条都对应一次真实翻车):
//  1. 同会话重复开同一条链 → 账本里长出两条 open 链,闸门永远算不清「还有几条没推完」;
//  2. attempt 只写明细不抬 rung → 链永远停在 0,「推进了一个台阶」无法被代码验证;
//  3. blocked 不校验证据 → 模型自述"打不动"就能关链,交付质量退回原样;
//  4. 链没有锚定类型/资产 → 通用 n-day 八股也能占一条 open 链(spec v2);
//  5. Stats 口径漂移 → 闸门/回执各算一套数。

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// newTestChainStore 建一个临时 sqlite(开外键,便于验证 cascade)并建表两次(幂等)。
func newTestChainStore(t *testing.T) *ChainStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chain.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000&_foreign_keys=1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewChainStore(db)
	if err != nil {
		t.Fatalf("new chain store: %v", err)
	}
	ctx := context.Background()
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("schema 不幂等: %v", err)
	}
	return s
}


// seedVariants 给链在指定台阶塞 n 个不同 payload 的尝试（M1.1 起 blocked 需 ≥3 变体）。
func seedVariants(t *testing.T, s *ChainStore, chainID string, rung, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := s.AddAttempt(context.Background(), &ChainAttempt{
			ChainID: chainID, Rung: rung,
			Payload: "probe-" + itoaForTest(i) + "-" + chainID[:8], EvidenceRef: "/tmp/ev/v" + itoaForTest(i) + ".txt",
			Verdict: "rejected",
		}); err != nil {
			t.Fatalf("seed variant %d: %v", i, err)
		}
	}
}

// newAnchorChain 造一条合法的 v2 锚定链(own-code + 目标模型引用)。
func newAnchorChain(convID, findingKey string) *Chain {
	return &Chain{
		ConversationID: convID,
		FindingKey:     findingKey,
		Title:          "订单详情接口越权",
		Hypothesis:     "id 换成他人订单号即可读",
		HypothesisType: HypOwnCode,
		TargetAsset:    "shop.example.com",
		TargetModelRef: "target/shop.example.com-model",
	}
}

func TestChainOpenReusesOpenChain(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()

	c1 := newAnchorChain("conv-1", "vuln:v-1")
	id1, err := s.Open(ctx, c1)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if id1 == "" {
		t.Fatal("open 应返回 id")
	}

	// 同 conversation+goal+finding_key 再开一次 → 必须复用同一条(不能长出第二条 open 链)
	c2 := newAnchorChain("conv-1", "vuln:v-1")
	id2, err := s.Open(ctx, c2)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	if id2 != id1 {
		t.Fatalf("同 finding_key 应复用链 %s,却新建了 %s", id1, id2)
	}

	list, err := s.List(ctx, "conv-1", ChainOpen)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("open 链应只有 1 条,实际 %d 条", len(list))
	}

	// 已收口的链不再被复用:关掉之后再开应是新的一条
	seedVariants(t, s, id1, 0, 3)
	if err := s.Close(ctx, id1, ChainClose{State: ChainBlocked,
		BlockerEvidence: "/tmp/ev/blocked.txt", EnumerationSpace: "试了 4 个变体", UnverifiedSpace: "未试 SSRF 回连",
		NextRungBlocker: "rung1 需要可读接口,目标模型里未见未授权读点"}); err != nil {
		t.Fatalf("close blocked: %v", err)
	}
	c3 := newAnchorChain("conv-1", "vuln:v-1")
	id3, err := s.Open(ctx, c3)
	if err != nil {
		t.Fatalf("third open: %v", err)
	}
	if id3 == id1 {
		t.Fatal("已收口的链不应被复用")
	}
}

func TestChainOpenValidatesAnchorFields(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()

	// ① 缺 hypothesis_type(spec v2 的硬门:通用清单式不许开链)
	c := newAnchorChain("conv-1", "vuln:v-1")
	c.HypothesisType = ""
	if _, err := s.Open(ctx, c); err == nil || !strings.Contains(err.Error(), "hypothesis_type") {
		t.Fatalf("缺 hypothesis_type 应报错,实际 %v", err)
	}

	// ② 非法 hypothesis_type
	c = newAnchorChain("conv-1", "vuln:v-1")
	c.HypothesisType = "n-day-八股"
	if _, err := s.Open(ctx, c); err == nil || !strings.Contains(err.Error(), "非法") {
		t.Fatalf("非法 hypothesis_type 应报错,实际 %v", err)
	}

	// ③ 缺 target_asset
	c = newAnchorChain("conv-1", "vuln:v-1")
	c.TargetAsset = ""
	if _, err := s.Open(ctx, c); err == nil || !strings.Contains(err.Error(), "target_asset") {
		t.Fatalf("缺 target_asset 应报错,实际 %v", err)
	}

	// ④ 四类锚定假设缺 target_model_ref(own-code 属于四类)
	c = newAnchorChain("conv-1", "vuln:v-1")
	c.TargetModelRef = ""
	if _, err := s.Open(ctx, c); err == nil || !strings.Contains(err.Error(), "target_model_ref") {
		t.Fatalf("own-code 缺 target_model_ref 应报错,实际 %v", err)
	}

	// ⑤ component-known / other 允许不锚模型条目
	c = newAnchorChain("conv-1", "vuln:v-2")
	c.HypothesisType = HypComponentKnown
	c.TargetModelRef = ""
	if _, err := s.Open(ctx, c); err != nil {
		t.Fatalf("component-known 允许空 target_model_ref,实际 %v", err)
	}

	// ⑥ "generic" 是 other 的别名,归一化后落库为 other
	c = newAnchorChain("conv-1", "vuln:v-3")
	c.HypothesisType = "generic"
	c.TargetModelRef = ""
	id, err := s.Open(ctx, c)
	if err != nil {
		t.Fatalf("generic 别名应可用,实际 %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.HypothesisType != HypOther {
		t.Fatalf("generic 应归一化为 other,实际 %q", got.HypothesisType)
	}
}

func TestChainAddAttemptRaisesRung(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()

	id, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:v-1"))
	if err != nil {
		t.Fatal(err)
	}

	// 第一次推进:rung=1
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 1, Payload: "GET /api/order?id=1002",
		EvidenceRef: "/home/kali/data/ev/order-1002.txt", Verdict: AttemptVerdictProgress,
		Summary: "读到他人订单",
	}); err != nil {
		t.Fatalf("attempt 1: %v", err)
	}
	c, _ := s.Get(ctx, id)
	if c.Rung != 1 {
		t.Fatalf("rung 应抬到 1,实际 %d", c.Rung)
	}

	// 回退尝试(更小 rung)不能把链降级
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 0, Payload: "GET /api/order?id=1001",
		EvidenceRef: "/home/kali/data/ev/order-1001.txt", Verdict: AttemptVerdictRejected,
	}); err != nil {
		t.Fatalf("attempt 2: %v", err)
	}
	c, _ = s.Get(ctx, id)
	if c.Rung != 1 {
		t.Fatalf("rung 只能上升,实际被降到 %d", c.Rung)
	}

	// 第二次推进:rung=3(跨台阶)
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 3, Payload: "POST /api/order/cancel id=1002",
		EvidenceRef: "https://evidence.local/order-cancel.png", Verdict: AttemptVerdictExploited,
	}); err != nil {
		t.Fatalf("attempt 3: %v", err)
	}
	c, _ = s.Get(ctx, id)
	if c.Rung != 3 {
		t.Fatalf("rung 应抬到 3,实际 %d", c.Rung)
	}

	// attempt_no 自增且连续
	var maxNo int
	if err := s.db.QueryRow(`SELECT MAX(attempt_no) FROM zl_chain_attempts WHERE chain_id=?`, id).Scan(&maxNo); err != nil {
		t.Fatal(err)
	}
	if maxNo != 3 {
		t.Fatalf("3 次尝试后 attempt_no 应为 3,实际 %d", maxNo)
	}

	// attempt verdict=exploited 不自动收口:链仍是 open(收口只走 zl_chain_close)
	if c.State != ChainOpen {
		t.Fatalf("attempt 不应自动收口,state=%s", c.State)
	}
}

func TestChainAddAttemptRequiresEvidence(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()
	id, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:v-1"))
	if err != nil {
		t.Fatal(err)
	}

	// 除 rejected 外,缺 evidence_ref 一律拒
	for _, verdict := range []string{AttemptVerdictProgress, AttemptVerdictExploited, AttemptVerdictBlocked} {
		_, err := s.AddAttempt(ctx, &ChainAttempt{ChainID: id, Rung: 1, Payload: "x", Verdict: verdict})
		if err == nil || !strings.Contains(err.Error(), "evidence_ref") {
			t.Fatalf("verdict=%s 缺 evidence_ref 应报错,实际 %v", verdict, err)
		}
	}
	// 非绝对路径/URL 也不算证据
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 1, Payload: "x", Verdict: AttemptVerdictProgress, EvidenceRef: "nmap 输出看起来正常",
	}); err == nil || !strings.Contains(err.Error(), "绝对路径") {
		t.Fatalf("自述型 evidence_ref 应报错,实际 %v", err)
	}
	// rejected 允许无证据
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 0, Payload: "x", Verdict: AttemptVerdictRejected,
	}); err != nil {
		t.Fatalf("rejected 允许无证据,实际 %v", err)
	}
}

func TestChainCloseBlockedRequiresThreePieces(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()
	id, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:v-1"))
	if err != nil {
		t.Fatal(err)
	}

	// ① 缺 blocker_evidence
	if err := s.Close(ctx, id, ChainClose{State: ChainBlocked,
		EnumerationSpace: "4 变体", UnverifiedSpace: "未试回连"}); err == nil || !strings.Contains(err.Error(), "blocker_evidence") {
		t.Fatalf("blocked 缺 blocker_evidence 应报错,实际 %v", err)
	}
	// ② 缺 enumeration_space
	if err := s.Close(ctx, id, ChainClose{State: ChainBlocked,
		BlockerEvidence: "/tmp/ev/b.txt", UnverifiedSpace: "未试回连"}); err == nil || !strings.Contains(err.Error(), "enumeration_space") {
		t.Fatalf("blocked 缺 enumeration_space 应报错,实际 %v", err)
	}
	// ③ 缺 unverified_space
	if err := s.Close(ctx, id, ChainClose{State: ChainBlocked,
		BlockerEvidence: "/tmp/ev/b.txt", EnumerationSpace: "4 变体"}); err == nil || !strings.Contains(err.Error(), "unverified_space") {
		t.Fatalf("blocked 缺 unverified_space 应报错,实际 %v", err)
	}
	// ④ 三缺全报(错误信息要能让模型知道补什么)
	if err := s.Close(ctx, id, ChainClose{State: ChainBlocked}); err == nil ||
		!strings.Contains(err.Error(), "blocker_evidence") ||
		!strings.Contains(err.Error(), "enumeration_space") ||
		!strings.Contains(err.Error(), "unverified_space") {
		t.Fatalf("三件全缺应一次报全,实际 %v", err)
	}
	// ⑤ 缺的关不掉,链仍是 open
	c, _ := s.Get(ctx, id)
	if c.State != ChainOpen {
		t.Fatalf("校验失败不应改状态,state=%s", c.State)
	}
	// ⑥ 三件齐全(且试够 3 变体、写明下一阶前置)才允许关
	seedVariants(t, s, id, 0, 3)
	if err := s.Close(ctx, id, ChainClose{
		State: ChainBlocked, BlockerEvidence: "/tmp/ev/b.txt",
		EnumerationSpace: "4 个变体: id 越权/参数篡改/批量接口/导出", UnverifiedSpace: "未试 SSRF 回连(需出网)",
		NextRungBlocker: "rung1 需要可读接口;目标模型里只有展示页,无可控读点",
		Note: "WAF 逐条 403",
	}); err != nil {
		t.Fatalf("三件齐全应可关,实际 %v", err)
	}
	c, _ = s.Get(ctx, id)
	if c.State != ChainBlocked || c.EnumerationSpace == "" || c.UnverifiedSpace == "" || c.BlockerEvidence == "" {
		t.Fatalf("blocked 三件未落库: %+v", c)
	}

	// ⑦ 已收口的链不能改写成另一个终态
	if err := s.Close(ctx, id, ChainClose{State: ChainExploited}); err == nil {
		t.Fatal("已 blocked 的链不应被改写成 exploited")
	}
}

func TestChainCloseExploitedRequiresRungAndEvidence(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()
	id, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:v-1"))
	if err != nil {
		t.Fatal(err)
	}

	// rung=0 且无证据 → 拒绝
	if err := s.Close(ctx, id, ChainClose{State: ChainExploited}); err == nil || !strings.Contains(err.Error(), "rung") {
		t.Fatalf("rung=0 收 exploited 应报错,实际 %v", err)
	}

	// rung 抬到 2 但没有任何证据 → 拒绝
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 2, Payload: "x", Verdict: AttemptVerdictRejected,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx, id, ChainClose{State: ChainExploited}); err == nil || !strings.Contains(err.Error(), "证据") {
		t.Fatalf("无证据收 exploited 应报错,实际 %v", err)
	}

	// 有 attempt 证据 → 允许
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 2, Payload: "Cookie 伪造 admin",
		EvidenceRef: "/home/kali/data/ev/admin-panel.png", Verdict: AttemptVerdictExploited,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx, id, ChainClose{State: ChainExploited, Note: "已进后台"}); err != nil {
		t.Fatalf("有证据应可收 exploited,实际 %v", err)
	}
	c, _ := s.Get(ctx, id)
	if c.State != ChainExploited {
		t.Fatalf("state 应为 exploited,实际 %s", c.State)
	}
	if c.BlockerEvidence != "" {
		t.Fatalf("exploited 应清空 blocker_evidence,实际 %q", c.BlockerEvidence)
	}
	// 幂等
	if err := s.Close(ctx, id, ChainClose{State: ChainExploited}); err != nil {
		t.Fatalf("重复收口同终态应幂等,实际 %v", err)
	}
}

func TestChainStatsAndSpecific(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()

	// 3 条锚定链(own-code + 模型引用)+ 1 条 component-known 无引用 + 1 条 other 无引用
	openAnchored, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:a"))
	if err != nil {
		t.Fatal(err)
	}
	exploitedAnchored, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:b"))
	if err != nil {
		t.Fatal(err)
	}
	blockedAnchored, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:c"))
	if err != nil {
		t.Fatal(err)
	}
	component := &Chain{
		ConversationID: "conv-1", FindingKey: "vuln:d", Title: "Struts2 版本",
		HypothesisType: HypComponentKnown, TargetAsset: "legacy.example.com",
	}
	if _, err := s.Open(ctx, component); err != nil {
		t.Fatal(err)
	}
	generic := &Chain{
		ConversationID: "conv-1", FindingKey: "vuln:e", Title: "通用清单试错",
		HypothesisType: HypOther, TargetAsset: "legacy.example.com",
	}
	if _, err := s.Open(ctx, generic); err != nil {
		t.Fatal(err)
	}
	// 另一个会话的链不得计入
	if _, err := s.Open(ctx, newAnchorChain("conv-2", "vuln:x")); err != nil {
		t.Fatal(err)
	}

	// 推进 exploitedAnchored 到 rung=5(执行)并收口
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: exploitedAnchored, Rung: 5, Payload: "cmd=id",
		EvidenceRef: "/home/kali/data/ev/rce-id.txt", Verdict: AttemptVerdictExploited,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx, exploitedAnchored, ChainClose{State: ChainExploited}); err != nil {
		t.Fatal(err)
	}
	// 收口 blockedAnchored
	seedVariants(t, s, blockedAnchored, 0, 3)
	if err := s.Close(ctx, blockedAnchored, ChainClose{
		State: ChainBlocked, BlockerEvidence: "/home/kali/data/ev/403.txt",
		EnumerationSpace: "3 变体", UnverifiedSpace: "未试上传",
		NextRungBlocker: "rung1 需要可读接口,源码已确认无未授权读点",
	}); err != nil {
		t.Fatal(err)
	}

	total, open, exploited, depth, specific, err := s.Stats(ctx, "conv-1")
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("total 应为 5,实际 %d", total)
	}
	if open != 3 { // openAnchored + component + generic
		t.Fatalf("open 应为 3,实际 %d", open)
	}
	if exploited != 1 {
		t.Fatalf("exploited 应为 1,实际 %d", exploited)
	}
	if depth != 5 {
		t.Fatalf("depth 应为 5,实际 %d", depth)
	}
	// specific = 3 条锚定(own-code 且带 target_model_ref);component/other 不算
	if specific != 3 {
		t.Fatalf("specific 应为 3,实际 %d", specific)
	}
	_ = openAnchored

	// 口径与 ChainIsSpecific 一致(逐条对照,防止 SQL 与 Go 两套口径漂移)
	list, err := s.List(ctx, "conv-1", "")
	if err != nil {
		t.Fatal(err)
	}
	goCount := 0
	for _, c := range list {
		if ChainIsSpecific(c) {
			goCount++
		}
	}
	if goCount != specific {
		t.Fatalf("ChainIsSpecific 计数 %d 与 Stats.specific %d 不一致", goCount, specific)
	}

	// 空会话 → 全 0 且不报错(闸门降级路径)
	total, open, exploited, depth, specific, err = s.Stats(ctx, "conv-empty")
	if err != nil {
		t.Fatalf("空会话统计不应报错: %v", err)
	}
	if total != 0 || open != 0 || exploited != 0 || depth != 0 || specific != 0 {
		t.Fatalf("空会话应全 0,实际 %d/%d/%d/%d/%d", total, open, exploited, depth, specific)
	}
}

func TestChainDeepestOpenAndListOrder(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()

	if _, err := s.DeepestOpen(ctx, "conv-1"); !errors.Is(err, ErrNoOpenChain) {
		t.Fatalf("无 open 链应返回 ErrNoOpenChain,实际 %v", err)
	}

	shallow, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:a"))
	if err != nil {
		t.Fatal(err)
	}
	deep, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:b"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: deep, Rung: 4, Payload: "upload", EvidenceRef: "/tmp/ev/u.txt", Verdict: AttemptVerdictProgress,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: shallow, Rung: 1, Payload: "read", EvidenceRef: "/tmp/ev/r.txt", Verdict: AttemptVerdictProgress,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.DeepestOpen(ctx, "conv-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != deep || got.Rung != 4 {
		t.Fatalf("最深的 open 链应是 %s(rung=4),实际 %s(rung=%d)", deep, got.ID, got.Rung)
	}

	list, err := s.List(ctx, "conv-1", ChainOpen)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Rung < list[1].Rung {
		t.Fatalf("List 必须 rung DESC,实际 %+v", list)
	}
}

func TestChainAttemptCascadeOnChainDelete(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()
	id, err := s.Open(ctx, newAnchorChain("conv-1", "vuln:v-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 1, Payload: "p", EvidenceRef: "/tmp/ev/1.txt", Verdict: AttemptVerdictProgress,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM zl_chains WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zl_chain_attempts WHERE chain_id=?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("删链应级联删 attempt,实际残留 %d 条", n)
	}
}

// TestChainCloseBlockedRequiresVariantsAndNextRungBlocker 守住 M1.1 的两条硬门槛：
// 同一台阶 <3 个不同变体、或没写"下一阶为什么到不了"，都不许 blocked。
func TestChainCloseBlockedRequiresVariantsAndNextRungBlocker(t *testing.T) {
	s := newTestChainStore(t)
	ctx := context.Background()
	c := newAnchorChain("conv-m11", "asset:shop.example.com:/api/order")
	id, err := s.Open(ctx, c)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// 只试 1 个变体 + 三要素齐全 → 仍应被拒（没打够）。
	if _, err := s.AddAttempt(ctx, &ChainAttempt{
		ChainID: id, Rung: 1, Payload: "GET /api/order?id=2", EvidenceRef: "/tmp/ev1.txt", Verdict: "rejected",
	}); err != nil {
		t.Fatalf("attempt: %v", err)
	}
	err = s.Close(ctx, id, ChainClose{
		State: ChainBlocked, BlockerEvidence: "/tmp/ev1.txt",
		EnumerationSpace: "1 个变体", UnverifiedSpace: "无", NextRungBlocker: "需要写接口",
	})
	if err == nil || !strings.Contains(err.Error(), "不同变体") {
		t.Fatalf("1 个变体就 blocked 应被拒，实际 err=%v", err)
	}

	// 补齐 3 个不同变体，但缺 next_rung_blocker → 仍应被拒。
	for i, p := range []string{"POST /api/order", "GET /api/order?fmt=json"} {
		if _, err := s.AddAttempt(ctx, &ChainAttempt{
			ChainID: id, Rung: 1, Payload: p + itoaForTest(i), EvidenceRef: "/tmp/ev" + itoaForTest(i+2) + ".txt", Verdict: "rejected",
		}); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	err = s.Close(ctx, id, ChainClose{
		State: ChainBlocked, BlockerEvidence: "/tmp/ev1.txt",
		EnumerationSpace: "3 个变体", UnverifiedSpace: "无",
	})
	if err == nil || !strings.Contains(err.Error(), "next_rung_blocker") {
		t.Fatalf("缺 next_rung_blocker 应被拒，实际 err=%v", err)
	}

	// max_reachable_rung 高于当前 rung = 谎报，拒。
	err = s.Close(ctx, id, ChainClose{
		State: ChainBlocked, BlockerEvidence: "/tmp/ev1.txt",
		EnumerationSpace: "3 个变体", UnverifiedSpace: "无", NextRungBlocker: "需要写接口",
		MaxReachableRung: 3,
	})
	if err == nil || !strings.Contains(err.Error(), "大于当前 rung") {
		t.Fatalf("谎报 max_reachable_rung 应被拒，实际 err=%v", err)
	}

	// 合规：3 变体 + next_rung_blocker + maxReachable==rung → 允许。
	if err := s.Close(ctx, id, ChainClose{
		State: ChainBlocked, BlockerEvidence: "/tmp/ev1.txt",
		EnumerationSpace: "3 个变体", UnverifiedSpace: "需要内网出口", NextRungBlocker: "写接口需认证，源码里未见未授权写",
		MaxReachableRung: 1,
	}); err != nil {
		t.Fatalf("合规 blocked 应通过: %v", err)
	}
}

// TestChainSchemaMigratesM11Columns 守住老库升级：已有 zl_chains 没有 M1.1 两列时，EnsureSchema 要补列。
func TestChainSchemaMigratesM11Columns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000&_foreign_keys=1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	// 模拟 M1 老表（无 max_reachable_rung / next_rung_blocker）。
	if _, err := db.Exec(`CREATE TABLE zl_chains (
		id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, goal_id TEXT NOT NULL DEFAULT '',
		run_id TEXT NOT NULL DEFAULT '', finding_key TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
		rung INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'open',
		hypothesis TEXT NOT NULL DEFAULT '', blocker_evidence TEXT NOT NULL DEFAULT '',
		note TEXT NOT NULL DEFAULT '', target_asset TEXT NOT NULL DEFAULT '',
		hypothesis_type TEXT NOT NULL DEFAULT '', target_model_ref TEXT NOT NULL DEFAULT '',
		enumeration_space TEXT NOT NULL DEFAULT '', unverified_space TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	s, _ := NewChainStore(db)
	if err := s.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("EnsureSchema 迁移失败: %v", err)
	}
	ok1, err1 := s.columnExists(context.Background(), "zl_chains", "max_reachable_rung")
	ok2, err2 := s.columnExists(context.Background(), "zl_chains", "next_rung_blocker")
	if err1 != nil || err2 != nil || !ok1 || !ok2 {
		t.Fatalf("迁移后应有两列: ok1=%v(%v) ok2=%v(%v)", ok1, err1, ok2, err2)
	}
}

// itoaForTest 是测试里的小工具（避免为一段拼接引入 fmt）。
func itoaForTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
