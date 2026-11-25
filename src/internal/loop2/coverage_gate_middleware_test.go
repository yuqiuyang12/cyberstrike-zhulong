package loop2

// coverage_gate_middleware_test.go —— 覆盖软门的行为验收(2026-10-22 ncc3 修复)
//
// 验收目标(对应 task-10 的 B3/A1/A5):
//  1) 噪声 token 不再触发 newAsset 告警(ncc3 3 小时 133 次的根因);
//  2) 真资产切换仍然告警(门不能因为修噪声而失效);
//  3) 记账类工具(mark_face_done 等)不算切换;
//  4) 进 path/param 前,port 面无证据 → 软提醒;
//  5) probe_plan 后 10 步没 face_probe → 软提醒(计划不能只生不执行)。

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp/builtin"

	"github.com/cloudwego/eino/compose"
	_ "github.com/mattn/go-sqlite3"
)

const gateTestConv = "conv-gate-1"

func newGateTestStore(t *testing.T) (*coverage.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "gate.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := coverage.EnsureSchema(db); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return coverage.NewStore(db), func() { db.Close() }
}

// gateRunner 用一个假 endpoint 驱动中间件,返回"结果字符串"。
type gateRunner struct {
	mw compose.ToolMiddleware
}

func newGateRunner(t *testing.T) (*gateRunner, *coverage.Store, func()) {
	t.Helper()
	store, done := newGateTestStore(t)
	mw := newCoverageGateMiddleware(store, gateTestConv, nil, nil, nil)
	return &gateRunner{mw: mw}, store, done
}

func (g *gateRunner) call(t *testing.T, name, args string) string {
	t.Helper()
	if g.mw.Invokable == nil {
		t.Fatal("中间件未构造(Invokable=nil)")
	}
	next := func(ctx context.Context, in *compose.ToolInput) (*compose.ToolOutput, error) {
		return &compose.ToolOutput{Result: "OK:" + in.Name}, nil
	}
	wrapped := g.mw.Invokable(next)
	out, err := wrapped(context.Background(), &compose.ToolInput{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("wrapped: %v", err)
	}
	if out == nil {
		t.Fatal("wrapped 返回 nil")
	}
	if !strings.Contains(out.Result, "OK:"+name) {
		t.Fatalf("原始结果被破坏: %q", out.Result)
	}
	return out.Result
}

func hasSwitchWarn(s string) bool { return strings.Contains(s, "[coverage-gate] 提醒:当前资产") }

func TestCoverageGateIgnoresNoiseTokens(t *testing.T) {
	g, store, done := newGateRunner(t)
	defer done()
	ctx := context.Background()
	if err := store.EnsureAsset(ctx, gateTestConv, "erp.zstack.io"); err != nil {
		t.Fatalf("EnsureAsset: %v", err)
	}
	// ncc3 真实噪声:文件、Python 属性、第三方域、回环、UA 版本号
	noisy := `{"command":"wpscan -o wpscan.txt; cat robots.txt proof/wpscan.txt; ` +
		`python3 -c \"import sqlite3,collections; sqlite3.connect('arsenal-cve.db'); collections.counter([])\"; ` +
		`curl -s https://api.github.com/orgs/zstack; curl -s http://127.0.0.1:9222/json/version; ` +
		`UA='Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36'; cat nmap-top1000.gnmap favicon.png 101-37-90-58-root.html"}`
	out := g.call(t, "exec", noisy)
	if hasSwitchWarn(out) {
		t.Fatalf("噪声 token 触发了资产切换告警(门会失真): %q", out)
	}
}

func TestCoverageGateWarnsOnRealSwitch(t *testing.T) {
	g, store, done := newGateRunner(t)
	defer done()
	ctx := context.Background()
	if err := store.EnsureAsset(ctx, gateTestConv, "erp.zstack.io"); err != nil {
		t.Fatalf("EnsureAsset 1: %v", err)
	}
	// 后登记的资产成为"当前资产"(CurrentAsset 按 updated_at/rowid 取最新)
	if err := store.EnsureAsset(ctx, gateTestConv, "47.243.58.27"); err != nil {
		t.Fatalf("EnsureAsset 2: %v", err)
	}
	cur, err := store.CurrentAsset(ctx, gateTestConv)
	if err != nil {
		t.Fatalf("CurrentAsset: %v", err)
	}
	if cur != "47.243.58.27" {
		t.Fatalf("当前资产应为 47.243.58.27,实际 %q", cur)
	}

	out := g.call(t, "exec", `{"command":"curl -sk https://erp.zstack.io/api/v1/users"}`)
	if !hasSwitchWarn(out) {
		t.Fatalf("真资产切换应告警,实际: %q", out)
	}
	if !strings.Contains(out, "erp.zstack.io") || !strings.Contains(out, "47.243.58.27") {
		t.Fatalf("告警应同时包含当前资产与新资产: %q", out)
	}

	// 10 分钟去重:同 (target,current) 第二次不再提醒
	out2 := g.call(t, "exec", `{"command":"curl -sk https://erp.zstack.io/api/v1/roles"}`)
	if hasSwitchWarn(out2) {
		t.Fatalf("去重失效,同一对资产重复告警: %q", out2)
	}
}

func TestCoverageGateSkipsLedgerTools(t *testing.T) {
	g, store, done := newGateRunner(t)
	defer done()
	ctx := context.Background()
	if err := store.EnsureAsset(ctx, gateTestConv, "erp.zstack.io"); err != nil {
		t.Fatalf("EnsureAsset: %v", err)
	}
	if err := store.EnsureAsset(ctx, gateTestConv, "47.243.58.27"); err != nil {
		t.Fatalf("EnsureAsset: %v", err)
	}
	// mark_face_done 里出现另一个资产 = 记账,不是切换
	out := g.call(t, builtin.ToolMarkFaceDone,
		`{"asset":"erp.zstack.io","face":"port","state":"done","evidence_ref":"/ev/nmap.gnmap"}`)
	if hasSwitchWarn(out) {
		t.Fatalf("记账工具不应触发新资产告警: %q", out)
	}
	// 带命名空间的工具名也要能被识别为记账工具
	out = g.call(t, "mcp__cyberstrike__coverage_report", `{"top":5,"asset":"erp.zstack.io"}`)
	if hasSwitchWarn(out) {
		t.Fatalf("命名空间形式的 coverage_report 不应告警: %q", out)
	}
}

func TestCoverageGatePortEvidenceWarn(t *testing.T) {
	// 场景 A:port 面 open + 证据空 → 进 path 面前提醒
	g, store, done := newGateRunner(t)
	ctx := context.Background()
	if err := store.EnsureAsset(ctx, gateTestConv, "erp.zstack.io"); err != nil {
		t.Fatalf("EnsureAsset: %v", err)
	}
	out := g.call(t, builtin.ToolFaceProbe, `{"asset":"erp.zstack.io","face":"path"}`)
	if !strings.Contains(out, "[coverage-gate] 提醒") || !strings.Contains(out, "port 面") {
		t.Fatalf("port 面无证据应提醒,实际: %q", out)
	}
	// 同一资产第二次不再刷屏(10 分钟去重)
	if out2 := g.call(t, builtin.ToolFaceProbe, `{"asset":"erp.zstack.io","face":"param"}`); strings.Contains(out2, "port 面") {
		t.Fatalf("port 提醒去重失效: %q", out2)
	}
	done()

	// 场景 B:port 面 done 且证据含 top1000 → 不再提醒
	g2, store2, done2 := newGateRunner(t)
	defer done2()
	if err := store2.EnsureAsset(ctx, gateTestConv, "fx-machine.zstack.io"); err != nil {
		t.Fatalf("EnsureAsset: %v", err)
	}
	if err := store2.SetFace(ctx, gateTestConv, "fx-machine.zstack.io", coverage.FacePort,
		coverage.StateDone, "/recon/nmap-top1000.gnmap", ""); err != nil {
		t.Fatalf("SetFace port: %v", err)
	}
	out = g2.call(t, builtin.ToolFaceProbe, `{"asset":"fx-machine.zstack.io","face":"path"}`)
	if strings.Contains(out, "port 面") {
		t.Fatalf("有端口扫描证据时不应提醒: %q", out)
	}

	// 场景 B2:port 面 done 且证据是 face_probe 自己的 face-port-*.jsonl → 不提醒
	if err := store2.SetFace(ctx, gateTestConv, "fx-machine.zstack.io", coverage.FacePort,
		coverage.StateDone, "/recon/php2shell/face-port-1792647331.jsonl", ""); err != nil {
		t.Fatalf("SetFace port face-port: %v", err)
	}
	out = g2.call(t, builtin.ToolFaceProbe, `{"asset":"fx-machine.zstack.io","face":"param"}`)
	if strings.Contains(out, "port 面") || strings.Contains(out, "端口扫描痕迹") {
		t.Fatalf("face-port 证据应被认作端口扫描: %q", out)
	}

	// 场景 C:port 面 done 但证据里没有扫描痕迹 → 仍提醒(盖章 ≠ 扫过)
	if err := store2.SetFace(ctx, gateTestConv, "fx-machine.zstack.io", coverage.FacePort,
		coverage.StateDone, "/ev/screenshot.png", ""); err != nil {
		t.Fatalf("SetFace port 2: %v", err)
	}
	out = g2.call(t, builtin.ToolFaceProbe, `{"asset":"fx-machine.zstack.io","face":"auth"}`)
	if !strings.Contains(out, "evidence_ref 里没有端口扫描痕迹") {
		t.Fatalf("done 但证据不实应提醒,实际: %q", out)
	}
}

func TestCoverageGatePlanExecBinding(t *testing.T) {
	g, store, done := newGateRunner(t)
	defer done()
	ctx := context.Background()
	if err := store.EnsureAsset(ctx, gateTestConv, "erp.zstack.io"); err != nil {
		t.Fatalf("EnsureAsset: %v", err)
	}
	// probe_plan:只生成计划
	if out := g.call(t, builtin.ToolProbePlan, `{"base_url":"https://erp.zstack.io","paths":["/"]}`); strings.Contains(out, "计划") {
		t.Fatalf("probe_plan 本身不应提醒计划未执行: %q", out)
	}
	// 前 9 步不提醒(ncc3 实测:计划 11:36 生成、face_probe 13:35 才用 → 十步内没执行)
	for i := 1; i <= 9; i++ {
		out := g.call(t, "exec", `{"command":"echo step"}`)
		if strings.Contains(out, "计划不执行等于没测") {
			t.Fatalf("第 %d 步就提醒了(窗口应为 %d 步): %q", i, planExecMaxSteps, out)
		}
	}
	out := g.call(t, "exec", `{"command":"echo step10"}`)
	if !strings.Contains(out, "计划不执行等于没测") {
		t.Fatalf("第 %d 步应提醒计划未执行,实际: %q", planExecMaxSteps, out)
	}
	// 之后不重复刷屏
	if out := g.call(t, "exec", `{"command":"echo step11"}`); strings.Contains(out, "计划不执行等于没测") {
		t.Fatalf("计划未执行提醒应只发一次: %q", out)
	}
	// 执行计划后清账:再生成一次计划,1 步后 face_probe → 后续不再提醒
	g.call(t, builtin.ToolProbePlan, `{"base_url":"https://erp.zstack.io"}`)
	g.call(t, "exec", `{"command":"echo y"}`)
	g.call(t, builtin.ToolFaceProbe, `{"asset":"erp.zstack.io","face":"path"}`)
	for i := 0; i < 12; i++ {
		if out := g.call(t, "exec", `{"command":"echo after"}`); strings.Contains(out, "计划不执行等于没测") {
			t.Fatalf("face_probe 已执行计划,不应再提醒: %q", out)
		}
	}
}

func TestCoverageGateLedgerAwareAssets(t *testing.T) {
	// 台账里显式登记过、但字面过不了严格校验的资产(如内网别名),仍应被识别为"目标",
	// 否则"同一套规则"会把真实资产漏掉。
	g, store, done := newGateRunner(t)
	defer done()
	ctx := context.Background()
	if err := store.EnsureAsset(ctx, gateTestConv, "oa"); err != nil {
		t.Fatalf("EnsureAsset oa: %v", err)
	}
	if err := store.EnsureAsset(ctx, gateTestConv, "erp.zstack.io"); err != nil {
		t.Fatalf("EnsureAsset erp: %v", err)
	}
	out := g.call(t, "exec", `{"command":"curl -s http://oa/login"}`)
	if !hasSwitchWarn(out) || !strings.Contains(out, "oa") {
		t.Fatalf("台账里的非标准资产应被识别并告警,实际: %q", out)
	}
}

func TestCoverageGatePortHintBudget(t *testing.T) {
	// A1 每会话最多投递 PortHintBudgetPerSession 条:沉淀在"提醒要不要先扫端口"上会变成新噪声。
	g, store, done := newGateRunner(t)
	defer done()
	ctx := context.Background()
	hints := 0
	for i := 0; i < coverage.PortHintBudgetPerSession+3; i++ {
		asset := fmt.Sprintf("h%d.zstack.io", i)
		if err := store.EnsureAsset(ctx, gateTestConv, asset); err != nil {
			t.Fatalf("EnsureAsset %s: %v", asset, err)
		}
		out := g.call(t, builtin.ToolFaceProbe, `{"asset":"`+asset+`","face":"path"}`)
		if strings.Contains(out, "port 面") {
			hints++
		}
	}
	if hints != coverage.PortHintBudgetPerSession {
		t.Fatalf("A1 提示应为 %d 条(预算),实际 %d 条", coverage.PortHintBudgetPerSession, hints)
	}
}

// TestCVELookupWarn 验收 A7:cve 面收口必须有检索痕迹(2026-10-27 乐橙事故)。
//  1. face_probe(face=cve) 不算查证 —— 它只做指纹,未命中什么也没证明;
//  2. exec 里跑过 cve_db.py / arsenal.json 才算查证;
//  3. db 为 nil 时静默返回空(不改变现有链路)。
func TestCVELookupWarn(t *testing.T) {
	dir := t.TempDir()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(dir, "cve-gate.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer sqlDB.Close()
	if _, err := sqlDB.Exec(`CREATE TABLE tool_executions (
		id INTEGER PRIMARY KEY, conversation_id TEXT, tool_name TEXT, arguments TEXT)`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	db := &database.DB{DB: sqlDB}
	ctx := context.Background()
	const conv = "conv-cve-1"

	if got := cveLookupWarnText(ctx, nil, conv); got != "" {
		t.Fatalf("db 为 nil 时应静默,实际: %q", got)
	}

	// 只有 face_probe(cve):不算查证 → 必须提醒
	if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
		conv, "face_probe", `{"asset":"mall.imou.com","face":"cve"}`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if got := cveLookupWarnText(ctx, db, conv); got == "" {
		t.Fatal("只有 face_probe(cve) 时应提醒「没有 CVE/武库检索痕迹」")
	}

	// 补一次真实检索 → 不再提醒
	if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
		conv, "exec", `{"command":"python3 scripts/cve_db.py -p spring-boot"}`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if got := cveLookupWarnText(ctx, db, conv); got != "" {
		t.Fatalf("已跑 cve_db.py 后不应提醒,实际: %q", got)
	}

	// 别的会话不受影响(按 conversation_id 隔离)
	if got := cveLookupWarnText(ctx, db, "conv-other"); got == "" {
		t.Fatal("另一个会话没有检索痕迹,应提醒")
	}
}

// TestLedgerLibraryReconcileWarn 验收 A8:覆盖台账 ↔ 资产库对账(2026-10-27 乐橙事故)。
// 台账由 probe 工具自动登记,资产库只由 create_asset 手工写 —— 两边不互通时用户看不到资产。
func TestLedgerLibraryReconcileWarn(t *testing.T) {
	dir := t.TempDir()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(dir, "reconcile.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer sqlDB.Close()
	for _, ddl := range []string{
		`CREATE TABLE conversations (id TEXT PRIMARY KEY, project_id TEXT)`,
		`CREATE TABLE asset_coverage (conversation_id TEXT, asset TEXT)`,
		`CREATE TABLE assets (project_id TEXT, host TEXT)`,
	} {
		if _, err := sqlDB.Exec(ddl); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	const conv = "conv-reconcile-1"
	if _, err := sqlDB.Exec(`INSERT INTO conversations (id, project_id) VALUES (?,?)`, conv, "proj-1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, h := range []string{"a.example.com", "b.example.com"} {
		if _, err := sqlDB.Exec(`INSERT INTO asset_coverage (conversation_id, asset) VALUES (?,?)`, conv, h); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if _, err := sqlDB.Exec(`INSERT INTO assets (project_id, host) VALUES (?,?)`, "proj-1", "a.example.com"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	db := &database.DB{DB: sqlDB}
	ctx := context.Background()

	got := ledgerLibraryReconcileWarnText(ctx, db, conv)
	if got == "" {
		t.Fatal("b.example.com 只在台账、不在资产库,应提醒")
	}
	if !strings.Contains(got, "b.example.com") || strings.Contains(got, "a.example.com") {
		t.Fatalf("应只点名缺失的 b.example.com,实际: %s", got)
	}

	// 补录后应静默
	if _, err := sqlDB.Exec(`INSERT INTO assets (project_id, host) VALUES (?,?)`, "proj-1", "b.example.com"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := ledgerLibraryReconcileWarnText(ctx, db, conv); got != "" {
		t.Fatalf("补齐后应静默,实际: %s", got)
	}

	// 会话未绑项目 → 退化为全库比对(不误报)
	if _, err := sqlDB.Exec(`UPDATE conversations SET project_id='' WHERE id=?`, conv); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := ledgerLibraryReconcileWarnText(ctx, db, conv); got != "" {
		t.Fatalf("未绑项目时应全库比对且已存在,不应提醒,实际: %s", got)
	}

	if got := ledgerLibraryReconcileWarnText(ctx, nil, conv); got != "" {
		t.Fatalf("db 为 nil 时应静默,实际: %s", got)
	}
}

// TestKnowledgeTriggerWarn 验收 A9:进入技术面却没查知识库/技能 → 提醒一次(2026-10-27 乐橙第三轮事故)。
func TestKnowledgeTriggerWarn(t *testing.T) {
	dir := t.TempDir()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(dir, "kb-gate.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer sqlDB.Close()
	if _, err := sqlDB.Exec(`CREATE TABLE tool_executions (
		id INTEGER PRIMARY KEY, conversation_id TEXT, tool_name TEXT, arguments TEXT)`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	db := &database.DB{DB: sqlDB}
	ctx := context.Background()
	const conv = "conv-kb-1"

	// ① 进签名还原面 + 近 20 步没查 KB → 必须提醒,且点出"签名还原"
	got := knowledgeTriggerWarnText(ctx, db, conv, "exec",
		`{"command":"curl -s https://auth.example.com/_nuxt/K7vArGXf.js -o m.js && grep x-pcs m.js"}`)
	if got == "" || !strings.Contains(got, "签名还原") {
		t.Fatalf("进入签名还原面且未查 KB,应提醒签名还原,实际: %q", got)
	}
	// ② 记账类工具提到技术面 → 不提醒(提及 ≠ 在该面作业)
	if got := knowledgeTriggerWarnText(ctx, db, conv, "upsert_project_fact", `{"body":"x-pcs 签名还原笔记"}`); got != "" {
		t.Fatalf("记账工具不应触发 A9,实际: %q", got)
	}
	// ③ 无关关键词 → 不提醒
	if got := knowledgeTriggerWarnText(ctx, db, conv, "exec", `{"command":"ls -la"}`); got != "" {
		t.Fatalf("无技术面关键词不应提醒,实际: %q", got)
	}
	// ④ 近 20 步内查过 KB → 不再提醒
	if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
		conv, "search_knowledge_base", `{"query":"x-pcs 签名还原 判据"}`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := knowledgeTriggerWarnText(ctx, db, conv, "exec", `{"command":"grep x-pcs m.js"}`); got != "" {
		t.Fatalf("已查过 KB 后不应提醒,实际: %q", got)
	}
	// ⑤ db 为 nil → 静默
	if got := knowledgeTriggerWarnText(ctx, nil, conv, "exec", `{"command":"grep x-pcs m.js"}`); got != "" {
		t.Fatalf("db 为 nil 应静默,实际: %q", got)
	}
}

// TestCVELookupWarnWindow 验收 A7 窗口修复:旧的事故提及不能永久放行 cve 面收口。
func TestCVELookupWarnWindow(t *testing.T) {
	dir := t.TempDir()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(dir, "cve-window.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer sqlDB.Close()
	if _, err := sqlDB.Exec(`CREATE TABLE tool_executions (
		id INTEGER PRIMARY KEY, conversation_id TEXT, tool_name TEXT, arguments TEXT)`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	db := &database.DB{DB: sqlDB}
	ctx := context.Background()
	const conv = "conv-cve-window"

	// 一条"旧提及"(which nuclei),随后 45 步无关动作把它挤出近 40 步窗口
	if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
		conv, "exec", `{"command":"which nuclei && ls poc-curated"}`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for i := 0; i < 45; i++ {
		if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
			conv, "exec", `{"command":"curl -sI https://example.com"}`); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if got := cveLookupWarnText(ctx, db, conv); got == "" {
		t.Fatal("旧提及被挤出窗口后,cve 面收口应重新提醒")
	}
	// 真的查一次 → 静默
	if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
		conv, "exec", `{"command":"python3 scripts/cve_db.py -p spring-boot"}`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := cveLookupWarnText(ctx, db, conv); got != "" {
		t.Fatalf("窗口内已查 cve_db 后不应提醒,实际: %q", got)
	}
}
