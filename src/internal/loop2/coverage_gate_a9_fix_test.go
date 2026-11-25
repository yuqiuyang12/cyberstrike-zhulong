package loop2

// coverage_gate_a9_fix_test.go —— P1 缺陷 R-A9 的回归测试（2026-11-06）。
//
// 缺陷两处（证据：~/data/zhulong-p0-2026-11-06/evidence/P1-DEFECT-R-A9.md）：
//   1. 抑制查询里 `tool_name IN (…,'skill')` **永假**——skill 是进程内中间件工具，不写 tool_executions
//      → 12:12 加载 src-hunting、12:16 仍弹「近 20 步内…也没加载对应技能」。
//   2. 三条 LIKE（%skills/% / %skill.md% / %search_knowledge_base%）双向失真：
//      read_file 读技能文件 = 假抑制；fact 正文提到关键词 = 假抑制。
//
// 修法：会话级进程内登记（MarkConversationSkillCalled，不建表）+ 收紧 LIKE 到 JSON 键形态。
// 本测试同时守住"KB 检索抑制不能被改坏"。

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"

	_ "github.com/mattn/go-sqlite3"
)

func newA9DB(t *testing.T) (*database.DB, *sql.DB) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "a9.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if _, err := sqlDB.Exec(`CREATE TABLE tool_executions (
		id INTEGER PRIMARY KEY, conversation_id TEXT, tool_name TEXT, arguments TEXT)`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return &database.DB{DB: sqlDB}, sqlDB
}

func resetSkillCallRegistry() {
	skillCallRegistry.mu.Lock()
	skillCallRegistry.last = map[string]time.Time{}
	skillCallRegistry.mu.Unlock()
}

const a9FaceArgs = `{"command":"curl -s https://api.example.com/sdk.js | grep x-pcs-signature"}`

// ① 本会话加载过技能 → 不再提醒（原实现因永假分支必然误报）。
func TestA9FixLoadedSkillSuppresses(t *testing.T) {
	resetSkillCallRegistry()
	db, _ := newA9DB(t)
	ctx := context.Background()
	const conv = "conv-a9-skill"

	if got := knowledgeTriggerWarnText(ctx, db, conv, "exec", a9FaceArgs); got == "" {
		t.Fatal("基线：进入签名还原面且未加载技能，应提醒")
	}
	// handler 在 skill 工具成功返回时登记（此处等价调用）。
	MarkConversationSkillCalled(conv)
	if got := knowledgeTriggerWarnText(ctx, db, conv, "exec", a9FaceArgs); got != "" {
		t.Fatalf("本会话刚加载过技能，不应再提醒，实际: %q", got)
	}
}

// ② 只有别的会话调过 skill → 本会话仍提醒（不能退化成全局抑制）。
func TestA9FixOtherConversationSkillDoesNotSuppress(t *testing.T) {
	resetSkillCallRegistry()
	db, _ := newA9DB(t)
	ctx := context.Background()
	MarkConversationSkillCalled("conv-a9-other")
	if got := knowledgeTriggerWarnText(ctx, db, "conv-a9-me", "exec", a9FaceArgs); got == "" {
		t.Fatal("别的会话加载过技能，本会话仍应提醒（否则跨会话假抑制）")
	}
}

// ③ KB 检索（tool_executions 真源）仍要抑制 —— 别把原有逻辑改坏。
func TestA9FixKnowledgeSearchStillSuppresses(t *testing.T) {
	resetSkillCallRegistry()
	db, sqlDB := newA9DB(t)
	ctx := context.Background()
	const conv = "conv-a9-kb"
	if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
		conv, "search_knowledge_base", `{"query":"x-pcs 签名还原 判据"}`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := knowledgeTriggerWarnText(ctx, db, conv, "exec", a9FaceArgs); got != "" {
		t.Fatalf("近 20 步查过 KB 应抑制提醒，实际: %q", got)
	}
	// list_knowledge_risk_types 同样算检索动作。
	const conv2 = "conv-a9-kb2"
	if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
		conv2, "list_knowledge_risk_types", `{}`); err != nil {
		t.Fatalf("seed2: %v", err)
	}
	if got := knowledgeTriggerWarnText(ctx, db, conv2, "exec", a9FaceArgs); got != "" {
		t.Fatalf("列过风险类目应抑制提醒，实际: %q", got)
	}
}

// ④ 误报源回归：读技能文件 / fact 正文提到关键词，都**不算**已加载/已查（旧实现会假抑制）。
func TestA9FixFalsePositiveBranchesRemoved(t *testing.T) {
	resetSkillCallRegistry()
	db, sqlDB := newA9DB(t)
	ctx := context.Background()

	cases := []struct {
		conv, tool, args, why string
	}{
		{"conv-a9-fp1", "eino_fs::read_file",
			`{"path":"/home/kali/work/skills/src-hunting/SKILL.md"}`, "读技能文件 ≠ 加载技能"},
		{"conv-a9-fp2", "eino_fs::read_file",
			`{"path":"/home/kali/work/skills/open-redirect/SKILL.md"}`, "skills/ 路径 ≠ 已加载"},
		{"conv-a9-fp3", "upsert_project_fact",
			`{"body":"下一步 search_knowledge_base 查一下 x-pcs 签名"}`, "正文提关键词 ≠ 已查 KB"},
	}
	for _, c := range cases {
		if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
			c.conv, c.tool, c.args); err != nil {
			t.Fatalf("seed: %v", err)
		}
		got := knowledgeTriggerWarnText(ctx, db, c.conv, "exec", a9FaceArgs)
		// 注：upsert_project_fact 属于"A9 不触发的记账类工具"，但那条判定看的是**当前**工具；
		// 这里是"历史里有一条记账行"，提醒仍应发出。
		if got == "" || !strings.Contains(got, "签名还原") {
			t.Fatalf("%s：应仍提醒，实际 %q", c.why, got)
		}
	}
}
