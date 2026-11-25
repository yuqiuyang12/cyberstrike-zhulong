package loop2

// p0_prompt_test.go —— P0 提示词改造的回归断言（2026-11-06，T1-T4）。
//
// 防的失败方式（实测症状）：
//  1. 46 个技能加载成功、133 步里 skill 调用 0 次 —— 提示词把技能写成"随便看的素材字典"；
//  2. KB 3/3 空手 —— 提示词没给"先技能后 KB"的先后顺序，也没给 KB 空之后的纠偏动作；
//  3. risk_type 乱传导致检索恒空 —— 没写"只传真实类目、拿不准不传"；
//  4. coverage-gate 的面提醒只推 KB、不推技能，纠偏文案与 zhulongPreamble 口径不一致。

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"

	_ "github.com/mattn/go-sqlite3"
)

// T1：zhulongPreamble 第 4 条必须是「技能优先,K B补充」口径。
func TestP0PreambleSkillFirst(t *testing.T) {
	for _, want := range []string{
		"技能优先",                             // 顺序：技能在前
		"先按名 skill 加载 1-2 个技能",             // 具体动作
		"risk_type 只传真实类目",                 // T4：risk_type 口径
		"KB 连续 2 次空必须回头加载技能",               // KB 空之后的纠偏
		"禁止空手继续",                           // 不许裸奔
		"照搬=失败",                            // 必须改造到本目标
		"mobile-and-thick-client",          // 面→技能映射（签名还原）
		"crypto-attacks",                   // 面→技能映射（加密）
		"deserialization-and-rce",          // 面→技能映射（反序列化）
		"file-traversal-and-upload",        // 面→技能映射（上传/路径）
		"sqli-sql-injection",               // 面→技能映射（注入）
		"ssrf-server-side-request-forgery", // 面→技能映射（SSRF）
	} {
		if !strings.Contains(zhulongPreamble, want) {
			t.Fatalf("zhulongPreamble 缺要点 %q\n---- 现状 ----\n%s", want, zhulongPreamble)
		}
	}
	// 旧的自贬口径必须消失（它把技能降级成"只是手法字典"）。
	if strings.Contains(zhulongPreamble, "只是手法字典") {
		t.Fatal("zhulongPreamble 仍留着「只是手法字典」的旧口径")
	}
}

// T3：常驻技能清单头部必须是「索引 + 先加载再动手」，不再自贬为"参考素材"。
func TestP0SkillHeaderIsIndex(t *testing.T) {
	head := compactSkillList(context.Background(), nil, 0, 0, false)
	for _, want := range []string{"可加载技能清单", "先按名", "skill", "自造打法", "照搬=失败"} {
		if !strings.Contains(head, want) {
			t.Fatalf("技能清单头部缺要点 %q, 实际: %q", want, head)
		}
	}
	if strings.Contains(head, "全部是参考素材") {
		t.Fatalf("技能清单头部仍有自贬句「全部是参考素材」: %q", head)
	}
}

// T2 + T4：coverage-gate 面提醒改成「先 skill 加载(本面推荐 X)再 search_knowledge_base」，
// 并带 risk_type 口径与「连续 2 次空」纠偏。用最小 sqlite schema 直跑行为函数。
func TestP0KnowledgeTriggerPrefersSkill(t *testing.T) {
	// ① 文案模板本身：要点必须齐（改文案时先看这里）。
	for _, want := range []string{"先 skill 加载", "再 search_knowledge_base", "本面推荐", "%s", "risk_type", "连续 2 次空"} {
		if !strings.Contains(knowledgeTriggerWarnTemplate, want) {
			t.Fatalf("提醒模板缺要点 %q: %s", want, knowledgeTriggerWarnTemplate)
		}
	}

	// ② 运行时行为：进签名还原面且近 20 步没查 KB/没加载技能 → 提醒里必须推技能。
	dir := t.TempDir()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(dir, "p0-kb-gate.db"))
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
	const conv = "conv-p0-kb"

	got := knowledgeTriggerWarnText(ctx, db, conv, "exec",
		`{"command":"curl -s https://api.example.com/sdk.js | grep x-pcs-signature"}`)
	if got == "" {
		t.Fatal("进入签名还原面且未查 KB/未载技能,应提醒")
	}
	for _, want := range []string{"签名还原/风控参数", "先 skill 加载", "mobile-and-thick-client", "连续 2 次空"} {
		if !strings.Contains(got, want) {
			t.Fatalf("提醒缺 %q, 实际: %s", want, got)
		}
	}
	// 抑制逻辑不变：近 20 步内加载过技能 → 静默。
	if _, err := sqlDB.Exec(`INSERT INTO tool_executions (conversation_id, tool_name, arguments) VALUES (?,?,?)`,
		conv, "skill", `{"name":"mobile-and-thick-client"}`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if again := knowledgeTriggerWarnText(ctx, db, conv, "exec", `{"command":"grep x-pcs-signature m.js"}`); again != "" {
		t.Fatalf("近 20 步已加载技能后不应再提醒, 实际: %q", again)
	}

	// ③ 面→技能映射必须覆盖 knowledgeTriggerSignals 的全部面（否则会回落到兜底文案）。
	faces := map[string]bool{}
	for _, sig := range knowledgeTriggerSignals {
		faces[sig.face] = true
	}
	if len(faces) != 8 {
		t.Fatalf("技术面应为 8 个, 实际 %d: %v", len(faces), faces)
	}
	for face := range faces {
		skills, ok := knowledgeTriggerFaceSkillMap[face]
		if !ok || strings.TrimSpace(skills) == "" {
			t.Fatalf("技术面 %q 缺面→技能映射", face)
		}
	}
}
