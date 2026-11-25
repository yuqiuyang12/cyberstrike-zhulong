package zhulong

// p2_fixes_test.go —— P2 小修：skill 步 evidence_ref 失真 + continue 措辞混淆（2026-11-06）。
//
// ① 实测缺陷：4 条 skill 步的 evidence_ref 全是 `/skill-as-boost.md`、`/thick-client-desktop.md`
//    这类技能正文里的相对碎片（ExtractEvidenceRef 从输出里"猜最后一个路径"）。
//    修法：skill 一律以**真实存在的技能目录**做 ref，不猜路径；解析不到则留空。
// ② MarkContinuePending 旧文案把「模型自主 continue」也写成「打回: 未通过交付判据」，
//    与「done 被闸门打回」无法区分。修法：两种来源用不同文案。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 造一个假技能树：<root>/<name>/SKILL.md + references/xxx.md
func newFakeSkill(t *testing.T) (root, name, dir string) {
	t.Helper()
	root = t.TempDir()
	name = "mobile-and-thick-client"
	dir = filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(dir, "references"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# skill\n判据：...\n"), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	for _, f := range []string{"skill-as-boost.md", "thick-client-desktop.md"} {
		if err := os.WriteFile(filepath.Join(dir, "references", f), []byte("ref"), 0o644); err != nil {
			t.Fatalf("write ref: %v", err)
		}
	}
	return root, name, dir
}

func TestSkillEvidenceRefPointsToRealDir(t *testing.T) {
	_, _, dir := newFakeSkill(t)

	// 真实 skill 输出形态：目录自述行 + 大量相对碎片（碎片会被旧实现当成 ref）。
	out := "正在启动 Skill：mobile-and-thick-client\n" +
		"此 Skill 的目录：" + dir + "\n\n# 正文\n" +
		"- references/skill-as-boost.md\n- references/thick-client-desktop.md\n" +
		"更多：/references/thick-client-desktop.md\n"

	ref := ExtractEvidenceRefForTool("skill", out)
	if ref != dir {
		t.Fatalf("skill 步 ref 必须指向真实技能目录 %q, 实际 %q", dir, ref)
	}
	if st, err := os.Stat(ref); err != nil || !st.IsDir() {
		t.Fatalf("ref 必须是存在目录: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ref, "SKILL.md")); err != nil {
		t.Fatalf("ref 目录内必须有 SKILL.md: %v", err)
	}
	// 通用 ExtractEvidenceRef 也认这条自述行（native turnloop 走的是它）。
	if got := ExtractEvidenceRef(out); got != dir {
		t.Fatalf("ExtractEvidenceRef 应认 skill 目录自述行, 实际 %q", got)
	}
	// 不存在的碎片绝不能变成 ref（旧实现会返回 /skill-as-boost.md）。
	fragOnly := "正文：- references/skill-as-boost.md\n- references/thick-client-desktop.md\n"
	if got := ExtractEvidenceRefForTool("skill", fragOnly); got != "" {
		t.Fatalf("skill 输出只有相对碎片时应留空而不是猜路径, 实际 %q", got)
	}
	// 非 skill 工具行为不变（仍取落盘路径）。
	if got := ExtractEvidenceRef(`{"ok":true} [saved] /tmp/e/order-2.json`); got != "/tmp/e/order-2.json" {
		t.Fatalf("非 skill 工具应沿用原逻辑, 实际 %q", got)
	}
}

func TestMarkContinuePendingDistinguishesSource(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// ① 模型自主 continue（无 codes）
	if err := store.CreateRun(ctx, &Run{ID: "zl-run-c-auto", ConversationID: "c-auto", GoalID: "g-auto"}); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := store.StartRun(ctx, "zl-run-c-auto"); err != nil {
		t.Fatalf("start run: %v", err)
	}
	if err := store.MarkContinuePending(ctx, "zl-run-c-auto", ""); err != nil {
		t.Fatalf("mark auto: %v", err)
	}
	auto, _ := store.GetRun(ctx, "zl-run-c-auto")

	// ② done 被 DecideDelivery 打回（带 codes）
	if err := store.CreateRun(ctx, &Run{ID: "zl-run-c-gate", ConversationID: "c-gate", GoalID: "g-gate"}); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := store.StartRun(ctx, "zl-run-c-gate"); err != nil {
		t.Fatalf("start run: %v", err)
	}
	if err := store.MarkContinuePending(ctx, "zl-run-c-gate", "open_chains,not_anchored"); err != nil {
		t.Fatalf("mark gate: %v", err)
	}
	gate, _ := store.GetRun(ctx, "zl-run-c-gate")

	if !strings.Contains(auto.Summary, "模型自主") || strings.Contains(auto.Summary, "打回") {
		t.Fatalf("模型自主 continue 不应出现「打回」: %q", auto.Summary)
	}
	if !strings.Contains(gate.Summary, "打回: open_chains,not_anchored") {
		t.Fatalf("闸门打回应带 codes: %q", gate.Summary)
	}
	if auto.Summary == gate.Summary {
		t.Fatalf("两种来源文案必须不同, 都是 %q", auto.Summary)
	}
	if auto.State != StateContinuePending || gate.State != StateContinuePending {
		t.Fatalf("两条都应是 continue_pending: %v %v", auto.State, gate.State)
	}
}
