package zhulong

// delivery_test.go —— 回执「能不能交卷」的确定性判据测试（烛龙 M1 · 任务 C）。
//
// 防的失败方式（每条都对应一次真实翻车）：
//  1. open 链还有一堆，模型交 done 就收工 → 链条一根都没推进（交委实测）；
//  2. 只有"通用 n-day / 清单"线索也交 done → 打的是自己的目标，交付却是别人的 checklist；
//  3. deliver_gate 首行 CONTINUE，run 仍然判 done → 闸门只是装饰；
//  4. 闸门未接线时静默放行 → 又回到"模型自报 done"的老 bug；
//  5. 每轮工具调用不落库 → 事后无法复核这一轮到底打了什么（本轮 zhulong_steps 0 行）；
//  6. 自动续轮的 objective 退化成"补覆盖/扫剩下的面" → 深度被降级成广度。

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func mustParseDoneReceipt(t *testing.T, nextActions ...string) *Receipt {
	t.Helper()
	next := "[]"
	if len(nextActions) > 0 {
		quoted := make([]string, 0, len(nextActions))
		for _, a := range nextActions {
			quoted = append(quoted, `"`+a+`"`)
		}
		next = "[" + strings.Join(quoted, ",") + "]"
	}
	text := "本轮结论。\n\n```zhulong\n" +
		`{"outcome":"done","summary":"推到 rung=2","evidence_refs":["/tmp/e/order.json"],"next_actions":` + next + "}" +
		"\n```"
	r, err := ParseReceipt(text)
	if err != nil {
		t.Fatalf("解析 done 回执失败: %v", err)
	}
	return r
}

func TestValidateAgainstChains(t *testing.T) {
	// 1) open 链未归零 → 回执非法（spec C1 硬校验）
	r := mustParseDoneReceipt(t)
	err := r.ValidateAgainstChains(ChainFacts{Total: 3, Open: 1, Exploited: 2, Depth: 2, Anchored: 2})
	if err == nil {
		t.Fatal("open 链=1 时 done 必须判非法")
	}
	if !strings.Contains(err.Error(), "仍有 1 条 open 链") {
		t.Fatalf("错误信息要写清还有几条链: %v", err)
	}
	if !isInvalidReceipt(err) {
		t.Fatalf("应是 ErrInvalidReceipt 族: %v", err)
	}

	// 2) open=0 但没有一条链锚定目标自身 → 回执非法（spec v2）
	r = mustParseDoneReceipt(t)
	err = r.ValidateAgainstChains(ChainFacts{Total: 4, Open: 0, Exploited: 4, Depth: 3, Anchored: 0})
	if err == nil {
		t.Fatal("没有锚定链时 done 必须判非法")
	}
	if !strings.Contains(err.Error(), "没有一条链锚定到目标自身模型") {
		t.Fatalf("错误信息要指出缺锚定: %v", err)
	}

	// 3) 两个前置都满足 → 合法
	r = mustParseDoneReceipt(t)
	if err := r.ValidateAgainstChains(ChainFacts{Total: 2, Open: 0, Exploited: 2, Depth: 4, Anchored: 1}); err != nil {
		t.Fatalf("前置满足时不应报错: %v", err)
	}

	// 4) 非 done（continue/nothing/blocked）不做交付校验
	r = &Receipt{Outcome: OutcomeContinue, Summary: "推到一半"}
	if err := r.ValidateAgainstChains(ChainFacts{Open: 5, Anchored: 0}); err != nil {
		t.Fatalf("continue 不应被交付校验拦住: %v", err)
	}
}

// 防死锁：干净目标（0 洞 0 链）不该被"必须有锚定链"永久卡住；有洞或有链时仍要拦。
func TestAnchorRuleDeadlockGuard(t *testing.T) {
	r := mustParseDoneReceipt(t)

	// 0 链 0 洞：跳过锚定规则（交给覆盖率闸门判）
	if _, reasons := DecideDelivery(r, ChainFacts{}, "PASS", "", "", nil); len(reasons) != 0 {
		t.Fatalf("0 洞 0 链时不应因锚定规则打回: %+v", reasons)
	}
	if err := r.ValidateAgainstChains(ChainFacts{}); err != nil {
		t.Fatalf("0 洞 0 链时严格校验也不该报错: %v", err)
	}

	// 有洞没链 → 必须拦（有该深挖的东西却只交了广度）
	_, reasons := DecideDelivery(r, ChainFacts{ConfirmedVulns: 2}, "PASS", "", "", nil)
	if !hasCode(reasons, "no-anchored-chain") {
		t.Fatalf("有确认漏洞却没有锚定链时必须打回, 实际 %+v", reasons)
	}
	// 有链但都不锚定 → 必须拦
	_, reasons = DecideDelivery(r, ChainFacts{Total: 3, Exploited: 3, Anchored: 0}, "PASS", "", "", nil)
	if !hasCode(reasons, "no-anchored-chain") {
		t.Fatalf("有链但无锚定链时必须打回, 实际 %+v", reasons)
	}
}

// 严格入口：done + open 链 → ParseReceiptAgainstChains 直接拒收（spec C1 的"回执判非法"）。
func TestParseReceiptAgainstChainsRejectsDone(t *testing.T) {
	text := "结论。\n\n```zhulong\n" +
		`{"outcome":"done","summary":"推进完成","evidence_refs":["/tmp/e/a.json"]}` +
		"\n```"
	if _, err := ParseReceiptAgainstChains(text, ChainFacts{Total: 2, Open: 1, Depth: 2, Anchored: 2}); err == nil {
		t.Fatal("open 链未归零时严格解析必须报错")
	}
	if _, err := ParseReceiptAgainstChains(text, ChainFacts{Total: 2, Open: 0, Depth: 2, Anchored: 0}); err == nil {
		t.Fatal("没有锚定链时严格解析必须报错")
	}
	if _, err := ParseReceiptAgainstChains(text, ChainFacts{Total: 2, Open: 0, Depth: 2, Anchored: 1}); err != nil {
		t.Fatalf("前置满足时不应报错: %v", err)
	}
}

func isInvalidReceipt(err error) bool {
	for err != nil {
		if err == ErrInvalidReceipt {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// 核心用例：done + gate CONTINUE → 不判 done（老 bug 就是这里放行的）。
func TestDecideDeliveryGateContinueBlocksDone(t *testing.T) {
	r := mustParseDoneReceipt(t, "把 shop.example.com 的 /api/order/detail 的 id 换号再试")
	facts := ChainFacts{Total: 2, Open: 0, Exploited: 2, Depth: 3, Anchored: 2}

	outcome, reasons := DecideDelivery(r, facts, "CONTINUE", "open-chains", "advance the chain", []string{"shop.example.com"})
	if outcome != OutcomeContinue {
		t.Fatalf("闸门 CONTINUE 时不得判 done，实际 %s", outcome)
	}
	if !hasCode(reasons, "gate-not-pass") {
		t.Fatalf("应给出 gate-not-pass 理由, 实际 %+v", reasons)
	}

	// PASS + 无 open 链 + 有锚定链 + next_actions 目标特定 → 才允许 done
	outcome, reasons = DecideDelivery(r, facts, "PASS", "closed+registered", "", []string{"shop.example.com"})
	if outcome != OutcomeDone {
		t.Fatalf("四个前置都满足时应判 done，实际 %s（理由 %+v）", outcome, reasons)
	}
}

// lead 裁决 1b：闸门未接线时必须保守判 continue。
func TestDecideDeliveryUnwiredGateBlocksDone(t *testing.T) {
	r := mustParseDoneReceipt(t)
	facts := ChainFacts{Total: 1, Open: 0, Exploited: 1, Depth: 2, Anchored: 1}

	outcome, reasons := DecideDelivery(r, facts, "", "", "", nil)
	if outcome != OutcomeContinue {
		t.Fatalf("闸门未接线时不得判 done，实际 %s", outcome)
	}
	if !hasCode(reasons, "unwired-gate") {
		t.Fatalf("应给出 unwired-gate 理由, 实际 %+v", reasons)
	}

	// open 链 > 0 或 specific=0 时，即使没有任何闸门结论也必须 continue（同一个保守结论）。
	outcome, reasons = DecideDelivery(r, ChainFacts{Total: 1, Open: 1, Anchored: 1}, "PASS", "", "", nil)
	if outcome != OutcomeContinue || !hasCode(reasons, "open-chains") {
		t.Fatalf("open 链>0 必须 continue, 实际 %s %+v", outcome, reasons)
	}
	outcome, reasons = DecideDelivery(r, ChainFacts{Total: 1, Open: 0, Anchored: 0}, "PASS", "", "", nil)
	if outcome != OutcomeContinue || !hasCode(reasons, "no-anchored-chain") {
		t.Fatalf("无锚定链必须 continue, 实际 %s %+v", outcome, reasons)
	}
}

// next_actions 全是通用套话 → 降级 continue（不是非法，是"还没交卷"）。
func TestDecideDeliveryGenericNextActionsDowngrade(t *testing.T) {
	r := mustParseDoneReceipt(t, "继续补覆盖", "扫剩下的面")
	facts := ChainFacts{Total: 1, Open: 0, Exploited: 1, Depth: 2, Anchored: 1}
	anchors := []string{"shop.example.com", "10.1.2.3"}

	outcome, reasons := DecideDelivery(r, facts, "PASS", "", "", anchors)
	if outcome != OutcomeContinue {
		t.Fatalf("通用 next_actions 应降级 continue，实际 %s", outcome)
	}
	if !hasCode(reasons, "generic-next-actions") {
		t.Fatalf("应给出 generic-next-actions 理由, 实际 %+v", reasons)
	}

	// 锚点为空 = 无法判断 → 不误伤
	if _, reasons := DecideDelivery(r, facts, "PASS", "", "", nil); len(reasons) != 0 {
		t.Fatalf("无锚点时不应因 next_actions 打回: %+v", reasons)
	}
}

func TestBuildContinueObjectiveText(t *testing.T) {
	// 2026-11-08 用户裁定：续轮指令就是人话——默认「继续」，不再拼模板。
	if got := BuildContinueObjectiveText(""); got != "继续" {
		t.Fatalf("无提示时续轮指令应为「继续」, 实际 %q", got)
	}
	if got := BuildContinueObjectiveText("   "); got != "继续" {
		t.Fatalf("空白提示应按无提示处理, 实际 %q", got)
	}

	// 用户写了续轮提示 → 原话附在「继续」后面，一字不改。
	hint := "看看有没有其他中危能在别的站点复现，顺便再查一遍 /home/kali/Desktop/cnvd/"
	text := BuildContinueObjectiveText(hint)
	if !strings.HasPrefix(text, "继续\n") {
		t.Fatalf("有提示时应以「继续」开头, 实际 %q", text)
	}
	if !strings.Contains(text, hint) {
		t.Fatalf("续轮提示必须原样出现:\n%s", text)
	}
	// 不再出现旧模板的"本轮指导/目标模型/禁止"式说教。
	for _, banned := range []string{"本轮指导", "目标模型", "禁止把本轮目标写成"} {
		if strings.Contains(text, banned) {
			t.Fatalf("续轮指令不应再含模板话术 %q:\n%s", banned, text)
		}
	}
}

// 自动续轮：只排"还该跑"的会话，间隔没到不排，正在跑的不排。
func TestDueConversations(t *testing.T) {
	store, chains := newTestDeliveryDB(t)
	ctx := context.Background()
	conv := "conv-due-1"

	if _, err := store.db.ExecContext(ctx,
		`INSERT INTO conversations(id, agent_mode, unattended_mode) VALUES(?,?,1)`, conv, "zhulong"); err != nil {
		t.Fatalf("insert conversation: %v", err)
	}

	if err := store.SaveGoal(ctx, &Goal{ID: "zl-goal-" + conv, ConversationID: conv, Objective: "打穿 shop.example.com"}); err != nil {
		t.Fatalf("save goal: %v", err)
	}
	if _, err := chains.Open(ctx, &Chain{
		ConversationID: conv, FindingKey: "vuln:1", Title: "订单越权",
		Hypothesis: "id 换号可读他人订单", HypothesisType: HypOwnCode,
		TargetAsset: "shop.example.com", TargetModelRef: "target/shop.example.com-model",
	}); err != nil {
		t.Fatalf("open chain: %v", err)
	}

	// 没有 run 记录 → 立即到点
	due, err := chains.DueConversations(ctx, AutoContinueOptions{Interval: time.Minute})
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 1 || due[0].ConversationID != conv {
		t.Fatalf("应有 1 条待续轮, 实际 %+v", due)
	}
	// 2026-11-08 用户裁定：无续轮提示时，objective 就是「继续」（不再指向具体链的模板）。
	if !strings.Contains(due[0].Objective, "继续") {
		t.Fatalf("objective 应为「继续」: %s", due[0].Objective)
	}

	// 刚跑完一轮（finished_at=现在）→ 间隔没到, 不排
	run := &Run{ID: "zl-run-1", ConversationID: conv, GoalID: "zl-goal-" + conv}
	if cerr := store.CreateRun(ctx, run); cerr != nil {
		t.Fatalf("create run: %v", cerr)
	}
	if ferr := store.FinishRun(ctx, run.ID, StateContinuePending, "", "推到 rung=1", ""); ferr != nil {
		t.Fatalf("finish run: %v", ferr)
	}
	due, err = chains.DueConversations(ctx, AutoContinueOptions{Interval: 10 * time.Minute})
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("间隔未到不应排轮, 实际 %+v", due)
	}
	// 时钟往后拨 11 分钟 → 到点
	due, err = chains.DueConversations(ctx, AutoContinueOptions{
		Interval: 10 * time.Minute,
		Now:      func() time.Time { return time.Now().Add(11 * time.Minute) },
	})
	if err != nil || len(due) != 1 {
		t.Fatalf("到点后应排一轮, 实际 %+v err=%v", due, err)
	}

	// 正在跑（state=running）→ 不排，避免同会话撞车
	running := &Run{ID: "zl-run-2", ConversationID: conv, GoalID: "zl-goal-" + conv}
	if cerr := store.CreateRun(ctx, running); cerr != nil {
		t.Fatalf("create run: %v", cerr)
	}
	if serr := store.StartRun(ctx, running.ID); serr != nil {
		t.Fatalf("start run: %v", serr)
	}
	due, err = chains.DueConversations(ctx, AutoContinueOptions{
		Interval: time.Minute,
		Now:      func() time.Time { return time.Now().Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("有 running run 时不应排轮, 实际 %+v", due)
	}
}

// 无人值守闸门（2026-11-08）：会话级开关关闭时，即使有 open 链也不自动续轮。
func TestDueConversationsRequiresUnattended(t *testing.T) {
	store, chains := newTestDeliveryDB(t)
	ctx := context.Background()
	conv := "conv-due-unattended"

	if _, err := store.db.ExecContext(ctx,
		`INSERT INTO conversations(id, agent_mode, unattended_mode) VALUES(?,?,1)`, conv, "zhulong"); err != nil {
		t.Fatalf("insert conversation: %v", err)
	}
	if err := store.SaveGoal(ctx, &Goal{ID: "zl-goal-" + conv, ConversationID: conv, Objective: "打穿 shop.example.com"}); err != nil {
		t.Fatalf("save goal: %v", err)
	}
	if _, err := chains.Open(ctx, &Chain{
		ConversationID: conv, FindingKey: "vuln:9", Title: "订单越权",
		Hypothesis: "id 换号可读他人订单", HypothesisType: HypOwnCode,
		TargetAsset: "shop.example.com", TargetModelRef: "target/shop.example.com-model",
	}); err != nil {
		t.Fatalf("open chain: %v", err)
	}

	// 默认 fixture = 无人值守开 → 到点。
	due, err := chains.DueConversations(ctx, AutoContinueOptions{Interval: time.Minute})
	if err != nil || len(due) != 1 {
		t.Fatalf("无人值守开启时应排一轮, 实际 %+v err=%v", due, err)
	}

	// 显式关闭 → 不排。
	if _, err := store.db.ExecContext(ctx, `UPDATE conversations SET unattended_mode=0 WHERE id=?`, conv); err != nil {
		t.Fatalf("close unattended: %v", err)
	}
	due, err = chains.DueConversations(ctx, AutoContinueOptions{Interval: time.Minute})
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("无人值守关闭后不应自动续轮, 实际 %+v", due)
	}

	// 再打开 → 恢复。
	if _, err := store.db.ExecContext(ctx, `UPDATE conversations SET unattended_mode=1 WHERE id=?`, conv); err != nil {
		t.Fatalf("open unattended: %v", err)
	}
	due, err = chains.DueConversations(ctx, AutoContinueOptions{Interval: time.Minute})
	if err != nil || len(due) != 1 {
		t.Fatalf("重新开启后应排一轮, 实际 %+v err=%v", due, err)
	}
}

// 轮数预算按「本次勾选」起算（2026-11-09）：历史跑满 18 轮不应导致重新勾选后永不启动。
func TestDueConversationsRoundsBudgetResetsOnToggle(t *testing.T) {
	store, chains := newTestDeliveryDB(t)
	ctx := context.Background()
	conv := "conv-budget"

	since := time.Now().Add(-time.Hour).Format(time.RFC3339)
	if _, err := store.db.ExecContext(ctx,
		`INSERT INTO conversations(id, agent_mode, unattended_mode, unattended_since) VALUES(?,?,1,?)`,
		conv, "zhulong", since); err != nil {
		t.Fatalf("insert conversation: %v", err)
	}
	if err := store.SaveGoal(ctx, &Goal{ID: "zl-goal-" + conv, ConversationID: conv, Objective: "打穿 shop.example.com"}); err != nil {
		t.Fatalf("save goal: %v", err)
	}
	if _, err := chains.Open(ctx, &Chain{
		ConversationID: conv, FindingKey: "vuln:budget", Title: "链",
		Hypothesis: "h", HypothesisType: HypOwnCode,
		TargetAsset: "shop.example.com", TargetModelRef: "target/shop.example.com-model",
	}); err != nil {
		t.Fatalf("open chain: %v", err)
	}
	// 造 3 轮已收口（均在 since 之后）。
	for i := 0; i < 3; i++ {
		run := &Run{ID: "zl-run-b" + itoaSmall(i), ConversationID: conv, GoalID: "zl-goal-" + conv}
		if err := store.CreateRun(ctx, run); err != nil {
			t.Fatalf("create run: %v", err)
		}
		if err := store.FinishRun(ctx, run.ID, StateNothing, "", "空轮", ""); err != nil {
			t.Fatalf("finish run: %v", err)
		}
	}
	now := func() time.Time { return time.Now().Add(2 * time.Hour) }

	// 预算 3 已用满 → 不排。
	due, err := chains.DueConversations(ctx, AutoContinueOptions{Interval: time.Minute, MaxRounds: 3, Now: now})
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("本次预算用满应不排, 实际 %+v", due)
	}

	// 重新勾选（起算时间拨到 1 分钟后）→ 新预算 → 排一轮。
	if _, err := store.db.ExecContext(ctx,
		`UPDATE conversations SET unattended_since=? WHERE id=?`,
		time.Now().Add(time.Minute).Format(time.RFC3339), conv); err != nil {
		t.Fatalf("reset unattended_since: %v", err)
	}
	due, err = chains.DueConversations(ctx, AutoContinueOptions{Interval: time.Minute, MaxRounds: 3, Now: now})
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("重新勾选后应排一轮, 实际 %+v", due)
	}
}

// 没有 open 链但有 continue_pending → objective 必须指向"建目标模型"，不是补覆盖。
func TestDueConversationsContinuePendingBuildsTargetModel(t *testing.T) {
	store, chains := newTestDeliveryDB(t)
	ctx := context.Background()
	conv := "conv-due-2"

	if _, err := store.db.ExecContext(ctx,
		`INSERT INTO conversations(id, agent_mode, unattended_mode) VALUES(?,?,1)`, conv, "zhulong"); err != nil {
		t.Fatalf("insert conversation: %v", err)
	}

	if _, err := store.db.ExecContext(ctx, `
INSERT INTO asset_coverage(conversation_id, asset, face, state, evidence_ref, note, updated_at)
VALUES(?,?,?,?,?,?,datetime('now'))`, conv, "shop.example.com", "path", "done", "/tmp/e/1.json", ""); err != nil {
		t.Fatalf("seed coverage: %v", err)
	}
	if err := store.SaveGoal(ctx, &Goal{ID: "zl-goal-" + conv, ConversationID: conv, Objective: "打穿 shop.example.com"}); err != nil {
		t.Fatalf("save goal: %v", err)
	}
	run := &Run{ID: "zl-run-c", ConversationID: conv, GoalID: "zl-goal-" + conv}
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := store.MarkContinuePending(ctx, run.ID, "no-anchored-chain"); err != nil {
		t.Fatalf("mark continue: %v", err)
	}

	due, err := chains.DueConversations(ctx, AutoContinueOptions{Interval: time.Minute,
		Now: func() time.Time { return time.Now().Add(time.Hour) }})
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("continue_pending 会话应被排轮, 实际 %+v", due)
	}
	obj := due[0].Objective
	// 2026-11-08 用户裁定：续轮指令就是「继续」，不再生成"建目标模型/开链"模板。
	if obj != "继续" {
		t.Fatalf("无续轮提示时 objective 应为「继续」, 实际 %q", obj)
	}
}

// 每步落库：一次 tool_call + 一次 tool_result 落成 1 行（同一 step_no 覆盖），并带证据路径。
func TestStepRecorderWritesPerToolCall(t *testing.T) {
	store, _ := newTestDeliveryDB(t)
	ctx := context.Background()
	run := &Run{ID: "zl-run-steps", ConversationID: "conv-steps", GoalID: "zl-goal-conv-steps"}
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}

	rec := NewStepRecorder(ctx, store, run.ID, nil)
	forwarded := 0
	progress := rec.WrapProgress(func(eventType, message string, data interface{}) { forwarded++ })

	progress("tool_call", "正在调用工具: exec", map[string]interface{}{
		"toolName": "exec", "arguments": `{"command":"curl -s /api/order/detail?id=2"}`,
		"toolCallId": "call-1",
	})
	progress("tool_result", "工具结果 (exec)", map[string]interface{}{
		"toolName":   "exec",
		"toolCallId": "call-1",
		"result":     "HTTP/1.1 200 OK\n{\"order\":1}\n[saved] /tmp/e/order-2.json",
	})

	if forwarded != 2 {
		t.Fatalf("包装后的 progress 必须原样转发事件, 实际 %d", forwarded)
	}
	steps, err := store.RecentSteps(ctx, run.ID, 20)
	if err != nil {
		t.Fatalf("recent steps: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("同一 tool 调用应只有 1 行（结果覆盖发起行），实际 %d: %+v", len(steps), steps)
	}
	if steps[0].ToolName != "exec" || steps[0].EvidenceRef != "/tmp/e/order-2.json" {
		t.Fatalf("步骤行缺工具名或证据路径: %+v", steps[0])
	}
	// 注：zhulong_steps 没有 outcome_so_far 列（不动既有表结构），
	// 成败只体现在 summary 前缀（"tool ← 结果"）上，这里只校验结果已回写。
	if !strings.Contains(steps[0].Summary, "←") {
		t.Fatalf("结果回写后 summary 应含结果段: %+v", steps[0])
	}
}

// done 时把该 goal 的 open 待办标 stale：不回注、也不冒充完成。
func TestMarkOpenTodosStale(t *testing.T) {
	store, _ := newTestDeliveryDB(t)
	ctx := context.Background()
	goalID := "zl-goal-conv-todo"
	if n, err := store.AddTodos(ctx, goalID, "run-a", []string{"推进链 A", "推进链 B"}); err != nil || n != 2 {
		t.Fatalf("add todos: n=%d err=%v", n, err)
	}
	if n, err := store.MarkOpenTodosStale(ctx, goalID); err != nil || n != 2 {
		t.Fatalf("mark stale: n=%d err=%v", n, err)
	}
	if left, err := store.ListOpenTodos(ctx, goalID, 20); err != nil || len(left) != 0 {
		t.Fatalf("stale 之后不应再有 open 待办: %d %v", len(left), err)
	}
}

func hasCode(reasons []DeliveryReason, code string) bool {
	for _, r := range reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

// newTestDeliveryDB 建一个带 zhulong 全表 + 链账本 + 最小 asset_coverage 的临时库。
func newTestDeliveryDB(t *testing.T) (*Store, *ChainStore) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "delivery.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000&_foreign_keys=1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("store schema: %v", err)
	}
	chains, err := NewChainStore(db)
	if err != nil {
		t.Fatalf("new chain store: %v", err)
	}
	if err := chains.EnsureSchema(ctx); err != nil {
		t.Fatalf("chain schema: %v", err)
	}
	// 自动续轮在"没有 open 链"时用覆盖台账挑资产锚点：只建测试所需的最小表。
	if _, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS asset_coverage (
  conversation_id TEXT NOT NULL,
  asset           TEXT NOT NULL,
  face            TEXT NOT NULL,
  state           TEXT NOT NULL DEFAULT 'open',
  evidence_ref    TEXT NOT NULL DEFAULT '',
  note            TEXT NOT NULL DEFAULT '',
  updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (conversation_id, asset, face)
)`); err != nil {
		t.Fatalf("coverage schema: %v", err)
	}
	// 自动续轮的「无人值守」闸门（2026-11-08）读 conversations.unattended_mode：
	// 测试默认建 1（=无人值守开），要验证"关了不续"的用例自行 UPDATE 成 0。
	if _, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS conversations (
  id              TEXT PRIMARY KEY,
  agent_mode      TEXT NOT NULL DEFAULT 'zhulong',
  unattended_mode INTEGER NOT NULL DEFAULT 1,
  unattended_since TEXT NOT NULL DEFAULT '',
  continue_hint   TEXT NOT NULL DEFAULT ''
)`); err != nil {
		t.Fatalf("conversations schema: %v", err)
	}
	return store, chains
}

// TestDecideDeliveryMinRoundWindow 守住"烛龙一轮至少 30 分钟"这条用户裁定：
// 早收必须真的做完了（GATE=PASS + open 链=0 + 锚定链≥1），否则打回 continue。
func TestDecideDeliveryMinRoundWindow(t *testing.T) {
	anchors := []string{"shop.example.com"}
	mk := func() *Receipt {
		return &Receipt{
			Outcome:     OutcomeDone,
			Summary:     "本轮结论",
			EvidenceRefs: []string{"/tmp/ev/a.txt"},
			NextActions: []string{"继续打 https://shop.example.com/api/order"},
		}
	}
	win := RoundWindow{ElapsedMin: 5, MinMin: 30}

	// ① 5 分钟、无 open 链、闸门 PASS、有锚定链 → 允许提前收口（真做完了）。
	if oc, reasons := DecideDelivery(mk(), ChainFacts{Total: 1, Exploited: 1, Depth: 3, Anchored: 1},
		"PASS", "", "", anchors, win); oc != OutcomeDone {
		t.Fatalf("真做完应允许提前收口，实际 %s %v", oc, reasons)
	}

	// ② 5 分钟、闸门 CONTINUE → 必须打回（min-round 或 gate 原因都算）。
	if oc, reasons := DecideDelivery(mk(), ChainFacts{Total: 1, Exploited: 0, Anchored: 1},
		"CONTINUE", "open-chains", "", anchors, win); oc != OutcomeContinue {
		t.Fatalf("早收且闸门未过应打回，实际 %s %v", oc, reasons)
	}

	// ③ 5 分钟、PASS 但无锚定链 → 打回。
	if oc, reasons := DecideDelivery(mk(), ChainFacts{Total: 1, Exploited: 1, Depth: 3, Anchored: 0},
		"PASS", "", "", anchors, win); oc != OutcomeContinue {
		t.Fatalf("无锚定链应打回，实际 %s %v", oc, reasons)
	}

	// ④ nothing + 5 分钟 + 仍有 open 链 → 改 continue。
	nr := &Receipt{Outcome: OutcomeNothing, Summary: "无事可做"}
	if oc, reasons := DecideDelivery(nr, ChainFacts{Total: 2, Open: 1, Anchored: 1}, "PASS", "", "", anchors, win); oc != OutcomeContinue {
		t.Fatalf("nothing 且有 open 链应改 continue，实际 %s %v", oc, reasons)
	}

	// ⑤ 35 分钟、全部达标 → done。
	if oc, _ := DecideDelivery(mk(), ChainFacts{Total: 1, Exploited: 1, Depth: 3, Anchored: 1},
		"PASS", "", "", anchors, RoundWindow{ElapsedMin: 35, MinMin: 30}); oc != OutcomeDone {
		t.Fatalf("超过最短轮时长且达标应 done，实际 %s", oc)
	}
}
