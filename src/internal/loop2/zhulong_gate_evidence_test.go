package loop2

// zhulong_gate_evidence_test.go —— R3a 证据可复核闸门的**集成级**验收（2026-11-06）。
//
// 单测 UnresolvableEvidenceRefs 只证明纯函数正确；本文件走真实
// zhulongApplyDeliveryGate 路径（回执解析 → 链事实 → DecideDelivery → 证据可复核性复核），
// 防的失败方式：
//  1. 证据存在性检查没接线（只在纯函数里测过），编造路径的 done 照样交卷；
//  2. 接线了但把真实落盘路径也误拦（把 done 改 continue，浪费一轮）；
//  3. 打回信息没写回回执（模型下一轮看不到"为什么不能交卷"）。

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/zhulong"

	_ "github.com/mattn/go-sqlite3"
)

// newGateTestDB 建一个空 sqlite（不建表）：
// 链事实/漏洞数/锚点一律走"读不到就降级为 0"路径，正好模拟干净目标。
func newGateTestDB(t *testing.T) *database.DB {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "gate.db")+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return &database.DB{DB: sqlDB}
}

// gateReceiptResult 造一个"正文 + 合法 zhulong 回执块"的 RunResult（done + 指定证据引用）。
func gateReceiptResult(t *testing.T, refs []string) *RunResult {
	t.Helper()
	rc := zhulong.Receipt{
		Outcome:      zhulong.OutcomeDone,
		Summary:      "自检回执",
		EvidenceRefs: refs,
		NextActions:  []string{"推进 example.com 的 /login 参数"},
	}
	block, err := zhulong.MarshalReceipt(&rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &RunResult{Response: "正文。\n\n```zhulong\n" + block + "\n```\n"}
}

func withPassGate(t *testing.T) {
	t.Helper()
	oldGate := ZhulongGateCheck
	ZhulongGateCheck = func(ctx context.Context, conversationID, projectID string) ZhulongGateResult {
		return ZhulongGateResult{Verdict: "PASS"}
	}
	t.Cleanup(func() { ZhulongGateCheck = oldGate })
}

// 编造路径 → 必须被闸门打回 continue，且打回理由写回回执。
func TestZhulongGateRejectsUnverifiableEvidence(t *testing.T) {
	withPassGate(t)
	db := newGateTestDB(t)
	badPath := filepath.Join(t.TempDir(), "no-such-evidence.txt")
	res := gateReceiptResult(t, []string{badPath})

	receipt, reasons := zhulongApplyDeliveryGate(context.Background(), db, "", "conv-gate-1", res, nil, nil, 0, 0)
	if receipt == nil {
		t.Fatal("回执应被解析")
	}
	if receipt.Outcome != zhulong.OutcomeContinue {
		t.Fatalf("不可复核证据应打回 continue, 实际 %s", receipt.Outcome)
	}
	found := false
	for _, r := range reasons {
		if r.Code == "evidence-unverifiable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少 evidence-unverifiable 理由: %+v", reasons)
	}
	if !strings.Contains(strings.Join(receipt.NextActions, "|"), "不能交卷") &&
		!strings.Contains(receipt.Summary, "打回") {
		t.Fatalf("打回信息未写回回执: next=%v summary=%q", receipt.NextActions, receipt.Summary)
	}
}

// 真实存在的落盘证据 → 不得误拦。
func TestZhulongGateAcceptsExistingEvidence(t *testing.T) {
	withPassGate(t)
	db := newGateTestDB(t)
	f := filepath.Join(t.TempDir(), "req.txt")
	if err := os.WriteFile(f, []byte("req"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := gateReceiptResult(t, []string{f})

	receipt, reasons := zhulongApplyDeliveryGate(context.Background(), db, "", "conv-gate-2", res, nil, nil, 0, 0)
	if receipt == nil {
		t.Fatal("回执应被解析")
	}
	if receipt.Outcome != zhulong.OutcomeDone {
		t.Fatalf("真实存在的证据不应被打回, 实际 %s reasons=%+v", receipt.Outcome, reasons)
	}
	if len(reasons) != 0 {
		t.Fatalf("不应有打回理由: %+v", reasons)
	}
}

// 闸门 PASS + 无证据引用（done 缺证据）：ParseReceipt 阶段就应拒绝 → gate 返回 nil 交 finalize 按失败收口。
func TestZhulongGateNilForDoneWithoutEvidence(t *testing.T) {
	withPassGate(t)
	db := newGateTestDB(t)
	// 手工造一个 done 但 evidence_refs 为空的回执块（绕过 Marshal 的类型约束）。
	res := &RunResult{Response: "正文。\n\n```zhulong\n{\"outcome\":\"done\",\"summary\":\"x\",\"next_actions\":[\"推进 example.com\"]}\n```\n"}
	receipt, _ := zhulongApplyDeliveryGate(context.Background(), db, "", "conv-gate-3", res, nil, nil, 0, 0)
	if receipt != nil {
		t.Fatalf("done 无证据引用应被解析拒绝（nil 回执），实际 %+v", receipt)
	}
}
