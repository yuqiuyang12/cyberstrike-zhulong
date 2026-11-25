package zhulong

import (
	"strings"
	"testing"
)

// 防的失败方式：
//  1. 收尾模型看不到目标就去编结论
//  2. 长日志整段塞进收尾输入（爆窗口 / 花钱）
//  3. 步骤摘要丢证据路径 → 回执里的 evidence_refs 编造
func TestBuildSettlementDigest(t *testing.T) {
	steps := []Step{
		{StepNo: 1, ToolName: "exec", Summary: "nmap -sV 目标", EvidenceRef: "/tmp/e/nmap.txt"},
		{StepNo: 2, ToolName: "httpx", Summary: "探活 1026 条"},
	}
	d := BuildSettlementDigest("测 example.com 的 80/443", "", steps, nil, 4000)

	for _, want := range []string{"测 example.com", "nmap", "/tmp/e/nmap.txt", "httpx"} {
		if !strings.Contains(d, want) {
			t.Fatalf("摘要缺少 %q:\n%s", want, d)
		}
	}
}

func TestBuildSettlementDigestTruncates(t *testing.T) {
	long := strings.Repeat("A", 50000)
	d := BuildSettlementDigest("目标", long, nil, nil, 2000)
	if n := len([]rune(d)); n > 2400 {
		t.Fatalf("摘要未受控，长度 %d", n)
	}
	if !strings.Contains(d, "中间省略") {
		t.Fatalf("长文本应保留头尾并标注省略")
	}
}

func TestSettlementPromptMentionsNoTools(t *testing.T) {
	// 收尾阶段的硬约束必须写在提示里（否则模型会继续申请工具）
	for _, want := range []string{"不再允许调用任何工具", "zhulong", "outcome"} {
		if !strings.Contains(SettlementPrompt, want) {
			t.Fatalf("收尾提示缺少关键约束: %q", want)
		}
	}
}

// 防的失败方式：收尾模型看不到原始工具输出 → 一律判 failed（M1 实测过）
func TestExtractToolSnippets(t *testing.T) {
	trace := `[
	  {"role":"user","content":"测 example.com"},
	  {"role":"assistant","content":"我来看一下"},
	  {"role":"tool","name":"exec","content":"80/tcp open http nginx 1.18.0"},
	  {"role":"tool","name":"httpx","content":"200 https://example.com [nginx]"}
	]`
	got := ExtractToolSnippets(trace, 8, 500)
	if len(got) != 2 {
		t.Fatalf("应抽出 2 条工具输出，实际 %d: %+v", len(got), got)
	}
	if got[0].Tool != "exec" || !strings.Contains(got[0].Content, "nginx") {
		t.Fatalf("抽取结果不对: %+v", got[0])
	}
}

func TestExtractToolSnippetsTolerant(t *testing.T) {
	// 非法 JSON / 空串 / null 一律返回 nil，绝不 panic
	for _, in := range []string{"", "[]", "null", "{not json", `{"a":1}`} {
		if got := ExtractToolSnippets(in, 4, 100); got != nil {
			t.Fatalf("输入 %q 应返回 nil，实际 %+v", in, got)
		}
	}
}

func TestBuildSettlementDigestIncludesToolEvidence(t *testing.T) {
	tools := []ToolSnippet{{Tool: "nmap", Content: "22/tcp open ssh"}}
	d := BuildSettlementDigest("目标", "", nil, tools, 4000)
	if !strings.Contains(d, "22/tcp open ssh") || !strings.Contains(d, "最近的工具输出") {
		t.Fatalf("摘要未包含工具证据:\n%s", d)
	}
}
