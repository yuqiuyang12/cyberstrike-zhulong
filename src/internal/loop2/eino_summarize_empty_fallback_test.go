package loop2

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/eino/schema"
)

func TestSummaryMessageHasUsableContent(t *testing.T) {
	cases := []struct {
		name string
		msg  *schema.Message
		want bool
	}{
		{"nil", nil, false},
		{"empty assistant", &schema.Message{Role: schema.Assistant, Content: ""}, false},
		{"whitespace", &schema.Message{Role: schema.Assistant, Content: "   \n  "}, false},
		{"tags only", &schema.Message{Role: schema.Assistant, Content: "<summary>  </summary>"}, false},
		{"too short", &schema.Message{Role: schema.Assistant, Content: "无"}, false},
		{"plain content", &schema.Message{Role: schema.Assistant, Content: "发现一处未授权访问端点 /admin,可读取数据"}, true},
		{
			"multimodal text",
			&schema.Message{
				Role: schema.Assistant,
				AssistantGenMultiContent: []schema.MessageOutputPart{
					{Type: schema.ChatMessagePartTypeText, Text: "压缩完成:资产 10 个,漏洞 2 个,继续下一步目录扫描"},
				},
			},
			true,
		},
		{
			"multimodal short text ignored",
			&schema.Message{
				Role: schema.Assistant,
				AssistantGenMultiContent: []schema.MessageOutputPart{
					{Type: schema.ChatMessagePartTypeText, Text: "无"},
				},
				Content: "",
			},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := summaryMessageHasUsableContent(c.msg); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestBuildHostFallbackSummaryMessage(t *testing.T) {
	msg := buildHostFallbackSummaryMessage("/data/conversation_artifacts/abc/summarization/transcript.txt")
	if msg == nil || msg.Role != schema.User {
		t.Fatal("fallback summary must be a user message")
	}
	if !strings.Contains(msg.Content, "宿主兜底") {
		t.Fatal("missing fallback marker")
	}
	if !strings.Contains(msg.Content, "transcript.txt") {
		t.Fatal("transcript path must be embedded")
	}
	if strings.TrimSpace(msg.Content) == "" {
		t.Fatal("content must be non-empty")
	}

	// 无 transcript 路径时也必须可用。
	msg2 := buildHostFallbackSummaryMessage("")
	if msg2 == nil || !strings.Contains(msg2.Content, "宿主兜底") {
		t.Fatal("fallback without transcript path invalid")
	}
}

func TestRegenerateEmptySummaryNilGuards(t *testing.T) {
	// nil model / nil rebuild → false，不 panic。
	if _, ok := regenerateEmptySummary(context.Background(), nil, func() ([]*schema.Message, error) {
		return nil, nil
	}, nil); ok {
		t.Fatal("nil model must fail")
	}
	if _, ok := regenerateEmptySummary(context.Background(), nil, nil, nil); ok {
		t.Fatal("nil rebuild must fail")
	}
}

func TestEmptySummaryRepromptInstructionContent(t *testing.T) {
	if !strings.Contains(emptySummaryRepromptInstruction, "禁止调用任何工具") {
		t.Fatal("reprompt must forbid tools")
	}
	if !strings.Contains(emptySummaryRepromptInstruction, "<summary>") {
		t.Fatal("reprompt must demand summary block")
	}
}
