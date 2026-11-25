package zhulong

import "testing"

func TestIsContinuationMessage(t *testing.T) {
	cases := map[string]bool{
		"":                true,
		"继续":              true,
		"继续。":             true,
		"继续推进":            true,
		"接着":              true,
		"下一步":             true,
		"continue":        true,
		"Go on":           true,
		"继续，另外测一下 x.com":  false, // 有信息量，不算纯继续
		"继续深入这个 SQL 注入点":  false,
		"测一下 example.com": false,
		"http://x.com":    false,
	}
	for in, want := range cases {
		if got := IsContinuationMessage(in); got != want {
			t.Fatalf("IsContinuationMessage(%q)=%v want %v", in, got, want)
		}
	}
}

func TestObjectiveForNextRound(t *testing.T) {
	cases := []struct{ prev, in, want string }{
		{"测 pile-bi 深度", "继续", "测 pile-bi 深度"},
		{"测 pile-bi 深度", "", "测 pile-bi 深度"},
		{"测 pile-bi 深度", "改测 cdzmini.cqtransit.com", "改测 cdzmini.cqtransit.com"},
		{"", "继续", "继续"},
		{"", "", "（空目标）"},
	}
	for _, c := range cases {
		if got := ObjectiveForNextRound(c.prev, c.in); got != c.want {
			t.Fatalf("ObjectiveForNextRound(%q,%q)=%q want %q", c.prev, c.in, got, c.want)
		}
	}
}
