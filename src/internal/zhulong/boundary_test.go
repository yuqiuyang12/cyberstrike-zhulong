package zhulong

import (
	"strings"
	"testing"
)

func TestParseGoalConstraints(t *testing.T) {
	cases := []struct {
		name      string
		objective string
		wantAllow []string
		wantDeny  []string
	}{
		{
			name:      "url与IP",
			objective: "http://cdzmini.cqtransit.com:80 测测看呢这个深度，10.0.0.5/24 也看一下",
			wantAllow: []string{"http://cdzmini.cqtransit.com:80", "10.0.0.5/24"},
		},
		{
			name:      "只测语句里的目标",
			objective: "只测 example.com 和 demo.example.org:8443",
			wantAllow: []string{"example.com", "demo.example.org:8443"},
		},
		{
			name:      "禁止语句整句进deny且不抽目标",
			objective: "不要动 10.9.9.9，禁止扫内网；测 example.com",
			wantAllow: []string{"example.com"},
			wantDeny:  []string{"不要动 10.9.9.9，禁止扫内网"},
		},
		{
			name:      "空目标不产生边界",
			objective: "（空目标）",
		},
		{
			name:      "版本号小数不算域名",
			objective: "服务版本 1.2.3 已确认，测 example.com",
			wantAllow: []string{"example.com"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseGoalConstraints(c.objective)
			if strings.Join(got.Allow, "|") != strings.Join(c.wantAllow, "|") {
				t.Fatalf("allow=%v want %v", got.Allow, c.wantAllow)
			}
			if strings.Join(got.Deny, "|") != strings.Join(c.wantDeny, "|") {
				t.Fatalf("deny=%v want %v", got.Deny, c.wantDeny)
			}
		})
	}
}

func TestMergeConstraintLines(t *testing.T) {
	prev := []string{"允许: example.com", "禁止: 不要碰 admin.example.com"}
	cur := []string{"允许: example.com", "允许: new.example.org"}
	merged := MergeConstraintLines(prev, cur)
	want := []string{"允许: example.com", "禁止: 不要碰 admin.example.com", "允许: new.example.org"}
	if strings.Join(merged, "\n") != strings.Join(want, "\n") {
		t.Fatalf("merged=%v want %v", merged, want)
	}
	// 上一轮非空、本轮为空（用户只回"继续"）→ 边界必须保留。
	if got := MergeConstraintLines(prev, nil); len(got) != 2 {
		t.Fatalf("prev 应保留: %v", got)
	}
}

func TestSplitConstraintLines(t *testing.T) {
	allow, deny := SplitConstraintLines([]string{"允许: a.com", "垃圾行", "禁止: 不要碰 b.com"})
	if len(allow) != 1 || allow[0] != "a.com" {
		t.Fatalf("allow=%v", allow)
	}
	if len(deny) != 1 || deny[0] != "不要碰 b.com" {
		t.Fatalf("deny=%v", deny)
	}
}

func TestConstraintsBlock(t *testing.T) {
	b := BoundaryConstraints{Allow: []string{"example.com"}, Deny: []string{"不要碰 admin.example.com"}}
	blk := b.Block()
	for _, want := range []string{"授权范围", "example.com", "明确禁止", "不要碰 admin.example.com", "不等于获得授权"} {
		if !strings.Contains(blk, want) {
			t.Fatalf("block 缺 %q:\n%s", want, blk)
		}
	}
	// 空边界不渲染（不注入噪声）。
	if (BoundaryConstraints{}).Block() != "" {
		t.Fatal("空边界应返回空串")
	}
}
