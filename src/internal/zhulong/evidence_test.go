package zhulong

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnresolvableEvidenceRefs(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "req.txt")
	if err := os.WriteFile(existing, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	missing := filepath.Join(dir, "nope.txt")
	refs := []string{
		existing,                  // 存在 → 可复核
		"https://example.com/a",   // URL → 离线不判
		"exec://123",              // 其它 scheme → 不判
		"file://" + existing,      // file:// 存在 → 可复核
		missing,                   // 不存在 → 不可复核
		"file://" + missing + "2", // file:// 不存在 → 不可复核
		"  ",                      // 空 → 忽略
	}
	bad := UnresolvableEvidenceRefs(refs)
	if len(bad) != 2 {
		t.Fatalf("bad=%v want 2 条", bad)
	}
	for _, b := range bad {
		if b != missing && b != "file://"+missing+"2" {
			t.Fatalf("误判不可复核: %q", b)
		}
	}
}

func TestUnresolvableEvidenceRefsNil(t *testing.T) {
	if bad := UnresolvableEvidenceRefs(nil); len(bad) != 0 {
		t.Fatalf("nil refs 应返回空: %v", bad)
	}
	if bad := UnresolvableEvidenceRefs([]string{"", " "}); len(bad) != 0 {
		t.Fatalf("空串应忽略: %v", bad)
	}
}
