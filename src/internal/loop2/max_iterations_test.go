package loop2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestAgentMaxIterations(t *testing.T) {
	if got := agentMaxIterations(nil); got != defaultAgentMaxIterations {
		t.Fatalf("nil cfg: got %d want %d", got, defaultAgentMaxIterations)
	}
	cfg := &config.Config{Agent: config.AgentConfig{MaxIterations: 12000}}
	if got := agentMaxIterations(cfg); got != 12000 {
		t.Fatalf("got %d want 12000", got)
	}
	cfg.Agent.MaxIterations = 0
	if got := agentMaxIterations(cfg); got != defaultAgentMaxIterations {
		t.Fatalf("zero: got %d want %d", got, defaultAgentMaxIterations)
	}
}

func TestResolveMaxIterations(t *testing.T) {
	cfg := &config.Config{Agent: config.AgentConfig{MaxIterations: 12000}}
	if got := resolveMaxIterations(cfg, 0); got != 12000 {
		t.Fatalf("global: got %d want 12000", got)
	}
	if got := resolveMaxIterations(cfg, 50); got != 50 {
		t.Fatalf("override: got %d want 50", got)
	}
}

// W5：agent.max_iterations_by_mode 命中即覆盖；未配置/未命中/mode 为空/值 ≤0 一律回落 agent.max_iterations。
func TestResolveMaxIterationsByMode(t *testing.T) {
	// 旧配置（无 max_iterations_by_mode）：行为与 agentMaxIterations 完全一致。
	legacy := &config.Config{Agent: config.AgentConfig{MaxIterations: 600}}
	if got := resolveMaxIterationsByMode(legacy, "deep"); got != 600 {
		t.Fatalf("legacy deep: got %d want 600", got)
	}
	if got := resolveMaxIterationsByMode(nil, "deep"); got != defaultAgentMaxIterations {
		t.Fatalf("nil cfg: got %d want %d", got, defaultAgentMaxIterations)
	}

	cfg := &config.Config{Agent: config.AgentConfig{
		MaxIterations:       600,
		MaxIterationsByMode: map[string]int{"deep": 2000, "Benchmark ": 5000, "plan_execute": 0, "supervisor": -1},
	}}
	if got := resolveMaxIterationsByMode(cfg, "deep"); got != 2000 {
		t.Fatalf("hit deep: got %d want 2000", got)
	}
	if got := resolveMaxIterationsByMode(cfg, "BENCHMARK"); got != 5000 {
		t.Fatalf("case/space insensitive hit: got %d want 5000", got)
	}
	if got := resolveMaxIterationsByMode(cfg, "eino_single"); got != 600 {
		t.Fatalf("miss: got %d want 600", got)
	}
	if got := resolveMaxIterationsByMode(cfg, "  "); got != 600 {
		t.Fatalf("empty mode: got %d want 600", got)
	}
	if got := resolveMaxIterationsByMode(cfg, "plan_execute"); got != 600 {
		t.Fatalf("zero value falls back: got %d want 600", got)
	}
	if got := resolveMaxIterationsByMode(cfg, "supervisor"); got != 600 {
		t.Fatalf("negative value falls back: got %d want 600", got)
	}
}

// W5：迭代上限触顶 → HANDOFF-<conversationId>.json 骨架（五个数组为空、reason=max_iterations）。
func TestEmitMaxIterationsHandoff(t *testing.T) {
	base := t.TempDir()
	path := emitMaxIterationsHandoff(nil, base, "conv-abc/../x", "deep")
	if path == "" {
		t.Fatalf("expected handoff file path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read handoff: %v", err)
	}
	var got handoffSkeleton
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal handoff: %v", err)
	}
	if got.Reason != handoffReasonMaxIterations {
		t.Fatalf("reason: got %q want %q", got.Reason, handoffReasonMaxIterations)
	}
	if got.Orchestration != "deep" {
		t.Fatalf("orchestration: got %q want deep", got.Orchestration)
	}
	if got.GeneratedAt == "" {
		t.Fatalf("generated_at 不能为空")
	}
	for name, arr := range map[string][]string{
		"shells": got.Shells, "creds_refs": got.CredsRefs, "topology": got.Topology,
		"incomplete_surfaces": got.IncompleteSurfaces, "next_actions": got.NextActions,
	} {
		if arr == nil || len(arr) != 0 {
			t.Fatalf("%s 必须是空数组（非 null），got %#v", name, arr)
		}
	}
	if filepath.Base(path) != "HANDOFF-conv-abc-__-x.json" {
		t.Fatalf("unexpected file name: %s", filepath.Base(path))
	}

	// conversationId 为空：只记日志、不写文件、不 panic。
	if p := emitMaxIterationsHandoff(nil, base, "   ", "deep"); p != "" {
		t.Fatalf("empty conversation id must not write file, got %q", p)
	}
}
