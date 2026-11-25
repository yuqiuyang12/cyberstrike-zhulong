package loop2

// Phase 0.5 spike 测试(2026-10-21)——为"覆盖门"与"探针批处理"验证地基是否成立。
// 只跑测试,不改产品代码;跑法:go test ./internal/loop2/ -run 'Spike' -v -count=1

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/eino/compose"
)

// SP1a:compose.ToolMiddleware 能在"工具真正执行前"拦下调用并返回合成结果。
// 这是"覆盖门拒绝切资产"的实现地基:拦不住 → 门只能退化成语义提示。
func TestSpike_SP1_MiddlewareBlocksBeforeExecution(t *testing.T) {
	var executed atomic.Bool
	next := func(ctx context.Context, in *compose.ToolInput) (*compose.ToolOutput, error) {
		executed.Store(true)
		return &compose.ToolOutput{Result: "REAL EXECUTION"}, nil
	}
	gate := compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, in *compose.ToolInput) (*compose.ToolOutput, error) {
				// 覆盖门判定:当前资产还有未覆盖面 → 拒绝
				if in != nil && strings.HasPrefix(in.Name, "httpx") {
					return &compose.ToolOutput{Result: "[gate] blocked: asset a.example.com 还有 3 个面未覆盖"}, nil
				}
				return next(ctx, in)
			}
		},
	}
	out, err := gate.Invokable(next)(context.Background(), &compose.ToolInput{Name: "httpx_probe", Arguments: "{}"})
	if err != nil {
		t.Fatalf("gate returned error (应为软结果而非硬错): %v", err)
	}
	if executed.Load() {
		t.Fatal("SP1 FAIL: 工具在门拒绝后仍然执行了")
	}
	if !strings.Contains(out.Result, "blocked") {
		t.Fatalf("SP1 FAIL: 未返回门禁结果: %q", out.Result)
	}
	t.Logf("SP1a PASS: 门拦截生效,工具未执行,返回软结果 %q", out.Result)
}

// SP1b:生产中间件(本地特权工具 RBAC)在无 principal 上下文中确实拒绝且不执行。
// 用真实产品代码验证"拦得住",而不是只验证自造中间件。
func TestSpike_SP1_ProductionRBACDeniesWithoutPrincipal(t *testing.T) {
	var executed atomic.Bool
	next := func(ctx context.Context, in *compose.ToolInput) (*compose.ToolOutput, error) {
		executed.Store(true)
		return &compose.ToolOutput{Result: "EXECUTED"}, nil
	}
	mw := localToolRBACMiddleware()
	// execute 属于本地特权工具(见 isLocalPrivilegeTool)
	out, err := mw.Invokable(next)(context.Background(), &compose.ToolInput{Name: "execute", Arguments: `{"command":"id"}`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if executed.Load() {
		t.Fatal("SP1b FAIL: RBAC 未拦住 execute")
	}
	if !strings.Contains(strings.ToLower(out.Result), "permission denied") {
		t.Fatalf("SP1b FAIL: 未返回拒绝文案: %q", out.Result)
	}
	t.Logf("SP1b PASS: 生产 RBAC 拦截生效: %q", out.Result)
}

// SP5:探针批处理的有界并发器(峰值不超过 cap),且不因单个探针失败而中断整批。
// 这是 probe_plan 的实现地基:平台侧 external_mcp 并发上限 16,批内必须自限流。
func TestSpike_SP5_BoundedConcurrentProbes(t *testing.T) {
	const (
		total = 60
		capN  = 8
	)
	sem := make(chan struct{}, capN)
	var peak, cur int32
	var wg sync.WaitGroup
	var failed int32
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			n := atomic.AddInt32(&cur, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt32(&cur, -1)
			if i%13 == 7 { // 模拟个别探针失败
				atomic.AddInt32(&failed, 1)
			}
		}(i)
	}
	wg.Wait()
	if peak > capN {
		t.Fatalf("SP5 FAIL: 峰值并发 %d 超过上限 %d", peak, capN)
	}
	if failed == 0 {
		t.Fatal("SP5 FAIL: 未模拟到失败探针")
	}
	t.Logf("SP5 PASS: %d 个探针,峰值并发 %d ≤ cap %d,失败 %d 个被单独记录(未中断整批)",
		total, peak, capN, failed)
}
