package loop2

// zhulong_budget_test.go —— 轮预算触顶纯函数的回归测试（P1-A，2026-11-06）。
//
// 防的失败方式：
//  1. 触顶判定散落在 settle 里，换引擎时口径漂移 → 契约⑥「触顶必进 settlement」只在 wrapper 下成立；
//  2. 把「用户点停止（context.Canceled）」误判成触顶 → 取消也跑收尾，白烧一次模型调用。
// 引擎分流用例随 native 引擎退役归档（_archive/zhulong-turnloop-2026-11-06）。

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// 三个触顶源 + 非触顶反例。
func TestP1BudgetExhaustedSources(t *testing.T) {
	bg := context.Background()

	// ① Eino 迭代上限（英文/中文文案都认）。
	for _, msg := range []string{
		"maximum iterations reached",
		"max iteration limit",
		"iteration limit exceeded",
		"agent 达到最大迭代次数",
	} {
		if !isZhulongBudgetExhausted(errors.New(msg), bg) {
			t.Fatalf("迭代上限错误未被识别为触顶: %q", msg)
		}
	}

	// ② runErr 链里的 DeadlineExceeded（要求 %w 包装也能穿透）。
	if !isZhulongBudgetExhausted(fmt.Errorf("model call: %w", context.DeadlineExceeded), bg) {
		t.Fatal("包装的 DeadlineExceeded 未被识别为触顶")
	}

	// ③ ctx 的 cause 是 DeadlineExceeded（runErr 为 nil 的墙钟到点场景）。
	done, cancel := context.WithTimeout(bg, time.Millisecond)
	defer cancel()
	<-done.Done()
	if !isZhulongBudgetExhausted(nil, done) {
		t.Fatal("ctx cause=DeadlineExceeded 应判触顶（runErr 可能为 nil）")
	}

	// 反例：用户取消 ≠ 触顶；普通错误 ≠ 触顶；全空不 panic。
	cancelled, cancel2 := context.WithCancel(bg)
	cancel2()
	if isZhulongBudgetExhausted(context.Canceled, cancelled) {
		t.Fatal("context.Canceled 是用户取消，不应判触顶（不跑收尾）")
	}
	if isZhulongBudgetExhausted(errors.New("tool failed"), bg) {
		t.Fatal("普通业务错误不应判触顶")
	}
	if isZhulongBudgetExhausted(nil, nil) {
		t.Fatal("nil ctx + nil err 应返回 false")
	}
	if isZhulongBudgetExhausted(nil, bg) {
		t.Fatal("正常 ctx 且无错误不应判触顶")
	}
}
