package zhulong

// heartbeat_test.go —— 租约心跳测试（P0 · T5）。
//
// 防的失败方式（2026-11-06 实测事故）：
//  1. `TouchRun` 在生产代码里零调用 → 60 分钟预算的轮在第 10 分钟左右被 lease 判 unknown；
//  2. 模型长时间思考（无 tool_call/tool_result 事件）时没有任何东西刷新 seen_at；
//  3. 心跳 goroutine 泄漏 / stop 不幂等 → 轮结束后还在写库；
//  4. 心跳沿用 runCtx：预算到点一取消，收尾阶段又掉租约。

import (
	"context"
	"testing"
	"time"
)

// mustRunWithOldSeenAt 建一条 running run，并把 seen_at 回拨一小时（模拟"心跳早停"）。
func mustRunWithOldSeenAt(t *testing.T, s *Store, runID string) time.Time {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateRun(ctx, &Run{ID: runID, ConversationID: "conv-hb", GoalID: "zl-goal-conv-hb"}); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := s.StartRun(ctx, runID); err != nil {
		t.Fatalf("start run: %v", err)
	}
	old := time.Now().UTC().Add(-time.Hour)
	if _, err := s.db.ExecContext(ctx, `UPDATE zhulong_runs SET seen_at=? WHERE id=?`, ts(old), runID); err != nil {
		t.Fatalf("seed seen_at: %v", err)
	}
	return old
}

// seenAt 读当前 seen_at。
func seenAt(t *testing.T, s *Store, runID string) time.Time {
	t.Helper()
	r, err := s.GetRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	return r.SeenAt
}

// ① WrapProgress 每个事件先刷租约：工具事件到达后 seen_at 必须变新。
func TestHeartbeatWrapProgressTouchesRun(t *testing.T) {
	store := newTestStore(t)
	const runID = "zl-run-hb-wrap"
	old := mustRunWithOldSeenAt(t, store, runID)
	ctx := context.Background()

	rec := NewStepRecorder(ctx, store, runID, nil)
	forwarded := 0
	progress := rec.WrapProgress(func(eventType, message string, data interface{}) { forwarded++ })

	progress("tool_call", "正在调用工具: exec", map[string]interface{}{
		"toolName": "exec", "arguments": `{"command":"id"}`, "toolCallId": "call-hb-1",
	})
	if forwarded != 1 {
		t.Fatalf("事件必须原样转发, 实际 %d", forwarded)
	}
	got := seenAt(t, store, runID)
	if !got.After(old) {
		t.Fatalf("WrapProgress 后 seen_at 应变新: old=%s got=%s", old, got)
	}

	// 节流：1 秒内第二个事件不得重复打库（seen_at 保持不变）——工具事件成串到达时别写放大。
	progress("tool_result", "工具结果 (exec)", map[string]interface{}{
		"toolName": "exec", "toolCallId": "call-hb-1", "result": "uid=0(root)",
	})
	if now := seenAt(t, store, runID); !now.Equal(got) {
		t.Fatalf("1 秒内应节流（seen_at 不变）: 前=%s 后=%s", got, now)
	}

	// store/runID 为空的 no-op recorder 不得 panic。
	NewStepRecorder(ctx, nil, "", nil).WrapProgress(nil)("tool_call", "x", nil)
}

// ② StartHeartbeat：短间隔跑两拍后 seen_at 变新；stop 幂等且停后不再写。
func TestHeartbeatStartHeartbeatTicks(t *testing.T) {
	store := newTestStore(t)
	const runID = "zl-run-hb-ticker"
	old := mustRunWithOldSeenAt(t, store, runID)

	stop := StartHeartbeat(context.Background(), store, runID, 20*time.Millisecond, nil)
	// 两拍 = 至少 40ms；给足余量，不做"睡死"式断言。
	deadline := time.Now().Add(2 * time.Second)
	var got time.Time
	for time.Now().Before(deadline) {
		got = seenAt(t, store, runID)
		if got.After(old) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !got.After(old) {
		t.Fatalf("心跳未刷新 seen_at: old=%s got=%s", old, got)
	}

	// stop 幂等：重复调用不得 panic / 阻塞。
	stop()
	stop()

	frozen := seenAt(t, store, runID)
	time.Sleep(80 * time.Millisecond) // 停后至少再跨 4 拍
	if after := seenAt(t, store, runID); !after.Equal(frozen) {
		t.Fatalf("stop 之后不应再写 seen_at: 停时=%s 之后=%s", frozen, after)
	}
}

// ③ 边界：interval<=0 走默认；store/runID 为空返回可安全调用的 stop。
func TestHeartbeatStartHeartbeatGuards(t *testing.T) {
	if DefaultHeartbeatInterval != 45*time.Second {
		t.Fatalf("默认心跳间隔应为 45s, 实际 %s", DefaultHeartbeatInterval)
	}
	store := newTestStore(t)
	const runID = "zl-run-hb-guard"
	mustRunWithOldSeenAt(t, store, runID)

	// interval<=0 用默认值：立刻 stop，只验证不 panic、可重复 stop。
	stop := StartHeartbeat(nil, store, runID, 0, nil)
	stop()
	stop()

	// store/runID 缺失 → no-op。
	StartHeartbeat(context.Background(), nil, "x", time.Millisecond, nil)()
	StartHeartbeat(context.Background(), store, "  ", time.Millisecond, nil)()
}
