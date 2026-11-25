package loop2

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

// TestGobCheckpointEncodesJSONShapedValues 是 gob 注册的回归护栏。
//
// 背景: Eino ADK 的 ChatModelAgent 在 graph 内无条件挂
// compose.WithCheckPointID(bridgeCheckpointID) + gobSerializer，中断(停止/中断并继续/
// preempt)时会把整个 compose checkpoint 用标准 gob 编码。gob 要求 interface 槽位里的
// 具体类型事先 gob.Register，而 JSON 解码产生的 map[string]interface{} / []interface{}
// 默认未注册 → 报
//
//	failed to set checkpoint: gob: type not registered for interface: map[string]interface {}
//
// 整轮对话直接失败(平台 0591737f/1e6ede9c/b9674b2d/9e6fcc1d 四次事故)。
// 修复为 init 注册两个 JSON 容器类型；此测试在未注册时会失败。
func TestGobCheckpointEncodesJSONShapedValues(t *testing.T) {
	type fakeCheckpoint struct {
		State    any
		Inputs   map[string]any
		Channels map[string]any
	}
	// 模拟一条模型消息的 Extra：agenticopenai 的 chat response meta 扩展键，经任何 JSON
	// 往返后会变成 map[string]interface{}。
	cp := fakeCheckpoint{
		State: map[string]any{
			"messages": []any{
				map[string]any{
					"extra": map[string]interface{}{
						"_eino_ext_agenticopenai_chat_response_meta_ext": map[string]interface{}{
							"finish_reason": "tool_calls",
							"id":            "0730a9831b6c3ee800f978c35fdf2dfa",
						},
					},
				},
			},
		},
		Inputs:   map[string]any{"node": []any{"x"}},
		Channels: map[string]any{},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&cp); err != nil {
		t.Fatalf("checkpoint gob encode failed: %v", err)
	}
	var back fakeCheckpoint
	if err := gob.NewDecoder(bytes.NewBuffer(buf.Bytes())).Decode(&back); err != nil {
		t.Fatalf("checkpoint gob decode failed: %v", err)
	}
	if got := fmt.Sprint(back.State); !strings.Contains(got, "tool_calls") {
		t.Fatalf("roundtrip lost extra payload: %s", got)
	}
}

// memCheckPointStore 内存版 CheckPointStore，用于在测试里驱动 TurnLoop 的 checkpoint 落盘。
type memCheckPointStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemCheckPointStore() *memCheckPointStore {
	return &memCheckPointStore{m: make(map[string][]byte)}
}

func (s *memCheckPointStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[key]
	return b, ok, nil
}

func (s *memCheckPointStore) Set(_ context.Context, key string, val []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = append([]byte(nil), val...)
	return nil
}

// TestEinoTurnLoopCheckpointWithJSONMapExtra 端到端复现：history 里带 JSON 形态 Extra
// (map[string]interface{}) 的会话被「停止/中断」时，TurnLoop 与 ChatModelAgent 的
// checkpoint 都必须能编码成功，且不得把 gob 注册错误抛成 run 错误。
func TestEinoTurnLoopCheckpointWithJSONMapExtra(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mockModel := newTurnLoopBlockingModel()
	agent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name:  "gob-repro-agent",
		Model: mockModel,
	})
	if err != nil {
		t.Fatalf("NewChatModelAgent: %v", err)
	}

	seed := schema.AssistantMessage("seed history", nil)
	seed.Extra = map[string]any{
		"meta": map[string]interface{}{
			"finish_reason": "tool_calls",
			"id":            "seed-id",
		},
	}

	store := newMemCheckPointStore()
	var mu sync.Mutex
	var eventErrs []error

	rt := NewEinoTurnLoopRuntime(EinoTurnLoopRuntimeConfig{
		Agent:            agent,
		Store:            store,
		CheckpointID:     "gob-repro-cp",
		InterruptTimeout: 20 * time.Millisecond,
		InitialMessages:  []*schema.Message{schema.UserMessage("run"), seed},
		OnAgentEvents: func(_ context.Context, _ *adk.TurnContext[EinoTurnLoopItem, *schema.Message], events *adk.AsyncIterator[*adk.AgentEvent]) error {
			for {
				ev, ok := events.Next()
				if !ok {
					return nil
				}
				if ev != nil && ev.Err != nil {
					mu.Lock()
					eventErrs = append(eventErrs, ev.Err)
					mu.Unlock()
				}
			}
		},
	})
	rt.Run(ctx)

	select {
	case <-mockModel.started:
	case <-ctx.Done():
		t.Fatal("model call did not start")
	}

	// 模拟用户在对话页点「停止」/「中断并继续」：TurnLoop 立即取消当前 turn，
	// ChatModelAgent 走 graph interrupt → 保存 checkpoint。
	rt.StopImmediate("test-stop")

	done := make(chan *adk.TurnLoopExitState[EinoTurnLoopItem, *schema.Message], 1)
	go func() { done <- rt.Wait() }()

	var state *adk.TurnLoopExitState[EinoTurnLoopItem, *schema.Message]
	select {
	case state = <-done:
	case <-ctx.Done():
		t.Fatal("turn loop did not exit after stop")
	}

	if state != nil && state.CheckpointErr != nil {
		t.Fatalf("turn loop checkpoint failed: %v", state.CheckpointErr)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, e := range eventErrs {
		if e != nil && strings.Contains(e.Error(), "type not registered for interface") {
			t.Fatalf("agent checkpoint hit gob registration error: %v", e)
		}
	}
}
