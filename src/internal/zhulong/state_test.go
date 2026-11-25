package zhulong

import (
	"context"
	"strings"
	"testing"
)

// 防的失败方式：
//  1. 上一轮的 next_actions 没落台账 → 下一轮又要人再说一遍
//  2. 同一条待办重复插入（每轮都加一遍，台账爆炸）
//  3. 状态块把目标/待办裁掉（裁剪顺序错，模型一开场就丢目标）
func TestTodosLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.SaveGoal(ctx, &Goal{ID: "g1", ConversationID: "c1", Objective: "测 example.com"}); err != nil {
		t.Fatal(err)
	}

	n, err := s.AddTodos(ctx, "g1", "run-1", []string{
		"补落盘回读，拿文件型证据",
		"补落盘回读，拿文件型证据", // 重复，应被去重
		"确认 443 是否走 CDN",
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("应写入 2 条（去重后），实际 %d", n)
	}

	// 第二轮再报同一批：不应重复插
	n2, err := s.AddTodos(ctx, "g1", "run-2", []string{"确认 443 是否走 CDN"})
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("已存在的 open 待办不应重复插入，实际新增 %d", n2)
	}

	list, err := s.ListOpenTodos(ctx, "g1", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("应有 2 条 open 待办，实际 %d", len(list))
	}

	closed, err := s.CloseTodos(ctx, "g1")
	if err != nil {
		t.Fatal(err)
	}
	if closed != 2 {
		t.Fatalf("应收口 2 条，实际 %d", closed)
	}
	list, _ = s.ListOpenTodos(ctx, "g1", 20)
	if len(list) != 0 {
		t.Fatalf("收口后不应有 open 待办，实际 %d", len(list))
	}
}

func TestRecentStepsOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateRun(ctx, &Run{ID: "r", ConversationID: "c", GoalID: "g"}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := s.AppendStep(ctx, &Step{RunID: "r", StepNo: i, ToolName: "exec"}); err != nil {
			t.Fatal(err)
		}
	}
	steps, err := s.RecentSteps(ctx, "r", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 3 || steps[0].StepNo != 3 || steps[2].StepNo != 5 {
		t.Fatalf("应取最近 3 条且旧→新，实际 %+v", steps)
	}
}

func TestBuildStateBlockKeepsHead(t *testing.T) {
	// 步骤极多时，目标与待办必须还在（裁剪只能砍尾部）
	long := make([]Step, 0, 200)
	for i := 1; i <= 200; i++ {
		long = append(long, Step{StepNo: i, ToolName: "exec", Summary: strings.Repeat("x", 100)})
	}
	blk := BuildStateBlock(StateBlockInput{
		Objective:   "测 example.com 全端口",
		Constraints: []string{"只测主域，不含子域"},
		Budget:      Run{StepBudget: 60, MinuteBudget: 25},
		Todos:       []Todo{{Text: "补文件型证据"}},
		RecentSteps: long,
	}, 3000)

	if !strings.Contains(blk, "测 example.com 全端口") {
		t.Fatalf("目标被裁掉:\n%s", blk[:200])
	}
	if !strings.Contains(blk, "补文件型证据") {
		t.Fatalf("待办被裁掉")
	}
	if !strings.Contains(blk, "只测主域") {
		t.Fatalf("约束被裁掉")
	}
}

func TestBuildStateBlockEmpty(t *testing.T) {
	blk := BuildStateBlock(StateBlockInput{Objective: "x", Budget: Run{StepBudget: 60, MinuteBudget: 25}}, 0)
	if !strings.Contains(blk, "目标") || strings.Contains(blk, "未完成待办") {
		t.Fatalf("空输入不应出现待办段: %s", blk)
	}
}
