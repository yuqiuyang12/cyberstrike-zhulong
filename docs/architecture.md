# 架构:三层

```
┌─────────────────────────────────────────────────────────────┐
│ ③ 接线层(平台侧,需按 hooks/ANCHORS.md 挂)                  │
│   app.go 注册链工具 / 注入闸门闭包 / StartAutoContinue      │
│   database: conversations 三列、zl_* 两表                   │
│   handler: GET|PUT /api/conversations/:id/unattended        │
│   web: 模式下拉「烛龙」+「无人值守」勾选(可选)              │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ ② 编排层 src/internal/loop2/                                │
│   zhulong_orchestrator.go  一轮闭环:注入状态→跑模型→收口    │
│   zhulong_budget.go        步数/墙钟预算、预算耗尽判定       │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ ① 引擎层 src/internal/zhulong/  (零平台依赖,可单独阅读/测试)│
│   chain.go       链账本 zl_chains/zl_chain_attempts         │
│   receipt.go     回合回执与交付判定(open 链未清零不许 done) │
│   store.go       目标/待办/轮次存储                          │
│   settlement.go  结算与每步落库                              │
│   autocontinue.go 自动续轮调度(会话级闸门)                  │
│   boundary.go / scope.go  写操作边界(四条底线)              │
│   lease.go / state.go / goal.go / jsonutil.go               │
└─────────────────────────────────────────────────────────────┘
```

## 一轮闭环(时序)

1. `RunZhulongRound` 读配置 → 校验 `multi_agent.zhulong.enabled`
2. 建 run → 注入状态块(上一轮结论/未完成待办/最近步骤/证据)
3. 模型决定:调 `zl_chain_list` 挑最深的 open 链,或 `zl_chain_open` 新开链
4. 每个变体 `zl_chain_attempt` 落一行(payload + 证据路径 + verdict)
5. 收口前跑 `deliver_gate`;`GATE=PASS` 且 open 链=0 才允许 done
6. 写回执 → `finalizeZhulongRun` → 自动续轮调度器决定下一轮

## 设计取向

- **确定性判据下沉到 Go 代码**:能不能交卷由代码算,不信模型自报。
- **状态从磁盘回注**:聊天历史被压缩后,目标/待办/证据依然在场。
- **blocked 也要"试够"**:同台阶 ≥3 个不同变体才允许以 blocked 收口。
