# 挂钩点清单(接线层)

> 本包只交付**烛龙代码**(`src/`)。平台侧需要按下面的锚点把烛龙接进去。
> 若你的树已含烛龙(即你在用带烛龙的版本),这些锚点已经存在 —— 直接覆盖 `src/` 即可升级。
> 若是干净平台,逐条按锚点接线;每处都是**外科手术式**改动,不改原有逻辑。

| # | 文件 | 锚点符号(现役位置) | 要加什么 |
|---|---|---|---|
| 1 | `internal/app/app.go` | `registerChainTools(...)`(254) | 注册链工具;两处调用点(MCP server + 后台轮) |
| 2 | `internal/app/app.go` | `loop2.ZhulongGateCheck = func(...)`(154) | 注入闸门闭包:`collectGateStats/decideGate` 未导出,必须同包注入 |
| 3 | `internal/app/app.go` | `zhulong.NewChainStore(db.DB)` + `EnsureSchema`(187/191) | 启动建 `zl_chains/zl_chain_attempts` 两表(幂等) |
| 4 | `internal/app/app.go` | `zhulong.StartAutoContinue(...)`(494 附近) | 启动自动续轮调度器(可配 interval/maxRounds/since) |
| 5 | `internal/app/deliver_gate_tools.go` | `collectChainStats` / `OpenChains`(145) | 闸门读链账本:open 链>0 → `CONTINUE open-chains` |
| 6 | `internal/coverage/coverage.go` | `BlockedFaces / ClosedFaces / ClosedPct`(251-253) | 收口口径:blocked 计入收口;`CoveragePct` 语义冻结 |
| 7 | `internal/app/vulnerability_tools.go` | `record_vulnerability` 成功分支(380 附近) | 中/高危自动 `zl_chain_open` 挂链,并在返回文案里引导下一台阶 |
| 8 | `internal/config/config.go` | `Zhulong ZhulongConfig`(420) + `type ZhulongConfig`(427) | 配置段 `multi_agent.zhulong`(见 `config/zhulong.example.yaml`) |
| 9 | `internal/database/database.go` | `unattended_mode` 迁移(1540-1552) | `conversations` 三列:unattended_mode / continue_hint / unattended_since(幂等 ALTER) |
| 10 | `internal/database/conversation.go` | `SetConversationUnattended`(526) / `GetConversationUnattendedSince`(550) | 读写三列的存取函数 |
| 11 | `internal/handler/agent.go` | `RunZhulongContinueRound`(2726) | 自动续轮入口(供 `StartAutoContinue` 注入) |
| 12 | `internal/handler/conversation.go` | `SetZhulongKick`(41) + unattended 路由 | `GET/PUT /api/conversations/:id/unattended`(勾选即起轮) |
| 13 | `internal/handler/multi_agent_prepare.go` | `req.Unattended`(159 附近) | 发消息时把 unattended 随会话落库(非 zhulong 模式忽略) |
| 14 | `internal/mcp/builtin/constants.go` | `ToolZLChainOpen/Attempt/Close/List`(38-41) + 白名单(120) | 工具名常量 + 进 `ToolNames()` 白名单 |
| 15 | `internal/app/mcp_authorization.go` | `case builtin.ToolZLChainOpen...`(155/159) | 授权分支:写类工具(pentest)与读取类分开归类 |
| 16 | `roles/*.yaml` | `tools:` 列表 | 19 个角色各加 4 个链工具(注册≠可见,见 `docs/roles.md`) |
| 17 | `web/templates/index.html` 等三件 | `zhulong-unattended` 相关(5/11/6 处) | 可选:模式下拉「烛龙」+ 仅烛龙可见的「无人值守」勾选 |

## 依赖说明

- 编排器 `src/internal/loop2/zhulong_orchestrator.go` 依赖平台侧的
  `internal/{agent,config,database,reasoning,zhaoheng}`。
  **`internal/zhaoheng` 必须存在**(昭衡是烛龙体系的前身,保留其包与命名);
  若你的树已删除该包,把编排器里 `zhaoheng.*` 三处(DefaultGuardLimits / DefaultDoD / AppendRoundReport)
  换成本地实现即可。
- 引擎包 `src/internal/zhulong/` **零平台依赖**,可单独 `go test ./internal/zhulong/`。

## 最小可跑集

1(注册) + 3(建表) + 5(闸门) + 8(配置) + 9(三列) → 后端能跑通一轮链闭环;
其余为无人值守、前端、角色可见性等增强。
