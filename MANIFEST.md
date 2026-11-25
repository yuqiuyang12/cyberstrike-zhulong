# 清单:本包改了什么

## 新增(直接落盘,不改平台既有文件)

| 路径 | 说明 |
|---|---|
| `src/internal/zhulong/*.go` | 引擎 27 文件(12 核心 + 15 测试) |
| `src/internal/loop2/` | **eino2 loop 引擎全量代码**(runner / eino_single_runner / eino_adk_run_loop / eino_turn_loop_* / eino_middleware / eino_summarize / eino_model_resilience / eino_skills / orchestration 等 216 文件) |
| `src/internal/app/chain_tools.go` | `zl_chain_open/attempt/close/list` 四个内置工具 |
| `schema/zhulong.sql` | `zl_chains`、`zl_chain_attempts` 两表 + `conversations` 三列 |
| `config/zhulong.example.yaml` | `multi_agent.zhulong` 配置样例 |
| `docs/*` `hooks/ANCHORS.md` | 架构/利用链/闸门/无人值守/角色 + 17 处挂钩点 |
| `scripts/*` | apply / verify / prepublish-check / regen-patches |

## 需要接线(平台既有文件,按 `hooks/ANCHORS.md`)

| 文件 | 改动性质 |
|---|---|
| `internal/app/app.go` | 注册链工具 / 注入闸门闭包 / 启动自动续轮 / 建表 |
| `internal/app/deliver_gate_tools.go` | 闸门读链账本(open 链阻断 PASS) |
| `internal/app/vulnerability_tools.go` | 中/高危自动开链 |
| `internal/coverage/coverage.go` | `ClosedPct` 收口口径(不动 `CoveragePct`) |
| `internal/config/config.go` | `ZhulongConfig` |
| `internal/database/{database,conversation}.go` | 三列迁移 + 存取 |
| `internal/handler/{agent,conversation,multi_agent_prepare}.go` | 续轮入口 / unattended API / 字段落库 |
| `internal/mcp/builtin/constants.go` + `internal/app/mcp_authorization.go` | 工具名 + 授权 |
| `roles/*.yaml`(19 个) | tools 白名单 +4 |
| `web/*`(可选) | 模式下拉 + 无人值守勾选 |

## 不含

二进制、业务库数据、知识库全文(仅 1 篇方法论)、武库/字典、客户与项目数据。
