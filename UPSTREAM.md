# 上游基线

> **发布前必填**：把下面的占位符替换成真实的上游仓库地址与 tag/commit。

| 项 | 值 |
|---|---|
| 上游项目 | CyberStrikeAI |
| 上游仓库 | `<TODO: https://github.com/<org>/CyberStrikeAI>` |
| 基线版本 | `1.7.17` |
| 基线 commit | `7d2201c`（打包方现役 HEAD，对应 20261110 构建） |
| 布局要求 | `loop2`（eino2）布局；`internal/multiagent` 旧布局不适用 |
| 额外依赖 | `internal/zhaoheng` 必须存在（昭衡为烛龙前身，保留其包） |
| Go 版本 | `go 1.25.0`（实测 1.25.5 与 1.26.5 均可构建） |

## 兼容矩阵

| 烛龙版本 | 目标平台 | 状态 |
|---|---|---|
| v0.1.0 | CyberStrikeAI 1.7.17 / loop2 | ✅ 打包方同源树验证 |
| v0.1.0 | `internal/multiagent` 旧布局 | ❌ 不支持（需先迁移布局） |

## 目标平台的底盘要求

- HTTP 层：gin 路由 + `handler.AgentHandler`（承接 zhulong 轮次）
- 模型层：eino 单代理 runner（`runEinoSingleChatModelAgentNamed` 或其等价物）
- 数据层：`data/conversations.db`（SQLite），`conversations` 表可加列
- 闸门层：`deliver_gate` 工具与 `coverage` 包（若缺，按 `hooks/ANCHORS.md` #5/#6 接）
