# 烛龙(Zhulong) · eino2 loop——CyberStrikeAI 的利用链闭环增强包

> **eino → eino2：从"跑一次就停"到"链没清零不许交卷"。**
> CyberStrikeAI 自带 `eino` 单代理 runner——跑一次就交卷，漏洞停在"确认"。
> 烛龙把它升级成 `eino2` loop 模式：**eino2 = 烛龙，烛龙 = eino2。**
> 每个中高危漏洞自动开链，open 链没清零，就不许交卷。

## eino vs eino2：代际演进

| | eino（v1） | eino2 / 烛龙（v2） |
|---|---|---|
| 交卷标准 | 跑完一轮 | open 链 = 0 才许 PASS |
| 优化目标 | 面覆盖率 | 链深度（0→6 台阶） |
| blocked | 记一笔就过 | ≥3 变体才许收口 |
| 无人值守 | 无 | 会话级勾选自动续轮 |
| 止损 | 无 | 连续 3 轮无 exploited → 止损轮；6 轮 → 停排 |

eino 是 CyberStrikeAI 的单代理引擎——一次对话、一次产出、结束。
eino2 是烛龙——一轮不是终点，是下一轮的起点。只要还有 open 链，loop 就不停。

## 它解决什么

传统渗透 Agent 的优化目标是"面覆盖率"——扫过没、跑完没。结果是：漏洞记了一堆，全停在"确认"这一步。

烛龙把目标换成**链深度**：

| 台阶 | 含义 |
|---|---|
| 0 | 漏洞已确认 |
| 1 | 读到敏感数据 |
| 2 | 认证绕过 |
| 3 | 写入(创建/修改业务数据) |
| 4 | 上传成功 |
| 5 | 执行 |
| 6 | 横向 |

- `zl_chain_open / attempt / close / list` 四工具记账，每次尝试落 payload + 证据绝对路径 + verdict
- `blocked` 不是免死金牌：同一台阶 **≥3 个不同变体** 才允许收口
- `deliver_gate` 硬门：**open 链 > 0 → 不许 PASS**
- 止损阀：连续 3 轮无 `exploited` → 转止损轮；6 轮 → 停排
- 无人值守：会话级勾选，勾选即起轮，每次重勾重置 18 轮预算

## 快速开始

```bash
git clone <this-repo> zhulong && cd zhulong
bash scripts/apply.sh /path/to/your/CyberStrikeAI     # 合并式覆盖,先备份原文件
cd /path/to/your/CyberStrikeAI && go build ./cmd/server
bash /path/to/zhulong/scripts/verify.sh .             # 静态检查接线是否齐
```

> **前置**：平台需为 `loop2`(eino2) 布局，且含 `internal/zhaoheng`（昭衡是烛龙体系的前身，其包与命名保留）。
> 若你的树还没有接线，按 `hooks/ANCHORS.md` 逐条挂（每处都是外科手术式改动）。

## 包内结构

```
src/internal/zhulong/          引擎(27 文件,零平台依赖,可单独 go test)
src/internal/loop2/            eino2 loop 引擎全量代码(216 文件: runner / eino_single_runner / eino_adk_run_loop / eino_turn_loop_* / eino_middleware / eino_summarize / eino_model_resilience / eino_skills / orchestration 等)
src/internal/app/chain_tools.go  zl_chain_* 四工具
schema/zhulong.sql             zl 两表 + conversations 三列
config/zhulong.example.yaml    multi_agent.zhulong 配置样例
hooks/ANCHORS.md               17 处挂钩点清单
docs/                          架构 / 利用链 / 闸门 / 无人值守 / 角色可见性 / 方法论
scripts/                       apply / verify / prepublish-check / regen-patches
```

## 边界与限制

- **只适配已装 CyberStrikeAI 的机器**，不提供平台本体；
- 前端开关（模式下拉 + 无人值守勾选）在 `hooks/ANCHORS.md` #17，属可选项；不接前端也能用 API 跑；
- 不对 CyberStrikeAI 本体问题提供支持；
- 仅用于**授权**安全测试与研究。

## 许可

Apache-2.0（与上游一致）。衍生分发请保留 `LICENSE` 与 `NOTICE`。

---

**作者**：yuqiuyang12  
**联系**：1850493807@qq.com