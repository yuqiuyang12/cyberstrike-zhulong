# 无人值守(会话级)

## 数据模型(conversations 三列)

| 列 | 类型 | 含义 |
|---|---|---|
| `unattended_mode` | INTEGER 0/1 | 该会话是否勾选无人值守 |
| `continue_hint` | TEXT | 续轮提示(人话,原样附在「继续」后) |
| `unattended_since` | TEXT | 本次勾选起始时间(轮数预算从此计) |

## 全局配置 multi_agent.zhulong

| 键 | 含义 | 现役值 |
|---|---|---|
| `enabled` | 总开关 | true |
| `step_budget` | 单轮工具步数上限 | 400 |
| `minute_budget` | 单轮墙钟上限(分钟) | 60 |
| `min_minute_budget` | 单轮最短(分钟),未达标不许提前收口 | 30 |
| `auto_continue` | 自动续轮总闸 | true |
| `auto_continue_interval_min` | 两轮最小间隔(分钟) | 5 |
| `max_rounds` | 单次勾选的轮数预算 | 18 |

## 行为要点

- **只续自己**:自动续轮只挑 `agent_mode=zhulong` 且 `unattended_mode=1` 的会话
- **勾选即起轮**:关→开时立即触发一轮,不等后台节拍
- **预算重置**:每次关→开把 `unattended_since` 置为当前,轮数预算重新计
- **续轮文案是人话**:默认就"继续",`continue_hint` 原文追加,不套模板
- **止损**:连续 6 轮无 exploited → 停排(代码内置)
