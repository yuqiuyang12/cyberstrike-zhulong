# 交付闸门 deliver_gate

## 判定顺序(命中即返回)

1. `faces==0` → `CONTINUE no-faces-registered`
2. `live==0` → `CONTINUE no-live-assets`
3. `OpenChains>0` → `CONTINUE open-chains`
4. 小集(`live<=small_set`)且 `ClosedPct>=100` → `PASS small-set-closed`
5. `ClosedPct>=min_coverage` 且 `registered>=ceil(live*min/100)` → `PASS closed+registered`
6. `ClosedPct>=100` → `PASS closed-100`
7. 停滞且 `ClosedPct>0` → `PARTIAL stall`
8. 其余 → `CONTINUE closed-below-threshold`

## 两个覆盖率口径

- `CoveragePct = doneFaces / totalFaces` —— 语义冻结,不参与"能否交卷"
- `ClosedPct = (doneFaces + blockedFaces) / totalFaces` —— 收口口径,blocked 也算收口

> 历史坑:只用 CoveragePct 时,`done=3/blocked=2/faces=5` 天花板 60%,
> 闸门会输出"还剩 0 个面"的自相矛盾文案,模型学会无视闸门。

## STATS 行

`STATS closed=%d done=%d blocked=%d faces=%d chains=%d open=%d exploited=%d depth=%d specific=%d vulns=%d`

## 输出契约

首行固定 `GATE=PASS|CONTINUE|PARTIAL`,随后 `REASON=`、`STATS`、`NEXT:` 建议。
下游(loop/自动续轮/回执)解析首行,不看正文措辞。
