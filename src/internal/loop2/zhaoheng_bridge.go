package loop2

// zhaoheng_bridge.go —— 昭衡（Zhaoheng）无人值守长任务在平台侧的接线。
//
// Z0 范围：mission 建立/复用、frontier 生成与选面、每轮把"下一步建议"注入上下文、
// 每轮结束写交接档。**尚不自动排下一轮**（那是 Z1），所以昭衡模式目前仍是"人点一次跑一轮"，
// 但每一轮都由台账决定打哪儿，而不是模型自由发挥。

import (
	"context"
	"fmt"
	"strings"

	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/zhaoheng"
	"cyberstrike-ai/internal/zhulong"

	"go.uber.org/zap"
)

const zhaohengOrchMode = "zhaoheng"

// zhaohengPrepare 在开跑前准备 mission + frontier，并返回要注入的上下文块。
// 任何一步失败都降级为空块（不阻塞本轮），但会记日志。
func zhaohengPrepare(
	ctx context.Context, db *database.DB, conversationID, objective string,
	limits zhaoheng.GuardLimits, dod zhaoheng.DoD, logger *zap.Logger,
) (block, missionID, asset, face string, stop bool) {
	if db == nil || db.DB == nil {
		return "", "", "", "", false
	}
	store, err := zhaoheng.NewStore(db.DB)
	if err != nil {
		if logger != nil {
			logger.Warn("zhaoheng: store 初始化失败", zap.Error(err))
		}
		return "", "", "", "", false
	}
	if err := store.EnsureSchema(ctx); err != nil {
		if logger != nil {
			logger.Warn("zhaoheng: 建表失败", zap.Error(err))
		}
		return "", "", "", "", false
	}

	// 复用会话当前的 mission；没有就建一个（目标 = 本轮用户输入）
	m, gerr := store.ActiveMissionForConversation(ctx, conversationID)
	if gerr != nil || m == nil {
		// 已存在但处于 stopped/done 的 mission：不再新建、不再复活，直接短路（零模型调用）
		existingID := fmt.Sprintf("zh-mission-%s", conversationID)
		if ex, eerr := store.GetMission(ctx, existingID); eerr == nil && ex != nil &&
			(ex.State == zhaoheng.MissionStopped || ex.State == zhaoheng.MissionDone) {
			block := "## 昭衡 mission 已结束\n- mission：" + ex.ID + "\n- 状态：" + ex.State +
				"\n- 停止原因：" + ex.StopReason + "\n- 若要重新开始，请新建 mission（或把状态改回 running）。\n"
			if logger != nil {
				logger.Info("zhaoheng mission already terminal",
					zap.String("missionId", ex.ID), zap.String("state", ex.State), zap.String("reason", ex.StopReason))
			}
			return block, ex.ID, "", "", true
		}
		m = &zhaoheng.Mission{
			ID:             fmt.Sprintf("zh-mission-%s", conversationID),
			ConversationID: conversationID,
			Objective:      objective,
			State:          zhaoheng.MissionRunning,
		}
		if cerr := store.CreateMission(ctx, m); cerr != nil {
			if logger != nil {
				logger.Warn("zhaoheng: 建 mission 失败", zap.Error(cerr))
			}
			return "", "", "", "", false
		}
	}

	if logger != nil {
		logger.Info("zhaoheng prepare enter",
			zap.String("conversationId", conversationID),
			zap.String("missionId", m.ID),
			zap.String("missionState", m.State),
			zap.String("createdAt", m.CreatedAt.Format(time.RFC3339Nano)))
	}

	// 每轮刷新前沿（幂等），然后确定性取一项作为本轮建议目标
	if n, berr := store.BuildFrontier(ctx, m.ID, conversationID); berr != nil {
		if logger != nil {
			logger.Warn("zhaoheng: 生成前沿失败", zap.Error(berr))
		}
	} else if logger != nil {
		logger.Info("zhaoheng frontier rebuilt", zap.String("missionId", m.ID), zap.Int("items", n))
	}
	// v2（2026-11-05 用户裁定）：面是地板、链是主线 —— 有 open 链的资产抬到最前。
	// 放在 BuildFrontier 之后（它会按台账重算 priority/reason，顺序不能反）。
	zhaohengBoostChainAssets(ctx, db, m.ID, conversationID, logger)

	// —— 六道安全阀：先判定"还该不该跑"，再决定"跑哪一项" ——
	lim := limits
	if lim.MaxRounds <= 0 {
		lim = zhaoheng.DefaultGuardLimits()
	}
	stats, _ := store.StatsSince(ctx, conversationID, m.CreatedAt)
	// 完成判据：每轮都算一次，注入"判据 vs 进度"，未达标不许 done
	var since time.Duration
	if !m.CreatedAt.IsZero() {
		since = time.Since(m.CreatedAt)
	}
	dodProgress := store.EvaluateDoD(ctx, conversationID, dod, stats.Total, since)
	fstats, _ := store.FrontierStats(ctx, m.ID)
	nextPeek, _ := store.NextFrontier(ctx, m.ID)
	peekAsset := ""
	if nextPeek != nil {
		peekAsset = nextPeek.Asset
	}
	noRung := store.NoProgressStreak(ctx, m.ID)
	d := zhaoheng.EvalGuard(zhaoheng.GuardInput{
		Mission:           m,
		Asset:             peekAsset,
		NoRungProgress:    noRung,
		RunsTotal:         stats.Total,
		ConsecutiveFailed: stats.ConsecutiveFailed,
		ConsecutiveNoGain: stats.ConsecutiveNoGain,
		FrontierPending:   fstats["pending"],
	}, lim)

	if logger != nil {
		logger.Info("zhaoheng guard evaluated",
			zap.String("verdict", string(d.Verdict)), zap.String("valve", d.Valve),
			zap.String("reason", d.Reason),
			zap.Int("runsTotal", stats.Total),
			zap.Int("consecFailed", stats.ConsecutiveFailed),
			zap.Int("consecNoGain", stats.ConsecutiveNoGain),
			zap.Int("pending", fstats["pending"]),
			zap.Int("noRungProgress", noRung))
	}
	if d.Verdict == zhaoheng.VerdictStop || d.Verdict == zhaoheng.VerdictPause {
		state := zhaoheng.MissionStopped
		if d.Verdict == zhaoheng.VerdictPause {
			state = zhaoheng.MissionPaused
		}
		if serr := store.StopMission(ctx, m.ID, state, d.Valve+": "+d.Reason); serr != nil && logger != nil {
			logger.Warn("zhaoheng: 更新 mission 状态失败", zap.Error(serr))
		}
		if logger != nil {
			logger.Warn("zhaoheng guard tripped",
				zap.String("missionId", m.ID), zap.String("valve", d.Valve),
				zap.String("verdict", string(d.Verdict)), zap.String("reason", d.Reason))
		}
		return zhaoheng.RenderDecision(d) + "\n## 昭衡任务状态\n- mission：" + m.ID + "\n", m.ID, "", "", true
	}

	next, nerr := store.NextFrontier(ctx, m.ID)
	if nerr != nil || next == nil {
		// 前沿抽干：没有缺口可打
		guidance := "台账还没有可打的缺口：先给目标建**它自己的模型**（业务形态/自有接口/自有代码或模板/版本线索），" +
			"再提 ≥2 条目标特定假设（引用它自己的 URL/参数/业务对象）并各开一条链。补面只为拿到建模线索，不是本轮目的。"
		if stats.Total > 0 {
			guidance = "台账已覆盖：本轮**只推链**——把已确认线索推到下一个台阶（读数据/绕过/写入/上传/执行/横向），" +
				"或在同台阶连续 3 个变体无增量后带拦截报文关链。不要回去补覆盖率数字。"
		}
		block = "## 昭衡任务状态\n- mission：" + m.ID + "\n- 前沿：**当前为空**\n- 本轮指导：" + guidance + "\n"
		// 首轮/前沿为空时也必须下发完成判据——恰恰是最需要它的一轮（2026-11-05 实测漏发）
		block += "\n" + zhaoheng.RenderDoD(dodProgress)
		return block, m.ID, "", "", false
	}

	fstats2, _ := store.FrontierStats(ctx, m.ID)
	chainsLine := zhaohengChainLine(ctx, db, m.ConversationID)
	block = strings.Join([]string{
		"## 昭衡任务状态（无人值守长任务）",
		"- mission：" + m.ID,
		"- 目标：" + oneLine(m.Objective, 300),
		fmt.Sprintf("- 前沿：pending=%d claimed=%d done=%d", fstats2["pending"], fstats2["claimed"], fstats2["done"]),
		chainsLine,
		fmt.Sprintf("- **本轮建议目标（由台账确定性选出，不是模型自选）**：资产 `%s` 的 `%s` 面（优先级 %d，%s）",
			next.Asset, next.Face, next.Priority, next.Reason),
		"- 面是**地板**不是主线：该资产若有 open 链，先推链（zl_chain_attempt 推台阶），面只在链推不动时补。",
		"- 若现场证据表明这一项确实打不动，可以在回执里说明并 continue，系统会在下一轮换下一项。",
	}, "\n")
	block += "\n" + zhaoheng.RenderDoD(dodProgress)

	if warn := zhaoheng.RenderDecision(d); warn != "" {
		block += "\n" + warn
	} else if d.Verdict == zhaoheng.VerdictContinue && d.Reason != "" {
		block += "\n## 本轮指导\n- " + d.Reason + "\n"
	}

	// 交接档如果有，一并注入（接手方先读交接）
	if h, herr := store.LatestHandoff(ctx, m.ID); herr == nil && h != nil {
		block += "\n" + zhaoheng.RenderHandoff(h)
	}
	return block, m.ID, next.Asset, next.Face, false
}

// zhaohengSettle 一轮结束后更新 frontier 状态并写交接档。
func zhaohengSettle(
	ctx context.Context, db *database.DB, missionID, asset, face string,
	receipt *zhulong.Receipt, runID string, logger *zap.Logger,
) {
	if db == nil || db.DB == nil || missionID == "" {
		return
	}
	store, err := zhaoheng.NewStore(db.DB)
	if err != nil {
		return
	}
	if asset != "" && face != "" && receipt != nil {
		state := "pending"
		reason := "本轮未覆盖"
		switch receipt.Outcome {
		case zhulong.OutcomeDone:
			state = "done"
			reason = "本轮已完成"
		case zhulong.OutcomeBlocked:
			state = "dropped"
			reason = "卡在需要人拍板"
		case zhulong.OutcomeNothing:
			state = "dropped"
			reason = "本轮无增量"
		}
		if serr := store.SettleFrontier(ctx, missionID, asset, face, state, reason); serr != nil && logger != nil {
			logger.Warn("zhaoheng: 更新前沿失败", zap.Error(serr))
		}
	}

	// M1.1：记本轮链进度（供 no-rung-progress 阀判"空转 vs 真进展"）。
	if cid := store.ConversationIDOfMission(ctx, missionID); cid != "" {
		rung, expl := store.ChainProgress(ctx, cid)
		if perr := store.RecordRoundProgress(ctx, missionID, runID, rung, expl); perr != nil && logger != nil {
			logger.Warn("zhaoheng: 记录轮进度失败", zap.Error(perr))
		}
	}

	// 回执 blocked = 需要人拍板 → mission 挂起，下次开跑时红线阀会拒绝自动继续
	if receipt != nil && receipt.Outcome == zhulong.OutcomeBlocked {
		if serr := store.StopMission(ctx, missionID, zhaoheng.MissionPaused, "回执 blocked，等待人工"); serr != nil && logger != nil {
			logger.Warn("zhaoheng: 挂起 mission 失败", zap.Error(serr))
		}
	}

	// 完成判据门：模型报 done 但判据不满足 → 不结 mission，把差距写进交接档，下一轮继续
	if receipt != nil && receipt.Outcome == zhulong.OutcomeDone {
		var since time.Duration
		stats, _ := store.StatsSince(ctx, receiptMissionConversation(store, missionID), time.Time{})
		if m, merr := store.GetMission(ctx, missionID); merr == nil && m != nil && !m.CreatedAt.IsZero() {
			since = time.Since(m.CreatedAt)
		}
		progress := store.EvaluateDoD(ctx, receiptMissionConversation(store, missionID), zhaoheng.DefaultDoD(), stats.Total, since)
		var gap []string
		for _, it := range progress.Unmet() {
			gap = append(gap, fmt.Sprintf("%s: %s（要求 %s）", it.Desc, it.Current, it.Target))
		}
		if len(gap) > 0 {
			if logger != nil {
				logger.Warn("zhaoheng DoD 未满足，拒绝结案",
					zap.String("missionId", missionID), zap.Int("unmet", len(gap)))
			}
			_ = store.StopMission(ctx, missionID, zhaoheng.MissionRunning, "")
			if receipt != nil {
				receipt.NextActions = append(receipt.NextActions, "【判据未满足，继续】"+strings.Join(gap, "；"))
			}
		} else {
			_ = store.StopMission(ctx, missionID, zhaoheng.MissionDone, "完成判据全部满足")
		}
	}

	// 每轮写一份交接档：断了之后接手方只读它就能继续
	if receipt != nil {
		h := &zhaoheng.Handoff{
			MissionID: missionID,
			Done:      []string{receipt.Summary},
			Todo:      receipt.NextActions,
			Evidence:  receipt.EvidenceRefs,
			Note:      "run " + runID + " / outcome=" + string(receipt.Outcome),
		}
		if herr := store.WriteHandoff(ctx, h); herr != nil && logger != nil {
			logger.Warn("zhaoheng: 写交接档失败", zap.Error(herr))
		}
	}
}

// receiptMissionConversation 取 mission 的会话 id（DoD 评估需要）。
func receiptMissionConversation(store *zhaoheng.Store, missionID string) string {
	if m, err := store.GetMission(context.Background(), missionID); err == nil && m != nil {
		return m.ConversationID
	}
	return ""
}

// ============================================================================
// v2（2026-11-05 用户裁定）：面是地板、链是主线
//
// 昭衡原本"每轮从前沿挑一个面"是纯广度驱动，模型很容易把"面扫完了"当进度。
// 现在两点改动，都不改 frontier 表的 SQL、也不改表结构：
//   1) 有 open 链的资产，其前沿项优先级在原值基础上 +50（封顶 100），优先被选中；
//   2) 上下文里直接写出链台账现状（open 几条 / 最深 rung），
//      并明说"面只是地板，有 open 链先推链"。
// ============================================================================

// zhaohengBoostChainAssets 把"有 open 链的资产"的前沿优先级抬到最前。
//
// 幂等：靠 reason 里的标记位判断本轮是否已抬过（BuildFrontier 每轮会重算 reason，
// 所以每轮最多抬一次，不会累加出 150）；只抬 pending 项，不动 claimed/done。
func zhaohengBoostChainAssets(ctx context.Context, db *database.DB, missionID, conversationID string, logger *zap.Logger) int {
	if db == nil || db.DB == nil || missionID == "" || conversationID == "" {
		return 0
	}
	rows, qerr := db.DB.QueryContext(ctx, `
SELECT DISTINCT target_asset FROM zl_chains
WHERE conversation_id=? AND state='open' AND TRIM(target_asset)<>'' LIMIT 20`, conversationID)
	if qerr != nil {
		// zl_chains 可能还没建（链账本灰度启用）：静默降级，不影响昭衡主流程。
		return 0
	}
	var assets []string
	for rows.Next() {
		var a string
		if rows.Scan(&a) == nil && strings.TrimSpace(a) != "" {
			assets = append(assets, strings.TrimSpace(a))
		}
	}
	_ = rows.Close()

	boosted := 0
	for _, asset := range assets {
		res, uerr := db.DB.ExecContext(ctx, `
UPDATE zh_frontier
SET priority = CASE WHEN priority + 50 > 100 THEN 100 ELSE priority + 50 END,
    reason   = reason || ' ｜open 链资产',
    updated_at = ?
WHERE mission_id=? AND asset=? AND state='pending' AND reason NOT LIKE '%open 链资产%'`,
			time.Now().UTC().Format(time.RFC3339Nano), missionID, asset)
		if uerr != nil {
			if logger != nil {
				logger.Warn("zhaoheng: 抬升 open 链资产优先级失败",
					zap.String("asset", asset), zap.Error(uerr))
			}
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			boosted += int(n)
		}
	}
	if boosted > 0 && logger != nil {
		logger.Info("zhaoheng open 链资产已抬到前沿最前",
			zap.String("missionId", missionID), zap.Int("items", boosted), zap.Strings("assets", assets))
	}
	return boosted
}

// zhaohengChainLine 渲染链台账现状（读不到就返回空串，不写噪声行）。
func zhaohengChainLine(ctx context.Context, db *database.DB, conversationID string) string {
	if db == nil || db.DB == nil || conversationID == "" {
		return ""
	}
	cs, err := zhulong.NewChainStore(db.DB)
	if err != nil {
		return ""
	}
	total, open, exploited, depth, specific, serr := cs.Stats(ctx, conversationID)
	if serr != nil || total == 0 {
		return ""
	}
	line := fmt.Sprintf("- 链台账：total=%d open=%d exploited=%d 最深=rung %d/6 锚定目标自身=%d",
		total, open, exploited, depth, specific)
	if open > 0 {
		line += "（**有 open 链：本轮先推链，别去补面**）"
	}
	return line
}
