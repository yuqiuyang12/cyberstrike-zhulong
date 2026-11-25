package loop2

// zhulong_orchestrator.go —— 「烛龙（Zhulong）」闭环模式。
//
// 设计要点（见 ~/data/agent-loop-audit-2026-11-04/LIVELOOP-DESIGN.md）：
//   - 一轮 = 一次短 ReAct，必须在最后一条回复里交结构化回执（outcome/summary/evidence_refs/...）。
//   - 状态外置：目标、轮次、进度、回执、卡片、定时器都落 zhulong_* 表，不依赖聊天历史。
//   - 与既有 5 个模式并存：本文件只做新增，既有模式的分支一行不改。
//
// M0 阶段：复用 RunEinoSingleChatModelAgent 执行单轮（含全部 MCP 工具/中间件/RBAC），
// 外层加「目标与轮次落库 + 回执解析 + 状态收口」。轮预算（步数/时长）在 M1 接入。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/reasoning"
	"cyberstrike-ai/internal/zhaoheng"
	"cyberstrike-ai/internal/zhulong"

	"go.uber.org/zap"
)

const (
	zhulongOrchMode = "zhulong"
	// zhulongAgentName 是烛龙在流式事件/过程面板里显示的代理名，
	// 与单代理的 cyberstrike-eino-single 区分，避免用户误以为跑的是单代理。
	zhulongAgentName = "cyberstrike-zhulong"
	// zhulongPreamble 是本模式的定位说明；回执契约由 zhulong.ReceiptContract 追加在后。
	//
	// 2026-11-05 M1 换脑（用户裁定，spec v2）：老版本写的是"一轮只推进一小段""到点就收口"，
	// 结果模型 6.5 分钟就判 done、4 次闸门 CONTINUE 照样收口、只产 low/medium 信息泄露。
	// 新口径：一轮 = 把一条链推进一个台阶；目标特定假设优先；信息泄露是燃料；done 有硬前置。
	zhulongPreamble = `## 运行模式：烛龙闭环（利用链引擎 · 目标特定）

本轮是**一轮**闭环执行，不是一次长对话，也不是一次"扫面"。我们打的是**专门、特定的资产**：
要按这个目标**自己的**业务 / 代码 / 接口打深，自己出 0day 或变体。

1. **本轮 = 把一条链推进一个台阶**。开工先 zl_chain_list：挑最深的 open 链继续推；
   某个新确认的漏洞还没有链，就 zl_chain_open 开一条（带 target_asset / hypothesis_type）。
2. 台阶：0 确认 → 1 读到敏感数据 → 2 认证绕过 → 3 写入 → 4 上传 → 5 执行 → 6 横向。
3. **本轮开头先写两段**（写在正文里，让人能复核）：
   ①这个目标**自己的模型**：业务形态 / 技术栈 / 自有接口 / 自有代码或模板 / 版本线索——
     只写已落盘证据支持的部分；没有证据就写"未知，本轮先去取"。
   ②**1-3 条目标特定假设**：每条必须引用该目标自己的 URL / 参数 / 业务对象 / 代码行。
     **不许引用通用清单**（"常见 OWASP 十项""该组件有 CVE-XXXX"是索引，不是假设）。
4. **技能优先，KB 补充**：识别出技术面后**先按名 skill 加载 1-2 个技能**再动手
   （签名还原→mobile-and-thick-client / reverse-engineering；加密→crypto-attacks；
   反序列化→deserialization-and-rce；认证/重置→authbypass-authentication-flaws / auth-protocol-and-session；
   未授权/BOLA→api-authorization-and-bola；上传/路径→file-traversal-and-upload；
   注入→sqli-sql-injection / injection-server-side；SSRF→ssrf-server-side-request-forgery）。
   risk_type 只传真实类目，拿不准不传；**KB 连续 2 次空必须回头加载技能，禁止空手继续**。
   技能/KB 命中必须**改造到本目标**（换它的参数名、它的编码、它的业务对象、它的版本分支），**照搬=失败**。
5. 每试一个变体就 zl_chain_attempt 落一行（payload + 原始报文绝对路径 + verdict），别攒到最后写总结。
6. **信息泄露是燃料，不是终点**：每确认一条泄露，立刻回答"它让我下一阶能试什么"并当轮去试
   （栈版本 / 源码路径 / 内网地址 / 密钥 / ID 规律 → 它指向的每个台阶都要试）。
7. 只有「同链同台阶连续 3 个不同变体都无增量」才允许 zl_chain_close(state=blocked)，
   且必须带拦截原始报文路径 + 试过什么（枚举空间）+ 还有什么没试（未覆盖面）。
8. **收口是最后一步**：done 的前置 = open 链为 0、至少一条链锚定到目标自身、
   deliver_gate 首行 GATE=PASS。三者没同时满足就交 continue，把下一台阶写进 next_actions；
   **不要**为了交卷把链随手标 blocked。
9. **禁止用"面还没扫完"当作不做深的原因**：面是地板，链是主线。补面只在"当前链完全推不动"时做，
   做完必须回到链上。
10. **批判思维**：模型/工具/知识库给的结论都先问"它凭什么"，用本目标自己的证据反驳一遍再采信。
11. **证据落盘**：任何结论都要在 evidence_refs 给出可复核的绝对路径或 URL；没有证据的结论按 failed 报。
`
)

var zhulongSchemaOnce struct {
	sync.Once
	err error
}

// zhulongEnabled 报告 zhulong 模式是否启用（默认关闭）。
func zhulongEnabled(ma *config.MultiAgentConfig) bool {
	return ma != nil && ma.Zhulong.Enabled
}

// zhulongStore 惰性建表并返回 store（每进程只建一次）。
func zhulongStore(ctx context.Context, db *database.DB) (*zhulong.Store, error) {
	if db == nil || db.DB == nil {
		return nil, fmt.Errorf("zhulong: 平台 DB 未就绪")
	}
	st, err := zhulong.NewStore(db.DB)
	if err != nil {
		return nil, err
	}
	zhulongSchemaOnce.Do(func() {
		zhulongSchemaOnce.err = st.EnsureSchema(ctx)
	})
	if zhulongSchemaOnce.err != nil {
		return nil, zhulongSchemaOnce.err
	}
	return st, nil
}

// zhulongGoalID 一个会话一条目标链（M2 再支持多目标）。
func zhulongGoalID(conversationID string) string {
	return "zl-goal-" + conversationID
}

func zhulongRunID(conversationID string, now time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", conversationID, now.UnixNano())))
	return "zl-run-" + hex.EncodeToString(h[:])[:16]
}

func zhulongHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ============================================================================
// C2（2026-11-05 M1）：闸门硬门化 —— 注入点
//
// 为什么是注入而不是直接调：判定闸门 collectGateStats/decideGate 在 package app 且未导出，
// 而 internal/app 已经 import internal/loop2。multiagent 反过来 import app 会循环依赖。
// 所以这里只定义**跨包视图**，由 internal/app 在启动时注入（一行赋值）。
//
// 未接线时的行为（lead 裁决 1b，保守）：不判 done —— 没有闸门就等于没有确定性判据，
// 宁可多跑一轮，也不能回到"模型自报 done 就交卷"的老 bug。
// ============================================================================

// ZhulongGateResult 是 deliver_gate 判定的跨包视图（含链台账事实，避免二次改造）。
type ZhulongGateResult struct {
	Verdict string // PASS / CONTINUE / PARTIAL
	Reason  string // 如 open-chains / small-set-needs-100
	Next    string // 给模型看的一句话下一步

	// 链台账事实（由 app 侧 collectGateStats 一并带回；全部为 0 表示它没有采集）
	Chains         int
	OpenChains     int
	ExploitChains  int
	ChainDepth     int
	SpecificChains int
}

// ZhulongGateCheck 由 internal/app 在启动时注入（app → multiagent 单向依赖）。
var ZhulongGateCheck func(ctx context.Context, conversationID, projectID string) ZhulongGateResult

// zhulongCollectChainFacts 采集链台账事实（读不到就降级为全 0，不阻塞本轮）。
//
// 降级语义：全 0 = "一条链都没有"，在 DecideDelivery 里会命中 no-anchored-chain →
// 不许交 done。这是刻意的保守：链账本读不出来时，没有资格宣布交付。
func zhulongCollectChainFacts(ctx context.Context, db *database.DB, conversationID string, logger *zap.Logger) zhulong.ChainFacts {
	if db == nil || db.DB == nil || strings.TrimSpace(conversationID) == "" {
		return zhulong.ChainFacts{}
	}
	cs, err := zhulong.NewChainStore(db.DB)
	if err != nil {
		if logger != nil {
			logger.Warn("zhulong: 链账本不可用，按 0 链处理", zap.Error(err))
		}
		return zhulong.ChainFacts{}
	}
	total, open, exploited, depth, specific, err := cs.Stats(ctx, conversationID)
	if err != nil {
		if logger != nil {
			logger.Warn("zhulong: 读取链台账失败，按 0 链处理",
				zap.String("conversationId", conversationID), zap.Error(err))
		}
		return zhulong.ChainFacts{}
	}
	return zhulong.ChainFacts{
		Total: total, Open: open, Exploited: exploited, Depth: depth, Anchored: specific,
		ConfirmedVulns: zhulongConfirmedVulnCount(ctx, db, conversationID),
	}
}

// zhulongConfirmedVulnCount 数该会话"已确认的中/高危漏洞"（severity ∈ critical/high/medium 且 status<>fixed）。
//
// 用途与 deliver_gate 的 rule 4 防死锁开关同口径：干净目标（0 洞 0 链）不可能有锚定链，
// 硬要求会把它永久卡在 continue。读不到一律 0（降级 = 放宽，不会误拦）。
func zhulongConfirmedVulnCount(ctx context.Context, db *database.DB, conversationID string) int {
	if db == nil || db.DB == nil || strings.TrimSpace(conversationID) == "" {
		return 0
	}
	var n int
	err := db.DB.QueryRowContext(ctx, `
SELECT COUNT(*) FROM vulnerabilities
WHERE conversation_id=? AND severity IN ('critical','high','medium') AND COALESCE(status,'') <> 'fixed'`,
		strings.TrimSpace(conversationID)).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// zhulongTargetAnchors 收集"目标自身"的锚点（资产名/主机），用于判断 next_actions 是否目标特定。
//
// 只看该会话已登记过的东西：覆盖台账里的资产 + open 链的 target_asset。
func zhulongTargetAnchors(ctx context.Context, db *database.DB, conversationID string) []string {
	if db == nil || db.DB == nil || strings.TrimSpace(conversationID) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < 3 {
			return
		}
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	if rows, err := db.DB.QueryContext(ctx, `
SELECT DISTINCT asset FROM asset_coverage WHERE conversation_id=? ORDER BY updated_at DESC LIMIT 8`,
		conversationID); err == nil {
		for rows.Next() {
			var asset string
			if rows.Scan(&asset) == nil {
				add(asset)
			}
		}
		_ = rows.Close()
	}
	if cs, err := zhulong.NewChainStore(db.DB); err == nil {
		if chains, cerr := cs.List(ctx, conversationID, ""); cerr == nil {
			for _, c := range chains {
				add(c.TargetAsset)
			}
		}
	}
	return out
}

// zhulongChainNextActions 把 open 链的"下一步"变成回执 next_actions（目标特定，可执行）。
func zhulongChainNextActions(chains []zhulong.Chain) []string {
	if len(chains) == 0 {
		return nil
	}
	// List 已按 rung DESC 排序：第一条就是最深的那条。
	out := make([]string, 0, 2)
	deepest := chains[0]
	hyp := strings.TrimSpace(deepest.Hypothesis)
	if hyp == "" {
		hyp = strings.TrimSpace(deepest.Title)
	}
	line := fmt.Sprintf("推进链 %s（rung=%d→%d）：%s", deepest.ID, deepest.Rung, deepest.Rung+1, oneLine(hyp, 160))
	if a := strings.TrimSpace(deepest.TargetAsset); a != "" {
		line += "（资产 " + a + "）"
	}
	out = append(out, line)
	if len(chains) > 1 {
		ids := make([]string, 0, len(chains)-1)
		for _, c := range chains[1:] {
			ids = append(ids, c.ID)
		}
		out = append(out, fmt.Sprintf("另有 %d 条 open 链待推进：%s", len(ids), strings.Join(ids, ", ")))
	}
	return out
}

// zhulongApplyDeliveryGate 是收口前的**确定性复核**（C2 核心）：
// 解析回执 → 采集链台账事实与闸门结论 → DecideDelivery 定 done 还是 continue。
//
// 返回 receipt=nil 表示"回执本身不合法/不存在"，交回既有 finalize 按失败收口。
func zhulongApplyDeliveryGate(
	ctx context.Context,
	db *database.DB,
	projectID, conversationID string,
	res *RunResult,
	logger *zap.Logger,
	progress func(eventType, message string, data interface{}),
	elapsedMin, minRoundMin float64,
) (*zhulong.Receipt, []zhulong.DeliveryReason) {
	text := ""
	if res != nil {
		text = res.Response
	}
	receipt, perr := zhulong.ParseReceipt(text)
	if perr != nil || receipt == nil {
		return nil, nil
	}
	// 非 done 不必复核：nothing/blocked/failed/continue 原样放行。
	if receipt.Outcome != zhulong.OutcomeDone {
		return receipt, nil
	}

	facts := zhulongCollectChainFacts(ctx, db, conversationID, logger)
	gateVerdict, gateReason, gateNext := "", "", ""
	if ZhulongGateCheck == nil {
		if logger != nil {
			logger.Warn("zhulong: 闸门未接线（multiagent.ZhulongGateCheck=nil），本轮不判 done",
				zap.String("conversationId", conversationID))
		}
		if progress != nil {
			progress("zhulong_gate_unwired", "烛龙闭环：确定性闸门未接线，本轮不判 done（保守收 continue）", map[string]interface{}{
				"conversationId": conversationID,
				"openChains":     facts.Open,
				"anchoredChains": facts.Anchored,
			})
		}
	} else {
		g := ZhulongGateCheck(ctx, conversationID, projectID)
		gateVerdict, gateReason, gateNext = g.Verdict, g.Reason, g.Next
		if g.Chains > 0 || g.OpenChains > 0 || g.SpecificChains > 0 {
			// 闸门侧采到了链事实就以它为准（同一轮的同一份台账，口径单点）。
			facts = zhulong.ChainFacts{
				Total:          g.Chains,
				Open:           g.OpenChains,
				Exploited:      g.ExploitChains,
				Depth:          g.ChainDepth,
				Anchored:       g.SpecificChains,
				ConfirmedVulns: facts.ConfirmedVulns,
			}
		}
	}

	anchors := zhulongTargetAnchors(ctx, db, conversationID)
	outcome, reasons := zhulong.DecideDelivery(receipt, facts, gateVerdict, gateReason, gateNext, anchors,
		zhulong.RoundWindow{ElapsedMin: elapsedMin, MinMin: minRoundMin})
	// R3a：done 回执的证据引用必须可复核（本地路径真实存在）——仅形状合法不算证据。
	if outcome == zhulong.OutcomeDone && len(reasons) == 0 {
		if unresolved := zhulong.UnresolvableEvidenceRefs(receipt.EvidenceRefs); len(unresolved) > 0 {
			outcome = zhulong.OutcomeContinue
			reasons = append(reasons, zhulong.DeliveryReason{
				Code: "evidence-unverifiable",
				Text: "done 回执的证据引用无法复核（本地绝对路径不存在/不可读）：" + strings.Join(unresolved, "、") +
					" —— 把真实落盘的 req/resp/截图/日志绝对路径逐条写进 evidence_refs，或改交 continue 补齐证据",
			})
		}
	}
	if len(reasons) == 0 {
		return receipt, nil
	}

	// 打回：改判 continue，把"为什么不能交卷 + 下一台阶"塞进 next_actions。
	receipt.Outcome = outcome
	var next []string
	for _, r := range reasons {
		next = append(next, "【不能交卷·"+r.Code+"】"+r.Text)
	}
	if db != nil && db.DB != nil {
		if cs, cerr := zhulong.NewChainStore(db.DB); cerr == nil {
			if chains, lerr := cs.List(ctx, conversationID, zhulong.ChainOpen); lerr == nil {
				next = append(next, zhulongChainNextActions(chains)...)
			}
		}
	}
	receipt.NextActions = append(next, receipt.NextActions...)
	receipt.Summary = oneLine(receipt.Summary, 3600) + " ｜打回: " + deliveryReasonCodes(reasons)

	if progress != nil {
		progress("zhulong_gate_continue", "烛龙闭环：done 被确定性判据打回，本轮改判 continue（不交卷）", map[string]interface{}{
			"conversationId": conversationID,
			"gateVerdict":    gateVerdict,
			"gateReason":     gateReason,
			"codes":          deliveryReasonCodes(reasons),
			"openChains":     facts.Open,
			"anchoredChains": facts.Anchored,
			"chainDepth":     facts.Depth,
		})
	}
	if logger != nil {
		logger.Info("zhulong done 被打回 continue",
			zap.String("conversationId", conversationID),
			zap.String("gateVerdict", gateVerdict),
			zap.String("gateReason", gateReason),
			zap.String("codes", deliveryReasonCodes(reasons)),
			zap.Int("openChains", facts.Open),
			zap.Int("anchoredChains", facts.Anchored))
	}
	return receipt, reasons
}

// deliveryReasonCodes 把打回理由压成一行（写进 summary / 日志）。
func deliveryReasonCodes(reasons []zhulong.DeliveryReason) string {
	if len(reasons) == 0 {
		return ""
	}
	codes := make([]string, 0, len(reasons))
	for _, r := range reasons {
		codes = append(codes, r.Code)
	}
	return strings.Join(codes, ",")
}

// runZhulongAgent 执行一轮烛龙闭环。
//
// 返回值与 RunEinoSingleChatModelAgent 一致，便于 handler 原样使用；
// 回执缺失/非法不会吞掉本轮文本，而是把 run 标为 failed 并广播 zhulong_receipt_missing。
func runZhulongAgent(
	ctx context.Context,
	appCfg *config.Config,
	ma *config.MultiAgentConfig,
	ag *agent.Agent,
	db *database.DB,
	logger *zap.Logger,
	conversationID string,
	projectID string,
	userMessage string,
	history []agent.ChatMessage,
	roleTools []string,
	progress func(eventType, message string, data interface{}),
	reasoningClient *reasoning.ClientIntent,
	systemPromptExtra string,
	profile string,
) (*RunResult, error) {
	if profile == zhaohengOrchMode {
		if ma == nil || !ma.Zhaoheng.Enabled {
			return nil, fmt.Errorf("zhaoheng（昭衡）模式已于 2026-11-06 退役，请改用烛龙（eino2.0）模式")
		}
	} else if !zhulongEnabled(ma) {
		return nil, fmt.Errorf("zhulong（烛龙）模式未启用：请在 config.yaml 的 multi_agent.zhulong.enabled 置为 true")
	}
	if strings.TrimSpace(conversationID) == "" {
		return nil, fmt.Errorf("zhulong: conversationID 为空")
	}

	store, err := zhulongStore(ctx, db)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	goalID := zhulongGoalID(conversationID)
	objective := strings.TrimSpace(userMessage)
	if objective == "" {
		objective = "（空目标）"
	}
	// R3b（2026-11-06）：一次 GetGoal 取上一轮目标与约束；"继续"类短消息不得覆盖持久目标
	// （auto-continue/hold 场景把目标写成"继续" = 目标漂移，对齐 ARTEX goals.go 的目标保持语义）。
	var prevObjective string
	var prevConstraints []string
	if prevGoal, gerr := store.GetGoal(ctx, goalID); gerr == nil && prevGoal != nil {
		prevObjective, prevConstraints = prevGoal.Objective, prevGoal.Constraints
	}
	objective = zhulong.ObjectiveForNextRound(prevObjective, objective)
	// R3a：本次任务操作边界——从目标里抽显式范围/禁止语句，与上一轮已存约束合并。
	curBoundary := zhulong.ParseGoalConstraints(objective)
	allow, deny := zhulong.SplitConstraintLines(zhulong.MergeConstraintLines(prevConstraints, curBoundary.Lines()))
	boundary := zhulong.BoundaryConstraints{Allow: allow, Deny: deny}
	// 目标按会话维护：首轮写入，后续轮以最新用户输入刷新 objective（约束由 R3a 边界解析填充）。
	if gerr := store.SaveGoal(ctx, &zhulong.Goal{
		ID:             goalID,
		ConversationID: conversationID,
		Objective:      objective,
		Constraints:    boundary.Lines(),
		CreatedAt:      now,
	}); gerr != nil && logger != nil {
		logger.Warn("zhulong: 保存目标失败", zap.Error(gerr))
	}

	run := &zhulong.Run{
		ID:             zhulongRunID(conversationID, now),
		ConversationID: conversationID,
		GoalID:         goalID,
		State:          zhulong.StateQueued,
		StepBudget:     ma.Zhulong.StepBudgetEffective(),
		MinuteBudget:   ma.Zhulong.MinuteBudgetEffective(),
		CreatedAt:      now,
	}
	if cerr := store.CreateRun(ctx, run); cerr != nil {
		return nil, cerr
	}
	// 契约①（P1-A 接线，2026-11-06）：同 (conversation, goal) 只允许一条 running。
	// 抢占失败（目标已有 running 轮次）→ **明确拒绝**：发一条 failed 语义 progress + 正常返回
	// （不是 500，也别静默继续双跑），并把自己刚建的 queued 行回滚掉——被拒的请求不产生 run 行。
	if serr := store.AcquireGoalSlot(ctx, run.ID); serr != nil {
		if dropErr := store.DropQueuedRun(ctx, run.ID); dropErr != nil && logger != nil {
			logger.Warn("zhulong: 回滚被拒 run 行失败", zap.String("runId", run.ID), zap.Error(dropErr))
		}
		if errors.Is(serr, zhulong.ErrGoalBusy) {
			busyMsg := "烛龙闭环：本轮被拒——该目标已有 running 轮次（不排队、不双跑，避免两轮同时打同一目标）；等上一轮收口后再触发"
			if logger != nil {
				logger.Warn("zhulong: 目标槽位被占，拒绝开轮",
					zap.String("conversationId", conversationID), zap.String("goalId", goalID), zap.String("runId", run.ID))
			}
			if progress != nil {
				progress("zhulong_run_end", busyMsg, map[string]interface{}{
					"runId":      run.ID,
					"goalId":     goalID,
					"outcome":    "failed",
					"reason":     "goal_busy",
					"sideEffect": "none",
				})
			}
			return &RunResult{Response: busyMsg, CompletionReason: "zhulong:goal_busy"}, nil
		}
		return nil, serr
	}
	// C4：每个工具调用都落一行 zhulong_steps（不再"只在 settlement 写"，那会本轮 0 行）。
	// recorder 包一层 progress，工具事件进来时先写库再原样转发；写库失败不阻塞本轮。
	recorder := zhulong.NewStepRecorder(ctx, store, run.ID, logger)
	progress = recorder.WrapProgress(progress)
	// C5（2026-11-06 P0）：租约心跳兜底。StepRecorder 只在工具事件上打心跳，
	// 模型长时间思考/进程忙时没有事件 → seen_at 停滞 → lease 把 60 分钟的轮判成 unknown。
	// 这里起 45s ticker 覆盖「执行 + 收尾」全程（defer 在函数返回时停，stop 幂等）。
	heartbeatStop := zhulong.StartHeartbeat(context.Background(), store, run.ID, zhulong.DefaultHeartbeatInterval, logger)
	defer heartbeatStop()
	if progress != nil {
		progress("zhulong_run_start", fmt.Sprintf("烛龙闭环：本轮开始（预算 %d 步 / %d 分钟）", run.StepBudget, run.MinuteBudget), map[string]interface{}{
			"runId":          run.ID,
			"goalId":         goalID,
			"conversationId": conversationID,
			"stepBudget":     run.StepBudget,
			"minuteBudget":   run.MinuteBudget,
		})
	}

	// 状态驱动上下文：回注上一轮结论、未完成待办、最近步骤与证据，
	// 让目标与待办在聊天历史被压缩后依然在场（对齐 Claude Code「压缩后从磁盘回注」）。
	stateBlock := buildZhulongStateBlock(ctx, store, goalID, objective, run, logger)
	missionID, missionAsset, missionFace := "", "", ""
	if profile == zhaohengOrchMode {
		limits := zhaoheng.DefaultGuardLimits()
		if ma != nil && ma.Zhaoheng.MaxRoundsEffective() > 0 {
			limits.MaxRounds = ma.Zhaoheng.MaxRoundsEffective()
		}
		dod := zhaoheng.DefaultDoD()
		if ma != nil {
			dod.MaxRounds = ma.Zhaoheng.MaxRoundsEffective()
			dod.MaxHours = ma.Zhaoheng.MaxHoursEffective()
		}
		zblock, mid, asset, face, stop := zhaohengPrepare(ctx, db, conversationID, objective, limits, dod, logger)
		if zblock != "" {
			stateBlock = zblock + "\n" + stateBlock
			missionID, missionAsset, missionFace = mid, asset, face
		}
		// 安全阀判定"停止/挂起"时**一次模型调用都不发**：cron 驱动的自动排轮会反复打到这里，
		// 但每次都是零 token 直接返回，避免"跑不动还一直烧钱"。
		if stop {
			res := &RunResult{Response: zblock, CompletionReason: "zhaoheng:valve_stopped"}
			fin := finalizeZhulongRun(ctx, store, run, res, nil, progress, logger)
			zhaohengSettle(ctx, db, missionID, missionAsset, missionFace, fin, run.ID, logger)
			return res, nil
		}
	}
	extraParts := make([]string, 0, 6)
	if blk := boundary.Block(); blk != "" {
		extraParts = append(extraParts, blk) // R3a：本次任务操作边界（最高优先级）
	}
	extraParts = append(extraParts,
		zhulongPreamble,
		zhulong.ScopeBoundary, // 写操作边界：只保留四条底线（2026-11-04 用户裁定；昭衡复用同一节）
		stateBlock,
		zhulong.ReceiptContract,
		systemPromptExtra,
	)
	extra := strings.TrimSpace(strings.Join(extraParts, "\n\n"))

	// 轮预算：步数通过 maxIterOverride 强制，时长通过带 deadline 的 ctx 强制。
	// 最短轮时长（用户 2026-11-05 裁定：烛龙一轮至少 30 分钟、最多 60 分钟）。
	// 只作为"提前收口的拦板"：真做完（GATE=PASS + open 链=0 + 锚定链≥1）仍可提前收口。
	minRoundMin := 30
	if ma != nil {
		minRoundMin = ma.Zhulong.MinMinuteBudgetEffective()
	}

	runCtx := ctx
	if run.MinuteBudget > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(run.MinuteBudget)*time.Minute)
		defer cancel()
	}

	// P3 前置（2026-11-06，task-10）：把「模型自主 continue」纳入最短轮。
	// hold 关闭（默认）时循环体只执行一次，等价于原实现（一次 inner run + settle），逐字节一致。
	// 开启时：continue 且 elapsed < min_minute_budget → **同一 run 内续跑一段**（不新开 run、不改状态机）；
	// 触顶/取消/blocked/failed/坏回执一律不 hold（不逼模型空转）。
	holdEnabled := ma != nil && ma.Zhulong.HoldContinueUntilMin
	holdMin := time.Duration(minRoundMin) * time.Minute
	holdRound := 0
	const maxHoldRounds = 4 // 防模型反复交 continue 打转；每段 inner run 自身仍受 runCtx/步预算夹住

	var res *RunResult
	var runErr error
	for {
		res, runErr = runEinoSingleChatModelAgentNamed(
			runCtx, appCfg, ma, ag, db, logger,
			conversationID, projectID, userMessage, history, roleTools,
			progress, reasoningClient, extra, zhulongAgentName, zhulongOrchMode,
			run.StepBudget, nil,
		)

		// 预算耗尽（步数触顶 / 时长到点）→ 进收尾阶段，压出一份合法回执，避免烂尾。
		if settled, ok := settleZhulongRun(runCtx, ctx, appCfg, ma, ag, db, logger,
			conversationID, projectID, objective, history, progress, reasoningClient,
			res, runErr, store, run, recorder); ok {
			res, runErr = settled, nil
			break
		}

		hold, why := holdContinuePlan(holdEnabled, receiptOfRunResult(res), time.Since(now), holdMin,
			recorder.NextStepNo(), run.StepBudget, runCtx.Err(), runErr, holdRound, maxHoldRounds)
		if !hold {
			if holdEnabled && progress != nil && why != "disabled" && why != "outcome" {
				progress("zhulong_hold_skip", "烛龙闭环：continue hold 未触发", map[string]interface{}{
					"runId": run.ID, "reason": why, "elapsedMin": time.Since(now).Minutes(),
				})
			}
			break
		}
		holdRound++
		if progress != nil {
			progress("zhulong_hold_continue", "烛龙闭环：未到最短轮，continue 被 hold 回本轮继续推进（不新开 run）",
				map[string]interface{}{
					"runId":       run.ID,
					"round":       holdRound,
					"elapsedMin":  time.Since(now).Minutes(),
					"minRoundMin": minRoundMin,
					"stepsUsed":   recorder.NextStepNo(),
				})
		}
		if logger != nil {
			logger.Info("zhulong hold continue",
				zap.String("runId", run.ID), zap.Int("round", holdRound),
				zap.Float64("elapsedMin", time.Since(now).Minutes()), zap.Int("minRoundMin", minRoundMin))
		}
		// 同一 run 续跑：历史带上本轮正文（让模型看见自己刚写了什么），user 段换成续跑提示。
		history = append(append([]agent.ChatMessage{}, history...),
			agent.ChatMessage{Role: "assistant", Content: res.Response})
		userMessage = buildHoldContinuePrompt(receiptOfRunResult(res), holdMin-time.Since(now))
	}

	_ = ctx
	// C2：收口前的确定性复核（不看模型自报）。done 必须过链台账 + 闸门，
	// 否则改判 continue 并由自动续轮接着排下一轮。
	// 执行本身失败（runErr != nil）时不做交付复核：失败域隔离，交给 finalize 按 failed 收口。
	var gateReceipt *zhulong.Receipt
	var blockedReasons []zhulong.DeliveryReason
	if runErr == nil {
		gateReceipt, blockedReasons = zhulongApplyDeliveryGate(ctx, db, projectID, conversationID, res, logger, progress,
			time.Since(now).Minutes(), float64(minRoundMin))
	}
	receipt := finalizeZhulongRunWithReceipt(ctx, store, run, res, runErr, gateReceipt, blockedReasons, progress, logger)
	// 无人值守最怕"打完一夜不知道干了什么"：每轮把结论追加到 mission 报告。
	reportKey := goalID
	if missionID != "" {
		reportKey = missionID
	}
	appendMissionReport(ctx, appCfg, store, reportKey, objective, run, receipt, logger)
	if profile == zhaohengOrchMode {
		zhaohengSettle(ctx, db, missionID, missionAsset, missionFace, receipt, run.ID, logger)
	}
	return res, runErr
}

// settleZhulongRun 在预算耗尽时跑一次"只出回执、不调工具"的收尾调用。
// 返回 ok=true 表示收尾成功（res 已替换为收尾输出，runErr 应忽略）。
func settleZhulongRun(
	runCtx, parentCtx context.Context,
	appCfg *config.Config, ma *config.MultiAgentConfig, ag *agent.Agent, db *database.DB,
	logger *zap.Logger, conversationID, projectID, objective string, history []agent.ChatMessage,
	progress func(eventType, message string, data interface{}), reasoningClient *reasoning.ClientIntent,
	res *RunResult, runErr error, store *zhulong.Store, run *zhulong.Run, recorder *zhulong.StepRecorder,
) (*RunResult, bool) {
	// 触顶判定抽成纯函数（P1 契约⑥，见 zhulong_budget.go）：三种来源——Eino 迭代上限、
	// runErr 链里的 DeadlineExceeded、runCtx 的 cause 是 DeadlineExceeded。行为与改造前逐字等价。
	exhausted := isZhulongBudgetExhausted(runErr, runCtx)
	if !exhausted {
		return nil, false
	}

	lastText := ""
	if res != nil {
		lastText = res.Response
	}
	// 把本轮真实工具输出喂给收尾，否则它只能看到助手自述，会一律判 failed。
	var tools []zhulong.ToolSnippet
	if res != nil {
		tools = zhulong.ExtractToolSnippets(res.LastAgentTraceInput, 8, 1200)
	}
	digest := zhulong.BuildSettlementDigest(objective, lastText, nil, tools, 12000)
	if progress != nil {
		progress("zhulong_settlement", "烛龙闭环：本轮预算耗尽，进入收尾（不再调用工具，只交回执）", map[string]interface{}{
			"runId":        run.ID,
			"stepBudget":   run.StepBudget,
			"minuteBudget": run.MinuteBudget,
		})
	}

	// 收尾用独立的 ctx：主 ctx 可能已被 deadline 取消。
	sctx, cancel := context.WithTimeout(context.WithoutCancel(parentCtx), 2*time.Minute)
	defer cancel()

	settleExtra := strings.TrimSpace(zhulong.SettlementPrompt + "\n\n" + zhulong.ReceiptContract)
	sres, serr := runEinoSingleChatModelAgentNamed(
		sctx, appCfg, ma, ag, db, logger,
		conversationID, projectID, digest, nil, roleToolsForSettlement(),
		progress, reasoningClient, settleExtra, zhulongAgentName+"-settle", zhulongOrchMode,
		2, []string{}, // 空白名单 = 零工具：收尾阶段禁止任何副作用
	)
	if serr != nil || sres == nil {
		if logger != nil {
			logger.Warn("zhulong 收尾调用失败，按失败收口",
				zap.String("runId", run.ID), zap.Error(serr))
		}
		return nil, false
	}
	if _, perr := zhulong.ParseReceipt(sres.Response); perr != nil {
		if logger != nil {
			logger.Warn("zhulong 收尾未产合法回执，按失败收口",
				zap.String("runId", run.ID), zap.Error(perr))
		}
		return nil, false
	}
	// 收尾输出合并进本轮结果（保留主轮正文，避免用户丢失已产出的内容）。
	if res != nil && strings.TrimSpace(lastText) != "" {
		sres.Response = strings.TrimSpace(lastText) + "\n\n---\n\n（预算耗尽后收尾）\n\n" + sres.Response
	}
	// 收尾也走同一个 recorder：不再手工抢一个 999 号（否则会和并行工具步骤撞号）。
	if recorder != nil {
		recorder.Record("settlement", "预算耗尽后的收尾调用（零工具）", "", "ok")
	} else {
		_ = store.AppendStep(sctx, &zhulong.Step{
			RunID: run.ID, StepNo: 999, ToolName: "settlement",
			Summary: "预算耗尽后的收尾调用（零工具）",
		})
	}
	return sres, true
}

// roleToolsForSettlement 返回空切片切片而非 nil：走白名单过滤路径（零工具）。
func roleToolsForSettlement() []string { return []string{} }

// buildZhulongStateBlock 组装本轮起始状态块（目标/约束/上一轮结论/待办/最近步骤/证据）。
// 任何一段读失败都降级为"没有该段"，不让状态读取阻塞本轮执行。
func buildZhulongStateBlock(
	ctx context.Context, store *zhulong.Store, goalID, objective string, run *zhulong.Run, logger *zap.Logger,
) string {
	in := zhulong.StateBlockInput{Objective: objective, Budget: *run}

	if g, gerr := store.GetGoal(ctx, goalID); gerr == nil && g != nil {
		in.Constraints = g.Constraints
	}

	if prev, perr := store.LatestRunForGoal(ctx, goalID); perr == nil && prev != nil && prev.ID != run.ID {
		in.LastSummary = prev.Summary
		if prev.ReceiptJSON != "" {
			if r, rerr := zhulong.ParseReceipt(prev.ReceiptJSON); rerr == nil && r != nil {
				in.LastOutcome = string(r.Outcome)
				in.EvidenceRefs = r.EvidenceRefs
			}
		}
		if steps, serr := store.RecentSteps(ctx, prev.ID, 12); serr == nil {
			in.RecentSteps = steps
		}
	}
	if todos, terr := store.ListOpenTodos(ctx, goalID, zhulong.MaxOpenTodos); terr == nil {
		in.Todos = todos
	}
	if logger != nil {
		logger.Info("zhulong state block built",
			zap.String("runId", run.ID),
			zap.Int("todos", len(in.Todos)),
			zap.Int("steps", len(in.RecentSteps)),
			zap.Int("evidence", len(in.EvidenceRefs)),
			zap.String("lastOutcome", in.LastOutcome),
		)
	}
	return zhulong.BuildStateBlock(in, 6000)
}

// zhulongStateBlock 把本轮的目标与预算以稳定格式注入，压缩后仍可读。
func zhulongStateBlock(objective string, run *zhulong.Run) string {
	var sb strings.Builder
	sb.WriteString("## 本轮状态（来自平台状态表，不是聊天历史）\n")
	sb.WriteString("- 目标：" + oneLine(objective, 500) + "\n")
	sb.WriteString(fmt.Sprintf("- 轮次：run=%s attempt=%d 预算=%d 步/%d 分钟\n", run.ID, run.Attempt, run.StepBudget, run.MinuteBudget))
	sb.WriteString("- 结束时必须交回执（见下），没有回执本轮判失败。\n")
	return sb.String()
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > max {
		r := []rune(s)
		return string(r[:max]) + "…"
	}
	return s
}

// finalizeZhulongRun 解析回执并把本轮收口（缺失/非法也收口，不吞结果）。
func finalizeZhulongRun(
	ctx context.Context,
	store *zhulong.Store,
	run *zhulong.Run,
	res *RunResult,
	runErr error,
	progress func(eventType, message string, data interface{}),
	logger *zap.Logger,
) *zhulong.Receipt {
	return finalizeZhulongRunWithReceipt(ctx, store, run, res, runErr, nil, nil, progress, logger)
}

// finalizeZhulongRunWithReceipt 是 finalize 的实现体。
//
// override/reasons 来自 zhulongApplyDeliveryGate（C2 的确定性复核）：
//   - override != nil 时**不再重复解析**模型文本，直接用复核后的回执收口（同一次解析，单一真相）；
//   - reasons 非空 = 本轮被打回（done → continue），收口时把理由落到 run.summary 便于事后审计。
func finalizeZhulongRunWithReceipt(
	ctx context.Context,
	store *zhulong.Store,
	run *zhulong.Run,
	res *RunResult,
	runErr error,
	override *zhulong.Receipt,
	reasons []zhulong.DeliveryReason,
	progress func(eventType, message string, data interface{}),
	logger *zap.Logger,
) *zhulong.Receipt {
	text := ""
	if res != nil {
		text = res.Response
	}

	// 收口必须用"不可取消"的 ctx：用户点停止时 ctx 已被取消，沿用原 ctx 写库会静默失败，
	// run 就永远卡在 running（2026-11-04 cnvd 会话实证：4 轮里 2 轮卡死）。
	fctx := context.WithoutCancel(ctx)

	// 执行本身失败：标 failed / cancelled（失败域隔离：不产生任何副作用）。
	if runErr != nil {
		state := zhulong.StateFailed
		outcome := string(zhulong.OutcomeFailed)
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			state = zhulong.StateCancelled
			outcome = "cancelled"
		}
		if ferr := store.FinishRun(fctx, run.ID, state, "", oneLine(runErr.Error(), 500), ""); ferr != nil && logger != nil {
			logger.Warn("zhulong: 收口写库失败", zap.String("runId", run.ID), zap.String("state", string(state)), zap.Error(ferr))
		}
		if progress != nil {
			label := "执行失败"
			if state == zhulong.StateCancelled {
				label = "被取消"
			}
			progress("zhulong_run_end", "烛龙闭环：本轮"+label+"，已收口", map[string]interface{}{
				"runId":      run.ID,
				"outcome":    outcome,
				"error":      oneLine(runErr.Error(), 300),
				"sideEffect": "none",
			})
		}
		return nil
	}

	var receipt *zhulong.Receipt
	var perr error
	if override != nil {
		receipt = override
	} else {
		receipt, perr = zhulong.ParseReceipt(text)
	}
	if perr != nil || receipt == nil {
		if perr == nil {
			perr = fmt.Errorf("%w: 回执为空", zhulong.ErrInvalidReceipt)
		}
		if ferr := store.FinishRun(fctx, run.ID, zhulong.StateFailed, "", "回执缺失或非法: "+oneLine(perr.Error(), 300), ""); ferr != nil && logger != nil {
			logger.Warn("zhulong: 收口写库失败", zap.String("runId", run.ID), zap.Error(ferr))
		}
		if res != nil {
			res.CompletionReason = "zhulong_receipt_missing"
		}
		if progress != nil {
			progress("zhulong_receipt_missing", "烛龙闭环：本轮未交合法回执，已按失败收口（不会重复执行业务）", map[string]interface{}{
				"runId":  run.ID,
				"reason": oneLine(perr.Error(), 300),
			})
		}
		return nil
	}

	state := zhulong.StateFailed
	switch receipt.Outcome {
	case zhulong.OutcomeDone:
		state = zhulong.StateDone
	case zhulong.OutcomeNothing:
		state = zhulong.StateNothing
	case zhulong.OutcomeBlocked:
		state = zhulong.StateBlocked
	case zhulong.OutcomeFailed:
		state = zhulong.StateFailed
	case zhulong.OutcomeContinue:
		// 没交卷也不是失败：自动续轮会接着排下一轮（终态里刻意不含 continue_pending）。
		state = zhulong.StateContinuePending
	}

	// 回执里的 next_actions 落成跨轮待办：下一轮开头回注（状态驱动上下文的核心闭环）。
	if len(receipt.NextActions) > 0 {
		if n, terr := store.AddTodos(fctx, run.GoalID, run.ID, receipt.NextActions); terr != nil && logger != nil {
			logger.Warn("zhulong: 待办落库失败", zap.String("runId", run.ID), zap.Error(terr))
		} else if n > 0 && logger != nil {
			logger.Info("zhulong todos added", zap.String("runId", run.ID), zap.Int("added", n))
		}
	}
	// 台账修剪：open 待办只保留最新 MaxOpenTodos 条，其余标 stale。
	// 防的是"continue 轮次措辞不同 → todo 只进不出"，回注块被历史噪声挤满。
	if n, perr := store.PruneOpenTodos(fctx, run.GoalID, zhulong.MaxOpenTodos); perr != nil {
		if logger != nil {
			logger.Warn("zhulong: 修剪待办失败", zap.String("runId", run.ID), zap.Error(perr))
		}
	} else if n > 0 && logger != nil {
		logger.Info("zhulong todos pruned", zap.String("runId", run.ID), zap.Int("pruned", n))
	}

	// C4：交付（done）时把该 goal 仍未结清的 open 待办标 stale。
	// 不标 done（那是造假：这些事并没做完），标 stale = 随本轮交付一起作废，不再回注。
	if receipt.Outcome == zhulong.OutcomeDone {
		if n, serr := store.MarkOpenTodosStale(fctx, run.GoalID); serr != nil {
			if logger != nil {
				logger.Warn("zhulong: 结清待办失败", zap.String("runId", run.ID), zap.Error(serr))
			}
		} else if n > 0 {
			receipt.NextActions = append(receipt.NextActions, fmt.Sprintf("【已结清】%d 条未结待办随本轮交付标 stale（未真的做完，不算完成）", n))
			if progress != nil {
				progress("zhulong_todos_stale", fmt.Sprintf("烛龙闭环：本轮交付，%d 条 open 待办标 stale", n), map[string]interface{}{
					"runId":  run.ID,
					"goalId": run.GoalID,
					"count":  n,
				})
			}
			if logger != nil {
				logger.Info("zhulong todos stale", zap.String("runId", run.ID), zap.Int("count", n))
			}
		}
	}

	rj, _ := zhulong.MarshalReceipt(receipt)
	if ferr := store.FinishRun(fctx, run.ID, state, rj, receipt.Summary, zhulongHash(rj)); ferr != nil && logger != nil {
		logger.Warn("zhulong: 收口写库失败", zap.String("runId", run.ID), zap.String("state", string(state)), zap.Error(ferr))
	}
	// 被打回的一轮：把理由写进 run（state=continue_pending + summary 追加"打回: code1,code2"）。
	if receipt.Outcome == zhulong.OutcomeContinue {
		reason := ""
		if len(reasons) > 0 {
			reason = deliveryReasonCodes(reasons)
		}
		if merr := store.MarkContinuePending(fctx, run.ID, reason); merr != nil && logger != nil {
			logger.Warn("zhulong: 标记 continue_pending 失败", zap.String("runId", run.ID), zap.Error(merr))
		}
	}
	if res != nil {
		res.CompletionReason = zhulongOrchMode + ":" + string(receipt.Outcome)
	}
	if progress != nil {
		progress("zhulong_receipt", fmt.Sprintf("烛龙闭环：本轮收口 outcome=%s", receipt.Outcome), map[string]interface{}{
			"runId":        run.ID,
			"goalId":       run.GoalID,
			"outcome":      string(receipt.Outcome),
			"summary":      receipt.Summary,
			"evidenceRefs": receipt.EvidenceRefs,
			"asks":         receipt.Asks,
			"nextActions":  receipt.NextActions,
		})
	}
	if logger != nil {
		logger.Info("zhulong run finished",
			zap.String("runId", run.ID),
			zap.String("conversationId", run.ConversationID),
			zap.String("outcome", string(receipt.Outcome)),
			zap.Int("evidenceRefs", len(receipt.EvidenceRefs)),
			zap.Int("asks", len(receipt.Asks)),
		)
	}
	return receipt
}

// appendMissionReport 把一轮结论追加到 <workspace>/zh-missions/<key>/MISSION.md。
// 只追加不改写；写失败仅记日志，不影响本轮结果（报告是交付物，不是执行前提）。
func appendMissionReport(
	ctx context.Context, appCfg *config.Config, store *zhulong.Store,
	key, objective string, run *zhulong.Run, receipt *zhulong.Receipt, logger *zap.Logger,
) {
	if store == nil || key == "" || receipt == nil {
		return
	}
	seq := 1
	if n, err := store.CountRuns(ctx, run.ConversationID); err == nil && n > 0 {
		seq = n
	}
	baseDir := ""
	if appCfg != nil {
		baseDir = appCfg.Agent.WorkspaceRootDir
	}
	path, err := zhaoheng.AppendRoundReport(baseDir, key, objective, zhaoheng.RoundReport{
		Seq:         seq,
		Time:        time.Now(),
		RunID:       run.ID,
		Outcome:     string(receipt.Outcome),
		Summary:     receipt.Summary,
		Evidence:    receipt.EvidenceRefs,
		NextActions: receipt.NextActions,
	})
	if err != nil {
		if logger != nil {
			logger.Warn("zhulong: 写 mission 报告失败", zap.String("key", key), zap.Error(err))
		}
		return
	}
	if logger != nil {
		logger.Info("zhulong mission report appended", zap.String("path", path), zap.Int("seq", seq))
	}
}

// ============================================================================
// P3 前置（task-10）：continue 纳入最短轮
// ============================================================================

// holdContinuePlan 决定「本轮是否 hold 回同一 run 再跑一段」。
//
// 纯函数（无 IO），把优先级写死在一处，便于单测穷举与事后复盘：
//
//	hold 关 → disabled（逐字节回归锚点）
//	已 hold 到上限 → max_holds
//	ctx 到点/取消 → ctx_done（墙钟优先，不再开新段）
//	inner run 有错 → run_error
//	没交合法回执 → no_receipt（交现役 finalize 按回执缺失收口）
//	非 continue（done/nothing/blocked/failed）→ outcome（各有自己的语义，不 hold）
//	未配最短轮 → no_min_round
//	已跑满最短轮 → min_reached
//	步数触顶 → step_budget（触顶优先进 settlement，不逼模型空转）
//	否则 → hold
func holdContinuePlan(
	holdEnabled bool, receipt *zhulong.Receipt, elapsed, minDuration time.Duration,
	stepsUsed, stepBudget int, ctxErr, runErr error, round, maxRounds int,
) (bool, string) {
	if !holdEnabled {
		return false, "disabled"
	}
	if receipt == nil {
		return false, "no_receipt"
	}
	if maxRounds > 0 && round >= maxRounds {
		return false, "max_holds"
	}
	if ctxErr != nil {
		return false, "ctx_done"
	}
	if runErr != nil {
		return false, "run_error"
	}
	if receipt.Outcome != zhulong.OutcomeContinue {
		return false, "outcome"
	}
	if stepBudget > 0 && stepsUsed >= stepBudget {
		return false, "step_budget"
	}
	if !zhulong.HoldContinueDecision(true, receipt.Outcome, elapsed, minDuration) {
		if minDuration <= 0 {
			return false, "no_min_round"
		}
		return false, "min_reached"
	}
	return true, "hold"
}

// receiptOfRunResult 从 RunResult 正文里解析回执（解析失败返回 nil，交给现役 finalize 处理）。
func receiptOfRunResult(res *RunResult) *zhulong.Receipt {
	if res == nil {
		return nil
	}
	r, err := zhulong.ParseReceipt(res.Response)
	if err != nil {
		return nil
	}
	return r
}

// buildHoldContinuePrompt 造"继续本轮"的续跑提示（hold 专用，不进默认路径）。
//
// 关键：明确禁止交回执，并把上一份 continue 的 summary/next_actions 当输入，避免模型换题打转。
func buildHoldContinuePrompt(r *zhulong.Receipt, remaining time.Duration) string {
	var b strings.Builder
	b.WriteString("## 未到最短轮（hold_continue_until_min）\n\n")
	if remaining < 0 {
		remaining = 0
	}
	b.WriteString("本轮是最短轮内的一次续跑：**不要交回执**，也不要写 zhulong 回执块。\n")
	b.WriteString("上一段你想交 continue 结束本轮，但配置要求单轮至少跑满最短轮（还需约 " +
		fmt.Sprintf("%.0f", remaining.Minutes()) + " 分钟）。\n\n")
	b.WriteString("接着往下做，要求：\n")
	b.WriteString("1. 沿上一段自己写的 next_actions / 假设继续推进**同一个目标、同一条链**，不要换题；\n")
	b.WriteString("2. 优先把当前链推上一个台阶：拿到新的原始报文/证据并落盘（evidence 路径写进链台账）；\n")
	b.WriteString("3. 真推不动就换入口/变体/编码再试，而不是交 continue 收工；\n")
	b.WriteString("4. 只有触顶、确需人拍板（blocked）或执行失败时才允许收口。\n")
	if r != nil {
		if s := strings.TrimSpace(r.Summary); s != "" {
			b.WriteString("\n上一段自述（作为输入，不要照抄）：" + oneLine(s, 500) + "\n")
		}
		if len(r.NextActions) > 0 {
			b.WriteString("\n上一段列的下一步（继续做，不是重写）：\n")
			for i, a := range r.NextActions {
				if i >= 8 {
					break
				}
				b.WriteString("- " + oneLine(a, 300) + "\n")
			}
		}
	}
	return b.String()
}
