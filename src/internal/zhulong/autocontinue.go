package zhulong

// autocontinue.go —— 烛龙「自动续轮」（2026-11-05 M1）。
//
// 为什么需要它（实测 bug）：一轮的预算写的是 60 分钟，实际 6.5 分钟就判 done 收工；
// 4 次 deliver_gate 全 CONTINUE 也照样收口；9 条 todo 全 open 从不结清。
// 结果是"只产 low/medium 信息泄露，链条一根都不推进"。
//
// 本文件负责"没人按按钮时，谁来跑下一轮"：
//   - 扫「还该跑」的会话：① 有 state=open 的链 ② 上一轮状态是 continue_pending（done 被打回）；
//   - 间隔到了才排下一轮（同一个会话不并发跑）；
//   - 每轮的 objective 由台账确定性生成：**推链**或**建目标模型**，
//     明令禁止写成"补覆盖/扫剩下的面"（那是把深度降级成广度，正是要治的病）；
//   - 单会话有轮数上限，避免"跑不动还一直烧钱"。
//
// 设计对齐 internal/zhaoheng/autoloop.go：本包不碰 HTTP、不碰模型，只调注入的 runner。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AutoContinueRunner 由 handler 注入：跑一轮烛龙，返回错误表示本轮没跑起来。
type AutoContinueRunner func(ctx context.Context, conversationID, objective string) error

// AutoContinueOptions 控制自动续轮的节奏与上限。
type AutoContinueOptions struct {
	// Interval 是同一会话两轮之间的最小间隔（<=0 用 1 分钟）。
	Interval time.Duration
	// MaxRounds 是单会话续轮上限（<=0 表示不限；仅统计已结束的 run）。
	MaxRounds int
	// Now 便于单测注入时钟。
	Now func() time.Time
	// MaxNoGainRoundsWarning:连续 N 轮无 exploited 链 → 下一轮改为止损轮(默认 3)。
	MaxNoGainRoundsWarning int
	// MaxNoGainRoundsStop:连续 N 轮无 exploited 链 → 停止自动排轮(默认 6)。
	MaxNoGainRoundsStop int
	// Since 是"起算时间"：只有最后收口时间 >= Since 的会话才会被自动续轮。
	// 零值 = 不设限。用途：开启开关时排除历史测试会话（避免重启后立刻打旧目标）。
	Since time.Time
	// Mode 是允许自动续轮的会话模式（默认 "zhulong"）；空串 = 不按模式过滤。
	// 目的：烛龙只续烛龙会话，不把昭衡（zhaoheng）等其它模式的会话拉起来跑。
	Mode string
}

// 自动续轮的默认节奏。
const (
	autoContinueDefaultInterval = time.Minute
	autoContinueMinInterval     = time.Minute
	autoContinueMaxInterval     = 60 * time.Minute
)

func (o AutoContinueOptions) normalized() AutoContinueOptions {
	if o.Interval <= 0 {
		o.Interval = autoContinueDefaultInterval
	}
	if o.Interval < autoContinueMinInterval {
		o.Interval = autoContinueMinInterval
	}
	if o.Interval > autoContinueMaxInterval {
		o.Interval = autoContinueMaxInterval
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	// M1.1:边际收益阈值(0 表示用默认值)。
	if o.MaxNoGainRoundsWarning <= 0 {
		o.MaxNoGainRoundsWarning = 3
	}
	if o.MaxNoGainRoundsStop <= 0 || o.MaxNoGainRoundsStop < o.MaxNoGainRoundsWarning {
		o.MaxNoGainRoundsStop = 6
	}
	if strings.TrimSpace(o.Mode) == "" {
		o.Mode = "zhulong"
	}
	return o
}

// StartAutoContinue 启动自动续轮循环（阻塞式 goroutine，进程退出即结束）。
//
// store 为 nil / runner 为 nil 时直接返回：宁可不跑，也不要在没接线的情况下空转。
func StartAutoContinue(store *ChainStore, opts AutoContinueOptions, runner AutoContinueRunner, logger *zap.Logger) {
	if store == nil || store.db == nil || runner == nil {
		if logger != nil {
			logger.Warn("zhulong 自动续轮未启动（store/runner 未就绪）")
		}
		return
	}
	opts = opts.normalized()
	tick := opts.Interval / 4
	if tick < 30*time.Second {
		tick = 30 * time.Second
	}

	go func() {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			due, err := store.DueConversations(ctx, opts)
			cancel()
			if err != nil {
				if logger != nil {
					logger.Warn("zhulong 自动续轮扫描失败", zap.Error(err))
				}
				continue
			}
			for _, item := range due {
				// 一轮的墙钟预算由配置决定（分钟级），这里给足 90 分钟硬上限，
				// 防止 runner 内部死等把整个循环卡住。
				rctx, rcancel := context.WithTimeout(context.Background(), 90*time.Minute)
				rerr := runner(rctx, item.ConversationID, item.Objective)
				rcancel()
				if rerr != nil {
					if logger != nil {
						logger.Warn("zhulong 自动续轮执行失败",
							zap.String("conversationId", item.ConversationID), zap.Error(rerr))
					}
					continue
				}
				if logger != nil {
					logger.Info("zhulong 自动续轮已触发一轮",
						zap.String("conversationId", item.ConversationID),
						zap.String("objective", oneLineText(item.Objective, 200)),
						zap.Int("openChains", item.OpenChains),
						zap.Int("rung", item.Rung))
				}
			}
		}
	}()
}

// AutoContinueItem 是一条待续轮的会话（objective 已按台账确定性生成）。
type AutoContinueItem struct {
	ConversationID string
	Objective      string
	OpenChains     int
	Rung           int
	Reason         string // open-chain | continue-pending
}

// DueConversations 返回当前应该排下一轮的会话。
//
// 粗筛在 SQL（有 open 链 / 上一轮 continue_pending），精筛在 Go（间隔、轮数上限、是否正在跑），
// 便于单测与打日志。
func (s *ChainStore) DueConversations(ctx context.Context, opts AutoContinueOptions) ([]AutoContinueItem, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("zhulong: chain store 未初始化")
	}
	opts = opts.normalized()
	now := opts.Now()

	candidates, err := s.autoContinueCandidates(ctx)
	if err != nil {
		return nil, err
	}
	var out []AutoContinueItem
	for _, cand := range candidates {
		running, err := s.conversationRunning(ctx, cand.conversationID)
		if err != nil {
			// 读不出来就跳过这一条：宁可不跑，也不要和正在跑的一轮撞车。
			continue
		}
		if running {
			continue
		}
		lastFinished, finishedCount, err := s.conversationLastFinished(ctx, cand.conversationID)
		if err != nil {
			continue
		}
		// 轮数上限按「本次勾选之后」计数（2026-11-09 用户裁定）：
		// 每次勾上无人值守都给一轮新预算，不会因会话历史跑满而永久不再启动。
		if opts.MaxRounds > 0 {
			count := finishedCount
			if since := s.conversationUnattendedSince(ctx, cand.conversationID); !since.IsZero() {
				if c := s.conversationFinishedCountSince(ctx, cand.conversationID, since); c >= 0 {
					count = c
				}
			}
			if count >= opts.MaxRounds {
				continue
			}
		}
		if !lastFinished.IsZero() && now.Sub(lastFinished) < opts.Interval {
			continue
		}
		// 起算时间：开启开关前的历史会话不自动续（避免重启后立刻对旧目标开打）。
		if !opts.Since.IsZero() {
			if lastFinished.IsZero() || lastFinished.Before(opts.Since) {
				continue
			}
		}
		// 模式过滤：烛龙只续烛龙会话（不把昭衡等其它模式的会话拉起来跑）。
		if mode := s.conversationAgentMode(ctx, cand.conversationID); mode != "" && !strings.EqualFold(mode, opts.Mode) {
			continue
		}
		// 无人值守闸门（2026-11-08 用户裁定）：只有会话级开关打开才自动续轮；
		// 关闭 = 正常单轮收口，绝不自动拉起。
		if !s.conversationUnattended(ctx, cand.conversationID) {
			continue
		}
		item, berr := s.buildAutoContinueItem(ctx, opts, cand)
		if berr != nil || strings.TrimSpace(item.Objective) == "" {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

type autoContinueCandidate struct {
	conversationID string
	reason         string
}

// autoContinueCandidates 取候选会话（去重）：有 open 链的，以及上一轮打回 continue 的。
//
// zl_chains 表可能尚未建（链账本灰度启用）：查不到就当"没有候选"，不报错。
func (s *ChainStore) autoContinueCandidates(ctx context.Context) ([]autoContinueCandidate, error) {
	seen := map[string]struct{}{}
	var out []autoContinueCandidate
	add := func(convID, reason string) {
		convID = strings.TrimSpace(convID)
		if convID == "" {
			return
		}
		if _, ok := seen[convID]; ok {
			return
		}
		seen[convID] = struct{}{}
		out = append(out, autoContinueCandidate{conversationID: convID, reason: reason})
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT conversation_id FROM zl_chains WHERE state=? LIMIT 200`, ChainOpen)
	if err != nil {
		// 表不存在（还没建链账本）不阻塞：继续看 continue_pending。
		if !isNoSuchTable(err) {
			return nil, fmt.Errorf("zhulong: 扫描 open 链失败: %w", err)
		}
	} else {
		for rows.Next() {
			var convID string
			if serr := rows.Scan(&convID); serr != nil {
				_ = rows.Close()
				return nil, serr
			}
			add(convID, "open-chain")
		}
		_ = rows.Close()
		if rerr := rows.Err(); rerr != nil {
			return nil, rerr
		}
	}

	prows, perr := s.db.QueryContext(ctx, `
SELECT DISTINCT conversation_id FROM zhulong_runs WHERE state=? LIMIT 200`, string(StateContinuePending))
	if perr != nil {
		return nil, fmt.Errorf("zhulong: 扫描 continue_pending 会话失败: %w", perr)
	}
	for prows.Next() {
		var convID string
		if serr := prows.Scan(&convID); serr != nil {
			_ = prows.Close()
			return nil, serr
		}
		add(convID, "continue-pending")
	}
	_ = prows.Close()
	if rerr := prows.Err(); rerr != nil {
		return nil, rerr
	}
	return out, nil
}

func (s *ChainStore) conversationRunning(ctx context.Context, convID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM zhulong_runs WHERE conversation_id=? AND state IN ('running','queued','unknown')`,
		convID).Scan(&n)
	return n > 0, err
}

// conversationAgentMode 取会话的 agent_mode；读不到（表/列缺失或会话不存在）返回空串。
// 空串在调用侧表示"不按模式过滤"，保证单测用的最小 schema 也能跑。
func (s *ChainStore) conversationAgentMode(ctx context.Context, convID string) string {
	var mode string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(agent_mode,'') FROM conversations WHERE id=?`, convID).Scan(&mode); err != nil {
		return ""
	}
	return strings.TrimSpace(mode)
}

// conversationUnattended 取会话的「无人值守」开关；读不到（列缺失/会话不存在）返回 false。
// 语义（2026-11-08 用户裁定）：只有用户在会话里显式开启无人值守，才允许自动续轮——
// 避免把普通会话自动拉起来连打 6 小时。
func (s *ChainStore) conversationUnattended(ctx context.Context, convID string) bool {
	var v int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(unattended_mode,0) FROM conversations WHERE id=?`, convID).Scan(&v); err != nil {
		return false
	}
	return v == 1
}

// conversationUnattendedSince 取「本次无人值守」的起算时间；读不到返回零值（= 按历史全量计数）。
func (s *ChainStore) conversationUnattendedSince(ctx context.Context, convID string) time.Time {
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(unattended_since,'') FROM conversations WHERE id=?`, convID).Scan(&raw); err != nil {
		return time.Time{}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

// conversationFinishedCountSince 数「since 之后收口」的轮次；读不到返回 -1（调用方回退到全量计数）。
func (s *ChainStore) conversationFinishedCountSince(ctx context.Context, convID string, since time.Time) int {
	if since.IsZero() {
		return -1
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT finished_at FROM zhulong_runs WHERE conversation_id=? AND state NOT IN ('running','queued')`, convID)
	if err != nil {
		return -1
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		if t, perr := time.Parse(time.RFC3339, strings.TrimSpace(raw)); perr == nil && !t.Before(since) {
			n++
		}
	}
	if err := rows.Err(); err != nil {
		return -1
	}
	return n
}

// conversationContinueHint 取会话的「续轮提示」；读不到返回空串（= 续轮只说「继续」）。
func (s *ChainStore) conversationContinueHint(ctx context.Context, convID string) string {
	var hint string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(continue_hint,'') FROM conversations WHERE id=?`, convID).Scan(&hint); err != nil {
		return ""
	}
	return strings.TrimSpace(hint)
}

func (s *ChainStore) conversationLastFinished(ctx context.Context, convID string) (time.Time, int, error) {
	var last string
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(MAX(finished_at),''), COUNT(*) FROM zhulong_runs
WHERE conversation_id=? AND state NOT IN ('running','queued')`, convID).Scan(&last, &n)
	if err != nil {
		return time.Time{}, 0, err
	}
	return parseTS(last), n, nil
}

// buildAutoContinueItem 用台账确定性生成 objective（不看模型自报）。
func (s *ChainStore) buildAutoContinueItem(ctx context.Context, opts AutoContinueOptions, cand autoContinueCandidate) (AutoContinueItem, error) {
	item := AutoContinueItem{ConversationID: cand.conversationID, Reason: cand.reason}

	chain, cerr := s.DeepestOpen(ctx, cand.conversationID)
	if cerr != nil && !errors.Is(cerr, ErrNoOpenChain) {
		// zl_chains 不存在是允许的降级；其他错误当"没有 open 链"处理。
		if !isNoSuchTable(cerr) {
			return item, cerr
		}
		chain = nil
	}
	if chain != nil {
		item.OpenChains = 1
		item.Rung = chain.Rung
	}
	// 续轮指令走"人话"：默认「继续」，用户在会话里写了续轮提示就附上原话。
	// 目标/链/证据由状态回注提供，不再拼模板。
	item.Objective = BuildContinueObjectiveText(s.conversationContinueHint(ctx, cand.conversationID))

	// M1.1(2026-11-05)边际收益闸:连续多轮没有一条链打到 exploited,说明在"开新链刷数",
	// 不是在打深。3 轮起提示换方向,6 轮起不再自动排(避免烧 token)。
	if _, finished, ferr := s.conversationLastFinished(ctx, cand.conversationID); ferr == nil {
		exploited, eerr := s.countExploitedChains(ctx, cand.conversationID)
		if eerr == nil && exploited == 0 {
			switch {
			case finished >= opts.MaxNoGainRoundsStop:
				item.Objective = "" // DueConversations 会跳过空 objective
			case finished >= opts.MaxNoGainRoundsWarning:
				item.Objective = "前几轮还没打穿,换个思路:换资产或换条假设试试;实在没口子就按 blocked 收口。\n" + item.Objective
			}
		}
	}
	return item, nil
}

// countExploitedChains 数该会话已击穿的链(exploited)。读不到按 0 处理。
func (s *ChainStore) countExploitedChains(ctx context.Context, convID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zl_chains WHERE conversation_id=? AND state='exploited'`, convID).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// itoaSmall 是给日志/提示用的最小整数格式化(避免为一行引入 strconv 依赖分歧)。
func itoaSmall(n int) string {
	if n <= 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// conversationObjective 取该会话的目标（zhulong_goals）；读不到返回空串。
func (s *ChainStore) conversationObjective(ctx context.Context, convID string) string {
	var objective string
	err := s.db.QueryRowContext(ctx, `
SELECT objective FROM zhulong_goals WHERE conversation_id=? ORDER BY created_at DESC LIMIT 1`,
		convID).Scan(&objective)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(objective)
}

// conversationTopAsset 在"没有 open 链"时给 objective 一个具体资产锚点：
// 取覆盖台账里最近更新过的那条（没有台账就返回空串，由文本兜底）。
func (s *ChainStore) conversationTopAsset(ctx context.Context, convID string) string {
	var asset string
	err := s.db.QueryRowContext(ctx, `
SELECT asset FROM asset_coverage WHERE conversation_id=? ORDER BY updated_at DESC, asset ASC LIMIT 1`,
		convID).Scan(&asset)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(asset)
}

// BuildContinueObjectiveText 生成自动续轮的用户侧指令（纯函数，可单测）。
//
// 2026-11-08 用户裁定（覆盖旧版"本轮指导"模板）：
//   - 默认就是人话两个字「继续」；
//   - 用户在会话里写了「续轮提示」时，把那段原话附在后面（例如"看看有没有其他中危能在别的站点复现，顺便再查一遍 /home/kali/Desktop/cnvd/"）；
//   - 目标/约束/上一轮结论/证据/待办已由状态回注另行提供，这里不再堆模板（模板化=太死板）。
func BuildContinueObjectiveText(hint string) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return "继续"
	}
	return "继续\n" + hint
}

// isNoSuchTable 判断错误是否是"表不存在"（链账本尚未建表时的合法降级）。
func isNoSuchTable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table")
}
