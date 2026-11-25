package loop2

// strategy.go —— 角色级作业策略(2026-10-22 Phase 6 分层)
//
// 背景:同一套"深挖"规则套在 19 个角色上必然失衡——信息收集被逼深挖、渗透测试又被
// 时间盒勒住。改为"按角色策略取时间盒":
//   breadth  = 广度/捏软柿子:单资产 15 步软提醒、25 步强提醒
//   balanced = 默认:25/40
//   deep     = 深度:40/60
// 策略来自 roles/*.yaml 的 strategy 字段;会话创建时记录 role_name,中间件按会话角色解析。

import (
	"context"
	"sync"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
)

type strategyCacheEntry struct {
	strategy string
	expire   time.Time
}

var (
	strategyCacheMu sync.Mutex
	strategyCache   = map[string]strategyCacheEntry{}
)

// conversationStrategy 解析某会话所属角色的作业策略(带 5 分钟缓存)。
// 解析顺序:会话 role_name → roles[role].Strategy → 默认 balanced。
func conversationStrategy(ctx context.Context, db *database.DB, cfg *config.Config, convID string) string {
	if convID == "" {
		return "balanced"
	}
	strategyCacheMu.Lock()
	if e, ok := strategyCache[convID]; ok && time.Now().Before(e.expire) {
		strategyCacheMu.Unlock()
		return e.strategy
	}
	strategyCacheMu.Unlock()

	strategy := "balanced"
	if db != nil && cfg != nil {
		if conv, err := db.GetConversationLite(convID); err == nil && conv != nil {
			role := conv.RoleName
			if r, ok := cfg.Roles[role]; ok {
				strategy = config.NormalizeRoleStrategy(r.Strategy)
			}
		}
	}
	strategyCacheMu.Lock()
	if len(strategyCache) > 2048 {
		strategyCache = map[string]strategyCacheEntry{}
	}
	strategyCache[convID] = strategyCacheEntry{strategy: strategy, expire: time.Now().Add(5 * time.Minute)}
	strategyCacheMu.Unlock()
	return strategy
}

// thresholdsFor 返回该策略的单资产步数阈值(软/强)。
func thresholdsFor(strategy string) (soft, hard int) {
	switch config.NormalizeRoleStrategy(strategy) {
	case "breadth":
		return 15, 25
	case "deep":
		return assetStepSoftWarn, assetStepHardWarn // 40 / 60
	default:
		return 25, 40
	}
}
