package zhulong

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

const (
	// DefaultLeaseStale 是心跳静默多久算"失联"。超过它仍可能还在跑，所以只标 unknown，不重派。
	DefaultLeaseStale = 10 * time.Minute
	// DefaultSweepInterval 是清扫间隔。
	DefaultSweepInterval = 60 * time.Second
)

// LeaseNotifyHook 是「run 被判 unknown」的最小通知钩子（契约⑦，P1 只做接口 + 最小实现，不接 SSE）。
//
// 契约约束（P2 接入 SSE/站内信时必须遵守）：
//   - **同一次状态跃迁只回调一次**：SweepStale 只会把 running 改成 unknown，
//     第二次清扫时该 run 已不是 running，自然不会重复通知；
//   - hook 必须是快操作：生产实现要丢进异步队列，不得阻塞清扫循环。
type LeaseNotifyHook func(ctx context.Context, runIDs []string)

// SweepStaleWithNotify 是 SweepStale 的带通知变体：有 run 被标记时回调**一次** hook（nil 安全）。
func (s *Store) SweepStaleWithNotify(ctx context.Context, staleAfter time.Duration, hook LeaseNotifyHook) ([]string, error) {
	marked, err := s.SweepStale(ctx, staleAfter)
	if err != nil {
		return marked, err
	}
	if len(marked) > 0 && hook != nil {
		hook(ctx, marked)
	}
	return marked, nil
}

// SweepStale 把心跳超时的 running run 标为 unknown，返回被标记的 run id。
//
// 语义（对齐 agent-autoloop 的 decide.ts:207-216）：
//   - 只标 unknown，不自动重派 —— 进程可能还在跑，重派会造成双跑；
//   - 不改变已完成/已收口的 run；
//   - 迟到的结果仍然生效（FinishRun 不检查前置状态）。
func (s *Store) SweepStale(ctx context.Context, staleAfter time.Duration) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("zhulong: store 未初始化")
	}
	if staleAfter <= 0 {
		staleAfter = DefaultLeaseStale
	}
	cutoff := time.Now().UTC().Add(-staleAfter).Format(tsLayout)

	// seen_at 为空时回落到 started_at（进程启动后从未上报事件的情况）。
	rows, err := s.db.QueryContext(ctx, `
SELECT id FROM zhulong_runs
WHERE state = ?
  AND COALESCE(NULLIF(seen_at,''), NULLIF(started_at,''), created_at) < ?`,
		string(StateRunning), cutoff)
	if err != nil {
		return nil, fmt.Errorf("zhulong: 扫描失联 run 失败: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	marked := make([]string, 0, len(ids))
	for _, id := range ids {
		res, uerr := s.db.ExecContext(ctx, `
UPDATE zhulong_runs SET state=? WHERE id=? AND state=?`,
			string(StateUnknown), id, string(StateRunning))
		if uerr != nil {
			return marked, fmt.Errorf("zhulong: 标记失联 run 失败: %w", uerr)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			marked = append(marked, id)
		}
	}
	return marked, nil
}

// StartLeaseLoop 启动后台租约清扫（与平台 audit/monitor 的 retention loop 同形）。
// 单实例即可：重复启动只会多几次空扫描，不会误标。
func StartLeaseLoop(store *Store, logger *zap.Logger) {
	if store == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(DefaultSweepInterval)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			marked, err := store.SweepStale(ctx, DefaultLeaseStale)
			cancel()
			if err != nil {
				if logger != nil {
					logger.Warn("zhulong 租约清扫失败", zap.Error(err))
				}
				continue
			}
			if len(marked) > 0 && logger != nil {
				logger.Warn("zhulong 租约超时，已标记 unknown（不重派）",
					zap.Int("count", len(marked)), zap.Strings("runIds", marked))
			}
		}
	}()
}
