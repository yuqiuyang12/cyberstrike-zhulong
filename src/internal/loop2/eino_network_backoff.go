package loop2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cloudwego/eino/adk"
)

// 网络超时轻量退避（不做完整熔断）
//
// 背景：模型调用在网络抖动时返回 dial/timeout 类错误。原生重试在持续性烂网下
// 耗尽后，错误冒泡即被 Handler 终止任务，需手动续跑。
// 本文件提供一个轻量判断 + 阻塞等待：
//   - IsNetworkTransientRunError 判断是否为「网络类、可等待恢复」的错误；
//   - WaitForNetworkTransientClear 周期性轻量探测模型端点，直到网络恢复
//     或 ctx 被取消。与熔断的区别：无状态机、无包装、无全局开关，
//     仅在错误发生点做一次性的退避等待。

// 默认等待节奏（固定，不做翻倍/封顶，保持轻量）。
const (
	networkBackoffProbeInterval = 20 * time.Second
	networkBackoffMaxTotal      = 8 * time.Minute
	networkBackoffProbeTimeout  = 8 * time.Second
)

// IsNetworkTransientRunError 判断运行错误是否为「网络类、值得等待恢复」的错误。
// 兼容两种形态：
//   - 直接的 dial/i/o timeout 错误；
//   - 原生重试耗尽（*adk.RetryExhaustedError），其 LastErr 为网络类 transient。
func IsNetworkTransientRunError(runErr error) bool {
	if runErr == nil {
		return false
	}
	// 用户取消不属于。
	if errors.Is(runErr, context.Canceled) {
		return false
	}

	var retryErr *adk.RetryExhaustedError
	if errors.As(runErr, &retryErr) {
		last := retryErr.LastErr
		if last == nil {
			return false
		}
		return isPlainNetworkTransient(last)
	}

	// 直接错误：含 i/o timeout / dial / 网络 transient 特征。
	return isPlainNetworkTransient(runErr)
}

// NetworkBackoffMaxTotalMinutes 返回网络退避的最大等待分钟数（供文案展示）。
func NetworkBackoffMaxTotalMinutes() int {
	return int(networkBackoffMaxTotal / time.Minute)
}

// isPlainNetworkTransient 判定单个错误是否为纯网络类（且非鉴权/请求体问题）。
func isPlainNetworkTransient(err error) bool {
	if err == nil {
		return false
	}
	// 复用唯一判据：transient（超时/连接类），其已排除 4xx 鉴权与用户取消。
	if !isEinoTransientRunError(err) {
		return false
	}
	return true
}

// ProbeModelEndpointReachable 轻量探测模型端点网络是否可达。
// 收到任意 HTTP 响应（含 401/404）即视为网络路径恢复。
func ProbeModelEndpointReachable(ctx context.Context, baseURL, apiKey string, httpClient *http.Client) bool {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return false
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: networkBackoffProbeTimeout}
	}

	probeCtx, cancel := context.WithTimeout(ctx, networkBackoffProbeTimeout)
	defer cancel()

	url := strings.TrimRight(baseURL, "/") + "/models"
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode > 0
}

// WaitForNetworkTransientClear 周期性探测直到网络恢复或达到最大等待/取消。
// 返回 true=网络已恢复可续跑；false=超时或用户取消。
// onWait 用于在每次等待前上报进度（可为 nil）。
func WaitForNetworkTransientClear(
	ctx context.Context,
	baseURL, apiKey string,
	httpClient *http.Client,
	onWait func(attempt int, interval time.Duration),
) bool {
	deadline := time.Now().Add(networkBackoffMaxTotal)
	attempt := 0

	for {
		attempt++
		if onWait != nil {
			onWait(attempt, networkBackoffProbeInterval)
		}

		select {
		case <-ctx.Done():
			return false
		case <-time.After(networkBackoffProbeInterval):
		}

		if ProbeModelEndpointReachable(ctx, baseURL, apiKey, httpClient) {
			return true
		}

		// 达到总等待上限仍不通：放弃，让调用方按原失败处理。
		if time.Now().After(deadline) {
			return false
		}
	}
}
