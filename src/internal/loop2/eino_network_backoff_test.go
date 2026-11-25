package loop2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk"
)

func TestIsNetworkTransientRunError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain dial timeout", errors.New(`Post "https://api.deepseek.com/chat/completions": dial tcp 1.2.3.4:443: i/o timeout`), true},
		{"connection reset", errors.New("read tcp 10.0.0.1:1234->1.2.3.4:443: connection reset by peer"), true},
		{"tls handshake timeout", errors.New("net/http: TLS handshake timeout"), true},
		{"context canceled", context.Canceled, false},
		{"http 400", errors.New("API request failed: http status 400 bad request"), false},
		{"http 401", errors.New("API request failed: http status 401 unauthorized"), false},
		{"http 403", errors.New("http status 403 forbidden"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsNetworkTransientRunError(c.err); got != c.want {
				t.Fatalf("got %v want %v (err=%v)", got, c.want, c.err)
			}
		})
	}
}

func TestIsNetworkTransientRunErrorRetryExhausted(t *testing.T) {
	// 重试耗尽 + 最后一次为网络错误 → 应等待恢复。
	netErr := errors.New(`dial tcp 111.12.215.79:443: i/o timeout`)
	exhausted := &adk.RetryExhaustedError{LastErr: netErr, TotalRetries: 4}
	if !IsNetworkTransientRunError(exhausted) {
		t.Fatal("retry exhausted with network last error must be transient")
	}

	// 重试耗尽 + 最后一次为 400 → 不应等待。
	badErr := errors.New("http status 400 bad request")
	exhausted2 := &adk.RetryExhaustedError{LastErr: badErr, TotalRetries: 4}
	if IsNetworkTransientRunError(exhausted2) {
		t.Fatal("retry exhausted with 400 must NOT be transient")
	}

	// 无 LastErr → 不等待。
	if IsNetworkTransientRunError(&adk.RetryExhaustedError{}) {
		t.Fatal("nil LastErr must not be transient")
	}
}

func TestProbeModelEndpointReachableBadURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// 空 base_url / 不可达地址 → false（不 panic）。
	if ProbeModelEndpointReachable(ctx, "", "k", nil) {
		t.Fatal("empty base url must be unreachable")
	}
	if ProbeModelEndpointReachable(ctx, "http://127.0.0.1:1", "k", nil) {
		t.Fatal("closed port must be unreachable")
	}
}

func TestProbeModelEndpointReachableLocalServer(t *testing.T) {
	// 起一个本地监听：任意 HTTP 响应即视为网络可达。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen failed: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := fmt.Sprintf("http://%s", ln.Addr().String())
	if !ProbeModelEndpointReachable(ctx, url, "k", nil) {
		t.Fatal("local server responding 401 must count as reachable")
	}
}

func TestWaitForNetworkTransientClearCancelled(t *testing.T) {
	// ctx 立即取消 → 返回 false，不应长时间阻塞。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if WaitForNetworkTransientClear(ctx, "http://127.0.0.1:1", "k", nil, nil) {
		t.Fatal("cancelled ctx must return false")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("must return promptly on cancel, took %v", elapsed)
	}
}

func TestNetworkBackoffMaxTotalMinutes(t *testing.T) {
	if got := NetworkBackoffMaxTotalMinutes(); got <= 0 {
		t.Fatalf("max total minutes must be positive, got %d", got)
	}
}
