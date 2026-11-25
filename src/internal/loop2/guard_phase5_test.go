package loop2

// Phase 5 护栏单测(2026-10-21):破坏性命令围栏 + 参数体积守卫 + 按面技能路由。

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"cyberstrike-ai/internal/coverage"

	"github.com/cloudwego/eino/compose"
)

func fenceArgs(cmd string) string {
	b, _ := json.Marshal(map[string]interface{}{"command": cmd})
	return string(b)
}

func TestDestructiveFenceBlocks(t *testing.T) {
	blocked := []string{
		"rm -rf /",
		"rm -rf /*",
		"sudo rm -rf /etc",
		"rm -rf ~/",
		"mkfs.ext4 /dev/sda1",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"shutdown -h now",
		"init 0",
		"kill -9 1",
		"chmod -R 777 /",
		"systemctl stop dsh-web",
		"systemctl restart cyberstrike-ai",
		"pkill -f node",
		"iptables -F",
		"history -c",
	}
	mw := destructiveFenceMiddleware(nil)
	executed := false
	next := func(ctx context.Context, in *compose.ToolInput) (*compose.ToolOutput, error) {
		executed = true
		return &compose.ToolOutput{Result: "EXECUTED"}, nil
	}
	for _, cmd := range blocked {
		executed = false
		out, err := mw.Invokable(next)(context.Background(),
			&compose.ToolInput{Name: "execute", Arguments: fenceArgs(cmd)})
		if err != nil {
			t.Fatalf("%q: 不应返回硬错: %v", cmd, err)
		}
		if executed {
			t.Fatalf("FAIL 未拦截: %q", cmd)
		}
		if out == nil || !strings.Contains(out.Result, fenceRefusalPrefix) {
			t.Fatalf("FAIL 未返回围栏文案: %q -> %v", cmd, out)
		}
	}
	t.Logf("PASS: %d 条破坏性命令全部拦截", len(blocked))
}

func TestDestructiveFenceAllowsNormalPentest(t *testing.T) {
	allowed := []string{
		"rm -rf /tmp/scan-out",
		"rm -f ./report.txt",
		"curl -s https://example.com/",
		"nmap -sV -p 80,443 10.0.0.5",
		"nuclei -u https://target -severity high",
		"ffuf -w /home/kali/work/dict/_curated/dir.txt -u https://t/FUZZ",
		"systemctl status cyberstrike-ai",
		"ls -la /home/kali/data",
		"python3 -c 'print(1+1)'",
		"cat /etc/hostname",
	}
	mw := destructiveFenceMiddleware(nil)
	for _, cmd := range allowed {
		var executed atomic.Bool
		next := func(ctx context.Context, in *compose.ToolInput) (*compose.ToolOutput, error) {
			executed.Store(true)
			return &compose.ToolOutput{Result: "OK"}, nil
		}
		if _, err := mw.Invokable(next)(context.Background(),
			&compose.ToolInput{Name: "execute", Arguments: fenceArgs(cmd)}); err != nil {
			t.Fatalf("%q: 意外错误 %v", cmd, err)
		}
		if !executed.Load() {
			t.Fatalf("FAIL 误拦正常动作: %q", cmd)
		}
	}
	t.Logf("PASS: %d 条正常渗透动作未被误拦", len(allowed))
}

func TestToolArgSizeGuard(t *testing.T) {
	mw := toolArgSizeGuardMiddleware(nil)
	var executed atomic.Bool
	next := func(ctx context.Context, in *compose.ToolInput) (*compose.ToolOutput, error) {
		executed.Store(true)
		return &compose.ToolOutput{Result: "OK"}, nil
	}
	big := `{"body":"` + strings.Repeat("A", toolArgMaxBytes+10) + `"}`
	out, err := mw.Invokable(next)(context.Background(), &compose.ToolInput{Name: "execute", Arguments: big})
	if err != nil {
		t.Fatalf("不应硬错: %v", err)
	}
	if executed.Load() {
		t.Fatal("FAIL 超大参数未被拦截")
	}
	if out == nil || !strings.Contains(out.Result, "arg-guard") {
		t.Fatalf("FAIL 文案缺失: %v", out)
	}
	// 正常大小放行
	executed.Store(false)
	if _, err := mw.Invokable(next)(context.Background(),
		&compose.ToolInput{Name: "execute", Arguments: fenceArgs("echo ok")}); err != nil {
		t.Fatalf("小参数报错: %v", err)
	}
	if !executed.Load() {
		t.Fatal("FAIL 正常参数被误拦")
	}
	t.Logf("PASS: 超限拦截、正常放行")
}

func TestFaceSkillHint(t *testing.T) {
	for _, face := range coverage.AllFaces() {
		hint := coverage.FaceSkillHint(face)
		switch face {
		case coverage.FacePort, coverage.FacePath, coverage.FaceParam, coverage.FaceAuth, coverage.FaceCVE:
			if hint == "" {
				t.Fatalf("面 %s 应有技能路由提示", face)
			}
			if !strings.Contains(hint, "/home/kali/work/skills/") {
				t.Fatalf("面 %s 提示缺绝对路径: %s", face, hint)
			}
		}
	}
	if h := coverage.FaceSkillHint("upload"); h != "" {
		t.Fatalf("未启用的面不应有路由: %q", h)
	}
	t.Logf("PASS: 5 个面均有技能路由,未启用面返回空")
}

// Phase6:时间盒计步——40 步软提醒、60 步强提醒,且各只提醒一次。
func TestAssetTimeBoxWarnings(t *testing.T) {
	s := newAssetBudgetState()
	key := "conv|asset"
	var soft, hard int
	for i := 1; i <= 100; i++ {
		steps, level := s.bump(key, assetStepSoftWarn, assetStepHardWarn)
		if steps != i {
			t.Fatalf("步数计数错误: want %d got %d", i, steps)
		}
		switch level {
		case 1:
			soft++
		case 2:
			hard++
		}
	}
	if soft != 1 {
		t.Fatalf("软提醒应只出现 1 次,实际 %d", soft)
	}
	if hard != 1 {
		t.Fatalf("强提醒应只出现 1 次,实际 %d", hard)
	}
	if msg := timeBoxWarnText("a.example.com", 40, 1, "deep", 40); !strings.Contains(msg, "time-box") || !strings.Contains(msg, "40") {
		t.Fatalf("软提醒文案异常: %s", msg)
	}
	if msg := timeBoxWarnText("a.example.com", 60, 2, "deep", 40); !strings.Contains(msg, "blocked") || !strings.Contains(msg, "找全") {
		t.Fatalf("强提醒文案异常: %s", msg)
	}
	t.Logf("PASS: 40 步软提醒 1 次、60 步强提醒 1 次,文案含收口指引")
}
