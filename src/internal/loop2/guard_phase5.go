package loop2

// guard_phase5.go —— Phase 5 借用的三件护栏(2026-10-21)
//
// 来源:商业 Windows 版逆向材料里的 `model_output_guard_middleware`、`agent/fence.go`、
// `agent/forced_skills.go`。按 F-INTEGRATION-REVIEW 的结论**改造后采纳**:
//   1) 破坏性命令围栏(fence):只拦"会把本机/平台搞坏"的命令,不限制正常渗透动作;
//   2) 工具参数体积守卫(model_output_guard 的可用子集):超限参数直接软拒绝,防上下文爆炸;
//   3) 按面技能路由(forced_skills 的轻量版):不做"每轮强制塞正文"(那是它原版的缺点),
//      改为"按面给 1-2 个技能绝对路径 + 判据,由模型按需 read"。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/cloudwego/eino/compose"
	"go.uber.org/zap"
)

const (
	// toolArgMaxBytes 单次工具调用入参上限;超限说明模型把大 payload 塞进参数了。
	toolArgMaxBytes = 32 * 1024
	// fenceRefusalPrefix 固定前缀,便于日志/验收检索(与平台软错误前缀区分)。
	fenceRefusalPrefix = "[fence] 已拦截:"
)

// destructivePatterns 只覆盖"明确会毁掉本机/平台"的动作;正常渗透动作(扫、跑 payload、
// 删自己工作目录里的文件)不在其中。
var destructivePatterns = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(/|/\*|~/|~\s|\$HOME/?|/home/kali/?|/etc|/usr|/var)\s*($|[;&|])`), "递归删除系统/家目录"},
	{regexp.MustCompile(`(?i)\bmkfs(\.\w+)?\s`), "格式化文件系统"},
	{regexp.MustCompile(`(?i)\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd|vd)`), "直写块设备"},
	{regexp.MustCompile(`(?i)>\s*/dev/(sd|nvme|hd|vd)`), "重定向直写块设备"},
	{regexp.MustCompile(`:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:\s*&`), "fork bomb"},
	{regexp.MustCompile(`(?i)\b(shutdown|poweroff|halt)\b(\s+(-h|now|\+0))?`), "关机/停机"},
	{regexp.MustCompile(`(?i)\binit\s+0\b|\binit\s+6\b`), "切换运行级(关机/重启)"},
	{regexp.MustCompile(`(?i)\bkill\s+-9\s+1\b|(?i)\bkillall\s+-9\b`), "杀 init/全部进程"},
	{regexp.MustCompile(`(?i)\bchmod\s+-R\s+(777|000)\s+/\s*($|[;&|])`), "递归改根目录权限"},
	{regexp.MustCompile(`(?i)\bchown\s+-R\s+[^\s]+\s+/\s*($|[;&|])`), "递归改根目录属主"},
	{regexp.MustCompile(`(?i)\bsystemctl\s+(stop|restart|disable|mask)\s+(dsh-web|cyberstrike-ai)\b`), "停/重启会话宿主或平台本体"},
	{regexp.MustCompile(`(?i)\bpkill\s+-f\b[^\n]*\b(dsh|node)\b`), "pkill 宽匹配(会误杀会话宿主)"},
	{regexp.MustCompile(`(?i)\b(sudo\s+)?iptables\s+-F\b|\bufw\s+disable\b`), "清空/关闭主机防火墙"},
	{regexp.MustCompile(`(?i)\bhistory\s+-c\b|(?i)\b(shred|wipe)\b[^\n]*\.bash_history`), "清空审计痕迹"},
}

// commandFields 可能承载 shell 命令的参数名。
var commandFields = []string{"command", "cmd", "script", "shell", "exec", "code"}

func extractCommands(arguments string) []string {
	if strings.TrimSpace(arguments) == "" {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(arguments), &m); err != nil {
		return []string{arguments}
	}
	var out []string
	for _, k := range commandFields {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		// 部分工具把命令塞在 args/argv 数组里
		for _, k := range []string{"args", "argv"} {
			if arr, ok := m[k].([]interface{}); ok {
				var parts []string
				for _, x := range arr {
					if s, ok := x.(string); ok {
						parts = append(parts, s)
					}
				}
				if len(parts) > 0 {
					out = append(out, strings.Join(parts, " "))
				}
			}
		}
	}
	return out
}

// destructiveFenceMiddleware 拦截破坏性本地命令(软拒绝,不中断整轮)。
func destructiveFenceMiddleware(logger *zap.Logger) compose.ToolMiddleware {
	return compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
				if input != nil {
					for _, cmd := range extractCommands(input.Arguments) {
						for _, p := range destructivePatterns {
							if p.re.MatchString(cmd) {
								if logger != nil {
									logger.Warn("fence_blocked",
										zap.String("tool", input.Name),
										zap.String("reason", p.reason),
										zap.String("command", truncateForLog(cmd, 200)))
								}
								return &compose.ToolOutput{Result: fmt.Sprintf(
									"%s 命中破坏性护栏(%s)。该命令会损坏本机或平台本体,平台拒绝执行。\n"+
										"如确属测试所需,请改用可控范围(限定到具体目录/自建对象),或由人类操作员在平台外执行。",
									fenceRefusalPrefix, p.reason)}, nil
							}
						}
					}
				}
				return next(ctx, input)
			}
		},
	}
}

// toolArgSizeGuardMiddleware 参数体积守卫:超限直接软拒绝,提示模型拆分。
func toolArgSizeGuardMiddleware(logger *zap.Logger) compose.ToolMiddleware {
	return compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
				if input != nil && len(input.Arguments) > toolArgMaxBytes {
					if logger != nil {
						logger.Warn("tool_arg_oversize",
							zap.String("tool", input.Name), zap.Int("bytes", len(input.Arguments)))
					}
					return &compose.ToolOutput{Result: fmt.Sprintf(
						"[arg-guard] 工具参数过大(%d 字节 > %d 上限),已拒绝执行以避免上下文爆炸。"+
							"请拆分:大 payload 先落盘到文件,再用 --data-binary @file / 读文件方式引用。",
						len(input.Arguments), toolArgMaxBytes)}, nil
				}
				return next(ctx, input)
			}
		},
	}
}

func truncateForLog(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
