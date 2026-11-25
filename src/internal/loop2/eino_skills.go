package loop2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/einomcp"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/tooloutput"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/filesystem"
	"github.com/cloudwego/eino/adk/middlewares/skill"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

func prepareEinoAgenticSkills(
	ctx context.Context,
	skillsDir string,
	ma *config.MultiAgentConfig,
	logger *zap.Logger,
) (loc *localbk.Local, skillMW adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage], fsTools bool, skillsRoot string, err error) {
	if ma == nil {
		return nil, nil, false, "", nil
	}
	needLocalBackend := ma.EinoMiddleware.ReductionEnable
	newLocalBackend := func() (*localbk.Local, error) {
		backend, backendErr := localbk.NewBackend(ctx, &localbk.Config{})
		if backendErr != nil {
			return nil, fmt.Errorf("eino local backend: %w", backendErr)
		}
		return backend, nil
	}
	if ma.EinoSkills.Disable {
		if !needLocalBackend {
			return nil, nil, false, "", nil
		}
		loc, err = newLocalBackend()
		return loc, nil, false, "", err
	}
	root := strings.TrimSpace(skillsDir)
	if root == "" {
		if logger != nil {
			logger.Warn("eino agentic skills: skills_dir empty, skip")
		}
		if !needLocalBackend {
			return nil, nil, false, "", nil
		}
		loc, err = newLocalBackend()
		return loc, nil, false, "", err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("skills_dir abs: %w", err)
	}
	// ⚠ 2026-09-26 修复(重大):eino skill 后端 list() 走 localbk.GlobInfo,而后者用 filepath.WalkDir,
	// **WalkDir 不跟进根目录符号链接** —— 本平台 skills_dir 恰是软链($ROOT/skills → /home/kali/work/skills),
	// 实测:软链路径扫到 0 个 SKILL.md,真实路径扫到 169 个 ⇒ skill 工具对所有技能恒返回
	// "skill not found",**该工具从未可用**(历史 tool_stats 里 skill 调用 0 次的真实原因)。
	// 修法:解析掉软链再交给后端(对非软链路径无副作用)。
	if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil && resolved != "" {
		if st, serr := os.Stat(resolved); serr == nil && st.IsDir() {
			abs = resolved
		}
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		if logger != nil {
			logger.Warn("eino agentic skills: directory missing, skip", zap.String("dir", abs), zap.Error(err))
		}
		if !needLocalBackend {
			return nil, nil, false, "", nil
		}
		loc, err = newLocalBackend()
		return loc, nil, false, "", err
	}

	loc, err = newLocalBackend()
	if err != nil {
		return nil, nil, false, "", err
	}

	skillBE, err := skill.NewBackendFromFilesystem(ctx, &skill.BackendFromFilesystemConfig{
		Backend: loc,
		BaseDir: abs,
	})
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("eino agentic skill filesystem backend: %w", err)
	}

	sc := &skill.TypedConfig[*schema.AgenticMessage]{Backend: skillBE}
	if name := strings.TrimSpace(ma.EinoSkills.SkillToolName); name != "" {
		sc.SkillToolName = &name
	}
	// 常驻技能清单瘦身(2026-09-18;2026-10-15 修订):默认全量注入 162 个描述 ≈12K tokens/轮。
	// 这里用 ADK 的 CustomToolDescription 钩子渲染精简清单:带判据标签者优先 + 描述按字符截断 + 总量封顶。
	maxChars := ma.EinoSkills.SkillListMaxChars
	descMaxChars := ma.EinoSkills.SkillDescriptionMaxCharsEffective()
	tagFirst := ma.EinoSkills.SkillListTagFirstEffective()
	sc.CustomToolDescription = func(ctx context.Context, fs []skill.FrontMatter) string {
		return compactSkillList(ctx, fs, maxChars, descMaxChars, tagFirst)
	}
	// 技能包内文件树(2026-09-26 新增):接上 eino 提供但此前未使用的 BuildContent 钩子。
	// 动机(实测):包内 references/ 与本轮新增的 payload-<sink>.md 之前对模型**不可见** ——
	//   后端 ListPackageFiles 只服务管理端 API,不进模型上下文;eino 后端只扫一层 */SKILL.md。
	//   结果是模型加载技能后只拿到「Base directory + SKILL.md 正文」,必须自己 ls/glob 才发现包内文件。
	// 做法:复刻默认内容(项目在 adk_init.go 设 adk.LanguageChinese,故用中文模板
	//   "正在启动 Skill：%s\n" + "此 Skill 的目录：%s\n\n%s"),再**追加**包内文件树。
	// 成本:仅在「加载技能」那一次随返回体返回,常驻 token 增量 = 0。
	// ⚠ 若 eino 升级后默认内容模板变更,此处需同步(格式差异不影响语义:name/dir/正文均已含)。
	sc.BuildContent = func(ctx context.Context, sk skill.Skill, rawArgs string) (string, error) {
		base := fmt.Sprintf("正在启动 Skill：%s\n", sk.Name) +
			fmt.Sprintf("此 Skill 的目录：%s\n\n%s", sk.BaseDirectory, sk.Content)
		return base + skillPackageFileTree(sk.BaseDirectory), nil
	}
	skillMW, err = skill.NewTyped[*schema.AgenticMessage](ctx, sc)
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("eino agentic skill middleware: %w", err)
	}

	// 2026-09-26 新增(C):启动自检 —— 把「实际加载到的技能数」写日志,0 则告警。
	// 背景:2026-09-24 00:34 skills_dir 被改为软链后,eino 后端(WalkDir 不跟进根软链)加载到 0 个技能,
	// skill 工具对所有技能恒返回 not found 且**静默无告警**,故障潜伏约 2 天(靠人工冒烟才发现)。
	// 有本自检时,那一刻日志就会报 "skills loaded: 0"。
	if logger != nil {
		if list, lerr := skillBE.List(ctx); lerr != nil {
			logger.Warn("eino agentic skills: 列举失败(技能工具可能不可用)",
				zap.String("dir", abs), zap.Error(lerr))
		} else {
			logger.Info("eino agentic skills loaded", zap.Int("skills", len(list)), zap.String("dir", abs))
			if len(list) == 0 {
				logger.Error("eino agentic skills: 加载到 0 个技能 —— skill 工具将恒返回 'skill not found'!! "+
					"排查:skills_dir 是否为软链(后端 WalkDir 不跟进根软链)/ 是否为空 / SKILL.md 是否合规",
					zap.String("dir", abs))
			}
		}
	}

	fsTools = ma.EinoSkills.EinoSkillFilesystemToolsEffective()
	return loc, skillMW, fsTools, abs, nil
}

func subAgentAgenticFilesystemMiddleware(
	ctx context.Context,
	loc *localbk.Local,
	invokeNotify *einomcp.ToolInvokeNotifyHolder,
	einoAgentName string,
	conversationID string,
	projectID string,
	reductionRootDir string,
	toolMaxBytes int,
	binder *MCPExecutionBinder,
	beginMonitor func(toolCallID, command string) string,
	appendPartialMonitor func(executionID, toolCallID, chunk string),
	registerCancelMonitor func(executionID string, cancel context.CancelFunc),
	unregisterCancelMonitor func(executionID string),
	finishMonitor func(executionID, toolCallID, command, stdout string, success bool, invokeErr error),
	toolTimeoutMinutes int,
	toolWaitTimeoutSeconds int,
	shellNoOutputTimeoutSec int,
	outputChunk func(toolName, toolCallID, chunk string),
) (adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage], error) {
	if loc == nil {
		return nil, nil
	}
	mw, err := filesystem.NewTyped[*schema.AgenticMessage](ctx, &filesystem.MiddlewareConfig{
		Backend: loc,
		StreamingShell: &einoStreamingShellWrap{
			inner:                   security.NewEinoStreamingShell(),
			invokeNotify:            invokeNotify,
			einoAgentName:           strings.TrimSpace(einoAgentName),
			outputChunk:             outputChunk,
			beginMonitor:            beginMonitor,
			appendPartialMonitor:    appendPartialMonitor,
			registerCancelMonitor:   registerCancelMonitor,
			unregisterCancelMonitor: unregisterCancelMonitor,
			finishMonitor:           finishMonitor,
			toolTimeoutMinutes:      toolTimeoutMinutes,
			toolWaitTimeoutSeconds:  toolWaitTimeoutSeconds,
			shellNoOutputTimeoutSec: shellNoOutputTimeoutSec,
		},
	})
	if err != nil {
		return nil, err
	}
	return &einoAgenticFilesystemToolMiddleware{
		TypedChatModelAgentMiddleware: mw,
		conversationID:                conversationID,
		projectID:                     projectID,
		reductionRootDir:              reductionRootDir,
		toolMaxBytes:                  toolMaxBytes,
		binder:                        binder,
	}, nil
}

type einoAgenticFilesystemToolMiddleware struct {
	adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage]
	conversationID   string
	projectID        string
	reductionRootDir string
	toolMaxBytes     int
	binder           *MCPExecutionBinder
}

func (m *einoAgenticFilesystemToolMiddleware) WrapInvokableToolCall(ctx context.Context, endpoint adk.InvokableToolCallEndpoint, tCtx *adk.ToolContext) (adk.InvokableToolCallEndpoint, error) {
	wrapped, err := m.TypedChatModelAgentMiddleware.WrapInvokableToolCall(ctx, endpoint, tCtx)
	if err != nil {
		return nil, err
	}
	if tCtx == nil || !isBuiltinEinoADKFilesystemToolName(tCtx.Name) {
		return wrapped, nil
	}
	return func(ctx context.Context, argumentsInJSON string, opts ...tool.Option) (string, error) {
		args := parseToolArgumentsObject(argumentsInJSON)
		if len(args) > 0 && m.binder != nil {
			m.binder.BindArguments(tCtx.CallID, args)
		}
		result, runErr := wrapped(ctx, argumentsInJSON, opts...)
		if runErr != nil {
			return result, runErr
		}
		return m.boundToolResult(tCtx.CallID, result), nil
	}, nil
}

func (m *einoAgenticFilesystemToolMiddleware) boundToolResult(toolCallID, result string) string {
	if m == nil || m.toolMaxBytes <= 0 || len(result) <= m.toolMaxBytes {
		return result
	}
	return tooloutput.BoundWithSpill(result, m.toolMaxBytes, tooloutput.SpillOpts{
		RootDir:        m.reductionRootDir,
		ProjectID:      m.projectID,
		ConversationID: m.conversationID,
		ExecutionID:    toolCallID,
	})
}

func parseToolArgumentsObject(raw string) map[string]interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" || raw == "null" {
		return nil
	}
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &args); err != nil || len(args) == 0 {
		return nil
	}
	return args
}

// agentToolTimeoutMinutes 返回 agent.tool_timeout_minutes（与 executeToolViaMCP 一致）；cfg 为 nil 时 0。
func agentToolTimeoutMinutes(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.Agent.ToolTimeoutMinutes
}

func agentToolWaitTimeoutSeconds(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.Agent.ToolWaitTimeoutSeconds
}

// agentShellNoOutputTimeoutSeconds：0=默认 300s（5 分钟）；-1=关闭；>0=自定义秒数。
func agentShellNoOutputTimeoutSeconds(cfg *config.Config) int {
	if cfg == nil {
		return 300
	}
	v := cfg.Agent.ShellNoOutputTimeoutSeconds
	if v < 0 {
		return 0
	}
	if v == 0 {
		return 300
	}
	return v
}

// compactSkillList 渲染"token 友好"的常驻技能清单(2026-10-15 修订):
// ①带判据标签(description 含「触发:」)的技能**优先且公平地列出**,每条描述按 descMaxChars 个字符截断(句读处断开);
// ②其余技能**只列名字**,保证可发现性(避免因长度上限而"消失");
// ③预算分配:先预留全部「裸名字」所需额度,余量才给标签描述(旧版硬编码 65%,描述与名字互相挤占);
// ④单个超长条目**只跳过自己**(continue),不再 break —— 旧版 break 会让字母序靠后的技能**整组**失去描述;
// ⑤tagFirst 时按「标签优先 + 组内字母序」稳定排序,使结果与目录扫描顺序无关。
//
// 修订起因(2026-10-15 实测):`skill_stats` 显示 src-hunting 累计 **0 次**调用,同族 pentest-windftsy 43 次。
// 探针 TestSkillListProbe 实测旧版:44 个带标签技能**只有 17 个**能显示描述(公平率 39%),153 个只剩裸名字。
//   - src-hunting 写的是「触发场景：」(全角冒号),未被 Contains(desc,"触发:") 识别 → 落普通桶 → 只留裸名字;
//   - 且旧版按字母序填充 softCap 并在首个超支条目 break,字母序在 jwt- 之后的标签技能
//     (src-hunting / sqli / xss / ssrf / upload / waf-bypass / open-redirect / race-condition / pentest-windftsy …)全被降级为裸名。
func compactSkillList(_ context.Context, fs []skill.FrontMatter, maxChars, descMaxChars int, tagFirst bool) string {
	if maxChars <= 0 {
		maxChars = 12000
	}
	if descMaxChars <= 0 {
		descMaxChars = 120
	}
	type item struct {
		name, desc string
		tagged     bool
	}
	var items []item
	for _, s := range fs {
		name := strings.TrimSpace(s.Name)
		if name == "" {
			continue
		}
		desc := strings.Join(strings.Fields(s.Description), " ")
		items = append(items, item{name: name, desc: desc, tagged: strings.Contains(desc, "触发:")})
	}
	if tagFirst {
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].tagged != items[j].tagged {
				return items[i].tagged
			}
			return items[i].name < items[j].name
		})
	}

	// 先为「全部裸名字」预留额度:名字是可发现性底线,不能被描述挤掉。
	namesCost := 0
	for _, it := range items {
		namesCost += len("- "+it.name) + 1
	}
	descBudget := maxChars - namesCost
	if descBudget < maxChars/3 {
		descBudget = maxChars / 3
	}

	var b strings.Builder
	b.WriteString("可加载技能清单(**索引**:先按名 `skill` 加载 1-2 个再动手;清单本身不是模板,现场不匹配就自造打法;加载后必须改造到本目标,照搬=失败)。\n")
	used := 0
	emit := func(line string) bool {
		if used+len(line)+1 > maxChars {
			return false
		}
		b.WriteString(line)
		b.WriteString("\n")
		used += len(line) + 1
		return true
	}
	seen := make(map[string]bool, len(items))
	descUsed := 0
	for _, it := range items {
		if !it.tagged {
			continue
		}
		line := "- " + it.name + ": " + clipSkillDesc(it.desc, descMaxChars)
		if descUsed+len(line)+1 > descBudget {
			continue // 旧版为 break:一个超长条目会拖垮其后全部标签技能
		}
		if emit(line) {
			seen[it.name] = true
			descUsed += len(line) + 1
		}
	}
	hidden := 0
	for _, it := range items {
		if seen[it.name] {
			continue
		}
		if !emit("- " + it.name) {
			hidden++
		}
	}
	if hidden > 0 {
		fmt.Fprintf(&b, "(另有 %d 个技能因长度上限未列出,可直接按名加载)\n", hidden)
	}
	return b.String()
}

// clipSkillDesc 把描述截到 n 个字符以内,优先在句读处断开(避免截成半句)。
func clipSkillDesc(desc string, n int) string {
	r := []rune(desc)
	if len(r) <= n {
		return desc
	}
	head := string(r[:n])
	for _, sep := range []string{"。", "；", ";", "、"} {
		if i := strings.LastIndex(head, sep); i >= n/2 {
			return head[:i+len(sep)]
		}
	}
	return head + "…"
}

// skillPackageFileTree 渲染技能包内文件树,供 BuildContent 追加到技能加载结果。
// 目的:让包内 references/(含 payload-<sink>.md 精华集)、scripts/、assets/ **在加载技能时即被发现**,
// 免去"模型自己 ls/glob"这一步。体积硬上限(默认 8KB)以保证上下文可控。
func skillPackageFileTree(baseDir string) string {
	const (
		maxBytes      = 8192
		maxPerSection = 60
	)
	if strings.TrimSpace(baseDir) == "" {
		return ""
	}
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return "" // 读不到就不追加,静默降级(不影响技能加载)
	}
	// 备份/临时垃圾:不进清单,避免诱导模型去读 .bak
	skip := func(name string) bool {
		if name == "SKILL.md" {
			return true
		}
		lower := strings.ToLower(name)
		if strings.Contains(lower, ".bak") || strings.Contains(name, ".20") ||
			strings.HasPrefix(name, ".") || lower == "__pycache__" {
			return true
		}
		return false
	}
	type section struct {
		title string
		dir   string
	}
	// 顺序即优先级:references 最前(我方 payload 精华集在此)
	sections := []section{{"references/", "references"}, {"scripts/", "scripts"}, {"assets/", "assets"}}
	var b strings.Builder
	b.WriteString("\n### 本技能包内文件(加载技能时已列出,可直接 read_file,无需再 ls)\n")
	any := false
	for _, sec := range sections {
		sub := filepath.Join(baseDir, sec.dir)
		if st, err := os.Stat(sub); err != nil || !st.IsDir() {
			continue
		}
		var names []string
		_ = filepath.Walk(sub, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			rel, rerr := filepath.Rel(baseDir, p)
			if rerr != nil || skip(info.Name()) {
				return nil
			}
			names = append(names, rel)
			return nil
		})
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		shown := names
		if len(shown) > maxPerSection {
			shown = shown[:maxPerSection]
		}
		any = true
		fmt.Fprintf(&b, "- **%s**\n", sec.title)
		payloadSeen := false
		for _, n := range shown {
			size := int64(0)
			if fi, err := os.Stat(filepath.Join(baseDir, n)); err == nil {
				size = fi.Size()
			}
			mark := ""
			if strings.HasPrefix(n, "references/payload-") {
				mark = "  ← **该漏洞类型的 payload 精华集(tier1 可直接用;判据须自建,勿照抄)**"
				payloadSeen = true
			}
			fmt.Fprintf(&b, "  - `%s`(%d B)%s\n", n, size, mark)
		}
		if len(names) > len(shown) {
			fmt.Fprintf(&b, "  - (另有 %d 个文件未列出)\n", len(names)-len(shown))
		}
		if payloadSeen {
			fmt.Fprintf(&b, "  → 另有按 sink 检索的入口:`python3 /home/kali/work/arsenal/attack-cards/payloads.py --sink <名>`;真源全表 `/home/kali/work/arsenal/payloads/`(按需查,勿整库读)\n")
		}
		if b.Len() > maxBytes {
			break
		}
	}
	// references 之外的散文件(如 SCENARIOS.md、ENGINE_PAYLOADS.md 直接放在包根)
	var root []string
	for _, e := range entries {
		if e.IsDir() || skip(e.Name()) {
			continue
		}
		root = append(root, e.Name())
	}
	if len(root) > 0 {
		sort.Strings(root)
		any = true
		fmt.Fprintf(&b, "- **包根附加文件**\n")
		for i, n := range root {
			if i >= maxPerSection {
				fmt.Fprintf(&b, "  - (另有 %d 个未列出)\n", len(root)-maxPerSection)
				break
			}
			fi, _ := os.Stat(filepath.Join(baseDir, n))
			fmt.Fprintf(&b, "  - `%s`(%d B)\n", n, fi.Size())
		}
	}
	if !any {
		return ""
	}
	out := b.String()
	if len(out) > maxBytes {
		out = truncRunes(out, maxBytes) + "\n(文件树已按上限截断)\n"
	}
	return out
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
