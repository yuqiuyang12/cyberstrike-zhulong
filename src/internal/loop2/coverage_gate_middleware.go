package loop2

// coverage_gate_middleware.go —— 覆盖软门(2026-10-21 Phase 2 第二批 / 2026-10-22 ncc3 修复)
//
// 作用:当模型把动作切到**新资产**时,若"当前资产"仍有未覆盖面,就在工具结果前面
// 追加一条提示(不拦截、不改结果),让模型看到"你还有一个资产没打完"。
//
// 为什么是"软门":
//   - SP1 已证明中间件拦得住(硬门技术可行),但"长枚举被门锁死"的风险(X5)未实测;
//   - 先用软门观察一周(coverage_switch_warn 计数),再决定是否切硬门。
//
// 为什么改"结果前缀"而不是拦截:
//   - 拦截会丢掉这次工具调用真实结果;前缀既保留证据,又能被模型读到。
//
// 2026-10-22 ncc3 实测暴露的三件事(本版修复):
//  1) 资产抽取必须与台账同一套规则(hosts.go):3 小时 133 次告警里大量是
//     wpscan.txt / robots.txt / sqlite3.connect / favicon.png / api.github.com / 127.0.0.1;
//  2) 记账类工具(coverage_report / mark_face_done / record_entrypoint / list_entrypoints)
//     提到 asset 是"记账",不是"切换目标",不能算 newAsset —— 否则每次收口都告警;
//  3) 两个新软提示:端口证据门槛(A1)、计划-执行绑定(A5)。
//
// 去重:同一 (会话, 新资产, 当前资产) 10 分钟内只提示一次,避免刷屏。

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"github.com/cloudwego/eino/compose"
	"go.uber.org/zap"
)

const (
	coverageGateWarnTTL = 10 * time.Minute
	// coverageLedgerCacheTTL 是"台账资产清单"的本地缓存时长(避免每次工具调用都查库)。
	coverageLedgerCacheTTL = 30 * time.Second
	// planExecMaxSteps 是 A5 的窗口:probe_plan 之后 N 步内必须出现 face_probe。
	planExecMaxSteps = 10
)

// coverageLedgerTools 是"记账类工具":它们参数里出现 asset 是台账操作,不代表切换目标。
// 把这些工具算成 newAsset 会把告警刷满(ncc3:87 次 mark_face_done = 87 次潜在误报)。
//
// deliver_gate 也归这里:它是只读闸门判定,参数里唯一的"自由文本"是 agent_report
// (上游 agent 输出原文,里面必然包含一堆主机名)。若让它走 mentionedAssets /
// PrimaryHost,一次闸门判定就会被当成"切到了新资产"并顺带累计时间盒步数——
// 那是纯误报。判定工具本身不对任何资产作业,按记账类处理。
var coverageLedgerTools = map[string]bool{
	builtin.ToolCoverageReport:   true,
	builtin.ToolMarkFaceDone:     true,
	builtin.ToolRecordEntrypoint: true,
	builtin.ToolListEntrypoints:  true,
	builtin.ToolDeliverGate:      true,
}

// portScanKeywords 是"能作为 port 面证据"的关键词(大小写不敏感)。
var portScanKeywords = []string{
	"nmap", "masscan", "rustscan", "naabu", "top1000", "top-ports", "top ports",
	"-p-", "端口", "portscan", "port scan", "ss -tlnp", "netstat",
	// face_probe(face=port) 自己的落盘命名:recon/.../face-port-<ts>.jsonl
	"face-port", "port-scan", "open-ports", ".gnmap", ".nmap",
}

// conversationIDFromToolCtx 与 app 包同名逻辑一致:先取 agent ctx,再取 MCP 头回填的会话 ID。
func conversationIDFromToolCtx(ctx context.Context) string {
	if id := agent.ConversationIDFromContext(ctx); id != "" {
		return id
	}
	return mcp.MCPConversationIDFromContext(ctx)
}

// toolShortName 去掉命名空间前缀(mcp__server__ / eino_fs::),与 coverage 包同一实现。
func toolShortName(name string) string {
	return coverage.ShortToolName(name)
}

type coverageGateState struct {
	mu   sync.Mutex
	seen map[string]time.Time
	// switchWarns 统计"已经真正发给模型的切换提示"条数(按会话),超预算只记 suppressed。
	switchWarns map[string]int
	suppressed  map[string]int
	// portHints 统计 A1 端口证据提示(A1 有独立预算,避免变成新的噪声源)。
	portHints map[string]int
	// kbHints 统计 A9 技术面触发式检索提示(A9 也必须有预算,否则每个动作都提醒就成了噪声)。
	kbHints map[string]int
}

// KbHintBudgetPerSession 是 A9「进了技术面却没查知识库」提示的每会话上限。
// 2 次足够纠正一次偏移;再多只会挤占上下文、并训练模型忽略 [coverage-gate] 前缀。
const KbHintBudgetPerSession = 2

// allowKbHint 判定 A9 提示是否还有预算。
func (s *coverageGateState) allowKbHint(convID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kbHints == nil {
		s.kbHints = map[string]int{}
	}
	if s.kbHints[convID] >= KbHintBudgetPerSession {
		return false
	}
	s.kbHints[convID]++
	return true
}

// allowPortHint 判定 A1 提示是否还有预算。
func (s *coverageGateState) allowPortHint(convID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.portHints == nil {
		s.portHints = map[string]int{}
	}
	if s.portHints[convID] >= coverage.PortHintBudgetPerSession {
		return false
	}
	s.portHints[convID]++
	return true
}

// allowSwitchWarn 判定是否还能把切换提示塞进上下文;超限返回 false 并累加 suppressed。
func (s *coverageGateState) allowSwitchWarn(convID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.switchWarns == nil {
		s.switchWarns = map[string]int{}
	}
	if s.switchWarns[convID] >= coverage.SwitchWarnBudgetPerSession {
		if s.suppressed == nil {
			s.suppressed = map[string]int{}
		}
		s.suppressed[convID]++
		return false
	}
	s.switchWarns[convID]++
	return true
}

// suppressedCount 返回因预算被压掉的提示条数(用于收尾日志)。
func (s *coverageGateState) suppressedCount(convID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.suppressed[convID]
}

func (s *coverageGateState) shouldWarn(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if t, ok := s.seen[key]; ok && now.Sub(t) < coverageGateWarnTTL {
		return false
	}
	s.seen[key] = now
	// 顺手清理过期项,避免无界增长
	if len(s.seen) > 512 {
		for k, t := range s.seen {
			if now.Sub(t) >= coverageGateWarnTTL {
				delete(s.seen, k)
			}
		}
	}
	return true
}

// ---------- 台账资产缓存(让 gate 认识"已在台账里"的资产) ----------

type coverageAssetEntry struct {
	assets []string
	at     time.Time
}

type coverageAssetCache struct {
	mu     sync.Mutex
	byConv map[string]coverageAssetEntry
}

func newCoverageAssetCache() *coverageAssetCache {
	return &coverageAssetCache{byConv: map[string]coverageAssetEntry{}}
}

// get 返回该会话台账资产(30s TTL);读库失败时返回 nil(降级为"只认严格抽取")。
func (c *coverageAssetCache) get(ctx context.Context, store *coverage.Store, convID string) []string {
	if c == nil || store == nil || convID == "" {
		return nil
	}
	c.mu.Lock()
	if e, ok := c.byConv[convID]; ok && time.Since(e.at) < coverageLedgerCacheTTL {
		c.mu.Unlock()
		return e.assets
	}
	c.mu.Unlock()

	assets, err := store.ListAssets(ctx, convID)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	if len(c.byConv) > 256 {
		c.byConv = map[string]coverageAssetEntry{}
	}
	c.byConv[convID] = coverageAssetEntry{assets: assets, at: time.Now()}
	c.mu.Unlock()
	return assets
}

// mentionedAssets 把"这次调用提到了哪些资产"合成一份:
// 严格抽取(hosts.go)∪ 台账里已有、且在文本中原样出现的资产。
// 后者保证"同一套规则"不误伤:模型显式登记的资产(哪怕字面过不了严格校验)仍被认作目标。
func mentionedAssets(text string, ledger []string) []string {
	out := coverage.ExtractHosts(text)
	seen := make(map[string]bool, len(out))
	for _, h := range out {
		seen[h] = true
	}
	if len(ledger) > 0 {
		low := strings.ToLower(text)
		for _, a := range ledger {
			if a == "" || seen[a] {
				continue
			}
			if strings.Contains(low, a) {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// portEvidenceLooksScanned 判定一段证据引用是否"确实做过端口扫描"。
func portEvidenceLooksScanned(ev string) bool {
	low := strings.ToLower(ev)
	for _, kw := range portScanKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// faceEnteredByTool 判定"这次调用要进入哪个面"——只对 path/param/auth/cve 生效。
// probe_plan 天然是 path 面;face_probe 看入参 face。
func faceEnteredByTool(shortName string, args map[string]interface{}) string {
	switch shortName {
	case builtin.ToolProbePlan:
		return coverage.FacePath
	case builtin.ToolFaceProbe:
		f := strings.ToLower(strings.TrimSpace(stringArgOf(args, "face")))
		switch f {
		case coverage.FacePath, coverage.FaceParam, coverage.FaceAuth, coverage.FaceCVE:
			return f
		}
	}
	return ""
}

// stringArgOf 从已解析的工具入参里取字符串。
func stringArgOf(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// ---------- A5:计划-执行绑定 ----------

type planExecPending struct {
	steps  int
	warned bool
}

type planExecState struct {
	mu      sync.Mutex
	pending map[string]*planExecPending
}

func newPlanExecState() *planExecState {
	return &planExecState{pending: map[string]*planExecPending{}}
}

// observe 每步调用一次:probe_plan 记账,face_probe 清账,其它工具累计步数,
// 超过窗口且未执行 → 返回一次提醒文本。
func (s *planExecState) observe(convID, shortName string) string {
	if s == nil || convID == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if shortName == builtin.ToolProbePlan {
		s.pending[convID] = &planExecPending{}
		if len(s.pending) > 256 {
			for k := range s.pending {
				if k != convID {
					delete(s.pending, k)
				}
			}
		}
		return ""
	}
	p := s.pending[convID]
	if p == nil {
		return ""
	}
	if shortName == builtin.ToolFaceProbe {
		delete(s.pending, convID)
		return ""
	}
	p.steps++
	if p.warned || p.steps < planExecMaxSteps {
		return ""
	}
	p.warned = true
	return fmt.Sprintf("[coverage-gate] 提醒:你 %d 步前用 probe_plan 生成了探测计划,但至今没有调用 face_probe 执行它。"+
		"计划不执行等于没测——请立刻 face_probe(asset=<当前资产>, face=path|param|port) 把计划跑成结论,"+
		"或在 mark_face_done 里写明为何放弃该计划。\n", p.steps)
}

// ---------- 软门中间件 ----------

// newCoverageGateMiddleware 构造软门中间件。store 为 nil 时返回空中间件(不影响链路)。
func newCoverageGateMiddleware(store *coverage.Store, conversationID string, logger *zap.Logger, cfg *config.Config, db *database.DB) compose.ToolMiddleware {
	if store == nil {
		return compose.ToolMiddleware{}
	}
	state := &coverageGateState{seen: map[string]time.Time{}, switchWarns: map[string]int{}, suppressed: map[string]int{}}
	budget := newAssetBudgetState()
	assets := newCoverageAssetCache()
	plans := newPlanExecState()

	warnText := func(current string, open []string, newAsset string) string {
		return "[coverage-gate] 提醒:当前资产 " + current + " 还有未覆盖面(" + strings.Join(open, ",") +
			"),你现在切到了 " + newAsset + "。请先把 " + current + " 的面补完或用 mark_face_done 标 blocked(写原因)," +
			"否则容易重演\"每个资产只浅测一发\"。若本次调用确实必须跨资产(如拿子域清单),忽略本提醒即可。\n"
	}

	return compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
				// 关键顺序:必须**先**判定(此时台账还是"上一次动作"的现场),
				// 再执行工具,最后把提醒前缀到结果上。
				// 若放在 next() 之后判定,probe_plan 会先把新资产登记成"当前资产",
				// 门就永远看到 current==target,永远不触发(2026-10-21 修)。
				convID := strings.TrimSpace(conversationID)
				if convID == "" {
					convID = conversationIDFromToolCtx(ctx)
				}

				warnPrefix, budgetPrefix := "", ""
				if convID != "" && input != nil {
					short := toolShortName(input.Name)

					// A5(软):计划-执行绑定。所有工具计步,probe_plan 记账,face_probe 清账。
					planPrefix := plans.observe(convID, short)
					if planPrefix != "" && logger != nil {
						logger.Info("coverage_plan_unexecuted_warn",
							zap.String("conversationId", convID), zap.String("tool", short))
					}

					openFaces := func(asset string) []string {
						open, oerr := store.UncoveredFaces(ctx, convID, asset)
						if oerr != nil {
							return nil
						}
						return open
					}

					// A8(软):覆盖台账 ↔ 资产库对账。
					// 事故来源(2026-10-27 乐橙):probe_plan/face_probe 自动登记了 11 个资产的覆盖台账,
					// 但资产库只有模型手工挑的 18 条,278 行全量还在工作区 TSV 里 —— 用户打开资产库
					// 想手工挑资产测,基本空手。台账有、库里没有的 host 必须补 create_asset。
					if short == builtin.ToolCoverageReport {
						if w := ledgerLibraryReconcileWarnText(ctx, db, convID); w != "" {
							if logger != nil {
								logger.Info("coverage_ledger_library_mismatch",
									zap.String("conversationId", convID))
							}
							warnPrefix += w
						}
					}

					// A9(软):技术面触发式检索。知识库不是"开工查一次",而是"每进一个新面查一次"。
					// 事故来源(2026-10-27 乐橙第三轮):执行者转去做「前端硬编码密钥 + x-pcs/HMAC 签名
					// 还原」,80 分钟 123 次浏览器调用硬推;而 KB-RT-02/KB-CASE-B/KB-REV-01/02 与
					// mobile-app-signature-recovery 正好覆盖该面 —— 全会话 0 次检索、0 次技能加载。
					if w := knowledgeTriggerWarnText(ctx, db, convID, short, input.Arguments); w != "" {
						if state.allowKbHint(convID) {
							if logger != nil {
								logger.Info("coverage_knowledge_trigger_warn",
									zap.String("conversationId", convID), zap.String("tool", short))
							}
							warnPrefix += w
						}
					}

					// A7(软):cve 面收口必须有"真的查过"的痕迹。
					// 事故来源(2026-10-27 乐橙):执行者识别出 Spring Boot / ASP.NET MVC / Nuxt / UmiJS,
					// face_probe(cve) 只回「未命中已知指纹」,就把 cve 面收了 —— 全程 0 次 CVE 库/武库/
					// 联网检索,等于用记忆冒充查证。这里在 mark_face_done 收口时补一句硬提醒。
					// 2026-10-28 修:判定窗口从"整个会话"收窄到"近 40 步",否则一条旧的 `which nuclei`
					// 就会把之后所有 cve 盖章永久放行(实测踩到)。
					if short == builtin.ToolMarkFaceDone {
						argsMap := parseToolArgumentsObject(input.Arguments)
						face := strings.ToLower(strings.TrimSpace(fmt.Sprint(argsMap["face"])))
						st := strings.ToLower(strings.TrimSpace(fmt.Sprint(argsMap["state"])))
						if face == coverage.FaceCVE && (st == coverage.StateDone || st == coverage.StateNA) {
							if w := cveLookupWarnText(ctx, db, convID); w != "" {
								if logger != nil {
									logger.Info("coverage_cve_lookup_warn",
										zap.String("conversationId", convID),
										zap.String("state", st))
								}
								warnPrefix += w
							}
						}
					}

					if !coverageLedgerTools[short] {
						ledgerAssets := assets.get(ctx, store, convID)
						hosts := mentionedAssets(input.Arguments, ledgerAssets)
						argsMap := parseToolArgumentsObject(input.Arguments)
						// 本次要进入的面(A1 用)
						enteredFace := faceEnteredByTool(short, argsMap)
						// L4/L5(2026-10-22 第二轮):只认"主目标"+"作业类工具"。
						// ncc3 里 subfinder/gau/fofa 一次列几十个子域、write_file 写清单,
						// 都被旧逻辑当成"切到了新资产" —— 那不是切换,是收集。
						primary := ""
						if !coverage.IsNonActingTool(short) {
							primary = coverage.PrimaryHost(input.Arguments, ledgerAssets)
						}

						current, cerr := store.CurrentAsset(ctx, convID)
						if cerr == nil && current != "" {
							target := ""
							if primary != "" && primary != current {
								target = primary
							}
							if target != "" {
								if open := openFaces(current); len(open) > 0 {
									key := convID + "|" + target + "|" + current
									if state.shouldWarn(key) {
										// 每会话最多向模型投递 SwitchWarnBudgetPerSession 条;
										// 超出的只记 suppressed(判定本身不省略,便于线上评估真实切换频率)。
										if !state.allowSwitchWarn(convID) {
											if logger != nil {
												logger.Info("coverage_switch_warn_suppressed",
													zap.String("conversationId", convID),
													zap.String("currentAsset", current),
													zap.String("newAsset", target),
													zap.Int("suppressedTotal", state.suppressedCount(convID)))
											}
										} else {
											if logger != nil {
												logger.Info("coverage_switch_warn",
													zap.String("conversationId", convID),
													zap.String("currentAsset", current),
													zap.String("newAsset", target),
													zap.Int("uncoveredFaces", len(open)),
													zap.Int("mentionedAssets", len(hosts)),
													zap.String("primaryHost", primary),
													zap.String("tool", short))
											}
											warnPrefix = warnText(current, open, target)
										}
									}
								}
							}
						}

						// A1(软):端口证据门槛——进 path/param 前,port 面未 done 且证据里
						// 没有端口扫描痕迹 → 提醒先补端口侦察(否则路径/参数结论建立在未知服务上)。
						if enteredFace != "" && short == builtin.ToolFaceProbe {
							focus := current
							if focus == "" && len(hosts) > 0 {
								focus = hosts[0]
							}
							if focus != "" {
								if warn := portEvidenceWarnText(ctx, store, convID, focus, enteredFace); warn != "" {
									if state.shouldWarn("port|"+convID+"|"+focus) && state.allowPortHint(convID) {
										if logger != nil {
											logger.Info("coverage_port_evidence_warn",
												zap.String("conversationId", convID),
												zap.String("asset", focus),
												zap.String("face", enteredFace),
												zap.String("tool", short))
										}
										warnPrefix += warn
									}
								}
							}
						}

						// 时间盒计步:仅统计"落在当前资产上的动作"(参数里出现该资产)
						if current, cerr := store.CurrentAsset(ctx, convID); cerr == nil && current != "" {
							for _, h := range hosts {
								if h == current {
									strat := conversationStrategy(ctx, db, cfg, convID)
									soft, hard := thresholdsFor(strat)
									if steps, level := budget.bump(convID+"|"+current, soft, hard); level > 0 {
										if logger != nil {
											logger.Info("coverage_timebox_warn",
												zap.String("conversationId", convID), zap.String("asset", current),
												zap.Int("steps", steps), zap.Int("level", level), zap.String("strategy", strat), zap.Int("soft", soft))
										}
										budgetPrefix = timeBoxWarnText(current, steps, level, strat, soft)
									}
									break
								}
							}
						}
					}
					warnPrefix = planPrefix + warnPrefix
				}

				out, err := next(ctx, input)
				if out != nil {
					out.Result = warnPrefix + budgetPrefix + out.Result
				}
				return out, err
			}
		},
	}
}

// ledgerLibraryReconcileWarnText 对比「覆盖台账」与「资产库」,返回空串表示已对齐。
//
// 判据:
//   - 台账侧 = asset_coverage 里本会话登记过的 distinct asset(host);
//   - 库侧   = assets 表里同 project 的 host(会话未绑项目时退化为全库 host 匹配);
//   - 台账有、库里没有的 host → 提醒补 create_asset(最多列 5 个 + 总数)。
//
// 只提示、不写库:补录的字段(存活/指纹/来源)只有执行者知道,平台替它填就是造数据。
func ledgerLibraryReconcileWarnText(ctx context.Context, db *database.DB, convID string) string {
	if db == nil || db.DB == nil || strings.TrimSpace(convID) == "" {
		return ""
	}
	rows, err := db.DB.QueryContext(ctx,
		`SELECT DISTINCT TRIM(asset) FROM asset_coverage WHERE conversation_id = ? AND TRIM(asset) <> ''`,
		convID)
	if err != nil {
		return ""
	}
	var ledger []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err == nil && host != "" {
			ledger = append(ledger, host)
		}
	}
	_ = rows.Close()
	if len(ledger) == 0 {
		return ""
	}

	// 库侧:优先按该会话所属项目取 host;项目为空时按全库比对(宁可少报,不可误报)。
	var projectID string
	_ = db.DB.QueryRowContext(ctx, `SELECT COALESCE(project_id,'') FROM conversations WHERE id = ?`, convID).Scan(&projectID)

	have := make(map[string]bool, len(ledger))
	var libRows *sql.Rows
	if strings.TrimSpace(projectID) != "" {
		libRows, err = db.DB.QueryContext(ctx,
			`SELECT DISTINCT LOWER(TRIM(host)) FROM assets WHERE project_id = ?`, projectID)
	} else {
		libRows, err = db.DB.QueryContext(ctx,
			`SELECT DISTINCT LOWER(TRIM(host)) FROM assets`)
	}
	if err != nil || libRows == nil {
		return ""
	}
	for libRows.Next() {
		var h string
		if err := libRows.Scan(&h); err == nil && h != "" {
			have[h] = true
		}
	}
	_ = libRows.Close()

	missing := make([]string, 0, len(ledger))
	for _, host := range ledger {
		if !have[strings.ToLower(strings.TrimSpace(host))] {
			missing = append(missing, host)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	sort.Strings(missing)
	shown := missing
	if len(shown) > 5 {
		shown = shown[:5]
	}
	return fmt.Sprintf("[coverage-gate] 提醒:覆盖台账里有 %d 个资产不在资产库(如 %s)。"+
		"台账是 agent 内部进度表,**用户打开资产库看不到它们、也没法挑着手工测**——"+
		"请按「资产入库铁律」补 `create_asset`(带 source、http_status、liveness、tech,实测值), "+
		"或在不补时用 `upsert_project_fact(\"target/asset-index\")` 写明丢弃原因。\n",
		len(missing), strings.Join(shown, ", "))
}

// knowledgeTriggerWarnText 实现 A9:进了新技术面却没查知识库/技能时给一句提醒。
//
// 判定分两步:
//  1. **触发**:当前工具是"作业类"(非记账/检索类),且参数里出现技术面关键词
//     (签名/加密/反序列化/上传/云凭证/域认证/协议逆向/前端 bundle);
//  2. **抑制**:该会话"近 20 步"内已经查过知识库或加载过技能 → 视为按规矩做了,不提醒。
//
// 只提示、不阻断:A9 的价值是"第一次提醒就够",所以有每会话预算(见 KbHintBudgetPerSession)。
func knowledgeTriggerWarnText(ctx context.Context, db *database.DB, convID, short, args string) string {
	if db == nil || db.DB == nil || strings.TrimSpace(convID) == "" || short == "" {
		return ""
	}
	if knowledgeNonActingTools[short] {
		return ""
	}
	lowered := strings.ToLower(args)
	hitFace := ""
	for _, sig := range knowledgeTriggerSignals {
		if strings.Contains(lowered, sig.kw) {
			hitFace = sig.face
			break
		}
	}
	if hitFace == "" {
		return ""
	}
	// R-A9 修（2026-11-06，P1 缺陷条目 DEC-R-A9）：
	//  ① skill 是**进程内中间件工具**，不写 tool_executions（审计确认：全库 'skill' 0 行），
	//     所以原来的 `tool_name IN (…,'skill')` 永假 → 「刚加载过技能仍弹提醒」。
	//     改为查会话级进程内登记（handler 在 skill 调用成功时 MarkConversationSkillCalled）。
	//  ② 原来的三个 LIKE（%skills/% / %skill.md% / %search_knowledge_base%）**双向失真**：
	//     read_file 读技能文件会被误判"已加载"，而把关键词写进 fact 正文又会被误判"已查 KB"。
	//     这里收紧成只认 `tool_name` 命中与 JSON 键形态（"tool":"skill" / "skill":）。
	if conversationSkillRecentlyCalled(convID, time.Now(), skillHintSuppressWindow) {
		return ""
	}
	// 近 20 步内已查过 KB / 已走 skill 中间件 → 不提醒（tool_executions 是 KB 检索的真源）。
	var n int
	const q = `SELECT COUNT(*) FROM (
		SELECT tool_name, arguments FROM tool_executions WHERE conversation_id = ?
		ORDER BY rowid DESC LIMIT 20
	) t WHERE t.tool_name IN ('search_knowledge_base','list_knowledge_risk_types','skill')
		OR lower(t.arguments) LIKE '%"tool":"skill"%'
		OR lower(t.arguments) LIKE '%"tool": "skill"%'
		OR lower(t.arguments) LIKE '%"skill":%'
		OR lower(t.arguments) LIKE '%"skill": %'
		OR lower(t.arguments) LIKE '%"tool":"search_knowledge_base"%'`
	if err := db.DB.QueryRowContext(ctx, q, convID).Scan(&n); err != nil || n > 0 {
		return ""
	}
	return fmt.Sprintf(knowledgeTriggerWarnTemplate, hitFace, knowledgeTriggerFaceSkills(hitFace))
}

// skillHintSuppressWindow 是「会话内加载过技能」的抑制窗口。
// 取 30 分钟：一轮烛龙最长 60 分钟，但提醒的价值在"开局前 30 分钟内没加载"，
// 窗口再长会让中途换面时的提醒彻底失效（技能口径是"每面都要先加载"）。
const skillHintSuppressWindow = 30 * time.Minute

// 会话级技能调用登记（R-A9 的 ① 收敛）：
// skill 工具不落 tool_executions / tool_stats 的会话维度，A9 抑制必须有自己的真源。
// 这里刻意用**进程内 map + 时间戳**（不建表、不落库、重启清零）：
// 只是提示抑制，丢失的代价 = 多提醒一次，比为一个提示加表划算。
var skillCallRegistry struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// MarkConversationSkillCalled 登记「该会话刚成功调用过 skill」（handler 在 skill 工具
// 结果事件里调用；进程内计数，不写库）。
func MarkConversationSkillCalled(conversationID string) {
	convID := strings.TrimSpace(conversationID)
	if convID == "" {
		return
	}
	skillCallRegistry.mu.Lock()
	defer skillCallRegistry.mu.Unlock()
	if skillCallRegistry.last == nil {
		skillCallRegistry.last = map[string]time.Time{}
	}
	skillCallRegistry.last[convID] = time.Now()
	// 防守：登记表按会话增长，超过 4096 条时清掉过期项，避免长跑进程内存无界。
	if len(skillCallRegistry.last) > 4096 {
		cutoff := time.Now().Add(-skillHintSuppressWindow)
		for k, ts := range skillCallRegistry.last {
			if ts.Before(cutoff) {
				delete(skillCallRegistry.last, k)
			}
		}
	}
}

// conversationSkillRecentlyCalled 报告该会话是否在 window 内调用过 skill。
func conversationSkillRecentlyCalled(conversationID string, now time.Time, window time.Duration) bool {
	convID := strings.TrimSpace(conversationID)
	if convID == "" {
		return false
	}
	if window <= 0 {
		window = skillHintSuppressWindow
	}
	skillCallRegistry.mu.Lock()
	defer skillCallRegistry.mu.Unlock()
	ts, ok := skillCallRegistry.last[convID]
	if !ok {
		return false
	}
	return now.Sub(ts) <= window
}

// knowledgeTriggerWarnTemplate 是 A9 提醒的文案模板(%s = 技术面,%s = 本面推荐技能)。
//
// 抽成常量是为了让单测能直接断言文案要点(先 skill 加载 / risk_type 口径 / 连续 2 次空纠偏),
// 运行时行为与内联写法完全一致。
const knowledgeTriggerWarnTemplate = "[coverage-gate] 提醒:你正在进入「%s」这个技术面,但近 20 步内没有检索知识库、也没加载对应技能。" +
	"这个面在库里有成体系的条目(如 `KB-RT-02-前端硬编码密钥与签名伪造`、`KB-REV-02-app-sign-sdk-canonical`)。" +
	"**先 skill 加载 1-2 个(本面推荐:%s),再 search_knowledge_base**" +
	"(`search_knowledge_base(query='<技术面>+<组件>+想要的结论')`,命中就 read 2-3 条判据段,再动手);" +
	"`risk_type` 只传平台真实类目(如「Web测试专篇」),拿不准就不传。" +
	"**KB 空 1 次就换词/加载技能,连续 2 次空禁止裸奔继续** —— 回头加载技能再动手。" +
	"技能/KB 命中必须改造到本目标(换它的参数名/它的编码/它的业务对象/它的版本分支),照搬=失败;" +
	"两种都空才允许自造手法,并在 fact 写「已查 KB(词:X)+已载技能(Y)」无命中。\n"

// knowledgeTriggerFaceSkills 是「技术面 → 优先加载的技能名」映射(A9 提醒与技能清单共用同一口径)。
// 未登记的面返回通用兜底:让模型按清单里各条 `触发:` 自行匹配。
func knowledgeTriggerFaceSkills(face string) string {
	if s, ok := knowledgeTriggerFaceSkillMap[face]; ok {
		return s
	}
	return "按技能清单里各条 `触发:` 匹配(拿不准就先加载 reverse-engineering)"
}

// knowledgeTriggerFaceSkillMap 覆盖 knowledgeTriggerSignals 的全部八个面。
var knowledgeTriggerFaceSkillMap = map[string]string{
	"签名还原/风控参数":        "mobile-and-thick-client / reverse-engineering",
	"加密与编码":            "crypto-attacks",
	"反序列化":             "deserialization-and-rce",
	"文件上传与预览管线":        "file-traversal-and-upload",
	"云凭证":              "cloud-container-attack",
	"域认证":              "active-directory-attack",
	"协议逆向":             "reverse-engineering",
	"前端 bundle 取接口与密钥": "mobile-and-thick-client",
}

// knowledgeTriggerSignal 是"技术面关键词 → 面名"的映射(小写子串匹配)。
type knowledgeTriggerSignal struct {
	kw   string
	face string
}

// knowledgeTriggerSignals 覆盖"最容易返工"的八个面;关键词按具体度排序,先命中哪个就报哪个。
var knowledgeTriggerSignals = []knowledgeTriggerSignal{
	// 签名 / 风控参数还原
	{"x-pcs", "签名还原/风控参数"}, {"x-pcs-signature", "签名还原/风控参数"},
	{"hmac", "签名还原/风控参数"}, {"signature", "签名还原/风控参数"},
	{"签名", "签名还原/风控参数"}, {"验签", "签名还原/风控参数"},
	{"nonce", "签名还原/风控参数"}, {"timestamp+sign", "签名还原/风控参数"},
	// 加密与编码
	{"aes-", "加密与编码"}, {"aes_", "加密与编码"}, {"sm2", "加密与编码"},
	{"rsa-", "加密与编码"}, {"jwt", "加密与编码"}, {"解密", "加密与编码"},
	// 序列化
	{"反序列化", "反序列化"}, {"unserialize", "反序列化"}, {"serializ", "反序列化"},
	{"viewstate", "反序列化"}, {"pickle", "反序列化"},
	// 上传 / 预览管线
	{"上传", "文件上传与预览管线"}, {"upload", "文件上传与预览管线"}, {"multipart", "文件上传与预览管线"},
	// 云凭证
	{"getosspolicy", "云凭证"}, {"oss-policy", "云凭证"}, {"sts-", "云凭证"},
	{"accesskey", "云凭证"}, {"s3://", "云凭证"},
	// 域认证
	{"kerberos", "域认证"}, {"adcs", "域认证"}, {"ntlm", "域认证"}, {"dcsync", "域认证"},
	// 协议逆向
	{"wsse", "协议逆向"}, {"mqtt", "协议逆向"}, {"grpc", "协议逆向"}, {"protobuf", "协议逆向"},
	// 前端 bundle 取接口与密钥
	{"_nuxt", "前端 bundle 取接口与密钥"}, {"webpack", "前端 bundle 取接口与密钥"},
	{"envinfo", "前端 bundle 取接口与密钥"}, {"chunk", "前端 bundle 取接口与密钥"},
}

// knowledgeNonActingTools 是"提及技术面 ≠ 在该面上作业"的工具(记账/检索/读写文件)。
var knowledgeNonActingTools = map[string]bool{
	"search_knowledge_base": true, "list_knowledge_risk_types": true, "skill": true,
	"upsert_project_fact": true, "get_project_fact": true, "search_project_facts": true,
	"list_project_facts": true, "deprecate_project_fact": true, "fact_add": true,
	"write_file": true, "read_file": true, "edit_file": true, "ls": true, "glob": true, "grep": true,
	"create_asset": true, "update_asset": true, "query_assets": true, "get_asset": true,
	"record_entrypoint": true, "list_entrypoints": true, "mark_face_done": true, "coverage_report": true,
	"record_vulnerability": true, "update_vulnerability_status": true, "list_vulnerabilities": true,
	"get_vulnerability": true, "probe_plan": true,
	// deliver_gate:只读闸门判定。它的 agent_report 常带"签名/上传/反序列化"等技术面词,
	// 但那是**上游报告的引用**,不是本次在做该面 → 归"提及技术面 ≠ 在该面上作业"。
	"deliver_gate": true,
}

// cveLookupWarnText 返回空字符串表示"查过,不用提醒"。
//
// 判据:本会话里存在**真的查证动作**,任一即可 ——
//   - exec 里出现 cve_db.py(离线 CVE 库)、arsenal(武库索引)、nuclei -t(定向模板);
//   - 非 face_probe/mark_face_done 的工具参数里出现 cve / poc(如知识库检索、联网检索)。
//
// face_probe(face=cve) 本身不算:它只做指纹,返回「未命中已知指纹」时什么都没证明。
func cveLookupWarnText(ctx context.Context, db *database.DB, convID string) string {
	if db == nil || db.DB == nil || strings.TrimSpace(convID) == "" {
		return ""
	}
	// 只看"近 40 步":2026-10-28 修 —— 原先查全会话,一条旧的 `which nuclei` 就会把之后
	// 所有 cve 盖章永久放行(2026-10-27 乐橙第三轮实测:3 个 cve 面标 done 而本轮 0 次检索)。
	const q = `SELECT COUNT(*) FROM (
		SELECT tool_name, arguments FROM tool_executions WHERE conversation_id = ?
		ORDER BY rowid DESC LIMIT 40
	) t WHERE (
		lower(t.arguments) LIKE '%cve_db%'
		OR lower(t.arguments) LIKE '%arsenal%'
		OR lower(t.arguments) LIKE '%nuclei -t%'
		OR (t.tool_name NOT IN ('face_probe','mark_face_done','coverage_report')
		    AND (lower(t.arguments) LIKE '%cve-%' OR lower(t.arguments) LIKE '%cve %' OR lower(t.arguments) LIKE '%cve/%'
		         OR lower(t.arguments) LIKE '%poc%')))`
	var n int
	if err := db.DB.QueryRowContext(ctx, q, convID).Scan(&n); err != nil || n > 0 {
		return ""
	}
	return "[coverage-gate] 提醒:cve 面要标 done/na,但本会话没有任何 CVE/武库检索痕迹" +
		"(exec 里的 `cve_db.py` / `arsenal.json` / `nuclei -t`,或带 cve 的知识库检索)。" +
		"**指纹未命中 ≠ 没有组件漏洞**——请先 `python3 scripts/cve_db.py -p <产品>` 或 " +
		"`-c CVE-xxxx-xxxxx` 查一次,把检索词与命中数写进 upsert_project_fact,再收口;" +
		"若确实查不到,就在 note 里写「未能查证 + 查了什么」,不要用记忆代替查证。\n"
}

// portEvidenceWarnText 返回空字符串表示"不需要提醒"(port 已 done / 证据够 / 查不到)。
func portEvidenceWarnText(ctx context.Context, store *coverage.Store, convID, asset, face string) string {
	if store == nil || asset == "" {
		return ""
	}
	snap, ok, err := store.FaceSnapshot(ctx, convID, asset, coverage.FacePort)
	if err != nil {
		return ""
	}
	if ok && snap.State == coverage.StateDone {
		if portEvidenceLooksScanned(snap.EvidenceRef + " " + snap.Note) {
			return ""
		}
		// done 但证据里没有端口扫描痕迹:仍然提醒(盖章不等于扫过)
		return fmt.Sprintf("[coverage-gate] 提醒:%s 的 port 面已标 done,但 evidence_ref 里没有端口扫描痕迹"+
			"(nmap/masscan/rustscan/top1000/端口)。若还没扫,请先补端口侦察并把真实输出路径写进 evidence_ref;"+
			"若扫过,请把证据路径改准确。\n", asset)
	}
	return fmt.Sprintf("[coverage-gate] 提醒:你正要进入 %s 的 %s 面,但它的 port 面还没标 done、也没有端口扫描证据。"+
		"路径/参数结论如果建立在未知服务上,很容易白打——建议先 face_probe(asset=%s, face=port) 或跑 nmap -sT --top-ports 1000,"+
		"把结果写进 mark_face_done(face=port, evidence_ref=<输出路径>) 后再回来。\n", asset, face, asset)
}

// coverageGate 是给两处 ToolsConfig 用的便捷构造(无 db 时返回空中间件,不改变行为)。
func coverageGate(db *database.DB, conversationID string, logger *zap.Logger, cfg *config.Config) compose.ToolMiddleware {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return compose.ToolMiddleware{}
	}
	return newCoverageGateMiddleware(coverage.NewStore(db.DB), conversationID, logger, cfg, db)
}

// ---------- 时间盒(per-asset step budget,2026-10-21 平衡版) ----------
//
// 背景:上一版只加了"深挖",没加"何时停",导致单个资产可以合法吃满整场预算
// (实测 ncc2:example.com 从 23:18 干到 00:55)。这里按资产计步,到阈值提醒收口。

const (
	assetStepSoftWarn = 40 // 40 步:软提醒
	assetStepHardWarn = 60 // 60 步:强提醒(仍未收口)
)

type assetBudgetState struct {
	mu     sync.Mutex
	steps  map[string]int
	warned map[string]int
}

func newAssetBudgetState() *assetBudgetState {
	return &assetBudgetState{steps: map[string]int{}, warned: map[string]int{}}
}

// bump 记录一次"落在该资产上的动作",返回累计步数与本次应发的提醒级别(0=不提醒)。
func (s *assetBudgetState) bump(key string, soft, hard int) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps[key]++
	n := s.steps[key]
	level := 0
	if n >= hard && s.warned[key] < 2 {
		level = 2
	} else if n >= soft && s.warned[key] < 1 {
		level = 1
	}
	if level > 0 {
		s.warned[key] = level
	}
	// 防无界增长
	if len(s.steps) > 1024 {
		for k, v := range s.steps {
			if v == 0 {
				delete(s.steps, k)
				delete(s.warned, k)
			}
		}
	}
	return n, level
}

func timeBoxWarnText(asset string, steps int, level int, strategy string, soft int) string {
	if level >= 2 {
		return fmt.Sprintf("[time-box] %s 已累计 %d 步仍未收口。时间盒判定:再没有新增证据就立即 mark_face_done(blocked, note=\"时间盒到,待续\") 并换下一个资产——"+
			"目标是\"漏洞找全\",不是\"一个站打穿\"。\n", asset, steps)
	}
	return fmt.Sprintf("[time-box] %s 已累计 %d 步(软阈值 %d)。若下一步仍无新增证据(无新入口/新漏洞/新可利用面),请收口换下一个资产;"+
		"有明确高价值线索可续 20 步并在 upsert_project_fact 写明理由(仅一次)。\n", asset, steps, soft)
}
