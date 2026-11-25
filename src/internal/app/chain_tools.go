package app

// chain_tools.go —— 利用链账本 MCP 工具(烛龙 M1 · 任务 B / 2026-11-05,spec v2 锚定修正同日)
//
// 四个内置工具(数据层在 internal/zhulong/chain.go):
//
//	zl_chain_list    看账本:哪些链还 open、各自推到第几个台阶、锚在哪个资产上
//	zl_chain_open    为新确认的漏洞/假设开一条链(必须锚:target_asset + hypothesis_type)
//	zl_chain_attempt 每次尝试落一行(payload + 原始报文路径 + verdict),并把 rung 抬到 max
//	zl_chain_close   收口:exploited(需 rung>=1 + 证据) 或 blocked(需 证据+枚举面+未覆盖面 三件)
//
// 三条确定性判据(不靠模型自报,spec §0):
//  1. 链必须锚在本目标自己的模型上:hypothesis_type 必填,四类锚定假设必须给 target_model_ref,
//     且该 fact_key 必须在 project_facts 里真实存在(否则就是通用 n-day 八股);
//  2. 除 rejected 外,每次尝试必须有 evidence_ref 且必须是绝对路径 / URL;
//  3. blocked 必须三件齐全,exploited 必须 rung>=1 且至少有证据。
//
// 注册要点见 docs/zh-CN/TOOL-REGISTRATION.md 的 7 点检查表(常量两处 + 授权分支一处)。

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/zhulong"

	"go.uber.org/zap"
)

// chainStoreFrom 取链账本 store,并就地幂等建表(表不存在时就地补,失败返回 nil 降级)。
//
// 建表是 CREATE TABLE IF NOT EXISTS,重复调用无副作用;放在这里而不是只靠 register 时一次,
// 是因为 record_vulnerability 自动挂链可能先于工具注册被调用(Lead 还没接线时也不崩)。
func chainStoreFrom(ctx context.Context, db *database.DB, logger *zap.Logger) *zhulong.ChainStore {
	if db == nil || db.DB == nil {
		return nil
	}
	store, err := zhulong.NewChainStore(db.DB)
	if err != nil {
		if logger != nil {
			logger.Warn("链账本 store 不可用", zap.Error(err))
		}
		return nil
	}
	if err := store.EnsureSchema(ctx); err != nil {
		if logger != nil {
			logger.Warn("链账本建表失败(链能力降级)", zap.Error(err))
		}
		return nil
	}
	return store
}

// chainLooksLikeEvidenceRef 与 zhulong.looksLikeEvidenceRef 同口径:
// 绝对路径、http(s) URL、或带 scheme 的 URI。包内跨层无法复用未导出函数,故本地复制一份。
func chainLooksLikeEvidenceRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "~/") {
		return true
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if c == ':' {
			scheme := ref[:i]
			if scheme == "" {
				return false
			}
			for j := 0; j < len(scheme); j++ {
				ch := scheme[j]
				ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
					(j > 0 && ((ch >= '0' && ch <= '9') || ch == '+' || ch == '.' || ch == '-'))
				if !ok {
					return false
				}
			}
			return i+2 < len(ref) && ref[i+1] == '/' && ref[i+2] == '/'
		}
	}
	return false
}

// normalizeChainAsset 把 URL / host:port / 带路径的目标串归一成资产名(小写、去 scheme/path/端口/www.)。
func normalizeChainAsset(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") { // IPv6
		if i := strings.Index(s, "]"); i > 0 {
			s = s[1:i]
		}
	} else if i := strings.LastIndex(s, ":"); i > 0 {
		if _, err := strconv.Atoi(s[i+1:]); err == nil {
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "www.")
	return s
}

// chainAssetHints 返回本项目已登记资产里与目标最像的几条(用于报错时提示正确写法)。
func chainAssetHints(db *database.DB, projectID string, limit int) []string {
	if db == nil || limit <= 0 {
		return nil
	}
	query := `SELECT host FROM assets WHERE TRIM(host) <> ''`
	var args []interface{}
	if projectID != "" {
		query += ` AND project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY last_seen_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			continue
		}
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// chainAssetRegistered 宽松校验 target_asset 是否落在本项目 assets 里。
//
// 宽松策略(避免为了记账反复卡住真正在干活的人):
//   - 归一化后精确匹配 host / domain / ip 任一即算命中;
//   - 再尝试后缀匹配(登记的 host 以资产名结尾,覆盖 shop.example.com ↔ example.com);
//   - 本项目一张资产都没登记时不做判定(返回 true + empty 标记),让链先开得起来。
func chainAssetRegistered(db *database.DB, projectID, asset string) (ok bool, projectHasAssets bool) {
	if db == nil {
		return true, false
	}
	h := normalizeChainAsset(asset)
	if h == "" {
		return false, false
	}
	countQuery := `SELECT COUNT(*) FROM assets`
	var countArgs []interface{}
	if projectID != "" {
		countQuery += ` WHERE project_id = ?`
		countArgs = append(countArgs, projectID)
	}
	var total int
	if err := db.QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		return true, false // 表/查询异常不阻塞业务
	}
	if total == 0 {
		return true, false
	}

	// 注意:OR 组必须整体加括号,否则后面的 AND project_id=? 只约束最后一个 LIKE 项
	// (SQL 里 AND 优先级高于 OR),会把别的项目同名资产算成本项目命中。
	query := `SELECT COUNT(*) FROM assets WHERE (
    LOWER(TRIM(host)) = ? OR LOWER(TRIM(domain)) = ? OR TRIM(ip) = ?
    OR LOWER(TRIM(host)) LIKE ? ESCAPE '\')`
	args := []interface{}{h, h, h, "%" + escapeLike(h)}
	if projectID != "" {
		query += ` AND project_id = ?`
		args = append(args, projectID)
	}
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		return true, true
	}
	return n > 0, true
}

// escapeLike 转义 LIKE 通配符(资产名里出现 % / _ 时不要把整表匹配进来)。
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	return strings.ReplaceAll(s, "_", "\\_")
}

// resolveTargetModelRef 在该会话所属项目里找「这个资产的目标模型条目」(…-model 结尾的 fact_key)。
// 找到即返回该 fact_key(供开链锚定),找不到返回空串(调用方降级为 other/component-known)。
func resolveTargetModelRef(db *database.DB, projectID, asset string) string {
	if db == nil {
		return ""
	}
	h := normalizeChainAsset(asset)
	if h == "" {
		return ""
	}
	query := `SELECT fact_key FROM project_facts WHERE fact_key LIKE ? ESCAPE '\'`
	args := []interface{}{"%/" + escapeLike(h) + "-model"}
	if projectID != "" {
		query += ` AND project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY LENGTH(fact_key) ASC LIMIT 1`
	var key string
	if err := db.QueryRow(query, args...).Scan(&key); err != nil {
		return ""
	}
	return strings.TrimSpace(key)
}

// chainProjectFactExists 校验 target_model_ref 指向的 fact_key 真实存在(项目内优先,未绑项目则全库)。
func chainProjectFactExists(db *database.DB, projectID, factKey string) bool {
	if db == nil || strings.TrimSpace(factKey) == "" {
		return false
	}
	query := `SELECT COUNT(*) FROM project_facts WHERE fact_key = ?`
	args := []interface{}{strings.TrimSpace(factKey)}
	if projectID != "" {
		query += ` AND project_id = ?`
		args = append(args, projectID)
	}
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		// 表异常时不误杀业务(降级放行),但要让日志看得见
		return true
	}
	return n > 0
}

// chainShortHash 生成稳定的短 id(同 conversation+finding_key 重复写不会长出新节点)。
func chainShortHash(parts ...string) string {
	sum := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

// zlChainRiskScore 把 rung 映射成攻击链节点的风险分(spec §2 B3 的 40/60/70/85/95/99)。
func zlChainRiskScore(rung int) int {
	switch {
	case rung >= zhulong.ChainRungLateral:
		return 99
	case rung >= zhulong.ChainRungExecute:
		return 95
	case rung >= zhulong.ChainRungUpload:
		return 85
	case rung >= zhulong.ChainRungWrite:
		return 70
	case rung >= zhulong.ChainRungAuthBypass:
		return 60
	default: // confirmed / sensitive-read
		return 40
	}
}

// persistExploitChain 在链被收口成 exploited 时,把「目标资产 → 漏洞节点」写进攻击链图谱。
//
// 字段对齐 internal/database/attackchain.go(先读后写,不猜):
//   - attack_chain_nodes(id, conversation_id, node_type, node_name, tool_execution_id, metadata, risk_score)
//   - attack_chain_edges(id, conversation_id, source_node_id, target_node_id, edge_type, weight)
//
// 关键坑:SaveAttackChainNode 用的是 INSERT OR REPLACE,而 edges 上是 ON DELETE CASCADE,
// 重复 replace 源节点会把已有边级联删掉。所以这里先查存在性,只在缺行时调用 Save*。
func persistExploitChain(db *database.DB, logger *zap.Logger, c *zhulong.Chain, targetOverride string) (string, error) {
	if db == nil || c == nil {
		return "", fmt.Errorf("链或数据库不可用")
	}
	convID := strings.TrimSpace(c.ConversationID)
	findingKey := strings.TrimSpace(c.FindingKey)
	if convID == "" || findingKey == "" {
		return "", fmt.Errorf("链缺少 conversation_id / finding_key")
	}

	// ---- 源节点:目标资产(优先用链自己锚定的 target_asset,其次显式参数,最后回落到漏洞记录里的 target)----
	assetName := normalizeChainAsset(c.TargetAsset)
	if assetName == "" {
		assetName = normalizeChainAsset(targetOverride)
	}
	if assetName == "" && strings.HasPrefix(findingKey, "vuln:") {
		if v, err := db.GetVulnerability(strings.TrimPrefix(findingKey, "vuln:")); err == nil && v != nil {
			assetName = normalizeChainAsset(v.Target)
		}
	}

	// ---- 漏洞节点 ----
	nodeID := "zlv_" + chainShortHash(convID, findingKey)
	metadata := map[string]interface{}{
		"source":           "zl_chain",
		"chain_id":         c.ID,
		"finding_key":      findingKey,
		"rung":             c.Rung,
		"state":            c.State,
		"title":            c.Title,
		"target_asset":     c.TargetAsset,
		"hypothesis_type":  c.HypothesisType,
		"target_model_ref": c.TargetModelRef,
	}
	metaJSON, _ := json.Marshal(metadata)
	nodeExisted := attackChainNodeExists(db, nodeID)
	if err := db.SaveAttackChainNode(convID, nodeID, "vuln", findingKey, "", string(metaJSON), zlChainRiskScore(c.Rung)); err != nil {
		return "", fmt.Errorf("写攻击链节点失败: %w", err)
	}

	if assetName == "" {
		return fmt.Sprintf("node=%s(%s)", nodeID, map[bool]string{true: "复用", false: "新建"}[nodeExisted]), nil
	}

	// ---- 资产节点 + exploit 边 ----
	sourceID := "zla_" + chainShortHash(convID, assetName)
	if !attackChainNodeExists(db, sourceID) {
		srcMeta, _ := json.Marshal(map[string]interface{}{
			"source": "zl_chain", "target_asset": assetName,
		})
		if err := db.SaveAttackChainNode(convID, sourceID, "target", assetName, "", string(srcMeta), 0); err != nil {
			return "", fmt.Errorf("写资产节点失败: %w", err)
		}
	}
	edgeID := "zle_" + chainShortHash(convID, sourceID, nodeID)
	weight := c.Rung + 3
	if weight < 1 {
		weight = 1
	}
	if weight > 10 {
		weight = 10
	}
	if !attackChainEdgeExists(db, edgeID) {
		if err := db.SaveAttackChainEdge(convID, edgeID, sourceID, nodeID, "exploit", weight); err != nil {
			return "", fmt.Errorf("写攻击链边失败: %w", err)
		}
	}
	return fmt.Sprintf("node=%s asset=%s edge=exploit(w=%d)", nodeID, assetName, weight), nil
}

func attackChainNodeExists(db *database.DB, id string) bool {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM attack_chain_nodes WHERE id=?`, id).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

func attackChainEdgeExists(db *database.DB, id string) bool {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM attack_chain_edges WHERE id=?`, id).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// autoOpenChainForVulnerability 记录漏洞成功后自动挂一条链(spec §2 B3)。
//
// 只对 critical/high/medium 挂;同 conversation+finding_key 已有 open 链则复用。
// hypothesis_type 的口径:本项目已建该资产的目标模型条目 → own-code + target_model_ref;
// 否则退化成 other(诚实标注「还没锚定」,闸门不会把它算进 specific)。
func autoOpenChainForVulnerability(ctx context.Context, db *database.DB, logger *zap.Logger, conversationID, vulnID, title, severity, target string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium":
	default:
		return ""
	}
	store := chainStoreFrom(ctx, db, logger)
	if store == nil {
		return ""
	}
	projectID := ""
	if pid, err := db.GetConversationProjectID(conversationID); err == nil {
		projectID = strings.TrimSpace(pid)
	}
	asset := normalizeChainAsset(target)
	if asset == "" {
		asset = normalizeChainAsset(targetOverrideFallback(title))
	}
	if asset == "" {
		asset = "unknown-target"
	}
	modelRef := resolveTargetModelRef(db, projectID, asset)
	hyp := zhulong.HypOther
	if modelRef != "" {
		hyp = zhulong.HypOwnCode
	}
	chain := &zhulong.Chain{
		ConversationID: conversationID,
		FindingKey:     "vuln:" + vulnID,
		Title:          title,
		Rung:           zhulong.ChainRungConfirmed,
		State:          zhulong.ChainOpen,
		Hypothesis:     fmt.Sprintf("已确认 %s 级漏洞,验证它能把攻击推进到下一个台阶", strings.ToLower(strings.TrimSpace(severity))),
		TargetAsset:    asset,
		HypothesisType: hyp,
		TargetModelRef: modelRef,
	}
	id, err := store.Open(ctx, chain)
	if err != nil {
		if logger != nil {
			logger.Warn("漏洞自动挂链失败(不阻塞漏洞记录)", zap.String("vuln_id", vulnID), zap.Error(err))
		}
		return ""
	}
	if logger != nil {
		logger.Info("漏洞已挂利用链", zap.String("vuln_id", vulnID), zap.String("chain_id", id), zap.String("hypothesis_type", hyp))
	}
	return id
}

// targetOverrideFallback 从标题里兜底猜一个资产名(标题常以 URL / 域名开头)。
func targetOverrideFallback(title string) string {
	t := strings.TrimSpace(title)
	if t == "" {
		return ""
	}
	fields := strings.FieldsFunc(t, func(r rune) bool {
		return r == ' ' || r == '，' || r == ',' || r == '、' || r == '|'
	})
	for _, f := range fields {
		if strings.Contains(f, ".") && !strings.Contains(f, "存在") {
			return f
		}
	}
	return ""
}

// chainStateLine 生成一行账本摘要(不依赖摘要器,天然不会被压缩)。
func chainStateLine(ctx context.Context, store *zhulong.ChainStore, convID string) string {
	if store == nil {
		return ""
	}
	total, open, exploited, depth, specific, err := store.Stats(ctx, convID)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("链账本: total=%d open=%d exploited=%d depth=%d/6 specific=%d", total, open, exploited, depth, specific)
}

// registerChainTools 注册 4 个利用链账本工具。
//
// 由 internal/app/app.go 调用(Lead 接线):
//
//	registerChainTools(mcpServer, db, log.Logger)
func registerChainTools(mcpServer *mcp.Server, db *database.DB, logger *zap.Logger) {
	store := chainStoreFrom(context.Background(), db, logger)
	if store == nil {
		if logger != nil {
			logger.Info("利用链账本工具未注册(无数据库或建表失败)")
		}
		return
	}

	// ---------- 1) zl_chain_open ----------
	openTool := mcp.Tool{
		Name: builtin.ToolZLChainOpen,
		Description: "为一条「针对这个目标自己」的可利用性假设开链(账本行)。链会被闸门统计:open 链存在时禁止交卷。\n" +
			"必填锚定三件:finding_key(稳定键,如 vuln:<id> / asset:port:path)、target_asset(具体资产 host)、hypothesis_type。" +
			"hypothesis_type=business-logic|own-code|own-contract|diff-probe 时还必须给 target_model_ref(指向 project_facts.fact_key,如 target/<asset>-model,且必须已用 upsert_project_fact 建好);" +
			"component-known(已知组件 n-day)/ other 可不锚模型条目,但不会计入 specific 口径,交付质量打折。\n" +
			"同 conversation+finding_key 已有 open 链时复用,不重复开。",
		ShortDescription: "开一条利用链(必须锚定目标资产与假设类型)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"finding_key": map[string]interface{}{
					"type":        "string",
					"description": "稳定键:漏洞用 vuln:<漏洞ID>,其他用 asset:port:path 形式",
				},
				"title": map[string]interface{}{"type": "string", "description": "一句话说明这条链要打通什么"},
				"hypothesis_type": map[string]interface{}{
					"type":        "string",
					"description": "business-logic|own-code|own-contract|component-known|diff-probe|other",
					"enum":        zhulong.ChainHypothesisTypes,
				},
				"target_asset": map[string]interface{}{
					"type":        "string",
					"description": "该链针对的具体资产(host 或 host:port),须落在本项目 assets 里",
				},
				"target_model_ref": map[string]interface{}{
					"type":        "string",
					"description": "指向 project_facts.fact_key(该目标自己的模型条目,如 target/<asset>-model);四类锚定假设必填",
				},
				"hypothesis": map[string]interface{}{"type": "string", "description": "假设内容:换成什么输入/身份,期望发生什么"},
				"rung":       map[string]interface{}{"type": "integer", "description": "初始台阶 0-6,默认 0(仅确认)"},
			},
			"required": []string{"finding_key", "title", "hypothesis_type", "target_asset"},
		},
	}
	mcpServer.RegisterTool(openTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		convID := conversationIDFromToolCtx(ctx)
		if convID == "" {
			return nil, fmt.Errorf("zl_chain_open: 无法确定当前对话(需在对话上下文中调用)")
		}
		findingKey := strings.TrimSpace(strArg(args, "finding_key"))
		if findingKey == "" {
			return nil, fmt.Errorf("zl_chain_open: 缺少 finding_key(用 vuln:<id> 或 asset:port:path)")
		}
		title := strings.TrimSpace(strArg(args, "title"))
		if title == "" {
			return nil, fmt.Errorf("zl_chain_open: 缺少 title(一句话说明这条链要打通什么)")
		}
		rawHyp := strings.TrimSpace(strArg(args, "hypothesis_type"))
		if rawHyp == "" {
			return nil, fmt.Errorf("zl_chain_open: 缺少 hypothesis_type,必须是 %s 之一——"+
				"不写类型等于通用 n-day/清单式试错,不算交付", strings.Join(zhulong.ChainHypothesisTypes, "|"))
		}
		hyp := zhulong.NormalizeHypothesisType(rawHyp)
		if !zhulong.ValidHypothesisType(hyp) {
			return nil, fmt.Errorf("zl_chain_open: hypothesis_type=%q 非法,必须是 %s 之一",
				rawHyp, strings.Join(zhulong.ChainHypothesisTypes, "|"))
		}
		asset := normalizeChainAsset(strArg(args, "target_asset"))
		if asset == "" {
			return nil, fmt.Errorf("zl_chain_open: 缺少 target_asset(这条链针对哪个具体资产,host 或 host:port)")
		}
		projectID := ""
		if pid, err := db.GetConversationProjectID(convID); err == nil {
			projectID = strings.TrimSpace(pid)
		}

		modelRef := strings.TrimSpace(strArg(args, "target_model_ref"))
		if zhulong.RequiresTargetModel(hyp) && modelRef == "" {
			return nil, fmt.Errorf("zl_chain_open: hypothesis_type=%s 必须提供 target_model_ref——"+
				"先用 upsert_project_fact 建目标模型条目 target/%s-model,再把该 fact_key 填进来", hyp, asset)
		}
		if modelRef != "" && !chainProjectFactExists(db, projectID, modelRef) {
			return nil, fmt.Errorf("zl_chain_open: target_model_ref=%q 在 project_facts 里不存在——"+
				"先用 upsert_project_fact 建目标模型条目 target/%s-model(项目=%s),再开链", modelRef, asset, orUnbound(projectID))
		}
		if ok, hasAssets := chainAssetRegistered(db, projectID, asset); !ok && hasAssets {
			hints := chainAssetHints(db, projectID, 5)
			return nil, fmt.Errorf("zl_chain_open: target_asset=%q 未落在本项目 assets 里(项目=%s),链必须锚到真实资产。"+
				"先 create_asset 登记该资产,或改用已登记名;当前已登记示例: %s",
				asset, orUnbound(projectID), strings.Join(hints, ", "))
		}

		chain := &zhulong.Chain{
			ConversationID: convID,
			FindingKey:     findingKey,
			Title:          title,
			Rung:           intArgDefault(args, "rung", zhulong.ChainRungConfirmed),
			Hypothesis:     strings.TrimSpace(strArg(args, "hypothesis")),
			TargetAsset:    asset,
			HypothesisType: hyp,
			TargetModelRef: modelRef,
		}
		id, err := store.Open(ctx, chain)
		if err != nil {
			return nil, fmt.Errorf("zl_chain_open: %w", err)
		}
		rung := chain.Rung
		if cur, gerr := store.Get(ctx, id); gerr == nil {
			rung = cur.Rung
		}
		anchor := modelRef
		if anchor == "" {
			anchor = "-"
		}
		msg := fmt.Sprintf("CHAIN=%s state=%s rung=%d hyp=%s target=%s anchor=%s\n"+
			"下一步: zl_chain_attempt(chain_id=%s, rung=<下一个台阶>, payload=<这个变体>, verdict=progress, evidence_ref=<原始报文绝对路径或URL>)",
			id, zhulong.ChainOpen, rung, hyp, asset, anchor, id)
		if line := chainStateLine(ctx, store, convID); line != "" {
			msg += "\n" + line
		}
		return textResult(msg, false), nil
	})

	// ---------- 2) zl_chain_attempt ----------
	attemptTool := mcp.Tool{
		Name: builtin.ToolZLChainAttempt,
		Description: "记录一次利用尝试(链推进的原子事实),并把链的 rung 抬到本次台阶(只能升不能降)。\n" +
			"台阶:0 确认 → 1 读到敏感数据 → 2 认证绕过 → 3 写入 → 4 上传 → 5 执行 → 6 横向。\n" +
			"verdict=progress(有增量)|exploited(本变体打穿)|rejected(被拒,什么都没发生)|blocked(被挡住,带拦截证据)。" +
			"除 rejected 外 evidence_ref 必填,且必须是绝对路径或 URL——「看起来正常」这类自述不算证据。\n" +
			"注意:verdict=exploited 只是本变体的事实,链要收口仍须 zl_chain_close(state=exploited)。",
		ShortDescription: "记录一次利用尝试并抬高链的台阶",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"chain_id": map[string]interface{}{"type": "string", "description": "链 id(zl_chain_open / zl_chain_list 得到)"},
				"rung":     map[string]interface{}{"type": "integer", "description": "本次尝试到达的台阶 0-6"},
				"payload":  map[string]interface{}{"type": "string", "description": "具体用的 payload / 请求 / 变体(可复现的最小形态)"},
				"verdict": map[string]interface{}{
					"type":        "string",
					"description": "progress|exploited|rejected|blocked",
					"enum": []string{zhulong.AttemptVerdictProgress, zhulong.AttemptVerdictExploited,
						zhulong.AttemptVerdictRejected, zhulong.AttemptVerdictBlocked},
				},
				"evidence_ref": map[string]interface{}{
					"type":        "string",
					"description": "原始报文/截图/日志落盘文件的绝对路径或 URL;除 rejected 外必填",
				},
				"summary": map[string]interface{}{"type": "string", "description": "一句话结论:看到什么、说明什么"},
			},
			"required": []string{"chain_id", "rung", "payload", "verdict"},
		},
	}
	mcpServer.RegisterTool(attemptTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		convID := conversationIDFromToolCtx(ctx)
		if convID == "" {
			return nil, fmt.Errorf("zl_chain_attempt: 无法确定当前对话")
		}
		chainID := strings.TrimSpace(strArg(args, "chain_id"))
		if chainID == "" {
			return nil, fmt.Errorf("zl_chain_attempt: 缺少 chain_id(先用 zl_chain_list 看现有链)")
		}
		if _, ok := args["rung"]; !ok {
			return nil, fmt.Errorf("zl_chain_attempt: 缺少 rung(本次尝试到达的台阶 0-6)")
		}
		payload := strings.TrimSpace(strArg(args, "payload"))
		if payload == "" {
			return nil, fmt.Errorf("zl_chain_attempt: 缺少 payload(具体用的请求/变体,要能复现)")
		}
		verdict := strings.TrimSpace(strArg(args, "verdict"))
		if verdict == "" {
			return nil, fmt.Errorf("zl_chain_attempt: 缺少 verdict(progress|exploited|rejected|blocked)")
		}
		evidenceRef := strings.TrimSpace(strArg(args, "evidence_ref"))
		if verdict != zhulong.AttemptVerdictRejected && evidenceRef == "" {
			return nil, fmt.Errorf("zl_chain_attempt: verdict=%s 必须带 evidence_ref(原始报文/截图/日志的绝对路径或 URL)", verdict)
		}
		if evidenceRef != "" && !chainLooksLikeEvidenceRef(evidenceRef) {
			return nil, fmt.Errorf("zl_chain_attempt: evidence_ref=%q 不是绝对路径或 URL;"+
				"先把原始报文落盘(如 ./data/ev/<case>/req.txt),不要用自述当证据", evidenceRef)
		}
		// 链必须属于当前会话,避免跨会话污染别人的账本
		chain, err := store.Get(ctx, chainID)
		if err != nil {
			return nil, fmt.Errorf("zl_chain_attempt: %w", err)
		}
		if chain.ConversationID != convID {
			return nil, fmt.Errorf("zl_chain_attempt: 链 %s 不属于当前对话,拒绝写入", chainID)
		}

		attempt := &zhulong.ChainAttempt{
			ChainID:     chainID,
			Rung:        intArgDefault(args, "rung", 0),
			Payload:     payload,
			EvidenceRef: evidenceRef,
			Verdict:     verdict,
			Summary:     strings.TrimSpace(strArg(args, "summary")),
		}
		id, err := store.AddAttempt(ctx, attempt)
		if err != nil {
			return nil, fmt.Errorf("zl_chain_attempt: %w", err)
		}
		cur, _ := store.Get(ctx, chainID)
		curRung := chain.Rung
		if cur != nil {
			curRung = cur.Rung
		}
		msg := fmt.Sprintf("ATTEMPT=%s no=%d verdict=%s rung=%d;CHAIN=%s rung=%d/%d state=%s",
			id, attempt.AttemptNo, verdict, attempt.Rung, chainID, curRung, zhulong.ChainRungMax, chain.State)
		if curRung == zhulong.ChainRungMax {
			msg += "\n已到最高台阶(6 横向):可以 zl_chain_close(state=exploited) 收口。"
		} else {
			msg += fmt.Sprintf("\n下一台阶: %d → %s", curRung+1, chainRungLabel(curRung+1))
		}
		return textResult(msg, false), nil
	})

	// ---------- 3) zl_chain_close ----------
	closeTool := mcp.Tool{
		Name: builtin.ToolZLChainClose,
		Description: "收口一条链(账本终态)。state=exploited(已实证击穿)或 blocked(带证据判死)。\n" +
			"state=exploited 要求:rung>=1(至少降到数据级/认证绕过/写入/上传/执行),且至少有证据(本次 blocker_evidence 或已记录的 attempt evidence_ref)。\n" +
			"state=blocked 要求三件齐全,缺一即拒:blocker_evidence(拦截原始报文/日志的绝对路径或 URL)+ " +
			"enumeration_space(试过哪些变体/多少个/什么方法)+ unverified_space(还有哪一类没试、为什么)。\n" +
			"判死口径(已硬校验):同一台阶至少 3 个不同变体(不同 payload)才算试够;" +
			"rung<6 的 blocked 还必须给 next_rung_blocker(下一阶前置为什么没有)与 max_reachable_rung。" +
			"收口成 exploited 会自动把「目标资产 → 漏洞」写进攻击链图谱。",
		ShortDescription: "收口利用链(exploited 需证据与台阶 / blocked 需三件齐全)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"chain_id": map[string]interface{}{"type": "string", "description": "链 id"},
				"state": map[string]interface{}{
					"type":        "string",
					"description": "exploited|blocked",
					"enum":        []string{zhulong.ChainExploited, zhulong.ChainBlocked},
				},
				"blocker_evidence": map[string]interface{}{
					"type":        "string",
					"description": "拦截原始报文/日志的绝对路径或 URL(blocked 必填)",
				},
				"enumeration_space": map[string]interface{}{
					"type":        "string",
					"description": "试过哪些变体/多少个/什么方法(blocked 必填,判死三要素之一)",
				},
				"unverified_space": map[string]interface{}{
					"type":        "string",
					"description": "还有哪一类没试、为什么(blocked 必填,判死三要素之三)",
				},
				"max_reachable_rung": map[string]interface{}{
					"type":        "integer",
					"description": "这条链的最大可及台阶(0-6)。blocked 时用它声明「在目标模型里穷尽下一阶前置后最高能到哪」;不得高于当前 rung",
				},
				"next_rung_blocker": map[string]interface{}{
					"type":        "string",
					"description": "下一阶为什么到不了:再上一阶需要什么前置、在目标模型里搜过什么、为什么没有(blocked 且 rung<6 必填)",
				},
				"target": map[string]interface{}{
					"type":        "string",
					"description": "可选:攻击链图谱里的源资产名;缺省用链的 target_asset(id 不以 vuln: 开头时建议显式给)",
				},
				"note": map[string]interface{}{"type": "string", "description": "备注(一句话结论)"},
			},
			"required": []string{"chain_id", "state"},
		},
	}
	mcpServer.RegisterTool(closeTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		convID := conversationIDFromToolCtx(ctx)
		if convID == "" {
			return nil, fmt.Errorf("zl_chain_close: 无法确定当前对话")
		}
		chainID := strings.TrimSpace(strArg(args, "chain_id"))
		if chainID == "" {
			return nil, fmt.Errorf("zl_chain_close: 缺少 chain_id")
		}
		state := strings.TrimSpace(strArg(args, "state"))
		if state == "" {
			return nil, fmt.Errorf("zl_chain_close: 缺少 state(exploited|blocked)")
		}
		if state != zhulong.ChainExploited && state != zhulong.ChainBlocked {
			return nil, fmt.Errorf("zl_chain_close: state=%q 非法,只能是 exploited 或 blocked", state)
		}

		chain, err := store.Get(ctx, chainID)
		if err != nil {
			return nil, fmt.Errorf("zl_chain_close: %w", err)
		}
		if chain.ConversationID != convID {
			return nil, fmt.Errorf("zl_chain_close: 链 %s 不属于当前对话,拒绝收口", chainID)
		}

		blockerEvidence := strings.TrimSpace(strArg(args, "blocker_evidence"))
		enumeration := strings.TrimSpace(strArg(args, "enumeration_space"))
		unverified := strings.TrimSpace(strArg(args, "unverified_space"))
		if state == zhulong.ChainBlocked {
			var missing []string
			if blockerEvidence == "" {
				missing = append(missing, "blocker_evidence(拦截原始报文/日志的绝对路径或 URL)")
			}
			if enumeration == "" {
				missing = append(missing, "enumeration_space(试过哪些变体/多少个/什么方法)")
			}
			if unverified == "" {
				missing = append(missing, "unverified_space(还有哪一类没试、为什么)")
			}
			if len(missing) > 0 {
				return nil, fmt.Errorf("zl_chain_close: state=blocked 缺 %s;判死必须三件齐全,无证据的「打不动」不算收口",
					strings.Join(missing, " + "))
			}
		}
		if err := store.Close(ctx, chainID, zhulong.ChainClose{
			State:            state,
			BlockerEvidence:  blockerEvidence,
			Note:             strings.TrimSpace(strArg(args, "note")),
			EnumerationSpace: enumeration,
			UnverifiedSpace:  unverified,
			MaxReachableRung: intArgDefault(args, "max_reachable_rung", -1),
			NextRungBlocker:  strings.TrimSpace(strArg(args, "next_rung_blocker")),
		}); err != nil {
			return nil, fmt.Errorf("zl_chain_close: %w", err)
		}

		cur, _ := store.Get(ctx, chainID)
		if cur == nil {
			cur = chain
		}
		msg := fmt.Sprintf("CHAIN=%s state=%s rung=%d/%d finding_key=%s",
			chainID, cur.State, cur.Rung, zhulong.ChainRungMax, cur.FindingKey)

		if state == zhulong.ChainExploited {
			if summary, perr := persistExploitChain(db, logger, cur, strArg(args, "target")); perr != nil {
				if logger != nil {
					logger.Warn("攻击链落库失败(链已收口,不影响账本)",
						zap.String("chain_id", chainID), zap.Error(perr))
				}
				msg += fmt.Sprintf("\n攻击链落库失败(账本已收口): %v", perr)
			} else if summary != "" {
				msg += "\n攻击链已落库: " + summary
			}
		}
		if line := chainStateLine(ctx, store, convID); line != "" {
			msg += "\n" + line
		}
		return textResult(msg, false), nil
	})

	// ---------- 4) zl_chain_list ----------
	listTool := mcp.Tool{
		Name: builtin.ToolZLChainList,
		Description: "列出当前会话的利用链账本(紧凑表:id | rung | state | hyp | target_asset | finding_key)。\n" +
			"用法:每轮开工先看一次,挑最深的 open 链继续推进;open 链未清零前不要交卷。",
		ShortDescription: "列出利用链账本",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"state": map[string]interface{}{
					"type":        "string",
					"description": "只列某状态:open|exploited|blocked(可选)",
					"enum":        []string{zhulong.ChainOpen, zhulong.ChainExploited, zhulong.ChainBlocked},
				},
				"asset": map[string]interface{}{"type": "string", "description": "只看某资产的链(可选)"},
			},
		},
	}
	mcpServer.RegisterTool(listTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		convID := conversationIDFromToolCtx(ctx)
		if convID == "" {
			return nil, fmt.Errorf("zl_chain_list: 无法确定当前对话")
		}
		state := strings.TrimSpace(strArg(args, "state"))
		if state != "" && state != zhulong.ChainOpen && state != zhulong.ChainExploited && state != zhulong.ChainBlocked {
			return nil, fmt.Errorf("zl_chain_list: state=%q 非法,只能是 open|exploited|blocked", state)
		}
		list, err := store.List(ctx, convID, state)
		if err != nil {
			return nil, fmt.Errorf("zl_chain_list: %w", err)
		}
		assetFilter := normalizeChainAsset(strArg(args, "asset"))
		if assetFilter != "" {
			filtered := make([]zhulong.Chain, 0, len(list))
			for _, c := range list {
				if normalizeChainAsset(c.TargetAsset) == assetFilter {
					filtered = append(filtered, c)
				}
			}
			list = filtered
		}
		if len(list) == 0 {
			msg := "链账本为空(当前会话没有匹配的链)。\n" +
				"下一步:对已确认的漏洞或自己发现的假设 zl_chain_open(finding_key=..., title=..., hypothesis_type=..., target_asset=..., target_model_ref=...);" +
				"没有目标模型条目就先 upsert_project_fact 建 target/<asset>-model。"
			if line := chainStateLine(ctx, store, convID); line != "" {
				msg += "\n" + line
			}
			return textResult(msg, false), nil
		}
		var b strings.Builder
		b.WriteString("id | rung | state | hyp | target_asset | finding_key\n")
		openCount := 0
		for _, c := range list {
			if c.State == zhulong.ChainOpen {
				openCount++
			}
			fmt.Fprintf(&b, "%s | %d | %s | %s | %s | %s\n",
				c.ID, c.Rung, c.State, orDash(c.HypothesisType), orDash(c.TargetAsset), c.FindingKey)
		}
		if line := chainStateLine(ctx, store, convID); line != "" {
			b.WriteString(line + "\n")
		}
		if openCount > 0 {
			fmt.Fprintf(&b, "还有 %d 条 open 链:挑 rung 最大的一条推进(zl_chain_attempt),或三件齐全后 zl_chain_close(blocked)。\n", openCount)
		} else {
			b.WriteString("本会话已无 open 链:先跑 deliver_gate 看首行是否 GATE=PASS,再决定能否交卷。\n")
		}
		return textResult(b.String(), false), nil
	})
}

// chainRungLabel 把台阶号渲染成人话(工具回显用)。
func chainRungLabel(rung int) string {
	switch rung {
	case zhulong.ChainRungSensitiveRead:
		return "读到敏感数据"
	case zhulong.ChainRungAuthBypass:
		return "认证/授权绕过"
	case zhulong.ChainRungWrite:
		return "写入(数据/配置)"
	case zhulong.ChainRungUpload:
		return "上传落地"
	case zhulong.ChainRungExecute:
		return "命令/代码执行"
	case zhulong.ChainRungLateral:
		return "横向到下一跳"
	default:
		return "确认现象"
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return strings.TrimSpace(s)
}

func orUnbound(projectID string) string {
	if strings.TrimSpace(projectID) == "" {
		return "未绑定"
	}
	return projectID
}
