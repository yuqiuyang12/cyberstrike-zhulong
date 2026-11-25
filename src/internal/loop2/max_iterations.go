package loop2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/project"

	"go.uber.org/zap"
)

const defaultAgentMaxIterations = 3000

// handoffReasonMaxIterations 迭代上限触发 handoff 标记时的 reason 值（写入 HANDOFF-*.json）。
const handoffReasonMaxIterations = "max_iterations"

// agentMaxIterations 全局上限：仅使用 config.agent.max_iterations；≤0 时与 config 默认一致为 3000。
func agentMaxIterations(appCfg *config.Config) int {
	if appCfg != nil && appCfg.Agent.MaxIterations > 0 {
		return appCfg.Agent.MaxIterations
	}
	return defaultAgentMaxIterations
}

// resolveMaxIterations 统一迭代上限：Markdown/子代理 front matter 中 max_iterations>0 可单独覆盖，否则使用 agent.max_iterations。
// multi_agent.max_iteration 与 sub_agent_max_iterations 已废弃，不再参与计算。
func resolveMaxIterations(appCfg *config.Config, markdownOverride int) int {
	if markdownOverride > 0 {
		return markdownOverride
	}
	return agentMaxIterations(appCfg)
}

// resolveMaxIterationsByMode 按编排/代理模式取迭代上限（W5）：
//   - agent.max_iterations_by_mode 存在且命中 mode（大小写不敏感、忽略首尾空白）→ 用该值；
//   - 未配置该键、mode 为空、或命中值 ≤0 → 回落 agent.max_iterations（旧配置行为完全不变）。
//
// 可用的 mode 键与编排模式一致：deep / supervisor / plan_execute / eino_single。
func resolveMaxIterationsByMode(appCfg *config.Config, mode string) int {
	key := strings.ToLower(strings.TrimSpace(mode))
	if key != "" && appCfg != nil {
		for modeKey, modeMax := range appCfg.Agent.MaxIterationsByMode {
			if modeMax <= 0 {
				continue
			}
			if strings.ToLower(strings.TrimSpace(modeKey)) == key {
				return modeMax
			}
		}
	}
	return agentMaxIterations(appCfg)
}

// handoffSkeleton 是 HANDOFF-<conversationId>.json 的骨架结构。
// 骨架内五个数组均为空，由后续会话/agent 依据过程详情补全。
type handoffSkeleton struct {
	Reason             string   `json:"reason"`
	ConversationID     string   `json:"conversation_id,omitempty"`
	Orchestration      string   `json:"orchestration,omitempty"`
	GeneratedAt        string   `json:"generated_at"`
	Note               string   `json:"note"`
	Shells             []string `json:"shells"`
	CredsRefs          []string `json:"creds_refs"`
	Topology           []string `json:"topology"`
	IncompleteSurfaces []string `json:"incomplete_surfaces"`
	NextActions        []string `json:"next_actions"`
}

// emitMaxIterationsHandoff 迭代上限触顶时的 handoff 标记（W5）：
//  1. 写一行结构化日志（key=handoff_required、conversationId、reason=max_iterations）；
//  2. 尽力在会话 workspace 落 HANDOFF-<conversationId>.json 骨架。
//
// 任何写盘/序列化失败只记日志、绝不影响主流程（调用方照常返回原有错误）。
// workspaceBaseDir 为 config.agent.workspace_root_dir（空=tmp/workspace，相对进程 CWD，与会话 workspace 规则一致）。
// 返回写入的文件绝对路径；未写成功返回空串。
func emitMaxIterationsHandoff(logger *zap.Logger, workspaceBaseDir, conversationID, orchMode string) string {
	if logger == nil {
		logger = zap.NewNop()
	}
	convID := strings.TrimSpace(conversationID)
	logger.Warn("handoff_required",
		zap.String("key", "handoff_required"),
		zap.String("conversationId", convID),
		zap.String("reason", handoffReasonMaxIterations),
		zap.String("orchestration", strings.TrimSpace(orchMode)),
	)
	if convID == "" {
		logger.Warn("handoff_required: conversationId 为空，跳过 HANDOFF 骨架写入")
		return ""
	}

	root := project.WorkspaceRootDir(workspaceBaseDir, "", convID)
	absDir, err := project.EnsureWorkspace(root)
	if err != nil {
		logger.Warn("handoff_required: workspace 不可用，跳过 HANDOFF 骨架写入",
			zap.String("conversationId", convID), zap.Error(err))
		return ""
	}

	skeleton := handoffSkeleton{
		Reason:         handoffReasonMaxIterations,
		ConversationID: convID,
		Orchestration:  strings.TrimSpace(orchMode),
		GeneratedAt:    time.Now().Format(time.RFC3339),
		Note: "由平台在迭代上限触发时自动生成的空骨架；shells/creds_refs/topology/incomplete_surfaces/next_actions " +
			"需由 agent 或人工按会话过程详情补全后再用于续跑。",
		Shells:             make([]string, 0),
		CredsRefs:          make([]string, 0),
		Topology:           make([]string, 0),
		IncompleteSurfaces: make([]string, 0),
		NextActions:        make([]string, 0),
	}
	data, err := json.MarshalIndent(skeleton, "", "  ")
	if err != nil {
		logger.Warn("handoff_required: HANDOFF 骨架序列化失败，跳过写入",
			zap.String("conversationId", convID), zap.Error(err))
		return ""
	}
	data = append(data, '\n')

	path := filepath.Join(absDir, "HANDOFF-"+handoffFileSafeID(convID)+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		logger.Warn("handoff_required: HANDOFF 骨架写入失败（不影响主流程）",
			zap.String("conversationId", convID), zap.String("path", path), zap.Error(err))
		return ""
	}
	logger.Info("handoff_required: HANDOFF 骨架已写入",
		zap.String("conversationId", convID), zap.String("path", path))
	return path
}

// handoffFileSafeID 把会话 ID 归一化为可作文件名的一段：去掉路径分隔符与上跳，长度上限 180（与 workspace 目录规则一致）。
func handoffFileSafeID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, "..", "__")
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}
