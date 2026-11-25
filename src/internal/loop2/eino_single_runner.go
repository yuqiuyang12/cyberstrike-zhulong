package loop2

import (
	"context"
	"fmt"
	"sync"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/einomcp"
	"cyberstrike-ai/internal/project"
	"cyberstrike-ai/internal/reasoning"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// einoSingleAgentName 与 ChatModelAgent.Name 一致，供流式事件映射主对话区。
const einoSingleAgentName = "cyberstrike-eino-single"

// RunEinoSingleChatModelAgent 使用 Eino TypedChatModelAgent[*schema.AgenticMessage] + adk.NewRunner.Run（官方 Quick Start 的 Query 同属 Runner API；此处用历史 + 用户消息切片等价于多轮 Query）。
// 与 RunDeepAgent 共享 runEinoADKAgentLoop 的 SSE 映射与 MCP 桥。
func RunEinoSingleChatModelAgent(
	ctx context.Context,
	appCfg *config.Config,
	ma *config.MultiAgentConfig,
	ag *agent.Agent,
	db *database.DB,
	logger *zap.Logger,
	conversationID string,
	projectID string,
	userMessage string,
	history []agent.ChatMessage,
	roleTools []string,
	progress func(eventType, message string, data interface{}),
	reasoningClient *reasoning.ClientIntent,
	systemPromptExtra string,
) (*RunResult, error) {
	return runEinoSingleChatModelAgentNamed(ctx, appCfg, ma, ag, db, logger,
		conversationID, projectID, userMessage, history, roleTools, progress,
		reasoningClient, systemPromptExtra, einoSingleAgentName, "eino_single", 0, nil)
}

// runEinoSingleChatModelAgentNamed 是单代理执行体的可命名变体。
//   - agentName 决定流式事件与过程面板里显示的代理名（zhulong 用它显示 cyberstrike-zhulong）
//   - orchMode 决定进度事件里的编排标识与按模式取迭代上限
//
// 既有调用方一律走 RunEinoSingleChatModelAgent（传 einoSingleAgentName / "eino_single"），
// 行为与拆分前逐字一致。
func runEinoSingleChatModelAgentNamed(
	ctx context.Context,
	appCfg *config.Config,
	ma *config.MultiAgentConfig,
	ag *agent.Agent,
	db *database.DB,
	logger *zap.Logger,
	conversationID string,
	projectID string,
	userMessage string,
	history []agent.ChatMessage,
	roleTools []string,
	progress func(eventType, message string, data interface{}),
	reasoningClient *reasoning.ClientIntent,
	systemPromptExtra string,
	agentName string,
	orchMode string,
	// maxIterOverride >0 时覆盖按编排模式取到的迭代上限（烛龙用它强制单轮步数预算）。
	maxIterOverride int,
	// toolWhitelist 非 nil 时只保留列表内的工具；空列表 = 一个工具都不给（收尾阶段用）。
	toolWhitelist []string,
) (*RunResult, error) {
	if appCfg == nil || ag == nil {
		return nil, fmt.Errorf("eino single: 配置或 Agent 为空")
	}
	if ma == nil {
		return nil, fmt.Errorf("eino single: multi_agent 配置为空")
	}
	runtimeUserMessage := prepareLatestUserMessageForModel(userMessage, appCfg, &ma.EinoMiddleware, conversationID, logger)

	einoLoc, einoSkillMW, einoFSTools, skillsRoot, einoErr := prepareEinoAgenticSkills(ctx, appCfg.SkillsDir, ma, logger)
	if einoErr != nil {
		return nil, einoErr
	}

	holder := &einomcp.ConversationHolder{}
	holder.Set(conversationID)

	var mcpIDsMu sync.Mutex
	var mcpIDs []string
	mcpExecBinder := NewMCPExecutionBinder()
	recorder := func(id, toolCallID string) {
		if id == "" {
			return
		}
		mcpExecBinder.Bind(toolCallID, id)
		mcpIDsMu.Lock()
		mcpIDs = append(mcpIDs, id)
		mcpIDsMu.Unlock()
	}

	snapshotMCPIDs := func() []string {
		mcpIDsMu.Lock()
		defer mcpIDsMu.Unlock()
		out := make([]string, len(mcpIDs))
		copy(out, mcpIDs)
		return out
	}

	toolInvokeNotify := einomcp.NewToolInvokeNotifyHolder()
	einoExecBegin, einoExecAppendPartial, einoExecRegisterCancel, einoExecUnregisterCancel, einoExecFinish := newEinoExecuteMonitorCallbacks(ctx, ag, recorder)
	mainDefs := ag.ToolsForRole(roleTools)
	// 白名单过滤：非 nil 即生效（空列表 = 零工具），避免"空集=全开"的 fail-open。
	if toolWhitelist != nil {
		allow := make(map[string]struct{}, len(toolWhitelist))
		for _, n := range toolWhitelist {
			allow[n] = struct{}{}
		}
		filtered := make([]agent.Tool, 0, len(toolWhitelist))
		for _, d := range mainDefs {
			if _, ok := allow[d.Function.Name]; ok {
				filtered = append(filtered, d)
			}
		}
		mainDefs = filtered
	}
	mainTools, err := einomcp.ToolsFromDefinitions(ag, holder, mainDefs, recorder, nil, toolInvokeNotify, agentName)
	if err != nil {
		return nil, err
	}

	mainToolsForCfg, mainOrchestratorPre, singleToolSearchActive, err := prependEinoAgenticMiddlewares(ctx, &ma.EinoMiddleware, einoMWMain, mainTools, einoLoc, skillsRoot, conversationID, projectID, logger)
	if err != nil {
		return nil, fmt.Errorf("eino single eino 中间件: %w", err)
	}

	baseHTTPClient := newEinoBaseHTTPClient()
	agenticModelFactory := newEinoAgenticChatModelFactory(baseHTTPClient, reasoningClient, logger)
	mainModel, err := agenticModelFactory(ctx, appCfg.OpenAI, einoModelModeNormal)
	if err != nil {
		return nil, fmt.Errorf("eino single agentic 模型: %w", err)
	}
	// 顺序要求：先建 failover 再建 retry（有备用通道时硬不可达不原地重试，直接切通道）。
	modelFailoverCfg, modelFailoverTracker, err := newEinoAgenticModelFailoverConfigWithTracker(ctx, appCfg, &ma.EinoMiddleware, einoModelModeNormal, agenticModelFactory, logger, orchMode, progress, orchMode, conversationID)
	if err != nil {
		return nil, err
	}
	modelRetryCfg := newEinoAgenticModelRetryConfigWithFailover(&ma.EinoMiddleware, logger, orchMode, modelFailoverCfg != nil)
	if modelFailoverTracker != nil && logger != nil {
		snap := modelFailoverTracker.Snapshot()
		logger.Info("eino 模型通道切换已挂载",
			zap.String("orchestration", orchMode),
			zap.Int("candidates", snap.Candidates),
			zap.Int("vendors", snap.Vendors),
			zap.Bool("crossVendorAvailable", snap.CrossVendorAvailable),
			zap.Bool("degraded", snap.Degraded),
			zap.String("modelRunId", snap.RunID),
		)
	}
	logEinoAgenticModelGate(
		logger,
		orchMode,
		orchMode,
		evaluateEinoAgenticModelGate(agenticModelGateFactory(agenticModelFactory, appCfg.OpenAI, einoModelModeNormal), einoAgenticRuntimeSupportV0914()),
	)

	mainSumMw, err := newEinoAgenticSummarizationMiddleware(ctx, mainModel, appCfg, &ma.EinoMiddleware, conversationID, db, projectID, logger)
	if err != nil {
		return nil, fmt.Errorf("eino single agentic summarization: %w", err)
	}

	modelFacingTrace := newModelFacingTraceHolder()

	handlers := make([]adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage], 0, 8)
	if len(mainOrchestratorPre) > 0 {
		handlers = append(handlers, mainOrchestratorPre...)
	}
	if einoSkillMW != nil {
		if einoFSTools && einoLoc != nil {
			fsMw, fsErr := subAgentAgenticFilesystemMiddleware(ctx, einoLoc, toolInvokeNotify, agentName, conversationID, projectID, ma.EinoMiddleware.ReductionRootDir, toolMaxBytesFromMW(&ma.EinoMiddleware), mcpExecBinder, einoExecBegin, einoExecAppendPartial, einoExecRegisterCancel, einoExecUnregisterCancel, einoExecFinish, agentToolTimeoutMinutes(appCfg), agentToolWaitTimeoutSeconds(appCfg), agentShellNoOutputTimeoutSeconds(appCfg), nil)
			if fsErr != nil {
				return nil, fmt.Errorf("eino single filesystem 中间件: %w", fsErr)
			}
			handlers = append(handlers, fsMw)
		}
		handlers = append(handlers, einoSkillMW)
	}
	handlers = appendEinoAgenticChatModelTailMiddlewares(handlers, einoChatModelTailConfig{
		logger:               logger,
		phase:                orchMode,
		agenticSummarization: mainSumMw,
		modelName:            appCfg.OpenAI.Model,
		maxTotalTokens:       appCfg.OpenAI.MaxTotalTokens,
		toolMaxBytes:         toolMaxBytesFromMW(&ma.EinoMiddleware),
		conversationID:       conversationID,
		trace:                modelFacingTrace,
		middlewareConfig:     &ma.EinoMiddleware,
	})

	// W5：按编排模式取迭代上限（agent.max_iterations_by_mode 命中则覆盖，否则回落 agent.max_iterations）。
	maxIter := resolveMaxIterationsByMode(appCfg, orchMode)
	if maxIterOverride > 0 {
		maxIter = maxIterOverride
	}
	// Phase2：预算按资产数分片 min(4000, base+40×资产数)
	if db != nil {
		if n, aerr := coverage.NewStore(db.DB).AssetCount(ctx, conversationID); aerr == nil && n > 0 {
			prev := maxIter
			maxIter = coverage.BudgetFor(maxIter, n)
			if logger != nil {
				logger.Info("coverage budget sharded",
					zap.String("orchestration", orchMode), zap.Int("assets", n),
					zap.Int("base", prev), zap.Int("budget", maxIter))
			}
		}
	}

	mainToolsCfg := adk.ToolsConfig{
		ToolsNodeConfig: compose.ToolsNodeConfig{
			Tools:               mainToolsForCfg,
			UnknownToolsHandler: einomcp.UnknownToolReminderHandler(),
			ToolCallMiddlewares: []compose.ToolMiddleware{
				modelOutputExecutionGuardMiddleware(),
				localToolRBACMiddleware(),
				hitlToolCallMiddleware(),
				softRecoveryToolMiddleware(),
				coverageGate(db, conversationID, logger, appCfg),
				destructiveFenceMiddleware(logger),
				toolArgSizeGuardMiddleware(logger),
			},
		},
		EmitInternalEvents: true,
	}
	ins := project.AppendSystemPromptBlock(ag.EinoSingleAgentSystemInstruction(), systemPromptExtra)
	ins = project.AppendVisionImageAnalysisIfReady(ins, appCfg.Vision.Ready())
	ins = injectToolNamesOnlyInstruction(ctx, ins, mainTools, singleToolSearchActive)
	if logger != nil {
		names := collectToolNames(ctx, mainTools)
		mountedNames := collectToolNames(ctx, mainToolsForCfg)
		logger.Info("eino tool-name injection",
			zap.String("scope", orchMode),
			zap.Int("tool_names", len(names)),
			zap.Int("mounted_tool_names", len(mountedNames)),
			zap.Bool("tool_search_middleware", singleToolSearchActive),
		)
	}

	chatCfg := einoAgenticChatModelAgentConfig{
		Name:                agentName,
		Description:         "Eino ADK ChatModelAgent with MCP tools for authorized security testing.",
		Instruction:         ins,
		GenModelInput:       literalAgenticInstructionGenModelInput,
		Model:               mainModel,
		ToolsConfig:         mainToolsCfg,
		MaxIterations:       maxIter,
		Handlers:            handlers,
		ModelRetryConfig:    modelRetryCfg,
		ModelFailoverConfig: modelFailoverCfg,
	}
	outKey, _ := deepExtrasFromConfig(ma)
	if outKey != "" {
		chatCfg.OutputKey = outKey
	}

	chatAgent, err := newEinoAgenticChatModelAgentAdapter(ctx, chatCfg)
	if err != nil {
		return nil, fmt.Errorf("eino single Agentic ChatModelAgent: %w", err)
	}

	baseMsgs := historyToMessages(history, appCfg, &ma.EinoMiddleware)
	baseMsgs = appendUserMessageIfNeeded(baseMsgs, runtimeUserMessage)

	streamsMainAssistant := func(agent string) bool {
		return agent == "" || agent == agentName
	}
	einoRoleTag := func(agent string) string {
		_ = agent
		return "orchestrator"
	}

	runResult, runErr := runEinoADKAgentLoop(ctx, &einoADKRunLoopArgs{
		OrchMode:             orchMode,
		OrchestratorName:     agentName,
		ConversationID:       conversationID,
		Progress:             progress,
		Logger:               logger,
		SnapshotMCPIDs:       snapshotMCPIDs,
		StreamsMainAssistant: streamsMainAssistant,
		EinoRoleTag:          einoRoleTag,
		// Chat history recovery is intentionally centralized in last_react_*.
		// ADK checkpoints are a second persisted model-state channel and make
		// stale-context bugs hard to reason about across user turns.
		CheckpointDir:           "",
		RunRetryMaxAttempts:     RunRetryMaxAttemptsFromConfig(&ma.EinoMiddleware),
		RunRetryMaxBackoffSec:   int(einoRunRetryMaxBackoffFromConfig(&ma.EinoMiddleware).Seconds()),
		McpIDsMu:                &mcpIDsMu,
		McpIDs:                  &mcpIDs,
		FilesystemMonitorAgent:  ag,
		FilesystemMonitorRecord: recorder,
		MCPExecutionBinder:      mcpExecBinder,
		ToolInvokeNotify:        toolInvokeNotify,
		DA:                      chatAgent,
		ModelFacingTrace:        modelFacingTrace,
		EinoCallbacks:           &ma.EinoCallbacks,
		MaxTotalTokens:          appCfg.OpenAI.MaxTotalTokens,
		ToolMaxBytes:            toolMaxBytesFromMW(&ma.EinoMiddleware),
		ModelName:               appCfg.OpenAI.Model,
		MiddlewareConfig:        &ma.EinoMiddleware,
		EmptyResponseMessage: "(Eino ADK single-agent session completed but no assistant text was captured. Check process details or logs.) " +
			"（Eino ADK 单代理会话已完成，但未捕获到助手文本输出。请查看过程详情或日志。）",
	}, baseMsgs)
	if runErr != nil && isEinoIterationLimitError(runErr) {
		// W5：迭代上限触顶 → handoff 标记（结构化日志 + HANDOFF-*.json 骨架），失败不影响返回。
		emitMaxIterationsHandoff(logger, appCfg.Agent.WorkspaceRootDir, conversationID, orchMode)
	}
	// 通道归属收尾：本轮最终由哪个通道/供应商/模型完成（复用 progress 通道，不新增表）。
	if modelFailoverTracker != nil {
		outcome := "completed"
		switch {
		case runErr == nil:
		case isEinoIterationLimitError(runErr):
			outcome = "iteration_limit"
		default:
			outcome = "failed"
		}
		modelFailoverTracker.EmitFinal(progress, outcome)
	}
	return runResult, runErr
}
