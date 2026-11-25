package zhulong

// boundary.go —— 任务级「操作边界」（移植自 ARTEX agent/constraints.go 的 task_constraints 机制）。
//
// 与 ScopeBoundary 的分工：
//   - ScopeBoundary 是"什么永远不能做"（全局四条底线，每轮注入，不随任务变化）；
//   - BoundaryConstraints 是"本次到底测哪里"：从用户目标里抽出的显式授权范围 + 显式禁止语句，
//     作为最高优先级系统提示块注入本轮，并持久化到 Goal.Constraints 供后续轮合并（objective
//     每轮会被最新用户输入刷新，单轮写"继续"不能把早先声明的范围弄丢）。
//
// 口径（对齐 ARTEX 与平台纪律）：只收录**显式**范围语句与目标 token，不做猜测；
// 没有命中就返回空（不注入噪声）。"发现范围外的新目标 ≠ 获得授权"由渲染块里的固定尾句承载。

import (
	"regexp"
	"strings"
)

// BoundaryConstraints 是一次任务的操作边界。
type BoundaryConstraints struct {
	Allow []string // 授权范围（只测这些）
	Deny  []string // 显式禁止语句（整句收录）
}

// boundaryTargetPattern 识别目标类 token：URL、域名（可带端口，末级标签须为 2-24 位字母）、
// IPv4/CIDR。末级要求字母是为了避免把版本号（1.2.3）/小数当成域名。
var boundaryTargetPattern = regexp.MustCompile(`(?i)(https?://[^\s"'<>（）()【】\[\],，;；]+|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}(?::\d{1,5})?|\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b)`)

// boundaryDenyPattern 是「显式禁止语句」的识别标记（按句切分后整句收录）。
var boundaryDenyPattern = regexp.MustCompile(`禁止|不要|别碰|别动|不得|不能|不测|不扫|不动|不许|范围外|越界|只记录不测试`)

const (
	boundaryMaxAllow = 16 // 授权目标上限（超出截断，防提示词膨胀）
	boundaryMaxDeny  = 8  // 禁止语句上限
	boundaryMaxLine  = 200
	boundaryMaxLines = 32 // Goal.Constraints 持久化行上限
)

// ParseGoalConstraints 从目标文本抽操作边界：
// 含禁止标记的句子整句进 deny；其余句子里的目标 token（URL/域名/IP）进 allow。
func ParseGoalConstraints(objective string) BoundaryConstraints {
	var b BoundaryConstraints
	seenAllow := map[string]struct{}{}
	seenDeny := map[string]struct{}{}
	addAllow := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || len(b.Allow) >= boundaryMaxAllow {
			return
		}
		key := strings.ToLower(s)
		if _, ok := seenAllow[key]; ok {
			return
		}
		seenAllow[key] = struct{}{}
		b.Allow = append(b.Allow, s)
	}
	addDeny := func(s string) {
		s = oneLineText(s, boundaryMaxLine)
		if s == "" || len(b.Deny) >= boundaryMaxDeny {
			return
		}
		key := strings.ToLower(s)
		if _, ok := seenDeny[key]; ok {
			return
		}
		seenDeny[key] = struct{}{}
		b.Deny = append(b.Deny, s)
	}
	for _, sent := range splitObjectiveSentences(objective) {
		if boundaryDenyPattern.MatchString(sent) {
			addDeny(sent)
			continue
		}
		for _, m := range boundaryTargetPattern.FindAllString(sent, boundaryMaxAllow) {
			addAllow(m)
		}
	}
	return b
}

// splitObjectiveSentences 按句末标点/换行切句。
func splitObjectiveSentences(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case '。', '；', ';', '\n', '\r', '！', '!', '？', '?':
			return true
		}
		return false
	})
}

// Lines 把边界转成可持久化到 Goal.Constraints 的行（"允许: x" / "禁止: y"）。
func (b BoundaryConstraints) Lines() []string {
	out := make([]string, 0, len(b.Allow)+len(b.Deny))
	for _, a := range b.Allow {
		out = append(out, "允许: "+a)
	}
	for _, d := range b.Deny {
		out = append(out, "禁止: "+d)
	}
	return out
}

// SplitConstraintLines 把持久化行反解成 allow/deny 两组（不认识的行丢弃）。
func SplitConstraintLines(lines []string) (allow, deny []string) {
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "允许: "):
			if v := strings.TrimSpace(strings.TrimPrefix(ln, "允许: ")); v != "" {
				allow = append(allow, v)
			}
		case strings.HasPrefix(ln, "禁止: "):
			if v := strings.TrimSpace(strings.TrimPrefix(ln, "禁止: ")); v != "" {
				deny = append(deny, v)
			}
		}
	}
	return allow, deny
}

// MergeConstraintLines 合并「上一轮已存的行」与「本轮新行」，去重并截断上限（先到先留）。
func MergeConstraintLines(prev, cur []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(prev)+len(cur))
	add := func(ln string) {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			return
		}
		key := strings.ToLower(ln)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, ln)
	}
	for _, ln := range prev {
		add(ln)
	}
	for _, ln := range cur {
		add(ln)
	}
	if len(out) > boundaryMaxLines {
		out = out[:boundaryMaxLines]
	}
	return out
}

// Block 渲染成最高优先级的系统提示块（ARTEX constraintBlock 的移植）。
// 空边界返回空串（不注入噪声）。
func (b BoundaryConstraints) Block() string {
	if len(b.Allow) == 0 && len(b.Deny) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("【本次任务操作边界（最高优先级，凌驾于一切探索/拓面启发式；每生成一条意图、每执行一个动作前先自检是否违反）】：")
	if len(b.Allow) > 0 {
		sb.WriteString("\n授权范围（只测这些）：")
		for _, a := range b.Allow {
			sb.WriteString("\n- " + a)
		}
	}
	if len(b.Deny) > 0 {
		sb.WriteString("\n明确禁止：")
		for _, d := range b.Deny {
			sb.WriteString("\n- " + d)
		}
	}
	sb.WriteString("\n（发现范围之外的新目标/新端口/新主机、或目标旁路出现的新资产，不等于获得授权：只记录为 out-of-scope 事实并跳过，不得为其执行动作或派生意图。）")
	return sb.String()
}
