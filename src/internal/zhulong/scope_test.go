package zhulong

import (
	"strings"
	"testing"
)

// TestScopeBoundaryHasFourBottomLines 守住"只保留四条底线"这个口径：
// 四类底线必须在场，且不得退化成禁令堆砌（出现 W0-W3 分层表即为口径跑偏）。
func TestScopeBoundaryHasFourBottomLines(t *testing.T) {
	s := ScopeBoundary
	required := []string{
		"禁可用性打击",
		"禁销毁他人既有数据",
		"禁真实资金/真实人员的不可逆动作",
		"不越出授权范围",
	}
	for _, k := range required {
		if !strings.Contains(s, k) {
			t.Errorf("ScopeBoundary 缺少底线条款：%q", k)
		}
	}
	for _, banned := range []string{"W0", "W1", "W2", "W3"} {
		if strings.Contains(s, banned) {
			t.Errorf("ScopeBoundary 不应再出现分层标记 %q（口径：只保留四条底线）", banned)
		}
	}
	if strings.Count(s, "\n1. ") < 1 || strings.Count(s, "\n4. ") < 1 {
		t.Error("ScopeBoundary 四条应带序号 1..4，便于模型逐条对照")
	}
}

// TestScopeBoundaryAllowsSelfCreatedObjects 自建对象上的验证必须被显式放行，
// 否则模型会退回"什么都不敢写"的老毛病。
func TestScopeBoundaryAllowsSelfCreatedObjects(t *testing.T) {
	if !strings.Contains(ScopeBoundary, "自建对象") {
		t.Error("ScopeBoundary 必须显式放行自建对象上的验证")
	}
	if !strings.Contains(ScopeBoundary, "不必请示") {
		t.Error("ScopeBoundary 必须写明四条以外不必请示")
	}
}
