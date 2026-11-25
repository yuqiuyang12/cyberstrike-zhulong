package zhulong

import (
	"encoding/json"
	"fmt"
)

func marshalStrings(v []string) (string, error) {
	if len(v) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("zhulong: 序列化字符串数组失败: %w", err)
	}
	return string(b), nil
}

func unmarshalStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
