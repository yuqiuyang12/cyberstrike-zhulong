package zhulong

import (
	"errors"
	"strings"
	"testing"
)

// 这些用例防的失败方式（照抄 agent-autoloop 的测试纪律：先写"它防什么"）：
//  1. 模型没交回执却当成成功（→ 必须 ErrMissingReceipt）
//  2. 回执字段写错名字被静默忽略（→ DisallowUnknownFields 必须报错）
//  3. outcome=done 但没有证据（→ 必须拒）
//  4. 正文里先复述一遍模板、真正的回执在后面（→ 必须取最后一个块）
//  5. 失败轮夹带提问/事实，污染失败域（→ 必须拒）
//  6. 提问缺少 key（→ 回答无法唤醒同一目标，必须拒）
func TestParseReceipt(t *testing.T) {
	done := "探查完成，80 端口开放 nginx 1.18。\n\n```zhulong\n" +
		`{"outcome":"done","summary":"80/tcp nginx 1.18","evidence_refs":["/tmp/e/req.txt"],"facts":["asset/web-80"]}` +
		"\n```\n"

	tests := []struct {
		name    string
		text    string
		wantErr error
		check   func(t *testing.T, r *Receipt)
	}{
		{
			name: "合法 done",
			text: done,
			check: func(t *testing.T, r *Receipt) {
				if r.Outcome != OutcomeDone || len(r.EvidenceRefs) != 1 {
					t.Fatalf("unexpected receipt: %+v", r)
				}
			},
		},
		{
			name:    "缺失回执",
			text:    "我扫了一下，发现 80 端口开着，就先这样吧。",
			wantErr: ErrMissingReceipt,
		},
		{
			name:    "空文本",
			text:    "",
			wantErr: ErrMissingReceipt,
		},
		{
			name:    "非法 outcome",
			text:    "```zhulong\n{\"outcome\":\"ok\",\"summary\":\"x\",\"evidence_refs\":[\"/a\"]}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "未知字段",
			text:    "```zhulong\n{\"outcome\":\"done\",\"summary\":\"x\",\"evidence_refs\":[\"/a\"],\"extra\":1}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "done 无证据",
			text:    "```zhulong\n{\"outcome\":\"done\",\"summary\":\"x\"}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "summary 为空",
			text:    "```zhulong\n{\"outcome\":\"done\",\"summary\":\"   \",\"evidence_refs\":[\"/a\"]}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "blocked 无提问",
			text:    "```zhulong\n{\"outcome\":\"blocked\",\"summary\":\"需要口令\"}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "failed 夹带提问",
			text:    "```zhulong\n{\"outcome\":\"failed\",\"summary\":\"挂了\",\"asks\":[{\"title\":\"继续?\",\"key\":\"k1\"}]}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "failed 夹带事实",
			text:    "```zhulong\n{\"outcome\":\"failed\",\"summary\":\"挂了\",\"facts\":[\"a/b\"]}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "提问缺 key",
			text:    "```zhulong\n{\"outcome\":\"blocked\",\"summary\":\"要口令\",\"asks\":[{\"title\":\"口令?\"}]}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "提问 key 非法",
			text:    "```zhulong\n{\"outcome\":\"blocked\",\"summary\":\"要口令\",\"asks\":[{\"title\":\"口令?\",\"key\":\"重启 服务\"}]}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name: "取最后一个块（正文先复述模板）",
			text: "模板长这样：\n```zhulong\n{\"outcome\":\"done\",\"summary\":\"模板\",\"evidence_refs\":[\"/template\"]}\n```\n\n真正的结论：\n" +
				"```zhulong\n{\"outcome\":\"nothing\",\"summary\":\"本轮无新增\"}\n```",
			check: func(t *testing.T, r *Receipt) {
				if r.Outcome != OutcomeNothing {
					t.Fatalf("应取最后一个块，实际 %+v", r)
				}
			},
		},
		{
			name: "兜底：标记写成 json 但含 outcome",
			text: "```json\n{\"outcome\":\"nothing\",\"summary\":\"没变化\"}\n```",
			check: func(t *testing.T, r *Receipt) {
				if r.Outcome != OutcomeNothing {
					t.Fatalf("json 兜底失败: %+v", r)
				}
			},
		},
		{
			name: "blocked 带提问合法",
			text: "```zhulong\n{\"outcome\":\"blocked\",\"summary\":\"需要重启服务\",\"asks\":[{\"title\":\"是否重启?\",\"key\":\"restart-svc\",\"options\":[\"重启\",\"不重启\"]}]}\n```",
			check: func(t *testing.T, r *Receipt) {
				if len(r.Asks) != 1 || r.Asks[0].Key != "restart-svc" {
					t.Fatalf("unexpected asks: %+v", r.Asks)
				}
			},
		},
		{
			name:    "坏 JSON",
			text:    "```zhulong\n{\"outcome\":\"done\",}\n```",
			wantErr: ErrInvalidReceipt,
		},
		{
			name:    "选项只有一个",
			text:    "```zhulong\n{\"outcome\":\"blocked\",\"summary\":\"x\",\"asks\":[{\"title\":\"t\",\"key\":\"k\",\"options\":[\"A\"]}]}\n```",
			wantErr: ErrInvalidReceipt,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseReceipt(tc.text)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("期望错误 %v，实际拿到 %+v", tc.wantErr, r)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("期望错误 %v，实际 %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不应报错: %v", err)
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		})
	}
}

func TestReceiptContractCoversAllFields(t *testing.T) {
	// 契约正文必须提到全部四个 outcome 与全部字段名，否则模型会漏字段。
	for _, want := range []string{"done", "nothing", "blocked", "failed", "summary", "evidence_refs", "next_actions", "asks", "facts"} {
		if !strings.Contains(ReceiptContract, want) {
			t.Fatalf("回执契约缺少字段/取值: %s", want)
		}
	}
}

func TestMarshalReceiptRoundTrip(t *testing.T) {
	r := &Receipt{Outcome: OutcomeNothing, Summary: "无增量"}
	s, err := MarshalReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, `"outcome":"nothing"`) {
		t.Fatalf("序列化异常: %s", s)
	}
}

// 防的失败方式：把"一句话自述"当证据（done 但无可复核依据）
func TestEvidenceRefStrictness(t *testing.T) {
	base := "```zhulong\n{\"outcome\":\"done\",\"summary\":\"x\",\"evidence_refs\":[%s]}\n```"
	good := []string{`"/tmp/e/nmap.txt"`, `"https://example.com/a"`, `"exec://date@2026-11-04"`, `"file:///tmp/x"`}
	for _, ref := range good {
		if _, err := ParseReceipt(strings.Replace(base, "%s", ref, 1)); err != nil {
			t.Fatalf("合法引用 %s 被拒: %v", ref, err)
		}
	}
	bad := []string{`"nmap 输出看起来正常"`, `"80 端口开放"`, `"见上文"`}
	for _, ref := range bad {
		if _, err := ParseReceipt(strings.Replace(base, "%s", ref, 1)); err == nil {
			t.Fatalf("非法引用 %s 应被拒", ref)
		}
	}
}
