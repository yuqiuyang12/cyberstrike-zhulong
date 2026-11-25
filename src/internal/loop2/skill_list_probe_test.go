package loop2

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk/middlewares/skill"
)

// 探针测试:直接调用生产函数 compactSkillList,测「哪些技能能拿到描述」。
//
// 背景(2026-10-15):skill_stats 显示 src-hunting 累计 0 次调用,而同族 pentest-windftsy 43 次。
// 根因是常驻技能清单里 src-hunting 只有裸名字、没有描述(执行者看不到它的卖点):
//   - 旧实现用 strings.Contains(desc, "触发:") 判定「高优先」,它写的是「触发场景：」→ 落普通桶;
//   - 旧实现按字母序填充 softCap 并在首个超支条目 break,字母序靠后的标签技能被**整组**降级为裸名。
//
// 复核命令(不依赖网络/目标,只读本地技能目录):
//
//	go test ./internal/loop2/ -run TestSkillListProbe -v
//
// 环境变量可覆盖两个旋钮(与 config.yaml 的 eino_skills.* 保持一致):
//
//	SKILL_LIST_MAX_CHARS / SKILL_DESC_MAX_CHARS
func TestSkillListProbe(t *testing.T) {
	const skillsDir = "/home/kali/work/skills"
	ctx := context.Background()

	be, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatalf("local backend: %v", err)
	}
	sb, err := skill.NewBackendFromFilesystem(ctx, &skill.BackendFromFilesystemConfig{
		Backend: be,
		BaseDir: skillsDir,
	})
	if err != nil {
		t.Fatalf("skill backend: %v", err)
	}
	list, err := sb.List(ctx)
	if err != nil {
		t.Fatalf("list skills: %v", err)
	}
	if len(list) == 0 {
		t.Fatalf("skills_dir 扫到 0 个技能 —— skill 工具将恒返回 not found")
	}

	// 与 config.yaml 的 eino_skills 段保持一致(改了配置请同步这两个默认值)。
	maxChars := envInt("SKILL_LIST_MAX_CHARS", 16000)
	descCap := envInt("SKILL_DESC_MAX_CHARS", 150)

	taggedTotal := 0
	for _, fm := range list {
		if strings.Contains(strings.Join(strings.Fields(fm.Description), " "), "触发:") {
			taggedTotal++
		}
	}

	stats := func(out string) (withDesc int, nameOnly int, hasSrc bool) {
		for _, line := range strings.Split(out, "\n") {
			if !strings.HasPrefix(line, "- ") {
				continue
			}
			body := strings.TrimPrefix(line, "- ")
			if i := strings.Index(body, ": "); i > 0 {
				withDesc++
				if body[:i] == "src-hunting" {
					hasSrc = true
				}
			} else {
				nameOnly++
			}
		}
		return withDesc, nameOnly, hasSrc
	}

	// 参数扫描:为配置定值提供实测依据。
	t.Log("=== 参数扫描(maxChars × descCap) ===")
	for _, mc := range []int{12000, 16000, 20000, 24000} {
		for _, dc := range []int{100, 120, 150, 200} {
			out := compactSkillList(ctx, list, mc, dc, true)
			w, n, src := stats(out)
			t.Logf("maxChars=%5d descCap=%3d -> 拿到描述=%2d/%d  裸名=%3d  字节=%5d  src-hunting有描述=%v",
				mc, dc, w, taggedTotal, n, len(out), src)
		}
	}

	out := compactSkillList(ctx, list, maxChars, descCap, true)
	withDesc, nameOnly, hasSrc := stats(out)
	t.Logf("=== 生产配置(maxChars=%d descCap=%d) ===", maxChars, descCap)
	t.Logf("技能总数=%d 带触发标签=%d 拿到描述=%d 仅裸名=%d 清单字节=%d",
		len(list), taggedTotal, withDesc, nameOnly, len(out))

	if !hasSrc {
		// 关键回归断言:src-hunting 必须拿到描述,否则执行者对它的全部卖点不可见(2026-10-15 实测 0 次调用)。
		t.Errorf("回归:%q 未拿到描述(只有裸名字)", "src-hunting")
	}
	// 打印 src-hunting 在清单里的**实际渲染行** —— 执行者看到的就是这一行,验收以它为准。
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "- src-hunting") {
			t.Logf("src-hunting 渲染行: %s", line)
			if !strings.Contains(line, "判据:") {
				t.Errorf("src-hunting 渲染行缺少「判据/价值排序」(被截断丢了重点): %s", line)
			}
		}
	}
	if withDesc < taggedTotal*9/10 {
		t.Errorf("公平性:带标签 %d 个,只有 %d 个拿到描述(<90%%)", taggedTotal, withDesc)
	}
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
