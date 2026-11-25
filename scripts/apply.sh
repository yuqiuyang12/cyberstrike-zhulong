#!/usr/bin/env bash
# apply.sh <你的平台根目录> [--dry-run]
# 把本包的 src/ 合并式覆盖到目标平台(不删任何既有文件)。
set -euo pipefail
T=${1:?用法: apply.sh <平台根目录> [--dry-run]}; shift || true
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$T/go.mod" ] || { echo "错误: $T 不是平台根目录(缺 go.mod)"; exit 1; }

echo "== 目标: $T"
# 备份将被覆盖的既有文件
BK="$T/.zhulong-backup-$(date +%Y%m%d-%H%M%S)"
n_new=0; n_ovr=0
while IFS= read -r f; do
  rel="${f#$HERE/src/}"
  if [ -e "$T/$rel" ]; then n_ovr=$((n_ovr+1)); else n_new=$((n_new+1)); fi
done < <(find "$HERE/src" -type f)
echo "== 将覆盖 $n_ovr 个既有文件,新增 $n_new 个文件"
[ "$DRY" = "1" ] && { echo "(dry-run,不写)"; exit 0; }

mkdir -p "$BK"
while IFS= read -r f; do
  rel="${f#$HERE/src/}"; dst="$T/$rel"
  if [ -e "$dst" ]; then mkdir -p "$BK/$(dirname "$rel")"; cp -p "$dst" "$BK/$rel"; fi
  mkdir -p "$(dirname "$dst")"; cp -p "$f" "$dst"
done < <(find "$HERE/src" -type f)
echo "== 已覆盖(原文件备份在 $BK)"
echo
echo "下一步:"
echo "  1) 确认平台已按 hooks/ANCHORS.md 完成接线(若你的树已含烛龙则跳过)"
echo "  2) cd $T && go build ./cmd/server"
echo "  3) bash $HERE/scripts/verify.sh $T"
