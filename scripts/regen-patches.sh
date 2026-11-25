#!/usr/bin/env bash
# regen-patches.sh <基线平台根目录> —— 把本包 src/ 与你的基线做 diff,生成可 apply 的补丁
set -euo pipefail
T=${1:?用法: regen-patches.sh <基线平台根目录(不含烛龙的树)>}
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/patches"; mkdir -p "$OUT"
i=0
while IFS= read -r f; do
  rel="${f#$HERE/src/}"
  [ -e "$T/$rel" ] || continue
  i=$((i+1))
  name=$(printf "%04d-%s.patch" "$i" "$(echo "$rel" | tr '/' '-')")
  diff -u "$T/$rel" "$f" > "$OUT/$name" || true
  echo "生成 $OUT/$name ($(wc -l < "$OUT/$name") 行)"
done < <(find "$HERE/src" -type f -name '*.go')
echo "共 $i 个补丁。应用: cd <基线树> && git apply $OUT/*.patch"
