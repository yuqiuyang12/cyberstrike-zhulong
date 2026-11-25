#!/usr/bin/env bash
# prepublish-check.sh —— 发布前自检:凭据 / 客户标识 / 内部绝对路径
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
echo "== 1) 凭据形态 =="
h=$(grep -rnE "sk-[A-Za-z0-9_-]{20,}|sk_tr_[A-Za-z0-9_-]+|AKIA[0-9A-Z]{16}|github_pat_[A-Za-z0-9_]{20,}" . --exclude=prepublish-check.sh | wc -l) || true
[ "$h" -eq 0 ] && echo "OK 0 命中" || { echo "FAIL $h 命中"; fail=1; }
echo "== 2) 私钥块 =="
p=$(grep -rn "BEGIN .* PRIVATE KEY" . --exclude=prepublish-check.sh | wc -l) || true
[ "$p" -eq 0 ] && echo "OK 0 命中" || { echo "FAIL $p 命中"; fail=1; }
echo "== 3) 客户标识 =="
c=$(grep -rlE "surongxc|airbnb|dycbctf|meituan|dianping|ninebot|segway|cqjtkt|cqsdlys|quantacn" . --exclude=prepublish-check.sh | wc -l) || true
[ "$c" -eq 0 ] && echo "OK 0 命中" || { echo "FAIL $c 个文件"; fail=1; }
echo "== 4) 本机绝对路径(警告级) =="
grep -rn "/home/kali" . --exclude=prepublish-check.sh | head -5 || echo "OK 无"
echo; [ "$fail" = 0 ] && echo "PREPUBLISH: PASS" || { echo "PREPUBLISH: FAILED"; exit 1; }
