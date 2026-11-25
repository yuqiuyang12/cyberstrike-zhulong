#!/usr/bin/env bash
# verify.sh <平台根目录> —— 静态检查烛龙是否装好(不启动服务)
set -euo pipefail
T=${1:?用法: verify.sh <平台根目录>}
cd "$T"; fail=0
chk(){ [ -e "$1" ] && echo "OK   $1" || { echo "MISS $1"; fail=1; }; }
grepchk(){ grep -q "$2" "$1" 2>/dev/null && echo "OK   $1 ⊃ $2" || { echo "MISS $1 ⊃ $2"; fail=1; }; }

chk internal/zhulong/chain.go
chk internal/zhulong/receipt.go
chk internal/zhulong/autocontinue.go
chk internal/loop2/zhulong_orchestrator.go
chk internal/app/chain_tools.go
chk internal/config/config.go
grepchk internal/config/config.go "ZhulongConfig"
grepchk internal/app/app.go "registerChainTools"
grepchk internal/app/app.go "ZhulongGateCheck"
grepchk internal/app/deliver_gate_tools.go "open-chains"
grepchk internal/coverage/coverage.go "ClosedPct"
grepchk internal/database/database.go "unattended_mode"
grepchk internal/mcp/builtin/constants.go "zl_chain_open"
n=$(grep -l "zl_chain_open" roles/*.yaml 2>/dev/null | wc -l); [ "$n" -ge 1 ] && echo "OK   角色白名单含链工具: $n 个" || { echo "WARN 角色白名单无 zl_chain_*"; }

echo; [ "$fail" = 0 ] && echo "VERIFY: PASS" || { echo "VERIFY: FAILED"; exit 1; }
