#!/usr/bin/env bash
# 性能基线采集（第十四刀）：记录"可复现的粗粒度性能锚点"。
#
# 指标（全部来自公开产物，不依赖额外插桩）：
#   1. 主机测试总数与耗时（回归即性能信号：测试数下降=覆盖回退）。
#   2. build-iso 全链耗时（构建侧健康度；磁盘闸触发会直接失败）。
#   3. 上电到 shell 提示符秒数（从 test-boot 串口日志 UEFI 起始行到
#      "Zero OS console (user shell)" 的行号差 × 平均节拍，粗估）。
#
# 用法：scripts/perf-baseline.sh > docs/perf-history/<date>.txt 后入库。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== Zero OS 性能基线 $(date '+%F %T') =="
echo "-- 主机测试 --"
/usr/bin/time -p cargo test -p zero-microkernel -p zero-abi -p zero-fsd \
  -p zero-zfs-core -p zero-securityd -p userlib 2>&1 | \
  { grep -E "test result|real" || true; }

echo "-- build-iso --"
/usr/bin/time -p cargo run -p xtask -- build-iso 2>&1 | tail -4

echo "-- 实机启动（test-boot 冒烟）--"
/usr/bin/time -p cargo run -p xtask -- test-boot 2>&1 | tail -6

echo "提示：将本次输出存入 docs/perf-history/ 并在 STATUS.md 登记趋势。"
