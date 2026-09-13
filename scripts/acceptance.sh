#!/usr/bin/env bash
# Zero OS 用户态验收序列（CI 与人工回归共用入口）。
#
# 流程：build-iso → 启动 QEMU（串口落盘 + cache=writethrough 挂盘）→
#       定时注入 launchd list / forktest / blktest / fstest →
#       grep 判定各项 PASS/FAIL → 打印摘要并以退出码汇总
#       （全过退出 0；任一失败退出 1）。
#
# 用法：
#   scripts/acceptance.sh              # 全链：先 build-iso 再实机验收
#   scripts/acceptance.sh --no-build   # 复用现有 target/zero-os.iso 快速回归
#
# 日志：target/acceptance-serial.log（失败时自动回放末尾若干行辅助定位）。
# 时长：全链构建数分钟；实机注入段约 50 秒。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/target/acceptance-serial.log"
ISO="$ROOT/target/zero-os.iso"
DISK="$ROOT/target/disk.img"
BIOS="${ZERO_OS_QEMU_BIOS:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}"

SKIP_BUILD=0
case "${1:-}" in
  "")          SKIP_BUILD=0 ;;
  --no-build)  SKIP_BUILD=1 ;;
  *) echo "acceptance: 用法: $0 [--no-build]" >&2; exit 2 ;;
esac

if [[ -z "$(command -v qemu-system-aarch64)" ]]; then
  echo "acceptance: 未找到 qemu-system-aarch64" >&2
  exit 1
fi

if [[ $SKIP_BUILD -eq 0 ]]; then
  echo "==> acceptance: build-iso"
  (cd "$ROOT" && cargo run -p xtask -- build-iso)
fi
if [[ ! -f "$ISO" ]]; then
  echo "acceptance: 未找到 $ISO —— 先跑一次不带 --no-build 的本脚本" >&2
  exit 1
fi

# 测试盘存在则复用：fstest 验证跨重启持久化；blktest 使用 ZFS 明确保留的最后 4KiB 诊断块。
if [[ ! -f "$DISK" ]]; then
  echo "acceptance: 创建测试盘 $DISK (32MiB raw)"
  dd if=/dev/zero of="$DISK" bs=1m count=32
fi

rm -f "$LOG"

QEMU_PID=""
kill_qemu() {
  [[ -n "$QEMU_PID" ]] && kill "$QEMU_PID" 2>/dev/null || true
}
trap kill_qemu EXIT INT TERM

# 注：macOS 自带 bash 3.2 会把紧随其后的多字节字符吞进变量名，
# 故此处必须用花括号形式。
echo "==> acceptance: 启动 QEMU（串口日志 ${LOG}）"
# 启动 ~12 秒出 zero> 提示符；注入节奏留足余量（forktest 父子收尸、
# fstest 六步 IPC 往返、secdemo 三轮 IPC 往返各需数秒）。挂盘
# cache=writethrough 与 run-qemu.sh 同参：guest 写入即时穿透宿主文件，
# 本脚本被 SIGKILL 也不丢已判定数据。
#
# 第十三刀注入段：login(root/zero) → whoami → secdemo →
# su(guest/guest 换会话) → whoami → sessions。
{
  sleep 18
  printf 'launchd list\r'; sleep 4
  printf 'login\r';        sleep 2
  printf 'root\r';         sleep 1
  printf 'zero\r';         sleep 3
  printf 'whoami\r';       sleep 2
  printf 'secdemo\r';      sleep 16
  printf 'su\r';           sleep 2
  printf 'guest\r';        sleep 1
  printf 'guest\r';        sleep 3
  printf 'whoami\r';       sleep 2
  printf 'sessions\r';     sleep 2
  printf 'sleepdemo\r';    sleep 8
  printf 'threaddemo\r';   sleep 10
  printf 'mutextest\r';    sleep 12
  printf 'forktest\r';     sleep 5
  # blktest 注入已恢复（第十刀集成：Shell 最小授权补授 CAP_BLOCK_DEV，
  # 原第八刀收权后的"permission denied"不再发生）。
  printf 'blktest\r';      sleep 4
  printf 'fstest\r';       sleep 14
  printf 'fsdemo\r';       sleep 14
} | qemu-system-aarch64 \
    -machine virt \
    -cpu cortex-a72 \
    -m 1024 \
    -bios "$BIOS" \
    -display none \
    -boot order=d \
    -serial mon:stdio \
    -cdrom "$ISO" \
    -drive if=none,file="$DISK",format=raw,id=zdisk,cache=writethrough \
    -device virtio-blk-device,drive=zdisk,bus=virtio-mmio-bus.0 \
    >"$LOG" 2>&1 &
QEMU_PID=$!

sleep 130
kill_qemu
wait "$QEMU_PID" 2>/dev/null || true
trap - EXIT INT TERM

# ---- 判定：逐项 grep 串口日志（-a 防串口控制字节把日志判成二进制）----
pass=0
fail=0
check() {
  local name="$1" pattern="$2"
  if grep -aqF -- "$pattern" "$LOG"; then
    printf "%-18s PASS   (%s)\n" "$name" "found: $pattern"
    pass=$((pass + 1))
  else
    printf "%-18s FAIL   (%s)\n" "$name" "missing: $pattern"
    fail=$((fail + 1))
  fi
}

echo "== acceptance summary =="
check "shell-up"         "Zero OS console (user shell)"
check "launchd-fsd"      "fsd [running"
check "launchd-blkdrv"   "blkdrv [running"
check "launchd-securityd" "securityd [running"
check "login-root"       "welcome root (session id="
check "secdemo"          "secdemo: PASS - RX/TX policy + dynamic capability lifecycle verified"
check "su-guest"         "welcome guest (session id="
check "sessions"         "sid=2 leader="
check "forktest"         "forktest: collected pid="
check "blktest"          "blktest: PASS"
check "fstest"           "fstest: PASS"
check "sleepdemo"        "sleepdemo: PASS (sleep/wake + frame writeback)"
check "fsdemo"           "fsdemo: PASS (mkdir/list/unlink/rmdir tree semantics)"
check "threaddemo"       "threaddemo: PASS (CreateThread + shared space + join)"
check "mutextest"        "mutextest: PASS (futex-backed mutex, exact count)"
echo "--------------------------"
total=$((pass + fail))
if [[ $fail -eq 0 ]]; then
  echo "result: ALL PASS ($total/$total)"
else
  echo "result: $fail/$total FAILED —— 串口日志末尾回放："
  tail -n 20 "$LOG" || true
  exit 1
fi
