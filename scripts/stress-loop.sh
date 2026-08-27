#!/usr/bin/env bash
# 多核压力循环（第十七刀 P1）：全套 demo 反复锤炼，抓竞态/退化。
# 用法：scripts/stress-loop.sh [轮数] （默认 3；需先 build-iso）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROUNDS="${1:-3}"
ISO="$ROOT/target/zero-os.iso"
cd "$ROOT"
[ -f target/disk.img ] || dd if=/dev/zero of=target/disk.img bs=1m count=32
for r in $(seq 1 "$ROUNDS"); do
  echo "== round $r/$ROUNDS =="
  LOG="/tmp/stress-$r.log"
  ROUND_DISK="$ROOT/target/stress-$r.img"
  rm -f "$LOG" "$ROUND_DISK"
  cp "$ROOT/target/disk.img" "$ROUND_DISK"

  # Run QEMU in the foreground.  The final Ctrl-A x is QEMU's mon:stdio mux
  # command to terminate the emulator itself, so there is no background pipeline
  # PID ambiguity and no orphan QEMU retaining a write lock on the test disk.
  # Each round uses its own disk image as an additional isolation fence.
  set +e
  {
    sleep 16
    printf 'login\r';         sleep 2
    printf 'root\r';          sleep 1
    printf 'zero\r';          sleep 3
    printf 'forktest\r';      sleep 6
    printf 'sleepdemo\r';     sleep 8
    printf 'threaddemo\r';    sleep 8
    printf 'mutextest\r';     sleep 20
    printf 'fstest\r';        sleep 16
    printf 'fsdemo\r';        sleep 16
    printf 'secdemo\r';       sleep 18
    printf '\001x'
  } | qemu-system-aarch64 -machine virt -cpu cortex-a72 -smp 4 -m 1024 \
      -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
      -display none -boot order=d -serial mon:stdio -cdrom "$ISO" \
      -drive if=none,file="$ROUND_DISK",format=raw,id=zdisk,cache=writethrough \
      -device virtio-blk-device,drive=zdisk,bus=virtio-mmio-bus.0 > "$LOG" 2>&1
  qrc=$?
  set -e
  rm -f "$ROUND_DISK"

  ok=0; total=0
  for pat in "forktest: PASS" "threaddemo: PASS" "mutextest: PASS" "fstest: PASS" "fsdemo: PASS" "secdemo: PASS"; do
    total=$((total+1))
    grep -aqF "$pat" "$LOG" && ok=$((ok+1)) || echo "  MISSING: $pat"
  done
  grep -aqF "smp: boot_secondaries done, online=4 multi_core=true" "$LOG" \
    || { echo "  MISSING: SMP4 online=4"; echo "STRESS FAILED at round $r (qemu_rc=$qrc)"; exit 1; }
  if grep -aqE 'panic at|SYSTEM HALT|\[KERNEL FAULT\]|trap: unknown sync|owner mismatch|still owned by cpu' "$LOG"; then
    echo "  FORBIDDEN: kernel fault / ownership violation"
    grep -aE 'panic at|SYSTEM HALT|\[KERNEL FAULT\]|trap: unknown sync|owner mismatch|still owned by cpu' "$LOG" | tail -20 || true
    echo "STRESS FAILED at round $r"
    exit 1
  fi
  echo "round $r: $ok/$total functional PASS + SMP4/no-fault (qemu_rc=$qrc)"
  [ "$ok" -eq "$total" ] || { echo "STRESS FAILED at round $r"; exit 1; }
done
echo "STRESS ALL GREEN ($ROUNDS rounds, 6/6 + SMP4/no-fault each)"
