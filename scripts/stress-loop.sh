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
  {
    sleep 16
    printf 'login\r';         sleep 2
    printf 'root\r';          sleep 1
    printf 'zero\r';          sleep 3
    printf 'forktest\r';      sleep 6
    printf 'sleepdemo\r';     sleep 8
    printf 'threaddemo\r';    sleep 8
    printf 'mutextest\r';     sleep 12
    printf 'fstest\r';        sleep 14
    printf 'fsdemo\r';        sleep 14
    printf 'secdemo\r';       sleep 14
  } | qemu-system-aarch64 -machine virt -cpu cortex-a72 -smp 4 -m 1024 \
      -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
      -display none -serial mon:stdio -cdrom "$ISO" \
      -drive if=none,file="$ROOT/target/disk.img",format=raw,id=zdisk,cache=writethrough \
      -device virtio-blk-device,drive=zdisk,bus=virtio-mmio-bus.0 > "/tmp/stress-$r.log" 2>&1 &
  QPID=$!; sleep 90; kill $QPID 2>/dev/null || true; wait $QPID 2>/dev/null || true
  ok=0; total=0
  for pat in "forktest: PASS" "threaddemo: PASS" "mutextest: PASS" "fstest: PASS" "fsdemo: PASS" "secdemo: PASS"; do
    total=$((total+1))
    grep -aqF "$pat" "/tmp/stress-$r.log" && ok=$((ok+1)) || echo "  MISSING: $pat"
  done
  echo "round $r: $ok/$total functional PASS"
  [ "$ok" -eq "$total" ] || { echo "STRESS FAILED at round $r"; exit 1; }
done
echo "STRESS ALL GREEN ($ROUNDS rounds)"
