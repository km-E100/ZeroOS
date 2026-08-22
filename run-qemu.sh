#!/usr/bin/env bash
# Zero OS 本地 QEMU 启动脚本（交互串口 + virtio-blk 挂盘）。
#
# 与 `cargo run -p xtask -- run` 的区别：这里用 -serial mon:stdio，
# 可直接在终端与用户态 shell 交互（Ctrl-A X 退出 QEMU）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ISO="$ROOT/target/zero-os.iso"
DISK="$ROOT/target/disk.img"
BIOS="/opt/homebrew/share/qemu/edk2-aarch64-code.fd"

if [[ ! -f "$ISO" ]]; then
  echo "run-qemu: 未找到 $ISO —— 请先执行 cargo run -p xtask -- build-iso" >&2
  exit 1
fi
if [[ ! -f "$BIOS" ]]; then
  echo "run-qemu: 未找到 EDK2 固件 $BIOS —— 请确认 Homebrew QEMU 安装位置" >&2
  exit 1
fi

# 32MiB raw 测试盘（存在则复用，保留上次写入的数据）。
# 驱动表登记的槽位：virtio-blk0 @ 0x0a000000 = virtio-mmio-bus.0，GIC INTID 48。
if [[ ! -f "$DISK" ]]; then
  echo "run-qemu: 创建测试盘镜像 $DISK (32MiB)"
  dd if=/dev/zero of="$DISK" bs=1m count=32
fi

exec qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a72 \
  -m 1024 \
  -bios "$BIOS" \
  -serial mon:stdio \
  -display none \
  -cdrom "$ISO" \
  -drive if=none,file="$DISK",format=raw,id=zdisk \
  -device virtio-blk-device,drive=zdisk,bus=virtio-mmio-bus.0
