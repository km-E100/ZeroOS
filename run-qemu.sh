#!/usr/bin/env bash
# Zero OS 本地 QEMU 启动脚本（交互串口 + virtio-blk 挂盘）。
#
# 用法：
#   ./run-qemu.sh            # 正常模式（默认）
#   ./run-qemu.sh recovery   # 恢复模式（-boot d，与 cargo run -p xtask -- run recovery 同参）
#
# 与 `cargo run -p xtask -- run` 的区别：这里用 -serial mon:stdio，
# 可直接在终端与用户态 shell 交互（Ctrl-A X 退出 QEMU）。
set -euo pipefail

MODE="${1:-normal}"
case "$MODE" in
  normal)   BOOT_ARGS=(-display none) ;;
  network)
    BOOT_ARGS=(-display none -netdev user,id=znet -device virtio-net-device,netdev=znet,bus=virtio-mmio-bus.1 -object rng-random,filename=/dev/urandom,id=zrng -device virtio-rng-device,rng=zrng,bus=virtio-mmio-bus.5)
    echo "run-qemu: network mode (usernet + virtio-rng)"
    ;;
  graphical)
    BOOT_ARGS=(-display cocoa -netdev user,id=znet -device virtio-net-device,netdev=znet,bus=virtio-mmio-bus.1 -device virtio-gpu-device,xres=1280,yres=720,bus=virtio-mmio-bus.2 -device virtio-keyboard-device,bus=virtio-mmio-bus.3 -device virtio-tablet-device,bus=virtio-mmio-bus.4 -object rng-random,filename=/dev/urandom,id=zrng -device virtio-rng-device,rng=zrng,bus=virtio-mmio-bus.5)
    echo "run-qemu: graphical mode (GOP + virtio-gpu + virtio-keyboard)"
    ;;
  recovery)
    # 恢复模式：-boot d 把 CD 提到固件启动序首位。镜像内含
    # zero-recovery.efi / boot-recovery.cfg / rootfs-recovery.bundle，
    # 引导器按加载路径中的 "recovery" 字样切恢复变体（与 xtask run
    # recovery 完全同参；连续失败 3 次自动进恢复的机制见 STATUS.md）。
    BOOT_ARGS=(-display none -boot d)
    echo "run-qemu: recovery mode (-boot d)"
    ;;
  *)
    echo "run-qemu: 未知模式 '"$MODE"'（用法: ./run-qemu.sh [normal|recovery]）" >&2
    exit 1
    ;;
esac

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

# 32MiB raw 测试盘（存在则复用，保留上次写入的数据——fstest/blktest
# 的跨重启持久化验收依赖这一点）。
# 驱动表登记的槽位：virtio-blk0 @ 0x0a000000 = virtio-mmio-bus.0，GIC INTID 48。
if [[ ! -f "$DISK" ]]; then
  echo "run-qemu: 创建测试盘镜像 $DISK (32MiB)"
  dd if=/dev/zero of="$DISK" bs=1m count=32
fi

# cache=writethrough 必选：writeback 下宿主 QEMU 被 SIGKILL 时未落盘的
# guest 写入会整批丢失，fstest「写后跨重启再读仍 MATCH」的持久化判定
# 就不可信了；writethrough 让每次 guest 写都穿透到宿主文件。
exec qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a72 \
  -m 1024 \
  -bios "$BIOS" \
  -serial mon:stdio \
  "${BOOT_ARGS[@]}" \
  -cdrom "$ISO" \
  -drive if=none,file="$DISK",format=raw,id=zdisk,cache=writethrough \
  -device virtio-blk-device,drive=zdisk,bus=virtio-mmio-bus.0
