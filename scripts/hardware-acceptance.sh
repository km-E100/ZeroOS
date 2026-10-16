#!/usr/bin/env bash
# Zero OS 第35~40刀硬件/QEMU专项验收。
#
# 35/36 共用一次启动，其余每刀独立：
#   K35 PCIe high-ECAM/BAR + EL0 MMIO lease
#   K36 GICv3 ITS/LPI/MSI + CPU1 affinity + SMP4
#   K37 modern VirtIO PCI-only blk/net/rng/gpu/input/sound
#   K38 ACPI IORT + SMMUv3 domain/map/fault/unmap/detach
#   K39 PCI xHCI + USB keyboard/tablet + QMP真实按键 -> inputd
#   K40 NVMe-only block backend + ZFS fstest/fsdemo + HTTPS ZeroPkg E2E
#
# 用法：
#   scripts/hardware-acceptance.sh              # 先 build-iso
#   scripts/hardware-acceptance.sh --no-build   # 复用现有 target/zero-os.iso
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ISO="$ROOT/target/zero-os.iso"
BIOS="${ZERO_OS_QEMU_BIOS:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}"
OUT="$ROOT/target/hardware-acceptance"
QEMU="${ZERO_OS_QEMU:-qemu-system-aarch64}"
mkdir -p "$OUT"

SKIP_BUILD=0
case "${1:-}" in
  "") SKIP_BUILD=0 ;;
  --no-build) SKIP_BUILD=1 ;;
  *) echo "hardware-acceptance: 用法: $0 [--no-build]" >&2; exit 2 ;;
esac

command -v "$QEMU" >/dev/null || { echo "missing $QEMU" >&2; exit 1; }
[ -f "$BIOS" ] || { echo "missing BIOS $BIOS" >&2; exit 1; }
if [ "$SKIP_BUILD" -eq 0 ]; then
  cargo run -p xtask -- build-iso
fi
[ -f "$ISO" ] || { echo "missing $ISO" >&2; exit 1; }

pass=0
fail=0
check() {
  name="$1"; pattern="$2"; log="$3"
  if grep -aqF -- "$pattern" "$log"; then
    printf '%-34s PASS\n' "$name"
    pass=$((pass + 1))
  else
    printf '%-34s FAIL  missing: %s\n' "$name" "$pattern"
    fail=$((fail + 1))
  fi
}
check_absent() {
  name="$1"; pattern="$2"; log="$3"
  if grep -aqE -- "$pattern" "$log"; then
    printf '%-34s FAIL  forbidden: %s\n' "$name" "$pattern"
    fail=$((fail + 1))
  else
    printf '%-34s PASS\n' "$name"
    pass=$((pass + 1))
  fi
}

kill_pid() { [ -z "${1:-}" ] || kill "$1" 2>/dev/null || true; }
wait_for() {
  log="$1"; pattern="$2"; pid="$3"; half_seconds="$4"
  i=0
  while [ "$i" -lt "$half_seconds" ]; do
    grep -aqF -- "$pattern" "$log" 2>/dev/null && return 0
    kill -0 "$pid" 2>/dev/null || return 1
    sleep .5
    i=$((i + 1))
  done
  return 1
}

# EDK2 may prefer a newly attached empty PCI/NVMe test disk over the ISO.
# Pin optical boot first so device-enumeration order cannot turn an OS test into
# a firmware boot-order timeout.
COMMON_MACHINE=(-machine virt,gic-version=3,its=on,msi=its -cpu cortex-a72 -m 1024 -bios "$BIOS" -display none -boot order=d -cdrom "$ISO")

# ---------------------------------------------------------------------------
# K35 + K36: PCIe high ECAM / BAR / EL0 lease + ITS/MSI/affinity/SMP4
# ---------------------------------------------------------------------------
LOG="$OUT/k35-k36.log"; rm -f "$LOG"
"$QEMU" "${COMMON_MACHINE[@]}" -smp 4 -serial file:"$LOG" \
  -device pci-testdev -device edu >"$OUT/k35-k36.qemu.log" 2>&1 &
PID=$!
wait_for "$LOG" "blkdrv: PCI MMIO LEASE SELFTEST PASS" "$PID" 120 || true
sleep 1; kill_pid "$PID"; wait "$PID" 2>/dev/null || true

echo "== Knife35 PCIe Core =="
check "K35 high ECAM" "pcie: high ECAM mapped phys=0x4010000000" "$LOG"
check "K35 enumeration" "pcie: enumeration complete" "$LOG"
check "K35 BAR R/W" "pcie: pci-testdev BAR0 MMIO R/W PASS" "$LOG"
check "K35 EL0 MMIO lease" "blkdrv: PCI MMIO LEASE SELFTEST PASS" "$LOG"

echo "== Knife36 GICv3 / ITS / MSI-X =="
check "K36 ITS selftest" "gicv3: ITS/LPI SELFTEST PASS" "$LOG"
check "K36 real PCI MSI" "pcie: EDU MSI PASS" "$LOG"
check "K36 IRQ affinity" "target_cpu=1 actual_cpu=1" "$LOG"
check "K36 SMP4 online" "smp: boot_secondaries done, online=4 multi_core=true" "$LOG"
check_absent "K35/36 no kernel fault" "panic at|SYSTEM HALT|\[KERNEL FAULT\]" "$LOG"

# ---------------------------------------------------------------------------
# K37: modern VirtIO PCI transport only (no virtio-mmio devices attached)
# ---------------------------------------------------------------------------
LOG="$OUT/k37.log"; DISK="$OUT/k37.img"; rm -f "$LOG" "$DISK"; truncate -s 32M "$DISK"
"$QEMU" "${COMMON_MACHINE[@]}" -smp 4 -serial file:"$LOG" \
  -drive if=none,file="$DISK",format=raw,id=k37disk,cache=writethrough \
  -device virtio-blk-pci-non-transitional,drive=k37disk \
  -netdev user,id=k37net -device virtio-net-pci-non-transitional,netdev=k37net \
  -object rng-random,filename=/dev/urandom,id=k37rng -device virtio-rng-pci-non-transitional,rng=k37rng \
  -device virtio-gpu-pci \
  -device virtio-keyboard-pci -device virtio-tablet-pci \
  -audiodev driver=none,id=k37audio -device virtio-sound-pci,audiodev=k37audio \
  >"$OUT/k37.qemu.log" 2>&1 &
PID=$!
wait_for "$LOG" "netd: DHCP bound" "$PID" 240 || true
sleep 1; kill_pid "$PID"; wait "$PID" 2>/dev/null || true

echo "== Knife37 VirtIO PCI Transport =="
check "K37 blk PCI" "virtio-pci: virtio-blk-pci" "$LOG"
check "K37 blk data path" "driver: virtio-blk 自检通过" "$LOG"
check "K37 net PCI" "virtio-pci: virtio-net-pci" "$LOG"
check "K37 net DHCP" "netd: DHCP bound" "$LOG"
check "K37 rng PCI" "virtio-pci: virtio-rng-pci" "$LOG"
check "K37 gpu PCI" "virtio-pci: virtio-gpu-pci" "$LOG"
check "K37 input PCI" "virtio-pci: virtio-input-pci" "$LOG"
check "K37 sound PCI" "virtio-pci: virtio-sound-pci" "$LOG"
check "K37 SMP4 + GPU stable" "smp: boot_secondaries done, online=4 multi_core=true" "$LOG"
check "K37 shell" "Zero OS console (user shell)" "$LOG"
check_absent "K37 no kernel fault" "panic at|SYSTEM HALT|\[KERNEL FAULT\]" "$LOG"

# ---------------------------------------------------------------------------
# K38: SMMUv3/IORT production domain API + iommu-testdev
# ---------------------------------------------------------------------------
LOG="$OUT/k38.log"; rm -f "$LOG"
"$QEMU" -machine virt,gic-version=3,its=on,msi=its,iommu=smmuv3 \
  -cpu cortex-a72 -smp 1 -m 1024 -bios "$BIOS" -display none -boot order=d -serial file:"$LOG" \
  -cdrom "$ISO" -device iommu-testdev >"$OUT/k38.qemu.log" 2>&1 &
PID=$!
wait_for "$LOG" "smmuv3: DOMAIN MAP/UNMAP/DETACH PASS" "$PID" 120 || true
sleep 1; kill_pid "$PID"; wait "$PID" 2>/dev/null || true

echo "== Knife38 IOMMU / IORT / SMMUv3 =="
check "K38 IORT discovery" "smmuv3: IORT base=" "$LOG"
check "K38 CMDQ+EVTQ" "smmuv3: enabled; CMDQ+EVTQ online" "$LOG"
check "K38 mapped DMA" "smmuv3: mapped IOVA DMA PASS" "$LOG"
check "K38 unmapped fault" "smmuv3: UNMAPPED IOVA FAULT PASS" "$LOG"
check "K38 domain detach" "smmuv3: DOMAIN MAP/UNMAP/DETACH PASS" "$LOG"
check_absent "K38 no kernel fault" "panic at|SYSTEM HALT|\[KERNEL FAULT\]" "$LOG"

# ---------------------------------------------------------------------------
# K39: qemu-xhci + USB keyboard/tablet; inject a real key through QMP.
# ---------------------------------------------------------------------------
LOG="$OUT/k39.log"; QMP="$OUT/k39.qmp"; rm -f "$LOG" "$QMP"
"$QEMU" "${COMMON_MACHINE[@]}" -smp 1 -serial file:"$LOG" \
  -qmp unix:"$QMP",server=on,wait=off \
  -device qemu-xhci,id=k39xhci -device usb-kbd,bus=k39xhci.0 -device usb-tablet,bus=k39xhci.0 \
  >"$OUT/k39.qemu.log" 2>&1 &
PID=$!
wait_for "$LOG" "driver: xHCI online usb_hid=2" "$PID" 120 || true
python3 - "$QMP" <<'PY' || true
import json, socket, sys, time
path=sys.argv[1]
for _ in range(50):
    try:
        s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(path); break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit(1)
f=s.makefile('rwb', buffering=0)
f.readline()
f.write(json.dumps({'execute':'qmp_capabilities'}).encode()+b'\n'); f.readline()
f.write(json.dumps({'execute':'human-monitor-command','arguments':{'command-line':'sendkey a'}}).encode()+b'\n')
f.readline(); time.sleep(.5); s.close()
PY
wait_for "$LOG" "inputd: USB HID normalized event PASS" "$PID" 40 || true
sleep 1; kill_pid "$PID"; wait "$PID" 2>/dev/null || true

echo "== Knife39 USB / xHCI / HID =="
check "K39 xHCI PCI" "xhci: PCI" "$LOG"
check "K39 two USB HID" "driver: xHCI online usb_hid=2" "$LOG"
check "K39 input ABI injection" "xhci: INPUT EVENT PATH PASS" "$LOG"
check "K39 inputd normalized" "inputd: USB HID normalized event PASS" "$LOG"
check "K39 WindowServer" "Zero OS WindowServer online" "$LOG"
check_absent "K39 no virtio-input PCI" "virtio-pci: virtio-input-pci" "$LOG"
check_absent "K39 no kernel fault" "panic at|SYSTEM HALT|\[KERNEL FAULT\]" "$LOG"

# ---------------------------------------------------------------------------
# K40: fresh NVMe-only root block device + ZFS + signed ZeroPkg over local TLS.
# ---------------------------------------------------------------------------
FIX="$OUT/pkgrepo"; APP="$FIX/PkgTest.app"; rm -rf "$FIX"; mkdir -p "$APP"
cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none \
  -p zero-pkghello --release >/dev/null
cp target/aarch64-unknown-none/release/zero-pkghello "$APP/main"
cat > "$APP/config" <<'EOF'
name = "PkgTest"
identifier = "org.zero.pkgtest"
version = "1.0.0"
storage = "1MiB"
description = "Zero OS hardware acceptance package"
EOF
cargo run -q -p zero-user-commands --bin zeropkg -- pack "$APP" -o "$FIX/pkgtest.zpkg" \
  --origin zero-os --sign-key tools/testkeys/zeropkg-zero-os-dev.seed.hex >/dev/null

if lsof -iTCP:8443 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "hardware-acceptance: TCP 8443 already in use; K40 local repo needs it" >&2
  exit 1
fi
(
  cd "$FIX"
  exec openssl s_server -accept 8443 \
    -cert "$ROOT/tools/testkeys/zeropkg-repo-server.cert.pem" \
    -key "$ROOT/tools/testkeys/zeropkg-repo-server.key.pem" -WWW -quiet
) >"$OUT/k40.tls.log" 2>&1 &
TLSPID=$!
for i in $(seq 1 30); do
  lsof -iTCP:8443 -sTCP:LISTEN >/dev/null 2>&1 && break
  sleep .1
done

LOG="$OUT/k40.log"; DISK="$OUT/k40-nvme.img"; rm -f "$LOG" "$DISK"; truncate -s 32M "$DISK"
{
  sleep 32
  printf 'launchd spawn pkgtest\r'; sleep 38
  printf 'fstest\r'; sleep 15
  printf 'fsdemo\r'; sleep 15
} | "$QEMU" "${COMMON_MACHINE[@]}" -smp 4 -serial mon:stdio \
  -drive if=none,file="$DISK",format=raw,id=k40nvme,cache=writethrough \
  -device nvme,drive=k40nvme,serial=ZEROOSHARDWARE \
  -netdev user,id=k40net -device virtio-net-pci-non-transitional,netdev=k40net \
  -object rng-random,filename=/dev/urandom,id=k40rng -device virtio-rng-pci-non-transitional,rng=k40rng \
  >"$LOG" 2>&1 &
PID=$!
wait_for "$LOG" "fsdemo: PASS (mkdir/list/unlink/rmdir tree semantics)" "$PID" 200 || true
sleep 1; kill_pid "$PID"; wait "$PID" 2>/dev/null || true; kill_pid "$TLSPID"; wait "$TLSPID" 2>/dev/null || true

echo "== Knife40 NVMe =="
check "K40 NVMe namespace" "nvme: namespace 1 online" "$LOG"
check "K40 NVMe R/W/flush" "nvme: READ/WRITE/FLUSH SELFTEST PASS" "$LOG"
check "K40 NVMe MSI-X" "nvme: MSI-X interrupt path PASS" "$LOG"
check "K40 blk backend abstraction" "blkdrv: passthrough backend ready (NVMe via kernel svc 7/8)" "$LOG"
check "K40 ZeroPkg install" "pkgtest: INSTALL PASS" "$LOG"
check "K40 ZeroPkg launch" "pkgtest: LAUNCH PASS" "$LOG"
check "K40 ZeroPkg full E2E" "pkgtest: ALL PASS" "$LOG"
check "K40 ZFS fstest" "fstest: PASS - fsd block-backed volume verified end-to-end" "$LOG"
check "K40 ZFS fsdemo" "fsdemo: PASS (mkdir/list/unlink/rmdir tree semantics)" "$LOG"
check_absent "K40 no virtio-blk backend" "driver: virtio-blk 初始化完成" "$LOG"
check_absent "K40 no unhandled RNG IRQ" "无处理器" "$LOG"
check_absent "K40 no kernel fault" "panic at|SYSTEM HALT|\[KERNEL FAULT\]" "$LOG"

# Keep logs; images are disposable and large.
rm -f "$OUT/k37.img" "$OUT/k40-nvme.img"

echo "--------------------------------------------"
total=$((pass + fail))
if [ "$fail" -eq 0 ]; then
  echo "hardware-acceptance: ALL PASS ($total/$total)"
  exit 0
fi
echo "hardware-acceptance: $fail/$total FAILED"
exit 1
