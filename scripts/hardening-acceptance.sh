#!/usr/bin/env bash
# Zero OS Knife 41~44 production-hardening acceptance.
# K41 power/auth, K42 PCIe bridge topology, K43 NVMe production hardening,
# K44 xHCI hub/hotplug/recovery.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ISO="$ROOT/target/zero-os.iso"
BIOS="${ZERO_OS_QEMU_BIOS:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}"
QEMU="${ZERO_OS_QEMU:-qemu-system-aarch64}"
OUT="$ROOT/target/hardening-acceptance"
mkdir -p "$OUT"
SKIP_BUILD=0
case "${1:-}" in
  "") ;;
  --no-build) SKIP_BUILD=1 ;;
  *) echo "usage: $0 [--no-build]" >&2; exit 2 ;;
esac
command -v "$QEMU" >/dev/null
[ -f "$BIOS" ]
if [ "$SKIP_BUILD" -eq 0 ]; then cargo run -p xtask -- build-iso; fi
[ -f "$ISO" ]
pass=0; fail=0
ok(){ printf '%-38s PASS\n' "$1"; pass=$((pass+1)); }
bad(){ printf '%-38s FAIL  %s\n' "$1" "$2"; fail=$((fail+1)); }
need(){ if grep -aqF -- "$2" "$3"; then ok "$1"; else bad "$1" "missing: $2"; fi; }
need_re(){ if grep -aqE -- "$2" "$3"; then ok "$1"; else bad "$1" "missing regex: $2"; fi; }
clean(){ if grep -aqE 'panic at|\[KERNEL FAULT\]|SYSTEM HALT|owner mismatch|still owned by cpu' "$2"; then bad "$1" 'kernel fault marker'; else ok "$1"; fi; }

# K41 shutdown: unauthenticated request denied, admin request really powers QEMU off.
L="$OUT/k41-shutdown.log"; rm -f "$L"
set +e
{
  sleep 16; printf 'shutdown\r'; sleep 3
  printf 'login\r'; sleep 2; printf 'root\r'; sleep 1; printf 'zero\r'; sleep 3
  printf 'shutdown\r'; sleep 15
} | "$QEMU" -machine virt,gic-version=3,its=on,msi=its -cpu cortex-a72 -smp 4 -m 1024 \
  -bios "$BIOS" -display none -boot order=d -serial mon:stdio -cdrom "$ISO" >"$L" 2>&1
K41_RC=$?
set -e
echo '== Knife41 Power / Firmware =='
need 'K41 unauth power denied' 'power: denied (admin login required)' "$L"
need 'K41 admin login' 'welcome root (session id=' "$L"
need 'K41 PSCI SYSTEM_OFF' 'power: requesting shutdown via PSCI' "$L"
[ "$K41_RC" -eq 0 ] && ok 'K41 QEMU actually powered off' || bad 'K41 QEMU actually powered off' "rc=$K41_RC"
clean 'K41 shutdown no kernel fault' "$L"

# K41 reboot: require a second EDK2 boot banner after PSCI reset. Run QEMU
# in the foreground and terminate it through mon:stdio Ctrl-A x after the reboot
# window. This avoids the old background-pipeline PID ambiguity that could leave
# an orphan QEMU process after the test completed.
L="$OUT/k41-reboot.log"; rm -f "$L"
set +e
{
  sleep 16; printf 'login\r'; sleep 2; printf 'root\r'; sleep 1; printf 'zero\r'; sleep 3
  printf 'reboot\r'; sleep 18
  printf '\001x'
} | "$QEMU" -machine virt,gic-version=3,its=on,msi=its -cpu cortex-a72 -smp 4 -m 1024 \
  -bios "$BIOS" -display none -boot order=d -serial mon:stdio -cdrom "$ISO" >"$L" 2>&1
K41_REBOOT_RC=$?
set -e
need 'K41 PSCI SYSTEM_RESET' 'power: requesting reboot via PSCI' "$L"
boots=$(grep -acF 'UEFI firmware' "$L" || true)
[ "$boots" -ge 2 ] && ok 'K41 firmware reboot observed' || bad 'K41 firmware reboot observed' "boot banners=$boots"
[ "$K41_REBOOT_RC" -eq 0 ] && ok 'K41 reboot runner exited cleanly' || bad 'K41 reboot runner exited cleanly' "rc=$K41_REBOOT_RC"
clean 'K41 reboot no kernel fault' "$L"

# K42: two root ports and two independent downstream devices/windows.
L="$OUT/k42-rootports.log"; D="$OUT/k42-nvme.img"; rm -f "$L" "$D"; truncate -s 32M "$D"
"$QEMU" -machine virt,gic-version=3,its=on,msi=its -cpu cortex-a72 -smp 4 -m 1024 \
  -bios "$BIOS" -display none -boot order=d -serial file:"$L" -cdrom "$ISO" \
  -device pcie-root-port,id=rp1,bus=pcie.0,addr=2.0,chassis=1,slot=1,mem-reserve=16M,pref64-reserve=64M \
  -drive if=none,file="$D",format=raw,id=k42nv -device nvme,drive=k42nv,serial=K42NVME,bus=rp1 \
  -device pcie-root-port,id=rp2,bus=pcie.0,addr=3.0,chassis=2,slot=2,mem-reserve=16M,pref64-reserve=64M \
  -device qemu-xhci,id=k42xhci,bus=rp2 >"$OUT/k42.qemu.log" 2>&1 & P=$!
for _ in $(seq 1 180); do sleep .25; grep -aqF 'Zero OS pkgd online' "$L" 2>/dev/null && { sleep 1; break; }; kill -0 "$P" 2>/dev/null || break; done
kill "$P" 2>/dev/null || true; wait "$P" 2>/dev/null || true
echo '== Knife42 PCIe Real-Hardware Hardening =='
need_re 'K42 root-port1 bridge window' 'pcie: bridge 0000:00:02\.0 buses=1->1 .*mem=\[0x[1-9a-f].*pref=\[0x[1-9a-f]' "$L"
need_re 'K42 root-port2 bridge window' 'pcie: bridge 0000:00:03\.0 buses=2->2 .*mem=\[0x[1-9a-f].*pref=\[0x[1-9a-f]' "$L"
need_re 'K42 downstream NVMe' 'pcie: 0000:01:00\.0 .* class=01:08:02' "$L"
need_re 'K42 downstream xHCI' 'pcie: 0000:02:00\.0 .* class=0c:03:30' "$L"
need 'K42 NVMe behind bridge active' 'nvme: PCI 0000:01:00.0' "$L"
need 'K42 xHCI behind bridge active' 'xhci: PCI 0000:02:00.0' "$L"
need 'K42 NVMe recovery across bridge' 'nvme: RESET/RECOVERY SELFTEST PASS' "$L"
need 'K42 xHCI recovery across bridge' 'xhci: RESET/RECOVERY SELFTEST PASS' "$L"
clean 'K42 no kernel fault' "$L"

# K43: 4K namespace first + second namespace, 4 queues, RMW, ZFS.
L="$OUT/k43-nvme4k.log"; D1="$OUT/k43-ns1-4k.img"; D2="$OUT/k43-ns2-512.img"
rm -f "$L" "$D1" "$D2"; truncate -s 64M "$D1"; truncate -s 32M "$D2"
{
  sleep 20; printf 'fstest\r'; sleep 14; printf 'fsdemo\r'; sleep 14
} | "$QEMU" -machine virt,gic-version=3,its=on,msi=its -cpu cortex-a72 -smp 4 -m 1024 \
  -bios "$BIOS" -display none -boot order=d -serial mon:stdio -cdrom "$ISO" \
  -device nvme-subsys,id=k43sub,nqn=nqn.2026-08.zeroos:k43 \
  -device nvme,id=k43nv,serial=K43HARDEN,subsys=k43sub,max_ioqpairs=8 \
  -drive if=none,file="$D1",format=raw,id=k43d1,cache=writethrough \
  -device nvme-ns,drive=k43d1,bus=k43nv,nsid=1,logical_block_size=4096,physical_block_size=4096 \
  -drive if=none,file="$D2",format=raw,id=k43d2,cache=writethrough \
  -device nvme-ns,drive=k43d2,bus=k43nv,nsid=2,logical_block_size=512,physical_block_size=512 \
  >"$L" 2>&1 & P=$!
for _ in $(seq 1 260); do sleep .25; grep -aqF 'fsdemo: PASS (mkdir/list/unlink/rmdir tree semantics)' "$L" 2>/dev/null && break; kill -0 "$P" 2>/dev/null || break; done
kill "$P" 2>/dev/null || true; wait "$P" 2>/dev/null || true
echo '== Knife43 NVMe Production Hardening =='
need 'K43 namespace1 discovered' 'nvme: namespace 1 discovered' "$L"
need 'K43 native 4K LBA' 'lba=4096B' "$L"
need 'K43 namespace2 discovered' 'nvme: namespace 2 discovered' "$L"
need 'K43 per-CPU I/O queues' 'io_queues=4' "$L"
need 'K43 512B-on-4K RMW' 'nvme: 512B ABI/NATIVE RMW SELFTEST PASS native=4096B' "$L"
need 'K43 reset/recovery multi-NS' 'RESET/RECOVERY PASS queues=4 namespaces=2' "$L"
need 'K43 ZFS fstest on 4K NS' 'fstest: PASS - fsd block-backed volume verified end-to-end' "$L"
need 'K43 ZFS fsdemo on 4K NS' 'fsdemo: PASS (mkdir/list/unlink/rmdir tree semantics)' "$L"
clean 'K43 no kernel fault' "$L"

# K44: xHCI -> hub -> keyboard, then QMP add/remove mouse downstream.
L="$OUT/k44-hub.log"; Q="$OUT/k44.qmp"; rm -f "$L" "$Q"
"$QEMU" -machine virt,gic-version=3,its=on,msi=its -cpu cortex-a72 -smp 4 -m 1024 \
  -bios "$BIOS" -display none -boot order=d -serial file:"$L" -qmp unix:"$Q",server=on,wait=off -cdrom "$ISO" \
  -device qemu-xhci,id=k44xhci -device usb-hub,id=k44hub,bus=k44xhci.0,port=1,ports=8 \
  -device usb-kbd,id=k44kbd,bus=k44xhci.0,port=1.1 >"$OUT/k44.qemu.log" 2>&1 & P=$!
qmp(){ python3 - "$Q" "$1" <<'PY'
import json,socket,sys
path,payload=sys.argv[1],json.loads(sys.argv[2]); s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(path); f=s.makefile('rwb',buffering=0)
f.readline(); f.write((json.dumps({'execute':'qmp_capabilities'})+'\n').encode())
while True:
 r=json.loads(f.readline())
 if 'return' in r: break
f.write((json.dumps(payload)+'\n').encode())
while True:
 r=json.loads(f.readline())
 if 'error' in r: raise SystemExit(str(r))
 if 'return' in r: break
s.close()
PY
}
for _ in $(seq 1 220); do sleep .25; grep -aqF 'xhci: RESET/RECOVERY SELFTEST PASS' "$L" 2>/dev/null && break; kill -0 "$P" 2>/dev/null || break; done
qmp '{"execute":"human-monitor-command","arguments":{"command-line":"sendkey a"}}'
for _ in $(seq 1 80); do sleep .15; grep -aqF 'inputd: USB HID normalized event PASS' "$L" && break; done
qmp '{"execute":"device_add","arguments":{"driver":"usb-mouse","id":"k44hotmouse","bus":"k44xhci.0","port":"1.2"}}'
for _ in $(seq 1 120); do sleep .15; grep -aqE 'HID=Mouse|HID Mouse READY' "$L" && break; done
qmp '{"execute":"device_del","arguments":{"id":"k44hotmouse"}}'
for _ in $(seq 1 120); do sleep .15; grep -aqE 'HOTPLUG disconnect hub_slot=.*port=2' "$L" && break; done
kill "$P" 2>/dev/null || true; wait "$P" 2>/dev/null || true; rm -f "$Q"
echo '== Knife44 USB/xHCI Production Hardening =='
need_re 'K44 hub enumerated' 'usb: HUB READY .*ports=' "$L"
need_re 'K44 routed downstream keyboard' 'HID Keyboard READY .*route=0x1' "$L"
need 'K44 recovery preserves topology' 'xhci: CONTROLLER RECOVERY PASS hid=1 hubs=1' "$L"
need 'K44 controller recovery selftest' 'xhci: RESET/RECOVERY SELFTEST PASS' "$L"
need 'K44 real keyboard input' 'xhci: INPUT EVENT PATH PASS' "$L"
need 'K44 inputd normalization' 'inputd: USB HID normalized event PASS' "$L"
need_re 'K44 hotplug mouse enumerated' 'HID=Mouse|HID Mouse READY' "$L"
need_re 'K44 hot-unplug reaped' 'HOTPLUG disconnect hub_slot=.*port=2' "$L"
clean 'K44 no kernel fault' "$L"

echo '--------------------------------------------'
total=$((pass+fail))
if [ "$fail" -eq 0 ]; then
  echo "hardening-acceptance: ALL PASS ($total/$total)"
else
  echo "hardening-acceptance: $fail/$total FAILED"
  exit 1
fi
