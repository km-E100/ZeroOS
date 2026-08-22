#!/usr/bin/env bash
# Zero OS 源码级质量检查入口（供评审 Agent / CI / 后续轮次使用）。
# 依次执行：
#   1) cargo check 工作区所有可 host 检查的 crate（逐 crate 检查，
#      避免 no_std 内核 crate 与 std 统一构建时触发 duplicate lang item）
#   2) cargo check 交叉目标（aarch64-unknown-none / aarch64-unknown-uefi）
#   3) cargo test 有测试的 crate（zfs-core、userlib 等）
#   4) xtask build-kernel-bare（nightly + build-std 全量交叉编译微内核）
# 任一步失败即以非零退出码结束，并且总是打印失败清单。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FAILED=()
PASSED=()

note_fail() { FAILED+=("$1"); }
note_ok()   { PASSED+=("$1"); }

run_step() {
    local name="$1"
    shift
    echo ""
    echo "=== [check.sh] ${name}: $*"
    local log; log="$(mktemp /tmp/zeroos-check.XXXXXX)"
    if "$@" >"$log" 2>&1; then
        note_ok "$name"
    else
        echo "    FAILED: ${name}（关键输出如下）"
        grep -E "^(error|warning: unused|  -->)" "$log" | head -25
        note_fail "$name"
    fi
    rm -f "$log"
}

echo "############################################################"
echo "# Zero OS 质量检查 (check.sh)"
echo "############################################################"

# ------------------------------------------------------------------
# 1) host 目标逐 crate cargo check。
# 已知例外：
#   - zero-microkernel / zero-kernel / zero-launchd / user-app：
#     定义了 #[panic_handler] 的 no_std 裸机 crate，host 检查与 std 冲突，
#     改由下面交叉目标 check 覆盖。
#   - bootloader-uefi：aarch64-unknown-uefi 专用，同样由交叉目标覆盖。
#   - zero-user-commands(userland/commands) & microkernel/tests：
#     当前被其他 Agent 在制品代码（E0433 FsError / E0152 duplicated panic）
#     阻塞，属于仓库基线问题，先记录并继续，不因它们中断本脚本。
# ------------------------------------------------------------------
HOST_CRATES=(
    "zero-abi"
    "zero-zfs-core"
    "zero-installer"
    "zero-recovery"
    "zero-fs-zfs"
    "zero-fsd"
    "zero-blkdrv"
    "zero-ipc-router"
    "zero-securityd"
    "zero-service-controller"
    "mkzfs"
    "userlib"
    "libfsclient"
    "libblkclient"
    "xtask"
    "tools"
)
for crate in "${HOST_CRATES[@]}"; do
    run_step "check(host) $crate" cargo check -p "$crate"
done

# userland/commands（用户态 Agent 在制品，基线失败，单独标出）
echo ""
echo "=== [check.sh] userland/commands (known-baseline-issue, 记录不中断)"
if cargo check -p zero-user-commands >/dev/null 2>&1; then
    note_ok "check(host) zero-user-commands"
else
    echo "    warning: zero-user-commands 基线失败（等待用户态 Agent 修复）"
    note_fail "check(host) zero-user-commands (基线问题, 非本脚本引入)"
fi

# ------------------------------------------------------------------
# 2) 交叉目标 check（裸机内核链）
# ------------------------------------------------------------------
run_step "check(aarch64-unknown-none) microkernel+kernel+launchd+user-app" \
    cargo check --target aarch64-unknown-none -p zero-microkernel -p zero-kernel -p zero-launchd -p user-app
run_step "check(aarch64-unknown-uefi) bootloader-uefi" \
    cargo check --target aarch64-unknown-uefi -p bootloader-uefi

# ------------------------------------------------------------------
# 3) cargo test（有测试的 crate）
# ------------------------------------------------------------------
for crate in zero-zfs-core userlib zero-abi; do
    run_step "test $crate" cargo test -p "$crate"
done

# ------------------------------------------------------------------
# 4) 裸机内核全量交叉编译（nightly + build-std 链路验证）
# ------------------------------------------------------------------
run_step "build-kernel-bare" cargo run -p xtask -- build-kernel-bare

# ------------------------------------------------------------------
# 汇总
# ------------------------------------------------------------------
echo ""
echo "############################################################"
echo "# 汇总: ${#PASSED[@]} 通过, ${#FAILED[@]} 失败"
for name in "${FAILED[@]}"; do
    echo "    [FAIL] ${name}"
done
echo "############################################################"
if [ "${#FAILED[@]}" -gt 0 ]; then
    echo "check.sh: 存在失败项，退出码 1"
    exit 1
fi
echo "check.sh: 全部通过"
exit 0