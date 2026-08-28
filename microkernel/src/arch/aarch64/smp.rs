//! SMP 多核支持（结构性天花板立项 · 阶段 0-2）。
//!
//! ## 启动协议
//! 主核（MPIDR aff0=0）走 UEFI→kernel_main 原路；`boot_secondaries`
//! 在用户态拉起前以 PSCI `CPU_ON` 探测 1..MAX_CPUS。AArch64 优先
//! 使用 native 64-bit FID 0xC400_0003；仅当固件明确返回 NOT_SUPPORTED
//! 时回退 32-bit FID 0x8400_0003。副核入口
//! `__secondary_entry`（arch/aarch64.rs）：独立 per-cpu 栈 + TPIDR 指
//! per-cpu idle scratch 帧 → `smp_secondary_main`。
//!
//! ## FP 语义裁决
//! MULTI_CORE 翻转后 FPEN=0b11 + FPU_DIRTY 冻结 NONE：入口存根的惰性
//! 门控自动退化为全急切保存（dirty≠owner 恒真），exit 侧由
//! restore_context 的 eager 分支全量装载——即第八刀语义，帧相对、
//! TPIDR 每 core 一份，跨核天然安全。单核路径（QEMU 默认 -smp 1）
//! 完整保留第十一刀惰性门。
//!
//! ## TLB 安全论证（为何阶段 0-2 无需 IPI 击落）
//! dispatch→activate 每次切换都 `tlbi vmalle1` 全量清本核 TLB；故每核
//! TLB 中只可能存在"该核正在/刚运行过的进程"的映射项，进程销毁后其
//! 陈旧项必然被该核下一次切换清空——无跨核悬脏窗口。IPI 击落优化与
//! COW 重开一并归入阶段 3。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

extern "C" {
    static __secondary_entry: u8;
}

/// 探测上核数上限（QEMU virt `-smp` 上限远超此值；够用）。
pub const MAX_CPUS: usize = 4;

/// 已上线核数（含主核）。主核恒先登记。
static ONLINE: AtomicUsize = AtomicUsize::new(1);
/// 多核模式总闸：翻转后 FP 走全急切、调度器跳过惰性降门。
static MULTI_CORE: AtomicBool = AtomicBool::new(false);

/// 当前逻辑 CPU 序号。PSCI CPU_ON 的 context_id 在副核入口 x0，
/// 入口写入 TPIDRRO_EL0；主核在 boot_secondaries 开头写 0。
/// 因此不依赖 MPIDR 必须落在 Aff0，真实硬件的 Aff1/Aff2 拓扑也安全。
#[inline(always)]
pub fn cpu_id() -> usize {
    #[cfg(test)]
    {
        0
    }
    #[cfg(not(test))]
    {
        let id: u64;
        unsafe { core::arch::asm!("mrs {}, tpidrro_el0", out(reg) id) };
        (id as usize).min(MAX_CPUS - 1)
    }
}

#[inline(always)]
pub fn online_count() -> usize {
    ONLINE.load(Ordering::Acquire)
}

#[inline(always)]
pub fn multi_core_active() -> bool {
    MULTI_CORE.load(Ordering::Acquire)
}

#[inline(always)]
pub fn online_mask() -> u32 {
    let n = online_count().min(MAX_CPUS);
    if n >= 32 {
        u32::MAX
    } else {
        (1u32 << n) - 1
    }
}

/// 主核侧：翻多核闸 → 探测点亮副核。幂等（仅 kernel_main 调用一次）。
///
/// 顺序纪律：必须先翻 MULTI_CORE + 切 FPEN=0b11 + 打开 FPU_EAGER_SMP，
/// 再发 CPU_ON——副核一上线就可能与主核并发跑调度/陷阱，FP 语义
/// 必须先行切换到“每异常 save / 每恢复 load”的跨核安全形态。
pub fn boot_secondaries() {
    unsafe { core::arch::asm!("msr tpidrro_el0, {}", in(reg) 0u64) };
    MULTI_CORE.store(true, Ordering::SeqCst);
    // FP 门位全开（EL0 不再因 FP 陷阱进内核）；fpu_freeze_none 同时
    // 打开 FPU_EAGER_SMP，入口存根从此无条件保存本 PE 的 FP/SIMD 现场。
    crate::arch::fpu_arm_full_access();
    crate::arch::fpu_freeze_none();
    // GICD 已由主核初始化；SGI0（RESCHED）在 GICv2 恒使能，无需配置。

    // 优先按 ACPI MADT 枚举；无 ACPI 时保留 legacy 探测。只统计
    // firmware 真正接受的 CPU_ON 请求，避免在 NOT_SUPPORTED 平台上
    // 仍按 MADT 声称核数空转等待。
    let mut topology = crate::acpi::cpu_mpidrs();
    let boot_topology = crate::bootinfo::boot_cpu_mpidrs();
    crate::info!(
        "smp: topology runtime={:?} uefi_mp={:?}",
        topology,
        boot_topology
    );
    if topology.len() <= 1 && boot_topology.len() > topology.len() {
        crate::info!(
            "smp: runtime MADT has {} possible CPU(s); using UEFI MP handoff {:?}",
            topology.len(),
            boot_topology
        );
        topology = boot_topology;
    }
    let inventory = crate::acpi::cpu_inventory();
    crate::info!(
        "smp: ACPI inventory={} possible={} psci={:?}",
        inventory.len(),
        topology.len(),
        crate::acpi::psci_conduit()
    );
    for cpu in &inventory {
        crate::info!(
            "smp: ACPI cpu uid={} mpidr={:#x} enabled={} online_capable={} park_ver={} parked={:#x}",
            cpu.uid,
            cpu.mpidr,
            cpu.enabled,
            cpu.online_capable,
            cpu.parking_protocol_version,
            cpu.parked_address
        );
    }
    let mut requested = 0usize;
    if topology.len() > 1 {
        // MADT does not promise that the boot CPU is entry 0. Compare only
        // architectural affinity fields (Aff3..Aff0), ignoring MPIDR flags.
        const AFFINITY_MASK: u64 = 0x0000_00ff_00ff_ffff;
        let boot_mpidr: u64;
        unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) boot_mpidr) };
        let boot_affinity = boot_mpidr & AFFINITY_MASK;
        let mut logical = 1usize;
        for mpidr in topology.into_iter() {
            if mpidr & AFFINITY_MASK == boot_affinity {
                continue;
            }
            if logical >= MAX_CPUS {
                break;
            }
            let result = psci_cpu_on(
                mpidr,
                unsafe { &__secondary_entry } as *const u8 as usize,
                logical,
            );
            if result.ok {
                crate::info!(
                    "smp: cpu{} CPU_ON accepted via MADT mpidr={:#x}",
                    logical,
                    mpidr
                );
                requested += 1;
                logical += 1;
            } else {
                crate::warn!("smp: MADT CPU_ON mpidr={:#x} failed={}", mpidr, result.raw);
                if result.raw == PSCI_NOT_SUPPORTED {
                    crate::warn!("smp: PSCI CPU_ON unsupported; falling back to single-core");
                    break;
                }
            }
        }
    } else {
        'outer: for cpu in 1..MAX_CPUS {
            for mpidr in legacy_mpidr_candidates(cpu) {
                let result = psci_cpu_on(
                    mpidr,
                    unsafe { &__secondary_entry } as *const u8 as usize,
                    cpu,
                );
                if result.ok {
                    crate::info!(
                        "smp: cpu{} CPU_ON accepted via legacy mpidr={:#010x}",
                        cpu,
                        mpidr
                    );
                    requested += 1;
                    continue 'outer;
                }
                if result.raw == PSCI_NOT_SUPPORTED {
                    crate::warn!("smp: PSCI CPU_ON unsupported; falling back to single-core");
                    break 'outer;
                }
                crate::warn!(
                    "smp: CPU_ON candidate logical={} mpidr={:#010x} failed={} ({})",
                    cpu,
                    mpidr,
                    result.raw,
                    psci_status_name(result.raw)
                );
            }
            crate::info!("smp: cpu{} exhausted, online={}", cpu, online_count());
            break;
        }
    }
    // PSCI CPU_ON is asynchronous: wait only for requests that firmware accepted.
    // A platform may describe several CPUs in MADT while intentionally rejecting
    // CPU_ON; in that case there is nothing to wait for.
    let expected = (1 + requested).min(MAX_CPUS);
    if requested != 0 {
        for _ in 0..20_000_000usize {
            if online_count() >= expected {
                break;
            }
            core::hint::spin_loop();
        }
    }
    let actual_multi = online_count() > 1;
    MULTI_CORE.store(actual_multi, Ordering::SeqCst);
    if actual_multi {
        let _ = super::gic::affinity_self_test(1);
    }
    crate::info!(
        "smp: boot_secondaries done, requested={} online={} multi_core={}",
        requested,
        online_count(),
        multi_core_active()
    );
}

/// 副核 Rust 入口（entry 汇编设好栈/TPIDR 后调用，noreturn）。
pub extern "C" fn smp_secondary_main(cpu: usize) -> ! {
    // PSCI starts a fresh PE: VBAR/CPACR/MAIR are per-CPU state, not inherited
    // from the boot PE. Install them before the first possible local IRQ.
    unsafe { super::init_secondary_local_state() };
    // 本核 CPU 接口（GICC 为 banked 寄存器，GICD 由主核一次性配好）。
    unsafe { crate::arch::gic_init_cpu_interface() };
    // 本核定时器：TICKS_PER_SLICE 全局量主核已算好，直接 arm 第一个 tick。
    unsafe { crate::arch::program_next_tick() };
    mark_online(cpu);
    crate::info!("smp: cpu{} online, entering scheduler loop", cpu);
    crate::scheduler::secondary_run()
}

fn mark_online(cpu: usize) {
    let prev = ONLINE.fetch_add(1, Ordering::AcqRel);
    let _ = (cpu, prev);
}

fn legacy_mpidr_candidates(cpu: usize) -> [u64; 4] {
    let id = cpu as u64;
    // PSCI target_cpu contains MPIDR affinity fields only. MPIDR_EL1 bit31 is
    // RES1 when read architecturally but is *not* part of MPIDR_HWID_BITMASK;
    // passing it makes strict firmware reject CPU_ON as INVALID_PARAMS. Cover
    // all four affinity levels for the no-ACPI fallback, including Aff3[39:32].
    [id, id << 8, id << 16, id << 32]
}

// ── PSCI 0.2 CPU_ON ─────────────────────────────────────────────────

/// PSCI 0.2 CPU_ON function IDs. On AArch64 the native call is SMC64/HVC64;
/// some firmware (including QEMU) also accepts the 32-bit variant, so retain it
/// only as a compatibility fallback after an explicit NOT_SUPPORTED response.
const PSCI_FN64_CPU_ON: u64 = 0xC400_0003;
const PSCI_FN32_CPU_ON: u64 = 0x8400_0003;
const PSCI_SUCCESS: i64 = 0;
const PSCI_NOT_SUPPORTED: i64 = -1;
const PSCI_INVALID_PARAMS: i64 = -2;
const PSCI_DENIED: i64 = -3;
const PSCI_ALREADY_ON: i64 = -4;
const PSCI_ON_PENDING: i64 = -5;
const PSCI_INTERNAL_FAILURE: i64 = -6;
const PSCI_NOT_PRESENT: i64 = -7;
const PSCI_DISABLED: i64 = -8;
const PSCI_INVALID_ADDRESS: i64 = -9;

fn psci_status_name(raw: i64) -> &'static str {
    match raw {
        PSCI_SUCCESS => "SUCCESS",
        PSCI_NOT_SUPPORTED => "NOT_SUPPORTED",
        PSCI_INVALID_PARAMS => "INVALID_PARAMS",
        PSCI_DENIED => "DENIED",
        PSCI_ALREADY_ON => "ALREADY_ON",
        PSCI_ON_PENDING => "ON_PENDING",
        PSCI_INTERNAL_FAILURE => "INTERNAL_FAILURE",
        PSCI_NOT_PRESENT => "NOT_PRESENT",
        PSCI_DISABLED => "DISABLED",
        PSCI_INVALID_ADDRESS => "INVALID_ADDRESS",
        _ => "UNKNOWN",
    }
}

struct PsciResult {
    ok: bool,
    raw: i64,
}

#[inline]
fn psci_cpu_on_call(fid: u64, target_mpidr: u64, entry: usize, logical_cpu: usize) -> i64 {
    let ret: i64;
    // FADT ARM boot flags are the authority for the conduit. Only the function
    // width is negotiated here; never silently switch HVC <-> SMC.
    match crate::acpi::psci_conduit() {
        crate::acpi::PsciConduit::Smc => unsafe {
            core::arch::asm!(
                "smc #0",
                in("x0") fid,
                in("x1") target_mpidr,
                in("x2") entry,
                in("x3") logical_cpu,
                lateout("x0") ret,
                options(nostack)
            );
        },
        crate::acpi::PsciConduit::Hvc | crate::acpi::PsciConduit::LegacyHvc => unsafe {
            core::arch::asm!(
                "hvc #0",
                in("x0") fid,
                in("x1") target_mpidr,
                in("x2") entry,
                in("x3") logical_cpu,
                lateout("x0") ret,
                options(nostack)
            );
        },
    }
    // PSCI status codes are architecturally signed 32-bit values even for
    // SMC64/HVC64 calls. Some hypervisors (Parallels/AppleHV) return them in
    // W0 without sign-extending X0, e.g. 0x00000000fffffffe for -2.
    // Normalize through i32 so comparisons and fallback logic are portable.
    (ret as u32 as i32) as i64
}

/// entry 以 EL1h/屏蔽中断进入（PSCI 规范保证）。
fn psci_cpu_on(target_mpidr: u64, entry: usize, logical_cpu: usize) -> PsciResult {
    let mut ret = psci_cpu_on_call(PSCI_FN64_CPU_ON, target_mpidr, entry, logical_cpu);
    if ret == PSCI_NOT_SUPPORTED {
        ret = psci_cpu_on_call(PSCI_FN32_CPU_ON, target_mpidr, entry, logical_cpu);
    }
    PsciResult {
        ok: ret == PSCI_SUCCESS,
        raw: ret,
    }
}

// ── 副核入口所需的数据（汇编按符号直达）────────────────────────────

/// 每副核内核栈：4 个槽位（cpu0 弃用不用，索引直乘）。64KiB 与主核
/// 进程栈同规格；入口汇编以 idx*SIZE 寻址。
pub const SECONDARY_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
pub struct SecondaryStacks(pub [[u8; SECONDARY_STACK_SIZE]; MAX_CPUS]);

#[no_mangle]
pub static SMP_SECONDARY_STACKS: SecondaryStacks =
    SecondaryStacks([[0; SECONDARY_STACK_SIZE]; MAX_CPUS]);

/// Dedicated per-CPU scheduler-idle stack.  Secondary bring-up already owns
/// one 64KiB stack per logical CPU; once a PE enters the scheduler that stack
/// is no longer a process stack, so it becomes the permanent idle/exception
/// continuation stack for that PE (CPU0's slot was previously unused).
///
/// This separation is mandatory on SMP: an idle PE must never keep sleeping on
/// the kernel stack of the last process it ran, because that process may migrate
/// and use the same KERNEL_STACKS[slot] concurrently on another PE.
pub fn idle_stack_top(cpu: usize) -> usize {
    let idx = cpu.min(MAX_CPUS - 1);
    let base = core::ptr::addr_of!(SMP_SECONDARY_STACKS.0[idx]) as *const u8 as usize;
    base + SECONDARY_STACK_SIZE
}

/// 副核入口符号（定义于 arch/aarch64.rs 的 global_asm）：
/// 汇编读 MPIDR 得 idx → 从 SMP_SECONDARY_STACKS 取本核栈 →
/// TPIDR_EL1 ← SMP_IDLE_FRAMES[idx] → bl __smp_secondary_rust。
pub const IDLE_FRAME_STRIDE: usize = 832; // == size_of::<TrapFrame>()（有静态断言）

#[cfg(test)]
mod idle_stack_tests {
    use super::*;

    #[test]
    #[test]
    fn legacy_mpidr_candidates_cover_all_affinity_levels() {
        assert_eq!(
            legacy_mpidr_candidates(1),
            [1, 0x100, 0x1_0000, 0x1_0000_0000]
        );
        for mpidr in legacy_mpidr_candidates(3) {
            assert_eq!(
                mpidr & 0x8000_0000,
                0,
                "RES1 bit is not part of PSCI target HWID"
            );
        }
    }

    fn psci_aarch64_cpu_on_ids_and_status_match_spec() {
        assert_eq!(PSCI_FN64_CPU_ON, 0xC400_0003);
        assert_eq!(PSCI_FN32_CPU_ON, 0x8400_0003);
        assert_eq!(PSCI_NOT_SUPPORTED, -1);
        assert_eq!((0x0000_0000_ffff_fffeu64 as u32 as i32) as i64, -2);
        assert_eq!(psci_status_name(-2), "INVALID_PARAMS");
        assert_eq!(psci_status_name(-4), "ALREADY_ON");
    }

    #[test]
    fn idle_stack_geometry_is_per_cpu() {
        for cpu in 0..MAX_CPUS {
            assert_eq!(idle_stack_top(cpu) & 0xf, 0);
            if cpu != 0 {
                assert_eq!(
                    idle_stack_top(cpu) - idle_stack_top(cpu - 1),
                    SECONDARY_STACK_SIZE
                );
            }
        }
    }
}
