//! SMP 多核支持（结构性天花板立项 · 阶段 0-2）。
//!
//! ## 启动协议
//! 主核（MPIDR aff0=0）走 UEFI→kernel_main 原路；`boot_secondaries`
//! 在用户态拉起前以 PSCI `CPU_ON`(0x8400_0003) 探测 1..MAX_CPUS——
//! 不存在的核同步返回 NOT_SUPPORTED，天然充当核数发现。副核入口
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
/// 顺序纪律：必须先翻 MULTI_CORE + 切 FPEN=0b11 + 冻结 FPU_DIRTY，
/// 再发 CPU_ON——副核一上线就可能与主核并发跑调度/陷阱，FP 语义
/// 必须先行切换到"帧相对急切"这一跨核安全的形态。
pub fn boot_secondaries() {
    unsafe { core::arch::asm!("msr tpidrro_el0, {}", in(reg) 0u64) };
    MULTI_CORE.store(true, Ordering::SeqCst);
    // FP 门位全开（EL0 不再因 FP 陷阱进内核）；FPU_DIRTY 冻结 NONE，
    // 入口存根的门控比较从此恒走"急切保存"分支。
    crate::arch::fpu_arm_full_access();
    crate::arch::fpu_freeze_none();
    // GICD 已由主核初始化；SGI0（RESCHED）在 GICv2 恒使能，无需配置。

    // 优先按 ACPI MADT 枚举；无 ACPI 时保留 legacy 探测。
    let madt = crate::acpi::cpu_mpidrs();
    if madt.len() > 1 {
        // MADT does not promise that the boot CPU is entry 0. Compare only
        // architectural affinity fields (Aff3..Aff0), ignoring MPIDR flags.
        const AFFINITY_MASK: u64 = 0x0000_00ff_00ff_ffff;
        let boot_mpidr: u64;
        unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) boot_mpidr) };
        let boot_affinity = boot_mpidr & AFFINITY_MASK;
        let mut logical = 1usize;
        for mpidr in madt.into_iter() {
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
                crate::info!("smp: cpu{} UP via MADT mpidr={:#x}", logical, mpidr);
                logical += 1;
            } else {
                crate::warn!("smp: MADT CPU_ON mpidr={:#x} failed={}", mpidr, result.raw);
            }
        }
    } else {
        'outer: for cpu in 1..MAX_CPUS {
            for (shift, use_res1) in [
                (0u32, true),
                (0, false),
                (8, true),
                (8, false),
                (16, true),
                (16, false),
            ] {
                let mut mpidr = (cpu as u64) << shift;
                if use_res1 {
                    mpidr |= 0x8000_0000;
                }
                let result = psci_cpu_on(
                    mpidr,
                    unsafe { &__secondary_entry } as *const u8 as usize,
                    cpu,
                );
                if result.ok {
                    crate::info!("smp: cpu{} UP via legacy mpidr={:#010x}", cpu, mpidr);
                    continue 'outer;
                }
                crate::debug!(
                    "smp-probe: CPU_ON mpidr={:#010x} -> {:#010x}",
                    mpidr,
                    result.raw as i32 as u32
                );
            }
            crate::info!("smp: cpu{} exhausted, online={}", cpu, online_count());
            break;
        }
    }
    crate::info!(
        "smp: boot_secondaries done, online={} multi_core={}",
        online_count(),
        multi_core_active()
    );
}

/// 副核 Rust 入口（entry 汇编设好栈/TPIDR 后调用，noreturn）。
pub extern "C" fn smp_secondary_main(cpu: usize) -> ! {
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

// ── PSCI 0.2 CPU_ON ─────────────────────────────────────────────────

const PSCI_FN_CPU_ON: u64 = 0x8400_0003;
const PSCI_SUCCESS: i64 = 0;
const PSCI_NOT_SUPPORTED: i64 = -4;

struct PsciResult {
    ok: bool,
    raw: i64,
}

/// entry 以 EL1h/屏蔽中断进入（PSCI 规范保证）。
fn psci_cpu_on(target_mpidr: u64, entry: usize, logical_cpu: usize) -> PsciResult {
    let ret: i64;
    // FADT ARM boot flags 是固件对 PSCI conduit 的权威描述。缺表时保留
    // Zero OS/QEMU 历史 HVC 路径；PSCI compliant + !USE_HVC 则使用 SMC。
    match crate::acpi::psci_conduit() {
        crate::acpi::PsciConduit::Smc => unsafe {
            core::arch::asm!(
                "smc #0",
                in("x0") PSCI_FN_CPU_ON,
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
                in("x0") PSCI_FN_CPU_ON,
                in("x1") target_mpidr,
                in("x2") entry,
                in("x3") logical_cpu,
                lateout("x0") ret,
                options(nostack)
            );
        },
    }
    PsciResult {
        ok: ret == PSCI_SUCCESS,
        raw: ret,
    }
}

#[allow(dead_code)]
const _: () = {
    let _ = PSCI_NOT_SUPPORTED; // 文档引用：-4 = NOT_SUPPORTED
};

// ── 副核入口所需的数据（汇编按符号直达）────────────────────────────

/// 每副核内核栈：4 个槽位（cpu0 弃用不用，索引直乘）。64KiB 与主核
/// 进程栈同规格；入口汇编以 idx*SIZE 寻址。
pub const SECONDARY_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
pub struct SecondaryStacks(pub [[u8; SECONDARY_STACK_SIZE]; MAX_CPUS]);

#[no_mangle]
pub static SMP_SECONDARY_STACKS: SecondaryStacks =
    SecondaryStacks([[0; SECONDARY_STACK_SIZE]; MAX_CPUS]);

/// 副核入口符号（定义于 arch/aarch64.rs 的 global_asm）：
/// 汇编读 MPIDR 得 idx → 从 SMP_SECONDARY_STACKS 取本核栈 →
/// TPIDR_EL1 ← SMP_IDLE_FRAMES[idx] → bl __smp_secondary_rust。
pub const IDLE_FRAME_STRIDE: usize = 832; // == size_of::<TrapFrame>()（有静态断言）
