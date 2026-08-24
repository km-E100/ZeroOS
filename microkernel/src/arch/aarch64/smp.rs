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

/// 当前核序号（MPIDR aff0）。⚠ 宿主单测在 EL0 执行，读 MPIDR 会
/// SIGILL——测试桩恒回 0（单测只验证纯逻辑，不依赖真核号）。
#[inline(always)]
pub fn cpu_id() -> usize {
    #[cfg(test)]
    {
        0
    }
    #[cfg(not(test))]
    {
        let mpidr: u64;
        unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr) };
        // QEMU virt：Aff0[7:0] 即核序号（每 cluster 单核）。
        (mpidr & 0xff) as usize
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
    if n >= 32 { u32::MAX } else { (1u32 << n) - 1 }
}

/// 主核侧：翻多核闸 → 探测点亮副核。幂等（仅 kernel_main 调用一次）。
///
/// 顺序纪律：必须先翻 MULTI_CORE + 切 FPEN=0b11 + 冻结 FPU_DIRTY，
/// 再发 CPU_ON——副核一上线就可能与主核并发跑调度/陷阱，FP 语义
/// 必须先行切换到"帧相对急切"这一跨核安全的形态。
pub fn boot_secondaries() {
    MULTI_CORE.store(true, Ordering::SeqCst);
    // FP 门位全开（EL0 不再因 FP 陷阱进内核）；FPU_DIRTY 冻结 NONE，
    // 入口存根的门控比较从此恒走"急切保存"分支。
    crate::arch::fpu_arm_full_access();
    crate::arch::fpu_freeze_none();
    // GICD 已由主核初始化；SGI0（RESCHED）在 GICv2 恒使能，无需配置。

    // 目标 MPIDR 蛮力扫描：aff0/aff1/aff2 三维度 × bit31 有无。
    // 命中即停；全部落空则如实记录放弃多核（单核语义不受影响）。
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
            let result = psci_cpu_on(mpidr, unsafe { &__secondary_entry } as *const u8 as usize);
            if result.ok {
                crate::info!("smp: cpu{} UP via mpidr={:#010x}", cpu, mpidr);
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
fn psci_cpu_on(target_mpidr: u64, entry: usize) -> PsciResult {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            in("x0") PSCI_FN_CPU_ON,
            in("x1") target_mpidr,
            in("x2") entry,
            in("x3") 0usize, // context：不用，入口自行取 MPIDR
            lateout("x0") ret,
            options(nostack)
        );
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
