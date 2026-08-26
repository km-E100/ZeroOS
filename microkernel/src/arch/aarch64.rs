use core::arch::asm;
#[cfg(target_os = "none")]
use core::arch::global_asm;

pub mod smp;
use core::hint::spin_loop;
use zero_abi::BootInfo;

use crate::mm::address_space::AddressSpace;
use crate::process::Context;

mod gic;
mod timer;

// eret 进 EL0t 的 SPSR：M[3:0]=0b0000（EL0t），DAIF 全清 → EL0 可被 timer 抢占。
// 内核侧全程保持 IRQ 屏蔽（异常入口硬件自动置 I=1），只有 eret 回 EL0 时
// 通过 SPSR 恢复 I=0 —— 单核自旋锁场景下这是唯一不会重入死锁的中断策略。
// 该值由 restore_context 从帧内 #264 恢复；帧初始化时写 0（见 process::init_user）。

#[cfg(target_os = "none")]
global_asm!(
    ".section .vectors,\"ax\"\n\
     .align 11\n\
     .global __vector_table\n\
__vector_table:\n\
     .macro vector_entry handler\n\
         b \\handler\n\
         .space 124\n\
     .endm\n\
     vector_entry __vector_sync_el1t\n\
     vector_entry __vector_irq_el1t\n\
     vector_entry __vector_fiq_el1t\n\
     vector_entry __vector_serror_el1t\n\
     vector_entry __vector_sync_el1h\n\
     vector_entry __vector_irq_el1h\n\
     vector_entry __vector_fiq_el1h\n\
     vector_entry __vector_serror_el1h\n\
     vector_entry __vector_sync_el0_64\n\
     vector_entry __vector_irq_el0_64\n\
     vector_entry __vector_fiq_el0_64\n\
     vector_entry __vector_serror_el0_64\n\
     vector_entry __vector_sync_el0_32\n\
     vector_entry __vector_irq_el0_32\n\
     vector_entry __vector_fiq_el0_32\n\
     vector_entry __vector_serror_el0_32\n\
\n\
     // ─── 异常入口统一存根：唯一合法的现场保存点 ─────────────────────\n\
     // 契约（2026-08-22 重构）：\n\
     // * 本宏生成的代码是进程寄存器状态的**唯一**写入者；任何 Rust 路径\n\
     //   （syscall 处理 / yield / exit / dispatch）都只读写 TRAP_FRAMES，\n\
     //   绝不重复保存（双保存曾用内核脏寄存器污染用户现场）。\n\
     // * TPIDR_EL1 由 restore_context/enter_user_mode 在每次 eret 前指向\n\
     //   当前进程的 TrapFrame —— 存根因此无需触碰任何锁或 Rust 代码即可\n\
     //   定位保存目标。内核全程屏蔽 IRQ ⇒ 所有异常都来自 EL0 或内核自身\n\
     //   bug，TPIDR_EL1 恒有效。\n\
     // * x16/x17 必须完整保存。AAPCS64 的 caller-clobbered 规则只约束函数调用，\n\
     //   IRQ/Data Abort 等异步异常必须透明保全它们。入口先在 EL1 栈暂存\n\
     //   x16/x17，再用 x16 定位 TrapFrame，随后落回各自帧槽并恢复 SP。\n\
     // * SP_EL1 在异常进入时由硬件自动切换，其当前值恒为该槽内核栈顶\n\
     //   （每次 eret 前都从帧内 #272 重置），故直接存入 #272 并复位 SP，\n\
     //   保证嵌套/重入时栈指针幂等归位。\n\
     // * 【第八刀：执行域扩展】TPIDR_EL0（用户 TLS）与 v0-v31/FPSR/FPCR\n\
     //   全量急切保存（帧内 #280 / #288..#804）。前提：arch::init 已置\n\
     //   CPACR_EL1.FPEN=0b11 —— 否则本存根的 stp q*/mrs fpsr 自身就会\n\
     //   同步异常。内核态浮点约定与 lazy-save 优化路径见 process::FpuState。\n\
     .macro SAVE_TRAP_AND_CALL kind\n\
         sub sp, sp, #16\n\
         stp x16, x17, [sp]\n\
         mrs x16, tpidr_el1\n\
         stp x0, x1, [x16, #0]\n\
         stp x2, x3, [x16, #16]\n\
         stp x4, x5, [x16, #32]\n\
         stp x6, x7, [x16, #48]\n\
         stp x8, x9, [x16, #64]\n\
         stp x10, x11, [x16, #80]\n\
         stp x12, x13, [x16, #96]\n\
         stp x14, x15, [x16, #112]\n\
         ldr x17, [sp, #0]\n\
         str x17, [x16, #128]\n\
         ldr x17, [sp, #8]\n\
         str x17, [x16, #136]\n\
         add sp, sp, #16\n\
         stp x18, x19, [x16, #144]\n\
         stp x20, x21, [x16, #160]\n\
         stp x22, x23, [x16, #176]\n\
         stp x24, x25, [x16, #192]\n\
         stp x26, x27, [x16, #208]\n\
         stp x28, x29, [x16, #224]\n\
         str x30, [x16, #240]\n\
         mrs x17, sp_el0\n\
         str x17, [x16, #248]\n\
         mrs x17, elr_el1\n\
         str x17, [x16, #256]\n\
         mrs x17, spsr_el1\n\
         str x17, [x16, #264]\n\
         mov x17, sp\n\
         str x17, [x16, #272]\n\
         mov sp, x17\n\
         // 用户 TLS（TPIDR_EL0）：x17 此刻已空闲（SPSR 已落帧），经其中转；\n\
         // EL1 访问 TPIDR_EL0 无条件允许。\n\
         mrs x17, tpidr_el0\n\
         str x17, [x16, #280]\n\
         // FPU/NEON 惰性保存门控（第十一刀）：仅当活寄存器归属本帧用户\n\
         // （FPU_DIRTY == frame.owner_slot）才急切保存——同进程 syscall\n\
         // 往返的现场保全；否则跳过（非 FP 用户零开销；他人现场由断链\n\
         // 路径 fpu_trap_replay 落账）。FPEN=0b01 下 EL1 的 stp/mrs 不陷阱。\n\
         // ⚠ 二分排查 C：完整门控复现（读+比较+b.ne 跳过保存）。
         adrp x17, FPU_DIRTY\n\
         add x17, x17, :lo12:FPU_DIRTY\n\
         ldr x15, [x16, #816]\n\
         ldr x17, [x17]\n\
         cmp x15, x17\n\
         b.ne 90\\@f\n\
         // FPU/NEON 全量急切保存：#288..#799 = v0-v31，#800/#804 = FPSR/\n\
         // FPCR。v 寄存器独立于 x16/x17 暂存方案，零冲突；内核不使用 FP\n\
         // => 存根此刻的 v 寄存器仍是用户现场原值（约定见 process::FpuState）。\n\
         // STP Qt 立即数须 16 对齐且 <=1008 —— 帧基址由 TrapFrameCell\n\
         // align(16) 保证对齐。FPSR/FPCR 是 32 位寄存器：用 str w 编码\n\
         // （imm12 按 4 缩放）；64 位 STR 立即数须 8 对齐，#804 编码不下。\n\
         stp q0, q1, [x16, #288]\n\
         stp q2, q3, [x16, #320]\n\
         stp q4, q5, [x16, #352]\n\
         stp q6, q7, [x16, #384]\n\
         stp q8, q9, [x16, #416]\n\
         stp q10, q11, [x16, #448]\n\
         stp q12, q13, [x16, #480]\n\
         stp q14, q15, [x16, #512]\n\
         stp q16, q17, [x16, #544]\n\
         stp q18, q19, [x16, #576]\n\
         stp q20, q21, [x16, #608]\n\
         stp q22, q23, [x16, #640]\n\
         stp q24, q25, [x16, #672]\n\
         stp q26, q27, [x16, #704]\n\
         stp q28, q29, [x16, #736]\n\
         stp q30, q31, [x16, #768]\n\
         mrs x17, fpsr\n\
         str w17, [x16, #800]\n\
         mrs x17, fpcr\n\
         str w17, [x16, #804]\n\
         90\\@:\n\
         mov x0, x16\n\
         mov x1, #\\kind\n\
         bl __zero_trap_handler\n\
     .endm\n\
\n\
     .global __vector_sync_el1t\n\
__vector_sync_el1t:\n\
     SAVE_TRAP_AND_CALL 0\n\
     .global __vector_irq_el1t\n\
__vector_irq_el1t:\n\
     SAVE_TRAP_AND_CALL 1\n\
     .global __vector_sync_el1h\n\
__vector_sync_el1h:\n\
     SAVE_TRAP_AND_CALL 0\n\
     .global __vector_irq_el1h\n\
__vector_irq_el1h:\n\
     SAVE_TRAP_AND_CALL 1\n\
     .global __vector_sync_el0_64\n\
__vector_sync_el0_64:\n\
     SAVE_TRAP_AND_CALL 0\n\
     .global __vector_irq_el0_64\n\
__vector_irq_el0_64:\n\
     SAVE_TRAP_AND_CALL 1\n\
\n\
     // ─── SMP 副核入口（第十四刀立项 · 阶段 1）─────────────────────\n\
     // PSCI CPU_ON 以 EL1h/IRQ 屏蔽跳入；x0=context_id（逻辑 CPU 号）。\n\
     // 栈：SMP_SECONDARY_STACKS[idx]；TPIDRRO_EL0 保存逻辑 CPU 号；\n\
     // TPIDR_EL1 ← SMP_IDLE_FRAMES[idx]。\n\
     // （异常保存目标即刻有效）。随后进 Rust 初始化 GICC/定时器。\n\
     .section .text.smp_entry,\"ax\"\n\
     .global __secondary_entry\n\
__secondary_entry:\n\
     msr daifset, #0xf\n\
     msr tpidrro_el0, x0\n\
     adrp x1, SMP_SECONDARY_STACKS\n\
     add x1, x1, :lo12:SMP_SECONDARY_STACKS\n\
     mov x2, #65536\n\
     mul x2, x0, x2\n\
     add x1, x1, x2\n\
     mov x3, #65536\n\
     add sp, x1, x3\n\
     adrp x1, SMP_IDLE_FRAMES\n\
     add x1, x1, :lo12:SMP_IDLE_FRAMES\n\
     mov x2, #832\n\
     mul x2, x0, x2\n\
     add x1, x1, x2\n\
     msr tpidr_el1, x1\n\
     bl __smp_secondary_rust\n"
);

#[cfg(target_os = "none")]
extern "C" {
    static __vector_table: u8;
    fn __zero_trap_handler(frame: *mut Context, kind: u64) -> !;
    static __secondary_entry: u8;
}

// macOS/AArch64 host tests compile this module because target_arch is also
// aarch64, but they must never assemble/link the EL1 vector table or PSCI
// secondary trampoline. Dummy symbols keep pure algorithm tests linkable.
#[cfg(not(target_os = "none"))]
#[no_mangle]
static __vector_table: u8 = 0;
#[cfg(not(target_os = "none"))]
#[no_mangle]
static __secondary_entry: u8 = 0;

pub fn init(_boot_info: &BootInfo) {
    unsafe {
        // 记录固件留下的 TCR/TTBR 配置，便于调试页表起始级别和地址空间布局。
        let tcr: u64;
        let ttbr0: u64;
        let ttbr1: u64;
        asm!("mrs {0}, tcr_el1", out(reg) tcr);
        asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0);
        asm!("mrs {0}, ttbr1_el1", out(reg) ttbr1);
        crate::info!(
            "arch/aarch64: TCR_EL1=0x{:016x} TTBR0_EL1=0x{:016x} TTBR1_EL1=0x{:016x}",
            tcr,
            ttbr0,
            ttbr1
        );

        // ── FPU/NEON 使能（第八刀引入；第十一刀升级为惰性保存）──────
        // CPACR_EL1.FPEN[21:20] = 0b01：EL0 的 FP/SIMD 访问陷阱
        // （EC=0x07 → fpu_trap_replay 断链装载后重放），EL1 内核访问
        // 不陷阱——入口存根/断链路径的 stp q*/ldp q* 因此可自由执行。
        // 必须先于 VBAR 安装执行。
        //
        // 惰性协议（对照 Linux switch_to_fpu）：
        // * FPU_DIRTY = 活寄存器当前归属的用户槽位（u64::MAX = 无主）；
        // * 异常入口：FPU_DIRTY == frame.owner_slot 才急切保存（同进程
        //   syscall 往返的现场保全），否则跳过——非 FP 用户零开销；
        // * eret 前（restore_context）：**从不**主动装载 frame.fpu，仅
        //   保持 FPEN=0b01，用户首条 FP/SIMD 指令经陷阱断链装载；
        // * 断链（fpu_trap_replay）：旧属主现场落回其帧 → 装载本人帧 →
        //   记 FPU_DIRTY → eret 重放；活寄存器本属本人则直接重放。
        // * execve/init_user 等重置帧内 fpu 区的路径必须同时 fpu_disown，
        //   防止「帧已新、寄存器还旧」被 dirty==owner 误判为新鲜。
        let mut cpacr: u64;
        asm!("mrs {}, cpacr_el1", out(reg) cpacr);
        cpacr = (cpacr & !(0b11u64 << 20)) | (0b01u64 << 20);
        asm!("msr cpacr_el1, {}", in(reg) cpacr);
        crate::info!("arch/aarch64: CPACR_EL1.FPEN=0b01 (EL0 FP lazy-trap enabled)");

        asm!("msr SPSel, #1", options(nostack, preserves_flags));
        set_vector_base(&__vector_table as *const _ as usize);
        crate::info!("arch/aarch64: vectors set");

        // MAIR AttrIdx 1 配置为 Device-nGnRE（0b0000_0100）：恒等映射的
        // MMIO 块引用该属性，寄存器访问不被缓存合并（对照 Linux ioremap）。
        // 保留其余属性槽（固件 Normal 定义在 AttrIdx 0，继续生效）。
        let mut mair: u64;
        asm!("mrs {}, mair_el1", out(reg) mair);
        mair &= !(0xFFu64 << 8);
        mair |= 0x04u64 << 8;
        asm!("msr mair_el1, {}", in(reg) mair);
        asm!("tlbi vmalle1", options(nostack));

        // GIC/timer 延后到 MM + ACPI 完成之后；否则 ACPI 永远只能“解析但不消费”。
        // Do not enable interrupts yet; defer until scheduler has installed a current slot.
    }
    crate::info!("arch/aarch64: vector table installed (platform IRQ init deferred)");
}

/// 第二阶段平台初始化：必须在 `acpi::init()` 之后调用。
pub fn init_platform() {
    unsafe {
        gic::init();
        crate::info!("arch/aarch64: gic platform init done");
        timer::init(10);
        crate::info!(
            "arch/aarch64: timer init done (irq={})",
            gic::timer_irq_id()
        );
    }
}

/// 仅恢复目标现场并 eret（**绝不保存当前寄存器**）。
///
/// ⚠ 所有权契约（2026-08-22 重构，修复「双保存」实机损坏）：
/// 陷阱帧的唯一合法写入者是 `trap_entry`——异常发生的第一瞬间把真实
/// 寄存器存入 TRAP_FRAMES[slot]，此后内核任何代码路径（yield / exit /
/// dispatch / 阻塞返回）都不得再次覆盖该帧。此前 context_switch 在
/// 调度路径上重复执行 save_trap_frame，用内核脏寄存器（x30=处理链返回
/// 地址、x0-x17 已被 Rust 代码改写、sp_el1=半栈深处）污染了被打断进程
/// 的用户现场：进程恢复后带着内核地址的 LR 与垃圾易变寄存器继续跑，
/// 最终以 EL0 访问内核地址的 permission fault 告终（QEMU -d int 实测）。
#[inline(always)]
pub unsafe fn switch_to(next: *mut Context) -> ! {
    restore_context(next)
}

/// SMP 副核 Rust 入口（汇编跳板 bl 到此，noreturn）。
#[no_mangle]
extern "C" fn __smp_secondary_rust(cpu: usize) -> ! {
    super::aarch64::smp::smp_secondary_main(cpu)
}

/// 冻结 FPU_DIRTY=NONE（SMP 翻闸时调用）：入口存根门控从此恒走急切保存。
pub fn fpu_freeze_none() {
    FPU_DIRTY.store(FPU_OWNER_NONE, Relaxed);
}

// ═══ 第十一刀：FPU/NEON 惰性保存 ═══════════════════════════════════
//
// 协议总纲见 arch::init 的 FPEN 注释。本模块职责：
// * FPU_DIRTY——活寄存器属主记账（入口存根与 restore_context 以
//   adrp 直达该符号做门控判定，故必须 #[no_mangle] 平铺 u64）；
// * fpu_trap_replay——EC=0x07 断链：偷取链落账 + 本人装载 + 重放；
// * fpu_disown——帧内 fpu 区被重置（execve/init_user）时切断
//   「寄存器=帧」的等式，防止陈旧寄存器被误认为新鲜现场。

/// 活 FP 寄存器当前归属的槽位号；`FPU_OWNER_NONE` 表示无主/内核。
#[no_mangle]
pub static FPU_DIRTY: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(FPU_OWNER_NONE);
pub const FPU_OWNER_NONE: u64 = u64::MAX;

use core::sync::atomic::Ordering::Relaxed;

/// 帧内 fpu 区被整体重置前调用（execve 换映像）：若活寄存器尚押着
/// 本进程现场则先落回帧内（随后被调用方覆写为干净初值），并切断
/// 「活寄存器=帧」归属等式。⚠ 只允许对当前进程自己的帧调用——
/// 全局 dirty 记账描述的是活寄存器，动他人帧不得碰它。
pub fn fpu_discard_live(frame: *mut Context) {
    if let Some(slot) = crate::scheduler::current_slot_opt() {
        unsafe {
            if FPU_DIRTY.load(Relaxed) == slot as u64 && (*frame).owner_slot == slot as u64 {
                // 先落账再作废：保证「dirty==owner ⇒ 帧=寄存器快照」
                // 不变式在任何观察点成立。
                asm_save_fpu_into(frame as *const u8);
            }
        }
    }
    FPU_DIRTY.store(FPU_OWNER_NONE, Relaxed);
}

/// EC=0x07（EL0 首用 FP/SIMD 或被偷取后的再次首用）断链入口：
/// 装载本人帧内现场到活寄存器并 eret 重放同一条指令。noreturn。
///
/// # 安全契约
/// * frame 必须是当前进程的陷阱帧（owner_slot 已由 restore_context 武装）；
/// * 仅允许 EL0 发起（trap.rs 已校验 SPSR.M）；
/// * FPEN=0b01 保证 EL1 侧 stp q*/mrs fpsr 自由执行、EL0 触发陷阱。
pub unsafe fn fpu_trap_replay(frame: *mut Context) -> ! {
    let slot = crate::scheduler::current_slot_opt().expect("fpu trap outside any process context");
    let owner = (*frame).owner_slot;
    debug_assert_eq!(owner, slot as u64, "fpu trap on un-armed frame");
    if FPU_DIRTY.load(Relaxed) != slot as u64 {
        // 偷取链收尾：若活寄存器还押着旧属主的现场，先替它落回其帧，
        // 再装载本人现场（对照 Linux fpsimd_thread_switch 的 save 链）。
        let dirty = FPU_DIRTY.load(Relaxed);
        if dirty != FPU_OWNER_NONE && (dirty as usize) < crate::process::MAX_PROCESSES {
            let old = crate::process::trap_frame(dirty as usize);
            asm_save_fpu_into(old as *const u8);
        }
        asm_load_fpu_from(frame as *const u8);
        FPU_DIRTY.store(slot as u64, Relaxed);
    } else {
        // 活寄存器本就是本人现场（dirty==owner）：无需搬运。
    }
    fpu_arm_full_access();
    // 活寄存器已确保为本人现场且 EL0 FP 已放行，eret 重放同一条指令。
    crate::arch::restore_frame(frame)
}

/// FPEN ← 0b11（EL0/EL1 全放行）：断链装载完成后调用——否则重放的
/// 用户 FP 指令在 0b01 门下永远再陷阱（实机：launchd 静默卡死）。
pub fn fpu_arm_full_access() {
    unsafe {
        let mut cpacr: u64;
        asm!("mrs {}, cpacr_el1", out(reg) cpacr);
        cpacr = (cpacr & !(0b11u64 << 20)) | (0b11u64 << 20);
        asm!("msr cpacr_el1, {}", in(reg) cpacr);
    }
}

/// FPEN ← 0b01（EL1 自由、EL0 陷阱）：eret 进用户态前的门位。
pub fn fpu_set_lazy_gate() {
    unsafe {
        let mut cpacr: u64;
        asm!("mrs {}, cpacr_el1", out(reg) cpacr);
        cpacr = (cpacr & !(0b11u64 << 20)) | (0b01u64 << 20);
        asm!("msr cpacr_el1, {}", in(reg) cpacr);
    }
}

/// 把活寄存器 v0-v31/FPSR/FPCR 写入 `base` 帧的 fpu 区（#288 偏移）。
/// 仅在断链路径调用：FPEN=0b01 下 EL1 执行不受限。
unsafe fn asm_save_fpu_into(base: *const u8) {
    asm!(
        "stp q0, q1, [{0}, #288]",
        "stp q2, q3, [{0}, #320]",
        "stp q4, q5, [{0}, #352]",
        "stp q6, q7, [{0}, #384]",
        "stp q8, q9, [{0}, #416]",
        "stp q10, q11, [{0}, #448]",
        "stp q12, q13, [{0}, #480]",
        "stp q14, q15, [{0}, #512]",
        "stp q16, q17, [{0}, #544]",
        "stp q18, q19, [{0}, #576]",
        "stp q20, q21, [{0}, #608]",
        "stp q22, q23, [{0}, #640]",
        "stp q24, q25, [{0}, #672]",
        "stp q26, q27, [{0}, #704]",
        "stp q28, q29, [{0}, #736]",
        "stp q30, q31, [{0}, #768]",
        "mrs {1}, fpsr",
        "str {1:w}, [{0}, #800]",
        "mrs {1}, fpcr",
        "str {1:w}, [{0}, #804]",
        in(reg) base,
        out(reg) _,
        options(nostack)
    );
}

/// 从 `base` 帧的 fpu 区（#288 偏移）装载 v0-v31/FPSR/FPCR 到活寄存器。
unsafe fn asm_load_fpu_from(base: *const u8) {
    asm!(
        "ldp q0, q1, [{0}, #288]",
        "ldp q2, q3, [{0}, #320]",
        "ldp q4, q5, [{0}, #352]",
        "ldp q6, q7, [{0}, #384]",
        "ldp q8, q9, [{0}, #416]",
        "ldp q10, q11, [{0}, #448]",
        "ldp q12, q13, [{0}, #480]",
        "ldp q14, q15, [{0}, #512]",
        "ldp q16, q17, [{0}, #544]",
        "ldp q18, q19, [{0}, #576]",
        "ldp q20, q21, [{0}, #608]",
        "ldp q22, q23, [{0}, #640]",
        "ldp q24, q25, [{0}, #672]",
        "ldp q26, q27, [{0}, #704]",
        "ldp q28, q29, [{0}, #736]",
        "ldp q30, q31, [{0}, #768]",
        "ldr w16, [{0}, #800]",
        "msr fpsr, x16",
        "ldr w16, [{0}, #804]",
        "msr fpcr, x16",
        in(reg) base,
        options(nostack)
    );
}

#[inline(always)]
pub unsafe fn acknowledge_irq() -> u32 {
    gic::acknowledge()
}

#[inline(always)]
pub unsafe fn end_irq(id: u32) {
    gic::end_interrupt(id);
}

#[inline(always)]
pub fn is_timer_irq(id: u32) -> bool {
    gic::is_timer_interrupt(id)
}

pub unsafe fn gic_init_cpu_interface() {
    gic::init_cpu_interface()
}

pub fn send_resched_sgi(target_mask: u8) {
    gic::send_resched_sgi(target_mask)
}

#[inline(always)]
pub unsafe fn program_next_tick() {
    timer::program_next_tick();
}

#[inline(always)]
pub fn interrupt_number(raw: u32) -> u32 {
    gic::interrupt_number(raw)
}

#[inline(always)]
pub unsafe fn enable_irq(id: u32) {
    gic::enable_irq(id);
}

#[inline(always)]
pub unsafe fn disable_irq(id: u32) {
    gic::disable_irq(id);
}

pub unsafe fn install_kernel_page_table(l1_phys: u64) {
    // 将 TTBR0_EL1/TTBR1_EL1 都指向同一个根页表。
    // 在保留固件 TCR/MAIR 配置的前提下，接管整个 EL1/EL0 地址空间。
    //
    // 切换后必须刷新 TLB：固件映射的残留条目会掩盖新页表的属性，
    // 内核会"靠旧 TLB 苟活"，直到第一次取指冷页才崩溃
    // （2025-11-15 死机日志的第二个根因）。
    asm!(
        "dsb ish",
        "msr ttbr0_el1, {0}",
        "msr ttbr1_el1, {0}",
        "isb",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        in(reg) l1_phys,
        options(nostack)
    );
}

unsafe fn set_vector_base(vbar: usize) {
    asm!(
        "msr VBAR_EL1, {0}",
        in(reg) vbar,
        options(nostack, preserves_flags)
    );
}

/// 直接改写 TPIDR_EL1（第十一刀：idle 切到 scratch 帧）。
#[inline(always)]
pub unsafe fn set_tpidr_el1(addr: usize) {
    asm!("msr tpidr_el1, {0}", in(reg) addr, options(nostack));
}

pub unsafe fn enable_interrupts() {
    asm!("msr daifclr, #0xf", options(nostack));
}

pub unsafe fn set_user_ttbr(root_phys: u64) {
    // 切换 TTBR0 后同样刷新 TLB，避免跨地址空间残留映射。
    asm!(
        "dsb ish",
        "msr ttbr0_el1, {0}",
        "isb",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        in(reg) root_phys,
        options(nostack)
    );
}

pub unsafe fn enter_user_mode(_aspace: &AddressSpace, tf: *const Context) -> ! {
    // TTBR0 已由 dispatch 的 space.activate() 切好；这里不重复写。
    // 首启进程同样走全量恢复：x4-x29 必须来自帧内清零值而不是内核残留，
    // 否则首启现场依赖内核寄存器垃圾（不可复现的 heisenbug 源）。
    crate::debug!(
        "enter_user_mode: ELR=0x{:x} SP_EL0=0x{:x}",
        (*tf).elr_el1,
        (*tf).sp_el0
    );
    restore_context(tf as *mut Context)
}

pub unsafe fn restore_context(frame: *mut Context) -> ! {
    let rc_slot = crate::scheduler::current_slot_opt();
    // 第十一刀：武装帧属主——入口存根的惰性保存门控以
    // 「FPU_DIRTY == frame.owner_slot」判定，本函数是唯一 eret 进
    // 用户态的必经之路（enter_user_mode / switch_to 均汇聚于此），
    // 故属主写入点单点闭环。current_slot 此刻已指向目标进程。
    (*frame).owner_slot = rc_slot.map(|s| s as u64).unwrap_or(FPU_OWNER_NONE);
    // ⚠ 惰性门位不在本函数调整（第十一刀排障结论）：restore_context
    // 同时服务「切换入」与「断链重放」两条路——此处若压回 01 门，
    // 重放的正是那条用户 FP 指令，会立刻再陷阱成死循环。门位由
    // 调度器在真正的上下文切换点（dispatch）统一下调，见
    // scheduler::dispatch → fpu_set_lazy_gate。
    let eager_fp = crate::arch::smp::multi_core_active();
    asm!(
        // TPIDR_EL1 := 帧指针 —— 异常入口存根靠它零成本定位保存目标。
        // 必须在任何 eret 前生效；x21 此刻仍持有 frame。
        "msr tpidr_el1, x21
         ldr x16, [x20, #272]
         mov sp, x16
         ldr x16, [x20, #248]
         msr sp_el0, x16
         ldr x16, [x20, #256]
         msr elr_el1, x16
         ldr x16, [x20, #264]
         msr spsr_el1, x16
         // 用户 TLS（TPIDR_EL0）—— 与入口存根对称保存。
         // x16 作暂存（随后被 ldp x16, x17 从帧内覆盖，无副作用）。
         ldr x16, [x20, #280]
         msr tpidr_el0, x16
         // ── FP 恢复双模（第十四刀 SMP）：x19=1（MULTI_CORE）走全量
         // 急切装载——帧相对、TPIDR 每 core 一份，跨核天然安全；
         // x19=0（单核）保持第十一刀惰性门：eret 前不装载不降门，
         // 用户首条 FP/SIMD 经 EC=0x07 断链。
         cbz x11, 55f
         // ── FPU 惰性恢复（第十一刀）：eret 前从不主动装载 frame.fpu，
         // 也不改写 FPU_DIRTY——活寄存器保持旧属主状态，用户首条
         // FP/SIMD 指令触发 EC=0x07 → fpu_trap_replay 断链装载后重放。
         // 非 FP 用户从此彻底零 FPU 开销；FP 用户跨切换只付一次陷阱。
         // （FPEN=0b01 由 arch::init 置定：EL1 自由、EL0 陷阱。）
         ldp q0, q1, [x20, #288]
         ldp q2, q3, [x20, #320]
         ldp q4, q5, [x20, #352]
         ldp q6, q7, [x20, #384]
         ldp q8, q9, [x20, #416]
         ldp q10, q11, [x20, #448]
         ldp q12, q13, [x20, #480]
         ldp q14, q15, [x20, #512]
         ldp q16, q17, [x20, #544]
         ldp q18, q19, [x20, #576]
         ldp q20, q21, [x20, #608]
         ldp q22, q23, [x20, #640]
         ldp q24, q25, [x20, #672]
         ldp q26, q27, [x20, #704]
         ldp q28, q29, [x20, #736]
         ldp q30, q31, [x20, #768]
         ldr w16, [x20, #800]
         msr fpsr, x16
         ldr w16, [x20, #804]
         msr fpcr, x16
         55:
         ldp x0, x1, [x20, #0]
         ldp x2, x3, [x20, #16]
         ldp x4, x5, [x20, #32]
         ldp x6, x7, [x20, #48]
         ldp x8, x9, [x20, #64]
         ldp x10, x11, [x20, #80]
         ldp x12, x13, [x20, #96]
         ldp x14, x15, [x20, #112]
         ldp x16, x17, [x20, #128]
         ldp x18, x19, [x20, #144]
         ldp x22, x23, [x20, #176]
         ldp x24, x25, [x20, #192]
         ldp x26, x27, [x20, #208]
         ldp x28, x29, [x20, #224]
         ldr x30, [x20, #240]
         ldr x20, [x21, #160]
         ldr x21, [x21, #168]
         eret",
        in("x20") frame,
        in("x21") frame,
        in("x11") eager_fp as usize,
        options(noreturn)
    )
}

#[derive(Debug)]
#[allow(dead_code)]
enum ExceptionClass {
    SyncEl1Sp0,
    IrqEl1Sp0,
    FiqEl1Sp0,
    SErrorEl1Sp0,
    SyncEl1Sp1,
    IrqEl1Sp1,
    FiqEl1Sp1,
    SErrorEl1Sp1,
    SyncEl0A64,
    IrqEl0A64,
    FiqEl0A64,
    SErrorEl0A64,
    SyncEl0A32,
    IrqEl0A32,
    FiqEl0A32,
    SErrorEl0A32,
}

fn default_exception(class: ExceptionClass) -> ! {
    let esr: u64;
    let far: u64;
    let elr: u64;
    let spsr: u64;
    let sp: u64;
    unsafe {
        asm!("mrs {0}, esr_el1", out(reg) esr);
        asm!("mrs {0}, far_el1", out(reg) far);
        asm!("mrs {0}, elr_el1", out(reg) elr);
        asm!("mrs {0}, spsr_el1", out(reg) spsr);
        asm!("mov {0}, sp", out(reg) sp);
    }
    let (slot, pid) = current_process_info();
    if let Some((kind, level)) = decode_data_abort(esr) {
        crate::info!(
            "AArch64 exception: {:?} ESR=0x{:016x} ({:?} level={:?}) FAR=0x{:016x} ELR=0x{:016x} SPSR=0x{:016x} SP=0x{:016x} slot={:?} pid={:?}",
            class,
            esr,
            kind,
            level,
            far,
            elr,
            spsr,
            sp,
            slot,
            pid,
        );
    } else {
        crate::info!(
            "AArch64 exception: {:?} ESR=0x{:016x} FAR=0x{:016x} ELR=0x{:016x} SPSR=0x{:016x} SP=0x{:016x} slot={:?} pid={:?}",
            class,
            esr,
            far,
            elr,
            spsr,
            sp,
            slot,
            pid
        );
    }
    crate::info!("AArch64 exception: entering spin loop");
    loop {
        spin_loop();
    }
}

// __vector_{sync,irq}_{el1t,el1h,el0_64} 现由汇编 SAVE_TRAP_AND_CALL 存根
// 直接实现（见文件头部 global_asm!）——现场保存必须发生在任何 Rust 代码
// 执行之前，Rust 函数序言会踩脏用户寄存器。

#[no_mangle]
extern "C" fn __vector_fiq_el1t() -> ! {
    default_exception(ExceptionClass::FiqEl1Sp0)
}

#[no_mangle]
extern "C" fn __vector_serror_el1t() -> ! {
    default_exception(ExceptionClass::SErrorEl1Sp0)
}

#[no_mangle]
extern "C" fn __vector_fiq_el1h() -> ! {
    default_exception(ExceptionClass::FiqEl1Sp1)
}

#[no_mangle]
extern "C" fn __vector_serror_el1h() -> ! {
    default_exception(ExceptionClass::SErrorEl1Sp1)
}

#[no_mangle]
extern "C" fn __vector_fiq_el0_64() -> ! {
    default_exception(ExceptionClass::FiqEl0A64)
}

#[no_mangle]
extern "C" fn __vector_serror_el0_64() -> ! {
    default_exception(ExceptionClass::SErrorEl0A64)
}

#[no_mangle]
extern "C" fn __vector_sync_el0_32() -> ! {
    default_exception(ExceptionClass::SyncEl0A32)
}

#[no_mangle]
extern "C" fn __vector_irq_el0_32() -> ! {
    default_exception(ExceptionClass::IrqEl0A32)
}

#[no_mangle]
extern "C" fn __vector_fiq_el0_32() -> ! {
    default_exception(ExceptionClass::FiqEl0A32)
}

#[no_mangle]
extern "C" fn __vector_serror_el0_32() -> ! {
    default_exception(ExceptionClass::SErrorEl0A32)
}

fn current_process_info() -> (Option<usize>, Option<u64>) {
    let slot = crate::scheduler::current_slot_opt();
    let pid = slot.and_then(|slot| crate::process::pid_at_slot(slot).map(|pid| pid.raw()));
    (slot, pid)
}

#[derive(Debug)]
enum AbortKind {
    Translation,
    Permission,
    AccessFlag,
    External,
    Alignment,
    Unknown,
}

fn decode_data_abort(esr: u64) -> Option<(AbortKind, Option<u8>)> {
    let ec = ((esr >> 26) & 0x3f) as u8;
    if ec != 0x25 && ec != 0x24 {
        return None;
    }
    let dfsc = (esr & 0x3f) as u8;
    let (kind, level) = match dfsc {
        0b000100..=0b000111 => (AbortKind::Translation, Some(dfsc & 0b11)),
        0b001100..=0b001111 => (AbortKind::Permission, Some(dfsc & 0b11)),
        0b001000..=0b001011 => (AbortKind::AccessFlag, Some(dfsc & 0b11)),
        0b010000..=0b010011 => (AbortKind::External, Some(dfsc & 0b11)),
        0b010100..=0b010111 => (AbortKind::External, Some(dfsc & 0b11)),
        0b100001 => (AbortKind::Alignment, None),
        _ => (AbortKind::Unknown, None),
    };
    Some((kind, level))
}
