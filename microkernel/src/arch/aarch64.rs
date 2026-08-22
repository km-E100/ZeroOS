use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use zero_abi::BootInfo;

use crate::mm::address_space::AddressSpace;
use crate::process::Context;

mod gic;
mod timer;

const SPSR_EL0T_MASKED: u64 = (1 << 6) | (1 << 7) | (1 << 8);
// M[3:0]=0b0000 (EL0t)，DAIF 全清 → EL0 可被 timer 抢占。
// 内核侧全程保持 IRQ 屏蔽（异常入口硬件自动置 I=1），只有 eret 回 EL0 时
// 通过 SPSR 恢复 I=0 —— 单核自旋锁场景下这是唯一不会重入死锁的中断策略。
const SPSR_EL0T_IRQ_ON: u64 = 0;

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
     vector_entry __vector_serror_el0_32\n"
);

extern "C" {
    static __vector_table: u8;
    fn __zero_trap_handler(frame: *mut Context, kind: u64) -> !;
}

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

        asm!("msr SPSel, #1", options(nostack, preserves_flags));
        set_vector_base(&__vector_table as *const _ as usize);
        crate::info!("arch/aarch64: vectors set");
        gic::init();
        crate::info!("arch/aarch64: gic init done");
        timer::init(10);
        crate::info!("arch/aarch64: timer init done");
        // Do not enable interrupts yet; defer until scheduler
        // has initialised and installed a current slot.
    }
    crate::info!("arch/aarch64: vector table installed");
}

pub unsafe fn context_switch(current: Option<*mut Context>, next: *mut Context) -> ! {
    if let Some(cur) = current {
        save_trap_frame(cur);
    }
    restore_context(next)
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

pub unsafe fn enter_user_mode(aspace: &AddressSpace, tf: *const Context) -> ! {
    let ttbr0 = aspace.ttbr0_phys();
    let spsr = SPSR_EL0T_IRQ_ON;
    // TTBR0 已由 dispatch 的 space.activate() 切好；这里不重复写。
    crate::info!(
        "enter_user_mode: TTBR0=0x{:016x} ELR=0x{:x} SP_EL0=0x{:x} SPSR=0x{:x}",
        ttbr0,
        (*tf).elr_el1,
        (*tf).sp_el0,
        spsr
    );
    // ⚠ 栈切换必须在**同一个** asm 块里完成：给编译器看到"mov sp"却声明
    // options(nostack) 会让 LLVM 误以为 sp 未变，后续所有 [sp+N] 局部
    // 引用全部错位（实测 &space 指向垃圾 → root_phys=0 → TTBR0:=0 → 死机）。
    asm!(
        // 切换内核栈（trap frame 里预存的 sp_el1 = kernel_stack_top）。
        // 此后不再触碰旧帧，全部经寄存器操作。
        "ldr x16, [{tf}, #272]",
        "mov sp, x16",
        // Restore argument registers x0-x3.
        "ldp x0, x1, [{tf}, #0]",
        "ldp x2, x3, [{tf}, #16]",
        // Restore LR from trap frame (regs[30]).
        "ldr x30, [{tf}, #240]",
        // Populate SP_EL0 (user stack pointer) and ELR_EL1 (resume PC).
        "ldr x16, [{tf}, #248]",
        "msr sp_el0, x16",
        "ldr x16, [{tf}, #256]",
        "msr elr_el1, x16",
        // Program SPSR_EL1 for an ERet into EL0t with IRQ/FIQ/SError enabled.
        "msr spsr_el1, {spsr}",
        "eret",
        spsr = in(reg) spsr,
        tf = in(reg) tf,
        options(noreturn)
    );
}

unsafe fn save_trap_frame(frame: *mut Context) {
    asm!(
        "stp x0, x1, [{frame}, #0]
         stp x2, x3, [{frame}, #16]
         stp x4, x5, [{frame}, #32]
         stp x6, x7, [{frame}, #48]
         stp x8, x9, [{frame}, #64]
         stp x10, x11, [{frame}, #80]
         stp x12, x13, [{frame}, #96]
         stp x14, x15, [{frame}, #112]
         stp x16, x17, [{frame}, #128]
         stp x18, x19, [{frame}, #144]
         stp x20, x21, [{frame}, #160]
         stp x22, x23, [{frame}, #176]
         stp x24, x25, [{frame}, #192]
         stp x26, x27, [{frame}, #208]
         stp x28, x29, [{frame}, #224]
         str x30, [{frame}, #240]
         mrs x16, sp_el0
         str x16, [{frame}, #248]
         mrs x16, elr_el1
         str x16, [{frame}, #256]
         mrs x16, spsr_el1
         str x16, [{frame}, #264]
         mov x16, sp
         str x16, [{frame}, #272]",
        frame = in(reg) frame,
        out("x16") _,
        options(nostack)
    );
}

pub unsafe fn restore_context(frame: *mut Context) -> ! {
    asm!(
        "ldr x16, [x20, #272]
         mov sp, x16
         ldr x16, [x20, #248]
         msr sp_el0, x16
         ldr x16, [x20, #256]
         msr elr_el1, x16
         ldr x16, [x20, #264]
         msr spsr_el1, x16
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

#[no_mangle]
extern "C" fn __vector_sync_el1t() -> ! {
    default_exception(ExceptionClass::SyncEl1Sp0)
}

#[no_mangle]
extern "C" fn __vector_irq_el1t() -> ! {
    unsafe { trap_entry(1) }
}

#[no_mangle]
extern "C" fn __vector_fiq_el1t() -> ! {
    default_exception(ExceptionClass::FiqEl1Sp0)
}

#[no_mangle]
extern "C" fn __vector_serror_el1t() -> ! {
    default_exception(ExceptionClass::SErrorEl1Sp0)
}

#[no_mangle]
extern "C" fn __vector_sync_el1h() -> ! {
    default_exception(ExceptionClass::SyncEl1Sp1)
}

#[no_mangle]
extern "C" fn __vector_irq_el1h() -> ! {
    unsafe { trap_entry(1) }
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
extern "C" fn __vector_sync_el0_64() -> ! {
    unsafe { trap_entry(0) }
}

#[no_mangle]
extern "C" fn __vector_irq_el0_64() -> ! {
    unsafe { trap_entry(1) }
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

unsafe fn trap_entry(kind: u64) -> ! {
    let slot = crate::scheduler::current_slot();
    let frame_ptr = crate::process::context_ptr(slot);
    save_trap_frame(frame_ptr);
    __zero_trap_handler(frame_ptr, kind)
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
