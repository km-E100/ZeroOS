use zero_abi::BootInfo;

use crate::process::{Context, TrapFrame};

#[cfg(target_arch = "aarch64")]
mod aarch64;

/// 供 crate::arch::smp 路径访问（process.rs/scheduler.rs 引用 MAX_CPUS 等）。
#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64_path {
    pub use super::aarch64::smp;
}

pub fn init(boot_info: &BootInfo) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::init(boot_info);
    }
}

/// MM + ACPI 之后的平台 IRQ/timer 第二阶段初始化。
pub fn init_platform() {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::init_platform();
    }
}

pub unsafe fn switch_to(next: *mut Context) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::switch_to(next)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = next;
        loop {}
    }
}

pub unsafe fn restore_frame(frame: *mut TrapFrame) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::restore_context(frame)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = frame;
        loop {}
    }
}

pub unsafe fn acknowledge_irq() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::acknowledge_irq()
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

pub unsafe fn end_irq(id: u32) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::end_irq(id);
    }
    let _ = id;
}

pub fn is_timer_irq(id: u32) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::is_timer_irq(id)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = id;
        false
    }
}

pub unsafe fn program_next_tick() {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::program_next_tick();
    }
}

pub use aarch64_path::smp;

/// RESCHED SGI 的 INTID（GICv2 SGI 恒使能；与 gic.rs 冻结值一致）。
pub const SGI_RESCHED: u32 = 0;

pub fn boot_secondaries() {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::smp::boot_secondaries();
    }
}

pub fn power_control(action: u32) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::power_control(action);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = action;
    }
}

pub fn fpu_arm_full_access() {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::fpu_arm_full_access();
    }
}

pub fn fpu_freeze_none() {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::fpu_freeze_none();
    }
}

/// Make newly written executable memory visible to instruction fetch on all PEs.
pub fn sync_instruction_cache(addr: usize, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::sync_instruction_cache(addr, len);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (addr, len);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

pub unsafe fn gic_init_cpu_interface() {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::gic_init_cpu_interface();
    }
}

pub fn send_resched_sgi(target_mask: u8) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::send_resched_sgi(target_mask);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = target_mask;
    }
}

pub fn interrupt_number(raw: u32) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::interrupt_number(raw)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = raw;
        0
    }
}

pub fn reserve_pci_msi_affinity(
    requester_id: u16,
    event: u32,
    cpu: usize,
) -> Option<(u64, u32, u32)> {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::reserve_pci_msi_affinity(requester_id, event, cpu)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (requester_id, event, cpu);
        None
    }
}

pub fn reserve_pci_msi(requester_id: u16, event: u32) -> Option<(u64, u32, u32)> {
    #[cfg(target_arch = "aarch64")]
    {
        return aarch64::reserve_pci_msi(requester_id, event);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (requester_id, event);
        None
    }
}

pub fn allocate_pci_msi_affinity(
    requester_id: u16,
    event: u32,
    cpu: usize,
    handler: fn(u32),
) -> Option<(u64, u32, u32)> {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::allocate_pci_msi_affinity(requester_id, event, cpu, handler)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (requester_id, event, cpu, handler);
        None
    }
}

pub fn allocate_pci_msi(
    requester_id: u16,
    event: u32,
    handler: fn(u32),
) -> Option<(u64, u32, u32)> {
    #[cfg(target_arch = "aarch64")]
    {
        return aarch64::allocate_pci_msi(requester_id, event, handler);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (requester_id, event, handler);
        None
    }
}

pub unsafe fn enable_irq(id: u32) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::enable_irq(id);
    }
    let _ = id;
}

pub unsafe fn disable_irq(id: u32) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::disable_irq(id);
    }
    let _ = id;
}

pub unsafe fn install_kernel_page_table(l1_phys: u64) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::install_kernel_page_table(l1_phys);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = l1_phys;
    }
}

pub unsafe fn set_tpidr_el1(addr: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::set_tpidr_el1(addr);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = addr;
    }
}

/// Switch to the per-CPU dedicated idle stack and never return to the caller's
/// process/IRQ stack.
pub unsafe fn enter_idle_stack(cpu: usize, entry: extern "C" fn(usize) -> !) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::enter_idle_stack(cpu, entry)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        entry(cpu)
    }
}

/// Abandon a process/IRQ stack and continue a scheduler handoff on the CPU's
/// private scheduler stack.
pub unsafe fn enter_scheduler_stack(
    cpu: usize,
    entry: extern "C" fn(usize, usize, usize) -> !,
    arg1: usize,
    arg2: usize,
) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::enter_scheduler_stack(cpu, entry, arg1, arg2)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        entry(cpu, arg1, arg2)
    }
}

pub unsafe fn enable_interrupts() {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::enable_interrupts();
    }
}

pub unsafe fn set_user_ttbr(root_phys: u64) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::set_user_ttbr(root_phys);
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = root_phys;
    }
}

pub unsafe fn enter_user_mode(
    aspace: &crate::mm::address_space::AddressSpace,
    tf: *const TrapFrame,
) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::enter_user_mode(aspace, tf)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (aspace, tf);
        loop {}
    }
}

/// 第十一刀 FPU 惰性保存：EC=0x07 断链装载 + eret 重放（仅 aarch64）。
pub unsafe fn fpu_trap_replay(frame: *mut TrapFrame) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::fpu_trap_replay(frame)
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = frame;
        loop {}
    }
}

/// 第十一刀 FPU 惰性保存：上下文切换点把 EL0 FP 访问压回陷阱门。
pub fn fpu_set_lazy_gate() {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::fpu_set_lazy_gate();
    }
}

/// 第十一刀 FPU 惰性保存：帧内 fpu 区作废前的活寄存器落账（execve）。
pub fn fpu_discard_live(frame: *mut TrapFrame) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::fpu_discard_live(frame);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = frame;
    }
}

/// Architectural cryptographic random-number capability, when the CPU exposes one.
pub fn hardware_rng_available() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        return aarch64::hardware_rng_available();
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Fill from an architectural hardware RNG only; never synthesizes clock-based entropy.
pub fn fill_hardware_random(out: &mut [u8]) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        return aarch64::fill_hardware_random(out);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = out;
        false
    }
}
