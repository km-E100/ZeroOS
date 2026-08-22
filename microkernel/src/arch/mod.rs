use zero_abi::BootInfo;

use crate::process::{Context, TrapFrame};

#[cfg(target_arch = "aarch64")]
mod aarch64;

pub fn init(boot_info: &BootInfo) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::init(boot_info);
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
