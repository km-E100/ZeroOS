use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use zero_abi::BootInfo;

static BOOT_INFO_PTR: AtomicPtr<BootInfo> = AtomicPtr::new(ptr::null_mut());

pub fn init(info: &'static BootInfo) {
    BOOT_INFO_PTR.store(info as *const _ as *mut BootInfo, Ordering::SeqCst);
}

pub fn get() -> Option<&'static BootInfo> {
    let ptr = BOOT_INFO_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

/// Early platform kinds patched by the UEFI loader into `.rodata.boot`.
pub const PLATFORM_UNKNOWN: u64 = 0;
pub const PLATFORM_QEMU_VIRT: u64 = 1;
pub const PLATFORM_PARALLELS_ARM: u64 = 2;

#[cfg(target_os = "none")]
extern "C" {
    static __zero_platform_kind: u64;
    static __zero_early_uart_base: u64;
    static __zero_pci_io_segment: u64;
    static __zero_pci_io_bus_base: u64;
    static __zero_pci_io_host_base: u64;
    static __zero_pci_io_len: u64;
    static __zero_boot_cpu_count: u64;
    static __zero_boot_cpu_mpidrs: [u64; 4];
}

#[inline]
pub fn platform_kind() -> u64 {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::addr_of!(__zero_platform_kind).read_volatile() }
    }
    #[cfg(not(target_os = "none"))]
    {
        PLATFORM_UNKNOWN
    }
}

#[inline]
pub fn early_uart_base() -> usize {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::addr_of!(__zero_early_uart_base).read_volatile() as usize }
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

#[inline]
pub fn qemu_virt_static_mmio() -> bool {
    platform_kind() == PLATFORM_QEMU_VIRT
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciIoWindow {
    pub segment: u16,
    /// PCI bus I/O address corresponding to `host_base`.
    pub bus_base: u64,
    /// CPU physical address of the root bridge I/O aperture.
    pub host_base: u64,
    pub len: u64,
}

/// PCI root-bridge I/O translation captured by UEFI before ExitBootServices.
/// This avoids an AML dependency for legacy PCI I/O BARs on ARM64.
pub fn pci_io_window() -> Option<PciIoWindow> {
    #[cfg(target_os = "none")]
    {
        let len = unsafe { core::ptr::addr_of!(__zero_pci_io_len).read_volatile() };
        if len == 0 {
            return None;
        }
        let segment = unsafe { core::ptr::addr_of!(__zero_pci_io_segment).read_volatile() };
        let bus_base = unsafe { core::ptr::addr_of!(__zero_pci_io_bus_base).read_volatile() };
        let host_base = unsafe { core::ptr::addr_of!(__zero_pci_io_host_base).read_volatile() };
        Some(PciIoWindow {
            segment: segment as u16,
            bus_base,
            host_base,
            len,
        })
    }
    #[cfg(not(target_os = "none"))]
    {
        None
    }
}

/// CPU affinities captured by UEFI MP Services before ExitBootServices.
/// Runtime ACPI is still authoritative when it enumerates a complete topology.
pub fn boot_cpu_mpidrs() -> Vec<u64> {
    #[cfg(target_os = "none")]
    {
        let count =
            unsafe { core::ptr::addr_of!(__zero_boot_cpu_count).read_volatile() as usize }.min(4);
        let base = core::ptr::addr_of!(__zero_boot_cpu_mpidrs) as *const u64;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let mpidr = unsafe { base.add(i).read_volatile() };
            if !out.contains(&mpidr) {
                out.push(mpidr);
            }
        }
        out
    }
    #[cfg(not(target_os = "none"))]
    {
        Vec::new()
    }
}
