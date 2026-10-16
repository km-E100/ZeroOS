#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![cfg_attr(target_os = "none", feature(alloc_error_handler))]
#[cfg(target_os = "none")]
use core::{alloc::Layout, panic::PanicInfo};
#[cfg(target_os = "none")]
use useralloc::StaticFreeList;
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOC: StaticFreeList<{ 128 * 1024 }> = StaticFreeList::new();
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        extern "C" {
            static mut __bss_start: u8;
            static mut __bss_end: u8;
        }
        let mut p = &raw mut __bss_start as *mut u8;
        let e = &raw mut __bss_end as *mut u8;
        while p < e {
            core::ptr::write_volatile(p, 0);
            p = p.add(1);
        }
    }
    zero_inputd::server_main()
}
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
#[cfg(target_os = "none")]
#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    loop {}
}
#[cfg(not(target_os = "none"))]
fn main() {
    panic!("zero-inputd is a bare-metal service")
}
