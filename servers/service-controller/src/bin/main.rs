#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![cfg_attr(target_os = "none", feature(alloc_error_handler))]

#[cfg(target_os = "none")]
extern crate zero_service_controller;

#[cfg(target_os = "none")]
use core::alloc::Layout;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
use useralloc::StaticFreeList;

#[cfg(target_os = "none")]
const HEAP_SIZE: usize = 32 * 1024;
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: StaticFreeList<HEAP_SIZE> = StaticFreeList::new();

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    zero_service_controller::server_main()
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(target_os = "none")]
#[alloc_error_handler]
fn alloc_error(_: Layout) -> ! {
    loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {
    panic!(
        "zero-service-controller must be built for the bare-metal target (e.g. aarch64-unknown-none)"
    );
}
