#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate zero_ipc_router;

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    zero_ipc_router::server_main()
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {
    panic!("zero-ipc-router binary must be built for the bare-metal target (e.g. aarch64-unknown-none)");
}
