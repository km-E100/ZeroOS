#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let _ = userlib::console_write(b"pkghello: launched\r\n");
    userlib::exit(0)
}
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    userlib::exit(98)
}
#[cfg(not(target_os = "none"))]
fn main() {}
