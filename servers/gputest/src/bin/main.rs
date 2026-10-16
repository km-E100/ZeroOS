#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
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
            p = p.add(1)
        }
    }
    zero_gputest::server_main()
}
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    userlib::exit(119)
}
#[cfg(not(target_os = "none"))]
fn main() {}
