#![no_std]
#![no_main]

use core::fmt::Write;
use core::panic::PanicInfo;

const PL011_BASE: usize = 0x0900_0000;

struct Logger;

impl Write for Logger {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe {
            for byte in s.bytes() {
                core::ptr::write_volatile(PL011_BASE as *mut u8, byte);
            }
        }
        Ok(())
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let mut log = Logger;
    let _ = writeln!(log, "launchd: panic");
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut log = Logger;
    let _ = writeln!(log, "launchd: started");
    loop {}
}
