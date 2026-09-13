#![no_std]

use userlib::{exit, yield_now};

#[no_mangle]
pub extern "C" fn user_entry() -> ! {
    let mut counter = 0u32;
    loop {
        counter += 1;
        if counter >= 5 {
            exit(0);
        }
        yield_now();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(-1)
}
