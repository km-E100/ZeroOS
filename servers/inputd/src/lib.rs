#![no_std]

use zero_abi::channels::INPUT_EVENT_BUS;
use zero_abi::input::InputEvent;
use zero_abi::ipc::Message;
use zero_abi::syscall::SysError;

/// inputd is intentionally policy-light: it owns the raw input capability and
/// republishes normalized events. Focus/shortcut/IME policy belongs to WindowServer.
pub extern "C" fn server_main() -> ! {
    let _ = userlib::console_write(b"Zero OS inputd online\r\n");
    loop {
        let mut event = InputEvent::default();
        match userlib::input_read(&mut event) {
            Ok(()) => publish(&event),
            Err(SysError::WouldBlock) => {
                let _ = userlib::sleep_ticks(1);
            }
            Err(_) => {
                let _ = userlib::sleep_ticks(1);
            }
        }
    }
}

fn publish(event: &InputEvent) {
    let mut msg = Message::empty();
    msg.code = 1;
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (event as *const InputEvent).cast::<u8>(),
            core::mem::size_of::<InputEvent>(),
        )
    };
    msg.payload[..bytes.len()].copy_from_slice(bytes);
    let _ = userlib::ipc_send(INPUT_EVENT_BUS, &msg);
}
