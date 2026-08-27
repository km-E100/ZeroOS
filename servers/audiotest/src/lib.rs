#![no_std]
use zero_abi::{channels, ipc::Message, protocol::audio as ap, syscall::SysError};
pub extern "C" fn server_main() -> ! {
    let _ = userlib::console_write(b"audiotest: request\r\n");
    let mut q = Message::empty();
    q.code = ap::PLAY_TEST;
    if userlib::ipc_send(channels::AUDIO_REQ, &q).is_err() {
        let _ = userlib::console_write(b"audiotest: FAIL send\r\n");
        userlib::exit(101)
    }
    loop {
        let mut r = Message::empty();
        match userlib::ipc_receive_from(channels::AUDIO_RESP, &mut r) {
            Ok(_) => {
                if r.code == ap::OK {
                    let _ = userlib::console_write(b"audiotest: PLAYBACK PASS\r\n");
                    userlib::exit(0)
                } else {
                    let _ = userlib::console_write(b"audiotest: FAIL playback\r\n");
                    userlib::exit(102)
                }
            }
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => {
                let _ = userlib::console_write(b"audiotest: FAIL recv\r\n");
                userlib::exit(103)
            }
        }
    }
}
