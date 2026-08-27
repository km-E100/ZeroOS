#![no_std]
use zero_abi::{channels, ipc::Message, protocol::audio as ap, syscall::SysError};

fn reply(pid: u64, code: u32, text: &[u8]) {
    let mut r = Message::empty();
    r.code = code;
    let n = text.len().min(r.payload.len());
    r.payload[..n].copy_from_slice(&text[..n]);
    let _ = userlib::ipc_send_to(channels::AUDIO_RESP, pid, &r);
}

fn play_acceptance_tone() -> Result<(), SysError> {
    let info = userlib::audio_info()?;
    if info.sample_rate != 48_000
        || info.channels != 2
        || info.sample_bits != 16
        || info.period_bytes != 2048
    {
        return Err(SysError::NotSupported);
    }
    let mut period = [0u8; 2048];
    // 440 Hz square wave, ~250 ms, stereo S16LE. Integer phase keeps audiod
    // independent of libm/FP and makes the WAV artifact deterministic.
    let mut phase = 0u32;
    for _ in 0..24 {
        for frame in period.chunks_exact_mut(4) {
            phase = phase.wrapping_add(440);
            if phase >= 48_000 {
                phase -= 48_000;
            }
            let sample: i16 = if phase < 24_000 { 6000 } else { -6000 };
            let b = sample.to_le_bytes();
            frame[0] = b[0];
            frame[1] = b[1];
            frame[2] = b[0];
            frame[3] = b[1];
        }
        userlib::audio_play_period(&period)?;
    }
    userlib::audio_stop()
}

pub extern "C" fn server_main() -> ! {
    let _ = userlib::console_write(b"Zero OS audiod online\r\n");
    loop {
        let mut q = Message::empty();
        match userlib::ipc_receive_from(channels::AUDIO_REQ, &mut q) {
            Ok(sender) => match q.code {
                ap::INFO => match userlib::audio_info() {
                    Ok(i) => {
                        let mut r = Message::empty();
                        r.code = ap::OK;
                        let b = unsafe {
                            core::slice::from_raw_parts(
                                (&i as *const zero_abi::audio::AudioInfo).cast::<u8>(),
                                16,
                            )
                        };
                        r.payload[..16].copy_from_slice(b);
                        let _ = userlib::ipc_send_to(channels::AUDIO_RESP, sender, &r);
                    }
                    Err(_) => reply(sender, ap::ERR, b"audio unavailable"),
                },
                ap::PLAY_TEST => match play_acceptance_tone() {
                    Ok(()) => reply(sender, ap::OK, b"played"),
                    Err(_) => reply(sender, ap::ERR, b"play failed"),
                },
                ap::STOP => match userlib::audio_stop() {
                    Ok(()) => reply(sender, ap::OK, b"stopped"),
                    Err(_) => reply(sender, ap::ERR, b"stop failed"),
                },
                _ => reply(sender, ap::ERR, b"unknown audio command"),
            },
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => userlib::yield_now(),
        }
    }
}
