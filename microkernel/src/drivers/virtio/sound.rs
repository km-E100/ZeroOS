//! VirtIO Sound playback backend (device id 25).
//!
//! Knife 33 intentionally keeps policy in `audiod`: the kernel owns only the
//! virtqueue/DMA transport and a capability-gated S16LE/48kHz/stereo period API.
//! The first QEMU stream is playback; we still query PCM_INFO and reject the
//! device unless the exact format/rate/channel tuple is advertised.

use alloc::alloc::{alloc_zeroed, Layout};
use spin::Mutex;
use zero_abi::driver::DriverDescriptor;

use super::{
    configure_queue, mmio_read32, negotiate_features, probe_device, set_driver_ok, VirtQueue,
    VirtqDesc, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};
use crate::{info, warn};

const DEVICE_ID_SOUND: u32 = 25;
const CONFIG_JACKS: usize = 0x100;
const CONFIG_STREAMS: usize = 0x104;
const CONFIG_CHMAPS: usize = 0x108;
const QSZ: usize = 8;
const EVENT_BYTES: usize = 8;
const POLL_LIMIT: usize = 8_000_000;

const R_PCM_INFO: u32 = 0x0100;
const R_PCM_SET_PARAMS: u32 = 0x0101;
const R_PCM_PREPARE: u32 = 0x0102;
const R_PCM_RELEASE: u32 = 0x0103;
const R_PCM_START: u32 = 0x0104;
const R_PCM_STOP: u32 = 0x0105;
const S_OK: u32 = 0x8000;

const D_OUTPUT: u8 = 0;
const FMT_S16: u8 = 5;
const RATE_48000: u8 = 7;
pub const CHANNELS: usize = 2;
pub const SAMPLE_RATE: usize = 48_000;
pub const SAMPLE_BYTES: usize = 2;
pub const FRAME_BYTES: usize = CHANNELS * SAMPLE_BYTES;
pub const PERIOD_BYTES: usize = 2048;
pub const BUFFER_BYTES: usize = 8192;

#[derive(Copy, Clone, Debug)]
pub struct PlaybackInfo {
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
    pub streams: u32,
}

struct State {
    base: usize,
    control: VirtQueue<QSZ>,
    event: VirtQueue<QSZ>,
    tx: VirtQueue<QSZ>,
    _rx: VirtQueue<QSZ>,
    _event_mem: usize,
    info: PlaybackInfo,
    prepared: bool,
    running: bool,
}
unsafe impl Send for State {}
static SOUND: Mutex<Option<State>> = Mutex::new(None);

pub fn init(desc: &DriverDescriptor) {
    let base = desc.mmio_base as usize;
    unsafe {
        if mmio_read32(base, 0x008) == 0 {
            return;
        }
        if !probe_device(base, DEVICE_ID_SOUND, "virtio-sound") || !negotiate_features(base) {
            return;
        }
    }
    let streams = unsafe { mmio_read32(base, CONFIG_STREAMS) };
    let jacks = unsafe { mmio_read32(base, CONFIG_JACKS) };
    let chmaps = unsafe { mmio_read32(base, CONFIG_CHMAPS) };
    if streams == 0 {
        warn!("virtio-sound: device exposes zero PCM streams");
        return;
    }
    let (Some(mut control), Some(mut event), Some(tx), Some(rx)) = (unsafe {
        (
            configure_queue::<QSZ>(base, 0),
            configure_queue::<QSZ>(base, 1),
            configure_queue::<QSZ>(base, 2),
            configure_queue::<QSZ>(base, 3),
        )
    }) else {
        warn!("virtio-sound: one or more required queues unavailable");
        return;
    };

    // The spec requires eventq to be pre-populated with device-writable buffers.
    let layout = Layout::from_size_align(QSZ * EVENT_BYTES, 8).unwrap();
    let event_mem = unsafe { alloc_zeroed(layout) };
    if event_mem.is_null() {
        warn!("virtio-sound: event buffers OOM");
        return;
    }
    unsafe {
        for i in 0..QSZ {
            *event.desc.add(i) = VirtqDesc {
                addr: event_mem.add(i * EVENT_BYTES) as u64,
                len: EVENT_BYTES as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };
            event.push(i as u16);
        }
        set_driver_ok(base);
    }

    let Some(info) = query_playback(&mut control, streams) else {
        warn!("virtio-sound: PCM stream 0 does not support 48kHz/S16/stereo output");
        return;
    };
    crate::drivers::register_irq_handler(desc.irq, irq_handler);
    *SOUND.lock() = Some(State {
        base,
        control,
        event,
        tx,
        _rx: rx,
        _event_mem: event_mem as usize,
        info,
        prepared: false,
        running: false,
    });
    info!(
        "driver: virtio-sound online streams={} jacks={} chmaps={} pcm=48k/S16/stereo base={:#x}",
        streams, jacks, chmaps, base
    );
}

fn query_playback(q: &mut VirtQueue<QSZ>, streams: u32) -> Option<PlaybackInfo> {
    // virtio_snd_query_info: code,start_id,count,size. PCM info is 32 bytes.
    let mut req = [0u8; 16];
    put32(&mut req, 0, R_PCM_INFO);
    put32(&mut req, 4, 0);
    put32(&mut req, 8, 1);
    put32(&mut req, 12, 32);
    let mut resp = [0u8; 36]; // status hdr + one pcm_info
    if !control_xfer(q, &req, &mut resp) || get32(&resp, 0) != S_OK {
        return None;
    }
    let formats = get64(&resp, 12); // response hdr(4) + info(hda4,features4)
    let rates = get64(&resp, 20);
    let direction = resp[28];
    let channels_min = resp[29];
    let channels_max = resp[30];
    if direction != D_OUTPUT
        || formats & (1u64 << FMT_S16) == 0
        || rates & (1u64 << RATE_48000) == 0
        || !(channels_min..=channels_max).contains(&(CHANNELS as u8))
    {
        return None;
    }
    Some(PlaybackInfo {
        channels: CHANNELS as u8,
        format: FMT_S16,
        rate: RATE_48000,
        streams,
    })
}

fn control_xfer(q: &mut VirtQueue<QSZ>, req: &[u8], resp: &mut [u8]) -> bool {
    if req.is_empty() || resp.len() < 4 {
        return false;
    }
    unsafe {
        *q.desc.add(0) = VirtqDesc {
            addr: req.as_ptr() as u64,
            len: req.len() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        *q.desc.add(1) = VirtqDesc {
            addr: resp.as_mut_ptr() as u64,
            len: resp.len() as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
    }
    q.push(0);
    for _ in 0..POLL_LIMIT {
        if q.pop_used().is_some() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn pcm_cmd(q: &mut VirtQueue<QSZ>, code: u32) -> bool {
    let mut req = [0u8; 8];
    put32(&mut req, 0, code);
    put32(&mut req, 4, 0); // stream_id 0 = first playback stream in QEMU
    let mut resp = [0u8; 4];
    control_xfer(q, &req, &mut resp) && get32(&resp, 0) == S_OK
}

fn ensure_prepared(s: &mut State) -> bool {
    if s.prepared {
        return true;
    }
    let mut req = [0u8; 24];
    put32(&mut req, 0, R_PCM_SET_PARAMS);
    put32(&mut req, 4, 0);
    put32(&mut req, 8, BUFFER_BYTES as u32);
    put32(&mut req, 12, PERIOD_BYTES as u32);
    put32(&mut req, 16, 0); // no stream feature bits selected
    req[20] = CHANNELS as u8;
    req[21] = FMT_S16;
    req[22] = RATE_48000;
    req[23] = 0;
    let mut resp = [0u8; 4];
    if !control_xfer(&mut s.control, &req, &mut resp) || get32(&resp, 0) != S_OK {
        return false;
    }
    if !pcm_cmd(&mut s.control, R_PCM_PREPARE) {
        return false;
    }
    s.prepared = true;
    true
}

/// Submit one S16LE stereo output period and wait until the device consumes it.
/// The first period is queued before START, satisfying the output pre-buffering
/// requirement. Subsequent periods run on the already-started stream.
pub fn play_period(pcm: &[u8]) -> bool {
    if pcm.is_empty() || pcm.len() > PERIOD_BYTES || pcm.len() % FRAME_BYTES != 0 {
        return false;
    }
    let mut guard = SOUND.lock();
    let Some(s) = guard.as_mut() else {
        return false;
    };
    if !ensure_prepared(s) {
        return false;
    }

    let xfer = 0u32.to_le_bytes();
    let mut status = [0u8; 8];
    unsafe {
        *s.tx.desc.add(0) = VirtqDesc {
            addr: xfer.as_ptr() as u64,
            len: xfer.len() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        *s.tx.desc.add(1) = VirtqDesc {
            addr: pcm.as_ptr() as u64,
            len: pcm.len() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: 2,
        };
        *s.tx.desc.add(2) = VirtqDesc {
            addr: status.as_mut_ptr() as u64,
            len: status.len() as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
    }
    s.tx.push(0);
    if !s.running {
        if !pcm_cmd(&mut s.control, R_PCM_START) {
            return false;
        }
        s.running = true;
    }
    for _ in 0..POLL_LIMIT {
        if s.tx.pop_used().is_some() {
            return get32(&status, 0) == S_OK;
        }
        core::hint::spin_loop();
    }
    false
}

pub fn stop() -> bool {
    let mut guard = SOUND.lock();
    let Some(s) = guard.as_mut() else {
        return false;
    };
    if s.running && !pcm_cmd(&mut s.control, R_PCM_STOP) {
        return false;
    }
    s.running = false;
    if s.prepared && !pcm_cmd(&mut s.control, R_PCM_RELEASE) {
        return false;
    }
    s.prepared = false;
    true
}

pub fn info() -> Option<PlaybackInfo> {
    SOUND.lock().as_ref().map(|s| s.info)
}
pub fn active() -> bool {
    SOUND.lock().is_some()
}

pub fn irq_handler(_irq: u32) {
    let mut guard = SOUND.lock();
    let Some(s) = guard.as_mut() else {
        return;
    };
    unsafe {
        let status = super::mmio_read32(s.base, super::REG_INTERRUPT_STATUS);
        if status != 0 {
            super::mmio_write32(s.base, super::REG_INTERRUPT_ACK, status);
        }
    }
    // Recycle any event buffers completed by the device. We currently negotiate
    // no period/xrun event feature bits, but eventq must remain valid by spec.
    while let Some(e) = s.event.pop_used() {
        if (e.id as usize) < QSZ {
            s.event.push(e.id as u16);
        } else {
            break;
        }
    }
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn get32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn get64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_constants_match_virtio_sound() {
        assert_eq!(DEVICE_ID_SOUND, 25);
        assert_eq!(
            (R_PCM_INFO, R_PCM_SET_PARAMS, R_PCM_PREPARE),
            (0x100, 0x101, 0x102)
        );
        assert_eq!(
            (R_PCM_RELEASE, R_PCM_START, R_PCM_STOP),
            (0x103, 0x104, 0x105)
        );
        assert_eq!(FMT_S16, 5);
        assert_eq!(RATE_48000, 7);
        assert_eq!(PERIOD_BYTES % FRAME_BYTES, 0);
        assert_eq!(BUFFER_BYTES % PERIOD_BYTES, 0);
    }
    #[test]
    fn pcm_info_offsets_are_spec_layout() {
        let mut r = [0u8; 36];
        put32(&mut r, 0, S_OK);
        r[28] = D_OUTPUT;
        r[29] = 1;
        r[30] = 2;
        r[12..20].copy_from_slice(&(1u64 << FMT_S16).to_le_bytes());
        r[20..28].copy_from_slice(&(1u64 << RATE_48000).to_le_bytes());
        assert_eq!(get32(&r, 0), S_OK);
        assert_ne!(get64(&r, 12) & (1 << FMT_S16), 0);
        assert_ne!(get64(&r, 20) & (1 << RATE_48000), 0);
    }
    #[test]
    fn queue_wire_types_fit_three_descriptor_tx() {
        assert_eq!(size_of::<VirtqDesc>(), 16);
        assert_eq!(EVENT_BYTES, 8);
    }
}
