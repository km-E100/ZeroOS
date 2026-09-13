//! VirtIO RNG (device id 4): bounded polling entropy source.
//!
//! TLS/ASLR/KASLR must never synthesize entropy from clocks. The device owns a
//! single writable descriptor; `fill_random` polls the used ring because syscalls
//! execute with IRQs masked and correctness cannot depend on interrupt delivery.

use alloc::alloc::{alloc_zeroed, Layout};
use core::ptr;
use spin::Mutex;
use zero_abi::driver::DriverDescriptor;

use super::{
    configure_queue, negotiate_features, probe_device, set_driver_ok, VirtQueue, VIRTQ_DESC_F_WRITE,
};
use crate::{info, warn};

const DEVICE_ID_RNG: u32 = 4;
const QUEUE_SIZE: usize = 1;
const CHUNK: usize = 256;
const POLL_LIMIT: usize = 1_000_000;

struct State {
    ready: bool,
    queue: Option<VirtQueue<QUEUE_SIZE>>,
    buffer: *mut u8,
}
unsafe impl Send for State {}
impl State {
    const fn new() -> Self {
        Self {
            ready: false,
            queue: None,
            buffer: ptr::null_mut(),
        }
    }
}
static STATE: Mutex<State> = Mutex::new(State::new());

pub fn init(desc: &DriverDescriptor) {
    let base = desc.mmio_base as usize;
    unsafe {
        if super::mmio_read32(base, 0x008) == 0 {
            return;
        }
        if !probe_device(base, DEVICE_ID_RNG, "virtio-rng") || !negotiate_features(base) {
            return;
        }
    }
    let Some(mut q) = (unsafe { configure_queue::<QUEUE_SIZE>(base, 0) }) else {
        warn!("virtio-rng: queue unavailable");
        return;
    };
    // RNG is deliberately polling-only: syscalls execute with IRQs masked and
    // completion correctness cannot depend on an interrupt. Prevent the device
    // from generating an otherwise-unhandled MSI-X/LPI for every entropy chunk.
    q.suppress_interrupts();
    let buf = unsafe { alloc_zeroed(Layout::from_size_align(CHUNK, 64).unwrap()) };
    if buf.is_null() {
        warn!("virtio-rng: buffer OOM");
        return;
    }
    unsafe {
        *q.desc = super::VirtqDesc {
            addr: buf as u64,
            len: CHUNK as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        set_driver_ok(base);
    }
    let mut s = STATE.lock();
    s.queue = Some(q);
    s.buffer = buf;
    s.ready = true;
    info!("driver: virtio-rng online (base={:#x})", base);
}

pub fn is_ready() -> bool {
    STATE.lock().ready
}

pub fn fill_random(out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }
    let mut s = STATE.lock();
    if !s.ready || s.buffer.is_null() {
        return false;
    }
    let buf = s.buffer;
    let mut done = 0usize;
    while done < out.len() {
        let want = (out.len() - done).min(CHUNK);
        unsafe {
            ptr::write_bytes(buf, 0, want);
            let Some(q) = s.queue.as_mut() else {
                return false;
            };
            (*q.desc).len = want as u32;
            q.push(0);
        }
        let mut completion = None;
        for _ in 0..POLL_LIMIT {
            if let Some(elem) = s.queue.as_mut().and_then(|q| q.pop_used()) {
                completion = Some(elem);
                break;
            }
            core::hint::spin_loop();
        }
        let Some(elem) = completion else {
            return false;
        };
        if elem.id != 0 || elem.len == 0 {
            return false;
        }
        let got = (elem.len as usize).min(want);
        unsafe {
            ptr::copy_nonoverlapping(buf, out.as_mut_ptr().add(done), got);
        }
        done += got;
    }
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn chunk_is_bounded_and_nonzero() {
        assert!(super::CHUNK >= 32);
        assert!(super::CHUNK <= 4096);
    }
}
