//! VirtIO input multiplexer (device id 18).
//!
//! Multiple virtio-input devices (keyboard/tablet/mouse) each own an event
//! virtqueue. IRQs are routed into one bounded normalized InputEvent ring read
//! only by CAP_INPUT_DEV inputd. Focus/IME policy stays in user space.

use alloc::alloc::{alloc_zeroed, Layout};
use alloc::vec::Vec;
use core::mem::size_of;
use spin::Mutex;
use zero_abi::driver::DriverDescriptor;
use zero_abi::input::{InputEvent, KIND_ABS, KIND_BUTTON, KIND_KEY, KIND_REL, KIND_WHEEL};

use super::{
    configure_queue, mmio_read32, mmio_write32, negotiate_features, probe_device, set_driver_ok,
    VirtQueue, VirtqDesc, VIRTQ_DESC_F_WRITE,
};
use crate::{info, warn};

const DEVICE_ID_INPUT: u32 = 18;
const QN: usize = 64;
const RING: usize = 256;
const MAX_DEVICES: usize = 4;
const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;
const REL_WHEEL: u16 = 8;
const BTN_MISC: u16 = 0x100;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct RawEvent {
    kind: u16,
    code: u16,
    value: i32,
}

struct Device {
    base: usize,
    irq: u32,
    queue: VirtQueue<QN>,
    buffers: *mut RawEvent,
    device_id: u32,
}
unsafe impl Send for Device {}

struct State {
    devices: Vec<Device>,
    ring: [InputEvent; RING],
    head: usize,
    tail: usize,
    dropped: u64,
}
unsafe impl Send for State {}
impl State {
    const fn new() -> Self {
        Self {
            devices: Vec::new(),
            ring: [InputEvent {
                kind: 0,
                code: 0,
                value: 0,
                modifiers: 0,
                device_id: 0,
                timestamp: 0,
            }; RING],
            head: 0,
            tail: 0,
            dropped: 0,
        }
    }
}
static STATE: Mutex<State> = Mutex::new(State::new());

pub fn init(desc: &DriverDescriptor) {
    let base = desc.mmio_base as usize;
    unsafe {
        if mmio_read32(base, 0x008) == 0 {
            return;
        }
        if !probe_device(base, DEVICE_ID_INPUT, "virtio-input") || !negotiate_features(base) {
            return;
        }
    }
    let Some(mut q) = (unsafe { configure_queue::<QN>(base, 0) }) else {
        warn!("virtio-input: event queue unavailable");
        return;
    };
    let layout = Layout::array::<RawEvent>(QN).unwrap();
    let buf = unsafe { alloc_zeroed(layout) as *mut RawEvent };
    if buf.is_null() {
        return;
    }
    unsafe {
        for i in 0..QN {
            *q.desc.add(i) = VirtqDesc {
                addr: buf.add(i) as u64,
                len: size_of::<RawEvent>() as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };
            q.push(i as u16)
        }
    }
    {
        let mut s = STATE.lock();
        if s.devices.len() >= MAX_DEVICES {
            warn!("virtio-input: too many devices");
            return;
        }
        s.devices.push(Device {
            base,
            irq: desc.irq,
            queue: q,
            buffers: buf,
            device_id: desc.irq,
        });
    }
    crate::drivers::register_irq_handler(desc.irq, irq_handler);
    unsafe { set_driver_ok(base) };
    info!(
        "driver: virtio-input online (base={:#x} irq={})",
        base, desc.irq
    );
}

fn translate(raw: RawEvent, device_id: u32) -> Option<InputEvent> {
    if raw.kind == EV_SYN {
        return None;
    }
    let kind = match raw.kind {
        EV_KEY if raw.code >= BTN_MISC => KIND_BUTTON,
        EV_KEY => KIND_KEY,
        EV_REL if raw.code == REL_WHEEL => KIND_WHEEL,
        EV_REL => KIND_REL,
        EV_ABS => KIND_ABS,
        _ => return None,
    };
    Some(InputEvent {
        kind,
        code: raw.code,
        value: raw.value,
        modifiers: 0,
        device_id,
        timestamp: crate::time::monotonic_ns(),
    })
}
fn push_ring(s: &mut State, e: InputEvent) {
    // Mirror keyboard text into the independent terminal byte queue before
    // inputd consumes the normalized event. GUI and console therefore both see
    // the key without racing for one shared IPC/ring element.
    crate::drivers::console_input::feed(&e);
    let next = (s.head + 1) % RING;
    if next == s.tail {
        s.dropped = s.dropped.saturating_add(1);
        return;
    }
    s.ring[s.head] = e;
    s.head = next
}
/// Inject an already-normalized event from another transport (USB/xHCI).
pub fn inject(event: InputEvent) {
    push_ring(&mut STATE.lock(), event);
}

pub fn pop() -> Option<InputEvent> {
    let mut s = STATE.lock();
    if s.tail == s.head {
        return None;
    }
    let e = s.ring[s.tail];
    s.tail = (s.tail + 1) % RING;
    Some(e)
}
pub fn is_ready() -> bool {
    !STATE.lock().devices.is_empty()
}
pub fn dropped_events() -> u64 {
    STATE.lock().dropped
}

pub fn irq_handler(irq: u32) {
    let mut s = STATE.lock();
    let Some(di) = s.devices.iter().position(|d| d.irq == irq) else {
        return;
    };
    loop {
        let (elem, buffers, device_id) = {
            let d = &mut s.devices[di];
            (d.queue.pop_used(), d.buffers, d.device_id)
        };
        let Some(elem) = elem else { break };
        let id = elem.id as usize;
        if id >= QN {
            continue;
        }
        let raw = unsafe { core::ptr::read_volatile(buffers.add(id)) };
        unsafe { core::ptr::write_volatile(buffers.add(id), RawEvent::default()) };
        if let Some(e) = translate(raw, device_id) {
            push_ring(&mut s, e)
        }
        s.devices[di].queue.push(id as u16);
    }
    let base = s.devices[di].base;
    unsafe {
        let status = mmio_read32(base, super::REG_INTERRUPT_STATUS);
        if status != 0 {
            mmio_write32(base, super::REG_INTERRUPT_ACK, status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn translate_linux_event_kinds() {
        assert_eq!(
            translate(
                RawEvent {
                    kind: EV_KEY,
                    code: 30,
                    value: 1
                },
                7
            )
            .unwrap()
            .kind,
            KIND_KEY
        );
        assert_eq!(
            translate(
                RawEvent {
                    kind: EV_KEY,
                    code: 0x110,
                    value: 1
                },
                7
            )
            .unwrap()
            .kind,
            KIND_BUTTON
        );
        assert_eq!(
            translate(
                RawEvent {
                    kind: EV_REL,
                    code: REL_WHEEL,
                    value: -1
                },
                7
            )
            .unwrap()
            .kind,
            KIND_WHEEL
        );
        assert!(translate(
            RawEvent {
                kind: EV_SYN,
                code: 0,
                value: 0
            },
            7
        )
        .is_none())
    }
    #[test]
    fn raw_event_wire_size() {
        assert_eq!(size_of::<RawEvent>(), 8);
        assert_eq!(size_of::<InputEvent>(), 24)
    }
    #[test]
    fn ring_overflow_is_bounded() {
        let mut s = State::new();
        for i in 0..RING + 5 {
            push_ring(
                &mut s,
                InputEvent {
                    kind: KIND_KEY,
                    code: i as u16,
                    ..InputEvent::default()
                },
            )
        }
        assert!(s.dropped > 0);
        let mut n = 0;
        while s.tail != s.head {
            s.tail = (s.tail + 1) % RING;
            n += 1
        }
        assert_eq!(n, RING - 1)
    }
}
