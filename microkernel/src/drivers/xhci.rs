//! Knife39: PCI xHCI + minimal USB HID stack.
//!
//! The controller owns command/event/transfer rings and USB enumeration.  HID
//! reports are normalized into the existing input ring so inputd/WindowServer do
//! not know whether an event came from virtio-input or USB.

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use zero_abi::input::{InputEvent, KIND_ABS, KIND_BUTTON, KIND_KEY, KIND_REL, KIND_WHEEL};

use crate::mm::phys;
use crate::pci::PciDevice;

const TRBS: usize = 256;
const LINK_INDEX: usize = 255;
const TRB_CYCLE: u32 = 1;
const TRB_TC: u32 = 1 << 1;
const TRB_ISP: u32 = 1 << 2;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;
const TRB_DIR_IN: u32 = 1 << 16;
const fn trb_type(t: u32) -> u32 {
    t << 10
}
const TRB_NORMAL: u32 = 1;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_DISABLE_SLOT: u32 = 10;
const TRB_ADDR_DEV: u32 = 11;
const TRB_CONFIG_EP: u32 = 12;
const TRB_EVAL_CTX: u32 = 13;
const TRB_TRANSFER: u32 = 32;
const TRB_COMPLETION: u32 = 33;
const TRB_PORT_STATUS: u32 = 34;

const PORT_CONNECT: u32 = 1 << 0;
const PORT_PE: u32 = 1 << 1;
const PORT_RESET: u32 = 1 << 4;
const PORT_POWER: u32 = 1 << 9;
const PORT_CHANGE: u32 = 0x7f << 17;
const PORT_RWS: u32 = (0xf << 5) | (1 << 9) | (0x3 << 14) | (0x7 << 25);
const PORT_RO: u32 = (1 << 0) | (1 << 3) | (0xf << 10) | (1 << 30);

const USB_DIR_IN: u8 = 0x80;
const USB_REQ_GET_STATUS: u8 = 0;
const USB_REQ_CLEAR_FEATURE: u8 = 1;
const USB_REQ_SET_FEATURE: u8 = 3;
const USB_REQ_GET_DESCRIPTOR: u8 = 6;
const USB_REQ_SET_CONFIGURATION: u8 = 9;
const USB_REQ_SET_PROTOCOL: u8 = 0x0b;
const USB_DT_DEVICE: u16 = 1;
const USB_DT_CONFIG: u16 = 2;
const USB_DT_HUB: u16 = 0x29;
const USB_CLASS_HID: u8 = 3;
const USB_CLASS_HUB: u8 = 9;
const HUB_PORT_RESET: u16 = 4;
const HUB_PORT_POWER: u16 = 8;
const HUB_C_PORT_CONNECTION: u16 = 16;
const HUB_C_PORT_RESET: u16 = 20;
const HUB_POLL_NS: u64 = 100_000_000;

const USB_DEVICE_ID_BASE: u32 = 0x5553_0000; // 'US' namespace

static IRQ_PENDING: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<Option<Controller>> = Mutex::new(None);
static USB_EVENT_SEEN: AtomicBool = AtomicBool::new(false);

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Trb {
    parameter: u64,
    status: u32,
    control: u32,
}

struct Ring {
    base: usize,
    enqueue: usize,
    cycle: bool,
}
impl Ring {
    unsafe fn new() -> Option<Self> {
        let base = phys::alloc_page()?;
        write_bytes(base as *mut u8, 0, 4096);
        let mut r = Self {
            base,
            enqueue: 0,
            cycle: true,
        };
        r.arm_link();
        Some(r)
    }
    unsafe fn arm_link(&mut self) {
        let p = (self.base as *mut Trb).add(LINK_INDEX);
        write_volatile(
            p,
            Trb {
                parameter: self.base as u64,
                status: 0,
                control: trb_type(TRB_LINK) | TRB_TC | if self.cycle { TRB_CYCLE } else { 0 },
            },
        );
    }
    unsafe fn push(&mut self, parameter: u64, status: u32, control: u32) -> usize {
        if self.enqueue >= LINK_INDEX {
            self.enqueue = 0;
            self.cycle = !self.cycle;
            self.arm_link();
        }
        let ptr = (self.base as *mut Trb).add(self.enqueue);
        // Publish cycle last.
        write_volatile(
            ptr,
            Trb {
                parameter,
                status,
                control: control & !TRB_CYCLE,
            },
        );
        core::arch::asm!("dmb oshst", options(nostack));
        write_volatile(
            core::ptr::addr_of_mut!((*ptr).control),
            (control & !TRB_CYCLE) | if self.cycle { TRB_CYCLE } else { 0 },
        );
        let addr = ptr as usize;
        self.enqueue += 1;
        addr
    }
    fn release(self) {
        phys::free_page(self.base);
    }
}

#[derive(Copy, Clone, Debug, Default)]
struct EndpointDesc {
    address: u8,
    max_packet: u16,
    interval: u8,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum HidKind {
    Keyboard,
    Tablet,
    Mouse,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct UsbTopology {
    root_port: u8,
    route: u32,
    depth: u8,
    parent_hub_slot: u8,
    parent_port: u8,
    parent_speed: u8,
}

impl UsbTopology {
    fn root(port: u8) -> Self {
        Self {
            root_port: port,
            ..Self::default()
        }
    }
    fn child(self, hub_slot: u8, hub_speed: u8, port: u8) -> Option<Self> {
        if self.depth >= 5 || port == 0 || port > 15 {
            return None;
        }
        let shift = self.depth as u32 * 4;
        let route = self.route | ((port as u32) << shift);
        Some(Self {
            root_port: self.root_port,
            route,
            depth: self.depth + 1,
            parent_hub_slot: hub_slot,
            parent_port: port,
            parent_speed: hub_speed,
        })
    }
}

struct UsbHub {
    slot: u8,
    topo: UsbTopology,
    speed: u8,
    ep0: Ring,
    device_ctx: usize,
    control_buf: usize,
    ports: u8,
    connected_mask: u32,
}

enum Enumerated {
    Hid(UsbHid),
    Hub(UsbHub),
}

struct UsbHid {
    slot: u8,
    topo: UsbTopology,
    speed: u8,
    device_ctx: usize,
    kind: HidKind,
    dci: u8,
    ring: Ring,
    report: usize,
    report_len: usize,
    prev_keys: [u8; 6],
    prev_mods: u8,
    prev_buttons: u8,
    prev_x: u16,
    prev_y: u16,
}

struct Controller {
    pci_address: crate::pci::PciAddress,
    base: usize,
    op: usize,
    rt: usize,
    db: usize,
    max_slots: u8,
    max_ports: u8,
    ctx_size: usize,
    dcbaa: usize,
    cmd: Ring,
    events: usize,
    event_idx: usize,
    event_cycle: bool,
    erst: usize,
    scratch_array: usize,
    scratch_array_pages: usize,
    scratch_buffers: Vec<usize>,
    irq: u32,
    devices: Vec<UsbHid>,
    hubs: Vec<UsbHub>,
    last_hub_poll_ns: u64,
}
unsafe impl Send for Controller {}

#[inline]
unsafe fn r8(a: usize) -> u8 {
    read_volatile(a as *const u8)
}
#[inline]
unsafe fn r32(a: usize) -> u32 {
    read_volatile(a as *const u32)
}
#[inline]
unsafe fn r64(a: usize) -> u64 {
    read_volatile(a as *const u64)
}
#[inline]
unsafe fn w32(a: usize, v: u32) {
    write_volatile(a as *mut u32, v)
}
#[inline]
unsafe fn w64(a: usize, v: u64) {
    write_volatile(a as *mut u64, v)
}

fn wait_until(mut yes: impl FnMut() -> bool, spins: usize) -> bool {
    for _ in 0..spins {
        if yes() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}
fn zero_page() -> Option<usize> {
    let p = phys::alloc_page()?;
    unsafe { write_bytes(p as *mut u8, 0, 4096) };
    Some(p)
}
fn neutral_port(v: u32) -> u32 {
    (v & PORT_RO) | (v & PORT_RWS)
}

fn controller_required_aperture(
    caplen: usize,
    hcs1: u32,
    dboff: usize,
    rtsoff: usize,
) -> Option<usize> {
    let max_slots = (hcs1 & 0xff) as usize;
    let max_ports = ((hcs1 >> 24) & 0xff) as usize;
    // Operational registers through the last PORTSC, doorbells through slot N,
    // and Runtime Interrupter 0 through ERDP. Conservatively round each region
    // upward inside the actual PCI BAR instead of assuming a 16KiB aperture.
    let op_end = caplen
        .checked_add(0x400)?
        .checked_add(max_ports.checked_mul(0x10)?)?;
    let db_end = dboff.checked_add((max_slots + 1).checked_mul(4)?)?;
    let rt_end = rtsoff.checked_add(0x40)?;
    Some(op_end.max(db_end).max(rt_end).max(0x20))
}

impl Controller {
    unsafe fn create(dev: &PciDevice) -> Option<Self> {
        let bar0 = dev.bar(0)?;
        let bar_len = usize::try_from(bar0.size).ok()?;
        if !(0x20..=0x10_0000).contains(&bar_len) {
            crate::warn!("xhci: BAR0 size unsupported len={:#x}", bar_len);
            return None;
        }
        let base = crate::pci::bar_mmio_ptr(dev, 0, 0, bar_len)?;
        let command = crate::pci::read_u16(dev.address, 0x04)?;
        crate::pci::write_u16(dev.address, 0x04, command | 0x2 | 0x4);
        let caplen = r8(base) as usize;
        if caplen < 0x20 {
            return None;
        }
        let hcs1 = r32(base + 0x04);
        let hcs2 = r32(base + 0x08);
        let hcc1 = r32(base + 0x10);
        let dboff = (r32(base + 0x14) & !3) as usize;
        let rtsoff = (r32(base + 0x18) & !0x1f) as usize;
        let max_slots = (hcs1 & 0xff) as u8;
        let max_ports = ((hcs1 >> 24) & 0xff) as u8;
        let required = controller_required_aperture(caplen, hcs1, dboff, rtsoff)?;
        if required > bar_len {
            crate::warn!(
                "xhci: BAR0 aperture too small len={:#x} required={:#x} caplen={:#x} dboff={:#x} rtsoff={:#x} slots={} ports={}",
                bar_len, required, caplen, dboff, rtsoff, max_slots, max_ports
            );
            return None;
        }
        let ctx_size = if hcc1 & (1 << 2) != 0 { 64 } else { 32 };
        let scratch_lo = (hcs2 >> 27) & 0x1f;
        let scratch_hi = (hcs2 >> 16) & 0x3e0;
        let scratchpads = scratch_lo | scratch_hi;
        crate::info!(
            "xhci: PCI {:04x}:{:02x}:{:02x}.{} base={:#x} bar_len={:#x} required={:#x} caplen={:#x} slots={} ports={} ctx={} scratch={}",
            dev.address.segment, dev.address.bus, dev.address.device, dev.address.function,
            base, bar_len, required, caplen, max_slots, max_ports, ctx_size, scratchpads
        );
        let op = base + caplen;
        let rt = base + rtsoff;
        let db = base + dboff;
        // Stop -> reset -> ready.
        let mut cmdv = r32(op);
        cmdv &= !1;
        w32(op, cmdv);
        if !wait_until(|| r32(op + 4) & 1 != 0, 2_000_000) {
            crate::warn!("xhci: halt timeout");
            return None;
        }
        w32(op, r32(op) | (1 << 1));
        if !wait_until(|| r32(op) & (1 << 1) == 0, 4_000_000) {
            crate::warn!("xhci: reset timeout");
            return None;
        }
        if !wait_until(|| r32(op + 4) & (1 << 11) == 0, 4_000_000) {
            crate::warn!("xhci: CNR timeout");
            return None;
        }

        let dcbaa = zero_page()?;
        // Scratchpad Buffer Array lives in DCBAA[0].  xHCI uses one controller
        // page per scratchpad; QEMU normally advertises zero, but real controllers
        // commonly require several and must not be rejected.
        let mut scratch_array = 0usize;
        let mut scratch_array_pages = 0usize;
        let mut scratch_buffers = Vec::new();
        if scratchpads != 0 {
            let count = scratchpads as usize;
            let array_pages = (count * 8).div_ceil(4096);
            scratch_array_pages = array_pages;
            scratch_array = phys::alloc_pages_contiguous(array_pages)?;
            write_bytes(scratch_array as *mut u8, 0, array_pages * 4096);
            for i in 0..count {
                let page = zero_page()?;
                write_volatile((scratch_array as *mut u64).add(i), page as u64);
                scratch_buffers.push(page);
            }
            w64(dcbaa, scratch_array as u64);
            crate::info!(
                "xhci: scratchpad array online count={} pages={} base={:#x}",
                count,
                array_pages,
                scratch_array
            );
        }
        let cmd = Ring::new()?;
        let events = zero_page()?;
        let erst = zero_page()?;
        // one ERST entry: base, TRB count, reserved
        w64(erst, events as u64);
        w32(erst + 8, TRBS as u32);
        w32(erst + 12, 0);
        w64(op + 0x30, dcbaa as u64);
        w64(op + 0x18, cmd.base as u64 | 1);
        w32(op + 0x38, max_slots.min(32) as u32);
        let ir0 = rt + 0x20;
        w32(ir0 + 8, 1); // ERSTSZ
        w64(ir0 + 0x10, erst as u64);
        w64(ir0 + 0x18, events as u64);
        w32(ir0 + 4, 0); // no moderation for bring-up
        w32(ir0, 0x2); // IE=1, IP=0
        core::arch::asm!("dsb oshst", options(nostack));
        w32(op, 1 | (1 << 2)); // RUN + INTE
        if !wait_until(|| r32(op + 4) & 1 == 0, 2_000_000) {
            crate::warn!("xhci: run timeout status={:#x}", r32(op + 4));
            return None;
        }
        let irq = crate::pci::configure_msix(dev, 0).unwrap_or(0);
        Some(Self {
            pci_address: dev.address,
            base,
            op,
            rt,
            db,
            max_slots,
            max_ports,
            ctx_size,
            dcbaa,
            cmd,
            events,
            event_idx: 0,
            event_cycle: true,
            erst,
            scratch_array,
            scratch_array_pages,
            scratch_buffers,
            irq,
            devices: Vec::new(),
            hubs: Vec::new(),
            last_hub_poll_ns: 0,
        })
    }

    unsafe fn event_pop(&mut self) -> Option<Trb> {
        let p = (self.events as *const Trb).add(self.event_idx);
        let t = read_volatile(p);
        if (t.control & TRB_CYCLE != 0) != self.event_cycle {
            return None;
        }
        self.event_idx += 1;
        if self.event_idx == TRBS {
            self.event_idx = 0;
            self.event_cycle = !self.event_cycle;
        }
        let next = self.events + self.event_idx * core::mem::size_of::<Trb>();
        w64(self.rt + 0x20 + 0x18, next as u64 | (1 << 3)); // ERDP + EHB
                                                            // Clear interrupter pending and USBSTS.EINT/PCD.
        let iman = r32(self.rt + 0x20);
        w32(self.rt + 0x20, iman | 1 | 2);
        let st = r32(self.op + 4);
        w32(self.op + 4, st & ((1 << 3) | (1 << 4)));
        Some(t)
    }
    unsafe fn wait_event(&mut self, expected: u32, slot: Option<u8>) -> Option<Trb> {
        for _ in 0..20_000_000usize {
            if let Some(t) = self.event_pop() {
                let ty = (t.control >> 10) & 0x3f;
                if ty == TRB_PORT_STATUS {
                    continue;
                }
                if ty == expected && slot.map(|s| (t.control >> 24) as u8 == s).unwrap_or(true) {
                    return Some(t);
                }
            }
            core::hint::spin_loop();
        }
        None
    }
    unsafe fn command(&mut self, parameter: u64, control: u32) -> Option<Trb> {
        let ptr = self.cmd.push(parameter, 0, control);
        core::arch::asm!("dsb oshst", options(nostack));
        w32(self.db, 0);
        let e = self.wait_event(TRB_COMPLETION, None)?;
        let code = e.status >> 24;
        if code != 1 {
            crate::warn!(
                "xhci: command type={} failed code={} event={:#x}",
                (control >> 10) & 0x3f,
                code,
                e.control
            );
            return None;
        }
        // Command completion should point back at the submitted command.
        if (e.parameter as usize & !0xf) != (ptr & !0xf) {
            crate::debug!(
                "xhci: completion ptr mismatch expected={:#x} got={:#x}",
                ptr,
                e.parameter
            );
        }
        Some(e)
    }
    unsafe fn reset_port(&mut self, port: u8) -> Option<u8> {
        let a = self.op + 0x400 + (port as usize - 1) * 0x10;
        let before = r32(a);
        if before & PORT_CONNECT == 0 {
            return None;
        }
        if before & PORT_POWER == 0 {
            w32(a, neutral_port(before) | PORT_POWER | PORT_CHANGE);
        }
        let powered = r32(a);
        let speed0 = ((powered >> 10) & 0xf) as u8;
        if speed0 <= 3 {
            w32(a, neutral_port(powered) | PORT_RESET | PORT_CHANGE);
            if !wait_until(|| r32(a) & PORT_RESET == 0, 4_000_000) {
                crate::warn!("xhci: port{} reset timeout sc={:#x}", port, r32(a));
                return None;
            }
        }
        let after = r32(a);
        // Clear accumulated change bits while preserving stable RW state.
        w32(a, neutral_port(after) | (after & PORT_CHANGE));
        if after & PORT_PE == 0 {
            crate::warn!("xhci: port{} not enabled sc={:#x}", port, after);
            return None;
        }
        let speed = ((after >> 10) & 0xf) as u8;
        crate::info!(
            "xhci: port{} connected speed={} sc={:#x}",
            port,
            speed,
            after
        );
        Some(speed)
    }
    fn ep0_mps(speed: u8) -> u16 {
        match speed {
            2 => 8,
            4 | 5 => 512,
            _ => 64,
        }
    }
    unsafe fn enumerate_device(&mut self, topo: UsbTopology, speed: u8) -> Option<Enumerated> {
        let e = self.command(0, trb_type(TRB_ENABLE_SLOT))?;
        let slot = (e.control >> 24) as u8;
        if slot == 0 || slot > self.max_slots {
            return None;
        }
        let device_ctx = zero_page()?;
        let input_ctx = zero_page()?;
        let mut ep0 = Ring::new()?;
        w64(self.dcbaa + slot as usize * 8, device_ctx as u64);
        let cs = self.ctx_size;
        w32(input_ctx + 4, 0x3);
        let slot_ctx = input_ctx + cs;
        w32(
            slot_ctx,
            (topo.route & 0x000f_ffff) | (speed as u32) << 20 | 1 << 27,
        );
        w32(slot_ctx + 4, (topo.root_port as u32) << 16);
        if topo.parent_hub_slot != 0 && speed <= 2 && topo.parent_speed == 3 {
            // Low/full-speed device behind a high-speed USB2 hub: identify TT.
            w32(
                slot_ctx + 8,
                topo.parent_hub_slot as u32 | ((topo.parent_port as u32) << 8),
            );
        }
        let ep0ctx = input_ctx + 2 * cs;
        w32(
            ep0ctx + 4,
            (4 << 3) | (3 << 1) | ((Self::ep0_mps(speed) as u32) << 16),
        );
        w64(ep0ctx + 8, ep0.base as u64 | 1);
        w32(ep0ctx + 16, 8);
        core::arch::asm!("dsb oshst", options(nostack));
        if self
            .command(
                input_ctx as u64,
                trb_type(TRB_ADDR_DEV) | ((slot as u32) << 24),
            )
            .is_none()
        {
            phys::free_page(input_ctx);
            phys::free_page(device_ctx);
            ep0.release();
            return None;
        }

        let data = zero_page()?;
        self.control_in(
            slot,
            &mut ep0,
            0x80,
            USB_REQ_GET_DESCRIPTOR,
            USB_DT_DEVICE << 8,
            0,
            18,
            data,
        )?;
        let devdesc = core::slice::from_raw_parts(data as *const u8, 18);
        let vid = u16::from_le_bytes([devdesc[8], devdesc[9]]);
        let pid = u16::from_le_bytes([devdesc[10], devdesc[11]]);
        let device_class = devdesc[4];
        self.control_in(
            slot,
            &mut ep0,
            0x80,
            USB_REQ_GET_DESCRIPTOR,
            USB_DT_CONFIG << 8,
            0,
            9,
            data,
        )?;
        let cfg9 = core::slice::from_raw_parts(data as *const u8, 9);
        let total = u16::from_le_bytes([cfg9[2], cfg9[3]]) as usize;
        if total < 9 || total > 4096 {
            phys::free_page(data);
            phys::free_page(input_ctx);
            return None;
        }
        let cfg_value = cfg9[5];
        self.control_in(
            slot,
            &mut ep0,
            0x80,
            USB_REQ_GET_DESCRIPTOR,
            USB_DT_CONFIG << 8,
            0,
            total as u16,
            data,
        )?;
        let cfg = core::slice::from_raw_parts(data as *const u8, total);
        let hid_desc = parse_hid_config(cfg);
        let is_hub =
            device_class == USB_CLASS_HUB || config_has_interface_class(cfg, USB_CLASS_HUB);
        self.control_no_data(
            slot,
            &mut ep0,
            0x00,
            USB_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
        )?;

        if let Some((kind, ep)) = hid_desc {
            crate::info!(
                "usb: slot{} root{} route={:#x} {:04x}:{:04x} HID={:?} ep={:#x} mps={} interval={}",
                slot,
                topo.root_port,
                topo.route,
                vid,
                pid,
                kind,
                ep.address,
                ep.max_packet,
                ep.interval
            );
            if matches!(kind, HidKind::Keyboard | HidKind::Mouse) {
                let _ = self.control_no_data(slot, &mut ep0, 0x21, USB_REQ_SET_PROTOCOL, 0, 0);
            }
            let dci = endpoint_dci(ep.address)?;
            let intr = Ring::new()?;
            write_bytes(input_ctx as *mut u8, 0, 4096);
            core::ptr::copy_nonoverlapping(
                device_ctx as *const u8,
                (input_ctx + cs) as *mut u8,
                cs,
            );
            w32(input_ctx + 4, 1 | (1u32 << dci));
            let sc = input_ctx + cs;
            let w0 = r32(sc);
            w32(sc, (w0 & !(0x1f << 27)) | ((dci as u32) << 27));
            let ec = input_ctx + (dci as usize + 1) * cs;
            let interval = xhci_interval(speed, ep.interval);
            w32(ec, (interval as u32) << 16);
            w32(ec + 4, (7 << 3) | (3 << 1) | ((ep.max_packet as u32) << 16));
            w64(ec + 8, intr.base as u64 | 1);
            w32(
                ec + 16,
                (ep.max_packet as u32) | ((ep.max_packet as u32) << 16),
            );
            core::arch::asm!("dsb oshst", options(nostack));
            self.command(
                input_ctx as u64,
                trb_type(TRB_CONFIG_EP) | ((slot as u32) << 24),
            )?;
            let report = zero_page()?;
            let mut hid = UsbHid {
                slot,
                topo,
                speed,
                device_ctx,
                kind,
                dci,
                ring: intr,
                report,
                report_len: ep.max_packet.min(64) as usize,
                prev_keys: [0; 6],
                prev_mods: 0,
                prev_buttons: 0,
                prev_x: 0,
                prev_y: 0,
            };
            queue_interrupt(self.db, &mut hid);
            phys::free_page(data);
            phys::free_page(input_ctx);
            ep0.release();
            crate::info!(
                "usb: HID {:?} READY slot={} root={} route={:#x} dci={}",
                kind,
                slot,
                topo.root_port,
                topo.route,
                dci
            );
            return Some(Enumerated::Hid(hid));
        }

        if is_hub {
            // USB2 hub descriptor: first 3 bytes include bNbrPorts.
            if self
                .control_in(
                    slot,
                    &mut ep0,
                    0xa0,
                    USB_REQ_GET_DESCRIPTOR,
                    USB_DT_HUB << 8,
                    0,
                    9,
                    data,
                )
                .is_none()
            {
                crate::warn!("usb: hub slot{} descriptor failed", slot);
                phys::free_page(data);
                phys::free_page(input_ctx);
                return None;
            }
            let ports = read_volatile((data + 2) as *const u8).min(15);
            if ports == 0 {
                phys::free_page(data);
                phys::free_page(input_ctx);
                return None;
            }
            // Update output Slot Context with Hub + Number of Ports via Evaluate Context.
            write_bytes(input_ctx as *mut u8, 0, 4096);
            w32(input_ctx + 4, 1); // Add Slot Context only.
            core::ptr::copy_nonoverlapping(
                device_ctx as *const u8,
                (input_ctx + cs) as *mut u8,
                cs,
            );
            let sc = input_ctx + cs;
            w32(sc, r32(sc) | (1 << 26));
            w32(sc + 4, (r32(sc + 4) & 0x00ff_ffff) | ((ports as u32) << 24));
            self.command(
                input_ctx as u64,
                trb_type(TRB_EVAL_CTX) | ((slot as u32) << 24),
            )?;
            phys::free_page(input_ctx);
            crate::info!(
                "usb: HUB READY slot={} root={} route={:#x} ports={} speed={}",
                slot,
                topo.root_port,
                topo.route,
                ports,
                speed
            );
            return Some(Enumerated::Hub(UsbHub {
                slot,
                topo,
                speed,
                ep0,
                device_ctx,
                control_buf: data,
                ports,
                connected_mask: 0,
            }));
        }

        crate::info!(
            "usb: slot{} {:04x}:{:04x} unsupported class={} (disable)",
            slot,
            vid,
            pid,
            device_class
        );
        let _ = self.disable_slot(slot);
        phys::free_page(data);
        phys::free_page(input_ctx);
        phys::free_page(device_ctx);
        ep0.release();
        None
    }

    unsafe fn disable_slot(&mut self, slot: u8) -> bool {
        if slot == 0 {
            return false;
        }
        self.command(0, trb_type(TRB_DISABLE_SLOT) | ((slot as u32) << 24))
            .is_some()
    }

    unsafe fn register_enumerated(&mut self, dev: Enumerated) {
        match dev {
            Enumerated::Hid(h) => self.devices.push(h),
            Enumerated::Hub(mut h) => {
                self.scan_hub_ports(&mut h, true);
                self.hubs.push(h);
            }
        }
    }

    unsafe fn hub_status(&mut self, h: &mut UsbHub, port: u8) -> Option<u32> {
        self.control_in(
            h.slot,
            &mut h.ep0,
            0xa3,
            USB_REQ_GET_STATUS,
            0,
            port as u16,
            4,
            h.control_buf,
        )?;
        Some(u32::from_le(read_volatile(h.control_buf as *const u32)))
    }
    fn hub_speed(status: u32) -> u8 {
        if status & (1 << 10) != 0 {
            3
        } else if status & (1 << 9) != 0 {
            2
        } else {
            1
        }
    }

    unsafe fn reset_hub_port(&mut self, h: &mut UsbHub, port: u8) -> Option<u8> {
        let _ = self.control_no_data(
            h.slot,
            &mut h.ep0,
            0x23,
            USB_REQ_SET_FEATURE,
            HUB_PORT_POWER,
            port as u16,
        );
        self.control_no_data(
            h.slot,
            &mut h.ep0,
            0x23,
            USB_REQ_SET_FEATURE,
            HUB_PORT_RESET,
            port as u16,
        )?;
        for _ in 0..256 {
            let st = self.hub_status(h, port)?;
            if st & (1 << 4) == 0 && st & (1 << 1) != 0 {
                let _ = self.control_no_data(
                    h.slot,
                    &mut h.ep0,
                    0x23,
                    USB_REQ_CLEAR_FEATURE,
                    HUB_C_PORT_RESET,
                    port as u16,
                );
                return Some(Self::hub_speed(st));
            }
            for _ in 0..20_000 {
                core::hint::spin_loop();
            }
        }
        crate::warn!("usb: hub slot{} port{} reset timeout", h.slot, port);
        None
    }

    unsafe fn scan_hub_ports(&mut self, h: &mut UsbHub, initial: bool) {
        for port in 1..=h.ports {
            let Some(st) = self.hub_status(h, port) else {
                continue;
            };
            let connected = st & 1 != 0;
            let bit = 1u32 << (port - 1);
            let was = h.connected_mask & bit != 0;
            if connected && (!was || initial) {
                // Ack the connection-change latch before reset. Hotplug devices
                // can appear before their emulated/physical port has settled;
                // a failed first reset/enumeration must *not* mark the port as
                // consumed, otherwise reconnect becomes a permanent one-shot
                // failure. Leave connected_mask clear and retry next poll.
                let _ = self.control_no_data(
                    h.slot,
                    &mut h.ep0,
                    0x23,
                    USB_REQ_CLEAR_FEATURE,
                    HUB_C_PORT_CONNECTION,
                    port as u16,
                );
                let mut enumerated = false;
                if let Some(speed) = self.reset_hub_port(h, port) {
                    if let Some(topo) = h.topo.child(h.slot, h.speed, port) {
                        if let Some(dev) = self.enumerate_device(topo, speed) {
                            self.register_enumerated(dev);
                            enumerated = true;
                        }
                    }
                }
                if enumerated {
                    h.connected_mask |= bit;
                    if !initial {
                        crate::info!("usb: HOTPLUG connect hub_slot={} port={}", h.slot, port);
                    }
                } else {
                    h.connected_mask &= !bit;
                    if !initial {
                        crate::debug!("usb: hub reconnect retry slot={} port={}", h.slot, port);
                    }
                }
            } else if !connected && was {
                crate::info!("usb: HOTPLUG disconnect hub_slot={} port={}", h.slot, port);
                self.remove_descendants(h.slot, port);
                h.connected_mask &= !bit;
                let _ = self.control_no_data(
                    h.slot,
                    &mut h.ep0,
                    0x23,
                    USB_REQ_CLEAR_FEATURE,
                    HUB_C_PORT_CONNECTION,
                    port as u16,
                );
            }
        }
    }

    unsafe fn remove_descendants(&mut self, parent_slot: u8, parent_port: u8) {
        let mut slots: Vec<u8> = Vec::new();
        for d in &self.devices {
            if d.topo.parent_hub_slot == parent_slot && d.topo.parent_port == parent_port {
                slots.push(d.slot);
            }
        }
        for h in &self.hubs {
            if h.topo.parent_hub_slot == parent_slot && h.topo.parent_port == parent_port {
                slots.push(h.slot);
            }
        }
        let mut i = 0;
        while i < slots.len() {
            let p = slots[i];
            for d in &self.devices {
                if d.topo.parent_hub_slot == p && !slots.contains(&d.slot) {
                    slots.push(d.slot);
                }
            }
            for h in &self.hubs {
                if h.topo.parent_hub_slot == p && !slots.contains(&h.slot) {
                    slots.push(h.slot);
                }
            }
            i += 1;
        }
        for &slot in slots.iter().rev() {
            let _ = self.disable_slot(slot);
        }
        let mut i = 0;
        while i < self.devices.len() {
            if slots.contains(&self.devices[i].slot) {
                let d = self.devices.remove(i);
                d.ring.release();
                phys::free_page(d.report);
                phys::free_page(d.device_ctx);
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < self.hubs.len() {
            if slots.contains(&self.hubs[i].slot) {
                let h = self.hubs.remove(i);
                h.ep0.release();
                phys::free_page(h.control_buf);
                phys::free_page(h.device_ctx);
            } else {
                i += 1;
            }
        }
    }

    unsafe fn remove_root(&mut self, port: u8) {
        let slots: Vec<u8> = self
            .devices
            .iter()
            .filter(|d| d.topo.root_port == port)
            .map(|d| d.slot)
            .chain(
                self.hubs
                    .iter()
                    .filter(|h| h.topo.root_port == port)
                    .map(|h| h.slot),
            )
            .collect();
        for &slot in slots.iter().rev() {
            let _ = self.disable_slot(slot);
        }
        let mut i = 0;
        while i < self.devices.len() {
            if self.devices[i].topo.root_port == port {
                let d = self.devices.remove(i);
                d.ring.release();
                phys::free_page(d.report);
                phys::free_page(d.device_ctx);
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < self.hubs.len() {
            if self.hubs[i].topo.root_port == port {
                let h = self.hubs.remove(i);
                h.ep0.release();
                phys::free_page(h.control_buf);
                phys::free_page(h.device_ctx);
            } else {
                i += 1;
            }
        }
    }

    unsafe fn rescan_root_port(&mut self, port: u8) {
        if port == 0 || port > self.max_ports {
            return;
        }
        let a = self.op + 0x400 + (port as usize - 1) * 0x10;
        let sc = r32(a);
        let connected = sc & PORT_CONNECT != 0;
        let present = self
            .devices
            .iter()
            .any(|d| d.topo.root_port == port && d.topo.parent_hub_slot == 0)
            || self
                .hubs
                .iter()
                .any(|h| h.topo.root_port == port && h.topo.parent_hub_slot == 0);
        if !connected && present {
            crate::info!("usb: HOTPLUG disconnect root_port={}", port);
            self.remove_root(port);
        } else if connected && !present {
            crate::info!("usb: HOTPLUG connect root_port={}", port);
            if let Some(speed) = self.reset_port(port) {
                if let Some(dev) = self.enumerate_device(UsbTopology::root(port), speed) {
                    self.register_enumerated(dev);
                }
            }
        }
        w32(a, neutral_port(r32(a)) | (r32(a) & PORT_CHANGE));
    }

    unsafe fn poll_hubs(&mut self) {
        let now = crate::time::monotonic_ns();
        if now.saturating_sub(self.last_hub_poll_ns) < HUB_POLL_NS {
            return;
        }
        self.last_hub_poll_ns = now;
        let count = self.hubs.len();
        for _ in 0..count {
            if self.hubs.is_empty() {
                break;
            }
            let mut h = self.hubs.remove(0);
            self.scan_hub_ports(&mut h, false);
            self.hubs.push(h);
        }
    }

    unsafe fn control_in(
        &mut self,
        slot: u8,
        ring: &mut Ring,
        bm: u8,
        req: u8,
        value: u16,
        index: u16,
        len: u16,
        data: usize,
    ) -> Option<()> {
        write_bytes(data as *mut u8, 0, len as usize);
        let setup = (bm as u64)
            | ((req as u64) << 8)
            | ((value as u64) << 16)
            | ((index as u64) << 32)
            | ((len as u64) << 48);
        ring.push(setup, 8, trb_type(TRB_SETUP) | TRB_IDT | (3 << 16));
        ring.push(
            data as u64,
            len as u32,
            trb_type(TRB_DATA) | TRB_DIR_IN | TRB_ISP,
        );
        ring.push(0, 0, trb_type(TRB_STATUS) | TRB_IOC); // status OUT
        core::arch::asm!("dsb oshst", options(nostack));
        w32(self.db + slot as usize * 4, 1);
        let e = self.wait_event(TRB_TRANSFER, Some(slot))?;
        let code = e.status >> 24;
        if code != 1 && code != 13 {
            crate::warn!("xhci: control IN fail slot={} code={}", slot, code);
            return None;
        }
        Some(())
    }
    unsafe fn control_no_data(
        &mut self,
        slot: u8,
        ring: &mut Ring,
        bm: u8,
        req: u8,
        value: u16,
        index: u16,
    ) -> Option<()> {
        let setup =
            (bm as u64) | ((req as u64) << 8) | ((value as u64) << 16) | ((index as u64) << 32);
        ring.push(setup, 8, trb_type(TRB_SETUP) | TRB_IDT);
        ring.push(0, 0, trb_type(TRB_STATUS) | TRB_IOC | TRB_DIR_IN);
        core::arch::asm!("dsb oshst", options(nostack));
        w32(self.db + slot as usize * 4, 1);
        let e = self.wait_event(TRB_TRANSFER, Some(slot))?;
        if e.status >> 24 != 1 {
            return None;
        }
        Some(())
    }

    unsafe fn poll_runtime(&mut self) -> bool {
        if r32(self.op + 4) & (1 << 2) != 0 {
            crate::error!("xhci: Host System Error status={:#x}", r32(self.op + 4));
            return false;
        }
        // A device/hypervisor is allowed to complete interrupt transfers very
        // aggressively. Never let one InputRead syscall become an unbounded
        // producer/consumer loop (completion -> requeue -> immediate completion).
        // A bounded batch also gives userland a chance to sleep/yield between
        // empty-report storms while preserving low latency for real bursts.
        const MAX_EVENTS_PER_POLL: usize = 128;
        let mut processed = 0usize;
        while processed < MAX_EVENTS_PER_POLL {
            let Some(e) = self.event_pop() else { break };
            processed += 1;
            let ty = (e.control >> 10) & 0x3f;
            match ty {
                TRB_TRANSFER => {
                    let slot = (e.control >> 24) as u8;
                    let ep = ((e.control >> 16) & 0x1f) as u8;
                    if let Some(i) = self
                        .devices
                        .iter()
                        .position(|d| d.slot == slot && d.dci == ep)
                    {
                        let code = e.status >> 24;
                        let residual = (e.status & 0x00ff_ffff) as usize;
                        let requested = self.devices[i].report_len;
                        if code == 1 || code == 13 {
                            let n = requested.saturating_sub(residual).min(64);
                            consume_hid_report(&mut self.devices[i], n);
                        }
                        queue_interrupt(self.db, &mut self.devices[i]);
                    }
                }
                TRB_PORT_STATUS => {
                    let port = ((e.parameter >> 24) & 0xff) as u8;
                    self.rescan_root_port(port);
                }
                _ => {}
            }
        }
        if processed == MAX_EVENTS_PER_POLL {
            crate::debug!("xhci: runtime event budget exhausted; deferring remaining events");
        }
        self.poll_hubs();
        true
    }

    unsafe fn release(mut self) {
        let slots: Vec<u8> = self
            .devices
            .iter()
            .map(|d| d.slot)
            .chain(self.hubs.iter().map(|h| h.slot))
            .collect();
        for &slot in slots.iter().rev() {
            let _ = self.disable_slot(slot);
        }
        for d in self.devices.drain(..) {
            d.ring.release();
            phys::free_page(d.report);
            phys::free_page(d.device_ctx);
        }
        for h in self.hubs.drain(..) {
            h.ep0.release();
            phys::free_page(h.control_buf);
            phys::free_page(h.device_ctx);
        }
        self.cmd.release();
        phys::free_page(self.events);
        phys::free_page(self.erst);
        phys::free_page(self.dcbaa);
        if self.scratch_array != 0 {
            for p in self.scratch_buffers.drain(..) {
                phys::free_page(p);
            }
            for i in 0..self.scratch_array_pages {
                phys::free_page(self.scratch_array + i * 4096);
            }
        }
    }
}

fn config_has_interface_class(cfg: &[u8], class: u8) -> bool {
    let mut off = 0;
    while off + 2 <= cfg.len() {
        let n = cfg[off] as usize;
        if n < 2 || off + n > cfg.len() {
            break;
        }
        if cfg[off + 1] == 4 && n >= 9 && cfg[off + 5] == class {
            return true;
        }
        off += n;
    }
    false
}

fn parse_hid_config(cfg: &[u8]) -> Option<(HidKind, EndpointDesc)> {
    let mut off = 0usize;
    let mut hid: Option<HidKind> = None;
    while off + 2 <= cfg.len() {
        let len = cfg[off] as usize;
        let ty = cfg[off + 1];
        if len < 2 || off + len > cfg.len() {
            break;
        }
        if ty == 4 && len >= 9 && cfg[off + 5] == USB_CLASS_HID {
            hid = Some(match cfg[off + 7] {
                1 => HidKind::Keyboard,
                2 => HidKind::Mouse,
                _ => HidKind::Tablet,
            });
        } else if ty == 5 && len >= 7 && hid.is_some() {
            let addr = cfg[off + 2];
            let attrs = cfg[off + 3] & 3;
            if addr & USB_DIR_IN != 0 && attrs == 3 {
                let mps = u16::from_le_bytes([cfg[off + 4], cfg[off + 5]]) & 0x7ff;
                return Some((
                    hid.unwrap(),
                    EndpointDesc {
                        address: addr,
                        max_packet: mps,
                        interval: cfg[off + 6],
                    },
                ));
            }
        }
        off += len;
    }
    None
}
fn endpoint_dci(addr: u8) -> Option<u8> {
    let ep = addr & 0x0f;
    if ep == 0 {
        return None;
    }
    Some(ep * 2 + if addr & 0x80 != 0 { 1 } else { 0 })
}
fn xhci_interval(speed: u8, b: u8) -> u8 {
    if speed >= 3 {
        b.clamp(1, 16) - 1
    } else {
        let mut v = (b.max(1) as u16) * 8;
        let mut n = 0u8;
        while v > 1 {
            v >>= 1;
            n += 1;
        }
        n.clamp(3, 10)
    }
}
unsafe fn queue_interrupt(db: usize, d: &mut UsbHid) {
    write_bytes(d.report as *mut u8, 0, d.report_len);
    d.ring.push(
        d.report as u64,
        d.report_len as u32,
        trb_type(TRB_NORMAL) | TRB_IOC | TRB_ISP,
    );
    core::arch::asm!("dsb oshst", options(nostack));
    w32(db + d.slot as usize * 4, d.dci as u32);
}

fn emit(kind: u16, code: u16, value: i32, device: u32) {
    if !USB_EVENT_SEEN.swap(true, Ordering::AcqRel) {
        crate::info!(
            "xhci: INPUT EVENT PATH PASS device={:#x} kind={} code={} value={}",
            device,
            kind,
            code,
            value
        );
    }
    crate::drivers::virtio::input::inject(InputEvent {
        kind,
        code,
        value,
        modifiers: 0,
        device_id: device,
        timestamp: crate::time::monotonic_ns(),
    });
}
fn usage_to_linux(u: u8) -> Option<u16> {
    // USB HID usage -> Linux input KEY_* codes for the common keyboard set.
    Some(match u {
        0x04 => 30,
        0x05 => 48,
        0x06 => 46,
        0x07 => 32,
        0x08 => 18,
        0x09 => 33,
        0x0a => 34,
        0x0b => 35,
        0x0c => 23,
        0x0d => 36,
        0x0e => 37,
        0x0f => 38,
        0x10 => 50,
        0x11 => 49,
        0x12 => 24,
        0x13 => 25,
        0x14 => 16,
        0x15 => 19,
        0x16 => 31,
        0x17 => 20,
        0x18 => 22,
        0x19 => 47,
        0x1a => 17,
        0x1b => 45,
        0x1c => 21,
        0x1d => 44,
        0x1e => 2,
        0x1f => 3,
        0x20 => 4,
        0x21 => 5,
        0x22 => 6,
        0x23 => 7,
        0x24 => 8,
        0x25 => 9,
        0x26 => 10,
        0x27 => 11,
        0x28 => 28,
        0x29 => 1,
        0x2a => 14,
        0x2b => 15,
        0x2c => 57,
        0x2d => 12,
        0x2e => 13,
        0x2f => 26,
        0x30 => 27,
        0x31 => 43,
        0x33 => 39,
        0x34 => 40,
        0x35 => 41,
        0x36 => 51,
        0x37 => 52,
        0x38 => 53,
        0x39 => 58,
        _ => return None,
    })
}
fn modifier_linux(bit: usize) -> u16 {
    [29, 42, 56, 125, 97, 54, 100, 126][bit]
}
fn consume_hid_report(d: &mut UsbHid, n: usize) {
    if n == 0 {
        return;
    }
    let b = unsafe { core::slice::from_raw_parts(d.report as *const u8, n) };
    let dev = USB_DEVICE_ID_BASE | d.slot as u32;
    match d.kind {
        HidKind::Keyboard if n >= 8 => {
            let mods = b[0];
            for bit in 0..8 {
                let mask = 1u8 << bit;
                if (mods & mask) != (d.prev_mods & mask) {
                    emit(
                        KIND_KEY,
                        modifier_linux(bit),
                        if mods & mask != 0 { 1 } else { 0 },
                        dev,
                    );
                }
            }
            let mut now = [0u8; 6];
            now.copy_from_slice(&b[2..8]);
            for &old in &d.prev_keys {
                if old != 0 && !now.contains(&old) {
                    if let Some(k) = usage_to_linux(old) {
                        emit(KIND_KEY, k, 0, dev);
                    }
                }
            }
            for &key in &now {
                if key != 0 && !d.prev_keys.contains(&key) {
                    if let Some(k) = usage_to_linux(key) {
                        emit(KIND_KEY, k, 1, dev);
                    }
                }
            }
            d.prev_keys = now;
            d.prev_mods = mods;
            crate::debug!(
                "usb-hid: keyboard report slot={} mods={:#x} keys={:02x?}",
                d.slot,
                mods,
                now
            );
        }
        HidKind::Tablet if n >= 6 => {
            let buttons = b[0];
            let x = u16::from_le_bytes([b[1], b[2]]);
            let y = u16::from_le_bytes([b[3], b[4]]);
            let wheel = b[5] as i8;
            if x != d.prev_x {
                emit(KIND_ABS, 0, x as i32, dev);
            }
            if y != d.prev_y {
                emit(KIND_ABS, 1, y as i32, dev);
            }
            for bit in 0..5 {
                let m = 1u8 << bit;
                if buttons & m != d.prev_buttons & m {
                    emit(
                        KIND_BUTTON,
                        0x110 + bit as u16,
                        if buttons & m != 0 { 1 } else { 0 },
                        dev,
                    );
                }
            }
            if wheel != 0 {
                emit(KIND_WHEEL, 8, wheel as i32, dev);
            }
            d.prev_x = x;
            d.prev_y = y;
            d.prev_buttons = buttons;
            crate::info!(
                "usb-hid: tablet report slot={} x={} y={} buttons={:#x}",
                d.slot,
                x,
                y,
                buttons
            );
        }
        HidKind::Mouse if n >= 3 => {
            let buttons = b[0];
            let dx = b[1] as i8 as i32;
            let dy = b[2] as i8 as i32;
            let wheel = if n >= 4 { b[3] as i8 as i32 } else { 0 };
            if dx != 0 {
                emit(KIND_REL, 0, dx, dev);
            }
            if dy != 0 {
                emit(KIND_REL, 1, dy, dev);
            }
            for bit in 0..5 {
                let m = 1u8 << bit;
                if buttons & m != d.prev_buttons & m {
                    emit(
                        KIND_BUTTON,
                        0x110 + bit as u16,
                        if buttons & m != 0 { 1 } else { 0 },
                        dev,
                    );
                }
            }
            if wheel != 0 {
                emit(KIND_WHEEL, 8, wheel, dev);
            }
            d.prev_buttons = buttons;
        }
        _ => {}
    }
}

fn irq_handler(_irq: u32) {
    IRQ_PENDING.store(true, Ordering::Release);
}

pub fn init() {
    let Some(dev) = crate::pci::devices()
        .into_iter()
        .find(|d| d.class == 0x0c && d.subclass == 0x03 && d.prog_if == 0x30)
    else {
        return;
    };
    let Some(mut c) = (unsafe { Controller::create(&dev) }) else {
        crate::warn!("xhci: controller init failed");
        return;
    };
    for port in 1..=c.max_ports {
        if let Some(speed) = unsafe { c.reset_port(port) } {
            if let Some(dev) = unsafe { c.enumerate_device(UsbTopology::root(port), speed) } {
                unsafe { c.register_enumerated(dev) };
            }
        }
    }
    let irq = c.irq;
    let n = c.devices.len();
    let hubs = c.hubs.len();
    *STATE.lock() = Some(c);
    if irq != 0 {
        crate::drivers::register_irq_handler(irq, irq_handler);
    }
    crate::info!(
        "driver: xHCI online usb_hid={} hubs={} irq={}",
        n,
        hubs,
        irq
    );
    // QEMU-only production recovery acceptance. Controller::create always
    // performs xHCI HCRST; recover_controller additionally attempts PCIe FLR,
    // tears down all DMA/rings/scratchpads, recreates them, and re-enumerates.
    // Real hardware does not pay this deliberate extra reset at normal boot.
    if dev.vendor_id == 0x1b36 && dev.device_id == 0x000d {
        if recover_controller() {
            crate::info!("xhci: RESET/RECOVERY SELFTEST PASS");
        } else {
            crate::warn!("xhci: RESET/RECOVERY SELFTEST FAIL");
        }
    }
}

pub fn poll() {
    let need_recover = {
        let mut s = STATE.lock();
        s.as_mut()
            .map(|c| unsafe { !c.poll_runtime() })
            .unwrap_or(false)
    };
    IRQ_PENDING.store(false, Ordering::Release);
    if need_recover {
        let _ = recover_controller();
    }
}

pub fn recover_controller() -> bool {
    let addr = {
        let s = STATE.lock();
        let Some(c) = s.as_ref() else { return false };
        c.pci_address
    };
    let Some(dev) = crate::pci::devices()
        .into_iter()
        .find(|d| d.address == addr)
    else {
        return false;
    };
    if let Some(old) = STATE.lock().take() {
        unsafe {
            old.release();
        }
    }
    let _ = crate::pci::function_level_reset(&dev);
    let Some(mut c) = (unsafe { Controller::create(&dev) }) else {
        crate::error!("xhci: recovery create failed");
        return false;
    };
    for port in 1..=c.max_ports {
        if let Some(speed) = unsafe { c.reset_port(port) } {
            if let Some(d) = unsafe { c.enumerate_device(UsbTopology::root(port), speed) } {
                unsafe { c.register_enumerated(d) };
            }
        }
    }
    let irq = c.irq;
    if irq != 0 {
        crate::drivers::register_irq_handler(irq, irq_handler);
    }
    let n = c.devices.len();
    let h = c.hubs.len();
    *STATE.lock() = Some(c);
    crate::info!("xhci: CONTROLLER RECOVERY PASS hid={} hubs={}", n, h);
    true
}

pub fn active() -> bool {
    STATE.lock().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_kib_controller_bar_can_be_sufficient() {
        // Small virtual xHCI implementations (e.g. Parallels) can fit their
        // entire register set in one 4KiB BAR; never impose QEMU's larger BAR.
        let hcs1 = 8u32 | (2u32 << 24);
        let required = controller_required_aperture(0x20, hcs1, 0x400, 0x800).unwrap();
        assert!(required <= 0x1000);
    }

    #[test]
    fn aperture_validation_accounts_for_ports_and_offsets() {
        let hcs1 = 32u32 | (16u32 << 24);
        let required = controller_required_aperture(0x40, hcs1, 0x2000, 0x3000).unwrap();
        assert!(required >= 0x3040);
    }
    #[test]
    fn dci_math() {
        assert_eq!(endpoint_dci(0x81), Some(3));
        assert_eq!(endpoint_dci(0x02), Some(4));
    }
    #[test]
    fn qemu_hid_config_parser() {
        let b = [
            9, 2, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0, 7, 5, 0x81, 3, 8, 0, 7,
        ];
        let (k, e) = parse_hid_config(&b).unwrap();
        assert_eq!(k, HidKind::Keyboard);
        assert_eq!(e.address, 0x81);
    }
    #[test]
    fn qemu_mouse_config_parser() {
        let b = [
            9, 2, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 1, 2, 0, 7, 5, 0x81, 3, 4, 0, 10,
        ];
        let (k, e) = parse_hid_config(&b).unwrap();
        assert_eq!(k, HidKind::Mouse);
        assert_eq!(e.max_packet, 4);
    }
    #[test]
    fn hub_route_string_building() {
        let root = UsbTopology::root(2);
        let c = root.child(7, 3, 4).unwrap();
        assert_eq!(c.route, 4);
        assert_eq!(c.root_port, 2);
        let d = c.child(8, 3, 3).unwrap();
        assert_eq!(d.route, 0x34);
        assert_eq!(d.parent_hub_slot, 8);
    }
    #[test]
    fn hub_interface_detection_and_speed() {
        let cfg = [9, 2, 18, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 9, 0, 0, 0];
        assert!(config_has_interface_class(&cfg, USB_CLASS_HUB));
        assert_eq!(Controller::hub_speed(1 << 10), 3);
        assert_eq!(Controller::hub_speed(1 << 9), 2);
        assert_eq!(Controller::hub_speed(0), 1);
    }

    #[test]
    fn interval_high_speed() {
        assert_eq!(xhci_interval(3, 7), 6);
        assert_eq!(xhci_interval(3, 4), 3);
    }
}
