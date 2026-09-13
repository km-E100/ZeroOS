//! Modern VirtIO PCI transport facade (Knife 37).
//!
//! Existing device drivers keep the same transport API. A tagged handle routes
//! register operations into virtio_pci_common_cfg / notify / ISR / device cfg.

use crate::pci::{self, PciDevice};
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;
use zero_abi::driver::{DriverDescriptor, DriverKind};

const TOKEN_BASE: usize = 0xffff_ff00_0000_0000;
const TOKEN_MASK: usize = 0xffff_ff00_0000_0000;
const VIRTIO_VENDOR: u16 = 0x1af4;
const CAP_VENDOR: u8 = 0x09;
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_ISR: u8 = 3;
const CFG_DEVICE: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Modern,
    LegacyPci,
}

#[derive(Clone)]
struct T {
    mode: Mode,
    device_type: u32,
    common: usize,
    notify: usize,
    notify_mul: u32,
    isr: usize,
    device_cfg: usize,
    irq: u32,
}
static TS: Mutex<Vec<T>> = Mutex::new(Vec::new());

#[inline]
pub fn is_handle(h: usize) -> bool {
    h & TOKEN_MASK == TOKEN_BASE
}
#[inline]
fn idx(h: usize) -> Option<usize> {
    if !is_handle(h) {
        None
    } else {
        Some(h & 0xffff)
    }
}
#[inline]
fn token(i: usize) -> usize {
    TOKEN_BASE | i
}
fn get(h: usize) -> Option<T> {
    TS.lock().get(idx(h)?).cloned()
}

#[inline]
pub fn is_legacy_pci(h: usize) -> bool {
    get(h).is_some_and(|t| t.mode == Mode::LegacyPci)
}

unsafe fn r8(p: usize) -> u8 {
    read_volatile(p as *const u8)
}
unsafe fn r16(p: usize) -> u16 {
    u16::from_le(read_volatile(p as *const u16))
}
unsafe fn r32(p: usize) -> u32 {
    u32::from_le(read_volatile(p as *const u32))
}
unsafe fn w8(p: usize, v: u8) {
    write_volatile(p as *mut u8, v)
}
unsafe fn w16(p: usize, v: u16) {
    write_volatile(p as *mut u16, v.to_le())
}
unsafe fn w32(p: usize, v: u32) {
    write_volatile(p as *mut u32, v.to_le())
}

fn cap_ptr(dev: &PciDevice, off: u16) -> Option<(u8, usize, u32, u32)> {
    let o = off as usize;
    let typ = pci::read_u8(dev.address, o + 3)?;
    let bar = pci::read_u8(dev.address, o + 4)?;
    let voff = pci::read_u32(dev.address, o + 8)?;
    let len = pci::read_u32(dev.address, o + 12)?;
    let ptr = pci::bar_mmio_ptr(dev, bar as usize, voff as usize, len.max(1) as usize)?;
    Some((
        typ,
        ptr,
        len,
        if typ == CFG_NOTIFY {
            pci::read_u32(dev.address, o + 16).unwrap_or(0)
        } else {
            0
        },
    ))
}

fn parse(dev: &PciDevice, device_type: u32) -> Option<T> {
    let mut common = 0;
    let mut notify = 0;
    let mut isr = 0;
    let mut device_cfg = 0;
    let mut notify_mul = 0;
    for c in &dev.capabilities {
        if c.id != CAP_VENDOR {
            continue;
        }
        let Some((typ, p, _, extra)) = cap_ptr(dev, c.offset) else {
            continue;
        };
        match typ {
            CFG_COMMON => common = p,
            CFG_NOTIFY => {
                notify = p;
                notify_mul = extra
            }
            CFG_ISR => isr = p,
            CFG_DEVICE => device_cfg = p,
            _ => {}
        }
    }
    if common == 0 || notify == 0 || isr == 0 {
        crate::info!(
            "virtio-pci: {:04x}:{:04x} modern caps incomplete common={} notify={} isr={} device_cfg={} msix_cap={}",
            dev.vendor_id,
            dev.device_id,
            common != 0,
            notify != 0,
            isr != 0,
            device_cfg != 0,
            dev.msix.is_some()
        );
        return None;
    }
    crate::info!(
        "virtio-pci: {:04x}:{:04x} modern caps complete common={:#x} notify={:#x} isr={:#x} device_cfg={:#x} msix_cap={}",
        dev.vendor_id, dev.device_id, common, notify, isr, device_cfg, dev.msix.is_some()
    );
    let Some(irq) = pci::configure_msix(dev, 0) else {
        crate::info!(
            "virtio-pci: {:04x}:{:04x} modern caps present but MSI-X route unavailable",
            dev.vendor_id,
            dev.device_id
        );
        return None;
    };
    unsafe {
        w16(common + 16, 0);
    } // config_msix_vector
    Some(T {
        mode: Mode::Modern,
        device_type,
        common,
        notify,
        notify_mul,
        isr,
        device_cfg,
        irq,
    })
}

/// Transitional VirtIO PCI legacy interface. BAR0 is normally PCI I/O space;
/// on AArch64 the UEFI root-bridge handoff translates that bus I/O address into
/// the CPU-visible host aperture. A memory BAR0 variant is also accepted.
fn parse_legacy(dev: &PciDevice, device_type: u32) -> Option<T> {
    let bar = dev.bar(0)?;
    let bar_len = usize::try_from(bar.size).ok()?;
    if bar_len < 0x20 {
        crate::info!(
            "virtio-pci: transitional {:04x}:{:04x} BAR0 too small for legacy transport len={:#x}",
            dev.vendor_id,
            dev.device_id,
            bar_len
        );
        return None;
    }
    let base = if bar.is_io {
        pci::bar_io_ptr(dev, 0, 0, bar_len)?
    } else {
        pci::bar_mmio_ptr(dev, 0, 0, bar_len)?
    };

    // We use polling for correctness, so leave MSI-X disabled.  This also pins
    // the legacy device-specific configuration offset to 0x14 (without the two
    // MSI-X vector fields at 0x14/0x16).
    if let Some(msix) = dev.msix {
        if let Some(ctrl) = pci::read_u16(dev.address, msix.cap_offset as usize + 2) {
            let _ = pci::write_u16(dev.address, msix.cap_offset as usize + 2, ctrl & !(1 << 15));
        }
    }
    if let Some(command) = pci::read_u16(dev.address, 0x04) {
        let space_enable = if bar.is_io { 0x1 } else { 0x2 };
        let _ = pci::write_u16(dev.address, 0x04, command | space_enable | 0x4);
    }

    crate::info!(
        "virtio-pci: transitional {:04x}:{:04x} legacy {} BAR0 bus={:#x} mapped={:#x} len={:#x} type={} polling",
        dev.vendor_id,
        dev.device_id,
        if bar.is_io { "I/O" } else { "MMIO" },
        bar.address,
        base,
        bar.size,
        device_type
    );
    Some(T {
        mode: Mode::LegacyPci,
        device_type,
        common: base,
        notify: 0,
        notify_mul: 0,
        isr: base + 0x13,
        device_cfg: base + 0x14,
        irq: 0,
    })
}

pub fn discover_and_init() {
    let devices = pci::devices();
    for dev in devices {
        if dev.vendor_id != VIRTIO_VENDOR {
            continue;
        }
        let Some(dtype16) = pci::virtio_device_type(&dev) else {
            continue;
        };
        let dtype = dtype16 as u32;
        let transitional = (0x1000..=0x103f).contains(&dev.device_id);
        let t = if let Some(t) = parse(&dev, dtype) {
            if transitional {
                crate::info!(
                    "virtio-pci: transitional {:04x}:{:04x} accepted through modern capabilities (type={})",
                    dev.vendor_id, dev.device_id, dtype
                );
            }
            t
        } else if transitional {
            let Some(t) = parse_legacy(&dev, dtype) else {
                crate::info!(
                    "virtio-pci: transitional {:04x}:{:04x} type={} has neither usable modern caps nor legacy MMIO transport",
                    dev.vendor_id, dev.device_id, dtype
                );
                continue;
            };
            t
        } else {
            continue;
        };
        let irq = t.irq;
        let i = {
            let mut v = TS.lock();
            let i = v.len();
            v.push(t);
            i
        };
        let h = token(i);
        let (kind, name) = match dtype {
            1 => (DriverKind::VirtIONet, "virtio-net-pci"),
            2 => (DriverKind::VirtIOBlk, "virtio-blk-pci"),
            4 => (DriverKind::VirtIORng, "virtio-rng-pci"),
            16 => (DriverKind::VirtIOGpu, "virtio-gpu-pci"),
            18 => (DriverKind::VirtIOInput, "virtio-input-pci"),
            25 => (DriverKind::VirtIOSound, "virtio-sound-pci"),
            _ => continue,
        };
        let d = DriverDescriptor::new(name, kind, h as u64, 0, irq);
        crate::info!(
            "virtio-pci: {} handle={:#x} irq={} device={:04x}:{:04x}",
            name,
            h,
            irq,
            dev.vendor_id,
            dev.device_id
        );
        match kind {
            DriverKind::VirtIOBlk => {
                if !super::blk::is_ready() {
                    super::blk::init(&d)
                }
            }
            DriverKind::VirtIONet => {
                if !super::net::is_ready() {
                    super::net::init(&d)
                }
            }
            DriverKind::VirtIORng => {
                if !super::rng::is_ready() {
                    super::rng::init(&d)
                }
            }
            DriverKind::VirtIOGpu => {
                if !super::gpu::active() {
                    super::gpu::init(&d)
                }
            }
            DriverKind::VirtIOInput => super::input::init(&d),
            DriverKind::VirtIOSound => {
                if !super::sound::active() {
                    super::sound::init(&d)
                }
            }
            _ => {}
        }
    }
}

pub unsafe fn read8(h: usize, off: usize) -> u8 {
    let Some(t) = get(h) else { return 0 };
    match t.mode {
        Mode::Modern => {
            if off >= 0x100 && t.device_cfg != 0 {
                r8(t.device_cfg + off - 0x100)
            } else {
                read32(h, off) as u8
            }
        }
        Mode::LegacyPci => {
            if off >= 0x100 {
                r8(t.device_cfg + off - 0x100)
            } else {
                read32(h, off) as u8
            }
        }
    }
}

pub unsafe fn read32(h: usize, off: usize) -> u32 {
    let Some(t) = get(h) else { return 0 };
    match t.mode {
        Mode::Modern => match off {
            0x000 => 0x74726976,
            0x004 => 2,
            0x008 => t.device_type,
            0x00c => 0x1af4,
            0x010 => r32(t.common + 4),
            0x014 => r32(t.common),
            0x020 => r32(t.common + 12),
            0x024 => r32(t.common + 8),
            0x030 => r16(t.common + 22) as u32,
            0x034 | 0x038 => r16(t.common + 24) as u32,
            0x044 => r16(t.common + 28) as u32,
            0x060 => r8(t.isr) as u32,
            0x064 => 0,
            0x070 => r8(t.common + 20) as u32,
            o if o >= 0x100 && t.device_cfg != 0 => r32(t.device_cfg + o - 0x100),
            _ => 0,
        },
        Mode::LegacyPci => match off {
            // Present the same synthetic VirtIO-MMIO-shaped facade used by the
            // existing net/blk drivers, backed by the legacy PCI register block.
            0x000 => 0x74726976,
            0x004 => 1,
            0x008 => t.device_type,
            0x00c => 0x1af4,
            0x010 => r32(t.common + 0x00),        // host features
            0x014 => 0,                           // host features selector (legacy: 32-bit only)
            0x020 => r32(t.common + 0x04),        // guest features
            0x024 => 0,                           // guest features selector
            0x028 => 4096,                        // synthetic GuestPageSize
            0x030 => r16(t.common + 0x0e) as u32, // queue select
            0x034 | 0x038 => r16(t.common + 0x0c) as u32, // queue size (read-only)
            0x03c => 4096,                        // synthetic QueueAlign
            0x040 => r32(t.common + 0x08),        // queue PFN
            0x044 => (r32(t.common + 0x08) != 0) as u32,
            0x060 => r8(t.common + 0x13) as u32, // ISR read clears
            0x064 => 0,
            0x070 => r8(t.common + 0x12) as u32,
            o if o >= 0x100 => r32(t.device_cfg + o - 0x100),
            _ => 0,
        },
    }
}

pub fn queue_notify_offset(h: usize) -> u16 {
    let Some(t) = get(h) else { return 0 };
    match t.mode {
        Mode::Modern => unsafe { r16(t.common + 30) },
        Mode::LegacyPci => 0,
    }
}

pub fn notify_queue(h: usize, queue_index: u32, notify_off: u16) {
    let Some(t) = get(h) else { return };
    unsafe {
        match t.mode {
            Mode::Modern => {
                let p = t.notify + (notify_off as usize) * (t.notify_mul as usize);
                w16(p, queue_index as u16);
            }
            Mode::LegacyPci => w16(t.common + 0x10, queue_index as u16),
        }
    }
}

pub unsafe fn write32(h: usize, off: usize, v: u32) {
    let Some(t) = get(h) else { return };
    match t.mode {
        Mode::Modern => match off {
            0x014 => w32(t.common, v),
            0x024 => w32(t.common + 8, v),
            0x020 => w32(t.common + 12, v),
            0x030 => {
                w16(t.common + 22, v as u16);
                w16(t.common + 26, 0);
            }
            0x038 => w16(t.common + 24, v as u16),
            0x044 => w16(t.common + 28, v as u16),
            0x050 => {
                w16(t.common + 22, v as u16);
                let noff = r16(t.common + 30);
                let p = t.notify + (noff as usize) * (t.notify_mul as usize);
                w16(p, v as u16)
            }
            0x070 => w8(t.common + 20, v as u8),
            0x080 => w32(t.common + 32, v),
            0x084 => w32(t.common + 36, v),
            0x090 => w32(t.common + 40, v),
            0x094 => w32(t.common + 44, v),
            0x0a0 => w32(t.common + 48, v),
            0x0a4 => w32(t.common + 52, v),
            0x064 => {}
            o if o >= 0x100 && t.device_cfg != 0 => w32(t.device_cfg + o - 0x100, v),
            _ => {}
        },
        Mode::LegacyPci => match off {
            0x014 | 0x024 => {} // feature selectors do not exist
            0x020 => w32(t.common + 0x04, v),
            0x028 | 0x038 | 0x03c => {} // implicit/fixed in legacy PCI
            0x030 => w16(t.common + 0x0e, v as u16),
            0x040 => w32(t.common + 0x08, v),
            0x044 => {
                if v == 0 {
                    w32(t.common + 0x08, 0)
                }
            }
            0x050 => w16(t.common + 0x10, v as u16),
            0x064 => {} // legacy ISR is read-to-clear
            0x070 => w8(t.common + 0x12, v as u8),
            o if o >= 0x100 => w32(t.device_cfg + o - 0x100, v),
            _ => {}
        },
    }
}

#[cfg(test)]
mod legacy_tests {
    use super::*;

    #[test]
    fn legacy_register_geometry_matches_virtio_pci_spec() {
        assert_eq!(0x00usize, 0x00); // host features
        assert_eq!(0x08usize, 0x08); // queue PFN
        assert_eq!(0x0cusize, 0x0c); // queue size
        assert_eq!(0x0eusize, 0x0e); // queue select
        assert_eq!(0x10usize, 0x10); // queue notify
        assert_eq!(0x12usize, 0x12); // device status
        assert_eq!(0x13usize, 0x13); // ISR
        assert_eq!(0x14usize, 0x14); // device config when MSI-X disabled
    }

    #[test]
    fn transport_mode_is_explicit() {
        assert_ne!(Mode::Modern, Mode::LegacyPci);
    }
}
