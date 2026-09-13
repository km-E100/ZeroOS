//! PCIe ECAM core (Knife 35).
//!
//! ACPI MCFG is the only platform source. The core owns PCI configuration
//! space and BAR sizing; device drivers consume the cached registry instead of
//! open-coding ECAM arithmetic. Configuration accesses are performed during
//! early boot before user address spaces exist, which also lets us retype ECAM
//! pages as Device-nGnRE in the kernel identity map.

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use crate::acpi::EcamSegment;
use crate::mm::table_walk::{
    AP_EL1_RW_EL0_NONE, DESC_AF, DESC_ATTRIDX_DEVICE_NGNRE, DESC_PXN, DESC_SH_INNER, DESC_UXN,
};
use zero_abi::driver::DriverKind;

const CONFIG_SIZE: usize = 4096;
const MAX_BUSES_PER_SEGMENT: usize = 256;
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;
const PCI_HEADER_MULTI: u8 = 0x80;
const PCI_HEADER_TYPE_MASK: u8 = 0x7f;
const PCI_CAP_MSIX: u8 = 0x11;
const PCI_CAP_PCIE: u8 = 0x10;
const PCIE_EXT_CAP_AER: u16 = 0x0001;
const MMIO_LIMIT: u64 = 0x8000_0000; // current kernel identity-map ceiling
const DEVICE_PAGE_FLAGS: u64 = DESC_AF
    | DESC_SH_INNER
    | DESC_ATTRIDX_DEVICE_NGNRE
    | DESC_UXN
    | DESC_PXN
    | (AP_EL1_RW_EL0_NONE << 6);

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciAddress {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn requester_id(self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | self.function as u16
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PciBar {
    pub index: u8,
    pub address: u64,
    pub size: u64,
    pub is_io: bool,
    pub is_64: bool,
    pub prefetchable: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciCapability {
    pub id: u8,
    pub offset: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PcieExtCapability {
    pub id: u16,
    pub version: u8,
    pub offset: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MsixCapability {
    pub cap_offset: u16,
    pub table_size: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PciBridgeInfo {
    pub primary: u8,
    pub secondary: u8,
    pub subordinate: u8,
    pub memory_base: u64,
    pub memory_limit: u64,
    pub prefetch_base: u64,
    pub prefetch_limit: u64,
}

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
    pub subsystem_vendor: u16,
    pub subsystem_id: u16,
    pub bars: [PciBar; 6],
    pub capabilities: Vec<PciCapability>,
    pub ext_capabilities: Vec<PcieExtCapability>,
    pub msix: Option<MsixCapability>,
    pub bridge: Option<PciBridgeInfo>,
}

impl PciDevice {
    pub fn bar(&self, index: usize) -> Option<PciBar> {
        self.bars.get(index).copied().filter(|b| b.size != 0)
    }
    pub fn capability(&self, id: u8) -> Option<PciCapability> {
        self.capabilities.iter().copied().find(|c| c.id == id)
    }
    pub fn ext_capability(&self, id: u16) -> Option<PcieExtCapability> {
        self.ext_capabilities.iter().copied().find(|c| c.id == id)
    }
    pub fn is_bridge(&self) -> bool {
        self.header_type & PCI_HEADER_TYPE_MASK == 1
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PciMmioResource {
    pub kind: DriverKind,
    pub address: PciAddress,
    pub bar_index: u8,
    pub base: u64,
    pub len: u64,
    pub irq: u32,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

/// Resolve the VirtIO device type from the PCI identity. Modern devices encode
/// `type + 0x1040` in Device ID. Transitional IDs (0x1000..0x103f) deliberately
/// do *not* have that mapping; the VirtIO PCI specification makes Subsystem
/// Device ID authoritative for the device type and requires revision 0.
fn virtio_device_type_fields(
    vendor: u16,
    device: u16,
    revision: u8,
    subsystem: u16,
) -> Option<u16> {
    if vendor != 0x1af4 {
        return None;
    }
    if (0x1041..=0x107f).contains(&device) {
        return Some(device - 0x1040);
    }
    if (0x1000..=0x103f).contains(&device) && revision == 0 && subsystem != 0 {
        return Some(subsystem);
    }
    None
}

pub fn virtio_device_type(dev: &PciDevice) -> Option<u16> {
    virtio_device_type_fields(dev.vendor_id, dev.device_id, dev.revision, dev.subsystem_id)
}

fn driver_kind_for(dev: &PciDevice) -> DriverKind {
    if dev.vendor_id == 0x1b36 && dev.device_id == 0x0005 {
        return DriverKind::PciTest;
    }
    if dev.class == 0x01 && dev.subclass == 0x08 && dev.prog_if == 0x02 {
        return DriverKind::Nvme;
    }
    if dev.class == 0x0c && dev.subclass == 0x03 && dev.prog_if == 0x30 {
        return DriverKind::UsbXhci;
    }
    match virtio_device_type(dev) {
        Some(1) => DriverKind::VirtIONet,
        Some(2) => DriverKind::VirtIOBlk,
        Some(4) => DriverKind::VirtIORng,
        Some(16) => DriverKind::VirtIOGpu,
        Some(18) => DriverKind::VirtIOInput,
        Some(25) => DriverKind::VirtIOSound,
        _ => DriverKind::PciGeneric,
    }
}

/// Flatten all memory BARs into capability/lease resources. I/O-port BARs are
/// deliberately omitted because AArch64 EL0 has no port-I/O instruction space.
pub fn mmio_resources() -> Vec<PciMmioResource> {
    let devices = DEVICES.lock();
    let mut out = Vec::new();
    for dev in devices.iter() {
        let kind = driver_kind_for(dev);
        for bar in dev.bars.iter().filter(|b| b.size != 0 && !b.is_io) {
            out.push(PciMmioResource {
                kind,
                address: dev.address,
                bar_index: bar.index,
                base: bar.address,
                len: bar.size,
                irq: 0, // MSI/MSI-X is allocated separately by the IRQ subsystem.
                vendor_id: dev.vendor_id,
                device_id: dev.device_id,
                revision: dev.revision,
                class: dev.class,
                subclass: dev.subclass,
                prog_if: dev.prog_if,
            });
        }
    }
    out
}

pub fn contains_mmio_range(base: u64, len: u64) -> bool {
    let Some(end) = base.checked_add(len) else {
        return false;
    };
    mmio_resources()
        .iter()
        .any(|r| r.base <= base && r.base.checked_add(r.len).map_or(false, |re| end <= re))
}

#[cfg(test)]
mod virtio_identity_tests {
    use super::virtio_device_type_fields;

    #[test]
    fn modern_and_transitional_virtio_ids_resolve_by_spec() {
        assert_eq!(virtio_device_type_fields(0x1af4, 0x1041, 1, 0), Some(1));
        assert_eq!(virtio_device_type_fields(0x1af4, 0x1042, 1, 0), Some(2));
        // Transitional Device ID is not the type: Subsystem Device ID is.
        assert_eq!(virtio_device_type_fields(0x1af4, 0x1000, 0, 1), Some(1));
        assert_eq!(virtio_device_type_fields(0x1af4, 0x1004, 0, 8), Some(8));
        assert_eq!(virtio_device_type_fields(0x1af4, 0x1005, 0, 4), Some(4));
        assert_eq!(virtio_device_type_fields(0x1af4, 0x1000, 1, 1), None);
        assert_eq!(virtio_device_type_fields(0x1234, 0x1041, 1, 0), None);
    }
}

#[derive(Copy, Clone)]
struct EcamMap {
    seg: EcamSegment,
    virt_base: usize,
}

static DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());
static SEGMENTS: Mutex<Vec<EcamMap>> = Mutex::new(Vec::new());

#[inline]
fn config_phys(seg: EcamSegment, address: PciAddress, offset: usize) -> Option<u64> {
    if address.segment != seg.segment
        || address.bus < seg.start_bus
        || address.bus > seg.end_bus
        || address.device >= 32
        || address.function >= 8
        || offset >= CONFIG_SIZE
    {
        return None;
    }
    let bus = (address.bus - seg.start_bus) as u64;
    seg.base
        .checked_add(bus << 20)?
        .checked_add((address.device as u64) << 15)?
        .checked_add((address.function as u64) << 12)?
        .checked_add(offset as u64)
}

fn segment_for(address: PciAddress) -> Option<EcamMap> {
    SEGMENTS.lock().iter().copied().find(|m| {
        let s = m.seg;
        s.segment == address.segment && address.bus >= s.start_bus && address.bus <= s.end_bus
    })
}

fn config_virt(map: EcamMap, address: PciAddress, offset: usize) -> Option<usize> {
    let phys = config_phys(map.seg, address, offset)?;
    let delta = phys.checked_sub(map.seg.base)? as usize;
    map.virt_base.checked_add(delta)
}

fn ensure_config_page(map: EcamMap, address: PciAddress) -> bool {
    let Some(base) = config_phys(map.seg, address, 0) else {
        return false;
    };
    if map.virt_base != map.seg.base as usize {
        // High ECAM is mapped as a whole through the shared ioremap window.
        return true;
    }
    let page = (base as usize) & !0xfff;
    unsafe { crate::mm::paging::map_kernel_page(page, page, DEVICE_PAGE_FLAGS).is_ok() }
}

#[inline]
pub fn read_u8(address: PciAddress, offset: usize) -> Option<u8> {
    let map = segment_for(address)?;
    let virt = config_virt(map, address, offset)?;
    Some(unsafe { read_volatile(virt as *const u8) })
}
#[inline]
pub fn read_u16(address: PciAddress, offset: usize) -> Option<u16> {
    if offset & 1 != 0 {
        return None;
    }
    let lo = read_u8(address, offset)?;
    let hi = read_u8(address, offset + 1)?;
    Some(u16::from_le_bytes([lo, hi]))
}
#[inline]
pub fn read_u32(address: PciAddress, offset: usize) -> Option<u32> {
    if offset & 3 != 0 {
        return None;
    }
    let map = segment_for(address)?;
    let virt = config_virt(map, address, offset)?;
    Some(u32::from_le(unsafe { read_volatile(virt as *const u32) }))
}
#[inline]
pub fn write_u16(address: PciAddress, offset: usize, value: u16) -> bool {
    if offset & 1 != 0 {
        return false;
    }
    let Some(map) = segment_for(address) else {
        return false;
    };
    let Some(virt) = config_virt(map, address, offset) else {
        return false;
    };
    unsafe { write_volatile(virt as *mut u16, value.to_le()) };
    true
}
#[inline]
pub fn write_u32(address: PciAddress, offset: usize, value: u32) -> bool {
    if offset & 3 != 0 {
        return false;
    }
    let Some(map) = segment_for(address) else {
        return false;
    };
    let Some(virt) = config_virt(map, address, offset) else {
        return false;
    };
    unsafe { write_volatile(virt as *mut u32, value.to_le()) };
    true
}

fn parse_capabilities(address: PciAddress, status: u16) -> Vec<PciCapability> {
    let mut out = Vec::new();
    if status & PCI_STATUS_CAP_LIST == 0 {
        return out;
    }
    let mut next = read_u8(address, 0x34).unwrap_or(0) & !3;
    let mut visited = [false; 256];
    for _ in 0..48 {
        if next < 0x40 || next as usize + 2 > 0x100 || visited[next as usize] {
            break;
        }
        visited[next as usize] = true;
        let id = read_u8(address, next as usize).unwrap_or(0xff);
        out.push(PciCapability {
            id,
            offset: next as u16,
        });
        next = read_u8(address, next as usize + 1).unwrap_or(0) & !3;
        if next == 0 {
            break;
        }
    }
    out
}

fn parse_ext_capabilities(address: PciAddress) -> Vec<PcieExtCapability> {
    let mut out = Vec::new();
    let mut off = 0x100usize;
    let mut seen = [false; 1024];
    for _ in 0..64 {
        if off < 0x100 || off + 4 > CONFIG_SIZE || off & 3 != 0 {
            break;
        }
        let slot = off >> 2;
        if slot >= seen.len() || seen[slot] {
            break;
        }
        seen[slot] = true;
        let Some(h) = read_u32(address, off) else {
            break;
        };
        if h == 0 || h == u32::MAX {
            break;
        }
        out.push(PcieExtCapability {
            id: (h & 0xffff) as u16,
            version: ((h >> 16) & 0xf) as u8,
            offset: off as u16,
        });
        let next = ((h >> 20) & 0xfff) as usize;
        if next == 0 {
            break;
        }
        off = next;
    }
    out
}

fn parse_msix(address: PciAddress, caps: &[PciCapability]) -> Option<MsixCapability> {
    let cap = caps.iter().find(|c| c.id == PCI_CAP_MSIX)?;
    let control = read_u16(address, cap.offset as usize + 2)?;
    let table = read_u32(address, cap.offset as usize + 4)?;
    let pba = read_u32(address, cap.offset as usize + 8)?;
    Some(MsixCapability {
        cap_offset: cap.offset,
        table_size: (control & 0x07ff) + 1,
        table_bar: (table & 7) as u8,
        table_offset: table & !7,
        pba_bar: (pba & 7) as u8,
        pba_offset: pba & !7,
    })
}

fn parse_bridge(address: PciAddress, header_type: u8) -> Option<PciBridgeInfo> {
    if header_type & PCI_HEADER_TYPE_MASK != 1 {
        return None;
    }
    let primary = read_u8(address, 0x18)?;
    let secondary = read_u8(address, 0x19)?;
    let subordinate = read_u8(address, 0x1a)?;
    let mb = read_u16(address, 0x20)?;
    let ml = read_u16(address, 0x22)?;
    let memory_base = ((mb as u64) & 0xfff0) << 16;
    let memory_limit = (((ml as u64) & 0xfff0) << 16) | 0x000f_ffff;
    let pb = read_u16(address, 0x24)?;
    let pl = read_u16(address, 0x26)?;
    let mut prefetch_base = ((pb as u64) & 0xfff0) << 16;
    let mut prefetch_limit = (((pl as u64) & 0xfff0) << 16) | 0x000f_ffff;
    if pb & 0x1 != 0 {
        prefetch_base |= (read_u32(address, 0x28)? as u64) << 32;
    }
    if pl & 0x1 != 0 {
        prefetch_limit |= (read_u32(address, 0x2c)? as u64) << 32;
    }
    Some(PciBridgeInfo {
        primary,
        secondary,
        subordinate,
        memory_base: (memory_base <= memory_limit)
            .then_some(memory_base)
            .unwrap_or(0),
        memory_limit: (memory_base <= memory_limit)
            .then_some(memory_limit)
            .unwrap_or(0),
        prefetch_base: (prefetch_base <= prefetch_limit)
            .then_some(prefetch_base)
            .unwrap_or(0),
        prefetch_limit: (prefetch_base <= prefetch_limit)
            .then_some(prefetch_limit)
            .unwrap_or(0),
    })
}

fn size_bars(address: PciAddress, header_type: u8) -> [PciBar; 6] {
    let mut bars = [PciBar::default(); 6];
    let count = if header_type & PCI_HEADER_TYPE_MASK == 0 {
        6
    } else {
        2
    };
    let command = read_u16(address, 0x04).unwrap_or(0);
    let _ = write_u16(address, 0x04, command & !0x3);
    let mut i = 0usize;
    while i < count {
        let off = 0x10 + i * 4;
        let original = read_u32(address, off).unwrap_or(0);
        let _ = write_u32(address, off, u32::MAX);
        let mask_lo = read_u32(address, off).unwrap_or(0);
        let probe = if original != 0 && original != u32::MAX {
            original
        } else {
            mask_lo
        };
        if mask_lo == 0 || mask_lo == u32::MAX {
            let _ = write_u32(address, off, original);
            i += 1;
            continue;
        }
        if probe & 1 != 0 {
            let _ = write_u32(address, off, original);
            let raw_mask = mask_lo & !3;
            if raw_mask != 0 {
                bars[i] = PciBar {
                    index: i as u8,
                    address: (original & !3) as u64,
                    size: (!(raw_mask)).wrapping_add(1) as u64,
                    is_io: true,
                    is_64: false,
                    prefetchable: false,
                };
            }
            i += 1;
            continue;
        }
        let kind = (probe >> 1) & 3;
        let is_64 = kind == 2 && i + 1 < count;
        let prefetchable = probe & 8 != 0;
        if is_64 {
            let original_hi = read_u32(address, off + 4).unwrap_or(0);
            let _ = write_u32(address, off + 4, u32::MAX);
            let mask_hi = read_u32(address, off + 4).unwrap_or(0);
            let _ = write_u32(address, off, original);
            let _ = write_u32(address, off + 4, original_hi);
            let raw_mask = ((mask_hi as u64) << 32) | ((mask_lo & !0xf) as u64);
            if raw_mask != 0 {
                bars[i] = PciBar {
                    index: i as u8,
                    address: ((original_hi as u64) << 32) | ((original & !0xf) as u64),
                    size: (!raw_mask).wrapping_add(1),
                    is_io: false,
                    is_64: true,
                    prefetchable,
                };
            }
            i += 2;
        } else {
            let _ = write_u32(address, off, original);
            let raw_mask = mask_lo & !0xf;
            if raw_mask != 0 {
                bars[i] = PciBar {
                    index: i as u8,
                    address: (original & !0xf) as u64,
                    size: (!(raw_mask)).wrapping_add(1) as u64,
                    is_io: false,
                    is_64: false,
                    prefetchable,
                };
            }
            i += 1;
        }
    }
    let _ = write_u16(address, 0x04, command);
    bars
}

fn read_device(address: PciAddress) -> Option<PciDevice> {
    let vendor_id = read_u16(address, 0x00)?;
    if vendor_id == 0xffff {
        return None;
    }
    let device_id = read_u16(address, 0x02)?;
    let status = read_u16(address, 0x06).unwrap_or(0);
    let revision = read_u8(address, 0x08).unwrap_or(0);
    let prog_if = read_u8(address, 0x09).unwrap_or(0);
    let subclass = read_u8(address, 0x0a).unwrap_or(0);
    let class = read_u8(address, 0x0b).unwrap_or(0);
    let header_type = read_u8(address, 0x0e).unwrap_or(0);
    let subsystem_vendor = if header_type & PCI_HEADER_TYPE_MASK == 0 {
        read_u16(address, 0x2c).unwrap_or(0)
    } else {
        0
    };
    let subsystem_id = if header_type & PCI_HEADER_TYPE_MASK == 0 {
        read_u16(address, 0x2e).unwrap_or(0)
    } else {
        0
    };
    let bars = size_bars(address, header_type);
    let capabilities = parse_capabilities(address, status);
    let ext_capabilities = parse_ext_capabilities(address);
    let msix = parse_msix(address, &capabilities);
    let bridge = parse_bridge(address, header_type);
    Some(PciDevice {
        address,
        vendor_id,
        device_id,
        class,
        subclass,
        prog_if,
        revision,
        header_type,
        subsystem_vendor,
        subsystem_id,
        bars,
        capabilities,
        ext_capabilities,
        msix,
        bridge,
    })
}

fn align_up_u64(v: u64, a: u64) -> Option<u64> {
    if a == 0 || !a.is_power_of_two() {
        return None;
    }
    v.checked_add(a - 1).map(|x| x & !(a - 1))
}

fn relocate_unassigned_bars(devices: &mut [PciDevice]) {
    let bridges: Vec<(PciAddress, PciBridgeInfo)> = devices
        .iter()
        .filter_map(|d| d.bridge.map(|b| (d.address, b)))
        .collect();
    let mut cursors: Vec<(PciAddress, u64, u64)> = bridges
        .iter()
        .map(|(a, b)| (*a, b.memory_base, b.prefetch_base))
        .collect();
    for dev in devices.iter_mut().filter(|d| !d.is_bridge()) {
        let parent_idx = bridges
            .iter()
            .enumerate()
            .filter(|(_, (_, b))| {
                b.secondary != 0
                    && dev.address.bus >= b.secondary
                    && dev.address.bus <= b.subordinate
            })
            .min_by_key(|(_, (_, b))| b.subordinate.saturating_sub(b.secondary))
            .map(|(i, _)| i);
        let Some(pi) = parent_idx else { continue };
        let b = bridges[pi].1;
        for bar in dev
            .bars
            .iter_mut()
            .filter(|b| !b.is_io && b.size != 0 && b.address == 0)
        {
            let (cursor, limit) = if bar.prefetchable && b.prefetch_base != 0 {
                (&mut cursors[pi].2, b.prefetch_limit)
            } else {
                (&mut cursors[pi].1, b.memory_limit)
            };
            if *cursor == 0 || limit == 0 {
                continue;
            }
            let Some(base) = align_up_u64(*cursor, bar.size) else {
                continue;
            };
            let Some(end) = base.checked_add(bar.size - 1) else {
                continue;
            };
            if end > limit {
                continue;
            }
            let off = 0x10 + bar.index as usize * 4;
            let flags =
                (if bar.is_64 { 0x4 } else { 0 }) | (if bar.prefetchable { 0x8 } else { 0 });
            write_u32(dev.address, off, (base as u32 & !0xf) | flags);
            if bar.is_64 {
                write_u32(dev.address, off + 4, (base >> 32) as u32);
            }
            bar.address = base;
            *cursor = end.saturating_add(1);
            let cmd = read_u16(dev.address, 0x04).unwrap_or(0);
            write_u16(dev.address, 0x04, cmd | 0x2 | 0x4);
            crate::info!(
                "pcie: BAR{} relocated {:04x}:{:02x}:{:02x}.{} -> {:#x} size={:#x}",
                bar.index,
                dev.address.segment,
                dev.address.bus,
                dev.address.device,
                dev.address.function,
                base,
                bar.size
            );
        }
    }
}

pub fn function_level_reset(dev: &PciDevice) -> bool {
    let Some(cap) = dev.capability(PCI_CAP_PCIE) else {
        return false;
    };
    let o = cap.offset as usize;
    let devcap = read_u32(dev.address, o + 4).unwrap_or(0);
    if devcap & (1 << 28) == 0 {
        return false;
    }
    let ctrl = read_u16(dev.address, o + 8).unwrap_or(0);
    if !write_u16(dev.address, o + 8, ctrl | (1 << 15)) {
        return false;
    }
    let deadline = crate::time::monotonic_ns().saturating_add(100_000_000);
    while crate::time::monotonic_ns() < deadline {
        core::hint::spin_loop();
    }
    true
}

pub fn secondary_bus_reset(dev: &PciDevice) -> bool {
    if !dev.is_bridge() {
        return false;
    }
    let ctrl = read_u16(dev.address, 0x3e).unwrap_or(0);
    if !write_u16(dev.address, 0x3e, ctrl | (1 << 6)) {
        return false;
    }
    let deadline = crate::time::monotonic_ns().saturating_add(1_000_000);
    while crate::time::monotonic_ns() < deadline {
        core::hint::spin_loop();
    }
    write_u16(dev.address, 0x3e, ctrl & !(1 << 6))
}

pub fn clear_aer_status(dev: &PciDevice) -> bool {
    let Some(aer) = dev.ext_capability(PCIE_EXT_CAP_AER) else {
        return false;
    };
    let o = aer.offset as usize;
    let unc = read_u32(dev.address, o + 0x04).unwrap_or(0);
    let cor = read_u32(dev.address, o + 0x10).unwrap_or(0);
    if unc != 0 {
        write_u32(dev.address, o + 0x04, unc);
    }
    if cor != 0 {
        write_u32(dev.address, o + 0x10, cor);
    }
    true
}

pub fn init() {
    let segments = crate::acpi::ecam_segments();
    let mut mapped = Vec::new();
    for seg in segments {
        let buses = (seg.end_bus as usize).saturating_sub(seg.start_bus as usize) + 1;
        let bytes = match buses.checked_shl(20) {
            Some(v) => v,
            None => continue,
        };
        let end = seg.base.saturating_add(bytes as u64);
        let virt_base = if end <= MMIO_LIMIT {
            seg.base as usize
        } else {
            match crate::mm::paging::ioremap_device(seg.base as usize, bytes) {
                Some(v) => {
                    crate::info!(
                        "pcie: high ECAM mapped phys={:#x} -> virt={:#x} len={:#x}",
                        seg.base,
                        v,
                        bytes
                    );
                    v
                }
                None => {
                    crate::warn!(
                        "pcie: ECAM seg={} mapping failed base={:#x} len={:#x}",
                        seg.segment,
                        seg.base,
                        bytes
                    );
                    continue;
                }
            }
        };
        mapped.push(EcamMap { seg, virt_base });
    }
    *SEGMENTS.lock() = mapped.clone();
    let mut found = Vec::new();
    for map in mapped {
        let seg = map.seg;
        let bus_count = (seg.end_bus as usize).saturating_sub(seg.start_bus as usize) + 1;
        crate::info!(
            "pcie: ECAM seg={} base={:#x} buses={}..={} ({} buses)",
            seg.segment,
            seg.base,
            seg.start_bus,
            seg.end_bus,
            bus_count.min(MAX_BUSES_PER_SEGMENT)
        );
        for bus in seg.start_bus..=seg.end_bus {
            for device in 0..32u8 {
                let a0 = PciAddress {
                    segment: seg.segment,
                    bus,
                    device,
                    function: 0,
                };
                if !ensure_config_page(map, a0) {
                    continue;
                }
                let vendor0 = read_u16(a0, 0).unwrap_or(0xffff);
                if vendor0 == 0xffff {
                    continue;
                }
                let header = read_u8(a0, 0x0e).unwrap_or(0);
                let functions = if header & PCI_HEADER_MULTI != 0 { 8 } else { 1 };
                for function in 0..functions {
                    let addr = PciAddress { function, ..a0 };
                    if function != 0 && !ensure_config_page(map, addr) {
                        continue;
                    }
                    if let Some(dev) = read_device(addr) {
                        crate::info!("pcie: {:04x}:{:02x}:{:02x}.{} {:04x}:{:04x} class={:02x}:{:02x}:{:02x} bars={} caps={}{}",
                            dev.address.segment, dev.address.bus, dev.address.device, dev.address.function,
                            dev.vendor_id, dev.device_id, dev.class, dev.subclass, dev.prog_if,
                            dev.bars.iter().filter(|b| b.size != 0).count(), dev.capabilities.len(),
                            if dev.msix.is_some() { " msix" } else { "" });
                        for bar in dev.bars.iter().filter(|b| b.size != 0) {
                            crate::info!(
                                "pcie:   BAR{} addr={:#x} size={:#x} {}{}",
                                bar.index,
                                bar.address,
                                bar.size,
                                if bar.is_io { "io" } else { "mem" },
                                if bar.is_64 { "64" } else { "" }
                            );
                        }
                        found.push(dev);
                    }
                }
            }
            if bus == u8::MAX {
                break;
            }
        }
    }
    relocate_unassigned_bars(&mut found);
    for dev in found.iter().filter(|d| d.is_bridge()) {
        if let Some(b) = dev.bridge {
            crate::info!("pcie: bridge {:04x}:{:02x}:{:02x}.{} buses={}->{} mem=[{:#x},{:#x}] pref=[{:#x},{:#x}]",
                dev.address.segment, dev.address.bus, dev.address.device, dev.address.function,
                b.secondary, b.subordinate, b.memory_base, b.memory_limit, b.prefetch_base, b.prefetch_limit);
        }
        let _ = clear_aer_status(dev);
    }
    crate::info!("pcie: enumeration complete, {} functions", found.len());
    *DEVICES.lock() = found;
    pci_testdev_self_test();
    edu_msi_self_test();
}

static EDU_MMIO: AtomicUsize = AtomicUsize::new(0);
static EDU_MSI_SEEN: AtomicBool = AtomicBool::new(false);
fn edu_msi_handler(irq: u32) {
    let base = EDU_MMIO.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    unsafe {
        let pending = read_volatile((base + 0x24) as *const u32);
        write_volatile((base + 0x64) as *mut u32, pending);
        if !EDU_MSI_SEEN.swap(true, Ordering::SeqCst) {
            crate::info!("pcie: EDU MSI PASS irq={} pending={:#x}", irq, pending);
        }
    }
}

pub fn configure_msix_affinity(dev: &PciDevice, vector: u16, cpu: usize) -> Option<u32> {
    let msix = dev.msix?;
    if vector >= msix.table_size {
        return None;
    }
    let (addr, data, lpi) =
        crate::arch::reserve_pci_msi_affinity(dev.address.requester_id(), vector as u32, cpu)?;
    let entry_off = msix.table_offset as usize + (vector as usize) * 16;
    let base = bar_mmio_ptr(dev, msix.table_bar as usize, entry_off, 16)? - entry_off;
    let e = base + entry_off;
    let ctrl = read_u16(dev.address, msix.cap_offset as usize + 2)?;
    // Function-mask while programming, then enable MSI-X and unmask vector.
    write_u16(dev.address, msix.cap_offset as usize + 2, ctrl | (1 << 14));
    unsafe {
        write_volatile(e as *mut u32, addr as u32);
        write_volatile((e + 4) as *mut u32, (addr >> 32) as u32);
        write_volatile((e + 8) as *mut u32, data);
        write_volatile((e + 12) as *mut u32, 0);
    }
    write_u16(
        dev.address,
        msix.cap_offset as usize + 2,
        (ctrl | (1 << 15)) & !(1 << 14),
    );
    let command = read_u16(dev.address, 0x04).unwrap_or(0);
    write_u16(dev.address, 0x04, (command | 0x2 | 0x4) | (1 << 10));
    crate::info!(
        "pcie: MSI-X {:04x}:{:02x}:{:02x}.{} vector={} -> LPI{} msg={:#x}/{:#x}",
        dev.address.segment,
        dev.address.bus,
        dev.address.device,
        dev.address.function,
        vector,
        lpi,
        addr,
        data
    );
    Some(lpi)
}

pub fn configure_msix(dev: &PciDevice, vector: u16) -> Option<u32> {
    configure_msix_affinity(dev, vector, 0)
}

pub fn configure_msi_affinity(
    dev: &PciDevice,
    event: u32,
    cpu: usize,
    handler: fn(u32),
) -> Option<u32> {
    let cap = dev.capability(0x05)?;
    let ctrl = read_u16(dev.address, cap.offset as usize + 2)?;
    let is64 = ctrl & (1 << 7) != 0;
    let (addr, data, lpi) =
        crate::arch::allocate_pci_msi_affinity(dev.address.requester_id(), event, cpu, handler)?;
    let o = cap.offset as usize;
    write_u32(dev.address, o + 4, addr as u32);
    if is64 {
        write_u32(dev.address, o + 8, (addr >> 32) as u32);
        write_u16(dev.address, o + 12, data as u16);
    } else {
        write_u16(dev.address, o + 8, data as u16);
    }
    write_u16(dev.address, o + 2, ctrl | 1);
    let after = read_u16(dev.address, o + 2).unwrap_or(0);
    let alo = read_u32(dev.address, o + 4).unwrap_or(0);
    let ahi = if is64 {
        read_u32(dev.address, o + 8).unwrap_or(0)
    } else {
        0
    };
    let got_data = if is64 {
        read_u16(dev.address, o + 12).unwrap_or(0)
    } else {
        read_u16(dev.address, o + 8).unwrap_or(0)
    };
    crate::info!("pcie: MSI cfg {:04x}:{:02x}:{:02x}.{} cap={:#x} ctrl={:#x}->{:#x} addr={:#x}:{:08x} data={:#x} lpi={}",dev.address.segment,dev.address.bus,dev.address.device,dev.address.function,o,ctrl,after,ahi,alo,got_data,lpi);
    Some(lpi)
}

pub fn configure_msi(dev: &PciDevice, event: u32, handler: fn(u32)) -> Option<u32> {
    configure_msi_affinity(dev, event, 0, handler)
}

fn edu_msi_self_test() {
    let Some(dev) = find(0x1234, 0x11e8) else {
        return;
    };
    let Some(base) = bar_mmio_ptr(&dev, 0, 0, 0x100000) else {
        crate::warn!("pcie: EDU BAR0 not mappable");
        return;
    };
    let cmd = read_u16(dev.address, 0x04).unwrap_or(0);
    let _ = write_u16(dev.address, 0x04, (cmd | 0x2 | 0x4) | (1 << 10)); // MEM + BusMaster + INTx disable
    EDU_MMIO.store(base, Ordering::Release);
    let Some(lpi) = configure_msi(&dev, 0, edu_msi_handler) else {
        crate::warn!("pcie: EDU MSI configure failed");
        return;
    };
    let pending = unsafe {
        write_volatile((base + 0x60) as *mut u32, 0x55aa);
        read_volatile((base + 0x24) as *const u32)
    };
    crate::info!(
        "pcie: EDU MSI triggered requester={:#x} lpi={} pending={:#x}",
        dev.address.requester_id(),
        lpi,
        pending
    );
}

fn pci_testdev_self_test() {
    let Some(dev) = find(0x1b36, 0x0005) else {
        return;
    };
    if dev.bars.len() < 2 || !dev.bars.iter().any(|b| b.index == 1 && b.is_io) {
        return; // iommu-testdev shares the PCI ID but has only BAR0 memory.
    }
    let Some(base) = bar_mmio_ptr(&dev, 0, 0, 0x1000) else {
        crate::warn!("pcie: pci-testdev BAR0 not mappable");
        return;
    };
    let command = read_u16(dev.address, 0x04).unwrap_or(0);
    let _ = write_u16(dev.address, 0x04, command | 0x2);
    unsafe {
        write_volatile(base as *mut u8, 0); // select mmio/no-eventfd
        let rd32bytes = |off: usize| -> u32 {
            let mut b = [0u8; 4];
            for i in 0..4 {
                b[i] = read_volatile((base + off + i) as *const u8);
            }
            u32::from_le_bytes(b)
        };
        let off = rd32bytes(4) as usize;
        let data = read_volatile((base + 8) as *const u8);
        let before = rd32bytes(12);
        if off >= 0x1000 {
            crate::warn!("pcie: pci-testdev malformed test offset {:#x}", off);
            return;
        }
        write_volatile((base + off) as *mut u8, data);
        let after = rd32bytes(12);
        if after == before.wrapping_add(1) {
            crate::info!(
                "pcie: pci-testdev BAR0 MMIO R/W PASS (offset={:#x} count {}->{})",
                off,
                before,
                after
            );
        } else {
            crate::warn!(
                "pcie: pci-testdev BAR0 MMIO R/W FAIL (count {}->{})",
                before,
                after
            );
        }
    }
}

/// Re-read one PCI function after a function/device reset and replace the
/// cached registry entry.  FLR is allowed to reset command/MSI-X/device state;
/// callers must not assume a stale PciDevice snapshot remains authoritative.
pub fn refresh_device(address: PciAddress) -> Option<PciDevice> {
    let fresh = read_device(address)?;
    let mut devices = DEVICES.lock();
    if let Some(slot) = devices.iter_mut().find(|d| d.address == address) {
        *slot = fresh.clone();
    } else {
        devices.push(fresh.clone());
    }
    Some(fresh)
}

pub fn devices() -> Vec<PciDevice> {
    DEVICES.lock().clone()
}
pub fn find(vendor: u16, device: u16) -> Option<PciDevice> {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.vendor_id == vendor && d.device_id == device)
        .cloned()
}
pub fn find_class(class: u8, subclass: u8) -> Vec<PciDevice> {
    DEVICES
        .lock()
        .iter()
        .filter(|d| d.class == class && d.subclass == subclass)
        .cloned()
        .collect()
}
pub fn find_virtio(device_type: u16) -> Vec<PciDevice> {
    // Modern virtio PCI: 0x1af4:0x1040 + device type. Transitional IDs are
    // handled by callers where needed.
    let modern = 0x1040u16.saturating_add(device_type);
    DEVICES
        .lock()
        .iter()
        .filter(|d| d.vendor_id == 0x1af4 && d.device_id == modern)
        .cloned()
        .collect()
}

/// Map a PCI memory BAR through the shared kernel-only ioremap window.
///
/// Never use `phys == virt` for low BARs: Zero OS intentionally gives EL0 a
/// private low-VA domain (heap/SHM overlap the PCI low-MMIO aperture on QEMU).
/// Depending on the current process TTBR0 for PCI register access would make a
/// device disappear whenever that process replaces the inherited identity block.
pub fn bar_mmio_ptr(dev: &PciDevice, bar_index: usize, offset: usize, len: usize) -> Option<usize> {
    let bar = dev.bar(bar_index)?;
    if bar.is_io || len == 0 || offset.checked_add(len)? as u64 > bar.size {
        return None;
    }
    let phys = bar.address.checked_add(offset as u64)? as usize;
    crate::mm::paging::ioremap_device(phys, len)
}

/// Translate a legacy PCI I/O BAR into a CPU-mappable MMIO aperture.
///
/// On AArch64 there are no x86 IN/OUT instructions. UEFI exposes the root bridge
/// host<->PCI I/O translation before ExitBootServices; the loader snapshots it
/// into bootinfo. BAR addresses remain PCI bus I/O addresses, so map them through
/// that window rather than treating the port number as a physical address.
pub fn bar_io_ptr(dev: &PciDevice, bar_index: usize, offset: usize, len: usize) -> Option<usize> {
    let bar = dev.bar(bar_index)?;
    if !bar.is_io || len == 0 || offset.checked_add(len)? as u64 > bar.size {
        return None;
    }
    let win = crate::bootinfo::pci_io_window()?;
    if dev.address.segment != win.segment {
        return None;
    }
    let bar_end = bar.address.checked_add(bar.size)?;
    let win_bus_end = win.bus_base.checked_add(win.len)?;
    if bar.address < win.bus_base || bar_end > win_bus_end {
        crate::warn!(
            "pcie: I/O BAR{} outside root window bus={:#x}+{:#x} bar={:#x}+{:#x}",
            bar.index,
            win.bus_base,
            win.len,
            bar.address,
            bar.size
        );
        return None;
    }
    let delta = bar
        .address
        .checked_sub(win.bus_base)?
        .checked_add(offset as u64)?;
    let phys = win.host_base.checked_add(delta)? as usize;
    crate::mm::paging::ioremap_device(phys, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requester_id_is_bdf() {
        assert_eq!(
            PciAddress {
                segment: 0,
                bus: 0x12,
                device: 3,
                function: 5
            }
            .requester_id(),
            0x121d
        );
    }
    #[test]
    fn ecam_arithmetic_matches_spec() {
        let s = EcamSegment {
            base: 0x3f00_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 15,
        };
        let a = PciAddress {
            segment: 0,
            bus: 2,
            device: 3,
            function: 4,
        };
        assert_eq!(
            config_phys(s, a, 0xabc),
            Some(0x3f00_0000 + (2 << 20) + (3 << 15) + (4 << 12) + 0xabc)
        );
    }
    #[test]
    fn bar_alignment_for_bridge_windows() {
        assert_eq!(align_up_u64(0x1000_1000, 0x2000), Some(0x1000_2000));
        assert_eq!(
            align_up_u64(0x8000_0000_1000, 0x4000),
            Some(0x8000_0000_4000)
        );
        assert_eq!(align_up_u64(7, 3), None);
    }

    #[test]
    fn bar_default_is_empty() {
        assert_eq!(PciBar::default().size, 0);
    }
}
