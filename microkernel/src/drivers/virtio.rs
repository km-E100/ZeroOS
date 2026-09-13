//! VirtIO MMIO shared transport (legacy v1 + modern v2).
//!
//! Existing blk/net devices remain compatible with legacy QEMU slots while newer
//! GPU/input/sound devices can use modern MMIO. Queue memory is one allocation but
//! modern transport receives explicit desc/avail/used addresses.

use crate::{debug, warn};
use alloc::alloc::{alloc_zeroed, Layout};
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};
pub mod pci_transport;

pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;

const REG_MAGIC: usize = 0x000;
const REG_VERSION: usize = 0x004;
const REG_DEVICE_ID: usize = 0x008;
const REG_VENDOR_ID: usize = 0x00c;
const REG_DEVICE_FEATURES: usize = 0x010;
const REG_DEVICE_FEATURES_SEL: usize = 0x014;
const REG_DRIVER_FEATURES: usize = 0x020;
const REG_DRIVER_FEATURES_SEL: usize = 0x024;
const REG_GUEST_PAGE_SIZE: usize = 0x028;
const REG_QUEUE_SEL: usize = 0x030;
const REG_QUEUE_NUM_MAX: usize = 0x034;
const REG_QUEUE_NUM: usize = 0x038;
const REG_QUEUE_ALIGN: usize = 0x03c;
const REG_QUEUE_PFN: usize = 0x040;
const REG_QUEUE_READY: usize = 0x044;
const REG_QUEUE_NOTIFY: usize = 0x050;
pub(crate) const REG_INTERRUPT_STATUS: usize = 0x060;
pub(crate) const REG_INTERRUPT_ACK: usize = 0x064;
const REG_STATUS: usize = 0x070;
const REG_QUEUE_DESC_LOW: usize = 0x080;
const REG_QUEUE_DESC_HIGH: usize = 0x084;
const REG_QUEUE_AVAIL_LOW: usize = 0x090;
const REG_QUEUE_AVAIL_HIGH: usize = 0x094;
const REG_QUEUE_USED_LOW: usize = 0x0a0;
const REG_QUEUE_USED_HIGH: usize = 0x0a4;
const PAGE_SHIFT: u32 = 12;
const VIRTIO_MAGIC: u32 = 0x7472_6976;

#[repr(C)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}
#[repr(C)]
pub struct VirtqAvail<const N: usize> {
    flags: u16,
    idx: u16,
    ring: [u16; N],
    event: u16,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}
#[repr(C)]
pub struct VirtqUsed<const N: usize> {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; N],
    event: u16,
}

pub unsafe fn mmio_read32(base: usize, offset: usize) -> u32 {
    if pci_transport::is_handle(base) {
        pci_transport::read32(base, offset)
    } else {
        read_volatile((base + offset) as *const u32)
    }
}
pub unsafe fn mmio_write32(base: usize, offset: usize, value: u32) {
    if pci_transport::is_handle(base) {
        pci_transport::write32(base, offset, value)
    } else {
        write_volatile((base + offset) as *mut u32, value)
    }
}
pub unsafe fn transport_read8(base: usize, offset: usize) -> u8 {
    if pci_transport::is_handle(base) {
        pci_transport::read8(base, offset)
    } else {
        read_volatile((base + offset) as *const u8)
    }
}
pub unsafe fn transport_version(base: usize) -> u32 {
    mmio_read32(base, REG_VERSION)
}

pub struct VirtQueue<const N: usize> {
    base: usize,
    queue_index: u32,
    notify_offset: u16,
    pub(crate) desc: *mut VirtqDesc,
    avail: *mut VirtqAvail<N>,
    used: *mut VirtqUsed<N>,
    pub(crate) queue_size: u16,
    avail_idx: u16,
    last_used_idx: u16,
}
unsafe impl<const N: usize> Send for VirtQueue<N> {}

impl<const N: usize> VirtQueue<N> {
    pub fn push(&mut self, head: u16) {
        unsafe {
            let avail = &mut *self.avail;
            avail.ring[(self.avail_idx % self.queue_size) as usize] = head;
            dmb_oshst();
            self.avail_idx = self.avail_idx.wrapping_add(1);
            avail.idx = self.avail_idx;
            dmb_oshst();
            if pci_transport::is_handle(self.base) {
                pci_transport::notify_queue(self.base, self.queue_index, self.notify_offset);
            } else {
                mmio_write32(self.base, REG_QUEUE_NOTIFY, self.queue_index);
            }
        }
    }
    /// Suppress used-buffer interrupts for a polling-only queue. We do not
    /// negotiate VIRTIO_F_EVENT_IDX, so avail.flags bit0 is the architectural
    /// VIRTQ_AVAIL_F_NO_INTERRUPT control.
    pub fn suppress_interrupts(&mut self) {
        unsafe {
            (*self.avail).flags |= 1;
            dmb_oshst();
        }
    }
    pub fn pop_used(&mut self) -> Option<VirtqUsedElem> {
        unsafe {
            let used = &*self.used;
            dmb_oshld();
            if self.last_used_idx == used.idx {
                return None;
            }
            dmb_oshld();
            let e = used.ring[(self.last_used_idx % self.queue_size) as usize];
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            Some(e)
        }
    }
    pub fn debug_layout(&self) -> (usize, usize, usize, u16, u16) {
        unsafe {
            let avail = &*self.avail;
            (
                self.desc as usize,
                self.avail as usize,
                self.used as usize,
                avail.idx,
                avail.ring[0],
            )
        }
    }
}

#[inline(always)]
fn dmb_oshst() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("dmb oshst", options(nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
}
#[inline(always)]
fn dmb_oshld() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("dmb oshld", options(nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);
}

pub unsafe fn probe_device(base: usize, expected_device_id: u32, what: &str) -> bool {
    let magic = mmio_read32(base, REG_MAGIC);
    let version = mmio_read32(base, REG_VERSION);
    let device_id = mmio_read32(base, REG_DEVICE_ID);
    let vendor = mmio_read32(base, REG_VENDOR_ID);
    debug!(
        "driver: {} mmio @ {:#x}: magic={:#x} version={} device_id={:#x} vendor={:#x}",
        what, base, magic, version, device_id, vendor
    );
    if magic != VIRTIO_MAGIC {
        warn!("driver: {} mmio @ {:#x} 魔数非法 {:#x}", what, base, magic);
        return false;
    }
    if version != 1 && version != 2 {
        warn!(
            "driver: {} mmio @ {:#x} version {} unsupported",
            what, base, version
        );
        return false;
    }
    if device_id != expected_device_id {
        warn!(
            "driver: {} mmio @ {:#x} 设备类型不符 (期望 {:#x}，实际 {:#x})",
            what, base, expected_device_id, device_id
        );
        return false;
    }
    true
}

/// Negotiate only transport-mandatory bits; device drivers may add features later.
pub unsafe fn negotiate_features(base: usize) -> bool {
    negotiate_features_low(base, 0).is_some()
}

/// Negotiate requested device-specific low 32-bit features plus the mandatory
/// VERSION_1 transport bit on modern devices. Returns the accepted low mask.
pub unsafe fn negotiate_features_low(base: usize, wanted_low: u32) -> Option<u32> {
    mmio_write32(base, REG_STATUS, 0);
    mmio_write32(base, REG_STATUS, STATUS_ACKNOWLEDGE);
    let mut status = STATUS_ACKNOWLEDGE | STATUS_DRIVER;
    mmio_write32(base, REG_STATUS, status);
    let version = mmio_read32(base, REG_VERSION);

    mmio_write32(base, REG_DEVICE_FEATURES_SEL, 0);
    let offered_low = mmio_read32(base, REG_DEVICE_FEATURES);
    let accepted_low = wanted_low & offered_low;
    mmio_write32(base, REG_DRIVER_FEATURES_SEL, 0);
    mmio_write32(base, REG_DRIVER_FEATURES, accepted_low);

    if version == 2 {
        mmio_write32(base, REG_DEVICE_FEATURES_SEL, 1);
        if mmio_read32(base, REG_DEVICE_FEATURES) & 1 == 0 {
            warn!("virtio: modern device missing VERSION_1");
            return None;
        }
        mmio_write32(base, REG_DRIVER_FEATURES_SEL, 1);
        mmio_write32(base, REG_DRIVER_FEATURES, 1);
    }
    // FEATURES_OK belongs to the modern 1.0 transport. Legacy PCI/MMIO
    // completes feature negotiation by proceeding directly to DRIVER_OK; old
    // transitional devices may legally ignore this status bit.
    if version == 2 {
        status |= STATUS_FEATURES_OK;
        mmio_write32(base, REG_STATUS, status);
        if mmio_read32(base, REG_STATUS) & STATUS_FEATURES_OK == 0 {
            return None;
        }
    }
    Some(accepted_low)
}

pub unsafe fn set_driver_ok(base: usize) {
    let s = mmio_read32(base, REG_STATUS) | STATUS_DRIVER_OK;
    mmio_write32(base, REG_STATUS, s)
}

pub unsafe fn configure_queue<const N: usize>(
    base: usize,
    queue_index: u32,
) -> Option<VirtQueue<N>> {
    let version = mmio_read32(base, REG_VERSION);
    mmio_write32(base, REG_QUEUE_SEL, queue_index);
    let notify_offset = if pci_transport::is_handle(base) {
        pci_transport::queue_notify_offset(base)
    } else {
        0
    };
    if version == 2 {
        if mmio_read32(base, REG_QUEUE_READY) != 0 {
            warn!("virtio: queue {} already ready", queue_index);
            return None;
        }
    } else {
        mmio_write32(base, REG_QUEUE_NUM, 0)
    }
    let max = mmio_read32(base, REG_QUEUE_NUM_MAX);
    if max == 0 {
        return None;
    }
    // Legacy PCI has no queue-size negotiation: the device's queue_size is the
    // exact ring geometry. Modern PCI and virtio-mmio may use a smaller queue.
    let q = if pci_transport::is_legacy_pci(base) {
        if max > N as u32 {
            warn!(
                "virtio: legacy PCI queue {} requires {} entries but driver capacity is {}",
                queue_index, max, N
            );
            return None;
        }
        max
    } else {
        (N as u32).min(max)
    };
    if q == 0 || !q.is_power_of_two() {
        return None;
    }
    if version == 1 {
        // Legacy virtio-mmio QueuePFN is expressed in units of GuestPageSize.
        // The PCI legacy facade treats these two synthetic registers as no-ops.
        mmio_write32(base, REG_GUEST_PAGE_SIZE, 4096);
        mmio_write32(base, REG_QUEUE_ALIGN, 4096)
    }
    let n = q as usize;
    let desc_bytes = size_of::<VirtqDesc>() * n;
    let avail_off = align_up(desc_bytes, 16);
    let used_off = align_up(avail_off + size_of::<VirtqAvail<N>>(), 4096);
    let total = used_off + size_of::<VirtqUsed<N>>();
    let layout = Layout::from_size_align(total, 4096).ok()?;
    let mem = alloc_zeroed(layout);
    if mem.is_null() {
        return None;
    }
    let desc = mem as *mut VirtqDesc;
    let avail = mem.add(avail_off) as *mut VirtqAvail<N>;
    let used = mem.add(used_off) as *mut VirtqUsed<N>;
    mmio_write32(base, REG_QUEUE_NUM, q);
    if version == 1 {
        let pfn = legacy_queue_pfn(mem as usize, 1usize << PAGE_SHIFT);
        mmio_write32(base, REG_QUEUE_PFN, pfn);
        crate::info!(
            "virtio: legacy queue={} max={} size={} pfn={:#x} mem={:#x}",
            queue_index,
            max,
            q,
            pfn,
            mem as usize
        );
    } else {
        write_u64_pair(base, REG_QUEUE_DESC_LOW, REG_QUEUE_DESC_HIGH, desc as u64);
        write_u64_pair(
            base,
            REG_QUEUE_AVAIL_LOW,
            REG_QUEUE_AVAIL_HIGH,
            avail as u64,
        );
        write_u64_pair(base, REG_QUEUE_USED_LOW, REG_QUEUE_USED_HIGH, used as u64);
        mmio_write32(base, REG_QUEUE_READY, 1);
    }
    debug!(
        "virtio: v{} queue {} size={} desc={:#x} avail={:#x} used={:#x}",
        version, queue_index, q, desc as usize, avail as usize, used as usize
    );
    Some(VirtQueue {
        base,
        queue_index,
        notify_offset,
        desc,
        avail,
        used,
        queue_size: q as u16,
        avail_idx: 0,
        last_used_idx: 0,
    })
}

#[inline]
unsafe fn write_u64_pair(base: usize, lo: usize, hi: usize, v: u64) {
    mmio_write32(base, lo, v as u32);
    mmio_write32(base, hi, (v >> 32) as u32)
}
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

#[inline]
fn legacy_queue_pfn(addr: usize, guest_page_size: usize) -> u32 {
    (addr / guest_page_size) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queue_layout_alignment() {
        assert_eq!(align_up(31, 16), 32);
        assert_eq!(align_up(4097, 4096), 8192)
    }
    #[test]
    fn transport_feature_bit_is_32() {
        assert_eq!(VIRTIO_F_VERSION_1, 0x1_0000_0000)
    }
    #[test]
    fn legacy_pfn_uses_negotiated_guest_page_size() {
        assert_eq!(legacy_queue_pfn(0x4145_0000, 4096), 0x41450);
    }
    #[test]
    fn descriptor_layout_is_spec() {
        assert_eq!(size_of::<VirtqDesc>(), 16);
        assert_eq!(size_of::<VirtqUsedElem>(), 8)
    }
}

pub mod blk;
pub mod gpu;
pub mod input;
pub mod net;
pub mod rng;
pub mod sound;
