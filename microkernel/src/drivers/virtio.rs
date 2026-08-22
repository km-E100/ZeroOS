//! virtio-mmio（legacy，version=1）共享核心。
//! blk/net 两个驱动共用的寄存器定义、MMIO 访问、设备探测、
//! 特征协商、virtqueue 布局与内存屏障，集中在此消除三份复制。

use alloc::alloc::{alloc_zeroed, Layout};
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

use crate::{debug, warn};

pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;

const REG_MAGIC: usize = 0x000;
const REG_VERSION: usize = 0x004;
const REG_DEVICE_ID: usize = 0x008;
const REG_VENDOR_ID: usize = 0x00c;
const REG_STATUS: usize = 0x070;
const REG_DRIVER_FEATURES: usize = 0x020;
const REG_DRIVER_FEATURES_SEL: usize = 0x024;
const REG_QUEUE_SEL: usize = 0x030;
const REG_QUEUE_NUM_MAX: usize = 0x034;
const REG_QUEUE_NUM: usize = 0x038;
const REG_QUEUE_ALIGN: usize = 0x03c;
const REG_QUEUE_PFN: usize = 0x040;
const REG_QUEUE_NOTIFY: usize = 0x050;
const REG_INTERRUPT_STATUS: usize = 0x060;
const REG_INTERRUPT_ACK: usize = 0x064;

pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

/// 队列内存 4K 页（与 REG_QUEUE_ALIGN=4096 一致）。
const PAGE_SHIFT: u32 = 12;

/// 期望的 virtio-mmio 版本（legacy）。
const VIRTIO_MMIO_VERSION: u32 = 1;
/// "virt" 魔数。
const VIRTIO_MAGIC: u32 = 0x7472_6976;

#[repr(C)]
pub struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
pub struct VirtqAvail<const N: usize> {
    flags: u16,
    idx: u16,
    ring: [u16; N],
    event: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
pub struct VirtqUsed<const N: usize> {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; N],
    event: u16,
}

pub unsafe fn mmio_read32(base: usize, offset: usize) -> u32 {
    read_volatile((base + offset) as *const u32)
}

pub unsafe fn mmio_write32(base: usize, offset: usize, value: u32) {
    write_volatile((base + offset) as *mut u32, value);
}

/// virtqueue：desc/avail/used 三段共享内存 + 驱动侧游标。
pub struct VirtQueue<const N: usize> {
    base: usize,
    queue_index: u32,
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail<N>,
    used: *mut VirtqUsed<N>,
    queue_size: u16,
    avail_idx: u16,
    last_used_idx: u16,
}

impl<const N: usize> VirtQueue<N> {
    /// 向可用环发布一个描述符链头并通知设备。
    /// 屏障：写描述符/avail 前 dmb oshst，保证设备侧可见。
    pub fn push(&mut self, head: u16) {
        unsafe {
            let avail = &mut *self.avail;
            avail.ring[(self.avail_idx % self.queue_size) as usize] = head;
            dmb_oshst();
            self.avail_idx = self.avail_idx.wrapping_add(1);
            avail.idx = self.avail_idx;
            dmb_oshst();
            mmio_write32(self.base, REG_QUEUE_NOTIFY, self.queue_index);
        }
    }

    /// 取出一个已完成的 used 元素。
    /// 屏障：读 used.idx 与元素前 dmb oshld，保证看到设备写入。
    pub fn pop_used(&mut self) -> Option<VirtqUsedElem> {
        unsafe {
            let used = &*self.used;
            dmb_oshld();
            if self.last_used_idx == used.idx {
                return None;
            }
            dmb_oshld();
            let elem = used.ring[(self.last_used_idx % self.queue_size) as usize];
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            Some(elem)
        }
    }
}

#[inline(always)]
fn dmb_oshst() {
    unsafe { asm!("dmb oshst", options(nostack)); }
}

#[inline(always)]
fn dmb_oshld() {
    unsafe { asm!("dmb oshld", options(nostack)); }
}

/// 探测设备：校验魔数/版本/设备类型。失败返回 false 并告警一行。
pub unsafe fn probe_device(base: usize, expected_device_id: u32, what: &str) -> bool {
    let magic = mmio_read32(base, REG_MAGIC);
    let version = mmio_read32(base, REG_VERSION);
    let device_id = mmio_read32(base, REG_DEVICE_ID);
    let vendor_id = mmio_read32(base, REG_VENDOR_ID);
    debug!(
        "driver: {} mmio @ {:#x}: magic={:#x} version={} device_id={:#x} vendor={:#x}",
        what, base, magic, version, device_id, vendor_id
    );
    if magic != VIRTIO_MAGIC {
        warn!("driver: {} mmio @ {:#x} 魔数非法 {:#x}", what, base, magic);
        return false;
    }
    if version != VIRTIO_MMIO_VERSION {
        warn!("driver: {} mmio @ {:#x} 版本 {}/{} 不支持", what, base, version, VIRTIO_MMIO_VERSION);
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

/// 特征协商：ACKNOWLEDGE → DRIVER → 特征清零 → FEATURES_OK → 设备回读校验。
/// 返回设备是否接受协商结果。
pub unsafe fn negotiate_features(base: usize) -> bool {
    mmio_write32(base, REG_STATUS, 0);
    mmio_write32(base, REG_STATUS, STATUS_ACKNOWLEDGE);
    let mut status = STATUS_ACKNOWLEDGE | STATUS_DRIVER;
    mmio_write32(base, REG_STATUS, status);
    // 仅用 legacy 基础功能，无需协商任何特征位。
    mmio_write32(base, REG_DRIVER_FEATURES_SEL, 0);
    mmio_write32(base, REG_DRIVER_FEATURES, 0);
    status |= STATUS_FEATURES_OK;
    mmio_write32(base, REG_STATUS, status);
    mmio_read32(base, REG_STATUS) & STATUS_FEATURES_OK != 0
}

/// 设备就绪：写 DRIVER_OK（须在队列配置与 IRQ 注册之后）。
pub unsafe fn set_driver_ok(base: usize) {
    let mut status = mmio_read32(base, REG_STATUS);
    status |= STATUS_DRIVER_OK;
    mmio_write32(base, REG_STATUS, status);
}

/// 配置一个 virtqueue（blk: 0；net: rx=0、tx=1）。
/// 校验：队列可用性（QUEUE_NUM_MAX>0）、virtqueue 大小（2 的幂）；
/// 分配 4K 对齐的 desc/avail/used 连续内存并写入 QUEUE_NUM/QUEUE_PFN。
pub unsafe fn configure_queue<const N: usize>(
    base: usize,
    queue_index: u32,
) -> Option<VirtQueue<N>> {
    // legacy virtio-mmio 必须先写 QUEUE_SEL 再操作队列寄存器。
    // （旧实现漏写，tx 队列实际读写的是队列 0 的配置。）
    mmio_write32(base, REG_QUEUE_SEL, queue_index);
    // 重新配置前必须清零 QUEUE_NUM。
    mmio_write32(base, REG_QUEUE_NUM, 0);

    let max_size = mmio_read32(base, REG_QUEUE_NUM_MAX);
    if max_size == 0 {
        warn!("virtio: 队列 {} 不可用 (QUEUE_NUM_MAX=0)", queue_index);
        return None;
    }
    let queue_size = (N as u32).min(max_size);
    if queue_size == 0 || !queue_size.is_power_of_two() {
        warn!("virtio: 队列 {} 大小非法 {}", queue_index, queue_size);
        return None;
    }
    mmio_write32(base, REG_QUEUE_ALIGN, 4096);

    let n = queue_size as usize;
    let desc_bytes = size_of::<VirtqDesc>() * n;
    let avail_offset = align_up(desc_bytes, 16);
    let used_offset = align_up(avail_offset + size_of::<VirtqAvail<N>>(), 4096);
    let total_size = used_offset + size_of::<VirtqUsed<N>>();
    let layout = match Layout::from_size_align(total_size, 4096) {
        Ok(layout) => layout,
        Err(_) => {
            warn!("virtio: 队列 {} 布局非法 (size={})", queue_index, total_size);
            return None;
        }
    };
    let mem = alloc_zeroed(layout);
    if mem.is_null() {
        warn!("virtio: 队列 {} 内存分配失败 (bytes={})", queue_index, total_size);
        return None;
    }
    let desc = mem as *mut VirtqDesc;
    let avail = mem.add(avail_offset) as *mut VirtqAvail<N>;
    let used = mem.add(used_offset) as *mut VirtqUsed<N>;

    mmio_write32(base, REG_QUEUE_NUM, queue_size);
    mmio_write32(base, REG_QUEUE_PFN, (mem as usize >> PAGE_SHIFT) as u32);
    debug!(
        "virtio: 队列 {} size={} desc={:#x} avail={:#x} used={:#x}",
        queue_index,
        queue_size,
        desc as usize,
        avail as usize,
        used as usize
    );

    Some(VirtQueue {
        base,
        queue_index,
        desc,
        avail,
        used,
        queue_size: queue_size as u16,
        avail_idx: 0,
        last_used_idx: 0,
    })
}

fn align_up(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value + mask) & !mask
}

pub mod blk;
pub mod net;
