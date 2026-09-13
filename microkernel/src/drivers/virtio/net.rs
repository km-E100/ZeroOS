//! virtio-net 网络设备驱动（virtio-mmio legacy）。
//! rx 队列 0（64 槽环形预填 RX 缓冲，吸收 TLS/TCP burst），tx 队列 1（单缓冲、非阻塞）。
//!
//! 与 blk 相同约束：EL1 屏蔽 IRQ，RX 完成依赖 EL0 窗口的 IRQ 处理，
//! 因此 poll_receive/transmit 均为轮询/非阻塞接口，不做无界等待。

use alloc::alloc::{alloc_zeroed, Layout};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use zero_abi::driver::DriverDescriptor;

use crate::{debug, info, warn};

use super::super::{register_irq_handler, NetError};
use super::{
    configure_queue, mmio_read32, mmio_write32, negotiate_features_low, probe_device,
    set_driver_ok, VirtQueue, VIRTQ_DESC_F_WRITE,
};

/// Legacy VirtIO PCI exposes a fixed, read-only Queue Size. Parallels net0
/// reports 256 entries for both RX/TX, so use the full transport size on all
/// backends; modern VirtIO can still negotiate down when a device advertises less.
const RX_QUEUE_SIZE: usize = 256;
const TX_QUEUE_SIZE: usize = 256;
const MAX_FRAME: usize = 1536;
const LEGACY_NET_HDR_LEN: usize = 10;
const MODERN_NET_HDR_LEN: usize = 12;
const NET_HDR_MAX: usize = MODERN_NET_HDR_LEN;
const BUFFER_LEN: usize = NET_HDR_MAX + MAX_FRAME;
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const REG_CONFIG: usize = 0x100;
const DEVICE_ID_NET: u32 = 1;

struct VirtioNetState {
    base: usize,
    ready: bool,
    rx_queue: Option<VirtQueue<RX_QUEUE_SIZE>>,
    tx_queue: Option<VirtQueue<TX_QUEUE_SIZE>>,
    rx_buffers: *mut u8,
    rx_lengths: [u16; RX_QUEUE_SIZE],
    tx_buffer: *mut u8,
    tx_inflight: bool,
    mac: [u8; 6],
    hdr_len: usize,
}

impl VirtioNetState {
    const fn new() -> Self {
        Self {
            base: 0,
            ready: false,
            rx_queue: None,
            tx_queue: None,
            rx_buffers: ptr::null_mut(),
            rx_lengths: [u16::MAX; RX_QUEUE_SIZE],
            tx_buffer: ptr::null_mut(),
            tx_inflight: false,
            mac: [0; 6],
            hdr_len: LEGACY_NET_HDR_LEN,
        }
    }
}

unsafe impl Send for VirtioNetState {}

static STATE: Mutex<VirtioNetState> = Mutex::new(VirtioNetState::new());
static TX_SUBMITS: AtomicU64 = AtomicU64::new(0);
static TX_COMPLETIONS: AtomicU64 = AtomicU64::new(0);
static RX_COMPLETIONS: AtomicU64 = AtomicU64::new(0);

pub fn init(descriptor: &DriverDescriptor) {
    let base = descriptor.mmio_base as usize;
    unsafe {
        let version = super::transport_version(base);
        crate::info!("virtio-net: transport version={}", version);
        STATE.lock().hdr_len = if version >= 2 {
            MODERN_NET_HDR_LEN
        } else {
            LEGACY_NET_HDR_LEN
        };
        if mmio_read32(base, 0x008) == 0 {
            return;
        }
        if !probe_device(base, DEVICE_ID_NET, "virtio-net") {
            return;
        }
        let Some(features) = negotiate_features_low(base, VIRTIO_NET_F_MAC) else {
            warn!("driver: virtio-net 特征协商失败 @ {:#x}", base);
            return;
        };
        if features & VIRTIO_NET_F_MAC != 0 {
            let mut mac = [0u8; 6];
            for (i, b) in mac.iter_mut().enumerate() {
                *b = super::transport_read8(base, REG_CONFIG + i);
            }
            crate::info!(
                "virtio-net: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
            STATE.lock().mac = mac;
        }
    }

    let mut state = STATE.lock();
    state.base = base;
    match unsafe { configure_queue::<RX_QUEUE_SIZE>(base, 0) } {
        Some(queue) => state.rx_queue = Some(queue),
        None => {
            warn!("driver: virtio-net RX 队列配置失败 @ {:#x}", base);
            return;
        }
    }
    if !init_rx_buffers(&mut state) {
        return;
    }
    match unsafe { configure_queue::<TX_QUEUE_SIZE>(base, 1) } {
        Some(queue) => state.tx_queue = Some(queue),
        None => {
            warn!("driver: virtio-net TX 队列配置失败 @ {:#x}", base);
            return;
        }
    }
    if !init_tx_buffer(&mut state) {
        return;
    }
    if let Some(q) = state.rx_queue.as_ref() {
        let (d, a, u, idx, r0) = q.debug_layout();
        crate::info!(
            "virtio-net: RX q desc={:#x} avail={:#x} used={:#x} idx={} ring0={}",
            d,
            a,
            u,
            idx,
            r0
        );
    }
    if let Some(q) = state.tx_queue.as_ref() {
        let (d, a, u, idx, r0) = q.debug_layout();
        crate::info!(
            "virtio-net: TX q desc={:#x} avail={:#x} used={:#x} idx={} ring0={}",
            d,
            a,
            u,
            idx,
            r0
        );
    }
    state.ready = true;
    drop(state);

    if descriptor.irq != 0 {
        register_irq_handler(descriptor.irq, irq_handler);
    } else {
        crate::info!("virtio-net: polling transport (no IRQ route)");
    }
    unsafe { set_driver_ok(base) };
    info!(
        "driver: virtio-net 初始化完成 (base=0x{:016x} irq={})",
        base, descriptor.irq
    );
}

pub fn is_ready() -> bool {
    STATE.lock().ready
}

/// Device MAC negotiated through VIRTIO_NET_F_MAC.
pub fn mac_address() -> Option<[u8; 6]> {
    let s = STATE.lock();
    (s.ready && s.mac != [0; 6]).then_some(s.mac)
}

/// Read-only transport/queue snapshot for platform bring-up.
pub fn diagnostic_snapshot() -> Option<zero_abi::driver::NetDriverDiag> {
    let state = STATE.lock();
    if !state.ready {
        return None;
    }
    unsafe {
        let base = state.base;
        let transport_version = super::transport_version(base);
        let device_status = mmio_read32(base, 0x070);
        mmio_write32(base, 0x030, 0);
        let rx_queue_size = mmio_read32(base, 0x034) as u16;
        let rx_queue_pfn = mmio_read32(base, 0x040);
        mmio_write32(base, 0x030, 1);
        let tx_queue_size = mmio_read32(base, 0x034) as u16;
        let tx_queue_pfn = mmio_read32(base, 0x040);
        mmio_write32(base, 0x030, 0);
        Some(zero_abi::driver::NetDriverDiag {
            transport_version,
            device_status,
            rx_queue_size,
            tx_queue_size,
            rx_queue_pfn,
            tx_queue_pfn,
            tx_submits: TX_SUBMITS.load(Ordering::Relaxed),
            tx_completions: TX_COMPLETIONS.load(Ordering::Relaxed),
            rx_completions: RX_COMPLETIONS.load(Ordering::Relaxed),
            mac: state.mac,
            reserved: [0; 2],
        })
    }
}

/// 主动收割 used ring。IRQ handler 与 syscall 轮询路径共用：网络正确性
/// 不依赖中断一定及时到达（QEMU/真机均允许 interrupt suppression/coalescing）。
fn reap_completions(state: &mut VirtioNetState) {
    if let Some(rx_queue) = state.rx_queue.as_mut() {
        let mut idxs = [0u16; RX_QUEUE_SIZE];
        let mut lens = [0u16; RX_QUEUE_SIZE];
        let mut count = 0usize;
        while let Some(elem) = rx_queue.pop_used() {
            let before = RX_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
            if before == 0 {
                crate::info!(
                    "virtio-net: FIRST RX COMPLETE id={} len={}",
                    elem.id,
                    elem.len
                );
            }
            if count < RX_QUEUE_SIZE {
                idxs[count] = elem.id as u16;
                lens[count] = elem.len.min(u16::MAX as u32) as u16;
                count += 1;
            }
        }
        for i in 0..count {
            let slot = idxs[i] as usize;
            if slot < RX_QUEUE_SIZE {
                state.rx_lengths[slot] = lens[i];
            }
        }
    }
    if let Some(tx_queue) = state.tx_queue.as_mut() {
        let mut completed = false;
        while let Some(elem) = tx_queue.pop_used() {
            let before = TX_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
            if before == 0 {
                crate::info!(
                    "virtio-net: FIRST TX COMPLETE id={} len={}",
                    elem.id,
                    elem.len
                );
            }
            completed = true;
        }
        if completed {
            state.tx_inflight = false;
        }
    }
}

/// 发送一帧：非阻塞。上一帧未完成（tx_inflight）时先主动收割 used ring；
/// 仍未完成才返回 Busy。这样 IRQ 是低延迟优化，不是正确性前提。
pub fn transmit(frame: &[u8]) -> Result<(), NetError> {
    if frame.is_empty() {
        return Ok(());
    }
    if frame.len() > MAX_FRAME {
        return Err(NetError::BufferTooSmall);
    }

    let mut state = STATE.lock();
    if !state.ready {
        return Err(NetError::NotReady);
    }
    reap_completions(&mut state);
    if state.tx_inflight {
        return Err(NetError::Busy);
    }
    let tx_buffer = state.tx_buffer;
    if tx_buffer.is_null() {
        return Err(NetError::DeviceError);
    }
    unsafe {
        let hdr_len = state.hdr_len;
        ptr::write_bytes(tx_buffer, 0, hdr_len);
        ptr::copy_nonoverlapping(frame.as_ptr(), tx_buffer.add(hdr_len), frame.len());
    }
    {
        let hdr_len = state.hdr_len;
        let queue = state.tx_queue.as_mut().ok_or(NetError::DeviceError)?;
        unsafe {
            let desc = queue.desc;
            (*desc).addr = tx_buffer as u64;
            (*desc).len = (hdr_len + frame.len()) as u32;
            (*desc).flags = 0;
            (*desc).next = 0;
            // push 内部负责 dmb oshst + 通知。
            queue.push(0);
            let before = TX_SUBMITS.fetch_add(1, Ordering::Relaxed);
            if before == 0 {
                crate::info!(
                    "virtio-net: FIRST TX SUBMIT frame={} total={} hdr={}",
                    frame.len(),
                    hdr_len + frame.len(),
                    hdr_len
                );
            }
        }
    }
    state.tx_inflight = true;
    Ok(())
}

/// 轮询收取一帧：缓冲区太小时返回 BufferTooSmall；
/// 无可用帧返回 None。
pub fn poll_receive(buffer: &mut [u8]) -> Result<Option<usize>, NetError> {
    let mut state = STATE.lock();
    if !state.ready {
        return Err(NetError::NotReady);
    }
    if state.rx_buffers.is_null() {
        return Err(NetError::DeviceError);
    }
    if state.rx_queue.is_none() {
        return Err(NetError::DeviceError);
    }
    reap_completions(&mut state);

    for idx in 0..RX_QUEUE_SIZE {
        let len = state.rx_lengths[idx];
        if len != u16::MAX {
            let total = len as usize;
            let hdr_len = state.hdr_len;
            if total < hdr_len {
                state.rx_lengths[idx] = u16::MAX;
                if let Some(queue) = state.rx_queue.as_mut() {
                    queue.push(idx as u16);
                }
                return Err(NetError::DeviceError);
            }
            let len_usize = total - hdr_len;
            if buffer.len() < len_usize {
                return Err(NetError::BufferTooSmall);
            }
            unsafe {
                let src = state.rx_buffers.add(idx * BUFFER_LEN + hdr_len);
                ptr::copy_nonoverlapping(src, buffer.as_mut_ptr(), len_usize);
            }
            state.rx_lengths[idx] = u16::MAX;
            if let Some(queue) = state.rx_queue.as_mut() {
                // 归还缓冲：把该槽位重新推入可用环。
                queue.push(idx as u16);
            }
            return Ok(Some(len_usize));
        }
    }

    Ok(None)
}

/// 分配 RX 缓冲池，预填描述符并全部推入可用环。
fn init_rx_buffers(state: &mut VirtioNetState) -> bool {
    let buffer_layout = match Layout::from_size_align(RX_QUEUE_SIZE * BUFFER_LEN, 64) {
        Ok(layout) => layout,
        Err(_) => {
            warn!("virtio-net: RX 缓冲布局非法");
            return false;
        }
    };
    let buffers = unsafe { alloc_zeroed(buffer_layout) };
    if buffers.is_null() {
        warn!(
            "virtio-net: RX 缓冲分配失败 (bytes={})",
            RX_QUEUE_SIZE * BUFFER_LEN
        );
        return false;
    }
    state.rx_buffers = buffers;
    state.rx_lengths = [u16::MAX; RX_QUEUE_SIZE];

    let Some(queue) = state.rx_queue.as_mut() else {
        warn!("virtio-net: RX 队列未配置");
        return false;
    };
    unsafe {
        for idx in 0..queue.queue_size as usize {
            let buffer = buffers.add(idx * BUFFER_LEN);
            let desc = queue.desc;
            (*desc.add(idx)).addr = buffer as u64;
            (*desc.add(idx)).len = BUFFER_LEN as u32;
            (*desc.add(idx)).flags = VIRTQ_DESC_F_WRITE;
            (*desc.add(idx)).next = 0;
        }
        for idx in 0..queue.queue_size as usize {
            queue.push(idx as u16);
        }
    }
    debug!("virtio-net: RX 缓冲就绪 ({} 槽)", queue.queue_size);
    true
}

/// 分配单 TX 缓冲。
fn init_tx_buffer(state: &mut VirtioNetState) -> bool {
    let buffer_layout = match Layout::from_size_align(BUFFER_LEN, 64) {
        Ok(layout) => layout,
        Err(_) => {
            warn!("virtio-net: TX 缓冲布局非法");
            return false;
        }
    };
    let buffer = unsafe { alloc_zeroed(buffer_layout) };
    if buffer.is_null() {
        warn!("virtio-net: TX 缓冲分配失败");
        return false;
    }
    state.tx_buffer = buffer;
    state.tx_inflight = false;
    true
}

fn irq_handler(_irq: u32) {
    let mut state = STATE.lock();
    if !state.ready {
        debug!("virtio::net::irq_handler: 尚未初始化");
        return;
    }
    unsafe {
        let status = mmio_read32(state.base, super::REG_INTERRUPT_STATUS);
        if status != 0 {
            mmio_write32(state.base, super::REG_INTERRUPT_ACK, status);
        }
    }

    // IRQ 只负责低延迟触发；实际 used-ring 收割与 syscall 轮询共用同一实现。
    reap_completions(&mut state);
}
