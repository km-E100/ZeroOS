//! virtio-net 网络设备驱动（virtio-mmio legacy）。
//! rx 队列 0（环形预填 RX 缓冲），tx 队列 1（单缓冲、非阻塞）。
//!
//! 与 blk 相同约束：EL1 屏蔽 IRQ，RX 完成依赖 EL0 窗口的 IRQ 处理，
//! 因此 poll_receive/transmit 均为轮询/非阻塞接口，不做无界等待。

use alloc::alloc::{alloc_zeroed, Layout};
use core::ptr;
use spin::Mutex;
use zero_abi::driver::DriverDescriptor;

use crate::{debug, info, warn};

use super::super::{register_irq_handler, NetError};
use super::{
    configure_queue, mmio_read32, mmio_write32, negotiate_features, probe_device, set_driver_ok,
    VirtQueue, VIRTQ_DESC_F_WRITE,
};

const RX_QUEUE_SIZE: usize = 8;
const TX_QUEUE_SIZE: usize = 8;
const MAX_FRAME: usize = 1536;
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
        }
    }
}

unsafe impl Send for VirtioNetState {}

static STATE: Mutex<VirtioNetState> = Mutex::new(VirtioNetState::new());

pub fn init(descriptor: &DriverDescriptor) {
    let base = descriptor.mmio_base as usize;
    unsafe {
        if !probe_device(base, DEVICE_ID_NET, "virtio-net") {
            return;
        }
        if !negotiate_features(base) {
            warn!("driver: virtio-net 特征协商失败 @ {:#x}", base);
            return;
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
    state.ready = true;
    drop(state);

    register_irq_handler(descriptor.irq, irq_handler);
    unsafe { set_driver_ok(base) };
    info!("driver: virtio-net 初始化完成 (base=0x{:016x} irq={})", base, descriptor.irq);
}

pub fn is_ready() -> bool {
    STATE.lock().ready
}

/// 发送一帧：非阻塞。上一帧未完成（tx_inflight）时返回 Busy，
/// 调用方稍后重试即可，不在此等待。
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
    if state.tx_inflight {
        return Err(NetError::Busy);
    }
    let tx_buffer = state.tx_buffer;
    if tx_buffer.is_null() {
        return Err(NetError::DeviceError);
    }
    unsafe {
        ptr::copy_nonoverlapping(frame.as_ptr(), tx_buffer, frame.len());
    }
    {
        let queue = state.tx_queue.as_mut().ok_or(NetError::DeviceError)?;
        unsafe {
            let desc = queue.desc;
            (*desc).addr = tx_buffer as u64;
            (*desc).len = frame.len() as u32;
            (*desc).flags = 0;
            (*desc).next = 0;
            // push 内部负责 dmb oshst + 通知。
            queue.push(0);
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

    for idx in 0..RX_QUEUE_SIZE {
        let len = state.rx_lengths[idx];
        if len != u16::MAX {
            let len_usize = len as usize;
            if buffer.len() < len_usize {
                return Err(NetError::BufferTooSmall);
            }
            unsafe {
                let src = state.rx_buffers.add(idx * MAX_FRAME);
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
    let buffer_layout = match Layout::from_size_align(RX_QUEUE_SIZE * MAX_FRAME, 64) {
        Ok(layout) => layout,
        Err(_) => {
            warn!("virtio-net: RX 缓冲布局非法");
            return false;
        }
    };
    let buffers = unsafe { alloc_zeroed(buffer_layout) };
    if buffers.is_null() {
        warn!("virtio-net: RX 缓冲分配失败 (bytes={})", RX_QUEUE_SIZE * MAX_FRAME);
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
            let buffer = buffers.add(idx * MAX_FRAME);
            let desc = queue.desc;
            (*desc.add(idx)).addr = buffer as u64;
            (*desc.add(idx)).len = MAX_FRAME as u32;
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
    let buffer_layout = match Layout::from_size_align(MAX_FRAME, 64) {
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

    // RX：把新到的帧长度记录到槽位，等待 poll_receive 取走。
    if let Some(rx_queue) = state.rx_queue.as_mut() {
        let mut idxs = [0u16; RX_QUEUE_SIZE];
        let mut lens = [0u16; RX_QUEUE_SIZE];
        let mut count = 0usize;
        while let Some(elem) = rx_queue.pop_used() {
            if count < RX_QUEUE_SIZE {
                idxs[count] = elem.id as u16;
                lens[count] = elem.len as u16;
                count += 1;
            }
        }
        for i in 0..count {
            let slot = (idxs[i] as usize) % RX_QUEUE_SIZE;
            state.rx_lengths[slot] = lens[i];
        }
    }

    // TX：上一帧已完成，放行下一次 transmit。
    if let Some(tx_queue) = state.tx_queue.as_mut() {
        let mut completed = false;
        while let Some(_) = tx_queue.pop_used() {
            completed = true;
        }
        if completed {
            state.tx_inflight = false;
        }
    }
}
