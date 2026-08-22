//! virtio-blk 块设备驱动（virtio-mmio legacy，queue 0）。
//! 单块 I/O 串行化：一次仅一个请求在途。
//!
//! 完成等待约束：内核在 EL1 全程屏蔽 IRQ（SPSR 只放行 EL0 中断），
//! syscall 路径上的完成等待因此必须带界——超时返回错误并复位内部状态
//! （inflight=false + discard_next），迟到的完成元素在 IRQ 路径被丢弃，
//! 保证单次超时后设备与驱动都能继续工作。

use alloc::alloc::{alloc_zeroed, Layout};
use core::cmp::min;
use core::ptr;
use spin::Mutex;
use zero_abi::driver::DriverDescriptor;

use crate::{debug, info, warn};

use super::super::{register_irq_handler, BlockError};
use super::{
    configure_queue, mmio_read32, mmio_write32, negotiate_features, probe_device, set_driver_ok,
    VirtQueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};

const SECTOR_SIZE: usize = 512;
const MAX_TRANSFER: usize = SECTOR_SIZE * 8;
const QUEUE_SIZE: usize = 16;
const DEVICE_ID_BLK: u32 = 2;

/// 完成等待自旋上限。
const COMPLETION_RETRIES: usize = 100_000;
/// 等待上一次 I/O 结束的自旋上限。
const IDLE_RETRIES: usize = 100_000;

#[repr(C)]
struct VirtioBlkReq {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

struct VirtioBlkState {
    base: usize,
    ready: bool,
    queue: Option<VirtQueue<QUEUE_SIZE>>,
    header: *mut VirtioBlkReq,
    status_ptr: *mut u8,
    bounce: *mut u8,
    bounce_len: usize,
    inflight: bool,
    /// 有请求被超时中止：下一个 used 元素属于已中止请求，应丢弃。
    discard_next: bool,
    last_status: u8,
    last_len: usize,
}

impl VirtioBlkState {
    const fn new() -> Self {
        Self {
            base: 0,
            ready: false,
            queue: None,
            header: ptr::null_mut(),
            status_ptr: ptr::null_mut(),
            bounce: ptr::null_mut(),
            bounce_len: 0,
            inflight: false,
            discard_next: false,
            last_status: 0xff,
            last_len: 0,
        }
    }
}

unsafe impl Send for VirtioBlkState {}

static STATE: Mutex<VirtioBlkState> = Mutex::new(VirtioBlkState::new());

pub fn init(descriptor: &DriverDescriptor) {
    let base = descriptor.mmio_base as usize;
    unsafe {
        if !probe_device(base, DEVICE_ID_BLK, "virtio-blk") {
            return;
        }
        if !negotiate_features(base) {
            warn!("driver: virtio-blk 特征协商失败 @ {:#x}", base);
            return;
        }
    }

    let mut state = STATE.lock();
    state.base = base;
    match unsafe { configure_queue::<QUEUE_SIZE>(base, 0) } {
        Some(queue) => state.queue = Some(queue),
        None => {
            warn!("driver: virtio-blk 队列配置失败 @ {:#x}", base);
            return;
        }
    }

    // 请求头 / 状态字节 / 数据弹跳区
    unsafe {
        let header_layout = Layout::from_size_align(size_of::<VirtioBlkReq>(), 16).unwrap();
        let header_ptr = alloc_zeroed(header_layout);
        if header_ptr.is_null() {
            warn!("driver: virtio-blk 请求头分配失败");
            return;
        }
        state.header = header_ptr as *mut VirtioBlkReq;

        let status_ptr = alloc_zeroed(Layout::from_size_align(1, 1).unwrap());
        if status_ptr.is_null() {
            warn!("driver: virtio-blk 状态字节分配失败");
            return;
        }
        state.status_ptr = status_ptr;

        let bounce_ptr = alloc_zeroed(Layout::from_size_align(MAX_TRANSFER, 16).unwrap());
        if bounce_ptr.is_null() {
            warn!("driver: virtio-blk 弹跳区分配失败");
            return;
        }
        state.bounce = bounce_ptr;
        state.bounce_len = MAX_TRANSFER;
    }
    state.ready = true;
    drop(state);

    register_irq_handler(descriptor.irq, irq_handler);
    unsafe { set_driver_ok(base) };
    info!("driver: virtio-blk 初始化完成 (base=0x{:016x} irq={})", base, descriptor.irq);
}

pub fn is_ready() -> bool {
    STATE.lock().ready
}

pub fn read_blocks(lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
    if buffer.is_empty() {
        return Ok(());
    }
    if buffer.len() % SECTOR_SIZE != 0 {
        return Err(BlockError::InvalidArgument);
    }

    let mut processed = 0;
    let mut current_lba = lba;
    while processed < buffer.len() {
        let chunk = min(buffer.len() - processed, MAX_TRANSFER);
        {
            let state = STATE.lock();
            if !state.ready {
                return Err(BlockError::NotReady);
            }
            drop(state);
            // 有界等待上一次请求结束（避免覆盖描述符）。
            wait_idle()?;
            let mut state = STATE.lock();
            prepare_request(&mut state, current_lba, chunk, None, true)?;
        }
        let len = wait_for_completion()?;
        let copy_len = len.min(chunk);
        let state = STATE.lock();
        if state.bounce.is_null() {
            return Err(BlockError::DeviceError);
        }
        unsafe {
            ptr::copy_nonoverlapping(
                state.bounce,
                buffer[processed..processed + copy_len].as_mut_ptr(),
                copy_len,
            );
        }
        processed += chunk;
        current_lba += (chunk / SECTOR_SIZE) as u64;
    }

    Ok(())
}

pub fn write_blocks(lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
    if buffer.is_empty() {
        return Ok(());
    }
    if buffer.len() % SECTOR_SIZE != 0 {
        return Err(BlockError::InvalidArgument);
    }

    let mut processed = 0;
    let mut current_lba = lba;
    while processed < buffer.len() {
        let chunk = min(buffer.len() - processed, MAX_TRANSFER);
        {
            let state = STATE.lock();
            if !state.ready {
                return Err(BlockError::NotReady);
            }
            drop(state);
            wait_idle()?;
            let mut state = STATE.lock();
            prepare_request(
                &mut state,
                current_lba,
                chunk,
                Some(&buffer[processed..processed + chunk]),
                false,
            )?;
        }
        wait_for_completion()?;
        processed += chunk;
        current_lba += (chunk / SECTOR_SIZE) as u64;
    }

    Ok(())
}

/// 组装一个块请求：header/数据/状态三段描述符 + 弹跳区拷贝。
fn prepare_request(
    state: &mut VirtioBlkState,
    lba: u64,
    data_len: usize,
    payload: Option<&[u8]>,
    is_read: bool,
) -> Result<(), BlockError> {
    let Some(queue) = state.queue.as_mut() else {
        return Err(BlockError::DeviceError);
    };
    if state.bounce_len < data_len {
        return Err(BlockError::InvalidArgument);
    }
    if state.header.is_null() || state.status_ptr.is_null() || state.bounce.is_null() {
        return Err(BlockError::DeviceError);
    }

    unsafe {
        if let Some(bytes) = payload {
            ptr::copy_nonoverlapping(bytes.as_ptr(), state.bounce, data_len);
        }
        (*state.header).req_type = if is_read { 0 } else { 1 };
        (*state.header).reserved = 0;
        (*state.header).sector = lba;
        ptr::write_volatile(state.status_ptr, 0xff);

        let desc = queue.desc;
        (*desc.add(0)).addr = state.header as u64;
        (*desc.add(0)).len = size_of::<VirtioBlkReq>() as u32;
        (*desc.add(0)).flags = VIRTQ_DESC_F_NEXT;
        (*desc.add(0)).next = 1;

        (*desc.add(1)).addr = state.bounce as u64;
        (*desc.add(1)).len = data_len as u32;
        (*desc.add(1)).flags =
            if is_read { VIRTQ_DESC_F_WRITE } else { 0 } | VIRTQ_DESC_F_NEXT;
        (*desc.add(1)).next = 2;

        (*desc.add(2)).addr = state.status_ptr as u64;
        (*desc.add(2)).len = 1;
        (*desc.add(2)).flags = VIRTQ_DESC_F_WRITE;
        (*desc.add(2)).next = 0;

        // push 内部负责 dmb oshst + 通知。
        queue.push(0);
    }

    state.last_status = 0xff;
    state.last_len = 0;
    state.inflight = true;
    Ok(())
}

/// 有界等待上一次请求完成。超时返回 Busy（不破坏状态，可稍后重试）。
fn wait_idle() -> Result<(), BlockError> {
    for _ in 0..IDLE_RETRIES {
        if !STATE.lock().inflight {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    warn!("virtio-blk: 上一次 I/O 未完成，放弃本次请求");
    Err(BlockError::Busy)
}

/// 有界等待完成：最多 COMPLETION_RETRIES 次自旋。
/// 超时后复位 inflight 并置 discard_next，使后续 I/O 可继续；
/// 迟到的完成元素在 IRQ 路径被丢弃，避免污染下一次请求的结果。
fn wait_for_completion() -> Result<usize, BlockError> {
    for _ in 0..COMPLETION_RETRIES {
        let (inflight, status, len) = {
            let state = STATE.lock();
            (state.inflight, state.last_status, state.last_len)
        };
        if !inflight {
            return if status == 0 { Ok(len) } else { Err(BlockError::DeviceError) };
        }
        core::hint::spin_loop();
    }
    warn!("virtio-blk: 完成等待超时，中止当前 I/O");
    {
        let mut state = STATE.lock();
        state.inflight = false;
        state.discard_next = true;
    }
    Err(BlockError::DeviceError)
}

fn irq_handler(_irq: u32) {
    let mut state = STATE.lock();
    if !state.ready {
        debug!("virtio::blk::irq_handler: 尚未初始化");
        return;
    }
    unsafe {
        let status = mmio_read32(state.base, super::REG_INTERRUPT_STATUS);
        if status != 0 {
            mmio_write32(state.base, super::super::virtio::REG_INTERRUPT_ACK, status);
        }
    }
    let mut completed = false;
    let mut length = 0usize;
    // 先取出 discard 标志，避免与 queue 的可变借用冲突。
    let mut discard = state.discard_next;
    if let Some(queue) = state.queue.as_mut() {
        while let Some(elem) = queue.pop_used() {
            if discard {
                // 迟到的完成：属于被超时中止的请求，丢弃并等待下一个。
                discard = false;
                continue;
            }
            completed = true;
            length = elem.len as usize;
        }
    }
    state.discard_next = discard;
    if completed {
        state.last_status = if state.status_ptr.is_null() {
            0xff
        } else {
            unsafe { ptr::read_volatile(state.status_ptr) }
        };
        state.last_len = length;
        state.inflight = false;
    }
}
