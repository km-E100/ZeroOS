//! virtio-blk 块设备驱动（virtio-mmio legacy，queue 0）。
//! 单块 I/O 串行化：一次仅一个请求在途。
//!
//! 完成等待设计：内核在 EL1 全程屏蔽 IRQ（SPSR 只放行 EL0 中断），
//! syscall 路径上的完成等待**不能依赖 irq_handler**——等待线程自己
//! 直接轮询 used 环（QEMU 对 QUEUE_NOTIFY 是同步处理的，通知返回时
//! 完成元素通常已就位）。IRQ 路径保留给未来 EL0 上下文的阻塞等待，
//! 两条路径共用 poll_completion_locked 取结果。
//! 等待仍带界——超时返回错误并复位内部状态（inflight=false +
//! discard_next），迟到的完成元素在任一路径被丢弃，
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
const REG_CONFIG: usize = 0x100;

/// Device completion is asynchronous relative to the vCPU. A raw iteration
/// count made success depend on host/QEMU scheduling speed (QEMU 11.1 could miss
/// a valid completion after ~100k spins). Use the architected monotonic clock as
/// the correctness bound; a generous spin ceiling only protects host/mock misuse.
const IO_TIMEOUT_NS: u64 = 2_000_000_000;
const MAX_POLL_SPINS: usize = 20_000_000;

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
    capacity_sectors: u64,
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
            capacity_sectors: 0,
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
    unsafe {
        let lo = mmio_read32(base, REG_CONFIG) as u64;
        let hi = mmio_read32(base, REG_CONFIG + 4) as u64;
        state.capacity_sectors = lo | (hi << 32);
    }
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
    info!(
        "driver: virtio-blk 初始化完成 (base=0x{:016x} irq={})",
        base, descriptor.irq
    );

    self_test();
}

/// 上电自检：向专用测试扇区写入特征图案，读回逐字节比对。
/// 失败仅告警不阻塞启动（设备保持 ready，交由调用方按错误处理）。
const SELF_TEST_LBA: u64 = 2048; // 1MiB 偏移；避开 userdb（LBA 128）等既有数据

fn self_test() {
    let mut pattern = [0u8; SECTOR_SIZE];
    for (i, byte) in pattern.iter_mut().enumerate() {
        // 与 LBA 相关的确定性图案，全 0 盘也能区分"读到旧数据"与"比对一致"。
        *byte = (i % 251) as u8 ^ (SELF_TEST_LBA as u8);
    }
    if let Err(e) = write_blocks(SELF_TEST_LBA, &pattern) {
        warn!(
            "driver: virtio-blk 自检写入失败 (LBA={}): {:?}",
            SELF_TEST_LBA, e
        );
        return;
    }
    let mut readback = [0u8; SECTOR_SIZE];
    if let Err(e) = read_blocks(SELF_TEST_LBA, &mut readback) {
        warn!(
            "driver: virtio-blk 自检读回失败 (LBA={}): {:?}",
            SELF_TEST_LBA, e
        );
        return;
    }
    if readback != pattern {
        if let Some(off) = readback
            .iter()
            .zip(pattern.iter())
            .position(|(r, p)| r != p)
        {
            warn!(
                "driver: virtio-blk 自检比对不一致 @{} (读 {:02x} 期望 {:02x})",
                off, readback[off], pattern[off]
            );
        } else {
            warn!("driver: virtio-blk 自检比对不一致");
        }
        return;
    }
    info!(
        "driver: virtio-blk 自检通过：LBA {} 写入+读回 {} 字节比对一致",
        SELF_TEST_LBA, SECTOR_SIZE
    );
}

pub fn is_ready() -> bool {
    STATE.lock().ready
}

pub fn capacity_sectors() -> Option<u64> {
    let state = STATE.lock();
    (state.ready && state.capacity_sectors > 0).then_some(state.capacity_sectors)
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
        (*desc.add(1)).flags = if is_read { VIRTQ_DESC_F_WRITE } else { 0 } | VIRTQ_DESC_F_NEXT;
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
    let deadline = crate::time::monotonic_ns().saturating_add(IO_TIMEOUT_NS);
    for _ in 0..MAX_POLL_SPINS {
        {
            let mut state = STATE.lock();
            if !state.inflight {
                return Ok(());
            }
            // Do not make forward progress depend on an IRQ arriving while the
            // caller is runnable; harvest a delayed used-ring element here too.
            poll_completion_locked(&mut state);
            if !state.inflight {
                return Ok(());
            }
        }
        if crate::time::monotonic_ns() >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
    warn!("virtio-blk: 上一次 I/O 在 2s deadline 内未完成，放弃本次请求");
    Err(BlockError::Busy)
}

/// 有界等待完成：最多 COMPLETION_RETRIES 次自旋。
///
/// 内核在 EL1 屏蔽 IRQ，等待线程必须自己轮询设备（见模块头注释）；
/// 若 IRQ 路径抢先完成了请求（EL0 上下文），inflight 已清零则直接取缓存结果。
/// 超时后复位 inflight 并置 discard_next，使后续 I/O 可继续；
/// 迟到的完成元素在任一路径被丢弃，避免污染下一次请求的结果。
fn wait_for_completion() -> Result<usize, BlockError> {
    let deadline = crate::time::monotonic_ns().saturating_add(IO_TIMEOUT_NS);
    for _ in 0..MAX_POLL_SPINS {
        {
            let mut state = STATE.lock();
            // IRQ 路径已完成：直接取缓存结果。
            if !state.inflight {
                return finish_result(&state);
            }
            // 主动轮询：取 used 环 + 应答中断原因。
            poll_completion_locked(&mut state);
            if !state.inflight {
                return finish_result(&state);
            }
        }
        if crate::time::monotonic_ns() >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
    warn!("virtio-blk: 完成等待超过 2s deadline，中止当前 I/O");
    {
        let mut state = STATE.lock();
        state.inflight = false;
        state.discard_next = true;
    }
    Err(BlockError::DeviceError)
}

/// 把缓存的完成结果翻译为返回值：状态字节非 0 视为设备错误。
fn finish_result(state: &VirtioBlkState) -> Result<usize, BlockError> {
    if state.last_status == 0 {
        Ok(state.last_len)
    } else {
        Err(BlockError::DeviceError)
    }
}

/// 在持有 STATE 锁的前提下直接轮询设备完成队列：
/// 取空 used 环（丢弃被超时中止的迟到元素）、读状态字节、ACK 中断原因，
/// 并复位 inflight。返回是否消费到了有效完成元素。
fn poll_completion_locked(state: &mut VirtioBlkState) -> bool {
    let Some(queue) = state.queue.as_mut() else {
        return false;
    };
    let mut length: Option<usize> = None;
    while let Some(elem) = queue.pop_used() {
        if state.discard_next {
            // 迟到的完成：属于被超时中止的请求，丢弃并继续。
            state.discard_next = false;
            continue;
        }
        length = Some(elem.len as usize);
    }
    let Some(len) = length else {
        return false;
    };
    unsafe {
        let status = mmio_read32(state.base, super::REG_INTERRUPT_STATUS);
        if status != 0 {
            mmio_write32(state.base, super::REG_INTERRUPT_ACK, status);
        }
    }
    state.last_status = if state.status_ptr.is_null() {
        0xff
    } else {
        unsafe { ptr::read_volatile(state.status_ptr) }
    };
    state.last_len = len;
    state.inflight = false;
    true
}

fn irq_handler(_irq: u32) {
    let mut state = STATE.lock();
    if !state.ready {
        debug!("virtio::blk::irq_handler: 尚未初始化");
        return;
    }
    // ACK 中断原因（即使无新完成也清标志，防重放），
    // 完成元素统一由 poll_completion_locked 取出。
    unsafe {
        let status = mmio_read32(state.base, super::REG_INTERRUPT_STATUS);
        if status != 0 {
            mmio_write32(state.base, super::REG_INTERRUPT_ACK, status);
        }
    }
    poll_completion_locked(&mut state);
}
