//! PL011 UART 驱动（QEMU virt @0x09000000，irq 33）。
//! 内核侧负责 RX（console 输入，环形缓冲 + 中断排空）；
//! 启动早期输出走 runtime::serial 直写，与本驱动并存互不干扰。
//!
//! 中断路径约定：IRQ 处理器在屏蔽中断的 EL1 上下文运行，
//! 内部不得做无界等待。TX 写入采用有界轮询，超时丢弃并计数，
//! 绝不拖住中断返回路径。

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use zero_abi::driver::DriverDescriptor;

use crate::{debug, info, warn};

use super::irq::register_irq_handler;

const DR: usize = 0x00;
const FR: usize = 0x18;
const IBRD: usize = 0x24;
const FBRD: usize = 0x28;
const LCRH: usize = 0x2c;
const CR: usize = 0x30;
const IMSC: usize = 0x38;
const MIS: usize = 0x40;
const ICR: usize = 0x44;

const FR_RXFE: u32 = 1 << 4; // RX FIFO 空
const FR_TXFF: u32 = 1 << 5; // TX FIFO 满

const RXIM: u32 = 1 << 4; // RX 数据可用中断
const RTIM: u32 = 1 << 6; // 接收超时中断
/// ICR 写 1 清位：覆盖 RX/RT/OVRN/FE/PE/BE 全部状态位。
const ICR_ALL: u32 = 0x7ff;

/// TX 忙等上限：量级为微秒，宁可丢字节也不阻塞。
const TX_RETRIES: usize = 100_000;
/// 单次 RX 排空上限：防设备异常导致无限循环。
const MAX_RX_DRAIN: usize = 256;

struct State {
    base: usize,
    ready: bool,
    rx_buf: [u8; 256],
    head: usize,
    tail: usize,
}

impl State {
    const fn new() -> Self {
        Self {
            base: 0,
            ready: false,
            rx_buf: [0; 256],
            head: 0,
            tail: 0,
        }
    }
}

static STATE: Mutex<State> = Mutex::new(State::new());

/// 因 TX FIFO 满被丢弃的字节总数（诊断用）。
static TX_DROPPED: AtomicUsize = AtomicUsize::new(0);

/// 初始化 PL011：幂等，重复调用直接返回，
/// 不重复写寄存器、不重复注册 IRQ 处理器。
pub fn init(descriptor: &DriverDescriptor) {
    let base = descriptor.mmio_base as usize;
    {
        let state = STATE.lock();
        if state.ready {
            debug!("pl011::init: 已初始化（幂等返回），base=0x{:016x}", base);
            return;
        }
    }

    unsafe {
        debug!("pl011::init: base=0x{:016x}", base);
        write32(base, CR, 0);
        write32(base, IMSC, 0);
        write32(base, ICR, ICR_ALL);
        write32(base, IBRD, 13);
        write32(base, FBRD, 2);
        write32(base, LCRH, 3 << 5);
        write32(base, CR, (1 << 0) | (1 << 8) | (1 << 9));
        write32(base, IMSC, RXIM | RTIM);
    }

    {
        let mut state = STATE.lock();
        state.base = base;
        state.ready = true;
        state.head = 0;
        state.tail = 0;
    }

    register_irq_handler(descriptor.irq, irq_handler);
    info!("driver: pl011 初始化完成 (irq={})", descriptor.irq);
}

/// 读一个已缓冲的 RX 字节；缓冲区空返回 None。
pub fn read_byte() -> Option<u8> {
    let mut state = STATE.lock();
    if !state.ready || state.head == state.tail {
        return None;
    }
    let byte = state.rx_buf[state.tail % state.rx_buf.len()];
    state.tail = (state.tail + 1) % state.rx_buf.len();
    Some(byte)
}

/// 把缓冲中的 RX 字节批量读入，返回实际读入数。
pub fn read_into(buffer: &mut [u8]) -> usize {
    let mut count = 0;
    for slot in buffer.iter_mut() {
        match read_byte() {
            Some(byte) => {
                *slot = byte;
                count += 1;
            }
            None => break,
        }
    }
    count
}

/// 把缓冲中的 RX 字节逐字节交给回调（console 轮询路径）。
pub fn poll_console<F: FnMut(u8)>(mut sink: F) {
    while let Some(byte) = read_byte() {
        sink(byte);
    }
}

/// 写单个字节：有界等待 TX FIFO 腾空（TXFF 清），超时丢弃并计数。
/// 等待期间不持有锁；调用方应避免在中断路径大量写入。
pub fn write_byte(byte: u8) {
    let base = {
        let state = STATE.lock();
        if !state.ready {
            return;
        }
        state.base
    };
    unsafe {
        for _ in 0..TX_RETRIES {
            if read32(base, FR) & FR_TXFF == 0 {
                write32(base, DR, byte as u32);
                return;
            }
            core::hint::spin_loop();
        }
    }
    let dropped = TX_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
    if dropped == 1 || dropped % 1_000 == 0 {
        warn!("pl011: TX FIFO 满，丢弃字节 (累计 {})", dropped);
    }
}

/// RX 中断处理器：确认中断后把 FIFO 全部排空进环形缓冲，
/// 最后清 ICR（含 OVRN/RT 等状态位），防止中断滞留导致风暴。
fn irq_handler(_irq: u32) {
    let mut state = STATE.lock();
    if !state.ready {
        debug!("pl011::irq_handler: 尚未初始化");
        return;
    }

    unsafe {
        let pending = read32(state.base, MIS);
        if pending & (RXIM | RTIM) != 0 {
            // 有界排空：RXFE 置位即空；上限防设备异常无限循环。
            let mut drained = 0;
            while drained < MAX_RX_DRAIN && read32(state.base, FR) & FR_RXFE == 0 {
                let byte = read32(state.base, DR) as u8;
                let len = state.rx_buf.len();
                let idx = state.head % len;
                state.rx_buf[idx] = byte;
                state.head = (state.head + 1) % len;
                if state.head == state.tail {
                    // 覆盖最旧字节，丢数据但不破坏环形结构。
                    state.tail = (state.tail + 1) % len;
                }
                drained += 1;
            }
        }
        // 写 1 清 0：清掉全部已置位的中断（含 RX 溢出）。
        write32(state.base, ICR, pending & ICR_ALL);
    }
}

unsafe fn read32(base: usize, offset: usize) -> u32 {
    read_volatile((base + offset) as *const u32)
}

unsafe fn write32(base: usize, offset: usize, value: u32) {
    write_volatile((base + offset) as *mut u32, value);
}
