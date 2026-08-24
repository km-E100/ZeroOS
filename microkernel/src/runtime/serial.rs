use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

const UART_BASE: usize = 0x0900_0000;
const UART_DR: usize = UART_BASE + 0x00;
const UART_FR: usize = UART_BASE + 0x18;
/// bit5 = TXFF（TX FIFO 满）。
const FR_TXFF: u32 = 1 << 5;
const UART_IBRD: usize = UART_BASE + 0x24;
const UART_FBRD: usize = UART_BASE + 0x28;
const UART_LCRH: usize = UART_BASE + 0x2c;
const UART_CR: usize = UART_BASE + 0x30;
const UART_IMSC: usize = UART_BASE + 0x38;

static TX_LOCK: Mutex<()> = Mutex::new(());

pub fn init() {
    unsafe {
        // 禁用 UART
        write_volatile(UART_CR as *mut u32, 0);
        // 屏蔽所有中断
        write_volatile(UART_IMSC as *mut u32, 0);
        // 设置波特率 (假定 24MHz 时钟，115200)
        write_volatile(UART_IBRD as *mut u32, 13);
        write_volatile(UART_FBRD as *mut u32, 2);
        // 8 位数据 + 使能 FIFO（FEN=bit4）：无 FIFO 时易溢出丢字符。
        write_volatile(UART_LCRH as *mut u32, (3 << 5) | (1 << 4));
        // 启动 UART (TX/RX)
        write_volatile(UART_CR as *mut u32, (1 << 0) | (1 << 8) | (1 << 9));
    }
}

pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

pub fn write_bytes(bytes: &[u8]) {
    let _guard = TX_LOCK.lock();
    write_bytes_unlocked(bytes);
}

pub fn write_byte(byte: u8) {
    let _guard = TX_LOCK.lock();
    write_byte_unlocked(byte);
}

fn write_bytes_unlocked(bytes: &[u8]) {
    for &byte in bytes {
        if byte == b'\n' {
            write_byte_unlocked(b'\r');
        }
        write_byte_unlocked(byte);
    }
}

fn write_byte_unlocked(byte: u8) {
    unsafe {
        // 有界等待 TX FIFO 腾空：内核日志完整性优先于极端情形下的微秒级
        // 延迟；上限防止硬件异常时卡死执行流（与 pl011 驱动同策略）。
        let mut retries = 100_000usize;
        while retries > 0 && read_volatile(UART_FR as *const u32) & FR_TXFF != 0 {
            retries -= 1;
            core::hint::spin_loop();
        }
        write_volatile(UART_DR as *mut u32, byte as u32);
    }
}

struct RawSerialSink;

impl Write for RawSerialSink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_bytes_unlocked(s.as_bytes());
        Ok(())
    }
}

/// SMP-safe atomic log line: formatting fragments cannot interleave across cores.
pub fn write_fmt_line(args: fmt::Arguments<'_>) {
    let _guard = TX_LOCK.lock();
    let mut sink = RawSerialSink;
    let _ = sink.write_fmt(args);
    write_bytes_unlocked(b"\n");
}
