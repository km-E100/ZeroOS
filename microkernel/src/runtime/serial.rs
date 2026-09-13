use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

/// PL011 register offsets. The MMIO base is a bootloader-patched platform
/// contract, not an ARM64 architectural constant. A zero base means no early
/// UART is known and every serial operation is a safe no-op.
const UART_DR: usize = 0x00;
const UART_FR: usize = 0x18;
const UART_IBRD: usize = 0x24;
const UART_FBRD: usize = 0x28;
const UART_LCRH: usize = 0x2c;
const UART_CR: usize = 0x30;
const UART_IMSC: usize = 0x38;
/// bit5 = TXFF（TX FIFO 满）。
const FR_TXFF: u32 = 1 << 5;

static TX_LOCK: Mutex<()> = Mutex::new(());

#[inline(always)]
fn uart_base() -> Option<usize> {
    let base = crate::bootinfo::early_uart_base();
    (base != 0).then_some(base)
}

pub fn active() -> bool {
    uart_base().is_some()
}

pub fn init() {
    let Some(base) = uart_base() else {
        return;
    };
    // SPCR means firmware has already configured the serial console. Only the
    // QEMU-virt fallback has a frozen 24MHz clock/divisor contract; other PL011
    // platforms keep the firmware programming and we merely transmit through it.
    if crate::bootinfo::platform_kind() != crate::bootinfo::PLATFORM_QEMU_VIRT {
        return;
    }
    unsafe {
        // 禁用 UART
        write_volatile((base + UART_CR) as *mut u32, 0);
        // 屏蔽所有中断
        write_volatile((base + UART_IMSC) as *mut u32, 0);
        // 设置波特率 (QEMU virt PL011 时钟 24MHz，115200)。未知平台绝不走此路径。
        write_volatile((base + UART_IBRD) as *mut u32, 13);
        write_volatile((base + UART_FBRD) as *mut u32, 2);
        // 8 位数据 + 使能 FIFO（FEN=bit4）。
        write_volatile((base + UART_LCRH) as *mut u32, (3 << 5) | (1 << 4));
        // 启动 UART (TX/RX)
        write_volatile((base + UART_CR) as *mut u32, (1 << 0) | (1 << 8) | (1 << 9));
    }
}

pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

pub fn write_bytes(bytes: &[u8]) {
    if !active() {
        return;
    }
    let _guard = TX_LOCK.lock();
    write_bytes_unlocked(bytes);
}

pub fn write_byte(byte: u8) {
    if !active() {
        return;
    }
    let _guard = TX_LOCK.lock();
    write_byte_unlocked(byte);
}

fn write_bytes_unlocked(bytes: &[u8]) {
    if !active() {
        return;
    }
    for &byte in bytes {
        if byte == b'\n' {
            write_byte_unlocked(b'\r');
        }
        write_byte_unlocked(byte);
    }
}

fn write_byte_unlocked(byte: u8) {
    let Some(base) = uart_base() else {
        return;
    };
    unsafe {
        let mut retries = 100_000usize;
        while retries > 0 && read_volatile((base + UART_FR) as *const u32) & FR_TXFF != 0 {
            retries -= 1;
            core::hint::spin_loop();
        }
        write_volatile((base + UART_DR) as *mut u32, byte as u32);
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
    if !active() {
        return;
    }
    let _guard = TX_LOCK.lock();
    let mut sink = RawSerialSink;
    let _ = sink.write_fmt(args);
    write_bytes_unlocked(b"\n");
}
