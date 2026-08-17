use core::ptr::{read_volatile, write_volatile};

const UART_BASE: usize = 0x0900_0000;
const UART_DR: usize = UART_BASE + 0x00;
const UART_FR: usize = UART_BASE + 0x18;
const UART_IBRD: usize = UART_BASE + 0x24;
const UART_FBRD: usize = UART_BASE + 0x28;
const UART_LCRH: usize = UART_BASE + 0x2c;
const UART_CR: usize = UART_BASE + 0x30;
const UART_IMSC: usize = UART_BASE + 0x38;

pub fn init() {
    unsafe {
        // 禁用 UART
        write_volatile(UART_CR as *mut u32, 0);
        // 屏蔽所有中断
        write_volatile(UART_IMSC as *mut u32, 0);
        // 设置波特率 (假定 24MHz 时钟，115200)
        write_volatile(UART_IBRD as *mut u32, 13);
        write_volatile(UART_FBRD as *mut u32, 2);
        // 8 位数据，无 FIFO
        write_volatile(UART_LCRH as *mut u32, 3 << 5);
        // 启动 UART (TX/RX)
        write_volatile(UART_CR as *mut u32, (1 << 0) | (1 << 8) | (1 << 9));
    }
}

pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

pub fn write_bytes(bytes: &[u8]) {
    for &byte in bytes {
        if byte == b'\n' {
            write_byte(b'\r');
        }
        write_byte(byte);
    }
}

pub fn write_byte(byte: u8) {
    unsafe {
        // 调试阶段，为彻底排除 UART 等待逻辑导致的卡死，这里不再
        // 轮询 TX FIFO 状态，直接写入数据寄存器。
        // 若 TX 忙，最多只是丢日志，不会阻塞内核执行。
        write_volatile(UART_DR as *mut u32, byte as u32);
    }
}
