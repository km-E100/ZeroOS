#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate zero_microkernel;

use core::arch::global_asm;

global_asm!(include_str!("../../boot/boot.S"));

mod drivers;
mod rootfs;

/// 堆分配失败的显式出口：编译器默认 handler 以非字符串载荷 panic，
/// 串口上只留下 `<non-string panic payload>`（实机曾因此误判为 rootfs
/// bug）。这里打印失败 Layout 与物理页余量，把 OOM 变成可诊断事件。
#[alloc_error_handler]
fn zero_oom(layout: core::alloc::Layout) -> ! {
    zero_microkernel::runtime::serial::write_str(
        "\r\n[HEAP OOM] layout size=");
    hex_u64(layout.size() as u64);
    zero_microkernel::runtime::serial::write_str(" align=");
    hex_u64(layout.align() as u64);
    zero_microkernel::runtime::serial::write_str(" phys_free=");
    hex_u64(zero_microkernel::mm::phys::free_pages() as u64);
    zero_microkernel::runtime::serial::write_str("\r\n");
    loop {
        core::hint::spin_loop();
    }
}

fn hex_u64(v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    let mut n = v;
    let mut i = buf.len();
    if n == 0 {
        zero_microkernel::runtime::serial::write_bytes(b"0");
        return;
    }
    while n > 0 && i > 0 {
        i -= 1;
        buf[i] = HEX[(n & 0xf) as usize];
        n >>= 4;
    }
    zero_microkernel::runtime::serial::write_bytes(&buf[i..]);
}

#[no_mangle]
pub extern "C" fn __zero_kernel_marker__() {}
