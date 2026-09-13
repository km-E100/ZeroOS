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
///
/// 降级语义（本轮改造）：heap_alloc 在 OOM 时返回 null（不再自旋），
/// core 分配路径（`alloc::vec`/`Box`…）把 null 升级为对 handler 的调用。
/// 本 handler **只打这一行摘要**（不刷屏），随后转入统一 `panic!`
/// 出口——panic=abort 下等效内核停机，但与一切致命错误共用同一条日志
/// 格式与故障位置记录，而非在 handler 里静默绕过 panic 机制。可优雅
/// 失败的调用方应在分配点用 fallible API 感知 null，而不是落到本出口。
#[alloc_error_handler]
fn zero_oom(layout: core::alloc::Layout) -> ! {
    zero_microkernel::runtime::serial::write_str("\r\n[HEAP OOM] layout size=");
    hex_u64(layout.size() as u64);
    zero_microkernel::runtime::serial::write_str(" align=");
    hex_u64(layout.align() as u64);
    zero_microkernel::runtime::serial::write_str(" phys_free=");
    hex_u64(zero_microkernel::mm::phys::free_pages() as u64);
    zero_microkernel::runtime::serial::write_str("\r\n");
    // no_std + panic=abort：无 unwind 可"catch"，abort 即正确语义；
    // 统一出口保证日志一致（panic 信息带位置，紧随上面一行摘要）。
    panic!("heap allocation failed (details above)");
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
