//! 上次崩溃日志取回（穷人版 pstore 的引导侧镜像协议）。
//!
//! 布局常量与 microkernel/src/debug/pstore.rs **严格一致**；两侧各自
//! 内联，避免为几个数字引入跨 crate 构建依赖（模式照抄
//! kernel_loader.rs 的 symbol_sink 镜像）。改动任一侧必须同步另一侧。
//!
//! 时序契约：real_entry 最早期调用 recover_previous() —— 必须先于任何
//! 可能重用窗口内存的分配（内核段加载、rootfs、bootinfo 等）：
//!   1) magic 有效 => 打印 "[pstore] previous crash log:" + 有序内容到
//!      控制台（QEMU virt 下 UEFI ConOut 镜像到串口，重启后第一屏即可
//!      看到上次死因），随后**清 magic** 防止重复打印；
//!   2) 用 AllocateAddress 把窗口从 UEFI 分配器手里占住，防止后续
//!      中期分配落在窗口上、与本次启动内核的 pstore 写入互踩
//!      （打印已完成，即使固件把页清零也无碍——magic 已消费）。

use core::ptr::{read_volatile, write_volatile};
use uefi::table::boot::{AllocateType, BootServices, MemoryType};

/// 窗口物理基址：QEMU virt RAM 内、实测内核镜像之外（debug 镜像末尾
/// ≈0x410D1000 ≈ 17 MiB；初版 0x4100_0000 被内核 BSS 段覆盖，已上移，
/// 详见 microkernel/src/debug/pstore.rs 模块文档「窗口与布局」）。
const PSTORE_BASE: u64 = 0x4200_0000;
/// 窗口总容量（字节）＝ microkernel debug::pstore::PSTORE_SIZE。
const PSTORE_SIZE: usize = 64 * 1024;
/// 头部：magic(u64) + seq(u32) + wr(u32)，全小端。
const HEADER_LEN: usize = 0x10;
/// 环形缓冲区容量（字节）。
const RING_LEN: usize = PSTORE_SIZE - HEADER_LEN;
/// 有效标志，ASCII "ZPST101\0"。
const MAGIC: u64 = u64::from_le_bytes(*b"ZPST101\0");

/// 启动早期入口：重放上次崩溃日志，然后为本次启动占住窗口。
pub fn recover_previous(bs: &BootServices) {
    replay_previous();
    reserve_window(bs);
}

fn rd_u32(base: *const u8, off: usize) -> u32 {
    unsafe { read_volatile(base.add(off) as *const u32) }
}

/// magic 有效则打印上次崩溃日志并清 magic；无效静默返回（首次启动 /
/// 已消费 / 窗口被固件清过）。
fn replay_previous() {
    let base = PSTORE_BASE as *const u8;
    let magic = unsafe { read_volatile(base as *const u64) };
    if magic != MAGIC {
        return;
    }
    let seq = rd_u32(base, 0x08);
    let wr = rd_u32(base, 0x0c);
    log_info!("[pstore] previous crash log:");

    // 有序重放（与内核侧 read_plan 同式）：有效长度 n=min(seq,RING)，
    // 最老字节位于 (wr + RING - n) % RING。
    let n = core::cmp::min(seq as usize, RING_LEN);
    let start = (wr as usize + RING_LEN - n) % RING_LEN;

    let mut buf = [0u8; 256];
    let mut blen = 0usize;
    for i in 0..n {
        let byte = unsafe { read_volatile(base.add(HEADER_LEN + (start + i) % RING_LEN)) };
        if byte == b'\n' || blen == buf.len() {
            flush_line(&mut buf, &mut blen);
        }
        if byte != b'\n' && blen < buf.len() {
            buf[blen] = byte;
            blen += 1;
        }
    }
    flush_line(&mut buf, &mut blen);

    // 消费完毕：清 magic 防重复打印。内核下次写入会重新初始化头部。
    unsafe { write_volatile(base as *mut u64, 0u64) };
}

/// 输出一行（UEFI ConOut 在 QEMU virt 上镜像到串口）。非 UTF-8 行降级
/// 为字节数提示——崩溃现场允许任意残迹，绝不因解码失败中断重放。
fn flush_line(buf: &mut [u8], len: &mut usize) {
    if *len == 0 {
        return;
    }
    match core::str::from_utf8(&buf[..*len]) {
        Ok(s) => {
            log_info!("{}", s);
        }
        Err(_) => {
            log_info!("[pstore] (non-utf8 line, {} bytes skipped)", *len);
        }
    }
    *len = 0;
}

/// AllocateAddress 占住窗口：后续内核段/rootfs 等中期分配不再落进来。
/// 失败仅告警——窗口可能已被占用，打印链路不受影响。
fn reserve_window(bs: &BootServices) {
    const PAGES: usize = PSTORE_SIZE / 0x1000;
    match bs.allocate_pages(
        AllocateType::Address(PSTORE_BASE),
        MemoryType::RUNTIME_SERVICES_DATA,
        PAGES,
    ) {
        Ok(_) => {}
        Err(e) => {
            log_warn!(
                "[pstore] window reserve failed: {:?} (continuing)",
                e.status()
            );
        }
    }
}
