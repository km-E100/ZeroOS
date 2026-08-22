//! 物理页分配器：位图 + 对称性校验。
//!
//! 算法核心在 `phys_bitmap.rs`（纯模块，可 host 单测）；本文件负责
//! 全局实例（静态位图 + 自旋锁）与页表页占用统计。
//!
//! 硬性契约（违反即 panic）：
//! - `free_page` 只接受分配器发过的、页对齐的、非保留区物理地址；
//!   double-free / 释放保留区 / 越界都会 panic（见 `PhysBitmap::free_page`）。
//! - 页表页通过 `alloc_page_table` / `free_page_table` 分配回收，
//!   与普通数据页共用位图，但单独计数（`page_table_pages()`）。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

pub use super::phys_bitmap::{PhysBitmap, PAGE_SIZE};

const MAX_PAGES: usize = 1024 * 1024; // 4 GiB / 4KiB pages (upper bound)

/// QEMU virt 机器的 RAM 物理基址（1GiB 内存时区间为 0x4000_0000..0x8000_0000）。
/// 此前分配器把物理地址 0 当作 RAM 起点，分配出的"物理页"全部落在
/// 固件/MMIO 空洞（0x1007000 等），用户数据写进去被静默丢弃。
pub const RAM_BASE: usize = 0x4000_0000;

static BITMAP_WORDS: [u64; MAX_PAGES / 64] = [0; MAX_PAGES / 64];
static MM: Mutex<PhysBitmap> = Mutex::new(PhysBitmap::empty());
static INITIALISED: AtomicBool = AtomicBool::new(false);

/// 分配给页表用途的页数（L0/L1/L2/L3 表），与数据页共用位图但单独统计，
/// 供诊断与未来配额使用。
static PAGE_TABLE_PAGES: AtomicUsize = AtomicUsize::new(0);

pub fn init(memory_bytes: usize, reserved_bytes: usize) {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }
    let total = usize::min(memory_bytes / PAGE_SIZE, MAX_PAGES);
    let reserved =
        usize::min(reserved_bytes / PAGE_SIZE, total).max(1);
    let mut mm = MM.lock();
    unsafe {
        mm.init(BITMAP_WORDS.as_ptr() as *mut u64, BITMAP_WORDS.len(), RAM_BASE, total, reserved);
    }
}

/// 分配一页物理内存，返回物理地址；无空闲页返回 None。
pub fn alloc_page() -> Option<usize> {
    MM.lock().alloc_page()
}

/// 分配 `count` 个**物理连续**的页，返回首页物理地址。
/// 用于 bootfs 等"以首页基址 + 页偏移寻址"的场景。
/// `count == 0` 返回 None（与 alloc_page 一致的空分配语义）。
pub fn alloc_pages_contiguous(count: usize) -> Option<usize> {
    MM.lock().alloc_contiguous(count)
}

/// 释放一页物理内存。对称性/越界/double-free 校验见 `PhysBitmap::free_page`。
pub fn free_page(addr: usize) {
    MM.lock().free_page(addr);
}

/// 分配一页用作**页表**（计入页表页占用统计）。
pub fn alloc_page_table() -> Option<usize> {
    let page = alloc_page()?;
    PAGE_TABLE_PAGES.fetch_add(1, Ordering::SeqCst);
    Some(page)
}

/// 释放一页**页表**页（同步扣减页表页占用统计）。
pub fn free_page_table(addr: usize) {
    free_page(addr);
    PAGE_TABLE_PAGES.fetch_sub(1, Ordering::SeqCst);
}

pub fn free_pages() -> usize {
    MM.lock().free_count()
}

pub fn page_table_pages() -> usize {
    PAGE_TABLE_PAGES.load(Ordering::SeqCst)
}

pub fn total_pages() -> usize {
    MM.lock().total_pages()
}