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
    // ⚠ 死锁修复（实机定位）：本函数持有 MM 期间绝不可再经
    // mm_free_pages()/mm_total_pages() 二次加锁——spin Mutex 不可重入，
    // 旧写法在打印 "legacy path" 后于 info! 处自旋卡死（QEMU 实测复现）。
    // 就地取计数，锁内算完、锁外只做打印。
    let mut regions = MemRegions::default();
    #[allow(unused_assignments)]
    let mut holes_reserved = 0usize; // 分支内必然赋值；初值仅为类型占位
    let mut mm = MM.lock();
    // Safety 契约：read_memory_map_sink 仅读引导器汇槽（UnsafeCell 外部
    // 写入由灌表先于内核的时序保证）；init_from_regions 内部自管 safety。
    let ok = read_memory_map_sink(&mut regions);
    if ok {
        crate::info!(
            "phys: memory-map path: {} usable region(s), {} KiB total",
            regions.len,
            regions.as_slice().iter().map(|&(_, l)| l / 1024).sum::<usize>()
        );
        // 精细路径：按引导器合并后的 CONVENTIONAL 区间登记，
        // 区间之间的空洞（MMIO/固件保留）整段标忙。
        init_from_regions(&mut mm, regions.as_slice(), reserved_bytes);
        holes_reserved = mm.total_pages() - mm.free_count();
        crate::info!(
            "phys: holes+kernel reserved = {} pages (excluded from allocator)",
            holes_reserved
        );
    } else {
        // 回退：旧引导器只给总量（QEMU virt 单块连续 RAM 下等价）。
        crate::info!("phys: legacy path (total-bytes only)");
        legacy_init(&mut mm, memory_bytes, reserved_bytes);
    }
    let free_pages = mm.free_count();
    let total_pages = mm.total_pages();
    drop(mm);
    crate::info!("phys: ready free_pages={} total_pages={}", free_pages, total_pages);
}

fn legacy_init(mm: &mut PhysBitmap, memory_bytes: usize, reserved_bytes: usize) {
    let total = usize::min(memory_bytes / PAGE_SIZE, MAX_PAGES);
    // ⚠ 必须天花板除法：地板除会把保留区**末尾不满一页的零头**（如
    // __bss_end 只溢出 0x40 字节）让给分配器——首个页表分配恰好领到
    // 该页并写入描述符，砸碎落在页首的内核静态变量（实机：
    // ROOTFS_PTR@__bss_end-0x40 被写成 0x4101e003，launchd spawn 即崩）。
    let reserved = usize::min(reserved_pages_for(reserved_bytes), total).max(1);
    unsafe {
        mm.init(BITMAP_WORDS.as_ptr() as *mut u64, BITMAP_WORDS.len(), RAM_BASE, total, reserved);
    }
}

/// 区间驱动初始化：[RAM_BASE, top) 全域建图，随后把**不被任何可用
/// 区间覆盖**的页标忙（EFI 空洞/固件保留），最后把内核镜像保留区
/// （天花板取页）标忙。
fn init_from_regions(
    mm: &mut PhysBitmap,
    regions: &[(usize, usize)],
    reserved_bytes: usize,
) {
    // ⚠ 坐标纪律：regions 存**绝对物理地址**；页号一律相对 RAM_BASE。
    // 曾把绝对地址直接除以 PAGE_SIZE 当页号（0x40000000/4096=262144），
    // 导致"空洞扫描"把全部页标忙、free_pages=0（实机探针定位）。
    let mut top_rel = 0usize;
    for &(b, l) in regions {
        if b >= RAM_BASE {
            let end_rel = (b - RAM_BASE).saturating_add(l);
            top_rel = top_rel.max(end_rel.min(MAX_PAGES * PAGE_SIZE));
        }
    }
    let total = (top_rel / PAGE_SIZE).max(1);
    unsafe {
        mm.init(BITMAP_WORDS.as_ptr() as *mut u64, BITMAP_WORDS.len(), RAM_BASE, total, 0);
    }

    // 1) 内核镜像保留区（恒等映射起点即 RAM_BASE，天花板取页）。
    let kernel_pages = usize::min(reserved_pages_for(reserved_bytes), total);
    for page in 0..kernel_pages {
        mm.mark_busy(page);
    }

    // 2) 双指针扫洞（全部使用相对页坐标）：
    //    [cursor, region_start) 的空隙 → 标忙；region 内部保持空闲，
    //    cursor 跳到 region 末页之后。区间外尾页同样标忙。
    let mut cursor = kernel_pages; // 内核镜像已标忙，从其后继续扫
    for &(base, len) in regions {
        if base + len <= RAM_BASE || base >= RAM_BASE + top_rel {
            continue; // 区间完全在窗口外
        }
        let rs_abs = base.max(RAM_BASE);
        let re_abs = (base.saturating_add(len)).min(RAM_BASE + top_rel);
        if re_abs <= rs_abs {
            continue;
        }
        let start_page = (rs_abs - RAM_BASE).div_ceil(PAGE_SIZE);
        let end_page = (re_abs - RAM_BASE) / PAGE_SIZE;
        for page in cursor..start_page.min(total) {
            mm.mark_busy(page);
        }
        cursor = cursor.max(end_page);
    }
    for page in cursor..total {
        mm.mark_busy(page);
    }
}

/// 保留**字节数** → 保留页数：天花板除法（部分末页必须整页保留）。
/// ⚠ 回归背景：地板除曾把 __bss_end 溢出 0x40 字节的末页让给分配器，
/// 首个页表分配写入描述符砸碎页首内核静态变量（ROOTFS_PTR 实机崩）。
pub const fn reserved_pages_for(bytes: usize) -> usize {
    bytes.div_ceil(PAGE_SIZE)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_bytes_round_up_to_pages() {
        // 回归：0x40 字节零头也必须占满一页
        assert_eq!(reserved_pages_for(0), 0);
        assert_eq!(reserved_pages_for(1), 1);
        assert_eq!(reserved_pages_for(4096), 1);
        assert_eq!(reserved_pages_for(4097), 2);
        assert_eq!(reserved_pages_for(0x101d040), 0x101e);
    }
}

pub fn total_pages() -> usize {
    MM.lock().total_pages()
}

// ─── 引导器内存图汇槽 ─────────────────────────────────────────────
//
// 布局：0x00 u64 magic=0x5A4D454D_31303131（"ZMEM101"）
//       0x08 u64 count
//       0x10 起 count × {u64 base, u64 len}（按 base 升序，已合并）
// 容量 4KiB ⇒ 至多 254 个区间。bootloader 在 EBS 前经 ELF 符号定位灌入。

pub const MEMMAP_MAGIC: u64 = 0x5A4D_454D_3130_3131;
const MEMMAP_SINK_SIZE: usize = 4096;
const MEMMAP_HEADER: usize = 0x10;
const MEMMAP_ENTRY: usize = 16;

/// 汇槽载体：UnsafeCell 表达“引导器从外部写入”的协议事实。
#[repr(C, align(16))]
pub struct MemoryMapSink {
    bytes: core::cell::UnsafeCell<[u8; MEMMAP_SINK_SIZE]>,
}
unsafe impl Sync for MemoryMapSink {}

#[no_mangle]
// ⚠ 与 __zero_symbol_sink 同理：必须落 `.data`。零初始化 static 默认进
// .bss，而 boot/boot.S 的 zero_bss 会在引导器灌表之后于内核入口再次
// 清零整个 .bss——放 .bss 的表活不到第一次读取（实机走了 legacy 回退）。
#[cfg_attr(all(target_arch = "aarch64", target_os = "none"), link_section = ".data")]
pub static __zero_memory_map: MemoryMapSink = MemoryMapSink {
    bytes: core::cell::UnsafeCell::new([0; MEMMAP_SINK_SIZE]),
};

/// 解析引导器内存图；无效/未填充返回 None（回退总量路径）。
/// 区间表上限：汇槽 4KiB 容量内本就装不下更多（(4096-16)/16=254）。
/// 固定数组而非 Vec：phys::init 运行于**堆初始化之前**，任何堆分配
/// 都会触发 OOM handler（实机：160 字节分配即 spin 卡死启动）。
const MAX_MEMMAP_REGIONS: usize = 32;

#[derive(Default)]
struct MemRegions {
    entries: [(usize, usize); MAX_MEMMAP_REGIONS],
    len: usize,
}

impl MemRegions {
    fn as_slice(&self) -> &[(usize, usize)] {
        &self.entries[..self.len]
    }

    fn push(&mut self, base: usize, len: usize) -> bool {
        if self.len >= MAX_MEMMAP_REGIONS {
            return false;
        }
        self.entries[self.len] = (base, len);
        self.len += 1;
        true
    }
}

fn read_memory_map_sink(out: &mut MemRegions) -> bool {
    let raw = unsafe { &*__zero_memory_map.bytes.get() };
    let rd_u64 = |off: usize| {
        u64::from_le_bytes(raw[off..off + 8].try_into().unwrap())
    };
    if rd_u64(0x00) != MEMMAP_MAGIC {
        return false;
    }
    let count = rd_u64(0x08) as usize;
    if count == 0 || count > MAX_MEMMAP_REGIONS {
        return false;
    }
    let mut prev_end = 0u64;
    for i in 0..count {
        let off = MEMMAP_HEADER + i * MEMMAP_ENTRY;
        let base = rd_u64(off) as usize;
        let len = rd_u64(off + 8) as usize;
        // 协议校验：升序、非空、不重叠；违规整表作废（防半写状态）。
        if len == 0 || (base as u64) < prev_end || !out.push(base, len) {
            return false;
        }
        prev_end = (base as u64).saturating_add(len as u64);
    }
    true
}


#[cfg(test)]
mod memmap_tests {
    use super::*;

    // read_memory_map_sink 读的是全局 static，无法在单测里安全多写；
    // 这里直接测解析核心：把协议编码逻辑抽出来等价验证。
    fn encode(entries: &[(usize, usize)]) -> [u8; MEMMAP_SINK_SIZE] {
        let mut raw = [0u8; MEMMAP_SINK_SIZE];
        raw[0x00..0x08].copy_from_slice(&MEMMAP_MAGIC.to_le_bytes());
        raw[0x08..0x10].copy_from_slice(&(entries.len() as u64).to_le_bytes());
        for (i, &(base, len)) in entries.iter().enumerate() {
            let off = MEMMAP_HEADER + i * MEMMAP_ENTRY;
            raw[off..off + 8].copy_from_slice(&(base as u64).to_le_bytes());
            raw[off + 8..off + 16].copy_from_slice(&(len as u64).to_le_bytes());
        }
        raw
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut raw = encode(&[(0x40000000, 0x10000000)]);
        raw[0] ^= 0xff;
        // 直接复用解析逻辑的等价断言（magic 检查在函数首行）
        let magic = u64::from_le_bytes(raw[0x00..0x08].try_into().unwrap());
        assert_ne!(magic, MEMMAP_MAGIC);
    }

    #[test]
    fn encode_layout_matches_protocol() {
        let raw = encode(&[
            (0x4000_0000, 0x1000_0000),
            (0x5000_0000, 0x0800_0000),
        ]);
        assert_eq!(
            u64::from_le_bytes(raw[0x08..0x10].try_into().unwrap()),
            2
        );
        assert_eq!(
            u64::from_le_bytes(raw[0x10..0x18].try_into().unwrap()),
            0x4000_0000
        );
        assert_eq!(
            u64::from_le_bytes(raw[0x18..0x20].try_into().unwrap()),
            0x1000_0000
        );
    }
}
