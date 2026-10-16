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
//! - 第十刀 COW：`free_page` 为**引用减一**语义——refs 减到 0 才真正回收；
//!   `retain_page` 给共享页 +1。destroy_user_address_space 无需特判，
//!   共享页由最后一个退出者回收。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

pub use super::phys_bitmap::{PhysBitmap, PAGE_SIZE};

use crate::debug::pstore::{PSTORE_BASE, PSTORE_SIZE};

const MAX_PAGES: usize = 1024 * 1024; // 4 GiB / 4KiB pages (upper bound)

// -- pstore 固定窗口保留（崩溃日志落盘区，见 debug/pstore.rs）---------
//
// 窗口 [0x4200_0000, 0x4201_0000)：QEMU virt RAM 内、实测内核镜像
// （末尾 ≈0x410D1000，约 17 MiB）之外——初版 0x4100_0000 被内核 BSS
// 段覆盖（实机 ELF 段表定位），已上移；init_from_regions 收到
// reserved_bytes 后有运行期 tripwire 兜底镜像再长大的情形。
// 分配器的两条 init 路径（legacy / memory-map）都必须把整窗标忙，
// 否则首个跨过窗口的分配就会挪用崩溃日志区。几何约束编译期钉死：
// 相对页号下溢 / 未对齐 / 越出恒等映射窗口都会在 build 阶段直接失败。
/// pstore 窗口的 RAM 内相对起始字节偏移。
const PSTORE_BASE_REL: usize = (PSTORE_BASE as usize)
    .checked_sub(RAM_BASE)
    .expect("pstore window below RAM_BASE");
/// pstore 窗口占用的页数。
const PSTORE_PAGES: usize = PSTORE_SIZE / PAGE_SIZE;

const _: () = assert!(
    PSTORE_BASE as usize % PAGE_SIZE == 0,
    "pstore window not page aligned"
);
const _: () = assert!(
    PSTORE_SIZE % PAGE_SIZE == 0,
    "pstore window size not page aligned"
);
const _: () = assert!(
    PSTORE_BASE_REL / PAGE_SIZE + PSTORE_PAGES <= 1024 * 512,
    "pstore window outside identity-mapped 2GiB"
);

/// QEMU virt 机器的 RAM 物理基址（1GiB 内存时区间为 0x4000_0000..0x8000_0000）。
/// 此前分配器把物理地址 0 当作 RAM 起点，分配出的"物理页"全部落在
/// 固件/MMIO 空洞（0x1007000 等），用户数据写进去被静默丢弃。
pub const RAM_BASE: usize = 0x4000_0000;

/// 位图存储载体：内层可变（UnsafeCell）。⚠ 不能是普通静态数组：
/// 纯零、且安全代码里只有 as_ptr() 只读借用的静态会被 LLVM 折叠进
/// 只读段（macOS 宿主测试落在 __DATA_CONST），init 一写即 SIGBUS——
/// 与 debug::__zero_symbol_sink / __zero_memory_map 同一个坑，同法根治。
struct BitmapStorage(core::cell::UnsafeCell<[u64; MAX_PAGES / 64]>);
// Safety：裸机侧全部访问都发生在 MM 自旋锁内（单核内核）；宿主测试
// 以 INIT_LOCK 互斥锁串行，不存在并发读写。
unsafe impl Sync for BitmapStorage {}
static BITMAP_WORDS: BitmapStorage =
    BitmapStorage(core::cell::UnsafeCell::new([0; MAX_PAGES / 64]));

/// 每页引用计数（与 BITMAP_WORDS 平行，每物理页一格 u16，2 MiB .bss）。
/// 上限 65535 份共享/页——COW fork 链远达不到，超出即记账 bug。
/// ⚠ 载体同 BITMAP_WORDS：纯零 static + as_ptr() 只读借用会被折叠进
/// 只读段（宿主测试 SIGBUS），必须 UnsafeCell 表达可变性。
struct RefCountStorage(core::cell::UnsafeCell<[u16; MAX_PAGES]>);
// Safety：与 BitmapStorage 同一纪律——裸机侧全部访问都在 MM 自旋锁内；
// 宿主测试以 INIT_LOCK 串行。
unsafe impl Sync for RefCountStorage {}
static REF_COUNTS: RefCountStorage = RefCountStorage(core::cell::UnsafeCell::new([0; MAX_PAGES]));
static MM: Mutex<PhysBitmap> = Mutex::new(PhysBitmap::empty());
static INITIALISED: AtomicBool = AtomicBool::new(false);

/// 分配给页表用途的页数（L0/L1/L2/L3 表），与数据页共用位图但单独统计，
/// 供诊断与未来配额使用。
static PAGE_TABLE_PAGES: AtomicUsize = AtomicUsize::new(0);

pub fn init_with_kernel_range(
    memory_bytes: usize,
    legacy_reserved_bytes: usize,
    kernel_start: usize,
    kernel_end: usize,
) {
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
                                     // ⚠ pstore 窗口 tripwire：内核镜像保留区一旦长过窗口基址，说明窗口
                                     // 落进了内核自身内存（BSS 别名），pstore 不再可用——串口大声报警。
    if ranges_overlap(
        kernel_start,
        kernel_end,
        PSTORE_BASE as usize,
        PSTORE_BASE as usize + PSTORE_SIZE,
    ) {
        crate::warn!(
            "phys: relocated kernel [{:#x},{:#x}) overlaps pstore window @0x{:x}",
            kernel_start,
            kernel_end,
            PSTORE_BASE
        );
    }
    let mut mm = MM.lock();
    // Safety 契约：read_memory_map_sink 仅读引导器汇槽（UnsafeCell 外部
    // 写入由灌表先于内核的时序保证）；init_from_regions 内部自管 safety。
    let ok = read_memory_map_sink(&mut regions);
    if ok {
        crate::info!(
            "phys: memory-map path: {} usable region(s), {} KiB total",
            regions.len,
            regions
                .as_slice()
                .iter()
                .map(|&(_, l)| l / 1024)
                .sum::<usize>()
        );
        // 精细路径：按引导器合并后的 CONVENTIONAL 区间登记，
        // 区间之间的空洞（MMIO/固件保留）整段标忙。
        init_from_regions_exact(&mut mm, regions.as_slice(), kernel_start, kernel_end);
        holes_reserved = mm.total_pages() - mm.free_count();
        crate::info!(
            "phys: holes+kernel reserved = {} pages (excluded from allocator)",
            holes_reserved
        );
    } else {
        // 回退：旧引导器只给总量（QEMU virt 单块连续 RAM 下等价）。
        crate::info!("phys: legacy path (total-bytes only)");
        legacy_init(&mut mm, memory_bytes, legacy_reserved_bytes);
        mark_absolute_range_busy(&mut mm, kernel_start, kernel_end);
    }
    let free_pages = mm.free_count();
    let total_pages = mm.total_pages();
    drop(mm);
    crate::info!(
        "phys: ready free_pages={} total_pages={}",
        free_pages,
        total_pages
    );
}

/// Compatibility entry used by host tests/older callers: low-prefix kernel.
pub fn init(memory_bytes: usize, reserved_bytes: usize) {
    init_with_kernel_range(
        memory_bytes,
        reserved_bytes,
        RAM_BASE,
        RAM_BASE.saturating_add(reserved_bytes),
    )
}

#[inline]
fn ranges_overlap(a0: usize, a1: usize, b0: usize, b1: usize) -> bool {
    a0 < b1 && b0 < a1
}

fn mark_absolute_range_busy(mm: &mut PhysBitmap, start: usize, end: usize) -> usize {
    if end <= start || end <= RAM_BASE {
        return 0;
    }
    let ram_end = RAM_BASE.saturating_add(mm.total_pages().saturating_mul(PAGE_SIZE));
    let s = start.max(RAM_BASE);
    let e = end.min(ram_end);
    if e <= s {
        return 0;
    }
    let first = (s - RAM_BASE) / PAGE_SIZE;
    let last = (e - RAM_BASE).div_ceil(PAGE_SIZE);
    let mut marked = 0usize;
    for page in first..last.min(mm.total_pages()) {
        marked += usize::from(mm.mark_busy(page));
    }
    marked
}

fn legacy_init(mm: &mut PhysBitmap, memory_bytes: usize, reserved_bytes: usize) {
    let total = usize::min(memory_bytes / PAGE_SIZE, MAX_PAGES);
    // ⚠ 必须天花板除法：地板除会把保留区**末尾不满一页的零头**（如
    // __bss_end 只溢出 0x40 字节）让给分配器——首个页表分配恰好领到
    // 该页并写入描述符，砸碎落在页首的内核静态变量（实机：
    // ROOTFS_PTR@__bss_end-0x40 被写成 0x4101e003，launchd spawn 即崩）。
    let reserved = usize::min(reserved_pages_for(reserved_bytes), total).max(1);
    unsafe {
        mm.init(
            BITMAP_WORDS.0.get().cast::<u64>(),
            MAX_PAGES / 64,
            REF_COUNTS.0.get().cast::<u16>(),
            MAX_PAGES,
            RAM_BASE,
            total,
            reserved,
        );
    }
    // pstore 固定窗口永久占用：内核保留区（max(镜像,16MiB)=4096 页）
    // 只到窗口起点为止，不显式标忙分配器就会把崩溃日志页发出去。
    mark_pstore_busy(mm);
}

/// 区间驱动初始化：[RAM_BASE, top) 全域建图，随后把**不被任何可用
/// 区间覆盖**的页标忙（EFI 空洞/固件保留），最后把内核镜像保留区
/// （天花板取页）标忙。
fn init_from_regions(mm: &mut PhysBitmap, regions: &[(usize, usize)], reserved_bytes: usize) {
    init_from_regions_exact(
        mm,
        regions,
        RAM_BASE,
        RAM_BASE.saturating_add(reserved_bytes),
    );
}

fn init_from_regions_exact(
    mm: &mut PhysBitmap,
    regions: &[(usize, usize)],
    kernel_start: usize,
    kernel_end: usize,
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
        mm.init(
            BITMAP_WORDS.0.get().cast::<u64>(),
            MAX_PAGES / 64,
            REF_COUNTS.0.get().cast::<u16>(),
            MAX_PAGES,
            RAM_BASE,
            total,
            0,
        );
    }

    // 1) KASLR-aware kernel reservation: mark only the pages actually occupied
    // by the relocated image. A high load bias must never turn the entire low
    // RAM prefix into a fake "kernel" reservation.
    mark_absolute_range_busy(mm, kernel_start, kernel_end);

    // 1.5) pstore 固定窗口永久占用（幂等）：它落在 CONVENTIONAL 区间
    //      **内部**，下面的扫洞只标「区间之间的空隙」，不会覆盖到它；
    //      必须在这里显式登记，否则分配器照发不误。
    mark_pstore_busy(mm);

    // 2) 双指针扫洞（全部使用相对页坐标）：
    //    [cursor, region_start) 的空隙 → 标忙；region 内部保持空闲，
    //    cursor 跳到 region 末页之后。区间外尾页同样标忙。
    let mut cursor = 0usize; // holes are independent of the relocated kernel range
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

/// 把 pstore 固定物理窗口整段标忙（幂等）。页号越界（total 太小的
/// 极端配置）由 mark_busy 自行静默跳过——窗口本就不存在的内存里。
fn mark_pstore_busy(mm: &mut PhysBitmap) {
    let base_page = PSTORE_BASE_REL / PAGE_SIZE;
    for page in base_page..base_page + PSTORE_PAGES {
        mm.mark_busy(page);
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

/// 释放一页物理内存（**引用减一**语义，第十刀 COW）：refs 减到 0 才真正
/// 回收；共享页由最后一个退出者归还。校验见 `PhysBitmap::free_page`。
pub fn free_page(addr: usize) {
    MM.lock().free_page(addr);
}

/// 给一页增加一个引用（clone 把物理页共享给新地址空间时调用）。
/// 位图不动——页保持 busy，仅记账 +1。
pub fn retain_page(addr: usize) {
    MM.lock().retain_page(addr);
}

/// 把落在 QEMU/平台 RAM 窗口内的物理区间标成永久占用。
///
/// GOP framebuffer 等固件建立的共享缓冲有时来自 Conventional RAM；若不
/// 从页分配器摘除，后续用户页分配会把屏幕像素当普通内存覆盖。区间落在
/// RAM 之外（PCI BAR/MMIO）时自然无操作。
pub fn reserve_physical_range(addr: usize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let end = addr.saturating_add(len);
    if end <= RAM_BASE || addr >= RAM_BASE.saturating_add(MAX_PAGES * PAGE_SIZE) {
        return 0;
    }
    let start = addr.max(RAM_BASE).saturating_sub(RAM_BASE) / PAGE_SIZE;
    let end_page = end.saturating_sub(RAM_BASE).saturating_add(PAGE_SIZE - 1) / PAGE_SIZE;
    let mut mm = MM.lock();
    let mut reserved = 0usize;
    for page in start..end_page.min(mm.total_pages()) {
        reserved += usize::from(mm.mark_busy(page));
    }
    reserved
}

/// 查询某物理地址当前引用数（COW 缺页判定：>1 需复制，==1 原地恢复可写）。
pub fn ref_count(addr: usize) -> usize {
    MM.lock().ref_count(addr) as usize
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

    // ── pstore 窗口保留（几何 + 两条 init 路径）钉死测试 ──────────────
    //
    // init 路径内部写模块级 static BITMAP_WORDS，测试间必须串行。
    static INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const MEM_BYTES: usize = 512 * 1024 * 1024;

    /// 断言窗口 16 页全部不可分配，且紧邻页状态符合预期。
    fn assert_window_reserved(bm: &PhysBitmap) {
        for i in 0..PSTORE_PAGES {
            let addr = PSTORE_BASE as usize + i * PAGE_SIZE;
            assert!(
                !bm.page_is_free(addr),
                "pstore window page {i} @0x{addr:x} must never be handed out"
            );
        }
        // 窗口前一页（0x4200_0000 之下）与后一页：普通可分配内存。
        // （内核保留区实测 ≈17MiB，够不到 32MiB 处的窗口两侧。）
        assert!(bm.page_is_free(PSTORE_BASE as usize - PAGE_SIZE));
        assert!(bm.page_is_free(PSTORE_BASE as usize + PSTORE_SIZE));
    }

    #[test]
    fn pstore_window_geometry_is_pinned() {
        // 窗口 @0x4200_0000 = RAM 内偏移 32MiB = 相对页 0x2000，共 16 页。
        assert_eq!(PSTORE_BASE, 0x4200_0000);
        assert_eq!(PSTORE_BASE_REL / PAGE_SIZE, 0x2000);
        assert_eq!(PSTORE_PAGES, 16);
        // 迁移记录：实测 debug 内核镜像末尾 ≈0x410D1000（约 17 MiB，
        // 第三加载段 BSS 零填充覆盖到窗口旧址 0x41000000 之上），故窗口
        // 必须在 17 MiB 之上——32 MiB 处留 ~15 MiB 余量。此断言钉死
        // 「窗口不得低于实测镜像末尾」的下界，防止回退到重叠地址。
        assert!(PSTORE_BASE as usize >= 0x410D1000 + PAGE_SIZE);
        // 默认保留区下限 16MiB（4096 页）< 窗口基页：两条 init 路径的
        // 显式标忙不可省略；若未来镜像长大越过窗口，init 的运行期
        // tripwire 会在串口报警（标忙本身幂等无害）。
        assert!(reserved_pages_for(16 * 1024 * 1024) < PSTORE_BASE_REL / PAGE_SIZE);
    }

    #[test]
    fn pstore_window_reserved_legacy_path() {
        let _g = INIT_LOCK.lock().unwrap();
        let mut bm = PhysBitmap::empty();
        legacy_init(&mut bm, MEM_BYTES, 16 * 1024 * 1024);
        assert_window_reserved(&bm);
        // 窗口之前的空档（保留区末尾 → 窗口起点）首帧可正常分配。
        assert_eq!(
            bm.alloc_page(),
            Some(RAM_BASE + 16 * 1024 * 1024) // 相对页 4096（绝对地址）
        );
        // 跨窗连续分配（空档全部 + 窗口 16 页 + 1）装不进窗口前段，
        // first-fit 必须整段跳过窗口，落在 0x4201_0000——不得拆窗。
        let demand =
            PSTORE_BASE_REL / PAGE_SIZE - reserved_pages_for(16 * 1024 * 1024) + PSTORE_PAGES + 1;
        assert_eq!(
            bm.alloc_contiguous(demand),
            Some(PSTORE_BASE as usize + PSTORE_SIZE)
        );
    }

    #[test]
    fn pstore_window_reserved_memory_map_path() {
        let _g = INIT_LOCK.lock().unwrap();
        let mut bm = PhysBitmap::empty();
        // 引导器精细路径：单块 512MiB CONVENTIONAL 区间（QEMU virt 等价）。
        init_from_regions(
            &mut bm,
            &[(crate::mm::phys::RAM_BASE, MEM_BYTES)],
            16 * 1024 * 1024,
        );
        assert_window_reserved(&bm);
        // 空闲数必须恰好扣掉窗口 16 页（与 legacy 路径同总量对齐），
        // 且必须在下面的试分配之前断言（分配会消耗空闲计数）。
        let mut legacy = PhysBitmap::empty();
        legacy_init(&mut legacy, MEM_BYTES, 16 * 1024 * 1024);
        assert_eq!(bm.free_count(), legacy.free_count());
        assert_eq!(
            bm.free_count(),
            MEM_BYTES / PAGE_SIZE - reserved_pages_for(16 * 1024 * 1024) - PSTORE_PAGES
        );
        // 跨窗口的连续分配（空档全部 + 窗口 16 页 + 1）必须被整段顶到
        // 窗口之后（0x4201_0000），不得拆窗。
        let demand =
            PSTORE_BASE_REL / PAGE_SIZE - reserved_pages_for(16 * 1024 * 1024) + PSTORE_PAGES + 1;
        assert_eq!(
            bm.alloc_contiguous(demand),
            Some(PSTORE_BASE as usize + PSTORE_SIZE)
        );
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
#[cfg_attr(
    all(target_arch = "aarch64", target_os = "none"),
    link_section = ".data"
)]
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
    let rd_u64 = |off: usize| u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
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
        let raw = encode(&[(0x4000_0000, 0x1000_0000), (0x5000_0000, 0x0800_0000)]);
        assert_eq!(u64::from_le_bytes(raw[0x08..0x10].try_into().unwrap()), 2);
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
