//! 物理页位图分配器的**纯算法核心**（不依赖任何内核模块，仅用 core）。
//!
//! 可独立在 host 上编译/测试（见 `microkernel/mm-host-tests`），内核侧
//! `phys.rs` 用 `static Mutex<PhysBitmap>` 包装本结构即可获得全局实例。
//!
//! 位图语义：bit=1 表示该页**不可用**（已分配或保留），bit=0 表示空闲。
//! 页索引 p 对应的物理地址 = `base + p * PAGE_SIZE`。

pub const PAGE_SIZE: usize = 4096;

/// 物理页位图。所有操作都带边界/对称性校验：
/// - `free_page` 对保留区（含页 0）、越界、double-free 一律 panic；
/// - 分配器保证绝不返回保留区内的页；
/// - 计数（total/reserved/free）与位图内容同步维护。
#[derive(Debug)]
pub struct PhysBitmap {
    words: *mut u64,
    nwords: usize,
    base: usize,
    total: usize,
    reserved: usize,
    free: usize,
}

unsafe impl Send for PhysBitmap {}
unsafe impl Sync for PhysBitmap {}

impl PhysBitmap {
    /// 构造空实例（未初始化，操作前必须 `init`）。
    pub const fn empty() -> Self {
        Self {
            words: core::ptr::null_mut(),
            nwords: 0,
            base: 0,
            total: 0,
            reserved: 0,
            free: 0,
        }
    }

    /// 初始化位图。
    ///
    /// # 参数
    /// - `words`: 位图存储，长度必须 >= `total / 64`（向上取整）；
    /// - `base`: 页 0 的物理地址；
    /// - `total`: 总页数；
    /// - `reserved`: 起始保留页数（至少 1：页 0 永不分配）。
    ///
    /// # Safety
    /// `words` 必须指向 `nwords * 8` 字节的可写内存，且在实例存活期间有效。
    pub unsafe fn init(&mut self, words: *mut u64, nwords: usize, base: usize, total: usize, reserved: usize) {
        assert!(total <= nwords * 64, "PhysBitmap: total exceeds bitmap capacity");
        self.words = words;
        self.nwords = nwords;
        self.base = base;
        self.total = total;
        for i in 0..nwords {
            *words.add(i) = 0;
        }
        let reserve = total.min(reserved.max(1)); // 无论如何保留页 0
        for page in 0..reserve {
            self.set_bit(page);
        }
        self.reserved = reserve;
        self.free = total - reserve;
    }

    /// 分配一页，返回物理地址；无空闲页返回 None。
    pub fn alloc_page(&mut self) -> Option<usize> {
        self.assert_ready();
        for index in 0..self.nwords {
            let slot = unsafe { *self.words.add(index) };
            // 只有“整字全忙”才能跳过；全零字（整个字都空闲）同样要
            // 分配——历史上 `|| slot == 0` 会跳过所有未被触碰过的字，
            // 导致 reserved 跨越多个字后（如保留 4096 页）所有分配
            // 立即 OOM（详见 mm-host-tests 回归用例）。
            if slot == u64::MAX {
                continue;
            }
            for bit in 0..64 {
                let page = index * 64 + bit;
                if page < self.reserved || page >= self.total {
                    continue;
                }
                if slot & (1u64 << bit) == 0 {
                    unsafe { *self.words.add(index) |= 1u64 << bit; }
                    self.free -= 1;
                    return Some(self.base + page * PAGE_SIZE);
                }
            }
        }
        None
    }

    /// 分配 `count` 个物理连续页，返回首页物理地址；失败返回 None。
    /// `count == 0` 返回 None（与 alloc_page 一致的空分配语义）。
    pub fn alloc_contiguous(&mut self, count: usize) -> Option<usize> {
        self.assert_ready();
        if count == 0 {
            return None;
        }
        let mut run = 0usize;
        let mut run_start = 0usize;
        for page in 1..self.total {
            if self.page_busy(page) {
                run = 0;
                continue;
            }
            if run == 0 {
                run_start = page;
            }
            run += 1;
            if run == count {
                for p in run_start..=page {
                    self.set_bit(p);
                }
                self.free -= count;
                return Some(self.base + run_start * PAGE_SIZE);
            }
        }
        None
    }

    /// 释放一页。对称性校验：越界、落在保留区（含页 0）、double-free 一律 panic。
    pub fn free_page(&mut self, addr: usize) {
        self.assert_ready();
        assert!(
            addr >= self.base,
            "PhysBitmap::free_page: address 0x{:x} below RAM base 0x{:x}",
            addr,
            self.base
        );
        let offset = addr - self.base;
        assert_eq!(
            offset % PAGE_SIZE,
            0,
            "PhysBitmap::free_page: address 0x{:x} not page aligned",
            addr
        );
        let page = offset / PAGE_SIZE;
        assert!(
            page < self.total,
            "PhysBitmap::free_page: page {} out of range (total {})",
            page,
            self.total
        );
        assert!(
            page >= self.reserved,
            "PhysBitmap::free_page: page {} is reserved [0,{}), cannot free",
            page,
            self.reserved
        );
        assert!(
            self.page_busy(page),
            "PhysBitmap::free_page: double free of page {} (0x{:x})",
            page,
            addr
        );
        self.clear_bit(page);
        self.free += 1;
    }

    /// 查询该物理地址的页是否空闲（测试/诊断用）。
    pub fn page_is_free(&self, addr: usize) -> bool {
        if addr < self.base {
            return false;
        }
        let offset = addr - self.base;
        if offset % PAGE_SIZE != 0 {
            return false;
        }
        let page = offset / PAGE_SIZE;
        page < self.total && !self.page_busy(page)
    }

    pub fn total_pages(&self) -> usize {
        self.total
    }

    pub fn reserved_pages(&self) -> usize {
        self.reserved
    }

    pub fn free_count(&self) -> usize {
        self.free
    }

    fn page_busy(&self, page: usize) -> bool {
        unsafe { *self.words.add(page / 64) & (1u64 << (page % 64)) != 0 }
    }

    fn set_bit(&self, page: usize) {
        unsafe { *self.words.add(page / 64) |= 1u64 << (page % 64); }
    }

    fn clear_bit(&self, page: usize) {
        unsafe { *self.words.add(page / 64) &= !(1u64 << (page % 64)); }
    }

    fn assert_ready(&self) {
        assert!(!self.words.is_null(), "PhysBitmap: not initialised");
        assert!(self.total > 0, "PhysBitmap: total pages is zero");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;

    const WORDS: usize = 8; // 512 页

    struct Harness {
        // Box：保证 words 数组**地址稳定**。
        // 若直接 `[u64; WORDS]`，Harness::new 返回时结构体会被整体搬移，
        // PhysBitmap.words 里保存的指针会指向已失效的旧栈位置（debug 构建
        // 下表现为隐蔽的写后丢失）。内核侧 PhysBitmap.words 指向 static，
        // 永不搬移，不受此问题影响。
        _words: Box<[u64; WORDS]>,
        mm: PhysBitmap,
    }

    impl Harness {
        fn new(total: usize, reserved: usize) -> Self {
            let mut h = Self {
                _words: Box::new([0; WORDS]),
                mm: PhysBitmap::empty(),
            };
            unsafe {
                h.mm.init(h._words.as_mut_ptr(), WORDS, 0x4000_0000, total, reserved);
            }
            h
        }
    }

    #[test]
    fn alloc_free_roundtrip() {
        let mut h = Harness::new(64, 4);
        assert_eq!(h.mm.free_count(), 60);
        let a = h.mm.alloc_page().unwrap();
        // 保留区之后的第一页
        assert_eq!(a, 0x4000_0000 + 4 * PAGE_SIZE);
        assert!(!h.mm.page_is_free(a), "allocated page must be busy");
        h.mm.free_page(a);
        assert!(h.mm.page_is_free(a));
        assert_eq!(h.mm.free_count(), 60);
        // 释放后可再分配
        let b = h.mm.alloc_page().unwrap();
        assert_eq!(b, a);
        h.mm.free_page(b);
    }

    #[test]
    fn reserved_page_never_allocated() {
        let mut h = Harness::new(32, 8);
        for _ in 0..(32 - 8) * 2 {
            if let Some(p) = h.mm.alloc_page() {
                assert!(p >= 0x4000_0000 + 8 * PAGE_SIZE);
            }
        }
        assert_eq!(h.mm.free_count(), 0);
        assert_eq!(h.mm.alloc_page(), None);
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_panics() {
        let mut h = Harness::new(32, 2);
        let p = h.mm.alloc_page().unwrap();
        h.mm.free_page(p);
        h.mm.free_page(p);
    }

    #[test]
    #[should_panic(expected = "reserved")]
    fn free_reserved_panics() {
        let mut h = Harness::new(32, 4);
        h.mm.free_page(0x4000_0000 + 2 * PAGE_SIZE);
    }

    #[test]
    #[should_panic(expected = "below RAM base")]
    fn free_below_base_panics() {
        let mut h = Harness::new(32, 2);
        h.mm.free_page(0x1000);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn free_out_of_range_panics() {
        let mut h = Harness::new(32, 2);
        h.mm.free_page(0x4000_0000 + 64 * PAGE_SIZE);
    }

    #[test]
    fn alloc_contiguous_basic() {
        let mut h = Harness::new(256, 2);
        let first = h.mm.alloc_contiguous(16).unwrap();
        assert_eq!(first, 0x4000_0000 + 2 * PAGE_SIZE);
        for i in 0..16 {
            assert!(!h.mm.page_is_free(first + i * PAGE_SIZE));
        }
        let next = h.mm.alloc_page().unwrap();
        assert_eq!(next, first + 16 * PAGE_SIZE);
        assert_eq!(h.mm.free_count(), 256 - 2 - 17);
        // 释放整个区间后可用
        for i in 0..16 {
            h.mm.free_page(first + i * PAGE_SIZE);
        }
        let again = h.mm.alloc_contiguous(16).unwrap();
        assert_eq!(again, first);
        for i in 0..16 {
            h.mm.free_page(again + i * PAGE_SIZE);
        }
        h.mm.free_page(next);
    }

    #[test]
    fn alloc_contiguous_zero_is_none() {
        let mut h = Harness::new(64, 2);
        assert_eq!(h.mm.alloc_contiguous(0), None);
    }

    #[test]
    fn alloc_contiguous_skips_busy_holes() {
        let mut h = Harness::new(128, 3);
        // 先占 3..8（5 页连续），再把页 5 挖回成洞：
        // 空闲布局 = {5, 8, 9, 10, ...}（5 只有 1 页，凑不成 3 页连续）
        let seg5 = h.mm.alloc_contiguous(5).unwrap();
        assert_eq!(seg5, 0x4000_0000 + 3 * PAGE_SIZE);
        h.mm.free_page(0x4000_0000 + 5 * PAGE_SIZE);
        let seg = h.mm.alloc_contiguous(3).unwrap();
        // 5 是孤页 → first-fit 必须落在 8..11
        assert_eq!(seg, 0x4000_0000 + 8 * PAGE_SIZE);
        for i in 0..3 {
            h.mm.free_page(seg + i * PAGE_SIZE);
        }
        // 页 5 在测试中途已释放（挖洞），清理时跳过，避免 double-free
        for i in 0..5 {
            if i == 2 {
                continue;
            }
            h.mm.free_page(seg5 + i * PAGE_SIZE);
        }
        assert_eq!(h.mm.free_count(), 128 - 3);
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut h = Harness::new(16, 1);
        for _ in 0..15 {
            assert!(h.mm.alloc_page().is_some());
        }
        assert_eq!(h.mm.alloc_page(), None);
    }
}