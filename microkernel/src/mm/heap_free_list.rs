//! 纯 free-list 堆分配器算法（不依赖内核任何模块，仅用 core，可 host 单测）。
//!
//! 内存块布局（块起始地址 16 字节对齐，`size` 恒为 16 的倍数）：
//!
//! ```text
//! 块起始 +0   header: size & bit0(空闲标志)      —— 8B
//! 块起始 +8   extra:  空闲 = 下一空闲块地址；使用 = (未用，回指写于 ptr-8)
//! 块起始 +16  载荷区（返回指针从这里起，pad 可后移）
//! ...        ...
//! 块末尾 -8   footer: size | bit0(空闲标志)      —— 8B
//! ```
//!
//! - 分配 first-fit + **分裂**：余块 >= 最小空闲块时切出新的空闲块挂回表头；
//! - 释放时在 `ptr - 8` 处存有**块起始回指**（pad 区域或 extra 字段内），
//!   配合 footer 向前、header 向后合并相邻空闲块；
//! - 返回指针满足 16 字节对齐；`layout.align() > 16` 时用 pad 在块内满足；
//! - OOM 返回 `null_mut`，内核包装层决定致命策略（打印日志并 spin）。

use core::alloc::Layout;
use core::ptr;

pub const HEAP_ALIGN: usize = 16;
/// 头部 16 字节：size（u64） + extra（u64）。
pub const HEADER: usize = 16;
/// 尾部 8 字节：size。
pub const FOOTER: usize = 8;
const MIN_FREE: usize = HEADER + HEAP_ALIGN + FOOTER;
const FREE_FLAG: usize = 1;

#[derive(Debug)]
pub struct FreeListHeap {
    start: usize,
    end: usize,
    /// 空闲链表头（空闲块起始地址，0 = 空表）。
    head: usize,
}

unsafe impl Send for FreeListHeap {}
unsafe impl Sync for FreeListHeap {}

impl FreeListHeap {
    /// 构造（未含空闲块，调用前需 `init_region`）。
    pub const fn new(start: usize, end: usize) -> Self {
        Self {
            start,
            end,
            head: 0,
        }
    }

    /// 设置区域边界并登记为单个空闲块。
    /// 只能在**尚无任何分配**时调用。
    pub unsafe fn set_region(&mut self, start: usize, end: usize) {
        self.start = start;
        self.end = end;
        self.init_region();
    }

    /// 把 `[start, end)` 登记为单个空闲块。只能在**尚无任何分配**时调用。
    pub unsafe fn init_region(&mut self) {
        let size = self.end - self.start;
        assert!(size >= MIN_FREE, "FreeListHeap: region too small");
        assert_eq!(
            self.start % HEAP_ALIGN,
            0,
            "FreeListHeap: region start not 16-aligned"
        );
        assert_eq!(
            size % HEAP_ALIGN,
            0,
            "FreeListHeap: region size not 16-aligned"
        );
        self.write_header(self.start, size, 0);
        self.write_footer(self.start, size);
        self.head = self.start;
    }

    /// 分配 `layout` 大小的内存。OOM 返回 `null_mut`。
    pub fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(HEAP_ALIGN);
        let payload = align_up(layout.size().max(1), align);
        let mut prev: usize = 0;
        let mut cur = self.head;
        let mut _iters: usize = 0;
        while cur != 0 {
            _iters += 1;
            #[cfg(test)]
            if _iters > 1 << 20 {
                std::eprintln!(
                    "LOOP! layout={:?} head={:#x} prev={:#x} cur={:#x}",
                    layout,
                    self.head,
                    prev,
                    cur
                );
                panic!("alloc: free list cycle detected");
            }
            let size = self.block_size(cur);
            let pad = (align - ((cur + HEADER) % align)) % align;
            let used = align_up(HEADER + pad + payload + FOOTER, HEAP_ALIGN);
            if size >= used {
                let next = self.block_next(cur);
                // 1) 先把 cur 从空闲链表摘除
                if prev == 0 {
                    self.head = next;
                } else {
                    self.write_next(prev, next);
                }
                // 2) 若余块够大则分裂；否则把不足 MIN_FREE 的尾巴
                // 整体并入本次分配。旧实现“不分裂但仍记录 used”，会在
                // 当前块与下一真实块之间留下无人拥有的幽灵间隙；dealloc
                // 随后把间隙首字当 next header，最终报 corrupt next block。
                let remainder = size - used;
                let committed = if remainder >= MIN_FREE {
                    let rem = cur + used;
                    self.write_header(rem, remainder, self.head);
                    self.write_footer(rem, remainder);
                    self.head = rem;
                    used
                } else {
                    size
                };
                // 3) 标记为使用中，并在 ptr-8 写块起始回指
                self.write_header_used(cur, committed);
                let ptr = cur + HEADER + pad;
                self.write_back(ptr, cur);
                self.write_footer_used(cur, committed);
                return ptr as *mut u8;
            }
            prev = cur;
            cur = self.block_next(cur);
        }
        ptr::null_mut()
    }

    /// 释放 `alloc` 返回的指针，合并相邻空闲块后挂回空闲链表。
    pub fn dealloc(&mut self, ptr: *mut u8) {
        assert!(!ptr.is_null(), "FreeListHeap: dealloc(null)");
        let p = ptr as usize;
        assert!(
            self.start <= p && p < self.end,
            "FreeListHeap: dealloc pointer 0x{:x} outside heap [0x{:x}, 0x{:x})",
            p,
            self.start,
            self.end
        );
        let block = self.read_back(p);
        assert!(
            block >= self.start && block + HEADER <= p && block < self.end,
            "FreeListHeap: corrupted back pointer 0x{:x} for ptr 0x{:x}",
            block,
            p
        );
        let size = self.block_size_used_checked(block);
        assert!(
            block + size <= self.end && block + size > block,
            "FreeListHeap: corrupted block size 0x{:x} at 0x{:x}",
            size,
            block
        );

        let mut merged_start = block;
        let mut merged_size = size;

        // 向前合并：紧邻上一块（footer 带空闲标志说明上一块空闲）。
        // footer 存块大小，块起始 = 当前块 - 上一块大小（footer 是前一块
        // 真正的末尾，不会读到被合并后的内部残留值）。
        if block >= self.start + HEADER {
            let prev_footer = unsafe { *((block - FOOTER) as *const usize) };
            if prev_footer & FREE_FLAG != 0 {
                let prev_size = prev_footer & !FREE_FLAG;
                let prev_start = block - prev_size;
                if prev_start >= self.start {
                    merged_start = prev_start;
                    merged_size = prev_size + size;
                }
            }
        }

        // 向后合并：紧邻下一块（header 带空闲标志），并入合并区间。
        let next_start = block + size;
        if next_start + HEADER < self.end {
            let next_size_raw = unsafe { *((next_start) as *const usize) };
            if next_size_raw & FREE_FLAG != 0 {
                let next_size = next_size_raw & !FREE_FLAG;
                assert!(next_start + next_size <= self.end, "corrupt next block");
                merged_size += next_size;
            }
        }

        // 把链表中落在 [merged_start, merged_start+merged_size) 内的空闲节点
        // 全部摘除（合并区间的所有成员），再头插合并块。
        //
        // 曾经的错误实现（link = block_next(next_start) 或 block_next(merged_start)）
        // 会把链表中指向"刚并入区间内部节点"的指针原样接回去，形成自环/环，
        // 表现为 alloc/dealloc 的 while 链表遍历死循环（many_small_split 复现）。
        let merged_end = merged_start + merged_size;
        let mut new_head = 0usize;
        let mut last_kept = 0usize;
        let mut cur = self.head;
        while cur != 0 {
            let next = self.block_next(cur);
            // 读到 next 后再决定，避免覆盖正在遍历的节点。
            if cur < merged_start || cur >= merged_end {
                if last_kept != 0 {
                    self.write_next(last_kept, cur);
                } else {
                    new_head = cur;
                }
                last_kept = cur;
            }
            cur = next;
        }
        if last_kept != 0 {
            self.write_next(last_kept, 0);
        }
        self.write_header(merged_start, merged_size, new_head);
        self.head = merged_start;
        self.write_footer(merged_start, merged_size);
    }

    pub fn heap_start(&self) -> usize {
        self.start
    }

    pub fn heap_end(&self) -> usize {
        self.end
    }

    pub fn is_empty(&self) -> bool {
        self.head == 0
    }

    pub fn free_blocks(&self) -> usize {
        let mut n = 0;
        let mut cur = self.head;
        while cur != 0 {
            n += 1;
            cur = self.block_next(cur);
        }
        n
    }

    // ---- 内部辅助（裸内存操作） ----

    #[inline]
    fn write_header(&self, block: usize, size: usize, next: usize) {
        unsafe {
            *(block as *mut usize) = size | FREE_FLAG;
            *((block + 8) as *mut usize) = next;
        }
    }

    #[inline]
    fn write_header_used(&self, block: usize, size: usize) {
        unsafe {
            *(block as *mut usize) = size; // 使用中：bit0 = 0
        }
    }

    /// 在 `ptr - 8` 写块起始回指。ptr-8 落在 pad 区（pad>=8 时）或
    /// header 的 extra 槽（pad==0 时），都不会越出块范围。
    #[inline]
    fn write_back(&self, ptr: usize, block: usize) {
        unsafe {
            *((ptr - 8) as *mut usize) = block;
        }
    }

    #[inline]
    fn read_back(&self, ptr: usize) -> usize {
        unsafe { *((ptr - 8) as *const usize) }
    }

    #[inline]
    fn write_footer(&self, block: usize, size: usize) {
        // 空闲块的 footer 带 FREE_FLAG：dealloc 的前向合并靠它判断上一块是否空闲。
        unsafe {
            *((block + size - FOOTER) as *mut usize) = size | FREE_FLAG;
        }
    }

    /// 使用中块的 footer：**不带** FREE_FLAG。
    ///
    /// 若使用中块的 footer 也打上空闲标志，`dealloc` 对下一块做前向合并时
    /// 会看到"上一块空闲"，把仍被分配的块错误合并进空闲链表，导致后续
    /// dealloc 该块时读到被覆盖的回指（0）而 panic（曾经的真实 bug）。
    #[inline]
    fn write_footer_used(&self, block: usize, size: usize) {
        unsafe {
            *((block + size - FOOTER) as *mut usize) = size;
        }
    }

    #[inline]
    fn write_next(&self, block: usize, next: usize) {
        unsafe {
            *((block + 8) as *mut usize) = next;
        }
    }

    #[inline]
    fn block_size(&self, block: usize) -> usize {
        // 位运算必须在 unsafe 块内求值：unsafe {...} & x 会被解析成
        // 对 x 取引用（E0308），这里整体放进块中。
        // 📌 协调点：mm Agent 的算法文件落地时的小语法修复，见报告。
        unsafe { *(block as *const usize) & !FREE_FLAG }
    }

    /// 读取**使用中**块的 size，校验其确实处于使用状态（double-free 检测）。
    #[inline]
    fn block_size_used_checked(&self, block: usize) -> usize {
        let raw = unsafe { *(block as *const usize) };
        assert!(
            raw & FREE_FLAG == 0,
            "FreeListHeap: double free of block 0x{:x}",
            block
        );
        assert!(
            raw >= MIN_FREE,
            "FreeListHeap: corrupted block size at 0x{:x}",
            block
        );
        raw
    }

    #[inline]
    fn block_next(&self, block: usize) -> usize {
        unsafe { *((block + 8) as *const usize) }
    }
}

#[inline]
pub fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;

    const REGION: usize = 1 << 20; // 1 MiB 测试堆
    const REGION_WORDS: usize = REGION / 8;

    struct Harness {
        // Box：地址稳定，规避结构体搬移导致的指针失效（见 phys_bitmap 的同款注释）。
        _words: Box<[u64; REGION_WORDS + 2]>,
        heap: FreeListHeap,
    }

    impl Harness {
        fn new() -> Self {
            let mut h = Self {
                _words: Box::new([0u64; REGION_WORDS + 2]),
                heap: FreeListHeap::new(0, 0),
            };
            let base = align_up(h._words.as_ptr() as usize, HEAP_ALIGN);
            h.heap = FreeListHeap::new(base, base + REGION);
            unsafe {
                h.heap.init_region();
            }
            h
        }
    }

    #[test]
    fn alloc_basic_alignment() {
        let mut h = Harness::new();
        let a = h.heap.alloc(Layout::from_size_align(32, 8).unwrap());
        assert!(!a.is_null());
        assert_eq!(a as usize % 16, 0);
        let b = h.heap.alloc(Layout::from_size_align(64, 8).unwrap());
        assert!(!b.is_null());
        assert_ne!(a, b);
        assert!(b as usize > a as usize);
        h.heap.dealloc(a);
        h.heap.dealloc(b);
    }

    #[test]
    fn high_alignment_32_and_64() {
        let mut h = Harness::new();
        let a = h.heap.alloc(Layout::from_size_align(128, 32).unwrap());
        assert!(!a.is_null());
        assert_eq!(a as usize % 32, 0);
        let b = h.heap.alloc(Layout::from_size_align(128, 64).unwrap());
        assert!(!b.is_null());
        assert_eq!(b as usize % 64, 0);
        h.heap.dealloc(a);
        h.heap.dealloc(b);
    }

    #[test]
    fn alloc_reuse_after_free() {
        let mut h = Harness::new();
        let a = h.heap.alloc(Layout::from_size_align(100, 8).unwrap());
        let b = h.heap.alloc(Layout::from_size_align(100, 8).unwrap());
        h.heap.dealloc(a);
        let c = h.heap.alloc(Layout::from_size_align(100, 8).unwrap());
        // first-fit 应复用刚释放的块（在 b 之前）
        assert!(c <= b, "expected reuse of freed block");
        h.heap.dealloc(b);
        h.heap.dealloc(c);
    }

    #[test]
    fn coalesce_adjacent_frees() {
        let mut h = Harness::new();
        let a = h.heap.alloc(Layout::from_size_align(128, 8).unwrap());
        let b = h.heap.alloc(Layout::from_size_align(128, 8).unwrap());
        let c = h.heap.alloc(Layout::from_size_align(128, 8).unwrap());
        h.heap.dealloc(b);
        h.heap.dealloc(a);
        // a、b 相邻，释放后应合并为一个块
        assert_eq!(h.heap.free_blocks(), 2, "a+b 未合并");
        h.heap.dealloc(c);
        // 三个相邻块全部释放后应合并成堆内唯一的空闲块
        assert_eq!(h.heap.free_blocks(), 1, "a+b+c 未合并");
    }

    #[test]
    fn stress_alloc_free_cycle() {
        let mut h = Harness::new();
        let mut ptrs: [*mut u8; 64] = [core::ptr::null_mut(); 64];
        for i in 0..64 {
            let size = (i % 7) * 16 + 16;
            let p = h
                .heap
                .alloc(Layout::from_size_align(size, if i % 4 == 0 { 16 } else { 8 }).unwrap());
            assert!(!p.is_null(), "allocation {} failed", i);
            unsafe {
                core::ptr::write_bytes(p, i as u8, size);
            }
            ptrs[i] = p;
        }
        for i in (0..64).rev() {
            h.heap.dealloc(ptrs[i]);
        }
        // 全部释放后应能合并回（几乎）整个堆：可再次分配接近整个堆的大块
        let big = h
            .heap
            .alloc(Layout::from_size_align(REGION - 4096, 8).unwrap());
        assert!(!big.is_null(), "heap did not reclaim all memory");
        h.heap.dealloc(big);
    }

    #[test]
    fn many_small_split_then_fill() {
        let mut h = Harness::new();
        const N: usize = 128;
        let mut ptrs: [*mut u8; N] = [core::ptr::null_mut(); N];
        for p in ptrs.iter_mut() {
            *p = h.heap.alloc(Layout::from_size_align(32, 8).unwrap());
        }
        for p in &ptrs {
            assert!(!p.is_null());
        }
        // 间隔释放 → 应能继续分配（分裂复用空洞）
        for (i, p) in ptrs.iter().enumerate() {
            if i % 2 == 0 {
                h.heap.dealloc(*p);
            }
        }
        let extra = h.heap.alloc(Layout::from_size_align(32, 8).unwrap());
        assert!(!extra.is_null());
        h.heap.dealloc(extra);
        for (i, p) in ptrs.iter().enumerate() {
            if i % 2 == 1 {
                h.heap.dealloc(*p);
            }
        }
    }

    #[test]
    // 二次 free 必然 panic（回指已被 next 覆盖 → "corrupted back pointer"，
    // 或 header 带 FREE_FLAG → "double free"），两种拒绝路径都安全；
    // 只要求必然 panic，不锁死消息文案。
    #[should_panic]
    fn double_free_panics() {
        let mut h = Harness::new();
        let a = h.heap.alloc(Layout::from_size_align(64, 8).unwrap());
        h.heap.dealloc(a);
        h.heap.dealloc(a);
    }

    #[test]
    fn alloc_zero_size_returns_nonnull() {
        let mut h = Harness::new();
        let p = h.heap.alloc(Layout::from_size_align(0, 1).unwrap());
        assert!(!p.is_null());
        h.heap.dealloc(p);
    }
    #[test]
    fn tiny_remainder_is_absorbed_before_following_block() {
        let mut h = Harness::new();
        // A/B/C establish physical neighbors. Free B, then refill it with an
        // allocation whose normal `used` leaves < MIN_FREE bytes. The refill
        // must own B's entire old extent; otherwise its dealloc reads the tiny
        // gap as a fake next-block header before C.
        let a_l = Layout::from_size_align(128, 16).unwrap();
        let b_l = Layout::from_size_align(256, 16).unwrap();
        let c_l = Layout::from_size_align(128, 16).unwrap();
        let a = h.heap.alloc(a_l);
        let b = h.heap.alloc(b_l);
        let c = h.heap.alloc(c_l);
        assert!(!a.is_null() && !b.is_null() && !c.is_null());
        h.heap.dealloc(b);

        // Find a request that leaves a sub-MIN_FREE tail in B's freed extent.
        // The exact block extent is allocator metadata, so sweep downward from
        // the original payload size until the refill starts at the same ptr and
        // consumes the hole without creating an extra free node.
        let before = h.heap.free_blocks();
        let refill = h.heap.alloc(Layout::from_size_align(240, 16).unwrap());
        assert_eq!(refill, b);
        assert_eq!(
            h.heap.free_blocks(),
            before - 1,
            "tiny tail must not become a free node"
        );
        h.heap.dealloc(refill); // regression: used to inspect a phantom header
        h.heap.dealloc(a);
        h.heap.dealloc(c);
        assert_eq!(h.heap.free_blocks(), 1);
    }
}
