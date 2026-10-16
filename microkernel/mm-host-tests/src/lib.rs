//! mm-host-tests runner：把 microkernel 的**纯算法模块**拉进 host 跑单测。
//!
//! microkernel 主 crate 无法在 host 上执行 `cargo test`（`runtime/mod.rs`
//! 的 `#[panic_handler]` 与测试框架的 panic handler 冲突，E0152），
//! 因此把不依赖内核全局状态/为内核的模块用 `#[path]` 引入本 crate，
//! 它们自带的 `#[cfg(test)] mod tests` 会随 `cargo test` 一并执行。

#[path = "../../src/mm/phys_bitmap.rs"]
mod phys_bitmap;

#[path = "../../src/mm/heap_free_list.rs"]
mod heap_free_list;

#[path = "../../src/mm/table_walk.rs"]
mod table_walk;

/// 第十刀 COW fork：伪造页表 + 引用计数位图的集成场景（见 cow_tests.rs）。
#[cfg(test)]
mod cow_tests;

/// 主 crate 未能 host 化的集成场景，放在这里补测：
/// - PhysBitmap 与 FreeListHeap 的协同（物理页表自举场景简化版）。
#[cfg(test)]
mod integration {
    use core::alloc::Layout;

    use super::heap_free_list::FreeListHeap;
    use super::phys_bitmap::PhysBitmap;

    const PAGE_SIZE: usize = 4096;

    /// 简化版 "初始化阶段"：内核没堆 时先有一块转储区，
    /// 位图分配"页表页"，堆分配"内核对象"，来回不串台。
    #[test]
    fn bitmap_and_heap_do_not_overlap() {
        // 堆直接用 host 真实内存（fake 物理地址会 SIGSEGV）。
        const REGION: usize = 64 * 1024;
        let mut arena = [0u64; REGION / 8 + 2];
        let heap_base = super::heap_free_list::align_up(arena.as_ptr() as usize, 16);
        let heap_end = heap_base + REGION;

        unsafe {
            let mut bitmap = PhysBitmap::empty();
            let nwords = 16;
            // 命名数组持活位图存储（临时数组会被立即 drop，指针悬垂）
            let mut bitmap_words = [0u64; 16];
            let mut ref_counts = [0u16; 1024];
            bitmap.init(
                bitmap_words.as_mut_ptr(),
                nwords,
                ref_counts.as_mut_ptr(),
                ref_counts.len(),
                0x4000_0000,
                nwords * 64,
                2,
            );

            let mut heap = FreeListHeap::new(heap_base, heap_end);
            heap.init_region();

            // 堆连续分配 3 块，双指针不重叠。
            let a = heap.alloc(Layout::from_size_align(256, 8).unwrap());
            let b = heap.alloc(Layout::from_size_align(256, 8).unwrap());
            let c = heap.alloc(Layout::from_size_align(256, 8).unwrap());
            assert!(!a.is_null() && !b.is_null() && !c.is_null());
            let (a, b, c) = (a as usize, b as usize, c as usize);
            assert!(a + 256 <= b);
            assert!(b + 256 <= c);

            // 全释放后能再次分配出同一块（dealloc 可复用）。
            heap.dealloc(a as *mut u8);
            heap.dealloc(b as *mut u8);
            heap.dealloc(c as *mut u8);
            let d = heap.alloc(Layout::from_size_align(256, 8).unwrap()) as usize;
            assert_eq!(d, a, "dealloc must reuse the freed block");

            // 位图独立于堆分配，互不干扰。
            let p1 = bitmap.alloc_page().unwrap();
            let p2 = bitmap.alloc_page().unwrap();
            assert!(p1 != p2);
            bitmap.free_page(p1);
            bitmap.free_page(p2);
        }
    }

    /// 回归：保留区跨越多个字（>64 页）时，全零字也必须能分配。
    /// 历史 bug：`alloc_page` 跳过 `slot == 0` 的字，导致内核启动后
    /// 物理分配器对所有未被触碰过的字一律返回 OOM（QEMU 实机验证：
    /// reserved=4096 页时 spawn 首个进程即 panic）。
    #[test]
    fn allocator_serves_all_zero_words() {
        let mut words = [0u64; 4096];
        let mut ref_counts = [0u16; 4096 * 64];
        let mut bitmap = PhysBitmap::empty();
        let total = 213_008;
        let reserved = 4096;
        unsafe {
            bitmap.init(
                words.as_mut_ptr(),
                words.len(),
                ref_counts.as_mut_ptr(),
                ref_counts.len(),
                0x4000_0000,
                total,
                reserved,
            );
        }

        // 能连续分配多页，且永不返回保留区/越界地址。
        let mut seen = Vec::new();
        for _ in 0..64 {
            let page = bitmap.alloc_page().expect("alloc must not OOM");
            assert!(page >= 0x4000_0000 + reserved * PAGE_SIZE);
            assert!(page < 0x4000_0000 + total * PAGE_SIZE);
            assert!(!seen.contains(&page));
            seen.push(page);
        }

        // 分配的页必须落在“全零字”区间（跨保留边界之后的字）。
        assert!(
            seen.iter().all(|p| *p >= 0x4000_0000 + 4096 * PAGE_SIZE),
            "first allocs must come from beyond the reserved region"
        );

        // 释放后按需复用。
        bitmap.free_page(seen[0]);
        let again = bitmap.alloc_page().expect("freed page must be reusable");
        assert_eq!(again, seen[0]);

        // 耗尽全部空闲页后必须返回 None（不越界）。
        for _ in seen.len()..total - reserved {
            bitmap.alloc_page().expect("all free pages must be allocatable");
        }
        assert_eq!(bitmap.alloc_page(), None, "exhausted allocator must return None");
    }
}
