//! 内核堆：free-list 分配器（算法见 `heap_free_list.rs`）。
//!
//! - 存储：静态 BSS 中的 8 MiB 区域（位于内核镜像内，恒等映射下始终可用，
//!   与 bootloader 报告的真实内存大小解耦——真实 RAM 大小只影响
//!   物理页分配器，不改变堆的可用性）。
//! - 复用：`dealloc` 真正回收内存（合并 + 分裂，见 FreeListHeap）。
//! - OOM：打印一行日志后 **返回 null**——GlobalAlloc 契约中 null 即
//!   "分配失败"，由调用方选择降级策略：
//!     - 经 `alloc::vec`/`Box` 等 core 分配路径，null 触发
//!       `handle_alloc_error` → 内核 `#[alloc_error_handler]`
//!       （kernel/src/main.rs）打印唯一一行 Layout 摘要后 panic
//!       （panic=abort），与一切内核致命错误同一出口；
//!     - 直接调用 `heap_alloc` 的代码必须自行检查 null。

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::heap_free_list::{align_up, FreeListHeap, HEAP_ALIGN};
use super::phys::PAGE_SIZE;

const HEAP_PAGES: usize = 2048; // 8 MiB with 4KiB pages
const HEAP_SIZE: usize = HEAP_PAGES * PAGE_SIZE;

// 静态 BSS 区域：位于内核镜像内，boot.rs 的保留计算（__bss_end）已覆盖。
// 📌 协调点：`#[repr(align)]` 不能直接挂 static（E0517），`#[align]`
// 属性 1.90 尚未稳定，故用 repr(align) 结构体包装（语义等价，见报告）。
#[repr(C, align(16))]
struct AlignedHeapArea([u8; HEAP_SIZE]);

static mut HEAP_AREA: AlignedHeapArea = AlignedHeapArea([0; HEAP_SIZE]);

static HEAP_INITIALISED: AtomicBool = AtomicBool::new(false);
static HEAP: Mutex<FreeListHeap> = Mutex::new(FreeListHeap::new(0, 0));

pub struct KernelHeap;

/// 初始化内核堆。`memory_bytes` 仅用于日志（展示真实 RAM 与堆的比例），
/// 本轮堆体量保持 8 MiB 静态 BSS；将来若要按比例扩堆，
/// 把 HEAP_AREA 换成 phys 页即可（本文件其余部分无需改动）。
#[allow(static_mut_refs)]
pub unsafe fn init_heap(memory_bytes: usize) {
    if HEAP_INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }

    let start = HEAP_AREA.0.as_ptr() as usize;
    let end = start + HEAP_SIZE;
    crate::info!(
        "heap::init_heap: heap=[0x{:016x}, 0x{:016x}) size=0x{:x} RAM=0x{:x} (heap/RAM={:.2}%)",
        start,
        end,
        HEAP_SIZE,
        memory_bytes,
        if memory_bytes > 0 {
            HEAP_SIZE as f32 / memory_bytes as f32 * 100.0
        } else {
            0.0
        }
    );
    assert_eq!(start % HEAP_ALIGN, 0, "kernel heap area not 16-aligned");
    {
        let mut heap = HEAP.lock();
        heap.set_region(start, end);
    }
    crate::info!("heap::init_heap: complete");
}

/// 内核堆分配入口（`KernelHeap` 的 GlobalAlloc 实现核心）。
///
/// OOM 降级语义（本轮改造）：区域耗尽时打印一行可诊断日志后 **返回
/// null**，不再关中断自旋挂死整个内核。失败处置权交还调用方：
/// - GlobalAlloc 包装层把 null 如实上报给 core 分配机制，`alloc::vec`/
///   `Box` 等自动走 `handle_alloc_error` → 显式 handler（打印一行后
///   panic，panic=abort）——不可恢复路径仍是受控停机，但不再绕过统一
///   panic 出口；
/// - 可降级路径（引导期探测、可选拒绝服务请求）应使用 fallible API 或
///   直接检查本函数返回值，在 null 上走自己的错误分支。
pub unsafe fn heap_alloc(layout: Layout) -> *mut u8 {
    let ptr = HEAP.lock().alloc(layout);
    if ptr.is_null() {
        // 仅此一行日志：真实停机决策在调用方（handler 只打一行不刷屏）。
        crate::info!(
            "heap OOM: size=0x{:x} align=0x{:x} — returning null (caller decides)",
            layout.size(),
            layout.align()
        );
    }
    ptr
}

pub unsafe fn heap_dealloc(ptr: *mut u8, _layout: Layout) {
    if ptr.is_null() {
        return;
    }
    HEAP.lock().dealloc(ptr);
}

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        heap_alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        heap_dealloc(ptr, layout)
    }
}

pub const GLOBAL_HEAP: KernelHeap = KernelHeap;

/// 诊断：当前空闲块数量（0 表示堆未被使用或已完全合并）。
pub fn free_blocks() -> usize {
    HEAP.lock().free_blocks()
}

#[allow(dead_code)]
pub fn heap_bounds() -> (usize, usize) {
    let heap = HEAP.lock();
    (heap.heap_start(), heap.heap_end())
}

#[allow(dead_code)]
pub fn align_up_16(value: usize) -> usize {
    align_up(value, HEAP_ALIGN)
}

// ⚠ 文件边界：FreeListHeap 算法本体与其既有单测在 heap_free_list.rs
// （本轮不改动该文件）。这里以**宿主单测**形式补充 OOM 降级契约：
// 区域耗尽必须返回 null（绝不 panic/hang——这是 heap_alloc 返回 null
// 降级语义的算法层前提），以及 set_region 的边界行为。
#[cfg(test)]
mod oom_contract_tests {
    use super::*;
    use alloc::boxed::Box;
    use core::alloc::Layout;

    /// 对齐的测试区域（Box 保地址稳定，与 heap_free_list::tests 同款手法）。
    struct Harness {
        _backing: Box<[u64; REGION / 8]>,
        heap: FreeListHeap,
    }

    const REGION: usize = 64 * 1024; // 64 KiB：耗尽循环几十次即触底
    const SLAB: usize = 1024; // 每次分配 1 KiB → 约 60+ 次

    impl Harness {
        fn new() -> Self {
            let mut h = Self {
                _backing: Box::new([0u64; REGION / 8]),
                heap: FreeListHeap::new(0, 0),
            };
            let base = align_up(h._backing.as_ptr() as usize, HEAP_ALIGN);
            unsafe { h.heap.set_region(base, base + REGION) };
            h
        }
    }

    fn slab_layout() -> Layout {
        Layout::from_size_align(SLAB, 16).unwrap()
    }

    /// OOM 契约主断言：区域耗尽时 alloc 返回 null（既有算法行为保持），
    /// 且释放一块后立刻恢复可分配——null 是"暂时失败"，不是堆损坏。
    #[test]
    fn exhaustion_returns_null_then_recovers_after_free() {
        let mut h = Harness::new();
        let mut ptrs = alloc::vec::Vec::new();
        loop {
            let p = h.heap.alloc(slab_layout());
            if p.is_null() {
                break;
            }
            ptrs.push(p);
            assert!(ptrs.len() <= REGION / SLAB + 1, "alloc 越界写穿区域");
        }
        let drained = ptrs.len();
        assert!(drained > 0, "区域应至少承载一次分配");
        // 继续分配仍然 null（稳定失败，不是随机行为）
        assert!(h.heap.alloc(slab_layout()).is_null());
        // 释放一块 → null 立刻变回成功
        h.heap.dealloc(ptrs.pop().unwrap());
        let recovered = h.heap.alloc(slab_layout());
        assert!(!recovered.is_null(), "释放后必须恢复可分配");
        for p in ptrs {
            h.heap.dealloc(p);
        }
        h.heap.dealloc(recovered);
        // 全部归还后合并回单一空闲块，可再吃下接近整域的大块
        let big = h
            .heap
            .alloc(Layout::from_size_align(REGION - 4096, 16).unwrap());
        assert!(!big.is_null(), "全量释放后应能重新分配大块");
    }

    // ── set_region 边界 ──────────────────────────────────────────────
    // 最小合法区域 = HEADER(16) + HEAP_ALIGN(16) + FOOTER(8) = 40，
    // 再向上对齐到 16 ⇒ 48 字节。48B 区域恰好容纳一个 ≤16B 分配。

    #[test]
    fn minimal_region_admits_exactly_one_small_alloc() {
        let mut backing = Box::new([0u64; 16]); // 128B ≥ 48B，16 对齐
        let base = align_up(backing.as_mut_ptr() as usize, HEAP_ALIGN);
        let mut heap = FreeListHeap::new(0, 0);
        unsafe { heap.set_region(base, base + 48) };
        let a = heap.alloc(Layout::from_size_align(16, 16).unwrap());
        assert!(!a.is_null(), "最小区域必须容纳一个 16B 分配");
        // 同一块已满：第二个小分配必须 null（而非破坏相邻内存）
        assert!(heap.alloc(Layout::from_size_align(1, 1).unwrap()).is_null());
        heap.dealloc(a);
        let b = heap.alloc(Layout::from_size_align(16, 16).unwrap());
        assert!(!b.is_null());
    }

    #[test]
    #[should_panic(expected = "region too small")]
    fn region_below_min_free_is_rejected() {
        let mut backing = Box::new([0u64; 16]);
        let base = align_up(backing.as_mut_ptr() as usize, HEAP_ALIGN);
        let mut heap = FreeListHeap::new(0, 0);
        unsafe { heap.set_region(base, base + 32) }; // 32 < MIN_FREE=40
    }

    #[test]
    #[should_panic(expected = "region start not 16-aligned")]
    fn unaligned_region_start_is_rejected() {
        let mut backing = Box::new([0u64; 16]);
        let base = align_up(backing.as_mut_ptr() as usize, HEAP_ALIGN);
        let mut heap = FreeListHeap::new(0, 0);
        unsafe { heap.set_region(base + 8, base + 8 + 4096) };
    }

    #[test]
    #[should_panic(expected = "region size not 16-aligned")]
    fn unaligned_region_size_is_rejected() {
        let mut backing = Box::new([0u64; 16]);
        let base = align_up(backing.as_mut_ptr() as usize, HEAP_ALIGN);
        let mut heap = FreeListHeap::new(0, 0);
        unsafe { heap.set_region(base, base + 4096 + 8) };
    }
}
