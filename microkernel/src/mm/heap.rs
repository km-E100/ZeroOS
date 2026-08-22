//! 内核堆：free-list 分配器（算法见 `heap_free_list.rs`）。
//!
//! - 存储：静态 BSS 中的 8 MiB 区域（位于内核镜像内，恒等映射下始终可用，
//!   与 bootloader 报告的真实内存大小解耦——真实 RAM 大小只影响
//!   物理页分配器，不改变堆的可用性）。
//! - 复用：`dealloc` 真正回收内存（合并 + 分裂，见 FreeListHeap）。
//! - OOM：打印日志后 **spin**（绝不静默返回 null 后让内核把 null 当正常指针用）。

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

pub unsafe fn heap_alloc(layout: Layout) -> *mut u8 {
    let ptr = HEAP.lock().alloc(layout);
    if ptr.is_null() {
        // OOM 是致命错误：打印详情后 spin，绝不把 null 当正常指针返回。
        crate::info!(
            "heap OOM: size=0x{:x} align=0x{:x} — spinning (kernel heap exhausted)",
            layout.size(),
            layout.align()
        );
        loop {
            core::hint::spin_loop();
        }
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