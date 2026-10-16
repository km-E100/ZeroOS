#[cfg(not(test))]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(not(test))]
use core::panic::PanicInfo;

pub mod logger;
pub mod serial;

// ⚠ 这两个 lang item / 全局分配器仅在内核目标生效。
// host 目标跑 `cargo test` 时 std 已提供 panic_impl 与默认分配器，
// 重复定义会导致 E0152；用 cfg(not(test)) 屏蔽后测试链接 std 正常。
#[cfg(not(test))]
struct KernelAllocator;

#[cfg(not(test))]
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        GlobalAlloc::alloc(&crate::mm::heap::GLOBAL_HEAP, layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        GlobalAlloc::dealloc(&crate::mm::heap::GLOBAL_HEAP, ptr, layout)
    }
}

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    logger::log_panic(info);
    loop {}
}

pub fn init() {
    serial::init();
}
