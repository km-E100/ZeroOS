use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

pub mod logger;
pub mod serial;

struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        GlobalAlloc::alloc(&crate::mm::heap::GLOBAL_HEAP, layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        GlobalAlloc::dealloc(&crate::mm::heap::GLOBAL_HEAP, ptr, layout)
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    logger::log_panic(info);
    loop {}
}

pub fn init() {
    serial::init();
}
