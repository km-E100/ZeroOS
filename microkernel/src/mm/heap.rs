use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

const HEAP_PAGES: usize = 2048; // 8 MiB with 4KiB pages
const HEAP_SIZE: usize = HEAP_PAGES * super::phys::PAGE_SIZE;

static mut HEAP_AREA: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

static HEAP_INITIALISED: AtomicBool = AtomicBool::new(false);
static HEAP_START: AtomicUsize = AtomicUsize::new(0);
static HEAP_END: AtomicUsize = AtomicUsize::new(0);
static NEXT_FREE: Mutex<usize> = Mutex::new(0);

pub struct KernelHeap;

pub unsafe fn init_heap() {
    if HEAP_INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }

    crate::info!("heap::init_heap: begin");
    crate::info!(
        "heap::init_heap: HEAP_PAGES={} HEAP_SIZE=0x{:x}",
        HEAP_PAGES,
        HEAP_SIZE
    );

    crate::info!("heap::init_heap: before HEAP_AREA ptr");
    // 使用内核镜像中的静态缓冲区作为堆，保证虚拟地址在固件留下的映射下可访问。
    let start = HEAP_AREA.as_ptr() as usize;
    let end = start + HEAP_SIZE;
    crate::info!(
        "heap::init_heap: computed bounds start=0x{:016x} end=0x{:016x}",
        start,
        end
    );
    crate::info!("heap::init_heap: range=0x{:016x}..0x{:016x}", start, end);
    HEAP_START.store(start, Ordering::SeqCst);
    HEAP_END.store(end, Ordering::SeqCst);
    crate::info!(
        "heap::init_heap: HEAP_START=0x{:016x} HEAP_END=0x{:016x}",
        HEAP_START.load(Ordering::SeqCst),
        HEAP_END.load(Ordering::SeqCst)
    );
    crate::info!("heap::init_heap: before NEXT_FREE init");
    *NEXT_FREE.lock() = start;
    crate::info!("heap::init_heap: NEXT_FREE initialised");
}

pub unsafe fn heap_alloc(layout: Layout) -> *mut u8 {
    let heap_start = HEAP_START.load(Ordering::SeqCst);
    let heap_end = HEAP_END.load(Ordering::SeqCst);
    if heap_start == 0 || heap_end <= heap_start {
        return null_mut();
    }

    let mut next = NEXT_FREE.lock();
    let aligned = align_up(*next, layout.align());
    let end = aligned.saturating_add(layout.size());
    if end > heap_end {
        null_mut()
    } else {
        *next = end;
        aligned as *mut u8
    }
}

pub unsafe fn heap_dealloc(_ptr: *mut u8, _layout: Layout) {
    // bump allocator: dealloc is a no-op
}

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        heap_alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        heap_dealloc(ptr, layout)
    }
}

#[inline]
fn align_up(addr: usize, align: usize) -> usize {
    let mask = align - 1;
    (addr + mask) & !mask
}

pub const GLOBAL_HEAP: KernelHeap = KernelHeap;
