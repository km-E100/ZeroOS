pub mod address_space;
pub mod heap;
pub mod kernel_l0;
pub mod kernel_l1;
pub mod kernel_l2;
pub mod paging;
pub mod phys;

use core::sync::atomic::{AtomicBool, Ordering};

static PAGING_READY: AtomicBool = AtomicBool::new(false);
const MIN_IDENTITY_BYTES: usize = 2 * 1024 * 1024 * 1024;

fn ensure_paging_ready() {
    if PAGING_READY.load(Ordering::SeqCst) {
        return;
    }
    unsafe {
        paging::init_kernel_page_table();
        paging::activate_kernel_page_table();
    }
    PAGING_READY.store(true, Ordering::SeqCst);
}

pub fn init_early(memory_bytes: usize, reserved_bytes: usize) {
    paging::configure_identity_map(
        0,
        core::cmp::max(memory_bytes, MIN_IDENTITY_BYTES) as u64,
    );
    phys::init(memory_bytes, reserved_bytes);
    // Do NOT activate our own page tables here; keep using firmware's mapping.
    // Only bring up the heap so early drivers can allocate safely.
    unsafe {
        heap::init_heap();
    }
}

pub fn init(memory_bytes: usize, reserved_bytes: usize) {
    crate::info!("mm::init: phys init");
    paging::configure_identity_map(
        0,
        core::cmp::max(memory_bytes, MIN_IDENTITY_BYTES) as u64,
    );
    phys::init(memory_bytes, reserved_bytes);
    crate::info!("mm::init: paging setup");
    ensure_paging_ready();
    crate::info!("mm::init: heap init");
    unsafe {
        heap::init_heap();
    }
    crate::info!("mm::init: complete");
}
