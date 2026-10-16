pub mod address_space;
pub mod heap;
pub mod heap_free_list;
pub mod kernel_l0;
pub mod kernel_l1;
pub mod kernel_l2;
pub mod paging;
pub mod phys;
pub mod phys_bitmap;
pub mod table_walk;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static PAGING_READY: AtomicBool = AtomicBool::new(false);
const MIN_IDENTITY_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// 引导阶段最终采用的 RAM 字节数（真实值优先，缺失时回退 512MiB）。
static MEMORY_BYTES: AtomicUsize = AtomicUsize::new(0);

pub fn memory_bytes() -> usize {
    MEMORY_BYTES.load(Ordering::SeqCst)
}

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
    MEMORY_BYTES.store(memory_bytes, Ordering::SeqCst);
    paging::configure_identity_map(0, core::cmp::max(memory_bytes, MIN_IDENTITY_BYTES) as u64);
    phys::init(memory_bytes, reserved_bytes);
    // Do NOT activate our own page tables here; keep using firmware's mapping.
    // Only bring up the heap so early drivers can allocate safely.
    unsafe {
        heap::init_heap(memory_bytes);
    }
}

/// Stage 1 of relocated-kernel MM bring-up. Keep firmware translations active
/// while initializing the physical allocator and kernel heap. This lets ACPI
/// tables live anywhere firmware mapped them (including above Zero OS's 2GiB
/// identity window) and gives the parser an allocator for its cached Vec state.
pub fn init_relocated_early(
    memory_bytes: usize,
    legacy_reserved_bytes: usize,
    kernel_start: usize,
    kernel_end: usize,
) {
    MEMORY_BYTES.store(memory_bytes, Ordering::SeqCst);
    crate::info!(
        "mm::init: phys init memory=0x{:x} kernel=[0x{:x},0x{:x})",
        memory_bytes,
        kernel_start,
        kernel_end
    );
    paging::configure_identity_map(0, core::cmp::max(memory_bytes, MIN_IDENTITY_BYTES) as u64);
    phys::init_with_kernel_range(
        memory_bytes,
        legacy_reserved_bytes,
        kernel_start,
        kernel_end,
    );
    crate::info!("mm::init: heap init under firmware translation");
    unsafe {
        heap::init_heap(memory_bytes);
    }
}

/// Stage 2: after ACPI has been parsed/cached, build and install Zero OS page
/// tables using those discovered device ranges. No firmware table access is
/// required after this point.
pub fn activate_relocated_paging() {
    crate::info!("mm::init: paging setup after ACPI cache");
    ensure_paging_ready();
    crate::info!(
        "mm::init: complete (RAM=0x{:x} free_pages={})",
        memory_bytes(),
        phys::free_pages()
    );
}

/// Compatibility wrapper for callers that do not need pre-paging ACPI parsing.
pub fn init_relocated(
    memory_bytes: usize,
    legacy_reserved_bytes: usize,
    kernel_start: usize,
    kernel_end: usize,
) {
    init_relocated_early(
        memory_bytes,
        legacy_reserved_bytes,
        kernel_start,
        kernel_end,
    );
    activate_relocated_paging();
}

pub fn init(memory_bytes: usize, reserved_bytes: usize) {
    MEMORY_BYTES.store(memory_bytes, Ordering::SeqCst);
    crate::info!(
        "mm::init: phys init memory=0x{:x} reserved=0x{:x}",
        memory_bytes,
        reserved_bytes
    );
    paging::configure_identity_map(0, core::cmp::max(memory_bytes, MIN_IDENTITY_BYTES) as u64);
    phys::init(memory_bytes, reserved_bytes);
    crate::info!("mm::init: paging setup");
    ensure_paging_ready();
    crate::info!("mm::init: heap init");
    unsafe {
        heap::init_heap(memory_bytes);
    }
    crate::info!(
        "mm::init: complete (RAM=0x{:x} free_pages={})",
        memory_bytes,
        phys::free_pages()
    );
}
