use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

pub const PAGE_SIZE: usize = 4096;
const MAX_PAGES: usize = 1024 * 1024; // 4 GiB / 4KiB pages (upper bound)

static BITMAP: Mutex<[u64; MAX_PAGES / 64]> = Mutex::new([0; MAX_PAGES / 64]);
static TOTAL_PAGES: AtomicUsize = AtomicUsize::new(0);
static FREE_PAGES: AtomicUsize = AtomicUsize::new(0);
static INITIALISED: AtomicBool = AtomicBool::new(false);

pub fn init(memory_bytes: usize, reserved_bytes: usize) {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }
    let total = usize::min(memory_bytes / PAGE_SIZE, MAX_PAGES);
    TOTAL_PAGES.store(total, Ordering::SeqCst);

    let mut bitmap = BITMAP.lock();

    // 根据 reserved_bytes 计算要保留的页数
    let mut reserve_pages = usize::min(reserved_bytes / PAGE_SIZE, total);

    // 无论如何都保留 page 0，避免把物理地址 0 当成指针使用
    if total > 0 {
        set_bit(&mut bitmap[..], 0);
        if reserve_pages == 0 {
            reserve_pages = 1;
        }
    }

    // 额外保留 [1, reserve_pages)
    for page in 1..reserve_pages {
        set_bit(&mut bitmap[..], page);
    }

    FREE_PAGES.store(
        total.saturating_sub(reserve_pages),
        Ordering::SeqCst,
    );
}

pub fn alloc_page() -> Option<usize> {
    let total = TOTAL_PAGES.load(Ordering::SeqCst);
    let mut bitmap = BITMAP.lock();
    for (index, slot) in bitmap.iter_mut().enumerate() {
        if *slot == u64::MAX {
            continue;
        }
        for bit in 0..64 {
            let page = index * 64 + bit;
            if page >= total {
                return None;
            }
            if page == 0 {
                continue; // 永远跳过物理页 0
            }
            if (*slot & (1u64 << bit)) == 0 {
                *slot |= 1u64 << bit;
                FREE_PAGES.fetch_sub(1, Ordering::SeqCst);
                return Some(page * PAGE_SIZE);
            }
        }
    }
    None
}

pub fn free_page(addr: usize) {
    let page = addr / PAGE_SIZE;
    let mut bitmap = BITMAP.lock();
    clear_bit(&mut bitmap[..], page);
    FREE_PAGES.fetch_add(1, Ordering::SeqCst);
}

pub fn free_pages() -> usize {
    FREE_PAGES.load(Ordering::SeqCst)
}

fn set_bit(bitmap: &mut [u64], page: usize) {
    let index = page / 64;
    let bit = page % 64;
    bitmap[index] |= 1u64 << bit;
}

fn clear_bit(bitmap: &mut [u64], page: usize) {
    let index = page / 64;
    let bit = page % 64;
    bitmap[index] &= !(1u64 << bit);
}
