#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate zero_fs_zfs;

#[cfg(target_os = "none")]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
use core::ptr;
#[cfg(target_os = "none")]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();
#[cfg(target_os = "none")]
const HEAP_SIZE: usize = 64 * 1024;
#[cfg(target_os = "none")]
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[cfg(target_os = "none")]
struct BumpAllocator {
    head: AtomicUsize,
}

#[cfg(target_os = "none")]
impl BumpAllocator {
    const fn new() -> Self {
        Self {
            head: AtomicUsize::new(0),
        }
    }
}

#[cfg(target_os = "none")]
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut current = self.head.load(Ordering::Relaxed);
        loop {
            let aligned = align_up(current, layout.align());
            let next = match aligned.checked_add(layout.size()) {
                Some(val) => val,
                None => return core::ptr::null_mut(),
            };
            if next > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            match self
                .head
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => {
                    let base = ptr::addr_of_mut!(HEAP) as *mut u8;
                    return base.add(aligned);
                }
                Err(old) => current = old,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[cfg(target_os = "none")]
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start(entries_ptr: u64, entries_len: u64) -> ! {
    let files = unsafe {
        core::slice::from_raw_parts(
            entries_ptr as *const zero_abi::bootfs::UserBootFile,
            entries_len as usize,
        )
    };
    zero_fs_zfs::server_main(files)
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(target_os = "none")]
#[alloc_error_handler]
fn alloc_error(_: Layout) -> ! {
    loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {
    panic!(
        "zero-fs-zfs binary must be built for the bare-metal target (e.g. aarch64-unknown-none)"
    );
}
