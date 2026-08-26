#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![cfg_attr(target_os = "none", feature(alloc_error_handler))]

#[cfg(target_os = "none")]
extern crate zero_fs_zfs;

#[cfg(target_os = "none")]
use core::alloc::Layout;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
use useralloc::StaticFreeList;

#[cfg(target_os = "none")]
const HEAP_SIZE: usize = 1024 * 1024;
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: StaticFreeList<HEAP_SIZE> = StaticFreeList::new();

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
    let _ = userlib::console_write(b"zfsd: OOM\r\n");
    userlib::exit(120)
}

#[cfg(not(target_os = "none"))]
fn main() {
    panic!(
        "zero-fs-zfs binary must be built for the bare-metal target (e.g. aarch64-unknown-none)"
    );
}
