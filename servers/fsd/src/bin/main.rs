#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
// 自定义 OOM 处理仍是 nightly 特性（仅裸机目标启用；host 构建不受影响）。
#![cfg_attr(target_os = "none", feature(alloc_error_handler))]

#[cfg(target_os = "none")]
extern crate zero_fsd;

#[cfg(target_os = "none")]
use core::alloc::Layout;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
use useralloc::StaticFreeList;

#[cfg(target_os = "none")]
const HEAP_SIZE: usize = 64 * 1024;
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: StaticFreeList<HEAP_SIZE> = StaticFreeList::new();

#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 内核加载器不保证清零 .bss（launchd/shell 同款前置）：
    // 本 crate 的静态 Mutex/AtomicBool/文件表全在 .bss，脏数据会直接破坏状态。
    unsafe {
        extern "C" {
            static mut __bss_start: u8;
            static mut __bss_end: u8;
        }
        let mut p = &raw mut __bss_start as *mut u8;
        let end = &raw mut __bss_end as *mut u8;
        while p < end {
            core::ptr::write_volatile(p, 0);
            p = p.add(1);
        }
    }
    zero_fsd::server_main()
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // 尽力在控制台留下痕迹后停机；console 失败则原地循环。
    if userlib::console_write(b"\nfsd panic\n").is_err() {
        loop {}
    }
    loop {}
}

#[cfg(target_os = "none")]
#[alloc_error_handler]
fn alloc_error(_: Layout) -> ! {
    loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {
    panic!("zero-fsd must be built for the bare-metal target");
}
