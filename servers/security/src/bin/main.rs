#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
// 自定义 OOM 处理仍是 nightly 特性（仅裸机目标启用；host 构建不受影响）。
#![cfg_attr(target_os = "none", feature(alloc_error_handler))]

#[cfg(target_os = "none")]
extern crate zero_securityd;

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
const HEAP_SIZE: usize = 32 * 1024;
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
extern "C" {
    static mut __bss_start: u8;
    static mut __bss_end: u8;
}

/// 入口（链接脚本 `ENTRY(_start)`，基址 0x200000，见 link.x）。
///
/// 内核 `process::spawn_user_from_bootfs` 以 x0-x3 传入启动参数：
/// - x0 = bootfs 文件表首地址（`UserBootFs.entries_ptr`）
/// - x1 = bootfs 条目数（`UserBootFs.entries_len`）
///
/// 与 user_app/shell 同一契约。先清 .bss（内核加载器不保证清零），
/// 再把 bootfs 参数交给服务主循环。
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start(a0: u64, a1: u64, _a2: u64, _a3: u64) -> ! {
    unsafe {
        let mut p = &raw mut __bss_start as *mut u8;
        let end = &raw mut __bss_end as *mut u8;
        while p < end {
            core::ptr::write_volatile(p, 0);
            p = p.add(1);
        }
    }
    zero_securityd::server_main(a0, a1)
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // 尽力在控制台留下痕迹后退出；console 失败则原地停机。
    let msg = b"\nsecurityd panic\n";
    if userlib::console_write(msg).is_err() {
        loop {}
    }
    userlib::exit(1)
}

#[cfg(target_os = "none")]
#[alloc_error_handler]
fn alloc_error(_: Layout) -> ! {
    let msg = b"\nsecurityd OOM\n";
    if userlib::console_write(msg).is_err() {
        loop {}
    }
    userlib::exit(1)
}

#[cfg(not(target_os = "none"))]
fn main() {
    panic!(
        "zero-securityd binary must be built for the bare-metal target (e.g. aarch64-unknown-none)"
    );
}
