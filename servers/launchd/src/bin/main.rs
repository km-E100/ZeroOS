//! zero-launchd 裸机二进制包装。
//!
//! - 裸机目标（`target_os = "none"`）：`_start` 由 `zero_launchd` lib
//!   提供（清 .bss → `server_main`），此处只挂 panic handler；
//! - host 目标：`main()` 立即 panic，防止误在 host 上链接裸机二进制。

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate zero_launchd;

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // 裸机 panic：没有可用的格式化输出路径，直接挂起。
    loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {
    panic!("zero-launchd must be built for the bare-metal target (aarch64-unknown-none)")
}
