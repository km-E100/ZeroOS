#![no_std]

// 主机测试（cargo test）需要 std 链接；裸机构建完全不含。
#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod arch;
pub mod boot;
pub mod bootinfo;
pub mod debug;
pub mod drivers; // drivers/ 目录模块（驱动与中断服务，拆分自 drivers.rs）
pub mod elf;
pub mod ipc;
pub mod mm;
pub mod process;
pub mod rootfs;
pub mod runtime;
pub mod scheduler;
pub mod services;
pub mod shm;
pub mod syscalls;
pub mod trap;
pub mod user_elf;

use core::sync::atomic::{AtomicBool, Ordering};
use zero_abi::BootInfo;

static INITIALISED: AtomicBool = AtomicBool::new(false);

/// Microkernel entry point invoked由引导阶段，在MMU就绪后启动。
#[no_mangle]
pub extern "C" fn kernel_main(boot_info: &'static BootInfo) -> ! {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        panic!("microkernel: kernel_main invoked twice");
    }

    info!("kernel_main: runtime init");
    runtime::init();
    info!("kernel_main: bootinfo init");
    bootinfo::init(boot_info);
    info!("kernel_main: entering boot::init_arch");
    boot::init_arch(boot_info);
    info!("kernel_main: boot::init_arch complete");
    info!(
        "kernel_main: rootfs init (boot_info.rootfs=0x{:016x})",
        boot_info.rootfs as usize
    );
    rootfs::init(boot_info.rootfs);
    info!("kernel_main: rootfs ready");
    info!(
        "kernel_main: drivers init (boot_info.drivers=0x{:016x})",
        boot_info.drivers as usize
    );
    drivers::init(boot_info.drivers);
    info!("kernel_main: drivers ready");
    ipc::init();
    process::init();
    scheduler::init();

    info!("Zero OS microkernel ready; launching userland servers");
    services::launch_core(boot_info);
    info!("kernel_main: services::launch_core returned");
    // console 现在是真正的用户态进程：从 rootfs 加载独立 ELF，
    // 只通过 userlib ABI 与内核交互，不访问任何内核地址。
    //
    // blktest 回归修复（第十刀集成）：Shell 以非特权拉起（正确——
    // 不给 CAP_MMIO/CAP_SPAWN_SVC），但 acceptance.sh 的 blktest 项
    // 依赖号位 7/8 raw 直通（CAP_BLOCK_DEV，第八刀收权后 Shell 全无
    // 能力位 ⇒ "permission denied"，实机验收清单自此缺列）。此处按
    // 最小授权原则补授单一位：块设备诊断直通。对照 Linux 给 disk
    // 组成员的 CAP_SYS_RAWIO 子集授予。
    match process::spawn_user_from_bootfs("/Applications/Shell", "console", false) {
        Ok(user_pid) => {
            process::set_capabilities(user_pid, zero_abi::cap::CAP_BLOCK_DEV);
            scheduler::enqueue(user_pid)
        }
        Err(e) => info!("failed to spawn console: {:?}", e),
    }
    scheduler::run()
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        $crate::runtime::logger::log(::core::format_args!($($arg)*));
    }};
}
