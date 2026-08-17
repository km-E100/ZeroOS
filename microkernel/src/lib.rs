#![no_std]

extern crate alloc;

pub mod arch;
pub mod boot;
pub mod bootinfo;
pub mod drivers;
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
pub mod user_shell;

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
    let user_pid = process::spawn_user(user_shell::user_entry, "console");
    scheduler::enqueue(user_pid);
    scheduler::run()
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        $crate::runtime::logger::log(::core::format_args!($($arg)*));
    }};
}
