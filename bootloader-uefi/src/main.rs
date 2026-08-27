#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod console;
mod boot_config;
mod boot_info;
mod boot_state;
mod elf;
mod fs;
mod kernel_loader;
mod pstore;
mod util;

use boot_config::{BootPaths, BootVariant};
use boot_info::KernelBootContext;
use boot_state::BootState;
use kernel_loader::KernelImage;
use uefi::prelude::*;

#[entry]
fn efi_main(handle: Handle, st: SystemTable<Boot>) -> Status {
    if let Err(status) = real_entry(handle, st) {
        return status;
    }
    Status::SUCCESS
}

fn real_entry(handle: Handle, mut st: SystemTable<Boot>) -> Result<(), Status> {
    uefi_services::init(&mut st).map_err(|e| e.status())?;
    console::init(&mut st);
    log::set_max_level(log::LevelFilter::Info);

    log_info!("Zero OS UEFI bootloader starting up");

    // 重启后第一屏：上次崩溃日志（若有）。必须先于任何可能重用窗口
    // 内存的中期分配完成读取与打印，随后占住窗口供本次内核使用。
    pstore::recover_previous(st.boot_services());

    let device_handle = boot_config::boot_device_handle(&st, handle)?;

    let (mut boot_paths, mut load_overrides, mut variant) = BootPaths::discover(&st, handle, None)?;
    log_info!(
        "boot variant {:?}, kernel path {}",
        variant,
        boot_paths.kernel_path
    );

    let (kernel_image, rootfs, config) = {
        let mut fs_iface = fs::FileSystem::open(device_handle, &st)?;
        let mut boot_state = BootState::load(&mut fs_iface)?;
        if boot_state.consume_success_flag() {
            log_info!("previous boot reported success, clearing failure counter");
        }

        if variant == BootVariant::Normal && boot_state.should_force_recovery() {
            log_warn!(
                "detected {} consecutive failed boots; falling back to recovery",
                boot_state.failures()
            );
            let (paths, overrides, forced_variant) =
                BootPaths::discover(&st, handle, Some(BootVariant::Recovery))?;
            boot_paths = paths;
            load_overrides = overrides;
            variant = forced_variant;
        }

        boot_state.record_attempt(&mut fs_iface, variant)?;
        log_info!("kernel path: {}", boot_paths.kernel_path);

        let config = boot_config::BootConfig::load(&mut fs_iface, &boot_paths, &load_overrides)?;
        log_info!("boot configuration loaded");

        let kernel_image = KernelImage::load(&mut fs_iface, &boot_paths, &config, &st)?;

        let rootfs = fs::load_rootfs_image(&mut fs_iface, &boot_paths, &config)?;
        (kernel_image, rootfs, config)
    };

    let boot_ctx = KernelBootContext::prepare(&mut st, &kernel_image, rootfs.as_ref(), &config)?;

    log_info!("exiting UEFI boot services");
    let _runtime_table = boot_ctx.exit_boot_services(st);

    unsafe { kernel_loader::jump_to_kernel(&kernel_image, &boot_ctx) };
}
