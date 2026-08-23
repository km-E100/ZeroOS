use zero_abi::boot::{RootFsEntry, RootFsImage};

// 内核自带的 rootfs 条目。通过 #[no_mangle] 强符号覆盖 boot/boot.S 中
// 同名弱符号（默认是 .quad 0 占位），使 boot_info_struct 指向真实数据。
#[no_mangle]
#[used]
#[link_section = ".rodata.boot"]
pub static __zero_rootfs_entries: [RootFsEntry; 10] = [
    RootFsEntry::new(
        "/etc/motd",
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/rootfs/etc/motd")),
    ),
    RootFsEntry::new(
        "/etc/users",
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/rootfs/etc/users")),
    ),
    RootFsEntry::new(
        "/System/LaunchDaemons/com.zero.ipcrouter.plist",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rootfs/System/LaunchDaemons/com.zero.ipcrouter.plist"
        )),
    ),
    RootFsEntry::new(
        "/System/Volumes/root.json",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rootfs/System/Volumes/root.json"
        )),
    ),
    RootFsEntry::new(
        "/Applications/LaunchServices/launchd.sh",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rootfs/Applications/LaunchServices/launchd.sh"
        )),
    ),
    RootFsEntry::new(
        "/System/Core/zero-launchd",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rootfs/System/Core/zero-launchd"
        )),
    ),
    RootFsEntry::new(
        "/Applications/Shell",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rootfs/Applications/Shell"
        )),
    ),
    // securityd 用户态服务裸机 ELF（由 xtask sync_userland_blobs 从
    // target/aarch64-unknown-none/release/zero-securityd 同步而来；
    // 内核侧仅登记路径，spawn 由 launchd 经 SpawnService 触发）。
    RootFsEntry::new(
        "/System/Core/zero-securityd",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rootfs/System/Core/zero-securityd"
        )),
    ),
    // blkdrv 块设备服务裸机 ELF（xtask sync_userland_blobs 同步；
    // launchd 启动对账时按名 spawn，见 services/mod.rs bundled）。
    RootFsEntry::new(
        "/System/Core/zero-blkdrv",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rootfs/System/Core/zero-blkdrv"
        )),
    ),
    // fsd 文件服务裸机 ELF（块后端卷文件表，fstest 端到端验证）。
    RootFsEntry::new(
        "/System/Core/zero-fsd",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rootfs/System/Core/zero-fsd"
        )),
    ),
];

#[no_mangle]
#[used]
#[link_section = ".rodata.boot"]
pub static __zero_rootfs_image: RootFsImage = RootFsImage::new(
    &__zero_rootfs_entries as *const RootFsEntry,
    __zero_rootfs_entries.len(),
);
