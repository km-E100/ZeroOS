use zero_abi::boot::{RootFsEntry, RootFsImage};

// 内核自带的 rootfs 条目。通过 #[no_mangle] 强符号覆盖 boot/boot.S 中
// 同名弱符号（默认是 .quad 0 占位），使 boot_info_struct 指向真实数据。
#[no_mangle]
#[used]
#[link_section = ".rodata.boot"]
pub static __zero_rootfs_entries: [RootFsEntry; 7] = [
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
];

#[no_mangle]
#[used]
#[link_section = ".rodata.boot"]
pub static __zero_rootfs_image: RootFsImage = RootFsImage::new(
    &__zero_rootfs_entries as *const RootFsEntry,
    __zero_rootfs_entries.len(),
);
