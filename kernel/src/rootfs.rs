use zero_abi::boot::{RootFsEntry, RootFsImage};

const ROOTFS_ENTRIES: [RootFsEntry; 6] = [
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
];

//#[no_mangle]
//#[used]
//pub static __zero_rootfs_entries: [RootFsEntry; ROOTFS_ENTRIES.len()] = ROOTFS_ENTRIES;

//#[no_mangle]
//#[used]
//#[link_section = ".rodata.boot"]
//pub static __zero_rootfs_image: RootFsImage =
//    RootFsImage::new(__zero_rootfs_entries.as_ptr(), __zero_rootfs_entries.len());
