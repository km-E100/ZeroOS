use zero_abi::boot::RootFsImage;

// Bootfs is no longer embedded into the kernel ELF. The UEFI loader parses
// rootfs.bundle and patches this tiny descriptor before ExitBootServices.
// boot/boot.S stores the address of this symbol in BootInfo.rootfs.
#[no_mangle]
#[used]
#[link_section = ".data.boot"]
pub static mut __zero_rootfs_image: RootFsImage = RootFsImage::new(core::ptr::null(), 0);
