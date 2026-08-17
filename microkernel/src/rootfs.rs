use core::sync::atomic::{AtomicPtr, Ordering};
use core::{cmp, mem, ptr};

use alloc::{boxed::Box, vec::Vec};

use crate::mm::address_space::{AddressSpace, MapError};
use crate::mm::paging::PAGE_SIZE;
use crate::mm::phys;
use spin::Mutex;
use zero_abi::boot::{RootFsEntry, RootFsImage};
use zero_abi::bootfs::{UserBootFile, UserBootFs};

//
// -----------------------------------------------------------------------------
//  Global State
// -----------------------------------------------------------------------------
static ROOTFS_PTR: AtomicPtr<RootFsImage> = AtomicPtr::new(ptr::null_mut());
static BOOTFS_CACHE: Mutex<Option<Vec<UserBootFile>>> = Mutex::new(None);

pub const USER_BOOTFS_BASE: usize = 0x0000_8000_0000;

//
// -----------------------------------------------------------------------------
//  Initialization
// -----------------------------------------------------------------------------
pub fn init(image_ptr: *const RootFsImage) {
    crate::info!("rootfs::init: begin image_ptr=0x{:016x}", image_ptr as usize);

    if image_ptr.is_null() {
        crate::info!("rootfs::init: image_ptr is NULL, skipping");
        return;
    }

    // 这里先只读 header 两个字段，不走 as_slice / entry.path() 之类复杂路径
    let image = unsafe { &*image_ptr };
    crate::info!(
        "rootfs::init: header entry_count={} entries_ptr=0x{:016x}",
        image.entry_count,
        image.entries as usize
    );

    ROOTFS_PTR.store(image_ptr as *mut RootFsImage, Ordering::SeqCst);

    crate::info!("rootfs::init: end");
}

//
// -----------------------------------------------------------------------------
//  Validation
// -----------------------------------------------------------------------------
fn validate_rootfs_image(image_ptr: *const RootFsImage) -> &'static RootFsImage {
    const IDENTITY_LIMIT: usize = 0x0000_0000_8000_0000; // first 2 GiB

    assert!(!image_ptr.is_null(), "rootfs::init: NULL image pointer");
    assert_eq!(
        (image_ptr as usize) % mem::align_of::<RootFsImage>(),
        0,
        "rootfs::init: image pointer misaligned"
    );

    let image = unsafe { &*image_ptr };

    assert!(image.entry_count > 0, "rootfs::init: entry_count = 0");

    assert!(!image.entries.is_null(), "rootfs::init: entries pointer NULL");

    assert_eq!(
        (image.entries as usize) % mem::align_of::<RootFsEntry>(),
        0,
        "rootfs::init: entries pointer misaligned"
    );

    let entry_bytes = image.entry_count * mem::size_of::<RootFsEntry>();
    let entries_base = image.entries as usize;
    let entries_limit = entries_base + entry_bytes;

    assert!(
        entries_limit <= IDENTITY_LIMIT,
        "rootfs::init: entries (0x{:016x}..0x{:016x}) outside identity map",
        entries_base,
        entries_limit
    );

    unsafe {
        let slice = core::slice::from_raw_parts(image.entries, image.entry_count);
        for (i, entry) in slice.iter().enumerate() {
            assert!(!entry.path_ptr.is_null(),  "rootfs::init: entry {} has NULL path", i);
            assert!(!entry.data_ptr.is_null(),  "rootfs::init: entry {} has NULL data", i);
        }
    }

    image
}

//
// -----------------------------------------------------------------------------
//  Accessors
// -----------------------------------------------------------------------------
pub fn image() -> Option<&'static RootFsImage> {
    let ptr = ROOTFS_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

pub fn entries() -> Option<&'static [RootFsEntry]> {
    image().map(|img| unsafe {
        core::slice::from_raw_parts(img.entries, img.entry_count)
    })
}

//
// -----------------------------------------------------------------------------
//  Build user bootfs metadata
// -----------------------------------------------------------------------------
pub fn build_user_bootfs_metadata(image: &RootFsImage) -> (Vec<UserBootFile>, usize) {
    let entries = unsafe { image.as_slice() };
    let mut files = Vec::with_capacity(entries.len());

    for entry in entries {
        let path = unsafe { entry.path() };
        let path_len = path.len();

        assert!(path_len <= PAGE_SIZE, "bootfs path too long");

        let path_phys = phys::alloc_page().expect("bootfs: OOM");
        unsafe {
            // 恒等映射下物理页可直接写入。
            core::ptr::copy_nonoverlapping(path.as_ptr(), path_phys as *mut u8, path_len);
        }

        let data = unsafe { entry.data() };
        let data_len = data.len();

        assert!(data_len <= PAGE_SIZE, "bootfs data too large");

        let data_phys = phys::alloc_page().expect("bootfs: OOM");
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), data_phys as *mut u8, data_len);
        }

        files.push(UserBootFile {
            path_phys: path_phys as u64,
            path_len: path_len as u64,
            path_ptr: 0,
            data_phys: data_phys as u64,
            data_len: data_len as u64,
            data_ptr: 0,
        });
    }

    // ⬇⬇⬇ 关键修复：不能在 move 后再 borrow ⬇⬇⬇
    let count = files.len();
    (files, count)
}

pub fn assign_user_bootfs_virtual_addresses(
    files: &mut [UserBootFile],
    mut base: usize,
) -> usize {
    for file in files.iter_mut() {
        file.path_ptr = base as u64;
        base += PAGE_SIZE;

        file.data_ptr = base as u64;
        base += PAGE_SIZE;
    }
    base
}

//
// -----------------------------------------------------------------------------
//  Build full user bootfs
// -----------------------------------------------------------------------------
pub fn build_user_bootfs_for_process(
    aspace: &mut AddressSpace,
    user_base: usize,
) -> Result<UserBootFs, MapError> {
    let image = match image() {
        Some(i) => i,
        None => {
            return Ok(UserBootFs { entries_ptr: 0, entries_len: 0 });
        }
    };

    let (mut files, count) = build_user_bootfs_metadata(image);

    if count == 0 {
        return Ok(UserBootFs { entries_ptr: 0, entries_len: 0 });
    }

    let mut cursor = assign_user_bootfs_virtual_addresses(&mut files, user_base);

    // Map pages
    for file in files.iter() {
        unsafe {
            aspace.map_page_phys(file.path_ptr as usize, file.path_phys as usize, false, false)?;
            aspace.map_page_phys(file.data_ptr as usize, file.data_phys as usize, false, false)?;
        }
    }

    // Erase physical pointers (handed to user)
    for file in files.iter_mut() {
        file.path_phys = 0;
        file.data_phys = 0;
    }

    // Serialize metadata
    let entry_bytes = count * mem::size_of::<UserBootFile>();
    let entries_base = (cursor + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let meta_bytes = unsafe {
        core::slice::from_raw_parts(files.as_ptr() as *const u8, entry_bytes)
    };

    let mut virt = entries_base;
    let mut offset = 0;

    while offset < entry_bytes {
        let chunk = cmp::min(PAGE_SIZE, entry_bytes - offset);
        let phys = phys::alloc_page().ok_or(MapError::OutOfMemory)?;

        unsafe {
            // 恒等映射下物理页可直接写入。
            let dst = phys as *mut u8;
            ptr::copy_nonoverlapping(meta_bytes.as_ptr().add(offset), dst, chunk);
            if chunk < PAGE_SIZE {
                ptr::write_bytes(dst.add(chunk), 0, PAGE_SIZE - chunk);
            }
            aspace.map_page_phys(virt, phys, true, false)?;
        }

        virt += PAGE_SIZE;
        offset += chunk;
    }

    Ok(UserBootFs {
        entries_ptr: entries_base as u64,
        entries_len: count as u64,
    })
}

//
// -----------------------------------------------------------------------------
//  read_file() – load file contents
// -----------------------------------------------------------------------------
/// 在根文件系统镜像中按路径查找文件内容。
/// 此前实现永远返回 None，导致 build_user_elf / map_user_elf_segments
/// 全部失败，任何用户进程都无法启动。
pub fn read_file(path: &str) -> Option<&'static [u8]> {
    let image = image()?;
    let entries = unsafe { image.as_slice() };
    for entry in entries {
        let entry_path = unsafe { entry.path() };
        if entry_path == path {
            return Some(unsafe { entry.data() });
        }
    }
    None
}