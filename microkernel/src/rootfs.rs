use core::sync::atomic::{AtomicPtr, Ordering};
use core::{cmp, mem, ptr};

use alloc::vec::Vec;

use crate::mm::address_space::{AddressSpace, MapError};
// PAGE_SIZE 已由 mm Agent 迁移至 table_walk 模块（paging 不再公开导出）。
use crate::mm::table_walk::PAGE_SIZE;
use crate::mm::phys;

use zero_abi::boot::{RootFsEntry, RootFsImage};
use zero_abi::bootfs::{UserBootFile, UserBootFs};

//
// -----------------------------------------------------------------------------
//  Global State
// -----------------------------------------------------------------------------
static ROOTFS_PTR: AtomicPtr<RootFsImage> = AtomicPtr::new(ptr::null_mut());

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

    // 全量校验（指针/对齐/条目完整性）后再登记——损坏的 rootfs 描述符
    // 若带病上线，会在任意 read_file 路径以更难定位的方式爆炸。
    let image = validate_rootfs_image(image_ptr);
    crate::info!(
        "rootfs::init: validated entry_count={} entries_ptr=0x{:016x}",
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
/// 一个文件/路径所需物理页数（向上取整），支持任意大小文件。
pub const fn pages_for_len(len: usize) -> usize {
    len.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE
}

/// 把数据按页拷贝到新分配的**物理连续**页中，返回 (首页物理地址, 页数)。
/// 用户侧看到的地址总是连续的（虚拟连续 + 物理连续），首页基址可直接推导后续页。
fn copy_into_pages(src: &[u8]) -> Option<(usize, usize)> {
    if src.is_empty() {
        return Some((0, 0));
    }
    let pages = pages_for_len(src.len());
    let first = phys::alloc_pages_contiguous(pages)?;
    let mut copied = 0usize;
    for i in 0..pages {
        let current = first + i * PAGE_SIZE;
        let chunk = cmp::min(PAGE_SIZE, src.len() - copied);
        unsafe {
            // 恒等映射下物理页可直接写入。
            core::ptr::write_bytes(current as *mut u8, 0, PAGE_SIZE);
            core::ptr::copy_nonoverlapping(src.as_ptr().add(copied), current as *mut u8, chunk);
        }
        copied += chunk;
    }
    Some((first, pages))
}

pub fn build_user_bootfs_metadata(image: &RootFsImage) -> (Vec<UserBootFile>, usize) {
    let entries = unsafe { image.as_slice() };
    let mut files = Vec::with_capacity(entries.len());

    for entry in entries {
        let path = unsafe { entry.path() };
        let path_len = path.len();
        let data = unsafe { entry.data() };
        let data_len = data.len();

        // 支持多页文件（如 /Applications/Shell 这种 2.6MB 的 ELF）。
        // path_phys / data_phys 记录首页物理地址即可：虚拟地址连续，
        // 且物理地址在下发用户态前会被抹除，消费者只依赖 data_ptr/data_len。
        let (path_phys, _) = copy_into_pages(path.as_bytes()).expect("bootfs: OOM");
        let (data_phys, _) = copy_into_pages(data).expect("bootfs: OOM");

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
        base += pages_for_len(file.path_len as usize) * PAGE_SIZE;

        file.data_ptr = base as u64;
        base += pages_for_len(file.data_len as usize) * PAGE_SIZE;
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

    let cursor = assign_user_bootfs_virtual_addresses(&mut files, user_base);

    // Map pages（每个文件可能跨多页，路径与数据分别映射完整页数）
    for file in files.iter() {
        unsafe {
            let path_pages = pages_for_len(file.path_len as usize);
            for i in 0..path_pages {
                aspace.map_page_phys(
                    file.path_ptr as usize + i * PAGE_SIZE,
                    file.path_phys as usize + i * PAGE_SIZE,
                    false,
                    false,
                )?;
            }
            let data_pages = pages_for_len(file.data_len as usize);
            for i in 0..data_pages {
                aspace.map_page_phys(
                    file.data_ptr as usize + i * PAGE_SIZE,
                    file.data_phys as usize + i * PAGE_SIZE,
                    false,
                    false,
                )?;
            }
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