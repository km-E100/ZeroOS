use core::{cmp, mem, ptr};

use alloc::vec::Vec;
use spin::Mutex;

use crate::mm::address_space::{AddressSpace, MapError};
// PAGE_SIZE 已由 mm Agent 迁移至 table_walk 模块（paging 不再公开导出）。
use crate::mm::phys;
use crate::mm::table_walk::PAGE_SIZE;

use zero_abi::boot::{RootFsEntry, RootFsImage};
use zero_abi::bootfs::{UserBootFile, UserBootFs};

//
// -----------------------------------------------------------------------------
//  Global State
// -----------------------------------------------------------------------------
/// 全系统唯一的 immutable bootfs 物理缓存。bundle/UEFI 内存不直接暴露给
/// EL0：启动时复制到物理分配器一次，之后所有进程只 retain + RO map。
struct BootFsCache {
    files: Vec<UserBootFile>,
    entries_phys: usize,
    entries_pages: usize,
    entries_base: usize,
    count: usize,
    payload_pages: usize,
}

static BOOTFS_CACHE: Mutex<Option<BootFsCache>> = Mutex::new(None);

pub const USER_BOOTFS_BASE: usize = 0x0000_8000_0000;

//
// -----------------------------------------------------------------------------
//  Initialization
// -----------------------------------------------------------------------------
pub fn init(image_ptr: *const RootFsImage) {
    crate::info!(
        "rootfs::init: begin image_ptr=0x{:016x}",
        image_ptr as usize
    );

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

    // Transfer ownership away from firmware/UEFI memory now, while its original
    // pointers are still valid under firmware translation. After this cache is
    // built, no runtime path may dereference RootFsImage/RootFsEntry source
    // pointers again.

    // 第25刀：把 bootfs payload 复制进物理分配器**一次**。旧实现每次
    // spawn/exec 都复制整份 bootfs；服务数增长后 9MiB × N 直接把启动
    // 拖到分钟级。缓存持有每页的基础引用，进程映射只 retain/free 自己
    // 的那一份引用，因此任一进程退出都不会破坏其他进程或缓存本体。
    let cache = build_bootfs_cache(image, USER_BOOTFS_BASE)
        .expect("rootfs: unable to build immutable bootfs cache");
    crate::info!(
        "rootfs: shared bootfs cache entries={} payload_pages={} metadata_pages={}",
        cache.count,
        cache.payload_pages,
        cache.entries_pages
    );
    *BOOTFS_CACHE.lock() = Some(cache);

    crate::info!("rootfs::init: end");
}

//
// -----------------------------------------------------------------------------
//  Validation
// -----------------------------------------------------------------------------
fn validate_rootfs_image(image_ptr: *const RootFsImage) -> &'static RootFsImage {
    const MAX_BOOTFS_ENTRIES: usize = 4096;

    assert!(!image_ptr.is_null(), "rootfs::init: NULL image pointer");
    assert_eq!(
        (image_ptr as usize) % mem::align_of::<RootFsImage>(),
        0,
        "rootfs::init: image pointer misaligned"
    );

    let image = unsafe { &*image_ptr };

    assert!(image.entry_count > 0, "rootfs::init: entry_count = 0");
    assert!(
        image.entry_count <= MAX_BOOTFS_ENTRIES,
        "rootfs::init: implausible entry_count {}",
        image.entry_count
    );

    assert!(
        !image.entries.is_null(),
        "rootfs::init: entries pointer NULL"
    );

    assert_eq!(
        (image.entries as usize) % mem::align_of::<RootFsEntry>(),
        0,
        "rootfs::init: entries pointer misaligned"
    );

    let entry_bytes = image
        .entry_count
        .checked_mul(mem::size_of::<RootFsEntry>())
        .expect("rootfs::init: entry table size overflow");
    let entries_base = image.entries as usize;
    let _entries_limit = entries_base
        .checked_add(entry_bytes)
        .expect("rootfs::init: entry table address overflow");

    // No 2GiB identity-map requirement here: this function intentionally runs
    // before Zero OS replaces the firmware translation regime. Parallels and
    // real firmware are free to allocate the bootfs table above 2GiB.
    unsafe {
        let slice = core::slice::from_raw_parts(image.entries, image.entry_count);
        for (i, entry) in slice.iter().enumerate() {
            assert!(
                !entry.path_ptr.is_null(),
                "rootfs::init: entry {} has NULL path",
                i
            );
            assert!(
                !entry.data_ptr.is_null(),
                "rootfs::init: entry {} has NULL data",
                i
            );
        }
    }

    image
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

fn build_user_bootfs_metadata(image: &RootFsImage) -> (Vec<UserBootFile>, usize, usize) {
    let entries = unsafe { image.as_slice() };
    let mut files = Vec::with_capacity(entries.len());
    let mut payload_pages = 0usize;

    for entry in entries {
        let path = unsafe { entry.path() };
        let path_len = path.len();
        let data = unsafe { entry.data() };
        let data_len = data.len();

        let (path_phys, path_pages) = copy_into_pages(path.as_bytes()).expect("bootfs: OOM");
        let (data_phys, data_pages) = copy_into_pages(data).expect("bootfs: OOM");
        payload_pages = payload_pages.saturating_add(path_pages + data_pages);

        files.push(UserBootFile {
            path_phys: path_phys as u64,
            path_len: path_len as u64,
            path_ptr: 0,
            data_phys: data_phys as u64,
            data_len: data_len as u64,
            data_ptr: 0,
        });
    }

    let count = files.len();
    (files, count, payload_pages)
}

pub fn assign_user_bootfs_virtual_addresses(files: &mut [UserBootFile], mut base: usize) -> usize {
    for file in files.iter_mut() {
        file.path_ptr = base as u64;
        base += pages_for_len(file.path_len as usize) * PAGE_SIZE;

        file.data_ptr = base as u64;
        base += pages_for_len(file.data_len as usize) * PAGE_SIZE;
    }
    base
}

fn build_bootfs_cache(image: &RootFsImage, user_base: usize) -> Result<BootFsCache, MapError> {
    let (mut files, count, payload_pages) = build_user_bootfs_metadata(image);
    let cursor = assign_user_bootfs_virtual_addresses(&mut files, user_base);
    let entries_base = (cursor + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let entry_bytes = count * mem::size_of::<UserBootFile>();
    let entries_pages = pages_for_len(entry_bytes);

    // 用户可见元数据不泄露物理地址；布局固定，因此所有进程可共享同一页。
    let mut user_files = files.clone();
    for file in user_files.iter_mut() {
        file.path_phys = 0;
        file.data_phys = 0;
    }
    let entries_phys = if entries_pages == 0 {
        0
    } else {
        let first = phys::alloc_pages_contiguous(entries_pages).ok_or(MapError::OutOfMemory)?;
        let bytes =
            unsafe { core::slice::from_raw_parts(user_files.as_ptr() as *const u8, entry_bytes) };
        unsafe {
            ptr::write_bytes(first as *mut u8, 0, entries_pages * PAGE_SIZE);
            ptr::copy_nonoverlapping(bytes.as_ptr(), first as *mut u8, entry_bytes);
        }
        first
    };

    Ok(BootFsCache {
        files,
        entries_phys,
        entries_pages,
        entries_base,
        count,
        payload_pages,
    })
}

#[inline]
unsafe fn retain_and_map_ro(
    aspace: &mut AddressSpace,
    virt: usize,
    phys_addr: usize,
) -> Result<(), MapError> {
    phys::retain_page(phys_addr);
    if let Err(err) = aspace.map_page_phys(virt, phys_addr, false, false) {
        // retain 尚未进入页表，必须单独撤销；已成功映射的旧页由调用方
        // destroy address space 时逐叶 free，缓存自己的基础引用始终保留。
        phys::free_page(phys_addr);
        return Err(err);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
//  Build per-process view of the globally shared immutable bootfs
// -----------------------------------------------------------------------------
pub fn build_user_bootfs_for_process(
    aspace: &mut AddressSpace,
    _user_base: usize,
) -> Result<UserBootFs, MapError> {
    let guard = BOOTFS_CACHE.lock();
    let Some(cache) = guard.as_ref() else {
        return Ok(UserBootFs {
            entries_ptr: 0,
            entries_len: 0,
        });
    };
    if cache.count == 0 {
        return Ok(UserBootFs {
            entries_ptr: 0,
            entries_len: 0,
        });
    }

    for file in cache.files.iter() {
        for i in 0..pages_for_len(file.path_len as usize) {
            unsafe {
                retain_and_map_ro(
                    aspace,
                    file.path_ptr as usize + i * PAGE_SIZE,
                    file.path_phys as usize + i * PAGE_SIZE,
                )?;
            }
        }
        for i in 0..pages_for_len(file.data_len as usize) {
            unsafe {
                retain_and_map_ro(
                    aspace,
                    file.data_ptr as usize + i * PAGE_SIZE,
                    file.data_phys as usize + i * PAGE_SIZE,
                )?;
            }
        }
    }

    for i in 0..cache.entries_pages {
        unsafe {
            retain_and_map_ro(
                aspace,
                cache.entries_base + i * PAGE_SIZE,
                cache.entries_phys + i * PAGE_SIZE,
            )?;
        }
    }

    Ok(UserBootFs {
        entries_ptr: cache.entries_base as u64,
        entries_len: cache.count as u64,
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
    let guard = BOOTFS_CACHE.lock();
    let cache = guard.as_ref()?;
    let wanted = path.as_bytes();
    for file in &cache.files {
        if file.path_phys == 0 {
            continue;
        }
        let path_bytes = unsafe {
            core::slice::from_raw_parts(file.path_phys as *const u8, file.path_len as usize)
        };
        if path_bytes != wanted {
            continue;
        }
        let data_len = file.data_len as usize;
        if data_len == 0 {
            return Some(&[]);
        }
        if file.data_phys == 0 {
            return None;
        }
        let data_ptr = file.data_phys as *const u8;
        // The cache owns a permanent base reference to every payload page for the
        // lifetime of the kernel. Returning a 'static view is therefore sound
        // even after the metadata mutex guard is dropped.
        return Some(unsafe { core::slice::from_raw_parts(data_ptr, data_len) });
    }
    None
}
