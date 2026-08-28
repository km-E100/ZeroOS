use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;

use super::phys;
use super::table_walk::{
    self, classify_leaf, cow_break_leaf, cow_share_leaf, descriptor_to_table, is_cow_leaf,
    is_table, is_valid, make_leaf_descriptor, make_table_descriptor, page_table_indices, walk,
    LeafShareClass, AP_EL1_RW_EL0_NONE, DESC_AF, DESC_ATTRIDX_DEVICE_NGNRE, DESC_ATTRIDX_NORMAL,
    DESC_PXN, DESC_SH_INNER, DESC_SW_BORROWED, DESC_SW_DEVICE, DESC_TYPE_TABLE, DESC_UXN,
    DESC_VALID, KERNEL_SHARED_L1 as TW_KERNEL_SHARED_L1, PHYS_ADDR_MASK, USER_AP_RW, USER_AP_RX,
};

// 本文件所用常量与 table_walk.rs 保持一致（语义相同，直接复用）。
pub use super::table_walk::PAGE_SIZE;
pub const USER_BASE_TEXT: usize = 0x0040_0000;
pub const USER_BASE_DATA: usize = 0x0060_0000;
pub const USER_STACK_TOP: usize = 0x0000_FFFF_F000;
pub const USER_STACK_LEN: usize = 0x0000_0000_0002_0000; // 128 KiB user stack
static mut ID_MAP_BASE: u64 = 0;
static mut ID_MAP_SIZE: u64 = 0;

/// Shared kernel-only virtual window for high PCI ECAM/BAR MMIO.
/// L1 entry 510 is inside L0[0] but far above the user ABI (<4GiB).
pub const KERNEL_IOREMAP_L1: usize = 510;
pub const KERNEL_IOREMAP_BASE: usize = KERNEL_IOREMAP_L1 << 30;
const KERNEL_IOREMAP_SIZE: usize = 1usize << 30;

#[derive(Copy, Clone)]
struct IoremapRange {
    phys: usize,
    len: usize,
    virt: usize,
}
static IOREMAP_NEXT: Mutex<usize> = Mutex::new(0);
static IOREMAP_RANGES: Mutex<Vec<IoremapRange>> = Mutex::new(Vec::new());

pub fn configure_identity_map(base: u64, size: u64) {
    unsafe {
        ID_MAP_BASE = base;
        ID_MAP_SIZE = size;
    }
}

#[repr(C, align(4096))]
#[derive(Copy, Clone)]
pub struct PageTable(pub [u64; 512]);

pub unsafe fn init_kernel_page_table() {
    // 简单恒等映射（4 级翻译）：
    // * L0: 根表，单个表描述符指向内核 L1
    // * L1: 每个 entry 指向一个 L2 表
    // * L2: 使用 2 MiB block 覆盖 [0, 2 GiB)
    //
    // 这包含了当前内核、堆、用户栈以及常用 MMIO 区域。
    crate::info!("paging: init_kernel_page_table: building identity map");

    const BLOCK_SIZE_L2: u64 = 1u64 << 21; // 2 MiB blocks at L2
    const BLOCKS_PER_L2: usize = 512; // 512 * 2MiB = 1GiB
    const NUM_L2_TABLES: usize = 2; // map first 2 GiB via two L2 tables

    // 页面属性基座：有效 block，Inner-shareable，AF=1，AP=EL1-only。
    // AttrIdx 按块地址二选一：
    //   * [DEVICE_LO, DEVICE_HI) → Device-nGnRE（MMIO 区间；Normal-cacheable
    //     下 volatile 绕不过硬件写合并，真实设备会收到错序访问）
    //   * 其余 → Normal
    // QEMU virt 设备区 0x0800_0000..0x1000_0000 恰为 2MiB 对齐，块级
    // 划分无跨界。对照 Linux ioremap 的 MT_DEVICE_nGnRE。
    let flags_base = DESC_VALID | DESC_AF | DESC_SH_INNER | (AP_EL1_RW_EL0_NONE << 6);
    const DEVICE_LO: u64 = 0x0800_0000;
    const DEVICE_HI: u64 = 0x1000_0000;
    // ACPI was intentionally parsed before TTBR takeover. One 2MiB block per
    // advertised GIC/GICR/ITS/SMMU base is conservative and sufficient for the
    // register apertures used during early platform bring-up. Legacy QEMU's
    // fixed window remains for descriptor compatibility.
    let platform_mmio = crate::acpi::early_mmio_bases();

    // GOP below RAM_BASE is a device aperture, never normal RAM. Do not classify
    // high GOP aliases here; they need page-granular ioremap rather than changing
    // an entire 2MiB RAM block's memory type.
    let boot_fb_low = crate::display::boot_framebuffer_range()
        .filter(|(base, _)| *base < crate::mm::phys::RAM_BASE);

    // L0: 根表，所有 entry 先清零。
    let l0 =
        (&raw const crate::mm::kernel_l0::__zero_kernel_l0 as *const PageTable) as *mut PageTable;
    (*l0).0.fill(0);

    // L1: 作为指向 L2 的表。
    let l1 =
        (&raw const crate::mm::kernel_l1::__zero_kernel_l1 as *const PageTable) as *mut PageTable;
    (*l1).0.fill(0);

    let l1_phys = l1 as usize as u64;

    // L0[0]: table descriptor 指向 L1。
    (*l0).0[0] = make_table_descriptor(l1_phys);

    // L2: 两个表，每个覆盖 1GiB（512 * 2MiB），共 2GiB。
    let l2_0 =
        (&raw const crate::mm::kernel_l2::__zero_kernel_l2_0 as *const PageTable) as *mut PageTable;
    let l2_1 =
        (&raw const crate::mm::kernel_l2::__zero_kernel_l2_1 as *const PageTable) as *mut PageTable;
    (*l2_0).0.fill(0);
    (*l2_1).0.fill(0);
    let l2_ioremap = (&raw const crate::mm::kernel_l2::__zero_kernel_l2_ioremap as *const PageTable)
        as *mut PageTable;
    (*l2_ioremap).0.fill(0);

    // L1[0]/[1] cover identity RAM/MMIO; L1[510] is a shared kernel-only ioremap window.
    (*l1).0[0] = make_table_descriptor(l2_0 as usize as u64);
    (*l1).0[1] = make_table_descriptor(l2_1 as usize as u64);
    (*l1).0[KERNEL_IOREMAP_L1] = make_table_descriptor(l2_ioremap as usize as u64);

    let base = unsafe { ID_MAP_BASE };
    let size = unsafe { ID_MAP_SIZE };
    let map_base = base & !(BLOCK_SIZE_L2 - 1);
    let limit = base + size;
    let ram_start_block = (map_base / BLOCK_SIZE_L2) as usize;
    let ram_end_block = ((limit + BLOCK_SIZE_L2 - 1) / BLOCK_SIZE_L2) as usize;
    let max_blocks = BLOCKS_PER_L2 * NUM_L2_TABLES;
    assert!(
        ram_end_block <= max_blocks,
        "identity mapping exceeds reserved L2 tables"
    );
    for block in ram_start_block..ram_end_block {
        let table_idx = block / BLOCKS_PER_L2;
        let entry_idx = block % BLOCKS_PER_L2;
        let pa = (block as u64) * BLOCK_SIZE_L2;
        // MMIO blocks use Device-nGnRE; RAM remains Normal WB. ACPI-derived
        // bases are compared by containing 2MiB block so no exact alignment is
        // assumed. A low GOP aperture is treated the same way.
        let block_end = pa.saturating_add(BLOCK_SIZE_L2);
        let acpi_device = platform_mmio
            .iter()
            .any(|base| pa <= *base && *base < block_end);
        let fb_device = boot_fb_low
            .map(|(base, size)| {
                let start = base as u64;
                let end = start.saturating_add(size as u64);
                pa < end && start < block_end
            })
            .unwrap_or(false);
        let attridx = if (pa >= DEVICE_LO && pa < DEVICE_HI) || acpi_device || fb_device {
            super::table_walk::DESC_ATTRIDX_DEVICE_NGNRE
        } else {
            DESC_ATTRIDX_NORMAL
        };
        let entry = (pa & 0x0000_ffff_ffe0_0000) | flags_base | attridx;
        match table_idx {
            0 => (*l2_0).0[entry_idx] = entry,
            1 => (*l2_1).0[entry_idx] = entry,
            _ => unreachable!("table index out of bounds"),
        }
    }

    crate::info!("paging: kernel L0 at virt=0x{:016x}", (l0 as usize));
    crate::info!("paging: kernel L1 at virt=0x{:016x}", (l1 as usize));
}

pub unsafe fn activate_kernel_page_table() {
    // 固件 TCR_EL1 的 T0SZ=20（44-bit VA，4KiB granule）=> 翻译起始级是 L0，
    // TTBR0/TTBR1 必须指向 L0 根表（kernel_l0），而不是 L1 表。
    let l0_virt = &raw const crate::mm::kernel_l0::__zero_kernel_l0 as *const PageTable as usize;
    let l0_phys = l0_virt as u64; // identity mapping
    crate::info!("paging: installing kernel L0 @phys=0x{:016x}", l0_phys);
    unsafe {
        crate::arch::install_kernel_page_table(l0_phys);
    }
}

/// AArch64 BBM（break-before-make）屏障：dsb ishst → tlbi vaae1is → dsb ish → isb。
/// host（非 aarch64）下为 no-op，仅用于单测遍历描述符写入。
#[inline]
const fn tlbi_va_operand(va: usize) -> u64 {
    // TLBI VAAE1IS encodes VA[55:12] in Xt[43:0]. Passing the byte VA
    // invalidates a completely different translation (effectively VA<<12).
    // This bug let stale RW TLB entries survive the parent-side COW BBM.
    (va as u64) >> 12
}

#[inline]
fn kbbm_barrier(va: usize) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vaae1is, {0}",
            "dsb ish",
            "isb",
            in(reg) tlbi_va_operand(va),
            options(nostack, preserves_flags)
        );
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = va;
}

/// 在内核恒等映射中以 **4KiB 粒度** 映射一页（用于 MMIO lease 等）。
///
/// `flags` 为页描述符属性位（AP / AttrIdx / UXN/PXN 等），由调用方提供；
/// VALID 位与"页"类型位（bits[1:0]=0b11）会被强制 OR 上。
/// 目标 2MiB 槽位如果已是 block，则执行完整 BBM 拆分（break-before-make：
/// 写无效 → dsb ishst / tlbi vaae1is / dsb ish / isb → 建 L3 回填整窗 →
/// 写表描述符 → 同序屏障），再页级 BBM 更新目标页。
///
/// ⚠ 设计约束（R3）：
/// - L1[0] 的低 1GiB 属于**用户进程私有 L2_0 快照**——在已有地址空间创建之后
///   再调用本函数，新 4K 映射对已存在的用户空间**不生效**（它们是快照副本）。
/// - L1[1]（≥1GiB）与所有用户空间**共享** L2_1 表本体，改动自动对所有空间生效。
/// - 恒等映射区只覆盖 [0, 2GiB)，越界 VA 直接 panic（内核编程错误）。
///
/// # Safety
/// virt/phys 必须页对齐且落在恒等映射区内。
#[allow(static_mut_refs)]
pub unsafe fn map_kernel_page(virt: usize, phys: usize, flags: u64) -> Result<(), MapError> {
    assert_eq!(
        virt & (PAGE_SIZE - 1),
        0,
        "map_kernel_page: virt 0x{:x} not page aligned",
        virt
    );
    assert_eq!(
        phys & (PAGE_SIZE - 1),
        0,
        "map_kernel_page: phys 0x{:x} not page aligned",
        phys
    );
    let [i0, i1, i2, i3] = page_table_indices(virt);
    assert!(
        i0 == 0 && i1 <= 1,
        "map_kernel_page: VA 0x{:x} outside identity map (2GiB limit)",
        virt
    );
    let l2 = if i1 == 0 {
        kernel_l2_0() as *mut PageTable
    } else {
        &raw const crate::mm::kernel_l2::__zero_kernel_l2_1 as *const PageTable as *mut PageTable
    };
    let l2_words = (*l2).0.as_mut_ptr();
    let entry = (*l2).0[i2];
    let desc = (phys as u64 & PHYS_ADDR_MASK) | flags | DESC_VALID | DESC_TYPE_TABLE;
    let window_base = (i1 << 30) | (i2 << 21);

    if is_table(entry) {
        // 已有 L3 表：页级 BBM 更新
        let l3_words = descriptor_to_table(entry) as *mut PageTable;
        if is_valid((*l3_words).0[i3]) {
            let mut b = |va: usize| kbbm_barrier(va);
            table_walk::bbm_update_page((*l3_words).0.as_mut_ptr(), i3, virt, desc, &mut b);
        } else {
            (*l3_words).0[i3] = desc;
            kbbm_barrier(virt);
        }
    } else if is_valid(entry) {
        // block → 拆成 L3 表（BBM）
        let l3 = alloc_page_table_fallible()?;
        let mut b = |va: usize| kbbm_barrier(va);
        table_walk::bbm_split_block(
            l2_words,
            i2,
            (*l3).0.as_mut_ptr(),
            window_base,
            entry,
            i3,
            desc,
            &mut b,
        );
    } else {
        // 槽位无效（恒等映射之外/空洞）：直接挂空表并映射目标页。
        // 正常恒等映射下 [0,2GiB) 全覆盖、不会走到这里；防御处理。
        let l3 = alloc_page_table_fallible()?;
        (*l3).0[i3] = desc;
        (*l2).0[i2] = make_table_descriptor(l3 as usize as u64);
        kbbm_barrier(virt);
    }
    Ok(())
}

/// Map arbitrary physical device MMIO into the shared kernel-only ioremap window.
/// The returned VA is stable for the lifetime of the kernel. Existing covering
/// mappings are reused, so PCI capability/BAR users do not create alias storms.
pub fn ioremap_device(phys: usize, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let offset = phys & (PAGE_SIZE - 1);
    let pbase = phys & !(PAGE_SIZE - 1);
    let total = align_up(offset.checked_add(len)?, PAGE_SIZE);
    {
        let maps = IOREMAP_RANGES.lock();
        let end = pbase.checked_add(total)?;
        if let Some(m) = maps
            .iter()
            .find(|m| pbase >= m.phys && end <= m.phys + m.len)
        {
            return Some(m.virt + (phys - m.phys));
        }
    }
    let mut next = IOREMAP_NEXT.lock();
    let rel = align_up(*next, PAGE_SIZE);
    let end_rel = rel.checked_add(total)?;
    if end_rel > KERNEL_IOREMAP_SIZE {
        return None;
    }
    let vbase = KERNEL_IOREMAP_BASE.checked_add(rel)?;
    let flags = DESC_AF
        | DESC_SH_INNER
        | DESC_ATTRIDX_DEVICE_NGNRE
        | DESC_UXN
        | DESC_PXN
        | (AP_EL1_RW_EL0_NONE << 6);
    for off in (0..total).step_by(PAGE_SIZE) {
        unsafe {
            map_ioremap_page(vbase + off, pbase + off, flags).ok()?;
        }
    }
    *next = end_rel;
    IOREMAP_RANGES.lock().push(IoremapRange {
        phys: pbase,
        len: total,
        virt: vbase,
    });
    Some(vbase + offset)
}

unsafe fn map_ioremap_page(virt: usize, phys: usize, flags: u64) -> Result<(), MapError> {
    let [i0, i1, i2, i3] = page_table_indices(virt);
    if i0 != 0 || i1 != KERNEL_IOREMAP_L1 {
        return Err(MapError::KernelRegion);
    }
    let l2 = &raw const crate::mm::kernel_l2::__zero_kernel_l2_ioremap as *const PageTable
        as *mut PageTable;
    let e2 = (*l2).0[i2];
    let l3 = if is_valid(e2) {
        if !is_table(e2) {
            return Err(MapError::AlreadyMapped);
        }
        descriptor_to_table(e2) as *mut PageTable
    } else {
        let t = alloc_page_table_fallible()?;
        (*l2).0[i2] = make_table_descriptor(t as usize as u64);
        kbbm_barrier(virt);
        t
    };
    let desc = (phys as u64 & PHYS_ADDR_MASK) | flags | DESC_VALID | DESC_TYPE_TABLE;
    if is_valid((*l3).0[i3]) {
        let old = (*l3).0[i3];
        if old & PHYS_ADDR_MASK == desc & PHYS_ADDR_MASK {
            return Ok(());
        }
        let mut b = |va: usize| kbbm_barrier(va);
        table_walk::bbm_update_page((*l3).0.as_mut_ptr(), i3, virt, desc, &mut b);
    } else {
        (*l3).0[i3] = desc;
        kbbm_barrier(virt);
    }
    Ok(())
}

#[derive(Copy, Clone)]
pub struct AddressSpace {
    /// Virtual pointer to the L0 root table backing this address space.
    root_table: *mut PageTable,
    /// Physical address of the root table; needed later for TTBR0 programming.
    root_phys: u64,
}

unsafe impl Send for AddressSpace {}
unsafe impl Sync for AddressSpace {}

impl AddressSpace {
    pub fn root_phys(&self) -> u64 {
        self.root_phys
    }
}

#[derive(Debug, Copy, Clone)]
pub enum MapError {
    OutOfMemory,
    AlreadyMapped,
    /// 目标虚拟地址落在内核共享区域 [1GiB,2GiB)。
    /// 该区间与内核共享同一张 L2 表本体，任何用户映射写进去都会
    /// 摧毁内核恒等映射（代码/堆/向量表/内核栈），必须拒绝。
    KernelRegion,
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn page_table_phys(table: *mut PageTable) -> u64 {
    table as usize as u64
}

fn install_table_descriptor(parent: *mut PageTable, slot: usize, child: *mut PageTable) {
    assert!(slot < 512);
    // SAFETY: parent/child 均为内核恒等映射内的有效页表页指针。
    unsafe { (*parent).0[slot] = make_table_descriptor(page_table_phys(child)) };
}

/// 分配页表页：phys 分配器 + 页表计数 + 清零。
fn alloc_page_table_raw() -> Option<*mut PageTable> {
    phys::alloc_page_table().map(|phys| {
        unsafe {
            zero_physical_page(phys);
        }
        phys as *mut PageTable
    })
}

fn alloc_page_table_fallible() -> Result<*mut PageTable, MapError> {
    alloc_page_table_raw().ok_or(MapError::OutOfMemory)
}

unsafe fn zero_physical_page(phys: usize) {
    // 内核恒等映射覆盖整个 RAM，物理页可以直接按地址清零，
    // 无需临时映射（map_temp_page 的页表建立与清零互相递归，
    // 且索引/表覆盖问题曾导致写穿与 translation fault）。
    ptr::write_bytes(phys as *mut u8, 0, PAGE_SIZE);
}

#[allow(static_mut_refs)]
fn kernel_l1() -> *mut PageTable {
    &raw const crate::mm::kernel_l1::__zero_kernel_l1 as *const PageTable as *mut PageTable
}

#[allow(static_mut_refs)]
fn kernel_l2_0() -> *const PageTable {
    &raw const crate::mm::kernel_l2::__zero_kernel_l2_0 as *const PageTable
}

/// 与内核共享的 L1 槽位：覆盖 [1GiB,2GiB)，指向内核 L2_1 表本体。
/// 该区间包含内核镜像、堆、向量表、内核栈与 TRAP_FRAMES，用户地址空间
/// 直接共享这张表描述符（零拷贝、内核后续改动自动对所有进程可见）。
/// 任何用户映射都不得写入该区间——`map_physical_page` 入口有护栏。
/// 与 table_walk::KERNEL_SHARED_L1 同值（克隆/回收逻辑共用）。
const KERNEL_SHARED_L1: usize = TW_KERNEL_SHARED_L1;
#[inline]
fn is_kernel_shared_l1(index: usize) -> bool {
    index == KERNEL_SHARED_L1 || index == KERNEL_IOREMAP_L1
}

/// Deep-copy the kernel low-1GiB L2 snapshot for one user address space.
/// Any kernel L3 leaf copied into the process is a borrowed EL1 mapping: the
/// process neither owns nor refcounts its output PA. This keeps legacy fixed
/// MMIO visible to EL1 while making the page-table pages themselves private.
unsafe fn clone_kernel_l2_0_snapshot() -> Result<*mut PageTable, MapError> {
    let dst = alloc_page_table_fallible()?;
    let src = kernel_l2_0();
    for i in 0..512usize {
        let e2 = (*src).0[i];
        if is_valid(e2) && is_table(e2) {
            let src_l3 = descriptor_to_table(e2) as *const PageTable;
            let dst_l3 = match alloc_page_table_fallible() {
                Ok(t) => t,
                Err(err) => {
                    // Every table descriptor already installed in dst was
                    // allocated by this function, so rollback may free them.
                    for j in 0..i {
                        let d = (*dst).0[j];
                        if is_valid(d) && is_table(d) {
                            phys::free_page_table(descriptor_to_table(d) as usize);
                        }
                    }
                    phys::free_page_table(dst as usize);
                    return Err(err);
                }
            };
            for slot in 0..512usize {
                let leaf = (*src_l3).0[slot];
                (*dst_l3).0[slot] = if is_valid(leaf) {
                    leaf | DESC_SW_BORROWED
                } else {
                    0
                };
            }
            (*dst).0[i] = make_table_descriptor(dst_l3 as usize as u64);
        } else {
            (*dst).0[i] = e2;
        }
    }
    Ok(dst)
}

#[allow(static_mut_refs)]
unsafe fn create_user_address_space_fallible() -> Result<AddressSpace, MapError> {
    let l0 = alloc_page_table_fallible()?;
    let l1 = match alloc_page_table_fallible() {
        Ok(table) => table,
        Err(err) => {
            phys::free_page_table(l0 as usize);
            return Err(err);
        }
    };
    install_table_descriptor(l0, 0, l1);

    // L1[1]：复制内核 L1 的共享表描述符；该表本体不归用户空间所有。
    (*l1).0[KERNEL_SHARED_L1] = (*kernel_l1()).0[KERNEL_SHARED_L1];
    (*l1).0[KERNEL_IOREMAP_L1] = (*kernel_l1()).0[KERNEL_IOREMAP_L1];

    // L1[0]：私有低地址快照。不能只 memcpy L2 描述符：内核若因
    // PCI/ECAM 等把某个 2MiB block 拆成 L3 table，浅拷贝会让进程直接
    // 指向内核 L3 本体。随后用户映射可改坏内核表，destroy 还会把其中
    // 的 MMIO output PA 当用户 RAM 回收。这里做二级深拷贝：
    // - block 描述符按值复制（destroy 本来就不 free block output）；
    // - L3 table 分配进程私有副本，所有继承 leaf 标 DESC_SW_BORROWED。
    let l2_0 = match clone_kernel_l2_0_snapshot() {
        Ok(table) => table,
        Err(err) => {
            phys::free_page_table(l1 as usize);
            phys::free_page_table(l0 as usize);
            return Err(err);
        }
    };
    install_table_descriptor(l1, 0, l2_0);

    Ok(AddressSpace {
        root_table: l0,
        root_phys: page_table_phys(l0),
    })
}

#[allow(static_mut_refs)]
pub unsafe fn create_user_address_space() -> AddressSpace {
    match create_user_address_space_fallible() {
        Ok(space) => space,
        Err(_) => {
            crate::info!(
                "paging: OOM creating user address space (free_pages={} page_table_pages={})",
                phys::free_pages(),
                phys::page_table_pages()
            );
            panic!("paging: out of physical memory for user address space")
        }
    }
}

unsafe fn ensure_child_table(
    parent: *mut PageTable,
    index: usize,
) -> Result<*mut PageTable, MapError> {
    let entry = (*parent).0[index];
    if entry & DESC_VALID != 0 {
        if entry & DESC_TYPE_TABLE == 0 {
            // 条目是 block 描述符（bit1=0）。这是从内核页表共享进来的 2MiB
            // block（例如内核 L2 的恒等映射）。用户地址空间需要在此处建立 4K
            // 页映射（例如用户 ELF 段落在同一 2MiB 窗口内），因此必须把 block
            // 原地拆分成一个空的 L3 表，并让本条目指向它。注意：被拆分的 2MiB
            // 窗口内、未被用户显式映射的地址在用户表中将变为无效——这对用户
            // 进程是安全的（EL0 本就无权访问该窗口内的内核映射）。
            //
            // ⚠ 该地址空间尚未装入任何 TTBR（映射都发生在 spawn 期间），
            // 因此无需 BBM；一旦将来在活跃空间上映射必须补 BBM 序列。
            let l3 = alloc_page_table_fallible()?;
            (*parent).0[index] = make_table_descriptor(page_table_phys(l3));
            Ok(l3)
        } else {
            Ok(descriptor_to_table(entry) as *mut PageTable)
        }
    } else {
        let table = alloc_page_table_fallible()?;
        install_table_descriptor(parent, index, table);
        Ok(table)
    }
}

/// 与 ensure_child_table 的区别：允许把继承来的 2MiB block 描述符替换成新的 L3 表。
/// 只能作用于进程私有的 L2 表——内核共享的 L1[KERNEL_SHARED_L1] 已在
/// map_physical_page 入口被护栏拒绝。
///
/// ⚠ break-before-make：block→table 替换在 ARMv8 下属于 BBM 场景，但当前所有
/// 映射都发生在 spawn 期间、该地址空间**尚未装入任何 TTBR**，因此无需
/// BBM 序列。将来在活跃空间上做 demand paging 时必须补全
/// （先清条目 + dsb ishst + tlbi vaae1is + dsb ish + isb，再写新描述符）。
unsafe fn ensure_user_leaf_table(
    l2: *mut PageTable,
    index: usize,
) -> Result<*mut PageTable, MapError> {
    let entry = (*l2).0[index];
    if entry & DESC_VALID != 0 && entry & DESC_TYPE_TABLE != 0 {
        return Ok(descriptor_to_table(entry) as *mut PageTable);
    }
    // entry == 0（未映射）或 entry 是 block（来自内核恒等映射的私有副本）：
    // 都换成一张空 L3 表。该 2MiB 在**本地址空间**内从此归用户所有；
    // 内核 L2_0 原表一个字节都不受影响。
    let table = alloc_page_table_fallible()?;
    install_table_descriptor(l2, index, table);
    Ok(table)
}

fn make_page_descriptor(phys: u64, ap: u64, executable: bool) -> u64 {
    // Final (L2/L3) descriptors mirror the AArch64 stage-1 layout: bits[1:0]=0b11 denote
    // a page, AttrIdx selects MAIR slot 0 (Normal memory), SH=Inner Shareable keeps
    // caches coherent, AF=1 marks the entry accessed, UXN governs user execute
    // permission, and AP bits encode the requested read/write policy. PXN stays clear
    // so EL1 can inspect user memory while still enforcing UXN for EL0.
    make_leaf_descriptor(phys, ap, executable)
}

fn alloc_user_page() -> Result<usize, MapError> {
    phys::alloc_page().ok_or(MapError::OutOfMemory)
}

unsafe fn map_physical_page(
    space: &mut AddressSpace,
    virt: usize,
    phys: usize,
    ap: u64,
    executable: bool,
) -> Result<(), MapError> {
    install_leaf_descriptor(
        space,
        virt,
        make_page_descriptor(phys as u64, ap, executable),
    )
}

/// 建全表链并把**完整构造好的叶子描述符**写入 VA 槽位。
/// clone 的 COW 共享映射需要带 DESC_SW_COW 等自定义位的描述符，
/// 故从 map_physical_page 抽出本入口（安全护栏原样保留）。
///
/// # Safety
/// space 的根表必须有效且未被并发修改；virt 页对齐。
unsafe fn install_leaf_descriptor(
    space: &mut AddressSpace,
    virt: usize,
    desc: u64,
) -> Result<(), MapError> {
    assert_eq!(
        virt & (PAGE_SIZE - 1),
        0,
        "virtual address must be page aligned"
    );
    let [l0_idx, l1_idx, l2_idx, l3_idx] = page_table_indices(virt);
    // ⛔ 安全闩：L1[KERNEL_SHARED_L1] 是内核 L2_1 表本体，用户映射一旦写
    // 进去会全局摧毁内核恒等映射（代码/堆/向量表/内核栈）。任何 VA 落在
    // [1GiB,2GiB) 的映射都直接拒绝。
    if l0_idx == 0 && is_kernel_shared_l1(l1_idx) {
        return Err(MapError::KernelRegion);
    }
    let l0 = space.root_table;
    let l1 = ensure_child_table(l0, l0_idx)?;
    let l2 = ensure_child_table(l1, l1_idx)?;
    // 拆 block 必须按需进行（用户 ELF 链接基址可能变化），且只能作用于
    // 进程私有表——共享的 L2_1 已在入口被拒，到不了这一步。
    let l3 = ensure_user_leaf_table(l2, l2_idx)?;
    let table = &mut *l3;
    let old = table.0[l3_idx];
    if old & DESC_VALID != 0 {
        if old & DESC_SW_BORROWED == 0 {
            return Err(MapError::AlreadyMapped);
        }
        // Private snapshot filler may be replaced by an explicit user-owned
        // page/MMIO lease. Use BBM because this helper is also used by runtime
        // brk/SHM paths after the address space can already be active.
        let mut b = |va: usize| kbbm_barrier(va);
        table_walk::bbm_update_page(table.0.as_mut_ptr(), l3_idx, virt, desc, &mut b);
        return Ok(());
    }
    table.0[l3_idx] = desc;
    Ok(())
}

unsafe fn map_zero_region(
    space: &mut AddressSpace,
    base: usize,
    size: usize,
    ap: u64,
) -> Result<(), MapError> {
    if size == 0 {
        return Ok(());
    }
    assert_eq!(
        base & (PAGE_SIZE - 1),
        0,
        "zero region must be page aligned"
    );
    let total = align_up(size, PAGE_SIZE);
    let mut mapped = 0usize;
    while mapped < total {
        let virt = base + mapped;
        let phys = alloc_user_page()?;
        // 恒等映射下物理页可直接清零，无需临时映射。
        ptr::write_bytes(phys as *mut u8, 0, PAGE_SIZE);
        map_physical_page(space, virt, phys, ap, false)?;
        mapped += PAGE_SIZE;
    }
    Ok(())
}

pub unsafe fn map_user_stack(
    space: &mut AddressSpace,
    stack_top: usize,
    size: usize,
) -> Result<(), MapError> {
    assert!(size > 0, "stack size must be non-zero");
    let aligned_top = align_up(stack_top, PAGE_SIZE);
    let aligned_size = align_up(size, PAGE_SIZE);
    let base = aligned_top - aligned_size;
    // 栈底下方一页（base - PAGE_SIZE）保持**未映射**，作为隐式 guard 页：
    // 用户栈下溢会立即触发 translation fault，而不是静默写穿到别的数据。
    // 显式 guard 页设计（若日后需要）见 address_space::clone_space 的注释。
    map_zero_region(space, base, aligned_size, USER_AP_RW)
}

pub unsafe fn activate_user_address_space(addr_space: &AddressSpace) {
    crate::arch::set_user_ttbr(addr_space.root_phys);
}

pub unsafe fn deactivate_user_address_space() {
    crate::arch::set_user_ttbr(kernel_l0_phys());
}

/// 递归释放用户地址空间：L0/L1/私有 L2/L3 页表页 + 用户数据/栈/bootfs 物理页。
///
/// ⚠ 第十刀 COW：叶子物理页经 phys::free_page **引用减一**释放——
/// COW 共享页（clone 时 retain 过）由最后一个退出者真正回收；
/// 先退出的一方只减记账，绝不回收仍被对端映射的页
/// （回归钉死见 mm-host-tests refcount_lifecycle / cow_fork 场景）。
/// 页表页永远独占（clone 全新分配），照旧直接回收。
///
/// ⚠ 铁律：**严禁**释放 L1[KERNEL_SHARED_L1] 指向的内核 L2_1 表本体——
/// 它属于内核恒等映射 [1GiB,2GiB)（镜像/堆/向量表/内核栈），一旦 free，
/// 下一次 alloc_page 就会把内核页表当普通页发出去，全局内存被撕裂。
/// 遍历 L1 时无条件跳过该槽位（连"查看"都不需要：它永远不该被回收）。
///
/// block 条目（L2 里的内核恒等快照/MMIO block）也不释放物理内存：
/// 那些页属于内核或设备，私有 L2 副本只是"引用"它们的地址。
///
/// # Safety
/// `space` 的 root_table 必须未被并发使用；重复 destroy 同一空间将触发
/// phys::free_page 的 double-free panic（响亮失败，而非静默泄漏）。
pub unsafe fn destroy_user_address_space(space: &AddressSpace) {
    let l0 = space.root_table;
    if l0.is_null() {
        return;
    }
    crate::info!(
        "paging: destroy_user_address_space root_phys=0x{:016x} (table_pages before: {})",
        space.root_phys,
        phys::page_table_pages()
    );

    let e0 = (*l0).0[0];
    if !is_valid(e0) || !is_table(e0) {
        // 防御：根表损坏时至少释放根表本身
        phys::free_page_table(l0 as usize);
        return;
    }
    let l1 = descriptor_to_table(e0) as *mut PageTable;

    for l1_idx in 0..512 {
        if is_kernel_shared_l1(l1_idx) {
            continue; // ⛔ shared kernel table, never own/free
        }
        let e1 = (*l1).0[l1_idx];
        if !is_valid(e1) || !is_table(e1) {
            continue;
        }
        let l2 = descriptor_to_table(e1) as *mut PageTable;
        for l2_idx in 0..512 {
            let e2 = (*l2).0[l2_idx];
            if !is_valid(e2) {
                continue;
            }
            if is_table(e2) {
                let l3 = descriptor_to_table(e2) as *mut PageTable;
                for l3_idx in 0..512 {
                    let pte = (*l3).0[l3_idx];
                    if is_valid(pte) && pte & (DESC_SW_DEVICE | DESC_SW_BORROWED) == 0 {
                        // 用户数据/栈/bootfs 页：归还物理分配器。Device leaf
                        // 与 block-split borrowed filler 均非 allocator-owned。
                        let pa = (pte & PHYS_ADDR_MASK) as usize;
                        phys::free_page(pa);
                    }
                }
                phys::free_page_table(l3 as usize); // L3 表页
            }
            // block：继承内核恒等映射快照 / MMIO → 不释放物理内存
        }
        phys::free_page_table(l2 as usize); // 私有 L2（含 L1[0] 的 L2_0 副本）
    }
    phys::free_page_table(l1 as usize);
    phys::free_page_table(l0 as usize);

    crate::info!(
        "paging: destroy_user_address_space complete (table_pages after: {})",
        phys::page_table_pages()
    );
}

pub(crate) fn kernel_l0_phys() -> u64 {
    &raw const crate::mm::kernel_l0::__zero_kernel_l0 as *const PageTable as usize as u64
}

pub unsafe fn map_user_phys_page(
    space: &mut AddressSpace,
    virt: usize,
    phys: usize,
    writable: bool,
    executable: bool,
) -> Result<(), MapError> {
    let ap = if writable { USER_AP_RW } else { USER_AP_RX };
    map_physical_page(space, virt, phys, ap, executable)
}

/// Map one MMIO page into EL0 as Device-nGnRE, RW, non-executable. The
/// DESC_SW_DEVICE marker records that the output PA is not allocator-owned RAM.
pub unsafe fn map_user_device_page(
    space: &mut AddressSpace,
    virt: usize,
    phys: usize,
) -> Result<(), MapError> {
    if virt & (PAGE_SIZE - 1) != 0 || phys & (PAGE_SIZE - 1) != 0 {
        return Err(MapError::AlreadyMapped);
    }
    let desc = (phys as u64 & PHYS_ADDR_MASK)
        | DESC_VALID
        | DESC_TYPE_TABLE
        | DESC_AF
        | DESC_SH_INNER
        | DESC_ATTRIDX_DEVICE_NGNRE
        | (USER_AP_RW << 6)
        | DESC_UXN
        | DESC_PXN
        | DESC_SW_DEVICE;
    install_leaf_descriptor(space, virt, desc)
}

/// 软件走表诊断/单测：返回 VA 在地址空间 `space` 中的解析结果（只读）。
pub fn walk_space(space: &AddressSpace, va: usize) -> table_walk::WalkOutcome {
    unsafe { walk(space.root_table as *mut u64, va) }
}

// ── COW clone 统计（最近一次 clone 的快照，fork 日志与验收脚本消费）──
static CLONE_COW_SHARED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static CLONE_RO_SHARED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static CLONE_COPIED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 最近一次 clone 的页级统计：(COW 共享, 只读直接共享, 实际复制)。
/// copied==0 即零复制 fork 生效的直接证据。
pub fn last_clone_stats() -> (usize, usize, usize) {
    use core::sync::atomic::Ordering::Relaxed;
    (
        CLONE_COW_SHARED.load(Relaxed),
        CLONE_RO_SHARED.load(Relaxed),
        CLONE_COPIED.load(Relaxed),
    )
}

/// COW 克隆地址空间（第十刀，fork 用）。零数据复制：
///
/// 1. 新建 child（create_user_address_space：私有 L0/L1/L2_0 + 共享 L1[1]）；
/// 2. 遍历 parent 除 KERNEL_SHARED_L1 外全部有效叶子 PTE，按
///    table_walk::classify_leaf 分派：
///    - CowShare（可写页 AP=RW，或已带 COW 位——fork 链二次 fork）：父子
///      共享同一物理页。phys::retain_page 记账后，子 PTE = 同 PA + AP 只读
///      + DESC_SW_COW；父 PTE 同步 BBM 改只读 + 置位（父此刻正运行，
///      陈旧 RW TLB 表项会让共享写静默穿透，必须逐 VA tlbi）。
///    - ReadOnlyDirect（text/rodata）：直接映射同一 PA 不复制、不打 COW 位
///      （写 text 必须 SIGSEGV，W^X 底线），retain_page 保命防一方退出误回收。
///    - EagerCopy（防御兜底，正常不出现）：保留旧全量 memcpy 路径。
/// 3. skip block 条目（内核恒等快照/MMIO，child 的 L2_0 副本已有同物）。
///
/// 断链在 trap 路径的 handle_cow_fault：任一方首写触发 Permission fault
/// 时按 refcount 复制或原地恢复可写。
///
/// ⚠ 绝不复制 L1[KERNEL_SHARED_L1]（共享表），绝不共享表描述符本体——
///   子的页表页全部新建，只有**数据叶**被共享。
///
/// 失败原子性：中途 OOM/建表失败会销毁半成品 child，并对“已 retain 但
/// 尚未安装 PTE”的当前页显式撤销引用；已安装页由 destroy 统一回滚。父侧
/// 已经改成 COW 的叶可以暂留只读标记，refcount 回到 1 后首写原地恢复。
///
/// # Safety
/// `parent` 必须处于稳定状态（无并发修改）；parent 当前已装入 TTBR 且
/// 可能在 eret 后立即执行（BBM 屏障不可省略）。
pub unsafe fn clone_user_address_space(parent: &AddressSpace) -> Result<AddressSpace, MapError> {
    use core::sync::atomic::Ordering::Relaxed;
    crate::info!(
        "paging: cow clone_user_address_space parent root_phys=0x{:016x}",
        parent.root_phys
    );
    let mut child = create_user_address_space_fallible()?;
    let pl0 = parent.root_table;
    let e0 = (*pl0).0[0];
    if !is_valid(e0) || !is_table(e0) {
        destroy_user_address_space(&child);
        return Err(MapError::OutOfMemory);
    }
    let pl1 = descriptor_to_table(e0) as *mut PageTable;

    let mut cow_shared = 0usize;
    let mut ro_shared = 0usize;
    let mut copied = 0usize;

    for l1_idx in 0..512 {
        if is_kernel_shared_l1(l1_idx) {
            continue; // ⛔ shared kernel tables are never cloned
        }
        let e1 = (*pl1).0[l1_idx];
        if !is_valid(e1) || !is_table(e1) {
            continue;
        }
        let pl2 = descriptor_to_table(e1) as *mut PageTable;
        for l2_idx in 0..512 {
            let e2 = (*pl2).0[l2_idx];
            if !is_valid(e2) {
                continue;
            }
            if !is_table(e2) {
                continue; // block：child 的 L2 副本已有同物
            }
            let pl3 = descriptor_to_table(e2) as *mut PageTable;
            for l3_idx in 0..512 {
                let pte = (*pl3).0[l3_idx];
                if !is_valid(pte) {
                    continue;
                }
                // 拒绝内核共享区（防御：parent 里本就不该有）
                if is_kernel_shared_l1(l1_idx) {
                    destroy_user_address_space(&child);
                    return Err(MapError::KernelRegion);
                }
                let src = (pte & PHYS_ADDR_MASK) as usize;
                let va = (l1_idx << 30) | (l2_idx << 21) | (l3_idx << 12);
                let executable = pte & DESC_UXN == 0;
                match classify_leaf(pte) {
                    LeafShareClass::BorrowedDirect => {
                        // Kernel/device-owned filler from a split identity block:
                        // clone descriptor verbatim, never retain/refcount it.
                        if let Err(err) = install_leaf_descriptor(&mut child, va, pte) {
                            destroy_user_address_space(&child);
                            return Err(err);
                        }
                    }
                    LeafShareClass::CowShare => {
                        // 父子共享同一物理页；双侧只读 + 软件 COW 位。
                        phys::retain_page(src);
                        let child_desc = cow_share_leaf(pte);
                        if let Err(err) = install_leaf_descriptor(&mut child, va, child_desc) {
                            // 当前 retain 尚未出现在 child PTE 中，先单独撤销；
                            // 之前已经安装的共享页由 destroy 逐叶归还。
                            phys::free_page(src);
                            destroy_user_address_space(&child);
                            return Err(err);
                        }
                        // 父侧 BBM 改只读 + 置位（保留 PA/attr/UXN，仅换 AP）。
                        // 父正在运行：陈旧 RW TLB 必须逐 VA 击落，否则共享写
                        // 会静默穿透 COW 防线（bbm_update_page 内含屏障序）。
                        let mut b = |v: usize| kbbm_barrier(v);
                        table_walk::bbm_update_page(
                            pl3 as *mut u64,
                            l3_idx,
                            va,
                            cow_share_leaf(pte),
                            &mut b,
                        );
                        cow_shared += 1;
                    }
                    LeafShareClass::ReadOnlyDirect => {
                        // text/rodata：同 PA 直接映射（省复制），不打 COW 位。
                        phys::retain_page(src);
                        if let Err(err) = install_leaf_descriptor(
                            &mut child,
                            va,
                            make_leaf_descriptor(src as u64, USER_AP_RX, executable),
                        ) {
                            phys::free_page(src);
                            destroy_user_address_space(&child);
                            return Err(err);
                        }
                        ro_shared += 1;
                    }
                    LeafShareClass::SkipDevice => {
                        // Capability leases are process-local; fork never inherits
                        // a raw hardware mapping. Child can request its own lease.
                    }
                    LeafShareClass::EagerCopy => {
                        // 兜底（异常 AP 编码）：维持旧全量复制语义。
                        let dst = match alloc_user_page() {
                            Ok(page) => page,
                            Err(err) => {
                                destroy_user_address_space(&child);
                                return Err(err);
                            }
                        };
                        ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, PAGE_SIZE);
                        let ap = (pte >> table_walk::AP_SHIFT) & 0b11;
                        if let Err(err) = install_leaf_descriptor(
                            &mut child,
                            va,
                            make_leaf_descriptor(dst as u64, ap, executable),
                        ) {
                            phys::free_page(dst);
                            destroy_user_address_space(&child);
                            return Err(err);
                        }
                        copied += 1;
                    }
                }
                // ⚠ 第十一刀锁域审计结论（并集保留）：本循环**不得**放行
                // 中断——fork 的 syscall 路径依赖「内核全程屏蔽 IRQ ⇒
                // syscall 原子」这一根基不变量；中途让出会被 tick 打断并
                // 触发调度重入（实机抓获：子进程以未初始化现场启动）。
                // 分块让出基础设施保留（SCHED_STARTED 安全闸 +
                // chunk_yield_point），待未来引入内核抢占框架后重启。
            }
        }
    }
    CLONE_COW_SHARED.store(cow_shared, Relaxed);
    CLONE_RO_SHARED.store(ro_shared, Relaxed);
    CLONE_COPIED.store(copied, Relaxed);
    crate::info!(
        "paging: cow clone done child root_phys=0x{:016x} shared={} readonly_shared={} copied={}",
        child.root_phys,
        cow_shared,
        ro_shared,
        copied
    );
    Ok(child)
}

// ═══ 号位 24 Brk：用户堆收缩的解除映射助手（第十刀新增，仅此一节）═══

/// 解除 `[start, end)` 内全部有效叶子页映射（纯表遍历核心）。
/// 物理页归还经 `on_free` 回调、BBM 屏障经 `barrier` 回调注入——host 单测
/// 传 no-op/记录闭包即可覆盖遍历/跳过/计数逻辑（⚠ host 也是 aarch64，
/// 真实 tlbi 指令在 EL0 属非法异常，故屏障必须可注入，与
/// table_walk::Barrier / map_kernel_page 的既有模式同源），生产路径由
/// [`unmap_user_range`] 绑定真实屏障与物理分配器。返回回收的物理页数。
///
/// - 只清 L3 有效**页**描述符（bits[1:0]=0b11）；L2 block（继承自内核
///   恒等映射快照 / MMIO 的 2MiB 窗口）与任一级断链一律跳过——brk 增长
///   从未分配过它们（map_physical_page 走 ensure_*_table 全部建 L3）；
/// - ⛔ 防御：`KERNEL_SHARED_L1` 槽位（[1GiB,2GiB) 内核共享表本体）
///   无条件跳过，与 destroy/clone 同一条铁律；
/// - **BBM 次序**：写无效（break）→ `kbbm_barrier`（dsb ishst /
///   tlbi vaae1is / dsb ish / isb，host 下 no-op）→ 屏障完成后才回调
///   `on_free` 归还物理页。次序保证不存在“陈旧 TLB 条目仍可写已达
///   分配器自由表的物理页”的窗口（否则后续 alloc 复用该页会被旧翻译
///   静默改写——内存撕裂级事故）；
/// - 清空后的 L3/L2 表页**不**就地回收：destroy_user_address_space 对
///   整树兜底，而堆上限 64MiB ⇒ 残留空表至多 ~33 页，换取实现简单与
///   无父槽回写竞态。
///
/// # Safety
/// `root` 必须是有效地址空间的根表，且调用点保证无并发修改者
/// （单核 + svc 上下文满足；与 map_physical_page 同一信任级别）。
unsafe fn clear_user_leaf_range(
    root: *mut PageTable,
    start: usize,
    end: usize,
    barrier: &mut dyn FnMut(usize),
    mut on_free: impl FnMut(usize),
) -> usize {
    assert!(
        start <= end && start & (PAGE_SIZE - 1) == 0 && end & (PAGE_SIZE - 1) == 0,
        "clear_user_leaf_range: range must be page-aligned (start={:#x} end={:#x})",
        start,
        end
    );
    let mut freed = 0usize;
    let mut va = start;
    while va < end {
        let [i0, i1, i2, i3] = page_table_indices(va);
        if !is_kernel_shared_l1(i1) {
            let e0 = (*root).0[i0];
            if is_valid(e0) && is_table(e0) {
                let l1 = descriptor_to_table(e0) as *mut PageTable;
                let e1 = (*l1).0[i1];
                if is_valid(e1) && is_table(e1) {
                    let l2 = descriptor_to_table(e1) as *mut PageTable;
                    let e2 = (*l2).0[i2];
                    if is_valid(e2) && is_table(e2) {
                        let l3 = descriptor_to_table(e2) as *mut PageTable;
                        let pte = (*l3).0[i3];
                        if is_valid(pte) && pte & DESC_TYPE_TABLE != 0 {
                            // break：先清叶子描述符，再走完整屏障序列。
                            (*l3).0[i3] = 0;
                            barrier(va);
                            // 屏障完成后才归还物理页（理由见函数头注释）。
                            on_free((pte & PHYS_ADDR_MASK) as usize);
                            freed += 1;
                        }
                    }
                    // e2 为 block：继承的恒等/MMIO 窗口，页属内核或设备，
                    // 私有 L2 副本只是“引用”——绝不 free、绝不清除。
                }
            }
        }
        va += PAGE_SIZE;
    }
    freed
}

/// 解除用户地址空间 `[start, end)` 的 4KiB 页映射并归还物理页
/// （号位 24 Brk 收缩路径的内核入口；start/end 必须页对齐）。
/// 返回回收的物理页数；遍历/BBM/防御语义见 [`clear_user_leaf_range`]。
pub unsafe fn unmap_user_range(space: &AddressSpace, start: usize, end: usize) -> usize {
    // 生产绑定：真实 BBM 屏障（dsb ishst / tlbi vaae1is / dsb ish / isb）。
    let mut b = |va: usize| kbbm_barrier(va);
    unsafe {
        clear_user_leaf_range(space.root_table, start, end, &mut b, |pa| {
            phys::free_page(pa)
        })
    }
}

#[cfg(test)]
mod unmap_tests {
    use super::*;

    #[test]
    fn tlbi_operand_is_page_number() {
        assert_eq!(tlbi_va_operand(0x1234_5000), 0x12345);
        assert_eq!(tlbi_va_operand(0xffff_f000), 0xfffff);
    }
    use crate::mm::table_walk::WalkOutcome;

    /// 4K 对齐伪页表（地址即“物理地址”，与 table_walk 单测同一手法）。
    #[repr(C, align(4096))]
    struct FakeTables {
        l0: [u64; 512],
        l1: [u64; 512],
        l2: [u64; 512],
        l3_a: [u64; 512],
        l3_b: [u64; 512],
        l3_shared: [u64; 512],
        l2_shared: [u64; 512],
    }

    impl FakeTables {
        fn new() -> Self {
            Self {
                l0: [0; 512],
                l1: [0; 512],
                l2: [0; 512],
                l3_a: [0; 512],
                l3_b: [0; 512],
                l3_shared: [0; 512],
                l2_shared: [0; 512],
            }
        }

        /// L0[0]→L1；L1[0]→L2（用户私有区）；L1[1]→L2_shared（模拟内核
        /// 共享表 KERNEL_SHARED_L1=1，[1GiB,2GiB)）。
        fn link_default(&mut self) {
            self.l0[0] = make_table_descriptor(self.l1.as_ptr() as u64);
            self.l1[0] = make_table_descriptor(self.l2.as_ptr() as u64);
            self.l1[KERNEL_SHARED_L1] = make_table_descriptor(self.l2_shared.as_ptr() as u64);
        }

        fn space(&self) -> AddressSpace {
            AddressSpace {
                root_table: self.l0.as_ptr() as *mut PageTable,
                root_phys: 0,
            }
        }

        fn root(&self) -> *mut u64 {
            self.l0.as_ptr() as *mut u64
        }
    }

    #[test]
    fn unmap_clears_leaps_blocks_and_kernel_shared() {
        let mut t = FakeTables::new();
        t.link_default();
        // 窗口 A：VA 0x1000_0000（L2[128]）挂 L3_a，两页有效 + 一槽空洞。
        t.l2[128] = make_table_descriptor(t.l3_a.as_ptr() as u64);
        t.l3_a[0] = make_leaf_descriptor(0x9000_0000, USER_AP_RW, false);
        t.l3_a[1] = make_leaf_descriptor(0x9000_1000, USER_AP_RW, false);
        // t.l3_a[2] 保持 0（未映射槽位，unmap 必须幂等跳过）。
        // 窗口 B：VA 0x1020_0000（L2[129]）是继承来的 2MiB block 快照。
        t.l2[129] = (0x1020_0000u64) | DESC_VALID | DESC_AF;
        // 内核共享区：VA 0x4000_0000（L1[1]）挂一页，unmap 绝不许碰。
        t.l2_shared[0] = make_table_descriptor(t.l3_shared.as_ptr() as u64);
        t.l3_shared[0] = make_leaf_descriptor(0xDEAD_B000, AP_EL1_RW_EL0_NONE, false);

        let space = t.space();
        let mut freed = [0usize; 8];
        let mut freed_n = 0usize;
        let mut barrier_count = 0usize;
        let mut barrier = |_: usize| barrier_count += 1; // host：no-op + 计数
        let n = unsafe {
            clear_user_leaf_range(
                space.root_table,
                0x1000_0000,
                0x1040_0000,
                &mut barrier,
                |pa| {
                    freed[freed_n] = pa;
                    freed_n += 1;
                },
            )
        };
        assert_eq!(barrier_count, 2, "每张被清的页必须各走一次 BBM 屏障");
        // 仅两张有效用户页被回收；空洞/block/共享区一个都不能多。
        assert_eq!(n, 2);
        assert_eq!(&freed[..freed_n], &[0x9000_0000, 0x9000_1000]);
        // 已清页走表必须 Unmapped（含原本就空的槽位）。
        for va in [0x1000_0000, 0x1000_1000, 0x1000_2000] {
            assert_eq!(unsafe { walk(t.root(), va) }, WalkOutcome::Unmapped);
        }
        // block 窗口原样保留（内核恒等快照不受 brk 收缩影响）。
        assert!(matches!(
            unsafe { walk(t.root(), 0x1020_1234) },
            WalkOutcome::Block { .. }
        ));
        // 内核共享表内容分毫未动（⛔ 铁律回归）。
        assert_eq!(
            unsafe { walk(t.root(), 0x4000_0000) },
            WalkOutcome::Page {
                desc: t.l3_shared[0],
                phys: 0xDEAD_B000,
            }
        );
    }

    #[test]
    fn unmap_is_idempotent_and_counts_zero_on_empty_range() {
        let mut t = FakeTables::new();
        t.link_default();
        let space = t.space();
        let mut barrier = |_: usize| {};
        let n = unsafe {
            clear_user_leaf_range(
                space.root_table,
                0x1000_0000,
                0x1000_3000,
                &mut barrier,
                |_| {},
            )
        };
        assert_eq!(n, 0, "全空范围必须零回收");
    }

    // 注：不写 #[should_panic] 对齐断言测试——workspace dev profile 为
    // panic=abort，should_panic 会以 SIGILL 击沉整个测试进程。对齐契约
    // 由 clear_user_leaf_range 入口 assert! 兜底（内核编程错误响亮失败）。
}

/// Remove user device mappings without returning their physical output addresses
/// to the RAM allocator. Used when the last MMIO lease reference is released.
pub unsafe fn unmap_user_device_range(space: &AddressSpace, start: usize, end: usize) -> usize {
    let mut b = |va: usize| kbbm_barrier(va);
    clear_user_leaf_range(space.root_table, start, end, &mut b, |_| {})
}

/// COW 缺页断链（trap.rs Permission fault 路径调用）。
///
/// 前置：far 处 PTE 带 DESC_SW_COW（clone 时双侧标记）。语义：
/// - refcount > 1（真共享）：分配新页、整页 memcpy、重映射为原 AP 可写
///   （UXN 沿用）、老页引用减一归对端——BBM 更新 + TLBI 后 eret 重放即可；
/// - refcount == 1（对端已退出/已断链）：同一物理页原地恢复可写，零分配。
///
/// 返回 true 表示已断链（调用方应 restore_frame 重放指令）；
/// false 表示与本机制无关或资源不足（OOM），调用方按原路径处置
/// （SIGSEGV 终止——OOM 下宁可杀进程也不静默吞掉用户写）。
///
/// # Safety
/// space 必须是当前正在故障的地址空间（单核同步 fault，无并发修改）。
pub unsafe fn handle_cow_fault(space: &AddressSpace, va: usize) -> bool {
    let [l0_idx, l1_idx, l2_idx, l3_idx] = page_table_indices(va);
    if l0_idx != 0 || is_kernel_shared_l1(l1_idx) {
        return false; // 内核区永远没有 COW 页
    }
    // walk 已验证链路有效，这里可直达各级表指针。
    let e0 = (*space.root_table).0[l0_idx];
    if !is_valid(e0) || !is_table(e0) {
        return false;
    }
    let l1 = descriptor_to_table(e0) as *mut PageTable;
    let e1 = (*l1).0[l1_idx];
    if !is_valid(e1) || !is_table(e1) {
        return false;
    }
    let l2 = descriptor_to_table(e1) as *mut PageTable;
    let e2 = (*l2).0[l2_idx];
    if !is_valid(e2) || !is_table(e2) {
        return false;
    }
    let l3 = descriptor_to_table(e2) as *mut PageTable;
    let pte = (*l3).0[l3_idx];
    if !is_valid(pte) || !is_cow_leaf(pte) {
        return false; // 非 COW 页：交还原故障路径（真 SIGSEGV）
    }

    let old_pa = (pte & PHYS_ADDR_MASK) as usize;
    let rc = phys::ref_count(old_pa);
    let new_pa = if rc > 1 {
        // 真共享：复制私有副本，老页减一留给对端。
        match alloc_user_page() {
            Ok(dst) => {
                ptr::copy_nonoverlapping(old_pa as *const u8, dst as *mut u8, PAGE_SIZE);
                phys::free_page(old_pa);
                dst
            }
            Err(_) => {
                crate::warn!("paging: cow fault OOM va=0x{:x} pa=0x{:x}", va, old_pa);
                return false;
            }
        }
    } else {
        // 最后一个持有者：无需复制，原地恢复可写。
        old_pa
    };
    let new_desc = cow_break_leaf(pte, new_pa as u64);
    let mut b = |v: usize| kbbm_barrier(v);
    table_walk::bbm_update_page(l3 as *mut u64, l3_idx, va, new_desc, &mut b);
    crate::debug!(
        "paging: cow break va=0x{:x} pa=0x{:x}->0x{:x} rc={}",
        va,
        old_pa,
        new_pa,
        rc
    );
    true
}
