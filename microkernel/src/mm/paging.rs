use core::ptr;

use super::phys;
use super::table_walk::{
    self, descriptor_to_table, is_table, is_valid, make_leaf_descriptor,
    make_table_descriptor, page_table_indices, walk, AP_EL1_RW_EL0_NONE, DESC_AF,
    DESC_ATTRIDX_NORMAL, DESC_SH_INNER, DESC_TYPE_TABLE, DESC_UXN, DESC_VALID,
    KERNEL_SHARED_L1 as TW_KERNEL_SHARED_L1, PHYS_ADDR_MASK, USER_AP_RW, USER_AP_RX,
};

// 本文件所用常量与 table_walk.rs 保持一致（语义相同，直接复用）。
pub use super::table_walk::PAGE_SIZE;
pub const USER_BASE_TEXT: usize = 0x0040_0000;
pub const USER_BASE_DATA: usize = 0x0060_0000;
pub const USER_STACK_TOP: usize = 0x0000_FFFF_F000;
pub const USER_STACK_LEN: usize = 0x0000_0000_0002_0000; // 128 KiB user stack
static mut ID_MAP_BASE: u64 = 0;
static mut ID_MAP_SIZE: u64 = 0;

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
    let l2_0 = (&raw const crate::mm::kernel_l2::__zero_kernel_l2_0 as *const PageTable)
        as *mut PageTable;
    let l2_1 = (&raw const crate::mm::kernel_l2::__zero_kernel_l2_1 as *const PageTable)
        as *mut PageTable;
    (*l2_0).0.fill(0);
    (*l2_1).0.fill(0);

    // L1[0] 和 L1[1] 指向两个 L2 表。
    (*l1).0[0] = make_table_descriptor(l2_0 as usize as u64);
    (*l1).0[1] = make_table_descriptor(l2_1 as usize as u64);

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
        // MMIO 窗口内的块用 Device-nGnRE（AttrIdx 1），其余 Normal。
        let attridx = if pa >= DEVICE_LO && pa < DEVICE_HI {
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
fn kbbm_barrier(va: usize) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vaae1is, {0}",
            "dsb ish",
            "isb",
            in(reg) va as u64,
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

fn alloc_page_table() -> *mut PageTable {
    match alloc_page_table_raw() {
        Some(t) => t,
        None => {
            crate::info!(
                "paging: OOM in alloc_page_table (free_pages={} page_table_pages={})",
                crate::mm::phys::free_pages(),
                crate::mm::phys::page_table_pages()
            );
            panic!("paging: out of physical memory for page tables")
        }
    }
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

#[allow(static_mut_refs)]
pub unsafe fn create_user_address_space() -> AddressSpace {
    let l0 = alloc_page_table();
    let l1 = alloc_page_table();
    install_table_descriptor(l0, 0, l1);

    // L1[1]：复制内核 L1 的**表描述符**，与内核共享 L2_1 表本体。
    (*l1).0[KERNEL_SHARED_L1] = (*kernel_l1()).0[KERNEL_SHARED_L1];

    // L1[0]：**私有 L2 副本**（4KiB memcpy）。既保留 GIC/PL011 等 MMIO
    // block 对 EL1 的可见性，又允许把用户 ELF 所在的 2MiB block 在私有
    // 副本里拆成 4K 页而不污染内核自己的 L2_0。
    let l2_0 = alloc_page_table();
    ptr::copy_nonoverlapping(kernel_l2_0() as *const u64, l2_0 as *mut u64, 512);
    install_table_descriptor(l1, 0, l2_0);

    AddressSpace {
        root_table: l0,
        root_phys: page_table_phys(l0),
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
unsafe fn ensure_user_leaf_table(l2: *mut PageTable, index: usize) -> Result<*mut PageTable, MapError> {
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
    assert_eq!(
        virt & (PAGE_SIZE - 1),
        0,
        "virtual address must be page aligned"
    );
    let [l0_idx, l1_idx, l2_idx, l3_idx] = page_table_indices(virt);
    // ⛔ 安全闩：L1[KERNEL_SHARED_L1] 是内核 L2_1 表本体，用户映射一旦写
    // 进去会全局摧毁内核恒等映射（代码/堆/向量表/内核栈）。任何 VA 落在
    // [1GiB,2GiB) 的映射都直接拒绝。
    if l0_idx == 0 && l1_idx == KERNEL_SHARED_L1 {
        return Err(MapError::KernelRegion);
    }
    let l0 = space.root_table;
    let l1 = ensure_child_table(l0, l0_idx)?;
    let l2 = ensure_child_table(l1, l1_idx)?;
    // 拆 block 必须按需进行（用户 ELF 链接基址可能变化），且只能作用于
    // 进程私有表——共享的 L2_1 已在入口被拒，到不了这一步。
    let l3 = ensure_user_leaf_table(l2, l2_idx)?;
    let table = &mut *l3;
    if table.0[l3_idx] & DESC_VALID != 0 {
        return Err(MapError::AlreadyMapped);
    }
    table.0[l3_idx] = make_page_descriptor(phys as u64, ap, executable);
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
        if l1_idx == KERNEL_SHARED_L1 {
            continue; // ⛔ 内核 L2_1 表本体，绝不动
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
                    if is_valid(pte) {
                        // 用户数据/栈/bootfs 页：归还物理分配器
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

fn kernel_l0_phys() -> u64 {
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

/// 软件走表诊断/单测：返回 VA 在地址空间 `space` 中的解析结果（只读）。
pub fn walk_space(space: &AddressSpace, va: usize) -> table_walk::WalkOutcome {
    unsafe { walk(space.root_table as *mut u64, va) }
}

/// eager-copy 克隆地址空间（fork 用）。
///
/// 算法（与设计方案一致）：
/// 1. 新建 child（复用 create_user_address_space：私有 L0/L1/L2_0 副本 + 共享 L1[1]）；
/// 2. 遍历 parent 除 KERNEL_SHARED_L1 外全部 L1 槽位；
/// 3. 对 parent 每个用户私有 L2 表：表条目逐页复制（新分配物理页 + memcpy，
///    恒等映射下直接按 PA 拷贝）；
/// 4. skip 一切 block 条目（只可能是继承来的内核恒等映射，
///    child 的 L2_0 副本里已有同物）；
/// 5. skip 未映射/无效条目；child 侧映射经 map_physical_page 统一建表
///    （自动处理 block 拆表与内核区护栏）。
///
/// ⚠ 绝不复制 L1[KERNEL_SHARED_L1]（共享表），绝不复制表描述符本体——
///   只复制叶子页的内容。COW 留待后续：帧上标注 refcount + 写时复制，
///   可复用的物理页对保留在 parent，child 首写时才分配。
///
/// 失败（OOM/非法条目）返回 Err；调用方负责丢弃半成品 child（此时
/// child 的页已由 map_physical_page 记账，不会泄漏到 allocator 之外）。
///
/// # Safety
/// `parent` 必须处于稳定状态（无并发修改）。
pub unsafe fn clone_user_address_space(parent: &AddressSpace) -> Result<AddressSpace, MapError> {
    crate::info!(
        "paging: clone_user_address_space parent root_phys=0x{:016x}",
        parent.root_phys
    );
    let mut child = create_user_address_space();
    let pl0 = parent.root_table;
    let e0 = (*pl0).0[0];
    if !is_valid(e0) || !is_table(e0) {
        return Err(MapError::OutOfMemory);
    }
    let pl1 = descriptor_to_table(e0) as *mut PageTable;

    for l1_idx in 0..512 {
        if l1_idx == KERNEL_SHARED_L1 {
            continue; // ⛔ 共享表绝不遍历
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
                let src = (pte & PHYS_ADDR_MASK) as usize;
                // 拒绝内核共享区（防御：parent 里本就不该有）
                if l1_idx == KERNEL_SHARED_L1 {
                    return Err(MapError::KernelRegion);
                }
                let va = (l1_idx << 30) | (l2_idx << 21) | (l3_idx << 12);
                let dst = alloc_user_page()?;
                ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, PAGE_SIZE);
                let ap = (pte >> 6) & 0b11;
                let executable = pte & DESC_UXN == 0;
                map_physical_page(&mut child, va, dst, ap, executable)?;
            }
        }
    }
    crate::info!(
        "paging: clone_user_address_space done child root_phys=0x{:016x}",
        child.root_phys
    );
    Ok(child)
}