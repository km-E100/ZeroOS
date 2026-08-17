use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use super::phys;

#[allow(dead_code)]
pub const PAGE_SIZE: usize = 4096;

const PHYS_ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
const DESC_TYPE_TABLE: u64 = 1 << 1;
const DESC_VALID: u64 = 1 << 0;
const DESC_AF: u64 = 1 << 10;
const DESC_SH_INNER: u64 = 3 << 8;
const DESC_ATTRIDX_NORMAL: u64 = 0 << 2;
const DESC_UXN: u64 = 1 << 54;
const DESC_PXN: u64 = 1 << 53;
const AP_SHIFT: u64 = 6;
const AP_EL1_RW_EL0_NONE: u64 = 0b00;
const USER_AP_RX: u64 = 0b11;
const USER_AP_RW: u64 = 0b10;

pub const USER_BASE_TEXT: usize = 0x0040_0000;
pub const USER_BASE_DATA: usize = 0x0060_0000;
pub const USER_STACK_TOP: usize = 0x0000_FFFF_F000;
pub const USER_STACK_LEN: usize = 0x0000_0000_0002_0000; // 128 KiB user stack
static mut ID_MAP_BASE: u64 = 0;
static mut ID_MAP_SIZE: u64 = 0;
/// Temporary kernel VA used to map arbitrary user-pages during ELF loading.
/// Must lie inside the kernel L0[0] region (< 512GiB) but ABOVE the identity
/// map's 2MiB blocks (>= 2GiB, L1 index >= 2), so that map_temp_page creates
/// fresh L2/L3 tables instead of clobbering an existing block descriptor.
///
/// 此前 TEMP_ELF_MAP_BASE = 0x3000_0000 落在恒等映射的 2MiB block 内：
/// ensure_child_table 把 block 描述符误当表描述符，L3 页表项被写到
/// 物理 0x3000_0000（QEMU virt 空洞，写入被静默丢弃），临时映射从未
/// 真正生效，用户进程代码页全是零。
const TEMP_ELF_MAP_BASE: usize = 0x0000_0000_9000_0000;

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

    // 页面属性：有效 block，Normal 内存，Inner-shareable，AF=1。
    // AP[2:1]=0b00 => EL1 可读写，EL0 无访问权限（内核恒等映射不对用户态开放）。
    //
    // 注意：此前的实现错误地在 BLOCK_FLAGS 里加了 DESC_PXN（bit 53），
    // 导致整个恒等映射对 EL1 也禁止取指：内核一旦真正走自己的页表取指
    // 就触发 permission fault（2025-11-15 死机日志的根因）。修复方式是
    // 去掉 PXN，并在切换页表后刷新 TLB（见 arch/aarch64.rs）。
    const PTE_VALID: u64 = 1 << 0;
    const PTE_BLOCK: u64 = 0 << 1;
    const PTE_AF: u64 = 1 << 10;
    const PTE_SH_INNER: u64 = 3 << 8;
    // AP[2:1]=0b00 => EL1 RW，EL0 无权限（ARMv8-A D5.3.3）。
    const PTE_AP_EL1_RW_EL0_NONE: u64 = 0 << 6;
    const PTE_ATTRIDX0: u64 = 0 << 2;
    const BLOCK_FLAGS: u64 =
        PTE_VALID | PTE_BLOCK | PTE_AF | PTE_SH_INNER | PTE_AP_EL1_RW_EL0_NONE | PTE_ATTRIDX0;

    // L0: 根表，所有 entry 先清零。
    let l0 =
        unsafe { (&crate::mm::kernel_l0::__zero_kernel_l0 as *const PageTable) as *mut PageTable };
    (*l0).0.fill(0);

    // L1: 作为指向 L2 的表。
    let l1 =
        unsafe { (&crate::mm::kernel_l1::__zero_kernel_l1 as *const PageTable) as *mut PageTable };
    (*l1).0.fill(0);

    let l1_phys = l1 as usize as u64;

    // L0[0]: table descriptor 指向 L1。
    // bits[47:12] = 下一级表物理基址，bit0=1(valid), bit1=1(table)。
    const TABLE_DESC_VALID: u64 = 1 << 0;
    const TABLE_DESC_TABLE: u64 = 1 << 1;
    let l0_entry = (l1_phys & 0x0000_ffff_ffff_f000) | TABLE_DESC_VALID | TABLE_DESC_TABLE;
    (*l0).0[0] = l0_entry;

    // L2: 两个表，每个覆盖 1GiB（512 * 2MiB），共 2GiB。
    let l2_0 = unsafe {
        (&crate::mm::kernel_l2::__zero_kernel_l2_0 as *const PageTable) as *mut PageTable
    };
    let l2_1 = unsafe {
        (&crate::mm::kernel_l2::__zero_kernel_l2_1 as *const PageTable) as *mut PageTable
    };
    (*l2_0).0.fill(0);
    (*l2_1).0.fill(0);

    let l2_phys_0 = l2_0 as usize as u64;
    let l2_phys_1 = l2_1 as usize as u64;

    // L1[0] 和 L1[1] 指向两个 L2 表。
    (*l1).0[0] = (l2_phys_0 & 0x0000_ffff_ffff_f000) | TABLE_DESC_VALID | TABLE_DESC_TABLE;
    (*l1).0[1] = (l2_phys_1 & 0x0000_ffff_ffff_f000) | TABLE_DESC_VALID | TABLE_DESC_TABLE;

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
        let entry = (pa & 0x0000_ffff_ffe0_0000) | BLOCK_FLAGS;
        if block == ((0x0100_0000 / BLOCK_SIZE_L2) as usize) {
            crate::info!(
                "paging: identity block for 0x0100_0000 -> table={} index={} entry=0x{:016x}",
                table_idx,
                entry_idx,
                entry
            );
        }
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
    //
    // 此前错误地指向 L1 表：在 TLB 未被刷新时固件残留映射掩盖了错误，
    // 一旦刷新 TLB（修复后），L1 表会被硬件当作 L0 表解读，
    // 内核取指立即翻译到错误的物理地址（实机验证：切表即崩）。
    let l0_virt = unsafe { &crate::mm::kernel_l0::__zero_kernel_l0 as *const PageTable as usize };
    let l0_phys = l0_virt as u64; // identity mapping
    crate::info!("paging: installing kernel L0 @phys=0x{:016x}", l0_phys);
    unsafe {
        crate::arch::install_kernel_page_table(l0_phys);
    }
}

pub fn map_kernel_page(_virt: usize, _phys: usize, _flags: u64) {
    // TODO: update L1/L2 entries, flush TLB
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
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

const TABLE_DESC_VALID: u64 = DESC_VALID;
const TABLE_DESC_TABLE: u64 = DESC_TYPE_TABLE;

fn page_table_phys(table: *mut PageTable) -> u64 {
    table as usize as u64
}

fn install_table_descriptor(parent: *mut PageTable, slot: usize, child: *mut PageTable) {
    assert!(slot < 512);
    let child_phys = page_table_phys(child) & PHYS_ADDR_MASK;
    let desc = child_phys | TABLE_DESC_VALID | TABLE_DESC_TABLE;
    unsafe {
        (*parent).0[slot] = desc;
    }
}

fn alloc_page_table_raw() -> Option<*mut PageTable> {
    phys::alloc_page().map(|phys| {
        unsafe {
            zero_physical_page(phys);
        }
        phys as *mut PageTable
    })
}

fn alloc_page_table() -> *mut PageTable {
    alloc_page_table_raw().expect("out of physical memory for page tables")
}

fn alloc_page_table_fallible() -> Result<*mut PageTable, MapError> {
    alloc_page_table_raw().ok_or(MapError::OutOfMemory)
}

static mut TEMP_L2: *mut PageTable = core::ptr::null_mut();
static mut TEMP_L3: *mut PageTable = core::ptr::null_mut();
static ZERO_TEMP_ACTIVE: AtomicBool = AtomicBool::new(false);

unsafe fn zero_physical_page(phys: usize) {
    if ZERO_TEMP_ACTIVE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        let tmp = map_temp_page(phys);
        ptr::write_bytes(tmp, 0, PAGE_SIZE);
        unmap_temp_page();
        ZERO_TEMP_ACTIVE.store(false, Ordering::Release);
    } else {
        // Re-entrant zeroing can occur while map_temp_page() is instantiating
        // its own page tables; fall back to the identity-mapped alias.
        ptr::write_bytes(phys as *mut u8, 0, PAGE_SIZE);
    }
}

/// Map a single physical page at a reserved kernel VA for temporary access.
pub unsafe fn map_temp_page(phys: usize) -> *mut u8 {
    let va = TEMP_ELF_MAP_BASE;
    let (l0_idx, l1_idx, l2_idx, l3_idx) = page_table_indices(va);

    if l0_idx != 0 {
        // Kernel L0 currently only wires index 0; using others would require more setup.
        panic!("temp map: L0 index {} unsupported", l0_idx);
    }
    let l1 = (&crate::mm::kernel_l1::__zero_kernel_l1 as *const PageTable) as *mut PageTable;

    let l2 = ensure_child_table(l1, l2_idx).expect("temp map: ensure L2");
    TEMP_L2 = l2;
    let l3 = ensure_child_table(l2, l3_idx).expect("temp map: ensure L3");
    TEMP_L3 = l3;

    let phys_masked = (phys as u64) & PHYS_ADDR_MASK;
    // Kernel RW, inner-shareable, AF=1, non-executable.
    let desc = phys_masked
        | DESC_VALID
        | (AP_EL1_RW_EL0_NONE << AP_SHIFT)
        | DESC_AF
        | DESC_SH_INNER
        | DESC_ATTRIDX_NORMAL
        | DESC_UXN
        | DESC_PXN;
    (*l3).0[l3_idx] = desc;
    asm!("dsb ish; isb", options(nostack));
    crate::info!("temp map: phys=0x{:016x} -> virt=0x{:016x}", phys, va);
    va as *mut u8
}

pub unsafe fn unmap_temp_page() {
    let va = TEMP_ELF_MAP_BASE;
    if TEMP_L3.is_null() {
        return;
    }
    let (_, _, _, l3_idx) = page_table_indices(va);
    (*TEMP_L3).0[l3_idx] = 0;
    asm!(
        "dsb ish",
        "tlbi vae1is, {addr}",
        "dsb ish",
        "isb",
        addr = in(reg) (va as u64 >> 12),
        options(nostack)
    );
}

#[allow(static_mut_refs)]
pub unsafe fn create_user_address_space() -> AddressSpace {
    let l0 = alloc_page_table();
    let l1 = alloc_page_table();
    let l2 = alloc_page_table();

    install_table_descriptor(l0, 0, l1);
    install_table_descriptor(l1, 0, l2);

    AddressSpace {
        root_table: l0,
        root_phys: page_table_phys(l0),
    }
}

fn page_table_indices(addr: usize) -> (usize, usize, usize, usize) {
    let l0 = (addr >> 39) & 0x1ff;
    let l1 = (addr >> 30) & 0x1ff;
    let l2 = (addr >> 21) & 0x1ff;
    let l3 = (addr >> 12) & 0x1ff;
    (l0, l1, l2, l3)
}

fn descriptor_to_table(desc: u64) -> *mut PageTable {
    (desc & PHYS_ADDR_MASK) as *mut PageTable
}

unsafe fn ensure_child_table(
    parent: *mut PageTable,
    index: usize,
) -> Result<*mut PageTable, MapError> {
    let entry = (*parent).0[index];
    if entry & TABLE_DESC_VALID != 0 {
        if entry & TABLE_DESC_TABLE == 0 {
            // 条目是 block 描述符（bit1=0），不能当作下级表使用。
            // 历史上 map_temp_page 因此把 L3 页表项写穿到 block 的物理地址
            // （0x3000_0000），临时映射从未生效。这里直接 panic 暴露错误。
            panic!(
                "ensure_child_table: block descriptor 0x{:016x} at table index {} cannot be used as a table",
                entry, index
            );
        }
        Ok(descriptor_to_table(entry))
    } else {
        let table = alloc_page_table_fallible()?;
        install_table_descriptor(parent, index, table);
        Ok(table)
    }
}

fn make_page_descriptor(phys: u64, ap: u64, executable: bool) -> u64 {
    // Final (L2/L3) descriptors mirror the AArch64 stage-1 layout: bits[1:0]=0b11 denote
    // a page, AttrIdx selects MAIR slot 0 (Normal memory), SH=Inner Shareable keeps
    // caches coherent, AF=1 marks the entry accessed, UXN governs user execute
    // permission, and AP bits encode the requested read/write policy. PXN stays clear
    // so EL1 can inspect user memory while still enforcing UXN for EL0.
    let mut desc = (phys & PHYS_ADDR_MASK)
        | DESC_VALID
        | DESC_TYPE_TABLE
        | DESC_AF
        | DESC_SH_INNER
        | DESC_ATTRIDX_NORMAL
        | (ap << AP_SHIFT);
    if !executable {
        desc |= DESC_UXN;
    }
    desc
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
    let (l0_idx, l1_idx, l2_idx, l3_idx) = page_table_indices(virt);
    let l0 = space.root_table;
    let l1 = ensure_child_table(l0, l0_idx)?;
    let l2 = ensure_child_table(l1, l1_idx)?;
    let l3 = ensure_child_table(l2, l2_idx)?;
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
        let kptr = map_temp_page(phys);
        ptr::write_bytes(kptr, 0, PAGE_SIZE);
        unmap_temp_page();
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
    map_zero_region(space, base, aligned_size, USER_AP_RW)
}

pub unsafe fn activate_user_address_space(addr_space: &AddressSpace) {
    crate::arch::set_user_ttbr(addr_space.root_phys);
}

pub unsafe fn deactivate_user_address_space() {
    crate::arch::set_user_ttbr(kernel_l0_phys());
}

#[allow(static_mut_refs)]
pub unsafe fn destroy_user_address_space(space: &AddressSpace) {
    let _ = space;
    // 目前没有为每个进程分配独立页表，无需回收。
}

fn kernel_l0_phys() -> u64 {
    unsafe { &crate::mm::kernel_l0::__zero_kernel_l0 as *const PageTable as usize as u64 }
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
