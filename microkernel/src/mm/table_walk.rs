//! AArch64 Stage-1 4 级页表的**纯算法核心**（仅用 core，可 host 单测）。
//!
//! - 描述符常量与构造（`make_table_descriptor` / `make_leaf_descriptor`）；
//! - 虚拟地址 → (L0,L1,L2,L3) 索引分解；
//! - 表遍历器 `walk`（对伪造表可软件走表验证）；
//! - break-before-make（BBM）序列：block → L3 表拆分与页级更新。
//!
//! BBM 的内存屏障/TLBI 通过 `Barrier` 回调注入：aarch64 内核侧提供真实
//! `dsb ish; tlbi vaae1is; dsb ish; isb` 序列，host 单测传 no-op 闭包。

pub const PAGE_SIZE: usize = 4096;

pub const PHYS_ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
pub const DESC_VALID: u64 = 1 << 0;
pub const DESC_TYPE_TABLE: u64 = 1 << 1;
pub const DESC_AF: u64 = 1 << 10;
pub const DESC_SH_INNER: u64 = 3 << 8;
pub const DESC_ATTRIDX_NORMAL: u64 = 0 << 2;
/// Device-nGnRE 属性（MAIR AttrIdx 1 = 0b0000_0100）。
/// MMIO 区间必须用 Device 内存：Normal-cacheable 下 volatile 绕不过
/// 硬件写合并/重排，真实设备会收到错序合并的寄存器访问。
pub const DESC_ATTRIDX_DEVICE_NGNRE: u64 = 1 << 2;
pub const DESC_UXN: u64 = 1 << 54;
pub const DESC_PXN: u64 = 1 << 53;
/// 软件 CoW 标记位（第十刀写时复制 fork）。
///
/// 选 bit11 的依据：stage-1 叶描述符里 bit11 硬件语义是 nG（非全局 TLB），
/// 而本内核每次地址空间切换（arch::set_user_ttbr）都 `tlbi vmalle1`
/// 全量刷新，TLB 条目从不跨切换存活 ⇒ nG 语义完全惰性，该位可安全
/// 挪作软件私有。任务书建议的 bit9 与 SH[9:8] 字段重叠（会降级
/// shareability），故弃用。
///
/// 纪律：仅叶子页描述符使用；clone 时父子双侧同时置位并把 AP 改只读，
/// COW 断链（handle_cow_fault）时清除并恢复原 AP。
pub const DESC_SW_COW: u64 = 1 << 11;
/// Software marker for user-visible device/MMIO leaves. Bit55 is software-use
/// in the stage-1 leaf format used by Zero OS. Device leaves are not allocator-
/// owned RAM: destroy/fork must never free or COW their output physical address.
pub const DESC_SW_DEVICE: u64 = 1 << 55;
/// Software ownership marker for leaves inherited from a kernel identity-map
/// block when BBM splits that block into a private user L3 table. These output
/// pages remain kernel/device-owned and must never be refcounted/freed as user
/// allocations. A process may replace individual borrowed slots with owned RAM,
/// SHM, or MMIO leaves; only the untouched filler leaves retain this bit.
pub const DESC_SW_BORROWED: u64 = 1 << 56;
pub const AP_SHIFT: u64 = 6;
/// AP[2:1] 字段掩码：改 AP 必须整字段清再置，禁止手写位移散落各处。
pub const AP_MASK: u64 = 0b11 << AP_SHIFT;
/// AP[2:1]=0b00：EL1 读写、EL0 无权限（内核恒等映射/内核页）。
pub const AP_EL1_RW_EL0_NONE: u64 = 0b00;
/// AP[2:1] stage-1 编码（ARM ARM DDI 0487）：
///   0b00 = EL1 RW / EL0 none    0b01 = EL1 RW / EL0 RW
///   0b10 = EL1 RO / EL0 none    0b11 = EL1 RO / EL0 RO
/// ⚠ 历史教训：USER_AP_RX 曾误用 0b10（"EL1 只读"想当然），实际语义是
/// **EL0 完全无访问** —— 用户代码/rodata 页全部对 EL0 关闭数据访问，
/// 内核代读（copy_from_user 跑在 EL1）掩盖了问题，直到 shell 第一次在
/// EL0 自行读取 rodata 比较命令才触发 permission fault（2026-08-22）。
/// 正确编码：用户只读段 = 0b11（EL0+EL1 均只读）。
pub const USER_AP_RX: u64 = 0b11;
/// EL0 读写（EL1 亦读写）。
pub const USER_AP_RW: u64 = 0b01;

/// 与内核共享的 L1 槽位：覆盖 [1GiB,2GiB)，指向内核 L2_1 表本体。
/// 遍历/克隆/回收必须无条件跳过（见 paging.rs 中 KERNEL_SHARED_L1 的注释）。
pub const KERNEL_SHARED_L1: usize = 1;

/// 虚拟地址 → (l0, l1, l2, l3) 索引。
pub fn page_table_indices(addr: usize) -> [usize; 4] {
    [
        (addr >> 39) & 0x1ff,
        (addr >> 30) & 0x1ff,
        (addr >> 21) & 0x1ff,
        (addr >> 12) & 0x1ff,
    ]
}

pub fn is_valid(desc: u64) -> bool {
    desc & DESC_VALID != 0
}

pub fn is_table(desc: u64) -> bool {
    desc & DESC_TYPE_TABLE != 0
}

/// 从描述符中取出下一级表的地址（恒等映射下 == 物理地址）。
pub fn descriptor_to_table(desc: u64) -> *mut u64 {
    ((desc & PHYS_ADDR_MASK) as usize) as *mut u64
}

/// 表描述符：指向下一级表。
pub fn make_table_descriptor(child_phys: u64) -> u64 {
    (child_phys & PHYS_ADDR_MASK) | DESC_VALID | DESC_TYPE_TABLE
}

/// 页/块描述符（叶子）。
pub fn make_leaf_descriptor(phys: u64, ap: u64, executable: bool) -> u64 {
    let mut desc = (phys & PHYS_ADDR_MASK)
        | DESC_VALID
        | DESC_TYPE_TABLE // bits[1:0]=0b11 → 页
        | DESC_AF
        | DESC_SH_INNER
        | DESC_ATTRIDX_NORMAL
        | (ap << AP_SHIFT);
    if !executable {
        desc |= DESC_UXN;
    }
    desc
}

/// 叶子共享分类：clone_user_address_space 对每个有效叶的处置策略（纯函数，
/// host 单测钉死判定矩阵；paging 侧按此分派）。
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LeafShareClass {
    /// Kernel/device-owned identity-map filler produced by a block split. Clone
    /// copies the descriptor verbatim without phys retain/COW; destroy skips it.
    BorrowedDirect,
    /// 真只读页（text/rodata，AP=0b11 且无 COW 位）：父子直接映射同一物理页，
    /// 不复制、不打 COW 标记（配 retain_page 保命，防一方退出误回收）。
    ReadOnlyDirect,
    /// 可写来源页（AP=USER_AP_RW，或已是 COW 共享页——二次 fork 场景）：
    /// 父子共享同一物理页，双侧 PTE 改只读 + DESC_SW_COW。
    CowShare,
    /// 其他 AP 编码（防御兜底，用户空间理论上不出现）：保持旧 eager 复制。
    EagerCopy,
    /// Device/MMIO mapping owned by a capability lease. A fork does not inherit
    /// hardware access: the child must independently hold CAP_MMIO and map it.
    SkipDevice,
}

/// 判定一个有效叶描述符的克隆策略。
/// COW 共享总开关。此前因 post-fork 异常现场损坏而临时回退 eager；
/// 异常入口现已完整保存 x16/x17，并重新以 host + QEMU 回归覆盖。
/// 保留常量便于未来故障二分，但正常构建默认启用零复制 fork。
pub const COW_SHARED_FORK: bool = true;
pub const COW_BISECT_SKIP_ASLR: bool = false;
pub const COW_BISECT_SKIP_PARENT_BBM: bool = false;

pub fn classify_leaf(leaf: u64) -> LeafShareClass {
    if leaf & DESC_SW_BORROWED != 0 {
        return LeafShareClass::BorrowedDirect;
    }
    if leaf & DESC_SW_DEVICE != 0 {
        return LeafShareClass::SkipDevice;
    }
    if !COW_SHARED_FORK {
        // 关闭共享：可写页一律 eager 复制兜底（语义正确，仅牺牲 fork
        // 性能）；真只读页保留直接映射——无写语义即无 COW 依赖，省内存
        // 且与历史只读共享行为一致。
        let ap = (leaf >> AP_SHIFT) & 0b11;
        if leaf & DESC_SW_COW == 0 && ap == USER_AP_RX {
            return LeafShareClass::ReadOnlyDirect;
        }
        return LeafShareClass::EagerCopy;
    }
    let ap = (leaf >> AP_SHIFT) & 0b11;
    if leaf & DESC_SW_COW != 0 {
        // 已是 COW 共享页（fork 链上二次 fork）：继续传播共享标记。
        return LeafShareClass::CowShare;
    }
    match ap {
        // 注意 USER_AP_RW=0b01 才是 EL0 可写；0b00 是 EL1-only（内核页），
        // 用户空间不该出现，出现则走兜底复制而非共享（防御）。
        a if a == USER_AP_RW => LeafShareClass::CowShare,
        a if a == USER_AP_RX => LeafShareClass::ReadOnlyDirect,
        _ => LeafShareClass::EagerCopy,
    }
}

/// 是否为带 CoW 标记的有效描述符（缺页路径的权威判定）。
/// 调用契约：入参必须是 L3 叶子 PTE（handle_cow_fault 只对 L3 槽位调用），
/// 因此这里只校验 VALID + 软件位，不再重复校验叶类型位。
pub fn is_cow_leaf(desc: u64) -> bool {
    desc & DESC_VALID != 0 && desc & DESC_SW_COW != 0
}

/// clone 共享化：把可写叶改成「同 PA、只读、COW 标记」。
/// 保留原 PA / attr / AF / SH / UXN，仅重写 AP 字段并置软件位。
pub fn cow_share_leaf(leaf: u64) -> u64 {
    (leaf & !AP_MASK) | (USER_AP_RX << AP_SHIFT) | DESC_SW_COW
}

/// COW 断链：把 COW 叶恢复为指向 `new_pa` 的原始可写叶（清软件位）。
/// UXN/attr 沿用旧描述符——断链只恢复写权限，不改执行权限。
pub fn cow_break_leaf(cow_leaf: u64, new_pa: u64) -> u64 {
    (cow_leaf & !(AP_MASK | DESC_SW_COW | PHYS_ADDR_MASK))
        | (new_pa & PHYS_ADDR_MASK)
        | (USER_AP_RW << AP_SHIFT)
}

#[derive(Debug, PartialEq, Eq)]
pub enum WalkOutcome {
    /// 未映射（某级入口无效）。
    Unmapped,
    /// 表遍历终止在块描述符（L2 block），返回块所在 2MiB 窗口基址。
    Block { desc: u64, block_base: usize },
    /// L3 页描述符。
    Page { desc: u64, phys: usize },
}

/// 软件走表：以 `l0` 为根解析 `va`。只读遍历，不修改任何表。
///
/// # Safety
/// `l0` 及其下游表必须有效；`va` 由调用方保证为合法虚拟地址。
pub unsafe fn walk(l0: *mut u64, va: usize) -> WalkOutcome {
    let [i0, i1, i2, i3] = page_table_indices(va);
    let e0 = *l0.add(i0);
    if !is_valid(e0) {
        return WalkOutcome::Unmapped;
    }
    let l1 = descriptor_to_table(e0);
    let e1 = *l1.add(i1);
    if !is_valid(e1) {
        return WalkOutcome::Unmapped;
    }
    let l2 = descriptor_to_table(e1);
    let e2 = *l2.add(i2);
    if !is_valid(e2) {
        return WalkOutcome::Unmapped;
    }
    if !is_table(e2) {
        // L2 block：恒等映射下 phys == va 所在 2MiB 窗口
        return WalkOutcome::Block {
            desc: e2,
            block_base: (i0 << 39) | (i1 << 30) | (i2 << 21),
        };
    }
    let l3 = descriptor_to_table(e2);
    let e3 = *l3.add(i3);
    if !is_valid(e3) {
        return WalkOutcome::Unmapped;
    }
    WalkOutcome::Page {
        desc: e3,
        phys: (e3 & PHYS_ADDR_MASK) as usize,
    }
}

/// BBM 内存屏障/TLBI 回调：`va` 为被拆/被改的虚拟地址。
pub type Barrier = dyn FnMut(usize);

/// BBM 拆分：把 L2 的 2MiB block 拆成 L3 表（break-before-make）。
///
/// - `l2`: L2 表地址；`index`: 目标槽位；
/// - `l3`: 调用方**新分配并清零、页对齐**的 L3 表（恒等映射下地址即物理地址）；
/// - `virt_base`: 2MiB 窗口的虚拟基址（恒等映射下 == 物理基址）；
/// - `block_desc`: 旧 block 描述符（回填页沿用其属性，粒度改为 4K）；
/// - `target`: 目标 4K 页在 L3 中的槽位，其描述符为 `target_desc`；
/// - `barrier`: BBM 屏障序列。
///
/// 顺序严格遵循 ARMv8：break（写无效）→ 屏障（dsb ishst / tlbi / dsb / isb）
/// → 建立 L3 内容 → make（写表描述符）→ 屏障。其余 511 页回填恒等页，
/// 保持整窗对内核可见（拆分后内核侧不能丢该窗口的映射）。
///
/// # Safety
/// 表指针必须页对齐且有效；`l3` 必须尚未挂入任何表。
#[allow(clippy::too_many_arguments)]
pub unsafe fn bbm_split_block(
    l2: *mut u64,
    index: usize,
    l3: *mut u64,
    virt_base: usize,
    block_desc: u64,
    target: usize,
    target_desc: u64,
    barrier: &mut Barrier,
) {
    assert!(
        index < 512 && target < 512,
        "bbm_split_block: slot out of range"
    );
    let old = *l2.add(index);
    assert!(
        old & DESC_VALID != 0 && old & DESC_TYPE_TABLE == 0,
        "bbm_split_block: entry 0x{:016x} is not a valid block",
        old
    );
    // break：先写无效
    *l2.add(index) = 0;
    barrier(virt_base);
    // 回填：整窗恒等 4K 页（沿用旧 block 的 AP/Attr 属性）
    let leaf_flags = (block_desc & !0b11) | DESC_VALID | DESC_TYPE_TABLE | DESC_SW_BORROWED;
    for slot in 0..512 {
        let pa = (virt_base + slot * PAGE_SIZE) as u64;
        *l3.add(slot) = (pa & PHYS_ADDR_MASK) | leaf_flags;
    }
    // 目标页换成调用方要求的描述符
    *l3.add(target) = target_desc;
    // make：写表描述符
    *l2.add(index) = make_table_descriptor(l3 as u64);
    barrier(virt_base);
}

/// BBM 页级更新：把 L3 槽位 `index` 更新为 `new_desc`（break-before-make）。
///
/// # Safety
/// `l3` 必须有效且处于活跃映射中。
pub unsafe fn bbm_update_page(
    l3: *mut u64,
    index: usize,
    va: usize,
    new_desc: u64,
    barrier: &mut Barrier,
) {
    assert!(index < 512, "bbm_update_page: slot out of range");
    assert!(
        *l3.add(index) & DESC_VALID != 0,
        "bbm_update_page: slot is invalid"
    );
    // break
    *l3.add(index) = 0;
    barrier(va);
    // make
    *l3.add(index) = new_desc;
    barrier(va);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 4K 对齐的 512 项表（模拟一页页表）。
    #[repr(align(4096))]
    struct AlignedTable([u64; 512]);

    /// 伪造 4 级页表（各字段按 4K 对齐布局，地址可直接当"物理地址"用）。
    #[repr(align(4096))]
    struct FakeTables {
        l0: [u64; 512],
        l1: [u64; 512],
        l2: [u64; 512],
        l3: [u64; 512],
    }

    impl FakeTables {
        fn new() -> Self {
            Self {
                l0: [0; 512],
                l1: [0; 512],
                l2: [0; 512],
                l3: [0; 512],
            }
        }

        fn link_default(&mut self) {
            self.l0[0] = make_table_descriptor(self.l1.as_ptr() as u64);
            self.l1[0] = make_table_descriptor(self.l2.as_ptr() as u64);
            self.l2[0] = make_table_descriptor(self.l3.as_ptr() as u64);
        }

        fn root(&self) -> *mut u64 {
            self.l0.as_ptr() as *mut u64
        }
    }

    #[test]
    fn indices_decomposition() {
        // 2MiB L2 block 粒度：0x40_0000 = 4MiB → L2 索引 2。
        assert_eq!(page_table_indices(0x0040_0000), [0, 0, 2, 0]);
        assert_eq!(page_table_indices(0x8000_0000), [0, 2, 0, 0]);
        assert_eq!(page_table_indices(0x0000_FFFF_F000), [0, 3, 0x1ff, 0x1ff]);
        assert_eq!(page_table_indices(0x0000_0000_0000), [0, 0, 0, 0]);
        assert_eq!(page_table_indices(0x0000_0040_1000), [0, 0, 2, 1]);
    }

    #[test]
    fn walk_unmapped() {
        let t = FakeTables::new();
        let out = unsafe { walk(t.root(), 0x1000) };
        assert_eq!(out, WalkOutcome::Unmapped);
    }

    #[test]
    fn walk_block_and_page() {
        let mut t = FakeTables::new();
        t.link_default();
        // L2[2] 放一个 block（0x40_0000 = 4MiB，2MiB block 粒度下的窗口 2）
        t.l2[2] = (0x40_0000u64) | DESC_VALID | DESC_AF; // 模拟 block 描述符（bit1=0）
                                                         // L3 挂一个页：VA 0x40_1000 → L3[1]
        t.l3[1] = make_leaf_descriptor(0x4100_3000, USER_AP_RW, false);
        let b = unsafe { walk(t.root(), 0x40_0000) };
        assert_eq!(
            b,
            WalkOutcome::Block {
                desc: t.l2[2],
                block_base: 0x40_0000,
            }
        );
        // 页级路径：L2[0]（link_default 已挂 L3），VA 0x1000 → L3[1]
        let p = unsafe { walk(t.root(), 0x1000) };
        assert_eq!(
            p,
            WalkOutcome::Page {
                desc: t.l3[1],
                phys: 0x4100_3000,
            }
        );
        // 相同 L3 表下未映射的页
        let u = unsafe { walk(t.root(), 0x2000) };
        assert_eq!(u, WalkOutcome::Unmapped);
        // 未链接的 L2 窗口（L2[1] 空，VA 2MiB 处）
        let u2 = unsafe { walk(t.root(), 0x0020_0000) };
        assert_eq!(u2, WalkOutcome::Unmapped);
    }

    #[test]
    fn descriptor_construction() {
        let table = make_table_descriptor(0x4000_1000);
        assert_eq!(table & 0b11, 0b11); // valid | table
        assert_eq!(table & PHYS_ADDR_MASK, 0x4000_1000);
        let leaf = make_leaf_descriptor(0x4000_2000, USER_AP_RW, false);
        assert_eq!(leaf & 0b11, 0b11);
        assert_eq!((leaf >> AP_SHIFT) & 0b11, USER_AP_RW);
        assert!(leaf & DESC_UXN != 0); // 不可执行
        let exec = make_leaf_descriptor(0x4000_2000, USER_AP_RX, true);
        assert!(exec & DESC_UXN == 0);
        assert_eq!((exec >> AP_SHIFT) & 0b11, USER_AP_RX);
    }

    #[test]
    fn bbm_split_replaces_block_with_table() {
        let mut t = FakeTables::new();
        t.link_default();
        // VA 0x40_0000（4MiB = L2[2]，2MiB block 粒度）是 block
        let old_block = (0x40_0000u64 & PHYS_ADDR_MASK) | DESC_VALID | DESC_AF;
        t.l2[2] = old_block;
        let mut l3_new = AlignedTable([0; 512]);
        let target_desc = make_leaf_descriptor(0x4100_3000, AP_EL1_RW_EL0_NONE, true);
        let mut barrier = |_: usize| {};
        unsafe {
            bbm_split_block(
                t.l2.as_mut_ptr(),
                2,
                l3_new.0.as_mut_ptr(),
                0x40_0000,
                old_block,
                1, // 目标页在窗口内的槽位：VA 0x40_1000
                target_desc,
                &mut barrier,
            );
        }
        // L2[2] 现在是表描述符
        assert!(is_table(t.l2[2]));
        assert_eq!(t.l2[2] & PHYS_ADDR_MASK, l3_new.0.as_ptr() as u64);
        // 回填页保持恒等 & EL1-only 属性
        for slot in 0..512 {
            if slot == 1 {
                continue;
            }
            let d = l3_new.0[slot];
            assert!(is_valid(d));
            assert_eq!(d & PHYS_ADDR_MASK, (0x40_0000 + slot * PAGE_SIZE) as u64);
            assert_eq!((d >> AP_SHIFT) & 0b11, AP_EL1_RW_EL0_NONE);
            assert_ne!(d & DESC_SW_BORROWED, 0, "identity filler must be borrowed");
        }
        // 目标页被替换，不能继承 borrowed 标记。
        assert_eq!(l3_new.0[1], target_desc);
        assert_eq!(l3_new.0[1] & DESC_SW_BORROWED, 0);
        // 走表验证：VA 0x40_1000 现在走进 L3
        let p = unsafe { walk(t.root(), 0x40_1000) };
        assert_eq!(
            p,
            WalkOutcome::Page {
                desc: target_desc,
                phys: 0x4100_3000,
            }
        );
    }

    // ── 第十刀 COW：纯函数判定矩阵 ─────────────────────────────

    fn rw_leaf(pa: u64) -> u64 {
        make_leaf_descriptor(pa, USER_AP_RW, false)
    }

    #[test]
    fn classify_leaf_matrix() {
        let borrowed =
            make_leaf_descriptor(0x1000_0000, AP_EL1_RW_EL0_NONE, false) | DESC_SW_BORROWED;
        assert_eq!(classify_leaf(borrowed), LeafShareClass::BorrowedDirect);
        let device = make_leaf_descriptor(0x1000_0000, USER_AP_RW, false) | DESC_SW_DEVICE;
        assert_eq!(classify_leaf(device), LeafShareClass::SkipDevice);
        // 开关关闭（第十四刀集成期默认）：一切叶子一律 eager 兜底，
        // 仅保留「只读直映射」判定供未来重开时对照。
        if !COW_SHARED_FORK {
            assert_eq!(
                classify_leaf(rw_leaf(0x5000_1000)),
                LeafShareClass::EagerCopy
            );
            let text = make_leaf_descriptor(0x5000_2000, USER_AP_RX, true);
            assert_eq!(classify_leaf(text), LeafShareClass::ReadOnlyDirect);
            return;
        }
        // 可写数据页 → 共享化
        assert_eq!(
            classify_leaf(rw_leaf(0x5000_1000)),
            LeafShareClass::CowShare
        );
        // 真只读 text 页（RX、无 COW 位）→ 直接映射
        let text = make_leaf_descriptor(0x5000_2000, USER_AP_RX, true);
        assert_eq!(classify_leaf(text), LeafShareClass::ReadOnlyDirect);
        // 已 COW 页（fork 链二次 fork）→ 继续共享，即便 AP 已被改成 RX
        assert_eq!(
            classify_leaf(cow_share_leaf(rw_leaf(0x5000_3000))),
            LeafShareClass::CowShare
        );
        // EL1-only AP（用户空间不应出现）→ 兜底 eager 复制
        let kern = make_leaf_descriptor(0x5000_4000, AP_EL1_RW_EL0_NONE, false);
        assert_eq!(classify_leaf(kern), LeafShareClass::EagerCopy);
    }

    #[test]
    fn cow_share_preserves_everything_but_ap() {
        let leaf = make_leaf_descriptor(0x5000_1000, USER_AP_RW, false);
        let shared = cow_share_leaf(leaf);
        // PA 原样（PA 必须页对齐，PHYS_ADDR_MASK 不含低 12 位属性）
        assert_eq!(shared & PHYS_ADDR_MASK, 0x5000_1000);
        // AP 变只读（EL0+EL1 均 RO）
        assert_eq!((shared >> AP_SHIFT) & 0b11, USER_AP_RX);
        // 软件 COW 位已置
        assert!(is_cow_leaf(shared));
        // UXN / AF / SH / attridx 与原描述符一致
        for mask in [DESC_UXN, DESC_AF, DESC_SH_INNER, DESC_ATTRIDX_NORMAL] {
            assert_eq!(shared & mask, leaf & mask);
        }
    }

    #[test]
    fn cow_share_is_idempotent() {
        let once = cow_share_leaf(rw_leaf(0x6000_0000));
        let twice = cow_share_leaf(once);
        assert_eq!(once, twice, "二次 fork 必须幂等（fork 链场景）");
    }

    #[test]
    fn cow_break_restores_writable_and_swaps_pa() {
        let shared = cow_share_leaf(make_leaf_descriptor(0x7000_0000, USER_AP_RW, false));
        let broken = cow_break_leaf(shared, 0x8000_9000);
        assert_eq!(broken & PHYS_ADDR_MASK, 0x8000_9000);
        assert_eq!((broken >> AP_SHIFT) & 0b11, USER_AP_RW);
        assert!(!is_cow_leaf(broken), "断链必须清软件位");
        // 执行权限沿用旧描述符（本例原页可执行位为不可执行）
        assert_eq!(broken & DESC_UXN, shared & DESC_UXN);
    }

    #[test]
    fn is_cow_leaf_rejects_non_cow_and_invalid() {
        // 真·只读 text 页不是 COW 页（写它必须 SIGSEGV 而非断链）
        assert!(!is_cow_leaf(make_leaf_descriptor(0x1000, USER_AP_RX, true)));
        // 可写但未标记的普通页（spawn 初始态）不是 COW 页
        assert!(!is_cow_leaf(make_leaf_descriptor(
            0x3000, USER_AP_RW, false
        )));
        // 无效描述符不算
        assert!(!is_cow_leaf(DESC_SW_COW));
        assert_eq!(is_cow_leaf(make_table_descriptor(0x2000)), false);
    }

    #[test]
    fn bbm_update_page_breaks_then_makes() {
        let mut t = FakeTables::new();
        t.link_default();
        // VA 0x40_7000 的窗口是 L2[2]（4MiB 处），把 L2[2] 挂到测试用 L3
        t.l2[2] = make_table_descriptor(t.l3.as_ptr() as u64);
        t.l3[7] = make_leaf_descriptor(0x5000_7000, USER_AP_RW, true);
        let old = t.l3[7];
        let new_desc = make_leaf_descriptor(0x6000_8000, USER_AP_RX, false);
        let va = 0x40_7000; // L2[1] 窗口内第 7 页
        let mut barrier = |_: usize| {};
        unsafe {
            bbm_update_page(t.l3.as_mut_ptr(), 7, va, new_desc, &mut barrier);
        }
        assert_eq!(t.l3[7], new_desc);
        assert_ne!(old, t.l3[7]);
        let p = unsafe { walk(t.root(), va) };
        assert_eq!(
            p,
            WalkOutcome::Page {
                desc: new_desc,
                phys: 0x6000_8000,
            }
        );
    }
}
