//! 第十刀 COW fork 集成场景（host 单测）。
//!
//! 用伪造的 L0..L3 页表 + 引用计数位图，完整重演 fork 的三个阶段：
//!   clone（父子 PTE 同 PA、只读、COW 标记）→
//!   缺页断链（子拿新页、父副本内容分毫不动）→
//!   销毁（任一方先退出都不得回收共享页；最后一个引用消失才回收）。
//!
//! 物理页用 host 数组模拟：分配器返回的"PA"只是编号，内容读写经
//! `FakePhys::page` 索引到 Box 存储——绝不把伪 PA 当宿主指针解引用。

use crate::phys_bitmap::PhysBitmap;
use crate::table_walk::{
    classify_leaf, cow_break_leaf, cow_share_leaf, is_cow_leaf, make_leaf_descriptor,
    make_table_descriptor, page_table_indices, walk, LeafShareClass, WalkOutcome, DESC_AF,
    DESC_SW_COW, DESC_TYPE_TABLE, DESC_UXN, DESC_VALID, PHYS_ADDR_MASK, USER_AP_RX, USER_AP_RW,
};

/// 4K 对齐的 512 项表（模拟一页页表）。
#[repr(align(4096))]
struct Table([u64; 512]);

/// 一套伪造地址空间：L0→L1→L2→L3 四级各一张（测试只映射一页窗口）。
struct FakeSpace {
    l0: Table,
    l1: Table,
    l2: Table,
    l3: Table,
}

impl FakeSpace {
    fn new() -> Self {
        Self {
            l0: Table([0; 512]),
            l1: Table([0; 512]),
            l2: Table([0; 512]),
            l3: Table([0; 512]),
        }
    }

    /// 必须在结构体落到最终位置**之后**调用：描述符记录的是字段地址，
    /// 若在 new() 返回前链接，return 的移动会让指针悬垂（walk 即 Unmapped）。
    /// 与 table_walk::tests::FakeTables::link_default 同一纪律。
    fn link(&mut self) {
        self.l0.0[0] = make_table_descriptor(self.l1.0.as_ptr() as u64);
        self.l1.0[0] = make_table_descriptor(self.l2.0.as_ptr() as u64);
        self.l2.0[0] = make_table_descriptor(self.l3.0.as_ptr() as u64);
    }

    fn root(&self) -> *mut u64 {
        self.l0.0.as_ptr() as *mut u64
    }

    /// 在 VA 处直接写入叶描述符（测试只用到低窗口的槽位）。
    fn install(&mut self, va: usize, desc: u64) {
        let [i0, i1, i2, i3] = page_table_indices(va);
        assert_eq!((i0, i1, i2), (0, 0, 0), "FakeSpace 只支持低窗口");
        self.l3.0[i3] = desc;
    }

    fn leaf_at(&self, va: usize) -> u64 {
        let [_, _, _, i3] = page_table_indices(va);
        self.l3.0[i3]
    }
}

/// 物理内存模拟：8 页，"PA"=FAKE_RAM_BASE+idx*4096，内容存 Box 数组。
struct FakePhys {
    bitmap: PhysBitmap,
    pages: Vec<u8>,
    refs_storage: Box<[u16; 16]>,
    words: Box<[u64; 4]>,
}

const FAKE_RAM_BASE: usize = 0x4000_0000;
const N_PAGES: usize = 8;

impl FakePhys {
    fn new() -> Self {
        let mut s = Self {
            bitmap: PhysBitmap::empty(),
            pages: vec![0; N_PAGES * 4096],
            refs_storage: Box::new([0; 16]),
            words: Box::new([0; 4]),
        };
        unsafe {
            s.bitmap.init(
                s.words.as_mut_ptr(),
                s.words.len(),
                s.refs_storage.as_mut_ptr(),
                s.refs_storage.len(),
                FAKE_RAM_BASE,
                N_PAGES,
                1,
            );
        }
        s
    }

    fn alloc(&mut self) -> usize {
        self.bitmap.alloc_page().expect("fake phys OOM")
    }

    fn offset(&self, pa: usize) -> usize {
        assert!(pa >= FAKE_RAM_BASE && pa < FAKE_RAM_BASE + N_PAGES * 4096);
        pa - FAKE_RAM_BASE
    }

    /// 可变访问一页（模拟内核在恒等映射下直写物理页）。
    fn page(&mut self, pa: usize) -> &mut [u8] {
        let off = self.offset(pa);
        &mut self.pages[off..off + 4096]
    }

    /// 共享访问一页（校验内容用）。
    fn peek(&self, pa: usize) -> &[u8] {
        let off = self.offset(pa);
        &self.pages[off..off + 4096]
    }

    fn rc(&self, pa: usize) -> usize {
        self.bitmap.ref_count(pa) as usize
    }
}

/// 给整页填入 tag+i 的确定性图案（校验时逐字节比对）。
fn fill(page: &mut [u8], tag: u8) {
    for (i, b) in page.iter_mut().enumerate() {
        *b = tag.wrapping_add(i as u8);
    }
}

fn assert_content(mem: &FakePhys, pa: usize, tag: u8) {
    for (i, &b) in mem.peek(pa).iter().enumerate() {
        assert_eq!(b, tag.wrapping_add(i as u8), "PA {pa:#x} 内容被污染 @ 字节 {i}");
    }
}

const VA_DATA: usize = 0x7000; // L2[0]/L3[7]：FakeSpace 链路内

// ── 场景一：clone 共享化 ────────────────────────────────────────

/// clone：可写页父子共享同一 PA，双侧只读 + COW 标记，refcount=2，
/// 分配器空闲数不变（零复制证据）。
#[test]
fn clone_shares_page_readonly_both_sides() {
    let mut mem = FakePhys::new();
    let free_before = mem.bitmap.free_count();
    let pa = mem.alloc(); // 父的数据页
    fill(mem.page(pa), 0xAA);

    let mut parent = FakeSpace::new();
    parent.install(VA_DATA, make_leaf_descriptor(pa as u64, USER_AP_RW, false));

    // ── clone 的 COW 化步骤（与 paging::clone_user_address_space 同逻辑）：
    let pte = parent.leaf_at(VA_DATA);
    assert!(pte & DESC_VALID != 0 && pte & DESC_TYPE_TABLE != 0);
    assert_eq!(classify_leaf(pte), LeafShareClass::CowShare);
    mem.bitmap.retain_page(pa); // 子空间共享记账
    let child_desc = cow_share_leaf(pte);
    let parent_desc = cow_share_leaf(pte);

    let mut child = FakeSpace::new();
    child.install(VA_DATA, child_desc);
    parent.install(VA_DATA, parent_desc);

    // 双侧同 PA / 只读 / COW 位
    for sp in [&parent, &child] {
        let leaf = sp.leaf_at(VA_DATA);
        assert_eq!(leaf & PHYS_ADDR_MASK, pa as u64);
        assert_eq!((leaf >> 6) & 0b11, USER_AP_RX);
        assert!(is_cow_leaf(leaf));
    }
    assert_eq!(mem.rc(pa), 2);
    assert_eq!(
        mem.bitmap.free_count(),
        free_before - 1,
        "clone 未新分配数据页（零复制）"
    );
}

// ── 场景二：断链与隔离 ─────────────────────────────────────────

/// 断链：子写 → 拿新私有可写页；父副本内容与 PTE 均不受扰动；
/// 销毁顺序无关；父后写原地恢复可写。
#[test]
fn child_write_breaks_cow_parent_copy_unpolluted() {
    let mut mem = FakePhys::new();
    let shared_pa = mem.alloc();
    fill(mem.page(shared_pa), 0x5A); // fork 时双方可见的内容

    let mut parent = FakeSpace::new();
    parent.install(
        VA_DATA,
        cow_share_leaf(make_leaf_descriptor(shared_pa as u64, USER_AP_RW, false)),
    );
    let mut child = FakeSpace::new();
    child.install(
        VA_DATA,
        cow_share_leaf(make_leaf_descriptor(shared_pa as u64, USER_AP_RW, false)),
    );
    mem.bitmap.retain_page(shared_pa); // clone 记账 → rc=2

    // ── COW 缺页：handle_cow_fault 的核心决策（rc>1 ⇒ 复制）。
    let cpte = child.leaf_at(VA_DATA);
    assert!(is_cow_leaf(cpte));
    let old_pa = (cpte & PHYS_ADDR_MASK) as usize;
    assert_eq!(mem.rc(old_pa), 2, "断链前必须是共享态");
    let new_pa = mem.alloc();
    {
        let src = mem.peek(old_pa).to_vec(); // 整页 memcpy（4K）
        mem.page(new_pa).copy_from_slice(&src);
    }
    fill(mem.page(new_pa), 0xC0); // 子进程写入自己的私有副本
    let broken = cow_break_leaf(cpte, new_pa as u64);
    child.install(VA_DATA, broken);
    mem.bitmap.free_page(old_pa); // 老页归父：rc 2→1

    // 子侧：新 PA、恢复可写、COW 位清除
    let leaf = child.leaf_at(VA_DATA);
    assert_eq!(leaf & PHYS_ADDR_MASK, new_pa as u64);
    assert_eq!((leaf >> 6) & 0b11, USER_AP_RW);
    assert!(!is_cow_leaf(leaf));
    // 父侧：PTE 原样（同 PA 只读 COW），内容一个字节都不许变
    let pleaf = parent.leaf_at(VA_DATA);
    assert_eq!(pleaf & PHYS_ADDR_MASK, shared_pa as u64);
    assert!(is_cow_leaf(pleaf));
    assert_content(&mem, shared_pa, 0x5A); // ⭐ 任务书钉死项：父副本未被污染
    assert_eq!(mem.rc(shared_pa), 1);

    // 父此后写自己页：rc==1 ⇒ 原地恢复可写（不再复制）
    let pte = parent.leaf_at(VA_DATA);
    let restored = cow_break_leaf(pte, shared_pa as u64);
    parent.install(VA_DATA, restored);
    assert_eq!((restored >> 6) & 0b11, USER_AP_RW, "唯一持有者原地恢复可写");
    assert_eq!(restored & PHYS_ADDR_MASK, shared_pa as u64);

    // ── 销毁顺序无关性：任何一步多释放都会 double-free panic；
    // 「子先退」的次序由 refcount_lifecycle 用例覆盖，这里走「父先退」。
    mem.bitmap.free_page(shared_pa); // 父销毁：真正回收
    assert!(mem.bitmap.page_is_free(shared_pa));
    mem.bitmap.free_page(new_pa); // 子销毁其私有页
    assert!(mem.bitmap.page_is_free(new_pa));
}

/// 二次 fork（fork 链）：已是 COW 页继续传播共享标记，rc 逐级 +1，
/// 多方断链各自减一，最后一级持有者才触发真回收。
#[test]
fn fork_chain_propagates_and_drains_refcounts() {
    let mut mem = FakePhys::new();
    let page = mem.alloc();

    let mut grandparent = FakeSpace::new();
    grandparent.install(
        VA_DATA,
        cow_share_leaf(make_leaf_descriptor(page as u64, USER_AP_RW, false)),
    );
    // 第一代 fork
    mem.bitmap.retain_page(page);
    assert_eq!(mem.rc(page), 2);
    // 孙代对「已是 COW 的父页」再 fork：classify 仍判 CowShare（幂等共享）
    let inherited = grandparent.leaf_at(VA_DATA);
    assert_eq!(classify_leaf(inherited), LeafShareClass::CowShare);
    let marked = cow_share_leaf(inherited);
    assert_eq!(marked, inherited, "cow_share 必须幂等");
    mem.bitmap.retain_page(page);
    assert_eq!(mem.rc(page), 3);

    // 三方相继退出：3→2→1 页始终 busy；最后 1→0 才回收。
    mem.bitmap.free_page(page);
    assert_eq!(mem.rc(page), 2);
    mem.bitmap.free_page(page);
    assert_eq!(mem.rc(page), 1);
    assert!(!mem.bitmap.page_is_free(page));
    mem.bitmap.free_page(page);
    assert!(mem.bitmap.page_is_free(page));
}

/// 真只读页（text）：clone 直接映射同一 PA（省一次复制）但**不打** COW 标记
/// ——写 text 必须 SIGSEGV，绝不能被断链成私有可写副本（W^X 底线）。
#[test]
fn readonly_text_pages_map_direct_without_cow_bit() {
    let mut mem = FakePhys::new();
    let text_pa = mem.alloc();
    let text_pte = make_leaf_descriptor(text_pa as u64, USER_AP_RX, true);
    assert_eq!(classify_leaf(text_pte), LeafShareClass::ReadOnlyDirect);

    // clone：直接映射 + retain（防一方退出误回收），无 COW 位
    mem.bitmap.retain_page(text_pa);
    let mut child = FakeSpace::new();
    child.install(VA_DATA, text_pte);
    let leaf = child.leaf_at(VA_DATA);
    assert!(!is_cow_leaf(leaf), "text 页不许带 COW 标记");
    assert_eq!((leaf >> 6) & 0b11, USER_AP_RX);
    assert_eq!(mem.rc(text_pa), 2);

    // 双侧销毁各减一，第二侧才回收。
    mem.bitmap.free_page(text_pa);
    assert!(!mem.bitmap.page_is_free(text_pa));
    mem.bitmap.free_page(text_pa);
    assert!(mem.bitmap.page_is_free(text_pa));
}

/// 断链描述符构造回归：UXN 沿用旧页（可执行 COW 页断链后仍可执行）、
/// attr/AF/SH 原样保留；walk 全链路命中断链后的叶子。
#[test]
fn cow_break_preserves_uxn_and_attrs_and_walks() {
    let exec_shared = cow_share_leaf(make_leaf_descriptor(0x5000_0000, USER_AP_RW, true));
    let broken = cow_break_leaf(exec_shared, 0x6000_1000);
    assert_eq!(broken & DESC_UXN, 0, "可执行页断链后保持可执行");
    assert_eq!(broken & DESC_AF, DESC_AF);
    let noexec_shared = cow_share_leaf(make_leaf_descriptor(0x5000_1000, USER_AP_RW, false));
    let broken2 = cow_break_leaf(noexec_shared, 0x6000_2000);
    assert_ne!(broken2 & DESC_UXN, 0, "不可执行属性不得丢失");

    let mut space = FakeSpace::new();
    space.link();
    space.install(VA_DATA, broken2);
    match unsafe { walk(space.root(), VA_DATA) } {
        WalkOutcome::Page { desc, phys } => {
            assert_eq!(desc, broken2);
            assert_eq!(phys, 0x6000_2000);
        }
        other => panic!("walk 应命中 Page，实际 {other:?}"),
    }
    // DESC_SW_COW 落位检查：bit11，且不与 VALID/bit1/SH(bits9:8)/AF(bit10) 重叠。
    assert_eq!(DESC_SW_COW, 1 << 11);
    assert_eq!(
        DESC_SW_COW & (DESC_VALID | DESC_TYPE_TABLE | 0b11 << 8 | DESC_AF),
        0,
        "软件位不得踩硬件字段"
    );
}
