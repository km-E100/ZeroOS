use super::paging;
use super::phys;
use super::table_walk::PAGE_SIZE;

pub use super::paging::{MapError, USER_STACK_LEN, USER_STACK_TOP};

/// 用户堆基址（号位 24 Brk 布局契约，zero-abi Syscall::Brk 文档同步冻结）。
/// 选址依据：ELF 链接区在 [0x20_0000, ~4MiB)、bootfs 在 2GiB、栈顶
/// 0xFFFF_F000——0x1000_0000（256 MiB）与三者皆不相交，且天然 2 MiB
/// 对齐；整个堆窗口 [BASE, BASE+64MiB) 落在用户私有 L1[0] 区间
/// （< KERNEL_REGION_START=1GiB），绝不触碰内核共享表 L1[1]。
pub const USER_HEAP_BASE: usize = 0x1000_0000;
/// 用户堆总量上限：64 MiB（超出按 POSIX ENOMEM 报 NoMemory）。
pub const USER_HEAP_MAX_LEN: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct AddressSpace {
    inner: paging::AddressSpace,
}

impl AddressSpace {
    pub unsafe fn new() -> Self {
        let space = paging::create_user_address_space();
        Self { inner: space }
    }

    pub unsafe fn activate(&self) {
        paging::activate_user_address_space(&self.inner);
    }

    pub unsafe fn deactivate() {
        paging::deactivate_user_address_space();
    }

    /// 递归释放整个地址空间（页表页 + 用户物理页）。
    /// 见 `paging::destroy_user_address_space`：严禁释放 L1[KERNEL_SHARED_L1]
    /// 指向的内核 L2_1 表本体；进程退出时必须调用（remove_slot 已接好）。
    pub unsafe fn destroy(&self) {
        crate::syscalls::on_address_space_destroy(self.ttbr0_phys());
        paging::destroy_user_address_space(&self.inner);
    }

    pub unsafe fn map_stack(&mut self, stack_top: usize, size: usize) -> Result<(), MapError> {
        paging::map_user_stack(&mut self.inner, stack_top, size)
    }

    pub unsafe fn map_page_phys(
        &mut self,
        virt: usize,
        phys: usize,
        writable: bool,
        executable: bool,
    ) -> Result<(), MapError> {
        paging::map_user_phys_page(&mut self.inner, virt, phys, writable, executable)
    }

    /// Map a PCI/MMIO page as EL0 RW Device-nGnRE. The physical page is not
    /// owned by the process and is therefore never freed by address-space teardown.
    pub unsafe fn map_device_page(&mut self, virt: usize, phys: usize) -> Result<(), MapError> {
        paging::map_user_device_page(&mut self.inner, virt, phys)
    }

    pub unsafe fn unmap_device_region(&self, start: usize, end: usize) -> usize {
        paging::unmap_user_device_range(&self.inner, start, end)
    }

    /// brk 增长路径（号位 24）：为 `[start, end)`（页对齐）逐页分配零页并以
    /// USER_AP_RW / UXN=1 映入本地址空间。新堆页**必须清零**——否则上一任
    /// 进程的数据会经分配器复用泄漏进新堆（跨进程信息流事故）。
    ///
    /// 原子性：任一页失败（OOM / AlreadyMapped）即回滚本次调用已映射的
    /// 全部页（unmap + 归还），地址空间保持调用前状态——半成品堆绝不
    /// 暴露给用户，调用方只需把 break 留在原值即可。
    ///
    /// # Safety
    /// 与 [`AddressSpace::map_page_phys`] 同一信任级别；须在无并发修改者
    /// 的上下文调用（单核 svc 上下文满足）。
    pub unsafe fn map_heap_region(&mut self, start: usize, end: usize) -> Result<(), MapError> {
        assert!(
            start <= end && start & (PAGE_SIZE - 1) == 0 && end & (PAGE_SIZE - 1) == 0,
            "map_heap_region: range must be page-aligned (start={:#x} end={:#x})",
            start,
            end
        );
        let mut mapped = start;
        while mapped < end {
            let Some(page) = phys::alloc_page() else {
                // OOM 回滚：撤销本次已映射的页后报错。
                unsafe {
                    paging::unmap_user_range(&self.inner, start, mapped);
                }
                return Err(MapError::OutOfMemory);
            };
            // 恒等映射下物理页可直接按 PA 清零，无需临时映射（同 ELF/bss 路径）。
            unsafe {
                core::ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE);
            }
            if let Err(err) = self.map_page_phys(mapped, page, true, false) {
                // 映射失败：刚分配的页先归还，再回滚此前已建好的映射。
                unsafe {
                    phys::free_page(page);
                    if mapped > start {
                        paging::unmap_user_range(&self.inner, start, mapped);
                    }
                }
                return Err(err);
            }
            mapped += PAGE_SIZE;
        }
        Ok(())
    }

    /// brk 收缩路径（号位 24）：解除 `[start, end)`（页对齐）的映射并归还
    /// 物理页。BBM 次序（清 PTE → dsb ishst/tlbi vaae1is/dsb ish/isb →
    /// 屏障后才 free）由 [`paging::unmap_user_range`] 保证。返回回收页数。
    ///
    /// # Safety
    /// 同上：无并发修改者上下文。
    pub unsafe fn unmap_heap_region(&self, start: usize, end: usize) -> usize {
        unsafe { paging::unmap_user_range(&self.inner, start, end) }
    }

    pub fn ttbr0_phys(&self) -> u64 {
        self.inner.root_phys()
    }

    /// 软件走表诊断：解析 VA 在本地址空间中的叶子描述符（trap 路径用）。
    pub fn walk(&self, va: usize) -> super::table_walk::WalkOutcome {
        paging::walk_space(&self.inner, va)
    }

    /// 第十刀 COW：写权限故障的写时复制断链。
    /// 返回 true = 已按 COW 处理（调用方应恢复现场重放指令）；
    /// false = 与 COW 无关（真非法访问）或资源不足。
    pub fn handle_cow_fault(&self, va: usize) -> bool {
        unsafe { paging::handle_cow_fault(&self.inner, va) }
    }
}

/// 栈底 guard 页设计说明：
///
/// 用户栈位于 [USER_STACK_TOP - USER_STACK_LEN, USER_STACK_TOP)，
/// 栈底下方一页（0xFFFD_E000..0xFFFD_F000）在地图总览里**天然无效**——
/// 低 1GiB 用户区映射（text/data）都在 0x00x_xxxx 级别，bootfs 在
/// 2GiB（0x8000_0000），栈顶之下没有任何映射覆盖 guard 页：
/// - 栈溢出向下滑入 guard 页 → 立即 translation fault（响亮失败）；
/// - 当前选择"隐式 guard"而非显式映射一张无效页：显式无效页需要为
///   每个进程多写一个 L3 表项，且在 fork COW 克隆 / brk 下探时
///   需要额外的"拷贝时跳过 guard"逻辑，收益为零（隐式本就无效）。
///   若未来用户堆向栈下方扩展，必须恢复显式 guard 页设计（见注释
///   `map_user_stack`）。
///
/// fork 克隆（clone_space）逐页复制后，child 的栈与 guard 布局与 parent
/// 完全一致（同 VA、异物理页），guard 依然隐式有效，无需额外处理。
///
/// 注意：`process.rs` 的 `user_stack_top_raw` 目前忽略 slot 参数（所有进程
/// 共享同一栈顶 VA）——栈**虚拟地址**相同不影响隔离（物理页独立）；
/// 只有栈**物理页泄漏/重映射**才会破坏隔离，本轮已由 destroy 修复。
pub fn clone_space(space: &AddressSpace) -> Result<AddressSpace, MapError> {
    let inner = unsafe { paging::clone_user_address_space(&space.inner) }?;
    Ok(AddressSpace { inner })
}
