use super::paging;

pub use super::paging::{MapError, USER_STACK_LEN, USER_STACK_TOP};

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

    pub fn ttbr0_phys(&self) -> u64 {
        self.inner.root_phys()
    }

    /// 软件走表诊断：解析 VA 在本地址空间中的叶子描述符（trap 路径用）。
    pub fn walk(&self, va: usize) -> super::table_walk::WalkOutcome {
        paging::walk_space(&self.inner, va)
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
///   每个进程多写一个 L3 表项，且在 fork eager-copy / 未来 brk 下探时
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