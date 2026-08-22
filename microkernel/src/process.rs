use crate::elf::{PF_W, PF_X};
use crate::mm::address_space::{self, AddressSpace, MapError, USER_STACK_LEN, USER_STACK_TOP};
// PAGE_SIZE 由 mm Agent 迁移至 table_walk 模块（paging 不再公开导出）。
use crate::mm::table_walk::PAGE_SIZE;
use crate::mm::phys;
use crate::rootfs;
use crate::user_elf;
use core::cell::UnsafeCell;
use core::cmp;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use zero_abi::{ProcessId, ThreadEntry};

const MAX_PROCESSES: usize = 64;
const USER_STACK_SIZE: usize = 0x4000;
const KERNEL_STACK_SIZE: usize = 0x4000;
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TrapFrame {
    pub regs: [u64; 31], // x0 - x30
    pub sp_el0: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub sp_el1: u64,
}

impl TrapFrame {
    pub const fn new() -> Self {
        Self {
            regs: [0; 31],
            sp_el0: 0,
            elr_el1: 0,
            spsr_el1: 0,
            sp_el1: 0,
        }
    }

    pub fn init_user(
        &mut self,
        entry: ThreadEntry,
        user_stack_top: usize,
        kernel_stack_top: usize,
    ) {
        self.regs = [0; 31];
        self.regs[30] = thread_exit as usize as u64;
        self.sp_el0 = user_stack_top as u64;
        self.elr_el1 = entry as usize as u64;
        self.spsr_el1 = 0; // EL0t, interrupts enabled
        self.sp_el1 = kernel_stack_top as u64;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Running,
    Blocked,
    Dying,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
struct ProcessRecord {
    pid: ProcessId,
    name: &'static str,
    entry: ThreadEntry,
    state: ProcessState,
    slot: usize,
    addr_space: Option<AddressSpace>,
    privileged: bool,
    entry_point: Option<usize>,
    user_stack_top: Option<usize>,
    started: bool,
}

static NEXT_PID: AtomicU64 = AtomicU64::new(2);
static PROCESS_TABLE: Mutex<[Option<ProcessRecord>; MAX_PROCESSES]> =
    Mutex::new([const { None }; MAX_PROCESSES]);
#[repr(C, align(16))]
struct TrapFrameCell(UnsafeCell<TrapFrame>);
impl TrapFrameCell {
    const fn new() -> Self {
        Self(UnsafeCell::new(TrapFrame::new()))
    }

    fn get(&self) -> *mut TrapFrame {
        self.0.get()
    }
}
unsafe impl Sync for TrapFrameCell {}

/// ⚠ align(16) 是硬性要求：AAPCS64 规定 SP 任意时刻必须 16 字节对齐。
/// 裸 [u8; N] 对齐数为 1，静态放置后的栈顶可能仅 8 对齐 —— 编译器在
/// 中断/系统调用路径生成 str q0（16B SIMD 存储清零局部变量）时触发
/// alignment fault（实机：launchd status 即崩，far=栈顶+0x70）。
#[repr(C, align(16))]
struct StackCell<const N: usize>(UnsafeCell<[u8; N]>);
impl<const N: usize> StackCell<N> {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }

    fn as_ptr(&self) -> *mut u8 {
        self.0.get().cast::<u8>()
    }
}
unsafe impl<const N: usize> Sync for StackCell<N> {}

static TRAP_FRAMES: [TrapFrameCell; MAX_PROCESSES] =
    [const { TrapFrameCell::new() }; MAX_PROCESSES];
static KERNEL_STACKS: [StackCell<KERNEL_STACK_SIZE>; MAX_PROCESSES] =
    [const { StackCell::new() }; MAX_PROCESSES];

#[derive(Debug)]
pub enum ProcessError {
    NoSuchProcess,
    TableFull,
    NoMemory,
    InvalidArgument,
    PermissionDenied,
    ElfError(crate::elf::ElfError),
    MapError(address_space::MapError),
}

pub fn init() {
    init_kernel_stack_tops();
    let mut table = PROCESS_TABLE.lock();
    for slot in table.iter_mut() {
        *slot = None;
    }
    NEXT_PID.store(2, Ordering::SeqCst);
}

pub fn spawn(entry: ThreadEntry, name: &'static str) -> ProcessId {
    crate::debug!("process::spawn called for name={}", name);
    let pid = ProcessId::new(NEXT_PID.fetch_add(1, Ordering::SeqCst));

    let mut table = PROCESS_TABLE.lock();
    let (slot_index, slot) = table
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| slot.is_none())
        .expect("process table full");

    let user_sp = user_stack_top_raw(slot_index);
    let kernel_sp = kernel_stack_top_raw(slot_index);
    unsafe {
        let tf = TRAP_FRAMES[slot_index].get();
        (*tf).init_user(entry, user_sp, kernel_sp);
    }

    crate::info!(
        "process::spawn: pid={} slot={} name={}",
        pid.raw(),
        slot_index,
        name
    );

    *slot = Some(ProcessRecord {
        pid,
        name,
        entry,
        state: ProcessState::Runnable,
        slot: slot_index,
        addr_space: None,
        privileged: false,
        entry_point: None,
        user_stack_top: None,
        started: true,
    });

    pid
}

pub fn spawn_user(entry: ThreadEntry, name: &'static str) -> ProcessId {
    // 恢复真实实现：console shell 是编译进内核的"内核内进程"，
    // 以函数指针为入口（与 ServiceEntry::KernelFn 同类）。
    // 注意：入口位于内核镜像内，进程以 EL0 运行，首次取指会因
    // 内核页表 AP=00（EL0 无权限）触发 instruction abort 而被终止
    // ——用户态异常路径的修复属于后续工作。
    crate::debug!("process::spawn_user called for name={}", name);
    spawn(entry, name)
}

pub fn spawn_user_from_bootfs(
    path: &str,
    name: &'static str,
    privileged: bool,
) -> Result<ProcessId, ProcessError> {
    crate::debug!("spawn_user_from_bootfs: path={}", path);
    let elf = user_elf::build_user_elf(path).map_err(ProcessError::ElfError)?;
    let pid = spawn(thread_exit, name);
    let Some(slot) = slot_for_pid(pid) else {
        return Err(ProcessError::NoSuchProcess);
    };

    let result = unsafe {
        let mut space = AddressSpace::new();
        map_user_elf_segments(&mut space, &elf, path).map_err(ProcessError::MapError)?;
        space
            .map_stack(USER_STACK_TOP, USER_STACK_LEN)
            .map_err(ProcessError::MapError)?;
        let bootfs_info =
            rootfs::build_user_bootfs_for_process(&mut space, rootfs::USER_BOOTFS_BASE)
                .map_err(ProcessError::MapError)?;
        let root_phys = space.ttbr0_phys();
        configure_user_process(slot, space, elf.entry as usize, USER_STACK_TOP);
        set_initial_user_args(
            slot,
            [bootfs_info.entries_ptr, bootfs_info.entries_len, 0, 0],
        );
        crate::debug!(
            "[aspace] pid={} slot={} path={} root_phys={:#x} entry={:#x}",
            pid.raw(),
            slot,
            path,
            root_phys,
            elf.entry as usize
        );
        let tf = TRAP_FRAMES[slot].get();
        (*tf).elr_el1 = elf.entry;
        (*tf).sp_el0 = USER_STACK_TOP as u64;
        Ok(())
    };

    if let Err(err) = result {
        remove_slot(slot);
        return Err(err);
    }

    if privileged {
        set_privileged(pid, true);
    }
    Ok(pid)
}

pub fn set_privileged(pid: ProcessId, privileged: bool) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = table
        .iter_mut()
        .filter_map(|slot| slot.as_mut())
        .find(|record| record.pid == pid)
    {
        record.privileged = privileged;
    }
}

pub fn is_slot_privileged(slot: usize) -> bool {
    let table = PROCESS_TABLE.lock();
    table
        .get(slot)
        .and_then(|entry| entry.as_ref())
        .map(|record| record.privileged)
        .unwrap_or(false)
}

pub fn slot_for_pid(pid: ProcessId) -> Option<usize> {
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter_map(|slot| slot.as_ref())
        .find(|record| record.pid == pid)
        .map(|record| record.slot)
}

pub fn set_state(pid: ProcessId, state: ProcessState) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = table
        .iter_mut()
        .filter_map(|slot| slot.as_mut())
        .find(|record| record.pid == pid)
    {
        record.state = state;
    }
}

pub fn set_state_slot(slot: usize, state: ProcessState) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = &mut table[slot] {
        record.state = state;
    }
}

pub fn state(pid: ProcessId) -> Option<ProcessState> {
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter_map(|slot| slot.as_ref())
        .find(|record| record.pid == pid)
        .map(|record| record.state)
}

pub unsafe fn trap_frame(slot: usize) -> *mut TrapFrame {
    TRAP_FRAMES[slot].get()
}

pub type Context = TrapFrame;

pub unsafe fn context_ptr(slot: usize) -> *mut Context {
    trap_frame(slot)
}

pub unsafe fn kernel_stack_top(slot: usize) -> usize {
    kernel_stack_top_raw(slot)
}

/// 内核栈顶的**存储位置**（trap_entry 用它一条指令装载 SP）。
/// 每槽一个 usize 单元，process::init 时写入一次，之后 trap_entry 只读。
/// 单核 + 初始化后只读 ⇒ 裸 UnsafeCell 的安全性由使用纪律保证
/// （与 TRAP_FRAMES/KERNEL_STACKS 同一信任级别）。
pub struct StackTopCell(UnsafeCell<usize>);
impl StackTopCell {
    const fn new() -> Self {
        Self(UnsafeCell::new(0))
    }
}
unsafe impl Sync for StackTopCell {}

static KERNEL_STACK_TOPS: [StackTopCell; MAX_PROCESSES] =
    [const { StackTopCell::new() }; MAX_PROCESSES];

pub unsafe fn kernel_stack_top_ptr(slot: usize) -> *mut usize {
    KERNEL_STACK_TOPS[slot].0.get()
}

/// 在 process::init 里为每槽预计算并缓存栈顶地址。
fn init_kernel_stack_tops() {
    for slot in 0..MAX_PROCESSES {
        unsafe {
            *KERNEL_STACK_TOPS[slot].0.get() = kernel_stack_top_raw(slot);
        }
    }
}

pub unsafe fn user_stack_top(slot: usize) -> usize {
    user_stack_top_raw(slot)
}

/// ⚠ 设计局限（本轮不改契约）：user_stack_top_raw 忽略 slot，
/// 所有进程共用同一个用户栈顶 USER_STACK_TOP（0x0000_FFFF_F000）。
/// shell ABI（含 fork 的栈重定位计算）依赖"栈顶与槽位无关"这一假设，
/// 因此本轮保留。未来方向：per-slot 栈顶（每个进程私有 128KiB 栈窗口）
/// 需同步修改 fork() 的栈基重算、exec 的栈重置与 user_shell ABI，
/// 属于破坏性变更，应单独一轮做并配套升级。
fn user_stack_top_raw(slot: usize) -> usize {
    let _ = slot;
    USER_STACK_TOP
}

fn kernel_stack_top_raw(slot: usize) -> usize {
    unsafe { KERNEL_STACKS[slot].as_ptr().add(KERNEL_STACK_SIZE) as usize }
}

pub fn pid_at_slot(slot: usize) -> Option<ProcessId> {
    let table = PROCESS_TABLE.lock();
    table[slot].map(|record| record.pid)
}

/// 回收进程槽位：从 PROCESS_TABLE 移除记录（含 pid/name 审计）、
/// 释放地址空间（页表回收，见下方协调点）、清 CURRENT_SLOT（若指向该槽）。
///
/// 📌 协调点（mm Agent）：地址空间销毁由 `mm::address_space` 提供——
/// 现经 `AddressSpace::destroy()` → `paging::destroy_user_address_space()`
/// 桥接，本轮 mm Agent 负责落地该函数的实现（当前为空占位）。
/// 销毁必须发生在 PROCESS_TABLE 锁外：记录是 Copy，take() 后 Guard
/// 立即释放。将来若 mm Agent 直接暴露同名自由函数
/// `mm::address_space::destroy_user_address_space(&AddressSpace)`，
/// 把 `space.destroy()` 换成对其的直接调用即可（桥接在销毁逻辑落定后
/// 属于冗余层）。
///
/// TRAP_FRAMES/KERNEL_STACKS 是 64×16KiB 静态数组，槽位回用即可，
/// 无需释放。
pub fn remove_slot(slot: usize) {
    assert!(slot < MAX_PROCESSES, "remove_slot: slot {} out of range", slot);
    let record = {
        let mut table = PROCESS_TABLE.lock();
        table[slot].take()
    };

    if let Some(record) = record {
        if let Some(space) = record.addr_space {
            // 锁外销毁：避免持进程表锁进入物理页分配器
            //（表锁→分配器锁的反转风险，见 scheduler.rs 锁纪律第 3 条）。
            unsafe {
                space.destroy();
            }
        }
        crate::warn!(
            "process {} (pid={} slot={}) removed: slot reclaimed",
            record.name,
            record.pid.raw(),
            slot
        );
    } else {
        crate::debug!("process::remove_slot: slot={} already empty", slot);
    }

    // 自退出场景：CURRENT_SLOT 仍指向本槽，先清掉，免得调度器把已回收
    // 槽当作"上一个进程"置回 Runnable。
    crate::scheduler::clear_current_slot_if(slot);
}

pub fn address_space(slot: usize) -> Option<AddressSpace> {
    let table = PROCESS_TABLE.lock();
    let out = table[slot].and_then(|record| record.addr_space);
    if let Some(s) = out {
        crate::debug!("process::address_space: slot={} root=0x{:x}", slot, s.ttbr0_phys());
    }
    out
}

#[allow(dead_code)]
pub fn set_address_space(slot: usize, space: AddressSpace) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = &mut table[slot] {
        record.addr_space = Some(space);
    }
}

fn configure_user_process(slot: usize, space: AddressSpace, entry: usize, user_sp: usize) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = &mut table[slot] {
        record.addr_space = Some(space);
        record.entry_point = Some(entry);
        record.user_stack_top = Some(user_sp);
        record.started = false;
    }
}

pub fn first_run_context(slot: usize) -> Option<(AddressSpace, *mut TrapFrame)> {
    let mut table = PROCESS_TABLE.lock();
    let record = table.get_mut(slot)?.as_mut()?;
    if record.started {
        return None;
    }
    if let (Some(space), Some(entry), Some(stack)) =
        (record.addr_space, record.entry_point, record.user_stack_top)
    {
        record.started = true;
        let tf = unsafe { TRAP_FRAMES[slot].get() };
        Some((space, tf))
    } else {
        None
    }
}

#[no_mangle]
extern "C" fn thread_exit() -> ! {
    // 进程主函数返回（LR=thread_exit）后的收尾 trampoline：
    // 标记 Dying → 走调度器退出路径（remove_slot + reschedule），
    // 槽位与地址空间在此回收。
    //
    // 说明：若该 trampoline 在 EL0 下被取指（内核区 AP 对 EL0 关闭），
    // 会先触发 instruction abort → 异常路径同样以 Dying + exit_current
    // 终止并回收；两个入口殊途同归，不会再有"死循环占槽"。
    let slot = crate::scheduler::current_slot();
    if let Some(pid) = pid_at_slot(slot) {
        crate::warn!("thread_exit: pid={} slot={} exiting (user main returned)", pid.raw(), slot);
    }
    set_state_slot(slot, ProcessState::Dying);
    crate::scheduler::exit_current()
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn set_initial_user_args(slot: usize, args: [u64; 4]) {
    unsafe {
        let tf = TRAP_FRAMES[slot].get();
        (*tf).regs[0] = args[0];
        (*tf).regs[1] = args[1];
        (*tf).regs[2] = args[2];
        (*tf).regs[3] = args[3];
    }
}

fn map_user_elf_segments(
    space: &mut AddressSpace,
    elf: &user_elf::UserElf,
    path: &str,
) -> Result<(), MapError> {
    let elf_bytes = rootfs::read_file(path).ok_or(MapError::OutOfMemory)?;
    crate::debug!("map_user_elf_segments: root_phys=0x{:x} path={}", space.ttbr0_phys(), path);
    for seg in elf.segments.iter() {
        if seg.memsz == 0 {
            continue;
        }
        crate::debug!(
            "map_user_elf_segments: vbase=0x{:x} mem_size=0x{:x} file_size=0x{:x}",
            seg.vaddr,
            seg.memsz,
            seg.filesz
        );
        let seg_start = seg.vaddr as usize;
        let seg_end = seg_start + seg.memsz as usize;
        let page_start = seg_start & !(PAGE_SIZE - 1);
        let page_end = align_up(seg_end, PAGE_SIZE);
        let mut writable = (seg.flags & PF_W) != 0;
        let executable = (seg.flags & PF_X) != 0;
        // 纵深防御：memsz > filesz ⇒ 段内含 .bss（NOLOAD 尾部），运行期
        // 必然要写。即便链接脚本漏标 PF_W（lld 在无 PHDRS 声明时会把
        // 纯 .bss 段标成只读，实机已踩），这里也强制补上写权限——
        // 宁可多给一页 W，也不能让用户进程在清零自己的 bss 时崩死。
        if seg.memsz > seg.filesz {
            writable = true;
        }
        let data_len = seg.filesz as usize;

        for page_va in (page_start..page_end).step_by(PAGE_SIZE) {
            let phys = phys::alloc_page().ok_or(MapError::OutOfMemory)?;
            crate::debug!(
                "map_user_elf_segments: page_va=0x{:x} phys=0x{:x}",
                page_va,
                phys
            );

            let page_first = page_va;
            let page_last = page_va + PAGE_SIZE;
            let copy_start = cmp::max(seg_start, page_first);
            let copy_end = cmp::min(seg_start + data_len, page_last);
            // 恒等映射下物理页可直接读写，无需临时映射。
            unsafe {
                let kptr = phys as *mut u8;
                core::ptr::write_bytes(kptr, 0, PAGE_SIZE);
                if copy_start < copy_end {
                    let src_off = copy_start - seg_start;
                    let dst_off = copy_start - page_first;
                    let len = copy_end - copy_start;
                    core::ptr::copy_nonoverlapping(
                        elf_bytes.as_ptr().add(seg.offset as usize + src_off),
                        kptr.add(dst_off),
                        len,
                    );
                }
            }
            unsafe {
                space.map_page_phys(page_va, phys, writable, executable)?;
            }
        }
    }
    Ok(())
}

pub fn fork(
    parent_slot: usize,
    parent_frame: &TrapFrame,
) -> Result<(ProcessId, usize), ProcessError> {
    let parent_record = {
        let table = PROCESS_TABLE.lock();
        table
            .get(parent_slot)
            .and_then(|entry| *entry)
            .ok_or(ProcessError::NoSuchProcess)?
    };

    let child_slot;
    let child_pid = ProcessId::new(NEXT_PID.fetch_add(1, Ordering::SeqCst));

    // 地址空间克隆必须在持锁外进行（分配物理页/可能失败），
    // 且 clone_space 当前显式失败（见 address_space.rs 注释）。
    let addr_space = if let Some(space) = parent_record.addr_space {
        let cloned = address_space::clone_space(&space).map_err(ProcessError::MapError)?;
        Some(cloned)
    } else {
        None
    };

    {
        let mut table = PROCESS_TABLE.lock();
        let (slot_index, slot) = table
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
            .ok_or(ProcessError::TableFull)?;
        child_slot = slot_index;

        *slot = Some(ProcessRecord {
            pid: child_pid,
            name: parent_record.name,
            entry: parent_record.entry,
            state: ProcessState::Runnable,
            slot: child_slot,
            addr_space,
            privileged: parent_record.privileged,
            entry_point: parent_record.entry_point,
            user_stack_top: parent_record.user_stack_top,
            started: true,
        });
    }

    unsafe {
        let child_tf = TRAP_FRAMES[child_slot].get();
        *child_tf = *parent_frame;
        // Reset return value for child
        (*child_tf).regs[0] = 0;

        // Rebase user stack pointer relative to new stack top
        let parent_top = user_stack_top_raw(parent_slot);
        let child_top = user_stack_top_raw(child_slot);
        let parent_sp = parent_frame.sp_el0 as usize;
        let used = parent_top.saturating_sub(parent_sp);
        (*child_tf).sp_el0 = child_top.saturating_sub(used) as u64;

        // Reset kernel stack pointer
        (*child_tf).sp_el1 = kernel_stack_top_raw(child_slot) as u64;

        // Clear kernel stack for determinism
        core::ptr::write_bytes(KERNEL_STACKS[child_slot].as_ptr(), 0, KERNEL_STACK_SIZE);
    }

    Ok((child_pid, child_slot))
}

pub unsafe fn exec(
    slot: usize,
    entry: ThreadEntry,
    arg: u64,
    frame: &mut TrapFrame,
) -> Result<(), ProcessError> {
    if entry as usize == 0 {
        return Err(ProcessError::InvalidArgument);
    }
    {
        let mut table = PROCESS_TABLE.lock();
        let record = table
            .get_mut(slot)
            .and_then(|slot| slot.as_mut())
            .ok_or(ProcessError::NoSuchProcess)?;
        record.entry = entry;
    }

    frame.regs = [0; 31];
    frame.regs[0] = arg;
    frame.regs[30] = thread_exit as usize as u64;
    frame.sp_el0 = user_stack_top_raw(slot) as u64;
    frame.sp_el1 = kernel_stack_top_raw(slot) as u64;
    frame.elr_el1 = entry as usize as u64;
    frame.spsr_el1 = 0;
    Ok(())
}
