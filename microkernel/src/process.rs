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
use zero_abi::syscall::SysError;
use zero_abi::{ProcessId, ThreadEntry};

const MAX_PROCESSES: usize = 64;
/// 内核栈 64KiB（×64 槽 = 4MiB 静态区）：对照 Linux THREAD_SIZE 16K/
/// XNU kernel_stack 16K——我们无中断栈分离，所有 EL1 工作（含 IPC 拷贝、
/// 页表操作）都在本栈，取 4 倍余量防深层调用链溢出。
const KERNEL_STACK_SIZE: usize = 0x1_0000;
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
    /// 已退出、退出码待父进程收集（POSIX zombie）。record 保留
    /// （父可查 exit_code），但地址空间与全部用户物理页在转入本态
    /// 时**当场释放**——尸体只占一个表槽，不占内存。调度器永远不会
    /// 调度本态进程（不入就绪队列；dispatch 换出逻辑视其非 Running
    /// 而不会“复活”它），等待父 WaitPid 收割或随父死亡级联回收。
    Zombie,
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
    /// 挂起的阻塞接收（通道号）：进程在阻塞中被唤醒后，由 dispatch 在
    /// 重入用户态前完成该系统调用的收尾（continuation 语义，对照 XNU）。
    pending_recv: Option<u32>,
    /// 父进程 pid：仅 Fork 出的子进程持有（内核直接 spawn 的根进程为
    /// None ⇒ 其退出走“无存活父”路径，立即完全回收，见文件尾部
    /// zombie/waitpid 状态机的设计注释）。
    parent: Option<ProcessId>,
    /// 退出码：Exit 系统调用记录；Zombie 态期间由父经 WaitPid 读走。
    exit_code: Option<i32>,
    /// 挂起的 WaitPid：父在“无可收子但有活子”时置位并阻塞；子 Exit
    /// 在同一表锁临界区内发现置位 ⇒ 取走标记并把编码好的返回值直接
    /// 写进父 TrapFrame 的 x0（零侵入 continuation，见设计注释）。
    pending_wait: bool,
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
        pending_recv: None,
        parent: None, // 内核直生的根进程：无父，退出即完全回收
        exit_code: None,
        pending_wait: false,
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

/// 设置/取走挂起的阻塞接收（continuation 机制，见 ProcessRecord 注释）。
pub fn set_pending_recv(slot: usize, chan: u32) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = &mut table[slot] {
        record.pending_recv = Some(chan);
    }
}

/// 取走挂起标记（dispatch 在重入用户态前调用一次）。
pub fn take_pending_recv(slot: usize) -> Option<u32> {
    let mut table = PROCESS_TABLE.lock();
    table.get_mut(slot).and_then(|record| record.as_mut()).and_then(|record| record.pending_recv.take())
}

/// 按槽位读状态（scheduler 的 dispatch 状态保护用）。
pub fn state_slot(slot: usize) -> Option<ProcessState> {
    let table = PROCESS_TABLE.lock();
    table.get(slot).and_then(|entry| entry.as_ref()).map(|record| record.state)
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

// ═══════════════════════════════════════════════════════════════════════
// 进程退出与回收：POSIX 风格 zombie / WaitPid（对标 Linux do_exit + wait4）
//
// 状态机（本轮冻结的最小完备集）：
//
//   Running/Runnable ──Exit(status)──▶ 有存活父？
//     ├─ 是 ──▶ Zombie：record 保留（pid/name/exit_code 可被父查询），
//     │         addr_space 与全部用户物理页**当场释放**——尸体不占内存，
//     │         只占一个表槽；不入就绪队列（从调度器消失）。
//     └─ 否（无父 / 父已死 / 父本身已僵）──▶ 完全回收：记录摘除 +
//               地址空间销毁（锁外）+ 孤儿级联（见 full_reap）。
//   Zombie ──父 WaitPid──▶ 完全回收，返回 (pid<<32)|exit_code。
//
// 【孤儿策略】（任务给定二选一：选“立即回收”，不重定向给初始进程）
//   父先死时：活子就地 parent=None（成为孤儿），此后它退出时因
//   “无存活父”直接完全回收；死者名下若已有 Zombie 尸体，随父死亡
//   **级联回收**（full_reap 的显式栈迭代，非递归）。
//   理由：本内核没有 init 常驻收割循环，把孤儿 parent 重定向给初始
//   进程只会让尸体挂在无人认领的槽位上直到表满（fork 泄漏）；
//   “死亡即级联清理 + 孤儿自灭”与 Linux 中 init 收割孤儿的最终效果
//   等价（资源必然释放），却不需要任何守护进程与族谱 reparent。
//
// 【挂起恢复 = 零侵入 continuation】（对照 pending_recv 模式，选最小
//   侵入方案：平行的 pending_wait 单标记，不改 scheduler.rs/trap.rs）
//   父 WaitPid 无可收子但有活子 ⇒ 同一表锁临界区内完成「扫描 + 置
//   pending_wait」（登记→阻塞原子；单核 + EL1 关中断 ⇒ 无丢失唤醒
//   窗口）⇒ block_current()。子 Exit 在锁内发现父 pending_wait 置位
//   ⇒ 取走标记，把编码好的返回值**直接写进父 TrapFrame 的 x0**，再
//   wake(父)。结果先于唤醒写入帧 ⇒ 父被 dispatch 恢复现场时 x0 已是
//   最终返回值——dispatch 无需任何 pending_wait 分支（scheduler.rs 本
//   轮只读的关键设计约束）。即使假想虚假唤醒，帧内也是正确结果。
//
// 【锁纪律】（照 scheduler.rs 头部）：表锁只在“决策 + 摘除/改字段”的
//   语句块内持有；AddressSpace::destroy 一律锁外执行（第 3 条）；
//   临界区内零堆分配——扫描视图用栈上定长数组（第 4 条）；
//   任何 Guard 不得活过 noreturn 调用（block/reschedule 前 drop）（第 1 条）。
// ═══════════════════════════════════════════════════════════════════════

/// WaitPid 返回值打包：(pid << 32) | (code as u32)。userlib::wait_pid
/// 以对称方式解包（负码按 32 位补码无损还原）。
pub(crate) fn pack_wait_result(pid: ProcessId, code: i32) -> u64 {
    (pid.raw() << 32) | (code as u32 as u64)
}

/// 退出处置决策（纯函数，主机单测覆盖）。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExitDisposition {
    /// 有存活父：转 Zombie 留尸待收。
    BecomeZombie,
    /// 无父 / 父已死 / 父已僵：立即完全回收。
    ReapImmediately,
}

pub(crate) fn exit_disposition(
    parent: Option<ProcessId>,
    parent_alive: bool,
) -> ExitDisposition {
    match parent {
        Some(_) if parent_alive => ExitDisposition::BecomeZombie,
        _ => ExitDisposition::ReapImmediately,
    }
}

/// 进程表行的只读快照：纯决策层的输入。运行时在表锁内以栈上定长数组
/// 构建（零堆分配）；主机测试直接手工构造——模型与实现共用同一函数，
/// 杜绝漂移。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcView {
    pub slot: usize,
    pub pid: ProcessId,
    pub parent: Option<ProcessId>,
    pub state: ProcessState,
    pub exit_code: Option<i32>,
}

/// WaitPid 扫描决策（纯函数）。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum WaitDecision {
    /// 发现可收尸：携带 (槽位, 子 pid, 退出码)。
    Collect { slot: usize, pid: ProcessId, code: i32 },
    /// 有匹配的活子未退：挂起等待。
    Block,
    /// 没有任何匹配子进程（含“早已收过”的重复 wait）：ECHILD。
    NoChild,
}

/// target=0 收任意子的僵尸（僵尸优先于活子，POSIX wait 语义）；
/// target≠0 只看该 pid。不变量：Zombie 必有 exit_code（zombify 时
/// 写入），异常行防御式跳过。
pub(crate) fn wait_scan(
    caller: ProcessId,
    target: u64,
    procs: &[Option<ProcView>],
) -> WaitDecision {
    let mut has_live_child = false;
    for view in procs.iter().flatten() {
        if view.parent != Some(caller) {
            continue;
        }
        if target != 0 && view.pid.raw() != target {
            continue;
        }
        if view.state == ProcessState::Zombie {
            if let Some(code) = view.exit_code {
                return WaitDecision::Collect {
                    slot: view.slot,
                    pid: view.pid,
                    code,
                };
            }
            continue;
        }
        has_live_child = true;
    }
    if has_live_child {
        WaitDecision::Block
    } else {
        WaitDecision::NoChild
    }
}

/// 完全回收 dying 时其子女的处置（纯函数）。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum OrphanAction {
    /// 子已是 Zombie 尸体：随父死亡级联回收。
    CascadeReap,
    /// 子还活着：摘除父链（parent=None）成为孤儿，此后自灭。
    Detach,
    /// 与死者无关。
    Ignore,
}

pub(crate) fn orphan_action(
    parent: Option<ProcessId>,
    state: ProcessState,
    dying: ProcessId,
) -> OrphanAction {
    match parent {
        Some(p) if p == dying => {
            if state == ProcessState::Zombie {
                OrphanAction::CascadeReap
            } else {
                OrphanAction::Detach
            }
        }
        _ => OrphanAction::Ignore,
    }
}

/// 完全回收 seed 槽，并级联处理其 Zombie 后代（显式栈迭代，非递归）。
/// 锁外销毁地址空间；全程零堆分配。槽已空则幂等跳过。
fn full_reap(seed: usize) {
    let mut stack = [0usize; MAX_PROCESSES];
    let mut top = 0usize;
    stack[top] = seed;
    top += 1;

    while top > 0 {
        top -= 1;
        let s = stack[top];
        // 锁内：摘除记录 + 决定子女去向（纯快照操作，无分配/打印）。
        let grabbed = {
            let mut table = PROCESS_TABLE.lock();
            match table[s].take() {
                None => None, // 并发已回收：幂等
                Some(record) => {
                    let dying = record.pid;
                    let mut casc_pids = [0u64; MAX_PROCESSES];
                    let mut casc_slots = [0usize; MAX_PROCESSES];
                    let mut casc_spaces: [Option<AddressSpace>; MAX_PROCESSES] =
                        [const { None }; MAX_PROCESSES];
                    let mut n = 0usize;
                    for (i, entry) in table.iter_mut().enumerate() {
                        let Some(rec) = entry.as_mut() else { continue };
                        match orphan_action(rec.parent, rec.state, dying) {
                            OrphanAction::CascadeReap => {
                                casc_pids[n] = rec.pid.raw();
                                casc_slots[n] = i;
                                casc_spaces[n] = rec.addr_space.take();
                                n += 1;
                                *entry = None;
                            }
                            OrphanAction::Detach => {
                                crate::warn!(
                                    "process {} (pid={}) orphaned: parent {} died",
                                    rec.name,
                                    rec.pid.raw(),
                                    dying.raw()
                                );
                                rec.parent = None;
                            }
                            OrphanAction::Ignore => {}
                        }
                    }
                    Some((record, casc_pids, casc_slots, casc_spaces, n))
                }
            }
        }; // 表锁已释放（记录是 Copy，take 后 Guard 立即结束）

        let Some((record, casc_pids, casc_slots, casc_spaces, n)) = grabbed else {
            continue;
        };
        if let Some(space) = record.addr_space {
            // 锁外销毁：避免持进程表锁进入物理页分配器
            //（表锁→分配器锁反转风险，scheduler.rs 锁纪律第 3 条）。
            unsafe {
                space.destroy();
            }
        }
        crate::warn!(
            "process {} (pid={} slot={}) fully reaped: slot reclaimed",
            record.name,
            record.pid.raw(),
            s
        );
        for k in 0..n {
            // 防御：级联对象是 Zombie，addr_space 正常已在 zombify 时清空。
            if let Some(space) = casc_spaces[k] {
                unsafe {
                    space.destroy();
                }
            }
            crate::warn!(
                "cascade reap: zombie pid={} slot={} (parent died)",
                casc_pids[k],
                casc_slots[k]
            );
            if top < MAX_PROCESSES {
                stack[top] = casc_slots[k];
                top += 1;
            }
        }
    }

    // 自退出场景：CURRENT_SLOT 可能仍指向本槽（svc#2 路径），先清掉，
    // 免得调度器把已回收槽当作"上一个进程"置回 Runnable。
    crate::scheduler::clear_current_slot_if(seed);
}

/// 回收进程槽位（遗留入口，签名不变）：委托 full_reap，自动获得
/// 孤儿级联处理。仍有两个调用方：trap.rs 的 svc#2 快捷退出
/// （语义 = 不留尸体的即时销毁，退出码不可收集，历史兼容）与
/// spawn_user_from_bootfs 的引导期失败路径。
///
/// 📌 协调点（mm Agent，历史注释保留）：地址空间销毁经
/// `AddressSpace::destroy()` → `paging::destroy_user_address_space()`
/// 桥接，销毁必须发生在 PROCESS_TABLE 锁外（full_reap 已遵守）。
/// TRAP_FRAMES/KERNEL_STACKS 是 64×16KiB 静态数组，槽位回用即可。
pub fn remove_slot(slot: usize) {
    assert!(slot < MAX_PROCESSES, "remove_slot: slot {} out of range", slot);
    full_reap(slot);
}

/// 当前进程带状态码退出——Exit 系统调用（号位 5）与 thread_exit
/// trampoline 的统一入口。按头部状态机决定 Zombie 或立即回收，
/// 最后 reschedule()（noreturn，绝不回到调用方）。
pub fn exit_current_with_status(status: i32) -> ! {
    let slot = crate::scheduler::current_slot();

    // —— 单一临界区：定处置 / 写 exit_code / 摘 addr_space / 取走父等待标记 ——
    struct ZombiePlan {
        wake_parent: Option<(usize, ProcessId)>,
        packed: u64,
        space: Option<AddressSpace>,
    }
    enum Plan {
        Zombie(ZombiePlan),
        ReapNow,
    }
    let plan = {
        let mut table = PROCESS_TABLE.lock();
        // —— 阶段 1（共享读）：自身/父视图快照。借用随后结束，给阶段 2 的
        //    可变改写让路（同函数内两段式，仍属同一临界区）。
        let Some(me_read) = table[slot].as_ref() else {
            // 记录已被并发回收（理论不可达，防御）：直接让出。
            drop(table);
            crate::scheduler::reschedule() // -> !，let-else 发散收尾
        };
        let my_pid = me_read.pid;
        let parent = me_read.parent;
        let parent_view: Option<ProcView> = parent.and_then(|pp| {
            table.iter().enumerate().find_map(|(i, e)| {
                let r = e.as_ref()?;
                (r.pid == pp).then_some(ProcView {
                    slot: i,
                    pid: r.pid,
                    parent: r.parent,
                    state: r.state,
                    exit_code: r.exit_code,
                })
            })
        });
        // “存活”= 表中在册且非 Zombie（Dying 是过渡态：其随后的
        // remove_slot/full_reap 会级联处理本尸，两条路都收敛）。
        let parent_alive = matches!(parent_view, Some(pv) if pv.state != ProcessState::Zombie);

        // —— 阶段 2（独占写）：定处置 / 写退出码 / 转 Zombie / 取走父等待标记 ——
        match exit_disposition(parent, parent_alive) {
            ExitDisposition::BecomeZombie => {
                // 单核 + 表锁内：刚才读到的记录必然仍在（不可能被并发移除）。
                let me = table[slot].as_mut().expect("record vanished under lock");
                me.exit_code = Some(status);
                me.state = ProcessState::Zombie;
                let space = me.addr_space.take(); // 用户页/页表此刻归还
                let wake_parent = parent_view.and_then(|pv| {
                    let marked = table[pv.slot]
                        .as_mut()
                        .map(|r| core::mem::replace(&mut r.pending_wait, false))
                        .unwrap_or(false);
                    marked.then_some((pv.slot, pv.pid))
                });
                Plan::Zombie(ZombiePlan {
                    wake_parent,
                    packed: pack_wait_result(my_pid, status),
                    space,
                })
            }
            ExitDisposition::ReapImmediately => {
                if let Some(me) = table[slot].as_mut() {
                    me.exit_code = Some(status); // 审计留痕（随后随记录销毁）
                }
                Plan::ReapNow
            }
        }
    }; // 表锁已释放（Guard 不跨 noreturn，锁纪律第 1 条）

    match plan {
        Plan::Zombie(zp) => {
            if let Some(space) = zp.space {
                unsafe {
                    space.destroy(); // 锁外销毁（纪律第 3 条）
                }
            }
            crate::info!(
                "process slot={} became zombie (status={}, waiter={:?})",
                slot,
                status,
                zp.wake_parent.map(|(_, p)| p.raw())
            );
            if let Some((parent_slot, parent_pid)) = zp.wake_parent {
                // 结果先写进父 TrapFrame 再唤醒：父被 dispatch 恢复现场时
                // x0 已是最终返回值，无需 dispatch 侧任何改动。单核 +
                // 父处于 Blocked ⇒ 写帧无竞争。
                unsafe {
                    (*TRAP_FRAMES[parent_slot].get()).regs[0] =
                        crate::trap::encode_result(Ok(zp.packed));
                }
                crate::scheduler::wake(parent_pid);
            }
        }
        Plan::ReapNow => full_reap(slot),
    }

    crate::scheduler::reschedule()
}

/// WaitPid 系统调用（号位 22）的核心步：原子「扫描 + 登记等待」后，
/// 由 syscalls.rs 决定返回还是阻塞。
pub enum WaitStep {
    /// 已收尸并完全回收：携带编码好的返回值（见 pack_wait_result）。
    Completed(u64),
    /// 有活子未退：调用方应立即 block_current()（pending_wait 已置位）。
    Blocked,
}

pub fn waitpid_step(target_pid: u64) -> Result<WaitStep, SysError> {
    let caller_slot = crate::scheduler::current_slot();

    enum Act {
        Collect { packed: u64, space: Option<AddressSpace> },
        Block,
    }
    let act = {
        let mut table = PROCESS_TABLE.lock();
        let Some(me) = table[caller_slot] else {
            return Err(SysError::PermissionDenied);
        };
        // 栈上快照：临界区内零堆分配（锁纪律第 4 条）。
        let mut views: [Option<ProcView>; MAX_PROCESSES] = [const { None }; MAX_PROCESSES];
        for (i, entry) in table.iter().enumerate() {
            views[i] = entry.map(|r| ProcView {
                slot: i,
                pid: r.pid,
                parent: r.parent,
                state: r.state,
                exit_code: r.exit_code,
            });
        }
        match wait_scan(me.pid, target_pid, &views) {
            WaitDecision::Collect { slot, pid, code } => {
                // 摘除尸体记录。不变量：addr_space 已在 zombify 时清空，
                // 此处防御式带出以防万一。
                let record = table[slot].take().ok_or(SysError::NotFound)?;
                Act::Collect {
                    packed: pack_wait_result(pid, code),
                    space: record.addr_space,
                }
            }
            WaitDecision::Block => {
                if let Some(me) = table[caller_slot].as_mut() {
                    me.pending_wait = true;
                }
                Act::Block
            }
            WaitDecision::NoChild => return Err(SysError::NotFound), // ECHILD
        }
    }; // 表锁已释放

    match act {
        Act::Collect { packed, space } => {
            if let Some(space) = space {
                unsafe {
                    space.destroy(); // 锁外（纪律第 3 条）
                }
            }
            crate::info!("waitpid: collected & fully reaped -> {:#x}", packed);
            Ok(WaitStep::Completed(packed))
        }
        Act::Block => Ok(WaitStep::Blocked),
    }
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
    // entry/stack 仅作就绪校验（真实值已在 TrapFrame 内，由 enter_user_mode 恢复）。
    if let (Some(space), Some(_entry), Some(_stack)) =
        (record.addr_space, record.entry_point, record.user_stack_top)
    {
        record.started = true;
        let tf = TRAP_FRAMES[slot].get();
        Some((space, tf))
    } else {
        None
    }
}

#[no_mangle]
extern "C" fn thread_exit() -> ! {
    // 进程主函数返回（LR=thread_exit）后的收尾 trampoline：
    // POSIX 语义 main 正常返回 = exit(0) ⇒ 走 zombie/waitpid 状态机
    // （exit_current_with_status）：有存活父则留尸可收集，否则即时回收。
    //
    // 说明：若该 trampoline 在 EL0 下被取指（内核区 AP 对 EL0 关闭），
    // 会先触发 instruction abort → 异常路径同样以 Dying + exit_current
    // 终止并回收；两个入口殊途同归，不会再有"死循环占槽"。
    let slot = crate::scheduler::current_slot();
    if let Some(pid) = pid_at_slot(slot) {
        crate::warn!("thread_exit: pid={} slot={} exiting (user main returned)", pid.raw(), slot);
    }
    exit_current_with_status(0)
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
            pending_recv: None,
            // 族谱：Fork 是唯一产生父子关系的入口（POSIX fork 对齐）。
            parent: Some(parent_record.pid),
            exit_code: None,
            pending_wait: false,
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

#[cfg(test)]
mod state_machine_tests {
    use super::*;

    /// 手工构造一行表快照。
    fn pv(
        slot: usize,
        pid_raw: u64,
        parent: Option<u64>,
        state: ProcessState,
        code: Option<i32>,
    ) -> Option<ProcView> {
        Some(ProcView {
            slot,
            pid: ProcessId::new(pid_raw),
            parent: parent.map(ProcessId::new),
            state,
            exit_code: code,
        })
    }

    fn table_of(entries: &[Option<ProcView>]) -> [Option<ProcView>; MAX_PROCESSES] {
        let mut t = [const { None }; MAX_PROCESSES];
        for (i, e) in entries.iter().enumerate() {
            t[i] = *e;
        }
        t
    }

    const P: u64 = 10; // 观察者（调用 wait 的父）
    fn caller() -> ProcessId {
        ProcessId::new(P)
    }

    #[test]
    fn exit_becomes_zombie_only_with_live_parent() {
        assert_eq!(
            exit_disposition(Some(ProcessId::new(9)), true),
            ExitDisposition::BecomeZombie
        );
        // 无父 / 父已死 / 父已僵 → 立即完全回收
        assert_eq!(exit_disposition(None, false), ExitDisposition::ReapImmediately);
        assert_eq!(
            exit_disposition(Some(ProcessId::new(9)), false),
            ExitDisposition::ReapImmediately
        );
    }

    #[test]
    fn wait_scan_collects_zombie_any_target() {
        let t = table_of(&[
            pv(0, P, None, ProcessState::Running, None),
            pv(1, 11, Some(P), ProcessState::Zombie, Some(42)),
            // 别人家的僵尸不得干扰
            pv(2, 12, Some(99), ProcessState::Zombie, Some(7)),
        ]);
        assert_eq!(
            wait_scan(caller(), 0, &t),
            WaitDecision::Collect { slot: 1, pid: ProcessId::new(11), code: 42 }
        );
        assert_eq!(
            wait_scan(caller(), 11, &t),
            WaitDecision::Collect { slot: 1, pid: ProcessId::new(11), code: 42 }
        );
    }

    #[test]
    fn wait_scan_blocks_on_live_child_only() {
        let t = table_of(&[
            pv(0, P, None, ProcessState::Running, None),
            pv(1, 11, Some(P), ProcessState::Running, None),
            pv(2, 12, Some(P), ProcessState::Blocked, None),
        ]);
        assert_eq!(wait_scan(caller(), 0, &t), WaitDecision::Block);
        assert_eq!(wait_scan(caller(), 12, &t), WaitDecision::Block);
        // 目标不是我的子 → ECHILD（NoChild）
        assert_eq!(wait_scan(caller(), 77, &t), WaitDecision::NoChild);
    }

    #[test]
    fn wait_scan_echild_when_no_children() {
        let t = table_of(&[pv(0, P, None, ProcessState::Running, None)]);
        assert_eq!(wait_scan(caller(), 0, &t), WaitDecision::NoChild);
    }

    #[test]
    fn repeated_wait_is_idempotent_no_double_collect() {
        let mut rows = [
            pv(0, P, None, ProcessState::Running, None),
            pv(1, 11, Some(P), ProcessState::Zombie, Some(-3)),
        ];
        // 第一次 wait：收尸（负码原样携带）
        let t1 = table_of(&rows);
        assert_eq!(
            wait_scan(caller(), 0, &t1),
            WaitDecision::Collect { slot: 1, pid: ProcessId::new(11), code: -3 }
        );
        // 模拟完全回收：尸体行消失（waitpid_step 的 take 之后即如此）
        rows[1] = None;
        // 第二次 wait：同目标 → NoChild（ECHILD），绝不二次收集、不 panic
        let t2 = table_of(&rows);
        assert_eq!(wait_scan(caller(), 0, &t2), WaitDecision::NoChild);
        assert_eq!(wait_scan(caller(), 11, &t2), WaitDecision::NoChild);
    }

    #[test]
    fn orphan_actions_on_parent_death() {
        let dying = ProcessId::new(20);
        // 僵尸儿子随父死亡级联回收
        assert_eq!(
            orphan_action(Some(dying), ProcessState::Zombie, dying),
            OrphanAction::CascadeReap
        );
        // 活儿子摘除父链成为孤儿
        assert_eq!(
            orphan_action(Some(dying), ProcessState::Runnable, dying),
            OrphanAction::Detach
        );
        // 孙子的父是被 Detach 的儿子（21），不是死者 → Ignore
        assert_eq!(
            orphan_action(Some(ProcessId::new(21)), ProcessState::Runnable, dying),
            OrphanAction::Ignore
        );
        assert_eq!(
            orphan_action(None, ProcessState::Zombie, dying),
            OrphanAction::Ignore
        );
    }

    #[test]
    fn wait_result_packing_roundtrip_including_negative() {
        for (raw, code) in [(7u64, 42i32), (1234, 0), (64, -1), (u32::MAX as u64, i32::MIN)] {
            let packed = pack_wait_result(ProcessId::new(raw), code);
            assert_eq!((packed >> 32, (packed as u32) as i32), (raw, code));
        }
    }
}
