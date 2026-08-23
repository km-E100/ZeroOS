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

/// init（launchd）的 pid，孤儿收养的目标（对标 Linux pid==1 /
/// child_subreaper 的 reparent 目标）。恒为 2 的依据：NEXT_PID 从 2
/// 起分配，而 services::launch_core 引导期第一个拉起的就是 essential
/// 的 launchd（见 services/mod.rs bundled[0]）——顺序先于一切 fork/
/// SpawnService。若未来引导顺序改变，必须同步改这里并加启动期断言。
const INIT_PID: u64 = 2;

fn init_pid() -> ProcessId {
    ProcessId::new(INIT_PID)
}
/// 内核栈 64KiB（×64 槽 = 4MiB 静态区）：对照 Linux THREAD_SIZE 16K/
/// XNU kernel_stack 16K——我们无中断栈分离，所有 EL1 工作（含 IPC 拷贝、
/// 页表操作）都在本栈，取 4 倍余量防深层调用链溢出。
const KERNEL_STACK_SIZE: usize = 0x1_0000;
/// FPU/NEON 全量保存区：v0–v31（32×16B）+ FPSR/FPCR，align(16) 把
/// sizeof 从 520 补齐到 528。布局被 arch/aarch64.rs 的 SAVE_TRAP_AND_CALL
/// 存根与 restore_context 按帧内偏移 #288 起硬编码访问——两侧必须同步。
///
/// 【内核态浮点使用约定】内核代码（core/alloc 及全部子系统）不持有跨
/// 调度点的 FP/SIMD 状态，因此异常入口的**全量急切保存**已完备：存根在
/// 任何 Rust 代码运行前抢先落盘 v 寄存器与 FPSR/FPCR，恢复路径 eret 前
/// 对称装回。即便未来某处内核代码意外动用 NEON（如 memcpy 向量化），
/// 用户现场也不会被污染——入口即保存，内核中间怎么折腾都无所谓；
/// 且内核从不在 eret 边界携带自己的活跃 FP 状态 ⇒ 无需"内核侧保存"。
///
/// 【未来优化路径：lazy save】CPACR_EL1.FPEN 改 0b01（EL0 访问 FP 即
/// 陷阱），首次陷阱时把本结构换入帧内并置 FPEN=0b11；调度换出时若目标
/// 进程从未用过 FP 则跳过这 528B 的 stp/ldp 搬运。当前全量方案每帧固定
/// ~40 条访存指令，正确性优先、开销可测再优化。
#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct FpuState {
    /// v0–v31 的 128 位视图（Q 寄存器）。S/D/H 视图是低位别名，
    /// 保存 Q 视图即覆盖全部 SIMD/FP 寄存器状态。
    pub v: [u128; 32],
    /// 浮点状态寄存器（N/Z/C/V、舍入不精确累计标志等）。
    pub fpsr: u32,
    /// 浮点控制寄存器（舍入模式、FZ、trap 使能等）。
    pub fpcr: u32,
}

impl FpuState {
    pub const fn new() -> Self {
        Self {
            v: [0; 32],
            fpsr: 0,
            fpcr: 0,
        }
    }
}

impl Default for FpuState {
    fn default() -> Self {
        Self::new()
    }
}

/// 异常现场帧。
///
/// ⚠ 偏移契约：#[0..#280] 是历史布局，SAVE_TRAP_AND_CALL 存根与
/// restore_context 以立即数硬编码这些偏移，**绝不可移动**；新字段一律
/// 尾部追加（tpidr_el0=#280，fpu=#288..#815，16 对齐）。下方静态断言
/// 钉死每个偏移与总大小——汇编/Rust 布局漂移即编译失败。
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TrapFrame {
    pub regs: [u64; 31], // x0 - x30   #0..#247
    pub sp_el0: u64,     // #248
    pub elr_el1: u64,    // #256
    pub spsr_el1: u64,   // #264
    pub sp_el1: u64,     // #272 —— 既有 280 字节到此为止
    /// 用户 TLS 寄存器 TPIDR_EL0（#280）。此前从不保存 ⇒ 跨上下文切换
    /// TLS 损坏（严苛评审结论之一）；fork 经整帧拷贝自然继承子进程 TLS
    /// （POSIX fork 语义）。用户态设置接口（set_tls 类 syscall）属后续。
    pub tpidr_el0: u64,
    /// FPU/NEON 全量保存区（#288..#815，16 对齐；约定见 FpuState 注释）。
    /// CPACR_EL1.FPEN=0b11 后 EL0 可用 FP/SIMD，现场必须随帧完整保存。
    pub fpu: FpuState,
}

// 布局契约静态断言：汇编按这些立即数访帧，漂移即编译失败。
const _: () = {
    assert!(core::mem::offset_of!(TrapFrame, regs) == 0);
    assert!(core::mem::offset_of!(TrapFrame, sp_el0) == 248);
    assert!(core::mem::offset_of!(TrapFrame, elr_el1) == 256);
    assert!(core::mem::offset_of!(TrapFrame, spsr_el1) == 264);
    assert!(core::mem::offset_of!(TrapFrame, sp_el1) == 272);
    assert!(core::mem::offset_of!(TrapFrame, tpidr_el0) == 280);
    assert!(core::mem::offset_of!(TrapFrame, fpu) == 288);
    assert!(core::mem::offset_of!(FpuState, v) == 0);
    assert!(core::mem::offset_of!(FpuState, fpsr) == 512);
    assert!(core::mem::offset_of!(FpuState, fpcr) == 516);
    assert!(core::mem::size_of::<FpuState>() == 528);
    assert!(core::mem::size_of::<TrapFrame>() == 816);
};

impl TrapFrame {
    pub const fn new() -> Self {
        Self {
            regs: [0; 31],
            sp_el0: 0,
            elr_el1: 0,
            spsr_el1: 0,
            sp_el1: 0,
            tpidr_el0: 0,
            fpu: FpuState::new(),
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
        // 新进程从零 TLS 与干净 FP 状态起步：TPIDR_EL0/FPCR/FPSR 归零，
        // v 寄存器清零（首次恢复装填确定值而非上一任进程的残留）。
        self.tpidr_el0 = 0;
        self.fpu = FpuState::new();
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
    /// 进程能力位图（位定义见 `zero_abi::cap`；第八刀自布尔特权位
    /// `privileged: bool` 升格）：bit0=CAP_MMIO、bit1=CAP_BLOCK_DEV、
    /// bit2=CAP_SPAWN_SVC。fork 原样继承；引导路径由
    /// spawn_user_from_bootfs 按遗留布尔参数映射（true=CAP_ALL /
    /// false=0，见 capabilities_from_flag）。
    capabilities: u32,
    entry_point: Option<usize>,
    user_stack_top: Option<usize>,
    started: bool,
    /// 挂起的阻塞接收（通道号）：进程在阻塞中被唤醒后，由 dispatch 在
    /// 重入用户态前完成该系统调用的收尾（continuation 语义，对照 XNU）。
    pending_recv: Option<u32>,
    /// 挂起信号位图：`bit(sig - 1)`，位值见 `zero_abi::signals`（第九刀
    /// 信号位图最小版）。EL0 故障路径投递默认动作前在此登记死因；当前
    /// 无 kill/sigreturn 消费方，父经 WaitPid 收到的 `-(sig)` 退出码即
    /// 可观测出口。POSIX fork 不继承挂起信号 ⇒ 子恒从空位图起步。
    pending_signals: u16,
    /// 父进程 pid：仅 Fork 出的子进程持有（内核直接 spawn 的根进程为
    /// None）。父死后孤儿被收养：parent 重定向为 INIT_PID（见文件头部
    /// 【孤儿策略】）。
    parent: Option<ProcessId>,
    /// 孤儿收养标记：本进程的 parent 曾被 full_reap 从死者重定向为
    /// INIT_PID。收养者（launchd）尚未实现 wait 收割循环 ⇒ 被收养孤儿
    /// 若再退出将无人收尸、尸体永久占槽（fork 泄漏），因此其退出按
    /// 过渡策略直接完全回收（见 exit_disposition 防御分支）。
    adopted: bool,
    /// 退出码：Exit 系统调用记录；Zombie 态期间由父经 WaitPid 读走。
    exit_code: Option<i32>,
    /// 挂起的 WaitPid **等待目标**（第九刀：bool 单标记 → 目标集合化）。
    /// None = 无挂起等待；Some(spec) = 父在“无可收子但有活子”时登记的
    /// 精确目标并阻塞。单线程进程同一时刻至多一个未完结的阻塞 wait，
    /// 单槽即完备集合。子 Exit 在同一表锁临界区内做 spec 匹配
    /// （wait_wake_decision）：匹配才取走登记并把编码好的返回值直接写进
    /// 父 TrapFrame 的 x0（零侵入 continuation，见设计注释）；不匹配则
    /// 登记原样保留——堵住第七刀已知缺口“父 wait(A) 期间子 B 先退出被
    /// 误投递”。
    wait_target: Option<WaitSpec>,
}

/// 挂起 WaitPid 的等待目标（目标集合化的集合元素），对标 POSIX wait4
/// 的 pid 参数二态：0=任意子、N=精确 pid。匹配永远比较**完整 64 位
/// pid 原始值**（含 generation，见 alloc_pid）——回绕复用后的 stale
/// pid（同 seq 不同代）天然不命中 wake/wait 匹配。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum WaitSpec {
    /// wait(0)：任何子退出都唤醒等待者（POSIX wait 语义）。
    Any,
    /// wait(N)：仅 pid==N 的子退出唤醒等待者。
    Pid(ProcessId),
}

impl WaitSpec {
    /// 唤醒判定（纯函数）：本等待目标是否覆盖 dying 子进程。
    pub(crate) fn matches(self, dying: ProcessId) -> bool {
        match self {
            WaitSpec::Any => true,
            WaitSpec::Pid(p) => p == dying,
        }
    }
}

/// 子 Exit 时对父登记目标的唤醒决策（纯函数，主机单测覆盖误投递回归；
/// exit_current_with_status 的实际取走逻辑直接调用本函数，模型与实现
/// 共用同一段代码杜绝漂移）。返回 false 时登记必须原样保留——这是
/// bool 时代无法表达的语义。
pub(crate) fn wait_wake_decision(
    registration: Option<WaitSpec>,
    dying: ProcessId,
) -> bool {
    matches!(registration, Some(spec) if spec.matches(dying))
}

// ── pid 分配：(generation << 16) | seq（第九刀防复用）─────────────────
// seq 段 16 位在 [PID_SEQ_FIRST, 0xFFFF] 内步进（0 无效、1 保留；
// INIT_PID=2 的引导约定要求首个分配值恰为 2）；seq 耗尽时代数 +1、
// 从 FIRST 重新起步。同一 seq 值跨代复现时完整 pid 已不同 ⇒ wake/wait
// 全值比较天然免疫 stale pid。
//
// 回绕周期估算：
//   - 结构回绕（同 seq 复现）：每代 65534 个 pid，即每 65534 次分配
//     一次；但完整 pid 不重复。
//   - 完整 pid 不复用窗口：48 位代数 × 每代 65534 ≈ 1.8e19 次。
//   - 实际承载上限受 pack_wait_result 的 32 位 pid 位宽约束（pid 放
//     高 32 位、退出码放低 32 位）：gen < 2^16，约 4.29e9 次分配触及
//     ——按每秒 1000 次 fork/spawn 连续压测也要 ~49.7 天，u64 空间
//     充足，无需更复杂的回收位图方案。
const PID_SEQ_BITS: u64 = 16;
const PID_SEQ_MASK: u64 = (1 << PID_SEQ_BITS) - 1;
const PID_SEQ_FIRST: u64 = 2;
const PID_SEQ_LAST: u64 = PID_SEQ_MASK;

static NEXT_PID: AtomicU64 = AtomicU64::new(PID_SEQ_FIRST);

/// 由当前计数器值推演下一合法分配值（纯函数，主机单测钉死回绕行为）。
pub(crate) fn next_pid_raw(cur: u64) -> u64 {
    let mut seq = cur & PID_SEQ_MASK;
    let mut gen = cur >> PID_SEQ_BITS;
    seq += 1;
    if seq > PID_SEQ_LAST {
        gen = gen.wrapping_add(1);
        seq = PID_SEQ_FIRST;
    }
    (gen << PID_SEQ_BITS) | seq
}

/// 分配全局唯一 pid（spawn / fork 共用入口）。单核 + SeqCst 即全局
/// 串行；CAS 循环仅为形式完备（fetch_add 无法表达 seq 段的跳变）。
pub(crate) fn alloc_pid() -> ProcessId {
    loop {
        let cur = NEXT_PID.load(Ordering::SeqCst);
        // pack_wait_result 把 pid 放进高 32 位：越过 2^32 会静默污染
        // 退出码位。debug 构建立即炸出；release 靠上方 4.29e9 次预算。
        debug_assert!(
            cur < (1 << 32),
            "pid space exceeded 32-bit pack_wait_result capacity"
        );
        let next = next_pid_raw(cur);
        if NEXT_PID
            .compare_exchange_weak(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return ProcessId::new(cur);
        }
    }
}
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
    NEXT_PID.store(PID_SEQ_FIRST, Ordering::SeqCst);
}

pub fn spawn(entry: ThreadEntry, name: &'static str) -> ProcessId {
    crate::debug!("process::spawn called for name={}", name);
    let pid = alloc_pid();

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
        // 内核直生进程：默认无能力（fail-closed；能力只经显式授予或 fork 继承）。
        capabilities: 0,
        entry_point: None,
        user_stack_top: None,
        started: true,
        pending_recv: None,
        pending_signals: 0,
        parent: None, // 内核直生的根进程：无父，退出即完全回收
        adopted: false,
        exit_code: None,
        wait_target: None,
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

    // 遗留布尔契约 → 能力位图映射（true = CAP_ALL 全位，false = 空）：
    // services 注册表仍以 bool 描述服务特权级（本文件不越界改动），
    // 细粒度按服务配置待其升格为 u32 位图后接入。
    set_privileged(pid, privileged);
    Ok(pid)
}

/// 遗留布尔特权接口（services 注册表与 spawn_user_from_bootfs 的
/// 布尔契约保持兼容）：true = 全能力位图（`zero_abi::cap::CAP_ALL`），
/// false = 空。细粒度授予走 [`set_capabilities`]。
pub fn set_privileged(pid: ProcessId, privileged: bool) {
    set_capabilities(pid, capabilities_from_flag(privileged));
}

/// 直接写进程能力位图（capability 升格后的规范入口）。
pub fn set_capabilities(pid: ProcessId, capabilities: u32) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = table
        .iter_mut()
        .filter_map(|slot| slot.as_mut())
        .find(|record| record.pid == pid)
    {
        record.capabilities = capabilities;
    }
}

/// 读槽位进程的能力位图（syscall 门控用）。空槽返回 0（fail-closed：
/// 查不到就当没有任何能力）。
pub fn slot_capabilities(slot: usize) -> u32 {
    let table = PROCESS_TABLE.lock();
    table
        .get(slot)
        .and_then(|entry| entry.as_ref())
        .map(|record| record.capabilities)
        .unwrap_or(0)
}

/// 遗留布尔 → 能力位图映射（纯函数，主机单测钉死）：privileged=true
/// 即全位（含 CAP_BLOCK_DEV——blkdrv 直通数据面、launchd 服务拉起都
/// 依赖该映射）；false 为空位图。
pub(crate) fn capabilities_from_flag(privileged: bool) -> u32 {
    if privileged {
        zero_abi::cap::CAP_ALL
    } else {
        0
    }
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

/// EL0 同步故障 → 默认动作投递辅助（第九刀信号位图最小版）。
///
/// 对标 Linux `force_sig(sig)` + 默认 fatal 行为：先在表锁内把故障信号
/// 置入 pending_signals 位图（死因登记），再返回 POSIX 信号退出码
/// `-(sig)`。调用方（trap.rs 的 terminate_faulting_process）以该码走与
/// Exit 系统调用完全相同的 Dying→Zombie→WaitPid 状态机——父 waitpid
/// 收到的 code 即区分死因（SIGSEGV → -11）。位可叠加：多次投递 OR 累积，
/// 取用方按 `zero_abi::signals::signal_bit` 探测。
///
/// 锁纪律照旧：语句级 Guard，锁内零分配零打印；Guard 绝不跨 noreturn。
pub(crate) fn deliver_fatal_signal(slot: usize, sig: u8) -> i32 {
    let code = zero_abi::signals::fatal_exit_code(sig);
    {
        let mut table = PROCESS_TABLE.lock();
        if let Some(record) = &mut table[slot] {
            record.pending_signals |= zero_abi::signals::signal_bit(sig);
        }
    } // 表锁已释放（Guard 不跨后续 noreturn 调用，锁纪律第 1 条）
    code
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

/// 读取指定槽位进程的父 pid（号位 23 GetPpid 的唯一只读助手，
/// 模式照抄 `pid_at_slot`；只读，不修改任何记录字段）。
///
/// 返回值双层 Option：
/// - 外层 `None`：槽位无有效记录（防御分支，由调用方映射为错误）；
/// - 外层 `Some`：记录存在，内层即 `record.parent`——`Some(pid)` 为
///   fork 建立的父子链（含被 init 收养的孤儿：其 parent 已重定向为
///   INIT_PID=2），`None` 为内核直生根进程（服务注册表 spawn 路径）。
pub fn get_parent_pid(slot: usize) -> Option<Option<ProcessId>> {
    let table = PROCESS_TABLE.lock();
    table[slot].map(|record| record.parent)
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
// 【孤儿策略：init 收养 + 过渡期防御回收】（第七刀，对标 Linux
//   child_subreaper / pid==1 reparent）
//   父先死时：活子的 parent **重定向为 INIT_PID=2（launchd）** 并置
//   adopted=true（族谱不断链，收养关系对调试/未来 getppid 可见）；
//   死者名下已有的 Zombie 尸体仍随父死亡**级联回收**（full_reap 显式
//   栈迭代，非递归）——尸体无人认领也无法复活，留着只会占槽。
//   ⚠ 过渡策略：launchd 尚未实现 wait 收割循环 ⇒ 被收养孤儿退出后
//   没有人会来收尸，尸体将永久滞留进程表（fork 泄漏）。防御：
//   adopted==true 的进程退出时**跳过 Zombie 态直接完全回收**
//   （exit_disposition 的防御分支）。代价是这类退出的退出码不可收集——
//   在 launchd 落地 wait 循环前这是正确性（防泄漏）对可观测性的取舍。
//   launchd 实现 wait 循环后，删除该防御分支即恢复 POSIX 收养语义，
//   届时被收养孤儿的尸体可被 launchd 正常 WaitPid 收集。
//
// 【挂起恢复 = 零侵入 continuation】（对照 pending_recv 模式，选最小
//   侵入方案：平行的 wait_target 登记字段，不改 scheduler.rs/trap.rs）
//   父 WaitPid 无可收子但有活子 ⇒ 同一表锁临界区内完成「扫描 + 登记
//   wait_target」（登记→阻塞原子；单核 + EL1 关中断 ⇒ 无丢失唤醒窗
//   口）⇒ block_current()。子 Exit 在锁内对父登记做精确匹配
//   （wait_wake_decision）：目标覆盖本退出子 ⇒ 取走登记，把编码好的
//   返回值**直接写进父 TrapFrame 的 x0**，再 wake(父)；不覆盖（典型：
//   父 wait(A) 期间子 B 先退）⇒ 登记原样保留、B 尸体留表待按需收取，
//   绝不假父之名投递（第九刀：bool 单标记 → 目标集合化）。结果先于
//   唤醒写入帧 ⇒ 父被 dispatch 恢复现场时 x0 已是最终返回值——
//   dispatch 无需任何 wait_target 分支（scheduler.rs 本轮只读的关键
//   设计约束）。即使假想虚假唤醒，帧内也是正确结果。
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
    /// 无父 / 父已死 / 父已僵 / **被收养孤儿（过渡防御）**：立即完全回收。
    ReapImmediately,
}

/// `adopted` = 本进程是父死后被收养给 INIT_PID 的孤儿。收养者
/// （launchd）当前没有 wait 收割循环，若让它走 Zombie 路径，尸体将
/// 无人认领、永久占槽 ⇒ 防御性直接回收（过渡策略，见文件头部
/// 【孤儿策略】；对标 Linux 中 init 收割孤儿的最终效果——资源必然
/// 释放，只是我们提前到退出瞬间）。
pub(crate) fn exit_disposition(
    parent: Option<ProcessId>,
    parent_alive: bool,
    adopted: bool,
) -> ExitDisposition {
    if adopted {
        return ExitDisposition::ReapImmediately;
    }
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
    /// 子还活着：**init 收养**——parent 重定向为 INIT_PID 并置 adopted
    /// （第七刀策略变更：旧实现是摘链自灭 parent=None；现对标 Linux
    /// child_subreaper 的 reparent-to-init，族谱保持可见）。
    AdoptToInit,
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
                OrphanAction::AdoptToInit
            }
        }
        _ => OrphanAction::Ignore,
    }
}

/// 进程表回收路径的审计日志（主机测试安全版）。
///
/// `crate::warn!` 直写 PL011 MMIO（0x0900_0000），在宿主机 cargo test
/// 里等于野指针写 → 段错误。而收养/级联回收是**表变更**而非纯函数，
/// 主机单测必须真实执行 full_reap 才有意义（只测纯决策函数测不出
/// 表状态机的回归）。故本文件内 full_reap 路径统一经此 shim：裸机 =
/// 正常 Warn 级输出；cfg(test) = 静默丢弃。新增表变更日志请走这里。
#[cfg(not(test))]
fn audit_warn(args: core::fmt::Arguments<'_>) {
    crate::runtime::logger::log_at(crate::runtime::logger::Level::Warn, args);
}
#[cfg(test)]
fn audit_warn(_args: core::fmt::Arguments<'_>) {}

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
                            OrphanAction::AdoptToInit => {
                                audit_warn(format_args!(
                                    "process {} (pid={}) orphaned: parent {} died, adopted by init(pid={})",
                                    rec.name,
                                    rec.pid.raw(),
                                    dying.raw(),
                                    INIT_PID
                                ));
                                // init 收养：族谱重定向到 launchd。adopted 置位后
                                // 该孤儿再退出时走防御回收（launchd 暂无 wait 循环，
                                // 留尸必滞留——见 exit_disposition / 文件头部策略）。
                                rec.parent = Some(init_pid());
                                rec.adopted = true;
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
        audit_warn(format_args!(
            "process {} (pid={} slot={}) fully reaped: slot reclaimed",
            record.name,
            record.pid.raw(),
            s
        ));
        for k in 0..n {
            // 防御：级联对象是 Zombie，addr_space 正常已在 zombify 时清空。
            if let Some(space) = casc_spaces[k] {
                unsafe {
                    space.destroy();
                }
            }
            audit_warn(format_args!(
                "cascade reap: zombie pid={} slot={} (parent died)",
                casc_pids[k],
                casc_slots[k]
            ));
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
        let adopted = me_read.adopted;
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
        match exit_disposition(parent, parent_alive, adopted) {
            ExitDisposition::BecomeZombie => {
                // 单核 + 表锁内：刚才读到的记录必然仍在（不可能被并发移除）。
                let me = table[slot].as_mut().expect("record vanished under lock");
                me.exit_code = Some(status);
                me.state = ProcessState::Zombie;
                let space = me.addr_space.take(); // 用户页/页表此刻归还
                // 第九刀目标集合化：仅当父的登记覆盖本退出子才取走标记。
                // 判定与取走在同一表锁临界区内两段完成（单核无并发窗口；
                // 决策函数 wait_wake_decision 与主机单测共用同一实现）。
                let wake_parent = parent_view.and_then(|pv| {
                    let hit = table[pv.slot]
                        .as_mut()
                        .map(|r| wait_wake_decision(r.wait_target, my_pid))
                        .unwrap_or(false);
                    if hit {
                        table[pv.slot].as_mut().and_then(|r| r.wait_target.take());
                    }
                    hit.then_some((pv.slot, pv.pid))
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
            if let Some((parent_slot, parent_pid)) = zp.wake_parent {
                // —— continuation 交付路径：结果直接写父 TrapFrame 再唤醒。
                // 父被 dispatch 恢复现场时 x0 已是最终返回值，无需 dispatch
                // 侧任何改动；单核 + 父处于 Blocked ⇒ 写帧无竞争。
                unsafe {
                    (*TRAP_FRAMES[parent_slot].get()).regs[0] =
                        crate::trap::encode_result(Ok(zp.packed));
                }
                // ⚠ 消费一次语义（实机回归：nohangtest 首轮轮询收到上一条
                // waittest 的陈旧尸体 pid=7/42）：continuation 已经把收尸
                // 结果交付给等待者，本尸体必须随交付即时摘除——否则记录
                // 残留为 Zombie，父的下一次 wait(任意) 会二次收集同一死
                // 子（返回陈旧数据；pid 复用后更是张冠李戴），违反 POSIX
                // wait 恰好消费一次的契约。与 waitpid_step 的 Collect 分支
                // （父事后补收路径）在此收敛为同一条不变量：
                // 「僵尸记录存在 ⇒ 尚无人收到结果」。
                let delivered = { PROCESS_TABLE.lock()[slot].take().is_some() };
                crate::debug!(
                    "process slot={} exit result delivered to pid={} (record consumed={})",
                    slot,
                    parent_pid.raw(),
                    delivered
                );
                crate::scheduler::wake(parent_pid);
            } else {
                // 无匹配等待者（父没在等 / 登记的是别的 pid）：留尸待父
                // 将来 wait 补收（快路径 Collect 分支）。
                crate::info!(
                    "process slot={} became zombie (status={})",
                    slot,
                    status
                );
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
    /// 有活子未退：调用方应立即 block_current()（wait_target 目标已登记）。
    Blocked,
    /// WNOHANG 置位且“有活子但无尸可收”：不挂起、不登记等待目标，
    /// 调用方立即返回 0（对照 Linux wait4 WNOHANG 约定，见 zero-abi）。
    WouldBlock,
}

/// 扫描决策 → 等待动作的映射（纯函数，主机单测覆盖 WNOHANG 语义）：
/// flags bit0（[`zero_abi::syscall::WAIT_NOHANG`]）置位时“有活子无尸”
/// 从 Sleep 改判 PollMiss；Collect / NoChild 不受 flags 影响
/// （ECHILD 在两种模式下一致——无子就是无子）。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum WaitAction {
    /// 收尸：携带 (槽位, 编码返回值)。
    Collect { slot: usize, packed: u64 },
    /// 挂起等待（登记 wait_target 精确目标后阻塞）。
    Sleep,
    /// WNOHANG 轮询落空：立即返回 0。
    PollMiss,
    /// 无匹配子进程：ECHILD（NotFound）。
    NoChild,
}

pub(crate) fn wait_plan(caller: ProcessId, target: u64, flags: u64, procs: &[Option<ProcView>]) -> WaitAction {
    match wait_scan(caller, target, procs) {
        WaitDecision::Collect { slot, pid, code } => WaitAction::Collect {
            slot,
            packed: pack_wait_result(pid, code),
        },
        WaitDecision::Block => {
            if flags & zero_abi::syscall::WAIT_NOHANG != 0 {
                WaitAction::PollMiss
            } else {
                WaitAction::Sleep
            }
        }
        WaitDecision::NoChild => WaitAction::NoChild,
    }
}

pub fn waitpid_step(target_pid: u64, flags: u64) -> Result<WaitStep, SysError> {
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
        match wait_plan(me.pid, target_pid, flags, &views) {
            WaitAction::Collect { slot, packed } => {
                // 摘除尸体记录。不变量：addr_space 已在 zombify 时清空，
                // 此处防御式带出以防万一。
                let record = table[slot].take().ok_or(SysError::NotFound)?;
                Act::Collect {
                    packed,
                    space: record.addr_space,
                }
            }
            WaitAction::Sleep => {
                if let Some(me) = table[caller_slot].as_mut() {
                    // 登记精确等待目标（第九刀目标集合化）：0=任意子、
                    // N=只等 pid==N。此后仅匹配的退出才唤醒本父。
                    me.wait_target = Some(if target_pid == 0 {
                        WaitSpec::Any
                    } else {
                        WaitSpec::Pid(ProcessId::new(target_pid))
                    });
                }
                Act::Block
            }
            // 关键：WNOHANG 落空**绝不**登记 wait_target——否则本次轮询的
            // 登记会与后续真正的阻塞 wait 语义互相污染（父没睡却带着
            // “有人在等”的标记，子退出时会白写一次帧 + 白唤醒一次）。
            WaitAction::PollMiss => return Ok(WaitStep::WouldBlock),
            WaitAction::NoChild => return Err(SysError::NotFound), // ECHILD
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

/// 第十刀 COW：EL0/EL1 写权限故障的写时复制断链入口（trap.rs 调用）。
///
/// 取当前槽位进程的地址空间，对 far 处 PTE 尝试 COW 断链：
/// - PTE 带 DESC_SW_COW ⇒ 按引用计数复制/恢复可写，返回 true，
///   调用方 restore_frame 后 eret 重放同一条指令；
/// - 否则返回 false，故障走原有信号/终止路径。
///
/// EL1 代用户写（copy_to_user 等）落在 COW 页上同样经此恢复：
/// 断链完成后 eret 回内核重放踩故障的那条访存指令，memcpy 无感续行。
/// 锁纪律：address_space() 的表锁语句级即放，物理分配器锁在其后获取，
/// 无反转风险（与 spawn 的 configure 流程同源）。
pub fn handle_cow_write_fault(far: usize) -> bool {
    let slot = crate::scheduler::current_slot();
    let Some(space) = address_space(slot) else {
        return false;
    };
    space.handle_cow_fault(far)
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
    let child_pid = alloc_pid();

    // 地址空间克隆必须在持锁外进行（分配物理页/可能失败）。
    // 第十刀 COW：clone 不再逐页 memcpy——父子共享数据页（双侧只读 +
    // DESC_SW_COW），首写 Permission fault 时才断链复制；共享/复制统计
    // 由 paging::last_clone_stats 快照，copied==0 即零复制 fork 生效。
    let addr_space = if let Some(space) = parent_record.addr_space {
        let cloned = address_space::clone_space(&space).map_err(ProcessError::MapError)?;
        let (shared, ro_shared, copied) = crate::mm::paging::last_clone_stats();
        crate::info!(
            "process: cow fork pid={} -> child pid={} shared_pages={} readonly_shared={} copied={}",
            parent_record.pid.raw(),
            child_pid.raw(),
            shared,
            ro_shared,
            copied
        );
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
            // 能力位图原样继承（对标 POSIX fork 的凭据继承语义）。
            capabilities: parent_record.capabilities,
            entry_point: parent_record.entry_point,
            user_stack_top: parent_record.user_stack_top,
            started: true,
            pending_recv: None,
            // POSIX fork 语义：子进程不继承父的挂起信号 ⇒ 空位图起步。
            pending_signals: 0,
            // 族谱：Fork 是唯一产生父子关系的入口（POSIX fork 对齐）。
            parent: Some(parent_record.pid),
            // 收养标记不随 Fork 遗传：被收养孤儿 fork 出的孙辈是“收养者
            // 的孙进程”而非收养孤儿本身，其退出语义与普通子一致。
            adopted: false,
            exit_code: None,
            wait_target: None,
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

// ═══════════════════════════════════════════════════════════════════════
// execve 最小完备版（第九刀）：真换地址空间的 Exec
//
// 语义（ABI 冻结说明见 zero-abi `Syscall::Exec` 与 syscalls.rs 号位 3 臂）：
//   销毁当前地址空间 → 按 rootfs 路径装载新 ELF → 切 TTBR0 → 重置帧跳新
//   入口。进程身份（pid / parent / capabilities / 族谱）原样保留——exec
//   换的是映像，不是进程。
//
// 【失败原子性】新地址空间在旧空间仍然完整时构建（BuildNewImage 是唯一
//   可失败阶段），任何一步失败都只销毁半成品新空间并返回 Err——旧映像
//   无损，调用进程原地继续（POSIX：exec 失败返回 -1）。Commit 之后不再
//   存在可失败步骤。
//
// 【提交次序不变量】BuildNewImage → CommitRebind → ActivateNew →
//   DestroyOld → ResetFrame。Activate 必须先于 DestroyOld：svc 返回走
//   trap.rs 的 restore_frame **直接 eret**，不经过 dispatch 的
//   address_space 激活路径；若先销毁后激活，TTBR0 会指向已释放页表。
//   次序由 exec_tests::exec_stage_plan_* 主机单测钉死。
//
// 【dispatch 无需额外处理】scheduler::dispatch 每次都从
//   process::address_space(next_slot) **现读**根表并 space.activate()
//   （见 scheduler.rs dispatch）——rebind 之后所有后续调度自然激活新根，
//   调度器侧零改动、零感知。exec 当次返回的 TTBR0 由 ActivateNew 显式
//   切换（理由见上）。
//
// 【TPIDR_EL1 时序】TPIDR_EL1 恒指向本槽 TRAP_FRAMES[slot]（静态存储，
//   生命周期与地址空间无关）；exec 全程处于本进程 EL1 syscall 上下文
//   （IRQ 屏蔽 + 单核），入口存根不可能在改写中途触发；restore_frame /
//   restore_context 在 eret 前把 TPIDR_EL1 重新指回同一槽帧——无需任何
//   特殊时序处理。锁纪律与 spawn_user_from_bootfs 的 configure 流程同源：
//   表锁只覆盖字段改写语句块，页表操作一律锁外。
//
// 【锁纪律】PROCESS_TABLE 仅在 rebind_address_space 的字段改写语句块内
//   持有；AddressSpace::destroy 一律锁外执行（scheduler.rs 锁纪律第 3
//   条：表锁→物理分配器锁的反转风险）。
// ═══════════════════════════════════════════════════════════════════════

/// exec 提交阶段模型（纯数据，主机单测钉死两条不变量：① 成功路径
/// ActivateNew 先于 DestroyOld；② 构建失败在触碰旧映像前短路）。
/// [`exec_load`] 按此计划执行，注释引用同名概念防实现与模型漂移。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExecStage {
    /// 阶段 1：旧映像完整时构建全新地址空间（唯一可失败阶段）。
    BuildNewImage,
    /// 提交点：表锁内换入新空间、带出旧空间（此后不可失败）。
    CommitRebind,
    /// 新 TTBR0 生效 + TLB 全量刷新（必须在 DestroyOld 之前，理由见头部）。
    ActivateNew,
    /// 锁外递归释放旧空间的页表页与用户物理页。
    DestroyOld,
    /// TrapFrame 重置为"新映像首启"现场（bootfs ABI + 干净执行域）。
    ResetFrame,
}

/// 阶段计划：成功为完整五步；构建失败止步于第一步——Commit 及其后全部
/// 不发生，旧地址空间自始至终不被触碰（失败原子性的模型化表述）。
pub(crate) fn exec_stage_plan(build_ok: bool) -> &'static [ExecStage] {
    if build_ok {
        &[
            ExecStage::BuildNewImage,
            ExecStage::CommitRebind,
            ExecStage::ActivateNew,
            ExecStage::DestroyOld,
            ExecStage::ResetFrame,
        ]
    } else {
        &[ExecStage::BuildNewImage]
    }
}

/// TrapFrame 重置为"新映像首启"现场（exec 专用辅助；纯函数，主机单测
/// 覆盖——TLS/FPU 归零是易漏点，漏了即跨 exec 泄漏上一映像的执行域状态）。
///
/// 参数布局（与 set_initial_user_args / bootfs ABI 对齐）：
/// - x0/x1 = bootfs 文件表首址 / 条目数（任何用户程序起步都能找到自己的文件）
/// - x2    = 调用方透传值（userlib::exec 的 arg；0 表示未使用）
/// - x3    = 0（预留）
fn apply_exec_frame(
    frame: &mut TrapFrame,
    entry: usize,
    user_sp: usize,
    kernel_sp: usize,
    args: [u64; 4],
) {
    frame.regs = [0; 31];
    frame.regs[0] = args[0];
    frame.regs[1] = args[1];
    frame.regs[2] = args[2];
    frame.regs[3] = args[3];
    // main 正常返回 = exit(0)：沿用 spawn 的 trampoline 约定，
    // 新映像的退出码同样可被父进程 WaitPid 收集（forktest/execdemo 依赖）。
    frame.regs[30] = thread_exit as usize as u64;
    frame.sp_el0 = user_sp as u64;
    frame.elr_el1 = entry as u64;
    frame.spsr_el1 = 0; // EL0t，中断随 SPSR 对 EL0 开启
    frame.sp_el1 = kernel_sp as u64;
    // 新映像从零 TLS 与干净 FP 状态起步（对照 init_user）：上一映像的
    // TPIDR_EL0 / FPCR / FPSR / v 寄存器一律不得泄漏进新执行域。
    frame.tpidr_el0 = 0;
    frame.fpu = FpuState::new();
}

/// 提交点（configure_user_process 的 exec 变体）：表锁内原子换入新地址
/// 空间并把旧空间带出，同步刷新 entry_point / user_stack_top / started。
/// 返回 (旧空间, 是否提交成功)；记录消失（理论不可达）时 committed=false，
/// 新空间由调用方销毁防泄漏。旧空间交调用方**锁外**销毁（锁纪律第 3 条）。
fn rebind_address_space(
    slot: usize,
    space: AddressSpace,
    entry: usize,
    user_sp: usize,
) -> (Option<AddressSpace>, bool) {
    let mut table = PROCESS_TABLE.lock();
    match table.get_mut(slot) {
        Some(Some(record)) => {
            let old = record.addr_space.take();
            record.addr_space = Some(space);
            record.entry_point = Some(entry);
            record.user_stack_top = Some(user_sp);
            // 新映像 = 首启语义：后续 dispatch 经 first_run_context 以
            // enter_user_mode 进入（与 spawn_user_from_bootfs 同一条路；
            // enter_user_mode 与 switch_to 最终都从同一 TrapFrame 恢复，
            // TTBR0 已由 dispatch 的 activate 分支现读现切）。
            record.started = false;
            (old, true)
        }
        _ => (None, false),
    }
}

/// Exec 系统调用核心：按 rootfs 路径重载当前进程映像（真 execve）。
///
/// 成功返回新映像的 bootfs 表首址（即新程序起步时的 x0 值；trap.rs 的
/// encode_result(Ok(v))==v 恒等写回 regs[0]，两处一致）。控制流随后转向
/// 新 ELF 入口，原调用点不再可见地"返回"。失败返回 Err 且旧映像完好。
///
/// # Safety
/// `frame` 必须是当前运行进程的 TrapFrame（syscall 入口传入的保存帧）；
/// 必须在该进程的 EL1 syscall 上下文中调用（IRQ 屏蔽、单核）。
pub unsafe fn exec_load(
    slot: usize,
    path: &str,
    passthrough: u64,
    frame: *mut TrapFrame,
) -> Result<u64, ProcessError> {
    let pid = pid_at_slot(slot);
    crate::debug!(
        "exec_load: slot={} pid={} path={}",
        slot,
        pid.map(|p| p.raw()).unwrap_or(0),
        path
    );

    // —— BuildNewImage：旧空间完整期间构建全新空间（唯一可失败阶段）。
    //    半成品当场销毁，绝不留泄漏；错误逐级映射保持 spawn 路径同款语义。
    let elf = user_elf::build_user_elf(path).map_err(ProcessError::ElfError)?;
    let mut space = AddressSpace::new();
    if let Err(err) = map_user_elf_segments(&mut space, &elf, path) {
        space.destroy();
        return Err(ProcessError::MapError(err));
    }
    if let Err(err) = space.map_stack(USER_STACK_TOP, USER_STACK_LEN) {
        space.destroy();
        return Err(ProcessError::MapError(err));
    }
    let bootfs_info =
        match rootfs::build_user_bootfs_for_process(&mut space, rootfs::USER_BOOTFS_BASE) {
            Ok(info) => info,
            Err(err) => {
                space.destroy();
                return Err(ProcessError::MapError(err));
            }
        };

    // —— CommitRebind：表锁内原子换入（此后不再有可失败步骤）。
    let (old_space, committed) =
        rebind_address_space(slot, space, elf.entry as usize, USER_STACK_TOP);
    if !committed {
        // AddressSpace 是 Copy，这里仍可触达新空间：防御性销毁防泄漏。
        space.destroy();
        return Err(ProcessError::NoSuchProcess);
    }

    // —— ActivateNew：本次 svc 返回不经 dispatch（restore_frame 直接
    //    eret），必须在此显式切换 TTBR0；set_user_ttbr 含全量 TLB 刷新。
    //    此刻起旧空间的页表再无硬件引用者，销毁窗口闭合。——
    space.activate();

    // —— DestroyOld：锁外递归回收（此刻 EL1 取指/栈都走内核共享 L1[1]，
    //    与被回收的私有表无关；TLB 已随 Activate 刷新，无陈旧翻译残留）。
    if let Some(old) = old_space {
        old.destroy();
    }

    // —— ResetFrame：新映像首启现场。x30=thread_exit 保证新程序的 main
    //    返回后走 exit(0) 状态机（可收集），而不是跌进未知地址。——
    apply_exec_frame(
        &mut *frame,
        elf.entry as usize,
        USER_STACK_TOP,
        kernel_stack_top_raw(slot),
        [
            bootfs_info.entries_ptr,
            bootfs_info.entries_len,
            passthrough,
            0,
        ],
    );
    crate::info!(
        "exec_load: pid={} image replaced with {} (entry={:#x} root_phys={:#x} old_as_destroyed=true)",
        pid.map(|p| p.raw()).unwrap_or(0),
        path,
        elf.entry as usize,
        space.ttbr0_phys()
    );
    Ok(bootfs_info.entries_ptr)
}

#[cfg(test)]
mod exec_tests {
    use super::*;

    /// 帧重置 = 全新执行域：寄存器清零、LR=thread_exit、ELR=新入口、
    /// TLS/FP 归零、参数精确落位 x0-x3。任何一项漂移都是跨 exec 的
    /// 执行域泄漏或启动现场污染（历史事故模式：伪 exec 只重置了半张帧）。
    #[test]
    fn exec_frame_reset_is_fresh_domain() {
        let mut frame = TrapFrame {
            regs: [0xDEAD_BEEF; 31],
            sp_el0: 0x1111,
            elr_el1: 0x2222,
            spsr_el1: 0xF,
            sp_el1: 0x3333,
            tpidr_el0: 0x5555,
            fpu: FpuState {
                v: [0xA5A5; 32],
                fpsr: 0x7F,
                fpcr: 0x3,
            },
        };
        apply_exec_frame(
            &mut frame,
            0x20_0000,
            0xFFFF_F000,
            0x8888_0000,
            [0x1000, 8, 77, 0],
        );
        assert_eq!(frame.elr_el1, 0x20_0000);
        assert_eq!(frame.spsr_el1, 0); // EL0t
        assert_eq!(frame.sp_el0, 0xFFFF_F000);
        assert_eq!(frame.sp_el1, 0x8888_0000);
        assert_eq!(frame.regs[0], 0x1000); // bootfs 表首址
        assert_eq!(frame.regs[1], 8); // bootfs 条目数
        assert_eq!(frame.regs[2], 77); // 调用方透传值
        assert_eq!(frame.regs[3], 0);
        for i in 4..31 {
            if i == 30 {
                assert_eq!(frame.regs[30], thread_exit as usize as u64);
            } else {
                assert_eq!(frame.regs[i], 0, "x{i} 必须清零");
            }
        }
        // 执行域归零：TLS 与 FP 状态不得残留上一映像的值。
        assert_eq!(frame.tpidr_el0, 0);
        assert!(frame.fpu.v.iter().all(|&v| v == 0));
        assert_eq!(frame.fpu.fpsr, 0);
        assert_eq!(frame.fpu.fpcr, 0);
    }

    /// 提交次序不变量（exec_load 头部注释的可执行化）：成功路径必须是
    /// Commit → Activate → Destroy → Reset 的严格次序（Activate 先于
    /// Destroy——svc 直接 eret 不经 dispatch，TTBR0 绝不能指向已释放
    /// 页表）；失败路径止步于 BuildNewImage，旧地址空间完整保留。
    #[test]
    fn exec_stage_plan_orders_activate_before_destroy_and_fails_atomically() {
        let ok = exec_stage_plan(true);
        let cmt = ok.iter().position(|s| *s == ExecStage::CommitRebind).unwrap();
        let act = ok.iter().position(|s| *s == ExecStage::ActivateNew).unwrap();
        let dst = ok.iter().position(|s| *s == ExecStage::DestroyOld).unwrap();
        assert!(cmt < act && act < dst, "Commit→Activate→Destroy 次序被破坏");
        assert_eq!(ok.last(), Some(&ExecStage::ResetFrame));
        // 失败原子性：构建失败 ⇒ Commit 及以后全部不发生。
        assert_eq!(exec_stage_plan(false), &[ExecStage::BuildNewImage]);
    }
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
            exit_disposition(Some(ProcessId::new(9)), true, false),
            ExitDisposition::BecomeZombie
        );
        // 无父 / 父已死 / 父已僵 → 立即完全回收
        assert_eq!(exit_disposition(None, false, false), ExitDisposition::ReapImmediately);
        assert_eq!(
            exit_disposition(Some(ProcessId::new(9)), false, false),
            ExitDisposition::ReapImmediately
        );
    }

    #[test]
    fn init_pid_is_frozen_at_two() {
        // 收养目标的 ABI 级约定（见 INIT_PID 注释）：launchd 引导期首个
        // spawn，NEXT_PID 自 2 起分配。此值一旦漂移，孤儿会被“收养”给
        // 无关进程——用测试钉死，改引导顺序时必须显式更新这里。
        assert_eq!(INIT_PID, 2);
        assert_eq!(init_pid(), ProcessId::new(2));
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
        // 活儿子：init 收养（parent 重定向 INIT_PID，第七刀策略）
        assert_eq!(
            orphan_action(Some(dying), ProcessState::Runnable, dying),
            OrphanAction::AdoptToInit
        );
        // 孙子的父是活着的中间儿子（21），不是死者 → Ignore（收养单层，
        // 中间儿子死后孙子才轮到被收养）
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

    // ── 第七刀新增：WNOHANG 与 init 收养 ─────────────────────────────

    #[test]
    fn wnohang_maps_live_child_block_to_poll_miss() {
        let t = table_of(&[
            pv(0, P, None, ProcessState::Running, None),
            pv(1, 11, Some(P), ProcessState::Running, None),
        ]);
        // 阻塞模式（flags=0）：有活子无尸可收 → Sleep
        assert_eq!(wait_plan(caller(), 0, 0, &t), WaitAction::Sleep);
        // WNOHANG 置位：同一张表 → PollMiss（不挂起，立即返回 0）
        let nohang = zero_abi::syscall::WAIT_NOHANG;
        assert_eq!(
            wait_plan(caller(), 0, nohang, &t),
            WaitAction::PollMiss
        );
        // 未定义位被忽略：只有 bit0 参与判定
        assert_eq!(
            wait_plan(caller(), 0, nohang | 0b1111_1110, &t),
            WaitAction::PollMiss
        );
        assert_eq!(wait_plan(caller(), 0, 0b10, &t), WaitAction::Sleep);
    }

    #[test]
    fn wnohang_leaves_collect_and_echild_untouched() {
        let zombie_t = table_of(&[
            pv(0, P, None, ProcessState::Running, None),
            pv(1, 11, Some(P), ProcessState::Zombie, Some(42)),
        ]);
        let nohang = zero_abi::syscall::WAIT_NOHANG;
        // 有尸可收：两种模式都立即收尸（WNOHANG 不改变 Collect）
        for flags in [0u64, nohang] {
            assert_eq!(
                wait_plan(caller(), 0, flags, &zombie_t),
                WaitAction::Collect { slot: 1, packed: pack_wait_result(ProcessId::new(11), 42) }
            );
        }
        // 无任何子：ECHILD 不受 WNOHANG 影响（Linux 同款语义）
        let lonely = table_of(&[pv(0, P, None, ProcessState::Running, None)]);
        for flags in [0u64, nohang] {
            assert_eq!(wait_plan(caller(), 0, flags, &lonely), WaitAction::NoChild);
        }
    }

    #[test]
    fn adopted_orphan_exit_is_reaped_not_zombified() {
        // 路径 B（过渡防御）：被收养孤儿再退出。launchd 尚无 wait 循环，
        // 若按常规转 Zombie，尸体无人认领 ⇒ 进程表泄漏。防御分支要求
        // adopted=true 时无论收养者死活都直接完全回收。
        assert_eq!(
            exit_disposition(Some(init_pid()), true, true),
            ExitDisposition::ReapImmediately
        );
        assert_eq!(
            exit_disposition(Some(init_pid()), false, true),
            ExitDisposition::ReapImmediately
        );
        // 对照组：非收养子、launchd 在世 → 正常留尸可收集（语义不变）。
        assert_eq!(
            exit_disposition(Some(init_pid()), true, false),
            ExitDisposition::BecomeZombie
        );
    }

    /// 表级测试的互斥哨兵：PROCESS_TABLE 是全局静态，而 cargo test
    /// 默认多线程并行。凡直接改真实表的测试都必须持锁。
    static TABLE_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn make_record(pid_raw: u64, slot: usize, parent: Option<u64>) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId::new(pid_raw),
            name: "test-proc",
            entry: thread_exit,
            state: ProcessState::Runnable,
            slot,
            addr_space: None, // 测试绝不触发 AddressSpace::destroy
            capabilities: 0,
            entry_point: None,
            user_stack_top: None,
            started: true,
            pending_recv: None,
            pending_signals: 0,
            parent: parent.map(ProcessId::new),
            adopted: false,
            exit_code: None,
            wait_target: None,
        }
    }

    #[test]
    fn full_reap_adopts_live_children_to_init() {
        // 路径 A：父死亡瞬间，活子 parent 重定向 INIT_PID 且置 adopted；
        // 孙辈不受牵连（收养单层），其父链仍指向活着的中间儿子。
        let _g = TABLE_GUARD.lock().unwrap();
        {
            let mut table = PROCESS_TABLE.lock();
            *table = [const { None }; MAX_PROCESSES];
            table[3] = Some(make_record(20, 3, None)); // 将死的父
            table[5] = Some(make_record(21, 5, Some(20))); // 活子
            table[7] = Some(make_record(22, 7, Some(21))); // 孙辈
        }
        full_reap(3); // 父“死亡”

        let table = PROCESS_TABLE.lock();
        assert!(table[3].is_none(), "dying parent must be fully reaped");
        let child = table[5].as_ref().expect("live child survives");
        assert_eq!(child.pid, ProcessId::new(21));
        assert_eq!(child.parent, Some(init_pid()), "orphan adopted by init");
        assert!(child.adopted, "adoption flag must be set");
        // 孙辈：父链仍指中间儿子（21），未被越级改写
        let grand = table[7].as_ref().expect("grandchild untouched");
        assert_eq!(grand.parent, Some(ProcessId::new(21)));
        assert!(!grand.adopted);
        // 清场：把全局表还原为空，避免影响其他测试对表状态的假设。
        drop(table);
        let mut table = PROCESS_TABLE.lock();
        *table = [const { None }; MAX_PROCESSES];
    }

    #[test]
    fn adopted_child_death_passes_adoption_to_grandchildren() {
        // 收养链传递：被收养孤儿死后，它自己的子女轮到被 init 收养；
        // 同时验证 adopted 标记只随 full_reap 的显式重定向置位，不随
        // 族谱自动扩散。
        let _g = TABLE_GUARD.lock().unwrap();
        {
            let mut table = PROCESS_TABLE.lock();
            *table = [const { None }; MAX_PROCESSES];
            table[5] = Some(make_record(21, 5, Some(INIT_PID))); // 已被收养的子
            table[5].as_mut().unwrap().adopted = true;
            table[7] = Some(make_record(22, 7, Some(21))); // 它的娃
        }
        full_reap(5); // 被收养孤儿退出（防御回收路径的表级效果）

        let table = PROCESS_TABLE.lock();
        assert!(table[5].is_none());
        let grand = table[7].as_ref().expect("grandchild survives");
        assert_eq!(grand.parent, Some(init_pid()));
        assert!(grand.adopted);
        drop(table);
        let mut table = PROCESS_TABLE.lock();
        *table = [const { None }; MAX_PROCESSES];
    }

    // ── 第八刀：capability bitmask 升格 ─────────────────────────────

    #[test]
    fn capability_flag_mapping_and_abi_bits() {
        use zero_abi::cap::{CAP_ALL, CAP_BLOCK_DEV, CAP_MMIO, CAP_SPAWN_SVC};
        // 位值即 ABI 契约（与 zero-abi::cap 双向钉死，漂移即编译期外红）。
        assert_eq!(CAP_MMIO, 1 << 0);
        assert_eq!(CAP_BLOCK_DEV, 1 << 1);
        assert_eq!(CAP_SPAWN_SVC, 1 << 2);
        assert_eq!(CAP_ALL, CAP_MMIO | CAP_BLOCK_DEV | CAP_SPAWN_SVC);
        // 遗留布尔映射：privileged=true ⇒ 全位；false ⇒ 空位图。
        assert_eq!(capabilities_from_flag(true), CAP_ALL);
        assert_eq!(capabilities_from_flag(false), 0);
        // blkdrv 内核直通数据面的依赖：全位必含 CAP_BLOCK_DEV。
        assert_ne!(capabilities_from_flag(true) & CAP_BLOCK_DEV, 0);
        // launchd 拉起服务的依赖：全位必含 CAP_SPAWN_SVC。
        assert_ne!(capabilities_from_flag(true) & CAP_SPAWN_SVC, 0);
    }

    // ── 第九刀：WaitSpec 目标集合化（wait 精确匹配 / 误投递回归）────

    #[test]
    fn wait_spec_matches_only_its_target() {
        let a = ProcessId::new(33);
        let b = ProcessId::new(34);
        // Any 覆盖一切子；Pid 只覆盖自身——完整 64 位原始值比较。
        assert!(WaitSpec::Any.matches(a));
        assert!(WaitSpec::Any.matches(b));
        assert!(WaitSpec::Pid(a).matches(a));
        assert!(!WaitSpec::Pid(a).matches(b));
        assert!(!WaitSpec::Pid(b).matches(a));
    }

    #[test]
    fn misdelivery_regression_parent_waiting_a_not_woken_by_b() {
        // 第七刀缺口回归（任务三指定场景）：父 wait_pid(A) 挂起（登记
        // Pid(A)），子 B 先退出。bool 单标记时代：标记被 B 的 Exit 取走
        // ⇒ B 的结果被写进父帧（张冠李戴）+ B 尸体被误消费 + 父带着
        // 已消费的登记假醒、A 死时再无人唤醒。目标集合化后：
        let a = ProcessId::new(40);
        let b = ProcessId::new(41);
        let mut registration = Some(WaitSpec::Pid(a));
        // ① B 先退：决策 false —— 登记原样保留，B 尸体留表待按需收取。
        assert!(!wait_wake_decision(registration, b));
        assert_eq!(
            registration,
            Some(WaitSpec::Pid(a)),
            "mismatched exit must not consume the registration"
        );
        // ② A 后退：命中 ⇒ 唤醒；实现侧 take 后登记清空。
        assert!(wait_wake_decision(registration, a));
        registration = None; // 模拟 exit_current_with_status 取走登记
        // ③ 二次事件（假想虚假唤醒/stale 投递）：登记已空，绝不再醒。
        assert!(!wait_wake_decision(registration, a));
        assert!(!wait_wake_decision(registration, b));
    }

    #[test]
    fn any_target_wakes_on_first_exiting_child_then_consumed() {
        // wait(0) 语义不变：任一子先退即唤醒（僵尸优先于活子的 POSIX
        // 行为由扫描面保证，见 targeted_scan_* 测试）。
        let a = ProcessId::new(50);
        let b = ProcessId::new(51);
        let mut registration = Some(WaitSpec::Any);
        assert!(wait_wake_decision(registration, b), "wait(0) wakes on any child");
        assert!(wait_wake_decision(registration, a));
        registration = None;
        assert!(!wait_wake_decision(registration, a));
    }

    #[test]
    fn targeted_scan_ignores_sibling_zombie_in_a_b_scenario() {
        // 扫描面配合：父只 wait(A)。B 已先退成尸（exit 路径正确地没
        // 唤醒、没误收）⇒ 此刻 wait(A) 必须 Block（A 还活着），且绝不
        // 能把 B 当成可收对象；wait(B) 则可直接快路径收 B。
        let t = table_of(&[
            pv(0, P, None, ProcessState::Running, None),
            pv(1, 60, Some(P), ProcessState::Zombie, Some(66)), // B 先退
            pv(2, 61, Some(P), ProcessState::Running, None),    // A 活着
        ]);
        assert_eq!(wait_scan(caller(), 61, &t), WaitDecision::Block);
        assert_eq!(
            wait_scan(caller(), 60, &t),
            WaitDecision::Collect { slot: 1, pid: ProcessId::new(60), code: 66 }
        );
        // A 也退出后：wait(A) 收 A 自身的码；两具尸体互不串线。
        let t2 = table_of(&[
            pv(0, P, None, ProcessState::Running, None),
            pv(1, 60, Some(P), ProcessState::Zombie, Some(66)),
            pv(2, 61, Some(P), ProcessState::Zombie, Some(33)),
        ]);
        assert_eq!(
            wait_scan(caller(), 61, &t2),
            WaitDecision::Collect { slot: 2, pid: ProcessId::new(61), code: 33 }
        );
        assert_eq!(
            wait_scan(caller(), 60, &t2),
            WaitDecision::Collect { slot: 1, pid: ProcessId::new(60), code: 66 }
        );
    }

    // ── 第九刀：pid generation 防复用 ──────────────────────────────────

    #[test]
    fn pid_seq_walks_monotonically_inside_generation() {
        // 引导初值 2 起，代内步进严格 +1 直到 seq 上界；首个分配值恰为
        // INIT_PID=2 的约定由此钉死（NEXT_PID 初值 = PID_SEQ_FIRST）。
        assert_eq!(PID_SEQ_FIRST, 2);
        let mut cur = PID_SEQ_FIRST;
        for expected in (PID_SEQ_FIRST + 1)..=PID_SEQ_LAST {
            let nxt = next_pid_raw(cur);
            assert_eq!(nxt, expected);
            cur = nxt;
        }
        // seq 耗尽：代数 +1，seq 回到 FIRST——reserved seq 0/1 永不复用。
        assert_eq!(next_pid_raw(cur), 0x1_0002);
    }

    #[test]
    fn pid_generation_wrap_skips_reserved_seqs_every_generation() {
        // 新代起点与代间衔接：任意代边界处都跳过 0/1。
        assert_eq!(next_pid_raw(0x0000_FFFF), 0x0001_0002);
        assert_eq!(next_pid_raw(0x0001_FFFF), 0x0002_0002);
        assert_eq!(next_pid_raw(0x7FFF_FFFF), 0x8000_0002);
        assert_eq!(next_pid_raw(0x0001_0002), 0x0001_0003);
    }

    #[test]
    fn pid_allocation_never_reuses_across_two_generations() {
        // 连续分配 > 2 个代（140_000 > 2×65534）：全值唯一，且观测窗口
        // 内始终低于 pack_wait_result 的 32 位 pid 承载上限。
        let mut seen = std::collections::HashSet::new();
        let mut cur = PID_SEQ_FIRST;
        for _ in 0..140_000usize {
            assert!(seen.insert(cur), "pid {} allocated twice", cur);
            cur = next_pid_raw(cur);
        }
        assert!(cur < (1u64 << 32), "pid budget must stay within packing capacity");
    }

    #[test]
    fn stale_pid_from_previous_generation_does_not_match() {
        // stale 免疫端到端：第 0 代用掉的 seq=42 与回绕后新代的 seq=42
        // 是不同完整 pid —— wake/wait 全值比较不会把旧引用错认新进程
        // （wake(ProcessId(stale)) 打不中新 pid；wait(stale) 也收不到它）。
        let stale = 42u64; // gen 0
        let mut cur = PID_SEQ_FIRST;
        while cur != PID_SEQ_LAST {
            cur = next_pid_raw(cur);
        }
        cur = next_pid_raw(cur); // 跨入 gen 1（0x1_0002）
        assert_eq!(cur >> PID_SEQ_BITS, 1);
        let fresh_same_seq = (cur & !PID_SEQ_MASK) | 42;
        assert_eq!(fresh_same_seq, 0x1_002a);
        assert_ne!(ProcessId::new(stale), ProcessId::new(fresh_same_seq));
        // 匹配层面：等 stale 的人不会被新代同 seq 进程惊醒，反之亦然。
        assert!(!WaitSpec::Pid(ProcessId::new(stale)).matches(ProcessId::new(fresh_same_seq)));
        assert!(!WaitSpec::Pid(ProcessId::new(fresh_same_seq)).matches(ProcessId::new(stale)));
    }

    // ── 第九刀：pending_signals 位图（设置/取用）─────────────────
    // ── 第九刀：pending_signals 位图（设置/取用）─────────────────────

    #[test]
    fn fault_signal_delivery_sets_bitmap_and_exit_code() {
        use zero_abi::signals::{fatal_exit_code, signal_bit, SIGBUS, SIGSEGV};
        let _g = TABLE_GUARD.lock().unwrap();
        {
            let mut table = PROCESS_TABLE.lock();
            *table = [const { None }; MAX_PROCESSES];
            table[9] = Some(make_record(30, 9, Some(P)));
        }
        // SIGSEGV 投递：返回 POSIX 死因编码 -11，位图置 bit(11-1)=bit10
        assert_eq!(deliver_fatal_signal(9, SIGSEGV), fatal_exit_code(SIGSEGV));
        assert_eq!(deliver_fatal_signal(9, SIGSEGV), -11);
        {
            let table = PROCESS_TABLE.lock();
            let rec = table[9].as_ref().expect("record kept for audit");
            assert_eq!(rec.pending_signals, signal_bit(SIGSEGV));
        }
        // 另一信号叠加为 OR 累积，不覆盖既有位
        deliver_fatal_signal(9, SIGBUS);
        {
            let table = PROCESS_TABLE.lock();
            let rec = table[9].as_ref().expect("record kept");
            assert_eq!(
                rec.pending_signals,
                signal_bit(SIGSEGV) | signal_bit(SIGBUS)
            );
            assert_eq!(rec.exit_code, None, "投递只登记位图；exit_code 由 exit 路径写入");
        }
        // 清场（仍持 _g）：还原空表，避免影响其他测试对表状态的假设
        {
            let mut table = PROCESS_TABLE.lock();
            *table = [const { None }; MAX_PROCESSES];
        }
    }
}
