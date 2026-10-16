use spin::Mutex;
use zero_abi::ProcessId;

use crate::mm::address_space::AddressSpace;
use crate::process::{self, ProcessState};
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

// ═══════════════════════════════════════════════════════════════════════
// 锁纪律（单核 spin::Mutex；内核态全程屏蔽 IRQ，仅 EL0 经 SPSR 打开中断）
//
// 1. 任何 lock() 产生的 MutexGuard 都不得活过「不返回」调用
//    （dispatch / context_switch / enter_user_mode / restore_frame 及
//    eret 路径）：这些调用永不返回，若持锁进入，锁会在用户态执行期间
//    一直被持有，下一轮定时器中断 yield 时对同一把锁自旋死锁。
//
// 2. reschedule() 取 RUNQUEUE 必须用「语句作用域」写法：
//        let next = { RUNQUEUE.lock().pop() };
//    `if let Some(pid) = RUNQUEUE.lock().pop() { dispatch(pid) }` 会让
//    临时量 Guard 存活到整个 if-let 语句结束，而 dispatch 是 noreturn，
//    锁必泄漏到用户态（2025-08-19 已修复的实机死锁）。
//
// 3. kill/exit 路径（process::remove_slot）：进程表锁只在「取出记录并
//    清槽」的语句块内持有；地址空间销毁/页表回收在锁外执行（记录是
//    Copy，take() 后 Guard 立即释放）——避免持表锁进入分配器（分配器
//    上锁会导致表锁→分配器锁 与 分配器→表锁 的潜在反转）。
//
// 4. 最短持锁窗口：current_slot() / current_slot_opt() 只持锁读一个
//    usize；enqueue / pop 各持锁一进一出。窗口内禁止任何打印、调度、
//    分配等可能重新入锁的操作。
// ═══════════════════════════════════════════════════════════════════════

static RUNQUEUE: Mutex<Mlfq> = Mutex::new(Mlfq::new());
/// 每核"当前进程槽位"。SMP（第十四刀）：核间无共享此状态——各核的
/// TPIDR_EL1 各自指向本核当前帧，本数组与之严格同步（dispatch 写入 /
/// clear_current_slot_if 清除）。
static CURRENT_SLOT: [Mutex<Option<usize>>; crate::arch::smp::MAX_CPUS] =
    [const { Mutex::new(None) }; crate::arch::smp::MAX_CPUS];

/// 每核 idle 标志：wake() 据此决定是否向该核广播 RESCHED SGI。
static CPU_IDLE: [core::sync::atomic::AtomicBool; crate::arch::smp::MAX_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; crate::arch::smp::MAX_CPUS];

// ═══ 第十一刀：多级反馈队列（MLFQ）与睡眠唤醒 ═══════════════════════
//
// 队列结构：LEVELS 级环形队列，级别 0 最高优先。时间片随级别指数加倍
// （4/8/16/32 tick）——交互型进程（频繁阻塞/让出）滞留高级别获得短延迟，
// CPU 密集型进程自然沉降到低级别换取长切片高吞吐（对照 Linux O(1)/CFQ
// 与教科书 MLFQ 折中）。防饥饿：每 BOOST_EVERY_TICKS tick 做一次全局
// 优先级提升（所有 Runnable 槽位归零），长跑重负载无法永久压死新到的
// 交互任务。
//
// 降级时机：on_tick_consume（tick 中断上下文）发现当前级时间片耗尽即
// 立即降级并记账清零；随后 yield_current 按新级别入队。升级只经由
// 主动阻塞后唤醒（wake → 归零入最高级）与周期 boost，无其他旁路。

/// MLFQ 级数（0 = 最高优先级）。
pub const MLFQ_LEVELS: usize = 4;
/// 各级基础时间片：SLICE_TICKS << level。
pub const BOOST_EVERY_TICKS: u64 = 200;
/// 睡眠队列单次注册上限防御值（对照 MAX_QUEUE 的防御哲学）。
const SLEEP_QUEUE_CAP: usize = 128;

/// 每槽当前 MLFQ 级别（u8 原子数组避免持锁；tick 路径在 IRQ 内）。
static PROC_LEVEL: [core::sync::atomic::AtomicU8; crate::process::MAX_PROCESSES] =
    [const { core::sync::atomic::AtomicU8::new(0) }; crate::process::MAX_PROCESSES];

/// 内核单调 tick 计数（每次定时器中断 +1）。睡眠唤醒的时钟基准。
static TICK_NOW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// 软看门狗：连续无 Running 进程的 tick 数（第十四刀，逐核记账）。
static IDLE_STREAK: [core::sync::atomic::AtomicU32; crate::arch::smp::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; crate::arch::smp::MAX_CPUS];
/// 告警阈值：600 tick（约 60s @100Hz；对照 Linux kernel panic 10s 的
/// 宽松化——本内核 idle 属常态而非故障）。
const WATCHDOG_IDLE_TICKS: u32 = 600;
/// 上一次全局优先级提升发生的 tick。
static LAST_BOOST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

struct SleepEntry {
    /// 唤醒时刻（TICK_NOW 语义）。
    wake_at: u64,
    /// 入睡时刻：elapsed = 唤醒 tick - start，实机断言「真睡眠」用。
    start: u64,
    pid: ProcessId,
}
static SLEEP_QUEUE: Mutex<Vec<SleepEntry>> = Mutex::new(Vec::new());
static SLEEP_TRACE_BUDGET: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// 当前内核单调 tick 快照（睡眠返回值的计算基准）。
pub fn tick_now() -> u64 {
    TICK_NOW.load(core::sync::atomic::Ordering::Relaxed)
}

fn slice_for_level(level: usize) -> u32 {
    SLICE_TICKS << level.min(MLFQ_LEVELS - 1)
}

fn proc_level(slot: usize) -> usize {
    (PROC_LEVEL[slot].load(core::sync::atomic::Ordering::Relaxed) as usize).min(MLFQ_LEVELS - 1)
}

/// 时间片耗尽后的级别迁移（纯函数，主机测试钉死）。
fn next_level_after_slice(level: usize) -> usize {
    (level + 1).min(MLFQ_LEVELS - 1)
}

/// A voluntary yield consumed CPU too: retaining level 0 lets a polling daemon
/// yield/requeue itself forever ahead of a preempted level-1 init process.
/// Demote one level exactly like a cooperative timeslice boundary. Processes
/// that truly block are still promoted by wake()/enqueue().
fn next_level_after_yield(level: usize) -> usize {
    (level + 1).min(MLFQ_LEVELS - 1)
}

/// 长操作分块让出点（第十一刀）：内核长循环（fork 地址空间克隆、execve
/// ELF 装载等）每 CHUNK 次迭代调用一次。短暂解除 IRQ 屏蔽使挂起的定时
/// 中断得到服务（tick 推进、睡眠唤醒、控制台活性），随即恢复屏蔽。
/// 锁纪律：只能在确认未持有任何 MutexGuard 的间隙调用——IRQ 处理路径
/// 会锁 CURRENT_SLOT / PROCESS_TABLE / RUNQUEUE / SLEEP_QUEUE。
pub fn chunk_yield_point() {
    // 安全闸（第十一刀实机排障结论）：调度器启动前 TPIDR_EL1 尚未武装，
    // 异常存根以它定位保存目标——此时放行中断会让 stub 以空帧跑通全程，
    // 最终在 restore_frame(0) 处崩塌。内核 spawn 路径（ELF 装载循环）
    // 恰在 scheduler::run 之前运行，必须直行不放行。
    if !SCHED_STARTED.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    unsafe {
        core::arch::asm!(
            "msr daifclr, #2", // 解除 IRQ 屏蔽：挂起中断立即注入
            "msr daifset, #2", // 恢复屏蔽后才安全继续触碰共享态
            options(nostack)
        );
    }
}

/// 调度器主循环启动标志（chunk_yield_point 的安全闸）。
static SCHED_STARTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// 时间片长度（timer tick 数）。当前进程连续占用超过该数量 tick 后
/// 才被强制让出——单进程独跑时消除每 tick 一次的无效上下文切换
/// （对照 Linux CFS 的 sched_latency / XNU timeslice 概念）。
pub const SLICE_TICKS: u32 = 4;

/// 每槽已消耗 tick 记账。u32 原子数组避免持锁（tick 路径在 IRQ 内）。
static SLICE_USED: [core::sync::atomic::AtomicU32; crate::process::MAX_PROCESSES] =
    [const { core::sync::atomic::AtomicU32::new(0) }; crate::process::MAX_PROCESSES];

pub fn init() {
    RUNQUEUE.lock().clear();
    for slot in CURRENT_SLOT.iter() {
        *slot.lock() = None;
    }
}

pub fn enqueue(pid: ProcessId) {
    crate::debug!("scheduler::enqueue: pid={}", pid.raw());
    // 持锁窗口：单次 push。新入队进程一律进最高级（fork/spawn/wake 的
    // 交互友好语义；yield 路径走 push_at_current_level 保留级别）。
    if let Some(slot) = process::slot_for_pid(pid) {
        PROC_LEVEL[slot].store(0, core::sync::atomic::Ordering::Relaxed);
    }
    RUNQUEUE.lock().push_at(pid, 0);
}

pub fn run() -> ! {
    crate::info!("scheduler::run: entering main loop");
    SCHED_STARTED.store(true, core::sync::atomic::Ordering::Release);
    schedule_loop()
}

/// 副核入口（第十四刀阶段 1）：主核已置 SCHED_STARTED，直接进循环。
/// 全局 Mlfq 跨核消费由 RUNQUEUE 互斥保护；pop 互斥保证同一 pid 同一
/// 时刻只被一个核取走。
pub fn secondary_run() -> ! {
    schedule_loop()
}

fn schedule_loop() -> ! {
    loop {
        let next = RUNQUEUE.lock().pop();
        match next {
            Some(pid) => dispatch(pid),
            None => idle(),
        }
    }
}

fn dispatch(pid: ProcessId) -> ! {
    // Atomic Runnable->Running claim makes stale/duplicate queue entries benign.
    let cpu = my_cpu() as u8;
    let Some(next_slot) = process::claim_runnable(pid, cpu) else {
        crate::debug!("scheduler: stale runqueue entry pid={}", pid.raw());
        reschedule()
    };
    debug_assert_eq!(process::owner_cpu(next_slot), Some(cpu));
    // 新调度周期：时间片清零（SLICE_TICKS 内不被强制抢占）。
    SLICE_USED[next_slot].store(0, core::sync::atomic::Ordering::Relaxed);

    // CPU ownership hand-off is completed by yield/block/exit *before* a pid
    // becomes runnable elsewhere. dispatch only claims the incoming slot; it must
    // never mutate the previous slot's global state because that process may
    // already be Running on another CPU.
    {
        let mut current = CURRENT_SLOT[my_cpu()].lock();
        *current = Some(next_slot);
    }
    CPU_IDLE[my_cpu()].store(false, core::sync::atomic::Ordering::Relaxed);

    // crate::arch::fpu_set_lazy_gate(); ← 二分排查：暂缓切换点降门

    unsafe {
        // 地址空间激活（不进用户态，此处允许持库调用；
        // 注意 dispatch 到这里为止不持有任何 Mutex）。
        if let Some(space) = process::address_space(next_slot) {
            space.activate();
        } else {
            AddressSpace::deactivate();
        }

        // 不在 EL1 打开中断：内核全程屏蔽 IRQ，只让 EL0 通过 SPSR 开中断
        // （异常入口硬件自动置 PSTATE.I=1）。理由：trap_entry → yield_current
        // 会锁 CURRENT_SLOT / PROCESS_TABLE，若 dispatch 在 first_run_context
        // 持锁窗口内被 IRQ 打断 → spin::Mutex 不可重入 → 单核死锁。
        // Periodic timer is independent of context switches. Re-arming here
        // postpones the deadline on every yield/dispatch and can starve ticks
        // forever under cooperative workloads. Only timer IRQ/init own CVAL.
    }

    if let Some((space, tf)) = process::first_run_context(next_slot) {
        unsafe {
            crate::arch::enter_user_mode(&space, tf);
        }
    }

    // 阻塞接收的 continuation：被唤醒的进程在重入用户态前完成挂起的
    // ReceiveMessage（把消息拷到用户缓冲、写回返回值）。complete_receive
    // 可能再次阻塞（虚假唤醒），noreturn 由其内部处理。
    if let Some(chan) = process::take_pending_recv(next_slot) {
        crate::syscalls::complete_receive(next_slot, chan);
    }

    let next_ctx = unsafe { process::context_ptr(next_slot) };

    // ⚠ 单一保存者契约：被打断进程的现场已由 trap_entry 在异常入口保存，
    // 这里只恢复下一进程，绝不再 save 当前寄存器（双保存曾用内核脏
    // 寄存器污染用户现场——见 arch::switch_to 文档）。
    unsafe { crate::arch::switch_to(next_ctx) }
}

fn idle() -> ! {
    let cpu = my_cpu();
    // Publish "no process owned by this PE" before abandoning its process stack.
    // IRQs are masked here, so no local exception can observe an intermediate
    // state.  Any future exception will target the per-CPU idle scratch frame.
    *CURRENT_SLOT[cpu].lock() = None;
    unsafe {
        crate::arch::set_tpidr_el1(process::idle_trap_frame_for(cpu) as usize);
    }
    CPU_IDLE[cpu].store(true, core::sync::atomic::Ordering::Release);

    // Critical SMP invariant: never WFI on KERNEL_STACKS[last_process].  That
    // process can migrate immediately and reuse the same stack on another PE.
    // Reset SP to a CPU-private 64KiB stack and branch (not call) into idle.
    unsafe { crate::arch::enter_idle_stack(cpu, __zero_scheduler_idle_loop) }
}

/// Runs exclusively on the per-CPU idle stack.  It is an extern-C branch target
/// so `arch::enter_idle_stack` can replace SP and discard any nested IRQ/Rust
/// frames accumulated before the CPU became idle.
extern "C" fn __zero_scheduler_idle_loop(cpu: usize) -> ! {
    debug_assert_eq!(cpu, my_cpu());
    unsafe {
        crate::arch::set_tpidr_el1(process::idle_trap_frame_for(cpu) as usize);
    }
    CPU_IDLE[cpu].store(true, core::sync::atomic::Ordering::Release);

    loop {
        unsafe {
            // Timer/SGI is the wake source.  Kernel shared-state manipulation
            // remains IRQ-masked; only the WFI window is interruptible.
            core::arch::asm!(
                "msr daifclr, #2",
                "wfi",
                "msr daifset, #2",
                options(nostack)
            );
        }
        CPU_IDLE[cpu].store(false, core::sync::atomic::Ordering::Relaxed);
        let next = { RUNQUEUE.lock().pop() };
        if let Some(pid) = next {
            dispatch(pid)
        }
        CPU_IDLE[cpu].store(true, core::sync::atomic::Ordering::Relaxed);
    }
}

/// 单级环形队列（原第七代 RunQueue 环，第十一刀起作为 MLFQ 的每级载体）。
/// 容量与 PROCESS_TABLE 上限（第十五刀起 256）严格一致：任一时刻每个
/// 进程最多在某**一级**中出现一次。
struct RunQueue {
    buf: [Option<ProcessId>; RUNQUEUE_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
}

const RUNQUEUE_CAPACITY: usize = crate::process::MAX_PROCESSES;

impl RunQueue {
    const fn new() -> Self {
        Self {
            buf: [None; RUNQUEUE_CAPACITY],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.len = 0;
        self.buf.fill(None);
    }

    /// 入队。满即 assert（而非返回 Err），理由：
    ///  1. 容量与进程槽位上限相等（当前 256 = 256），队列满 ⇒ 同一 pid 重复
    ///     入队（状态机错误）或内存被踩 —— 是内核 bug，不是可恢复的
    ///     用户错误；assert 在最接近 BUG 的位置暴露。
    ///  2. 返回 Err 需要所有调用点（yield_current / enqueue / fork /
    ///     spawn_service）选择「丢弃 or 重试」，单核下任何选择都会丢
    ///     掉一个本可运行进程（livelock）或掩盖状态机错误。
    fn push(&mut self, pid: ProcessId) {
        assert!(
            self.len < RUNQUEUE_CAPACITY,
            "runqueue full (len={}): duplicate enqueue or lost pop? pid={}",
            self.len,
            pid.raw()
        );
        self.buf[self.tail] = Some(pid);
        self.tail = (self.tail + 1) % self.buf.len();
        self.len += 1;
    }

    /// 出队。空返回 None。head/tail 环形推进，len 区分空/满。
    fn pop(&mut self) -> Option<ProcessId> {
        if self.len == 0 {
            return None;
        }
        let pid = self.buf[self.head].take();
        self.head = (self.head + 1) % self.buf.len();
        self.len -= 1;
        pid
    }
}

/// 多级反馈队列（第十一刀）：levels[0] 最高优先。pop 自高向低扫描，
/// 级内严格 FIFO——同级进程不因先后入队而获得不同配额。
struct Mlfq {
    levels: [RunQueue; MLFQ_LEVELS],
}

impl Mlfq {
    const fn new() -> Self {
        Self {
            levels: [const { RunQueue::new() }; MLFQ_LEVELS],
        }
    }

    fn clear(&mut self) {
        for level in &mut self.levels {
            level.clear();
        }
    }

    fn push_at(&mut self, pid: ProcessId, level: usize) {
        self.levels[level.min(MLFQ_LEVELS - 1)].push(pid);
    }

    fn pop(&mut self) -> Option<ProcessId> {
        for level in &mut self.levels {
            if let Some(pid) = level.pop() {
                return Some(pid);
            }
        }
        None
    }
}

#[inline(always)]
fn my_cpu() -> usize {
    crate::arch::smp::cpu_id()
}

pub fn current_slot() -> usize {
    // 最短持锁窗口：仅一次读。SMP：读本核槽位。
    (*CURRENT_SLOT[my_cpu()].lock()).expect("scheduler: no current slot")
}

pub fn current_slot_opt() -> Option<usize> {
    // 最短持锁窗口：仅一次读。
    *CURRENT_SLOT[my_cpu()].lock()
}

/// 若 CURRENT_SLOT 正指向该槽（典型场景：进程自退出），清空之。
/// 由 process::remove_slot 在槽位回收后调用，避免后续 dispatch 把
/// 已被回收的槽当作"上一个进程"置回 Runnable。
pub fn clear_current_slot_if(slot: usize) {
    // SMP：目标进程可能死在任意一核上——逐核清陈旧指向。
    for entry in CURRENT_SLOT.iter() {
        let mut current = entry.lock();
        if *current == Some(slot) {
            *current = None;
        }
    }
}

/// Release this CPU's claim on `slot` before making that process visible to
/// another CPU. IRQs are masked throughout kernel scheduling paths, so once the
/// local CURRENT_SLOT is cleared no local timer/SGI can mistake a process that
/// has migrated elsewhere for the process executing on this PE.
pub(crate) fn detach_current(slot: usize) {
    let cpu = my_cpu();
    let mut current = CURRENT_SLOT[cpu].lock();
    assert_eq!(
        *current,
        Some(slot),
        "scheduler: detach_current slot mismatch cpu={} expected={} current={:?}",
        cpu,
        slot,
        *current
    );
    *current = None;
}

pub fn reschedule() -> ! {
    // ⚠ 不能用 `if let Some(pid) = RUNQUEUE.lock().pop() { ... }`：
    // MutexGuard 临时量的生命周期会延续到整个 if-let 语句块结束，
    // dispatch() 又永不返回（eret 进用户态），锁会在用户态执行期间
    // 一直被持有 → 下一轮 yield_current 锁同一把锁 → 死锁自旋。
    let next = { RUNQUEUE.lock().pop() };
    match next {
        Some(pid) => dispatch(pid),
        None => idle(),
    }
}

pub fn yield_current() -> ! {
    let slot = current_slot();
    let cpu = my_cpu();
    // Keep ProcessState=Running and FRAME_OWNER=cpu until *after* SP leaves the
    // process kernel stack. Otherwise another PE may claim the same process and
    // enter a syscall on KERNEL_STACKS[slot] while this PE still runs reschedule.
    unsafe { crate::arch::enter_scheduler_stack(cpu, __zero_yield_handoff, slot, 0) }
}

extern "C" fn __zero_yield_handoff(cpu: usize, slot: usize, _unused: usize) -> ! {
    debug_assert_eq!(cpu, my_cpu());
    unsafe { crate::arch::set_tpidr_el1(process::idle_trap_frame_for(cpu) as usize) };
    detach_current(slot);
    if let Some(pid) = process::release_running(slot, cpu as u8) {
        let level = next_level_after_yield(proc_level(slot));
        PROC_LEVEL[slot].store(level as u8, core::sync::atomic::Ordering::Relaxed);
        SLICE_USED[slot].store(0, core::sync::atomic::Ordering::Relaxed);
        RUNQUEUE.lock().push_at(pid, level);
    }
    reschedule()
}

pub fn exit_current() -> ! {
    let slot = current_slot();
    let cpu = my_cpu();
    unsafe { crate::arch::enter_scheduler_stack(cpu, __zero_exit_handoff, slot, 0) }
}

extern "C" fn __zero_exit_handoff(cpu: usize, slot: usize, _unused: usize) -> ! {
    debug_assert_eq!(cpu, my_cpu());
    unsafe { crate::arch::set_tpidr_el1(process::idle_trap_frame_for(cpu) as usize) };
    detach_current(slot);
    process::release_owner_for_exit(slot, cpu as u8);
    process::remove_slot(slot);
    reschedule()
}

/// 阻塞当前进程（Blocked：不进就绪队列，直到 wake(pid)）。
/// 阻塞式 IPC 的基石：调用方必须**先**在任何表/通道里登记等待意图、
/// 释放自己的锁，再调用本函数（锁纪律第 1 条：Guard 不得跨 noreturn）。
/// timer tick 记账（第十一刀 tick 引擎，IRQ 上下文调用）：
/// 1. TICK_NOW 推进；睡眠队列到期者唤醒（Blocked → Runnable 最高级）；
/// 2. 周期性全局优先级提升（BOOST_EVERY_TICKS），MLFQ 防饥饿；
/// 3. 当前进程当前级时间片消耗；耗尽则**先降级再抢占**——返回 true。
/// 返回 false 表示中断直接返回原进程（省一次完整上下文切换）。
pub fn on_tick_consume() -> bool {
    let now = TICK_NOW.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;

    // ── 睡眠唤醒：持锁窗口仅做「摘除到期项」，状态迁移在锁外 ──
    let expired: Vec<(ProcessId, u64)> = {
        let mut q = SLEEP_QUEUE.lock();
        let mut due = Vec::new();
        while q.first().map_or(false, |front| front.wake_at <= now) {
            // 队列按 wake_at 升序维护（见 sleep_current 的插入位置）
            let entry = q.remove(0);
            // elapsed 在唤醒侧计算并直接写入睡眠者的陷阱帧 x0——
            // Blocked 进程无人触碰其帧，IRQ 上下文回写安全。
            unsafe {
                if let Some(slot) = process::slot_for_pid(entry.pid) {
                    (*process::trap_frame(slot)).regs[0] = now - entry.start;
                }
            }
            due.push((entry.pid, now - entry.start));
        }
        due
    };
    for (pid, _elapsed) in expired {
        if SLEEP_TRACE_BUDGET.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 32 {}
        wake(pid); // atomic Blocked->Runnable or latched register->block wake
    }

    // ── 防饥饿 boost：所有 Runnable 槽位级别归零（Running 不动——它
    // 正在执行，boost 后由下一次调度周期自然回到高级别竞争）──
    if now.saturating_sub(LAST_BOOST.load(core::sync::atomic::Ordering::Relaxed))
        >= BOOST_EVERY_TICKS
    {
        LAST_BOOST.store(now, core::sync::atomic::Ordering::Relaxed);
        for slot in 0..64usize {
            if process::state_slot(slot) == Some(ProcessState::Runnable) {
                PROC_LEVEL[slot].store(0, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    // ── 软看门狗（第十四刀）：连续 N tick 无 Running 进程即告警一次。
    // 单核 idle 属正常（对照 Linux cpuidle），告警阈值远高于正常空转；
    // 若系"全员阻塞且唤醒者缺席"类调度事故，此处留下第一现场日志。
    if current_slot_opt()
        .map(|slot| process::state_slot(slot) != Some(ProcessState::Running))
        .unwrap_or(true)
    {
        let streak = IDLE_STREAK[my_cpu()].fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
        if streak == WATCHDOG_IDLE_TICKS {
            crate::error!(
                "watchdog: no Running process for {} ticks (idle streak), tick_now={}",
                streak,
                now
            );
        }
        return false;
    }
    IDLE_STREAK[my_cpu()].store(0, core::sync::atomic::Ordering::Relaxed);

    // ── 当前进程时间片记账与降级 ──
    // 守门（第十一刀实机排障结论）：CURRENT_SLOT 在进程 Blocking 后
    // 保持陈旧指向（TPIDR_EL1 仍需它定位恢复帧）。idle 期间 tick 到来
    // 时若照旧记账，陈旧槽位的"时间片"会被空转耗尽并触发抢占——
    // 把一个 Blocked 睡眠者当 Running 复活入队（sleepdemo 双睡场景
    // 实机抓获：子进程睡眠被跳过、返回值垃圾）。只有存在真正的
    // Running 进程才允许记账与抢占判定。
    let Some(slot) = current_slot_opt() else {
        return false;
    };
    if process::state_slot(slot) != Some(ProcessState::Running) {
        return false;
    }
    let level = proc_level(slot);
    let used = SLICE_USED[slot].fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
    if used >= slice_for_level(level) {
        SLICE_USED[slot].store(0, core::sync::atomic::Ordering::Relaxed);
        PROC_LEVEL[slot].store(
            next_level_after_slice(level) as u8,
            core::sync::atomic::Ordering::Relaxed,
        );
        return true;
    }
    false
}

/// 睡眠当前进程 ticks 个 timer tick（号位 25 Sleepticks 的内核入口，
/// noreturn：注册后 block，由 tick 中断唤醒重入调度流；ticks==0 由
/// 系统调用分发层同步返回，不入本函数）。返回值经唤醒侧帧回写
/// （elapsed = 唤醒 tick - 入睡 tick ≥ ticks）。
/// 锁纪律：登记持锁语句块内完成；block_current 前必须已释放全部锁
/// （第 1 条纪律）。单核 IRQ 全屏蔽 ⇒ 登记-阻塞窗口内不可能被唤醒，
/// 无 lost-wakeup 窗口。
pub fn sleep_current(ticks: u64) -> ! {
    let start = tick_now();
    let pid = process::pid_at_slot(current_slot())
        .expect("scheduler: sleep_current without live process");
    if SLEEP_TRACE_BUDGET.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 16 {}
    {
        let mut q = SLEEP_QUEUE.lock();
        assert!(
            q.len() < SLEEP_QUEUE_CAP,
            "sleep queue full: {} entries",
            q.len()
        );
        // 升序插入（到期扫描依赖队首最小 wake_at）
        let pos = q.partition_point(|e| e.wake_at <= start + ticks);
        q.insert(
            pos,
            SleepEntry {
                wake_at: start + ticks,
                start,
                pid,
            },
        );
    }
    block_current()
}

pub fn block_current() -> ! {
    let slot = current_slot();
    let cpu = my_cpu();
    assert!(
        process::begin_block(slot, cpu as u8),
        "block_current: current process not Running"
    );
    // Wakeups in the register->block window latch wake_pending while the record
    // stays Running. Publish Blocked/Runnable only after the CPU-private stack
    // handoff, so no PE can reuse this process stack early.
    unsafe { crate::arch::enter_scheduler_stack(cpu, __zero_block_handoff, slot, 0) }
}

extern "C" fn __zero_block_handoff(cpu: usize, slot: usize, _unused: usize) -> ! {
    debug_assert_eq!(cpu, my_cpu());
    unsafe { crate::arch::set_tpidr_el1(process::idle_trap_frame_for(cpu) as usize) };
    detach_current(slot);
    match process::finish_block(slot, cpu as u8) {
        process::BlockFinish::Blocked => reschedule(),
        process::BlockFinish::Requeue(pid) => {
            enqueue(pid);
            reschedule()
        }
        process::BlockFinish::Invalid => panic!("block_current: invalid block handoff"),
    }
}

/// 唤醒一个阻塞进程：Blocked → Runnable 并入队。非 Blocked 状态
/// （已可运行/已退出）为幂等 no-op，防止重复入队破坏状态机不变量。
pub fn wake(pid: ProcessId) {
    match process::request_wake(pid) {
        process::WakeTransition::Enqueue { pid, slot } => {
            PROC_LEVEL[slot].store(0, core::sync::atomic::Ordering::Relaxed);
            RUNQUEUE.lock().push_at(pid, 0);
            kick_idle_cores();
        }
        process::WakeTransition::Pending | process::WakeTransition::Ignore => {}
    }
}

/// 广播 RESCHED SGI 给"其他在线且正 idle 的核"（第十四刀阶段 2）：
/// 目标核在 WFI 中被 SGI 打断 → reschedule 立即取队首，省掉等下一
/// tick 的延迟。忙核不需要踢——它跑完当前片自然回队列竞争。
fn kick_idle_cores() {
    if !crate::arch::smp::multi_core_active() {
        return;
    }
    let self_cpu = my_cpu();
    let mut mask: u8 = 0;
    for cpu in 0..crate::arch::smp::MAX_CPUS.min(crate::arch::smp::online_count()) {
        if cpu != self_cpu && CPU_IDLE[cpu].load(core::sync::atomic::Ordering::Acquire) {
            mask |= 1 << cpu;
        }
    }
    crate::arch::send_resched_sgi(mask);
}

/// RESCHED SGI 处理（trap.rs 的 IRQ 分支转交）：按被打断上下文分流——
/// 真 Running 进程被 SGI 打断 ⇒ 让出重排队（可能仍选中自己）；idle/
/// 陈旧上下文 ⇒ 直接重新决策（多半取到刚入队的进程）。
pub fn handle_resched_sgi() -> ! {
    match current_slot_opt() {
        Some(slot) if process::state_slot(slot) == Some(ProcessState::Running) => yield_current(),
        _ => reschedule(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u64) -> ProcessId {
        ProcessId::new(n)
    }

    #[test]
    fn push_pop_roundtrip() {
        let mut q = RunQueue::new();
        assert_eq!(q.pop(), None);
        q.push(pid(2));
        q.push(pid(3));
        assert_eq!(q.pop(), Some(pid(2)));
        assert_eq!(q.pop(), Some(pid(3)));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn clear_resets() {
        let mut q = RunQueue::new();
        q.push(pid(7));
        q.clear();
        assert_eq!(q.pop(), None);
        assert_eq!(q.len, 0);
    }

    #[test]
    fn wrap_around_preserves_order() {
        let mut q = RunQueue::new();
        for n in 0..60 {
            q.push(pid(100 + n));
        }
        for n in 0..60 {
            assert_eq!(q.pop(), Some(pid(100 + n)));
        }
        // 空后从环绕位置继续入队，顺序不破
        for n in 0..64 {
            q.push(pid(200 + n));
        }
        for n in 0..64 {
            assert_eq!(q.pop(), Some(pid(200 + n)));
        }
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn capacity_exact() {
        let mut q = RunQueue::new();
        for n in 0..RUNQUEUE_CAPACITY as u64 {
            q.push(pid(n));
        }
        assert_eq!(q.len, RUNQUEUE_CAPACITY);
        // 满员后 pop 一个再 push 一个
        assert_eq!(q.pop(), Some(pid(0)));
        q.push(pid(RUNQUEUE_CAPACITY as u64));
        assert_eq!(q.pop(), Some(pid(1)));
    }

    #[test]
    #[should_panic(expected = "runqueue full")]
    fn push_full_asserts() {
        let mut q = RunQueue::new();
        for n in 0..RUNQUEUE_CAPACITY as u64 {
            q.push(pid(n));
        }
        q.push(pid(RUNQUEUE_CAPACITY as u64 + 1)); // 超员 → 必须触发 assert
    }

    // ── 第十一刀：MLFQ 与睡眠队列 ──────────────────────────────────

    /// 高级队列严格优先于低级；级内 FIFO。
    #[test]
    fn mlfq_pop_prefers_higher_level() {
        let mut q = Mlfq::new();
        q.push_at(pid(2), 2);
        q.push_at(pid(1), 0);
        q.push_at(pid(3), 1);
        q.push_at(pid(4), 0);
        assert_eq!(q.pop(), Some(pid(1)));
        assert_eq!(q.pop(), Some(pid(4)));
        assert_eq!(q.pop(), Some(pid(3)));
        assert_eq!(q.pop(), Some(pid(2)));
        assert_eq!(q.pop(), None);
    }

    /// 越界级别钳位到最低级（防御性）。
    #[test]
    fn mlfq_push_clamps_level() {
        let mut q = Mlfq::new();
        q.push_at(pid(9), 99);
        assert_eq!(q.pop(), Some(pid(9)));
    }

    /// 时间片耗尽降级单调不回退，且封顶最低级。
    #[test]
    fn demotion_monotone_and_capped() {
        assert_eq!(next_level_after_slice(0), 1);
        assert_eq!(next_level_after_slice(1), 2);
        assert_eq!(next_level_after_slice(MLFQ_LEVELS - 1), MLFQ_LEVELS - 1);
    }

    /// 各级时间片指数加倍（4/8/16/32），封顶后不再增长。
    #[test]
    fn voluntary_yield_demotes_and_caps() {
        assert_eq!(next_level_after_yield(0), 1);
        assert_eq!(next_level_after_yield(1), 2);
        assert_eq!(next_level_after_yield(2), 3);
        assert_eq!(next_level_after_yield(3), 3);
        assert_eq!(next_level_after_yield(99), 3);
    }

    #[test]
    fn slice_doubles_per_level() {
        assert_eq!(slice_for_level(0), SLICE_TICKS);
        assert_eq!(slice_for_level(1), SLICE_TICKS * 2);
        assert_eq!(slice_for_level(2), SLICE_TICKS * 4);
        assert_eq!(slice_for_level(3), SLICE_TICKS * 8);
        assert_eq!(slice_for_level(99), SLICE_TICKS << (MLFQ_LEVELS - 1));
    }

    /// 睡眠队列升序插入：partition_point 找到的位置保持 wake_at 有序，
    /// 到期扫描（队首最小）语义依赖此不变式。
    #[test]
    fn sleep_queue_stays_sorted_on_insert() {
        let mut v: Vec<(u64, u64)> = Vec::new(); // (wake_at, start) 模拟
        let insert = |v: &mut Vec<(u64, u64)>, start: u64, ticks: u64| {
            let pos = v.partition_point(|e| e.0 <= start + ticks);
            v.insert(pos, (start + ticks, start));
        };
        insert(&mut v, 100, 5); // wake 105
        insert(&mut v, 100, 20); // wake 120
        insert(&mut v, 90, 10); // wake 100 → 应插到队首
        insert(&mut v, 100, 20); // wake 120 → 同刻排后（FIFO 稳定）
        let wakes: Vec<u64> = v.iter().map(|e| e.0).collect();
        assert_eq!(wakes, vec![100, 105, 120, 120]);
        assert_eq!(v[2].1, 100); // 先插入的 120 在前（start 区分）
    }
}
