use spin::Mutex;
use zero_abi::ProcessId;

use alloc::vec;
use alloc::vec::Vec;
use crate::mm::address_space::AddressSpace;
use crate::process::{self, ProcessState};

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
static CURRENT_SLOT: Mutex<Option<usize>> = Mutex::new(None);

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
static PROC_LEVEL: [core::sync::atomic::AtomicU8; 64] =
    [const { core::sync::atomic::AtomicU8::new(0) }; 64];

/// 内核单调 tick 计数（每次定时器中断 +1）。睡眠唤醒的时钟基准。
static TICK_NOW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
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
static SLICE_USED: [core::sync::atomic::AtomicU32; 64] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 64];

pub fn init() {
    RUNQUEUE.lock().clear();
    *CURRENT_SLOT.lock() = None;
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
    loop {
        let next = RUNQUEUE.lock().pop();
        match next {
            Some(pid) => dispatch(pid),
            None => idle(),
        }
    }
}

fn dispatch(pid: ProcessId) -> ! {
    let next_slot = process::slot_for_pid(pid).expect("scheduler: unknown pid");
    process::set_state(pid, ProcessState::Running);
    // 新调度周期：时间片清零（SLICE_TICKS 内不被强制抢占）。
    SLICE_USED[next_slot].store(0, core::sync::atomic::Ordering::Relaxed);

    // 持锁窗口：读出上一个 current 并写入新的，单语句块结束即释放。
    let current_slot = {
        let mut current = CURRENT_SLOT.lock();
        let previous = *current;
        *current = Some(next_slot);
        previous
    };

    // crate::arch::fpu_set_lazy_gate(); ← 二分排查：暂缓切换点降门

    if let Some(slot) = current_slot {
        // 仅 Running → Runnable。Blocked（阻塞等 IPC）/ Dying 的进程
        // 绝不能被 dispatch 的换出逻辑"复活"——否则状态声称可运行却
        // 不在就绪队列，造成永久饥饿。
        if process::state_slot(slot) == Some(ProcessState::Running) {
            process::set_state_slot(slot, ProcessState::Runnable);
        }
    }

    unsafe {
        // 地址空间激活与下一 tick 编程（不进用户态，此处允许持库调用；
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
        crate::arch::program_next_tick();
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
    // ⚠ 第十一刀关键修复：空转前把异常保存目标切到 idle scratch 帧。
    // 否则 TPIDR_EL1 仍指向最后那个 Blocked 进程的帧——idle 窗口的
    // 每个定时器中断都会用 idle 的 EL1 现场覆盖它的保存区，进程被
    // 唤醒后恢复出垃圾上下文（sleepdemo 实机抓获）。
    unsafe {
        crate::arch::set_tpidr_el1(process::idle_trap_frame() as usize);
    }
    // 无可运行进程：WFI 休眠等待中断（对照 Linux do_idle 的 default_idle）。
    // 唤醒源：定时器 tick（idle 循环里必须持续重编程，否则睡死）。
    //
    // ⚠ 此处运行于 EL1、IRQ 屏蔽状态 —— WFI 在 IRQ 屏蔽时不休眠！
    // 因此先解除 IRQ 屏蔽再 WFI，唤醒后立即重新屏蔽（与内核全程屏蔽
    // IRQ 的锁纪律兼容：屏蔽恢复后才可能触碰任何共享结构）。
    loop {
        unsafe {
            crate::arch::program_next_tick();
            core::arch::asm!(
                "msr daifclr, #2", // 解除 IRQ 屏蔽（bit1 = I）
                "wfi",
                "msr daifset, #2", // 立即重新屏蔽，之后才安全触碰共享态
                options(nostack)
            );
        }
        // 被唤醒：可能有进程入队。重新调度。
        let next = { RUNQUEUE.lock().pop() };
        if let Some(pid) = next {
            dispatch(pid)
        }
    }
}

/// 单级环形队列（原第七代 RunQueue 环，第十一刀起作为 MLFQ 的每级载体）。
/// 容量与 PROCESS_TABLE（64）严格一致：任一时刻每个进程最多在某**一级**
/// 中出现一次（状态机不变量；跨级重复由 push_at 前的状态检查排除）。
struct RunQueue {
    buf: [Option<ProcessId>; 64],
    head: usize,
    tail: usize,
    len: usize,
}

const RUNQUEUE_CAPACITY: usize = 64;

impl RunQueue {
    const fn new() -> Self {
        Self {
            buf: [None; 64],
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
    ///  1. 容量与进程槽位上限相等（64 = 64），队列满 ⇒ 同一 pid 重复
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

pub fn current_slot() -> usize {
    // 最短持锁窗口：仅一次读。
    (*CURRENT_SLOT.lock()).expect("scheduler: no current slot")
}

pub fn current_slot_opt() -> Option<usize> {
    // 最短持锁窗口：仅一次读。
    *CURRENT_SLOT.lock()
}

/// 若 CURRENT_SLOT 正指向该槽（典型场景：进程自退出），清空之。
/// 由 process::remove_slot 在槽位回收后调用，避免后续 dispatch 把
/// 已被回收的槽当作"上一个进程"置回 Runnable。
pub fn clear_current_slot_if(slot: usize) {
    let mut current = CURRENT_SLOT.lock();
    if *current == Some(slot) {
        *current = None;
    }
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
    if let Some(pid) = process::pid_at_slot(slot) {
        process::set_state_slot(slot, ProcessState::Runnable);
        // MLFQ（第十一刀）：主动让出保留当前级别——协作式让出不因
        // 礼让而升级，防止 CPU 密集进程借高频 yield 钉死最高级。
        let level = proc_level(slot);
        RUNQUEUE.lock().push_at(pid, level);
    }
    reschedule()
}

pub fn exit_current() -> ! {
    let slot = current_slot();
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
        if process::state(pid) == Some(ProcessState::Blocked) {
            process::set_state(pid, ProcessState::Runnable);
            enqueue(pid); // 唤醒即最高级：交互/定时器路径的延迟最优
        }
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
    {
        let mut q = SLEEP_QUEUE.lock();
        assert!(
            q.len() < SLEEP_QUEUE_CAP,
            "sleep queue full: {} entries",
            q.len()
        );
        // 升序插入（到期扫描依赖队首最小 wake_at）
        let pos = q.partition_point(|e| e.wake_at <= start + ticks);
        q.insert(pos, SleepEntry { wake_at: start + ticks, start, pid });
    }
    block_current()
}

pub fn block_current() -> ! {
    let slot = current_slot();
    process::set_state_slot(slot, ProcessState::Blocked);
    reschedule()
}

/// 唤醒一个阻塞进程：Blocked → Runnable 并入队。非 Blocked 状态
/// （已可运行/已退出）为幂等 no-op，防止重复入队破坏状态机不变量。
pub fn wake(pid: ProcessId) {
    if process::state(pid) != Some(ProcessState::Blocked) {
        return;
    }
    process::set_state(pid, ProcessState::Runnable);
    enqueue(pid);
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
        for n in 0..64 {
            q.push(pid(n));
        }
        assert_eq!(q.len, RUNQUEUE_CAPACITY);
        // 满员后 pop 一个再 push 一个
        assert_eq!(q.pop(), Some(pid(0)));
        q.push(pid(64));
        assert_eq!(q.pop(), Some(pid(1)));
    }

    #[test]
    #[should_panic(expected = "runqueue full")]
    fn push_full_asserts() {
        let mut q = RunQueue::new();
        for n in 0..64 {
            q.push(pid(n));
        }
        q.push(pid(65)); // 第 65 个 → 必须触发 assert
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