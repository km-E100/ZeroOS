use spin::Mutex;
use zero_abi::ProcessId;

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

static RUNQUEUE: Mutex<RunQueue> = Mutex::new(RunQueue::new());
static CURRENT_SLOT: Mutex<Option<usize>> = Mutex::new(None);

pub fn init() {
    RUNQUEUE.lock().clear();
    *CURRENT_SLOT.lock() = None;
}

pub fn enqueue(pid: ProcessId) {
    crate::debug!("scheduler::enqueue: pid={}", pid.raw());
    // 持锁窗口：单次 push。
    RUNQUEUE.lock().push(pid);
}

pub fn run() -> ! {
    crate::info!("scheduler::run: entering main loop");
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
    crate::debug!("scheduler::dispatch: pid={} slot={}", pid.raw(), next_slot);
    process::set_state(pid, ProcessState::Running);

    // 持锁窗口：读出上一个 current 并写入新的，单语句块结束即释放。
    let current_slot = {
        let mut current = CURRENT_SLOT.lock();
        let previous = *current;
        *current = Some(next_slot);
        previous
    };

    if let Some(slot) = current_slot {
        process::set_state_slot(slot, ProcessState::Runnable);
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

    let next_ctx = unsafe { process::context_ptr(next_slot) };

    // ⚠ 单一保存者契约：被打断进程的现场已由 trap_entry 在异常入口保存，
    // 这里只恢复下一进程，绝不再 save 当前寄存器（双保存曾用内核脏
    // 寄存器污染用户现场——见 arch::switch_to 文档）。
    unsafe { crate::arch::switch_to(next_ctx) }
}

fn idle() -> ! {
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

/// 64 槽环形就绪队列。容量与 PROCESS_TABLE（64）严格一致：
/// 任一时刻每个进程最多在队列中出现一次（状态机不变量）。
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
        RUNQUEUE.lock().push(pid);
    }
    reschedule()
}

pub fn exit_current() -> ! {
    let slot = current_slot();
    process::remove_slot(slot);
    reschedule()
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
}