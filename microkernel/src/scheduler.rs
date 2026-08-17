use core::arch::asm;
use spin::Mutex;
use zero_abi::ProcessId;

use crate::mm::address_space::AddressSpace;
use crate::process::{self, ProcessState};

static RUNQUEUE: Mutex<RunQueue> = Mutex::new(RunQueue::new());
static CURRENT_SLOT: Mutex<Option<usize>> = Mutex::new(None);

pub fn init() {
    RUNQUEUE.lock().clear();
    *CURRENT_SLOT.lock() = None;
}

pub fn enqueue(pid: ProcessId) {
    crate::info!("scheduler::enqueue: pid={}", pid.raw());
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
    crate::info!("scheduler::dispatch: pid={} slot={}", pid.raw(), next_slot);
    process::set_state(pid, ProcessState::Running);

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
        if let Some(space) = process::address_space(next_slot) {
            space.activate();
        } else {
            AddressSpace::deactivate();
        }

        // Now that we have a current slot, enable interrupts and
        // program the first timer slice.
        crate::arch::enable_interrupts();
        crate::arch::program_next_tick();
    }

    if let Some((space, tf)) = process::first_run_context(next_slot) {
        unsafe {
            let kernel_sp = process::kernel_stack_top(next_slot);
            asm!("mov sp, {0}", in(reg) kernel_sp);
            crate::arch::enter_user_mode(&space, tf);
        }
    }

    let next_ctx = unsafe { process::context_ptr(next_slot) };
    let current_ctx = current_slot.map(|slot| unsafe { process::context_ptr(slot) });

    unsafe { crate::arch::context_switch(current_ctx, next_ctx) }
}

fn idle() -> ! {
    // TODO: 低功耗等待中断 (WFI)
    loop {
        core::hint::spin_loop();
    }
}

struct RunQueue {
    buf: [Option<ProcessId>; 64],
    head: usize,
    tail: usize,
}

impl RunQueue {
    const fn new() -> Self {
        Self {
            buf: [None; 64],
            head: 0,
            tail: 0,
        }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.buf.fill(None);
    }

    fn push(&mut self, pid: ProcessId) {
        self.buf[self.tail % self.buf.len()] = Some(pid);
        self.tail = (self.tail + 1) % self.buf.len();
    }

    fn pop(&mut self) -> Option<ProcessId> {
        let pid = self.buf[self.head % self.buf.len()];
        if pid.is_some() {
            self.buf[self.head % self.buf.len()] = None;
            self.head = (self.head + 1) % self.buf.len();
        }
        pid
    }
}

pub fn current_slot() -> usize {
    (*CURRENT_SLOT.lock()).expect("scheduler: no current slot")
}

pub fn current_slot_opt() -> Option<usize> {
    *CURRENT_SLOT.lock()
}

pub fn reschedule() -> ! {
    if let Some(pid) = RUNQUEUE.lock().pop() {
        dispatch(pid)
    } else {
        idle()
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
