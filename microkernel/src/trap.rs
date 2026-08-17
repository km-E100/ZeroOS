use alloc::string::String;
use core::{arch::asm, fmt::Write};
use zero_abi::{
    syscall::{SysError, Syscall},
    ProcessId,
};

use crate::process::{self, ProcessState, TrapFrame};

#[repr(u64)]
pub enum TrapKind {
    Sync = 0,
    Irq = 1,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum FaultKind {
    Translation,
    Permission,
    AccessFlag,
    AddressSize,
    SyncExternal,
    Alignment,
    Unknown,
}

#[derive(Debug, Copy, Clone)]
struct FaultInfo {
    dfsc: u8,
    level: Option<u8>,
    kind: FaultKind,
}

#[derive(Debug, Copy, Clone)]
enum SyncExceptionKind {
    Svc,
    DataAbort(FaultInfo),
    InstructionAbort(FaultInfo),
    Other,
}

#[derive(Debug, Copy, Clone)]
struct DecodedEsr {
    ec: u8,
    iss: u32,
    kind: SyncExceptionKind,
    from_el0: bool,
}

#[derive(Debug, Copy, Clone)]
struct TrapContext {
    elr: u64,
    far: u64,
    slot: Option<usize>,
    pid: Option<ProcessId>,
}

#[no_mangle]
pub extern "C" fn __zero_trap_handler(frame: *mut TrapFrame, kind: u64) -> ! {
    crate::info!("__zero_trap_handler: kind={} frame={:p}", kind, frame);
    match TrapKind::from(kind) {
        TrapKind::Sync => {
            crate::info!("__zero_trap_handler: entering handle_sync");
            handle_sync(frame)
        }
        TrapKind::Irq => {
            crate::info!("__zero_trap_handler: entering handle_irq");
            handle_irq(frame)
        }
    }
}

fn handle_sync(frame: *mut TrapFrame) -> ! {
    let esr = read_esr_el1();
    crate::info!("handle_sync: ESR_EL1=0x{:016x}", esr);
    let decoded = decode_esr(esr);
    match decoded.kind {
        SyncExceptionKind::Svc => handle_svc(frame, esr),
        SyncExceptionKind::DataAbort(_) | SyncExceptionKind::InstructionAbort(_) => {
            let ctx = capture_trap_context();
            let message = format_sync_exception(&decoded, &ctx);
            crate::info!("{}", message);
            if decoded.from_el0 {
                terminate_faulting_process(&ctx)
            } else {
                trap_panic("kernel sync exception", esr)
            }
        }
        SyncExceptionKind::Other => {
            log_unknown_sync(esr);
            trap_panic("unknown sync exception", esr)
        }
    }
}

fn handle_irq(frame: *mut TrapFrame) -> ! {
    unsafe {
        let raw = crate::arch::acknowledge_irq();
        let irq = crate::arch::interrupt_number(raw);
        crate::info!(
            "handle_irq: raw=0x{:08x} irq={} is_timer={}",
            raw,
            irq,
            crate::arch::is_timer_irq(irq)
        );
        if crate::arch::is_timer_irq(irq) {
            crate::arch::program_next_tick();
            crate::arch::end_irq(raw);
            crate::info!("handle_irq: timer tick, yielding current");
            crate::scheduler::yield_current()
        } else {
            let handled = crate::drivers::handle_irq(irq);
            crate::arch::end_irq(raw);
            crate::info!("handle_irq: non-timer irq={} handled={}", irq, handled);
            if handled {
                crate::info!("handle_irq: restoring frame after handled IRQ");
                crate::arch::restore_frame(frame)
            } else {
                crate::info!("handle_irq: yielding current after unhandled IRQ");
                crate::scheduler::yield_current()
            }
        }
    }
}

fn handle_svc(frame: *mut TrapFrame, esr: u64) -> ! {
    let imm = (esr & 0xffff) as u16;
    unsafe {
        match imm {
            0 => {
                let regs = &mut (*frame).regs;
                let syscall = decode_syscall(regs);
                match syscall {
                    Some(call) => {
                        let result = crate::syscalls::handle(call, frame);
                        regs[0] = encode_result(result);
                        crate::arch::restore_frame(frame)
                    }
                    None => trap_panic("invalid syscall", esr),
                }
            }
            1 => crate::scheduler::yield_current(),
            2 => crate::scheduler::exit_current(),
            _ => trap_panic("unknown svc", esr),
        }
    }
}

fn decode_syscall(regs: &[u64; 31]) -> Option<Syscall> {
    let number = regs[0];
    match number {
        0 => Some(Syscall::SendMessage {
            channel: regs[1] as u32,
            user_message: regs[2] as usize,
        }),
        1 => Some(Syscall::ReceiveMessage {
            channel: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        2 => Some(Syscall::Fork),
        3 => {
            let entry_reg = regs[1];
            if entry_reg == 0 {
                return None;
            }
            Some(Syscall::Exec {
                entry: unsafe {
                    core::mem::transmute::<usize, zero_abi::ThreadEntry>(entry_reg as usize)
                },
                arg: regs[2],
            })
        }
        4 => Some(Syscall::Yield),
        5 => Some(Syscall::Exit {
            status: regs[1] as i32,
        }),
        6 => Some(Syscall::ConsoleRead {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        7 => Some(Syscall::BlockRead {
            lba: regs[1],
            user_buffer: regs[2] as usize,
            len: regs[3] as usize,
        }),
        8 => Some(Syscall::BlockWrite {
            lba: regs[1],
            user_buffer: regs[2] as usize,
            len: regs[3] as usize,
        }),
        9 => Some(Syscall::ConsoleWrite {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        10 => Some(Syscall::ShmCreate {
            size: regs[1] as usize,
            user_result: regs[2] as usize,
        }),
        11 => Some(Syscall::ShmMap {
            handle: regs[1] as u32,
        }),
        12 => Some(Syscall::ShmLen {
            handle: regs[1] as u32,
        }),
        13 => Some(Syscall::ShmRetain {
            handle: regs[1] as u32,
        }),
        14 => Some(Syscall::ShmRelease {
            handle: regs[1] as u32,
        }),
        15 => Some(Syscall::DriverCount),
        16 => Some(Syscall::DriverInfo {
            index: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        17 => Some(Syscall::ShmPhys {
            handle: regs[1] as u32,
        }),
        18 => Some(Syscall::MmioMap {
            index: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        19 => Some(Syscall::MmioUnmap {
            index: regs[1] as u32,
        }),
        20 => Some(Syscall::SpawnService {
            name_ptr: regs[1] as usize,
            name_len: regs[2] as usize,
        }),
        _ => None,
    }
}

fn encode_result(result: Result<u64, SysError>) -> u64 {
    match result {
        Ok(value) => value,
        Err(err) => match err {
            SysError::InvalidArgument => u64::MAX,
            SysError::PermissionDenied => u64::MAX - 1,
            SysError::ChannelUnavailable => u64::MAX - 2,
            SysError::NotFound => u64::MAX - 3,
            SysError::NoMemory => u64::MAX - 4,
            SysError::WouldBlock => u64::MAX - 5,
            SysError::DeviceError => u64::MAX - 6,
            SysError::Busy => u64::MAX - 7,
        },
    }
}

fn log_unknown_sync(esr: u64) {
    let ctx = capture_trap_context();
    let ec = (esr >> 26) & 0x3f;
    let iss = esr & 0x01ff_ffff;
    let slot = ctx.slot.unwrap_or(usize::MAX);
    let pid_raw = ctx.pid.map(|p| p.raw()).unwrap_or(0);
    crate::info!(
        "trap: sync exception ec=0x{:x} iss=0x{:08x} esr=0x{:016x} elr=0x{:016x} far=0x{:016x} slot={} pid={}",
        ec,
        iss,
        esr,
        ctx.elr,
        ctx.far,
        slot,
        pid_raw
    );
}

fn trap_panic(msg: &str, esr: u64) -> ! {
    crate::info!("trap panic: {msg} (ESR=0x{esr:016x})");
    loop {
        core::hint::spin_loop();
    }
}

fn read_esr_el1() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {0}, esr_el1", out(reg) value);
    }
    value
}

fn read_elr_el1() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {0}, elr_el1", out(reg) value);
    }
    value
}

fn read_far_el1() -> u64 {
    let value: u64;
    unsafe {
        asm!("mrs {0}, far_el1", out(reg) value);
    }
    value
}

fn capture_trap_context() -> TrapContext {
    let slot = crate::scheduler::current_slot();
    let pid = process::pid_at_slot(slot);
    TrapContext {
        elr: read_elr_el1(),
        far: read_far_el1(),
        slot: Some(slot),
        pid,
    }
}

fn terminate_faulting_process(ctx: &TrapContext) -> ! {
    if let Some(slot) = ctx.slot {
        process::set_state_slot(slot, ProcessState::Dying);
    }
    match (ctx.pid, ctx.slot) {
        (Some(pid), Some(slot)) => {
            crate::info!(
                "[trap] terminating pid={} slot={} due to user sync exception",
                pid.raw(),
                slot
            );
        }
        _ => crate::info!("[trap] terminating unknown process due to user sync exception"),
    }
    crate::scheduler::exit_current()
}

fn decode_esr(esr: u64) -> DecodedEsr {
    let ec = ((esr >> 26) & 0x3f) as u8;
    let iss = (esr & 0x01ff_ffff) as u32;
    let kind = match ec {
        0x15 => SyncExceptionKind::Svc,
        0x24 | 0x25 => SyncExceptionKind::DataAbort(decode_fault_info(iss)),
        0x20 | 0x21 => SyncExceptionKind::InstructionAbort(decode_fault_info(iss)),
        _ => SyncExceptionKind::Other,
    };
    DecodedEsr {
        ec,
        iss,
        kind,
        from_el0: matches!(ec, 0x15 | 0x20 | 0x24),
    }
}

fn decode_fault_info(iss: u32) -> FaultInfo {
    let dfsc = (iss & 0x3f) as u8;
    let (kind, level) = match dfsc {
        0b000000..=0b000011 => (FaultKind::AddressSize, Some(dfsc & 0b11)),
        0b000100..=0b000111 => (FaultKind::Translation, Some(dfsc & 0b11)),
        0b001000..=0b001011 => (FaultKind::AccessFlag, Some(dfsc & 0b11)),
        0b001100..=0b001111 => (FaultKind::Permission, Some(dfsc & 0b11)),
        0b010000..=0b010111 => (FaultKind::SyncExternal, Some(dfsc & 0b11)),
        0b100001 => (FaultKind::Alignment, None),
        _ => (FaultKind::Unknown, None),
    };
    FaultInfo { dfsc, level, kind }
}

fn format_sync_exception(decoded: &DecodedEsr, ctx: &TrapContext) -> String {
    let mut msg = String::new();
    let origin = if decoded.from_el0 { "EL0" } else { "EL1" };
    match decoded.kind {
        SyncExceptionKind::DataAbort(info) => {
            let _ = write!(
                msg,
                "[trap] {} data abort: {}",
                origin,
                fault_kind_str(info.kind),
            );
            append_level(info.level, &mut msg);
            let _ = write!(msg, " far=0x{:016x} elr=0x{:016x}", ctx.far, ctx.elr);
        }
        SyncExceptionKind::InstructionAbort(info) => {
            let _ = write!(
                msg,
                "[trap] {} instruction abort: {}",
                origin,
                fault_kind_str(info.kind),
            );
            append_level(info.level, &mut msg);
            let _ = write!(msg, " far=0x{:016x} elr=0x{:016x}", ctx.far, ctx.elr);
        }
        SyncExceptionKind::Svc => {
            let _ = write!(
                msg,
                "[trap] SVC from {}: iss=0x{:08x} elr=0x{:016x}",
                origin, decoded.iss, ctx.elr
            );
        }
        SyncExceptionKind::Other => {
            let _ = write!(
                msg,
                "[trap] sync exception ec=0x{:02x} iss=0x{:08x} elr=0x{:016x} far=0x{:016x}",
                decoded.ec, decoded.iss, ctx.elr, ctx.far
            );
        }
    }

    if let Some(pid) = ctx.pid {
        let _ = write!(msg, " pid={}", pid.raw());
    } else {
        let _ = write!(msg, " in kernel");
    }
    if let Some(slot) = ctx.slot {
        let _ = write!(msg, " slot={}", slot);
    }
    msg
}

fn fault_kind_str(kind: FaultKind) -> &'static str {
    match kind {
        FaultKind::Translation => "translation fault",
        FaultKind::Permission => "permission fault",
        FaultKind::AccessFlag => "access-flag fault",
        FaultKind::AddressSize => "address-size fault",
        FaultKind::SyncExternal => "sync external abort",
        FaultKind::Alignment => "alignment fault",
        FaultKind::Unknown => "unknown fault",
    }
}

fn append_level(level: Option<u8>, msg: &mut String) {
    if let Some(level) = level {
        let _ = write!(msg, " at level {}", level);
    }
}

impl From<u64> for TrapKind {
    fn from(value: u64) -> Self {
        match value {
            1 => TrapKind::Irq,
            _ => TrapKind::Sync,
        }
    }
}
