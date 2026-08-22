use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// ENOSYS 限流计数器（见 handle_svc 的采样逻辑）。
static ENOSYS_LOG_COUNT: AtomicU64 = AtomicU64::new(0);

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
    /// BRK 指令（EC=0x3C）：用户态即 Rust panic / 显式陷阱，
    /// 语义对标 Linux SIGTRAP —— 终止进程，绝不 HALT 整机。
    Brk,
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

/// 异常/IRQ 总入口（由 arch 侧 trap_entry 调起，noreturn）。
///
/// 锁纪律：本路径进入 terminate / exit_current / reschedule 前必须
/// 已释放全部 MutexGuard —— 所有 lock() 均以语句级表达式使用，
/// 不存在跨函数调用的 Guard（见 scheduler.rs 头部锁纪律注释）。
#[no_mangle]
pub extern "C" fn __zero_trap_handler(frame: *mut TrapFrame, kind: u64) -> ! {
    crate::debug!("trap: kind={} frame={:p}", kind, frame);
    match TrapKind::from(kind) {
        TrapKind::Sync => handle_sync(frame),
        TrapKind::Irq => handle_irq(frame),
    }
}

fn handle_sync(frame: *mut TrapFrame) -> ! {
    let esr = read_esr_el1();
    crate::debug!("trap: sync ESR_EL1=0x{:016x}", esr);
    let decoded = decode_esr(esr);
    match decoded.kind {
        SyncExceptionKind::Svc => handle_svc(frame, esr),
        SyncExceptionKind::Brk => {
            let ctx = capture_trap_context();
            if decoded.from_el0 || ctx.slot.is_some() {
                crate::info!(
                    "[trap] EL0 breakpoint (panic/udf): elr=0x{:016x} pid={:?}",
                    ctx.elr,
                    ctx.pid.map(|p| p.raw())
                );
                terminate_faulting_process(&ctx)
            } else {
                kernel_sync_fault("BRK issued from kernel", esr, frame)
            }
        }
        SyncExceptionKind::DataAbort(_) | SyncExceptionKind::InstructionAbort(_) => {
            let ctx = capture_trap_context();
            let message = format_sync_exception(&decoded, &ctx);
            if decoded.from_el0 {
                // 用户态故障：审计行保留 info，然后杀进程回收槽位。
                crate::info!("{}", message);
                crate::info!(
                    "[trap] DBG LR=0x{:016x} FP=0x{:016x} x11=0x{:016x} x0=0x{:016x} x1=0x{:016x}",
                    unsafe { (*frame).regs[30] },
                    unsafe { (*frame).regs[29] },
                    unsafe { (*frame).regs[11] },
                    unsafe { (*frame).regs[0] },
                    unsafe { (*frame).regs[1] },
                );
                dump_user_pte(ctx.far);
                terminate_faulting_process(&ctx)
            } else {
                // EL1 内核态同步异常：完整上下文 + 重启，绝不裸死循环。
                crate::error!("{}", message);
                kernel_sync_fault(&message, esr, frame)
            }
        }
        SyncExceptionKind::Other => {
            log_unknown_sync(esr);
            kernel_sync_fault("unknown sync exception", esr, frame)
        }
    }
}

fn handle_irq(frame: *mut TrapFrame) -> ! {
    unsafe {
        let raw = crate::arch::acknowledge_irq();
        let irq = crate::arch::interrupt_number(raw);
        // 每次 tick 都执行到此：整条路径只留一行 debug（默认关闭）。
        crate::debug!(
            "trap: irq raw=0x{:08x} irq={} is_timer={}",
            raw,
            irq,
            crate::arch::is_timer_irq(irq)
        );
        if crate::arch::is_timer_irq(irq) {
            crate::arch::program_next_tick();
            crate::arch::end_irq(raw);
            // 时间片记账：未耗尽则直接返回被打断进程（restore_frame），
            // 省去一次完整切换；耗尽才走 yield 让出。
            if crate::scheduler::on_tick_consume() {
                crate::debug!("trap: timer tick, yielding current");
                crate::scheduler::yield_current()
            }
            crate::arch::restore_frame(frame)
        } else {
            let handled = crate::drivers::handle_irq(irq);
            crate::arch::end_irq(raw);
            // 未处理的非 timer IRQ 属异常事件，但可能高频重放（UART 调试
            // 线），故仍走 debug；跟踪低频事件时打开 debug 级日志即可。
            crate::debug!("trap: non-timer irq={} handled={}", irq, handled);
            if handled {
                crate::arch::restore_frame(frame)
            } else {
                crate::debug!("trap: unhandled irq={}, yielding current", irq);
                crate::scheduler::yield_current()
            }
        }
    }
}

fn handle_svc(frame: *mut TrapFrame, esr: u64) -> ! {
    // ⛔ 仅允许 EL0t 发起 SVC：校验保存的 SPSR_EL1.M[3:0] 必须为 0b0000。
    // SVC 的 EC（0x15）无法区分来源 EL —— SPSR.M 才是权威字段；
    // EL1 内核态发 SVC 视为内核 bug，直接打印完整上下文并复位。
    let saved_m = unsafe { (*frame).spsr_el1 & 0x0f };
    if saved_m != 0 {
        crate::error!(
            "SVC issued from EL1 (kernel bug): SPSR.M[3:0]=0b{:04b} esr=0x{:016x}",
            saved_m,
            esr
        );
        kernel_sync_fault("SVC issued from EL1 (kernel bug)", esr, frame)
    }

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
                    // ⚠ 用户态发了未知/非法编号：这是用户程序 bug，不是内核
                    // bug。POSIX 语义 = 返回 ENOSYS 让调用方自行处理；
                    // 此前直接 kernel_sync_fault 把整台机器 HALT 掉——一个
                    // 用户态错误就击沉内核（Linux/XNU 均不会如此）。
                    None => {
                        let number = (*frame).regs[0];
                        // 限流：用户态死循环打未知 syscall 时按 2 的幂采样，
                        // 既保留首现证据又不淹没串口（实测曾 25 秒刷 89 万行）。
                        let n = ENOSYS_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
                        if n == 0 || n.is_power_of_two() {
                            crate::warn!(
                                "syscall ENOSYS #{}: number={} elr=0x{:016x} pid={}",
                                n,
                                number,
                                read_elr_el1(),
                                crate::process::pid_at_slot(crate::scheduler::current_slot())
                                    .map(|p| p.raw())
                                    .unwrap_or(0),
                            );
                        }
                        (*frame).regs[0] = encode_result(Err(SysError::NotFound));
                        crate::arch::restore_frame(frame)
                    }
                }
            }
            1 => crate::scheduler::yield_current(),
            2 => crate::scheduler::exit_current(),
            _ => {
                // 未知 svc 立即数同理：ENOSYS 返回，不 HALT。
                crate::warn!(
                    "unknown svc immediate {} at elr=0x{:016x}",
                    imm,
                    read_elr_el1()
                );
                (*frame).regs[0] = encode_result(Err(SysError::NotFound));
                crate::arch::restore_frame(frame)
            }
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
        21 => Some(Syscall::GetPid),
        _ => None,
    }
}

/// 用户态返回码编码（与 userland/userlib 的 decode_result 一一对应，
/// 参见 ipc/syscall ABI）。
pub fn encode_result(result: Result<u64, SysError>) -> u64 {
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
    // 符号化回溯（对标 Linux oops）：ELR 归到最近符号；无表则维持裸地址。
    let sym = crate::debug::symbol_note(ctx.elr);
    crate::error!(
        "trap: unknown sync ec=0x{:x} iss=0x{:08x} esr=0x{:016x} elr=0x{:016x}{} far=0x{:016x} slot={} pid={}",
        ec,
        iss,
        esr,
        ctx.elr,
        sym,
        ctx.far,
        slot,
        pid_raw
    );
}

/// EL1 内核态同步异常 / 内核 bug 的统一出口：
/// 打印完整上下文（ESR/FAR/ELR/SPSR/SP、槽号、pid、trap frame 指针），
/// 然后尝试复位机器；复位不可用时打印 "SYSTEM HALT" 后停机（日志直写
/// PL011，已完整落盘）。
fn kernel_sync_fault(reason: &str, esr: u64, frame: *mut TrapFrame) -> ! {
    let slot = crate::scheduler::current_slot_opt();
    let pid = slot
        .and_then(|s| process::pid_at_slot(s).map(|p| p.raw()))
        .unwrap_or(0);
    let slot = slot.unwrap_or(usize::MAX);
    let elr = read_elr_el1();
    let far = read_far_el1();
    let spsr = unsafe { (*frame).spsr_el1 };
    let sp = unsafe { (*frame).sp_el1 };
    // 符号化回溯（对标 Linux oops 的 func+0xoff）：bootloader 灌表后
    // ELR 落到最近内核符号，如 (__zero_trap_handler+0x24)；无表时为空串。
    let sym = crate::debug::symbol_note(elr);
    crate::error!(
        "[KERNEL FAULT] {reason}: ESR=0x{esr:016x} FAR=0x{far:016x} ELR=0x{elr:016x}{sym} \
         SPSR=0x{spsr:016x} SP_EL1=0x{sp:016x} slot={slot} pid={pid} frame={frame:p}"
    );
    dump_frame_registers(frame);

    // FP 链栈回溯（对标 Linux oops 的 Call Trace 段）：从故障现场
    // 的 x29 起向上收集，逐帧符号化。链断条件见 backtrace_from。
    // 注意：x29 取自**保存的现场**而非当前内核栈，保证回溯的是
    // 故障发生时刻的调用链。
    let fp = unsafe { (*frame).regs[29] };
    let trace = crate::debug::backtrace_from(fp, 12);
    if !trace.is_empty() {
        crate::error!("Call Trace:");
        for (i, fr) in trace.iter().enumerate() {
            crate::error!("  #{i} pc=0x{:016x}{}", fr.pc, fr.note);
        }
    }
    reset_or_halt()
}

/// 全量寄存器现场转储（4 个/行，x0–x30 + sp_el0/elr/spsr/sp_el1）。
/// 对标 XNU panic report / Linux oops 的寄存器段；内核故障诊断的最低配置。
fn dump_frame_registers(frame: *mut TrapFrame) {
    if frame.is_null() {
        return;
    }
    unsafe {
        let f = &*frame;
        for row in 0..8 {
            let base = row * 4;
            let mut line = String::new();
            for col in 0..4 {
                let idx = base + col;
                if idx < 30 {
                    let _ = write!(line, "x{idx}=0x{:016x} ", f.regs[idx]);
                }
            }
            match row {
                7 => {
                    let _ = write!(
                        line,
                        "x30=0x{:016x}",
                        f.regs[30]
                    );
                }
                _ => {}
            }
            crate::error!("  {}", line);
        }
        crate::error!(
            "  sp_el0=0x{:016x} elr=0x{:016x} spsr=0x{:016x} sp_el1=0x{:016x}",
            f.sp_el0,
            f.elr_el1,
            f.spsr_el1,
            f.sp_el1
        );
    }
}

/// 复位或停机。
///
/// aarch64/QEMU virt：SMC #0 进 EL3 走 PSCI SYSTEM_RESET（FID=0x8400_0008，
/// PSCI 0.2 标准），QEMU 自带 EL3 固件会真实复位机器。
/// 若固件/EL3 缺失，SMC 会作为同步异常绕回异常向量（arch 侧
/// default_exception 兜底打印并停机）—— 于是我们提前把 SYSTEM HALT
/// 与全部上下文落盘，保证诊断信息不丢。
///
/// 真实硬件路径（协调点，arch Agent）：硬件 WDT（如 dw_wdt / SP805）
/// 触发复位；arch Agent 落地 `arch::reset()` 后应改调它。
/// 故障路径重入保护：复位调用本身再次异常时（如 PSCI conduit 缺失），
/// 直接静默停机，绝不递归打印（实测 smc 弹回曾造成 HALT 日志无限刷屏）。
static IN_FAULT_PATH: AtomicBool = AtomicBool::new(false);

fn reset_or_halt() -> ! {
    if IN_FAULT_PATH.swap(true, Ordering::SeqCst) {
        // 已在故障路径中：复位调用又触发了异常。立即停机，不再打印。
        loop {
            core::hint::spin_loop();
        }
    }
    crate::error!("SYSTEM HALT: 内核故障，尝试复位后停机");
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let fid: u64 = 0x8400_0008; // PSCI SYSTEM_RESET
        // QEMU virt (TCG) 的 PSCI conduit 是 HVC；SMC 会作为未定义异常
        // 弹回 EL1 自家向量表（实测），故必须用 hvc。
        asm!("hvc #0", in("x0") fid, options(nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // host 测试/其他目标：直接停机（永不返回）。
    }
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

/// 对用户态故障地址做软件走表，打印叶子描述符原始位。
/// 权限类 bug（AP 编码错、UXN 误置、AF 缺失）一眼可判，不必再猜。
fn dump_user_pte(far: u64) {
    let slot = crate::scheduler::current_slot_opt();
    let Some(space) = slot.and_then(crate::process::address_space) else {
        return;
    };
    match space.walk(far as usize) {
        crate::mm::table_walk::WalkOutcome::Page { desc, phys } => crate::info!(
            "[trap] PTE far=0x{:016x} desc=0x{:016x} phys=0x{:x} ap={} uxn={} af={} attridx={}",
            far,
            desc,
            phys,
            (desc >> 6) & 0b11,
            (desc >> 54) & 1,
            (desc >> 10) & 1,
            (desc >> 2) & 0b111,
        ),
        crate::mm::table_walk::WalkOutcome::Block { desc, block_base } => crate::info!(
            "[trap] BLOCK far=0x{:016x} desc=0x{:016x} base=0x{:x} ap={}",
            far,
            desc,
            block_base,
            (desc >> 6) & 0b11,
        ),
        crate::mm::table_walk::WalkOutcome::Unmapped => {
            crate::info!("[trap] PTE far=0x{:016x}: unmapped", far)
        }
    }
}

fn capture_trap_context() -> TrapContext {
    // 非 panic 版本：异常可能在任何时刻到来（包括尚无当前进程的窗口）。
    let slot = crate::scheduler::current_slot_opt();
    let pid = slot.and_then(|slot| process::pid_at_slot(slot));
    TrapContext {
        elr: read_elr_el1(),
        far: read_far_el1(),
        slot,
        pid,
    }
}

/// 终止故障进程。锁纪律：两个 lock()（PROCESS_TABLE / CURRENT_SLOT）
/// 都是语句级 Guard，进入 exit_current → reschedule 前已全部释放，
/// 绝无跨 noreturn 调用持锁。
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
        0x3c => SyncExceptionKind::Brk,
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
                "[trap] {} data abort: {} (dfsc=0b{:06b})",
                origin,
                fault_kind_str(info.kind),
                dfsc_raw(&info),
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
        SyncExceptionKind::Brk => {
            let _ = write!(
                msg,
                "[trap] BRK (panic/udf) from {}: elr=0x{:016x}",
                origin, ctx.elr
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

/// DFSC 原始码诊断出口（保留字段被本函数消费）。
fn dfsc_raw(info: &FaultInfo) -> u8 {
    info.dfsc
}

impl From<u64> for TrapKind {
    fn from(value: u64) -> Self {
        match value {
            1 => TrapKind::Irq,
            _ => TrapKind::Sync,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 userland/userlib::decode_result 保持一致的解码（仅测试用，
    /// 验证 encode 是它的逆操作）。
    fn decode_result(value: u64) -> Result<u64, SysError> {
        match value {
            val if val == u64::MAX => Err(SysError::InvalidArgument),
            val if val == u64::MAX - 1 => Err(SysError::PermissionDenied),
            val if val == u64::MAX - 2 => Err(SysError::ChannelUnavailable),
            val if val == u64::MAX - 3 => Err(SysError::NotFound),
            val if val == u64::MAX - 4 => Err(SysError::NoMemory),
            val if val == u64::MAX - 5 => Err(SysError::WouldBlock),
            val if val == u64::MAX - 6 => Err(SysError::DeviceError),
            val if val == u64::MAX - 7 => Err(SysError::Busy),
            other => Ok(other),
        }
    }

    #[test]
    fn encode_decode_ok_roundtrip() {
        for value in [0u64, 1, 42, u64::MAX - 8, (1 << 48) - 1] {
            assert_eq!(decode_result(encode_result(Ok(value))), Ok(value));
        }
    }

    #[test]
    fn encode_decode_err_roundtrip() {
        let errors = [
            SysError::InvalidArgument,
            SysError::PermissionDenied,
            SysError::ChannelUnavailable,
            SysError::NotFound,
            SysError::NoMemory,
            SysError::WouldBlock,
            SysError::DeviceError,
            SysError::Busy,
        ];
        for err in errors {
            let encoded = encode_result(Err(err));
            assert!(
                encoded >= u64::MAX - 7,
                "error sentinel must live in reserved range: got 0x{encoded:x}"
            );
            assert_eq!(decode_result(encoded), Err(err));
        }
    }

    extern "C" fn fake_entry() -> ! {
        loop {}
    }

    fn regs(number: u64, args: [u64; 4]) -> [u64; 31] {
        let mut regs = [0u64; 31];
        regs[0] = number;
        regs[1] = args[0];
        regs[2] = args[1];
        regs[3] = args[2];
        regs[4] = args[3];
        regs
    }

    #[test]
    fn decode_syscall_table() {
        assert!(matches!(
            decode_syscall(&regs(0, [1, 0x8000_0000, 0, 0])),
            Some(Syscall::SendMessage { channel: 1, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(1, [1, 0x8000_0000, 0, 0])),
            Some(Syscall::ReceiveMessage { channel: 1, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(2, [0, 0, 0, 0])),
            Some(Syscall::Fork)
        ));
        // Exec: entry 必须非零
        assert!(decode_syscall(&regs(3, [0, 0, 0, 0])).is_none());
        assert!(matches!(
            decode_syscall(&regs(3, [fake_entry as usize as u64, 7, 0, 0])),
            Some(Syscall::Exec { arg: 7, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(4, [0, 0, 0, 0])),
            Some(Syscall::Yield)
        ));
        assert!(matches!(
            decode_syscall(&regs(5, [-1i32 as u64, 0, 0, 0])),
            Some(Syscall::Exit { status: -1 })
        ));
        assert!(matches!(
            decode_syscall(&regs(6, [0x8000_0000, 512, 0, 0])),
            Some(Syscall::ConsoleRead { len: 512, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(7, [42, 0x8000_0000, 512, 0])),
            Some(Syscall::BlockRead { lba: 42, len: 512, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(8, [42, 0x8000_0000, 4096, 0])),
            Some(Syscall::BlockWrite { lba: 42, len: 4096, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(9, [0x8000_0000, 32, 0, 0])),
            Some(Syscall::ConsoleWrite { len: 32, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(10, [4096, 0x8000_0000, 0, 0])),
            Some(Syscall::ShmCreate { size: 4096, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(11, [3, 0, 0, 0])),
            Some(Syscall::ShmMap { handle: 3 })
        ));
        assert!(matches!(
            decode_syscall(&regs(12, [3, 0, 0, 0])),
            Some(Syscall::ShmLen { handle: 3 })
        ));
        assert!(matches!(
            decode_syscall(&regs(13, [3, 0, 0, 0])),
            Some(Syscall::ShmRetain { handle: 3 })
        ));
        assert!(matches!(
            decode_syscall(&regs(14, [3, 0, 0, 0])),
            Some(Syscall::ShmRelease { handle: 3 })
        ));
        assert!(matches!(
            decode_syscall(&regs(15, [0, 0, 0, 0])),
            Some(Syscall::DriverCount)
        ));
        assert!(matches!(
            decode_syscall(&regs(16, [0, 0x8000_0000, 0, 0])),
            Some(Syscall::DriverInfo { index: 0, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(17, [3, 0, 0, 0])),
            Some(Syscall::ShmPhys { handle: 3 })
        ));
        assert!(matches!(
            decode_syscall(&regs(18, [0, 0x8000_0000, 0, 0])),
            Some(Syscall::MmioMap { index: 0, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(19, [0, 0, 0, 0])),
            Some(Syscall::MmioUnmap { index: 0 })
        ));
        assert!(matches!(
            decode_syscall(&regs(20, [0x8000_0000, 8, 0, 0])),
            Some(Syscall::SpawnService { name_len: 8, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(21, [0, 0, 0, 0])),
            Some(Syscall::GetPid)
        ));
        assert!(decode_syscall(&regs(22, [0, 0, 0, 0])).is_none());
        assert!(decode_syscall(&regs(999, [0, 0, 0, 0])).is_none());
    }

    #[test]
    fn decode_esr_classes() {
        // EC=0x15 SVC（AArch64）
        assert!(matches!(
            decode_esr(0x15u64 << 26).kind,
            SyncExceptionKind::Svc
        ));
        // EC=0x24 data abort from lower EL：DFSC=0b000101 → translation L1
        let esr = (0x24u64 << 26) | 0b000101;
        match decode_esr(esr).kind {
            SyncExceptionKind::DataAbort(info) => {
                assert_eq!(info.kind, FaultKind::Translation);
                assert_eq!(info.level, Some(1));
                assert!(decode_esr(esr).from_el0);
            }
            _ => panic!("expected data abort"),
        }
        // EC=0x25 data abort same EL（内核态）：from_el0=false
        let esr = (0x25u64 << 26) | 0b001101; // permission L1
        match decode_esr(esr).kind {
            SyncExceptionKind::DataAbort(info) => {
                assert_eq!(info.kind, FaultKind::Permission);
                assert!(!decode_esr(esr).from_el0);
            }
            _ => panic!("expected data abort"),
        }
        // EC=0x21 instruction abort same EL
        let esr = (0x21u64 << 26) | 0b000100;
        match decode_esr(esr).kind {
            SyncExceptionKind::InstructionAbort(info) => {
                assert_eq!(info.kind, FaultKind::Translation);
                assert_eq!(info.level, Some(0));
            }
            _ => panic!("expected instruction abort"),
        }
        // 未知 EC
        assert!(matches!(
            decode_esr(0x01u64 << 26).kind,
            SyncExceptionKind::Other
        ));
    }

    #[test]
    fn decode_fault_unknown() {
        let info = decode_fault_info(0);
        assert_eq!(info.kind, FaultKind::AddressSize);
        assert_eq!(info.level, Some(0));
        let info = decode_fault_info(0b111111);
        assert_eq!(info.kind, FaultKind::Unknown);
        assert_eq!(info.level, None);
    }
}