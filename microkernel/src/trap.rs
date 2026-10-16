use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::{arch::asm, fmt::Write};
use zero_abi::{
    syscall::{SysError, Syscall},
    ProcessId,
};

use crate::process::{self, TrapFrame};

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
    /// SIMD/FP 访问陷阱（EC=0x07，第十一刀 FPU 惰性保存）：FPEN=00 时
    /// EL0 首次触碰 FP/SIMD 触发，内核断链装载后重放；EL1 触发即内核
    /// 违反「内核不使用浮点」约定，按致命错误处置。
    FpuAccess,
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
pub extern "C" fn __zero_trap_handler(
    frame: *mut TrapFrame,
    kind: u64,
    esr_snapshot: u64,
    far_snapshot: u64,
) -> ! {
    // The assembly entry used TPIDR_EL1 to save the interrupted context. From
    // this point onward the CPU is executing kernel code: retarget any nested
    // exception to a per-CPU scratch frame before touching locks/allocators or
    // code that may ever unmask interrupts. This preserves the original user
    // TrapFrame as an immutable continuation until restore_context/dispatch.
    unsafe {
        let cpu = crate::arch::smp::cpu_id();
        crate::arch::set_tpidr_el1(crate::process::idle_trap_frame_for(cpu) as usize);
    }
    match TrapKind::from(kind) {
        TrapKind::Sync => handle_sync(frame, esr_snapshot, far_snapshot),
        TrapKind::Irq => handle_irq(frame),
    }
}

fn handle_sync(frame: *mut TrapFrame, esr: u64, far: u64) -> ! {
    crate::debug!("trap: sync ESR_EL1(snapshot)=0x{:016x}", esr);
    let from_el0 = unsafe { (*frame).spsr_el1 & 0x0f } == 0;
    let mut decoded = decode_esr(esr);
    decoded.from_el0 = from_el0;
    match decoded.kind {
        SyncExceptionKind::Svc => handle_svc(frame, esr, far),
        SyncExceptionKind::FpuAccess => {
            // 第十一刀 FPU 惰性保存断链入口。EC=0x07 不区分来源 EL，
            // SPSR.M[3:0]==0b0000（EL0t）才是合法用户态首用陷阱。
            if !from_el0 {
                kernel_sync_fault(
                    "FP/SIMD access under FPEN=00 from kernel (kernel-fp ban violated)",
                    esr,
                    far,
                    frame,
                )
            }
            unsafe { crate::arch::fpu_trap_replay(frame) }
        }
        SyncExceptionKind::Brk => {
            let ctx = capture_trap_context(frame, far);
            // 来源判定（第十刀集成修复）：EC=0x3C 与 SVC/FPU 同理不区分
            // 来源 EL，SPSR.M 才是权威字段。旧判据 `ctx.slot.is_some()`
            // 会把「内核在用户进程 syscall 路径中执行的 BRK」误判为
            // 用户 panic——无辜进程被 SIGTRAP 杀死，kernel_sync_fault
            // （pstore 持久化 + 复位）永不触达。实机 drill 抓获。
            if from_el0 {
                crate::info!(
                    "[trap] EL0 breakpoint (panic/udf): elr=0x{:016x} pid={:?}",
                    ctx.elr,
                    ctx.pid.map(|p| p.raw())
                );
                terminate_faulting_process(&ctx, zero_abi::signals::SIGTRAP)
            } else {
                kernel_sync_fault("BRK issued from kernel", esr, far, frame)
            }
        }
        SyncExceptionKind::DataAbort(_) | SyncExceptionKind::InstructionAbort(_) => {
            let ctx = capture_trap_context(frame, far);
            let message = format_sync_exception(&decoded, &ctx);
            if decoded.from_el0 {
                // ── 第十刀 COW：EL0 写权限故障优先走写时复制断链 ──
                // PTE 带 DESC_SW_COW ⇒ 分配私有副本/原地恢复可写后
                // restore_frame，eret 重放同一条访存指令（不杀不重启）。
                // 非 COW 页原样落入下方 SIGSEGV 路径。
                if let SyncExceptionKind::DataAbort(info) = decoded.kind {
                    if info.kind == FaultKind::Permission {
                        let broken = process::handle_cow_write_fault(ctx.far as usize);
                        if broken {
                            unsafe { crate::arch::restore_frame(frame) }
                        } else {
                            // 第十七刀探针：断链失败=不可恢复写越权，转储现场
                            crate::error!(
                                "COW-MISS far={:#x} elr={:#x} slot={:?} pid={:?}",
                                ctx.far,
                                ctx.elr,
                                ctx.slot,
                                ctx.pid
                            );
                        }
                    }
                }
                // 用户态故障：审计行保留 info，然后按默认动作投递信号终止。
                // 信号归因对标 Linux force_sig_fault 的页故障分类：
                // 数据访问对齐错误 → SIGBUS；其余页故障（翻译/权限/
                // 取指 abort）→ SIGSEGV。
                let sig = match &decoded.kind {
                    SyncExceptionKind::DataAbort(info) if info.kind == FaultKind::Alignment => {
                        zero_abi::signals::SIGBUS
                    }
                    _ => zero_abi::signals::SIGSEGV,
                };
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
                terminate_faulting_process(&ctx, sig)
            } else {
                // ── 第十刀 COW：EL1 代用户写落在 COW 共享页上同样可恢复 ──
                // （fork 后窗口内 copy_to_user 写用户缓冲即此场景）：
                // 断链成功则 eret 回 EL1 重放踩故障的访存指令，memcpy 无感续行；
                // PTE 无 COW 位则照旧走下方处置，行为不变。
                if let SyncExceptionKind::DataAbort(info) = decoded.kind {
                    if info.kind == FaultKind::Permission
                        && ctx.slot.is_some()
                        && process::handle_cow_write_fault(ctx.far as usize)
                    {
                        crate::info!("[trap] cow break on EL1 user-write far=0x{:016x}", ctx.far);
                        unsafe { crate::arch::restore_frame(frame) }
                    }
                }
                // 穷人版 exception table（对照 Linux __ex_table）：内核在
                // 代用户拷贝（copy_slice_from/to_user）时踩到坏页 ⇒
                // 视为 EFAULT 类用户错误：杀调用进程，而非重启整机。
                let elr = ctx.elr;
                if ctx.slot.is_some() && fault_in_user_copy_path(elr) {
                    crate::error!(
                        "[trap] user-copy path fault; killing caller (ELR=0x{:016x})",
                        elr
                    );
                    terminate_faulting_process(&ctx, zero_abi::signals::SIGSEGV)
                }
                crate::error!("{}", message);
                kernel_sync_fault(&message, esr, far, frame)
            }
        }
        SyncExceptionKind::Other => {
            if decoded.from_el0 {
                if let Some(svc_esr) = recover_lost_svc_esr(esr, frame) {
                    let imm = (svc_esr & 0xffff) as u16;
                    crate::warn!(
                        "[trap] recovered lost SVC syndrome: raw_esr=0x{:016x} imm={} elr=0x{:016x}",
                        esr,
                        imm,
                        unsafe { (*frame).elr_el1 }
                    );
                    handle_svc(frame, svc_esr, far)
                }
                let ctx = capture_trap_context(frame, far);
                crate::warn!(
                    "[trap] unknown sync from EL0: terminating pid={:?} slot={:?} elr=0x{:016x}",
                    ctx.pid.map(|p| p.raw()),
                    ctx.slot,
                    ctx.elr
                );
                terminate_faulting_process(&ctx, zero_abi::signals::SIGSEGV)
            } else {
                log_unknown_sync(esr, far, frame);
                kernel_sync_fault("unknown sync exception", esr, far, frame)
            }
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
        } else if irq == crate::arch::SGI_RESCHED {
            // 跨核唤醒 SGI（第十四刀阶段 2）：EOI 后按上下文分流。
            crate::arch::end_irq(raw);
            crate::scheduler::handle_resched_sgi()
        } else {
            let handled = crate::drivers::handle_irq(irq);
            crate::arch::end_irq(raw);
            // 未处理的非 timer IRQ 属异常事件，但可能高频重放（UART 调试
            // 线），故仍走 debug；跟踪低频事件时打开 debug 级日志即可。
            crate::debug!("trap: non-timer irq={} handled={}", irq, handled);
            if handled {
                crate::arch::restore_frame(frame)
            } else {
                // 杂散 IRQ：EOI 已完成（上方 end_irq），无任何驱动事件、
                // 无任何调度理由 —— 直接恢复被打断进程。此前误走
                // yield_current()：一次硬件噪声就强制一次上下文切换，
                // 白白损失当前进程剩余时间片并放大延迟；且杂散 IRQ 高频
                // 重放时会把调度器搅成抖动源。restore_frame 只重装现场
                // 并 eret，不触碰就绪队列。
                crate::debug!("trap: stray irq={}, resuming current", irq);
                crate::arch::restore_frame(frame)
            }
        }
    }
}

fn handle_svc(frame: *mut TrapFrame, esr: u64, far: u64) -> ! {
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
        kernel_sync_fault("SVC issued from EL1 (kernel bug)", esr, far, frame)
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
                                (*frame).elr_el1,
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
                    (*frame).elr_el1
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
        // 号位 22（WaitPid，zombie/waitpid 回收）：ABI 已冻结于 zero-abi。
        // 【边界披露】本文件本轮由并行 Agent 维护（FP 栈回溯），此处仅
        // 追加这一条 match 臂——任务要求 decode_syscall/handle/ABI 三处
        // 一致，且无此臂则号位 22 永远 ENOSYS、端到端验收不可能达成；
        // 插入点与其余改动区域零重叠。
        22 => Some(Syscall::WaitPid { pid: regs[1] }),
        // 号位 23（GetPpid，POSIX getppid 最小集）：ABI 已冻结于 zero-abi。
        // 【边界披露】本文件由并行 Agent 分头维护；此处仅追加这一条
        // match 臂（及下方表测试一行断言）——任务要求 decode_syscall/
        // handle/ABI 三处一致，且无此臂则号位 23 永远 ENOSYS、端到端
        // 验收不可能达成；插入点与其余改动区域零重叠（模式照抄号位 21）。
        23 => Some(Syscall::GetPpid),
        // 号位 24（Brk，用户堆增长/收缩，第十刀 WS-B 移交的精确补丁）：
        // x1=新 break（0=查询）。ABI 冻结于 zero-abi（Syscall::Brk）。
        24 => Some(Syscall::Brk {
            new_break: regs[1] as usize,
        }),
        // 号位 25（Sleepticks，第十一刀）：x1=tick 数。ABI 冻结于
        // zero-abi（Syscall::Sleepticks）；唤醒侧经陷阱帧回写 elapsed。
        25 => Some(Syscall::Sleepticks { ticks: regs[1] }),
        // 号位 26（CreateThread，第十五刀）：x1=entry/x2=stack/x3=tls/
        // x4=arg。ABI 冻结于 zero-abi；tid 为 wait_pid 可 join 的真 pid。
        26 => Some(Syscall::CreateThread {
            entry: regs[1] as usize,
            stack_top: regs[2] as usize,
            tls: regs[3] as usize,
            arg: regs[4] as usize,
        }),
        // 号位 27/28（FutexWait/Wake，第十五刀二期）：线程同步原语。
        27 => Some(Syscall::FutexWait {
            uaddr: regs[1] as usize,
            expected: regs[2] as u32,
        }),
        28 => Some(Syscall::FutexWake {
            uaddr: regs[1] as usize,
            max: regs[2] as usize,
        }),
        // ═══ 号位 40-45：安全模型成型（第十三刀，本刀领地）═════════
        // 号位 25=Sleep、26+=文件系统已被并行刀占用，安全扩展自 40 起。
        // ABI 契约见 zero-abi Syscall::CapGrant..SessionList 文档；
        // 内核臂见 syscalls.rs 同号位段；登记于 docs/abi_syscall_reference.md。
        //
        // 【边界披露】CapGrant/CapRevoke 的 caps/ttl 参数走 x2/x3 直读
        // （syscalls::handle 从帧取），此处只解 x1——与号位 22 flags 的
        // "冻结解码面 + handle 补取"先例同一模式。
        40 => Some(Syscall::CapGrant {
            target_pid: regs[1],
        }),
        41 => Some(Syscall::CapRevoke { token: regs[1] }),
        42 => Some(Syscall::CreateChannel {
            user_desc: regs[1] as usize,
        }),
        43 => Some(Syscall::SessionBegin {
            login_token: regs[1],
        }),
        44 => Some(Syscall::GetSession),
        45 => Some(Syscall::SessionList {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        46 => Some(Syscall::ShmGrant {
            handle: regs[1] as u32,
            target_pid: regs[2],
        }),
        47 => Some(Syscall::InputRead {
            user_event: regs[1] as usize,
        }),
        48 => Some(Syscall::DisplayPresent {
            user_buffer: regs[1] as usize,
            width: regs[2] as usize,
            height: regs[3] as usize,
            stride: regs[4] as usize,
        }),
        49 => Some(Syscall::ClockGet {
            clock_id: regs[1] as u32,
        }),
        50 => Some(Syscall::SleepUntil {
            deadline_ns: regs[1],
        }),
        51 => Some(Syscall::NetSend {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        52 => Some(Syscall::NetRecv {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        53 => Some(Syscall::NetGetMac {
            user_buffer: regs[1] as usize,
        }),
        54 => Some(Syscall::IpcSendTo {
            channel: regs[1] as u32,
            target_pid: regs[2],
            user_message: regs[3] as usize,
        }),
        55 => Some(Syscall::TryReceiveMessage {
            channel: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        56 => Some(Syscall::GetRandom {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        57 => Some(Syscall::BlockCapacity),
        58 => Some(Syscall::SpawnImage {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        59 => Some(Syscall::AudioInfo {
            user_info: regs[1] as usize,
        }),
        60 => Some(Syscall::AudioPlay {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        61 => Some(Syscall::AudioStop),
        62 => Some(Syscall::Gpu3dInfo {
            user_info: regs[1] as usize,
        }),
        63 => Some(Syscall::Gpu3dContextCreate {
            capset_id: regs[1] as u32,
        }),
        64 => Some(Syscall::Gpu3dContextDestroy {
            ctx_id: regs[1] as u32,
        }),
        65 => Some(Syscall::Gpu3dResourceCreate {
            user_desc: regs[1] as usize,
        }),
        66 => Some(Syscall::Gpu3dResourceDestroy {
            resource_id: regs[1] as u32,
        }),
        67 => Some(Syscall::Gpu3dContextAttach {
            ctx_id: regs[1] as u32,
            resource_id: regs[2] as u32,
        }),
        68 => Some(Syscall::Gpu3dSubmit {
            ctx_id: regs[1] as u32,
            user_buffer: regs[2] as usize,
            len: regs[3] as usize,
        }),
        69 => Some(Syscall::Gpu3dReadback {
            resource_id: regs[1] as u32,
            user_buffer: regs[2] as usize,
            len: regs[3] as usize,
        }),
        70 => Some(Syscall::Gpu3dGetCapset {
            capset_id: regs[1] as u32,
            version: regs[2] as u32,
            user_buffer: regs[3] as usize,
            len: regs[4] as usize,
        }),
        71 => Some(Syscall::BlockBackend),
        72 => Some(Syscall::PowerControl {
            action: regs[1] as u32,
        }),
        73 => Some(Syscall::PciCount),
        74 => Some(Syscall::PciInfo {
            index: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        75 => Some(Syscall::NetDiag {
            user_buffer: regs[1] as usize,
        }),
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
            SysError::NotSupported => u64::MAX - 8,
        },
    }
}

fn fault_arch_state() -> (u64, u64, u64, u64, u64) {
    #[cfg(target_os = "none")]
    unsafe {
        let sctlr: u64;
        let tcr: u64;
        let ttbr0: u64;
        let current_el: u64;
        let cpacr: u64;
        core::arch::asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nostack));
        core::arch::asm!("mrs {0}, tcr_el1", out(reg) tcr, options(nostack));
        core::arch::asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0, options(nostack));
        core::arch::asm!("mrs {0}, CurrentEL", out(reg) current_el, options(nostack));
        core::arch::asm!("mrs {0}, cpacr_el1", out(reg) cpacr, options(nostack));
        (sctlr, tcr, ttbr0, current_el, cpacr)
    }
    #[cfg(not(target_os = "none"))]
    {
        (0, 0, 0, 0, 0)
    }
}

fn log_unknown_sync(esr: u64, far: u64, frame: *mut TrapFrame) {
    let ctx = capture_trap_context(frame, far);
    let ec = (esr >> 26) & 0x3f;
    let iss = esr & 0x01ff_ffff;
    let slot = ctx.slot.unwrap_or(usize::MAX);
    let pid_raw = ctx.pid.map(|p| p.raw()).unwrap_or(0);
    // 符号化回溯（对标 Linux oops）：ELR 归到最近符号；无表时同时保留
    // 最关键的保存寄存器，避免后续 fault-report 锁竞争把第一现场吞掉。
    let sym = crate::debug::symbol_note(ctx.elr);
    let (x20, x21, x29, x30, sp0, sp1, spsr) = unsafe {
        if frame.is_null() {
            (0, 0, 0, 0, 0, 0, 0)
        } else {
            let f = &*frame;
            (
                f.regs[20], f.regs[21], f.regs[29], f.regs[30], f.sp_el0, f.sp_el1, f.spsr_el1,
            )
        }
    };
    let (insn, pte) = if crate::boot::kernel_runtime_contains(ctx.elr as usize, 4) {
        (
            unsafe { core::ptr::read_volatile(ctx.elr as *const u32) },
            0,
        )
    } else if let Some(slot) = ctx.slot {
        if let Some(space) = crate::process::address_space(slot) {
            match space.walk(ctx.elr as usize) {
                crate::mm::table_walk::WalkOutcome::Page { desc, phys } => {
                    let off = (ctx.elr as usize) & (crate::mm::table_walk::PAGE_SIZE - 1);
                    (
                        unsafe { core::ptr::read_volatile((phys + off) as *const u32) },
                        desc,
                    )
                }
                crate::mm::table_walk::WalkOutcome::Block { desc, .. } => (0, desc),
                crate::mm::table_walk::WalkOutcome::Unmapped => (0, 0),
            }
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };
    let cpu = crate::arch::smp::cpu_id();
    let (sctlr, tcr, ttbr0, current_el, cpacr) = fault_arch_state();
    crate::error!(
        "trap: unknown sync cpu={} ec=0x{:x} iss=0x{:08x} esr=0x{:016x} elr=0x{:016x}{} insn=0x{:08x} pte=0x{:016x} far=0x{:016x} slot={} pid={} spsr=0x{:016x} x20=0x{:016x} x21=0x{:016x} fp=0x{:016x} lr=0x{:016x} sp0=0x{:016x} sp1=0x{:016x} sctlr=0x{:016x} tcr=0x{:016x} ttbr0=0x{:016x} currentel=0x{:x} cpacr=0x{:016x}",
        cpu, ec, iss, esr, ctx.elr, sym, insn, pte, ctx.far, slot, pid_raw, spsr, x20, x21, x29, x30, sp0, sp1, sctlr, tcr, ttbr0, current_el, cpacr
    );
}

/// EL1 内核态同步异常 / 内核 bug 的统一出口：
/// 打印完整上下文（ESR/FAR/ELR/SPSR/SP、槽号、pid、trap frame 指针），
/// 然后尝试复位机器；复位不可用时打印 "SYSTEM HALT" 后停机（日志直写
/// PL011，已完整落盘）。
/// 故障 PC 是否落在内核代用户拷贝的例程内（copy_slice_from/to_user）。
/// 依据符号表子串匹配——Rust 修饰名包含完整路径，contains 足够稳健。
/// 这是穷人版 exception table：命中即把故障降级为调用进程终止，
/// 而非整机重启（对照 Linux __ex_table 的 fixup 跳转）。
fn fault_in_user_copy_path(pc: u64) -> bool {
    match crate::debug::symbolize(pc) {
        Some((name, _)) => {
            name.contains("copy_slice_from_user") || name.contains("copy_slice_to_user")
        }
        None => false,
    }
}

fn kernel_sync_fault(reason: &str, esr: u64, far: u64, frame: *mut TrapFrame) -> ! {
    let slot = crate::scheduler::current_slot_opt();
    let pid = slot
        .and_then(|s| process::pid_at_slot(s).map(|p| p.raw()))
        .unwrap_or(0);
    let slot = slot.unwrap_or(usize::MAX);
    let elr = unsafe { (*frame).elr_el1 };
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
    // 完整故障摘要持久化到 pstore 固定物理窗口：串口之外的第二份现场，
    // 复位后由 bootloader 在下一启第一屏取回打印（穷人版 pstore 链路）。
    crate::debug::pstore::log_kernel_fault(reason, esr, far, elr, &trace);
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
                    let _ = write!(line, "x30=0x{:016x}", f.regs[30]);
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
        // PSCI 0.2 功能 ID（ARM DEN 0022D 表 11）：SYSTEM_RESET =
        // 0x8400_0009。旧值 0x8400_0008 是 SYSTEM_OFF——"复位"实为
        // 关机，pstore 双启动链路因此从未真正走通过（第十刀 drill
        // 实测抓获：QEMU 进程整体退出而非热复位）。
        let fid: u64 = 0x8400_0009; // PSCI SYSTEM_RESET
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

fn capture_trap_context(frame: *mut TrapFrame, far: u64) -> TrapContext {
    // ELR/SPSR were captured by the assembly entry; FAR is the x3 entry snapshot.
    // Never combine a saved TrapFrame with later live EL1 syndrome registers:
    // nested exceptions may overwrite the latter.
    let slot = crate::scheduler::current_slot_opt();
    let pid = slot.and_then(|slot| process::pid_at_slot(slot));
    TrapContext {
        elr: unsafe { (*frame).elr_el1 },
        far,
        slot,
        pid,
    }
}

/// 终止故障进程：先投递默认动作信号，再走 Exit 同款状态机（第九刀）。
///
/// 此前实现是“无声蒸发”：置 Dying 后 remove_slot 即时销毁——退出码不
/// 可收集，父进程无从得知死因（无信号语义不可观测）。现对标 Linux
/// `force_sig(SIGSEGV)` + do_group_exit 默认动作：把 `sig` 登记进当前
/// 进程 pending_signals 位图（死因登记，见 process::deliver_fatal_signal），
/// 并以 POSIX 信号退出码 code = -(sig) 走与 Exit 系统调用**完全相同**的
/// Dying→Zombie→WaitPid 流程——父 waitpid 收到的 code 即区分死因
/// （SIGSEGV → -11、SIGBUS → -7、SIGTRAP → -5）。
///
/// 锁纪律照旧：deliver_fatal_signal / exit_current_with_status 各自持表
/// 锁且均为语句级 Guard，进入 noreturn 前已全部释放；无进程上下文
/// （slot=None）时维持旧路 exit_current（行为不变）。
fn terminate_faulting_process(ctx: &TrapContext, sig: u8) -> ! {
    match (ctx.pid, ctx.slot) {
        (Some(pid), Some(slot)) => {
            crate::info!(
                "[trap] terminating pid={} slot={} due to user sync exception (default action: sig={})",
                pid.raw(),
                slot,
                sig
            );
            let code = process::deliver_fatal_signal(slot, sig);
            process::exit_current_with_status(code)
        }
        _ => {
            crate::info!("[trap] terminating unknown process due to user sync exception");
            crate::scheduler::exit_current()
        }
    }
}

/// QEMU/firmware compatibility recovery for a rare syndrome-loss case seen
/// under SMP4: the EL0 SVC advances ELR correctly, but ESR_EL1 arrives with
/// EC=0 and only IL=1 preserved (0x0200_0000). We recover *only* when the
/// instruction immediately before saved ELR is verifiably an AArch64 SVC.
/// This keeps genuine Uncategorized exceptions fail-closed.
fn decode_aarch64_svc(insn: u32) -> Option<u16> {
    // SVC #imm16 encoding: 11010100 000 imm16 00001.
    if insn & 0xffe0_001f != 0xd400_0001 {
        return None;
    }
    Some(((insn >> 5) & 0xffff) as u16)
}

fn user_instruction_at(slot: usize, va: usize) -> Option<u32> {
    if va & 3 != 0 {
        return None;
    }
    let space = crate::process::address_space(slot)?;
    match space.walk(va) {
        crate::mm::table_walk::WalkOutcome::Page { phys, .. } => {
            let off = va & (crate::mm::table_walk::PAGE_SIZE - 1);
            Some(unsafe { core::ptr::read_volatile((phys + off) as *const u32) })
        }
        _ => None,
    }
}

fn recover_lost_svc_esr(esr: u64, frame: *mut TrapFrame) -> Option<u64> {
    // Require Uncategorized + AArch64 instruction length bit.
    if (esr >> 26) & 0x3f != 0 || esr & (1 << 25) == 0 || frame.is_null() {
        return None;
    }
    let f = unsafe { &*frame };
    if f.spsr_el1 & 0x1f != 0 || f.elr_el1 < 4 {
        return None;
    }
    let slot = crate::scheduler::current_slot_opt()?;
    let svc_pc = (f.elr_el1 as usize).checked_sub(4)?;
    let imm = decode_aarch64_svc(user_instruction_at(slot, svc_pc)?)?;
    // EC=0x15 (SVC AArch64), IL=1, ISS[15:0]=immediate.
    Some((0x15u64 << 26) | (1u64 << 25) | imm as u64)
}

fn decode_esr(esr: u64) -> DecodedEsr {
    let ec = ((esr >> 26) & 0x3f) as u8;
    let iss = (esr & 0x01ff_ffff) as u32;
    let kind = match ec {
        0x15 => SyncExceptionKind::Svc,
        0x24 | 0x25 => SyncExceptionKind::DataAbort(decode_fault_info(iss)),
        0x20 | 0x21 => SyncExceptionKind::InstructionAbort(decode_fault_info(iss)),
        0x3c => SyncExceptionKind::Brk,
        // SIMD/FP 访问陷阱（第十一刀）：EC 不区分来源 EL，SPSR.M 才权威
        // （与 SVC 同一判据哲学），在 handle_sync 臂内校验。
        0x07 => SyncExceptionKind::FpuAccess,
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
        SyncExceptionKind::FpuAccess => {
            let _ = write!(
                msg,
                "[trap] FP/SIMD access trap (lazy FPU) from {}: elr=0x{:016x}",
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
            val if val == u64::MAX - 8 => Err(SysError::NotSupported),
            other => Ok(other),
        }
    }

    #[test]
    fn encode_decode_ok_roundtrip() {
        // u64::MAX-8 起被 NotSupported 占用（第八刀），样本下移一格。
        for value in [0u64, 1, 42, u64::MAX - 9, (1 << 48) - 1] {
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
            SysError::NotSupported,
        ];
        for err in errors {
            let encoded = encode_result(Err(err));
            assert!(
                encoded >= u64::MAX - 8,
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
            Some(Syscall::BlockRead {
                lba: 42,
                len: 512,
                ..
            })
        ));
        assert!(matches!(
            decode_syscall(&regs(8, [42, 0x8000_0000, 4096, 0])),
            Some(Syscall::BlockWrite {
                lba: 42,
                len: 4096,
                ..
            })
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
        assert!(matches!(
            decode_syscall(&regs(22, [7, 0, 0, 0])),
            Some(Syscall::WaitPid { pid: 7 })
        ));
        assert!(matches!(
            decode_syscall(&regs(23, [0, 0, 0, 0])),
            Some(Syscall::GetPpid)
        ));
        // 号位 40-45（第十三刀）：解码面冻结断言（x2/x3 参数由
        // handle 从帧直读，此处只验 x1 映射）。
        assert!(matches!(
            decode_syscall(&regs(40, [9, 0, 0, 0])),
            Some(Syscall::CapGrant { target_pid: 9 })
        ));
        assert!(matches!(
            decode_syscall(&regs(41, [5, 0, 0, 0])),
            Some(Syscall::CapRevoke { token: 5 })
        ));
        assert!(matches!(
            decode_syscall(&regs(42, [0x8000_0000, 0, 0, 0])),
            Some(Syscall::CreateChannel {
                user_desc: 0x8000_0000
            })
        ));
        assert!(matches!(
            decode_syscall(&regs(43, [3, 0, 0, 0])),
            Some(Syscall::SessionBegin { login_token: 3 })
        ));
        assert!(matches!(
            decode_syscall(&regs(44, [0, 0, 0, 0])),
            Some(Syscall::GetSession)
        ));
        assert!(matches!(
            decode_syscall(&regs(45, [0x8000_0000, 64, 0, 0])),
            Some(Syscall::SessionList {
                user_buffer: 0x8000_0000,
                len: 64
            })
        ));
        assert!(matches!(
            decode_syscall(&regs(59, [0x8000_0000, 0, 0, 0])),
            Some(Syscall::AudioInfo { .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(60, [0x8000_0000, 2048, 0, 0])),
            Some(Syscall::AudioPlay { len: 2048, .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(61, [0, 0, 0, 0])),
            Some(Syscall::AudioStop)
        ));
        assert!(matches!(
            decode_syscall(&regs(62, [0x8000_0000, 0, 0, 0])),
            Some(Syscall::Gpu3dInfo { .. })
        ));
        assert!(matches!(
            decode_syscall(&regs(63, [2, 0, 0, 0])),
            Some(Syscall::Gpu3dContextCreate { capset_id: 2 })
        ));
        assert!(matches!(
            decode_syscall(&regs(68, [7, 0x8000_0000, 64, 0])),
            Some(Syscall::Gpu3dSubmit {
                ctx_id: 7,
                len: 64,
                ..
            })
        ));
        assert!(matches!(
            decode_syscall(&regs(70, [2, 1, 0x8000_0000, 512])),
            Some(Syscall::Gpu3dGetCapset {
                capset_id: 2,
                version: 1,
                len: 512,
                ..
            })
        ));
        assert!(matches!(
            decode_syscall(&regs(71, [0, 0, 0, 0])),
            Some(Syscall::BlockBackend)
        ));
        assert!(decode_syscall(&regs(999, [0, 0, 0, 0])).is_none());
    }

    #[test]
    fn svc_encoding_recovery_is_fail_closed() {
        assert_eq!(decode_aarch64_svc(0xd400_0001), Some(0));
        assert_eq!(decode_aarch64_svc(0xd400_0021), Some(1));
        assert_eq!(decode_aarch64_svc(0xd400_2461), Some(0x123));
        assert_eq!(decode_aarch64_svc(0xd65f_03c0), None); // RET
        assert_eq!(decode_aarch64_svc(0x17ff_ffee), None); // B
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
