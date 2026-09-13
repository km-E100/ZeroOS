//! # userlib —— 用户态系统调用封装库
//!
//! 提供 `svc #0` 内联汇编封装与全部已冻结系统调用的安全包装
//! （调用号、参数、返回值编码均定义在 `zero-abi`，本库只做搬运）。
//!
//! ## 撤销约定
//!
//! 所有返回 `Result` 的函数，`Err` 都是 [`zero_abi::syscall::SysError`]，
//! 来自 [`zero_abi::syscall::decode`] 的错误区间解码（`u64::MAX - k`）。
//!
//! ## 历史快捷入口
//!
//! `yield_now` / `exit` 使用 `svc #1` / `svc #2` 立即数入口
//! （等价于通过 `svc #0` 分发号位 4 / 5，见 `zero-abi` crate 文档）。

#![no_std]

use zero_abi::ipc::Message;
use zero_abi::syscall::SysError;

#[inline(always)]
#[allow(dead_code)]
fn svc_call(number: u16, args: [u64; 4]) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x0") number as u64,
            in("x1") args[0],
            in("x2") args[1],
            in("x3") args[2],
            in("x4") args[3],
            lateout("x0") ret,
            // 内核异常入口存根牺牲用户 x16（IP0）作帧指针暂存、并改写
            // x17；AAPCS64 允许，但必须显式告知 LLVM：禁止在 svc 边界
            // 跨这两个寄存器存活任何值。
            out("x16") _,
            out("x17") _,
            options(nostack)
        );
    }
    ret
}

/* ⚠ 历史教训（2026-08-22 实机定位，保留给所有后来者）：
 *
 * 旧实现用 `mov x0,{num}; mov x1,{a0}; ...; svc` + in(reg) 让 LLVM 自由
 * 选择输入寄存器。当 LLVM 把 {a0} 分配到 x0 时，第一条 `mov x0,{num}`
 * 会先毁掉 a0 的存放处，后续 `mov x1,{a0}` 读到垃圾 —— 系统调用号正确、
 * 参数随机。加入 x16/x17 clobber 后寄存器分配恰好踩中此雷：ConsoleRead
 * 的缓冲区指针变成野值，内核把字节写进未知地址，shell 永远读到 0。
 *
 * 修正：固定寄存器约束（in("x0") 等），LLVM 在 asm 前把操作数放进指定
 * 寄存器、无分配彩票 —— 与 Linux \__syscall_inline 同一做法。
 */

/// 让出 CPU（等价内核号位 4 `Yield`，经历史快捷入口 `svc #1`）。
///
/// **正常返回**：调度器切走后会在合适时机把控制权交回到本函数的
/// 调用点之后（svc 的返回地址）。无输入可读（`ConsoleRead` 返回
/// `WouldBlock`）时应当调用本函数等待，而不是自旋空转。
///
/// ⚠ 历史教训：本函数曾被误标为 `-> !`，LLVM 遂在 `svc #1` 后放置
/// unreachable 陷阱（brk #1）；而 yield 实际必然返回，控制流一回来就
/// 踩中陷阱 —— 实机表现为 shell 打印提示符后立即 panic。
pub fn yield_now() {
    unsafe {
        core::arch::asm!(
            "svc #1",
            out("x16") _,
            out("x17") _,
            options(nostack)
        );
    }
}

/// 退出当前进程（号位 5 `Exit`）。
///
/// `code` 为退出状态码：有存活父进程时本进程转 Zombie，父可经
/// [`wait_pid`] 收集该码；无父/父已死则由内核立即完全回收。
///
/// 历史注记：旧实现走快捷入口 `svc #2`；但内核侧 svc#2 是“不留尸体”
/// 的即时销毁路径（退出码丢弃、不可收集）。为让 wait4 语义端到端
/// 可用，本库统一改走正式号位 5——两者最终都不返回，行为差异仅在
/// 状态码是否可被父进程收集。
pub fn exit(code: i32) -> ! {
    unsafe {
        // noreturn asm 不能声明输出；x16/x17 在此路径无所谓（进程即将消亡）。
        core::arch::asm!(
            "svc #0",
            in("x0") 5u64,
            in("x1") code as u64,
            options(noreturn)
        );
    }
}

/// 故意触发一次 EL0 数据 abort：对地址 0 写 1 字节（segvdemo 用）。
///
/// 内核 EL0 故障路径会把该页故障按默认动作投递 SIGSEGV（登记
/// zero_abi::signals 的 pending 位图），进程以退出码 -11 终止，父进程经
/// [wait_pid] 收集——本函数永不返回。
///
/// 为什么用内联汇编而不是 unsafe 空指针 write_volatile：LLVM 有权把
/// “必然 UB”的 Rust 级空指针写直接折叠成 UDF/brk 指令——那会走 SIGTRAP
/// 而非 SIGSEGV 路径。asm 里写死 mov x0, xzr + sturb wzr, [x0]：保证生成
/// 的就是对地址 0 的一条普通 store 字节（AArch64 的访存基址寄存器槽位
/// 与 SP 复用，XZR 不可作基址，故必须先落一个真寄存器），页表翻译必然
/// 失败、必然落入 abort 投递路径。
#[inline(never)]
pub fn cause_segv() -> ! {
    unsafe {
        // noreturn asm 不能声明输出；x0 被改写无所谓（进程即将消亡）。
        core::arch::asm!("mov x0, xzr", "sturb wzr, [x0]", options(noreturn));
    }
}

/// 等待子进程退出并收集其退出码（号位 22，POSIX wait4 最小集；阻塞版）。
///
/// - `pid = 0`：等待**任意**子进程；否则只等指定 pid 的子进程。
/// - 成功：`Ok((child_pid, exit_code))`。
/// - 无任何匹配子进程（含早已收过的重复 wait）：`Err(NotFound)`
///   （对应 POSIX ECHILD；幂等安全）。
/// - 有未退出的活子：调用方挂起，子退出时内核带回结果后本函数返回。
///
/// 非阻塞轮询请用 [`wait_pid_flags`] + [`WAIT_NOHANG`]。
pub fn wait_pid(pid: u64) -> Result<(u64, i32), SysError> {
    match wait_pid_flags(pid, 0)? {
        Some(pair) => Ok(pair),
        // flags=0 时内核不可能返回轮询落空（0 值只在 WNOHANG 下出现），
        // 此分支纯防御：视作无效结果而非静默错误。
        None => Err(SysError::InvalidArgument),
    }
}

/// [`Syscall::WaitPid`] 的 x3 flags 位（与 `zero_abi::syscall::WAIT_NOHANG`
/// 同值；此处再导出方便用户态只依赖 userlib 的场景）。
pub use zero_abi::syscall::WAIT_NOHANG;

/// 等待子进程（号位 22）的 **flags 扩展版**（第七刀）：
///
/// - `flags = 0`：与 [`wait_pid`] 完全一致（阻塞等待）。
/// - `flags` 含 [`WAIT_NOHANG`]（bit0）：无尸可收但有活子时**不挂起**，
///   立即返回 `Ok(None)`（内核侧返回 0；对照 Linux `wait4(..., WNOHANG)`
///   对未退出子进程返回 0 的约定）。pid≥2 恒非 0，故 0 值无歧义。
/// - 无任何匹配子进程：两种模式一致返回 `Err(NotFound)`（ECHILD）。
/// - 有尸可收：两种模式一致返回 `Ok(Some((pid, code)))` 并完成回收。
pub fn wait_pid_flags(pid: u64, flags: u64) -> Result<Option<(u64, i32)>, SysError> {
    let ret = svc_call(22, [pid, 0, flags, 0]);
    map_wait_value(decode_result(ret)?, flags)
}

/// 内核返回值 → 用户结果的纯映射（主机单测覆盖 WNOHANG 判定段；
/// 真实 svc 路径无法在宿主执行，判定逻辑收敛于此函数避免测试漂移）。
fn map_wait_value(value: u64, flags: u64) -> Result<Option<(u64, i32)>, SysError> {
    if value == 0 && flags & WAIT_NOHANG != 0 {
        return Ok(None); // 轮询落空：有活子、无尸可收
    }
    Ok(Some(unpack_wait_result(value)?))
}

/// 内核返回值解包：`(pid << 32) | (code as u32)` → (pid, code)。
/// 与内核 process::pack_wait_result 严格对称（负码按 32 位补码还原）。
fn unpack_wait_result(value: u64) -> Result<(u64, i32), SysError> {
    Ok((value >> 32, value as u32 as i32))
}

/// 创建当前进程的子进程（号位 2，`Syscall::Fork`）。
///
/// 返回值区分父子：
/// - 父进程：`Ok(child_pid)` —— 内核新分配的子进程 PID；
/// - 子进程：`Ok(0)` —— 内核把子进程 TrapFrame 的 x0 清零。
///
/// 语义：可写用户页以 COW 方式共享、只读页直接共享；任一方首写时
/// 内核复制该页并重放故障指令。内核栈、TrapFrame 与页表树仍各自独立。
/// 错误码见 `SysError`（NoMemory=克隆失败/表满，NotFound=无当前进程）。
pub fn fork() -> Result<u64, SysError> {
    let ret = svc_call(2, [0, 0, 0, 0]);
    decode_result(ret)
}

/// 替换当前进程映像为 rootfs 内 `path` 指向的 ELF（号位 3，POSIX exec 最小集）。
///
/// - **成功不返回**：内核销毁当前地址空间、装入新 ELF 并把控制流转向其
///   入口；新映像以 `x0`=bootfs 表首址、`x1`=条目数、`x2`=`arg` 起步。
///   配合 [`fork`] 即可实现"换程序不换 pid"（execdemo 模式）。
/// - 失败返回 `Err`：旧映像完好无损，调用方可原地继续（原子性）。
/// - `path` 必须是 rootfs 已登记文件：未登记返回 `NotFound`；已登记但
///   非合法 ELF 返回 `InvalidArgument`。
pub fn exec(path: &str, arg: u64) -> Result<(), SysError> {
    let ret = svc_call(3, [path.as_ptr() as u64, path.len() as u64, arg, 0]);
    decode_result(ret).map(|_| ())
}

/// 从控制台读取最多 `buffer.len()` 字节（号位 6）。
///
/// - 成功返回**实际读取的字节数**（可能小于 `len`）。
/// - 无按键输入时返回 `Err(WouldBlock)` —— 调用方应收敛为
///   [`yield_now`] 后重试；`WouldBlock` 不是致命错误。
pub fn console_read(buffer: &mut [u8]) -> Result<usize, SysError> {
    if buffer.is_empty() {
        return Ok(0);
    }
    let ret = svc_call(6, [buffer.as_mut_ptr() as u64, buffer.len() as u64, 0, 0]);
    match decode_result(ret)? {
        value => Ok(value as usize),
    }
}

/// 向控制台写入 `buffer`（号位 9）。
///
/// 内核按 512 字节分块搬入；空切片为幂等成功。
pub fn console_write(buffer: &[u8]) -> Result<(), SysError> {
    if buffer.is_empty() {
        return Ok(());
    }
    let ret = svc_call(9, [buffer.as_ptr() as u64, buffer.len() as u64, 0, 0]);
    decode_result(ret).map(|_| ())
}

/// 向通道发送一条消息（号位 0）。
///
/// 通道必须已由内核创建（见 [`zero_abi::channels`]）；
/// 队列满时返回 `Err(ChannelUnavailable)`。
/// `message` 会被内核整块拷贝（132 字节），不解析语义。
pub fn ipc_send(channel: u32, message: &Message) -> Result<(), SysError> {
    let ret = svc_call(0, [channel as u64, message as *const Message as u64, 0, 0]);
    decode_result(ret).map(|_| ())
}

/// Targeted response on a shared service channel (syscall 54).
pub fn ipc_send_to(channel: u32, target_pid: u64, message: &Message) -> Result<(), SysError> {
    decode_result(svc_call(
        54,
        [
            channel as u64,
            target_pid,
            message as *const Message as u64,
            0,
        ],
    ))
    .map(|_| ())
}

/// 从通道接收一条消息（号位 1）。
///
/// 队列空时**阻塞当前进程**，直到有本进程可收的消息；多事件源事件循环
/// 应使用 [`ipc_try_receive_from`]，不要在某一通道上把自己永久挂住。
pub fn ipc_receive_from(channel: u32, message: &mut Message) -> Result<u64, SysError> {
    let ret = svc_call(1, [channel as u64, message as *mut Message as u64, 0, 0]);
    decode_result(ret)
}

/// 兼容包装：忽略发送者身份。安全敏感服务应使用 [`ipc_receive_from`]。
pub fn ipc_receive(channel: u32, message: &mut Message) -> Result<(), SysError> {
    ipc_receive_from(channel, message).map(|_| ())
}

/// 非阻塞 IPC 接收（号位 55）。队列没有本进程可收消息时返回 WouldBlock。
pub fn ipc_try_receive_from(channel: u32, message: &mut Message) -> Result<u64, SysError> {
    let ret = svc_call(55, [channel as u64, message as *mut Message as u64, 0, 0]);
    decode_result(ret)
}

pub fn ipc_try_receive(channel: u32, message: &mut Message) -> Result<(), SysError> {
    ipc_try_receive_from(channel, message).map(|_| ())
}

/// 按 LBA 读块设备（号位 7）。`buffer.len()` 必须是 512 的倍数。
pub fn block_read(lba: u64, buffer: &mut [u8]) -> Result<(), SysError> {
    let ret = svc_call(7, [lba, buffer.as_mut_ptr() as u64, buffer.len() as u64, 0]);
    decode_result(ret).map(|_| ())
}

/// 按 LBA 写块设备（号位 8）。`buffer.len()` 必须是 512 的倍数。
pub fn block_write(lba: u64, buffer: &[u8]) -> Result<(), SysError> {
    let ret = svc_call(8, [lba, buffer.as_ptr() as u64, buffer.len() as u64, 0]);
    decode_result(ret).map(|_| ())
}

/// 共享内存对象描述（创建 / 查询的结果）。
pub struct SharedMemory {
    /// 句柄（后续 `shm_map` / `shm_len` / `shm_retain` / `shm_release` 使用）。
    pub handle: u32,
    /// 首次映射后的虚拟地址。
    pub ptr: *mut u8,
    /// 映射长度（字节）。
    pub len: usize,
}

/// 创建共享内存对象并映射进当前进程（号位 10）。
///
/// 内核把 `[handle, ptr, len]` 回填到内部缓冲区，返回即首次映射。
pub fn shm_create(size: usize) -> Result<SharedMemory, SysError> {
    let mut info = [0u64; 3];
    let ret = svc_call(10, [size as u64, info.as_mut_ptr() as u64, 0, 0]);
    decode_result(ret).map(|_| SharedMemory {
        handle: info[0] as u32,
        ptr: info[1] as *mut u8,
        len: info[2] as usize,
    })
}

/// 把已创建的共享内存映射到当前进程（号位 11），返回虚拟地址。
pub fn shm_map(handle: u32) -> Result<*mut u8, SysError> {
    let ret = svc_call(11, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|ptr| ptr as *mut u8)
}

/// 查询共享内存长度（号位 12）。
pub fn shm_len(handle: u32) -> Result<usize, SysError> {
    let ret = svc_call(12, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|len| len as usize)
}

/// 增加共享内存引用计数（号位 13）。
pub fn shm_retain(handle: u32) -> Result<(), SysError> {
    let ret = svc_call(13, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|_| ())
}

/// 释放共享内存引用计数（号位 14）；归零后由内核回收。
pub fn shm_release(handle: u32) -> Result<(), SysError> {
    let ret = svc_call(14, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|_| ())
}

/// 物理地址查询永久禁用：共享内存只暴露 opaque handle + 用户 VA。
pub fn shm_phys(handle: u32) -> Result<usize, SysError> {
    let ret = svc_call(17, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|addr| addr as usize)
}

/// owner 显式把 handle 授权给目标 pid（号位 46）。目标随后自行 shm_map。
pub fn shm_grant(handle: u32, target_pid: u64) -> Result<(), SysError> {
    let ret = svc_call(46, [handle as u64, target_pid, 0, 0]);
    decode_result(ret).map(|_| ())
}

pub fn input_read(event: &mut zero_abi::input::InputEvent) -> Result<(), SysError> {
    let ret = svc_call(47, [event as *mut _ as u64, 0, 0, 0]);
    decode_result(ret).map(|_| ())
}

pub fn display_present_bgrx(
    surface: &[u8],
    width: usize,
    height: usize,
    stride: usize,
) -> Result<(), SysError> {
    let ret = svc_call(
        48,
        [
            surface.as_ptr() as u64,
            width as u64,
            height as u64,
            stride as u64,
        ],
    );
    decode_result(ret).map(|_| ())
}

pub fn clock_get(clock_id: u32) -> Result<u64, SysError> {
    decode_result(svc_call(49, [clock_id as u64, 0, 0, 0]))
}
pub fn monotonic_ns() -> Result<u64, SysError> {
    clock_get(0)
}
pub fn realtime_ns() -> Result<u64, SysError> {
    clock_get(1)
}
pub fn sleep_until(deadline_ns: u64) -> Result<u64, SysError> {
    decode_result(svc_call(50, [deadline_ns, 0, 0, 0]))
}

pub fn net_send_frame(frame: &[u8]) -> Result<(), SysError> {
    decode_result(svc_call(
        51,
        [frame.as_ptr() as u64, frame.len() as u64, 0, 0],
    ))
    .map(|_| ())
}
/// Fill a buffer with cryptographically secure random bytes (syscall 56).
pub fn getrandom(out: &mut [u8]) -> Result<(), SysError> {
    let ret = svc_call(56, [out.as_mut_ptr() as u64, out.len() as u64, 0, 0]);
    decode_result(ret).map(|_| ())
}

/// Kernel-owned block device capacity in 512-byte sectors (syscall 57).
pub fn block_capacity_sectors() -> Result<u64, SysError> {
    decode_result(svc_call(57, [0, 0, 0, 0]))
}

/// Active kernel block backend (`zero_abi::protocol::blk::DEVICE_TYPE_*`, syscall 71).
/// Request a privileged platform power transition (syscall72). Successful
/// shutdown/reboot never returns; a returned Ok would only mean a broken firmware path.
pub fn power_control(action: u32) -> Result<(), SysError> {
    decode_result(svc_call(72, [action as u64, 0, 0, 0])).map(|_| ())
}

/// Read-only PCI inventory count (syscall 73).
pub fn pci_count() -> Result<usize, SysError> {
    decode_result(svc_call(73, [0, 0, 0, 0])).map(|v| v as usize)
}

/// Read-only PCI function snapshot (syscall 74).
pub fn pci_info(index: u32) -> Result<zero_abi::driver::PciFunctionInfo, SysError> {
    let mut info = zero_abi::driver::PciFunctionInfo::default();
    decode_result(svc_call(
        74,
        [
            index as u64,
            (&mut info as *mut zero_abi::driver::PciFunctionInfo) as u64,
            0,
            0,
        ],
    ))?;
    Ok(info)
}

/// Read-only virtio-net queue/transport diagnostic snapshot (syscall 75).
pub fn net_diag() -> Result<zero_abi::driver::NetDriverDiag, SysError> {
    let mut info = zero_abi::driver::NetDriverDiag::default();
    decode_result(svc_call(
        75,
        [
            (&mut info as *mut zero_abi::driver::NetDriverDiag) as u64,
            0,
            0,
            0,
        ],
    ))?;
    Ok(info)
}

pub fn block_backend_type() -> Result<u8, SysError> {
    decode_result(svc_call(71, [0, 0, 0, 0])).map(|v| v as u8)
}

/// Spawn an ELF image from the caller's verified byte buffer (syscall58).
/// Requires a dynamically granted CAP_SPAWN_APP.
pub fn spawn_image(image: &[u8]) -> Result<u64, SysError> {
    if image.len() < 64 {
        return Err(SysError::InvalidArgument);
    }
    decode_result(svc_call(
        58,
        [image.as_ptr() as u64, image.len() as u64, 0, 0],
    ))
}

pub fn net_recv_frame(frame: &mut [u8]) -> Result<usize, SysError> {
    decode_result(svc_call(
        52,
        [frame.as_mut_ptr() as u64, frame.len() as u64, 0, 0],
    ))
    .map(|n| n as usize)
}

pub fn net_get_mac() -> Result<[u8; 6], SysError> {
    let mut mac = [0u8; 6];
    decode_result(svc_call(53, [mac.as_mut_ptr() as u64, 0, 0, 0])).map(|_| mac)
}

/// Query the fixed first-generation PCM contract (syscall 59).
pub fn audio_info() -> Result<zero_abi::audio::AudioInfo, SysError> {
    let mut info = zero_abi::audio::AudioInfo::default();
    decode_result(svc_call(59, [&mut info as *mut _ as u64, 0, 0, 0]))?;
    Ok(info)
}
/// Submit one audio period (syscall 60; audiod-only capability).
pub fn audio_play_period(pcm: &[u8]) -> Result<(), SysError> {
    decode_result(svc_call(60, [pcm.as_ptr() as u64, pcm.len() as u64, 0, 0])).map(|_| ())
}
pub fn audio_stop() -> Result<(), SysError> {
    decode_result(svc_call(61, [0, 0, 0, 0])).map(|_| ())
}

/// Query the negotiated VirtIO-GPU 3D contract (syscall 62; CAP_DISPLAY).
pub fn gpu3d_info() -> Result<zero_abi::gpu::Gpu3dInfo, SysError> {
    let mut info = zero_abi::gpu::Gpu3dInfo::default();
    decode_result(svc_call(62, [&mut info as *mut _ as u64, 0, 0, 0]))?;
    Ok(info)
}
pub fn gpu3d_context_create(capset_id: u32) -> Result<u32, SysError> {
    decode_result(svc_call(63, [capset_id as u64, 0, 0, 0])).map(|v| v as u32)
}
pub fn gpu3d_context_destroy(ctx: u32) -> Result<(), SysError> {
    decode_result(svc_call(64, [ctx as u64, 0, 0, 0])).map(|_| ())
}
pub fn gpu3d_resource_create(desc: &zero_abi::gpu::Gpu3dResourceDesc) -> Result<u32, SysError> {
    decode_result(svc_call(65, [desc as *const _ as u64, 0, 0, 0])).map(|v| v as u32)
}
pub fn gpu3d_resource_destroy(id: u32) -> Result<(), SysError> {
    decode_result(svc_call(66, [id as u64, 0, 0, 0])).map(|_| ())
}
pub fn gpu3d_context_attach(ctx: u32, id: u32) -> Result<(), SysError> {
    decode_result(svc_call(67, [ctx as u64, id as u64, 0, 0])).map(|_| ())
}
pub fn gpu3d_submit(ctx: u32, stream: &[u8]) -> Result<(), SysError> {
    decode_result(svc_call(
        68,
        [ctx as u64, stream.as_ptr() as u64, stream.len() as u64, 0],
    ))
    .map(|_| ())
}
pub fn gpu3d_readback(id: u32, out: &mut [u8]) -> Result<usize, SysError> {
    decode_result(svc_call(
        69,
        [id as u64, out.as_mut_ptr() as u64, out.len() as u64, 0],
    ))
    .map(|v| v as usize)
}
pub fn gpu3d_get_capset(capset_id: u32, version: u32, out: &mut [u8]) -> Result<usize, SysError> {
    decode_result(svc_call(
        70,
        [
            capset_id as u64,
            version as u64,
            out.as_mut_ptr() as u64,
            out.len() as u64,
        ],
    ))
    .map(|v| v as usize)
}

/// 驱动信息记录（`DriverInfo` 系统调用回填的投影格式，
/// 与内核 `syscalls.rs::write_driver_info` 输出布局一致）。
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DriverInfo {
    /// 设备种类（[`zero_abi::driver::DriverKind`] 的 `u32` 值）。
    pub kind: u32,
    /// PCI identity packed as low16=vendor, high16=device; zero for non-PCI.
    /// This field occupies historical repr(C) padding, preserving all old offsets.
    pub pci_id: u32,
    /// MMIO 寄存器基地址（物理地址）。
    pub mmio_base: u64,
    /// MMIO 区域长度。
    pub mmio_len: u64,
    /// 中断号。
    pub irq: u32,
    /// low bytes: class, subclass, prog_if, revision; zero for non-PCI.
    /// This occupies the historical tail padding; total ABI size stays 32 bytes.
    pub pci_class: u32,
}

/// 查询驱动描述符数量（号位 15）。
pub fn driver_count() -> Result<u64, SysError> {
    let ret = svc_call(15, [0, 0, 0, 0]);
    decode_result(ret)
}

/// 查询第 `index` 个驱动的信息（号位 16）。
///
/// `index` 越界 / 无驱动表时返回 `Err(NotFound)`。
pub fn driver_info(index: u32) -> Result<DriverInfo, SysError> {
    let mut info = DriverInfo {
        kind: 0,
        pci_id: 0,
        mmio_base: 0,
        mmio_len: 0,
        irq: 0,
        pci_class: 0,
    };
    let ret = svc_call(16, [index as u64, &mut info as *mut _ as u64, 0, 0]);
    decode_result(ret).map(|_| info)
}

/// MMIO 租约描述（映射成功后返回）。
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    /// Capability-gated user virtual address of the mapped register window.
    pub base: u64,
    /// 寄存器区长度。
    pub len: u64,
}

/// 申请第 `index` 个驱动的 MMIO 租约（号位 18）。
///
/// Requires CAP_MMIO. Success installs Device-nGnRE pages into the caller's
/// address space and returns their EL0 virtual range; the physical BAR stays an
/// inventory detail and is never directly dereferenced by EL0.
pub fn mmio_map(index: u32) -> Result<MmioRegion, SysError> {
    let mut info = [0u64; 2];
    let ret = svc_call(18, [index as u64, info.as_mut_ptr() as u64, 0, 0]);
    decode_result(ret).map(|base| MmioRegion { base, len: info[1] })
}

/// 释放第 `index` 个驱动的 MMIO 租约（号位 19）。
pub fn mmio_unmap(index: u32) -> Result<(), SysError> {
    let ret = svc_call(19, [index as u64, 0, 0, 0]);
    decode_result(ret).map(|_| ())
}

/// 按服务名启动内核登记的服务（号位 20）。
///
/// 语义：`name` 必须是内核 `services::SERVICE_REGISTRY` 已登记的
/// 服务名（当前仅 `"launchd"` 被引导期登记；其余服务名需要
/// 内核 Agent 在 `services::launch_core` 中补充登记后才可启动）。
/// 成功返回**新进程 PID**；名字未登记返回 `Err(NotFound)`。
/// 仅特权进程可调用；普通进程返回 `Err(PermissionDenied)`。
///
/// 与实际启动路径：`launchd spawn <name>` 命令 → 本包装 →
/// 服务控制器（service-controller）与其配合：
/// 需要生命周期管理（keepalive / 状态上报）时建议走
/// `SERVICE_CONTROL_BUS` 通道，而不是裸调用本函数。
pub fn service_spawn(name: &str) -> Result<u64, SysError> {
    if name.is_empty() {
        return Err(SysError::InvalidArgument);
    }
    let ret = svc_call(20, [name.as_ptr() as u64, name.len() as u64, 0, 0]);
    decode_result(ret)
}

/// 查询当前进程 PID（号位 21）。
///
/// 内核已对接（`trap.rs::decode_syscall` 号位 21 → `syscalls::GetPid`
/// 返回当前 slot 的 pid），shell 的 `pid` 命令已端到端验证。
pub fn getpid() -> Result<u64, SysError> {
    let ret = svc_call(21, [0, 0, 0, 0]);
    decode_result(ret)
}

/// 查询当前进程的父进程 PID（号位 23）。
///
/// 语义对齐内核孤儿策略（`zero_abi::syscall::Syscall::GetPpid` 文档）：
/// - fork 出的子进程返回父进程 pid（含被 init 收养的孤儿——返回收养者
///   launchd 的 pid=2）；
/// - 内核直生根进程（服务注册表 spawn 路径，如 shell 自身）无父，
///   返回 0。
pub fn getppid() -> Result<u64, SysError> {
    let ret = svc_call(23, [0, 0, 0, 0]);
    decode_result(ret)
}

/// 调整用户堆 break（号位 24，POSIX brk 最小集）。
///
/// - `new_break = 0`：查询——返回当前 break（堆区域为
///   `[USER_HEAP_BASE=0x1000_0000, break)`，初始 break == 基址）；
/// - `new_break > 当前`：内核按页分配零页映入增长区间；
/// - `new_break < 当前`：解除映射并归还物理页；
/// - 成功返回**生效后的新 break**（内核向上对齐到 4KiB 页界后的规范值，
///   与 Linux 返回原始请求值的差异见 ABI 冻结注释披露）；
/// - 越过堆基址下界 → `Err(InvalidArgument)`；越过 64 MiB 上限或物理
///   内存不足 → `Err(NoMemory)`（对应 POSIX ENOMEM）。
pub fn brk(new_break: usize) -> Result<usize, SysError> {
    let ret = svc_call(24, [new_break as u64, 0, 0, 0]);
    decode_result(ret).map(|v| v as usize)
}

/// 睡眠 ticks 个 timer tick（号位 25，第十一刀）。
///
/// 成功返回实际流逝的 tick 数（≥ 请求值，实机可断言「真睡眠不忙等」）；
/// `ticks == 0` 立即返回 Ok(0)。睡眠期间进程 Blocked、不参与调度。
pub fn sleep_ticks(ticks: u64) -> Result<u64, SysError> {
    let ret = svc_call(25, [ticks, 0, 0, 0]);
    decode_result(ret)
}

/// 在调用方地址空间内创建线程（号位 26，第十五刀）。
///
/// 返回新线程 tid（真 pid，可用 [`wait_pid`] join）。共享语义：堆与
/// 已映射页立即可见。`entry` 不得返回——应自行调用 [`exit`]（线程
/// 语境下仅终结本线程）。
///
/// # Safety
/// `entry`/`stack_top` 必须指向调用方地址空间内的合法代码/栈；
/// `stack_top` 需预留足够深度且 16 字节对齐。
pub unsafe fn create_thread(
    entry: usize,
    stack_top: usize,
    tls: usize,
    arg: usize,
) -> Result<u64, SysError> {
    let ret = svc_call(26, [entry as u64, stack_top as u64, tls as u64, arg as u64]);
    decode_result(ret)
}

/// futex 条件等待（号位 27）：`*uaddr == expected` 才睡眠。
/// 返回 Ok(0)=被唤醒；Err 里带不匹配时的实际值语义由内核约定：
/// 不匹配时内核直接返回 actual（非错误码），故此处 actual 会经
/// decode_result 变成 Ok(actual)——调用方用 [`futex_wait`] 即可屏蔽。
pub fn futex_wait_raw(uaddr: usize, expected: u32) -> Result<u64, SysError> {
    let ret = svc_call(27, [uaddr as u64, expected as u64, 0, 0]);
    decode_result(ret)
}

/// 唤醒至多 max 个等在 uaddr 的线程，返回实际唤醒数（号位 28）。
pub fn futex_wake(uaddr: usize, max: usize) -> Result<usize, SysError> {
    let ret = svc_call(28, [uaddr as u64, max as u64, 0, 0]);
    decode_result(ret).map(|v| v as usize)
}

/// 以**增量**调整用户堆 break（号位 24 的 POSIX sbrk 语义封装）。
///
/// 成功返回**调用前的旧 break**（对照 POSIX sbrk：返回值指向新分配
/// 区域的起点，`旧break .. 旧break+delta` 即本次到手的内存）。`delta
/// = 0` 等价于查询当前 break。
///
/// 失败返回 `Err` 且 break 保持不变（正增量 OOM 回滚由内核保证原子性）。
pub fn sbrk(delta: i64) -> Result<usize, SysError> {
    let cur = brk(0)?;
    let target = sbrk_next(cur, delta).ok_or(SysError::InvalidArgument)?;
    brk(target)?;
    Ok(cur)
}

/// sbrk 目标值纯计算（主机单测钉死；溢出一律 None → 上层报错且不动堆）。
fn sbrk_next(cur: usize, delta: i64) -> Option<usize> {
    if delta >= 0 {
        cur.checked_add(delta as usize)
    } else {
        cur.checked_sub(delta.unsigned_abs() as usize)
    }
}

// ═══ 第十三刀：capability 动态签发 / 会话（号位 40-45）════════════

/// 动态签发能力授予（号位 40）。**仅 securityd（CAP_ISSUER 持有者）
/// 可调**；普通进程返回 `Err(PermissionDenied)`。
///
/// - `target_pid`：被授予进程；`caps`：[`zero_abi::cap`] 位或组合；
/// - `ttl`：有效期（逻辑 tick，见 zero-abi 号位 40 文档；0=不过期）。
/// - 成功返回内核分配的令牌编号 token（撤销/校验凭据）。
pub fn cap_grant(target_pid: u64, caps: u32, ttl: u64) -> Result<u64, SysError> {
    let ret = svc_call(40, [target_pid, caps as u64, ttl, 0]);
    decode_result(ret)
}

/// 撤销能力授予（号位 41）。仅 CAP_ISSUER 持有者可调；未知令牌返回
/// `Err(NotFound)`。撤销即时生效（活算模型，无需回写目标进程）。
pub fn cap_revoke(token: u64) -> Result<(), SysError> {
    let ret = svc_call(41, [token, 0, 0, 0]);
    decode_result(ret).map(|_| ())
}

/// 创建 IPC 通道（号位 42）：`desc` 的 tx/rx_groups 任一非 0（受保护
/// 通道）需要 CAP_CHANNEL_CREATE 能力。id 冲突返回
/// `Err(ChannelUnavailable)`。
pub fn create_channel(desc: &zero_abi::ipc::ChannelDesc) -> Result<(), SysError> {
    let ret = svc_call(
        42,
        [desc as *const zero_abi::ipc::ChannelDesc as u64, 0, 0, 0],
    );
    decode_result(ret).map(|_| ())
}

/// 建立登录会话（号位 43）：消费本进程名下一枚含 CAP_SESSION 的登录
/// 令牌，返回新会话 id（≥1）。su 场景下旧会话整体注销（绑定旧会话的
/// 授予一并失效——跨会话重放防线）。
pub fn session_begin(login_token: u64) -> Result<u64, SysError> {
    let ret = svc_call(43, [login_token, 0, 0, 0]);
    decode_result(ret)
}

/// 查询当前进程会话 id（号位 44）；无会话返回 0。
pub fn get_session() -> Result<u64, SysError> {
    let ret = svc_call(44, [0, 0, 0, 0]);
    decode_result(ret)
}

/// 列出全部存活会话（号位 45）：行集 `sid=N leader=P\n` 写入 buffer
/// （截断到容量），返回实际写入字节数。
pub fn session_list(buffer: &mut [u8]) -> Result<usize, SysError> {
    let ret = svc_call(45, [buffer.as_mut_ptr() as u64, buffer.len() as u64, 0, 0]);
    decode_result(ret).map(|v| v as usize)
}

/// 把 `code` 与文本载荷编码为一条 IPC `Message`。
///
/// `text` 最多 127 字节（payload 128 字节，末字节保持 0，
/// 保证下游 NUL 结尾文本解析的正确收尾）。返回编码后的消息，
/// 可直接交给 [`ipc_send`]。
pub fn encode_message(code: u32, text: &[u8]) -> Message {
    let mut message = Message::empty();
    message.code = code;
    let len = text.len().min(message.payload.len().saturating_sub(1));
    message.payload[..len].copy_from_slice(&text[..len]);
    message
}

/// 从 payload 中提取 NUL 结尾的文本（无 NUL 时取满 128 字节）。
pub fn extract_payload_text(payload: &[u8]) -> &str {
    let len = payload
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(payload.len());
    core::str::from_utf8(&payload[..len]).unwrap_or("")
}

fn decode_result(value: u64) -> Result<u64, SysError> {
    zero_abi::syscall::decode(value)
}
#[cfg(test)]
mod tests {
    #[test]
    fn driver_info_abi_reuses_padding_without_growth() {
        assert_eq!(core::mem::size_of::<DriverInfo>(), 32);
        assert_eq!(core::mem::offset_of!(DriverInfo, kind), 0);
        assert_eq!(core::mem::offset_of!(DriverInfo, pci_id), 4);
        assert_eq!(core::mem::offset_of!(DriverInfo, mmio_base), 8);
        assert_eq!(core::mem::offset_of!(DriverInfo, mmio_len), 16);
        assert_eq!(core::mem::offset_of!(DriverInfo, irq), 24);
        assert_eq!(core::mem::offset_of!(DriverInfo, pci_class), 28);
    }

    use super::*;
    use zero_abi::syscall::{decode, SysError};

    #[test]
    fn decode_ok_values_pass_through() {
        assert_eq!(decode_result(0).unwrap(), 0);
        assert_eq!(decode_result(42).unwrap(), 42);
        // 错误区间下界（u64::MAX - 8 已被 NotSupported 占用，第八刀）
        // 之外的值一律视为成功。
        assert_eq!(decode_result(u64::MAX - 9).unwrap(), u64::MAX - 9);
    }

    #[test]
    fn decode_error_interval_maps_to_sys_error() {
        assert_eq!(decode_result(u64::MAX), Err(SysError::InvalidArgument));
        assert_eq!(decode_result(u64::MAX - 1), Err(SysError::PermissionDenied));
        assert_eq!(
            decode_result(u64::MAX - 2),
            Err(SysError::ChannelUnavailable)
        );
        assert_eq!(decode_result(u64::MAX - 3), Err(SysError::NotFound));
        assert_eq!(decode_result(u64::MAX - 4), Err(SysError::NoMemory));
        assert_eq!(decode_result(u64::MAX - 5), Err(SysError::WouldBlock));
        assert_eq!(decode_result(u64::MAX - 6), Err(SysError::DeviceError));
        assert_eq!(decode_result(u64::MAX - 7), Err(SysError::Busy));
        // 第八刀新增：SHM 族下线的 NotSupported（k=8）。
        assert_eq!(decode_result(u64::MAX - 8), Err(SysError::NotSupported));
    }

    #[test]
    fn sys_error_code_roundtrip() {
        // SysError::code() 与内核 encode_result 映射一致
        assert_eq!(SysError::InvalidArgument.code(), u64::MAX);
        assert_eq!(SysError::Busy.code(), u64::MAX - 7);
        for err in [
            SysError::InvalidArgument,
            SysError::PermissionDenied,
            SysError::ChannelUnavailable,
            SysError::NotFound,
            SysError::NoMemory,
            SysError::WouldBlock,
            SysError::DeviceError,
            SysError::Busy,
            SysError::NotSupported,
        ] {
            assert_eq!(decode(err.code()), Err(err));
        }
        assert_eq!(SysError::WouldBlock.as_str(), "would block");
    }

    #[test]
    fn encode_message_keeps_code_and_truncates_text() {
        let m = encode_message(0x42, b"hello");
        assert_eq!(m.code, 0x42);
        assert_eq!(extract_payload_text(&m.payload), "hello");
        assert_eq!(m.payload[5], 0);

        // 长文本截断到 127 字节，保留 NUL 收尾
        let long = [b'x'; 200];
        let m = encode_message(7, &long);
        assert_eq!(m.code, 7);
        assert_eq!(extract_payload_text(&m.payload).len(), 127);
        assert_eq!(m.payload[127], 0);
    }

    #[test]
    fn wait_pid_unpack_matches_kernel_pack() {
        // 与内核 process::pack_wait_result 的编码严格对称：
        // packed = (pid << 32) | (code as u32)，负码按补码无损还原。
        let pack = |pid: u64, code: i32| (pid << 32) | (code as u32 as u64);
        for (pid, code) in [
            (7u64, 42i32),
            (1234, 0),
            (64, -1),
            (u32::MAX as u64, i32::MIN),
        ] {
            assert_eq!(unpack_wait_result(pack(pid, code)).unwrap(), (pid, code));
        }
        // 注：错误区间由 wait_pid 内的 decode_result 先行拦截（见
        // decode_error_interval_maps_to_sys_error），unpack 只处理成功值。
    }

    #[test]
    fn wnohang_zero_result_maps_to_none_only_when_flagged() {
        // 内核 WNOHANG 落空返回 0：flags 带 bit0 ⇒ Ok(None)（不挂起）。
        assert_eq!(map_wait_value(0, WAIT_NOHANG), Ok(None));
        // flags=0 时的 0 值：收尸结果恒含 pid≥2，0 不是合法收尸值，
        // 但映射层不做二次判读——原样透传 Some((0,0))，绝不吞异常返回。
        assert_eq!(map_wait_value(0, 0), Ok(Some((0, 0))));
        // 未定义位不参与判定：bit1 置位但无 bit0 ≠ WNOHANG
        assert_eq!(map_wait_value(0, 0b10), Ok(Some((0, 0))));
        // 正常收尸值在 WNOHANG 模式下照常解包
        let packed = (7u64 << 32) | 42u32 as u64;
        assert_eq!(map_wait_value(packed, WAIT_NOHANG), Ok(Some((7, 42))));
    }

    #[test]
    fn message_layout_is_frozen() {
        // 冻结布局：code@0，payload@4，总大小 132 字节
        assert_eq!(core::mem::size_of::<Message>(), 132);
        assert_eq!(core::mem::align_of::<Message>(), 4);
    }

    #[test]
    fn sbrk_target_math_and_overflow_guards() {
        const HB: usize = 0x1000_0000;
        // 正增量：旧 break + delta。
        assert_eq!(sbrk_next(HB, 0), Some(HB));
        assert_eq!(sbrk_next(HB, 8192), Some(HB + 8192));
        // 负增量：收缩到旧 break - |delta|（i64::MIN 的 unsigned_abs 无溢出）。
        assert_eq!(sbrk_next(HB + 8192, -4096), Some(HB + 4096));
        assert_eq!(sbrk_next(HB, -(HB as i64)), Some(0));
        // 溢出防御：上溢/下溢一律 None（上层转 InvalidArgument，不动堆）。
        assert_eq!(sbrk_next(usize::MAX, 1), None);
        assert_eq!(sbrk_next(0, -1), None);
        // i64::MIN：unsigned_abs 无溢出，但收缩量超过当前 break ⇒ 下溢 None。
        assert_eq!(sbrk_next(HB, i64::MIN), None);
    }
}
// ═══ 第十五刀二期：用户态互斥锁（futex 慢路径）═══════════════════
//
// 三态字约定（Linux 风格）：0=解锁、1=锁定无竞争、2=锁定有等待者。
// lock 快路径 CAS 0→1；失败置 2 并 FutexWait(2)；unlock 置 0 后若
// 此前为 2 则 FutexWake(1)。

use core::sync::atomic::{AtomicU32, Ordering};

const MUTEX_UNLOCKED: u32 = 0;
const MUTEX_LOCKED: u32 = 1;
const MUTEX_CONTENDED: u32 = 2;

/// 内核辅助的互斥锁。`T` 值本身由使用者另行存放（本锁只管门闩），
/// 或直接把 `Mutex<u32>` 当计数闸使用。
pub struct UserMutex {
    word: AtomicU32,
}

impl UserMutex {
    pub const fn new() -> Self {
        Self {
            word: AtomicU32::new(MUTEX_UNLOCKED),
        }
    }

    /// 加锁：快路径 CAS 0→1；一旦进入竞争慢路径，获得锁的线程保持
    /// word=2（CONTENDED）而不是降回 1。这样它 unlock 时一定 wake 下一
    /// 个 waiter，直到等待链耗尽。旧实现 wake 后递归走 0→1，会把
    /// “还有其它 waiter”信息抹掉：三线程 SMP 下第一个被唤醒者解锁时
    /// 不再 FutexWake，剩余线程永久睡眠。
    pub fn lock(&self) {
        if self
            .word
            .compare_exchange(
                MUTEX_UNLOCKED,
                MUTEX_LOCKED,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return;
        }

        loop {
            // swap(2) 原子完成两件事：若前值非0则维持“有竞争者”标记；
            // 若前值恰为0，则本线程直接以 state=2 获得锁，保留 wake 链。
            if self.word.swap(MUTEX_CONTENDED, Ordering::Acquire) == MUTEX_UNLOCKED {
                return;
            }
            while self.word.load(Ordering::Relaxed) == MUTEX_CONTENDED {
                let _ = futex_wait_raw(self.word.as_ptr() as usize, MUTEX_CONTENDED);
            }
        }
    }

    /// 解锁：置 0；此前为 CONTENDED 则唤醒一个等待者。
    pub fn unlock(&self) {
        if self.word.swap(MUTEX_UNLOCKED, Ordering::Release) == MUTEX_CONTENDED {
            let _ = futex_wake(self.word.as_ptr() as usize, 1);
        }
    }
}

#[cfg(test)]
mod user_mutex_state_tests {
    use super::*;

    #[test]
    fn contended_successor_keeps_state_two_and_chains_wakeup() {
        let word = AtomicU32::new(MUTEX_LOCKED);
        // Two contenders both advertise contention while the original owner runs.
        assert_eq!(word.swap(MUTEX_CONTENDED, Ordering::Acquire), MUTEX_LOCKED);
        assert_eq!(
            word.swap(MUTEX_CONTENDED, Ordering::Acquire),
            MUTEX_CONTENDED
        );
        // Original owner must observe 2 and therefore wake one waiter.
        assert_eq!(
            word.swap(MUTEX_UNLOCKED, Ordering::Release),
            MUTEX_CONTENDED
        );
        // Woken waiter acquires through the slow path and deliberately leaves 2.
        assert_eq!(
            word.swap(MUTEX_CONTENDED, Ordering::Acquire),
            MUTEX_UNLOCKED
        );
        assert_eq!(word.load(Ordering::Relaxed), MUTEX_CONTENDED);
        // Its unlock must still observe 2, guaranteeing wake chaining.
        assert_eq!(
            word.swap(MUTEX_UNLOCKED, Ordering::Release),
            MUTEX_CONTENDED
        );
    }
}

/// 条件变量（第十五刀二期 · futex 实现）。
///
/// 用法契约：`wait` 必须在持有配套 [`UserMutex`] 时调用——内部先解锁、
/// 睡眠、被唤醒后重新加锁返回（对照 POSIX pthread_cond_wait 的原子
/// 释放-等待语义，由「先解互斥锁再 futex 睡眠」的顺序近似；存在经典
/// 唤醒丢失窗口的调用方应改用带谓词的重试循环）。
pub struct Condvar {
    word: AtomicU32,
}

impl Condvar {
    pub const fn new() -> Self {
        Self {
            word: AtomicU32::new(0),
        }
    }

    /// 阻塞等待：解锁 `m` → futex 睡眠 → 醒来后重加锁 `m`。
    pub fn wait(&self, m: &UserMutex) {
        m.unlock();
        let _ = futex_wait_raw(self.word.as_ptr() as usize, 0);
        m.lock();
    }

    /// 唤醒一个等待者。
    pub fn notify_one(&self) {
        let _ = futex_wake(self.word.as_ptr() as usize, 1);
    }

    /// 唤醒全部等待者。
    pub fn notify_all(&self) {
        let _ = futex_wake(self.word.as_ptr() as usize, u32::MAX as usize);
    }
}
