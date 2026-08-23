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
/// 语义：子进程获得父进程用户地址空间的 eager-copy 副本（独立物理页、
/// 同一虚拟布局），从 svc 返回点之后继续执行；内核栈与 TrapFrame 各自
/// 独立。错误码见 `SysError`（NoMemory=克隆失败/表满，NotFound=无当前进程）。
pub fn fork() -> Result<u64, SysError> {
    let ret = svc_call(2, [0, 0, 0, 0]);
    decode_result(ret)
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

/// 从通道接收一条消息（号位 1）。
///
/// 队列空时返回 `Err(WouldBlock)` —— 服务器主循环的标准写法是
/// 收到 `WouldBlock` 后 [`yield_now`] 再重收。
pub fn ipc_receive(channel: u32, message: &mut Message) -> Result<(), SysError> {
    let ret = svc_call(1, [channel as u64, message as *mut Message as u64, 0, 0]);
    decode_result(ret).map(|_| ())
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

/// 查询共享内存首个物理页地址（号位 17）；
/// 供与内核交换物理页的底层场景使用。
pub fn shm_phys(handle: u32) -> Result<usize, SysError> {
    let ret = svc_call(17, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|addr| addr as usize)
}

/// 驱动信息记录（`DriverInfo` 系统调用回填的投影格式，
/// 与内核 `syscalls.rs::write_driver_info` 输出布局一致）。
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DriverInfo {
    /// 设备种类（[`zero_abi::driver::DriverKind`] 的 `u32` 值）。
    pub kind: u32,
    /// MMIO 寄存器基地址（物理地址）。
    pub mmio_base: u64,
    /// MMIO 区域长度。
    pub mmio_len: u64,
    /// 中断号。
    pub irq: u32,
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
        mmio_base: 0,
        mmio_len: 0,
        irq: 0,
    };
    let ret = svc_call(16, [index as u64, &mut info as *mut _ as u64, 0, 0]);
    decode_result(ret).map(|_| info)
}

/// MMIO 租约描述（映射成功后返回）。
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    /// 寄存器区基地址（物理地址）。
    pub base: u64,
    /// 寄存器区长度。
    pub len: u64,
}

/// 申请第 `index` 个驱动的 MMIO 租约（号位 18）。
///
/// **仅特权进程**（引导期内核登记的服务）允许；普通进程返回
/// `Err(PermissionDenied)`。成功后返回区域信息，此后才能合法访问。
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
    use super::*;
    use zero_abi::syscall::{decode, SysError};

    #[test]
    fn decode_ok_values_pass_through() {
        assert_eq!(decode_result(0).unwrap(), 0);
        assert_eq!(decode_result(42).unwrap(), 42);
        // 错误区间下界（u64::MAX - 7）之外的值一律视为成功
        assert_eq!(decode_result(u64::MAX - 8).unwrap(), u64::MAX - 8);
    }

    #[test]
    fn decode_error_interval_maps_to_sys_error() {
        assert_eq!(decode_result(u64::MAX), Err(SysError::InvalidArgument));
        assert_eq!(decode_result(u64::MAX - 1), Err(SysError::PermissionDenied));
        assert_eq!(decode_result(u64::MAX - 2), Err(SysError::ChannelUnavailable));
        assert_eq!(decode_result(u64::MAX - 3), Err(SysError::NotFound));
        assert_eq!(decode_result(u64::MAX - 4), Err(SysError::NoMemory));
        assert_eq!(decode_result(u64::MAX - 5), Err(SysError::WouldBlock));
        assert_eq!(decode_result(u64::MAX - 6), Err(SysError::DeviceError));
        assert_eq!(decode_result(u64::MAX - 7), Err(SysError::Busy));
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
        for (pid, code) in [(7u64, 42i32), (1234, 0), (64, -1), (u32::MAX as u64, i32::MIN)] {
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
}