use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::str;
use spin::Mutex;
use zero_abi::ipc::Message;
use zero_abi::syscall::{SysError, Syscall, SyscallResult};

use crate::process::TrapFrame;
use crate::runtime::serial;
use crate::shm;

#[derive(Clone, Copy)]
struct MmioLease {
    slot: usize,
    index: u32,
    refs: u32,
}

static MMIO_LEASES: Mutex<Vec<MmioLease>> = Mutex::new(Vec::new());

/// 用户地址空间布局（与 mm/paging.rs 一致）。冻结值自工程化第八刀起
/// 单源于 `zero_abi::validate`（宿主可测纯函数层，见 tools/fuzz-syscall）；
/// 内核侧仅保留 usize 镜像常量供既有单测对照（非测试构建不编译）：
/// - [USER_VA_LO, 1GiB)：用户代码/数据（L1[0] 私有副本，可映射）
/// - [1GiB, 2GiB)：内核专用共享表（L1[1]），用户指针一律拒绝
/// - [2GiB, USER_VA_MAX]：bootfs 与用户栈（L1[2]/L1[3] 私有表，可映射）
#[cfg(test)]
const USER_VA_LO: usize = zero_abi::validate::USER_VA_LO as usize;
#[cfg(test)]
const KERNEL_REGION_START: usize = zero_abi::validate::KERNEL_REGION_START as usize; // 1 GiB
#[cfg(test)]
const KERNEL_REGION_END: usize = zero_abi::validate::KERNEL_REGION_END as usize; // 2 GiB
#[cfg(test)]
const USER_VA_MAX: usize = zero_abi::validate::USER_VA_MAX as usize; // 用户栈顶（4GiB - 4KiB）

/// QEMU virt 外设空间（MMIO 设备区）边界冻结于
/// `zero_abi::validate::DEVICE_MMIO_LO/HI`（[0x0800_0000, 0x1000_0000)，
/// GIC/PL011/virtio-mmio 所在区间）；内核侧无本地镜像——mmio lease 校验
/// 已整体委托该纯函数。

/// 用户指针校验（第一道：地址范围 + 布局）。
///
/// 📌 协调点（mm Agent）：当前只查范围，不查映射存在性 —— 未映射页
/// 仍会由硬件 data abort 兜底杀进程（可用），但要防"读脏地址才爆炸"
/// 的窗口。待 mm Agent 落地 `AddressSpace::translate_user_addr` 或等价
/// 页表 walk（见 mm/paging.rs：L0→L1→L2→L3 四级翻译 + PHYS_ADDR_MASK），
/// 在此追加"逐页映射存在性"检查：每个 4KiB 页的 L3 entry valid &&
/// 非块描述符。调用方已按页步进拷贝（见 copy_slice_from/to_user），
/// 每页一个校验点即可无缝接入。
fn validate_user_ptr(addr: usize, size: usize) -> Result<(), SysError> {
    // 工程化第八刀：判定逻辑上收 `zero_abi::validate`（纯函数、宿主可测、
    // 由 tools/fuzz-syscall 模糊覆盖）；usize→u64 在 AArch64 同宽，语义逐位一致。
    zero_abi::validate::validate_user_ptr(addr as u64, size as u64)
}

/// mmio lease 校验：phys 必须落在 QEMU virt 设备区且长度不越界。
fn validate_mmio_region(base: u64, len: u64) -> Result<(), SysError> {
    // 同上：真值源在 `zero_abi::validate`（u64 签名原生对齐，无类型适配）。
    zero_abi::validate::validate_mmio_region(base, len)
}

/// 阻塞接收的收尾（由 scheduler::dispatch 在重入用户态前调用）。
/// 虚假唤醒（唤醒者发送后消息被他人取走等）自动重新挂起。
pub fn complete_receive(slot: usize, chan: u32) {
    let pid = crate::process::pid_at_slot(slot).expect("pending recv: no pid");
    let frame = unsafe { crate::process::trap_frame(slot) };
    loop {
        match crate::ipc::receive(pid, chan) {
            Ok(message) => {
                unsafe {
                    let user_buffer = (*frame).regs[2] as usize;
                    let result = copy_message_to_user(user_buffer, &message);
                    (*frame).regs[0] =
                        crate::trap::encode_result(result.map(|_| 0));
                }
                return;
            }
            Err(_) => {
                let _ = crate::ipc::register_waiter(pid, chan);
                crate::process::set_pending_recv(slot, chan);
                crate::scheduler::block_current();
            }
        }
    }
}

pub fn handle(syscall: Syscall, frame: *mut TrapFrame) -> SyscallResult {
    match syscall {
        Syscall::SendMessage {
            channel,
            user_message,
        } => {
            let caller_slot = crate::scheduler::current_slot();
            let caller_pid =
                crate::process::pid_at_slot(caller_slot).ok_or(SysError::PermissionDenied)?;
            let message = unsafe { copy_message_from_user(user_message)? };
            crate::ipc::send(caller_pid, channel, &message).map_err(map_ipc_error)?;
            Ok(0)
        }
        Syscall::ReceiveMessage {
            channel,
            user_buffer,
        } => {
            let caller_slot = crate::scheduler::current_slot();
            let caller_pid =
                crate::process::pid_at_slot(caller_slot).ok_or(SysError::PermissionDenied)?;
            match crate::ipc::receive(caller_pid, channel) {
                Ok(message) => {
                    unsafe {
                        copy_message_to_user(user_buffer, &message)?;
                    }
                    Ok(0)
                }
                Err(crate::ipc::IpcError::Empty) => {
                    // 阻塞语义（对照 Mach mach_msg）：队列空 → 登记等待者
                    // 并挂起进程。单核 + EL1 关中断 ⇒ 登记→置 Blocked→切换
                    // 原子，无丢失唤醒窗口。被 send 唤醒后由 dispatch 调
                    // complete_receive 完成收尾（continuation）。
                    crate::ipc::register_waiter(caller_pid, channel)
                        .map_err(map_ipc_error)?;
                    crate::process::set_pending_recv(caller_slot, channel);
                    crate::scheduler::block_current()
                }
                Err(e) => Err(map_ipc_error(e)),
            }
        }
        Syscall::ConsoleRead { user_buffer, len } => {
            if len == 0 {
                return Ok(0);
            }
            let request_len = len.min(1024);
            let mut buffer = vec![0u8; request_len];
            let read = crate::drivers::pl011::read_into(&mut buffer);
            if read == 0 {
                return Err(SysError::WouldBlock);
            }
            unsafe {
                copy_slice_to_user(user_buffer, &buffer[..read])?;
            }
            Ok(read as u64)
        }
        Syscall::ConsoleWrite { user_buffer, len } => {
            if len == 0 {
                return Ok(0);
            }
            let mut remaining = len;
            let mut offset = 0usize;
            while remaining > 0 {
                let chunk = remaining.min(512);
                let mut buffer = alloc::vec![0u8; chunk];
                unsafe {
                    copy_slice_from_user(user_buffer + offset, &mut buffer)?;
                }
                serial::write_bytes(&buffer);
                remaining -= chunk;
                offset += chunk;
            }
            Ok(len as u64)
        }
        Syscall::BlockRead {
            lba,
            user_buffer,
            len,
        } => {
            if len == 0 {
                return Ok(0);
            }
            if len % 512 != 0 {
                return Err(SysError::InvalidArgument);
            }
            let mut buffer = vec![0u8; len];
            crate::drivers::virtio::blk::read_blocks(lba, &mut buffer).map_err(map_block_error)?;
            unsafe {
                copy_slice_to_user(user_buffer, &buffer)?;
            }
            Ok(len as u64)
        }
        Syscall::BlockWrite {
            lba,
            user_buffer,
            len,
        } => {
            if len == 0 {
                return Ok(0);
            }
            if len % 512 != 0 {
                return Err(SysError::InvalidArgument);
            }
            let mut buffer = vec![0u8; len];
            unsafe {
                copy_slice_from_user(user_buffer, &mut buffer)?;
            }
            crate::drivers::virtio::blk::write_blocks(lba, &buffer).map_err(map_block_error)?;
            Ok(len as u64)
        }
        Syscall::ShmCreate { size, user_result } => {
            let (handle, ptr, len) = shm::create(size).map_err(map_shm_error)?;
            unsafe {
                write_shm_create_result(user_result, handle, ptr, len)?;
            }
            Ok(0)
        }
        Syscall::ShmMap { handle } => {
            let ptr = shm::map(handle).map_err(map_shm_error)?;
            Ok(ptr as u64)
        }
        Syscall::ShmLen { handle } => {
            let len = shm::len(handle).map_err(map_shm_error)?;
            Ok(len as u64)
        }
        Syscall::ShmRetain { handle } => {
            shm::retain(handle).map_err(map_shm_error)?;
            Ok(0)
        }
        Syscall::ShmRelease { handle } => {
            shm::release(handle).map_err(map_shm_error)?;
            Ok(0)
        }
        Syscall::DriverCount => {
            let count = crate::drivers::descriptors()
                .map(|table| table.len())
                .unwrap_or(0);
            Ok(count as u64)
        }
        Syscall::DriverInfo { index, user_buffer } => {
            let descriptor = descriptor_for_index(index)?;
            unsafe {
                write_driver_info(user_buffer, descriptor)?;
            }
            Ok(0)
        }
        Syscall::ShmPhys { handle } => {
            let phys = shm::phys(handle).map_err(map_shm_error)?;
            Ok(phys as u64)
        }
        Syscall::MmioMap { index, user_buffer } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_privileged(caller_slot)?;
            let descriptor = descriptor_for_index(index)?;
            // 校验 lease 的 phys（mmio_base）落在设备区，防驱动表被污染。
            validate_mmio_region(descriptor.mmio_base, descriptor.mmio_len)?;
            acquire_mmio(caller_slot, index)?;
            unsafe {
                write_mmio_info(user_buffer, descriptor.mmio_base, descriptor.mmio_len)?;
            }
            Ok(descriptor.mmio_base)
        }
        Syscall::MmioUnmap { index } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_privileged(caller_slot)?;
            release_mmio(caller_slot, index)?;
            Ok(0)
        }
        Syscall::Fork => {
            let caller_slot = crate::scheduler::current_slot();
            let parent_frame = unsafe { &*frame };
            let (child_pid, _) =
                crate::process::fork(caller_slot, parent_frame).map_err(map_process_error)?;
            crate::scheduler::enqueue(child_pid);
            Ok(child_pid.raw())
        }
        Syscall::Exec { entry, arg } => {
            let caller_slot = crate::scheduler::current_slot();
            unsafe {
                crate::process::exec(caller_slot, entry, arg, &mut *frame)
                    .map_err(map_process_error)?;
                Ok((*frame).regs[0])
            }
        }
        Syscall::SpawnService { name_ptr, name_len } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_privileged(caller_slot)?;
            let name = copy_string_from_user(name_ptr, name_len)?;
            match crate::services::spawn_service_by_name(name.as_str()) {
                Ok(pid) => {
                    crate::scheduler::enqueue(pid);
                    Ok(pid.raw())
                }
                Err(_) => Err(SysError::NotFound),
            }
        }
        // 语义升级（zombie/waitpid 状态机，见 process.rs 头部设计注释）：
        // Exit 记录退出码并按父子关系决定 Zombie/即时回收，随后
        // reschedule 收尾——本调用 noreturn，返回值类型仅为签名兼容。
        Syscall::Exit { status } => crate::process::exit_current_with_status(status),
        Syscall::Yield => crate::scheduler::yield_current(),
        Syscall::GetPid => {
            let caller_slot = crate::scheduler::current_slot();
            let caller_pid =
                crate::process::pid_at_slot(caller_slot).ok_or(SysError::PermissionDenied)?;
            Ok(caller_pid.raw())
        }
        // 号位 22（POSIX wait4 最小集）：收尸返回 (pid<<32)|exit_code；
        // 有活子未退则挂起（pending_wait 登记 + block_current，子退出时
        // 由其 Exit 路径写父 TrapFrame 并 wake——零侵入 continuation）；
        // 无任何匹配子进程返回 NotFound（对应 ECHILD，重复 wait 幂等）。
        //
        // 第七刀 WNOHANG 扩展：x3 = flags（bit0 = WAIT_NOHANG）。flags
        // 不经 trap.rs::decode_syscall 解包（该处对号位 22 冻结为只取
        // x1=pid），在此直接从调用方 TrapFrame 读 x3 —— ABI 契约见
        // zero-abi Syscall::WaitPid 文档。置位 WNOHANG 且“有活子无尸”
        // 时不挂起、立即 Ok(0)；pending_wait 保持清零（见 process.rs
        // WaitAction::PollMiss 注释）。
        Syscall::WaitPid { pid } => {
            let flags = unsafe { (*frame).regs[3] };
            match crate::process::waitpid_step(pid, flags) {
                Ok(crate::process::WaitStep::Completed(value)) => Ok(value),
                Ok(crate::process::WaitStep::Blocked) => crate::scheduler::block_current(),
                Ok(crate::process::WaitStep::WouldBlock) => Ok(0),
                Err(e) => Err(e),
            }
        }
    }
}

fn map_ipc_error(err: crate::ipc::IpcError) -> SysError {
    match err {
        crate::ipc::IpcError::NotReady => SysError::InvalidArgument,
        crate::ipc::IpcError::ChannelBusy => SysError::ChannelUnavailable,
        crate::ipc::IpcError::Invalid => SysError::InvalidArgument,
        crate::ipc::IpcError::Empty => SysError::WouldBlock,
        crate::ipc::IpcError::AccessDenied => SysError::PermissionDenied,
    }
}

fn map_process_error(err: crate::process::ProcessError) -> SysError {
    match err {
        crate::process::ProcessError::NoSuchProcess => SysError::NotFound,
        crate::process::ProcessError::TableFull => SysError::NoMemory,
        crate::process::ProcessError::NoMemory => SysError::NoMemory,
        crate::process::ProcessError::InvalidArgument => SysError::InvalidArgument,
        crate::process::ProcessError::PermissionDenied => SysError::PermissionDenied,
        crate::process::ProcessError::ElfError(_) => SysError::InvalidArgument,
        crate::process::ProcessError::MapError(_) => SysError::InvalidArgument,
    }
}

fn map_block_error(err: crate::drivers::BlockError) -> SysError {
    match err {
        crate::drivers::BlockError::NotReady => SysError::DeviceError,
        crate::drivers::BlockError::Busy => SysError::Busy,
        crate::drivers::BlockError::DeviceError => SysError::DeviceError,
        crate::drivers::BlockError::InvalidArgument => SysError::InvalidArgument,
    }
}

fn map_shm_error(err: shm::ShmError) -> SysError {
    match err {
        shm::ShmError::Invalid => SysError::InvalidArgument,
        shm::ShmError::NotFound => SysError::NotFound,
        shm::ShmError::Capacity => SysError::NoMemory,
    }
}

fn ensure_privileged(slot: usize) -> Result<(), SysError> {
    if crate::process::is_slot_privileged(slot) {
        Ok(())
    } else {
        Err(SysError::PermissionDenied)
    }
}

fn descriptor_for_index(
    index: u32,
) -> Result<&'static zero_abi::driver::DriverDescriptor, SysError> {
    let descriptors = crate::drivers::descriptors().ok_or(SysError::NotFound)?;
    descriptors.get(index as usize).ok_or(SysError::NotFound)
}

fn acquire_mmio(slot: usize, index: u32) -> Result<(), SysError> {
    let mut leases = MMIO_LEASES.lock();
    if let Some(entry) = leases
        .iter_mut()
        .find(|entry| entry.slot == slot && entry.index == index)
    {
        entry.refs = entry.refs.checked_add(1).ok_or(SysError::NoMemory)?;
        return Ok(());
    }
    leases.push(MmioLease {
        slot,
        index,
        refs: 1,
    });
    Ok(())
}

fn release_mmio(slot: usize, index: u32) -> Result<(), SysError> {
    let mut leases = MMIO_LEASES.lock();
    if let Some(pos) = leases
        .iter()
        .position(|entry| entry.slot == slot && entry.index == index)
    {
        if leases[pos].refs > 1 {
            leases[pos].refs -= 1;
        } else {
            leases.swap_remove(pos);
        }
        Ok(())
    } else {
        Err(SysError::InvalidArgument)
    }
}

unsafe fn copy_message_from_user(addr: usize) -> Result<Message, SysError> {
    // 基本对齐检查：Message 指针需按自身对齐（规则真值源 zero_abi::validate）。
    if !zero_abi::validate::message_ptr_aligned(addr as u64) {
        return Err(SysError::InvalidArgument);
    }
    let mut msg = Message::empty();
    let bytes = core::slice::from_raw_parts_mut(
        (&mut msg as *mut Message).cast::<u8>(),
        core::mem::size_of::<Message>(),
    );
    copy_slice_from_user(addr, bytes)?;
    Ok(msg)
}

unsafe fn copy_message_to_user(addr: usize, msg: &Message) -> Result<(), SysError> {
    if !zero_abi::validate::message_ptr_aligned(addr as u64) {
        return Err(SysError::InvalidArgument);
    }
    let bytes = core::slice::from_raw_parts(
        (msg as *const Message).cast::<u8>(),
        core::mem::size_of::<Message>(),
    );
    copy_slice_to_user(addr, bytes)
}

/// 逐页步进拷贝到用户空间：每页单独校验（跨页 boundary 安全；
/// 也是将来逐页"映射存在性"检查的挂载点）。
unsafe fn copy_slice_to_user(addr: usize, data: &[u8]) -> Result<(), SysError> {
    let mut remaining = data.len();
    let mut src_off = 0usize;
    let mut cur = addr;
    while remaining > 0 {
        let page_avail = crate::mm::table_walk::PAGE_SIZE - (cur & (crate::mm::table_walk::PAGE_SIZE - 1));
        let chunk = remaining.min(page_avail);
        validate_user_ptr(cur, chunk)?;
        ptr::copy_nonoverlapping(data.as_ptr().add(src_off), cur as *mut u8, chunk);
        cur += chunk;
        src_off += chunk;
        remaining -= chunk;
    }
    Ok(())
}

/// 逐页步进拷贝自用户空间（同上，方向相反）。
unsafe fn copy_slice_from_user(addr: usize, dst: &mut [u8]) -> Result<(), SysError> {
    let mut remaining = dst.len();
    let mut dst_off = 0usize;
    let mut cur = addr;
    while remaining > 0 {
        let page_avail = crate::mm::table_walk::PAGE_SIZE - (cur & (crate::mm::table_walk::PAGE_SIZE - 1));
        let chunk = remaining.min(page_avail);
        validate_user_ptr(cur, chunk)?;
        ptr::copy_nonoverlapping(cur as *const u8, dst.as_mut_ptr().add(dst_off), chunk);
        cur += chunk;
        dst_off += chunk;
        remaining -= chunk;
    }
    Ok(())
}

fn copy_string_from_user(ptr: usize, len: usize) -> Result<String, SysError> {
    if ptr == 0 || len == 0 || len > 256 {
        return Err(SysError::InvalidArgument);
    }
    validate_user_ptr(ptr, len)?;
    let mut buffer = vec![0u8; len];
    unsafe {
        copy_slice_from_user(ptr, &mut buffer)?;
    }
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(len);
    let slice = &buffer[..end];
    let text = str::from_utf8(slice).map_err(|_| SysError::InvalidArgument)?;
    Ok(String::from(text))
}

unsafe fn write_shm_create_result(
    addr: usize,
    handle: u32,
    ptr_value: usize,
    len: usize,
) -> Result<(), SysError> {
    let rec = [handle as u64, ptr_value as u64, len as u64];
    let bytes = core::slice::from_raw_parts(rec.as_ptr().cast::<u8>(), rec.len() * 8);
    copy_slice_to_user(addr, bytes)
}

unsafe fn write_driver_info(
    addr: usize,
    descriptor: &zero_abi::driver::DriverDescriptor,
) -> Result<(), SysError> {
    #[repr(C)]
    struct DriverInfoRecord {
        kind: u32,
        mmio_base: u64,
        mmio_len: u64,
        irq: u32,
    }
    let record = DriverInfoRecord {
        kind: descriptor.kind as u32,
        mmio_base: descriptor.mmio_base,
        mmio_len: descriptor.mmio_len,
        irq: descriptor.irq,
    };
    let bytes = core::slice::from_raw_parts(
        (&record as *const DriverInfoRecord).cast::<u8>(),
        core::mem::size_of::<DriverInfoRecord>(),
    );
    copy_slice_to_user(addr, bytes)
}

unsafe fn write_mmio_info(addr: usize, base: u64, len: u64) -> Result<(), SysError> {
    let rec = [base, len];
    let bytes = core::slice::from_raw_parts(rec.as_ptr().cast::<u8>(), rec.len() * 8);
    copy_slice_to_user(addr, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ptr_rejects_null() {
        assert!(validate_user_ptr(0, 1).is_err());
    }

    #[test]
    fn validate_ptr_rejects_below_user_va_lo() {
        assert!(validate_user_ptr(USER_VA_LO - 1, 1).is_err());
        assert!(validate_user_ptr(USER_VA_LO, 0).is_ok());
    }

    #[test]
    fn validate_ptr_rejects_kernel_region() {
        assert!(validate_user_ptr(KERNEL_REGION_START, 1).is_err());
        assert!(validate_user_ptr(KERNEL_REGION_START + 0x1000, 4096).is_err());
        assert!(validate_user_ptr(KERNEL_REGION_END - 1, 1).is_err());
    }

    #[test]
    fn validate_ptr_rejects_overflow_and_top() {
        assert!(validate_user_ptr(usize::MAX, 2).is_err());
        assert!(validate_user_ptr(USER_VA_MAX - 3, 4).is_err());
        assert!(validate_user_ptr(USER_VA_MAX - 4, 4).is_ok());
    }

    #[test]
    fn validate_ptr_boundary_case() {
        // 恰好落在 1GiB 边界以下（0x3FFF_FFFF 属于用户区末尾）
        assert!(validate_user_ptr(KERNEL_REGION_START - 1, 1).is_ok());
    }

    #[test]
    fn validate_mmio_region_cases() {
        // QEMU virt：PL011 @0x0900_0000 len 0x1000 合法
        assert!(validate_mmio_region(0x0900_0000, 0x1000).is_ok());
        // 区间外拒绝
        assert!(validate_mmio_region(0x0900_0000, 0x1000_0000).is_err());
        assert!(validate_mmio_region(0x0000_0000, 0x1000).is_err());
        assert!(validate_mmio_region(0x0900_0000, 0).is_err());
        assert!(validate_mmio_region(0x07ff_ffff, 0x1000).is_err());
        // 上界含端
        assert!(validate_mmio_region(0x0ff0_0000, 0x0010_0000).is_ok());
        assert!(validate_mmio_region(0x0ff0_0000, 0x0010_0001).is_err());
    }
}
