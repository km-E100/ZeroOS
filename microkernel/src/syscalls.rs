use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;
use zero_abi::cap::{
    CAP_AUDIO_DEV, CAP_BLOCK_DEV, CAP_CHANNEL_CREATE, CAP_DISPLAY, CAP_INPUT_DEV, CAP_ISSUER,
    CAP_MMIO, CAP_NET_DEV, CAP_POWER, CAP_SPAWN_APP, CAP_SPAWN_SVC,
};
use zero_abi::ipc::{ChannelDesc, Message};
use zero_abi::syscall::{SysError, Syscall, SyscallResult};
use zero_abi::ProcessId;

use crate::mm::address_space::{USER_HEAP_BASE, USER_HEAP_MAX_LEN};
use crate::mm::table_walk::{WalkOutcome, PAGE_SIZE};
use crate::process::TrapFrame;
use crate::runtime::serial;

#[derive(Clone, Copy, Debug)]
struct DriverResource {
    kind: zero_abi::driver::DriverKind,
    // Occupy the historical repr(C) padding after `kind` without moving any
    // existing field: low16=vendor, high16=device; zero for non-PCI resources.
    pci_id: u32,
    mmio_base: u64,
    mmio_len: u64,
    irq: u32,
    // Occupy the historical tail padding: class/subclass/prog_if/revision.
    pci_class: u32,
}

#[derive(Clone, Copy)]
struct MmioLease {
    /// Address-space identity, not a transient process-table slot. Threads in
    /// one group share the same TTBR0 and therefore the same hardware mapping.
    space_key: u64,
    index: u32,
    refs: u32,
    map_base: usize,
    user_base: usize,
    map_len: usize,
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

/// EL0 virtual window reserved for capability-gated device mappings. It sits
/// above the 64MiB brk window (ends at 0x1400_0000) and below secure SHM
/// (starts at 0x2000_0000). Fork deliberately does not inherit these leaves.
const USER_MMIO_BASE: usize = 0x1800_0000;
const USER_MMIO_END: usize = 0x2000_0000;

/// 单次块 IO 的长度上限（1 MiB = 2048 扇区）：BlockRead/BlockWrite 在
/// 内核侧以 `vec![0u8; len]` 中转，无上限时用户可用一次系统调用触发
/// 任意大的堆分配（OOM DoS）。1 MiB 覆盖现有分块协议（blkdrv 按扇区
/// 分片）与 securityd 整库读写需求。
const BLOCK_IO_MAX_LEN: usize = 1024 * 1024;

/// 用户指针两道门合一入口（所有代用户拷贝路径的唯一校验点）。
fn validate_user_ptr(addr: usize, size: usize) -> Result<(), SysError> {
    validate_user_range(addr, size)?;
    validate_user_mapping(addr, size)
}

/// 第一道门：地址范围 + 布局（纯逻辑，host 可单测，不触页表）。
fn validate_user_range(addr: usize, size: usize) -> Result<(), SysError> {
    // 工程化第八刀：判定逻辑上收 `zero_abi::validate`（纯函数、宿主可测、
    // 由 tools/fuzz-syscall 模糊覆盖）；usize→u64 在 AArch64 同宽，语义逐位一致。
    zero_abi::validate::validate_user_ptr(addr as u64, size as u64)
}

/// 第二道门（第八刀）：对 [addr, addr+len) 覆盖的每个 4KiB 页做
/// 页级映射校验——用当前进程地址空间的软件走表（mm/paging.rs 的
/// walk_space，L0→L1→L2→L3）确认该页落在**有效 L3 页描述符**上。
///
/// 为什么必须逐页走表（严苛评审 Top 缺陷）：仅查范围放过了两类
/// 危险指针——① 完全未映射的页（靠硬件 data abort 兜底杀进程，
/// "读脏地址才爆炸"）；② 从内核恒等映射继承来的 2MiB **block** 窗口
/// （私有 L2 副本原样引用，AP=EL1-only）。第②类最阴险：EL0 自行访问
/// 会被权限挡住，但内核代拷贝跑在 EL1、会绕过 AP 把设备/MMIO 窗口
/// 当普通内存读写——等于给用户一个借内核之手触碰恒等映射的旁路。
/// 因此 Unmapped 与 Block 一律拒绝，只有 Page 通过。
///
/// 性能：拷贝路径本就按 4KiB 步进（copy_slice_from/to_user 每页一次
/// 校验点），每页一次纯内存走表是 O(1)，无堆分配。
fn validate_user_mapping(addr: usize, size: usize) -> Result<(), SysError> {
    let slot = crate::scheduler::current_slot();
    // 无地址空间的进程（内核直生占位）没有任何合法用户缓冲区：
    // fail-closed，一律 InvalidArgument。
    let Some(space) = crate::process::address_space(slot) else {
        return Err(SysError::InvalidArgument);
    };
    for page in page_bases(addr, size) {
        if !page_walk_accepts(space.walk(page)) {
            return Err(SysError::InvalidArgument);
        }
    }
    Ok(())
}

/// [addr, addr+size) 覆盖的 4KiB 页基址迭代（含首尾非对齐页；
/// size=0 为空迭代）。纯算术，host 单测钉死边界。
fn page_bases(addr: usize, size: usize) -> impl Iterator<Item = usize> {
    let end = addr.saturating_add(size);
    let first = addr & !(PAGE_SIZE - 1);
    (first..end).step_by(PAGE_SIZE)
}

/// 页级判定（纯函数，host 用伪造描述符表单测）：只有有效 L3 页
/// 描述符通过；Unmapped（任一级无效）与 Block（继承的恒等映射块）
/// 都拒绝——理由见 validate_user_mapping 文档。空槽/无地址空间由
/// 上游 fail-closed，这里只看走表结果。
fn page_walk_accepts(outcome: WalkOutcome) -> bool {
    matches!(outcome, WalkOutcome::Page { .. })
}

/// Validate a physical device range. Legacy platform devices are accepted from
/// the architectural QEMU-virt window; PCI memory BARs are accepted only when
/// the enumerated BAR registry proves the entire interval belongs to a device.
fn validate_mmio_region(base: u64, len: u64) -> Result<(), SysError> {
    // 工程化第八刀：QEMU virt 设备区的纯范围判定上收 zero_abi；
    // 当前硬件封板同时允许已枚举 PCI BAR（包括高于 4GiB 的 BAR）。
    let legacy = zero_abi::validate::validate_mmio_region(base, len).is_ok();
    if legacy || crate::pci::contains_mmio_range(base, len) {
        Ok(())
    } else {
        Err(SysError::InvalidArgument)
    }
}

/// 阻塞接收的收尾（由 scheduler::dispatch 在重入用户态前调用）。
/// 虚假唤醒（唤醒者发送后消息被他人取走等）自动重新挂起。
pub fn complete_receive(slot: usize, chan: u32) {
    let pid = crate::process::pid_at_slot(slot).expect("pending recv: no pid");
    let frame = unsafe { crate::process::trap_frame(slot) };
    loop {
        match crate::ipc::receive_or_register_waiter(pid, chan) {
            Ok(Some((sender, message))) => {
                unsafe {
                    let user_buffer = (*frame).regs[2] as usize;
                    let result = copy_message_to_user(user_buffer, &message);
                    (*frame).regs[0] = crate::trap::encode_result(result.map(|_| sender.raw()));
                }
                return;
            }
            Ok(None) => {
                crate::process::set_pending_recv(slot, chan);
                crate::scheduler::block_current();
            }
            Err(err) => {
                unsafe {
                    (*frame).regs[0] = crate::trap::encode_result(Err(map_ipc_error(err)));
                }
                return;
            }
        }
    }
}

pub fn handle(syscall: Syscall, frame: *mut TrapFrame) -> SyscallResult {
    // 逻辑时钟步进（第十三刀）：security 模块的 TTL 以本计数近似单调
    // 时间（每次任意系统调用 +1，见 security.rs 模块文档第 2 点）。
    crate::security::advance_clock();
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
            match crate::ipc::receive_or_register_waiter(caller_pid, channel) {
                Ok(Some((sender, message))) => {
                    unsafe {
                        copy_message_to_user(user_buffer, &message)?;
                    }
                    Ok(sender.raw())
                }
                Ok(None) => {
                    // SMP-safe blocking receive: queue check + waiter registration
                    // happened atomically under CHANNEL_TABLE. A sender racing from
                    // here to block_current is latched by wake_pending.
                    crate::process::set_pending_recv(caller_slot, channel);
                    crate::scheduler::block_current()
                }
                Err(e) => Err(map_ipc_error(e)),
            }
        }
        Syscall::TryReceiveMessage {
            channel,
            user_buffer,
        } => {
            let caller_slot = crate::scheduler::current_slot();
            let caller_pid =
                crate::process::pid_at_slot(caller_slot).ok_or(SysError::PermissionDenied)?;
            match crate::ipc::receive(caller_pid, channel) {
                Ok((sender, message)) => {
                    unsafe {
                        copy_message_to_user(user_buffer, &message)?;
                    }
                    Ok(sender.raw())
                }
                Err(crate::ipc::IpcError::Empty) => Err(SysError::WouldBlock),
                Err(e) => Err(map_ipc_error(e)),
            }
        }
        Syscall::ConsoleRead { user_buffer, len } => {
            if len == 0 {
                return Ok(0);
            }
            let request_len = len.min(1024);
            let mut buffer = vec![0u8; request_len];
            // Preserve the historical serial console when PL011 exists, but
            // fall back to the independent HID terminal queue on ARM64 platforms
            // without an interactive UART (Parallels/real UEFI machines).
            let mut read = crate::drivers::pl011::read_into(&mut buffer);
            if read == 0 {
                read = crate::drivers::console_input::read_into(&mut buffer);
            }
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
                crate::display::write_bytes(&buffer);
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
            // 第八刀：块直通数据面收权——仅持 CAP_BLOCK_DEV 的进程
            // （blkdrv）可发起；len 上限防 vec![0u8; len] 巨分配 DoS。
            let caller_slot = crate::scheduler::current_slot();
            ensure_capability(caller_slot, CAP_BLOCK_DEV)?;
            if len == 0 {
                return Ok(0);
            }
            check_block_io_len(len)?;
            let mut buffer = vec![0u8; len];
            crate::drivers::block_read(lba, &mut buffer).map_err(map_block_error)?;
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
            // 门控同 BlockRead（CAP_BLOCK_DEV + 1 MiB 上限）。
            let caller_slot = crate::scheduler::current_slot();
            ensure_capability(caller_slot, CAP_BLOCK_DEV)?;
            if len == 0 {
                return Ok(0);
            }
            check_block_io_len(len)?;
            let mut buffer = vec![0u8; len];
            unsafe {
                copy_slice_from_user(user_buffer, &mut buffer)?;
            }
            crate::drivers::block_write(lba, &buffer).map_err(map_block_error)?;
            Ok(len as u64)
        }
        // ═══ 安全 SHM（第25刀）：opaque handle + 真用户页映射 ═══
        // 物理地址始终留在 EL1；对象页有独立 owner ref，每个用户映射再
        // retain 一份，release/unmap/进程退出均按引用计数回收。
        Syscall::ShmCreate { size, user_result } => {
            let slot = crate::scheduler::current_slot();
            let (handle, ptr, len) = crate::shm::create(slot, size).map_err(map_shm_error)?;
            let words = [handle as u64, ptr as u64, len as u64];
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    words.as_ptr().cast::<u8>(),
                    core::mem::size_of_val(&words),
                )
            };
            unsafe { copy_slice_to_user(user_result, bytes)? };
            Ok(handle as u64)
        }
        Syscall::ShmMap { handle } => {
            let slot = crate::scheduler::current_slot();
            crate::shm::map(slot, handle)
                .map(|v| v as u64)
                .map_err(map_shm_error)
        }
        Syscall::ShmLen { handle } => {
            let slot = crate::scheduler::current_slot();
            crate::shm::len(slot, handle)
                .map(|v| v as u64)
                .map_err(map_shm_error)
        }
        Syscall::ShmRetain { handle } => {
            let slot = crate::scheduler::current_slot();
            crate::shm::retain(slot, handle)
                .map(|_| 0)
                .map_err(map_shm_error)
        }
        Syscall::ShmRelease { handle } => {
            let slot = crate::scheduler::current_slot();
            crate::shm::release(slot, handle)
                .map(|_| 0)
                .map_err(map_shm_error)
        }
        Syscall::DriverCount => Ok(driver_resource_count() as u64),
        Syscall::DriverInfo { index, user_buffer } => {
            let resource = resource_for_index(index)?;
            unsafe {
                write_driver_info(user_buffer, resource)?;
            }
            Ok(0)
        }
        // 号位 17：物理地址直接出内核 = 信息泄漏，随 SHM 族一并下线。
        Syscall::ShmPhys { handle: _ } => Err(SysError::NotSupported),
        Syscall::MmioMap { index, user_buffer } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_capability(caller_slot, CAP_MMIO)?;
            let resource = resource_for_index(index)?;
            validate_mmio_region(resource.mmio_base, resource.mmio_len)?;
            let (user_base, len) = acquire_mmio(caller_slot, index, resource)?;
            unsafe {
                write_mmio_info(user_buffer, user_base as u64, len as u64)?;
            }
            Ok(user_base as u64)
        }
        Syscall::MmioUnmap { index } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_capability(caller_slot, CAP_MMIO)?;
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
        // ═══ 号位 3：execve 最小完备版（第九刀，破坏性升级）═══
        // ABI 冻结（zero-abi Syscall::Exec 同步注释）：x1=name_ptr（rootfs
        // 内路径，如 /System/Core/zero-launchd）、x2=name_len、x3=透传参数
        // （新映像以 x2 收到；对照号位 22 flags 的帧直读先例，不经
        // decode_syscall 解包——trap.rs 对本号位的冻结映射恰好兼容）。
        //
        // 【为何放弃 x2==0 旧函数指针兼容门——三理由】
        // 1) 全仓库零调用方：grep 证实 userland/kernel 无任何 legacy exec
        //    调用点（仅 decode_syscall 单测构造过假值），破坏性升级的实际
        //    破坏面为零；
        // 2) 双语义同号位存在永久编码歧义：legacy 调用方传非零 arg 时，其
        //    x1（内核文本指针）会被误读为路径指针，只能靠 validate 兜底拒
        //    绝——ABI 从此说不清 x2 到底是 arg 还是 name_len；
        // 3) 旧语义正是本轮替换对象：伪 exec 不换地址空间、不加载 ELF，
        //    进程身份与映像脱节；保留它等于永久维护两套互斥的进程模型。
        // 附带收益：decode_syscall 对号位 3 冻结的 x1!=0 强制恰好等价于
        // "路径指针非 NULL"——trap.rs 零改动即获得 NULL 拒绝。
        Syscall::Exec { entry, arg } => {
            let caller_slot = crate::scheduler::current_slot();
            // 线程组守门（第十五刀）：仅空间载体可 exec——成员线程 exec
            // 会换掉全组映像且其余线程无法跟随（POSIX：exec 杀死组内
            // 其余线程）。本里程碑先拒绝，文档已披露。
            if !crate::process::owns_address_space(caller_slot) {
                return Err(SysError::InvalidArgument);
            }
            let name_len = arg as usize;
            if name_len == 0 {
                // x2=0 不再是"函数指针模式"开关：空长度即非法路径长度。
                return Err(SysError::InvalidArgument);
            }
            // 路径两道门校验 + 代拷贝（validate_user_ptr 页级走表针对当前
            // 地址空间——此刻仍是旧映像，正确；换空间发生在 exec_load 的
            // Commit 之后）。len≤256 / UTF-8 / NUL 截断语义同 SpawnService。
            let path = copy_string_from_user(entry as usize, name_len)?;
            // 仅允许 rootfs 已登记文件：未登记路径返回 NotFound（区别于
            // 已登记但 ELF 解析失败的 InvalidArgument）。loader 内部会再次
            // 读取文件内容，此处预检只为错误码精度。
            if crate::rootfs::read_file(path.as_str()).is_none() {
                return Err(SysError::NotFound);
            }
            let passthrough = unsafe { (*frame).regs[3] };
            let entries_ptr = unsafe {
                crate::process::exec_load(caller_slot, &path, passthrough, &mut *frame)
                    .map_err(map_process_error)?
            };
            // encode_result(Ok(v))==v（恒等编码）：eret 后 x0=entries_ptr，
            // 与帧内预设的 bootfs ABI 一致。成功路径控制流已转向新映像入口，
            // 本 Ok 值仅作为新程序的第一份 x0 生效，不会回到原调用点。
            Ok(entries_ptr)
        }
        Syscall::SpawnService { name_ptr, name_len } => {
            let caller_slot = crate::scheduler::current_slot();
            // 第十三刀门控升级：静态位图 ∪ 动态授予（securityd 签发的
            // 令牌）共同参与判定——持有效 cap 才能拉起受保护服务。
            ensure_effective_capability(caller_slot, CAP_SPAWN_SVC)?;
            let name = copy_string_from_user(name_ptr, name_len)?;
            match crate::services::spawn_service_by_name(name.as_str()) {
                Ok(pid) => {
                    crate::scheduler::enqueue(pid);
                    // 会话记账（第十三刀）：registry spawn 的服务继承
                    // 发起者的登录会话（fork 路径在 process::fork 内
                    // 继承；这里是另一条 spawn 入口的对齐语义）。
                    let caller_session = crate::process::session_of_slot(caller_slot);
                    if caller_session != 0 {
                        crate::process::set_session(pid, caller_session);
                    }
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
        // 号位 23（POSIX getppid 最小集）：模式照抄 GetPid——经
        // process::get_parent_pid 只读助手取当前 slot 的 parent 字段。
        // 语义与孤儿收养策略天然一致：被 init 收养的孤儿其 parent 已
        // 重定向为 INIT_PID(2)，直接返回字段值即得收养者 pid；内核直生
        // 根进程（服务注册表 spawn 路径，parent=None）按“无父返回 0”
        // 约定回 0。外层 None（槽位无记录）与 GetPid 同一防御语义。
        Syscall::GetPpid => {
            let caller_slot = crate::scheduler::current_slot();
            match crate::process::get_parent_pid(caller_slot) {
                Some(parent) => Ok(parent.map_or(0, |pid| pid.raw())),
                None => Err(SysError::PermissionDenied),
            }
        }
        // ═══ 号位 24：用户堆 break（POSIX brk 最小集，第十刀）═══
        // ABI 冻结（zero-abi Syscall::Brk 同步注释）：x1=请求的新 break
        // 虚拟地址；x1=0 为查询。布局：堆区域 [USER_HEAP_BASE(0x1000_0000),
        // brk)，总量上限 64MiB。无需能力位图——进程只能调整自己的地址空间。
        // 引擎与规划函数见文件尾部 brk 一节（两阶段锁纪律同 fork/exec）。
        Syscall::Brk { new_break } => {
            let caller_slot = crate::scheduler::current_slot();
            sys_brk(caller_slot, new_break as u64)
        }
        // ═══ 号位 25：Sleepticks（第十一刀）═════════════════════════
        // ticks==0 同步返回 0（纯查询语义，不进睡眠队列）；否则注册
        // 睡眠项并 block（noreturn），唤醒侧回写 elapsed 到陷阱帧 x0。
        Syscall::Sleepticks { ticks } => {
            if ticks == 0 {
                Ok(0)
            } else {
                // 上限防御：单次睡眠 ≤ 2^32 tick，防 u64 溢出与
                // 「永久睡死」类滥用；超限拒绝而非截断（语义诚实）。
                if ticks > (1u64 << 32) {
                    return Err(SysError::InvalidArgument);
                }
                crate::scheduler::sleep_current(ticks)
            }
        }
        // ═══ 号位 27/28：FutexWait/Wake（第十五刀二期）════════════
        Syscall::FutexWait { uaddr, expected } => {
            match crate::process::futex_wait_check(uaddr, expected)? {
                Some(actual) => Ok(actual as u64), // 条件不匹配：不睡眠
                None => crate::process::futex_block_current(), // noreturn
            }
        }
        Syscall::FutexWake { uaddr, max } => Ok(crate::process::futex_wake(uaddr, max) as u64),
        // ═══ 号位 26：CreateThread（第十五刀线程模型）═════════════
        Syscall::CreateThread {
            entry,
            stack_top,
            tls,
            arg,
        } => {
            let caller_slot = crate::scheduler::current_slot();
            let tid = crate::process::create_thread(caller_slot, entry, stack_top, tls, arg)
                .map_err(map_process_error)?;
            // ⚠ 入队（实机踩坑）：漏掉则新线程永不上调度，父 join 死等
            // 触发软看门狗告警。
            crate::scheduler::enqueue(tid);
            Ok(tid.raw())
        }
        // ═══ 号位 40-45：capability 动态签发 / 会话（第十三刀）═════
        // ABI 冻结于 zero-abi（Syscall::CapGrant 等变体文档）；台账与
        // 活算模型见 crate::security 模块文档。
        Syscall::CapGrant { target_pid } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_effective_capability(caller_slot, CAP_ISSUER)?;
            let target = ProcessId::new(target_pid);
            let caps = unsafe { (*frame).regs[2] } as u32;
            let ttl = unsafe { (*frame).regs[3] };
            crate::security::issue_grant(target, caps, ttl).map_err(map_issue_error)
        }
        Syscall::CapRevoke { token } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_effective_capability(caller_slot, CAP_ISSUER)?;
            match crate::security::revoke_grant(token) {
                Some(()) => Ok(0),
                None => Err(SysError::NotFound),
            }
        }
        Syscall::CreateChannel { user_desc } => {
            let caller_slot = crate::scheduler::current_slot();
            if user_desc % core::mem::align_of::<ChannelDesc>() != 0 {
                return Err(SysError::InvalidArgument);
            }
            let mut desc = ChannelDesc::open(0, 0);
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    (&mut desc as *mut ChannelDesc).cast::<u8>(),
                    core::mem::size_of::<ChannelDesc>(),
                )
            };
            unsafe {
                copy_slice_from_user(user_desc, bytes)?;
            }
            // 受保护通道创建门控（第十三刀）：tx/rx 任一掩码非 0 即要求
            // CAP_CHANNEL_CREATE（含动态授予）。全通通道无门控——与
            // 引导期预建通道同一信任级别。
            if desc.tx_groups != 0 || desc.rx_groups != 0 {
                ensure_effective_capability(caller_slot, CAP_CHANNEL_CREATE)?;
            }
            match crate::ipc::create_channel(desc) {
                Ok(()) => Ok(0),
                Err(crate::ipc::IpcError::Invalid) => {
                    // id 冲突（重复创建）：如实报通道不可用，secdemo 等
                    // 调用方按"已存在"处理。
                    Err(SysError::ChannelUnavailable)
                }
                Err(crate::ipc::IpcError::ChannelBusy) => Err(SysError::NoMemory),
                Err(_) => Err(SysError::InvalidArgument),
            }
        }
        Syscall::SessionBegin { login_token } => {
            let caller_slot = crate::scheduler::current_slot();
            let caller_pid =
                crate::process::pid_at_slot(caller_slot).ok_or(SysError::PermissionDenied)?;
            // 授权内嵌于令牌：token 必须属于本进程且含 CAP_SESSION，
            // 无需额外能力位（见 security::begin_session）。
            crate::security::begin_session(caller_pid, login_token).map_err(map_session_error)
        }
        Syscall::GetSession => {
            let caller_slot = crate::scheduler::current_slot();
            Ok(crate::process::session_of_slot(caller_slot))
        }
        Syscall::SessionList { user_buffer, len } => {
            // 文本行集 `sid=N leader=P\n` 截断到 len 写入用户缓冲区；
            // 返回实际写入字节数。会话数 ≤8，行集最长 ~8×40 字节。
            let sessions = crate::security::sessions_snapshot();
            let mut text = alloc::string::String::new();
            for (sid, leader) in sessions.iter() {
                use core::fmt::Write as _;
                let _ = write!(text, "sid={} leader={}\n", sid, leader.raw());
            }
            let out_len = (text.len() as u64).min(len as u64) as usize;
            unsafe {
                copy_slice_to_user(user_buffer, &text.as_bytes()[..out_len])?;
            }
            Ok(out_len as u64)
        }
        Syscall::ShmGrant { handle, target_pid } => {
            let slot = crate::scheduler::current_slot();
            crate::shm::grant(slot, handle, zero_abi::ProcessId::new(target_pid))
                .map(|_| 0)
                .map_err(map_shm_error)
        }
        Syscall::InputRead { user_event } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_INPUT_DEV)?;
            crate::drivers::xhci::poll();
            let event = crate::drivers::virtio::input::pop().ok_or(SysError::WouldBlock)?;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&event as *const zero_abi::input::InputEvent).cast::<u8>(),
                    core::mem::size_of::<zero_abi::input::InputEvent>(),
                )
            };
            unsafe {
                copy_slice_to_user(user_event, bytes)?;
            }
            Ok(0)
        }
        Syscall::DisplayPresent {
            user_buffer,
            width,
            height,
            stride,
        } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            if width == 0 || height == 0 || stride < width || width > 4096 || height > 4096 {
                return Err(SysError::InvalidArgument);
            }
            let len = stride
                .checked_mul(height)
                .and_then(|n| n.checked_mul(4))
                .ok_or(SysError::InvalidArgument)?;
            if len > 64 * 1024 * 1024 {
                return Err(SysError::InvalidArgument);
            }
            let mut surface = vec![0u8; len];
            unsafe {
                copy_slice_from_user(user_buffer, &mut surface)?;
            }
            if crate::display::present_xrgb(&surface, width, height, stride) {
                Ok(len as u64)
            } else {
                Err(SysError::DeviceError)
            }
        }
        Syscall::ClockGet { clock_id } => {
            crate::time::get(clock_id).ok_or(SysError::InvalidArgument)
        }
        Syscall::SleepUntil { deadline_ns } => {
            let ticks = crate::time::deadline_to_scheduler_ticks(deadline_ns);
            if ticks == 0 {
                Ok(0)
            } else {
                crate::scheduler::sleep_current(ticks)
            }
        }
        Syscall::NetSend { user_buffer, len } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_NET_DEV)?;
            if len == 0 || len > 1536 {
                return Err(SysError::InvalidArgument);
            }
            let mut frame = vec![0u8; len];
            unsafe {
                copy_slice_from_user(user_buffer, &mut frame)?;
            }
            crate::drivers::virtio::net::transmit(&frame)
                .map(|_| len as u64)
                .map_err(map_net_error)
        }
        Syscall::NetRecv { user_buffer, len } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_NET_DEV)?;
            if len == 0 || len > 1536 {
                return Err(SysError::InvalidArgument);
            }
            let mut frame = vec![0u8; len];
            match crate::drivers::virtio::net::poll_receive(&mut frame).map_err(map_net_error)? {
                Some(n) => {
                    unsafe {
                        copy_slice_to_user(user_buffer, &frame[..n])?;
                    }
                    Ok(n as u64)
                }
                None => Err(SysError::WouldBlock),
            }
        }
        Syscall::NetGetMac { user_buffer } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_NET_DEV)?;
            let mac = crate::drivers::virtio::net::mac_address().ok_or(SysError::DeviceError)?;
            unsafe {
                copy_slice_to_user(user_buffer, &mac)?;
            }
            Ok(0)
        }
        Syscall::IpcSendTo {
            channel,
            target_pid,
            user_message,
        } => {
            let slot = crate::scheduler::current_slot();
            let caller = crate::process::pid_at_slot(slot).ok_or(SysError::PermissionDenied)?;
            let target = ProcessId::new(target_pid);
            if crate::process::slot_for_pid(target).is_none() {
                return Err(SysError::NotFound);
            }
            let msg = unsafe { copy_message_from_user(user_message)? };
            crate::ipc::send_to(caller, target, channel, &msg).map_err(map_ipc_error)?;
            Ok(0)
        }
        Syscall::GetRandom { user_buffer, len } => {
            if len > 64 * 1024 {
                return Err(SysError::InvalidArgument);
            }
            if len == 0 {
                return Ok(0);
            }
            let mut bytes = vec![0u8; len];
            if !crate::drivers::fill_random(&mut bytes) {
                return Err(SysError::DeviceError);
            }
            unsafe {
                copy_slice_to_user(user_buffer, &bytes)?;
            }
            Ok(len as u64)
        }
        // 号位 22（POSIX wait4 最小集）：收尸返回 (pid<<32)|exit_code；
        // 有活子未退则挂起（登记精确等待目标 wait_target + block_current，
        // 仅匹配目标的子退出才由其 Exit 路径写父 TrapFrame 并 wake——
        // 零侵入 continuation，第九刀目标集合化堵误投递）；无任何匹配
        // 子进程返回 NotFound（对应 ECHILD，重复 wait 幂等）。
        //
        // 第七刀 WNOHANG 扩展：x3 = flags（bit0 = WAIT_NOHANG）。flags
        // 不经 trap.rs::decode_syscall 解包（该处对号位 22 冻结为只取
        // x1=pid），在此直接从调用方 TrapFrame 读 x3 —— ABI 契约见
        // zero-abi Syscall::WaitPid 文档。置位 WNOHANG 且“有活子无尸”
        // 时不挂起、立即 Ok(0)；等待目标保持未登记（见 process.rs
        // WaitAction::PollMiss 注释）。
        Syscall::BlockCapacity => {
            crate::drivers::block_capacity_sectors().ok_or(SysError::NotFound)
        }
        Syscall::BlockBackend => {
            use crate::drivers::BlockBackendKind;
            match crate::drivers::block_backend_kind().ok_or(SysError::NotFound)? {
                BlockBackendKind::Virtio => Ok(zero_abi::protocol::blk::DEVICE_TYPE_VIRTIO as u64),
                BlockBackendKind::Nvme => Ok(zero_abi::protocol::blk::DEVICE_TYPE_NVME as u64),
            }
        }
        Syscall::PciCount => Ok(crate::pci::devices().len() as u64),
        Syscall::PciInfo { index, user_buffer } => {
            let devices = crate::pci::devices();
            let dev = devices.get(index as usize).ok_or(SysError::NotFound)?;
            let info = pci_function_info(dev);
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&info as *const zero_abi::driver::PciFunctionInfo).cast::<u8>(),
                    core::mem::size_of::<zero_abi::driver::PciFunctionInfo>(),
                )
            };
            unsafe {
                copy_slice_to_user(user_buffer, bytes)?;
            }
            Ok(0)
        }
        Syscall::NetDiag { user_buffer } => {
            let info =
                crate::drivers::virtio::net::diagnostic_snapshot().ok_or(SysError::NotFound)?;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&info as *const zero_abi::driver::NetDriverDiag).cast::<u8>(),
                    core::mem::size_of::<zero_abi::driver::NetDriverDiag>(),
                )
            };
            unsafe {
                copy_slice_to_user(user_buffer, bytes)?;
            }
            Ok(0)
        }
        Syscall::PowerControl { action } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_POWER)?;
            if action != zero_abi::syscall::POWER_OFF && action != zero_abi::syscall::POWER_REBOOT {
                return Err(SysError::InvalidArgument);
            }
            // Best-effort persistence barrier before firmware tears hardware down.
            let _ = crate::drivers::block_flush();
            if crate::drivers::nvme::is_ready() {
                crate::drivers::nvme::shutdown();
            }
            crate::arch::power_control(action);
            Err(SysError::NotSupported)
        }
        Syscall::SpawnImage { user_buffer, len } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_effective_capability(caller_slot, CAP_SPAWN_APP)?;
            if len < 64 || len > 16 * 1024 * 1024 {
                return Err(SysError::InvalidArgument);
            }
            let caller_pid =
                crate::process::pid_at_slot(caller_slot).ok_or(SysError::PermissionDenied)?;
            let mut image = vec![0u8; len];
            unsafe {
                copy_slice_from_user(user_buffer, &mut image)?;
            }
            let pid = crate::process::spawn_user_from_image(&image, "app", Some(caller_pid))
                .map_err(map_process_error)?;
            let sid = crate::process::session_of_slot(caller_slot);
            if sid != 0 {
                crate::process::set_session(pid, sid);
            }
            crate::scheduler::enqueue(pid);
            Ok(pid.raw())
        }
        Syscall::AudioInfo { user_info } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_AUDIO_DEV)?;
            if !crate::drivers::virtio::sound::active() {
                return Err(SysError::NotFound);
            }
            let info = zero_abi::audio::AudioInfo {
                sample_rate: crate::drivers::virtio::sound::SAMPLE_RATE as u32,
                channels: crate::drivers::virtio::sound::CHANNELS as u16,
                sample_bits: (crate::drivers::virtio::sound::SAMPLE_BYTES * 8) as u16,
                period_bytes: crate::drivers::virtio::sound::PERIOD_BYTES as u32,
                buffer_bytes: crate::drivers::virtio::sound::BUFFER_BYTES as u32,
            };
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&info as *const zero_abi::audio::AudioInfo).cast::<u8>(),
                    core::mem::size_of::<zero_abi::audio::AudioInfo>(),
                )
            };
            unsafe {
                copy_slice_to_user(user_info, bytes)?;
            }
            Ok(0)
        }
        Syscall::AudioPlay { user_buffer, len } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_AUDIO_DEV)?;
            if len == 0
                || len > crate::drivers::virtio::sound::PERIOD_BYTES
                || len % crate::drivers::virtio::sound::FRAME_BYTES != 0
            {
                return Err(SysError::InvalidArgument);
            }
            let mut pcm = vec![0u8; len];
            unsafe {
                copy_slice_from_user(user_buffer, &mut pcm)?;
            }
            if crate::drivers::virtio::sound::play_period(&pcm) {
                Ok(len as u64)
            } else {
                Err(SysError::DeviceError)
            }
        }
        Syscall::AudioStop => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_AUDIO_DEV)?;
            if crate::drivers::virtio::sound::stop() {
                Ok(0)
            } else {
                Err(SysError::DeviceError)
            }
        }
        Syscall::Gpu3dInfo { user_info } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            let info = crate::drivers::virtio::gpu::three_d_info().map_err(map_gpu3d_error)?;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&info as *const zero_abi::gpu::Gpu3dInfo).cast::<u8>(),
                    core::mem::size_of::<zero_abi::gpu::Gpu3dInfo>(),
                )
            };
            unsafe {
                copy_slice_to_user(user_info, bytes)?;
            }
            Ok(0)
        }
        Syscall::Gpu3dContextCreate { capset_id } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            crate::drivers::virtio::gpu::create_context(capset_id)
                .map(|v| v as u64)
                .map_err(map_gpu3d_error)
        }
        Syscall::Gpu3dContextDestroy { ctx_id } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            crate::drivers::virtio::gpu::destroy_context(ctx_id)
                .map(|_| 0)
                .map_err(map_gpu3d_error)
        }
        Syscall::Gpu3dResourceCreate { user_desc } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            let mut desc = zero_abi::gpu::Gpu3dResourceDesc::default();
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    (&mut desc as *mut zero_abi::gpu::Gpu3dResourceDesc).cast::<u8>(),
                    core::mem::size_of::<zero_abi::gpu::Gpu3dResourceDesc>(),
                )
            };
            unsafe {
                copy_slice_from_user(user_desc, bytes)?;
            }
            crate::drivers::virtio::gpu::create_resource(desc)
                .map(|v| v as u64)
                .map_err(map_gpu3d_error)
        }
        Syscall::Gpu3dResourceDestroy { resource_id } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            crate::drivers::virtio::gpu::destroy_resource(resource_id)
                .map(|_| 0)
                .map_err(map_gpu3d_error)
        }
        Syscall::Gpu3dContextAttach {
            ctx_id,
            resource_id,
        } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            crate::drivers::virtio::gpu::attach_resource(ctx_id, resource_id)
                .map(|_| 0)
                .map_err(map_gpu3d_error)
        }
        Syscall::Gpu3dSubmit {
            ctx_id,
            user_buffer,
            len,
        } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            if len == 0 || len > 1024 * 1024 || len & 3 != 0 {
                return Err(SysError::InvalidArgument);
            }
            let mut stream = vec![0u8; len];
            unsafe {
                copy_slice_from_user(user_buffer, &mut stream)?;
            }
            crate::drivers::virtio::gpu::submit_3d(ctx_id, &stream)
                .map(|_| len as u64)
                .map_err(map_gpu3d_error)
        }
        Syscall::Gpu3dReadback {
            resource_id,
            user_buffer,
            len,
        } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            if len == 0 || len > 64 * 1024 * 1024 {
                return Err(SysError::InvalidArgument);
            }
            let mut out = vec![0u8; len];
            let n = crate::drivers::virtio::gpu::readback_3d(resource_id, &mut out)
                .map_err(map_gpu3d_error)?;
            unsafe {
                copy_slice_to_user(user_buffer, &out[..n])?;
            }
            Ok(n as u64)
        }
        Syscall::Gpu3dGetCapset {
            capset_id,
            version,
            user_buffer,
            len,
        } => {
            let slot = crate::scheduler::current_slot();
            ensure_effective_capability(slot, CAP_DISPLAY)?;
            if len == 0 || len > 1024 * 1024 {
                return Err(SysError::InvalidArgument);
            }
            let mut out = vec![0u8; len];
            let n = crate::drivers::virtio::gpu::get_capset(capset_id, version, &mut out)
                .map_err(map_gpu3d_error)?;
            unsafe {
                copy_slice_to_user(user_buffer, &out[..n])?;
            }
            Ok(n as u64)
        }
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

// ═══════════════════════════════════════════════════════════════════════
// 号位 24：用户堆 break 引擎（POSIX brk 最小集，第十刀新增）。
//
// 两阶段锁纪律（同 fork/exec 的「分配在锁外、提交在锁内」）：
//   阶段一（表锁内）：process::heap_view 取 (地址空间副本, 当前 brk)；
//   页表操作（表锁外）：增长 map_heap_region / 收缩 unmap_heap_region
//     ——物理分配器与 TLB 操作绝不持表锁；
//   阶段二（表锁内）：process::store_brk 提交新值。
// 单核 + svc 上下文中本进程是自身 brk 的唯一写者，阶段间无并发窗口；
// 中途失败时增长路径在 map_heap_region 内部整体回滚，调用方只需不提交。
// ═══════════════════════════════════════════════════════════════════════

/// break 规划结果（纯数据，主机单测钉死查询/对齐/上限三态边界）。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BrkAction {
    /// x1==0 查询：只返回当前值，不做任何修改。
    Query,
    /// 对齐后的目标与当前一致：无页表操作，幂等成功。
    Same,
    /// 增长：映射 [from, to)（均页对齐、to 为新 break）。
    Grow { from: usize, to: usize },
    /// 收缩：解除 [to, from) 并归还物理页，to 为新 break。
    Shrink { from: usize, to: usize },
}

/// 纯规划函数：当前 brk `cur` + 用户原始请求 → 校验/对齐/上限裁决。
///
/// - requested == 0 → Query（brk(0) 返回当前 break）；
/// - 0 < requested < USER_HEAP_BASE → InvalidArgument（堆区之外）；
/// - 目标向上对齐到 4KiB；对齐算术溢出或越过 64MiB 上限 → NoMemory
///   （对应 POSIX ENOMEM；恰好在上限边界上的请求合法放行）；
/// - 其余按目标与当前的相对位置给出 Grow/Shrink/Same。
fn plan_brk(cur: usize, requested: u64) -> Result<BrkAction, SysError> {
    const HEAP_LIMIT: usize = USER_HEAP_BASE + USER_HEAP_MAX_LEN;
    if requested == 0 {
        return Ok(BrkAction::Query);
    }
    let req = requested as usize;
    if req < USER_HEAP_BASE {
        return Err(SysError::InvalidArgument);
    }
    let target = match req.checked_add(PAGE_SIZE - 1) {
        Some(v) => v & !(PAGE_SIZE - 1),
        None => return Err(SysError::NoMemory),
    };
    if target > HEAP_LIMIT {
        return Err(SysError::NoMemory);
    }
    if target == cur {
        return Ok(BrkAction::Same);
    }
    if target > cur {
        Ok(BrkAction::Grow {
            from: cur,
            to: target,
        })
    } else {
        Ok(BrkAction::Shrink {
            from: cur,
            to: target,
        })
    }
}

/// Brk 引擎主体：规划 → 锁外页操作 → 提交。返回生效后的新 break
/// （页对齐规范值；对照 Linux 返回原始请求值的差异见 ABI 披露）。
fn sys_brk(slot: usize, requested: u64) -> SyscallResult {
    // 无地址空间（内核直生占位）/槽位无效：fail-closed，与 GetPid
    // 的 PermissionDenied 防御语义同一风格。
    let Some((mut space, cur)) = crate::process::heap_view(slot) else {
        return Err(SysError::PermissionDenied);
    };
    let target = match plan_brk(cur, requested)? {
        BrkAction::Query => return Ok(cur as u64),
        BrkAction::Same => cur,
        BrkAction::Grow { from, to } => {
            // OOM/已映射：map_heap_region 已回滚本次全部映射，break 不动。
            unsafe { space.map_heap_region(from, to) }.map_err(|_| SysError::NoMemory)?;
            to
        }
        BrkAction::Shrink { from, to } => {
            // 收缩不可失败（清 PTE + BBM + free；空槽幂等跳过）。
            unsafe { space.unmap_heap_region(to, from) };
            to
        }
    };
    crate::process::store_brk(slot, target);
    Ok(target as u64)
}

fn map_ipc_error(err: crate::ipc::IpcError) -> SysError {
    match err {
        crate::ipc::IpcError::NotReady => SysError::InvalidArgument,
        crate::ipc::IpcError::ChannelBusy => SysError::ChannelUnavailable,
        crate::ipc::IpcError::Invalid => SysError::InvalidArgument,
        crate::ipc::IpcError::Empty => SysError::WouldBlock,
        crate::ipc::IpcError::AccessDenied => SysError::PermissionDenied,
        // 组策略拒绝与 owner 不符对用户态同一编码（PermissionDenied）；
        // 内核侧区分两个变体只为测试与审计精度。
        crate::ipc::IpcError::PolicyDenied => SysError::PermissionDenied,
    }
}

/// 签发失败映射（号位 40）：InvalidScope=参数非法（空/含签发权）、
/// TableFull=台账满（资源耗尽语义）。
fn map_issue_error(err: crate::security::IssueError) -> SysError {
    match err {
        crate::security::IssueError::InvalidScope => SysError::InvalidArgument,
        crate::security::IssueError::NoSuchProcess => SysError::NotFound,
        crate::security::IssueError::TableFull => SysError::NoMemory,
    }
}

/// 会话失败映射（号位 43）：令牌无效/非本人 → NotFound/PermissionDenied、
/// 过期 → InvalidArgument（对照"凭据过期须重新获取"的调用方重试语义）。
fn map_session_error(err: crate::security::SessionError) -> SysError {
    match err {
        crate::security::SessionError::NoSuchToken => SysError::NotFound,
        crate::security::SessionError::NotYours => SysError::PermissionDenied,
        crate::security::SessionError::Expired => SysError::InvalidArgument,
        crate::security::SessionError::TableFull => SysError::NoMemory,
    }
}

fn map_gpu3d_error(err: crate::drivers::virtio::gpu::Gpu3dError) -> SysError {
    match err {
        crate::drivers::virtio::gpu::Gpu3dError::Unsupported => SysError::NotSupported,
        crate::drivers::virtio::gpu::Gpu3dError::Invalid => SysError::InvalidArgument,
        crate::drivers::virtio::gpu::Gpu3dError::NotFound => SysError::NotFound,
        crate::drivers::virtio::gpu::Gpu3dError::Device => SysError::DeviceError,
        crate::drivers::virtio::gpu::Gpu3dError::NoMemory => SysError::NoMemory,
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

fn map_shm_error(err: crate::shm::ShmError) -> SysError {
    match err {
        crate::shm::ShmError::Invalid => SysError::InvalidArgument,
        crate::shm::ShmError::NotFound => SysError::NotFound,
        crate::shm::ShmError::Capacity | crate::shm::ShmError::NoMemory => SysError::NoMemory,
        crate::shm::ShmError::Permission => SysError::PermissionDenied,
        crate::shm::ShmError::Map => SysError::InvalidArgument,
    }
}

fn map_net_error(err: crate::drivers::NetError) -> SysError {
    match err {
        crate::drivers::NetError::NotReady | crate::drivers::NetError::DeviceError => {
            SysError::DeviceError
        }
        crate::drivers::NetError::Busy => SysError::Busy,
        crate::drivers::NetError::BufferTooSmall => SysError::InvalidArgument,
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

/// 能力判定（纯函数，host 单测覆盖）：`caps` 持有 `required` 的**全部**
/// 位才放行；required=0 防御性拒绝（空掩码恒真会静默放行一切）。
fn ensure_caps(caps: u32, required: u32) -> Result<(), SysError> {
    if required != 0 && caps & required == required {
        Ok(())
    } else {
        Err(SysError::PermissionDenied)
    }
}

/// 按槽位取能力位图并做门控（第八刀自布尔特权位升格：原
/// ensure_privileged/is_slot_privileged 只认一个 bool，无法表达
/// "能拉起服务但不能摸块设备"这类最小授权）。
fn ensure_capability(slot: usize, required: u32) -> Result<(), SysError> {
    ensure_caps(crate::process::slot_capabilities(slot), required)
}

/// 有效能力门控（第十三刀）：静态位图 ∪ securityd 动态签发的有效授予。
/// 仅用于本轮纳管的受保护资源（SpawnService / CreateChannel 受保护
/// 创建 / IPC 组校验走 ipc 内部同源路径）；块设备与 MMIO 维持纯静态
/// 门控——动态权柄不应触及硬件数据面（最小授权边界，见 abi::cap 注释）。
fn ensure_effective_capability(slot: usize, required: u32) -> Result<(), SysError> {
    let pid = crate::process::pid_at_slot(slot).ok_or(SysError::PermissionDenied)?;
    ensure_caps(crate::security::effective_caps(pid), required)
}

/// 块 IO 长度校验（BlockRead/BlockWrite 共用）：非零 + 512 对齐 +
/// 1 MiB 上限（上限理由见 BLOCK_IO_MAX_LEN 注释）。len=0 的合法早退
/// 语义由调用方先行处理；走到本函数的 0 视为调用序错误。
fn check_block_io_len(len: usize) -> Result<(), SysError> {
    if len == 0 || len % 512 != 0 || len > BLOCK_IO_MAX_LEN {
        return Err(SysError::InvalidArgument);
    }
    Ok(())
}

fn pci_function_info(dev: &crate::pci::PciDevice) -> zero_abi::driver::PciFunctionInfo {
    use zero_abi::driver::{PciBarInfo, PciFunctionInfo, PCI_BAR_64, PCI_BAR_IO, PCI_BAR_PREFETCH};

    let mut bars = [PciBarInfo::default(); 6];
    for (i, bar) in dev.bars.iter().enumerate() {
        let mut flags = 0u32;
        if bar.is_io {
            flags |= PCI_BAR_IO;
        }
        if bar.is_64 {
            flags |= PCI_BAR_64;
        }
        if bar.prefetchable {
            flags |= PCI_BAR_PREFETCH;
        }
        bars[i] = PciBarInfo {
            address: bar.address,
            size: bar.size,
            flags,
            reserved: 0,
        };
    }
    let mut capability_bits = 0u64;
    let mut virtio_cfg_types = 0u32;
    for cap in &dev.capabilities {
        if cap.id < 64 {
            capability_bits |= 1u64 << cap.id;
        }
        if cap.id == 0x09 {
            if let Some(cfg_type) = crate::pci::read_u8(dev.address, cap.offset as usize + 3) {
                if cfg_type < 32 {
                    virtio_cfg_types |= 1u32 << cfg_type;
                }
            }
        }
    }
    let (msix_table_size, msix_table_bar, msix_pba_bar, msix_table_offset, msix_pba_offset) =
        if let Some(msix) = dev.msix {
            (
                msix.table_size,
                msix.table_bar,
                msix.pba_bar,
                msix.table_offset,
                msix.pba_offset,
            )
        } else {
            (0, 0, 0, 0, 0)
        };
    PciFunctionInfo {
        segment: dev.address.segment,
        bus: dev.address.bus,
        device: dev.address.device,
        function: dev.address.function,
        header_type: dev.header_type,
        class: dev.class,
        subclass: dev.subclass,
        prog_if: dev.prog_if,
        revision: dev.revision,
        vendor_id: dev.vendor_id,
        device_id: dev.device_id,
        subsystem_vendor: dev.subsystem_vendor,
        subsystem_id: dev.subsystem_id,
        capability_bits,
        virtio_cfg_types,
        msix_table_size,
        msix_table_bar,
        msix_pba_bar,
        msix_table_offset,
        msix_pba_offset,
        bars,
    }
}

fn driver_resource_count() -> usize {
    let boot = crate::drivers::descriptors().map_or(0, |d| d.len());
    boot.saturating_add(crate::pci::mmio_resources().len())
}

fn resource_for_index(index: u32) -> Result<DriverResource, SysError> {
    let i = index as usize;
    let boot = crate::drivers::descriptors().unwrap_or(&[]);
    if let Some(d) = boot.get(i) {
        return Ok(DriverResource {
            kind: d.kind,
            pci_id: 0,
            mmio_base: d.mmio_base,
            mmio_len: d.mmio_len,
            irq: d.irq,
            pci_class: 0,
        });
    }
    let pci = crate::pci::mmio_resources();
    let r = pci
        .get(i.saturating_sub(boot.len()))
        .ok_or(SysError::NotFound)?;
    Ok(DriverResource {
        kind: r.kind,
        pci_id: (r.vendor_id as u32) | ((r.device_id as u32) << 16),
        mmio_base: r.base,
        mmio_len: r.len,
        irq: r.irq,
        pci_class: (r.class as u32)
            | ((r.subclass as u32) << 8)
            | ((r.prog_if as u32) << 16)
            | ((r.revision as u32) << 24),
    })
}

fn aligned_mmio_geometry(resource: DriverResource) -> Result<(usize, usize, usize), SysError> {
    let phys = usize::try_from(resource.mmio_base).map_err(|_| SysError::InvalidArgument)?;
    let len = usize::try_from(resource.mmio_len).map_err(|_| SysError::InvalidArgument)?;
    if len == 0 {
        return Err(SysError::InvalidArgument);
    }
    let map_phys = phys & !(PAGE_SIZE - 1);
    let offset = phys - map_phys;
    let needed = offset.checked_add(len).ok_or(SysError::InvalidArgument)?;
    let map_len = needed
        .checked_add(PAGE_SIZE - 1)
        .ok_or(SysError::InvalidArgument)?
        & !(PAGE_SIZE - 1);
    Ok((map_phys, offset, map_len))
}

fn choose_mmio_va(leases: &[MmioLease], space_key: u64, len: usize) -> Option<usize> {
    let mut candidate = USER_MMIO_BASE;
    loop {
        let end = candidate.checked_add(len)?;
        if end > USER_MMIO_END {
            return None;
        }
        let mut collision_end = None;
        for l in leases.iter().filter(|l| l.space_key == space_key) {
            let le = l.map_base.checked_add(l.map_len)?;
            if candidate < le && end > l.map_base {
                collision_end = Some(le);
                break;
            }
        }
        match collision_end {
            Some(next) => candidate = (next + PAGE_SIZE - 1) & !(PAGE_SIZE - 1),
            None => return Some(candidate),
        }
    }
}

fn acquire_mmio(
    slot: usize,
    index: u32,
    resource: DriverResource,
) -> Result<(usize, usize), SysError> {
    let mut space = crate::process::address_space(slot).ok_or(SysError::PermissionDenied)?;
    let space_key = space.ttbr0_phys();
    let mut leases = MMIO_LEASES.lock();
    if let Some(entry) = leases
        .iter_mut()
        .find(|e| e.space_key == space_key && e.index == index)
    {
        entry.refs = entry.refs.checked_add(1).ok_or(SysError::NoMemory)?;
        return Ok((entry.user_base, resource.mmio_len as usize));
    }
    let (map_phys, offset, map_len) = aligned_mmio_geometry(resource)?;
    let map_base = choose_mmio_va(&leases, space_key, map_len).ok_or(SysError::NoMemory)?;
    let mut mapped = 0usize;
    while mapped < map_len {
        let result = unsafe { space.map_device_page(map_base + mapped, map_phys + mapped) };
        if result.is_err() {
            if mapped != 0 {
                unsafe {
                    space.unmap_device_region(map_base, map_base + mapped);
                }
            }
            return Err(SysError::NoMemory);
        }
        mapped += PAGE_SIZE;
    }
    let user_base = map_base + offset;
    leases.push(MmioLease {
        space_key,
        index,
        refs: 1,
        map_base,
        user_base,
        map_len,
    });
    crate::info!(
        "mmio: lease idx={} TTBR0={:#x} phys={:#x}+{:#x} -> user={:#x}",
        index,
        space_key,
        resource.mmio_base,
        resource.mmio_len,
        user_base
    );
    Ok((user_base, resource.mmio_len as usize))
}

fn release_mmio(slot: usize, index: u32) -> Result<(), SysError> {
    let space = crate::process::address_space(slot).ok_or(SysError::PermissionDenied)?;
    let space_key = space.ttbr0_phys();
    let removed = {
        let mut leases = MMIO_LEASES.lock();
        let pos = leases
            .iter()
            .position(|e| e.space_key == space_key && e.index == index)
            .ok_or(SysError::InvalidArgument)?;
        if leases[pos].refs > 1 {
            leases[pos].refs -= 1;
            return Ok(());
        }
        leases.swap_remove(pos)
    };
    unsafe {
        space.unmap_device_region(removed.map_base, removed.map_base + removed.map_len);
    }
    Ok(())
}

/// AddressSpace::destroy calls this before tearing down page tables. Whole-space
/// destruction already drops the device PTEs, so only the lease bookkeeping must
/// be removed here (and the software device marker prevents freeing BAR PAs).
pub(crate) fn on_address_space_destroy(space_key: u64) {
    MMIO_LEASES.lock().retain(|e| e.space_key != space_key);
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
        let page_avail =
            crate::mm::table_walk::PAGE_SIZE - (cur & (crate::mm::table_walk::PAGE_SIZE - 1));
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
        let page_avail =
            crate::mm::table_walk::PAGE_SIZE - (cur & (crate::mm::table_walk::PAGE_SIZE - 1));
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

unsafe fn write_driver_info(addr: usize, resource: DriverResource) -> Result<(), SysError> {
    #[repr(C)]
    struct DriverInfoRecord {
        kind: u32,
        pci_id: u32,
        mmio_base: u64,
        mmio_len: u64,
        irq: u32,
        pci_class: u32,
    }
    let record = DriverInfoRecord {
        kind: resource.kind as u32,
        pci_id: resource.pci_id,
        mmio_base: resource.mmio_base,
        mmio_len: resource.mmio_len,
        irq: resource.irq,
        pci_class: resource.pci_class,
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
    use crate::mm::table_walk::{
        make_leaf_descriptor, make_table_descriptor, walk, DESC_AF, DESC_VALID, USER_AP_RW,
    };

    // ── 第一道门：范围 + 布局（纯逻辑） ─────────────────────────────

    #[test]
    fn validate_range_rejects_null() {
        assert!(validate_user_range(0, 1).is_err());
    }

    #[test]
    fn validate_range_rejects_below_user_va_lo() {
        assert!(validate_user_range(USER_VA_LO - 1, 1).is_err());
        assert!(validate_user_range(USER_VA_LO, 0).is_ok());
    }

    #[test]
    fn validate_range_rejects_kernel_region() {
        assert!(validate_user_range(KERNEL_REGION_START, 1).is_err());
        assert!(validate_user_range(KERNEL_REGION_START + 0x1000, 4096).is_err());
        assert!(validate_user_range(KERNEL_REGION_END - 1, 1).is_err());
    }

    #[test]
    fn validate_range_rejects_overflow_and_top() {
        assert!(validate_user_range(usize::MAX, 2).is_err());
        assert!(validate_user_range(USER_VA_MAX - 3, 4).is_err());
        assert!(validate_user_range(USER_VA_MAX - 4, 4).is_ok());
    }

    #[test]
    fn validate_range_boundary_case() {
        // 恰好落在 1GiB 边界以下（0x3FFF_FFFF 属于用户区末尾）
        assert!(validate_user_range(KERNEL_REGION_START - 1, 1).is_ok());
    }

    // ── 第二道门：页级映射校验（伪造描述符表驱动纯逻辑） ───────────

    /// 4K 对齐的伪页表（与 table_walk 单测同一手法：地址即“物理地址”）。
    #[repr(align(4096))]
    struct FakeTables {
        l0: [u64; 512],
        l1: [u64; 512],
        l2: [u64; 512],
        l3: [u64; 512],
    }

    impl FakeTables {
        fn new() -> Self {
            Self {
                l0: [0; 512],
                l1: [0; 512],
                l2: [0; 512],
                l3: [0; 512],
            }
        }

        fn link_default(&mut self) {
            self.l0[0] = make_table_descriptor(self.l1.as_ptr() as u64);
            self.l1[0] = make_table_descriptor(self.l2.as_ptr() as u64);
            self.l2[0] = make_table_descriptor(self.l3.as_ptr() as u64);
        }

        fn root(&self) -> *mut u64 {
            self.l0.as_ptr() as *mut u64
        }
    }

    #[test]
    fn page_walk_accepts_valid_l3_page_only() {
        let mut t = FakeTables::new();
        t.link_default();
        // L3[1] 挂有效页描述符：VA 0x1000 必须通过。
        t.l3[1] = make_leaf_descriptor(0x4100_3000, USER_AP_RW, false);
        let outcome = unsafe { walk(t.root(), 0x1000) };
        assert!(matches!(outcome, WalkOutcome::Page { .. }));
        assert!(page_walk_accepts(outcome));
        // 同一张 L3 下未映射的槽位（L3[2]=0）：拒绝——未映射页不再
        // 依赖硬件 data abort 兜底，校验点直接回 InvalidArgument。
        let unmapped = unsafe { walk(t.root(), 0x2000) };
        assert_eq!(unmapped, WalkOutcome::Unmapped);
        assert!(!page_walk_accepts(unmapped));
        // 上级表断链（L1[1] 空 → VA 1GiB 处）：同样拒绝。
        assert!(!page_walk_accepts(unsafe { walk(t.root(), 0x4000_0000) }));
    }

    #[test]
    fn page_walk_rejects_block_descriptor() {
        // 安全核心：从内核恒等映射继承来的 2MiB block（AP=EL1-only）
        // 对 EL0 本不可访问，但内核代拷贝跑在 EL1 会绕过 AP——第二道
        // 门必须把 Block 判为非法，堵死“借内核之手读写恒等映射”旁路。
        let mut t = FakeTables::new();
        t.link_default();
        // L2[2] 放 block 描述符（bit1=0），覆盖 VA [4MiB, 6MiB) 窗口。
        t.l2[2] = (0x40_0000u64) | DESC_VALID | DESC_AF;
        let outcome = unsafe { walk(t.root(), 0x40_1234) };
        assert!(matches!(outcome, WalkOutcome::Block { .. }));
        assert!(!page_walk_accepts(outcome));
    }

    #[test]
    fn page_bases_iteration_math() {
        const P: usize = PAGE_SIZE;
        // size=0 → 空迭代（校验直通，与历史 len=0 早退语义一致）。
        assert_eq!(page_bases(P, 0).count(), 0);
        // 页内单字节 → 一页。
        assert_eq!(page_bases(P + 5, 1).collect::<Vec<_>>(), vec![P]);
        // 起始非对齐跨两页。
        assert_eq!(page_bases(P - 1, 2).collect::<Vec<_>>(), vec![0, P]);
        // 尾字节恰好落进下一页首字节：新页必须计入。
        assert_eq!(page_bases(P, P + 1).collect::<Vec<_>>(), vec![P, 2 * P]);
        // 整数页跨度。
        assert_eq!(
            page_bases(P, 3 * P).collect::<Vec<_>>(),
            vec![P, 2 * P, 3 * P]
        );
    }

    // ── capability bitmask 门控（纯逻辑） ──────────────────────────

    #[test]
    fn ensure_caps_bitwise_decision() {
        use zero_abi::cap::{CAP_ALL, CAP_BLOCK_DEV, CAP_MMIO, CAP_SPAWN_SVC};
        // 单位授予/缺位拒绝。
        assert_eq!(ensure_caps(CAP_MMIO, CAP_MMIO), Ok(()));
        assert_eq!(ensure_caps(0, CAP_MMIO), Err(SysError::PermissionDenied));
        // 多位要求：必须全部置位（子集不算持有）。
        let both = CAP_MMIO | CAP_BLOCK_DEV;
        assert_eq!(ensure_caps(both, both), Ok(()));
        assert_eq!(ensure_caps(CAP_MMIO, both), Err(SysError::PermissionDenied));
        // 多余能力不碍事（最小授权的反面是超集无害）。
        assert_eq!(ensure_caps(CAP_ALL, CAP_SPAWN_SVC), Ok(()));
        // required=0 防御性拒绝：空掩码不能静默放行一切。
        assert_eq!(ensure_caps(CAP_ALL, 0), Err(SysError::PermissionDenied));
        assert_eq!(ensure_caps(0, 0), Err(SysError::PermissionDenied));
    }

    // ── 块 IO 长度上限（防巨分配 DoS） ─────────────────────────────

    #[test]
    fn block_io_len_gate_boundaries() {
        const MAX: usize = BLOCK_IO_MAX_LEN;
        assert!(check_block_io_len(512).is_ok());
        assert!(check_block_io_len(1024 * 512).is_ok());
        // 恰 1 MiB（2048 扇区）合法；再多半扇区即拒。
        assert!(check_block_io_len(MAX).is_ok());
        assert!(check_block_io_len(MAX + 512).is_err());
        assert!(check_block_io_len(MAX * 16).is_err());
        assert!(check_block_io_len(usize::MAX / 2).is_err());
        // 非 512 对齐一律拒绝。
        assert!(check_block_io_len(513).is_err());
        assert!(check_block_io_len(511).is_err());
        // len=0 不进本函数（调用方早退返回 Ok(0)）；此处防御性拒绝。
        assert!(check_block_io_len(0).is_err());
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

    // ── 号位 24：brk 查询 / 对齐 / 上限（纯逻辑） ──────────────────

    const HB: usize = USER_HEAP_BASE;
    /// 堆上限边界（BASE + 64MiB）。
    const HL: u64 = (USER_HEAP_BASE + USER_HEAP_MAX_LEN) as u64;

    #[test]
    fn brk_zero_is_query_and_never_mutates() {
        assert_eq!(plan_brk(HB, 0), Ok(BrkAction::Query));
        assert_eq!(plan_brk(HB + 8192, 0), Ok(BrkAction::Query));
        // 查询与当前值无关，也不产生页操作。
    }

    #[test]
    fn brk_below_heap_base_rejected() {
        assert_eq!(
            plan_brk(HB, (HB - 1) as u64),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(plan_brk(HB, 5), Err(SysError::InvalidArgument));
        assert_eq!(plan_brk(HB, 1), Err(SysError::InvalidArgument));
        // 边界：恰好等于基址合法（Same）。
        assert_eq!(plan_brk(HB, HB as u64), Ok(BrkAction::Same));
    }

    #[test]
    fn brk_grow_aligns_up_to_page() {
        // 非对齐请求向上取整到下一页界。
        assert_eq!(
            plan_brk(HB, (HB + 1) as u64),
            Ok(BrkAction::Grow {
                from: HB,
                to: HB + PAGE_SIZE
            })
        );
        assert_eq!(
            plan_brk(HB, (HB + 8192) as u64),
            Ok(BrkAction::Grow {
                from: HB,
                to: HB + 2 * PAGE_SIZE
            })
        );
        // 对齐后恰等于当前值 → Same（幂等）。
        assert_eq!(plan_brk(HB + 8192, (HB + 8000) as u64), Ok(BrkAction::Same));
        assert_eq!(plan_brk(HB + 4096, (HB + 4096) as u64), Ok(BrkAction::Same));
    }

    #[test]
    fn brk_shrink_targets_aligned_downside() {
        assert_eq!(
            plan_brk(HB + 8192, HB as u64),
            Ok(BrkAction::Shrink {
                from: HB + 8192,
                to: HB
            })
        );
        // 非对齐收缩请求：目标对齐到页界后仍小于当前 → 收缩一页。
        assert_eq!(
            plan_brk(HB + 8192, (HB + 1000) as u64),
            Ok(BrkAction::Shrink {
                from: HB + 8192,
                to: HB + PAGE_SIZE
            })
        );
        // 对齐后等于当前 → Same（重复收缩幂等）。
        assert_eq!(
            plan_brk(HB + PAGE_SIZE, (HB + 1) as u64),
            Ok(BrkAction::Same)
        );
    }

    #[test]
    fn brk_cap_is_exactly_64mib_with_enomem_beyond() {
        // 恰好顶满上限：合法。
        assert_eq!(
            plan_brk(HB, HL),
            Ok(BrkAction::Grow {
                from: HB,
                to: HL as usize
            })
        );
        // 上限内非对齐尾请求：对齐后恰好落在上限上——放行。
        assert_eq!(
            plan_brk(HB, HL - 100),
            Ok(BrkAction::Grow {
                from: HB,
                to: HL as usize
            })
        );
        // 越过上限一字节即 ENOMEM（NoMemory）。
        assert_eq!(plan_brk(HB, HL + 1), Err(SysError::NoMemory));
        // 极端值走 checked_add 溢出防御路径，同样 ENOMEM。
        assert_eq!(plan_brk(HB, u64::MAX), Err(SysError::NoMemory));
        assert_eq!(plan_brk(HB, u64::MAX - 100), Err(SysError::NoMemory));
    }
}
