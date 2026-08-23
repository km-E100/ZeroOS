//! # zero_abi —— Zero OS 用户态 ABI 契约 crate
//!
//! 本 crate 是**内核 ↔ 用户态**的唯一契约层：系统调用号、错误编码、
//! IPC 通道 ID、协议命令码、启动信息（BootInfo / RootFs / DriverTable）、
//! 消息布局全部在此冻结。用户态（userlib、服务器、shell、客户端库）与
//! 内核（microkernel）都不允许把约定写死在本地，必须引用此 crate。
//!
//! ## 调用约定（AArch64，`svc #0` 通用入口）
//!
//! - `x0` = 系统调用号（见 [`syscall::Syscall`] 的判别值）
//! - `x1..=x4` = 参数 0..3（64 位）
//! - 返回值写在 `x0`：**成功**为具体数值；**失败**为错误编码
//!   （[`syscall`] 模块，`u64::MAX - k` 区间）
//! - 另有两个历史快捷入口：`svc #1` = 让出 CPU（yield）、
//!   `svc #2` = 退出当前进程（exit），不需要参数寄存器的安排。
//!
//! ## 变更纪律
//!
//! 所有已发布的常量/结构体都是 ABI 冻结值：**只能加注释，不能改值**。
//! 新增能力走新号位（如 `syscall::GetPid`），并在文档中标注
//! “待内核实现”，由内核侧 Agent 在本 crate 之外实现后解除标记。

#![no_std]

pub mod bootfs;

/// 内核在引导阶段传给用户进程的启动数据集合。
///
/// 该结构由引导器经 `boot_info_struct` 强符号固定在内核镜像的
/// `.rodata.boot` 段；`kernel_main` 以 `&'static BootInfo` 形式接收，
/// 字段语义如下：
///
/// - `ipc_server_entry` / `zfs_server_entry` / `launchd_entry`：
///   内核内置（编译进内核镜像）的服务器入口函数指针。当前架构已改为
///   **从 rootfs 加载独立 ELF** 的用户态服务器（见 `services::launch_core`），
///   这三个字段保留作为 KernelFn 型服务的后备入口，不再被引导路径使用。
/// - `rootfs`：指向 [`boot::RootFsImage`] 的指针；内核在 `rootfs::init`
///   阶段把该镜像展开为可查询的文件表，并拷贝一份
///   [`bootfs::UserBootFs`] 到各用户进程的地址空间。
/// - `drivers`：指向 [`driver::DriverTable`] 的指针；系统所有外设描述符
///   由它登记，用户态通过 `DriverCount` / `DriverInfo` 系统调用查询。
/// 引导信息：bootloader 与内核之间的契约结构。
/// 字段顺序与 boot/boot.S 的 boot_info_struct 逐一对应（追加新字段必须同步 boot.S）。
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BootInfo {
    pub ipc_server_entry: extern "C" fn() -> !,
    pub zfs_server_entry: extern "C" fn() -> !,
    pub launchd_entry: extern "C" fn() -> !,
    pub rootfs: *const boot::RootFsImage,
    pub drivers: *const driver::DriverTable,
    /// 指向内核 `__zero_memory_bytes` slot 的地址（boot/boot.S 定义，
    /// bootloader 启动前把真实 RAM 字节数写入该 slot）。因此要拿到
    /// 字节数必须对字段值**解引用**，直接当作数值使用是错的。
    /// 该 slot 恒为 0 或异常值表示 bootloader 未提供，内核按保守
    /// 回退处理（见 boot.rs）。
    pub memory_bytes: u64,
}

/// 引导期只读文件镜像（内核启动时由 bootloader/根包装配）。
///
/// 注意：本模块描述的是**内核侧**的静态 rootfs（编译期内嵌），
/// 用户进程实际拿到的是 [`bootfs::UserBootFs`]（物理/虚拟地址对），
/// 二者不要混淆。
pub mod boot {
    use core::{slice, str};

    /// rootfs 中的单条文件记录。
    ///
    /// 所有字段都是引导器可用的裸指针/长度，且指向**内核地址空间**
    /// （`.rodata.boot` 段），用户态禁止直接解引用 —— 用户态请走
    /// `rootfs` 模块的内核 API 或使用内核已在进程中映射的
    /// [`crate::bootfs::UserBootFs`]。
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct RootFsEntry {
        /// 文件路径字符串起始地址（UTF-8，不以 NUL 结尾）。
        pub path_ptr: *const u8,
        /// 文件路径字节长度。
        pub path_len: usize,
        /// 文件内容起始地址。
        pub data_ptr: *const u8,
        /// 文件内容字节长度。
        pub data_len: usize,
    }

    impl RootFsEntry {
        /// 由静态字符串与静态字节切片构造条目（编译期内嵌用）。
        pub const fn new(path: &'static str, data: &'static [u8]) -> Self {
            Self {
                path_ptr: path.as_ptr(),
                path_len: path.len(),
                data_ptr: data.as_ptr(),
                data_len: data.len(),
            }
        }

        /// 读取路径（仅内核侧调用；调用方必须保证指针有效）。
        pub unsafe fn path(&self) -> &'static str {
            str::from_utf8_unchecked(slice::from_raw_parts(self.path_ptr, self.path_len))
        }

        /// 读取文件内容（仅内核侧调用；调用方必须保证指针有效）。
        pub unsafe fn data(&self) -> &'static [u8] {
            slice::from_raw_parts(self.data_ptr, self.data_len)
        }
    }

    unsafe impl Sync for RootFsEntry {}

    /// rootfs 文件表镜像：`entries` 指向 `entry_count` 个
    /// [`RootFsEntry`] 的连续数组。
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct RootFsImage {
        pub entries: *const RootFsEntry,
        pub entry_count: usize,
    }

    impl RootFsImage {
        pub const fn new(entries: *const RootFsEntry, entry_count: usize) -> Self {
            Self {
                entries,
                entry_count,
            }
        }

        /// 零安全地把表转换为切片（空表返回空切片，不会解引用空指针）。
        pub unsafe fn as_slice(&self) -> &'static [RootFsEntry] {
            if self.entries.is_null() || self.entry_count == 0 {
                &[]
            } else {
                slice::from_raw_parts(self.entries, self.entry_count)
            }
        }
    }

    unsafe impl Sync for RootFsImage {}
}

/// 外设驱动描述符表：内核把探测到的设备登记为
/// [`DriverDescriptor`] 数组，用户态通过
/// `syscall::DriverCount`(15) / `syscall::DriverInfo`(16) 查询，
/// 通过 `syscall::MmioMap`(18) 申请 MMIO 租约后才能访问寄存器。
pub mod driver {
    use core::{slice, str};

    /// 设备种类标识（`DriverInfo` 返回的 `kind` 字段即此值）。
    ///
    /// 语义约定：`DriverInfo.kind` 直接取 `DriverKind as u32`，
    /// 用户态按此值分发设备操作路径。
    #[repr(u32)]
    #[derive(Copy, Clone)]
    pub enum DriverKind {
        /// ARM PrimeCell PL011 串口（console 设备）。
        Pl011 = 1,
        /// VirtIO 块设备。
        VirtIOBlk = 2,
        /// VirtIO 网络设备。
        VirtIONet = 3,
        /// VirtIO 控制台设备。
        VirtIOConsole = 4,
        /// VirtIO 随机数设备。
        VirtIORng = 5,
        /// NVMe 块设备。
        Nvme = 6,
    }

    /// 单条驱动描述符（`DriverInfo` 系统调用回填用户缓冲区的**源格式**；
    /// 用户侧 `userlib::DriverInfo` 结构是它的投影）。
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct DriverDescriptor {
        /// 驱动名字符串指针（内核地址空间，用户态不可解引用）。
        pub name_ptr: *const u8,
        /// 驱动名长度。
        pub name_len: usize,
        /// 设备种类（[`DriverKind`]）。
        pub kind: DriverKind,
        /// MMIO 寄存器基地址（物理地址）。
        pub mmio_base: u64,
        /// MMIO 区域长度（字节）。
        pub mmio_len: u64,
        /// 中断号（GIC SPI 编号）。
        pub irq: u32,
        pub reserved: u32,
    }

    impl DriverDescriptor {
        pub const fn new(
            name: &'static str,
            kind: DriverKind,
            mmio_base: u64,
            mmio_len: u64,
            irq: u32,
        ) -> Self {
            Self {
                name_ptr: name.as_ptr(),
                name_len: name.len(),
                kind,
                mmio_base,
                mmio_len,
                irq,
                reserved: 0,
            }
        }

        /// 读取驱动名（仅内核侧调用）。
        pub unsafe fn name(&self) -> &'static str {
            str::from_utf8_unchecked(slice::from_raw_parts(self.name_ptr, self.name_len))
        }
    }

    unsafe impl Sync for DriverDescriptor {}

    /// 驱动表镜像：`entries` 指向 `count` 个 [`DriverDescriptor`]。
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct DriverTable {
        pub entries: *const DriverDescriptor,
        pub count: usize,
    }

    impl DriverTable {
        pub const fn new(entries: *const DriverDescriptor, count: usize) -> Self {
            Self { entries, count }
        }

        /// 零安全切片访问（仅内核侧）。
        pub unsafe fn as_slice(&self) -> &'static [DriverDescriptor] {
            if self.entries.is_null() || self.count == 0 {
                &[]
            } else {
                slice::from_raw_parts(self.entries, self.count)
            }
        }
    }

    unsafe impl Sync for DriverTable {}
}

/// 进程 ID 包装类型：`raw` 即内核进程表分配的唯一编号
/// （`launchd` = 2，首个 `console` shell = 3 的观测值仅作参考，
/// 实际取值以内核 `process::spawn` 为准）。
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProcessId(u64);

impl ProcessId {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

/// 用户线程入口函数类型（`Exec` 系统调用与 KernelFn 型服务入口共用）。
pub type ThreadEntry = extern "C" fn() -> !;

/// IPC 通道 ID（全局唯一，冻结值）。
///
/// 通道由内核 `services::init_channels` 在引导期统一创建：
/// - `0x20x` 段：核心服务（service-controller / ipc router）
/// - `0x22x` 段：IPC 路由总线
/// - `0x23x` 段：安全服务
/// - `0x24x` 段：launchd 命令总线
/// - `0x25x` 段：文件系统
/// - `0x26x` 段：块设备
pub mod channels {
    /// IPC router 总线：进程间消息汇聚/转发的默认通道。
    pub const IPC_ROUTER_BUS: u32 = 0x220;
    /// 安全服务（securityd）请求通道：客户端发送认证/用户管理命令。
    pub const SECURITY_USER_REQ: u32 = 0x230;
    /// 安全服务（securityd）响应通道：securityd 回写结果。
    pub const SECURITY_USER_RESP: u32 = 0x231;
    /// launchd 命令请求通道：用户态（shell/客户端）下发 launchd 命令。
    pub const LAUNCHD_CMD_REQ: u32 = 0x240;
    /// launchd 命令响应通道：launchd 回写结果（同一 `Message`）。
    pub const LAUNCHD_CMD_RESP: u32 = 0x241;
    /// service-controller 控制总线：发起服务启动/重启/查询。
    pub const SERVICE_CONTROL_BUS: u32 = 0x200;
    /// service-controller 响应通道：答复请求方。
    pub const SERVICE_CONTROL_RESP: u32 = 0x201;
    /// service-controller 事件通道：广播服务状态变化。
    pub const SERVICE_CONTROL_EVENT: u32 = 0x202;
    /// 文件系统服务器请求通道（fs 线 Agent 的契约，勿改）。
    pub const FS_REQ: u32 = 0x250;
    /// 文件系统服务器响应通道。
    pub const FS_RESP: u32 = 0x251;
    /// 块设备服务器请求通道。
    pub const BLKDRV_REQ: u32 = 0x260;
    /// 块设备服务器响应通道。
    pub const BLKDRV_RESP: u32 = 0x261;
    /// 块设备服务器事件通道（热插拔通知）。
    pub const BLKDRV_EVENT: u32 = 0x262;
}

/// 各服务器的**命令协议码**（`Message.code` 字段取值）。
///
/// 通用响应约定（所有 bus 相同）：
/// - `code == 0`：成功，`payload` 携带结果文本/数据。
/// - `code != 0`：失败，`payload` 携带错误说明（不保证非空）。
pub mod protocol {
    /// securityd（安全服务）命令码。
    pub mod security {
        /// 列出全部用户（响应 payload：`name:role\n...` 文本）。
        pub const CMD_USER_LIST: u32 = 0x10;
        /// 新建用户（payload：`name\0password\0role\0`）。
        pub const CMD_USER_ADD: u32 = 0x11;
        /// 修改密码（payload：`name\0newpassword\0`）。
        pub const CMD_USER_PASSWD: u32 = 0x12;
        /// 删除用户（payload：`name\0`）。
        pub const CMD_USER_DELETE: u32 = 0x13;
        /// 校验凭据（payload：`name\0password\0`；响应 code==0 表示通过）。
        pub const CMD_USER_VERIFY: u32 = 0x14;
    }

    /// launchd（系统初始化守护）命令码。
    ///
    /// payload 编码约定：`CMD_START_APPLICATION` 为
    /// `name\0binary\0flags(u8)`（对齐旧内核 shell 的历史格式）；
    /// 其余命令为单个 `\0` 结尾的服务名。
    pub mod launchd {
        /// 列出已登记服务（响应 payload：按行文本 `name [状态]`）。
        pub const CMD_LIST_SERVICES: u32 = 0x10;
        /// 重启指定服务（payload：`name\0`）。
        pub const CMD_RESTART_SERVICE: u32 = 0x11;
        /// 启动应用（payload：`name\0binary\0flags`，flags：bit0=keepalive，bit1=foreground）。
        pub const CMD_START_APPLICATION: u32 = 0x12;
        /// 重新加载 rootfs（本轮预留，launchd 返回“未实现”）。
        pub const CMD_RELOAD_FS: u32 = 0x13;
        /// 查询 launchd 自身状态（响应 payload：`uptime=<n> services=<n>` 文本）。
        pub const CMD_STATUS: u32 = 0x14;
    }

    /// service-controller（服务控制器）命令码与状态值。
    ///
    /// 请求 payload 布局（固定头 5 字节 + 路径文本）：
    /// `[0..4]` request_id（小端 u32），`[4]` flags（bit0=keepalive，bit1=foreground），
    /// `[5..]` 服务路径（`\0` 结尾）。
    /// 响应 payload 布局：`[0..4]` request_id，`[4..]` 结果文本（`\0` 结尾）。
    pub mod service_control {
        /// 启动服务。
        pub const CMD_START: u32 = 0x01;
        /// 重启服务。
        pub const CMD_RESTART: u32 = 0x02;
        /// 服务运行中上报状态变化。
        pub const CMD_STATUS_REPORT: u32 = 0x03;
        /// 查询服务状态。
        pub const CMD_QUERY_STATUS: u32 = 0x04;

        /// flags 位：进程退出后自动重启。
        pub const FLAG_KEEPALIVE: u8 = 0x1;
        /// flags 位：前台运行（占用 console）。
        pub const FLAG_FOREGROUND: u8 = 0x2;

        /// 状态：空闲（已登记未启动）。
        pub const STATUS_IDLE: u8 = 0;
        /// 状态：正在启动。
        pub const STATUS_STARTING: u8 = 1;
        /// 状态：运行中。
        pub const STATUS_RUNNING: u8 = 2;
        /// 状态：启动失败。
        pub const STATUS_FAILED: u8 = 3;
    }

    /// 文件系统服务器命令码（fs 线 Agent 的契约，勿改）。
    pub mod fs {
        pub const CMD_OPEN: u32 = 0x01;
        pub const CMD_READ: u32 = 0x02;
        pub const CMD_CLOSE: u32 = 0x03;
        pub const CMD_LIST: u32 = 0x04;
        pub const CMD_WRITE_FILE: u32 = 0x05;
        pub const CMD_DELETE_FILE: u32 = 0x06;
        pub const CMD_INSTALL_BUNDLE: u32 = 0x07;
        pub const CMD_SNAPSHOT: u32 = 0x08;
        pub const CMD_SNAPSHOT_SCHEDULE: u32 = 0x09;
        pub const CMD_LIST_DEVICES: u32 = 0x0A;
        pub const CMD_INSTALL_DEVICE: u32 = 0x0B;
        pub const CMD_WRITE_SHARED: u32 = 0x0C;

        pub const ERR_NOT_FOUND: u32 = 1;
        pub const ERR_INVALID: u32 = 2;
        pub const ERR_NO_DESCRIPTOR: u32 = 3;
        pub const ERR_DEVICE: u32 = 4;
    }

    /// 块设备服务器命令码（fs 线 Agent 的契约，勿改）。
    pub mod blk {
        pub const CMD_INFO: u32 = 0x01;
        pub const CMD_LIST: u32 = 0x02;
        pub const CMD_READ: u32 = 0x10;
        pub const CMD_WRITE: u32 = 0x11;
        pub const CMD_FLUSH: u32 = 0x12;
        pub const CMD_PARTITION_INFO: u32 = 0x20;
        pub const CMD_IDENTIFY: u32 = 0x21;

        pub const STATUS_OK: u32 = 0;
        pub const STATUS_INVALID: u32 = 1;
        pub const STATUS_IOERR: u32 = 2;
        pub const STATUS_UNSUPPORTED: u32 = 3;

        pub const DEVICE_TYPE_VIRTIO: u8 = 0x01;
        pub const DEVICE_TYPE_NVME: u8 = 0x02;
        pub const DEVICE_TYPE_SATA: u8 = 0x03;

        pub const EVENT_DEVICE_ADDED: u8 = 0x01;
        pub const EVENT_DEVICE_REMOVED: u8 = 0x02;
    }
}

/// IPC 消息结构（**冻结布局**）。
///
/// 内存布局（`#[repr(C)]`，大小 132 字节，无 padding）：
/// - 偏移 `0x00`：`code: u32`（协议命令码，见 [`protocol`]）
/// - 偏移 `0x04`：`payload: [u8; 128]`（命令参数/结果数据，一般约定
///   以 `\0` 结尾的 UTF-8 文本）
///
/// 内核在 `copy_message_from_user` / `copy_message_to_user` 中原样
/// 拷贝 132 字节，不解释内容 —— 语义完全由收发双方按 [`protocol`]
/// 对齐。
pub mod ipc {
    /// 通道描述符：内核 `services::init_channels` 建通道时传入。
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct ChannelDesc {
        /// 通道 ID（见 [`crate::channels`] 冻结值）。
        pub id: u32,
        /// 通道队列容量（条消息；内核上限 16，超出按 16 计）。
        pub capacity: u32,
    }

    /// 单条 IPC 消息（132 字节；见模块文档的布局说明）。
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct Message {
        pub code: u32,
        pub payload: [u8; 128],
    }

    impl Message {
        /// 全零消息（code=0，payload 清零）。
        pub const fn empty() -> Self {
            Self {
                code: 0,
                payload: [0; 128],
            }
        }

        pub const fn new(code: u32, payload: [u8; 128]) -> Self {
            Self { code, payload }
        }
    }
}

/// 系统调用契约（号位即 ABI，冻结值，与内核 `trap.rs::decode_syscall`
/// 的映射严格一致）。
///
/// 调用约定见 crate 级文档；返回值见 [`SyscallResult`]。
///
/// ## 实现状态（2026-08-22 核对）
///
/// 号位 0–21 已全部在内核 `trap.rs::decode_syscall` + `syscalls::handle`
/// 落地；GetPid 已实机验证（shell `pid` 命令返回正确 PID）。
/// 阻塞语义：号位 1 空队列时挂起进程，send 唤醒（continuation 收尾）。
/// 号位 22（WaitPid）2026-08 新增：zombie 子进程回收 + 阻塞等待，
/// decode_syscall / handle / userlib 三处同步落地（见各文件头部设计注释）。
pub mod syscall {
    use super::ThreadEntry;

    /// 系统调用枚举；判别值即 AArch64 `x0` 中的调用号。
    #[derive(Copy, Clone)]
    #[repr(u64)]
    pub enum Syscall {
        /// (0) 发消息到通道：`x1`=channel，`x2`=&Message。
        SendMessage {
            channel: u32,
            user_message: usize,
        },
        /// (1) 从通道收消息（空队列返回 WouldBlock）：`x1`=channel，`x2`=&mut Message。
        ReceiveMessage {
            channel: u32,
            user_buffer: usize,
        },
        /// (2) 派生子进程（返回子进程 PID）。
        Fork,
        /// (3) 替换当前进程映像：`x1`=entry，`x2`=arg。
        Exec {
            entry: ThreadEntry,
            arg: u64,
        },
        /// (4) 让出 CPU（等价于历史快捷入口 `svc #1`）。
        Yield,
        /// (5) 退出当前进程：`x1`=退出码（等价于历史快捷入口 `svc #2`）。
        Exit {
            status: i32,
        },
        /// (6) 读取控制台：`x1`=&buf，`x2`=len；无输入返回 WouldBlock。
        ConsoleRead {
            user_buffer: usize,
            len: usize,
        },
        /// (7) 块设备读（LBA 对齐 512B）：`x1`=lba，`x2`=&buf，`x3`=len。
        BlockRead {
            lba: u64,
            user_buffer: usize,
            len: usize,
        },
        /// (8) 块设备写：`x1`=lba，`x2`=&buf，`x3`=len。
        BlockWrite {
            lba: u64,
            user_buffer: usize,
            len: usize,
        },
        /// (9) 写入控制台：`x1`=&buf，`x2`=len。
        ConsoleWrite {
            user_buffer: usize,
            len: usize,
        },
        /// (10) 创建共享内存：`x1`=size，`x2`=&[handle, ptr, len]。
        ShmCreate {
            size: usize,
            user_result: usize,
        },
        /// (11) 映射共享内存，返回映射地址。
        ShmMap {
            handle: u32,
        },
        /// (12) 查询共享内存长度。
        ShmLen {
            handle: u32,
        },
        /// (13) 增加共享内存引用。
        ShmRetain {
            handle: u32,
        },
        /// (14) 释放共享内存引用。
        ShmRelease {
            handle: u32,
        },
        /// (15) 查询驱动数量。
        DriverCount,
        /// (16) 查询驱动信息：`x1`=index，`x2`=&DriverInfo 记录。
        DriverInfo {
            index: u32,
            user_buffer: usize,
        },
        /// (17) 查询共享内存物理页地址（返回物理地址）。
        ShmPhys {
            handle: u32,
        },
        /// (18) 申请 MMIO 租约：`x1`=index，`x2`=&[base, len]；仅特权进程。
        MmioMap {
            index: u32,
            user_buffer: usize,
        },
        /// (19) 释放 MMIO 租约：`x1`=index；仅特权进程。
        MmioUnmap {
            index: u32,
        },
        /// (20) 按名启动内核登记的服务：`x1`=name_ptr，`x2`=len；仅特权进程。
        SpawnService {
            name_ptr: usize,
            name_len: usize,
        },
        /// (21) 查询当前进程 PID（已实现并实机验证）。
        GetPid,
        /// (22) 等待子进程退出并收集退出码（POSIX wait4 最小完备集，2026-08 新增）：
        /// `x1`=目标 pid（**0 = 任意子进程**）。
        ///
        /// 返回值编码：成功为 `(child_pid << 32) | (exit_code as u32)`
        /// （exit_code 按 32 位二进制补码解释，负值可无损还原）。
        /// 错误语义：
        /// - 无任何（匹配的）子进程 → [`SysError::NotFound`]（对应 POSIX ECHILD）；
        ///   含“子早已被收集/回收后再 wait”的重复调用——幂等安全。
        /// - 有未退出的活子进程 → 内核挂起调用方，待其退出时以
        ///   continuation 方式带回结果（对照号位 1 的阻塞接收语义）。
        WaitPid {
            /// 目标子 pid；0 表示任意子进程。
            pid: u64,
        },
    }

    /// 系统调用结果：成功返回 `u64`，失败返回 [`SysError`]。
    ///
    /// 与内核的二进制契约（`encode_result` / 本模块的 [`decode`]）：
    /// 错误一律编码为 `u64::MAX - k`（k 见 [`SysError`] 判别值），
    /// 其余数值视为成功。
    pub type SyscallResult = Result<u64, SysError>;

    /// 系统调用错误码（判别值 = `u64::MAX - k` 中的 k，冻结）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u64)]
    pub enum SysError {
        /// 参数非法（指针越界、长度不符等）。
        InvalidArgument = 0,
        /// 权限不足（MMIO 租约、SpawnService 等特权操作）。
        PermissionDenied = 1,
        /// 通道不可用（队列已满等）。
        ChannelUnavailable = 2,
        /// 找不到目标（服务名、驱动索引、句柄等）。
        NotFound = 3,
        /// 内存不足。
        NoMemory = 4,
        /// 资源暂时不可用（空队列、无键盘输入）。
        WouldBlock = 5,
        /// 设备错误。
        DeviceError = 6,
        /// 资源忙。
        Busy = 7,
    }

    impl SysError {
        /// 人类可读的错误名（供服务器往响应 payload 里写）。
        pub const fn as_str(&self) -> &'static str {
            match self {
                SysError::InvalidArgument => "invalid argument",
                SysError::PermissionDenied => "permission denied",
                SysError::ChannelUnavailable => "channel unavailable",
                SysError::NotFound => "not found",
                SysError::NoMemory => "no memory",
                SysError::WouldBlock => "would block",
                SysError::DeviceError => "device error",
                SysError::Busy => "busy",
            }
        }

        /// 错误编码（`u64::MAX - k`），与内核 `encode_result` 一致。
        pub const fn code(self) -> u64 {
            u64::MAX - (self as u64)
        }
    }

    /// 把内核返回的 `x0` 解码为 [`SyscallResult`]。
    ///
    /// 规则与内核 `encode_result` 严格镜像：
    /// `u64::MAX` 及其以下 7 个值为错误，其余为成功数值。
    #[inline]
    pub const fn decode(value: u64) -> Result<u64, SysError> {
        match value {
            val if val == SysError::InvalidArgument.code() => Err(SysError::InvalidArgument),
            val if val == SysError::PermissionDenied.code() => Err(SysError::PermissionDenied),
            val if val == SysError::ChannelUnavailable.code() => Err(SysError::ChannelUnavailable),
            val if val == SysError::NotFound.code() => Err(SysError::NotFound),
            val if val == SysError::NoMemory.code() => Err(SysError::NoMemory),
            val if val == SysError::WouldBlock.code() => Err(SysError::WouldBlock),
            val if val == SysError::DeviceError.code() => Err(SysError::DeviceError),
            val if val == SysError::Busy.code() => Err(SysError::Busy),
            other => Ok(other),
        }
    }
}