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
    ///
    /// 第七刀起 fsd 由“只读 rootfs 镜像服务”升级为**块设备卷文件服务**
    /// （数据落 virtio-blk，见本模块 `fs::vtable` 子协议）。上方
    /// 0x01..0x0C 旧码保持冻结：fsd 对 0x01/0x02/0x03/0x04 做兼容映射
    /// （语义与 vtable 同名命令一致，OPEN 无 mode 字节时按
    /// `fs::vtable::OPEN_EXISTING` 处理），其余旧码回 ERR_INVALID。
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

        /// 块设备卷文件协议（fsd 第七刀新增，**冻结**）。
        ///
        /// fsd 维护一张内存版文件表（固定槽位：名字→LBA 映射），元数据
        /// 持久化于卷超级块（LBA 布局见 servers/fsd/src/lib.rs 头注），
        /// 文件数据按固定容量槽位落盘。所有请求走 FS_REQ/FS_RESP，
        /// Message.code 取下列命令码；错误复用上层 ERR_*。
        ///
        /// payload 约定（小端；\\0 表示 NUL 字节，\\n 表示换行）：
        /// - OPEN：`[path\0][mode u8]`（mode 可省略=EXISTING）；
        ///   成功响应 payload[0..4] = fd。
        /// - WRITE：`[fd u32][len u32][data..]`（len+8 ≤ 128）；
        ///   成功响应 payload[0..4] = 实写入字节数。
        /// - READ：`[fd u32][len u32]`（单条消息最多回 128 字节）；
        ///   成功响应 payload = 数据本身（有效长度由请求 len 与文件剩余量推知）。
        /// - CLOSE：`[fd u32]`。
        /// - LIST：空；响应 payload = `name\n` 串（NUL 收尾）。
        pub mod vtable {
            /// 打开（可创建）文件。
            pub const CMD_OPEN: u32 = 0x20;
            /// 按 fd 当前偏移写入并推进偏移。
            pub const CMD_WRITE: u32 = 0x21;
            /// 按 fd 当前偏移读取并推进偏移。
            pub const CMD_READ: u32 = 0x22;
            /// 关闭 fd（文件与数据保留）。
            pub const CMD_CLOSE: u32 = 0x23;
            /// 列出卷内全部文件名。
            pub const CMD_LIST: u32 = 0x24;

            /// OPEN mode：仅打开已存在文件（不存在 → ERR_NOT_FOUND）。
            pub const OPEN_EXISTING: u8 = 0;
            /// OPEN mode：不存在则创建空文件，存在则原样打开（续写）。
            pub const OPEN_CREATE: u8 = 1;
        }
    }

    /// 块设备服务器命令码（fs 线 Agent 的契约，勿改）。
    ///
    /// 第七刀起 blkdrv 的数据面改为**内核直通委托**（号位 7/8
    /// BlockRead/BlockWrite，内核 virtio-blk 驱动保持设备唯一属主），
    /// 原生 MMIO 队列路径暂缓：内核与用户双驱动会争用同一 virtqueue，
    /// 且内核 shm 缓冲位于恒等映射区、对 EL0 不可见（详见
    /// servers/blkdrv/src/lib.rs 头注）。上方 shm 句柄版 CMD_READ/
    /// CMD_WRITE 回 STATUS_UNSUPPORTED；分块直通协议见
    /// `blk::passthrough`。
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

        /// 直通分块 IO 协议（blkdrv 第七刀新增，**冻结**）。
        ///
        /// 走 BLKDRV_REQ/BLKDRV_RESP。单条消息载荷上限 128 字节，大块 IO
        /// 由调用方（fsd）按**单扇区内字节块**分片：每次请求的
        /// [offset, offset+len) 必须落在同一 512B 扇区内；blkdrv 对写做
        /// “读-改-写整扇区”，对读直接回数据分片。
        ///
        /// READ_CHUNK 请求 payload（小端）：
        /// [0]=device u8，[1..4]=0，[4..12]=lba u64，[12..16]=offset u32，
        /// [16..20]=len u32（≤124 且 offset+len ≤ 512）。
        /// 成功响应 code=STATUS_OK，payload = len 字节数据。
        ///
        /// WRITE_CHUNK 请求 payload（小端）：
        /// [0]=device u8，[1..4]=0，[4..12]=lba u64，[12..16]=offset u32，
        /// [16..20]=len u32（≤104 且 offset+len ≤ 512），[20..20+len]=data。
        /// 成功响应 code=STATUS_OK，payload[0..4] = 受理字节数。
        pub mod passthrough {
            /// 读单扇区内字节块。
            pub const CMD_READ_CHUNK: u32 = 0x30;
            /// 写单扇区内字节块（内部读-改-写）。
            pub const CMD_WRITE_CHUNK: u32 = 0x31;

            /// 后端无可用块设备（未挂盘/驱动未就绪）。
            pub const STATUS_NODEVICE: u32 = 4;
        }
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
        /// (22) 等待子进程退出并收集退出码（POSIX wait4 最小完备集，2026-08 新增；
        /// 2026-08 第七刀扩展 WNOHANG）：`x1`=目标 pid（**0 = 任意子进程**）、
        /// `x3`=flags（bit0 = [`WAIT_NOHANG`]，其余位保留必须清零）。
        ///
        /// 返回值编码：成功为 `(child_pid << 32) | (exit_code as u32)`
        /// （exit_code 按 32 位二进制补码解释，负值可无损还原）；
        /// **WNOHANG 置位且“有活子但无尸可收”时返回 0**——不挂起、立即
        /// 返回（对照 Linux `wait4(..., WNOHANG)` 对未退出子进程返回 0
        /// 的约定；pid≥2 恒非 0，与收尸成功值天然无歧义）。
        /// 错误语义：
        /// - 无任何（匹配的）子进程 → [`SysError::NotFound`]（对应 POSIX ECHILD）；
        ///   含“子早已被收集/回收后再 wait”的重复调用——幂等安全。
        ///   该错误**不受 WNOHANG 影响**（无子就是无子，两种模式一致）。
        /// - 有未退出的活子进程且未置 WNOHANG → 内核挂起调用方，待其
        ///   退出时以 continuation 方式带回结果（对照号位 1 的阻塞接收语义）。
        ///
        /// 实现注记：flags 走 x3 但不经 `trap.rs::decode_syscall` 解包
        /// （该函数对号位 22 只取 x1=pid，保持冻结），由内核
        /// `syscalls::handle` 直接从 TrapFrame 读 x3 —— ABI 契约以此处
        /// 文档为准。userlib 侧对应封装见 `userlib::wait_pid_flags`。
        WaitPid {
            /// 目标子 pid；0 表示任意子进程。
            pid: u64,
        },
    }

    /// [`Syscall::WaitPid`] 的 `x3` flags 位定义（第七刀冻结）。
    ///
    /// - bit0 = WNOHANG：无尸可收但有活子时不挂起，立即返回 0；
    /// - bit1..63：保留，调用方必须清零（内核当前忽略未知位，
    ///   未来启用新位前会先改为拒绝，避免静默语义漂移）。
    pub const WAIT_NOHANG: u64 = 1 << 0;
    /// 全部已定义的 WaitPid flags 位掩码（供校验用）。
    pub const WAIT_FLAGS_MASK: u64 = WAIT_NOHANG;

    /// 系统调用结果：成功返回 `u64`，失败返回 [`SysError`]。
    ///
    /// 与内核的二进制契约（本模块的 [`encode_result`] / [`decode`]，互逆）：
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

    /// 错误哨兵区间长度（冻结）：合法错误编码恰为 `u64::MAX - k`，
    /// `k ∈ [0, ERROR_INTERVAL_LEN)`，与 [`SysError`] 判别值个数一致。
    /// 新增错误必须同步扩区间；表驱动一致性测试
    /// （`libs/abi/tests/abi_consistency.rs`）锁定该不变量。
    pub const ERROR_INTERVAL_LEN: u64 = 8;

    /// **单一真值源**：把系统调用结果编码为内核写回 `x0` 的返回值。
    ///
    /// 编码规则（ABI 冻结，真值源即本函数与本文档）：
    /// - `Ok(v)`：原样透传 `v`；
    /// - `Err(e)`：`u64::MAX - k`（`k` = `e` 的判别值，见 [`SysError`]）。
    ///
    /// 内核 `trap.rs::encode_result` 与用户态 `userlib::decode_result`
    /// 都必须与本函数一致。本轮工程化改造时 trap.rs 由并行 Agent 维护
    /// （禁改），内核侧暂保留本地 match，一致性由
    /// `libs/abi/tests/abi_consistency.rs` 的语义快照测试锁定；
    /// 内核接入本函数后即可删除快照（待合并点，见该测试头部说明）。
    #[inline]
    pub const fn encode_result(result: Result<u64, SysError>) -> u64 {
        match result {
            Ok(value) => value,
            Err(err) => err.code(),
        }
    }

    /// 值域谓词：`value` 是否落在错误哨兵区间（即 [`decode`] 会报错的
    /// `[u64::MAX - (ERROR_INTERVAL_LEN - 1), u64::MAX]`）。
    ///
    /// 内核处理器约定：任何以成功语义返回的值都**不得**落入本区间
    /// （否则会被用户态误判为错误）；`tools/fuzz-syscall` 对该不变量
    /// 做确定性随机扫描。
    #[inline]
    pub const fn is_error_encoded(value: u64) -> bool {
        value >= u64::MAX - (ERROR_INTERVAL_LEN - 1)
    }
}

/// 系统调用参数校验的**纯函数层**（宿主机可测，工程化第八刀上收）。
///
/// 内核 `microkernel/src/syscalls.rs` 的第一道防线原本以 `usize`
/// 私有函数实现、无法脱离内核 crate 测试；本模块冻结其布局常量与
/// 判定逻辑，内核侧只保留类型适配的薄委托（usize → u64，AArch64
/// 两者同宽，语义逐位一致）。模糊测试套件见 `tools/fuzz-syscall`
///（属性式边界值 + 伪随机扫描）。
///
/// ## 用户地址空间布局（与 mm/paging.rs 一致，冻结）
///
/// - `[USER_VA_LO, 1GiB)`：用户代码/数据（L1[0] 私有副本，可映射）
/// - `[1GiB, 2GiB)`：内核专用共享表（L1[1]），用户指针一律拒绝
/// - `[2GiB, USER_VA_MAX]`：bootfs 与用户栈（L1[2]/L1[3] 私有表）
pub mod validate {
    use super::syscall::SysError;

    /// 用户区下界（2 MiB；低于它的地址一律拒绝，0 指针天然被覆盖）。
    pub const USER_VA_LO: u64 = 0x0020_0000;
    /// 内核恒等映射区起点（1 GiB）：共享页表本体，绝不能被用户缓冲区命中。
    pub const KERNEL_REGION_START: u64 = 0x4000_0000;
    /// 内核恒等映射区终点（2 GiB，半开区间）。
    pub const KERNEL_REGION_END: u64 = 0x8000_0000;
    /// 用户栈顶（4 GiB − 4 KiB）：`addr + len` 不得超过。
    pub const USER_VA_MAX: u64 = 0x0000_FFFF_F000;

    /// QEMU virt 外设空间下界（GIC/PL011/virtio-mmio 所在区间）。
    pub const DEVICE_MMIO_LO: u64 = 0x0800_0000;
    /// QEMU virt 外设空间上界（半开）。
    pub const DEVICE_MMIO_HI: u64 = 0x1000_0000;

    /// IPC [`crate::ipc::Message`] 的对齐要求（132 字节 `repr(C)`，对齐 4）。
    pub const MESSAGE_ALIGN: u64 = core::mem::align_of::<crate::ipc::Message>() as u64;

    /// 用户指针校验（第一道：地址范围 + 布局；与内核原实现逐条一致）：
    ///
    /// 1. `addr == 0` 拒绝（NULL 防御）；
    /// 2. `addr < USER_VA_LO` 拒绝；
    /// 3. 落在 `[KERNEL_REGION_START, KERNEL_REGION_END)` 拒绝（内核区）；
    /// 4. `addr + len` 回绕溢出或 `> USER_VA_MAX` 拒绝（checked_add 防回绕）。
    ///
    /// 注意：只查范围、不查映射存在性——未映射页仍由硬件 data abort
    /// 兜底杀进程（内核 syscalls.rs 的 📌 协调点：待 mm 落地逐页
    /// `translate_user_addr` 后在此追加映射存在性检查）。
    #[inline]
    pub const fn validate_user_ptr(addr: u64, size: u64) -> Result<(), SysError> {
        if addr == 0 {
            return Err(SysError::InvalidArgument);
        }
        if addr < USER_VA_LO {
            return Err(SysError::InvalidArgument);
        }
        if addr >= KERNEL_REGION_START && addr < KERNEL_REGION_END {
            // 内核恒等映射区：共享页表本体，绝不能把用户缓冲区的拷贝写进去。
            return Err(SysError::InvalidArgument);
        }
        let end = match addr.checked_add(size) {
            Some(end) => end,
            None => return Err(SysError::InvalidArgument),
        };
        if end > USER_VA_MAX {
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// MMIO 租约校验：`[base, base+len)` 必须整体落在 QEMU virt 设备区
    /// 且 `len != 0`（0 长度租约无意义，按 InvalidArgument 拒绝）。
    #[inline]
    pub const fn validate_mmio_region(base: u64, len: u64) -> Result<(), SysError> {
        if len == 0 || base < DEVICE_MMIO_LO {
            return Err(SysError::InvalidArgument);
        }
        let end = match base.checked_add(len) {
            Some(end) => end,
            None => return Err(SysError::InvalidArgument),
        };
        if end > DEVICE_MMIO_HI {
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// IPC `Message` 用户指针对齐检查（内核 `copy_message_from/to_user`
    /// 的前置判定；不对齐按 InvalidArgument 拒绝）。
    #[inline]
    pub const fn message_ptr_aligned(addr: u64) -> bool {
        addr % MESSAGE_ALIGN == 0
    }
}

/// securityd 用户数据库的**磁盘持久化布局**（跨启动 ABI，第七刀冻结）。
///
/// 固定扇区布局（512B/扇区，小端编码）：
///
/// ```text
///   LBA 4096            头部扇区（见 [`userdb::encode_header`]）：
///                       [0..4)   magic b"SUD1"
///                       [4..8)   version u32（当前 1）
///                       [8..12)  记录区扇区数 u32
///                       [12..16) 预留 0
///                       [16..512) 预留 0
///   LBA 4097 .. 4096+N  用户记录文本（`name:password:role\n` 行集，
///                       尾部零填充；N = 头部记录的扇区数）
/// ```
///
/// 选址依据：LBA 4096 = 2MiB 偏移——避开 MBR/GPT 区、驱动上电自检扇区
/// （virtio-blk SELF_TEST_LBA=2048，1MiB）与历史 userdb 区（LBA 128），
/// 三者互不相交，任何一方写坏都不会殃及其他数据。
///
/// 提交顺序约定：**先写记录区、后写头部**——头部是提交标记；写入中途
/// 断电只会留下旧头部/无头部，加载方按 magic 校验失败回退默认表重播，
/// 不会读到半截新数据。
pub mod userdb {
    /// 头部扇区所在 LBA（2MiB 偏移，选址依据见模块文档）。
    pub const HDR_LBA: u64 = 4096;
    /// 扇区大小：块设备语义 + DMA 对齐下限。
    pub const SECTOR: usize = 512;
    /// 魔数 "SUD1"（Security User DB v1）。
    pub const MAGIC: [u8; 4] = *b"SUD1";
    /// 当前头部版本。
    pub const VERSION: u32 = 1;

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn get_u32(buf: &[u8], off: usize) -> u32 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&buf[off..off + 4]);
        u32::from_le_bytes(raw)
    }

    /// 把头部扇区编码进 `buf`（整扇区清零后写前 12 字节）。
    /// `record_sectors` 必须落在 1..=4095（防御性上限：2MiB 记录区足够
    /// 任何可预见规模；调用方按自身容量再收紧）。
    pub fn encode_header(buf: &mut [u8; SECTOR], record_sectors: u32) {
        assert!(
            record_sectors >= 1 && record_sectors <= 4095,
            "record_sectors out of range"
        );
        *buf = [0u8; SECTOR];
        buf[0..4].copy_from_slice(&MAGIC);
        put_u32(buf, 4, VERSION);
        put_u32(buf, 8, record_sectors);
    }

    /// 校验并解析头部扇区：magic/版本/扇区数全部合法才返回
    /// `Some(record_sectors)`；否则 None（加载方应回退内置默认表）。
    pub fn parse_header(buf: &[u8; SECTOR]) -> Option<u32> {
        if buf[0..4] != MAGIC {
            return None;
        }
        if get_u32(buf, 4) != VERSION {
            return None;
        }
        let sectors = get_u32(buf, 8);
        if sectors == 0 || sectors > 4095 {
            return None;
        }
        Some(sectors)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn header_roundtrip() {
            let mut buf = [0u8; SECTOR];
            encode_header(&mut buf, 8);
            assert_eq!(&buf[0..4], b"SUD1");
            assert_eq!(parse_header(&buf), Some(8));
            // 编码是幂等的全扇区格式：尾部保持零
            assert!(buf[16..].iter().all(|&b| b == 0));
        }

        #[test]
        fn zeroed_sector_is_rejected() {
            // 出厂盘全零：必须走“无有效头部 → 默认表”路径
            assert_eq!(parse_header(&[0u8; SECTOR]), None);
        }

        #[test]
        fn bad_magic_or_version_or_count_rejected() {
            let mut buf = [0u8; SECTOR];
            encode_header(&mut buf, 1);

            let mut bad_magic = buf;
            bad_magic[0] = b'X';
            assert_eq!(parse_header(&bad_magic), None);

            let mut bad_ver = buf;
            bad_ver[4] = 0xFF; // version 0x000000FF != 1
            assert_eq!(parse_header(&bad_ver), None);

            for count in [0u32, 4096, u32::MAX] {
                let mut bad_cnt = buf;
                bad_cnt[8..12].copy_from_slice(&count.to_le_bytes());
                assert_eq!(parse_header(&bad_cnt), None, "count={count}");
            }
        }

        #[test]
        fn little_endian_layout_is_frozen() {
            // 跨启动 ABI 冻结检查：字段偏移与字节序固定
            let mut buf = [0u8; SECTOR];
            encode_header(&mut buf, 3);
            assert_eq!(&buf[0..4], b"SUD1");
            assert_eq!(&buf[4..8], &[0x01, 0x00, 0x00, 0x00]);
            assert_eq!(&buf[8..12], &[0x03, 0x00, 0x00, 0x00]);
        }
    }
}