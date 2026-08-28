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

#[cfg(feature = "zpkg")]
extern crate alloc;

pub mod bootfs;

/// POSIX 信号编号最小集 + 进程 pending 位图编码（第九刀「信号位图最小版」）。
///
/// 只取当前故障投递需要的常量，值严格对齐 POSIX `<signal.h>`；位图约定
/// `bit(sig - 1)`。宿主单测把位值钉死——漂移即编译期外红。
///
/// 【宽度披露】批评报告草案写的是 u8 位图，但 SIGSEGV=11 ⇒ `bit(10)`
/// 超出 u8 的 bit0..=7 —— 故位图宽度定为 **u16**（覆盖 sig 1..=16，
/// 含本模块全部常量），`bit(sig - 1)` 编码语义不变。
pub mod signals {
    /// 非法指令。当前内核故障路径无对应信号源（AArch64 未分配编码走
    /// Uncategorized EC，尚未接投递）；预留，值对齐 POSIX。
    pub const SIGILL: u8 = 4;
    /// 断点陷阱：EL0 BRK（Rust panic / 显式陷阱）。对标 Linux 把 brk
    /// 异常 force_sig(SIGTRAP) 的默认动作。
    pub const SIGTRAP: u8 = 5;
    /// 总线错误：EL0 数据访问的地址对齐故障（DFSC=0b100001）。
    pub const SIGBUS: u8 = 7;
    /// 浮点异常。当前 CPACR_EL1.FPEN 全开、无 FP 陷阱源；预留。
    pub const SIGFPE: u8 = 8;
    /// 段违例：EL0 取指/数据 abort 的页故障（翻译/权限等）——解引用
    /// 空指针即落到本信号，默认动作 = 终止进程。
    pub const SIGSEGV: u8 = 11;

    /// pending 位图的位：`bit(sig - 1)`。sig 必须落在 1..=16（u16 容量，
    /// 见模块头宽度披露）；内核侧仅以本模块常量调用，越界属契约破坏，
    /// 调试构建直接断言暴露。
    pub const fn signal_bit(sig: u8) -> u16 {
        debug_assert!(sig >= 1 && sig <= 16, "signal number out of bitmap range");
        1u16 << (sig - 1)
    }

    /// 故障默认动作的退出码编码：POSIX waitpid 用“被信号杀死”表达死因；
    /// 我们沿用最小可观测形式 `code = -(sig)`（如 SIGSEGV → -11）。负码
    /// 经内核 pack_wait_result / 用户态 unpack_wait_result 的 32 位补码
    /// 路径无损往返（见两侧单测）。
    pub const fn fatal_exit_code(sig: u8) -> i32 {
        -(sig as i32)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn values_match_posix() {
            assert_eq!(SIGILL, 4);
            assert_eq!(SIGTRAP, 5);
            assert_eq!(SIGBUS, 7);
            assert_eq!(SIGFPE, 8);
            assert_eq!(SIGSEGV, 11);
        }

        #[test]
        fn bitmap_bit_is_sig_minus_one() {
            assert_eq!(signal_bit(SIGILL), 1 << 3);
            assert_eq!(signal_bit(SIGTRAP), 1 << 4);
            assert_eq!(signal_bit(SIGBUS), 1 << 6);
            assert_eq!(signal_bit(SIGFPE), 1 << 7);
            // u8 容不下 bit10：这正是位图取 u16 的原因（模块头披露）
            assert_eq!(signal_bit(SIGSEGV), 1 << 10);
            // 位互不重叠：多信号可共存于同一位图
            let all = signal_bit(SIGILL)
                | signal_bit(SIGTRAP)
                | signal_bit(SIGBUS)
                | signal_bit(SIGFPE)
                | signal_bit(SIGSEGV);
            assert_eq!(all.count_ones(), 5);
        }

        #[test]
        fn fatal_exit_code_is_negative_signal() {
            assert_eq!(fatal_exit_code(SIGSEGV), -11);
            assert_eq!(fatal_exit_code(SIGBUS), -7);
            // 补码往返：按内核 (pid<<32)|code 打包再解包，父进程看到的仍是 -11
            let packed = (7u64 << 32) | (fatal_exit_code(SIGSEGV) as u32 as u64);
            assert_eq!((packed >> 32, packed as u32 as i32), (7, -11));
        }
    }
}

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
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
        /// VirtIO GPU（2D/3D display）。
        VirtIOGpu = 7,
        /// VirtIO input（keyboard/mouse/tablet）。
        VirtIOInput = 8,
        /// VirtIO sound。
        VirtIOSound = 9,
        /// PCI xHCI USB host controller。
        UsbXhci = 10,
        /// Generic PCI memory BAR resource (class-specific user driver may bind).
        PciGeneric = 11,
        /// QEMU pci-testdev acceptance device (`1b36:0005`). This is deliberately
        /// distinct from PciGeneric so production hardware is never touched by
        /// destructive/read-side-effect acceptance probes.
        PciTest = 12,
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

    /// Read-only PCI BAR snapshot flags used by [`PciFunctionInfo`].
    pub const PCI_BAR_IO: u32 = 1 << 0;
    pub const PCI_BAR_64: u32 = 1 << 1;
    pub const PCI_BAR_PREFETCH: u32 = 1 << 2;

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct PciBarInfo {
        pub address: u64,
        pub size: u64,
        pub flags: u32,
        pub reserved: u32,
    }

    /// Read-only PCI function snapshot for syscall 74. This is inventory only:
    /// it never grants configuration/MMIO/I/O-space access.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct PciFunctionInfo {
        pub segment: u16,
        pub bus: u8,
        pub device: u8,
        pub function: u8,
        pub header_type: u8,
        pub class: u8,
        pub subclass: u8,
        pub prog_if: u8,
        pub revision: u8,
        pub vendor_id: u16,
        pub device_id: u16,
        pub subsystem_vendor: u16,
        pub subsystem_id: u16,
        /// Standard PCI capability IDs 0..63 represented as a bitset.
        pub capability_bits: u64,
        /// VirtIO vendor capability cfg_type values represented as bit positions.
        pub virtio_cfg_types: u32,
        /// 0 when no MSI-X capability is present. Otherwise table entries count.
        pub msix_table_size: u16,
        pub msix_table_bar: u8,
        pub msix_pba_bar: u8,
        pub msix_table_offset: u32,
        pub msix_pba_offset: u32,
        pub bars: [PciBarInfo; 6],
    }

    /// Read-only virtio-net transport/queue snapshot for syscall 75.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct NetDriverDiag {
        pub transport_version: u32,
        pub device_status: u32,
        pub rx_queue_size: u16,
        pub tx_queue_size: u16,
        pub rx_queue_pfn: u32,
        pub tx_queue_pfn: u32,
        pub tx_submits: u64,
        pub tx_completions: u64,
        pub rx_completions: u64,
        pub mac: [u8; 6],
        pub reserved: [u8; 2],
    }
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
/// - `0x27x` 段：动态创建的受保护通道（第十三刀起；经号位 42
///   `CreateChannel` 运行时创建，引导期不预建）
pub mod channels {
    /// secdemo 受保护通道（第十三刀）：tx_groups 门控演示用，
    /// 由 `secdemo` 命令经号位 42 运行时创建，重复创建返回已存在。
    pub const SECDEMO_CH: u32 = 0x270;
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
    /// inputd 发布的统一输入事件流（键盘/鼠标/触控）。
    pub const INPUT_EVENT_BUS: u32 = 0x280;
    /// WindowServer 请求/事件总线。
    pub const WINDOW_REQ: u32 = 0x290;
    pub const WINDOW_RESP: u32 = 0x291;
    pub const NET_REQ: u32 = 0x2a0;
    pub const NET_RESP: u32 = 0x2a1;
    pub const PKG_REQ: u32 = 0x2b0;
    pub const PKG_RESP: u32 = 0x2b1;
    /// audiod command/response buses (Knife 33).
    pub const AUDIO_REQ: u32 = 0x2c0;
    pub const AUDIO_RESP: u32 = 0x2c1;
}

/// 统一输入事件 ABI。布局固定 24 字节，可直接装入 Message.payload。
pub mod input {
    pub const KIND_KEY: u16 = 1;
    pub const KIND_REL: u16 = 2;
    pub const KIND_ABS: u16 = 3;
    pub const KIND_BUTTON: u16 = 4;
    pub const KIND_WHEEL: u16 = 5;
    pub const KIND_IME_COMPOSITION: u16 = 0x100;
    pub const KIND_IME_COMMIT: u16 = 0x101;

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct InputEvent {
        pub kind: u16,
        pub code: u16,
        pub value: i32,
        pub modifiers: u32,
        pub device_id: u32,
        /// 单调时间戳；Knife26 接入真实 monotonic clock 前允许为 0。
        pub timestamp: u64,
    }

    const _: () = assert!(core::mem::size_of::<InputEvent>() == 24);
}

/// Stable userspace audio format exposed by audiod/kernel. Knife33 deliberately
/// freezes one first-generation PCM contract instead of leaking VirtIO enums.
pub mod audio {
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct AudioInfo {
        pub sample_rate: u32,
        pub channels: u16,
        pub sample_bits: u16,
        pub period_bytes: u32,
        pub buffer_bytes: u32,
    }
    const _: () = assert!(core::mem::size_of::<AudioInfo>() == 16);
}

/// Stable userspace VirtIO-GPU 3D ABI (Knife34). The kernel owns VirtIO
/// queue/context/resource lifetime; userspace submits an opaque VirGL command stream.
pub mod gpu {
    pub const GPU3D_FLAG_VIRGL: u32 = 1 << 0;
    pub const GPU3D_FLAG_CONTEXT_INIT: u32 = 1 << 1;

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Gpu3dInfo {
        pub flags: u32,
        pub capset_id: u32,
        pub capset_version: u32,
        pub capset_size: u32,
    }

    /// Resource description mirrors the stable subset of virtio_gpu_resource_create_3d.
    /// `backing_bytes=0` creates a host-only resource; non-zero asks the kernel to
    /// allocate/attach guest backing so userspace can read rendered pixels back.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Gpu3dResourceDesc {
        pub target: u32,
        pub format: u32,
        pub bind: u32,
        pub width: u32,
        pub height: u32,
        pub depth: u32,
        pub array_size: u32,
        pub last_level: u32,
        pub nr_samples: u32,
        pub flags: u32,
        pub backing_bytes: u64,
    }
    const _: () = assert!(core::mem::size_of::<Gpu3dInfo>() == 16);
    const _: () = assert!(core::mem::size_of::<Gpu3dResourceDesc>() == 48);
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

        // ── 第十三刀：capability 动态签发 / 撤销协议 ────────────────
        //
        // 全部走 SECURITY_USER_REQ(0x230) → SECURITY_USER_RESP(0x231)，
        // payload 为十进制文本字段、`\0` 分隔（对齐既有 userdb 协议
        // 风格；编解码收敛在下方 encode_/parse_ 纯函数，两侧共用杜绝
        // 漂移）。通用响应约定：code==0 成功、非 0 失败。

        /// 动态签发能力令牌（payload 见 [`encode_cap_issue`]；
        /// 成功响应 payload：`token\0` 十进制）。内核 IPC 会把真实发送者
        /// PID 作为 ReceiveMessage 返回值交给 securityd：普通已认证用户只
        /// 能为自己申请 CAP_SESSION，其余签发/撤销由 admin 策略裁决；
        /// 内核号位 40 再做 CAP_ISSUER 与不可转授的第二道门。
        pub const CMD_CAP_ISSUE: u32 = 0x20;
        /// 撤销能力令牌（payload：`token\0`；成功 code==0）。
        pub const CMD_CAP_REVOKE: u32 = 0x21;
        /// 列出本 securityd 实例的令牌台账（响应 payload：多行文本）。
        pub const CMD_CAP_LIST: u32 = 0x22;
        /// 校验令牌在台账中的状态（payload：`token\0`；code==0 有效）。
        pub const CMD_CAP_VERIFY: u32 = 0x23;
        /// Verify ZeroPkg v2 Ed25519 signature. Payload:
        /// `[origin_len u8][origin][message_hash 32][signature 64]`.
        pub const CMD_PKG_VERIFY: u32 = 0x30;

        /// CMD_CAP_ISSUE 请求字段。
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub struct CapIssueRequest {
            /// 目标进程 pid（内核把授予记到该 pid 名下）。
            ///
            /// 本字段只是“目标”，不是调用者身份。调用者 PID 由内核 IPC
            /// envelope 单独提供，securityd 不信任 payload 自报来源。
            pub target_pid: u64,
            /// 请求授予的能力位图（[`crate::cap`] 位或组合）。
            pub caps: u32,
            /// 有效期（逻辑时钟 tick；每次任意系统调用 +1，见内核
            /// security 模块文档）。**0 = 不过期**（u64::MAX 封顶）。
            pub ttl: u64,
        }

        /// 编码 CMD_CAP_ISSUE 请求：`target_pid\0caps_hex\0ttl\0`。
        /// payload 必须至少 128 字节（Message.payload 大小）；编码不下
        /// 返回 false（字段异常超长，调用方报参数错误）。
        pub fn encode_cap_issue(payload: &mut [u8], req: &CapIssueRequest) -> bool {
            let mut hex = [0u8; 8];
            let hex_len = write_u32_hex(&mut hex, req.caps);
            write_fields(
                payload,
                &[
                    u64_dec(req.target_pid).as_slice(),
                    &hex[..hex_len],
                    u64_dec(req.ttl).as_slice(),
                ],
            )
        }

        /// 解析 CMD_CAP_ISSUE 请求（[`encode_cap_issue`] 的逆运算；
        /// 字段缺失/非数字返回 None）。
        pub fn parse_cap_issue(payload: &[u8]) -> Option<CapIssueRequest> {
            let mut fields = Fields3::split(payload);
            Some(CapIssueRequest {
                target_pid: fields.next_u64()?,
                caps: fields.next_hex_u32()?,
                ttl: fields.next_u64()?,
            })
        }

        /// 把令牌编号编码为响应 payload：`token\0`（十进制）。
        pub fn encode_token(payload: &mut [u8], token: u64) -> bool {
            write_fields(payload, &[u64_dec(token).as_slice()])
        }

        /// 解析令牌编号 payload（请求与响应通用）。
        pub fn parse_token(payload: &[u8]) -> Option<u64> {
            let mut fields = Fields3::split(payload);
            fields.next_u64()
        }

        // ── 文本字段编解码内部件（主机单测钉死格式） ────────────────

        /// u32 小写十六进制（无前导零，全零写 "0"）。返回写入长度。
        fn write_u32_hex(buf: &mut [u8; 8], value: u32) -> usize {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            if value == 0 {
                buf[0] = b'0';
                return 1;
            }
            let mut tmp = [0u8; 8];
            let mut len = 0;
            let mut v = value;
            while v > 0 {
                tmp[len] = HEX[(v & 0xf) as usize];
                len += 1;
                v >>= 4;
            }
            buf[..len].copy_from_slice(&tmp[..len]);
            buf[..len].reverse();
            len
        }

        /// 栈上十进制缓冲（u64 最大 20 位）。
        struct DecBuf {
            buf: [u8; 20],
            len: usize,
        }

        impl DecBuf {
            fn as_slice(&self) -> &[u8] {
                &self.buf[..self.len]
            }
        }

        fn u64_dec(value: u64) -> DecBuf {
            let mut buf = [0u8; 20];
            let mut v = value;
            let mut len = 0;
            loop {
                buf[len] = b'0' + (v % 10) as u8;
                len += 1;
                v /= 10;
                if v == 0 {
                    break;
                }
            }
            buf[..len].reverse();
            DecBuf { buf, len }
        }

        /// 以 `\0` 连接字段写入 payload（尾部补 `\0` 收尾；越界返回 false，
        /// payload 保持原样不写半截）。
        fn write_fields(payload: &mut [u8], fields: &[&[u8]]) -> bool {
            let mut total = 0usize;
            for f in fields {
                total += f.len() + 1;
            }
            if total > payload.len() {
                return false;
            }
            let mut off = 0usize;
            for f in fields {
                payload[off..off + f.len()].copy_from_slice(f);
                off += f.len();
                payload[off] = 0;
                off += 1;
            }
            true
        }

        /// `\0` 分隔字段游标解析器（最多取 [`FIELDS_MAX`] 个字段）。
        struct Fields3<'a> {
            rest: &'a [u8],
            taken: usize,
        }

        const FIELDS_MAX: usize = 8;

        impl<'a> Fields3<'a> {
            fn split(payload: &'a [u8]) -> Self {
                Self {
                    rest: payload,
                    taken: 0,
                }
            }

            fn next_raw(&mut self) -> Option<&'a [u8]> {
                if self.taken >= FIELDS_MAX || self.rest.is_empty() {
                    return None;
                }
                let end = self
                    .rest
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(self.rest.len());
                let field = &self.rest[..end];
                self.rest = if end < self.rest.len() {
                    &self.rest[end + 1..]
                } else {
                    &self.rest[end..]
                };
                self.taken += 1;
                if field.is_empty() {
                    return None;
                }
                Some(field)
            }

            fn next_u64(&mut self) -> Option<u64> {
                let text = self.next_raw()?;
                let mut value: u64 = 0;
                for &b in text {
                    if !b.is_ascii_digit() {
                        return None;
                    }
                    value = value.checked_mul(10)?.checked_add((b - b'0') as u64)?;
                }
                Some(value)
            }

            fn next_hex_u32(&mut self) -> Option<u32> {
                let text = self.next_raw()?;
                if text.is_empty() || text.len() > 8 {
                    return None;
                }
                let mut value: u32 = 0;
                for &b in text {
                    let d = match b {
                        b'0'..=b'9' => (b - b'0') as u32,
                        b'a'..=b'f' => (b - b'a') as u32 + 10,
                        _ => return None,
                    };
                    value = value.checked_mul(16)?.checked_add(d)?;
                }
                Some(value)
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            /// 测试辅助：取第一个 `\0` 前的字段文本（断言可读性用）。
            fn first_field(payload: &[u8]) -> &str {
                let end = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                core::str::from_utf8(&payload[..end]).unwrap_or("?")
            }

            #[test]
            fn cap_issue_roundtrip() {
                let mut payload = [0u8; 128];
                let req = CapIssueRequest {
                    target_pid: 42,
                    caps: 0x50,
                    ttl: 1_000_000,
                };
                assert!(encode_cap_issue(&mut payload, &req));
                // 布局钉死：pid 十进制、caps 十六进制、ttl 十进制，`\0` 分隔收尾
                assert_eq!(&payload[..14], b"42\050\01000000\0");
                assert_eq!(parse_cap_issue(&payload), Some(req));
            }

            #[test]
            fn cap_issue_zero_values_and_huge_ttl() {
                let mut payload = [0u8; 128];
                let req = CapIssueRequest {
                    target_pid: 0,
                    caps: 0,
                    ttl: 0,
                };
                assert!(encode_cap_issue(&mut payload, &req));
                assert_eq!(parse_cap_issue(&payload), Some(req));
                let big = CapIssueRequest {
                    target_pid: u64::MAX,
                    caps: u32::MAX,
                    ttl: u64::MAX,
                };
                assert!(encode_cap_issue(&mut payload, &big));
                assert_eq!(parse_cap_issue(&payload), Some(big));
            }

            #[test]
            fn cap_issue_garbage_rejected() {
                assert_eq!(
                    parse_cap_issue(b"12\x00zz\x00100\x00"),
                    None,
                    "caps 字段非十六进制必须拒绝"
                );
                assert_eq!(parse_cap_issue(b"\x00\x00"), None, "空字段拒绝");
                assert_eq!(parse_cap_issue(&[]), None);
                // 负数字符混入十进制字段同样拒绝
                assert_eq!(parse_cap_issue(b"-5\x007\x007\x00"), None);
            }

            #[test]
            fn token_roundtrip_and_layout() {
                let mut payload = [0u8; 128];
                assert!(encode_token(&mut payload, 7));
                // 布局钉死：`token\0`，尾部保持零
                assert_eq!(&payload[..2], b"7\0");
                assert_eq!(payload[3], 0);
                assert_eq!(parse_token(&payload), Some(7));
                assert_eq!(parse_token(&[0u8; 128]), None);
                assert_eq!(parse_token(b"99x\x00"), None);
            }

            #[test]
            fn encode_overflow_keeps_payload_intact() {
                // 128 字节 payload 装不下四个 41 字节字段：拒绝且不写半截
                let mut payload = [0xEEu8; 128];
                let ok = write_fields(
                    &mut payload,
                    &[&[b'9'; 40], &[b'9'; 40], &[b'9'; 40], &[b'9'; 40]],
                );
                assert!(!ok);
                assert!(payload.iter().all(|&b| b == 0xEE));
            }
        }
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
    /// WindowServer commands. Payloads are fixed little-endian scalars; large
    /// pixel surfaces are referenced by secure SHM handles, never copied through IPC.
    pub mod net {
        pub const STATUS: u32 = 1;
        pub const PING: u32 = 2;
        pub const UDP_OPEN: u32 = 0x10;
        pub const UDP_SEND: u32 = 0x11;
        pub const UDP_RECV: u32 = 0x12;
        pub const TCP_CONNECT: u32 = 0x20;
        pub const TCP_STATE: u32 = 0x21;
        pub const TCP_SEND: u32 = 0x22;
        pub const TCP_RECV: u32 = 0x23;
        /// Bulk TCP receive through a caller-owned secure SHM region.
        /// request payload: handle(u32), shm_handle(u32), max(u32).
        /// response payload: actual(u32). The bytes live in the shared region.
        pub const TCP_RECV_SHM: u32 = 0x24;
        /// Read-only TCP bring-up counters used by platform diagnostics.
        pub const TCP_DIAG: u32 = 0x25;
        pub const DNS_QUERY: u32 = 0x30;
        pub const HTTP_GET: u32 = 0x31;
        pub const OK: u32 = 0;
        pub const AGAIN: u32 = 1;
        pub const ERR: u32 = 2;
        pub const UNSUPPORTED: u32 = 3;
    }

    pub mod pkg {
        pub const INSTALL_URL: u32 = 1;
        pub const REMOVE: u32 = 2;
        pub const VERIFY: u32 = 3;
        pub const LAUNCH: u32 = 4;
        pub const LIST: u32 = 5;
        pub const OK: u32 = 0;
        pub const ERR: u32 = 1;
    }

    pub mod audio {
        pub const INFO: u32 = 1;
        /// Ask audiod to play the deterministic acceptance tone. Normal apps
        /// will later use stream/buffer commands; this code is intentionally
        /// an audiod policy operation, not a raw device syscall.
        pub const PLAY_TEST: u32 = 2;
        pub const STOP: u32 = 3;
        pub const OK: u32 = 0;
        pub const ERR: u32 = 1;
    }

    pub mod window {
        pub const CREATE: u32 = 0x01;
        pub const DESTROY: u32 = 0x02;
        pub const SET_GEOMETRY: u32 = 0x03;
        pub const RAISE: u32 = 0x04;
        pub const SUBMIT_SHM: u32 = 0x05;
        pub const OK: u32 = 0;
        pub const ERR: u32 = 1;
    }

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
            /// 列出目录内容（第十二刀起支持路径参数：空=根目录）。
            pub const CMD_LIST: u32 = 0x24;
            /// 创建目录（第十二刀）：`[path\0]`，父目录必须已存在。
            pub const CMD_MKDIR: u32 = 0x25;
            /// 删除空目录（第十二刀）：`[path\0]`，含子项 → ERR_INVALID。
            pub const CMD_RMDIR: u32 = 0x26;
            /// 删除文件（第十二刀）：`[path\0]`；目录须走 CMD_RMDIR。
            pub const CMD_UNLINK: u32 = 0x27;
            /// 原子重命名（第十八刀 ZeroPkg 安装事务地基）：
            /// `[old\0new\0]`——同卷内换路径，目标存在即拒绝。
            /// 用途：安装流先写临时名 `.tmp`，校验后原子 rename 上线，
            /// 实现「读者要么看到旧版、要么看到新版」的提交语义。
            pub const CMD_RENAME: u32 = 0x28;
            /// Sized read: request `[fd u32][max u32]`; response
            /// `[actual u32][data..]`. Added for streaming packages/ELFs without
            /// relying on zero padding to infer EOF. max <= 124.
            pub const CMD_READ_SIZED: u32 = 0x29;
            /// Bulk read through secure SHM: request
            /// `[fd u32][handle u32][max u32]`; response `[actual u32]`.
            /// The caller must explicitly grant `handle` to fsd before each
            /// request; fsd maps, copies at most `max` bytes, releases its
            /// holder, advances the fd offset, then replies.
            pub const CMD_READ_SHARED: u32 = 0x2a;

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

/// 进程能力位图（capability bitmask；第八刀自布尔特权位升格）。
///
/// 每个进程在内核 `ProcessRecord.capabilities: u32` 中持有一份位图，
/// 内核在敏感系统调用入口按位校验（缺位一律 `PermissionDenied`）：
/// - 号位 7/8 `BlockRead`/`BlockWrite` → [`CAP_BLOCK_DEV`]（另受 1 MiB
///   单次长度上限约束，见内核 syscalls.rs）；
/// - 号位 18/19 `MmioMap`/`MmioUnmap` → [`CAP_MMIO`]；
/// - 号位 20 `SpawnService` → [`CAP_SPAWN_SVC`]。
///
/// 继承规则：fork 原样复制父进程位图。引导路径沿用
/// `spawn_user_from_bootfs(.., privileged: bool)` 的遗留布尔契约：
/// true 映射为 [`CAP_ALL`]、false 为空位图；按服务的细粒度配置待
/// services 注册表升格后接入。
pub mod cap {
    /// MMIO 租约申请/释放（号位 18/19，设备寄存器窗口）。
    pub const CAP_MMIO: u32 = 1 << 0;
    /// 块设备直通 IO（号位 7/8 BlockRead/BlockWrite）。
    pub const CAP_BLOCK_DEV: u32 = 1 << 1;
    /// 按名启动内核登记的服务（号位 20 SpawnService）。
    pub const CAP_SPAWN_SVC: u32 = 1 << 2;
    /// 创建受保护通道（号位 42 CreateChannel 且 desc 带 tx/rx_groups
    /// 掩码时门控；第十三刀）。全通通道（掩码全 0）无需本位。
    pub const CAP_CHANNEL_CREATE: u32 = 1 << 3;
    /// 受保护通道收发组（第十三刀）：通道 tx_groups/rx_groups 掩码的
    /// 示范组位——持有即落入该通道的许可集合。
    pub const CAP_SECURE_IPC: u32 = 1 << 4;
    /// 能力签发权（第十三刀）：号位 40 CapGrant / 41 CapRevoke 仅限
    /// 本位持有者（当前仅 securityd 引导期静态持有）。**不可经
    /// CapGrant 转授**（签发权扩散等于策略失效），内核侧强制拒绝。
    pub const CAP_ISSUER: u32 = 1 << 5;
    /// 登录会话准入（第十三刀）：securityd 校验凭据后签发的一次性
    /// 令牌位；目标进程持含本位的有效令牌调号位 43 SessionBegin
    /// 建立会话，令牌随即消费（防重放）。
    pub const CAP_SESSION: u32 = 1 << 6;
    /// 从内核输入设备队列读取事件（仅 inputd）。
    pub const CAP_INPUT_DEV: u32 = 1 << 7;
    /// 向显示后端提交合成后的 surface（仅 WindowServer/displayd）。
    pub const CAP_DISPLAY: u32 = 1 << 8;
    /// 直接收发二层网络帧（仅 netd）。
    pub const CAP_NET_DEV: u32 = 1 << 9;
    /// 音频设备数据面（仅 audiod）。
    pub const CAP_AUDIO_DEV: u32 = 1 << 10;
    /// 从已验证的用户缓冲区启动应用镜像（号位58 SpawnImage）。
    /// 不并入 CAP_ALL；仅 launcher/admin 会话按需动态领取。
    pub const CAP_SPAWN_APP: u32 = 1 << 11;
    /// Send administrative requests to pkgd's protected command channel.
    pub const CAP_PKG_CLIENT: u32 = 1 << 12;
    /// Send commands to audiod. Raw VirtIO sound access remains CAP_AUDIO_DEV
    /// and is held only by audiod.
    pub const CAP_AUDIO_CLIENT: u32 = 1 << 13;
    /// Platform power transition (syscall 72): shutdown/reboot. Never part of
    /// legacy CAP_ALL; interactive callers obtain it dynamically after admin auth.
    pub const CAP_POWER: u32 = 1 << 14;
    /// 全部已定义能力的组合（引导期 privileged 服务的缺省位图）。
    ///
    /// 【第十三刀边界】动态管理位（CHANNEL_CREATE/SECURE_IPC/ISSUER/
    /// SESSION）**不并入 CAP_ALL**：引导期布尔映射不应静默携带签发权
    /// 或会话准入，这些能力只能显式授予或动态签发，保持最小授权。
    // Compatibility meaning of legacy `privileged=true`: only the original
    // kernel resource trio. Device-service capabilities added later are never
    // inherited implicitly; inputd/displayd/netd/audiod receive them explicitly.
    pub const CAP_ALL: u32 = CAP_MMIO | CAP_BLOCK_DEV | CAP_SPAWN_SVC;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bits_are_distinct_and_all_composes() {
            // 位值即 ABI 契约：bit0..bit2 冻结（第八刀），bit3..bit6
            // 第十三刀追加；冻结后只能追加不能改义。
            assert_eq!(CAP_MMIO, 0b0000_0001);
            assert_eq!(CAP_BLOCK_DEV, 0b0000_0010);
            assert_eq!(CAP_SPAWN_SVC, 0b0000_0100);
            assert_eq!(CAP_CHANNEL_CREATE, 0b0000_1000);
            assert_eq!(CAP_SECURE_IPC, 0b0001_0000);
            assert_eq!(CAP_ISSUER, 0b0010_0000);
            assert_eq!(CAP_SESSION, 0b0100_0000);
            assert_eq!(CAP_ALL, 0b0111);
            // 两两不相交：任何能力都不能被其余能力组合伪造出来。
            let all = [
                CAP_MMIO,
                CAP_BLOCK_DEV,
                CAP_SPAWN_SVC,
                CAP_CHANNEL_CREATE,
                CAP_SECURE_IPC,
                CAP_ISSUER,
                CAP_SESSION,
                CAP_INPUT_DEV,
                CAP_DISPLAY,
                CAP_NET_DEV,
                CAP_AUDIO_DEV,
                CAP_SPAWN_APP,
                CAP_PKG_CLIENT,
                CAP_AUDIO_CLIENT,
                CAP_POWER,
            ];
            for (i, a) in all.iter().enumerate() {
                for (j, b) in all.iter().enumerate() {
                    if i != j {
                        assert_eq!(a & b, 0, "bits {i} and {j} overlap");
                    }
                }
            }
            assert_eq!(CAP_ALL & !(CAP_MMIO | CAP_BLOCK_DEV | CAP_SPAWN_SVC), 0);
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
    /// 通道描述符（内核建通道时传入；号位 42 `CreateChannel` 运行时
    /// 建通道复用同一布局）。
    ///
    /// 【第十三刀扩展】尾部追加 `tx_groups` / `rx_groups` 许可位图：
    /// **0 = 不限（全通）**——既有构造方不写新字段即等价旧语义，
    /// 引导期全部预建通道保持全通，向后兼容成立。非 0 时收发按
    /// 调用方能力位图（[`crate::cap`]）与掩码求交判定，越权返回
    /// `IpcError::PolicyDenied`（内核侧映射 PermissionDenied）。
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct ChannelDesc {
        /// 通道 ID（见 [`crate::channels`] 冻结值；0x270 段为运行时动态段）。
        pub id: u32,
        /// 通道队列容量（条消息；内核上限 16，超出按 16 计）。
        pub capacity: u32,
        /// 发送许可位图（第十三刀）：0=全通；非 0 要求发送方能力位图
        /// 与本掩码**有交集**（任一位置位即可，最小授权取"或"语义）。
        pub tx_groups: u32,
        /// 接收许可位图（第十三刀）：语义同 [`ChannelDesc::tx_groups`]，
        /// 约束 receive 与阻塞等待登记。
        pub rx_groups: u32,
    }

    impl ChannelDesc {
        /// 全通描述符（历史两字段语义的规范构造器）：引导期预建
        /// 通道一律经此入口，保证"默认全通"的向后兼容不变量。
        pub const fn open(id: u32, capacity: u32) -> Self {
            Self {
                id,
                capacity,
                tx_groups: 0,
                rx_groups: 0,
            }
        }
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
        /// (1) 从通道收消息：`x1`=channel，`x2`=&mut Message；成功返回发送者 PID。
        /// 空队列时内核阻塞并在 continuation 完成后同样返回发送者 PID。
        ReceiveMessage {
            channel: u32,
            user_buffer: usize,
        },
        /// (2) 派生子进程（返回子进程 PID）。
        Fork,
        /// (3) 替换当前进程映像（第九刀 execve 最小完备版，**破坏性升级**，
        /// 2026-08 冻结）：`x1`=name_ptr（rootfs 内路径），`x2`=name_len
        /// （>0 且 ≤256），`x3`=arg（透传给新映像的 x2）。成功后控制流转向
        /// 新 ELF 入口——本调用对调用方不再"返回"；失败返回错误码且旧映像
        /// 完好（原子性）。新映像起步现场：x0/x1=bootfs 表首址/条目数、
        /// x2=arg、x30=thread_exit（main 返回即 exit(0)，退出码可被父收集）；
        /// 进程 pid / 族谱 / capabilities 保留——exec 换映像不换进程。
        ///
        /// 【语义冻结说明】旧「`x1`=entry 函数指针，`x2`=arg」伪 exec 语义
        /// 废除：全仓库无调用方；双语义同号位存在编码歧义；且该语义不换
        /// 地址空间、不加载 ELF（完整理由见内核 microkernel/src/syscalls.rs
        /// 号位 3 臂）。内核行为：销毁旧地址空间 → map_user_elf_segments
        /// 装载 → 切 TTBR0 → 重置 TrapFrame 跳 ELF 入口。下方字段名
        /// `entry`/`arg` 为历史遗留命名（源兼容保留），现语义分别为
        /// name_ptr / name_len。
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
        ///
        /// 第八刀能力门控：需 [`super::cap::CAP_BLOCK_DEV`]（无位返回
        /// `PermissionDenied`）；len 另受 1 MiB 上限（2048 扇区），超出
        /// 返回 `InvalidArgument`——内核中转缓冲按 len 分配，无上限即
        /// 用户可控的巨分配 DoS。
        BlockRead {
            lba: u64,
            user_buffer: usize,
            len: usize,
        },
        /// (8) 块设备写：`x1`=lba，`x2`=&buf，`x3`=len。门控同
        /// [`Syscall::BlockRead`]：需 [`super::cap::CAP_BLOCK_DEV`] 且
        /// len ≤ 1 MiB。
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
        ///
        /// ⚠ 第八刀下线：号位 10-14/17 恒返回 [`SysError::NotSupported`]。
        /// 现实现把内核恒等映射区的指针直接交给 EL0——用户态首次解引用即
        /// 致命异常（恒等映射对 EL0 无权限），号位 17 更是直接泄漏物理地址；
        /// 双路封死，止血下线。重设计（Region 表 + map 进请求者地址空间）
        /// 见 STATUS「第八刀候选」第 3 条。
        ShmCreate {
            size: usize,
            user_result: usize,
        },
        /// (11) 映射共享内存，返回映射地址。⚠ 已下线，恒返回
        /// [`SysError::NotSupported`]（理由见 [`Syscall::ShmCreate`]）。
        ShmMap {
            handle: u32,
        },
        /// (12) 查询共享内存长度。⚠ 已下线，恒返回
        /// [`SysError::NotSupported`]。
        ShmLen {
            handle: u32,
        },
        /// (13) 增加共享内存引用。⚠ 已下线，恒返回
        /// [`SysError::NotSupported`]。
        ShmRetain {
            handle: u32,
        },
        /// (14) 释放共享内存引用。⚠ 已下线，恒返回
        /// [`SysError::NotSupported`]。
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
        /// (17) 查询共享内存物理页地址（返回物理地址）。⚠ 已下线，
        /// 恒返回 [`SysError::NotSupported`]（物理地址泄漏给 EL0，
        /// 理由见 [`Syscall::ShmCreate`]）。
        ShmPhys {
            handle: u32,
        },
        /// (18) 申请 MMIO 租约：`x1`=index，`x2`=&[base, len]；需
        /// [`super::cap::CAP_MMIO`] 能力（第八刀自布尔特权位升格）。
        MmioMap {
            index: u32,
            user_buffer: usize,
        },
        /// (19) 释放 MMIO 租约：`x1`=index；需 [`super::cap::CAP_MMIO`]。
        MmioUnmap {
            index: u32,
        },
        /// (20) 按名启动内核登记的服务：`x1`=name_ptr，`x2`=len；需
        /// [`super::cap::CAP_SPAWN_SVC`] 能力。
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
        /// (23) 查询当前进程的父进程 PID（POSIX getppid 最小集，2026-08 新增；
        /// **号位 23 冻结**）。无参数。返回值语义与内核孤儿策略
        /// （microkernel process.rs【孤儿策略】）对齐：
        /// - Fork 出的子进程：返回父进程 pid——父死后被收养的孤儿，其
        ///   parent 已被 full_reap 重定向为 INIT_PID，故返回收养者
        ///   launchd 的 pid=2；
        /// - 内核直生根进程（服务注册表 spawn 路径，parent=None）：返回
        ///   0（“无父”约定，对照 Linux 中 pid 1 的 ppid=0）。
        /// 错误：当前槽位无有效记录 → [`SysError::PermissionDenied`]
        /// （与号位 21 GetPid 同一防御语义）。
        GetPpid,
        /// (24) 调整用户堆 break（POSIX brk 最小集，第十刀；**号位 24 冻结**，
        /// 2026-08 新增）：`x1`=请求的新 break 虚拟地址（u64 按 usize 解释）。
        ///
        /// 布局契约（与内核 `mm/address_space.rs::USER_HEAP_BASE` 一致）：
        /// - 堆区域为 `[USER_HEAP_BASE, brk)`，`USER_HEAP_BASE = 0x1000_0000`
        ///   （256 MiB，2 MiB 对齐：避开 [0x20_0000, ~4MiB) 的 ELF 链接区，
        ///   与 bootfs(2GiB)/栈顶(0xFFFF_F000) 不相交，且整段落在用户私有
        ///   L1[0] 区间（<1GiB），不触碰内核共享表 L1[1]）；
        /// - 初始 break == USER_HEAP_BASE（0 字节堆）；spawn/exec 重置、
        ///   fork 原样继承（子堆页随 eager-copy 克隆自然带上）；
        /// - 上限：堆总量 ≤ 64 MiB（`USER_HEAP_MAX_LEN`），超出返回
        ///   [`SysError::NoMemory`]（对应 POSIX ENOMEM）。
        ///
        /// 语义：
        /// - `x1 > 当前 break`：按页分配零页并以 USER_AP_RW 映入
        ///   `[旧break, 对齐后新break)`；中途失败整体回滚（原子性）；
        /// - `x1 < 当前 break`：解除映射并归还物理页（清 PTE + BBM TLB flush）；
        /// - `x1 == 0`：查询——返回当前 break，不做任何修改；
        /// - 请求值向上对齐到 4 KiB 页边界后生效并**返回对齐后的新 break**
        ///   （对照 Linux 返回原始请求值的差异在此披露：本内核以页为唯一
        ///   粒度，对齐值即规范值）；`x1 < USER_HEAP_BASE` 返回
        ///   [`SysError::InvalidArgument`]；
        /// - 当前进程无地址空间（内核直生占位）→ [`SysError::PermissionDenied`]。
        Brk {
            /// 请求的新 break 虚拟地址；0 表示查询当前值。
            new_break: usize,
        },
        /// 号位 25：Sleepticks——当前进程睡眠指定 timer tick 数（第十一刀）。
        ///
        /// - `x1` = 睡眠时长（tick 数，0 等价于让出一次调度）；
        /// - 返回值 = 实际流逝的 tick 快照差（≥ 请求值；供实机断言
        ///   "真睡眠不忙等"），失败返回 [`SysError`]；
        /// - 睡眠期间进程 Blocked、不参与调度（对照 nanosleep 语义）；
        /// - 定时器轮到期由 tick 中断唤醒，无忙等循环。
        Sleepticks {
            /// 睡眠时长（timer tick 数）。
            ticks: u64,
        },
        /// 号位 26：CreateThread——在**调用方地址空间**内创建线程
        /// （第十五刀线程模型）。
        ///
        /// - `x1`=entry、`x2`=stack_top（调用方自备栈）、`x3`=tls
        ///   （写入 TPIDR_EL0）、`x4`=arg（新线程 x0 初值）；
        /// - 返回值 = 新线程 tid（真 pid，可经号位 22 wait_pid join）；
        /// - 共享语义：堆与已映射页全组立即可见，无复制无 COW；
        /// - 约定：entry 不得返回（返回即 SIGSEGV 终结本线程），应自行
        ///   调用号位 5 Exit——线程语境下仅终结本线程，组空间由末代
        ///   成员回收（载体所有权转移，见内核 process.rs 文档）。
        CreateThread {
            /// 线程入口（用户虚拟地址）。
            entry: usize,
            /// 线程栈顶（向下生长，页对齐推荐）。
            stack_top: usize,
            /// TLS 基址（TPIDR_EL0 初值；0 = 无 TLS）。
            tls: usize,
            /// 传给入口的参数（x0）。
            arg: usize,
        },
        /// 号位 27：FutexWait——条件等待（第十五刀线程二期）。
        FutexWait {
            /// 目标用户字（4 字节对齐 u32）。
            uaddr: usize,
            /// 期望值（不匹配即不睡眠，返回实际值）。
            expected: u32,
        },
        /// 号位 28：FutexWake——唤醒至多 max 个等在该地址的线程。
        FutexWake {
            /// 目标用户字。
            uaddr: usize,
            /// 最大唤醒数。
            max: usize,
        },
        // ═══ 第十三刀（安全模型成型）号位 40-45 ═════════════════════
        // 号位 25=Sleep、26+=文件系统已被并行刀占用，安全扩展从 40 起。
        // 内核侧落点：trap.rs::decode_syscall + syscalls::handle +
        // security 模块（GrantBook 台账）；文档登记见
        // docs/abi_syscall_reference.md。
        /// (40) 动态签发能力授予：`x1`=目标 pid，`x2`=能力位图
        /// （[`crate::cap`] 位或），`x3`=有效期 TTL（逻辑 tick，见下；
        /// 0 = 不过期）。**仅 [`crate::cap::CAP_ISSUER`] 持有者可调**
        /// （当前仅 securityd 引导期静态持有；其余一律 PermissionDenied）。
        ///
        /// 语义：内核记一条 Grant{token, pid, caps, expires_at,
        /// session}，token 为内核单调分配的 u64 编号。生效规则是**活算**
        /// （live evaluation）：目标的"有效能力"= 静态位图 ∪ Σ{有效
        /// 授予的 caps}——授予/撤销/过期都不改写进程表，撤销即时生效、
        /// fork 不继承动态授予（子 pid 名下无台账）。约束：
        /// - caps 含 [`crate::cap::CAP_ISSUER`] → InvalidArgument
        ///   （签发权不可转授）；
        /// - caps == 0 → InvalidArgument；
        /// - 目标 pid 无进程记录仍可签发（先签后 spawn 的编排自由度），
        ///   但目标消亡时授予随之清除。
        ///
        /// 成功返回 token（u64）。TTL 单位为**逻辑时钟 tick**：单核实验
        /// 内核无墙钟，以全局逻辑时钟近似单调时间——每次任意系统调用
        /// 步进 1（内核 security 模块维护），过期惰性判定（被查询时才
        /// 失效，不占中断预算）。
        CapGrant {
            target_pid: u64,
        },
        /// (41) 撤销能力授予：`x1`=token。仅 CAP_ISSUER 持有者可调。
        /// 撤销即时生效（活算模型无需回写目标位图）；未知/已撤销的
        /// token 返回 NotFound（幂等安全的重复撤销报错不静默）。
        CapRevoke {
            /// 内核在号位 40 返回的令牌编号。
            token: u64,
        },
        /// (42) 创建 IPC 通道：`x1`=&ChannelDesc（用户指针，长度必须
        /// 等于 sizeof(ChannelDesc)=16）。通道 id 冲突返回
        /// ChannelUnavailable（对照既有 create 语义的对外映射）；表满
        /// 返回 NoMemory。
        ///
        /// 门控（第十三刀）：desc 的 tx_groups/rx_groups 任一非 0
        /// （即创建**受保护通道**）要求调用方持有效
        /// [`crate::cap::CAP_CHANNEL_CREATE`]（含动态授予），否则
        /// PermissionDenied。全通通道（掩码全 0）无门控——与引导期
        /// 预建通道同一信任级别。
        CreateChannel {
            user_desc: usize,
        },
        /// (43) 建立登录会话：`x1`=登录令牌 token。令牌必须是本进程
        /// 名下、未消费、未过期且含 [`crate::cap::CAP_SESSION`] 的授予
        /// （由 securityd 校验凭据后经号位 40 签发）；校验通过即**一次性
        /// 消费**该令牌并完成：
        /// - 分配新 session id（≥1；0 保留为"无会话"）；
        /// - 调用方会话字段置为新 sid；fork 子进程继承、exec 保持；
        /// - 若调用方此前已领有会话（su 场景）：旧会话整体注销——其名下
        ///   全部成员进程的会话清零、绑定旧会话的授予全部失效（跨会话
        ///   重放防线）。
        /// 令牌无效/不属于本进程/已过期 → PermissionDenied 或 NotFound。
        SessionBegin {
            login_token: u64,
        },
        /// (44) 查询当前进程会话 id。返回值即 sid（无会话返回 0）。
        GetSession,
        /// (45) 列出全部存活会话：`x1`=&buf，`x2`=len。内核把文本行集
        /// `sid=N leader=P\n` 写入用户缓冲区（截断到 len），返回实际
        /// 写入字节数。供 shell `sessions` 命令使用。
        SessionList {
            user_buffer: usize,
            len: usize,
        },
        /// (46) 共享内存 owner 显式授权：`x1`=handle, `x2`=target pid。
        /// 只授予 opaque handle 的访问权；目标仍须自行 ShmMap，内核选择 VA。
        ShmGrant {
            handle: u32,
            target_pid: u64,
        },
        /// (47) 从内核输入设备队列取一条 [`crate::input::InputEvent`]。
        InputRead {
            user_event: usize,
        },
        /// (48) WindowServer 提交 XRGB8888 surface：x1=ptr,x2=width,x3=height,x4=stride(px)。
        DisplayPresent {
            user_buffer: usize,
            width: usize,
            height: usize,
            stride: usize,
        },
        /// (49) 读取时钟：clock_id 0=monotonic ns, 1=realtime unix ns。
        ClockGet {
            clock_id: u32,
        },
        /// (50) 睡眠至 monotonic deadline(ns)。
        SleepUntil {
            deadline_ns: u64,
        },
        /// (51/52) netd 专属二层帧数据面。
        NetSend {
            user_buffer: usize,
            len: usize,
        },
        NetRecv {
            user_buffer: usize,
            len: usize,
        },
        /// (53) netd-only: copy the negotiated virtio-net MAC (6 bytes).
        NetGetMac {
            user_buffer: usize,
        },
        /// (54) targeted IPC send: same channel ACL as IpcSend, but only target_pid may receive.
        IpcSendTo {
            channel: u32,
            target_pid: u64,
            user_message: usize,
        },
        /// (55) 非阻塞 IPC 接收：与号位 1 同 ACL/targeted-envelope 语义，
        /// 但队列无本进程可收消息时立即返回 WouldBlock，绝不登记 waiter。
        TryReceiveMessage {
            channel: u32,
            user_buffer: usize,
        },
        /// (56) cryptographic random bytes from the platform entropy source.
        GetRandom {
            user_buffer: usize,
            len: usize,
        },
        /// (57) kernel-owned block device capacity in 512-byte sectors.
        BlockCapacity,
        /// (58) Spawn a user ELF supplied in caller memory. Requires
        /// [`crate::cap::CAP_SPAWN_APP`]. The kernel copies/maps the image but
        /// never performs filesystem IPC itself.
        SpawnImage {
            user_buffer: usize,
            len: usize,
        },
        /// (59) audiod-only: copy stable [`crate::audio::AudioInfo`] to EL0.
        AudioInfo {
            user_info: usize,
        },
        /// (60) audiod-only: submit one S16LE/48kHz/stereo PCM period.
        AudioPlay {
            user_buffer: usize,
            len: usize,
        },
        /// (61) audiod-only: stop/release the active PCM stream.
        AudioStop,
        /// (62) CAP_DISPLAY: query negotiated VirtIO-GPU 3D/capset contract.
        Gpu3dInfo {
            user_info: usize,
        },
        /// (63) CAP_DISPLAY: create one VirGL context for a negotiated capset.
        Gpu3dContextCreate {
            capset_id: u32,
        },
        /// (64) CAP_DISPLAY: destroy an empty VirGL context.
        Gpu3dContextDestroy {
            ctx_id: u32,
        },
        /// (65) CAP_DISPLAY: create a 3D resource from [`crate::gpu::Gpu3dResourceDesc`].
        Gpu3dResourceCreate {
            user_desc: usize,
        },
        /// (66) CAP_DISPLAY: detach/unref a 3D resource.
        Gpu3dResourceDestroy {
            resource_id: u32,
        },
        /// (67) CAP_DISPLAY: attach a resource to a context.
        Gpu3dContextAttach {
            ctx_id: u32,
            resource_id: u32,
        },
        /// (68) CAP_DISPLAY: submit an opaque VirGL dword stream (len multiple of 4).
        Gpu3dSubmit {
            ctx_id: u32,
            user_buffer: usize,
            len: usize,
        },
        /// (69) CAP_DISPLAY: transfer rendered B8G8R8X8 resource data back to EL0.
        Gpu3dReadback {
            resource_id: u32,
            user_buffer: usize,
            len: usize,
        },
        /// (70) CAP_DISPLAY: copy negotiated capset bytes to EL0.
        Gpu3dGetCapset {
            capset_id: u32,
            version: u32,
            user_buffer: usize,
            len: usize,
        },
        /// (71) kernel-owned block backend type (`protocol::blk::DEVICE_TYPE_*`).
        /// Used by blkdrv to report whether syscall 7/8 are backed by VirtIO or NVMe.
        BlockBackend,
        /// (72) Platform power transition. x1=0 shutdown, x1=1 reboot.
        /// Requires [`crate::cap::CAP_POWER`]; success does not return.
        PowerControl {
            action: u32,
        },
        /// (73) Read-only PCI function count discovered from ACPI MCFG/ECAM.
        PciCount,
        /// (74) Read-only PCI function snapshot; x1=index, x2=&mut PciFunctionInfo.
        PciInfo {
            index: u32,
            user_buffer: usize,
        },
        /// (75) Read-only virtio-net transport/queue diagnostic snapshot.
        NetDiag {
            user_buffer: usize,
        },
    }

    pub const POWER_OFF: u32 = 0;
    pub const POWER_REBOOT: u32 = 1;

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
        /// 功能未实现/已下线（第八刀新增：SHM 系统调用族止血下线，
        /// 见 [`Syscall`] 号位 10-14/17 的注释）。
        NotSupported = 8,
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
                SysError::NotSupported => "not supported",
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
    /// `u64::MAX` 及其以下 9 个值为错误（k=0..8，k=8 第八刀新增），
    /// 其余为成功数值。
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
            val if val == SysError::NotSupported.code() => Err(SysError::NotSupported),
            other => Ok(other),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn not_supported_error_contract() {
            // 判别值冻结：k=8（第八刀新增，SHM 系统调用族下线止血）。
            assert_eq!(SysError::NotSupported as u64, 8);
            assert_eq!(SysError::NotSupported.code(), u64::MAX - 8);
            assert_eq!(decode(u64::MAX - 8), Err(SysError::NotSupported));
            assert_eq!(SysError::NotSupported.as_str(), "not supported");
            // 错误区间下界随之外移一格：k≥9 的值仍是合法成功数值。
            assert_eq!(decode(u64::MAX - 9), Ok(u64::MAX - 9));
        }

        #[test]
        fn all_error_codes_decode_roundtrip() {
            for (k, err) in [
                (0u64, SysError::InvalidArgument),
                (1, SysError::PermissionDenied),
                (2, SysError::ChannelUnavailable),
                (3, SysError::NotFound),
                (4, SysError::NoMemory),
                (5, SysError::WouldBlock),
                (6, SysError::DeviceError),
                (7, SysError::Busy),
                (8, SysError::NotSupported),
            ] {
                assert_eq!(err as u64, k);
                assert_eq!(err.code(), u64::MAX - k);
                assert_eq!(decode(u64::MAX - k), Err(err));
            }
        }
    }

    /// 错误哨兵区间长度（冻结）：合法错误编码恰为 `u64::MAX - k`，
    /// `k ∈ [0, ERROR_INTERVAL_LEN)`，与 [`SysError`] 判别值个数一致。
    /// 新增错误必须同步扩区间；表驱动一致性测试
    /// （`libs/abi/tests/abi_consistency.rs`）锁定该不变量。
    pub const ERROR_INTERVAL_LEN: u64 = 9;

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
// ---------------------------------------------------------------------------
// 第十四刀：ABI 解码模糊属性测试（宿主）。
//
// LCG 伪随机 u64 全域轰击 syscall::decode：断言两条不变式——
// (1) 任意输入不 panic 且判定确定；(2) 错误带（u64::MAX-8..=MAX）之外
// 一律原样 Ok 透传、带内一律 Err。错误码契约见 SysError 文档（冻结）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod fuzz_tests {
    use super::syscall::decode;

    /// LCG 参数取 Numerical Recipes 常量；u64 溢出即自由截断。
    fn next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }

    #[test]
    fn decode_never_panics_and_band_contract_holds() {
        let mut state = 0x5EED_2026u64; // 第十四刀种子
        for _ in 0..20_000 {
            let raw = next(&mut state);
            let in_error_band = raw >= u64::MAX - 8;
            match decode(raw) {
                Ok(v) => {
                    assert!(!in_error_band, "raw=0x{raw:016x} 落入错误区间却解码成功");
                    assert_eq!(v, raw, "成功值必须原样透传");
                }
                Err(_) => {
                    assert!(in_error_band, "raw=0x{raw:016x} 应视为成功透传");
                }
            }
        }
    }

    #[test]
    fn error_band_boundaries_are_exact() {
        // 带外第一格必须成功；带内九个判别值必须全部 Err。
        assert!(decode(u64::MAX - 9).is_ok());
        for k in 0..9u64 {
            assert!(decode(u64::MAX - k).is_err(), "k={k} 应解码为错误");
        }
    }
}

#[cfg(feature = "zpkg")]
#[cfg(feature = "zpkg")]
pub mod zpkg;
