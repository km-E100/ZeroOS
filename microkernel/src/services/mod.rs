use spin::Mutex;
use zero_abi::channels;
use zero_abi::ipc::ChannelDesc;
use zero_abi::{BootInfo, ProcessId};

use crate::process::ProcessError;
use crate::{process, scheduler};

static SERVICE_REGISTRY: Mutex<[Option<ServiceDescriptor>; 16]> = Mutex::new([None; 16]);

pub fn launch_core(_info: &BootInfo) {
    crate::debug!("services::launch_core: begin");
    init_channels();

    let bundled = [
        ServiceDescriptor {
            name: "launchd",
            entry: ServiceEntry::Bootfs("/System/Core/zero-launchd"),
            essential: true,
            privileged: true, // 作为 init 应当是 privileged
            capabilities: zero_abi::cap::CAP_ALL,
        },
        ServiceDescriptor {
            name: "securityd",
            entry: ServiceEntry::Bootfs("/System/Core/zero-securityd"),
            // 非核心用户态服务：纯 IPC + 控制台即可运行，无需 MMIO
            // 租约（privileged=false）。内核只登记不引导——由 launchd
            // 经 SpawnService 拉起并记账（见 servers/launchd 的
            // KNOWN_SERVICES 启动对账），否则 launchd 拿不到真实 pid。
            essential: false,
            privileged: false,
            // userdb 持久化经号位 7/8 写盘 ⇒ 需要 CAP_BLOCK_DEV；
            // 第十三刀：CAP_ISSUER 是全系统唯一的静态签发权——securityd
            // 凭此调号位 40/41 CapGrant/CapRevoke 动态签发能力令牌。
            capabilities: zero_abi::cap::CAP_BLOCK_DEV | zero_abi::cap::CAP_ISSUER,
        },
        ServiceDescriptor {
            name: "blkdrv",
            entry: ServiceEntry::Bootfs("/System/Core/zero-blkdrv"),
            // 块设备服务（第七刀）：数据面经号位 7/8 内核直通（块设备
            // 唯一属主仍是内核 virtio-blk 驱动）。privileged=true 按
            // 服务契约预留——未来恢复用户态原生 MMIO 队列路径时需要
            // MmioMap 租约；当前直通路径不强制。
            essential: false,
            privileged: true,
            capabilities: zero_abi::cap::CAP_BLOCK_DEV | zero_abi::cap::CAP_MMIO,
        },
        ServiceDescriptor {
            name: "fsd",
            entry: ServiceEntry::Bootfs("/System/Core/zero-fs-zfs"),
            // 文件服务（第32刀）：默认后端 zero-fs-zfs；客户端
            // 面保持 FS_REQ/FS_RESP + vtable ABI。内核仍是唯一块设备
            // owner；受信 zfsd 以 CAP_BLOCK_DEV 直接走序列化 BlockRead/Write，
            // 避免 4KiB ZFS block 被 128-byte IPC 放大成数十次往返。
            // zero-fsd/blkdrv 继续作为 legacy 与通用块服务保留。
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_BLOCK_DEV,
        },
        ServiceDescriptor {
            name: "inputd",
            entry: ServiceEntry::Bootfs("/System/Core/zero-inputd"),
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_INPUT_DEV,
        },
        ServiceDescriptor {
            name: "windowserver",
            entry: ServiceEntry::Bootfs("/System/Core/zero-windowserver"),
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_DISPLAY,
        },
        ServiceDescriptor {
            name: "netd",
            entry: ServiceEntry::Bootfs("/System/Core/zero-netd"),
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_NET_DEV,
        },
        ServiceDescriptor {
            name: "webtest",
            entry: ServiceEntry::Bootfs("/System/Core/zero-webtest"),
            // TEMP Parallels bring-up hook: auto-run the network diagnostic so
            // the result does not depend on flaky host key injection. Revert
            // after the TCPDIAG result is captured.
            essential: crate::bootinfo::platform_kind() == crate::bootinfo::PLATFORM_PARALLELS_ARM,
            privileged: false,
            capabilities: 0,
        },
        ServiceDescriptor {
            name: "pkgd",
            entry: ServiceEntry::Bootfs("/System/Core/zero-pkgd"),
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_SPAWN_APP,
        },
        ServiceDescriptor {
            name: "pkgtest",
            entry: ServiceEntry::Bootfs("/System/Core/zero-pkgtest"),
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_PKG_CLIENT,
        },
        ServiceDescriptor {
            name: "audiod",
            entry: ServiceEntry::Bootfs("/System/Core/zero-audiod"),
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_AUDIO_DEV,
        },
        ServiceDescriptor {
            name: "audiotest",
            entry: ServiceEntry::Bootfs("/System/Core/zero-audiotest"),
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_AUDIO_CLIENT,
        },
        ServiceDescriptor {
            name: "gputest",
            entry: ServiceEntry::Bootfs("/System/Core/zero-gputest"),
            essential: false,
            privileged: false,
            capabilities: zero_abi::cap::CAP_DISPLAY,
        },
        ServiceDescriptor {
            name: "pietest",
            entry: ServiceEntry::Bootfs("/System/Core/zero-pietest"),
            essential: false,
            privileged: false,
            capabilities: 0,
        },
        ServiceDescriptor {
            name: "dynapp",
            entry: ServiceEntry::Bootfs("/System/Test/zero-dynapp"),
            essential: false,
            privileged: false,
            capabilities: 0,
        },
    ];

    for service in bundled {
        register_service(service);
        // 核心服务（launchd）由内核引导期直接拉起；其余仅登记，
        // 由 launchd 在用户态统一 spawn——生命周期状态（running/
        // failed/not-installed）才能如实呈现给 `launchd list`。
        if service.essential {
            launch_service(service);
        }
    }

    crate::info!(
        "services::launch_core: registered {} service(s); kernel launched essential only",
        bundled.len()
    );
}

fn init_channels() {
    // 第十三刀：引导期预建通道一律 ChannelDesc::open（tx/rx_groups=0，
    // 全通）——向后兼容不变量：既有收发路径零感知。受保护通道由
    // 号位 42 CreateChannel 运行时按需创建（需 CAP_CHANNEL_CREATE）。
    let channels_to_create = [
        ChannelDesc::open(channels::IPC_ROUTER_BUS, 16),
        ChannelDesc::open(channels::SECURITY_USER_REQ, 4),
        ChannelDesc::open(channels::SECURITY_USER_RESP, 4),
        ChannelDesc::open(channels::LAUNCHD_CMD_REQ, 4),
        ChannelDesc::open(channels::LAUNCHD_CMD_RESP, 4),
        ChannelDesc::open(channels::SERVICE_CONTROL_BUS, 8),
        ChannelDesc::open(channels::SERVICE_CONTROL_RESP, 8),
        ChannelDesc::open(channels::SERVICE_CONTROL_EVENT, 8),
        ChannelDesc::open(channels::FS_REQ, 8),
        ChannelDesc::open(channels::FS_RESP, 8),
        ChannelDesc::open(channels::BLKDRV_REQ, 8),
        ChannelDesc::open(channels::BLKDRV_RESP, 8),
        ChannelDesc::open(channels::BLKDRV_EVENT, 4),
        ChannelDesc::open(channels::INPUT_EVENT_BUS, 32),
        ChannelDesc::open(channels::WINDOW_REQ, 16),
        ChannelDesc::open(channels::WINDOW_RESP, 16),
        ChannelDesc::open(channels::NET_REQ, 32),
        ChannelDesc::open(channels::NET_RESP, 32),
        ChannelDesc {
            id: channels::PKG_REQ,
            capacity: 8,
            tx_groups: zero_abi::cap::CAP_PKG_CLIENT,
            rx_groups: 0,
        },
        ChannelDesc::open(channels::PKG_RESP, 8),
        ChannelDesc {
            id: channels::AUDIO_REQ,
            capacity: 8,
            tx_groups: zero_abi::cap::CAP_AUDIO_CLIENT,
            rx_groups: 0,
        },
        ChannelDesc::open(channels::AUDIO_RESP, 8),
    ];

    for desc in channels_to_create {
        let _ = crate::ipc::create_channel(desc);
    }
}

pub fn register_service(descriptor: ServiceDescriptor) {
    let mut registry = SERVICE_REGISTRY.lock();
    if let Some(slot) = registry.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(descriptor);
    } else {
        panic!("service registry full");
    }
}

#[derive(Debug)]
pub enum ServiceError {
    NotFound,
    SpawnFailed(ProcessError),
}

pub fn spawn_service_by_name(name: &str) -> Result<ProcessId, ServiceError> {
    let registry = SERVICE_REGISTRY.lock();
    if let Some(descriptor) = registry.iter().flatten().find(|desc| desc.name == name) {
        spawn_server(descriptor)
    } else {
        Err(ServiceError::NotFound)
    }
}

fn launch_service(descriptor: ServiceDescriptor) {
    match spawn_server(&descriptor) {
        Ok(pid) => scheduler::enqueue(pid),
        Err(err) => {
            crate::warn!("failed to spawn service {}: {:?}", descriptor.name, err);
            if descriptor.essential {
                panic!(
                    "essential service {} failed to start: {:?}",
                    descriptor.name, err
                );
            }
        }
    }
}

fn spawn_server(descriptor: &ServiceDescriptor) -> Result<ProcessId, ServiceError> {
    let kind = match descriptor.entry {
        ServiceEntry::KernelFn(_) => "KernelFn",
        ServiceEntry::Bootfs(_) => "Bootfs",
    };
    crate::debug!("spawn_server: name={} entry={}", descriptor.name, kind);
    match descriptor.entry {
        ServiceEntry::KernelFn(entry) => {
            // 表满降级：spawn 的 TableFull 与 Bootfs 分支的失败同构，
            // 统一映射为 SpawnFailed —— launch_service 对非核心服务
            // 仅告警跳过，essential（launchd）仍走既有 panic 兜底。
            let pid = process::spawn(entry, descriptor.name).map_err(ServiceError::SpawnFailed)?;
            if descriptor.privileged {
                process::set_privileged(pid, true);
            }
            Ok(pid)
        }
        ServiceEntry::Bootfs(path) => {
            let pid = process::spawn_user_from_bootfs(path, descriptor.name, descriptor.privileged)
                .map_err(|e| ServiceError::SpawnFailed(e))?;
            // 精细能力授予：descriptor.capabilities 位或 privileged 布尔
            // 的历史映射（true=CAP_ALL），两者并存取并集。
            let caps = if descriptor.privileged {
                zero_abi::cap::CAP_ALL | descriptor.capabilities
            } else {
                descriptor.capabilities
            };
            if caps != 0 {
                process::set_capabilities(pid, caps);
            }
            Ok(pid)
        }
    }
}

#[derive(Copy, Clone)]
pub struct ServiceDescriptor {
    pub name: &'static str,
    pub entry: ServiceEntry,
    pub essential: bool,
    /// 兼容字段：true ⇒ spawn 时映射 CAP_ALL（历史语义）。
    /// 新代码请用 [`capabilities`] 精细位图；两者并存时按位或生效。
    pub privileged: bool,
    /// 精细能力位图（zero_abi::cap 常量）：spawn 后经 set_capabilities
    /// 授予。0 = 仅继承 privileged 标志的映射。
    pub capabilities: u32,
}

#[derive(Copy, Clone)]
pub enum ServiceEntry {
    KernelFn(extern "C" fn() -> !),
    Bootfs(&'static str),
}
