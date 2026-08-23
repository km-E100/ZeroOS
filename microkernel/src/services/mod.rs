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
        },
        ServiceDescriptor {
            name: "fsd",
            entry: ServiceEntry::Bootfs("/System/Core/zero-fsd"),
            // 文件服务（第七刀）：块后端卷文件表（名字→LBA），客户端
            // 面纯 IPC（FS_REQ/FS_RESP），对 blkdrv 走 BLKDRV_REQ 分块
            // 直通。无 MMIO 依赖，privileged=false。
            essential: false,
            privileged: false,
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
    let channels_to_create = [
        ChannelDesc {
            id: channels::IPC_ROUTER_BUS,
            capacity: 16,
        },
        ChannelDesc {
            id: channels::SECURITY_USER_REQ,
            capacity: 4,
        },
        ChannelDesc {
            id: channels::SECURITY_USER_RESP,
            capacity: 4,
        },
        ChannelDesc {
            id: channels::LAUNCHD_CMD_REQ,
            capacity: 4,
        },
        ChannelDesc {
            id: channels::LAUNCHD_CMD_RESP,
            capacity: 4,
        },
        ChannelDesc {
            id: channels::SERVICE_CONTROL_BUS,
            capacity: 8,
        },
        ChannelDesc {
            id: channels::SERVICE_CONTROL_RESP,
            capacity: 8,
        },
        ChannelDesc {
            id: channels::SERVICE_CONTROL_EVENT,
            capacity: 8,
        },
        ChannelDesc {
            id: channels::FS_REQ,
            capacity: 8,
        },
        ChannelDesc {
            id: channels::FS_RESP,
            capacity: 8,
        },
        ChannelDesc {
            id: channels::BLKDRV_REQ,
            capacity: 8,
        },
        ChannelDesc {
            id: channels::BLKDRV_RESP,
            capacity: 8,
        },
        ChannelDesc {
            id: channels::BLKDRV_EVENT,
            capacity: 4,
        },
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
            let pid = process::spawn(entry, descriptor.name);
            if descriptor.privileged {
                process::set_privileged(pid, true);
            }
            Ok(pid)
        }
        ServiceEntry::Bootfs(path) => {
            process::spawn_user_from_bootfs(path, descriptor.name, descriptor.privileged)
                .map_err(|e| ServiceError::SpawnFailed(e))
        }
    }
}

#[derive(Copy, Clone)]
pub struct ServiceDescriptor {
    pub name: &'static str,
    pub entry: ServiceEntry,
    pub essential: bool,
    pub privileged: bool,
}

#[derive(Copy, Clone)]
pub enum ServiceEntry {
    KernelFn(extern "C" fn() -> !),
    Bootfs(&'static str),
}
