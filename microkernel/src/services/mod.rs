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
    ];

    for service in bundled {
        register_service(service);
        launch_service(service);
    }

    crate::info!(
        "services::launch_core: finished launching {} service(s)",
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
