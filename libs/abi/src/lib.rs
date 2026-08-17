#![no_std]

pub mod bootfs;

pub mod boot {
    use core::{slice, str};

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct RootFsEntry {
        pub path_ptr: *const u8,
        pub path_len: usize,
        pub data_ptr: *const u8,
        pub data_len: usize,
    }

    impl RootFsEntry {
        pub const fn new(path: &'static str, data: &'static [u8]) -> Self {
            Self {
                path_ptr: path.as_ptr(),
                path_len: path.len(),
                data_ptr: data.as_ptr(),
                data_len: data.len(),
            }
        }

        pub unsafe fn path(&self) -> &'static str {
            str::from_utf8_unchecked(slice::from_raw_parts(self.path_ptr, self.path_len))
        }

        pub unsafe fn data(&self) -> &'static [u8] {
            slice::from_raw_parts(self.data_ptr, self.data_len)
        }
    }

    unsafe impl Sync for RootFsEntry {}

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

        pub unsafe fn as_slice(&self) -> &'static [RootFsEntry] {
            slice::from_raw_parts(self.entries, self.entry_count)
        }
    }

    unsafe impl Sync for RootFsImage {}
}

pub mod driver {
    use core::{slice, str};

    #[repr(u32)]
    #[derive(Copy, Clone)]
    pub enum DriverKind {
        Pl011 = 1,
        VirtIOBlk = 2,
        VirtIONet = 3,
        VirtIOConsole = 4,
        VirtIORng = 5,
        Nvme = 6,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct DriverDescriptor {
        pub name_ptr: *const u8,
        pub name_len: usize,
        pub kind: DriverKind,
        pub mmio_base: u64,
        pub mmio_len: u64,
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

        pub unsafe fn name(&self) -> &'static str {
            str::from_utf8_unchecked(slice::from_raw_parts(self.name_ptr, self.name_len))
        }
    }

    unsafe impl Sync for DriverDescriptor {}

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

        pub unsafe fn as_slice(&self) -> &'static [DriverDescriptor] {
            slice::from_raw_parts(self.entries, self.count)
        }
    }

    unsafe impl Sync for DriverTable {}
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BootInfo {
    pub ipc_server_entry: extern "C" fn() -> !,
    pub zfs_server_entry: extern "C" fn() -> !,
    pub launchd_entry: extern "C" fn() -> !,
    pub rootfs: *const boot::RootFsImage,
    pub drivers: *const driver::DriverTable,
}

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

pub type ThreadEntry = extern "C" fn() -> !;

pub mod channels {
    pub const IPC_ROUTER_BUS: u32 = 0x220;
    pub const SECURITY_USER_REQ: u32 = 0x230;
    pub const SECURITY_USER_RESP: u32 = 0x231;
    pub const LAUNCHD_CMD_REQ: u32 = 0x240;
    pub const LAUNCHD_CMD_RESP: u32 = 0x241;
    pub const SERVICE_CONTROL_BUS: u32 = 0x200;
    pub const SERVICE_CONTROL_RESP: u32 = 0x201;
    pub const SERVICE_CONTROL_EVENT: u32 = 0x202;
    pub const FS_REQ: u32 = 0x250;
    pub const FS_RESP: u32 = 0x251;
    pub const BLKDRV_REQ: u32 = 0x260;
    pub const BLKDRV_RESP: u32 = 0x261;
    pub const BLKDRV_EVENT: u32 = 0x262;
}

pub mod protocol {
    pub mod security {
        pub const CMD_USER_LIST: u32 = 0x10;
        pub const CMD_USER_ADD: u32 = 0x11;
        pub const CMD_USER_PASSWD: u32 = 0x12;
        pub const CMD_USER_DELETE: u32 = 0x13;
        pub const CMD_USER_VERIFY: u32 = 0x14;
    }

    pub mod launchd {
        pub const CMD_LIST_SERVICES: u32 = 0x10;
        pub const CMD_RESTART_SERVICE: u32 = 0x11;
        pub const CMD_START_APPLICATION: u32 = 0x12;
        pub const CMD_RELOAD_FS: u32 = 0x13;
    }

    pub mod service_control {
        pub const CMD_START: u32 = 0x01;
        pub const CMD_RESTART: u32 = 0x02;
        pub const CMD_STATUS_REPORT: u32 = 0x03;
        pub const CMD_QUERY_STATUS: u32 = 0x04;

        pub const FLAG_KEEPALIVE: u8 = 0x1;
        pub const FLAG_FOREGROUND: u8 = 0x2;

        pub const STATUS_IDLE: u8 = 0;
        pub const STATUS_STARTING: u8 = 1;
        pub const STATUS_RUNNING: u8 = 2;
        pub const STATUS_FAILED: u8 = 3;
    }

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

pub mod ipc {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct ChannelDesc {
        pub id: u32,
        pub capacity: u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct Message {
        pub code: u32,
        pub payload: [u8; 128],
    }

    impl Message {
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

pub mod syscall {
    use super::ThreadEntry;
    #[derive(Copy, Clone)]
    pub enum Syscall {
        SendMessage {
            channel: u32,
            user_message: usize,
        },
        ReceiveMessage {
            channel: u32,
            user_buffer: usize,
        },
        Fork,
        Exec {
            entry: ThreadEntry,
            arg: u64,
        },
        Exit {
            status: i32,
        },
        Yield,
        ConsoleRead {
            user_buffer: usize,
            len: usize,
        },
        ConsoleWrite {
            user_buffer: usize,
            len: usize,
        },
        BlockRead {
            lba: u64,
            user_buffer: usize,
            len: usize,
        },
        BlockWrite {
            lba: u64,
            user_buffer: usize,
            len: usize,
        },
        ShmCreate {
            size: usize,
            user_result: usize,
        },
        ShmMap {
            handle: u32,
        },
        ShmLen {
            handle: u32,
        },
        ShmRetain {
            handle: u32,
        },
        ShmRelease {
            handle: u32,
        },
        DriverCount,
        DriverInfo {
            index: u32,
            user_buffer: usize,
        },
        ShmPhys {
            handle: u32,
        },
        MmioMap {
            index: u32,
            user_buffer: usize,
        },
        MmioUnmap {
            index: u32,
        },
        SpawnService {
            name_ptr: usize,
            name_len: usize,
        },
    }

    pub type SyscallResult = Result<u64, SysError>;

    #[derive(Debug)]
    pub enum SysError {
        InvalidArgument,
        PermissionDenied,
        ChannelUnavailable,
        NotFound,
        NoMemory,
        WouldBlock,
        DeviceError,
        Busy,
    }
}
