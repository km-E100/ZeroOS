//! zero-blkdrv —— 块设备服务（EL0 特权服务，内核直通委托数据面）。
//!
//! ## 架构决策（第七刀，2026-08）
//!
//! 收到 BLKDRV_REQ 后把请求翻译为号位 7/8（BlockRead/BlockWrite）
//! 系统调用，由内核 virtio-blk 驱动（**设备唯一属主**）完成实际 IO。
//! 不让用户态直接接管 MMIO 队列，两个硬约束：
//!
//! 1. **双驱动争用**：用户态若重配 virtio-mmio 队列（QUEUE_NUM/PFN），
//!    内核侧既有队列状态立即失效——securityd userdb 等仍走号位 7/8
//!    的路径会整体劣化；单属主委托下两条路径天然串行（单核 +
//!    syscall 同步完成），零争用。
//! 2. **shm 缓冲对 EL0 不可见**：内核 ShmCreate 返回的是恒等映射区
//!    （内核堆）地址，页表 AP=EL1_RW/EL0_NONE（mm/paging.rs）——
//!    旧版“shm 句柄 + DMA 物理地址”协议在 EL0 第一次解引用缓冲就会
//!    permission fault。等 mm 提供真正跨进程共享映射后再评估原生路径。
//!
//! 旧的原生 virtio-mmio/NVMe 队列实现保留在 git 历史；待内核让渡
//! 设备所有权后可以以本服务的 privileged 身份恢复。
//!
//! 数据传输采用 zero_abi::protocol::blk::passthrough（冻结协议）：
//! 单条消息载荷有限，大块 IO 由调用方按**单扇区内字节块**分片；
//! 写路径在本地 .bss 暂存扇区上做“读-改-写整扇区”。号位 7/8 要求
//! 调用方缓冲位于自身用户空间（内核 validate_user_ptr 拒绝
//! [1GiB,2GiB) 恒等区），静态缓冲天然满足。

#![no_std]

use core::convert::TryInto;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;
use userlib::{
    self, block_backend_type, block_capacity_sectors, block_read, block_write, driver_count,
    driver_info, mmio_map, mmio_unmap, yield_now,
};
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::blk as blk_proto;
use zero_abi::protocol::blk::passthrough as pt_proto;
use zero_abi::syscall::SysError;

const SECTOR_SIZE: usize = 512;
/// READ_CHUNK 单片上限（响应载荷 128 字节封顶）。
const READ_CHUNK_MAX: u32 = 124;
/// WRITE_CHUNK 单片上限（请求头 20 字节 + 数据上限）。
const WRITE_CHUNK_MAX: u32 = 104;

/// 直通后端唯一逻辑设备号：号位 7/8 无设备参数，内核当前只驱动
/// 一块 virtio-blk；多盘支持留待内核暴露几何信息后再扩展映射表。
const PASSTHROUGH_DEVICE: u8 = 0;

/// 单扇区暂存缓冲：号位 7/8 的目标缓冲必须在调用方自身用户空间
/// （.bss 位于 <1GiB 用户代码/数据区）。blkdrv 单线程独占执行，
/// Mutex 仅满足静态可变安全。
static SECTOR_BUF: Mutex<[u8; SECTOR_SIZE]> = Mutex::new([0u8; SECTOR_SIZE]);

/// 后端就绪标志（启动时扫描内核驱动表得出）。
static BACKEND_READY: AtomicBool = AtomicBool::new(false);

pub extern "C" fn server_main() -> ! {
    print_line("Zero OS blkdrv (EL0 service) online");
    let ready = probe_backend();
    BACKEND_READY.store(ready, Ordering::SeqCst);
    if ready {
        let kind = block_backend_type().unwrap_or(0);
        if kind == blk_proto::DEVICE_TYPE_NVME {
            print_line("blkdrv: passthrough backend ready (NVMe via kernel svc 7/8)");
        } else {
            print_line("blkdrv: passthrough backend ready (VirtIO blk via kernel svc 7/8)");
        }
    } else {
        print_line(
            "blkdrv: WARNING no block device in kernel table; IO fails with STATUS_NODEVICE",
        );
    }
    pci_mmio_lease_self_test();

    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive(channels::BLKDRV_REQ, &mut message) {
            Ok(_) => dispatch(&message),
            // WouldBlock 只是防御分支：阻塞接收通常由内核 continuation
            // 直接带回消息（见 microkernel/src/syscalls.rs ReceiveMessage）。
            Err(SysError::WouldBlock) => yield_now(),
            Err(_) => {
                warn_line("blkdrv: receive error");
                yield_now();
            }
        }
    }
}

/// Knife35 hardware acceptance hook. Only runs when a generic PCI test device
/// is present, so normal boots pay only a DriverCount/DriverInfo scan. The
/// volatile EL0 read proves MmioMap installed a real user Device mapping rather
/// than merely returning a physical address token.
fn pci_mmio_lease_self_test() {
    let Ok(count) = driver_count() else { return };
    for index in 0..count.min(256) {
        let Ok(info) = driver_info(index as u32) else {
            continue;
        };
        if info.kind != zero_abi::driver::DriverKind::PciTest as u32 || info.mmio_len < 4 {
            continue;
        }
        let Ok(region) = mmio_map(index as u32) else {
            print_line("blkdrv: PCI MMIO LEASE SELFTEST FAIL map");
            return;
        };
        // A lease is a user VA, never the PCI physical BAR address.
        if region.base == info.mmio_base || region.len < 4 {
            let _ = mmio_unmap(index as u32);
            print_line("blkdrv: PCI MMIO LEASE SELFTEST FAIL geometry");
            return;
        }
        unsafe {
            core::ptr::read_volatile(region.base as *const u32);
        }
        if mmio_unmap(index as u32).is_err() {
            print_line("blkdrv: PCI MMIO LEASE SELFTEST FAIL unmap");
            return;
        }
        print_line("blkdrv: PCI MMIO LEASE SELFTEST PASS");
        return;
    }
}

/// Query the live kernel backend. Static boot descriptors are not authoritative
/// once PCI-discovered VirtIO/NVMe controllers are supported.
fn probe_backend() -> bool {
    block_capacity_sectors().map(|v| v > 0).unwrap_or(false)
}

fn dispatch(request: &Message) {
    match request.code {
        blk_proto::CMD_LIST => cmd_list(),
        blk_proto::CMD_INFO => cmd_info(),
        pt_proto::CMD_READ_CHUNK => cmd_read_chunk(&request.payload),
        pt_proto::CMD_WRITE_CHUNK => cmd_write_chunk(&request.payload),
        // shm 句柄版数据面废弃（EL0 无法解引用内核恒等区缓冲）；
        // FLUSH/partition/identify 尚无对应语义。
        blk_proto::CMD_READ
        | blk_proto::CMD_WRITE
        | blk_proto::CMD_FLUSH
        | blk_proto::CMD_PARTITION_INFO
        | blk_proto::CMD_IDENTIFY => respond_status(blk_proto::STATUS_UNSUPPORTED, &[]),
        _ => respond_status(blk_proto::STATUS_INVALID, &[]),
    }
}

fn cmd_list() {
    let ready = BACKEND_READY.load(Ordering::SeqCst);
    let mut payload = [0u8; 2];
    payload[0] = if ready { 1 } else { 0 };
    payload[1] = PASSTHROUGH_DEVICE;
    respond_status(blk_proto::STATUS_OK, &payload);
}

fn cmd_info() {
    if !BACKEND_READY.load(Ordering::SeqCst) {
        respond_status(pt_proto::STATUS_NODEVICE, &[]);
        return;
    }
    let mut payload = [0u8; 20];
    payload[0] = PASSTHROUGH_DEVICE;
    payload[1] = block_backend_type().unwrap_or(blk_proto::DEVICE_TYPE_VIRTIO);
    payload[4..12].copy_from_slice(&(SECTOR_SIZE as u64).to_le_bytes());
    let capacity = block_capacity_sectors().unwrap_or(0);
    payload[12..20].copy_from_slice(&capacity.to_le_bytes());
    respond_status(blk_proto::STATUS_OK, &payload);
}

/// 单扇区内字节块读取。
fn cmd_read_chunk(payload: &[u8]) {
    let Some(request) = ChunkRequest::parse(payload, false) else {
        respond_status(blk_proto::STATUS_INVALID, &[]);
        return;
    };
    if !request.targets_backend() {
        respond_status(blk_proto::STATUS_INVALID, &[]);
        return;
    }
    if !BACKEND_READY.load(Ordering::SeqCst) {
        respond_status(pt_proto::STATUS_NODEVICE, &[]);
        return;
    }
    let start = request.offset as usize;
    let end = start + request.len as usize;
    let mut sector = SECTOR_BUF.lock();
    if let Err(err) = block_read(request.lba, &mut sector[..]) {
        warn_line("blkdrv: passthrough read failed");
        respond_status(map_sys_error(err), &[]);
        return;
    }
    respond_status(blk_proto::STATUS_OK, &sector[start..end]);
}

/// 单扇区内字节块写入（内部整扇区读-改-写）。
fn cmd_write_chunk(payload: &[u8]) {
    let Some(request) = ChunkRequest::parse(payload, true) else {
        respond_status(blk_proto::STATUS_INVALID, &[]);
        return;
    };
    if !request.targets_backend() {
        respond_status(blk_proto::STATUS_INVALID, &[]);
        return;
    }
    if !BACKEND_READY.load(Ordering::SeqCst) {
        respond_status(pt_proto::STATUS_NODEVICE, &[]);
        return;
    }
    let start = request.offset as usize;
    let end = start + request.len as usize;
    let mut sector = SECTOR_BUF.lock();
    if let Err(err) = block_read(request.lba, &mut sector[..]) {
        warn_line("blkdrv: rmw read failed");
        respond_status(map_sys_error(err), &[]);
        return;
    }
    sector[start..end].copy_from_slice(&payload[HEADER_LEN..HEADER_LEN + request.len as usize]);
    if let Err(err) = block_write(request.lba, &sector[..]) {
        warn_line("blkdrv: passthrough write failed");
        respond_status(map_sys_error(err), &[]);
        return;
    }
    respond_status(blk_proto::STATUS_OK, &request.len.to_le_bytes());
}

/// 分块请求公共头（小端）：[0]=device，[1..4]=0，[4..12]=lba，
/// [12..16]=offset，[16..20]=len；WRITE_CHUNK 头后紧跟 len 字节数据。
const HEADER_LEN: usize = 20;

struct ChunkRequest {
    device: u8,
    lba: u64,
    offset: u32,
    len: u32,
}

impl ChunkRequest {
    fn parse(payload: &[u8], is_write: bool) -> Option<Self> {
        if payload.len() < HEADER_LEN {
            return None;
        }
        let device = payload[0];
        let lba = u64::from_le_bytes(payload[4..12].try_into().ok()?);
        let offset = u32::from_le_bytes(payload[12..16].try_into().ok()?);
        let len = u32::from_le_bytes(payload[16..20].try_into().ok()?);
        let limit = if is_write {
            WRITE_CHUNK_MAX
        } else {
            READ_CHUNK_MAX
        };
        if len == 0 || len > limit {
            return None;
        }
        if offset.checked_add(len)? > SECTOR_SIZE as u32 {
            return None;
        }
        if is_write && payload.len() < HEADER_LEN + len as usize {
            return None;
        }
        Some(Self {
            device,
            lba,
            offset,
            len,
        })
    }

    fn targets_backend(&self) -> bool {
        self.device == PASSTHROUGH_DEVICE
    }
}

fn map_sys_error(err: SysError) -> u32 {
    match err {
        SysError::InvalidArgument => blk_proto::STATUS_INVALID,
        _ => blk_proto::STATUS_IOERR,
    }
}

/// 发送一条响应（code=协议状态码，payload 附带数据）。
fn respond_status(code: u32, payload: &[u8]) {
    let mut message = Message::empty();
    message.code = code;
    let len = payload.len().min(message.payload.len());
    message.payload[..len].copy_from_slice(&payload[..len]);
    let _ = userlib::ipc_send(channels::BLKDRV_RESP, &message);
}

/// 生命周期行必须走 console（log 宏无 logger 注册，不会上串口）。
fn print_line(text: &str) {
    let _ = userlib::console_write(text.as_bytes());
    let _ = userlib::console_write(
        b"
",
    );
}

fn warn_line(text: &str) {
    print_line(text);
}
