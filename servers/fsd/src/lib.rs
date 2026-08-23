//! zero-fsd —— 块设备卷文件服务（EL0）。
//!
//! ## 架构决策（第七刀，2026-08）
//!
//! 由“只读 rootfs 镜像服务”升级为**块后端文件服务**：
//! - **内存版文件表**：MAX_FILES 个固定槽位的“名字→LBA”映射，常驻
//!   内存；元数据持久化于卷超级块（单扇区），文件数据按固定容量
//!   槽位落盘（每槽 FILE_SECTORS 个扇区）。
//! - **零硬件访问**：fsd 不碰 MMIO/号位7/8，文件 IO 全部翻译为对
//!   blkdrv 的 protocol::blk::passthrough 分块直通请求
//!   （BLKDRV_REQ/BLKDRV_RESP），块设备由内核驱动唯一属主持有。
//! - **懒挂载**：首次收到 FS 请求才探测 blkdrv 并装载超级块——
//!   launchd 按 KNOWN_SERVICES 顺序 spawn，fsd 先于 blkdrv 运行，
//!   懒挂载天然消除启动竞态；blkdrv 缺席时进入降级模式（所有
//!   文件操作回 ERR_DEVICE，与 securityd 无盘降级同款策略）。
//!
//! ## 卷布局（QEMU 测试盘 target/disk.img，32MiB）
//!
//!   LBA 128..136   （旧 userdb 区，遗留）
//!   LBA 2048       内核 virtio-blk 自检图案扇区（他人所有）
//!   LBA 4096 起    securityd userdb SUD1 头部+记录区（他人所有）
//!   LBA 8192       卷超级块：magic "ZVTB" | version u32 | used u32 |
//!                  MAX_FILES x { name[24] NUL 填充, size u64, reserved u64 }
//!   LBA 16384 起   数据区：槽 i @ DATA_LBA + i*FILE_SECTORS，
//!                  容量 FILE_SECTORS*512 = 16KiB/槽
//!
//! 客户端协议见 zero_abi::protocol::fs::vtable（冻结）；旧码
//! 0x01/0x02/0x03/0x04 兼容映射到同名语义（OPEN 视为 EXISTING）。
//! 单客户端假设：FS_RESP/BLKDRV_RESP 是共享响应通道，本里程碑仅
//! shell 的 fstest 一个客户端，响应配对依赖串行收发。

#![no_std]

use core::cmp::min;
use core::convert::TryInto;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;
use userlib::{self, ipc_receive, ipc_send, yield_now};
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::blk as blk_proto;
use zero_abi::protocol::blk::passthrough as pt_proto;
use zero_abi::protocol::fs as fs_proto;
use zero_abi::protocol::fs::vtable as vt;
use zero_abi::syscall::SysError;

const SECTOR: usize = 512;
/// 文件槽位数（固定，内存表容量）。
const MAX_FILES: usize = 8;
/// 文件名上限（含 NUL 填充位）。
const NAME_MAX: usize = 24;
/// 每槽扇区数（16KiB/文件）。
const FILE_SECTORS: usize = 32;
const FILE_BYTES: u64 = (FILE_SECTORS * SECTOR) as u64;
// 卷外保留区（勿与任何写入方重叠）：
// - 内核 virtio-blk 自检图案扇区 @LBA 2048（microkernel SELF_TEST_LBA）；
// - securityd userdb 头部+记录区 @LBA 4096 起（SUD1 布局）。
const SUPER_LBA: u64 = 8192;
const DATA_LBA: u64 = 16384;

/// 超级块魔数（"ZVTB" = Zero Volume Table Block）。
const SUPER_MAGIC: [u8; 4] = *b"ZVTB";
const SUPER_VERSION: u32 = 1;
/// 超级块内单条槽位记录字节数：name[24] + size u64 + reserved u64。
const SLOT_RECORD: usize = 24 + 8 + 8;

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
struct Slot {
    used: bool,
    name: [u8; NAME_MAX],
    size: u64,
}

impl Slot {
    const EMPTY: Self = Self {
        used: false,
        name: [0; NAME_MAX],
        size: 0,
    };

    fn matches(&self, path: &[u8]) -> bool {
        self.used && self.name[..path.len()] == *path && self.name[path.len()] == 0
    }

    fn set_name(&mut self, path: &[u8]) -> bool {
        if path.is_empty() || path.len() >= NAME_MAX {
            return false;
        }
        self.name = [0; NAME_MAX];
        self.name[..path.len()].copy_from_slice(path);
        true
    }

    fn lba(&self, index: usize) -> u64 {
        DATA_LBA + (index as u64) * FILE_SECTORS as u64
    }
}

struct Volume {
    /// 已尝试过挂载（成功与否都只做一次）。
    attempted: bool,
    /// true = 后端缺席（无 blkdrv / 无盘），全部文件操作降级。
    degraded: bool,
    slots: [Slot; MAX_FILES],
}

static VOLUME: Mutex<Volume> = Mutex::new(Volume {
    attempted: false,
    degraded: false,
    slots: [Slot::EMPTY; MAX_FILES],
});

#[derive(Copy, Clone)]
struct FileDesc {
    id: u32,
    slot: usize,
    offset: u64,
}

static FDS: Mutex<[Option<FileDesc>; MAX_FILES]> = Mutex::new([None; MAX_FILES]);
static NEXT_FD: AtomicU32 = AtomicU32::new(1);

/// 挂载是否已成功（把重复的懒挂载尝试收敛为一次降级判定）。
static MOUNT_OK: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// 主循环
// ---------------------------------------------------------------------------

pub extern "C" fn server_main() -> ! {
    print_line("Zero OS fsd (EL0 service) online");
    print_line("fsd: block-backed volume, lazy mount on first request");

    loop {
        let mut message = Message::empty();
        match ipc_receive(channels::FS_REQ, &mut message) {
            Ok(_) => handle_request(&message),
            // WouldBlock 只是防御分支：阻塞接收通常由内核 continuation
            // 直接带回消息。
            Err(SysError::WouldBlock) => yield_now(),
            Err(_) => {
                warn_line("fsd: receive error");
                yield_now();
            }
        }
    }
}

fn handle_request(message: &Message) {
    ensure_mounted();
    match message.code {
        vt::CMD_OPEN => cmd_open(&message.payload),
        vt::CMD_WRITE => cmd_write(&message.payload),
        vt::CMD_READ => cmd_read(&message.payload),
        vt::CMD_CLOSE => cmd_close(&message.payload),
        vt::CMD_LIST => cmd_list(),
        // 旧码兼容映射（ABI 冻结值，见 protocol::fs 注释）：
        fs_proto::CMD_OPEN => cmd_open(&message.payload), // 无 mode 字节 → EXISTING
        fs_proto::CMD_READ => cmd_read(&message.payload),
        fs_proto::CMD_CLOSE => cmd_close(&message.payload),
        fs_proto::CMD_LIST => cmd_list(),
        _ => respond(fs_proto::ERR_INVALID, &[]),
    }
}

// ---------------------------------------------------------------------------
// 挂载
// ---------------------------------------------------------------------------

/// 首个请求到达时执行一次：探测 blkdrv → 读超级块（或格式化）。
fn ensure_mounted() {
    let mut volume = VOLUME.lock();
    if volume.attempted {
        return;
    }
    volume.attempted = true;

    // 1) 探测后端：BLKDRV_CMD_LIST。请求会排队等 blkdrv 上线，
    //    阻塞接收在响应到达前由内核挂起本进程——无自旋、无竞态。
    let Some(reply) = blk_call(blk_proto::CMD_LIST, &[]) else {
        volume.degraded = true;
        warn_line("fsd: blkdrv unreachable; degraded mode");
        return;
    };
    if reply.code != blk_proto::STATUS_OK || reply.payload[0] == 0 {
        volume.degraded = true;
        warn_line("fsd: no block device behind blkdrv; degraded mode");
        return;
    }

    // 2) 读超级块。
    let mut sector = [0u8; SECTOR];
    if let Err(status) = blk_read_sector(SUPER_LBA, &mut sector) {
        volume.degraded = true;
        log_status("fsd: superblock read failed", status);
        return;
    }

    let version = u32::from_le_bytes(sector[4..8].try_into().unwrap_or([0; 4]));
    if sector[0..4] != SUPER_MAGIC || version != SUPER_VERSION {
        // 3a) 空卷/异卷 → 格式化（全空表落盘）。
        volume.slots = [Slot::EMPTY; MAX_FILES];
        persist_super_locked(&mut volume);
        print_line("fsd: fresh volume initialized (formatted)");
        MOUNT_OK.store(true, Ordering::SeqCst);
        return;
    }

    // 3b) 正常装载槽位表。
    for (index, slot) in volume.slots.iter_mut().enumerate() {
        let base = 12 + index * SLOT_RECORD;
        let record = &sector[base..base + SLOT_RECORD];
        let name_len = record[..NAME_MAX].iter().position(|&b| b == 0);
        let size = u64::from_le_bytes(record[NAME_MAX..NAME_MAX + 8].try_into().unwrap_or([0; 8]));
        if let Some(len) = name_len {
            if len > 0 {
                slot.used = true;
                slot.name = [0; NAME_MAX];
                slot.name[..len].copy_from_slice(&record[..len]);
                slot.size = size;
            }
        }
    }
    MOUNT_OK.store(true, Ordering::SeqCst);
    print_line("fsd: volume mounted");
    for slot in volume.slots.iter().filter(|s| s.used) {
        let end = slot.name.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
        let _ = userlib::console_write(b"  - ");
        let _ = userlib::console_write(&slot.name[..end]);
        let _ = userlib::console_write(b"\r\n");
    }
}

/// 把内存表写回超级块扇区（调用方持锁；RMW 单扇区）。
fn persist_super_locked(volume: &mut Volume) {
    let mut sector = [0u8; SECTOR];
    sector[0..4].copy_from_slice(&SUPER_MAGIC);
    sector[4..8].copy_from_slice(&SUPER_VERSION.to_le_bytes());
    let used = volume.slots.iter().filter(|s| s.used).count() as u32;
    sector[8..12].copy_from_slice(&used.to_le_bytes());
    for (index, slot) in volume.slots.iter().enumerate() {
        if !slot.used {
            continue;
        }
        let base = 12 + index * SLOT_RECORD;
        sector[base..base + NAME_MAX].copy_from_slice(&slot.name);
        sector[base + NAME_MAX..base + NAME_MAX + 8].copy_from_slice(&slot.size.to_le_bytes());
    }
    if let Err(status) = blk_write_sector(SUPER_LBA, &sector) {
        log_status("fsd: superblock persist failed", status);
    }
}

// ---------------------------------------------------------------------------
// 文件命令
// ---------------------------------------------------------------------------

/// OPEN：payload [path NUL][mode u8?]。成功回 fd（payload[0..4]）。
fn cmd_open(payload: &[u8]) {
    let Some((path, mode)) = parse_open(payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    if !MOUNT_OK.load(Ordering::SeqCst) {
        respond(fs_proto::ERR_DEVICE, &[]);
        return;
    }

    let mut volume = VOLUME.lock();
    if volume.degraded {
        respond(fs_proto::ERR_DEVICE, &[]);
        return;
    }

    let existing = volume.slots.iter().position(|slot| slot.matches(path));

    let slot_index = match existing {
        Some(index) => index,
        None => {
            if mode != vt::OPEN_CREATE {
                respond(fs_proto::ERR_NOT_FOUND, &[]);
                return;
            }
            match volume.slots.iter().position(|slot| !slot.used) {
                Some(index) => {
                    volume.slots[index] = Slot::EMPTY;
                    volume.slots[index].used = true;
                    volume.slots[index].set_name(path);
                    persist_super_locked(&mut volume);
                    index
                }
                None => {
                    respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
                    return;
                }
            }
        }
    };

    let mut fds = FDS.lock();
    let free = fds.iter_mut().find(|entry| entry.is_none());
    let Some(entry) = free else {
        respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
        return;
    };
    let id = NEXT_FD.fetch_add(1, Ordering::SeqCst);
    *entry = Some(FileDesc {
        id,
        slot: slot_index,
        offset: 0,
    });
    respond(0, &id.to_le_bytes());
}

/// WRITE：payload [fd u32][len u32][data..]。按 fd 偏移写入，推进
/// 偏移并维护文件大小；逐受影响扇区读-改-写落盘。
fn cmd_write(payload: &[u8]) {
    if payload.len() < 8 {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let fd = u32::from_le_bytes(payload[0..4].try_into().unwrap_or([0; 4]));
    let len = u32::from_le_bytes(payload[4..8].try_into().unwrap_or([0; 4])) as usize;
    if len == 0 || len > 120 || payload.len() < 8 + len {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let data = &payload[8..8 + len];

    if !MOUNT_OK.load(Ordering::SeqCst) {
        respond(fs_proto::ERR_DEVICE, &[]);
        return;
    }
    let mut volume = VOLUME.lock();
    if volume.degraded {
        respond(fs_proto::ERR_DEVICE, &[]);
        return;
    }
    let mut fds = FDS.lock();
    let Some(descriptor) = fds.iter_mut().find_map(|e| e.as_mut().filter(|d| d.id == fd)) else {
        respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
        return;
    };
    let start = descriptor.offset;
    let end = start + len as u64;
    if end > FILE_BYTES {
        // 固定槽位容量写满即拒（本里程碑不做跨槽扩展）。
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }

    let slot_lba = volume.slots[descriptor.slot].lba(descriptor.slot);
    let mut sector_buf = [0u8; SECTOR];
    let first_sector = (start / SECTOR as u64) as usize;
    let last_sector = ((end - 1) / SECTOR as u64) as usize;
    let mut cursor = first_sector;
    while cursor <= last_sector {
        let sector_start = (cursor as u64) * SECTOR as u64;
        if blk_read_sector(slot_lba + cursor as u64, &mut sector_buf).is_err() {
            respond(fs_proto::ERR_DEVICE, &[]);
            return;
        }
        let from = (start - sector_start) as usize;
        let to = (end - sector_start) as usize;
        let data_from = (sector_start.max(start) - start) as usize;
        sector_buf[from..to].copy_from_slice(&data[data_from..data_from + (to - from)]);
        if blk_write_sector(slot_lba + cursor as u64, &sector_buf).is_err() {
            respond(fs_proto::ERR_DEVICE, &[]);
            return;
        }
        cursor += 1;
    }

    let slot = &mut volume.slots[descriptor.slot];
    if end > slot.size {
        slot.size = end;
        persist_super_locked(&mut volume);
    }
    descriptor.offset = end;
    respond(0, &(len as u32).to_le_bytes());
}

/// READ：payload [fd u32][len u32]。最多回一条消息的数据
/// （≤128 字节）；数据直接作为响应载荷。
fn cmd_read(payload: &[u8]) {
    if payload.len() < 8 {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let fd = u32::from_le_bytes(payload[0..4].try_into().unwrap_or([0; 4]));
    let requested = u32::from_le_bytes(payload[4..8].try_into().unwrap_or([0; 4])) as usize;
    if requested == 0 {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    if !MOUNT_OK.load(Ordering::SeqCst) {
        respond(fs_proto::ERR_DEVICE, &[]);
        return;
    }
    let volume = VOLUME.lock();
    if volume.degraded {
        respond(fs_proto::ERR_DEVICE, &[]);
        return;
    }
    let mut fds = FDS.lock();
    let Some(descriptor) = fds.iter_mut().find_map(|e| e.as_mut().filter(|d| d.id == fd)) else {
        respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
        return;
    };
    let size = volume.slots[descriptor.slot].size;
    let avail = size.saturating_sub(descriptor.offset) as usize;
    let total = min(min(requested, avail), 128);

    let slot_lba = volume.slots[descriptor.slot].lba(descriptor.slot);
    let mut response = Message::empty();
    response.code = 0;
    let mut sector_buf = [0u8; SECTOR];
    let mut pos = descriptor.offset;
    let mut done = 0usize;
    while done < total {
        let sector_index = (pos / SECTOR as u64) as usize;
        if blk_read_sector(slot_lba + sector_index as u64, &mut sector_buf).is_err() {
            respond(fs_proto::ERR_DEVICE, &[]);
            return;
        }
        let in_off = (pos % SECTOR as u64) as usize;
        let take = min(total - done, SECTOR - in_off);
        response.payload[done..done + take].copy_from_slice(&sector_buf[in_off..in_off + take]);
        done += take;
        pos += take as u64;
    }
    descriptor.offset += total as u64;
    let _ = ipc_send(channels::FS_RESP, &response);
}

/// CLOSE：payload [fd u32]。释放描述符，文件保留。
fn cmd_close(payload: &[u8]) {
    if payload.len() < 4 {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let fd = u32::from_le_bytes(payload[0..4].try_into().unwrap_or([0; 4]));
    let mut fds = FDS.lock();
    if let Some(pos) = fds
        .iter()
        .position(|entry| entry.map(|d| d.id == fd).unwrap_or(false))
    {
        fds[pos] = None;
        respond(0, &[]);
    } else {
        respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
    }
}

/// LIST：响应 payload 为 name+LF 串（NUL 收尾）。
fn cmd_list() {
    if !MOUNT_OK.load(Ordering::SeqCst) {
        respond(fs_proto::ERR_DEVICE, &[]);
        return;
    }
    let volume = VOLUME.lock();
    if volume.degraded {
        respond(fs_proto::ERR_DEVICE, &[]);
        return;
    }
    let mut response = Message::empty();
    response.code = 0;
    let mut offset = 0usize;
    for slot in volume.slots.iter().filter(|s| s.used) {
        let end = slot.name.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
        if offset + end + 2 >= response.payload.len() {
            break;
        }
        response.payload[offset..offset + end].copy_from_slice(&slot.name[..end]);
        offset += end;
        response.payload[offset] = b'\n';
        offset += 1;
    }
    let _ = ipc_send(channels::FS_RESP, &response);
}

// ---------------------------------------------------------------------------
// open 解析与块 IO
// ---------------------------------------------------------------------------

/// 解析 [path NUL][mode u8?]；路径规整：剥一个前导 '/'，拒绝内嵌
/// '/'，长度 <NAME_MAX。返回 (path 字节, mode)。
fn parse_open(payload: &[u8]) -> Option<(&[u8], u8)> {
    let end = payload.iter().position(|&b| b == 0)?;
    let raw = &payload[..end];
    let rest = &payload[end + 1..];
    let mode = if rest.is_empty() { vt::OPEN_EXISTING } else { rest[0] };
    let path = if raw.first() == Some(&b'/') { &raw[1..] } else { raw };
    if path.is_empty() || path.len() >= NAME_MAX || path.contains(&b'/') {
        return None;
    }
    Some((path, mode))
}

/// 发送一条 BLKDRV 请求并阻塞等待配对响应。失败（通道错误）返回
/// None，调用方统一按 ERR_DEVICE 处理。响应配对依赖单客户端纪律。
fn blk_call(code: u32, payload: &[u8]) -> Option<Message> {
    let mut message = Message::empty();
    message.code = code;
    let len = payload.len().min(message.payload.len());
    message.payload[..len].copy_from_slice(&payload[..len]);
    ipc_send(channels::BLKDRV_REQ, &message).ok()?;
    let mut reply = Message::empty();
    loop {
        match ipc_receive(channels::BLKDRV_RESP, &mut reply) {
            Ok(_) => return Some(reply),
            Err(SysError::WouldBlock) => yield_now(),
            Err(_) => return None,
        }
    }
}

/// 整扇区读：按 ≤124 字节分片拼装。
fn blk_read_sector(lba: u64, out: &mut [u8; SECTOR]) -> Result<(), u32> {
    let mut done = 0usize;
    while done < SECTOR {
        let take = min(SECTOR - done, 124);
        let mut request = [0u8; 20];
        request[4..12].copy_from_slice(&lba.to_le_bytes());
        request[12..16].copy_from_slice(&(done as u32).to_le_bytes());
        request[16..20].copy_from_slice(&(take as u32).to_le_bytes());
        let reply = blk_call(pt_proto::CMD_READ_CHUNK, &request).ok_or(blk_proto::STATUS_IOERR)?;
        if reply.code != blk_proto::STATUS_OK {
            return Err(reply.code);
        }
        out[done..done + take].copy_from_slice(&reply.payload[..take]);
        done += take;
    }
    Ok(())
}

/// 整扇区写：按 ≤104 字节分片（blkdrv 内部整扇区读-改-写）。
fn blk_write_sector(lba: u64, data: &[u8; SECTOR]) -> Result<(), u32> {
    let mut done = 0usize;
    while done < SECTOR {
        let take = min(SECTOR - done, 104);
        let mut request = [0u8; 20 + 104];
        request[4..12].copy_from_slice(&lba.to_le_bytes());
        request[12..16].copy_from_slice(&(done as u32).to_le_bytes());
        request[16..20].copy_from_slice(&(take as u32).to_le_bytes());
        request[20..20 + take].copy_from_slice(&data[done..done + take]);
        let reply = blk_call(pt_proto::CMD_WRITE_CHUNK, &request[..20 + take])
            .ok_or(blk_proto::STATUS_IOERR)?;
        if reply.code != blk_proto::STATUS_OK {
            return Err(reply.code);
        }
        done += take;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 杂项
// ---------------------------------------------------------------------------

fn respond(code: u32, payload: &[u8]) {
    let mut message = Message::empty();
    message.code = code;
    let len = payload.len().min(message.payload.len());
    message.payload[..len].copy_from_slice(&payload[..len]);
    let _ = ipc_send(channels::FS_RESP, &message);
}

/// 生命周期行必须走 console（log 宏无 logger 注册，不会上串口）。
fn print_line(text: &str) {
    let _ = userlib::console_write(text.as_bytes());
    let _ = userlib::console_write(b"\r\n");
}

fn warn_line(text: &str) {
    print_line(text);
}

fn log_status(prefix: &str, status: u32) {
    warn_line(prefix);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 8];
    let mut v = status;
    for idx in (0..8).rev() {
        buf[idx] = HEX[(v & 0xf) as usize];
        v >>= 4;
    }
    let _ = userlib::console_write(b"  status=0x");
    let _ = userlib::console_write(&buf);
    let _ = userlib::console_write(b"\r\n");
}
