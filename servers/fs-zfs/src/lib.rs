#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::str;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use core::slice;
use heapless::{String as HeaplessString, Vec as HeaplessVec};
use libblkclient;
use log::{error, info, warn};
use spin::Mutex;
use userlib;
use zero_abi::bootfs::UserBootFile;
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::fs as fs_proto;
use zero_abi::protocol::fs::vtable as vt;
use zero_abi::syscall::SysError;
use zero_zfs_core::{DeviceError, MountOptions, SnapshotInfo, Volume, ZfsError};

const STATUS_OK: u32 = 0;
const MAX_PATH: usize = 112;
static VOLUME: Mutex<Option<Volume<blockdev::BlockServiceDevice>>> = Mutex::new(None);
static SNAPSHOT_QUEUE: Mutex<HeaplessVec<SnapshotSchedule, 8>> = Mutex::new(HeaplessVec::new());
const MAX_DESCRIPTORS: usize = 16;
static OPEN_FILES: Mutex<[Option<OpenFile>; MAX_DESCRIPTORS]> =
    Mutex::new([const { None }; MAX_DESCRIPTORS]);
static NEXT_DESCRIPTOR: AtomicU32 = AtomicU32::new(1);
/// Current request sender. zfsd is single-threaded, so one atomic slot is enough
/// to make every legacy `respond(...)` call targeted without threading sender
/// through ~80 handlers. A targeted envelope cannot be stolen by another FS client.
static REPLY_TARGET: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct SnapshotSchedule {
    label: String,
    include_bootstrap: bool,
}

#[derive(Clone)]
struct OpenFile {
    id: u32,
    path: String,
    offset: usize,
}

#[derive(Debug)]
enum ServerError {
    NotMounted,
    Fs(ZfsError),
    Block(libblkclient::Error),
    Shared(SysError),
}

impl From<ZfsError> for ServerError {
    fn from(value: ZfsError) -> Self {
        ServerError::Fs(value)
    }
}

impl From<libblkclient::Error> for ServerError {
    fn from(value: libblkclient::Error) -> Self {
        ServerError::Block(value)
    }
}

pub fn server_main(boot_files: &[UserBootFile]) -> ! {
    mount_root_volume(boot_files);
    if VOLUME.lock().is_some() {
        let _ = userlib::console_write(b"Zero OS zfsd (default fsd) online\r\n");
    } else {
        let _ = userlib::console_write(b"Zero OS zfsd mount FAILED\r\n");
    }
    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive_from(channels::FS_REQ, &mut message) {
            Ok(sender) => {
                REPLY_TARGET.store(sender, Ordering::Release);
                handle_request(&message);
                REPLY_TARGET.store(0, Ordering::Release);
            }
            Err(SysError::ChannelUnavailable | SysError::WouldBlock) => userlib::yield_now(),
            Err(err) => {
                // No valid requester exists on a receive failure, so broadcasting
                // an ERR_DEVICE response would itself corrupt another client's RPC.
                warn!("zfs: IPC receive error {:?}", err);
                userlib::yield_now();
            }
        }
        process_snapshot_queue();
    }
}

fn mount_root_volume(boot_files: &[UserBootFile]) {
    info!("zfs: mounting root volume");
    let device = match blockdev::BlockServiceDevice::open_default() {
        Ok(device) => device,
        Err(err) => {
            error!("zfs: no block device available: {:?}", err);
            return;
        }
    };
    let mut mount_options = MountOptions::default();
    // Cross-subsystem raw regions must never enter the ZFS allocator:
    // - kernel virtio-blk power-on self-test uses sector 2048 => 4KiB block 256;
    // - securityd legacy userdb uses sectors 4096..=4104 => blocks 512/513;
    // - the final 4KiB block is the shell's raw `blktest` diagnostic sandbox.
    //   The shell derives its LBA from BlockCapacity, so this remains correct
    //   for any disk size rather than assuming the old 32MiB/60000 layout.
    mount_options
        .reserved_blocks
        .extend_from_slice(&[256, 512, 513]);
    if let Some(last) = device.logical_blocks().checked_sub(1) {
        mount_options.reserved_blocks.push(last);
    }
    let mut volume = match Volume::mount(device, mount_options) {
        Ok(volume) => volume,
        Err(err) => {
            error!("zfs: failed to mount volume: {:?}", err);
            return;
        }
    };

    let needs_bootstrap = volume.directory_index().get("/.zero-bootstrap").is_none();
    if needs_bootstrap {
        import_bootstrap_from_user(boot_files, &mut volume);
    } else {
        info!("zfs: existing filesystem detected, skipping bootstrap import");
    }

    *VOLUME.lock() = Some(volume);
}

fn import_bootstrap_from_user(
    files: &[UserBootFile],
    volume: &mut Volume<blockdev::BlockServiceDevice>,
) {
    if files.is_empty() {
        warn!("zfs: no bootstrap entries bundled");
        return;
    }
    let mut imported = 0usize;
    for file in files {
        let path = unsafe {
            let p = file.path_ptr as *const u8;
            let s = slice::from_raw_parts(p, file.path_len as usize);
            str::from_utf8_unchecked(s)
        };
        // Bootfs executables are already immutable boot assets. Persist only
        // configuration/static data; package/application payloads enter this
        // volume through the normal FS API after boot.
        if path.starts_with("/System/Core/") || path == "/Applications/Shell" {
            continue;
        }
        let data =
            unsafe { slice::from_raw_parts(file.data_ptr as *const u8, file.data_len as usize) };
        match volume.import_file(path, data) {
            Ok(_) => imported += 1,
            Err(err) => warn!("zfs: failed to import {}: {:?}", path, err),
        }
    }
    if volume
        .import_file("/.zero-bootstrap", b"zfs-runtime-v1\n")
        .is_ok()
    {
        imported += 1;
    }
    info!("zfs: imported {} persistent bootstrap files", imported);
}

fn build_device_list_payload() -> Result<([u8; 128], usize), ServerError> {
    let devices = blockdev::enumerate_devices()?;
    const RECORD_LEN: usize = 14;
    let mut payload = [0u8; 128];
    let mut offset = 1usize;
    let mut count = 0u8;
    for info in devices.iter() {
        if offset + RECORD_LEN > payload.len() {
            break;
        }
        payload[offset] = info.index;
        payload[offset + 1] = info.device_type;
        payload[offset + 2..offset + 6].copy_from_slice(&info.block_size.to_le_bytes());
        payload[offset + 6..offset + 14].copy_from_slice(&info.capacity_blocks.to_le_bytes());
        offset += RECORD_LEN;
        count = count.saturating_add(1);
    }
    payload[0] = count;
    Ok((payload, offset))
}

fn install_on_device(index: u8) -> Result<(), ServerError> {
    let device = blockdev::BlockServiceDevice::open_index(index)?;
    device.zero_prefix(32)?;
    let mut volume = Volume::mount(device, MountOptions::default()).map_err(ServerError::from)?;
    import_bootstrap_from_user(&[], &mut volume);
    *VOLUME.lock() = Some(volume);
    Ok(())
}

fn handle_request(message: &Message) {
    match message.code {
        vt::CMD_OPEN => handle_vt_open(message),
        vt::CMD_WRITE => handle_vt_write(message),
        vt::CMD_READ => handle_read(message),
        vt::CMD_READ_SIZED => handle_read_sized(message),
        vt::CMD_READ_SHARED => handle_read_shared(message),
        vt::CMD_CLOSE => handle_close(message),
        vt::CMD_LIST => handle_vt_list(message),
        vt::CMD_MKDIR => handle_mkdir(message),
        vt::CMD_RMDIR => handle_rmdir(message),
        vt::CMD_UNLINK => handle_delete(message),
        vt::CMD_RENAME => handle_rename(message),
        fs_proto::CMD_OPEN => handle_open(message),
        fs_proto::CMD_READ => handle_read(message),
        fs_proto::CMD_CLOSE => handle_close(message),
        fs_proto::CMD_LIST => handle_vt_list(message),
        fs_proto::CMD_WRITE_FILE => handle_write(message),
        fs_proto::CMD_WRITE_SHARED => handle_write_shared(message),
        fs_proto::CMD_DELETE_FILE => handle_delete(message),
        fs_proto::CMD_INSTALL_BUNDLE => handle_install_bundle(message),
        fs_proto::CMD_SNAPSHOT => handle_snapshot_request(message),
        fs_proto::CMD_SNAPSHOT_SCHEDULE => handle_snapshot_schedule(message),
        fs_proto::CMD_LIST_DEVICES => handle_list_devices(),
        fs_proto::CMD_INSTALL_DEVICE => handle_install_device(message),
        _ => respond(fs_proto::ERR_INVALID, &[]),
    }
}

fn respond(status: u32, payload: &[u8]) {
    let target = REPLY_TARGET.load(Ordering::Acquire);
    if target == 0 {
        warn!(
            "zfs: refusing response without request target status={}",
            status
        );
        return;
    }
    let mut response = Message::empty();
    response.code = status;
    let copy_len = payload.len().min(response.payload.len());
    response.payload[..copy_len].copy_from_slice(&payload[..copy_len]);
    let _ = userlib::ipc_send_to(channels::FS_RESP, target, &response);
}

fn handle_open(message: &Message) {
    let Some(raw) = extract_path(&message.payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let Some(path) = canonical_path(raw) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    match with_volume(|volume| volume.file_size(path.as_str()).map(|_| ())) {
        Ok(()) => match allocate_handle(path.as_str()) {
            Some(id) => respond(STATUS_OK, &id.to_le_bytes()),
            None => respond(fs_proto::ERR_INVALID, &[]),
        },
        Err(err) => respond(map_error(err), &[]),
    }
}

fn parse_vt_open(payload: &[u8; 128]) -> Option<(&str, u8)> {
    let end = payload.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    let path = str::from_utf8(&payload[..end]).ok()?;
    let mode = payload.get(end + 1).copied().unwrap_or(vt::OPEN_EXISTING);
    if mode != vt::OPEN_EXISTING && mode != vt::OPEN_CREATE {
        return None;
    }
    Some((path, mode))
}

fn handle_vt_open(message: &Message) {
    let Some((raw, mode)) = parse_vt_open(&message.payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let Some(path) = canonical_path(raw) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let result = with_volume(|volume| match volume.file_size(path.as_str()) {
        Ok(_) => Ok(()),
        Err(ZfsError::NotFound) if mode == vt::OPEN_CREATE => {
            let parent = parent_path(path.as_str());
            if parent != "/" {
                let Some(e) = volume.directory_index().get(parent) else {
                    return Err(ZfsError::NotFound);
                };
                if e.kind() != zero_zfs_core::on_disk::InodeKind::Directory {
                    return Err(ZfsError::NotFound);
                }
            }
            volume.write_file(path.as_str(), &[], None)?;
            Ok(())
        }
        Err(e) => Err(e),
    });
    match result {
        Ok(()) => match allocate_handle(path.as_str()) {
            Some(id) => respond(STATUS_OK, &id.to_le_bytes()),
            None => respond(fs_proto::ERR_NO_DESCRIPTOR, &[]),
        },
        Err(err) => respond(map_error(err), &[]),
    }
}

fn handle_vt_write(message: &Message) {
    let fd = u32::from_le_bytes(message.payload[0..4].try_into().unwrap_or([0; 4]));
    let len = u32::from_le_bytes(message.payload[4..8].try_into().unwrap_or([0; 4])) as usize;
    if len == 0 || len > 120 || 8 + len > message.payload.len() {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let (path, offset) = {
        let table = OPEN_FILES.lock();
        let Some(h) = table.iter().flatten().find(|h| h.id == fd) else {
            respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
            return;
        };
        (h.path.clone(), h.offset)
    };
    let end = match offset.checked_add(len) {
        Some(v) => v,
        None => {
            respond(fs_proto::ERR_INVALID, &[]);
            return;
        }
    };
    let mut data = Vec::new();
    if let Err(err) = with_volume(|v| v.read_file(path.as_str(), &mut data)) {
        respond(map_error(err), &[]);
        return;
    }
    if data.len() < end {
        data.resize(end, 0)
    }
    data[offset..end].copy_from_slice(&message.payload[8..8 + len]);
    if let Err(err) = with_volume(|v| v.write_file(path.as_str(), &data, None)) {
        respond(map_error(err), &[]);
        return;
    }
    let mut table = OPEN_FILES.lock();
    if let Some(h) = table.iter_mut().flatten().find(|h| h.id == fd) {
        h.offset = end;
    }
    respond(STATUS_OK, &(len as u32).to_le_bytes());
}

fn parent_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &trimmed[..i],
    }
}
fn base_name(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or("")
}

/// FS wire contract accepts root-relative and absolute paths. Canonicalize at
/// the service boundary so the ZFS core only ever sees one namespace form and
/// traversal can never reach DirectoryIndex as a literal key.
fn canonical_path(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.starts_with("//") {
        return None;
    }
    if raw == "/" {
        return Some(String::from("/"));
    }
    let body = raw.trim_matches('/');
    if body.is_empty() {
        return Some(String::from("/"));
    }
    let mut out = String::from("/");
    for (i, part) in body.split('/').enumerate() {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
        if i != 0 {
            out.push('/');
        }
        out.push_str(part);
        if out.len() > MAX_PATH {
            return None;
        }
    }
    Some(out)
}

fn handle_vt_list(message: &Message) {
    let raw = extract_list_filter(&message.payload).unwrap_or("");
    let Some(dir) = canonical_path(if raw.is_empty() { "/" } else { raw }) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let result = with_volume(|volume| {
        if dir.as_str() != "/" {
            let Some(e) = volume.directory_index().get(dir.as_str()) else {
                return Err(ZfsError::NotFound);
            };
            if e.kind() != zero_zfs_core::on_disk::InodeKind::Directory {
                return Err(ZfsError::NotFound);
            }
        }
        let snap = volume.directory_index().snapshot();
        let prefix = if dir.as_str() == "/" {
            String::from("/")
        } else {
            let mut p = String::from(dir.as_str().trim_end_matches('/'));
            p.push('/');
            p
        };
        let mut out = [0u8; 128];
        let mut off = 0usize;
        for (path, entry) in snap.iter() {
            if !path.starts_with(&prefix) {
                continue;
            }
            let rest = &path[prefix.len()..];
            if rest.is_empty() || rest.contains('/') {
                continue;
            }
            let name = base_name(path);
            let extra = usize::from(entry.kind() == zero_zfs_core::on_disk::InodeKind::Directory);
            if off + name.len() + extra + 1 >= out.len() {
                break;
            }
            out[off..off + name.len()].copy_from_slice(name.as_bytes());
            off += name.len();
            if extra == 1 {
                out[off] = b'/';
                off += 1;
            }
            out[off] = b'\n';
            off += 1;
        }
        Ok((out, off))
    });
    match result {
        Ok((out, n)) => respond(STATUS_OK, &out[..n]),
        Err(e) => respond(map_error(e), &[]),
    }
}

fn handle_mkdir(message: &Message) {
    let Some(raw) = extract_path(&message.payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let Some(path) = canonical_path(raw) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let result = with_volume(|v| {
        let parent = parent_path(path.as_str());
        if parent != "/" {
            let Some(e) = v.directory_index().get(parent) else {
                return Err(ZfsError::NotFound);
            };
            if e.kind() != zero_zfs_core::on_disk::InodeKind::Directory {
                return Err(ZfsError::NotFound);
            }
        }
        v.create_dir(path.as_str())
    });
    match result {
        Ok(()) => respond(STATUS_OK, &[]),
        Err(e) => respond(map_error(e), &[]),
    }
}
fn handle_rmdir(message: &Message) {
    let Some(raw) = extract_path(&message.payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let Some(path) = canonical_path(raw) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    match with_volume(|v| v.remove_dir(path.as_str())) {
        Ok(()) => respond(STATUS_OK, &[]),
        Err(e) => respond(map_error(e), &[]),
    }
}
fn handle_rename(message: &Message) {
    let first = match message.payload.iter().position(|&b| b == 0) {
        Some(v) => v,
        None => {
            respond(fs_proto::ERR_INVALID, &[]);
            return;
        }
    };
    let rest = &message.payload[first + 1..];
    let second = match rest.iter().position(|&b| b == 0) {
        Some(v) => v,
        None => {
            respond(fs_proto::ERR_INVALID, &[]);
            return;
        }
    };
    let Some(old_raw) = str::from_utf8(&message.payload[..first]).ok() else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let Some(new_raw) = str::from_utf8(&rest[..second]).ok() else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let Some(old) = canonical_path(old_raw) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let Some(new) = canonical_path(new_raw) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let result = with_volume(|v| {
        let parent = parent_path(new.as_str());
        if parent != "/" {
            let Some(e) = v.directory_index().get(parent) else {
                return Err(ZfsError::NotFound);
            };
            if e.kind() != zero_zfs_core::on_disk::InodeKind::Directory {
                return Err(ZfsError::NotFound);
            }
        }
        v.rename_path(old.as_str(), new.as_str())
    });
    if result.is_ok() {
        let mut table = OPEN_FILES.lock();
        for h in table.iter_mut().flatten() {
            if h.path == old.as_str() {
                h.path = new.clone();
            }
        }
    }
    match result {
        Ok(()) => respond(STATUS_OK, &[]),
        Err(e) => respond(map_error(e), &[]),
    }
}

fn handle_read_sized(message: &Message) {
    let id = u32::from_le_bytes(message.payload[0..4].try_into().unwrap_or([0; 4]));
    let requested = u32::from_le_bytes(message.payload[4..8].try_into().unwrap_or([0; 4])) as usize;
    if requested == 0 || requested > 124 {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let (path, offset) = {
        let table = OPEN_FILES.lock();
        let Some(h) = table.iter().flatten().find(|h| h.id == id) else {
            respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
            return;
        };
        (h.path.clone(), h.offset)
    };
    let mut out = [0u8; 128];
    let n = match with_volume(|v| v.read_file_at(path.as_str(), offset, &mut out[4..4 + requested]))
    {
        Ok(n) => n,
        Err(e) => {
            respond(map_error(e), &[]);
            return;
        }
    };
    out[..4].copy_from_slice(&(n as u32).to_le_bytes());
    {
        let mut table = OPEN_FILES.lock();
        if let Some(h) = table.iter_mut().flatten().find(|h| h.id == id) {
            h.offset = offset + n;
        }
    }
    respond(STATUS_OK, &out[..4 + n]);
}

fn handle_read_shared(message: &Message) {
    let id = u32::from_le_bytes(message.payload[0..4].try_into().unwrap_or([0; 4]));
    let shm_handle = u32::from_le_bytes(message.payload[4..8].try_into().unwrap_or([0; 4]));
    let requested =
        u32::from_le_bytes(message.payload[8..12].try_into().unwrap_or([0; 4])) as usize;
    if requested == 0 {
        let _ = userlib::shm_release(shm_handle);
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let result = (|| -> Result<usize, ServerError> {
        let available = userlib::shm_len(shm_handle).map_err(ServerError::Shared)?;
        let cap = core::cmp::min(requested, available);
        let ptr = userlib::shm_map(shm_handle).map_err(ServerError::Shared)?;
        if ptr.is_null() {
            return Err(ServerError::Shared(SysError::InvalidArgument));
        }
        let (path, offset) = {
            let table = OPEN_FILES.lock();
            let h = table
                .iter()
                .flatten()
                .find(|h| h.id == id)
                .ok_or(ServerError::Fs(ZfsError::NotFound))?;
            (h.path.clone(), h.offset)
        };
        let dst = unsafe { slice::from_raw_parts_mut(ptr, cap) };
        let n = with_volume(|v| v.read_file_at(path.as_str(), offset, dst))?;
        let mut table = OPEN_FILES.lock();
        if let Some(h) = table.iter_mut().flatten().find(|h| h.id == id) {
            h.offset = offset + n;
        }
        Ok(n)
    })();
    let _ = userlib::shm_release(shm_handle);
    match result {
        Ok(n) => respond(STATUS_OK, &(n as u32).to_le_bytes()),
        Err(ServerError::Fs(ZfsError::NotFound)) => respond(fs_proto::ERR_NO_DESCRIPTOR, &[]),
        Err(e) => respond(map_error(e), &[]),
    }
}

fn handle_read(message: &Message) {
    let id = u32::from_le_bytes(message.payload[0..4].try_into().unwrap_or([0; 4]));
    let requested = u32::from_le_bytes(message.payload[4..8].try_into().unwrap_or([0; 4])) as usize;
    let cap = requested.min(128);
    let (path, offset) = {
        let table = OPEN_FILES.lock();
        let Some(h) = table.iter().flatten().find(|h| h.id == id) else {
            respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
            return;
        };
        (h.path.clone(), h.offset)
    };
    let mut out = [0u8; 128];
    let n = match with_volume(|v| v.read_file_at(path.as_str(), offset, &mut out[..cap])) {
        Ok(n) => n,
        Err(e) => {
            respond(map_error(e), &[]);
            return;
        }
    };
    {
        let mut table = OPEN_FILES.lock();
        if let Some(h) = table.iter_mut().flatten().find(|h| h.id == id) {
            h.offset = offset + n;
        }
    }
    respond(STATUS_OK, &out[..n]);
}

fn handle_close(message: &Message) {
    if message.payload.len() < 4 {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let mut id_bytes = [0u8; 4];
    id_bytes.copy_from_slice(&message.payload[..4]);
    let id = u32::from_le_bytes(id_bytes);
    let mut table = OPEN_FILES.lock();
    if let Some(slot) = table.iter_mut().find(|entry| {
        entry
            .as_ref()
            .map(|handle| handle.id == id)
            .unwrap_or(false)
    }) {
        *slot = None;
        respond(STATUS_OK, &[]);
    } else {
        respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
    }
}

fn handle_list(message: &Message) {
    let Some(filter) = extract_list_filter(&message.payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    match with_volume(|volume| {
        let snapshot = volume.directory_index().snapshot();
        let mut names = Vec::new();
        for key in snapshot.keys() {
            if filter.is_empty() || key.starts_with(filter) {
                names.push(key.clone());
            }
        }
        Ok(names)
    }) {
        Ok(entries) => {
            let mut buffer = [0u8; 128];
            let mut offset = 0usize;
            for name in entries {
                let bytes = name.as_bytes();
                if offset + bytes.len() + 1 > buffer.len() {
                    break;
                }
                buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
                offset += bytes.len();
                buffer[offset] = b'\n';
                offset += 1;
            }
            respond(STATUS_OK, &buffer[..offset]);
        }
        Err(err) => respond(map_error(err), &[]),
    }
}

fn handle_write(message: &Message) {
    match parse_write_payload(&message.payload) {
        Some((raw, data, _signature)) => {
            let Some(path) = canonical_path(raw) else {
                respond(fs_proto::ERR_INVALID, &[]);
                return;
            };
            let result = with_volume(|volume| volume.write_file(path.as_str(), data, None));
            match result {
                Ok(_) => respond(STATUS_OK, &[]),
                Err(err) => respond(map_error(err), &[]),
            }
        }
        None => respond(fs_proto::ERR_INVALID, &[]),
    }
}

fn handle_write_shared(message: &Message) {
    match parse_shared_write(&message.payload) {
        Some(req) => {
            let result = match read_shared_slice(req.handle, req.length) {
                Ok(view) => with_volume(|volume| unsafe {
                    let slice = slice::from_raw_parts(view.ptr, view.len);
                    volume.write_file(req.path.as_str(), slice, None)
                }),
                Err(err) => Err(err),
            };
            // The client granted one holder reference specifically for this
            // transaction. Drop it after the copy/commit so the service never
            // keeps foreign application buffers mapped indefinitely.
            let _ = userlib::shm_release(req.handle);
            match result {
                Ok(_) => respond(STATUS_OK, &[]),
                Err(err) => respond(map_error(err), &[]),
            }
        }
        None => respond(fs_proto::ERR_INVALID, &[]),
    }
}

fn handle_delete(message: &Message) {
    let Some(raw) = extract_path(&message.payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    let Some(path) = canonical_path(raw) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    match with_volume(|volume| volume.remove_file(path.as_str())) {
        Ok(_) => respond(STATUS_OK, &[]),
        Err(err) => respond(map_error(err), &[]),
    }
}

fn handle_install_bundle(message: &Message) {
    match parse_write_payload(&message.payload) {
        Some((raw, data, Some(signature))) => {
            let Some(path) = canonical_path(raw) else {
                respond(fs_proto::ERR_INVALID, &[]);
                return;
            };
            let result =
                with_volume(|volume| volume.write_file(path.as_str(), data, Some(signature)));
            match result {
                Ok(_) => respond(STATUS_OK, &[]),
                Err(err) => respond(map_error(err), &[]),
            }
        }
        Some((_path, _data, None)) => respond(fs_proto::ERR_INVALID, &[]),
        None => respond(fs_proto::ERR_INVALID, &[]),
    }
}

fn handle_snapshot_request(message: &Message) {
    match handle_snapshot(&message.payload) {
        Ok(buffer) => respond(STATUS_OK, &buffer),
        Err(err) => respond(map_error(err), &[]),
    }
}

fn handle_snapshot_schedule(message: &Message) {
    if schedule_snapshot(&message.payload) {
        respond(STATUS_OK, &[]);
    } else {
        respond(fs_proto::ERR_INVALID, &[]);
    }
}

fn handle_list_devices() {
    match build_device_list_payload() {
        Ok((payload, len)) => respond(STATUS_OK, &payload[..len]),
        Err(err) => respond(map_error(err), &[]),
    }
}

fn handle_install_device(message: &Message) {
    match message.payload.first().copied() {
        Some(index) => match install_on_device(index) {
            Ok(_) => respond(STATUS_OK, &[]),
            Err(err) => respond(map_error(err), &[]),
        },
        None => respond(fs_proto::ERR_INVALID, &[]),
    }
}

fn allocate_handle(path: &str) -> Option<u32> {
    let mut table = OPEN_FILES.lock();
    if let Some(slot) = table.iter_mut().find(|entry| entry.is_none()) {
        let id = NEXT_DESCRIPTOR.fetch_add(1, Ordering::SeqCst);
        *slot = Some(OpenFile {
            id,
            path: String::from(path),
            offset: 0,
        });
        Some(id)
    } else {
        None
    }
}

fn handle_snapshot(payload: &[u8]) -> Result<[u8; 128], ServerError> {
    if payload.is_empty() {
        return Err(ServerError::Fs(ZfsError::InvalidSuperblock));
    }
    let mut out = [0u8; 128];
    match payload[0] {
        0 => {
            // create snapshot, label after flag as UTF-8 string
            let label = if payload.len() > 1 {
                let label_bytes = &payload[1..];
                let label_len = label_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(label_bytes.len());
                core::str::from_utf8(&label_bytes[..label_len]).unwrap_or("snapshot")
            } else {
                "snapshot"
            };
            let snapshot = with_volume(|volume| volume.create_snapshot(label))?;
            out[..8].copy_from_slice(&snapshot.id.to_le_bytes());
            out[8..16].copy_from_slice(&snapshot.logical_time.to_le_bytes());
            let label_bytes = snapshot.label.as_bytes();
            let copy_len = core::cmp::min(label_bytes.len(), out.len() - 16);
            out[16..16 + copy_len].copy_from_slice(&label_bytes[..copy_len]);
        }
        1 => {
            with_volume(|volume| {
                let mut snapshots = Vec::new();
                volume.list_snapshots(&mut snapshots);
                encode_snapshot_list(&snapshots, &mut out);
                Ok(())
            })?;
        }
        2 => {
            if payload.len() < 9 {
                return Err(ServerError::Fs(ZfsError::InvalidArgument));
            }
            let mut id_bytes = [0u8; 8];
            id_bytes.copy_from_slice(&payload[1..9]);
            let id = u64::from_le_bytes(id_bytes);
            with_volume(|volume| volume.restore_snapshot(id))?;
        }
        _ => return Err(ServerError::Fs(ZfsError::InvalidArgument)),
    }
    Ok(out)
}

fn schedule_snapshot(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let label_len = payload[0] as usize;
    if label_len == 0 || 1 + label_len > payload.len() {
        return false;
    }
    let label_bytes = &payload[1..1 + label_len];
    let include_bootstrap = payload.get(1 + label_len).copied().unwrap_or(0) != 0;
    let label = match core::str::from_utf8(label_bytes) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let mut queue = SNAPSHOT_QUEUE.lock();
    if queue.iter().any(|entry| entry.label.as_str() == label) {
        return true;
    }
    let entry = SnapshotSchedule {
        label: String::from(label),
        include_bootstrap,
    };
    queue.push(entry).is_ok()
}

fn process_snapshot_queue() {
    let mut queue = SNAPSHOT_QUEUE.lock();
    if let Some(schedule) = queue.pop() {
        info!(
            "zfs: executing scheduled snapshot {} (bootstrap={})",
            schedule.label, schedule.include_bootstrap
        );
        let label = schedule.label.clone();
        if let Err(err) = with_volume(|volume| volume.create_snapshot(label.as_str())) {
            warn!("zfs: scheduled snapshot failed: {:?}", err);
        }
    }
}

fn encode_snapshot_list(list: &[SnapshotInfo], out: &mut [u8; 128]) {
    out.fill(0);
    let mut offset = 0usize;
    for info in list.iter().take(4) {
        if offset + 24 > out.len() {
            break;
        }
        out[offset..offset + 8].copy_from_slice(&info.id.to_le_bytes());
        out[offset + 8..offset + 16].copy_from_slice(&info.logical_time.to_le_bytes());
        out[offset + 16..offset + 24].copy_from_slice(&info.free_blocks.to_le_bytes());
        offset += 24;
    }
}

fn extract_path(payload: &[u8; 128]) -> Option<&str> {
    let len = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    if len == 0 {
        return None;
    }
    str::from_utf8(&payload[..len]).ok()
}

fn extract_list_filter(payload: &[u8; 128]) -> Option<&str> {
    let len = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    if len == 0 {
        Some("")
    } else {
        str::from_utf8(&payload[..len]).ok()
    }
}

fn parse_write_payload(payload: &[u8; 128]) -> Option<(&str, &[u8], Option<&[u8]>)> {
    if payload.len() < 3 {
        return None;
    }
    let path_len = payload[0] as usize;
    let data_len = payload[1] as usize;
    let has_signature = payload[2] != 0;
    let mut offset = 3;
    if path_len == 0 || offset + path_len > payload.len() {
        return None;
    }
    let path = str::from_utf8(&payload[offset..offset + path_len]).ok()?;
    offset += path_len;
    if offset + data_len > payload.len() {
        return None;
    }
    let data = &payload[offset..offset + data_len];
    offset += data_len;
    let signature = if has_signature {
        if offset + 32 > payload.len() {
            return None;
        }
        Some(&payload[offset..offset + 32])
    } else {
        None
    };
    Some((path, data, signature))
}

fn parse_shared_write(payload: &[u8; 128]) -> Option<SharedWriteRequest> {
    if payload.is_empty() {
        return None;
    }
    let path_len = payload[0] as usize;
    let mut offset = 1usize;
    if path_len == 0 || offset + path_len > payload.len() {
        return None;
    }
    let raw_path = core::str::from_utf8(&payload[offset..offset + path_len]).ok()?;
    offset += path_len;
    if offset + 8 > payload.len() {
        return None;
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&payload[offset..offset + 4]);
    offset += 4;
    let mut handle_bytes = [0u8; 4];
    handle_bytes.copy_from_slice(&payload[offset..offset + 4]);
    let length = u32::from_le_bytes(len_bytes) as usize;
    let handle = u32::from_le_bytes(handle_bytes);
    if length == 0 {
        return None;
    }
    let canonical = canonical_path(raw_path)?;
    let mut path = HeaplessString::<MAX_PATH>::new();
    path.push_str(canonical.as_str()).ok()?;
    Some(SharedWriteRequest {
        path,
        handle,
        length,
    })
}

struct SharedWriteRequest {
    path: HeaplessString<MAX_PATH>,
    handle: u32,
    length: usize,
}

struct SharedSliceView {
    ptr: *const u8,
    len: usize,
}

fn read_shared_slice(handle: u32, len: usize) -> Result<SharedSliceView, ServerError> {
    let available = userlib::shm_len(handle).map_err(ServerError::Shared)?;
    if len > available {
        return Err(ServerError::Shared(SysError::InvalidArgument));
    }
    let ptr = userlib::shm_map(handle).map_err(ServerError::Shared)?;
    if ptr.is_null() {
        return Err(ServerError::Shared(SysError::InvalidArgument));
    }
    Ok(SharedSliceView { ptr, len })
}

fn with_volume<F, R>(f: F) -> Result<R, ServerError>
where
    F: FnOnce(&mut Volume<blockdev::BlockServiceDevice>) -> Result<R, ZfsError>,
{
    let mut guard = VOLUME.lock();
    let volume = guard.as_mut().ok_or(ServerError::NotMounted)?;
    f(volume).map_err(ServerError::from)
}

fn map_error(err: ServerError) -> u32 {
    match err {
        ServerError::NotMounted => fs_proto::ERR_INVALID,
        ServerError::Fs(ZfsError::NotFound) => fs_proto::ERR_NOT_FOUND,
        ServerError::Fs(ZfsError::SignatureMismatch) => fs_proto::ERR_INVALID,
        ServerError::Fs(ZfsError::Device(DeviceError::Io)) => fs_proto::ERR_DEVICE,
        ServerError::Fs(ZfsError::Device(DeviceError::OutOfBounds)) => fs_proto::ERR_DEVICE,
        ServerError::Fs(ZfsError::SnapshotNotFound) => fs_proto::ERR_NOT_FOUND,
        ServerError::Fs(ZfsError::Unsupported) => fs_proto::ERR_INVALID,
        ServerError::Fs(ZfsError::InvalidArgument) => fs_proto::ERR_INVALID,
        ServerError::Fs(err) => {
            warn!("zfs: fs error {:?}", err);
            fs_proto::ERR_INVALID
        }
        ServerError::Block(err) => {
            warn!("zfs: block device error {:?}", err);
            fs_proto::ERR_DEVICE
        }
        ServerError::Shared(err) => {
            warn!("zfs: shared memory error {:?}", err);
            fs_proto::ERR_INVALID
        }
    }
}

mod blockdev {
    use heapless::Vec as HeaplessVec;
    use libblkclient::{self, DeviceInfo};
    use log::info;
    use userlib::{block_capacity_sectors, block_read, block_write};
    use zero_zfs_core::device::{BlockDevice, DeviceError};

    const MAX_DEVICES: usize = 8;

    pub fn enumerate_devices() -> Result<HeaplessVec<DeviceInfo, MAX_DEVICES>, libblkclient::Error>
    {
        let mut infos = [DeviceInfo::default(); MAX_DEVICES];
        let count = libblkclient::enumerate_devices(&mut infos)?;
        let mut out = HeaplessVec::new();
        for info in infos.iter().take(count) {
            let _ = out.push(*info);
        }
        Ok(out)
    }

    pub struct BlockServiceDevice {
        index: u8,
        sectors_per_block: u32,
        logical_blocks: u64,
    }

    impl BlockServiceDevice {
        pub fn open_default() -> Result<Self, libblkclient::Error> {
            // Root ZFS is a trusted system service. The kernel remains the sole
            // virtio-blk owner; zfsd merely invokes the same serialized block
            // syscalls as securityd. This avoids ~40 IPC messages per 4KiB
            // block while preserving the single hardware-owner invariant.
            let capacity_sectors = block_capacity_sectors().map_err(libblkclient::Error::Ipc)?;
            if capacity_sectors == 0 {
                return Err(libblkclient::Error::NoDevice);
            }
            let sectors_per_block = (Self::BLOCK_SIZE / 512) as u32;
            info!(
                "zfs: selected kernel block device idx=0 block=512 capacity={} sectors",
                capacity_sectors
            );
            Ok(Self {
                index: 0,
                sectors_per_block,
                logical_blocks: capacity_sectors / sectors_per_block as u64,
            })
        }

        pub fn open_index(index: u8) -> Result<Self, libblkclient::Error> {
            if index == 0 {
                return Self::open_default();
            }
            let info = libblkclient::device_info(index)?;
            Self::from_info(&info)
        }

        fn from_info(info: &DeviceInfo) -> Result<Self, libblkclient::Error> {
            let block_bytes = info.block_size as usize;
            if block_bytes == 0 || Self::BLOCK_SIZE % block_bytes != 0 {
                return Err(libblkclient::Error::InvalidResponse);
            }
            let sectors_per_block = (Self::BLOCK_SIZE / block_bytes) as u32;
            info!(
                "zfs: selected block device idx={} type={} block={} capacity={} blocks",
                info.index, info.device_type, info.block_size, info.capacity_blocks
            );
            Ok(Self {
                index: info.index,
                sectors_per_block,
                logical_blocks: info.capacity_blocks / sectors_per_block as u64,
            })
        }

        pub fn zero_prefix(&self, blocks: usize) -> Result<(), libblkclient::Error> {
            let zero = [0u8; Self::BLOCK_SIZE];
            for block in 0..blocks {
                block_write(self.hw_lba(block as u64), &zero).map_err(libblkclient::Error::Ipc)?;
            }
            Ok(())
        }

        pub fn logical_blocks(&self) -> u64 {
            self.logical_blocks
        }

        fn hw_lba(&self, logical_block: u64) -> u64 {
            logical_block * self.sectors_per_block as u64
        }
    }

    impl Clone for BlockServiceDevice {
        fn clone(&self) -> Self {
            Self {
                index: self.index,
                sectors_per_block: self.sectors_per_block,
                logical_blocks: self.logical_blocks,
            }
        }
    }

    impl BlockDevice for BlockServiceDevice {
        const BLOCK_SIZE: usize = 4096;

        fn block_count(&self) -> Option<u64> {
            Some(self.logical_blocks)
        }

        fn read_block(&self, lba: u64, buffer: &mut [u8]) -> Result<(), DeviceError> {
            if buffer.len() != Self::BLOCK_SIZE {
                return Err(DeviceError::Unsupported);
            }
            block_read(self.hw_lba(lba), buffer).map_err(map_sys_error)
        }

        fn write_block(&self, lba: u64, buffer: &[u8]) -> Result<(), DeviceError> {
            if buffer.len() != Self::BLOCK_SIZE {
                return Err(DeviceError::Unsupported);
            }
            block_write(self.hw_lba(lba), buffer).map_err(map_sys_error)
        }
    }

    fn map_sys_error(err: zero_abi::syscall::SysError) -> DeviceError {
        match err {
            zero_abi::syscall::SysError::InvalidArgument => DeviceError::Unsupported,
            _ => DeviceError::Io,
        }
    }
}
