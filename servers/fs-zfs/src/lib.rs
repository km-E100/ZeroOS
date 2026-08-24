#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::str;
use core::sync::atomic::{AtomicU32, Ordering};

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

#[derive(Clone)]
struct SnapshotSchedule {
    label: String,
    include_bootstrap: bool,
}

#[derive(Clone)]
struct OpenFile {
    id: u32,
    data: Vec<u8>,
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
    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive(channels::FS_REQ, &mut message) {
            Ok(_) => handle_request(&message),
            Err(SysError::ChannelUnavailable) => userlib::yield_now(),
            Err(err) => {
                warn!("zfs: IPC receive error {:?}", err);
                respond(fs_proto::ERR_DEVICE, &[]);
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
    let mut volume = match Volume::mount(device, MountOptions::default()) {
        Ok(volume) => volume,
        Err(err) => {
            error!("zfs: failed to mount volume: {:?}", err);
            return;
        }
    };

    let needs_bootstrap = volume
        .directory_index()
        .get("/System/Core/zero-launchd")
        .is_none();
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
        let data =
            unsafe { slice::from_raw_parts(file.data_ptr as *const u8, file.data_len as usize) };
        match volume.import_file(path, data) {
            Ok(_) => imported += 1,
            Err(err) => warn!("zfs: failed to import {}: {:?}", path, err),
        }
    }
    info!("zfs: imported {} bootstrap files", imported);
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
        fs_proto::CMD_OPEN => handle_open(message),
        fs_proto::CMD_READ => handle_read(message),
        fs_proto::CMD_CLOSE => handle_close(message),
        fs_proto::CMD_LIST => handle_list(message),
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
    let mut response = Message::empty();
    response.code = status;
    let copy_len = payload.len().min(response.payload.len());
    response.payload[..copy_len].copy_from_slice(&payload[..copy_len]);
    let _ = userlib::ipc_send(channels::FS_RESP, &response);
}

fn handle_open(message: &Message) {
    let Some(path) = extract_path(&message.payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    match with_volume(|volume| {
        let mut buffer = Vec::new();
        volume.read_file(path, &mut buffer)?;
        Ok(buffer)
    }) {
        Ok(data) => match allocate_handle(data) {
            Some(id) => respond(STATUS_OK, &id.to_le_bytes()),
            None => respond(fs_proto::ERR_INVALID, &[]),
        },
        Err(err) => respond(map_error(err), &[]),
    }
}

fn handle_read(message: &Message) {
    if message.payload.len() < 8 {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    }
    let mut id_bytes = [0u8; 4];
    id_bytes.copy_from_slice(&message.payload[..4]);
    let id = u32::from_le_bytes(id_bytes);
    let length = u32::from_le_bytes([
        message.payload[4],
        message.payload[5],
        message.payload[6],
        message.payload[7],
    ]) as usize;
    let mut table = OPEN_FILES.lock();
    if let Some(handle) = table
        .iter_mut()
        .find_map(|slot| slot.as_mut().filter(|h| h.id == id))
    {
        let remaining = handle.data.len().saturating_sub(handle.offset);
        let to_read = remaining.min(length).min(Message::empty().payload.len());
        let start = handle.offset;
        let end = start + to_read;
        let mut response = Message::empty();
        response.code = STATUS_OK;
        response.payload[..to_read].copy_from_slice(&handle.data[start..end]);
        handle.offset = end;
        let _ = userlib::ipc_send(channels::FS_RESP, &response);
    } else {
        respond(fs_proto::ERR_NO_DESCRIPTOR, &[]);
    }
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
        Some((path, data, _signature)) => {
            let result = with_volume(|volume| volume.write_file(path, data, None));
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
        Some(req) => match read_shared_slice(req.handle, req.length) {
            Ok(view) => {
                let result = with_volume(|volume| unsafe {
                    let slice = slice::from_raw_parts(view.ptr, view.len);
                    volume.write_file(req.path.as_str(), slice, None)
                });
                match result {
                    Ok(_) => respond(STATUS_OK, &[]),
                    Err(err) => respond(map_error(err), &[]),
                }
            }
            Err(err) => respond(map_error(err), &[]),
        },
        None => respond(fs_proto::ERR_INVALID, &[]),
    }
}

fn handle_delete(message: &Message) {
    let Some(path) = extract_path(&message.payload) else {
        respond(fs_proto::ERR_INVALID, &[]);
        return;
    };
    match with_volume(|volume| volume.remove_file(path)) {
        Ok(_) => respond(STATUS_OK, &[]),
        Err(err) => respond(map_error(err), &[]),
    }
}

fn handle_install_bundle(message: &Message) {
    match parse_write_payload(&message.payload) {
        Some((path, data, Some(signature))) => {
            let result = with_volume(|volume| volume.write_file(path, data, Some(signature)));
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

fn allocate_handle(data: Vec<u8>) -> Option<u32> {
    let mut table = OPEN_FILES.lock();
    if let Some(slot) = table.iter_mut().find(|entry| entry.is_none()) {
        let id = NEXT_DESCRIPTOR.fetch_add(1, Ordering::SeqCst);
        *slot = Some(OpenFile {
            id,
            data,
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
    let mut path = HeaplessString::<MAX_PATH>::new();
    path.push_str(raw_path).ok()?;
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
    use core::ptr;

    use heapless::Vec as HeaplessVec;
    use libblkclient::{self, DeviceInfo, SharedBuffer};
    use log::info;
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
        buffer: SharedBuffer,
    }

    impl BlockServiceDevice {
        pub fn open_default() -> Result<Self, libblkclient::Error> {
            let devices = enumerate_devices()?;
            let info = devices
                .iter()
                .find(|entry| entry.block_size != 0)
                .ok_or(libblkclient::Error::NoDevice)?;
            Self::from_info(info)
        }

        pub fn open_index(index: u8) -> Result<Self, libblkclient::Error> {
            let info = libblkclient::device_info(index)?;
            Self::from_info(&info)
        }

        fn from_info(info: &DeviceInfo) -> Result<Self, libblkclient::Error> {
            let block_bytes = info.block_size as usize;
            if block_bytes == 0 || Self::BLOCK_SIZE % block_bytes != 0 {
                return Err(libblkclient::Error::InvalidResponse);
            }
            let sectors_per_block = (Self::BLOCK_SIZE / block_bytes) as u32;
            let buffer = SharedBuffer::new_aligned(Self::BLOCK_SIZE, 4096)?;
            info!(
                "zfs: selected block device idx={} type={} block={} capacity={} blocks",
                info.index, info.device_type, info.block_size, info.capacity_blocks
            );
            Ok(Self {
                index: info.index,
                sectors_per_block,
                buffer,
            })
        }

        pub fn zero_prefix(&self, blocks: usize) -> Result<(), libblkclient::Error> {
            unsafe {
                ptr::write_bytes(self.buffer.ptr(), 0, Self::BLOCK_SIZE);
            }
            for block in 0..blocks {
                let hw_lba = self.hw_lba(block as u64);
                libblkclient::submit_write(self.index, hw_lba, Self::BLOCK_SIZE, &self.buffer)?;
            }
            Ok(())
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
                buffer: self.buffer.clone(),
            }
        }
    }

    impl BlockDevice for BlockServiceDevice {
        const BLOCK_SIZE: usize = 4096;

        fn read_block(&self, lba: u64, buffer: &mut [u8]) -> Result<(), DeviceError> {
            if buffer.len() != Self::BLOCK_SIZE {
                return Err(DeviceError::Unsupported);
            }
            let hw_lba = self.hw_lba(lba);
            let len = buffer.len();
            libblkclient::submit_read(self.index, hw_lba, len, &self.buffer)
                .map_err(map_io_error)?;
            unsafe {
                ptr::copy_nonoverlapping(self.buffer.ptr(), buffer.as_mut_ptr(), len);
            }
            Ok(())
        }

        fn write_block(&self, lba: u64, buffer: &[u8]) -> Result<(), DeviceError> {
            if buffer.len() != Self::BLOCK_SIZE {
                return Err(DeviceError::Unsupported);
            }
            unsafe {
                ptr::copy_nonoverlapping(buffer.as_ptr(), self.buffer.ptr(), buffer.len());
            }
            let hw_lba = self.hw_lba(lba);
            libblkclient::submit_write(self.index, hw_lba, buffer.len(), &self.buffer)
                .map_err(map_io_error)?;
            Ok(())
        }
    }

    fn map_io_error(err: libblkclient::Error) -> DeviceError {
        match err {
            libblkclient::Error::BufferTooSmall => DeviceError::Unsupported,
            _ => DeviceError::Io,
        }
    }
}
