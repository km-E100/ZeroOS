#![no_std]

use core::sync::atomic::{AtomicU32, Ordering};

use heapless::String;
use log::{info, warn};
use spin::Mutex;
use userlib::{self, yield_now};
use zero_abi::boot::{RootFsEntry, RootFsImage};
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::fs as fs_proto;
use zero_abi::syscall::SysError;

const MAX_DESCRIPTORS: usize = 16;
const PATH_MAX: usize = 96;

static DESCRIPTORS: Mutex<[Option<FileHandle>; MAX_DESCRIPTORS]> =
    Mutex::new([const { None }; MAX_DESCRIPTORS]);
static REQUEST_COUNTER: AtomicU32 = AtomicU32::new(1);

extern "C" {
    static __zero_rootfs_image: RootFsImage;
}

#[derive(Clone)]
#[allow(dead_code)]
struct FileHandle {
    id: u32,
    data: &'static [u8],
    offset: usize,
    path: String<PATH_MAX>,
}

pub extern "C" fn server_main() -> ! {
    info!("fsd: ready (read-only rootfs)");
    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive(channels::FS_REQ, &mut message) {
            Ok(_) => handle_request(&message),
            Err(SysError::WouldBlock) => yield_now(),
            Err(err) => {
                warn!("fsd: receive error {:?}", err);
                yield_now();
            }
        }
    }
}

fn handle_request(message: &Message) {
    match message.code {
        fs_proto::CMD_OPEN => handle_open(message),
        fs_proto::CMD_READ => handle_read(message),
        fs_proto::CMD_CLOSE => handle_close(message),
        fs_proto::CMD_LIST => handle_list(message),
        _ => respond(message.code, fs_proto::ERR_INVALID, &[]),
    }
}

fn handle_open(message: &Message) {
    let path = extract_string(&message.payload);
    if path.is_empty() {
        respond(message.code, fs_proto::ERR_INVALID, &[]);
        return;
    }
    if let Some((data, normalized)) = locate_entry(path) {
        if let Some(handle) = allocate_descriptor(data, normalized) {
            respond(message.code, 0, &handle.id.to_le_bytes());
        } else {
            respond(message.code, fs_proto::ERR_INVALID, &[]);
        }
    } else {
        respond(message.code, fs_proto::ERR_NOT_FOUND, &[]);
    }
}

fn handle_read(message: &Message) {
    if message.payload.len() < 8 {
        respond(message.code, fs_proto::ERR_INVALID, &[]);
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
    let mut table = DESCRIPTORS.lock();
    if let Some(handle) = table
        .iter_mut()
        .find_map(|slot| slot.as_mut().filter(|descriptor| descriptor.id == id))
    {
        let remaining = handle.data.len().saturating_sub(handle.offset);
        let to_read = remaining
            .min(length)
            .min(message.payload.len().saturating_sub(8));
        let start = handle.offset;
        let end = start + to_read;
        let mut response = Message::empty();
        response.code = 0;
        response.payload[..to_read].copy_from_slice(&handle.data[start..end]);
        handle.offset = end;
        let _ = userlib::ipc_send(channels::FS_RESP, &response);
    } else {
        respond(message.code, fs_proto::ERR_NO_DESCRIPTOR, &[]);
    }
}

fn handle_close(message: &Message) {
    if message.payload.len() < 4 {
        respond(message.code, fs_proto::ERR_INVALID, &[]);
        return;
    }
    let mut id_bytes = [0u8; 4];
    id_bytes.copy_from_slice(&message.payload[..4]);
    let id = u32::from_le_bytes(id_bytes);
    let mut table = DESCRIPTORS.lock();
    if let Some(slot) = table.iter_mut().find(|entry| {
        entry
            .as_ref()
            .map(|handle| handle.id == id)
            .unwrap_or(false)
    }) {
        *slot = None;
        respond(message.code, 0, &[]);
    } else {
        respond(message.code, fs_proto::ERR_NO_DESCRIPTOR, &[]);
    }
}

fn handle_list(message: &Message) {
    let Some(entries) = rootfs_entries() else {
        respond(message.code, fs_proto::ERR_INVALID, &[]);
        return;
    };
    let mut response = Message::empty();
    response.code = 0;
    let mut offset = 0;
    for entry in entries {
        let path = unsafe { entry.path() };
        if !path.starts_with("/Applications/") && !path.starts_with("/System/") {
            continue;
        }
        let bytes = path.as_bytes();
        if offset + bytes.len() + 1 >= response.payload.len() {
            break;
        }
        response.payload[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
        response.payload[offset] = b'\n';
        offset += 1;
    }
    let _ = userlib::ipc_send(channels::FS_RESP, &response);
}

fn respond(_code: u32, status: u32, payload: &[u8]) {
    let mut message = Message::empty();
    message.code = status;
    let len = payload.len().min(message.payload.len());
    message.payload[..len].copy_from_slice(&payload[..len]);
    let _ = userlib::ipc_send(channels::FS_RESP, &message);
}

fn allocate_descriptor(data: &'static [u8], path: String<PATH_MAX>) -> Option<FileHandle> {
    let mut table = DESCRIPTORS.lock();
    let id = REQUEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let descriptor = FileHandle {
        id,
        data,
        offset: 0,
        path,
    };
    if let Some(slot) = table.iter_mut().find(|entry| entry.is_none()) {
        *slot = Some(descriptor.clone());
        Some(descriptor)
    } else {
        None
    }
}

fn locate_entry(path: &str) -> Option<(&'static [u8], String<PATH_MAX>)> {
    let entries = rootfs_entries()?;
    for entry in entries {
        let entry_path = unsafe { entry.path() };
        if entry_path == path {
            let data = unsafe { entry.data() };
            let mut normalized = String::<PATH_MAX>::new();
            normalized.push_str(entry_path).ok()?;
            return Some((data, normalized));
        }
    }
    None
}

fn rootfs_entries() -> Option<&'static [RootFsEntry]> {
    unsafe {
        let image = &__zero_rootfs_image;
        if image.entry_count == 0 {
            None
        } else {
            Some(image.as_slice())
        }
    }
}

fn extract_string(payload: &[u8]) -> &str {
    let len = payload
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(payload.len());
    core::str::from_utf8(&payload[..len]).unwrap_or("")
}
