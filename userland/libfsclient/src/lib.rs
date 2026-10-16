#![no_std]
extern crate alloc;

use alloc::vec::Vec;

use core::{
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};
use userlib;
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::fs;
use zero_abi::syscall::SysError;

static FSD_PID: AtomicU64 = AtomicU64::new(0);

pub struct FsHandle {
    id: u32,
}

pub fn open(path: &str) -> Result<FsHandle, FsError> {
    let mut message = Message::empty();
    message.code = fs::CMD_OPEN;
    encode_path(&mut message.payload, path)?;
    userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code == 0 {
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&response.payload[..4]);
        Ok(FsHandle {
            id: u32::from_le_bytes(id_bytes),
        })
    } else {
        Err(FsError::from_code(response.code))
    }
}

impl FsHandle {
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, FsError> {
        let mut message = Message::empty();
        message.code = fs::CMD_READ;
        message.payload[..4].copy_from_slice(&self.id.to_le_bytes());
        let len = buffer.len().min((u32::MAX / 2) as usize);
        message.payload[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
        let mut response = Message::empty();
        wait_response(&mut response)?;
        if response.code == 0 {
            let read_len = buffer.len().min(response.payload.len());
            buffer[..read_len].copy_from_slice(&response.payload[..read_len]);
            Ok(read_len)
        } else {
            Err(FsError::from_code(response.code))
        }
    }

    pub fn close(self) -> Result<(), FsError> {
        let mut message = Message::empty();
        message.code = fs::CMD_CLOSE;
        message.payload[..4].copy_from_slice(&self.id.to_le_bytes());
        userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
        let mut response = Message::empty();
        wait_response(&mut response)?;
        if response.code == 0 {
            Ok(())
        } else {
            Err(FsError::from_code(response.code))
        }
    }
}

pub fn read_file(path: &str, max_len: usize) -> Result<Vec<u8>, FsError> {
    use zero_abi::protocol::fs::vtable;
    let mut q = Message::empty();
    q.code = vtable::CMD_OPEN;
    encode_vt_open(&mut q.payload, path, vtable::OPEN_EXISTING)?;
    userlib::ipc_send(channels::FS_REQ, &q).map_err(FsError::Ipc)?;
    let mut r = Message::empty();
    wait_response(&mut r)?;
    if r.code != 0 {
        return Err(FsError::from_code(r.code));
    }
    let fd = u32::from_le_bytes(r.payload[..4].try_into().unwrap());
    let fsd_pid = FSD_PID.load(Ordering::Acquire);
    if fsd_pid == 0 {
        let _ = close_fd(fd);
        return Err(FsError::Syscall(SysError::NotFound));
    }

    // One reusable 16 KiB owner mapping; each transfer grants a one-shot fsd
    // holder which the server releases before replying. This keeps the secure
    // holder model intact while replacing hundreds of 124-byte IPC reads.
    const BULK: usize = 16 * 1024;
    let shm = userlib::shm_create(BULK).map_err(FsError::Syscall)?;
    let mut out = Vec::new();
    let result = (|| -> Result<(), FsError> {
        loop {
            let remaining = max_len.saturating_sub(out.len());
            if remaining == 0 {
                return Err(FsError::Invalid);
            }
            let want = core::cmp::min(shm.len, remaining);
            userlib::shm_grant(shm.handle, fsd_pid).map_err(FsError::Syscall)?;
            let mut q = Message::empty();
            q.code = vtable::CMD_READ_SHARED;
            q.payload[..4].copy_from_slice(&fd.to_le_bytes());
            q.payload[4..8].copy_from_slice(&shm.handle.to_le_bytes());
            q.payload[8..12].copy_from_slice(&(want as u32).to_le_bytes());
            userlib::ipc_send(channels::FS_REQ, &q).map_err(FsError::Ipc)?;
            let mut r = Message::empty();
            wait_response(&mut r)?;
            if r.code != 0 {
                return Err(FsError::from_code(r.code));
            }
            let n = u32::from_le_bytes(r.payload[..4].try_into().unwrap_or([0; 4])) as usize;
            if n > want || n > shm.len {
                return Err(FsError::Invalid);
            }
            if n != 0 {
                let old = out.len();
                out.resize(old + n, 0);
                unsafe {
                    core::ptr::copy_nonoverlapping(shm.ptr, out.as_mut_ptr().add(old), n);
                }
            }
            if n < want {
                break;
            }
        }
        Ok(())
    })();
    let _ = userlib::shm_release(shm.handle);
    let close_result = close_fd(fd);
    result?;
    close_result?;
    Ok(out)
}

pub fn mkdir(path: &str) -> Result<(), FsError> {
    path_op(zero_abi::protocol::fs::vtable::CMD_MKDIR, path)
}
pub fn rmdir(path: &str) -> Result<(), FsError> {
    path_op(zero_abi::protocol::fs::vtable::CMD_RMDIR, path)
}
pub fn unlink(path: &str) -> Result<(), FsError> {
    path_op(zero_abi::protocol::fs::vtable::CMD_UNLINK, path)
}
pub fn rename(old: &str, new: &str) -> Result<(), FsError> {
    use zero_abi::protocol::fs::vtable;
    if old.is_empty() || new.is_empty() || old.len() + new.len() + 2 > 128 {
        return Err(FsError::Invalid);
    }
    let mut q = Message::empty();
    q.code = vtable::CMD_RENAME;
    q.payload[..old.len()].copy_from_slice(old.as_bytes());
    let o = old.len() + 1;
    q.payload[o..o + new.len()].copy_from_slice(new.as_bytes());
    userlib::ipc_send(channels::FS_REQ, &q).map_err(FsError::Ipc)?;
    let mut r = Message::empty();
    wait_response(&mut r)?;
    if r.code == 0 {
        Ok(())
    } else {
        Err(FsError::from_code(r.code))
    }
}
fn path_op(code: u32, path: &str) -> Result<(), FsError> {
    let mut q = Message::empty();
    q.code = code;
    encode_path(&mut q.payload, path)?;
    userlib::ipc_send(channels::FS_REQ, &q).map_err(FsError::Ipc)?;
    let mut r = Message::empty();
    wait_response(&mut r)?;
    if r.code == 0 {
        Ok(())
    } else {
        Err(FsError::from_code(r.code))
    }
}
fn close_fd(fd: u32) -> Result<(), FsError> {
    let mut q = Message::empty();
    q.code = zero_abi::protocol::fs::vtable::CMD_CLOSE;
    q.payload[..4].copy_from_slice(&fd.to_le_bytes());
    userlib::ipc_send(channels::FS_REQ, &q).map_err(FsError::Ipc)?;
    let mut r = Message::empty();
    wait_response(&mut r)?;
    if r.code == 0 {
        Ok(())
    } else {
        Err(FsError::from_code(r.code))
    }
}
fn encode_vt_open(payload: &mut [u8; 128], path: &str, mode: u8) -> Result<(), FsError> {
    if path.is_empty() || path.len() + 2 > payload.len() {
        return Err(FsError::Invalid);
    }
    payload.fill(0);
    payload[..path.len()].copy_from_slice(path.as_bytes());
    payload[path.len() + 1] = mode;
    Ok(())
}

pub fn list_entries(buffer: &mut [u8]) -> Result<usize, FsError> {
    list_directory("", buffer)
}

pub fn list_directory(path: &str, buffer: &mut [u8]) -> Result<usize, FsError> {
    let mut message = Message::empty();
    message.code = fs::CMD_LIST;
    encode_optional_path(&mut message.payload, path)?;
    userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code == 0 {
        // Directory records are newline-delimited UTF-8 names and NUL is not a
        // legal path byte. Message payloads are zero-initialised, so the first
        // NUL is the authoritative response length; the old code returned all
        // 128 bytes and made callers interpret the zero tail as a bogus name.
        let actual = response
            .payload
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(response.payload.len());
        let len = buffer.len().min(actual);
        buffer[..len].copy_from_slice(&response.payload[..len]);
        Ok(len)
    } else {
        Err(FsError::from_code(response.code))
    }
}

const INLINE_DATA_LIMIT: usize = 96;

pub fn write_file(path: &str, data: &[u8]) -> Result<(), FsError> {
    if data.len() > INLINE_DATA_LIMIT {
        return write_file_shared(path, data);
    }
    let mut message = Message::empty();
    message.code = fs::CMD_WRITE_FILE;
    encode_write_payload(&mut message.payload, path, data, false)?;
    userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code == 0 {
        Ok(())
    } else {
        Err(FsError::from_code(response.code))
    }
}

fn write_file_shared(path: &str, data: &[u8]) -> Result<(), FsError> {
    if data.is_empty() {
        return Err(FsError::Invalid);
    }
    // Learn the actual fsd PID from any prior FS response. Large writes are
    // never allowed to bypass the SHM holder policy: the owner explicitly
    // grants the opaque handle to the service that replied on FS_RESP.
    let fsd_pid = FSD_PID.load(Ordering::Acquire);
    if fsd_pid == 0 {
        return Err(FsError::Syscall(SysError::NotFound));
    }
    let shm = userlib::shm_create(data.len()).map_err(FsError::Syscall)?;
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), shm.ptr, data.len());
    }
    if let Err(e) = userlib::shm_grant(shm.handle, fsd_pid) {
        let _ = userlib::shm_release(shm.handle);
        return Err(FsError::Syscall(e));
    }
    let result = send_shared_write(path, shm.handle, data.len());
    let _ = userlib::shm_release(shm.handle);
    result
}

fn send_shared_write(path: &str, handle: u32, len: usize) -> Result<(), FsError> {
    let mut message = Message::empty();
    message.code = fs::CMD_WRITE_SHARED;
    encode_shared_payload(&mut message.payload, path, handle, len)?;
    userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code == 0 {
        Ok(())
    } else {
        Err(FsError::from_code(response.code))
    }
}

pub fn delete_file(path: &str) -> Result<(), FsError> {
    let mut message = Message::empty();
    message.code = fs::CMD_DELETE_FILE;
    encode_path(&mut message.payload, path)?;
    userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code == 0 {
        Ok(())
    } else {
        Err(FsError::from_code(response.code))
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct DeviceSummary {
    pub index: u8,
    pub device_type: u8,
    pub block_size: u32,
    pub capacity_blocks: u64,
}

pub fn list_devices(buffer: &mut [DeviceSummary]) -> Result<usize, FsError> {
    let mut message = Message::empty();
    message.code = fs::CMD_LIST_DEVICES;
    userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code != 0 {
        return Err(FsError::from_code(response.code));
    }
    let count = response.payload[0] as usize;
    let mut written = 0usize;
    const RECORD_LEN: usize = 14;
    let mut offset = 1usize;
    for _ in 0..count {
        if offset + RECORD_LEN > response.payload.len() || written >= buffer.len() {
            break;
        }
        buffer[written] = decode_device(&response.payload[offset..offset + RECORD_LEN]);
        written += 1;
        offset += RECORD_LEN;
    }
    Ok(written)
}

pub fn install_device(index: u8) -> Result<(), FsError> {
    let mut message = Message::empty();
    message.code = fs::CMD_INSTALL_DEVICE;
    message.payload[0] = index;
    userlib::ipc_send(channels::FS_REQ, &message).map_err(FsError::Ipc)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code == 0 {
        Ok(())
    } else {
        Err(FsError::from_code(response.code))
    }
}

fn decode_device(bytes: &[u8]) -> DeviceSummary {
    let mut block = [0u8; 4];
    block.copy_from_slice(&bytes[2..6]);
    let mut capacity = [0u8; 8];
    capacity.copy_from_slice(&bytes[6..14]);
    DeviceSummary {
        index: bytes[0],
        device_type: bytes[1],
        block_size: u32::from_le_bytes(block),
        capacity_blocks: u64::from_le_bytes(capacity),
    }
}

fn encode_path(payload: &mut [u8; 128], path: &str) -> Result<(), FsError> {
    if path.is_empty() {
        return Err(FsError::Invalid);
    }
    encode_optional_path(payload, path)
}

fn encode_optional_path(payload: &mut [u8; 128], path: &str) -> Result<(), FsError> {
    payload.fill(0);
    let bytes = path.as_bytes();
    if bytes.len() >= payload.len() {
        return Err(FsError::Invalid);
    }
    payload[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

fn encode_write_payload(
    payload: &mut [u8; 128],
    path: &str,
    data: &[u8],
    include_signature: bool,
) -> Result<(), FsError> {
    payload.fill(0);
    if path.is_empty() || path.len() >= 255 || data.len() >= 255 {
        return Err(FsError::Invalid);
    }
    let mut offset = 0usize;
    payload[offset] = path.len() as u8;
    offset += 1;
    payload[offset] = data.len() as u8;
    offset += 1;
    payload[offset] = if include_signature { 1 } else { 0 };
    offset += 1;
    if offset + path.len() >= payload.len() {
        return Err(FsError::Invalid);
    }
    payload[offset..offset + path.len()].copy_from_slice(path.as_bytes());
    offset += path.len();
    if offset + data.len() > payload.len() {
        return Err(FsError::Invalid);
    }
    payload[offset..offset + data.len()].copy_from_slice(data);
    Ok(())
}

fn encode_shared_payload(
    payload: &mut [u8; 128],
    path: &str,
    handle: u32,
    len: usize,
) -> Result<(), FsError> {
    if path.is_empty() || path.len() >= 255 {
        return Err(FsError::Invalid);
    }
    if len == 0 || len > u32::MAX as usize {
        return Err(FsError::Invalid);
    }
    payload.fill(0);
    payload[0] = path.len() as u8;
    let mut offset = 1usize;
    payload[offset..offset + path.len()].copy_from_slice(path.as_bytes());
    offset += path.len();
    payload[offset..offset + 4].copy_from_slice(&(len as u32).to_le_bytes());
    offset += 4;
    payload[offset..offset + 4].copy_from_slice(&handle.to_le_bytes());
    Ok(())
}

fn wait_response(buffer: &mut Message) -> Result<(), FsError> {
    loop {
        match userlib::ipc_receive_from(channels::FS_RESP, buffer) {
            Ok(sender) => {
                FSD_PID.store(sender, Ordering::Release);
                return Ok(());
            }
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(err) => return Err(FsError::Ipc(err)),
        }
    }
}

#[derive(Debug)]
pub enum FsError {
    NotFound,
    Invalid,
    NoDescriptor,
    DeviceError,
    Ipc(SysError),
    Syscall(SysError),
    Unknown(u32),
}

impl FsError {
    fn from_code(code: u32) -> Self {
        match code {
            0 => FsError::Invalid,
            fs::ERR_NOT_FOUND => FsError::NotFound,
            fs::ERR_INVALID => FsError::Invalid,
            fs::ERR_NO_DESCRIPTOR => FsError::NoDescriptor,
            fs::ERR_DEVICE => FsError::DeviceError,
            other => FsError::Unknown(other),
        }
    }
}
