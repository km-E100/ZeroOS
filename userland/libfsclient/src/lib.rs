#![no_std]

use core::ptr;
use userlib;
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::fs;
use zero_abi::syscall::SysError;

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
        let len = buffer.len().min(response.payload.len());
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
    let shm = userlib::shm_create(data.len()).map_err(FsError::Syscall)?;
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), shm.ptr, data.len());
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
        match userlib::ipc_receive(channels::FS_RESP, buffer) {
            Ok(_) => return Ok(()),
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
