#![no_std]

use core::convert::TryInto;

use userlib::{ipc_receive, ipc_send, shm_create, shm_phys, shm_release, shm_retain, yield_now};
use zero_abi::{channels, ipc::Message, protocol::blk, syscall::SysError};

const RESPONSE_PAYLOAD_LEN: usize = 128;

#[derive(Copy, Clone, Debug, Default)]
pub struct DeviceInfo {
    pub index: u8,
    pub device_type: u8,
    pub block_size: u32,
    pub capacity_blocks: u64,
}

pub fn enumerate_devices(buffer: &mut [DeviceInfo]) -> Result<usize, Error> {
    let mut request = Message::empty();
    request.code = blk::CMD_LIST;
    send_request(&request)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code != blk::STATUS_OK {
        return Err(Error::Status(response.code));
    }
    let count = response.payload[0] as usize;
    let mut written = 0usize;
    for (_slot, entry) in response.payload[1..].iter().enumerate().take(count) {
        if written >= buffer.len() {
            break;
        }
        let info = device_info(*entry)?;
        buffer[written] = info;
        written += 1;
    }
    Ok(written)
}

pub fn device_info(index: u8) -> Result<DeviceInfo, Error> {
    let mut request = Message::empty();
    request.code = blk::CMD_INFO;
    request.payload[0] = index;
    send_request(&request)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code != blk::STATUS_OK {
        return Err(Error::Status(response.code));
    }
    if response.payload.len() < 20 || response.payload[0] != index {
        return Err(Error::InvalidResponse);
    }
    let block_size = u64::from_le_bytes(response.payload[4..12].try_into().unwrap());
    let capacity = u64::from_le_bytes(response.payload[12..20].try_into().unwrap());
    Ok(DeviceInfo {
        index,
        device_type: response.payload[1],
        block_size: block_size as u32,
        capacity_blocks: capacity,
    })
}

#[derive(Debug)]
pub enum Error {
    Ipc(SysError),
    Status(u32),
    InvalidResponse,
    BufferTooSmall,
    NoDevice,
    SharedMem(SysError),
}

impl From<SysError> for Error {
    fn from(value: SysError) -> Self {
        Error::Ipc(value)
    }
}

pub fn submit_read(
    device: u8,
    lba: u64,
    len: usize,
    buffer: &SharedBuffer,
) -> Result<usize, Error> {
    submit_io(device, lba, len, buffer, false)
}

pub fn submit_write(
    device: u8,
    lba: u64,
    len: usize,
    buffer: &SharedBuffer,
) -> Result<usize, Error> {
    submit_io(device, lba, len, buffer, true)
}

fn submit_io(
    device: u8,
    lba: u64,
    len: usize,
    buffer: &SharedBuffer,
    write: bool,
) -> Result<usize, Error> {
    if len == 0 || len > buffer.len() || len > u32::MAX as usize {
        return Err(Error::BufferTooSmall);
    }
    let mut request = Message::empty();
    request.code = if write { blk::CMD_WRITE } else { blk::CMD_READ };
    encode_io_request(&mut request.payload, device, lba, len as u32, buffer)?;
    send_request(&request)?;
    let mut response = Message::empty();
    wait_response(&mut response)?;
    if response.code != blk::STATUS_OK {
        return Err(Error::Status(response.code));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&response.payload[..4]);
    Ok(u32::from_le_bytes(len_bytes) as usize)
}

fn encode_io_request(
    payload: &mut [u8; RESPONSE_PAYLOAD_LEN],
    device: u8,
    lba: u64,
    len: u32,
    buffer: &SharedBuffer,
) -> Result<(), Error> {
    payload.fill(0);
    payload[0] = device;
    payload[4..12].copy_from_slice(&lba.to_le_bytes());
    payload[12..16].copy_from_slice(&len.to_le_bytes());
    payload[16..20].copy_from_slice(&buffer.handle().to_le_bytes());
    payload[20..24].copy_from_slice(&buffer.offset().to_le_bytes());
    Ok(())
}

fn send_request(message: &Message) -> Result<(), Error> {
    ipc_send(channels::BLKDRV_REQ, message).map_err(Error::Ipc)
}

fn wait_response(message: &mut Message) -> Result<(), Error> {
    loop {
        match ipc_receive(channels::BLKDRV_RESP, message) {
            Ok(_) => return Ok(()),
            Err(SysError::WouldBlock) => yield_now(),
            Err(err) => return Err(Error::Ipc(err)),
        }
    }
}

/// Read arbitrary bytes through the frozen blkdrv passthrough protocol.
/// The request stream is split so no chunk crosses a 512-byte sector and no
/// IPC response exceeds 128 bytes.
pub fn passthrough_read(device: u8, lba: u64, out: &mut [u8]) -> Result<(), Error> {
    let mut done = 0usize;
    while done < out.len() {
        let sector = lba + (done / 512) as u64;
        let sector_off = done % 512;
        let n = core::cmp::min(out.len() - done, core::cmp::min(124, 512 - sector_off));
        let mut q = Message::empty();
        q.code = zero_abi::protocol::blk::passthrough::CMD_READ_CHUNK;
        q.payload[0] = device;
        q.payload[4..12].copy_from_slice(&sector.to_le_bytes());
        q.payload[12..16].copy_from_slice(&(sector_off as u32).to_le_bytes());
        q.payload[16..20].copy_from_slice(&(n as u32).to_le_bytes());
        send_request(&q)?;
        let mut r = Message::empty();
        wait_response(&mut r)?;
        if r.code != zero_abi::protocol::blk::STATUS_OK {
            return Err(Error::Status(r.code));
        }
        out[done..done + n].copy_from_slice(&r.payload[..n]);
        done += n;
    }
    Ok(())
}

/// Write arbitrary bytes through blkdrv's sector-local read/modify/write path.
pub fn passthrough_write(device: u8, lba: u64, data: &[u8]) -> Result<(), Error> {
    let mut done = 0usize;
    while done < data.len() {
        let sector = lba + (done / 512) as u64;
        let sector_off = done % 512;
        let n = core::cmp::min(data.len() - done, core::cmp::min(104, 512 - sector_off));
        let mut q = Message::empty();
        q.code = zero_abi::protocol::blk::passthrough::CMD_WRITE_CHUNK;
        q.payload[0] = device;
        q.payload[4..12].copy_from_slice(&sector.to_le_bytes());
        q.payload[12..16].copy_from_slice(&(sector_off as u32).to_le_bytes());
        q.payload[16..20].copy_from_slice(&(n as u32).to_le_bytes());
        q.payload[20..20 + n].copy_from_slice(&data[done..done + n]);
        send_request(&q)?;
        let mut r = Message::empty();
        wait_response(&mut r)?;
        if r.code != zero_abi::protocol::blk::STATUS_OK {
            return Err(Error::Status(r.code));
        }
        let wrote = u32::from_le_bytes(r.payload[..4].try_into().unwrap()) as usize;
        if wrote != n {
            return Err(Error::InvalidResponse);
        }
        done += n;
    }
    Ok(())
}

pub struct SharedBuffer {
    handle: u32,
    ptr: *mut u8,
    len: usize,
    offset: u32,
    phys: usize,
}

impl SharedBuffer {
    pub fn new(size: usize) -> Result<Self, Error> {
        Self::new_aligned(size, 1)
    }

    pub fn new_aligned(size: usize, align: usize) -> Result<Self, Error> {
        if size == 0 {
            return Err(Error::BufferTooSmall);
        }
        let mut alloc_size = size;
        if align > 1 {
            alloc_size = size.checked_add(align).ok_or(Error::BufferTooSmall)?;
        }
        let shm = shm_create(alloc_size).map_err(Error::SharedMem)?;
        let base_ptr = shm.ptr as usize;
        let aligned = align_up(base_ptr, align.max(1));
        if aligned + size > base_ptr + shm.len {
            let _ = shm_release(shm.handle);
            return Err(Error::BufferTooSmall);
        }
        let offset = (aligned - base_ptr) as u32;
        let phys = shm_phys(shm.handle).map_err(Error::SharedMem)? + offset as usize;
        Ok(Self {
            handle: shm.handle,
            ptr: aligned as *mut u8,
            len: size,
            offset,
            phys,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub fn phys(&self) -> usize {
        self.phys
    }

    pub fn handle(&self) -> u32 {
        self.handle
    }

    pub fn offset(&self) -> u32 {
        self.offset
    }
}

impl Clone for SharedBuffer {
    fn clone(&self) -> Self {
        let _ = shm_retain(self.handle);
        Self {
            handle: self.handle,
            ptr: self.ptr,
            len: self.len,
            offset: self.offset,
            phys: self.phys,
        }
    }
}

impl Drop for SharedBuffer {
    fn drop(&mut self) {
        let _ = shm_release(self.handle);
    }
}

unsafe impl Send for SharedBuffer {}

const fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}
