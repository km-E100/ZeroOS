#![no_std]

use zero_abi::ipc::Message;
use zero_abi::syscall::SysError;

#[inline(always)]
#[allow(dead_code)]
fn svc_call(number: u16, args: [u64; 4]) -> u64 {
    let mut ret: u64;
    unsafe {
        core::arch::asm!(
            "mov x0, {num}\n\
             mov x1, {a0}\n\
             mov x2, {a1}\n\
             mov x3, {a2}\n\
             mov x4, {a3}\n\
             svc #0\n\
             mov {ret}, x0",
            num = in(reg) number as u64,
            a0 = in(reg) args[0],
            a1 = in(reg) args[1],
            a2 = in(reg) args[2],
            a3 = in(reg) args[3],
            ret = out(reg) ret,
            options(nostack)
        );
    }
    ret
}

pub fn yield_now() -> ! {
    unsafe {
        core::arch::asm!("svc #1", options(noreturn));
    }
}

pub fn exit(code: i32) -> ! {
    unsafe {
        core::arch::asm!(
            "mov x0, {code}\n svc #2",
            code = in(reg) code as u64,
            options(noreturn)
        );
    }
}

pub fn console_read(buffer: &mut [u8]) -> Result<usize, SysError> {
    if buffer.is_empty() {
        return Ok(0);
    }
    let ret = svc_call(6, [buffer.as_mut_ptr() as u64, buffer.len() as u64, 0, 0]);
    match decode_result(ret)? {
        value => Ok(value as usize),
    }
}

pub fn console_write(buffer: &[u8]) -> Result<(), SysError> {
    if buffer.is_empty() {
        return Ok(());
    }
    let ret = svc_call(9, [buffer.as_ptr() as u64, buffer.len() as u64, 0, 0]);
    decode_result(ret).map(|_| ())
}

pub fn ipc_send(channel: u32, message: &Message) -> Result<(), SysError> {
    let ret = svc_call(0, [channel as u64, message as *const Message as u64, 0, 0]);
    decode_result(ret).map(|_| ())
}

pub fn ipc_receive(channel: u32, message: &mut Message) -> Result<(), SysError> {
    let ret = svc_call(1, [channel as u64, message as *mut Message as u64, 0, 0]);
    decode_result(ret).map(|_| ())
}

pub fn block_read(lba: u64, buffer: &mut [u8]) -> Result<(), SysError> {
    let ret = svc_call(7, [lba, buffer.as_mut_ptr() as u64, buffer.len() as u64, 0]);
    decode_result(ret).map(|_| ())
}

pub fn block_write(lba: u64, buffer: &[u8]) -> Result<(), SysError> {
    let ret = svc_call(8, [lba, buffer.as_ptr() as u64, buffer.len() as u64, 0]);
    decode_result(ret).map(|_| ())
}

pub struct SharedMemory {
    pub handle: u32,
    pub ptr: *mut u8,
    pub len: usize,
}

pub fn shm_create(size: usize) -> Result<SharedMemory, SysError> {
    let mut info = [0u64; 3];
    let ret = svc_call(10, [size as u64, info.as_mut_ptr() as u64, 0, 0]);
    decode_result(ret).map(|_| SharedMemory {
        handle: info[0] as u32,
        ptr: info[1] as *mut u8,
        len: info[2] as usize,
    })
}

pub fn shm_map(handle: u32) -> Result<*mut u8, SysError> {
    let ret = svc_call(11, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|ptr| ptr as *mut u8)
}

pub fn shm_len(handle: u32) -> Result<usize, SysError> {
    let ret = svc_call(12, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|len| len as usize)
}

pub fn shm_retain(handle: u32) -> Result<(), SysError> {
    let ret = svc_call(13, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|_| ())
}

pub fn shm_release(handle: u32) -> Result<(), SysError> {
    let ret = svc_call(14, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|_| ())
}

pub fn shm_phys(handle: u32) -> Result<usize, SysError> {
    let ret = svc_call(17, [handle as u64, 0, 0, 0]);
    decode_result(ret).map(|addr| addr as usize)
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DriverInfo {
    pub kind: u32,
    pub mmio_base: u64,
    pub mmio_len: u64,
    pub irq: u32,
}

pub fn driver_count() -> Result<u64, SysError> {
    let ret = svc_call(15, [0, 0, 0, 0]);
    decode_result(ret)
}

pub fn driver_info(index: u32) -> Result<DriverInfo, SysError> {
    let mut info = DriverInfo {
        kind: 0,
        mmio_base: 0,
        mmio_len: 0,
        irq: 0,
    };
    let ret = svc_call(16, [index as u64, &mut info as *mut _ as u64, 0, 0]);
    decode_result(ret).map(|_| info)
}

#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    pub base: u64,
    pub len: u64,
}

pub fn mmio_map(index: u32) -> Result<MmioRegion, SysError> {
    let mut info = [0u64; 2];
    let ret = svc_call(18, [index as u64, info.as_mut_ptr() as u64, 0, 0]);
    decode_result(ret).map(|base| MmioRegion { base, len: info[1] })
}

pub fn mmio_unmap(index: u32) -> Result<(), SysError> {
    let ret = svc_call(19, [index as u64, 0, 0, 0]);
    decode_result(ret).map(|_| ())
}

pub fn service_spawn(name: &str) -> Result<u64, SysError> {
    if name.is_empty() {
        return Err(SysError::InvalidArgument);
    }
    let ret = svc_call(20, [name.as_ptr() as u64, name.len() as u64, 0, 0]);
    decode_result(ret)
}

fn decode_result(value: u64) -> Result<u64, SysError> {
    match value {
        val if val == u64::MAX => Err(SysError::InvalidArgument),
        val if val == u64::MAX - 1 => Err(SysError::PermissionDenied),
        val if val == u64::MAX - 2 => Err(SysError::ChannelUnavailable),
        val if val == u64::MAX - 3 => Err(SysError::NotFound),
        val if val == u64::MAX - 4 => Err(SysError::NoMemory),
        val if val == u64::MAX - 5 => Err(SysError::WouldBlock),
        val if val == u64::MAX - 6 => Err(SysError::DeviceError),
        val if val == u64::MAX - 7 => Err(SysError::Busy),
        other => Ok(other),
    }
}
