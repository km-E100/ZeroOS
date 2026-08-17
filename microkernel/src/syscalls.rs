use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::str;
use spin::Mutex;
use zero_abi::ipc::Message;
use zero_abi::syscall::{SysError, Syscall, SyscallResult};

use crate::process::TrapFrame;
use crate::runtime::serial;
use crate::shm;

#[derive(Clone, Copy)]
struct MmioLease {
    slot: usize,
    index: u32,
    refs: u32,
}

static MMIO_LEASES: Mutex<Vec<MmioLease>> = Mutex::new(Vec::new());

/// Minimum virtual address that we consider valid for user mappings.
/// The kernel and all user code/stacks are linked at or above 0x4008_0000
/// (see boot/linker.ld), while low addresses like 0x0..0x1000 are unmapped
/// under the firmware's page tables.
const USER_VA_MIN: usize = 0x4000_0000;

fn validate_user_ptr(addr: usize, size: usize) -> Result<(), SysError> {
    if addr == 0 {
        return Err(SysError::InvalidArgument);
    }
    if addr < USER_VA_MIN {
        return Err(SysError::InvalidArgument);
    }
    let end = addr.checked_add(size).ok_or(SysError::InvalidArgument)?;
    if end < USER_VA_MIN {
        return Err(SysError::InvalidArgument);
    }
    Ok(())
}

pub fn handle(syscall: Syscall, frame: *mut TrapFrame) -> SyscallResult {
    match syscall {
        Syscall::SendMessage {
            channel,
            user_message,
        } => {
            let caller_slot = crate::scheduler::current_slot();
            let caller_pid =
                crate::process::pid_at_slot(caller_slot).ok_or(SysError::PermissionDenied)?;
            let message = unsafe { copy_message_from_user(user_message)? };
            crate::ipc::send(caller_pid, channel, &message).map_err(map_ipc_error)?;
            Ok(0)
        }
        Syscall::ReceiveMessage {
            channel,
            user_buffer,
        } => {
            let caller_slot = crate::scheduler::current_slot();
            let caller_pid =
                crate::process::pid_at_slot(caller_slot).ok_or(SysError::PermissionDenied)?;
            let message = crate::ipc::receive(caller_pid, channel).map_err(map_ipc_error)?;
            unsafe {
                copy_message_to_user(user_buffer, &message)?;
            }
            Ok(0)
        }
        Syscall::ConsoleRead { user_buffer, len } => {
            if len == 0 {
                return Ok(0);
            }
            let request_len = len.min(1024);
            let mut buffer = vec![0u8; request_len];
            let read = crate::drivers::pl011::read_into(&mut buffer);
            if read == 0 {
                return Err(SysError::WouldBlock);
            }
            unsafe {
                copy_slice_to_user(user_buffer, &buffer[..read])?;
            }
            Ok(read as u64)
        }
        Syscall::ConsoleWrite { user_buffer, len } => {
            if len == 0 {
                return Ok(0);
            }
            let mut remaining = len;
            let mut offset = 0usize;
            while remaining > 0 {
                let chunk = remaining.min(512);
                let mut buffer = alloc::vec![0u8; chunk];
                unsafe {
                    copy_slice_from_user(user_buffer + offset, &mut buffer)?;
                }
                serial::write_bytes(&buffer);
                remaining -= chunk;
                offset += chunk;
            }
            Ok(len as u64)
        }
        Syscall::BlockRead {
            lba,
            user_buffer,
            len,
        } => {
            if len == 0 {
                return Ok(0);
            }
            if len % 512 != 0 {
                return Err(SysError::InvalidArgument);
            }
            let mut buffer = vec![0u8; len];
            crate::drivers::virtio::blk::read_blocks(lba, &mut buffer).map_err(map_block_error)?;
            unsafe {
                copy_slice_to_user(user_buffer, &buffer)?;
            }
            Ok(len as u64)
        }
        Syscall::BlockWrite {
            lba,
            user_buffer,
            len,
        } => {
            if len == 0 {
                return Ok(0);
            }
            if len % 512 != 0 {
                return Err(SysError::InvalidArgument);
            }
            let mut buffer = vec![0u8; len];
            unsafe {
                copy_slice_from_user(user_buffer, &mut buffer)?;
            }
            crate::drivers::virtio::blk::write_blocks(lba, &buffer).map_err(map_block_error)?;
            Ok(len as u64)
        }
        Syscall::ShmCreate { size, user_result } => {
            let (handle, ptr, len) = shm::create(size).map_err(map_shm_error)?;
            unsafe {
                write_shm_create_result(user_result, handle, ptr, len)?;
            }
            Ok(0)
        }
        Syscall::ShmMap { handle } => {
            let ptr = shm::map(handle).map_err(map_shm_error)?;
            Ok(ptr as u64)
        }
        Syscall::ShmLen { handle } => {
            let len = shm::len(handle).map_err(map_shm_error)?;
            Ok(len as u64)
        }
        Syscall::ShmRetain { handle } => {
            shm::retain(handle).map_err(map_shm_error)?;
            Ok(0)
        }
        Syscall::ShmRelease { handle } => {
            shm::release(handle).map_err(map_shm_error)?;
            Ok(0)
        }
        Syscall::DriverCount => {
            let count = crate::drivers::descriptors()
                .map(|table| table.len())
                .unwrap_or(0);
            Ok(count as u64)
        }
        Syscall::DriverInfo { index, user_buffer } => {
            let descriptor = descriptor_for_index(index)?;
            unsafe {
                write_driver_info(user_buffer, descriptor)?;
            }
            Ok(0)
        }
        Syscall::ShmPhys { handle } => {
            let phys = shm::phys(handle).map_err(map_shm_error)?;
            Ok(phys as u64)
        }
        Syscall::MmioMap { index, user_buffer } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_privileged(caller_slot)?;
            let descriptor = descriptor_for_index(index)?;
            acquire_mmio(caller_slot, index)?;
            unsafe {
                write_mmio_info(user_buffer, descriptor.mmio_base, descriptor.mmio_len)?;
            }
            Ok(descriptor.mmio_base)
        }
        Syscall::MmioUnmap { index } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_privileged(caller_slot)?;
            release_mmio(caller_slot, index)?;
            Ok(0)
        }
        Syscall::Fork => {
            let caller_slot = crate::scheduler::current_slot();
            let parent_frame = unsafe { &*frame };
            let (child_pid, _) =
                crate::process::fork(caller_slot, parent_frame).map_err(map_process_error)?;
            crate::scheduler::enqueue(child_pid);
            Ok(child_pid.raw())
        }
        Syscall::Exec { entry, arg } => {
            let caller_slot = crate::scheduler::current_slot();
            unsafe {
                crate::process::exec(caller_slot, entry, arg, &mut *frame)
                    .map_err(map_process_error)?;
                Ok((*frame).regs[0])
            }
        }
        Syscall::SpawnService { name_ptr, name_len } => {
            let caller_slot = crate::scheduler::current_slot();
            ensure_privileged(caller_slot)?;
            let name = copy_string_from_user(name_ptr, name_len)?;
            match crate::services::spawn_service_by_name(name.as_str()) {
                Ok(pid) => {
                    crate::scheduler::enqueue(pid);
                    Ok(pid.raw())
                }
                Err(_) => Err(SysError::NotFound),
            }
        }
        Syscall::Exit { status: _ } => crate::scheduler::exit_current(),
        Syscall::Yield => crate::scheduler::yield_current(),
    }
}

fn map_ipc_error(err: crate::ipc::IpcError) -> SysError {
    match err {
        crate::ipc::IpcError::NotReady => SysError::InvalidArgument,
        crate::ipc::IpcError::ChannelBusy => SysError::ChannelUnavailable,
        crate::ipc::IpcError::Invalid => SysError::InvalidArgument,
        crate::ipc::IpcError::Empty => SysError::WouldBlock,
        crate::ipc::IpcError::AccessDenied => SysError::PermissionDenied,
    }
}

fn map_process_error(err: crate::process::ProcessError) -> SysError {
    match err {
        crate::process::ProcessError::NoSuchProcess => SysError::NotFound,
        crate::process::ProcessError::TableFull => SysError::NoMemory,
        crate::process::ProcessError::NoMemory => SysError::NoMemory,
        crate::process::ProcessError::InvalidArgument => SysError::InvalidArgument,
        crate::process::ProcessError::PermissionDenied => SysError::PermissionDenied,
        crate::process::ProcessError::ElfError(_) => SysError::InvalidArgument,
        crate::process::ProcessError::MapError(_) => SysError::InvalidArgument,
    }
}

fn map_block_error(err: crate::drivers::BlockError) -> SysError {
    match err {
        crate::drivers::BlockError::NotReady => SysError::DeviceError,
        crate::drivers::BlockError::Busy => SysError::Busy,
        crate::drivers::BlockError::DeviceError => SysError::DeviceError,
        crate::drivers::BlockError::InvalidArgument => SysError::InvalidArgument,
    }
}

fn map_shm_error(err: shm::ShmError) -> SysError {
    match err {
        shm::ShmError::Invalid => SysError::InvalidArgument,
        shm::ShmError::NotFound => SysError::NotFound,
        shm::ShmError::Capacity => SysError::NoMemory,
    }
}

fn ensure_privileged(slot: usize) -> Result<(), SysError> {
    if crate::process::is_slot_privileged(slot) {
        Ok(())
    } else {
        Err(SysError::PermissionDenied)
    }
}

fn descriptor_for_index(
    index: u32,
) -> Result<&'static zero_abi::driver::DriverDescriptor, SysError> {
    let descriptors = crate::drivers::descriptors().ok_or(SysError::NotFound)?;
    descriptors.get(index as usize).ok_or(SysError::NotFound)
}

fn acquire_mmio(slot: usize, index: u32) -> Result<(), SysError> {
    let mut leases = MMIO_LEASES.lock();
    if let Some(entry) = leases
        .iter_mut()
        .find(|entry| entry.slot == slot && entry.index == index)
    {
        entry.refs = entry.refs.checked_add(1).ok_or(SysError::NoMemory)?;
        return Ok(());
    }
    leases.push(MmioLease {
        slot,
        index,
        refs: 1,
    });
    Ok(())
}

fn release_mmio(slot: usize, index: u32) -> Result<(), SysError> {
    let mut leases = MMIO_LEASES.lock();
    if let Some(pos) = leases
        .iter()
        .position(|entry| entry.slot == slot && entry.index == index)
    {
        if leases[pos].refs > 1 {
            leases[pos].refs -= 1;
        } else {
            leases.swap_remove(pos);
        }
        Ok(())
    } else {
        Err(SysError::InvalidArgument)
    }
}

unsafe fn copy_message_from_user(addr: usize) -> Result<Message, SysError> {
    validate_user_ptr(addr, core::mem::size_of::<Message>())?;
    let ptr = addr as *const Message;
    // Basic alignment check: require pointer aligned to Message
    if ptr as usize % core::mem::align_of::<Message>() != 0 {
        return Err(SysError::InvalidArgument);
    }
    Ok(ptr.read())
}

unsafe fn copy_message_to_user(addr: usize, msg: &Message) -> Result<(), SysError> {
    validate_user_ptr(addr, core::mem::size_of::<Message>())?;
    let ptr = addr as *mut Message;
    if ptr as usize % core::mem::align_of::<Message>() != 0 {
        return Err(SysError::InvalidArgument);
    }
    ptr.write(*msg);
    Ok(())
}

unsafe fn copy_slice_to_user(addr: usize, data: &[u8]) -> Result<(), SysError> {
    validate_user_ptr(addr, data.len())?;
    let ptr = addr as *mut u8;
    ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
    Ok(())
}

unsafe fn copy_slice_from_user(addr: usize, dst: &mut [u8]) -> Result<(), SysError> {
    validate_user_ptr(addr, dst.len())?;
    let ptr = addr as *const u8;
    ptr::copy_nonoverlapping(ptr, dst.as_mut_ptr(), dst.len());
    Ok(())
}

fn copy_string_from_user(ptr: usize, len: usize) -> Result<String, SysError> {
    if ptr == 0 || len == 0 || len > 256 {
        return Err(SysError::InvalidArgument);
    }
    validate_user_ptr(ptr, len)?;
    let mut buffer = vec![0u8; len];
    unsafe {
        copy_slice_from_user(ptr, &mut buffer)?;
    }
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(len);
    let slice = &buffer[..end];
    let text = str::from_utf8(slice).map_err(|_| SysError::InvalidArgument)?;
    Ok(String::from(text))
}

unsafe fn write_shm_create_result(
    addr: usize,
    handle: u32,
    ptr_value: usize,
    len: usize,
) -> Result<(), SysError> {
    validate_user_ptr(addr, 3 * core::mem::size_of::<u64>())?;
    let ptr = addr as *mut u64;
    ptr.add(0).write(handle as u64);
    ptr.add(1).write(ptr_value as u64);
    ptr.add(2).write(len as u64);
    Ok(())
}

unsafe fn write_driver_info(
    addr: usize,
    descriptor: &zero_abi::driver::DriverDescriptor,
) -> Result<(), SysError> {
    validate_user_ptr(addr, core::mem::size_of::<DriverInfoRecord>())?;
    #[repr(C)]
    struct DriverInfoRecord {
        kind: u32,
        mmio_base: u64,
        mmio_len: u64,
        irq: u32,
    }
    let record = DriverInfoRecord {
        kind: descriptor.kind as u32,
        mmio_base: descriptor.mmio_base,
        mmio_len: descriptor.mmio_len,
        irq: descriptor.irq,
    };
    let ptr = addr as *mut DriverInfoRecord;
    ptr.write(record);
    Ok(())
}

unsafe fn write_mmio_info(addr: usize, base: u64, len: u64) -> Result<(), SysError> {
    validate_user_ptr(addr, 2 * core::mem::size_of::<u64>())?;
    let ptr = addr as *mut u64;
    ptr.add(0).write(base);
    ptr.add(1).write(len);
    Ok(())
}
