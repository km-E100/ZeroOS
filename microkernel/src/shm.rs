use alloc::{boxed::Box, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

#[derive(Debug)]
pub enum ShmError {
    Invalid,
    NotFound,
    Capacity,
}

struct Region {
    id: u32,
    buffer: Box<[u8]>,
    phys_addr: usize,
    refcount: u32,
}

static REGIONS: Mutex<Vec<Region>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);
const MAX_REGIONS: usize = 128;

pub fn create(size: usize) -> Result<(u32, usize, usize), ShmError> {
    if size == 0 {
        return Err(ShmError::Invalid);
    }
    let buffer = vec![0u8; size].into_boxed_slice();
    let ptr = buffer.as_ptr() as usize;
    let len = buffer.len();
    let mut table = REGIONS.lock();
    if table.len() >= MAX_REGIONS {
        return Err(ShmError::Capacity);
    }
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    table.push(Region {
        id,
        buffer,
        phys_addr: ptr,
        refcount: 1,
    });
    Ok((id, ptr, len))
}

pub fn map(handle: u32) -> Result<usize, ShmError> {
    let table = REGIONS.lock();
    if let Some(region) = table.iter().find(|r| r.id == handle) {
        Ok(region.buffer.as_ptr() as usize)
    } else {
        Err(ShmError::NotFound)
    }
}

pub fn len(handle: u32) -> Result<usize, ShmError> {
    let table = REGIONS.lock();
    if let Some(region) = table.iter().find(|r| r.id == handle) {
        Ok(region.buffer.len())
    } else {
        Err(ShmError::NotFound)
    }
}

pub fn retain(handle: u32) -> Result<(), ShmError> {
    let mut table = REGIONS.lock();
    if let Some(region) = table.iter_mut().find(|r| r.id == handle) {
        region.refcount = region.refcount.checked_add(1).ok_or(ShmError::Capacity)?;
        Ok(())
    } else {
        Err(ShmError::NotFound)
    }
}

pub fn phys(handle: u32) -> Result<usize, ShmError> {
    let table = REGIONS.lock();
    if let Some(region) = table.iter().find(|r| r.id == handle) {
        Ok(region.phys_addr)
    } else {
        Err(ShmError::NotFound)
    }
}

pub fn release(handle: u32) -> Result<(), ShmError> {
    let mut table = REGIONS.lock();
    if let Some(index) = table.iter().position(|r| r.id == handle) {
        if table[index].refcount == 0 {
            return Err(ShmError::Invalid);
        }
        table[index].refcount -= 1;
        if table[index].refcount == 0 {
            table.swap_remove(index);
        }
        Ok(())
    } else {
        Err(ShmError::NotFound)
    }
}
