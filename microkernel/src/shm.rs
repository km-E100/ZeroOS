//! Secure shared-memory objects (Knife 25).
//!
//! EL0 sees only opaque handles + user virtual mappings. Physical addresses never
//! cross the syscall boundary. Each object owns one ref on every physical page;
//! every active process mapping retains an additional page ref so normal unmap can
//! safely drop it. Explicit grant is owner-only.

use crate::mm::{address_space::AddressSpace, phys};
use crate::process;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;
use zero_abi::ProcessId;

const PAGE: usize = 4096;
const SHM_BASE: usize = 0x2000_0000;
const SHM_END: usize = 0x3000_0000;
pub(crate) const SHM_PUBLIC_END_FOR_TEST: usize = SHM_END;
const MAX_OBJECT: usize = 16 * 1024 * 1024;
const MAX_REGIONS: usize = 128;
const MAX_MAPPINGS: usize = 512;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ShmError {
    Invalid,
    NotFound,
    Capacity,
    Permission,
    NoMemory,
    Map,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Holder {
    pid: u64,
    refs: u32,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Mapping {
    pid: u64,
    handle: u32,
    va: usize,
    len: usize,
}
struct Region {
    id: u32,
    owner: u64,
    len: usize,
    pages: Vec<usize>,
    holders: Vec<Holder>,
}
static REGIONS: Mutex<Vec<Region>> = Mutex::new(Vec::new());
static MAPPINGS: Mutex<Vec<Mapping>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

fn align_up(v: usize) -> Option<usize> {
    v.checked_add(PAGE - 1).map(|x| x & !(PAGE - 1))
}
fn pid_for_slot(slot: usize) -> Result<ProcessId, ShmError> {
    process::pid_at_slot(slot).ok_or(ShmError::Permission)
}
fn holder(r: &Region, pid: u64) -> bool {
    r.holders.iter().any(|h| h.pid == pid && h.refs > 0)
}

pub fn create(slot: usize, size: usize) -> Result<(u32, usize, usize), ShmError> {
    let pid = pid_for_slot(slot)?.raw();
    let len = align_up(size)
        .filter(|v| *v > 0 && *v <= MAX_OBJECT)
        .ok_or(ShmError::Invalid)?;
    if REGIONS.lock().len() >= MAX_REGIONS {
        return Err(ShmError::Capacity);
    }
    let mut pages = Vec::with_capacity(len / PAGE);
    for _ in 0..len / PAGE {
        let Some(p) = phys::alloc_page() else {
            for p in pages {
                phys::free_page(p)
            }
            return Err(ShmError::NoMemory);
        };
        unsafe { core::ptr::write_bytes(p as *mut u8, 0, PAGE) };
        pages.push(p);
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed).max(1);
    REGIONS.lock().push(Region {
        id,
        owner: pid,
        len,
        pages,
        holders: alloc::vec![Holder { pid, refs: 1 }],
    });
    match map(slot, id) {
        Ok(va) => Ok((id, va, len)),
        Err(e) => {
            destroy_if_owner_only(pid, id);
            Err(e)
        }
    }
}

pub fn map(slot: usize, handle: u32) -> Result<usize, ShmError> {
    let pid = pid_for_slot(slot)?.raw();
    if let Some(m) = MAPPINGS
        .lock()
        .iter()
        .find(|m| m.pid == pid && m.handle == handle)
        .copied()
    {
        return Ok(m.va);
    }
    let mut space: AddressSpace = process::address_space(slot).ok_or(ShmError::Permission)?;
    let mut regions = REGIONS.lock();
    let r = regions
        .iter_mut()
        .find(|r| r.id == handle)
        .ok_or(ShmError::NotFound)?;
    if !holder(r, pid) {
        return Err(ShmError::Permission);
    }
    let va = find_va(pid, r.len)?;
    let mut mapped = 0usize;
    for (i, page) in r.pages.iter().copied().enumerate() {
        phys::retain_page(page);
        if unsafe { space.map_page_phys(va + i * PAGE, page, true, false) }.is_err() {
            phys::free_page(page);
            if mapped > 0 {
                unsafe {
                    space.unmap_heap_region(va, va + mapped);
                }
            }
            return Err(ShmError::Map);
        }
        mapped += PAGE;
    }
    drop(regions);
    let mut maps = MAPPINGS.lock();
    if maps.len() >= MAX_MAPPINGS {
        drop(maps);
        unsafe {
            space.unmap_heap_region(va, va + mapped);
        };
        return Err(ShmError::Capacity);
    }
    maps.push(Mapping {
        pid,
        handle,
        va,
        len: mapped,
    });
    Ok(va)
}

fn find_va(pid: u64, len: usize) -> Result<usize, ShmError> {
    let maps = MAPPINGS.lock();
    let mut candidate = SHM_BASE;
    loop {
        let end = candidate.checked_add(len).ok_or(ShmError::Capacity)?;
        if end > SHM_END {
            return Err(ShmError::Capacity);
        }
        let mut collision = None;
        for m in maps.iter().filter(|m| m.pid == pid) {
            if candidate < m.va + m.len && end > m.va {
                collision = Some(m.va + m.len);
                break;
            }
        }
        match collision {
            Some(next) => candidate = align_up(next).ok_or(ShmError::Capacity)?,
            None => return Ok(candidate),
        }
    }
}

pub fn len(slot: usize, handle: u32) -> Result<usize, ShmError> {
    let pid = pid_for_slot(slot)?.raw();
    let t = REGIONS.lock();
    let r = t
        .iter()
        .find(|r| r.id == handle)
        .ok_or(ShmError::NotFound)?;
    holder(r, pid).then_some(r.len).ok_or(ShmError::Permission)
}
pub fn retain(slot: usize, handle: u32) -> Result<(), ShmError> {
    let pid = pid_for_slot(slot)?.raw();
    let mut t = REGIONS.lock();
    let r = t
        .iter_mut()
        .find(|r| r.id == handle)
        .ok_or(ShmError::NotFound)?;
    let h = r
        .holders
        .iter_mut()
        .find(|h| h.pid == pid)
        .ok_or(ShmError::Permission)?;
    h.refs = h.refs.checked_add(1).ok_or(ShmError::Capacity)?;
    Ok(())
}

/// Owner-only transfer. The target receives a handle reference but must call map
/// itself, so the kernel always chooses the target VA and page permissions.
pub fn grant(slot: usize, handle: u32, target: ProcessId) -> Result<(), ShmError> {
    let pid = pid_for_slot(slot)?.raw();
    if process::slot_for_pid(target).is_none() {
        return Err(ShmError::NotFound);
    }
    let mut t = REGIONS.lock();
    let r = t
        .iter_mut()
        .find(|r| r.id == handle)
        .ok_or(ShmError::NotFound)?;
    if r.owner != pid {
        return Err(ShmError::Permission);
    }
    if let Some(h) = r.holders.iter_mut().find(|h| h.pid == target.raw()) {
        h.refs = h.refs.checked_add(1).ok_or(ShmError::Capacity)?
    } else {
        r.holders.push(Holder {
            pid: target.raw(),
            refs: 1,
        })
    }
    Ok(())
}

pub fn release(slot: usize, handle: u32) -> Result<(), ShmError> {
    let pid = pid_for_slot(slot)?.raw();
    let remove_holder = {
        let mut t = REGIONS.lock();
        let r = t
            .iter_mut()
            .find(|r| r.id == handle)
            .ok_or(ShmError::NotFound)?;
        let i = r
            .holders
            .iter()
            .position(|h| h.pid == pid)
            .ok_or(ShmError::Permission)?;
        if r.holders[i].refs > 1 {
            r.holders[i].refs -= 1;
            false
        } else {
            r.holders.swap_remove(i);
            true
        }
    };
    if remove_holder {
        unmap_pid_handle(pid, handle);
    }
    reap_empty(handle);
    Ok(())
}

fn unmap_pid_handle(pid: u64, handle: u32) {
    let mapping = {
        let mut maps = MAPPINGS.lock();
        maps.iter()
            .position(|m| m.pid == pid && m.handle == handle)
            .map(|i| maps.swap_remove(i))
    };
    let Some(m) = mapping else { return };
    let Some(slot) = process::slot_for_pid(ProcessId::new(pid)) else {
        return;
    };
    let Some(space) = process::address_space(slot) else {
        return;
    };
    unsafe {
        space.unmap_heap_region(m.va, m.va + m.len);
    }
}
fn reap_empty(handle: u32) {
    let dead = {
        let mut t = REGIONS.lock();
        t.iter()
            .position(|r| r.id == handle && r.holders.is_empty())
            .map(|i| t.swap_remove(i))
    };
    if let Some(r) = dead {
        for p in r.pages {
            phys::free_page(p)
        }
    }
}
fn destroy_if_owner_only(pid: u64, handle: u32) {
    let dead = {
        let mut t = REGIONS.lock();
        t.iter()
            .position(|r| r.id == handle && r.owner == pid)
            .map(|i| t.swap_remove(i))
    };
    if let Some(r) = dead {
        for p in r.pages {
            phys::free_page(p)
        }
    }
}

/// Process-reap hook: remove all mappings and handle refs, then reclaim empty objects.
pub fn on_process_gone(pid: ProcessId) {
    let raw = pid.raw();
    // Address space is already being destroyed on most reap paths, so only forget
    // mapping metadata here; page refs are drained by address-space destruction.
    MAPPINGS.lock().retain(|m| m.pid != raw);
    let mut empty = Vec::new();
    {
        let mut t = REGIONS.lock();
        for r in t.iter_mut() {
            r.holders.retain(|h| h.pid != raw);
            if r.holders.is_empty() {
                empty.push(r.id)
            }
        }
    }
    for h in empty {
        reap_empty(h)
    }
}

pub fn physical_address(_slot: usize, _handle: u32) -> Result<usize, ShmError> {
    Err(ShmError::Permission)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn align_and_window() {
        assert_eq!(align_up(1), Some(4096));
        assert_eq!(align_up(4096), Some(4096));
        assert_eq!(SHM_END - SHM_BASE, 256 * 1024 * 1024)
    }
    #[test]
    fn holder_policy_is_explicit() {
        let r = Region {
            id: 1,
            owner: 7,
            len: PAGE,
            pages: Vec::new(),
            holders: alloc::vec![Holder { pid: 7, refs: 1 }],
        };
        assert!(holder(&r, 7));
        assert!(!holder(&r, 8));
    }
}
