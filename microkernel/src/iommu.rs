//! ARM SMMUv3 DMA domain manager (Knife 38).
//!
//! The SMMU is discovered from ACPI IORT. PCI requester IDs start in BYPASS so
//! enabling the unit cannot regress devices which are still using direct DMA.
//! Drivers that opt in receive an opaque [`DomainId`] and IOVA mappings; physical
//! addresses stay inside EL1. Runtime STE/page-table changes are made visible via
//! the architectural command queue (CFGI + S12 VMALL + CMD_SYNC).

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::mm::phys;

const CR0: usize = 0x20;
const CR0ACK: usize = 0x24;
const STRTAB_BASE: usize = 0x80;
const STRTAB_BASE_CFG: usize = 0x88;
const CMDQ_BASE: usize = 0x90;
const CMDQ_PROD: usize = 0x98;
const CMDQ_CONS: usize = 0x9c;
const EVTQ_BASE: usize = 0xa0;
const EVTQ_PROD: usize = 0xa8;
const EVTQ_CONS: usize = 0xac;
const IDR0: usize = 0x00;
const IDR1: usize = 0x04;
const IDR5: usize = 0x14;

const CR0_SMMUEN: u32 = 1 << 0;
const CR0_EVTQEN: u32 = 1 << 2;
const CR0_CMDQEN: u32 = 1 << 3;
const CR0_WANT: u32 = CR0_SMMUEN | CR0_EVTQEN | CR0_CMDQEN;

const STE_DWORDS: usize = 8;
const STE_BYTES: usize = STE_DWORDS * 8;
const STE_VALID: u64 = 1;
const STE_CFG_BYPASS: u64 = 4 << 1;
const STE_CFG_S2_TRANS: u64 = 6 << 1;

// Command queue: 4KiB / 16-byte command = 256 entries.
const CMDQ_LOG2: u32 = 8;
const CMDQ_ENTRIES: u32 = 1 << CMDQ_LOG2;
const CMDQ_INDEX_MASK: u32 = CMDQ_ENTRIES - 1;
const CMDQ_PTR_MASK: u32 = (CMDQ_ENTRIES << 1) - 1; // index + wrap bit
const CMDQ_OP_CFGI_STE: u64 = 0x03;
const CMDQ_OP_TLBI_S12_VMALL: u64 = 0x28;
const CMDQ_OP_SYNC: u64 = 0x46;

const EVTQ_LOG2: u32 = 4; // 16 x 32B = 512B (one allocated page)
const EVTQ_ENTRIES: u32 = 1 << EVTQ_LOG2;
const EVTQ_INDEX_MASK: u32 = EVTQ_ENTRIES - 1;

const PAGE: usize = 4096;
const DMA_IOVA_BASE: u64 = 0x0100_0000;
const DMA_IOVA_END: u64 = 0x8000_0000;
const IOVA_FAULT: u64 = 0x0030_0000;
const TEST_LEN: u32 = 64;
const ITD_ERR_TX_FAIL: u32 = 0xdead_0002;

static READY: AtomicBool = AtomicBool::new(false);
static NEXT_DOMAIN: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IommuError {
    NotReady,
    Invalid,
    Busy,
    NoMemory,
    NotFound,
    Hardware,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DomainId(u32);

#[derive(Debug, Clone)]
struct Mapping {
    iova: u64,
    phys: usize,
    pages: usize,
}

#[derive(Debug)]
struct Domain {
    id: DomainId,
    sid: u16,
    vmid: u16,
    root: usize,
    mappings: Vec<Mapping>,
}

/// Kernel-owned DMA object. Drivers see `iova()` and length; the backing PA is
/// intentionally private to this module so EL0 can never obtain it through the
/// DMA API. This mirrors the opaque-handle policy used by secure SHM.
pub struct DmaBuffer {
    domain: DomainId,
    iova: u64,
    phys: usize,
    pages: usize,
    len: usize,
}
impl DmaBuffer {
    pub fn iova(&self) -> u64 {
        self.iova
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

struct SmmuState {
    base: usize,
    stream: usize,
    stream_entries: usize,
    evtq: usize,
    cmdq: usize,
    cmd_prod: u32,
}
unsafe impl Send for SmmuState {}

static STATE: Mutex<Option<SmmuState>> = Mutex::new(None);
static DOMAINS: Mutex<Vec<Domain>> = Mutex::new(Vec::new());

#[inline]
unsafe fn r32(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}
#[inline]
unsafe fn w32(base: usize, off: usize, v: u32) {
    write_volatile((base + off) as *mut u32, v)
}
#[inline]
unsafe fn w64(base: usize, off: usize, v: u64) {
    write_volatile((base + off) as *mut u64, v)
}

#[inline(always)]
fn dma_barrier() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb oshst", "isb", options(nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

fn alloc_aligned_pages(pages: usize, align_pages: usize) -> Option<usize> {
    if pages == 0 || !align_pages.is_power_of_two() {
        return None;
    }
    let raw_pages = pages.checked_add(align_pages.saturating_sub(1))?;
    let raw = phys::alloc_pages_contiguous(raw_pages)?;
    let align = align_pages * PAGE;
    let aligned = (raw + align - 1) & !(align - 1);
    let prefix = (aligned - raw) / PAGE;
    for i in 0..prefix {
        phys::free_page(raw + i * PAGE);
    }
    for i in prefix + pages..raw_pages {
        phys::free_page(raw + i * PAGE);
    }
    Some(aligned)
}

unsafe fn zero_pages(base: usize, pages: usize) {
    write_bytes(base as *mut u8, 0, pages * PAGE);
}

unsafe fn write_ste(stream: usize, sid: u16, words: [u64; STE_DWORDS]) {
    let p = (stream + sid as usize * STE_BYTES) as *mut u64;
    for (i, word) in words.iter().enumerate() {
        write_volatile(p.add(i), *word);
    }
}

unsafe fn make_bypass_table(stream: usize, count: usize) {
    zero_pages(stream, (count * STE_BYTES).div_ceil(PAGE));
    for sid in 0..count {
        write_ste(
            stream,
            sid as u16,
            [STE_VALID | STE_CFG_BYPASS, 0, 0, 0, 0, 0, 0, 0],
        );
    }
}

fn vtcr_32bit_4k() -> u64 {
    // S2T0SZ=32, S2SL0=1 (L1 start), WBWA inner/outer, inner-shareable,
    // TG0=4KiB, PS=44-bit. QEMU advertises 44-bit OAS in the validation matrix.
    32 | (1 << 6) | (1 << 8) | (1 << 10) | (3 << 12) | (4 << 16)
}

unsafe fn install_s2_ste(stream: usize, sid: u16, vmid: u16, root: usize) {
    let vtcr = vtcr_32bit_4k();
    let word2 = (vmid as u64) | (vtcr << 32) | (1 << 51) | (1 << 58); // S2AA64 + record faults
    write_ste(
        stream,
        sid,
        [
            STE_VALID | STE_CFG_S2_TRANS,
            0,
            word2,
            root as u64,
            0,
            0,
            0,
            0,
        ],
    );
}

unsafe fn install_bypass_ste(stream: usize, sid: u16) {
    write_ste(
        stream,
        sid,
        [STE_VALID | STE_CFG_BYPASS, 0, 0, 0, 0, 0, 0, 0],
    );
}

fn wait_ack(base: usize, want: u32) -> bool {
    for _ in 0..1_000_000 {
        if unsafe { r32(base, CR0ACK) } & CR0_WANT == want & CR0_WANT {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Submit one 16-byte SMMUv3 command and wait until the consumer has passed it.
/// This is deliberately synchronous: Zero OS currently has low command volume,
/// and correctness of DMA ownership changes is more important than batching.
unsafe fn cmdq_submit(s: &mut SmmuState, cmd: [u64; 2]) -> bool {
    let slot = (s.cmd_prod & CMDQ_INDEX_MASK) as usize;
    let p = (s.cmdq + slot * 16) as *mut u64;
    write_volatile(p, cmd[0]);
    write_volatile(p.add(1), cmd[1]);
    dma_barrier();
    let next = s.cmd_prod.wrapping_add(1) & CMDQ_PTR_MASK;
    w32(s.base, CMDQ_PROD, next);
    for _ in 0..1_000_000 {
        let cons = r32(s.base, CMDQ_CONS) & CMDQ_PTR_MASK;
        if cons == next {
            s.cmd_prod = next;
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

unsafe fn cmdq_sync(s: &mut SmmuState) -> bool {
    cmdq_submit(s, [CMDQ_OP_SYNC, 0])
}
unsafe fn invalidate_ste(s: &mut SmmuState, sid: u16) -> bool {
    cmdq_submit(s, [CMDQ_OP_CFGI_STE | ((sid as u64) << 32), 1]) && cmdq_sync(s)
}
unsafe fn invalidate_vmid(s: &mut SmmuState, vmid: u16) -> bool {
    cmdq_submit(s, [CMDQ_OP_TLBI_S12_VMALL | ((vmid as u64) << 32), 0]) && cmdq_sync(s)
}

#[inline]
fn table_valid(v: u64) -> bool {
    v & 1 != 0
}
#[inline]
fn table_ptr(v: u64) -> usize {
    (v & 0x0000_ffff_ffff_f000) as usize
}

unsafe fn s2_map_page(root: usize, iova: u64, pa: usize) -> Result<(), IommuError> {
    if iova & 0xfff != 0 || pa & 0xfff != 0 || iova >= (1u64 << 32) {
        return Err(IommuError::Invalid);
    }
    let l1 = root as *mut u64;
    let i1 = ((iova >> 30) & 0x1ff) as usize;
    let i2 = ((iova >> 21) & 0x1ff) as usize;
    let i3 = ((iova >> 12) & 0x1ff) as usize;
    let e1 = read_volatile(l1.add(i1));
    let l2p = if table_valid(e1) {
        table_ptr(e1)
    } else {
        let p = phys::alloc_page().ok_or(IommuError::NoMemory)?;
        zero_pages(p, 1);
        write_volatile(l1.add(i1), (p as u64) | 0b11);
        p
    };
    let l2 = l2p as *mut u64;
    let e2 = read_volatile(l2.add(i2));
    let l3p = if table_valid(e2) {
        table_ptr(e2)
    } else {
        let p = phys::alloc_page().ok_or(IommuError::NoMemory)?;
        zero_pages(p, 1);
        write_volatile(l2.add(i2), (p as u64) | 0b11);
        p
    };
    let l3 = l3p as *mut u64;
    if table_valid(read_volatile(l3.add(i3))) {
        return Err(IommuError::Busy);
    }
    // Stage-2 page: Normal WB, RW, Inner-shareable, AF, page descriptor.
    let leaf = (pa as u64 & 0x0000_ffff_ffff_f000)
        | (0x0f << 2)
        | (0b11 << 6)
        | (0b11 << 8)
        | (1 << 10)
        | 0b11;
    write_volatile(l3.add(i3), leaf);
    Ok(())
}

unsafe fn s2_unmap_page(root: usize, iova: u64) -> bool {
    if iova & 0xfff != 0 || iova >= (1u64 << 32) {
        return false;
    }
    let l1 = root as *mut u64;
    let i1 = ((iova >> 30) & 0x1ff) as usize;
    let i2 = ((iova >> 21) & 0x1ff) as usize;
    let i3 = ((iova >> 12) & 0x1ff) as usize;
    let e1 = read_volatile(l1.add(i1));
    if !table_valid(e1) {
        return false;
    }
    let l2 = table_ptr(e1) as *mut u64;
    let e2 = read_volatile(l2.add(i2));
    if !table_valid(e2) {
        return false;
    }
    let l3 = table_ptr(e2) as *mut u64;
    if !table_valid(read_volatile(l3.add(i3))) {
        return false;
    }
    write_volatile(l3.add(i3), 0);
    true
}

unsafe fn free_s2_tables(root: usize) {
    let l1 = root as *mut u64;
    for i1 in 0..512 {
        let e1 = read_volatile(l1.add(i1));
        if !table_valid(e1) {
            continue;
        }
        let l2p = table_ptr(e1);
        let l2 = l2p as *mut u64;
        for i2 in 0..512 {
            let e2 = read_volatile(l2.add(i2));
            if table_valid(e2) {
                phys::free_page(table_ptr(e2));
            }
        }
        phys::free_page(l2p);
    }
    phys::free_page(root);
}

fn choose_iova(mappings: &[Mapping], pages: usize) -> Option<u64> {
    let bytes = (pages as u64).checked_mul(PAGE as u64)?;
    let mut candidate = DMA_IOVA_BASE;
    loop {
        let end = candidate.checked_add(bytes)?;
        if end > DMA_IOVA_END {
            return None;
        }
        let mut collision_end = None;
        for m in mappings {
            let m_end = m.iova + (m.pages as u64) * PAGE as u64;
            if candidate < m_end && end > m.iova {
                collision_end = Some(m_end);
                break;
            }
        }
        match collision_end {
            Some(v) => candidate = (v + 0xfff) & !0xfff,
            None => return Some(candidate),
        }
    }
}

/// Create and attach a stage-2 domain to one PCI requester ID (SID/RID).
pub fn create_domain(sid: u16) -> Result<DomainId, IommuError> {
    if !READY.load(Ordering::Acquire) {
        return Err(IommuError::NotReady);
    }
    if DOMAINS.lock().iter().any(|d| d.sid == sid) {
        return Err(IommuError::Busy);
    }
    let root = phys::alloc_page().ok_or(IommuError::NoMemory)?;
    unsafe {
        zero_pages(root, 1);
    }
    let raw_id = NEXT_DOMAIN.fetch_add(1, Ordering::SeqCst);
    let id = DomainId(raw_id);
    let vmid = ((raw_id - 1) % 0xfffe + 1) as u16;
    {
        let mut state = STATE.lock();
        let s = state.as_mut().ok_or(IommuError::NotReady)?;
        if sid as usize >= s.stream_entries {
            phys::free_page(root);
            return Err(IommuError::Invalid);
        }
        unsafe {
            install_s2_ste(s.stream, sid, vmid, root);
            dma_barrier();
            if !invalidate_ste(s, sid) {
                install_bypass_ste(s.stream, sid);
                phys::free_page(root);
                return Err(IommuError::Hardware);
            }
        }
    }
    DOMAINS.lock().push(Domain {
        id,
        sid,
        vmid,
        root,
        mappings: Vec::new(),
    });
    Ok(id)
}

/// Map a physically-contiguous range and return its first IOVA.
pub fn map_contiguous(domain: DomainId, pa: usize, len: usize) -> Result<u64, IommuError> {
    if len == 0 || pa & (PAGE - 1) != 0 {
        return Err(IommuError::Invalid);
    }
    let pages = len.div_ceil(PAGE);
    let (iova, root, vmid) = {
        let mut domains = DOMAINS.lock();
        let d = domains
            .iter_mut()
            .find(|d| d.id == domain)
            .ok_or(IommuError::NotFound)?;
        let iova = choose_iova(&d.mappings, pages).ok_or(IommuError::NoMemory)?;
        let mut done = 0usize;
        while done < pages {
            if let Err(e) =
                unsafe { s2_map_page(d.root, iova + (done * PAGE) as u64, pa + done * PAGE) }
            {
                for n in 0..done {
                    unsafe {
                        s2_unmap_page(d.root, iova + (n * PAGE) as u64);
                    }
                }
                return Err(e);
            }
            done += 1;
        }
        d.mappings.push(Mapping {
            iova,
            phys: pa,
            pages,
        });
        (iova, d.root, d.vmid)
    };
    let _ = root;
    dma_barrier();
    let mut state = STATE.lock();
    if !unsafe { invalidate_vmid(state.as_mut().ok_or(IommuError::NotReady)?, vmid) } {
        return Err(IommuError::Hardware);
    }
    Ok(iova)
}

pub fn unmap(domain: DomainId, iova: u64) -> Result<(), IommuError> {
    let vmid = {
        let mut domains = DOMAINS.lock();
        let d = domains
            .iter_mut()
            .find(|d| d.id == domain)
            .ok_or(IommuError::NotFound)?;
        let pos = d
            .mappings
            .iter()
            .position(|m| m.iova == iova)
            .ok_or(IommuError::NotFound)?;
        let m = d.mappings.remove(pos);
        for n in 0..m.pages {
            unsafe {
                s2_unmap_page(d.root, m.iova + (n * PAGE) as u64);
            }
        }
        d.vmid
    };
    dma_barrier();
    let mut state = STATE.lock();
    if !unsafe { invalidate_vmid(state.as_mut().ok_or(IommuError::NotReady)?, vmid) } {
        return Err(IommuError::Hardware);
    }
    Ok(())
}

pub fn alloc_dma(domain: DomainId, len: usize) -> Result<DmaBuffer, IommuError> {
    if len == 0 {
        return Err(IommuError::Invalid);
    }
    let pages = len.div_ceil(PAGE);
    let phys_base = phys::alloc_pages_contiguous(pages).ok_or(IommuError::NoMemory)?;
    unsafe {
        zero_pages(phys_base, pages);
    }
    match map_contiguous(domain, phys_base, len) {
        Ok(iova) => Ok(DmaBuffer {
            domain,
            iova,
            phys: phys_base,
            pages,
            len,
        }),
        Err(e) => {
            for n in 0..pages {
                phys::free_page(phys_base + n * PAGE);
            }
            Err(e)
        }
    }
}

pub fn free_dma(buffer: DmaBuffer) -> Result<(), IommuError> {
    unmap(buffer.domain, buffer.iova)?;
    for n in 0..buffer.pages {
        phys::free_page(buffer.phys + n * PAGE);
    }
    Ok(())
}

pub fn destroy_domain(id: DomainId) -> Result<(), IommuError> {
    let (sid, root) = {
        let mut domains = DOMAINS.lock();
        let pos = domains
            .iter()
            .position(|d| d.id == id)
            .ok_or(IommuError::NotFound)?;
        if !domains[pos].mappings.is_empty() {
            return Err(IommuError::Busy);
        }
        let d = domains.remove(pos);
        (d.sid, d.root)
    };
    {
        let mut state = STATE.lock();
        let s = state.as_mut().ok_or(IommuError::NotReady)?;
        unsafe {
            install_bypass_ste(s.stream, sid);
            dma_barrier();
            if !invalidate_ste(s, sid) {
                return Err(IommuError::Hardware);
            }
        }
    }
    unsafe {
        free_s2_tables(root);
    }
    Ok(())
}

/// Initialise the first ACPI-IORT SMMUv3. Returns false if the platform has none.
pub fn init() -> bool {
    let Some(info) = crate::acpi::smmu_v3_units().into_iter().next() else {
        return false;
    };
    let base = info.base as usize;
    let idr0 = unsafe { r32(base, IDR0) };
    let idr1 = unsafe { r32(base, IDR1) };
    let idr5 = unsafe { r32(base, IDR5) };
    crate::info!(
        "smmuv3: IORT base={:#x} event_irq={} RID=[{:#x},+{:#x}) idr0={:#x} idr1={:#x} idr5={:#x}",
        base,
        info.event_irq,
        info.rid_start,
        info.rid_count,
        idr0,
        idr1,
        idr5
    );

    // IORT root-complex mapping tells us the requester-ID range. Round up to a
    // power of two for a linear stream table, capped at 16-bit SIDs.
    let wanted = (info.rid_start as usize)
        .saturating_add(info.rid_count as usize)
        .max(256);
    let stream_entries = wanted.next_power_of_two().min(65536);
    let stream_pages = (stream_entries * STE_BYTES).div_ceil(PAGE);
    let stream_align_pages = stream_pages.next_power_of_two().max(1);
    let Some(stream) = alloc_aligned_pages(stream_pages, stream_align_pages) else {
        crate::warn!("smmuv3: stream table allocation failed");
        return false;
    };
    let Some(evtq) = phys::alloc_page() else {
        return false;
    };
    let Some(cmdq) = phys::alloc_page() else {
        return false;
    };
    unsafe {
        make_bypass_table(stream, stream_entries);
        zero_pages(evtq, 1);
        zero_pages(cmdq, 1);
        w64(base, STRTAB_BASE, stream as u64);
        w32(base, STRTAB_BASE_CFG, stream_entries.trailing_zeros());
        w64(base, CMDQ_BASE, cmdq as u64 | CMDQ_LOG2 as u64);
        w32(base, CMDQ_PROD, 0);
        w32(base, CMDQ_CONS, 0);
        w64(base, EVTQ_BASE, evtq as u64 | EVTQ_LOG2 as u64);
        w32(base, EVTQ_PROD, 0);
        w32(base, EVTQ_CONS, 0);
        dma_barrier();
        w32(base, CR0, CR0_WANT);
    }
    if !wait_ack(base, CR0_WANT) {
        crate::warn!("smmuv3: CR0 enable timeout ack={:#x}", unsafe {
            r32(base, CR0ACK)
        });
        return false;
    }
    *STATE.lock() = Some(SmmuState {
        base,
        stream,
        stream_entries,
        evtq,
        cmdq,
        cmd_prod: 0,
    });
    DOMAINS.lock().clear();
    READY.store(true, Ordering::Release);
    crate::info!("smmuv3: enabled; CMDQ+EVTQ online, default PCI RID policy=BYPASS");
    self_test();
    true
}

fn itd_write(base: usize, off: usize, val: u32) {
    unsafe { write_volatile((base + off) as *mut u32, val) }
}
fn itd_read(base: usize, off: usize) -> u32 {
    unsafe { read_volatile((base + off) as *const u32) }
}
fn program_itd(base: usize, iova: u64, pa: u64) {
    itd_write(base, 0x04, iova as u32);
    itd_write(base, 0x08, (iova >> 32) as u32);
    itd_write(base, 0x0c, TEST_LEN);
    itd_write(base, 0x1c, pa as u32);
    itd_write(base, 0x20, (pa >> 32) as u32);
    itd_write(base, 0x18, 1 << 1); // NonSecure space
    itd_write(base, 0x14, 1); // arm
    let _ = itd_read(base, 0x00); // trigger on read
}

fn self_test() {
    let Some(dev) = crate::pci::find(0x1b36, 0x0005) else {
        crate::info!("smmuv3: iommu-testdev absent; self-test skipped");
        return;
    };
    if dev.bar(0).is_none() || dev.bar(1).is_some() {
        crate::info!(
            "smmuv3: RedHat test device is pci-testdev, not iommu-testdev; self-test skipped"
        );
        return;
    }
    let sid = dev.address.requester_id();
    let Some(mmio) = crate::pci::bar_mmio_ptr(&dev, 0, 0, 0x1000) else {
        return;
    };
    let cmd = crate::pci::read_u16(dev.address, 0x04).unwrap_or(0);
    let _ = crate::pci::write_u16(dev.address, 0x04, cmd | 0x2 | 0x4);

    let Ok(domain) = create_domain(sid) else {
        crate::warn!("smmuv3: domain create failed sid={:#x}", sid);
        return;
    };
    let Ok(buf) = alloc_dma(domain, PAGE) else {
        crate::warn!("smmuv3: DMA buffer allocation failed");
        let _ = destroy_domain(domain);
        return;
    };
    program_itd(mmio, buf.iova(), buf.phys as u64);
    let ok = itd_read(mmio, 0x10);
    if ok != 0 {
        crate::warn!("smmuv3: mapped IOVA DMA FAIL result={:#x}", ok);
        let _ = free_dma(buf);
        let _ = destroy_domain(domain);
        return;
    }
    crate::info!(
        "smmuv3: mapped IOVA DMA PASS sid={:#x} iova={:#x} pa={:#x}",
        sid,
        buf.iova(),
        buf.phys
    );

    let (smmu, evtq, before) = {
        let state = STATE.lock();
        let s = state.as_ref().unwrap();
        (s.base, s.evtq, unsafe { r32(s.base, EVTQ_PROD) })
    };
    program_itd(mmio, IOVA_FAULT, buf.phys as u64);
    let fault_result = itd_read(mmio, 0x10);
    let after = unsafe { r32(smmu, EVTQ_PROD) };
    let slot = (before & EVTQ_INDEX_MASK) as usize;
    let ep = evtq + slot * 32;
    let event = unsafe { read_volatile(ep as *const u32) } & 0xff;
    let event_sid = unsafe { read_volatile((ep + 4) as *const u32) };
    if fault_result == ITD_ERR_TX_FAIL
        && after != before
        && event == 0x10
        && event_sid == sid as u32
    {
        crate::info!(
            "smmuv3: UNMAPPED IOVA FAULT PASS sid={:#x} iova={:#x} event=0x{:x}",
            sid,
            IOVA_FAULT,
            event
        );
        unsafe { w32(smmu, EVTQ_CONS, after) };
    } else {
        crate::warn!(
            "smmuv3: fault test FAIL result={:#x} prod={:#x}->{:#x} event={:#x} sid={:#x}",
            fault_result,
            before,
            after,
            event,
            event_sid
        );
    }

    // Exercise production unmap/detach paths too; test success means the domain
    // can return to BYPASS without leaking a physical page or stale translation.
    if free_dma(buf).is_ok() && destroy_domain(domain).is_ok() {
        crate::info!("smmuv3: DOMAIN MAP/UNMAP/DETACH PASS");
    }
}

pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vtcr_geometry_is_32bit_level1_4k() {
        let vtcr = vtcr_32bit_4k();
        assert_eq!(vtcr & 0x3f, 32);
        assert_eq!((vtcr >> 6) & 3, 1);
        assert_eq!((vtcr >> 14) & 3, 0);
        assert_eq!((vtcr >> 16) & 7, 4);
    }

    #[test]
    fn iova_first_fit_reuses_hole() {
        let m = [
            Mapping {
                iova: DMA_IOVA_BASE,
                phys: 0x4000_0000,
                pages: 2,
            },
            Mapping {
                iova: DMA_IOVA_BASE + 4 * PAGE as u64,
                phys: 0x4000_4000,
                pages: 1,
            },
        ];
        assert_eq!(choose_iova(&m, 2), Some(DMA_IOVA_BASE + 2 * PAGE as u64));
    }

    #[test]
    fn command_encodings_match_smmuv3_fields() {
        let sid = 0x123u16;
        let vmid = 7u16;
        assert_eq!(CMDQ_OP_CFGI_STE | ((sid as u64) << 32), 0x123_0000_0003);
        assert_eq!(
            CMDQ_OP_TLBI_S12_VMALL | ((vmid as u64) << 32),
            0x7_0000_0028
        );
        assert_eq!(CMDQ_OP_SYNC, 0x46);
    }
}
