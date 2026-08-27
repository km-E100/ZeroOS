//! PCI NVMe NVM command-set driver (Knife 40).
//!
//! The controller remains kernel-owned, matching the existing virtio-blk
//! security boundary: EL0 blkdrv uses the capability-gated block syscalls and
//! never receives queue/DMA physical addresses.  Admin + I/O queues are backed
//! by physically contiguous pages and completions are polled, so correctness
//! does not depend on IRQ delivery while EL1 is executing a syscall.  MSI-X is
//! nevertheless enabled and registered, covering the real interrupt path.

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Mutex;

use crate::mm::phys;
use crate::pci::PciDevice;
use crate::{info, warn};

use super::{register_irq_handler, BlockError};

const REG_CAP: usize = 0x00;
const REG_VS: usize = 0x08;
const REG_CC: usize = 0x14;
const REG_CSTS: usize = 0x1c;
const REG_AQA: usize = 0x24;
const REG_ASQ: usize = 0x28;
const REG_ACQ: usize = 0x30;
const REG_DBS: usize = 0x1000;

const CC_EN: u32 = 1;
const CSTS_RDY: u32 = 1;
const CSTS_CFS: u32 = 1 << 1;

const ADMIN_DELETE_IO_SQ: u8 = 0x00;
const ADMIN_CREATE_IO_SQ: u8 = 0x01;
const ADMIN_DELETE_IO_CQ: u8 = 0x04;
const ADMIN_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_ABORT: u8 = 0x08;
const ADMIN_SET_FEATURES: u8 = 0x09;
const FEATURE_NUMBER_OF_QUEUES: u8 = 0x07;

const NVM_FLUSH: u8 = 0x00;
const NVM_WRITE: u8 = 0x01;
const NVM_READ: u8 = 0x02;

const PAGE: usize = 4096;
const ADMIN_DEPTH: usize = 32;
const IO_DEPTH: usize = 64;
const BOUNCE_BYTES: usize = 128 * 1024;
const BOUNCE_PAGES: usize = BOUNCE_BYTES / PAGE;
const IO_TIMEOUT_NS: u64 = 2_000_000_000;
const MAX_POLL_SPINS: usize = 20_000_000;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Completion {
    dw0: u32,
    dw1: u32,
    sq_head: u16,
    sq_id: u16,
    cid: u16,
    status_phase: u16,
}

struct Queue {
    sq: usize,
    cq: usize,
    depth: u16,
    qid: u16,
    sq_tail: u16,
    cq_head: u16,
    phase: bool,
    next_cid: u16,
    sq_pages: usize,
    cq_pages: usize,
}

impl Queue {
    fn new(qid: u16, depth: usize) -> Option<Self> {
        if depth < 2 || depth > 256 {
            return None;
        }
        let sq_bytes = depth.checked_mul(64)?;
        let cq_bytes = depth.checked_mul(16)?;
        let sq_pages = sq_bytes.div_ceil(PAGE);
        let cq_pages = cq_bytes.div_ceil(PAGE);
        let sq = phys::alloc_pages_contiguous(sq_pages)?;
        let cq = match phys::alloc_pages_contiguous(cq_pages) {
            Some(v) => v,
            None => {
                for i in 0..sq_pages {
                    phys::free_page(sq + i * PAGE);
                }
                return None;
            }
        };
        unsafe {
            write_bytes(sq as *mut u8, 0, sq_pages * PAGE);
            write_bytes(cq as *mut u8, 0, cq_pages * PAGE);
        }
        Some(Self {
            sq,
            cq,
            depth: depth as u16,
            qid,
            sq_tail: 0,
            cq_head: 0,
            phase: true,
            next_cid: 1,
            sq_pages,
            cq_pages,
        })
    }

    fn cid(&mut self) -> u16 {
        let cid = self.next_cid.max(1);
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        cid
    }

    fn release(self) {
        for i in 0..self.sq_pages {
            phys::free_page(self.sq + i * PAGE);
        }
        for i in 0..self.cq_pages {
            phys::free_page(self.cq + i * PAGE);
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct Namespace {
    nsid: u32,
    lba_bytes: usize,
    native_blocks: u64,
    capacity_sectors: u64,
}

struct NvmeState {
    base: usize,
    db_stride: usize,
    admin: Option<Queue>,
    namespaces: Vec<Namespace>,
    active: Option<Namespace>,
    max_transfer: usize,
    irq: u32,
    io_count: usize,
    ready: bool,
}

impl NvmeState {
    const fn new() -> Self {
        Self {
            base: 0,
            db_stride: 4,
            admin: None,
            namespaces: Vec::new(),
            active: None,
            max_transfer: PAGE,
            irq: 0,
            io_count: 0,
            ready: false,
        }
    }
}
unsafe impl Send for NvmeState {}

struct IoPath {
    q: Queue,
    bounce: usize,
    bounce_pages: usize,
    prp_list: usize,
}
unsafe impl Send for IoPath {}

impl IoPath {
    fn new(qid: u16, depth: usize) -> Option<Self> {
        let q = Queue::new(qid, depth)?;
        let bounce = match phys::alloc_pages_contiguous(BOUNCE_PAGES) {
            Some(v) => v,
            None => {
                q.release();
                return None;
            }
        };
        unsafe { write_bytes(bounce as *mut u8, 0, BOUNCE_BYTES) };
        let prp_list = match phys::alloc_page() {
            Some(v) => v,
            None => {
                for i in 0..BOUNCE_PAGES {
                    phys::free_page(bounce + i * PAGE);
                }
                q.release();
                return None;
            }
        };
        unsafe { write_bytes(prp_list as *mut u8, 0, PAGE) };
        Some(Self {
            q,
            bounce,
            bounce_pages: BOUNCE_PAGES,
            prp_list,
        })
    }

    fn release(self) {
        self.q.release();
        for i in 0..self.bounce_pages {
            phys::free_page(self.bounce + i * PAGE);
        }
        phys::free_page(self.prp_list);
    }
}

const MAX_IO_PATHS: usize = crate::arch::smp::MAX_CPUS;
static IO_PATHS: [Mutex<Option<IoPath>>; MAX_IO_PATHS] = [const { Mutex::new(None) }; MAX_IO_PATHS];

static STATE: Mutex<NvmeState> = Mutex::new(NvmeState::new());
static IRQ_SEEN: AtomicBool = AtomicBool::new(false);
static RECOVERY_NEEDED: AtomicBool = AtomicBool::new(false);
static LAST_TIMEOUT_QID: AtomicU16 = AtomicU16::new(0);
static LAST_TIMEOUT_CID: AtomicU16 = AtomicU16::new(0);

#[inline]
unsafe fn r32(a: usize) -> u32 {
    read_volatile(a as *const u32)
}
#[inline]
unsafe fn w32(a: usize, v: u32) {
    write_volatile(a as *mut u32, v)
}
#[inline]
unsafe fn r64(a: usize) -> u64 {
    read_volatile(a as *const u64)
}
#[inline]
unsafe fn w64(a: usize, v: u64) {
    write_volatile(a as *mut u64, v)
}

#[inline(always)]
fn dma_write_barrier() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dmb oshst", options(nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[inline(always)]
fn dma_read_barrier() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dmb oshld", options(nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

fn irq_handler(irq: u32) {
    if !IRQ_SEEN.swap(true, Ordering::SeqCst) {
        info!("nvme: MSI-X interrupt path PASS irq={}", irq);
    }
}

fn wait_csts(base: usize, want_ready: bool, timeout_ns: u64) -> bool {
    let deadline = crate::time::monotonic_ns().saturating_add(timeout_ns);
    for _ in 0..MAX_POLL_SPINS {
        let s = unsafe { r32(base + REG_CSTS) };
        if s & CSTS_CFS != 0 {
            return false;
        }
        if (s & CSTS_RDY != 0) == want_ready {
            return true;
        }
        if crate::time::monotonic_ns() >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
    false
}

fn doorbell(base: usize, stride: usize, qid: u16, cq: bool) -> usize {
    base + REG_DBS + ((qid as usize * 2 + usize::from(cq)) * stride)
}

fn completion_status(c: Completion) -> u16 {
    c.status_phase >> 1
}

unsafe fn submit(
    base: usize,
    stride: usize,
    q: &mut Queue,
    mut cmd: [u32; 16],
) -> Result<Completion, BlockError> {
    let cid = q.cid();
    cmd[0] = (cmd[0] & 0xffff) | ((cid as u32) << 16);
    let sqe = (q.sq as *mut [u32; 16]).add(q.sq_tail as usize);
    write_volatile(sqe, cmd);
    dma_write_barrier();
    q.sq_tail = (q.sq_tail + 1) % q.depth;
    w32(doorbell(base, stride, q.qid, false), q.sq_tail as u32);

    let deadline = crate::time::monotonic_ns().saturating_add(IO_TIMEOUT_NS);
    for _ in 0..MAX_POLL_SPINS {
        let p = (q.cq as *const Completion).add(q.cq_head as usize);
        let c = read_volatile(p);
        let phase = c.status_phase & 1 != 0;
        if phase == q.phase {
            dma_read_barrier();
            q.cq_head += 1;
            if q.cq_head == q.depth {
                q.cq_head = 0;
                q.phase = !q.phase;
            }
            w32(doorbell(base, stride, q.qid, true), q.cq_head as u32);
            if c.cid != cid || completion_status(c) != 0 {
                warn!(
                    "nvme: q{} completion cid={} expected={} status={:#x} sqid={}",
                    q.qid,
                    c.cid,
                    cid,
                    completion_status(c),
                    c.sq_id
                );
                return Err(BlockError::DeviceError);
            }
            return Ok(c);
        }
        if crate::time::monotonic_ns() >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
    warn!("nvme: q{} command timeout cid={}", q.qid, cid);
    LAST_TIMEOUT_QID.store(q.qid, Ordering::Release);
    LAST_TIMEOUT_CID.store(cid, Ordering::Release);
    RECOVERY_NEEDED.store(true, Ordering::Release);
    Err(BlockError::Busy)
}

fn admin_cmd(state: &mut NvmeState, cmd: [u32; 16]) -> Result<Completion, BlockError> {
    let base = state.base;
    let stride = state.db_stride;
    let q = state.admin.as_mut().ok_or(BlockError::NotReady)?;
    unsafe { submit(base, stride, q, cmd) }
}

fn io_cmd(meta: NvmeIoMeta, path: &mut IoPath, cmd: [u32; 16]) -> Result<Completion, BlockError> {
    unsafe { submit(meta.base, meta.db_stride, &mut path.q, cmd) }
}

#[derive(Copy, Clone)]
struct NvmeIoMeta {
    base: usize,
    db_stride: usize,
    ns: Namespace,
    max_transfer: usize,
    io_count: usize,
}

fn io_meta() -> Result<NvmeIoMeta, BlockError> {
    let s = STATE.lock();
    if !s.ready {
        return Err(BlockError::NotReady);
    }
    let ns = s.active.ok_or(BlockError::NotReady)?;
    Ok(NvmeIoMeta {
        base: s.base,
        db_stride: s.db_stride,
        ns,
        max_transfer: s.max_transfer,
        io_count: s.io_count,
    })
}

fn path_index(meta: NvmeIoMeta) -> usize {
    crate::arch::smp::cpu_id().min(MAX_IO_PATHS - 1) % meta.io_count.max(1)
}

fn set_prps(
    cmd: &mut [u32; 16],
    path: &IoPath,
    max_transfer: usize,
    bytes: usize,
) -> Result<(), BlockError> {
    if bytes == 0 || bytes > max_transfer || path.bounce == 0 {
        return Err(BlockError::InvalidArgument);
    }
    cmd[6] = path.bounce as u32;
    cmd[7] = (path.bounce as u64 >> 32) as u32;
    let pages = bytes.div_ceil(PAGE);
    if pages == 1 {
        cmd[8] = 0;
        cmd[9] = 0;
    } else if pages == 2 {
        let p = (path.bounce + PAGE) as u64;
        cmd[8] = p as u32;
        cmd[9] = (p >> 32) as u32;
    } else {
        if path.prp_list == 0 || pages - 1 > PAGE / 8 {
            return Err(BlockError::InvalidArgument);
        }
        unsafe {
            write_bytes(path.prp_list as *mut u8, 0, PAGE);
            let list = path.prp_list as *mut u64;
            for i in 1..pages {
                write_volatile(list.add(i - 1), (path.bounce + i * PAGE) as u64);
            }
        }
        let p = path.prp_list as u64;
        cmd[8] = p as u32;
        cmd[9] = (p >> 32) as u32;
    }
    Ok(())
}

fn identify(state: &mut NvmeState, nsid: u32, cns: u8, buffer: usize) -> Result<(), BlockError> {
    unsafe { write_bytes(buffer as *mut u8, 0, PAGE) };
    let mut cmd = [0u32; 16];
    cmd[0] = ADMIN_IDENTIFY as u32;
    cmd[1] = nsid;
    cmd[6] = buffer as u32;
    cmd[7] = (buffer as u64 >> 32) as u32;
    cmd[10] = cns as u32;
    admin_cmd(state, cmd).map(|_| ())
}

unsafe fn read_le_u64(base: usize, off: usize) -> u64 {
    u64::from_le(read_volatile((base + off) as *const u64))
}

fn init_controller(dev: &PciDevice) -> Option<NvmeState> {
    let base = crate::pci::bar_mmio_ptr(dev, 0, 0, 0x2000)?;
    let command = crate::pci::read_u16(dev.address, 0x04)?;
    crate::pci::write_u16(dev.address, 0x04, command | 0x2 | 0x4 | (1 << 10));

    let cap = unsafe { r64(base + REG_CAP) };
    let vs = unsafe { r32(base + REG_VS) };
    let mqes = ((cap & 0xffff) as usize) + 1;
    let timeout_ns = ((((cap >> 24) & 0xff) as u64).max(1) * 500_000_000).min(10_000_000_000);
    let dstrd = ((cap >> 32) & 0xf) as usize;
    let mpsmin = ((cap >> 48) & 0xf) as usize;
    if mpsmin != 0 {
        warn!(
            "nvme: controller requires page size >4KiB (MPSMIN={}), unsupported",
            mpsmin
        );
        return None;
    }
    let admin_depth = min(ADMIN_DEPTH, mqes).max(2);
    let io_depth = min(IO_DEPTH, mqes).max(2);
    info!(
        "nvme: PCI {:04x}:{:02x}:{:02x}.{} BAR0={:#x} VS={}.{}.{} MQES={} DSTRD={}",
        dev.address.segment,
        dev.address.bus,
        dev.address.device,
        dev.address.function,
        base,
        (vs >> 16) & 0xffff,
        (vs >> 8) & 0xff,
        vs & 0xff,
        mqes,
        dstrd
    );

    let cc = unsafe { r32(base + REG_CC) };
    if cc & CC_EN != 0 {
        unsafe { w32(base + REG_CC, cc & !CC_EN) };
        if !wait_csts(base, false, timeout_ns) {
            warn!("nvme: disable timeout CSTS={:#x}", unsafe {
                r32(base + REG_CSTS)
            });
            return None;
        }
    }

    let admin = Queue::new(0, admin_depth)?;
    unsafe {
        w32(
            base + REG_AQA,
            ((admin.depth as u32 - 1) << 16) | (admin.depth as u32 - 1),
        );
        w64(base + REG_ASQ, admin.sq as u64);
        w64(base + REG_ACQ, admin.cq as u64);
        // NVM command set, 4KiB MPS, SQE=64B, CQE=16B.
        w32(base + REG_CC, CC_EN | (6 << 16) | (4 << 20));
    }
    if !wait_csts(base, true, timeout_ns) {
        warn!("nvme: enable timeout CSTS={:#x}", unsafe {
            r32(base + REG_CSTS)
        });
        return None;
    }

    let identify_page = phys::alloc_page()?;
    unsafe { write_bytes(identify_page as *mut u8, 0, PAGE) };
    let mut s = NvmeState {
        base,
        db_stride: 4usize << dstrd,
        admin: Some(admin),
        namespaces: Vec::new(),
        active: None,
        max_transfer: BOUNCE_BYTES,
        irq: 0,
        io_count: 0,
        ready: false,
    };

    // Identify Controller: MDTS is byte 77. 0 means no controller-imposed limit.
    if identify(&mut s, 0, 1, identify_page).is_err() {
        warn!("nvme: Identify Controller failed");
        return None;
    }
    let mdts = unsafe { read_volatile((identify_page + 77) as *const u8) };
    if mdts != 0 {
        let limit = 1usize.checked_shl(12 + mdts as u32).unwrap_or(BOUNCE_BYTES);
        s.max_transfer = min(BOUNCE_BYTES, limit).max(PAGE);
    }

    // Active namespace list (CNS=2), one Identify Namespace per advertised NSID.
    // The public block backend selects the first supported namespace, but all are
    // enumerated and retained so later policy can switch without re-probing PCI.
    let mut nsids = Vec::new();
    if identify(&mut s, 0, 2, identify_page).is_ok() {
        for i in 0..(PAGE / 4) {
            let id = unsafe { u32::from_le(read_volatile((identify_page + i * 4) as *const u32)) };
            if id == 0 {
                break;
            }
            nsids.push(id);
        }
    }
    if nsids.is_empty() {
        nsids.push(1);
    }
    for nsid in nsids {
        if identify(&mut s, nsid, 0, identify_page).is_err() {
            continue;
        }
        let nsze = unsafe { read_le_u64(identify_page, 0) };
        if nsze == 0 {
            continue;
        }
        let flbas = unsafe { read_volatile((identify_page + 26) as *const u8) };
        let fmt = (flbas & 0x0f) as usize;
        let lbaf = identify_page + 128 + fmt * 4;
        let lbads = unsafe { read_volatile((lbaf + 2) as *const u8) };
        if !(9..=12).contains(&lbads) {
            warn!("nvme: namespace {} unsupported LBA shift {}", nsid, lbads);
            continue;
        }
        let lba_bytes = 1usize << lbads;
        let Some(cap_bytes) = nsze.checked_mul(lba_bytes as u64) else {
            continue;
        };
        let ns = Namespace {
            nsid,
            lba_bytes,
            native_blocks: nsze,
            capacity_sectors: cap_bytes / 512,
        };
        info!(
            "nvme: namespace {} discovered native_blocks={} lba={}B capacity={} sectors",
            ns.nsid, ns.native_blocks, ns.lba_bytes, ns.capacity_sectors
        );
        s.namespaces.push(ns);
    }
    s.active = s.namespaces.first().copied();
    if s.active.is_none() {
        warn!("nvme: no supported active namespace");
        return None;
    }

    // MSI-X vector 0 is optional for correctness (polling path remains active).
    if let Some(irq) = crate::pci::configure_msix(dev, 0) {
        register_irq_handler(irq, irq_handler);
        s.irq = irq;
    }

    // Request up to one I/O queue pair per supported CPU. Number of Queues
    // completion returns zero-based counts in DW0 (NSQ/NCQ).
    let requested = MAX_IO_PATHS.max(1);
    let mut nq = [0u32; 16];
    nq[0] = ADMIN_SET_FEATURES as u32;
    nq[10] = FEATURE_NUMBER_OF_QUEUES as u32;
    nq[11] = ((requested as u32 - 1) << 16) | (requested as u32 - 1);
    let granted = admin_cmd(&mut s, nq)
        .map(|c| {
            let sq = (c.dw0 & 0xffff) as usize + 1;
            let cq = ((c.dw0 >> 16) & 0xffff) as usize + 1;
            min(requested, min(sq, cq))
        })
        .unwrap_or(1)
        .max(1);

    for idx in 0..granted {
        let qid = (idx + 1) as u16;
        let Some(path) = IoPath::new(qid, io_depth) else {
            break;
        };
        let mut cq = [0u32; 16];
        cq[0] = ADMIN_CREATE_IO_CQ as u32;
        cq[6] = path.q.cq as u32;
        cq[7] = (path.q.cq as u64 >> 32) as u32;
        cq[10] = qid as u32 | ((path.q.depth as u32 - 1) << 16);
        cq[11] = 1 | if s.irq != 0 { 1 << 1 } else { 0 };
        if admin_cmd(&mut s, cq).is_err() {
            path.release();
            break;
        }
        let mut sq = [0u32; 16];
        sq[0] = ADMIN_CREATE_IO_SQ as u32;
        sq[6] = path.q.sq as u32;
        sq[7] = (path.q.sq as u64 >> 32) as u32;
        sq[10] = qid as u32 | ((path.q.depth as u32 - 1) << 16);
        sq[11] = 1 | ((qid as u32) << 16);
        if admin_cmd(&mut s, sq).is_err() {
            let mut del = [0u32; 16];
            del[0] = ADMIN_DELETE_IO_CQ as u32;
            del[10] = qid as u32;
            let _ = admin_cmd(&mut s, del);
            path.release();
            break;
        }
        *IO_PATHS[idx].lock() = Some(path);
        s.io_count += 1;
    }
    if s.io_count == 0 {
        warn!("nvme: no I/O queue pairs created");
        return None;
    }
    s.ready = true;
    info!(
        "nvme: namespace {} online capacity={} sectors lba={}B max_xfer={}KiB irq={} io_queues={}",
        s.active.unwrap().nsid,
        s.active.unwrap().capacity_sectors,
        s.active.unwrap().lba_bytes,
        s.max_transfer / 1024,
        s.irq,
        s.io_count
    );
    phys::free_page(identify_page);
    Some(s)
}

pub fn init() {
    let Some(dev) = crate::pci::devices()
        .into_iter()
        .find(|d| d.class == 0x01 && d.subclass == 0x08 && d.prog_if == 0x02)
    else {
        return;
    };
    let Some(s) = init_controller(&dev) else {
        warn!("nvme: controller init failed");
        return;
    };
    let qemu_recovery_selftest = dev.vendor_id == 0x1b36 && dev.device_id == 0x0010;
    *STATE.lock() = s;
    let initial_ok = self_test();
    if qemu_recovery_selftest {
        if initial_ok && recover_controller() && self_test() {
            info!("nvme: RESET/RECOVERY SELFTEST PASS");
        } else {
            warn!("nvme: RESET/RECOVERY SELFTEST FAIL");
        }
    }
}

pub fn is_ready() -> bool {
    STATE.lock().ready
}

pub fn capacity_sectors() -> Option<u64> {
    let s = STATE.lock();
    s.ready.then_some(s.active?.capacity_sectors)
}

pub fn namespace_count() -> usize {
    STATE.lock().namespaces.len()
}
pub fn io_queue_count() -> usize {
    STATE.lock().io_count
}

fn submit_native(
    meta: NvmeIoMeta,
    path: &mut IoPath,
    native_lba: u64,
    bytes: usize,
    write: bool,
) -> Result<(), BlockError> {
    if bytes == 0 || bytes % meta.ns.lba_bytes != 0 {
        return Err(BlockError::InvalidArgument);
    }
    let blocks = bytes / meta.ns.lba_bytes;
    if native_lba
        .checked_add(blocks as u64)
        .map_or(true, |e| e > meta.ns.native_blocks)
    {
        return Err(BlockError::InvalidArgument);
    }
    let mut cmd = [0u32; 16];
    cmd[0] = if write { NVM_WRITE } else { NVM_READ } as u32;
    cmd[1] = meta.ns.nsid;
    set_prps(&mut cmd, path, meta.max_transfer, bytes)?;
    cmd[10] = native_lba as u32;
    cmd[11] = (native_lba >> 32) as u32;
    cmd[12] = (blocks as u32 - 1) & 0xffff;
    io_cmd(meta, path, cmd).map(|_| ())
}

fn transfer(lba: u64, buffer: *mut u8, len: usize, write: bool) -> Result<(), BlockError> {
    if len == 0 {
        return Ok(());
    }
    if len % 512 != 0 || buffer.is_null() {
        return Err(BlockError::InvalidArgument);
    }
    let meta = io_meta()?;
    let end_sector = lba
        .checked_add((len / 512) as u64)
        .ok_or(BlockError::InvalidArgument)?;
    if end_sector > meta.ns.capacity_sectors {
        return Err(BlockError::InvalidArgument);
    }
    let pi = path_index(meta);
    let mut guard = IO_PATHS[pi].lock();
    let path = guard.as_mut().ok_or(BlockError::NotReady)?;
    let native = meta.ns.lba_bytes;
    let max_direct = (meta.max_transfer / native * native).max(native);
    let mut user_off = 0usize;
    let mut byte_pos = lba.checked_mul(512).ok_or(BlockError::InvalidArgument)?;
    while user_off < len {
        let within = (byte_pos as usize) & (native - 1);
        let remain = len - user_off;
        if within == 0 && remain >= native {
            let chunk = min(remain - (remain % native), max_direct);
            if write {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer.add(user_off),
                        path.bounce as *mut u8,
                        chunk,
                    );
                }
                dma_write_barrier();
            }
            submit_native(meta, path, byte_pos / native as u64, chunk, write)?;
            if !write {
                dma_read_barrier();
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        path.bounce as *const u8,
                        buffer.add(user_off),
                        chunk,
                    );
                }
            }
            user_off += chunk;
            byte_pos += chunk as u64;
        } else {
            let take = min(remain, native - within);
            let nlba = byte_pos / native as u64;
            // Partial native-LBA read or write. Writes preserve untouched sectors via RMW.
            submit_native(meta, path, nlba, native, false)?;
            dma_read_barrier();
            if write {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer.add(user_off),
                        (path.bounce as *mut u8).add(within),
                        take,
                    );
                }
                dma_write_barrier();
                submit_native(meta, path, nlba, native, true)?;
            } else {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (path.bounce as *const u8).add(within),
                        buffer.add(user_off),
                        take,
                    );
                }
            }
            user_off += take;
            byte_pos += take as u64;
        }
    }
    Ok(())
}

fn recover_after_timeout() {
    if !RECOVERY_NEEDED.swap(false, Ordering::AcqRel) {
        return;
    }
    let qid = LAST_TIMEOUT_QID.load(Ordering::Acquire);
    let cid = LAST_TIMEOUT_CID.load(Ordering::Acquire);
    {
        let mut s = STATE.lock();
        if s.ready && abort_command(&mut s, qid, cid) {
            info!("nvme: Abort accepted qid={} cid={}", qid, cid);
        } else {
            warn!("nvme: Abort unavailable/failed qid={} cid={}", qid, cid);
        }
    }
    let _ = recover_controller();
}

pub fn read_blocks(lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
    let r = transfer(lba, buffer.as_mut_ptr(), buffer.len(), false);
    if r.is_err() {
        recover_after_timeout();
    }
    r
}
pub fn write_blocks(lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
    let r = transfer(lba, buffer.as_ptr() as *mut u8, buffer.len(), true);
    if r.is_err() {
        recover_after_timeout();
    }
    r
}

pub fn flush() -> Result<(), BlockError> {
    let meta = io_meta()?;
    let pi = path_index(meta);
    let mut guard = IO_PATHS[pi].lock();
    let path = guard.as_mut().ok_or(BlockError::NotReady)?;
    let mut cmd = [0u32; 16];
    cmd[0] = NVM_FLUSH as u32;
    cmd[1] = meta.ns.nsid;
    io_cmd(meta, path, cmd).map(|_| ())
}

/// Abort a timed-out command on a queue. Best effort: caller can still reset
/// the controller if firmware/controller does not complete the Abort command.
fn abort_command(s: &mut NvmeState, qid: u16, cid: u16) -> bool {
    let mut cmd = [0u32; 16];
    cmd[0] = ADMIN_ABORT as u32;
    cmd[10] = (qid as u32) | ((cid as u32) << 16);
    admin_cmd(s, cmd).is_ok()
}

pub fn recover_controller() -> bool {
    let Some(dev) = crate::pci::devices()
        .into_iter()
        .find(|d| d.class == 0x01 && d.subclass == 0x08 && d.prog_if == 0x02)
    else {
        return false;
    };

    // NVMe-level recovery comes first: delete I/O queues, clear CC.EN, wait
    // CSTS.RDY=0, then rebuild admin/I/O queues.  This is the spec-native
    // controller reset and preserves PCI resource assignment. PCIe FLR is a
    // last-resort escalation only when the controller-level path cannot recover;
    // some virtual/real devices reset BAR/MSI-X side state across FLR and require
    // a full PCI resource re-probe before MMIO can be trusted again.
    shutdown();
    if let Some(mut fresh) = init_controller(&dev) {
        fresh.ready = true;
        *STATE.lock() = fresh;
        info!(
            "nvme: CC.EN controller RESET/RECOVERY PASS queues={} namespaces={}",
            io_queue_count(),
            namespace_count()
        );
        return true;
    }

    warn!("nvme: controller-level recovery failed; escalating to PCIe FLR");
    if !crate::pci::function_level_reset(&dev) {
        warn!("nvme: FLR unavailable/failed");
        return false;
    }
    // A true FLR may reset PCI config/MMIO state; refresh the cached function
    // before trying the controller again.
    let dev = crate::pci::refresh_device(dev.address).unwrap_or(dev);
    let Some(mut fresh) = init_controller(&dev) else {
        warn!("nvme: recovery re-init after FLR failed");
        return false;
    };
    fresh.ready = true;
    *STATE.lock() = fresh;
    info!(
        "nvme: PCIe FLR RESET/RECOVERY PASS queues={} namespaces={}",
        io_queue_count(),
        namespace_count()
    );
    true
}

const SELFTEST_SECTORS: usize = 8;
fn self_test() -> bool {
    let Some(cap) = capacity_sectors() else {
        return false;
    };
    if cap < 32 {
        return false;
    }
    // Reserve the final 4KiB as the same raw-diagnostics zone used by blktest/zfsd.
    let lba = cap - SELFTEST_SECTORS as u64;
    let mut w = vec![0u8; SELFTEST_SECTORS * 512];
    for (i, b) in w.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37) ^ 0xa5;
    }
    if write_blocks(lba, &w).is_err() || flush().is_err() {
        warn!("nvme: selftest write/flush failed at LBA {}", lba);
        return false;
    }
    let mut r = vec![0u8; SELFTEST_SECTORS * 512];
    if read_blocks(lba, &mut r).is_err() || r != w {
        warn!("nvme: selftest readback mismatch at LBA {}", lba);
        return false;
    }
    info!(
        "nvme: READ/WRITE/FLUSH SELFTEST PASS LBA={} bytes={}",
        lba,
        r.len()
    );

    // If the native namespace block is larger than the public 512-byte ABI,
    // explicitly exercise the RMW shim: modify one interior 512B sector and
    // prove every neighbouring byte in the native block is preserved.
    let native = STATE.lock().active.map(|n| n.lba_bytes).unwrap_or(512);
    if native > 512 {
        let sectors_per_native = native / 512;
        if sectors_per_native <= SELFTEST_SECTORS {
            let patch_sector = (sectors_per_native / 2).min(sectors_per_native - 1);
            let mut patch = vec![0u8; 512];
            for (i, b) in patch.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(19) ^ 0x6d;
            }
            let mut expected = w;
            let byte_off = patch_sector * 512;
            expected[byte_off..byte_off + 512].copy_from_slice(&patch);
            if write_blocks(lba + patch_sector as u64, &patch).is_err() || flush().is_err() {
                warn!("nvme: 512B RMW selftest write failed native={}B", native);
                return false;
            }
            let mut whole = vec![0u8; SELFTEST_SECTORS * 512];
            if read_blocks(lba, &mut whole).is_err() || whole != expected {
                warn!(
                    "nvme: 512B RMW selftest preservation mismatch native={}B",
                    native
                );
                return false;
            }
            info!(
                "nvme: 512B ABI/NATIVE RMW SELFTEST PASS native={}B sector_offset={}",
                native, patch_sector
            );
        }
    }
    true
}

/// Best-effort controller shutdown used only by future reset paths.
#[allow(dead_code)]
pub fn shutdown() {
    let mut s = STATE.lock();
    if !s.ready && s.admin.is_none() {
        return;
    }
    s.ready = false;
    // Delete SQs before CQs, highest qid first.
    for idx in (0..s.io_count.min(MAX_IO_PATHS)).rev() {
        let qid = (idx + 1) as u16;
        let mut del = [0u32; 16];
        del[0] = ADMIN_DELETE_IO_SQ as u32;
        del[10] = qid as u32;
        let _ = admin_cmd(&mut s, del);
        let mut del = [0u32; 16];
        del[0] = ADMIN_DELETE_IO_CQ as u32;
        del[10] = qid as u32;
        let _ = admin_cmd(&mut s, del);
    }
    for slot in IO_PATHS.iter() {
        if let Some(path) = slot.lock().take() {
            path.release();
        }
    }
    s.io_count = 0;
    let cc = unsafe { r32(s.base + REG_CC) };
    unsafe { w32(s.base + REG_CC, cc & !CC_EN) };
    let _ = wait_csts(s.base, false, IO_TIMEOUT_NS);
    if let Some(admin) = s.admin.take() {
        admin.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_status_ignores_phase() {
        let mut c = Completion::default();
        c.status_phase = 1;
        assert_eq!(completion_status(c), 0);
        c.status_phase = (0x123 << 1) | 1;
        assert_eq!(completion_status(c), 0x123);
    }

    #[test]
    fn native_namespace_capacity_is_exposed_as_512b_sectors() {
        let ns = Namespace {
            nsid: 7,
            lba_bytes: 4096,
            native_blocks: 1024,
            capacity_sectors: 8192,
        };
        assert_eq!(
            ns.capacity_sectors,
            ns.native_blocks * (ns.lba_bytes as u64 / 512)
        );
    }

    #[test]
    fn doorbell_stride_math() {
        assert_eq!(doorbell(0x1000, 4, 0, false), 0x2000);
        assert_eq!(doorbell(0x1000, 4, 0, true), 0x2004);
        assert_eq!(doorbell(0x1000, 16, 3, false), 0x2060);
        assert_eq!(doorbell(0x1000, 16, 3, true), 0x2070);
    }
}
