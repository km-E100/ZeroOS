//! Minimal GICv3 ITS + physical LPI path (Knife 36).
//!
//! QEMU virt exposes a flat device table and collection table. We still derive
//! entry geometry from GITS_BASER reset values, allocate cache-coherent tables,
//! and use architectural MAPD/MAPC/MAPTI commands. A built-in INT command
//! self-test proves the full translation path before PCI MSI-X is enabled.

use alloc::vec::Vec;
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

const GITS_CTLR: usize = 0x0000;
const GITS_TYPER: usize = 0x0008;
const GITS_CBASER: usize = 0x0080;
const GITS_CWRITER: usize = 0x0088;
const GITS_CREADR: usize = 0x0090;
const GITS_BASER: usize = 0x0100;
pub const GITS_TRANSLATER: usize = 0x10040;
const GITS_CTLR_ENABLE: u32 = 1;
const GITS_CTLR_QUIESCENT: u32 = 1 << 31;
const GITS_VALID: u64 = 1 << 63;
const SHARE_INNER: u64 = 1 << 10;
const CACHE_RAWAWB: u64 = 7 << 59;
const BASER_PAGE_64K: u64 = 2 << 8;
const CMDQ_SIZE: usize = 64 * 1024;
const CMD_SIZE: usize = 32;
const LPI_BASE: u32 = 8192;
const LPI_BITS: usize = 16;
const PROP_SIZE: usize = 64 * 1024;
const PEND_SIZE: usize = 64 * 1024;
const GICR_CTLR: usize = 0x0000;
const GICR_PROPBASER: usize = 0x0070;
const GICR_PENDBASER: usize = 0x0078;
const GICR_TYPER: usize = 0x0008;
const GICR_INVLPIR: usize = 0x00a0;
const GICR_SYNCR: usize = 0x00c0;
const GICR_ENABLE_LPIS: u32 = 1;

#[derive(Copy, Clone)]
struct ItsState {
    base: usize,
    cmd: usize,
    writer: usize,
    prop: usize,
    pta: bool,
    collections: u64,
    ready: bool,
}
impl ItsState {
    const fn new() -> Self {
        Self {
            base: 0,
            cmd: 0,
            writer: 0,
            prop: 0,
            pta: false,
            collections: 0,
            ready: false,
        }
    }
}
static STATE: Mutex<ItsState> = Mutex::new(ItsState::new());
static READY: AtomicBool = AtomicBool::new(false);
static SELFTEST_HITS: AtomicU32 = AtomicU32::new(0);
static AFFINITY_HITS: AtomicU32 = AtomicU32::new(0);
static AFFINITY_TARGET: AtomicU32 = AtomicU32::new(0);
static NEXT_LPI: AtomicU32 = AtomicU32::new(LPI_BASE + 1);
#[derive(Copy, Clone)]
struct DeviceMap {
    devid: u32,
    itt: usize,
}
static DEVICE_MAPS: Mutex<Vec<DeviceMap>> = Mutex::new(Vec::new());
/// Per-redistributor pending tables. Property table is shared; pending bits are
/// PE-local and must never be shared between CPUs.
static PEND_TABLES: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

#[inline]
unsafe fn rd32(b: usize, o: usize) -> u32 {
    read_volatile((b + o) as *const u32)
}
#[inline]
unsafe fn wr32(b: usize, o: usize, v: u32) {
    write_volatile((b + o) as *mut u32, v)
}
#[inline]
unsafe fn rd64(b: usize, o: usize) -> u64 {
    read_volatile((b + o) as *const u64)
}
#[inline]
unsafe fn wr64(b: usize, o: usize, v: u64) {
    write_volatile((b + o) as *mut u64, v)
}

fn alloc_aligned_64k(bytes: usize) -> Option<usize> {
    let pages = bytes.div_ceil(4096);
    let raw_pages = pages.checked_add(15)?;
    let raw = crate::mm::phys::alloc_pages_contiguous(raw_pages)?;
    let aligned = (raw + 0xffff) & !0xffff;
    let prefix = (aligned - raw) / 4096;
    for i in 0..prefix {
        crate::mm::phys::free_page(raw + i * 4096);
    }
    for i in prefix + pages..raw_pages {
        crate::mm::phys::free_page(raw + i * 4096);
    }
    unsafe {
        core::ptr::write_bytes(aligned as *mut u8, 0, bytes);
    }
    Some(aligned)
}
fn log2_pow2(v: usize) -> u8 {
    debug_assert!(v.is_power_of_two());
    v.trailing_zeros() as u8
}

unsafe fn program_baser(base: usize, index: usize, phys: usize, bytes: usize) -> bool {
    let reset = rd64(base, GITS_BASER + index * 8);
    let typ = (reset >> 56) & 7;
    let entry = ((reset >> 48) & 0x1f) + 1;
    if typ == 0 {
        return false;
    }
    let pages = bytes.div_ceil(64 * 1024);
    if pages == 0 || pages > 256 {
        return false;
    }
    let val = (phys as u64 & 0x0000_ffff_ffff_0000)
        | (typ << 56)
        | ((entry - 1) << 48)
        | CACHE_RAWAWB
        | SHARE_INNER
        | BASER_PAGE_64K
        | ((pages - 1) as u64)
        | GITS_VALID;
    wr64(base, GITS_BASER + index * 8, val);
    let got = rd64(base, GITS_BASER + index * 8);
    if got & GITS_VALID == 0 {
        crate::warn!("gicv3: ITS BASER{} rejected {:#x}->{:#x}", index, val, got);
        return false;
    }
    true
}

unsafe fn issue(cmd: [u64; 4]) -> bool {
    let mut s = STATE.lock();
    if !s.ready {
        return false;
    }
    let slot = s.cmd + s.writer;
    for (i, w) in cmd.iter().enumerate() {
        write_volatile((slot + i * 8) as *mut u64, w.to_le());
    }
    asm!("dsb sy", options(nostack));
    s.writer = (s.writer + CMD_SIZE) % CMDQ_SIZE;
    wr64(s.base, GITS_CWRITER, s.writer as u64);
    let want = s.writer as u64;
    for _ in 0..2_000_000 {
        let r = rd64(s.base, GITS_CREADR) & 0xffff_ffe0;
        if r == want {
            return true;
        }
        core::hint::spin_loop();
    }
    crate::warn!(
        "gicv3: ITS command timeout writer={:#x} reader={:#x}",
        want,
        rd64(s.base, GITS_CREADR)
    );
    false
}
fn mapd(devid: u32, itt: usize, nrites: usize) -> [u64; 4] {
    let size = log2_pow2(nrites) - 1;
    [
        (0x08u64) | ((devid as u64) << 32),
        size as u64,
        ((itt as u64 >> 8) << 8) | (1u64 << 63),
        0,
    ]
}
fn mapc(col: u16, target: u64) -> [u64; 4] {
    [
        0x09,
        0,
        ((target >> 16) << 16) | (col as u64) | (1u64 << 63),
        0,
    ]
}
fn mapti(devid: u32, event: u32, lpi: u32, col: u16) -> [u64; 4] {
    [
        (0x0au64) | ((devid as u64) << 32),
        (event as u64) | ((lpi as u64) << 32),
        col as u64,
        0,
    ]
}
fn int_cmd(devid: u32, event: u32) -> [u64; 4] {
    [(0x03u64) | ((devid as u64) << 32), event as u64, 0, 0]
}
fn sync_cmd(target: u64) -> [u64; 4] {
    [0x05, 0, (target >> 16) << 16, 0]
}
fn invall(col: u16) -> [u64; 4] {
    [0x0d, 0, col as u64, 0]
}

fn selftest_handler(_irq: u32) {
    let n = SELFTEST_HITS.fetch_add(1, Ordering::SeqCst) + 1;
    if n == 1 {
        crate::info!("gicv3: ITS/LPI SELFTEST PASS (LPI {})", LPI_BASE);
    }
}

fn affinity_selftest_handler(irq: u32) {
    let actual = crate::arch::smp::cpu_id();
    let target = AFFINITY_TARGET.load(Ordering::Acquire) as usize;
    let n = AFFINITY_HITS.fetch_add(1, Ordering::SeqCst) + 1;
    if n == 1 {
        if actual == target {
            crate::info!(
                "gicv3: ITS IRQ AFFINITY PASS lpi={} target_cpu={} actual_cpu={}",
                irq,
                target,
                actual
            );
        } else {
            crate::warn!(
                "gicv3: ITS IRQ AFFINITY FAIL lpi={} target_cpu={} actual_cpu={}",
                irq,
                target,
                actual
            );
        }
    }
}

pub fn init() {
    let Some(base) = crate::acpi::its_base().map(|x| x as usize) else {
        return;
    };
    let Some(rdist) = super::boot_redist_base() else {
        crate::warn!("gicv3: ITS has no boot redistributor");
        return;
    };
    unsafe {
        wr32(base, GITS_CTLR, 0);
        for _ in 0..1_000_000 {
            if rd32(base, GITS_CTLR) & GITS_CTLR_QUIESCENT != 0 {
                break;
            }
        }
        let typer = rd64(base, GITS_TYPER);
        let devbits = ((typer >> 13) & 0x1f) + 1;
        let idbits = ((typer >> 8) & 0x1f) + 1;
        let itt_entry = ((typer >> 4) & 0xf) + 1;
        let pta = typer & (1 << 19) != 0;
        crate::info!(
            "gicv3: ITS base={:#x} devbits={} idbits={} itt_entry={} pta={}",
            base,
            devbits,
            idbits,
            itt_entry,
            pta
        );

        let cmd = match alloc_aligned_64k(CMDQ_SIZE) {
            Some(v) => v,
            None => return,
        };
        let prop = match alloc_aligned_64k(PROP_SIZE) {
            Some(v) => v,
            None => return,
        };
        let pend = match alloc_aligned_64k(PEND_SIZE) {
            Some(v) => v,
            None => return,
        };
        // One configuration byte per LPI, index = INTID-8192. Group-1, priority A0, disabled.
        core::ptr::write_bytes(prop as *mut u8, 0xa2, PROP_SIZE);
        core::ptr::write_bytes(pend as *mut u8, 0, PEND_SIZE);
        wr64(
            rdist,
            GICR_PROPBASER,
            (prop as u64) | SHARE_INNER | (7 << 7) | ((LPI_BITS - 1) as u64),
        );
        wr64(
            rdist,
            GICR_PENDBASER,
            (pend as u64) | SHARE_INNER | (7 << 7),
        );
        wr32(rdist, GICR_CTLR, rd32(rdist, GICR_CTLR) | GICR_ENABLE_LPIS);

        // Flat device table: 2^DEVBITS entries. QEMU reports 8-byte entries.
        let device_bytes = (1usize << devbits.min(20)) * 8;
        let collection_bytes = 64 * 1024;
        let devtab = match alloc_aligned_64k(device_bytes) {
            Some(v) => v,
            None => return,
        };
        let coltab = match alloc_aligned_64k(collection_bytes) {
            Some(v) => v,
            None => return,
        };
        if !program_baser(base, 0, devtab, device_bytes)
            || !program_baser(base, 1, coltab, collection_bytes)
        {
            return;
        }
        wr64(
            base,
            GITS_CBASER,
            (cmd as u64) | GITS_VALID | CACHE_RAWAWB | SHARE_INNER | 15,
        );
        wr64(base, GITS_CWRITER, 0);
        wr32(base, GITS_CTLR, GITS_CTLR_ENABLE);
        if rd32(base, GITS_CTLR) & GITS_CTLR_ENABLE == 0 {
            crate::warn!("gicv3: ITS enable rejected");
            return;
        }
        {
            let mut s = STATE.lock();
            *s = ItsState {
                base,
                cmd,
                writer: 0,
                prop,
                pta,
                collections: 0,
                ready: true,
            };
        }
        READY.store(true, Ordering::Release);

        // Self-test device/ITT. Keep two event slots (architectural minimum power-of-two).
        const DEV: u32 = 0x1234;
        let itt_page = match crate::mm::phys::alloc_page() {
            Some(v) => v,
            None => return,
        };
        core::ptr::write_bytes(itt_page as *mut u8, 0, 4096);
        PEND_TABLES.lock().push((rdist, pend));
        if !issue(mapd(DEV, itt_page, 2)) {
            return;
        }
        if !ensure_collection(0) {
            return;
        }
        if !issue(mapti(DEV, 0, LPI_BASE, 0)) {
            return;
        }
        if !issue(invall(0)) || !sync_collection(0) {
            return;
        }
        enable_lpi(LPI_BASE, true);
        crate::drivers::register_irq_handler(LPI_BASE, selftest_handler);
        if issue(int_cmd(DEV, 0)) {
            crate::info!("gicv3: ITS selftest INT queued for LPI {}", LPI_BASE);
        }
    }
}

/// Program the shared LPI property table and a private pending table for one
/// redistributor. Called from each secondary CPU after its GICR is awake.
pub fn init_cpu_lpi(rdist: usize) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    if PEND_TABLES.lock().iter().any(|(r, _)| *r == rdist) {
        return;
    }
    let prop = STATE.lock().prop;
    if prop == 0 {
        return;
    }
    let Some(pend) = alloc_aligned_64k(PEND_SIZE) else {
        crate::warn!("gicv3: LPI pending table OOM rdist={:#x}", rdist);
        return;
    };
    unsafe {
        core::ptr::write_bytes(pend as *mut u8, 0, PEND_SIZE);
        wr64(
            rdist,
            GICR_PROPBASER,
            (prop as u64) | SHARE_INNER | (7 << 7) | ((LPI_BITS - 1) as u64),
        );
        wr64(
            rdist,
            GICR_PENDBASER,
            (pend as u64) | SHARE_INNER | (7 << 7),
        );
        asm!("dsb sy", options(nostack));
        wr32(rdist, GICR_CTLR, rd32(rdist, GICR_CTLR) | GICR_ENABLE_LPIS);
    }
    PEND_TABLES.lock().push((rdist, pend));
}

fn ensure_collection(cpu: usize) -> bool {
    if cpu >= 64 || !READY.load(Ordering::Acquire) {
        return false;
    }
    let bit = 1u64 << cpu;
    let (pta, already) = {
        let s = STATE.lock();
        (s.pta, s.collections & bit != 0)
    };
    if already {
        return true;
    }
    let Some(target) = super::collection_target(cpu, pta) else {
        return false;
    };
    if !unsafe { issue(mapc(cpu as u16, target)) } {
        return false;
    }
    STATE.lock().collections |= bit;
    crate::info!("gicv3: ITS collection{} -> target={:#x}", cpu, target);
    true
}

pub unsafe fn enable_lpi(id: u32, enable: bool) {
    if !READY.load(Ordering::Acquire) || id < LPI_BASE {
        return;
    }
    let s = STATE.lock();
    let idx = (id - LPI_BASE) as usize;
    if idx >= PROP_SIZE {
        return;
    }
    let p = (s.prop + idx) as *mut u8;
    let mut v = read_volatile(p);
    if enable {
        v |= 1
    } else {
        v &= !1
    }
    write_volatile(p, v);
    asm!("dsb ishst", options(nostack));
}

unsafe fn invalidate_lpi_on_cpu(cpu: usize, id: u32) -> bool {
    let Some(rdist) = super::redist_for_logical_cpu(cpu) else {
        return false;
    };
    // GICR caches LPI configuration bytes. Updating the shared property table is
    // not sufficient once a PE has EnableLPIs set: invalidate this INTID and wait
    // for the redistributor synchronization point before injecting the event.
    wr64(rdist, GICR_INVLPIR, id as u64);
    asm!("dsb sy", options(nostack));
    for _ in 0..1_000_000usize {
        if rd64(rdist, GICR_SYNCR) & 1 == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    crate::warn!("gicv3: GICR INVLPIR timeout cpu={} lpi={}", cpu, id);
    false
}

fn ensure_device(devid: u32) -> bool {
    if DEVICE_MAPS.lock().iter().any(|d| d.devid == devid) {
        return true;
    }
    let Some(itt) = crate::mm::phys::alloc_page() else {
        return false;
    };
    unsafe {
        core::ptr::write_bytes(itt as *mut u8, 0, 4096);
    }
    // 32 event slots: ample for current MSI/MSI-X queues, still one 4KiB ITT page.
    if !unsafe { issue(mapd(devid, itt, 32)) } {
        return false;
    }
    DEVICE_MAPS.lock().push(DeviceMap { devid, itt });
    true
}

fn sync_collection(cpu: usize) -> bool {
    let pta = STATE.lock().pta;
    let Some(target) = super::collection_target(cpu, pta) else {
        return false;
    };
    unsafe { issue(sync_cmd(target)) }
}

pub fn reserve_event_on_cpu(devid: u32, event: u32, cpu: usize) -> Option<u32> {
    if !READY.load(Ordering::Acquire)
        || event >= 32
        || !ensure_device(devid)
        || !ensure_collection(cpu)
    {
        return None;
    }
    let lpi = NEXT_LPI.fetch_add(1, Ordering::SeqCst);
    if lpi >= LPI_BASE + (PROP_SIZE as u32) {
        return None;
    }
    let col = cpu as u16;
    if !unsafe { issue(mapti(devid, event, lpi, col)) } || !unsafe { issue(invall(col)) } {
        return None;
    }
    unsafe {
        enable_lpi(lpi, true);
        if !invalidate_lpi_on_cpu(cpu, lpi) {
            return None;
        }
    }
    if !sync_collection(cpu) {
        return None;
    }
    Some(lpi)
}

pub fn reserve_event(devid: u32, event: u32) -> Option<u32> {
    reserve_event_on_cpu(devid, event, 0)
}

pub fn allocate_event_on_cpu(devid: u32, event: u32, cpu: usize, handler: fn(u32)) -> Option<u32> {
    let lpi = reserve_event_on_cpu(devid, event, cpu)?;
    crate::drivers::register_irq_handler(lpi, handler);
    Some(lpi)
}

pub fn allocate_event(devid: u32, event: u32, handler: fn(u32)) -> Option<u32> {
    allocate_event_on_cpu(devid, event, 0, handler)
}

/// QEMU/bring-up proof that a collection can route an LPI to a non-boot PE.
/// Called only after secondaries have their GICR/LPI pending tables online.
pub fn affinity_self_test(cpu: usize) -> bool {
    if cpu == 0 || !READY.load(Ordering::Acquire) {
        return false;
    }
    const DEV: u32 = 0x1235;
    const EVENT: u32 = 0;
    AFFINITY_HITS.store(0, Ordering::Release);
    AFFINITY_TARGET.store(cpu as u32, Ordering::Release);
    let Some(lpi) = allocate_event_on_cpu(DEV, EVENT, cpu, affinity_selftest_handler) else {
        crate::warn!(
            "gicv3: ITS affinity selftest allocation failed target_cpu={}",
            cpu
        );
        return false;
    };
    if !unsafe { issue(int_cmd(DEV, EVENT)) } {
        crate::warn!("gicv3: ITS affinity selftest INT failed target_cpu={}", cpu);
        return false;
    }
    crate::info!(
        "gicv3: ITS affinity selftest queued LPI {} -> cpu{}",
        lpi,
        cpu
    );
    let deadline = crate::time::monotonic_ns().saturating_add(2_000_000_000);
    while crate::time::monotonic_ns() < deadline {
        if AFFINITY_HITS.load(Ordering::Acquire) != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    let rdist = super::redist_for_logical_cpu(cpu).unwrap_or(0);
    let pend = PEND_TABLES
        .lock()
        .iter()
        .find(|(r, _)| *r == rdist)
        .map(|(_, p)| *p)
        .unwrap_or(0);
    let prop = STATE.lock().prop;
    let prop_byte = if prop != 0 {
        unsafe { read_volatile((prop + (lpi - LPI_BASE) as usize) as *const u8) }
    } else {
        0
    };
    let pend_byte = if pend != 0 {
        unsafe { read_volatile((pend + (lpi as usize / 8)) as *const u8) }
    } else {
        0
    };
    crate::warn!(
        "gicv3: ITS IRQ AFFINITY TIMEOUT lpi={} cpu={} prop={:#x} pend_byte={:#x} bit={}",
        lpi,
        cpu,
        prop_byte,
        pend_byte,
        lpi & 7
    );
    false
}

pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}
pub fn msi_address() -> Option<u64> {
    crate::acpi::its_base().map(|b| b + GITS_TRANSLATER as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_encoding() {
        assert_eq!(mapd(0x12, 0x4000_0000, 2)[0], 0x12_00000008);
        assert_eq!(mapti(1, 2, 8192, 3)[1], 2 | (8192u64 << 32));
        assert_eq!(sync_cmd(0x1234_0000)[2], 0x1234_0000);
    }
}
