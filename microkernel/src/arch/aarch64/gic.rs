//! ARM GIC interrupt-controller layer (GICv2 + GICv3).
//!
//! QEMU `virt` historically booted Zero OS with GICv2, while the PCI/MSI
//! hardware phase requires GICv3's system-register CPU interface and ITS/LPI.
//! Selection is firmware-driven: a MADT redistributor range with no GICC means
//! v3; otherwise the old GICv2 path remains intact.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

mod its;

const LEGACY_GICD_BASE: usize = 0x0800_0000;
const LEGACY_GICC_BASE: usize = 0x0801_0000;
static GICD_BASE: AtomicUsize = AtomicUsize::new(LEGACY_GICD_BASE);
static GICC_BASE: AtomicUsize = AtomicUsize::new(LEGACY_GICC_BASE);
static GICR_BASE: AtomicUsize = AtomicUsize::new(0);
static TIMER_IRQ: AtomicU32 = AtomicU32::new(30);
static VERSION: AtomicU8 = AtomicU8::new(2);
static BOOT_MPIDR: AtomicU64 = AtomicU64::new(0);

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_IGROUPR: usize = 0x080;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_ICACTIVER: usize = 0x380;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_IROUTER: usize = 0x6000;
const GICD_CTLR_RWP: u32 = 1 << 31;
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
const GICD_CTLR_ENABLE_G1A: u32 = 1 << 1;
const GICD_CTLR_ENABLE_G1: u32 = 1 << 0;

// GICv2 CPU interface.
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00c;
const GICC_EOIR: usize = 0x010;

// GICv3 redistributor.
const GICR_STRIDE: usize = 0x20_000;
const GICR_TYPER: usize = 0x008;
const GICR_WAKER: usize = 0x014;
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
const GICR_SGI_BASE: usize = 0x1_0000;
const GICR_IGROUPR0: usize = 0x080;
const GICR_ISENABLER0: usize = 0x100;
const GICR_ICENABLER0: usize = 0x180;
const GICR_ICACTIVER0: usize = 0x380;
const GICR_IPRIORITYR0: usize = 0x400;

const GICV2_INTID_MASK: u32 = 0x3ff;
const GICV3_INTID_MASK: u32 = 0x00ff_ffff;
const MAX_SPI_INTID: u32 = 1019;
const LPI_BASE: u32 = 8192;

static INITIALISED: AtomicBool = AtomicBool::new(false);
static RANGE_WARNED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
unsafe fn rd32(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}
#[inline(always)]
unsafe fn wr32(base: usize, off: usize, v: u32) {
    write_volatile((base + off) as *mut u32, v)
}
#[inline(always)]
unsafe fn rd64(base: usize, off: usize) -> u64 {
    read_volatile((base + off) as *const u64)
}
#[inline(always)]
unsafe fn wr64(base: usize, off: usize, v: u64) {
    write_volatile((base + off) as *mut u64, v)
}
#[inline(always)]
fn gicd() -> usize {
    GICD_BASE.load(Ordering::Relaxed)
}
#[inline(always)]
fn gicc() -> usize {
    GICC_BASE.load(Ordering::Relaxed)
}
#[inline(always)]
pub fn is_v3() -> bool {
    VERSION.load(Ordering::Acquire) == 3
}
#[inline(always)]
pub fn timer_irq_id() -> u32 {
    TIMER_IRQ.load(Ordering::Acquire)
}

#[inline]
fn affinity32(mpidr: u64) -> u32 {
    ((mpidr >> 32) as u32 & 0xff00_0000) | ((mpidr as u32) & 0x00ff_ffff)
}

#[inline]
fn current_mpidr() -> u64 {
    let v: u64;
    unsafe {
        asm!("mrs {0}, mpidr_el1", out(reg) v, options(nostack, preserves_flags));
    }
    v & 0xff00_00ff_00ff_ffff
}

fn find_redist(mpidr: u64) -> Option<usize> {
    let base = GICR_BASE.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    let wanted = affinity32(mpidr);
    for n in 0..64usize {
        let r = base + n * GICR_STRIDE;
        let typer = unsafe { rd64(r, GICR_TYPER) };
        if (typer >> 32) as u32 == wanted {
            return Some(r);
        }
        if typer & (1 << 4) != 0 {
            break;
        } // Last
    }
    None
}

fn wait_dist_rwp() {
    for _ in 0..1_000_000 {
        if unsafe { rd32(gicd(), GICD_CTLR) } & GICD_CTLR_RWP == 0 {
            return;
        }
        core::hint::spin_loop();
    }
    crate::warn!("gicv3: distributor RWP timeout");
}

fn wake_redist(r: usize) -> bool {
    unsafe {
        let mut w = rd32(r, GICR_WAKER);
        w &= !GICR_WAKER_PROCESSOR_SLEEP;
        wr32(r, GICR_WAKER, w);
        for _ in 0..1_000_000 {
            if rd32(r, GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
    }
    false
}

unsafe fn init_v3_dist() {
    let base = gicd();
    wr32(base, GICD_CTLR, 0);
    wait_dist_rwp();
    let typer = rd32(base, GICD_TYPER);
    let nr_irqs = (((typer & 0x1f) + 1) * 32).min(1020);
    for id in (32..nr_irqs).step_by(32) {
        let n = (id / 32) as usize;
        wr32(base, GICD_IGROUPR + n * 4, u32::MAX);
        wr32(base, GICD_ICENABLER + n * 4, u32::MAX);
        wr32(base, GICD_ICACTIVER + n * 4, u32::MAX);
    }
    for id in (32..nr_irqs).step_by(4) {
        wr32(base, GICD_IPRIORITYR + id as usize, 0xa0a0_a0a0);
    }
    // Route all SPIs to the boot PE. ARE_NS must be set before these registers
    // are meaningful, but QEMU accepts programming before final enable just as
    // Linux/KVM selftests do.
    let aff = affinity32(current_mpidr()) as u64;
    for id in 32..nr_irqs {
        wr64(base, GICD_IROUTER + (id as usize) * 8, aff);
    }
    wr32(
        base,
        GICD_CTLR,
        GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_G1A | GICD_CTLR_ENABLE_G1,
    );
    wait_dist_rwp();
    crate::info!("gicv3: distributor ready irqs={}", nr_irqs);
}

unsafe fn init_v3_cpu() {
    let Some(r) = find_redist(current_mpidr()) else {
        crate::warn!("gicv3: no redistributor for mpidr={:#x}", current_mpidr());
        return;
    };
    if !wake_redist(r) {
        crate::warn!("gicv3: redistributor wake timeout @ {:#x}", r);
    }
    let sgi = r + GICR_SGI_BASE;
    wr32(sgi, GICR_IGROUPR0, u32::MAX);
    wr32(sgi, GICR_ICENABLER0, u32::MAX);
    wr32(sgi, GICR_ICACTIVER0, u32::MAX);
    for off in (0..32usize).step_by(4) {
        wr32(sgi, GICR_IPRIORITYR0 + off, 0xa0a0_a0a0);
    }
    let timer = timer_irq_id();
    if timer < 32 {
        wr32(sgi, GICR_ISENABLER0, 1u32 << timer);
    }

    let mut sre: u64;
    asm!("mrs {0}, ICC_SRE_EL1", out(reg) sre, options(nostack));
    sre |= 1;
    asm!("msr ICC_SRE_EL1, {0}", "isb", in(reg) sre, options(nostack));
    asm!("msr ICC_PMR_EL1, {0}", in(reg) 0xffu64, options(nostack));
    asm!("msr ICC_BPR1_EL1, {0}", in(reg) 0u64, options(nostack));
    asm!("msr ICC_IGRPEN1_EL1, {0}", "isb", in(reg) 1u64, options(nostack));
    let sre_after: u64;
    let pmr_after: u64;
    let grp_after: u64;
    let ctlr_after: u64;
    asm!("mrs {0}, ICC_SRE_EL1", out(reg) sre_after, options(nostack));
    asm!("mrs {0}, ICC_PMR_EL1", out(reg) pmr_after, options(nostack));
    asm!("mrs {0}, ICC_IGRPEN1_EL1", out(reg) grp_after, options(nostack));
    asm!("mrs {0}, ICC_CTLR_EL1", out(reg) ctlr_after, options(nostack));
    crate::info!(
        "gicv3: cpu interface ready mpidr={:#x} rdist={:#x} sre={:#x} pmr={:#x} grp1={} ctlr={:#x}",
        current_mpidr(),
        r,
        sre_after,
        pmr_after,
        grp_after & 1,
        ctlr_after
    );
}

pub unsafe fn init() {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }
    BOOT_MPIDR.store(current_mpidr(), Ordering::Release);
    let gicd_base = crate::acpi::gicd_base()
        .map(|v| v as usize)
        .unwrap_or(LEGACY_GICD_BASE);
    let gicc_opt = crate::acpi::gicc_base().map(|v| v as usize);
    let gicr_opt = crate::acpi::gicr_base().map(|v| v as usize);
    let timer = crate::acpi::timer_irq().unwrap_or(30);
    GICD_BASE.store(gicd_base, Ordering::Release);
    TIMER_IRQ.store(timer, Ordering::Release);

    if gicr_opt.is_some() && gicc_opt.is_none() {
        VERSION.store(3, Ordering::Release);
        GICR_BASE.store(gicr_opt.unwrap(), Ordering::Release);
        init_v3_dist();
        init_v3_cpu();
        its::init();
        crate::info!(
            "gic: v3 platform gicd={:#x} gicr={:#x} its={:?} timer_irq={}",
            gicd_base,
            gicr_opt.unwrap(),
            crate::acpi::its_base(),
            timer
        );
        return;
    }

    VERSION.store(2, Ordering::Release);
    let gicc_base = gicc_opt.unwrap_or(LEGACY_GICC_BASE);
    GICC_BASE.store(gicc_base, Ordering::Release);
    wr32(gicd_base, GICD_CTLR, 0);
    wr32(gicc_base, GICC_CTLR, 0);
    wr32(gicc_base, GICC_PMR, 0xff);
    enable_irq(timer);
    set_priority_v2(timer, 0x20);
    wr32(gicd_base, GICD_CTLR, 1);
    wr32(gicc_base, GICC_CTLR, 1);
    crate::info!(
        "gic: v2 platform gicd={:#x} gicc={:#x} timer_irq={}",
        gicd_base,
        gicc_base,
        timer
    );
}

pub unsafe fn init_cpu_interface() {
    if is_v3() {
        init_v3_cpu();
        if let Some(r) = find_redist(current_mpidr()) {
            its::init_cpu_lpi(r);
        }
        return;
    }
    wr32(gicc(), GICC_PMR, 0xff);
    wr32(gicc(), GICC_CTLR, 1);
}

pub const SGI_RESCHED: u32 = 0;

pub fn send_resched_sgi(target_mask: u8) {
    if target_mask == 0 {
        return;
    }
    if !is_v3() {
        let word = ((target_mask as u32) << 16) | SGI_RESCHED;
        unsafe {
            wr32(gicd(), 0xF00, word);
        }
        return;
    }
    for logical in 0..8usize {
        if target_mask & (1 << logical) == 0 {
            continue;
        }
        let Some(m) = logical_cpu_mpidr(logical) else {
            continue;
        };
        let aff0 = (m & 0xff) as u64;
        let aff1 = ((m >> 8) & 0xff) as u64;
        let aff2 = ((m >> 16) & 0xff) as u64;
        let aff3 = ((m >> 32) & 0xff) as u64;
        if aff0 >= 16 {
            continue;
        }
        let sgi1r = (aff3 << 48)
            | (aff2 << 32)
            | ((SGI_RESCHED as u64) << 24)
            | (aff1 << 16)
            | (1u64 << aff0);
        unsafe {
            asm!("msr ICC_SGI1R_EL1, {0}", "isb", in(reg) sgi1r, options(nostack));
        }
    }
}

pub unsafe fn acknowledge() -> u32 {
    if is_v3() {
        let v: u64;
        asm!("mrs {0}, ICC_IAR1_EL1", out(reg)v, options(nostack));
        v as u32
    } else {
        rd32(gicc(), GICC_IAR)
    }
}
pub unsafe fn end_interrupt(raw: u32) {
    if is_v3() {
        asm!("msr ICC_EOIR1_EL1, {0}", in(reg) raw as u64, options(nostack));
    } else {
        wr32(gicc(), GICC_EOIR, raw);
    }
}
pub fn is_timer_interrupt(id: u32) -> bool {
    interrupt_number(id) == timer_irq_id()
}
pub fn interrupt_number(raw: u32) -> u32 {
    raw & if is_v3() {
        GICV3_INTID_MASK
    } else {
        GICV2_INTID_MASK
    }
}

pub unsafe fn enable_irq(id: u32) {
    if is_v3() {
        if id >= LPI_BASE {
            its::enable_lpi(id, true);
            return;
        }
        if id < 32 {
            if let Some(r) = find_redist(current_mpidr()) {
                wr32(r + GICR_SGI_BASE, GICR_ISENABLER0, 1 << id);
            }
        } else if id <= MAX_SPI_INTID {
            let n = (id / 32) as usize;
            wr32(gicd(), GICD_ISENABLER + n * 4, 1 << (id % 32));
        } else {
            warn_range(id);
        }
        return;
    }
    if id > 255 {
        warn_range(id);
        return;
    }
    let n = (id / 32) as usize;
    wr32(gicd(), GICD_ISENABLER + n * 4, 1 << (id % 32));
    set_priority_v2(id, 0x40);
}
pub unsafe fn disable_irq(id: u32) {
    if is_v3() {
        if id >= LPI_BASE {
            its::enable_lpi(id, false);
            return;
        }
        if id < 32 {
            if let Some(r) = find_redist(current_mpidr()) {
                wr32(r + GICR_SGI_BASE, GICR_ICENABLER0, 1 << id);
            }
        } else if id <= MAX_SPI_INTID {
            let n = (id / 32) as usize;
            wr32(gicd(), GICD_ICENABLER + n * 4, 1 << (id % 32));
        } else {
            warn_range(id);
        }
        return;
    }
    if id > 255 {
        warn_range(id);
        return;
    }
    let n = (id / 32) as usize;
    wr32(gicd(), GICD_ICENABLER + n * 4, 1 << (id % 32));
}

unsafe fn set_priority_v2(id: u32, priority: u32) {
    let off = (id as usize) & !3;
    let shift = (id % 4) * 8;
    let p = (gicd() + GICD_IPRIORITYR + off) as *mut u32;
    let mut v = read_volatile(p);
    v = (v & !(0xff << shift)) | (priority << shift);
    write_volatile(p, v);
}
fn warn_range(id: u32) {
    if !RANGE_WARNED.swap(true, Ordering::SeqCst) {
        crate::warn!("gic: interrupt {} outside supported range", id);
    }
}

fn logical_cpu_mpidr(cpu: usize) -> Option<u64> {
    let boot = BOOT_MPIDR.load(Ordering::Acquire);
    if cpu == 0 {
        return (boot != 0 || current_mpidr() == 0).then_some(boot);
    }
    const AFFINITY_MASK: u64 = 0x0000_00ff_00ff_ffff;
    let boot_aff = boot & AFFINITY_MASK;
    let mut logical = 1usize;
    for m in crate::acpi::cpu_mpidrs() {
        if m & AFFINITY_MASK == boot_aff {
            continue;
        }
        if logical == cpu {
            return Some(m);
        }
        logical += 1;
    }
    None
}

pub(crate) fn redist_for_logical_cpu(cpu: usize) -> Option<usize> {
    find_redist(logical_cpu_mpidr(cpu)?)
}

pub(crate) fn collection_target(cpu: usize, pta: bool) -> Option<u64> {
    let r = redist_for_logical_cpu(cpu)?;
    if pta {
        return Some(r as u64);
    }
    let cpu_num = unsafe { (rd64(r, GICR_TYPER) >> 8) & 0xffff };
    Some(cpu_num << 16)
}

pub fn reserve_pci_msi_affinity(
    requester_id: u16,
    event: u32,
    cpu: usize,
) -> Option<(u64, u32, u32)> {
    if !is_v3() {
        return None;
    }
    let lpi = its::reserve_event_on_cpu(requester_id as u32, event, cpu)?;
    Some((its::msi_address()?, event, lpi))
}

pub fn reserve_pci_msi(requester_id: u16, event: u32) -> Option<(u64, u32, u32)> {
    reserve_pci_msi_affinity(requester_id, event, 0)
}

pub fn allocate_pci_msi_affinity(
    requester_id: u16,
    event: u32,
    cpu: usize,
    handler: fn(u32),
) -> Option<(u64, u32, u32)> {
    if !is_v3() {
        return None;
    }
    let lpi = its::allocate_event_on_cpu(requester_id as u32, event, cpu, handler)?;
    Some((its::msi_address()?, event, lpi))
}

pub fn allocate_pci_msi(
    requester_id: u16,
    event: u32,
    handler: fn(u32),
) -> Option<(u64, u32, u32)> {
    allocate_pci_msi_affinity(requester_id, event, 0, handler)
}

pub(crate) fn affinity_self_test(cpu: usize) -> bool {
    if !is_v3() {
        return false;
    }
    its::affinity_self_test(cpu)
}

pub(crate) fn current_redist_base() -> Option<usize> {
    find_redist(current_mpidr())
}
pub(crate) fn boot_redist_base() -> Option<usize> {
    let mpidrs = crate::acpi::cpu_mpidrs();
    mpidrs.first().and_then(|m| find_redist(*m))
}
