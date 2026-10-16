//! ACPI 静态平台描述。
//!
//! 第十八刀已经打通 RSDP → XSDT → MADT CPU 枚举；第20刀把静态表
//! 真正变成平台驱动的数据源：MADT(GIC)、GTDT(timer)、FADT(PSCI conduit)
//! 与 MCFG(PCI ECAM)。AML 仍明确不做。任何坏表都 fail-open 到 QEMU virt
//! 的 legacy 常量，绝不因为固件描述异常击穿启动。

#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

#[cfg(all(target_os = "none", not(test)))]
extern "C" {
    /// bootloader 在 ExitBootServices 前从 UEFI config table 捕获并补丁。
    static __zero_rsdp_phys: u64;
}

const MAX_TABLE_LEN: usize = 1024 * 1024;
const SDT_HEADER_LEN: usize = 36;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MadtCpu {
    pub mpidr: u64,
    pub uid: u32,
    pub enabled: bool,
    /// ACPI GICC flags bit3: disabled at boot but firmware permits later online.
    pub online_capable: bool,
    /// ACPI GICC parking protocol metadata. Version 0/address 0 means absent.
    pub parking_protocol_version: u32,
    pub parked_address: u64,
    /// GICv2 CPU interface MMIO base（0 = MADT 未提供/系统使用 sysreg interface）。
    pub gicc_base: u64,
    /// GIC redistributor base（GICv3；0 = 未提供）。
    pub gicr_base: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EcamSegment {
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SmmuV3Info {
    pub base: u64,
    pub event_irq: u32,
    pub pri_irq: u32,
    pub gerr_irq: u32,
    pub sync_irq: u32,
    /// PCI requester-ID range routed through this SMMU by the IORT root complex.
    pub rid_start: u32,
    pub rid_count: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResetRegister {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
    pub value: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PsciConduit {
    /// FADT 没有有效 ARM boot flags，保留 Zero OS 历史/QEMU 默认 HVC。
    LegacyHvc = 0,
    Hvc = 1,
    Smc = 2,
}

#[derive(Default, Debug)]
struct ParsedTables {
    cpus: Vec<MadtCpu>,
    gicd: u64,
    gicc: u64,
    gicr: u64,
    its: u64,
    timer_irq: u32,
    timer_flags: u32,
    psci_conduit: u8,
    reset: Option<ResetRegister>,
    ecam: Vec<EcamSegment>,
    smmus: Vec<SmmuV3Info>,
}

static CPUS: spin::Mutex<Vec<MadtCpu>> = spin::Mutex::new(Vec::new());
static ECAM: spin::Mutex<Vec<EcamSegment>> = spin::Mutex::new(Vec::new());
static SMMUS: spin::Mutex<Vec<SmmuV3Info>> = spin::Mutex::new(Vec::new());
static GICD_BASE: AtomicU64 = AtomicU64::new(0);
static GICC_BASE: AtomicU64 = AtomicU64::new(0);
static GICR_BASE: AtomicU64 = AtomicU64::new(0);
static ITS_BASE: AtomicU64 = AtomicU64::new(0);
static TIMER_IRQ: AtomicU32 = AtomicU32::new(0);
static TIMER_FLAGS: AtomicU32 = AtomicU32::new(0);
static PSCI_CONDUIT: AtomicU8 = AtomicU8::new(PsciConduit::LegacyHvc as u8);
static RESET_REGISTER: spin::Mutex<Option<ResetRegister>> = spin::Mutex::new(None);
static PARSED: AtomicBool = AtomicBool::new(false);

#[inline]
fn rd8(base: u64, off: usize) -> u8 {
    unsafe { ((base + off as u64) as *const u8).read_volatile() }
}

#[inline]
fn rd32(base: u64, off: usize) -> u32 {
    let mut bytes = [0u8; 4];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = rd8(base, off + i);
    }
    u32::from_le_bytes(bytes)
}

#[inline]
fn rd64(base: u64, off: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = rd8(base, off + i);
    }
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
fn checksum_bytes(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0
}

fn rsdp_valid(rsdp: u64) -> bool {
    if (0..8).any(|i| rd8(rsdp, i) != b"RSD PTR "[i]) {
        return false;
    }
    // ACPI 1.0 checksum is always required; XSDT requires revision >= 2 + extended checksum.
    let legacy_sum = (0..20).fold(0u8, |sum, i| sum.wrapping_add(rd8(rsdp, i)));
    if legacy_sum != 0 || rd8(rsdp, 15) < 2 {
        return false;
    }
    let len = rd32(rsdp, 20) as usize;
    if !(36..=MAX_TABLE_LEN).contains(&len) {
        return false;
    }
    (0..len).fold(0u8, |sum, i| sum.wrapping_add(rd8(rsdp, i))) == 0
}

fn sdt_header(base: u64) -> Option<([u8; 4], usize)> {
    let sig = [rd8(base, 0), rd8(base, 1), rd8(base, 2), rd8(base, 3)];
    let len = rd32(base, 4) as usize;
    if !(SDT_HEADER_LEN..=MAX_TABLE_LEN).contains(&len) {
        return None;
    }
    let sum = (0..len).fold(0u8, |sum, i| sum.wrapping_add(rd8(base, i)));
    (sum == 0).then_some((sig, len))
}

#[inline]
fn le16(bytes: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(off..off + 2)?.try_into().ok()?,
    ))
}
#[inline]
fn le32(bytes: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(off..off + 4)?.try_into().ok()?,
    ))
}
#[inline]
fn le64(bytes: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(off..off + 8)?.try_into().ok()?,
    ))
}

/// MADT ARM Generic Interrupt entries（types 11/12/14）。
fn parse_madt_entries(
    bytes: &[u8],
    body_off: usize,
) -> (Vec<MadtCpu>, Option<u64>, Option<u64>, Option<u64>) {
    let mut cpus = Vec::new();
    let mut gicd = None;
    let mut redistributor = None;
    let mut its = None;
    let mut off = body_off;
    while off + 2 <= bytes.len() {
        let etype = bytes[off];
        let elen = bytes[off + 1] as usize;
        if elen < 2
            || off
                .checked_add(elen)
                .filter(|e| *e <= bytes.len())
                .is_none()
        {
            break;
        }
        match etype {
            // Generic Interrupt CPU Interface (ACPI 5+), minimum through MPIDR.
            11 if elen >= 76 => {
                let flags = le32(bytes, off + 12).unwrap_or(0);
                cpus.push(MadtCpu {
                    uid: le32(bytes, off + 8).unwrap_or(0),
                    enabled: flags & 1 != 0,
                    online_capable: flags & (1 << 3) != 0,
                    parking_protocol_version: le32(bytes, off + 16).unwrap_or(0),
                    parked_address: le64(bytes, off + 24).unwrap_or(0),
                    gicc_base: le64(bytes, off + 32).unwrap_or(0),
                    gicr_base: le64(bytes, off + 60).unwrap_or(0),
                    mpidr: le64(bytes, off + 68).unwrap_or(0),
                });
            }
            // Generic Interrupt Distributor.
            12 if elen >= 20 => {
                gicd.get_or_insert(le64(bytes, off + 8).unwrap_or(0));
            }
            // Generic Interrupt Redistributor discovery range.
            14 if elen >= 16 => {
                redistributor.get_or_insert(le64(bytes, off + 4).unwrap_or(0));
            }
            // GIC Interrupt Translation Service (ITS).
            15 if elen >= 20 => {
                its.get_or_insert(le64(bytes, off + 8).unwrap_or(0));
            }
            _ => {}
        }
        off += elen;
    }
    (
        cpus,
        gicd.filter(|v| *v != 0),
        redistributor.filter(|v| *v != 0),
        its.filter(|v| *v != 0),
    )
}

/// GTDT: Non-Secure EL1 physical timer GSIV/flags are +56/+60 from table base.
fn parse_gtdt(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 64 {
        return None;
    }
    let irq = le32(bytes, 56)?;
    let flags = le32(bytes, 60)?;
    // Architectural interrupt IDs are 16-bit; 0/1023 are not useful timer inputs.
    (irq > 0 && irq < 1020).then_some((irq, flags))
}

/// FADT ARM Boot Architecture Flags at byte offset 129 (ACPI 5.1+).
/// bit0 PSCI_COMPLIANT, bit1 PSCI_USE_HVC.
fn parse_fadt_psci(bytes: &[u8]) -> PsciConduit {
    let Some(flags) = le16(bytes, 129) else {
        return PsciConduit::LegacyHvc;
    };
    if flags & 1 == 0 {
        PsciConduit::LegacyHvc
    } else if flags & 2 != 0 {
        PsciConduit::Hvc
    } else {
        PsciConduit::Smc
    }
}

/// FADT Reset Register: Flags.RESET_REG_SUP(bit10), GAS @116, ResetValue @128.
/// Zero OS consumes SystemMemory GAS on AArch64; SystemIO is retained as metadata
/// but cannot be issued without an architecture-specific I/O-port mechanism.
fn parse_fadt_reset(bytes: &[u8]) -> Option<ResetRegister> {
    if bytes.len() < 129 {
        return None;
    }
    let flags = le32(bytes, 112)?;
    if flags & (1 << 10) == 0 {
        return None;
    }
    let address_space = bytes[116];
    let bit_width = bytes[117];
    let bit_offset = bytes[118];
    let access_size = bytes[119];
    let address = le64(bytes, 120)?;
    let value = bytes[128];
    if address == 0 || bit_width == 0 || bit_width > 64 || bit_offset >= 64 {
        return None;
    }
    Some(ResetRegister {
        address_space,
        bit_width,
        bit_offset,
        access_size,
        address,
        value,
    })
}

/// MCFG: header(36) + reserved(8), then 16-byte allocation structures.
fn parse_mcfg(bytes: &[u8]) -> Vec<EcamSegment> {
    let mut out = Vec::new();
    if bytes.len() < 44 {
        return out;
    }
    let mut off = 44usize;
    while off + 16 <= bytes.len() {
        let Some(base) = le64(bytes, off) else { break };
        let Some(segment) = le16(bytes, off + 8) else {
            break;
        };
        let start_bus = bytes[off + 10];
        let end_bus = bytes[off + 11];
        if base != 0 && start_bus <= end_bus {
            out.push(EcamSegment {
                base,
                segment,
                start_bus,
                end_bus,
            });
        }
        off += 16;
    }
    out
}

/// IORT parser for the subset required by Knife38: SMMUv3 nodes and
/// Root-Complex requester-ID mappings. Node offsets and ID-map output
/// references are relative to the beginning of the IORT table.
fn parse_iort(bytes: &[u8]) -> Vec<SmmuV3Info> {
    if bytes.len() < 48 {
        return Vec::new();
    }
    let count = le32(bytes, 36).unwrap_or(0) as usize;
    let first = le32(bytes, 40).unwrap_or(0) as usize;
    if count == 0 || first < 48 || first >= bytes.len() {
        return Vec::new();
    }
    let mut nodes: Vec<(usize, u8, usize)> = Vec::new();
    let mut off = first;
    for _ in 0..count {
        if off + 16 > bytes.len() {
            break;
        }
        let ty = bytes[off];
        let len = le16(bytes, off + 1).unwrap_or(0) as usize;
        if len < 16 || off.checked_add(len).filter(|e| *e <= bytes.len()).is_none() {
            break;
        }
        nodes.push((off, ty, len));
        off += len;
    }
    let mut out = Vec::new();
    for &(node_off, ty, len) in &nodes {
        if ty != 4 || len < 68 {
            continue;
        }
        let base = le64(bytes, node_off + 16).unwrap_or(0);
        if base == 0 {
            continue;
        }
        out.push(SmmuV3Info {
            base,
            event_irq: le32(bytes, node_off + 44).unwrap_or(0),
            pri_irq: le32(bytes, node_off + 48).unwrap_or(0),
            gerr_irq: le32(bytes, node_off + 52).unwrap_or(0),
            sync_irq: le32(bytes, node_off + 56).unwrap_or(0),
            rid_start: 0,
            rid_count: 0,
        });
    }
    // Root Complex (type 2) ID mappings point at SMMUv3 node offsets.
    for &(node_off, ty, len) in &nodes {
        if ty != 2 || len < 36 {
            continue;
        }
        let maps = le32(bytes, node_off + 8).unwrap_or(0) as usize;
        let map_off = le32(bytes, node_off + 12).unwrap_or(0) as usize;
        let start = node_off.saturating_add(map_off);
        for i in 0..maps {
            let m = start.saturating_add(i * 20);
            if m + 20 > node_off + len || m + 20 > bytes.len() {
                break;
            }
            let input = le32(bytes, m).unwrap_or(0);
            let count_minus_1 = le32(bytes, m + 4).unwrap_or(0);
            let output_ref = le32(bytes, m + 12).unwrap_or(u32::MAX) as usize;
            if let Some((idx, _)) = nodes
                .iter()
                .enumerate()
                .find(|(_, n)| n.0 == output_ref && n.1 == 4)
            {
                if let Some(smmu) = out.get_mut(
                    idx.saturating_sub(nodes.iter().take(idx).filter(|n| n.1 != 4).count()),
                ) {
                    if smmu.rid_count == 0 {
                        smmu.rid_start = input;
                        smmu.rid_count = count_minus_1.saturating_add(1);
                    }
                }
            }
        }
    }
    out
}

fn parse_table_bytes(sig: [u8; 4], bytes: &[u8], parsed: &mut ParsedTables) {
    match &sig {
        b"APIC" if bytes.len() >= 44 => {
            let (cpus, gicd, gicr, its) = parse_madt_entries(bytes, 44);
            parsed.cpus.extend(cpus);
            if parsed.gicd == 0 {
                parsed.gicd = gicd.unwrap_or(0);
            }
            if parsed.gicr == 0 {
                parsed.gicr = gicr.unwrap_or(0);
            }
            if parsed.its == 0 {
                parsed.its = its.unwrap_or(0);
            }
            if parsed.gicc == 0 {
                parsed.gicc = parsed
                    .cpus
                    .iter()
                    .find_map(|c| (c.gicc_base != 0).then_some(c.gicc_base))
                    .unwrap_or(0);
            }
            if parsed.gicr == 0 {
                parsed.gicr = parsed
                    .cpus
                    .iter()
                    .find_map(|c| (c.gicr_base != 0).then_some(c.gicr_base))
                    .unwrap_or(0);
            }
        }
        b"GTDT" => {
            if let Some((irq, flags)) = parse_gtdt(bytes) {
                parsed.timer_irq = irq;
                parsed.timer_flags = flags;
            }
        }
        b"FACP" => {
            parsed.psci_conduit = parse_fadt_psci(bytes) as u8;
            parsed.reset = parse_fadt_reset(bytes);
        }
        b"MCFG" => parsed.ecam.extend(parse_mcfg(bytes)),
        b"IORT" => parsed.smmus.extend(parse_iort(bytes)),
        _ => {}
    }
}

/// 引导期一次性解析。此函数必须在 MM/恒等映射完成后、GIC/timer 平台初始化前调用。
pub fn init() {
    if PARSED.swap(true, Ordering::SeqCst) {
        return;
    }
    #[cfg(any(test, not(target_os = "none")))]
    let rsdp = 0u64;
    #[cfg(any(test, not(target_os = "none")))]
    {
        return;
    }
    #[cfg(all(target_os = "none", not(test)))]
    let rsdp = unsafe { core::ptr::addr_of!(__zero_rsdp_phys).read_volatile() };
    if rsdp == 0 || !rsdp_valid(rsdp) {
        crate::info!("acpi: RSDP absent/invalid; legacy platform defaults stay");
        return;
    }
    let xsdt = rd64(rsdp, 24);
    let Some((sig, xsdt_len)) = (xsdt != 0).then(|| sdt_header(xsdt)).flatten() else {
        crate::info!("acpi: XSDT invalid; legacy platform defaults stay");
        return;
    };
    if &sig != b"XSDT" || (xsdt_len - SDT_HEADER_LEN) % 8 != 0 {
        crate::info!("acpi: XSDT malformed; legacy platform defaults stay");
        return;
    }

    let mut parsed = ParsedTables {
        psci_conduit: PsciConduit::LegacyHvc as u8,
        ..ParsedTables::default()
    };
    let entries = (xsdt_len - SDT_HEADER_LEN) / 8;
    for i in 0..entries {
        let table = rd64(xsdt, SDT_HEADER_LEN + i * 8);
        let Some((table_sig, len)) = (table != 0).then(|| sdt_header(table)).flatten() else {
            continue;
        };
        let bytes = unsafe { core::slice::from_raw_parts(table as *const u8, len) };
        parse_table_bytes(table_sig, bytes, &mut parsed);
    }

    parsed.cpus.sort_by_key(|c| (c.mpidr, c.uid));
    parsed.cpus.dedup_by_key(|c| (c.mpidr, c.uid));
    let cpu_count = parsed.cpus.iter().filter(|c| c.enabled).count();
    let ecam_count = parsed.ecam.len();
    *CPUS.lock() = parsed.cpus;
    *ECAM.lock() = parsed.ecam;
    *SMMUS.lock() = parsed.smmus;
    GICD_BASE.store(parsed.gicd, Ordering::SeqCst);
    GICC_BASE.store(parsed.gicc, Ordering::SeqCst);
    GICR_BASE.store(parsed.gicr, Ordering::SeqCst);
    ITS_BASE.store(parsed.its, Ordering::SeqCst);
    TIMER_IRQ.store(parsed.timer_irq, Ordering::SeqCst);
    TIMER_FLAGS.store(parsed.timer_flags, Ordering::SeqCst);
    PSCI_CONDUIT.store(parsed.psci_conduit, Ordering::SeqCst);
    *RESET_REGISTER.lock() = parsed.reset;
    crate::info!(
        "acpi: cpus={} gicd={:#x} gicc={:#x} gicr={:#x} its={:#x} timer_irq={} psci={:?} reset_reg={} ecam_segments={} smmu_v3={}",
        cpu_count,
        parsed.gicd,
        parsed.gicc,
        parsed.gicr,
        parsed.its,
        parsed.timer_irq,
        psci_conduit(),
        RESET_REGISTER.lock().is_some(),
        ecam_count,
        SMMUS.lock().len()
    );
}

pub fn cpu_mpidrs() -> Vec<u64> {
    init();
    CPUS.lock()
        .iter()
        .filter(|c| c.enabled || c.online_capable)
        .map(|c| c.mpidr)
        .collect()
}

/// Cached raw GICC inventory for SMP/platform diagnostics. Never re-reads ACPI.
pub fn cpu_inventory() -> Vec<MadtCpu> {
    init();
    CPUS.lock().clone()
}

pub fn gicd_base() -> Option<u64> {
    init();
    match GICD_BASE.load(Ordering::SeqCst) {
        0 => None,
        v => Some(v),
    }
}

pub fn gicc_base() -> Option<u64> {
    init();
    match GICC_BASE.load(Ordering::SeqCst) {
        0 => None,
        v => Some(v),
    }
}

pub fn gicr_base() -> Option<u64> {
    init();
    match GICR_BASE.load(Ordering::SeqCst) {
        0 => None,
        v => Some(v),
    }
}

pub fn its_base() -> Option<u64> {
    init();
    match ITS_BASE.load(Ordering::SeqCst) {
        0 => None,
        v => Some(v),
    }
}

pub fn timer_irq() -> Option<u32> {
    init();
    match TIMER_IRQ.load(Ordering::SeqCst) {
        0 => None,
        v => Some(v),
    }
}

pub fn timer_flags() -> u32 {
    init();
    TIMER_FLAGS.load(Ordering::SeqCst)
}

pub fn psci_conduit() -> PsciConduit {
    init();
    match PSCI_CONDUIT.load(Ordering::SeqCst) {
        x if x == PsciConduit::Hvc as u8 => PsciConduit::Hvc,
        x if x == PsciConduit::Smc as u8 => PsciConduit::Smc,
        _ => PsciConduit::LegacyHvc,
    }
}

pub fn reset_register() -> Option<ResetRegister> {
    init();
    *RESET_REGISTER.lock()
}

/// Best-effort FADT reset write. A successful reset never returns; `true` only
/// means the SystemMemory GAS write was issued and the caller may wait briefly.
pub fn try_fadt_reset() -> bool {
    let Some(r) = reset_register() else {
        return false;
    };
    if r.address_space != 0 || r.bit_offset != 0 || r.bit_width > 8 {
        crate::warn!(
            "acpi: FADT reset GAS unsupported space={} width={} offset={}",
            r.address_space,
            r.bit_width,
            r.bit_offset
        );
        return false;
    }
    let Some(v) = crate::mm::paging::ioremap_device(r.address as usize, 1) else {
        return false;
    };
    unsafe { core::ptr::write_volatile(v as *mut u8, r.value) };
    true
}

pub fn ecam_segments() -> Vec<EcamSegment> {
    init();
    ECAM.lock().clone()
}

pub fn smmu_v3_units() -> Vec<SmmuV3Info> {
    init();
    SMMUS.lock().clone()
}

/// Early platform MMIO bases that must be Device memory in the kernel identity
/// map before GIC/SMMU code can touch them. ACPI has already been parsed while
/// firmware page tables are still active, so this function reads cached state
/// only; it never dereferences firmware tables after TTBR handoff.
pub fn early_mmio_bases() -> Vec<u64> {
    init();
    let mut out = Vec::new();
    for base in [
        GICD_BASE.load(Ordering::SeqCst),
        GICC_BASE.load(Ordering::SeqCst),
        GICR_BASE.load(Ordering::SeqCst),
        ITS_BASE.load(Ordering::SeqCst),
    ] {
        if base != 0 && !out.contains(&base) {
            out.push(base);
        }
    }
    for cpu in CPUS.lock().iter() {
        for base in [cpu.gicc_base, cpu.gicr_base] {
            if base != 0 && !out.contains(&base) {
                out.push(base);
            }
        }
    }
    for smmu in SMMUS.lock().iter() {
        if smmu.base != 0 && !out.contains(&smmu.base) {
            out.push(smmu.base);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(buf: &mut Vec<u8>, off: usize, bytes: &[u8]) {
        if buf.len() < off + bytes.len() {
            buf.resize(off + bytes.len(), 0);
        }
        buf[off..off + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn madt_parses_cpu_gicd_gicc_and_gicr() {
        let mut b = vec![0u8; 44];
        let gicd = b.len();
        put(&mut b, gicd, &[12, 24]);
        put(&mut b, gicd + 8, &0x0800_0000u64.to_le_bytes());
        let cpu = gicd + 24;
        put(&mut b, cpu, &[11, 80]);
        put(&mut b, cpu + 8, &7u32.to_le_bytes());
        put(&mut b, cpu + 12, &1u32.to_le_bytes());
        put(&mut b, cpu + 32, &0x0801_0000u64.to_le_bytes());
        put(&mut b, cpu + 60, &0x080a_0000u64.to_le_bytes());
        put(&mut b, cpu + 68, &0x8000_0001u64.to_le_bytes());
        let redist = cpu + 80;
        put(&mut b, redist, &[14, 16]);
        put(&mut b, redist + 4, &0x080b_0000u64.to_le_bytes());
        b.resize(redist + 16, 0);
        let (cpus, dist, red, its) = parse_madt_entries(&b, 44);
        assert_eq!(dist, Some(0x0800_0000));
        assert_eq!(red, Some(0x080b_0000));
        assert_eq!(its, None);
        assert_eq!(
            cpus,
            vec![MadtCpu {
                mpidr: 0x8000_0001,
                uid: 7,
                enabled: true,
                online_capable: false,
                parking_protocol_version: 0,
                parked_address: 0,
                gicc_base: 0x0801_0000,
                gicr_base: 0x080a_0000
            }]
        );
    }

    #[test]
    fn madt_preserves_online_capable_cpu() {
        let mut b = vec![0u8; 44];
        let cpu = b.len();
        put(&mut b, cpu, &[11, 80]);
        put(&mut b, cpu + 8, &9u32.to_le_bytes());
        put(&mut b, cpu + 12, &(1u32 << 3).to_le_bytes());
        put(&mut b, cpu + 68, &2u64.to_le_bytes());
        b.resize(cpu + 80, 0);
        let (cpus, _, _, _) = parse_madt_entries(&b, 44);
        assert_eq!(cpus.len(), 1);
        assert!(!cpus[0].enabled);
        assert!(cpus[0].online_capable);
        assert_eq!(cpus[0].parking_protocol_version, 0);
        assert_eq!(cpus[0].parked_address, 0);
        assert_eq!(cpus[0].mpidr, 2);
    }

    #[test]
    fn madt_parses_parking_protocol_metadata() {
        let mut b = vec![0u8; 44];
        let cpu = b.len();
        put(&mut b, cpu, &[11, 80]);
        put(&mut b, cpu + 8, &3u32.to_le_bytes());
        put(&mut b, cpu + 12, &1u32.to_le_bytes());
        put(&mut b, cpu + 16, &1u32.to_le_bytes());
        put(&mut b, cpu + 24, &0x1234_5000u64.to_le_bytes());
        put(&mut b, cpu + 68, &3u64.to_le_bytes());
        b.resize(cpu + 80, 0);
        let (cpus, _, _, _) = parse_madt_entries(&b, 44);
        assert_eq!(cpus[0].parking_protocol_version, 1);
        assert_eq!(cpus[0].parked_address, 0x1234_5000);
    }

    #[test]
    fn madt_truncated_entry_stops_safely() {
        let mut b = vec![0u8; 46];
        b[44] = 11;
        b[45] = 80;
        let (cpus, gicd, gicr, its) = parse_madt_entries(&b, 44);
        assert!(cpus.is_empty());
        assert_eq!(gicd, None);
        assert_eq!(gicr, None);
        assert_eq!(its, None);
    }

    #[test]
    fn gtdt_timer_fields_and_truncation() {
        let mut b = vec![0u8; 64];
        put(&mut b, 56, &30u32.to_le_bytes());
        put(&mut b, 60, &3u32.to_le_bytes());
        assert_eq!(parse_gtdt(&b), Some((30, 3)));
        assert_eq!(parse_gtdt(&b[..63]), None);
    }

    #[test]
    fn fadt_psci_conduit_matrix() {
        let mut b = vec![0u8; 136];
        assert_eq!(parse_fadt_psci(&b), PsciConduit::LegacyHvc);
        put(&mut b, 129, &1u16.to_le_bytes());
        assert_eq!(parse_fadt_psci(&b), PsciConduit::Smc);
        put(&mut b, 129, &3u16.to_le_bytes());
        assert_eq!(parse_fadt_psci(&b), PsciConduit::Hvc);
        assert_eq!(parse_fadt_psci(&b[..129]), PsciConduit::LegacyHvc);
    }

    #[test]
    fn fadt_reset_register_is_parsed_only_when_supported() {
        let mut b = vec![0u8; 136];
        put(&mut b, 112, &(1u32 << 10).to_le_bytes());
        b[116] = 0;
        b[117] = 8;
        b[118] = 0;
        b[119] = 1;
        put(&mut b, 120, &0x0902_0000u64.to_le_bytes());
        b[128] = 0x5a;
        assert_eq!(
            parse_fadt_reset(&b),
            Some(ResetRegister {
                address_space: 0,
                bit_width: 8,
                bit_offset: 0,
                access_size: 1,
                address: 0x0902_0000,
                value: 0x5a
            })
        );
        put(&mut b, 112, &0u32.to_le_bytes());
        assert_eq!(parse_fadt_reset(&b), None);
    }

    #[test]
    fn mcfg_filters_invalid_ranges() {
        let mut b = vec![0u8; 44];
        put(&mut b, 44, &0x4010_0000u64.to_le_bytes());
        put(&mut b, 52, &2u16.to_le_bytes());
        b.resize(60, 0);
        b[54] = 0x20;
        b[55] = 0x2f;
        put(&mut b, 60, &0x5000_0000u64.to_le_bytes());
        b.resize(76, 0);
        b[70] = 5;
        b[71] = 4;
        assert_eq!(
            parse_mcfg(&b),
            vec![EcamSegment {
                base: 0x4010_0000,
                segment: 2,
                start_bus: 0x20,
                end_bus: 0x2f
            }]
        );
    }

    #[test]
    fn iort_parses_smmuv3_and_root_rid_mapping() {
        let mut b = vec![0u8; 48];
        put(&mut b, 36, &2u32.to_le_bytes());
        put(&mut b, 40, &48u32.to_le_bytes());
        let smmu = 48usize;
        b.resize(smmu + 68, 0);
        b[smmu] = 4;
        put(&mut b, smmu + 1, &68u16.to_le_bytes());
        put(&mut b, smmu + 16, &0x0905_0000u64.to_le_bytes());
        put(&mut b, smmu + 44, &106u32.to_le_bytes());
        let rc = smmu + 68;
        b.resize(rc + 56, 0);
        b[rc] = 2;
        put(&mut b, rc + 1, &56u16.to_le_bytes());
        put(&mut b, rc + 8, &1u32.to_le_bytes());
        put(&mut b, rc + 12, &36u32.to_le_bytes());
        let m = rc + 36;
        put(&mut b, m, &0u32.to_le_bytes());
        put(&mut b, m + 4, &255u32.to_le_bytes());
        put(&mut b, m + 12, &(smmu as u32).to_le_bytes());
        let got = parse_iort(&b);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].base, 0x0905_0000);
        assert_eq!(got[0].event_irq, 106);
        assert_eq!((got[0].rid_start, got[0].rid_count), (0, 256));
    }

    #[test]
    fn checksum_helper_rejects_corruption() {
        assert!(checksum_bytes(&[1, 2, 253]));
        assert!(!checksum_bytes(&[1, 2, 252]));
    }
}
