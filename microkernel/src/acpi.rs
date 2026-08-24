//! ACPI 静态表解析（第十八刀立项 · docs/acpi_static_plan.md WS-C）。
//!
//! 范围：RSDP → XSDT → MADT（GICC 核列表 / GICD 基址）。**AML 不做**。
//! 恒等映射下 VA==PA，表可直接按物理地址读取；checksum 校验失败或
//! 结构异常一律返回空结果——调用方（smp/gic/timer）回退硬编码路径，
//! 不存在"坏表打穿启动"的路径。
//!
//! 数据源：bootloader 在 ExitBootServices 前补丁的 `__zero_rsdp_phys`
//! （0 = 无 ACPI）。

use alloc::vec::Vec;
#[cfg(test)]
use alloc::vec;

/// bootloader 补丁的 RSDP 物理地址（0 = 不可用）。槽位本体定义于
/// boot/boot.S（.rodata.boot，与 __zero_memory_bytes 同款模式）。
extern "C" {
    static __zero_rsdp_phys: u64;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MadtCpu {
    pub mpidr: u64,
    pub uid: u32,
    pub enabled: bool,
}

static CPUS: spin::Mutex<Vec<MadtCpu>> = spin::Mutex::new(Vec::new());
static GICD_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static PARSED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn rd8(base: u64, off: usize) -> u8 {
    unsafe { ((base + off as u64) as *const u8).read_volatile() }
}
fn rd32(base: u64, off: usize) -> u32 {
    unsafe { ((base + off as u64) as *const u32).read_volatile() }
}
fn rd64(base: u64, off: usize) -> u64 {
    unsafe { ((base + off as u64) as *const u64).read_volatile() }
}

/// RSDP 校验：签名 "RSD PTR "、rev>=2、第一段校验和（前 20 字节）
/// 与扩展校验和（全长）均为 0。
fn rsdp_valid(rsdp: u64) -> bool {
    const SIG: [u8; 8] = *b"RSD PTR ";
    for (i, b) in SIG.iter().enumerate() {
        if rd8(rsdp, i) != *b {
            return false;
        }
    }
    let len = rd32(rsdp, 20) as usize; // XSDT 版长度字段位于 +20
    if len < 36 || len > 1024 * 1024 {
        return false;
    }
    let mut sum = 0u8;
    for i in 0..20 {
        sum = sum.wrapping_add(rd8(rsdp, i));
    }
    if sum != 0 {
        return false;
    }
    let mut sum2 = 0u8;
    for i in 0..len {
        sum2 = sum2.wrapping_add(rd8(rsdp, i));
    }
    sum2 == 0
}

/// SDT 头校验：sig(4)+len(4)+summing 全 0。
fn sdt_valid(sdt: u64, sig: &[u8; 4]) -> bool {
    for (i, b) in sig.iter().enumerate() {
        if rd8(sdt, i) != *b {
            return false;
        }
    }
    let len = rd32(sdt, 4) as usize;
    if len < 36 || len > 1024 * 1024 {
        return false;
    }
    let mut sum = 0u8;
    for i in 0..len {
        sum = sum2_wrap(sum, rd8(sdt, i));
    }
    sum == 0
}
fn sum2_wrap(a: u8, b: u8) -> u8 {
    a.wrapping_add(b)
}

/// 纯函数：从 MADT 条目流解析 GICC 核列表与 GICD 基址。
/// `body_off` 为条目区起始（MADT=44）。截断/未知类型跳过不报错。
fn parse_madt_entries(
    bytes: &[u8],
    body_off: usize,
) -> (Vec<MadtCpu>, Option<u64>) {
    let mut cpus = Vec::new();
    let mut gicd: Option<u64> = None;
    let mut off = body_off;
    while off + 2 <= bytes.len() {
        let etype = bytes[off];
        let elen = bytes[off + 1] as usize;
        if elen < 2 || off + elen > bytes.len() {
            break;
        }
        match etype {
            11 if elen >= 76 => {
                // GICC（ACPI v5+）：MPIDR@+68，Flags@+12，UID@+8
                let rd32le = |o: usize| {
                    u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap_or([0; 4]))
                };
                let rd64le = |o: usize| {
                    u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap_or([0; 8]))
                };
                let flags = rd32le(off + 12);
                cpus.push(MadtCpu {
                    mpidr: rd64le(off + 68),
                    uid: rd32le(off + 8),
                    enabled: flags & 1 != 0,
                });
            }
            12 if elen >= 16 => {
                gicd.get_or_insert_with(|| {
                    u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap_or([0; 8]))
                });
            }
            _ => {}
        }
        off += elen;
    }
    (cpus, gicd)
}

/// 引导期一次性解析（幂等）。失败静默留空——调用方回退 legacy 探测。
pub fn init() {
    if PARSED.swap(true, Ordering::SeqCst) {
        return;
    }
    let rsdp = unsafe { core::ptr::addr_of!(__zero_rsdp_phys).read_volatile() };
    if rsdp == 0 || !rsdp_valid(rsdp) {
        crate::info!("acpi: RSDP absent/invalid; legacy probe stays");
        return;
    }
    let xsdt = rd64(rsdp, 24);
    if xsdt == 0 || !sdt_valid(xsdt, b"XSDT") {
        crate::info!("acpi: XSDT invalid; legacy probe stays");
        return;
    }
    let xsdt_len = rd32(xsdt, 4) as usize;
    let entries = (xsdt_len - 36) / 8;

    let mut cpus: Vec<MadtCpu> = Vec::new();
    let mut gicd: u64 = 0;
    for e in 0..entries {
        let table = rd64(xsdt, 36 + e * 8);
        if table == 0 || !sdt_valid(table, b"APIC") {
            continue;
        }
        let tlen = rd32(table, 4) as usize;
        if tlen > 1024 * 1024 {
            break;
        }
        let bytes = unsafe { core::slice::from_raw_parts(table as *const u8, tlen) };
        let (found_cpus, found_gicd) = parse_madt_entries(bytes, 44);
        cpus.extend(found_cpus);
        if gicd == 0 {
            gicd = found_gicd.unwrap_or(0);
        }
        crate::info!("acpi: APIC table parsed at {:#x}", table);
        break; // 只取第一个 APIC 表
    }

    let n = cpus.len();
    *CPUS.lock() = cpus;
    GICD_BASE.store(gicd, Ordering::SeqCst);
    crate::info!(
        "acpi: MADT cpus={} gicd={:#x}",
        n,
        GICD_BASE.load(Ordering::SeqCst)
    );
}

/// 已枚举的核列表（含主核；enabled 位过滤）。
pub fn cpu_mpidrs() -> Vec<u64> {
    init();
    CPUS.lock()
        .iter()
        .filter(|c| c.enabled)
        .map(|c| c.mpidr)
        .collect()
}

/// MADT 枚举的 GICD 基址（0 = 未提供）。
pub fn gicd_base() -> u64 {
    init();
    GICD_BASE.load(Ordering::SeqCst)
}

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin;



#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    
    fn put(buf: &mut Vec<u8>, off: usize, bytes: &[u8]) {
        let end = off + bytes.len();
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[off..off + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn madt_entry_parse_matrix() {
        let mut b: Vec<u8> = alloc::vec![0; 0];
        // 头部 44 字节占位（纯函数只关心条目区）
        b.resize(44, 0);
        let e0 = 44usize;
        put(&mut b, e0, &[12, 16]);                     // GICD len=16
        put(&mut b, e0 + 8, &0x0800_0000u64.to_le_bytes());
        let e1 = e0 + 16;
        put(&mut b, e1, &[11, 80]);                     // GICC cpu1 enabled
        put(&mut b, e1 + 12, &1u32.to_le_bytes());      // flags.enabled
        put(&mut b, e1 + 68, &0x8000_0001u64.to_le_bytes());
        let e2 = e1 + 80;
        put(&mut b, e2, &[11, 80]);                     // GICC cpu2 disabled
        put(&mut b, e2 + 12, &0u32.to_le_bytes());
        put(&mut b, e2 + 68, &0x8000_0002u64.to_le_bytes());
        let tail = e2 + 84;
        // 截断条目（len 声明越界）应被安全跳过：
        put(&mut b, tail, &[11, 200]);

        let (cpus, gicd) = super::parse_madt_entries(&b, 44);
        assert_eq!(gicd, Some(0x0800_0000));
        assert_eq!(cpus.len(), 2); // 截断条目不计入
        assert!(cpus[0].enabled && !cpus[1].enabled);
        assert_eq!(cpus[0].mpidr, 0x8000_0001);
        assert_eq!(cpus[1].mpidr, 0x8000_0002);
    }

    #[test]
    fn madt_truncated_body_is_safe() {
        let mut b = vec![0u8; 46];
        b[44] = 11;
        b[45] = 80; // 声明 80 字节但只有 2 字节可用
        let (cpus, gicd) = super::parse_madt_entries(&b, 44);
        assert!(cpus.is_empty());
        assert_eq!(gicd, None);
    }

}
