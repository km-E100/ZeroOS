//! GIC-400（QEMU virt）中断控制器驱动。
//!
//! 设备映射：定时器 PPI=30；virtio-blk irq=32；PL011 irq=33；virtio-net irq=34。
//!
//! 安全策略：
//! - `enable_irq` / `disable_irq` 校验中断号范围 0..=255，越界告警并跳过；
//! - `acknowledge` 直接返回 INTID（剥掉高 22 位状态）；
//! - `end_interrupt` 无条件写 EOIR——对不认识/越界的中断也必须 end，防风暴；
//! - 未 `init` 就调用 enable/disable 时告警（仍写入使能位，位会在分发器
//!   使能后生效，不丢配置）；
//! - `init` 幂等：重复调用直接返回。

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

const LEGACY_GICD_BASE: usize = 0x0800_0000;
const LEGACY_GICC_BASE: usize = 0x0801_0000;
static GICD_BASE: AtomicUsize = AtomicUsize::new(LEGACY_GICD_BASE);
static GICC_BASE: AtomicUsize = AtomicUsize::new(LEGACY_GICC_BASE);
static TIMER_IRQ: AtomicU32 = AtomicU32::new(30);

const CTLR_OFFSET: usize = 0x000;
const PMR_OFFSET: usize = 0x004;
const IAR_OFFSET: usize = 0x00c;
const EOIR_OFFSET: usize = 0x010;
const ISENABLER_OFFSET: usize = 0x100;
const ICENABLER_OFFSET: usize = 0x180;
const IPRIORITY_OFFSET: usize = 0x400;

/// INTID 有效位掩码（GIC-400 为 10 位）：spurious 1023 保留。
const INTID_MASK: u32 = 0x3ff;
/// 本项目只使用 SGI/PPI/SPI，SPI 上限 255。
const MAX_INTID: u32 = 255;

/// 当前每 CPU 定时器 PPI。GTDT 有效时由 ACPI 覆盖，缺失时保持 30。
#[inline]
pub fn timer_irq_id() -> u32 {
    TIMER_IRQ.load(Ordering::Acquire)
}

static INITIALISED: AtomicBool = AtomicBool::new(false);
/// 越界告警只报一次，防高频错误调用刷屏。
static RANGE_WARNED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
unsafe fn gicd_reg(offset: usize) -> *mut u32 {
    (GICD_BASE.load(Ordering::Relaxed) + offset) as *mut u32
}

#[inline(always)]
unsafe fn gicc_reg(offset: usize) -> *mut u32 {
    (GICC_BASE.load(Ordering::Relaxed) + offset) as *mut u32
}

/// 初始化 GIC：幂等。先置位标志，使 init 内部调用 enable_irq 不误告警。
pub unsafe fn init() {
    if INITIALISED.swap(true, Ordering::SeqCst) {
        return;
    }

    let gicd = crate::acpi::gicd_base()
        .map(|v| v as usize)
        .unwrap_or(LEGACY_GICD_BASE);
    let gicc = crate::acpi::gicc_base()
        .map(|v| v as usize)
        .unwrap_or(LEGACY_GICC_BASE);
    let timer_irq = crate::acpi::timer_irq()
        .filter(|id| *id <= MAX_INTID)
        .unwrap_or(30);
    GICD_BASE.store(gicd, Ordering::Release);
    GICC_BASE.store(gicc, Ordering::Release);
    TIMER_IRQ.store(timer_irq, Ordering::Release);

    // 关闭分发器与 CPU 接口，再逐项配置。
    write_volatile(gicd_reg(CTLR_OFFSET), 0);
    write_volatile(gicc_reg(CTLR_OFFSET), 0);

    // 允许全部优先级。
    write_volatile(gicc_reg(PMR_OFFSET), 0xFF);

    // 使能固件描述的 NS EL1 timer PPI；GTDT 缺失时回退 INTID 30。
    enable_irq(timer_irq);
    set_priority(timer_irq, 0x20);

    // 使能分发器与 CPU 接口。
    write_volatile(gicd_reg(CTLR_OFFSET), 1);
    write_volatile(gicc_reg(CTLR_OFFSET), 1);

    crate::info!(
        "gic: platform gicd={:#x} gicc={:#x} timer_irq={}{}",
        gicd,
        gicc,
        timer_irq,
        if crate::acpi::timer_irq().is_some() {
            " (ACPI)"
        } else {
            " (legacy)"
        }
    );
}

/// 副核专用：只初始化本核 banked 的 CPU 接口（GICD 由主核一次配好）。
/// GICv2 的 SGI（INTID 0-15）恒使能，RESCHED SGI 无需额外配置。
pub unsafe fn init_cpu_interface() {
    write_volatile(gicc_reg(PMR_OFFSET), 0xFF);
    write_volatile(gicc_reg(CTLR_OFFSET), 1);
}

/// RESCHED SGI 的 INTID（GICv2 SGI 恒使能，ID0 安全）。
pub const SGI_RESCHED: u32 = 0;

/// 向目标核掩码广播 RESCHED SGI（GICD_SGIR，filter=00 按目标列表）。
/// mask bit i ↔ MPIDR aff0=i。调用方须先扣掉自己（filter=01 是"除己
/// 全体"，这里用显式掩码以便精确控制）。
pub fn send_resched_sgi(target_mask: u8) {
    if target_mask == 0 {
        return;
    }
    let word: u32 = ((target_mask as u32 & 0xFF) << 16) | (SGI_RESCHED & 0xF);
    unsafe { write_volatile(gicd_reg(0xF00), word) };
}

/// 读取并确认中断，返回 INTID（剥掉高 22 位状态）。
/// spurious（1023）原样返回，由调用方 end 并继续。
pub unsafe fn acknowledge() -> u32 {
    read_volatile(gicc_reg(IAR_OFFSET)) & INTID_MASK
}

/// 结束中断。无条件写 EOIR：不认识/越界的中断也必须 end，防止重复触发。
pub unsafe fn end_interrupt(id: u32) {
    write_volatile(gicc_reg(EOIR_OFFSET), id);
}

pub fn is_timer_interrupt(id: u32) -> bool {
    (id & INTID_MASK) == timer_irq_id()
}

pub fn interrupt_number(raw: u32) -> u32 {
    raw & INTID_MASK
}

/// 使能一个 IRQ（并设默认优先级 0x40）。
/// 中断号越界（>255）告警并跳过；init 前调用告警但照常写入。
pub unsafe fn enable_irq(id: u32) {
    if id > MAX_INTID {
        warn_range(id);
        return;
    }
    if !INITIALISED.load(Ordering::SeqCst) {
        crate::warn!("gic: enable_irq({}) 在 init 之前调用", id);
    }
    let enable_index = (id / 32) as usize;
    let bit = id % 32;
    let addr = gicd_reg(ISENABLER_OFFSET + enable_index * 4);
    // ISENABLER 写 1 使能，读回当前值做 RMW 保持其他位。
    let value = read_volatile(addr) | (1 << bit);
    write_volatile(addr, value);

    set_priority(id, 0x40);
}

/// 屏蔽一个 IRQ。中断号越界告警并跳过；init 前调用告警但照常写入。
pub unsafe fn disable_irq(id: u32) {
    if id > MAX_INTID {
        warn_range(id);
        return;
    }
    if !INITIALISED.load(Ordering::SeqCst) {
        crate::warn!("gic: disable_irq({}) 在 init 之前调用", id);
    }
    let disable_index = (id / 32) as usize;
    let bit = id % 32;
    let addr = gicd_reg(ICENABLER_OFFSET + disable_index * 4);
    write_volatile(addr, 1 << bit);
}

/// 写优先级寄存器中对应中断的 8 位字段。
unsafe fn set_priority(id: u32, priority: u32) {
    let priority_index = (id as usize) & !0x3;
    let shift = (id % 4) * 8;
    let priority_reg = gicd_reg(IPRIORITY_OFFSET + priority_index);
    let mut priorities = read_volatile(priority_reg);
    priorities &= !(0xFF << shift);
    priorities |= priority << shift;
    write_volatile(priority_reg, priorities);
}

fn warn_range(id: u32) {
    if !RANGE_WARNED.swap(true, Ordering::SeqCst) {
        crate::warn!("gic: 中断号 {} 越界 (0..={})", id, MAX_INTID);
    }
}
