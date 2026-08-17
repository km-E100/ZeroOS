use core::ptr::{read_volatile, write_volatile};

const GICD_BASE: usize = 0x0800_0000;
const GICC_BASE: usize = 0x0801_0000;

const CTLR_OFFSET: usize = 0x000;
const PMR_OFFSET: usize = 0x004;
const IAR_OFFSET: usize = 0x00c;
const EOIR_OFFSET: usize = 0x010;
const ISENABLER_OFFSET: usize = 0x100;
const IPRIORITY_OFFSET: usize = 0x400;
const ICENABLER_OFFSET: usize = 0x180;

pub const TIMER_IRQ_ID: u32 = 30; // PPI for per-cpu timer

#[inline(always)]
unsafe fn gicd_reg(offset: usize) -> *mut u32 {
    (GICD_BASE + offset) as *mut u32
}

#[inline(always)]
unsafe fn gicc_reg(offset: usize) -> *mut u32 {
    (GICC_BASE + offset) as *mut u32
}

pub unsafe fn init() {
    // Disable
    write_volatile(gicd_reg(CTLR_OFFSET), 0);
    write_volatile(gicc_reg(CTLR_OFFSET), 0);

    // Allow all priorities
    write_volatile(gicc_reg(PMR_OFFSET), 0xFF);

    // Enable timer interrupt (PPI 30)
    enable_irq(TIMER_IRQ_ID);

    // Set priority
    let priority_index = (TIMER_IRQ_ID as usize) & !0x3;
    let shift = (TIMER_IRQ_ID % 4) * 8;
    let priority_reg = gicd_reg(IPRIORITY_OFFSET + priority_index);
    let mut priorities = read_volatile(priority_reg);
    priorities &= !(0xFF << shift);
    priorities |= 0x20 << shift;
    write_volatile(priority_reg, priorities);

    // Enable distributor & CPU interface
    write_volatile(gicd_reg(CTLR_OFFSET), 1);
    write_volatile(gicc_reg(CTLR_OFFSET), 1);
}

pub unsafe fn acknowledge() -> u32 {
    read_volatile(gicc_reg(IAR_OFFSET))
}

pub unsafe fn end_interrupt(id: u32) {
    write_volatile(gicc_reg(EOIR_OFFSET), id);
}

pub fn is_timer_interrupt(id: u32) -> bool {
    (id & 0x3ff) == TIMER_IRQ_ID
}

pub fn interrupt_number(raw: u32) -> u32 {
    raw & 0x3ff
}

pub unsafe fn enable_irq(id: u32) {
    let enable_index = (id / 32) as usize;
    let bit = id % 32;
    let addr = gicd_reg(ISENABLER_OFFSET + enable_index * 4);
    let value = read_volatile(addr) | (1 << bit);
    write_volatile(addr, value);

    let priority_index = (id as usize) & !0x3;
    let shift = (id % 4) * 8;
    let priority_reg = gicd_reg(IPRIORITY_OFFSET + priority_index);
    let mut priorities = read_volatile(priority_reg);
    priorities &= !(0xFF << shift);
    priorities |= 0x40 << shift;
    write_volatile(priority_reg, priorities);
}

pub unsafe fn disable_irq(id: u32) {
    let disable_index = (id / 32) as usize;
    let bit = id % 32;
    let addr = gicd_reg(ICENABLER_OFFSET + disable_index * 4);
    write_volatile(addr, 1 << bit);
}
