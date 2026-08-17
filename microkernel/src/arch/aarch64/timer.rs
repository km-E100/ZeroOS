use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

static TICKS_PER_SLICE: AtomicU64 = AtomicU64::new(0);

pub unsafe fn init(slice_ms: u64) {
    let freq: u64;
    asm!("mrs {0}, cntfrq_el0", out(reg) freq);
    let ticks = core::cmp::max((freq / 1_000).saturating_mul(slice_ms), 1);
    TICKS_PER_SLICE.store(ticks, Ordering::SeqCst);

    // Disable while programming the next tick to avoid spurious expiry.
    asm!("msr cntp_ctl_el0, {ctl}", ctl = in(reg) 0u64, options(nostack));
    program_next_tick();
    asm!("msr cntp_ctl_el0, {ctl}", ctl = in(reg) 1u64, options(nostack));
}

pub unsafe fn program_next_tick() {
    let ticks = TICKS_PER_SLICE.load(Ordering::SeqCst);
    let next = read_counter() + ticks;
    asm!(
        "msr cntp_cval_el0, {val}\nisb",
        val = in(reg) next,
        options(nostack)
    );
}

#[inline(always)]
fn read_counter() -> u64 {
    let value: u64;
    unsafe { asm!("mrs {0}, cntpct_el0", out(reg) value) };
    value
}
