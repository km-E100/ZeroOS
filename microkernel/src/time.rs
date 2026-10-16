//! Timekeeping (Knife 26): architected monotonic clock + PL031 realtime RTC.
//!
//! Monotonic time never depends on scheduler tick frequency. Realtime is kept
//! separate because wall-clock can jump after future NTP/manual adjustments.

#[cfg(any(test, not(target_os = "none")))]
use core::sync::atomic::{AtomicU64, Ordering};

pub const CLOCK_MONOTONIC: u32 = 0;
pub const CLOCK_REALTIME: u32 = 1;
const NS_PER_SEC: u64 = 1_000_000_000;
const PL031_BASE: usize = 0x0901_0000;

#[cfg(all(target_arch = "aarch64", target_os = "none", not(test)))]
#[inline]
fn counter() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {0}, cntpct_el0",out(reg)v) };
    v
}
#[cfg(all(target_arch = "aarch64", target_os = "none", not(test)))]
#[inline]
fn frequency() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {0}, cntfrq_el0",out(reg)v) };
    v
}

#[cfg(any(test, not(target_os = "none")))]
static HOST_NS: AtomicU64 = AtomicU64::new(0);
#[cfg(any(test, not(target_os = "none")))]
fn counter() -> u64 {
    HOST_NS.load(Ordering::Relaxed)
}
#[cfg(any(test, not(target_os = "none")))]
fn frequency() -> u64 {
    NS_PER_SEC
}

#[inline]
fn ticks_to_ns(ticks: u64, freq: u64) -> u64 {
    if freq == 0 {
        return 0;
    }
    let sec = ticks / freq;
    let rem = ticks % freq;
    sec.saturating_mul(NS_PER_SEC)
        .saturating_add(rem.saturating_mul(NS_PER_SEC) / freq)
}

pub fn monotonic_ns() -> u64 {
    ticks_to_ns(counter(), frequency())
}
pub fn monotonic_ms() -> u64 {
    monotonic_ns() / 1_000_000
}

pub fn realtime_ns() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "none", not(test)))]
    unsafe {
        // QEMU virt exposes ARM PrimeCell PL031. DR is a 32-bit Unix-seconds
        // counter. The platform is fixed today; true-hardware discovery belongs
        // to the PCI/DT/ACPI hardware phase.
        let seconds = core::ptr::read_volatile(PL031_BASE as *const u32) as u64;
        return seconds.saturating_mul(NS_PER_SEC);
    }
    #[cfg(any(test, not(target_os = "none")))]
    {
        monotonic_ns()
    }
}

pub fn get(clock: u32) -> Option<u64> {
    match clock {
        CLOCK_MONOTONIC => Some(monotonic_ns()),
        CLOCK_REALTIME => Some(realtime_ns()),
        _ => None,
    }
}

/// Convert an absolute monotonic deadline to 10ms scheduler ticks, rounding up.
pub fn deadline_to_scheduler_ticks(deadline_ns: u64) -> u64 {
    let now = monotonic_ns();
    if deadline_ns <= now {
        return 0;
    }
    let delta = deadline_ns - now;
    delta.saturating_add(9_999_999) / 10_000_000
}

#[cfg(test)]
pub fn set_test_monotonic_ns(v: u64) {
    HOST_NS.store(v, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conversion_avoids_large_multiply_overflow() {
        assert_eq!(ticks_to_ns(5_000_000_123, 1_000_000_000), 5_000_000_123);
        assert_eq!(ticks_to_ns(50, 10), 5_000_000_000)
    }
    #[test]
    fn deadline_rounds_up() {
        set_test_monotonic_ns(1_000_000_000);
        assert_eq!(deadline_to_scheduler_ticks(1_000_000_001), 1);
        assert_eq!(deadline_to_scheduler_ticks(1_010_000_000), 1);
        assert_eq!(deadline_to_scheduler_ticks(1_010_000_001), 2);
        assert_eq!(deadline_to_scheduler_ticks(999_000_000), 0)
    }
}
