//! ARMv8 通用定时器（CNTP，EL1 物理计数器）。
//! 提供周期 tick（10ms 时间片，调度器使用，语义保持不变）与
//! 一次性相对定时（`arm_timer_relative`），供未来 tickless/wfi 使用。
//!
//! cntp_ctl_el0 位定义：bit0 ENABLE、bit1 IMASK（=1 屏蔽中断）。
//! 正确序列：先 IMASK（ctl=2，同时停用）→ 写 cntp_cval_el0 → isb → 解掩
//! （ctl=1）。防止计数越过旧 CVal 的边界竞态导致多打/漏打 tick。

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const CTL_ENABLE: u64 = 1; // ENABLE=1, IMASK=0：运行且中断放行
const CTL_MASKED: u64 = 2; // ENABLE=0, IMASK=1：停止且屏蔽（编程窗口）
/// 完全关闭定时器（仅 tickless/wfi 路径使用，当前回合未接线）。
#[allow(dead_code)]
const CTL_OFF: u64 = 0;

/// 每个时间片的计数器 tick 数（init 时按 cntfrq_el0 换算）。
static TICKS_PER_SLICE: AtomicU64 = AtomicU64::new(0);

/// 初始化：按 cntfrq_el0 换算时间片（默认 10ms）并 arm 第一个 tick。
pub unsafe fn init(slice_ms: u64) {
    let freq = read_freq();
    let ticks = core::cmp::max((freq / 1_000).saturating_mul(slice_ms), 1);
    TICKS_PER_SLICE.store(ticks, Ordering::SeqCst);
    program_next_tick();
}

/// 周期 tick（供调度器调用，语义与拆分前一致）：
/// 自当前计数起 + 一个时间片后再次触发。
pub unsafe fn program_next_tick() {
    let ticks = TICKS_PER_SLICE.load(Ordering::SeqCst);
    arm_cval(read_counter().saturating_add(ticks));
}

/// 一次性相对定时：`delta_ns` 纳秒后触发一次。
/// 供未来 tickless/wfi 使用（当前调度器仍走 program_next_tick，
/// 故本回合未接线，属前瞻 API）。
#[allow(dead_code)]
pub unsafe fn arm_timer_relative(delta_ns: u64) {
    let freq = read_freq();
    // ns → ticks：delta * freq / 1e9，至少 1 tick。
    let delta_ticks = core::cmp::max(delta_ns.saturating_mul(freq) / 1_000_000_000, 1);
    arm_cval(read_counter().saturating_add(delta_ticks));
}

/// 屏蔽并停止定时器（tickless/wfi 进入 idle 时调用）；
/// 停止后不再产生中断。前瞻 API，本回合未接线。
#[allow(dead_code)]
pub unsafe fn disable_timer() {
    asm!("msr cntp_ctl_el0, {ctl}\nisb", ctl = in(reg) CTL_OFF, options(nostack));
}

/// 核心编程序列：mask → 写 CVal → unmask，isb 保证 CVal 先于解掩生效。
#[inline(always)]
unsafe fn arm_cval(cval: u64) {
    asm!("msr cntp_ctl_el0, {ctl}", ctl = in(reg) CTL_MASKED, options(nostack));
    asm!("msr cntp_cval_el0, {val}\nisb", val = in(reg) cval, options(nostack));
    asm!("msr cntp_ctl_el0, {ctl}", ctl = in(reg) CTL_ENABLE, options(nostack));
}

#[inline(always)]
fn read_counter() -> u64 {
    let value: u64;
    unsafe { asm!("mrs {0}, cntpct_el0", out(reg) value) };
    value
}

#[inline(always)]
fn read_freq() -> u64 {
    let freq: u64;
    unsafe { asm!("mrs {0}, cntfrq_el0", out(reg) freq) };
    freq
}
