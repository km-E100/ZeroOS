//! 启动期熵源与伪随机数（KASLR 阶段 1 · 第十五刀）。
//!
//! 熵源：cntpct_el0 计数器抖动 ⊕ MPIDR（多核下副核上线时序天然异步，
//! 抖动熵充足）。**非密码学安全**——仅用于地址布局随机化（用户栈偏移）。
//!
//! 输出：splitmix64 终结混合，全局原子状态 CAS 步进保证多核不重样。

use core::sync::atomic::{AtomicU64, Ordering};

static STATE: AtomicU64 = AtomicU64::new(0);

/// ⚠ 宿主单测在 EL0 执行，读计数器/MPIDR 会 SIGILL——测试桩返回常量
/// （splitmix 混合逻辑仍被真实覆盖，仅熵源退化为确定性）。
#[inline(always)]
fn counter() -> u64 {
    #[cfg(test)]
    {
        0x5EED_C0DE_FEED
    }
    #[cfg(not(test))]
    {
        let v: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v) };
        v
    }
}

#[inline(always)]
fn mpidr() -> u64 {
    #[cfg(test)]
    {
        0x8000_0000
    }
    #[cfg(not(test))]
    {
        let v: u64;
        unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) v) };
        v
    }
}

/// 取一个伪随机 u64（splitmix64 终结；CAS 步进防跨核重样）。
pub fn next() -> u64 {
    let mut old = STATE.load(Ordering::Relaxed);
    loop {
        let candidate = old.wrapping_add(0x9E37_79B9_7F4A_7C15);
        match STATE.compare_exchange(old, candidate, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => {
                let mut z = candidate ^ counter().rotate_left(17) ^ mpidr();
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                return z ^ (z >> 31);
            }
            Err(observed) => old = observed,
        }
    }
}

/// 页粒度随机偏移：`[0, max_pages)` 页。max_pages=0 时返回 0。
pub fn random_page_offset(max_pages: usize) -> usize {
    if max_pages == 0 {
        return 0;
    }
    (next() as usize) % max_pages
}
