//! # fuzz-syscall —— syscall 参数校验模糊测试 harness（工程化基建三件套 · 件二）
//!
//! 针对内核 syscall 入口的**纯函数**校验层做属性式测试（评审意见：恶意指针/
//! 巨大 len/哨兵区间此前无模糊测试覆盖）：
//!
//! - [`zero_abi::validate::validate_user_ptr`]：范围 / 内核区隔离 /
//!   `checked_add` 溢出 / 用户栈顶上限；
//! - [`zero_abi::validate::validate_mmio_region`]：QEMU virt 设备区边界；
//! - [`zero_abi::validate::message_ptr_aligned`]：IPC Message 对齐（align=4）；
//! - `decode_syscall` 表完整性：号位 0..=22 全覆盖、未知号位 None
//!   （内核 trap.rs 实现的语义快照，见 tests/decode_table_fuzz.rs）。
//!
//! ## 确定性纪律
//!
//! 伪随机统一走本 crate 的 [`Rng`]（xorshift64*，固定种子）。任何一次
//! 失败都能用同一 seed 原样复现——CI 里没有 flake，只有真 bug。
//! 被测逻辑本体是 zero_abi 宿主可测纯函数层（工程化第八刀从内核
//! syscalls.rs 上收），本 crate 不链接内核。

/// xorshift64* 确定性伪随机数发生器（零依赖；种子恒非零）。
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self(seed | 1) // 0 是 xorshift 不动点，强制非零
    }

    /// 下一个 64 位伪随机值。
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// `[0, bound)` 内的伪随机值（取模偏差对边界扫描无影响）。
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}
