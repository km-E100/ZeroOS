//! 属性式模糊测试：用户指针 / MMIO 租约校验（恶意指针与巨大 len 防线）。
//!
//! 被测真值源：[`zero_abi::validate`]（自内核 syscalls.rs 上收的纯函数层）。
//! 判定基准（oracle）按 ABI 文档**独立**重写，而非复用被测函数——两边
//! 实现路径不同，一致才算过。

use fuzz_syscall::Rng;
use zero_abi::validate::{
    validate_mmio_region, validate_user_ptr, DEVICE_MMIO_HI, DEVICE_MMIO_LO, KERNEL_REGION_END,
    KERNEL_REGION_START, USER_VA_LO, USER_VA_MAX,
};

/// 文档规则的重写版（返回是否放行）：NULL 拒绝、低于 USER_VA_LO 拒绝、
/// 内核区拒绝、回绕溢出或越过栈顶拒绝。
fn oracle_user_ptr(addr: u64, size: u64) -> bool {
    addr != 0
        && addr >= USER_VA_LO
        && !(KERNEL_REGION_START..KERNEL_REGION_END).contains(&addr)
        && match addr.checked_add(size) {
            Some(end) => end <= USER_VA_MAX,
            None => false,
        }
}

/// MMIO oracle：len 非 0 且 [base, base+len) 整体落在设备区。
fn oracle_mmio(base: u64, len: u64) -> bool {
    len != 0
        && base >= DEVICE_MMIO_LO
        && match base.checked_add(len) {
            Some(end) => end <= DEVICE_MMIO_HI,
            None => false,
        }
}

/// 冻结边界与其页界邻域（0、MAX、MAX-1、边界±1、页界±1 全覆盖）。
fn addr_edges() -> Vec<u64> {
    let mut v = vec![0u64, 1, 2, 0x1000, u64::MAX - 1, u64::MAX];
    for b in [
        USER_VA_LO,
        KERNEL_REGION_START,
        KERNEL_REGION_END,
        USER_VA_MAX,
    ] {
        v.extend([b - 0x1000, b - 1, b, b + 1, b + 0x1000]);
    }
    v
}

fn size_edges() -> Vec<u64> {
    vec![
        0,
        1,
        2,
        3,
        4,
        4095,
        4096,
        4097,
        USER_VA_MAX,
        u64::MAX - 1,
        u64::MAX,
    ]
}

#[test]
fn edge_grid_matches_documented_rule() {
    // 冻结边界 × 典型长度的全组合：被测函数与 oracle 必须逐一吻合，
    // 且错误一律是 InvalidArgument（第一道防线的唯一出口）。
    for a in addr_edges() {
        for s in size_edges() {
            let got = validate_user_ptr(a, s);
            assert_eq!(
                got.is_ok(),
                oracle_user_ptr(a, s),
                "addr=0x{a:x} size=0x{s:x} got={got:?}"
            );
            if let Err(e) = got {
                assert_eq!(e, zero_abi::syscall::SysError::InvalidArgument);
            }
        }
    }
}

#[test]
fn kernel_region_is_absolutely_sealed() {
    // 内核恒等映射区 [1GiB, 2GiB)（半开区间）：任何 len（含 0）都不得进入。
    for a in KERNEL_REGION_START..KERNEL_REGION_END {
        assert!(validate_user_ptr(a, 0).is_err(), "addr=0x{a:x}");
    }
    // 区外紧邻地址必须放行（len=0 的纯范围探测）。
    assert!(validate_user_ptr(KERNEL_REGION_START - 1, 0).is_ok());
    assert!(validate_user_ptr(KERNEL_REGION_END, 0).is_ok());
}

#[test]
fn overflow_and_top_rejected() {
    // 回绕溢出与栈顶越界的代表样本（含内核单测固化的两个端点）。
    for (a, s) in [
        (u64::MAX, 2),
        (u64::MAX - 1, 2),
        (USER_VA_MAX - 3, 4), // 越顶 1 字节
        (USER_VA_LO, u64::MAX),
    ] {
        assert!(
            validate_user_ptr(a, s).is_err(),
            "addr=0x{a:x} size=0x{s:x}"
        );
    }
    assert!(validate_user_ptr(USER_VA_MAX - 4, 4).is_ok()); // 恰好贴顶
}

#[test]
fn random_pairs_match_oracle() {
    // 固定种子伪随机扫描：均匀 addr × 多种长度分布（小 len / 巨型 len）。
    for seed in [0xDEAD_BEEFu64, 0x0DDB1A5, 0xFEED_FACE] {
        let mut rng = Rng::new(seed);
        for _ in 0..4096 {
            let a = rng.next_u64();
            let strategies = [
                rng.below(4096),         // 小缓冲区
                rng.below(1 << 33),      // GB 级
                u64::MAX - rng.below(8), // 贴 MAX（必炸）
                rng.next_u64(),          // 全域均匀
            ];
            for s in strategies {
                let got = validate_user_ptr(a, s);
                assert_eq!(
                    got.is_ok(),
                    oracle_user_ptr(a, s),
                    "seed=0x{seed:x} addr=0x{a:x} size=0x{s:x}"
                );
            }
        }
    }
}

#[test]
fn acceptance_is_downward_closed_in_len() {
    // 放行不变量：(a, s) 放行 ⇒ 更短的 (a, s·) 也放行。
    // （全部与长度有关的判定都经 end = a+s ≤ USER_VA_MAX 单调传导。）
    let mut rng = Rng::new(0xABCD_1234);
    for _ in 0..2048 {
        let (a, s) = (rng.next_u64(), rng.next_u64());
        if validate_user_ptr(a, s).is_ok() {
            for smaller in [0, 1, s / 2, s - 1] {
                assert!(
                    validate_user_ptr(a, smaller).is_ok(),
                    "downward closure violated: a=0x{a:x} s=0x{s:x} -> {smaller}"
                );
            }
        }
    }
}

#[test]
fn mmio_edge_grid_matches_documented_rule() {
    // 设备区边界的全邻域组合；len=0 与下界之下必须拒绝（内核单测同款样本）。
    let bases = [
        0u64,
        DEVICE_MMIO_LO - 1,
        DEVICE_MMIO_LO,
        0x0900_0000, // PL011
        DEVICE_MMIO_HI - 0x1000,
        DEVICE_MMIO_HI - 1,
        DEVICE_MMIO_HI,
        u64::MAX,
    ];
    for b in bases {
        for l in [
            0u64,
            1,
            0x1000,
            0x0010_0000,
            0x0010_0001,
            DEVICE_MMIO_HI,
            u64::MAX,
        ] {
            let got = validate_mmio_region(b, l);
            assert_eq!(
                got.is_ok(),
                oracle_mmio(b, l),
                "base=0x{b:x} len=0x{l:x} got={got:?}"
            );
        }
    }
    // 内核单测固化的合法租约保持合法（行为不因上收而变）。
    assert!(validate_mmio_region(0x0900_0000, 0x1000).is_ok());
    assert!(validate_mmio_region(0x0ff0_0000, 0x0010_0000).is_ok());
}
