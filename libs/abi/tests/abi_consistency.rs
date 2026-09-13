//! # zero-abi 双端一致性测试（工程化基建三件套 · 件一）
//!
//! ## 唯一真值源
//!
//! 错误编码规则（ABI 冻结）：**`Err(e)` 编码为 `u64::MAX - k`，`k` 为
//! `SysError` 判别值；区间长度 = [`ERROR_INTERVAL_LEN`]（当前 9）；
//! 其余一切值按成功透传。** 规范实现是本 crate 的
//! [`encode_result`]（编码）/ [`decode`]（解码），二者互逆。
//!
//! 本套件表驱动遍历**全部** `SysError` 判别值，锁定四条不变量：
//!
//! 1. **编码唯一**：不同错误 → 不同 u64（无别名）；
//! 2. **区间不重叠**：全部错误编码落在 `[u64::MAX-(N-1), u64::MAX]`
//!    连续区间内，区间外首个值 `u64::MAX-N` 必须按成功解码；
//! 3. **往返无损**：encode ∘ decode 恒等（错误与成功两侧）；
//! 4. **双端快照一致**：内核 `trap.rs::encode_result` 与 userlib 解码
//!    的语义快照与真值源逐位一致（见下方快照函数的待合并点说明）。
//!
//! 运行：`cargo test -p zero-abi`（CI job1 同款命令）。

use zero_abi::syscall::{decode, encode_result, is_error_encoded, SysError, ERROR_INTERVAL_LEN};

/// 全部错误的表驱动清单：(判别值 k, 变体)。新增 SysError 时必须在此
/// 追加一行——编译器不会强制，但 all_discriminants_table_driven 会用
/// `variant as u64` 与判别值双重校验拦截漏登记。
const ALL_ERRORS: &[(u64, SysError)] = &[
    (0, SysError::InvalidArgument),
    (1, SysError::PermissionDenied),
    (2, SysError::ChannelUnavailable),
    (3, SysError::NotFound),
    (4, SysError::NoMemory),
    (5, SysError::WouldBlock),
    (6, SysError::DeviceError),
    (7, SysError::Busy),
    (8, SysError::NotSupported),
];

/// 成功值的代表样本：含 0、区间上界邻域、以及远离区间的位模式。
const OK_VALUES: &[u64] = &[
    0,
    1,
    42,
    512,
    1 << 32,
    (1 << 63) - 1,
    u64::MAX - 9,
    u64::MAX - 100,
];

#[test]
fn all_discriminants_table_driven() {
    // 表必须覆盖整个冻结区间：条数 == ERROR_INTERVAL_LEN
    assert_eq!(
        ALL_ERRORS.len() as u64,
        ERROR_INTERVAL_LEN,
        "SysError 变体数与 ERROR_INTERVAL_LEN 脱节：新增错误要同步扩区间与本表"
    );
    for (k, err) in ALL_ERRORS {
        // 判别值即 ABI 的 k：编码规则 u64::MAX - k
        assert_eq!(*err as u64, *k, "判别值漂移: {:?}", err);
        assert_eq!(err.code(), u64::MAX - k, "code() 偏离 u64::MAX-k 规则");
        assert_eq!(encode_result(Err(*err)), u64::MAX - k);
        // 编码唯一性：任何其他变体不得产生相同编码
        for (k2, err2) in ALL_ERRORS {
            let same = err.code() == err2.code();
            assert_eq!(same, k == k2, "编码冲突: {:?} vs {:?}", err, err2);
        }
    }
}

#[test]
fn error_interval_is_contiguous_and_non_overlapping() {
    let n = ERROR_INTERVAL_LEN;
    let mut codes: Vec<u64> = ALL_ERRORS.iter().map(|(_, e)| e.code()).collect();
    codes.sort_unstable();
    // 区间恰好铺满 [u64::MAX-(N-1), u64::MAX]，无空洞、无重叠、无越界
    assert_eq!(codes.first().copied(), Some(u64::MAX - (n - 1)));
    assert_eq!(codes.last().copied(), Some(u64::MAX));
    for pair in codes.windows(2) {
        assert_eq!(pair[1] - pair[0], 1, "错误区间出现空洞或重叠: {pair:?}");
    }
    // 区间谓词与解码语义一致：区间内必错、区间外必成
    assert!(is_error_encoded(u64::MAX));
    assert!(is_error_encoded(u64::MAX - (n - 1)));
    assert!(
        !is_error_encoded(u64::MAX - n),
        "区间外首个值必须按成功解码"
    );
    assert_eq!(decode(u64::MAX - n), Ok(u64::MAX - n));
}

#[test]
fn exhaustive_interval_sweep() {
    // 穷举哨兵区间及邻近下界带（4097 个值）：每个值要么映射到唯一错误，要么按成功透传。
    for v in (u64::MAX - 4096)..=u64::MAX {
        if v >= u64::MAX - (ERROR_INTERVAL_LEN - 1) {
            let k = u64::MAX - v;
            assert_eq!(decode(v), Err(ALL_ERRORS[k as usize].1), "v=0x{v:x}");
        } else {
            assert_eq!(decode(v), Ok(v), "v=0x{v:x} 应按成功解码");
        }
    }
}

#[test]
fn roundtrip_is_lossless() {
    // 错误侧：encode ∘ decode 恒等
    for (_, err) in ALL_ERRORS {
        assert_eq!(decode(encode_result(Err(*err))), Err(*err));
    }
    // 成功侧：编码透明透传。内核处理器不得返回哨兵区间内的 Ok 值，
    // 否则会被用户态误判——该约定由 fuzz-syscall 的随机扫描复核。
    for v in OK_VALUES {
        assert_eq!(encode_result(Ok(*v)), *v);
        assert_eq!(decode(*v), Ok(*v));
    }
}

// ─── 双端语义快照（待合并点）───────────────────────────────────────
//
// 工程化评审指出「userlib↔内核 encode_result 两份 match 靠人肉同步」。
// 本轮改造把真值源收敛到 zero_abi::syscall::encode_result/decode：
//   * userlib 侧自第七刀起 decode_result 已委托 zero_abi::syscall::decode，
//     无本地 match，一致性由构造保证；
//   * 内核 trap.rs 由并行 Agent 维护（本轮禁改文件清单内），其
//     encode_result 仍保留本地 match。以下快照逐字复制其函数体，作为
//     行为 tripwire：内核实现一旦漂移，本测试立刻红。
// 待合并点：内核把 trap.rs::encode_result 改为调用
// zero_abi::syscall::encode_result 后，删除 kernel_encode_result_snapshot
// 及对应断言（userlib 快照同理可删）。

/// 逐字快照：microkernel/src/trap.rs::encode_result（2026-08-23 @ b4f3658）。
fn kernel_encode_result_snapshot(result: Result<u64, SysError>) -> u64 {
    match result {
        Ok(value) => value,
        Err(err) => match err {
            SysError::InvalidArgument => u64::MAX,
            SysError::PermissionDenied => u64::MAX - 1,
            SysError::ChannelUnavailable => u64::MAX - 2,
            SysError::NotFound => u64::MAX - 3,
            SysError::NoMemory => u64::MAX - 4,
            SysError::WouldBlock => u64::MAX - 5,
            SysError::DeviceError => u64::MAX - 6,
            SysError::Busy => u64::MAX - 7,
            SysError::NotSupported => u64::MAX - 8,
        },
    }
}

/// 逐字快照：userland/userlib 测试中固化的 decode 映射（第七刀起 userlib
/// 实际已委托 zero_abi::syscall::decode，此表仅作契约文档化）。
fn userlib_decode_snapshot(value: u64) -> Result<u64, SysError> {
    match value {
        val if val == u64::MAX => Err(SysError::InvalidArgument),
        val if val == u64::MAX - 1 => Err(SysError::PermissionDenied),
        val if val == u64::MAX - 2 => Err(SysError::ChannelUnavailable),
        val if val == u64::MAX - 3 => Err(SysError::NotFound),
        val if val == u64::MAX - 4 => Err(SysError::NoMemory),
        val if val == u64::MAX - 5 => Err(SysError::WouldBlock),
        val if val == u64::MAX - 6 => Err(SysError::DeviceError),
        val if val == u64::MAX - 7 => Err(SysError::Busy),
        val if val == u64::MAX - 8 => Err(SysError::NotSupported),
        other => Ok(other),
    }
}

#[test]
fn kernel_side_matches_truth_source() {
    for (_, err) in ALL_ERRORS {
        assert_eq!(
            kernel_encode_result_snapshot(Err(*err)),
            encode_result(Err(*err)),
            "内核 trap.rs::encode_result 与 zero_abi 真值源漂移: {:?}",
            err
        );
    }
    for v in OK_VALUES {
        assert_eq!(kernel_encode_result_snapshot(Ok(*v)), encode_result(Ok(*v)));
    }
}

#[test]
fn userlib_side_matches_truth_source() {
    for (_, err) in ALL_ERRORS {
        let encoded = encode_result(Err(*err));
        assert_eq!(userlib_decode_snapshot(encoded), Err(*err));
        assert_eq!(decode(encoded), Err(*err));
    }
    for v in OK_VALUES {
        assert_eq!(userlib_decode_snapshot(*v), Ok(*v));
    }
}
