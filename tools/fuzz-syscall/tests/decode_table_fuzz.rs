//! 属性式模糊测试：decode_syscall 分发表完整性与寄存器提取（trap.rs 语义快照）。
//!
//! ABI 契约：号位 0..=28 与 40..=75 已冻结于 `zero_abi::syscall::Syscall`；
//! 未知号位必须解码为 None，内核按 ENOSYS 语义回 NotFound 编码
//! （`u64::MAX - 3`），绝不 HALT 整机。
//!
//! ⚠ 待合并点：`decode_syscall` 定义在 microkernel/src/trap.rs——该文件由
//! 并行 Agent 维护、本轮禁改，故这里保留**逐字快照**作为行为 tripwire。
//! 内核侧实现一旦漂移（加号位 / 改提取规则），下方测试会红，届时请把
//! 快照同步为新语义或把 decode_syscall 上收到 zero_abi 后删除快照。

use fuzz_syscall::Rng;
use zero_abi::syscall::{decode, encode_result, is_error_encoded, SysError, Syscall};

type Regs = [u64; 31];

fn regs_of(number: u64, args: [u64; 4]) -> Regs {
    let mut regs = [0u64; 31];
    regs[0] = number;
    regs[1] = args[0];
    regs[2] = args[1];
    regs[3] = args[2];
    regs[4] = args[3];
    regs
}

// ─── 逐字快照：microkernel/src/trap.rs::decode_syscall（2026-08-23 @ b4f3658）───
fn decode_syscall_snapshot(regs: &Regs) -> Option<Syscall> {
    let number = regs[0];
    match number {
        0 => Some(Syscall::SendMessage {
            channel: regs[1] as u32,
            user_message: regs[2] as usize,
        }),
        1 => Some(Syscall::ReceiveMessage {
            channel: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        2 => Some(Syscall::Fork),
        3 => {
            let entry_reg = regs[1];
            if entry_reg == 0 {
                return None;
            }
            Some(Syscall::Exec {
                entry: unsafe {
                    core::mem::transmute::<usize, zero_abi::ThreadEntry>(entry_reg as usize)
                },
                arg: regs[2],
            })
        }
        4 => Some(Syscall::Yield),
        5 => Some(Syscall::Exit {
            status: regs[1] as i32,
        }),
        6 => Some(Syscall::ConsoleRead {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        7 => Some(Syscall::BlockRead {
            lba: regs[1],
            user_buffer: regs[2] as usize,
            len: regs[3] as usize,
        }),
        8 => Some(Syscall::BlockWrite {
            lba: regs[1],
            user_buffer: regs[2] as usize,
            len: regs[3] as usize,
        }),
        9 => Some(Syscall::ConsoleWrite {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        10 => Some(Syscall::ShmCreate {
            size: regs[1] as usize,
            user_result: regs[2] as usize,
        }),
        11 => Some(Syscall::ShmMap {
            handle: regs[1] as u32,
        }),
        12 => Some(Syscall::ShmLen {
            handle: regs[1] as u32,
        }),
        13 => Some(Syscall::ShmRetain {
            handle: regs[1] as u32,
        }),
        14 => Some(Syscall::ShmRelease {
            handle: regs[1] as u32,
        }),
        15 => Some(Syscall::DriverCount),
        16 => Some(Syscall::DriverInfo {
            index: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        17 => Some(Syscall::ShmPhys {
            handle: regs[1] as u32,
        }),
        18 => Some(Syscall::MmioMap {
            index: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        19 => Some(Syscall::MmioUnmap {
            index: regs[1] as u32,
        }),
        20 => Some(Syscall::SpawnService {
            name_ptr: regs[1] as usize,
            name_len: regs[2] as usize,
        }),
        21 => Some(Syscall::GetPid),
        22 => Some(Syscall::WaitPid { pid: regs[1] }),
        23 => Some(Syscall::GetPpid),
        24 => Some(Syscall::Brk {
            new_break: regs[1] as usize,
        }),
        25 => Some(Syscall::Sleepticks { ticks: regs[1] }),
        26 => Some(Syscall::CreateThread {
            entry: regs[1] as usize,
            stack_top: regs[2] as usize,
            tls: regs[3] as usize,
            arg: regs[4] as usize,
        }),
        27 => Some(Syscall::FutexWait {
            uaddr: regs[1] as usize,
            expected: regs[2] as u32,
        }),
        28 => Some(Syscall::FutexWake {
            uaddr: regs[1] as usize,
            max: regs[2] as usize,
        }),
        40 => Some(Syscall::CapGrant {
            target_pid: regs[1],
        }),
        41 => Some(Syscall::CapRevoke { token: regs[1] }),
        42 => Some(Syscall::CreateChannel {
            user_desc: regs[1] as usize,
        }),
        43 => Some(Syscall::SessionBegin {
            login_token: regs[1],
        }),
        44 => Some(Syscall::GetSession),
        45 => Some(Syscall::SessionList {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        46 => Some(Syscall::ShmGrant {
            handle: regs[1] as u32,
            target_pid: regs[2],
        }),
        47 => Some(Syscall::InputRead {
            user_event: regs[1] as usize,
        }),
        48 => Some(Syscall::DisplayPresent {
            user_buffer: regs[1] as usize,
            width: regs[2] as usize,
            height: regs[3] as usize,
            stride: regs[4] as usize,
        }),
        49 => Some(Syscall::ClockGet {
            clock_id: regs[1] as u32,
        }),
        50 => Some(Syscall::SleepUntil {
            deadline_ns: regs[1],
        }),
        51 => Some(Syscall::NetSend {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        52 => Some(Syscall::NetRecv {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        53 => Some(Syscall::NetGetMac {
            user_buffer: regs[1] as usize,
        }),
        54 => Some(Syscall::IpcSendTo {
            channel: regs[1] as u32,
            target_pid: regs[2],
            user_message: regs[3] as usize,
        }),
        55 => Some(Syscall::TryReceiveMessage {
            channel: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        56 => Some(Syscall::GetRandom {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        57 => Some(Syscall::BlockCapacity),
        58 => Some(Syscall::SpawnImage {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        59 => Some(Syscall::AudioInfo {
            user_info: regs[1] as usize,
        }),
        60 => Some(Syscall::AudioPlay {
            user_buffer: regs[1] as usize,
            len: regs[2] as usize,
        }),
        61 => Some(Syscall::AudioStop),
        62 => Some(Syscall::Gpu3dInfo {
            user_info: regs[1] as usize,
        }),
        63 => Some(Syscall::Gpu3dContextCreate {
            capset_id: regs[1] as u32,
        }),
        64 => Some(Syscall::Gpu3dContextDestroy {
            ctx_id: regs[1] as u32,
        }),
        65 => Some(Syscall::Gpu3dResourceCreate {
            user_desc: regs[1] as usize,
        }),
        66 => Some(Syscall::Gpu3dResourceDestroy {
            resource_id: regs[1] as u32,
        }),
        67 => Some(Syscall::Gpu3dContextAttach {
            ctx_id: regs[1] as u32,
            resource_id: regs[2] as u32,
        }),
        68 => Some(Syscall::Gpu3dSubmit {
            ctx_id: regs[1] as u32,
            user_buffer: regs[2] as usize,
            len: regs[3] as usize,
        }),
        69 => Some(Syscall::Gpu3dReadback {
            resource_id: regs[1] as u32,
            user_buffer: regs[2] as usize,
            len: regs[3] as usize,
        }),
        70 => Some(Syscall::Gpu3dGetCapset {
            capset_id: regs[1] as u32,
            version: regs[2] as u32,
            user_buffer: regs[3] as usize,
            len: regs[4] as usize,
        }),
        71 => Some(Syscall::BlockBackend),
        72 => Some(Syscall::PowerControl {
            action: regs[1] as u32,
        }),
        73 => Some(Syscall::PciCount),
        74 => Some(Syscall::PciInfo {
            index: regs[1] as u32,
            user_buffer: regs[2] as usize,
        }),
        75 => Some(Syscall::NetDiag {
            user_buffer: regs[1] as usize,
        }),
        _ => None,
    }
}

/// 判别值序的完整错误表（与 zero_abi::syscall::SysError 一致；编码规则
/// 本身由 libs/abi/tests/abi_consistency.rs 表驱动锁定，此处只消费 k 序）。
const ERR_BY_K: &[SysError] = &[
    SysError::InvalidArgument,
    SysError::PermissionDenied,
    SysError::ChannelUnavailable,
    SysError::NotFound,
    SysError::NoMemory,
    SysError::WouldBlock,
    SysError::DeviceError,
    SysError::Busy,
    SysError::NotSupported,
];

/// 每个已冻结号位的「能解码」参数组（Exec 需要非零 entry，其余全零即可）。
fn canonical_args(number: u64) -> [u64; 4] {
    if number == 3 {
        [0x0800_0000, 0, 0, 0] // 合法用户态入口地址
    } else {
        [0; 4]
    }
}

#[test]
fn table_covers_all_frozen_numbers() {
    // 表完整性：ABI 冻结的每个号位都必须可解码；保留的空洞与其后的
    // 连续号位段、远端位模式必须全部 None（ENOSYS 路径）。
    for n in 0..=28u64 {
        assert!(
            decode_syscall_snapshot(&regs_of(n, canonical_args(n))).is_some(),
            "frozen number {n} must decode"
        );
    }
    for n in 40..=75u64 {
        assert!(
            decode_syscall_snapshot(&regs_of(n, canonical_args(n))).is_some(),
            "frozen number {n} must decode"
        );
    }
    for n in 29..=39u64 {
        assert!(
            decode_syscall_snapshot(&regs_of(n, canonical_args(n))).is_none(),
            "number {n} is reserved but decodes"
        );
    }
    for n in 76..=1023u64 {
        assert!(
            decode_syscall_snapshot(&regs_of(n, canonical_args(n))).is_none(),
            "number {n} is not frozen but decodes"
        );
    }
    for n in [u16::MAX as u64, u32::MAX as u64, (1 << 40) + 7, u64::MAX] {
        assert!(decode_syscall_snapshot(&regs_of(n, [0; 4])).is_none());
    }
}

#[test]
fn exec_rejects_null_entry_only() {
    // Exec 特例：entry=0 视为未提供 → None；其余值（含边界位模式）放行。
    assert!(decode_syscall_snapshot(&regs_of(3, [0, 0, 0, 0])).is_none());
    for entry in [1u64, 0x0020_0000, 0x8000_0000, u64::MAX] {
        let got = decode_syscall_snapshot(&regs_of(3, [entry, 42, 0, 0]));
        assert!(
            matches!(got, Some(Syscall::Exec { arg: 42, .. })),
            "entry=0x{entry:x}"
        );
    }
}

#[test]
fn register_extraction_matches_abi_truncation_rules() {
    // 寄存器→字段提取契约：u32 字段截断高 32 位；usize/u64 字段全宽。
    let hi = (u32::MAX as u64) + 1; // 截断后变 0 的探针
    match decode_syscall_snapshot(&regs_of(0, [hi | 3, 0x8000_0000, 0, 0])) {
        Some(Syscall::SendMessage {
            channel,
            user_message,
        }) => {
            assert_eq!(channel, 3); // 高位被截掉
            assert_eq!(user_message, 0x8000_0000);
        }
        _other => panic!("unexpected SendMessage decode"),
    }
    match decode_syscall_snapshot(&regs_of(22, [u64::MAX, 0, 0, 0])) {
        Some(Syscall::WaitPid { pid }) => assert_eq!(pid, u64::MAX), // pid 全宽
        _other => panic!("unexpected WaitPid decode"),
    }
    match decode_syscall_snapshot(&regs_of(5, [(-1i32) as u64, 0, 0, 0])) {
        Some(Syscall::Exit { status }) => assert_eq!(status, -1), // i32 补码还原
        _other => panic!("unexpected Exit decode"),
    }
    match decode_syscall_snapshot(&regs_of(7, [u64::MAX, hi | 0x8000_0000, 512, 0])) {
        Some(Syscall::BlockRead {
            lba,
            user_buffer,
            len,
        }) => {
            assert_eq!(lba, u64::MAX);
            // usize 字段全宽不截断：hi 位原样保留（截断只发生在 u32 字段）。
            assert_eq!(user_buffer, ((u32::MAX as u64 + 1) | 0x8000_0000) as usize);
            assert_eq!(len, 512);
        }
        _other => panic!("unexpected BlockRead decode"),
    }
}

#[test]
fn random_extraction_identity_for_hot_numbers() {
    // 伪随机属性：对热点号位反复注入随机寄存器，提取结果恒等于
    // 「按 ABI 手工截断」的表达式（防未来重排参数寄存器时无人察觉）。
    let mut rng = Rng::new(0xC0FF_EE00);
    for _ in 0..256 {
        let r = [
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ];
        match decode_syscall_snapshot(&regs_of(1, r)) {
            Some(Syscall::ReceiveMessage {
                channel,
                user_buffer,
            }) => {
                assert_eq!(channel, r[0] as u32);
                assert_eq!(user_buffer, r[1] as usize);
            }
            _other => panic!("unexpected ReceiveMessage decode"),
        }
        match decode_syscall_snapshot(&regs_of(20, r)) {
            Some(Syscall::SpawnService { name_ptr, name_len }) => {
                assert_eq!(name_ptr, r[0] as usize);
                assert_eq!(name_len, r[1] as usize);
            }
            _other => panic!("unexpected SpawnService decode"),
        }
    }
}

#[test]
fn unknown_number_maps_to_enosys_not_found_encoding() {
    // ENOSYS 语义：None → encode_result(Err(NotFound)) = u64::MAX-3，
    // 且该编码必须落在哨兵区间内、解码后原样还原（绝不 HALT 整机）。
    for bad in [29u64, 999, u64::MAX] {
        if decode_syscall_snapshot(&regs_of(bad, canonical_args(bad))).is_none() {
            let encoded = encode_result(Err(SysError::NotFound));
            assert_eq!(encoded, u64::MAX - 3);
            assert!(is_error_encoded(encoded));
            assert_eq!(decode(encoded), Err(SysError::NotFound));
            return;
        }
    }
    panic!("all probe numbers decoded; snapshot table drifted");
}

#[test]
fn result_encoding_transparent_for_success_values() {
    // 不变量：encode ∘ decode 对非哨兵值恒等。内核处理器若把哨兵区间内
    // 的值当成功返回就会被用户态误判——随机扫描该风险面并记录约定。
    let mut rng = Rng::new(0x5173_5173);
    for _ in 0..8192 {
        let v = rng.next_u64();
        if !is_error_encoded(v) {
            assert_eq!(encode_result(Ok(v)), v);
            assert_eq!(decode(v), Ok(v));
        } else {
            let k = u64::MAX - v;
            assert_eq!(decode(v), Err(ERR_BY_K[k as usize]));
        }
    }
}
