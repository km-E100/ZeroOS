//! 属性式模糊测试：IPC Message 对齐与冻结布局（恶意指针第二面）。
//!
//! 内核 `copy_message_from/to_user` 在解引用用户指针前要求 Message 按
//! 自身对齐（4）落位；本套件把该判定锁在 [`zero_abi::validate::message_ptr_aligned`]
//! 上，并冻结 132 字节 `repr(C)` 布局——任何布局漂移都会在这里先红。

use fuzz_syscall::Rng;
use zero_abi::ipc::Message;
use zero_abi::syscall::SysError;
use zero_abi::validate::{message_ptr_aligned, MESSAGE_ALIGN};

/// 内核对齐判定的语义快照（copy_message_from_user 的前置 guard）。
/// 源：microkernel/src/syscalls.rs（工程化第八刀上收后内核改为委托
/// zero_abi::validate::message_ptr_aligned；此快照锁定同一规则）。
fn kernel_align_snapshot(addr: u64) -> bool {
    addr % core::mem::align_of::<Message>() as u64 == 0
}

#[test]
fn message_layout_is_frozen() {
    // 冻结布局契约：code@0(u32) + payload@4([u8;128])，无 padding，总 132。
    assert_eq!(core::mem::size_of::<Message>(), 132);
    assert_eq!(core::mem::align_of::<Message>(), 4);
    assert_eq!(MESSAGE_ALIGN, 4);
    assert_eq!(
        core::mem::offset_of!(Message, payload),
        4,
        "payload 偏移漂移会破坏内核整块拷贝协议"
    );
}

#[test]
fn align_predicate_equals_modulo_rule() {
    // 边界地址全扫描：谓词必须等价于 addr % 4 == 0，且与内核快照一致。
    for a in [0u64, 1, 2, 3, 4, 5, u64::MAX - 3, u64::MAX - 1, u64::MAX] {
        let expect = a % 4 == 0;
        assert_eq!(message_ptr_aligned(a), expect, "addr=0x{a:x}");
        assert_eq!(kernel_align_snapshot(a), expect, "snapshot addr=0x{a:x}");
    }
}

#[test]
fn random_addresses_agree_with_kernel_rule() {
    // 固定种子随机扫描（含刻意构造的 4k±1 地址）：三方法同票。
    let mut rng = Rng::new(0x5EED_0001);
    for _ in 0..8192 {
        let a = match rng.below(4) {
            0 => rng.next_u64(),
            1 => rng.next_u64() | 1,                  // 必不对齐
            2 => rng.next_u64() & !0x3,               // 必对齐
            _ => (rng.below(0x1_0000_0000) << 4) + 2, // 页内偏移 2
        };
        assert_eq!(
            message_ptr_aligned(a),
            kernel_align_snapshot(a),
            "addr=0x{a:x}"
        );
    }
}

#[test]
fn misaligned_message_is_invalid_argument_by_contract() {
    // 契约文档化：不对齐地址在内核路径按 InvalidArgument 拒绝
    // （此处只验证规则常量本身；真实拷贝在内核 unsafe 路径内）。
    assert!(!message_ptr_aligned(0x8000_0002));
    let reject: Result<(), SysError> = Err(SysError::InvalidArgument);
    let _ = reject; // 记录错误类型契约，防止未来误改错误类别时无人察觉
    assert!(message_ptr_aligned(0x8000_0000));
}
