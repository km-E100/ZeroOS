//! 内核故障符号化（对标 Linux oops 的 `func+0xoff/0xsize` 输出）。
//!
//! 引导期协议（两侧布局常量必须严格一致）：
//!
//! 1. 本模块在内核镜像里预留零初始化的汇槽 [`__zero_symbol_sink`]。
//!    **槽必须落在 `.data` 而非 `.bss`**：boot/boot.S 的 `zero_bss` 会在
//!    bootloader 灌入符号表之后（内核入口处）再次清零整个 `.bss`，
//!    放 `.bss` 的表会在内核真正用上之前被抹掉。`.data` 段由
//!    boot/linker.ld 的 `*(.data*)` 通配收纳，无需改链接脚本。
//! 2. UEFI bootloader 加载内核段后，把过滤后的符号表按本文件定义的
//!    布局写入该槽（bootloader-uefi/src/kernel_loader.rs::fill_symbol_sink，
//!    常量镜像见其 `symbol_sink` 模块）。内核恒等映射，VA 即物理地址。
//! 3. 内核故障路径（trap.rs）用 [`symbolize`] 把 ELR 解析为
//!    `(符号名, 符号内偏移)`，输出形如 `elr=0x… (__symbol+0x24)`。
//!
//! 优雅退化：bootloader 未填充（旧引导器 / strip 过的 release 内核）时
//! magic 不符，[`symbolize`] 恒返回 `None`，故障行维持裸地址原样。
//!
//! 汇槽内存布局（192 KiB，全部按小端编码）：
//!
//! ```text
//! 0x00  u64  magic       = 0x5A53_594D_5431_3031（ASCII "ZSYMT101"）
//! 0x08  u64  count       条目数
//! 0x10  u64  names_bytes 名字区总字节数（含每名的 NUL）
//! 0x18  条目数组（按 addr 升序，每条 12 字节）：
//!        +0x00 u64 addr     符号地址
//!        +0x08 u32 name_off 名字在名字区内的偏移
//! 之后   名字区：NUL 结尾字符串连续存放
//! ```

use alloc::string::String;
use core::cell::UnsafeCell;

pub mod pstore;

/// 汇槽有效标志，ASCII "ZSYMT101"（Zero SYMbol Table v1.0.1）。
pub const SINK_MAGIC: u64 = 0x5A53_594D_5431_3031;
/// 汇槽总容量（字节）。bootloader 侧 `symbol_sink::CAPACITY` 与此一致。
pub const SINK_SIZE: usize = 192 * 1024;

const HEADER_LEN: usize = 0x18;
const ENTRY_LEN: usize = 12;

/// 汇槽载体：整块零初始化字节数组，布局见模块文档。
///
/// 内层用 `UnsafeCell`：bootloader 在内核启动前从外部写入该内存，
/// `UnsafeCell` 既如实表达这一点，又阻止 LLVM 把静态量按常量折叠进
/// 只读段（实测 macOS 主机上无内层可变性时会被放进 `__DATA_CONST`，
/// 测试一写即 SIGBUS）。
#[repr(C, align(16))]
pub struct SymbolSink {
    bytes: UnsafeCell<[u8; SINK_SIZE]>,
}

// Safety：内核侧只在故障路径做只读解析；唯一的写入方是引导器，
// 且协议保证灌表完成于内核第一条读取指令之前，不存在数据竞争。
unsafe impl Sync for SymbolSink {}

impl SymbolSink {
    /// 槽内容只读视图。
    fn slice(&self) -> &[u8] {
        // Safety：仅借用，不与其它读冲突；写方（引导器）先于一切读。
        unsafe { &*self.bytes.get() }
    }
}

/// 内核符号汇槽。
///
/// 裸机内核（ELF 目标）显式落 `.data`，理由见模块文档；主机目标
/// （测试/宿主构建）不做段指定。用 `target_os = "none"` 区分：
/// macOS 主机同为 aarch64，但 Mach-O 不接受 ELF 风格段名。
#[no_mangle]
#[cfg_attr(
    all(target_arch = "aarch64", target_os = "none"),
    link_section = ".data"
)]
pub static __zero_symbol_sink: SymbolSink = SymbolSink {
    bytes: UnsafeCell::new([0; SINK_SIZE]),
};

/// 把 `addr` 解析为 `(&'static str 符号名, 符号内偏移)`。
///
/// 在条目数组（按 addr 升序）里二分查找 ≤ addr 的最大条目；
/// magic 不符或表损坏（越界/溢出）一律返回 `None`。
pub fn symbolize(addr: u64) -> Option<(&'static str, u64)> {
    let buf: &'static [u8] = __zero_symbol_sink.slice();
    if read_u64(buf, 0x00)? != SINK_MAGIC {
        return None;
    }
    let count = read_u64(buf, 0x08)? as usize;
    let names_bytes = read_u64(buf, 0x10)? as usize;
    // 损坏表防御：任何越界/溢出都直接判无效，不做部分解析。
    let entries_end = HEADER_LEN.checked_add(count.checked_mul(ENTRY_LEN)?)?;
    let names_base = entries_end;
    if entries_end > SINK_SIZE || names_base.checked_add(names_bytes)? > SINK_SIZE {
        return None;
    }

    // 二分：lo 收敛到第一个 addr > 目标的条目，则 lo-1 即 ≤addr 的最大者。
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if entry_addr(buf, mid)? <= addr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None; // 低于最低符号：无符号可归
    }
    let idx = lo - 1;
    let sym_addr = entry_addr(buf, idx)?;
    let name_off = read_u32(buf, HEADER_LEN + idx * ENTRY_LEN + 8)? as usize;
    let name = read_name(
        buf,
        names_base.checked_add(name_off)?,
        names_base + names_bytes,
    )?;
    Some((name, addr - sym_addr))
}

/// 故障日志专用：`" (__symbol+0xoff)"`；无符号时返回空串（行保持原样）。
pub fn symbol_note(addr: u64) -> String {
    match symbolize(addr) {
        Some((name, off)) => alloc::format!(" ({}+0x{:x})", name, off),
        None => String::new(),
    }
}

/// 小端读取 u64；越界返回 `None`（字节读取，天然免疫对齐问题）。
fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = buf.get(off..off + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// 小端读取 u32；越界返回 `None`。
fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// 第 idx 个条目的符号地址。
fn entry_addr(buf: &[u8], idx: usize) -> Option<u64> {
    read_u64(buf, HEADER_LEN + idx * ENTRY_LEN)
}

/// 从 `[start, names_end)` 内读出 NUL 结尾的名字。
fn read_name(buf: &'static [u8], start: usize, names_end: usize) -> Option<&'static str> {
    let region = buf.get(start..names_end)?;
    let len = region.iter().position(|b| *b == 0)?;
    core::str::from_utf8(&region[..len]).ok()
}

// ---------------------------------------------------------------------------
// 主机单测：手工按布局灌槽，再验证 symbolize 的边界行为。
// 测试直接经裸指针写静态槽 —— 仅限单进程测试环境，用互斥锁串行化。
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::String;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// 串行化所有触碰全局汇槽的测试。
    static SINK_LOCK: Mutex<()> = Mutex::new(());

    /// 汇槽基址。仅测试用：静态槽本不可变，写入口经裸指针绕过
    /// （单进程测试环境，互斥锁串行化，不参与正式构建）。
    fn sink_base() -> *mut u8 {
        core::ptr::from_ref(&__zero_symbol_sink)
            .cast::<SymbolSink>()
            .cast::<u8>()
            .cast_mut()
    }

    /// 按协议布局把 entries 灌入汇槽（bootloader fill_symbol_sink 的测试镜像）。
    fn install(entries: &[(u64, &str)]) {
        let base = sink_base();
        unsafe {
            // 清零整槽：模拟“上一轮残留 + 新一轮灌表”。
            core::ptr::write_bytes(base, 0, SINK_SIZE);

            // 第一遍：定出装得下的条目数。
            let mut used = HEADER_LEN;
            let mut fit = 0usize;
            for (_, name) in entries {
                let need = ENTRY_LEN + name.len() + 1;
                if used + need > SINK_SIZE {
                    break;
                }
                used += need;
                fit += 1;
            }
            let names_base = HEADER_LEN + fit * ENTRY_LEN;

            let mut entry_off = HEADER_LEN;
            let mut name_off = 0usize;
            for (addr, name) in &entries[..fit] {
                put(base, entry_off, &addr.to_le_bytes());
                put(base, entry_off + 8, &(name_off as u32).to_le_bytes());
                entry_off += ENTRY_LEN;
                put(base, names_base + name_off, name.as_bytes());
                *base.add(names_base + name_off + name.len()) = 0;
                name_off += name.len() + 1;
            }
            put(base, 0x08, &fit.to_le_bytes());
            put(base, 0x10, &(name_off as u64).to_le_bytes());
            // magic 最后写：半途失败不会留下看似有效的表。
            put(base, 0x00, &SINK_MAGIC.to_le_bytes());
        }
    }

    /// 直接改写槽内任意偏移的 u64（构造损坏表的用例）。
    fn poke_u64(off: usize, value: u64) {
        let base = sink_base();
        unsafe { put(base, off, &value.to_le_bytes()) };
    }

    /// 清空汇槽（模拟 bootloader 未填充）。
    fn reset() {
        let base = sink_base();
        unsafe {
            core::ptr::write_bytes(base, 0, SINK_SIZE);
        }
    }

    unsafe fn put(base: *mut u8, off: usize, bytes: &[u8]) {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(off), bytes.len());
    }

    #[test]
    fn unfilled_sink_yields_none() {
        let _g = SINK_LOCK.lock().unwrap();
        reset();
        assert_eq!(symbolize(0x4008_0000), None);
        assert_eq!(symbolize(0), None);
        assert_eq!(symbolize(u64::MAX), None);
    }

    #[test]
    fn bad_magic_yields_none() {
        let _g = SINK_LOCK.lock().unwrap();
        reset();
        poke_u64(0x00, 0x1234_5678);
        assert_eq!(symbolize(0x1000), None);
    }

    #[test]
    fn exact_hit_offset_and_clamp() {
        let _g = SINK_LOCK.lock().unwrap();
        install(&[
            (0x1000, "alpha"),
            (0x2000, "beta_func"),
            (0x2040, "beta_local"),
        ]);
        // 精确命中：偏移 0
        assert_eq!(symbolize(0x2000), Some(("beta_func", 0)));
        // 符号内部：归最近的前一条
        assert_eq!(symbolize(0x2050), Some(("beta_local", 0x10)));
        assert_eq!(symbolize(0x1fff), Some(("alpha", 0xfff)));
        // 高于最高符号：钳到最后一条
        assert_eq!(symbolize(0x4000), Some(("beta_local", 0x1fc0)));
        // 低于最低符号：无符号可归
        assert_eq!(symbolize(0x0fff), None);
        assert_eq!(symbolize(0), None);
    }

    #[test]
    fn two_entry_table_and_gap() {
        let _g = SINK_LOCK.lock().unwrap();
        install(&[(0x4008_0000, "kernel_main"), (0x4008_0100, "handle_svc")]);
        assert_eq!(symbolize(0x4008_0000), Some(("kernel_main", 0)));
        assert_eq!(symbolize(0x4008_00ff), Some(("kernel_main", 0xff)));
        assert_eq!(symbolize(0x4008_0180), Some(("handle_svc", 0x80)));
    }

    #[test]
    fn corrupt_count_rejected() {
        let _g = SINK_LOCK.lock().unwrap();
        install(&[(0x1000, "alpha")]);
        poke_u64(0x08, u64::MAX); // count 爆炸 → 条目区溢出
        assert_eq!(symbolize(0x1000), None);
    }

    #[test]
    fn corrupt_names_bytes_rejected() {
        let _g = SINK_LOCK.lock().unwrap();
        install(&[(0x1000, "alpha")]);
        poke_u64(0x10, SINK_SIZE as u64); // 名字区越出槽容量
        assert_eq!(symbolize(0x1000), None);
    }

    #[test]
    fn symbol_note_formatting() {
        let _g = SINK_LOCK.lock().unwrap();
        reset();
        assert_eq!(symbol_note(0x1234), "");
        install(&[(0x1000, "alpha")]);
        assert_eq!(symbol_note(0x1010), " (alpha+0x10)");
        assert_eq!(symbol_note(0x10), "");
    }

    #[test]
    fn many_symbols_binary_search_correct() {
        let _g = SINK_LOCK.lock().unwrap();
        // 512 个等距符号，验证二分在偶数/奇数边界都不偏。
        let entries: Vec<(u64, String)> = (0..512)
            .map(|i| (0x1000 + i * 0x40, format!("sym_{i}")))
            .collect();
        let refs: Vec<(u64, &str)> = entries.iter().map(|(a, n)| (*a, n.as_str())).collect();
        install(&refs);
        for (addr, name) in &entries {
            assert_eq!(symbolize(*addr), Some((name.as_str(), 0)), "addr={addr:#x}");
            assert_eq!(
                symbolize(addr + 0x3f),
                Some((name.as_str(), 0x3f)),
                "addr={addr:#x}+0x3f"
            );
        }
    }
}

// ─── FP 链栈回溯（对照 Linux arch/arm64/kernel/stacktrace.c）────────
//
// AArch64 帧指针约定：每帧开头 `stp x29, x30, [sp]`，x29 指向该处：
// [fp] = 上一帧 FP，[fp+8] = 返回地址。内核 debug 构建保留 FP
// （实测 117 处 stp x29,x30 prologue），回溯因此可行。
//
// 终止条件（任一满足即停，绝不猜测性解引用）：
// * fp 非法（非 16 对齐 / 越出恒等映射窗口 [RAM_BASE, RAM_BASE+2GiB)）
// * 帧链不再向上（next_fp <= fp：回环或到达栈顶）
// * 收集帧数达上限

/// 单帧回溯结果。
pub struct Frame {
    /// 返回地址（调用点下一条指令）。
    pub pc: u64,
    /// symbol_note(pc) 的现成文本（形如 " (__symbol+0xoff)"）。
    pub note: String,
}

/// 从起始 FP 沿帧链向上收集至多 max_frames 帧。
/// fp0 由调用方以 `asm!("mov {}, x29")` 取得（见 [`current_fp`]）。
pub fn backtrace_from(fp0: u64, max_frames: usize) -> alloc::vec::Vec<Frame> {
    const RAM_LO: u64 = 0x4000_0000;
    const RAM_HI: u64 = 0xC000_0000; // 恒等映射上界（2GiB）+ 余量
    let mut frames = alloc::vec::Vec::new();
    let mut fp = fp0;
    for _ in 0..max_frames {
        if fp < RAM_LO || fp >= RAM_HI || fp & 0xf != 0 {
            break; // 链断：野 FP 或已离开内核栈区
        }
        // Safety：FP 经边界校验后按 AArch64 帧布局读取两字；
        // 链位于恒等映射内的合法可读内存。
        let pair = unsafe { *(fp as *const [u64; 2]) };
        let (next_fp, lr) = (pair[0], pair[1]);
        let note = symbol_note(lr);
        frames.push(Frame { pc: lr, note });
        if next_fp <= fp {
            break;
        }
        fp = next_fp;
    }
    frames
}

/// 当前帧指针（故障路径回溯起点）。
#[inline(never)]
pub fn current_fp() -> u64 {
    let fp: u64;
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp);
    }
    fp
}
