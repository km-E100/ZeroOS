//! 穷人版 pstore：内核故障摘要落固定物理窗口，复位不丢，重启后由
//! bootloader 在第一屏取回打印（对标 Linux pstore/ramoops 的最小子集）。
//!
//! ## 窗口与布局
//!
//! 固定物理窗口 [0x4200_0000, 0x4201_0000)（64 KiB）：QEMU virt RAM 内、
//! **实测内核镜像之外**（debug 构建镜像末尾 ≈0x410D1000，约 17 MiB——
//! 初版选的 0x4100_0000 实测被第三加载段（BSS 零填充）覆盖，内核会把
//! 自己的 BSS 当日志区写、且引导器按段清零会抹掉上次日志，故上移到
//! 32 MiB 处，余量 ~15 MiB；几何约束由 mm/phys.rs 编译期断言 + 运行期
//! tripwire 钉死）。恒等映射下 VA 即 PA，内核直接裸写。
//! phys::init 的两条初始化路径都把整窗标忙，分配器永不发放（防挪用）。
//!
//! 全部小端编码：
//!
//!     0x00  u64 magic   = "ZPST101\0"（有效性承诺，最后落笔）
//!     0x08  u32 seq     累计写入字节数（饱和；> RING_LEN 即发生过回绕）
//!     0x0c  u32 wr      环内下一写入偏移（字节，恒 < RING_LEN）
//!     0x10  [u8; RING_LEN] 环形缓冲区（写入即持久）
//!
//! ## 崩溃一致性（复位任意时刻安全）
//!
//! 追加顺序：数据字节先落 -> dmb -> wr 落 -> dmb -> seq 最后落（seq 是
//! 读侧可见性承诺）。半途复位的残段恰好落在旧读窗口之外（未回绕时新
//! 数据从 wr 起；已回绕时新数据覆盖的是最老字节），旧 seq 读不出脏尾。
//!
//! ## 取回协议（bootloader 镜像实现，见 bootloader-uefi/src/pstore.rs）
//!
//! magic 有效 => 有效长度 n = min(seq, RING_LEN)，最老字节位于
//! (wr + RING_LEN - n) % RING_LEN，顺序重放 n 字节后清 magic。
//!
//! 布局常量与 bootloader 侧各自内联（模式照抄 debug/mod.rs 与
//! kernel_loader.rs::symbol_sink 的两侧镜像），改动任一侧必须同步另一侧。

use core::fmt::Write;

/// 窗口物理基址：QEMU virt RAM（0x4000_0000 起）内、实测内核镜像
/// （≈17 MiB）之外。⚠ 迁移记录：初版 0x4100_0000 被内核 BSS 段覆盖，
/// 详见模块文档「窗口与布局」。
pub const PSTORE_BASE: u64 = 0x4200_0000;
/// 窗口总容量（字节）。
pub const PSTORE_SIZE: usize = 64 * 1024;
/// 头部长度：magic(u64) + seq(u32) + wr(u32)。
pub const HEADER_LEN: usize = 0x10;
/// 环形缓冲区容量（字节）。
pub const RING_LEN: usize = PSTORE_SIZE - HEADER_LEN;
/// 有效标志，ASCII "ZPST101\0"（Zero PSTore v1.01）。
pub const PSTORE_MAGIC: u64 = u64::from_le_bytes(*b"ZPST101\0");

// ── 存储后端抽象 ────────────────────────────────────────────────────
//
// 布局逻辑只写一遍，泛型挂在极小的读写接口上：宿主单测在内存镜像上
// 验证的代码与裸机经 volatile 打进固定窗口的代码是**同一份**（杜绝
// 「测的是镜像、跑的是另一份」的漂移）。泛型单态化后无堆无锁，
// 满足故障路径纪律。

/// 存储后端：对窗口头/环的原始字节访问。
pub trait Store {
    /// 读 (magic, seq, wr) 三元组。
    fn read_header(&self) -> (u64, u32, u32);
    /// 向环内偏移 pos（必须 < RING_LEN 且本段不跨回绕）写入 bytes。
    fn write_ring(&mut self, pos: usize, bytes: &[u8]);
    /// 全新初始化：清 seq/wr 后 magic 最后落笔（有效性最终承诺）。
    fn init_fresh(&mut self);
    /// 数据落定后提交新头。wr 先落、seq 最后落（可见性承诺）。
    fn commit_header(&mut self, seq: u32, wr: u32);
}

/// 确保头部有效；无效（首次写入 / bootloader 已清 magic）则全新初始化。
fn ensure_valid<S: Store>(s: &mut S) -> bool {
    if s.read_header().0 == PSTORE_MAGIC {
        return true;
    }
    s.init_fresh();
    true
}

/// 环形追加一段字节（公开给宿主测试复用同一份逻辑）。
///
/// 单次超过环形容量时只保留末尾 RING_LEN 字节（最新内容优先）。
pub fn append<S: Store>(s: &mut S, bytes: &[u8]) {
    ensure_valid(s);
    let (_, _, wr0) = s.read_header();
    let payload: &[u8] = if bytes.len() > RING_LEN {
        &bytes[bytes.len() - RING_LEN..]
    } else {
        bytes
    };
    if payload.is_empty() {
        return;
    }
    let start = wr0 as usize % RING_LEN;
    let first = core::cmp::min(payload.len(), RING_LEN - start);
    s.write_ring(start, &payload[..first]);
    if first < payload.len() {
        s.write_ring(0, &payload[first..]);
    }
    let new_wr = ((wr0 as usize + payload.len()) % RING_LEN) as u32;
    let new_seq = s.read_header().1.saturating_add(payload.len() as u32);
    s.commit_header(new_seq, new_wr);
}

/// 重放计划：(环内起点, 有效字节数)。bootloader 侧按同一公式镜像实现。
pub fn read_plan(seq: u32, wr: u32) -> (usize, usize) {
    let n = core::cmp::min(seq as usize, RING_LEN);
    let start = (wr as usize + RING_LEN - n) % RING_LEN;
    (start, n)
}

// ── 裸机固定窗口后端 ────────────────────────────────────────────────

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod fixed_window {
    use super::*;
    use core::ptr::{read_volatile, write_volatile};

    #[inline]
    fn dmb() {
        // 数据 -> 头部的发布序；头部落定前数据必须全局可见。
        unsafe { core::arch::asm!("dmb ish", options(nostack)) };
    }

    /// 固定物理窗口（恒等映射：VA 即 PA）。
    pub struct FixedWindow;

    impl Store for FixedWindow {
        fn read_header(&self) -> (u64, u32, u32) {
            unsafe {
                let base = PSTORE_BASE as *const u8;
                let magic = read_volatile(base as *const u64);
                let seq = read_volatile(base.add(0x08) as *const u32);
                let wr = read_volatile(base.add(0x0c) as *const u32);
                (magic, seq, wr)
            }
        }

        fn write_ring(&mut self, pos: usize, bytes: &[u8]) {
            unsafe {
                let mut p = (PSTORE_BASE as usize + HEADER_LEN + pos) as *mut u8;
                for &byte in bytes {
                    write_volatile(p, byte);
                    p = p.add(1);
                }
            }
            dmb();
        }

        fn init_fresh(&mut self) {
            unsafe {
                write_volatile((PSTORE_BASE + 0x08) as *mut u32, 0); // seq=0
                write_volatile((PSTORE_BASE + 0x0c) as *mut u32, 0); // wr=0
            }
            dmb();
            // magic 最后落笔：半途失败不会留下看似有效的头。
            unsafe { write_volatile(PSTORE_BASE as *mut u64, PSTORE_MAGIC) };
            dmb();
        }

        fn commit_header(&mut self, seq: u32, wr: u32) {
            unsafe {
                write_volatile((PSTORE_BASE + 0x0c) as *mut u32, wr);
            }
            dmb();
            unsafe {
                // seq 最后落：它一变，读侧即认为新尾部可见。
                write_volatile((PSTORE_BASE + 0x08) as *mut u32, seq);
            }
            dmb();
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use fixed_window::FixedWindow;

/// 环形追加一段字节到固定窗口（故障路径安全：无堆、无锁、volatile 直写）。
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn write_bytes(bytes: &[u8]) {
    append(&mut FixedWindow, bytes);
}

/// 宿主构建（cargo test / 主机目标）没有恒等映射窗口，空实现防误用。
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn write_bytes(bytes: &[u8]) {
    let _ = bytes;
}

/// 环形追加一个字符串（对外主 API）。
pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

// ── 故障摘要 ────────────────────────────────────────────────────────

/// 行缓冲上限：超长截断（故障路径禁堆，行宽以串口可读为准）。
const LINE_MAX: usize = 192;

/// 栈上行缓冲 writer：凑满一行（含换行）即整行落 pstore。
struct LineBuf {
    buf: [u8; LINE_MAX],
    len: usize,
}

impl LineBuf {
    fn new() -> Self {
        Self {
            buf: [0; LINE_MAX],
            len: 0,
        }
    }

    fn push_line(mut self) {
        if self.len < LINE_MAX {
            self.buf[self.len] = b'\n';
            self.len += 1;
        }
        write_bytes(&self.buf[..self.len]);
    }
}

impl Write for LineBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len >= LINE_MAX {
                return Ok(()); // 截断：静默丢弃超出部分
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

/// 把完整故障摘要（reason/ESR/FAR/ELR/Call Trace）写入 pstore。
///
/// 由 trap.rs 的 kernel_sync_fault 在 Call Trace 串口输出之后、复位之前
/// 调用一次。逐行落盘：即使中途再炸，已落的行也在窗口里。
pub fn log_kernel_fault(reason: &str, esr: u64, far: u64, elr: u64, trace: &[super::Frame]) {
    let mut line = LineBuf::new();
    let _ = write!(line, "[pstore] KERNEL FAULT: {}", reason);
    line.push_line();

    let mut line = LineBuf::new();
    let _ = write!(
        line,
        "ESR=0x{:016x} FAR=0x{:016x} ELR=0x{:016x}",
        esr, far, elr
    );
    line.push_line();

    if trace.is_empty() {
        return;
    }
    let mut line = LineBuf::new();
    let _ = write!(line, "Call Trace:");
    line.push_line();

    for (i, fr) in trace.iter().enumerate() {
        let mut line = LineBuf::new();
        let _ = write!(line, " #{i} pc=0x{:016x}{}", fr.pc, fr.note);
        line.push_line();
    }
}

// ── 宿主单测：内存镜像后端验证与裸机完全同源的布局逻辑 ────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // no_std + 宿主测试：std 集合按需引入（模式同 debug/mod.rs::tests）。
    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;

    /// 内存镜像后端（FixedWindow 的测试替身，走同一份 append/read_plan）。
    struct Image(Box<[u8; PSTORE_SIZE]>);

    impl Image {
        fn zeroed() -> Self {
            Image(
                vec![0u8; PSTORE_SIZE]
                    .into_boxed_slice()
                    .try_into()
                    .unwrap(),
            )
        }
    }

    impl Store for Image {
        fn read_header(&self) -> (u64, u32, u32) {
            let mut m = [0u8; 8];
            m.copy_from_slice(&self.0[0x00..0x08]);
            let mut s = [0u8; 4];
            s.copy_from_slice(&self.0[0x08..0x0c]);
            let mut w = [0u8; 4];
            w.copy_from_slice(&self.0[0x0c..0x10]);
            (
                u64::from_le_bytes(m),
                u32::from_le_bytes(s),
                u32::from_le_bytes(w),
            )
        }

        fn write_ring(&mut self, pos: usize, bytes: &[u8]) {
            assert!(
                pos < RING_LEN && pos + bytes.len() <= RING_LEN,
                "segment out of ring"
            );
            self.0[HEADER_LEN + pos..HEADER_LEN + pos + bytes.len()].copy_from_slice(bytes);
        }

        fn init_fresh(&mut self) {
            self.0[0x08..0x10].fill(0);
            self.0[0x00..0x08].copy_from_slice(&PSTORE_MAGIC.to_le_bytes());
        }

        fn commit_header(&mut self, seq: u32, wr: u32) {
            self.0[0x0c..0x10].copy_from_slice(&wr.to_le_bytes());
            self.0[0x08..0x0c].copy_from_slice(&seq.to_le_bytes());
        }
    }

    /// 按 bootloader 重放协议从镜像读出有序内容（取回算法的镜像实现）。
    fn replay(img: &Image) -> Option<Vec<u8>> {
        let (magic, seq, wr) = img.read_header();
        if magic != PSTORE_MAGIC {
            return None;
        }
        let (start, n) = read_plan(seq, wr);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(img.0[HEADER_LEN + (start + i) % RING_LEN]);
        }
        Some(out)
    }

    #[test]
    fn fresh_window_appends_and_reads_back() {
        let mut img = Image::zeroed();
        append(&mut img, b"first fault\n");
        append(&mut img, b"second fault\n");
        assert_eq!(replay(&img).unwrap(), b"first fault\nsecond fault\n");
        // 12 + 13 字节（含各自换行）。
        let (_, seq, wr) = img.read_header();
        assert_eq!(seq as usize, 25);
        assert_eq!(wr as usize, 25);
    }

    #[test]
    fn wraparound_keeps_exactly_last_ring_bytes() {
        let mut img = Image::zeroed();
        // 写入 RING_LEN + 128 字节的计数序列：应只剩末尾 RING_LEN 字节。
        let total = RING_LEN + 128;
        let data: Vec<u8> = (0..total).map(|i| (i & 0xff) as u8).collect();
        append(&mut img, &data);
        let got = replay(&img).unwrap();
        assert_eq!(got.len(), RING_LEN);
        for (i, b) in got.iter().enumerate() {
            assert_eq!(*b, ((i + 128) & 0xff) as u8, "offset {i}");
        }
        // 回绕后再追加小段：仍保持有序拼接、不越容量。
        append(&mut img, b"TAIL");
        let got = replay(&img).unwrap();
        assert_eq!(&got[got.len() - 4..], b"TAIL");
        assert_eq!(got.len(), RING_LEN);
    }

    #[test]
    fn oversize_single_append_keeps_tail_only() {
        let mut img = Image::zeroed();
        append(&mut img, &vec![b'A'; RING_LEN - 2]);
        append(&mut img, &vec![b'B'; RING_LEN + 5]); // 超容量：只留末尾
        let got = replay(&img).unwrap();
        assert_eq!(got.len(), RING_LEN);
        assert!(got.iter().all(|&b| b == b'B'));
    }

    #[test]
    fn cleared_magic_reinitializes_like_bootloader_consumption() {
        let mut img = Image::zeroed();
        append(&mut img, b"old boot log\n");
        // bootloader 取回后清 magic —— 内核下一次写入应全新起账。
        img.0[0x00..0x08].fill(0);
        append(&mut img, b"new boot log\n");
        assert_eq!(replay(&img).unwrap(), b"new boot log\n");
        let (_, seq, _) = img.read_header();
        assert_eq!(seq as usize, 13);
    }

    #[test]
    fn torn_append_never_corrupts_readable_tail() {
        // 模拟「数据写了、头没提交就复位」：直接 write_ring 不 commit。
        let mut img = Image::zeroed();
        append(&mut img, b"committed\n");
        let (_, _, wr) = img.read_header();
        let torn = b"torn-bytes";
        img.write_ring(wr as usize, torn);
        // 读侧按旧头重放：看不到任何撕裂字节。
        assert_eq!(replay(&img).unwrap(), b"committed\n");
    }

    #[test]
    fn read_plan_edges() {
        // 空：起点无所谓（n=0）。
        assert_eq!(read_plan(0, 77), (77, 0));
        // 未回绕：从头开始。
        assert_eq!(read_plan(100, 100), (0, 100));
        // 恰好满一圈。
        assert_eq!(read_plan(RING_LEN as u32, 0), (0, RING_LEN));
        // 回绕：最老字节在 wr 处。
        assert_eq!(read_plan(RING_LEN as u32 + 10, 10), (10, RING_LEN));
    }

    #[test]
    fn seq_saturates_instead_of_wrapping_into_a_lie() {
        let mut img = Image::zeroed();
        // 直接摆一个接近 u32::MAX 的 seq：继续追加不得回卷成「看起来很新」。
        img.init_fresh();
        img.commit_header(u32::MAX - 3, 0);
        append(&mut img, &[b'x'; 16]);
        let (_, seq, _) = img.read_header();
        assert_eq!(seq, u32::MAX);
        // 重放长度被钳到 RING_LEN，不因回卷变小。
        assert_eq!(replay(&img).unwrap().len(), RING_LEN);
    }

    #[test]
    fn layout_constants_match_protocol_doc() {
        assert_eq!(PSTORE_BASE, 0x4200_0000);
        assert_eq!(PSTORE_SIZE, 64 * 1024);
        assert_eq!(HEADER_LEN, 0x10);
        assert_eq!(RING_LEN, PSTORE_SIZE - HEADER_LEN);
        // magic 必须正是 "ZPST101\0" 的小端编码。
        assert_eq!(PSTORE_MAGIC.to_le_bytes(), *b"ZPST101\0");
    }
}
