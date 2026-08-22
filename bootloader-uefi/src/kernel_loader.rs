use uefi::prelude::*;
use uefi::table::boot::BootServices;

use crate::boot_config::BootConfig;
use crate::boot_config::BootPaths;
use crate::boot_info::KernelBootContext;
use crate::elf::{self, ElfImage};
use crate::fs::FileSystem;

pub struct KernelImage {
    pub entry_point: u64,
    pub segments: ElfImage,
}

impl KernelImage {
    pub fn load(
        fs: &mut FileSystem<'_>,
        paths: &BootPaths,
        config: &BootConfig,
        bs: &BootServices,
    ) -> Result<KernelImage, Status> {
        let kernel_bytes = fs.read_to_vec(&paths.kernel_path)?;
        let elf = ElfImage::parse(&kernel_bytes)?;

        elf::load_segments(bs, &elf, &kernel_bytes)?;

        // 内核故障符号化：把符号表灌进内核自留的汇槽（对标 Linux
        // kallsyms 的引导期注入）。必须在 load_segments 之后、
        // jump_to_kernel 之前完成。
        fill_symbol_sink(bs, &elf);

        let entry = config.kernel_address.unwrap_or(elf.entry);

        log_info!("kernel loaded at entry=0x{:016x}", entry);
        Ok(KernelImage {
            entry_point: entry,
            segments: elf,
        })
    }
}

// ---------------------------------------------------------------------------
// 符号汇槽填充（协议见 microkernel/src/debug/mod.rs 的模块文档）
//
// 布局常量与内核侧严格对齐；两侧各自内联，避免为几个数字引入跨 crate
// 构建依赖。改动任一侧时必须同步另一侧。
// ---------------------------------------------------------------------------
mod symbol_sink {
    /// 汇槽有效标志，ASCII "ZSYMT101"。
    pub const MAGIC: u64 = 0x5A53_594D_5431_3031;
    /// 汇槽总容量（字节）＝ microkernel debug::SINK_SIZE。
    pub const CAPACITY: usize = 192 * 1024;
    /// 头部：magic/count/names_bytes 三个 u64。
    pub const HEADER_LEN: usize = 0x18;
    /// 单条目：{ u64 addr; u32 name_off; }。
    pub const ENTRY_LEN: usize = 12;
}

/// 把过滤后的内核符号表灌入内核镜像里的 `__zero_symbol_sink` 汇槽。
///
/// - 只收 STT_FUNC / STT_OBJECT 且地址非零的符号，按地址升序写入；
/// - 名字区紧随条目数组之后，name_off 相对名字区起始；
/// - 超出容量时截断到能完整放下的条目数（保留低地址段）；
/// - magic 最后落笔：半途失败也不会留下看似有效的半张表。
///
/// 时序关键：槽位于内核 `.data` 段（不能是 .bss —— boot/boot.S 的
/// zero_bss 会在本函数灌表之后于内核入口处再次清零整个 .bss）。
/// 恒等映射下 VA 即物理地址，直接按 ELF 符号值裸写即可，与
/// boot_info.rs 的 patch_kernel_memory 同法。
fn fill_symbol_sink(_bs: &BootServices, elf: &ElfImage) {
    const SINK_SYMBOL: &str = "__zero_symbol_sink";
    const STT_OBJECT: u8 = 1;
    const STT_FUNC: u8 = 2;

    let Some(sink_va) = elf.symbol_address(SINK_SYMBOL) else {
        log_info!("symbol sink `{SINK_SYMBOL}` absent; kernel faults stay un-symbolized");
        return;
    };
    // 防呆：汇槽必须落在某个已加载段内，否则视为镜像/协议不符。
    if !elf.segments.iter().any(|seg| {
        sink_va >= seg.physical_addr && sink_va < seg.physical_addr + seg.mem_size
    }) {
        log_warn!(
            "symbol sink address 0x{sink_va:016x} outside loaded segments; skipped"
        );
        return;
    }

    // 过滤 FUNC/OBJECT 且地址非零，按地址升序，同址同名去重。
    let mut syms: alloc::vec::Vec<(u64, &str)> = elf
        .symbols()
        .iter()
        .filter(|s| s.value != 0 && matches!(s.sym_type(), STT_OBJECT | STT_FUNC))
        .map(|s| (s.value, s.name.as_str()))
        .collect();
    syms.sort_unstable_by_key(|(addr, _)| *addr);
    syms.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

    // 第一遍：定出装得下的条目数（名字区紧随条目数组之后）。
    let mut used = symbol_sink::HEADER_LEN;
    let mut fit = 0usize;
    let mut names_len = 0usize;
    for (_, name) in &syms {
        let need = symbol_sink::ENTRY_LEN + name.len() + 1;
        if used + need > symbol_sink::CAPACITY {
            log_warn!(
                "symbol sink full: {} of {} symbols fit (capacity {} bytes)",
                fit,
                syms.len(),
                symbol_sink::CAPACITY
            );
            break;
        }
        used += need;
        names_len += name.len() + 1;
        fit += 1;
    }
    if fit == 0 {
        log_warn!("symbol sink too small for any symbol; skipped");
        return; // 不写 magic：内核侧保持优雅退化
    }

    let names_base = symbol_sink::HEADER_LEN + fit * symbol_sink::ENTRY_LEN;
    let sink = sink_va as *mut u8;

    unsafe {
        let mut entry_off = symbol_sink::HEADER_LEN;
        let mut name_off = 0usize;
        for (addr, name) in &syms[..fit] {
            store(sink, entry_off, &addr.to_le_bytes());
            store(sink, entry_off + 8, &(name_off as u32).to_le_bytes());
            entry_off += symbol_sink::ENTRY_LEN;
            store(sink, names_base + name_off, name.as_bytes());
            store(sink, names_base + name_off + name.len(), &[0]);
            name_off += name.len() + 1;
        }
        // 头部最后落笔：count/names_bytes 就绪后才写有效标志。
        store_u64(sink, 0x08, fit as u64);
        store_u64(sink, 0x10, names_len as u64);
        store_u64(sink, 0x00, symbol_sink::MAGIC);
    }

    log_info!(
        "symbol sink filled @0x{sink_va:016x}: {fit} symbols, {names_len} name bytes"
    );
}

/// 字节级写入（条目 12 字节跨步，u64 字段天然非对齐，逐字节拷贝免疫）。
///
/// # Safety
/// `buf..buf+off+bytes.len()` 必须是可写的已加载内存。
unsafe fn store(buf: *mut u8, off: usize, bytes: &[u8]) {
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.add(off), bytes.len());
}

/// 小端写入 u64。
///
/// # Safety
/// 同 [`store`]。
unsafe fn store_u64(buf: *mut u8, off: usize, value: u64) {
    store(buf, off, &value.to_le_bytes());
}

pub unsafe fn jump_to_kernel(kernel: &KernelImage, ctx: &KernelBootContext) -> ! {
    let entry: extern "C" fn(&KernelBootContext) -> ! =
        core::mem::transmute(kernel.entry_point as usize);
    entry(ctx)
}
