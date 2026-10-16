use core::arch::asm;
use uefi::prelude::*;
use uefi::proto::rng::Rng;
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
        st: &SystemTable<Boot>,
    ) -> Result<KernelImage, Status> {
        let kernel_bytes = fs.read_to_vec(&paths.kernel_path).map_err(|e| {
            log_error!("kernel read failed: {:?}", e);
            e
        })?;
        let mut elf = ElfImage::parse(&kernel_bytes).map_err(|e| {
            log_error!("kernel ELF parse failed: {:?}", e);
            e
        })?;
        let bs = st.boot_services();

        if elf.is_pie() {
            load_pie_with_kaslr(st, &mut elf, &kernel_bytes).map_err(|e| {
                log_error!("kernel KASLR load failed: {:?}", e);
                e
            })?;
            elf::apply_relocations(&elf).map_err(|e| {
                log_error!("kernel relocation failed: {:?}", e);
                e
            })?;
        } else {
            elf::load_segments(bs, &elf, &kernel_bytes).map_err(|e| {
                log_error!("kernel segment load failed: {:?}", e);
                e
            })?;
        }

        // 内核故障符号化：把符号表灌进内核自留的汇槽（对标 Linux
        // kallsyms 的引导期注入）。必须在 load_segments 之后、
        // jump_to_kernel 之前完成。
        fill_symbol_sink(bs, &elf);

        let entry = config.kernel_address.unwrap_or_else(|| elf.runtime_entry());

        log_info!("kernel loaded at entry=0x{:016x}", entry);
        Ok(KernelImage {
            entry_point: entry,
            segments: elf,
        })
    }
}

const KASLR_START: u64 = 0x4800_0000;
const KASLR_END: u64 = 0x5800_0000;
const KASLR_ALIGN: u64 = 2 * 1024 * 1024;

fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn boot_entropy(st: &SystemTable<Boot>) -> (u64, bool) {
    let bs = st.boot_services();
    if let Ok(handle) = bs.get_handle_for_protocol::<Rng>() {
        if let Ok(mut rng) = bs.open_protocol_exclusive::<Rng>(handle) {
            let mut bytes = [0u8; 8];
            if rng.get_rng(None, &mut bytes).is_ok() {
                return (u64::from_le_bytes(bytes), true);
            }
        }
    }
    let mut seed =
        (st as *const _ as usize as u64) ^ (bs as *const _ as usize as u64).rotate_left(17);
    if let Ok(t) = st.runtime_services().get_time() {
        seed ^= (t.year() as u64) << 48;
        seed ^= (t.month() as u64) << 40;
        seed ^= (t.day() as u64) << 32;
        seed ^= (t.hour() as u64) << 24;
        seed ^= (t.minute() as u64) << 16;
        seed ^= (t.second() as u64) << 8;
        seed ^= t.nanosecond() as u64;
    }
    (mix64(seed), false)
}

fn load_pie_with_kaslr(
    st: &SystemTable<Boot>,
    elf: &mut ElfImage,
    bytes: &[u8],
) -> Result<(), Status> {
    let span = elf.image_span().ok_or(Status::INVALID_PARAMETER)?;
    let span = (span + KASLR_ALIGN - 1) & !(KASLR_ALIGN - 1);
    if KASLR_START
        .checked_add(span)
        .map_or(true, |v| v > KASLR_END)
    {
        log_error!("PIE kernel span 0x{:x} does not fit KASLR window", span);
        return Err(Status::OUT_OF_RESOURCES);
    }
    let slots = ((KASLR_END - KASLR_START - span) / KASLR_ALIGN + 1) as usize;
    let (entropy, strong) = boot_entropy(st);
    let first = (entropy as usize) % slots;
    if strong {
        log_info!("KASLR entropy source: UEFI RNG");
    } else {
        log_warn!("KASLR entropy source: weak UEFI time/address mixer (RNG protocol unavailable)");
    }
    for attempt in 0..slots {
        let idx = (first + attempt) % slots;
        let bias = KASLR_START + (idx as u64) * KASLR_ALIGN;
        elf.set_load_bias(bias)?;
        match elf::load_segments(st.boot_services(), elf, bytes) {
            Ok(()) => {
                log_info!(
                    "KASLR kernel base=0x{:016x} span=0x{:x} slot={}/{}",
                    bias,
                    span,
                    idx,
                    slots
                );
                return Ok(());
            }
            Err(_) => continue,
        }
    }
    log_error!("no KASLR candidate address was free");
    Err(Status::OUT_OF_RESOURCES)
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
    if !elf
        .segments
        .iter()
        .any(|seg| sink_va >= seg.physical_addr && sink_va < seg.physical_addr + seg.mem_size)
    {
        log_warn!("symbol sink address 0x{sink_va:016x} outside loaded segments; skipped");
        return;
    }

    // 过滤 FUNC/OBJECT 且地址非零，按地址升序，同址同名去重。
    let mut syms: alloc::vec::Vec<(u64, &str)> = elf
        .symbols()
        .iter()
        .filter(|s| s.value != 0 && matches!(s.sym_type(), STT_OBJECT | STT_FUNC))
        .map(|s| (elf.runtime_addr(s.value), s.name.as_str()))
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

    log_info!("symbol sink filled @0x{sink_va:016x}: {fit} symbols, {names_len} name bytes");
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

const PF_X: u32 = 1;

/// Publish bootloader-written executable PT_LOAD bytes to AArch64 instruction
/// fetch. Loading/relocating a kernel is self-modifying-code from the CPU's
/// perspective: QEMU TCG often hides the required cache maintenance, while
/// real ARM/AppleHV may otherwise fetch stale bytes from a reused physical page.
unsafe fn sync_instruction_cache_range(start: usize, len: usize) {
    if len == 0 {
        return;
    }
    let ctr: u64;
    asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nostack, preserves_flags));
    // CTR_EL0 line-size fields are log2(words-per-line), one word = 4 bytes.
    let iline = 4usize << (ctr & 0xf);
    let dline = 4usize << ((ctr >> 16) & 0xf);
    let end = start.saturating_add(len);

    let mut p = start & !(dline - 1);
    while p < end {
        asm!("dc cvau, {0}", in(reg) p, options(nostack));
        p = p.saturating_add(dline);
    }
    asm!("dsb ish", options(nostack));

    let mut p = start & !(iline - 1);
    while p < end {
        asm!("ic ivau, {0}", in(reg) p, options(nostack));
        p = p.saturating_add(iline);
    }
    asm!("dsb ish", "isb", options(nostack));
}

unsafe fn publish_kernel_instruction_cache(kernel: &KernelImage) {
    let mut ranges = 0usize;
    for seg in &kernel.segments.segments {
        if seg.flags & PF_X == 0 || seg.mem_size == 0 {
            continue;
        }
        sync_instruction_cache_range(seg.physical_addr as usize, seg.mem_size as usize);
        ranges += 1;
    }
    log_info!(
        "kernel I-cache publication complete: {} executable segment(s)",
        ranges
    );
}

pub unsafe fn jump_to_kernel(kernel: &KernelImage, ctx: &KernelBootContext) -> ! {
    publish_kernel_instruction_cache(kernel);
    let entry: extern "C" fn(&KernelBootContext) -> ! =
        core::mem::transmute(kernel.entry_point as usize);
    entry(ctx)
}
