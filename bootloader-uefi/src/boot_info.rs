use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::table::Runtime;

/// 内核镜像 `.rodata.boot` 中的内存占位符号名（见 boot/boot.S）。
/// bootloader 在退出 Boot Services 前把真实内存量写回该位置，
/// 使内核拿到的 `BootInfo.memory_bytes` 反映实际硬件配置。
const KERNEL_MEMORY_SYMBOL: &str = "__zero_memory_bytes";

/// ACPI 静态表支持（立项 docs/acpi_static_plan.md · WS-A）：
/// 从 UEFI System Table 的 config 数组抓 ACPI 2.0+ RSDP，补丁进内核
/// 符号 `__zero_rsdp_phys`（0 = 未找到，内核回退硬编码探测路径）。
const KERNEL_RSDP_SYMBOL: &str = "__zero_rsdp_phys";
use uefi::table::cfg::ACPI2_GUID;

fn find_rsdp_phys(st: &SystemTable<Boot>) -> Option<u64> {
    for entry in st.config_table() {
        if entry.guid == ACPI2_GUID {
            return Some(entry.address as usize as u64);
        }
    }
    None
}

fn patch_kernel_rsdp(kernel: &crate::kernel_loader::KernelImage, rsdp: Option<u64>) {
    let Some(addr) = kernel.segments.symbol_address(KERNEL_RSDP_SYMBOL) else {
        log_warn!("kernel symbol `{}` not found; rsdp stays 0", KERNEL_RSDP_SYMBOL);
        return;
    };
    let value = rsdp.unwrap_or(0);
    unsafe {
        core::ptr::write_volatile(addr as *mut u64, value);
    }
    if let Some(v) = rsdp {
        log_info!(
            "patched kernel `{}` @0x{:016x} = RSDP 0x{:x}",
            KERNEL_RSDP_SYMBOL,
            addr,
            v
        );
    } else {
        log_warn!("no ACPI RSDP in config table; kernel `{}` = 0", KERNEL_RSDP_SYMBOL);
    }
}

/// 内核引导上下文：UEFI bootloader 与内核之间的协议载体。
///
/// 当前内核入口 (boot.S `_start`) 固定读取静态 `boot_info_struct`，
/// 因此这里除了保存计算结果外，还会在 prepare() 阶段把 `memory_bytes`
/// 直接补丁进已加载的内核镜像（通过 ELF 符号定位）。
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct KernelBootContext {
    /// 协商出的可用物理内存字节数（0 = 未知，内核回退 512 MiB）。
    pub memory_bytes: u64,
    /// EFI CONVENTIONAL 区间总量（仅用于诊断日志）。
    pub total_usable_bytes: u64,
    /// EFI CONVENTIONAL 最大连续块字节数（仅用于诊断日志）。
    pub max_contiguous_bytes: u64,
}

impl KernelBootContext {
    pub fn prepare(
        st: &mut SystemTable<Boot>,
        kernel: &crate::kernel_loader::KernelImage,
        _rootfs: Option<&Vec<u8>>,
        _config: &crate::boot_config::BootConfig,
    ) -> Result<Self, Status> {
        let (total, max_block) = collect_usable_memory(st)?;

        // 保守策略：取「CONVENTIONAL 区间的最大连续块」而非总量。
        // 理由：内核位图分配器（microkernel/src/mm/phys.rs）假定物理内存从
        // RAM_BASE 连续延伸 memory_bytes 字节；若传总量而 EFI 在中间留下
        // MMIO/保留空洞，分配器可能把空洞当成 RAM 分配出去。
        // QEMU virt 下 0x4000_0000 开始的整块 RAM 就是最大连续块，二者等价。
        let memory_bytes = if max_block.bytes > 0 {
            max_block.bytes
        } else {
            total
        };

        log_info!(
            "EFI usable memory: total={} bytes, max_contiguous={} bytes @0x{:016x}",
            total,
            max_block.bytes,
            max_block.start
        );
        log_info!(
            "kernel memory_bytes = {} bytes ({} MiB)",
            memory_bytes,
            memory_bytes / (1024 * 1024)
        );

        patch_kernel_memory(kernel, memory_bytes);

        // ACPI（WS-A）：ExitBootServices 前 RSDP 仍由固件持有/有效。
        patch_kernel_rsdp(kernel, find_rsdp_phys(st));

        // 精细内存图：把合并后的 CONVENTIONAL 区间表灌入内核汇槽，
        // 物理分配器据此登记空洞（失败仅告警，内核回退总量路径）。
        fill_memory_map_sink(kernel, st);

        log_info!("boot context prepared");
        Ok(Self {
            memory_bytes,
            total_usable_bytes: total,
            max_contiguous_bytes: max_block.bytes,
        })
    }

    pub fn exit_boot_services(&self, st: SystemTable<Boot>) -> SystemTable<Runtime> {
        let (runtime, memory_map) = st.exit_boot_services();
        log_info!(
            "exited boot services with {} entries",
            memory_map.entries().len()
        );
        runtime
    }
}

#[derive(Default, Copy, Clone)]
struct UsableBlock {
    start: u64,
    bytes: u64,
}

/// 遍历 EFI memory map，统计 CONVENTIONAL 可用内存：
/// 返回 (总量, 最大连续块)。相邻且地址连续的 CONVENTIONAL 描述符合并为一个块。
fn collect_usable_memory(st: &mut SystemTable<Boot>) -> Result<(u64, UsableBlock), Status> {
    // memory_map() 需要调用方提供缓冲；内核加载已完成，堆仍可用，64 KiB 足够容纳
    // 数百个 EFI 描述符（每个 48 字节）。
    let mut buffer = alloc::vec![0u8; 64 * 1024];
    let map = st
        .boot_services()
        .memory_map(&mut buffer)
        .map_err(|e| e.status())?;
    let mut total = 0u64;
    let mut best = UsableBlock::default();
    let mut run = UsableBlock::default(); // 当前合并中的连续块
    let mut in_run = false;

    for desc in map.entries() {
        if desc.ty != uefi::table::boot::MemoryType::CONVENTIONAL {
            in_run = false;
            continue;
        }
        let bytes = desc.page_count * 4096;
        total += bytes;

        let contiguous = in_run
            && desc.phys_start <= run.start + run.bytes
            && desc.phys_start + bytes >= run.start + run.bytes;
        if contiguous {
            let end = desc.phys_start + bytes;
            run.bytes = end.saturating_sub(run.start);
        } else {
            run = UsableBlock {
                start: desc.phys_start,
                bytes,
            };
            in_run = true;
        }
        if run.bytes > best.bytes {
            best = run;
        }
    }
    Ok((total, best))
}

/// 内核侧 `__zero_memory_map` 汇槽协议常量（与 mm/phys.rs 镜像一致）。
mod memory_map_sink {
    pub const MAGIC: u64 = 0x5A4D_454D_3130_3131;
    pub const HEADER: usize = 0x10;
    pub const ENTRY: usize = 16;
    pub const CAPACITY: usize = 4096;
}

/// 把合并后的 CONVENTIONAL 区间表写入内核 `__zero_memory_map` 汇槽。
/// 超容截断保低址段；magic 最后落笔；任何异常仅告警——内核侧会
/// 因 magic 不符回退总量路径。
fn fill_memory_map_sink(
    kernel: &crate::kernel_loader::KernelImage,
    st: &mut SystemTable<Boot>,
) {
    let Some(sink_va) = kernel.segments.symbol_address("__zero_memory_map") else {
        log_warn!("memory map sink `__zero_memory_map` absent; kernel uses total fallback");
        return;
    };
    if !kernel.segments.contains_addr(sink_va) {
        log_warn!("memory map sink outside loaded segments; skipped");
        return;
    }

    // 收集并合并 CONVENTIONAL 区间（升序）。
    let mut buffer = alloc::vec![0u8; 64 * 1024];
    let map = match st.boot_services().memory_map(&mut buffer) {
        Ok(m) => m,
        Err(e) => {
            log_warn!("memory map unavailable: {:?}", e.status());
            return;
        }
    };
    let mut regions: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    for desc in map.entries() {
        if desc.ty != uefi::table::boot::MemoryType::CONVENTIONAL {
            continue;
        }
        let start = desc.phys_start;
        let end = desc.phys_start.saturating_add(desc.page_count * 4096);
        if let Some(last) = regions.last_mut() {
            let last_end = last.0.saturating_add(last.1);
            if start <= last_end {
                last.1 = end.saturating_sub(last.0);
                continue;
            }
        }
        regions.push((start, end - start));
    }

    let max_entries = (memory_map_sink::CAPACITY - memory_map_sink::HEADER)
        / memory_map_sink::ENTRY;
    if regions.len() > max_entries {
        regions.truncate(max_entries);
    }

    let sink = sink_va as *mut u8;
    unsafe {
        let mut off = memory_map_sink::HEADER;
        for &(base, len) in &regions {
            core::ptr::copy_nonoverlapping(
                base.to_le_bytes().as_ptr(),
                sink.add(off),
                8,
            );
            core::ptr::copy_nonoverlapping(
                len.to_le_bytes().as_ptr(),
                sink.add(off + 8),
                8,
            );
            off += memory_map_sink::ENTRY;
        }
        // count 先于 magic 落笔，magic 是有效性最终承诺。
        core::ptr::copy_nonoverlapping(
            (regions.len() as u64).to_le_bytes().as_ptr(),
            sink.add(0x08),
            8,
        );
        core::ptr::copy_nonoverlapping(
            memory_map_sink::MAGIC.to_le_bytes().as_ptr(),
            sink,
            8,
        );
    }
    log_info!(
        "memory map sink filled @0x{sink_va:016x}: {} regions",
        regions.len()
    );
}

/// 写回内核镜像 `.rodata.boot` 的 `__zero_memory_bytes` 占位符。
/// 内核按 p_vaddr 恒等映射加载，符号 VA 即可直接作为物理地址写入。
fn patch_kernel_memory(kernel: &crate::kernel_loader::KernelImage, memory_bytes: u64) {
    let Some(addr) = kernel.segments.symbol_address(KERNEL_MEMORY_SYMBOL) else {
        log_warn!(
            "kernel symbol `{}` not found; memory_bytes stays 0 (kernel falls back to 512 MiB)",
            KERNEL_MEMORY_SYMBOL
        );
        return;
    };
    unsafe {
        core::ptr::write_volatile(addr as *mut u64, memory_bytes);
    }
    log_info!(
        "patched kernel `{}` @0x{:016x} = {}",
        KERNEL_MEMORY_SYMBOL,
        addr,
        memory_bytes
    );
}