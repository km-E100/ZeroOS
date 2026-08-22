use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::table::Runtime;

/// 内核镜像 `.rodata.boot` 中的内存占位符号名（见 boot/boot.S）。
/// bootloader 在退出 Boot Services 前把真实内存量写回该位置，
/// 使内核拿到的 `BootInfo.memory_bytes` 反映实际硬件配置。
const KERNEL_MEMORY_SYMBOL: &str = "__zero_memory_bytes";

/// 内核引导上下文：UEFI bootloader 与内核之间的协议载体。
///
/// 当前内核入口 (boot.S `_start`) 固定读取静态 `boot_info_struct`，
/// 因此这里除了保存计算结果外，还会在 prepare() 阶段把 `memory_bytes`
/// 直接补丁进已加载的内核镜像（通过 ELF 符号定位）。
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