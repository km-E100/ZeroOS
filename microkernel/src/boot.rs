use zero_abi::BootInfo;

use crate::arch;
use crate::mm;

// 内核镜像（含 .bss）结束地址，由 boot/linker.ld 定义。
extern "C" {
    static __kernel_start: u8;
    static __bss_end: u8;
}

/// Whether `[addr, addr+len)` lies inside the relocated kernel image.
/// Used by crash diagnostics before dereferencing a faulting ELR.
pub fn kernel_runtime_contains(addr: usize, len: usize) -> bool {
    let start = unsafe { &__kernel_start as *const u8 as usize };
    let end = unsafe { &__bss_end as *const u8 as usize };
    addr >= start
        && addr
            .checked_add(len)
            .map(|range_end| range_end <= end)
            .unwrap_or(false)
}

/// 默认回退内存大小：bootloader 未提供真实值时使用（QEMU 惯性配置 512MiB
/// 是保守下限，即使真实机器大于此值，恒等映射 2GiB 仍是上限）。
const FALLBACK_MEMORY_BYTES: usize = 512 * 1024 * 1024;
/// 合理性下限：真实 RAM 不可能小于 16MiB（低于此值视为 bootloader 未填）。
const MIN_PLAUSIBLE_MEMORY: usize = 16 * 1024 * 1024;
/// 合理性上限：恒等映射只覆盖 2GiB，报告值超过它说明字段没填对。
const MAX_PLAUSIBLE_MEMORY: usize = 2 * 1024 * 1024 * 1024;

/// 从 BootInfo 解析物理内存大小（真实值优先，缺失/异常回退 512MiB）。
///
/// ABI 约定（见 boot/boot.S）：`BootInfo.memory_bytes` 是指向
/// `__zero_memory_bytes` slot 的地址（bootloader 把真实值写入该 slot），
/// 必须**解引用**后才是 RAM 字节数，字段本身不是值。
fn memory_bytes_of(boot_info: &BootInfo) -> usize {
    // SAFETY: slot 位于内核镜像 .rodata.boot，恒等映射内，生命期 'static。
    let reported = unsafe { *(boot_info.memory_bytes as *const u64) } as usize;
    if reported == 0 {
        crate::info!(
            "boot: bootloader did not report memory_bytes (0), falling back to {} MiB",
            FALLBACK_MEMORY_BYTES / (1024 * 1024)
        );
        return FALLBACK_MEMORY_BYTES;
    }
    if !(MIN_PLAUSIBLE_MEMORY..=MAX_PLAUSIBLE_MEMORY).contains(&reported) {
        crate::info!(
            "boot: bootloader reported implausible memory_bytes=0x{:x}, falling back to {} MiB",
            reported,
            FALLBACK_MEMORY_BYTES / (1024 * 1024)
        );
        return FALLBACK_MEMORY_BYTES;
    }
    crate::info!(
        "boot: bootloader reported memory_bytes=0x{:x} ({})",
        reported,
        reported
    );
    reported
}

/// 平台相关初始化：设置异常向量、启用计时器、配置权限域等。
pub fn init_arch(boot_info: &BootInfo) {
    // 先安装异常向量和中断控制器，这样在后续内存管理初始化阶段发生的同步异常
    // 会通过我们的 trap 处理路径打印详细信息，而不是落回固件向量表静默挂起。
    crate::info!("boot::init_arch: arch init");
    arch::init(boot_info);
    crate::info!("boot::init_arch: arch init done");

    // 真实内存模型：优先用 bootloader 报告的 RAM 总量；缺失/异常时
    // 保守回退 512MiB（见 memory_bytes_of）。
    let memory_bytes = memory_bytes_of(boot_info);

    crate::info!("boot::init_arch: mm init");
    // KASLR-aware reservation: the linker symbols resolve to the relocated
    // runtime image. Only this exact interval is pinned. The 16 MiB legacy
    // prefix is retained solely for total-bytes-only old bootloaders; modern
    // UEFI memory-map boots do not waste the gap below a high random base.
    let kernel_start = unsafe { &__kernel_start as *const u8 as usize };
    let kernel_end = unsafe { &__bss_end as *const u8 as usize };
    const LEGACY_LOW_RESERVE: usize = 16 * 1024 * 1024;
    crate::info!(
        "boot::init_arch: kernel runtime range [0x{:x},0x{:x}) span=0x{:x}",
        kernel_start,
        kernel_end,
        kernel_end.saturating_sub(kernel_start)
    );
    // Stage 1 keeps firmware page tables active: initialize phys + heap first,
    // then parse/copy ACPI while every firmware table is still reachable. Some
    // real/virtual firmware (Parallels included) places RSDP/XSDT above Zero
    // OS's deliberately small 2GiB identity window.
    mm::init_relocated_early(memory_bytes, LEGACY_LOW_RESERVE, kernel_start, kernel_end);
    crate::info!("boot::init_arch: mm early init done; taking ownership of bootfs");
    crate::rootfs::init(boot_info.rootfs);
    crate::info!("boot::init_arch: bootfs cache owned; parsing ACPI under firmware TTBR");
    crate::acpi::init();

    // Stage 2 owns the translation regime. paging::init_kernel_page_table now
    // consumes the cached ACPI MMIO bases so GIC/SMMU registers are Device memory
    // from the first instruction after TTBR takeover.
    mm::activate_relocated_paging();
    crate::info!("boot::init_arch: mm paging takeover done");

    arch::init_platform();
    // Knife35: enumerate PCIe from MCFG before user address spaces are cloned.
    crate::pci::init();
    crate::iommu::init();
    crate::display::init();
    crate::info!("boot::init_arch: ACPI + platform IRQ/display init done");
}
