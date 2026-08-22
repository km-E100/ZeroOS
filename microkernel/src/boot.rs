use zero_abi::BootInfo;

use crate::arch;
use crate::mm;

// 内核镜像（含 .bss）结束地址，由 boot/linker.ld 定义。
extern "C" {
    static __bss_end: u8;
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
    // 保留 RAM 内 [0, kernel_image_bytes) 给内核自身（镜像 + 页表 + 栈），
    // 避免物理分配器把内核 .bss 页分配出去导致页表/栈被覆盖。
    // 注意：__bss_end 是 VA（内核链接在 0x4000_0000 起），分配器的保留
    // 参数是 RAM 内偏移字节数，必须减去 RAM_BASE，否则保留量会超过
    // 总内存导致全部内存被保留、alloc 必 OOM。
    let kernel_end = unsafe { &__bss_end as *const u8 as usize };
    let kernel_image_bytes = kernel_end.saturating_sub(crate::mm::phys::RAM_BASE);
    let reserved = kernel_image_bytes.max(16 * 1024 * 1024);
    crate::info!(
        "boot::init_arch: reserving 0x{:x} bytes of RAM for kernel image",
        reserved
    );
    mm::init(memory_bytes, reserved);
    crate::info!("boot::init_arch: mm init done");
}