use zero_abi::BootInfo;

use crate::arch;
use crate::mm;

/// 内核镜像（含 .bss）结束地址，由 boot/linker.ld 定义。
extern "C" {
    static __bss_end: u8;
}

/// 平台相关初始化：设置异常向量、启用计时器、配置权限域等。
pub fn init_arch(boot_info: &BootInfo) {
    // 先安装异常向量和中断控制器，这样在后续内存管理初始化阶段发生的同步异常
    // 会通过我们的 trap 处理路径打印详细信息，而不是落回固件向量表静默挂起。
    crate::info!("boot::init_arch: arch init");
    arch::init(boot_info);
    crate::info!("boot::init_arch: arch init done");
    crate::info!("boot::init_arch: mm init");
    // 保留 [0, __bss_end) 给内核自身（镜像 + 页表 + 栈），
    // 避免物理分配器把内核 .bss 页分配出去导致页表/栈被覆盖。
    let kernel_end = unsafe { &__bss_end as *const u8 as usize };
    let reserved = kernel_end.max(16 * 1024 * 1024);
    crate::info!(
        "boot::init_arch: reserving 0x{:x} bytes for kernel image",
        reserved
    );
    mm::init(512 * 1024 * 1024, reserved);
    crate::info!("boot::init_arch: mm init done");
}
