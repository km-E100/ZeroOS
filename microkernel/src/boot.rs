use zero_abi::BootInfo;

use crate::arch;
use crate::mm;

/// 平台相关初始化：设置异常向量、启用计时器、配置权限域等。
pub fn init_arch(boot_info: &BootInfo) {
    // 先安装异常向量和中断控制器，这样在后续内存管理初始化阶段发生的同步异常
    // 会通过我们的 trap 处理路径打印详细信息，而不是落回固件向量表静默挂起。
    crate::info!("boot::init_arch: arch init");
    arch::init(boot_info);
    crate::info!("boot::init_arch: arch init done");
    crate::info!("boot::init_arch: mm init");
    mm::init(512 * 1024 * 1024, 16 * 1024 * 1024); // placeholder: 512MiB total, 16MiB reserved for kernel
    crate::info!("boot::init_arch: mm init done");
}
