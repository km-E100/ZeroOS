//! 设备驱动与中断服务子系统。
//!
//! 由原单文件 drivers.rs（1107 行）拆分为模块目录：
//! - `irq`：IRQ 分发表（256 槽）、注册/注销、未处理中断计数（防假中断风暴）
//! - `pl011`：PL011 串口驱动（RX 环形缓冲 + 有界 TX 等待）
//! - `virtio`：virtio-mmio 共享核心与 blk/net 两个设备驱动
//!
//! 对外 API 与拆分前完全一致，调用方无感知：
//! `init` / `descriptors` / `handle_irq` / `register_irq_handler` /
//! `unregister_irq_handler` / `pl011::*` / `virtio::blk::*` / `virtio::net::*`，
//! 以及 `BlockError` / `NetError`。
//!
//! 日志分级：使用全局 `debug!` / `info!` / `warn!` 宏。
//! 正常路径 0 噪音——探测细节、队列状态等均走 `debug!`（默认阈值 Info，被过滤），
//! 仅探测失败、超时、越界等异常事件走 `warn!`，初始化完成各保留一行 `info!`。

use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use zero_abi::driver::{DriverDescriptor, DriverKind, DriverTable};

use crate::{debug, info, warn};

pub mod irq;
pub mod pl011;
pub mod virtio;

pub use irq::{handle_irq, register_irq_handler, unregister_irq_handler};

/// 块设备错误。语义与拆分前一致。
#[derive(Debug)]
pub enum BlockError {
    NotReady,
    Busy,
    DeviceError,
    InvalidArgument,
}

/// 网络设备错误。语义与拆分前一致。
#[derive(Debug)]
pub enum NetError {
    NotReady,
    Busy,
    BufferTooSmall,
    DeviceError,
}

/// 引导器提供的驱动描述符表（boot_info.drivers）。
static DRIVER_TABLE_PTR: AtomicPtr<DriverTable> = AtomicPtr::new(ptr::null_mut());

/// 驱动注册入口：遍历引导器描述符，按类型分派到各驱动。
pub fn init(table_ptr: *const DriverTable) {
    debug!("drivers::init: table_ptr=0x{:016x}", table_ptr as usize);
    DRIVER_TABLE_PTR.store(table_ptr as *mut DriverTable, Ordering::SeqCst);

    let Some(descriptors) = descriptors() else {
        debug!("drivers::init: bootloader 未提供描述符");
        return;
    };

    debug!("drivers::init: {} 个描述符", descriptors.len());
    for descriptor in descriptors {
        let name = unsafe { descriptor.name() };
        debug!(
            "drivers::init: 探测 {} (kind={} mmio=0x{:016x} irq={})",
            name,
            descriptor.kind as u32,
            descriptor.mmio_base,
            descriptor.irq
        );

        match descriptor.kind {
            DriverKind::Pl011 => pl011::init(descriptor),
            DriverKind::VirtIOBlk => virtio::blk::init(descriptor),
            DriverKind::VirtIONet => virtio::net::init(descriptor),
            DriverKind::VirtIOConsole | DriverKind::VirtIORng => {
                warn!("driver: 暂不支持 virtio kind {}", descriptor.kind as u32)
            }
            DriverKind::Nvme => {
                info!("driver: NVMe 设备 '{}' 交由用户态处理", name)
            }
        }
    }
}

/// 读取引导器提供的驱动描述符列表。
pub fn descriptors() -> Option<&'static [DriverDescriptor]> {
    let ptr = DRIVER_TABLE_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).as_slice() })
    }
}
