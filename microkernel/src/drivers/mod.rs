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
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use zero_abi::driver::{DriverDescriptor, DriverKind, DriverTable};

use crate::{debug, warn};

pub mod console_input;
pub mod irq;
pub mod nvme;
pub mod pl011;
pub mod virtio;
pub mod xhci;

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

// 0=unreported, 1=VirtIO RNG, 2=AArch64 RNDR. This is diagnostic only; the
// backend is selected afresh per request so hot-added devices remain usable.
static RNG_BACKEND_LOGGED: AtomicU8 = AtomicU8::new(0);

/// Cryptographic random bytes from a real platform source. Never mixes clocks,
/// addresses or other predictable state. VirtIO RNG remains preferred when
/// present; FEAT_RNG/RNDR is the architecture-native fallback.
pub fn fill_random(out: &mut [u8]) -> bool {
    if virtio::rng::fill_random(out) {
        if RNG_BACKEND_LOGGED.swap(1, Ordering::Relaxed) != 1 {
            crate::info!("entropy: backend=virtio-rng");
        }
        return true;
    }
    if crate::arch::fill_hardware_random(out) {
        if RNG_BACKEND_LOGGED.swap(2, Ordering::Relaxed) != 2 {
            crate::info!("entropy: backend=arm64-rndr");
        }
        return true;
    }
    false
}

/// 驱动注册入口：遍历引导器描述符，按类型分派到各驱动。
pub fn init(table_ptr: *const DriverTable) {
    debug!("drivers::init: table_ptr=0x{:016x}", table_ptr as usize);
    DRIVER_TABLE_PTR.store(table_ptr as *mut DriverTable, Ordering::SeqCst);

    // The compiled boot descriptor table is a QEMU-virt legacy board table, not
    // an ARM64 universal device list. Touch it only when the UEFI loader has
    // positively identified that platform; other firmware proceeds through
    // ACPI/PCI discovery without speculative MMIO.
    if crate::bootinfo::qemu_virt_static_mmio() {
        if let Some(descriptors) = descriptors() {
            debug!(
                "drivers::init: {} QEMU-virt static descriptor(s)",
                descriptors.len()
            );
            for descriptor in descriptors {
                let name = unsafe { descriptor.name() };
                debug!(
                    "drivers::init: 探测 {} (kind={} mmio=0x{:016x} irq={})",
                    name, descriptor.kind as u32, descriptor.mmio_base, descriptor.irq
                );

                match descriptor.kind {
                    DriverKind::Pl011 => pl011::init(descriptor),
                    DriverKind::VirtIOBlk => virtio::blk::init(descriptor),
                    DriverKind::VirtIONet => virtio::net::init(descriptor),
                    DriverKind::VirtIOGpu => virtio::gpu::init(descriptor),
                    DriverKind::VirtIORng => virtio::rng::init(descriptor),
                    DriverKind::VirtIOInput => virtio::input::init(descriptor),
                    DriverKind::VirtIOSound => virtio::sound::init(descriptor),
                    DriverKind::VirtIOConsole => {
                        warn!("driver: 暂不支持 virtio kind {}", descriptor.kind as u32)
                    }
                    DriverKind::Nvme => {
                        debug!(
                            "driver: boot descriptor NVMe '{}' deferred to PCI discovery",
                            name
                        )
                    }
                    DriverKind::UsbXhci | DriverKind::PciGeneric | DriverKind::PciTest => {
                        debug!(
                            "driver: dynamic PCI resource '{}' is not a boot transport",
                            name
                        )
                    }
                }
            }
        }
    } else {
        crate::info!(
            "drivers: skipping QEMU-virt static MMIO table on platform kind={}",
            crate::bootinfo::platform_kind()
        );
    }
    // Knife37: modern VirtIO PCI devices discovered from the Knife35 PCI registry.
    virtio::pci_transport::discover_and_init();
    nvme::init();
    xhci::init();
}

/// Active kernel-owned block backend. VirtIO keeps priority when both are
/// present so an auxiliary NVMe device cannot silently replace the boot disk.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockBackendKind {
    Virtio,
    Nvme,
}

pub fn block_backend_kind() -> Option<BlockBackendKind> {
    if virtio::blk::is_ready() {
        Some(BlockBackendKind::Virtio)
    } else if nvme::is_ready() {
        Some(BlockBackendKind::Nvme)
    } else {
        None
    }
}

pub fn block_capacity_sectors() -> Option<u64> {
    match block_backend_kind()? {
        BlockBackendKind::Virtio => virtio::blk::capacity_sectors(),
        BlockBackendKind::Nvme => nvme::capacity_sectors(),
    }
}

pub fn block_read(lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
    match block_backend_kind().ok_or(BlockError::NotReady)? {
        BlockBackendKind::Virtio => virtio::blk::read_blocks(lba, buffer),
        BlockBackendKind::Nvme => nvme::read_blocks(lba, buffer),
    }
}

pub fn block_write(lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
    match block_backend_kind().ok_or(BlockError::NotReady)? {
        BlockBackendKind::Virtio => virtio::blk::write_blocks(lba, buffer),
        BlockBackendKind::Nvme => nvme::write_blocks(lba, buffer),
    }
}

pub fn block_flush() -> Result<(), BlockError> {
    match block_backend_kind().ok_or(BlockError::NotReady)? {
        // VirtIO blk currently has no explicit FLUSH feature; synchronous used-ring
        // completion is the strongest contract exposed by that legacy backend.
        BlockBackendKind::Virtio => Ok(()),
        BlockBackendKind::Nvme => nvme::flush(),
    }
}

/// 读取引导器提供的驱动描述符列表。
pub fn descriptors() -> Option<&'static [DriverDescriptor]> {
    // The compiled descriptor table describes the QEMU `virt` board only.
    // Never expose those synthetic MMIO devices to EL0 on another ARM64
    // platform: DriverCount/DriverInfo are part of the capability boundary, so
    // a descriptor that was intentionally skipped by drivers::init must not
    // remain visible as an apparently mappable device resource.
    if !crate::bootinfo::qemu_virt_static_mmio() {
        return None;
    }
    let ptr = DRIVER_TABLE_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).as_slice() })
    }
}
