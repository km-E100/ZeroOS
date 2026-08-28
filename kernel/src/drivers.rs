use zero_abi::driver::{DriverDescriptor, DriverKind, DriverTable};

// QEMU virt 平台的 legacy/MMIO 驱动描述符。该表仍编进镜像以保留
// QEMU 启动兼容，但 microkernel::drivers::init 仅在 bootloader 明确标记
// PLATFORM_QEMU_VIRT 时消费；其他 ARM64 平台绝不盲探这些地址。
//
// IRQ 编号约定 = GIC INTID（SGI 0-15 / PPI 16-31 / SPI 32+）：
// - PL011        = INTID 33（QEMU virt SPI 1）
// - virtio-mmio 槽 N @ 0x0a000000 + 0x200*N = SPI 16+N → INTID 48+N：
//     槽 0（0x0a000000）= 48，槽 1（0x0a000200）= 49。
//   此前误写 32/34（INTID 32 = SPI 0 保留未用；INTID 34 = RTC），
//   设备中断永远到不了处理器——块 I/O 完成只能靠驱动内轮询兜底。
#[no_mangle]
#[used]
#[link_section = ".rodata.boot"]
pub static __zero_driver_entries: [DriverDescriptor; 8] = [
    DriverDescriptor::new("uart0-pl011", DriverKind::Pl011, 0x0900_0000, 0x1000, 33),
    DriverDescriptor::new(
        "virtio-blk0",
        DriverKind::VirtIOBlk,
        0x0a00_0000,
        0x2000,
        48,
    ),
    DriverDescriptor::new(
        "virtio-net0",
        DriverKind::VirtIONet,
        0x0a00_0200,
        0x2000,
        49,
    ),
    DriverDescriptor::new(
        "virtio-gpu0",
        DriverKind::VirtIOGpu,
        0x0a00_0400,
        0x2000,
        50,
    ),
    DriverDescriptor::new(
        "virtio-input0",
        DriverKind::VirtIOInput,
        0x0a00_0600,
        0x2000,
        51,
    ),
    DriverDescriptor::new(
        "virtio-pointer0",
        DriverKind::VirtIOInput,
        0x0a00_0800,
        0x2000,
        52,
    ),
    DriverDescriptor::new(
        "virtio-rng0",
        DriverKind::VirtIORng,
        0x0a00_0a00,
        0x2000,
        53,
    ),
    DriverDescriptor::new(
        "virtio-sound0",
        DriverKind::VirtIOSound,
        0x0a00_0c00,
        0x2000,
        54,
    ),
];

#[no_mangle]
#[used]
#[link_section = ".rodata.boot"]
pub static __zero_driver_table: DriverTable = DriverTable::new(
    &__zero_driver_entries as *const DriverDescriptor,
    __zero_driver_entries.len(),
);
