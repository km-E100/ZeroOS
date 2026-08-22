use zero_abi::driver::{DriverDescriptor, DriverKind, DriverTable};

// QEMU virt 平台的驱动描述符，通过强符号覆盖 boot.S 弱符号占位，
// 内核 drivers::init 才能拿到真实的设备表。
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
pub static __zero_driver_entries: [DriverDescriptor; 3] = [
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
];

#[no_mangle]
#[used]
#[link_section = ".rodata.boot"]
pub static __zero_driver_table: DriverTable = DriverTable::new(
    &__zero_driver_entries as *const DriverDescriptor,
    __zero_driver_entries.len(),
);
