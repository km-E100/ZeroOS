use zero_abi::driver::{DriverDescriptor, DriverKind, DriverTable};

// QEMU virt 平台的驱动描述符，通过强符号覆盖 boot.S 弱符号占位，
// 内核 drivers::init 才能拿到真实的设备表。
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
        32,
    ),
    DriverDescriptor::new(
        "virtio-net0",
        DriverKind::VirtIONet,
        0x0a00_0200,
        0x2000,
        34,
    ),
];

#[no_mangle]
#[used]
#[link_section = ".rodata.boot"]
pub static __zero_driver_table: DriverTable = DriverTable::new(
    &__zero_driver_entries as *const DriverDescriptor,
    __zero_driver_entries.len(),
);
