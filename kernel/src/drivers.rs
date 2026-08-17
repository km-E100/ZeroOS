use zero_abi::driver::{DriverDescriptor, DriverKind, DriverTable};

const DRIVER_DESCRIPTORS: [DriverDescriptor; 3] = [
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

//#[no_mangle]
//pub static __zero_driver_entries: [DriverDescriptor; DRIVER_DESCRIPTORS.len()] = DRIVER_DESCRIPTORS;

//#[no_mangle]
//pub static __zero_driver_table: DriverTable =
//    DriverTable::new(__zero_driver_entries.as_ptr(), __zero_driver_entries.len());
