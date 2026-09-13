use super::paging::PageTable;

// 内核 L2 页表实例：每个表覆盖 1 GiB（512 * 2MiB）。
// PageTable 已保证 4KiB 对齐。
#[no_mangle]
pub static mut __zero_kernel_l2_0: PageTable = PageTable([0; 512]);

#[no_mangle]
pub static mut __zero_kernel_l2_1: PageTable = PageTable([0; 512]);

/// Shared kernel ioremap L2: L1[510] => [510GiB,511GiB).
/// User address spaces copy the table descriptor but EL0 cannot access its AP=00 leaves.
#[no_mangle]
pub static mut __zero_kernel_l2_ioremap: PageTable = PageTable([0; 512]);
