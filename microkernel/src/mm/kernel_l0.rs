use super::paging::PageTable;

// 内核 L0 页表实例，作为翻译根表存在。
// PageTable 已保证 4KiB 对齐。
#[no_mangle]
pub static mut __zero_kernel_l0: PageTable = PageTable([0; 512]);
