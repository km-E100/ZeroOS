use super::paging::PageTable;

// 内核 L1 页表实例，由 PageTable 的 repr(align(4096)) 保证对齐。
#[no_mangle]
pub static mut __zero_kernel_l1: PageTable = PageTable([0; 512]);
