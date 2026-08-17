use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use zero_abi::BootInfo;

static BOOT_INFO_PTR: AtomicPtr<BootInfo> = AtomicPtr::new(ptr::null_mut());

pub fn init(info: &'static BootInfo) {
    BOOT_INFO_PTR.store(info as *const _ as *mut BootInfo, Ordering::SeqCst);
}

pub fn get() -> Option<&'static BootInfo> {
    let ptr = BOOT_INFO_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}
