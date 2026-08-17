use super::paging;

pub use super::paging::{MapError, USER_STACK_LEN, USER_STACK_TOP};

#[derive(Clone, Copy)]
pub struct AddressSpace {
    inner: paging::AddressSpace,
}

impl AddressSpace {
    pub unsafe fn new() -> Self {
        let space = paging::create_user_address_space();
        Self { inner: space }
    }

    pub unsafe fn activate(&self) {
        paging::activate_user_address_space(&self.inner);
    }

    pub unsafe fn deactivate() {
        paging::deactivate_user_address_space();
    }

    pub unsafe fn destroy(&self) {
        paging::destroy_user_address_space(&self.inner);
    }

    pub unsafe fn map_stack(&mut self, stack_top: usize, size: usize) -> Result<(), MapError> {
        paging::map_user_stack(&mut self.inner, stack_top, size)
    }

    pub unsafe fn map_page_phys(
        &mut self,
        virt: usize,
        phys: usize,
        writable: bool,
        executable: bool,
    ) -> Result<(), MapError> {
        paging::map_user_phys_page(&mut self.inner, virt, phys, writable, executable)
    }

    pub fn ttbr0_phys(&self) -> u64 {
        self.inner.root_phys()
    }
}

pub fn clone_space(_space: &AddressSpace) -> AddressSpace {
    unsafe {
        let cloned = paging::create_user_address_space();
        AddressSpace { inner: cloned }
    }
}
