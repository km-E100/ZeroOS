use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::table::Runtime;

pub struct KernelBootContext;

impl KernelBootContext {
    pub fn prepare(
        _st: &mut SystemTable<Boot>,
        _kernel: &crate::kernel_loader::KernelImage,
        _rootfs: Option<&Vec<u8>>,
        _config: &crate::boot_config::BootConfig,
    ) -> Result<Self, Status> {
        log_info!("boot context prepared");
        Ok(Self)
    }

    pub fn exit_boot_services(&self, st: SystemTable<Boot>) -> SystemTable<Runtime> {
        let (runtime, memory_map) = st.exit_boot_services();
        log_info!(
            "exited boot services with {} entries",
            memory_map.entries().len()
        );
        runtime
    }
}
