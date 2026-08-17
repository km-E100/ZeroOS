use uefi::prelude::*;
use uefi::table::boot::BootServices;

use crate::boot_config::BootConfig;
use crate::boot_config::BootPaths;
use crate::boot_info::KernelBootContext;
use crate::elf::{self, ElfImage};
use crate::fs::FileSystem;

pub struct KernelImage {
    pub entry_point: u64,
    pub segments: ElfImage,
}

impl KernelImage {
    pub fn load(
        fs: &mut FileSystem<'_>,
        paths: &BootPaths,
        config: &BootConfig,
        bs: &BootServices,
    ) -> Result<KernelImage, Status> {
        let kernel_bytes = fs.read_to_vec(&paths.kernel_path)?;
        let elf = ElfImage::parse(&kernel_bytes)?;

        elf::load_segments(bs, &elf, &kernel_bytes)?;

        let entry = config.kernel_address.unwrap_or(elf.entry);

        log_info!("kernel loaded at entry=0x{:016x}", entry);
        Ok(KernelImage {
            entry_point: entry,
            segments: elf,
        })
    }
}

pub unsafe fn jump_to_kernel(kernel: &KernelImage, ctx: &KernelBootContext) -> ! {
    let entry: extern "C" fn(&KernelBootContext) -> ! =
        core::mem::transmute(kernel.entry_point as usize);
    entry(ctx)
}
