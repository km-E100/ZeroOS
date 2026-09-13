use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::proto::media::file::{
    Directory, File, FileAttribute, FileInfo, FileMode, FileType, RegularFile,
};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::CString16;

pub struct FileSystem<'a> {
    #[allow(dead_code)]
    fs: ScopedProtocol<'a, SimpleFileSystem>,
    root: Directory,
}

impl<'a> FileSystem<'a> {
    pub fn open(handle: Handle, st: &SystemTable<Boot>) -> Result<FileSystem<'_>, Status> {
        let params = OpenProtocolParams {
            handle,
            agent: st.boot_services().image_handle(),
            controller: None,
        };
        let mut fs = unsafe {
            st.boot_services()
                .open_protocol::<SimpleFileSystem>(params, OpenProtocolAttributes::Exclusive)
                .map_err(|e| e.status())?
        };
        let root = fs.open_volume().map_err(|e| e.status())?;
        Ok(FileSystem { fs, root })
    }

    pub fn read_to_vec(&mut self, path: &str) -> Result<Vec<u8>, Status> {
        let path = CString16::try_from(path).map_err(|_| Status::INVALID_PARAMETER)?;
        let mut file = self.open_regular(&path)?;
        let size = file_size(&mut file)?;
        // UEFI File::read is allowed to return a short read. The old loader
        // called it once, ignored the returned byte count, and then parsed the
        // uninitialised tail as ELF/rootfs data. This became deterministic once
        // the PIE/KASLR kernel grew beyond the firmware's convenient read size.
        let mut buf = alloc::vec![0u8; size];
        let mut offset = 0usize;
        while offset < size {
            let n = file
                .read(&mut buf[offset..])
                .map_err(|_| Status::DEVICE_ERROR)?;
            if n == 0 {
                log_error!(
                    "short UEFI file read: got {} of {} bytes for {}",
                    offset,
                    size,
                    path
                );
                return Err(Status::DEVICE_ERROR);
            }
            offset = offset.checked_add(n).ok_or(Status::DEVICE_ERROR)?;
        }
        Ok(buf)
    }

    pub fn open_regular(&mut self, path: &CString16) -> Result<RegularFile, Status> {
        let handle = self
            .root
            .open(path, FileMode::Read, FileAttribute::empty())
            .map_err(|e| e.status())?;
        match handle.into_type().map_err(|e| e.status())? {
            FileType::Regular(file) => Ok(file),
            _ => Err(Status::NOT_FOUND),
        }
    }

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), Status> {
        let path = CString16::try_from(path).map_err(|_| Status::INVALID_PARAMETER)?;
        let file = self
            .root
            .open(&path, FileMode::CreateReadWrite, FileAttribute::empty())
            .map_err(|e| e.status())?;
        let mut regular = match file.into_type().map_err(|e| e.status())? {
            FileType::Regular(file) => file,
            _ => return Err(Status::ACCESS_DENIED),
        };
        regular.set_position(0).map_err(|e| e.status())?;
        regular.write(data).map_err(|e| e.status())?;
        regular.flush().map_err(|e| e.status())
    }
}

pub fn load_rootfs_image(
    fs: &mut FileSystem<'_>,
    paths: &crate::boot_config::BootPaths,
    config: &crate::boot_config::BootConfig,
) -> Result<Option<Vec<u8>>, Status> {
    if !config.rootfs_as_ramdisk {
        return Ok(None);
    }

    match fs.read_to_vec(&paths.rootfs_path) {
        Ok(bytes) => {
            log_info!("loaded rootfs image ({} bytes)", bytes.len());
            Ok(Some(bytes))
        }
        Err(status) => {
            log_warn!("rootfs image not found: status={:?}", status);
            Ok(None)
        }
    }
}

fn file_size(file: &mut RegularFile) -> Result<usize, Status> {
    let mut buffer = [0u8; 512];
    let info: &FileInfo = file.get_info(&mut buffer).map_err(|e| e.status())?;
    Ok(info.file_size() as usize)
}
