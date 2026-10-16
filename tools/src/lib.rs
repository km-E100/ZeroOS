use anyhow::{anyhow, Context, Result};
use spin::Mutex;
use std::fs;
use std::path::Path;
use zero_zfs_core::{
    device::MemoryBlockDevice, BlockDevice, MountOptions, SnapshotInfo, Volume, ZfsError,
};

pub struct ZfsImageBuilder {
    memory: &'static Mutex<Vec<u8>>,
}

impl ZfsImageBuilder {
    pub fn new(size: usize) -> Result<Self> {
        if size < MemoryBlockDevice::BLOCK_SIZE {
            return Err(anyhow!(
                "image size must be at least {} bytes",
                MemoryBlockDevice::BLOCK_SIZE
            ));
        }
        let data = vec![0u8; size];
        Ok(Self::from_vec(data))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path).context("reading image")?;
        Ok(Self::from_vec(data))
    }

    fn from_vec(data: Vec<u8>) -> Self {
        let leaked = Box::leak(Box::new(Mutex::new(data)));
        Self { memory: leaked }
    }

    fn device(&self) -> MemoryBlockDevice {
        MemoryBlockDevice::new(self.memory)
    }

    fn with_volume<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Volume<MemoryBlockDevice>) -> Result<R, ZfsError>,
    {
        let mut volume = Volume::mount(self.device(), MountOptions::default())
            .map_err(|e| anyhow!("volume mount failed: {e}"))?;
        let result = f(&mut volume).map_err(|e| anyhow!("volume operation failed: {e}"))?;
        Ok(result)
    }

    pub fn format(&self) -> Result<()> {
        {
            let mut data = self.memory.lock();
            for byte in data.iter_mut() {
                *byte = 0;
            }
        }
        self.ensure_system_dirs()?;
        self.write_file("/README.txt", b"ZeroFS volume\n")
    }

    pub fn import_bundle(&self, bundle: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        if bundle.len() < 8 {
            return Err(anyhow!("bundle too small"));
        }
        if &bundle[..8] != b"ZEROFSB\0" {
            return Err(anyhow!("invalid rootfs bundle signature"));
        }
        offset += 8;
        let count = u32::from_le_bytes(bundle[offset..offset + 4].try_into().unwrap());
        offset += 4;
        self.with_volume(|volume| {
            for _ in 0..count {
                if offset + 4 > bundle.len() {
                    return Err(ZfsError::InvalidArgument);
                }
                let path_len =
                    u32::from_le_bytes(bundle[offset..offset + 4].try_into().unwrap()) as usize;
                offset += 4;
                if offset + path_len > bundle.len() {
                    return Err(ZfsError::InvalidArgument);
                }
                let path = core::str::from_utf8(&bundle[offset..offset + path_len])
                    .map_err(|_| ZfsError::InvalidArgument)?;
                offset += path_len;
                if offset + 4 > bundle.len() {
                    return Err(ZfsError::InvalidArgument);
                }
                let data_len =
                    u32::from_le_bytes(bundle[offset..offset + 4].try_into().unwrap()) as usize;
                offset += 4;
                if offset + data_len > bundle.len() {
                    return Err(ZfsError::InvalidArgument);
                }
                let data = &bundle[offset..offset + data_len];
                offset += data_len;
                volume.import_file(path, data)?;
            }
            Ok(())
        })
    }

    pub fn ensure_system_dirs(&self) -> Result<()> {
        self.write_file("/etc/.keep", b"")?;
        self.write_file("/System/.keep", b"")?;
        self.write_file("/Users/.keep", b"")
    }

    pub fn write_passwd(&self, user: &str, hash: &str) -> Result<()> {
        let entry = format!("{}:{}\n", user, hash);
        self.with_volume(|volume| {
            let mut existing = Vec::new();
            if volume.read_file("/etc/passwd", &mut existing).is_err() {
                existing.extend_from_slice(b"root:x:0:0:root:/root:/bin/sh\n");
            }
            existing.extend_from_slice(entry.as_bytes());
            volume.write_file("/etc/passwd", &existing, None)?;
            Ok(())
        })
    }

    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<()> {
        self.with_volume(|volume| {
            volume.write_file(path, data, None)?;
            Ok(())
        })
    }

    pub fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        self.with_volume(|volume| {
            let mut list = Vec::new();
            volume.list_snapshots(&mut list);
            Ok(list)
        })
    }

    pub fn restore_snapshot(&self, id: u64) -> Result<()> {
        self.with_volume(|volume| {
            volume.restore_snapshot(id)?;
            Ok(())
        })
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.with_volume(|volume| {
            let mut data = Vec::new();
            volume.read_file(path, &mut data)?;
            Ok(data)
        })
    }

    pub fn flush_to<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = self.memory.lock();
        fs::write(path, data.as_slice()).context("writing image")
    }
}
