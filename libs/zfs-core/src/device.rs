use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeviceError {
    OutOfBounds,
    Io,
    Unsupported,
}

pub trait BlockDevice: Clone {
    const BLOCK_SIZE: usize;
    /// Fixed device capacity when known. `None` is permitted for streaming or
    /// legacy backends; Volume then falls back to its historical minimum.
    fn block_count(&self) -> Option<u64> {
        None
    }
    fn read_block(&self, lba: u64, buffer: &mut [u8]) -> Result<(), DeviceError>;
    fn write_block(&self, lba: u64, buffer: &[u8]) -> Result<(), DeviceError>;
}

#[derive(Clone)]
pub struct MemoryBlockDevice {
    storage: &'static Mutex<Vec<u8>>,
}

impl MemoryBlockDevice {
    pub fn new(backing: &'static Mutex<Vec<u8>>) -> Self {
        Self { storage: backing }
    }

    fn ensure_capacity(&self, lba: u64, len: usize) -> Result<(), DeviceError> {
        let mut storage = self.storage.lock();
        let required = ((lba as usize) * Self::BLOCK_SIZE) + len;
        if storage.len() < required {
            storage.resize(required, 0);
        }
        Ok(())
    }
}

impl BlockDevice for MemoryBlockDevice {
    const BLOCK_SIZE: usize = 4096;

    fn block_count(&self) -> Option<u64> {
        Some((self.storage.lock().len() / Self::BLOCK_SIZE) as u64)
    }

    fn read_block(&self, lba: u64, buffer: &mut [u8]) -> Result<(), DeviceError> {
        if buffer.len() != Self::BLOCK_SIZE {
            return Err(DeviceError::Unsupported);
        }
        let offset = (lba as usize) * Self::BLOCK_SIZE;
        let storage = self.storage.lock();
        if offset + Self::BLOCK_SIZE > storage.len() {
            return Err(DeviceError::OutOfBounds);
        }
        buffer.copy_from_slice(&storage[offset..offset + Self::BLOCK_SIZE]);
        Ok(())
    }

    fn write_block(&self, lba: u64, buffer: &[u8]) -> Result<(), DeviceError> {
        if buffer.len() != Self::BLOCK_SIZE {
            return Err(DeviceError::Unsupported);
        }
        let offset = (lba as usize) * Self::BLOCK_SIZE;
        self.ensure_capacity(lba, Self::BLOCK_SIZE)?;
        let mut storage = self.storage.lock();
        if offset + Self::BLOCK_SIZE > storage.len() {
            return Err(DeviceError::OutOfBounds);
        }
        storage[offset..offset + Self::BLOCK_SIZE].copy_from_slice(buffer);
        Ok(())
    }
}
