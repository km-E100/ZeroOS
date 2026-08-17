use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::allocator::{AllocatorSnapshot, BlockAllocator};
use crate::crypto;
use crate::device::{BlockDevice, DeviceError};
use crate::directory::{DirectoryEntry, DirectoryIndex};
use crate::error::ZfsError;
use crate::journal::{Journal, JournalEntry};
use crate::on_disk::{Inode, InodeId, InodeKind, SuperBlock};
use crate::snapshot::{Snapshot, SnapshotInfo, SnapshotManager};

const SUPERBLOCK_MAGIC: &[u8; 8] = b"ZFS00   ";
const SUPERBLOCK_SIZE: usize = core::mem::size_of::<SuperBlock>();

#[derive(Clone)]
pub struct MountOptions {
    pub journal_capacity: usize,
    pub reserved_blocks: Vec<u64>,
    pub verify_signatures: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            journal_capacity: 256,
            reserved_blocks: vec![0],
            verify_signatures: true,
        }
    }
}

pub struct Volume<D: BlockDevice> {
    device: D,
    superblock: SuperBlock,
    allocator: BlockAllocator,
    journal: Journal,
    directory: DirectoryIndex,
    snapshots: SnapshotManager,
    options: MountOptions,
    block_size: usize,
    next_inode: u64,
    logical_time: u64,
}

impl<D: BlockDevice> Volume<D> {
    pub fn mount(device: D, mut options: MountOptions) -> Result<Self, ZfsError> {
        if options.journal_capacity == 0 {
            options.journal_capacity = 16;
        }

        let mut raw = vec![0u8; D::BLOCK_SIZE];
        let mut superblock = match device.read_block(0, &mut raw) {
            Ok(()) => parse_superblock(&raw),
            Err(DeviceError::OutOfBounds) => None,
            Err(err) => return Err(ZfsError::from(err)),
        };

        if superblock.is_none() {
            superblock = Some(create_default_superblock(D::BLOCK_SIZE as u32));
        }
        let superblock = superblock.ok_or(ZfsError::InvalidSuperblock)?;
        let total_blocks = core::cmp::max(superblock.cluster_size as u64, 4096);
        let block_size = if superblock.block_size == 0 {
            D::BLOCK_SIZE
        } else {
            superblock.block_size as usize
        };

        let mut reserved = options.reserved_blocks.clone();
        if !reserved.contains(&0) {
            reserved.push(0);
        }
        let journal_blocks = core::cmp::max(
            1u64,
            ((options.journal_capacity as u64 * block_size as u64) + (block_size as u64 - 1))
                / block_size as u64,
        );
        for i in 0..journal_blocks {
            reserved.push(1 + i);
        }

        let mut allocator = BlockAllocator::new(1, total_blocks.saturating_sub(1));
        for &block in &reserved {
            allocator.mark_used(block);
        }

        options.reserved_blocks = reserved;

        Ok(Self {
            device,
            superblock,
            allocator,
            journal: Journal::new(options.journal_capacity),
            directory: DirectoryIndex::new(),
            snapshots: SnapshotManager::new(),
            options,
            block_size,
            next_inode: 2,
            logical_time: 1,
        })
    }

    pub fn superblock(&self) -> &SuperBlock {
        &self.superblock
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn free_blocks(&self) -> u64 {
        self.allocator.free_count()
    }

    pub fn read_file(&self, path: &str, buffer: &mut Vec<u8>) -> Result<(), ZfsError> {
        let entry = self.directory.get(path).ok_or(ZfsError::NotFound)?;
        if entry.kind() != InodeKind::File {
            return Err(ZfsError::Unsupported);
        }
        buffer.clear();
        buffer.reserve(entry.size() as usize);
        let mut offset = 0;
        for &block in &entry.blocks {
            let mut tmp = vec![0u8; self.block_size];
            self.device.read_block(block, &mut tmp)?;
            let remaining = (entry.size() as usize).saturating_sub(offset);
            let chunk = core::cmp::min(remaining, self.block_size);
            buffer.extend_from_slice(&tmp[..chunk]);
            offset += chunk;
        }
        Ok(())
    }

    pub fn write_file(
        &mut self,
        path: &str,
        data: &[u8],
        expected_signature: Option<&[u8]>,
    ) -> Result<(), ZfsError> {
        let digest = crypto::sha256(data);
        if self.options.verify_signatures {
            if let Some(signature) = expected_signature {
                if !constant_time_eq(signature, &digest) {
                    return Err(ZfsError::SignatureMismatch);
                }
            }
        }

        if let Some(existing) = self.directory.remove(path) {
            for block in existing.blocks {
                self.allocator.free(block);
                let _ = self.journal.record(JournalEntry::Free { block });
            }
        }

        let block_count = blocks_needed(data.len(), self.block_size);
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            let block = self
                .allocator
                .allocate()
                .ok_or(ZfsError::AllocationFailed)?;
            self.journal.record(JournalEntry::Allocate { block })?;
            blocks.push(block);
        }

        for (index, &block) in blocks.iter().enumerate() {
            let mut tmp = vec![0u8; self.block_size];
            let start = index * self.block_size;
            let end = core::cmp::min(start + self.block_size, data.len());
            tmp[..end - start].copy_from_slice(&data[start..end]);
            self.device.write_block(block, &tmp)?;
        }

        self.logical_time = self.logical_time.saturating_add(1);
        let inode_id = InodeId(self.next_inode);
        self.next_inode = self.next_inode.saturating_add(1);

        let mut inode = Inode {
            id: inode_id,
            kind: InodeKind::File,
            size: data.len() as u64,
            mode: 0o644,
            uid: 0,
            gid: 0,
            links: 1,
            data: [0; 12],
            extent_root: 0,
            ctime: self.logical_time,
            mtime: self.logical_time,
        };
        for (slot, block) in blocks.iter().take(12).enumerate() {
            inode.data[slot] = *block;
        }

        let entry = DirectoryEntry::new(inode, blocks.clone(), Some(digest));
        self.directory.insert(path, entry);

        self.journal.record(JournalEntry::Write {
            path: String::from(path),
            blocks,
            size: data.len() as u64,
            checksum: digest,
        })?;

        Ok(())
    }

    pub fn remove_file(&mut self, path: &str) -> Result<(), ZfsError> {
        let entry = self.directory.remove(path).ok_or(ZfsError::NotFound)?;
        for block in entry.blocks {
            self.allocator.free(block);
            let _ = self.journal.record(JournalEntry::Free { block });
        }
        Ok(())
    }

    pub fn directory_index(&self) -> &DirectoryIndex {
        &self.directory
    }

    pub fn create_snapshot(&mut self, label: &str) -> Result<Snapshot, ZfsError> {
        self.logical_time = self.logical_time.saturating_add(1);
        let snapshot = self.snapshots.create(
            label,
            self.logical_time,
            &self.allocator.snapshot(),
            &self.directory.snapshot(),
        );
        self.journal.record(JournalEntry::Snapshot {
            id: snapshot.id,
            label: snapshot.label.clone(),
        })?;
        Ok(snapshot)
    }

    pub fn list_snapshots(&self, out: &mut Vec<SnapshotInfo>) {
        self.snapshots.list(out);
    }

    pub fn restore_snapshot(&mut self, id: u64) -> Result<(), ZfsError> {
        let snapshot = self.snapshots.get(id).ok_or(ZfsError::SnapshotNotFound)?;
        self.allocator.restore(&snapshot.allocator);
        self.directory.restore(&snapshot.directory);
        Ok(())
    }

    pub fn import_file(&mut self, path: &str, data: &[u8]) -> Result<(), ZfsError> {
        self.write_file(path, data, None)
    }

    pub fn reopen(mut self, device: D) -> Self {
        self.device = device;
        self
    }

    pub fn allocator_snapshot(&self) -> AllocatorSnapshot {
        self.allocator.snapshot()
    }
}

fn parse_superblock(raw: &[u8]) -> Option<SuperBlock> {
    if raw.len() < SUPERBLOCK_SIZE {
        return None;
    }
    let mut buf = [0u8; SUPERBLOCK_SIZE];
    buf.copy_from_slice(&raw[..SUPERBLOCK_SIZE]);
    let superblock = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const SuperBlock) };
    if &superblock.magic != SUPERBLOCK_MAGIC {
        return None;
    }
    Some(superblock)
}

fn create_default_superblock(block_size: u32) -> SuperBlock {
    SuperBlock {
        magic: *SUPERBLOCK_MAGIC,
        version: 1,
        block_size,
        cluster_size: 4096,
        root_dir: InodeId(1),
        journal_head: 1,
        flags: 0,
        fs_uuid: [0u8; 16],
    }
}

fn blocks_needed(len: usize, block_size: usize) -> usize {
    if len == 0 {
        0
    } else {
        (len + block_size - 1) / block_size
    }
}

fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in lhs.iter().zip(rhs.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use spin::Mutex;

    static MEMORY: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    fn create_volume() -> Volume<crate::device::MemoryBlockDevice> {
        let device = crate::device::MemoryBlockDevice::new(&MEMORY);
        Volume::mount(device, MountOptions::default()).unwrap()
    }

    #[test]
    fn write_read_roundtrip() {
        let mut volume = create_volume();
        let data = b"hello world";
        volume.write_file("/hello.txt", data, None).unwrap();
        let mut buf = Vec::new();
        volume.read_file("/hello.txt", &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn snapshot_and_restore() {
        let mut volume = create_volume();
        volume.write_file("/hello", b"a", None).unwrap();
        let snapshot = volume.create_snapshot("first").unwrap();
        volume.write_file("/hello", b"b", None).unwrap();
        volume.restore_snapshot(snapshot.id).unwrap();
        let mut buf = Vec::new();
        volume.read_file("/hello", &mut buf).unwrap();
        assert_eq!(&buf, b"a");
    }
}
