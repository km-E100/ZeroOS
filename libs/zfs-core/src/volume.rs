use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::allocator::{AllocatorSnapshot, BlockAllocator};
use crate::crypto;
use crate::device::{BlockDevice, DeviceError};
use crate::directory::{DirectoryEntry, DirectoryIndex};
use crate::error::ZfsError;
use crate::journal::{Journal, JournalEntry};
use crate::metadata;
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
    metadata_generation: u64,
}

impl<D: BlockDevice> Volume<D> {
    pub fn mount(device: D, mut options: MountOptions) -> Result<Self, ZfsError> {
        if options.journal_capacity == 0 {
            options.journal_capacity = 16;
        }

        let mut raw = vec![0u8; D::BLOCK_SIZE];
        let superblock = match device.read_block(0, &mut raw) {
            Ok(()) => parse_superblock(&raw),
            Err(DeviceError::OutOfBounds) => None,
            Err(err) => return Err(ZfsError::from(err)),
        };
        let fresh = superblock.is_none();
        let superblock =
            superblock.unwrap_or_else(|| create_default_superblock(D::BLOCK_SIZE as u32));
        // `cluster_size` is allocation geometry, never capacity.
        let total_blocks = device
            .block_count()
            .filter(|n| *n > metadata::RESERVED_END)
            .unwrap_or_else(|| core::cmp::max(superblock.cluster_size as u64, 4096));
        let block_size = if superblock.block_size == 0 {
            D::BLOCK_SIZE
        } else {
            superblock.block_size as usize
        };

        // Block0 = superblock. Blocks 1..RESERVED_END are the crash-safe
        // metadata banks. The historical in-memory Journal no longer reserves
        // one disk block per entry; doing so wasted capacity without persistence.
        let mut reserved = options.reserved_blocks.clone();
        if !reserved.contains(&0) {
            reserved.push(0);
        }
        for block in 1..metadata::RESERVED_END {
            reserved.push(block);
        }
        reserved.sort_unstable();
        reserved.dedup();

        let mut allocator = BlockAllocator::new(1, total_blocks.saturating_sub(1));
        for &block in &reserved {
            if allocator.in_range(block) {
                allocator
                    .mark_used_idempotent(block)
                    .map_err(|_| ZfsError::CorruptEntry)?;
            }
        }
        options.reserved_blocks = reserved;

        let restored = metadata::load(&device)?;
        let (directory, next_inode, logical_time, metadata_generation) =
            if let Some(state) = restored {
                let mut directory = DirectoryIndex::new();
                for (path, entry) in &state.entries {
                    for &block in &entry.blocks {
                        if !allocator.in_range(block) || block < metadata::RESERVED_END {
                            return Err(ZfsError::CorruptEntry);
                        }
                        allocator
                            .mark_used_idempotent(block)
                            .map_err(|_| ZfsError::CorruptEntry)?;
                    }
                    directory.insert(path.clone(), entry.clone());
                }
                (
                    directory,
                    state.next_inode,
                    state.logical_time,
                    state.generation,
                )
            } else {
                (DirectoryIndex::new(), 2, 1, 0)
            };

        let mut volume = Self {
            device,
            superblock,
            allocator,
            journal: Journal::new(options.journal_capacity),
            directory,
            snapshots: SnapshotManager::new(),
            options,
            block_size,
            next_inode,
            logical_time,
            metadata_generation,
        };
        if fresh {
            volume.persist_superblock()?;
        }
        // Seed an empty valid metadata bank on first mount. This makes a
        // formatted-but-empty volume distinguishable from legacy RAM-only ZFS.
        if volume.metadata_generation == 0 {
            volume.persist_metadata()?;
        }
        Ok(volume)
    }

    fn persist_superblock(&self) -> Result<(), ZfsError> {
        let mut block = vec![0u8; D::BLOCK_SIZE];
        let n = core::cmp::min(core::mem::size_of::<SuperBlock>(), block.len());
        unsafe {
            core::ptr::copy_nonoverlapping(
                (&self.superblock as *const SuperBlock).cast::<u8>(),
                block.as_mut_ptr(),
                n,
            );
        }
        self.device.write_block(0, &block)?;
        Ok(())
    }

    fn persist_metadata(&mut self) -> Result<(), ZfsError> {
        self.metadata_generation = metadata::store(
            &self.device,
            self.metadata_generation,
            self.directory.as_map(),
            self.next_inode,
            self.logical_time,
        )?;
        Ok(())
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

    /// Read at most `out.len()` bytes starting at a file offset without first
    /// materialising the whole file. Only blocks intersecting the requested
    /// range are touched; this is the data path used by fsd file descriptors.
    pub fn read_file_at(
        &self,
        path: &str,
        offset: usize,
        out: &mut [u8],
    ) -> Result<usize, ZfsError> {
        let entry = self.directory.get(path).ok_or(ZfsError::NotFound)?;
        if entry.kind() != InodeKind::File {
            return Err(ZfsError::Unsupported);
        }
        let size = usize::try_from(entry.size()).map_err(|_| ZfsError::InvalidArgument)?;
        if offset >= size || out.is_empty() {
            return Ok(0);
        }
        let want = core::cmp::min(out.len(), size - offset);
        let first_block = offset / self.block_size;
        let last_block = (offset + want - 1) / self.block_size;
        let mut written = 0usize;
        let mut tmp = vec![0u8; self.block_size];
        for block_index in first_block..=last_block {
            let block = *entry
                .blocks
                .get(block_index)
                .ok_or(ZfsError::InvalidSuperblock)?;
            self.device.read_block(block, &mut tmp)?;
            let block_file_start = block_index * self.block_size;
            let from = offset.saturating_sub(block_file_start);
            let file_end = offset + want;
            let to = core::cmp::min(self.block_size, file_end - block_file_start);
            let n = to.saturating_sub(from);
            out[written..written + n].copy_from_slice(&tmp[from..to]);
            written += n;
        }
        Ok(written)
    }

    pub fn file_size(&self, path: &str) -> Result<usize, ZfsError> {
        let entry = self.directory.get(path).ok_or(ZfsError::NotFound)?;
        if entry.kind() != InodeKind::File {
            return Err(ZfsError::Unsupported);
        }
        usize::try_from(entry.size()).map_err(|_| ZfsError::InvalidArgument)
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

        // Transaction order: allocate/write new blocks while the old directory
        // remains authoritative. Only after metadata bank commit succeeds may
        // old blocks be returned to the live allocator.
        let old = self.directory.get(path).cloned();
        let block_count = blocks_needed(data.len(), self.block_size);
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            match self.allocator.allocate() {
                Ok(block) => blocks.push(block),
                Err(_) => {
                    for b in blocks {
                        let _ = self.allocator.free(b);
                    }
                    return Err(ZfsError::AllocationFailed);
                }
            }
        }
        for (index, &block) in blocks.iter().enumerate() {
            let mut tmp = vec![0u8; self.block_size];
            let start = index * self.block_size;
            let end = core::cmp::min(start + self.block_size, data.len());
            tmp[..end - start].copy_from_slice(&data[start..end]);
            if let Err(err) = self.device.write_block(block, &tmp) {
                for &b in &blocks {
                    let _ = self.allocator.free(b);
                }
                return Err(err.into());
            }
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
        self.directory.insert(
            path,
            DirectoryEntry::new(inode, blocks.clone(), Some(digest)),
        );

        if let Err(err) = self.persist_metadata() {
            self.directory.remove(path);
            if let Some(ref old_entry) = old {
                self.directory.insert(path, old_entry.clone());
            }
            for &b in &blocks {
                let _ = self.allocator.free(b);
            }
            self.next_inode = self.next_inode.saturating_sub(1).max(2);
            return Err(err);
        }
        let _ = self.journal.record(JournalEntry::Write {
            path: String::from(path),
            blocks: blocks.clone(),
            size: data.len() as u64,
            checksum: digest,
        });
        if let Some(old_entry) = old {
            for block in old_entry.blocks {
                if !self.snapshots.references(block) {
                    let _ = self.allocator.free(block);
                    let _ = self.journal.record(JournalEntry::Free { block });
                }
            }
        }
        Ok(())
    }

    pub fn remove_file(&mut self, path: &str) -> Result<(), ZfsError> {
        let entry = self
            .directory
            .get(path)
            .cloned()
            .ok_or(ZfsError::NotFound)?;
        if entry.kind() != InodeKind::File {
            return Err(ZfsError::Unsupported);
        }
        let entry = self.directory.remove(path).ok_or(ZfsError::NotFound)?;
        if let Err(err) = self.persist_metadata() {
            self.directory.insert(path, entry);
            return Err(err);
        }
        for block in entry.blocks {
            if self.snapshots.references(block) {
                continue;
            }
            let _ = self.allocator.free(block);
            let _ = self.journal.record(JournalEntry::Free { block });
        }
        Ok(())
    }

    pub fn entry_exists(&self, path: &str) -> bool {
        self.directory.get(path).is_some()
    }

    pub fn create_dir(&mut self, path: &str) -> Result<(), ZfsError> {
        if path.is_empty() || path == "/" || !path.starts_with('/') || path.contains("..") {
            return Err(ZfsError::PathInvalid);
        }
        if self.directory.get(path).is_some() {
            return Err(ZfsError::DirectoryConflict);
        }
        self.logical_time = self.logical_time.saturating_add(1);
        let inode = Inode {
            id: InodeId(self.next_inode),
            kind: InodeKind::Directory,
            size: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            links: 1,
            data: [0; 12],
            extent_root: 0,
            ctime: self.logical_time,
            mtime: self.logical_time,
        };
        self.next_inode = self.next_inode.saturating_add(1);
        self.directory
            .insert(path, DirectoryEntry::new(inode, Vec::new(), None));
        if let Err(err) = self.persist_metadata() {
            self.directory.remove(path);
            self.next_inode = self.next_inode.saturating_sub(1).max(2);
            return Err(err);
        }
        Ok(())
    }

    pub fn remove_dir(&mut self, path: &str) -> Result<(), ZfsError> {
        let entry = self
            .directory
            .get(path)
            .cloned()
            .ok_or(ZfsError::NotFound)?;
        if entry.kind() != InodeKind::Directory {
            return Err(ZfsError::Unsupported);
        }
        let prefix = if path.ends_with('/') {
            String::from(path)
        } else {
            let mut p = String::from(path);
            p.push('/');
            p
        };
        if self
            .directory
            .snapshot()
            .keys()
            .any(|p| p.starts_with(&prefix))
        {
            return Err(ZfsError::DirectoryConflict);
        }
        self.directory.remove(path);
        if let Err(err) = self.persist_metadata() {
            self.directory.insert(path, entry);
            return Err(err);
        }
        Ok(())
    }

    /// Atomic namespace commit: data blocks never move. Metadata is committed
    /// through the dual-bank checkpoint, so after a crash either old or new
    /// path is visible, never a half-renamed entry.
    pub fn rename_path(&mut self, old: &str, new: &str) -> Result<(), ZfsError> {
        if old == new || new.is_empty() || !new.starts_with('/') || new.contains("..") {
            return Err(ZfsError::InvalidArgument);
        }
        if self.directory.get(new).is_some() {
            return Err(ZfsError::DirectoryConflict);
        }
        let root = self.directory.get(old).cloned().ok_or(ZfsError::NotFound)?;
        if root.kind() != InodeKind::Directory {
            self.directory.remove(old);
            self.directory.insert(new, root.clone());
            if let Err(err) = self.persist_metadata() {
                self.directory.remove(new);
                self.directory.insert(old, root);
                return Err(err);
            }
            return Ok(());
        }

        // Directory rename is a single namespace transaction. Collect the
        // subtree first, rewrite all keys in RAM, then commit one metadata bank.
        let prefix = {
            let mut p = String::from(old.trim_end_matches('/'));
            p.push('/');
            p
        };
        let new_prefix = {
            let mut p = String::from(new.trim_end_matches('/'));
            p.push('/');
            p
        };
        let snapshot = self.directory.snapshot();
        let mut moves: Vec<(String, String, DirectoryEntry)> = Vec::new();
        moves.push((String::from(old), String::from(new), root));
        for (path, entry) in snapshot.iter() {
            if path.starts_with(&prefix) {
                let mut dest = new_prefix.clone();
                dest.push_str(&path[prefix.len()..]);
                if snapshot.contains_key(&dest) {
                    return Err(ZfsError::DirectoryConflict);
                }
                moves.push((path.clone(), dest, entry.clone()));
            }
        }
        for (src, _, _) in &moves {
            self.directory.remove(src);
        }
        for (_, dst, e) in &moves {
            self.directory.insert(dst.clone(), e.clone());
        }
        if let Err(err) = self.persist_metadata() {
            for (_, dst, _) in &moves {
                self.directory.remove(dst);
            }
            for (src, _, e) in moves {
                self.directory.insert(src, e);
            }
            return Err(err);
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

    pub fn delete_snapshot(&mut self, id: u64) -> Result<(), ZfsError> {
        let removed = self
            .snapshots
            .remove(id)
            .ok_or(ZfsError::SnapshotNotFound)?;
        let mut live: BTreeSet<u64> = self
            .directory
            .snapshot()
            .values()
            .flat_map(|entry| entry.blocks.iter().copied())
            .collect();
        for snap in self.snapshots.iter() {
            for entry in snap.directory.values() {
                live.extend(entry.blocks.iter().copied());
            }
        }
        for block in removed
            .directory
            .values()
            .flat_map(|entry| entry.blocks.iter().copied())
        {
            if live.contains(&block) {
                continue;
            }
            if self.allocator.free(block).is_ok() {
                let _ = self.journal.record(JournalEntry::Free { block });
            }
        }
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
        version: 2,
        block_size,
        cluster_size: 4096,
        root_dir: InodeId(1),
        journal_head: 1,
        flags: 0,
        fs_uuid: [0u8; 16],
        sb_sequence: 1,
        region_start: 4,
        region_len: 0,
        active_half: 0,
        sb_crc: 0,
        reserved: [0u8; 24],
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

    static MEMORY_A: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static MEMORY_B: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static MEMORY_C: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    #[test]
    fn volume_capacity_follows_block_device_not_cluster_size() {
        static STORAGE_CAP: Mutex<Vec<u8>> = Mutex::new(Vec::new());
        *STORAGE_CAP.lock() = vec![0; 64 * 1024 * 1024];
        let volume = Volume::mount(
            crate::device::MemoryBlockDevice::new(&STORAGE_CAP),
            MountOptions::default(),
        )
        .unwrap();
        // 64MiB / 4KiB = 16384 blocks, minus superblock/journal reservations.
        assert!(
            volume.free_blocks() > 12_000,
            "capacity must exceed old 4096-block cap"
        );
    }

    fn create_volume(storage: &'static Mutex<Vec<u8>>) -> Volume<crate::device::MemoryBlockDevice> {
        let device = crate::device::MemoryBlockDevice::new(storage);
        Volume::mount(device, MountOptions::default()).unwrap()
    }

    #[test]
    fn write_read_roundtrip() {
        let mut volume = create_volume(&MEMORY_A);
        let data = b"hello world";
        volume.write_file("/hello.txt", data, None).unwrap();
        let mut buf = Vec::new();
        volume.read_file("/hello.txt", &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn remount_restores_directory_and_allocator() {
        static MEMORY_D: Mutex<Vec<u8>> = Mutex::new(Vec::new());
        MEMORY_D.lock().clear();
        MEMORY_D.lock().resize(4 * 1024 * 1024, 0);
        let device = crate::device::MemoryBlockDevice::new(&MEMORY_D);
        {
            let mut volume = Volume::mount(device.clone(), MountOptions::default()).unwrap();
            volume
                .write_file("/Applications/demo.app/bin", b"persistent-elf-bytes", None)
                .unwrap();
        }
        {
            let mut volume = Volume::mount(device.clone(), MountOptions::default()).unwrap();
            let mut out = Vec::new();
            volume
                .read_file("/Applications/demo.app/bin", &mut out)
                .unwrap();
            assert_eq!(&out, b"persistent-elf-bytes");
            // Restored data blocks must be marked busy, so a new write cannot
            // silently reuse and corrupt the first file.
            volume
                .write_file("/Applications/demo.app/manifest", b"v=1", None)
                .unwrap();
            volume.remove_file("/Applications/demo.app/bin").unwrap();
        }
        let volume = Volume::mount(device, MountOptions::default()).unwrap();
        let mut out = Vec::new();
        assert!(matches!(
            volume.read_file("/Applications/demo.app/bin", &mut out),
            Err(ZfsError::NotFound)
        ));
        volume
            .read_file("/Applications/demo.app/manifest", &mut out)
            .unwrap();
        assert_eq!(&out, b"v=1");
    }

    #[test]
    fn snapshot_and_restore() {
        let mut volume = create_volume(&MEMORY_B);
        volume.write_file("/hello", b"a", None).unwrap();
        let snapshot = volume.create_snapshot("first").unwrap();
        volume.write_file("/hello", b"b", None).unwrap();
        volume.restore_snapshot(snapshot.id).unwrap();
        let mut buf = Vec::new();
        volume.read_file("/hello", &mut buf).unwrap();
        assert_eq!(&buf, b"a");
    }

    #[test]
    fn snapshot_releases_blocks_on_delete() {
        let mut volume = create_volume(&MEMORY_C);
        let free_before = volume.allocator_snapshot().free;
        volume
            .write_file("/data", b"snapshot payload", None)
            .unwrap();
        let snapshot = volume.create_snapshot("keep").unwrap();
        volume.write_file("/data", b"v2", None).unwrap();
        volume.delete_snapshot(snapshot.id).unwrap();
        assert_eq!(volume.allocator_snapshot().free, free_before - 1);
    }
    #[test]
    fn directory_subtree_rename_is_persistent() {
        static MEMORY_E: Mutex<Vec<u8>> = Mutex::new(Vec::new());
        MEMORY_E.lock().clear();
        MEMORY_E.lock().resize(4 * 1024 * 1024, 0);
        let dev = crate::device::MemoryBlockDevice::new(&MEMORY_E);
        {
            let mut v = Volume::mount(dev.clone(), MountOptions::default()).unwrap();
            v.create_dir("/Applications").unwrap();
            v.create_dir("/Applications/.tmp").unwrap();
            v.write_file("/Applications/.tmp/main", b"elf", None)
                .unwrap();
            v.create_dir("/Applications/.tmp/res").unwrap();
            v.write_file("/Applications/.tmp/res/a", b"a", None)
                .unwrap();
            v.rename_path("/Applications/.tmp", "/Applications/Demo.app")
                .unwrap();
        }
        let mut v = Volume::mount(dev, MountOptions::default()).unwrap();
        let mut out = Vec::new();
        v.read_file("/Applications/Demo.app/main", &mut out)
            .unwrap();
        assert_eq!(&out, b"elf");
        assert!(v.entry_exists("/Applications/Demo.app/res"));
        assert!(!v.entry_exists("/Applications/.tmp/main"));
    }
}
