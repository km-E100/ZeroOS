use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::allocator::AllocatorSnapshot;
use crate::directory::DirectoryEntry;

#[derive(Clone)]
pub struct Snapshot {
    pub id: u64,
    pub label: String,
    pub logical_time: u64,
    pub allocator: AllocatorSnapshot,
    pub directory: BTreeMap<String, DirectoryEntry>,
}

#[derive(Clone)]
pub struct SnapshotInfo {
    pub id: u64,
    pub label: String,
    pub logical_time: u64,
    pub free_blocks: u64,
}

pub struct SnapshotManager {
    next_id: u64,
    snapshots: Vec<Snapshot>,
}

impl SnapshotManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            snapshots: Vec::new(),
        }
    }

    pub fn create(
        &mut self,
        label: impl Into<String>,
        logical_time: u64,
        allocator: &AllocatorSnapshot,
        directory: &BTreeMap<String, DirectoryEntry>,
    ) -> Snapshot {
        let snapshot = Snapshot {
            id: self.next_id,
            label: label.into(),
            logical_time,
            allocator: allocator.clone(),
            directory: directory.clone(),
        };
        self.next_id += 1;
        self.snapshots.push(snapshot.clone());
        snapshot
    }

    pub fn list(&self, out: &mut Vec<SnapshotInfo>) {
        out.clear();
        for snapshot in &self.snapshots {
            out.push(SnapshotInfo {
                id: snapshot.id,
                label: snapshot.label.clone(),
                logical_time: snapshot.logical_time,
                free_blocks: snapshot.allocator.free,
            });
        }
    }

    pub fn get(&self, id: u64) -> Option<&Snapshot> {
        self.snapshots.iter().find(|snap| snap.id == id)
    }

    pub fn iter(&self) -> core::slice::Iter<'_, Snapshot> {
        self.snapshots.iter()
    }

    /// 任一存活快照的目录是否引用了该数据块（CoW 保护判定）。
    pub fn references(&self, block: u64) -> bool {
        self.snapshots
            .iter()
            .flat_map(|snap| snap.directory.values())
            .any(|entry| entry.blocks.contains(&block))
    }

    pub fn remove(&mut self, id: u64) -> Option<Snapshot> {
        let index = self.snapshots.iter().position(|s| s.id == id)?;
        Some(self.snapshots.remove(index))
    }
}
