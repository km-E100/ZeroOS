use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::on_disk::{Inode, InodeKind};

#[derive(Clone)]
pub struct DirectoryEntry {
    pub inode: Inode,
    pub blocks: Vec<u64>,
    pub signature: Option<[u8; 32]>,
}

impl DirectoryEntry {
    pub fn new(inode: Inode, blocks: Vec<u64>, signature: Option<[u8; 32]>) -> Self {
        Self {
            inode,
            blocks,
            signature,
        }
    }

    pub fn kind(&self) -> InodeKind {
        self.inode.kind
    }

    pub fn size(&self) -> u64 {
        self.inode.size
    }
}

pub struct DirectoryIndex {
    entries: BTreeMap<String, DirectoryEntry>,
}

impl DirectoryIndex {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, path: impl Into<String>, entry: DirectoryEntry) {
        self.entries.insert(normalize(path), entry);
    }

    pub fn get(&self, path: &str) -> Option<&DirectoryEntry> {
        self.entries.get(&normalize(path))
    }

    pub fn get_mut(&mut self, path: &str) -> Option<&mut DirectoryEntry> {
        self.entries.get_mut(&normalize(path))
    }

    pub fn remove(&mut self, path: &str) -> Option<DirectoryEntry> {
        self.entries.remove(&normalize(path))
    }

    pub fn list_prefix<'a>(&'a self, prefix: &str, out: &mut Vec<(&'a str, &'a DirectoryEntry)>) {
        let prefix = normalize(prefix);
        for (path, entry) in self.entries.range(prefix.clone()..) {
            if !path.starts_with(&prefix) {
                break;
            }
            out.push((path.as_str(), entry));
        }
    }

    pub fn as_map(&self) -> &BTreeMap<String, DirectoryEntry> {
        &self.entries
    }

    pub fn snapshot(&self) -> BTreeMap<String, DirectoryEntry> {
        self.entries.clone()
    }

    pub fn restore(&mut self, entries: &BTreeMap<String, DirectoryEntry>) {
        self.entries = entries.clone();
    }
}

fn normalize(path: impl Into<String>) -> String {
    let mut value = path.into();
    if value.is_empty() {
        return "/".to_string();
    }
    if !value.starts_with('/') {
        value.insert(0, '/');
    }
    while value.ends_with('/') && value.len() > 1 {
        value.pop();
    }
    value
}
