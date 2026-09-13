use alloc::string::String;
use alloc::vec::Vec;

use crate::error::ZfsError;

#[derive(Clone)]
pub enum JournalEntry {
    Allocate {
        block: u64,
    },
    Free {
        block: u64,
    },
    Write {
        path: String,
        blocks: Vec<u64>,
        size: u64,
        checksum: [u8; 32],
    },
    Snapshot {
        id: u64,
        label: String,
    },
}

#[derive(Clone)]
pub struct Journal {
    entries: Vec<JournalEntry>,
    capacity: usize,
    sequence: u64,
}

impl Journal {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
            sequence: 0,
        }
    }

    pub fn record(&mut self, entry: JournalEntry) -> Result<(), ZfsError> {
        if self.entries.len() == self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(entry);
        self.sequence = self.sequence.wrapping_add(1);
        Ok(())
    }

    pub fn recent(&self) -> &[JournalEntry] {
        &self.entries
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}
