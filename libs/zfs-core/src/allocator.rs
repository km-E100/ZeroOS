use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct AllocatorSnapshot {
    pub base: u64,
    pub total: u64,
    pub bitmap: Vec<u64>,
    pub free: u64,
}

pub struct BlockAllocator {
    base: u64,
    total: u64,
    free: u64,
    bitmap: Vec<u64>,
}

impl BlockAllocator {
    pub fn new(base: u64, total: u64) -> Self {
        let words = ((total + 63) / 64) as usize;
        Self {
            base,
            total,
            free: total,
            bitmap: vec![0; words],
        }
    }

    pub fn with_reserved(base: u64, total: u64, reserved: &[u64]) -> Self {
        let mut allocator = Self::new(base, total);
        for &block in reserved {
            allocator.mark_used(block);
        }
        allocator
    }

    pub fn allocate(&mut self) -> Option<u64> {
        if self.free == 0 {
            return None;
        }
        for (index, word) in self.bitmap.iter_mut().enumerate() {
            if *word == u64::MAX {
                continue;
            }
            let free_bit = (!*word).trailing_zeros() as usize;
            let block = self.base + (index * 64 + free_bit) as u64;
            if block >= self.base + self.total {
                return None;
            }
            *word |= 1u64 << free_bit;
            self.free -= 1;
            return Some(block);
        }
        None
    }

    pub fn allocate_many(&mut self, count: usize) -> Vec<u64> {
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(block) = self.allocate() {
                blocks.push(block);
            } else {
                break;
            }
        }
        blocks
    }

    pub fn free(&mut self, block: u64) {
        if block < self.base || block >= self.base + self.total {
            return;
        }
        let offset = (block - self.base) as usize;
        let word = offset / 64;
        let bit = offset % 64;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask != 0 {
            self.bitmap[word] &= !mask;
            self.free += 1;
        }
    }

    pub fn mark_used(&mut self, block: u64) {
        if block < self.base || block >= self.base + self.total {
            return;
        }
        let offset = (block - self.base) as usize;
        let word = offset / 64;
        let bit = offset % 64;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask == 0 {
            self.bitmap[word] |= mask;
            if self.free > 0 {
                self.free -= 1;
            }
        }
    }

    pub fn free_count(&self) -> u64 {
        self.free
    }

    pub fn snapshot(&self) -> AllocatorSnapshot {
        AllocatorSnapshot {
            base: self.base,
            total: self.total,
            bitmap: self.bitmap.clone(),
            free: self.free,
        }
    }

    pub fn restore(&mut self, snapshot: &AllocatorSnapshot) {
        self.base = snapshot.base;
        self.total = snapshot.total;
        self.free = snapshot.free;
        self.bitmap = snapshot.bitmap.clone();
    }
}
