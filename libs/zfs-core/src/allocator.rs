use alloc::vec;
use alloc::vec::Vec;

/// 块分配器错误（Round 1 硬化：边界校验 / 双写检测 / 重复释放检测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// 磁盘空间耗尽（位图全部置位）
    NoSpace,
    /// 请求的块号越界（超出 [base, base+total) 或块号上溢）
    OutOfBounds,
    /// 对一个已经分配（位图置位）的块重复分配
    DoubleAlloc,
    /// 释放了一个未分配（位图清零）的块
    NotAllocated,
}

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
            allocator.mark_used(block).ok();
        }
        allocator
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    /// 边界校验：block 是否落在 [base, base+total) 内
    pub fn in_range(&self, block: u64) -> bool {
        block >= self.base && block < self.base.saturating_add(self.total)
    }

    /// 分配一个块。越界 / 耗尽返回错误。
    pub fn allocate(&mut self) -> Result<u64, AllocError> {
        if self.free == 0 {
            return Err(AllocError::NoSpace);
        }
        for (index, word) in self.bitmap.iter_mut().enumerate() {
            if *word == u64::MAX {
                continue;
            }
            let free_bit = (!*word).trailing_zeros() as usize;
            let block = self.base.checked_add((index * 64 + free_bit) as u64);
            let Some(block) = block else {
                return Err(AllocError::OutOfBounds);
            };
            if block >= self.base.saturating_add(self.total) {
                return Err(AllocError::OutOfBounds);
            }
            debug_assert_eq!(*word & (1u64 << free_bit), 0);
            *word |= 1u64 << free_bit;
            self.free -= 1;
            return Ok(block);
        }
        Err(AllocError::NoSpace)
    }

    /// 尽力分配 count 个块（可能少于请求数）。
    pub fn allocate_many(&mut self, count: usize) -> Vec<u64> {
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            match self.allocate() {
                Ok(block) => blocks.push(block),
                Err(_) => break,
            }
        }
        blocks
    }

    /// 严格释放：未分配或越界均报错（重放场景请用 `try_free`）。
    pub fn free(&mut self, block: u64) -> Result<(), AllocError> {
        if !self.in_range(block) {
            return Err(AllocError::OutOfBounds);
        }
        let offset = (block - self.base) as usize;
        let word = offset / 64;
        let bit = offset % 64;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask == 0 {
            return Err(AllocError::NotAllocated);
        }
        self.bitmap[word] &= !mask;
        self.free += 1;
        Ok(())
    }

    /// 幂等释放（重放日志时允许重复 / 遗漏的 Free 记录）。
    pub fn try_free(&mut self, block: u64) -> Result<(), AllocError> {
        if !self.in_range(block) {
            return Err(AllocError::OutOfBounds);
        }
        let offset = (block - self.base) as usize;
        let word = offset / 64;
        let bit = offset % 64;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask != 0 {
            self.bitmap[word] &= !mask;
            self.free += 1;
        }
        Ok(())
    }

    /// 严格标记占用：越界 / 已占用报错（双写检测）。
    pub fn mark_used(&mut self, block: u64) -> Result<(), AllocError> {
        if !self.in_range(block) {
            return Err(AllocError::OutOfBounds);
        }
        let offset = (block - self.base) as usize;
        let word = offset / 64;
        let bit = offset % 64;
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask != 0 {
            return Err(AllocError::DoubleAlloc);
        }
        self.bitmap[word] |= mask;
        if self.free > 0 {
            self.free -= 1;
        }
        Ok(())
    }

    /// 幂等标记占用（重放场景）。
    pub fn mark_used_idempotent(&mut self, block: u64) -> Result<(), AllocError> {
        if !self.in_range(block) {
            return Err(AllocError::OutOfBounds);
        }
        let offset = (block - self.base) as usize;
        let mask = 1u64 << (offset % 64);
        if self.bitmap[offset / 64] & mask == 0 {
            self.mark_used(block)
        } else {
            Ok(())
        }
    }

    pub fn is_allocated(&self, block: u64) -> bool {
        if !self.in_range(block) {
            return false;
        }
        let offset = (block - self.base) as usize;
        self.bitmap[offset / 64] & (1u64 << (offset % 64)) != 0
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

#[cfg(test)]
mod tests {
    use super::*;

    fn allocator() -> BlockAllocator {
        let mut a = BlockAllocator::new(0, 1000);
        // 保留前 8 块（超级块/日志区等系统区域）
        for b in 0..8 {
            a.mark_used(b).unwrap();
        }
        a
    }

    #[test]
    fn allocate_and_free_roundtrip() {
        let mut a = allocator();
        let block = a.allocate().unwrap();
        assert_eq!(block, 8);
        assert!(a.is_allocated(block));
        a.free(block).unwrap();
        assert!(!a.is_allocated(block));
        // 释放后可重新分配
        assert_eq!(a.allocate().unwrap(), block);
    }

    #[test]
    fn out_of_bounds_rejected() {
        let mut a = allocator();
        assert_eq!(a.free(u64::MAX), Err(AllocError::OutOfBounds));
        assert_eq!(a.free(999), Err(AllocError::NotAllocated));
        assert_eq!(a.free(1000), Err(AllocError::OutOfBounds));
        assert_eq!(a.mark_used(1001), Err(AllocError::OutOfBounds));
        assert_eq!(a.mark_used(u64::MAX), Err(AllocError::OutOfBounds));
        assert!(!a.is_allocated(1000));
    }

    #[test]
    fn double_free_and_double_alloc_detected() {
        let mut a = allocator();
        let block = a.allocate().unwrap();
        a.free(block).unwrap();
        assert_eq!(a.free(block), Err(AllocError::NotAllocated));
        assert_eq!(a.mark_used(block), Ok(()));
        assert_eq!(a.mark_used(block), Err(AllocError::DoubleAlloc));
    }

    #[test]
    fn idempotent_variants_for_replay() {
        let mut a = allocator();
        a.mark_used_idempotent(10).unwrap();
        a.mark_used_idempotent(10).unwrap();
        assert!(a.is_allocated(10));
        assert_eq!(a.free_count(), 1000 - 8 - 1);
        a.try_free(10).unwrap();
        a.try_free(10).unwrap();
        assert!(!a.is_allocated(10));
        assert_eq!(a.free_count(), 1000 - 8);
    }

    #[test]
    fn fragmentation_loop_conserves_blocks() {
        let mut a = allocator();
        let start_free = a.free_count();
        let mut live = Vec::new();
        // 交叉分配 / 释放循环：先分配 500 个块，随机序释放一半再补满，重复 20 轮
        for _ in 0..20 {
            while live.len() < 500 {
                live.push(a.allocate().unwrap());
            }
            // 间隔释放（制造碎片）
            let mut keep = Vec::with_capacity(live.len() / 2);
            for (i, block) in live.drain(..).enumerate() {
                if i % 2 == 0 {
                    a.free(block).unwrap();
                } else {
                    keep.push(block);
                }
            }
            live = keep;
        }
        // 释放全部并统计：可用块数必须守恒
        for block in live.drain(..) {
            a.free(block).unwrap();
        }
        assert_eq!(a.free_count(), start_free);
        // 全部可重新分配，且互不重复
        let mut seen = Vec::new();
        while let Ok(block) = a.allocate() {
            assert!(!seen.contains(&block), "block {} allocated twice", block);
            seen.push(block);
        }
        assert_eq!(seen.len() as u64, start_free);
    }

    #[test]
    fn tiny_allocator_exhaustion() {
        // 位图单词边界（64 块）两侧的行为
        let mut a = BlockAllocator::new(0, 64);
        let mut all = Vec::new();
        while let Ok(block) = a.allocate() {
            all.push(block);
        }
        assert_eq!(all.len(), 64);
        assert_eq!(a.free_count(), 0);
        assert_eq!(a.allocate(), Err(AllocError::NoSpace));
        assert_eq!(&all[..4], &[0, 1, 2, 3]);
        assert_eq!(*all.last().unwrap(), 63);
    }

    #[test]
    fn mark_used_reserved_start() {
        let mut a = BlockAllocator::new(1, 100);
        a.mark_used(1).unwrap();
        assert_eq!(a.allocate(), Ok(2));
    }
}
