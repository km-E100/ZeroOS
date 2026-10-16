use core::fmt;

use crate::device::DeviceError;

#[derive(Debug)]
pub enum ZfsError {
    InvalidSuperblock,
    Device(DeviceError),
    AllocationFailed,
    NotFound,
    SignatureMismatch,
    JournalFull,
    SnapshotNotFound,
    DirectoryConflict,
    Unsupported,
    InvalidArgument,
    /// 请求越界（块号 / 偏移超出容量）
    OutOfBounds,
    /// 释放了一个未分配（或已释放）的块
    NotAllocated,
    /// 对一个已经分配的块重复分配
    DoubleFree,
    /// 日志区域内容损坏（魔数 / CRC 校验失败）
    JournalCorrupt,
    /// 检查点映像超过日志半区容量
    CheckpointTooLarge,
    /// 路径非法（空、非绝对路径、含 `..` 逃逸等）
    PathInvalid,
    /// Inode / 目录条目字段超出合法范围
    CorruptEntry,
}

impl fmt::Display for ZfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZfsError::InvalidSuperblock => write!(f, "invalid superblock"),
            ZfsError::Device(err) => write!(f, "device error: {:?}", err),
            ZfsError::AllocationFailed => write!(f, "no space available"),
            ZfsError::NotFound => write!(f, "entry not found"),
            ZfsError::SignatureMismatch => write!(f, "signature mismatch"),
            ZfsError::JournalFull => write!(f, "journal full"),
            ZfsError::SnapshotNotFound => write!(f, "snapshot not found"),
            ZfsError::DirectoryConflict => write!(f, "directory conflict"),
            ZfsError::Unsupported => write!(f, "unsupported operation"),
            ZfsError::InvalidArgument => write!(f, "invalid argument"),
            ZfsError::OutOfBounds => write!(f, "request out of bounds"),
            ZfsError::NotAllocated => write!(f, "freeing an unallocated block"),
            ZfsError::DoubleFree => write!(f, "double allocation of a block"),
            ZfsError::JournalCorrupt => write!(f, "journal record corrupt"),
            ZfsError::CheckpointTooLarge => write!(f, "checkpoint image too large"),
            ZfsError::PathInvalid => write!(f, "invalid path"),
            ZfsError::CorruptEntry => write!(f, "corrupt inode or directory entry"),
        }
    }
}

impl From<DeviceError> for ZfsError {
    fn from(value: DeviceError) -> Self {
        ZfsError::Device(value)
    }
}
