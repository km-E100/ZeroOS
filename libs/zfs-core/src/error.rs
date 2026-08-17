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
        }
    }
}

impl From<DeviceError> for ZfsError {
    fn from(value: DeviceError) -> Self {
        ZfsError::Device(value)
    }
}
