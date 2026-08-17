use serde::{Deserialize, Serialize};

/// Zero File System (ZFS) 超级块结构。
#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct SuperBlock {
    pub magic: [u8; 8],
    pub version: u32,
    pub block_size: u32,
    pub cluster_size: u32,
    pub root_dir: InodeId,
    pub journal_head: u64,
    pub flags: u64,
    pub fs_uuid: [u8; 16],
}

#[repr(transparent)]
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InodeId(pub u64);

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Inode {
    pub id: InodeId,
    pub kind: InodeKind,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub data: [u64; 12],
    pub extent_root: u64,
    pub ctime: u64,
    pub mtime: u64,
}

#[repr(u8)]
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InodeKind {
    File = 1,
    Directory = 2,
    Symlink = 3,
    AppBundle = 4,
}

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct BundleHeader {
    pub manifest_inode: InodeId,
    pub signature_inode: InodeId,
    pub resources_inode: InodeId,
    pub flags: u32,
}
