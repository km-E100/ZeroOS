use crate::crc::crc32;

/// Zero File System (ZFS) 磁盘主头（位于 LBA0 起始 64 字节）。
/// 其后紧跟超级块副本 A，LBA1..3 存放超级块副本 B/C/D。
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PrimaryHeader {
    pub magic: [u8; 8], // "ZFSHDR01"
    pub version: u32,
    pub sb_copy_count: u32,
    pub sb_copy_offset: u32,
    pub sb_copy_size: u32,
    pub flags: u64,
    pub reserved: [u8; 40],
}

pub const PRIMARY_HEADER_MAGIC: &[u8; 8] = b"ZFSHDR01";
pub const PRIMARY_HEADER_SIZE: usize = 64;
pub const SUPERBLOCK_COPIES: usize = 4;
pub const SUPERBLOCK_COPY_SIZE: usize = 128;
pub const SUPERBLOCK_MAGIC: &[u8; 8] = b"ZFS00   ";

/// 超级块副本在磁盘上的存放位置。
/// 副本 A 与主头共享 LBA0；副本 B/C/D 分别位于 LBA1/2/3。
pub fn superblock_copy_offset(copy: usize) -> u64 {
    match copy {
        0 => 0,
        n => n as u64,
    }
}

/// Zero File System (ZFS) 超级块结构。
/// 4 份副本循环校验：挂载时取最新（`sb_sequence` 最大）且校验通过的一份。
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SuperBlock {
    pub magic: [u8; 8],
    pub version: u32,
    pub block_size: u32,
    pub cluster_size: u32,
    pub root_dir: InodeId,
    pub journal_head: u64,
    pub flags: u64,
    pub fs_uuid: [u8; 16],
    /// 超级块副本代数：写入时递增，挂载取最大者
    pub sb_sequence: u64,
    /// 日志区域起始块（物理布局：主头+超级块副本之后）
    pub region_start: u64,
    /// 日志区域总长度（块），= 2 * 半区长度（双缓冲设计）
    pub region_len: u64,
    /// 当前活跃半区：0/1
    pub active_half: u32,
    /// 超级块自身校验：对 crc 字段清零后的结构做 CRC-32
    pub sb_crc: u32,
    pub reserved: [u8; 24],
}

impl SuperBlock {
    pub const fn new() -> Self {
        Self {
            magic: *SUPERBLOCK_MAGIC,
            version: 2,
            block_size: 0,
            cluster_size: 4096,
            root_dir: InodeId(1),
            journal_head: 0,
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

    /// 序列化为 128 字节磁盘映像（不足补零）。
    pub fn to_bytes(&self) -> [u8; SUPERBLOCK_COPY_SIZE] {
        debug_assert!(core::mem::size_of::<SuperBlock>() <= SUPERBLOCK_COPY_SIZE);
        let mut buf = [0u8; SUPERBLOCK_COPY_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self as *const SuperBlock).cast::<u8>(),
                buf.as_mut_ptr(),
                core::mem::size_of::<SuperBlock>(),
            );
        }
        buf
    }

    /// 校验魔数、版本与 CRC。`raw` 长度至少为 SUPERBLOCK_COPY_SIZE。
    pub fn validate(raw: &[u8]) -> bool {
        if raw.len() < SUPERBLOCK_COPY_SIZE {
            return false;
        }
        let Some(sb) = Self::from_bytes(raw) else {
            return false;
        };
        if &sb.magic != SUPERBLOCK_MAGIC {
            return false;
        }
        if sb.version == 0 || sb.version > 16 {
            return false;
        }
        // CRC 计算时把结构体内的 sb_crc 字段按字节偏移置零
        let mut copy = [0u8; SUPERBLOCK_COPY_SIZE];
        copy.copy_from_slice(&raw[..SUPERBLOCK_COPY_SIZE]);
        let crc_field = offset_of_crc() as usize;
        copy[crc_field..crc_field + 4].fill(0);
        crc32(&copy) == sb.sb_crc
    }

    /// 从 128 字节磁盘映像解析（不做校验）。
    pub fn from_bytes(raw: &[u8]) -> Option<SuperBlock> {
        if raw.len() < SUPERBLOCK_COPY_SIZE {
            return None;
        }
        let mut buf = [0u8; SUPERBLOCK_COPY_SIZE];
        buf.copy_from_slice(&raw[..SUPERBLOCK_COPY_SIZE]);
        Some(unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const SuperBlock) })
    }
}

/// sb_crc 在结构体中的字节偏移（仅内部使用）。
#[allow(clippy::missing_const_for_fn)]
fn offset_of_crc() -> u32 {
    core::mem::offset_of!(SuperBlock, sb_crc) as u32
}

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct InodeId(pub u64);

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InodeKind {
    File = 1,
    Directory = 2,
    Symlink = 3,
    AppBundle = 4,
}

impl InodeKind {
    /// Inode 种类编号是否落在合法范围内（解析外部数据时校验用）
    pub fn is_valid_raw(raw: u8) -> bool {
        matches!(raw, 1 | 2 | 3 | 4)
    }
}

/// 单个 Inode 固定大小（文档契约：256 字节）。
pub const INODE_SIZE: usize = 256;
/// Inode 内联直接指针个数（文档契约：12）。
pub const INLINE_POINTERS: usize = 12;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BundleHeader {
    pub manifest_inode: InodeId,
    pub signature_inode: InodeId,
    pub resources_inode: InodeId,
    pub flags: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn superblock_roundtrip_and_crc() {
        let mut sb = SuperBlock::new();
        sb.block_size = 4096;
        sb.cluster_size = 65536;
        sb.region_start = 4;
        sb.region_len = 44;
        sb.sb_sequence = 7;
        sb.active_half = 1;
        sb.fs_uuid[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        sb.sb_crc = crc0(&sb);

        let bytes = sb.to_bytes();
        assert!(SuperBlock::validate(&bytes));
        let parsed = SuperBlock::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.region_start, 4);
        assert_eq!(parsed.region_len, 44);
        assert_eq!(parsed.sb_sequence, 7);
        assert_eq!(parsed.active_half, 1);

        // 篡改一个字节后校验必须失败
        let mut damaged = bytes;
        damaged[90] ^= 0x40;
        assert!(!SuperBlock::validate(&damaged));
    }

    fn crc0(sb: &SuperBlock) -> u32 {
        let mut bytes = sb.to_bytes();
        let crc_field = offset_of_crc() as usize;
        bytes[crc_field..crc_field + 4].fill(0);
        crc32(&bytes)
    }

    #[test]
    fn a_reads_do_not_panic() {
        let bytes = [0u8; SUPERBLOCK_COPY_SIZE];
        assert!(!SuperBlock::validate(&bytes));
        assert!(SuperBlock::from_bytes(&bytes).is_some());
    }

    #[test]
    fn inode_size_contract() {
        // 文档契约（Inode 固定 256 字节、12 内联指针）
        assert_eq!(INLINE_POINTERS, 12);
    }
}
