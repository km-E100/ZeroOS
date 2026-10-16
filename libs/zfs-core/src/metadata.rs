use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::crc::crc32;
use crate::device::BlockDevice;
use crate::directory::DirectoryEntry;
use crate::error::ZfsError;
use crate::on_disk::{Inode, InodeId, InodeKind};

const MAGIC: &[u8; 8] = b"ZMDT0001";
pub const BANK_BLOCKS: u64 = 32;
pub const BANK_A: u64 = 1;
pub const BANK_B: u64 = BANK_A + BANK_BLOCKS;
pub const RESERVED_END: u64 = BANK_B + BANK_BLOCKS;

pub struct MetadataState {
    pub generation: u64,
    pub entries: BTreeMap<String, DirectoryEntry>,
    pub next_inode: u64,
    pub logical_time: u64,
}

pub fn load<D: BlockDevice>(device: &D) -> Result<Option<MetadataState>, ZfsError> {
    let a = load_bank(device, BANK_A)?;
    let b = load_bank(device, BANK_B)?;
    Ok(match (a, b) {
        (Some(a), Some(b)) => Some(if b.generation > a.generation { b } else { a }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    })
}

pub fn store<D: BlockDevice>(
    device: &D,
    generation: u64,
    entries: &BTreeMap<String, DirectoryEntry>,
    next_inode: u64,
    logical_time: u64,
) -> Result<u64, ZfsError> {
    let next_generation = generation.saturating_add(1).max(1);
    let target = if next_generation & 1 == 1 {
        BANK_A
    } else {
        BANK_B
    };
    let payload = encode(entries, next_inode, logical_time)?;
    let capacity = ((BANK_BLOCKS - 1) as usize) * D::BLOCK_SIZE;
    if payload.len() > capacity {
        return Err(ZfsError::CheckpointTooLarge);
    }

    // Payload first, header last: an interrupted write leaves the previous bank
    // authoritative. CRC rejects a torn new bank. The header carries the exact
    // payload length, so blocks beyond that length are semantically unreachable:
    // do NOT rewrite all 31 payload blocks on every namespace mutation. Besides
    // avoiding needless wear on real media, this turns a tiny mkdir/rename from
    // 128 KiB of synchronous I/O into normally one payload block + one header.
    let payload_blocks = payload.len().div_ceil(D::BLOCK_SIZE);
    let mut offset = 0usize;
    for i in 0..payload_blocks {
        let mut block = vec![0u8; D::BLOCK_SIZE];
        let n = core::cmp::min(D::BLOCK_SIZE, payload.len() - offset);
        block[..n].copy_from_slice(&payload[offset..offset + n]);
        offset += n;
        device.write_block(target + 1 + i as u64, &block)?;
    }
    let mut header = vec![0u8; D::BLOCK_SIZE];
    header[..8].copy_from_slice(MAGIC);
    header[8..16].copy_from_slice(&next_generation.to_le_bytes());
    header[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header[20..24].copy_from_slice(&crc32(&payload).to_le_bytes());
    header[24..28].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    device.write_block(target, &header)?;
    Ok(next_generation)
}

fn load_bank<D: BlockDevice>(device: &D, start: u64) -> Result<Option<MetadataState>, ZfsError> {
    let mut header = vec![0u8; D::BLOCK_SIZE];
    match device.read_block(start, &mut header) {
        Ok(()) => {}
        Err(crate::device::DeviceError::OutOfBounds) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if header.get(..8) != Some(MAGIC.as_slice()) {
        return Ok(None);
    }
    let generation = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    let expected_crc = u32::from_le_bytes(header[20..24].try_into().unwrap());
    let max = ((BANK_BLOCKS - 1) as usize) * D::BLOCK_SIZE;
    if len > max {
        return Ok(None);
    }
    let mut payload = vec![0u8; len];
    let mut offset = 0usize;
    for i in 1..BANK_BLOCKS {
        if offset >= len {
            break;
        }
        let mut block = vec![0u8; D::BLOCK_SIZE];
        device.read_block(start + i, &mut block)?;
        let n = core::cmp::min(D::BLOCK_SIZE, len - offset);
        payload[offset..offset + n].copy_from_slice(&block[..n]);
        offset += n;
    }
    if crc32(&payload) != expected_crc {
        return Ok(None);
    }
    let (entries, next_inode, logical_time) = decode(&payload)?;
    Ok(Some(MetadataState {
        generation,
        entries,
        next_inode,
        logical_time,
    }))
}

fn encode(
    entries: &BTreeMap<String, DirectoryEntry>,
    next_inode: u64,
    logical_time: u64,
) -> Result<Vec<u8>, ZfsError> {
    let mut out = Vec::new();
    out.extend_from_slice(&next_inode.to_le_bytes());
    out.extend_from_slice(&logical_time.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (path, entry) in entries {
        if path.len() > u16::MAX as usize || entry.blocks.len() > u16::MAX as usize {
            return Err(ZfsError::CheckpointTooLarge);
        }
        out.extend_from_slice(&(path.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entry.blocks.len() as u16).to_le_bytes());
        out.push(entry.inode.kind as u8);
        out.push(u8::from(entry.signature.is_some()));
        out.extend_from_slice(&entry.inode.mode.to_le_bytes());
        out.extend_from_slice(&entry.inode.id.0.to_le_bytes());
        out.extend_from_slice(&entry.inode.size.to_le_bytes());
        out.extend_from_slice(&entry.inode.uid.to_le_bytes());
        out.extend_from_slice(&entry.inode.gid.to_le_bytes());
        out.extend_from_slice(&entry.inode.links.to_le_bytes());
        out.extend_from_slice(&entry.inode.ctime.to_le_bytes());
        out.extend_from_slice(&entry.inode.mtime.to_le_bytes());
        out.extend_from_slice(path.as_bytes());
        for block in &entry.blocks {
            out.extend_from_slice(&block.to_le_bytes());
        }
        if let Some(sig) = entry.signature {
            out.extend_from_slice(&sig);
        }
    }
    Ok(out)
}

fn decode(data: &[u8]) -> Result<(BTreeMap<String, DirectoryEntry>, u64, u64), ZfsError> {
    let mut c = Cursor { data, off: 0 };
    let next_inode = c.u64()?;
    let logical_time = c.u64()?;
    let count = c.u32()? as usize;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let path_len = c.u16()? as usize;
        let blocks_len = c.u16()? as usize;
        let kind = match c.u8()? {
            1 => InodeKind::File,
            2 => InodeKind::Directory,
            3 => InodeKind::Symlink,
            4 => InodeKind::AppBundle,
            _ => return Err(ZfsError::CorruptEntry),
        };
        let has_sig = c.u8()? != 0;
        let mode = c.u32()?;
        let id = InodeId(c.u64()?);
        let size = c.u64()?;
        let uid = c.u32()?;
        let gid = c.u32()?;
        let links = c.u32()?;
        let ctime = c.u64()?;
        let mtime = c.u64()?;
        let path_bytes = c.bytes(path_len)?;
        let path = core::str::from_utf8(path_bytes).map_err(|_| ZfsError::CorruptEntry)?;
        if path.is_empty() || !path.starts_with('/') || path.contains("..") {
            return Err(ZfsError::PathInvalid);
        }
        let mut blocks = Vec::with_capacity(blocks_len);
        for _ in 0..blocks_len {
            blocks.push(c.u64()?);
        }
        let signature = if has_sig {
            let mut sig = [0u8; 32];
            sig.copy_from_slice(c.bytes(32)?);
            Some(sig)
        } else {
            None
        };
        let mut inode = Inode {
            id,
            kind,
            size,
            mode,
            uid,
            gid,
            links,
            data: [0; 12],
            extent_root: 0,
            ctime,
            mtime,
        };
        for (i, block) in blocks.iter().take(12).enumerate() {
            inode.data[i] = *block;
        }
        entries.insert(
            String::from(path),
            DirectoryEntry::new(inode, blocks, signature),
        );
    }
    if c.off != data.len() {
        return Err(ZfsError::JournalCorrupt);
    }
    Ok((entries, next_inode.max(2), logical_time.max(1)))
}

struct Cursor<'a> {
    data: &'a [u8],
    off: usize,
}
impl<'a> Cursor<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ZfsError> {
        let end = self.off.checked_add(n).ok_or(ZfsError::JournalCorrupt)?;
        let s = self
            .data
            .get(self.off..end)
            .ok_or(ZfsError::JournalCorrupt)?;
        self.off = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ZfsError> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ZfsError> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, ZfsError> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ZfsError> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spin::Mutex;
    static MEM: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    #[test]
    fn dual_bank_roundtrip_and_crc_fallback() {
        MEM.lock().clear();
        MEM.lock().resize(512 * 4096, 0);
        let dev = crate::device::MemoryBlockDevice::new(&MEM);
        let mut map = BTreeMap::new();
        let inode = Inode {
            id: InodeId(7),
            kind: InodeKind::File,
            size: 3,
            mode: 0o644,
            uid: 1,
            gid: 2,
            links: 1,
            data: [0; 12],
            extent_root: 0,
            ctime: 9,
            mtime: 10,
        };
        map.insert(
            String::from("/a"),
            DirectoryEntry::new(inode, vec![100], Some([3; 32])),
        );
        let g1 = store(&dev, 0, &map, 8, 11).unwrap();
        let one = load(&dev).unwrap().unwrap();
        assert_eq!(one.generation, g1);
        assert_eq!(one.entries.get("/a").unwrap().blocks, vec![100]);
        map.insert(
            String::from("/b"),
            DirectoryEntry::new(inode, vec![101], None),
        );
        let g2 = store(&dev, g1, &map, 9, 12).unwrap();
        assert_eq!(load(&dev).unwrap().unwrap().generation, g2);
        // Tear newest bank payload: loader must fall back to previous valid bank.
        let bank = if g2 & 1 == 1 { BANK_A } else { BANK_B };
        let mut bad = vec![0u8; 4096];
        dev.read_block(bank + 1, &mut bad).unwrap();
        bad[0] ^= 0x55;
        dev.write_block(bank + 1, &bad).unwrap();
        let fallback = load(&dev).unwrap().unwrap();
        assert_eq!(fallback.generation, g1);
        assert!(fallback.entries.contains_key("/a"));
        assert!(!fallback.entries.contains_key("/b"));
    }
}
