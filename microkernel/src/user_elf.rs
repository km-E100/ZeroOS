//! ELF metadata parser for Zero OS user binaries.
//!
//! Supports fixed ET_EXEC, static PIE ET_DYN and the minimal dynamic-runtime
//! subset needed by Knife 30. Dynamic relocations are intentionally fail-closed:
//! only AArch64 RELATIVE / ABS64 / GLOB_DAT / JUMP_SLOT are accepted. Symbol
//! count comes from the standard DT_HASH nchain field, avoiding section-header
//! dependence at runtime.

use alloc::{string::String, vec::Vec};

use crate::elf::{
    parse_elf_header, parse_program_header, ElfError, ElfProgramHeader, ET_DYN, ET_EXEC, PF_X,
    PT_DYNAMIC, PT_LOAD,
};
use crate::rootfs;

pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const RELA_ENT: usize = 24;
const SYM_ENT: usize = 24;
const MAX_SEGMENTS: usize = 12;
const MAX_RELOCATIONS: usize = 8192;
const MAX_NEEDED: usize = 32;
const MAX_NEEDED_NAME: usize = 128;
const MAX_SYMBOLS: usize = 8192;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UserElfKind {
    Exec,
    Dyn,
}

#[derive(Debug, Copy, Clone)]
pub struct UserElfSegment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UserRela {
    pub offset: u64,
    pub typ: u32,
    pub sym: u32,
    pub addend: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDynSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub defined: bool,
    pub binding: u8,
}

pub struct UserElf {
    pub kind: UserElfKind,
    /// Link-time entry; ET_DYN callers add load_bias.
    pub entry: u64,
    pub segments: Vec<UserElfSegment>,
    pub relas: Vec<UserRela>,
    pub needed: Vec<String>,
    pub symbols: Vec<UserDynSymbol>,
}

pub fn build_user_elf(path: &str) -> Result<UserElf, ElfError> {
    let elf_bytes = rootfs::read_file(path).ok_or(ElfError::FileNotFound)?;
    parse_user_elf(elf_bytes)
}

pub fn parse_user_elf(elf_bytes: &[u8]) -> Result<UserElf, ElfError> {
    let ehdr = parse_elf_header(elf_bytes)?;
    let kind = match ehdr.e_type {
        ET_EXEC => UserElfKind::Exec,
        ET_DYN => UserElfKind::Dyn,
        _ => return Err(ElfError::UnsupportedType),
    };

    let mut segments = Vec::new();
    let mut dynamic: Option<ElfProgramHeader> = None;
    for index in 0..ehdr.phnum {
        let ph = parse_program_header(elf_bytes, &ehdr, index as usize)?;
        match ph.p_type {
            PT_LOAD => {
                validate_segment_bounds(&ph, elf_bytes.len())?;
                if segments.len() >= MAX_SEGMENTS {
                    return Err(ElfError::TooManySegments);
                }
                segments.push(UserElfSegment {
                    vaddr: ph.p_vaddr,
                    offset: ph.p_offset,
                    filesz: ph.p_filesz,
                    memsz: ph.p_memsz,
                    flags: ph.p_flags,
                });
            }
            PT_DYNAMIC => {
                validate_segment_bounds(&ph, elf_bytes.len())?;
                if dynamic.replace(ph).is_some() {
                    return Err(ElfError::MalformedDynamic);
                }
            }
            _ => {}
        }
    }
    if segments.is_empty() {
        return Err(ElfError::InvalidHeader);
    }

    // Shared objects commonly have e_entry=0. Only runnable main images need a
    // valid executable entry; the process loader never enters a DT_NEEDED image.
    if ehdr.entry != 0 {
        let entry_ok = segments.iter().any(|seg| {
            (seg.flags & PF_X) != 0
                && ehdr.entry >= seg.vaddr
                && ehdr.entry < seg.vaddr.saturating_add(seg.memsz)
        });
        if !entry_ok {
            return Err(ElfError::InvalidHeader);
        }
    }

    let mut elf = UserElf {
        kind,
        entry: ehdr.entry,
        segments,
        relas: Vec::new(),
        needed: Vec::new(),
        symbols: Vec::new(),
    };
    if let Some(ph) = dynamic {
        parse_dynamic(elf_bytes, ph, &mut elf)?;
    }
    Ok(elf)
}

#[derive(Default)]
struct DynamicInfo {
    rela_va: Option<u64>,
    rela_sz: usize,
    rela_ent: usize,
    jmprel_va: Option<u64>,
    pltrel_sz: usize,
    plt_rel_kind: u64,
    strtab_va: Option<u64>,
    strsz: usize,
    symtab_va: Option<u64>,
    syment: usize,
    hash_va: Option<u64>,
    needed_offsets: Vec<usize>,
}

fn parse_dynamic(bytes: &[u8], ph: ElfProgramHeader, elf: &mut UserElf) -> Result<(), ElfError> {
    // PT_DYNAMIC may include tail padding / adjacent load-window bytes.
    // Elf64_Dyn records are fixed 16 bytes and DT_NULL terminated; requiring
    // p_filesz % 16 == 0 incorrectly rejects valid lld output.
    if ph.p_filesz < 16 {
        return Err(ElfError::MalformedDynamic);
    }
    let start = ph.p_offset as usize;
    let end = start
        .checked_add(ph.p_filesz as usize)
        .ok_or(ElfError::MalformedDynamic)?;
    let dyns = bytes.get(start..end).ok_or(ElfError::MalformedDynamic)?;
    let mut di = DynamicInfo {
        rela_ent: RELA_ENT,
        syment: SYM_ENT,
        ..DynamicInfo::default()
    };

    for d in dyns.chunks_exact(16) {
        let tag = i64::from_le_bytes(d[0..8].try_into().unwrap());
        let val = u64::from_le_bytes(d[8..16].try_into().unwrap());
        match tag {
            DT_NULL => break,
            DT_NEEDED => {
                if di.needed_offsets.len() >= MAX_NEEDED {
                    return Err(ElfError::TooManyNeeded);
                }
                di.needed_offsets.push(val as usize)
            }
            DT_PLTRELSZ => di.pltrel_sz = val as usize,
            DT_HASH => di.hash_va = Some(val),
            DT_STRTAB => di.strtab_va = Some(val),
            DT_SYMTAB => di.symtab_va = Some(val),
            DT_RELA => di.rela_va = Some(val),
            DT_RELASZ => di.rela_sz = val as usize,
            DT_RELAENT => di.rela_ent = val as usize,
            DT_STRSZ => di.strsz = val as usize,
            DT_SYMENT => di.syment = val as usize,
            DT_PLTREL => di.plt_rel_kind = val,
            DT_JMPREL => di.jmprel_va = Some(val),
            _ => {}
        }
    }

    let strtab = if di.strsz != 0 || !di.needed_offsets.is_empty() || di.symtab_va.is_some() {
        let str_va = di.strtab_va.ok_or(ElfError::MalformedDynamic)?;
        let str_off = va_to_file_offset(elf, str_va).ok_or(ElfError::MalformedDynamic)?;
        bytes
            .get(
                str_off
                    ..str_off
                        .checked_add(di.strsz)
                        .ok_or(ElfError::MalformedDynamic)?,
            )
            .ok_or(ElfError::MalformedDynamic)?
    } else {
        &[][..]
    };

    for off in di.needed_offsets {
        let name = string_at(strtab, off)?;
        if name.len() > MAX_NEEDED_NAME {
            return Err(ElfError::TooManyNeeded);
        }
        elf.needed.push(String::from(name));
    }

    if let Some(sym_va) = di.symtab_va {
        if di.syment != SYM_ENT {
            return Err(ElfError::MalformedDynamic);
        }
        let hash_va = di.hash_va.ok_or(ElfError::MalformedDynamic)?;
        let hash_off = va_to_file_offset(elf, hash_va).ok_or(ElfError::MalformedDynamic)?;
        let h = bytes
            .get(hash_off..hash_off + 8)
            .ok_or(ElfError::MalformedDynamic)?;
        let nchain = u32::from_le_bytes(h[4..8].try_into().unwrap()) as usize;
        if nchain > MAX_SYMBOLS {
            return Err(ElfError::MalformedDynamic);
        }
        let sym_off = va_to_file_offset(elf, sym_va).ok_or(ElfError::MalformedDynamic)?;
        let raw = bytes
            .get(
                sym_off
                    ..sym_off
                        .checked_add(nchain * SYM_ENT)
                        .ok_or(ElfError::MalformedDynamic)?,
            )
            .ok_or(ElfError::MalformedDynamic)?;
        for s in raw.chunks_exact(SYM_ENT) {
            let name_off = u32::from_le_bytes(s[0..4].try_into().unwrap()) as usize;
            let info = s[4];
            let shndx = u16::from_le_bytes(s[6..8].try_into().unwrap());
            let value = u64::from_le_bytes(s[8..16].try_into().unwrap());
            let size = u64::from_le_bytes(s[16..24].try_into().unwrap());
            let name = if name_off == 0 {
                ""
            } else {
                string_at(strtab, name_off)?
            };
            elf.symbols.push(UserDynSymbol {
                name: String::from(name),
                value,
                size,
                defined: shndx != 0,
                binding: info >> 4,
            });
        }
    }

    if di.rela_sz != 0 {
        if di.rela_ent != RELA_ENT || di.rela_sz % RELA_ENT != 0 {
            return Err(ElfError::MalformedDynamic);
        }
        parse_rela_range(
            bytes,
            elf,
            di.rela_va.ok_or(ElfError::MalformedDynamic)?,
            di.rela_sz,
        )?;
    }
    if di.pltrel_sz != 0 {
        // DT_PLTREL value is DT_RELA (7) for ELF64 AArch64.
        if di.plt_rel_kind != DT_RELA as u64 || di.pltrel_sz % RELA_ENT != 0 {
            return Err(ElfError::UnsupportedRelocation);
        }
        parse_rela_range(
            bytes,
            elf,
            di.jmprel_va.ok_or(ElfError::MalformedDynamic)?,
            di.pltrel_sz,
        )?;
    }

    for r in &elf.relas {
        if r.typ != R_AARCH64_RELATIVE && r.sym as usize >= elf.symbols.len() {
            return Err(ElfError::MalformedDynamic);
        }
    }
    Ok(())
}

fn parse_rela_range(bytes: &[u8], elf: &mut UserElf, va: u64, size: usize) -> Result<(), ElfError> {
    let off = va_to_file_offset(elf, va).ok_or(ElfError::MalformedDynamic)?;
    let raw = bytes
        .get(off..off.checked_add(size).ok_or(ElfError::MalformedDynamic)?)
        .ok_or(ElfError::MalformedDynamic)?;
    for r in raw.chunks_exact(RELA_ENT) {
        if elf.relas.len() >= MAX_RELOCATIONS {
            return Err(ElfError::TooManyRelocations);
        }
        let offset = u64::from_le_bytes(r[0..8].try_into().unwrap());
        let info = u64::from_le_bytes(r[8..16].try_into().unwrap());
        let addend = i64::from_le_bytes(r[16..24].try_into().unwrap());
        let typ = info as u32;
        let sym = (info >> 32) as u32;
        match typ {
            R_AARCH64_RELATIVE if sym == 0 => {}
            R_AARCH64_ABS64 | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT if sym != 0 => {}
            _ => return Err(ElfError::UnsupportedRelocation),
        }
        elf.relas.push(UserRela {
            offset,
            typ,
            sym,
            addend,
        });
    }
    Ok(())
}

fn string_at(table: &[u8], off: usize) -> Result<&str, ElfError> {
    let tail = table.get(off..).ok_or(ElfError::MalformedDynamic)?;
    let n = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(ElfError::MalformedDynamic)?;
    core::str::from_utf8(&tail[..n]).map_err(|_| ElfError::MalformedDynamic)
}

fn va_to_file_offset(elf: &UserElf, va: u64) -> Option<usize> {
    let seg = elf.segments.iter().find(|s| {
        s.vaddr
            .checked_add(s.filesz)
            .map_or(false, |end| va >= s.vaddr && va < end)
    })?;
    let delta = va.checked_sub(seg.vaddr)?;
    usize::try_from(seg.offset.checked_add(delta)?).ok()
}

impl UserElf {
    pub fn image_span(&self) -> Option<usize> {
        self.segments.iter().try_fold(0usize, |end, s| {
            let next = usize::try_from(s.vaddr.checked_add(s.memsz)?).ok()?;
            Some(end.max(next))
        })
    }
    pub fn runtime_entry(&self, bias: usize) -> Option<usize> {
        usize::try_from(self.entry).ok()?.checked_add(bias)
    }
    pub fn symbol(&self, index: u32) -> Option<&UserDynSymbol> {
        self.symbols.get(index as usize)
    }
}

fn validate_segment_bounds(ph: &ElfProgramHeader, len: usize) -> Result<(), ElfError> {
    if ph.p_filesz > ph.p_memsz {
        return Err(ElfError::InvalidHeader);
    }
    let offset = ph.p_offset as usize;
    let filesz = ph.p_filesz as usize;
    let end = offset
        .checked_add(filesz)
        .ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    if end > len {
        return Err(ElfError::ProgramHeaderOutOfBounds);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relocation_constants_match_aarch64_abi() {
        assert_eq!(R_AARCH64_ABS64, 257);
        assert_eq!(R_AARCH64_GLOB_DAT, 1025);
        assert_eq!(R_AARCH64_JUMP_SLOT, 1026);
        assert_eq!(R_AARCH64_RELATIVE, 1027);
    }
    #[test]
    fn et_dyn_accepts_tail_padding_in_pt_dynamic() {
        let mut b = alloc::vec![0u8; 0x200];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // ELF64
        b[5] = 1; // little endian
        b[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        b[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&2u16.to_le_bytes());
        // Executable PT_LOAD covers [vaddr 0x1000,0x1200).
        let p0 = 64usize;
        b[p0..p0 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[p0 + 4..p0 + 8].copy_from_slice(&(crate::elf::PF_R | PF_X).to_le_bytes());
        b[p0 + 16..p0 + 24].copy_from_slice(&0x1000u64.to_le_bytes());
        b[p0 + 32..p0 + 40].copy_from_slice(&0x200u64.to_le_bytes());
        b[p0 + 40..p0 + 48].copy_from_slice(&0x200u64.to_le_bytes());
        b[p0 + 48..p0 + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        // PT_DYNAMIC is 16-byte DT_NULL plus 8 bytes of legal segment padding.
        let p1 = p0 + 56;
        b[p1..p1 + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        b[p1 + 8..p1 + 16].copy_from_slice(&0x180u64.to_le_bytes());
        b[p1 + 16..p1 + 24].copy_from_slice(&0x1180u64.to_le_bytes());
        b[p1 + 32..p1 + 40].copy_from_slice(&24u64.to_le_bytes());
        b[p1 + 40..p1 + 48].copy_from_slice(&24u64.to_le_bytes());
        b[0x190..0x198].fill(0xa5); // ignored tail padding after DT_NULL
        let elf = parse_user_elf(&b).expect("valid padded PT_DYNAMIC");
        assert_eq!(elf.kind, UserElfKind::Dyn);
        assert!(elf.relas.is_empty());
        assert!(elf.needed.is_empty());
    }

    #[test]
    fn runtime_entry_adds_bias() {
        let elf = UserElf {
            kind: UserElfKind::Dyn,
            entry: 0x1234,
            segments: Vec::new(),
            relas: Vec::new(),
            needed: Vec::new(),
            symbols: Vec::new(),
        };
        assert_eq!(elf.runtime_entry(0x4000000), Some(0x4001234));
    }
}
