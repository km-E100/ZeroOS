//! ELF metadata parser for user binaries.
//! This module only parses headers; it does not allocate or copy data.

use heapless::Vec;

use crate::elf::{
    parse_elf_header, parse_program_header, ElfError, ElfProgramHeader, PF_X, PT_LOAD,
};
use crate::rootfs;

pub struct UserElfSegment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

pub struct UserElf {
    pub entry: u64,
    pub segments: Vec<UserElfSegment, 8>,
}

pub fn build_user_elf(path: &str) -> Result<UserElf, ElfError> {
    let elf_bytes = rootfs::read_file(path).ok_or(ElfError::FileNotFound)?;
    let ehdr = parse_elf_header(elf_bytes)?;

    let mut segments: Vec<UserElfSegment, 8> = Vec::new();
    let mut entry_vaddr: Option<u64> = None;
    for index in 0..ehdr.phnum {
        let ph = parse_program_header(elf_bytes, &ehdr, index as usize)?;
        if ph.p_type != PT_LOAD {
            continue;
        }
        validate_segment_bounds(&ph, elf_bytes.len())?;
        if entry_vaddr.is_none() && (ph.p_flags & PF_X) != 0 {
            entry_vaddr = Some(ph.p_vaddr);
        }
        segments
            .push(UserElfSegment {
                vaddr: ph.p_vaddr,
                offset: ph.p_offset,
                filesz: ph.p_filesz,
                memsz: ph.p_memsz,
                flags: ph.p_flags,
            })
            .map_err(|_| ElfError::TooManySegments)?;
    }

    let entry = entry_vaddr.unwrap_or(ehdr.entry);
    Ok(UserElf { entry, segments })
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
