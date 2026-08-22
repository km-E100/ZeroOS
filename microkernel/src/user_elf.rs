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
    for index in 0..ehdr.phnum {
        let ph = parse_program_header(elf_bytes, &ehdr, index as usize)?;
        if ph.p_type != PT_LOAD {
            continue;
        }
        validate_segment_bounds(&ph, elf_bytes.len())?;
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

    // ⚠ 入口点必须取 ELF 头的 e_entry 字段本身。
    // 历史缺陷：曾用「第一个可执行 LOAD 段的 p_vaddr」充当入口——那是段基址，
    // 不是入口！所有用户进程因此从 .text 中某个随机函数的中间开始执行，
    // 且携带 x30=thread_exit 的陷阱帧寄存器，行为完全不可预测。
    // 这里额外校验 e_entry 必须落在某个可执行 LOAD 段内，防畸形 ELF。
    let entry = ehdr.entry;
    let entry_ok = segments.iter().any(|seg| {
        (seg.flags & PF_X) != 0
            && entry >= seg.vaddr
            && entry < seg.vaddr.saturating_add(seg.memsz)
    });
    if !entry_ok {
        return Err(ElfError::InvalidHeader);
    }
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
