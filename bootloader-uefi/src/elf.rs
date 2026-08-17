use alloc::vec::Vec;
use core::mem;
use core::ptr::copy_nonoverlapping;
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, BootServices, MemoryType};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

pub struct LoadedSegment {
    pub virtual_addr: u64,
    pub physical_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
    pub file_offset: u64,
    pub flags: u32,
}

pub struct ElfImage {
    pub entry: u64,
    pub segments: Vec<LoadedSegment>,
}

impl ElfImage {
    pub fn parse(data: &[u8]) -> Result<Self, Status> {
        if data.len() < mem::size_of::<Elf64Ehdr>() {
            log_error!("ELF file too small");
            return Err(Status::INVALID_PARAMETER);
        }
        let header = unsafe { *(data.as_ptr() as *const Elf64Ehdr) };
        if header.e_ident[..4] != ELF_MAGIC {
            log_error!("invalid ELF magic");
            return Err(Status::INVALID_PARAMETER);
        }
        if header.e_machine != 0xb7 {
            log_error!("unsupported machine: {}", header.e_machine);
            return Err(Status::UNSUPPORTED);
        }

        let phoff = header.e_phoff as usize;
        let phentsize = header.e_phentsize as usize;
        let phnum = header.e_phnum as usize;

        let mut segments = Vec::new();
        for idx in 0..phnum {
            let offset = phoff + idx * phentsize;
            if offset + phentsize > data.len() {
                log_error!("program header out of range");
                return Err(Status::INVALID_PARAMETER);
            }
            let ph = unsafe { *(data.as_ptr().add(offset) as *const Elf64Phdr) };
            if ph.p_type != PT_LOAD {
                continue;
            }
            segments.push(LoadedSegment {
                virtual_addr: ph.p_vaddr,
                physical_addr: ph.p_paddr,
                mem_size: ph.p_memsz,
                file_size: ph.p_filesz,
                file_offset: ph.p_offset,
                flags: ph.p_flags,
            });
        }

        log_info!(
            "ELF entry=0x{:016x}, segments={} ",
            header.e_entry,
            segments.len()
        );
        Ok(ElfImage {
            entry: header.e_entry,
            segments,
        })
    }
}

pub fn load_segments(bs: &BootServices, image: &ElfImage, file_data: &[u8]) -> Result<(), Status> {
    for segment in &image.segments {
        if segment.mem_size == 0 {
            continue;
        }
        let pages = ((segment.mem_size + 0xfff) / 0x1000) as usize;
        log_info!(
            "alloc segment @0x{:016x} pages={} mem=0x{:x}",
            segment.physical_addr,
            pages,
            segment.mem_size
        );
        let dest = match bs.allocate_pages(
            AllocateType::Address(segment.physical_addr),
            MemoryType::LOADER_CODE,
            pages,
        ) {
            Ok(ptr) => ptr as *mut u8,
            Err(e) => {
                log_error!(
                    "allocate_pages failed @0x{:016x} pages={} status={:?}",
                    segment.physical_addr,
                    pages,
                    e.status()
                );
                return Err(e.status());
            }
        };

        let src_offset = segment.file_offset as usize;
        let copy_size = segment.file_size as usize;
        unsafe {
            copy_nonoverlapping(file_data.as_ptr().add(src_offset), dest, copy_size);
            core::ptr::write_bytes(
                dest.add(copy_size),
                0,
                segment.mem_size as usize - copy_size,
            );
        }
    }
    Ok(())
}
