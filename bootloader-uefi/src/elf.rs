use alloc::vec::Vec;
use core::mem;
use core::ptr::copy_nonoverlapping;
use uefi::prelude::*;
use uefi::table::boot::{AllocateType, BootServices, MemoryType};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const R_AARCH64_RELATIVE: u32 = 1027;
const RELA_ENT: usize = 24;

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
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const SHN_UNDEF: u16 = 0;

#[derive(Clone, Copy)]
pub struct LoadedSegment {
    pub virtual_addr: u64,
    /// Runtime physical address. For ET_DYN this is filled by set_load_bias().
    pub physical_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
    pub file_offset: u64,
    pub flags: u32,
}

#[derive(Clone)]
pub struct KernelSymbol {
    pub name: alloc::string::String,
    /// Link-time st_value. Call ElfImage::runtime_addr before dereferencing.
    pub value: u64,
    pub info: u8,
}
impl KernelSymbol {
    pub fn sym_type(&self) -> u8 {
        self.info & 0x0f
    }
}

#[derive(Clone, Copy, Debug)]
pub struct KernelRela {
    pub offset: u64,
    pub addend: i64,
}

pub struct ElfImage {
    pub entry: u64,
    pub segments: Vec<LoadedSegment>,
    symbols: Vec<KernelSymbol>,
    relocations: Vec<KernelRela>,
    e_type: u16,
    load_bias: u64,
}

impl ElfImage {
    pub fn parse(data: &[u8]) -> Result<Self, Status> {
        if data.len() < mem::size_of::<Elf64Ehdr>() {
            log_error!("ELF file too small");
            return Err(Status::INVALID_PARAMETER);
        }
        let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Elf64Ehdr) };
        if header.e_ident[..4] != ELF_MAGIC {
            log_error!("invalid ELF magic");
            return Err(Status::INVALID_PARAMETER);
        }
        if header.e_machine != 0xb7 {
            log_error!("unsupported machine: {}", header.e_machine);
            return Err(Status::UNSUPPORTED);
        }
        if !matches!(header.e_type, ET_EXEC | ET_DYN) {
            log_error!("unsupported ELF type: {}", header.e_type);
            return Err(Status::UNSUPPORTED);
        }

        let phoff = header.e_phoff as usize;
        let phentsize = header.e_phentsize as usize;
        let phnum = header.e_phnum as usize;
        if phentsize != mem::size_of::<Elf64Phdr>() {
            return Err(Status::INVALID_PARAMETER);
        }

        let mut segments = Vec::new();
        let mut dynamic = None;
        for idx in 0..phnum {
            let offset = phoff
                .checked_add(
                    idx.checked_mul(phentsize)
                        .ok_or(Status::INVALID_PARAMETER)?,
                )
                .ok_or(Status::INVALID_PARAMETER)?;
            if offset + phentsize > data.len() {
                return Err(Status::INVALID_PARAMETER);
            }
            let ph =
                unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const Elf64Phdr) };
            match ph.p_type {
                PT_LOAD => {
                    if ph.p_filesz > ph.p_memsz
                        || (ph.p_offset as usize)
                            .checked_add(ph.p_filesz as usize)
                            .map_or(true, |e| e > data.len())
                    {
                        return Err(Status::INVALID_PARAMETER);
                    }
                    segments.push(LoadedSegment {
                        virtual_addr: ph.p_vaddr,
                        physical_addr: if header.e_type == ET_DYN {
                            ph.p_vaddr
                        } else {
                            ph.p_paddr
                        },
                        mem_size: ph.p_memsz,
                        file_size: ph.p_filesz,
                        file_offset: ph.p_offset,
                        flags: ph.p_flags,
                    });
                }
                PT_DYNAMIC => dynamic = Some(ph),
                _ => {}
            }
        }
        if segments.is_empty() {
            return Err(Status::INVALID_PARAMETER);
        }

        let symbols = parse_symbol_table(data, &header).map_err(|e| {
            log_error!("ELF symbol table parse failed: {:?}", e);
            e
        })?;
        let relocations = if header.e_type == ET_DYN {
            parse_dynamic_relocations(data, dynamic, &segments).map_err(|e| {
                log_error!("ELF dynamic relocation parse failed: {:?}", e);
                e
            })?
        } else {
            Vec::new()
        };

        log_info!(
            "ELF type={} entry=0x{:016x}, segments={}, symbols={}, relocs={}",
            if header.e_type == ET_DYN {
                "DYN"
            } else {
                "EXEC"
            },
            header.e_entry,
            segments.len(),
            symbols.len(),
            relocations.len()
        );
        Ok(Self {
            entry: header.e_entry,
            segments,
            symbols,
            relocations,
            e_type: header.e_type,
            load_bias: 0,
        })
    }

    pub fn is_pie(&self) -> bool {
        self.e_type == ET_DYN
    }
    pub fn load_bias(&self) -> u64 {
        self.load_bias
    }
    pub fn image_span(&self) -> Option<u64> {
        self.segments.iter().try_fold(0u64, |hi, s| {
            Some(hi.max(s.virtual_addr.checked_add(s.mem_size)?))
        })
    }
    pub fn set_load_bias(&mut self, bias: u64) -> Result<(), Status> {
        if self.e_type == ET_EXEC {
            self.load_bias = 0;
            return Ok(());
        }
        if bias & 0xfff != 0 {
            return Err(Status::INVALID_PARAMETER);
        }
        self.load_bias = bias;
        for seg in &mut self.segments {
            seg.physical_addr = bias
                .checked_add(seg.virtual_addr)
                .ok_or(Status::INVALID_PARAMETER)?;
        }
        Ok(())
    }
    pub fn runtime_addr(&self, link_addr: u64) -> u64 {
        if self.is_pie() {
            self.load_bias.saturating_add(link_addr)
        } else {
            link_addr
        }
    }
    pub fn runtime_entry(&self) -> u64 {
        self.runtime_addr(self.entry)
    }
    pub fn contains_addr(&self, addr: u64) -> bool {
        self.segments
            .iter()
            .any(|s| addr >= s.physical_addr && addr < s.physical_addr.saturating_add(s.mem_size))
    }
    pub fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols
            .iter()
            .find(|s| s.name.as_str() == name)
            .map(|s| self.runtime_addr(s.value))
    }
    pub fn symbols(&self) -> &[KernelSymbol] {
        &self.symbols
    }
    pub fn relocations(&self) -> &[KernelRela] {
        &self.relocations
    }
}

fn parse_dynamic_relocations(
    data: &[u8],
    dynamic: Option<Elf64Phdr>,
    segments: &[LoadedSegment],
) -> Result<Vec<KernelRela>, Status> {
    let Some(ph) = dynamic else {
        return Ok(Vec::new());
    };
    // PT_DYNAMIC may legally extend through alignment/padding (and lld can
    // place the following GOT in the same load window). Dynamic entries are
    // fixed 16-byte Elf64_Dyn records and are terminated by DT_NULL, so parse
    // only complete records and ignore tail padding instead of requiring the
    // entire program-header file size to be a multiple of 16.
    if ph.p_filesz < 16 {
        return Err(Status::INVALID_PARAMETER);
    }
    let start = ph.p_offset as usize;
    let end = start
        .checked_add(ph.p_filesz as usize)
        .ok_or(Status::INVALID_PARAMETER)?;
    let raw = data.get(start..end).ok_or(Status::INVALID_PARAMETER)?;
    let mut rela_va = None;
    let mut rela_sz = 0usize;
    let mut rela_ent = RELA_ENT;
    for d in raw.chunks_exact(16) {
        let tag = i64::from_le_bytes(d[..8].try_into().unwrap());
        let val = u64::from_le_bytes(d[8..16].try_into().unwrap());
        match tag {
            DT_NULL => break,
            DT_RELA => rela_va = Some(val),
            DT_RELASZ => rela_sz = val as usize,
            DT_RELAENT => rela_ent = val as usize,
            _ => {}
        }
    }
    if rela_sz == 0 {
        return Ok(Vec::new());
    }
    if rela_ent != RELA_ENT || rela_sz % RELA_ENT != 0 {
        return Err(Status::UNSUPPORTED);
    }
    let va = rela_va.ok_or(Status::INVALID_PARAMETER)?;
    let off = va_to_file_offset(segments, va).ok_or(Status::INVALID_PARAMETER)?;
    let rel = data
        .get(off..off.checked_add(rela_sz).ok_or(Status::INVALID_PARAMETER)?)
        .ok_or(Status::INVALID_PARAMETER)?;
    let mut out = Vec::new();
    for r in rel.chunks_exact(RELA_ENT) {
        let offset = u64::from_le_bytes(r[0..8].try_into().unwrap());
        let info = u64::from_le_bytes(r[8..16].try_into().unwrap());
        let addend = i64::from_le_bytes(r[16..24].try_into().unwrap());
        let typ = info as u32;
        let sym = info >> 32;
        if typ != R_AARCH64_RELATIVE || sym != 0 {
            log_error!("unsupported kernel PIE relocation type={} sym={}", typ, sym);
            return Err(Status::UNSUPPORTED);
        }
        out.push(KernelRela { offset, addend });
    }
    Ok(out)
}

fn va_to_file_offset(segments: &[LoadedSegment], va: u64) -> Option<usize> {
    let s = segments.iter().find(|s| {
        s.virtual_addr
            .checked_add(s.file_size)
            .map_or(false, |end| va >= s.virtual_addr && va < end)
    })?;
    usize::try_from(s.file_offset.checked_add(va.checked_sub(s.virtual_addr)?)?).ok()
}

fn parse_symbol_table(data: &[u8], header: &Elf64Ehdr) -> Result<Vec<KernelSymbol>, Status> {
    const SHT_STRTAB: u32 = 3;
    let shoff = header.e_shoff as usize;
    let shentsize = header.e_shentsize as usize;
    let shnum = header.e_shnum as usize;
    if shentsize != mem::size_of::<Elf64Shdr>() {
        log_error!(
            "bad section header size: {} expected {}",
            shentsize,
            mem::size_of::<Elf64Shdr>()
        );
        return Err(Status::INVALID_PARAMETER);
    }
    if shoff
        .checked_add(
            shnum
                .checked_mul(shentsize)
                .ok_or(Status::INVALID_PARAMETER)?,
        )
        .map_or(true, |end| end > data.len())
    {
        log_error!(
            "section header table out of bounds: off={:#x} n={} ents={} file={:#x}",
            shoff,
            shnum,
            shentsize,
            data.len()
        );
        return Err(Status::INVALID_PARAMETER);
    }
    let mut sections = Vec::new();
    for idx in 0..shnum {
        let offset = shoff + idx * shentsize;
        if offset + shentsize > data.len() {
            break;
        }
        let sh =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const Elf64Shdr) };
        sections.push((
            sh.sh_type,
            sh.sh_offset as usize,
            sh.sh_size as usize,
            sh.sh_link as usize,
        ));
    }
    let mut out = Vec::new();
    for (ty, sym_off, sym_size, strtab_idx) in &sections {
        if *ty != SHT_SYMTAB && *ty != SHT_DYNSYM {
            continue;
        }
        let (strtab_off, strtab_size) = match sections.get(*strtab_idx) {
            Some((SHT_STRTAB, off, size, _)) => (*off, *size),
            _ => continue,
        };
        let entsize = mem::size_of::<Elf64Sym>();
        let end = sym_off + sym_size;
        if end > data.len() {
            continue;
        }
        for pos in (*sym_off..end).step_by(entsize) {
            if pos + entsize > data.len() {
                break;
            }
            let sym =
                unsafe { core::ptr::read_unaligned(data.as_ptr().add(pos) as *const Elf64Sym) };
            if sym.st_shndx == SHN_UNDEF || sym.st_name == 0 {
                continue;
            }
            let name_off = strtab_off + sym.st_name as usize;
            if name_off >= strtab_off + strtab_size || name_off >= data.len() {
                continue;
            }
            let str_end = strtab_off
                .checked_add(strtab_size)
                .ok_or(Status::INVALID_PARAMETER)?;
            let tail = data
                .get(name_off..str_end)
                .ok_or(Status::INVALID_PARAMETER)?;
            let len = tail.iter().position(|b| *b == 0).ok_or_else(|| {
                log_error!(
                    "symbol name missing NUL inside strtab: name_off={:#x} str_end={:#x}",
                    name_off,
                    str_end
                );
                Status::INVALID_PARAMETER
            })?;
            if let Ok(name) = alloc::string::String::from_utf8(tail[..len].to_vec()) {
                out.push(KernelSymbol {
                    name,
                    value: sym.st_value,
                    info: sym.st_info,
                });
            }
        }
    }
    Ok(out)
}

/// Load an image after its bias is fixed. ET_EXEC preserves the old per-segment
/// exact-address behavior. ET_DYN reserves one contiguous KASLR window, which
/// means a failed candidate consumes no partial segment allocations and can be retried.
pub fn load_segments(bs: &BootServices, image: &ElfImage, file_data: &[u8]) -> Result<(), Status> {
    if image.is_pie() {
        let span = image.image_span().ok_or(Status::INVALID_PARAMETER)?;
        let pages = ((span + 0xfff) / 0x1000) as usize;
        let base = image.load_bias();
        log_info!(
            "alloc PIE kernel @0x{:016x} pages={} span=0x{:x}",
            base,
            pages,
            span
        );
        let dest = bs
            .allocate_pages(AllocateType::Address(base), MemoryType::LOADER_CODE, pages)
            .map_err(|e| e.status())? as *mut u8;
        unsafe {
            core::ptr::write_bytes(dest, 0, pages * 4096);
        }
        for s in &image.segments {
            let src = s.file_offset as usize;
            let n = s.file_size as usize;
            if src.checked_add(n).map_or(true, |e| e > file_data.len()) {
                return Err(Status::INVALID_PARAMETER);
            }
            unsafe {
                copy_nonoverlapping(file_data.as_ptr().add(src), s.physical_addr as *mut u8, n);
            }
        }
        return Ok(());
    }

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
        let dest = bs
            .allocate_pages(
                AllocateType::Address(segment.physical_addr),
                MemoryType::LOADER_CODE,
                pages,
            )
            .map_err(|e| e.status())? as *mut u8;
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

pub fn apply_relocations(image: &ElfImage) -> Result<(), Status> {
    if !image.is_pie() {
        return Ok(());
    }
    for r in image.relocations() {
        let target = image
            .load_bias()
            .checked_add(r.offset)
            .ok_or(Status::INVALID_PARAMETER)?;
        if !image.contains_addr(target) {
            return Err(Status::INVALID_PARAMETER);
        }
        let value = (image.load_bias() as i128) + (r.addend as i128);
        if !(0..=u64::MAX as i128).contains(&value) {
            return Err(Status::INVALID_PARAMETER);
        }
        unsafe {
            core::ptr::write_unaligned(target as *mut u64, value as u64);
        }
    }
    log_info!(
        "kernel PIE relocations applied: {}",
        image.relocations().len()
    );
    Ok(())
}
