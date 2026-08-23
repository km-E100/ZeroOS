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

pub struct LoadedSegment {
    pub virtual_addr: u64,
    pub physical_addr: u64,
    pub mem_size: u64,
    pub file_size: u64,
    pub file_offset: u64,
    pub flags: u32,
}

/// 单条内核符号记录（symtab 原始信息的最小子集）。
#[derive(Clone)]
pub struct KernelSymbol {
    /// 符号名（经 sh_link 指向的 .strtab 解析）。
    pub name: alloc::string::String,
    /// st_value：加载后 VA（内核恒等映射时即物理地址）。
    pub value: u64,
    /// 原始 st_info：低 4 位为 STT 类型，高 4 位为绑定。
    pub info: u8,
}

impl KernelSymbol {
    /// STT 类型（st_info 低 4 位）。
    pub fn sym_type(&self) -> u8 {
        self.info & 0x0f
    }
}

pub struct ElfImage {
    pub entry: u64,
    pub segments: Vec<LoadedSegment>,
    // 已解析符号表。用于引导参数打补丁与符号汇槽填充。
    symbols: Vec<KernelSymbol>,
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

        let symbols = parse_symbol_table(data, &header)?;

        log_info!(
            "ELF entry=0x{:016x}, segments={}, symbols={} ",
            header.e_entry,
            segments.len(),
            symbols.len()
        );
        Ok(ElfImage {
            entry: header.e_entry,
            segments,
            symbols,
        })
    }

    /// 判断地址是否落在任一已加载段内（含 bss 的 mem_size 尾部）。
    pub fn contains_addr(&self, addr: u64) -> bool {
        self.segments
            .iter()
            .any(|seg| addr >= seg.physical_addr && addr < seg.physical_addr + seg.mem_size)
    }

    /// 在内核镜像（已按 p_vaddr 恒等映射加载）中查找符号的加载地址。
    pub fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols
            .iter()
            .find(|sym| sym.name.as_str() == name)
            .map(|sym| sym.value)
    }

    /// 全量符号表（只读视图），供符号汇槽填充等引导期用途。
    pub fn symbols(&self) -> &[KernelSymbol] {
        &self.symbols
    }
}

/// 解析 SHT_SYMTAB / SHT_DYNSYM 符号表，收集 (名字, st_value, st_info)。
/// 内核是 debug（未 strip）构建，symtab 一定存在；找不到时仅告警。
/// 符号名经 sh_link 指向的 .strtab 节解析（st_name 相对该节偏移）。
fn parse_symbol_table(
    data: &[u8],
    header: &Elf64Ehdr,
) -> Result<Vec<KernelSymbol>, Status> {
    const SHT_STRTAB: u32 = 3;

    let shoff = header.e_shoff as usize;
    let shentsize = header.e_shentsize as usize;
    let shnum = header.e_shnum as usize;

    // 第一遍：收集所有节的 (类型, 内容偏移, 内容长度, sh_link)。
    let mut sections = Vec::new();
    for idx in 0..shnum {
        let offset = shoff + idx * shentsize;
        if offset + shentsize > data.len() {
            break;
        }
        let sh = unsafe { *(data.as_ptr().add(offset) as *const Elf64Shdr) };
        sections.push((sh.sh_type, sh.sh_offset as usize, sh.sh_size as usize, sh.sh_link as usize));
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
            let sym = unsafe { *(data.as_ptr().add(pos) as *const Elf64Sym) };
            if sym.st_shndx == SHN_UNDEF || sym.st_name == 0 {
                continue;
            }
            let name_off = strtab_off + sym.st_name as usize;
            if name_off >= strtab_off + strtab_size || name_off >= data.len() {
                continue;
            }
            let tail = &data[name_off..];
            let len = tail
                .iter()
                .position(|b| *b == 0)
                .ok_or(Status::INVALID_PARAMETER)?;
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
