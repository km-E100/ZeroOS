//! Minimal ELF header parsing (ELF64 little-endian, ET_EXEC only).
//!
//! This does not perform any mapping or program header processing; it only
//! validates and extracts a few key header fields for later use.

#[derive(Debug, Copy, Clone)]
pub struct ElfHeader {
    pub e_type: u16,
    pub entry: u64,
    pub phoff: u64,
    pub phnum: u16,
    pub phentsize: u16,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedType,
    InvalidHeader,
    ProgramHeaderOutOfBounds,
    ProgramHeaderSizeMismatch,
    UnsupportedProgramHeaderSize,
    InvalidProgramHeaderCount,
    FileNotFound,
    OutOfMemory,
    TooManySegments,
    MalformedDynamic,
    TooManyRelocations,
    UnsupportedRelocation,
    TooManyNeeded,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ElfProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

/// Parse and validate an ELF64 little-endian executable header.
pub fn parse_elf_header(data: &[u8]) -> Result<ElfHeader, ElfError> {
    // ELF64 header is 64 bytes.
    if data.len() < 64 {
        return Err(ElfError::TooShort);
    }

    // Magic: 0x7F 'E' 'L' 'F'.
    let magic = &data[0..4];
    if magic != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::BadMagic);
    }

    // Class: 2 = 64-bit.
    if data[4] != 2 {
        return Err(ElfError::UnsupportedClass);
    }

    // Endianness: 1 = little-endian.
    if data[5] != 1 {
        return Err(ElfError::UnsupportedEndian);
    }

    // User images may be fixed ET_EXEC or position-independent ET_DYN.
    let e_type = u16::from_le_bytes([data[16], data[17]]);
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError::UnsupportedType);
    }

    // e_ehsize (offset 52, u16) should be 64 for ELF64.
    let e_ehsize = u16::from_le_bytes([data[52], data[53]]);
    if e_ehsize != 64 {
        return Err(ElfError::InvalidHeader);
    }

    // Program header entry size (offset 54) and count (offset 56).
    let phentsize = u16::from_le_bytes([data[54], data[55]]);
    let phnum = u16::from_le_bytes([data[56], data[57]]);
    if phentsize == 0 {
        return Err(ElfError::InvalidHeader);
    }

    // Entry point (offset 24) and program header offset (offset 32).
    let entry = u64::from_le_bytes([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
    ]);
    let phoff = u64::from_le_bytes([
        data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
    ]);

    Ok(ElfHeader {
        e_type,
        entry,
        phoff,
        phnum,
        phentsize,
    })
}

/// Read the index-th program header by byte-copying its fields.
///
/// 按索引逐字段字节拷贝（小端），不依赖输入数据的对齐：
/// include_bytes! 嵌入的 rootfs 文件在 .rodata 中只按 1 字节对齐，
/// 直接强转 *const ElfProgramHeader（align 8）会触发 UB。
pub fn parse_program_header(
    data: &[u8],
    ehdr: &ElfHeader,
    index: usize,
) -> Result<ElfProgramHeader, ElfError> {
    let entsz = ehdr.phentsize as usize;
    if entsz != core::mem::size_of::<ElfProgramHeader>() {
        return Err(ElfError::UnsupportedProgramHeaderSize);
    }
    let count = ehdr.phnum as usize;
    if index >= count {
        return Err(ElfError::InvalidProgramHeaderCount);
    }

    let phoff = ehdr.phoff as usize;
    let off = phoff
        .checked_add(index * entsz)
        .ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    let end = off
        .checked_add(entsz)
        .ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    if end > data.len() {
        return Err(ElfError::ProgramHeaderOutOfBounds);
    }

    let b = &data[off..end];
    // ELF64 小端 phdr 布局：p_type u32, p_flags u32, 六个 u64。
    Ok(ElfProgramHeader {
        p_type: u32::from_le_bytes(b[0..4].try_into().unwrap()),
        p_flags: u32::from_le_bytes(b[4..8].try_into().unwrap()),
        p_offset: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        p_vaddr: u64::from_le_bytes(b[16..24].try_into().unwrap()),
        p_paddr: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        p_filesz: u64::from_le_bytes(b[32..40].try_into().unwrap()),
        p_memsz: u64::from_le_bytes(b[40..48].try_into().unwrap()),
        p_align: u64::from_le_bytes(b[48..56].try_into().unwrap()),
    })
}
