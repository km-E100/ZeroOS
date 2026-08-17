//! Minimal ELF header parsing (ELF64 little-endian, ET_EXEC only).
//!
//! This does not perform any mapping or program header processing; it only
//! validates and extracts a few key header fields for later use.

#[derive(Debug, Copy, Clone)]
pub struct ElfHeader {
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

pub const PT_LOAD: u32 = 1;

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

    // e_type (offset 16, u16) must be ET_EXEC = 2.
    let e_type = u16::from_le_bytes([data[16], data[17]]);
    if e_type != 2 {
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
        entry,
        phoff,
        phnum,
        phentsize,
    })
}

/// Parse the program header table. Returns a slice backed by `data`.
///
/// If `phnum` is zero, an empty slice is returned.
pub fn parse_program_headers<'a>(
    data: &'a [u8],
    ehdr: &ElfHeader,
) -> Result<&'a [ElfProgramHeader], ElfError> {
    let entsz = ehdr.phentsize as usize;
    if entsz != core::mem::size_of::<ElfProgramHeader>() {
        return Err(ElfError::UnsupportedProgramHeaderSize);
    }
    let count = ehdr.phnum as usize;
    // Allow zero headers; return an empty slice.
    if count == 0 {
        return Ok(&[]);
    }

    let phoff = ehdr.phoff as usize;
    let total = entsz
        .checked_mul(count)
        .ok_or(ElfError::ProgramHeaderSizeMismatch)?;
    let end = phoff
        .checked_add(total)
        .ok_or(ElfError::ProgramHeaderOutOfBounds)?;
    if end > data.len() {
        return Err(ElfError::ProgramHeaderOutOfBounds);
    }

    // Safety: bounds checked above; layout matches #[repr(C)] ElfProgramHeader.
    let slice = unsafe {
        let ptr = data.as_ptr().add(phoff) as *const ElfProgramHeader;
        core::slice::from_raw_parts(ptr, count)
    };
    Ok(slice)
}
