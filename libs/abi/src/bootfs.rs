#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UserBootFs {
    pub entries_ptr: u64,
    pub entries_len: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UserBootFile {
    pub path_phys: u64,
    pub path_ptr: u64,
    pub path_len: u64,
    pub data_phys: u64,
    pub data_ptr: u64,
    pub data_len: u64,
}
