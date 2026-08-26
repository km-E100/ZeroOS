//! 用户进程引导参数（x0/x1）。
//!
//! 内核在 `process::spawn_user_from_bootfs` 中为本进程映射一份
//! rootfs 的只读拷贝，并把表首地址与条目数写入进程初始寄存器：
//!
//! - `x0` = [`UserBootFs::entries_ptr`]（表首地址）
//! - `x1` = [`UserBootFs::entries_len`]（条目数）
//! - `x2` / `x3` = 0（预留，后续版本可承载会话/登录参数）
//!
//! 用户进程入口（`user_entry(a0, a1, a2, a3)`）收到的前两个参数
//! 即此结构的内容。表内每个 [`UserBootFile`] 同时给出物理地址
//! （`*_phys`）与映射后的虚拟地址（`*_ptr`，优先使用），便于
//! 进程绕过 BLKDRV 直接定位文件。

/// 用户进程视角的 bootfs 文件表（即进程初始 `x0`/`x1` 的内容）。
///
/// `entries_ptr` 指向 [`UserBootFile`] 连续数组，`entries_len`
/// 为条目数；空表时 `entries_ptr` 为 0。
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UserBootFs {
    pub entries_ptr: u64,
    pub entries_len: u64,
}

/// bootfs 中的单条文件记录。
///
/// - `path_phys` / `path_ptr` / `path_len`：路径的物理地址、映射后
///   虚拟地址、长度（UTF-8，无 NUL 结尾）。
/// - `data_phys` / `data_ptr` / `data_len`：文件内容的物理地址、
///   虚拟地址、长度。
///
/// 用户态应当使用 `*_ptr` 系列（已映射到本进程地址空间）；
/// `*_phys` 用于与内核交换物理页等场景。
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
