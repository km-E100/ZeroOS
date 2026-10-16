//! QEMU 命令行组装：与《编译打包命令.txt》保持一致的基线参数，
//! 外加 virtio-blk 挂盘（`-drive if=none,... -device virtio-blk-device,...`）。
//!
//! 测试盘约定为 `target/disk.img`（32MiB raw）：专用空盘，内核/用户态
//! 的块 I/O 自检与数据都落在它上面，不会污染 rootfs 镜像。
use anyhow::Result;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// machine virt + cortex-a72 + 1GiB + EDK2 UEFI 固件。
pub const QEMU_BASE_ARGS: &[&str] = &[
    "-machine",
    "virt",
    "-cpu",
    "cortex-a72",
    "-m",
    "1024",
    "-bios",
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
    "-display",
    "none",
];

/// virtio-blk 测试盘镜像（相对项目根）。
pub const DISK_REL_PATH: &str = "target/disk.img";
/// 测试盘容量 32MiB。
pub const DISK_SIZE_BYTES: u64 = 32 * 1024 * 1024;

pub fn iso_path(project_root: &Path) -> PathBuf {
    project_root.join("target/zero-os.iso")
}

pub fn disk_path(project_root: &Path) -> PathBuf {
    project_root.join(DISK_REL_PATH)
}

/// 确保 raw 测试盘镜像存在；缺失时创建 32MiB 零填充文件。
/// 已存在则原样复用（保留上次运行写入的数据）。
pub fn ensure_disk_image(project_root: &Path) -> Result<PathBuf> {
    let path = disk_path(project_root);
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        file.set_len(DISK_SIZE_BYTES)?;
        println!(
            "qemu: created virtio test disk {} ({} MiB)",
            path.display(),
            DISK_SIZE_BYTES / 1024 / 1024
        );
    }
    Ok(path)
}

/// 组装完整 QEMU 参数列表。
pub fn build_args(
    iso: &Path,
    serial_log: &Path,
    boot_d: bool,
    virtio_disk: Option<&Path>,
) -> Vec<String> {
    let mut args: Vec<String> = QEMU_BASE_ARGS.iter().map(|s| s.to_string()).collect();
    args.push("-cdrom".into());
    args.push(iso.to_string_lossy().to_string());
    if boot_d {
        args.push("-boot".into());
        args.push("d".into());
    }
    args.push("-serial".into());
    args.push(format!("file:{}", serial_log.display()));
    if let Some(disk) = virtio_disk {
        // 与《编译打包命令.txt》的挂盘参数一致：
        // 槽 0 @ 0x0a000000，对应驱动表 virtio-blk0（GIC INTID 48）。
        args.push("-drive".into());
        args.push(format!(
            "if=none,file={},format=raw,id=zdisk",
            disk.display()
        ));
        args.push("-device".into());
        args.push("virtio-blk-device,drive=zdisk,bus=virtio-mmio-bus.0".into());
    }
    args
}
