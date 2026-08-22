//! QEMU 命令行组装：与《编译打包命令.txt》保持一致的基线参数，
//! 外加可选 virtio-blk 挂盘（`-drive if=none,... -device virtio-blk-device,...`）。
use std::path::{Path, PathBuf};

/// machine virt + cortex-a72 + 1GiB + EDK2 UEFI 固件 + ISO 光盘启动。
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

pub fn iso_path(project_root: &Path) -> PathBuf {
    project_root.join("target/zero-os.iso")
}

/// 组装完整 QEMU 参数列表。
pub fn build_args(iso: &Path, serial_log: &Path, boot_d: bool, virtio_disk: Option<&Path>) -> Vec<String> {
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
        // 与《编译打包命令.txt》末尾的现成参数一致
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
