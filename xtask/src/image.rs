use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use xshell::{cmd, Shell};

const ESP_IMAGE_NAME: &str = "esp.img";
/// ESP 容量：内容实测 ~72MiB（内核+双 EFI+64M rootfs 镜像），取 96MiB
/// 留增长余量。此前固定 256MiB 且 esp.img 会作为普通文件再进 ISO 一次，
/// 白白翻倍镜像体积（546MB ISO 的主因）。
const ESP_SIZE_MB: u32 = 96;

pub fn build_full_image(sh: &Shell) -> Result<PathBuf> {
    // Capture source provenance before build-rootfs sync rewrites tracked blob files.
    let source_provenance = source_provenance(&sh.current_dir());
    build_components(sh)?;

    let project_root = sh.current_dir();
    let iso_dir = project_root.join("target/iso");
    if iso_dir.exists() {
        fs::remove_dir_all(&iso_dir)?;
    }
    fs::create_dir_all(&iso_dir)?;

    let efi_boot_dir = iso_dir.join("EFI").join("BOOT");
    let efi_zeroos_dir = iso_dir.join("EFI").join("ZEROOS");
    fs::create_dir_all(&efi_boot_dir)?;
    fs::create_dir_all(&efi_zeroos_dir)?;

    fs::write(efi_zeroos_dir.join("build-info.txt"), &source_provenance)?;

    let kernel = project_root.join("target/aarch64-unknown-none-pic/release/zero-kernel");
    if !kernel.exists() {
        return Err(anyhow!(
            "kernel binary not found at {}; run `cargo run -p xtask -- build-image` first",
            kernel.display()
        ));
    }
    fs::copy(&kernel, efi_zeroos_dir.join("zero-kernel"))?;

    // rootfs image produced by installer
    let rootfs_img = project_root.join("target/zero-rootfs.img");
    if !rootfs_img.exists() {
        return Err(anyhow!(
            "rootfs image not found at {}; run `cargo run -p zero-installer`",
            rootfs_img.display()
        ));
    }
    fs::copy(&rootfs_img, efi_zeroos_dir.join("zero-rootfs.img"))?;

    // Bootfs (early userspace ELF/files) is a compact bundle consumed by the
    // UEFI loader. It is intentionally separate from the persistent volume.
    let bootfs_bundle = project_root.join("target/rootfs.bundle");
    if !bootfs_bundle.exists() {
        return Err(anyhow!(
            "bootfs bundle missing at {}",
            bootfs_bundle.display()
        ));
    }
    fs::copy(&bootfs_bundle, efi_zeroos_dir.join("rootfs.bundle"))?;

    let artifact_info = format!(
        "{}kernel_sha256={}\nrootfs_sha256={}\n",
        source_provenance,
        crate::hash::hash_file(&kernel)?,
        crate::hash::hash_file(&rootfs_img)?,
    );
    fs::write(efi_zeroos_dir.join("build-info.txt"), artifact_info)?;

    let boot_cfg = "\
# Zero OS boot configuration
log=info
rootfs_as_ramdisk=1
";
    fs::write(efi_zeroos_dir.join("boot.cfg"), boot_cfg)?;

    let recovery_cfg = "\
# Zero OS recovery configuration
log=debug
rootfs_as_ramdisk=1
";
    fs::write(efi_zeroos_dir.join("boot-recovery.cfg"), recovery_cfg)?;

    let recovery_bundle = project_root.join("target/rootfs-recovery.bundle");
    if recovery_bundle.exists() {
        fs::copy(
            &recovery_bundle,
            efi_zeroos_dir.join("rootfs-recovery.bundle"),
        )?;
    } else {
        println!(
            "xtask: warning: recovery rootfs bundle not found at {}",
            recovery_bundle.display()
        );
    }

    let bootloader = find_bootloader_image(&project_root)?;
    fs::copy(&bootloader, efi_zeroos_dir.join("zero-normal.efi"))?;
    fs::copy(&bootloader, efi_zeroos_dir.join("zero-recovery.efi"))?;
    fs::copy(&bootloader, efi_boot_dir.join("BOOTAA64.EFI"))?;

    // initial boot state file consumed by bootloader + OS `bootctl`
    let boot_env_path = efi_zeroos_dir.join("boot.env");
    if !boot_env_path.exists() {
        fs::write(&boot_env_path, b"boot_failures=0\nboot_success=0\n")?;
    }

    let startup_script = "\
echo -off\r\n\
if exist fs0:\\EFI\\BOOT\\BOOTAA64.EFI then\r\n  fs0:\\EFI\\BOOT\\BOOTAA64.EFI\r\nendif\r\n\
if exist fs1:\\EFI\\BOOT\\BOOTAA64.EFI then\r\n  fs1:\\EFI\\BOOT\\BOOTAA64.EFI\r\nendif\r\n\
if exist fs2:\\EFI\\BOOT\\BOOTAA64.EFI then\r\n  fs2:\\EFI\\BOOT\\BOOTAA64.EFI\r\nendif\r\n\
if exist fs3:\\EFI\\BOOT\\BOOTAA64.EFI then\r\n  fs3:\\EFI\\BOOT\\BOOTAA64.EFI\r\nendif\r\n";
    fs::write(iso_dir.join("startup.nsh"), startup_script)?;

    // include user-space binaries for convenience
    let debug_dir = project_root.join("target/debug");
    let userland_dir = iso_dir.join("userland");
    fs::create_dir_all(&userland_dir)?;
    for bin in [
        "zero-fs-zfs",
        "zero-fsd",
        "zero-blkdrv",
        "zero-ipc-router",
        "zero-securityd",
        "zero-service-controller",
        "zero-installer",
        "zero-recovery",
    ] {
        let src = debug_dir.join(bin);
        if src.exists() {
            fs::copy(&src, userland_dir.join(bin))?;
        } else {
            println!("xtask: warning: {} not built", bin);
        }
    }

    // copy mkzfs CLI
    let mkzfs_bin = project_root.join("target/debug/mkzfs");
    if mkzfs_bin.exists() {
        fs::copy(&mkzfs_bin, userland_dir.join("mkzfs"))?;
    }

    let iso_path = project_root.join("target/zero-os.iso");
    if iso_path.exists() {
        fs::remove_file(&iso_path)?;
    }

    build_esp_image(sh, &iso_dir)?;

    let iso_script = project_root.join("xtask/src/iso.sh");
    cmd!(sh, "{iso_script} {iso_path} {iso_dir} {ESP_IMAGE_NAME}")
        .run()
        .context("running mkisofs")?;

    println!("ISO image written to {}", iso_path.display());
    Ok(iso_path)
}

fn build_components(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo build -p zero-microkernel").run()?;
    cmd!(sh, "cargo build -p zero-fs-zfs -p zero-fsd -p zero-blkdrv -p zero-ipc-router -p zero-securityd -p zero-inputd -p zero-windowserver -p zero-netd -p zero-webtest -p zero-pkgd -p zero-pkgtest -p zero-audiod -p zero-audiotest -p zero-gputest -p zero-service-controller -p zero-installer -p zero-recovery -p mkzfs").run()?;
    // ⚠ user-app（zero-shell）也必须在此构建：否则 sync_userland_blobs 会把
    // 上次手动构建的陈旧 blob 打进镜像 —— 源码改动“神秘失效”皆源于此。
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p user-app").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-launchd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-securityd -p zero-inputd -p zero-windowserver -p zero-netd -p zero-webtest -p zero-pkgd -p zero-pkgtest -p zero-audiod -p zero-audiotest -p zero-gputest -p zero-fs-zfs -p zero-fsd -p zero-blkdrv --release").run()?;

    // 在 build-rootfs 打包之前，把刚构建的用户态裸机 ELF 同步进 kernel/rootfs
    // （zero-shell / zero-launchd；产物缺失时回退仓库已有 blob 并 warn）。
    // build-rootfs 内部还会再做一次同步，这里显式执行以保证顺序清晰。
    crate::sync_userland_blobs(sh, true)?;

    cmd!(sh, "cargo run -p xtask -- build-rootfs").run()?;
    cmd!(sh, "cargo run -p zero-installer").run()?;
    crate::build_kernel_pie(sh)?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-uefi -p bootloader-uefi").run()?;
    Ok(())
}

fn source_provenance(project_root: &Path) -> String {
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(project_root)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let status = git(&["status", "--porcelain", "--untracked-files=no"]).unwrap_or_default();
    let dirty = if status.is_empty() { "false" } else { "true" };
    format!("commit={commit}\ndirty={dirty}\n")
}

fn find_bootloader_image(project_root: &Path) -> Result<PathBuf> {
    let base = project_root.join("target/aarch64-unknown-uefi/debug");
    for candidate in ["bootloader-uefi", "bootloader-uefi.efi"] {
        let path = base.join(candidate);
        if path.exists() {
            return Ok(path);
        }
    }
    Err(anyhow!(
        "bootloader image not found under {}; run `cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-uefi -p bootloader-uefi`",
        base.display()
    ))
}

fn build_esp_image(sh: &Shell, iso_dir: &Path) -> Result<()> {
    let esp_path = iso_dir.join(ESP_IMAGE_NAME);
    if esp_path.exists() {
        fs::remove_file(&esp_path)?;
    }
    let count_arg = ESP_SIZE_MB.to_string();
    cmd!(sh, "dd if=/dev/zero of={esp_path} bs=1m count={count_arg}")
        .run()
        .context("creating blank ESP image")?;
    cmd!(sh, "mformat -i {esp_path} -F -v ZEROESP ::")
        .run()
        .context("formatting ESP image with FAT32")?;

    let efi_src = iso_dir.join("EFI");
    if efi_src.exists() {
        cmd!(sh, "mcopy -i {esp_path} -s {efi_src} ::/")
            .run()
            .context("copying EFI tree into ESP image")?;
    }

    let boot_src = iso_dir.join("boot");
    if boot_src.exists() {
        cmd!(sh, "mcopy -i {esp_path} -s {boot_src} ::/boot")
            .run()
            .context("copying boot directory into ESP image")?;
    }

    let startup = iso_dir.join("startup.nsh");
    if startup.exists() {
        cmd!(sh, "mcopy -i {esp_path} {startup} ::/startup.nsh")
            .run()
            .context("copying startup.nsh into ESP image")?;
    }

    Ok(())
}
