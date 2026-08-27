//! rebuild-fast：STATUS.md「省钱工作流」点名的增量重打包通道。
//!
//! 跳过 build-iso 全链，只重编「指纹发生变化」的组件，并把产物拷入
//! target/iso 暂存树 → 重建 esp.img → iso.sh 重打 ISO → 写 MANIFEST。
//!
//! 增量判断基于源码内容 SHA-256（state.rs 快照，落盘 target/rebuild-fast.state），
//! 与 cargo 自身的 mtime/内容增量互补：cargo 负责"编不编"，本模块负责
//! "哪些下游步骤（rootfs bundle / installer / ESP 重灌 / mkisofs）可以跳过"。
//!
//! 组件分组与触发动作：
//!   kernel      microkernel/src kernel/src boot        → nightly none 构建 + ELF 拷入 ESP 树
//!   bootloader  bootloader-uefi                        → nightly uefi 构建 + EFI 三处拷贝
//!   userland    userland libs servers/launchd          → launchd(release)/user-app(debug) 构建
//!                                                          + sync blobs（可能弄脏 rootfs_tree）
//!   rootfs_tree kernel/rootfs*                         → build-rootfs + zero-installer 重写镜像
//!   installer   installer tools libs/zfs-core          → 同上（安装器逻辑变了要重写 img）
//!   servers     servers（除 launchd 外的 host 服务）   → host 构建 + 拷入 ISO userland/
use crate::hash;
use crate::manifest;
use crate::state::{self, Snapshot};
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::time::Instant;
use xshell::{cmd, Shell};

const STATE_FILE: &str = "target/rebuild-fast.state";
const ISO_STAGING: &str = "target/iso";

/// (组名, 参与指纹的仓库根相对目录)
const GROUPS: &[(&str, &[&str])] = &[
    (
        "kernel",
        &[
            "microkernel/src",
            "microkernel/Cargo.toml",
            "kernel/src",
            "kernel/Cargo.toml",
            "kernel/build.rs",
            "boot",
        ],
    ),
    (
        "bootloader",
        &[
            "bootloader-uefi/src",
            "bootloader-uefi/Cargo.toml",
            "bootloader-uefi/build.rs",
        ],
    ),
    ("userland", &["userland", "libs", "servers/launchd"]),
    ("rootfs_tree", &["kernel/rootfs", "kernel/rootfs-recovery"]),
    (
        "installer",
        &[
            "installer",
            "tools/src",
            "tools/Cargo.toml",
            "libs/zfs-core",
        ],
    ),
    ("servers", &["servers"]),
];

pub struct RebuildFastArgs {
    /// 即使无变更也强制重打包 ISO
    pub force: bool,
}

pub fn run(sh: &Shell, args: RebuildFastArgs) -> Result<()> {
    let t0 = Instant::now();
    let project_root = sh.current_dir().to_path_buf();
    let state_path = project_root.join(STATE_FILE);

    println!("==> rebuild-fast: 计算源码指纹 ...");
    let current = full_snapshot(&project_root)?;

    let baseline = match state::load_state(&state_path) {
        Some(s) => s,
        None => {
            println!(
                "    首次运行（无 {}），按全量执行一次并建立基线",
                STATE_FILE
            );
            Snapshot::new()
        }
    };

    // 判定各组 dirty；首次运行全部视为 dirty（安全优先）
    let mut dirty: Vec<&str> = Vec::new();
    for (name, dirs) in GROUPS {
        let old = group_snapshot(&baseline, dirs);
        let new = group_snapshot(&current, dirs);
        if old != new {
            let (changed, removed) = state::diff_summary(&old, &new);
            let n = changed.len() + removed.len();
            if baseline.is_empty() {
                dirty.push(name);
            } else {
                println!(
                    "    [dirty] {name}: {n} 个文件变更（如 {}）",
                    changed
                        .first()
                        .cloned()
                        .unwrap_or_else(|| removed.first().cloned().unwrap_or_default())
                );
                dirty.push(name);
            }
        }
    }

    if !staging_ready(&project_root)? {
        println!("    target/iso 暂存树缺失，回退全链 build-iso 建立基线 ...");
        crate::image::build_full_image(sh)?;
        state::save_state(&state_path, &current)?;
        manifest::write_manifest(&project_root, "rebuild-fast(cold)")?;
        println!(
            "==> rebuild-fast 完成（cold 全链，耗时 {:.1}s）",
            t0.elapsed().as_secs_f32()
        );
        return Ok(());
    }

    if dirty.is_empty() && !args.force {
        let iso = crate::qemu::iso_path(&project_root);
        if iso.exists() {
            println!(
                "==> rebuild-fast: 无源码变更，ISO 已是最新（{}，{:.1}s）",
                iso.display(),
                t0.elapsed().as_secs_f32()
            );
            return Ok(());
        }
        println!("    无变更但 ISO 缺失，执行重打包 ...");
    }

    // ---- 分组执行构建动作 ----
    let mut need_repack = args.force || dirty.is_empty();

    if dirty.contains(&"bootloader") {
        println!("==> rebuild-fast: 构建 UEFI bootloader");
        cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-uefi -p bootloader-uefi").run()?;
        copy_bootloader(&project_root)?;
        need_repack = true;
    }

    // Any userland/library/server source can affect a bare-metal ELF embedded in
    // kernel/rootfs. Rebuild the complete runtime blob set once, rather than
    // refreshing only launchd/user-app and silently shipping stale pkgd/netd/etc.
    if dirty.contains(&"userland") || dirty.contains(&"servers") {
        println!("==> rebuild-fast: 构建并同步用户态裸机 runtime blobs");
        crate::build_baremetal_blobs(sh)?;
        crate::sync_userland_blobs(sh, true)?;
        // blob 同步改写 kernel/rootfs → rootfs bundle/installer 必须跟进。
        if !dirty.contains(&"rootfs_tree") {
            dirty.push("rootfs_tree");
        }
    }

    if dirty.contains(&"rootfs_tree") || dirty.contains(&"installer") {
        println!("==> rebuild-fast: 重建 rootfs bundle + 安装器写盘");
        crate::build_rootfs(sh)?;
        cmd!(sh, "cargo run -p zero-installer").run()?;
        copy_rootfs_img(&project_root)?;
        need_repack = true;
    } else if !rootfs_in_staging_is_current(&project_root)? {
        println!("==> rebuild-fast: 同步落后的 rootfs 产物到 ISO staging");
        copy_rootfs_img(&project_root)?;
        need_repack = true;
    }

    if dirty.contains(&"servers") {
        println!("==> rebuild-fast: 构建 host 服务二进制");
        cmd!(sh, "cargo build -p zero-fs-zfs -p zero-fsd -p zero-blkdrv -p zero-ipc-router -p zero-securityd -p zero-inputd -p zero-windowserver -p zero-netd -p zero-webtest -p zero-pkgd -p zero-pkgtest -p zero-audiod -p zero-audiotest -p zero-gputest -p zero-service-controller -p zero-installer -p zero-recovery -p mkzfs").run()?;
        copy_host_bins(&project_root)?;
        need_repack = true;
    }

    if dirty.contains(&"kernel") || !kernel_in_staging_is_current(&project_root)? {
        println!("==> rebuild-fast: 构建 aarch64-unknown-none 内核");
        crate::build_kernel_pie(sh)?;
        copy_kernel(&project_root)?;
        need_repack = true;
    }

    // ---- 打包 ----
    if need_repack {
        repack_iso(sh, &project_root)?;
        manifest::write_manifest(&project_root, "rebuild-fast")?;
    }

    // Build steps may rewrite tracked rootfs blobs (sync_userland_blobs). Persist
    // the post-build snapshot, otherwise the next invocation sees our own output
    // as a fresh source change and rebuilds again.
    let final_snapshot = full_snapshot(&project_root)?;
    state::save_state(&state_path, &final_snapshot)?;

    let secs = t0.elapsed().as_secs_f32();
    println!(
        "==> rebuild-fast 完成{}（耗时 {secs:.1}s，目标 <30s）{}",
        if need_repack {
            ""
        } else {
            "（up-to-date，未重打包）"
        },
        if secs < 30.0 {
            " ✓"
        } else {
            " ⚠ 超出预算"
        }
    );
    Ok(())
}

fn full_snapshot(project_root: &Path) -> Result<Snapshot> {
    let mut all: Vec<&str> = Vec::new();
    for (_, dirs) in GROUPS {
        all.extend_from_slice(dirs);
    }
    state::snapshot_dirs(project_root, &all)
}

fn group_snapshot<'a>(snap: &'a Snapshot, dirs: &[&str]) -> Snapshot {
    snap.iter()
        .filter(|(k, _)| dirs.iter().any(|d| k.starts_with(d)))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// 暂存树是否由上一次 build-iso/rebuild-fast 建立（含 ESP 所需全部文件）。
fn staging_ready(project_root: &Path) -> Result<bool> {
    let ok = project_root
        .join(format!("{ISO_STAGING}/EFI/BOOT"))
        .is_dir()
        && project_root
            .join(format!("{ISO_STAGING}/EFI/ZEROOS"))
            .is_dir();
    Ok(ok)
}

fn staging_zeroos(project_root: &Path) -> PathBuf {
    project_root.join(format!("{ISO_STAGING}/EFI/ZEROOS"))
}

fn copy_kernel(project_root: &Path) -> Result<()> {
    let src = project_root.join("target/aarch64-unknown-none-pic/release/zero-kernel");
    let dst = staging_zeroos(project_root).join("zero-kernel");
    fs_xcopy(&src, &dst)
}

fn copy_bootloader(project_root: &Path) -> Result<()> {
    let base = project_root.join("target/aarch64-unknown-uefi/debug");
    let src = ["bootloader-uefi", "bootloader-uefi.efi"]
        .iter()
        .map(|c| base.join(c))
        .find(|p| p.exists())
        .ok_or_else(|| anyhow!("bootloader image not found under {}", base.display()))?;
    let z = staging_zeroos(project_root);
    fs_xcopy(&src, &z.join("zero-normal.efi"))?;
    fs_xcopy(&src, &z.join("zero-recovery.efi"))?;
    fs_xcopy(
        &src,
        &project_root.join(format!("{ISO_STAGING}/EFI/BOOT/BOOTAA64.EFI")),
    )?;
    Ok(())
}

fn copy_rootfs_img(project_root: &Path) -> Result<()> {
    // UEFI bootloader consumes rootfs.bundle directly. Keeping only the installed
    // zero-rootfs.img current is insufficient: a stale staged bundle silently
    // boots old userland even though rebuild-fast just rebuilt all runtime blobs.
    let bundle = project_root.join("target/rootfs.bundle");
    if bundle.exists() {
        fs_xcopy(&bundle, &staging_zeroos(project_root).join("rootfs.bundle"))?;
    }
    let src = project_root.join("target/zero-rootfs.img");
    if src.exists() {
        fs_xcopy(&src, &staging_zeroos(project_root).join("zero-rootfs.img"))?;
    }
    let rec = project_root.join("target/rootfs-recovery.bundle");
    if rec.exists() {
        fs_xcopy(
            &rec,
            &staging_zeroos(project_root).join("rootfs-recovery.bundle"),
        )?;
    }
    Ok(())
}

fn rootfs_in_staging_is_current(project_root: &Path) -> Result<bool> {
    for name in ["rootfs.bundle", "rootfs-recovery.bundle", "zero-rootfs.img"] {
        let built = project_root.join("target").join(name);
        let staged = staging_zeroos(project_root).join(name);
        if !built.exists() || !staged.exists() {
            return Ok(false);
        }
        if hash::hash_file(&built)? != hash::hash_file(&staged)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn copy_host_bins(project_root: &Path) -> Result<()> {
    let debug = project_root.join("target/debug");
    let userland = project_root.join(format!("{ISO_STAGING}/userland"));
    std::fs::create_dir_all(&userland)?;
    for bin in [
        "zero-launchd",
        "zero-fs-zfs",
        "zero-fsd",
        "zero-blkdrv",
        "zero-ipc-router",
        "zero-securityd",
        "zero-inputd",
        "zero-windowserver",
        "zero-netd",
        "zero-webtest",
        "zero-pkgd",
        "zero-pkgtest",
        "zero-audiod",
        "zero-audiotest",
        "zero-gputest",
        "zero-service-controller",
        "zero-installer",
        "zero-recovery",
        "mkzfs",
    ] {
        let src = debug.join(bin);
        if src.exists() {
            fs_xcopy(&src, &userland.join(bin))?;
        }
    }
    Ok(())
}

/// 暂存树里的内核 ELF 是否落后于最新构建产物。
fn kernel_in_staging_is_current(project_root: &Path) -> Result<bool> {
    let built = project_root.join("target/aarch64-unknown-none-pic/release/zero-kernel");
    let staged = staging_zeroos(project_root).join("zero-kernel");
    if !built.exists() || !staged.exists() {
        return Ok(false);
    }
    let hb = hash::hash_file(&built)?;
    let hs = hash::hash_file(&staged)?;
    Ok(hb == hs)
}

/// 重建 esp.img 并用 iso.sh 重打 ISO（不触碰暂存树其余内容）。
fn repack_iso(sh: &Shell, project_root: &Path) -> Result<()> {
    let iso_dir = project_root.join(ISO_STAGING);
    let esp_path = iso_dir.join("esp.img");

    println!("==> rebuild-fast: 重建 esp.img + 打包 ISO");
    if esp_path.exists() {
        std::fs::remove_file(&esp_path)?;
    }
    cmd!(sh, "dd if=/dev/zero of={esp_path} bs=1m count=96")
        .run()
        .context("creating blank ESP image")?;
    cmd!(sh, "mformat -i {esp_path} -F -v ZEROESP ::")
        .run()
        .context("formatting ESP")?;
    cmd!(sh, "mcopy -i {esp_path} -s {iso_dir}/EFI ::/")
        .run()
        .context("copying EFI tree into ESP")?;
    let startup = iso_dir.join("startup.nsh");
    if startup.exists() {
        cmd!(sh, "mcopy -i {esp_path} {startup} ::/startup.nsh").run()?;
    }

    let iso_script = project_root.join("xtask/src/iso.sh");
    let iso_path = crate::qemu::iso_path(project_root);
    if iso_path.exists() {
        std::fs::remove_file(&iso_path)?;
    }
    cmd!(sh, "{iso_script} {iso_path} {iso_dir} esp.img")
        .run()
        .context("running mkisofs")?;
    println!("    ISO written to {}", iso_path.display());
    Ok(())
}

/// fs::copy 但确保父目录存在。
fn fs_xcopy(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dst)
        .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
    Ok(())
}
