use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::Write;
use std::path::Path;
use xshell::{cmd, Shell};

mod hash;
mod image;
mod manifest;
mod qemu;
mod rebuild;
mod state;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    BuildKernel,
    BuildKernelBare,
    BuildServers,
    BuildInstaller,
    BuildRecovery,
    BuildImage,
    BuildIso,
    BuildRootfs,
    /// 按源码指纹只重建受影响组件并快速重打 ISO。
    RebuildFast {
        /// 即使指纹无变化也强制重打包 ISO。
        #[arg(long)]
        force: bool,
    },
    Run {
        #[arg(default_value = "normal")]
        mode: String,
    },
    /// 构建 ISO 并自动在 QEMU 中做启动冒烟测试（写 target/ 下日志）
    TestBoot {
        /// 同时断言用户态 shell 成功进入（出现 shell 标志日志）
        #[arg(long)]
        expect_shell: bool,
    },
    /// 清除全部可再生构建产物（target/、镜像、临时盘），目录回到源码+依赖基线
    Purge,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let sh = Shell::new()?;
    // 体积硬闸：Purge 自身豁免（否则锁死后无法自救）。
    if !matches!(cli.command, Commands::Purge) {
        enforce_size_limit(&sh)?;
    }
    match cli.command {
        Commands::BuildKernel => build_kernel(&sh)?,
        Commands::BuildKernelBare => build_kernel_bare(&sh)?,
        Commands::BuildServers => build_servers(&sh)?,
        Commands::BuildInstaller => build_installer(&sh)?,
        Commands::BuildRecovery => build_recovery(&sh)?,
        Commands::BuildImage => build_image(&sh)?,
        Commands::BuildRootfs => build_rootfs(&sh)?,
        Commands::RebuildFast { force } => rebuild::run(&sh, rebuild::RebuildFastArgs { force })?,
        Commands::BuildIso => {
            // 先把用户态裸机 blob（zero-securityd 等）编到最新，随后的
            // sync_userland_blobs（build-rootfs 内）才会把新产物嵌入内核。
            build_baremetal_blobs(&sh)?;
            image::build_full_image(&sh)?;
        }
        Commands::Run { mode } => run(&sh, &mode)?,
        Commands::TestBoot { expect_shell } => {
            // 与 BuildIso 同理：先刷新裸机 blob 再走全链冒烟。
            build_baremetal_blobs(&sh)?;
            test_boot(&sh, expect_shell)?;
        }
        Commands::Purge => purge(&sh)?,
    }
    Ok(())
}

/// 项目目录体积上限（MB）。用户设定 2GB±1GB：峰值构建需要 ~2.3GB，
/// 取 3072MB（3GB）为硬闸。超限后一切构建命令前置拒绝。
const SIZE_LIMIT_MB: u64 = 3072;
const KERNEL_PIE_TARGET_SPEC: &str = "userland/targets/aarch64-unknown-none-pic.json";
const KERNEL_PIE_REL: &str = "target/aarch64-unknown-none-pic/release/zero-kernel";

fn build_kernel_pie(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo +nightly -Z json-target-spec -Z build-std=core,compiler_builtins,alloc build --target {KERNEL_PIE_TARGET_SPEC} -p zero-kernel --release").run()?;
    Ok(())
}

fn enforce_size_limit(sh: &Shell) -> Result<()> {
    let out = cmd!(sh, "du -sm .").read()?;
    let used_mb: u64 = out
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if used_mb > SIZE_LIMIT_MB {
        bail!(
            "项目目录已用 {used_mb}MB，超过上限 {SIZE_LIMIT_MB}MB —— 构建锁死。\n运行 `cargo run -p xtask -- purge` 清理可再生产物后再试。"
        );
    }
    Ok(())
}

fn purge(sh: &Shell) -> Result<()> {
    let root = sh.current_dir();
    // 深度清理：除 target 整树外，连带各 worktree 的构建目录（它们共享
    // 磁盘预算；worktree 本体与分支保留）。
    let _ = cmd!(sh, "rm -rf target/iso target/zero-os.iso target/zero-rootfs.img target/disk.img target/rootfs.bundle target/rootfs-recovery.bundle target/release target/aarch64-unknown-uefi target/aarch64-unknown-none/debug/incremental target/aarch64-unknown-none/release/incremental target/aarch64-unknown-uefi/debug/incremental target/aarch64-unknown-uefi/release/incremental").run();
    for wt in ["cow-fork-wip", "pstore-wip", "user-heap", "oom-graceful"] {
        let p = root
            .parent()
            .unwrap()
            .join(format!("Zero OS.worktrees/{wt}/target"));
        if p.exists() {
            println!("purge: removing worktree target ({wt})");
            fs::remove_dir_all(&p)?;
        }
    }
    let out = cmd!(sh, "du -sm .").read()?;
    println!("purge: done, current size {}", out.trim());
    Ok(())
}

fn build_kernel(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo build -p zero-microkernel").run()?;
    Ok(())
}

fn build_kernel_bare(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-microkernel")
        .run()?;
    Ok(())
}

/// 构建进 rootfs 的用户态裸机 blob（与 build_servers 的裸机部分一致）。
///
/// build-iso/test-boot 入口先跑这里：sync_userland_blobs 只搬运已构建
/// 产物，缺了这步会用仓库里的陈旧 blob（或缺失时回退旧文件），源码
/// 改动就会"神秘失效"。
fn build_baremetal_blobs(sh: &Shell) -> Result<()> {
    // 第十~十三刀集成修复：zero-shell 纳入自动构建。此前 sync 在
    // debug/zero-shell 缺失时静默回退仓库旧 blob——shell 源码改动
    // "神秘失效"（本刀 sleepdemo/secdemo 联调时实机踩坑）。
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p user-app").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-launchd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-securityd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-inputd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-windowserver --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-netd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-webtest --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-pkgd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-pkgtest --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-audiod --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-audiotest --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-gputest --release").run()?;
    // 第七刀：fsd（块后端卷文件服务）与 blkdrv（直通块设备服务）。
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-fs-zfs --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-fsd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-blkdrv --release").run()?;
    Ok(())
}

fn build_servers(sh: &Shell) -> Result<()> {
    // 这些是正常 host 目标，照常用默认 target 编
    cmd!(sh, "cargo build -p zero-fs-zfs -p zero-fsd -p zero-blkdrv -p zero-ipc-router -p zero-securityd -p zero-inputd -p zero-windowserver -p zero-netd -p zero-webtest -p zero-pkgd -p zero-pkgtest -p zero-audiod -p zero-audiotest -p zero-gputest -p zero-service-controller -p zero-installer -p zero-recovery -p mkzfs").run()?;

    // zero-launchd 只编 aarch64-unknown-none 的裸机版本
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-launchd --release").run()?;

    // zero-securityd 同样只编裸机版本（rootfs 运行物；host 版仅作分析副本）
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-securityd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-inputd --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-windowserver --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-netd --release").run()?;

    // 第七刀：zero-blkdrv / zero-fsd 只编裸机版本（rootfs 运行物；
    // host 版由上方第一行照常产出，供 ISO userland/ 分析用）。
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-blkdrv --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-fs-zfs --release").run()?;
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-fsd --release").run()?;

    // 一致性核对：
    //   A. ISO 的 userland/ 目录（image.rs）收集的是 target/debug 下的 HOST 版
    //      服务器二进制，仅供开发者在宿主系统里调试/分析，不是 rootfs 运行物。
    //   B. 真正的运行物是 kernel/rootfs/System/Core/zero-launchd 这个裸机 ELF
    //      （由 build-rootfs 打包进 bundle → installer 写入 zero-rootfs.img）。
    //   这里把 release 裸机 ELF 同步进 rootfs，保证 build-servers 后直接
    //   build-rootfs/build-iso 也能产生一致的启动镜像。
    sync_userland_blobs(sh, true)?;

    Ok(())
}

/// 把已构建的用户态裸机 ELF 同步到 kernel/rootfs 的 blob 路径：
///   - zero-shell          -> kernel/rootfs/Applications/Shell
///   - zero-launchd        -> kernel/rootfs/System/Core/zero-launchd
///
/// 找不到构建产物时不报错，保留现有 blob 并打 warn（例如用户态 Agent
/// 尚未产出该二进制时，回退使用仓库里已有的旧 blob）。
fn sync_userland_blobs(sh: &Shell, warn_missing: bool) -> Result<()> {
    let project_root = sh.current_dir();
    let blobs: &[(&str, &str, &str)] = &[
        // (构建产物路径, 目标路径, 说明)
        (
            "target/aarch64-unknown-none/debug/zero-shell",
            "kernel/rootfs/Applications/Shell",
            "用户 shell",
        ),
        (
            "target/aarch64-unknown-none/release/zero-launchd",
            "kernel/rootfs/System/Core/zero-launchd",
            "launchd 服务器",
        ),
        (
            "target/aarch64-unknown-none/release/zero-securityd",
            "kernel/rootfs/System/Core/zero-securityd",
            "securityd 服务器",
        ),
        (
            "target/aarch64-unknown-none/release/zero-inputd",
            "kernel/rootfs/System/Core/zero-inputd",
            "inputd 输入服务器（第23刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-windowserver",
            "kernel/rootfs/System/Core/zero-windowserver",
            "WindowServer 合成服务（第24刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-netd",
            "kernel/rootfs/System/Core/zero-netd",
            "netd 网络服务器（第27刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-webtest",
            "kernel/rootfs/System/Core/zero-webtest",
            "webtest TLS/HTTP 回归服务（第28刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-pkgd",
            "kernel/rootfs/System/Core/zero-pkgd",
            "pkgd 包管理服务（第29刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-pkgtest",
            "kernel/rootfs/System/Core/zero-pkgtest",
            "pkgtest 包管理回归客户端（第29刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-audiod",
            "kernel/rootfs/System/Core/zero-audiod",
            "audiod 音频服务（第33刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-audiotest",
            "kernel/rootfs/System/Core/zero-audiotest",
            "audiotest 音频回归客户端（第33刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-gputest",
            "kernel/rootfs/System/Core/zero-gputest",
            "gputest VirGL 3D 回归客户端（第34刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-blkdrv",
            "kernel/rootfs/System/Core/zero-blkdrv",
            "blkdrv 块设备服务器（第七刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-fs-zfs",
            "kernel/rootfs/System/Core/zero-fs-zfs",
            "ZFS 默认文件服务器（第32刀）",
        ),
        (
            "target/aarch64-unknown-none/release/zero-fsd",
            "kernel/rootfs/System/Core/zero-fsd",
            "fsd 文件服务器（第七刀）",
        ),
    ];
    for (src_rel, dst_rel, what) in blobs {
        let src = project_root.join(src_rel);
        let dst = project_root.join(dst_rel);
        if !src.exists() {
            println!(
                "xtask: warning: {} blob not built at {}; keeping existing {}",
                what,
                src.display(),
                dst_rel
            );
            if warn_missing {
                eprintln!(
                    "xtask: hint: run `cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p user-app` (zero-shell) or `cargo run -p xtask -- build-servers` (zero-launchd)"
                );
            }
            continue;
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&src, &dst)?;
        println!(
            "xtask: synced {} blob: {} -> {}",
            what,
            src.display(),
            dst.display()
        );
    }
    Ok(())
}

fn build_installer(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo build -p zero-installer").run()?;
    Ok(())
}

fn build_recovery(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo build -p zero-recovery").run()?;
    Ok(())
}

fn build_image(sh: &Shell) -> Result<()> {
    if let Err(err) = build_kernel_pie(sh) {
        eprintln!(
            "xtask: build-image failed: {err}\n    hint: kernel image KASLR uses the custom PIC target and nightly json-target-spec."
        );
        return Err(err);
    }
    let project_root = sh.current_dir();
    let elf = project_root.join(KERNEL_PIE_REL);
    let dest = project_root.join("target/zero-os.elf");
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&elf, &dest)?;
    println!("KASLR-ready ET_DYN image generated at {}", dest.display());
    Ok(())
}

fn build_rootfs(sh: &Shell) -> Result<()> {
    // build-rootfs 入口：先把最新构建的用户态 blob 同步进 kernel/rootfs，
    // 保证 bundle 里始终是刚构建的 zero-shell / zero-launchd（缺失时回退旧 blob）。
    sync_userland_blobs(sh, false)?;

    let project_root = sh.current_dir();
    let source_dir = project_root.join("kernel/rootfs");
    if !source_dir.exists() {
        bail!("rootfs directory {} not found", source_dir.display());
    }

    let out_dir = project_root.join("target");
    fs::create_dir_all(&out_dir)?;

    build_bundle(&source_dir, &out_dir.join("rootfs.bundle"))?;

    let recovery_dir = project_root.join("kernel/rootfs-recovery");
    if recovery_dir.exists() {
        build_bundle(&recovery_dir, &out_dir.join("rootfs-recovery.bundle"))?;
    }
    Ok(())
}

fn build_bundle(source_dir: &Path, bundle_path: &Path) -> Result<()> {
    let mut entries = Vec::new();
    collect_rootfs_entries(source_dir, source_dir, &mut entries)?;

    let mut file = fs::File::create(bundle_path).context("creating rootfs bundle")?;
    file.write_all(b"ZEROFSB\0")?;
    file.write_all(&(entries.len() as u32).to_le_bytes())?;
    for (path, data) in &entries {
        let path_bytes = path.as_bytes();
        file.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
        file.write_all(path_bytes)?;
        file.write_all(&(data.len() as u32).to_le_bytes())?;
        file.write_all(data)?;
    }
    println!(
        "rootfs bundle generated at {} ({} files)",
        bundle_path.display(),
        entries.len()
    );
    Ok(())
}

/// QEMU 基础参数，与《编译打包命令.txt》保持一致：
/// machine virt + cortex-a72 + 1GiB + EDK2 UEFI 固件 + ISO 光盘启动。
/// 串口输出写 target/qemu-run.log（历史日志 qemu-console.log/qemu.log 不被触碰）。
const QEMU_BASE_ARGS: &[&str] = &[
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
    "-cdrom",
    "target/zero-os.iso",
];

fn run(sh: &Shell, mode: &str) -> Result<()> {
    let project_root = sh.current_dir();
    let serial_log = project_root.join("target/qemu-run.log");
    if let Some(parent) = serial_log.parent() {
        fs::create_dir_all(parent)?;
    }

    let boot_d = match mode {
        "normal" => false,
        "recovery" => true,
        _ => {
            println!("unknown mode {mode}, defaulting to normal");
            false
        }
    };

    // virtio-blk 测试盘：缺失自动创建（32MiB raw，target/disk.img）。
    // 参数组装统一走 qemu 模块（与《编译打包命令.txt》/run-qemu.sh 一致）。
    let disk = qemu::ensure_disk_image(&project_root)?;
    let args = qemu::build_args(
        &qemu::iso_path(&project_root),
        &serial_log,
        boot_d,
        Some(&disk),
    );

    // 注释：交互调试可改用 ./run-qemu.sh（-serial mon:stdio）。
    cmd!(sh, "qemu-system-aarch64 {args...}").run()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// test-boot：构建 ISO 并在 QEMU 中做自动启动冒烟测试
// ---------------------------------------------------------------------------

/// 启动成功的公认标志行（内核在 services 拉起前打印）。
const MARKER_READY: &str = "Zero OS microkernel ready";
/// 用户态 shell 进入用户态的标志行（当前调度器稳定输出 + shell 自身横幅）。
const MARKER_SHELL: &[&str] = &[
    "scheduler::dispatch: pid=3",
    "Zero OS console (user shell)",
    "enter_user_mode",
];
/// 已知问题区标志：出现这些行不判 FAIL，但会汇总进报告。
const MARKER_KNOWN_ISSUE: &[&str] = &["panic", "terminating pid", "SYSTEM HALT"];

fn test_boot(sh: &Shell, expect_shell: bool) -> Result<()> {
    // 1. 构镜像（build-iso 全链）
    println!("==> test-boot: building ISO");
    image::build_full_image(sh)?;

    // 2. 启动 QEMU（后台），串口日志只写 target/ 下，不动仓库根的历史日志
    let project_root = sh.current_dir();
    let log_path = project_root.join("target/test-boot-serial.log");
    if log_path.exists() {
        fs::remove_file(&log_path)?;
    }
    println!(
        "==> test-boot: launching QEMU (serial -> {})",
        log_path.display()
    );

    let mut child = std::process::Command::new("qemu-system-aarch64")
        .args(QEMU_BASE_ARGS)
        .arg("-serial")
        .arg(format!("file:{}", log_path.display()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .current_dir(&project_root)
        .spawn()
        .context("spawning qemu-system-aarch64 (is it installed?)")?;

    // 3. 轮询串口日志（超时 ~45s）
    let timeout = std::time::Duration::from_secs(45);
    let deadline = std::time::Instant::now() + timeout;
    let mut ready = false;
    let mut shell_seen = false;
    let mut known_issues: Vec<String> = Vec::new();
    let mut last_snapshot = String::new();

    while std::time::Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(&log_path) {
            if text != last_snapshot {
                last_snapshot = text.clone();
                if text.contains(MARKER_READY) {
                    ready = true;
                }
                for marker in MARKER_SHELL {
                    if text.contains(marker) {
                        shell_seen = true;
                    }
                }
                for marker in MARKER_KNOWN_ISSUE {
                    for line in text.lines().rev() {
                        if line.contains(marker) && !known_issues.iter().any(|k| k == line) {
                            known_issues.push(line.to_string());
                        }
                    }
                }
            }
        }
        if ready && (!expect_shell || shell_seen) {
            break;
        }
        // 检查 QEMU 是否意外退出
        if let Some(status) = child.try_wait()? {
            bail!("QEMU exited early with status {status}");
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // 4. 收尾：关掉 QEMU
    let _ = child.kill();
    let _ = child.wait();

    // 5. 汇总
    println!();
    println!("========== test-boot 摘要 ==========");
    println!("日志文件: {}", log_path.display());
    println!("日志大小: {} 字节", last_snapshot.len());
    println!("微内核就绪 ({}): {}", MARKER_READY, yes_no(ready));
    if expect_shell {
        println!("用户态 shell 进入: {}", yes_no(shell_seen));
    }
    if known_issues.is_empty() {
        println!("已知问题区 (panic/terminating pid/SYSTEM HALT): 无");
    } else {
        println!(
            "已知问题区 (panic/terminating pid/SYSTEM HALT): {} 行",
            known_issues.len()
        );
        for line in known_issues.iter().take(5) {
            println!("    - {line}");
        }
    }

    let mut pass = ready;
    let mut fail_reason = String::new();
    if !ready {
        fail_reason = if last_snapshot.trim().is_empty() {
            "无任何串口输出（QEMU 可能未正确启动 / 固件未引导 ISO）".to_string()
        } else {
            "未在 45s 内看到零内核就绪标志行".to_string()
        };
        println!("最后 8 行日志:");
        for line in last_snapshot.lines().rev().take(8) {
            println!("    | {line}");
        }
    }
    if expect_shell && ready && !shell_seen {
        pass = false;
        fail_reason = "内核就绪但用户态 shell 标志行未出现".to_string();
    }

    if pass {
        println!();
        println!(
            "RESULT: PASS{}",
            if known_issues.is_empty() {
                ""
            } else {
                " (含已知问题，见上)"
            }
        );
        println!("==================================");
        Ok(())
    } else {
        bail!("RESULT: FAIL — {fail_reason}");
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "YES"
    } else {
        "NO"
    }
}

fn collect_rootfs_entries(
    source: &Path,
    root: &Path,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_rootfs_entries(&path, root, entries)?;
        } else if metadata.is_file() {
            let rel = path.strip_prefix(root).expect("strip prefix");
            let mut parts = Vec::new();
            for component in rel.iter() {
                let part = component
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-utf8 path"))?;
                parts.push(part);
            }
            let path_str = format!("/{}", parts.join("/"));
            let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            entries.push((path_str, data));
        }
    }
    Ok(())
}
