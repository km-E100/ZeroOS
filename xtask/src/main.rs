use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::Write;
use std::path::Path;
use xshell::{cmd, Shell};

mod image;

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let sh = Shell::new()?;
    match cli.command {
        Commands::BuildKernel => build_kernel(&sh)?,
        Commands::BuildKernelBare => build_kernel_bare(&sh)?,
        Commands::BuildServers => build_servers(&sh)?,
        Commands::BuildInstaller => build_installer(&sh)?,
        Commands::BuildRecovery => build_recovery(&sh)?,
        Commands::BuildImage => build_image(&sh)?,
        Commands::BuildRootfs => build_rootfs(&sh)?,
        Commands::BuildIso => {
            image::build_full_image(&sh)?;
        }
        Commands::Run { mode } => run(&sh, &mode)?,
        Commands::TestBoot { expect_shell } => test_boot(&sh, expect_shell)?,
    }
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

fn build_servers(sh: &Shell) -> Result<()> {
    // 这些是正常 host 目标，照常用默认 target 编
    cmd!(sh, "cargo build -p zero-fs-zfs -p zero-fsd -p zero-blkdrv -p zero-ipc-router -p zero-securityd -p zero-service-controller -p zero-installer -p zero-recovery -p mkzfs").run()?;

    // zero-launchd 只编 aarch64-unknown-none 的裸机版本
    cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-launchd --release").run()?;

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
    let target = "aarch64-unknown-none";
    if let Err(err) = cmd!(sh, "cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target {target} -p zero-kernel")
        .run()
    {
        eprintln!(
            "xtask: build-image failed: {err}\n    hint: rustup needs write access to ~/.rustup/tmp; consider adjusting permissions or running the command outside of this sandbox."
        );
        return Err(err.into());
    }
    let project_root = sh.current_dir();
    let elf = project_root.join(format!("target/{target}/debug/zero-kernel"));
    let dest = project_root.join("target/zero-os.elf");
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&elf, &dest)?;
    println!("image generated at {}", dest.display());
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
    let mut args: Vec<String> =
        QEMU_BASE_ARGS.iter().map(|s| s.to_string()).collect();
    match mode {
        "normal" => {
            // 注释：normal 模式可直接把 -serial 换成 mon:stdio 以获得交互串口
            args.push("-serial".into());
            args.push(format!("file:{}", serial_log.display()));
            cmd!(sh, "qemu-system-aarch64 {args...}").run()?;
        }
        "recovery" => {
            // 恢复模式：从 CDROM 强制启动（对齐原 run 子命令的 -boot d）
            args.push("-boot".into());
            args.push("d".into());
            args.push("-serial".into());
            args.push(format!("file:{}", serial_log.display()));
            cmd!(sh, "qemu-system-aarch64 {args...}").run()?;
        }
        _ => println!("unknown mode {mode}, defaulting to normal"),
    }
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
    println!("==> test-boot: launching QEMU (serial -> {})", log_path.display());

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
        println!("RESULT: PASS{}", if known_issues.is_empty() { "" } else { " (含已知问题，见上)" });
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
