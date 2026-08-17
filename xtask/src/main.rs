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

fn run(sh: &Shell, mode: &str) -> Result<()> {
    match mode {
        "normal" => cmd!(
            sh,
            "qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 1024"
        )
        .run()?,
        "recovery" => cmd!(
            sh,
            "qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 1024 -boot d"
        )
        .run()?,
        _ => println!("unknown mode {mode}, defaulting to normal"),
    }
    Ok(())
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
