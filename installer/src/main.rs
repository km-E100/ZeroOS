use anyhow::{anyhow, Context, Result};
use mkzfs::ZfsImageBuilder;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    println!("Zero OS 安装程序");
    let config = collect_user_input();
    let bundle_path = locate_rootfs_bundle();
    let builder = ZfsImageBuilder::new(64 * 1024 * 1024)?;
    builder.format()?;
    if let Some(bundle) = bundle_path {
        let data = fs::read(&bundle).context("reading rootfs bundle")?;
        builder.import_bundle(&data)?;
    } else {
        println!("warning: rootfs bundle not found, installing empty volume");
    }
    builder.ensure_system_dirs()?;
    write_admin_account(&config, &builder)?;
    copy_system_components(&builder)?;
    install_default_apps(&config, &builder)?;
    builder.flush_to(&config.target)?;
    println!("安装完成！");
    Ok(())
}

fn collect_user_input() -> InstallConfig {
    InstallConfig {
        target: PathBuf::from("target/zero-rootfs.img"),
        admin_user: "admin".into(),
        default_apps_dir: "/Applications".into(),
    }
}

fn write_admin_account(config: &InstallConfig, builder: &ZfsImageBuilder) -> Result<()> {
    let hash = format!("$zero$dummy${}", config.admin_user);
    builder.write_passwd(&config.admin_user, &hash)?;
    let shadow_entry = format!("{}:{}:::::::\n", config.admin_user, hash);
    builder.write_file("/etc/shadow", shadow_entry.as_bytes())?;
    Ok(())
}

fn copy_system_components(builder: &ZfsImageBuilder) -> Result<()> {
    let binaries: &[(&str, &str)] = &[
        ("zero-kernel", "/System/Core/zero-kernel"),
        ("zero-launchd", "/System/Core/zero-launchd"),
        ("zero-fs-zfs", "/System/Core/zero-fs-zfs"),
        ("zero-fsd", "/System/Core/zero-fsd"),
        ("zero-blkdrv", "/System/Core/zero-blkdrv"),
        ("zero-ipc-router", "/System/Core/zero-ipc-router"),
        ("zero-securityd", "/System/Core/zero-securityd"),
        (
            "zero-service-controller",
            "/System/Core/zero-service-controller",
        ),
    ];

    for (binary, dest) in binaries {
        if let Some(host_path) = resolve_host_binary(binary) {
            let data =
                fs::read(&host_path).with_context(|| format!("reading {}", host_path.display()))?;
            builder.write_file(dest, &data)?;
        } else {
            println!(
                "warning: component {} not found (expected under target/*/{})",
                binary, binary
            );
        }
    }

    // Basic launch manifest stub
    let launchd_manifest = br#"[[services]]
name = "launchd"
binary = "/System/Core/zero-launchd"
"#;
    builder.write_file("/System/LaunchDaemons/launchd.toml", launchd_manifest)?;

    Ok(())
}

fn resolve_host_binary(name: &str) -> Option<PathBuf> {
    let candidates = [
        format!("target/debug/{name}"),
        format!("target/release/{name}"),
        format!("target/aarch64-unknown-none/debug/{name}"),
        format!("target/aarch64-unknown-none/release/{name}"),
    ];

    for candidate in candidates.iter() {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    None
}

fn install_default_apps(config: &InstallConfig, builder: &ZfsImageBuilder) -> Result<()> {
    println!("将系统基础应用安装到 {}", config.default_apps_dir);
    let apps_dir = Path::new("installer/Applications");
    if apps_dir.exists() {
        let mut entries = Vec::new();
        collect_entries(apps_dir, apps_dir, &mut entries)?;
        for (rel, data) in entries {
            let full = format!(
                "{}/{}",
                config.default_apps_dir,
                rel.trim_start_matches('/')
            );
            builder.write_file(&full, &data)?;
        }
    }
    Ok(())
}

fn locate_rootfs_bundle() -> Option<PathBuf> {
    let path = Path::new("target/rootfs.bundle");
    if path.exists() {
        Some(path.to_path_buf())
    } else {
        None
    }
}

fn collect_entries(source: &Path, root: &Path, entries: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_entries(&path, root, entries)?;
        } else if metadata.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| anyhow!("non-utf8 path"))?;
            let mut parts = Vec::new();
            for component in rel.iter() {
                let part = component.to_str().ok_or_else(|| anyhow!("non-utf8 path"))?;
                parts.push(part);
            }
            let dest = format!("/{}", parts.join("/"));
            let data = fs::read(&path)?;
            entries.push((dest, data));
        }
    }
    Ok(())
}

struct InstallConfig {
    target: PathBuf,
    admin_user: String,
    default_apps_dir: String,
}
