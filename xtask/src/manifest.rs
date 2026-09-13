//! 镜像产物清单：build-iso / rebuild-fast 完成后打印并落盘 target/MANIFEST.txt，
//! 便于回归对比（上一份自动滚存为 MANIFEST.prev.txt）。
use crate::hash::hash_file;
use anyhow::Result;
use std::fs;
use std::path::Path;

/// 关键产物（仓库相对路径；不存在的自动跳过）。
const ARTIFACTS: &[&str] = &[
    "target/zero-os.iso",
    "target/zero-rootfs.img",
    "target/rootfs.bundle",
    "target/rootfs-recovery.bundle",
    "target/iso/esp.img",
    "target/aarch64-unknown-none-pic/release/zero-kernel",
    "target/aarch64-unknown-uefi/debug/bootloader-uefi",
    "target/aarch64-unknown-none/release/zero-launchd",
];

pub fn write_manifest(project_root: &Path, trigger: &str) -> Result<Vec<String>> {
    let mut rows: Vec<String> = Vec::new();
    for rel in ARTIFACTS {
        let path = project_root.join(rel);
        if !path.exists() {
            continue;
        }
        let meta = fs::metadata(&path)?;
        let size = meta.len();
        let sha = hash_file(&path)?;
        rows.push(format!("{sha}  {size:>12}  {rel}"));
    }

    let manifest_path = project_root.join("target/MANIFEST.txt");
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    // 上一份清单滚存，便于 diff 回归
    let prev = project_root.join("target/MANIFEST.prev.txt");
    if manifest_path.exists() {
        let _ = fs::copy(&manifest_path, &prev);
    }

    let git_rev = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(project_root)
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8(o.stdout)
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());

    let mut text = String::new();
    text.push_str("# Zero OS build artifact manifest\n");
    text.push_str(&format!("# trigger : {trigger}\n"));
    text.push_str(&format!("# time    : {}\n", chrono_now()));
    text.push_str(&format!("# git     : {git_rev}\n"));
    text.push_str("# sha256                                  size_bytes  path\n");
    for r in &rows {
        text.push_str(r);
        text.push('\n');
    }
    fs::write(&manifest_path, &text)?;

    println!("==> 产物清单 (SHA256):");
    for r in &rows {
        println!("    {r}");
    }
    println!("    written to {}", manifest_path.display());
    Ok(rows)
}

fn chrono_now() -> String {
    // 避免 xtask 引入 chrono：用 std 取 UNIX 时间戳即可满足回归对比需求。
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs} (unix)")
}
