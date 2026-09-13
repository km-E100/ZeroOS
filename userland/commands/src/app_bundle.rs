use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use walkdir::WalkDir;

use crate::{
    allocate_app_storage, current_storage_allocation, read_text_file, release_app_storage,
    StorageAllocation,
};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub identifier: String,
    pub version: String,
    pub storage: String,
    #[allow(dead_code)]
    pub description: Option<String>,
    #[allow(dead_code)]
    pub permissions: Option<Vec<String>>,
    #[allow(dead_code)]
    pub args: Option<Vec<String>>,
}

pub struct InstallOutcome {
    pub config: AppConfig,
    pub destination: PathBuf,
    pub storage: StorageAllocation,
    pub overwritten: bool,
}

pub struct UninstallOutcome {
    pub config: Option<AppConfig>,
    pub storage: Option<StorageAllocation>,
    pub removed: bool,
}

pub struct BundleInfo {
    pub path: PathBuf,
    pub config: AppConfig,
    pub storage: Option<StorageAllocation>,
}

pub fn validate_bundle(bundle_path: &Path) -> Result<AppConfig> {
    if !bundle_path.is_dir() {
        anyhow::bail!("应用目录 {} 不存在或不是目录", bundle_path.display());
    }

    let bundle_name = bundle_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("无法获取应用目录名称"))?;
    if !bundle_name.ends_with(".app") {
        anyhow::bail!(
            "目录 {} 不是合法的 .app 包（缺少 .app 后缀）",
            bundle_path.display()
        );
    }

    let main = bundle_path.join("main");
    if !main.exists() {
        anyhow::bail!("应用缺少入口文件 {}", main.display());
    }

    let config_path = bundle_path.join("config");
    if !config_path.exists() {
        anyhow::bail!("应用缺少配置文件 {}", config_path.display());
    }

    load_app_config(bundle_path)
}

pub fn load_app_config(bundle_path: &Path) -> Result<AppConfig> {
    let config_path = bundle_path.join("config");
    let content = read_text_file(&config_path)?;
    let config: AppConfig =
        toml::from_str(&content).with_context(|| format!("解析 {} 失败", config_path.display()))?;
    Ok(config)
}

pub fn install_bundle(bundle_path: &Path, apps_dir: &Path) -> Result<InstallOutcome> {
    let config = validate_bundle(bundle_path)?;
    fs::create_dir_all(apps_dir).with_context(|| format!("创建应用目录 {}", apps_dir.display()))?;

    let bundle_name = bundle_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("无法获取应用目录名称"))?;
    let dest = apps_dir.join(bundle_name);
    let overwritten = dest.exists();
    if overwritten {
        fs::remove_dir_all(&dest).with_context(|| format!("删除旧版本 {}", dest.display()))?;
    }
    copy_dir(bundle_path, &dest)?;

    let storage = allocate_app_storage(&config.identifier, &config.storage)?;

    Ok(InstallOutcome {
        config,
        destination: dest,
        storage,
        overwritten,
    })
}

pub fn uninstall_bundle(apps_dir: &Path, name: &str) -> Result<UninstallOutcome> {
    let target = apps_dir.join(format!("{name}.app"));
    if !target.exists() {
        anyhow::bail!("未找到应用 {}", target.display());
    }

    let config = load_app_config(&target).ok();
    fs::remove_dir_all(&target).with_context(|| format!("移除应用 {}", target.display()))?;

    let storage = if let Some(cfg) = &config {
        release_app_storage(&cfg.identifier)?
    } else {
        None
    };

    Ok(UninstallOutcome {
        config,
        storage,
        removed: true,
    })
}

pub fn list_bundles(apps_dir: &Path) -> Result<Vec<BundleInfo>> {
    if !apps_dir.exists() {
        return Ok(Vec::new());
    }

    let mut bundles = Vec::new();
    for entry in fs::read_dir(apps_dir)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().ends_with(".app") {
            continue;
        }
        let path = entry.path();
        match load_app_config(&path) {
            Ok(config) => {
                let storage = current_storage_allocation(&config.identifier)?;
                bundles.push(BundleInfo {
                    path,
                    config,
                    storage,
                });
            }
            Err(err) => {
                anyhow::bail!("读取 {} 失败: {}", entry.path().display(), err);
            }
        }
    }
    bundles.sort_by(|a, b| a.config.name.cmp(&b.config.name));
    Ok(bundles)
}

fn copy_dir(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    for entry in WalkDir::new(src) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(src).context("strip prefix")?;
        let target = dest.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target).with_context(|| {
                format!("复制 {} -> {}", entry.path().display(), target.display())
            })?;
        }
    }
    Ok(())
}
