pub mod app_bundle;
pub mod crypto;
pub mod pkg;

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub fn read_text_file<P: AsRef<Path>>(path: P) -> Result<String> {
    let mut buf = String::new();
    File::open(path.as_ref())
        .with_context(|| format!("open {}", path.as_ref().display()))?
        .read_to_string(&mut buf)?;
    Ok(buf)
}

pub fn write_text_file<P: AsRef<Path>>(path: P, content: &str) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path.as_ref())
        .with_context(|| format!("create {}", path.as_ref().display()))?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

pub fn ensure_applications_dir() -> Result<PathBuf> {
    let default = dirs_next::home_dir()
        .map(|mut p| {
            p.push("Applications");
            p
        })
        .unwrap_or_else(|| PathBuf::from("/Applications"));
    std::fs::create_dir_all(&default)?;
    Ok(default)
}

pub struct StorageAllocation {
    pub requested: String,
    pub allocated: String,
    pub path: PathBuf,
}

#[derive(Default, Serialize, Deserialize)]
struct StorageRegistry {
    entries: BTreeMap<String, StorageRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StorageRecord {
    requested: String,
    allocated: String,
}

pub fn allocate_app_storage(identifier: &str, requested: &str) -> Result<StorageAllocation> {
    let mut registry = load_registry()?;
    if let Some(record) = registry.entries.get(identifier) {
        let path = storage_root()?.join(&record.allocated);
        fs::create_dir_all(&path)?;
        return Ok(StorageAllocation {
            requested: record.requested.clone(),
            allocated: record.allocated.clone(),
            path,
        });
    }

    let requested_display = canonical_requested(requested);
    let sanitized = sanitize_storage_name(&requested_display);
    let mut allocated = sanitized.clone();
    let mut conflict_index = 0usize;

    while registry
        .entries
        .values()
        .any(|record| record.allocated == allocated)
    {
        conflict_index += 1;
        allocated = format!(".{}__{:04}", sanitized, conflict_index);
    }

    let entry = StorageRecord {
        requested: requested_display.clone(),
        allocated: allocated.clone(),
    };
    registry
        .entries
        .insert(identifier.to_owned(), entry.clone());
    save_registry(&registry)?;

    let path = storage_root()?.join(&allocated);
    fs::create_dir_all(&path)?;

    Ok(StorageAllocation {
        requested: entry.requested,
        allocated: entry.allocated,
        path,
    })
}

pub fn release_app_storage(identifier: &str) -> Result<Option<StorageAllocation>> {
    let mut registry = load_registry()?;
    let Some(record) = registry.entries.remove(identifier) else {
        return Ok(None);
    };
    save_registry(&registry)?;
    let path = storage_root()?.join(&record.allocated);
    Ok(Some(StorageAllocation {
        requested: record.requested,
        allocated: record.allocated,
        path,
    }))
}

pub fn current_storage_allocation(identifier: &str) -> Result<Option<StorageAllocation>> {
    let registry = load_registry()?;
    let Some(record) = registry.entries.get(identifier) else {
        return Ok(None);
    };
    let path = storage_root()?.join(&record.allocated);
    Ok(Some(StorageAllocation {
        requested: record.requested.clone(),
        allocated: record.allocated.clone(),
        path,
    }))
}

fn zero_state_dir() -> Result<PathBuf> {
    let home = dirs_next::home_dir().ok_or_else(|| anyhow::anyhow!("无法定位用户主目录"))?;
    let dir = home.join(".zero");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn storage_root() -> Result<PathBuf> {
    let root = zero_state_dir()?.join("app-data");
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn registry_path() -> Result<PathBuf> {
    Ok(zero_state_dir()?.join("app-storage.json"))
}

fn load_registry() -> Result<StorageRegistry> {
    let path = registry_path()?;
    if !path.exists() {
        return Ok(StorageRegistry::default());
    }
    let content = read_text_file(&path)?;
    let registry: StorageRegistry =
        serde_json::from_str(&content).with_context(|| format!("解析 {} 失败", path.display()))?;
    Ok(registry)
}

fn save_registry(registry: &StorageRegistry) -> Result<()> {
    let path = registry_path()?;
    let content = serde_json::to_string_pretty(registry)?;
    write_text_file(path, &content)
}

fn canonical_requested(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        "appdata".to_string()
    } else {
        trimmed.to_string()
    }
}

fn sanitize_storage_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "appdata".to_string();
    }
    let mut result = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            result.push(ch);
        } else {
            result.push('_');
        }
    }
    result
}
