//! 递归目录遍历 + 源码指纹快照，供 rebuild-fast 增量判断使用。
use crate::hash::hash_file;
use anyhow::Result;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// relpath(以仓库根为基准) -> sha256
pub type Snapshot = BTreeMap<String, String>;

/// 需要在遍历时跳过的目录名（构建产物 / VCS / 垃圾文件）。
const SKIP_DIRS: &[&str] = &["target", ".git", ".github", "node_modules"];
const SKIP_FILES: &[&str] = &[".DS_Store"];

pub fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk_inner(root, root, &mut out)?;
    Ok(out)
}

fn walk_inner(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()), // 目录不存在：视为空集
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();
        if entry.file_type()?.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) || name.starts_with('.') {
                continue;
            }
            walk_inner(root, &path, out)?;
        } else {
            if SKIP_FILES.contains(&name.as_str()) {
                continue;
            }
            out.push(path);
        }
    }
    Ok(())
}

/// 对一组根目录建立内容指纹快照。
pub fn snapshot_dirs(project_root: &Path, dirs: &[&str]) -> Result<Snapshot> {
    let mut snap = Snapshot::new();
    for d in dirs {
        let abs = project_root.join(d);
        for f in walk_files(&abs)? {
            let rel = f
                .strip_prefix(project_root)
                .expect("strip prefix")
                .to_string_lossy()
                .to_string();
            let h = hash_file(&f)?;
            snap.insert(rel, h);
        }
    }
    Ok(snap)
}

/// 计算两个快照的差异摘要：(新增+修改, 删除) 数量与样例。
pub fn diff_summary(old: &Snapshot, new: &Snapshot) -> (Vec<String>, Vec<String>) {
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    for (k, v) in old {
        match new.get(k) {
            Some(nv) if nv == v => {}
            _ => removed.push(k.clone()),
        }
    }
    for (k, v) in new {
        match old.get(k) {
            Some(ov) if ov == v => {}
            _ => changed.push(k.clone()),
        }
    }
    (changed, removed)
}

pub fn load_state(path: &Path) -> Option<Snapshot> {
    let text = fs::read_to_string(path).ok()?;
    let mut map = Snapshot::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, ' ');
        let h = it.next()?;
        let p = it.next()?.to_string();
        map.insert(p, h.to_string());
    }
    Some(map)
}

pub fn save_state(path: &Path, snap: &Snapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut text = String::from("# rebuild-fast fingerprint state (sha256 per file)\n");
    for (k, v) in snap {
        text.push_str(&format!("{v} {k}\n"));
    }
    fs::write(path, text)?;
    Ok(())
}
