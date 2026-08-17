use core::sync::atomic::{AtomicBool, Ordering};

use crate::rootfs;
use heapless::{String, Vec};
use spin::Mutex;
use userlib;

pub(crate) const MAX_APPS: usize = 8;
pub(crate) const APP_NAME_MAX: usize = 24;
pub(crate) const APP_PATH_MAX: usize = 96;
pub(crate) const APP_VERSION_MAX: usize = 16;
pub(crate) const APP_STORAGE_MAX: usize = 64;
pub(crate) const APP_LINE_MAX: usize =
    APP_NAME_MAX + APP_PATH_MAX + APP_VERSION_MAX + APP_STORAGE_MAX + 8;
pub(crate) const APP_DB_LBA: u64 = 640;
const APP_DB_SECTOR_SIZE: usize = 512;
const APP_DB_SECTORS: usize = 4;
const APP_DB_CAPACITY: usize = APP_DB_SECTOR_SIZE * APP_DB_SECTORS;

pub(crate) struct AppRegistry {
    apps: Mutex<Vec<AppRecord, MAX_APPS>>,
    loaded: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct AppRecord {
    pub(crate) name: String<APP_NAME_MAX>,
    pub(crate) binary: String<APP_PATH_MAX>,
    pub(crate) version: String<APP_VERSION_MAX>,
    pub(crate) storage: String<APP_STORAGE_MAX>,
    pub(crate) keep_alive: bool,
}

pub(crate) enum InstallOutcome {
    Created,
    Updated,
}

impl AppRegistry {
    pub const fn new() -> Self {
        Self {
            apps: Mutex::new(Vec::new()),
            loaded: AtomicBool::new(false),
        }
    }

    pub fn ensure_loaded(&self) {
        if self.loaded.load(Ordering::SeqCst) {
            return;
        }
        let _ = self.load_from_disk();
        if self.apps.lock().is_empty() {
            self.discover_rootfs_apps();
            let _ = self.persist();
        }
        self.loaded.store(true, Ordering::SeqCst);
    }

    pub fn install(
        &self,
        name: &str,
        binary: &str,
        version: &str,
        storage: &str,
        keep_alive: bool,
        force: bool,
    ) -> Result<InstallOutcome, &'static str> {
        self.ensure_loaded();
        if name.len() > APP_NAME_MAX
            || binary.len() > APP_PATH_MAX
            || version.len() > APP_VERSION_MAX
            || storage.len() > APP_STORAGE_MAX
        {
            return Err("name or path too long");
        }
        let mut table = self.apps.lock();
        if let Some(index) = table.iter().position(|app| app.name.as_str() == name) {
            if !force {
                return Err("application already exists (use --force)");
            }
            let record = AppRecord::new(name, binary, version, storage, keep_alive)
                .ok_or("invalid application record")?;
            table[index] = record;
            drop(table);
            self.persist().map_err(|_| "failed to persist apps")?;
            return Ok(InstallOutcome::Updated);
        }
        if table.len() == table.capacity() {
            return Err("registry full");
        }
        let record = AppRecord::new(name, binary, version, storage, keep_alive)
            .ok_or("invalid application record")?;
        table.push(record).map_err(|_| "registry full")?;
        drop(table);
        self.persist().map_err(|_| "failed to persist apps")?;
        Ok(InstallOutcome::Created)
    }

    pub fn remove(&self, name: &str) -> bool {
        self.ensure_loaded();
        let mut table = self.apps.lock();
        if let Some(index) = table.iter().position(|app| app.name.as_str() == name) {
            table.swap_remove(index);
            drop(table);
            let _ = self.persist();
            true
        } else {
            false
        }
    }

    pub fn find(&self, name: &str) -> Option<AppRecord> {
        self.ensure_loaded();
        let table = self.apps.lock();
        table.iter().find(|app| app.name.as_str() == name).cloned()
    }

    pub fn snapshot(&self) -> Vec<AppRecord, MAX_APPS> {
        self.ensure_loaded();
        let table = self.apps.lock();
        let mut out = Vec::new();
        for app in table.iter() {
            let _ = out.push(app.clone());
        }
        out
    }

    fn load_from_disk(&self) -> Result<(), ()> {
        let mut buffer = [0u8; APP_DB_CAPACITY];
        if userlib::block_read(APP_DB_LBA, &mut buffer).is_err() {
            return Err(());
        }
        let used = match buffer.iter().rposition(|byte| *byte != 0) {
            Some(pos) => pos + 1,
            None => return Ok(()),
        };
        let blob = &buffer[..used];
        let text = core::str::from_utf8(blob).map_err(|_| ())?;
        let mut table = self.apps.lock();
        table.clear();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.split('|');
            let (Some(name), Some(binary)) = (parts.next(), parts.next()) else {
                continue;
            };
            let version = parts.next().unwrap_or("1.0.0");
            let storage = parts.next().unwrap_or("/var/appdata");
            let keep_alive = parts.next().map(|flag| flag == "1").unwrap_or(false);
            if let Some(record) = AppRecord::new(name, binary, version, storage, keep_alive) {
                let _ = table.push(record);
            }
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), ()> {
        let table = self.apps.lock();
        let mut buffer = [0u8; APP_DB_CAPACITY];
        let mut offset = 0;
        for app in table.iter() {
            let line = {
                let mut text = String::<{ APP_LINE_MAX }>::new();
                let _ = text.push_str(app.name.as_str());
                let _ = text.push('|');
                let _ = text.push_str(app.binary.as_str());
                let _ = text.push('|');
                let _ = text.push_str(app.version.as_str());
                let _ = text.push('|');
                let _ = text.push_str(app.storage.as_str());
                let _ = text.push('|');
                let _ = text.push_str(if app.keep_alive { "1" } else { "0" });
                let _ = text.push('\n');
                text
            };
            let bytes = line.as_bytes();
            if offset + bytes.len() > buffer.len() {
                break;
            }
            buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
            offset += bytes.len();
        }
        userlib::block_write(APP_DB_LBA, &buffer).map_err(|_| ())
    }

    fn discover_rootfs_apps(&self) {
        let Some(entries) = rootfs::entries() else {
            return;
        };
        let mut table = self.apps.lock();
        if !table.is_empty() {
            return;
        }
        for entry in entries {
            let path = unsafe { entry.path() };
            let Some((name, binary)) = extract_rootfs_app(path) else {
                continue;
            };
            if table.iter().any(|app| app.name.as_str() == name) {
                continue;
            }
            let Ok(storage) = build_storage_path(name, None) else {
                continue;
            };
            if let Some(record) = AppRecord::new(name, binary, "1.0.0", storage.as_str(), false) {
                let _ = table.push(record);
                if table.len() == table.capacity() {
                    break;
                }
            }
        }
    }
}

impl AppRecord {
    fn new(
        name: &str,
        binary: &str,
        version: &str,
        storage: &str,
        keep_alive: bool,
    ) -> Option<Self> {
        if name.is_empty() || binary.is_empty() || version.is_empty() || storage.is_empty() {
            return None;
        }
        let mut name_buf = String::<APP_NAME_MAX>::new();
        name_buf.push_str(name).ok()?;
        let mut bin_buf = String::<APP_PATH_MAX>::new();
        bin_buf.push_str(binary).ok()?;
        let mut ver_buf = String::<APP_VERSION_MAX>::new();
        ver_buf.push_str(version).ok()?;
        let mut storage_buf = String::<APP_STORAGE_MAX>::new();
        storage_buf.push_str(storage).ok()?;
        Some(Self {
            name: name_buf,
            binary: bin_buf,
            version: ver_buf,
            storage: storage_buf,
            keep_alive,
        })
    }
}

pub(crate) static APP_REGISTRY: AppRegistry = AppRegistry::new();

pub(crate) fn build_storage_path(
    name: &str,
    override_path: Option<&str>,
) -> Result<String<APP_STORAGE_MAX>, &'static str> {
    let mut storage = String::<APP_STORAGE_MAX>::new();
    if let Some(path) = override_path {
        if path.len() > APP_STORAGE_MAX {
            return Err("Storage path too long.");
        }
        storage
            .push_str(path)
            .map_err(|_| "Storage path too long.")?;
    } else {
        storage
            .push_str("/var/appdata/")
            .map_err(|_| "Storage path too long.")?;
        storage
            .push_str(name)
            .map_err(|_| "Storage path too long.")?;
    }
    Ok(storage)
}

pub(crate) fn binary_exists(path: &str) -> bool {
    if let Some(entries) = rootfs::entries() {
        for entry in entries {
            let entry_path = unsafe { entry.path() };
            if entry_path == path {
                return true;
            }
        }
    }
    false
}

pub(crate) fn encode_app_payload(
    buffer: &mut [u8; 128],
    name: &str,
    binary: &str,
    flags: u8,
) -> Result<(), &'static str> {
    buffer.fill(0);
    let mut offset = 0;
    for field in [name, binary] {
        let bytes = field.as_bytes();
        if bytes.is_empty() {
            return Err("field cannot be empty");
        }
        if offset + bytes.len() + 1 > buffer.len() {
            return Err("payload too large");
        }
        buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
        buffer[offset] = 0;
        offset += 1;
    }
    if offset + 2 > buffer.len() {
        return Err("payload too large");
    }
    buffer[offset] = flags;
    buffer[offset + 1] = 0;
    Ok(())
}

fn extract_rootfs_app(path: &str) -> Option<(&str, &str)> {
    if !path.starts_with("/Applications/") {
        return None;
    }
    let rest = &path["/Applications/".len()..];
    let mut segments = rest.split('/');
    let name = segments.next()?.trim();
    if name.is_empty() {
        return None;
    }
    let last_segment = segments.clone().last().unwrap_or("");
    if last_segment.is_empty() {
        return None;
    }
    Some((name, path))
}
