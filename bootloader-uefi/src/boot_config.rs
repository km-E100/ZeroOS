use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::str;
use uefi::prelude::*;
use uefi::proto::device_path::{self, DevicePath, DeviceSubType, DeviceType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

use crate::fs::FileSystem;

pub struct BootPaths {
    pub kernel_path: heapless::String<128>,
    pub rootfs_path: heapless::String<128>,
    pub config_path: heapless::String<128>,
}

impl BootPaths {
    pub fn discover(
        st: &SystemTable<Boot>,
        image: Handle,
        forced_variant: Option<BootVariant>,
    ) -> Result<(Self, LoadOverrides, BootVariant), Status> {
        let mut variant = detect_variant(st, image)?;
        if let Some(forced) = forced_variant {
            variant = forced;
        }
        let options = parse_load_options(st, image)?;

        let mut kernel = heapless::String::new();
        kernel.push_str("\\EFI\\ZEROOS\\zero-kernel").unwrap();

        let mut rootfs = heapless::String::new();
        let default_rootfs = match variant {
            BootVariant::Normal => "\\EFI\\ZEROOS\\rootfs.bundle",
            BootVariant::Recovery => "\\EFI\\ZEROOS\\rootfs-recovery.bundle",
        };
        assign_path(
            &mut rootfs,
            options.rootfs_path.as_deref().unwrap_or(default_rootfs),
        )?;

        let mut config = heapless::String::new();
        let default_config = match variant {
            BootVariant::Normal => "\\EFI\\ZEROOS\\boot.cfg",
            BootVariant::Recovery => "\\EFI\\ZEROOS\\boot-recovery.cfg",
        };
        assign_path(
            &mut config,
            options.config_path.as_deref().unwrap_or(default_config),
        )?;

        Ok((
            Self {
                kernel_path: kernel,
                rootfs_path: rootfs,
                config_path: config,
            },
            LoadOverrides {
                log_override: options.log_level,
                rootfs_ramdisk: options.rootfs_ramdisk,
            },
            variant,
        ))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BootVariant {
    Normal,
    Recovery,
}

pub fn detect_variant(st: &SystemTable<Boot>, image: Handle) -> Result<BootVariant, Status> {
    let params = OpenProtocolParams {
        handle: image,
        agent: image,
        controller: None,
    };

    let loaded = unsafe {
        st.boot_services()
            .open_protocol::<LoadedImage>(params, OpenProtocolAttributes::Exclusive)
            .map_err(|e| e.status())?
    };

    let variant = if let Some(path) = loaded.file_path() {
        if path_contains_recovery(path) {
            BootVariant::Recovery
        } else {
            BootVariant::Normal
        }
    } else {
        BootVariant::Normal
    };

    Ok(variant)
}

fn path_contains_recovery(path: &DevicePath) -> bool {
    for node in path.node_iter() {
        if node.device_type() == DeviceType::MEDIA
            && node.sub_type() == DeviceSubType::MEDIA_FILE_PATH
        {
            if let Ok(file_path) = <&device_path::media::FilePath>::try_from(node) {
                if let Some(text) = utf16_path_to_string(file_path) {
                    if text.to_ascii_lowercase().contains("recovery") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn boot_device_handle(st: &SystemTable<Boot>, image: Handle) -> Result<Handle, Status> {
    let params = OpenProtocolParams {
        handle: image,
        agent: image,
        controller: None,
    };
    let loaded = unsafe {
        st.boot_services()
            .open_protocol::<LoadedImage>(params, OpenProtocolAttributes::Exclusive)
            .map_err(|e| e.status())?
    };
    Ok(loaded.device())
}

fn utf16_path_to_string(path: &device_path::media::FilePath) -> Option<String> {
    let mut buf = Vec::new();
    for value in path.path_name().iter() {
        if value == 0 {
            break;
        }
        buf.push(value);
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&buf))
    }
}

fn assign_path(dest: &mut heapless::String<128>, value: &str) -> Result<(), Status> {
    dest.clear();
    dest.push_str(value).map_err(|_| Status::BUFFER_TOO_SMALL)
}

#[derive(Default)]
struct ParsedOptions {
    config_path: Option<String>,
    rootfs_path: Option<String>,
    log_level: Option<log::LevelFilter>,
    rootfs_ramdisk: Option<bool>,
}

pub struct LoadOverrides {
    pub log_override: Option<log::LevelFilter>,
    pub rootfs_ramdisk: Option<bool>,
}

fn parse_load_options(st: &SystemTable<Boot>, image: Handle) -> Result<ParsedOptions, Status> {
    let params = OpenProtocolParams {
        handle: image,
        agent: image,
        controller: None,
    };

    let loaded = unsafe {
        st.boot_services()
            .open_protocol::<LoadedImage>(params, OpenProtocolAttributes::Exclusive)
            .map_err(|e| e.status())?
    };

    let mut opts = ParsedOptions::default();
    if let Ok(cstr) = loaded.load_options_as_cstr16() {
        let utf8 = String::from(cstr);
        for token in utf8.split_whitespace() {
            if let Some((key, value)) = token.split_once('=') {
                match key {
                    "config" => opts.config_path = Some(value.to_string()),
                    "rootfs" => opts.rootfs_path = Some(value.to_string()),
                    "log" => opts.log_level = parse_log_level(value),
                    "ramdisk" => opts.rootfs_ramdisk = parse_bool(value),
                    _ => {}
                }
            }
        }
    }
    Ok(opts)
}

fn parse_log_level(value: &str) -> Option<log::LevelFilter> {
    match value {
        "error" => Some(log::LevelFilter::Error),
        "warn" => Some(log::LevelFilter::Warn),
        "info" => Some(log::LevelFilter::Info),
        "debug" => Some(log::LevelFilter::Debug),
        "trace" => Some(log::LevelFilter::Trace),
        _ => None,
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

#[derive(Clone)]
pub struct BootConfig {
    pub kernel_address: Option<u64>,
    pub kernel_stack: Option<u64>,
    pub rootfs_as_ramdisk: bool,
    pub log_level: log::LevelFilter,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            kernel_address: None,
            kernel_stack: None,
            rootfs_as_ramdisk: false,
            log_level: log::LevelFilter::Info,
        }
    }
}

impl BootConfig {
    pub fn load(
        fs: &mut FileSystem,
        paths: &BootPaths,
        overrides: &LoadOverrides,
    ) -> Result<Self, Status> {
        let mut cfg = match fs.read_to_vec(&paths.config_path) {
            Ok(bytes) => Self::parse(&bytes)?,
            Err(_) => {
                log_warn!("boot.cfg not found, using defaults");
                Self::default()
            }
        };

        if let Some(level) = overrides.log_override {
            cfg.log_level = level;
        }
        if let Some(ramdisk) = overrides.rootfs_ramdisk {
            cfg.rootfs_as_ramdisk = ramdisk;
        }
        Ok(cfg)
    }

    fn parse(bytes: &[u8]) -> Result<Self, Status> {
        let mut cfg = BootConfig::default();
        for line in bytes.split(|b| *b == b'\n') {
            if line.starts_with(b"#") || line.trim().is_empty() {
                continue;
            }
            if let Some((key, value)) = split_once(line, b'=') {
                match key {
                    b"kernel_address" => {
                        if let Ok(addr) = parse_hex(value) {
                            cfg.kernel_address = Some(addr);
                        }
                    }
                    b"kernel_stack" => {
                        if let Ok(addr) = parse_hex(value) {
                            cfg.kernel_stack = Some(addr);
                        }
                    }
                    b"rootfs_as_ramdisk" => {
                        cfg.rootfs_as_ramdisk = matches!(value, b"1" | b"true" | b"True");
                    }
                    b"log" => {
                        cfg.log_level = match value {
                            b"error" => log::LevelFilter::Error,
                            b"warn" => log::LevelFilter::Warn,
                            b"info" => log::LevelFilter::Info,
                            b"debug" => log::LevelFilter::Debug,
                            b"trace" => log::LevelFilter::Trace,
                            _ => log::LevelFilter::Info,
                        };
                    }
                    _ => {}
                }
            }
        }
        Ok(cfg)
    }
}

fn split_once<'a>(line: &'a [u8], needle: u8) -> Option<(&'a [u8], &'a [u8])> {
    line.iter()
        .position(|b| *b == needle)
        .map(|idx| (line[..idx].trim(), line[idx + 1..].trim()))
}

trait TrimExt {
    fn trim(&self) -> &[u8];
}

impl TrimExt for [u8] {
    fn trim(&self) -> &[u8] {
        let mut start = 0;
        let mut end = self.len();
        while start < end && self[start].is_ascii_whitespace() {
            start += 1;
        }
        while end > start && self[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        &self[start..end]
    }
}

fn parse_hex(bytes: &[u8]) -> Result<u64, Status> {
    let trimmed = str::from_utf8(bytes.trim()).map_err(|_| Status::INVALID_PARAMETER)?;
    u64::from_str_radix(trimmed.trim_start_matches("0x"), 16).map_err(|_| Status::INVALID_PARAMETER)
}
