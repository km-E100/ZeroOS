use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::app_bundle::{self, InstallOutcome};
use crate::crypto;

const MAGIC: &[u8] = b"ZEROPKG1\n";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub format_version: u32,
    pub bundle_name: String,
    pub name: String,
    pub identifier: String,
    pub version: String,
    pub storage: String,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub args: Option<Vec<String>>,
    pub bundle_hash: String,
    pub origin: Option<String>,
    pub signature: Option<String>,
}

pub struct PackageEntry {
    pub manifest: PackageManifest,
    pub path: PathBuf,
}

pub fn pack(
    app_path: &Path,
    output: Option<&Path>,
    origin: Option<&str>,
    sign_key_path: Option<&Path>,
) -> Result<(PathBuf, PackageManifest)> {
    let config = app_bundle::validate_bundle(app_path)?;
    let bundle_name = app_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("无法获取应用目录名称"))?
        .to_string();

    let hash = hash_directory(app_path)?;

    let mut manifest = PackageManifest {
        format_version: 2,
        bundle_name: bundle_name.clone(),
        name: config.name.clone(),
        identifier: config.identifier.clone(),
        version: config.version.clone(),
        storage: config.storage.clone(),
        description: config.description.clone(),
        permissions: config.permissions.clone(),
        args: config.args.clone(),
        bundle_hash: hash,
        origin: origin.map(|s| s.to_string()),
        signature: None,
    };

    if let Some(sign_key_path) = sign_key_path {
        let origin = manifest
            .origin
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("签名需要指定 --origin"))?;
        let key = fs::read_to_string(sign_key_path)
            .with_context(|| format!("读取签名密钥 {} 失败", sign_key_path.display()))?;
        let signature = compute_signature(
            key.trim(),
            origin,
            &manifest.identifier,
            &manifest.version,
            &manifest.bundle_hash,
        )?;
        manifest.signature = Some(signature);
    }

    let output_path = determine_output_path(&manifest, output)?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    write_package(&manifest, app_path, &output_path)?;
    Ok((output_path, manifest))
}

pub fn inspect(package_path: &Path) -> Result<PackageManifest> {
    let mut file = File::open(package_path)
        .with_context(|| format!("打开包 {} 失败", package_path.display()))?;
    let (manifest, _) = read_header(&mut file)?;
    Ok(manifest)
}

pub struct InstallPlan {
    pub manifest: PackageManifest,
    pub warnings: Vec<String>,
    bundle_dir: PathBuf,
    temp_root: PathBuf,
}

impl InstallPlan {
    pub fn commit(mut self, apps_dir: &Path) -> Result<InstallOutcome> {
        let bundle_dir = self.bundle_dir.clone();
        let temp_root = self.temp_root.clone();
        self.bundle_dir = PathBuf::new();
        self.temp_root = PathBuf::new();
        let result = app_bundle::install_bundle(&bundle_dir, apps_dir);
        let _ = fs::remove_dir_all(&temp_root);
        result
    }
}

impl Drop for InstallPlan {
    fn drop(&mut self) {
        if !self.temp_root.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.temp_root);
        }
    }
}

pub fn prepare_install(package_path: &Path) -> Result<InstallPlan> {
    let mut file = File::open(package_path)
        .with_context(|| format!("打开包 {} 失败", package_path.display()))?;
    let (manifest, file_count) = read_header(&mut file)?;

    let temp_root = create_temp_dir()?;
    extract_files(&mut file, &manifest, file_count, &temp_root)?;

    let bundle_dir = temp_root.join(&manifest.bundle_name);
    if !bundle_dir.exists() {
        anyhow::bail!(
            "包 {} 不包含目录 {}",
            package_path.display(),
            manifest.bundle_name
        );
    }

    let mut warnings = Vec::new();
    match hash_directory(&bundle_dir) {
        Ok(extracted_hash) => {
            if extracted_hash != manifest.bundle_hash {
                warnings.push(format!(
                    "哈希校验不一致：manifest={} 实际={}",
                    manifest.bundle_hash, extracted_hash
                ));
            }
        }
        Err(err) => warnings.push(format!("计算包内容哈希失败: {err}")),
    }

    warnings.extend(trust_warnings(&manifest)?);

    Ok(InstallPlan {
        manifest,
        warnings,
        bundle_dir,
        temp_root,
    })
}

pub fn publish(package_path: &Path) -> Result<PathBuf> {
    let target_dir = repository_packages_dir()?;
    fs::create_dir_all(&target_dir)?;
    let file_name = package_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("无法获取包文件名"))?;
    let target = target_dir.join(file_name);
    fs::copy(package_path, &target)
        .with_context(|| format!("拷贝包到仓库 {} 失败", target.display()))?;
    Ok(target)
}

pub fn repository_root() -> Result<PathBuf> {
    let home = dirs_next::home_dir().ok_or_else(|| anyhow::anyhow!("无法定位用户主目录"))?;
    let root = home.join(".zero").join("pkg");
    fs::create_dir_all(&root)?;
    Ok(root)
}

pub fn repository_packages_dir() -> Result<PathBuf> {
    let dir = repository_root()?.join("repo");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn repository_packages() -> Result<Vec<PackageEntry>> {
    let dir = repository_packages_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("zpkg"))
            .unwrap_or(false)
        {
            match inspect(&path) {
                Ok(manifest) => entries.push(PackageEntry { manifest, path }),
                Err(err) => {
                    anyhow::bail!("解析仓库包 {} 失败: {}", path.display(), err);
                }
            }
        }
    }
    entries.sort_by(|a, b| {
        let aid = &a.manifest.identifier;
        let bid = &b.manifest.identifier;
        aid.cmp(bid)
            .then(a.manifest.version.cmp(&b.manifest.version))
    });
    Ok(entries)
}

pub fn find_package(name: &str) -> Result<Option<PackageEntry>> {
    let packages = repository_packages()?;
    Ok(packages.into_iter().find(|entry| {
        entry.manifest.identifier == name
            || entry.manifest.bundle_name == name
            || entry.manifest.name == name
    }))
}

pub fn trust_warnings(manifest: &PackageManifest) -> Result<Vec<String>> {
    collect_trust_warnings(manifest)
}

fn write_package(manifest: &PackageManifest, app_path: &Path, output_path: &Path) -> Result<()> {
    let mut file = File::create(output_path)
        .with_context(|| format!("创建包文件 {} 失败", output_path.display()))?;
    file.write_all(MAGIC)?;
    let manifest_bytes = toml::to_string(manifest)?;
    let manifest_bytes = manifest_bytes.as_bytes();
    let len = manifest_bytes.len() as u32;
    file.write_all(&len.to_le_bytes())?;
    file.write_all(manifest_bytes)?;

    let files = collect_files(app_path)?;
    file.write_all(&(files.len() as u32).to_le_bytes())?;

    for rel in files {
        let path_str = rel.to_string_lossy().to_string();
        let path_bytes = path_str.as_bytes();
        file.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
        file.write_all(path_bytes)?;

        let source = app_path.join(&rel);
        let size = fs::metadata(&source)?.len();
        file.write_all(&size.to_le_bytes())?;

        let mut reader = File::open(&source)?;
        copy_stream(&mut reader, &mut file, size)?;
    }

    Ok(())
}

fn read_header(file: &mut File) -> Result<(PackageManifest, u32)> {
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; MAGIC.len()];
    file.read_exact(&mut magic)?;
    if magic != MAGIC {
        anyhow::bail!("不是有效的 ZeroPkg 文件");
    }
    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf)?;
    let manifest_len = u32::from_le_bytes(len_buf) as usize;
    let mut manifest_buf = vec![0u8; manifest_len];
    file.read_exact(&mut manifest_buf)?;
    let manifest_str = String::from_utf8(manifest_buf)?;
    let manifest: PackageManifest = toml::from_str(&manifest_str)?;
    file.read_exact(&mut len_buf)?;
    let file_count = u32::from_le_bytes(len_buf);
    Ok((manifest, file_count))
}

fn extract_files(
    file: &mut File,
    manifest: &PackageManifest,
    file_count: u32,
    temp_root: &Path,
) -> Result<()> {
    for _ in 0..file_count {
        let mut len_buf = [0u8; 4];
        file.read_exact(&mut len_buf)?;
        let path_len = u32::from_le_bytes(len_buf) as usize;
        let mut path_buf = vec![0u8; path_len];
        file.read_exact(&mut path_buf)?;
        let path_str = String::from_utf8(path_buf)?;
        let rel_path = Path::new(&path_str);
        let dest = temp_root.join(&manifest.bundle_name).join(rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut size_buf = [0u8; 8];
        file.read_exact(&mut size_buf)?;
        let size = u64::from_le_bytes(size_buf);
        let mut writer = File::create(&dest)?;
        copy_stream(file, &mut writer, size)?;
    }
    Ok(())
}

fn copy_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
) -> Result<()> {
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let chunk = std::cmp::min(remaining, buffer.len() as u64);
        let n = reader.read(&mut buffer[..chunk as usize])?;
        if n == 0 {
            anyhow::bail!("包内容过早结束");
        }
        writer.write_all(&buffer[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

fn collect_files(app_path: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(app_path).sort_by_file_name() {
        let entry = entry?;
        if entry.file_type().is_dir() {
            continue;
        }
        let rel = entry.path().strip_prefix(app_path)?;
        files.push(rel.to_path_buf());
    }
    files.sort();
    Ok(files)
}

fn hash_directory(dir: &Path) -> Result<String> {
    let files = collect_files(dir)?;
    let mut canonical = Vec::new();
    for rel in files.iter() {
        let path_str = rel.to_string_lossy();
        let path = path_str.as_bytes();
        canonical.extend_from_slice(&(path.len() as u32).to_le_bytes());
        canonical.extend_from_slice(path);
        let file = dir.join(rel);
        let data = fs::read(&file)?;
        canonical.extend_from_slice(&(data.len() as u64).to_le_bytes());
        canonical.extend_from_slice(&data);
    }
    Ok(hex_encode(&crypto::sha256(&canonical)))
}

fn hex_encode(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}
fn hex_decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    let b = text.trim().as_bytes();
    if b.len() != N * 2 {
        anyhow::bail!("hex length mismatch: expected {}", N * 2);
    }
    let mut out = [0u8; N];
    fn v(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    for i in 0..N {
        out[i] = (v(b[i * 2]).ok_or_else(|| anyhow::anyhow!("bad hex"))? << 4)
            | v(b[i * 2 + 1]).ok_or_else(|| anyhow::anyhow!("bad hex"))?;
    }
    Ok(out)
}

fn signature_message_hash(
    origin: &str,
    identifier: &str,
    version: &str,
    bundle_hash: &str,
) -> [u8; 32] {
    let mut m = Vec::new();
    m.extend_from_slice(b"zero-pkg-v2\0");
    for v in [origin, identifier, version, bundle_hash] {
        m.extend_from_slice(v.as_bytes());
        m.push(0);
    }
    crypto::sha256(&m)
}

fn determine_output_path(manifest: &PackageManifest, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    let mut base = manifest.bundle_name.trim_end_matches(".app").to_string();
    if base.is_empty() {
        base = manifest.identifier.replace('.', "_");
    }
    let file_name = format!("{}-{}.zpkg", base, manifest.version);
    let cwd = std::env::current_dir()?;
    Ok(cwd.join(file_name))
}

fn create_temp_dir() -> Result<PathBuf> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let pid = std::process::id();
    let temp_dir = std::env::temp_dir().join(format!("zero_pkg_{}_{}", pid, ts));
    fs::create_dir_all(&temp_dir)?;
    Ok(temp_dir)
}

fn collect_trust_warnings(manifest: &PackageManifest) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let trusted = load_trusted_origins()?;

    match manifest.origin.as_deref() {
        Some(origin) => {
            if !trusted.contains(origin) {
                warnings.push(format!(
                    "来源 {} 未列入 ~/.zero/pkg/trust/origins.txt",
                    origin
                ));
            }
            match load_trusted_key(origin)? {
                Some(key) => match manifest.signature.as_ref() {
                    Some(signature) => {
                        if signature.len() != 128 {
                            warnings
                                .push(format!("签名长度异常（origin={}，expect 128 hex）", origin));
                        }
                        if !verify_signature_hex(
                            key.trim(),
                            signature,
                            origin,
                            &manifest.identifier,
                            &manifest.version,
                            &manifest.bundle_hash,
                        ) {
                            warnings.push(format!("签名校验失败（origin={}）", origin));
                        }
                    }
                    None => warnings.push(format!("来源 {} 缺少签名字段", origin)),
                },
                None => warnings.push(format!(
                    "未找到来源 {} 对应的密钥文件 ~/.zero/pkg/trust/{}.key",
                    origin, origin
                )),
            }
        }
        None => {
            warnings.push("包未声明来源 origin".to_string());
            if manifest.signature.is_some() {
                warnings.push("包包含签名但缺少 origin 无法验证".to_string());
            }
        }
    }

    Ok(warnings)
}

fn load_trusted_origins() -> Result<HashSet<String>> {
    let path = trusted_origins_path()?;
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let content = fs::read_to_string(&path)?;
    let mut set = HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        set.insert(trimmed.to_string());
    }
    Ok(set)
}

fn load_trusted_key(origin: &str) -> Result<Option<String>> {
    let path = trust_dir()?.join(format!("{}.key", origin));
    if !path.exists() {
        return Ok(None);
    }
    let key = fs::read_to_string(&path)?;
    Ok(Some(key.trim().to_string()))
}

fn trust_dir() -> Result<PathBuf> {
    let dir = repository_root()?.join("trust");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn trusted_origins_path() -> Result<PathBuf> {
    Ok(trust_dir()?.join("origins.txt"))
}

pub fn list_trust() -> Result<Vec<TrustEntry>> {
    let entries = load_trusted_origins()?;
    let mut list = Vec::new();
    let dir = trust_dir()?;
    for origin in entries.iter() {
        let key_path = dir.join(format!("{}.key", origin));
        list.push(TrustEntry {
            origin: origin.clone(),
            key_present: key_path.exists(),
        });
    }
    list.sort_by(|a, b| a.origin.cmp(&b.origin));
    Ok(list)
}

pub fn add_trust(origin: &str, key_data: &str) -> Result<()> {
    let mut entries = load_trusted_origins()?;
    entries.insert(origin.to_string());
    save_trusted_origins(&entries)?;
    let path = trust_dir()?.join(format!("{}.key", origin));
    fs::write(&path, key_data.trim().as_bytes())?;
    Ok(())
}

pub fn remove_trust(origin: &str) -> Result<bool> {
    let mut entries = load_trusted_origins()?;
    if !entries.remove(origin) {
        return Ok(false);
    }
    save_trusted_origins(&entries)?;
    let key_path = trust_dir()?.join(format!("{}.key", origin));
    if key_path.exists() {
        let _ = fs::remove_file(key_path);
    }
    Ok(true)
}

pub struct TrustEntry {
    pub origin: String,
    pub key_present: bool,
}

fn save_trusted_origins(entries: &HashSet<String>) -> Result<()> {
    let mut list: Vec<_> = entries.iter().cloned().collect();
    list.sort();
    let mut content = String::new();
    for origin in list {
        content.push_str(origin.trim());
        content.push('\n');
    }
    let path = trusted_origins_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn compute_signature(
    seed_hex: &str,
    origin: &str,
    identifier: &str,
    version: &str,
    bundle_hash: &str,
) -> Result<String> {
    let seed = hex_decode::<32>(seed_hex)?;
    let signing = SigningKey::from_bytes(&seed);
    let digest = signature_message_hash(origin, identifier, version, bundle_hash);
    let sig: Signature = signing.sign(&digest);
    Ok(hex_encode(&sig.to_bytes()))
}

fn verify_signature_hex(
    public_hex: &str,
    signature_hex: &str,
    origin: &str,
    identifier: &str,
    version: &str,
    bundle_hash: &str,
) -> bool {
    let Ok(pk) = hex_decode::<32>(public_hex) else {
        return false;
    };
    let Ok(sb) = hex_decode::<64>(signature_hex) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify(
        &signature_message_hash(origin, identifier, version, bundle_hash),
        &Signature::from_bytes(&sb),
    )
    .is_ok()
}
