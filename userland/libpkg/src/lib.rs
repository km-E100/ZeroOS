#![no_std]
extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write as _;
use zero_abi::{channels, ipc::Message, protocol::security, syscall::SysError};

const MAGIC: &[u8] = b"ZEROPKG1\n";
const MAX_PACKAGE: usize = 8 * 1024 * 1024;
const DEV_REPO_CA: &[u8] = include_bytes!("../../../libs/certs/zeropkg-dev-repo-ca.der");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Format,
    Hash,
    Signature,
    Fs,
    FsRng,
    FsTemp,
    FsWrite,
    FsRead,
    FsCompare,
    FsCommit,
    FsRegistry,
    Network,
    Http(u16),
    NotFound,
    TooLarge,
    Permission,
    Spawn,
}
impl Error {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Hash => "hash",
            Self::Signature => "signature",
            Self::Fs => "fs",
            Self::FsRng => "fs-rng",
            Self::FsTemp => "fs-temp",
            Self::FsWrite => "fs-write",
            Self::FsRead => "fs-read",
            Self::FsCompare => "fs-compare",
            Self::FsCommit => "fs-commit",
            Self::FsRegistry => "fs-registry",
            Self::Network => "network",
            Self::Http(_) => "http",
            Self::NotFound => "not-found",
            Self::TooLarge => "too-large",
            Self::Permission => "permission",
            Self::Spawn => "spawn",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Manifest {
    pub format_version: u32,
    pub bundle_name: String,
    pub identifier: String,
    pub version: String,
    pub origin: String,
    pub bundle_hash: String,
    pub signature: String,
}
#[derive(Clone, Debug)]
struct Entry {
    path: String,
    data: Vec<u8>,
}
#[derive(Clone, Debug)]
struct Package {
    manifest: Manifest,
    entries: Vec<Entry>,
}

fn kv(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once('=')?;
        if k.trim() == key {
            let v = v.trim();
            if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                return Some(v[1..v.len() - 1].to_string());
            } else {
                return Some(v.to_string());
            }
        }
    }
    None
}
fn parse_manifest(t: &str) -> Result<Manifest, Error> {
    let format_version = kv(t, "format_version")
        .and_then(|v| v.parse().ok())
        .ok_or(Error::Format)?;
    Ok(Manifest {
        format_version,
        bundle_name: kv(t, "bundle_name").ok_or(Error::Format)?,
        identifier: kv(t, "identifier").ok_or(Error::Format)?,
        version: kv(t, "version").ok_or(Error::Format)?,
        origin: kv(t, "origin").ok_or(Error::Format)?,
        bundle_hash: kv(t, "bundle_hash").ok_or(Error::Format)?,
        signature: kv(t, "signature").ok_or(Error::Format)?,
    })
}
struct Cur<'a> {
    b: &'a [u8],
    o: usize,
}
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let e = self.o.checked_add(n).ok_or(Error::Format)?;
        let s = self.b.get(self.o..e).ok_or(Error::Format)?;
        self.o = e;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}
fn safe_rel(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.split('/').any(|x| x.is_empty() || x == "." || x == "..")
}
fn parse_package(b: &[u8]) -> Result<Package, Error> {
    if b.len() > MAX_PACKAGE || !b.starts_with(MAGIC) {
        return Err(Error::Format);
    }
    let mut c = Cur { b, o: MAGIC.len() };
    let ml = c.u32()? as usize;
    if ml > 64 * 1024 {
        return Err(Error::Format);
    };
    let mt = core::str::from_utf8(c.take(ml)?).map_err(|_| Error::Format)?;
    let manifest = parse_manifest(mt)?;
    if manifest.format_version != 2 || !manifest.bundle_name.ends_with(".app") {
        return Err(Error::Format);
    };
    let n = c.u32()? as usize;
    if n == 0 || n > 4096 {
        return Err(Error::Format);
    };
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let pl = c.u32()? as usize;
        if pl == 0 || pl > 512 {
            return Err(Error::Format);
        };
        let p = core::str::from_utf8(c.take(pl)?).map_err(|_| Error::Format)?;
        if !safe_rel(p) || entries.iter().any(|e: &Entry| e.path == p) {
            return Err(Error::Format);
        }
        let sz = c.u64()? as usize;
        if sz > MAX_PACKAGE {
            return Err(Error::TooLarge);
        }
        let data = c.take(sz)?.to_vec();
        entries.push(Entry {
            path: p.to_string(),
            data,
        });
    }
    if c.o != b.len() || !entries.iter().any(|e| e.path == "main") {
        return Err(Error::Format);
    };
    Ok(Package { manifest, entries })
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char)
    }
    s
}
fn unhex<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return Err(Error::Format);
    }
    fn v(x: u8) -> Option<u8> {
        match x {
            b'0'..=b'9' => Some(x - b'0'),
            b'a'..=b'f' => Some(x - b'a' + 10),
            b'A'..=b'F' => Some(x - b'A' + 10),
            _ => None,
        }
    }
    let mut o = [0u8; N];
    for i in 0..N {
        o[i] = (v(b[2 * i]).ok_or(Error::Format)? << 4) | v(b[2 * i + 1]).ok_or(Error::Format)?;
    }
    Ok(o)
}
fn canonical_hash(entries: &[Entry]) -> [u8; 32] {
    let mut refs: Vec<&Entry> = entries.iter().collect();
    refs.sort_by(|a, b| a.path.cmp(&b.path));
    let mut c = Vec::new();
    for e in refs {
        c.extend_from_slice(&(e.path.len() as u32).to_le_bytes());
        c.extend_from_slice(e.path.as_bytes());
        c.extend_from_slice(&(e.data.len() as u64).to_le_bytes());
        c.extend_from_slice(&e.data);
    }
    zero_zfs_core::crypto::sha256(&c)
}
fn message_hash(m: &Manifest) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"zero-pkg-v2\0");
    for s in [&m.origin, &m.identifier, &m.version, &m.bundle_hash] {
        b.extend_from_slice(s.as_bytes());
        b.push(0)
    }
    zero_zfs_core::crypto::sha256(&b)
}
fn verify_signature(m: &Manifest) -> Result<(), Error> {
    let sig = unhex::<64>(&m.signature)?;
    let hash = message_hash(m);
    if m.origin.len() > 30 {
        return Err(Error::Format);
    }
    let mut q = Message::empty();
    q.code = security::CMD_PKG_VERIFY;
    q.payload[0] = m.origin.len() as u8;
    q.payload[1..1 + m.origin.len()].copy_from_slice(m.origin.as_bytes());
    let o = 1 + m.origin.len();
    q.payload[o..o + 32].copy_from_slice(&hash);
    q.payload[o + 32..o + 96].copy_from_slice(&sig);
    userlib::ipc_send(channels::SECURITY_USER_REQ, &q).map_err(|_| Error::Signature)?;
    loop {
        let mut r = Message::empty();
        match userlib::ipc_receive(channels::SECURITY_USER_RESP, &mut r) {
            Ok(_) => {
                return if r.code == 0 {
                    Ok(())
                } else {
                    Err(Error::Signature)
                }
            }
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => return Err(Error::Signature),
        }
    }
}
fn validate(p: &Package) -> Result<(), Error> {
    let actual_hash = hex(&canonical_hash(&p.entries));
    if actual_hash != p.manifest.bundle_hash {
        let mut line = String::from("zeropkg: bundle hash mismatch expected=");
        line.push_str(&p.manifest.bundle_hash);
        line.push_str(" actual=");
        line.push_str(&actual_hash);
        line.push_str("\r\n");
        let _ = userlib::console_write(line.as_bytes());
        return Err(Error::Hash);
    }
    verify_signature(&p.manifest)
}
fn join(a: &str, b: &str) -> String {
    let mut s = String::from(a.trim_end_matches('/'));
    s.push('/');
    s.push_str(b.trim_start_matches('/'));
    s
}
fn ensure_dirs(path: &str) {
    let mut cur = String::new();
    for part in path.trim_matches('/').split('/') {
        cur.push('/');
        cur.push_str(part);
        let _ = libfsclient::mkdir(&cur);
    }
}
fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}
fn remove_tree(path: &str) -> Result<(), Error> {
    let mut buf = [0u8; 4096];
    match libfsclient::list_directory(path, &mut buf) {
        Ok(n) => {
            let text = core::str::from_utf8(&buf[..n]).map_err(|_| Error::Fs)?;
            let names: Vec<String> = text.lines().map(|x| x.to_string()).collect();
            for name in names {
                if name.ends_with('/') {
                    remove_tree(&join(path, name.trim_end_matches('/')))?
                } else {
                    libfsclient::unlink(&join(path, &name)).map_err(|_| Error::Fs)?
                }
            }
            libfsclient::rmdir(path).map_err(|_| Error::Fs)
        }
        Err(_) => libfsclient::unlink(path).map_err(|_| Error::Fs),
    }
}
fn registry_path(id: &str) -> String {
    let mut s = String::from("/var/lib/zeropkg/");
    s.push_str(id);
    s.push_str(".meta");
    s
}
fn registry(m: &Manifest) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "bundle={}\nversion={}\nhash={}\n",
        m.bundle_name, m.version, m.bundle_hash
    );
    s
}
fn reg_value(t: &str, k: &str) -> Option<String> {
    t.lines().find_map(|l| {
        l.split_once('=')
            .and_then(|(a, b)| (a == k).then(|| b.to_string()))
    })
}

pub fn install_bytes(bytes: &[u8]) -> Result<Manifest, Error> {
    let p = parse_package(bytes)?;
    validate(&p)?;
    ensure_dirs("/Applications");
    ensure_dirs("/var/lib/zeropkg");
    let mut rnd = [0u8; 8];
    if userlib::getrandom(&mut rnd).is_err() {
        return Err(Error::FsRng);
    }
    let temp = format_path("/Applications/.pkg-", &hex(&rnd));
    let _ = remove_tree(&temp);
    if libfsclient::mkdir(&temp).is_err() {
        return Err(Error::FsTemp);
    }
    for e in &p.entries {
        let dest = join(&temp, &e.path);
        ensure_dirs(parent(&dest));
        if libfsclient::write_file(&dest, &e.data).is_err() {
            let _ = remove_tree(&temp);
            return Err(Error::FsWrite);
        }
        let back = match libfsclient::read_file(&dest, e.data.len() + 1) {
            Ok(v) => v,
            Err(_) => {
                let _ = remove_tree(&temp);
                return Err(Error::FsRead);
            }
        };
        if back != e.data {
            let _ = remove_tree(&temp);
            return Err(Error::FsCompare);
        }
    }
    let finalp = join("/Applications", &p.manifest.bundle_name);
    let backup = format_path(&finalp, ".old");
    let had_old = libfsclient::rename(&finalp, &backup).is_ok();
    if libfsclient::rename(&temp, &finalp).is_err() {
        if had_old {
            let _ = libfsclient::rename(&backup, &finalp);
        }
        let _ = remove_tree(&temp);
        return Err(Error::FsCommit);
    }
    if had_old {
        let _ = remove_tree(&backup);
    }
    let meta = registry(&p.manifest);
    if libfsclient::write_file(&registry_path(&p.manifest.identifier), meta.as_bytes()).is_err() {
        return Err(Error::FsRegistry);
    }
    Ok(p.manifest)
}

fn format_path(a: &str, b: &str) -> String {
    let mut s = String::from(a);
    s.push_str(b);
    s
}

pub fn install_url(url: &str) -> Result<Manifest, Error> {
    let (host, port, path) = parse_https_url(url)?;
    let r = if host == "10.0.2.2" {
        libweb::https_get_with_ca(&host, port, &path, DEV_REPO_CA)
    } else if port == 443 {
        libweb::https_get(&host, &path)
    } else {
        return Err(Error::Network);
    }
    .map_err(|_| Error::Network)?;
    if r.status != 200 {
        return Err(Error::Http(r.status));
    }
    install_bytes(&r.body)
}
fn parse_https_url(url: &str) -> Result<(String, u16, String), Error> {
    let rest = url.strip_prefix("https://").ok_or(Error::Format)?;
    let slash = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash];
    let path = if slash < rest.len() {
        rest[slash..].to_string()
    } else {
        "/".to_string()
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => {
            (h.to_string(), p.parse().map_err(|_| Error::Format)?)
        }
        _ => (authority.to_string(), 443),
    };
    Ok((host, port, path))
}

pub fn remove(id: &str) -> Result<(), Error> {
    let meta = libfsclient::read_file(&registry_path(id), 4096).map_err(|_| Error::NotFound)?;
    let t = core::str::from_utf8(&meta).map_err(|_| Error::Format)?;
    let bundle = reg_value(t, "bundle").ok_or(Error::Format)?;
    remove_tree(&join("/Applications", &bundle))?;
    libfsclient::unlink(&registry_path(id)).map_err(|_| Error::Fs)
}
pub fn launch(id: &str) -> Result<u64, Error> {
    let meta = libfsclient::read_file(&registry_path(id), 4096).map_err(|_| Error::NotFound)?;
    let t = core::str::from_utf8(&meta).map_err(|_| Error::Format)?;
    let bundle = reg_value(t, "bundle").ok_or(Error::Format)?;
    let image = libfsclient::read_file(
        &join(&join("/Applications", &bundle), "main"),
        16 * 1024 * 1024,
    )
    .map_err(|_| Error::Fs)?;
    userlib::spawn_image(&image).map_err(|_| Error::Spawn)
}
pub fn verify(id: &str) -> Result<bool, Error> {
    let meta = libfsclient::read_file(&registry_path(id), 4096).map_err(|_| Error::NotFound)?;
    let t = core::str::from_utf8(&meta).map_err(|_| Error::Format)?;
    let bundle = reg_value(t, "bundle").ok_or(Error::Format)?;
    let expected = reg_value(t, "hash").ok_or(Error::Format)?;
    let root = join("/Applications", &bundle);
    let mut entries = Vec::new();
    collect_installed(&root, "", &mut entries)?;
    Ok(hex(&canonical_hash(&entries)) == expected)
}
fn collect_installed(root: &str, rel: &str, out: &mut Vec<Entry>) -> Result<(), Error> {
    let dir = if rel.is_empty() {
        root.to_string()
    } else {
        join(root, rel)
    };
    let mut buf = [0u8; 4096];
    let n = libfsclient::list_directory(&dir, &mut buf).map_err(|_| Error::Fs)?;
    let text = core::str::from_utf8(&buf[..n]).map_err(|_| Error::Fs)?;
    let names: Vec<String> = text.lines().map(|x| x.to_string()).collect();
    for name in names {
        let child_rel = if rel.is_empty() {
            name.trim_end_matches('/').to_string()
        } else {
            join(rel, name.trim_end_matches('/'))
        };
        if name.ends_with('/') {
            collect_installed(root, &child_rel, out)?
        } else {
            let data = libfsclient::read_file(&join(root, &child_rel), MAX_PACKAGE)
                .map_err(|_| Error::Fs)?;
            out.push(Entry {
                path: child_rel,
                data,
            })
        }
    }
    Ok(())
}
pub fn list(out: &mut [u8]) -> Result<usize, Error> {
    let mut tmp = [0u8; 4096];
    let n = libfsclient::list_directory("/var/lib/zeropkg", &mut tmp).map_err(|_| Error::Fs)?;
    let t = core::str::from_utf8(&tmp[..n]).map_err(|_| Error::Fs)?;
    let mut o = 0;
    for line in t.lines() {
        if let Some(id) = line.strip_suffix(".meta") {
            if o + id.len() + 1 > out.len() {
                break;
            }
            out[o..o + id.len()].copy_from_slice(id.as_bytes());
            o += id.len();
            out[o] = b'\n';
            o += 1
        }
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_parse() {
        assert_eq!(
            parse_https_url("https://10.0.2.2:8443/a").unwrap(),
            ("10.0.2.2".to_string(), 8443, "/a".to_string())
        );
    }
    #[test]
    fn rel_safety() {
        assert!(safe_rel("a/b"));
        assert!(!safe_rel("../x"));
        assert!(!safe_rel("/x"));
    }
}
