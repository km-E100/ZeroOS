//! ZeroPkg 设备端只读核（第十五刀后续 · docs/zeropkg_inos_plan.md WS-A）。
//!
//! 与宿主 `pkg.rs` 的格式契约对齐：`MAGIC "ZEROPKG1\n"` + manifest_len
//! (u32 LE) + manifest 文本 + file_count (u32 LE) + 条目流。
//!
//! 宿主侧 manifest 为 TOML——设备端 no_std 不引 TOML 解析器，改用**行级
//! KV 提取**：只认 `key = "value"` 形态，覆盖 pkg ls 所需的 name/version
//! 两字段。完整 TOML 语义仍以宿主为准（写入端保证这两行是简单 KV）。

use alloc::string::String;
use alloc::vec::Vec;

/// ZeroPkg 魔数（与宿主 pkg.rs MAGIC 一致）。
pub const ZPKG_MAGIC: &[u8] = b"ZEROPKG1\n";

#[derive(Debug, PartialEq, Eq)]
pub struct ManifestBrief {
    pub name: String,
    pub version: String,
}

/// 从 manifest 文本提取 name/version（行级 KV："key = \"value\""）。
/// 宿主 TOML 中这两个字段恒为简单字符串字面量，故本解析完备够用；
/// 其他字段/表格结构一律忽略。
fn kv_extract(manifest: &str, key: &str) -> Option<String> {
    let needle_prefix = key;
    for line in manifest.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with(needle_prefix) {
            continue;
        }
        let rest = trimmed[needle_prefix.len()..].trim_start();
        if let Some(rest) = rest.strip_prefix('=') {
            let v = rest.trim();
            if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                return Some(String::from(&v[1..v.len() - 1]));
            }
        }
    }
    None
}

/// 校验魔数并解析 manifest 头部摘要。
/// 输入为整包前缀字节（至少包含 magic+len+manifest）。
pub fn parse_brief(pkg: &[u8]) -> Option<ManifestBrief> {
    if pkg.len() < ZPKG_MAGIC.len() || &pkg[..ZPKG_MAGIC.len()] != ZPKG_MAGIC {
        return None;
    }
    let o = ZPKG_MAGIC.len();
    if pkg.len() < o + 4 {
        return None;
    }
    let mlen = u32::from_le_bytes([pkg[o], pkg[o + 1], pkg[o + 2], pkg[o + 3]]) as usize;
    let mstart = o + 4;
    if mlen > pkg.len().saturating_sub(mstart) {
        return None; // 截断
    }
    let text = core::str::from_utf8(&pkg[mstart..mstart + mlen]).ok()?;
    let name = kv_extract(text, "name")?;
    let version = kv_extract(text, "version").unwrap_or_else(|| String::from("0.0.0"));
    Some(ManifestBrief { name, version })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn build_pkg(manifest: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(ZPKG_MAGIC);
        b.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        b.extend_from_slice(manifest.as_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // file_count 占位
        b
    }

    #[test]
    fn brief_parses_name_and_version() {
        let m = "format_version = 1\nname = \"demo\"\nversion = \"1.2.3\"\n";
        let brief = parse_brief(&build_pkg(m)).expect("parse");
        assert_eq!(brief.name, "demo");
        assert_eq!(brief.version, "1.2.3");
    }

    #[test]
    fn bad_magic_rejected() {
        let mut b = build_pkg("name = \"x\"");
        b[0] = b'X';
        assert!(parse_brief(&b).is_none());
    }

    #[test]
    fn truncated_manifest_rejected() {
        let mut b = build_pkg("name = \"demo\"");
        let cut = ZPKG_MAGIC.len() + 2;
        b.truncate(cut);
        // len 字段声称的长度超过剩余 ⇒ 截断拒绝
        assert!(parse_brief(&b).is_none());
    }

    #[test]
    fn missing_version_defaults() {
        let m = "format_version = 1\nname = \"only-name\"\n";
        let brief = parse_brief(&build_pkg(m)).unwrap();
        assert_eq!(brief.name, "only-name");
        assert_eq!(brief.version, "0.0.0");
    }
}
