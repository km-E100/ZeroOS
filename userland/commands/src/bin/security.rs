use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// 第十三刀「安全模型成型」命令行升级：
///
/// - 原有 `keychain` 子命令保持不变；
/// - 新增 `issue` / `revoke` / `list` 三个能力令牌子命令——在宿主侧
///   维护一份与 Zero OS securityd 同构的**本地台账**（~/.zeroos/caps），
///   字段与实机协议一一对应（token / target pid / caps 位图 / 有效期），
///   用于开发期演练签发-撤销生命周期与脚本化回归。实机权威状态在
///   内核 security 台账（号位 40/41），本文件只是宿主镜像工具。
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    ListKeychains,
    CreateKeychain {
        name: String,
    },
    DeleteKeychain {
        name: String,
    },
    /// 签发一枚能力令牌（对齐实机 CMD_CAP_ISSUE 0x20）
    Issue {
        /// 目标进程 pid
        #[arg(long)]
        target: u64,
        /// 能力位图（十六进制，如 0x50；位定义见 zero_abi::cap）
        #[arg(long)]
        caps: String,
        /// 有效期（秒；0 = 不过期，对应内核逻辑时钟 ttl=0）
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
    },
    /// 撤销一枚能力令牌（对齐实机 CMD_CAP_REVOKE 0x21）
    Revoke {
        /// 令牌编号
        token: u64,
    },
    /// 列出台账（对齐实机 CMD_CAP_LIST 0x22）
    List,
}

#[derive(Serialize, Deserialize, Default)]
struct Keychain {
    pub items: Vec<String>,
}

/// 能力令牌台账行（与 zero_abi::protocol::security::CapIssueRequest 对齐）。
#[derive(Serialize, Deserialize, Clone)]
struct CapEntry {
    token: u64,
    target_pid: u64,
    /// 十六进制文本保存的位图（JSON 无 u32 hex 字面量）。
    caps_hex: String,
    /// 签发时刻（Unix 秒）。
    issued_at: u64,
    /// 有效期（秒；0 = 不过期）。
    ttl_secs: u64,
    revoked: bool,
}

impl CapEntry {
    fn expired(&self, now: u64) -> bool {
        self.ttl_secs != 0 && now >= self.issued_at.saturating_add(self.ttl_secs)
    }

    fn state(&self, now: u64) -> &'static str {
        if self.revoked {
            "[revoked]"
        } else if self.expired(now) {
            "[expired]"
        } else {
            "[active]"
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::ListKeychains => {
            let dir = keychain_dir();
            fs::create_dir_all(&dir)?;
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                println!("{}", entry.path().display());
            }
        }
        Command::CreateKeychain { name } => {
            let dir = keychain_dir();
            fs::create_dir_all(&dir)?;
            let path = dir.join(format!("{name}.json"));
            let kc = Keychain::default();
            fs::write(&path, serde_json::to_vec_pretty(&kc)?)?;
            println!("已创建钥匙串 {}", name);
        }
        Command::DeleteKeychain { name } => {
            let path = keychain_dir().join(format!("{name}.json"));
            if path.exists() {
                fs::remove_file(path)?;
                println!("已删除钥匙串 {}", name);
            } else {
                anyhow::bail!("security: 未找到 {}", name);
            }
        }
        Command::Issue { target, caps, ttl } => {
            let caps_value = parse_caps_hex(&caps).ok_or_else(|| {
                anyhow::anyhow!("security: caps 需为 1..=8 位十六进制（如 0x50）")
            })?;
            if caps_value == 0 {
                bail!("security: caps 不能为空位图");
            }
            let mut ledger = load_ledger()?;
            let entry = CapEntry {
                token: generate_token(),
                target_pid: target,
                caps_hex: format!("{caps_value:#x}"),
                issued_at: unix_now(),
                ttl_secs: ttl,
                revoked: false,
            };
            println!(
                "已签发 token={} target={} caps={} ttl={}s",
                entry.token, entry.target_pid, entry.caps_hex, entry.ttl_secs
            );
            ledger.push(entry);
            save_ledger(&ledger)?;
        }
        Command::Revoke { token } => {
            let mut ledger = load_ledger()?;
            match ledger.iter_mut().find(|e| e.token == token) {
                Some(entry) if !entry.revoked => {
                    entry.revoked = true;
                    save_ledger(&ledger)?;
                    println!("已撤销 token={token}");
                }
                Some(_) => bail!("security: token={token} 已处于撤销态"),
                None => bail!("security: 未找到 token={token}"),
            }
        }
        Command::List => {
            let ledger = load_ledger()?;
            let now = unix_now();
            if ledger.is_empty() {
                println!("(尚未签发任何能力令牌)");
            }
            for entry in &ledger {
                println!(
                    "token={} pid={} caps={} {}",
                    entry.token,
                    entry.target_pid,
                    entry.caps_hex,
                    entry.state(now)
                );
            }
        }
    }
    Ok(())
}

/// 十六进制解析（容忍 0x/0X 前缀，也接受裸十六进制；越宽返回 None）。
fn parse_caps_hex(text: &str) -> Option<u32> {
    let body = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if body.is_empty() || body.len() > 8 {
        return None;
    }
    u32::from_str_radix(body, 16).ok()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 令牌编号生成（宿主侧无内核单调分配器）：纳秒时钟截断 + 非零保证。
/// 仅用于本地台账的唯一性，不承担防猜测职责（实机由内核分配）。
fn generate_token() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(1);
    nanos.max(1)
}

fn cap_ledger_path() -> PathBuf {
    dirs_next::home_dir()
        .map(|mut p| {
            p.push(".zeroos/caps.json");
            p
        })
        .unwrap_or_else(|| PathBuf::from("/var/zeroos/caps.json"))
}

/// 历史钥匙串目录（keychain 子命令族保留使用）。
fn keychain_dir() -> PathBuf {
    dirs_next::home_dir()
        .map(|mut p| {
            p.push(".zeroos/keychains");
            p
        })
        .unwrap_or_else(|| PathBuf::from("/var/zeroos/keychains"))
}

fn load_ledger() -> Result<Vec<CapEntry>> {
    let path = cap_ledger_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice(&fs::read(&path)?)?)
}

fn save_ledger(ledger: &[CapEntry]) -> Result<()> {
    let path = cap_ledger_path();
    fs::write(&path, serde_json::to_vec_pretty(ledger)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_hex_accepts_prefixed_and_bare() {
        assert_eq!(parse_caps_hex("0x50"), Some(0x50));
        assert_eq!(parse_caps_hex("50"), Some(0x50));
        assert_eq!(parse_caps_hex("0XfF"), Some(0xff));
        assert_eq!(parse_caps_hex(""), None);
        assert_eq!(parse_caps_hex("0x"), None);
        assert_eq!(parse_caps_hex("0011223344"), None, "超宽拒绝");
        assert_eq!(parse_caps_hex("zz"), None);
    }

    #[test]
    fn expiry_semantics_match_kernel_ttl_zero_is_never() {
        // 与内核 GrantBook 同一约定：ttl=0 永不过期；其余按绝对时刻判定。
        let never = CapEntry {
            token: 1,
            target_pid: 2,
            caps_hex: "0x10".into(),
            issued_at: 100,
            ttl_secs: 0,
            revoked: false,
        };
        assert!(!never.expired(u64::MAX));
        let short = CapEntry {
            token: 2,
            target_pid: 2,
            caps_hex: "0x10".into(),
            issued_at: 100,
            ttl_secs: 10,
            revoked: false,
        };
        assert!(!short.expired(109));
        assert!(short.expired(110), "含端不含端语义与内核一致");
        assert_eq!(short.state(109), "[active]");
        assert_eq!(short.state(200), "[expired]");
        let revoked = CapEntry {
            revoked: true,
            ..short.clone()
        };
        assert_eq!(revoked.state(100), "[revoked]", "撤销态优先于过期态");
    }

    #[test]
    fn token_generator_never_returns_zero() {
        for _ in 0..16 {
            assert_ne!(generate_token(), 0, "0 不是合法 token（内核同约定）");
        }
    }
}
