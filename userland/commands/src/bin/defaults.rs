use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Read {
        domain: String,
        key: Option<String>,
    },
    Write {
        domain: String,
        key: String,
        value: String,
    },
    Delete {
        domain: String,
        key: Option<String>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let base = defaults_dir();
    fs::create_dir_all(&base)?;
    match args.command {
        Command::Read { domain, key } => {
            let path = defaults_path(&base, &domain);
            let data = read_defaults(&path)?;
            if let Some(key) = key {
                if let Some(value) = data.get(&key) {
                    println!("{}", value);
                } else {
                    anyhow::bail!("defaults: 未找到键 {}", key);
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&data)?);
            }
        }
        Command::Write { domain, key, value } => {
            let path = defaults_path(&base, &domain);
            let mut data = read_defaults(&path)?;
            let parsed: Value = serde_json::from_str(&value).unwrap_or(Value::String(value));
            data[key] = parsed;
            fs::write(&path, serde_json::to_vec_pretty(&data)?)?;
        }
        Command::Delete { domain, key } => {
            let path = defaults_path(&base, &domain);
            if key.is_none() && path.exists() {
                fs::remove_file(&path)?;
                return Ok(());
            }
            let mut data = read_defaults(&path)?;
            if let Some(key) = key {
                data.as_object_mut()
                    .ok_or_else(|| anyhow::anyhow!("defaults: 格式错误"))?
                    .remove(&key);
                fs::write(&path, serde_json::to_vec_pretty(&data)?)?;
            }
        }
    }
    Ok(())
}

fn defaults_dir() -> PathBuf {
    dirs_next::home_dir()
        .map(|mut p| {
            p.push(".zeroos/defaults");
            p
        })
        .unwrap_or_else(|| PathBuf::from("/etc/zero/defaults"))
}

fn defaults_path(base: &PathBuf, domain: &str) -> PathBuf {
    base.join(format!("{domain}.json"))
}

fn read_defaults(path: &PathBuf) -> Result<Value> {
    if path.exists() {
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    } else {
        Ok(Value::Object(Default::default()))
    }
}
