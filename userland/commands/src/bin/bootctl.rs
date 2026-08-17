use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

const DEFAULT_ENV_PATH: &str = "/boot/EFI/ZEROOS/boot.env";

#[derive(Parser)]
#[command(about = "Record Zero OS boot success state", author, version)]
struct Cli {
    /// Path to the Zero OS boot environment file
    #[arg(long, default_value = DEFAULT_ENV_PATH)]
    path: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    mark_boot_success(&cli.path)
}

fn mark_boot_success(path: &PathBuf) -> Result<()> {
    let mut vars = read_env(path).unwrap_or_default();
    vars.insert("boot_success".to_string(), "1".to_string());
    vars.insert("boot_failures".to_string(), "0".to_string());
    write_env(path, &vars)?;
    println!("bootctl: recorded successful boot in {}", path.display());
    Ok(())
}

fn read_env(path: &PathBuf) -> Result<BTreeMap<String, String>> {
    let bytes = fs::read(path).context("reading boot env")?;
    Ok(parse_env(&bytes))
}

fn parse_env(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            vars.insert(key.to_string(), value.to_string());
        }
    }
    vars
}

fn write_env(path: &PathBuf, vars: &BTreeMap<String, String>) -> Result<()> {
    let mut content = String::new();
    for (key, value) in vars {
        content.push_str(key);
        content.push('=');
        content.push_str(value);
        content.push('\n');
    }
    fs::write(path, content).context("writing boot env")
}
