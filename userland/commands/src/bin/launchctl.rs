use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    List,
    Load { path: PathBuf },
    Unload { label: String },
}

#[derive(Serialize, Deserialize)]
struct LaunchEntry {
    label: String,
    program: String,
    args: Vec<String>,
    run_at_load: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let dir = launchd_dir();
    fs::create_dir_all(&dir)?;

    match args.command {
        Command::List => {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let content = fs::read_to_string(entry.path())?;
                let parsed: LaunchEntry = toml::from_str(&content)?;
                println!("{}\t{}", parsed.label, parsed.program);
            }
        }
        Command::Load { path } => {
            let content =
                fs::read_to_string(&path).with_context(|| format!("读取 {}", path.display()))?;
            let entry: LaunchEntry = toml::from_str(&content)?;
            let dest = dir.join(format!("{}.toml", entry.label));
            fs::write(&dest, content)?;
            println!("加载守护进程 {}", entry.label);
        }
        Command::Unload { label } => {
            let target = dir.join(format!("{}.toml", label));
            if target.exists() {
                fs::remove_file(target)?;
                println!("卸载守护进程 {}", label);
            } else {
                anyhow::bail!("launchctl: 未找到 {}", label);
            }
        }
    }
    Ok(())
}

fn launchd_dir() -> PathBuf {
    dirs_next::home_dir()
        .map(|mut p| {
            p.push(".zeroos/launchd");
            p
        })
        .unwrap_or_else(|| PathBuf::from("/System/LaunchDaemons"))
}
