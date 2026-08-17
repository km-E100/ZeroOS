use anyhow::Result;
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
    ListKeychains,
    CreateKeychain { name: String },
    DeleteKeychain { name: String },
}

#[derive(Serialize, Deserialize, Default)]
struct Keychain {
    pub items: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let dir = keychain_dir();
    fs::create_dir_all(&dir)?;
    match args.command {
        Command::ListKeychains => {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                println!("{}", entry.path().display());
            }
        }
        Command::CreateKeychain { name } => {
            let path = dir.join(format!("{name}.json"));
            let kc = Keychain::default();
            fs::write(&path, serde_json::to_vec_pretty(&kc)?)?;
            println!("已创建钥匙串 {}", name);
        }
        Command::DeleteKeychain { name } => {
            let path = dir.join(format!("{name}.json"));
            if path.exists() {
                fs::remove_file(path)?;
                println!("已删除钥匙串 {}", name);
            } else {
                anyhow::bail!("security: 未找到 {}", name);
            }
        }
    }
    Ok(())
}

fn keychain_dir() -> PathBuf {
    dirs_next::home_dir()
        .map(|mut p| {
            p.push(".zeroos/keychains");
            p
        })
        .unwrap_or_else(|| PathBuf::from("/var/zeroos/keychains"))
}
