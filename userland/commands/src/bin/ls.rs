use anyhow::{anyhow, Result};
use clap::{ArgAction, Parser};
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Parser)]
struct Args {
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    #[arg(short = 'l', action = ArgAction::SetTrue)]
    long: bool,

    #[arg(short = 'R', action = ArgAction::SetTrue)]
    recursive: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    for path in args.paths {
        if args.recursive {
            for entry in WalkDir::new(&path) {
                let entry = entry?;
                print_entry(entry.path(), args.long)?;
            }
        } else {
            if path.is_dir() {
                for entry in fs::read_dir(&path)? {
                    let entry = entry?;
                    print_entry(&entry.path(), args.long)?;
                }
            } else if path.exists() {
                print_entry(&path, args.long)?;
            } else {
                return Err(anyhow!("ls: {} 不存在", path.display()));
            }
        }
    }
    Ok(())
}

fn print_entry(path: &std::path::Path, long: bool) -> Result<()> {
    if long {
        let meta = path.metadata()?;
        let file_type = if meta.is_dir() { "d" } else { "-" };
        let size = meta.len();
        println!("{file_type} {size:>10} {}", path.display());
    } else {
        println!("{}", path.display());
    }
    Ok(())
}
