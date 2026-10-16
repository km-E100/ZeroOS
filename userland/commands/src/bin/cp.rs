use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(short = 'R', long = "recursive", action = ArgAction::SetTrue)]
    recursive: bool,

    #[arg(required = true)]
    sources: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.sources.len() < 2 {
        anyhow::bail!("cp: 需要至少一个源和一个目标路径");
    }
    let (targets, dest) = args.sources.split_at(args.sources.len() - 1);
    let dest = &dest[0];
    for src in targets {
        copy_path(src, dest, args.recursive)?;
    }
    Ok(())
}

fn copy_path(src: &Path, dest: &Path, recursive: bool) -> Result<()> {
    let meta = fs::metadata(src)?;
    if meta.is_dir() {
        if !recursive {
            anyhow::bail!("cp: -R 未指定，无法复制目录 {}", src.display());
        }
        let target_dir = if dest.is_dir() {
            dest.join(src.file_name().ok_or_else(|| anyhow::anyhow!("无效路径"))?)
        } else {
            dest.to_path_buf()
        };
        fs::create_dir_all(&target_dir)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_path(&entry.path(), &target_dir, recursive)?;
        }
    } else {
        let target = if dest.is_dir() {
            dest.join(src.file_name().ok_or_else(|| anyhow::anyhow!("无效路径"))?)
        } else {
            dest.to_path_buf()
        };
        copy_file(src, &target)?;
    }
    Ok(())
}

fn copy_file(src: &Path, dest: &Path) -> Result<()> {
    let mut input = fs::File::open(src).with_context(|| format!("打开源文件 {}", src.display()))?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output =
        fs::File::create(dest).with_context(|| format!("创建目标文件 {}", dest.display()))?;
    let mut buf = Vec::new();
    input.read_to_end(&mut buf)?;
    output.write_all(&buf)?;
    Ok(())
}
