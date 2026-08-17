use anyhow::Result;
use clap::{Parser, Subcommand};
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
    Info { device: PathBuf },
    EraseVolume { device: PathBuf, name: String },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::List => list_disks(),
        Command::Info { device } => show_info(&device),
        Command::EraseVolume { device, name } => erase_volume(&device, &name),
    }
}

fn list_disks() -> Result<()> {
    println!("寻找 ZeroFS 卷...");
    for entry in fs::read_dir("/dev")? {
        let entry = entry?;
        println!("{}", entry.path().display());
    }
    Ok(())
}

fn show_info(device: &PathBuf) -> Result<()> {
    if !device.exists() {
        anyhow::bail!("diskutil: 未找到 {}", device.display());
    }
    println!("设备: {}", device.display());
    println!("大小: 未实现 (需要块设备查询)");
    println!("格式: ZeroFS (假定)");
    Ok(())
}

fn erase_volume(device: &PathBuf, name: &str) -> Result<()> {
    println!(
        "将设备 {} 擦除并重新格式化为 ZeroFS，卷名 {}",
        device.display(),
        name
    );
    println!("警告: 实际擦写功能尚未实现。");
    Ok(())
}
