use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mkzfs::ZfsImageBuilder;
use std::path::PathBuf;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::List { image } => list_snapshots(&image)?,
        Command::Restore { image, snapshot } => restore_snapshot(&image, snapshot)?,
        Command::InjectAdmin { image, user, hash } => inject_admin(&image, &user, &hash)?,
        Command::ShowPasswd { image } => show_passwd(&image)?,
    }
    Ok(())
}

#[derive(Parser)]
#[command(author, version, about = "Zero OS Recovery Toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List snapshots stored in the given ZeroFS image
    List {
        #[arg(long)]
        image: PathBuf,
    },
    /// Restore a snapshot by id
    Restore {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        snapshot: u64,
    },
    /// Inject or update an administrator account
    InjectAdmin {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long)]
        hash: String,
    },
    /// Dump /etc/passwd from the image
    ShowPasswd {
        #[arg(long)]
        image: PathBuf,
    },
}

fn list_snapshots(image: &PathBuf) -> Result<()> {
    let builder = ZfsImageBuilder::load(image)?;
    let snapshots = builder.list_snapshots()?;
    if snapshots.is_empty() {
        println!("no snapshots found");
    } else {
        for snap in snapshots {
            println!(
                "id={} label={} time={} free_blocks={}",
                snap.id, snap.label, snap.logical_time, snap.free_blocks
            );
        }
    }
    Ok(())
}

fn restore_snapshot(image: &PathBuf, snapshot: u64) -> Result<()> {
    let builder = ZfsImageBuilder::load(image)?;
    builder
        .restore_snapshot(snapshot)
        .with_context(|| format!("snapshot {} not found", snapshot))?;
    builder.flush_to(image)?;
    println!("restored snapshot {}", snapshot);
    Ok(())
}

fn inject_admin(image: &PathBuf, user: &str, hash: &str) -> Result<()> {
    let builder = ZfsImageBuilder::load(image)?;
    builder.write_passwd(user, hash)?;
    builder.flush_to(image)?;
    println!("updated /etc/passwd");
    Ok(())
}

fn show_passwd(image: &PathBuf) -> Result<()> {
    let builder = ZfsImageBuilder::load(image)?;
    match builder.read_file("/etc/passwd") {
        Ok(data) => {
            let text = String::from_utf8_lossy(&data);
            println!("{}", text);
        }
        Err(err) => {
            println!("failed to read /etc/passwd: {err}");
        }
    }
    Ok(())
}
