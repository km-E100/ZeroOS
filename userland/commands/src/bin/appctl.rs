use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zero_user_commands::app_bundle;
use zero_user_commands::ensure_applications_dir;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Install {
        app_path: PathBuf,
        #[arg(long)]
        target: Option<PathBuf>,
    },
    Uninstall {
        name: String,
    },
    List,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Install { app_path, target } => {
            let dest = target.unwrap_or(ensure_applications_dir()?);
            let outcome = app_bundle::install_bundle(&app_path, &dest)?;
            if outcome.overwritten {
                println!(
                    "覆盖安装 {} ({}) -> {}",
                    outcome.config.name,
                    outcome.config.version,
                    outcome.destination.display()
                );
            } else {
                println!(
                    "安装 {} ({}) -> {}",
                    outcome.config.name,
                    outcome.config.version,
                    outcome.destination.display()
                );
            }
            println!(
                "数据目录 \"{}\" 实际对应 {}",
                outcome.storage.requested,
                outcome.storage.path.display()
            );
        }
        Command::Uninstall { name } => {
            let dest = ensure_applications_dir()?;
            let outcome = app_bundle::uninstall_bundle(&dest, &name)?;
            if let Some(config) = outcome.config {
                if let Some(storage) = outcome.storage {
                    println!(
                        "已卸载 {}.app ({})，保留数据目录 {} ({})",
                        config.name,
                        config.version,
                        storage.requested,
                        storage.path.display()
                    );
                } else {
                    println!(
                        "已卸载 {}.app ({})（未记录数据目录）",
                        config.name, config.version
                    );
                }
            } else {
                println!("已卸载 {name}.app（未找到配置文件）");
            }
        }
        Command::List => {
            let dest = ensure_applications_dir()?;
            let bundles = app_bundle::list_bundles(&dest)?;
            if bundles.is_empty() {
                println!("未在 {} 中找到任何 .app", dest.display());
                return Ok(());
            }
            for bundle in bundles {
                if let Some(storage) = bundle.storage {
                    println!(
                        "{} ({}) - {} | 数据目录 {} ({})",
                        bundle.config.name,
                        bundle.config.version,
                        bundle.path.display(),
                        storage.requested,
                        storage.path.display()
                    );
                } else {
                    println!(
                        "{} ({}) - {} | 数据目录：{}",
                        bundle.config.name,
                        bundle.config.version,
                        bundle.path.display(),
                        bundle.config.storage
                    );
                }
            }
        }
    }
    Ok(())
}
