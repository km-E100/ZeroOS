use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use zero_user_commands::app_bundle;
use zero_user_commands::ensure_applications_dir;
use zero_user_commands::pkg;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 列出仓库中可用的 ZeroPkg 包
    List,
    /// 安装指定包，未指定则安装全部
    Install {
        #[arg(value_name = "PACKAGE")]
        packages: Vec<String>,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long, action = ArgAction::SetTrue)]
        yes: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::List => list_packages()?,
        Command::Install {
            packages,
            target,
            yes,
        } => install_packages(packages, target, yes)?,
    }
    Ok(())
}

fn list_packages() -> Result<()> {
    let packages = pkg::repository_packages()?;
    if packages.is_empty() {
        println!("ZeroPkg 仓库为空。");
        return Ok(());
    }

    let apps_dir = ensure_applications_dir()?;
    let installed = app_bundle::list_bundles(&apps_dir)?;
    let mut installed_map: HashMap<String, String> = HashMap::new();
    for bundle in installed {
        installed_map.insert(
            bundle.config.identifier.clone(),
            bundle.config.version.clone(),
        );
    }

    println!(
        "可用包列表 (仓库: {})",
        pkg::repository_packages_dir()?.display()
    );
    for entry in packages {
        let status = match installed_map.get(&entry.manifest.identifier) {
            Some(version) if *version == entry.manifest.version => "已安装最新".to_string(),
            Some(version) => format!("已安装 {version}, 可更新"),
            None => "未安装".to_string(),
        };
        let trust = pkg::trust_warnings(&entry.manifest)?;
        let trust_note = if trust.is_empty() {
            "可信".to_string()
        } else {
            format!("警告: {}", trust.join("; "))
        };
        println!(
            "{} ({}) [{}] - {} | {}",
            entry.manifest.name,
            entry.manifest.version,
            entry.manifest.identifier,
            status,
            trust_note
        );
    }
    Ok(())
}

fn install_packages(packages: Vec<String>, target: Option<PathBuf>, auto_yes: bool) -> Result<()> {
    let apps_dir = target.unwrap_or(ensure_applications_dir()?);
    let entries = if packages.is_empty() {
        pkg::repository_packages()?
    } else {
        let mut selected = Vec::new();
        for name in packages {
            let pkg =
                pkg::find_package(&name)?.with_context(|| format!("仓库中未找到包 {name}"))?;
            selected.push(pkg);
        }
        selected
    };

    if entries.is_empty() {
        println!("没有可安装的包。");
        return Ok(());
    }

    for entry in entries {
        println!(
            "安装 {} ({})...",
            entry.manifest.name, entry.manifest.version
        );
        let plan = pkg::prepare_install(&entry.path)?;
        if !plan.warnings.is_empty() {
            if !confirm_install(&plan.warnings, auto_yes)? {
                println!(
                    "跳过安装 {} ({})",
                    plan.manifest.name, plan.manifest.version
                );
                continue;
            }
        }
        let outcome = plan.commit(&apps_dir)?;
        println!(
            " -> {} | 数据目录 {} ({})",
            outcome.destination.display(),
            outcome.storage.requested,
            outcome.storage.path.display()
        );
    }
    Ok(())
}

fn confirm_install(warnings: &[String], auto_yes: bool) -> Result<bool> {
    if warnings.is_empty() {
        return Ok(true);
    }

    println!("检测到以下问题：");
    for warn in warnings {
        println!("  - {}", warn);
    }

    if auto_yes {
        println!("已使用 --yes，继续安装。");
        return Ok(true);
    }

    print!("继续安装？[y/N] ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_ascii_lowercase();
    Ok(matches!(answer.as_str(), "y" | "yes"))
}
