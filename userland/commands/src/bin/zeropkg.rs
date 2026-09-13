use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zero_user_commands::pkg;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Pack {
        app: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        publish: bool,
        #[arg(long)]
        origin: Option<String>,
        #[arg(long = "sign-key")]
        sign_key: Option<PathBuf>,
    },
    Inspect {
        package: PathBuf,
    },
    Install {
        package: PathBuf,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long, action = ArgAction::SetTrue)]
        yes: bool,
    },
    Publish {
        package: PathBuf,
    },
    Repo {
        #[command(subcommand)]
        repo: RepoCommand,
    },
    Trust {
        #[command(subcommand)]
        trust: TrustCommand,
    },
}

#[derive(Subcommand)]
enum RepoCommand {
    List,
}

#[derive(Subcommand)]
enum TrustCommand {
    /// 列出当前信任的来源
    List,
    /// 添加信任来源（会写入 origins.txt 并保存密钥）
    Add {
        origin: String,
        #[arg(long = "key-file")]
        key_file: Option<PathBuf>,
        #[arg(long)]
        key: Option<String>,
    },
    /// 移除信任来源
    Remove { origin: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Pack {
            app,
            output,
            publish,
            origin,
            sign_key,
        } => {
            let (path, manifest) = pkg::pack(
                &app,
                output.as_deref(),
                origin.as_deref(),
                sign_key.as_deref(),
            )?;
            println!(
                "已生成包 {} ({}) -> {}",
                manifest.name,
                manifest.version,
                path.display()
            );
            if publish {
                let published = pkg::publish(&path)?;
                println!("已发布到 {}", published.display());
            }
        }
        Command::Inspect { package } => {
            let manifest = pkg::inspect(&package)?;
            print_manifest(&manifest, &package);
        }
        Command::Install {
            package,
            target,
            yes,
        } => {
            let apps_dir = match target {
                Some(dir) => dir,
                None => zero_user_commands::ensure_applications_dir()?,
            };
            let plan = pkg::prepare_install(&package)?;
            if !plan.warnings.is_empty() {
                if !confirm_install(&plan.warnings, yes)? {
                    println!("已取消安装 {}", package.display());
                    return Ok(());
                }
            }
            let manifest = plan.manifest.clone();
            let outcome = plan.commit(&apps_dir)?;
            println!(
                "安装 {} ({}) -> {}",
                manifest.name,
                manifest.version,
                outcome.destination.display()
            );
            println!(
                "数据目录 \"{}\" 对应 {}",
                outcome.storage.requested,
                outcome.storage.path.display()
            );
            if outcome.overwritten {
                println!("覆盖了已安装版本。");
            }
        }
        Command::Publish { package } => {
            let target = pkg::publish(&package)?;
            println!("已发布包到 {}", target.display());
        }
        Command::Repo { repo } => match repo {
            RepoCommand::List => {
                let packages = pkg::repository_packages()?;
                if packages.is_empty() {
                    println!("仓库为空。");
                } else {
                    for entry in packages {
                        let trust = pkg::trust_warnings(&entry.manifest)?;
                        let trust_info = if trust.is_empty() {
                            "可信".to_string()
                        } else {
                            format!("警告: {}", trust.join("; "))
                        };
                        println!(
                            "{} ({}) [{}] -> {} | {}",
                            entry.manifest.name,
                            entry.manifest.version,
                            entry.manifest.identifier,
                            entry.path.display(),
                            trust_info
                        );
                    }
                }
            }
        },
        Command::Trust { trust } => match trust {
            TrustCommand::List => {
                let entries = pkg::list_trust()?;
                if entries.is_empty() {
                    println!("未配置任何信任来源。");
                } else {
                    for entry in entries {
                        let status = if entry.key_present {
                            "已配置密钥"
                        } else {
                            "缺少密钥"
                        };
                        println!("{} - {}", entry.origin, status);
                    }
                }
            }
            TrustCommand::Add {
                origin,
                key_file,
                key,
            } => {
                let key_data = match (key_file, key) {
                    (Some(path), None) => std::fs::read_to_string(&path)
                        .with_context(|| format!("读取密钥文件 {} 失败", path.display()))?,
                    (None, Some(value)) => value,
                    (Some(_), Some(_)) => {
                        anyhow::bail!("请只提供 --key-file 或 --key 其中之一");
                    }
                    (None, None) => {
                        anyhow::bail!("需要通过 --key-file 或 --key 指定密钥内容");
                    }
                };
                pkg::add_trust(&origin, &key_data)?;
                println!("已信任来源 {}", origin);
            }
            TrustCommand::Remove { origin } => {
                if pkg::remove_trust(&origin)? {
                    println!("已移除来源 {}", origin);
                } else {
                    println!("来源 {} 未在列表中", origin);
                }
            }
        },
    }
    Ok(())
}

fn print_manifest(manifest: &pkg::PackageManifest, package: &Path) {
    println!("包文件: {}", package.display());
    println!("名称: {}", manifest.name);
    println!("Identifier: {}", manifest.identifier);
    println!("版本: {}", manifest.version);
    println!("Bundle: {}", manifest.bundle_name);
    println!("Storage: {}", manifest.storage);
    if let Some(desc) = &manifest.description {
        println!("描述: {}", desc);
    }
    if let Some(perms) = &manifest.permissions {
        println!("权限: {}", perms.join(", "));
    }
    if let Some(args) = &manifest.args {
        println!("默认参数: {}", args.join(" "));
    }
    println!("哈希: {}", manifest.bundle_hash);
    if let Some(origin) = &manifest.origin {
        println!("来源: {}", origin);
    }
    if let Some(sig) = &manifest.signature {
        println!("签名: {}", sig);
    }
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
