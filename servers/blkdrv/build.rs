//! 为用户态服务注入专用链接脚本（仅裸机目标生效）。
//!
//! 与 servers/security/build.rs 同源：本服务必须链接在 0x200000
//! （用户代码区，L1[0] 私有副本），绝不能用内核链接脚本（基址
//! 0x40080000 在内核共享区，会破坏用户地址空间的映射）。
//!
//! 必须按 TARGET 门控：build_servers / build-iso 还会把本 crate
//! 编成宿主版本（ISO userland/ 目录的开发者分析用副本），宿主
//! ld 不认识 -T link.x，无条件注入会让 host 构建直接失败。

use std::path::PathBuf;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("aarch64-unknown-none") {
        return;
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let linker = manifest.join("link.x");
    let linker = linker
        .to_str()
        .expect("linker path is not valid UTF-8")
        .replace('\\', "/");

    println!("cargo:rustc-link-arg=-T{}", linker);
    println!("cargo:rustc-link-arg=--build-id=none");
    println!("cargo:rerun-if-changed={}", linker);
}
