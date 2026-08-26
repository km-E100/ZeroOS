//! 为用户态服务注入专用链接脚本。
//!
//! 与 user_app 的 build.rs 同源：launchd 必须链接在 0x200000
//! （用户代码区，L1[0] 私有副本），绝不能用内核链接脚本
//! （基址 0x40080000 在内核共享区，会破坏用户地址空间的映射）。

use std::path::PathBuf;

fn main() {
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
