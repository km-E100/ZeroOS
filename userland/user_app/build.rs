use std::path::PathBuf;

fn main() {
    // 用户程序专用链接脚本（基址 0x200000，禁止使用 boot/linker.ld——
    // 那是内核链接脚本，基址 0x40080000 恰在内核共享区，曾导致用户表
    // 摧毁内核恒等映射）。用 build.rs 注入 link-arg 比 .cargo/config.toml
    // 更可靠：不依赖 cargo 配置合并规则，也不受绝对路径/空格解析影响。
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let linker = manifest.join("link-user.ld");
    let linker = linker
        .to_str()
        .expect("linker path is not valid UTF-8")
        .replace('\\', "/");

    println!("cargo:rustc-link-arg=-T{}", linker);
    println!("cargo:rustc-link-arg=--build-id=none");
    // 让 cargo 在链接脚本变化时重新链接
    println!("cargo:rerun-if-changed={}", linker);
}
