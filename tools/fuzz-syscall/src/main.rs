//! fuzz-syscall 目前只承载 `cargo test -p fuzz-syscall` 的测试套件；
//! 二进制目标仅打印提示，保持 crate 可独立构建。
fn main() {
    println!("fuzz-syscall: run `cargo test -p fuzz-syscall`");
}
