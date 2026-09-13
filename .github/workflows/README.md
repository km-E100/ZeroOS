# Zero OS CI 说明

本目录承载仓库唯一的 CI 流水线（`ci.yaml`，runner = `macos-latest` +
`nightly` 工具链）。选 macOS/AArch64 的原因：内核 trap/arch 路径含
`aarch64` 汇编（`mrs esr_el1` 等），主机单测必须在本机目标上编译执行；
裸机构建走 `-Zbuild-std`，需要 nightly 的 `rust-src` 组件。

## Job 结构与本地等价命令

| Job | 内容 | 本地等价命令 |
| --- | --- | --- |
| `host-tests` | 内核纯逻辑层 69 项单测 | `cargo test -p zero-microkernel` |
| | MM 算法 host 单测（独立 mini 工程） | `cargo test --manifest-path microkernel/mm-host-tests/Cargo.toml` |
| | zero-abi 双端一致性测试（件一） | `cargo test -p zero-abi` |
| | syscall 参数校验模糊测试（件二） | `cargo test -p fuzz-syscall` |
| `baremetal-builds` | 内核裸机构建，零 error 断言 | `cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-microkernel` |
| | UEFI 引导器构建，零 error 断言 | `cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-uefi -p bootloader-uefi` |
| | user-app（zero-shell）构建，零 error 断言 | `cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p user-app` |
| `build-iso-smoke`（continue-on-error） | 全链 ISO 打包冒烟 | `cargo run -p xtask -- build-iso` |

## 零 error 断言的实现

job2 每步 `set -o pipefail` 后把编译输出 `tee` 进日志再执行
`! grep -q "^error" <log>`：cargo 非零退出码与日志中的 error 行任一出现
都会让该 job 失败——防止 error 被管道或 warning 化处理吞掉。

## 提交前本地自检（与 CI 完全一致）

```bash
cargo test -p zero-microkernel
cargo test --manifest-path microkernel/mm-host-tests/Cargo.toml
cargo test -p zero-abi
cargo test -p fuzz-syscall
cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p zero-microkernel
cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-uefi -p bootloader-uefi
cargo +nightly build -Zbuild-std=core,compiler_builtins,alloc --target aarch64-unknown-none -p user-app
```

## 备注

- `xtask build-iso` 自带项目体积硬闸（2048MB，超限拒绝并提示 purge）；
  CI runner 磁盘充裕，一般不会触发。冒烟 job 失败不阻塞合流，但日志会
  被保留在 Actions 运行详情里供排查。
- 工具链安装用 `dtolnay/rust-toolchain@nightly`（含 `rust-src` 组件与
  两个 aarch64 target），与 xtask 各构建命令的 `+nightly` 前缀对应。
