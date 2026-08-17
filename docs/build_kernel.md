# 构建 Zero OS 微内核（aarch64-unknown-none）

本指南说明如何在本地交叉编译 `zero-microkernel`，并为后续生成完整内核镜像做准备。

## 1. 安装依赖

```bash
rustup toolchain install nightly
rustup target add aarch64-unknown-none --toolchain nightly
brew install qemu aarch64-none-elf-gcc   # macOS 示例，可换成发行版包
```

## 2. 编译微内核

仓库提供了 `xtask build-kernel-bare` 命令，会调用：

```bash
cargo +nightly build \
    -Zbuild-std=core,compiler_builtins,alloc \
    --target aarch64-unknown-none \
    -p zero-microkernel
```

该命令会：
- 使用 `nightly` 与 `build-std` 构建 `core/alloc`，以便在 `aarch64-unknown-none` 上编译无标准库代码。
- 输出结果位于 `target/aarch64-unknown-none/debug/libzero_microkernel.a`。

若要构建包含引导代码的完整内核镜像，可执行：

```bash
cargo run -p xtask -- build-image
```

该命令会触发 `cargo +nightly build ... -p zero-kernel`，并在 `target/zero-os.elf` 生成可供 QEMU 加载的镜像（使用 `boot/linker.ld`）。

## 3. 引导代码

`boot/boot.S` 提供最小化的 AArch64 启动例程，会：
1. 准备栈（4 KiB）；
2. 构造占位 `BootInfo`；
3. 跳转至 `kernel_main`。

要把汇编对象与 Rust 静态库链接成最终内核镜像，可在后续阶段引入新的 `kernel` 二进制 crate，或在 `build.rs` 中调用 `cc` 将 `boot.S` 编译成对象并与微内核链接。

## 4. 后续步骤

- 实现内核所需的内存分配器与页表初始化，然后在 `boot::init_arch` 中接入。
- 构建 rootfs、打包 ZeroFS，并利用 QEMU 进行启动验证。
- 根据硬件平台调整链接脚本 `boot/linker.ld`，包含设备寄存器映射与内核放置地址。

完成这些后，即可继续开发驱动、文件服务器与用户态组件，逐步实现完整的 Zero OS。 
