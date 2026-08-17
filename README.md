# Zero OS

Zero OS 是一款基于 ARM64 的实验性微内核操作系统，目标是提供类 Unix 的多用户环境、与 macOS 相似的安全等级，并通过 Zero File System (ZFS) 和 `.app` 应用包格式实现现代化应用分发。

## 特性概览
- **微内核 + 用户态服务器**：进程管理、IPC、文件系统、权限服务均在用户态运行，内核仅负责调度与消息传递。
- **Zero File System (ZFS)**：全新磁盘格式，支持快照、日志、`.app` 原子安装。
- **`.app` 应用包**：每个包至少包含 `main` 与 `config`，系统默认执行 `main` 并依据 `config` 管理应用数据目录。
- **安全模型**：多用户、能力令牌、强制访问控制、恢复模式。
- **文本控制台**：内置多用户登录、账户管理、`su`/`adduser` 等命令，可直接在串口下完成基本维护。
- **安装生态**：提供安装镜像、恢复镜像、ZeroPkg 包管理。

## 仓库结构
- `boot/`：引导代码与链接脚本。
- `microkernel/`：Rust 实现的微内核核心。
- `servers/`：用户态核心服务（IPC、ZFS、launchd、安全服务）。
- `libs/`：ABI、ZFS 核心逻辑等共享库。
- `installer/`：文本安装器，负责分区、创建管理员用户、部署 `.app`。
- `recovery/`：恢复模式环境。
- `userapps/`：示例 `.app` 模板。
- `docs/`：设计文档、规范说明。
- `kernel/rootfs`：随内核打包的最小系统目录；`kernel/rootfs-recovery` 则提供恢复模式使用的只读根。

## 构建
```bash
cargo run -p xtask -- build-kernel
cargo run -p xtask -- build-servers
# 构建安装器、恢复镜像等
cargo run -p xtask -- build-installer
cargo run -p xtask -- build-recovery
# 生成 rootfs.bundle
cargo run -p xtask -- build-rootfs
# 调用安装器产出 rootfs 镜像
cargo run -p zero-installer
# 生成可启动 ISO 镜像
cargo run -p xtask -- build-iso
```

ISO 打包流程会顺便编译 `bootloader-uefi`，将生成的二进制同时复制到 `EFI/BOOT/BOOTAA64.EFI`、`EFI/ZEROOS/zero-normal.efi` 与 `EFI/ZEROOS/zero-recovery.efi`。Zero OS 自研 UEFI Loader 会解析 `EFI/ZEROOS/boot.cfg`、`boot.env`（失败计数）、`zero-rootfs.img` 等文件，默认安静引导正常模式。如连续 3 次标记为失败，将自动切换至恢复模式。

系统成功启动后请在用户态运行 `bootctl`（默认操作 `/boot/EFI/ZEROOS/boot.env`）把 `boot_success` 置为 1、`boot_failures` 清零，下一次启动即恢复正常模式。Loader 同样会解析 UEFI load options（例如 `rootfs=... log=debug ramdisk=1`），便于安装器或外部工具在链式引导时覆盖配置。

## 下一步
- 填充微内核上下文切换、系统调用实现。
- 实现 Zero File System 块分配器与日志恢复。
- 完成 ZeroPkg 与 `.app` 安装命令行工具。
- 构建完整的 QEMU 启动流程与测试套件。
