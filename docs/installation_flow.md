# Zero OS 安装 & 应用部署流程

1. **引导安装器**  
   - 从 `ZeroOS-installer.iso` 启动，进入文本安装界面。  
   - 安装器读取系统镜像中的 `InstallManifest.toml`，列出可选组件。

2. **磁盘准备**  
   - 创建 GPT：ESP、ZeroFS (root)、ZeroFS (users)、Recovery。  
   - 对根分区执行 `mkzfs`（`cargo run -p mkzfs -- create --output target/rootfs.img --size 67108864`），写入超级块并初始化基础目录。  
   - 如需预置 `kernel/rootfs` 目录内容，可先运行 `cargo run -p xtask -- build-rootfs`，再执行 `cargo run -p mkzfs -- import-rootfs --output target/rootfs.img --rootfs-bundle target/rootfs.bundle`。

3. **创建管理员账户**  
   - 生成 `root`、管理员用户的密码哈希，写入 `/etc/passwd` 和 `/etc/shadow`.  
   - Securityd 在首次启动时导入初始能力策略。

4. **安装基础服务**  
   - 复制 microkernel、服务器二进制到 `/System/Core`.  
   - 注册服务描述文件 `Launch.toml` 供 launchd 启动。  
   - 安装器可通过 `mkzfs::ZfsImageBuilder::write_file` 写入二进制和配置文件，并使用 `write_passwd` 更新 `/etc/passwd`。

5. **部署应用程序**  
   - 安装器遍历 `InstallerPayload/Applications/*.app`，调用 `appctl install`.  
   - 用户可以指定 `/Applications` 或自定义路径；若缺省则使用默认目录。

6. **恢复镜像生成**  
   - 将当前 rootfs 快照写入恢复分区，并记录 UUID。  
   - 生成 `RecoveryManifest.json`，用于恢复模式识别。

7. **生成镜像与发布**  
   - 使用 `cargo run -p xtask -- build-iso` 生成包含 `zero-kernel`、`zero-rootfs.img`、Zero OS UEFI Loader 以及用户态工具的 ISO 镜像。  
   - ISO 的 `EFI/BOOT/BOOTAA64.EFI`、`EFI/ZEROOS/zero-{normal,recovery}.efi` 均由 `bootloader-uefi` 提供，默认 0 秒静默引导 Zero OS，连续失败 3 次会自动切换到恢复入口。  
   - `EFI/ZEROOS/` 内放置配置 `boot*.cfg`、磁盘镜像 `zero-rootfs.img`、`rootfs-recovery.bundle`，以及 `boot.env`（loader 维护的失败计数）。系统成功后应在用户态运行 `bootctl`（默认操作 `/boot/EFI/ZEROOS/boot.env`）清零失败计数。  
   - `userland/` 目录打包了服务器、安装器、恢复工具及 `mkzfs`，方便维护人员在救援环境下执行操作。  

8. **首次启动**  
   - Bootloader 加载 microkernel，启动 `launchd`。  
   - launchd 读取 `/System/LaunchAgents`，启动登录服务，提示创建或导入其他用户。  
   - 串口控制台提供多用户文本界面，默认账号 `root/zero`、`guest/guest`，可在登录后使用 `adduser`、`passwd`、`su`、`users` 等命令管理系统。
