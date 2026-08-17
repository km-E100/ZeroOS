# macOS 风格命令行工具

Zero OS 提供一组与 macOS 相似的命令行工具，便于用户快速上手：

| 命令 | 功能 | 备注 |
|------|------|------|
| `ls` | 列出文件/目录，支持 `-l`、`-R` | 对应 macOS `ls` |
| `cp` | 复制文件或目录，支持 `-R` | |
| `defaults` | 管理用户偏好设置 `~/.zeroos/defaults` | 子命令 `read`、`write`、`delete` |
| `launchctl` | 加载/卸载守护进程配置 | 保存于 `~/.zeroos/launchd` |
| `diskutil` | 浏览、擦除卷（目前为占位实现） | |
| `softwareupdate` | 列出/安装 ZeroPkg 包 | 默认仓库 `~/.zero/pkg/repo`，安装前会提示来源/签名告警（`--yes` 跳过确认） |
| `zeropkg` | 打包/检查 `.zpkg`、发布到仓库 | 支持 `--origin`/`--sign-key` 以及 `trust` 子命令，与 `softwareupdate` 共用仓库 |
| `security` | 管理钥匙串（JSON 存储） | `~/.zeroos/keychains` |
| `appctl` | 安装、卸载、列出 `.app` 应用包 | 默认安装到 `~/Applications` |

所有命令位于 `userland/commands` crate，可通过 `cargo build -p zero-user-commands --bins` 编译测试。
