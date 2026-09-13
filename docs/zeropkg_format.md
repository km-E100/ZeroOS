# ZeroPkg 包格式

ZeroPkg 为 Zero OS 设计的轻量级应用分发格式，用于封装 `.app` 目录并记录元数据。每个 `.zpkg` 文件均由 `zeropkg pack` 生成，内部结构如下：

```
ZEROPKG1\n                 # 魔数与版本号
<manifest_len:u32>   # manifest 字节长度（小端）
<manifest bytes>     # TOML 格式的 Package.toml
<file_count:u32>     # 随后的文件条目数量
重复 file_count 次:
  <path_len:u32>
  <path bytes>       # UTF-8，相对于 .app 根目录
  <file_size:u64>
  <file bytes>
```

## Manifest 字段

`Package.toml` 对应 `PackageManifest` 结构：

```toml
format_version = 1
bundle_name = "MyApp.app"
name = "MyApp"
identifier = "org.zeroos.myapp"
version = "1.0.0"
storage = "MyAppData"
bundle_hash = "4c1b..."

# 可选字段
origin = "zero-os-official"
signature = "7fa2..."

description = "示例应用"
permissions = ["fs.read"]
args = ["--foreground"]
```

- `bundle_hash` 为 `.app` 内容（路径 + 文件数据）的 SipHash（`DefaultHasher`）十六进制表示，用于安装时校验完整性。
- `origin` 标记包的发行方，`signature` 为基于发行方密钥、`origin`、`identifier`、`version`、`bundle_hash` 计算的签名。
- 其余字段与 `config` 中保持一致，便于 `softwareupdate` 在安装前了解应用信息。

### 签名与来源

- `zeropkg pack --origin <origin> --sign-key <path>` 会在 manifest 中写入来源与签名，其中签名密钥文件内容可为任意字符串，用作共享密钥。
- 验证时工具会读取 `~/.zero/pkg/trust/origins.txt` 中列出的可信来源，并尝试在 `~/.zero/pkg/trust/<origin>.key` 中找到对应密钥；若缺失或校验失败，将提示用户确认是否继续安装。
- 即便缺少签名或来源，用户仍可选择安装，但命令行会打印警告并请求确认（可使用 `--yes` 或 `--force` 跳过交互）。

## 仓库布局

- 默认仓库位于 `~/.zero/pkg/repo`，`zeropkg pack --publish` 会将新生成的包拷贝至此。
- `softwareupdate list` 遍历仓库并比对当前安装状态，同时输出来源&签名诊断信息；`softwareupdate install` 会在安装前执行完整性/签名检查并提示用户是否继续。
- 信任配置示例：在 `~/.zero/pkg/trust/origins.txt` 中每行写入一个来源 ID（支持 `#` 注释）；对应密钥保存在 `~/.zero/pkg/trust/<origin>.key` 中，内容即为 `--sign-key` 使用的同一字符串。也可使用 `zeropkg trust add <origin> --key-file secret.txt` 帮助生成/更新配置。
- 仓库为纯文件目录，可通过任意方式同步或分发。
