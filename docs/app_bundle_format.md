# Zero OS `.app` 包格式

Zero OS 将每个应用封装在一个以 `.app` 结尾的目录中。核心约定只有两个：

- `main`：无扩展名的可执行文件，系统启动应用时默认运行它。
- `config`：无扩展名的配置文件，提供应用元数据与数据存储声明。

除此之外，开发者可以按需组织其他文件与目录。

## 基本目录结构
```
MyApp.app/
  main               # 必须：应用入口，可执行文件或脚本
  config             # 必须：应用配置（TOML 格式）
  Resources/         # 可选：资源文件
  CodeSignature      # 可选：签名/校验信息
  ...
```

### `config` 文件

`config` 采用 TOML 语法，不带扩展名，至少包含以下字段：

```toml
name = "MyApp"
identifier = "org.zeroos.myapp"
version = "1.2.0"
storage = "MyAppData"          # 应用在用户目录下的首选数据目录名称

# 可选字段
description = "示例应用"
permissions = ["fs.read", "net.client"]
args = ["--foreground"]
```

- `name`：展示名称。
- `identifier`：全局唯一，建议使用反向域名。
- `version`：语义化版本。
- `storage`：应用要求的数据目录名称，系统会在用户目录下分配该名称；若冲突则分配隐藏后缀并记录映射。
- `description`、`permissions`、`args` 等字段由系统或 Launchd 可选使用，开发者也可自行扩展。

### 数据存储约束

- 应用产生的持久化文件必须写入用户目录下以 `storage` 字段命名的目录。
- 如果同名目录已被其他应用占用，安装器会为该应用创建隐藏后缀（例如 `.MyAppData__a1b2`），并将映射记录在 `~/.zero/app-storage.json`。
- 映射由系统维护，卸载应用时默认保留数据目录；未来可在工具中提供清理选项。

## 安装流程
1. 获取包含 `main` 与 `config` 的 `.app` 目录。
2. 运行 `appctl install <path-to-app.app> [--target /Applications]`。
3. 安装器解析 `config`，为 `storage` 字段分配实际目录，并将整个 `.app` 复制到目标目录。

## 打包与发布
- 使用 `zeropkg pack MyApp.app --origin <issuer> --sign-key <secret> --publish` 可将 `.app` 打包为 `.zpkg` 文件并同步到本地仓库（`~/.zero/pkg/repo`）。
- `zeropkg inspect pkg.zpkg` 查看包内 manifest 信息。
- `softwareupdate list` 列出仓库中可用的包；`softwareupdate install <identifier>` 可安装或升级到指定版本。
- `.zpkg` 文件内部包含 `Package.toml` manifest 与 `.app` 目录快照，安装时会校验 bundle 哈希并复用 `appctl` 逻辑完成部署。来源或签名缺失/不可信时会提示用户是否继续安装，可在 `~/.zero/pkg/trust/origins.txt` 与 `~/.zero/pkg/trust/<origin>.key` 中维护信任列表。
- 可通过 `zeropkg trust add <origin> --key-file secret.txt` 管理信任来源，`zeropkg trust list` 查看现有配置。

## 运行时
- Launchd 或用户直接执行应用时，默认运行 `main` 文件。
- 安全服务器（securityd）可以根据 `permissions` 字段授予能力。
- 应用可携带多语言可执行文件，使用 Zero OS ABI 与系统调用接口。

## 签名与扩展
- `CodeSignature` 文件可用于存放 ZeroPkg 生成的签名信息（可选）。
- 开发者可以在 `.app` 中加入额外配置、资源或嵌套目录，系统只要求 `main` 与 `config` 存在。
