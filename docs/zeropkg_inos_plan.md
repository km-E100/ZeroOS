# ZeroPkg 生态 · 设备内（in-OS）补全立项设计

> 现状盘点：宿主侧生态已成型——`zeropkg`（repo/trust 子命令，257 行）、
> `pkg.rs` 核心库（pack/inspect/prepare_install/publish，558 行）、
> `appctl install` 部署链路、信任列表（origins.txt + per-origin key）。
> **缺口在设备内**：Zero OS 运行期没有任何包管理入口——`.app` 只能由
> 宿主预置进 rootfs，无法运行期安装/查询/卸载。

## 立项范围（建议一个刀次，四步）

### WS-A 包格式设备端只读核
`libs/abi` 新增 `.zpkg` manifest 的 no_std 解析子模块（复用
`userland/commands/src/pkg.rs::inspect` 逻辑下沉）：Package.toml 字段
校验、bundle 哈希核对。主机单测与宿主实现共享同一份测试向量。

### WS-B fsd 卷上的安装事务
经 libfsclient 落盘：`/Applications/<name>.app/{main,config}` 原子写入
（先写临时名 → 校验哈希 → rename 语义 = 第十二刀 unlink+create 组合，
需 fsd 增加 CMD_RENAME 或"提交标记文件"约定）。断电安全：提交标记后
才可见。

### WS-C shell 命令面
`pkg ls` / `pkg install <rootfs路径>` / `pkg remove <name>` 三命令
（shell.rs 命令链末尾追加），权限挂 CAP_SPAWN_SVC 同级的新位或直接
要求 carrier + 登录会话（第十三刀 session 绑定现成可用）。

### WS-D 实机验收
rootfs 预置 demo.zpkg → 设备内 pkg install → threaddemo 式运行验证 →
pkg remove → 复查。纳入 scripts/acceptance.sh 注入序列。

## 依赖与风险
- 依赖第十二刀 fsd 目录树（已交付）与第十三刀 session/capability（已交付）；
- `.zpkg` 哈希算法若为 SHA-256 需引入 no_std 实现（audit：纯 Rust
  实现约 300 行，无 unsafe）；manifest 若为 TOML 则建议降级为键值对
  （no_std TOML 解析器成本高，格式文档同步修订）；
- 与镜像级 KASLR 无耦合，可并行。
