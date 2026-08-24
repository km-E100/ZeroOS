# Zero OS

Zero OS 是一款基于 **ARM64（AArch64）** 的实验性微内核操作系统：QEMU virt
上四核 SMP 稳定运行，具备进程/线程双模型、能力安全模型、块设备文件系统
与包管理格式。Rust 实现，`#![no_std]`，主机测试 166+，实机验收矩阵 15 项。

## 能力一览（截至第十八刀）

| 域 | 能力 |
| --- | --- |
| **多核** | 4 核 SMP：PSCI CPU_ON 点亮、全局 MLFQ 跨核调度、RESCHED SGI、per-CPU 状态 |
| **调度** | 多级反馈队列（4 级）、Sleep(ticks) 定时器轮、软看门狗 |
| **内存** | COW fork 默认启用（可写页共享、首写断链；只读页直映射）、brk 用户堆、pstore 崩溃落盘 + bootloader 取回、KASLR 栈随机化 |
| **线程** | CreateThread 共享地址空间线程、tid 可 join、FutexWait/Wake + UserMutex（CAS 快路径/futex 慢路径） |
| **进程** | 动态槽位（256）、execve 五阶段原子换映像、信号位图、精确 wait/join、孤儿收养 |
| **安全** | 内核盖章 IPC sender PID、capability 动态签发/撤销（TTL 活算台账）、管理员策略、哈希 userdb + 旧明文自动迁移、登录会话 |
| **文件系统** | 当前运行时为轻量 `zero-fsd` 块后端目录树（mkdir/rmdir/unlink/LIST）、cat/ls、fstest/fsdemo；`zero-fs-zfs`/`zfs-core` 为独立实现资产，尚未替换默认服务 |
| **可靠性** | GitHub Actions CI、host/mm 回归矩阵、ABI 模糊测试、可回收 user allocator、ISO commit/dirty/hash provenance、性能基线脚本 |
| **ACPI** | RSDP/XSDT/MADT 静态解析（GICC 核列表/GICD），SMP 枚举正规化；AML 不做 |

> 当前 COW 已默认开启。2026-08-25 收口时定位到历史回归根因：
> AArch64 `TLBI VAAE1IS` 的寄存器操作数误传完整 byte VA，正确编码应为
> `VA >> 12`，导致父进程残留 RW TLB 翻译并静默写穿共享栈页。
> 同轮还修复 free-list “不足最小块的尾巴未并入分配”造成的幽灵 gap。
> 详见 `docs/mm_heap_corruption_investigation.md`。

> 仍属路线图而非当前默认能力：镜像级 KASLR、AML，以及把
> `zero-fs-zfs` 切成默认运行时文件服务。

## 快速开始

```bash
cargo run -p xtask -- build-iso     # 构建镜像（超 3GB 自动拒绝，purge 自救）
./run-qemu.sh                       # 单核交互串口
scripts/acceptance.sh --no-build    # 实机验收矩阵（15 项，exit 0 = ALL PASS）
scripts/stress-loop.sh 3            # -smp4 四核压力循环
scripts/perf-baseline.sh            # 性能基线采集
```

多核验证：给 QEMU 加 `-smp 4` 即进入多核模式（副核 PSCI CPU_ON 点亮）。

## 仓库结构

- `microkernel/`：微内核核心（调度/进程/线程/mm/中断/ACPI/security）
- `servers/`：用户态服务（launchd / fsd / blkdrv / securityd / ipc-router）
- `userland/`：shell 与演示命令（forktest/threaddemo/mutextest/secdemo/fstest/fsdemo…）
- `libs/`：`zero-abi`（系统调用契约）/ `zfs-core` 等
- `bootloader-uefi/`：UEFI 引导（ELF 加载/pstore 取回/RSDP 抓取）
- `docs/`：设计文档与立项计划（KASLR/ZeroPkg/ACPI/堆损坏调查）
- `scripts/`：acceptance / stress-loop / perf-baseline

## 设计文档索引

- ABI 冻结契约：`docs/abi_syscall_reference.md`
- 内存/COW 调查：`docs/memory_management.md`、`docs/mm_heap_corruption_investigation.md`
- 文件系统与包格式：`docs/zero_file_system_spec.md`、`docs/app_bundle_format.md`
- 待实施立项：`docs/kaslr_image_plan.md`、`docs/zeropkg_inos_plan.md`、`docs/acpi_static_plan.md`
- 断点存档：`STATUS.md`（每轮会话先读它接续进度）

## 许可

MIT OR Apache-2.0
