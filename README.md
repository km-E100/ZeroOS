# Zero OS

Zero OS 是一款基于 **ARM64（AArch64）** 的实验性微内核操作系统：QEMU virt
上四核 SMP 稳定运行，具备进程/线程双模型、能力安全模型、ZFS/包管理、
PCIe/IOMMU/NVMe/USB xHCI、图形/网络/音频与固件电源链。Rust 实现，`#![no_std]`；
当前 microkernel 主机回归 203 项，基础实机 15/15、硬件专项 45/45、第41～44刀生产硬化 36/36。

## 能力一览（截至第44刀）

| 域 | 能力 |
| --- | --- |
| **多核** | 4 核 SMP：PSCI CPU_ON 点亮、全局 MLFQ 跨核调度、RESCHED SGI、per-CPU 状态 |
| **调度** | 多级反馈队列（4 级）、Sleep(ticks) 定时器轮、软看门狗 |
| **内存/运行时** | COW fork、brk、secure SHM、用户 PIE/ASLR、共享库动态链接、kernel Image KASLR、pstore |
| **线程** | CreateThread 共享地址空间线程、tid 可 join、FutexWait/Wake + UserMutex（CAS 快路径/futex 慢路径） |
| **进程** | 动态槽位（256）、execve 五阶段原子换映像、信号位图、精确 wait/join、孤儿收养 |
| **安全** | 内核盖章 IPC sender PID、capability 动态签发/撤销（TTL 活算台账）、管理员策略、哈希 userdb + 旧明文自动迁移、登录会话 |
| **文件系统/包** | 默认 `zero-fs-zfs` 持久卷（metadata/remount/atomic rename）+ ZeroPkg HTTPS/Ed25519/install/verify/launch/remove；`zero-fsd` 仅保留 legacy |
| **可靠性** | GitHub Actions CI、host/mm 回归矩阵、ABI 模糊测试、可回收 user allocator、ISO commit/dirty/hash provenance、性能基线脚本 |
| **图形/GPU** | GOP framebuffer + UTF-8/CJK console、VirtIO GPU 2D、inputd、WindowServer、VirGL 3D context/resource/submit/readback |
| **网络/Web** | netd（ARP/IPv4/ICMP/UDP/TCP/DHCP）、DNS、TLS 1.3、HTTP/1.1、SHM bulk I/O |
| **音频** | VirtIO Sound PCM + audiod；48kHz S16 stereo playback 实机/文件捕获验收 |
| **ACPI** | RSDP/XSDT/MADT/GTDT/FADT/MCFG；SMP/GIC/timer/PSCI/ECAM 真消费；AML 按真机需求再做 |
| **PCIe / IOMMU** | MCFG/high-ECAM、bridge/root-port window、32/64-bit BAR、MSI/MSI-X、GICv3 ITS/LPI affinity、IORT/SMMUv3 domain/IOVA/fault |
| **存储硬件** | VirtIO Blk + NVMe；多 namespace、4KiB native LBA RMW、per-CPU I/O queue、MDTS、Abort/reset/FLR recovery |
| **USB** | PCI xHCI、scratchpad、USB2 hub/Route String/TT、keyboard/mouse/tablet、root/hub hotplug、controller recovery |
| **电源/固件** | admin 动态 CAP_POWER、PSCI shutdown/reboot、FADT ResetReg fallback、持久化 flush/shutdown |

> 当前 COW 已默认开启。2026-08-25 收口时定位到历史回归根因：
> AArch64 `TLBI VAAE1IS` 的寄存器操作数误传完整 byte VA，正确编码应为
> `VA >> 12`，导致父进程残留 RW TLB 翻译并静默写穿共享栈页。
> 同轮还修复 free-list “不足最小块的尾巴未并入分配”造成的幽灵 gap。
> 详见 `docs/mm_heap_corruption_investigation.md`。

> 当前第20～44刀已全部落地并封板。通用 AML 仍刻意按需：只有出现明确真机需求时再单独立项，
> 不作为当前未完成项。STATUS 目前没有登记中的下一刀。

> 最终收口验收（2026-08-27）：`tools/check.sh` **57/57**；基础 QEMU **15/15**；
> 第35～40刀硬件专项 **45/45**；第41～44刀 hardening **36/36**；`-smp 4` 压力 **3轮×6/6 + zero fault**。
> 最终 ISO SHA-256 `8cc3ced62264c6bf80d4f7250734d3ec6dbaa799e2ab3a44194db7c4e37f344f`。
> `tools/testkeys` 中私钥/签名 seed 仅留本机测试，不入 Git；仓库只携带公开证书/公钥。

## 快速开始

```bash
cargo run -p xtask -- build-iso     # 构建镜像（超 3GB 自动拒绝，purge 自救）
./run-qemu.sh                       # 单核交互串口
scripts/acceptance.sh --no-build    # 基础验收矩阵（15/15）
scripts/hardware-acceptance.sh --no-build # 第35~40刀硬件专项（45/45）
scripts/hardening-acceptance.sh --no-build # 第41~44刀生产硬化专项（36/36）
scripts/stress-loop.sh 3            # -smp4 三轮 6/6 + no-fault 压力
scripts/perf-baseline.sh            # 性能基线采集
```

多核验证：给 QEMU 加 `-smp 4` 即进入多核模式（副核 PSCI CPU_ON 点亮）。

## 仓库结构

- `microkernel/`：微内核核心（调度/进程/线程/mm/中断/ACPI/security）
- `servers/`：用户态服务（launchd / zfsd / blkdrv / securityd / inputd / WindowServer / netd / pkgd / audiod 等）
- `userland/`：shell、syscall/client libs、PIE target、动态 runtime/网络/Web/包管理客户端
- `libs/`：`zero-abi`（系统调用契约）/ `zfs-core` 等
- `bootloader-uefi/`：UEFI 引导（ET_DYN kernel KASLR/RELA、bootfs handoff、pstore、ACPI/GOP）
- `docs/`：设计/历史调查文档（KASLR/ZeroPkg/ACPI/COW/堆等；已实施状态以 STATUS 为准）
- `scripts/`：基础 acceptance / hardware-acceptance / hardening-acceptance / stress-loop / perf-baseline

## 设计文档索引

- ABI 冻结契约：`docs/abi_syscall_reference.md`
- 内存/COW 调查：`docs/memory_management.md`、`docs/mm_heap_corruption_investigation.md`
- 文件系统与包格式：`docs/zero_file_system_spec.md`、`docs/app_bundle_format.md`
- 历史立项/实现依据：`docs/kaslr_image_plan.md`、`docs/zeropkg_inos_plan.md`、`docs/acpi_static_plan.md`（均已落地，见 STATUS）
- 断点存档：`STATUS.md`（每轮会话先读它接续进度）

## 许可

本项目代码以 [MIT](LICENSE) 或 [Apache-2.0](LICENSE-APACHE) 双许可提供。
仓库不包含本地测试私钥、历史 QEMU 日志及第三方 Kali/GRUB 引导文件。
`kernel/rootfs/etc/users` 中的账户仅用于开发与演示；部署前请替换默认账户和凭据。
