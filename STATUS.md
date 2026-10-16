# Zero OS 复兴状态（断点存档）

> 新会话先读本文件 + `git log --oneline` 接上进度。

## 2026-10-16 · TODO List（下一阶段路线，P0/P1 + 第45～56刀）

> 本节由 2026-10-16 基线复核后建立。上一节记录的 45/45、36/36 等指标为
> 2026-08-27 的声明值；2026-10-16 本机复跑 `hardware-acceptance.sh` 实测
> **36/45**，差异已在下方 P0/P1 中定位。
>
> 共 7 组约 **100 项**：P0/P1 缺陷、第45～50刀（内存→地址空间→TCP/存储/安全→KPTI）、
> 第51～56刀（进程控制面→FS 完整性→内存安全→动态加载/可观测性→测试闸→隔离）。
> 第51刀为 2026-10-16 全仓审计新发现，信号/进程组/RLIMIT 等**完全为零**。

### 🔴 P0 · 真实缺陷（实机暴露，优先修复）

**blkdrv 后端探测不验证可用性** — 一条探测缺陷废掉整条 NVMe 存储路径。

```
driver: virtio-blk 自检写入失败 (LBA=2048): DeviceError        ← 自检失败
blkdrv: passthrough backend ready (VirtIO blk via kernel svc 7/8)   ← 却仍然绑定
nvme: READ/WRITE/FLUSH SELFTEST PASS                            ← NVMe 已就绪却被跳过
Zero OS zfsd mount FAILED
[1/6] open "zerofsd.txt" create: FAIL (open: invalid argument)
```

根因 `servers/blkdrv/src/lib.rs` `probe_backend()` 只判断容量 > 0，不做读写验证：
```rust
fn probe_backend() -> bool {
    block_capacity_sectors().map(|v| v > 0).unwrap_or(false)
}
```
自检失败的 virtio-blk 被照单全收，且**无回退到下一候选设备**；fsd 拿到坏后端后
mount 失败且未上报，级联导致 ZeroPkg 安装与全部文件系统操作返回 `invalid argument`。

| # | 任务 |
| --- | --- |
| P0-1 | `probe_backend` 增加读写往返验证（写标记→读回→比对），而非仅看容量 |
| P0-2 | 绑定失败时回退到下一候选设备（NVMe 已就绪却被跳过） |
| P0-3 | fsd/zfsd 拿到不可用后端时明确上报 `NODEV`，不静默返回 `invalid argument` |
| P0-4 | regression：`hardware-acceptance.sh` 增加「blkdrv 必须自绑定成功」断言 |

### 🟡 P1 · 测试脚本缺陷（非系统缺陷，但掩盖真实状态）

| # | 任务 | 真相 |
| --- | --- | --- |
| P1-1 | `check()` 等待串口日志落盘，消除竞态假 FAIL | K36/K37 SMP4 系统正常，`boot_secondaries done, requested=3 online=4` 确实在日志第 178 行，判定时日志未刷新 |
| P1-2 | K40 期望字符串随 P0 修复后同步 | 现期望 `NVMe via`，实测 `VirtIO blk via` |

### 🔵 第45刀 · 内存管理地基（最底层，后续一切依赖它）

| # | 任务 | 现状依据 |
| --- | --- | --- |
| 45-a | 物理分配器水位线游标 | `phys_bitmap.rs` `alloc_page` 每次从第 0 字扫至第 16384 字，无游标 |
| 45-b | SMP 并发分配 | 全局单 `spin::Mutex`，SMP 下所有核串行 |
| 45-c | 突破 4 GiB 硬上限 | `phys.rs` `MAX_PAGES = 1024*1024` 写死 |
| 45-d | 内核堆动态化 | `heap.rs` `HEAP_PAGES = 2048` 静态 8 MiB BSS |
| 45-e | slab / size-class 分配器 | 小对象碎片与锁竞争 |
| 45-f | host 回归 | 碎片守恒 / 耗尽 / 并发压力入 `mm-host-tests` |

### 🔵 第46刀 · 地址空间与 VM API（KPTI 的前置条件）

| # | 任务 | 现状依据 |
| --- | --- | --- |
| 46-a | 通用 `mmap`/`munmap`/`mprotect` | 当前零实现，仅 brk / 栈 / ELF 三条专用路径 |
| 46-b | 按需分页 demand paging | 无缺页异常路径 |
| 46-c | ASID 引入 | 无 ASID，每次切换 `tlbi vmalle1` 全量清 TLB |
| 46-d | 跨核 TLB shootdown | 仅本核精确失效，无按 ASID / IPI 广播 |
| 46-e | 用户栈 guard 页显式化 | 当前隐式设计 |
| 46-f | 进程表扩容 | `MAX_PROCESSES = 256` 固定 |

### 🔵 第47刀 · netd TCP 可靠传输

| # | 任务 | 现状依据 |
| --- | --- | --- |
| 47-a | 数据段重传队列 + RTO 指数退避 + 快速重传 | 仅 SYN 有重传（`TCP_SYN_RETRY_MS=750` / `LIMIT=5`），已发数据段无任何重传 |
| 47-b | ACK 去重与累计确认 | 状态机仅 SynSent/Established/Closed 三态 |
| 47-c | 补齐状态机 + `listen`/`accept` | 缺 Listen/SynReceived/FinWait/CloseWait/TimeWait |
| 47-d | 拥塞控制 slow start + congestion avoidance | 无 cwnd/ssthresh |
| 47-e | 丢包注入回归纳入 acceptance | 需新增 |

### 🔵 第48刀 · 存储持久化

| # | 任务 | 现状依据 |
| --- | --- | --- |
| 48-a | 快照落盘 + 重启恢复 | `metadata.rs` 中 `snapshot` 出现 0 次，重启即丢 |
| 48-b | 突破 metadata bank 上限 | `BANK_BLOCKS = 32` → 约 252 KiB，超出即 `CheckpointTooLarge` |
| 48-c | Journal 落盘与崩溃重放 | `journal.rs` 纯内存 `Vec`，满了 `remove(0)` |

### 🔵 第49刀 · 内核安全与健壮性

| # | 任务 | 现状依据 |
| --- | --- | --- |
| 49-a | PAN / UAO 引入 | 全仓库零使用 |
| 49-b | 中断栈分离 | `process.rs` 自承「我们无中断栈分离」 |
| 49-c | 进程槽引用计数 / pin | `remove_slot` 后存在 UAF 窗口 |
| 49-d | 口令哈希加盐 + 迭代 | `security` 用无 salt 单次 `sha256` |
| 49-e | capability 台账持久化 | 签发/撤销重启即丢 |
| 49-f | 孤儿语义修正 | adopted 走 `ReapImmediately`，偏离 POSIX |

### 🔵 第50刀 · KPTI 与真 KASLR

| # | 任务 | 现状依据 |
| --- | --- | --- |
| 50-a | 真 KASLR | 页表基址与内核镜像固定，仅随机栈顶约 1 MiB |
| 50-b | KPTI | `TTBR0_EL1`/`TTBR1_EL1` 指向同一根表 |
| 50-c | 内核栈随机化与 KASLR 联动 | — |

### 横切 · 系统完整性

| # | 任务 |
| --- | --- |
| C-1 | launchd 自动崩溃恢复（退出检测 + 退避重启；`restart` 命令当前仅人工触发） |
| C-2 | 僵尸进程收割：launchd `wait`/`reap` 循环（全库无） |
| C-3 | README 指标同步：45/45 等改为本机实测值并标注复现命令 |
| C-4 | 本节基线复跑：hardening-acceptance 36/36 与 stress-loop SMP4 待补 |

### 🔴 第51刀 · 进程控制面（POSIX 缺口，当前完全为零）

> 本轮全仓审计确认以下能力**完全不存在**（grep 零命中），
> 对一个具备 MLFQ 调度、COW fork、capability 的 OS 属于基础缺口。

| # | 任务 | 现状 |
| --- | --- | --- |
| 51-a | 信号机制：信号位图 + 投递 + 屏蔽字 + 处理器注册 | **零实现**，无 `SIGKILL`/`signal_send` |
| 51-b | `kill` 系统调用 + `wait` 状态扩展（被信号终止） | 无 |
| 51-c | 进程组 / 会话 / job control（`setpgid`/`tcsetpgrp`） | **零实现** |
| 51-d | 优先级 / nice：MLFQ 四级与 nice 值映射 | **零实现**，优先级完全由 MLFQ 隐式决定 |
| 51-e | RLIMIT 资源上限：`setrlimit`/`getrlimit` + 强制点 | **零实现** |

### 🔴 第52刀 · 文件系统完整性

| # | 任务 | 现状 |
| --- | --- | --- |
| 52-a | 符号链接真实实现（`symlink`/`readlink`/解析路径） | 仅 `InodeKind::Symlink` 枚举定义，无行为 |
| 52-b | 硬链接 + `nlink` 引用计数 | **零实现** |
| 52-c | `fsck` / 一致性检查与修复工具 | **零实现** |
| 52-d | 磁盘配额 quota | **零实现** |
| 52-e | 大文件支持：单文件超过 metadata bank 容量时的分段存储 | 受 252 KiB 天花板约束 |

### 🔵 第53刀 · 内存安全与用户态加固

| # | 任务 | 现状 |
| --- | --- | --- |
| 53-a | 栈保护 canary（用户 ELF 栈 + 内核栈） | **零实现**，无 `__stack_chk` |
| 53-b | 用户态 ASLR 强化：栈 / 堆 / mmap 基址随机化 | 仅 load_bias 一处 |
| 53-c | 堆加固：guard page + canary + 溢出检测 | 无 |
| 53-d | 越界检测工具链（静态/动态）纳入 check.sh | 无 |

### 🔵 第54刀 · 动态加载与可观测性

| # | 任务 | 现状 |
| --- | --- | --- |
| 54-a | `dlopen`/`dlsym`/`dlclose` 运行时加载 | 仅 `DT_NEEDED` 启动时加载，全仓库无 `dlopen` |
| 54-b | trace ring buffer：可导出的调度/IPC/内存事件流 | 5 处提及，无统一事件环 |
| 54-c | profiling：可直接读取的调度延迟/上下文切换统计 | 3 处提及，非公开产物 |

### 🔵 第55刀 · 测试与质量闸

| # | 任务 | 现状 |
| --- | --- | --- |
| 55-a | sanitizer（ASan/TSan 语义等价）接入 host 测试 | 无，且 `no_std` 需自建插桩 |
| 55-b | 集成测试框架与用例目录 | 无 `tests/` 目录 |
| 55-c | 覆盖率统计（`llvm-cov` 等） | 无 |
| 55-d | 回归基线快照机制：每刀变更前后性能/验收自动对比 | 无 |

### 🔵 第56刀 · 安全隔离

| # | 任务 | 现状 |
| --- | --- | --- |
| 56-a | `seccomp` 式系统调用白名单沙箱 | **零实现** |
| 56-b | cgroup 式资源分组与限额 | **零实现**（依赖 51-e RLIMIT） |

### 🧭 全局排序与实施建议

本节共 6 组约 **100 项**，横跨信号、内存、存储、网络、安全、测试六个面。
若目标是一次性全部落地，建议顺序与理由：

```
第51刀 进程控制面   ← 缺口最大，且是后续多项的前置（job control 依赖信号）
第45刀 内存地基     ← 一切的性能基础
第52刀 FS 完整性    ← 依赖 48 的存储改造
第46刀 地址空间     ← KPTI 与 53 用户态加固的前置
第47～49刀 可靠性    ← TCP / 存储 / 安全
第50～53刀 纵深防御  ← 依赖前述
第54～56刀 工程化    ← 测试与隔离，最后收
```

注意事项：

- **信号（第51刀）与调度器耦合最深**，会触及 MLFQ 唤醒路径与 `ProcessState` 迁移，
  需配 SMP4 压测回归，否则易重演 owner/state 双源真相类问题。
- **KPTI 之前必须先有 ASID 与通用 VM API**，否则第50刀无法实施。
- **第55刀（测试基建）建议提前**，否则上述每项改动都缺少自动对照面。
- 全部落地预计触及 `zero-abi`（冻结合同），**每次新增系统调用都需同步 ABI 一致性测试**。
## ✅ 2026-10-16 · 第45刀 a：物理页分配器水位线

| 项 | 值 |
| --- | --- |
| 改动 | `alloc_page` 两级查找：先查上次命中的位图字，为满才完整扫描 |
| mm-host-tests | 42/42，耗时 **5.30s → 0.22s** |
| 零微内核 | 224/224 |

位图最多 1M 页 = 16384 个 u64 字，早前每次分配都从头扫到尾，且全程持全局锁。

**游标只是提示，不是状态** —— 当前字无可用位就回落到全扫描，
所以分配结果与原实现逐位等价，也不存在绕回死循环。

> 首版曾把回绕写成 index == start；在 reserved = 4096 页（跨 64 个满字）时
> allocator_serves_all_zero_words 死锁超过 60 秒，已废弃。
> **教训：优化必须先有正确性护栏，测试通过才进主干。**

### 环境备注

tools/check.sh 的 57 项中曾有 1 项失败，原因是项目目录 3360 MB 超过
3072 MB 的构建锁上限（xtask purge 清理后恢复）。**与代码无关。**
## ✅ 2026-10-16 · 验收基础设施修复（44/44 全绿）

**基线里剩下的失败，多半不是系统缺陷，而是验收脚本自身的问题。** 这一刀把
「脚本故障」与「系统故障」彻底分开。

| 问题 | 表现 | 真实根因 |
| --- | --- | --- |
| K40 pkgtest × 3 | `install failed: network` | **宿主 8443 被系统组件占用**（bind 失败但 lsof 查不到属主），`s_server` 静默退出 |
| 全矩阵 | 日志只有 UEFI 固件错误 | **非交互 shell 的 PATH 不含 Homebrew bin**，QEMU 解析失败 |
| K40 时序 | 偶发 bind 失败 | 端口检查与 `s_server` 启动之间的竞态 |
| K36/K37 SMP4 | 假 FAIL | 断言字符串过时（`online=4` vs `requested=3 online=4`）+ 日志未落盘 |

### 修复要点

- **pkgtest 候选端口**：系统无参数传递、无环境变量，端口无法注入，
  故 `pkgtest` 按序尝试 `8443 / 8444 / 18443`，任一可用即通过。
- **QEMU 路径回退**：`PATH` → `/opt/homebrew/bin` → `/usr/local/bin`。
- **端口探测用 `bind` 而非 `connect_ex`**：`openssl s_server` 的成败取决于 bind；
  实测 `connect_ex` 对被 DROP 的端口返回 60 而非 0，会给出错误结论。

### 实测

| 矩阵 | 修复前 | 修复后 |
| --- | --- | --- |
| hardware-acceptance | 36/45 | **44/44** |
| mm-host-tests | 42/42 | 42/42（未变） |

> **教训**：分配器水位线游标改动曾让 `allocator_serves_all_zero_words` 死锁，
> 已回滚。**未验证的改动不进主干**——这比多一项优化更重要。
## ✅ 2026-10-16 · P0 修复完成（第 0 刀）

**blkdrv 后端探测不验证可用性 —— 已修复并回归钉死。**

| 项 | 状态 |
| --- | --- |
| P0-1 `probe_backend` 增加读写验证 | ✅ 内核侧加 `healthy` 标志，`self_test()` 返回真实结果 |
| P0-2 绑定失败回退到下一候选设备 | ✅ `is_ready()` 要求 `ready && healthy`，自动回退 NVMe |
| P0-3 未挂载时明确报错 | ✅ `NotMounted` → `ERR_DEVICE`（原 `ERR_INVALID`，与参数错误混淆） |
| P0-4 回归断言 | ✅ 新增 3 条断言 + 4 项 host 单测（220 → **224**） |
| P1-1 脚本竞态 | ✅ 加 `settle_log()` |
| P1-2 断言字符串过时 | ✅ SMP4 期望 `online=4`，实际 `requested=3 online=4`（2 处） |

### 实测效果

```
K40 修复前：blkdrv: passthrough backend ready (VirtIO blk ...)   ← 坏设备
           Zero OS zfsd mount FAILED

K40 修复后：blkdrv: passthrough backend ready (NVMe via kernel svc 7/8)
           Zero OS zfsd (default fsd) online
           fstest: PASS - fsd block-backed volume verified end-to-end
           fsdemo: PASS (mkdir/list/unlink/rmdir tree semantics)
```

| 矩阵 | 修复前 | 修复后 |
| --- | --- | --- |
| hardware-acceptance | 36/45 | **41/44** |
| hardening-acceptance | 34/36 | **36/36** ✓ |
| 微内核 host 测试 | 220 | **224** |

> 断言总数由 45 调整为 44：删除 `K40 no virtio-blk backend` ——
> QEMU 的 `-netdev user` 会附带 virtio-blk（网络后端需块设备存密钥），
> 其枚举属预期行为；真正该断言的是「blkdrv 没绑定它」，已由新断言覆盖。

### 剩余失败（3 项，归属第47刀）

`K40 ZeroPkg install / launch / full E2E` —— `pkgtest: install failed: network`。

调用链：`pkgd:28` → `libpkg:386 install_url()` → `libweb::https_get_with_ca()` →
`Error::Network`。网络层正常（`netd: DHCP bound`），属 netd TLS/大响应传输路径，
与存储无关。**这是第47刀 TCP 可靠传输的第一个真实缺陷证据。**
### 📌 实施约束（2026-10-16 审计确认，动手前必读）

#### 约束一：syscall 号位冻结

- 号段现状：**0–28 全用，29–39 空洞保留，40–75 连续**；最高已用 **75 = NetDiag**，下一个可用 **76**。
- 新增 syscall 需**三处手工同步**（非宏）：
  `libs/abi/src/lib.rs` 枚举 → `microkernel/src/trap.rs` `decode_syscall` → `microkernel/src/syscalls.rs` `handle` → `userland/userlib` 封装。
- ⚠️ **隐藏地雷**：`tools/fuzz-syscall/tests/decode_table_fuzz.rs` 断言 `40..=75` 必须解码、
  `76..=1023` 必须为 None。新增 76 会**直接打红**，必须同步改边界。
  同类断言另见 `trap.rs:1141` 的 `decode_syscall_table` 内嵌表。

#### 约束二：信号机制已有骨架（并非从零）

第九刀「信号位图最小版」已落地：

- `zero_abi::signals`（SIGILL/SIGTRAP/SIGBUS/SIGFPE/SIGSEGV）已定义；
- `ProcessRecord.pending_signals: u16` 位图**已存在**（`process.rs:234`），投递用 `|=` 累积；
- EL0 故障的**致命信号投递路径已通**（`trap.rs` → `deliver_fatal_signal` → `exit_current_with_status`）。

**缺的是**：kill 注入 / sigaction / sigreturn / 阻塞式可挂起信号。
故 51-a 是「补齐消费方」而非「新建投递机制」，风险低于预期。

#### 约束三：进程状态迁移的 SMP 纪律

- `ProcessState` 五态：Runnable / Running / Blocked / Dying / Zombie。
- 所有迁移**必须在 `PROCESS_TABLE` 单锁内完成，且与 `PROCESS_OWNER` 释放在同一临界区**
  （无「Running 无 owner」也无「Runnable 有 owner」的非法组合）。
- ⚠️ **禁止使用 `set_state` / `set_state_slot`**（`process.rs:738/749`）——它们不做 owner 纪律，
  会破坏该不变量。信号注入必须走 `request_wake` 之类带断言的转换。
- ⚠️ **持表锁时不得调 `restore_frame` / 切地址空间**；`deliver_fatal_signal` 是正确写法范例。

#### 约束四：信号不应复用 `ipc::Message`

- `Message` = `{code: u32, payload: [u8;128]}`，语义是**通道队列里的排队数据报**（需 channel id + ACL + wait 登记）。
- POSIX 信号是**定向单 pid 的位图置位**，标准信号不排队（同号多次投递只置一位）。
- `Message` 连来源 pid 字段都没有（发送者 pid 是 receive 的返回值）。
- **结论**：沿用 `pending_signals` 位图 + 新 syscall 号位，不走 IPC。

#### 约束五：符号链接必须先解决磁盘格式兼容

- `InodeKind::Symlink` 当前**仅是 1 字节判别值，无目标路径字段、无 API、无解析逻辑**（全仓零行为实现）。
- ⚠️ **`metadata.rs` 的 checkpoint 无版本号**：MAGIC `"ZMDT0001"` 是唯一版本线索，代码无版本分支。
- `decode` 末尾强制校验游标正好耗尽（`metadata.rs:219-221`），失败即整 bank 判废并静默回退。
  因此**在条目头插入 symlink target 字段会双向静默破坏旧卷**。
- 安全做法二选一：(a) MAGIC 升到 `"ZMDT0002"` 并给 `load_bank` 加版本分派；
  (b) 保持头部不变，把 target 追加到条目尾部，用 `payload_len` 做可选扩展。
- 符号链接展开落在 `fs-zfs` 的 `canonical_path`，**必须保留 `MAX_PATH=112` 上限与 `.`/`..` 拒绝**，
  否则引入目录穿越漏洞。
### 总体路线

```
P0/P1 缺陷修复
   ↓
第45刀 内存地基 ──── 一切的性能基础（物理分配器/堆/slab）
   ↓
第46刀 地址空间 ──── KPTI 的前置（VM API / ASID / shootdown）
   ↓
第51刀 进程控制面 ── 缺口最大（信号/进程组/RLIMIT，当前为零）
   ↓
第52刀 FS 完整性 ← 依赖第48刀存储改造
第47刀 TCP 可靠 ┐
第48刀 存储持久 ┘├─ 功能可靠性
第49刀 内核安全 ┘
   ↓
第50刀 KPTI/KASLR ┐
第53刀 内存安全   ┘├─ 纵深防御（依赖 46/51）
   ↓
第54～56刀 动态加载 / 可观测性 / 测试闸 / 隔离 ── 工程化收口
```

第50刀 KPTI 排后并非低估：它依赖第46刀的 ASID 与通用 VM API，改动面最大，
且属纵深防御而非当前正确性缺口。

---


## 2026-08-27 · 第35～44刀：真机硬件链与可靠性收口（当前最高权威状态）

> 第20～34刀全栈基线继续成立；本节记录其后的 PCIe/ITS/IOMMU/xHCI/NVMe、
> 电源与生产级硬化，以及这轮真正解决的 SMP 调度/栈/futex 并发根因。

### 最终总闸
- 第35～40刀 QEMU 真设备专项：`scripts/hardware-acceptance.sh --no-build` **45/45 ALL PASS**。
- 第41～44刀生产硬化专项：`scripts/hardening-acceptance.sh --no-build` **36/36 ALL PASS**；
  shutdown/reboot（含 runner clean-exit）、双 root-port、4KiB NVMe、多 namespace、USB hub/hotplug/recovery 均有真设备路径证据。
- 基础兼容矩阵：`scripts/acceptance.sh --no-build` **15/15 ALL PASS**。
- 全仓质量闸：`tools/check.sh` **57/57，0 失败**（host、AArch64 bare-metal、PIC/KASLR、UEFI、单测、kernel build）。
- SMP4 压力：`scripts/stress-loop.sh 3` **3 轮 × 6/6 + online=4 + zero fault**；每轮 QEMU 自身 rc=0。
- 额外根因验证：owner/state 收口后连续 **20/20 SMP4 冷启动**无 `unknown sync`、ownership mismatch、panic。
- 当前最终 ISO（2026-08-27 11:30:31）：SHA-256
  `8cc3ced62264c6bf80d4f7250734d3ec6dbaa799e2ab3a44194db7c4e37f344f`；
  `rootfs.bundle` SHA-256 `f4e6478ef018f5e3ec262b0cfaa7d3d016769b0564ac19c4d9201200ada8c46d`。

### 本轮关键可靠性结案
- **SMP4 随机 EC=0 真根因**并不是 AArch64 随机“不认识合法 B/RET”：
  1. idle CPU 曾继续睡在最后一个进程的 `KERNEL_STACKS[slot]` 上，进程迁核后两 PE 会同时写同一内核栈；
  2. yield/block/exit 曾在旧 PE 仍使用 process stack 时就发布 Runnable/Blocked/Zombie，允许新 PE 过早复用同一栈；
  3. `ProcessState` 与独立 `FRAME_OWNER` 是双源真相，可观察到 `Runnable + old owner` 的非法组合。
  现已改为 **per-CPU scheduler/idle stack + 离栈后再发布状态 + owner/state 在 PROCESS_TABLE 同锁原子迁移**。
- **SMP FPU/NEON** 改为多核 eager save/load；副核显式安装 VBAR/CPACR/MAIR/TCR/SCTLR/TTBR；
  nested EL1 异常切 per-CPU scratch TrapFrame；ELF/共享库可执行页补 AArch64 D-cache→I-cache 发布。
- **futex/UserMutex SMP 死锁**双根因已修：FutexWait 在 futex 表锁内二次检查用户字，关闭 wake-before-register；
  UserMutex 慢路径持有 state=2 维持 waiter wake chain。最终 SMP4 `mutextest` 三 worker 全退出，`counter=1500`。
- **验收 runner** 也完成工程化：硬件矩阵显式 `-boot order=d`；stress 每轮独立盘并由 `Ctrl-A x` 让 QEMU 自退出，
  不再产生 orphan QEMU/磁盘锁假失败；K41 reboot runner 同样不再泄漏后台 QEMU。

## 2026-08-26 · 第20～34刀：现代 OS 全栈闭环（当前权威状态）

> 基线：第十九刀的 COW/TLBI、free-list、SMP、securityd、useralloc 与
> 15/15 收口全部保留。第20～34刀在此稳定基线上连续实施；本节覆盖
> **平台 → 图形 → 输入 → IPC/共享内存 → 时间 → 网络 → TLS → 包管理 →
> PIE/动态链接 → 内核 KASLR → ZFS → 音频 → VirGL 3D** 的当前事实。

### 总览

| 刀次 | 交付 | 当前证据 |
| --- | --- | --- |
| 20 | ACPI 平台描述收尾 | MADT→SMP/GIC、GTDT→timer、FADT→PSCI、MCFG→ECAM；`-smp4` 实机枚举 |
| 21 | Display Foundation | UEFI GOP handoff、framebuffer logger、UTF-8/CJK glyph ROM、2D primitives |
| 22 | VirtIO GPU 2D | modern/legacy virtio-mmio、resource/backing/scanout/transfer/flush；640×480/800×600 实机 |
| 23 | Input Stack | 多 virtio-input 设备、keyboard+tablet 共用事件 ring、`inputd` |
| 24 | WindowServer | create/destroy、z-order、clip、hit-test、drag、SHM surface 协议 |
| 25 | Secure SHM | opaque handle、owner/holder/grant/map/refcount；物理地址继续 fail-closed |
| 26 | Time | architected monotonic、PL031 realtime、absolute deadline；TTL 迁到真实单调时间 |
| 27 | Network | `netd`: ARP/IPv4/ICMP/UDP/TCP/DHCP；targeted IPC、流控、SHM bulk I/O |
| 28 | DNS/TLS/HTTP | DNS A + TLS 1.3 + cert hostname/time 验证 + HTTP/1.1；真实 HTTPS GET PASS |
| 29 | ZeroPkg | HTTPS download → SHA/Ed25519 → ZFS temp → atomic rename → verify/launch/remove，ALL PASS |
| 30 | PIE / Dynamic Runtime | ET_DYN、ASLR load bias、AArch64 RELA、DT_NEEDED、最小共享库 loader |
| 31 | Image KASLR | kernel ET_DYN、UEFI 随机选址、bootloader relocation、符号/provenance 重定位保持 |
| 32 | ZFS Runtime | 默认 `fsd` 已切到 `zero-fs-zfs`；持久 metadata/allocator/rename/remount |
| 33 | Audio | VirtIO Sound PCM 48k/S16/stereo、`audiod`、真实 playback WAV 回归 |
| 34 | GPU 3D | VirtIO GPU VirGL capset/context/resource/submit/readback；真实 clear+DMA readback PASS |

### 最终验收闸（第20～34刀收口）
- `tools/check.sh` 已扩展覆盖新全栈 crate + AArch64 bare-metal + PIC/KASLR + UEFI：**57 通过 / 0 失败**。
- 基础兼容矩阵：**15/15 ALL PASS**（登录/安全/COW/sleep/thread/futex/raw-block/ZFS tree 全绿）。
- `-smp 4` 压力：**3 轮 × 6/6**，每轮 MADT 四核 `online=4`，fork/thread/futex/ZFS/security 全绿。
- 专项：HTTPS TLS1.3、ZeroPkg ALL PASS、PIE RELA + shared library PASS、VirtIO Sound playback PASS、VirGL CLEAR+DMA readback ALL PASS。
- QEMU host 已升级至 **11.1.0**；macOS bottle 的 2D-only fallback 与隔离 virglrenderer 真 3D 两条路径均已验收。

### 最终交付阶段额外结案
- **UEFI 大文件读取**：`read_to_vec` 改为 read-exact 循环，不再假设一次 `File::read` 会填满整个 kernel；同时消除未初始化尾部。
- **ET_DYN/PT_DYNAMIC**：lld 可让 `PT_DYNAMIC.p_filesz` 覆盖后续 GOT/padding，不能要求 segment size 必须是 16 的倍数；现按完整 `Elf64_Dyn` 逐条读并在 `DT_NULL` 截断，尾 padding 合法忽略。内核/用户 PIE parser 都有同规则，新增 host 回归。
- **ZFS wire path**：第32刀切默认 ZFS 后，旧 FS ABI 的 root-relative path 与 ZFS core 的 absolute path 契约冲突；现统一在 zfsd 边界 canonicalize，拒绝 `.`/`..`/空组件，旧 shell 与 ZeroPkg 同时兼容。
- **raw block diagnostics**：ZFS 已消费整盘，历史 LBA60000 不再是“卷外安全带”。默认 blktest 改为设备最后一个 4KiB block，zfsd 永久保留该块；当前 32MiB 测试盘对应首 LBA **65528**。
- **VirtIO blk timeout**：完成等待由固定 100k spin 改为 monotonic deadline，避免 QEMU/宿主调度速度变化造成假超时。
- 最终正式 ISO 上再次确认：`blktest LBA=65528 PASS`、`fstest PASS`、`fsdemo PASS`；KASLR/RELA 正常。

### 第20刀 · ACPI 平台描述：✅
- UEFI ACPI 2.0 GUID 使用权威常量；RSDP/XSDT/MADT 的未对齐读取全部按字节解码。
- MADT CPU affinity 真正进入 SMP；GICD/GICC 参数进入 GIC；GTDT timer PPI 进入 timer；
  FADT ARM boot flags 决定 PSCI HVC/SMC；MCFG 保存 PCI ECAM segment。
- QEMU `-smp 4` 证据：`acpi: cpus=4 ... timer_irq=30 psci=Hvc ecam_segments=1`，
  cpu1/2/3 由 MADT MPIDR 拉起。无 ACPI 时 legacy 常量回退仍保留。
- AML 仍**明确不做**：只有真机设备/电源管理出现实际需求才立项。

### 第21～24刀 · 图形/输入/窗口：✅
- bootloader 把 GOP framebuffer 的 base/size/stride/pixel format 交给内核；display logger 与 PL011
  双 sink。第一版即支持 UTF-8：构建期从现有中文日志生成 CJK 16×16 glyph ROM，运行时不借宿主字体。
- VirtIO GPU 2D 支持 GET_DISPLAY_INFO、CREATE_2D、ATTACH_BACKING、SET_SCANOUT、
  TRANSFER_TO_HOST_2D、FLUSH；GPU 与 logger 的锁域已审计，禁止持 GPU mutex 进入会触发 flush 的日志路径。
- virtio-input 改为多设备模型：keyboard/tablet 同时挂载；`inputd` 统一 key/rel/abs/button/wheel 事件。
- WindowServer 软件 compositor 已有 clip/z-order/hit-test/drag，应用 surface 采用 SHM handle 协议；
  Terminal/IME overlay 的 ABI 边界保留，完整桌面 UI 仍可在此基础上继续长，不再需要改内核显示协议。

### 第25刀 · Shared Memory / Shared Surface：✅
- SHM 是内核对象：物理页集合 + owner + holders + per-process mappings；EL0 只见 opaque handle/VA。
- owner 必须 `shm_grant(handle,target_pid)`，目标才能 map；进程退出自动移除 holder/mapping 并回收。
- `ShmPhys` 永久拒绝，DMA/设备不能通过物理地址泄漏绕过 capability。
- FS/net bulk 路径已实际消费该模型；曾发现的“只把 handle 数字发给 fsd、未 grant”问题已修为
  response sender PID 学习 → 显式 grant → 服务 map/use/release。
- bootfs 同时改成全局 immutable cache：每进程只 RO retain/map，同一 5～9MiB bootfs 不再每 spawn 复制一次。

### 第26刀 · Time / RTC / Deadline：✅
- monotonic 来自 ARM architected counter；realtime 来自 PL031；`ClockGet/SleepUntil` 已冻结 ABI。
- tick→ns 转换与 deadline round-up 有 host 测试；Sleep/调度/SMP 下单调不倒退。
- capability TTL 以真实 monotonic deadline 计，不再取决于“进程调用了多少次 syscall”。
- TLS 证书有效期直接消费 realtime；随机数不拿时钟冒充，统一走 VirtIO RNG/GetRandom。

### 第27刀 · Network Stack：✅
- 修正 VirtIO Net wire：RX/TX 带 `virtio_net_hdr`；legacy v1 显式写 GuestPageSize=4096；
  IRQ + 主动 poll 双完成路径，正确性不依赖中断恰好送达。
- `netd` 在 EL0 实现 Ethernet/ARP/IPv4/ICMP/UDP/TCP/DHCP；内核只保留 capability-gated raw frame/MAC。
- 新增 targeted IPC reply 与真正非阻塞 TryReceive；多事件源 daemon 不再被控制面阻塞。
- MLFQ 修过 polling-daemon 饥饿：voluntary yield 会下沉一级，sleep/block 唤醒仍回高优先级。
- TCP 窗口按 RX buffer 剩余空间真实通告；只 ACK 实际接纳字节，应用 drain 后发 window update。
  大流量已在 pcap 看到窗口收缩到个位/几十字节后再次打开；SHM bulk recv 解除 128-byte IPC 吞吐瓶颈。
- QEMU usernet 实机：DISCOVER/OFFER/REQUEST/ACK 完整，`netd: DHCP bound`。

### 第28刀 · DNS / TLS 1.3 / HTTP：✅
- `libweb` 提供 DNS A、TCP adapter、HTTP/1.1 framing 与 TLS 1.3。
- TLS 使用成熟 `embedded-tls`，P-256/AES-GCM/SHA-256；公网链/hostname/time 验证开启。
- 本地开发 repo 的 IP literal 证书改成标准 `iPAddress SAN`，额外严格检查 `10.0.2.2`，
  不是 NoVerify/宽松 CN 绕过；CA 仍做链与签名验证。
- VirtIO RNG → syscall 56 为 ECDHE/ASLR/KASLR 提供统一真 entropy。
- QEMU NAT 实机 `webtest`：`DNS PASS`、`HTTPS TLS13 PASS`；pcap 有真实 TLS 1.3/HTTPS 流量。

### 第29刀 · ZeroPkg in-OS：✅
- `pkgd` 是受保护服务；客户端需 `CAP_PKG_CLIENT`，pkgd 自身持 `CAP_SPAWN_APP`。
- v2 package：canonical SHA-256 + Ed25519；securityd 仅信任内置 `origin=zero-os` 公钥并验证签名。
- 事务：HTTPS → parse/hash/signature → `/Applications/.pkg-*` → ZFS write+readback → atomic rename → registry。
- 公共 PKG IPC 回归客户端实际走：
  `INSTALL PASS → VERIFY PASS → LIST PASS → LAUNCH PASS → REMOVE PASS → ABSENT PASS → ALL PASS`。
- 大包下载同时推动 TCP 真流控 + SHM bulk；安装不再依赖“大缓存一次吞完”。

### 第30刀 · Dynamic Runtime / PIE / Shared Libraries：✅
- user ELF loader 支持 ET_EXEC + ET_DYN；PT_DYNAMIC、DT_RELA/RELASZ/RELAENT、DT_NEEDED、dynstr。
- AArch64 `R_AARCH64_RELATIVE` 与共享库符号重定位有明确拒绝/支持矩阵，未知 relocation fail-closed。
- PIE load bias 从 VirtIO RNG 选 2MiB 对齐随机槽，避开 heap/bootfs/stack；spawn/exec/SpawnImage 共用。
- `tools/dynlink-test`: `libzero.so + zero-dynapp`；实机连续启动看到不同 PIE bias，
  `pietest: RELOC PASS` 与 `dynapp: SHARED PASS` 均重复通过。
- 自定义 `aarch64-unknown-none-pic` target 把 PIC codegen 固化进构建，不靠临时 RUSTFLAGS。

### 第31刀 · Kernel Image KASLR / Hardening：✅
- kernel 自身改为 ET_DYN/PIC；UEFI loader 随机挑选合法 2MiB 槽，加载后应用 RELA，再跳 runtime entry。
- UEFI RNG 可用时作为 KASLR entropy；无协议时有显式 weak fallback 警告，不伪装强随机。
- 多次实机看到不同 base（例如 0x4f600000 / 0x50600000 / 0x55400000）；当前镜像约 300+ relocation 全部应用。
- kernel runtime range、物理分配保留区、符号 sink/backtrace、build provenance 都按 runtime bias 工作。

### 第32刀 · ZFS Runtime Migration：✅
- 默认 `fsd` service descriptor 已指向 `/System/Core/zero-fs-zfs`；旧 `zero-fsd` 仅保留 legacy/回归资产。
- 修复 Volume 曾把 `cluster_size` 误当“总 block 数”的容量 bug，allocator 现在消费真实 BlockDevice block count。
- metadata 采用持久化双 bank/校验与 remount 恢复，目录/rename/allocator 状态跨挂载；package 原子 rename 真走该路径。
- bootfs 与 persistent rootfs 已分层：早期服务来自 boot bundle，持久应用/registry 在 ZFS 卷，kernel ELF 不再背用户态 blob。

### 第33刀 · Audio Stack：✅
- VirtIO Sound PCM：设备枚举、SET_PARAMS/PREPARE/START/STOP、48kHz S16 stereo playback。
- `audiod` 是唯一音频策略服务，应用走 IPC；测试客户端不需要设备 capability。
- 真 QEMU 回归：`driver: virtio-sound online ... pcm=48k/S16/stereo`，`audiotest: PLAYBACK PASS`；
  宿主 file audiodev 捕获 `/tmp/zero-audio-final.wav`，不是“命令返回 OK”式假验收。

### 第34刀 · VirtIO GPU VirGL 3D：✅
- feature negotiation：`VIRTIO_GPU_F_VIRGL` / CONTEXT_INIT；GET_CAPSET_INFO/GET_CAPSET；
  context create/destroy、RESOURCE_CREATE_3D、backing attach/detach、ctx attach/detach、SUBMIT_3D、fence、readback。
- syscall 62～70 以 `CAP_DISPLAY` 门控：EL0 可查询 capset、管理 ctx/resource、提交 opaque VirGL dword stream，
  但 virtqueue/DMA 生命周期仍由内核掌握；未知/无 3D backend 时返回 NotSupported，2D 不受影响。
- `gputest` 做硬验收：64×64 B8G8R8X8 render target → VirGL surface/framebuffer → CLEAR 红色 →
  TRANSFER_FROM_HOST_3D → guest backing → 检查 BGR 像素，最终 `VIRGL CLEAR+READBACK PASS / ALL PASS`。
- macOS Homebrew QEMU 已升级到 11.1.0（仅连带其 `p11-kit/libssh` 依赖）；该 bottle 仍未编 `virtio-gpu-gl`，
  因此 stock 路径实测 `host backend is 2D-only` + `gputest: HOST 3D UNSUPPORTED`，2D fallback 正常。
- 真 3D 验收在隔离 Debian arm64 QEMU 10.0.11 + virglrenderer 1.1.0 + Mesa llvmpipe(OpenGL 4.5) 上完成：
  `VirGL 3D feature online capsets=2`，capset1=VirGL(308B)、capset2=VirGL2(1384B)，随后 gputest 全绿。
  隔离 Docker 容器/镜像已删除并停止，不成为项目运行依赖。

### 正常启动服务与回归服务
- 正常 launchd 自启：`blkdrv / fsd(zfsd) / securityd / inputd / windowserver / netd / pkgd / audiod`
  （service-controller/ipcrouter 若 blob/策略允许仍按 registry 管理）。
- `webtest / pkgtest / pietest / dynapp / audiotest / gputest` 为**手动回归资产**，不会污染正常开机。
- 第35～44刀已把 PCIe/ITS/IOMMU/xHCI/NVMe/电源与生产硬化全部落地并验收；当前 STATUS **没有登记中的下一刀**。
  AML 继续是“出现明确真机需求再立项”的按需能力，不属于未完成登记项。

## 第35～40刀：✅ 已完成（2026-08-27 最终封板）

### 第35刀 · PCIe Core
- MCFG → ECAM → bus/device/function 枚举；Vendor/Device/Class/Subclass/ProgIF/multifunction；
- PCI capability / PCIe extended capability；32/64-bit BAR 解析与 sizing；
- bridge/root-port 最小枚举；BAR/MMIO 资源以 capability/lease 边界暴露给 EL0 driver。
验收：QEMU `pci-testdev` + virtio-pci 可枚举，BAR 读写 PASS。

### 第36刀 · GICv3 / ITS / MSI-X
- GICv3 Redistributor / per-CPU GICR；LPI；ITS command queue；device/event ID；
- PCI MSI / MSI-X capability、table/PBA、ITS doorbell 与 IRQ affinity。
验收：`-machine virt,gic-version=3,its=on,msi=its` 下 PCI 设备 MSI-X 真中断，`-smp4` 回归全绿。

### 第37刀 · VirtIO PCI Transport
- VirtIO PCI common/notify/ISR/device config；modern feature negotiation；MSI-X queue vector；
- 现有 blk/net/gpu/sound device logic 复用，不复制一套 driver。
验收：QEMU 只挂 `virtio-*-pci`，现有块/网/图形/音频链继续工作。

### 第38刀 · IOMMU / IORT / SMMUv3
- IORT parser；SMMUv3 discovery；stream ID/domain/IOVA allocator/map/unmap/fault；
- DMA object 与 secure SHM/capability 对齐，设备不能直接拿任意 PA。
验收：`iommu=smmuv3` + `iommu-testdev`，合法 IOVA DMA PASS，未映射 IOVA 触发 fault。

### 第39刀 · USB Core / xHCI / HID
- PCIe xHCI：command/event ring、ERST、slot/context、control/interrupt transfer；
- USB descriptor / enumeration；HID keyboard/mouse/tablet；事件接现有 inputd ABI。
验收：移除 virtio-input，使用 `qemu-xhci + usb-kbd + usb-tablet`，WindowServer 键鼠路径继续工作。

### 第40刀 · NVMe
- PCI NVMe controller、admin queue、Identify、namespace、I/O queue、PRP、read/write/flush、MSI-X；
- blk service 后端抽象为 VirtIO Blk / NVMe，ZFS 上层无感。
验收：不挂 virtio-blk，只挂 QEMU NVMe，ZFS `fstest/fsdemo` 与包管理存储链通过。

> 第35～40刀的共同约束：优先复用现有 capability/SHM/IPC/device-service 边界；QEMU 有真设备则必须实机验收，禁止只以 host parser test 判定完成。


### 第35～40刀收口阻塞项 · SMP4 偶发 `EC=0`：✅ 根因结案
- **历史表象**：曾在合法 AArch64 `B/RET` 或 SVC 返回点观察到 `EC=0`，进程/PC 不固定；仅按 EL0/EL1 分流处置并不构成根因修复。
- **最终第一现场**最终在 owner guard 与 EL1 诊断下被抓住：idle PE/旧 PE 与迁移后的新 PE 会复用同一 process kernel stack；
  随后又直接抓到 `TrapFrame double ownership`，证明问题是跨核调度 handoff 生命周期，而非指令解码。
- **最终修复**：
  1. 每 CPU 独立 64KiB scheduler/idle stack，WFI 永不借进程 kernel stack；
  2. yield/block/exit 先切 scheduler stack，再 detach/publish 进程状态；
  3. 删除独立 `FRAME_OWNER` 双源状态，`ProcessState + owner_cpu` 在 `PROCESS_TABLE` 同锁完成 claim/release；
  4. scheduler stack AArch64 asm 使用固定寄存器约束，避免 LLVM clobber/分配歧义；
  5. 异常入口继续保留 ESR/FAR 快照与 per-CPU scratch TrapFrame，作为长期 crash diagnostics。
- **并发后续根因**：SMP4 `mutextest` 还暴露 FutexWait wake-before-register 与 UserMutex waiter-chain 丢失，两者均已修复。
- **最终证据**：20/20 SMP4 冷启动零 fault；`stress-loop.sh 3` 三轮均 6/6 + `online=4` + zero fault；
  第35～40刀当前最终镜像 `hardware-acceptance` **45/45**。本阻塞项正式关闭。


## 第41～44刀：✅ 全部完成（2026-08-27）


### 第41刀 · Power Management / Firmware Runtime：✅
- 新增动态 `CAP_POWER` + syscall72；Shell `shutdown/reboot` 必须先经 securityd 的 admin 身份签发，未登录请求明确拒绝。
- PSCI `SYSTEM_OFF/SYSTEM_RESET` 按 FADT conduit 走 HVC/SMC；reboot 另解析 FADT Reset Register 作为 firmware 返回后的 fallback。
- 电源切换前做 block flush/NVMe shutdown；idle/WFI 已迁到 per-CPU dedicated scheduler stack。
- 验收：未登录 shutdown DENY；root shutdown 让 QEMU rc=0 真关机；reboot 后观察到第二次 EDK2 firmware banner。

### 第42刀 · PCIe Real-Hardware Hardening：✅
- bridge/root-port 解析 primary/secondary/subordinate bus、memory/prefetch window；保留多个 MCFG segment/高 ECAM 支持。
- 未分配 downstream BAR 可在明确 bridge window 内安全 relocation；root bus 无 `_CRS` 时不猜平台资源。
- PCIe FLR、secondary bus reset、AER status clear 与 refresh path 已落地。
- 验收：两个 QEMU root-port 分别挂 NVMe/xHCI，bus1/bus2、16MiB memory window、64-bit prefetch window 均被解析；
  两个下游驱动与各自 reset/recovery 全绿。

### 第43刀 · NVMe Production Hardening：✅
- Active Namespace List + 多 namespace metadata；MDTS；Number of Queues；最多一套 per-CPU I/O SQ/CQ/bounce/PRP path。
- 公共 block ABI 保持 512B sector；4KiB native namespace 的边缘访问走 RMW，未触碰字节保持不变。
- timeout 记录 qid/cid → Admin Abort → CC.EN controller reset/re-init；失败才升级 PCIe FLR，随后重建 queues/namespaces。
- 验收：QEMU ns1=4KiB + ns2=512B，`io_queues=4`、`512B ABI/NATIVE RMW SELFTEST PASS`、
  `RESET/RECOVERY PASS queues=4 namespaces=2`，且 ZFS `fstest/fsdemo` 在 4KiB active namespace 上通过。

### 第44刀 · USB / xHCI Production Hardening：✅
- scratchpad、controller teardown/rebuild、FLR recovery、root Port Status Change、hub port poll/hotplug 全部落地。
- USB2 hub class：descriptor、port power/reset/status、Route String、LS/FS behind HS hub 的 TT Hub Slot/Port；递归枚举下游 HID。
- HID keyboard/mouse/tablet 继续注入原 input ABI；拔除会 Disable Slot 并释放 ring/report/context，防生命周期泄漏。
- 验收：`xHCI → hub → keyboard` route=0x1；QMP 真按键到 inputd；运行时 hot-add mouse route=0x2 再 hot-unplug；
  controller recovery 后仍保持 `hid=1 hubs=1`，全程无 kernel fault。

> 第41～44刀共同原则：优先把已经“能工作”的硬件链变成可长期运行、可恢复、可迁移到真机的工程实现；不以新增设备数量替代可靠性收口。
> 正式验收入口：`scripts/hardening-acceptance.sh --no-build`，当前 **36/36 ALL PASS**（含 K41 reboot runner clean-exit）。

## 当前里程碑（2026-08-24 · 第十~十四刀单日走完，四线并行+集成）

### 第十刀 内存现代化（实机全绿）
- **COW fork 闭环**：移除 bisect kill-switch 后共享只读克隆生效；
  实机 `copied=0`（34 共享 + 971 只读直映射），forktest PASS
- **pstore 双启动链路打通**：故障落盘→复位→bootloader 取回打印，
  靠 drill 注入实测验证；顺带修掉两个真 bug：
  ① Brk 来源判定改 SPSR.M 权威（内核态 BRK 曾误杀无辜进程）
  ② PSCI 功能号 0x84000008 是 SYSTEM_OFF 不是 RESET——"复位"实为关机，
     pstore 链路此前从未真正走通
- **blktest 回归修复**：第八刀收权后 Shell 无 CAP_BLOCK_DEV 被拒；
  最小授权补授单一位，验收清单恢复该项

### 第十一刀 调度与时钟（实机全绿，含三次深度排障）
- **MLFQ**：4 级反馈队列（4/8/16/32 tick），200 tick 全局提升防饥饿；
  yield 保级、唤醒归零；主机测试钉死判定矩阵
- **Sleep(ticks) 号位 25**：定时器轮 + 唤醒侧陷阱帧回写 elapsed；
  sleepdemo 实机：父睡 5 精确醒、子睡 12 elapsed=12 PASS
- **FPU 惰性保存**：FPEN=0b01 门 + EC=0x07 断链（fpu_trap_replay）+
  切换点降门（dispatch 统一 fpu_set_lazy_gate）；非 FP 用户零开销
- **排障战果（都是真雷）**：① stub 空帧跑通全程（TPIDR 未武装时放行
  中断）② idle 复活路径（陈旧 TPIDR 把 Blocked 进程 eret 回用户态）
  ③ FP 重放死循环（restore_context 重降门位）——修复=idle scratch 帧 +
  on_tick 守门 + 门位下移
- **分块让出**：基础设施就绪（SCHED_STARTED 安全闸 + chunk_yield_point）；
  两处插入点经锁域审计后缓用（spawn/fork 路径上游持表锁，放行即死锁）

### 第十二刀 文件系统成体系（实机全绿）
- fsd 目录树：显式目录标记槽（尾'/'），超级块 v1 不变免迁移；
  mkdir/rmdir/unlink/LIST 路径版；空段/点段拒绝在服务端权威判定
- shell 新命令：`ls`/`cat`/`mkdir` + `fsdemo` 九步树语义验收全过
- ZFS 选型结论落 docs/zero_file_system_spec.md：fsd 层扁平全路径+
  标记槽方案胜出，zfs-core 元数据树化延后立项

### 第十三刀 安全模型成型（实机全绿）
- capability 动态签发（号位 40-45）：Grant/Revoke/CreateChannel/
  SessionBegin/GetSession/SessionList；TTL 台账 + 活算模型
- 通道 RX/TX 权限位图（abi ChannelDesc 扩展，向后兼容）
- 登录会话：login/su/sessions/whoami；会话绑定防跨会话重放

### 第十四刀 可靠性冲刺
- GitHub Actions CI：主机测试 + 裸机构建双闸（.github/workflows/ci.yml）
- abi 解码模糊属性测试：LCG 2 万次轰击 decode 带契约
- 软看门狗：连续 600 tick 无 Running 进程告警一次（scheduler）
- 性能基线：scripts/perf-baseline.sh + docs/performance_baseline.md

## 实机验收现状（scripts/acceptance.sh，**15/15 ALL PASS**）

✅ shell-up / launchd-fsd / launchd-blkdrv / launchd-securityd / login-root /
secdemo / su-guest / sessions / forktest / blktest / fstest / sleepdemo /
fsdemo / threaddemo / mutextest。

### COW 历史回归：✅ 2026-08-25 已结案
`table_walk::COW_SHARED_FORK = true`。最终根因是父侧 BBM 后的 TLBI
operand 编码：`VAAE1IS` 接收页号而不是 byte VA，旧代码传 `va` 导致
陈旧 RW TLB 留存。修为 `va >> 12` 后，fresh 实机 COW 日志为
`copied=0` 且 sleepdemo/forktest/线程/文件链全绿。同期发现的内核堆
损坏另有独立根因：不可分裂的小尾巴形成 ghost gap，现亦有回归测试。

## 第十六刀（2026-08-24 · 三大件一气呵成）

### ✅ 动态进程槽
PROCESS_TABLE 改 Vec 按需生长至 256 槽（空洞复用优先）；full_reap
级联缓冲改堆分配（防 16KiB 栈压穿）；RUNQUEUE 容量同步 256。

### ✅ 线程模型（号位 26 CreateThread）
- ABI 冻结：x1=entry / x2=stack_top / x3=tls(TPIDR_EL0) / x4=arg；
  返回 tid（真 pid，WaitPid 原样 join）
- **组载体空间模型**：组内恰一条记录持有 addr_space，成员 None；
  address_space() 回退查找；exit/reap 时所有权转移给幸存者，
  TTBR0 值不变运行中成员零感知；末代成员销毁。TTBR0 转移前后一致，
  多核下无 TLB 失配窗口
- exec 仅载体可发起（成员线程拒绝，文档披露 POSIX 差异）
- 实机：threaddemo 双轮 PASS（sbrk 栈 + 共享区写入验证 + join code=77）

### ✅ KASLR 阶段 1（历史阶段；第31刀已完成镜像级 KASLR）
- rng 模块：cntpct 抖动 ⊕ MPIDR → splitmix64（非密码学安全，已披露）
- spawn/exec 两路用户栈顶向下随机偏移 ≤1MiB（页粒度，保底半栈深）
- 历史记录：当时镜像级 KASLR 尚待 PIE；现已由第30/31刀 ET_DYN/PIC + bootloader relocation 完成

## 历史立项表（当前均已实施或被新路线替代）
| 项目 | 立项文档 | 关键结论 |
| --- | --- | --- |
| SMP 阶段 3 · COW 重开 | docs/mm_heap_corruption_investigation.md | ✅ 2026-08-25：TLBI operand + free-list ghost gap 双根因结案，COW 默认开启 |
| 镜像级 KASLR | docs/kaslr_image_plan.md | ✅ 第31刀已实施：kernel ET_DYN/PIC + UEFI 随机选址/RELA |
| ZeroPkg 生态 | docs/zeropkg_inos_plan.md | ✅ 第29刀已实施：HTTPS/install/verify/launch/remove 全闭环 |
| ACPI 静态表 | docs/acpi_static_plan.md | ✅ 第20刀已实施：MADT/GIC/GTDT/FADT/MCFG 真消费；AML 按需 |

## 第十七/十八刀历史阶段（✅ 已结案；后续由第20～44刀覆盖）

| 档 | 内容 | 状态 |
| --- | --- | --- |
| 🥇 | 堆损坏猎杀：最终定位 free-list 不可分裂尾巴形成 ghost gap；修复并加回归 | ✅2026-08-25 结案 |
| 🥈 | ZeroPkg 设备内早期 WS-A~D | ✅ 后续由第29刀 HTTPS→签名→ZFS→launch/remove 全闭环正式替代 |
| 🥉 | 线程二期：号位 27/28 FutexWait/Wake + userlib UserMutex + mutextest | ✅实机 PASS |
| 小件 | threaddemo+mutextest 注入 acceptance（15 项）；crashlog 缓行 | ✅ |
| ➕ | **第十八刀·ACPI 静态表第一阶段**：RSDP 经 UEFI config table 抓取→boot.S 槽位补丁→no_std RSDP/XSDT/MADT 解析器(host矩阵测试)→SMP 按 MADT 点亮(legacy 回退保留)；GIC/GTDT/FADT/MCFG 消费归第20刀 | ✅-smp4 实机验证 |

**验收现状：15/15 ALL PASS**（含 threaddemo/mutextest 新项）
**压力长跑：-smp4 三轮 6/6 functional 全绿**（scripts/stress-loop.sh）
**P1-P3 收口**：stress-loop 脚本入库 / README 现代化 / perf-history 首期
入库 / knife10~13 worktree 与分支清理。
**第十八刀追加（历史）**：userlib Condvar（futex 实现）交付；当时的 COW 重开阻塞已于 2026-08-25
由 TLBI operand + free-list ghost gap 双根因正式结案；ZeroPkg 早期 WS-B/C 也已由第29刀完整事务链替代。

解锁路径已完成：堆损坏结案 → COW_SHARED_FORK 重开 → SMP 阶段 3 收口。
结构性天花板已越过：镜像级 KASLR 已由第31刀实施；后续转入真机硬件路线。

### SMP 多核立项（2026-08-24 定稿，四阶段）
> 裁决：先 SMP 后 ACPI。virt 上副核启动走 PSCI CPU_ON（conduit 已验证），
> 不依赖 ACPI；ACPI 的兑现点（MADT 枚举/GTDT/电源）在多核之后才有价值，
> 届时作为 bootloader-uefi 抓 RSDP 塞 bootinfo 的前置子任务并入。

| 阶段 | 内容 | 验收 | 状态 |
| --- | --- | --- | --- |
| 0 | per-CPU 地基：CURRENT_SLOT/看门狗逐核化；每核 idle scratch 帧；自旋锁跨核纪律成文 | `-smp 1` 全功能零回归 | ✅2026-08-24 |
| 1 | 副核点亮：PSCI CPU_ON 探测 1..MAX → 入口汇编（独立栈+TPIDR+GICC 初始化）→ 进调度循环 | `-smp 4` cpu1-3 online 日志 | ✅2026-08-24 |
| 2 | 调度多核化：全局队列跨核消费；wake() 广播 RESCHED SGI 踢醒 WFI 核 | `-smp 4` forktest/sleepdemo/fstest/fsdemo/secdemo 全绿 | ✅2026-08-24 |
| 3 | TLB 击落 + 重开 COW_SHARED_FORK（跨核页表语义收口） | COW 实机 copied=0 且 demo 全绿 | ✅2026-08-25 |

> **实机战报**：`-smp 4` 下 forktest/sleepdemo/fstest/fsdemo/secdemo 全 PASS；
> `-smp 1` 标准验收 15/15 零回归。两个关键坑：
> ① PSCI 目标 MPIDR 不带 AArch64 的 RES1 位（bit31）——按 DT reg 原值
>    （0x0/0x1/...）匹配，带位反而 INVALID_PARAMETERS；
> ② QEMU virt 默认拓扑把逻辑核放 Aff0，但真机/socket 拓扑在 Aff1——
>    双格式候选探测通吃。
> FP 语义：MULTI_CORE 翻闸即 FPEN=0b11 + 入口恒急切保存 + exit 急切
> 装载（restore_context x11 选择子双分支）；单核惰性门完整保留。

FP 语义裁决：MULTI_CORE 激活后 FPEN=0b11 + 帧回写全急切（第八刀语义，
天然核安全）；单核保留第十一刀惰性门。惰性方案的跨核化（TPIDRRO_EL0
per-cpu 基址方案）与阶段 3 一并立项。

## 构建与实机验证
cargo run -p xtask -- build-iso          # 超 3072MB 锁死，purge 自救
                                         # ⚠ user-app 已纳入自动构建
./run-qemu.sh                            # 交互串口 + writethrough 挂盘
scripts/acceptance.sh                    # 自动验收（exit 0 = ALL PASS）
scripts/perf-baseline.sh                 # 性能基线采集（新增）
# shell 命令全景：help/forktest/waittest/nohangtest/orphantest/waitspec/
#   execdemo/segvdemo/ppid/pid/sleepdemo/brktest/fstest/fsdemo/blktest/
#   ls/cat/mkdir/login/su/whoami/sessions/secdemo/launchd/clear/history

## Worktree 遗产
ws/knife10-memory · ws/knife11-sched · ws/knife12-fs · ws/knife13-security
已全部并入 main（保留可考）；worktree 目录可 `git worktree remove` 清理。
