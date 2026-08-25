# Zero OS 复兴状态（断点存档）

> 新会话先读本文件 + `git log --oneline` 接上进度。

## 2026-08-25 · 第十九刀：全仓收口（当前权威状态）

- **标准实机验收：15/15 ALL PASS**。root/guest 会话、动态 capability、
  COW fork、Sleep、线程/futex、块设备与 fsd 全链均在 fresh ISO 上通过。
- **四核压力**：fresh `-smp 4` 下 `stress-loop.sh 3` 连续三轮均 6/6；
  MADT 枚举 4 核，cpu1/2/3 经 ACPI MPIDR 点亮，最终 `online=4`。
- **COW 默认重开并结案**：`COW_SHARED_FORK=true`。根因不是 Vec/FPU/进程表，
  而是 `TLBI VAAE1IS` 错把完整 VA 当寄存器操作数；AArch64 要求传
  `VA[55:12]`，即 `va >> 12`。旧 RW TLB 未被真正击落，父进程因此能
  静默写穿 COW 共享栈，最终让子进程读到父分支的 fork 返回值。
- **内核 free-list 结案**：free block 分配后若余量 `< MIN_FREE`，旧代码
  不分裂却仍记录较小 `used`，留下无人拥有的 ghost gap；dealloc 后把
  gap 当 next header。现改为把小尾巴并入本次分配，并有专门回归测试。
  新 `useralloc::StaticFreeList` 同类边界也同步修复。
- **异常现场**：AArch64 vector 入口先保存 x16/x17，再借 x16 定位
  TrapFrame；异步 IRQ/Data Abort 不再错误套用 AAPCS caller-clobbered 规则。
- **SMP/ACPI**：修复副核栈 double-add；PSCI context_id 写 TPIDRRO_EL0
  作为逻辑 CPU id；MADT 按实际 boot CPU affinity 过滤；ACPI GUID 改用
  UEFI crate 权威常量，多字节 packed 字段改逐字节 volatile 解码。
- **256 槽补齐**：MLFQ `PROC_LEVEL`/`SLICE_USED` 从遗留 64 改为
  `MAX_PROCESSES`，动态进程槽不再只扩进程表没扩调度记账。
- **安全边界补齐**：IPC queue 由 `Message` 升为 `(sender PID, Message)`；
  securityd 只信内核返回的 sender。普通已认证用户只能为自己申请
  `CAP_SESSION`，普通 capability/撤销/用户库管理需 admin。userdb 改
  `$zero$sha256$...` 编码，旧明文盘自动迁移；验证直接比较 32-byte digest，
  密码输入不回显。
- **长期用户态堆**：shell/fsd/securityd/blkdrv 等从永不回收的 bump heap
  统一迁到固定预算、可 free/coalesce、带锁的 `useralloc::StaticFreeList`。
- **工程链**：host SIGSEGV（wait_scan 残留 error! 直写 PL011）与
  mm-host-tests 编译回归已修；CI/check.sh 更新；ISO 内写入 commit、dirty
  与 kernel/rootfs SHA256。Git dangling commit 先挂 `refs/archive/dangling/*`
  后清掉 lost-found/tmp packs，`.git` 从约 1.7GB 降到约 107MB。

### 当前仍是路线图/架构取舍
镜像级 KASLR 尚未实施；AML 暂不做；默认文件服务仍是轻量 `zero-fsd`，
`zero-fs-zfs`/`zfs-core` 尚未切为运行时默认。这三项不是当前验收红灯。

## 第20～24刀路线（2026-08-25 冻结）

### 第20刀 · ACPI 平台描述收尾
目标：把“能解析 ACPI”推进到“核心平台驱动真正消费 ACPI”。
- MADT 的 GICD/GICR 信息接入 GIC 初始化，QEMU 常量仅作无 ACPI 回退；
- 解析 GTDT，让 timer PPI/flags 来自固件描述；
- 解析 FADT/PSCI 相关静态信息，HVC/SMC conduit 不再只靠平台先验；
- 增加 MCFG/PCIe ECAM 描述解析地基，为后续真实 PCI/GPU/设备枚举铺路；
- AML 仍明确不做，所有静态表解析失败必须安全回退当前 legacy 路径。
验收：`-smp 4` + 标准 15/15 全绿，GIC/timer 启动日志能证明 ACPI 数据被真实消费。

### 第21刀 · Display Foundation
目标：Zero OS 第一次脱离“只有宿主终端帮忙画字”的状态。
- UEFI GOP framebuffer 信息随 boot handoff 传入内核并保留/映射；
- 最小 2D framebuffer primitives（fill/blit/alpha blend/dirty rect）；
- 图形 console/logger sink，与现有串口 sink 并存；
- **UTF-8 中文作为第一版硬验收项**：现有中文内核日志必须能直接在屏幕正确显示；
- 最小字体栈：Unicode decode → cmap/glyph lookup → rasterize → glyph cache → alpha blend。
验收：QEMU 图形窗口中可直接看到 Zero OS 启动日志，中文无 `???/□□□` 退化，串口仍保持完整输出。

### 第22刀 · VirtIO GPU 2D
目标：从 CPU framebuffer 后端切到真正的虚拟 GPU/display device。
- virtio transport 从 legacy-only 补到 modern virtio-mmio v2；
- 驱动 `virtio-gpu-device`，最小支持 GET_DISPLAY_INFO / RESOURCE_CREATE_2D /
  RESOURCE_ATTACH_BACKING / SET_SCANOUT / TRANSFER_TO_HOST_2D / RESOURCE_FLUSH；
- GPU/MMIO/IRQ/DMA 能力边界按微内核模型封装，优先把高层驱动放 EL0；
- 第21刀文本/2D API 保持不变，只替换底层显示 backend。
验收：framebuffer console 在 virtio-gpu scanout 上工作；中文、滚屏、脏矩形刷新稳定。

### 第23刀 · Input Stack
目标：建立真正的输入事件系统，而不是应用直接读 PL011。
- 键盘 + 指针设备（优先 virtio-input，必要时保留串口键盘回退）；
- `inputd` 统一事件协议：key/button/motion/wheel/modifier；
- 焦点与事件路由的最小模型，为 WindowServer/IME 留 ABI；
- 中文输入法此刀只冻结 composition/commit 协议，不强行实现完整拼音词库。
验收：图形环境下鼠标移动/点击、键盘输入可由用户态服务稳定接收，串口 shell 不回归。

### 第24刀 · WindowServer / Compositor
目标：Zero OS 从“图形控制台”跨成真正的图形操作系统。
- 窗口创建/销毁、z-order、裁剪、dirty region、合成与焦点；
- 鼠标 hit-test / 拖动窗口；
- Terminal 搬进窗口，复用第21刀 Unicode/CJK 文本栈；
- 为 IME composition overlay、应用绘图 surface、未来 GPU 3D surface 留协议边界。
验收：开机进入图形环境 → 有鼠标 → 打开/显示 Terminal → 中文文本正常 → 窗口可拖动，
同时标准系统服务与 15/15 功能链无回归。

## 第25～34刀路线（2026-08-25 冻结）

### 第25刀 · Shared Memory / mmap / Shared Surface
目标：补回被第八刀止血下线的共享内存，但以安全句柄模型重做，而不是泄漏物理地址。
- 新 SHM object：内核持有页集合 + refcount + owner/capability，EL0 只拿 opaque handle；
- `mmap/munmap/mprotect` 最小集，先支持 anonymous/private/shared，再为 file mapping 留接口；
- WindowServer ↔ Application / displayd ↔ GPU 的共享 surface 走 SHM 映射，避免大图逐条 IPC copy；
- 禁止重新引入 `ShmPhys` 物理地址暴露，DMA 另走受控映射/lease。
验收：两个独立进程共享 surface 双向可见、权限隔离正确、销毁顺序/refcount 无泄漏；WindowServer 可切到共享 surface 路径。

### 第26刀 · Time / RTC / Deadline
目标：从“tick + syscall 次数逻辑时钟”升级成真正时间子系统。
- 单调时钟（GTDT/architected timer）与墙钟分离；
- QEMU virt 优先接 PL031 RTC，提供 realtime/monotonic API；
- sleep/timer 改支持绝对 deadline；capability TTL 从 syscall-count 迁到 monotonic time；
- 为文件时间戳、TLS 证书有效期、日志时间与后续 NTP 校时提供统一接口。
验收：跨 sleep/调度/SMP 单调不回退；RTC 重启后时间连续；TTL 不再受“系统调用多少”影响。

### 第27刀 · Network Stack Foundation
目标：把现有 `virtio-net` 二层驱动上面的空白补成可真正联网的用户态网络栈。
- modern virtio-net 收口（复用第22刀 modern virtio transport）；
- `netd`：Ethernet / ARP / IPv4 / ICMP / UDP / TCP / DHCP；
- socket-like IPC API，应用不直接碰网卡 ring；
- 基础 loopback/端口/连接状态与超时，网络 buffer 优先走第25刀共享内存。
验收：DHCP 获取地址、ping 网关、UDP echo、TCP 连接均在 QEMU NAT 下通过，多进程 socket 隔离正确。

### 第28刀 · DNS / TLS / HTTP
目标：从“有 TCP”升级为“能安全访问互联网服务”。
- DNS resolver + 缓存；
- TLS 1.3 客户端最小闭环，证书有效期依赖第26刀墙钟；
- HTTP/1.1（必要时后续加 HTTP/2）客户端库；
- 下载流/大响应不能靠单个 128-byte Message，走 stream + shared buffer。
验收：设备内解析域名并 HTTPS GET 固定测试站点，证书错误/过期必须拒绝。

### 第29刀 · ZeroPkg in-OS 完整闭环
目标：把现有 WS-A~C（manifest parser / fsd rename / `pkg ls|rename`）推进到真正包管理。
- `pkg install/remove/verify` 本地事务闭环：临时目录 → hash/signature 校验 → 原子 rename commit；
- 接第28刀 HTTPS repository：`pkg update/install <name>`；
- 安装后应用可被 launcher/WindowServer 启动，卸载后 registry/文件都清理；
- 信任根、origin key 与 admin/session 权限统一进 securityd。
验收：联网安装 demo.app → 启动 → 重启仍在 → 校验 → remove；中途断电/校验失败不留下半安装应用。

### 第30刀 · Dynamic Runtime / PIE / Shared Libraries
目标：结束“所有用户程序固定地址、每个二进制各带一份运行时代码”的阶段。
- 用户 ELF PIE + ASLR；exec loader 处理 AArch64 RELA；
- `mmap` 支撑 image mapping；
- 最小动态链接器与共享库 ABI（先 `libzero`/基础 runtime，是否追 POSIX libc 另议）；
- 应用 bundle/ZeroPkg manifest 能声明 runtime/ABI 版本。
验收：同一 PIE 程序连续启动基址不同；多个进程共享只读库页；fork/exec/COW 无回归。

### 第31刀 · Image KASLR / Hardening
目标：在第30刀用户态 PIE 验证成熟后再随机化内核镜像，而不是直接拿固定链接内核硬搬。
- bootloader 随机选择物理加载基址并处理 kernel relocation；
- 内核 VA/PA 映射与恒等窗口解耦，收紧 `KERNEL_SHARED_L1`；
- W^X / guard page / stack guard / NX 审计同步推进；
- crash symbol/provenance 在重定位后仍能正确解析。
验收：连续 20 次 `-smp 4` 启动基址分布变化，15/15 + stress 全绿，错误指针仍不能越过用户/内核边界。

### 第32刀 · ZFS Runtime Migration
目标：让仓库里已经存在的 `zero-fs-zfs` / `zero-zfs-core` 从“实现资产”升级为默认运行时文件服务。
- 对齐现有 fsd vtable，先保证应用/ZeroPkg 无感切换；
- journal / snapshot / allocator / 元数据树走真实运行链；
- 设计 fsd v1 卷 → ZFS 卷迁移/导入工具，而不是直接让旧盘失效；
- package install 与系统更新利用事务/快照做 rollback。
验收：默认启动走 zero-fs-zfs；15/15/ZeroPkg 全绿；制造中途写失败后 journal replay/rollback 正确。

### 第33刀 · Audio Stack
目标：补齐图形系统之后最明显缺失的用户设备能力。
- 优先 VirtIO Sound（virtio-snd）PCM playback/capture；
- `audiod` 用户态 mixer，应用走 stream API；
- 多应用混音、音量、buffer underrun/latency 基础处理；
- 与 WindowServer 的媒体/通知声音接口解耦。
验收：两个进程同时播放不同 PCM 可正常混音，无内核态音频策略代码。

### 第34刀 · GPU 3D
目标：在 2D/display/shared-memory 都稳定后再上 3D，不把“能出画面”和“完整 GPU”混成一刀。
- 优先 VirtIO GPU 3D 路线（VirGL 或 Venus 二选一，按 QEMU/宿主支持裁决）；
- render context / buffer object / command submission / fence；
- `renderd` 与 WindowServer surface 互操作，GPU 进程崩溃不能拖死内核；
- OpenGL/Vulkan 用户 API 层另做薄封装，先证明三角形/纹理/合成闭环。
验收：用户态应用硬件加速绘制并提交到 WindowServer，2D fallback 始终可用。

### 第35刀以后 · 真机硬件路线（暂不冻结具体刀数）
第20刀 MCFG 只铺 PCIe 地基；若目标从 QEMU virt 转向真实 ARM64 机器，再按硬件需求进入：
PCIe ECAM 枚举 → BAR/MSI/MSI-X → IOMMU/IORT → USB/xHCI/HID/存储 → 电源管理。
**AML 解释器只在真机设备/电源管理明确需要时立项**，不为了“ACPI 完整”而提前造一套巨大解释器。

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

### ✅ KASLR 阶段 1（栈随机化 + 熵源基建）
- rng 模块：cntpct 抖动 ⊕ MPIDR → splitmix64（非密码学安全，已披露）
- spawn/exec 两路用户栈顶向下随机偏移 ≤1MiB（页粒度，保底半栈深）
- 镜像级 KASLR 待 PIE 工具链改造（bootloader 选址+重定位），另行立项

## 待立项 → 已立项（设计冻结，实施待排）
| 项目 | 立项文档 | 关键结论 |
| --- | --- | --- |
| SMP 阶段 3 · COW 重开 | docs/mm_heap_corruption_investigation.md | ✅ 2026-08-25：TLBI operand + free-list ghost gap 双根因结案，COW 默认开启 |
| 镜像级 KASLR | docs/kaslr_image_plan.md | 推荐 PIE 方案四步走，用户态先行；阶段1栈随机化已交付 |
| ZeroPkg 生态 | docs/zeropkg_inos_plan.md | WS-A~C 已交付（manifest parser / fsd rename / `pkg ls|rename`）；第29刀完成 install/remove/verify + HTTPS repo 闭环 |
| ACPI 静态表 | docs/acpi_static_plan.md | RSDP/XSDT/MADT + SMP CPU 枚举已交付；GIC/GTDT/FADT/MCFG 的真实消费归第20刀收尾；AML 暂不做 |

## 第十七刀（进行中 · 四档菜单全干）

| 档 | 内容 | 状态 |
| --- | --- | --- |
| 🥇 | 堆损坏猎杀：最终定位 free-list 不可分裂尾巴形成 ghost gap；修复并加回归 | ✅2026-08-25 结案 |
| 🥈 | ZeroPkg 设备内：WS-A(abi::zpkg 解析核)+WS-B(fsd CMD_RENAME 原子改名)+WS-C(shell pkg ls/rename) 已交付；WS-D 安装全流待卷预置链路 | ✅WS-A~C·实机 15/15 |
| 🥉 | 线程二期：号位 27/28 FutexWait/Wake + userlib UserMutex + mutextest | ✅实机 PASS |
| 小件 | threaddemo+mutextest 注入 acceptance（15 项）；crashlog 缓行 | ✅ |
| ➕ | **第十八刀·ACPI 静态表第一阶段**：RSDP 经 UEFI config table 抓取→boot.S 槽位补丁→no_std RSDP/XSDT/MADT 解析器(host矩阵测试)→SMP 按 MADT 点亮(legacy 回退保留)；GIC/GTDT/FADT/MCFG 消费归第20刀 | ✅-smp4 实机验证 |

**验收现状：15/15 ALL PASS**（含 threaddemo/mutextest 新项）
**压力长跑：-smp4 三轮 6/6 functional 全绿**（scripts/stress-loop.sh）
**P1-P3 收口**：stress-loop 脚本入库 / README 现代化 / perf-history 首期
入库 / knife10~13 worktree 与分支清理。
**第十八刀追加**：userlib Condvar（futex 实现）交付；COW 重开阻塞立案
（Vec 生长假说已排除，见调查文档「已排除」节）；ZeroPkg WS-B/C 交付。

解锁路径已完成：堆损坏结案 → COW_SHARED_FORK 重开 → SMP 阶段 3 收口。
结构性天花板剩余：镜像级 KASLR 实施（设计已冻结）。

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
