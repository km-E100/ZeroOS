# Zero OS 系统调用参考（ABI 冻结版）

> 契约源：`libs/abi/src/lib.rs::syscall`（号位冻结）↔ `microkernel/src/trap.rs::decode_syscall`。
> 调用约定：AArch64 `svc #0`，`x0`=调用号，`x1..x4`=参数；返回值在 `x0`。
> 快捷入口：`svc #1`=Yield(4)、`svc #2`=Exit(5)。
> 错误编码：失败时 `x0 = u64::MAX - k`（k 见下表）；其余值视为成功。

## 调用表

| 号位 | 名称 | 参数 (x1,x2,x3,x4) | 成功返回 | 阻塞语义 | 特权 |
|-----|------|--------------------|---------|---------|------|
| 0 | SendMessage | channel, &msg, -, - | 0 | 队列满 → ChannelUnavailable | - |
| 1 | ReceiveMessage | channel, &buf, -, - | 0 | **空队列挂起进程**，send 唤醒后由内核完成拷贝（continuation） | - |
| 2 | Fork | -,-,-,- | 子进程 PID | 父继续/子从 svc 返回处 x0=0 | - |
| 3 | Exec | entry, arg, -, - | arg | 重置现场 | - |
| 4 | Yield | -,-,-,- | -（不返回到 x0 语义） | 让出 CPU | - |
| 5 | Exit | code, -, -, - | 不返回 | 进程回收 | - |
| 6 | ConsoleRead | &buf, len, -, - | 实际字节数 | 无输入 WouldBlock（轮询型） | - |
| 7 | BlockRead | lba, &buf, len, - | len | 同步 IO | len%512=0 |
| 8 | BlockWrite | lba, &buf, len, - | len | 同步 IO | len%512=0 |
| 9 | ConsoleWrite | &buf, len, -, - | len | 分块拷贝写串口 | - |
| 10 | ShmCreate | size, &res[3], -, - | 0 | 回填 handle/ptr/len | - |
| 11 | ShmMap | handle, -, -, - | 映射地址 | | - |
| 12 | ShmLen | handle, -, -, - | len | | - |
| 13 | ShmRetain | handle, -, -, - | 0 | 引用+1 | - |
| 14 | ShmRelease | handle, -, -, - | 0 | 归零回收 | - |
| 15 | DriverCount | -,-,-,- | 数量 | | - |
| 16 | DriverInfo | index, &info, -, - | 0 | {kind,u64 base,u64 len,u32 irq} | - |
| 17 | ShmPhys | handle, -, -, - | 物理地址 | | - |
| 18 | MmioMap | index, &[base,len], -, - | base | 租约引用计数 | ✔特权 |
| 19 | MmioUnmap | index, -, -, - | 0 | | ✔特权 |
| 20 | SpawnService | name_ptr, len, -, - | 新 PID | 内核注册表查找 | ✔特权 |
| 21 | GetPid | -,-,-,- | PID | 已实机验证 | - |
| 22 | WaitPid | pid, -, flags(x3), - | (pid<<32)\|code | 空队列挂起/收尸唤醒；WNOHANG 轮询回 0 | - |
| 23 | GetPpid | -,-,-,- | PPID（孤儿=收养者 2 / 根=0） | 已实机验证 | - |
| 24 | Brk | new_break(0=查询), -, -, - | 生效后 break | 页粒度增长/收缩；上限 64MiB | - |
| 40 | CapGrant | target_pid, caps, ttl, - | token | 动态签发能力授予（TTL=逻辑 tick，0=不过期）；仅 CAP_ISSUER 持有者；caps 含 CAP_ISSUER 拒绝 | ✔CAP_ISSUER |
| 41 | CapRevoke | token, -, -, - | 0 | 撤销即时生效（活算模型）；未知 token → NotFound | ✔CAP_ISSUER |
| 42 | CreateChannel | &ChannelDesc(16B), -, -, - | 0 | desc.tx/rx_groups 非 0（受保护通道）需 CAP_CHANNEL_CREATE；id 冲突 → ChannelUnavailable | 受保护创建需能力 |
| 43 | SessionBegin | login_token, -, -, - | 新 sid | 一次性消费本进程名下含 CAP_SESSION 的令牌建会话；su 换会话注销旧会话 | 令牌即授权 |
| 44 | GetSession | -,-,-,- | sid（无会话=0） | - | - |
| 45 | SessionList | &buf, len, -, - | 写入字节数 | 行集 `sid=N leader=P\n` 截断到 len | - |
| 26 | CreateThread | entry, stack_top, tls, arg | tid（真 pid，可 wait_pid join） | 共享地址空间线程（组载体模型：堆/映射页全组立即可见）；entry 不得返回（返回=SIGSEGV 终结本线程）；Exit 在线程语境仅终结本线程，组空间由末代成员回收 | - |
| 27 | FutexWait | uaddr, expected, -, - | 0（被唤醒）/ actual（不匹配不睡眠） | 原子条件等待；uaddr 4 字节对齐；线程死亡自动摘除登记 |
| 28 | FutexWake | uaddr, max, -, - | 实际唤醒数 | 唤醒至多 max 个等在 uaddr 的线程；配合 UserMutex 三态字约定 |

### 第十三刀补充说明（号位 40-45）

- **逻辑时钟**：单核实验内核无墙钟，CapGrant 的 TTL 以全局逻辑时钟计——每次任意系统调用步进 1（`security::advance_clock`）；过期惰性判定。
- **活算模型**：授予/撤销不改写进程表静态位图；有效能力 = 静态位图 ∪ Σ有效授予，门控时现算（SpawnService/CreateChannel/IPC 组校验统一走 `security::effective_caps`）。fork 不继承动态授予（子 pid 名下无台账）。
- **会话绑定**：授予签发时记目标当前会话；会话注销（su 换会话 / 会话领袖消亡）时绑定该会话的授予一并失效——跨会话重放防线。session=0 视为未绑定。
- **号位占用披露**：25=Sleep、26+=文件系统由并行刀预留，安全扩展自 40 起。

## 错误码（k = u64::MAX - x0）

| k | SysError | 典型来源 |
|---|----------|---------|
| 0 | InvalidArgument | 指针校验失败（范围/对齐）、长度越界 |
| 1 | PermissionDenied | 特权操作、通道 owner 不符 |
| 2 | ChannelUnavailable | 队列满 / 等待者槽满 |
| 3 | NotFound | 服务名未登记、驱动 index 越界、未知 syscall |
| 4 | NoMemory | 页分配失败、进程表满 |
| 5 | WouldBlock | ConsoleRead 无输入（ReceiveMessage 已改阻塞，不再返回此码）|
| 6 | DeviceError | virtio 底层错误 |
| 7 | Busy | 设备忙 |

## 用户指针安全模型

- 有效用户区：`[0x20_0000, 1GiB) ∪ [2GiB, 4GiB-4K)`；`[1GiB,2GiB)` 为内核共享表，一律拒绝。
- 拷贝按页步进、逐页校验（copy_slice_to/from_user）；未映射页由硬件 abort 兜底杀进程。

## 变更纪律

号位与错误判别值为**冻结 ABI**：只能追加新号位，不能改已有语义。
新增能力先在本文件与 `libs/abi` 注释同步，再实现内核侧。
