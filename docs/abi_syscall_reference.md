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
