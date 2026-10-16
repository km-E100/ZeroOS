# Zero OS 微内核运行时概览

本文简述当前微内核启动路径、异常向量、串口调试输出与系统调用框架，便于后续扩展。

## 启动流程
1. `boot/boot.S` 负责在固件跳转后建立 16 KiB 栈、清零 `.bss`，并构造占位 `BootInfo`，随后调用 `kernel_main`。
2. `kernel_main` (位于 `microkernel/src/lib.rs`) 顺序执行：
   - `runtime::init()`：初始化串口控制台；
   - `boot::init_arch()`：安装 AArch64 异常向量表、切换至 SP_EL1；
   - `ipc::init()`、`process::init()`、`scheduler::init()`；
   - 通过 `services::launch_core` 启动用户态服务器。

## 异常向量
- `microkernel/src/arch/aarch64.rs` 使用 `global_asm!` 定义 2048 字节对齐的向量表；
- 所有 16 个入口（EL1t/EL1h/EL0 64/32）目前跳转到占位处理函数，会打印异常类别及 `ESR_EL1` / `FAR_EL1` 并停机；
- `init()` 设置 `VBAR_EL1` 指向该向量表，同时强制使用 `SP_EL1`。

后续可以在 `default_exception` 中添加寄存器转储、错误恢复逻辑，或为具体异常提供专用处理函数。

## 串口输出
- `runtime::serial` 以 PL011 (QEMU virt，基址 `0x0900_0000`) 为目标，初始化波特率 115200、8N1；
- `runtime::logger` 的 `log()` 与 `log_panic()` 直接写入串口，并为 `panic!` 输出前缀；
- 内核层可通过 `info!(...)` 宏打印调试信息。
- `user_demo::user_entry` 提供内置示例任务：循环触发 `svc #1`（yield）五次后 `svc #2`（exit），展示了用户态 ↔ 内核态 切换流程。可根据需要替换为自定义用户程序。

## 镜像组件
- `boot/boot.S` 的 `boot_info_struct` 现已包含根文件系统描述和驱动表地址，默认由 `kernel` crate 提供强符号覆盖；
- `kernel/src/servers.rs` 将 IPC Router、ZFS、launchd、securityd 的 `server_main` 入口暴露为引导期可用函数；
- `kernel/src/rootfs.rs` 嵌入了一个最小 RootFS（`/etc/motd`、LaunchDaemons 配置、ZFS 启动卷 JSON 等），微内核在启动日志中会打印打包条目数；
- `kernel/src/drivers.rs` 广播了基础驱动描述（PL011 串口、VirtIO 块设备），供用户态服务器探测；
- `microkernel/src/drivers.rs` 根据 `DriverTable` 初始化设备，并注册中断处理：目前已接入 PL011 UART（支持 RX 中断缓存输入）、VirtIO 块/网卡（完成基本握手并屏蔽/确认中断源）；
- `microkernel/src/services/mod.rs` 会在核心三大服务之外附加拉起 `securityd`，同时 `drivers::init` / `rootfs::init` 负责记录并打印这些描述信息。
- 可使用 `cargo run -p xtask -- build-rootfs` 将 `kernel/rootfs` 目录打包为 `target/rootfs.tar`，便于向安装镜像或测试环境分发。

## 系统调用概览
- `svc #0` 入口根据 X0 选择具体 syscall，目前实现：  
  - `SendMessage(channel, user_ptr)`：向当前进程拥有的 IPC 通道发送 128 字节消息；  
  - `ReceiveMessage(channel, user_ptr)`：从通道取消息写回用户缓冲区；  
  - `Fork()`：复制当前进程上下文（含用户栈），子进程返回 0，父进程得到子 PID；  
  - `Exec(entry, arg)`：重建进程上下文并跳转到新的用户入口；  
  - `Yield()`：显式让出时间片；  
  - `Exit(status)`：当前任务退出（调度器回收插槽）。  
  - `ConsoleRead(buf, len)`：从 PL011 中断环形缓冲中读取输入；无数据时返回 `WouldBlock`；  
  - `BlockRead/BlockWrite(lba, buf, len)`：访问 VirtIO 块设备，长度需为 512 字节的整数倍。  
- 计时器中断（10ms 时间片）会触发调度器重新编程下一 tick 并执行轮转调度，保障任务不会长时间占用 CPU。
- 调用返回值通过 X0 传递，`u64::MAX` 起始的一段值被映射为 `SysError` 枚举，便于用户态统一处理。

- `boot/boot.S` 内置的 `boot_info_struct` 会指向三个弱符号 `__zero_ipc_server_entry` / `__zero_zfs_server_entry` / `__zero_launchd_entry`，后续链接实际服务器即可覆盖（未覆盖时会停留在占位循环）。

验证方式：
```bash
# 使用 xtask 交叉编译微内核（需 nightly + build-std）
cargo run -p xtask -- build-kernel-bare

# 或直接生成包含 boot 的完整镜像
cargo run -p xtask -- build-image

# 在 QEMU 上运行
qemu-system-aarch64 -machine virt -cpu cortex-a72 -nographic \
    -kernel target/zero-os.elf
```

串口输出将显示类似如下日志：

```
arch/aarch64: vector table installed
Zero OS microkernel ready; launching userland servers
User demo task yielding (svc #1)
```

若触发异常，会额外输出 `ESR_EL1` / `FAR_EL1`，便于定位故障。 
