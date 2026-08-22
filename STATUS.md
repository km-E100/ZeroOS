# Zero OS 复兴状态（断点存档）

> 本文件用于"一刀一会话"工作流：新会话先读本文件 + `git log --oneline` 即可接上进度。

## 当前里程碑（2026-08-22 · 第四刀：阻塞 IPC + 工程卫生）
- **阻塞式 IPC**：ReceiveMessage 空队列时挂起进程（等待者槽×4/通道），send 成功
  释放锁后唤醒；continuation 语义在 dispatch 重入用户态前完成挂起调用
  （对照 Mach mach_msg / XNU continuation）。实机 shell↔launchd 全命令验证通过。
- **工程卫生归零警告**：死代码清除（context_switch/save_trap_frame/仪表残留）、
  串口写加有界 FIFO 等待+使能 FIFO（不再丢日志字节）、rootfs 校验器接入 init、
  内核栈 16K→64K（无独立中断栈，取 Linux THREAD_SIZE 的余量策略）
- **shell 新命令**：pid（GetPid 端到端）/clear/history

## 全会话修复史（本四刀）
1. 异常入口现场保存缺失（汇编 SAVE_TRAP_AND_CALL 存根，TPIDR_EL1 定位帧）——致命
2. yield_now 错标 ->!（LLVM 在 svc 后放 brk）；read_line 贯穿缺 continue
3. USER_AP_RX=0b10 实为 EL0 无访问 → 0b11
4. 链接脚本 PHDRS 缺失致 .bss 只读；内核对 memsz>filesz 段强制可写
5. svc 封装固定寄存器约束；EL0 BRK 终止进程不 HALT；PSCI 改 HVC；故障重入保护
6. 内核栈 16 字节对齐缺失（AAPCS64 违例，launchd status 必崩根因）
7. WFI idle；ENOSYS 限流；build-iso 补建 user-app；no_std 测试 std 链接

## 已知待办（下一刀候选）
1. fork 端到端验证（clone_space eager-copy 已实现但无实机触发路径）
2. 物理分配器消费 bootloader EFI memory map（当前仅总量）
3. virtio-blk 挂盘 → ZFS/fsd/blkdrv 用户态服务真实上线
4. 内核故障符号化回溯（bootloader 已加载 7974 个符号可利用）
5. mm-host-tests 回归进 CI；userland 命令主机测试
6. 时间片/优先级调度（当前纯 RR）

## 构建与实机验证
cargo run -p xtask -- build-iso
qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 1024 \
  -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
  -serial mon:stdio -display none -cdrom target/zero-os.iso