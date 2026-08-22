# Zero OS 复兴状态（断点存档）

> 新会话先读本文件 + `git log --oneline` 接上进度。

## 当前里程碑（2026-08-22 · 第五刀：三线并行交付）
- **fork 端到端打通**（实机）：clone_user_address_space eager-copy 零缺陷；
  shell `forktest` 命令父子双行验证；子进程回收链路完整
- **virtio-blk 上线**（实机自检通过）：IRQ 槽位修正 48/49、EL1 轮询完成路径、
  开机 LBA2048 写读自检；run-qemu.sh / xtask run 挂盘固化；专用 disk.img
- **内核故障符号化回溯**（实机）：bootloader 灌符号进 .data 汇槽
  （192KiB，.data 而非 .bss——zero_bss 会清掉后者）；trap 输出 elr=__symbol+off；
  8 项单测。注意：汇槽容量截断保低址段
- **体积硬闸**：xtask 所有命令前置 du 检查，超 2048MB 锁死构建；`purge` 自救
- **诊断增强**：显式 alloc_error_handler（OOM 打印 Layout+phys 余量）；
  logger 支持动态格式化 panic 载荷（曾吞掉 assert_eq! 真实文本）

## 实机验收清单（全部 ✓）
symbol sink / launchd online / shell 交互 / forktest 父子 / 服务注册表视图 /
pid / 无 MISALIGNED / 无 panic

## 已知待办（第六刀候选）
1. wait/waitpid/zombie 回收（fork 已通，POSIX 进程族谱缺一半）
2. userland block_write/read 端到端命令（驱动已就绪，缺 shell 集成）
3. ZFS/fsd/blkdrv 用户态服务真实上线（依赖块设备，现已具备）
4. EFI memory map 精细消费；时间片/优先级调度；符号化栈回溯（FP 链）
5. virtio-net 槽位空置 warn 噪音；短读语义；真机 DMA cache 一致性

## 构建与实机验证
cargo run -p xtask -- build-iso          # 超 2048MB 会锁死，purge 自救
./run-qemu.sh                            # 交互串口 + 自动挂盘
# 或 cargo run -p xtask -- run normal