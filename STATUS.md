# Zero OS 复兴状态（断点存档）

> 本文件用于"一刀一会话"工作流：新会话先读本文件 + `git log --oneline` 即可接上进度。
> 更新时机：每刀结束 / 会话中断时。

## 当前里程碑（2026-08-22 · 用户态全面打通）
- **交互式用户 Shell 实机可用**：help / echo / info / whoami 全部工作；launchd 在线
- 本轮修复（全部经 QEMU 实机验证）：
  1. **异常入口现场保存缺失**（致命）：WIP 重构删掉了保存动作——trap_entry 的 Rust
     前奏会踩脏寄存器。现由汇编 SAVE_TRAP_AND_CALL 存根在异常第一瞬间全量保存到
     TRAP_FRAMES[slot]（TPIDR_EL1 指帧，eret 前由 restore_context/enter_user_mode 设置）
  2. yield_now 错标 `-> !`：LLVM 在 svc 后放 unreachable brk，yield 返回即踩中 → 改为正常返回
  3. read_line match 贯穿：WouldBlock 臂缺 continue，缓冲区被 NUL 填满、命令永远匹配不上
  4. USER_AP_RX=0b10 是 "EL0 无访问"：改 0b11（EL0+EL1 只读）
  5. 链接脚本无 PHDRS：纯 .bss 段被标只读 → 显式 PHDRS + 内核对 memsz>filesz 段强制可写
  6. svc 封装改固定寄存器约束（in("x0") 等），杜绝输入寄存器分配彩票
  7. EL0 BRK(Rust panic) 终止进程而非 HALT 整机；SMC→HVC（PSCI）；故障路径重入保护
  8. ENOSYS 日志限流（曾 25 秒刷 89 万行）；build-iso 补建 user-app（陈旧 blob 根因）

## 已知待办（下一刀候选）
1. `launchd status` → EL1 alignment fault @0x400ac3fc（far=0x40bd0318 堆区）——IPC 消息拷贝非对齐访问
2. fork 的 clone_space 仍是占位失败；COW 缺失
3. phys 分配器未消费 bootloader memory map（保留区粒度粗）
4. virtio-blk 未挂盘；idle 无 WFI
5. 主机测试仅覆盖纯逻辑层；mm-host-tests 不在 workspace members

## 构建与实机验证命令
```
cargo run -p xtask -- build-iso          # 全链构建（含 bootloader/kernel/rootfs/ISO）
qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 1024 \
  -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
  -serial mon:stdio -display none -cdrom target/zero-os.iso
# 等 ~12 秒出现 zero> 提示符即可交互
```

## 省钱工作流（重要）
- 一刀一会话；每刀结束更新本文件
- 调试只跑增量编译 + 快速重打包（rebuild-fast 脚本待建：跳过全链，只重编 kernel 拷入 ESP）
- 串口日志只 grep 关键行
- 每刀设工具调用预算（如 20 轮），到点停手写存档