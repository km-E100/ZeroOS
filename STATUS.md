# Zero OS 复兴状态（断点存档）

> 本文件用于"一刀一会话"工作流：新会话先读本文件 + `git log --oneline` 即可接上进度。
> 更新时机：每刀结束 / 会话中断时。

## 当前里程碑（2026-08-17）
- **系统已能从 ISO 完整启动到调度器**：rootfs(6 条) / 驱动表(3 个) / launchd 进程 spawn 成功 / `scheduler::run` 主循环启动
- 修复前：死在 mm::init（恒等映射 PXN + 无 TLB 维护）
- 全部修复经 QEMU 实机串口验证（target/boot-serial*.log 留存）

## 已知待办（下一刀候选）
1. **用户态架构死结**（已实测坐实）：dispatch 切 TTBR0=用户表后开 IRQ，
   异常向量(低地址 0x400d4000)在用户表未映射 → 静默死循环。
   修复方向（已分析）：
   - 方案 1（推荐，半天~1天）：用户表共享内核映射——
     create_user_address_space 里把内核 L1[0]/[1] 的 block 挂进用户表；
     用户区 0x200000 附近需把 2MiB block 拆成 4K 页表；
     隔离靠 AP=00（EL1-only）
   - 方案 2（工程量大，暂缓）：内核迁高半区 TTBR1——需低地址
     trampoline、物理窗口映射（刚改的 7 处恒等直写全部回炉）、
     linker AT()、MMIO 高区窗口、5 处页表物理地址计算
2. zero-launchd 是 stub（loop{}），console shell 1204 行已编译进内核
3. phys::init 的 memory_bytes=512MiB 是占位（QEMU 实际 1GiB）；
   bootloader 拿到 memory map 但 KernelBootContext 丢弃了（下划线参数）
4. virtio-blk/net 未挂盘（QEMU 命令无 -drive），探测优雅失败

## 构建与实机验证命令
```
cargo run -p xtask -- build-iso          # 全链构建（含 bootloader/kernel/rootfs/ISO）
qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 1024 \
  -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
  -serial file:target/boot-serial.log -display none -cdrom target/zero-os.iso
# 等 ~15 秒后 Ctrl-C，看 target/boot-serial.log
```

## 修复史（9 提交，f093027 存档起）
1. 6419545  恒等映射去 PXN + TTBR 切换补 tlbi
2. 3fd463b  TTBR 改指 L0 根表（T0SZ=20 → 起始级 L0，此前错指 L1）
3. 7ebc933  启用被注释的 rootfs/驱动表（强符号覆盖弱符号）+ read_file 实现 + ABI 空表防御
4. d795fa9  ELF 程序头解析改逐字段字节拷贝（include_bytes 数据 1 字节对齐的 UB）
5. 6be6f71  map_temp_page 写穿修复（block 描述符误当表）
6. cee6a06  map_temp_page 页表级索引错位（l2_idx 误当 L1 索引）
7. d3a14af  废除 map_temp_page，物理页恒等直写（7 处）
8. d075827  物理分配器 RAM 基址修正（QEMU virt RAM 在 0x40000000 起）+ 保留区改 __bss_end-RAM_BASE
9. 6561a87  恢复 spawn_user 实现（引导路径第三颗雷）

## 省钱工作流（重要）
- 一刀一会话；每刀结束更新本文件
- 调试只跑增量编译 + 快速重打包（rebuild-fast 脚本待建：跳过全链，只重编 kernel 拷入 ESP）
- 串口日志只 grep 关键行
- 每刀设工具调用预算（如 20 轮），到点停手写存档
