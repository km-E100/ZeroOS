# Zero OS 复兴状态（断点存档）

> 新会话先读本文件 + `git log --oneline` 接上进度。

## 当前里程碑（2026-08-23 · 第七刀：安全边界 + 精细内存图 + 文件服务持久化）
- **fsd 文件服务端到端**：fstest 写读比对 MATCH，**跨重启卷持久化**
  （超级块@LBA8192、数据区@LBA16384；懒挂载消竞态）；blkdrv 数据面 =
  内核直通委托（用户态原生 MMIO 与 shm 句柄协议均实机必死，已文档化）
- **安全硬化三连**（批评代理 Top-5 落地）：① 恒等映射 [0x08000000,0x10000000)
  强制 Device-nGnRE（MAIR AttrIdx1）；② 内核代用户拷贝路径内故障降级为杀进程
  （穷人版 exception table，消除用户可控整机重启）；③ WaitPid WNOHANG +
  孤儿 init 收养（消费一次不变量修复双重收尸）
- **EFI memory map 精细消费**：__zero_memory_map 汇槽 → init_from_regions
  双指针扫洞（坐标纪律：绝对地址≠页号——曾致 free_pages=0 全图占用）；
  零分配解析（phys 先于堆初始化）
- **时间片调度** SLICE_TICKS=4；**FP 链符号化 Call Trace**；**体积硬闸 2GB**

## 实机验收清单（全部 ✓）
四服务在线（launchd/fsd/blkdrv/securityd）/ fstest 跨重启 PASS / forktest 父子 /
waittest+nohangtest+orphantest / memory-map path 10 regions free=248K /
symbol sink 1423 符号 / 无 MISALIGNED 无 panic / 69 测试全绿零警告

## 已知待办（第八刀候选）
1. pending_wait 目标集合化（父 wait(A) 期间子 B 退出误投递的 POSIX 缺口）
2. FPU/NEON 保存（CPACR_EL1.FPEN + TrapFrame 扩展）；TPIDR_EL0 用户 TLS
3. SHM 重设计（Region 表 + map 进请求者 AS；现返回恒等映射指针双路封死）
4. capability bitmask 升格（privileged bool → u32 位图）；通道 RX/TX 权限位
5. execve 最小版（复用 map_user_elf_segments 换地址空间）；信号位图投递
6. COW fork（PTE 只读 + Permission-abort 翻页挂载点已留）；pstore 故障落盘

## 构建与实机验证
cargo run -p xtask -- build-iso          # 超 2048MB 锁死，purge 自救
./run-qemu.sh                            # 交互串口 + 自动挂盘（cache=writethrough）
# shell 命令：help/forktest/waittest/nohangtest/orphantest/fstest/pid/clear/history