# Zero OS 复兴状态（断点存档）

> 新会话先读本文件 + `git log --oneline` 接上进度。

## 当前里程碑（2026-08-22 · 第六刀：POSIX 进程回收 + 双服务在线）
- **zombie/waitpid 实机打通**：Exit 有父转 Zombie（释放地址空间保留
  退出码）；号位 22 WaitPid 收集返回 (pid<<32)|code，无可收子挂起，
  无子 NotFound；shell waittest 实机验证 zombie→collected 全链路
- **securityd 真实上线**：launchd spawn 运行 [running] pid=4，加载
  /etc/users，auth/userdb 就绪；blk 缺失时优雅降级警告
- **时间片调度**：SLICE_TICKS=4 记账，未耗尽直接 restore_frame 免切换
- **FP 链符号化栈回溯**：kernel_sync_fault 输出 Call Trace 段

## 实机验收清单（全部 ✓）
forktest 父子 / waittest zombie→collected / launchd list 含 running 服务 /
securityd banner+userdb / symbol sink / shell 交互 / 时间片下响应正常

## 已知待办（第七刀候选）
1. 孤儿进程策略文档化 + init 收养模式；waitpid 扩展 WNOHANG
2. fsd 上线（blkdrv IPC 通道对接 virtio-blk）→ ZFS 挂载路径
3. 用户态块设备命令（blktest）；securityd userdb 落盘持久化
4. EFI memory map 精细消费；符号化栈回溯接入用户态故障路径
5. 多核 GIC/SMP 评估；每 CPU 中断栈分离

## 构建与实机验证
cargo run -p xtask -- build-iso          # 超 2048MB 锁死，purge 自救
./run-qemu.sh                            # 交互串口 + 自动挂盘