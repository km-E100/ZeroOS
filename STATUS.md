# Zero OS 复兴状态（断点存档）

> 新会话先读本文件 + `git log --oneline` 接上进度。

## 当前里程碑（2026-08-23 · 第九刀：进程模型收尾，四线并行全交付）
- **wait 精确化**：pending_wait bool → WaitSpec{Any,Pid} 目标集合；
  子退出经 wait_wake_decision 纯函数精确匹配，误投递缺口闭合；
  NEXT_PID → (generation<<16|seq) 防复用（实机 waitspec 乱序双收集 PASS）
- **execve 真·换地址空间**：五阶段流水 BuildNew→CommitRebind→Activate→
  Destroy→ResetFrame（激活先于销毁的原子性）；号位 3 破坏性升级为
  路径语义（零 legacy 调用方）；execdemo 实机 root_phys 变更证据
- **信号位图**：EL0 故障按 DFSC 归因 SIGSEGV/SIGTRAP/SIGBUS →
  pending_signals u16 位图 → exit(-sig) 走 zombie 路径；
  segvdemo 实机 collected code=-11 (SIGSEGV)
- **GetPpid 号位 23**：孤儿返回收养者 init=2，根进程返回 0
  （对照 Linux pid1 语义；spawn 路径记父为后续刀次候选）
- **开发模式**：worktree 四线并行（wait/exec/signals/ppid），
  顺序 merge 仅 2 处 shell.rs 冲突手工并集解决

## 实机验收清单（全部 ✓）
forktest(getppid 断言) / waittest(42) / segvdemo(-11 SIGSEGV) /
execdemo(root_phys 变更+exit 77) / waitspec(乱序精确) / ppid=0 语义 /
四服务在线 / fstest / 86 主机测试全绿

## 后续刀次路线图（第九刀已勾销）
第十刀 内存现代化：COW fork（挂载点已留）、brk 用户堆、pstore 故障落盘
第十一刀 调度与时钟：长操作分块让出、Sleep(ticks)、多级反馈队列、FPU 惰性保存
第十二刀 文件系统成体系：fsd 目录树/多文件、cat/ls、ZFS 选型落地
第十三刀 安全模型成型：capability 动态签发、通道 RX/TX 权限、登录会话
第十四刀 可靠性冲刺：fuzz/压力进 CI、watchdog、性能基线

### 结构性天花板（架构级决策，单独立项）
SMP 多核 / 线程模型（ABI 级约定）/ KASLR / 动态进程槽

## 构建与实机验证
cargo run -p xtask -- build-iso          # 超 2048MB 锁死，purge 自救
./run-qemu.sh                            # 交互串口 + writethrough 挂盘
scripts/acceptance.sh                    # 自动验收（exit 0 = ALL PASS）
# shell 命令全景：help/forktest/waittest/nohangtest/orphantest/waitspec/
#   execdemo/segvdemo/ppid/pid/fstest/blktest/launchd/clear/history