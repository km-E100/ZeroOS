# Zero OS 复兴状态（断点存档）

> 新会话先读本文件 + `git log --oneline` 接上进度。

## 当前里程碑（2026-08-23 · 第八刀：worktree 四线并行 + 安全边界闭合）
- **开发模式升级**：git worktree 四分支并行（syscall-security / exec-domain /
  userland-acceptance / engineering），四代理独立构建验证，main 顺序合并
- **syscall 边界安全三连**：validate_user_ptr 页级 walk 二道门（堵住 EL1 代拷贝
  绕过 AP 的旁路）；capability 位图升格（privileged bool → u32，Block*/MMIO/
  SpawnService 按位门控 + 块 IO 1MiB 上限）；SHM 六号位下线（NotSupported）
- **执行域补全**：TPIDR_EL0 用户 TLS + FPU/NEON 全量急切保存（TrapFrame 
  280→816B，静态断言钉死偏移）；CPACR_EL1.FPEN=0b11；杂散 IRQ 不再引发切换
- **services 精细能力授予**：descriptor.capabilities 位图 → spawn 后授予；
  securityd userdb 持久化经 CAP_BLOCK_DEV 实机恢复（首启播种→写盘校验）
- **用户态验收生态**：blktest（LBA≥40000 纪律）/ help 分组 / run-qemu.sh 
  writethrough+recovery / scripts/acceptance.sh（7/7 ALL PASS exit 0）
- **工程基建**：zero-abi 双端一致性测试（穷举哨兵区间）+ fuzz-syscall 16 属性
  测试（xorshift64* 可复现）+ CI 三 job（host tests/三裸机构建/ISO 冒烟）
- **EFI memory map 精细消费**：__zero_memory_map 汇槽 → init_from_regions
  双指针扫洞（坐标纪律修复绝对地址误作页号的 free_pages=0 全占事故）

## 实机验收清单（全部 ✓）
memory-map path 10 regions free=248K / symbol sink / 四服务在线 / fstest 跨重启
MATCH / forktest / waittest / nohangtest / orphantest / blktest LBA 纪律 / 无 panic

## 后续刀次路线图（已立项待指挥，2026-08-23 定稿）

> 批评代理基线 4.2/10 → 第八刀后预计 ~5.5。下表为到"准生产级"的分刀计划；
> 每刀完成后按实机验收清单判定，未达标不进入下一刀。

| 刀 | 主题 | 内容 | 完成标志 |
|----|------|------|---------|
| 第九刀 | 进程模型收尾 | pending_wait 目标集合化、pid generation、execve 最小版（真换地址空间）、信号位图最小版 | waittest+execdemo 全通；SIGSEGV 可观测 |
| 第十刀 | 内存现代化 | COW fork（挂载点已留）、brk 用户堆、pstore 故障落盘 | fork 写时复制；崩溃后可取回现场 |
| 第十一刀 | 调度与时钟 | 内核长操作分块让出、Sleep(ticks)、多级反馈队列、FPU 惰性保存 | 延迟上界可控；用户程序能 sleep |
| 第十二刀 | 文件系统成体系 | fsd 目录树/多文件扩容、cat/ls 用户态命令、ZFS 落地选型 | 重启后目录结构完整保留 |
| 第十三刀 | 安全模型成型 | securityd 动态签发 capability、通道 RX/TX 权限分离、登录会话 | 无凭据进程摸不到块设备 |
| 第十四刀 | 可靠性冲刺 | fuzz/压力进 CI、百次 fork/wait 压测、watchdog、性能基线 | 24h 无泄漏无 panic |

### 结构性天花板（架构级决策，单独立项，不在常规刀次内）
- SMP 多核：需重做调度器锁模型与 per-CPU 结构
- 线程模型：一进程一帧是 ABI 级约定，牵动整个进程模型
- KASLR / 64→动态进程槽

### 细粒度待办池（各刀领取）
- pending_wait 目标集合化；getppid/进程组；pid generation 防复用误配
- SHM 重设计（Region 表 + map 进请求者 AS + refcount）
- Sleep(ticks) 接 timer 前瞻 API；长拷贝 syscall 分块让出
- securityd 权限精化：capability 由内核签发而非描述符静态声明
- 符号化回溯接入用户态故障路径；FPU 惰性保存优化

## 构建与实机验证
cargo run -p xtask -- build-iso          # 超 2048MB 锁死，purge 自救
./run-qemu.sh                            # 交互串口 + writethrough 挂盘
scripts/acceptance.sh                    # 7/7 自动验收（exit 0 = ALL PASS）