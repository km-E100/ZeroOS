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

## 已知待办（第九刀候选）
1. pending_wait 目标集合化；getppid/进程组；pid generation 防复用误配
2. execve 最小版（换地址空间）；信号位图（SIGSEGV 投递默认动作）
3. SHM 重设计（Region 表 + map 进请求者 AS + refcount）
4. COW fork（PTE 只读 + Permission-abort 翻页）；pstore 故障落盘
5. Sleep(ticks) 接 timer 前瞻 API；长拷贝 syscall 分块让出
6. securityd 权限精化路线：capability 由内核签发而非描述符静态声明

## 构建与实机验证
cargo run -p xtask -- build-iso          # 超 2048MB 锁死，purge 自救
./run-qemu.sh                            # 交互串口 + writethrough 挂盘
scripts/acceptance.sh                    # 7/7 自动验收（exit 0 = ALL PASS）