# Zero OS 复兴状态（断点存档）

> 新会话先读本文件 + `git log --oneline` 接上进度。

## 当前里程碑（2026-08-24 · 第十~十四刀单日走完，四线并行+集成）

### 第十刀 内存现代化（实机全绿）
- **COW fork 闭环**：移除 bisect kill-switch 后共享只读克隆生效；
  实机 `copied=0`（34 共享 + 971 只读直映射），forktest PASS
- **pstore 双启动链路打通**：故障落盘→复位→bootloader 取回打印，
  靠 drill 注入实测验证；顺带修掉两个真 bug：
  ① Brk 来源判定改 SPSR.M 权威（内核态 BRK 曾误杀无辜进程）
  ② PSCI 功能号 0x84000008 是 SYSTEM_OFF 不是 RESET——"复位"实为关机，
     pstore 链路此前从未真正走通
- **blktest 回归修复**：第八刀收权后 Shell 无 CAP_BLOCK_DEV 被拒；
  最小授权补授单一位，验收清单恢复该项

### 第十一刀 调度与时钟（实机全绿，含三次深度排障）
- **MLFQ**：4 级反馈队列（4/8/16/32 tick），200 tick 全局提升防饥饿；
  yield 保级、唤醒归零；主机测试钉死判定矩阵
- **Sleep(ticks) 号位 25**：定时器轮 + 唤醒侧陷阱帧回写 elapsed；
  sleepdemo 实机：父睡 5 精确醒、子睡 12 elapsed=12 PASS
- **FPU 惰性保存**：FPEN=0b01 门 + EC=0x07 断链（fpu_trap_replay）+
  切换点降门（dispatch 统一 fpu_set_lazy_gate）；非 FP 用户零开销
- **排障战果（都是真雷）**：① stub 空帧跑通全程（TPIDR 未武装时放行
  中断）② idle 复活路径（陈旧 TPIDR 把 Blocked 进程 eret 回用户态）
  ③ FP 重放死循环（restore_context 重降门位）——修复=idle scratch 帧 +
  on_tick 守门 + 门位下移
- **分块让出**：基础设施就绪（SCHED_STARTED 安全闸 + chunk_yield_point）；
  两处插入点经锁域审计后缓用（spawn/fork 路径上游持表锁，放行即死锁）

### 第十二刀 文件系统成体系（实机全绿）
- fsd 目录树：显式目录标记槽（尾'/'），超级块 v1 不变免迁移；
  mkdir/rmdir/unlink/LIST 路径版；空段/点段拒绝在服务端权威判定
- shell 新命令：`ls`/`cat`/`mkdir` + `fsdemo` 九步树语义验收全过
- ZFS 选型结论落 docs/zero_file_system_spec.md：fsd 层扁平全路径+
  标记槽方案胜出，zfs-core 元数据树化延后立项

### 第十三刀 安全模型成型（实机全绿）
- capability 动态签发（号位 40-45）：Grant/Revoke/CreateChannel/
  SessionBegin/GetSession/SessionList；TTL 台账 + 活算模型
- 通道 RX/TX 权限位图（abi ChannelDesc 扩展，向后兼容）
- 登录会话：login/su/sessions/whoami；会话绑定防跨会话重放

### 第十四刀 可靠性冲刺
- GitHub Actions CI：主机测试 + 裸机构建双闸（.github/workflows/ci.yml）
- abi 解码模糊属性测试：LCG 2 万次轰击 decode 带契约
- 软看门狗：连续 600 tick 无 Running 进程告警一次（scheduler）
- 性能基线：scripts/perf-baseline.sh + docs/performance_baseline.md

## 实机验收现状（scripts/acceptance.sh，13 项）

✅ shell-up / launchd 三服务 / login-root / su-guest / sessions /
   forktest(COW) / fstest / fsdemo(树语义)
❌ **secdemo**（child code=1 + collected pid=2105656 垃圾值，确定性复现）
❌ **sleepdemo**（父 elapsed=0 立即返回 + wait NotFound(3)；SVC25 探针证明
   内核已收到 ticks=5，问题在睡眠登记→唤醒→帧回写链路与会话/COW 叠加态）
❌ **blktest**（knife13 版脚本注释掉了注入项；CAP 修复已在 main，恢复注入即可）

> ⚠ 三红均为**并行刀叠加交互**问题：各刀在自身分支实机均 PASS。
> 主嫌疑：idle-scratch 修复未覆盖「父阻塞等尸」窗口的 TPIDR 陈旧指向 ×
> 会话撤销路径。已定位到 SVC25 收到 ticks=5 但 elapsed 回写为 0 的断层。
> 下会话首选：以 sleepdemo 为靶，二分 on_tick_consume 的 expiry 写回与
> dispatch 恢复之间的帧一致性。

## 结构性天花板（架构级决策，单独立项）
SMP 多核 / 线程模型（ABI 级约定）/ KASLR / 动态进程槽

## 构建与实机验证
cargo run -p xtask -- build-iso          # 超 3072MB 锁死，purge 自救
                                         # ⚠ user-app 已纳入自动构建
./run-qemu.sh                            # 交互串口 + writethrough 挂盘
scripts/acceptance.sh                    # 自动验收（exit 0 = ALL PASS）
scripts/perf-baseline.sh                 # 性能基线采集（新增）
# shell 命令全景：help/forktest/waittest/nohangtest/orphantest/waitspec/
#   execdemo/segvdemo/ppid/pid/sleepdemo/brktest/fstest/fsdemo/blktest/
#   ls/cat/mkdir/login/su/whoami/sessions/secdemo/launchd/clear/history

## Worktree 遗产
ws/knife10-memory · ws/knife11-sched · ws/knife12-fs · ws/knife13-security
已全部并入 main（保留可考）；worktree 目录可 `git worktree remove` 清理。
