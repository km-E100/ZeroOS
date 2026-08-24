# 内核堆损坏调查（SMP 阶段 3 · COW 重开阻塞项）

> 状态：未结案。已建自动捕获工具（heap_free_list 分配史环形记录 +
> dealloc 入口下一块 header 校验，HEAP-CORRUPT 转储）。本文档冻结
> 全部取证，供下会话直接续查。

## 症状（确定性复现）
`COW_SHARED_FORK=true` 时标准验收 6/13：secdemo/sleepdemo/forktest/
fstest/fsdemo/blktest 全崩；eager 模式（false）13/13 全绿。
触发点：任意 COW fork 之后的首批子进程活动。

## 关键证据
1. `HEAP-CORRUPT: dealloc ... next_hdr=0x4529313131313030`
   （ASCII: "001119)E"）与 `next_hdr=0x20746c756166206e`（"n fault "）
   —— **trap 日志消息文本片段**出现在空闲链 header 处。
2. `secdemo: collected pid=2105656` —— WaitPid 打包的 pid 高位字被
   覆盖为垃圾 ⇒ PROCESS_TABLE（Vec，堆上）记录字段遭越界写。
3. 同一指针 0x417971c0 反复以不同 size（0x30/40/60）分配释放——
   短命格式化 String 的典型复用模式。
4. eager 模式全绿 ⇒ 损坏与 COW 特有的运行期行为强相关：
   子/父栈首写触发的 Permission fault → 断链路径。

## 主嫌疑链
`handle_sync` 的 DataAbort 分支构造 `format_sync_exception`（堆 String，
~100B，恰为受损块尺寸档）→ 若断链失败落 SIGSEGV 终止路径，消息 String
的生命周期与某处裸指针写入交错。**待验证假设**：断链失败（或重复断链）
时 terminate 路径对 PROCESS_TABLE / TrapFrame 的写与 String 增长重分配
存在别名叠加。

## 下会话行动清单
1. 在 `format_sync_exception` 返回的 String 上加 canary（尾部 MAGIC），
   drop 前校验——把「谁写穿它」钉死到具体调用点；
2. 审查 handle_cow_write_fault 失败分支（返回 false 时是否仍继续用
   已 take 的空间/frame）；
3. 验证 Permission fault 是否在断链成功后被**二次**触发（TLB 未击落？
   bbm 屏障序？）——若是，free-list 损坏可能源于 phys 页被双计；
4. 修复后翻转 COW_SHARED_FORK 重跑 13/13 + `-smp 4` forktest 压力。

## 工具遗产
heap_free_list::dump_if_suspicious / HIST_RING（16 条分配史环形缓冲）：
dealloc 入口自动校验下一块 header，异常即打印最近分配序列。
生产保留无害（校验 O(1)）；定位完成后可移除。

## 追加取证（2026-08-24 深夜 · 全量堆轨迹 + 生命周期探针轮）

1. **内核堆完全干净**：sleepdemo 全窗口 alloc/dealloc 轨迹逐条核验，
   地址/尺寸序列合法，无任何越界或重叠——损坏不在堆分配器。
2. **父进程路径正确**：恰好一次睡眠登记、一次唤醒、elapsed 打印，
   随后阻塞 join——符合预期。
3. **子进程三怪象**：① 仅一次成功 COW-BREAK（far=栈页 ✓ ok=true）后
   静默自旋（反复 DISP 同一 pid、零输出零退出）；② 最终其记录**凭空
   消失**（父 wait 得 NotFound(3)）；③ 无任何 trap 终止日志。
4. 结论修正：损坏的「日志串覆写」表象可能是果不是因——子进程记录
   字段被破坏在先，后续 dealloc 读到被挪用的相邻块。

## 下会话首选工具
`qemu -d int -D int.log` 抓 fork 窗口全异常流；重点核对：
dispatch→switch_to 对「started=true 的 COW 子进程」首次恢复路径 vs
knife10 分支同路径的差异（含 TTBR0 activate 时序 × KASLR 栈偏移）。

## 二分排除（2026-08-24 深夜 · 第17-18刀期间）
| 实验 | 结果 | 结论 |
| --- | --- | --- |
| 禁用父侧 BBM 断链（父保持 RW 直写共享页） | 仍 6/15 崩，签名一致 | **父侧断链/屏障序排除** |
| 堆全量轨迹（sleepdemo 窗口） | 序列完全合法 | 分配器算法本身无恙 |
| CANARY-SMASH 全程零触发 | 载荷尾部无越界 | 写入者绕过 canary 位置（header 直写/wild write） |

## 收窄后的事故模型
COW fork 完成后的**子进程首次用户态活动窗口**内，某处对内核堆的
free-list header 发生 8 字节级覆写（内容为 trap 日志串片段）；子进程
随之静默自旋、记录消失。eager 模式（不共享页、全量复制）确定性无此象。

## 下会话首选
`qemu -d int -D int.log -singlestep` 包裹 sleepdemo fork 窗口，
对照 eager/COW 两次运行的异常流差异；同时审查 `cow_share_leaf`/
`install_leaf_descriptor` 与 `map_physical_page` 在**子表新建 L1/L2**
时对 `KERNEL_SHARED_L1` 的处理是否与 eager 路径存在别名差异。

## 终极隔离实验（2026-08-24 · 子进程立即退出诊断模式）
子进程首语句改为 `exit(0x42)`（无任何打印/syscall 前置）：
- 结果：父 elapsed=0、wait NotFound(3)、**exit(0x42) 从未被收集**
- ⇒ 子进程在 fork 返回后**一条用户指令都没执行**
- ⇒ 且父进程的 Sleepticks 回写同样丢失（elapsed=0）
- 双症状同窗：fork 完成 → enqueue(child) → 父阻塞 → 调度切换窗口

## 收窄后唯一自洽的事故模型
`alloc_table_slot_locked` 在 fork 中可能触发 **Vec 重分配**（表生长），
而 COW clone 之后、记录写入之前存在一个窗口——若此刻发生槽位/索引
错位（Vec realloc 搬移 × 快照序号），父子帧与表的映射即错乱。
eager 模式同样走此代码却全绿 ⇒ 差异必然在 **COW 特有的克隆路径
（bbm/tlbi/refcount 触碰了什么共享状态）× Vec 生长的叠加**。

## 已排除（2026-08-24 深夜追加）
- ~~fork 窗口 Vec 生长~~：预扩容实验（clone 前 reserve至上限）未修复，
  仍 2/15 败（secdemo/sleepdemo）——排除表生长错位假说。
- 分配器算法：全量轨迹合法。
- 父侧 BBM 断链/屏障序：跳过实验仍崩。

## 剩余差异面（eager 与 COW 的全部区别）
1. 子页表含指向**父物理页**的 RO+COW 描述符（vs 私有 RW 副本）；
2. 父侧 PTE 经 BBM 改写 + TLBI 击落；
3. 运行期子进程首写触发断链（alloc+copy+remap+tlbi）；
4. retain/free 引用计数记账。

# 内核堆损坏调查（SMP 阶段 3 · COW 重开阻塞项）

> 状态：未结案。已建自动捕获工具（heap_free_list 分配史环形记录 +
> dealloc 入口下一块 header 校验，HEAP-CORRUPT 转储）。本文档冻结
> 全部取证，供下会话直接续查。

## 症状（确定性复现）
`COW_SHARED_FORK=true` 时标准验收 6/13：secdemo/sleepdemo/forktest/
fstest/fsdemo/blktest 全崩；eager 模式（false）13/13 全绿。
触发点：任意 COW fork 之后的首批子进程活动。

## 关键证据
1. `HEAP-CORRUPT: dealloc ... next_hdr=0x4529313131313030`
   （ASCII: "001119)E"）与 `next_hdr=0x20746c756166206e`（"n fault "）
   —— **trap 日志消息文本片段**出现在空闲链 header 处。
2. `secdemo: collected pid=2105656` —— WaitPid 打包的 pid 高位字被
   覆盖为垃圾 ⇒ PROCESS_TABLE（Vec，堆上）记录字段遭越界写。
3. 同一指针 0x417971c0 反复以不同 size（0x30/40/60）分配释放——
   短命格式化 String 的典型复用模式。
4. eager 模式全绿 ⇒ 损坏与 COW 特有的运行期行为强相关：
   子/父栈首写触发的 Permission fault → 断链路径。

## 主嫌疑链
`handle_sync` 的 DataAbort 分支构造 `format_sync_exception`（堆 String，
~100B，恰为受损块尺寸档）→ 若断链失败落 SIGSEGV 终止路径，消息 String
的生命周期与某处裸指针写入交错。**待验证假设**：断链失败（或重复断链）
时 terminate 路径对 PROCESS_TABLE / TrapFrame 的写与 String 增长重分配
存在别名叠加。

## 下会话行动清单
1. 在 `format_sync_exception` 返回的 String 上加 canary（尾部 MAGIC），
   drop 前校验——把「谁写穿它」钉死到具体调用点；
2. 审查 handle_cow_write_fault 失败分支（返回 false 时是否仍继续用
   已 take 的空间/frame）；
3. 验证 Permission fault 是否在断链成功后被**二次**触发（TLB 未击落？
   bbm 屏障序？）——若是，free-list 损坏可能源于 phys 页被双计；
4. 修复后翻转 COW_SHARED_FORK 重跑 13/13 + `-smp 4` forktest 压力。

## 工具遗产
heap_free_list::dump_if_suspicious / HIST_RING（16 条分配史环形缓冲）：
dealloc 入口自动校验下一块 header，异常即打印最近分配序列。
生产保留无害（校验 O(1)）；定位完成后可移除。

## 追加取证（2026-08-24 深夜 · 全量堆轨迹 + 生命周期探针轮）

1. **内核堆完全干净**：sleepdemo 全窗口 alloc/dealloc 轨迹逐条核验，
   地址/尺寸序列合法，无任何越界或重叠——损坏不在堆分配器。
2. **父进程路径正确**：恰好一次睡眠登记、一次唤醒、elapsed 打印，
   随后阻塞 join——符合预期。
3. **子进程三怪象**：① 仅一次成功 COW-BREAK（far=栈页 ✓ ok=true）后
   静默自旋（反复 DISP 同一 pid、零输出零退出）；② 最终其记录**凭空
   消失**（父 wait 得 NotFound(3)）；③ 无任何 trap 终止日志。
4. 结论修正：损坏的「日志串覆写」表象可能是果不是因——子进程记录
   字段被破坏在先，后续 dealloc 读到被挪用的相邻块。

## 下会话首选工具
`qemu -d int -D int.log` 抓 fork 窗口全异常流；重点核对：
dispatch→switch_to 对「started=true 的 COW 子进程」首次恢复路径 vs
knife10 分支同路径的差异（含 TTBR0 activate 时序 × KASLR 栈偏移）。

## 二分排除（2026-08-24 深夜 · 第17-18刀期间）
| 实验 | 结果 | 结论 |
| --- | --- | --- |
| 禁用父侧 BBM 断链（父保持 RW 直写共享页） | 仍 6/15 崩，签名一致 | **父侧断链/屏障序排除** |
| 堆全量轨迹（sleepdemo 窗口） | 序列完全合法 | 分配器算法本身无恙 |
| CANARY-SMASH 全程零触发 | 载荷尾部无越界 | 写入者绕过 canary 位置（header 直写/wild write） |

## 收窄后的事故模型
COW fork 完成后的**子进程首次用户态活动窗口**内，某处对内核堆的
free-list header 发生 8 字节级覆写（内容为 trap 日志串片段）；子进程
随之静默自旋、记录消失。eager 模式（不共享页、全量复制）确定性无此象。

## 下会话首选
`qemu -d int -D int.log -singlestep` 包裹 sleepdemo fork 窗口，
对照 eager/COW 两次运行的异常流差异；同时审查 `cow_share_leaf`/
`install_leaf_descriptor` 与 `map_physical_page` 在**子表新建 L1/L2**
时对 `KERNEL_SHARED_L1` 的处理是否与 eager 路径存在别名差异。

## 终极隔离实验（2026-08-24 · 子进程立即退出诊断模式）
子进程首语句改为 `exit(0x42)`（无任何打印/syscall 前置）：
- 结果：父 elapsed=0、wait NotFound(3)、**exit(0x42) 从未被收集**
- ⇒ 子进程在 fork 返回后**一条用户指令都没执行**
- ⇒ 且父进程的 Sleepticks 回写同样丢失（elapsed=0）
- 双症状同窗：fork 完成 → enqueue(child) → 父阻塞 → 调度切换窗口

## 收窄后唯一自洽的事故模型
`alloc_table_slot_locked` 在 fork 中可能触发 **Vec 重分配**（表生长），
而 COW clone 之后、记录写入之前存在一个窗口——若此刻发生槽位/索引
错位（Vec realloc 搬移 × 快照序号），父子帧与表的映射即错乱。
eager 模式同样走此代码却全绿 ⇒ 差异必然在 **COW 特有的克隆路径
（bbm/tlbi/refcount 触碰了什么共享状态）× Vec 生长的叠加**。

## 已排除（2026-08-24 深夜追加）
- ~~fork 窗口 Vec 生长~~：预扩容实验（clone 前 reserve至上限）未修复，
  仍 2/15 败（secdemo/sleepdemo）——排除表生长错位假说。
- 分配器算法：全量轨迹合法。
- 父侧 BBM 断链/屏障序：跳过实验仍崩。

## 剩余差异面（eager 与 COW 的全部区别）
1. 子页表含指向**父物理页**的 RO+COW 描述符（vs 私有 RW 副本）；
2. 父侧 PTE 经 BBM 改写 + TLBI 击落；
3. 运行期子进程首写触发断链（alloc+copy+remap+tlbi）；
4. retain/free 引用计数记账。

## 下会话首选
`qemu -d int,in_asm -D trace.log` 包裹 sleepdemo fork→首断链窗口，
eager/COW 各跑一次 diff 异常流；重点核对断链后**重取指的翻译来源**
（TLB vs 页表）与子页表 L1/L2 新建表的内核别名可见性。



## -d int 全异常流结论（2026-08-24 · 追加轮）
COW-on sleepdemo 全程 237K 异常逐条核验：
1. 内核侧异常流 **100% 正常**——无意外 abort、无缺失返回；唯一 Data
   Abort 即子进程首栈写（断链 ok=true）；
2. 子进程断链后陷入 **单地址无限 SVC 循环**（ELR 恒 0x2130a4 ×9），随后
   让位给 shell 主循环的 ConsoleRead/Yield 忙等对（91K×2，正常空转）；
3. **僵尸记录 pid 字段被覆写为垃圾**（2105656）——wait 扫描按 pid 匹配
   故 NotFound(3)，统一解释「子进程静默消失」。

## 事故模型 v3（当前最优）
COW fork 后某刻，进程表内僵尸/活体记录的头部字段被外部数据覆写——
覆写内容含日志风格 ASCII ⇒ 覆写者持有指向表缓冲的错位指针。
eager 同路径全绿 ⇒ 因果挂靠 COW 特有的 phys retain/bbm 序列，
或该序列首次踩中潜伏分配缺陷。

## 下会话首选：表内存取证
wait NotFound 处 `dump_record_bytes(slot)` hex-dump 记录 256B，对照
ProcessRecord 布局找被覆写字段偏移；再由覆写内容反查来源缓冲。

## 🎯 根因行为锁定（2026-08-24 · WAIT-STEP 探针轮）
`WAIT-STEP caller_slot=5 target=7 flags=0`——**子进程（pid7/slot5）以
「父分支」语义调用 wait_pid(7)**（等待自己 ⇒ NoChild ⇒ NotFound(3)）。

⇒ COW 模式下 fork 的返回值分配被破坏：**子进程拿到的 x0 ≠ 0**。
⇒ 连锁全解释：子走父分支→sleep(垃圾ticks)/wait(自身)→NotFound→FAIL
  →回主循环忙转（DISP spam）；真父阻塞等一个永不退出的"伪父"
  （elapsed 回写丢失亦同源——帧归属错乱）。
⇒ forktest 为何通过：其子分支首两个 syscall(getpid/getppid) 不依赖
  x0 值，且打印内容恰能掩盖分支错位（待复核）。

## 已证实/已排除边界
✅ 创建时 `(*child_tf).regs[0] = 0` 写入正确（FORK-COPY 探针实读）
✅ 进程表记录完好（hex-dump 实证 pid/tgid/parent 全对）
✅ 堆轨迹合法、Vec 生长排除、父侧 BBM 排除、CANARY 零触发
❓ 写入(创建时) 与 装载(dispatch 时) 之间，child_tf.regs[0] 被改写
   —— 或 restore_context 装载路径读错偏移/帧

## 下会话行动（二选一或并用）
1. 括号探针：fork 写零后、dispatch switch_to 前，两处各打
   `child_tf.regs[0]` —— 精确圈定改写发生的半区；
2. 若装载侧：dump restore_context 入口处 frame 前 16 字节 +
   实际 ldp 的 x0 值对照；若写侧：在 write 后立即回读断言。
3. 终极兜底：`-d int,in_asm --singlestep` 包裹窗口逐指令对照。


---

## 2026-08-25 最终结案（后文优先于以上历史假说）

此前的 Vec、FPU、日志 String、进程表覆写等判断均是逐步二分时的中间
假说。fresh HEAD + fresh ISO 重新验收后，最终确认是**两个彼此独立的
底层 bug 叠加**。

### 根因 A：COW 的 TLBI operand 编码错误

父侧 fork 共享可写页时，PTE 的 BBM 次序本身正确：先 break，再把父 PTE
改成 RO + software COW 位。但 `kbbm_barrier(va)` 执行：

```text
tlbi vaae1is, Xt
```

时把**完整 byte VA**放进 `Xt`。AArch64 按 VA 的 TLBI 指令在寄存器中
编码的是 `VA[55:12]`，因此正确 operand 是 `va >> 12`。

错误后果不是立刻 fault，而是父核的旧 **RW TLB translation 仍然存活**。
页表看起来已经只读，父进程却能继续借陈旧 TLB 静默写共享物理栈页。
子进程 fork 返回后第一条栈写本应保存 `x0=0`，但共享栈又被父分支覆盖，
于是出现历史上的统一症状：子拿父返回值、走父分支、wait 自己、记录随后
表现为“被覆写/消失”。这也解释了为什么大量进程表/Vec 探针抓不到真正
写入者——写穿发生在**用户共享物理页 + stale TLB**，不是内核 Vec。

修复：`tlbi_va_operand(va) = va >> 12`，并加纯函数单测钉死编码。
修后 fresh QEMU：`shared=34 ... copied=0`，子分支正常，标准 15/15 全绿。

### 根因 B：free-list 的不可分裂尾巴形成 ghost gap

另一个 `corrupt next block` 是分配器自身 bug。选中 free block 后若
`remainder < MIN_FREE`，旧实现正确地“不创建新 free block”，却仍把
allocated header/footer 的 size 写成较小的 `used`。因此 `used` 与原 block
结尾之间留下了一段**没有任何 header 所有权的 gap**。

后续 dealloc 以 `block + used` 当下一块起点，把 gap 里的任意数据解析成
header，最终报出巨大的假 free block / `corrupt next block`。修复规则是：
余量不足以构成合法 free block 时，本次 allocation 必须吞掉整个原 block，
即 committed size = original size。新增 `tiny_remainder_is_absorbed...` 回归；
公共用户态 `StaticFreeList` 同类边界同步修复。

### 同轮修出的相关正确性问题（非上述主根因）

- AArch64 异常入口过去先用 x16 取 TPIDR_EL1，导致异步异常丢失用户 x16；
  现先在 EL1 栈暂存 x16/x17，再落 TrapFrame。
- COW clone 中途 OOM 现在销毁半成品页表并撤销 retain，不再泄漏引用。
- 调查期 `FORK-DONE/WAIT-STEP/TBL-DUMP/HIST_RING` 等探针已全部移除。

结论：`COW_SHARED_FORK` 现默认 **true**，历史“COW 阻塞项”关闭。
