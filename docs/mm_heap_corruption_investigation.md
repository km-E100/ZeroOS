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
