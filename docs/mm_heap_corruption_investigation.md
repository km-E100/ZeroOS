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
