# Zero OS 内存管理现状

## 当前实现（2026-08-25）

- **物理页分配**：`microkernel/src/mm/phys.rs` + `phys_bitmap.rs` 以 4KiB
  页位图管理 RAM，并维护每页 `u16` 引用计数供 COW 使用。UEFI bootloader
  会把 CONVENTIONAL memory map 写入内核汇槽；内核按真实可用区间排除洞、
  内核镜像与 pstore，而不是把 `[RAM_BASE, RAM_BASE+N)` 全当连续 RAM。
- **AArch64 页表**：内核恒等映射 + 每进程独立用户页表树；支持 L3 4KiB
  映射、权限/W^X、BBM 更新、TLBI、用户栈、ELF 段、brk 区域与 MMIO 租约。
  调度切换由 `AddressSpace::activate()` 写 TTBR0 并做本核 TLB 维护。
- **COW fork**：默认启用（`table_walk::COW_SHARED_FORK = true`）。可写叶
  fork 时父子共享物理页、双侧改 RO + software COW 位并 `retain_page`；
  任一方首写触发 Data Abort，按 refcount 复制或原地恢复可写后重放指令。
  text/rodata 直接只读共享。clone 中途 OOM 会回滚半成品页表和引用。
- **用户堆**：号位 24 `Brk` 管理 `[USER_HEAP_BASE, brk)`，增长分配物理页、
  收缩执行 BBM+TLBI 后回收物理页；fork 继承 break 与对应 COW 映射。
- **内核堆**：8MiB 固定区域上的可回收 first-fit free-list，支持 split、
  footer/back-pointer、相邻合并与高对齐。2026-08-25 修复了“余量不足
  `MIN_FREE` 时未吞掉尾巴”的 ghost-gap bug，并有 host 回归测试。
- **用户态运行库堆**：长期服务与 shell 统一使用
  `useralloc::StaticFreeList<N>`，固定内存预算但可 free/coalesce，替代原来
  永不回收的 bump allocator；内部有锁，可供用户线程共享。
- **栈随机化**：spawn/exec 的用户栈顶按页向下随机偏移；bootfs spawn
  不再在装载收尾把随机 SP 覆盖回固定 `USER_STACK_TOP`。

## 2026-08-25 COW 根因结案

历史 COW 回归的关键不是 PTE 本身，而是父侧 BBM 后的 TLBI operand。
AArch64 `TLBI VAAE1IS, Xt` 在 `Xt` 中要求 `VA[55:12]`，旧实现却传完整
byte VA。于是父 PTE 虽已只读，旧 RW TLB translation 仍存活，父进程可
静默写穿共享用户栈，最终让子进程读到父分支的 fork 返回值。现统一通过
`tlbi_va_operand(va) = va >> 12` 编码并有单测。详细取证见
`docs/mm_heap_corruption_investigation.md`。

## 仍待演进

1. **通用 mmap/region VM API**：当前有 brk、栈、ELF、MMIO 等专用路径，
   尚没有完整的用户态 mmap/munmap/protection 接口。
2. **ASID 与更细粒度 shootdown**：当前上下文切换偏保守地清 TLB；SMP
   正确性已覆盖，但可进一步引入 ASID、按地址/按进程的跨核 IPI shootdown。
3. **内核对象分配器**：free-list 已可回收，但长期可考虑 slab/size class
   降低碎片与锁竞争。
4. **镜像级 KASLR**：目前只有用户栈随机化；内核/用户 ELF PIE 重定位
   仍见 `docs/kaslr_image_plan.md`。
5. **NUMA/大页/内存压力回收**：当前 QEMU virt/实验硬件暂不需要，属于
   后续扩展而非现有正确性缺口。
