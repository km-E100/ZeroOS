# Zero OS 内存管理规划

## 目标
- **物理内存分配器**：提供基本的页分配与回收接口，后续可拓展伙伴算法/NUMA。
- **虚拟内存**：建立内核页表、映射用户态，支持页保护与懒加载。
- **堆分配**：为内核与用户态提供动态分配器（如 `linked_list_allocator` 或自研 slab/arena）。

## 当前进展
- `microkernel/src/mm/phys.rs` 提供位图式物理页分配器：
  * `init(memory_bytes, reserved_bytes)` 初始化位图并预留内核所需页。
  * `alloc_page` / `free_page` 返回页对齐的物理地址。
  * `free_pages` 查询剩余页数量。
- `microkernel/src/mm/paging.rs`：建立基础 L1 页表（2MiB block identity 映射）并在启动时安装至 `TTBR1_EL1`；可为用户线程创建/激活独立的 L1 页表副本。
- `microkernel/src/mm/address_space.rs`：封装 `AddressSpace`，调度器在上下文切换时自动写入/清空 `TTBR0_EL1`。
- `microkernel/src/mm/heap.rs`：实现简单的 bump allocator（从物理页分配器申请 1 MiB）并注册为内核全局分配器。

当前 `mm::init` 在启动阶段执行：初始化物理内存、加载内核页表、启动堆。

## 下一步
1. **页表拓展**
   - 解析 BootInfo/设备树获取实际内存区段，完善内核映射（代码/数据/设备）。
   - 支持 finer-grained 映射（L2/L3 页表），实现 `map_kernel_page`、`map_user_page` 等 API 并处理 TLB flush。

2. **用户空间映射**
   - 在 `AddressSpace::map_stack`/`map_region` 中真正分配物理页并映射到用户虚拟地址。
   - 进程加载阶段将 ELF 段或 `.app` 内容映射到新建地址空间。

3. **堆与系统接口**
   - bump allocator 仅支持线性增长，需引入 slab/伙伴或全局 `linked_list_allocator`，同时实现回收逻辑。
   - 设计 `sys_brk`、`sys_mmap` 系统调用，允许用户态按需向内核申请/释放页。

4. **增强与维护**
   - 大页、懒加载、写时复制、NUMA、自适应回收策略。
   - 将 `mm::init` 使用的固定总量/预留值替换为 BootInfo/Bios 提供的真实内存布局。

后续迭代将围绕“精细映射 + 可回收堆 + 系统调用”展开，逐步构建完整的内存管理子系统。 
