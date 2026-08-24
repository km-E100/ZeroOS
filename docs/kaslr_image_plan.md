# 镜像级 KASLR 立项设计（结构性天花板 · 待实施）

> 前置事实：第十五刀已交付 KASLR 阶段 1（rng 模块熵源 + spawn/exec
> 用户栈随机化 ≤1MiB）。本文档规划**阶段 2：内核/用户镜像基址随机化**。

## 为什么不能直接做

内核与用户 ELF 均为**静态链接、固定虚地址**：
- 微内核：恒等映射基址 0x40000000 段，代码内绝对地址由链接脚本定死；
- 用户 ELF：zero-shell 等固定加载于 0x200000（map_user_elf_segments
  按 segment vaddr 原地映射）。

直接挪动加载地址 ⇒ 所有绝对寻址失效。随机化必须二选一：

| 方案 | 改动面 | 风险 |
| --- | --- | --- |
| A. PIE 化 | `-C relocation-model=pie` + `-pie` 链接 + boot 时处理 `R_AARCH64_RELATIVE` 重定位表 | 链接脚本/UEFI PE 封装/`-Zbuild-std` 三处联动；裸机 std 构建兼容性未知 |
| B. 固定偏移重定位 | 链接时在镜像头预留 reloc 目录（自定义 section），bootloader 按随机页对齐 offset 扫描修正绝对地址 | 需要枚举全部绝对地址来源（字面量池/GOT/跳转表），LLVM 无现成出口 |

## 推荐路径：A（PIE），分四步

1. **用户态先行**：user_app/userlib 试开 PIE——exec 加载器解析
   `.dynamic` 的 RELA 表逐条 `base+addend` 修正。用户镜像小、失败面小，
   且 exec 五阶段流水已有 CommitRebind 原子性骨架可挂载修正步骤。
2. **bootloader 侧**：bootloader-uefi 为镜像分配 N 个候选基址之一
   （rng 已有），PE 头 ImageBase 同步改写。
3. **微内核跟进**：恒等映射改为「物理随机基址 + VA=PA+offset」双映射，
   kernel_main 相对寻址自举（参照 Linux `CONFIG_RELOCATABLE` 的
   relocate_kernel 做法）。
4. **验收**：连续 20 次 `-smp 4` 启动，dump 内核基址分布；15/15 验收
   全绿；threaddemo/forktest 压力无回归。

## 与既有安全层的关系

- 阶段 1 栈随机化保持不变，二者叠加；
- KASLR 生效后需同步审计 `KERNEL_SHARED_L1` 恒等窗口的暴露面；
- COW 重开（SMP 阶段 3，见 docs/mm_heap_corruption_investigation.md）
  不依赖本项目，可并行。
