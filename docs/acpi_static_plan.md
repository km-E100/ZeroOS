# ACPI 静态表支持立项设计（真机迁移前置 · 结构性天花板收口）

> 裁决沿革：原"先 SMP 后 ACPI"。SMP 阶段 0-2 已交付（蛮力 MPIDR 探测
> 在 QEMU virt 可用），ACPI 窗口开启。**关键更新：QEMU virt + edk2 即
> 生成完整 ACPI 表**（RSDP 挂 UEFI System Table config table），解析/
> 测试全程可在 QEMU 完成，不受真机限制——时机纯属优先级选择。

## 范围：只做静态表解析，AML 明确不做

| 表 | 内容 | 内核消费方 |
| --- | --- | --- |
| RSDP → XSDT | 表目录 | bootloader 侧一次性遍历 |
| MADT | GICC 条目（每核 MPIDR/GICR 指针）、GICD 帧、MSI 帧 | `boot_secondaries` 替换蛮力 MPIDR 扫描；GIC 初始化参数化 |
| GTDT | EL1 物理定时器 PPI 号与标志 | timer::init 的硬编码 IRQ=30 替换 |
| FADT | （可选）PSCI 通道确认 | 与 DT/hvc 实测互为校验 |

**明确不做**：AML 解释器、_DSM/_PTS 电源对象、热插拔——QEMU 场景
用不到，真机需求出现时另立项。

## 四步实施

### WS-A bootloader 抓表
bootloader-uefi 在 `ExitBootServices` **前**从 System Table config
数组按 `EFI_ACPI_TABLE_GUID` 取 RSDP→XSDT；校验 checksum 后把
RSDP 物理地址塞进 bootinfo 新增字段（向后兼容：0 = 无 ACPI）。

### WS-B abi/bootinfo 扩展
`zero_abi::BootInfo` 追加 `rsdp_phys: u64`；文档登记。内核侧
`mm/mod.rs` 引导期把 XSDT 区域恒等映射标记保留（防分配器挪用）。

### WS-C 内核解析器（no_std）
新模块 `acpi.rs`：XSDT 遍历 → MADT IC 条目流（GICC/GICD/GICR）→
产出 `CpuList { mpidr, }` 与 `GicInfo`、`TimerInfo(GTDT)`。
host 单测：手工构造字节表钉死解析矩阵（checksum 错/条目截断/重复项）。

### WS-D 替换蛮力点 + 验收
1. `smp::boot_secondaries`：按 CpuList 逐核 CPU_ON（删除六组合扫描，
   保留作为无 ACPI 回退）；2. gic/timer 参数化；3. `-smp 4` 下打印
   枚举结果与实测一致；4. 标准验收 15/15 零回归。

## 工作量与风险
一个会话可收口。风险最低项：QEMU 生成的表格式稳定；checksum 校验
失败一律回退现有硬编码路径（fail-open to legacy），不存在"解析坏表
打穿启动"的路径。
