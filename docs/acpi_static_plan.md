# ACPI 静态表支持（实现状态 + 后续范围）

## 2026-08-25 已落地

Zero OS 当前只做**静态 ACPI 表**，AML 明确不做。QEMU virt + edk2 可在
UEFI System Table 的 config table 暴露 ACPI 2.0 RSDP，因此整个链路可在
QEMU 验证。

当前真实数据流：

1. `bootloader-uefi` 用 `uefi::table::cfg::ACPI2_GUID` 找 RSDP；
2. 不扩 `zero_abi::BootInfo`，而是像 memory-bytes 汇槽一样，通过已加载
   kernel 的 ELF symbol `__zero_rsdp_phys` 直接补丁 RSDP 物理地址；
3. MM/恒等映射建立后 `microkernel::acpi::init()` 解析 RSDP → XSDT →
   第一个 MADT/APIC 表；多字节 packed 字段逐字节 volatile 读取后按
   little-endian 组装，避免未对齐 `read_volatile` UB；
4. MADT 当前产出 enabled CPU 的 MPIDR 列表与 GICD base；
5. `smp::boot_secondaries()` 优先按 MADT CPU list 做 PSCI CPU_ON，并用
   当前 boot CPU 的 MPIDR affinity 过滤自身；无 ACPI 时保留 legacy
   MPIDR 探测回退。

fresh `-smp 4` 验证可见：`MADT cpus=4`，cpu1/2/3 均通过 MADT MPIDR
点亮，最终 `online=4`。

## 当前范围边界

| 表 | 当前状态 | 消费方 |
| --- | --- | --- |
| RSDP → XSDT | ✅ 校验签名/checksum/长度 | ACPI 目录入口 |
| MADT GICC | ✅ enabled + MPIDR | SMP CPU_ON |
| MADT GICD | ✅ 解析并缓存 base | 尚未替换 GIC driver 的 QEMU 默认基址 |
| GTDT | ⏳ 未解析 | timer 仍使用当前平台参数 |
| FADT/PSCI 描述 | ⏳ 未解析 | PSCI conduit 仍按已验证的 HVC 路径 |
| AML / _DSM / _PTS / 热插拔 | ❌ 明确不做 | 未来真机需求另立项 |

## 后续如果继续做 ACPI

1. GIC 初始化优先消费 MADT GICD/GICR 数据，legacy 常量只作回退；
2. 解析 GTDT，把 timer PPI/flags 从平台常量变成固件数据；
3. 若迁移到需要 SMC conduit 的真机，再消费 FADT/DT 信息选择 PSCI
   conduit；
4. 对 XSDT/MADT 增加更多 malformed/fuzz case，但任何解析失败都必须
   fail-open 到已验证的 legacy 平台路径，不能让坏表打穿启动。
