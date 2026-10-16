.section .text.boot
.align 7
.globl _start
.type _start, %function
_start:
    // 1. 关闭 IRQ/FIQ 并使用 EL1 栈
    msr    DAIFSet, #0xf           // 屏蔽所有异常
    msr    SPSel, #1               // 使用 SP_EL1

    // 2. 建立初始栈
    adrp   x0, _stack_top
    add    x0, x0, :lo12:_stack_top
    mov    sp, x0

    // 3. 清理 BSS 段
    bl     zero_bss

    // 4. 以 PC-relative 地址在运行时填 BootInfo。这样 boot_info_struct
    // 不含任何 ABS64 relocation，整个入口从第一条指令即可任意搬移。
    adrp   x0, boot_info_struct
    add    x0, x0, :lo12:boot_info_struct
    adrp   x1, __zero_ipc_server_entry
    add    x1, x1, :lo12:__zero_ipc_server_entry
    str    x1, [x0, #0]
    adrp   x1, __zero_zfs_server_entry
    add    x1, x1, :lo12:__zero_zfs_server_entry
    str    x1, [x0, #8]
    adrp   x1, __zero_launchd_entry
    add    x1, x1, :lo12:__zero_launchd_entry
    str    x1, [x0, #16]
    adrp   x1, __zero_rootfs_image
    add    x1, x1, :lo12:__zero_rootfs_image
    str    x1, [x0, #24]
    adrp   x1, __zero_driver_table
    add    x1, x1, :lo12:__zero_driver_table
    str    x1, [x0, #32]
    adrp   x1, __zero_memory_bytes
    add    x1, x1, :lo12:__zero_memory_bytes
    str    x1, [x0, #40]
    bl     kernel_main

// 如果返回则挂起
1:
    wfe
    b      1b

.size _start, . - _start

// -----------------------------------------------------------------------------
// Zero BSS helper
// -----------------------------------------------------------------------------
.align 2
.type zero_bss, %function
zero_bss:
    adrp   x0, __bss_start
    add    x0, x0, :lo12:__bss_start
    adrp   x1, __bss_end
    add    x1, x1, :lo12:__bss_end
    cmp    x0, x1
    b.hs   2f
1:
    str    xzr, [x0], #8
    cmp    x0, x1
    b.lo   1b
2:
    ret
.size zero_bss, . - zero_bss

// -----------------------------------------------------------------------------
// BootInfo storage. `_start` fills all six words with PC-relative addresses.
// Keeping this in writable data avoids absolute pointers in the ELF image and
// is also more honest than declaring a runtime-filled structure read-only.
// -----------------------------------------------------------------------------
.section .data.boot, "aw"
.align 3
.globl boot_info_struct
boot_info_struct:
    .zero 48

// 默认服务器入口占位符（可被强符号覆盖）
.section .text.boot
.weak __zero_ipc_server_entry
.type __zero_ipc_server_entry, %function
__zero_ipc_server_entry:
    b .

.weak __zero_zfs_server_entry
.type __zero_zfs_server_entry, %function
__zero_zfs_server_entry:
    b .

.weak __zero_launchd_entry
.type __zero_launchd_entry, %function
__zero_launchd_entry:
    b .

// __zero_rootfs_image / __zero_driver_table are mandatory strong Rust symbols
// from kernel/src/rootfs.rs and kernel/src/drivers.rs. Do not define weak
// fallbacks in this same global_asm object: release codegen can coalesce the
// Rust statics and assembly, and LLVM's assembler then rejects a same-object
// weak definition whose binding is later upgraded to global.
.section .rodata.boot, "a"
.align 3

// 可用物理内存字节数占位（BootInfo.memory_bytes 指向的位置）。
// 0 = 未知：内核 mm 初始化时回退到默认 512 MiB。
// UEFI 路径由 bootloader 在启动前把真实值写回这里；
// 也可由内核强符号覆盖（[no_mangle] static __zero_memory_bytes: u64）。
.align 3
.weak __zero_memory_bytes
.type __zero_memory_bytes, %object
__zero_memory_bytes:
    .quad 0

// RSDP 物理地址占位（ACPI 立项 · docs/acpi_static_plan.md WS-A/B）：
// bootloader 从 UEFI config table 抓 ACPI2.0 RSDP 写入此处；0 = 无 ACPI，
// 内核回退硬编码探测路径。恒等映射内，内核直接读。
.align 3
.weak __zero_rsdp_phys
.type __zero_rsdp_phys, %object
__zero_rsdp_phys:
    .quad 0

// Early platform handoff. 0 = unknown/fail-safe, 1 = QEMU virt,
// 2 = Parallels ARM. early_uart_base is nonzero only when the bootloader knows
// that touching the MMIO address before ACPI/PCI discovery is safe.
.align 3
.globl __zero_platform_kind
__zero_platform_kind: .quad 0
.globl __zero_early_uart_base
__zero_early_uart_base: .quad 0

// UEFI PCI Root Bridge I/O handoff. The bootloader converts the root bridge
// Configuration() QWORD I/O descriptor into one segment/bus/host/length tuple.
// A PCI I/O BAR contains a bus address; the kernel maps it to CPU physical as
// host_base + (bar_bus_address - bus_base). len=0 means unavailable.
.globl __zero_pci_io_segment
__zero_pci_io_segment:   .quad 0
.globl __zero_pci_io_bus_base
__zero_pci_io_bus_base:  .quad 0
.globl __zero_pci_io_host_base
__zero_pci_io_host_base: .quad 0
.globl __zero_pci_io_len
__zero_pci_io_len:       .quad 0

// UEFI MP Services topology snapshot. The loader briefly runs a callback on each
// enabled AP before ExitBootServices and records the architectural MPIDR_EL1
// affinity value. The kernel uses this only when its runtime ACPI MADT view does
// not enumerate the full topology. Count is capped at four (MAX_CPUS).
.globl __zero_boot_cpu_count
__zero_boot_cpu_count: .quad 0
.globl __zero_boot_cpu_mpidrs
__zero_boot_cpu_mpidrs:
    .quad 0, 0, 0, 0

// UEFI GOP framebuffer handoff（第21刀）。bootloader 在 ExitBootServices 前
// 补丁这些标量；base=0 表示没有可直接访问的 GOP framebuffer。
.align 3
.globl __zero_fb_base
__zero_fb_base:   .quad 0
.globl __zero_fb_size
__zero_fb_size:   .quad 0
.globl __zero_fb_width
__zero_fb_width:  .quad 0
.globl __zero_fb_height
__zero_fb_height: .quad 0
.globl __zero_fb_stride
__zero_fb_stride: .quad 0
.globl __zero_fb_format
__zero_fb_format: .quad 0   // 1=RGBX8888, 2=BGRX8888

// -----------------------------------------------------------------------------
// 内核引导栈
// -----------------------------------------------------------------------------
.section .bss.boot, "aw", %nobits
.align 12
.globl _stack_bottom
_stack_bottom:
    .skip 0x4000
.globl _stack_top
_stack_top:
