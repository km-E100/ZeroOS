.section .text.boot
.align 7
.globl _start
.type _start, %function
_start:
    // 1. 关闭 IRQ/FIQ 并使用 EL1 栈
    msr    DAIFSet, #0xf           // 屏蔽所有异常
    msr    SPSel, #1               // 使用 SP_EL1

    // 2. 建立初始栈
    ldr    x0, =_stack_top
    mov    sp, x0

    // 3. 清理 BSS 段
    bl     zero_bss

    // 4. 调用内核入口
    ldr    x0, =boot_info_struct
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
    ldr    x0, =__bss_start
    ldr    x1, =__bss_end
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
// 静态引导信息（可由链接时覆盖）
// -----------------------------------------------------------------------------
.section .rodata.boot, "a"
.align 3
.globl boot_info_struct
boot_info_struct:
    .quad __zero_ipc_server_entry
    .quad __zero_zfs_server_entry
    .quad __zero_launchd_entry
    .quad __zero_rootfs_image
    .quad __zero_driver_table

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

.section .rodata.boot, "a"
.align 3
.weak __zero_rootfs_image
.type __zero_rootfs_image, %object
__zero_rootfs_image:
    .quad 0
    .quad 0

.align 3
.weak __zero_driver_table
.type __zero_driver_table, %object
__zero_driver_table:
    .quad 0
    .quad 0

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
