/* Zero OS user application linker script.
 *
 * 用户程序链接基址必须落在内核共享区之外：
 *   - [0x200000, 1GiB)  用户代码/数据（L1[0] 私有 L2 副本，block 按需拆分）
 *   - [2GiB, 4GiB)      预留（bootfs 0x80000000、用户栈顶 0xFFFF_F000）
 *   - [1GiB, 2GiB)      内核共享表（L1[1]）——用户程序绝不允许链接到这里，
 *                       否则 map_physical_page 会以 MapError::KernelRegion 拒绝。
 *
 * 历史教训：链接在 0x40080000（与内核同址）的 Shell 曾把用户表里内核
 * 2MiB block 拆掉，切表后内核自身取指/向量表全部丢失映射 → 递归异常风暴。
 */
ENTRY(_start)

SECTIONS
{
    . = 0x200000;

    .text : ALIGN(4K) {
        KEEP(*(.text.boot))
        *(.text*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata*)
    }

    .data : ALIGN(4K) {
        *(.data*)
    }

    .bss (NOLOAD) : ALIGN(4K) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    }

    /DISCARD/ : {
        *(.comment*)
    }
}
