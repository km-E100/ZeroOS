/* Zero OS launchd 用户态链接脚本。
 *
 * 基址 0x200000：用户代码/数据区（L1[0] 私有副本），与
 * userland/user_app/link-user.ld 的契约一致——加载器按 PT_LOAD
 * 段虚拟地址映射，入口取第一个可执行段（0x200000）。
 *
 * 历史教训：链接在 0x40080000（与内核同址）的旧版 blob 曾把用户表
 * 里内核 2MiB block 拆掉，导致切表后内核取指/向量表丢失映射。
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