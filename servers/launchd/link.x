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

/* 显式 PHDRS：与 userland/user_app/link-user.ld 同一契约。
 * 不声明时 lld 会把纯 .bss 段标成只读 R，运行期清 bss 即 permission
 * fault（user_app 已实机踩雷）。text=R+X(5)，data=R+W(6)。 */
PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x200000;

    .text : ALIGN(4K) {
        KEEP(*(.text.boot))
        *(.text*)
    } :text

    .rodata : ALIGN(4K) {
        *(.rodata*)
    } :text

    .data : ALIGN(4K) {
        *(.data*)
    } :data

    .bss (NOLOAD) : ALIGN(4K) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    } :data

    /DISCARD/ : {
        *(.comment*)
    }
}