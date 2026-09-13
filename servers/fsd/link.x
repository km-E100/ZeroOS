/* Zero OS 用户态服务链接脚本（与 servers/security/link.x 同一契约）。
 *
 * 基址 0x200000（用户代码区，L1[0] 私有副本），加载器按 PT_LOAD 段
 * 虚拟地址映射，入口取 ELF 头 e_entry（user_elf 校验其落在可执行
 * LOAD 段内）。
 *
 * 显式 PHDRS：不声明时 lld 会把纯 .bss 段标成只读 R，运行期清 bss
 * 即 permission fault（launchd/user_app 已实机踩雷）。text=R+X(5)，
 * data=R+W(6)。_start 先清 .bss 再进 server_main。
 */
ENTRY(_start)

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
