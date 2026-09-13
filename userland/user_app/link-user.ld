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

/* 显式 PHDRS：不声明时 lld 会按"实际有内容的节"推断段标志，
 * .data 为空而只有 .bss 时整段被标成只读 R —— 用户态清 .bss 第一笔
 * 写入即触发 permission fault（2026-08-22 实机复现）。
 * text=R+X(5)，data=R+W(6)；两段都必须存在，即使某一侧为空。 */
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
