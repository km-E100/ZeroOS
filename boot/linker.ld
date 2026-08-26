ENTRY(_start)

SECTIONS
{
    . = 0x40080000;
    __kernel_start = .;

    .text : ALIGN(4K) {
        KEEP(*(.text.boot))
        *(.text*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata.boot*)
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
