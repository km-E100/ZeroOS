ENTRY(_start)
PHDRS {
 text PT_LOAD FLAGS(5);
 data PT_LOAD FLAGS(6);
 dynamic PT_DYNAMIC FLAGS(6);
}
SECTIONS {
 . = 0;
 .text : ALIGN(4K) { KEEP(*(.text.boot)) *(.text*) } :text
 .rodata : ALIGN(4K) { *(.rodata*) } :text
 .rela.dyn : ALIGN(8) { *(.rela.dyn*) } :text
 .data : ALIGN(4K) { *(.data*) } :data
 .dynamic : ALIGN(8) { *(.dynamic) } :data :dynamic
 .bss (NOLOAD) : ALIGN(4K) { __bss_start=.; *(.bss*) *(COMMON) __bss_end=.; } :data
 /DISCARD/ : { *(.comment*) }
}
