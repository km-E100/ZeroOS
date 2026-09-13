.text
.global _start
.type _start,%function
.extern shared_answer
_start:
    bl shared_answer
    cmp x0, #42
    b.ne 1f
    adr x1, passmsg
    mov x2, #(passend-passmsg)
    mov x0, #9
    svc #0
    mov x1, #42
    mov x0, #5
    svc #0
0:  b 0b
1:
    adr x1, failmsg
    mov x2, #(failend-failmsg)
    mov x0, #9
    svc #0
    mov x1, #98
    mov x0, #5
    svc #0
2:  b 2b
.section .rodata
passmsg: .ascii "dynapp: SHARED PASS\r\n"
passend:
failmsg: .ascii "dynapp: SHARED FAIL\r\n"
failend:
