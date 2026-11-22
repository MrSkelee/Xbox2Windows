; probe(fn, ctx, count, trace, observed): inspect RSI, RDI and DF after the call.
.code
probe PROC FRAME
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, rcx
    mov rcx, rdx
    mov rdx, r8
    mov r8, r9
    mov rsi, 0123456789abcdefh
    mov rdi, 0fedcba9876543210h
    call rax
    mov r10, [rsp+60h]
    mov [r10], rsi
    mov [r10+8], rdi
    pushfq
    pop r11
    and r11, 400h
    mov [r10+16], r11
    cld
    add rsp, 28h
    pop rdi
    pop rsi
    ret
probe ENDP
END
