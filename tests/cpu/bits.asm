; Source-owned differential fixture for bit manipulation and conversion instructions
; (POPCNT, LZCNT, BSF, BSR, BSWAP, BT, BTS, BTR, BTC, CBW, CWDE, CDQE, CWD, CDQ, CQO)
.code

popcnt32 PROC FRAME
    .endprolog
    mov rax, -1
    popcnt eax, ecx
    mov r9d, 0
    jne short @F
    or r9d, 1                ; ZF = 1
@@:
    mov qword ptr [rdx], r9
    ret
popcnt32 ENDP

popcnt64 PROC FRAME
    .endprolog
    popcnt rax, rcx
    mov r9d, 0
    jne short @F
    or r9d, 1                ; ZF = 1
@@:
    mov qword ptr [rdx], r9
    ret
popcnt64 ENDP

lzcnt32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1
    lzcnt eax, ecx
    mov r9d, 0
    jae short @F
    mov r9d, 2               ; CF = 1
@@:
    jne short @F
    or r9d, 1                ; ZF = 1
@@:
    mov qword ptr [rdx], r9
    ret
lzcnt32 ENDP

lzcnt64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1
    lzcnt rax, rcx
    mov r9d, 0
    jae short @F
    mov r9d, 2               ; CF = 1
@@:
    jne short @F
    or r9d, 1                ; ZF = 1
@@:
    mov qword ptr [rdx], r9
    ret
lzcnt64 ENDP

bsf32 PROC FRAME
    .endprolog
    mov rax, -1
    bsf eax, ecx
    mov r9d, 0
    jne short @F
    or r9d, 1                ; ZF = 1
    xor eax, eax             ; defined zero for test
@@:
    mov qword ptr [rdx], r9
    ret
bsf32 ENDP

bsf64 PROC FRAME
    .endprolog
    bsf rax, rcx
    mov r9d, 0
    jne short @F
    or r9d, 1                ; ZF = 1
    xor rax, rax
@@:
    mov qword ptr [rdx], r9
    ret
bsf64 ENDP

bsr32 PROC FRAME
    .endprolog
    mov rax, -1
    bsr eax, ecx
    mov r9d, 0
    jne short @F
    or r9d, 1                ; ZF = 1
    xor eax, eax
@@:
    mov qword ptr [rdx], r9
    ret
bsr32 ENDP

bsr64 PROC FRAME
    .endprolog
    bsr rax, rcx
    mov r9d, 0
    jne short @F
    or r9d, 1                ; ZF = 1
    xor rax, rax
@@:
    mov qword ptr [rdx], r9
    ret
bsr64 ENDP

bswap32 PROC FRAME
    .endprolog
    mov eax, ecx
    bswap eax
    ret
bswap32 ENDP

bswap64 PROC FRAME
    .endprolog
    mov rax, rcx
    bswap rax
    ret
bswap64 ENDP

bt32 PROC FRAME
    .endprolog
    xor eax, eax
    bt ecx, edx
    jnc short @F
    mov eax, 2               ; CF = 1
@@:
    mov qword ptr [r8], rax
    ret
bt32 ENDP

bt64 PROC FRAME
    .endprolog
    xor eax, eax
    bt rcx, rdx
    jnc short @F
    mov eax, 2               ; CF = 1
@@:
    mov qword ptr [r8], rax
    ret
bt64 ENDP

bts32 PROC FRAME
    .endprolog
    mov eax, ecx
    bts eax, edx
    mov r9d, 0
    jnc short @F
    mov r9d, 2               ; CF = 1
@@:
    mov qword ptr [r8], r9
    ret
bts32 ENDP

bts64 PROC FRAME
    .endprolog
    mov rax, rcx
    bts rax, rdx
    mov r9d, 0
    jnc short @F
    mov r9d, 2               ; CF = 1
@@:
    mov qword ptr [r8], r9
    ret
bts64 ENDP

btr32 PROC FRAME
    .endprolog
    mov eax, ecx
    btr eax, edx
    mov r9d, 0
    jnc short @F
    mov r9d, 2               ; CF = 1
@@:
    mov qword ptr [r8], r9
    ret
btr32 ENDP

btr64 PROC FRAME
    .endprolog
    mov rax, rcx
    btr rax, rdx
    mov r9d, 0
    jnc short @F
    mov r9d, 2               ; CF = 1
@@:
    mov qword ptr [r8], r9
    ret
btr64 ENDP

btc32 PROC FRAME
    .endprolog
    mov eax, ecx
    btc eax, edx
    mov r9d, 0
    jnc short @F
    mov r9d, 2               ; CF = 1
@@:
    mov qword ptr [r8], r9
    ret
btc32 ENDP

btc64 PROC FRAME
    .endprolog
    mov rax, rcx
    btc rax, rdx
    mov r9d, 0
    jnc short @F
    mov r9d, 2               ; CF = 1
@@:
    mov qword ptr [r8], r9
    ret
btc64 ENDP

cbw_test PROC FRAME
    .endprolog
    movzx eax, cl
    cbw
    movzx eax, ax
    ret
cbw_test ENDP

cwde_test PROC FRAME
    .endprolog
    movzx eax, cx
    cwde
    ret
cwde_test ENDP

cdqe_test PROC FRAME
    .endprolog
    mov eax, ecx
    cdqe
    ret
cdqe_test ENDP

cwd_test PROC FRAME
    .endprolog
    mov r8, rdx
    mov eax, ecx
    cwd
    movzx edx, dx
    mov qword ptr [r8], rdx
    movzx eax, ax
    ret
cwd_test ENDP

cdq_test PROC FRAME
    .endprolog
    mov r8, rdx
    mov eax, ecx
    cdq
    mov qword ptr [r8], rdx
    ret
cdq_test ENDP

cqo_test PROC FRAME
    .endprolog
    mov r8, rdx
    mov rax, rcx
    cqo
    mov qword ptr [r8], rdx
    ret
cqo_test ENDP

END
