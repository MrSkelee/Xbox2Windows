; One-operand MUL, IMUL, DIV and IDIV and the sign extensions CBW, CWDE, CDQE, CDQ and CQO, which
; use RAX and RDX implicitly, for the jump-table translator.
; Every export takes RCX = x, RDX = y and R8 = address of three writable QWORDs. The divides and
; multiplies store the remainder or the high half to [R8] and return the quotient or the low half.
.code
; Unsigned divide of EDX:EAX = x by the low 32 bits of y. It faults when the divisor is 0 or the
; quotient needs more than 32 bits (x >> 32 >= divisor).
div32 PROC FRAME
    .endprolog
    mov r9d, edx
    mov rax, rcx
    shr rcx, 32
    mov edx, ecx
    div r9d
    mov QWORD PTR [r8], rdx
    ret
div32 ENDP

; Signed divide of ECX by EDX after CDQ. It faults when the divisor is 0 and for -2^31 / -1.
idiv32 PROC FRAME
    .endprolog
    mov r9d, edx
    mov eax, ecx
    cdq
    idiv r9d
    mov QWORD PTR [r8], rdx
    ret
idiv32 ENDP

; Unsigned divide of RCX by RDX, with RDX cleared first. It faults when the divisor is 0.
div64 PROC FRAME
    .endprolog
    mov r9, rdx
    mov rax, rcx
    xor edx, edx
    div r9
    mov QWORD PTR [r8], rdx
    ret
div64 ENDP

; Unsigned divide of RDX:RAX = x:y by a fixed divisor. It faults when x >= the divisor.
udiv128 PROC FRAME
    .endprolog
    mov rax, rdx
    mov rdx, rcx
    mov r9, 123456789ABCDEF1h
    div r9
    mov QWORD PTR [r8], rdx
    ret
udiv128 ENDP

; Signed divide of RCX by y after CQO, with y read from [R8+8]. It faults when y is 0 and for
; -2^63 / -1.
idiv64 PROC FRAME
    .endprolog
    mov QWORD PTR [r8+8], rdx
    mov rax, rcx
    cqo
    idiv QWORD PTR [r8+8]
    mov QWORD PTR [r8], rdx
    ret
idiv64 ENDP

; RDX:RAX = RCX * RDX: the source RDX is also an output.
mul64 PROC FRAME
    .endprolog
    mov rax, rcx
    mul rdx
    mov QWORD PTR [r8], rdx
    ret
mul64 ENDP

; Signed RDX:RAX = RCX * y, with y read from [R8+8] through RDX, which the multiply overwrites.
imul64_1 PROC FRAME
    .endprolog
    mov QWORD PTR [r8+8], rdx
    lea rdx, [r8+8]
    mov rax, rcx
    imul QWORD PTR [rdx]
    mov QWORD PTR [r8], rdx
    ret
imul64_1 ENDP

; EDX:EAX = ECX * EDX. Both results are zero-extended over the upper halves of RCX and RDX.
mul32 PROC FRAME
    .endprolog
    mov rax, rcx
    mul edx
    mov QWORD PTR [r8], rdx
    ret
mul32 ENDP

; Signed EDX:EAX = ECX * EDX.
imul32 PROC FRAME
    .endprolog
    mov rax, rcx
    imul edx
    mov QWORD PTR [r8], rdx
    ret
imul32 ENDP

; The 8-bit forms write AX only: bits 16-63 of RAX keep RCX, and RDX is not written.
mul8 PROC FRAME
    .endprolog
    mov rax, rcx
    mul dl
    mov QWORD PTR [r8], rax
    mov QWORD PTR [r8+8], rdx
    mov rax, rcx
    imul dl
    ret
mul8 ENDP

; The 16-bit forms write DX:AX: bits 16-63 of RAX and RDX keep their values.
mul16 PROC FRAME
    .endprolog
    mov r9, rdx
    mov rax, rcx
    mul dx
    mov QWORD PTR [r8], rax
    mov QWORD PTR [r8+8], rdx
    mov rax, rcx
    mov rdx, r9
    imul r9w
    mov QWORD PTR [r8+16], rdx
    ret
mul16 ENDP

; CBW merges AX into RAX, CWDE writes EAX and clears bits 32-63, CDQE writes RAX. The return
; value chains all three on DL.
widen PROC FRAME
    .endprolog
    mov rax, rcx
    cbw
    mov QWORD PTR [r8], rax
    mov rax, rcx
    cwde
    mov QWORD PTR [r8+8], rax
    mov rax, rcx
    cdqe
    mov QWORD PTR [r8+16], rax
    mov rax, rdx
    cbw
    cwde
    cdqe
    ret
widen ENDP

; CDQ (EDX = sign of ECX, bits 32-63 of RDX cleared), CQO (RDX = sign of y) and CWD (DX = sign of AX)
; sit between CMP and SETL, which still reads the comparison of RCX with RDX. Bits 8-63 of RAX hold y.
sign_dx PROC FRAME
    .endprolog
    mov r9, rdx
    mov rax, rcx
    cmp rcx, rdx
    cdq
    mov QWORD PTR [r8], rdx
    mov rax, r9
    cqo
    mov QWORD PTR [r8+8], rdx
    mov rax, rcx
    cwd
    mov QWORD PTR [r8+16], rdx
    mov rax, r9
    setl al
    ret
sign_dx ENDP

; Rejected: JC reads the carry flag of MUL, which the flag model does not cover.
mul_carry PROC FRAME
    .endprolog
    mov rax, rcx
    mul rdx
    jc carry_set
    ret
carry_set:
    mov rax, -1
    ret
mul_carry ENDP

; Rejected, never called: MUL overwrites RDX, the table base, before the dispatch.
base_clobber PROC FRAME
    .endprolog
    mov eax, ecx
    cmp ecx, 1
    ja base_default
    mov ecx, eax
    lea rdx, base_table
    mul r8
    movsxd rax, DWORD PTR [rdx+rcx*4]
    add rax, rdx
    jmp rax
base_case:
    mov eax, 1
    ret
base_default:
    xor eax, eax
    ret
    ALIGN 4
base_table:
    DD base_case - base_table, base_default - base_table
base_clobber ENDP

; Rejected, never called: CQO overwrites RDX, the table index, after the bound check.
index_clobber PROC FRAME
    .endprolog
    mov eax, ecx
    cmp ecx, 1
    ja index_default
    mov edx, ecx
    cqo
    lea r9, index_table
    movsxd rax, DWORD PTR [r9+rdx*4]
    add rax, r9
    jmp rax
index_case:
    mov eax, 1
    ret
index_default:
    xor eax, eax
    ret
    ALIGN 4
index_table:
    DD index_case - index_table, index_default - index_table
index_clobber ENDP

; Rejected, never called: after LEA, RDX holds a guest address and counts as undefined. The 8-bit
; MUL does not write RDX, so the store reads it.
guest_rdx PROC FRAME
    .endprolog
    lea rdx, guest_rdx
    mov rax, rcx
    mul cl
    mov QWORD PTR [r8], rdx
    ret
guest_rdx ENDP
END
