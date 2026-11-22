; Source-owned control for immediate shifts whose masked count is zero.
; A 32-bit destination is still written, so the upper half of the register clears;
; the flags keep the values from the preceding compare.
.code
shl_zero PROC FRAME
    .endprolog
    mov rax, rcx
    shl eax, 0
    ret
shl_zero ENDP

shr_zero PROC FRAME
    .endprolog
    mov rax, rcx
    shr eax, 0
    ret
shr_zero ENDP

sar_zero PROC FRAME
    .endprolog
    mov rax, rcx
    sar eax, 0
    ret
sar_zero ENDP

; The count is masked to five bits for a 32-bit destination.
shl_masked32 PROC FRAME
    .endprolog
    mov rax, rcx
    shl eax, 32
    ret
shl_masked32 ENDP

; A 64-bit destination keeps every bit when the masked count is zero.
shl_masked64 PROC FRAME
    .endprolog
    mov rax, rcx
    shl rax, 64
    ret
shl_masked64 ENDP

; Nonzero control through the existing shift path.
shl_three PROC FRAME
    .endprolog
    mov rax, rcx
    shl eax, 3
    ret
shl_three ENDP

; Nonzero arithmetic shift left (synonym for SHL).
sal_three PROC FRAME
    .endprolog
    mov rax, rcx
    sal eax, 3
    ret
sal_three ENDP

; Nonzero arithmetic shift: the vacated bits take the sign of the 32-bit source.
sar_three PROC FRAME
    .endprolog
    mov rax, rcx
    sar eax, 3
    ret
sar_three ENDP

; RCX, RDX = compared values. Returns the CF that the zero-count shift must keep from the compare.
carry_zero PROC FRAME
    .endprolog
    mov rax, r8
    cmp ecx, edx
    shl eax, 0
    mov r9d, 0
    jae short @F
    mov r9d, 1
@@:
    mov rax, r9
    ret
carry_zero ENDP

; RCX, RDX = compared values, R8 = initial RAX. SETE observes ZF after the zero-count shift.
flags_zero PROC FRAME
    .endprolog
    mov rax, r8
    cmp ecx, edx
    shl eax, 0
    sete al
    ret
flags_zero ENDP
END
