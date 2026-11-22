; Source-owned differential fixture for BMI2 and ADX bit-manipulation instructions
; (BZHI, RORX, SARX, SHLX, SHRX, MULX, PDEP, PEXT, ADCX, ADOX) in 32-bit and 64-bit forms.
.code

bzhi32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, which BZHI clears if index < 32
    bzhi eax, ecx, edx
    mov r9d, 0
    jae short @F
    mov r9d, 2               ; CF = 1
@@:
    jne short @F
    or r9d, 1                ; ZF = 1
@@:
    mov qword ptr [r8], r9
    ret
bzhi32 ENDP

bzhi64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, which BZHI clears if index < 64
    bzhi rax, rcx, rdx
    mov r9d, 0
    jae short @F
    mov r9d, 2               ; CF = 1
@@:
    jne short @F
    or r9d, 1                ; ZF = 1
@@:
    mov qword ptr [r8], r9
    ret
bzhi64 ENDP

rorx32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, ZF = 0 (flags to preserve)
    rorx eax, ecx, 13
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [rdx], r9
    ret
rorx32 ENDP

rorx64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, ZF = 0 (flags to preserve)
    rorx rax, rcx, 27
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [rdx], r9
    ret
rorx64 ENDP

sarx32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, ZF = 0 (flags to preserve)
    sarx eax, ecx, edx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
sarx32 ENDP

sarx64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, ZF = 0 (flags to preserve)
    sarx rax, rcx, rdx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
sarx64 ENDP

shlx32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, ZF = 0 (flags to preserve)
    shlx eax, ecx, edx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
shlx32 ENDP

shlx64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, ZF = 0 (flags to preserve)
    shlx rax, rcx, rdx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
shlx64 ENDP

shrx32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, ZF = 0 (flags to preserve)
    shrx eax, ecx, edx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
shrx32 ENDP

shrx64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1, ZF = 0 (flags to preserve)
    shrx rax, rcx, rdx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
shrx64 ENDP

mulx32 PROC FRAME
    .endprolog
    mov rax, -1
    mov r9, -1
    mulx eax, r9d, ecx
    mov [r8], eax
    mov eax, r9d
    ret
mulx32 ENDP

mulx64 PROC FRAME
    .endprolog
    mulx rax, r9, rcx
    mov [r8], rax
    mov rax, r9
    ret
mulx64 ENDP

pext32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1
    pext eax, ecx, edx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
pext32 ENDP

pext64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1
    pext rax, rcx, rdx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
pext64 ENDP

pdep32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1
    pdep eax, ecx, edx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
pdep32 ENDP

pdep64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1
    pdep rax, rcx, rdx
    mov r9d, 0
    jae short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
pdep64 ENDP

adcx32 PROC FRAME
    .endprolog
    mov rax, -1
    xor r9d, r9d
    cmp r9, 1                ; CF = 1
    adcx ecx, edx
    mov eax, ecx
    mov r9d, 0
    jae short @F
    mov r9d, 2               ; CF = 1
@@:
    mov qword ptr [r8], r9
    ret
adcx32 ENDP

adcx64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1
    adcx rcx, rdx
    mov rax, rcx
    mov r9d, 0
    jae short @F
    mov r9d, 2               ; CF = 1
@@:
    mov qword ptr [r8], r9
    ret
adcx64 ENDP

adox32 PROC FRAME
    .endprolog
    mov rax, -1
    mov r9d, 7fffffffh
    add r9d, 1               ; OF = 1
    adox ecx, edx
    mov eax, ecx
    mov r9d, 0
    jno short @F
    mov r9d, 4               ; OF = 1
@@:
    mov qword ptr [r8], r9
    ret
adox32 ENDP

adox64 PROC FRAME
    .endprolog
    mov r9, 7fffffffffffffffh
    add r9, 1                ; OF = 1
    adox rcx, rdx
    mov rax, rcx
    mov r9d, 0
    jno short @F
    mov r9d, 4               ; OF = 1
@@:
    mov qword ptr [r8], r9
    ret
adox64 ENDP

END
