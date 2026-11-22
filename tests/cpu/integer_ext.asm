; Source-owned differential fixture for extended integer instructions:
; ADC, SBB, CLC, STC, CMC, ROL, ROR, SHLD, SHRD, XCHG, XADD,
; SETcc (SETA, SETAE, SETGE, SETNO, SETNP, SETNS, SETO, SETP),
; CMOVcc (CMOVAE, CMOVBE, CMOVG, CMOVGE, CMOVL, CMOVLE, CMOVNO, CMOVNP, CMOVO, CMOVP, CMOVS, CMOVNS)
.code

adc32 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1
    adc ecx, edx
    mov eax, ecx
    mov r9d, 0
    jnc short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
adc32 ENDP

adc64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1
    adc rcx, rdx
    mov rax, rcx
    mov r9d, 0
    jnc short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
adc64 ENDP

sbb32 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1
    sbb ecx, edx
    mov eax, ecx
    mov r9d, 0
    jnc short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
sbb32 ENDP

sbb64 PROC FRAME
    .endprolog
    xor r9d, r9d
    cmp r9, 1                ; CF = 1
    sbb rcx, rdx
    mov rax, rcx
    mov r9d, 0
    jnc short @F
    mov r9d, 2
@@:
    jne short @F
    or r9d, 1
@@:
    mov qword ptr [r8], r9
    ret
sbb64 ENDP

rol32 PROC FRAME
    .endprolog
    mov eax, ecx
    rol eax, 5
    ret
rol32 ENDP

rol64 PROC FRAME
    .endprolog
    mov rax, rcx
    rol rax, 11
    ret
rol64 ENDP

ror32 PROC FRAME
    .endprolog
    mov eax, ecx
    ror eax, 5
    ret
ror32 ENDP

ror64 PROC FRAME
    .endprolog
    mov rax, rcx
    ror rax, 11
    ret
ror64 ENDP

shld32 PROC FRAME
    .endprolog
    mov eax, ecx
    shld eax, edx, 7
    ret
shld32 ENDP

shld64 PROC FRAME
    .endprolog
    mov rax, rcx
    shld rax, rdx, 15
    ret
shld64 ENDP

shrd32 PROC FRAME
    .endprolog
    mov eax, ecx
    shrd eax, edx, 7
    ret
shrd32 ENDP

shrd64 PROC FRAME
    .endprolog
    mov rax, rcx
    shrd rax, rdx, 15
    ret
shrd64 ENDP

xchg32 PROC FRAME
    .endprolog
    mov eax, ecx
    mov edx, edx
    xchg eax, edx
    mov [r8], edx
    ret
xchg32 ENDP

xchg64 PROC FRAME
    .endprolog
    mov rax, rcx
    xchg rax, rdx
    mov [r8], rdx
    ret
xchg64 ENDP

xadd32 PROC FRAME
    .endprolog
    mov eax, ecx
    xadd eax, edx
    mov [r8], edx
    ret
xadd32 ENDP

xadd64 PROC FRAME
    .endprolog
    mov rax, rcx
    xadd rax, rdx
    mov [r8], rdx
    ret
xadd64 ENDP

set_conds PROC FRAME
    .endprolog
    ; rcx = a, rdx = b, r8 = out_buf (8 bytes)
    cmp rcx, rdx
    seta byte ptr [r8]
    setae byte ptr [r8+1]
    setge byte ptr [r8+2]
    setno byte ptr [r8+3]
    setnp byte ptr [r8+4]
    setns byte ptr [r8+5]
    seto byte ptr [r8+6]
    setp byte ptr [r8+7]
    ret
set_conds ENDP

cmov_conds PROC FRAME
    .endprolog
    ; rcx = a, rdx = b, r8 = default_val, r9 = target_val
    cmp rcx, rdx
    mov rax, r8
    cmovae rax, r9
    cmovg rax, r9
    cmovl rax, r9
    cmovle rax, r9
    cmovno rax, r9
    cmovnp rax, r9
    cmovo rax, r9
    cmovp rax, r9
    cmovs rax, r9
    ret
cmov_conds ENDP

flags_ctrl PROC FRAME
    .endprolog
    clc
    stc
    cmc
    std
    cld
    mov rax, 42
    ret
flags_ctrl ENDP

jcc_walk PROC FRAME
    .endprolog
    cmp ecx, edx
    jg short @F
    jge short @F
    jl short @F
    jle short @F
    jnp short @F
    jns short @F
    jo short @F
    jp short @F
    js short @F
@@:
    mov eax, 100
    ret
jcc_walk ENDP

END
