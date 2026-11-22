; coverage: source cpu_aot_system_atomics
; Source-built fixture for system, cache, and atomic instructions.
.code

clflush_op PROC FRAME
    .endprolog
    clflush byte ptr [rcx]
    ret
clflush_op ENDP

clflushopt_op PROC FRAME
    .endprolog
    clflushopt byte ptr [rcx]
    ret
clflushopt_op ENDP

clwb_op PROC FRAME
    .endprolog
    clwb byte ptr [rcx]
    ret
clwb_op ENDP

clzero_op PROC FRAME
    .endprolog
    mov rax, rcx
    clzero
    ret
clzero_op ENDP

sfence_op PROC FRAME
    .endprolog
    sfence
    ret
sfence_op ENDP

lfence_op PROC FRAME
    .endprolog
    lfence
    ret
lfence_op ENDP

mfence_op PROC FRAME
    .endprolog
    mfence
    ret
mfence_op ENDP

prefetchnta_op PROC FRAME
    .endprolog
    prefetchnta byte ptr [rcx]
    ret
prefetchnta_op ENDP

prefetcht0_op PROC FRAME
    .endprolog
    prefetcht0 byte ptr [rcx]
    ret
prefetcht0_op ENDP

prefetcht1_op PROC FRAME
    .endprolog
    prefetcht1 byte ptr [rcx]
    ret
prefetcht1_op ENDP

prefetcht2_op PROC FRAME
    .endprolog
    prefetcht2 byte ptr [rcx]
    ret
prefetcht2_op ENDP

prefetch_op PROC FRAME
    .endprolog
    prefetch byte ptr [rcx]
    ret
prefetch_op ENDP

prefetchw_op PROC FRAME
    .endprolog
    prefetchw byte ptr [rcx]
    ret
prefetchw_op ENDP

cpuid_op PROC FRAME
    .endprolog
    mov r10, r8
    mov r11, rbx
    mov rax, rcx
    mov rcx, rdx
    cpuid
    mov dword ptr [r10], eax
    mov dword ptr [r10+4], ebx
    mov dword ptr [r10+8], ecx
    mov dword ptr [r10+12], edx
    mov rbx, r11
    ret
cpuid_op ENDP

rdtsc_op PROC FRAME
    .endprolog
    rdtsc
    shl rdx, 32
    mov eax, eax
    or rax, rdx
    ret
rdtsc_op ENDP

rdtscp_op PROC FRAME
    .endprolog
    mov r10, rcx
    rdtscp
    mov dword ptr [r10], ecx
    shl rdx, 32
    mov eax, eax
    or rax, rdx
    ret
rdtscp_op ENDP

rdrand_op PROC FRAME
    .endprolog
    rdrand rax
    ret
rdrand_op ENDP

rdseed_op PROC FRAME
    .endprolog
    rdseed rax
    ret
rdseed_op ENDP

cmpxchg8b_op PROC FRAME
    .endprolog
    mov r10, rcx
    mov r11, rbx
    mov rax, rdx
    mov rbx, r8
    shr rdx, 32
    mov rcx, r8
    shr rcx, 32
    cmpxchg8b qword ptr [r10]
    shl rdx, 32
    mov eax, eax
    or rax, rdx
    mov rbx, r11
    ret
cmpxchg8b_op ENDP

cmpxchg16b_op PROC FRAME
    .endprolog
    mov r10, rcx
    mov r11, rbx
    mov rax, qword ptr [rdx]
    mov rdx, qword ptr [rdx+8]
    mov rbx, qword ptr [r8]
    mov rcx, qword ptr [r8+8]
    cmpxchg16b xmmword ptr [r10]
    mov rbx, r11
    ret
cmpxchg16b_op ENDP

END
