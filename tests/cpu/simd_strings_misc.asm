; coverage: source cpu_aot_simd_strings_misc
.code

ifdef RECORD_ONLY
    pcmpestri64
    pcmpestrm64
    vpcmpestri64
    vpcmpestrm64
endif

pcmpistri_op proc frame
    .endprolog
    mov r9, rcx
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    pcmpistri xmm0, xmm1, 00h
    mov qword ptr [r9], rcx
    ret
pcmpistri_op endp

pcmpistrm_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    pcmpistrm xmm0, xmm1, 00h
    movdqu xmmword ptr [rcx], xmm0
    ret
pcmpistrm_op endp

pcmpestri_op proc frame
    .endprolog
    mov r9, rcx
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    mov eax, 4
    mov edx, 4
    pcmpestri xmm0, xmm1, 00h
    mov qword ptr [r9], rcx
    ret
pcmpestri_op endp

pcmpestrm_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    mov eax, 4
    mov edx, 4
    pcmpestrm xmm0, xmm1, 00h
    movdqu xmmword ptr [rcx], xmm0
    ret
pcmpestrm_op endp

vpcmpistri_op proc frame
    .endprolog
    mov r9, rcx
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    vpcmpistri xmm0, xmm1, 00h
    mov qword ptr [r9], rcx
    ret
vpcmpistri_op endp

vpcmpistrm_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    vpcmpistrm xmm0, xmm1, 00h
    movdqu xmmword ptr [rcx], xmm0
    ret
vpcmpistrm_op endp

vpcmpestri_op proc frame
    .endprolog
    mov r9, rcx
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    mov eax, 4
    mov edx, 4
    vpcmpestri xmm0, xmm1, 00h
    mov qword ptr [r9], rcx
    ret
vpcmpestri_op endp

vpcmpestrm_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    mov eax, 4
    mov edx, 4
    vpcmpestrm xmm0, xmm1, 00h
    movdqu xmmword ptr [rcx], xmm0
    ret
vpcmpestrm_op endp

extrq_imm_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    extrq xmm0, 8, 0
    movdqu xmmword ptr [rcx], xmm0
    ret
extrq_imm_op endp

extrq_reg_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    extrq xmm0, xmm1
    movdqu xmmword ptr [rcx], xmm0
    ret
extrq_reg_op endp

insertq_imm_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    insertq xmm0, xmm1, 8, 0
    movdqu xmmword ptr [rcx], xmm0
    ret
insertq_imm_op endp

insertq_reg_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    insertq xmm0, xmm1
    movdqu xmmword ptr [rcx], xmm0
    ret
insertq_reg_op endp

maskmovdqu_op proc frame
    .endprolog
    mov r9, rdi
    mov rdi, rcx
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    maskmovdqu xmm0, xmm1
    mov rdi, r9
    ret
maskmovdqu_op endp

vmaskmovdqu_op proc frame
    .endprolog
    mov r9, rdi
    mov rdi, rcx
    movdqu xmm0, xmmword ptr [rdx]
    movdqu xmm1, xmmword ptr [r8]
    vmaskmovdqu xmm0, xmm1
    mov rdi, r9
    ret
vmaskmovdqu_op endp

end
