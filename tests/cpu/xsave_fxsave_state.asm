; coverage: source cpu_aot_xsave_fxsave_state
.code

ifdef RECORD_ONLY
    fxsave64
    fxrstor64
    xsave64
    xrstor64
    xsaveopt64
    xsavec64
endif

xgetbv_op proc frame
    .endprolog
    xor ecx, ecx
    xgetbv
    mov qword ptr [r8], rax
    mov qword ptr [r8+8], rdx
    ret
xgetbv_op endp

fxsave_op proc frame
    .endprolog
    fxsave [rcx]
    ret
fxsave_op endp

fxrstor_op proc frame
    .endprolog
    fxrstor [rcx]
    ret
fxrstor_op endp

xsave_op proc frame
    .endprolog
    mov eax, 7
    xor edx, edx
    xsave [rcx]
    ret
xsave_op endp

xrstor_op proc frame
    .endprolog
    mov eax, 7
    xor edx, edx
    xrstor [rcx]
    ret
xrstor_op endp

xsaveopt_op proc frame
    .endprolog
    mov eax, 7
    xor edx, edx
    xsaveopt [rcx]
    ret
xsaveopt_op endp

xsavec_op proc frame
    .endprolog
    mov eax, 7
    xor edx, edx
    xsavec [rcx]
    ret
xsavec_op endp

end
