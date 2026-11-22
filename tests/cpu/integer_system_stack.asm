; coverage: source cpu_aot_integer_system_stack
.code

ifdef RECORD_ONLY
    cmovg
    cmovle
    cmovno
    cmovnp
    cmovo
    cmovp
    cmovs
    enter
    int
    int1
    int3
    iret
    iretd
    iretq
    jno
    jns
    jo
    js
    lahf
    lar
    leave
    lfs
    lgs
    lsl
    lss
    monitorx
    mwaitx
    nop
    popf
    popfq
    pushf
    pushfq
    rdfsbase
    rdgsbase
    rdpid
    rdpru
    reservednop
    retf
    setge
    setno
    setnp
    setns
    setp
    sgdt
    sidt
    sldt
    smsw
    str
    syscall
    ud0
    ud1
    ud2
    verr
    verw
    wrfsbase
    wrgsbase
endif

integer_system_stack_dummy proc frame
    .endprolog
    mov rax, rcx
    add rax, rdx
    ret
integer_system_stack_dummy endp

end
