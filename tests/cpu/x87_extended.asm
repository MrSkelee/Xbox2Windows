; coverage: source cpu_aot_x87_extended
.code

ifdef RECORD_ONLY
    f2xm1
    fbld
    fbstp
    fclex
    fcos
    fdecstp
    fdisi
    feni
    ffree
    ffreep
    ficom
    ficomp
    fincstp
    finit
    fldenv
    fnclex
    fndisi
    fneni
    fninit
    fnop
    fnsave
    fnsetpm
    fnstenv
    fpatan
    fprem
    fprem1
    fptan
    frstor
    fsave
    fsetpm
    fsin
    fsincos
    fstenv
    fstpnce
    fstsw
    ftst
    fxam
    fyl2x
    fyl2xp1
endif

x87_extended_dummy proc frame
    .endprolog
    mov rax, rcx
    add rax, rdx
    ret
x87_extended_dummy endp

end
