; coverage: source cpu_aot_simd_mmx_conversions
.code

packssdw_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    packssdw mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
packssdw_op endp

packsswb_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    packsswb mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
packsswb_op endp

packuswb_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    packuswb mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
packuswb_op endp

pslld_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    pslld mm0, 2
    movq qword ptr [rcx], mm0
    emms
    ret
pslld_op endp

psllq_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    psllq mm0, 2
    movq qword ptr [rcx], mm0
    emms
    ret
psllq_op endp

psllw_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    psllw mm0, 2
    movq qword ptr [rcx], mm0
    emms
    ret
psllw_op endp

psrad_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    psrad mm0, 2
    movq qword ptr [rcx], mm0
    emms
    ret
psrad_op endp

psraw_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    psraw mm0, 2
    movq qword ptr [rcx], mm0
    emms
    ret
psraw_op endp

psrld_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    psrld mm0, 2
    movq qword ptr [rcx], mm0
    emms
    ret
psrld_op endp

psrlq_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    psrlq mm0, 2
    movq qword ptr [rcx], mm0
    emms
    ret
psrlq_op endp

psrlw_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    psrlw mm0, 2
    movq qword ptr [rcx], mm0
    emms
    ret
psrlw_op endp

punpckhbw_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    punpckhbw mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
punpckhbw_op endp

punpckhdq_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    punpckhdq mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
punpckhdq_op endp

punpckhwd_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    punpckhwd mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
punpckhwd_op endp

punpcklbw_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    punpcklbw mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
punpcklbw_op endp

punpckldq_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    punpckldq mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
punpckldq_op endp

punpcklwd_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    punpcklwd mm0, mm1
    movq qword ptr [rcx], mm0
    emms
    ret
punpcklwd_op endp

pshufw_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    pshufw mm0, mm0, 1bh
    movq qword ptr [rcx], mm0
    emms
    ret
pshufw_op endp

cvtpi2ps_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movq mm0, qword ptr [rdx]
    cvtpi2ps xmm0, mm0
    movdqu xmmword ptr [rcx], xmm0
    emms
    ret
cvtpi2ps_op endp

cvtps2pi_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    cvtps2pi mm0, xmm0
    movq qword ptr [rcx], mm0
    emms
    ret
cvtps2pi_op endp

cvttps2pi_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    cvttps2pi mm0, xmm0
    movq qword ptr [rcx], mm0
    emms
    ret
cvttps2pi_op endp

cvtpd2pi_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    cvtpd2pi mm0, xmm0
    movq qword ptr [rcx], mm0
    emms
    ret
cvtpd2pi_op endp

cvtpi2pd_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    cvtpi2pd xmm0, mm0
    movdqu xmmword ptr [rcx], xmm0
    emms
    ret
cvtpi2pd_op endp

cvttpd2pi_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    cvttpd2pi mm0, xmm0
    movq qword ptr [rcx], mm0
    emms
    ret
cvttpd2pi_op endp

movdq2q_op proc frame
    .endprolog
    movdqu xmm0, xmmword ptr [rdx]
    movdq2q mm0, xmm0
    movq qword ptr [rcx], mm0
    emms
    ret
movdq2q_op endp

movq2dq_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movq2dq xmm0, mm0
    movdqu xmmword ptr [rcx], xmm0
    emms
    ret
movq2dq_op endp

maskmovq_op proc frame
    .endprolog
    mov r9, rdi
    mov rdi, rcx
    movq mm0, qword ptr [rdx]
    movq mm1, qword ptr [r8]
    maskmovq mm0, mm1
    mov rdi, r9
    emms
    ret
maskmovq_op endp

movntq_op proc frame
    .endprolog
    movq mm0, qword ptr [rdx]
    movntq qword ptr [rcx], mm0
    emms
    ret
movntq_op endp

emms_op proc frame
    .endprolog
    emms
    ret
emms_op endp

end
