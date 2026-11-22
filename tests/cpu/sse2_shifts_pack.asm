; coverage: source cpu_aot_sse2_shifts_pack
; Source-owned differential fixture for 25 baseline 128-bit SSE2 packed shifts, packs, unpacks, shuffles, and movemask instructions.
.code

psllw_imm_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psllw xmm0, 5
    movdqu xmmword ptr [r8], xmm0
    ret
psllw_imm_op ENDP

psllw_reg_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    psllw xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
psllw_reg_op ENDP

pslld_imm_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    pslld xmm0, 11
    movdqu xmmword ptr [r8], xmm0
    ret
pslld_imm_op ENDP

pslld_reg_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    pslld xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
pslld_reg_op ENDP

psllq_imm_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psllq xmm0, 19
    movdqu xmmword ptr [r8], xmm0
    ret
psllq_imm_op ENDP

psllq_reg_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    psllq xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
psllq_reg_op ENDP

psrlw_imm_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psrlw xmm0, 5
    movdqu xmmword ptr [r8], xmm0
    ret
psrlw_imm_op ENDP

psrlw_reg_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    psrlw xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
psrlw_reg_op ENDP

psrld_imm_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psrld xmm0, 11
    movdqu xmmword ptr [r8], xmm0
    ret
psrld_imm_op ENDP

psrld_reg_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    psrld xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
psrld_reg_op ENDP

psrlq_imm_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psrlq xmm0, 19
    movdqu xmmword ptr [r8], xmm0
    ret
psrlq_imm_op ENDP

psrlq_reg_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    psrlq xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
psrlq_reg_op ENDP

psraw_imm_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psraw xmm0, 5
    movdqu xmmword ptr [r8], xmm0
    ret
psraw_imm_op ENDP

psraw_reg_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    psraw xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
psraw_reg_op ENDP

psrad_imm_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psrad xmm0, 11
    movdqu xmmword ptr [r8], xmm0
    ret
psrad_imm_op ENDP

psrad_reg_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    psrad xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
psrad_reg_op ENDP

pslldq_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    pslldq xmm0, 3
    movdqu xmmword ptr [r8], xmm0
    ret
pslldq_op ENDP

psrldq_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psrldq xmm0, 5
    movdqu xmmword ptr [r8], xmm0
    ret
psrldq_op ENDP

packsswb_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    packsswb xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
packsswb_op ENDP

packssdw_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    packssdw xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
packssdw_op ENDP

packuswb_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    packuswb xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
packuswb_op ENDP

punpcklbw_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    punpcklbw xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
punpcklbw_op ENDP

punpcklwd_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    punpcklwd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
punpcklwd_op ENDP

punpckldq_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    punpckldq xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
punpckldq_op ENDP

punpcklqdq_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    punpcklqdq xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
punpcklqdq_op ENDP

punpckhbw_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    punpckhbw xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
punpckhbw_op ENDP

punpckhwd_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    punpckhwd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
punpckhwd_op ENDP

punpckhdq_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    punpckhdq xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
punpckhdq_op ENDP

punpckhqdq_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    punpckhqdq xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
punpckhqdq_op ENDP

pshufd_op PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    pshufd xmm0, xmm1, 0B1h
    movdqu xmmword ptr [r8], xmm0
    ret
pshufd_op ENDP

pshuflw_op PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    pshuflw xmm0, xmm1, 01Bh
    movdqu xmmword ptr [r8], xmm0
    ret
pshuflw_op ENDP

pshufhw_op PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    pshufhw xmm0, xmm1, 04Eh
    movdqu xmmword ptr [r8], xmm0
    ret
pshufhw_op ENDP

pmovmskb_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    pmovmskb eax, xmm0
    ret
pmovmskb_op ENDP

psrld_imm_32_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    psrld xmm0, 32
    movdqu xmmword ptr [r8], xmm0
    ret
psrld_imm_32_op ENDP

punpckhqdq_self_op PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    punpckhqdq xmm0, xmm0
    movdqu xmmword ptr [r8], xmm0
    ret
punpckhqdq_self_op ENDP

pshufd_b3_op PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    pshufd xmm0, xmm1, 0B3h
    movdqu xmmword ptr [r8], xmm0
    ret
pshufd_b3_op ENDP

packssdw_reverse_regs_op PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm0, xmmword ptr [rdx]
    packssdw xmm1, xmm0
    movdqu xmmword ptr [r8], xmm1
    ret
packssdw_reverse_regs_op ENDP

END
