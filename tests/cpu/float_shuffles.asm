; coverage: source cpu_aot_float_shuffles
; Source-built fixture for 51 shuffle, unpacking, and vector move instructions.
.code

shufps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        shufps xmm0, xmm1, 044h
        movdqu [r8], xmm0
    vzeroupper
    ret
shufps_op ENDP

unpckhps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        unpckhps xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
unpckhps_op ENDP

unpcklps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        unpcklps xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
unpcklps_op ENDP

movhlps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        movhlps xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
movhlps_op ENDP

movlhps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        movlhps xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
movlhps_op ENDP

movmskps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movmskps eax, xmm0
        mov [r8], eax
    vzeroupper
    ret
movmskps_op ENDP

movups_op PROC FRAME
    .endprolog
    vzeroupper
    movups xmm0, xmmword ptr [rcx]
        movups xmmword ptr [r8], xmm0
    vzeroupper
    ret
movups_op ENDP

pmovmskb_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        pmovmskb eax, xmm0
        mov [r8], eax
    vzeroupper
    ret
pmovmskb_op ENDP

rcpps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        rcpps xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
rcpps_op ENDP

rcpss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        rcpss xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
rcpss_op ENDP

rsqrtps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        rsqrtps xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
rsqrtps_op ENDP

rsqrtss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        rsqrtss xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
rsqrtss_op ENDP

shufpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        shufpd xmm0, xmm1, 1
        movdqu [r8], xmm0
    vzeroupper
    ret
shufpd_op ENDP

unpckhpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        unpckhpd xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
unpckhpd_op ENDP

unpcklpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        unpcklpd xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
unpcklpd_op ENDP

movmskpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movmskpd eax, xmm0
        mov [r8], eax
    vzeroupper
    ret
movmskpd_op ENDP

movupd_op PROC FRAME
    .endprolog
    vzeroupper
    movupd xmm0, xmmword ptr [rcx]
        movupd xmmword ptr [r8], xmm0
    vzeroupper
    ret
movupd_op ENDP

movapd_op PROC FRAME
    .endprolog
    vzeroupper
    movapd xmm0, xmmword ptr [rcx]
        movapd xmmword ptr [r8], xmm0
    vzeroupper
    ret
movapd_op ENDP

movdqa_op PROC FRAME
    .endprolog
    vzeroupper
    movdqa xmm0, xmmword ptr [rcx]
        movdqa xmmword ptr [r8], xmm0
    vzeroupper
    ret
movdqa_op ENDP

pshufd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        pshufd xmm0, xmm1, 044h
        movdqu [r8], xmm0
    vzeroupper
    ret
pshufd_op ENDP

pshufhw_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        pshufhw xmm0, xmm1, 044h
        movdqu [r8], xmm0
    vzeroupper
    ret
pshufhw_op ENDP

pshuflw_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        pshuflw xmm0, xmm1, 044h
        movdqu [r8], xmm0
    vzeroupper
    ret
pshuflw_op ENDP

pslldq_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        pslldq xmm0, 2
        movdqu [r8], xmm0
    vzeroupper
    ret
pslldq_op ENDP

psrldq_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        psrldq xmm0, 2
        movdqu [r8], xmm0
    vzeroupper
    ret
psrldq_op ENDP

punpckhqdq_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        punpckhqdq xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
punpckhqdq_op ENDP

punpcklqdq_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        movdqu xmm1, [rdx]
        punpcklqdq xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
punpcklqdq_op ENDP

vshufps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vshufps xmm0, xmm1, xmm2, 044h
        movdqu [r8], xmm0
    vzeroupper
    ret
vshufps_op ENDP

vunpckhps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vunpckhps xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vunpckhps_op ENDP

vunpcklps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vunpcklps xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vunpcklps_op ENDP

vshufpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vshufpd xmm0, xmm1, xmm2, 1
        movdqu [r8], xmm0
    vzeroupper
    ret
vshufpd_op ENDP

vunpckhpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vunpckhpd xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vunpckhpd_op ENDP

vunpcklpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vunpcklpd xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vunpcklpd_op ENDP

vpshufd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        vpshufd xmm0, xmm1, 044h
        movdqu [r8], xmm0
    vzeroupper
    ret
vpshufd_op ENDP

vpshufhw_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        vpshufhw xmm0, xmm1, 044h
        movdqu [r8], xmm0
    vzeroupper
    ret
vpshufhw_op ENDP

vpshuflw_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        vpshuflw xmm0, xmm1, 044h
        movdqu [r8], xmm0
    vzeroupper
    ret
vpshuflw_op ENDP

vmovhlps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vmovhlps xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vmovhlps_op ENDP

vmovlhps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vmovlhps xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vmovlhps_op ENDP

vmovmskps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        vmovmskps eax, xmm0
        mov [r8], eax
    vzeroupper
    ret
vmovmskps_op ENDP

vmovmskpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        vmovmskpd eax, xmm0
        mov [r8], eax
    vzeroupper
    ret
vmovmskpd_op ENDP

vmovaps_op PROC FRAME
    .endprolog
    vzeroupper
    vmovaps xmm0, xmmword ptr [rcx]
        vmovaps xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmovaps_op ENDP

vmovapd_op PROC FRAME
    .endprolog
    vzeroupper
    vmovapd xmm0, xmmword ptr [rcx]
        vmovapd xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmovapd_op ENDP

vmovdqa_op PROC FRAME
    .endprolog
    vzeroupper
    vmovdqa xmm0, xmmword ptr [rcx]
        vmovdqa xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmovdqa_op ENDP

vpmovmskb_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, [rcx]
        vpmovmskb eax, xmm0
        mov [r8], eax
    vzeroupper
    ret
vpmovmskb_op ENDP

vrcpps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        vrcpps xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
vrcpps_op ENDP

vrcpss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vrcpss xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vrcpss_op ENDP

vrsqrtps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        vrsqrtps xmm0, xmm1
        movdqu [r8], xmm0
    vzeroupper
    ret
vrsqrtps_op ENDP

vrsqrtss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vrsqrtss xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vrsqrtss_op ENDP

vpslldq_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        vpslldq xmm0, xmm1, 2
        movdqu [r8], xmm0
    vzeroupper
    ret
vpslldq_op ENDP

vpsrldq_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        vpsrldq xmm0, xmm1, 2
        movdqu [r8], xmm0
    vzeroupper
    ret
vpsrldq_op ENDP

vpunpckhqdq_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vpunpckhqdq xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vpunpckhqdq_op ENDP

vpunpcklqdq_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, [rcx]
        movdqu xmm2, [rdx]
        vpunpcklqdq xmm0, xmm1, xmm2
        movdqu [r8], xmm0
    vzeroupper
    ret
vpunpcklqdq_op ENDP

END
