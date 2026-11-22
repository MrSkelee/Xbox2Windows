; coverage: source cpu_aot_float_packed
; Source-built fixture for 56 packed and scalar SSE/SSE2/AVX float/double instructions.
.code

addps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    addps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
addps_op ENDP

subps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    subps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
subps_op ENDP

mulps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    mulps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
mulps_op ENDP

divps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    divps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
divps_op ENDP

maxps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    maxps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
maxps_op ENDP

minps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    minps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
minps_op ENDP

sqrtps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    sqrtps xmm0, xmm0
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
sqrtps_op ENDP

andps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    andps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
andps_op ENDP

andnps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    andnps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
andnps_op ENDP

orps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    orps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
orps_op ENDP

xorps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    xorps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
xorps_op ENDP

sqrtss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    sqrtss xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
sqrtss_op ENDP

maxss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    maxss xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
maxss_op ENDP

minss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    minss xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
minss_op ENDP

addpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    addpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
addpd_op ENDP

subpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    subpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
subpd_op ENDP

mulpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    mulpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
mulpd_op ENDP

divpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    divpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
divpd_op ENDP

maxpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    maxpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
maxpd_op ENDP

minpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    minpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
minpd_op ENDP

sqrtpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    sqrtpd xmm0, xmm0
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
sqrtpd_op ENDP

andpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    andpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
andpd_op ENDP

andnpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    andnpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
andnpd_op ENDP

orpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    orpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
orpd_op ENDP

xorpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    xorpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
xorpd_op ENDP

sqrtsd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    sqrtsd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
sqrtsd_op ENDP

maxsd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    maxsd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
maxsd_op ENDP

minsd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    minsd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
minsd_op ENDP

vaddps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vaddps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vaddps_op ENDP

vsubps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vsubps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vsubps_op ENDP

vmulps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vmulps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmulps_op ENDP

vdivps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vdivps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vdivps_op ENDP

vmaxps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vmaxps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmaxps_op ENDP

vminps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vminps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vminps_op ENDP

vsqrtps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    vsqrtps xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vsqrtps_op ENDP

vandps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vandps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vandps_op ENDP

vandnps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vandnps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vandnps_op ENDP

vorps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vorps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vorps_op ENDP

vxorps_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vxorps xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vxorps_op ENDP

vaddpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vaddpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vaddpd_op ENDP

vsubpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vsubpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vsubpd_op ENDP

vmulpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vmulpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmulpd_op ENDP

vdivpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vdivpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vdivpd_op ENDP

vmaxpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vmaxpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmaxpd_op ENDP

vminpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vminpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vminpd_op ENDP

vsqrtpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    vsqrtpd xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vsqrtpd_op ENDP

vandpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vandpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vandpd_op ENDP

vandnpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vandnpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vandnpd_op ENDP

vorpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vorpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vorpd_op ENDP

vxorpd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vxorpd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vxorpd_op ENDP

vsqrtss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vsqrtss xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vsqrtss_op ENDP

vmaxss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vmaxss xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmaxss_op ENDP

vminss_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vminss xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vminss_op ENDP

vsqrtsd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vsqrtsd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vsqrtsd_op ENDP

vmaxsd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vmaxsd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vmaxsd_op ENDP

vminsd_op PROC FRAME
    .endprolog
    vzeroupper
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vminsd xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    vzeroupper
    ret
vminsd_op ENDP

END
