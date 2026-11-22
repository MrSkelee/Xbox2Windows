; coverage: source cpu_aot_simd_ssse3_sse4
.code

pabsb_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    pabsb xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
pabsb_op ENDP

pabsw_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    pabsw xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
pabsw_op ENDP

pabsd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    pabsd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
pabsd_op ENDP

psignb_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    psignb xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
psignb_op ENDP

psignw_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    psignw xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
psignw_op ENDP

psignd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    psignd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
psignd_op ENDP

palignr_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    palignr xmm0, xmm1, 4
    movdqu XMMWORD PTR [r8], xmm0
    ret
palignr_op ENDP

pshufb_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    pshufb xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
pshufb_op ENDP

vpshufb_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vpshufb xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vpshufb_op ENDP

phaddw_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    phaddw xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
phaddw_op ENDP

phaddd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    phaddd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
phaddd_op ENDP

phaddsw_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    phaddsw xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
phaddsw_op ENDP

phsubw_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    phsubw xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
phsubw_op ENDP

phsubd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    phsubd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
phsubd_op ENDP

phsubsw_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    phsubsw xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
phsubsw_op ENDP

haddps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    haddps xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
haddps_op ENDP

vhaddps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vhaddps xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vhaddps_op ENDP

haddpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    haddpd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
haddpd_op ENDP

vhaddpd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vhaddpd xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vhaddpd_op ENDP

hsubps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    hsubps xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
hsubps_op ENDP

vhsubps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vhsubps xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vhsubps_op ENDP

hsubpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    hsubpd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
hsubpd_op ENDP

vhsubpd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vhsubpd xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vhsubpd_op ENDP

addsubps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    addsubps xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
addsubps_op ENDP

vaddsubps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vaddsubps xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vaddsubps_op ENDP

addsubpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    addsubpd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
addsubpd_op ENDP

vaddsubpd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vaddsubpd xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vaddsubpd_op ENDP

roundps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    roundps xmm0, xmm1, 1
    movdqu XMMWORD PTR [r8], xmm0
    ret
roundps_op ENDP

vroundps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rdx]
    vroundps xmm0, xmm1, 1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vroundps_op ENDP

roundpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    roundpd xmm0, xmm1, 2
    movdqu XMMWORD PTR [r8], xmm0
    ret
roundpd_op ENDP

vroundpd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rdx]
    vroundpd xmm0, xmm1, 2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vroundpd_op ENDP

roundss_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    roundss xmm0, xmm1, 3
    movdqu XMMWORD PTR [r8], xmm0
    ret
roundss_op ENDP

vroundss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vroundss xmm0, xmm1, xmm2, 3
    movdqu XMMWORD PTR [r8], xmm0
    ret
vroundss_op ENDP

roundsd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    roundsd xmm0, xmm1, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
roundsd_op ENDP

vroundsd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vroundsd xmm0, xmm1, xmm2, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
vroundsd_op ENDP

movshdup_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rdx]
    movshdup xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
movshdup_op ENDP

movsldup_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rdx]
    movsldup xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
movsldup_op ENDP

movddup_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rdx]
    movddup xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
movddup_op ENDP

blendps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    blendps xmm0, xmm1, 5
    movdqu XMMWORD PTR [r8], xmm0
    ret
blendps_op ENDP

blendpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    blendpd xmm0, xmm1, 2
    movdqu XMMWORD PTR [r8], xmm0
    ret
blendpd_op ENDP

dpps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    dpps xmm0, xmm1, 0f1h
    movdqu XMMWORD PTR [r8], xmm0
    ret
dpps_op ENDP

vdpps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vdpps xmm0, xmm1, xmm2, 0f1h
    movdqu XMMWORD PTR [r8], xmm0
    ret
vdpps_op ENDP

dppd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    dppd xmm0, xmm1, 31h
    movdqu XMMWORD PTR [r8], xmm0
    ret
dppd_op ENDP

vdppd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vdppd xmm0, xmm1, xmm2, 31h
    movdqu XMMWORD PTR [r8], xmm0
    ret
vdppd_op ENDP

vaddss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vaddss xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vaddss_op ENDP

vsubss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vsubss xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vsubss_op ENDP

vmulss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vmulss xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vmulss_op ENDP

vdivss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vdivss xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vdivss_op ENDP

vaddsd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vaddsd xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vaddsd_op ENDP

vsubsd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vsubsd xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vsubsd_op ENDP

vmulsd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vmulsd xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vmulsd_op ENDP

vdivsd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vdivsd xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vdivsd_op ENDP

END
