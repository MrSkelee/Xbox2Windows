; coverage: source cpu_aot_simd_conversions
.code

cvtdq2pd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvtdq2pd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
cvtdq2pd_op ENDP

vcvtdq2pd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtdq2pd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtdq2pd_op ENDP

cvtdq2ps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvtdq2ps xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
cvtdq2ps_op ENDP

vcvtdq2ps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtdq2ps xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtdq2ps_op ENDP

cvtpd2dq_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvtpd2dq xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
cvtpd2dq_op ENDP

vcvtpd2dq_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtpd2dq xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtpd2dq_op ENDP

cvtpd2ps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvtpd2ps xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
cvtpd2ps_op ENDP

vcvtpd2ps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtpd2ps xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtpd2ps_op ENDP

cvtps2dq_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvtps2dq xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
cvtps2dq_op ENDP

vcvtps2dq_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtps2dq xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtps2dq_op ENDP

cvtps2pd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvtps2pd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
cvtps2pd_op ENDP

vcvtps2pd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtps2pd xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtps2pd_op ENDP

cvtsd2si_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvtsd2si rax, xmm1
    mov QWORD PTR [r8], rax
    ret
cvtsd2si_op ENDP

vcvtsd2si_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtsd2si rax, xmm1
    mov QWORD PTR [r8], rax
    ret
vcvtsd2si_op ENDP

cvtss2si_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvtss2si rax, xmm1
    mov QWORD PTR [r8], rax
    ret
cvtss2si_op ENDP

vcvtss2si_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtss2si rax, xmm1
    mov QWORD PTR [r8], rax
    ret
vcvtss2si_op ENDP

cvttpd2dq_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvttpd2dq xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
cvttpd2dq_op ENDP

vcvttpd2dq_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvttpd2dq xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvttpd2dq_op ENDP

cvttps2dq_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    cvttps2dq xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
cvttps2dq_op ENDP

vcvttps2dq_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvttps2dq xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvttps2dq_op ENDP

vcvttsd2si_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvttsd2si rax, xmm1
    mov QWORD PTR [r8], rax
    ret
vcvttsd2si_op ENDP

vcvttss2si_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvttss2si rax, xmm1
    mov QWORD PTR [r8], rax
    ret
vcvttss2si_op ENDP

vcvtsd2ss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vcvtsd2ss xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtsd2ss_op ENDP

vcvtss2sd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vcvtss2sd xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtss2sd_op ENDP

vcvtsi2sd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    mov rax, QWORD PTR [rdx]
    vcvtsi2sd xmm0, xmm1, rax
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtsi2sd_op ENDP

vcvtsi2ss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    mov rax, QWORD PTR [rdx]
    vcvtsi2ss xmm0, xmm1, rax
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtsi2ss_op ENDP

vcvtph2ps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtph2ps xmm0, xmm1
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtph2ps_op ENDP

vcvtps2ph_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vcvtps2ph xmm0, xmm1, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcvtps2ph_op ENDP

cmpps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    cmpps xmm0, xmm1, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
cmpps_op ENDP

vcmpps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vcmpps xmm0, xmm1, xmm2, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcmpps_op ENDP

cmppd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    cmppd xmm0, xmm1, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
cmppd_op ENDP

vcmppd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vcmppd xmm0, xmm1, xmm2, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcmppd_op ENDP

cmpss_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    cmpss xmm0, xmm1, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
cmpss_op ENDP

vcmpss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vcmpss xmm0, xmm1, xmm2, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcmpss_op ENDP

vcmpsd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vcmpsd xmm0, xmm1, xmm2, 0
    movdqu XMMWORD PTR [r8], xmm0
    ret
vcmpsd_op ENDP

vcomiss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vcomiss xmm1, xmm2
    seta al
    setz ah
    movzx eax, ax
    mov DWORD PTR [r8], eax
    ret
vcomiss_op ENDP

vcomisd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vcomisd xmm1, xmm2
    seta al
    setz ah
    movzx eax, ax
    mov DWORD PTR [r8], eax
    ret
vcomisd_op ENDP

vucomiss_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vucomiss xmm1, xmm2
    seta al
    setz ah
    movzx eax, ax
    mov DWORD PTR [r8], eax
    ret
vucomiss_op ENDP

vucomisd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vucomisd xmm1, xmm2
    seta al
    setz ah
    movzx eax, ax
    mov DWORD PTR [r8], eax
    ret
vucomisd_op ENDP

vmovq_op PROC FRAME
    .endprolog
    mov rax, QWORD PTR [rcx]
    vmovq xmm0, rax
    movdqu XMMWORD PTR [r8], xmm0
    ret
vmovq_op ENDP

vpandn_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vpandn xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vpandn_op ENDP

vpavgb_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vpavgb xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vpavgb_op ENDP

vpaddsw_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vpaddsw xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vpaddsw_op ENDP

vpmaddubsw_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vpmaddubsw xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vpmaddubsw_op ENDP

vpmullw_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vpmullw xmm0, xmm1, xmm2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vpmullw_op ENDP

vpsrad_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    vpsrad xmm0, xmm1, 2
    movdqu XMMWORD PTR [r8], xmm0
    ret
vpsrad_op ENDP

vptest_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vptest xmm1, xmm2
    setz al
    setc ah
    movzx eax, ax
    mov DWORD PTR [r8], eax
    ret
vptest_op ENDP

vtestps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vtestps xmm1, xmm2
    setz al
    setc ah
    movzx eax, ax
    mov DWORD PTR [r8], eax
    ret
vtestps_op ENDP

vtestpd_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    movdqu xmm2, XMMWORD PTR [rdx]
    vtestpd xmm1, xmm2
    setz al
    setc ah
    movzx eax, ax
    mov DWORD PTR [r8], eax
    ret
vtestpd_op ENDP

extractps_op PROC FRAME
    .endprolog
    movdqu xmm1, XMMWORD PTR [rcx]
    extractps eax, xmm1, 1
    mov DWORD PTR [r8], eax
    ret
extractps_op ENDP

insertps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    insertps xmm0, xmm1, 10h
    movdqu XMMWORD PTR [r8], xmm0
    ret
insertps_op ENDP

blendvps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    blendvps xmm1, xmm0, xmm0
    movdqu XMMWORD PTR [r8], xmm1
    ret
blendvps_op ENDP

blendvpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movdqu xmm1, XMMWORD PTR [rdx]
    blendvpd xmm1, xmm0, xmm0
    movdqu XMMWORD PTR [r8], xmm1
    ret
blendvpd_op ENDP

lddqu_op PROC FRAME
    .endprolog
    lddqu xmm0, XMMWORD PTR [rcx]
    movdqu XMMWORD PTR [r8], xmm0
    ret
lddqu_op ENDP

movhps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movhps QWORD PTR [r8], xmm0
    ret
movhps_op ENDP

movlps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movlps QWORD PTR [r8], xmm0
    ret
movlps_op ENDP

movhpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movhpd QWORD PTR [r8], xmm0
    ret
movhpd_op ENDP

movlpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movlpd QWORD PTR [r8], xmm0
    ret
movlpd_op ENDP

ldmxcsr_stmxcsr_op PROC FRAME
    .endprolog
    stmxcsr DWORD PTR [r8]
    ldmxcsr DWORD PTR [r8]
    ret
ldmxcsr_stmxcsr_op ENDP

vldmxcsr_vstmxcsr_op PROC FRAME
    .endprolog
    vstmxcsr DWORD PTR [r8]
    vldmxcsr DWORD PTR [r8]
    ret
vldmxcsr_vstmxcsr_op ENDP

movntps_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movntps XMMWORD PTR [r8], xmm0
    ret
movntps_op ENDP

movntpd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movntpd XMMWORD PTR [r8], xmm0
    ret
movntpd_op ENDP

movntdq_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movntdq XMMWORD PTR [r8], xmm0
    ret
movntdq_op ENDP

movnti_op PROC FRAME
    .endprolog
    mov eax, DWORD PTR [rcx]
    movnti DWORD PTR [r8], eax
    ret
movnti_op ENDP

movntss_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movntss DWORD PTR [r8], xmm0
    ret
movntss_op ENDP

movntsd_op PROC FRAME
    .endprolog
    movdqu xmm0, XMMWORD PTR [rcx]
    movntsd QWORD PTR [r8], xmm0
    ret
movntsd_op ENDP

END
