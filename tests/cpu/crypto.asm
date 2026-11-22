; Source-owned differential fixture for Zen 2 x64 Crypto instructions:
; AES: AESENC, VAESENC, AESENCLAST, VAESENCLAST, AESDEC, VAESDEC, AESDECLAST, VAESDECLAST, AESIMC, VAESIMC, AESKEYGENASSIST, VAESKEYGENASSIST
; PCLMULQDQ: PCLMULQDQ, VPCLMULQDQ
; SHA: SHA1MSG1, SHA1MSG2, SHA1NEXTE, SHA1RNDS4, SHA256MSG1, SHA256MSG2, SHA256RNDS2
.code

fn_aesenc PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    aesenc xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_aesenc ENDP

fn_vaesenc PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vaesenc xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    ret
fn_vaesenc ENDP

fn_aesenclast PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    aesenclast xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_aesenclast ENDP

fn_vaesenclast PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vaesenclast xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    ret
fn_vaesenclast ENDP

fn_aesdec PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    aesdec xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_aesdec ENDP

fn_vaesdec PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vaesdec xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    ret
fn_vaesdec ENDP

fn_aesdeclast PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    aesdeclast xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_aesdeclast ENDP

fn_vaesdeclast PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vaesdeclast xmm0, xmm1, xmm2
    movdqu xmmword ptr [r8], xmm0
    ret
fn_vaesdeclast ENDP

fn_aesimc PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    aesimc xmm0, xmm1
    movdqu xmmword ptr [rdx], xmm0
    ret
fn_aesimc ENDP

fn_vaesimc PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    vaesimc xmm0, xmm1
    movdqu xmmword ptr [rdx], xmm0
    ret
fn_vaesimc ENDP

fn_aeskeygenassist PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    aeskeygenassist xmm0, xmm1, 5
    movdqu xmmword ptr [rdx], xmm0
    ret
fn_aeskeygenassist ENDP

fn_vaeskeygenassist PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    vaeskeygenassist xmm0, xmm1, 5
    movdqu xmmword ptr [rdx], xmm0
    ret
fn_vaeskeygenassist ENDP

fn_pclmulqdq PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    pclmulqdq xmm0, xmm1, 17h
    movdqu xmmword ptr [r8], xmm0
    ret
fn_pclmulqdq ENDP

fn_vpclmulqdq PROC FRAME
    .endprolog
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    vpclmulqdq xmm0, xmm1, xmm2, 17h
    movdqu xmmword ptr [r8], xmm0
    ret
fn_vpclmulqdq ENDP

fn_sha1msg1 PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    sha1msg1 xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_sha1msg1 ENDP

fn_sha1msg2 PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    sha1msg2 xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_sha1msg2 ENDP

fn_sha1nexte PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    sha1nexte xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_sha1nexte ENDP

fn_sha1rnds4 PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    sha1rnds4 xmm0, xmm1, 1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_sha1rnds4 ENDP

fn_sha256msg1 PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    sha256msg1 xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_sha256msg1 ENDP

fn_sha256msg2 PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [rcx]
    movdqu xmm1, xmmword ptr [rdx]
    sha256msg2 xmm0, xmm1
    movdqu xmmword ptr [r8], xmm0
    ret
fn_sha256msg2 ENDP

fn_sha256rnds2 PROC FRAME
    .endprolog
    movdqu xmm0, xmmword ptr [r8]
    movdqu xmm1, xmmword ptr [rcx]
    movdqu xmm2, xmmword ptr [rdx]
    sha256rnds2 xmm1, xmm2, xmm0
    movdqu xmmword ptr [r9], xmm1
    ret
fn_sha256rnds2 ENDP

END
