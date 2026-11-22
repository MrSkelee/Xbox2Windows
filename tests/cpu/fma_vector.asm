; coverage: source cpu_aot_fma_vector
; Source-owned differential fixture for all 36 vector FMA3 instructions (ps/pd).
; Each export loads YMM0=[rcx], YMM1=[rdx], YMM2=[r8], runs the 128-bit vector FMA, and stores YMM0 to [r9].
.code

vfmadd132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd132ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd132ps_op ENDP

vfmadd132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd132pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd132pd_op ENDP

vfmadd213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd213ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd213ps_op ENDP

vfmadd213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd213pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd213pd_op ENDP

vfmadd231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd231ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd231ps_op ENDP

vfmadd231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd231pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd231pd_op ENDP

vfmsub132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub132ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub132ps_op ENDP

vfmsub132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub132pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub132pd_op ENDP

vfmsub213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub213ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub213ps_op ENDP

vfmsub213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub213pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub213pd_op ENDP

vfmsub231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub231ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub231ps_op ENDP

vfmsub231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub231pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub231pd_op ENDP

vfnmadd132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd132ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd132ps_op ENDP

vfnmadd132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd132pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd132pd_op ENDP

vfnmadd213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd213ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd213ps_op ENDP

vfnmadd213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd213pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd213pd_op ENDP

vfnmadd231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd231ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd231ps_op ENDP

vfnmadd231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd231pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd231pd_op ENDP

vfnmsub132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub132ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub132ps_op ENDP

vfnmsub132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub132pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub132pd_op ENDP

vfnmsub213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub213ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub213ps_op ENDP

vfnmsub213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub213pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub213pd_op ENDP

vfnmsub231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub231ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub231ps_op ENDP

vfnmsub231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub231pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub231pd_op ENDP

vfmaddsub132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub132ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub132ps_op ENDP

vfmaddsub132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub132pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub132pd_op ENDP

vfmaddsub213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub213ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub213ps_op ENDP

vfmaddsub213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub213pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub213pd_op ENDP

vfmaddsub231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub231ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub231ps_op ENDP

vfmaddsub231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub231pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub231pd_op ENDP

vfmsubadd132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd132ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd132ps_op ENDP

vfmsubadd132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd132pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd132pd_op ENDP

vfmsubadd213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd213ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd213ps_op ENDP

vfmsubadd213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd213pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd213pd_op ENDP

vfmsubadd231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd231ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd231ps_op ENDP

vfmsubadd231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd231pd xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd231pd_op ENDP

END
