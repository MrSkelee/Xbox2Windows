; coverage: source cpu_aot_fma_packed
; Source-owned differential fixture for all 36 packed FMA3 instructions (ps/pd).
.code

vfmadd132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd132ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd132ps_op ENDP

vfmadd132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd132pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd132pd_op ENDP

vfmadd213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd213ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd213ps_op ENDP

vfmadd213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd213pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd213pd_op ENDP

vfmadd231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd231ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd231ps_op ENDP

vfmadd231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd231pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd231pd_op ENDP

vfmsub132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub132ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub132ps_op ENDP

vfmsub132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub132pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub132pd_op ENDP

vfmsub213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub213ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub213ps_op ENDP

vfmsub213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub213pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub213pd_op ENDP

vfmsub231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub231ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub231ps_op ENDP

vfmsub231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsub231pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub231pd_op ENDP

vfnmadd132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd132ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd132ps_op ENDP

vfnmadd132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd132pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd132pd_op ENDP

vfnmadd213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd213ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd213ps_op ENDP

vfnmadd213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd213pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd213pd_op ENDP

vfnmadd231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd231ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd231ps_op ENDP

vfnmadd231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmadd231pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmadd231pd_op ENDP

vfnmsub132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub132ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub132ps_op ENDP

vfnmsub132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub132pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub132pd_op ENDP

vfnmsub213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub213ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub213ps_op ENDP

vfnmsub213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub213pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub213pd_op ENDP

vfnmsub231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub231ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub231ps_op ENDP

vfnmsub231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfnmsub231pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfnmsub231pd_op ENDP

vfmaddsub132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub132ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub132ps_op ENDP

vfmaddsub132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub132pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub132pd_op ENDP

vfmaddsub213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub213ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub213ps_op ENDP

vfmaddsub213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub213pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub213pd_op ENDP

vfmaddsub231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub231ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub231ps_op ENDP

vfmaddsub231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmaddsub231pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmaddsub231pd_op ENDP

vfmsubadd132ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd132ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd132ps_op ENDP

vfmsubadd132pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd132pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd132pd_op ENDP

vfmsubadd213ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd213ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd213ps_op ENDP

vfmsubadd213pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd213pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd213pd_op ENDP

vfmsubadd231ps_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd231ps ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd231ps_op ENDP

vfmsubadd231pd_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmsubadd231pd ymm0, ymm1, ymm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsubadd231pd_op ENDP

vfmadd132ps_xmm_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vmovups ymm2, ymmword ptr [r8]
    vfmadd132ps xmm0, xmm1, xmm2
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmadd132ps_xmm_op ENDP

vfmsub213ps_mem_op PROC FRAME
    .endprolog
    vmovups ymm0, ymmword ptr [rcx]
    vmovups ymm1, ymmword ptr [rdx]
    vfmsub213ps ymm0, ymm1, ymmword ptr [r8]
    vmovups ymmword ptr [r9], ymm0
    vzeroupper
    ret
vfmsub213ps_mem_op ENDP

END
