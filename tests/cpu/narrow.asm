; 8- and 16-bit register writes and returns that define 0, 1, 2 or 8 low bytes of RAX, for the
; jump-table translator. qword_ops and flag_results cover 64-bit IMUL, CL shifts and MOVSX and
; the flags of INC, TEST and CMP.
; Every export takes RCX, RDX and R8 = address of three writable QWORDs. An 8- or 16-bit write
; leaves the other bytes of its register unchanged; a 32-bit write zero-extends.
.code
; Byte writes merged into defined registers: RAX = RCX with low byte DL, [R8] = RDX with low byte CL.
byte_merge PROC FRAME
    .endprolog
    mov rax, rcx
    mov al, dl
    mov r9, rdx
    mov r9b, cl
    mov QWORD PTR [r8], r9
    ret
byte_merge ENDP

; Word ADD, SUB, three-operand IMUL and MOVZX into a word register.
word_ops PROC FRAME
    .endprolog
    mov rax, rcx
    add ax, dx
    mov r9, rdx
    sub r9w, cx
    mov QWORD PTR [r8], r9
    mov r10, rcx
    imul r10w, dx, -3
    mov QWORD PTR [r8+8], r10
    mov r11, rcx
    movzx r11w, dl
    mov QWORD PTR [r8+16], r11
    ret
word_ops ENDP

; Byte and word shifts of RDX by CL; x86 masks the count to five bits for both widths.
byte_shift PROC FRAME
    .endprolog
    mov rax, rdx
    shl al, cl
    mov r9, rdx
    sar r9b, cl
    mov QWORD PTR [r8], r9
    mov r10, rdx
    shr r10w, cl
    mov QWORD PTR [r8+8], r10
    mov r11, rdx
    sar r11w, cl
    mov QWORD PTR [r8+16], r11
    ret
byte_shift ENDP

byte_unary PROC FRAME
    .endprolog
    mov rax, rcx
    inc al
    mov r9, rcx
    neg r9w
    mov QWORD PTR [r8], r9
    mov r10, rdx
    not r10b
    mov QWORD PTR [r8+8], r10
    dec dl
    mov QWORD PTR [r8+16], rdx
    ret
byte_unary ENDP

; Only AL is written on both paths; the rest of RAX is whatever the caller left.
al_less PROC FRAME
    .endprolog
    cmp rcx, rdx
    jb is_less
    xor al, al
    ret
is_less:
    mov al, 1
    ret
al_less ENDP

; One RET returns a 32-bit value, the other only AL: one byte is defined at every RET.
mixed_width PROC FRAME
    .endprolog
    test cl, 1
    jnz byte_path
    mov eax, edx
    ret
byte_path:
    mov al, dl
    ret
mixed_width ENDP

; Only AX is written: two low bytes of RAX are defined at the RET.
ax_copy PROC FRAME
    .endprolog
    mov ax, dx
    ret
ax_copy ENDP

; MOVZX from AL defines all of RAX again.
zx_byte PROC FRAME
    .endprolog
    mov al, dl
    movzx eax, al
    ret
zx_byte ENDP

; SETcc is a byte write: only AL is defined at RET. The byte MOV between CMP and SETL leaves the
; flags unchanged; [R8] = RDX with low byte CL.
set_less PROC FRAME
    .endprolog
    mov r9, rdx
    cmp rcx, rdx
    mov r9b, cl
    setl al
    mov QWORD PTR [r8], r9
    ret
set_less ENDP

; A byte compare feeds SETB, and MOVZX then defines all of RAX.
set_zx PROC FRAME
    .endprolog
    cmp cl, dl
    setb al
    movzx eax, al
    ret
set_zx ENDP

store_only PROC FRAME
    .endprolog
    mov QWORD PTR [r8], rdx
    ret
store_only ENDP

; ML64 encodes RET 0 as C3, so the C2 form is emitted as bytes.
store_ret0 PROC FRAME
    .endprolog
    mov QWORD PTR [r8+8], rcx
    DB 0C2h, 0, 0
store_ret0 ENDP

; No RET is reachable: the loop branches to itself. It is translated and inspected, never called.
self_loop PROC FRAME
    .endprolog
spin:
    pause
    inc rcx
    jmp spin
self_loop ENDP

qword_ops PROC FRAME
    .endprolog
    mov rax, rcx
    imul rax, rdx
    mov r9, rdx
    shl r9, cl
    mov QWORD PTR [r8], r9
    mov r10, rdx
    sar r10, cl
    mov QWORD PTR [r8+8], r10
    movsx r11, dl
    mov QWORD PTR [r8+16], r11
    ret
qword_ops ENDP

flag_results PROC FRAME
    .endprolog
    movzx eax, cl
    inc al
    sete al
    mov QWORD PTR [r8], rax
    test rcx, rdx
    setb al
    mov QWORD PTR [r8+8], rax
    cmp rcx, rdx
    setle al
    mov QWORD PTR [r8+16], rax
    sets al
    ret
flag_results ENDP

; Rejected: after the join only AL is defined on one path, and ADD reads all of EAX.
join_wide PROC FRAME
    .endprolog
    test cl, 1
    jnz join_byte
    mov eax, edx
    jmp join_add
join_byte:
    mov al, dl
join_add:
    add eax, 1
    ret
join_wide ENDP

; Rejected: a 16-bit CMOVcc merges into AX, unlike the zero-extending 32-bit form.
cmov_word PROC FRAME
    .endprolog
    mov rax, rcx
    cmp rcx, rdx
    cmovb ax, dx
    ret
cmov_word ENDP

; Rejected: RAX holds a guest address that the translation does not reproduce.
address_return PROC FRAME
    .endprolog
    lea rax, byte_merge
    ret
address_return ENDP

; Three-operand IMUL writes its destination without reading it: R10, R9 and RAX are not defined
; before the multiplies. The 16-bit form merges into R9W, and MOVZX reads only that word.
imul3_fresh PROC FRAME
    .endprolog
    imul r10, rdx, -5
    mov QWORD PTR [r8], r10
    imul r9w, cx, 7FFFh
    movzx r9d, r9w
    mov QWORD PTR [r8+8], r9
    imul eax, ecx, 1010101h
    ret
imul3_fresh ENDP

; Rejected: two-operand IMUL reads its destination, and EAX is not defined at entry.
imul2_undefined PROC FRAME
    .endprolog
    imul eax, ecx
    ret
imul2_undefined ENDP
END
