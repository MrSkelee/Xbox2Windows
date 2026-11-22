; Integer overflow/parity consumers: RCX, RDX inputs; R8 points to 16 guarded bytes.
; All source registers are overwritten after the producer, before consumers.
FLAG_CASE MACRO symbol, operation, lhs, rhs, cc
    LOCAL taken
symbol PROC FRAME
    .endprolog
    mov rax, rcx
    IFIDNI <operation>, <inc>
        operation lhs
    ELSEIFIDNI <operation>, <dec>
        operation lhs
    ELSE
        operation lhs, rhs
    ENDIF
    mov rax, 0
    mov rdx, 0
    nop
    set&cc BYTE PTR [r8]
    IFIDNI <lhs>, <rax>
        mov rax, 10000002Ah
        mov r10, 100000011h
        cmov&cc rax, r10
        mov QWORD PTR [r8+4], rax
    ELSE
        mov eax, 42
        mov r10d, 17
        cmov&cc eax, r10d
        mov DWORD PTR [r8+4], eax
    ENDIF
    j&cc taken
    mov eax, 0
    ret
taken:
    mov eax, 1
    ret
symbol ENDP
ENDM
.code
FLAG_CASE flags_cmp_8_o, cmp, al, dl, o
FLAG_CASE flags_cmp_8_no, cmp, al, dl, no
FLAG_CASE flags_cmp_8_p, cmp, al, dl, p
FLAG_CASE flags_cmp_8_np, cmp, al, dl, np
FLAG_CASE flags_cmp_16_o, cmp, ax, dx, o
FLAG_CASE flags_cmp_16_no, cmp, ax, dx, no
FLAG_CASE flags_cmp_16_p, cmp, ax, dx, p
FLAG_CASE flags_cmp_16_np, cmp, ax, dx, np
FLAG_CASE flags_cmp_32_o, cmp, eax, edx, o
FLAG_CASE flags_cmp_32_no, cmp, eax, edx, no
FLAG_CASE flags_cmp_32_p, cmp, eax, edx, p
FLAG_CASE flags_cmp_32_np, cmp, eax, edx, np
FLAG_CASE flags_cmp_64_o, cmp, rax, rdx, o
FLAG_CASE flags_cmp_64_no, cmp, rax, rdx, no
FLAG_CASE flags_cmp_64_p, cmp, rax, rdx, p
FLAG_CASE flags_cmp_64_np, cmp, rax, rdx, np
FLAG_CASE flags_sub_8_o, sub, al, dl, o
FLAG_CASE flags_sub_8_no, sub, al, dl, no
FLAG_CASE flags_sub_8_p, sub, al, dl, p
FLAG_CASE flags_sub_8_np, sub, al, dl, np
FLAG_CASE flags_sub_16_o, sub, ax, dx, o
FLAG_CASE flags_sub_16_no, sub, ax, dx, no
FLAG_CASE flags_sub_16_p, sub, ax, dx, p
FLAG_CASE flags_sub_16_np, sub, ax, dx, np
FLAG_CASE flags_sub_32_o, sub, eax, edx, o
FLAG_CASE flags_sub_32_no, sub, eax, edx, no
FLAG_CASE flags_sub_32_p, sub, eax, edx, p
FLAG_CASE flags_sub_32_np, sub, eax, edx, np
FLAG_CASE flags_sub_64_o, sub, rax, rdx, o
FLAG_CASE flags_sub_64_no, sub, rax, rdx, no
FLAG_CASE flags_sub_64_p, sub, rax, rdx, p
FLAG_CASE flags_sub_64_np, sub, rax, rdx, np
FLAG_CASE flags_add_8_o, add, al, dl, o
FLAG_CASE flags_add_8_no, add, al, dl, no
FLAG_CASE flags_add_8_p, add, al, dl, p
FLAG_CASE flags_add_8_np, add, al, dl, np
FLAG_CASE flags_add_16_o, add, ax, dx, o
FLAG_CASE flags_add_16_no, add, ax, dx, no
FLAG_CASE flags_add_16_p, add, ax, dx, p
FLAG_CASE flags_add_16_np, add, ax, dx, np
FLAG_CASE flags_add_32_o, add, eax, edx, o
FLAG_CASE flags_add_32_no, add, eax, edx, no
FLAG_CASE flags_add_32_p, add, eax, edx, p
FLAG_CASE flags_add_32_np, add, eax, edx, np
FLAG_CASE flags_add_64_o, add, rax, rdx, o
FLAG_CASE flags_add_64_no, add, rax, rdx, no
FLAG_CASE flags_add_64_p, add, rax, rdx, p
FLAG_CASE flags_add_64_np, add, rax, rdx, np
FLAG_CASE flags_test_8_o, test, al, dl, o
FLAG_CASE flags_test_8_no, test, al, dl, no
FLAG_CASE flags_test_8_p, test, al, dl, p
FLAG_CASE flags_test_8_np, test, al, dl, np
FLAG_CASE flags_test_16_o, test, ax, dx, o
FLAG_CASE flags_test_16_no, test, ax, dx, no
FLAG_CASE flags_test_16_p, test, ax, dx, p
FLAG_CASE flags_test_16_np, test, ax, dx, np
FLAG_CASE flags_test_32_o, test, eax, edx, o
FLAG_CASE flags_test_32_no, test, eax, edx, no
FLAG_CASE flags_test_32_p, test, eax, edx, p
FLAG_CASE flags_test_32_np, test, eax, edx, np
FLAG_CASE flags_test_64_o, test, rax, rdx, o
FLAG_CASE flags_test_64_no, test, rax, rdx, no
FLAG_CASE flags_test_64_p, test, rax, rdx, p
FLAG_CASE flags_test_64_np, test, rax, rdx, np
FLAG_CASE flags_and_8_o, and, al, dl, o
FLAG_CASE flags_and_8_no, and, al, dl, no
FLAG_CASE flags_and_8_p, and, al, dl, p
FLAG_CASE flags_and_8_np, and, al, dl, np
FLAG_CASE flags_and_16_o, and, ax, dx, o
FLAG_CASE flags_and_16_no, and, ax, dx, no
FLAG_CASE flags_and_16_p, and, ax, dx, p
FLAG_CASE flags_and_16_np, and, ax, dx, np
FLAG_CASE flags_and_32_o, and, eax, edx, o
FLAG_CASE flags_and_32_no, and, eax, edx, no
FLAG_CASE flags_and_32_p, and, eax, edx, p
FLAG_CASE flags_and_32_np, and, eax, edx, np
FLAG_CASE flags_and_64_o, and, rax, rdx, o
FLAG_CASE flags_and_64_no, and, rax, rdx, no
FLAG_CASE flags_and_64_p, and, rax, rdx, p
FLAG_CASE flags_and_64_np, and, rax, rdx, np
FLAG_CASE flags_or_8_o, or, al, dl, o
FLAG_CASE flags_or_8_no, or, al, dl, no
FLAG_CASE flags_or_8_p, or, al, dl, p
FLAG_CASE flags_or_8_np, or, al, dl, np
FLAG_CASE flags_or_16_o, or, ax, dx, o
FLAG_CASE flags_or_16_no, or, ax, dx, no
FLAG_CASE flags_or_16_p, or, ax, dx, p
FLAG_CASE flags_or_16_np, or, ax, dx, np
FLAG_CASE flags_or_32_o, or, eax, edx, o
FLAG_CASE flags_or_32_no, or, eax, edx, no
FLAG_CASE flags_or_32_p, or, eax, edx, p
FLAG_CASE flags_or_32_np, or, eax, edx, np
FLAG_CASE flags_or_64_o, or, rax, rdx, o
FLAG_CASE flags_or_64_no, or, rax, rdx, no
FLAG_CASE flags_or_64_p, or, rax, rdx, p
FLAG_CASE flags_or_64_np, or, rax, rdx, np
FLAG_CASE flags_xor_8_o, xor, al, dl, o
FLAG_CASE flags_xor_8_no, xor, al, dl, no
FLAG_CASE flags_xor_8_p, xor, al, dl, p
FLAG_CASE flags_xor_8_np, xor, al, dl, np
FLAG_CASE flags_xor_16_o, xor, ax, dx, o
FLAG_CASE flags_xor_16_no, xor, ax, dx, no
FLAG_CASE flags_xor_16_p, xor, ax, dx, p
FLAG_CASE flags_xor_16_np, xor, ax, dx, np
FLAG_CASE flags_xor_32_o, xor, eax, edx, o
FLAG_CASE flags_xor_32_no, xor, eax, edx, no
FLAG_CASE flags_xor_32_p, xor, eax, edx, p
FLAG_CASE flags_xor_32_np, xor, eax, edx, np
FLAG_CASE flags_xor_64_o, xor, rax, rdx, o
FLAG_CASE flags_xor_64_no, xor, rax, rdx, no
FLAG_CASE flags_xor_64_p, xor, rax, rdx, p
FLAG_CASE flags_xor_64_np, xor, rax, rdx, np
FLAG_CASE flags_inc_8_o, inc, al, dl, o
FLAG_CASE flags_inc_8_no, inc, al, dl, no
FLAG_CASE flags_inc_8_p, inc, al, dl, p
FLAG_CASE flags_inc_8_np, inc, al, dl, np
FLAG_CASE flags_inc_16_o, inc, ax, dx, o
FLAG_CASE flags_inc_16_no, inc, ax, dx, no
FLAG_CASE flags_inc_16_p, inc, ax, dx, p
FLAG_CASE flags_inc_16_np, inc, ax, dx, np
FLAG_CASE flags_inc_32_o, inc, eax, edx, o
FLAG_CASE flags_inc_32_no, inc, eax, edx, no
FLAG_CASE flags_inc_32_p, inc, eax, edx, p
FLAG_CASE flags_inc_32_np, inc, eax, edx, np
FLAG_CASE flags_inc_64_o, inc, rax, rdx, o
FLAG_CASE flags_inc_64_no, inc, rax, rdx, no
FLAG_CASE flags_inc_64_p, inc, rax, rdx, p
FLAG_CASE flags_inc_64_np, inc, rax, rdx, np
FLAG_CASE flags_dec_8_o, dec, al, dl, o
FLAG_CASE flags_dec_8_no, dec, al, dl, no
FLAG_CASE flags_dec_8_p, dec, al, dl, p
FLAG_CASE flags_dec_8_np, dec, al, dl, np
FLAG_CASE flags_dec_16_o, dec, ax, dx, o
FLAG_CASE flags_dec_16_no, dec, ax, dx, no
FLAG_CASE flags_dec_16_p, dec, ax, dx, p
FLAG_CASE flags_dec_16_np, dec, ax, dx, np
FLAG_CASE flags_dec_32_o, dec, eax, edx, o
FLAG_CASE flags_dec_32_no, dec, eax, edx, no
FLAG_CASE flags_dec_32_p, dec, eax, edx, p
FLAG_CASE flags_dec_32_np, dec, eax, edx, np
FLAG_CASE flags_dec_64_o, dec, rax, rdx, o
FLAG_CASE flags_dec_64_no, dec, rax, rdx, no
FLAG_CASE flags_dec_64_p, dec, rax, rdx, p
FLAG_CASE flags_dec_64_np, dec, rax, rdx, np
FLAG_CASE flags_add_8_e, add, al, dl, e
FLAG_CASE flags_add_8_ne, add, al, dl, ne
FLAG_CASE flags_add_8_s, add, al, dl, s
FLAG_CASE flags_add_8_ns, add, al, dl, ns
FLAG_CASE flags_add_16_e, add, ax, dx, e
FLAG_CASE flags_add_16_ne, add, ax, dx, ne
FLAG_CASE flags_add_16_s, add, ax, dx, s
FLAG_CASE flags_add_16_ns, add, ax, dx, ns
FLAG_CASE flags_add_32_e, add, eax, edx, e
FLAG_CASE flags_add_32_ne, add, eax, edx, ne
FLAG_CASE flags_add_32_s, add, eax, edx, s
FLAG_CASE flags_add_32_ns, add, eax, edx, ns
FLAG_CASE flags_add_64_e, add, rax, rdx, e
FLAG_CASE flags_add_64_ne, add, rax, rdx, ne
FLAG_CASE flags_add_64_s, add, rax, rdx, s
FLAG_CASE flags_add_64_ns, add, rax, rdx, ns
FLAG_CASE flags_cmp_8_l, cmp, al, dl, l
FLAG_CASE flags_cmp_8_ge, cmp, al, dl, ge
FLAG_CASE flags_cmp_8_le, cmp, al, dl, le
FLAG_CASE flags_cmp_8_g, cmp, al, dl, g
FLAG_CASE flags_cmp_16_l, cmp, ax, dx, l
FLAG_CASE flags_cmp_16_ge, cmp, ax, dx, ge
FLAG_CASE flags_cmp_16_le, cmp, ax, dx, le
FLAG_CASE flags_cmp_16_g, cmp, ax, dx, g
FLAG_CASE flags_cmp_32_l, cmp, eax, edx, l
FLAG_CASE flags_cmp_32_ge, cmp, eax, edx, ge
FLAG_CASE flags_cmp_32_le, cmp, eax, edx, le
FLAG_CASE flags_cmp_32_g, cmp, eax, edx, g
FLAG_CASE flags_cmp_64_l, cmp, rax, rdx, l
FLAG_CASE flags_cmp_64_ge, cmp, rax, rdx, ge
FLAG_CASE flags_cmp_64_le, cmp, rax, rdx, le
FLAG_CASE flags_cmp_64_g, cmp, rax, rdx, g
FLAG_CASE flags_sub_8_l, sub, al, dl, l
FLAG_CASE flags_sub_8_ge, sub, al, dl, ge
FLAG_CASE flags_sub_8_le, sub, al, dl, le
FLAG_CASE flags_sub_8_g, sub, al, dl, g
FLAG_CASE flags_sub_16_l, sub, ax, dx, l
FLAG_CASE flags_sub_16_ge, sub, ax, dx, ge
FLAG_CASE flags_sub_16_le, sub, ax, dx, le
FLAG_CASE flags_sub_16_g, sub, ax, dx, g
FLAG_CASE flags_sub_32_l, sub, eax, edx, l
FLAG_CASE flags_sub_32_ge, sub, eax, edx, ge
FLAG_CASE flags_sub_32_le, sub, eax, edx, le
FLAG_CASE flags_sub_32_g, sub, eax, edx, g
FLAG_CASE flags_sub_64_l, sub, rax, rdx, l
FLAG_CASE flags_sub_64_ge, sub, rax, rdx, ge
FLAG_CASE flags_sub_64_le, sub, rax, rdx, le
FLAG_CASE flags_sub_64_g, sub, rax, rdx, g
END
