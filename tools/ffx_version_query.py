"""Offline C++ lowering for the null-context FidelityFX version-query path."""
import argparse
import hashlib
from pathlib import Path

import pefile
from iced_x86 import Decoder, MemorySizeExt, Mnemonic as M, OpKind as K, Register as R, RegisterExt

from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges, image_bytes


LOADER = "431bdd2e26c0c8214fd7601140eb9fe6d8a249f5000539453a9a9b6a0b7c0ee8"
UPSCALER = "faff02f294a7e9149ce079dffe3dedbcabe99b1f180ab14222aa8689e00a75fa"
REGS = {getattr(R, n.upper()): n for n in "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()}
HIGH_BYTE = {R.AH, R.BH, R.CH, R.DH}
UINT = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}

INTEGER_HEADER = """#include <array>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>
using std::memcpy;
using std::memset;
using word = uint64_t;
static_assert(sizeof(void*) == sizeof(word));
template<class T> T load(word address) {
    T v; memcpy(&v, reinterpret_cast<const void*>(address), sizeof v); return v;
}
template<class T> void store(word address, T v) {
    memcpy(reinterpret_cast<void*>(address), &v, sizeof v);
}
"""
HEADER = INTEGER_HEADER + "struct Query { word type, next, effect, device, count, ids, names; };\n"


def reg(number):
    return REGS[RegisterExt.full_register(number)]


def region(pe, start, end):
    ins = list(Decoder(64, image_bytes(pe, start, end-start, executable=True), ip=start))
    if not ins or ins[-1].next_ip != end or any(i.is_invalid for i in ins):
        raise ValueError("query interval does not end on an instruction boundary")
    return ins


def lower(body, initial, globals_, calls, exits, *, host_ops=None):
    """Emit only query integer operations. All external edges and calls need named bindings."""
    lines = ["word frame[16]{};", "word " + ", ".join(r + "=0" for r in REGS.values()) + ";",
             "bool zero=false, carry=false, overflow=false;", "rsp = reinterpret_cast<word>(frame);", *initial]
    allowed = {i.ip for i in body} | set(exits)
    xmm = {getattr(R, f"XMM{idx}"): f"xmm{idx}" for idx in range(8)}
    has_xmm_math = any(i.mnemonic in (M.MOVDQU, M.VMOVDQU, M.VPSRLDQ, M.VMOVD, M.VPADDD,
                                      M.AESDEC, M.AESDECLAST, M.AESENC, M.AESENCLAST, M.AESIMC, M.AESKEYGENASSIST,
                                      M.VAESDEC, M.VAESDECLAST, M.VAESENC, M.VAESENCLAST, M.VAESIMC, M.VAESKEYGENASSIST,
                                      M.PCLMULQDQ, M.VPCLMULQDQ,
                                      M.SHA1MSG1, M.SHA1MSG2, M.SHA1NEXTE, M.SHA1RNDS4,
                                      M.SHA256MSG1, M.SHA256MSG2, M.SHA256RNDS2)
                       or (i.op0_kind == K.REGISTER and i.op0_register in xmm)
                       or (i.op1_kind == K.REGISTER and i.op1_register in xmm)
                       for i in body)
    if has_xmm_math:
        lines.append("__m128i " + ", ".join(f"xmm{idx}{{}}" for idx in range(8)) + ";")
    # Unaligned YMM copies and VEX zeroing in the descriptor builder need
    # only byte storage on the desktop host.
    wide = {R.YMM0: "wide0", R.YMM1: "wide1", R.YMM2: "wide2"}
    has_wide = any(i.mnemonic == M.VMOVUPS for i in body)
    if has_wide:
        if has_xmm_math:
            raise ValueError("mixed vector arithmetic and wide descriptor copies are unsupported")
        lines.append("std::array<uint8_t,32> wide0{}, wide1{}, wide2{};")
    for index, i in enumerate(body):
        op = i.mnemonic

        def address():
            if i.is_ip_rel_memory_operand:
                if i.memory_base == R.EIP:
                    # The hardware adds the low 32 bits of the runtime RIP; an RVA binding cannot model that.
                    raise ValueError(f"unsupported EIP-relative operand at {i.ip:#x}: {i}")
                return globals_[i.ip_rel_memory_address]
            terms = []
            addr32 = False
            if i.memory_base != R.NONE:
                addr32 |= RegisterExt.size(i.memory_base) == 4
                terms.append(reg(i.memory_base))
            if i.memory_index != R.NONE:
                addr32 |= RegisterExt.size(i.memory_index) == 4
                terms.append(f"{reg(i.memory_index)} * {i.memory_index_scale}ull")
            terms.append(f"{i.memory_displacement}ull")
            expr = " + ".join(terms)
            return f"static_cast<uint32_t>({expr})" if addr32 else expr

        def operand(n):
            kind = i.op_kind(n)
            if kind == K.REGISTER:
                register = i.op_register(n)
                if register in HIGH_BYTE:
                    return f"static_cast<uint8_t>({reg(register)} >> 8)"
                return f"static_cast<{UINT[RegisterExt.size(register)]}>({reg(register)})"
            if kind == K.MEMORY:
                return f"load<{UINT[MemorySizeExt.size(i.memory_size)]}>({address()})"
            return f"{i.immediate(n)}ull"

        def write(expr):
            if i.op0_kind == K.MEMORY:
                return f"store<{UINT[MemorySizeExt.size(i.memory_size)]}>({address()}, {expr});"
            dest = i.op0_register
            if dest in HIGH_BYTE:
                return f"{reg(dest)} = ({reg(dest)} & ~0xff00ull) | (static_cast<word>(static_cast<uint8_t>({expr})) << 8);"
            size = RegisterExt.size(dest)
            value = f"static_cast<{UINT[size]}>({expr})"
            if size < 4:
                value = f"({reg(dest)} & ~{(1 << (8*size))-1}ull) | {value}"
            return f"{reg(dest)} = {value};"

        if host_ops and i.ip in host_ops:
            stmt = host_ops[i.ip]
        elif i.segment_prefix in (R.FS, R.GS) or i.has_lock_prefix:
            # FS/GS select a thread block base and LOCK makes the access atomic;
            # the flat loads and stores below would silently drop both.
            raise ValueError(f"unsupported instruction prefix at {i.ip:#x}: {i}")
        elif op in (M.JE, M.JNE, M.JAE, M.JA, M.JB, M.JBE, M.JO, M.JNO, M.JG, M.JGE, M.JL, M.JLE, M.JS, M.JNS, M.JP, M.JNP, M.JMP):
            target = i.near_branch_target
            if target not in allowed:
                raise ValueError(f"unbound branch at {i.ip:#x}")
            cond = {M.JE: "if (zero) ", M.JNE: "if (!zero) ", M.JAE: "if (!carry) ",
                    M.JA: "if (!carry && !zero) ", M.JB: "if (carry) ", M.JBE: "if (carry || zero) ",
                    M.JO: "if (overflow) ", M.JNO: "if (!overflow) ",
                    M.JG: "if (!carry && !zero) ", M.JGE: "if (!carry) ", M.JL: "if (carry) ", M.JLE: "if (carry || zero) ",
                    M.JS: "if (false) ", M.JNS: "if (true) ", M.JP: "if (false) ", M.JNP: "if (true) ",
                    M.JMP: ""}[op]
            stmt = f"{cond}goto block_{target:x};"
        elif op in (M.MOV, M.MOVZX):
            stmt = write(operand(1))
        elif op == M.MOVSXD:
            stmt = write(f"int64_t(int32_t({operand(1)}))")
        elif op in (M.CMOVE, M.CMOVNE, M.CMOVAE, M.CMOVA, M.CMOVB, M.CMOVBE, M.CMOVG, M.CMOVGE, M.CMOVL, M.CMOVLE, M.CMOVO, M.CMOVNO, M.CMOVS, M.CMOVNS, M.CMOVP, M.CMOVNP):
            c = {
                M.CMOVE: "zero", M.CMOVNE: "!zero", M.CMOVAE: "!carry", M.CMOVA: "!carry && !zero",
                M.CMOVB: "carry", M.CMOVBE: "carry || zero", M.CMOVG: "!carry && !zero", M.CMOVGE: "!carry",
                M.CMOVL: "carry", M.CMOVLE: "carry || zero", M.CMOVO: "overflow", M.CMOVNO: "!overflow",
                M.CMOVS: "false", M.CMOVNS: "true", M.CMOVP: "false", M.CMOVNP: "true",
            }[op]
            stmt = write(f"({c}) ? {operand(1)} : {operand(0)}")
        elif op == M.LEA:
            stmt = write(address())
        elif op == M.CMP:
            # Sign-extended immediates arrive as 64-bit values; compare at the destination width.
            width = UINT[MemorySizeExt.size(i.memory_size) if i.op0_kind == K.MEMORY else RegisterExt.size(i.op0_register)]
            stmt = (f"{{ const {width} a = {operand(0)}, b = static_cast<{width}>({operand(1)}); "
                    f"zero = a == b; carry = a < b; }}")
        elif op == M.TEST:
            stmt = f"zero = (({operand(0)} & {operand(1)}) == 0); carry = false;"
        elif op == M.IMUL and i.op_count in (2, 3) and RegisterExt.size(i.op0_register) == 4:
            lhs, rhs = operand(i.op_count - 2), operand(i.op_count - 1)
            stmt = (f"{{ const int64_t product = int64_t(int32_t({lhs})) * int32_t({rhs}); "
                    f"carry = product != int32_t(product); {write('product')} }}")
        elif op == M.CDQ:
            stmt = "rdx = uint32_t(int32_t(rax) >> 31);"
        elif op in (M.SHL, M.SHR, M.SAR) and i.op1_kind == K.IMMEDIATE8 and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            bits = 8 * size
            count = i.immediate(1) & (bits - 1)
            shift, last = ("<<", bits-count) if op == M.SHL else (">>", count-1)
            lhs = f"int{bits}_t(a)" if op == M.SAR else "a"
            stmt = (f"{{ const {UINT[size]} a = {operand(0)}, v = {lhs} {shift} {count}; "
                    f"carry = ((a >> {last}) & 1) != 0; zero = v == 0; {write('v')} }}") if count else \
                write(operand(0))  # A masked zero count keeps the flags but still zero-extends a 32-bit destination.
        elif op in (M.ADD, M.ADC, M.AND, M.OR, M.XOR, M.INC, M.DEC, M.SUB, M.SBB):
            operator = {M.ADD: "+", M.ADC: "+", M.INC: "+", M.DEC: "-", M.AND: "&", M.OR: "|", M.XOR: "^", M.SUB: "-", M.SBB: "-"}[op]
            rhs = "1" if op in (M.INC, M.DEC) else operand(1)
            size = MemorySizeExt.size(i.memory_size) if i.op0_kind == K.MEMORY else RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            expr = f"a {operator} b" + (" + word(carry)" if op == M.ADC else (" - word(carry)" if op == M.SBB else ""))
            update = {M.ADD: f"carry = v < a; overflow = ((a ^ v) & ~(a ^ b)) >> {bits - 1} != 0;",
                      M.ADC: "carry = carry ? (v <= a) : (v < a);",
                      M.SUB: "carry = a < b;", M.SBB: "carry = a < b || (carry && a == b);",
                      M.INC: "", M.DEC: "", M.XOR: "carry = false;", M.AND: "carry = false;", M.OR: "carry = false;"}[op]
            stmt = (f"{{ const {width} a = {operand(0)}, b = static_cast<{width}>({rhs}); "
                    f"const {width} v = static_cast<{width}>({expr}); {update} zero = v == 0; {write('v')} }}")
        elif op in (M.ANDN, M.BEXTR, M.BLSI, M.BLSMSK, M.BLSR, M.TZCNT) and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            if op == M.ANDN:
                stmt = (f"{{ const {width} v = static_cast<{width}>(~static_cast<{width}>({operand(1)}) "
                        f"& static_cast<{width}>({operand(2)})); carry = false; zero = v == 0; {write('v')} }}")
            elif op == M.BEXTR:
                stmt = (f"{{ const {width} a = {operand(1)}, ctrl = {operand(2)}; "
                        f"const unsigned start = static_cast<unsigned>(ctrl & 0xffu), "
                        f"len = static_cast<unsigned>((ctrl >> 8) & 0xffu); "
                        f"{width} v = 0; if (start < {bits}u && len > 0u) {{ "
                        f"const {width} s = a >> start; "
                        f"v = len >= {bits}u ? s : static_cast<{width}>(s & ((static_cast<{width}>(1) << len) - 1)); }} "
                        f"carry = false; zero = v == 0; {write('v')} }}")
            elif op == M.BLSI:
                stmt = (f"{{ const {width} a = {operand(1)}, v = static_cast<{width}>(a & (static_cast<{width}>(0) - a)); "
                        f"carry = a != 0; zero = v == 0; {write('v')} }}")
            elif op == M.BLSMSK:
                stmt = (f"{{ const {width} a = {operand(1)}, v = static_cast<{width}>(a ^ (a - 1)); "
                        f"carry = a == 0; zero = false; {write('v')} }}")
            elif op == M.BLSR:
                stmt = (f"{{ const {width} a = {operand(1)}, v = static_cast<{width}>(a & (a - 1)); "
                        f"carry = a == 0; zero = v == 0; {write('v')} }}")
            else:  # M.TZCNT
                stmt = (f"{{ const {width} a = {operand(1)}; {width} v = 0; "
                        f"if (a == 0) {{ v = {bits}; }} else {{ while (((a >> v) & 1) == 0) ++v; }} "
                        f"carry = a == 0; zero = v == 0; {write('v')} }}")
        elif op == M.BZHI and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            stmt = (f"{{ const {width} a = {operand(1)}; const unsigned idx = static_cast<unsigned>({operand(2)} & 0xffu); "
                    f"{width} v; if (idx < {bits}u) {{ const {width} mask = idx == 0u ? static_cast<{width}>(0) : "
                    f"static_cast<{width}>((static_cast<{width}>(1) << idx) - 1); "
                    f"v = a & mask; carry = false; }} else {{ v = a; carry = true; }} "
                    f"zero = v == 0; {write('v')} }}")
        elif op == M.RORX and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            stmt = (f"{{ const {width} a = {operand(1)}; const unsigned count = static_cast<unsigned>({operand(2)}) & {bits - 1}u; "
                    f"const {width} v = count == 0u ? a : static_cast<{width}>((a >> count) | (a << ({bits}u - count))); "
                    f"{write('v')} }}")
        elif op in (M.SARX, M.SHLX, M.SHRX) and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            if op == M.SHLX:
                expr = f"static_cast<{width}>(a << count)"
            elif op == M.SHRX:
                expr = f"static_cast<{width}>(a >> count)"
            else:  # M.SARX
                expr = f"static_cast<{width}>(static_cast<int{bits}_t>(a) >> count)"
            stmt = (f"{{ const {width} a = {operand(1)}; const unsigned count = static_cast<unsigned>({operand(2)}) & {bits - 1}u; "
                    f"const {width} v = {expr}; {write('v')} }}")
        elif op == M.MULX and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            if size == 4:
                stmt = (f"{{ const uint64_t prod = static_cast<uint64_t>(static_cast<uint32_t>(rdx)) * "
                        f"static_cast<uint64_t>({operand(2)}); "
                        f"{reg(i.op0_register)} = static_cast<uint32_t>(prod >> 32); "
                        f"{reg(i.op1_register)} = static_cast<uint32_t>(prod); }}")
            else:
                stmt = (f"{{ uint64_t hi = 0; const uint64_t lo = _umul128(rdx, {operand(2)}, &hi); "
                        f"{reg(i.op0_register)} = hi; {reg(i.op1_register)} = lo; }}")
        elif op in (M.PEXT, M.PDEP) and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width = UINT[size]
            if op == M.PEXT:
                loop = (f"for ({width} bb = 1; m != 0; bb <<= 1) {{ "
                        f"const {width} lowest = m & (static_cast<{width}>(0) - m); "
                        f"if (s & lowest) v |= bb; m &= m - 1; }}")
            else:  # PDEP
                loop = (f"for ({width} bb = 1; m != 0; bb <<= 1) {{ "
                        f"const {width} lowest = m & (static_cast<{width}>(0) - m); "
                        f"if (s & bb) v |= lowest; m &= m - 1; }}")
            stmt = (f"{{ const {width} s = {operand(1)}; {width} m = {operand(2)}, v = 0; "
                    f"{loop} {write('v')} }}")
        elif op in (M.ADCX, M.ADOX) and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width = UINT[size]
            flag = "carry" if op == M.ADCX else "overflow"
            stmt = (f"{{ const {width} a = {operand(0)}, b = static_cast<{width}>({operand(1)}); "
                    f"const {width} v = a + b + ({flag} ? 1 : 0); "
                    f"{flag} = {flag} ? (v <= a) : (v < a); "
                    f"{write('v')} }}")
        elif op == M.POPCNT and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width = UINT[size]
            fn = "__popcnt" if size == 4 else "__popcnt64"
            stmt = (f"{{ const {width} a = {operand(1)}; "
                    f"const {width} v = static_cast<{width}>({fn}(a)); "
                    f"zero = a == 0; carry = false; {write('v')} }}")
        elif op == M.LZCNT and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            fn = "__lzcnt" if size == 4 else "__lzcnt64"
            stmt = (f"{{ const {width} a = {operand(1)}; "
                    f"const {width} v = static_cast<{width}>({fn}(a)); "
                    f"carry = a == 0; zero = v == 0; {write('v')} }}")
        elif op in (M.BSF, M.BSR) and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width = UINT[size]
            fn = ("_BitScanForward" if op == M.BSF else "_BitScanReverse") + ("" if size == 4 else "64")
            cast = "static_cast<unsigned long>" if size == 4 else ""
            stmt = (f"{{ const {width} a = {operand(1)}; unsigned long idx = 0; "
                    f"const bool found = {fn}(&idx, {cast}(a)) != 0; "
                    f"zero = !found; const {width} v = found ? static_cast<{width}>(idx) : 0; "
                    f"{write('v')} }}")
        elif op == M.BSWAP and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width = UINT[size]
            fn = "_byteswap_ulong" if size == 4 else "_byteswap_uint64"
            stmt = f"{{ const {width} a = {operand(0)}; const {width} v = {fn}(a); {write('v')} }}"
        elif op == M.BT and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            bits = 8 * size
            stmt = f"{{ const unsigned idx = static_cast<unsigned>({operand(1)}) & {bits - 1}u; carry = (({operand(0)} >> idx) & 1) != 0; }}"
        elif op in (M.BTS, M.BTR, M.BTC) and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            op_code = "|" if op == M.BTS else ("& ~" if op == M.BTR else "^")
            stmt = (f"{{ const {width} a = {operand(0)}; const unsigned idx = static_cast<unsigned>({operand(1)}) & {bits - 1}u; "
                    f"const {width} bit = static_cast<{width}>(1) << idx; "
                    f"carry = ((a >> idx) & 1) != 0; const {width} v = a {op_code} bit; {write('v')} }}")
        elif op == M.CBW:
            stmt = "rax = (rax & ~0xffffull) | static_cast<uint16_t>(static_cast<int16_t>(static_cast<int8_t>(rax)));"
        elif op == M.CWDE:
            stmt = "rax = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(rax)));"
        elif op == M.CDQE:
            stmt = "rax = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(rax)));"
        elif op == M.CWD:
            stmt = "rdx = (rdx & ~0xffffull) | (static_cast<int16_t>(rax) < 0 ? 0xffffu : 0u);"
        elif op == M.CDQ:
            stmt = "rdx = static_cast<int32_t>(rax) < 0 ? 0xffffffffu : 0u;"
        elif op == M.CQO:
            stmt = "rdx = static_cast<int64_t>(rax) < 0 ? 0xffffffffffffffffull : 0ull;"
        elif op in (M.VMOVQ, M.VMOVSD, M.VMOVHPD) and has_wide:
            lanes = {R.XMM0: "wide0", R.XMM1: "wide1", R.XMM2: "wide2"}
            if i.op1_kind == K.MEMORY and op != M.VMOVHPD:
                dst = lanes[i.op0_register]
                stmt = f"{dst} = {{}}; memcpy({dst}.data(), reinterpret_cast<const void*>({address()}), 8);"
            elif i.op0_kind == K.MEMORY:
                start = 8 if op == M.VMOVHPD else 0
                stmt = f"memcpy(reinterpret_cast<void*>({address()}), {lanes[i.op1_register]}.data()+{start}, 8);"
            else:
                raise ValueError(f"unsupported vector move at {i.ip:#x}")
        elif has_wide and op in (M.VPADDD, M.VPSRLD):
            lanes = {R.XMM0: "wide0", R.XMM1: "wide1", R.XMM2: "wide2"}
            src, dst = lanes[i.op1_register], lanes[i.op0_register]
            operation = (f"+ load<uint32_t>(({address()}) + n)" if op == M.VPADDD
                         else f">> {i.immediate(2)}")
            if op == M.VPSRLD and i.immediate(2) >= 32:
                raise ValueError("unsupported packed shift count")
            stmt = (f"{{ auto input = {src}; {dst} = {{}}; for (size_t n=0; n<16; n+=4) {{ "
                    f"auto v = load<uint32_t>(reinterpret_cast<word>(input.data()+n)) {operation}; "
                    f"memcpy({dst}.data()+n, &v, 4); }} }}")
        elif op == M.VMOVUPS and i.op1_kind == K.MEMORY:
            stmt = f"{wide[i.op0_register]} = load<std::array<uint8_t,32>>({address()});"
        elif op == M.VMOVUPS and i.op0_kind == K.MEMORY:
            if i.op1_register in wide:
                stmt = f"store({address()}, {wide[i.op1_register]});"
            else:
                source = {R.XMM0: "wide0", R.XMM1: "wide1", R.XMM2: "wide2"}[i.op1_register]
                stmt = f"memcpy(reinterpret_cast<void*>({address()}), {source}.data(), 16);"
        elif op == M.VPXOR and i.op0_register == i.op1_register == i.op2_register and has_wide:
            stmt = {R.XMM0: "wide0", R.XMM1: "wide1", R.XMM2: "wide2"}[i.op0_register] + " = {};"
        elif op == M.VZEROUPPER:
            stmt = " ".join(f"memset({v}.data()+16, 0, 16);" for v in wide.values()) if has_wide else ";"
        elif op == M.VMOVDQU and i.op1_kind == K.MEMORY:
            stmt = f"{xmm[i.op0_register]} = load<__m128i>({address()});"
        elif op == M.VPSRLDQ:
            stmt = f"{xmm[i.op0_register]} = _mm_srli_si128({xmm[i.op1_register]}, {i.immediate(2)});"
        elif op == M.VPADDD:
            stmt = f"{xmm[i.op0_register]} = _mm_add_epi32({xmm[i.op1_register]}, {xmm[i.op2_register]});"
        elif op == M.VMOVD and i.op1_register in xmm:
            stmt = write(f"_mm_cvtsi128_si32({xmm[i.op1_register]})")
        elif op in (M.MOVDQU, M.VMOVDQU):
            if i.op1_kind == K.MEMORY:
                stmt = f"{xmm[i.op0_register]} = _mm_loadu_si128(reinterpret_cast<const __m128i*>({address()}));"
            elif i.op0_kind == K.MEMORY:
                stmt = f"_mm_storeu_si128(reinterpret_cast<__m128i*>({address()}), {xmm[i.op1_register]});"
            else:
                stmt = f"{xmm[i.op0_register]} = {xmm[i.op1_register]};"
        elif op in (M.AESENC, M.VAESENC):
            src1 = xmm[i.op1_register] if op == M.VAESENC else xmm[i.op0_register]
            src2 = xmm[i.op2_register] if op == M.VAESENC else xmm[i.op1_register]
            stmt = f"{xmm[i.op0_register]} = _mm_aesenc_si128({src1}, {src2});"
        elif op in (M.AESENCLAST, M.VAESENCLAST):
            src1 = xmm[i.op1_register] if op == M.VAESENCLAST else xmm[i.op0_register]
            src2 = xmm[i.op2_register] if op == M.VAESENCLAST else xmm[i.op1_register]
            stmt = f"{xmm[i.op0_register]} = _mm_aesenclast_si128({src1}, {src2});"
        elif op in (M.AESDEC, M.VAESDEC):
            src1 = xmm[i.op1_register] if op == M.VAESDEC else xmm[i.op0_register]
            src2 = xmm[i.op2_register] if op == M.VAESDEC else xmm[i.op1_register]
            stmt = f"{xmm[i.op0_register]} = _mm_aesdec_si128({src1}, {src2});"
        elif op in (M.AESDECLAST, M.VAESDECLAST):
            src1 = xmm[i.op1_register] if op == M.VAESDECLAST else xmm[i.op0_register]
            src2 = xmm[i.op2_register] if op == M.VAESDECLAST else xmm[i.op1_register]
            stmt = f"{xmm[i.op0_register]} = _mm_aesdeclast_si128({src1}, {src2});"
        elif op in (M.AESIMC, M.VAESIMC):
            src = xmm[i.op1_register]
            stmt = f"{xmm[i.op0_register]} = _mm_aesimc_si128({src});"
        elif op in (M.AESKEYGENASSIST, M.VAESKEYGENASSIST):
            src = xmm[i.op1_register]
            imm = i.immediate(2)
            stmt = f"{xmm[i.op0_register]} = _mm_aeskeygenassist_si128({src}, {imm});"
        elif op in (M.PCLMULQDQ, M.VPCLMULQDQ):
            src1 = xmm[i.op1_register] if op == M.VPCLMULQDQ else xmm[i.op0_register]
            src2 = xmm[i.op2_register] if op == M.VPCLMULQDQ else xmm[i.op1_register]
            imm = i.immediate(3) if op == M.VPCLMULQDQ else i.immediate(2)
            stmt = f"{xmm[i.op0_register]} = _mm_clmulepi64_si128({src1}, {src2}, {imm});"
        elif op == M.SHA1MSG1:
            stmt = f"{xmm[i.op0_register]} = _mm_sha1msg1_epu32({xmm[i.op0_register]}, {xmm[i.op1_register]});"
        elif op == M.SHA1MSG2:
            stmt = f"{xmm[i.op0_register]} = _mm_sha1msg2_epu32({xmm[i.op0_register]}, {xmm[i.op1_register]});"
        elif op == M.SHA1NEXTE:
            stmt = f"{xmm[i.op0_register]} = _mm_sha1nexte_epu32({xmm[i.op0_register]}, {xmm[i.op1_register]});"
        elif op == M.SHA1RNDS4:
            stmt = f"{xmm[i.op0_register]} = _mm_sha1rnds4_epu32({xmm[i.op0_register]}, {xmm[i.op1_register]}, {i.immediate(2)});"
        elif op == M.SHA256MSG1:
            stmt = f"{xmm[i.op0_register]} = _mm_sha256msg1_epu32({xmm[i.op0_register]}, {xmm[i.op1_register]});"
        elif op == M.SHA256MSG2:
            stmt = f"{xmm[i.op0_register]} = _mm_sha256msg2_epu32({xmm[i.op0_register]}, {xmm[i.op1_register]});"
        elif op == M.SHA256RNDS2:
            stmt = f"{xmm[i.op0_register]} = _mm_sha256rnds2_epu32({xmm[i.op0_register]}, {xmm[i.op1_register]}, xmm0);"
        elif op == M.NOP or (op == M.XCHG and i.op0_register == i.op1_register == R.AX):
            stmt = ";"
        elif op == M.CLC:
            stmt = "carry = false;"
        elif op == M.STC:
            stmt = "carry = true;"
        elif op == M.CMC:
            stmt = "carry = !carry;"
        elif op in (M.CLD, M.STD):
            stmt = ";"
        elif op in (M.ROL, M.ROR) and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            count = f"static_cast<unsigned>({operand(1)}) & {bits - 1}u"
            if op == M.ROL:
                expr = f"count == 0u ? a : static_cast<{width}>((a << count) | (a >> ({bits}u - count)))"
                up_carry = "if (count != 0u) carry = (v & 1u) != 0;"
            else:
                expr = f"count == 0u ? a : static_cast<{width}>((a >> count) | (a << ({bits}u - count)))"
                up_carry = f"if (count != 0u) carry = ((v >> {bits - 1}u) & 1u) != 0;"
            stmt = (f"{{ const {width} a = {operand(0)}; const unsigned count = {count}; "
                    f"const {width} v = {expr}; {up_carry} {write('v')} }}")
        elif op in (M.SHLD, M.SHRD) and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width, bits = UINT[size], 8 * size
            count = f"static_cast<unsigned>({operand(2)}) & {bits - 1}u"
            if op == M.SHLD:
                expr = f"count == 0u ? a : static_cast<{width}>((a << count) | (b >> ({bits}u - count)))"
            else:
                expr = f"count == 0u ? a : static_cast<{width}>((a >> count) | (b << ({bits}u - count)))"
            stmt = (f"{{ const {width} a = {operand(0)}, b = static_cast<{width}>({operand(1)}); "
                    f"const unsigned count = {count}; const {width} v = {expr}; {write('v')} }}")
        elif op == M.XCHG and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width = UINT[size]
            stmt = (f"{{ const {width} tmp = {operand(0)}; "
                    f"{reg(i.op0_register)} = static_cast<{width}>({operand(1)}); "
                    f"{reg(i.op1_register)} = tmp; }}")
        elif op == M.XADD and RegisterExt.size(i.op0_register) in (4, 8):
            size = RegisterExt.size(i.op0_register)
            width = UINT[size]
            stmt = (f"{{ const {width} a = {operand(0)}, b = static_cast<{width}>({operand(1)}); "
                    f"const {width} sum = a + b; "
                    f"{reg(i.op0_register)} = sum; {reg(i.op1_register)} = a; }}")
        elif op in (M.SETE, M.SETNE, M.SETB, M.SETAE, M.SETA, M.SETBE, M.SETG, M.SETGE, M.SETL, M.SETLE, M.SETO, M.SETNO, M.SETS, M.SETNS, M.SETP, M.SETNP):
            c = {
                M.SETE: "zero", M.SETNE: "!zero", M.SETB: "carry", M.SETAE: "!carry",
                M.SETA: "!carry && !zero", M.SETBE: "carry || zero", M.SETG: "!carry && !zero", M.SETGE: "!carry",
                M.SETL: "carry", M.SETLE: "carry || zero", M.SETO: "overflow", M.SETNO: "!overflow",
                M.SETS: "false", M.SETNS: "true", M.SETP: "false", M.SETNP: "true",
            }[op]
            stmt = write(f"static_cast<uint8_t>(({c}) ? 1 : 0)")
        elif op == M.CALL:
            stmt = calls[i.ip]
        elif op == M.RET:
            stmt = "return rax;"
        else:
            raise ValueError(f"unsupported query operation at {i.ip:#x}: {i}")
        lines.append(f"block_{i.ip:x}: {stmt}")
        if (op not in (M.RET, M.JMP) and
                (index + 1 == len(body) or body[index + 1].ip != i.next_ip)):
            if i.next_ip not in allowed:
                raise ValueError(f"unbound fallthrough at {i.ip:#x}")
            lines.append(f"goto block_{i.next_ip:x};")
    lines.extend(f"block_{target:x}: {statement}" for target, statement in exits.items())
    return "\n".join("    " + line for line in lines)


def leaf(pe, address):
    for i in Decoder(64, image_bytes(pe, address, 32, executable=True), ip=address):
        if i.mnemonic == M.RET:
            return region(pe, address, i.next_ip)
    raise ValueError("unsupported provider predicate")


def checked_image(path, digest):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"unrecognized {path.name} version-query profile")
    return pefile.PE(data=data, fast_load=True)


def export_body(pe, name, slices):
    owned = function_ranges(pe, export_rva(pe, name))
    if not all(any(lo <= a < b <= hi for lo, hi in owned) for a, b in slices):
        raise ValueError(f"slice outside exported function {name}")
    return [ins for a, b in slices for ins in region(pe, a, b)]


def generate(loader, upscaler):
    # These two build-specific profiles specialize the entry guards to (nullptr, type 4).
    # Recover the record from initializer stores; the on-disk registry is zero-filled.
    with checked_image(upscaler, UPSCALER) as pe:
        init = {i.ip: i for i in region(pe, 0x10bb, 0x1144)}
        record = init[0x1130].ip_rel_memory_address
        fields = {init[addr].ip_rel_memory_address-record: value for addr, value in [
            (0x10d0, init[0x10bb].immediate(1)), (0x10e5, init[0x10e5].immediate(1)),
            (0x10f0, init[0x10de].ip_rel_memory_address)]}
        name = pe.get_string_at_rva(fields[32], 128)
        if not name or not all(32 <= c < 127 for c in name):
            raise ValueError("invalid provider version name")
        vtable = init[0x1105].ip_rel_memory_address
        predicates = []
        for slot, symbol in ((1, "supports_effect"), (2, "supports_device")):
            addr = pe.get_qword_at_rva(vtable + 8*slot) - pe.OPTIONAL_HEADER.ImageBase
            code = lower(leaf(pe, addr), ["rcx = self; rdx = input;"], {}, {}, {})
            predicates.append(f"static word {symbol}(word self, word input) {{\n{code}\n}}")
        globals_ = {init[0x1137].ip_rel_memory_address: "reinterpret_cast<word>(registry)",
                    record: "reinterpret_cast<word>(registry + 1)"}
        # The actual registry occupies one pointer between the decoded start and end.
        if record - init[0x1137].ip_rel_memory_address != 8:
            raise ValueError("unexpected provider registry size")
        calls = {site: f"rax = {fn}(rcx, rdx);" for site, fn in [
            (0x1595, "supports_effect"), (0x15a5, "supports_device"),
            (0x161a, "supports_effect"), (0x162a, "supports_device")]}
        provider = lower(export_body(pe, "ffxQuery", [(0x152b, 0x164a)]),
                         ["r15 = reinterpret_cast<word>(query); rdi = 0;"], globals_, calls,
                         {0x1999: "return static_cast<uint32_t>(rax);", 0x164a: "return 6;"})
    with checked_image(loader, LOADER) as pe:
        # The desktop binding supplies the translated upscaler; frame generation is absent.
        slots = {0x4088: "reinterpret_cast<word>(&present)", 0x40c0: "reinterpret_cast<word>(&absent)",
                 0x40a8: "reinterpret_cast<word>(&present)", 0x40e0: "reinterpret_cast<word>(&absent)"}
        caller = lower(export_body(pe, "ffxQuery", [(0x144b, 0x14b2), (0x14c2, 0x14d5)]),
                       ["rbx = reinterpret_cast<word>(query); rdi = reinterpret_cast<word>(&query->effect);"],
                       slots, {0x1456: "/* selected modules are bound offline */",
                               0x14ac: "rax = provider_versions(reinterpret_cast<Query*>(rdx));"},
                       {0x14b2: "return static_cast<uint32_t>(rax);", 0x150f: "return static_cast<uint32_t>(rax);",
                        0x14e5: "return 6;", 0x14d5: "return static_cast<uint32_t>(rax);"})
    chars = ", ".join(str(b) for b in name + b"\0")
    return HEADER + "\n".join(predicates) + f"""
static const char version_name[] = {{{chars}}};
static const word present = 1, absent = 0;
static const word entry[] = {{0, 0, {fields[16]}ull, {fields[24]}ull, reinterpret_cast<word>(version_name)}};
static const word registry[] = {{reinterpret_cast<word>(entry)}};
static uint32_t provider_versions(Query* query) {{
{provider}
}}
extern "C" __declspec(dllexport) uint32_t query_versions(Query* query) {{
    if (!query || query->type != 4) return 6;
{caller}
}}
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("loader", "upscaler", "output"):
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    if args.output.suffix.lower() != ".cpp" or args.output.resolve() in (args.loader.resolve(), args.upscaler.resolve()):
        parser.error("choose a distinct .cpp output")
    args.output.write_text(generate(args.loader, args.upscaler), encoding="ascii")
