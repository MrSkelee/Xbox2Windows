"""Compare native and translated BMI2 and ADX bit-manipulation instructions (32-bit and 64-bit)."""
import ctypes
from pathlib import Path
import sys

import pefile
from iced_x86 import Decoder

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff

BINARY_EXPORTS = (
    "bzhi32", "bzhi64",
    "sarx32", "sarx64",
    "shlx32", "shlx64",
    "shrx32", "shrx64",
    "mulx32", "mulx64",
    "pext32", "pext64",
    "pdep32", "pdep64",
    "adcx32", "adcx64",
    "adox32", "adox64",
)
UNARY_EXPORTS = ("rorx32", "rorx64")


def emit(image, output):
    parts = [
        "#include <intrin.h>\n",
        INTEGER_HEADER,
        'extern "C" __declspec(dllexport) int host_has_bmi2() {\n'
        "    int regs[4]{};\n"
        "    __cpuid(regs, 0);\n"
        "    if (regs[0] < 7) return 0;\n"
        "    __cpuidex(regs, 7, 0);\n"
        "    return (regs[1] & (1 << 8)) != 0;\n"
        "}\n",
    ]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in BINARY_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = flags_out;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word flags_out) {{\n{code}\n}}\n')
        for name in UNARY_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = flags_out;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word flags_out) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in BINARY_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, U64, ctypes.POINTER(U64)], U64
    for name in UNARY_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, ctypes.POINTER(U64)], U64
    return lib


def ref_bzhi(a, idx, bits):
    mask_width = (1 << bits) - 1
    a &= mask_width
    idx &= 0xff
    if idx < bits:
        mask = (1 << idx) - 1 if idx > 0 else 0
        v = a & mask
        cf = 0
    else:
        v = a
        cf = 1
    zf = 1 if v == 0 else 0
    return v, (cf << 1) | zf


def ref_rorx(a, count, bits):
    mask = (1 << bits) - 1
    a &= mask
    c = count & (bits - 1)
    if c == 0:
        v = a
    else:
        v = ((a >> c) | (a << (bits - c))) & mask
    return v, 2


def ref_sarx(a, count, bits):
    mask = (1 << bits) - 1
    a &= mask
    c = count & (bits - 1)
    sign_bit = 1 << (bits - 1)
    signed_val = (a ^ sign_bit) - sign_bit
    v = (signed_val >> c) & mask
    return v, 2


def ref_shlx(a, count, bits):
    mask = (1 << bits) - 1
    a &= mask
    c = count & (bits - 1)
    v = (a << c) & mask
    return v, 2


def ref_shrx(a, count, bits):
    mask = (1 << bits) - 1
    a &= mask
    c = count & (bits - 1)
    v = (a >> c) & mask
    return v, 2


def ref_mulx(a, b, bits):
    mask = (1 << bits) - 1
    a &= mask
    b &= mask
    prod = a * b
    return (prod & mask), ((prod >> bits) & mask)


def ref_pext(a, m, bits):
    mask_w = (1 << bits) - 1
    a &= mask_w
    m &= mask_w
    res = 0
    bb = 1
    for i in range(bits):
        if (m >> i) & 1:
            if (a >> i) & 1:
                res |= bb
            bb <<= 1
    return res, 2


def ref_pdep(a, m, bits):
    mask_w = (1 << bits) - 1
    a &= mask_w
    m &= mask_w
    res = 0
    bb = 1
    for i in range(bits):
        if (m >> i) & 1:
            if (a & bb):
                res |= (1 << i)
            bb <<= 1
    return res, 2


def ref_adcx(a, b, bits):
    mask_w = (1 << bits) - 1
    a &= mask_w
    b &= mask_w
    total = a + b + 1
    v = total & mask_w
    cf = 1 if total > mask_w else 0
    return v, (cf << 1)


def ref_adox(a, b, bits):
    mask_w = (1 << bits) - 1
    a &= mask_w
    b &= mask_w
    total = a + b + 1
    v = total & mask_w
    of = 1 if total > mask_w else 0
    return v, (of << 2)


def check(native_path, lifted_path):
    lifted = load_lib(lifted_path)
    lifted.host_has_bmi2.argtypes, lifted.host_has_bmi2.restype = [], ctypes.c_int
    if not lifted.host_has_bmi2():
        print("Host CPU lacks BMI2 (CPUID leaf 7 EBX bit 8); skipping native differential check.")
        sys.exit(77)
    native = load_lib(native_path)
    flag_slot = U64(0)
    values = (
        0, 1, 2, 3, 0x80, 0x100, 0x55aa55aa, 0x7fffffff, 0x80000000, 0xffffffff,
        0x100000000, 0xdeadbeef00000000, 0xdeadbeef00000001, 0x8000000000000000,
        0x7fffffffffffffff, 0xffffffffffffffff, 0x0123456789abcdef,
    )
    shift_counts = (
        0, 1, 2, 5, 13, 27, 31, 32, 33, 63, 64, 65, 0x7f, 0x80, 0xff, 0x101,
    )

    binary_checks = 0

    # 1. BZHI checks
    for name, bits in (("bzhi32", 32), ("bzhi64", 64)):
        for a in values:
            for idx in shift_counts:
                want_v, want_f = ref_bzhi(a, idx, bits)
                for lib, label in ((native, "native"), (lifted, "lifted")):
                    flag_slot.value = 0xdeadbeef
                    got_v = getattr(lib, name)(a, idx, ctypes.byref(flag_slot))
                    if (got_v, flag_slot.value) != (want_v, want_f):
                        raise AssertionError(
                            f"{label} {name}({a:#x}, {idx:#x}) = ({got_v:#x}, {flag_slot.value:#x}), "
                            f"expected ({want_v:#x}, {want_f:#x})"
                        )
                binary_checks += 1

    # 2. SARX, SHLX, SHRX checks
    shift_tests = (
        ("sarx32", ref_sarx, 32),
        ("sarx64", ref_sarx, 64),
        ("shlx32", ref_shlx, 32),
        ("shlx64", ref_shlx, 64),
        ("shrx32", ref_shrx, 32),
        ("shrx64", ref_shrx, 64),
    )
    for name, ref_fn, bits in shift_tests:
        for a in values:
            for count in shift_counts:
                want_v, want_f = ref_fn(a, count, bits)
                for lib, label in ((native, "native"), (lifted, "lifted")):
                    flag_slot.value = 0xdeadbeef
                    got_v = getattr(lib, name)(a, count, ctypes.byref(flag_slot))
                    if (got_v, flag_slot.value) != (want_v, want_f):
                        raise AssertionError(
                            f"{label} {name}({a:#x}, {count:#x}) = ({got_v:#x}, {flag_slot.value:#x}), "
                            f"expected ({want_v:#x}, {want_f:#x})"
                        )
                binary_checks += 1

    # 3. MULX checks
    for name, bits in (("mulx32", 32), ("mulx64", 64)):
        for a in values:
            for b in values:
                want_lo, want_hi = ref_mulx(a, b, bits)
                for lib, label in ((native, "native"), (lifted, "lifted")):
                    flag_slot.value = 0xdeadbeef
                    got_lo = getattr(lib, name)(a, b, ctypes.byref(flag_slot))
                    got_hi = flag_slot.value
                    if (got_lo, got_hi) != (want_lo, want_hi):
                        raise AssertionError(
                            f"{label} {name}({a:#x}, {b:#x}) = (lo={got_lo:#x}, hi={got_hi:#x}), "
                            f"expected (lo={want_lo:#x}, hi={want_hi:#x})"
                        )
                binary_checks += 1

    # 4. PEXT & PDEP checks
    for name, ref_fn, bits in (
        ("pext32", ref_pext, 32),
        ("pext64", ref_pext, 64),
        ("pdep32", ref_pdep, 32),
        ("pdep64", ref_pdep, 64),
    ):
        for a in values:
            for m in values:
                want_v, want_f = ref_fn(a, m, bits)
                for lib, label in ((native, "native"), (lifted, "lifted")):
                    flag_slot.value = 0xdeadbeef
                    got_v = getattr(lib, name)(a, m, ctypes.byref(flag_slot))
                    if (got_v, flag_slot.value) != (want_v, want_f):
                        raise AssertionError(
                            f"{label} {name}({a:#x}, {m:#x}) = ({got_v:#x}, {flag_slot.value:#x}), "
                            f"expected ({want_v:#x}, {want_f:#x})"
                        )
                binary_checks += 1

    # 5. ADCX & ADOX checks
    for name, ref_fn, bits in (
        ("adcx32", ref_adcx, 32),
        ("adcx64", ref_adcx, 64),
        ("adox32", ref_adox, 32),
        ("adox64", ref_adox, 64),
    ):
        for a in values:
            for b in values:
                want_v, want_f = ref_fn(a, b, bits)
                for lib, label in ((native, "native"), (lifted, "lifted")):
                    flag_slot.value = 0xdeadbeef
                    got_v = getattr(lib, name)(a, b, ctypes.byref(flag_slot))
                    if (got_v, flag_slot.value) != (want_v, want_f):
                        raise AssertionError(
                            f"{label} {name}({a:#x}, {b:#x}) = ({got_v:#x}, {flag_slot.value:#x}), "
                            f"expected ({want_v:#x}, {want_f:#x})"
                        )
                binary_checks += 1

    # 6. RORX checks
    unary_checks = 0
    for name, count, bits in (("rorx32", 13, 32), ("rorx64", 27, 64)):
        for a in values:
            want_v, want_f = ref_rorx(a, count, bits)
            for lib, label in ((native, "native"), (lifted, "lifted")):
                flag_slot.value = 0xdeadbeef
                got_v = getattr(lib, name)(a, ctypes.byref(flag_slot))
                if (got_v, flag_slot.value) != (want_v, want_f):
                    raise AssertionError(
                        f"{label} {name}({a:#x}) = ({got_v:#x}, {flag_slot.value:#x}), "
                        f"expected ({want_v:#x}, {want_f:#x})"
                    )
            unary_checks += 1

    print(f"{binary_checks} binary and {unary_checks} unary BMI2/ADX cases (values + flags) matched native and translated DLLs")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "emit":
        emit(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "check":
        check(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        print("usage: bmi2.py emit <pe> <out.cpp> | check <native.dll> <lifted.dll>", file=sys.stderr)
        sys.exit(2)
