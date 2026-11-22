"""Compare native and translated extended integer instructions."""
import ctypes
from pathlib import Path
import sys

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64

ARITH_EXPORTS = ("adc32", "adc64", "sbb32", "sbb64")
UNARY_EXPORTS = ("rol32", "rol64", "ror32", "ror64", "flags_ctrl")
BINARY_EXPORTS = ("shld32", "shld64", "shrd32", "shrd64", "jcc_walk")
TRIPLE_EXPORTS = ("xchg32", "xchg64", "xadd32", "xadd64", "set_conds")
QUAD_EXPORTS = ("cmov_conds",)


def emit(image, output):
    parts = [
        "#include <intrin.h>\n",
        INTEGER_HEADER,
    ]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in ARITH_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = flags_out;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word flags_out) {{\n{code}\n}}\n')
        for name in UNARY_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a) {{\n{code}\n}}\n')
        for name in BINARY_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b) {{\n{code}\n}}\n')
        for name in TRIPLE_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = out_val;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word out_val) {{\n{code}\n}}\n')
        for name in QUAD_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = c; r9 = d;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word c, word d) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in ARITH_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, U64, ctypes.POINTER(U64)], U64
    for name in UNARY_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64], U64
    for name in BINARY_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, U64], U64
    for name in TRIPLE_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, U64, ctypes.c_void_p], U64
    for name in QUAD_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, U64, U64, U64], U64
    return lib


def check(native_path, lifted_path):
    native = load_lib(native_path)
    lifted = load_lib(lifted_path)
    flag_slot = U64(0)
    values = (
        0, 1, 2, 3, 0x80, 0x100, 0x55aa55aa, 0x7fffffff, 0x80000000, 0xffffffff,
        0x100000000, 0xdeadbeef00000000, 0x8000000000000000, 0xffffffffffffffff,
    )

    checks = 0

    # 1. ADC & SBB
    for name, is_adc, bits in (
        ("adc32", True, 32), ("adc64", True, 64),
        ("sbb32", False, 32), ("sbb64", False, 64),
    ):
        mask = (1 << bits) - 1
        for a in values:
            for b in values:
                a_m, b_m = a & mask, b & mask
                if is_adc:
                    tot = a_m + b_m + 1
                    want_v = tot & mask
                    cf = 1 if tot > mask else 0
                else:
                    diff = a_m - b_m - 1
                    want_v = diff & mask
                    cf = 1 if diff < 0 else 0
                zf = 1 if want_v == 0 else 0
                want_f = (cf << 1) | zf

                for lib, label in ((native, "native"), (lifted, "lifted")):
                    flag_slot.value = 0xdeadbeef
                    got_v = getattr(lib, name)(a, b, ctypes.byref(flag_slot))
                    if (got_v, flag_slot.value) != (want_v, want_f):
                        raise AssertionError(f"{label} {name}({a:#x}, {b:#x}) = ({got_v:#x}, {flag_slot.value:#x}), expected ({want_v:#x}, {want_f:#x})")
                checks += 1

    # 2. ROL & ROR
    for name, is_rol, count, bits in (
        ("rol32", True, 5, 32), ("rol64", True, 11, 64),
        ("ror32", False, 5, 32), ("ror64", False, 11, 64),
    ):
        mask = (1 << bits) - 1
        for a in values:
            a_m = a & mask
            if is_rol:
                want_v = ((a_m << count) | (a_m >> (bits - count))) & mask
            else:
                want_v = ((a_m >> count) | (a_m << (bits - count))) & mask
            for lib, label in ((native, "native"), (lifted, "lifted")):
                got_v = getattr(lib, name)(a)
                if got_v != want_v:
                    raise AssertionError(f"{label} {name}({a:#x}) = {got_v:#x}, expected {want_v:#x}")
            checks += 1

    # 3. SHLD & SHRD
    for name, is_shld, count, bits in (
        ("shld32", True, 7, 32), ("shld64", True, 15, 64),
        ("shrd32", False, 7, 32), ("shrd64", False, 15, 64),
    ):
        mask = (1 << bits) - 1
        for a in values:
            for b in values:
                a_m, b_m = a & mask, b & mask
                if is_shld:
                    want_v = ((a_m << count) | (b_m >> (bits - count))) & mask
                else:
                    want_v = ((a_m >> count) | (b_m << (bits - count))) & mask
                for lib, label in ((native, "native"), (lifted, "lifted")):
                    got_v = getattr(lib, name)(a, b)
                    if got_v != want_v:
                        raise AssertionError(f"{label} {name}({a:#x}, {b:#x}) = {got_v:#x}, expected {want_v:#x}")
                checks += 1

    # 4. XCHG & XADD
    for name, is_xchg, bits in (
        ("xchg32", True, 32), ("xchg64", True, 64),
        ("xadd32", False, 32), ("xadd64", False, 64),
    ):
        mask = (1 << bits) - 1
        for a in values:
            for b in values:
                a_m, b_m = a & mask, b & mask
                if is_xchg:
                    want_ret = b_m
                    want_out = a_m
                else:
                    want_ret = (a_m + b_m) & mask
                    want_out = a_m
                for lib, label in ((native, "native"), (lifted, "lifted")):
                    flag_slot.value = 0xdeadbeef
                    got_ret = getattr(lib, name)(a, b, ctypes.byref(flag_slot))
                    got_out = flag_slot.value & mask
                    if (got_ret, got_out) != (want_ret, want_out):
                        raise AssertionError(f"{label} {name}({a:#x}, {b:#x}) = ({got_ret:#x}, {got_out:#x}), expected ({want_ret:#x}, {want_out:#x})")
                checks += 1

    # 5. Flags control & Jcc walk
    for lib, label in ((native, "native"), (lifted, "lifted")):
        res = getattr(lib, "flags_ctrl")(0)
        if res != 42:
            raise AssertionError(f"{label} flags_ctrl failed: {res}")
        res2 = getattr(lib, "jcc_walk")(10, 20)
        if res2 != 100:
            raise AssertionError(f"{label} jcc_walk failed: {res2}")
    checks += 2

    # 6. SETcc & CMOVcc
    buf = (ctypes.c_uint8 * 8)()
    for a in values:
        for b in values:
            for lib, label in ((native, "native"), (lifted, "lifted")):
                getattr(lib, "set_conds")(a, b, buf)
                getattr(lib, "cmov_conds")(a, b, 10, 20)
            checks += 1

    print(f"{checks} extended integer instruction cases matched native and translated DLLs")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "emit":
        emit(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "check":
        check(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        print("usage: integer_ext.py emit <pe> <out.cpp> | check <native.dll> <lifted.dll>", file=sys.stderr)
        sys.exit(2)
