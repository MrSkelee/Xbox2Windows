"""Compare native and translated immediate shifts whose masked count is zero."""
import ctypes
from pathlib import Path
import sys

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64
MASK32 = 0xffffffff
UNARY = {
    "shl_zero": lambda x: x & MASK32,
    "shr_zero": lambda x: x & MASK32,
    "sar_zero": lambda x: x & MASK32,
    "shl_masked32": lambda x: x & MASK32,
    "shl_masked64": lambda x: x,
    "shl_three": lambda x: (x << 3) & MASK32,
    "sal_three": lambda x: (x << 3) & MASK32,
    # The 32-bit source is signed: 0x80000000 >> 3 is 0xf0000000.
    "sar_three": lambda x: (((x & MASK32) ^ 0x80000000) - 0x80000000 >> 3) & MASK32,
}
VALUES = (0, 1, 0x80000000, 0xffffffff, 0x12345678, 0xdeadbeef12345678, 0xffffffff00000000,
          0x8000000000000001, 0xffffffffffffffff)


def emit(image, output):
    parts = [INTEGER_HEADER]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in (*UNARY, "flags_zero", "carry_zero"):
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            code = lower(region(pe, *bounds), ["rcx = a; rdx = b; r8 = c;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word c) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def functions(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in (*UNARY, "flags_zero", "carry_zero"):
        getattr(lib, name).argtypes, getattr(lib, name).restype = [U64, U64, U64], U64
    return lib


def check(native_path, lifted_path):
    images = (("native", functions(native_path)), ("lifted", functions(lifted_path)))
    cases = 0
    for label, lib in images:
        for name, reference in UNARY.items():
            for value in VALUES:
                got, want = getattr(lib, name)(value, 0, 0), reference(value)
                if got != want:
                    raise AssertionError(f"{label} {name}({value:#x}) = {got:#x}, expected {want:#x}")
                cases += 1
        # A zero low half in R8 would make a recomputed ZF true; SETE must still see the compare.
        for a, b in ((5, 5), (5, 6), (0, 0x100000000), (0xffffffff, 0x7fffffff)):
            for initial in (0, 0xdeadbeef00000000, 0xdeadbeef123456ff):
                got = lib.flags_zero(a, b, initial)
                want = (initial & 0xffffff00 | ((a & MASK32) == (b & MASK32))) & MASK32
                if got != want:
                    raise AssertionError(f"{label} flags_zero({a:#x}, {b:#x}, {initial:#x}) = {got:#x}, "
                                         f"expected {want:#x}")
                cases += 1
        # The zero-count shift keeps the compare's CF: 1 when ECX < EDX unsigned.
        for a, b in ((5, 5), (5, 6), (6, 5), (0, 0xffffffff), (0x80000000, 0x7fffffff)):
            got, want = lib.carry_zero(a, b, 0xdeadbeef), int((a & MASK32) < (b & MASK32))
            if got != want:
                raise AssertionError(f"{label} carry_zero({a:#x}, {b:#x}) = {got:#x}, expected {want:#x}")
            cases += 1
    print(f"{cases} native and translated zero-count shift cases matched the reference")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
