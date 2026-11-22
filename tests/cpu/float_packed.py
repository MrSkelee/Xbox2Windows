"""Compare native and translated packed and scalar SSE/SSE2/AVX floating point instructions."""
import ctypes
from pathlib import Path
import struct
import sys

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64

EXPORTS = (
    # Legacy SSE
    "addps", "subps", "mulps", "divps", "maxps", "minps", "sqrtps",
    "andps", "andnps", "orps", "xorps",
    "sqrtss", "maxss", "minss",
    # Legacy SSE2
    "addpd", "subpd", "mulpd", "divpd", "maxpd", "minpd", "sqrtpd",
    "andpd", "andnpd", "orpd", "xorpd",
    "sqrtsd", "maxsd", "minsd",
    # VEX AVX
    "vaddps", "vsubps", "vmulps", "vdivps", "vmaxps", "vminps", "vsqrtps",
    "vandps", "vandnps", "vorps", "vxorps",
    "vaddpd", "vsubpd", "vmulpd", "vdivpd", "vmaxpd", "vminpd", "vsqrtpd",
    "vandpd", "vandnpd", "vorpd", "vxorpd",
    "vsqrtss", "vmaxss", "vminss",
    "vsqrtsd", "vmaxsd", "vminsd",
)
EXPORT_NAMES = tuple(f"{op}_op" for op in EXPORTS)


def emit(image, output):
    parts = [INTEGER_HEADER]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in EXPORT_NAMES:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = dst;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word dst) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in EXPORT_NAMES:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], U64
    return lib


def check(native_path, lifted_path):
    native, lifted = load_lib(native_path), load_lib(lifted_path)
    out_n = (ctypes.c_uint8 * 16)()
    out_l = (ctypes.c_uint8 * 16)()

    # Test patterns:
    # 4 floats (16 bytes)
    float_patterns = [
        struct.pack("<4f", 1.0, 2.0, 3.0, 4.0),
        struct.pack("<4f", 0.5, -0.5, 2.0, -2.0),
        struct.pack("<4f", 0.0, -0.0, 100.0, -100.0),
        struct.pack("<4f", 1e-20, 1e20, 1.5, 3.75),
        struct.pack("<4f", 9.0, 16.0, 25.0, 100.0),
        struct.pack("<4I", 0x7f800000, 0xff800000, 0x7fc00000, 0xffc00000),  # inf, -inf, qnan, -qnan
        struct.pack("<4I", 0x7f800001, 0xffa00000, 0x00000001, 0x80000001),  # snans, denormals
        struct.pack("<4I", 0xaaaaaaaa, 0x55555555, 0x0f0f0f0f, 0xf0f0f0f0),  # bitwise patterns
    ]

    total_comparisons = 0
    for p1 in float_patterns:
        for p2 in float_patterns:
            b1 = ctypes.create_string_buffer(p1, 16)
            b2 = ctypes.create_string_buffer(p2, 16)
            for name in EXPORT_NAMES:
                ctypes.memset(out_n, 0xaa, 16)
                ctypes.memset(out_l, 0x55, 16)
                getattr(native, name)(b1, b2, out_n)
                getattr(lifted, name)(b1, b2, out_l)
                if bytes(out_n) != bytes(out_l):
                    raise AssertionError(f"{name}: lifted {bytes(out_l).hex()} != native {bytes(out_n).hex()}")
                total_comparisons += 1

    print(f"{total_comparisons} comparisons matched bit-for-bit across all 56 packed and scalar float/double instructions")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
