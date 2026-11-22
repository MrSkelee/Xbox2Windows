"""Compare native and translated 128-bit SSSE3 integer instructions."""
import ctypes
from pathlib import Path
import struct
import sys

import pefile
from iced_x86 import Decoder

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64
UNARY = ("pabsb_op", "pabsw_op", "pabsd_op")
BINARY = ("psignb_op", "psignw_op", "psignd_op", "pshufb_op", "palignr_op", "palignr_hi",
          "phaddw_op", "phaddd_op", "phsubw_op", "phsubd_op", "phaddsw_op", "phsubsw_op")


def emit(image, output):
    parts = [
        "#include <intrin.h>\n",
        INTEGER_HEADER,
        'extern "C" __declspec(dllexport) int host_has_ssse3() {\n'
        "    int regs[4]{};\n"
        "    __cpuid(regs, 1);\n"
        "    return (regs[2] & (1 << 9)) != 0;\n"
        "}\n",
    ]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in UNARY:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = src; rdx = dst;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word src, word dst) {{\n{code}\n}}\n')
        for name in BINARY:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = dst;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word dst) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in UNARY:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p], U64
    for name in BINARY:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], U64
    return lib


def check(native_path, lifted_path):
    lifted = load_lib(lifted_path)
    lifted.host_has_ssse3.argtypes, lifted.host_has_ssse3.restype = [], ctypes.c_int
    if not lifted.host_has_ssse3():
        print("Host CPU lacks SSSE3 (CPUID leaf 1 ECX bit 9); skipping native differential check.")
        sys.exit(77)
    native = load_lib(native_path)
    out_n = (ctypes.c_uint8 * 16)()
    out_l = (ctypes.c_uint8 * 16)()

    # Include INT_MIN, INT_MAX, -1, 0, +1, and saturation edge cases.
    a_b = struct.pack("<16b", -128, -127, -1, 0, 1, 127, -42, 42, -100, 100, -5, 5, -1, -128, 0, 64)
    b_b = struct.pack("<16b", -1, 0, 1, -128, 127, -1, 0, 1, 15, -128, 3, -4, 0x7f, -1, 0, 12)
    a_w = struct.pack("<8h", -32768, -32767, -1, 0, 1, 32767, 20000, 20000)
    b_w = struct.pack("<8h", -20000, -20000, 32767, -32768, 100, -100, 0, -1)
    a_d = struct.pack("<4i", -2147483648, -1, 0, 2147483647)
    b_d = struct.pack("<4i", -1, 0, 1, -2147483648)
    shuf_mask = bytes([0, 15, 0x80, 0xff, 7, 3, 0x12, 0x85, 14, 1, 2, 0x90, 15, 0, 8, 9])

    cases = 0
    for name, src in (("pabsb_op", a_b), ("pabsw_op", a_w), ("pabsd_op", a_d)):
        buf = ctypes.create_string_buffer(src, 16)
        ctypes.memset(out_n, 0xaa, 16)
        ctypes.memset(out_l, 0x55, 16)
        getattr(native, name)(buf, out_n)
        getattr(lifted, name)(buf, out_l)
        if bytes(out_n) != bytes(out_l):
            raise AssertionError(f"{name}: lifted {bytes(out_l).hex()} != native {bytes(out_n).hex()}")
        cases += 1

    for name, a, b in (
        ("psignb_op", a_b, b_b), ("psignw_op", a_w, b_w), ("psignd_op", a_d, b_d),
        ("pshufb_op", a_b, shuf_mask), ("palignr_op", a_b, b_b), ("palignr_hi", a_b, b_b),
        ("phaddw_op", a_w, b_w), ("phaddd_op", a_d, b_d),
        ("phsubw_op", a_w, b_w), ("phsubd_op", a_d, b_d),
        ("phaddsw_op", a_w, b_w), ("phsubsw_op", a_w, b_w),
    ):
        ba = ctypes.create_string_buffer(a, 16)
        bb = ctypes.create_string_buffer(b, 16)
        ctypes.memset(out_n, 0xaa, 16)
        ctypes.memset(out_l, 0x55, 16)
        getattr(native, name)(ba, bb, out_n)
        getattr(lifted, name)(ba, bb, out_l)
        if bytes(out_n) != bytes(out_l):
            raise AssertionError(f"{name}: lifted {bytes(out_l).hex()} != native {bytes(out_n).hex()}")
        cases += 1

    print(f"{cases} SSSE3 integer vector cases across 14 instructions matched native and translated DLLs")


def check_rejections():
    controls = (
        ("MMX pabsb", "0f 38 1c c1 c3", "unsupported query operation"),
        ("pabsb with untracked XMM3", "66 0f 38 1c c3 c3", "unsupported SSSE3 source"),
        ("pabsb with memory source", "66 0f 38 1c 01 c3", "unsupported SSSE3 source"),
    )
    for label, code, diagnostic in controls:
        insns = list(Decoder(64, bytes.fromhex(code), ip=0x1000))
        try:
            lower(insns, [], {}, {}, {})
        except ValueError as exc:
            if not str(exc).startswith(f"{diagnostic} at 0x1000"):
                raise AssertionError(f"{label}: unexpected diagnostic {exc}") from exc
        else:
            raise AssertionError(f"accepted {label}")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check_rejections()
        check(native, other)
    else:
        raise ValueError(mode)
