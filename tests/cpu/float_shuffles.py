"""Compare native and translated shuffle, unpacking, and vector move instructions."""
import ctypes
import math
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
    "shufps", "unpckhps", "unpcklps", "movhlps", "movlhps", "movmskps", "movups", "pmovmskb",
    "rcpps", "rcpss", "rsqrtps", "rsqrtss",
    "shufpd", "unpckhpd", "unpcklpd", "movmskpd", "movupd", "movapd", "movdqa",
    "pshufd", "pshufhw", "pshuflw", "pslldq", "psrldq", "punpckhqdq", "punpcklqdq",
    "vshufps", "vunpckhps", "vunpcklps", "vshufpd", "vunpckhpd", "vunpcklpd",
    "vpshufd", "vpshufhw", "vpshuflw", "vmovhlps", "vmovlhps", "vmovmskps", "vmovmskpd",
    "vmovaps", "vmovapd", "vmovdqa", "vpmovmskb", "vrcpps", "vrcpss", "vrsqrtps", "vrsqrtss",
    "vpslldq", "vpsrldq", "vpunpckhqdq", "vpunpcklqdq",
)
EXPORT_NAMES = tuple(f"{op}_op" for op in EXPORTS)


def emit(image, output):
    parts = [INTEGER_HEADER]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in EXPORT_NAMES:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = c;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word c) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in EXPORT_NAMES:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], U64
    return lib


def aligned_buffer(data_bytes):
    raw = ctypes.create_string_buffer(len(data_bytes) + 32)
    addr = ctypes.addressof(raw)
    off = (16 - (addr % 16)) % 16
    ptr = addr + off
    ctypes.memmove(ptr, data_bytes, len(data_bytes))
    return raw, ptr


def check(native_path, lifted_path):
    native, lifted = load_lib(native_path), load_lib(lifted_path)

    p1 = struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)
    p2 = struct.pack("<4f", 10.0, 20.0, 30.0, 40.0)
    p3 = struct.pack("<4I", 0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00)
    p4 = struct.pack("<4I", 0x80808080, 0x01010101, 0x8f8f8f8f, 0x00000000)

    patterns = [(p1, p2), (p3, p4), (p1, p3)]

    rcp_rsqrt_ops = {"rcpps_op", "rcpss_op", "rsqrtps_op", "rsqrtss_op",
                     "vrcpps_op", "vrcpss_op", "vrsqrtps_op", "vrsqrtss_op"}

    mask_ops = {"movmskps_op", "movmskpd_op", "pmovmskb_op",
                "vmovmskps_op", "vmovmskpd_op", "vpmovmskb_op"}

    comparisons = 0
    for a_bytes, b_bytes in patterns:
        raw_a, ptr_a = aligned_buffer(a_bytes)
        raw_b, ptr_b = aligned_buffer(b_bytes)
        raw_out_n, ptr_out_n = aligned_buffer(b"\xaa" * 16)
        raw_out_l, ptr_out_l = aligned_buffer(b"\x55" * 16)

        for name in EXPORT_NAMES:
            ctypes.memset(ptr_out_n, 0xaa, 16)
            ctypes.memset(ptr_out_l, 0x55, 16)
            getattr(native, name)(ptr_a, ptr_b, ptr_out_n)
            getattr(lifted, name)(ptr_a, ptr_b, ptr_out_l)
            res_n = ctypes.string_at(ptr_out_n, 16)
            res_l = ctypes.string_at(ptr_out_l, 16)

            if name in rcp_rsqrt_ops:
                fn_floats_n = struct.unpack("<4f", res_n)
                fn_floats_l = struct.unpack("<4f", res_l)
                for fn, fl in zip(fn_floats_n, fn_floats_l):
                    if math.isnan(fn) and math.isnan(fl):
                        continue
                    if not math.isclose(fn, fl, rel_tol=0.01, abs_tol=1e-4):
                        raise AssertionError(f"{name}: approx mismatch native {fn} != lifted {fl}")
            elif name in mask_ops:
                if res_n[:4] != res_l[:4]:
                    raise AssertionError(f"{name}: native {res_n[:4].hex()} != lifted {res_l[:4].hex()}")
            else:
                if res_n != res_l:
                    raise AssertionError(f"{name}: native {res_n.hex()} != lifted {res_l.hex()}")
            comparisons += 1

    print(f"All {comparisons} shuffle and vector move operations verified across native and lifted DLLs")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
