"""Differential tests for SSSE3/SSE4 horizontal, blend, rounding, dot-product, and AVX scalar math."""
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

EXPORT_NAMES = [
    "pabsb_op", "pabsw_op", "pabsd_op",
    "psignb_op", "psignw_op", "psignd_op",
    "palignr_op", "pshufb_op", "vpshufb_op",
    "phaddw_op", "phaddd_op", "phaddsw_op",
    "phsubw_op", "phsubd_op", "phsubsw_op",
    "haddps_op", "vhaddps_op", "haddpd_op", "vhaddpd_op",
    "hsubps_op", "vhsubps_op", "hsubpd_op", "vhsubpd_op",
    "addsubps_op", "vaddsubps_op", "addsubpd_op", "vaddsubpd_op",
    "roundps_op", "vroundps_op", "roundpd_op", "vroundpd_op",
    "roundss_op", "vroundss_op", "roundsd_op", "vroundsd_op",
    "movshdup_op", "movsldup_op", "movddup_op",
    "blendps_op", "blendpd_op",
    "dpps_op", "vdpps_op", "dppd_op", "vdppd_op",
    "vaddss_op", "vsubss_op", "vmulss_op", "vdivss_op",
    "vaddsd_op", "vsubsd_op", "vmulsd_op", "vdivsd_op",
]

FLOAT_OPS = {
    "haddps_op", "vhaddps_op", "hsubps_op", "vhsubps_op",
    "addsubps_op", "vaddsubps_op", "roundps_op", "vroundps_op",
    "roundss_op", "vroundss_op", "movshdup_op", "movsldup_op",
    "blendps_op", "dpps_op", "vdpps_op",
    "vaddss_op", "vsubss_op", "vmulss_op", "vdivss_op",
}

DOUBLE_OPS = {
    "haddpd_op", "vhaddpd_op", "hsubpd_op", "vhsubpd_op",
    "addsubpd_op", "vaddsubpd_op", "roundpd_op", "vroundpd_op",
    "roundsd_op", "vroundsd_op", "movddup_op",
    "blendpd_op", "dppd_op", "vdppd_op",
    "vaddsd_op", "vsubsd_op", "vmulsd_op", "vdivsd_op",
}


def emit(image: Path, output: Path):
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


def aligned_buffer(data_bytes: bytes):
    raw = ctypes.create_string_buffer(len(data_bytes) + 32)
    addr = ctypes.addressof(raw)
    off = (16 - (addr % 16)) % 16
    ptr = addr + off
    ctypes.memmove(ptr, data_bytes, len(data_bytes))
    return raw, ptr


def check(native_path: str, lifted_path: str):
    native = load_lib(native_path)
    lifted = load_lib(lifted_path)

    patterns = [
        (
            struct.pack("<4f", 1.5, -2.5, 3.25, -4.75),
            struct.pack("<4f", 0.5, 1.25, -2.0, 3.5),
        ),
        (
            struct.pack("<2d", 12.345, -67.89),
            struct.pack("<2d", -1.23, 4.56),
        ),
        (
            bytes([k * 17 % 256 for k in range(16)]),
            bytes([(255 - k * 31) % 256 for k in range(16)]),
        ),
        (
            bytes([0x80, 0x7f, 0x00, 0xff, 0x01, 0xfe, 0xaa, 0x55] * 2),
            bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] * 2),
        ),
    ]

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

            if res_n != res_l:
                if name in FLOAT_OPS:
                    floats_n = struct.unpack("<4f", res_n)
                    floats_l = struct.unpack("<4f", res_l)
                    for fn, fl in zip(floats_n, floats_l):
                        if math.isnan(fn) and math.isnan(fl):
                            continue
                        if not math.isclose(fn, fl, rel_tol=1e-5, abs_tol=1e-5):
                            raise AssertionError(f"{name}: float mismatch native {fn} != lifted {fl}")
                elif name in DOUBLE_OPS:
                    doubles_n = struct.unpack("<2d", res_n)
                    doubles_l = struct.unpack("<2d", res_l)
                    for dn, dl in zip(doubles_n, doubles_l):
                        if math.isnan(dn) and math.isnan(dl):
                            continue
                        if not math.isclose(dn, dl, rel_tol=1e-5, abs_tol=1e-5):
                            raise AssertionError(f"{name}: double mismatch native {dn} != lifted {dl}")
                else:
                    raise AssertionError(f"{name}: native {res_n.hex()} != lifted {res_l.hex()}")
            comparisons += 1

    print(f"All {comparisons} SSSE3/SSE4/AVX operations verified across native and lifted DLLs")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
