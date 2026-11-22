"""Differential tests for MMX and MMX-SSE conversion and move instructions."""
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

EXPORT_NAMES = [
    "packssdw_op", "packsswb_op", "packuswb_op",
    "pslld_op", "psllq_op", "psllw_op",
    "psrad_op", "psraw_op", "psrld_op", "psrlq_op", "psrlw_op",
    "punpckhbw_op", "punpckhdq_op", "punpckhwd_op",
    "punpcklbw_op", "punpckldq_op", "punpcklwd_op",
    "pshufw_op",
    "cvtpi2ps_op", "cvtps2pi_op", "cvttps2pi_op",
    "cvtpd2pi_op", "cvtpi2pd_op", "cvttpd2pi_op",
    "movdq2q_op", "movq2dq_op",
    "maskmovq_op", "movntq_op", "emms_op",
]

SIXTEEN_BYTE_OPS = {
    "cvtpi2ps_op", "cvtpi2pd_op", "movq2dq_op",
}


def emit(image: Path, output: Path):
    parts = [INTEGER_HEADER]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in EXPORT_NAMES:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = c;"], {}, {}, {}, mmx=True)
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
            struct.pack("<4i", 10, -20, 30, -40),
            struct.pack("<4i", 1, 2, -3, 4),
        ),
        (
            struct.pack("<4f", 10.0, 20.0, 30.0, 40.0),
            struct.pack("<4f", 1.0, 2.0, 3.0, 4.0),
        ),
        (
            struct.pack("<2d", 123.0, -456.0),
            struct.pack("<2d", 10.0, -20.0),
        ),
        (
            bytes([0x80, 0x12, 0xff, 0x00, 0xaa, 0x55, 0x33, 0xcc] * 2),
            bytes([0x01, 0x80, 0x7f, 0x88, 0x55, 0xaa, 0xcc, 0x33] * 2),
        ),
    ]

    comparisons = 0
    for a_bytes, b_bytes in patterns:
        raw_a, ptr_a = aligned_buffer(a_bytes)
        raw_b, ptr_b = aligned_buffer(b_bytes)
        raw_out_n, ptr_out_n = aligned_buffer(b"\x33" * 16)
        raw_out_l, ptr_out_l = aligned_buffer(b"\x33" * 16)

        for name in EXPORT_NAMES:
            ctypes.memset(ptr_out_n, 0x33, 16)
            ctypes.memset(ptr_out_l, 0x33, 16)
            getattr(native, name)(ptr_out_n, ptr_a, ptr_b)
            getattr(lifted, name)(ptr_out_l, ptr_a, ptr_b)
            res_n = ctypes.string_at(ptr_out_n, 16)
            res_l = ctypes.string_at(ptr_out_l, 16)
            if name not in SIXTEEN_BYTE_OPS:
                res_n = res_n[:8]
                res_l = res_l[:8]

            if res_n != res_l:
                raise AssertionError(f"{name}: native {res_n.hex()} != lifted {res_l.hex()}")
            comparisons += 1

    print(f"All {comparisons} MMX and MMX-SSE conversion and move operations verified across native and lifted DLLs")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
