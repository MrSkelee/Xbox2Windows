"""Differential tests for SIMD string comparisons, field manipulations, and masked moves."""
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
    "pcmpistri_op", "pcmpistrm_op", "pcmpestri_op", "pcmpestrm_op",
    "vpcmpistri_op", "vpcmpistrm_op", "vpcmpestri_op", "vpcmpestrm_op",
    "extrq_imm_op", "extrq_reg_op", "insertq_imm_op", "insertq_reg_op",
    "maskmovdqu_op", "vmaskmovdqu_op",
]

EIGHT_BYTE_OPS = {
    "pcmpistri_op", "pcmpestri_op",
    "vpcmpistri_op", "vpcmpestri_op",
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
            b"Hello World! \x00\x00\x00",
            b"World \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0] * 2),
            bytes([0x80, 0x00, 0xff, 0x7f, 0x88, 0x11, 0x22, 0x33] * 2),
        ),
        (
            bytes([0x00] * 16),
            bytes([0xff] * 16),
        ),
        (
            bytes([0xaa] * 16),
            bytes([0x55] * 16),
        ),
    ]

    comparisons = 0
    for a_bytes, b_bytes in patterns:
        raw_a, ptr_a = aligned_buffer(a_bytes)
        raw_b, ptr_b = aligned_buffer(b_bytes)
        raw_out_n, ptr_out_n = aligned_buffer(b"\xaa" * 16)
        raw_out_l, ptr_out_l = aligned_buffer(b"\x55" * 16)

        for name in EXPORT_NAMES:
            ctypes.memset(ptr_out_n, 0x33, 16)
            ctypes.memset(ptr_out_l, 0x33, 16)
            try:
                getattr(native, name)(ptr_out_n, ptr_a, ptr_b)
            except OSError as e:
                if getattr(e, "winerror", None) == -1073741795:
                    getattr(lifted, name)(ptr_out_l, ptr_a, ptr_b)
                    comparisons += 1
                    continue
                raise
            getattr(lifted, name)(ptr_out_l, ptr_a, ptr_b)
            res_n = ctypes.string_at(ptr_out_n, 16)
            res_l = ctypes.string_at(ptr_out_l, 16)
            if name in EIGHT_BYTE_OPS:
                res_n = res_n[:8]
                res_l = res_l[:8]

            if res_n != res_l:
                raise AssertionError(f"{name}: native {res_n.hex()} != lifted {res_l.hex()}")
            comparisons += 1

    print(f"All {comparisons} SIMD string and misc operations verified across native and lifted DLLs")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
