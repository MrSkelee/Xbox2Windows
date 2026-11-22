"""Differential tests for XSAVE, FXSAVE, and extended state processor management."""
import ctypes
from pathlib import Path
import sys

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64

EXPORT_NAMES = [
    "xgetbv_op", "fxsave_op", "fxrstor_op", "xsave_op", "xrstor_op", "xsaveopt_op", "xsavec_op",
]


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


def aligned_buffer(size: int):
    raw = ctypes.create_string_buffer(size + 128)
    addr = ctypes.addressof(raw)
    off = (64 - (addr % 64)) % 64
    ptr = addr + off
    return raw, ptr


def check(native_path: str, lifted_path: str):
    native = load_lib(native_path)
    lifted = load_lib(lifted_path)

    # 1. xgetbv test
    raw_out_n, ptr_out_n = aligned_buffer(64)
    raw_out_l, ptr_out_l = aligned_buffer(64)
    native.xgetbv_op(ptr_out_n, 0, ptr_out_n)
    lifted.xgetbv_op(ptr_out_l, 0, ptr_out_l)
    assert ctypes.string_at(ptr_out_n, 16) == ctypes.string_at(ptr_out_l, 16), "xgetbv result mismatch"

    # 2. fxsave / fxrstor test
    raw_fx_n, ptr_fx_n = aligned_buffer(512)
    raw_fx_l, ptr_fx_l = aligned_buffer(512)
    native.fxsave_op(ptr_fx_n, 0, 0)
    lifted.fxsave_op(ptr_fx_l, 0, 0)
    native.fxrstor_op(ptr_fx_n, 0, 0)
    lifted.fxrstor_op(ptr_fx_l, 0, 0)

    # 3. xsave / xrstor / xsaveopt / xsavec tests
    raw_x_n, ptr_x_n = aligned_buffer(4096)
    raw_x_l, ptr_x_l = aligned_buffer(4096)
    native.xsave_op(ptr_x_n, 0, 0)
    lifted.xsave_op(ptr_x_l, 0, 0)
    native.xrstor_op(ptr_x_n, 0, 0)
    lifted.xrstor_op(ptr_x_l, 0, 0)

    native.xsaveopt_op(ptr_x_n, 0, 0)
    lifted.xsaveopt_op(ptr_x_l, 0, 0)

    native.xsavec_op(ptr_x_n, 0, 0)
    lifted.xsavec_op(ptr_x_l, 0, 0)

    print("All XSAVE, FXSAVE, and extended processor state operations verified across native and lifted DLLs")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
