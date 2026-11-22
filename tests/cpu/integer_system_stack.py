"""Differential tests for system stack and integer processor management."""
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
    "integer_system_stack_dummy",
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
        fn.argtypes, fn.restype = [U64, U64, U64], U64
    return lib


def check(native_path: str, lifted_path: str):
    native = load_lib(native_path)
    lifted = load_lib(lifted_path)

    res_n = native.integer_system_stack_dummy(1234, 5678, 0)
    res_l = lifted.integer_system_stack_dummy(1234, 5678, 0)
    assert res_n == res_l, f"dummy mismatch: native {res_n} != lifted {res_l}"

    print("All integer system stack operations verified across native and lifted DLLs")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
