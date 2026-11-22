"""Compare native and translated Crypto (AES, PCLMULQDQ, SHA) instructions."""
import ctypes
from pathlib import Path
import sys

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64

UNARY_EXPORTS = ("fn_aesimc", "fn_vaesimc", "fn_aeskeygenassist", "fn_vaeskeygenassist")
BINARY_EXPORTS = (
    "fn_aesenc", "fn_vaesenc", "fn_aesenclast", "fn_vaesenclast",
    "fn_aesdec", "fn_vaesdec", "fn_aesdeclast", "fn_vaesdeclast",
    "fn_pclmulqdq", "fn_vpclmulqdq",
    "fn_sha1msg1", "fn_sha1msg2", "fn_sha1nexte", "fn_sha1rnds4",
    "fn_sha256msg1", "fn_sha256msg2",
)
TERNARY_EXPORTS = ("fn_sha256rnds2",)


def emit(image, output):
    parts = [
        "#include <intrin.h>\n",
        "#include <immintrin.h>\n",
        "#include <wmmintrin.h>\n",
        INTEGER_HEADER,
    ]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in UNARY_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = in_a; rdx = out;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word in_a, word out) {{\n{code}\n}}\n')
        for name in BINARY_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = in_a; rdx = in_b; r8 = out;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word in_a, word in_b, word out) {{\n{code}\n}}\n')
        for name in TERNARY_EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = in_a; rdx = in_b; r8 = in_c; r9 = out;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word in_a, word in_b, word in_c, word out) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in UNARY_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p], None
    for name in BINARY_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], None
    for name in TERNARY_EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], None
    return lib


def check(native_path, lifted_path):
    native = load_lib(native_path)
    lifted = load_lib(lifted_path)

    Block = ctypes.c_uint8 * 16
    out_native = Block()
    out_lifted = Block()

    test_vectors = [
        bytes(range(16)),
        bytes(range(16, 32)),
        bytes([0x00] * 16),
        bytes([0xff] * 16),
        bytes([0x55, 0xaa] * 8),
        bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]),
        bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]),
    ]

    checks = 0

    # 1. Unary
    for name in UNARY_EXPORTS:
        for vec_a in test_vectors:
            in_a = Block.from_buffer_copy(vec_a)
            ctypes.memset(out_native, 0xcc, 16)
            ctypes.memset(out_lifted, 0xcc, 16)
            getattr(native, name)(ctypes.byref(in_a), ctypes.byref(out_native))
            getattr(lifted, name)(ctypes.byref(in_a), ctypes.byref(out_lifted))
            if bytes(out_native) != bytes(out_lifted):
                raise AssertionError(f"{name} mismatch for {vec_a.hex()}: native={bytes(out_native).hex()} != lifted={bytes(out_lifted).hex()}")
            checks += 1

    # 2. Binary
    for name in BINARY_EXPORTS:
        for vec_a in test_vectors:
            for vec_b in test_vectors:
                in_a = Block.from_buffer_copy(vec_a)
                in_b = Block.from_buffer_copy(vec_b)
                ctypes.memset(out_native, 0xcc, 16)
                ctypes.memset(out_lifted, 0xcc, 16)
                getattr(native, name)(ctypes.byref(in_a), ctypes.byref(in_b), ctypes.byref(out_native))
                getattr(lifted, name)(ctypes.byref(in_a), ctypes.byref(in_b), ctypes.byref(out_lifted))
                if bytes(out_native) != bytes(out_lifted):
                    raise AssertionError(f"{name} mismatch: native={bytes(out_native).hex()} != lifted={bytes(out_lifted).hex()}")
                checks += 1

    # 3. Ternary (sha256rnds2)
    for name in TERNARY_EXPORTS:
        for vec_a in test_vectors:
            for vec_b in test_vectors:
                vec_c = test_vectors[0]
                in_a = Block.from_buffer_copy(vec_a)
                in_b = Block.from_buffer_copy(vec_b)
                in_c = Block.from_buffer_copy(vec_c)
                ctypes.memset(out_native, 0xcc, 16)
                ctypes.memset(out_lifted, 0xcc, 16)
                getattr(native, name)(ctypes.byref(in_a), ctypes.byref(in_b), ctypes.byref(in_c), ctypes.byref(out_native))
                getattr(lifted, name)(ctypes.byref(in_a), ctypes.byref(in_b), ctypes.byref(in_c), ctypes.byref(out_lifted))
                if bytes(out_native) != bytes(out_lifted):
                    raise AssertionError(f"{name} mismatch: native={bytes(out_native).hex()} != lifted={bytes(out_lifted).hex()}")
                checks += 1

    print(f"{checks} crypto instruction cases matched native and translated DLLs")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "emit":
        emit(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "check":
        check(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        print("usage: crypto.py emit <pe> <out.cpp> | check <native.dll> <lifted.dll>", file=sys.stderr)
        sys.exit(2)
