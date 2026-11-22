"""Compare native and translated packed FMA3 instructions (all 36 ps/pd forms)."""
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
KINDS = ("madd", "msub", "nmadd", "nmsub", "maddsub", "msubadd")
ORDERS = ("132", "213", "231")
EXPORTS = tuple(f"vf{k}{o}{s}_op" for k in KINDS for o in ORDERS for s in ("ps", "pd")) + (
    "vfmadd132ps_xmm_op", "vfmsub213ps_mem_op",
)


def emit(image, output):
    parts = [
        "#include <intrin.h>\n",
        INTEGER_HEADER,
        'extern "C" __declspec(dllexport) int host_has_fma() {\n'
        "    int regs[4]{};\n"
        "    __cpuid(regs, 1);\n"
        "    if ((regs[2] & (1 << 27)) == 0 || (regs[2] & (1 << 12)) == 0) return 0;\n"
        "    return (_xgetbv(0) & 6ull) == 6ull;\n"
        "}\n",
    ]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = c; r9 = dst;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word c, word dst) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], U64
    return lib


def check(native_path, lifted_path):
    lifted = load_lib(lifted_path)
    lifted.host_has_fma.argtypes, lifted.host_has_fma.restype = [], ctypes.c_int
    if not lifted.host_has_fma():
        print("Host CPU/OS lacks FMA3 (CPUID leaf 1 ECX bit 12 / XCR0 YMM); skipping native differential check.")
        sys.exit(77)
    native = load_lib(native_path)
    out_n = (ctypes.c_uint8 * 32)()
    out_l = (ctypes.c_uint8 * 32)()

    ps_a = bytearray(struct.pack("<8f", 1.0 + 2.0**-23, 1.5, -2.25, 0.0, 1e20, 0, 1.0, 1.0))
    ps_b = bytearray(struct.pack("<8f", 1.0 - 2.0**-23, -2.25, 4.0, -0.0, 1e20, 4.5, 0, 2.0))
    ps_c = bytearray(struct.pack("<8f", -1.0, 3.75, 0.5, 0.0, -1e38, -0.125, 1.25, 0))
    struct.pack_into("<I", ps_a, 5 * 4, 0x7f800123)
    struct.pack_into("<I", ps_b, 6 * 4, 0xffc00124)
    struct.pack_into("<I", ps_c, 7 * 4, 0xff800125)

    pd_a = bytearray(struct.pack("<4d", 1.0 + 2.0**-52, 0, 1.0, 1.0))
    pd_b = bytearray(struct.pack("<4d", 1.0 - 2.0**-52, -2.25, 0, 2.0))
    pd_c = bytearray(struct.pack("<4d", -1.0, 3.75, -0.125, 0))
    struct.pack_into("<Q", pd_a, 1 * 8, 0x7ff0000012345678)
    struct.pack_into("<Q", pd_b, 2 * 8, 0xfff8000012345679)
    struct.pack_into("<Q", pd_c, 3 * 8, 0xfff000001234567a)

    distinct32 = tuple(struct.pack("<I", bits) * 8 for bits in (0x7fc00127, 0xff800128, 0xffc00129))
    distinct64 = tuple(struct.pack("<Q", bits) * 4 for bits in
                       (0x7ff800001234567b, 0xfff000001234567c, 0xfff800001234567d))
    cases = 0
    for name in EXPORTS:
        is_double = name.endswith("pd_op")
        single_nan = (pd_a, pd_b, pd_c) if is_double else (ps_a, ps_b, ps_c)
        distinct = distinct64 if is_double else distinct32
        one = struct.pack("<d" if is_double else "<f", 1.0)
        finite = one * (32 // len(one))
        pairs = tuple(
            (f"NaN pair with finite operand {index}", distinct[:index] + (finite,) + distinct[index + 1:])
            for index in range(3)
        )
        for label, operands in (("single NaN and finite lanes", single_nan), ("three NaNs", distinct), *pairs):
            a, b, c = (ctypes.create_string_buffer(bytes(arg), 32) for arg in operands)
            ctypes.memset(out_n, 0xaa, 32)
            ctypes.memset(out_l, 0x55, 32)
            getattr(native, name)(a, b, c, out_n)
            getattr(lifted, name)(a, b, c, out_l)
            if bytes(out_n) != bytes(out_l):
                raise AssertionError(
                    f"{name} ({label}): lifted {bytes(out_l).hex()} != native {bytes(out_n).hex()}"
                )
            if name == "vfmadd132ps_xmm_op" and any(out_l[16:]):
                raise AssertionError("128-bit FMA did not clear the upper YMM half")
            cases += 1

    print(f"{cases} packed FMA3 vector cases matched native and translated DLLs bit-for-bit")


def check_rejections():
    # EVEX broadcast vfmadd132ps ymm0, ymm1, dword ptr [rdx]{1to8} (62 f2 75 38 98 02) must be rejected.
    insns = list(Decoder(64, bytes.fromhex("62 f2 75 38 98 02 c3"), ip=0x1000))
    assert insns[0].is_broadcast
    try:
        lower(insns, [], {}, {}, {})
    except ValueError as exc:
        if not str(exc).startswith("unsupported query operation at 0x1000"):
            raise AssertionError(f"unexpected diagnostic {exc}") from exc
    else:
        raise AssertionError("accepted EVEX broadcast vfmadd132ps")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check_rejections()
        check(native, other)
    else:
        raise ValueError(mode)
