"""Compare native and translated vector FMA3 instructions (all 36 ps/pd forms)."""
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
EXPORTS = tuple(f"vf{k}{o}{s}_op" for k in KINDS for o in ORDERS for s in ("ps", "pd"))


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
        print("Host CPU/OS lacks FMA3; skipping native differential check.")
        sys.exit(77)
    native = load_lib(native_path)
    out_n = (ctypes.c_uint8 * 32)()
    out_l = (ctypes.c_uint8 * 32)()

    qnan32 = struct.pack("<I", 0xffc12345)
    snan32 = struct.pack("<I", 0x7f812345)
    qnan64 = struct.pack("<Q", 0xfff8000012345678)
    snan64 = struct.pack("<Q", 0x7ff0000012345678)

    f32_vecs = (
        (1.5, -2.25, 3.75, -1.0),
        (0.0, -0.0, 1.0, -1.0),
        (1.0 + 2.0**-23, 1.0 - 2.0**-23, 2.0, -2.0),
        (-3.25, 4.5, -0.125, 0.5),
        (1.0, 1.0, qnan32, snan32),
    )
    f64_vecs = (
        (1.5, -2.25),
        (0.0, -0.0),
        (1.0 + 2.0**-52, 1.0 - 2.0**-52),
        (-3.25, 4.5),
        (qnan64, snan64),
    )

    pad_noise = bytes(range(0xA0, 0xC0))

    cases = 0
    for name in EXPORTS:
        is_f64 = name.endswith("pd_op")
        fmt, sz, count, vecs = ("<d", 8, 2, f64_vecs) if is_f64 else ("<f", 4, 4, f32_vecs)
        for i in range(len(vecs)):
            v0 = vecs[i]
            v1 = vecs[(i + 1) % len(vecs)]
            v2 = vecs[(i + 2) % len(vecs)]
            def pack_v(v):
                return b"".join(x if isinstance(x, bytes) else struct.pack(fmt, x) for x in v)
            buf_a = ctypes.create_string_buffer(pack_v(v0) + pad_noise[:16], 32)
            buf_b = ctypes.create_string_buffer(pack_v(v1) + pad_noise[:16], 32)
            buf_c = ctypes.create_string_buffer(pack_v(v2) + pad_noise[:16], 32)
            ctypes.memset(out_n, 0xaa, 32)
            ctypes.memset(out_l, 0x55, 32)
            getattr(native, name)(buf_a, buf_b, buf_c, out_n)
            getattr(lifted, name)(buf_a, buf_b, buf_c, out_l)
            bn, bl = bytes(out_n), bytes(out_l)
            if bn != bl:
                raise AssertionError(f"{name} mismatch: lifted {bl.hex()} != native {bn.hex()}")
            if bl[16:] != b"\x00" * 16:
                raise AssertionError(f"{name} upper 128-bit YMM was not zeroed: {bl.hex()}")
            cases += 1

    print(f"{cases} vector FMA3 cases across all 36 ps/pd forms matched native and translated DLLs bit-for-bit")


def check_rejections():
    insns = list(Decoder(64, bytes.fromhex("62 f2 75 09 98 c2 c3"), ip=0x1000))
    try:
        lower(insns, [], {}, {}, {})
    except ValueError as exc:
        if not str(exc).startswith("unsupported query operation at 0x1000"):
            raise AssertionError(f"unexpected diagnostic {exc}") from exc
    else:
        raise AssertionError("accepted EVEX vfmadd132ps")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check_rejections()
        check(native, other)
    else:
        raise ValueError(mode)
