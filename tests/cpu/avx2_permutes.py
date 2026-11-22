"""Compare native and translated AVX2 lane ops, blends, and cross-lane permutes."""
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
TWO_ARG = ("bcast_i128", "extract_i128_hi", "permq256", "permpd256",
           "extract_i128_reg_imm2", "permq256_imm4")
THREE_ARG = ("insert_i128_hi", "pblendd256", "pblendd256_mem", "pblendd256_mem_zero", "perm2i128_hi", "perm2i128_zero", "permd256", "permps256",
             "insert_i128_reg_imm2", "pblendd256_lane0", "perm2i128_zero_lo")


def emit(image, output):
    parts = [
        "#include <intrin.h>\n",
        INTEGER_HEADER,
        'extern "C" __declspec(dllexport) int host_has_avx2() {\n'
        "    int regs[4]{};\n"
        "    __cpuid(regs, 0);\n"
        "    if (regs[0] < 7) return 0;\n"
        "    __cpuid(regs, 1);\n"
        "    if ((regs[2] & (1 << 27)) == 0) return 0;\n"
        "    if ((_xgetbv(0) & 6ull) != 6ull) return 0;\n"
        "    __cpuidex(regs, 7, 0);\n"
        "    return (regs[1] & (1 << 5)) != 0;\n"
        "}\n",
    ]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in TWO_ARG:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = src; rdx = dst;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word src, word dst) {{\n{code}\n}}\n')
        for name in THREE_ARG:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = dst;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word dst) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in TWO_ARG:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p], U64
    for name in THREE_ARG:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], U64
    return lib


def check(native_path, lifted_path):
    lifted = load_lib(lifted_path)
    lifted.host_has_avx2.argtypes, lifted.host_has_avx2.restype = [], ctypes.c_int
    if not lifted.host_has_avx2():
        print("Host CPU/OS lacks AVX2 (CPUID leaf 7 EBX bit 5 / XCR0 YMM); skipping native differential check.")
        sys.exit(77)
    native = load_lib(native_path)
    cases = 0

    a_bytes = bytes(range(0x10, 0x30))
    b_bytes = bytes(range(0x80, 0xa0))
    a_buf = ctypes.create_string_buffer(a_bytes, 32)
    b_buf = ctypes.create_string_buffer(b_bytes, 32)
    dst_buf = (ctypes.c_uint8 * 32)()

    def run2(name, src, want, size=32):
        nonlocal cases
        for lib, label in ((native, "native"), (lifted, "lifted")):
            ctypes.memset(dst_buf, 0xaa, 32)
            getattr(lib, name)(src, dst_buf)
            got = bytes(dst_buf[:size])
            if got != want:
                raise AssertionError(f"{label} {name} = {got.hex()}, expected {want.hex()}")
        cases += 1

    def run3(name, x, y, want):
        nonlocal cases
        for lib, label in ((native, "native"), (lifted, "lifted")):
            ctypes.memset(dst_buf, 0xaa, 32)
            getattr(lib, name)(x, y, dst_buf)
            got = bytes(dst_buf)
            if got != want:
                raise AssertionError(f"{label} {name} = {got.hex()}, expected {want.hex()}")
        cases += 1

    run2("bcast_i128", a_buf, a_bytes[:16] * 2)
    run2("extract_i128_hi", a_buf, a_bytes[16:32], size=16)
    run3("insert_i128_hi", a_buf, b_buf, a_bytes[:16] + b_bytes[:16])

    a_d = struct.unpack("<8I", a_bytes)
    b_d = struct.unpack("<8I", b_bytes)
    want_blend = struct.pack("<8I", *(b_d[i] if (0xa5 >> i) & 1 else a_d[i] for i in range(8)))
    run3("pblendd256", a_buf, b_buf, want_blend)

    want_mem_blend = struct.pack("<8I", *(b_d[i] if (0x05 >> i) & 1 else a_d[i] for i in range(8)))
    run3("pblendd256_mem", a_buf, b_buf, want_mem_blend)
    run3("pblendd256_mem_zero", a_buf, b_buf, a_bytes)

    # Both selected lanes are in the readable half. The full operand still crosses the page.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p]
    kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    page = 4096  # Windows x64 fixture page size
    base = kernel32.VirtualAlloc(None, 2 * page, 0x3000, 0x04)
    if not base:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        old = ctypes.c_uint32()
        if not kernel32.VirtualProtect(base + page, page, 0x01, ctypes.byref(old)):
            raise ctypes.WinError(ctypes.get_last_error())
        pointer = base + page - 16
        ctypes.memmove(pointer, b_bytes, 16)
        for name, source in (("pblendd256_mem", pointer), ("pblendd256_mem_zero", base + page)):
            for lib, label in ((native, "native"), (lifted, "lifted")):
                ctypes.memset(dst_buf, 0xaa, 32)
                try:
                    getattr(lib, name)(a_buf, source, dst_buf)
                except OSError as exc:
                    if "access violation reading" not in str(exc):
                        raise
                else:
                    raise AssertionError(f"{label} {name} failed to read masked-off memory")
                if bytes(dst_buf) != bytes([0xaa]) * 32:
                    raise AssertionError(f"{label} {name} wrote output before the fault")
    finally:
        if not kernel32.VirtualFree(base, 0, 0x8000):
            raise ctypes.WinError(ctypes.get_last_error())

    run3("perm2i128_hi", a_buf, b_buf, a_bytes[16:32] + b_bytes[16:32])
    run3("perm2i128_zero", a_buf, b_buf, b_bytes[:16] + b"\x00" * 16)

    idx = (7, 0, 5, 2, 11, 0xffffffff, 4, 1)  # tests masking to low 3 bits
    idx_buf = ctypes.create_string_buffer(struct.pack("<8I", *idx), 32)
    want_permd = struct.pack("<8I", *(b_d[i & 7] for i in idx))
    run3("permd256", idx_buf, b_buf, want_permd)
    run3("permps256", idx_buf, b_buf, want_permd)

    a_q = struct.unpack("<4Q", a_bytes)
    run2("permq256", a_buf, struct.pack("<4Q", *(a_q[(0x1b >> (2 * i)) & 3] for i in range(4))))
    run2("permpd256", a_buf, struct.pack("<4Q", *(a_q[(0x93 >> (2 * i)) & 3] for i in range(4))))

    run2("extract_i128_reg_imm2", a_buf, a_bytes[:16] + bytes(16))
    run3("insert_i128_reg_imm2", a_buf, b_buf, b_bytes[:16] + a_bytes[16:])
    run3("pblendd256_lane0", a_buf, b_buf, b_bytes[:4] + a_bytes[4:])
    run3("perm2i128_zero_lo", a_buf, b_buf, bytes(16) + b_bytes[16:])

    idx_six = (6,) + idx[1:]
    idx_six_buf = ctypes.create_string_buffer(struct.pack("<8I", *idx_six), 32)
    want_permd_six = struct.pack("<8I", *(b_d[i & 7] for i in idx_six))
    run3("permd256", idx_six_buf, b_buf, want_permd_six)

    run2("permq256_imm4", a_buf, struct.pack("<4Q", a_q[0], a_q[1], a_q[0], a_q[0]))

    print(f"{cases} AVX2 lane, blend, and cross-lane permute cases matched native and translated DLLs")


def check_rejections():
    # EVEX scalar-broadcast vpermd ymm0, ymm1, dword ptr [rdx]{1to8} (62 f2 75 38 36 02) must be rejected.
    insns = list(Decoder(64, bytes.fromhex("62 f2 75 38 36 02 c3"), ip=0x1000))
    assert insns[0].is_broadcast
    try:
        lower(insns, [], {}, {}, {})
    except ValueError as exc:
        if not str(exc).startswith("unsupported query operation at 0x1000"):
            raise AssertionError(f"unexpected diagnostic {exc}") from exc
    else:
        raise AssertionError("accepted EVEX broadcast vpermd")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check_rejections()
        check(native, other)
    else:
        raise ValueError(mode)
