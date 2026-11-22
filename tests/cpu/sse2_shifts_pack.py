"""Differential check for baseline 128-bit SSE2 packed shifts, packs, unpacks, shuffles, and movemask."""
import ctypes
import struct
import sys
from pathlib import Path

import pefile
from iced_x86 import Decoder

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

VEC_EXPORTS = (
    "psllw_imm_op", "psllw_reg_op", "pslld_imm_op", "pslld_reg_op", "psllq_imm_op", "psllq_reg_op",
    "psrlw_imm_op", "psrlw_reg_op", "psrld_imm_op", "psrld_reg_op", "psrlq_imm_op", "psrlq_reg_op",
    "psraw_imm_op", "psraw_reg_op", "psrad_imm_op", "psrad_reg_op",
    "pslldq_op", "psrldq_op",
    "packsswb_op", "packssdw_op", "packuswb_op",
    "punpcklbw_op", "punpcklwd_op", "punpckldq_op", "punpcklqdq_op",
    "punpckhbw_op", "punpckhwd_op", "punpckhdq_op", "punpckhqdq_op",
    "pshufd_op", "pshuflw_op", "pshufhw_op",
    "psrld_imm_32_op", "punpckhqdq_self_op", "pshufd_b3_op", "packssdw_reverse_regs_op",
)
ALL_EXPORTS = VEC_EXPORTS + ("pmovmskb_op",)


def emit(native_dll: Path, output_cpp: Path) -> None:
    parts = [INTEGER_HEADER]
    with pefile.PE(str(native_dll), fast_load=True) as pe:
        for name in ALL_EXPORTS:
            ranges = function_ranges(pe, export_rva(pe, name))
            body = [ins for lo, hi in ranges for ins in region(pe, lo, hi)]
            code = lower(body, ["rcx = a; rdx = b; r8 = dst;"], {}, {}, {})
            parts.append(
                f'extern "C" __declspec(dllexport) uint64_t {name}(uint64_t a, uint64_t b, uint64_t dst) {{\n{code}\n}}'
            )
    output_cpp.write_text("\n".join(parts) + "\n", encoding="utf-8")


def clamp(v: int, lo: int, hi: int) -> int:
    return lo if v < lo else (hi if v > hi else v)


def ref_vec(name: str, a: bytes, b: bytes) -> bytes:
    cnt_q = struct.unpack_from("<Q", b, 0)[0]
    if name in ("psllw_imm_op", "psllw_reg_op"):
        c = 5 if "imm" in name else cnt_q
        return struct.pack("<8H", *(0 if c >= 16 else ((x << c) & 0xffff) for x in struct.unpack("<8H", a)))
    if name in ("pslld_imm_op", "pslld_reg_op"):
        c = 11 if "imm" in name else cnt_q
        return struct.pack("<4I", *(0 if c >= 32 else ((x << c) & 0xffffffff) for x in struct.unpack("<4I", a)))
    if name in ("psllq_imm_op", "psllq_reg_op"):
        c = 19 if "imm" in name else cnt_q
        return struct.pack("<2Q", *(0 if c >= 64 else ((x << c) & 0xffffffffffffffff) for x in struct.unpack("<2Q", a)))
    if name in ("psrlw_imm_op", "psrlw_reg_op"):
        c = 5 if "imm" in name else cnt_q
        return struct.pack("<8H", *(0 if c >= 16 else (x >> c) for x in struct.unpack("<8H", a)))
    if name == "psrld_imm_32_op":
        return bytes(16)
    if name in ("psrld_imm_op", "psrld_reg_op"):
        c = 11 if "imm" in name else cnt_q
        return struct.pack("<4I", *(0 if c >= 32 else (x >> c) for x in struct.unpack("<4I", a)))
    if name in ("psrlq_imm_op", "psrlq_reg_op"):
        c = 19 if "imm" in name else cnt_q
        return struct.pack("<2Q", *(0 if c >= 64 else (x >> c) for x in struct.unpack("<2Q", a)))
    if name in ("psraw_imm_op", "psraw_reg_op"):
        c = min(5 if "imm" in name else cnt_q, 15)
        return struct.pack("<8h", *(x >> c for x in struct.unpack("<8h", a)))
    if name in ("psrad_imm_op", "psrad_reg_op"):
        c = min(11 if "imm" in name else cnt_q, 31)
        return struct.pack("<4i", *(x >> c for x in struct.unpack("<4i", a)))
    if name == "pslldq_op":
        return b"\x00" * 3 + a[:13]
    if name == "psrldq_op":
        return a[5:] + b"\x00" * 5
    if name == "packsswb_op":
        vals = list(struct.unpack("<8h", a)) + list(struct.unpack("<8h", b))
        return struct.pack("<16b", *(clamp(x, -128, 127) for x in vals))
    if name in ("packssdw_op", "packssdw_reverse_regs_op"):
        vals = list(struct.unpack("<4i", a)) + list(struct.unpack("<4i", b))
        return struct.pack("<8h", *(clamp(x, -32768, 32767) for x in vals))
    if name == "packuswb_op":
        vals = list(struct.unpack("<8h", a)) + list(struct.unpack("<8h", b))
        return struct.pack("<16B", *(clamp(x, 0, 255) for x in vals))
    if name == "punpcklbw_op":
        return bytes(v for pair in zip(a[:8], b[:8]) for v in pair)
    if name == "punpckhbw_op":
        return bytes(v for pair in zip(a[8:], b[8:]) for v in pair)
    if name == "punpcklwd_op":
        return struct.pack("<8H", *(v for pair in zip(struct.unpack("<8H", a)[:4], struct.unpack("<8H", b)[:4]) for v in pair))
    if name == "punpckhwd_op":
        return struct.pack("<8H", *(v for pair in zip(struct.unpack("<8H", a)[4:], struct.unpack("<8H", b)[4:]) for v in pair))
    if name == "punpckldq_op":
        return struct.pack("<4I", *(v for pair in zip(struct.unpack("<4I", a)[:2], struct.unpack("<4I", b)[:2]) for v in pair))
    if name == "punpckhdq_op":
        return struct.pack("<4I", *(v for pair in zip(struct.unpack("<4I", a)[2:], struct.unpack("<4I", b)[2:]) for v in pair))
    if name == "punpcklqdq_op":
        return a[:8] + b[:8]
    if name == "punpckhqdq_op":
        return a[8:] + b[8:]
    if name == "punpckhqdq_self_op":
        return a[8:] * 2
    if name in ("pshufd_op", "pshufd_b3_op"):
        imm = 0xB3 if name == "pshufd_b3_op" else 0xB1
        lanes = struct.unpack("<4I", a)
        return struct.pack("<4I", *(lanes[(imm >> (2 * i)) & 3] for i in range(4)))
    if name == "pshuflw_op":
        lo = struct.unpack("<4H", a[:8])
        return struct.pack("<4H", *(lo[(0x1B >> (2 * i)) & 3] for i in range(4))) + a[8:]
    if name == "pshufhw_op":
        hi = struct.unpack("<4H", a[8:])
        return a[:8] + struct.pack("<4H", *(hi[(0x4E >> (2 * i)) & 3] for i in range(4)))
    raise AssertionError(name)


def check_controls() -> None:
    controls = (
        ("MMX packsswb", "0f 63 c1 c3", "unsupported query operation"),
        ("memory packsswb", "66 0f 63 02 c3", "unsupported SSE2 source operand"),
        ("memory psllw", "66 0f f1 02 c3", "unsupported SSE2 shift source"),
        ("memory pshufd", "66 0f 70 02 1b c3", "unsupported SSE2 source operand"),
    )
    for label, code, diagnostic in controls:
        instructions = list(Decoder(64, bytes.fromhex(code), ip=0x1000))
        try:
            lower(instructions, [], {}, {}, {})
        except ValueError as exc:
            if not str(exc).startswith(f"{diagnostic} at 0x1000"):
                raise AssertionError(f"{label}: unexpected diagnostic {exc}") from exc
        else:
            raise AssertionError(f"accepted {label}")


def check(native_dll: Path, lifted_dll: Path) -> None:
    check_controls()
    native = ctypes.CDLL(str(native_dll))
    lifted = ctypes.CDLL(str(lifted_dll))
    a_bytes = bytes([
        0x00, 0x80, 0x7f, 0x01, 0xff, 0x7f, 0x00, 0xfe,
        0x81, 0x00, 0x12, 0x34, 0xab, 0xcd, 0xef, 0x90,
    ])
    # Test multiple b_bytes vectors so register-count shifts exercise small, boundary, and out-of-range (>=64) counts.
    b_vectors = [
        bytes([0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x01, 0x02, 0x7f, 0x80, 0x00, 0x7f]),
        bytes([0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        bytes([0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x7f, 0x00, 0x00, 0x80, 0xff, 0x7f]),
        # Low qword count 0x0000010000000003, with a signed word of 256 in RHS lane 2.
        struct.pack("<4I", 3, 256, 0, 0),
    ]
    a_buf = (ctypes.c_ubyte * 16)(*a_bytes)
    out_n = (ctypes.c_ubyte * 16)()
    out_l = (ctypes.c_ubyte * 16)()
    cases = 0
    for b_bytes in b_vectors:
        b_buf = (ctypes.c_ubyte * 16)(*b_bytes)
        for name in VEC_EXPORTS:
            fn_n = getattr(native, name)
            fn_l = getattr(lifted, name)
            fn_n.argtypes = fn_l.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
            fn_n.restype = fn_l.restype = ctypes.c_uint64
            fn_n(ctypes.addressof(a_buf), ctypes.addressof(b_buf), ctypes.addressof(out_n))
            fn_l(ctypes.addressof(a_buf), ctypes.addressof(b_buf), ctypes.addressof(out_l))
            got_n, got_l = bytes(out_n), bytes(out_l)
            expected = ref_vec(name, a_bytes, b_bytes)
            if got_n != expected or got_l != expected:
                raise AssertionError(f"{name}: expected={expected.hex()} native={got_n.hex()} lifted={got_l.hex()}")
            cases += 1
    # Check pmovmskb_op
    fn_n = native.pmovmskb_op
    fn_l = lifted.pmovmskb_op
    fn_n.argtypes = fn_l.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    fn_n.restype = fn_l.restype = ctypes.c_uint64
    for mask_input in (a_bytes, bytes(12) + b"\x80" + bytes(3)):
        mask_buf = (ctypes.c_ubyte * 16)(*mask_input)
        got_n = fn_n(ctypes.addressof(mask_buf), 0, 0)
        got_l = fn_l(ctypes.addressof(mask_buf), 0, 0)
        expected_mask = sum(((mask_input[i] >> 7) & 1) << i for i in range(16))
        if got_n != expected_mask or got_l != expected_mask:
            raise AssertionError(f"pmovmskb_op: expected={expected_mask:#x} native={got_n:#x} lifted={got_l:#x}")
        cases += 1
    print(f"{cases} baseline 128-bit SSE2 shift/pack/unpack/shuffle/movemask cases matched native and translated DLLs")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:4]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(Path(native), Path(other))
    else:
        raise SystemExit(f"unknown mode {mode}")
