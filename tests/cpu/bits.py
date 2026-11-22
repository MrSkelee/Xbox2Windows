"""Compare native and translated bit-manipulation and conversion instructions."""
import ctypes
from pathlib import Path
import sys

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64

UNARY_WITH_FLAGS = (
    "popcnt32", "popcnt64",
    "lzcnt32", "lzcnt64",
    "bsf32", "bsf64",
    "bsr32", "bsr64",
)
BINARY_WITH_FLAGS = (
    "bt32", "bt64",
    "bts32", "bts64",
    "btr32", "btr64",
    "btc32", "btc64",
)
UNARY_VALUE_ONLY = ("bswap32", "bswap64", "cbw_test", "cwde_test", "cdqe_test")
CONVERT_WITH_OUT = ("cwd_test", "cdq_test", "cqo_test")


def emit(image, output):
    parts = [
        "#include <intrin.h>\n",
        INTEGER_HEADER,
    ]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in UNARY_WITH_FLAGS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = flags_out;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word flags_out) {{\n{code}\n}}\n')
        for name in BINARY_WITH_FLAGS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = flags_out;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word flags_out) {{\n{code}\n}}\n')
        for name in UNARY_VALUE_ONLY:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a) {{\n{code}\n}}\n')
        for name in CONVERT_WITH_OUT:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = out_val;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word out_val) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in UNARY_WITH_FLAGS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, ctypes.POINTER(U64)], U64
    for name in BINARY_WITH_FLAGS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, U64, ctypes.POINTER(U64)], U64
    for name in UNARY_VALUE_ONLY:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64], U64
    for name in CONVERT_WITH_OUT:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [U64, ctypes.POINTER(U64)], U64
    return lib


def ref_popcnt(a, bits):
    mask = (1 << bits) - 1
    a &= mask
    cnt = bin(a).count("1")
    zf = 1 if a == 0 else 0
    return cnt, zf


def ref_lzcnt(a, bits):
    mask = (1 << bits) - 1
    a &= mask
    if a == 0:
        return bits, 2
    lz = bits - a.bit_length()
    zf = 1 if lz == 0 else 0
    return lz, zf


def ref_bsf(a, bits):
    mask = (1 << bits) - 1
    a &= mask
    if a == 0:
        return 0, 1  # ZF=1
    return (a & -a).bit_length() - 1, 0


def ref_bsr(a, bits):
    mask = (1 << bits) - 1
    a &= mask
    if a == 0:
        return 0, 1  # ZF=1
    return a.bit_length() - 1, 0


def ref_bswap(a, bits):
    mask = (1 << bits) - 1
    a &= mask
    b = a.to_bytes(bits // 8, byteorder="big")
    return int.from_bytes(b, byteorder="little")


def check(native_path, lifted_path):
    native = load_lib(native_path)
    lifted = load_lib(lifted_path)
    flag_slot = U64(0)
    values = (
        0, 1, 2, 3, 0x80, 0x100, 0x55aa55aa, 0x7fffffff, 0x80000000, 0xffffffff,
        0x100000000, 0xdeadbeef00000000, 0xdeadbeef00000001, 0x8000000000000000,
        0x7fffffffffffffff, 0xffffffffffffffff, 0x0123456789abcdef,
    )
    bit_indices = (0, 1, 7, 15, 31, 32, 63, 64, 127)

    checks = 0

    # 1. POPCNT
    for name, bits in (("popcnt32", 32), ("popcnt64", 64)):
        for a in values:
            want_v, want_f = ref_popcnt(a, bits)
            for lib, label in ((native, "native"), (lifted, "lifted")):
                flag_slot.value = 0xdeadbeef
                got_v = getattr(lib, name)(a, ctypes.byref(flag_slot))
                if (got_v, flag_slot.value) != (want_v, want_f):
                    raise AssertionError(f"{label} {name}({a:#x}) = ({got_v:#x}, {flag_slot.value:#x}), expected ({want_v:#x}, {want_f:#x})")
            checks += 1

    # 2. LZCNT
    for name, bits in (("lzcnt32", 32), ("lzcnt64", 64)):
        for a in values:
            want_v, want_f = ref_lzcnt(a, bits)
            for lib, label in ((native, "native"), (lifted, "lifted")):
                flag_slot.value = 0xdeadbeef
                got_v = getattr(lib, name)(a, ctypes.byref(flag_slot))
                if (got_v, flag_slot.value) != (want_v, want_f):
                    raise AssertionError(f"{label} {name}({a:#x}) = ({got_v:#x}, {flag_slot.value:#x}), expected ({want_v:#x}, {want_f:#x})")
            checks += 1

    # 3. BSF & BSR
    for name, ref_fn, bits in (
        ("bsf32", ref_bsf, 32),
        ("bsf64", ref_bsf, 64),
        ("bsr32", ref_bsr, 32),
        ("bsr64", ref_bsr, 64),
    ):
        for a in values:
            want_v, want_f = ref_fn(a, bits)
            for lib, label in ((native, "native"), (lifted, "lifted")):
                flag_slot.value = 0xdeadbeef
                got_v = getattr(lib, name)(a, ctypes.byref(flag_slot))
                if (got_v, flag_slot.value) != (want_v, want_f):
                    raise AssertionError(f"{label} {name}({a:#x}) = ({got_v:#x}, {flag_slot.value:#x}), expected ({want_v:#x}, {want_f:#x})")
            checks += 1

    # 4. BSWAP
    for name, bits in (("bswap32", 32), ("bswap64", 64)):
        for a in values:
            want_v = ref_bswap(a, bits)
            for lib, label in ((native, "native"), (lifted, "lifted")):
                got_v = getattr(lib, name)(a)
                if got_v != want_v:
                    raise AssertionError(f"{label} {name}({a:#x}) = {got_v:#x}, expected {want_v:#x}")
            checks += 1

    # 5. BT, BTS, BTR, BTC
    for name, bits, op in (
        ("bt32", 32, "test"), ("bt64", 64, "test"),
        ("bts32", 32, "set"), ("bts64", 64, "set"),
        ("btr32", 32, "reset"), ("btr64", 64, "reset"),
        ("btc32", 32, "comp"), ("btc64", 64, "comp"),
    ):
        mask = (1 << bits) - 1
        for a in values:
            for idx in bit_indices:
                bit_pos = idx & (bits - 1)
                cf = (a >> bit_pos) & 1
                want_f = (cf << 1)
                bit_val = 1 << bit_pos
                if op == "test":
                    want_v = 0
                elif op == "set":
                    want_v = ((a & mask) | bit_val) & mask
                elif op == "reset":
                    want_v = ((a & mask) & ~bit_val) & mask
                else:
                    want_v = ((a & mask) ^ bit_val) & mask

                for lib, label in ((native, "native"), (lifted, "lifted")):
                    flag_slot.value = 0xdeadbeef
                    got_v = getattr(lib, name)(a, idx, ctypes.byref(flag_slot))
                    if op == "test":
                        if flag_slot.value != want_f:
                            raise AssertionError(f"{label} {name}({a:#x}, {idx}) flag = {flag_slot.value:#x}, expected {want_f:#x}")
                    else:
                        if (got_v, flag_slot.value) != (want_v, want_f):
                            raise AssertionError(f"{label} {name}({a:#x}, {idx}) = ({got_v:#x}, {flag_slot.value:#x}), expected ({want_v:#x}, {want_f:#x})")
                checks += 1

    # 6. Conversion instructions
    for val in (-128, -1, 0, 1, 127):
        for lib, label in ((native, "native"), (lifted, "lifted")):
            got = getattr(lib, "cbw_test")(val & 0xff)
            want = val & 0xffff
            if got != want:
                raise AssertionError(f"{label} cbw({val}) = {got:#x}, expected {want:#x}")
        checks += 1

    for val in (-32768, -1, 0, 1, 32767):
        for lib, label in ((native, "native"), (lifted, "lifted")):
            got = getattr(lib, "cwde_test")(val & 0xffff)
            want = val & 0xffffffff
            if got != want:
                raise AssertionError(f"{label} cwde({val}) = {got:#x}, expected {want:#x}")
        checks += 1

    for val in (-0x80000000, -1, 0, 1, 0x7fffffff):
        for lib, label in ((native, "native"), (lifted, "lifted")):
            got = getattr(lib, "cdqe_test")(val & 0xffffffff)
            want = val & 0xffffffffffffffff
            if got != want:
                raise AssertionError(f"{label} cdqe({val}) = {got:#x}, expected {want:#x}")
        checks += 1

    # CWD, CDQ, CQO
    for val in (-32768, -1, 0, 1, 32767):
        want_dx = 0xffff if val < 0 else 0
        for lib, label in ((native, "native"), (lifted, "lifted")):
            flag_slot.value = 0xdeadbeef
            got_ax = getattr(lib, "cwd_test")(val & 0xffff, ctypes.byref(flag_slot))
            if (got_ax, flag_slot.value) != (val & 0xffff, want_dx):
                raise AssertionError(f"{label} cwd({val}) = ({got_ax:#x}, {flag_slot.value:#x}), expected ({val & 0xffff:#x}, {want_dx:#x})")
        checks += 1

    for val in (-0x80000000, -1, 0, 1, 0x7fffffff):
        want_edx = 0xffffffff if val < 0 else 0
        for lib, label in ((native, "native"), (lifted, "lifted")):
            flag_slot.value = 0xdeadbeef
            got_eax = getattr(lib, "cdq_test")(val & 0xffffffff, ctypes.byref(flag_slot))
            if (got_eax, flag_slot.value) != (val & 0xffffffff, want_edx):
                raise AssertionError(f"{label} cdq({val}) = ({got_eax:#x}, {flag_slot.value:#x}), expected ({val & 0xffffffff:#x}, {want_edx:#x})")
        checks += 1

    for val in (-0x8000000000000000, -1, 0, 1, 0x7fffffffffffffff):
        want_rdx = 0xffffffffffffffff if val < 0 else 0
        for lib, label in ((native, "native"), (lifted, "lifted")):
            flag_slot.value = 0xdeadbeef
            got_rax = getattr(lib, "cqo_test")(val & 0xffffffffffffffff, ctypes.byref(flag_slot))
            if (got_rax, flag_slot.value) != (val & 0xffffffffffffffff, want_rdx):
                raise AssertionError(f"{label} cqo({val}) = ({got_rax:#x}, {flag_slot.value:#x}), expected ({val & 0xffffffffffffffff:#x}, {want_rdx:#x})")
        checks += 1

    print(f"{checks} bit manipulation and sign conversion cases matched native and translated DLLs")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "emit":
        emit(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "check":
        check(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        print("usage: bits.py emit <pe> <out.cpp> | check <native.dll> <lifted.dll>", file=sys.stderr)
        sys.exit(2)
