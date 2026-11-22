"""Differential checks, divide errors and rejection controls for RDX:RAX multiplies, divides and
sign extensions."""

import ctypes
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

import pefile
from iced_x86 import Decoder, Mnemonic

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_switch_aot import translate
from cpu_leaf_aot import export_rva
from direct_check import GUARDS, MASK, SENTINELS, Word, input_pairs, observe, register_probe

M32 = (1 << 32) - 1
INT32_MIN, INT64_MIN = 1 << 31, 1 << 63  # as unsigned register values
DIVISOR = 0x123456789ABCDEF1  # the fixed divisor of udiv128
NAMES = ("div32", "idiv32", "div64", "udiv128", "idiv64", "mul64", "imul64_1", "mul32", "imul32",
         "mul8", "mul16", "widen", "sign_dx")
# The largest quotients that fit, the minimum dividends, rounding toward zero across the sign
# boundaries, and upper register halves that the 32-bit forms must ignore.
EDGES = {
    "div32": [(0x12345677ffffffff, 0x12345678), (0xfffffffeffffffff, M32), (M32, 0xdeadbeef00000001), (0, M32)],
    "idiv32": [(INT32_MIN, 1), (INT32_MIN, 2), (INT32_MIN, M32 - 1), (M32, 2), (7, M32 - 1), (M32 - 6, 2),
               (0x7fffffff, M32), (INT32_MIN, INT32_MIN), (0xdeadbeef00000000 | INT32_MIN, 0xfeedface00000003)],
    "div64": [(MASK, 1), (MASK, MASK), (MASK, INT64_MIN), (INT64_MIN, 3)],
    "udiv128": [(DIVISOR - 1, MASK), (DIVISOR - 1, 0), (0, MASK)],
    "idiv64": [(INT64_MIN, 1), (INT64_MIN, 2), (INT64_MIN, MASK - 1), (MASK, 2), (7, MASK - 1), (MASK - 6, 2),
               (INT64_MIN - 1, MASK), (INT64_MIN, INT64_MIN)],
}
FAULTS = (("div32", 5, 0, "zero divisor"), ("div32", 1 << 32, 1, "quotient above 32 bits"),
          ("idiv32", 5, 0xffffffff00000000, "zero divisor"), ("idiv32", INT32_MIN, M32, "-2^31 / -1"),
          ("div64", 5, 0, "zero divisor"), ("udiv128", DIVISOR, 0, "quotient above 64 bits"),
          ("idiv64", 5, 0, "zero divisor"), ("idiv64", INT64_MIN, MASK, "-2^63 / -1"))
# ctypes turns the structured exception of a divide error into OSError with one of these messages.
DIVIDE_ERRORS = ("exception: integer divide by zero", "exception: integer overflow")


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def merge(register, value, width):
    """An x86 write of the low width bytes of value into register."""
    low = (1 << width * 8) - 1
    return (register & ~low | value & low) & MASK


def truncated(dividend, divisor):
    """IDIV rounds the quotient toward zero, unlike Python's //, which rounds toward minus infinity."""
    quotient = abs(dividend) // abs(divisor)
    if (dividend < 0) != (divisor < 0):
        quotient = -quotient
    return quotient, dividend - quotient * divisor


def reference(name, x, y):
    """RAX and the guarded trace after name(x, y, trace), or None when the divide faults."""
    trace = [MASK] * 3
    if name == "div32":
        divisor = y & M32
        if divisor == 0 or x >> 32 >= divisor:
            return None
        rax, trace[0] = divmod(x, divisor)
    elif name in ("idiv32", "idiv64"):
        bits = 32 if name == "idiv32" else 64
        dividend, divisor = signed(x, bits), signed(y, bits)
        if divisor == 0 or (dividend == -1 << bits - 1 and divisor == -1):
            return None
        quotient, remainder = truncated(dividend, divisor)
        rax, trace[0] = quotient & (1 << bits) - 1, remainder & (1 << bits) - 1
        if name == "idiv64":
            trace[1] = y
    elif name == "div64":
        if y == 0:
            return None
        rax, trace[0] = divmod(x, y)
    elif name == "udiv128":
        if x >= DIVISOR:
            return None
        rax, trace[0] = divmod(x << 64 | y, DIVISOR)
    elif name in ("mul64", "imul64_1"):
        product = x * y if name == "mul64" else signed(x, 64) * signed(y, 64) & (1 << 128) - 1
        rax, trace[0] = product & MASK, product >> 64
        if name == "imul64_1":
            trace[1] = y
    elif name in ("mul32", "imul32"):
        product = (x & M32) * (y & M32) if name == "mul32" else signed(x, 32) * signed(y, 32) & MASK
        rax, trace[0] = product & M32, product >> 32
    elif name == "mul8":
        trace[0], trace[1] = merge(x, (x & 0xff) * (y & 0xff), 2), y
        rax = merge(x, signed(x, 8) * signed(y, 8), 2)
    elif name == "mul16":
        product = (x & 0xffff) * (y & 0xffff)
        trace[0], trace[1] = merge(x, product, 2), merge(y, product >> 16, 2)
        product = signed(x, 16) * signed(y, 16) & M32
        rax, trace[2] = merge(x, product, 2), merge(y, product >> 16, 2)
    elif name == "widen":
        trace = [merge(x, signed(x, 8), 2), signed(x, 16) & M32, signed(x, 32) & MASK]
        rax = signed(y, 8) & MASK
    elif name == "sign_dx":
        trace[0] = M32 if x >> 31 & 1 else 0
        trace[1] = MASK if y >> 63 else 0
        trace[2] = merge(trace[1], 0xffff if x >> 15 & 1 else 0, 2)
        rax = merge(y, int(signed(x, 64) < signed(y, 64)), 1)
    return rax, (GUARDS[0], *trace, GUARDS[1])


def check(probe_path, original_path, lifted_path):
    probe = register_probe(probe_path)
    native, lifted = ctypes.CDLL(original_path), ctypes.CDLL(lifted_path)
    total = 0
    for name in NAMES:
        source, translation = getattr(native, name), getattr(lifted, "lifted_" + name)
        compared = faulting = 0
        for x, y in input_pairs() + EDGES.get(name, []):
            want = reference(name, x, y)
            if want is None:
                faulting += 1
                continue
            original, actual = observe(probe, source, x, y), observe(probe, translation, x, y)
            if original != (*want, SENTINELS):
                raise AssertionError(f"original {name}({x:#x}, {y:#x}): {original} != {want}")
            if actual != original:
                raise AssertionError(f"lifted_{name}({x:#x}, {y:#x}): {actual} != {original}")
            compared += 1
        total += compared
        print(f"{name}: {compared} inputs match the reference" + (f", {faulting} faulting inputs skipped" if faulting else ""))
    print(f"{total} inputs match the reference and the original in RAX, the guarded trace, RBX and RSI")
    check_faults(probe, native, lifted)


def raised(probe, function, x, y):
    """The message of the OSError that ctypes raises for the call, or its result, and the trace."""
    trace = (Word * 5)(GUARDS[0], MASK, MASK, MASK, GUARDS[1])
    output = ctypes.cast(ctypes.byref(trace, ctypes.sizeof(Word)), ctypes.POINTER(Word))
    try:
        outcome = f"returned {probe(function, x, y, output, (Word * 2)()):#x}"
    except OSError as error:
        outcome = str(error)
    return outcome, tuple(trace)


def check_faults(probe, native, lifted):
    """A divide error must be raised by the original and the translation alike."""
    for name, x, y, case in FAULTS:
        if reference(name, x, y) is not None:
            raise AssertionError(f"{name}({x:#x}, {y:#x}) does not fault in the reference")
        original = raised(probe, getattr(native, name), x, y)
        actual = raised(probe, getattr(lifted, "lifted_" + name), x, y)
        if original[0] not in DIVIDE_ERRORS or actual != original:
            raise AssertionError(f"{name}({x:#x}, {y:#x}), {case}: original {original}, translation {actual}")
        print(f"fault {name}({x:#x}, {y:#x}), {case}: original and translation raise OSError "
              f"'{original[0]}' and leave the same trace")


def instruction(pe, name, mnemonic, position=0):
    entry = export_rva(pe, name)
    found = [ins for ins in Decoder(64, pe.get_data(entry, 0x40), ip=entry) if ins.mnemonic == mnemonic]
    if len(found) <= position:
        raise AssertionError(f"no {mnemonic} at position {position} in {name}")
    return found[position]


def check_rejections(original_path):
    data = Path(original_path).read_bytes()
    with pefile.PE(data=data, fast_load=True) as pe:
        div = instruction(pe, "div32", Mnemonic.DIV)
        div64 = instruction(pe, "div64", Mnemonic.DIV)
        after = Decoder(64, pe.get_data(div64.next_ip, 0x10), ip=div64.next_ip).decode()
        controls = [
            ("div32", div, "41 f6 f1", "unsupported divide width"),  # div r9b: AH receives the remainder
            ("div32", div, "66 f7 f1", "unsupported divide width"),  # div cx
            # JE right after DIV reads flags that the flag model does not give DIV.
            ("div64", after, "74 01 90", "unsupported flag producer"),
            # CLC writes CF between CMP and SETL, so SETL may no longer read the comparison.
            ("sign_dx", instruction(pe, "sign_dx", Mnemonic.CDQ), "f8", "unsupported flag producer"),
            # MUL and CDQ read RAX, which is undefined at entry when the MOV before them writes RCX instead.
            ("mul64", instruction(pe, "mul64", Mnemonic.MOV), "48 8b c9",
             f"undefined register rax at RVA {instruction(pe, 'mul64', Mnemonic.MUL).ip:#x}"),
            ("idiv32", instruction(pe, "idiv32", Mnemonic.MOV, 1), "8b c9",
             f"undefined register rax at RVA {instruction(pe, 'idiv32', Mnemonic.CDQ).ip:#x}"),
            # DIV reads EDX, which holds a guest address after the LEA in guest_rdx.
            ("guest_rdx", instruction(pe, "guest_rdx", Mnemonic.MUL), "f7 f1",
             f"undefined register rdx at RVA {instruction(pe, 'guest_rdx', Mnemonic.MUL).ip:#x}"),
        ]
        offsets = [pe.get_offset_from_rva(ins.ip) for _, ins, _, _ in controls]
        guest_store = instruction(pe, "guest_rdx", Mnemonic.MOV, 1)
    with TemporaryDirectory() as folder:
        path = Path(folder) / "control.dll"
        for (name, ins, patch, reason), offset in zip(controls, offsets):
            patch = bytes.fromhex(patch)
            replacement = list(Decoder(64, patch, ip=ins.ip))
            if len(patch) != ins.len or any(r.is_invalid for r in replacement) or replacement[-1].next_ip != ins.next_ip:
                raise AssertionError(f"{name}: {ins} and {replacement} differ in length")
            damaged = bytearray(data)
            damaged[offset:offset + ins.len] = patch
            path.write_bytes(damaged)
            run_control(name, f"{ins} -> {'; '.join(map(str, replacement))}", path, reason)
    exports = (("mul_carry", "unsupported flag producer"),
               ("base_clobber", "table base rdx is not a RIP-relative address"),
               ("index_clobber", "jump-table index rdx is not the bounded value"),
               ("guest_rdx", f"undefined register rdx at RVA {guest_store.ip:#x}"))
    for name, reason in exports:
        run_control(name, "source export", original_path, reason)
    print(f"{len(controls) + len(exports)} rejection controls passed")


def run_control(name, change, image, reason):
    try:
        translate(image, [name])
    except ValueError as exc:
        if reason not in str(exc):
            raise AssertionError(f"{name} ({change}): expected {reason!r}, got {exc}") from exc
        print(f"rejected {name} ({change}): {exc}")
    else:
        raise AssertionError(f"accepted control {name} ({change})")


if __name__ == "__main__":
    check(*sys.argv[1:])
    check_rejections(sys.argv[2])
