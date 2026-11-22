"""Native/AOT differential checks for integer OF/PF conditional consumers."""
import ctypes
import os
from pathlib import Path
import random
import struct
import sys
from tempfile import TemporaryDirectory

import pefile
from iced_x86 import Decoder, Mnemonic

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from cpu_switch_aot import translate
from cpu_leaf_aot import export_rva

OPS = ('cmp', 'sub', 'add', 'test', 'and', 'or', 'xor', 'inc', 'dec')
BITS = (8, 16, 32, 64)
CONDITIONS = ('o', 'no', 'p', 'np')
def conditions(op):
    if op == 'add':
        return CONDITIONS + ('e', 'ne', 's', 'ns')
    if op in ('cmp', 'sub'):
        return CONDITIONS + ('l', 'ge', 'le', 'g')
    return CONDITIONS


NAMES = [f'flags_{op}_{bits}_{cc}' for op in OPS for bits in BITS for cc in conditions(op)]
MASK64 = (1 << 64) - 1


def reference(op, bits, a, b):
    mask, sign = (1 << bits) - 1, 1 << (bits - 1)
    a, b = a & mask, b & mask
    signed = lambda v: v - (1 << bits) if v >= sign else v
    if op in ('cmp', 'sub'):
        result, exact = a - b, signed(a) - signed(b)
    elif op == 'add':
        result, exact = a + b, signed(a) + signed(b)
    elif op == 'inc':
        result, exact = a + 1, signed(a) + 1
    elif op == 'dec':
        result, exact = a - 1, signed(a) - 1
    else:
        result = {'test': a & b, 'and': a & b, 'or': a | b, 'xor': a ^ b}[op]
        exact = 0  # Logical producers clear overflow.
    overflow = not -sign <= exact < sign
    parity = ((result & 0xff).bit_count() % 2) == 0
    return dict(o=overflow, no=not overflow, p=parity, np=not parity,
                e=(result & mask) == 0, ne=(result & mask) != 0,
                s=bool(result & sign), ns=not bool(result & sign),
                l=signed(a) < signed(b), ge=signed(a) >= signed(b),
                le=signed(a) <= signed(b), g=signed(a) > signed(b))


def inputs(bits):
    sign, mask = 1 << (bits - 1), (1 << bits) - 1
    edges = sorted({0, 1, 2, 3, 0x7f, 0x80, 0xff, 0x100, 0x101, sign - 1, sign, sign + 1, mask - 1, mask})
    pairs = [(a, b) for a in edges for b in edges]
    # Every low result byte, both operand signs, and arbitrary upper input bytes.
    for a in range(256):
        pairs.extend((a | (0x123456789abc0000 & ~mask & MASK64), b)
                     for b in (0, 1, 3, sign - 1, sign, mask))
    rng = random.Random(0x0f02 + bits)
    pairs.extend((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(128))
    return pairs


def rejected(image):
    data = bytearray(Path(image).read_bytes())
    with pefile.PE(data=data, fast_load=True) as pe:
        entry = export_rva(pe, 'flags_add_64_o')
        body = list(Decoder(64, pe.get_data(entry, 96), ip=entry))
        producer = next(i for i in body if i.mnemonic == Mnemonic.ADD)
        at = pe.get_offset_from_rva(producer.ip)
    if producer.len != 3:
        raise AssertionError('unexpected ADD fixture encoding')
    # Shift flags cannot be substituted for those of the ADD. Variable-count
    # shifts have flag-preserving and undefined-OF cases outside this profile.
    data[at:at + 3] = bytes.fromhex('48 d3 e0')  # SHL RAX, CL
    with TemporaryDirectory() as tmp:
        target = Path(tmp) / 'shift-producer.dll'
        target.write_bytes(data)
        try:
            translate(target, ['flags_add_64_o'])
        except ValueError as exc:
            if 'unsupported flag producer' not in str(exc):
                raise
        else:
            raise AssertionError('accepted a shift as the OF/PF producer')
    print('unsupported shift flag producer rejected')


def check(original, lifted):
    libraries = [ctypes.CDLL(str(Path(p).resolve())) for p in (original, lifted)]
    buffer = (ctypes.c_ubyte * 16)()
    count = 0
    for op in OPS:
        for bits in BITS:
            pairs = inputs(bits)
            for cc in conditions(op):
                name = f'flags_{op}_{bits}_{cc}'
                functions = [getattr(lib, prefix + name) for lib, prefix in zip(libraries, ('', 'lifted_'))]
                for function in functions:
                    function.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p]
                    function.restype = ctypes.c_uint64
                for a, b in pairs:
                    take = int(reference(op, bits, a, b)[cc])
                    expected = bytearray(b'\xa5' * 16)
                    expected[0] = take
                    selected = (17 if take else 42) | ((1 << 32) if bits == 64 else 0)
                    struct.pack_into('<Q' if bits == 64 else '<I', expected, 4, selected)
                    for label, function in zip(('native', 'lifted'), functions):
                        ctypes.memset(buffer, 0xa5, 16)
                        result = function(a, b, buffer)
                        if result != take or bytes(buffer) != expected:
                            raise AssertionError(f'{label} {name}({a:#x},{b:#x}): '
                                                 f'return={result}, trace={bytes(buffer).hex()}, expected={expected.hex()}')
                    count += 1
    rejected(original)
    record = os.environ.get('FORM_COVERAGE_RECORD')
    if record:
        from iced_x86 import Formatter, FormatterSyntax
        formatter = Formatter(FormatterSyntax.INTEL)
        _, translated = translate(original, NAMES)
        forms = {formatter.format_mnemonic(ins).lower()
                 for function in translated for ins in function.instructions.values()}
        Path(record).parent.mkdir(parents=True, exist_ok=True)
        Path(record).write_text(''.join(word + '\n' for word in sorted(forms)), encoding='utf-8')
    print(f'{len(NAMES)} exports: {count} native/AOT/reference comparisons passed '
          '(Jcc, SETcc, CMOVcc; 8/16/32/64-bit producers; output guards intact)')


if __name__ == '__main__':
    mode, original, destination = sys.argv[1:]
    if mode == 'emit':
        Path(destination).write_text(translate(original, NAMES)[0], encoding='utf-8')
    elif mode == 'check':
        if os.environ.get('FORM_COVERAGE_RECORD'):
            Path(os.environ['FORM_COVERAGE_RECORD']).unlink(missing_ok=True)
        check(original, destination)
    else:
        raise SystemExit('expected emit or check')
