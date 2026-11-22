"""Native/AOT/reference comparisons for string transfers in the control-flow lifter."""
import ctypes as C
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

import pefile
from iced_x86 import Decoder, Formatter, FormatterSyntax, Mnemonic as M, Register as R

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from cpu_leaf_aot import bounded_code, export_rva
from cpu_switch_aot import Lifter, PRELUDE, translate

WORD = C.c_uint64
MASK = (1 << 64) - 1
SENTINELS = (0x0123456789abcdef, 0xfedcba9876543210, 0)
GUARDS = (0xa55aa55adeadbeef, 0x5aa55aa5feedface)
WIDTHS = dict(b=1, w=2, d=4, q=8)
NAMES = ('rep_movsb_forward', 'rep_movsw_forward', 'rep_movsd_forward', 'rep_movsq_forward', 'rep_stosb_forward', 'rep_stosw_forward', 'rep_stosd_forward', 'rep_stosq_forward', 'rep_movsb_backward', 'rep_movsw_backward', 'rep_movsd_backward', 'rep_movsq_backward', 'rep_stosb_backward', 'rep_stosw_backward', 'rep_stosd_backward', 'rep_stosq_backward', 'branch_direction', 'loop_copy', 'call_copy')


def spec(name, backwards):
    if name in ('branch_direction', 'loop_copy', 'call_copy'):
        return 'movs', 1, True, backwards if name == 'branch_direction' else False, 3 if name == 'loop_copy' else 1
    repeat, operation, direction = name.split('_')
    return operation[:-1], WIDTHS[operation[-1]], repeat == 'rep', direction == 'backward', 1


def reference(initial, source, target, fill, count, name, backwards):
    """Read each element from the current byte array; deliberately preserve destructive overlap."""
    kind, width, repeated, backwards, outer = spec(name, backwards)
    memory = bytearray(initial)
    step = -width if backwards else width
    for _ in range(outer):
        for _ in range(count if repeated else 1):
            value = bytes(memory[source:source+width]) if kind == 'movs' else (fill & ((1 << (width*8))-1)).to_bytes(width, 'little')
            assert len(value) == width and 0 <= target <= len(memory)-width
            memory[target:target+width] = value
            if kind == 'movs':
                source += step
            target += step
    return bytes(memory), (0 if repeated else count), source, target, 0 if name == 'loop_copy' else int(count < 3)


def rejection_checks(image):
    data = Path(image).read_bytes()
    cases = [(name, data, 'direction flag') for name in ('bad_df_call', 'bad_df_tail', 'bad_df_join')]
    with pefile.PE(str(image), fast_load=True) as pe:
        def instructions(name):
            start = export_rva(pe, name)
            return list(Decoder(64, bounded_code(pe, start), ip=start))
        def patch(name, select, replacement, expected):
            ins = next(i for i in instructions(name) if select(i))
            assert len(replacement) == ins.len
            pos = pe.get_offset_from_rva(ins.ip)
            altered = bytearray(data)
            altered[pos:pos+ins.len] = replacement
            cases.append((name, altered, expected))
        patch('rep_movsb_backward', lambda i: i.mnemonic == M.CLD, b'\x90', 'direction flag')
        patch('branch_direction', lambda i: i.mnemonic == M.CLD, b'\xfd', 'direction flag')
        patch('call_copy', lambda i: i.mnemonic == M.CALL, b'\xfd\x90\x90\x90\x90', 'direction flag')
        patch('rep_movsb_forward', lambda i: i.mnemonic == M.POP, b'\x90', 'stack not balanced')
        patch('rep_movsb_forward', lambda i: i.mnemonic == M.MOVSB, b'\xf2\xa4', 'unsupported prefix')
        # Do not invent an RSI/RDI value if the only definition is removed.
        patch('rep_movsb_forward', lambda i: i.mnemonic == M.MOV and i.op0_register == R.RSI,
              b'\x90'*3, 'nonvolatile register')
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / 'rejected.dll'
        for name, altered, expected in cases:
            path.write_bytes(altered)
            try:
                translate(path, [name])
            except ValueError as exc:
                assert expected in str(exc), (name, expected, str(exc))
            else:
                raise AssertionError(f'Accepted {name}: {expected}')
    # Address-size, thread-segment bases, repeat misuse and SSE MOVSD stay outside this profile.
    for raw in ('67f3a4', '64f3a4', 'f2a4', 'f00fae00', 'f20f10c1'):
        instruction = next(iter(Decoder(64, bytes.fromhex(raw))))
        try:
            Lifter().statement(instruction)
        except (ValueError, KeyError):
            pass
        else:
            raise AssertionError(f'Accepted unsupported {instruction}')
    print(f'{len(cases)} whole-PE rejection controls and 5 unsupported forms rejected')


def emit_mutants(image, output):
    """Three incorrect implementations that the public comparison must distinguish."""
    bodies = []
    for name, export, old, new in (
        ('rep_movsb_backward', 'bad_direction', 'direction ? 0ull - 1ull : 1ull', '1ull'),
        ('rep_movsb_forward', 'bad_overlap',
         'while (rcx != 0) { *reinterpret_cast<volatile std::uint8_t*>(rdi) = load_always<std::uint8_t>(rsi); rsi += step; rdi += step; --rcx; }',
         'std::memmove(reinterpret_cast<void*>(rdi), reinterpret_cast<void*>(rsi), static_cast<std::size_t>(rcx)); rsi += rcx; rdi += rcx; rcx = 0;'),
        ('rep_movsq_forward', 'bad_count', '--rcx;', 'rcx = 0;'),
    ):
        source, _ = translate(image, [name])
        assert source.startswith(PRELUDE) and old in source
        body = source[len(PRELUDE):].replace('lifted_'+name, export).replace(old, new)
        bodies.append(body)
    Path(output).write_text(PRELUDE + '\n'.join(bodies), encoding='utf-8')


def mutation_controls(path):
    library = C.CDLL(str(Path(path).resolve()))
    for export, name, src, dst, backwards in (
        ('bad_direction', 'rep_movsb_backward', 64, 96, True),
        ('bad_overlap', 'rep_movsb_forward', 64, 65, False),
        ('bad_count', 'rep_movsq_forward', 16, 160, False),
    ):
        data = (C.c_ubyte * 256)(*range(256))
        base = C.addressof(data)
        expected, left, end_src, end_dst, flag = reference(bytes(data), src, dst, 0, 7, name, backwards)
        context = (WORD * 4)(base+src, base+dst, 0, int(backwards))
        trace = (WORD * 4)()
        function = getattr(library, export)
        function.argtypes, function.restype = [WORD, WORD, C.POINTER(WORD)], WORD
        result = function(C.addressof(context), 7, trace)
        assert (bytes(data), result, tuple(trace)) != (expected, left, (left, base+end_src, base+end_dst, flag)), export
    print('3 compiled /O2 semantic mutations detected: ignored DF, memmove overlap, truncated REP count')


def differential(probe_path, native_path, *lifted_paths):
    probe = C.CDLL(str(Path(probe_path).resolve())).probe
    probe.argtypes = [C.c_void_p, WORD, WORD, C.POINTER(WORD), C.POINTER(WORD)]
    probe.restype = WORD
    libraries = [C.CDLL(str(Path(path).resolve())) for path in (native_path, *lifted_paths)]
    storage = (C.c_ubyte * 1024)()
    base = C.addressof(storage)
    initial = bytes((i*73 + (i >> 3)*19 + 17) & 255 for i in range(len(storage)))
    cases = 0
    for name in NAMES:
        functions = [getattr(lib, ('' if n == 0 else 'lifted_') + name) for n, lib in enumerate(libraries)]
        for count in (0, 1, 2, 3, 7, 16, 31):
            for delta in (None, -7, -1, 0, 1, 7):
                for fill in (0, 0x80ff7f0100ff0180, MASK):
                    for backwards in ((False, True) if name == 'branch_direction' else (False,)):
                        source, target = (256, 640) if delta is None else (512, 512+delta)
                        expected, left, source_end, target_end, flag = reference(initial, source, target, fill, count, name, backwards)
                        context = (WORD * 4)(base+source, base+target, fill, int(backwards))
                        for function in functions:
                            storage[:] = initial
                            trace = (WORD * 6)(GUARDS[0], MASK, MASK, MASK, MASK, GUARDS[1])
                            observed = (WORD * 3)()
                            pointer = C.cast(C.byref(trace, 8), C.POINTER(WORD))
                            result = probe(function, C.addressof(context), count, pointer, observed)
                            wanted = (GUARDS[0], left, base+source_end, base+target_end, flag, GUARDS[1])
                            if (result != left or tuple(trace) != wanted or bytes(storage) != expected
                                    or tuple(observed) != SENTINELS):
                                raise AssertionError((name, count, delta, fill, backwards, result, tuple(trace), wanted,
                                                      tuple(observed), 'memory matches', bytes(storage) == expected))
                            cases += 1
    # Genuine guard pages, not a null address that an optimizer can reason about.
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_uint32]
    kernel.VirtualAlloc.restype = C.c_void_p
    kernel.VirtualFree.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32]
    kernel.VirtualFree.restype = C.c_int
    inaccessible = kernel.VirtualAlloc(None, 4096, 0x3000, 0x01)
    if not inaccessible:
        raise C.WinError(C.get_last_error())
    try:
        for name in NAMES:
            if not name.startswith('rep_'):
                continue
            for n, lib in enumerate(libraries):
                function = getattr(lib, ('' if n == 0 else 'lifted_')+name)
                context = (WORD * 4)(inaccessible, inaccessible, MASK, 0)
                trace, observed = (WORD * 4)(), (WORD * 3)()
                assert probe(function, C.addressof(context), 0, trace, observed) == 0
                assert tuple(trace) == (0, inaccessible, inaccessible, 1) and tuple(observed) == SENTINELS
                cases += 1
    finally:
        if not kernel.VirtualFree(inaccessible, 0, 0x8000):
            raise C.WinError(C.get_last_error())
    print(f'{cases} native/AOT/reference cases passed: bytes, guards, remaining count, pointers, CF, RSI/RDI and DF')


def faults(guard_path, native_path, *lifted_paths):
    guarded = C.CDLL(str(Path(guard_path).resolve())).guarded_call
    guarded.argtypes = [C.c_void_p, WORD, WORD, C.POINTER(WORD), C.POINTER(WORD)]
    guarded.restype = C.c_uint32
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_uint32]
    kernel.VirtualAlloc.restype = C.c_void_p
    kernel.VirtualProtect.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.POINTER(C.c_uint32)]
    kernel.VirtualFree.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32]
    page = kernel.VirtualAlloc(None, 8192, 0x3000, 0x04)
    if not page:
        raise C.WinError(C.get_last_error())
    old = C.c_uint32()
    if not kernel.VirtualProtect(page+4096, 4096, 0x01, C.byref(old)):
        kernel.VirtualFree(page, 0, 0x8000)
        raise C.WinError(C.get_last_error())
    count = 0
    split_element_results = {}
    try:
        for path in (native_path, *lifted_paths):
            lib = C.CDLL(str(Path(path).resolve()))
            prefix = '' if path == native_path else 'lifted_'
            for suffix in WIDTHS:
                for kind in ('movs', 'stos'):
                    if 'rep_'+kind+suffix+'_forward' not in NAMES:
                        continue
                    function = getattr(lib, prefix+'rep_'+kind+suffix+'_forward')
                    for source, destination in ((0, 0), (page+4096, page), (page, page+4096)):
                        if kind == 'stos' and destination == page:
                            continue  # STOS does not access the source.
                        context = (WORD * 4)(source, destination, MASK, 0)
                        trace, result = (WORD * 4)(MASK, MASK, MASK, MASK), WORD()
                        code = guarded(function, C.addressof(context), 1, trace, C.byref(result))
                        assert code == 0xc0000005 and tuple(trace) == (MASK,)*4, (kind, suffix, hex(code), tuple(trace))
                        count += 1
            # A word, dword or qword can straddle a page. Match native bytes even
            # when the faulting access is within one element, not between iterations.
            for suffix in ("w", "d", "q"):
                function = getattr(lib, prefix + "rep_movs" + suffix + "_forward")
                for access in ("source", "destination"):
                    C.memset(page, 0xa5, 4096)
                    C.memset(page + 16, 0x6c, 8)
                    edge = page + 4095
                    source, destination = (edge, page + 32) if access == "source" else (page + 16, edge)
                    context = (WORD * 4)(source, destination, 0, 0)
                    trace, result = (WORD * 4)(MASK, MASK, MASK, MASK), WORD()
                    code = guarded(function, C.addressof(context), 1, trace, C.byref(result))
                    assert code == 0xc0000005 and tuple(trace) == (MASK,) * 4, (suffix, access, hex(code))
                    written = C.string_at(page + 32, 8) + C.string_at(edge, 1)
                    key = (suffix, access)
                    assert written == split_element_results.setdefault(key, written), (key, written)
                    count += 1
            # Three byte iterations complete before a source page fault. The trace
            # follows REP, so no trace store may move before the faulting instruction.
            C.memmove(page+4093, b'abc', 3)
            target = (C.c_ubyte * 16)(*[0xa5]*16)
            context = (WORD * 4)(page+4093, C.addressof(target)+4, 0, 0)
            trace, result = (WORD * 4)(MASK, MASK, MASK, MASK), WORD()
            code = guarded(getattr(lib, prefix+'rep_movsb_forward'), C.addressof(context), 8, trace, C.byref(result))
            assert code == 0xc0000005 and bytes(target) == bytes([0xa5]*4)+b'abc'+bytes([0xa5]*9)
            assert tuple(trace) == (MASK,)*4
            count += 1
    finally:
        if not kernel.VirtualFree(page, 0, 0x8000):
            raise C.WinError(C.get_last_error())
    print(f'{count} nonzero-count access violations preserved, including /O2')


if __name__ == '__main__':
    mode, *args = sys.argv[1:]
    if mode == 'emit':
        source, _ = translate(args[0], NAMES)
        Path(args[1]).write_text(source, encoding='utf-8')
    elif mode == 'mutants':
        emit_mutants(*args)
    elif mode == 'check':
        probe, guard, native, lifted, optimized, mutant = args
        record = os.environ.get('FORM_COVERAGE_RECORD')
        if record:
            Path(record).unlink(missing_ok=True)
        rejection_checks(native)
        differential(probe, native, lifted, optimized)
        faults(guard, native, lifted, optimized)
        mutation_controls(mutant)
        if record:
            # Decode the functions actually compared, not the MASM macro invocations.
            _, functions = translate(native, NAMES)
            formatter = Formatter(FormatterSyntax.NASM)
            forms = set()
            for function in functions:
                for ins in function.instructions.values():
                    words = formatter.format(ins).split()
                    forms.add(words[1] if words[0] in ('rep', 'repe', 'repne') else words[0])
            destination = Path(record)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(''.join(word+'\n' for word in sorted(forms)), encoding='utf-8')
    else:
        raise ValueError('Expected emit or check')
