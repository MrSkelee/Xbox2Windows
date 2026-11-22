"""Compare AMD64 HIGHLOW/DIR64 fixups with Windows without calling patched guest code."""
import ctypes as C
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory

import pefile

from native_map_check import Mapper, kernel


def check(mapper_path, fixture, provider_path):
    fixture, provider_path = Path(fixture).resolve(), Path(provider_path).resolve()
    original = fixture.read_bytes()
    with pefile.PE(str(fixture)) as pe:
        entries = [entry for block in pe.DIRECTORY_ENTRY_BASERELOC for entry in block.entries if entry.type == 10]
        assert len(entries) == 1
        entry = entries[0]
        patch, slot = entry.struct.get_file_offset(), entry.rva
        reloc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
        directory, directory_size = reloc.VirtualAddress, reloc.Size
        block_offset = patch - 8
        preferred, size = pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SizeOfImage
        data_offset = pe.get_offset_from_rva(slot)
        section = next(s for s in pe.sections if s.VirtualAddress <= slot < s.VirtualAddress+s.SizeOfRawData)
        virtual_size_offset = section.get_file_offset()+8
        virtual_size = max(section.Misc_VirtualSize, 64)
        assert struct.unpack_from('<I', original, block_offset+4)[0] == 12
        assert struct.unpack_from('<H', original, patch+2)[0] == 0  # padding entry for mixed-width case

    mapper = Mapper(str(Path(mapper_path).resolve()))
    provider = C.CDLL(str(provider_path))
    bindings = {provider_path.name.casefold(): provider}
    kernel.VirtualAlloc.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_uint32]
    kernel.VirtualAlloc.restype = C.c_void_p
    kernel.VirtualFree.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32]
    kernel.VirtualFree.restype = C.c_int
    # An existing allocation also forces rebasing. If the preferred address is
    # free, reserve it so neither side can accidentally avoid applying the delta.
    reservation = kernel.VirtualAlloc(preferred, size, 0x2000, 0x01)

    def variant(target, kind, seed=None, mixed=False):
        data = bytearray(original)
        # Put guard bytes and the second fixup inside the declared section, not
        # section padding whose copy behavior differs between the two loaders.
        struct.pack_into('<I', data, virtual_size_offset, virtual_size)
        struct.pack_into('<I', data, block_offset, target & ~0xfff)
        struct.pack_into('<H', data, patch, (target & 0xfff) | (kind << 12))
        if seed is not None:
            offset = data_offset + target - slot
            data[offset-1:offset+9] = b'\x5a' + struct.pack('<I', seed) + b'\xa5\xc3\xd2\xe1\xf0'
        fixes = [(target, 4 if kind == 3 else 8, seed if seed is not None else 0)]
        if mixed:
            struct.pack_into('<H', data, patch, 0xa000 | (slot & 0xfff))
            struct.pack_into('<H', data, patch+2, 0x3000 | ((slot+8) & 0xfff))
            struct.pack_into('<I', data, data_offset+8, 0xfffffff0)
            struct.pack_into('<I', data, data_offset+12, 0x5aa5c33c)
            fixes = [(slot, 8, struct.unpack_from('<Q', original, data_offset)[0]), (slot+8, 4, 0xfffffff0)]
        return data, fixes

    positives = [
        ('zero', *variant(slot, 3, 0)),
        ('carry', *variant(slot, 3, 0xffffffff)),
        ('sign', *variant(slot, 3, 0x80000000)),
        ('unaligned', *variant(slot+1, 3, 0x12345678)),
        ('mixed', *variant(slot, 10, mixed=True)),
        ('image-final-dword', *variant(size-4, 3)),
        ('before-driver', *variant(directory-4, 3)),
    ]
    try:
        with TemporaryDirectory() as tmp:
            for name, data, fixes in positives:
                path = Path(tmp)/(name+'.dll')
                path.write_bytes(data)
                native = kernel.LoadLibraryExW(str(path), None, 1)  # DONT_RESOLVE_DLL_REFERENCES
                if not native:
                    raise C.WinError(C.get_last_error())
                base = None
                try:
                    base, status, detail, _ = mapper(path, bindings)
                    assert base and status == 0, (name, status, detail)
                    assert base != preferred and native != preferred
                    for target, width, linked in fixes:
                        native_value = int.from_bytes(C.string_at(native+target, width), 'little')
                        mask = (1 << (width*8))-1
                        assert native_value == (linked+native-preferred) & mask, (name, 'Windows', target)
                        actual = int.from_bytes(C.string_at(base+target, width), 'little')
                        expected = (linked + base-preferred) & mask
                        assert actual == expected, (name, target, width, actual, expected)
                    # Compare an entire 32-byte window, including guard bytes. The
                    # two images differ only in their explicitly relocated fields.
                    first = min(target for target, _, _ in fixes)
                    start = slot if slot <= first < slot+32 else first-1
                    length = min(32, size-start)
                    normalized = bytearray(C.string_at(native+start, length))
                    for target, width, _ in fixes:
                        value = int.from_bytes(C.string_at(base+target, width), 'little')
                        normalized[target-start:target-start+width] = value.to_bytes(width, 'little')
                    assert bytes(normalized) == C.string_at(base+start, length), name
                finally:
                    if base:
                        assert mapper.release(base) == 1
                    kernel.FreeLibrary(native)
            negatives = [
                ('unknown-type', *variant(slot, 7)),
                ('headers', *variant(0x40, 3)),
                ('driver-overlap', *variant(directory+4, 3)),
                ('short-highlow', *variant(size-3, 3)),
                ('short-dir64', *variant(size-4, 10)),
            ]
            for name, data, _ in negatives:
                path = Path(tmp)/(name+'.dll')
                path.write_bytes(data)
                base, status, detail, _ = mapper(path, bindings)
                if base:
                    mapper.release(base)
                assert not base and status == 4 and 'unsupported relocation' in detail, (name, status, detail)
    finally:
        if reservation:
            assert kernel.VirtualFree(reservation, 0, 0x8000)
    print('7 Windows/pe_map relocation comparisons passed: aligned, unaligned, carry, mixed widths and exact boundaries')
    print('5 malformed/unsupported relocation controls rejected; adjacent bytes unchanged; no guest code called')


if __name__ == '__main__':
    check(*sys.argv[1:])
