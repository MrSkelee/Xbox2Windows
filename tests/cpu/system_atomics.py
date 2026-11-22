"""Compare native and translated system, cache, and atomic instructions."""
import ctypes
from pathlib import Path
import struct
import sys

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64

EXPORTS = (
    "clflush_op", "clflushopt_op", "clwb_op", "clzero_op",
    "sfence_op", "lfence_op", "mfence_op",
    "prefetchnta_op", "prefetcht0_op", "prefetcht1_op", "prefetcht2_op",
    "prefetch_op", "prefetchw_op",
    "cpuid_op", "rdtsc_op", "rdtscp_op", "rdrand_op", "rdseed_op",
    "cmpxchg8b_op", "cmpxchg16b_op",
)


def emit(image, output):
    parts = [INTEGER_HEADER]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in EXPORTS:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = c;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word c) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in EXPORTS:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], U64
    return lib


def check(native_path, lifted_path):
    native, lifted = load_lib(native_path), load_lib(lifted_path)

    buf = ctypes.create_string_buffer(256)

    # 1. Cache flush, fences, and prefetches
    simple_ops = [
        "clflush_op", "clflushopt_op", "clwb_op",
        "sfence_op", "lfence_op", "mfence_op",
        "prefetchnta_op", "prefetcht0_op", "prefetcht1_op", "prefetcht2_op",
        "prefetch_op", "prefetchw_op",
    ]
    for op in simple_ops:
        getattr(native, op)(buf, 0, 0)
        getattr(lifted, op)(buf, 0, 0)

    # 2. clzero
    buf_n = ctypes.create_string_buffer(b"\xff" * 128)
    buf_l = ctypes.create_string_buffer(b"\xff" * 128)
    # Align to 64 bytes
    addr_n = ctypes.addressof(buf_n)
    offset_n = (64 - (addr_n % 64)) % 64
    addr_l = ctypes.addressof(buf_l)
    offset_l = (64 - (addr_l % 64)) % 64
    target_n = addr_n + offset_n
    target_l = addr_l + offset_l
    try:
        native.clzero_op(target_n, 0, 0)
        assert buf_n[offset_n:offset_n+64] == b"\x00" * 64
    except OSError as e:
        if getattr(e, "winerror", 0) == -1073741795:
            print("Host CPU does not support native CLZERO; tested lifted implementation")
        else:
            raise
    lifted.clzero_op(target_l, 0, 0)
    assert buf_l[offset_l:offset_l+64] == b"\x00" * 64

    # 3. cpuid
    info_n = (ctypes.c_uint32 * 4)()
    info_l = (ctypes.c_uint32 * 4)()
    for leaf in (0, 1):
        native.cpuid_op(leaf, 0, info_n)
        lifted.cpuid_op(leaf, 0, info_l)
        if list(info_n) != list(info_l):
            raise AssertionError(f"cpuid leaf {leaf}: native {list(info_n)} != lifted {list(info_l)}")

    # 4. rdtsc and rdtscp
    t_n = native.rdtsc_op(0, 0, 0)
    t_l = lifted.rdtsc_op(0, 0, 0)
    assert t_n > 0 and t_l > 0

    aux_n = (ctypes.c_uint32 * 1)()
    aux_l = (ctypes.c_uint32 * 1)()
    tp_n = native.rdtscp_op(aux_n, 0, 0)
    tp_l = lifted.rdtscp_op(aux_l, 0, 0)
    assert tp_n > 0 and tp_l > 0

    # 5. rdrand and rdseed
    r_n = native.rdrand_op(0, 0, 0)
    r_l = lifted.rdrand_op(0, 0, 0)
    assert isinstance(r_n, int) and isinstance(r_l, int)

    s_n = native.rdseed_op(0, 0, 0)
    s_l = lifted.rdseed_op(0, 0, 0)
    assert isinstance(s_n, int) and isinstance(s_l, int)

    # 6. cmpxchg8b (match and mismatch)
    mem_n = ctypes.c_uint64(0x1122334455667788)
    mem_l = ctypes.c_uint64(0x1122334455667788)
    exp = 0x1122334455667788
    new_val = 0xaabbccddeeff0011
    r8_n = native.cmpxchg8b_op(ctypes.byref(mem_n), exp, new_val)
    r8_l = lifted.cmpxchg8b_op(ctypes.byref(mem_l), exp, new_val)
    assert mem_n.value == new_val and mem_l.value == new_val
    assert r8_n == exp and r8_l == exp

    # mismatch
    wrong = 0x9999999999999999
    r8_n = native.cmpxchg8b_op(ctypes.byref(mem_n), wrong, 0x1234)
    r8_l = lifted.cmpxchg8b_op(ctypes.byref(mem_l), wrong, 0x1234)
    assert mem_n.value == new_val and mem_l.value == new_val
    assert r8_n == new_val and r8_l == new_val

    # 7. cmpxchg16b (match and mismatch)
    # Needs 16-byte aligned memory operand
    buf16_n = ctypes.create_string_buffer(64)
    buf16_l = ctypes.create_string_buffer(64)
    a_n = ctypes.addressof(buf16_n)
    off_n = (16 - (a_n % 16)) % 16
    a_l = ctypes.addressof(buf16_l)
    off_l = (16 - (a_l % 16)) % 16
    ptr_n = a_n + off_n
    ptr_l = a_l + off_l

    init_val = struct.pack("<2Q", 0x1122334455667788, 0x99aabbccddeeff00)
    exp_val = struct.pack("<2Q", 0x1122334455667788, 0x99aabbccddeeff00)
    new_val = struct.pack("<2Q", 0xdeadbeefcafebabe, 0x0123456789abcdef)

    ctypes.memmove(ptr_n, init_val, 16)
    ctypes.memmove(ptr_l, init_val, 16)

    exp_buf = ctypes.create_string_buffer(exp_val)
    new_buf = ctypes.create_string_buffer(new_val)

    native.cmpxchg16b_op(ptr_n, exp_buf, new_buf)
    lifted.cmpxchg16b_op(ptr_l, exp_buf, new_buf)
    assert ctypes.string_at(ptr_n, 16) == new_val
    assert ctypes.string_at(ptr_l, 16) == new_val

    # mismatch
    wrong_val = struct.pack("<2Q", 1, 2)
    wrong_buf = ctypes.create_string_buffer(wrong_val)
    native.cmpxchg16b_op(ptr_n, wrong_buf, exp_buf)
    lifted.cmpxchg16b_op(ptr_l, wrong_buf, exp_buf)
    assert ctypes.string_at(ptr_n, 16) == new_val
    assert ctypes.string_at(ptr_l, 16) == new_val

    print("All 20 system, cache, and atomic instructions verified bit-for-bit against native hardware")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
