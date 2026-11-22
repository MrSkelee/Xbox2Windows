"""Check the single-store compute profile with original synthetic kernels."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from pixel_aot_check import envelope, must_reject
import compute_store_aot as aot
from pixel_aot import _read_named_container, disassemble
from resource_inventory import parts

SENTINEL = 0xc5c5c5c5
INDEXED = [
    "s_mov_b32 s12, s7", "s_mov_b32 s13, 0",
    "s_load_dwordx4 s[20:23], s[12:13], 0x30",
    "v_lshl_add_u32 v8, s11, 5, v0",
    "v_mov_b32_e32 v15, 19", "v_mov_b32_e32 v16, -5",
    "s_waitcnt lgkmcnt(0)", "buffer_store_dwordx2 v[15:16], v8, s[20:23], 0 idxen offset:4",
    "s_endpgm",
]
FIXED = [
    "s_mov_b32 s9, 0", "s_load_dwordx4 s[12:15], s[8:9], null",
    "v_mov_b32_e32 v20, 11", "v_mov_b32_e32 v21, 23", "v_mov_b32_e32 v22, -2",
    "s_waitcnt lgkmcnt(0)", "buffer_store_dwordx3 v[20:22], off, s[12:15], 0 offset:20",
    "s_endpgm",
]
MULTI_FIXED = [
    "s_mov_b32 s9, 0",
    "s_load_dwordx4 s[12:15], s[8:9], null",
    "s_mov_b32 s10, 0x12345678",
    "s_movk_i32 s11, 0xfffc",
    "v_mov_b32_e32 v4, s10",
    "v_mov_b32_e32 v5, s11",
    "v_mov_b32_e32 v6, v4",
    "v_mov_b32_e32 v7, 7",
    "s_waitcnt lgkmcnt(0)",
    "s_clause 0x1",
    "buffer_store_dwordx2 v[4:5], off, s[12:15], 0 offset:8",
    "buffer_store_dwordx2 v[6:7], off, s[12:15], 0 offset:32",
    "s_endpgm",
]
MULTI_INDEXED = [
    "s_mov_b32 s12, s7",
    "s_mov_b32 s13, 0",
    "s_load_dwordx4 s[20:23], s[12:13], 0x30",
    "s_mov_b32 s14, 0x00abcdef",
    "s_movk_i32 s15, 0xfff0",
    "v_lshl_add_u32 v8, s11, 5, v0",
    "v_mov_b32_e32 v10, s14",
    "v_mov_b32_e32 v11, s15",
    "s_waitcnt lgkmcnt(0) vmcnt(0)",
    "buffer_store_dword v10, v8, s[20:23], 0 idxen",
    "buffer_store_dword v11, v8, s[20:23], 0 idxen offset:8",
    "s_endpgm",
]
RUNTIME = [
    "s_mov_b32 s9, 0",
    "s_load_dwordx4 s[12:15], s[8:9], null",
    "s_load_dwordx4 s[16:19], s[8:9], 0x20",
    "s_waitcnt lgkmcnt(0)",
    "s_buffer_load_dword s20, s[16:19], null",
    "s_buffer_load_dwordx2 s[22:23], s[16:19], 0xc",
    "s_buffer_load_dwordx4 s[24:27], s[16:19], 0x30",
    "s_waitcnt lgkmcnt(0)",
    "s_mov_b32 s28, s20",
    "v_mov_b32_e32 v10, s28", "v_mov_b32_e32 v11, s22", "v_mov_b32_e32 v12, s23",
    "v_mov_b32_e32 v13, s27", "v_mov_b32_e32 v14, s26", "v_mov_b32_e32 v15, s25",
    "v_mov_b32_e32 v16, s24", "v_mov_b32_e32 v17, v16",
    "buffer_store_dwordx3 v[10:12], off, s[12:15], 0 offset:16",
    "buffer_store_dwordx4 v[13:16], off, s[12:15], 0 offset:32",
    "buffer_store_dword v17, off, s[12:15], 0 offset:64",
    "s_endpgm",
]
INDEX_BINDING = dict(table_reg=7, group_reg=11, descriptor_offset=48, stride=12)
FIXED_BINDING = dict(table_reg=8, descriptor_offset=0)
RUNTIME_BINDING = dict(FIXED_BINDING, constant_descriptor=32)
CASES = [
    ("indexed", INDEXED, 32, INDEX_BINDING),
    ("fixed", FIXED, 1, FIXED_BINDING),
    ("multi_fixed", MULTI_FIXED, 1, FIXED_BINDING),
    ("multi_indexed", MULTI_INDEXED, 32, INDEX_BINDING),
    ("runtime", RUNTIME, 1, RUNTIME_BINDING),
]


def controls():
    for change in (dict(table_reg=6), dict(group_reg=10), dict(descriptor_offset=32), dict(stride=8)):
        must_reject(lambda: aot.lower(INDEXED, 32, **(INDEX_BINDING | change)))
    for old, new in (("lgkmcnt(0)", "lgkmcnt(1)"), ("s11, 5", "s11, 4"),
                     ("s[20:23], 0 idxen", "s[24:27], 0 idxen"), ("s13, 0", "s13, 1")):
        must_reject(lambda: aot.lower([s.replace(old, new) for s in INDEXED], 32, **INDEX_BINDING))
    must_reject(lambda: aot.lower(INDEXED[:6] + INDEXED[7:], 32, **INDEX_BINDING))
    must_reject(lambda: aot.lower(INDEXED[:7] + ["s_mov_b32 s21, 0"] + INDEXED[7:], 32, **INDEX_BINDING))
    must_reject(lambda: aot.lower(FIXED, 32, **FIXED_BINDING))
    must_reject(lambda: aot.lower(["s_endpgm"], 1, **FIXED_BINDING))

    # Read a constant word directly into v10 before the constant-load wait.
    must_reject(lambda: aot.lower(
        RUNTIME[:7] + ["v_mov_b32_e32 v10, s20", RUNTIME[7]] + RUNTIME[10:],
        1, **RUNTIME_BINDING))
    for old, new in (("s11, 5, v0", "s11, 5, v1"),
                     ("v[15:16], v8,", "v[15:16], v0,"),
                     ("0 idxen offset:4", "0 offset:4")):
        must_reject(lambda: aot.lower([s.replace(old, new) for s in INDEXED], 32, **INDEX_BINDING))
    must_reject(lambda: aot.lower(
        RUNTIME[:4] + ["s_mov_b32 s17, 0"] + RUNTIME[4:], 1, **RUNTIME_BINDING))
    must_reject(lambda: aot.lower(
        INDEXED[:7] + ["s_mov_b32 s23, 0"] + INDEXED[7:], 32, **INDEX_BINDING))
    movk_boundary = FIXED[:2] + ["s_movk_i32 s10, 0x8000", "v_mov_b32_e32 v20, s10"] + FIXED[3:]
    assert "    outputData.Store3(20u, uint3(0xffff8000u, 0x00000017u, 0xfffffffeu));" in (
        aot.lower(movk_boundary, 1, **FIXED_BINDING).splitlines())
    must_reject(lambda: aot.lower(FIXED, 1, **dict(FIXED_BINDING, constant_descriptor=8)))

    # Overlapping store spans in one invocation are rejected.
    must_reject(lambda: aot.lower(
        MULTI_FIXED[:-1] + ["buffer_store_dword v7, off, s[12:15], 0 offset:12", "s_endpgm"],
        1, **FIXED_BINDING))
    must_reject(lambda: aot.lower(
        MULTI_INDEXED[:-1] + ["buffer_store_dwordx2 v[10:11], v8, s[20:23], 0 idxen offset:4", "s_endpgm"],
        32, **INDEX_BINDING))
    # Non-constant or pending scalar/vector sources and out-of-range hints/immediates are rejected.
    must_reject(lambda: aot.lower(
        [s.replace("v_mov_b32_e32 v4, s10", "v_mov_b32_e32 v4, s8") for s in MULTI_FIXED],
        1, **FIXED_BINDING))
    must_reject(lambda: aot.lower(
        [s.replace("v_mov_b32_e32 v4, s10", "v_mov_b32_e32 v4, s12") for s in MULTI_FIXED],
        1, **FIXED_BINDING))
    must_reject(lambda: aot.lower(
        [s.replace("v_mov_b32_e32 v6, v4", "v_mov_b32_e32 v6, v0") for s in MULTI_FIXED],
        1, **FIXED_BINDING))
    must_reject(lambda: aot.lower(
        [s.replace("s_clause 0x1", "s_clause 0x40") for s in MULTI_FIXED],
        1, **FIXED_BINDING))
    must_reject(lambda: aot.lower(
        [s.replace("s_movk_i32 s11, 0xfffc", "s_movk_i32 s11, 0x10000") for s in MULTI_FIXED],
        1, **FIXED_BINDING))
    must_reject(aot.group_width, bytes(52))
    for descriptor in (None, 8, 16, 33):
        must_reject(lambda: aot.lower(RUNTIME, 1, **dict(FIXED_BINDING, constant_descriptor=descriptor)))
    for old, new in (
        ("s[16:19], 0x30", "s[16:19], 0x34"),
        ("s[16:19], 0xc", "s[16:19], 0xa"),
        ("s[16:19], 0xc", "s[12:15], 0xc"),
        ("s[22:23]", "s[21:22]"),
        ("s[24:27]", "s[20:23]"),
        ("s[12:15], 0 offset:64", "s[16:19], 0 offset:64"),
    ):
        must_reject(lambda: aot.lower([line.replace(old, new) for line in RUNTIME], 1, **RUNTIME_BINDING))
    for slot in (3, 7):
        early = RUNTIME.copy()
        early[slot] = "s_waitcnt vmcnt(0)"
        must_reject(lambda: aot.lower(early, 1, **RUNTIME_BINDING))


def binary(directory, assembler, objcopy, library):
    for _, lines, width, binding in CASES:
        src, obj, raw = [directory / x for x in ("test.s", "test.o", "test.bin")]
        src.write_text("\n".join(lines) + "\n", encoding="ascii")
        subprocess.run([assembler, "-triple=amdgcn--amdpal", "-mcpu=gfx1013", "-filetype=obj", src, "-o", obj], check=True)
        subprocess.run([objcopy, "-O", "binary", "--only-section=.text", obj, raw], check=True)
        code = raw.read_bytes()
        padded = code + bytes.fromhex("00009fbf") * (4 - (len(code) // 4 + 10) % 4)
        payload = envelope(padded, directory_end=(40 + len(padded), 288 + len(padded)), compute_width=width)
        blob = _read_named_container(payload, 1 + len(b"fixture") + 1)
        sections = parts(blob)
        assert aot.group_width(sections[b"PSV0"]) == width
        assert aot.container_code(sections[b"DXIL"], stage=5) == code
        must_reject(lambda: aot.container_code(sections[b"DXIL"], stage=0))
        assert aot.lower(disassemble(code, library), width, **binding) == aot.lower(lines, width, **binding)
        container, output = directory / "input.dxbc", directory / "cli.hlsl"
        container.write_bytes(blob)
        options = [item for key, value in binding.items() for item in ("--" + key.replace("_", "-"), str(value))]
        subprocess.run([sys.executable, "-B", str(Path(aot.__file__)), container, "--output", output,
                        "--llvm", library, *options], check=True)
        assert output.read_text() == aot.lower(lines, width, **binding)


def draw_runtime(cmd, case):
    first = [0x80000000 + i * 0x101 for i in range(16)]
    second = [0x7fc00000 + i * 0x181 for i in range(16)]
    refs = []
    for values in (first, second):
        words = [SENTINEL] * 320
        words[4:7] = [values[0], values[3], values[4]]
        words[8:12] = values[12:16][::-1]
        words[16] = values[12]
        refs.append(words)
        case.write_bytes(struct.pack("<337I", 1, *words, *values))
        result = subprocess.run(cmd)
        if result.returncode:
            return result.returncode
    case.write_bytes(struct.pack("<337I", 1, *refs[0], *second))
    stale = subprocess.run(cmd, capture_output=True, text=True)
    if (stale.returncode != 1 or "word=4 expected=80000000 actual=7fc00000" not in stale.stderr
            or "groups=1 compared_words=320 mismatches=8" not in stale.stdout.splitlines()):
        raise AssertionError(f"Expected a stale runtime constant mismatch\n{stale.stdout}\n{stale.stderr}")
    case.write_bytes(struct.pack("<337I", 1, *refs[1], *second)[:-4])
    truncated = subprocess.run(cmd, capture_output=True, text=True)
    if truncated.returncode != 1 or "Invalid compute store constants" not in truncated.stderr:
        raise AssertionError(f"Expected a truncated constants error\n{truncated.stdout}\n{truncated.stderr}")
    return 0


def draw(directory, compiler, renderer, backend):
    for name, lines, width, binding in CASES:
        src, cso, case = [directory / x for x in ("store.hlsl", "store.cso", "store.case")]
        src.write_text(aot.lower(lines, width, **binding), encoding="ascii")
        subprocess.run([compiler, "-T", "cs_6_0", "-E", "main", "-Fo", cso, src], check=True)
        cmd = [renderer, backend, "--compute-store-case", cso, case]
        if name == "runtime":
            result = draw_runtime(cmd, case)
            if result:
                return result
            continue
        for groups in ((1, 3) if width == 32 else (1,)):
            words = [SENTINEL] * 320
            if name == "fixed":
                words[5:8] = [11, 23, 0xfffffffe]
                guard_word, stored_word = 0, 5
            elif name == "indexed":
                for i in range(groups * 32):
                    words[3*i+1:3*i+3] = [19, 0xfffffffb]
                guard_word, stored_word = 0, 1
            elif name == "multi_fixed":
                words[2:4] = [0x12345678, 0xfffffffc]
                words[8:10] = [0x12345678, 7]
                guard_word, stored_word = 4, 9
            else:
                for i in range(groups * 32):
                    words[3*i] = 0x00abcdef
                    words[3*i+2] = 0xfffffff0
                guard_word, stored_word = 1, 2
            case.write_bytes(struct.pack("<321I", groups, *words))
            result = subprocess.run(cmd)
            if result.returncode:
                return result.returncode
        words[guard_word] ^= 1
        case.write_bytes(struct.pack("<321I", groups, *words))
        bad = subprocess.run(cmd, capture_output=True, text=True)
        if bad.returncode != 1 or f"word={guard_word} expected=" not in bad.stderr:
            raise AssertionError("A wrong untouched word escaped detection")
        words[guard_word] ^= 1
        words[stored_word] ^= 1
        case.write_bytes(struct.pack("<321I", groups, *words))
        bad = subprocess.run(cmd, capture_output=True, text=True)
        if bad.returncode != 1 or "Compute readback differs" not in bad.stderr:
            raise AssertionError("A wrong stored word escaped detection")
    return 0


if __name__ == "__main__":
    controls()
    mode, *args = sys.argv[1:]
    with tempfile.TemporaryDirectory() as tmp:
        sys.exit({"binary": binary, "draw": draw}[mode](Path(tmp), *args))
