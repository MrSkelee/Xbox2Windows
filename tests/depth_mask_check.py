"""Two descriptor tables, depth export, and a physical CBV swap."""

from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from depth_mask_aot import lower

VS = """
float4 main(uint id : SV_VertexID) : SV_Position {
    return float4(float2((id << 1) & 2, id & 2) * float2(2,-2) + float2(-1,1), 0.375, 1);
}
"""


def program(extended=False):
    # Original fixture. The offsets here are instruction addresses in a decoded stream.
    prefix = [
        "s_mov_b32 s7, 0",
        "s_mov_b32 s11, 0",
        "s_mov_b64 s[22:23], exec",
        "s_mov_b64 s[24:25], exec",
        "s_load_dwordx4 s[12:15], s[6:7], 0x20",
        "s_load_dwordx4 s[16:19], s[10:11], 0x10",
        "s_waitcnt lgkmcnt(0)",
        f"s_buffer_load_dword s30, s[12:15], {0x18 if extended else 0x4:#x}",
        "s_buffer_load_dword s31, s[16:19], null",
        "s_waitcnt lgkmcnt(0)",
    ]
    if extended:
        prefix += ["s_add_i32 s30, s30, 12", "s_and_b32 s30, s30, 31"]
    # The extended fixture samples Y in a 32-pixel period.
    position, scale = ("v3", "0x3d000000") if extended else ("v2", "0x3e000000")
    prefix += [
        "v_cvt_f32_ubyte0_e32 v5, s30",
        f"v_mul_legacy_f32_e32 v7, {scale}, {position}",
        f"v_fmac_f32_e32 v7, {scale}, v5",
        "v_fract_f32_e32 v7, v7",
    ]
    exits = [
        "v_cmpx_lt_f32_e32 s31, v7",
        "s_andn2_b64 s[22:23], s[22:23], exec",
        "s_cbranch_scc0 4",
        "s_and_b64 exec, s[24:25], s[22:23]",
        "exp mrtz, v4, off, off, off done vm",
        "s_endpgm",
        "s_mov_b64 exec, s[22:23]",
        "exp null, off, off, off, off done vm",
        "s_endpgm",
    ]
    return prefix + exits


def source(extended=False):
    lines = program(extended)
    sizes = [
        8 if line.startswith(("s_load_", "s_buffer_load_", "exp ")) else 4
        for line in lines
    ]
    offsets = [sum(sizes[:i]) for i in range(len(sizes))]
    decoded = list(zip(offsets, lines))
    tables = [(6, 32), (10, 16)]
    for bad in ([(6, 16), (10, 32)], [(10, 32), (6, 16)]):
        try:
            lower(decoded, bad)
        except ValueError:
            continue
        raise AssertionError("Unbound descriptor accepted")
    for original, replacement in (
        ("s_waitcnt lgkmcnt(0)", "s_nop 0"),
        ("s_cbranch_scc0 4", "s_cbranch_scc0 3"),
    ):
        changed = [
            (pc, replacement if line == original else line) for pc, line in decoded
        ]
        try:
            lower(changed, tables)
        except ValueError:
            continue
        raise AssertionError("Unverified mask or pending load accepted")
    return lower(decoded, tables)


def draw(dxc, renderer, adapter, tmp, shader, word_offset, noise, *, thresholds=()):
    vs, ps = tmp / "vertex.dxil", tmp / "pixel.dxil"
    for name, profile, text, binary in [("v", "vs", VS, vs), ("p", "ps", shader, ps)]:
        path = tmp / (name + ".hlsl")
        path.write_text(text)
        subprocess.run(
            [dxc, "-T", profile + "_6_0", "-E", "main", "-Fo", binary, path], check=True
        )
    a, b = bytearray(2048), bytearray(2048)
    for buf, threshold, seed in ((a, 0.25, 7), (b, 0.625, 29)):
        struct.pack_into("<f", buf, 0, threshold)
        struct.pack_into("<I", buf, word_offset, seed)

    def picture(seed, threshold):
        return b"".join(
            struct.pack(
                "<f", 0.375 if noise(x + 0.5, y + 0.5, seed) <= threshold else 0.9375
            )
            for y in range(32)
            for x in range(32)
        )

    expected = picture(7, 0.625)
    exchanged = picture(29, 0.25)
    assert (
        expected != exchanged
        and picture(29, 0.625) != expected
        and picture(7, 0.25) != expected
    )
    for swapped, seed, threshold, reference, negative in (
        (False, 7, 0.625, expected, False),
        (False, 29, 0.625, picture(29, 0.625), False),
        (False, 7, 0.25, picture(7, 0.25), False),
        (True, 7, 0.625, expected, True),
        (True, 7, 0.625, exchanged, False),
        *((False, 7, threshold, picture(7, threshold), False) for threshold in thresholds),
    ):
        struct.pack_into("<I", a, word_offset, seed)
        struct.pack_into("<f", b, 0, threshold)
        fixture = tmp / "draw.bin"
        fixture.write_bytes(a + b + reference)
        mode = "--depth-mask-swapped" if swapped else "--depth-mask"
        result = subprocess.run(
            [renderer, adapter, mode, vs, ps, fixture], capture_output=True, text=True
        )
        print(result.stdout, result.stderr)
        if result.returncode == 77 and not swapped:
            return 77
        if negative:
            if (
                result.returncode != 1
                or "Draw reference mismatch" not in result.stderr
                or "debug_errors=0" not in result.stdout
                and "debug_layer=unavailable" not in result.stdout
            ):
                raise AssertionError(
                    "Swapped descriptors must fail at depth comparison"
                )
        else:
            result.check_returncode()
    return 0


def binary(tmp, assembler, objcopy, library):
    from pixel_aot_check import envelope
    from pixel_aot import _read_named_container

    src, obj, raw = (tmp / name for name in ("fixture.s", "fixture.o", "fixture.bin"))
    lines = program()
    src.write_text(
        "\n".join(
            s.replace("mrtz,", "mrtz")
            .replace("null,", "null")
            .replace("prim,", "prim")
            .replace("pos0,", "pos0")
            for s in lines
        )
        + "\n"
    )
    subprocess.run(
        [
            assembler,
            "-triple=amdgcn--amdpal",
            "-mcpu=gfx1013",
            "-filetype=obj",
            src,
            "-o",
            obj,
        ],
        check=True,
    )
    subprocess.run(
        [objcopy, "-O", "binary", "--only-section=.text", obj, raw], check=True
    )
    code = raw.read_bytes()
    padded = code + bytes.fromhex("00009fbf") * (4 - (len(code) // 4 + 10) % 4)
    record = envelope(padded, directory_end=(40 + len(padded), 288 + len(padded)))
    container = tmp / "input.dxbc"
    container.write_bytes(_read_named_container(record, len(b"fixture") + 2))
    translated = tmp / "out.hlsl"
    tables = ["--table", "6", "32", "--table", "10", "16"]
    tool = Path(__file__).resolve().parents[1] / "tools" / "depth_mask_aot.py"
    subprocess.run(
        [
            sys.executable,
            "-B",
            tool,
            container,
            "--llvm",
            library,
            "--output",
            translated,
            *tables,
        ],
        check=True,
    )
    assert translated.read_text() == source()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        if sys.argv[1] == "binary":
            binary(Path(directory), *sys.argv[2:])
            sys.exit(0)
        draw_args = (*sys.argv[1:], Path(directory))
        result = draw(*draw_args, source(), 4, lambda x, y, seed: ((x + seed) / 8) % 1)
        if result:
            sys.exit(result)
        sys.exit(
            draw(
                *draw_args,
                source(extended=True),
                0x18,
                lambda x, y, seed: ((y + seed + 12) % 32) / 32,
                thresholds=(62 / 64, 63 / 64),
            )
        )
