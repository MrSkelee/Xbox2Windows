"""Verify indexed PARAM0 UVs and a translated sample in the same D3D12 draw."""

from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from mesh_attribute_check import program
from mesh_entry_check import binary, enumerate_pcs, fixture
from mesh_indexed_check import HEADER, SMALL, WORDS, inputs, lower, small_raster
from pixel_aot import lower as lower_pixel
from pixel_aot_check import compile_shader, lod_zero_sample


PALETTE = ((255, 0, 0, 255), (0, 255, 0, 255), (0, 0, 255, 255), (255, 255, 0, 255))
POSITIONS = [SMALL[i] for i in (1, 2, 0)]


def texture_case(colors, flip):
    data = inputs(SMALL)
    for i, (u, v) in enumerate(((0, 2), (2, 2), (0, 0))):
        struct.pack_into("<3f", data, 1028 + 64 + i * 12, 1 - u if flip else u, v, 0)
    coverage = small_raster()
    pixels = bytearray(coverage)
    for y in range(32):
        for x in range(32):
            offset = (y * 32 + x) * 4
            if coverage[offset + 1]:
                # Edges run from x=4 to 28 and y=5 to 28. The UV range is two units per edge.
                u = 2 * (x + 0.5 - 4) / 24
                v = 2 * (y + 0.5 - 5) / 23
                col = (1 - u if flip else u) >= 0.5
                row = v >= 0.5
                pixels[offset:offset + 4] = bytes(colors[2 * row + col])
    return data, bytes(pixels), bytes(channel for pixel in colors for channel in pixel)


def mesh_program():
    code = program()
    # PARAM0.x/y are the first two fetched attributes rather than the color fixture's swizzle.
    code[code.index("exp param0 v7, v4, v6, v5 done")] = "exp param0 v5, v6, v7, v4 done"
    return code


def run(tmp, compiler, renderer, adapter):
    code = mesh_program()
    mesh_source, mesh = tmp / "mesh.hlsl", tmp / "mesh.dxil"
    mesh_source.write_text(lower(enumerate_pcs(code), WORDS, (3, 1), HEADER), encoding="ascii")
    pixel_source, pixel = tmp / "pixel.hlsl", tmp / "pixel.dxil"
    pixel_source.write_text(lower_pixel(lod_zero_sample(), 20, 24, [1, 2, 3, 4], texcoord_components=4),
                            encoding="ascii")
    compile_shader(compiler, pixel_source, pixel)
    cases = (texture_case(PALETTE, False), texture_case(PALETTE[1:] + PALETTE[:1], False),
             texture_case(PALETTE, True))
    for traced in (False, True):
        flags = ["-DTRACE_EXPORTS"] if traced else []
        subprocess.run([compiler, "-T", "ms_6_5", "-E", "main", *flags, "-Fo", mesh, mesh_source], check=True)
        for index, (data, pixels, texels) in enumerate(cases):
            path = tmp / f"case-{index}.bin"
            path.write_bytes(fixture(data, POSITIONS, pixels, traced) + texels)
            result = subprocess.run([renderer, adapter, "--mesh-textured", mesh, pixel, path])
            if result.returncode == 77:
                return 77
            result.check_returncode()
    for index in (1, 2):
        data, _, texels = cases[index]
        baseline = cases[0][1]
        path = tmp / f"stale-{index}.bin"
        path.write_bytes(fixture(data, POSITIONS, baseline, True) + texels)
        result = subprocess.run([renderer, adapter, "--mesh-textured", mesh, pixel, path],
                                capture_output=True, text=True)
        if (result.returncode != 1 or "pixels=1024 mismatches=276" not in result.stdout.splitlines()
                or ("debug_layer=enabled" in result.stdout
                    and "debug_errors=0 debug_warnings=0" not in result.stdout.splitlines())
                or "Draw reference mismatch" not in result.stderr):
            raise AssertionError(f"Unexpected stale-image result\n{result.stdout}\n{result.stderr}")
        print(f"stale_reference={index} mismatches=276")
    return 0


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        if sys.argv[1] == "binary":
            binary(tmp, *sys.argv[2:], program=mesh_program(), words=WORDS, header=HEADER)
        else:
            sys.exit(run(tmp, *sys.argv[1:]))
