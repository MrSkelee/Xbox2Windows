"""Draw two indexed triangles into one color/depth target and verify both readbacks."""

from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from mesh_attribute_check import program
from mesh_entry_check import enumerate_pcs, fixture
from mesh_indexed_check import HEADER, SMALL, WORDS, inputs, lower
from pixel_aot_check import attribute_color, translate_attribute

COLORS = ((255, 0, 0, 255), (0, 0, 255, 255))


def scene(depths, order):
    uploads, traces = [], []
    for i in order:
        points = [(x + i / 4, y, depths[i], w) for x, y, _, w in SMALL]
        data = inputs(points)
        for vertex in range(3):
            struct.pack_into("<3f", data, 1028 + 64 + 12 * vertex,
                             *(channel / 255 for channel in COLORS[i][:3]))
        uploads.append(data)
        positions = [points[j] for j in (1, 2, 0)]
        traces.append(fixture(b"", positions, b"", True))

    rgba, depth_bytes = bytearray(), bytearray()
    overlap = 0
    for y in range(32):
        for x in range(32):
            # Integer twice-center coordinates avoid edge rounding in the reference.
            hits = [i for i in range(2) if x >= 4 + 4 * i and y < 28
                    and 23 * (2 * x + 1 - 2 * (4 + 4 * i)) < 24 * (2 * y + 1 - 10)]
            overlap += len(hits) == 2
            if hits:
                winner = min(hits, key=depths.__getitem__)
                rgba.extend(COLORS[winner])
                depth_bytes.extend(struct.pack("<f", depths[winner]))
            else:
                rgba.extend((0, 0, 0, 255))
                depth_bytes.extend(struct.pack("<f", 1))
    return b"".join(uploads + traces), bytes(rgba), bytes(depth_bytes), overlap


def run(tmp, compiler, renderer, adapter):
    for stage, profile, text, flags in (
        ("mesh", "ms_6_5", lower(enumerate_pcs(program()), WORDS, (3, 1), HEADER), ["-DTRACE_EXPORTS"]),
        ("pixel", "ps_6_0", translate_attribute(attribute_color(False)), []),
    ):
        source = tmp / f"{stage}.hlsl"
        source.write_text(text, encoding="ascii")
        subprocess.run([compiler, "-T", profile, "-E", "main", *flags, "-Fo",
                        tmp / f"{stage}.dxil", source], check=True)
    path = tmp / "depth-pair.case"
    command = [renderer, adapter, "--mesh-depth-pair", tmp / "mesh.dxil", tmp / "pixel.dxil", path]
    base = scene((0.25, 0.75), (0, 1))
    reverse = scene((0.25, 0.75), (1, 0))
    swapped = scene((0.75, 0.25), (0, 1))
    assert base[1:] == reverse[1:]
    for data, rgba, depth, _ in (base, reverse, swapped):
        path.write_bytes(data + rgba + depth)
        result = subprocess.run(command)
        if result.returncode == 77:
            return 77
        result.check_returncode()
    data, rgba, depth, overlap = swapped
    depth_changes = sum(depth[i:i + 4] != base[2][i:i + 4] for i in range(0, len(depth), 4))
    assert overlap == 190 and depth_changes == 172
    for color_ref, depth_ref, color_errors, depth_errors, message in (
        (base[1], depth, overlap, 0, "Draw reference mismatch"),
        (rgba, base[2], 0, depth_changes, "Depth reference mismatch"),
    ):
        path.write_bytes(data + color_ref + depth_ref)
        result = subprocess.run(command, capture_output=True, text=True)
        expected = {f"pixels=1024 mismatches={color_errors}", f"depth_pixels=1024 depth_mismatches={depth_errors}"}
        if (result.returncode != 1 or not expected <= set(result.stdout.splitlines())
                or message not in result.stderr.splitlines()
                or ("debug_layer=enabled" in result.stdout
                    and "debug_errors=0 debug_warnings=0" not in result.stdout.splitlines())):
            raise AssertionError(f"Unexpected negative control\n{result.stdout}\n{result.stderr}")
        print(f"Expected failure: {message}, color={color_errors}, depth={depth_errors}")
    return 0


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        sys.exit(run(Path(directory), *sys.argv[1:]))
