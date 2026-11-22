"""Compare the linked shim EXE, the mapped image and the AOT process on one raster draw.

The draw case renders the repository's 64x64 test triangle offscreen from the same
EXE entry that runs the startup shims and the compute dispatch. The provider
publishes the raw RGBA bytes after the startup output; this check compares them
byte for byte across runners and against the CPU pixel rule. The flip case mirrors
X in the vertex shader and must exit 20 with bytes that differ from the rule but
still agree across runners.
"""
import os
from pathlib import Path
import subprocess
import sys

from shim_startup_check import EXPECTED, SHIM_IMPORTS, check


SIDE = 64
BYTES = SIDE * SIDE * 4


def reference(flip=False):
    out = bytearray()
    for y in range(SIDE):
        for x in range(SIDE):
            xx, yy = (y, x) if flip else (x, y)
            inside = xx >= 8 and yy >= 8 and xx + yy <= 63
            out += bytes((0, 255 if inside else 0, 0, 255))
    return bytes(out)


def verify(case, result, expected_pixels):
    check("startup output before draw", result.stdout[:len(EXPECTED.output)], EXPECTED.output)
    pixels = result.stdout[len(EXPECTED.output):]
    if case == "bogus":
        check("unknown draw case exits", result.returncode, 21)
        check("unknown draw case publishes nothing", pixels, b"")
        return None
    check("draw publishes a full frame", len(pixels), BYTES)
    if case == "flip":
        check("mirrored draw exits", result.returncode, 20)
        if pixels == expected_pixels:
            raise AssertionError("mirrored draw matches the exact rule")
        return pixels
    check("exact draw exits", result.returncode, 42)
    check("exact draw matches the CPU rule", pixels, expected_pixels)
    return pixels


def compare(mapper, exe, lifted, companion, io, xmem, d3d12):
    digest = reference()
    green = sum(1 for i in range(0, BYTES, 4) if digest[i + 1] == 255)
    print(f"draw frame: {SIDE}x{SIDE} RGBA ({BYTES} bytes); CPU rule holds {green} green pixels")
    map_command = [sys.executable, "-B", Path(__file__).with_name("shim_startup_check.py"), "--map",
                   mapper, exe, companion, io, xmem, d3d12, ""]
    markers = sorted(f"bound {dll}!{symbol}" for dll, symbols in SHIM_IMPORTS.items() for symbol in symbols)
    for case in ("draw", "flip", "bogus"):
        env = dict(os.environ, X2W_SHIM_DRAW_CASE="" if case == "bogus" else case,
                   X2W_SHIM_COMPUTE_CASE="")
        if case == "bogus":
            env["X2W_SHIM_DRAW_CASE"] = "no such case"
        outputs = {}
        for runner, command in (("native", [exe]), ("pe_map", map_command), ("AOT", [lifted])):
            child = subprocess.run(command, env=env, capture_output=True, timeout=120)
            lines = child.stderr.decode(errors="replace").splitlines()
            if (case == "draw" and runner == "native" and child.returncode == 77
                    and env.get("X2W_SHIM_DRAW_ADAPTER") == "hardware"):
                check("hardware capability diagnostic", lines, ["no D3D12 physical adapter"])
                check("startup before hardware capability skip", child.stdout, EXPECTED.output)
                print(lines[0])
                return 77
            if runner == "pe_map":
                if case == "bogus":
                    # ExitProcess(21) kills the mapped child before it prints the
                    # return marker; the six shim bindings are already logged.
                    check("explicit shim bindings", sorted(lines), markers)
                else:
                    check("mapper returned", lines[-1:], ["mapped host returned"])
                    check("explicit shim bindings", sorted(lines[:-1]), markers)
            else:
                check(f"{case} {runner} diagnostics", lines, [])
            outputs[runner] = verify(case, child, digest)
        if case != "bogus":
            check(f"{case} runners agree",
                  (outputs["native"], outputs["AOT"], len(outputs["pe_map"] or b"")),
                  (outputs["pe_map"], outputs["pe_map"], BYTES))
        print(f"{case}: exits checked; "
              f"pixels={len(outputs['native']) if outputs['native'] else 0}")


if __name__ == "__main__":
    # The draw provider path is passed so the test depends on its build; the guest
    # locates it next to the EXE, like the compute provider.
    sys.exit(compare(*map(Path, sys.argv[1:-1])))
