"""Check the Xbox2Windows exponent helpers on Vulkan with exact binary32 readback."""

import argparse
import math
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from pixel_aot import PREAMBLE  # noqa: E402


# Each value is the source binary32 word and the signed LDEXP exponent.
CASES = [
    (0x00000000, 200),
    (0x80000000, -200),
    (0x00000001, 23),
    (0x00000001, -1),
    (0x80000001, -1),
    (0x00000003, -1),
    (0x007FFFFF, 1),
    (0x807FFFFF, 1),
    (0x00800000, -23),
    (0x00800000, -24),
    (0x00800001, -1),
    (0x00800003, -1),
    (0x00FFFFFF, -1),
    (0x3F7FFFFF, 1),
    (0xBF800000, -149),
    (0x7F7FFFFF, 1),
    (0xFF7FFFFF, 1),
    (0x3F800000, 2**31 - 1),
    (0xBF800000, -2**31),
    (0x7F800000, -100),
    (0xFF800000, 100),
    (0x7FC12345, -13),
    (0xFFC12345, 13),
]


def float_bits(value):
    try:
        return struct.unpack("<I", struct.pack("<f", value))[0]
    except OverflowError:
        return struct.unpack("<I", struct.pack("<f", math.copysign(math.inf, value)))[0]


def reference(bits, exponent):
    value = struct.unpack("<f", struct.pack("<I", bits))[0]
    if math.isnan(value):
        return 0x7FC00000, 0x7FC00000
    if math.isinf(value) or value == 0:
        return bits, bits
    try:
        scaled = math.ldexp(value, exponent)
    except OverflowError:
        scaled = math.copysign(math.inf, value)
    return float_bits(math.frexp(value)[0]), float_bits(scaled)


def shader_test(shader):
    words = struct.unpack(f"<{len(shader) // 4}I", shader)
    if words[0] != 0x07230203:
        raise ValueError("DXC output is not SPIR-V")
    input_words = [word for bits, exp in CASES for word in (bits, exp & 0xFFFFFFFF)]
    expected_words = [word for case in CASES for word in reference(*case)]
    return (
        "[compute shader binary]\n"
        + "\n".join(" ".join(f"{w:x}" for w in words[i:i + 8]) for i in range(0, len(words), 8))
        + "\n[test]\n"
        + "ssbo 0 subdata uint 0 " + " ".join(str(x) for x in input_words)
        + f"\nssbo 1 {len(expected_words) * 4}\n"
        + f"compute {len(CASES)} 1 1\n"
        + "probe ssbo uint 1 0 == " + " ".join(str(x) for x in expected_words)
        + "\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dxc", type=Path)
    parser.add_argument("vkrunner", type=Path)
    parser.add_argument("--device", action="append", type=int, help="One-based VkRunner device index")
    args = parser.parse_args()
    pattern = r"^float (?:frexp_mant32|ldexp32)\([^\n]*\) \{\n.*?^\}"
    helpers = re.findall(pattern, PREAMBLE, re.M | re.S)
    if len(helpers) != 2:
        raise ValueError("Expected frexp_mant32 and ldexp32 in pixel_aot.py")
    library = "\n".join(helpers)
    tie_even = "rem > half_bit || (rem == half_bit && (q & 1u) != 0u)"
    if library.count(tie_even) != 1:
        raise ValueError("The LDEXP tie-to-even control needs updating")
    wrapper = """
[[vk::binding(0, 0)]] ByteAddressBuffer inputs;
[[vk::binding(1, 0)]] RWByteAddressBuffer outputs;
uint readback_word(float value) {
    uint bits = asuint(value);
    // Test NaN classification without requiring a particular payload.
    return (bits & 0x7fffffffu) > 0x7f800000u ? 0x7fc00000u : bits;
}
[numthreads(1, 1, 1)]
void main(uint3 tid : SV_DispatchThreadID) {
    uint address = tid.x * 8;
    uint2 pair = inputs.Load2(address);
    float value = asfloat(pair.x);
    outputs.Store2(address, uint2(
        readback_word(frexp_mant32(value)), readback_word(ldexp32(value, asint(pair.y)))));
}
"""
    out = Path(__file__).resolve().parents[1] / "out"
    out.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pixel-fp32-", dir=out) as d:
        work = Path(d)
        for version, code in (("original", library), ("round_ties_up", library.replace(tie_even, "rem >= half_bit"))):
            hlsl = work / f"{version}.hlsl"
            spv = hlsl.with_suffix(".spv")
            test = hlsl.with_suffix(".shader_test")
            hlsl.write_text(code + wrapper)
            subprocess.run([
                str(args.dxc.resolve()), "-spirv", "-fspv-target-env=vulkan1.1",
                "-T", "cs_6_0", "-E", "main", "-Fo", spv, hlsl,
            ], check=True)
            test.write_text(shader_test(spv.read_bytes()))
            for device in args.device or [None]:
                cmd = [str(args.vkrunner.resolve())]
                if device is not None:
                    cmd.extend(("--device-id", str(device)))
                run = subprocess.run([*cmd, test], capture_output=True, text=True)
                print(f"Device {device or 'default'}, {version}: {run.returncode}", flush=True)
                # VkRunner reports probe failures on stdout and only the PIGLIT line on stderr.
                output = run.stdout + run.stderr
                print(output, end="")
                if version == "original" and run.returncode != 0:
                    raise SystemExit("The GPU results differ from the binary32 reference")
                if version == "round_ties_up" and not (run.returncode == 1 and "SSBO probe failed" in output):
                    raise SystemExit("The rounding negative control did not produce a failing probe")
    print(f"{len(CASES)} cases, {2 * len(CASES)} output words checked per GPU")


if __name__ == "__main__":
    main()
