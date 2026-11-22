"""Exercise the named ballot profile before HLSL compilation and at GPU readback."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from spirv_ballot_extract import lower_ballot_extract


def emit(directory, assembler, validator, cross):
    source = Path(__file__).with_name("ballot.spvasm")
    adapted = directory / "logical.spvasm"
    adapted.write_text(lower_ballot_extract(source.read_text()))
    module = directory / "module.spv"
    for path in (source, adapted):
        subprocess.run([assembler, "--target-env", "vulkan1.2", path, "-o", module], check=True)
        subprocess.run([validator, "--target-env", "vulkan1.2", module], check=True)
    hlsl = directory / "ballot.hlsl"
    subprocess.run([cross, module, "--hlsl", "--shader-model", "66", "--output", hlsl], check=True)
    return hlsl


def draw(directory, dxil, renderer, adapter):
    mask = 0x784632A0A156789102CABEDE81234567
    bits = [(mask >> i) & 1 for i in range(128)]
    for wrong in (False, True):
        expected = bits.copy()
        if wrong:
            expected[31], expected[32] = expected[32], expected[31]
            assert expected != bits
        case = directory / "ballot.case"
        case.write_bytes(struct.pack("<321I", 4, *expected, *([0xc5c5c5c5] * 192)))
        run = subprocess.run([renderer, adapter, "--compute-store-case", dxil, case],
                             capture_output=True, text=True)
        print(run.stdout, run.stderr, flush=True)
        if run.returncode == 77 and not wrong:
            return 77
        mismatches = 2 if wrong else 0
        if (run.returncode != int(wrong)
                or f"compared_words=320 mismatches={mismatches}" not in run.stdout):
            raise RuntimeError("Unexpected ballot readback")
    return 0


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        hlsl = emit(directory, *sys.argv[1:4])
        if len(sys.argv) > 4:
            dxil = directory / "ballot.dxil"
            subprocess.run([sys.argv[4], "-T", "cs_6_6", "-E", "main", "-Fo", dxil, hlsl], check=True)
            sys.exit(draw(directory, dxil, *sys.argv[5:]))
