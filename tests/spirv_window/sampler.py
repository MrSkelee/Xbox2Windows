"""Validate the original and split sampler module, then optionally run the D3D12 readback."""
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from spirv_sampler_views import split_sampler_views


def emit(folder, assembler, validator, cross, pixel=False):
    original = Path(__file__).with_name("sampler.spvasm")
    if pixel:
        # Same resource flow with implicit LOD in the fragment stage.
        text = original.read_text().replace('GLCompute', 'Fragment').replace(' %out %tid', ' %out')
        text = text.replace('LocalSize 1 1 1', 'OriginUpperLeft')
        text = text.replace('OpDecorate %tid BuiltIn WorkgroupId', '').replace('%tid = OpVariable %input Input', '')
        text = text.replace('%xyzval = OpLoad %xyz %tid', '').replace('OpCompositeExtract %uint %xyzval 0', 'OpCopyObject %uint %zero')
        text = text.replace('OpImageSampleExplicitLod %vec4 %si %uv Lod %lod', 'OpImageSampleImplicitLod %vec4 %si %uv')
        original = folder / "pixel.spvasm"
        original.write_text(text)
    split = folder / "split.spvasm"
    source = original.read_text()
    for unsupported in (source.replace("DescriptorSet 0", "DescriptorSet 3", 1),
                        source.replace("OpDecorate %out Binding 0", "OpDecorate %p NonUniformEXT")):
        try:
            split_sampler_views(unsupported)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted an unsupported descriptor layout")
    split.write_text(split_sampler_views(source))
    module = folder / "shader.spv"
    for source in (original, split):
        subprocess.run([assembler, "--target-env", "vulkan1.2", source, "-o", module], check=True)
        subprocess.run([validator, "--target-env", "vulkan1.2", module], check=True)
    hlsl = folder / "shader.hlsl"
    subprocess.run([cross, module, "--hlsl", "--shader-model", "66", "--output", hlsl], check=True)
    text = hlsl.read_text()
    for token in ("SamplerState ", "SamplerComparisonState ", (".Sample(" if pixel else ".SampleLevel("), ".SampleCmpLevelZero("):
        if token not in text:
            raise ValueError(f"missing {token} in emitted HLSL")
    return hlsl


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        pixel = emit(Path(tmp), *sys.argv[1:4], pixel=True)
        if len(sys.argv) > 4:
            subprocess.run([sys.argv[4], "-T", "ps_6_6", "-E", "main", "-Fo", pixel.with_suffix(".dxil"), pixel], check=True)
        hlsl = emit(Path(tmp), *sys.argv[1:4])
        if len(sys.argv) > 4:
            dxil = hlsl.with_suffix(".dxil")
            subprocess.run([sys.argv[4], "-T", "cs_6_6", "-E", "main", "-Fo", dxil, hlsl], check=True)
            sys.exit(subprocess.run([sys.argv[5], sys.argv[6], "--spirv-sampler-views", dxil]).returncode)
