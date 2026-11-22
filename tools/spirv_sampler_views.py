"""Separate the named bindless sampler table's depth-reference uses for HLSL."""
import re


def split_sampler_views(assembly):
    if "Dref" not in assembly or "%samplers " not in assembly:
        return assembly
    lines = assembly.splitlines()
    definitions = {}
    comparisons = []
    ordinary = False
    decorated = set()
    indirect_decorations = False
    for index, line in enumerate(lines):
        words = line.split()
        if words[:1] in (["OpGroupDecorate"], ["OpDecorateId"]):
            indirect_decorations = True
        if words[:1] == ["OpDecorate"] and len(words) >= 3 and words[2] not in ("Binding", "DescriptorSet"):
            decorated.add(words[1])
        if len(words) < 4 or words[1] != "=":
            continue
        definitions[words[0]] = words[2:]
        if words[2].startswith("OpImage") and "Dref" in words[2]:
            comparisons.append((index, words))
        elif words[2].startswith(("OpImageSample", "OpImageGather")):
            ordinary = True
    if not comparisons or not ordinary:
        return assembly
    if indirect_decorations:
        raise ValueError("unsupported indirect descriptor decorations")
    prefix = "%bridge_cmp"
    if prefix in assembly or re.search(r"OpDecorate %\S+ DescriptorSet 3\b", assembly):
        raise ValueError("comparison sampler view requires free descriptor set 3 and bridge_cmp IDs")
    table = definitions.get("%samplers", [])
    if table != ["OpVariable", "%_ptr_UC_rt_smp", "UniformConstant"]:
        raise ValueError("unsupported sampler table declaration")
    replacements = {}
    for index, words in comparisons:
        image = definitions.get(words[4], [])
        if len(image) != 4 or image[0] != "OpSampledImage":
            raise ValueError("unsupported depth-reference sampled image")
        sampler = definitions.get(image[3], [])
        if len(sampler) != 3 or sampler[:2] != ["OpLoad", "%smp"]:
            raise ValueError("unsupported depth-reference sampler load")
        pointer = definitions.get(sampler[2], [])
        if len(pointer) != 4 or pointer[:3] != ["OpAccessChain", "%_ptr_UC_smp", "%samplers"]:
            raise ValueError("unsupported depth-reference sampler provenance")
        if decorated.intersection(("%samplers", words[4], image[3], sampler[2])):
            raise ValueError("unsupported decorated sampler path")
        name = f"{prefix}_{index}"
        words[4] = name + "_image"
        replacements[index] = [
            f"{name}_ptr = OpAccessChain %_ptr_UC_smp {prefix} {pointer[3]}",
            f"{name}_value = OpLoad %smp {name}_ptr",
            f"{name}_image = OpSampledImage {image[1]} {image[2]} {name}_value",
            " ".join(words),
        ]
    bindings = {line.strip() for line in lines if line.strip().startswith("OpDecorate %samplers ")}
    if bindings != {"OpDecorate %samplers Binding 1", "OpDecorate %samplers DescriptorSet 0"}:
        raise ValueError("expected undecorated sampler table at set 0 binding 1")
    out = []
    for i, line in enumerate(lines):
        words = line.split()
        if words[:1] == ["OpEntryPoint"] and "%samplers" in words:
            line += " " + prefix
        if words == ["OpDecorate", "%samplers", "Binding", "1"]:
            out.extend([f"OpDecorate {prefix} DescriptorSet 3", f"OpDecorate {prefix} Binding 1"])
        if words[:2] == ["%samplers", "="]:
            out.append(f"{prefix} = " + " ".join(table))
        out.extend(replacements.get(i, [line]))
    return "\n".join(out) + "\n"
