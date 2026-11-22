"""Lower the named, DWORD-addressed SPIR-V profile to two logical storage buffers."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


from spirv_ballot_extract import lower_ballot_extract
from spirv_sampler_views import split_sampler_views


ID = r"%[A-Za-z0-9_]+"
CAST = re.compile(rf"({ID}) = OpConvertUToPtr %_ptr_PSB_(arr|uint) ({ID})")
ACCESS = re.compile(rf"({ID}) = OpAccessChain %_ptr_PSB_uint ({ID}) ({ID})")
POINTER = re.compile(rf"({ID}) = OpTypePointer (\w+) ({ID})")


def word_pointer(dst, base, index):
    """Select the last DWORD offset for an unaligned or unrepresentable address."""
    name = "%x2w_" + dst[1:]
    lines = []
    addr = base
    if index:
        addr = name + "_address"
        lines.extend([
            f"{name}_index = OpUConvert %ulong {index}",
            f"{name}_delta = OpShiftLeftLogical %ulong {name}_index %x2w_shift",
            f"{addr} = OpIAdd %ulong {base} {name}_delta",
        ])
    lines.extend([
        f"{name}_low = OpBitwiseAnd %ulong {addr} %x2w_mask",
        f"{name}_aligned = OpIEqual %bool {name}_low %x2w_zero64",
        f"{name}_range = OpULessThan %bool {addr} %x2w_end",
        f"{name}_valid = OpLogicalAnd %bool {name}_aligned {name}_range",
    ])
    valid = name + "_valid"
    if index:
        valid = name + "_checked"
        lines.extend([
            f"{name}_nowrap = OpUGreaterThanEqual %bool {addr} {base}",
            f"{valid} = OpLogicalAnd %bool {name}_valid {name}_nowrap",
        ])
    lines.extend([
        f"{name}_word64 = OpShiftRightLogical %ulong {addr} %x2w_shift",
        f"{name}_word = OpUConvert %uint {name}_word64",
        f"{name}_selected = OpSelect %uint {valid} {name}_word %x2w_invalid",
        f"{dst} = OpAccessChain %_ptr_PSB_uint %x2w_heap %c0 {name}_selected",
    ])
    return lines


def merge_pointer_types(lines):
    # The push-constant and physical pointer types can become the same logical
    # pointer type. SPIR-V validation requires a single such declaration.
    seen = {}
    aliases = {}
    kept = []
    for line in lines:
        match = POINTER.fullmatch(line)
        if match:
            name, storage, pointee = match.groups()
            key = storage, aliases.get(pointee, pointee)
            if key in seen:
                aliases[name] = seen[key]
                continue
            seen[key] = name
        kept.append(line)
    return "\n".join(re.sub(ID, lambda m: aliases.get(m[0], m[0]), line) for line in kept) + "\n"


def lower(assembly):
    lines = [line.strip() for line in split_sampler_views(lower_ballot_extract(assembly)).splitlines() if line.strip()]
    model = "OpMemoryModel PhysicalStorageBuffer64 GLSL450"
    if model not in lines or lines.count("%user_data = OpVariable %_ptr_PC_UserData PushConstant") != 1:
        raise ValueError("expected a physical-address module with the named user-data block")
    if any("%x2w_" in line or re.fullmatch(rf"OpDecorate {ID} DescriptorSet [12]", line) for line in lines):
        raise ValueError("address window needs unused identifier prefix x2w_ and descriptor sets 1 and 2")
    if sum(line.startswith("OpEntryPoint ") for line in lines) != 1:
        raise ValueError("expected one shader entry point")
    required = {"%uint = OpTypeInt 32 0", "%ulong = OpTypeInt 64 0", "%bool = OpTypeBool",
                "%c0 = OpConstant %uint 0", "%rt_uint = OpTypeRuntimeArray %uint",
                "OpDecorate %rt_uint ArrayStride 4", "OpDecorate %UserData Block",
                "%_ptr_PSB_uint = OpTypePointer PhysicalStorageBuffer %uint",
                "%_ptr_PSB_arr = OpTypePointer PhysicalStorageBuffer %rt_uint"}
    if required.difference(lines):
        raise ValueError("unsupported physical pointer or scalar layout")
    annotations = ["OpDecorate %user_data DescriptorSet 1", "OpDecorate %user_data Binding 0",
                   "OpDecorate %user_data NonWritable", "OpDecorate %x2w_heap DescriptorSet 2",
                   "OpDecorate %x2w_heap Binding 0", "OpDecorate %x2w_block Block",
                   "OpMemberDecorate %x2w_block 0 Offset 0"]
    declarations = ["%x2w_block = OpTypeStruct %rt_uint",
                    "%x2w_heap_ptr = OpTypePointer StorageBuffer %x2w_block",
                    "%x2w_heap = OpVariable %x2w_heap_ptr StorageBuffer",
                    "%x2w_shift = OpConstant %uint 2", "%x2w_mask = OpConstant %ulong 3",
                    "%x2w_zero64 = OpConstant %ulong 0", "%x2w_end = OpConstant %ulong 4294967292",
                    "%x2w_invalid = OpConstant %uint 1073741823"]
    output = []
    arrays = {}
    physical_words = set()
    for line in lines:
        cast = CAST.fullmatch(line)
        access = ACCESS.fullmatch(line)
        if access or cast and cast[2] == "uint":
            physical_words.add((access or cast)[1])
    for line in lines:
        if line in ('OpExtension "SPV_KHR_physical_storage_buffer"', "OpCapability PhysicalStorageBufferAddresses",
                    "%_ptr_PSB_arr = OpTypePointer PhysicalStorageBuffer %rt_uint"):
            continue
        if line.startswith("OpDecorate ") and annotations:
            output.extend(annotations)
            annotations = []
        if " = OpFunction " in line and declarations:
            output.extend(declarations)
            declarations = []
        if cast := CAST.fullmatch(line):
            dst, kind, addr = cast.groups()
            if kind == "arr":
                arrays[dst] = addr
            else:
                output.extend(word_pointer(dst, addr, None))
            continue
        if access := ACCESS.fullmatch(line):
            dst, pointer, index = access.groups()
            if pointer not in arrays:
                raise ValueError("unknown physical array pointer")
            output.extend(word_pointer(dst, arrays[pointer], index))
            continue
        used = set(re.findall(ID, line)) & physical_words
        if used:
            fields = line.split()
            reads_word = fields[1:4] == ["=", "OpLoad", "%uint"] and fields[4] in used
            writes_word = fields[0] == "OpStore" and fields[1] in used
            if not (reads_word or writes_word) or len(used) != 1:
                raise ValueError("unhandled physical word pointer use")
        if line == model:
            line = "OpMemoryModel Logical GLSL450"
        elif line.startswith("OpEntryPoint "):
            line += " %x2w_heap"
        elif line == "%_ptr_PSB_uint = OpTypePointer PhysicalStorageBuffer %uint":
            line = "%_ptr_PSB_uint = OpTypePointer StorageBuffer %uint"
        elif "PushConstant" in line:
            if line.split(" = ")[0] not in ("%_ptr_PC_UserData", "%_ptr_PC_uint", "%user_data"):
                raise ValueError("unrecognized push-constant declaration")
            line = line.replace("PushConstant", "StorageBuffer")
        elif any(word in line for word in ("PhysicalStorageBuffer", "OpConvertUToPtr", "OpConvertPtrToU", "%_ptr_PSB_arr")):
            raise ValueError("unhandled physical pointer operation")
        output.append(line)
    return merge_pointer_types(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--assembler", default="spirv-as")
    parser.add_argument("--validator", default="spirv-val")
    args = parser.parse_args()
    if args.output.resolve() == args.source.resolve():
        parser.error("use separate input assembly and output binary paths")
    original = args.source.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(dir=args.output.parent) as directory:
        path = Path(directory)
        binary = path / "module.spv"

        def validate(source):
            subprocess.run([args.assembler, "--target-env", "vulkan1.2", source, "-o", binary], check=True)
            subprocess.run([args.validator, "--target-env", "vulkan1.2", binary], check=True)

        snapshot = path / "original.spvasm"
        snapshot.write_text(original, encoding="utf-8")
        validate(snapshot)
        adapted = path / "logical.spvasm"
        adapted.write_text(lower(original), encoding="utf-8")
        validate(adapted)
        binary.replace(args.output)


if __name__ == "__main__":
    main()
