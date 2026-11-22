"""Lower subgroup ballot extraction in the bridge's named uint32 SPIR-V profile."""
import re

OP = re.compile(r"\s*(%\w+)\s*=\s*OpGroupNonUniformBallotBitExtract\s+%bool\s+%\w+\s+(%\w+)\s+(%\w+)\s*(?:;.*)?")


def lower_ballot_extract(assembly):
    if "OpGroupNonUniformBallotBitExtract" not in assembly:
        return assembly
    if "%x2w_ballot_" in assembly:
        raise ValueError("Reserved ballot lowering ID already in use")
    lines = []
    declared = False
    for line in assembly.splitlines():
        if not declared and re.search(r"=\s*OpFunction\s", line):
            for value in (0, 1, 5, 31):
                lines.append(f"%x2w_ballot_c{value} = OpConstant %uint {value}")
            declared = True
        match = OP.fullmatch(line)
        if not match:
            lines.append(line)
            continue
        dst, ballot, index = match.groups()
        tmp = "%x2w_ballot_" + dst[1:] + "_"
        lines.extend([
            f"{tmp}word_index = OpShiftRightLogical %uint {index} %x2w_ballot_c5",
            f"{tmp}word = OpVectorExtractDynamic %uint {ballot} {tmp}word_index",
            f"{tmp}bit = OpBitwiseAnd %uint {index} %x2w_ballot_c31",
            f"{tmp}shifted = OpShiftRightLogical %uint {tmp}word {tmp}bit",
            f"{tmp}low = OpBitwiseAnd %uint {tmp}shifted %x2w_ballot_c1",
            f"{dst} = OpINotEqual %bool {tmp}low %x2w_ballot_c0",
        ])
    return "\n".join(lines) + "\n"

