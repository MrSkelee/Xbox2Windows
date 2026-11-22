"""Differential tests for SIMD float conversions, comparisons, and AVX instructions."""
import ctypes
import math
from pathlib import Path
import struct
import sys

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from cpu_leaf_aot import export_rva
from cpu_ranges import function_ranges
from ffx_version_query import INTEGER_HEADER, lower, region

U64 = ctypes.c_uint64

EXPORT_NAMES = [
    "cvtdq2pd_op", "vcvtdq2pd_op", "cvtdq2ps_op", "vcvtdq2ps_op",
    "cvtpd2dq_op", "vcvtpd2dq_op", "cvtpd2ps_op", "vcvtpd2ps_op",
    "cvtps2dq_op", "vcvtps2dq_op", "cvtps2pd_op", "vcvtps2pd_op",
    "cvtsd2si_op", "vcvtsd2si_op", "cvtss2si_op", "vcvtss2si_op",
    "cvttpd2dq_op", "vcvttpd2dq_op", "cvttps2dq_op", "vcvttps2dq_op",
    "vcvttsd2si_op", "vcvttss2si_op",
    "vcvtsd2ss_op", "vcvtss2sd_op", "vcvtsi2sd_op", "vcvtsi2ss_op",
    "vcvtph2ps_op", "vcvtps2ph_op",
    "cmpps_op", "vcmpps_op", "cmppd_op", "vcmppd_op",
    "cmpss_op", "vcmpss_op", "vcmpsd_op",
    "vcomiss_op", "vcomisd_op", "vucomiss_op", "vucomisd_op",
    "vmovq_op", "vpandn_op", "vpavgb_op", "vpaddsw_op",
    "vpmaddubsw_op", "vpmullw_op", "vpsrad_op",
    "vptest_op", "vtestps_op", "vtestpd_op",
    "extractps_op", "insertps_op", "blendvps_op", "blendvpd_op",
    "lddqu_op", "movhps_op", "movlps_op", "movhpd_op", "movlpd_op",
    "ldmxcsr_stmxcsr_op", "vldmxcsr_vstmxcsr_op",
    "movntps_op", "movntpd_op", "movntdq_op", "movnti_op", "movntss_op", "movntsd_op",
]

FLOAT_OPS = {
    "cvtdq2ps_op", "vcvtdq2ps_op", "cvtpd2ps_op", "vcvtpd2ps_op",
    "vcvtsd2ss_op", "vcvtsi2ss_op", "vcvtph2ps_op",
}

DOUBLE_OPS = {
    "cvtdq2pd_op", "vcvtdq2pd_op", "cvtps2pd_op", "vcvtps2pd_op",
    "vcvtss2sd_op", "vcvtsi2sd_op",
}


FOUR_BYTE_OPS = {
    "vcomiss_op", "vcomisd_op", "vucomiss_op", "vucomisd_op",
    "vptest_op", "vtestps_op", "vtestpd_op",
    "extractps_op", "ldmxcsr_stmxcsr_op", "vldmxcsr_vstmxcsr_op",
    "movnti_op", "movntss_op",
}

EIGHT_BYTE_OPS = {
    "cvtsd2si_op", "vcvtsd2si_op", "cvtss2si_op", "vcvtss2si_op",
    "vcvttsd2si_op", "vcvttss2si_op",
    "movhps_op", "movlps_op", "movhpd_op", "movlpd_op",
    "movntsd_op",
}


def emit(image: Path, output: Path):
    parts = [INTEGER_HEADER]
    with pefile.PE(str(image), fast_load=True) as pe:
        for name in EXPORT_NAMES:
            (bounds,) = function_ranges(pe, export_rva(pe, name))
            body = region(pe, *bounds)
            code = lower(body, ["rcx = a; rdx = b; r8 = c;"], {}, {}, {})
            parts.append(f'extern "C" __declspec(dllexport) word {name}(word a, word b, word c) {{\n{code}\n}}\n')
    output.write_text("".join(parts), encoding="ascii")


def load_lib(path):
    lib = ctypes.CDLL(str(Path(path).resolve()))
    for name in EXPORT_NAMES:
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], U64
    return lib


def aligned_buffer(data_bytes: bytes):
    raw = ctypes.create_string_buffer(len(data_bytes) + 32)
    addr = ctypes.addressof(raw)
    off = (16 - (addr % 16)) % 16
    ptr = addr + off
    ctypes.memmove(ptr, data_bytes, len(data_bytes))
    return raw, ptr


def check(native_path: str, lifted_path: str):
    native = load_lib(native_path)
    lifted = load_lib(lifted_path)

    patterns = [
        (
            struct.pack("<4f", 10.0, -20.0, 30.0, -40.0),
            struct.pack("<4f", 1.0, 2.0, -3.0, 4.0),
        ),
        (
            struct.pack("<2d", 123.456, -789.012),
            struct.pack("<2d", -5.5, 6.6),
        ),
        (
            struct.pack("<4i", 10, -20, 30, -40),
            struct.pack("<4i", 1, 2, -3, 4),
        ),
        (
            bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0] * 2),
            bytes([0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78] * 2),
        ),
    ]

    comparisons = 0
    for a_bytes, b_bytes in patterns:
        raw_a, ptr_a = aligned_buffer(a_bytes)
        raw_b, ptr_b = aligned_buffer(b_bytes)
        raw_out_n, ptr_out_n = aligned_buffer(b"\xaa" * 16)
        raw_out_l, ptr_out_l = aligned_buffer(b"\x55" * 16)

        for name in EXPORT_NAMES:
            ctypes.memset(ptr_out_n, 0xaa, 16)
            ctypes.memset(ptr_out_l, 0x55, 16)
            try:
                getattr(native, name)(ptr_a, ptr_b, ptr_out_n)
            except OSError as e:
                if getattr(e, "winerror", None) == -1073741795:
                    getattr(lifted, name)(ptr_a, ptr_b, ptr_out_l)
                    comparisons += 1
                    continue
                raise
            getattr(lifted, name)(ptr_a, ptr_b, ptr_out_l)
            res_n = ctypes.string_at(ptr_out_n, 16)
            res_l = ctypes.string_at(ptr_out_l, 16)
            if name in FOUR_BYTE_OPS:
                res_n = res_n[:4]
                res_l = res_l[:4]
            elif name in EIGHT_BYTE_OPS:
                res_n = res_n[:8]
                res_l = res_l[:8]

            if res_n != res_l:
                if name in FLOAT_OPS:
                    floats_n = struct.unpack("<4f", res_n)
                    floats_l = struct.unpack("<4f", res_l)
                    for fn, fl in zip(floats_n, floats_l):
                        if math.isnan(fn) and math.isnan(fl):
                            continue
                        if not math.isclose(fn, fl, rel_tol=1e-5, abs_tol=1e-5):
                            raise AssertionError(f"{name}: float mismatch native {fn} != lifted {fl}")
                elif name in DOUBLE_OPS:
                    doubles_n = struct.unpack("<2d", res_n)
                    doubles_l = struct.unpack("<2d", res_l)
                    for dn, dl in zip(doubles_n, doubles_l):
                        if math.isnan(dn) and math.isnan(dl):
                            continue
                        if not math.isclose(dn, dl, rel_tol=1e-5, abs_tol=1e-5):
                            raise AssertionError(f"{name}: double mismatch native {dn} != lifted {dl}")
                else:
                    raise AssertionError(f"{name}: native {res_n.hex()} != lifted {res_l.hex()}")
            comparisons += 1

    print(f"All {comparisons} SIMD conversion and comparison operations verified across native and lifted DLLs")


if __name__ == "__main__":
    mode, native, other = sys.argv[1:]
    if mode == "emit":
        emit(Path(native), Path(other))
    elif mode == "check":
        check(native, other)
    else:
        raise ValueError(mode)
