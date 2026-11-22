"""Controls for dependency_paths: an unrecognized loader hash is reported, not silently skipped."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "dependency_paths.py"
sys.path.insert(0, str(TOOL.parent))
from dependency_paths import FFX_EXPORTS, FFX_LOADER, trace  # noqa: E402

LOADER = "pkg/amd_fidelityfx_loader_xbox.dll"
UPSCALER = "pkg/amd_fidelityfx_upscaler_xbox.dll"


def inventory(loader_hash):
    return {
        "images": {
            LOADER: {"sha256": loader_hash, "exports": []},
            UPSCALER: {"sha256": "0" * 64, "exports": [{"name": name} for name in FFX_EXPORTS]},
        },
        "imports": [],
    }


def check_cli_survives_narrow_stdout():
    name = "pkg/Ωmega.dll"
    data = {"images": {name: {"sha256": "0" * 64, "exports": []}}, "imports": []}
    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    env.pop("PYTHONUTF8", None)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "inventory.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        result = subprocess.run([sys.executable, "-B", str(TOOL), str(path)],
                                capture_output=True, env=env)
    if result.returncode != 0:
        raise AssertionError(f"CLI failed on a cp1252 stdout: {result.stderr.decode(errors='replace')}")
    if name not in json.loads(result.stdout)["entries"]:
        raise AssertionError(f"image name did not survive the JSON output: {result.stdout!r}")


def main():
    check_cli_survives_narrow_stdout()
    pinned = trace(inventory(FFX_LOADER), LOADER)
    if UPSCALER not in pinned["reachable"]:
        raise AssertionError(f"pinned loader did not reach the upscaler: {pinned['reachable']}")
    if "ffx:0x10000" not in pinned["reachable"][UPSCALER]["reasons"]:
        raise AssertionError(f"missing conditional reason: {pinned['reachable'][UPSCALER]}")
    if [f for f in pinned["findings"] if f["problem"] == "unverified_loader_hash"]:
        raise AssertionError(f"pinned loader reported as unverified: {pinned['findings']}")

    other = "1" * 64
    changed = trace(inventory(other), LOADER)
    if UPSCALER in changed["reachable"]:
        raise AssertionError(f"unverified loader still reached the conditional target: {changed['reachable']}")
    findings = [f for f in changed["findings"] if f["problem"] == "unverified_loader_hash"]
    if len(findings) != 1:
        raise AssertionError(f"expected one unverified loader finding: {changed['findings']}")
    if findings[0]["sha256"] != other or findings[0]["expected"] != FFX_LOADER:
        raise AssertionError(f"finding does not name both hashes: {findings[0]}")

    print("dependency_paths: the pinned hash reaches the conditional target; "
          "a different hash reports unverified_loader_hash and no conditional edge")


if __name__ == "__main__":
    sys.exit(main())
