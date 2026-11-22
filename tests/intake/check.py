"""End-to-end CLI checks with locally compiled PE fixtures. Never load a fixture."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

import pefile

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))
from intake_exe import main as intake_main
from pe_inventory import exports, scan


def check(folder, fixture, provider):
    # A native x64 interpreter can run in a shell without this environment hint.
    os.environ.pop("PROCESSOR_ARCHITECTURE", None)
    root = folder / "build"
    root.mkdir()
    shutil.copyfile(provider, root / provider.name)
    slot = "main.exe"
    (root / "MicrosoftGame.Config").write_text(
        '<Game><ExecutableList><Executable TargetDeviceFamily="Scarlett" Name="main.exe"/></ExecutableList></Game>')
    (root / "layout.xml").write_text(
        '<Package><Chunk Id="1001"><FileGroup DestinationPath="/" Include="main.exe"/></Chunk></Package>')
    # A standard multifile v1 torrent with one piece crossing the fixture files.
    files = sorted(root.iterdir())
    piece = hashlib.sha1(b"".join(p.read_bytes() for p in files)).digest()
    entries = b"".join(
        b"d6:lengthi%de4:pathl%d:%see" %
        (p.stat().st_size, len(p.name), p.name.encode("ascii")) for p in files)
    torrent = root / "fixture.torrent"
    torrent.write_bytes(b"d4:infod5:filesl" + entries +
                        b"e4:name5:build12:piece lengthi16777216e6:pieces20:" + piece + b"ee")
    integrity = folder / "integrity.json"
    subprocess.run([sys.executable, "-B", str(TOOLS / "verify_build.py"), str(root),
                    "--output", str(integrity)], check=True, capture_output=True)
    baseline = folder / "baseline.json"
    baseline.write_text(json.dumps(scan(root)))
    original = baseline.read_bytes()
    reports = folder / "reports"

    cli_checked = False

    def run(expected_exit, *args):
        nonlocal cli_checked
        before = set(reports.glob("*.json"))
        cli_args = ["--build", str(root), "--baseline", str(baseline), "--integrity", str(integrity),
                    "--reports", str(reports), *map(str, args)]
        if not cli_checked:
            result = subprocess.run([sys.executable, "-B", str(TOOLS / "intake_exe.py"), *cli_args],
                                    capture_output=True, text=True)
            code, out, err = result.returncode, result.stdout, result.stderr
            cli_checked = True
        else:
            out_buf, err_buf = io.StringIO(), io.StringIO()
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                code = intake_main(cli_args)
            out, err = out_buf.getvalue(), err_buf.getvalue()
        assert code == expected_exit, (out, err)
        new, = set(reports.glob("*.json")) - before
        assert baseline.read_bytes() == original
        return json.loads(new.read_text(encoding="utf-8"))

    assert run(3)["status"] == "awaiting_executable"
    report = run(0, fixture)
    assert report["diff"]["added_images"] == [slot]
    assert report["package"]["old_pieces"]["matched"] == 1
    assert report["diff"]["changed_images"] == report["diff"]["removed_images"] == []
    assert report["candidate"]["sha256"] == hashlib.sha256(fixture.read_bytes()).hexdigest()
    assert report["pe"]["entry_rva"] and report["pe"]["entry_section"] == ".text"
    assert report["pe"]["tls"]["callbacks_rva"] and report["pe"]["tls"]["template_start_va"]
    startup = report["pe"]["startup"]
    locations = startup["locations"]
    assert [loc["role"] for loc in locations] == ["tls_callback"] * (len(locations) - 1) + ["entry"]
    assert [loc["rva"] for loc in locations] == report["pe"]["tls"]["callbacks_rva"] + [report["pe"]["entry_rva"]]
    with pefile.PE(str(fixture)) as pe:
        functions = [record.struct for record in pe.DIRECTORY_ENTRY_EXCEPTION]
        assert startup["exception_table"] == "indexed" and startup["runtime_functions"] == len(functions)
        for loc in locations:
            assert loc["file_offset"] == pe.get_offset_from_rva(loc["rva"])
            match = next((f for f in functions if f.BeginAddress <= loc["rva"] < f.EndAddress), None)
            assert loc["runtime_function"] == (dict(begin_rva=match.BeginAddress, end_rva=match.EndAddress,
                unwind_data_rva=match.UnwindData) if match else None)
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        directory.Size -= 1
        incomplete = folder / "incomplete-directory.exe"
        pe.write(str(incomplete))
        directory.VirtualAddress = directory.Size = 0
        absent = folder / "no-directory.exe"
        pe.write(str(absent))
    incomplete_startup = run(0, incomplete)["pe"]["startup"]
    assert incomplete_startup["exception_table"] == "unusable"
    absent_startup = run(0, absent)["pe"]["startup"]
    assert absent_startup["exception_table"] == "absent"
    assert all(loc["runtime_function"] is None for loc in absent_startup["locations"])
    for result in (absent_startup, incomplete_startup):
        assert [loc["file_offset"] for loc in result["locations"]] == [loc["file_offset"] for loc in locations]
    paths = report["dependency_paths"]
    assert paths["reachable"][provider.name] == dict(conditional=False, path=[slot, provider.name], reasons=["normal"])
    assert any(f["dll"] == "intake_delay.dll" and f["conditional"] and f["reasons"] == ["delay"]
               for f in paths["findings"])
    loader = "amd_fidelityfx_loader_xbox.dll"
    normal, = [f for f in paths["findings"] if f["dll"] == loader and f["symbol"] == "ffxQuery"]
    assert normal["path"] == [slot] and normal["reasons"] == ["normal"] and not normal["conditional"]
    assert normal["problem"] == "provider_not_found" and normal["desktop_chain"] == [
        dict(dll=loader, provider=loader, symbol="ffxQuery")]
    assert not any(f["dll"] == "amd_fidelityfx_framegeneration_xbox.dll" for f in paths["findings"])
    edges = {(r["kind"], r["dll"], r["symbol"]): r for r in report["inventory"]["imports"] if r["image"] == slot}
    for symbol in ("named_value", "#77"):
        assert edges["normal", provider.name, symbol]["bundle_exports_in"] == [provider.name]
    delayed = edges["delay", "intake_delay.dll", "delayed_value"]
    gaps = {(r["kind"], r["dll"], r["symbol"]): r["seen_unresolved_in_baseline"]
            for r in report["entry_import_gaps"]}
    assert gaps["delay", "intake_delay.dll", "delayed_value"] is False
    assert gaps["normal", loader, "ffxQuery"] is False
    assert ("normal", provider.name, "named_value") not in gaps
    assert not delayed["bundle_exports_in"] and delayed["desktop_export"] == "provider_not_found"
    assert not (root / slot).exists()
    # A second synthetic image already asks for the same unresolved symbols.
    # Its baseline demonstrates the difference between a new caller and a new gap.
    peer = root / "peer.exe"
    shutil.copyfile(fixture, peer)
    peer_baseline = folder / "peer-baseline.json"
    peer_baseline.write_text(json.dumps(scan(root)))
    repeated = run(0, fixture, "--baseline", peer_baseline)
    peer.unlink()
    assert repeated["entry_import_gaps"]
    assert all(r["seen_unresolved_in_baseline"] for r in repeated["entry_import_gaps"])
    # pefile skips import names outside letters, digits and ._?@$()<>, and drops a descriptor
    # left empty. A same-length rename keeps the image layout and must keep both edges.
    renamed = folder / "renamed-imports.exe"
    with pefile.PE(str(fixture)) as pe:
        targets = [s for d in pe.DIRECTORY_ENTRY_IMPORT + pe.DIRECTORY_ENTRY_DELAY_IMPORT
                   for s in d.imports if s.name in (b"named_value", b"delayed_value")]
        assert len(targets) == 2
        for s in targets:
            pe.set_bytes_at_offset(s.name_offset, s.name.replace(b"_", b"-"))
        pe.write(str(renamed))
    renamed_report = run(0, renamed)
    renamed_edges = {(r["kind"], r["dll"], r["symbol"]) for r in renamed_report["inventory"]["imports"]
                     if r["image"] == slot}
    assert renamed_edges == set(edges) - {("normal", provider.name, "named_value"),
                                          ("delay", "intake_delay.dll", "delayed_value")} | {
        ("normal", provider.name, "named-value"), ("delay", "intake_delay.dll", "delayed-value")}
    renamed_gaps = {(r["kind"], r["dll"], r["symbol"]) for r in renamed_report["entry_import_gaps"]}
    assert {("normal", provider.name, "named-value"), ("delay", "intake_delay.dll", "delayed-value")} <= renamed_gaps
    mismatch, = [f for f in renamed_report["dependency_paths"]["findings"] if f.get("symbol") == "named-value"]
    assert mismatch["problem"] == "bundled_export_missing" and mismatch["candidates"] == [provider.name]
    truncated = folder / "truncated.exe"
    truncated.write_bytes(fixture.read_bytes()[:-256])
    assert "Section extends" in run(2, truncated)["error"]
    bad_tls = folder / "bad-tls.exe"
    with pefile.PE(str(fixture)) as pe:
        table_va = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        pe.set_qword_at_rva(table_va - pe.OPTIONAL_HEADER.ImageBase, 1)
        pe.write(str(bad_tls))
    assert "RVA" in run(2, bad_tls)["error"]
    # Windows locates the TLS directory by VirtualAddress alone and ignores Size.
    for size in (0, 39):
        small_tls = folder / f"tls-size-{size}.exe"
        with pefile.PE(str(fixture), fast_load=True) as pe:
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = size
            pe.write(str(small_tls))
        small_report = run(0, small_tls)
        assert small_report["pe"]["tls"] == report["pe"]["tls"]
        assert small_report["pe"]["startup"]["locations"] == locations
    zero_tls_addr = folder / "tls-zero-addr.exe"
    with pefile.PE(str(fixture), fast_load=True) as pe:
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = 40
        pe.write(str(zero_tls_addr))
    zero_tls_report = run(0, zero_tls_addr)
    assert zero_tls_report["pe"]["tls"] is None
    assert [loc["role"] for loc in zero_tls_report["pe"]["startup"]["locations"]] == ["entry"]
    oob_tls = folder / "tls-oob.exe"
    with pefile.PE(str(fixture), fast_load=True) as pe:
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = pe.OPTIONAL_HEADER.SizeOfImage - 16
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = 0
        pe.write(str(oob_tls))
    assert "RVA" in run(2, oob_tls)["error"]
    staged = root / "incoming.exe"
    shutil.copyfile(fixture, staged)
    assert run(0, staged)["diff"]["added_images"] == [slot]
    staged.unlink()
    shutil.copyfile(fixture, root / slot)
    assert run(0)["diff"]["added_images"] == [slot]
    assert "occupies" in run(2, fixture)["error"]
    # Valid JSON of the wrong shape in either input is an intake error, not a traceback.
    good = json.loads(integrity.read_text(encoding="utf-8"))
    shapes = {
        "integrity-list": ("integrity", []),
        "integrity-torrent-int": ("integrity", {**good, "torrent": 7}),
        "baseline-list": ("baseline", []),
    }
    for label, (which, payload) in shapes.items():
        broken = folder / (label + ".json")
        broken.write_text(json.dumps(payload), encoding="utf-8")
        cli_args = ["--build", str(root), "--baseline", str(broken if which == "baseline" else baseline),
                    "--integrity", str(broken if which == "integrity" else integrity),
                    "--reports", str(reports / label)]
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = intake_main(cli_args)
        assert code == 2, (label, code, out_buf.getvalue(), err_buf.getvalue())
        error_report, = (reports / label).glob("*.error.json")
        assert json.loads(error_report.read_text(encoding="utf-8")).get("error"), label
    torrent.write_bytes(b"different")
    assert "Torrent hash differs" in run(2)["error"]
    # pefile stops reading export names at the first one outside its character set and lists the
    # rest as bare ordinals. A same-length rename of the first name must leave named_value bound.
    rejected = folder / "rejected-export"
    rejected.mkdir()
    shutil.copyfile(fixture, rejected / slot)
    with pefile.PE(str(provider)) as pe:
        stored = {s.name: s.ordinal for s in pe.DIRECTORY_ENTRY_EXPORT.symbols}
        alias, = [s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"named_alias"]
        pe.set_bytes_at_offset(alias.name_offset, b"named alias")
        pe.write(str(rejected / provider.name))
    inventory = scan(rejected)
    assert {(e["ordinal"], e["name"]) for e in inventory["images"][provider.name]["exports"]} == {
        (stored[b"named_alias"], "named alias"), (stored[b"named_value"], "named_value"), (77, None)}
    named, = [r for r in inventory["imports"] if r["symbol"] == "named_value"]
    assert named["bundle_exports_in"] == [provider.name]
    check_export_reads(folder, provider)
    check_modified_directory(folder, fixture, provider)


def check_export_reads(folder, provider):
    """A name, forwarder or table outside section file data stops the scan with its RVA."""

    def patched(name, change):
        target = folder / f"export-{name}"
        target.mkdir()
        with pefile.PE(str(provider)) as pe:
            d = pe.DIRECTORY_ENTRY_EXPORT.struct
            rva = change(pe, d, pe.get_section_by_rva(d.AddressOfNames))
            pe.write(str(target / provider.name))
        return target, rva

    def outside(pe, d, section):
        rva = pe.OPTIONAL_HEADER.SizeOfImage + 0x100
        pe.set_dword_at_rva(d.AddressOfNames, rva)
        return rva

    def unterminated(pe, d, section):
        # The last byte of the section's file data, followed by no NUL.
        rva = section.VirtualAddress + section.SizeOfRawData - 1
        section.Misc_VirtualSize = section.SizeOfRawData
        pe.set_bytes_at_rva(rva, b"x")
        pe.set_dword_at_rva(d.AddressOfNames + 4 * (d.NumberOfNames - 1), rva)
        return rva

    def short_names(pe, d, section):
        d.NumberOfNames = (section.VirtualAddress + section.SizeOfRawData - d.AddressOfNames) // 4 + 1
        return d.AddressOfNames

    def forwarder(pe, d, section):
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        rva = pe.OPTIONAL_HEADER.SizeOfImage + 0x100
        directory.Size = rva + 0x100 - directory.VirtualAddress
        pe.set_dword_at_rva(d.AddressOfFunctions + 4 * (77 - d.Base), rva)
        return rva

    def directory_edge(pe, d, section, include_nul):
        value = b"fixture.target\0"
        rva = section.VirtualAddress + section.SizeOfRawData - len(value)
        section.Misc_VirtualSize = section.SizeOfRawData
        pe.set_bytes_at_rva(rva, value)
        pe.set_dword_at_rva(d.AddressOfFunctions + 4 * (77 - d.Base), rva)
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        directory.Size = rva + len(value) - directory.VirtualAddress - int(not include_nul)
        return rva

    valid, _ = patched("last-byte", lambda *args: directory_edge(*args, include_nul=True))
    with pefile.PE(str(valid / provider.name)) as pe:
        assert any(row["ordinal"] == 77 and row["forwarder"] == "fixture.target" for row in exports(pe))

    for name, change, message in (
            ("past-end", lambda *args: directory_edge(*args, include_nul=False), "Unterminated export forwarder at RVA {:#x}"),
            ("outside", outside, "Export name at RVA {:#x} is outside the file's sections"),
            ("unterminated", unterminated, "Unterminated export name at RVA {:#x}"),
            ("short-names", short_names, "Export name pointer table at RVA {:#x} is outside the file's sections"),
            ("forwarder", forwarder, "Export forwarder at RVA {:#x} is outside the file's sections")):
        target, rva = patched(name, change)
        try:
            scan(target)
        except ValueError as error:
            assert str(error) == message.format(rva), (name, error)
        else:
            raise AssertionError(f"{name}: the scan accepted an unreadable export")


def check_modified_directory(folder, fixture, provider):
    """Scan a synthetic directory twice after replacing a DLL in place and adding a new DLL."""
    synth_root = folder / "synth-pkg"
    synth_system = folder / "synth-sys"
    synth_root.mkdir()
    synth_system.mkdir()
    shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "apisetschema.dll",
                    synth_system / "apisetschema.dll")
    shutil.copyfile(fixture, synth_root / "main.exe")
    tampered = bytearray(provider.read_bytes())
    pos = tampered.index(b"named_value\0")
    tampered[pos:pos + 11] = b"other_value"
    sys_provider = synth_system / provider.name
    pkg_provider = synth_root / provider.name
    sys_provider.write_bytes(tampered)
    pkg_provider.write_bytes(tampered)

    first = scan(synth_root, system=synth_system)
    first_edges = {(r["kind"], r["dll"], r["symbol"]): r for r in first["imports"] if r["image"] == "main.exe"}
    assert first_edges["normal", provider.name.lower(), "named_value"]["desktop_export"] == "export_not_found"
    assert first_edges["normal", provider.name.lower(), "named_value"]["bundle_exports_in"] == []
    assert first_edges["delay", "intake_delay.dll", "delayed_value"]["desktop_export"] == "provider_not_found"

    # Replace intake_provider.dll at the exact same path and add a new DLL (intake_delay.dll) to both directories.
    sys_provider.write_bytes(provider.read_bytes())
    pkg_provider.write_bytes(provider.read_bytes())
    delay_fixture = provider.parent / "intake_delay.dll"
    shutil.copyfile(delay_fixture, synth_system / "intake_delay.dll")
    shutil.copyfile(delay_fixture, synth_root / "intake_delay.dll")

    second = scan(synth_root, system=synth_system)
    second_edges = {(r["kind"], r["dll"], r["symbol"]): r for r in second["imports"] if r["image"] == "main.exe"}
    assert second_edges["normal", provider.name.lower(), "named_value"]["desktop_export"] == "export_present"
    assert second_edges["normal", provider.name.lower(), "named_value"]["bundle_exports_in"] == [provider.name]
    assert second_edges["delay", "intake_delay.dll", "delayed_value"]["desktop_export"] == "export_present"
    assert second_edges["delay", "intake_delay.dll", "delayed_value"]["bundle_exports_in"] == ["intake_delay.dll"]


if __name__ == "__main__":
    with TemporaryDirectory() as temporary:
        check(Path(temporary), Path(sys.argv[1]), Path(sys.argv[2]))
