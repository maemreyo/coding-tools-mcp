#!/usr/bin/env python3
"""Build and verify the BG-P6W offline Manager wheelhouse; never installs into Manager.

Explicitly offline; dependency wheels must already exist and match reviewed pins.
Only output_dir is written. SOURCE_DATE_EPOCH fixes wheel zip timestamps.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.5.2+zamery.browser2.oauth1"
PREVIOUS_WHEEL_SHA256 = "4583a411b6e9759a7afa68197bd7ac637efb831e003957235006e7dafb845fb1"
SOURCE_BASE = "6ede335ee54881aee9fce0be5b61563c834dacb4"
EPOCH = "1792368000"
REVIEWED_DEPS = {
    "cffi-2.1.1-cp314-cp314-macosx_11_0_arm64.whl":
        "661c298b4821edebead0c91edd2b00374d67ad7c5a1f7a91d4442633b79d6a72",
    "cryptography-46.0.7-cp311-abi3-macosx_10_9_universal2.whl":
        "ea42cbe97209df307fdc3b155f1b6fa2577c0defa8f1f7d3be7d31d189108ad4",
    "pillow-12.3.0-cp314-cp314-macosx_11_0_arm64.whl":
        "e158cb00350dc278f3b91551101aa7d12415a66ebf2c91d8d5ac14e56ddd3ad0",
    "pycparser-3.11-py3-none-any.whl":
        "51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80",
    "pyjwt-2.15.1-py3-none-any.whl":
        "42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193",
}
SOURCE_FILES = ("coding_tools_mcp/browser_v2_gateway.py",
                "coding_tools_mcp/server.py", "coding_tools_mcp/__init__.py",
                "pyproject.toml", "tests/test_browser_v2_setup_signer.py")


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(*args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=ROOT, env=env, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "dist/browser-v2-bg-p6w-py314-arm64")
    parser.add_argument("--python", default="/opt/homebrew/bin/python3.14")
    args = parser.parse_args()

    output = args.output.resolve()
    if output.exists():
        parser.error("output exists; choose a fresh directory (no implicit overwrite)")
    if not Path(args.python).is_file():
        parser.error("CPython 3.14 executable not found")
    major_minor = subprocess.check_output(
        [args.python, "-c", "import sys; print('.'.join(map(str,sys.version_info[:2])))"],
        text=True).strip()
    if major_minor != "3.14":
        parser.error("CPython 3.14 is required for the pinned macOS arm64 wheels")
    if sys.platform != "darwin":
        parser.error("This wheelhouse is macOS arm64-only")
    machine = subprocess.check_output(["uname", "-m"], text=True).strip()
    if machine != "arm64":
        parser.error("This wheelhouse is macOS arm64-only")
    for wheel, digest in REVIEWED_DEPS.items():
        source = args.source_wheelhouse / wheel
        if not source.is_file() or sha(source) != digest:
            parser.error("missing or unreviewed dependency wheel: " + wheel)
    if f'version = "{VERSION}"' not in (ROOT / "pyproject.toml").read_text():
        parser.error("distribution version is not pinned to BG-P6W")

    env = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH, UV_OFFLINE="1")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".bg-p6w-build-", dir=output.parent) as tmp:
        temp = Path(tmp)
        first, second = temp / "build1", temp / "build2"
        first.mkdir()
        second.mkdir()
        run("uv", "build", "--offline", "--wheel", "--out-dir", str(first), env=env)
        run("uv", "build", "--offline", "--wheel", "--out-dir", str(second), env=env)
        name = f"coding_tools_mcp-{VERSION}-py3-none-any.whl"
        a, b = first / name, second / name
        if not a.is_file() or not b.is_file() or sha(a) != sha(b):
            raise SystemExit("wheel build is NOT byte-reproducible; distribution aborted")
        if sha(a) == PREVIOUS_WHEEL_SHA256:
            raise SystemExit("old pre-OAuth wheel checksum was reused")
        with zipfile.ZipFile(a) as archive:
            members = archive.namelist()
            metadata = archive.read(
                f"coding_tools_mcp-{VERSION}.dist-info/METADATA").decode()
            gateway = archive.read("coding_tools_mcp/browser_v2_gateway.py").decode()
            server = archive.read("coding_tools_mcp/server.py").decode()
            if (f"Version: {VERSION}" not in metadata or
                "zam.browser.setup.caller.v1" not in gateway or
                "def dispatch_setup(" not in gateway or
                "browser_v2_setup" not in server or
                "coding_tools_mcp/__init__.py" not in members):
                raise SystemExit("OAuth signer source/metadata is missing from wheel")
        staged = temp / "bundle"
        staged.mkdir()
        shutil.copyfile(a, staged / name)
        for item in REVIEWED_DEPS:
            shutil.copyfile(args.source_wheelhouse / item, staged / item)
        inventory = [{
            "wheel": item.name, "sha256": sha(item), "bytes": item.stat().st_size,
            "role": "gateway" if item.name == name else "reviewed-offline-dependency"
        } for item in sorted(staged.glob("*.whl"))]
        smoke_venv = temp / "smoke"
        run("uv", "venv", "--offline", "--python", args.python, str(smoke_venv), env=env)
        run("uv", "pip", "install", "--offline", "--no-index", "--python",
            str(smoke_venv / "bin/python"), "--find-links", str(staged),
            f"coding-tools-mcp[browser-v2]=={VERSION}", env=env)
        run(str(smoke_venv / "bin/python"), "-c",
            "import importlib.metadata as m; import coding_tools_mcp.browser_v2_gateway as g; "
            f"assert m.version('coding-tools-mcp') == '{VERSION}'; "
            "assert g.SETUP_CLAIM_SCHEMA == 'zam.browser.setup.caller.v1'", env=env)

        manifest = {
            "format": "zamery.browser-v2.bg-p6w.offline-wheel-inventory.v1",
            "source_base_commit": SOURCE_BASE,
            "package": "coding-tools-mcp",
            "version": VERSION,
            "platform": "macos-arm64-cpython3.14",
            "source_date_epoch": int(EPOCH),
            "byte_reproducible_two_builds": True,
            "offline_disposable_venv_install": "PASS",
            "source_file_sha256": {s: sha(ROOT / s) for s in SOURCE_FILES},
            "wheels": inventory,
        }
        data = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        (staged / "wheel-inventory.json").write_text(data)
        (staged / "SHA256SUMS").write_text(
            "".join(f"{x['sha256']}  {x['wheel']}\n" for x in inventory))
        staged.rename(output)
        report = ROOT / "docs/browser-v2-bg-p6w-wheel-inventory-20261019.json"
        report.write_text(data)
        print(f"PASS: {name}, sha256={sha(output / name)}")
        print(f"PASS: {len(inventory)} offline wheels; reproducible 2 builds; isolated install")
        print(f"MANIFEST: {report}")
        print(f"WHEELHOUSE: {output}")


if __name__ == "__main__":
    main()
