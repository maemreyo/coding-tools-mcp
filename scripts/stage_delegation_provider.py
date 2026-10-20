#!/usr/bin/env python3
"""Build a reproducible provider wheel from clean Git source. Never installs the serving provider."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tomllib
import venv


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean(root: Path) -> None:
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise SystemExit("Refusing artifact from a dirty source checkout")


def build(root: Path, out: Path, source_sha: str, epoch: str, log) -> Path:
    out.mkdir(parents=True, exist_ok=False)
    raw = subprocess.check_output(["git", "-C", str(root), "archive", source_sha])
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        archive.extractall(out, filter="data")
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
    env["SOURCE_DATE_EPOCH"] = epoch
    env["PYTHONHASHSEED"] = "0"
    subprocess.run([sys.executable, "-m", "build", "--wheel", "--no-isolation"],
                   cwd=out, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    wheels = list((out / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one wheel")
    return wheels[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manager", type=Path, required=True)
    parser.add_argument("--manager-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manager = args.manager.resolve()
    clean(root)
    clean(manager)
    manager_sha = git(manager, "rev-parse", "HEAD")
    if manager_sha != git(manager, "rev-parse", args.manager_sha + "^{commit}"):
        raise SystemExit("Manager HEAD does not match the approved artifact source")
    catalog = manager / "docs/agent-workflows/delegation-v1/contracts/tool-catalog.json"
    bundled = root / "coding_tools_mcp/delegation_catalog.json"
    if bundled.read_bytes() != catalog.read_bytes():
        raise SystemExit("Bundled catalog differs from the Manager generator output")
    schema = json.loads(catalog.read_text())["schemaDigest"]
    source_sha = git(root, "rev-parse", "HEAD")
    source_tree = git(root, "rev-parse", "HEAD^{tree}")
    epoch = git(root, "show", "-s", "--format=%ct", "HEAD")
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    with (out / "build.log").open("w") as log:
        a = build(root, out / "build-a", source_sha, epoch, log)
        b = build(root, out / "build-b", source_sha, epoch, log)
    if sha(a) != sha(b):
        raise SystemExit("Wheel reproducibility check failed")
    wheel = out / a.name
    shutil.copyfile(a, wheel)
    isolated = out / "isolated-venv"
    venv.EnvBuilder(with_pip=True).create(isolated)
    python = isolated / "bin/python"
    subprocess.run([str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
                   cwd=out, check=True, stdout=subprocess.DEVNULL)
    probe = """import hashlib,json,importlib.metadata as m
from coding_tools_mcp import __version__
from coding_tools_mcp.delegation_ingress import load_catalog,CATALOG_FILE_SHA256
c=load_catalog()
assert m.version('coding-tools-mcp') == __version__
print(json.dumps({'version':__version__,'schemaDigest':c['schemaDigest'],'toolCount':len(c['tools']),'catalogSha256':CATALOG_FILE_SHA256}))
"""
    installed = json.loads(subprocess.check_output([str(python), "-I", "-c", probe], cwd=out, text=True))
    expected = {"version": version, "schemaDigest": schema, "toolCount": 10, "catalogSha256": sha(catalog)}
    if installed != expected:
        raise SystemExit("Installed wheel metadata/catalog differs from clean source")
    clean(root)
    clean(manager)
    if source_sha != git(root, "rev-parse", "HEAD") or manager_sha != git(manager, "rev-parse", "HEAD"):
        raise SystemExit("Source identity changed during artifact construction")
    manifest = {
        "status": "PACKAGING_VERIFIED_TRANSPORT_ACCEPTANCE_SEPARATE",
        "providerSha": source_sha, "providerTree": source_tree, "managerSha": manager_sha,
        "managerTree": git(manager, "rev-parse", "HEAD^{tree}"),
        "version": version, "publicSchemaDigest": schema, "catalogSha256": sha(catalog),
        "wheel": wheel.name, "wheelSha256": sha(wheel), "reproducible": True,
        "sourceDateEpoch": int(epoch), "isolatedInstalledCatalog": installed,
        "runtime": {"python": sys.version.split()[0]},
        "productionChanged": False, "liveTurnsConsumed": 0,
    }
    (out / "artifact-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
