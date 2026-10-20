#!/usr/bin/env python3
"""One-time owner's macOS launchd migration with automatic rollback.

Usage:
  python3 scripts/activate-browser-v2-oauth2.py install

install stages a one-shot LaunchAgent without changing the active service;
run is invoked only by that LaunchAgent. No OAuth or signing keys are
regenerated, exported, logged or modified. This is an on-device QA migration.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import pwd
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
ROOT = HOME / "Library/Application Support/ZameryCodingMCP/browser-v2"
CONFIG = HOME / ".config/zamery-coding-mcp/runtime.env"
BACKUP = CONFIG.with_name("runtime.env.pre-browser-v2-oauth2-20261020.backup")
STATUS = ROOT / "oauth2-activation-status.json"
RUNTIME = ROOT / "releases/oauth2-453063ad/venv/bin/coding-tools-mcp"
ISSUER = "https://zamery-coding-mcp.zamery-center.workers.dev"
MCP_JOB = f"gui/{os.getuid()}/com.zamery.coding-mcp"
JOB_NAME = "com.zamery.browser-v2-oauth2-cutover-20261020"
PLIST = HOME / "Library/LaunchAgents" / (JOB_NAME + ".plist")
LOG = ROOT / "oauth2-activation.log"


def mark(state: str, **details: object) -> None:
    """Write only non-secret state and reason types."""
    temp = STATUS.with_suffix(".pending")
    data = {"state": state, "version": "0.5.2+zamery.browser2.oauth2",
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **details}
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(data, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, STATUS)
    print("BROWSER_V2_OAUTH2=" + state, flush=True)


def atomic_configuration(data: bytes) -> None:
    tmp = CONFIG.with_name("runtime.env.oauth2.pending")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, CONFIG)


def restart_mcp() -> None:
    cmd = subprocess.run(
        ["/bin/launchctl", "kickstart", "-k", MCP_JOB],
        capture_output=True, timeout=20, check=False,
    )
    if cmd.returncode != 0:
        raise RuntimeError("MCP launchctl kickstart failed")


def local_http(url: str, post: bool = False) -> tuple[int, bytes]:
    request = urllib.request.Request(url)
    if post:
        request.data = (
            b'{"jsonrpc":"2.0","id":1,"method":"initialize",'
            b'"params":{"protocolVersion":"2025-11-25",'
            b'"capabilities":{},"clientInfo":{"name":"cutover","version":"1"}}}'
        )
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json, text/event-stream")
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            return response.status, response.read(16000)
    except urllib.error.HTTPError as error:
        return error.code, b""
    except Exception:
        return 0, b""


def readiness(seconds: int) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        code, response = local_http(
            "http://127.0.0.1:8765/.well-known/oauth-authorization-server"
        )
        if code == 200:
            try:
                issuer_ok = json.loads(response).get("issuer") == ISSUER
            except ValueError:
                issuer_ok = False
            if issuer_ok and local_http("http://127.0.0.1:8765/mcp", post=True)[0] == 401:
                # curl is used for the public health probe because Cloudflare
                # may block Python's default HTTP User-Agent.
                public = subprocess.run(
                    ["/usr/bin/curl", "-sS", "--max-time", "6",
                     "-o", "/dev/null", "-w", "%{http_code}",
                     ISSUER + "/.well-known/oauth-authorization-server"],
                    capture_output=True, timeout=8, check=False,
                )
                if public.returncode == 0 and public.stdout.strip() == b"200":
                    return True
        time.sleep(1)
    return False


def run() -> None:
    old: bytes | None = None
    switched = False
    try:
        if not CONFIG.is_file() or CONFIG.is_symlink():
            raise RuntimeError("Missing or unsafe active configuration")
        if CONFIG.stat().st_mode & 0o077:
            raise RuntimeError("Private configuration permissions are unsafe")
        if not RUNTIME.is_file() or not os.access(RUNTIME, os.X_OK):
            raise RuntimeError("Reviewed oauth2 runtime missing")
        version = subprocess.run([str(RUNTIME), "--version"],
                                 capture_output=True, timeout=10, check=False)
        if (version.returncode != 0
                or b"0.5.2+zamery.browser2.oauth2" not in version.stdout):
            raise RuntimeError("New runtime version mismatch")
        old = CONFIG.read_bytes()
        if BACKUP.exists():
            if BACKUP.read_bytes() != old:
                raise RuntimeError("Existing rollback backup disagrees with active state")
        rows = old.decode().splitlines()
        matched = sum(row.startswith("ZAMERY_RUNTIME_BIN=") for row in rows)
        if matched != 1:
            raise RuntimeError("Expected one active runtime path")
        if not all(any(row.startswith(k + "=") for row in rows)
                   for k in ("CODING_TOOLS_MCP_BROWSER_V2_GATEWAY_ID",
                             "CODING_TOOLS_MCP_BROWSER_V2_KEY_FILE",
                             "CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI",
                             "CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI_SHA256")):
            raise RuntimeError("Existing owner-enrolled Gateway configuration missing")
        updated = [
            "ZAMERY_RUNTIME_BIN=" + shlex.quote(str(RUNTIME))
            if row.startswith("ZAMERY_RUNTIME_BIN=") else row
            for row in rows
        ]
        new = ("\n".join(updated) + "\n").encode()
        if old == new:
            raise RuntimeError("No runtime change to apply")
        if not BACKUP.exists():
            fd = os.open(BACKUP, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(old)
                out.flush()
                os.fsync(out.fileno())
        atomic_configuration(new)
        switched = True
        mark("SWITCHING")
        restart_mcp()
        if not readiness(60):
            raise RuntimeError("New runtime readiness failed")
        time.sleep(3)
        if not readiness(10):
            raise RuntimeError("Post-start readiness failed")
        mark("ACTIVE", rollback_backup_available=True,
             public_oauth_200=True, unauthenticated_mcp_401=True)
    except Exception as error:
        if switched and old is not None:
            try:
                atomic_configuration(old)
                restart_mcp()
                restored = readiness(45)
                mark("ROLLED_BACK" if restored else "ROLLBACK_HEALTH_UNKNOWN",
                     error_type=type(error).__name__)
            except Exception as rollback_error:
                mark("ROLLBACK_FAILED",
                     error_type=type(error).__name__,
                     rollback_error_type=type(rollback_error).__name__)
        else:
            mark("NOT_SWITCHED", error_type=type(error).__name__)
        sys.exit(1)


def install() -> None:
    if PLIST.exists():
        raise SystemExit("One-shot launchd plist exists; will not overwrite")
    if STATUS.exists():
        raise SystemExit("Activation status exists; reconcile before retry")
    if not RUNTIME.is_file():
        raise SystemExit("Runtime does not exist")
    if ROOT.stat().st_uid != os.getuid() or ROOT.stat().st_mode & 0o077:
        raise SystemExit("Unsafe owner storage")
    manifest = {
        "Label": JOB_NAME, "RunAtLoad": True, "KeepAlive": False,
        "ProgramArguments": [sys.executable, str(Path(__file__).resolve()), "run"],
        "EnvironmentVariables": {"HOME": str(HOME),
                                 "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"},
        "StandardOutPath": str(LOG), "StandardErrorPath": str(LOG),
    }
    fd = os.open(PLIST, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(plistlib.dumps(manifest))
    print("ONE_SHOT_LAUNCHAGENT_PREPARED")
    print("SERVICE_NOT_SWITCHED_YET")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("install", "run"))
    args = parser.parse_args()
    if args.mode == "install":
        install()
    else:
        run()
