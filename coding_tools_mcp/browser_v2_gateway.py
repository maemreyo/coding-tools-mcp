"""Opt-in Browser V2 caller bridge for the existing authenticated MCP HTTP server.

No owner/browser permissions are granted here. The gateway authenticates OAuth,
signs only a particular operation/scope and forwards it to the EXISTING Zamm CLI.
There is deliberately no default image-read bridge: private T2 disclosure needs
an independent, trusted, foreground macOS owner decision.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ToolFailure

OPERATIONS = frozenset((
    "request_access", "list_shared", "open_managed", "status", "snapshot",
    "click", "fill", "screenshot", "request_renewal", "release",
))
CLAIM_SCHEMA = "zam.browser.gateway.caller.v1"
CONSUMER_NAMESPACE = uuid.UUID("9c66daed-98e0-5c82-9db9-6ee55dd9ad72")
UUID_FIELDS = frozenset(("session_id", "consumer_instance_id", "installation_id",
                         "browser_instance_id", "tab_handle", "document_id"))


def _deny(reason: str = "Browser V2 caller not authenticated") -> ToolFailure:
    return ToolFailure("BROWSER_V2_DENIED", reason, category="permission")


def canonical_json(value: Any) -> bytes:
    # Foundation JSONEncoder(.sortedKeys) escapes forward slashes by default.
    # This detail is digest- and signature-critical for HTTPS origin fields.
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return encoded.replace("/", "\\/").encode("utf-8")


def _uuid(raw: Any) -> str:
    if not isinstance(raw, str):
        raise _deny()
    try:
        parsed = uuid.UUID(raw)
    except ValueError as exc:
        raise _deny() from exc
    return str(parsed).upper()


def _exact(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _deny()
    return value


def _origin(raw: Any) -> str:
    if not isinstance(raw, str) or len(raw) > 1024:
        raise _deny()
    try:
        parsed = urllib.parse.urlsplit(raw)
        valid_scheme = parsed.scheme == "https" or (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        )
        if (not valid_scheme or not parsed.hostname or parsed.username or parsed.password
                or parsed.path or parsed.query or parsed.fragment
                or not re.fullmatch(r"[a-zA-Z0-9.:\[\]-]+", parsed.netloc)
                or raw != f"{parsed.scheme}://{parsed.netloc}"):
            raise _deny()
        _ = parsed.port
    except ValueError as exc:
        raise _deny() from exc
    return raw


def canonical_scope(raw: Any) -> tuple[dict[str, Any], bytes]:
    scope = _exact(raw, {"session_id", "audience", "target"})
    audience = _exact(scope["audience"], {"kind", "consumer_instance_id"})
    target = _exact(scope["target"], {"backend", "installation_id",
                                     "browser_instance_id", "tab_handle",
                                     "document_id", "origin"})
    if audience["kind"] != "chatgpt_zamm" or target["backend"] not in (
        "chrome_companion", "managed_playwright"
    ):
        raise _deny()
    normalized = {
        "session_id": _uuid(scope["session_id"]),
        "audience": {
            "kind": "chatgpt_zamm",
            "consumer_instance_id": _uuid(audience["consumer_instance_id"]),
        },
        "target": {
            "backend": target["backend"],
            "installation_id": _uuid(target["installation_id"]),
            "browser_instance_id": _uuid(target["browser_instance_id"]),
            "tab_handle": _uuid(target["tab_handle"]),
            "document_id": _uuid(target["document_id"]),
            "origin": _origin(target["origin"]),
        },
    }
    return normalized, canonical_json(normalized)


@dataclass(frozen=True)
class BrowserCaller:
    """Derived ONLY from independently verified gateway OAuth JWT claims."""

    session_id: str
    consumer_instance_id: str

    @classmethod
    def from_oauth_claims(cls, claims: dict[str, Any], issuer: str) -> "BrowserCaller":
        client = claims.get("client_id")
        token_id = claims.get("jti")
        if (not isinstance(client, str) or not client
                or claims.get("sub") != client
                or not isinstance(token_id, str)
                or claims.get("iss") != issuer):
            raise _deny()
        session_id = _uuid(token_id)
        # OAuth in this upstream identifies a registered CLIENT, not an OS
        # installation. Session UUID is token-unique; audience UUID represents
        # the registered client. See the acceptance report for this boundary.
        audience = str(uuid.uuid5(CONSUMER_NAMESPACE, issuer + "|" + client)).upper()
        return cls(session_id, audience)


def _owner_private_key(path: Path) -> bytes:
    # No auto-generated key, env secret, argv secret or developer fixture.
    if not path.is_absolute() or path.is_symlink():
        raise _deny("Gateway key custody is not approved")
    parent = path.parent
    if parent.is_symlink():
        raise _deny("Gateway key custody is not approved")
    pst = parent.stat()
    if pst.st_uid != os.getuid() or stat.S_IMODE(pst.st_mode) & 0o077:
        raise _deny("Gateway key custody is not approved")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fs = os.fstat(fd)
        if (fs.st_uid != os.getuid() or not stat.S_ISREG(fs.st_mode)
                or fs.st_nlink != 1 or stat.S_IMODE(fs.st_mode) & 0o177):
            raise _deny("Gateway key custody is not approved")
        raw = os.read(fd, 65)
        if len(raw) != 32:
            raise _deny("Gateway key custody is not approved")
        return raw
    finally:
        os.close(fd)


def _checked_cli(path: Path, expected_sha256: str) -> str:
    if (not path.is_absolute() or path.is_symlink()
            or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)):
        raise _deny("Unapproved Zamm CLI")
    fs = path.stat()
    if (not stat.S_ISREG(fs.st_mode) or fs.st_uid != os.getuid()
            or fs.st_mode & 0o022 or not fs.st_mode & stat.S_IXUSR):
        raise _deny("Unapproved Zamm CLI")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        raise _deny("Zamm CLI integrity mismatch")
    return str(path)


class BrowserGateway:
    def __init__(self, gateway_id: str, secret_key_path: Path,
                 cli_path: Path, cli_sha256: str) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.gateway_id = _uuid(gateway_id)
        self._signer = Ed25519PrivateKey.from_private_bytes(_owner_private_key(secret_key_path))
        self._cli_path = cli_path
        self._cli_sha256 = cli_sha256

    def caller_proof(self, caller: BrowserCaller, scope_bytes: bytes, operation: str,
                     now_ms: int | None = None) -> str:
        if operation not in OPERATIONS and operation != "artifact_read":
            raise _deny()
        now = int(time.time() * 1000) if now_ms is None else now_ms
        claim = {
            "schema_version": CLAIM_SCHEMA,
            "gateway_id": self.gateway_id,
            "session_id": caller.session_id,
            "consumer_instance_id": caller.consumer_instance_id,
            "scope_sha256": hashlib.sha256(scope_bytes).hexdigest(),
            "operation": operation,
            "nonce": str(uuid.uuid4()).upper(),
            "issued_at_ms": now,
            "expires_at_ms": now + 20_000,
        }
        payload = canonical_json(claim)
        signature = self._signer.sign(payload)
        proof = canonical_json({
            "payload": base64.b64encode(payload).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        })
        return base64.urlsafe_b64encode(proof).rstrip(b"=").decode("ascii")

    def dispatch(self, caller: BrowserCaller | None, args: dict[str, Any]) -> dict[str, Any]:
        if caller is None:
            raise _deny()
        op = args.get("operation")
        if not isinstance(op, str) or op not in OPERATIONS:
            raise _deny()
        scope, scope_bytes = canonical_scope(args.get("scope"))
        if (scope["session_id"] != caller.session_id
                or scope["audience"]["consumer_instance_id"] != caller.consumer_instance_id):
            raise _deny()
        if args.get("ref") is not None and op not in {"click", "fill"}:
            raise _deny()
        if (op in {"click", "fill"}) != (isinstance(args.get("ref"), dict)):
            raise _deny()
        if (op == "fill") != (isinstance(args.get("input"), str)):
            raise _deny()
        fill_data = args.get("input", "").encode("utf-8")
        if len(fill_data) > 8192:
            raise _deny()
        cli = _checked_cli(self._cli_path, self._cli_sha256)
        argv = [cli, "browser", "v2", op.replace("_", "-"),
                "--scope=" + base64.urlsafe_b64encode(scope_bytes).rstrip(b"=").decode("ascii"),
                "--caller-proof=" + self.caller_proof(caller, scope_bytes, op)]
        if op in {"click", "fill"}:
            ref = args["ref"]
            if not isinstance(ref, dict) or ref.get("scope") != scope:
                raise _deny()
            ref_bytes = canonical_json(ref)
            if len(ref_bytes) > 8192:
                raise _deny()
            argv.append("--ref=" + base64.urlsafe_b64encode(ref_bytes).rstrip(b"=").decode("ascii"))
        if op == "fill":
            argv.append("--input-stdin=true")
        try:
            result = subprocess.run(argv, input=fill_data, capture_output=True,
                                    timeout=25, check=False,
                                    env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())})
            if len(result.stdout) > 2_097_152 or len(result.stderr) > 131_072:
                raise _deny("Zamm CLI response exceeds transport bounds")
            response = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise _deny("Zamm CLI unavailable or response invalid") from exc
        if not isinstance(response, dict):
            raise _deny("Invalid Zamm CLI response")
        # AgentCLIResult must be the typed Browser V2 wire response, never
        # untrusted stdout such as logs/paths/base64 screenshot bytes.
        if (not {"schema_version", "request_id", "status", "reason_code"}.issubset(response)
                or not set(response).issubset(
                    {"schema_version", "request_id", "status", "reason_code", "data"}
                )
                or response.get("schema_version") != "zam.browser.v2"
                or response.get("status") not in (
                    "complete", "pending", "denied", "unavailable",
                    "invalid", "failed", "outcome_unknown")
                or not isinstance(response.get("request_id"), str)
                or response.get("reason_code") not in {
                    "ok", "waiting_for_owner", "owner_denied", "expired",
                    "cancelled", "not_implemented", "unavailable",
                    "unknown_command", "invalid_arguments", "unsupported_schema",
                    "policy_denied", "unsafe_storage", "resource_limit",
                    "execution_failed", "outcome_unknown",
                }):
            raise _deny("Unexpected Zamm CLI response")
        exits = {
            "complete": 0, "pending": 3, "denied": 4,
            "unavailable": 5, "invalid": 6,
            "failed": 7, "outcome_unknown": 7,
        }
        if result.returncode != exits[response["status"]]:
            raise _deny("Zamm CLI status/exit mismatch")
        safe = {k: response[k] for k in ("schema_version", "status",
                                       "reason_code", "request_id") if k in response}
        data = response.get("data")
        if data is not None:
            if (not isinstance(data, dict)
                    or not set(data).issubset({
                        "operation", "scope", "scopes", "observation", "capture"
                    }) or data.get("operation") != op
                    or len(canonical_json(data)) > 1_048_576):
                raise _deny("Unexpected Zamm CLI data")
            safe["data"] = data
        return {"ok": True, **safe, "cli_exit_code": result.returncode}


def verified_png_block(pixels: bytes, width: int, height: int,
                       digest: str) -> dict[str, str]:
    """Only for a separately owner-approved native T2 relay, never MCP input."""
    if (not isinstance(pixels, bytes) or len(pixels) > 5_242_880
            or pixels[:8] != b"\x89PNG\r\n\x1a\n"
            or len(pixels) < 24 or pixels[12:16] != b"IHDR"
            or int.from_bytes(pixels[16:20], "big") != width
            or int.from_bytes(pixels[20:24], "big") != height
            or not (0 < width <= 8192 and 0 < height <= 8192)
            or hashlib.sha256(pixels).hexdigest() != digest):
        raise _deny("Private image integrity not verified")
    # Header bytes alone do NOT establish a decodable image.
    try:
        from PIL import Image
        with Image.open(io.BytesIO(pixels)) as probe:
            if probe.format != "PNG" or probe.size != (width, height):
                raise _deny("Private image integrity not verified")
            probe.verify()
        with Image.open(io.BytesIO(pixels)) as decoded:
            decoded.load()
    except (OSError, ValueError, SyntaxError) as exc:
        raise _deny("Private image integrity not verified") from exc
    return {"type": "image", "mimeType": "image/png",
            "data": base64.b64encode(pixels).decode("ascii")}
