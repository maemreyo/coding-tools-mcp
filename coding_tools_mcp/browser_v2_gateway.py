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
SETUP_CLAIM_SCHEMA = "zam.browser.setup.caller.v1"
SETUP_OPERATIONS = frozenset((
    "status", "verify", "stage_companion", "stage_native",
    "request_registration", "get_job", "cancel_job", "reconcile_job",
))
CONSUMER_NAMESPACE = uuid.UUID("9c66daed-98e0-5c82-9db9-6ee55dd9ad72")
SETUP_REQUEST_NAMESPACE = uuid.UUID("4a9809c2-18b6-4354-a68f-f3769b9b8b45")
UUID_FIELDS = frozenset(("session_id", "consumer_instance_id", "installation_id",
                         "browser_instance_id", "tab_handle", "document_id"))


def _deny(reason: str = "Browser V2 caller not authenticated") -> ToolFailure:
    return ToolFailure("BROWSER_V2_DENIED", reason, category="permission")


def canonical_json(value: Any) -> bytes:
    # Foundation JSONEncoder(.sortedKeys) escapes forward slashes by default.
    # This detail is digest- and signature-critical for HTTPS origin fields.
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return encoded.replace("/", "\\/").encode("utf-8")


def setup_arguments_json(value: dict[str, Any]) -> bytes:
    """Mirror Manager JSONEncoder.sortedKeys + withoutEscapingSlashes.

    Unlike BrowserV2Wire, the setup contract uses camelCase property names.
    The exact bytes, rather than the raw MCP JSON, are SHA-256 committed.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


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


def canonical_ref(raw: Any, requested_scope: dict[str, Any]) -> bytes:
    """Normalize the complete Swift Snapshot ref before forwarding to the CLI.

    The ref is NOT authorization evidence; C4/native must still validate it
    against the current browser-issued observation immediately before action.
    """
    ref = _exact(raw, {"observation_id", "node_handle", "scope",
                       "generation", "grant_epoch"})
    embedded_scope, _ = canonical_scope(ref["scope"])
    if embedded_scope != requested_scope:
        raise _deny("Browser V2 reference scope mismatch")
    generation, epoch = ref["generation"], ref["grant_epoch"]
    if (type(generation) is not int or type(epoch) is not int
            or not (0 < generation < 2**64) or not (0 < epoch < 2**64)):
        raise _deny("Invalid Browser V2 reference counters")
    wire = canonical_json({
        "observation_id": _uuid(ref["observation_id"]),
        "node_handle": _uuid(ref["node_handle"]),
        "scope": embedded_scope,
        "generation": generation,
        "grant_epoch": epoch,
    })
    if len(wire) > 8192:
        raise _deny("Browser V2 reference too large")
    return wire


def provisional_access_scope(caller: "BrowserCaller") -> dict[str, Any]:
    """Gateway-owned request placeholder; NEVER an actual tab identity.

    The native owner consent flow chooses and attests the real tab scope.
    The provisional target is used only for request_access/list_shared;
    no snapshot, interaction or screenshot may use it. Session/audience
    come exclusively from the gateway's verified OAuth caller.
    """
    return {
        "session_id": caller.session_id,
        "audience": {"kind": "chatgpt_zamm",
                     "consumer_instance_id": caller.consumer_instance_id},
        "target": {
            "backend": "chrome_companion",
            "installation_id": str(uuid.uuid4()).upper(),
            "browser_instance_id": str(uuid.uuid4()).upper(),
            "tab_handle": str(uuid.uuid4()).upper(),
            "document_id": str(uuid.uuid4()).upper(),
            "origin": "https://example.invalid",
        },
    }


@dataclass(frozen=True)
class BrowserCaller:
    """Derived ONLY from independently verified gateway OAuth JWT claims."""

    session_id: str
    consumer_instance_id: str

    @classmethod
    def from_oauth_claims(cls, claims: dict[str, Any], issuer: str,
                          verified_token: str | None = None) -> "BrowserCaller":
        client = claims.get("client_id")
        token_id = claims.get("jti")
        if (not isinstance(client, str) or not client
                or claims.get("sub") != client
                or claims.get("iss") != issuer):
            raise _deny()
        if isinstance(token_id, str):
            session_id = _uuid(token_id)
        elif token_id is None and isinstance(verified_token, str) and verified_token:
            # Historical OAuth tokens were issued without JTI. This fallback
            # is ONLY called after independent JWT signature, issuer, audience,
            # expiry, and client-registry validation. Hash the *verified token*
            # itself to keep sessions opaque, stable, and distinct per token.
            session_id = str(uuid.uuid5(
                CONSUMER_NAMESPACE, "legacy-token|" +
                hashlib.sha256(verified_token.encode("utf-8")).hexdigest()
            )).upper()
        else:
            raise _deny()
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

    def setup_proof(self, caller: BrowserCaller, arguments: dict[str, Any],
                    now_ms: int | None = None) -> dict[str, str]:
        """Sign setup intent with the SAME owner-pinned Ed25519 identity.

        The caller must already have been verified by the HTTP transport.
        The v1 Manager proof checks gateway/request/operation/arguments/nonce;
        session/consumer are enforced at the Gateway boundary (the v1 setup
        verifier cannot independently check OAuth identity).
        """
        if (not isinstance(caller, BrowserCaller) or not isinstance(arguments, dict)
                or not isinstance(arguments.get("operation"), str)
                or arguments["operation"] not in SETUP_OPERATIONS
                or "requestID" not in arguments):
            raise _deny()
        raw_arguments = setup_arguments_json(arguments)
        now = int(time.time() * 1000) if now_ms is None else now_ms
        claim = {
            "schemaVersion": SETUP_CLAIM_SCHEMA,
            "gatewayID": self.gateway_id,
            "requestID": arguments["requestID"],
            "nonce": str(uuid.uuid4()).upper(),
            "operation": arguments["operation"],
            "argumentsSHA256": hashlib.sha256(raw_arguments).hexdigest(),
            "issuedAtMS": now,
            "expiresAtMS": now + 20_000,
        }
        payload = setup_arguments_json(claim)
        return {
            "payload": base64.b64encode(payload).decode("ascii"),
            "signature": base64.b64encode(self._signer.sign(payload)).decode("ascii"),
        }

    def dispatch_setup(self, caller: BrowserCaller | None,
                       args: dict[str, Any]) -> dict[str, Any]:
        """OAuth-authenticated, allowlisted background setup over pinned CLI.

        Browser grants, Chrome Share, image disclosure, and owner registration
        approval are NOT authorized by this path. Setup proof travels via stdin
        and never appears in argv, environment, trace or tool response.
        """
        if caller is None or not isinstance(caller, BrowserCaller) or not isinstance(args, dict):
            raise _deny()
        operation = args.get("operation")
        if not isinstance(operation, str) or operation not in SETUP_OPERATIONS:
            raise _deny()
        expected = {"operation", "request_id"}
        if operation == "request_registration":
            expected |= {"extension_id", "node_path"}
        if set(args) != expected:
            raise _deny("Unrecognized or incomplete setup request")
        request_id = _uuid(args.get("request_id"))
        # Setup v1's Manager claim lacks OAuth session/consumer fields. Bind the
        # Manager-side job namespace deterministically to the validated token,
        # so another client/session reusing a visible request_id can NEVER poll
        # or cancel the original job. This is a namespace fence, not a grant.
        scoped_request_id = str(uuid.uuid5(
            SETUP_REQUEST_NAMESPACE,
            caller.session_id + "|" + caller.consumer_instance_id + "|" + request_id,
        )).upper()
        arguments: dict[str, Any] = {"requestID": scoped_request_id, "operation": operation}
        if operation == "request_registration":
            extension_id, node_path = args["extension_id"], args["node_path"]
            # Chrome IDs are [a-p]{32}, not arbitrary manifest contents.
            if not isinstance(extension_id, str) or not re.fullmatch(r"[a-p]{32}", extension_id):
                raise _deny("Invalid Chrome extension identity")
            if (not isinstance(node_path, str) or not node_path.startswith("/")
                    or len(node_path.encode("utf-8")) >= 1024 or "\x00" in node_path
                    or ".." in node_path.split("/") or any(ord(x) < 32 for x in node_path)):
                raise _deny("Invalid reviewed Node path")
            arguments["extensionID"] = extension_id
            arguments["nodePath"] = node_path
        cli = _checked_cli(self._cli_path, self._cli_sha256)
        request = setup_arguments_json({
            "arguments": arguments,
            "proof": self.setup_proof(caller, arguments),
        })
        if len(request) > 16_384:
            raise _deny("Setup request exceeds CLI limit")
        try:
            result = subprocess.run(
                [cli, "browser", "v2", "setup"], input=request,
                capture_output=True, timeout=25, check=False,
                env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
            )
            if len(result.stdout) > 1_048_576 or len(result.stderr) > 131_072:
                raise _deny("Setup CLI response exceeds bounds")
            response = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise _deny("Setup CLI unavailable or response invalid") from exc
        exit_codes = {"complete": 0, "pending": 3, "denied": 4,
                      "unavailable": 5, "invalid": 6, "failed": 7,
                      "outcome_unknown": 7}
        reasons = {"ok", "waiting_for_owner", "owner_denied", "expired", "cancelled",
                   "not_implemented", "unavailable", "unknown_command", "invalid_arguments",
                   "unsupported_schema", "policy_denied", "unsafe_storage", "resource_limit",
                   "execution_failed", "outcome_unknown"}
        if (not isinstance(response, dict)
                or set(response) - {"schema_version", "status", "reason_code", "request_id", "data"}
                or response.get("schema_version") != "zam.cli.v1"
                or not isinstance(response.get("request_id"), str)
                or response["request_id"].upper() != scoped_request_id
                or not isinstance(response.get("status"), str)
                or response["status"] not in exit_codes
                or not isinstance(response.get("reason_code"), str)
                or response["reason_code"] not in reasons
                or result.returncode != exit_codes[response["status"]]):
            raise _deny("Unexpected setup CLI response")
        # Do not relay private native registration details or arbitrary file
        # paths in data. A state-only projection supports job reconciliation;
        # actual owner review remains native to Manager.
        safe = {"ok": True, "schema_version": "zam.cli.v1",
                "request_id": request_id, "status": response["status"],
                "reason_code": response["reason_code"],
                "cli_exit_code": result.returncode}
        data = response.get("data")
        if (isinstance(data, dict) and isinstance(data.get("state"), str)
                and data["state"] in {"pending_owner", "committing", "cancelled",
                                      "completed", "verified_staged"}):
            safe["state"] = data["state"]
        return safe

    def dispatch(self, caller: BrowserCaller | None, args: dict[str, Any]) -> dict[str, Any]:
        if caller is None:
            raise _deny()
        op = args.get("operation")
        if not isinstance(op, str) or op not in OPERATIONS:
            raise _deny()
        allowed = {"operation", "scope"}
        if op in {"click", "fill"}:
            allowed.add("ref")
        if op == "fill":
            allowed.add("input")
        if set(args) != allowed:
            raise _deny("Unrecognized or incomplete Browser V2 arguments")
        requested_scope = args.get("scope")
        if op in {"request_access", "list_shared"} and requested_scope == {}:
            # An authenticated ChatGPT caller does not know its OAuth session
            # ID until the trusted gateway binds it. Do not ask agents to
            # fabricate browser identity or pass caller-supplied UUIDs.
            # list_shared can then return owner-attested *real* tab scopes.
            requested_scope = provisional_access_scope(caller)
        scope, scope_bytes = canonical_scope(requested_scope)
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
            ref_bytes = canonical_ref(args["ref"], scope)
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
        # CLI emits only a bounded stage/reason pair; never expose arbitrary
        # stderr, which could contain page text or sensitive fill data.
        if response["status"] != "complete":
            match = re.search(
                rb"(?m)^browser_v2_s1 stage=(cli_parse|caller_proof|runtime_broker|"
                rb"live_observation|fill_stdin|transport_request|transport_response) "
                rb"reason=([a-z0-9_]{1,48})$", result.stderr[-131072:])
            diagnostic_reasons = {
                "invalid_verb_or_count", "invalid_flag_syntax", "unknown_or_duplicate_flag",
                "invalid_scope_token", "invalid_ref_token", "ref_scope_mismatch",
                "ref_epoch_or_generation", "unexpected_ref", "invalid_stdin_flag",
                "invalid_managed_backend", "invalid_input", "stale_observation",
                "unverified_channel", "wrong_scope", "wrong_audience",
                "invalid_receipt", "invalid_identity", "invalid_operation",
                "expired", "revoked", "forbidden_origin", "missing_grant",
                "insufficient_permission", "human_takeover", "policy_denied",
                "execution_failed", "outcome_unknown", "resource_limit",
                "unavailable", "invalid_arguments", "unexpected",
            }
            if match is not None and match.group(2).decode("ascii") in diagnostic_reasons:
                safe["diagnostic"] = {
                    "stage": match.group(1).decode("ascii"),
                    "reason_code": match.group(2).decode("ascii"),
                }
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
