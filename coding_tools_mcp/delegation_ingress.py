"""Zamery agent-delegation ingress: the ten ``work_*`` tools served by this provider.

The provider owns NO delegation state. It (1) validates the caller's OAuth token (done by the HTTP handler),
(2) signs a short-lived proof binding that verified OAuth principal to ONE tool and the exact argument bytes,
and (3) forwards the call to the Manager's owner-only local ingress, which re-verifies, authorizes and executes it.
Loopback reachability, tool arguments, workerId and prompt text are never identity.

Opt-in like Browser V2: stdio and static-bearer transports never expose these tools.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import stat
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from .browser_v2_gateway import BrowserCaller, _owner_private_key
from .errors import JsonRpcError, ToolFailure

PROOF_SCHEMA = "zam.delegation.ingress.v1"
PROOF_AUDIENCE = "zamery-manager.delegation"
DESCRIPTOR_SCHEMA = "zam.delegation.ingress.descriptor.v1"
CONTRACT_VERSION = "0.1.0"
# Pins: the bundled catalog is the Foundation artifact. Both the file and the contract digest it declares are checked at load,
# so a hand-edited schema/description cannot be advertised under the Foundation contract.
CATALOG_FILE_SHA256 = "da7e1bd839796ee01a8272925438defcbeea5f33d6ec1f62b30d3e0ec1abe9ec"
CATALOG_SCHEMA_DIGEST = "sha256:94e9661f5ef7f338221462ce22d5c00ac2f3f5864233b1e98254ef712e813a0e"
TOOL_NAMES = (
    "work_capabilities", "work_submit", "work_list", "work_inspect", "work_wait",
    "work_message", "work_result", "work_pause", "work_cancel", "work_resume",
)
IDEMPOTENT_RETRY_TOOLS = frozenset(("work_submit", "work_message", "work_pause", "work_cancel", "work_resume"))
MAX_RESPONSE_BYTES = 4_194_304
MAX_ARGUMENT_BYTES = 1_000_000


@dataclass(frozen=True)
class DelegationCaller:
    """Derived ONLY from independently verified gateway OAuth JWT claims (never from request metadata)."""

    issuer: str
    client_id: str
    session_id: str
    consumer_instance_id: str

    @classmethod
    def from_oauth_claims(cls, claims: dict[str, Any], issuer: str, verified_token: str | None = None) -> "DelegationCaller":
        browser = BrowserCaller.from_oauth_claims(claims, issuer, verified_token=verified_token)
        return cls(issuer, str(claims["client_id"]), browser.session_id, browser.consumer_instance_id)


_delegation_caller: ContextVar[DelegationCaller | None] = ContextVar("verified_delegation_oauth_caller", default=None)


def load_catalog() -> dict[str, Any]:
    raw = resources.files("coding_tools_mcp").joinpath("delegation_catalog.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != CATALOG_FILE_SHA256:
        raise ToolFailure("DELEGATION_CATALOG_MISMATCH", "bundled delegation catalog differs from the pinned Foundation artifact", category="internal")
    catalog = json.loads(raw)
    if catalog.get("schemaDigest") != CATALOG_SCHEMA_DIGEST or catalog.get("contractVersion") != CONTRACT_VERSION:
        raise ToolFailure("DELEGATION_CATALOG_MISMATCH", "delegation catalog contract/digest differs from the pin", category="internal")
    if tuple(t["name"] for t in catalog["tools"]) != TOOL_NAMES:
        raise ToolFailure("DELEGATION_CATALOG_MISMATCH", "delegation tool names changed", category="internal")
    return catalog


def _canonical_arguments(arguments: dict[str, Any]) -> bytes:
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def business_error(code: str, message: str, *, retry_safe: bool = False, needed: str | None = None,
                   next_tool: str | None = None) -> dict[str, Any]:
    """Provider-originated failure in the Foundation BusinessError shape (never a raw secret, path or stack)."""
    error: dict[str, Any] = {"code": code, "message": message[:500], "retrySafe": retry_safe, "nextActions": []}
    if needed:
        error["neededAction"] = needed[:300]
    if next_tool:
        error["nextActions"] = [{"tool": next_tool, "reason": "Check state before retrying."}]
    return {"ok": False, "contractVersion": CONTRACT_VERSION, "error": error}


class DelegationGateway:
    def __init__(self, gateway_id: str, secret_key_path: Path, descriptor_path: Path) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        try:
            self.gateway_id = str(uuid.UUID(gateway_id)).upper()
        except ValueError as exc:
            raise ToolFailure("DELEGATION_CONFIG", "invalid delegation gateway id", category="validation") from exc
        self._signer = Ed25519PrivateKey.from_private_bytes(_owner_private_key(secret_key_path))
        if not descriptor_path.is_absolute():
            raise ToolFailure("DELEGATION_CONFIG", "delegation descriptor path must be absolute", category="validation")
        self._descriptor_path = descriptor_path
        self.catalog = load_catalog()
        self._verified_instance: str | None = None

    # -- proof ---------------------------------------------------------------------------------------------------------------------
    def proof(self, caller: DelegationCaller, tool: str, argument_bytes: bytes, now_ms: int | None = None) -> str:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        claim = {
            "schema": PROOF_SCHEMA, "audience": PROOF_AUDIENCE, "method": "tools/call", "tool": tool,
            "gatewayId": self.gateway_id, "argumentsSha256": hashlib.sha256(argument_bytes).hexdigest(),
            "principal": {"issuer": caller.issuer, "clientId": caller.client_id, "sessionId": caller.session_id,
                          "consumerInstanceId": caller.consumer_instance_id},
            "nonce": uuid.uuid4().hex, "issuedAtMs": now, "expiresAtMs": now + 20_000,
        }
        payload = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("utf-8")
        outer = json.dumps({"payload": base64.b64encode(payload).decode("ascii"),
                            "signature": base64.b64encode(self._signer.sign(payload)).decode("ascii")},
                           separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(outer).rstrip(b"=").decode("ascii")

    # -- Manager discovery: follow the OWNER descriptor, never a remembered port --------------------------------------------------
    def _descriptor(self) -> dict[str, Any]:
        path = self._descriptor_path
        try:
            st = path.lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077
                    or path.parent.stat().st_uid != os.getuid() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077):
                raise ValueError("descriptor custody")
            data = json.loads(path.read_text("utf-8"))
            sock = Path(data["socketPath"])
            sst = sock.lstat()
            if (data.get("schema") != DESCRIPTOR_SCHEMA or not stat.S_ISSOCK(sst.st_mode) or sst.st_uid != os.getuid()
                    or stat.S_IMODE(sst.st_mode) & 0o077 or sock.parent != path.parent):
                raise ValueError("descriptor content")
            return data
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise _Unavailable("setup", "The Zamery Manager is not running or delegation is not enabled for it.") from exc

    def _exchange(self, data: dict[str, Any], frame: dict[str, Any], timeout: float) -> dict[str, Any]:
        line = (json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect(data["socketPath"])
        except OSError as exc:
            s.close()
            raise _Unavailable("setup", "The Zamery Manager ingress is not reachable (not running or restarting).") from exc
        try:
            s.settimeout(timeout)
            s.sendall(line)
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    raise _Unavailable("lost", "The Manager closed the connection before replying.")
                buf += chunk
                if len(buf) > MAX_RESPONSE_BYTES:
                    raise _Unavailable("lost", "The Manager reply exceeded the transport bound.")
            return json.loads(buf.split(b"\n", 1)[0])
        except socket.timeout as exc:
            raise _Unavailable("lost", "The Manager did not reply in time.") from exc
        except (OSError, ValueError) as exc:
            raise _Unavailable("lost", "The Manager reply was unreadable.") from exc
        finally:
            s.close()

    def _check_instance(self, data: dict[str, Any]) -> None:
        if self._verified_instance == data.get("instanceId"):
            return
        hello = self._exchange(data, {"v": 1, "id": uuid.uuid4().hex, "op": "hello"}, 5.0)
        info = hello.get("reply") if hello.get("ok") else None
        if (not isinstance(info, dict) or info.get("instanceId") != data.get("instanceId")
                or info.get("contractVersion") != CONTRACT_VERSION or info.get("schemaDigest") != CATALOG_SCHEMA_DIGEST):
            raise _Unavailable("contract", "The Manager speaks a different delegation contract or instance than its descriptor; update Manager or provider.")
        self._verified_instance = data["instanceId"]

    # -- call ------------------------------------------------------------------------------------------------------------------------
    def call(self, caller: DelegationCaller | None, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if caller is None or not isinstance(caller, DelegationCaller):
            raise ToolFailure("DELEGATION_DENIED", "Delegation requires an OAuth-authenticated connector.", category="permission")
        if tool not in TOOL_NAMES:
            raise ToolFailure("DELEGATION_DENIED", "unknown delegation tool", category="validation")
        argument_bytes = _canonical_arguments(arguments)
        if len(argument_bytes) > MAX_ARGUMENT_BYTES:
            raise JsonRpcError(-32602, "arguments exceed the delegation bound", {"reason": "invalid_arguments"})
        wait_ms = arguments.get("waitMs") if tool == "work_wait" and isinstance(arguments.get("waitMs"), int) else 0
        timeout = 20.0 + wait_ms / 1000.0
        retry_hint = tool in IDEMPOTENT_RETRY_TOOLS or tool in ("work_list", "work_inspect", "work_wait", "work_result", "work_capabilities")
        try:
            last: _Unavailable | None = None
            for attempt in range(2):  # a second pass re-reads the owner descriptor: the Manager may have restarted on a new socket
                try:
                    data = self._descriptor()
                    self._check_instance(data)
                    # A fresh proof (new nonce) per attempt: a replayed proof is rejected by design.
                    frame = {"v": 1, "id": uuid.uuid4().hex, "op": "call", "tool": tool,
                             "argumentsJson": argument_bytes.decode("utf-8"), "proof": self.proof(caller, tool, argument_bytes)}
                    return self._interpret(self._exchange(data, frame, timeout))
                except _Unavailable as exc:
                    last = exc
                    self._verified_instance = None
                    if exc.kind not in ("setup",) or attempt:
                        break
            assert last is not None
            raise last
        except _Unavailable as exc:
            if exc.kind == "setup":
                return business_error("SETUP_REQUIRED", exc.message, retry_safe=True,
                                      needed="Open the Zamery MCP Manager app and enable agent delegation, then retry.")
            if exc.kind == "contract":
                return business_error("INTERNAL_UNAVAILABLE", exc.message, needed="Update the Zamery MCP Manager or the coding-tools provider.")
            return business_error(
                "INTERNAL_UNAVAILABLE", exc.message, retry_safe=retry_hint,
                needed=("Retry with the SAME idempotencyKey; the original request may or may not have been recorded."
                        if tool in IDEMPOTENT_RETRY_TOOLS else "Retry the call."),
                next_tool="work_list" if tool == "work_submit" else ("work_inspect" if tool in IDEMPOTENT_RETRY_TOOLS else None))

    def _interpret(self, resp: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(resp, dict):
            raise _Unavailable("lost", "The Manager reply was not an object.")
        if resp.get("ok") is True and isinstance(resp.get("reply"), dict) and isinstance(resp["reply"].get("ok"), bool):
            reply = resp["reply"]
            if reply.get("contractVersion") != CONTRACT_VERSION:
                raise _Unavailable("contract", "The Manager reply carries an unexpected contract version.")
            return reply
        error = resp.get("error") if isinstance(resp.get("error"), dict) else {}
        kind = str(error.get("kind", ""))
        if kind in ("invalid-arguments", "malformed") and error.get("rpcCode") in (-32602, -32600):
            raise JsonRpcError(-32602, str(error.get("message", "invalid arguments"))[:500], {"reason": "invalid_arguments"})
        if kind in ("unknown-gateway", "bad-signature"):
            raise _Unavailable("setup", "This provider is not enrolled with the Manager (gateway key not recognised).")
        if kind in ("expired", "replay"):
            raise _Unavailable("lost", "The Manager rejected the request proof (" + kind + "); check both clocks and retry.")
        raise _Unavailable("lost", "The Manager could not process the request.")


class _Unavailable(Exception):
    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


def gateway_from_env(env: dict[str, str], prefix: str) -> DelegationGateway | None:
    gateway_id = env.get(f"{prefix}_DELEGATION_GATEWAY_ID", "")
    key_file = env.get(f"{prefix}_DELEGATION_KEY_FILE", "")
    descriptor = env.get(f"{prefix}_DELEGATION_DESCRIPTOR", "")
    if not (gateway_id and key_file and descriptor):
        return None
    return DelegationGateway(gateway_id, Path(key_file), Path(descriptor))
