"""Browser V2 gateway security unit tests — all keys/CLI here are temporary fixtures.

These tests do not attest an installed Chrome host, live C4 grants,
owner image disclosure or real pixels delivered to ChatGPT.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import stat
import subprocess
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image

from coding_tools_mcp.browser_v2_gateway import (
    BrowserCaller, BrowserGateway, canonical_json, canonical_scope, verified_png_block,
)
from coding_tools_mcp.errors import ToolFailure
from coding_tools_mcp.oauth import OAuthConfig, create_access_token, validated_access_token_claims
from coding_tools_mcp.server import MCPHandler, Runtime, RuntimeHTTPServer


def _scope(caller: BrowserCaller) -> dict:
    return {
        "session_id": caller.session_id,
        "audience": {
            "kind": "chatgpt_zamm", "consumer_instance_id": caller.consumer_instance_id,
        },
        "target": {
            "backend": "chrome_companion",
            "installation_id": str(uuid.uuid4()).upper(),
            "browser_instance_id": str(uuid.uuid4()).upper(),
            "tab_handle": str(uuid.uuid4()).upper(),
            "document_id": str(uuid.uuid4()).upper(),
            "origin": "https://example.test",
        },
    }


class BrowserGatewayTests(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory()
        self.addCleanup(self.private.cleanup)
        self.directory = Path(self.private.name)
        self.directory.chmod(0o700)
        self.signer = Ed25519PrivateKey.generate()
        key = self.directory / "secret"
        key.write_bytes(self.signer.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ))
        key.chmod(0o600)
        self.cli = self.directory / "zam"
        self.cli.write_text("#!/bin/sh\nexit 0\n")
        self.cli.chmod(0o700)
        self.sha = hashlib.sha256(self.cli.read_bytes()).hexdigest()
        self.gateway = BrowserGateway(str(uuid.uuid4()), key, self.cli, self.sha)
        self.issuer = "https://verified.example.test"
        self.cfg = OAuthConfig(
            password="test-only", token_secret=b"1" * 32, server_url=self.issuer
        )
        self.cfg.registry.add_preregistered(
            "registered-test-client", ("http://127.0.0.1/callback",), client_secret=None
        )
        token = create_access_token(self.cfg, self.issuer, client_id="registered-test-client")
        claims = validated_access_token_claims(token, self.cfg, self.issuer)
        self.assertIsNotNone(claims)
        self.caller = BrowserCaller.from_oauth_claims(claims, self.issuer)
        self.scope = _scope(self.caller)

    def _proof(self, operation="status"):
        normalized, raw_scope = canonical_scope(self.scope)
        proof = self.gateway.caller_proof(self.caller, raw_scope, operation, now_ms=1000)
        plain = base64.urlsafe_b64decode(proof + "=" * (-len(proof) % 4))
        envelope = json.loads(plain)
        payload = base64.b64decode(envelope["payload"])
        signature = base64.b64decode(envelope["signature"])
        self.signer.public_key().verify(signature, payload)
        return json.loads(payload), envelope

    def test_oauth_session_is_from_signed_token(self):
        second = create_access_token(self.cfg, self.issuer, client_id="registered-test-client")
        second_caller = BrowserCaller.from_oauth_claims(
            validated_access_token_claims(second, self.cfg, self.issuer), self.issuer
        )
        self.assertNotEqual(self.caller.session_id, second_caller.session_id)
        self.assertEqual(self.caller.consumer_instance_id, second_caller.consumer_instance_id)
        self.assertIsNone(validated_access_token_claims("untrusted", self.cfg, self.issuer))
        with self.assertRaises(ToolFailure):
            BrowserCaller.from_oauth_claims({"client_id": "spoofed"}, self.issuer)

    def test_legacy_verified_access_token_binds_a_stable_session(self):
        # Exact pre-JTI access token format. Only the HTTP JWT validator may
        # supply the token and claims to BrowserCaller.
        old_token = jwt.encode({
            "iss": self.issuer, "aud": self.issuer,
            "sub": "registered-test-client", "client_id": "registered-test-client",
            "iat": 1000, "exp": 4102444800, "scope": "mcp",
        }, self.cfg.token_secret, algorithm="HS256")
        claims = validated_access_token_claims(old_token, self.cfg, self.issuer)
        self.assertIsNotNone(claims)
        first = BrowserCaller.from_oauth_claims(
            claims, self.issuer, verified_token=old_token
        )
        second = BrowserCaller.from_oauth_claims(
            claims, self.issuer, verified_token=old_token
        )
        self.assertEqual(first, second)
        self.assertNotEqual(first.session_id, self.caller.session_id)
        self.assertEqual(first.consumer_instance_id, self.caller.consumer_instance_id)
        with self.assertRaises(ToolFailure):
            BrowserCaller.from_oauth_claims(claims, self.issuer)
        with self.assertRaises(ToolFailure):
            BrowserCaller.from_oauth_claims(claims, self.issuer, verified_token="")
        self.assertIsNone(validated_access_token_claims(
            old_token + "tampered", self.cfg, self.issuer
        ))

    def test_empty_scope_bootstraps_only_access_request_from_verified_caller(self):
        pending = {
            "schema_version": "zam.browser.v2",
            "request_id": str(uuid.uuid4()).upper(),
            "status": "pending", "reason_code": "waiting_for_owner",
        }
        response = subprocess.CompletedProcess([], 3, json.dumps(pending).encode(), b"")
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run",
                   return_value=response) as cli:
            result = self.gateway.dispatch(self.caller, {
                "operation": "request_access", "scope": {},
            })
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["reason_code"], "waiting_for_owner")
        argv = cli.call_args.args[0]
        self.assertEqual(argv[1:4], ["browser", "v2", "request-access"])
        encoded = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--scope="))
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        scope, _ = canonical_scope(json.loads(raw))
        self.assertEqual(scope["session_id"], self.caller.session_id)
        self.assertEqual(scope["audience"]["consumer_instance_id"],
                         self.caller.consumer_instance_id)
        self.assertEqual(scope["target"]["backend"], "chrome_companion")
        self.assertEqual(scope["target"]["origin"], "https://example.invalid")
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run") as no_run:
            for op in ("status", "snapshot", "screenshot", "release"):
                with self.subTest(operation=op), self.assertRaises(ToolFailure):
                    self.gateway.dispatch(self.caller, {"operation": op, "scope": {}})
            with self.assertRaises(ToolFailure):
                self.gateway.dispatch(None, {"operation": "request_access", "scope": {}})
            no_run.assert_not_called()
        listed = dict(pending, status="complete", reason_code="ok",
                      data={"operation": "list_shared", "scopes": []})
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run",
                   return_value=subprocess.CompletedProcess(
                       [], 0, json.dumps(listed).encode(), b""
                   )):
            result = self.gateway.dispatch(self.caller, {
                "operation": "list_shared", "scope": {},
            })
        self.assertEqual(result["data"]["scopes"], [])

    def test_real_ed25519_proof_claims(self):
        signed, envelope = self._proof()
        self.assertEqual(signed["operation"], "status")
        self.assertEqual(signed["session_id"], self.caller.session_id)
        self.assertEqual(signed["consumer_instance_id"], self.caller.consumer_instance_id)
        self.assertEqual(signed["schema_version"], "zam.browser.gateway.caller.v1")
        self.assertEqual(signed["expires_at_ms"] - signed["issued_at_ms"], 20000)
        self.assertEqual(len(base64.b64decode(envelope["signature"])), 64)
        self.assertRegex(signed["scope_sha256"], r"^[a-f0-9]{64}$")

    def test_canonical_json_matches_swift_foundation_vector(self):
        # Generated with Foundation JSONEncoder sortedKeys/convertToSnakeCase:
        # RFC 8259 encoding alone misses escaped forward slashes.
        raw = {
            "session_id": "75D6E851-3E11-409D-BCD8-CEADF2ADB92F",
            "origin": "https://example.test",
            "issued_at_ms": 1234,
        }
        self.assertEqual(
            canonical_json(raw),
            b'{"issued_at_ms":1234,"origin":"https:\\/\\/example.test",'
            b'"session_id":"75D6E851-3E11-409D-BCD8-CEADF2ADB92F"}',
        )

    def test_proof_is_operation_scoped_nonce_unique(self):
        status1, _ = self._proof("status")
        status2, _ = self._proof("status")
        click, _ = self._proof("click")
        self.assertNotEqual(status1["nonce"], status2["nonce"])
        self.assertNotEqual(status1["operation"], click["operation"])
        self.assertNotEqual(status1["nonce"], click["nonce"])
        changed = json.loads(json.dumps(self.scope))
        changed["target"]["document_id"] = str(uuid.uuid4()).upper()
        changed_hash = hashlib.sha256(canonical_scope(changed)[1]).hexdigest()
        self.assertNotEqual(status1["scope_sha256"], changed_hash)

    def test_cross_session_and_wrong_audience_denied_before_cli(self):
        wrong = json.loads(json.dumps(self.scope))
        wrong["session_id"] = str(uuid.uuid4()).upper()
        with self.assertRaises(ToolFailure):
            self.gateway.dispatch(self.caller, {"operation": "status", "scope": wrong})
        wrong = json.loads(json.dumps(self.scope))
        wrong["audience"]["consumer_instance_id"] = str(uuid.uuid4()).upper()
        with self.assertRaises(ToolFailure):
            self.gateway.dispatch(self.caller, {"operation": "status", "scope": wrong})
        with self.assertRaises(ToolFailure):
            self.gateway.dispatch(None, {"operation": "status", "scope": self.scope})

    def test_all_ten_operations_forward_with_fresh_proof(self):
        from subprocess import CompletedProcess
        used = []
        def fake_run(argv, **kwargs):
            op = argv[3].replace("-", "_")
            used.append((op, argv, kwargs))
            answer = {
                "schema_version": "zam.browser.v2",
                "request_id": str(uuid.uuid4()).upper(),
                "status": "pending" if op == "request_access" else "complete",
                "reason_code": "ok",
                "data": {"operation": op} if op != "request_access" else None,
            }
            return CompletedProcess(argv, 3 if op == "request_access" else 0,
                                    json.dumps(answer).encode(), b"")
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run", side_effect=fake_run):
            for op in sorted([
                "request_access", "list_shared", "open_managed", "status", "snapshot",
                "click", "fill", "screenshot", "request_renewal", "release"
            ]):
                arguments = {"operation": op, "scope": self.scope}
                if op in {"click", "fill"}:
                    arguments["ref"] = {"scope": self.scope}
                if op == "fill":
                    arguments["input"] = "secret typed input"
                response = self.gateway.dispatch(self.caller, arguments)
                self.assertTrue(response["ok"])
                self.assertEqual(response["status"], "pending" if op == "request_access" else "complete")
        self.assertEqual(len(used), 10)
        for op, argv, kwargs in used:
            self.assertEqual(argv[:3], [str(self.cli), "browser", "v2"])
            self.assertTrue(any(a.startswith("--caller-proof=") for a in argv))
            self.assertFalse(any("secret typed input" in a for a in argv))
            self.assertEqual(kwargs["input"], b"secret typed input" if op == "fill" else b"")

    def test_reject_tampered_cli_and_extra_response_fields(self):
        self.cli.write_text("#!/bin/sh\nexit 1\n")
        with self.assertRaises(ToolFailure):
            self.gateway.dispatch(self.caller, {"operation": "status", "scope": self.scope})
        self.cli.write_text("#!/bin/sh\nexit 0\n")
        from subprocess import CompletedProcess
        answer = {"schema_version": "zam.browser.v2", "request_id": str(uuid.uuid4()),
                  "status": "complete", "reason_code": "ok", "data": None,
                  "private_image_data": "MUST-NOT-BE-LEAKED"}
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run",
                   return_value=CompletedProcess([], 0, json.dumps(answer).encode(), b"")):
            with self.assertRaises(ToolFailure):
                self.gateway.dispatch(self.caller, {"operation": "status", "scope": self.scope})

    def test_cli_status_exit_must_match_swift_contract(self):
        from subprocess import CompletedProcess
        message = {"schema_version": "zam.browser.v2", "request_id": str(uuid.uuid4()),
                   "status": "denied", "reason_code": "owner_denied"}
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run",
                   return_value=CompletedProcess([], 0, json.dumps(message).encode(), b"")):
            with self.assertRaises(ToolFailure):
                self.gateway.dispatch(self.caller, {"operation": "status", "scope": self.scope})
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run",
                   return_value=CompletedProcess([], 4, json.dumps(message).encode(), b"")):
            result = self.gateway.dispatch(self.caller, {"operation": "status", "scope": self.scope})
            self.assertEqual(result["status"], "denied")

    def test_png_is_actually_decoded_and_sha_checked(self):
        import io
        pixels = io.BytesIO()
        Image.new("RGB", (2, 3)).save(pixels, format="PNG")
        image = pixels.getvalue()
        block = verified_png_block(image, 2, 3, hashlib.sha256(image).hexdigest())
        self.assertEqual(block["type"], "image")
        self.assertEqual(block["mimeType"], "image/png")
        self.assertEqual(base64.b64decode(block["data"]), image)
        for width, height, digest, raw in (
            (1, 3, hashlib.sha256(image).hexdigest(), image),
            (2, 3, "0" * 64, image),
            (2, 3, hashlib.sha256(image[:-5]).hexdigest(), image[:-5]),
        ):
            with self.assertRaises(ToolFailure):
                verified_png_block(raw, width, height, digest)

    def test_key_custody_rejects_broad_permissions(self):
        bad = self.directory / "broad"
        bad.write_bytes(self.signer.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        bad.chmod(0o644)
        with self.assertRaises(ToolFailure):
            BrowserGateway(str(uuid.uuid4()), bad, self.cli, self.sha)

    def test_real_http_mcp_tools_call_binds_verified_oauth_token(self):
        # Real JSON-RPC Streamable HTTP handler and real OAuth JWT validation.
        # CLI execution remains a synthetic transport fixture, NOT Chrome E2E.
        env = {
            "CODING_TOOLS_MCP_BROWSER_V2_GATEWAY_ID": self.gateway.gateway_id,
            "CODING_TOOLS_MCP_BROWSER_V2_KEY_FILE": str(self.directory / "secret"),
            "CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI": str(self.cli),
            "CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI_SHA256": self.sha,
        }
        from subprocess import CompletedProcess
        output = {
            "schema_version": "zam.browser.v2",
            "request_id": str(uuid.uuid4()).upper(),
            "status": "complete",
            "reason_code": "ok",
            "data": {"operation": "status"},
        }
        with patch.dict(os.environ, env):
            runtime = Runtime(self.directory, transport="http", oauth_config=self.cfg)
        self.assertIn("browser_v2", runtime.exposed_tool_names())
        server = RuntimeHTTPServer(("127.0.0.1", 0), MCPHandler, runtime)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(runtime.close)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = server.server_address[1]

        def call(token: str | None, scope: dict):
            conn = http.client.HTTPConnection("127.0.0.1", endpoint, timeout=5)
            body = json.dumps({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {
                    "name": "browser_v2",
                    "arguments": {"operation": "status", "scope": scope},
                },
            })
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            conn.request("POST", "/mcp", body, headers)
            response = conn.getresponse()
            payload = json.loads(response.read())
            conn.close()
            return response.status, payload

        from unittest.mock import patch as mock_patch
        verified_token = create_access_token(
            self.cfg, self.issuer, client_id="registered-test-client"
        )
        verified = BrowserCaller.from_oauth_claims(
            validated_access_token_claims(verified_token, self.cfg, self.issuer), self.issuer
        )
        allowed_scope = _scope(verified)
        with mock_patch("coding_tools_mcp.browser_v2_gateway.subprocess.run",
                        return_value=CompletedProcess([], 0, json.dumps(output).encode(), b"")):
            status, result = call(verified_token, allowed_scope)
            self.assertEqual(status, 200)
            self.assertFalse(result["result"]["isError"])
            self.assertEqual(result["result"]["structuredContent"]["status"], "complete")
            old_token = jwt.encode({
                "iss": self.issuer, "aud": self.issuer,
                "sub": "registered-test-client", "client_id": "registered-test-client",
                "iat": 1000, "exp": 4102444800, "scope": "mcp",
            }, self.cfg.token_secret, algorithm="HS256")
            old_caller = BrowserCaller.from_oauth_claims(
                validated_access_token_claims(old_token, self.cfg, self.issuer),
                self.issuer, verified_token=old_token,
            )
            status, result = call(old_token, _scope(old_caller))
            self.assertEqual(status, 200)
            self.assertFalse(result["result"]["isError"])
            self.assertEqual(result["result"]["structuredContent"]["status"], "complete")
            status, result = call(old_token, allowed_scope)
            self.assertEqual(status, 200)
            self.assertTrue(result["result"]["isError"])
            status, result = call(None, allowed_scope)
            self.assertEqual(status, 401)
            status, result = call(verified_token, self.scope)
            self.assertEqual(status, 200)
            self.assertTrue(result["result"]["isError"])
            self.assertEqual(
                result["result"]["structuredContent"]["error"]["code"], "BROWSER_V2_DENIED"
            )

    def test_browser_tool_not_exposed_without_owner_enrollment(self):
        with patch.dict(os.environ, {
            "CODING_TOOLS_MCP_BROWSER_V2_GATEWAY_ID": "",
            "CODING_TOOLS_MCP_BROWSER_V2_KEY_FILE": "",
            "CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI": "",
            "CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI_SHA256": "",
        }):
            runtime = Runtime(self.directory, transport="http", oauth_config=self.cfg)
        try:
            tools = runtime.exposed_tool_names()
            self.assertNotIn("browser_v2", tools)
            self.assertIn("view_image", tools)
            self.assertIn("server_info", tools)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
