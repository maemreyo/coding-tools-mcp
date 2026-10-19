"""Authenticated Browser V2 setup signer acceptance at the MCP transport boundary.

Only disposable signer keys, local HTTP server, and fake CLI are used.
The Manager's separate owner authorization and live Chrome are not simulated as success.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import tempfile
import threading
import unittest
import urllib.parse
import uuid
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from coding_tools_mcp.browser_v2_gateway import (
    BrowserCaller, BrowserGateway, SETUP_OPERATIONS, SETUP_REQUEST_NAMESPACE,
    setup_arguments_json,
)
from coding_tools_mcp.errors import ToolFailure
from coding_tools_mcp.oauth import (
    OAuthConfig, create_access_token, validated_access_token_claims,
)
from coding_tools_mcp.server import MCPHandler, Runtime, RuntimeHTTPServer


class BrowserSetupSignerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.key = Ed25519PrivateKey.generate()
        self.key_path = self.root / "owner.key"
        self.key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ))
        self.key_path.chmod(0o600)
        self.cli = self.root / "zam"
        self.cli.write_text("#!/bin/sh\nexit 0\n")
        self.cli.chmod(0o700)
        self.digest = hashlib.sha256(self.cli.read_bytes()).hexdigest()
        self.gateway = BrowserGateway(str(uuid.uuid4()), self.key_path, self.cli, self.digest)
        self.issuer = "https://gateway.test"
        self.oauth = OAuthConfig(password="fixture", token_secret=b"S" * 32,
                                 server_url=self.issuer)
        self.oauth.registry.add_preregistered(
            "client-a", ("http://127.0.0.1/callback",), client_secret=None,
        )
        self.oauth.registry.add_preregistered(
            "client-b", ("http://127.0.0.1/b",), client_secret=None,
        )
        self.token_a = create_access_token(self.oauth, self.issuer, client_id="client-a")
        self.token_b = create_access_token(self.oauth, self.issuer, client_id="client-b")
        self.token_a2 = create_access_token(self.oauth, self.issuer, client_id="client-a")
        self.caller_a = self._caller(self.token_a)
        self.caller_b = self._caller(self.token_b)
        self.caller_a2 = self._caller(self.token_a2)
        self.request_id = str(uuid.uuid4()).upper()

    def _caller(self, token):
        claims = validated_access_token_claims(token, self.oauth, self.issuer)
        return BrowserCaller.from_oauth_claims(claims, self.issuer)

    def _scoped_id(self, caller, request_id=None):
        return str(uuid.uuid5(
            SETUP_REQUEST_NAMESPACE, caller.session_id + "|" +
            caller.consumer_instance_id + "|" + (request_id or self.request_id),
        )).upper()

    def _args(self, op="status"):
        result = {"request_id": self.request_id, "operation": op}
        if op == "request_registration":
            result.update(extension_id="a" * 32, node_path="/opt/homebrew/bin/node")
        return result

    def _cli(self, argv, **kwargs):
        self.assertEqual(argv, [str(self.cli), "browser", "v2", "setup"])
        self.assertEqual(set(kwargs), {"input", "capture_output", "timeout",
                                       "check", "env"})
        self.assertTrue(kwargs["capture_output"])
        self.assertFalse(kwargs["check"])
        self.assertEqual(kwargs["timeout"], 25)
        self.assertNotIn(b"private", kwargs["input"])
        request = json.loads(kwargs["input"])
        self.assertEqual(set(request), {"arguments", "proof"})
        claim_bytes = base64.b64decode(request["proof"]["payload"], validate=True)
        signature = base64.b64decode(request["proof"]["signature"], validate=True)
        self.key.public_key().verify(signature, claim_bytes)
        claim = json.loads(claim_bytes)
        self.assertEqual(claim["schemaVersion"], "zam.browser.setup.caller.v1")
        self.assertEqual(claim["gatewayID"], self.gateway.gateway_id)
        self.assertEqual(claim["requestID"], request["arguments"]["requestID"])
        self.assertEqual(claim["operation"], request["arguments"]["operation"])
        self.assertEqual(claim["argumentsSHA256"],
                         hashlib.sha256(setup_arguments_json(request["arguments"])).hexdigest())
        self.assertEqual(claim["expiresAtMS"] - claim["issuedAtMS"], 20000)
        self.assertRegex(claim["nonce"], r"^[0-9A-F-]{36}$")
        response = {
            "schema_version": "zam.cli.v1",
            "status": "pending" if claim["operation"] == "request_registration" else "complete",
            "reason_code": ("waiting_for_owner"
                            if claim["operation"] == "request_registration" else "ok"),
            "request_id": request["arguments"]["requestID"],
            "data": {"state": "pending_owner", "private_path": "/do-not-expose"},
        }
        exit_code = 3 if response["status"] == "pending" else 0
        return CompletedProcess(argv, exit_code, json.dumps(response).encode(), b"")

    def test_codec_and_proof_are_compatible_with_manager_setup_v1(self):
        args = {"requestID": self.request_id, "operation": "request_registration",
                "extensionID": "a" * 32, "nodePath": "/A Folder/node"}
        raw = setup_arguments_json(args)
        self.assertIn(b'"/A Folder/node"', raw)
        self.assertNotIn(b"\\/", raw)
        self.assertEqual(list(json.loads(raw)), sorted(args))
        proof = self.gateway.setup_proof(self.caller_a, args, now_ms=1000)
        self.assertEqual(set(proof), {"payload", "signature"})
        payload = base64.b64decode(proof["payload"])
        self.key.public_key().verify(base64.b64decode(proof["signature"]), payload)
        claim = json.loads(payload)
        self.assertEqual(claim["issuedAtMS"], 1000)
        self.assertEqual(claim["expiresAtMS"], 21000)
        self.assertEqual(claim["argumentsSHA256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(set(claim), {
            "schemaVersion", "gatewayID", "requestID", "nonce", "operation",
            "argumentsSHA256", "issuedAtMS", "expiresAtMS",
        })

    def test_proof_expiry_replay_and_payload_mutation_are_detectable(self):
        args = {"requestID": self.request_id, "operation": "status"}
        first = self.gateway.setup_proof(self.caller_a, args, now_ms=1000)
        second = self.gateway.setup_proof(self.caller_a, args, now_ms=1000)
        claim = json.loads(base64.b64decode(first["payload"]))
        other = json.loads(base64.b64decode(second["payload"]))
        self.assertNotEqual(claim["nonce"], other["nonce"])
        # Manager rejects expired proofs and persists used gateway/nonce receipts.
        self.assertLess(claim["expiresAtMS"], 22000)
        seen = set()
        def manager_like_fence(proof, now_ms):
            raw = base64.b64decode(proof["payload"])
            self.key.public_key().verify(base64.b64decode(proof["signature"]), raw)
            c = json.loads(raw)
            self.assertGreaterEqual(c["expiresAtMS"], now_ms)
            self.assertNotIn(c["nonce"], seen)
            seen.add(c["nonce"])
        manager_like_fence(first, 2000)
        with self.assertRaises(AssertionError):
            manager_like_fence(first, 2000)
        with self.assertRaises(AssertionError):
            manager_like_fence(second, 22000)
        with self.assertRaises(InvalidSignature):
            tampered = dict(first)
            tampered["payload"] = base64.b64encode(
                base64.b64decode(first["payload"]).replace(b"status", b"verify")
            ).decode("ascii")
            manager_like_fence(tampered, 2000)

    def test_allowlisted_cli_forwarding_and_no_owner_approval(self):
        proofs = []
        def run(argv, **kwargs):
            request = json.loads(kwargs["input"])
            proofs.append(json.loads(base64.b64decode(request["proof"]["payload"]))["nonce"])
            self.assertEqual(request["arguments"]["requestID"], self._scoped_id(self.caller_a))
            return self._cli(argv, **kwargs)
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run", side_effect=run):
            for op in sorted(SETUP_OPERATIONS):
                result = self.gateway.dispatch_setup(self.caller_a, self._args(op))
                self.assertEqual(result["request_id"], self.request_id)
                self.assertNotIn("private_path", json.dumps(result))
                self.assertNotIn("payload", result)
                self.assertEqual(result["state"], "pending_owner")
        self.assertEqual(len(proofs), len(SETUP_OPERATIONS))
        self.assertEqual(len(set(proofs)), len(proofs))

    def test_cross_session_and_consumer_are_namespaced(self):
        original = self._scoped_id(self.caller_a)
        self.assertNotEqual(original, self._scoped_id(self.caller_a2))
        self.assertNotEqual(original, self._scoped_id(self.caller_b))
        ids = []
        def run(argv, **kwargs):
            argument = json.loads(kwargs["input"])["arguments"]
            ids.append(argument["requestID"])
            return self._cli(argv, **kwargs)
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run", side_effect=run):
            for caller in (self.caller_a, self.caller_a2, self.caller_b):
                self.gateway.dispatch_setup(caller, self._args("get_job"))
        self.assertEqual(len(set(ids)), 3)

    def test_invalid_calls_never_execute_cli(self):
        invalid = [
            (None, self._args()),
            (self.caller_a, {"request_id": self.request_id, "operation": "owner_approve"}),
            (self.caller_a, {**self._args(), "consumer_instance_id": self.caller_b.consumer_instance_id}),
            (self.caller_a, {**self._args(), "caller": {"client_id": "client-b"}}),
            (self.caller_a, {**self._args(), "extension_id": "a" * 32}),
            (self.caller_a, {**self._args("request_registration"), "node_path": "../node"}),
            (self.caller_a, {**self._args("request_registration"), "extension_id": "x" * 32}),
            (self.caller_a, {**self._args("request_registration"), "node_path": "/bin/../node"}),
            (self.caller_a, {**self._args(), "request_id": "not-a-uuid"}),
        ]
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run") as run:
            for caller, args in invalid:
                with self.subTest(args=args), self.assertRaises(ToolFailure):
                    self.gateway.dispatch_setup(caller, args)
            run.assert_not_called()

    def test_cli_response_request_mismatch_and_shape_fail_closed(self):
        valid = {"schema_version": "zam.cli.v1", "status": "complete",
                 "reason_code": "ok", "request_id": self._scoped_id(self.caller_a)}
        bad = [
            {**valid, "request_id": self.request_id},
            {**valid, "request_id": 45},
            {**valid, "status": "admin_approved"},
            {**valid, "private_token": "SECRET"},
            {**valid, "schema_version": "zam.browser.v2"},
        ]
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run") as run:
            for body in bad:
                run.return_value = CompletedProcess([], 0, json.dumps(body).encode(), b"")
                with self.assertRaises(ToolFailure):
                    self.gateway.dispatch_setup(self.caller_a, self._args())

    def test_real_http_transport_auth_and_no_spoofing(self):
        env = {
            "CODING_TOOLS_MCP_BROWSER_V2_GATEWAY_ID": self.gateway.gateway_id,
            "CODING_TOOLS_MCP_BROWSER_V2_KEY_FILE": str(self.key_path),
            "CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI": str(self.cli),
            "CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI_SHA256": self.digest,
        }
        with patch.dict(os.environ, env):
            runtime = Runtime(self.root, transport="http", oauth_config=self.oauth)
        self.addCleanup(runtime.close)
        self.assertIn("browser_v2_setup", runtime.exposed_tool_names())
        server = RuntimeHTTPServer(("127.0.0.1", 0), MCPHandler, runtime)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        def request(token=None, extra=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            args = self._args()
            if extra:
                args.update(extra)
            payload = {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                       "params": {"name": "browser_v2_setup", "arguments": args}}
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            conn.request("POST", "/mcp", json.dumps(payload), headers)
            response = conn.getresponse()
            body = json.loads(response.read())
            conn.close()
            return response.status, body
        seen = []
        def run(argv, **kwargs):
            seen.append(json.loads(kwargs["input"])["arguments"]["requestID"])
            return self._cli(argv, **kwargs)
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run", side_effect=run):
            status, response = request(self.token_a)
            self.assertEqual(status, 200)
            self.assertFalse(response["result"]["isError"])
            status, response = request(None)
            self.assertEqual(status, 401)
            status, response = request("invalid-token")
            self.assertEqual(status, 401)
            status, response = request(self.token_a, {"caller": {"session_id": self.caller_b.session_id}})
            self.assertEqual(status, 200)
            self.assertTrue(response.get("error") or response.get("result", {}).get("isError"))
            status, response = request(self.token_b)
            self.assertEqual(status, 200)
            self.assertFalse(response["result"]["isError"])
            # Exercise the actual password + PKCE authorization-code
            # endpoints, not just a hand-minted test JWT.
            verifier = "x" * 64
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            redirect = "http://127.0.0.1/callback"
            consent = urllib.parse.urlencode({
                "client_id": "client-a", "redirect_uri": redirect,
                "code_challenge": challenge, "code_challenge_method": "S256",
                "state": "fixture-state", "resource": self.issuer, "password": "fixture",
            })
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/oauth/authorize", consent,
                         {"Content-Type": "application/x-www-form-urlencoded"})
            authorized = conn.getresponse()
            location = authorized.getheader("Location")
            self.assertEqual(authorized.status, 302)
            authorized.read()
            conn.close()
            code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["code"][0]
            exchange = urllib.parse.urlencode({
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": redirect, "client_id": "client-a",
                "code_verifier": verifier, "resource": self.issuer,
            })
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/oauth/token", exchange,
                         {"Content-Type": "application/x-www-form-urlencoded"})
            issued = conn.getresponse()
            self.assertEqual(issued.status, 200)
            fresh_token = json.loads(issued.read())["access_token"]
            conn.close()
            status, response = request(fresh_token)
            self.assertEqual(status, 200)
            self.assertFalse(response["result"]["isError"])
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/oauth/token", exchange,
                         {"Content-Type": "application/x-www-form-urlencoded"})
            reused = conn.getresponse()
            self.assertEqual(reused.status, 400)
            reused.read()
            conn.close()
        self.assertEqual(seen, [self._scoped_id(self.caller_a), self._scoped_id(self.caller_b),
                                self._scoped_id(self._caller(fresh_token))])
        self.assertNotEqual(seen[0], seen[2])


if __name__ == "__main__":
    unittest.main()
