"""BG-P6W subprocess boundary, offline packaging and Manager CLI safe-probe tests.

A disposable, SHA-pinned executable verifies the actual signed stdin bytes.
Optional compiled-Manager CLI probes are read-only or fail before private storage.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from coding_tools_mcp.browser_v2_gateway import (
    BrowserCaller, BrowserGateway, setup_arguments_json,
)
from coding_tools_mcp.errors import ToolFailure


STUB = """#!{python}
import base64
import hashlib
import json
import sys
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

assert sys.argv[1:] == ["browser", "v2", "setup"]
request = json.load(sys.stdin)
claim_bytes = base64.b64decode(request["proof"]["payload"], validate=True)
signature = base64.b64decode(request["proof"]["signature"], validate=True)
pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex("{public_key_hex}"))
pubkey.verify(signature, claim_bytes)
claim = json.loads(claim_bytes)
arguments = request["arguments"]
digest = hashlib.sha256(json.dumps(
    arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    allow_nan=False).encode("utf-8")).hexdigest()
assert claim["argumentsSHA256"] == digest
assert claim["schemaVersion"] == "zam.browser.setup.caller.v1"
assert claim["gatewayID"] == "{gateway_id}"
assert claim["requestID"] == arguments["requestID"]
assert claim["operation"] == arguments["operation"]
assert claim["expiresAtMS"] - claim["issuedAtMS"] == 20000
assert claim["issuedAtMS"] <= int(time.time() * 1000) <= claim["expiresAtMS"]
receipt = Path("{receipt_dir}") / claim["nonce"]
receipt.touch(exist_ok=False)
pending = arguments["operation"] == "request_registration"
response = {{
    "schema_version": "zam.cli.v1",
    "request_id": arguments["requestID"],
    "status": "pending" if pending else "complete",
    "reason_code": "waiting_for_owner" if pending else "ok",
    "data": {{"state": "pending_owner" if pending else "verified_staged",
              "node_path": "/not-for-disclosure"}}
}}
sys.stdout.write(json.dumps(response, sort_keys=True))
sys.exit(3 if pending else 0)
"""


class BackgroundOAuthWheelIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.key = Ed25519PrivateKey.generate()
        self.key_path = self.root / "fixture-signing.key"
        self.key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        self.gateway_id = str(uuid.uuid4()).upper()
        self.caller = BrowserCaller(str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper())
        self.args = {"operation": "status", "request_id": str(uuid.uuid4()).upper()}
        self.receipts = self.root / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.cli = self.root / "disposable-zam"
        self.cli.write_text(STUB.format(
            python=sys.executable, public_key_hex=self.key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
            gateway_id=self.gateway_id, receipt_dir=str(self.receipts)))
        self.cli.chmod(0o700)
        self.gateway = BrowserGateway(self.gateway_id, self.key_path, self.cli,
                                      hashlib.sha256(self.cli.read_bytes()).hexdigest())

    def test_real_pinned_subprocess_status_signed_stdin_and_redaction(self):
        result = self.gateway.dispatch_setup(self.caller, self.args)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["cli_exit_code"], 0)
        self.assertEqual(result["request_id"], self.args["request_id"])
        self.assertNotIn("node_path", result)
        self.assertEqual(len(list(self.receipts.iterdir())), 1)
        # A new nonce is allowed for a repeated read-only request.
        self.assertEqual(self.gateway.dispatch_setup(self.caller, self.args)["status"],
                         "complete")
        self.assertEqual(len(list(self.receipts.iterdir())), 2)

    def test_pending_owner_does_not_approve_registration(self):
        args = dict(self.args, operation="request_registration",
                    extension_id="a" * 32, node_path="/opt/homebrew/bin/node")
        result = self.gateway.dispatch_setup(self.caller, args)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["reason_code"], "waiting_for_owner")
        self.assertEqual(result["state"], "pending_owner")
        self.assertNotIn("node_path", result)

    def test_cli_timeout_and_malformed_output_fail_closed(self):
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("zam", timeout=25)):
            with self.assertRaises(ToolFailure):
                self.gateway.dispatch_setup(self.caller, self.args)
        for stdout in (b"", b"not-json", b"[]", b"{}", b'{"status":"complete"}'):
            with self.subTest(stdout=stdout), patch(
                "coding_tools_mcp.browser_v2_gateway.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout, b"")
            ):
                with self.assertRaises(ToolFailure):
                    self.gateway.dispatch_setup(self.caller, self.args)

    def test_untrusted_signer_or_extra_authority_does_not_run_cli(self):
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run") as run:
            for args in (
                dict(self.args, owner_approved=True),
                dict(self.args, session_id=self.caller.session_id),
                dict(self.args, request_id="malformed"),
                dict(self.args, operation="owner_approve"),
            ):
                with self.subTest(args=args), self.assertRaises(ToolFailure):
                    self.gateway.dispatch_setup(self.caller, args)
            run.assert_not_called()

    def test_cli_pin_precedes_dispatch(self):
        self.cli.write_text(self.cli.read_text() + "\n# mutated")
        with patch("coding_tools_mcp.browser_v2_gateway.subprocess.run") as run:
            with self.assertRaises(ToolFailure):
                self.gateway.dispatch_setup(self.caller, self.args)
            run.assert_not_called()

    def test_manager_canonical_json_argument_digest_fixture(self):
        arguments = {"requestID": self.args["request_id"],
                     "operation": "request_registration", "extensionID": "a" * 32,
                     "nodePath": "/tmp/Node Path"}
        encoded = setup_arguments_json(arguments)
        self.assertEqual(encoded, json.dumps(arguments, sort_keys=True,
                                             separators=(",", ":")).encode())
        self.assertIn(b'"/tmp/Node Path"', encoded)
        proof = self.gateway.setup_proof(self.caller, arguments)
        payload = base64.b64decode(proof["payload"], validate=True)
        self.key.public_key().verify(base64.b64decode(proof["signature"]), payload)
        claim = json.loads(payload)
        self.assertEqual(claim["argumentsSHA256"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(claim["requestID"], arguments["requestID"])

    def test_compiled_manager_cli_safe_probe_if_available(self):
        path = os.environ.get("BG_P6W_MANAGER_CLI")
        digest = os.environ.get("BG_P6W_MANAGER_CLI_SHA256")
        if not path or not digest:
            self.skipTest("No explicitly pinned compiled Manager CLI configured")
        path = Path(path)
        if (not path.is_file() or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            self.fail("Compiled Manager CLI checksum does not match explicit pin")
        # These paths do not instantiate AgentPrivateStorage and cannot commit.
        version = subprocess.run([str(path), "--version"], capture_output=True,
                                 timeout=15, check=False)
        self.assertEqual(version.returncode, 0)
        self.assertEqual(json.loads(version.stdout)["schema_version"], "zam.cli.v1")
        malformed = subprocess.run([str(path), "browser", "v2", "setup"],
                                   input=b'{"not":"a valid signed request"}',
                                   capture_output=True, timeout=15, check=False)
        self.assertEqual(malformed.returncode, 6)
        response = json.loads(malformed.stdout)
        self.assertEqual(response["schema_version"], "zam.cli.v1")
        self.assertEqual(response["status"], "invalid")
        self.assertEqual(response["reason_code"], "invalid_arguments")


if __name__ == "__main__":
    unittest.main()
