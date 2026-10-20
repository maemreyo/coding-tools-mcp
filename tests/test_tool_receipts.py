"""Server-side tool receipts: authenticated, digest-only, hash-chained evidence (mode: transport-auth, local protocol client)."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from coding_tools_mcp.oauth import OAuthConfig, create_access_token
from coding_tools_mcp.server import MCPHandler, Runtime, RuntimeHTTPServer

ISSUER = "https://receipt-test.example.test"
NONCE = "run-nonce-7f3a91-do-not-log-me"


class ToolReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()
        (self.workspace / "fact.txt").write_text(f"fact {NONCE}\n", encoding="utf-8")
        self.log = self.root / "receipts" / "tool-receipts.jsonl"
        self.cfg = OAuthConfig(password="p", token_secret=b"3" * 32, server_url=ISSUER)
        self.cfg.registry.add_preregistered("worker-client", ("http://127.0.0.1/cb",), client_secret=None)
        with patch.dict(os.environ, {"CODING_TOOLS_MCP_RECEIPT_LOG": str(self.log)}):
            self.runtime = Runtime(self.workspace, transport="http", oauth_config=self.cfg)
            self.stdio = Runtime(self.workspace)
        self.addCleanup(self.runtime.close)
        self.addCleanup(self.stdio.close)
        self.server = RuntimeHTTPServer(("127.0.0.1", 0), MCPHandler, self.runtime)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, name, args, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + create_access_token(self.cfg, ISSUER, client_id="worker-client")
        conn.request("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}), headers)
        r = conn.getresponse()
        body = r.read()
        conn.close()
        return r.status, json.loads(body) if body else None

    def entries(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_authenticated_read_writes_digest_only_chained_receipt(self):
        status, body = self.call("read_file", {"path": "fact.txt"})
        self.assertEqual(status, 200)
        content = body["result"]["structuredContent"]["content"]
        self.call("list_dir", {"path": "."})
        entries = self.entries()
        self.assertEqual([e["tool"] for e in entries], ["read_file", "list_dir"])
        first = entries[0]
        self.assertEqual(first["resultContentSha256"], hashlib.sha256(content.encode()).hexdigest())
        self.assertEqual(first["pathSha256"], hashlib.sha256(b"fact.txt").hexdigest())
        self.assertEqual(entries[1]["prevHash"], first["hash"])
        self.assertEqual(first["prevHash"], "0" * 64)
        raw = self.log.read_text()
        self.assertNotIn(NONCE, raw)
        self.assertNotIn("fact.txt", raw)
        self.assertEqual(oct(self.log.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(self.log.parent.stat().st_mode & 0o777), "0o700")

    def test_unauthenticated_and_non_allowlisted_calls_leave_no_receipt(self):
        status, _ = self.call("read_file", {"path": "fact.txt"}, token=False)
        self.assertEqual(status, 401)
        self.call("git_status", {})
        self.assertEqual(self.entries(), [])
        self.assertIsNone(self.stdio.receipt_log)

    def test_failed_reads_are_not_receipted(self):
        self.call("read_file", {"path": "missing.txt"})
        self.assertEqual(self.entries(), [])


if __name__ == "__main__":
    unittest.main()
