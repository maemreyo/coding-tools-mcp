"""Authenticated-transport proof for the ten work_* tools (mode: transport-auth, NOT ChatGPT-live).

Real pieces: this repo's HTTP MCP server + real OAuth JWT validation + the real Ed25519-signed provider->Manager proof + the real Manager
ingress server (a separate Node process under the offline network guard, boot via Runtime/AgentWorkflows/tests/delegation-ingress/ingress-harness.ts)
over an owner-only unix socket. The Manager executor is an explicit FAKE (no ChatGPT, no browser, no model call).
Set ZAMERY_MANAGER_AGENTWORKFLOWS to the Manager checkout's Runtime/AgentWorkflows directory; the suite skips otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import queue
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from coding_tools_mcp import delegation_ingress as deleg
from coding_tools_mcp.oauth import OAuthConfig, create_access_token, validated_access_token_claims
from coding_tools_mcp.server import MCPHandler, Runtime, RuntimeHTTPServer

MANAGER = os.environ.get("ZAMERY_MANAGER_AGENTWORKFLOWS", "")
ISSUER = "https://delegation-test.example.test"
CLIENTS = {"coord-a": ("owner-a", "coordinator"), "worker-a": ("owner-a", "worker"), "coord-b": ("owner-b", "coordinator")}


class Harness:
    """Owner-side control of the Manager process (what the Manager app/Owner Inbox does)."""

    def __init__(self, gateway_id: str, public_b64: str, base_dir: str | None = None) -> None:
        cfg = {"gatewayId": gateway_id, "publicKeyB64": public_b64, "hasReader": []}
        if base_dir:
            cfg["baseDir"] = base_dir
        self.proc = subprocess.Popen(
            ["node", "--import", "./deny-network.mjs", "--experimental-strip-types", "--no-warnings",
             "tests/delegation-ingress/ingress-harness.ts", json.dumps(cfg)],
            cwd=MANAGER, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.lines: queue.Queue[dict] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self.ready = self.lines.get(timeout=30)
        assert self.ready.get("ready"), self.ready
        self._n = 0

    def _pump(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            try:
                self.lines.put(json.loads(line))
            except ValueError:
                pass

    def cmd(self, name: str, **kw):
        self._n += 1
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps({"cmd": name, "id": self._n, **kw}) + "\n")
        self.proc.stdin.flush()
        reply = self.lines.get(timeout=15)
        assert reply.get("ok"), reply
        return reply

    def stop(self) -> None:
        try:
            assert self.proc.stdin
            self.proc.stdin.write('{"cmd":"stop"}\n')
            self.proc.stdin.flush()
            self.proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            self.proc.kill()


@unittest.skipUnless(MANAGER and Path(MANAGER, "tests/delegation-ingress/ingress-harness.ts").exists() and shutil.which("node"),
                     "set ZAMERY_MANAGER_AGENTWORKFLOWS to Manager Runtime/AgentWorkflows")
class DelegationTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.dir.chmod(0o700)
        signer = Ed25519PrivateKey.generate()
        raw = signer.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        cls.key = cls.dir / "deleg-key"
        cls.key.write_bytes(raw)
        cls.key.chmod(0o600)
        cls.public_b64 = base64.b64encode(signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        cls.gateway_id = str(uuid.uuid4()).upper()
        cls.manager = Harness(cls.gateway_id, cls.public_b64)
        cls.descriptor = Path(cls.manager.ready["descriptorPath"])
        cls.cfg = OAuthConfig(password="test-only", token_secret=b"2" * 32, server_url=ISSUER)
        for client in [*CLIENTS, "stranger"]:
            cls.cfg.registry.add_preregistered(client, ("http://127.0.0.1/callback",), client_secret=None)
        for client, (owner, role) in CLIENTS.items():
            cls.manager.cmd("enrol", issuer=ISSUER, clientId=client, ownerId=owner, role=role)
        cls.grant_a = cls.manager.cmd("grant", ownerId="owner-a")["grantId"]
        cls.manager.cmd("grant", ownerId="owner-b", spec={"projectRefs": ["project:b"]})
        env = {
            "CODING_TOOLS_MCP_DELEGATION_GATEWAY_ID": cls.gateway_id,
            "CODING_TOOLS_MCP_DELEGATION_KEY_FILE": str(cls.key),
            "CODING_TOOLS_MCP_DELEGATION_DESCRIPTOR": str(cls.descriptor),
        }
        with patch.dict(os.environ, env):
            cls.runtime = Runtime(cls.dir, transport="http", oauth_config=cls.cfg)
        cls.server = RuntimeHTTPServer(("127.0.0.1", 0), MCPHandler, cls.runtime)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.runtime.close()
        cls.manager.stop()
        cls.tmp.cleanup()

    # -- helpers -------------------------------------------------------------------------------------------------------------------
    def token(self, client: str) -> str:
        return create_access_token(self.cfg, ISSUER, client_id=client)

    def rpc(self, token: str | None, method: str, params: dict | None = None, rid: int = 1):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=40)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        conn.request("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}), headers)
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response.status, (json.loads(body) if body else None)

    def tool(self, token: str, name: str, args: dict) -> dict:
        status, body = self.rpc(token, "tools/call", {"name": name, "arguments": args})
        self.assertEqual(status, 200, body)
        self.assertNotIn("error", body, body)
        return body["result"]["structuredContent"]

    def sends(self) -> int:
        return self.manager.cmd("sends")["sends"]

    def submit(self, client: str, key: str, goal: str = "summarize the docs", **extra) -> dict:
        return self.tool(self.token(client), "work_submit", {"idempotencyKey": key, "goal": goal, **extra})

    def raw_frame(self, args_for_proof: dict, args_sent: dict, tool: str = "work_list", client: str = "coord-a") -> dict:
        """Hand-built signed frame for tamper/replay probes: the SAME real socket, the SAME real gateway key."""
        caller = deleg.DelegationCaller.from_oauth_claims(
            validated_access_token_claims(self.token(client), self.cfg, ISSUER), ISSUER)
        gw = self.runtime.delegation_gateway
        proof = gw.proof(caller, tool, deleg._canonical_arguments(args_for_proof))
        frame = {"v": 1, "id": "probe", "op": "call", "tool": tool, "argumentsJson": deleg._canonical_arguments(args_sent).decode(), "proof": proof}
        return self.send_frame(frame)

    def send_frame(self, frame: dict) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(str(self.manager.ready["socketPath"]))
        s.sendall((json.dumps(frame) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            buf += s.recv(65536)
        s.close()
        return json.loads(buf.split(b"\n", 1)[0])

    # -- T1: catalog + auth ----------------------------------------------------------------------------------------------------------
    def test_t1_tools_list_has_ten_exact_foundation_tools_and_keeps_existing(self):
        status, body = self.rpc(self.token("coord-a"), "tools/list")
        self.assertEqual(status, 200)
        tools = {t["name"]: t for t in body["result"]["tools"]}
        catalog = json.loads(Path(MANAGER, "../../docs/agent-workflows/delegation-v1/contracts/tool-catalog.json").resolve().read_text())
        self.assertEqual(deleg.CATALOG_SCHEMA_DIGEST, catalog["schemaDigest"])
        for entry in catalog["tools"]:
            served = tools[entry["name"]]
            self.assertEqual(served["inputSchema"], entry["inputSchema"])
            self.assertEqual(served["outputSchema"], entry["outputSchema"])
            self.assertEqual(served["description"], entry["description"])
            self.assertEqual({k: v for k, v in served["annotations"].items() if k != "title"}, entry["annotations"])
        with patch.dict(os.environ, {}, clear=False):
            for key in [k for k in os.environ if "DELEGATION" in k]:
                os.environ.pop(key)
            baseline = Runtime(self.dir, transport="http", oauth_config=self.cfg)
        self.addCleanup(baseline.close)
        base_names = baseline.exposed_tool_names()
        self.assertFalse(any(n.startswith("work_") for n in base_names))
        self.assertEqual(sorted(tools), sorted([*base_names, *deleg.TOOL_NAMES]))
        for name in base_names:  # existing tool contracts unchanged
            self.assertEqual(tools[name], __import__("coding_tools_mcp.server", fromlist=["x"]).tool_definition(name))

    def test_t1_stdio_and_static_bearer_never_expose_delegation(self):
        with patch.dict(os.environ, {"CODING_TOOLS_MCP_DELEGATION_GATEWAY_ID": self.gateway_id,
                                      "CODING_TOOLS_MCP_DELEGATION_KEY_FILE": str(self.key),
                                      "CODING_TOOLS_MCP_DELEGATION_DESCRIPTOR": str(self.descriptor)}):
            stdio = Runtime(self.dir)
            static = Runtime(self.dir, transport="http", auth_token="x" * 24)
        self.addCleanup(stdio.close)
        self.addCleanup(static.close)
        self.assertFalse(any(n.startswith("work_") for n in stdio.exposed_tool_names() + static.exposed_tool_names()))

    def test_t1_missing_and_invalid_auth_are_rejected_before_any_tool(self):
        before = self.manager.cmd("counts")
        status, _ = self.rpc(None, "tools/call", {"name": "work_submit", "arguments": {"idempotencyKey": "k-noauth", "goal": "x"}})
        self.assertEqual(status, 401)
        forged = create_access_token(OAuthConfig(password="p", token_secret=b"9" * 32, server_url=ISSUER), ISSUER, client_id="coord-a")
        status, _ = self.rpc(forged, "tools/call", {"name": "work_submit", "arguments": {"idempotencyKey": "k-forged", "goal": "x"}})
        self.assertEqual(status, 401)
        self.assertEqual(self.manager.cmd("counts")["works"], before["works"])

    def test_t1_unenrolled_connector_gets_setup_required_and_owner_sees_pending_request(self):
        reply = self.tool(self.token("stranger"), "work_list", {})
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "SETUP_REQUIRED")
        pending = self.manager.cmd("pending")["pending"]
        self.assertTrue(any(p["issuer"] == ISSUER for p in pending))

    def test_t1_invalid_arguments_are_protocol_errors(self):
        status, body = self.rpc(self.token("coord-a"), "tools/call", {"name": "work_submit", "arguments": {"goal": "no key"}})
        self.assertEqual(status, 200)
        self.assertEqual(body["error"]["code"], -32602)

    # -- T1/T2/T3: owner success, duplicates, fresh session --------------------------------------------------------------------------
    def test_t2_owner_flow_duplicate_conflict_and_lost_ack_do_not_resend(self):
        first = self.submit("coord-a", "t2-flow")
        self.assertTrue(first["ok"], first)
        work_id = first["workId"]
        # duplicate: same key + content -> original receipt, no second Work, no second send
        again = self.submit("coord-a", "t2-flow")
        self.assertTrue(again["ok"] and again["workId"] == work_id and again.get("idempotentReplay") is True, again)
        # changed content under the same key conflicts
        conflict = self.submit("coord-a", "t2-flow", goal="something else")
        self.assertEqual(conflict["error"]["code"], "IDEMPOTENCY_CONFLICT")
        # alternate key, same content: refused by the grant (key rotation cannot mint extra roots)
        rotated = self.submit("coord-a", "t2-flow-rotated")
        self.assertEqual(rotated["error"]["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(rotated["error"]["workId"], work_id)
        # lost ACK: frame delivered, reply never read, caller retries with the same key
        caller = deleg.DelegationCaller.from_oauth_claims(validated_access_token_claims(self.token("coord-a"), self.cfg, ISSUER), ISSUER)
        args = {"idempotencyKey": "t2-lost", "goal": "lost ack goal"}
        raw = deleg._canonical_arguments(args)
        lost = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        lost.connect(str(self.manager.ready["socketPath"]))
        lost.sendall((json.dumps({"v": 1, "id": "lost", "op": "call", "tool": "work_submit", "argumentsJson": raw.decode(),
                                   "proof": self.runtime.delegation_gateway.proof(caller, "work_submit", raw)}) + "\n").encode())
        lost.close()
        time.sleep(0.5)
        recovered = self.submit("coord-a", "t2-lost", goal="lost ack goal")
        self.assertTrue(recovered["ok"] and recovered.get("idempotentReplay") is True, recovered)
        deadline = time.time() + 10
        while time.time() < deadline and self.sends() < 2:
            time.sleep(0.1)
        self.assertEqual(self.sends(), 2, "exactly one send per distinct Work (t2-flow, t2-lost)")
        # result retrievable; fresh OAuth session (new token) can list and fetch it
        deadline = time.time() + 10
        result = {}
        while time.time() < deadline:
            result = self.tool(self.token("coord-a"), "work_result", {"workId": work_id})
            if result.get("ok") and result.get("state") in ("completed", "partial"):
                break
            time.sleep(0.2)
        self.assertTrue(result["ok"], result)
        listed = self.tool(self.token("coord-a"), "work_list", {})
        self.assertIn(work_id, json.dumps(listed))

    # -- T3: other principal ---------------------------------------------------------------------------------------------------------
    def test_t3_other_owner_cannot_read_by_guessing_ids_and_sees_no_foreign_work(self):
        work_id = self.submit("coord-a", "t3-private", goal="private to owner a")["workId"]
        denied = self.tool(self.token("coord-b"), "work_inspect", {"workId": work_id})
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "WORK_NOT_FOUND")
        self.assertNotIn(work_id, json.dumps(self.tool(self.token("coord-b"), "work_list", {})))
        cancel = self.tool(self.token("coord-b"), "work_cancel", {"workId": work_id, "idempotencyKey": "b-cancel"})
        self.assertEqual(cancel["error"]["code"], "WORK_NOT_FOUND")

    # -- T4: bounded wait -------------------------------------------------------------------------------------------------------------
    def test_t4_wait_timeout_is_not_failure_and_leaves_work_active(self):
        work_id = self.submit("coord-a", "t4-wait", goal="wait goal")["workId"]
        started = time.time()
        waited = self.tool(self.token("coord-a"), "work_wait", {"workIds": [work_id], "waitMs": 600, "until": "attention"})
        self.assertLess(time.time() - started, 5)
        self.assertTrue(waited["ok"], waited)

    # -- T5: recursion -----------------------------------------------------------------------------------------------------------------
    def test_t5_worker_connector_cannot_create_roots_or_read_work(self):
        before = self.manager.cmd("counts")
        refused = self.tool(self.token("worker-a"), "work_submit", {"idempotencyKey": "w-root", "goal": "spawn"})
        self.assertEqual(refused["error"]["code"], "RECURSION_REFUSED")
        self.assertEqual(self.tool(self.token("worker-a"), "work_list", {})["error"]["code"], "SCOPE_DENIED")
        self.assertTrue(self.tool(self.token("worker-a"), "work_capabilities", {})["ok"])
        self.assertEqual(self.manager.cmd("counts")["works"], before["works"])

    def test_t5_scope_denied_outside_grant_and_resource_refs_need_reader(self):
        out = self.submit("coord-a", "t5-scope", goal="x scope", projectRef="project:other")
        self.assertEqual(out["error"]["code"], "SCOPE_DENIED")
        res = self.submit("coord-a", "t5-res", goal="x res", projectRef="project:docs", inputRefs=["resource:report"])
        self.assertIn(res["error"]["code"], ("SCOPE_DENIED", "RESOURCE_ACCESS_UNSUPPORTED"))

    # -- T6: tamper / replay / revocation ---------------------------------------------------------------------------------------------
    def test_t6_tampered_arguments_after_signing_are_rejected(self):
        resp = self.raw_frame({"query": "harmless"}, {"query": "tampered"})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["kind"], "binding-mismatch")

    def test_t6_proof_for_another_tool_and_replayed_proof_are_rejected(self):
        caller = deleg.DelegationCaller.from_oauth_claims(validated_access_token_claims(self.token("coord-a"), self.cfg, ISSUER), ISSUER)
        raw = deleg._canonical_arguments({})
        proof = self.runtime.delegation_gateway.proof(caller, "work_list", raw)
        wrong = self.send_frame({"v": 1, "id": "w", "op": "call", "tool": "work_capabilities", "argumentsJson": raw.decode(), "proof": proof})
        self.assertEqual(wrong["error"]["kind"], "binding-mismatch")
        ok_frame = {"v": 1, "id": "r1", "op": "call", "tool": "work_list", "argumentsJson": raw.decode(), "proof": proof}
        first = self.send_frame(ok_frame)
        self.assertTrue(first["ok"], first)
        replay = self.send_frame({**ok_frame, "id": "r2"})
        self.assertEqual(replay["error"]["kind"], "replay")

    def test_t6_forged_signature_and_unknown_gateway_are_rejected(self):
        other = deleg.DelegationGateway.__new__(deleg.DelegationGateway)
        other.gateway_id = self.gateway_id
        other._signer = Ed25519PrivateKey.generate()
        caller = deleg.DelegationCaller.from_oauth_claims(validated_access_token_claims(self.token("coord-a"), self.cfg, ISSUER), ISSUER)
        raw = deleg._canonical_arguments({})
        resp = self.send_frame({"v": 1, "id": "f", "op": "call", "tool": "work_list", "argumentsJson": raw.decode(), "proof": other.proof(caller, "work_list", raw)})
        self.assertEqual(resp["error"]["kind"], "bad-signature")
        other.gateway_id = str(uuid.uuid4()).upper()
        resp = self.send_frame({"v": 1, "id": "g", "op": "call", "tool": "work_list", "argumentsJson": raw.decode(), "proof": other.proof(caller, "work_list", raw)})
        self.assertEqual(resp["error"]["kind"], "unknown-gateway")

    def test_t6_expired_proof_is_rejected(self):
        caller = deleg.DelegationCaller.from_oauth_claims(validated_access_token_claims(self.token("coord-a"), self.cfg, ISSUER), ISSUER)
        raw = deleg._canonical_arguments({})
        stale = self.runtime.delegation_gateway.proof(caller, "work_list", raw, now_ms=int(time.time() * 1000) - 120_000)
        resp = self.send_frame({"v": 1, "id": "e", "op": "call", "tool": "work_list", "argumentsJson": raw.decode(), "proof": stale})
        self.assertEqual(resp["error"]["kind"], "expired")

    def test_t6_revocation_stops_new_roots_and_messages_but_not_safety_controls(self):
        grant = self.manager.cmd("grant", ownerId="owner-r")["grantId"]
        self.manager.cmd("enrol", issuer=ISSUER, clientId="coord-r", ownerId="owner-r", role="coordinator")
        self.cfg.registry.add_preregistered("coord-r", ("http://127.0.0.1/callback",), client_secret=None)
        made = self.submit("coord-r", "rev-1", goal="revocation work")
        self.assertTrue(made["ok"], made)
        self.manager.cmd("revoke", grantId=grant, reason="owner pulled it")
        blocked = self.submit("coord-r", "rev-2", goal="after revoke")
        self.assertEqual(blocked["error"]["code"], "GRANT_REQUIRED")
        msg = self.tool(self.token("coord-r"), "work_message", {"workId": made["workId"], "idempotencyKey": "m1", "message": "hello"})
        self.assertEqual(msg["error"]["code"], "GRANT_REQUIRED")
        cancel = self.tool(self.token("coord-r"), "work_cancel", {"workId": made["workId"], "idempotencyKey": "c1"})
        self.assertNotEqual(cancel.get("error", {}).get("code"), "GRANT_REQUIRED", "cancel is a safety control and stays available to the owner")
        self.assertTrue(self.tool(self.token("coord-r"), "work_inspect", {"workId": made["workId"]})["ok"], "reads survive revocation")

    # -- reconnect follows owner identity --------------------------------------------------------------------------------------------
    def test_z_manager_unavailable_is_structured_and_restart_is_followed_via_descriptor(self):
        self.manager.stop()
        down = self.tool(self.token("coord-a"), "work_list", {})
        self.assertFalse(down["ok"])
        self.assertEqual(down["error"]["code"], "SETUP_REQUIRED")
        self.assertTrue(down["error"]["retrySafe"])
        self.assertNotIn("Traceback", json.dumps(down))
        old_instance, old_dir = self.manager.ready["instanceId"], self.manager.ready["baseDir"]
        type(self).manager = Harness(self.gateway_id, self.public_b64, base_dir=old_dir)
        self.assertNotEqual(self.manager.ready["instanceId"], old_instance)
        back = self.tool(self.token("coord-a"), "work_list", {})
        self.assertTrue(back["ok"], back)
        self.assertGreaterEqual(len(back.get("items", [])), 1, "Works persisted in the Manager ledger survive the restart")


if __name__ == "__main__":
    unittest.main()
