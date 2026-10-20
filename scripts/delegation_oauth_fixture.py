#!/usr/bin/env python3
"""Disposable real OAuth HTTP provider for composed offline acceptance.

Only the public gateway key and business replies leave this process. The owner
supplies its actual ingress descriptor; no engine, grant or Kit fixture is made here.
"""
from __future__ import annotations
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from coding_tools_mcp.oauth import OAuthConfig, create_access_token
from coding_tools_mcp.server import MCPHandler, Runtime, RuntimeHTTPServer


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--descriptor", type=Path, required=True)
    args = parser.parse_args()
    state = args.state_dir
    if not state.is_absolute() or not args.descriptor.is_absolute():
        raise SystemExit("Fixture paths must be absolute")
    state.mkdir(mode=0o700, parents=False, exist_ok=False)
    state.chmod(0o700)
    signer = Ed25519PrivateKey.generate()
    seed = signer.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    key = state / "gateway.key"
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(seed)
    gateway_id = str(uuid.uuid4()).upper()
    public = base64.b64encode(signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    issuer = "https://delegation-offline.example.test"
    cfg = OAuthConfig(password=secrets.token_urlsafe(24), token_secret=secrets.token_bytes(32), server_url=issuer)
    cfg.registry.add_preregistered("qa-coordinator", ("http://127.0.0.1/callback",), client_secret=None)
    cfg.registry.add_preregistered("qa-worker", ("http://127.0.0.1/callback",), client_secret=None)
    os.environ.update({
        "CODING_TOOLS_MCP_DELEGATION_GATEWAY_ID": gateway_id,
        "CODING_TOOLS_MCP_DELEGATION_KEY_FILE": str(key),
        "CODING_TOOLS_MCP_DELEGATION_DESCRIPTOR": str(args.descriptor),
    })
    runtime = Runtime(state, transport="http", oauth_config=cfg)
    server = RuntimeHTTPServer(("127.0.0.1", 0), MCPHandler, runtime)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    emit({"ready": True, "mode": "offline-oauth-http", "gatewayId": gateway_id,
          "publicKeyB64": public, "port": server.server_address[1],
          "issuer": issuer, "clients": ["qa-coordinator", "qa-worker"]})
    try:
        for line in sys.stdin:
            try:
                request = json.loads(line)
                if request.get("cmd") == "stop":
                    break
                if request.get("cmd") not in ("call", "list"):
                    emit({"id": request.get("id"), "ok": False, "error": "UNKNOWN_FIXTURE_COMMAND"})
                    continue
                client = request.get("client", "qa-coordinator")
                if client not in ("qa-coordinator", "qa-worker"):
                    raise ValueError("unknown fixture client")
                token = create_access_token(cfg, issuer, client_id=client)
                method = "tools/list" if request["cmd"] == "list" else "tools/call"
                params = {} if request["cmd"] == "list" else {"name": request["tool"], "arguments": request.get("args", {})}
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=50)
                try:
                    body = json.dumps({"jsonrpc": "2.0", "id": request.get("id", 1), "method": method, "params": params})
                    conn.request("POST", "/mcp", body, {"Content-Type": "application/json", "Authorization": "Bearer " + token})
                    response = conn.getresponse()
                    value = json.loads(response.read())
                    emit({"id": request.get("id"), "httpStatus": response.status, "body": value})
                finally:
                    conn.close()
            except Exception as exc:
                # Never print paths, request arguments, token, nonce or traceback.
                emit({"ok": False, "error": type(exc).__name__})
    finally:
        server.shutdown()
        server.server_close()
        runtime.close()
        thread.join(5)


if __name__ == "__main__":
    main()
