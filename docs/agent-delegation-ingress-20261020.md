# Agent delegation ingress (work_* tools)

Status: implemented on branch `feat/delegation-v1-mcp-auth-20261020` (from serving source `50e0cf0`). Offline/transport-auth proven; **not** deployed to the
live connector. Contract: Zamery delegation Foundation v0.1.0, schema digest
`sha256:19c77ef3b387ab9dbde9595b379efe823c194a12c67c39373b4ef31cb9123e1d`.
Catalog source: Manager integration amendment `6cd7af52f2f8fb9d2583825e01307b18620499b4`.
Bundled catalog file SHA-256: `d2bfda2c5acf94507538bc9199a1ecdb5504741696412de510a1381d8fb9a57b`.
Offline provider transport suite: 18/18 passing against the Manager's authenticated **real v1 engine**
and a pinned FakeKit executor, including the revoke/expiry-after-receipt-before-dispatch cases.
This is **not** a live connector deployment or proof of a real ChatGPT worker.

Staged wheel for this exact amended catalog (not installed):
`dist/delegation-v1-contract-19c77ef3/coding_tools_mcp-0.5.2+zamery.browser2.oauth2.delegation1.c19c77e-py3-none-any.whl`,
SHA-256 `1b8e2463d25b4684713665e24120b7a70775d8d3b63282deb4c418ba2e8df584`.
The wheel was installed into an isolated throwaway venv and its `load_catalog()` returned all ten tools with the pinned digest.
The previous `delegation1` wheel has a different catalog and is superseded for staging only. No live provider, tunnel or connector was modified.

**Integration branch is moving:** this wheel pins the `6cd7af5`-era catalog. After it was tested, the Manager coordinator merged lane 06 (`7287996`) and began merging lane 03; the coordinator's working tree had unresolved conflict stages in contract files and `contracts:check` failed. Therefore this wheel is **not installable as a matching candidate for the moving integration checkout**. First finalize the combined contract, regenerate and check it, then pin and stage a new wheel/version; do not merely edit the declared digest.

## What this provider does and does not do

- It serves ten tools: `work_capabilities`, `work_submit`, `work_list`, `work_inspect`, `work_wait`, `work_message`, `work_result`, `work_pause`,
  `work_cancel`, `work_resume` (schemas, descriptions and annotations verbatim from `delegation_catalog.json`; file and digest are pinned in code).
- It owns **no delegation state**: no Work store, no grants, no Kit client, no journal. Every call is forwarded to the Zamery Manager's owner-only local ingress.
- Ordinary tool calls work without MCP Tasks. Optional MCP Tasks are not negotiated by this provider (stateless protocol layer); the Manager exposes a
  mapping onto the same Work IDs for a future negotiated adapter.

## Trust chain

1. The HTTP handler validates the OAuth bearer (existing code). Identity = verified claims only: issuer, `client_id`, session (jti or hashed legacy token).
2. The gateway signs a proof (Ed25519, key under the same owner-custody rules as Browser V2) that commits to: audience, method `tools/call`, the tool name, the
   SHA-256 of the exact UTF-8 argument bytes, the verified principal fields, a nonce and a 20 s validity window.
3. The proof travels over an owner-only unix socket (`0600`, directory `0700`). The Manager verifies the signature against its pinned public key, rejects expiry,
   replay (nonce store), a different tool, or altered arguments, then maps the OAuth client to an owner-enrolled principal and applies server-owned grants.
4. Loopback reachability, arguments, workerId and prompt text are never identity.

## Configuration (opt-in)

| Env var | Meaning |
| --- | --- |
| `CODING_TOOLS_MCP_DELEGATION_GATEWAY_ID` | UUID of this provider gateway, pinned in the Manager |
| `CODING_TOOLS_MCP_DELEGATION_KEY_FILE` | absolute path, 32-byte raw Ed25519 seed, mode 0600, owner-only directory |
| `CODING_TOOLS_MCP_DELEGATION_DESCRIPTOR` | absolute path of the Manager's `ingress.json` descriptor (owner-only); re-read on every reconnect |

Without all three, or under stdio / static bearer, no `work_*` tool exists.

## Failure replies

Provider-originated failures use the Foundation `BusinessError` shape: `SETUP_REQUIRED` (Manager not running / not enrolled), `INTERNAL_UNAVAILABLE`
(lost reply; retry with the same `idempotencyKey`). Malformed arguments are JSON-RPC `-32602`. The repeat-failure breaker is bypassed for `work_*`
(business states are Manager-owned) and trace logging never records their arguments.

## Tests

- `tests/test_delegation_transport.py` (real HTTP MCP server + real OAuth JWT + real signed proof + real Manager ingress process with a fake executor;
  needs `ZAMERY_MANAGER_AGENTWORKFLOWS`).
- `tests/test_tool_receipts.py` (authenticated, digest-only, hash-chained server-side receipts for allowlisted read-only tools).

## Server-side tool receipts (evidence for a live read)

`CODING_TOOLS_MCP_RECEIPT_LOG=/abs/owner-only/dir/tool-receipts.jsonl` (optional `CODING_TOOLS_MCP_RECEIPT_TOOLS`, default `read_file,list_dir`)
makes the provider append one hash-chained, digest-only record per successful OAuth-authenticated call of an allowlisted tool. It never stores content,
paths or arguments. A receipt is same-host evidence that an authenticated call returned content with a given digest; it cannot say which chat made it.
The Manager verifies the chain and matches path/content digests (`Runtime/AgentWorkflows/src/delegation-ingress/receipts.ts`).
