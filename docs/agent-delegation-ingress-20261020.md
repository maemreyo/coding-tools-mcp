# Agent delegation ingress (work_* tools)

Status: implemented on branch `feat/delegation-v1-mcp-auth-20261020` (from serving source `50e0cf0`). Offline/transport-auth proven; **not** deployed to the
live connector. Contract: Zamery delegation Foundation v0.1.0, schema digest
`sha256:94e9661f5ef7f338221462ce22d5c00ac2f3f5864233b1e98254ef712e813a0e`.
Catalog source: Manager integration branch after composed lane 02/03/06/07/08 merges (`00aa6b9`), final generated contract SHA-256 as below.
Bundled catalog file SHA-256: `da7e1bd839796ee01a8272925438defcbeea5f33d6ec1f62b30d3e0ec1abe9ec`.
Offline provider transport suite: 18/18 passing against the Manager's authenticated **real v1 engine**
and a pinned FakeKit executor, including the revoke/expiry-after-receipt-before-dispatch cases.
This is **not** a live connector deployment or proof of a real ChatGPT worker.

The old c19c77e wheel belongs to a superseded contract. See
[the completion candidate and rebuild/rollout runbook](delegation-completion-provider-20261020.md)
for the versioned c94e9661 candidate. The final artifact manifest, not an earlier
wheel report, identifies the matching Manager and provider source.

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
