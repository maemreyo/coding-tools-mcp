# Delegation provider completion candidate — 2026-10-20

Candidate version: `0.5.2+zamery.browser2.oauth2.delegation2.c94e9661`.
Public contract: `0.1.0`,
`sha256:94e9661f5ef7f338221462ce22d5c00ac2f3f5864233b1e98254ef712e813a0e`.
Catalog file SHA-256: `da7e1bd839796ee01a8272925438defcbeea5f33d6ec1f62b30d3e0ec1abe9ec`.

This is a separate staged candidate. Serving release `oauth2-453063ad`, its launcher,
virtual environment, connector, tunnel, keys and state remain untouched. The earlier
`delegation1.c19c77e` wheel contains a different catalog and must not be used for this contract.

## Scope and verification

The provider exposes the generated ten `work_*` tools only with all delegation
settings present and OAuth transport. Existing baseline tools remain unchanged.
The authoritative catalog is the Manager generator's
`docs/agent-workflows/delegation-v1/contracts/tool-catalog.json`; no provider-owned
schema or grant logic exists.

The provider verifies OAuth claims and signs a tool/argument-bound 20-second
Ed25519 proof. Manager owns identity enrollment, authority, Work state, grants,
accounting, results and execution. An account principal is not a per-chat identity.
Digest-only tool receipts record no plaintext paths, arguments, tokens or nonce.

Transport reads now use a total monotonic deadline, preventing slow partial
replies from extending the request indefinitely. `work_wait.waitMs` is bounded by
the generated maximum of 25000 ms before connecting. Transport timeout or lost ACK
does not imply cancellation; an idempotent mutation is retried only with the same
key. Explicit `work_cancel` is a separate Manager safety control.

Preparation results on Manager completion base `7289f28`:
18/18 real OAuth HTTP -> signed proof -> real v1 engine transport tests;
31/31 Browser V2, setup signer, digest-only receipts and release metadata unit
regressions; 2/2 transport boundary tests including an actual slow AF_UNIX reply.
Fake executor only; this is not Swift/Kit composed or live ChatGPT acceptance.
Final Manager source and installed-wheel transport results belong in the artifact
manifest and completion handoff after the coordinator freezes the final source.

## Rebuild and inspect

From this clean provider checkout, using its private development venv containing
`build`, `setuptools>=68,<77`, and `wheel`:

```sh
.venv/bin/python scripts/stage_delegation_provider.py \
  --manager <clean-manager-checkout> --manager-sha <full-final-commit> \
  --out dist/delegation-completion-final
```

The script refuses dirty source, requires exact Manager HEAD and byte-identical
generated catalog, archives the committed provider source twice, builds with a
fixed `SOURCE_DATE_EPOCH`, compares wheel SHA-256, installs into a new isolated
venv, and checks installed metadata/catalog equality. It records source/tree,
Manager SHA/tree, wheel and catalog digests in `artifact-manifest.json`.
Its status is packaging verification; transport and composed app acceptance
remain separate gates. Do not relabel it as composed product acceptance.

For transport, set `ZAMERY_MANAGER_AGENTWORKFLOWS` to the final Manager's
`Runtime/AgentWorkflows` and run `tests.test_delegation_transport` using the
candidate installed in an isolated venv. Run copied tests from a directory
outside the source checkout, so imports cannot silently use checkout code.
The Manager harness runs under `deny-network.mjs`; only disposable state/key
material is used.

## Parallel installation and rollback plan — NOT EXECUTED

1. Verify final app/provider/Kit manifests and offline acceptance. Check the exact
   wheel SHA-256 and schema digest before creating a new versioned venv.
2. Install this exact wheel with its `browser-v2` optional dependencies into a
   new candidate release venv. Never install over `oauth2-453063ad`.
3. Keep the current launcher unchanged while testing a separate loopback server.
   Supply the native owner-provisioned delegation gateway/key/descriptor settings:
   `CODING_TOOLS_MCP_DELEGATION_GATEWAY_ID`,
   `CODING_TOOLS_MCP_DELEGATION_KEY_FILE`,
   `CODING_TOOLS_MCP_DELEGATION_DESCRIPTOR`. Use a private owner-owned directory.
   No static bearer or worker-supplied identity may enable delegation.
4. Confirm `tools/list` preserves the baseline and adds exactly ten tools,
   descriptor instance/contract handshake matches the packaged Manager, and
   owner enrollment/grants operate through the app. Check a restart rereads the
   descriptor and persisted Work remains visible. No live model turn is needed.
5. After separate rollout authorization, switch only the launcher target to the
   candidate version, refresh connector discovery, and verify tool inventory.
   A live probe is separately bounded and approved; it is not part of this run.
6. Roll back by returning the launcher target to the preserved serving release.
   Stop only exact candidate-owned processes. Preserve unresolved Work/attempt
   evidence and candidate logs, and revoke candidate grants through the owner.
   Do not delete profiles, copy cookies, erase production state, or retry unknown
   sends. A transport response loss is never proof a user turn was not sent.
