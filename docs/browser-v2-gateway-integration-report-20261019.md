# Browser V2 — Existing OAuth/MCP Gateway Integration (2026-10-19)

**Status: PARTIAL ENGINEERING / REAL E2E NOT DONE / RELEASE NO-GO.**
Never interpret localhost fixture execution or a signed payload as owner browser consent, an actual T2 image read, or ChatGPT-visible pixels. No production deployment, merge, OAuth cutover, key provisioning or owner Chrome action was performed.

## Repository and exact ownership

- **Actual deployed gateway implementation:** upstream `xyTom/coding-tools-mcp` (`https://github.com/xyTom/coding-tools-mcp`), not the Manager's `scripts/mcp_gateway_*.py` offline/test prototypes and not Zamery Browser's independent MCP.
- Documented existing production service: `com.zamery.coding-mcp`, with OAuth 2.1/PKCE, local HTTP `/mcp`, Cloudflare tunnel. Manager documentation describes runtime 0.5.0 but **the live executable's exact Git commit/digest was not independently established**.
- Integration baseline: upstream tag `v0.5.0`, commit `aa1cbf3832e0c85994600f2249d9544fbae2f49e`; upstream remote main was `47dbccf2c3d6fa27eacf8970c8cd44d3dbcd3377` on discovery. Deliberately based on the known 0.5.0 API release instead of assuming newer upstream main matches production.
- Isolated feature branch: `feat/browser-v2-gateway-integration-20261019`; worktree `.external-src/coding-tools-mcp/.worktrees/browser-v2-gateway-integration-20261019` under the authorized development workspace. This is a *new source checkout*, not the deployed runtime path. Source repo main is untouched.
- **INT-3B contract**: `maemreyo/zamery-mcp-manager` branch `integration/agent-int3b-browser-v2-20261019`, clean source commit `bbfdb62e1587a12bd57c729c4b303d8b37c6365a`; original worktree not modified. Specifically read `GATEWAY_IMAGE_CONTRACT.md`, `REAL_ACCEPTANCE_EVIDENCE.md`, `SECURITY_REVIEW.md`, `OWNER_ACTION_PLAYBOOK.md` and inspected `BrowserV2GatewayCallerBinding.swift`, `BrowserV2MCPImageDelivery.swift`, `BrowserV2ScopedArtifactReadAuthorization.swift`, `BrowserV2T2ArtifactAdapter.swift`, `BrowserV2UnifiedCLI.swift` and `BrowserV2Wire.swift`.

## Real production code entrypoints

| Concern | Existing source |
| --- | --- |
| OAuth 2.1 + PKCE, JWT issuance/introspection | `coding_tools_mcp/oauth.py`; HTTP auth grant handlers in `server.py` |
| Authenticated HTTP MCP transport, `tools/call` | `coding_tools_mcp/server.py`, `MCPHandler`, `RuntimeHTTPServer` |
| MCP dispatcher, tool registration | `coding_tools_mcp/protocol.py`, `server.py` `TOOL_REGISTRY` / `Runtime.call_tool` |
| Existing native MCP image serializer | `server.py` `_image_content` and `coding_tools_mcp/tool_results.py` |
| Existing Zamm CLI | INT-3B `BrowserV2UnifiedCLI` and `Sources/AgentCLI`; no alternate browser implementation added |
| T2 private storage / scoped read | INT-3B Swift adapter and private authorization, **not yet a cross-process bridge** |

## Changes implemented in this isolated gateway source branch

1. `coding_tools_mcp/oauth.py`: new opaque, random `jti` UUID on every issued OAuth access token; claim-returning independently verified introspection. Existing `validate_access_token` still provides a boolean for legacy callers and existing OAuth methods are unchanged. Old OAuth tokens lack a JTI: **existing MCP works, new Browser V2 denies**.
2. `coding_tools_mcp/browser_v2_gateway.py`: parses the actual validated JWT, derives a token-specific Browser V2 session UUID and OAuth registered-client-scoped audience UUID, denies mismatched agent-supplied scope, canonicalizes snake_case scope JSON to match Swift `JSONEncoder(.sortedKeys)` (including escaped forward slashes and UUID case), SHA256-binds exact scope, signs operation-specific one-use, 20-second Ed25519 `BrowserV2GatewayCallerClaim`, sends signed proof through existing Zamm CLI and tightly checks typed response, operation, exit code and bounded output. Fill value is stdin only.
3. Signing seed is read only from explicit private owner-owned 0600 file within 0700 directory. No key generation, fixture seed reuse, untrusted CLI arguments, or key contents in code/logs. The gateway requires an owner-pinned exact executable digest. **Owner must independently approve/pin the *public* key in Manager before use**.
4. `coding_tools_mcp/server.py`: adds a **tool to the existing MCP provider**, not a second provider. The additive `browser_v2` tool is hidden and non-callable unless all four private, opt-in gateway configuration items are valid and HTTP OAuth is active. `MCPHandler.handle_rpc` binds the already-verified OAuth JWT to a per-request `ContextVar`, preventing shared-runtime HTTP client identity leakage. Static bearer and stdio transports cannot authenticate a Browser V2 call. Browser tool traces omit tab scope, typed input, DOM refs and private page content.
5. `verified_png_block` provides a bounded, actual Pillow-decoded PNG / IHDR dimension / SHA256 verification seam and builds the native `type:image` MCP content block. **This is not a T2 owner-approved image delivery endpoint**; no image is auto-exposed, no artifact ID/path can trigger disclosure.
6. `tests/test_browser_v2_gateway.py`: ephemeral Ed25519 test keys, test OAuth token and *synthetic CLI* fixtures; validates all ten verbs, one-use proof uniqueness and operation/scope binding, wrong session and audience refusal, signed wire layout, Swift Foundation canonicalization vector, key custody refusal, CLI SHA and strict response/exit mismatch refusal, actual PNG decode/hash validation, and an actual non-production HTTP `tools/call` through `MCPHandler` (valid OAuth JWT 200, absent JWT 401, forged scope denied).
7. `pyproject.toml` and `uv.lock`: opt-in `browser-v2` extras for Ed25519 and image decoding. Existing protocol v0.5.0 entrypoints preserved.

**Operator enrollment is intentionally not performed by code.** All four gateway options below require an owner-reviewed staging deployment; simply changing them in production is outside task authorization:

```text
CODING_TOOLS_MCP_BROWSER_V2_GATEWAY_ID=<owner-reviewed UUID>
CODING_TOOLS_MCP_BROWSER_V2_KEY_FILE=<absolute protected private seed path>
CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI=<absolute reviewed Zamm CLI path>
CODING_TOOLS_MCP_BROWSER_V2_ZAM_CLI_SHA256=<approved binary SHA256>
```

The Manager alone must receive the corresponding verified **public** Ed25519 key and gateway UUID in `browser_v2_gateway/owner-approved.json`. Never copy the private key to the Manager or a browser extension.

## Executed test evidence (gateway checkout)

- `uv run --extra browser-v2 --no-dev python -m unittest -v tests.test_browser_v2_gateway`: **12 PASS**, on non-production localhost and ephemeral fixtures.
- `uv run --extra browser-v2 --no-dev python -m unittest -q tests.test_browser_v2_gateway tests.compliance.test_security tests.compliance.test_mcp_contract`: **94 PASS after the final typed-response hardening**, including the 12 new tests and existing OAuth/PKCE, MCP HTTP/stdio and security regression. Observed `Ran 94 tests in 63.805s; OK`.
- Local Swift Foundation JSONEncoder vector compared byte-for-byte with Python canonical JSON; confirmed escaped slash and uppercase UUID requirements.
- Browser INT-3B previously reported 344 Manager self-tests PASS (provided source baseline; not a new observation from this checkout).

**None of these** prove the currently deployed gateway binary, a browser host connection, C4 real owner grants, private T2 cross-process records, or ChatGPT image rendering.

## Remaining engineering blockers (NOT DONE)

1. **Independent authenticated consumer instance identity.** The upstream OAuth JWT authenticates a registered *OAuth client*, not a device-specific ChatGPT instance. This implementation derives a stable audience UUID5 from issuer + registered client and a session UUID from token JTI. It cannot independently attest an exact ChatGPT device/instance on a shared OAuth client: additional trusted gateway instance enrollment/binding is required before the release requirement can be considered met.
2. **Cross-process T2 image artifact binding** remains per-process in INT-3B `BrowserV2ScopedArtifactReadAuthorization`. Need owner-private transactional record of session, consumer, audience, exact tab/document, artifact UUID/SHA/capture timestamp/expiry/revocation; crash/restart, cleanup, concurrent read, and replay tests; no arbitrary file reads.
3. **No separately authenticated `artifact_read` tool/host handler exists in production.** Its caller proof must be independently signed for `artifact_read` and Manager-side verified; current `zam browser v2` CLI accepts ten *browser* verbs only, **not** artifact_read. The Python PNG converter is intentionally not registered as a public file-read tool.
4. **No actual foreground one-use owner image-release approval** is connected; Manager defaults to `BrowserV2DenyImageRead`. Capture remains distinct from disclose. Cannot forward actual image pixels to ChatGPT while this approval path is absent.
5. **Owner-approved installed Chrome Companion + Native Messaging origin provenance / same-UID hardening** remains unverified. An origin argument, local Unix socket or file SHA does not independently prove Chrome process ancestry.
6. **Manager 2048-proof persistent nonce ledger** fails closed at capacity. Owner-reviewed rotation requires a checkpoint/epoch design that retains replay nonces until all issued proofs have expired; an atomic epoch/version change with owner-approved key and gateway ID pin and fail-closed interruption, not silent eviction.
7. Real B1/B3/B5 plus INT-3B cross-process regression, crash/restart, concurrent revoke and full live gateway/browser E2E have not been rerun against an installed host.
8. Live deployed gateway version/digest and eligibility to modify or fork the third-party upstream were not verified; release requires repository ownership/maintenance review before using a modified upstream runtime.

## Remaining owner actions (DO NOT AUTOMATE)

Review/pin the exact gateway public key and protected installer provenance; review/approve the unchanged operating OAuth runtime during a separately authorized staging window; approve only the specific installed signed native host and Chrome Companion extension; explicitly Share a safe staging tab; approve inspect/interact/capture separately; then separately approve one private image read for a named artifact and witness the actual PNG displayed in ChatGPT; revoke and verify every subsequent browser and artifact read is denied. Do not import a personal Chrome profile, export cookies/passwords, install dependencies/browser, change credentials, restart launchd/tunnels or deploy from this development branch.

## Release gates

| Gate | Evidence | Verdict |
| --- | --- | --- |
| Gateway implementation | OAuth-authenticated signed CLI forwarding exists, image relay missing | **PARTIAL / NOT DONE** |
| Deterministic gateway acceptance | 94 passing gateway+regression tests; no cross-process T2/owner integration | **PARTIAL PASS / FULL INTEGRATION NOT DONE** |
| Real *deployed* authenticated gateway E2E | Non-production localhost handler only | **NOT DONE** |
| Owner-approved real Chrome E2E | No approved installation or Share | **NOT DONE** |
| Real ChatGPT T2 image content/pixel display | Native block tested locally, no T2/owner/ChatGPT relay | **NOT DONE** |
| Release GO | Security + owner gates open | **NO-GO** |

## INT-3B integration instructions for separately approved follow-up

1. Keep `bbfdb62` immutable. Use a **new** Manager integration worktree from INT-3B to implement persistent T2 capture bindings and a Mac owner-confirmed one-use `artifact_read` handler with C4 and Ed25519 proof revalidation. Never mistake captured T2 receipt for model-visible image content.
2. Add gateway image-read `tools/call` handling only after the trusted host handler is available; forward verified image bytes via native MCP `content:[{type:image,mimeType:image/png,data:...}]`, not a base64 plaintext message or arbitrary filesystem path.
3. In isolated staging, enroll approved public key on host; validate matching ephemeral/non-exportable production signer custody, exact device instance/session identity and CLI digest. Run tests A–O from task against genuine authenticated HTTP and approved browser; observe image digest/bytes inside ChatGPT. Preserve B1/B3/B5 and all legacy MCP tools.
4. Coordinate an owner-approved nonce-ledger rotation policy before exhaustion, then secure release review. No merge to upstream or Manager main, no deployment, without explicit approval.

**No source-side browser/grant/security bypass has been added. Release remains blocked.**
