# BG-P6 — OAuth-authenticated Browser V2 Gateway signer

Date: 2026-10-19. Repository: `coding-tools-mcp`.
Base: `ceafa72bf52bddbdd23774a84fa999347a145072`.
Branch: `feat/browser-v2-oauth-signer-20261019`.

## Implemented boundary

The **existing** HTTP OAuth handler, not the MCP `arguments`, validates the
Bearer JWT (HS256 signature, issuer, audience, expiry, registered client).
The request-local ContextVar supplies the derived `BrowserCaller` to both
`browser_v2` and the new `browser_v2_setup` tool. Legacy static bearer
tokens, unauthenticated requests and stdio transport cannot attest a Browser
V2 caller. No OAuth credentials or production configuration were changed.

`BrowserCaller.session_id` is the JWT `jti` (canonical uppercase UUID).
`consumer_instance_id` is UUIDv5 of `issuer + "|" + registered client_id`,
using the existing `CONSUMER_NAMESPACE`. This is a *registered OAuth client*
identity, not independently verified OS/Chrome installation identity; each
new authorization-code token is a different session. The handler rejects
caller/session/consumer overrides in MCP arguments.

`browser_v2` continues to sign `zam.browser.gateway.caller.v1` with the
existing pinned Ed25519 private key, using `BrowserV2Wire` sorted-key,
snake_case, slash-escaped JSON bytes and SHA-256 scope digest. The Manager's
`BrowserV2GatewayCallerBinding` checks the pinned public key/gateway ID,
scope, operation, bounded time, nonce replay and its **separate C4 browser
grant**. Neither a valid JWT nor a signature grants browser access.

## New MCP tool: `browser_v2_setup`

Exposed only when all existing Browser V2 Gateway enrollment settings are
present, the pinned CLI checksum is valid, and runtime uses HTTP OAuth.
Input schema:

```json
{"operation":"request_registration","request_id":"<UUID>",
 "extension_id":"<verified 32-character Chrome extension ID>",
 "node_path":"<reviewed absolute Node path>"}
```

Other allowed operations use **exactly** `{"operation":"status",
"request_id":"<UUID>"}` (substitute `verify`, `stage_companion`,
`stage_native`, `get_job`, `cancel_job`, or `reconcile_job`).
`request_registration` alone needs `extension_id` and `node_path`.
No arbitrary paths for stage, shell input, owner approval, scripts, browser
cookies, private images, or extra fields are permitted.

To prevent a different OAuth session/consumer from polling or cancelling a
known setup job UUID, the Gateway converts the logical caller `request_id`
into a **session-bound Manager job ID**:

```
managerRequestID = uppercase(UUIDv5(
  namespace=4a9809c2-18b6-4354-a68f-f3769b9b8b45,
  name=verifiedSessionUUID + "|" + verifiedConsumerUUID + "|" + uppercase(request_id)
))
```

A repeat request within the *same* OAuth access-token session maps to the
same Manager ID. A different access token, even for the same registered
client, maps to a different Manager ID. This is a deterministic namespace
fence; **it is not a replacement for a Manager owner grant**, nor an
independent local proof of the OAuth client. Polling an existing job after
token renewal needs an explicit future Manager-approved recovery workflow.
The MCP response reports the original logical `request_id`; only the
signed stdin request carries the scoped Manager UUID.

## Exact Manager setup verification contract

Read-only source at implementation: Manager
`Sources/Core/Setup/BrowserV2SetupAgentAuthorization.swift` and
`Sources/AgentCLI/Commands/BrowserV2SetupCommandHandler.swift` on the
background-first worktree. This implementation modifies **no Manager file**.

1. Use the same owner-reviewed Ed25519 key and gateway UUID already used
   for `zam.browser.gateway.caller.v1`. Do **not** create a second signing
   identity, embed a private key, or allow fixture credentials at runtime.
2. Arguments are UTF-8 compact JSON, sorted keys, **no escaped slashes**,
   camelCase keys `requestID`, `operation`, and only when present
   `extensionID`, `nodePath`. This matches Manager
   `JSONEncoder.sortedKeys + withoutEscapingSlashes`. `requestID` is
   the session-bound UUID above. The digest is lowercase hex SHA-256 of
   these **exact JSON bytes**, not of the original MCP input.
3. Sign the UTF-8 bytes of sorted camelCase JSON with these **exact keys**:

   `schemaVersion="zam.browser.setup.caller.v1"`,
   `gatewayID` (UUID), `requestID` (UUID), `nonce` (fresh UUID),
   `operation` (allowlisted name), `argumentsSHA256` (hex digest),
   `issuedAtMS` (Unix epoch milliseconds), `expiresAtMS=issuedAtMS+20000`.

   Ed25519 signature is 64 bytes. Both payload and signature are standard
   base64 strings (with padding), not the base64url proof used for the
   existing `browser_v2` scoped caller.
4. Invoke the **checksum-pinned** absolute `zam browser v2 setup` CLI
   with **no dynamic command-line arguments**. Send one JSON object on stdin:

   `{"arguments":<the exact arguments object>,"proof":{"payload":"<base64 signed JSON bytes>","signature":"<base64 signature>"}}`.

   Input is at most 16 KiB; CLI timeout 25 seconds. No full proof, Node path,
   keys or registration data appear in argv, env, logs, tracing or response.
5. Manager verifies pinned public key/gateway ID, exact request ID,
   operation, argument digest, ≤30-second expiry and non-reused nonce before
   touching installation/job state. Manager separately performs real owner
   review for any privileged Native Messaging registration. **The Gateway
   cannot approve owner prompts or commit native host installation.**
6. Accept only typed `zam.cli.v1` responses with matching *scoped*
   Manager `request_id`, matching status/exit code
   (`complete=0`, `pending=3`, `denied=4`, `unavailable=5`,
   `invalid=6`, `failed/outcome_unknown=7`). Project response to
   original logical `request_id`, status, reason, exit code and a bounded
   allowlisted job `state`. Suppress all other Manager response data, in
   particular file locations or private installation details.

The initial Manager `BrowserV2SetupAgentClaim` has **no session/consumer
claim fields** and cannot itself independently validate JWT identity. The
Gateway enforces verified identity before signing and namespaces Manager
request IDs to limit cross-session job access. A future Manager contract
revision should explicitly carry attested session/consumer claims and
coordinate token-rotation recovery; do not describe the v1 verifier as
performing a check it does not perform.

## Authorization domains deliberately independent

- **C4 browser access**: Manager's browser grant after signed caller.
- **C4 interactions**: separate live-ref validation/grant; `click` and
  `fill` remain subject to Manager checks.
- **Screenshot capture**: separate C4 capture permission; no pixel data
  returned by this tool.
- **T2 artifact read**: requires different `artifact_read` caller proof
  and foreground owner-approved, scope-bound disclosure; not implemented
  by this BG-P6 setup endpoint.
- **MCP image delivery**: no automatic relay; remains blocked on actual
  separately authorized and integrity-checked private pixels.

## Verification and remaining acceptance

Offline tests: `uv run --offline --extra browser-v2 --no-dev python -m
unittest -q tests.test_browser_v2_gateway tests.test_browser_v2_setup_signer`.
These exercise Ed25519 proof, exact digest, pinned CLI, operation whitelist,
nonce freshness, mocked replay/expiry fence, logical/Manager request ID
session isolation, and real local Streamable HTTP + password/PKCE OAuth
authorization-code/token exchange with negative unauthenticated, spoofed
caller, and reused-code tests.

Observed: **27/27 PASS** including `tests.compliance.test_schema_drift`.
Full `unittest discover -s tests -p 'test_*.py'`: **480 tests, four
failures, seven skipped** before inventory documentation correction. The
inventory failure was fixed and its schema suite rerun successfully. The
remaining three failures (two assertions in repeated-destination patch
compatibility, one module-entrypoint display string) were reproduced directly
on untouched exact-base `ceafa72`, so are pre-existing and out of scope.
Official SDK-dependent tests were skipped in the offline test environment.

Still blocked on real owner/Gateway enrollment, a real Manager CLI roundtrip
under an approved pin, background macOS process focus acceptance, a real
Chrome Native Messaging handshake + owner Share, real owner-local T2 image
disclosure and delivered ChatGPT pixels. There is **no claim of live OAuth
ChatGPT acceptance** or production release readiness.

The previously reviewed offline wheel in
`docs/browser-v2-zamery-distribution-20261019.md` predates BG-P6 and its
checksum must **not** be reused for a new wheel. Rebuild/review/pin a new
wheel in the Manager distribution *only after* independent integration QA and
owner approval; do not deploy or replace running Gateway/MCP/Chrome.
