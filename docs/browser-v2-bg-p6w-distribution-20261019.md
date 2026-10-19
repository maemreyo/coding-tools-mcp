# BG-P6W — OAuth Gateway offline wheel and Manager compatibility

Date: 2026-10-19. Repository: `coding-tools-mcp`.
Source commit: `6ede335ee54881aee9fce0be5b61563c834dacb4` (verified).
Workstream: `integration/browser-v2-oauth-wheel-20261019` in
`.worktrees/browser-v2-oauth-wheel-20261019`.
This is an **offline distribution and compatibility candidate**, not a deployed
OAuth Gateway or an owner-approved browser session.

## Outcome

- Gateway package: `coding-tools-mcp==0.5.2+zamery.browser2.oauth1`.
  Old pre-OAuth `0.5.1+zamery.browser2` checksum MUST NOT be reused.
- New wheel: `coding_tools_mcp-0.5.2+zamery.browser2.oauth1-py3-none-any.whl`,
  **180097 bytes**, **SHA-256
  `e675ee61513cc32baa5c12968916752dc72f83f2ab158f17dd7fc9a5fa457db1`**.
- A six-wheel macOS arm64, Python 3.14 bundle exists locally at
  `dist/browser-v2-bg-p6w-py314-arm64/`. Only the five dependencies from
  the independently reviewed old bundle were reused after exact SHA-256 checks.
  The Gateway wheel was built **fresh from this branch** and not copied from
  Manager.
- Convenience transfer archive (not an input for Manager's six-wheel verifier):
  `dist/browser-v2-bg-p6w-py314-arm64.zip`, 12326823 bytes,
  SHA-256 `633279dda69b13664f4ea36253972048c23e63ecb8491e24cfaa453462431b66`.
- Machine-verifiable wheel inventory:
  `docs/browser-v2-bg-p6w-wheel-inventory-20261019.json`, and local
  `dist/browser-v2-bg-p6w-py314-arm64/{SHA256SUMS,wheel-inventory.json}`.
  The JSON covers all six wheel names, sizes, SHA-256 hashes, source file
  hashes, Python architecture and offline installation result.
- Two clean offline builds with fixed `SOURCE_DATE_EPOCH=1792368000` yielded
  byte-identical Gateway wheel checksums. A disposable Python 3.14 venv installed
  the six wheels via `uv pip install --offline --no-index` and successfully
  imported `coding_tools_mcp.browser_v2_gateway` and checked distribution
  version/signing schema.
- No credentials, Chrome profiles, real owner files or running Gateway were
  changed. No Manager production installer was modified.

## Rebuild, verify and install without network

Requirements: Apple Silicon macOS, existing CPython 3.14, `uv` and an offline
`setuptools` build backend already in its build cache; read-only access to
the reviewed dependency wheelhouse. Run from **this worktree root**:

```bash
uv lock --offline
python3.14 scripts/build-browser-v2-bg-p6w.py \
  --python /opt/homebrew/bin/python3.14 \
  --source-wheelhouse /Users/trung.ngo/Documents/zaob-dev/zamery-mcp-manager/Sources/App/BrowserV2Distribution/gateway-wheel-py314-arm64
cd dist/browser-v2-bg-p6w-py314-arm64
shasum -a 256 -c SHA256SUMS
```

The script refuses unexpected dependency hashes, wrong Python/architecture,
missing OAuth source/metadata, non-reproducible dual builds, or overwriting an
existing output directory. For independent reruns, pass `--output` with a **new**
directory; the tracked inventory is refreshed. It does not install into
Manager. `--source-wheelhouse` may point to any previously reviewed offline
five-dependency wheel folder; the exact five checksum pins are in the script.
The installer smoke test is fully local and uses a disposable venv.

Note: the bundle directory includes JSON and SHA256SUMS for auditing.
**Manager's `verifyBundle` requires precisely six `*.whl` entries and no
extra files**; copy ONLY those six wheels into the eventual Manager resource.

## OAuth and Manager wire review

The existing HTTP server validates JWT **signature, issuer, audience, expiry,
registered client** before deriving the request-local caller. The registered
OAuth client ID is not OS device identity. `jti` is the per-token session;
the consumer ID derives deterministically from issuer and verified client.
MCP arguments cannot override either. Static bearer/stdio are not an
authenticated setup caller.

The Gateway creates a scoped Manager `requestID` from UUIDv5(session,
consumer, logical request ID), signs the sorted camelCase arguments SHA-256,
and uses the already-enrolled Ed25519 Gateway identity. Exact claim is
`zam.browser.setup.caller.v1` with `gatewayID`, `requestID`, `nonce`,
`operation`, `argumentsSHA256`, `issuedAtMS`, `expiresAtMS`. Proof
payload/signature are standard padded base64. The CLI receives one bounded
JSON object via stdin, never proof on the command line. The gateway validates
typed `zam.cli.v1` response/exit code and projects only status/reason/safe
state into the logical MCP reply.

Read-only Manager comparison:

| Manager snapshot | Result |
| --- | --- |
| `b1fe8a730e15cf56d41e6123197b854ea0ba4b76` | Same schema, Ed25519, base64, arguments SHA-256, sorted JSON/no escaped slashes, nonce fence, gateway pin, owner approval. |
| `4d907177d2df11e8943580fc7a916db38f8ad1fe` (`integration/browser-bg-final-20261019`) | Contract preserved; CLI now checks exact argument/proof key sets and bounds stdin reading. Our payload satisfies both; cancelled registration returns cancelled instead of pending. |

The final branch's checked source files are
`Sources/Core/Setup/BrowserV2SetupAgentAuthorization.swift` and
`Sources/AgentCLI/Commands/BrowserV2SetupCommandHandler.swift`.
A compiled `zam` on each snapshot was probed **only** with `--version`
and malformed signed-setup input (denied before private storage creation):
both accepted the typed CLI wire and rejected malformed input. To extend
this beyond mock responses, the independent
`scripts/check-browser-v2-bg-p6w-manager-wire.py` harness archives exact
Manager commit `4d90717`, compiles the **actual Swift setup handler source**
against that commit's `MCPManagerCore`, injects disposable private storage and
fake Chrome directory, then passes actual OAuth Gateway-signed stdin over a
checksum-pinned executable wrapper. **PASS**: signed `status` result 0, first
use of a signed nonce 0, exact replay denied 4, expired claim denied 4.
These tests use a generated disposable Ed25519 key and **real Manager
verifier/handler code**, but not production `zam`'s hardwired storage path.
Production `AgentPrivateStorage()` resolves the account with `getpwuid`,
not `HOME`; forged HOME would still write to the real user's account.
The executable disposable fake-CLI tests additionally cover timeout,
malformed result, unauthorized caller, redaction and signed JSON. No actual
owner or Chrome registration was attempted.

No new Manager authorization surface was added. A valid signature is NOT
owner approval: Native Messaging registration remains a separate native
approval action. Cross-token recovery of an existing logical job requires a
future explicit Manager-approved protocol; the UUIDv5 namespace alone does
not enable rotation recovery.

### Explicit Manager pinning changes (NOT applied by BG-P6W)

Create a **separate Manager integration branch** based on an approved
Manager release candidate. Preserve original `main` and running app.

1. Copy only `*.whl` files from this worktree's
   `dist/browser-v2-bg-p6w-py314-arm64/` into Manager
   `Sources/App/BrowserV2Distribution/gateway-wheel-py314-arm64/`.
   Remove the **old** `coding_tools_mcp-0.5.1+zamery.browser2-py3-none-any.whl`
   from the new bundle. Do not place the two audit files inside resources.
2. Change `Sources/Core/Setup/BrowserV2BundledWheelInstaller.swift`:
   - `version = "0.5.2+zamery.browser2.oauth1"`
   - First wheel name
     `coding_tools_mcp-0.5.2+zamery.browser2.oauth1-py3-none-any.whl`
   - First wheel `size:180097`, `sha256:"e675ee61513cc32baa5c12968916752dc72f83f2ab158f17dd7fc9a5fa457db1"`
   - `relativeFolder = relativeParent + "/sha256_e675ee61513cc32b"`
   - Keep the other five dependency pins *unchanged*, as shown by the
     inventory. Retain every `verifyBundle` and installed-code check.
3. Update the hardcoded previous SHA prefix in
   `tests/browser-v2/setup/Sources/main.swift` for the disposable installed
   code tamper test, and update Manager's old-wheel design notes.
4. Rebuild Manager's app resource bundle, run
   `bash tests/browser-v2/setup/run-acceptance.sh`, the dedicated headless
   background QA, resource packaging checks and full relevant Manager
   regression. Confirm `BrowserV2BundledWheelInstaller.verifyBundle`
   refuses a mutated wheel, a missing wheel and the OLD pre-OAuth wheel.
5. Only then perform owner-reviewed staged Gateway installation; enrollment
   must still pin the real compiled `zam`, owner Ed25519 public key and
   gateway UUID. Never infer these values from `SHA256SUMS`, a package
   version string or MCP arguments. Do not auto-switch the running provider.

The independent Mach-O
`BrowserV2GatewayReleaseCatalog.reviewed = nil` mechanism is a different
distribution pathway and remains **unset**. This Python wheel is **not**
a signed/notarized macOS Gateway binary release and does not satisfy that
release-catalog prerequisite.

## Regression evidence

- Initial unmodified BG-P6 source: 27/27 PASS for Browser V2 Gateway,
  OAuth setup signer and schema drift.
- BG-P6W targeted: 34 tests, **PASS with one skipped** when no compiled CLI
  pin was specified. The optional compiled-CLI test passed independently for
  the exact-base Manager and the later final integration binary
  (`7/7 PASS` each).
- Additional real disposable subprocess tests cover the pinned CLI path,
  signed stdin, SHA-256/Ed25519 verification, nonce uniqueness, status and
  pending-owner projection, forbidden owner override, tamper, malformed
  responses and timeout.
- Cross-language compiled Manager code test at exact final commit:
  `BG_P6W_SWIFT_MANAGER_SIGNED_STDIN_PASS` (status/one-use/replay/expiry).
  Reproduce via `uv run --offline --extra browser-v2 --no-dev python
  scripts/check-browser-v2-bg-p6w-manager-wire.py --manager-repository
  <local-manager-repo>`. Requires local Swift toolchain; builds solely in
  ignored disposable `dist/` staging and archives the immutable Manager code.
- Full `python -m unittest discover -s tests -p 'test_*.py'`:
  **487 tests, 3 FAIL, 8 skipped** (139.610 seconds). No BG-P6W-specific
  failure. Exactly three failing assertions are pre-existing:
  `CodexApplyPatchCompatibilityTests.test_repeated_destination_keeps_the_first_conflict_baseline`
  has the `add` and `move` subcase failures; and
  `RuntimeHelperTests.test_package_module_entrypoint_exposes_version`
  expects `__main__.py` while actual display starts with
  `python -m coding_tools_mcp`.
- To avoid treating previous reports as proof, those **same three failures**
  were reproduced directly using a fresh `git archive` checkout of original
  untouched `ceafa72bf52bddbdd23774a84fa999347a145072` and the same
  interpreter, without copying code from BG-P6W. See local retained logs
  `dist/bg-p6w-{full-test,baseline-known-failures}.log`.
- Official MCP SDK-dependent smoke tests were skipped in this fully offline,
  no-dev environment. These skips must not be described as successful
  external SDK acceptance.

Exact target test commands:

```bash
uv run --offline --extra browser-v2 --no-dev python -m unittest -q \
  tests.test_browser_v2_gateway tests.test_browser_v2_setup_signer \
  tests.test_browser_v2_bg_p6w_integration tests.compliance.test_schema_drift
uv run --offline --extra browser-v2 --no-dev python -m unittest discover \
  -s tests -p 'test_*.py'
```

Optional safe compiled Manager smoke requires `BG_P6W_MANAGER_CLI`
(absolute compiled executable) **and**
`BG_P6W_MANAGER_CLI_SHA256` (reviewed binary pin). No Manager storage
is accessed in the safe probe.

## Outstanding owner/live acceptance, safety and remote

No production credentials/keys used or generated. No production Gateway
restart, Cloudflare deployment, Chrome profile modification, owner approval,
or MCP config replacement. Actual OAuth ChatGPT live requests against the
separately enrolled owner Gateway, signed CLI success with real owner-pinned
key, real Chrome Native Messaging handshake, owner Share/Stop and T2 pixel
disclosure remain **NOT VERIFIED**. The tests cannot override these blocks.

Configured Git remote is solely
`origin=https://github.com/xyTom/coding-tools-mcp.git`. It is not
assumed writable and BG-P6W must **not push** to it. No other authorized
user-owned fork remote was present. Keep the branch commit locally. For a
future push, the owner must first explicitly authorize a fork URL and configure
a distinct remote, for example `git remote add <owner-approved-name>
<owner-approved-fork-url>`, then explicitly authorize a push to
`integration/browser-v2-oauth-wheel-20261019`. Do not invent the URL or
push to someone else's repository automatically.
