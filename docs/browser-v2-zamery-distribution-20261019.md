# Zamery Browser V2 Gateway — local wheel release candidate

Date: 2026-10-19. Branch: `feat/browser-v2-gateway-integration-20261019`.

This forkable integration branch exposes the existing OAuth-authenticated
`browser_v2` gateway and has **its own Python distribution version**:
`0.5.1+zamery.browser2`. It must not be confused with upstream `0.5.0`.
The version is synchronized across `pyproject.toml` and
`coding_tools_mcp/__init__.py`.

## Reviewed owner-machine package

Built locally using `uv build --offline --wheel`, without an Apple Developer
account. Exact wheel:

- `coding_tools_mcp-0.5.1+zamery.browser2-py3-none-any.whl`
- SHA-256: `4583a411b6e9759a7afa68197bd7ac637efb831e003957235006e7dafb845fb1`
- Size: 177988 bytes.
- Contains `coding_tools_mcp/browser_v2_gateway.py`.

Dependencies locked for **macOS arm64 CPython 3.14 only** using the upstream
wheel SHA-256 and pinned sizes:

| Name | Version | SHA-256 |
| --- | --- | --- |
| cffi | 2.1.1 | 661c298b4821edebead0c91edd2b00374d67ad7c5a1f7a91d4442633b79d6a72 |
| cryptography | 46.0.7 | ea42cbe97209df307fdc3b155f1b6fa2577c0defa8f1f7d3be7d31d189108ad4 |
| pillow | 12.3.0 | e158cb00350dc278f3b91551101aa7d12415a66ebf2c91d8d5ac14e56ddd3ad0 |
| pycparser | 3.11 | 51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80 |
| pyjwt | 2.15.1 | 42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193 |

All six reviewed wheels are bundled in the **Zamery MCP Manager**
`Sources/App/BrowserV2Distribution/gateway-wheel-py314-arm64/` resource
directory and installed only through its owner-confirmed offline installer.
The Manager's separate, pinned-venv runtime does not replace the existing
Coding Tools 0.5.0 or the running gateway. No external PyPI request is
performed at *installation* time.

The observed Gateway scope tests: `python -m unittest -q
tests.test_browser_v2_gateway` **12/12 PASS**, including a fixture HTTP
OAuth call. This is a release-candidate packaging test, not an E2E pass.

## Open release blockers

- Currently needs an existing CPython 3.14 on macOS arm64; Manager should
  eventually distribute an appropriately reviewed embedded interpreter
  to remove that prerequisite.
- Gateway OAuth runtime must be configured and undergo actual authenticated
  traffic acceptance, not only have its wheel installed.
- The private Ed25519 signer key, exact gateway UUID, pinned Zamm CLI path
  and checksum must be bound to a trusted Manager-owned deployment.
- Browser V2 `artifact_read`/foreground owner image-disclosure and actual
  MCP image pixels are **not wired through real ChatGPT**.
- Owner-approved Chrome extension/native-host provenance and real Chrome
  Share/Stop/roundtrip acceptance remain pending.

Do not claim production release readiness or modify running production
gateway/Cloudflare deployment solely because these wheels install.
