# SPACE fork: security and deployment review

**Baseline:** `perplexityai/SPACE` / `mileadev/SPACE` `82296d7cf0618096fc69c847d8664b00d224ee5f` (2026-10-29). **Scope:** repository tree inventory (5,994 entries), documentation and CI configuration, source inspection of the network-gateway DNS/egress/route-verification paths, SPACE's first-sandbox client, and the new MCP integration. This is a **bounded security review, not a complete 59 MB line-by-line Rust audit or live penetration test**. No malware verdict is asserted for unreviewed files.

## Verified observations

| Priority | Evidence | Result / action |
| --- | --- | --- |
| HIGH | `.github/workflows/pull-ci.yml`, `main-ci.yml`, `rust-static-ci.yml`: `if: github.repository == 'perplexityai/SPACE'` | Fork does not execute those repository-gated checks. Add fork-owned MCP/unit/syntax CI. Full upstream Rust/Kind workflows remain unavailable until explicitly adapted to the fork's runners and artifact permissions. |
| HIGH | `docs/installation.md` | Local SPACE needs Linux x86_64/KVM, privileged Docker/Kind, TUN/loop/btrfs. macOS cannot host the documented setup natively. Deploy platform on Linux; run the MCP client on macOS if desired. |
| HIGH | `docs/architecture.md`, `examples/first_sandbox.py` | Management bearer token and data-plane session token are separate. Creating a command does not start execution; event attachment is mandatory. The adapter validates the attachment origin/path, disables redirects/proxies, and requires a verified exit frame. |
| HIGH | MCP tool exposure | A bearer token with sandbox create/exec is powerful. Default-disable all mutations, constrain sandboxes, require explicit model allowlists, and keep provider credentials exclusively in the host process. |
| MEDIUM | `docs/egress-profiles.md`, `crates/libs/net/gateway/server/src/{dns,egress,tcp_proxy}.rs` | Domain attribution and CDN authority validation are security boundaries. Preserve DNS attribution/HTTP Host/TLS SNI checks; add regression tests for DNS spoofing, shared-IP authority switching, unsupported UDP and failure of inspection. Do not assume an IP allowlist is a domain allowlist. |
| MEDIUM | `.gitleaks.toml`, `deny.toml` | Secret scanning contains fixture-specific allowlists; `RUSTSEC-2024-0449` is explicitly ignored as informational/unmaintained. Review exception provenance at each dependency update and run cargo-deny, cargo-vet, cargo-audit, gitleaks. No exploitability was established by this review. |
| MEDIUM | `integrations/space-mcp` | Local inference allows loopback HTTP; remote insecure HTTP is explicit opt-in. Bedrock uses AWS SDK credential chain; cloud credentials and prompts must not reach guests. Public HTTP transport is disabled; loopback HTTP requires a 32+ character bearer token. |

## Verification matrix

- **Executed offline:** Python syntax compilation and MCP bridge unit tests (argument validation, auth presence, redirect rejection, sandbox scoping, idempotency key, stream attachment/exit, provider allowlists).
- **Not executed here:** entire Rust `cargo test --locked` suite, `cargo clippy`, `cargo deny`, cargo-vet, full gitleaks scan, native KVM/Kind smoke, Bedrock/Ollama paid-cloud live requests, sandbox breakout tests, cross-client MCP HTTP/stdio protocol conformance. Therefore **no claim of full-code audit completion, production readiness, or universal harness support** is made.
- **Required before production:** run `ci/scripts/run-rust-checks.sh` in its supported CI environment, Kind smoke and native sandbox scenarios; run gitleaks and dependency advisories; test each configured MCP client and provider with sandbox-specific policies; review IAM and rotate any exposed credentials.

## Change isolation and rollback

The adapter is deliberately separate from `crates/` and SPACE's network/VM security implementation. Remove or disable `integrations/space-mcp`, revoke its service token, and revert README/CI changes to roll back without mutating guest images or databases. Changes should enter the fork through a reviewed PR; the upstream main branch is untouched.
