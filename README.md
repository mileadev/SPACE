# SPACE

[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) · [Guide](https://space.docs.perplexity.ai/guide/index.html) · [API reference](https://space.docs.perplexity.ai/api/index.html)

**Sandboxed Platform for Agentic Code Execution:** isolated Firecracker microVMs, managed via HTTP APIs for sandbox lifecycle, process execution, streaming output, storage, and network policy. SPACE is an execution boundary, **not** an inference server or LLM gateway.

## Run locally

Requires **Linux x86_64 with KVM**, Docker, and the prerequisites documented in [Installation](docs/installation.md). The Kind development cluster does not run natively on macOS; use a compatible Linux host or VM exposing KVM.

```bash
bash infra/space/kind/scripts/install-prereqs.sh
bash infra/space/kind/scripts/install-fc-vendor.sh
bash infra/space/kind/scripts/up.sh
# Authenticate as described in docs/installation.md, then:
python3 examples/first_sandbox.py
```

Do not start the cluster before reviewing [host requirements](docs/installation.md) and its privileges. Stop/teardown: `bash infra/space/kind/scripts/teardown.sh`.

## AI and MCP integrations

[SPACE MCP bridge](integrations/space-mcp/README.md): host-side stdio/loopback Streamable HTTP MCP server for Claude, Codex, Cursor, VS Code, Gemini CLI and compatible MCP harnesses, with provider-aware `model_chat` for **local Ollama, Ollama Cloud, and Amazon Bedrock**. Explicit model allowlists and opt-in mutation gates; no provider keys in guest sandboxes.

## References

- [Architecture and security boundaries](docs/architecture.md) · [Network egress profiles](docs/egress-profiles.md) · [TLS exemptions](docs/tls-interception-exemptions.md)
- [Native API](docs/api/index.md) · [First sandbox](docs/first-sandbox.md) · [E2B compatibility](docs/ecw.md)
- [Configuration](docs/configuration.md) · [Troubleshooting](docs/troubleshooting.md) · [Observability](docs/observability.md)
- [Security review scope and findings](docs/fork-security-review.md) · [Security disclosure](SECURITY.md) · [Contribution guide](CONTRIBUTING.md)

The native platform follows upstream `perplexityai/SPACE`. Preserve upstream dependency, sandbox and egress security controls when syncing. Licensed under [Apache-2.0](LICENSE).
