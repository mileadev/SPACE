# SPACE MCP bridge

Host-side adapter for [SPACE](../../README.md). Exposes sandbox tools plus allowlisted inference through **local Ollama**, **Ollama Cloud**, and **Amazon Bedrock**. Uses the official MCP Python SDK 2.3.0 (stdio and Streamable HTTP, including legacy MCP clients); does **not** modify VM isolation or inject model credentials into guests.

## Requirements

- Python 3.11+ on the MCP **client host**; SPACE itself requires a **Linux x86_64 KVM host**. macOS must call a separately deployed SPACE instance; it cannot run the documented Kind/Firecracker setup natively.
- A working SPACE installation: [installation](../../docs/installation.md). Obtain `SPACE_API_TOKEN` through its documented login flow; never commit it.
- Ollama locally (default `127.0.0.1:11434`), an Ollama Cloud API key, or Bedrock IAM credentials, depending on provider.

```bash
cd integrations/space-mcp
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
# Export SPACE_API_URL, SPACE_DATA_PLANE_URL, SPACE_API_TOKEN from the SPACE guide.
# Export SPACE_MCP_MODELS_OLLAMA_LOCAL=llama3.2 (or an installed model name).
.venv/bin/python server.py --stdio
```

The stdio process expects an MCP client to launch it; running it in a terminal without input produces no prompt. Place secrets in a shell secret manager, not in command arguments or client JSON. `.env.example` documents settings but is **not** automatically loaded.

## Permissions and models

- Default tools: `space_list` (only owned/allowlisted IDs), `space_status`, `space_operation`, `model_chat`.
- Mutations: `space_create` requires `SPACE_MCP_ALLOW_CREATE=1`; `space_run` requires `SPACE_MCP_ALLOW_EXEC=1`; `space_delete` requires `SPACE_MCP_ALLOW_DELETE=1` **and** matching the ID in `confirmation`. Enable only when your MCP host prompts for human approval. Created sandbox IDs are scoped to the bridge process; existing IDs must be explicitly listed in `SPACE_MCP_SANDBOX_IDS` (comma-separated).
- Model inference: `model_chat(provider, model, prompt, system)` takes `ollama_local`, `ollama_cloud`, or `bedrock`. Set the exact model allowlist in `SPACE_MCP_MODELS_OLLAMA_LOCAL`, `_OLLAMA_CLOUD`, or `_BEDROCK`. No models are usable without explicit allowlisting.
- Local Ollama defaults to `http://127.0.0.1:11434/api/chat`. HTTPS is required on non-loopback endpoints unless `OLLAMA_ALLOW_INSECURE_LAN=1` is **explicitly** enabled for trusted LAN traffic. Ollama Cloud uses `https://ollama.com/api/chat` and `OLLAMA_API_KEY`. Bedrock uses `boto3` `Converse`, `AWS_REGION`, and the standard AWS credential chain; grant `bedrock:Converse`/`bedrock:InvokeModel` only on the exact model resources needed. **Cloud inference may incur charges and transmit prompts off-host.**
- The SPACE management token never reaches model APIs or guest command environments. Output is capped at 64 KiB per stream, command sessions at 30s, prompts at 16k chars. A non-zero command exit is returned explicitly, not treated as success.

## MCP harness registration

Use the same stdio process for **Claude Desktop/Claude Code, Cursor, VS Code MCP, Codex, Gemini CLI, OpenCode, Windsurf**, and other clients supporting stdio MCP. Set absolute executable/script paths in your harness's MCP settings; these are *structural* examples, not provider-specific file paths:

```json
{
  "mcpServers": {
    "space": {
      "command": "/ABSOLUTE/PATH/integrations/space-mcp/.venv/bin/python",
      "args": ["/ABSOLUTE/PATH/integrations/space-mcp/server.py"]
    }
  }
}
```

Codex's TOML-style server configuration:

```toml
[mcp_servers.space]
command = "/ABSOLUTE/PATH/integrations/space-mcp/.venv/bin/python"
args = ["/ABSOLUTE/PATH/integrations/space-mcp/server.py"]
```

Your harness may use a different configuration wrapper or key names; keep `command` and `args` and map them to the client's current MCP schema. Credentials remain in the launching process environment or secret manager, **not** in committed harness settings. MCP tool names and schemas remain identical across transports.

For HTTP-only MCP hosts, run `.venv/bin/python server.py --http` after exporting a random `SPACE_MCP_HTTP_TOKEN` of 32+ characters; endpoint `http://127.0.0.1:8765/mcp` (configurable `SPACE_MCP_HTTP_PORT`). The server binds **loopback only**, validates `Origin`/`Host` and bearer authentication, and disables access logs. Do not expose this endpoint publicly; use a separately authenticated TLS proxy and review its identity/authorization model first.

## Deploy, verify, rollback

1. On **Linux x86_64 with KVM**, follow [SPACE's Kind installation](../../docs/installation.md) and run `python3 examples/first_sandbox.py` once using its own safe create/attach/delete workflow. On macOS, use an SSH tunnel to loopback API and data-plane ports on a Linux KVM host.
2. Export `SPACE_API_URL`/`SPACE_DATA_PLANE_URL` and the management token obtained from the SPACE CLI/login. Set one local model allowlist entry and configure a client. Test `tools/list`, `space_list`, and `model_chat` first. Enable `space_create`/`space_run` only for an approved sandbox; confirm exit code and output. Test Bedrock/Cloud with a budget-limited model and explicit approval.
3. Run offline tests: `python3 -m unittest discover -s integrations/space-mcp -p 'test_*.py' -v`. For full platform tests, run upstream Rust, dependency, Kind and gateway policy suites on the required Linux host; this bridge test suite is **not** a VM-escape or egress-policy certification.
4. Rollback: disable `SPACE_MCP_ALLOW_*`, stop the bridge process, revoke the scoped SPACE token and any unneeded cloud credentials. SPACE's native cluster/services are unchanged.

**Threat model:** A model/harness controlling an MCP tool can request code execution. Constrain service-token scope, approve mutation tool calls, use default-deny SPACE egress policies (including protections for DNS spoofing and shared-IP/CDN routing), and never mount host credentials or Docker sockets into untrusted guests. HTTP clients must not reach this bridge without an authenticated local boundary.
