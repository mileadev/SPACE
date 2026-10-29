"""MCP v2 stdio/loopback-HTTP adapter for the SPACE execution API."""

import hmac
import os
import sys
from contextlib import asynccontextmanager

from bridge import SpaceClient, chat


def build_server():
    from mcp.server import MCPServer

    server = MCPServer("SPACE sandbox and model bridge", version="0.1.0")
    client = None

    def space():
        nonlocal client
        if client is None:
            client = SpaceClient()
        return client

    @server.tool()
    def space_list() -> list[dict]:
        """List sandbox IDs and states visible to this bridge."""
        return space().list()

    @server.tool()
    def space_create() -> dict:
        """Create an isolated Firecracker sandbox; requires SPACE_MCP_ALLOW_CREATE=1."""
        return space().create()

    @server.tool()
    def space_status(sandbox_id: str) -> dict:
        """Inspect an owned/allowlisted sandbox; creation may still be pending."""
        return space().inspect(sandbox_id)

    @server.tool()
    def space_operation(operation_id: str) -> dict:
        """Poll a creation/deletion operation issued by this bridge."""
        return space().operation(operation_id)

    @server.tool()
    def space_run(sandbox_id: str, command: list[str]) -> dict:
        """Run bounded argv inside an owned sandbox; requires SPACE_MCP_ALLOW_EXEC=1."""
        return space().execute(sandbox_id, command)

    @server.tool()
    def space_delete(sandbox_id: str, confirmation: str) -> dict:
        """Delete owned sandbox; requires SPACE_MCP_ALLOW_DELETE=1 and human approval."""
        return space().delete(sandbox_id, confirmation)

    @server.tool()
    def model_chat(provider: str, model: str, prompt: str, system: str = "") -> dict:
        """Query allowlisted ollama_local, ollama_cloud, or bedrock model from the host."""
        return chat(provider, model, prompt, system)

    return server


def http_authorized(headers, port, secret):
    """Fail closed on ambiguous credentials, cross-origin requests and DNS rebinding."""
    pairs = [(key.lower(), val) for key, val in headers]
    for name in (b"authorization", b"host", b"origin"):
        if sum(key == name for key, _ in pairs) > 1:
            return False
    values = dict(pairs)
    host = values.get(b"host", b"").decode("ascii", "replace")
    supplied = values.get(b"authorization", b"").decode("utf-8", "replace")
    request_origin = values.get(b"origin", b"").decode("ascii", "replace")
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    return (host in allowed_hosts and
            (not request_origin or request_origin == f"http://{host}") and
            hmac.compare_digest(supplied, "Bearer " + secret))


def run_http(server):
    """HTTP is opt-in, loopback-only and requires a bearer token for every call."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Mount

    secret = os.getenv("SPACE_MCP_HTTP_TOKEN", "")
    if len(secret) < 32:
        raise RuntimeError("SPACE_MCP_HTTP_TOKEN must contain at least 32 characters")
    port = int(os.getenv("SPACE_MCP_HTTP_PORT", "8765"))
    if not 1024 <= port <= 65535:
        raise ValueError("Invalid HTTP port")
    app = server.streamable_http_app(json_response=True, stateless_http=True)

    async def authenticate(scope, receive, send):
        if scope["type"] == "http":
            if not http_authorized(scope["headers"], port, secret):
                await send({"type": "http.response.start", "status": 403, "headers": []})
                await send({"type": "http.response.body", "body": b"Forbidden"})
                return
        await app(scope, receive, send)

    @asynccontextmanager
    async def lifespan(_):
        async with server.session_manager.run():
            yield

    uvicorn.run(Starlette(routes=[Mount("/", app=authenticate)], lifespan=lifespan),
                host="127.0.0.1", port=port, access_log=False)


def main():
    server = build_server()
    if len(sys.argv) == 1 or sys.argv[1:] == ["--stdio"]:
        server.run(transport="stdio")
    elif sys.argv[1:] == ["--http"]:
        run_http(server)
    else:
        raise SystemExit("Usage: python server.py [--stdio|--http]")


if __name__ == "__main__":
    main()
