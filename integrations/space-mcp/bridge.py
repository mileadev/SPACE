"""Security-conscious SPACE API and optional inference clients; no MCP dependency."""

import base64
import json
import os
import re
import uuid
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


HTTP = build_opener(ProxyHandler({}), NoRedirect())
ID_PATTERN = re.compile(r"sbx_[A-Za-z0-9_-]+\Z")
MAX_OUTPUT = 65536


def origin(name, default, *, local_only=False):
    value = os.getenv(name, default).rstrip("/")
    parsed = urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.path or parsed.query
            or parsed.fragment):
        raise ValueError(f"{name} must be an HTTP(S) origin without credentials or a path")
    parsed.port  # Validate port.
    loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if local_only and not loopback:
        raise ValueError(f"{name} must be loopback")
    if parsed.scheme == "http" and not loopback and not (
        name == "OLLAMA_LOCAL_URL" and os.getenv("OLLAMA_ALLOW_INSECURE_LAN") == "1"
    ):
        raise ValueError(f"{name}: HTTP is only allowed on loopback")
    return value


def require_id(sandbox_id):
    if not isinstance(sandbox_id, str) or not ID_PATTERN.fullmatch(sandbox_id):
        raise ValueError("Invalid sandbox ID")
    return sandbox_id


def required_secret(name):
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Configure {name} outside source control")
    return value


def request_json(url, method="GET", data=None, *, token=None, key=None, timeout=30):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if key:
        headers["Idempotency-Key"] = key
    payload = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        payload = json.dumps(data).encode("utf-8")
    req = Request(url, data=payload, headers=headers, method=method)
    try:
        with HTTP.open(req, timeout=timeout) as response:
            if response.status == 204:
                return {}
            raw = response.read(2 * 1024 * 1024 + 1)
    except HTTPError as exc:
        # Do not echo response bodies: they may contain secrets or prompt contents.
        raise RuntimeError(f"Upstream HTTP {exc.code}") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise RuntimeError("Upstream response exceeded size limit")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise RuntimeError("Upstream response was not an object")
    return result


class SpaceClient:
    def __init__(self):
        self.api = origin("SPACE_API_URL", "http://127.0.0.1:8080")
        self.data_plane = origin("SPACE_DATA_PLANE_URL", "http://127.0.0.1:8090")
        self.token = required_secret("SPACE_API_TOKEN")
        self.created = set()
        self.operations = set()

    def request(self, method, path, body=None, *, mutation=False):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Only relative API paths are accepted")
        return request_json(self.api + path, method, body, token=self.token,
                            key=uuid.uuid4().hex if mutation else None)

    def allowed(self, sandbox_id):
        require_id(sandbox_id)
        configured = set(os.getenv("SPACE_MCP_SANDBOX_IDS", "").split(","))
        if sandbox_id not in self.created and sandbox_id not in configured:
            raise PermissionError("Sandbox is not owned or allowlisted for this bridge")

    @staticmethod
    def enabled(flag):
        if os.getenv(flag) != "1":
            raise PermissionError(f"Explicit opt-in required: {flag}=1")

    def list(self):
        result = self.request("GET", "/v1/sandboxes?limit=50")
        allowed = self.created | set(os.getenv("SPACE_MCP_SANDBOX_IDS", "").split(","))
        return [{k: s.get(k) for k in ("sandbox_id", "name", "state")}
                for s in result.get("data", [])
                if isinstance(s, dict) and s.get("sandbox_id") in allowed]

    def create(self):
        self.enabled("SPACE_MCP_ALLOW_CREATE")
        template = os.getenv("SPACE_TEMPLATE", "seed:latest")
        response = self.request("POST", "/v1/sandboxes",
                                {"template": template, "runtime": "fc"}, mutation=True)
        sandbox_id = require_id(response.get("sandbox_id"))
        self.created.add(sandbox_id)
        operation_id = response.get("operation_id")
        if isinstance(operation_id, str) and re.fullmatch(r"op_[A-Za-z0-9_-]+", operation_id):
            self.operations.add(operation_id)
        return {"sandbox_id": sandbox_id, "operation_id": operation_id,
                "note": "Creation is asynchronous; inspect state before running commands"}

    def operation(self, operation_id):
        if (not isinstance(operation_id, str)
                or not re.fullmatch(r"op_[A-Za-z0-9_-]+", operation_id)
                or operation_id not in self.operations):
            raise PermissionError("Operation is not owned by this bridge")
        result = self.request("GET", f"/v1/operations/{operation_id}")
        return {"operation_id": operation_id, "state": result.get("state")}

    def inspect(self, sandbox_id):
        self.allowed(sandbox_id)
        data = self.request("GET", f"/v1/sandboxes/{sandbox_id}")
        return {k: data.get(k) for k in ("sandbox_id", "name", "state", "runtime")}

    def execute(self, sandbox_id, command):
        self.enabled("SPACE_MCP_ALLOW_EXEC")
        self.allowed(sandbox_id)
        if (not isinstance(command, list) or not 1 <= len(command) <= 32
                or any(not isinstance(x, str) or not 1 <= len(x) <= 2048 or "\x00" in x
                       for x in command)):
            raise ValueError("Command must be an array of 1-32 bounded argument strings")
        created = self.request("POST", f"/v1/sandboxes/{sandbox_id}/commands",
                               {"command": command, "timeout": "30s"}, mutation=True)
        session_id = created.get("session_id", "")
        if not re.fullmatch(r"proc_[A-Za-z0-9_-]+", session_id):
            raise RuntimeError("Invalid command session identifier")
        path = f"/v1/sessions/{session_id}/events"
        target = self.data_plane + path
        attach = created.get("attach", {})
        if not isinstance(attach, dict) or attach.get("events_url") not in (path, target):
            raise RuntimeError("Attachment URL failed origin/path verification")
        token = attach.get("token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("Missing session-scoped attachment token")
        req = Request(target, headers={"Authorization": "Bearer " + token,
                                       "Accept": "text/event-stream"})
        out = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = False
        exited = None
        with HTTP.open(req, timeout=45) as response:
            parts = []
            while True:
                line = response.readline(262145)
                if not line:
                    break
                if len(line) > 262144:
                    raise RuntimeError("Command stream frame exceeded size limit")
                line = line.rstrip(b"\r\n")
                if line.startswith(b"data:"):
                    parts.append(line[5:].lstrip(b" "))
                elif not line and parts:
                    frame = json.loads(b"\n".join(parts))
                    parts = []
                    kind = frame.get("type")
                    if kind in ("error", "resync_required"):
                        raise RuntimeError(f"Command stream reported {kind}")
                    if kind in out:
                        raw = base64.b64decode(frame["data_base64"], validate=True)
                        remaining = max(0, MAX_OUTPUT - len(out[kind]))
                        out[kind].extend(raw[:remaining])
                        truncated |= len(raw) > remaining
                    elif kind == "process_exited":
                        exited = frame.get("exit_code")
                        break
        if type(exited) is not int:
            raise RuntimeError("Command did not produce a verified exit event")
        return {"process_id": created.get("process_id"), "exit_code": exited,
                "stdout": out["stdout"].decode("utf-8", "replace"),
                "stderr": out["stderr"].decode("utf-8", "replace"),
                "truncated": truncated}

    def delete(self, sandbox_id, confirmation):
        self.enabled("SPACE_MCP_ALLOW_DELETE")
        self.allowed(sandbox_id)
        if confirmation != sandbox_id:
            raise PermissionError("Confirmation must equal the exact sandbox ID")
        response = self.request("DELETE", f"/v1/sandboxes/{sandbox_id}", mutation=True)
        operation_id = response.get("operation_id")
        if isinstance(operation_id, str) and re.fullmatch(r"op_[A-Za-z0-9_-]+", operation_id):
            self.operations.add(operation_id)
        return {"sandbox_id": sandbox_id, "operation_id": operation_id,
                "note": "Deletion is asynchronous; poll its operation; do not blindly retry"}


def chat(provider, model, prompt, system=""):
    if provider not in ("ollama_local", "ollama_cloud", "bedrock"):
        raise ValueError("Unknown provider")
    if (not isinstance(model, str) or not 1 <= len(model) <= 200
            or not re.fullmatch(r"[A-Za-z0-9._:/-]+", model)):
        raise ValueError("Invalid model identifier")
    if not isinstance(prompt, str) or not 1 <= len(prompt) <= 16000:
        raise ValueError("Prompt must be 1-16000 characters")
    if not isinstance(system, str) or len(system) > 4000:
        raise ValueError("System message too long")
    allowed = os.getenv(f"SPACE_MCP_MODELS_{provider.upper()}", "")
    if model not in {x.strip() for x in allowed.split(",") if x.strip()}:
        raise PermissionError(f"Model is not allowlisted in SPACE_MCP_MODELS_{provider.upper()}")
    if provider == "bedrock":
        # Boto3 uses the AWS credential provider chain (including SSO and IAM roles).
        import boto3
        from botocore.config import Config
        region = required_secret("AWS_REGION")
        messages = [{"role": "user", "content": [{"text": prompt}]}]
        args = {"modelId": model, "messages": messages,
                "inferenceConfig": {"maxTokens": 1024}}
        if system:
            args["system"] = [{"text": system}]
        response = boto3.client("bedrock-runtime", region_name=region,
                                config=Config(connect_timeout=5, read_timeout=60,
                                              retries={"max_attempts": 2})).converse(**args)
        content = response["output"]["message"]["content"]
        return {"provider": provider, "model": model,
                "text": "\n".join(x["text"] for x in content if "text" in x)[:32768]}
    url = ("https://ollama.com/api/chat" if provider == "ollama_cloud" else
           origin("OLLAMA_LOCAL_URL", "http://127.0.0.1:11434") + "/api/chat")
    token = required_secret("OLLAMA_API_KEY") if provider == "ollama_cloud" else None
    messages = ([{"role": "system", "content": system}] if system else []) + [
        {"role": "user", "content": prompt}]
    response = request_json(url, "POST", {"model": model, "messages": messages,
                                          "stream": False}, token=token, timeout=90)
    message = response.get("message", {})
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise RuntimeError("Ollama returned no assistant content")
    return {"provider": provider, "model": model, "text": message["content"][:32768]}
