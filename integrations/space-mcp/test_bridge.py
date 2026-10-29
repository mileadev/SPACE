"""Offline tests; no live AWS, Ollama, KVM or SPACE deployment required."""

import base64
import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import bridge


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class BridgeTests(unittest.TestCase):
    def env(self, **values):
        return patch.dict(os.environ, values, clear=True)

    def test_requires_token(self):
        with self.env():
            with self.assertRaisesRegex(RuntimeError, "SPACE_API_TOKEN"):
                bridge.SpaceClient()

    def test_rejects_nonloopback_http_and_url_credentials(self):
        with self.env(SPACE_API_URL="http://example.com:80", SPACE_API_TOKEN="x"):
            with self.assertRaises(ValueError):
                bridge.SpaceClient()
        with self.env(SPACE_API_URL="https://u:p@example.com", SPACE_API_TOKEN="x"):
            with self.assertRaises(ValueError):
                bridge.SpaceClient()

    def test_no_implicit_redirects_or_proxy(self):
        self.assertTrue(any(isinstance(h, bridge.NoRedirect) for h in bridge.HTTP.handlers))
        with self.assertRaises(RuntimeError), patch.object(bridge.HTTP, "open", side_effect=HTTPError("u", 302, "", {}, None)):
            bridge.request_json("https://example.com")

    def test_create_mutations_disabled(self):
        with self.env(SPACE_API_TOKEN="x"):
            with self.assertRaises(PermissionError):
                bridge.SpaceClient().create()

    def test_created_sandbox_owned_and_explicit_idempotency(self):
        with self.env(SPACE_API_TOKEN="x", SPACE_MCP_ALLOW_CREATE="1"):
            client = bridge.SpaceClient()
            with patch("bridge.request_json", return_value={"sandbox_id": "sbx_abc", "operation_id": "op_xyz"}) as call:
                result = client.create()
            self.assertEqual(result["sandbox_id"], "sbx_abc")
            self.assertIn("sbx_abc", client.created)
            self.assertIsNotNone(call.call_args.kwargs["key"])

    def test_sandbox_scope(self):
        with self.env(SPACE_API_TOKEN="x", SPACE_MCP_ALLOW_EXEC="1"):
            client = bridge.SpaceClient()
            with self.assertRaises(PermissionError):
                client.execute("sbx_other", ["id"])
            with self.assertRaises(ValueError):
                client.inspect("http://malicious/path")

    def test_execute_session_attachment_and_exit(self):
        with self.env(SPACE_API_TOKEN="x", SPACE_MCP_ALLOW_EXEC="1", SPACE_MCP_SANDBOX_IDS="sbx_ok"):
            client = bridge.SpaceClient()
            attached = {"session_id": "proc_a", "process_id": "proc_a",
                        "attach": {"events_url": "/v1/sessions/proc_a/events", "token": "private"}}
            frames = ([{"type": "stdout", "data_base64": base64.b64encode(b"hello").decode()},
                       {"type": "process_exited", "exit_code": 0}])
            sse = "".join("data: " + json.dumps(f) + "\n\n" for f in frames).encode()
            with patch("bridge.request_json", return_value=attached), patch.object(bridge.HTTP, "open", return_value=Response(sse)) as opened:
                result = client.execute("sbx_ok", ["printf", "hello"])
            self.assertEqual((result["exit_code"], result["stdout"]), (0, "hello"))
            self.assertEqual(opened.call_args.args[0].headers["Authorization"], "Bearer private")

    def test_rejects_attachment_traffic_redirection(self):
        with self.env(SPACE_API_TOKEN="x", SPACE_MCP_ALLOW_EXEC="1", SPACE_MCP_SANDBOX_IDS="sbx_ok"):
            client = bridge.SpaceClient()
            with patch("bridge.request_json", return_value={"session_id": "proc_a", "attach": {"events_url": "https://evil.example/", "token": "s"}}):
                with self.assertRaisesRegex(RuntimeError, "origin/path"):
                    client.execute("sbx_ok", ["id"])

    def test_no_clean_exit_is_failure(self):
        with self.env(SPACE_API_TOKEN="x", SPACE_MCP_ALLOW_EXEC="1", SPACE_MCP_SANDBOX_IDS="sbx_ok"):
            created = {"session_id": "proc_a", "attach": {"events_url": "/v1/sessions/proc_a/events", "token": "s"}}
            with patch("bridge.request_json", return_value=created), patch.object(bridge.HTTP, "open", return_value=Response(b"")):
                with self.assertRaisesRegex(RuntimeError, "verified exit"):
                    bridge.SpaceClient().execute("sbx_ok", ["id"])

    def test_model_allowlist_and_local_chat(self):
        with self.env(SPACE_MCP_MODELS_OLLAMA_LOCAL="tiny:latest"):
            with self.assertRaises(PermissionError):
                bridge.chat("ollama_local", "other", "test")
            with patch("bridge.request_json", return_value={"message": {"content": "hi"}}) as call:
                result = bridge.chat("ollama_local", "tiny:latest", "test")
            self.assertEqual(result["text"], "hi")
            self.assertIsNone(call.call_args.kwargs["token"])
            self.assertEqual(call.call_args.args[0], "http://127.0.0.1:11434/api/chat")

    def test_cloud_auth(self):
        with self.env(OLLAMA_API_KEY="secret", SPACE_MCP_MODELS_OLLAMA_CLOUD="cloud:model"):
            with patch("bridge.request_json", return_value={"message": {"content": "cloud"}}) as call:
                bridge.chat("ollama_cloud", "cloud:model", "hello")
            self.assertEqual(call.call_args.kwargs["token"], "secret")
            self.assertEqual(call.call_args.args[0], "https://ollama.com/api/chat")

    def test_delete_requires_two_gates(self):
        with self.env(SPACE_API_TOKEN="x", SPACE_MCP_ALLOW_DELETE="1", SPACE_MCP_SANDBOX_IDS="sbx_ok"):
            with self.assertRaises(PermissionError):
                bridge.SpaceClient().delete("sbx_ok", "no")


class AdditionalTests(unittest.TestCase):
    def test_http_auth_and_origin(self):
        from server import http_authorized
        secret = "x" * 32
        good = [(b"host", b"127.0.0.1:8765"),
                (b"authorization", b"Bearer " + secret.encode()),
                (b"origin", b"http://127.0.0.1:8765")]
        self.assertTrue(http_authorized(good, 8765, secret))
        self.assertFalse(http_authorized(good + [(b"authorization", b"Bearer other")], 8765, secret))
        self.assertFalse(http_authorized(good[:-1] + [(b"origin", b"http://evil.test")], 8765, secret))
        self.assertFalse(http_authorized(good[:1], 8765, secret))

    def test_bedrock_uses_aws_sdk_only(self):
        with patch.dict(os.environ, {"AWS_REGION": "us-east-1",
                                  "SPACE_MCP_MODELS_BEDROCK": "us.test:model"}, clear=True):
            with patch("boto3.client") as client:
                client.return_value.converse.return_value = {
                    "output": {"message": {"content": [{"text": "bedrock"}]}}}
                result = bridge.chat("bedrock", "us.test:model", "ping")
            self.assertEqual(result["text"], "bedrock")
            client.assert_called_once()
            self.assertEqual(client.call_args.args[0], "bedrock-runtime")

    def test_list_only_scoped_sandboxes(self):
        with patch.dict(os.environ, {"SPACE_API_TOKEN": "x", "SPACE_MCP_SANDBOX_IDS": "sbx_yes"}, clear=True):
            with patch("bridge.request_json", return_value={"data": [
                {"sandbox_id": "sbx_yes", "name": "allowed"},
                {"sandbox_id": "sbx_no", "name": "private"}]}) as _:
                result = bridge.SpaceClient().list()
            self.assertEqual([x["sandbox_id"] for x in result], ["sbx_yes"])

    def test_operation_scoping(self):
        with patch.dict(os.environ, {"SPACE_API_TOKEN": "x"}, clear=True):
            client = bridge.SpaceClient()
            with self.assertRaises(PermissionError):
                client.operation("op_notmine")
            client.operations.add("op_good")
            with patch("bridge.request_json", return_value={"state": "succeeded"}):
                self.assertEqual(client.operation("op_good")["state"], "succeeded")


if __name__ == "__main__":
    unittest.main()
