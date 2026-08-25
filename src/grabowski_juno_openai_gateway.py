from __future__ import annotations

import argparse
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
import uuid

import grabowski_coding_agent_router as coding_agent_router

MODEL_ID = "grabowski-juno"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18195
DEFAULT_TOKEN_PATH = (
    Path.home()
    / ".local"
    / "state"
    / "grabowski"
    / "juno-openai-gateway"
    / "token"
)
MAX_BODY_BYTES = 64 * 1024
MAX_MESSAGES = 32
MAX_MESSAGE_BYTES = 8 * 1024
MAX_TOTAL_CONTENT_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 120
MAX_CONCURRENT_REQUESTS = 1
_ALLOWED_REQUEST_FIELDS = {
    "model",
    "messages",
    "stream",
    "stream_options",
    "temperature",
    "top_p",
    "max_tokens",
    "max_completion_tokens",
    "stop",
    "n",
    "seed",
    "user",
}
_PROVIDER_SECRET_ENV = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "XAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
    }
)
_DISABLED_CODEX_FEATURES = (
    "shell_tool",
    "unified_exec",
    "hooks",
    "apps",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "plugins",
    "multi_agent",
    "image_generation",
    "view_image",
    "tool_suggest",
    "remote_plugin",
    "skill_mcp_dependency_install",
)
_REQUEST_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)


class GatewayError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _error(status: int, code: str, message: str) -> GatewayError:
    return GatewayError(status, code, message)


def load_bearer_token(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"cannot open gateway token: {type(exc).__name__}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("gateway token must be a regular file")
        if before.st_uid != os.getuid():
            raise RuntimeError("gateway token owner is invalid")
        if before.st_nlink != 1:
            raise RuntimeError("gateway token must have exactly one hard link")
        if stat.S_IMODE(before.st_mode) & 0o077:
            raise RuntimeError("gateway token permissions are too broad")
        if not 32 <= before.st_size <= 4096:
            raise RuntimeError("gateway token size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                raise RuntimeError("gateway token ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError("gateway token grew while being read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise RuntimeError("gateway token changed while being read")
    try:
        token = b"".join(chunks).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("gateway token must be ASCII") from exc
    if not 32 <= len(token) <= 512 or any(character.isspace() for character in token):
        raise RuntimeError("gateway token content is invalid")
    return token


def _extract_text_content(content: Any, *, index: int) -> str:
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts: list[str] = []
        for part_index, part in enumerate(content):
            if (
                not isinstance(part, dict)
                or part.get("type") not in {"text", "input_text"}
                or not isinstance(part.get("text"), str)
            ):
                raise _error(
                    HTTPStatus.BAD_REQUEST,
                    "unsupported_content",
                    f"messages[{index}].content[{part_index}] must be a text part",
                )
            parts.append(part["text"])
        text = "\n".join(parts)
    else:
        raise _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_messages",
            f"messages[{index}].content must be text",
        )
    if len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise _error(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "message_too_large",
            f"messages[{index}] exceeds the per-message limit",
        )
    return text


def validate_chat_request(payload: Any) -> tuple[list[dict[str, str]], bool]:
    if not isinstance(payload, dict):
        raise _error(HTTPStatus.BAD_REQUEST, "invalid_request", "request body must be an object")
    unknown = sorted(set(payload) - _ALLOWED_REQUEST_FIELDS)
    if unknown:
        raise _error(
            HTTPStatus.BAD_REQUEST,
            "unsupported_parameter",
            "unsupported request fields: " + ", ".join(unknown),
        )
    if payload.get("model") != MODEL_ID:
        raise _error(HTTPStatus.BAD_REQUEST, "model_not_found", f"model must be {MODEL_ID}")
    raw_messages = payload.get("messages")
    if not isinstance(raw_messages, list) or not raw_messages or len(raw_messages) > MAX_MESSAGES:
        raise _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_messages",
            f"messages must contain between 1 and {MAX_MESSAGES} entries",
        )
    messages: list[dict[str, str]] = []
    total_bytes = 0
    for index, raw in enumerate(raw_messages):
        if not isinstance(raw, dict) or set(raw) - {"role", "content", "name"}:
            raise _error(
                HTTPStatus.BAD_REQUEST,
                "invalid_messages",
                f"messages[{index}] has unsupported fields",
            )
        role = raw.get("role")
        if role not in {"system", "user", "assistant"}:
            raise _error(
                HTTPStatus.BAD_REQUEST,
                "invalid_messages",
                f"messages[{index}].role is unsupported",
            )
        text = _extract_text_content(raw.get("content"), index=index)
        total_bytes += len(text.encode("utf-8"))
        if total_bytes > MAX_TOTAL_CONTENT_BYTES:
            raise _error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "context_too_large",
                "conversation exceeds the gateway context limit",
            )
        messages.append({"role": role, "content": text})
    stream = payload.get("stream", False)
    if not isinstance(stream, bool):
        raise _error(HTTPStatus.BAD_REQUEST, "invalid_stream", "stream must be boolean")
    if "stream_options" in payload and not isinstance(payload["stream_options"], dict):
        raise _error(
            HTTPStatus.BAD_REQUEST,
            "invalid_stream_options",
            "stream_options must be an object",
        )
    if payload.get("n", 1) != 1:
        raise _error(HTTPStatus.BAD_REQUEST, "unsupported_parameter", "n must be 1")
    for field in ("temperature", "top_p"):
        if field in payload and (
            isinstance(payload[field], bool) or not isinstance(payload[field], (int, float))
        ):
            raise _error(HTTPStatus.BAD_REQUEST, "unsupported_parameter", f"{field} must be numeric")
    for field in ("max_tokens", "max_completion_tokens", "seed"):
        if field in payload and (
            isinstance(payload[field], bool) or not isinstance(payload[field], int)
        ):
            raise _error(HTTPStatus.BAD_REQUEST, "unsupported_parameter", f"{field} must be an integer")
    return messages, stream


def _conversation_prompt(messages: list[dict[str, str]]) -> str:
    rendered = "\n\n".join(
        f"<{message['role']}>\n{message['content']}\n</{message['role']}>"
        for message in messages
    )
    return (
        "You are serving an authenticated private chat endpoint. "
        "Answer only from the supplied conversation and your model knowledge. "
        "Do not use tools, shell commands, files, repositories, MCP, browser, network, "
        "local state, memories, plugins, apps, or external resources. "
        "Return only the assistant response text, with no transport metadata.\n\n"
        "<conversation>\n"
        f"{rendered}\n"
        "</conversation>"
    )


def select_advisory_contract() -> dict[str, Any]:
    try:
        selection = coding_agent_router.select_contrast_routes(
            "triage",
            changed_files=0,
            duration_minutes=3,
            novelty="low",
            risk_flags=["private-context", "user_data"],
            latency_priority=True,
            max_candidates=2,
            allow_paid=False,
            allowed_harnesses={"codex"},
        )
    except Exception as exc:
        raise _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "router_unavailable",
            f"coding-agent router unavailable: {type(exc).__name__}",
        ) from exc
    routes = selection.get("routes")
    if selection.get("status") != "recommended" or not isinstance(routes, list) or not routes:
        raise _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "no_safe_route",
            "no current non-paid Codex advisory route is available",
        )
    route = routes[0]
    if (
        not isinstance(route, dict)
        or route.get("harness") != "codex"
        or route.get("paid_only") is True
        or "openrouter" in str(route.get("route", "")).lower()
        or "openrouter" in str(route.get("provider_family", "")).lower()
    ):
        raise _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "unsafe_route",
            "router returned a route outside the gateway safety contract",
        )
    route_id = route.get("route")
    if not isinstance(route_id, str) or not route_id:
        raise _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "unsafe_route",
            "router returned an invalid route id",
        )
    try:
        contract = coding_agent_router.advisory_route_execution_contract(
            route_id, paid_execution_authorized=False
        )
    except Exception as exc:
        raise _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "route_revalidation_failed",
            f"advisory route revalidation failed: {type(exc).__name__}",
        ) from exc
    if (
        contract.get("route_id") != route_id
        or contract.get("authority") != "advisory_only"
        or contract.get("automatic_patch_apply") is not False
        or contract.get("harness") != "codex"
        or contract.get("harness_binary") != "codex"
        or contract.get("paid_only") is True
     ):
        raise _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "unsafe_route",
            "revalidated route is outside the gateway safety contract",
        )
    argv_prefix = contract.get("argv_prefix")
    if (
        not isinstance(argv_prefix, list)
        or not argv_prefix
        or argv_prefix[0] != "codex"
        or any(not isinstance(item, str) or not item for item in argv_prefix)
    ):
        raise _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "unsafe_route",
            "revalidated route has an invalid execution prefix",
        )
    return contract


def build_codex_argv(contract: dict[str, Any], prompt: str, output_path: Path) -> list[str]:
    argv = list(contract["argv_prefix"])
    argv.extend(
        [
            "exec",
            "--sandbox",
            "read-only",
            "--skip-git-repo-check",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
        ]
    )
    for feature in _DISABLED_CODEX_FEATURES:
        argv.extend(["--disable", feature])
    argv.extend(
        [
            "--color",
            "never",
            "--output-last-message",
            str(output_path),
            prompt,
        ]
    )
    return argv


def _scrubbed_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in _PROVIDER_SECRET_ENV
    }
    environment["NO_COLOR"] = "1"
    return environment


def run_advisory(
    messages: list[dict[str, str]],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    runner: Any = subprocess.run,
) -> tuple[str, dict[str, Any]]:
    contract = select_advisory_contract()
    prompt = _conversation_prompt(messages)
    with tempfile.TemporaryDirectory(prefix="grabowski-juno-openai-") as directory:
        root = Path(directory)
        output_path = root / "answer.txt"
        argv = build_codex_argv(contract, prompt, output_path)
        try:
            completed = runner(
                argv,
                cwd=root,
                env=_scrubbed_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise _error(
                HTTPStatus.GATEWAY_TIMEOUT,
                "backend_timeout",
                "advisory backend timed out",
            ) from exc
        except OSError as exc:
            raise _error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "backend_unavailable",
                f"cannot start advisory backend: {type(exc).__name__}",
            ) from exc
        if completed.returncode != 0:
            raise _error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "backend_failed",
                f"advisory backend failed with exit status {completed.returncode}",
            )
        try:
            data = output_path.read_bytes()
        except OSError as exc:
            raise _error(
                HTTPStatus.BAD_GATEWAY,
                "backend_output_missing",
                "advisory backend did not produce a final response",
            ) from exc
        if not data or len(data) > MAX_OUTPUT_BYTES:
            raise _error(
                HTTPStatus.BAD_GATEWAY,
                "backend_output_invalid",
                "advisory backend output is empty or exceeds the limit",
            )
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise _error(
                HTTPStatus.BAD_GATEWAY,
                "backend_output_invalid",
                "advisory backend output is not UTF-8",
            ) from exc
        if not text:
            raise _error(
                HTTPStatus.BAD_GATEWAY,
                "backend_output_invalid",
                "advisory backend output is empty",
            )
    return text, {
        "route_id": contract["route_id"],
        "route_contract_sha256": contract["route_contract_sha256"],
        "catalog_sha256": contract["catalog_sha256"],
    }


def chat_completion_payload(text: str) -> dict[str, Any]:
    now = int(time.time())
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": now,
        "model": MODEL_ID,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
    }


def stream_chunks(text: str) -> list[bytes]:
    identifier = f"chatcmpl-{uuid.uuid4().hex}"
    now = int(time.time())
    first = {
        "id": identifier,
        "object": "chat.completion.chunk",
        "created": now,
        "model": MODEL_ID,
        "choices": [
            {
                "index": 0,
                "delta": {"role": "assistant", "content": text},
                "finish_reason": None,
            }
        ],
    }
    final = {
        "id": identifier,
        "object": "chat.completion.chunk",
        "created": now,
        "model": MODEL_ID,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    }
    return [
        b"data: " + json.dumps(first, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n\n",
        b"data: " + json.dumps(final, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n\n",
        b"data: [DONE]\n\n",
    ]


class GatewayRequestHandler(BaseHTTPRequestHandler):
    server_version = "grabowski-juno-openai-gateway/1"
    sys_version = ""

    @property
    def gateway_token(self) -> str:
        return self.server.gateway_token  # type: ignore[attr-defined]

    @property
    def backend_timeout_seconds(self) -> int:
        return self.server.backend_timeout_seconds  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, error: GatewayError) -> None:
        self._send_json(
            error.status,
            {
                "error": {
                    "message": error.message,
                    "type": "invalid_request_error"
                    if error.status < 500
                    else "server_error",
                    "code": error.code,
                }
            },
        )

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization")
        if not isinstance(value, str) or not value.startswith("Bearer "):
            return False
        candidate = value[7:]
        return hmac.compare_digest(candidate, self.gateway_token)

    def _require_authorized(self) -> bool:
        if self._authorized():
            return True
        self._send_error(
            _error(HTTPStatus.UNAUTHORIZED, "invalid_api_key", "invalid bearer token")
        )
        return False

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(
                HTTPStatus.OK,
                {"status": "ok", "service": "grabowski-juno-openai-gateway"},
            )
            return
        if self.path == "/v1/models":
            if not self._require_authorized():
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "object": "list",
                    "data": [
                        {
                            "id": MODEL_ID,
                            "object": "model",
                            "created": 0,
                            "owned_by": "grabowski",
                        }
                    ],
                },
            )
            return
        self._send_error(_error(HTTPStatus.NOT_FOUND, "not_found", "not found"))

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self._send_error(_error(HTTPStatus.NOT_FOUND, "not_found", "not found"))
            return
        if not self._require_authorized():
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            self._send_error(
                _error(HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length is required")
            )
            return
        if length > MAX_BODY_BYTES:
            self._send_error(
                _error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request_too_large", "request body exceeds the limit")
            )
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._send_error(
                _error(HTTPStatus.BAD_REQUEST, "invalid_request", "request body ended early")
            )
            return
        try:
            payload = json.loads(body.decode("utf-8"))
            messages, stream = validate_chat_request(payload)
        except UnicodeDecodeError:
            self._send_error(
                _error(HTTPStatus.BAD_REQUEST, "invalid_json", "request body must be UTF-8 JSON")
            )
            return
        except json.JSONDecodeError:
            self._send_error(
                _error(HTTPStatus.BAD_REQUEST, "invalid_json", "request body must be valid JSON")
            )
            return
        except GatewayError as exc:
            self._send_error(exc)
            return
        if not _REQUEST_SEMAPHORE.acquire(blocking=False):
            self._send_error(
                _error(HTTPStatus.TOO_MANY_REQUESTS, "busy", "gateway already has an active request")
            )
            return
        try:
            text, route_evidence = run_advisory(
                messages,
                timeout_seconds=self.backend_timeout_seconds,
            )
            print(
                json.dumps(
                    {
                        "event": "completion",
                        "route_id": route_evidence["route_id"],
                        "route_contract_sha256": route_evidence["route_contract_sha256"],
                        "catalog_sha256": route_evidence["catalog_sha256"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )
        except GatewayError as exc:
            self._send_error(exc)
            return
        finally:
            _REQUEST_SEMAPHORE.release()
        if not stream:
            self._send_json(HTTPStatus.OK, chat_completion_payload(text))
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        for chunk in stream_chunks(text):
            self.wfile.write(chunk)
            self.wfile.flush()


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        gateway_token: str,
        backend_timeout_seconds: int,
    ) -> None:
        super().__init__(address, handler)
        self.gateway_token = gateway_token
        self.backend_timeout_seconds = backend_timeout_seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Loopback-only OpenAI-compatible Juno gateway")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token-file", type=Path, default=DEFAULT_TOKEN_PATH)
    parser.add_argument("--backend-timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("gateway refuses non-loopback bind addresses")
    if not 1024 <= args.port <= 65535:
        raise SystemExit("port must be between 1024 and 65535")
    if not 10 <= args.backend_timeout_seconds <= 300:
        raise SystemExit("backend timeout must be between 10 and 300 seconds")
    token = load_bearer_token(args.token_file.expanduser())
    server = GatewayServer(
        (args.host, args.port),
        GatewayRequestHandler,
        gateway_token=token,
        backend_timeout_seconds=args.backend_timeout_seconds,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
