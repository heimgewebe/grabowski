from __future__ import annotations

from http import HTTPStatus
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
import urllib.error
import urllib.request

try:
    import pytest
except ModuleNotFoundError:  # unittest discovery environment intentionally omits pytest
    class _PytestFallback:
        @staticmethod
        def fixture(function):
            return function

    pytest = _PytestFallback()  # type: ignore[assignment]

import grabowski_juno_openai_gateway as gateway


_INSTALLER_PATH = (
    Path(__file__).resolve().parents[1] / "tools" / "install_juno_openai_gateway.py"
)
_INSTALLER_SPEC = importlib.util.spec_from_file_location(
    "install_juno_openai_gateway_tested", _INSTALLER_PATH
)
assert _INSTALLER_SPEC is not None and _INSTALLER_SPEC.loader is not None
installer = importlib.util.module_from_spec(_INSTALLER_SPEC)
_INSTALLER_SPEC.loader.exec_module(installer)


def _contract() -> dict[str, object]:
    return {
        "route_id": "codex-spark-low",
        "authority": "advisory_only",
        "automatic_patch_apply": False,
        "harness": "codex",
        "harness_binary": "codex",
        "paid_only": False,
        "argv_prefix": ["codex", "--model", "gpt-test"],
        "route_contract_sha256": "a" * 64,
        "catalog_sha256": "b" * 64,
    }


def _request_payload(**extra):
    payload = {
        "model": gateway.MODEL_ID,
        "messages": [{"role": "user", "content": "hello"}],
    }
    payload.update(extra)
    return payload


def test_token_loader_accepts_private_regular_file(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text("x" * 48, encoding="ascii")
    path.chmod(0o600)
    assert gateway.load_bearer_token(path) == "x" * 48


def test_token_loader_rejects_broad_permissions(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text("x" * 48, encoding="ascii")
    path.chmod(0o644)
    with pytest.raises(RuntimeError, match="permissions"):
        gateway.load_bearer_token(path)


def test_token_loader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.write_text("x" * 48, encoding="ascii")
    target.chmod(0o600)
    link = tmp_path / "token"
    link.symlink_to(target)
    with pytest.raises(RuntimeError, match="cannot open"):
        gateway.load_bearer_token(link)


def test_request_validation_accepts_text_and_stream() -> None:
    messages, stream = gateway.validate_chat_request(
        _request_payload(
            stream=True,
            temperature=0.2,
            messages=[
                {"role": "system", "content": "brief"},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "hello"},
                        {"type": "input_text", "text": "world"},
                    ],
                },
            ],
        )
    )
    assert stream is True
    assert messages[-1]["content"] == "hello\nworld"


def test_request_validation_rejects_tools_and_wrong_model() -> None:
    with pytest.raises(gateway.GatewayError) as tools:
        gateway.validate_chat_request(_request_payload(tools=[]))
    assert tools.value.status == HTTPStatus.BAD_REQUEST
    with pytest.raises(gateway.GatewayError) as model:
        gateway.validate_chat_request({**_request_payload(), "model": "other"})
    assert model.value.code == "model_not_found"


def test_request_validation_enforces_message_limit() -> None:
    oversized = "x" * (gateway.MAX_MESSAGE_BYTES + 1)
    with pytest.raises(gateway.GatewayError) as exc:
        gateway.validate_chat_request(
            {
                "model": gateway.MODEL_ID,
                "messages": [{"role": "user", "content": oversized}],
            }
        )
    assert exc.value.status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE


def test_route_selection_is_codex_nonpaid_and_revalidated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = {}

    def contract(route_id, *, paid_execution_authorized):
        seen["route_id"] = route_id
        seen["paid"] = paid_execution_authorized
        return _contract()

    router = SimpleNamespace(
        select_contrast_routes=lambda *args, **kwargs: {
            "status": "recommended",
            "routes": [
                {
                    "route": "codex-spark-low",
                    "harness": "codex",
                    "provider_family": "openai",
                    "paid_only": False,
                }
            ],
        },
        advisory_route_execution_contract=contract,
    )
    monkeypatch.setattr(gateway, "_router_module", lambda: router)
    result = gateway.select_advisory_contract()
    assert result["route_id"] == "codex-spark-low"
    assert seen == {"route_id": "codex-spark-low", "paid": False}


def test_route_selection_rejects_paid_openrouter_or_wrong_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    routes = (
        {
            "route": "paid",
            "harness": "codex",
            "provider_family": "openai",
            "paid_only": True,
        },
        {
            "route": "opencode-openrouter-ox-alpha-free-preview",
            "harness": "codex",
            "provider_family": "openrouter",
            "paid_only": False,
        },
        {
            "route": "wrong-harness",
            "harness": "claude",
            "provider_family": "anthropic",
            "paid_only": False,
        },
    )
    for route in routes:
        router = SimpleNamespace(
            select_contrast_routes=lambda *args, _route=route, **kwargs: {
                "status": "recommended",
                "routes": [_route],
            }
        )
        monkeypatch.setattr(gateway, "_router_module", lambda _router=router: _router)
        with pytest.raises(gateway.GatewayError) as exc:
            gateway.select_advisory_contract()
        assert exc.value.code == "unsafe_route"


def test_route_selection_fails_closed_when_no_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    router = SimpleNamespace(
        select_contrast_routes=lambda *args, **kwargs: {
            "status": "no-route",
            "routes": [],
        }
    )
    monkeypatch.setattr(gateway, "_router_module", lambda: router)
    with pytest.raises(gateway.GatewayError) as exc:
        gateway.select_advisory_contract()
    assert exc.value.status == HTTPStatus.SERVICE_UNAVAILABLE


def test_codex_command_is_toolless_read_only_ephemeral(tmp_path: Path) -> None:
    argv = gateway.build_codex_argv(_contract(), tmp_path / "answer")
    assert argv[:3] == ["codex", "--model", "gpt-test"]
    assert "--sandbox" in argv
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert "--ephemeral" in argv
    assert "--skip-git-repo-check" in argv
    assert "--ignore-user-config" in argv
    assert "--ignore-rules" in argv
    assert argv[-1] == "-"
    assert "prompt" not in argv
    assert "workspace-write" not in argv
    assert "--dangerously-bypass-approvals-and-sandbox" not in argv
    disabled = {
        argv[index + 1]
        for index, item in enumerate(argv[:-1])
        if item == "--disable"
    }
    assert {
        "shell_tool",
        "unified_exec",
        "hooks",
        "apps",
        "plugins",
        "in_app_browser",
        "shell_snapshot",
        "skill_search",
        "tool_call_mcp_elicitation",
        "workspace_dependencies",
    } <= disabled


def test_backend_environment_uses_minimal_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret2")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret3")
    monkeypatch.setenv("UNRELATED_PRIVATE_VALUE", "secret4")
    monkeypatch.setenv("HOME", "/test-home")
    monkeypatch.setenv("PATH", "/test-bin")
    environment = gateway._scrubbed_environment()
    assert "OPENAI_API_KEY" not in environment
    assert "OPENROUTER_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "UNRELATED_PRIVATE_VALUE" not in environment
    assert environment["HOME"] == "/test-home"
    assert environment["PATH"] == "/test-bin"
    assert environment["NO_COLOR"] == "1"


def test_run_advisory_reads_only_final_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway, "select_advisory_contract", _contract)
    observed = {}

    def runner(argv, **kwargs):
        observed["argv"] = argv
        observed["cwd"] = kwargs["cwd"]
        observed["input"] = kwargs["input"]
        output = Path(argv[argv.index("--output-last-message") + 1])
        output.write_text("answer\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="event noise", stderr="")

    text, evidence = gateway.run_advisory(
        [{"role": "user", "content": "hello"}],
        runner=runner,
    )
    assert text == "answer"
    assert evidence["route_id"] == "codex-spark-low"
    assert observed["argv"][-1] == "-"
    assert "hello" in observed["input"]
    assert Path(observed["cwd"]).name.startswith("grabowski-juno-openai-")


def test_openai_payload_and_sse_shape() -> None:
    payload = gateway.chat_completion_payload("hello")
    assert payload["object"] == "chat.completion"
    assert payload["model"] == gateway.MODEL_ID
    assert payload["choices"][0]["message"] == {"role": "assistant", "content": "hello"}
    chunks = gateway.stream_chunks("hello")
    assert chunks[-1] == b"data: [DONE]\n\n"
    first = json.loads(chunks[0][6:].strip())
    assert first["object"] == "chat.completion.chunk"
    assert first["choices"][0]["delta"]["content"] == "hello"


@pytest.fixture
def live_server(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        gateway,
        "run_advisory",
        lambda messages, *, timeout_seconds: (
            "stub reply",
            {
                "route_id": "codex-spark-low",
                "route_contract_sha256": "a" * 64,
                "catalog_sha256": "b" * 64,
            },
        ),
    )
    server = gateway.GatewayServer(
        ("127.0.0.1", 0),
        gateway.GatewayRequestHandler,
        gateway_token="t" * 48,
        backend_timeout_seconds=10,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _urlopen(request: urllib.request.Request):
    return urllib.request.urlopen(request, timeout=3)


def test_http_auth_models_chat_and_stream(live_server: str) -> None:
    with pytest.raises(urllib.error.HTTPError) as unauthorized:
        _urlopen(urllib.request.Request(live_server + "/v1/models"))
    assert unauthorized.value.code == HTTPStatus.UNAUTHORIZED

    headers = {"Authorization": "Bearer " + "t" * 48}
    with _urlopen(
        urllib.request.Request(live_server + "/v1/models", headers=headers)
    ) as response:
        models = json.loads(response.read())
    assert models["data"][0]["id"] == gateway.MODEL_ID

    body = json.dumps(_request_payload()).encode()
    with _urlopen(
        urllib.request.Request(
            live_server + "/v1/chat/completions",
            data=body,
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
    ) as response:
        chat = json.loads(response.read())
    assert chat["choices"][0]["message"]["content"] == "stub reply"

    stream_body = json.dumps(_request_payload(stream=True)).encode()
    with _urlopen(
        urllib.request.Request(
            live_server + "/v1/chat/completions",
            data=stream_body,
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
    ) as response:
        streamed = response.read()
    assert b'"object":"chat.completion.chunk"' in streamed
    assert streamed.endswith(b"data: [DONE]\n\n")


def test_healthz_does_not_require_secret(live_server: str) -> None:
    with _urlopen(urllib.request.Request(live_server + "/healthz")) as response:
        payload = json.loads(response.read())
    assert payload == {
        "status": "ok",
        "service": "grabowski-juno-openai-gateway",
    }


def test_main_rejects_ipv6_and_hostname_loopback() -> None:
    for host in ("::1", "localhost"):
        with pytest.raises(SystemExit, match=r"127\.0\.0\.1"):
            gateway.main(["--host", host])


def test_installer_completion_smoke_posts_authenticated_chat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": installer.INSTALL_SMOKE_REPLY
                            }
                        }
                    ]
                }
            ).encode("utf-8")

    def fake_urlopen(request, timeout):
        observed["request"] = request
        observed["timeout"] = timeout
        return Response()

    monkeypatch.setattr(installer.urllib.request, "urlopen", fake_urlopen)
    token = "t" * 48
    installer._completion_smoke(token, timeout_seconds=7)
    request = observed["request"]
    assert isinstance(request, urllib.request.Request)
    assert request.full_url.endswith("/v1/chat/completions")
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer " + token
    payload = json.loads(request.data)
    assert payload["model"] == installer.MODEL_ID
    assert installer.INSTALL_SMOKE_REPLY in payload["messages"][0]["content"]
    assert observed["timeout"] == 7


def _configure_installer_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Path, Path, Path, Path, Path]:
    source = tmp_path / "source.py"
    template = tmp_path / "service.example"
    gateway_path = tmp_path / "installed" / "gateway.py"
    unit_path = tmp_path / "systemd" / installer.SERVICE_NAME
    token_path = tmp_path / "state" / "token"
    source.write_text("print('new gateway')\n", encoding="utf-8")
    template.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    monkeypatch.setattr(installer, "GATEWAY_SOURCE_PATH", source)
    monkeypatch.setattr(installer, "TEMPLATE_PATH", template)
    monkeypatch.setattr(installer, "GATEWAY_EXEC_PATH", gateway_path)
    monkeypatch.setattr(installer, "UNIT_PATH", unit_path)
    monkeypatch.setattr(installer, "TOKEN_PATH", token_path)
    return source, template, gateway_path, unit_path, token_path


def test_installer_restarts_after_replacing_active_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure_installer_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(
        installer, "_service_state", lambda: {"active": False, "enabled": False}
    )
    calls: list[tuple[str, ...]] = []

    def systemctl(*arguments: str):
        calls.append(arguments)
        stdout = "active\n" if arguments == ("is-active", installer.SERVICE_NAME) else ""
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(installer, "_systemctl", systemctl)
    monkeypatch.setattr(installer, "_wait_for_smoke", lambda _path: None)
    assert installer.main([]) == 0
    capsys.readouterr()
    assert ("enable", installer.SERVICE_NAME) in calls
    assert ("restart", installer.SERVICE_NAME) in calls
    assert calls.index(("restart", installer.SERVICE_NAME)) > calls.index(
        ("enable", installer.SERVICE_NAME)
    )


def test_installer_rolls_back_artifacts_and_service_state_after_smoke_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source, _template, gateway_path, unit_path, _token_path = (
        _configure_installer_paths(monkeypatch, tmp_path)
    )
    gateway_path.parent.mkdir(parents=True)
    unit_path.parent.mkdir(parents=True)
    gateway_path.write_text("old gateway\n", encoding="utf-8")
    gateway_path.chmod(0o700)
    unit_path.write_text("old unit\n", encoding="utf-8")
    unit_path.chmod(0o644)
    monkeypatch.setattr(
        installer, "_service_state", lambda: {"active": True, "enabled": True}
    )
    calls: list[tuple[str, ...]] = []

    def systemctl(*arguments: str):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout="active\n", stderr="")

    def systemctl_probe(*arguments: str):
        calls.append(("probe", *arguments))
        return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")

    monkeypatch.setattr(installer, "_systemctl", systemctl)
    monkeypatch.setattr(installer, "_systemctl_probe", systemctl_probe)

    def fail_smoke(_path: Path) -> None:
        raise RuntimeError("synthetic smoke failure")

    monkeypatch.setattr(installer, "_wait_for_smoke", fail_smoke)
    with pytest.raises(RuntimeError, match="synthetic smoke failure"):
        installer.main([])
    assert gateway_path.read_text(encoding="utf-8") == "old gateway\n"
    assert unit_path.read_text(encoding="utf-8") == "old unit\n"
    assert ("restart", installer.SERVICE_NAME) in calls
    assert ("probe", "stop", installer.SERVICE_NAME) in calls
    assert ("probe", "disable", installer.SERVICE_NAME) in calls


class JunoOpenAIGatewayUnittestSmoke(unittest.TestCase):
    def test_wrong_model_fails_closed(self) -> None:
        with self.assertRaises(gateway.GatewayError) as caught:
            gateway.validate_chat_request({**_request_payload(), "model": "other"})
        self.assertEqual(caught.exception.code, "model_not_found")

    def test_only_ipv4_loopback_is_accepted(self) -> None:
        for host in ("::1", "localhost", "0.0.0.0"):
            with self.subTest(host=host), self.assertRaises(SystemExit):
                gateway.main(["--host", host])

    def test_private_token_loader_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("x" * 48, encoding="ascii")
            path.chmod(0o600)
            self.assertEqual(gateway.load_bearer_token(path), "x" * 48)
