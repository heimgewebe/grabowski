from __future__ import annotations

from http import HTTPStatus
import json
import os
from pathlib import Path
import subprocess
import threading
import urllib.error
import urllib.request

import pytest

import grabowski_juno_openai_gateway as gateway


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


def test_route_selection_is_codex_nonpaid_and_revalidated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gateway.coding_agent_router,
        "select_contrast_routes",
        lambda *args, **kwargs: {
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
     )
    seen = {}

    def contract(route_id, *, paid_execution_authorized):
        seen["route_id"] = route_id
        seen["paid"] = paid_execution_authorized
        return _contract()

    monkeypatch.setattr(
        gateway.coding_agent_router,
        "advisory_route_execution_contract",
        contract,
    )
    result = gateway.select_advisory_contract()
    assert result["route_id"] == "codex-spark-low"
    assert seen == {"route_id": "codex-spark-low", "paid": False}


@pytest.mark.parametrize(
    "route",
    [
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
    ],
)
def test_route_selection_rejects_paid_openrouter_or_wrong_harness(
    monkeypatch: pytest.MonkeyPatch, route: dict[str, object]
) -> None:
    monkeypatch.setattr(
        gateway.coding_agent_router,
        "select_contrast_routes",
        lambda *args, **kwargs: {"status": "recommended", "routes": [route]},
    )
    with pytest.raises(gateway.GatewayError) as exc:
        gateway.select_advisory_contract()
    assert exc.value.code == "unsafe_route"


def test_route_selection_fails_closed_when_no_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gateway.coding_agent_router,
        "select_contrast_routes",
        lambda *args, **kwargs: {"status": "no-route", "routes": []},
     )
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
    assert {"shell_tool", "unified_exec", "hooks", "apps", "plugins"} <= disabled


def test_provider_secret_environment_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret2")
    monkeypatch.setenv("PATH", "/test")
    environment = gateway._scrubbed_environment()
    assert "OPENAI_API_KEY" not in environment
    assert "OPENROUTER_API_KEY" not in environment
    assert environment["PATH"] == "/test"


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
