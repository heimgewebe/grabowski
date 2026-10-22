"""Fail-closed, non-inferencing Codex review admission for the dedicated auth profile.

Only metadata RPCs are sent. A successful preflight proves that a ChatGPT
credential was accepted by a remote usage endpoint and that the exact model is
advertised; it does NOT prove a later model turn can run or grant review PASS.
No provider output, account ID, token or raw error is retained.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import tempfile
import time
from typing import Any


MAX_OUTPUT_BYTES = 131072
MAX_MESSAGES = 64
MAX_MODEL_PAGES = 5
PREFLIGHT_SECONDS = 20
ALLOWED_NOTIFICATIONS = frozenset({"account/updated", "remoteControl/status/changed"})


class CodexPreflightDenied(RuntimeError):
    """A bounded, secret-free failure class; never display provider output."""

    def __init__(self, code: str):
        if re.fullmatch(r"[a-z_]{2,64}", code) is None:
            code = "invalid_preflight_error"
        self.code = code
        super().__init__(code)


def _exact_reviewer_model(command: list[str], route: dict[str, Any]) -> tuple[str, str]:
    if not command or Path(command[0]).name != "codex":
        raise CodexPreflightDenied("not_codex")
    if route.get("provider_family") != "openai":
        raise CodexPreflightDenied("provider_mismatch")
    model_flags = [index for index, arg in enumerate(command) if arg == "--model"]
    if len(model_flags) != 1 or model_flags[0] + 1 >= len(command):
        raise CodexPreflightDenied("model_identity_unavailable")
    model = command[model_flags[0] + 1]
    if model != route.get("model") or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,99}", model) is None:
        raise CodexPreflightDenied("model_identity_mismatch")
    efforts = []
    for index, arg in enumerate(command[:-1]):
        if arg == "-c" and index + 1 < len(command):
            candidate = command[index + 1]
            if candidate.startswith("model_reasoning_effort="):
                efforts.append(candidate.split("=", 1)[1].strip('"'))
    if len(efforts) != 1 or efforts[0] not in {"low", "medium", "high", "xhigh"}:
        raise CodexPreflightDenied("effort_identity_unavailable")
    return model, efforts[0]


class _Rpc:
    def __init__(self, process: subprocess.Popen[bytes], deadline: float):
        self.process = process
        self.deadline = deadline
        self.pending = b""
        self.total = 0
        self.count = 0

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": {}})

    def _send(self, message: dict[str, Any]) -> None:
        payload = (json.dumps(message, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        if len(payload) > 4096 or time.monotonic() >= self.deadline:
            raise CodexPreflightDenied("timeout")
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(payload)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise CodexPreflightDenied("transport_closed") from None

    def call(self, request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method not in {"initialize", "account/read", "account/rateLimits/read", "model/list"}:
            raise CodexPreflightDenied("unapproved_method")
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            if b"\n" in self.pending:
                raw, self.pending = self.pending.split(b"\n", 1)
                self.count += 1
                if self.count > MAX_MESSAGES or not raw or len(raw) > 65536:
                    raise CodexPreflightDenied("oversized_or_mixed_output")
                try:
                    item = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise CodexPreflightDenied("malformed_output") from None
                if not isinstance(item, dict) or item.get("jsonrpc", "2.0") != "2.0":
                    raise CodexPreflightDenied("malformed_output")
                if "method" in item:
                    notification = item["method"]
                    if "id" in item or not isinstance(notification, str) or notification not in ALLOWED_NOTIFICATIONS:
                        raise CodexPreflightDenied("unexpected_notification")
                    continue
                if item.get("id") != request_id or "error" in item or set(item) - {"jsonrpc", "id", "result"}:
                    raise CodexPreflightDenied("invalid_rpc_reply")
                result = item.get("result")
                if not isinstance(result, dict):
                    raise CodexPreflightDenied("invalid_rpc_result")
                return result
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise CodexPreflightDenied("timeout")
            if self.process.poll() is not None:
                raise CodexPreflightDenied("transport_closed")
            try:
                assert self.process.stdout is not None
                readable, _, _ = select.select([self.process.stdout.fileno()], [], [], remaining)
                if not readable:
                    raise CodexPreflightDenied("timeout")
                data = os.read(self.process.stdout.fileno(), 16384)
            except (OSError, ValueError):
                raise CodexPreflightDenied("transport_error") from None
            if not data:
                raise CodexPreflightDenied("transport_closed")
            self.total += len(data)
            if self.total > MAX_OUTPUT_BYTES:
                raise CodexPreflightDenied("oversized_or_mixed_output")
            self.pending += data


def _check_protocol(argv: list[str], *, model: str, effort: str, deadline_seconds: int = PREFLIGHT_SECONDS) -> dict[str, Any]:
    """Only supported non-model metadata RPCs, with bounded owner process lifetime."""
    if not argv or deadline_seconds < 1 or deadline_seconds > 30:
        raise CodexPreflightDenied("invalid_launch")
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
        )
    except (OSError, ValueError):
        raise CodexPreflightDenied("launch_failed") from None
    try:
        rpc = _Rpc(process, time.monotonic() + deadline_seconds)
        init = rpc.call(1, "initialize", {
            "clientInfo": {"name": "grabowski-review-preflight", "title": "Grabowski review preflight", "version": "1"},
            "capabilities": {"experimentalApi": False},
        })
        if not isinstance(init.get("userAgent"), str) and not isinstance(init.get("serverInfo"), dict):
            raise CodexPreflightDenied("handshake_identity_missing")
        rpc.notify("initialized")
        account = rpc.call(2, "account/read", {"refreshToken": True})
        if not isinstance(account.get("account"), dict) or account["account"].get("type") != "chatgpt":
            raise CodexPreflightDenied("chatgpt_auth_unavailable")
        if account.get("requiresOpenaiAuth") is not True:
            raise CodexPreflightDenied("provider_auth_mismatch")
        routing = account.get("workspaceRouting")
        if not isinstance(routing, dict) or not isinstance(routing.get("chatgptAccountId"), str) or not routing["chatgptAccountId"]:
            raise CodexPreflightDenied("workspace_identity_unavailable")
        limits = rpc.call(3, "account/rateLimits/read", {
            "supportsLunaReserve": False, "excludeResetCreditDetails": True,
        })
        if limits.get("ordinaryUsageAllowed") is not True or not isinstance(limits.get("rateLimits"), dict):
            raise CodexPreflightDenied("remote_usage_unavailable")
        if limits.get("accountId") != routing["chatgptAccountId"]:
            raise CodexPreflightDenied("credential_workspace_mismatch")
        cursor = None
        matched = False
        for page in range(MAX_MODEL_PAGES):
            params: dict[str, Any] = {"includeHidden": False, "limit": 100}
            if cursor is not None:
                params["cursor"] = cursor
            listed = rpc.call(4 + page, "model/list", params)
            data = listed.get("data")
            if not isinstance(data, list) or len(data) > 100:
                raise CodexPreflightDenied("invalid_model_catalog")
            for row in data:
                if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not isinstance(row.get("model"), str):
                    raise CodexPreflightDenied("invalid_model_catalog")
                if row["id"] != model and row["model"] != model:
                    continue
                if matched or row["id"] != model or row["model"] != model or row.get("hidden") is not False:
                    raise CodexPreflightDenied("model_identity_mismatch")
                efforts = row.get("supportedReasoningEfforts")
                if not isinstance(efforts, list) or not any(
                    isinstance(x, dict) and x.get("reasoningEffort") == effort for x in efforts
                ):
                    raise CodexPreflightDenied("model_effort_unavailable")
                matched = True
            next_cursor = listed.get("nextCursor")
            if next_cursor is None:
                break
            if not isinstance(next_cursor, str) or not next_cursor or page + 1 >= MAX_MODEL_PAGES:
                raise CodexPreflightDenied("model_catalog_incomplete")
            cursor = next_cursor
        if not matched:
            raise CodexPreflightDenied("exact_model_unavailable")
        # A terminal metadata reply must not conceal buffered model turns,
        # malformed extensions or unsolicited semantic notifications.
        if rpc.pending:
            raise CodexPreflightDenied("unexpected_trailing_output")
        if process.stdout is not None and select.select([process.stdout.fileno()], [], [], 0)[0]:
            raise CodexPreflightDenied("unexpected_trailing_output")
        return {
            "kind": "grabowski.codex_preinference_preflight",
            "schema_version": 1,
            "status": "metadata_accepted",
            "model": model,
            "effort": effort,
            "auth_source": "dedicated_codex_sandbox",
            "remote_usage_authenticated": True,
            "model_catalog_observed": True,
            "no_thread_request_sent": True,
            "does_not_establish": [
                "later_remote_model_inference_success",
                "freshness_of_cached_model_catalog",
                "review_pass",
                "absence_of_historical_inference",
            ],
        }
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for pipe in (process.stdin, process.stdout):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass


def require_codex_review_preflight(command: list[str], route: dict[str, Any]) -> dict[str, Any] | None:
    """Invoke identical durable reviewer auth in a minimal isolated preflight sandbox."""
    if not command or Path(command[0]).name != "codex":
        return None
    model, effort = _exact_reviewer_model(command, route)
    try:
        from grabowski_agent_sandbox import (
            prepare_external_agent_command, minimal_sandbox_argv, runtime_sandbox_argv,
        )
        # The same dedicated, owner-private auth file and serialized lock as
        # the real Codex reviewer; never fall back to the host ~/.codex.
        prepared = prepare_external_agent_command(["codex", "--model", model, "app-server"])
        with tempfile.TemporaryDirectory(prefix="grabowski-codex-preflight-") as directory:
            argv = runtime_sandbox_argv(minimal_sandbox_argv(
                workspace=Path(directory),
                command=list(prepared.command),
                workspace_writable=False,
                extra_read_only=prepared.extra_read_only,
                extra_read_write=prepared.extra_read_write,
                extra_directories=prepared.extra_directories,
            ))
            return _check_protocol(argv, model=model, effort=effort)
    except CodexPreflightDenied:
        raise
    except Exception:
        # All ordinary provider/toolchain failures must yield an auditable
        # denial before durable DecisionReview job registration.
        raise CodexPreflightDenied("sandbox_unavailable") from None
