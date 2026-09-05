from __future__ import annotations

from collections.abc import Mapping
import argparse
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
from typing import Any, BinaryIO

from grabowski_operator_fence import (
    OperatorFenceDenied,
    OperatorFenceError,
    OperatorFenceStore,
)


SCHEMA_VERSION = 1
REQUEST_KIND = "grabowski.operator_fence_rpc_request"
RESPONSE_KIND = "grabowski.operator_fence_rpc_response"
MAX_REQUEST_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 10
SERVER_REQUEST_TIMEOUT_SECONDS = 5
REMOTE_COMMAND = "operator-fence-rpc-v1"
IDENTITY_RE = re.compile(r"[A-Za-z0-9._:@/-]+\Z")
ALLOWED_PEERS = frozenset({"grabowski", "der-kleine-maulwurf"})
ALLOWED_OPERATIONS = frozenset(
    {"status", "acquire", "renew", "begin", "settle", "reconcile", "release"}
)

_REQUIRED_ARGUMENTS: dict[str, frozenset[str]] = {
    "status": frozenset(),
    "acquire": frozenset({"session_id", "reason", "lease_seconds"}),
    "renew": frozenset({"session_id", "generation", "lease_seconds"}),
    "begin": frozenset(
        {"session_id", "generation", "operation_id", "operation_name", "intent_sha256"}
    ),
    "settle": frozenset(
        {
            "session_id",
            "generation",
            "operation_id",
            "operation_name",
            "intent_sha256",
            "outcome",
            "evidence_sha256",
        }
    ),
    "reconcile": frozenset(
        {
            "generation",
            "operation_id",
            "operation_name",
            "intent_sha256",
            "outcome",
            "evidence_sha256",
        }
    ),
    "release": frozenset({"session_id", "generation"}),
}
_OPTIONAL_ARGUMENTS = frozenset({"expected_instance_id", "minimum_generation_seen"})


class OperatorFenceRpcError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _bounded_identity(value: Any, field: str, *, maximum: int = 160) -> str:
    if not isinstance(value, str):
        raise OperatorFenceRpcError(f"invalid_{field}")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized.encode("utf-8")) > maximum
        or IDENTITY_RE.fullmatch(normalized) is None
    ):
        raise OperatorFenceRpcError(f"invalid_{field}")
    return normalized


def _peer_id(value: Any) -> str:
    peer = _bounded_identity(value, "peer_id")
    if peer not in ALLOWED_PEERS:
        raise OperatorFenceRpcError("unsupported_peer")
    return peer


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _validate_state_path(value: str | os.PathLike[str]) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise OperatorFenceRpcError("state_path_not_absolute")
    if path.name in {"", ".", ".."}:
        raise OperatorFenceRpcError("invalid_state_path")
    return path


def _validate_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "request_id",
        "operation",
        "arguments",
    }:
        raise OperatorFenceRpcError("invalid_request_shape")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != REQUEST_KIND:
        raise OperatorFenceRpcError("unsupported_request_contract")
    request_id = _bounded_identity(value.get("request_id"), "request_id")
    operation = value.get("operation")
    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise OperatorFenceRpcError("unsupported_operation")
    arguments = value.get("arguments")
    if not isinstance(arguments, dict) or not all(
        isinstance(key, str) for key in arguments
    ):
        raise OperatorFenceRpcError("invalid_arguments")
    required = _REQUIRED_ARGUMENTS[operation]
    keys = frozenset(arguments)
    if "owner_id" in keys or "reconciler_id" in keys:
        raise OperatorFenceRpcError("caller_identity_argument_forbidden")
    if not required.issubset(keys) or not keys.issubset(required | _OPTIONAL_ARGUMENTS):
        raise OperatorFenceRpcError("invalid_argument_set")
    return {
        "request_id": request_id,
        "operation": operation,
        "arguments": dict(arguments),
    }


def _canonical_request(value: Any) -> dict[str, Any]:
    normalized = _validate_request(value)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": REQUEST_KIND,
        "request_id": normalized["request_id"],
        "operation": normalized["operation"],
        "arguments": normalized["arguments"],
    }


def _request_from_bytes(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_REQUEST_BYTES or b"\x00" in raw:
        raise OperatorFenceRpcError("invalid_request_bytes")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorFenceRpcError("invalid_request_json") from exc
    return _canonical_request(value)


def _read_request_frame(
    input_stream: BinaryIO, *, timeout_seconds: float = SERVER_REQUEST_TIMEOUT_SECONDS
) -> bytes:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
        or timeout_seconds > 60
    ):
        raise OperatorFenceRpcError("invalid_request_timeout")
    try:
        descriptor = input_stream.fileno()
    except (AttributeError, OSError):
        raw = input_stream.read(MAX_REQUEST_BYTES + 1)
        newline = raw.find(b"\n")
        if newline < 0:
            if len(raw) > MAX_REQUEST_BYTES:
                raise OperatorFenceRpcError("invalid_request_bytes")
            raise OperatorFenceRpcError("request_frame_incomplete")
        frame = raw[: newline + 1]
        if len(frame) > MAX_REQUEST_BYTES or raw[newline + 1 :].strip():
            raise OperatorFenceRpcError("invalid_request_bytes")
        return frame

    deadline = time.monotonic() + float(timeout_seconds)
    buffered = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OperatorFenceRpcError("request_timeout")
        try:
            readable, _, _ = select.select([descriptor], [], [], remaining)
        except (OSError, ValueError) as exc:
            raise OperatorFenceRpcError("request_read_failed") from exc
        if not readable:
            raise OperatorFenceRpcError("request_timeout")
        try:
            chunk = os.read(descriptor, min(4096, MAX_REQUEST_BYTES + 1 - len(buffered)))
        except OSError as exc:
            raise OperatorFenceRpcError("request_read_failed") from exc
        if not chunk:
            raise OperatorFenceRpcError("request_frame_incomplete")
        newline = chunk.find(b"\n")
        if newline >= 0:
            buffered.extend(chunk[: newline + 1])
            if len(buffered) > MAX_REQUEST_BYTES or chunk[newline + 1 :].strip():
                raise OperatorFenceRpcError("invalid_request_bytes")
            return bytes(buffered)
        buffered.extend(chunk)
        if len(buffered) >= MAX_REQUEST_BYTES:
            raise OperatorFenceRpcError("invalid_request_bytes")


def _success_response(*, request_id: str, peer_id: str, result: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESPONSE_KIND,
        "request_id": request_id,
        "peer_id": peer_id,
        "ok": True,
        "result": result,
        "error": None,
    }


def _error_response(
    *, request_id: str, peer_id: str, error_kind: str, code: str
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESPONSE_KIND,
        "request_id": request_id,
        "peer_id": peer_id,
        "ok": False,
        "result": None,
        "error": {"kind": error_kind, "code": code},
    }


def dispatch_request(
    store: OperatorFenceStore,
    *,
    peer_id: str,
    request: Mapping[str, Any],
) -> dict[str, Any]:
    peer = _peer_id(peer_id)
    normalized = _validate_request(dict(request))
    request_id = normalized["request_id"]
    operation = normalized["operation"]
    arguments = normalized["arguments"]
    try:
        if operation == "status":
            result = store.status()
        elif operation == "acquire":
            result = store.acquire(owner_id=peer, **arguments)
        elif operation == "renew":
            result = store.renew(owner_id=peer, **arguments)
        elif operation == "begin":
            result = store.begin_effect(owner_id=peer, **arguments)
        elif operation == "settle":
            result = store.settle_effect(owner_id=peer, **arguments)
        elif operation == "reconcile":
            result = store.reconcile_effect(reconciler_id=peer, **arguments)
        elif operation == "release":
            result = store.release(owner_id=peer, **arguments)
        else:  # pragma: no cover - validated above
            raise OperatorFenceRpcError("unsupported_operation")
    except OperatorFenceDenied as exc:
        return _error_response(
            request_id=request_id,
            peer_id=peer,
            error_kind="denied",
            code=exc.code,
        )
    except (OperatorFenceError, PermissionError) as exc:
        return _error_response(
            request_id=request_id,
            peer_id=peer,
            error_kind="store_error",
            code=type(exc).__name__,
        )
    except (TypeError, ValueError):
        return _error_response(
            request_id=request_id,
            peer_id=peer,
            error_kind="invalid_arguments",
            code="invalid_operation_arguments",
        )
    return _success_response(request_id=request_id, peer_id=peer, result=result)


def serve_once(
    *,
    state_path: str | os.PathLike[str],
    peer_id: str,
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    required_original_command: str | None = REMOTE_COMMAND,
    environment: Mapping[str, str] | None = None,
) -> int:
    peer = _peer_id(peer_id)
    env = os.environ if environment is None else environment
    if required_original_command is not None:
        if env.get("SSH_ORIGINAL_COMMAND") != required_original_command:
            response = _error_response(
                request_id="transport",
                peer_id=peer,
                error_kind="transport",
                code="unexpected_original_command",
            )
            output_stream.write(_canonical_json_bytes(response) + b"\n")
            output_stream.flush()
            return 0
    request_id = "invalid"
    try:
        raw = _read_request_frame(input_stream)
        request = _request_from_bytes(raw)
        request_id = request["request_id"]
        store = OperatorFenceStore(_validate_state_path(state_path))
        response = dispatch_request(store, peer_id=peer, request=request)
    except OperatorFenceRpcError as exc:
        response = _error_response(
            request_id=request_id,
            peer_id=peer,
            error_kind="protocol",
            code=exc.code,
        )
    except (OperatorFenceError, PermissionError) as exc:
        response = _error_response(
            request_id=request_id,
            peer_id=peer,
            error_kind="store_error",
            code=type(exc).__name__,
        )
    encoded = _canonical_json_bytes(response) + b"\n"
    if len(encoded) > MAX_RESPONSE_BYTES:
        encoded = _canonical_json_bytes(
            _error_response(
                request_id=request_id,
                peer_id=peer,
                error_kind="protocol",
                code="response_too_large",
            )
        ) + b"\n"
    output_stream.write(encoded)
    output_stream.flush()
    return 0


def _validate_private_regular(
    path_value: str | os.PathLike[str], *, error_code: str, exact_mode: int | None = None
) -> Path:
    path = Path(path_value).expanduser()
    if not path.is_absolute() or path.is_symlink():
        raise OperatorFenceRpcError(error_code)
    try:
        info = path.stat()
    except OSError as exc:
        raise OperatorFenceRpcError(error_code) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or (exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode)
    ):
        raise OperatorFenceRpcError(error_code)
    return path


def _validate_known_hosts(path_value: str | os.PathLike[str]) -> Path:
    return _validate_private_regular(path_value, error_code="unsafe_known_hosts")


def _validate_identity_file(path_value: str | os.PathLike[str]) -> Path:
    return _validate_private_regular(
        path_value, error_code="unsafe_identity_file", exact_mode=0o600
    )


def _validate_ssh_executable(path_value: str | os.PathLike[str]) -> Path:
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink():
        raise OperatorFenceRpcError("unsafe_ssh_executable")
    try:
        info = path.stat()
    except OSError as exc:
        raise OperatorFenceRpcError("unsafe_ssh_executable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink < 1
        or info.st_mode & 0o022
        or not info.st_mode & 0o111
    ):
        raise OperatorFenceRpcError("unsafe_ssh_executable")
    return path


class OperatorFenceSshClient:
    def __init__(
        self,
        *,
        host: str,
        remote_user: str,
        expected_peer_id: str,
        known_hosts_path: str | os.PathLike[str],
        identity_file: str | os.PathLike[str],
        host_key_alias: str | None = None,
        ssh_executable: str = "/usr/bin/ssh",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.host = _bounded_identity(host, "host", maximum=255)
        if self.host.startswith("-"):
            raise OperatorFenceRpcError("invalid_host")
        self.remote_user = _bounded_identity(remote_user, "remote_user", maximum=128)
        if self.remote_user.startswith("-"):
            raise OperatorFenceRpcError("invalid_remote_user")
        self.expected_peer_id = _peer_id(expected_peer_id)
        self.known_hosts_path = _validate_known_hosts(known_hosts_path)
        self.identity_file = _validate_identity_file(identity_file)
        self.host_key_alias = _bounded_identity(
            host_key_alias or self.host, "host_key_alias", maximum=255
        )
        self.ssh_executable = str(_validate_ssh_executable(ssh_executable))
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise OperatorFenceRpcError("invalid_timeout")
        if timeout_seconds < 1 or timeout_seconds > 60:
            raise OperatorFenceRpcError("invalid_timeout")
        self.timeout_seconds = timeout_seconds

    def ssh_argv(self) -> list[str]:
        return [
            self.ssh_executable,
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ControlPersist=no",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "GSSAPIAuthentication=no",
            "-o",
            "HostbasedAuthentication=no",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"ConnectTimeout={self.timeout_seconds}",
            "-o",
            f"UserKnownHostsFile={self.known_hosts_path}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "VerifyHostKeyDNS=no",
            "-o",
            f"HostKeyAlias={self.host_key_alias}",
            "-i",
            str(self.identity_file),
            "-l",
            self.remote_user,
            self.host,
            REMOTE_COMMAND,
        ]

    def call(self, request: Mapping[str, Any]) -> dict[str, Any]:
        canonical = _canonical_request(dict(request))
        payload = _canonical_json_bytes(canonical) + b"\n"
        try:
            completed = subprocess.run(
                self.ssh_argv(),
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OperatorFenceRpcError("ssh_transport_failed") from exc
        if completed.returncode != 0:
            raise OperatorFenceRpcError("ssh_transport_failed")
        if (
            not completed.stdout
            or len(completed.stdout) > MAX_RESPONSE_BYTES
            or b"\x00" in completed.stdout
        ):
            raise OperatorFenceRpcError("invalid_response_bytes")
        try:
            response = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OperatorFenceRpcError("invalid_response_json") from exc
        if not isinstance(response, dict) or set(response) != {
            "schema_version",
            "kind",
            "request_id",
            "peer_id",
            "ok",
            "result",
            "error",
        }:
            raise OperatorFenceRpcError("invalid_response_shape")
        if (
            response.get("schema_version") != SCHEMA_VERSION
            or response.get("kind") != RESPONSE_KIND
            or response.get("request_id") != canonical["request_id"]
            or response.get("peer_id") != self.expected_peer_id
            or not isinstance(response.get("ok"), bool)
        ):
            raise OperatorFenceRpcError("response_binding_mismatch")
        if response["ok"]:
            if response["error"] is not None:
                raise OperatorFenceRpcError("invalid_response_shape")
        else:
            error = response.get("error")
            if (
                response["result"] is not None
                or not isinstance(error, dict)
                or set(error) != {"kind", "code"}
                or not all(isinstance(error.get(key), str) for key in ("kind", "code"))
            ):
                raise OperatorFenceRpcError("invalid_response_shape")
        return response


def request_document(
    *, request_id: str, operation: str, arguments: Mapping[str, Any]
) -> dict[str, Any]:
    return _canonical_request(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": REQUEST_KIND,
            "request_id": request_id,
            "operation": operation,
            "arguments": dict(arguments),
        }
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="grabowski-operator-fence-rpc")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--state-path", required=True)
    serve.add_argument("--peer-id", required=True, choices=sorted(ALLOWED_PEERS))
    serve.add_argument("--required-original-command", default=REMOTE_COMMAND)
    local = subparsers.add_parser("local")
    local.add_argument("--state-path", required=True)
    local.add_argument("--peer-id", required=True, choices=sorted(ALLOWED_PEERS))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "serve":
        return serve_once(
            state_path=args.state_path,
            peer_id=args.peer_id,
            input_stream=sys.stdin.buffer,
            output_stream=sys.stdout.buffer,
            required_original_command=args.required_original_command,
        )
    if args.command == "local":
        return serve_once(
            state_path=args.state_path,
            peer_id=args.peer_id,
            input_stream=sys.stdin.buffer,
            output_stream=sys.stdout.buffer,
            required_original_command=None,
            environment={},
        )
    raise SystemExit(2)


__all__ = [
    "ALLOWED_OPERATIONS",
    "ALLOWED_PEERS",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "OperatorFenceRpcError",
    "OperatorFenceSshClient",
    "REMOTE_COMMAND",
    "REQUEST_KIND",
    "RESPONSE_KIND",
    "SCHEMA_VERSION",
    "SERVER_REQUEST_TIMEOUT_SECONDS",
    "dispatch_request",
    "main",
    "request_document",
    "serve_once",
]


if __name__ == "__main__":
    raise SystemExit(main())
