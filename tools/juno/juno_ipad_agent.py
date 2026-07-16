#!/usr/bin/env python3
"""Authenticated arbitrary-Python job runner for Juno on iPadOS.

The process intentionally grants remote execution with the permissions of the
Juno process. It does not and cannot grant iPadOS root access or access outside
Juno's sandbox and explicitly selected document-provider locations.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import hashlib
import hmac
import io
import ipaddress
import json
import os
import platform
import queue
import re
import secrets
import signal
import sys
import threading
import time
import tempfile
import traceback
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

SCHEMA_VERSION = 1
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8765
DEFAULT_PAIRING_PEER = "100.68.88.111"
PAIRING_SECRET_BYTES = 32
PAIRING_CONSENT_TTL_SECONDS = 600
PAIRING_CONSENT_MAX_ATTEMPTS = 5
PAIRING_CONSENT_RE = re.compile(r"^[0-9]{6}$")
MAX_BODY_BYTES = 512 * 1024
MAX_CODE_BYTES = 384 * 1024
MAX_OUTPUT_CHARS = 256 * 1024
MAX_RESULT_CHARS = 256 * 1024
MAX_METADATA_BYTES = 32 * 1024
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 300
AUTH_SKEW_SECONDS = 90
JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
TERMINAL_STATES = {
    "succeeded",
    "failed",
    "timed_out",
    "abandoned_after_restart",
}
TAILSCALE_IPV4 = ipaddress.ip_network("100.64.0.0/10")
TAILSCALE_IPV6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")


def client_address_allowed(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return address.is_loopback or address in TAILSCALE_IPV4 or address in TAILSCALE_IPV6


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_create_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)


def atomic_create_json(path: Path, value: Any) -> None:
    atomic_create_bytes(path, canonical_json_bytes(value) + b"\n")


def atomic_replace_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(value) + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def probe_writable_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    probe = path / f".grabowski-write-probe-{os.getpid()}-{threading.get_ident()}"
    fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(b"ok")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            probe.unlink()
    return path.resolve()


def directory_is_persistent(path: Path) -> bool:
    lowered = {part.lower() for part in path.parts}
    return "caches" not in lowered and "tmp" not in lowered


def default_state_root_candidates(script_path: Path) -> list[tuple[str, Path, bool]]:
    script_sibling = script_path.with_name("grabowski_workspace")
    candidates = [
        (
            "script_sibling",
            script_sibling,
            directory_is_persistent(script_sibling),
        ),
    ]
    with contextlib.suppress(OSError):
        candidates.append(
            (
                "application_support",
                Path.home()
                / "Library"
                / "Application Support"
                / "GrabowskiJunoAgent",
                True,
            )
        )
    with contextlib.suppress(OSError):
        working = Path.cwd() / "grabowski_workspace"
        candidates.append(
            ("working_directory", working, directory_is_persistent(working))
        )
    candidates.append(
        (
            "temporary_directory",
            Path(tempfile.gettempdir()) / "grabowski-juno-agent",
            False,
        )
    )
    unique: list[tuple[str, Path, bool]] = []
    seen: set[str] = set()
    for source, candidate, persistent in candidates:
        marker = os.path.abspath(os.fspath(candidate))
        if marker in seen:
            continue
        seen.add(marker)
        unique.append((source, candidate, persistent))
    return unique


def select_state_root(
    script_path: Path,
    explicit_root: Path | None,
) -> tuple[Path, str, bool, list[str]]:
    if explicit_root is not None:
        selected = probe_writable_directory(explicit_root.expanduser())
        return selected, "explicit", True, []
    failures: list[str] = []
    for source, candidate, persistent in default_state_root_candidates(script_path):
        try:
            selected = probe_writable_directory(candidate)
        except OSError as exc:
            failures.append(f"{source}:{type(exc).__name__}:{exc.errno}")
            continue
        return selected, source, persistent, failures
    raise RuntimeError(
        "Kein beschreibbares Arbeitsverzeichnis gefunden: " + ", ".join(failures)
    )


def load_secret(
    script_path: Path,
    state_root: Path,
) -> tuple[bytes | None, str, Path]:
    environment_secret = os.environ.get("GRABOWSKI_JUNO_SECRET")
    if environment_secret is not None:
        secret = environment_secret.encode("utf-8")
        if len(secret) < PAIRING_SECRET_BYTES:
            raise RuntimeError("Agent-Schlüssel muss mindestens 32 Byte lang sein")
        return secret, "environment", state_root / "juno_ipad_agent.key"
    script_key = script_path.with_name("juno_ipad_agent.key")
    state_key = state_root / "juno_ipad_agent.key"
    key_candidates = [script_key]
    if state_key != script_key:
        key_candidates.append(state_key)
    for key_path in key_candidates:
        try:
            secret = key_path.read_bytes()
        except FileNotFoundError:
            continue
        except OSError:
            if key_path == script_key and state_key != script_key:
                continue
            raise
        if len(secret) < PAIRING_SECRET_BYTES:
            raise RuntimeError("Agent-Schlüssel muss mindestens 32 Byte lang sein")
        return secret, str(key_path), key_path
    return None, "unpaired", state_key


class AuthenticationError(ValueError):
    """Request authentication failed."""


class RequestAuthenticator:
    def __init__(self, secret: bytes, skew_seconds: int = AUTH_SKEW_SECONDS) -> None:
        self._secret = secret
        self._skew_seconds = skew_seconds
        self._seen_nonces: dict[str, int] = {}
        self._lock = threading.Lock()

    def matches_secret(self, candidate: bytes) -> bool:
        return hmac.compare_digest(self._secret, candidate)

    @staticmethod
    def canonical_message(
        method: str,
        path_with_query: str,
        timestamp: str,
        nonce: str,
        body_sha256: str,
    ) -> bytes:
        return (
            f"{method.upper()}\n{path_with_query}\n{timestamp}\n{nonce}\n{body_sha256}"
        ).encode("utf-8")

    def verify(
        self,
        method: str,
        path_with_query: str,
        body: bytes,
        headers: Mapping[str, str],
        *,
        now: int | None = None,
    ) -> None:
        timestamp = headers.get("X-Grabowski-Timestamp", "")
        nonce = headers.get("X-Grabowski-Nonce", "")
        claimed_body_hash = headers.get("X-Grabowski-Body-SHA256", "")
        signature = headers.get("X-Grabowski-Signature", "")
        try:
            timestamp_value = int(timestamp)
        except ValueError as exc:
            raise AuthenticationError("invalid_timestamp") from exc
        current = int(time.time()) if now is None else int(now)
        if abs(current - timestamp_value) > self._skew_seconds:
            raise AuthenticationError("stale_timestamp")
        if not NONCE_RE.fullmatch(nonce):
            raise AuthenticationError("invalid_nonce")
        actual_body_hash = sha256_hex(body)
        if not hmac.compare_digest(claimed_body_hash, actual_body_hash):
            raise AuthenticationError("body_hash_mismatch")
        message = self.canonical_message(
            method,
            path_with_query,
            timestamp,
            nonce,
            actual_body_hash,
        )
        expected = hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise AuthenticationError("invalid_signature")
        with self._lock:
            cutoff = current - self._skew_seconds
            self._seen_nonces = {
                key: value for key, value in self._seen_nonces.items() if value >= cutoff
            }
            if nonce in self._seen_nonces:
                raise AuthenticationError("replayed_nonce")
            self._seen_nonces[nonce] = timestamp_value


class BoundedTextIO(io.TextIOBase):
    def __init__(self, limit: int) -> None:
        super().__init__()
        self._limit = limit
        self._parts: list[str] = []
        self._length = 0
        self.truncated = False

    @property
    def encoding(self) -> str:
        return "utf-8"

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        if not isinstance(text, str):
            text = str(text)
        original_length = len(text)
        remaining = self._limit - self._length
        if remaining > 0:
            accepted = text[:remaining]
            self._parts.append(accepted)
            self._length += len(accepted)
        if original_length > max(remaining, 0):
            self.truncated = True
        return original_length

    def getvalue(self) -> str:
        return "".join(self._parts)


class JobTimedOut(TimeoutError):
    pass


def bounded_repr(value: Any) -> str:
    try:
        return repr(value)
    except BaseException as exc:
        return (
            f"<unrepresentable {type(value).__name__}: "
            f"{type(exc).__name__}>"
        )


def json_safe_result(value: Any) -> tuple[Any, bool]:
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError, RecursionError):
        rendered = bounded_repr(value)
        truncated = len(rendered) > MAX_RESULT_CHARS
        return rendered[:MAX_RESULT_CHARS], truncated
    if len(encoded) <= MAX_RESULT_CHARS:
        return value, False
    rendered = bounded_repr(value)
    return rendered[:MAX_RESULT_CHARS], True


class AgentState:
    def __init__(
        self,
        root: Path,
        *,
        start_worker: bool = True,
        storage_source: str = "explicit",
        storage_persistent: bool = True,
    ) -> None:
        self.root = root.resolve()
        self.storage_source = storage_source
        self.storage_persistent = storage_persistent
        self.jobs_root = self.root / "jobs"
        self.workspace = self.root / "workspace"
        self.audit_path = self.root / "audit.jsonl"
        self.jobs_root.mkdir(parents=True, exist_ok=True)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._audit_lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._recover_incomplete_jobs()
        if start_worker:
            self._worker = threading.Thread(
                target=self._worker_loop,
                name="juno-ipad-agent-worker",
                daemon=True,
            )
            self._worker.start()

    def _job_dir(self, job_id: str) -> Path:
        if not JOB_ID_RE.fullmatch(job_id):
            raise ValueError("invalid_job_id")
        return self.jobs_root / job_id

    def _audit(self, event: str, **fields: Any) -> None:
        record = {
            "schema_version": SCHEMA_VERSION,
            "event": event,
            "observed_at": utc_now(),
            **fields,
        }
        payload = canonical_json_bytes(record) + b"\n"
        with self._audit_lock:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(
                self.audit_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                with os.fdopen(fd, "ab", closefd=False) as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                os.close(fd)

    def _recover_incomplete_jobs(self) -> None:
        for job_dir in sorted(self.jobs_root.iterdir()):
            if not job_dir.is_dir():
                continue
            request_path = job_dir / "request.json"
            result_path = job_dir / "result.json"
            if not request_path.is_file() or result_path.exists():
                continue
            try:
                request = read_json(request_path)
                job_id = request["job_id"]
                code_sha256 = request["code_sha256"]
            except (OSError, ValueError, KeyError, TypeError):
                continue
            result = {
                "schema_version": SCHEMA_VERSION,
                "job_id": job_id,
                "state": "abandoned_after_restart",
                "code_sha256": code_sha256,
                "started_at": None,
                "finished_at": utc_now(),
                "duration_seconds": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "result": None,
                "result_truncated": False,
                "error": "agent_restarted_before_terminal_receipt",
            }
            try:
                atomic_create_json(result_path, result)
            except FileExistsError:
                continue
            self._audit(
                "job_recovered",
                job_id=job_id,
                state="abandoned_after_restart",
                code_sha256=code_sha256,
                result_sha256=sha256_hex(canonical_json_bytes(result)),
            )

    def submit_job(self, document: Mapping[str, Any]) -> dict[str, Any]:
        if document.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported_schema_version")
        job_id = document.get("job_id")
        code = document.get("code")
        timeout_seconds = document.get("timeout_seconds", 60)
        metadata = document.get("metadata", {})
        if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
            raise ValueError("invalid_job_id")
        if not isinstance(code, str):
            raise ValueError("code_must_be_string")
        code_bytes = code.encode("utf-8")
        if not code_bytes or len(code_bytes) > MAX_CODE_BYTES:
            raise ValueError("code_size_out_of_range")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise ValueError("timeout_must_be_integer")
        if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout_out_of_range")
        if not isinstance(metadata, dict):
            raise ValueError("metadata_must_be_object")
        if len(canonical_json_bytes(metadata)) > MAX_METADATA_BYTES:
            raise ValueError("metadata_too_large")
        request = {
            "schema_version": SCHEMA_VERSION,
            "job_id": job_id,
            "code": code,
            "code_sha256": sha256_hex(code_bytes),
            "timeout_seconds": timeout_seconds,
            "metadata": metadata,
            "submitted_at": utc_now(),
        }
        job_dir = self._job_dir(job_id)
        try:
            job_dir.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise FileExistsError("job_id_already_exists") from exc
        try:
            atomic_create_json(job_dir / "request.json", request)
            atomic_replace_json(
                job_dir / "status.json",
                {
                    "schema_version": SCHEMA_VERSION,
                    "job_id": job_id,
                    "state": "queued",
                    "code_sha256": request["code_sha256"],
                    "submitted_at": request["submitted_at"],
                },
            )
        except Exception:
            with contextlib.suppress(OSError):
                for child in job_dir.iterdir():
                    child.unlink()
                job_dir.rmdir()
            raise
        self._audit(
            "job_submitted",
            job_id=job_id,
            code_sha256=request["code_sha256"],
            timeout_seconds=timeout_seconds,
        )
        self._queue.put(job_id)
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        result_path = job_dir / "result.json"
        status_path = job_dir / "status.json"
        if result_path.is_file():
            value = read_json(result_path)
        elif status_path.is_file():
            value = read_json(status_path)
        else:
            raise FileNotFoundError("job_not_found")
        if not isinstance(value, dict):
            raise ValueError("invalid_job_record")
        return value

    def list_jobs(self, limit: int = 50) -> list[dict[str, Any]]:
        if not 1 <= limit <= 200:
            raise ValueError("limit_out_of_range")
        jobs: list[dict[str, Any]] = []
        candidates = sorted(
            (path for path in self.jobs_root.iterdir() if path.is_dir()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for path in candidates[:limit]:
            try:
                jobs.append(self.get_job(path.name))
            except (OSError, ValueError):
                continue
        return jobs

    def _worker_loop(self) -> None:
        while True:
            job_id = self._queue.get()
            try:
                if job_id is None:
                    return
                try:
                    self.run_job_now(job_id)
                except BaseException as exc:
                    with contextlib.suppress(Exception):
                        self._audit(
                            "worker_internal_error",
                            job_id=job_id,
                            error_type=type(exc).__name__,
                        )
                    print(
                        f"Interner Jobfehler für {job_id}: {type(exc).__name__}",
                        file=sys.__stderr__,
                    )
            finally:
                self._queue.task_done()

    def stop(self) -> None:
        if self._worker is not None:
            self._queue.put(None)

    def run_job_now(self, job_id: str) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        request = read_json(job_dir / "request.json")
        result_path = job_dir / "result.json"
        if result_path.exists():
            return read_json(result_path)
        started_at = utc_now()
        start_monotonic = time.monotonic()
        timeout_seconds = int(request["timeout_seconds"])
        deadline = start_monotonic + timeout_seconds
        atomic_replace_json(
            job_dir / "status.json",
            {
                "schema_version": SCHEMA_VERSION,
                "job_id": job_id,
                "state": "running",
                "code_sha256": request["code_sha256"],
                "submitted_at": request["submitted_at"],
                "started_at": started_at,
            },
        )
        self._audit(
            "job_started",
            job_id=job_id,
            code_sha256=request["code_sha256"],
        )
        stdout = BoundedTextIO(MAX_OUTPUT_CHARS)
        stderr = BoundedTextIO(MAX_OUTPUT_CHARS)
        namespace: dict[str, Any] = {
            "__name__": "__grabowski_job__",
            "__file__": f"<grabowski-job-{job_id}>",
            "GRABOWSKI_JOB_ID": job_id,
            "GRABOWSKI_WORKSPACE": self.workspace,
            "GRABOWSKI_METADATA": request["metadata"],
            "GRABOWSKI_RESULT": None,
        }
        state = "succeeded"
        error: str | None = None
        old_cwd = Path.cwd()

        def deadline_trace(frame: Any, event: str, arg: Any) -> Any:
            del frame, event, arg
            if time.monotonic() > deadline:
                raise JobTimedOut(f"job exceeded {timeout_seconds} seconds")
            return deadline_trace

        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                sys.settrace(deadline_trace)
                try:
                    compiled = compile(
                        request["code"],
                        f"<grabowski-job-{job_id}>",
                        "exec",
                    )
                    exec(compiled, namespace, namespace)
                finally:
                    sys.settrace(None)
        except JobTimedOut:
            state = "timed_out"
            error = f"cooperative_python_timeout_after_{timeout_seconds}_seconds"
        except BaseException as exc:  # arbitrary jobs may raise SystemExit/KeyboardInterrupt
            state = "failed"
            error = f"{type(exc).__name__}: {exc}"
            traceback.print_exc(file=stderr)
        finally:
            sys.settrace(None)
            with contextlib.suppress(OSError):
                os.chdir(old_cwd)
        result_value, result_truncated = json_safe_result(namespace.get("GRABOWSKI_RESULT"))
        finished_at = utc_now()
        result = {
            "schema_version": SCHEMA_VERSION,
            "job_id": job_id,
            "state": state,
            "code_sha256": request["code_sha256"],
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(time.monotonic() - start_monotonic, 6),
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "stdout_truncated": stdout.truncated,
            "stderr_truncated": stderr.truncated,
            "result": result_value,
            "result_truncated": result_truncated,
            "error": error,
        }
        try:
            atomic_create_json(result_path, result)
        except FileExistsError:
            result = read_json(result_path)
        atomic_replace_json(job_dir / "status.json", result)
        self._audit(
            "job_finished",
            job_id=job_id,
            state=result["state"],
            code_sha256=request["code_sha256"],
            result_sha256=sha256_hex(canonical_json_bytes(result)),
            duration_seconds=result["duration_seconds"],
        )
        return result


class AgentHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        authenticator: RequestAuthenticator | None,
        state: AgentState,
        secret_source: str,
        key_path: Path,
        pairing_peer: str,
        started_at: str,
        pairing_consent_code: str | None,
        pairing_consent_expires_at_unix: int | None,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.authenticator = authenticator
        self.state = state
        self.secret_source = secret_source
        self.key_path = key_path
        self.pairing_peer = pairing_peer
        self.started_at = started_at
        self.pairing_consent_code = pairing_consent_code
        self.pairing_consent_expires_at_unix = pairing_consent_expires_at_unix
        self.pairing_consent_attempts = 0
        self.auth_lock = threading.Lock()

    def is_paired(self) -> bool:
        with self.auth_lock:
            return self.authenticator is not None

    def current_authenticator(self) -> RequestAuthenticator | None:
        with self.auth_lock:
            return self.authenticator

    def pair(
        self,
        secret: bytes,
        consent_code: str,
        *,
        now: int | None = None,
    ) -> str:
        if len(secret) != PAIRING_SECRET_BYTES:
            raise ValueError("pairing_secret_must_be_32_bytes")
        with self.auth_lock:
            if self.authenticator is not None:
                if self.authenticator.matches_secret(secret):
                    return "already_paired_same_secret"
                raise FileExistsError("agent_already_paired")
            current = int(time.time()) if now is None else int(now)
            if not PAIRING_CONSENT_RE.fullmatch(consent_code):
                raise ValueError("pairing_consent_code_invalid")
            if (
                self.pairing_consent_code is None
                or self.pairing_consent_expires_at_unix is None
                or current > self.pairing_consent_expires_at_unix
            ):
                raise PermissionError("pairing_consent_expired")
            if not hmac.compare_digest(consent_code, self.pairing_consent_code):
                self.pairing_consent_attempts += 1
                if self.pairing_consent_attempts >= PAIRING_CONSENT_MAX_ATTEMPTS:
                    self.pairing_consent_code = None
                    self.pairing_consent_expires_at_unix = None
                    raise PermissionError("pairing_consent_locked")
                raise PermissionError("pairing_consent_mismatch")
            atomic_create_bytes(self.key_path, secret)
            self.authenticator = RequestAuthenticator(secret)
            self.secret_source = self.key_path.name
            self.pairing_consent_code = None
            self.pairing_consent_expires_at_unix = None
            self.pairing_consent_attempts = 0
            return "paired"


class AgentHandler(BaseHTTPRequestHandler):
    server_version = "GrabowskiJunoAgent/1.0"

    @property
    def agent_server(self) -> AgentHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt: str, *args: object) -> None:
        print(
            f"[{datetime.now().astimezone().isoformat()}] "
            f"{self.client_address[0]} {fmt % args}",
            file=sys.__stdout__,
        )

    def _client_allowed(self) -> bool:
        if client_address_allowed(self.client_address[0]):
            return True
        self._send_json(
            HTTPStatus.FORBIDDEN,
            {"schema_version": SCHEMA_VERSION, "error": "tailscale_source_required"},
        )
        return False

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Any,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        body = canonical_json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("invalid_content_length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise OverflowError("request_body_too_large")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("incomplete_request_body")
        return body

    def _authenticate(self, body: bytes) -> bool:
        authenticator = self.agent_server.current_authenticator()
        if authenticator is None:
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"schema_version": SCHEMA_VERSION, "error": "agent_unpaired"},
            )
            return False
        try:
            authenticator.verify(
                self.command,
                self.path,
                body,
                self.headers,
            )
        except AuthenticationError:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"schema_version": SCHEMA_VERSION, "error": "unauthorized"},
            )
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._client_allowed():
            return
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/health"}:
            self._send_json(
                HTTPStatus.OK,
                {
                    "schema_version": SCHEMA_VERSION,
                    "service": "grabowski-juno-ipad-agent",
                    "status": "ok",
                    "execution_scope": "juno_process_permissions",
                    "arbitrary_python": True,
                    "started_at": self.agent_server.started_at,
                    "observed_at": utc_now(),
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                    "workspace": str(self.agent_server.state.workspace),
                    "state_root": str(self.agent_server.state.root),
                    "state_storage_source": self.agent_server.state.storage_source,
                    "state_persistent": self.agent_server.state.storage_persistent,
                    "secret_source": self.agent_server.secret_source,
                    "paired": self.agent_server.is_paired(),
                    "pairing_peer": self.agent_server.pairing_peer,
                    "pairing_consent_required": (
                        not self.agent_server.is_paired()
                        and self.agent_server.pairing_consent_code is not None
                    ),
                    "pairing_consent_expires_at_unix": (
                        self.agent_server.pairing_consent_expires_at_unix
                    ),
                    "pairing_consent_attempts_remaining": (
                        max(
                            0,
                            PAIRING_CONSENT_MAX_ATTEMPTS
                            - self.agent_server.pairing_consent_attempts,
                        )
                        if not self.agent_server.is_paired()
                        else None
                    ),
                    "timeout_contract": "cooperative_python_only",
                    "network_policy": "tailscale_or_loopback_source",
                },
            )
            return
        if not self._authenticate(b""):
            return
        if parsed.path == "/v1/jobs":
            query = parse_qs(parsed.query)
            try:
                limit = int(query.get("limit", ["50"])[0])
                jobs = self.agent_server.state.list_jobs(limit)
            except (ValueError, OSError) as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"schema_version": SCHEMA_VERSION, "error": str(exc)},
                )
                return
            self._send_json(
                HTTPStatus.OK,
                {"schema_version": SCHEMA_VERSION, "jobs": jobs},
            )
            return
        prefix = "/v1/jobs/"
        if parsed.path.startswith(prefix) and parsed.query == "":
            job_id = parsed.path[len(prefix) :]
            try:
                job = self.agent_server.state.get_job(job_id)
            except FileNotFoundError:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"schema_version": SCHEMA_VERSION, "error": "job_not_found"},
                )
                return
            except (ValueError, OSError) as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"schema_version": SCHEMA_VERSION, "error": str(exc)},
                )
                return
            self._send_json(HTTPStatus.OK, job)
            return
        self._send_json(
            HTTPStatus.NOT_FOUND,
            {"schema_version": SCHEMA_VERSION, "error": "not_found"},
        )

    def do_POST(self) -> None:  # noqa: N802
        if not self._client_allowed():
            return
        try:
            body = self._read_body()
        except OverflowError as exc:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"schema_version": SCHEMA_VERSION, "error": str(exc)},
            )
            return
        except ValueError as exc:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"schema_version": SCHEMA_VERSION, "error": str(exc)},
            )
            return
        parsed = urlparse(self.path)
        if parsed.path == "/v1/pair" and parsed.query == "":
            if self.client_address[0].split("%", 1)[0] != self.agent_server.pairing_peer:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"schema_version": SCHEMA_VERSION, "error": "pairing_peer_required"},
                )
                return
            try:
                document = json.loads(body.decode("utf-8"))
                if not isinstance(document, dict):
                    raise ValueError("request_must_be_object")
                if document.get("schema_version") != SCHEMA_VERSION:
                    raise ValueError("unsupported_schema_version")
                encoded_secret = document.get("secret_b64")
                if not isinstance(encoded_secret, str):
                    raise ValueError("secret_b64_must_be_string")
                consent_code = document.get("consent_code")
                if not isinstance(consent_code, str):
                    raise ValueError("consent_code_must_be_string")
                padding = "=" * (-len(encoded_secret) % 4)
                secret = base64.b64decode(
                    encoded_secret + padding,
                    altchars=b"-_",
                    validate=True,
                )
                outcome = self.agent_server.pair(secret, consent_code)
            except UnicodeDecodeError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"schema_version": SCHEMA_VERSION, "error": "body_not_utf8"},
                )
                return
            except PermissionError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"schema_version": SCHEMA_VERSION, "error": str(exc)},
                )
                return
            except FileExistsError:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"schema_version": SCHEMA_VERSION, "error": "agent_already_paired"},
                )
                return
            except (json.JSONDecodeError, binascii.Error, ValueError, OSError) as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"schema_version": SCHEMA_VERSION, "error": str(exc)},
                )
                return
            self._send_json(
                HTTPStatus.CREATED if outcome == "paired" else HTTPStatus.OK,
                {
                    "schema_version": SCHEMA_VERSION,
                    "status": outcome,
                    "paired": True,
                    "secret_source": self.agent_server.secret_source,
                },
            )
            return
        if not self._authenticate(body):
            return
        if parsed.path == "/v1/jobs" and parsed.query == "":
            try:
                document = json.loads(body.decode("utf-8"))
                if not isinstance(document, dict):
                    raise ValueError("request_must_be_object")
                job = self.agent_server.state.submit_job(document)
            except UnicodeDecodeError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"schema_version": SCHEMA_VERSION, "error": "body_not_utf8"},
                )
                return
            except json.JSONDecodeError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"schema_version": SCHEMA_VERSION, "error": "invalid_json"},
                )
                return
            except FileExistsError:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"schema_version": SCHEMA_VERSION, "error": "job_id_already_exists"},
                )
                return
            except (ValueError, OSError) as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"schema_version": SCHEMA_VERSION, "error": str(exc)},
                )
                return
            self._send_json(
                HTTPStatus.ACCEPTED,
                job,
                extra_headers={"Location": f"/v1/jobs/{job['job_id']}"},
            )
            return
        if parsed.path == "/v1/shutdown" and parsed.query == "":
            self._send_json(
                HTTPStatus.ACCEPTED,
                {"schema_version": SCHEMA_VERSION, "status": "shutting_down"},
            )
            threading.Thread(
                target=self.agent_server.shutdown,
                name="juno-agent-shutdown",
                daemon=True,
            ).start()
            return
        self._send_json(
            HTTPStatus.NOT_FOUND,
            {"schema_version": SCHEMA_VERSION, "error": "not_found"},
        )

    def do_PUT(self) -> None:  # noqa: N802
        if not self._client_allowed():
            return
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"schema_version": SCHEMA_VERSION, "error": "method_not_allowed"},
        )

    do_PATCH = do_PUT
    do_DELETE = do_PUT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--pairing-peer", default=DEFAULT_PAIRING_PEER)
    parser.add_argument(
        "--state-root",
        type=Path,
        help="State directory; default is grabowski_workspace beside this script",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port muss zwischen 1 und 65535 liegen")
    script_path = Path(__file__).resolve()
    try:
        pairing_peer = str(ipaddress.ip_address(args.pairing_peer.split("%", 1)[0]))
    except ValueError as exc:
        raise SystemExit("--pairing-peer muss eine gültige IP-Adresse sein") from exc
    if not client_address_allowed(pairing_peer):
        raise SystemExit("--pairing-peer muss Loopback oder eine Tailscale-IP sein")
    state_root, state_source, state_persistent, state_fallbacks = select_state_root(
        script_path,
        args.state_root,
    )
    secret, secret_source, key_path = load_secret(script_path, state_root)
    state = AgentState(
        state_root,
        storage_source=state_source,
        storage_persistent=state_persistent,
    )
    started_at = utc_now()
    pairing_consent_code = (
        f"{secrets.randbelow(1_000_000):06d}" if secret is None else None
    )
    pairing_consent_expires_at_unix = (
        int(time.time()) + PAIRING_CONSENT_TTL_SECONDS
        if pairing_consent_code is not None
        else None
    )
    server = AgentHTTPServer(
        (args.host, args.port),
        AgentHandler,
        authenticator=RequestAuthenticator(secret) if secret is not None else None,
        state=state,
        secret_source=secret_source,
        key_path=key_path,
        pairing_peer=pairing_peer,
        started_at=started_at,
        pairing_consent_code=pairing_consent_code,
        pairing_consent_expires_at_unix=pairing_consent_expires_at_unix,
    )

    def request_stop(signum: int, _frame: Any) -> None:
        print(f"\nSignal {signum} empfangen; Agent wird beendet …")
        threading.Thread(target=server.shutdown, daemon=True).start()

    for signal_name in ("SIGINT", "SIGTERM"):
        candidate = getattr(signal, signal_name, None)
        if candidate is not None:
            signal.signal(candidate, request_stop)

    print("Grabowski Juno iPad Agent läuft.")
    print(f"Bind: {args.host}:{args.port}")
    print(f"State: {state_root}")
    print(
        f"State-Modus: {state_source}; "
        f"{'persistent' if state_persistent else 'temporär'}"
    )
    if state_fallbacks:
        print(
            "Hinweis: frühere Standardpfade waren nicht beschreibbar; "
            "ein zulässiger Ersatzpfad wurde automatisch gewählt."
        )
    print(f"Schlüsselquelle: {secret_source}")
    if secret is None:
        print(f"Kopplung: wartet einmalig auf {pairing_peer}")
        print(
            f"Lokaler Kopplungscode: {pairing_consent_code} "
            f"({PAIRING_CONSENT_TTL_SECONDS // 60} Minuten gültig)"
        )
    else:
        print("Kopplung: aktiv")
    print("Rechte: beliebiges Python mit den Rechten des Juno-Prozesses")
    print("Stop: Juno-Stopptaste, Ctrl-C oder signiertes POST /v1/shutdown")
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        state.stop()
        server.server_close()
        print("Agent beendet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
