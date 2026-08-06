"""Typed read-only adapter for the canonical Systemkatalog query contract."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import sys
from typing import Annotated, Any, Literal

from pydantic import Field

import grabowski_operator_core as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

SCHEMA_VERSION = 1
RESULT_KIND = "grabowski.systemkatalog_query"
CATALOG_REPOSITORY = "heimgewebe/systemkatalog"
ROOT_ENVIRONMENT = "GRABOWSKI_SYSTEMKATALOG_ROOT"
DEFAULT_ROOT = Path.home() / "repos" / "systemkatalog"
QUERY_SCRIPT = Path("scripts/systemkatalog_query.py")
QUERY_TIMEOUT_SECONDS = 15
GIT_TIMEOUT_SECONDS = 5
MAX_STDOUT_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_SCRIPT_BYTES = 1024 * 1024
MAX_VALUE_CHARS = 240
VALUE_OPERATIONS = frozenset(
    {"system", "repository", "truth-owner", "relations", "entrypoints"}
)
VALUELESS_OPERATIONS = frozenset({"authority-matrix", "manifest"})
OPERATIONS = VALUE_OPERATIONS | VALUELESS_OPERATIONS
ALLOWED_ORIGINS = frozenset(
    {
        "git@github.com:heimgewebe/systemkatalog.git",
        "https://github.com/heimgewebe/systemkatalog",
        "https://github.com/heimgewebe/systemkatalog.git",
    }
)
ADAPTER_DOES_NOT_ESTABLISH = (
    "runtime_health",
    "task_status",
    "pull_request_state",
    "ci_state",
    "merge_readiness",
    "execution_permission",
    "current_external_truth",
    "catalog_semantic_completeness",
    "consumer_view_correctness",
    "catalog_freshness_after_query",
    "write_authority",
)

SystemkatalogOperation = Literal[
    "system",
    "repository",
    "truth-owner",
    "relations",
    "entrypoints",
    "authority-matrix",
    "manifest",
]


class SystemkatalogAdapterError(RuntimeError):
    """One typed fail-closed adapter failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _argv_sha256(argv: list[str]) -> str:
    payload = json.dumps(
        argv,
        ensure_ascii=False,
        sort_keys=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(payload)


def _bounded_value(operation: str, value: str | None) -> str | None:
    if operation not in OPERATIONS:
        raise SystemkatalogAdapterError(
            "operation_unsupported",
            "unsupported Systemkatalog operation",
            details={"operation": operation},
        )
    if value is not None and not isinstance(value, str):
        raise SystemkatalogAdapterError(
            "value_invalid",
            "query value must be text",
        )
    normalized = value.strip() if isinstance(value, str) else None
    if normalized and (
        len(normalized) > MAX_VALUE_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise SystemkatalogAdapterError(
            "value_invalid",
            "query value exceeds its bound or contains control characters",
        )
    if operation in VALUE_OPERATIONS and not normalized:
        raise SystemkatalogAdapterError(
            "value_required",
            "the selected Systemkatalog operation requires a query value",
            details={"operation": operation},
        )
    if operation in VALUELESS_OPERATIONS and normalized:
        raise SystemkatalogAdapterError(
            "value_forbidden",
            "the selected Systemkatalog operation does not accept a query value",
            details={"operation": operation},
        )
    return normalized


def _configured_root() -> Path:
    raw = Path(os.environ.get(ROOT_ENVIRONMENT, str(DEFAULT_ROOT))).expanduser()
    if not raw.is_absolute():
        raise SystemkatalogAdapterError(
            "root_invalid",
            f"{ROOT_ENVIRONMENT} must be an absolute path",
        )
    try:
        root = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SystemkatalogAdapterError(
            "root_unavailable",
            "the configured Systemkatalog repository is unavailable",
            details={"error_type": type(exc).__name__},
        ) from exc
    if not root.is_dir():
        raise SystemkatalogAdapterError(
            "root_invalid",
            "the configured Systemkatalog root is not a directory",
        )
    return root


def _regular_file_identity(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise SystemkatalogAdapterError(
            "query_script_missing",
            "the Systemkatalog query script is missing",
        ) from exc
    except OSError as exc:
        raise SystemkatalogAdapterError(
            "query_script_unreadable",
            "the Systemkatalog query script cannot be opened safely",
            details={"error_type": type(exc).__name__},
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemkatalogAdapterError(
                "query_script_invalid",
                "the Systemkatalog query script is not a regular file",
            )
        if metadata.st_size > MAX_SCRIPT_BYTES:
            raise SystemkatalogAdapterError(
                "query_script_too_large",
                "the Systemkatalog query script exceeds the adapter size bound",
                details={"bytes": metadata.st_size, "maximum": MAX_SCRIPT_BYTES},
            )
        chunks: list[bytes] = []
        remaining = MAX_SCRIPT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_SCRIPT_BYTES:
            raise SystemkatalogAdapterError(
                "query_script_too_large",
                "the Systemkatalog query script exceeds the adapter size bound",
            )
        observed = os.fstat(descriptor)
        if (
            observed.st_dev != metadata.st_dev
            or observed.st_ino != metadata.st_ino
            or observed.st_size != metadata.st_size
            or observed.st_mtime_ns != metadata.st_mtime_ns
        ):
            raise SystemkatalogAdapterError(
                "query_script_changed",
                "the Systemkatalog query script changed while it was read",
            )
        return {
            "path": str(path),
            "sha256": _sha256(payload),
            "bytes": len(payload),
        }
    finally:
        os.close(descriptor)


def _subprocess_environment() -> dict[str, str]:
    return {
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    for termination_signal, grace_seconds in (
        (signal.SIGTERM, 1.0),
        (signal.SIGKILL, 1.0),
    ):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, termination_signal)
        except ProcessLookupError:
            return
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            continue
        return


def _run(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int | float,
) -> subprocess.CompletedProcess[bytes]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise SystemkatalogAdapterError(
            "timeout_invalid",
            "subprocess timeout must be a positive number",
        )
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=_subprocess_environment(),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except OSError as exc:
            raise SystemkatalogAdapterError(
                "subprocess_unavailable",
                "a bounded Systemkatalog adapter subprocess could not start",
                details={"error_type": type(exc).__name__},
            ) from exc
        try:
            returncode = process.wait(timeout=float(timeout_seconds))
        except subprocess.TimeoutExpired as exc:
            _terminate_process_group(process)
            raise SystemkatalogAdapterError(
                "subprocess_timeout",
                "a bounded Systemkatalog adapter subprocess timed out",
                details={"timeout_seconds": timeout_seconds},
            ) from exc
        stdout_bytes = stdout_file.tell()
        stderr_bytes = stderr_file.tell()
        if stdout_bytes > MAX_STDOUT_BYTES:
            raise SystemkatalogAdapterError(
                "stdout_too_large",
                "Systemkatalog output exceeds the adapter size bound",
                details={"bytes": stdout_bytes, "maximum": MAX_STDOUT_BYTES},
            )
        if stderr_bytes > MAX_STDERR_BYTES:
            raise SystemkatalogAdapterError(
                "stderr_too_large",
                "Systemkatalog stderr exceeds the adapter size bound",
                details={"bytes": stderr_bytes, "maximum": MAX_STDERR_BYTES},
            )
        stdout_file.seek(0)
        stderr_file.seek(0)
        return subprocess.CompletedProcess(
            args=argv,
            returncode=returncode,
            stdout=stdout_file.read(),
            stderr=stderr_file.read(),
        )


def _decode_text(payload: bytes, *, label: str) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemkatalogAdapterError(
            f"{label}_invalid_utf8",
            f"{label} is not valid UTF-8",
        ) from exc


def _git_text(root: Path, arguments: list[str]) -> str:
    completed = _run(
        ["git", "-C", str(root), *arguments],
        cwd=root,
        timeout_seconds=GIT_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise SystemkatalogAdapterError(
            "git_identity_failed",
            "the configured Systemkatalog Git identity cannot be read",
            details={
                "arguments": arguments,
                "returncode": completed.returncode,
                "stderr_sha256": _sha256(completed.stderr),
            },
        )
    return _decode_text(completed.stdout, label="git_stdout").strip()


def _repository_identity(root: Path) -> dict[str, Any]:
    head = _git_text(root, ["rev-parse", "--verify", "HEAD"])
    if len(head) != 40 or any(character not in "0123456789abcdef" for character in head):
        raise SystemkatalogAdapterError(
            "git_head_invalid",
            "the configured Systemkatalog HEAD is not a full SHA-1 object id",
        )
    status = _git_text(root, ["status", "--porcelain=v1", "--untracked-files=normal"])
    if status:
        raise SystemkatalogAdapterError(
            "repository_dirty",
            "the configured Systemkatalog repository has uncommitted state",
            details={"status_sha256": _sha256(status.encode("utf-8"))},
        )
    origin = _git_text(root, ["remote", "get-url", "origin"])
    if origin.rstrip("/") not in ALLOWED_ORIGINS:
        raise SystemkatalogAdapterError(
            "origin_unexpected",
            "the configured Systemkatalog origin does not match the canonical repository",
            details={"origin_sha256": _sha256(origin.encode("utf-8"))},
        )
    return {
        "repository": CATALOG_REPOSITORY,
        "head": head,
        "origin_sha256": _sha256(origin.encode("utf-8")),
        "clean": True,
    }


def _validate_payload(
    payload: Any,
    *,
    operation: str,
    value: str | None,
    head: str,
    returncode: int,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SystemkatalogAdapterError(
            "payload_invalid",
            "Systemkatalog output must be a JSON object",
        )
    status = payload.get("status")
    expected_kind = {
        "ok": "system_catalog_query_result",
        "degraded": "system_catalog_query_error",
    }.get(status)
    if payload.get("schemaVersion") != 2 or expected_kind is None:
        raise SystemkatalogAdapterError(
            "payload_contract_mismatch",
            "Systemkatalog output does not implement query envelope schema v2",
        )
    if payload.get("kind") != expected_kind:
        raise SystemkatalogAdapterError(
            "payload_kind_mismatch",
            "Systemkatalog output kind does not match its status",
        )
    if payload.get("command") != operation:
        raise SystemkatalogAdapterError(
            "payload_operation_mismatch",
            "Systemkatalog output is not bound to the requested operation",
        )
    query = payload.get("query")
    if not isinstance(query, dict) or query.get("value") != value:
        raise SystemkatalogAdapterError(
            "payload_query_mismatch",
            "Systemkatalog output is not bound to the requested query value",
        )
    if payload.get("catalogRepository") != CATALOG_REPOSITORY:
        raise SystemkatalogAdapterError(
            "payload_repository_mismatch",
            "Systemkatalog output names an unexpected catalog repository",
        )
    if payload.get("catalogCommit") != head:
        raise SystemkatalogAdapterError(
            "payload_commit_mismatch",
            "Systemkatalog output is not bound to the observed repository HEAD",
            details={
                "expected_head": head,
                "observed_commit": payload.get("catalogCommit"),
            },
        )
    expected_returncode = 0 if status == "ok" else 3
    if returncode != expected_returncode:
        raise SystemkatalogAdapterError(
            "payload_exit_mismatch",
            "Systemkatalog exit code does not match its typed status",
            details={"returncode": returncode, "status": status},
        )
    nonclaims = payload.get("doesNotEstablish")
    if not isinstance(nonclaims, list) or not all(
        isinstance(item, str) and item for item in nonclaims
    ):
        raise SystemkatalogAdapterError(
            "payload_nonclaims_invalid",
            "Systemkatalog output does not carry a valid epistemic boundary",
        )
    if status == "ok":
        identity = payload.get("catalogIdentity")
        manifest = (
            identity.get("artifactManifest")
            if isinstance(identity, dict)
            else None
        )
        manifest_sha256 = (
            manifest.get("sha256") if isinstance(manifest, dict) else None
        )
        if (
            not isinstance(identity, dict)
            or identity.get("repository") != CATALOG_REPOSITORY
            or identity.get("commit") != head
            or not isinstance(manifest, dict)
            or not isinstance(manifest.get("path"), str)
            or not isinstance(manifest_sha256, str)
            or len(manifest_sha256) != 64
            or any(character not in "0123456789abcdef" for character in manifest_sha256)
            or isinstance(manifest.get("bytes"), bool)
            or not isinstance(manifest.get("bytes"), int)
            or manifest["bytes"] < 0
        ):
            raise SystemkatalogAdapterError(
                "payload_identity_invalid",
                "Systemkatalog success output lacks a valid manifest-bound catalog identity",
            )
        source_paths = payload.get("sourcePaths")
        source_evidence = payload.get("sourceEvidence")
        if (
            not isinstance(source_paths, list)
            or not source_paths
            or not isinstance(source_evidence, list)
            or len(source_evidence) != len(source_paths)
        ):
            raise SystemkatalogAdapterError(
                "payload_evidence_invalid",
                "Systemkatalog success output lacks bounded query-specific source evidence",
            )
        observed_paths: list[str] = []
        for evidence in source_evidence:
            evidence_sha256 = (
                evidence.get("sha256") if isinstance(evidence, dict) else None
            )
            if (
                not isinstance(evidence, dict)
                or not isinstance(evidence.get("path"), str)
                or not isinstance(evidence_sha256, str)
                or len(evidence_sha256) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in evidence_sha256
                )
                or isinstance(evidence.get("bytes"), bool)
                or not isinstance(evidence.get("bytes"), int)
                or evidence["bytes"] < 0
            ):
                raise SystemkatalogAdapterError(
                    "payload_evidence_invalid",
                    "Systemkatalog source evidence contains an invalid identity",
                )
            observed_paths.append(evidence["path"])
        if source_paths != observed_paths or len(set(observed_paths)) != len(observed_paths):
            raise SystemkatalogAdapterError(
                "payload_evidence_invalid",
                "Systemkatalog source paths and evidence identities do not match exactly",
            )
        if "result" not in payload:
            raise SystemkatalogAdapterError(
                "payload_result_missing",
                "Systemkatalog success output has no result payload",
            )
    else:
        error = payload.get("error")
        if (
            not isinstance(error, dict)
            or not isinstance(error.get("code"), str)
            or not error["code"]
            or not isinstance(error.get("message"), str)
            or not error["message"]
        ):
            raise SystemkatalogAdapterError(
                "payload_error_invalid",
                "Systemkatalog degraded output has no typed error payload",
            )
    return payload


def _failure(
    operation: str,
    value: str | None,
    error: SystemkatalogAdapterError,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "status": "degraded",
        "operation": operation,
        "value": value,
        "adapter_error": {
            "code": error.code,
            "message": str(error),
            "details": error.details,
        },
        "systemkatalog": None,
        "does_not_establish": list(ADAPTER_DOES_NOT_ESTABLISH),
    }


def query_systemkatalog(
    operation: str,
    value: str | None = None,
) -> dict[str, Any]:
    """Invoke exactly one revision-bound Systemkatalog v2 read operation."""
    normalized_operation = operation.strip() if isinstance(operation, str) else ""
    try:
        normalized_value = _bounded_value(normalized_operation, value)
        root = _configured_root()
        repository = _repository_identity(root)
        script = _regular_file_identity(root / QUERY_SCRIPT)
        argv = [
            sys.executable,
            script["path"],
            "--root",
            str(root),
            normalized_operation,
        ]
        if normalized_value is not None:
            argv.append(normalized_value)
        completed = _run(
            argv,
            cwd=root,
            timeout_seconds=QUERY_TIMEOUT_SECONDS,
        )
        post_repository = _repository_identity(root)
        if post_repository != repository:
            raise SystemkatalogAdapterError(
                "repository_changed",
                "the Systemkatalog repository identity changed during the query",
                details={
                    "before_head": repository.get("head"),
                    "after_head": post_repository.get("head"),
                },
            )
        post_script = _regular_file_identity(root / QUERY_SCRIPT)
        if post_script != script:
            raise SystemkatalogAdapterError(
                "query_script_changed",
                "the Systemkatalog query script identity changed during the query",
                details={
                    "before_sha256": script.get("sha256"),
                    "after_sha256": post_script.get("sha256"),
                },
            )
        if completed.returncode not in {0, 3}:
            raise SystemkatalogAdapterError(
                "query_failed",
                "Systemkatalog query exited outside its typed contract",
                details={
                    "returncode": completed.returncode,
                    "stderr_sha256": _sha256(completed.stderr),
                },
            )
        stdout = _decode_text(completed.stdout, label="query_stdout")
        try:
            decoded = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise SystemkatalogAdapterError(
                "query_json_invalid",
                "Systemkatalog query output is not valid JSON",
                details={"stdout_sha256": _sha256(completed.stdout)},
            ) from exc
        payload = _validate_payload(
            decoded,
            operation=normalized_operation,
            value=normalized_value,
            head=repository["head"],
            returncode=completed.returncode,
        )
        combined_nonclaims = list(
            dict.fromkeys(
                [*payload["doesNotEstablish"], *ADAPTER_DOES_NOT_ESTABLISH]
            )
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": RESULT_KIND,
            "status": payload["status"],
            "operation": normalized_operation,
            "value": normalized_value,
            "adapter_identity": {
                "repository": repository,
                "query_script": script,
                "argv_sha256": _argv_sha256(argv),
                "timeout_seconds": QUERY_TIMEOUT_SECONDS,
                "max_stdout_bytes": MAX_STDOUT_BYTES,
            },
            "systemkatalog": payload,
            "does_not_establish": combined_nonclaims,
        }
    except SystemkatalogAdapterError as exc:
        return _failure(normalized_operation, value, exc)
    except Exception as exc:  # pragma: no cover - defensive fail-closed boundary
        return _failure(
            normalized_operation,
            value,
            SystemkatalogAdapterError(
                "adapter_internal_error",
                "the Systemkatalog adapter failed closed",
                details={"error_type": type(exc).__name__},
            ),
        )


@mcp.tool(name="grabowski_systemkatalog_query", annotations=READ_ONLY)
def grabowski_systemkatalog_query(
    operation: Annotated[
        SystemkatalogOperation,
        Field(description="Exact Systemkatalog read operation."),
    ],
    value: Annotated[
        str | None,
        Field(
            description=(
                "Bound query value for system, repository, truth-owner, relations "
                "or entrypoints; omit for authority-matrix and manifest."
            ),
            max_length=MAX_VALUE_CHARS,
        ),
    ] = None,
) -> dict[str, Any]:
    """Run one typed, revision-bound Systemkatalog v2 query without write authority."""
    return query_systemkatalog(operation, value)
