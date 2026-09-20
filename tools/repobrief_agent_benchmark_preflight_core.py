#!/usr/bin/env python3
"""Run exactly one cost-bounded RepoBrief benchmark preflight pair.

The preflight proves runner/provider compatibility only. It cannot dispatch the
full benchmark or establish RepoBrief usefulness.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import platform
import select
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from typing import Any

SOURCE_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024



def _open_absolute_regular_nofollow(path: Path, *, label: str) -> int:
    requested = path.expanduser()
    if not requested.is_absolute():
        raise RuntimeError(f"{label} path must be absolute")
    parts = requested.parts
    if (
        len(parts) < 2
        or parts[0] != os.sep
        or any(part in {"", ".", ".."} for part in parts[1:])
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise RuntimeError(f"{label} path is not safely openable")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directories: list[int] = []
    try:
        current = os.open(os.sep, directory_flags)
        directories.append(current)
        for component in parts[1:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            directories.append(current)
            if not stat.S_ISDIR(os.fstat(current).st_mode):
                raise RuntimeError(f"{label} parent path is not a directory")
        return os.open(parts[-1], file_flags, dir_fd=current)
    except OSError as exc:
        raise RuntimeError(f"{label} path must be symlink-free") from exc
    finally:
        for directory_fd in reversed(directories):
            os.close(directory_fd)


def _read_startup_source_snapshot(path: Path, *, label: str) -> tuple[bytes, dict[str, Any]]:
    requested = path.expanduser()
    try:
        before = requested.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > SOURCE_SNAPSHOT_MAX_BYTES:
        raise RuntimeError(f"{label} is empty or oversized")
    descriptor = _open_absolute_regular_nofollow(requested, label=label)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev, before.st_ino, before.st_size
        ):
            raise RuntimeError(f"{label} changed before load")
        data = bytearray()
        while len(data) <= SOURCE_SNAPSHOT_MAX_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, SOURCE_SNAPSHOT_MAX_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after_descriptor = os.fstat(descriptor)
        try:
            descriptor_path = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError as exc:
            raise RuntimeError(f"{label} opened path cannot be bound") from exc
        if (
            not os.path.isabs(descriptor_path)
            or descriptor_path.endswith(" (deleted)")
            or os.path.normpath(descriptor_path) != os.path.normpath(str(requested))
        ):
            raise RuntimeError(f"{label} opened path is unavailable")
        try:
            after = requested.lstat()
        except OSError as exc:
            raise RuntimeError(f"{label} disappeared during load") from exc
        if (
            len(data) != opened.st_size
            or len(data) > SOURCE_SNAPSHOT_MAX_BYTES
            or (after_descriptor.st_dev, after_descriptor.st_ino, after_descriptor.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
            or (after.st_dev, after.st_ino, after.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
        ):
            raise RuntimeError(f"{label} changed during load")
        resolved = Path(descriptor_path)
        identity = {
            "path": str(resolved),
            "name": resolved.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return bytes(data), identity
    finally:
        os.close(descriptor)


def _record_startup_code_identity(identity: Mapping[str, Any]) -> None:
    path = identity.get("path")
    if not isinstance(path, str) or not path:
        raise RuntimeError("preflight startup code identity is invalid")
    current = {
        "path": path,
        "name": identity.get("name"),
        "bytes": identity.get("bytes"),
        "sha256": identity.get("sha256"),
    }
    previous = _STARTUP_CODE_IDENTITIES.get(path)
    if previous is not None and previous != current:
        raise RuntimeError("preflight code changed between module loads")
    _STARTUP_CODE_IDENTITIES[path] = current


def _load_startup_source_module(
    name: str, path: Path, raw: bytes, identity: Mapping[str, Any]
) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
        _after_raw, after_identity = _read_startup_source_snapshot(
            path, label=f"{path.name} source"
        )
        if dict(identity) != after_identity:
            raise RuntimeError(f"{path.name} changed while being loaded")
    except BaseException:
        sys.modules.pop(name, None)
        raise
    module.__grabowski_source_identity__ = dict(identity)
    return module


MODULE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_runner.py")
CODEX_MODULE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_codex_runner.py")
CODEX_PREFLIGHT_PATH = Path(__file__).with_name("repobrief_agent_benchmark_codex_preflight.py")
CODEX_BOOTSTRAP_PATH = Path(__file__).with_name(
    "repobrief_agent_benchmark_source_bootstrap.py"
)
CODEX_BOOTSTRAP_KIND = "grabowski.python_c_source_bootstrap"
CODEX_BOOTSTRAP_SCHEMA_VERSION = 1
_STARTUP_CODE_IDENTITIES: dict[str, dict[str, Any]] = {}
_STARTUP_BOOTSTRAP_IDENTITY: dict[str, Any] | None = None
_CORE_SOURCE_RAW, _CORE_SOURCE_IDENTITY = _read_startup_source_snapshot(
    Path(__file__), label="preflight core source"
)
_RUNNER_SOURCE_RAW, _RUNNER_SOURCE_IDENTITY = _read_startup_source_snapshot(
    MODULE_PATH, label="benchmark runner source"
)
_record_startup_code_identity(_CORE_SOURCE_IDENTITY)
_record_startup_code_identity(_RUNNER_SOURCE_IDENTITY)
runner = _load_startup_source_module(
    "repobrief_agent_benchmark_runner",
    MODULE_PATH,
    _RUNNER_SOURCE_RAW,
    _RUNNER_SOURCE_IDENTITY,
)
_codex_runner_cache: Any | None = None


def _codex_runner_module() -> Any:
    global _codex_runner_cache
    if _codex_runner_cache is not None:
        return _codex_runner_cache
    try:
        raw, identity = _read_startup_source_snapshot(
            CODEX_MODULE_PATH, label="Codex benchmark runner source"
        )
        _record_startup_code_identity(identity)
        module = _load_startup_source_module(
            "repobrief_agent_benchmark_codex_runner_for_preflight",
            CODEX_MODULE_PATH,
            raw,
            identity,
        )
    except RuntimeError as exc:
        raise PreflightError(str(exc)) from exc
    _codex_runner_cache = module
    return module

REPORT_KIND = "repobrief.agent_benchmark_live_preflight"
FIXTURE_REPORT_KIND = "repobrief.agent_benchmark_preflight_fixture_report"
VERSION = "1.0"
MAX_PER_RUN_COST_USD = Decimal("1.00")
MAX_TOTAL_COST_USD = Decimal("2.00")
MAX_REQUEST_FILES = 128
MAX_MCP_LINE_BYTES = 4 * 1024 * 1024
MAX_VALIDATOR_OUTPUT_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
EXECUTABLE_HASH_CHUNK_BYTES = 1024 * 1024
MAX_LEDGER_ARTIFACT_BYTES = 16 * 1024 * 1024
LEDGER_KIND = "repobrief.agent_benchmark_preflight_dispatch_ledger"
LEDGER_EVENT_KIND = "repobrief.agent_benchmark_preflight_dispatch_event"
LEDGER_VERSION = "1.0"
REPOBRIEF_ABSTRACT_TOOLS = {
    "ask_context",
    "grounding_verify",
    "live_freshness",
    "repobrief_resource_read",
}
DOES_NOT_ESTABLISH = (
    "repobrief_usefulness",
    "benchmark_completion",
    "provider_reliability_beyond_preflight",
    "answer_correctness_outside_selected_case",
    "default_promotion",
    "permission_to_dispatch_full_benchmark",
)


class PreflightError(ValueError):
    """The preflight contract or evidence is invalid."""


def _register_startup_code_identity(identity: Mapping[str, Any]) -> None:
    try:
        _record_startup_code_identity(identity)
    except RuntimeError as exc:
        raise PreflightError(str(exc)) from exc


def _register_startup_bootstrap_identity(identity: Mapping[str, Any]) -> None:
    global _STARTUP_BOOTSTRAP_IDENTITY
    expected_keys = {"schema_version", "kind", "name", "bytes", "sha256"}
    if (
        set(identity) != expected_keys
        or identity.get("schema_version") != CODEX_BOOTSTRAP_SCHEMA_VERSION
        or identity.get("kind") != CODEX_BOOTSTRAP_KIND
        or identity.get("name") != CODEX_BOOTSTRAP_PATH.name
        or not isinstance(identity.get("bytes"), int)
        or isinstance(identity.get("bytes"), bool)
        or int(identity["bytes"]) <= 0
        or not isinstance(identity.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(identity["sha256"])) is None
    ):
        raise PreflightError("Codex immutable source bootstrap identity is invalid")
    current = dict(identity)
    if (
        _STARTUP_BOOTSTRAP_IDENTITY is not None
        and _STARTUP_BOOTSTRAP_IDENTITY != current
    ):
        raise PreflightError("Codex immutable source bootstrap changed between loads")
    _STARTUP_BOOTSTRAP_IDENTITY = current


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _load_object(path: Path, *, maximum: int = runner.MAX_REQUEST_BYTES) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PreflightError(f"cannot read {path}") from exc
    if not raw or len(raw) > maximum:
        raise PreflightError(f"{path} is empty or oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError(f"{path} is not one UTF-8 JSON object") from exc
    if not isinstance(value, dict):
        raise PreflightError(f"{path} must contain one JSON object")
    return value


def _write_private_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    data = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise PreflightError(f"artifact already exists: {path.name}") from exc
    except OSError as exc:
        raise PreflightError(f"cannot create artifact: {path.name}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _write_report_artifacts(report_path: Path, value: Mapping[str, Any]) -> None:
    report_path = report_path.expanduser().resolve()
    digest_path = Path(str(report_path) + ".sha256")
    if report_path.exists() or digest_path.exists():
        raise PreflightError("report or digest path already exists")
    try:
        _write_private_exclusive(report_path, value)
        report_bytes = report_path.read_bytes()
        digest = (
            f"{_sha256_bytes(report_bytes)}  {report_path.name}\n"
        ).encode("ascii")
        descriptor = os.open(
            digest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(digest)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        report_path.unlink(missing_ok=True)
        digest_path.unlink(missing_ok=True)
        raise


def _remove_report_artifacts(report_path: Path) -> None:
    report_path = report_path.expanduser().resolve()
    digest_path = Path(str(report_path) + ".sha256")
    failures: list[str] = []
    for path in (digest_path, report_path):
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            failures.append(f"{path.name}:{type(exc).__name__}")
    try:
        descriptor = os.open(report_path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        failures.append(f"parent:{type(exc).__name__}")
    else:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            failures.append(f"parent-fsync:{type(exc).__name__}")
        finally:
            os.close(descriptor)
    if failures:
        raise PreflightError(
            "cannot remove incomplete preflight report artifacts: " + ",".join(failures)
        )


def _file_identity(
    path: Path,
    *,
    maximum: int,
    label: str,
    require_private: bool = False,
) -> dict[str, Any]:
    requested = path.expanduser()
    try:
        metadata = requested.lstat()
    except OSError as exc:
        raise PreflightError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PreflightError(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise PreflightError(f"{label} is empty or oversized")
    if require_private and metadata.st_mode & 0o077:
        raise PreflightError(f"{label} must not be group- or world-accessible")
    try:
        descriptor = _open_absolute_regular_nofollow(requested, label=label)
    except RuntimeError as exc:
        raise PreflightError(f"{label} could not be opened safely") from exc
    digest = hashlib.sha256()
    count = 0
    try:
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
            or current.st_size != metadata.st_size
        ):
            raise PreflightError(f"{label} changed during validation")
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if count > maximum:
                raise PreflightError(f"{label} is oversized")
            digest.update(chunk)
        final_descriptor = os.fstat(descriptor)
        try:
            descriptor_path = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError as exc:
            raise PreflightError(f"{label} opened path cannot be bound") from exc
        if (
            not os.path.isabs(descriptor_path)
            or descriptor_path.endswith(" (deleted)")
            or os.path.normpath(descriptor_path) != os.path.normpath(str(requested))
        ):
            raise PreflightError(f"{label} opened path is unavailable")
        try:
            final = requested.lstat()
        except OSError as exc:
            raise PreflightError(f"{label} disappeared during validation") from exc
        if (
            final_descriptor.st_dev != current.st_dev
            or final_descriptor.st_ino != current.st_ino
            or final_descriptor.st_size != current.st_size
            or final.st_dev != current.st_dev
            or final.st_ino != current.st_ino
            or final.st_size != current.st_size
            or count != current.st_size
        ):
            raise PreflightError(f"{label} changed during validation")
        return {
            "path": descriptor_path,
            "bytes": count,
            "sha256": digest.hexdigest(),
            "mode": oct(current.st_mode & 0o777),
        }
    finally:
        os.close(descriptor)


def _command_file_identities(
    command: Sequence[Any],
    *,
    relative_to: Path | None = None,
    executable_search_path: str | None = None,
) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    seen: set[str] = set()
    relative_root = None if relative_to is None else relative_to.expanduser().resolve()
    for index, raw in enumerate(command):
        if not isinstance(raw, str) or not raw:
            continue
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            if index == 0 and executable_search_path is not None:
                resolved_executable = shutil.which(raw, path=executable_search_path)
                if resolved_executable is None:
                    raise PreflightError("MCP command executable is unavailable on the runtime PATH")
                candidate = Path(resolved_executable)
            elif relative_root is None:
                continue
            else:
                candidate = relative_root / candidate
        if not candidate.exists():
            continue
        resolved = candidate.resolve()
        key = str(resolved)
        if key in seen or not resolved.is_file():
            continue
        seen.add(key)
        identities.append(
            _file_identity(
                resolved,
                maximum=runner.MAX_PROVIDER_EXECUTABLE_BYTES,
                label="MCP command file",
            )
        )
    return identities


def _dispatch_provider_binding(claude: str, synthetic: bool) -> dict[str, Any]:
    if synthetic:
        return {
            "mode": "synthetic_fixture",
            "claude_command": claude,
        }
    raise PreflightError("live preflight provider binding adapter is unavailable")


def _request_validation_runner(request: Mapping[str, Any]) -> Any:
    contract = request.get("runner")
    if not isinstance(contract, Mapping):
        raise PreflightError("request runner contract is invalid")
    provider = contract.get("provider")
    if provider == runner.PROVIDER:
        return runner
    if provider == "openai-codex-cli":
        codex_runner = _codex_runner_module()
        if contract.get("execution_contract") != codex_runner.EXECUTION_CONTRACT:
            raise PreflightError("Codex request execution contract mismatch")
        return codex_runner
    raise PreflightError("request provider is not supported by benchmark preflight")


def _validate_provider_request(request: Mapping[str, Any]) -> Any:
    selected = _request_validation_runner(request)
    try:
        selected.validate_request(request)
    except selected.RunnerError as exc:
        raise PreflightError(str(exc)) from exc
    return selected


def _preflight_code_identity(request: Mapping[str, Any]) -> dict[str, Any]:
    selected = _request_validation_runner(request)
    if selected is runner:
        paths = (
            Path(__file__).resolve(),
            Path(__file__).with_name("repobrief_agent_benchmark_preflight.py").resolve(),
            MODULE_PATH.resolve(),
        )
    else:
        paths = (
            Path(__file__).resolve(),
            CODEX_PREFLIGHT_PATH.resolve(),
            MODULE_PATH.resolve(),
            CODEX_BOOTSTRAP_PATH.resolve(),
            CODEX_MODULE_PATH.resolve(),
        )
    require_startup_binding = selected is not runner
    files: list[dict[str, Any]] = []
    for path in paths:
        current = _file_identity(
            path,
            maximum=MAX_LEDGER_ARTIFACT_BYTES,
            label=f"preflight code file {path.name}",
        )
        startup = (
            _STARTUP_BOOTSTRAP_IDENTITY
            if path == CODEX_BOOTSTRAP_PATH.resolve()
            else _STARTUP_CODE_IDENTITIES.get(str(path.resolve()))
        )
        if startup is not None:
            if (
                startup.get("name") != path.name
                or startup.get("bytes") != current.get("bytes")
                or startup.get("sha256") != current.get("sha256")
            ):
                raise PreflightError(
                    f"preflight code file changed after module load: {path.name}"
                )
        elif require_startup_binding:
            raise PreflightError(
                f"preflight code file lacks startup binding: {path.name}"
            )
        files.append(
            {
                "name": path.name,
                "bytes": current["bytes"],
                "sha256": current["sha256"],
            }
        )
    return {
        "files": files,
        "bundle_sha256": _sha256_json(files),
    }


def _dispatch_binding(
    *,
    baseline: Mapping[str, Any],
    treatment: Mapping[str, Any],
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_out: Path | None,
    claude: str,
    max_cost_usd: Decimal,
    validator_command: Sequence[str],
    synthetic: bool,
    provider_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    repobrief = treatment.get("repobrief")
    if not isinstance(repobrief, Mapping):
        raise PreflightError("treatment RepoBrief binding is unavailable")
    manifest_path = Path(str(repobrief.get("manifest")))
    mcp_command = repobrief.get("mcp_command")
    if not isinstance(mcp_command, list):
        raise PreflightError("treatment MCP command is unavailable")
    request_files = {
        condition: _file_identity(
            _request_path(request_root, request),
            maximum=runner.MAX_REQUEST_BYTES,
            label=f"{condition} request",
        )
        for condition, request in (
            ("baseline", baseline),
            ("treatment", treatment),
        )
    }
    report_path = None if report_out is None else report_out.expanduser().resolve()
    return {
        "pair_id": baseline["pair_id"],
        "pair_sha256": _sha256_json(
            {
                "baseline": baseline,
                "treatment": treatment,
            }
        ),
        "requests": {
            "baseline": {
                "request_id": baseline["request_id"],
                "sha256": _sha256_json(baseline),
                "file": request_files["baseline"],
            },
            "treatment": {
                "request_id": treatment["request_id"],
                "sha256": _sha256_json(treatment),
                "file": request_files["treatment"],
            },
        },
        "taskset_id": baseline["taskset_id"],
        "taskset_sha256": baseline["taskset_sha256"],
        "repository": baseline["repository"],
        "runner": baseline["runner"],
        "budgets": baseline["budgets"],
        "request_root": str(request_root.expanduser().resolve()),
        "repository_map": _file_identity(
            repository_map,
            maximum=runner.MAX_REQUEST_BYTES,
            label="repository map",
        ),
        "manifest": _file_identity(
            manifest_path,
            maximum=MAX_MANIFEST_BYTES,
            label="RepoBrief manifest",
        ),
        "mcp_command_sha256": _sha256_json(mcp_command),
        "mcp_command_files": _command_file_identities(
            mcp_command,
            relative_to=Path.cwd(),
            executable_search_path=(
                _request_validation_runner(treatment).provider_env().get("PATH")
                if treatment.get("runner", {}).get("provider") == "openai-codex-cli"
                else None
            ),
        ),
        "state_root": str(state_root.expanduser().resolve()),
        "transcript_root": str(transcript_root.expanduser().resolve()),
        "evidence_root": str(evidence_root.expanduser().resolve()),
        "report_out": None if report_path is None else str(report_path),
        "report_digest_out": (
            None if report_path is None else str(Path(str(report_path) + ".sha256"))
        ),
        "max_cost_usd": format(max_cost_usd, "f"),
        "max_provider_processes": 0 if synthetic else 2,
        "validator_command": list(validator_command),
        "validator_command_sha256": _sha256_json(list(validator_command)),
        "validator_command_files": _command_file_identities(validator_command),
        "synthetic_fixture": synthetic,
        "provider": (
            dict(provider_binding)
            if provider_binding is not None
            else _dispatch_provider_binding(claude, synthetic)
        ),
        "code": _preflight_code_identity(treatment),
    }


def _assert_dispatch_binding_unchanged(
    expected: Mapping[str, Any],
    *,
    pair_id: str,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_out: Path | None,
    claude: str,
    max_cost_usd: Decimal,
    validator_command: Sequence[str],
    synthetic: bool,
    provider_binding: Mapping[str, Any] | None = None,
) -> None:
    baseline, treatment = load_pair(request_root, pair_id)
    current = _dispatch_binding(
        baseline=baseline,
        treatment=treatment,
        request_root=request_root,
        repository_map=repository_map,
        state_root=state_root,
        transcript_root=transcript_root,
        evidence_root=evidence_root,
        report_out=report_out,
        claude=claude,
        max_cost_usd=max_cost_usd,
        validator_command=validator_command,
        synthetic=synthetic,
        provider_binding=provider_binding,
    )
    if _sha256_json(current) != _sha256_json(expected):
        raise PreflightError(
            "dispatch binding changed after authorization; provider start is blocked"
        )


def _assert_output_paths_available(
    *,
    baseline: Mapping[str, Any],
    treatment: Mapping[str, Any],
    transcript_root: Path,
    evidence_root: Path,
    report_out: Path | None,
) -> None:
    paths: list[tuple[str, Path]] = []
    for condition, request in (
        ("baseline", baseline),
        ("treatment", treatment),
    ):
        transcript_path, _artifact = runner._transcript_path(request, transcript_root)
        paths.extend(
            [
                (f"{condition} transcript", transcript_path),
                (f"{condition} receipt", _receipt_path(evidence_root, request)),
            ]
        )
    if report_out is not None:
        report_path = report_out.expanduser().resolve()
        paths.extend(
            [
                ("preflight report", report_path),
                ("preflight report digest", Path(str(report_path) + ".sha256")),
            ]
        )
    for label, path in paths:
        if path.is_symlink() or path.exists():
            raise PreflightError(f"{label} path already exists")


def _existing_ledger_reason(pair_root: Path, expected_sha256: str) -> str:
    authorization = pair_root / "authorization.json"
    try:
        existing = _load_object(authorization, maximum=MAX_LEDGER_ARTIFACT_BYTES)
    except PreflightError:
        return "dispatch ledger is incomplete; prior or ambiguous attempt blocks retry"
    if existing.get("contract_sha256") != expected_sha256:
        return (
            "dispatch ledger exists with a different schema, code, plan, path, or "
            "budget binding; retry is blocked"
        )
    return "dispatch ledger already exists; prior or ambiguous attempt blocks retry"


def _initialize_dispatch_ledger(
    *,
    binding: Mapping[str, Any],
    state_root: Path,
) -> dict[str, Any]:
    requested_root = state_root.expanduser()
    if requested_root.is_symlink():
        raise PreflightError("state root must not be a symlink")
    root = requested_root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not root.is_dir() or root.stat().st_mode & 0o077:
        raise PreflightError("state root must be a private directory")
    ledger_parent = root / "preflight-dispatch-ledger"
    if ledger_parent.is_symlink():
        raise PreflightError("dispatch ledger parent must not be a symlink")
    ledger_parent.mkdir(parents=False, exist_ok=True, mode=0o700)
    if not ledger_parent.is_dir() or ledger_parent.stat().st_mode & 0o077:
        raise PreflightError("dispatch ledger parent must be a private directory")
    contract_sha256 = _sha256_json(binding)
    pair_root = ledger_parent / hashlib.sha256(
        str(binding["pair_id"]).encode("utf-8")
    ).hexdigest()
    try:
        os.mkdir(pair_root, 0o700)
    except FileExistsError as exc:
        raise PreflightError(
            _existing_ledger_reason(pair_root, contract_sha256)
        ) from exc
    except OSError as exc:
        raise PreflightError("cannot create dispatch ledger") from exc
    events_root = pair_root / "events"
    try:
        os.mkdir(events_root, 0o700)
    except OSError as exc:
        raise PreflightError("cannot create dispatch ledger event directory") from exc
    return {
        "root": pair_root,
        "events_root": events_root,
        "pair_id": binding["pair_id"],
        "contract_sha256": contract_sha256,
        "authorization_sha256": None,
        "next_sequence": 0,
        "previous_event_sha256": contract_sha256,
        "condition_intents": [],
        "provider_process_intents": 0,
        "fixture_intents": 0,
        "observed_costs": {},
        "failure_recorded": False,
        "terminal_recorded": False,
    }


def _prepare_dispatch_publication(
    ledger: Mapping[str, Any], binding: Mapping[str, Any]
) -> dict[str, Any]:
    if _sha256_json(binding) != ledger["contract_sha256"]:
        raise PreflightError("dispatch authorization binding changed before publication")
    authorization_path = Path(ledger["root"]) / "authorization.json"
    if ledger.get("authorization_sha256") is not None or authorization_path.exists():
        raise PreflightError("dispatch authorization is already published")
    sequence = int(ledger["next_sequence"])
    event = {
        "kind": LEDGER_EVENT_KIND,
        "version": LEDGER_VERSION,
        "sequence": sequence,
        "event": "authorized",
        "recorded_at": _iso(_utc_now()),
        "pair_id": ledger["pair_id"],
        "contract_sha256": ledger["contract_sha256"],
        "previous_event_sha256": ledger["previous_event_sha256"],
        "payload": {
            "synthetic_fixture": bool(binding["synthetic_fixture"]),
            "max_provider_processes": int(binding["max_provider_processes"]),
        },
    }
    authorization = {
        "kind": LEDGER_KIND,
        "version": LEDGER_VERSION,
        "created_at": _iso(_utc_now()),
        "contract_sha256": ledger["contract_sha256"],
        "binding": dict(binding),
        "retry_permitted": False,
    }
    return {
        "event": event,
        "event_path": Path(ledger["events_root"]) / f"{sequence:04d}-authorized.json",
        "event_sha256": _sha256_json(event),
        "authorization": authorization,
        "authorization_path": authorization_path,
        "authorization_sha256": _sha256_json(authorization),
    }


def _dispatch_ledger_report_after_publication(
    ledger: Mapping[str, Any], publication: Mapping[str, Any]
) -> dict[str, Any]:
    report = _dispatch_ledger_report(ledger)
    report["authorization_sha256"] = publication["authorization_sha256"]
    report["event_count"] = int(ledger["next_sequence"]) + 1
    report["final_event_sha256"] = publication["event_sha256"]
    return report


def _dispatch_report_evidence_projection(
    report: Mapping[str, Any],
) -> dict[str, Any]:
    projected = json.loads(_canonical_json(report))
    ledger = projected.get("dispatch_ledger")
    if not isinstance(ledger, dict):
        raise PreflightError("dispatch report ledger is invalid")
    ledger["authorization_sha256"] = None
    return projected


def _bind_dispatch_report_evidence(
    publication: dict[str, Any],
    report: dict[str, Any],
) -> None:
    authorization = publication.get("authorization")
    ledger = report.get("dispatch_ledger")
    if not isinstance(authorization, dict) or not isinstance(ledger, dict):
        raise PreflightError("dispatch report evidence binding is invalid")
    authorization["report_evidence_sha256"] = _sha256_json(
        _dispatch_report_evidence_projection(report)
    )
    publication["authorization_sha256"] = _sha256_json(authorization)
    ledger["authorization_sha256"] = publication["authorization_sha256"]


def _publish_dispatch_authorization(
    ledger: dict[str, Any],
    binding: Mapping[str, Any],
    *,
    prepared: Mapping[str, Any] | None = None,
) -> None:
    publication = (
        _prepare_dispatch_publication(ledger, binding)
        if prepared is None
        else dict(prepared)
    )
    if _sha256_json(binding) != ledger["contract_sha256"]:
        raise PreflightError("dispatch authorization binding changed before publication")
    if publication.get("authorization_sha256") != _sha256_json(publication["authorization"]):
        raise PreflightError("prepared dispatch authorization identity is invalid")
    if publication.get("event_sha256") != _sha256_json(publication["event"]):
        raise PreflightError("prepared dispatch authorization event identity is invalid")
    if int(publication["event"].get("sequence", -1)) != int(ledger["next_sequence"]):
        raise PreflightError("prepared dispatch authorization sequence is stale")
    if publication["event"].get("previous_event_sha256") != ledger["previous_event_sha256"]:
        raise PreflightError("prepared dispatch authorization event chain is stale")
    authorization_path = Path(publication["authorization_path"])
    event_path = Path(publication["event_path"])
    if authorization_path.exists() or event_path.exists():
        raise PreflightError("dispatch authorization publication path already exists")

    # The report/digest is already durable at this point.  These are the final
    # create-only publication writes; no success-path persistence follows.
    _write_private_exclusive(event_path, publication["event"])
    ledger["next_sequence"] = int(ledger["next_sequence"]) + 1
    ledger["previous_event_sha256"] = publication["event_sha256"]
    _write_private_exclusive(authorization_path, publication["authorization"])
    ledger["authorization_sha256"] = publication["authorization_sha256"]

def _append_ledger_event(
    ledger: dict[str, Any], event_type: str, payload: Mapping[str, Any]
) -> dict[str, Any]:
    sequence = int(ledger["next_sequence"])
    event = {
        "kind": LEDGER_EVENT_KIND,
        "version": LEDGER_VERSION,
        "sequence": sequence,
        "event": event_type,
        "recorded_at": _iso(_utc_now()),
        "pair_id": ledger["pair_id"],
        "contract_sha256": ledger["contract_sha256"],
        "previous_event_sha256": ledger["previous_event_sha256"],
        "payload": dict(payload),
    }
    path = ledger["events_root"] / f"{sequence:04d}-{event_type}.json"
    _write_private_exclusive(path, event)
    event_sha256 = _sha256_json(event)
    ledger["next_sequence"] = sequence + 1
    ledger["previous_event_sha256"] = event_sha256
    return {
        "path": str(path),
        "sha256": event_sha256,
    }


def _record_dispatch_intent(
    ledger: dict[str, Any],
    request: Mapping[str, Any],
    *,
    synthetic: bool,
    max_cost_usd: Decimal,
) -> None:
    condition = str(request.get("condition"))
    if condition not in {"baseline", "treatment"}:
        raise PreflightError("dispatch intent condition is invalid")
    intents = ledger["condition_intents"]
    if condition in intents:
        raise PreflightError(f"dispatch intent already exists for {condition}")
    if len(intents) >= 2:
        raise PreflightError("dispatch ledger refuses a third process intent")
    intents.append(condition)
    if synthetic:
        ledger["fixture_intents"] = int(ledger["fixture_intents"]) + 1
    else:
        ledger["provider_process_intents"] = (
            int(ledger["provider_process_intents"]) + 1
        )
        if int(ledger["provider_process_intents"]) > 2:
            raise PreflightError("dispatch ledger refuses a third provider process")
    _append_ledger_event(
        ledger,
        "dispatch-intent",
        {
            "condition": condition,
            "request_id": request["request_id"],
            "request_sha256": _sha256_json(request),
            "process_index": len(intents),
            "synthetic_fixture": synthetic,
            "max_cost_usd": None if synthetic else format(max_cost_usd, "f"),
        },
    )


def _error_evidence(exc: BaseException) -> dict[str, Any]:
    raw = str(exc).encode("utf-8", errors="replace")
    return {
        "error_type": type(exc).__name__,
        "error_bytes": len(raw),
        "error_sha256": _sha256_bytes(raw),
    }


def _zero_provider_usage(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    token_fields = (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    )
    for field in token_fields:
        amount = value.get(field)
        if isinstance(amount, bool) or not isinstance(amount, int) or amount != 0:
            return False
    server_tools = value.get("server_tool_use")
    if not isinstance(server_tools, Mapping) or not server_tools:
        return False
    return all(
        not isinstance(amount, bool) and isinstance(amount, int) and amount == 0
        for amount in server_tools.values()
    )


def _provider_execution_classification(
    messages: Sequence[Mapping[str, Any]], result: Mapping[str, Any]
) -> dict[str, Any]:
    unknown = {
        "classification": "unknown_or_model_work_possible",
        "classification_grants_retry": False,
        "reason": "insufficient_immutable_evidence",
    }
    if result.get("is_error") is not True:
        return unknown
    if result.get("terminal_reason") != "api_error":
        return unknown
    status = result.get("api_error_status")
    if isinstance(status, bool) or not isinstance(status, int) or status != 429:
        return unknown
    duration_api_ms = result.get("duration_api_ms")
    if (
        isinstance(duration_api_ms, bool)
        or not isinstance(duration_api_ms, int)
        or duration_api_ms != 0
    ):
        return unknown
    if not _zero_provider_usage(result.get("usage")):
        return unknown
    try:
        cost = Decimal(str(result.get("total_cost_usd")))
    except Exception:
        return unknown
    if not cost.is_finite() or cost != 0:
        return unknown
    if result.get("modelUsage") != {}:
        return unknown
    subagents = result.get("subagent_stats")
    if not isinstance(subagents, Mapping):
        return unknown
    for field in ("spawned", "started_in_background", "completed", "failed"):
        amount = subagents.get(field)
        if isinstance(amount, bool) or not isinstance(amount, int) or amount != 0:
            return unknown
    allowed_message_types = {"system", "rate_limit_event", "assistant", "result"}
    if any(message.get("type") not in allowed_message_types for message in messages):
        return unknown
    rate_events = [message for message in messages if message.get("type") == "rate_limit_event"]
    if len(rate_events) != 1:
        return unknown
    rate_info = rate_events[0].get("rate_limit_info")
    if not isinstance(rate_info, Mapping) or rate_info.get("status") != "rejected":
        return unknown
    if rate_info.get("isUsingOverage") is not False:
        return unknown
    rate_limit_type = rate_info.get("rateLimitType")
    if not isinstance(rate_limit_type, str) or not rate_limit_type:
        return unknown
    assistants = [message for message in messages if message.get("type") == "assistant"]
    if len(assistants) != 1:
        return unknown
    assistant = assistants[0]
    nested = assistant.get("message")
    if not isinstance(nested, Mapping):
        return unknown
    if assistant.get("is_api_error_message") is not True or assistant.get("error") != "rate_limit":
        return unknown
    if nested.get("model") != "<synthetic>" or not _zero_provider_usage(nested.get("usage")):
        return unknown
    content = nested.get("content")
    if not isinstance(content, list) or not content:
        return unknown
    if any(not isinstance(block, Mapping) or block.get("type") != "text" for block in content):
        return unknown
    try:
        uses, tool_results = runner._tool_blocks(messages)
    except runner.RunnerError:
        return unknown
    if uses or tool_results:
        return unknown
    session_ids: set[str] = set()
    for message in messages:
        session_id = message.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            return unknown
        session_ids.add(session_id)
    if len(session_ids) != 1:
        return unknown
    return {
        "classification": "provider_refusal_before_model_execution",
        "classification_grants_retry": False,
        "reason": "explicit_rate_limit_rejection_zero_usage_zero_cost_no_model_or_tool_work",
        "api_error_status": status,
        "rate_limit_type": rate_limit_type,
    }


def _failure_transcript_summary(
    request: Mapping[str, Any], transcript_root: Path
) -> dict[str, Any]:
    path, artifact = runner._transcript_path(request, transcript_root)
    summary: dict[str, Any] = {
        "present": False,
        "artifact": artifact,
        "outcome_ambiguous": True,
        "observed_cost_usd": None,
        "provider_execution": {
            "classification": "unknown_or_model_work_possible",
            "classification_grants_retry": False,
            "reason": "insufficient_immutable_evidence",
        },
    }
    try:
        if path.is_symlink() or not path.is_file():
            return summary
        raw = path.read_bytes()
    except OSError:
        return summary
    if not raw or len(raw) > runner.MAX_TRANSCRIPT_BYTES:
        return summary
    summary.update(
        {
            "present": True,
            "bytes": len(raw),
            "sha256": _sha256_bytes(raw),
        }
    )
    try:
        messages = runner.parse_jsonl(raw)
    except runner.RunnerError:
        return summary
    results = [item for item in messages if item.get("type") == "result"]
    if len(results) != 1:
        return summary
    result = results[0]
    summary.update(
        {
            "outcome_ambiguous": False,
            "subtype": result.get("subtype"),
            "is_error": result.get("is_error"),
            "provider_execution": _provider_execution_classification(messages, result),
        }
    )
    try:
        cost = Decimal(str(result.get("total_cost_usd")))
    except Exception:
        return summary
    if cost.is_finite() and cost >= 0:
        summary["observed_cost_usd"] = format(cost, "f")
    return summary


def _record_condition_failure(
    ledger: dict[str, Any],
    request: Mapping[str, Any],
    transcript_root: Path,
    exc: BaseException,
) -> None:
    condition = str(request.get("condition"))
    transcript = _failure_transcript_summary(request, transcript_root)
    observed = transcript.get("observed_cost_usd")
    if isinstance(observed, str):
        ledger["observed_costs"][condition] = observed
    _append_ledger_event(
        ledger,
        "condition-failed",
        {
            "condition": condition,
            "request_id": request.get("request_id"),
            "error": _error_evidence(exc),
            "transcript": transcript,
        },
    )
    ledger["failure_recorded"] = True


def _record_condition_completed(
    ledger: dict[str, Any],
    request: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    synthetic: bool,
    observed_cost: Decimal | None,
) -> None:
    condition = str(request["condition"])
    if observed_cost is not None:
        ledger["observed_costs"][condition] = format(observed_cost, "f")
    _append_ledger_event(
        ledger,
        "condition-completed",
        {
            "condition": condition,
            "request_id": request["request_id"],
            "receipt_sha256": _sha256_json(receipt),
            "transcript": receipt.get("transcript"),
            "synthetic_fixture": synthetic,
            "observed_cost_usd": (
                None if observed_cost is None else format(observed_cost, "f")
            ),
        },
    )


def _record_preflight_failure(ledger: dict[str, Any], exc: BaseException) -> None:
    if ledger["terminal_recorded"]:
        return
    _append_ledger_event(
        ledger,
        "preflight-failed",
        {
            "error": _error_evidence(exc),
            "condition_intents": list(ledger["condition_intents"]),
            "provider_process_intents": int(ledger["provider_process_intents"]),
            "fixture_intents": int(ledger["fixture_intents"]),
            "observed_costs": dict(ledger["observed_costs"]),
            "retry_permitted": False,
        },
    )
    ledger["terminal_recorded"] = True


def _record_preflight_complete(
    ledger: dict[str, Any],
    *,
    total_observed: Decimal | None,
    source_after: Mapping[str, Any],
) -> None:
    _append_ledger_event(
        ledger,
        "preflight-evidence-complete",
        {
            "condition_intents": list(ledger["condition_intents"]),
            "provider_process_intents": int(ledger["provider_process_intents"]),
            "fixture_intents": int(ledger["fixture_intents"]),
            "total_observed_usd": (
                None if total_observed is None else format(total_observed, "f")
            ),
            "source_after_sha256": _sha256_json(source_after),
            "retry_permitted": False,
        },
    )
    ledger["terminal_recorded"] = True


def _dispatch_ledger_report(ledger: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "root": str(ledger["root"]),
        "authorization": str(ledger["root"] / "authorization.json"),
        "authorization_sha256": ledger["authorization_sha256"],
        "contract_sha256": ledger["contract_sha256"],
        "event_count": int(ledger["next_sequence"]),
        "final_event_sha256": ledger["previous_event_sha256"],
        "condition_intents": list(ledger["condition_intents"]),
        "provider_process_intents": int(ledger["provider_process_intents"]),
        "fixture_intents": int(ledger["fixture_intents"]),
        "observed_costs": dict(ledger["observed_costs"]),
        "retry_permitted": False,
    }


def _request_files(request_root: Path) -> list[Path]:
    if request_root.is_symlink():
        raise PreflightError("request root must not be a symlink")
    root = request_root.expanduser().resolve()
    if not root.is_dir():
        raise PreflightError("request root is not a directory")
    files = sorted(root.glob("*.json"))
    if len(files) > MAX_REQUEST_FILES:
        raise PreflightError("request root exceeds planned request limit")
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise PreflightError("request root contains an unsafe JSON entry")
    return files


def load_pair(request_root: Path, pair_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for path in _request_files(request_root):
        value = _load_object(path)
        if value.get("pair_id") == pair_id:
            matches.append(value)
    if len(matches) != 2:
        raise PreflightError(f"pair must contain exactly two planned requests, got {len(matches)}")
    by_condition = {str(item.get("condition")): item for item in matches}
    if set(by_condition) != {"baseline", "treatment"}:
        raise PreflightError("pair must contain baseline and treatment")
    baseline = by_condition["baseline"]
    treatment = by_condition["treatment"]
    baseline_runner = _validate_provider_request(baseline)
    treatment_runner = _validate_provider_request(treatment)
    if baseline_runner is not treatment_runner:
        raise PreflightError("paired requests use different provider contracts")
    _validate_pair(baseline, treatment)
    runner.load_planned_request(baseline, request_root)
    runner.load_planned_request(treatment, request_root)
    return baseline, treatment


def _validate_pair(baseline: Mapping[str, Any], treatment: Mapping[str, Any]) -> None:
    same_fields = (
        "pair_id",
        "case_id",
        "repetition",
        "taskset_id",
        "taskset_sha256",
        "prompt",
        "budgets",
        "runner",
        "repository",
    )
    for field in same_fields:
        if baseline.get(field) != treatment.get(field):
            raise PreflightError(f"paired requests disagree on {field}")
    if baseline.get("condition") != "baseline" or treatment.get("condition") != "treatment":
        raise PreflightError("pair conditions are invalid")
    if baseline.get("session_id") == treatment.get("session_id"):
        raise PreflightError("paired requests reuse session identity")
    if baseline.get("workspace_id") == treatment.get("workspace_id"):
        raise PreflightError("paired requests reuse workspace identity")
    orders = sorted([int(baseline.get("order", 0)), int(treatment.get("order", 0))])
    if orders != [1, 2]:
        raise PreflightError("pair order must contain 1 and 2")


def _git(command: Sequence[str], *, cwd: Path) -> str:
    environment = runner._git_environment()
    try:
        completed = subprocess.run(
            ["git", *command],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError(f"Git readback failed: {command[0]}") from exc
    return completed.stdout.strip()


def source_state(source: Path) -> dict[str, Any]:
    root = source.expanduser().resolve()
    if not root.is_dir() or not (root / ".git").exists():
        raise PreflightError("source root is not a Git checkout")
    head = _git(["rev-parse", "HEAD"], cwd=root)
    status = _git(["status", "--porcelain=v1", "--untracked-files=all"], cwd=root)
    index_path = Path(_git(["rev-parse", "--git-path", "index"], cwd=root))
    if not index_path.is_absolute():
        index_path = (root / index_path).resolve()
    try:
        index_bytes = index_path.read_bytes()
    except OSError as exc:
        raise PreflightError("cannot read Git index for integrity binding") from exc
    return {
        "root": str(root),
        "head": head,
        "clean": status == "",
        "status_sha256": _sha256_bytes(status.encode("utf-8")),
        "index_sha256": _sha256_bytes(index_bytes),
    }


def _assert_source_unchanged(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    for field in ("root", "head", "clean", "status_sha256", "index_sha256"):
        if before.get(field) != after.get(field):
            raise PreflightError(f"source checkout changed during preflight: {field}")


def _assert_source_matches_requested_commit(
    observed: Mapping[str, Any], request: Mapping[str, Any]
) -> None:
    repository = request.get("repository")
    expected = repository.get("commit") if isinstance(repository, Mapping) else None
    if (
        not isinstance(expected, str)
        or re.fullmatch(r"[0-9a-f]{40}", expected) is None
        or observed.get("head") != expected
    ):
        raise PreflightError(
            "source checkout HEAD does not match requested repository commit"
        )


def prepare_snapshot(treatment: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    started = time.monotonic()
    binding = treatment.get("repobrief")
    if not isinstance(binding, Mapping):
        raise PreflightError("treatment request has no RepoBrief binding")
    manifest = Path(str(binding.get("manifest", ""))).expanduser().resolve()
    try:
        with manifest.open("rb") as handle:
            data = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise PreflightError("bound RepoBrief manifest is unavailable") from exc
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise PreflightError("bound RepoBrief manifest is empty or oversized")
    expected = str(binding.get("manifest_sha256", ""))
    actual = _sha256_bytes(data)
    if actual != expected:
        raise PreflightError("bound RepoBrief manifest SHA-256 mismatch")
    elapsed = max(int((time.monotonic() - started) * 1000), 0)
    return {
        "manifest": str(manifest),
        "manifest_sha256": actual,
        "snapshot_reused": True,
        "snapshot_rebuilt": False,
    }, elapsed


def _readline_with_timeout(stream, *, timeout_seconds: float) -> bytes:
    ready, _, _ = select.select([stream], [], [], timeout_seconds)
    if not ready:
        raise PreflightError("RepoBrief MCP response timed out")
    line = stream.readline(MAX_MCP_LINE_BYTES + 1)
    if not line:
        raise PreflightError("RepoBrief MCP closed before responding")
    if len(line) > MAX_MCP_LINE_BYTES:
        raise PreflightError("RepoBrief MCP response is oversized")
    if not line.endswith(b"\n"):
        raise PreflightError("RepoBrief MCP response is not newline terminated")
    return line


def _rpc(process: subprocess.Popen, message: Mapping[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    if process.stdin is None or process.stdout is None:
        raise PreflightError("RepoBrief MCP pipes are unavailable")
    process.stdin.write((_canonical_json(message) + "\n").encode("utf-8"))
    process.stdin.flush()
    raw = _readline_with_timeout(process.stdout, timeout_seconds=timeout_seconds)
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError("RepoBrief MCP returned invalid JSON") from exc
    if (
        not isinstance(response, dict)
        or response.get("jsonrpc") != "2.0"
        or response.get("id") != message.get("id")
    ):
        raise PreflightError("RepoBrief MCP response envelope is invalid")
    has_result = "result" in response
    has_error = "error" in response
    if has_result == has_error:
        raise PreflightError("RepoBrief MCP response envelope is invalid")
    if has_error:
        raise PreflightError("RepoBrief MCP returned a JSON-RPC error")
    result = response.get("result")
    if not isinstance(result, dict):
        raise PreflightError("RepoBrief MCP result is not an object")
    return result


def _unprivileged_environment() -> dict[str, str]:
    allowed = {"PATH", "LANG", "LC_ALL", "TMPDIR"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment["HOME"] = "/nonexistent/repobrief-preflight"
    return environment


def _mcp_environment() -> dict[str, str]:
    return _unprivileged_environment()


def probe_freshness(treatment: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    binding = treatment.get("repobrief")
    if not isinstance(binding, Mapping):
        raise PreflightError("treatment request has no RepoBrief binding")
    command = binding.get("mcp_command")
    if not isinstance(command, list) or not command or not all(
        isinstance(item, str) and item for item in command
    ):
        raise PreflightError("treatment MCP command is invalid")
    environment = _mcp_environment()
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=environment,
        )
    except OSError as exc:
        raise PreflightError("RepoBrief MCP could not be started") from exc
    try:
        _rpc(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "repobrief-live-preflight", "version": VERSION},
                },
            },
            timeout_seconds=20,
        )
        result = _rpc(
            process,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "live_freshness",
                    "arguments": {"bundle_manifest": str(binding.get("manifest"))},
                },
            },
            timeout_seconds=30,
        )
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        stderr = b"" if process.stderr is None else process.stderr.read(runner.MAX_STDERR_BYTES + 1)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    if stderr:
        raise PreflightError(
            f"RepoBrief MCP stderr is non-empty: {_sha256_bytes(stderr)} ({len(stderr)} bytes)"
        )
    structured = result.get("structuredContent")
    if result.get("isError") is not False or not isinstance(structured, dict):
        raise PreflightError("RepoBrief MCP freshness call failed")
    status = structured.get("status")
    elapsed = max(int((time.monotonic() - started) * 1000), 0)
    return {
        "status": status,
        "reason": structured.get("reason"),
        "result_sha256": _sha256_json(structured),
        "stale_blocked": status != "fresh",
    }, elapsed


def _transcript_result(receipt: Mapping[str, Any], transcript_root: Path) -> Mapping[str, Any]:
    transcript = receipt.get("transcript")
    if not isinstance(transcript, Mapping):
        raise PreflightError("receipt transcript contract is missing")
    artifact = transcript.get("artifact")
    if not isinstance(artifact, str) or not artifact:
        raise PreflightError("receipt transcript artifact is missing")
    path = (transcript_root.expanduser().resolve() / artifact).resolve()
    try:
        path.relative_to(transcript_root.expanduser().resolve())
    except ValueError as exc:
        raise PreflightError("receipt transcript escapes transcript root") from exc
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PreflightError("receipt transcript cannot be read") from exc
    if _sha256_bytes(raw) != transcript.get("sha256") or len(raw) != transcript.get("bytes"):
        raise PreflightError("receipt transcript binding mismatch")
    messages = runner.parse_jsonl(raw)
    return runner._single_message(messages, message_type="result")


def _observed_cost(receipt: Mapping[str, Any], transcript_root: Path) -> Decimal:
    result = _transcript_result(receipt, transcript_root)
    value = result.get("total_cost_usd")
    try:
        cost = Decimal(str(value))
    except Exception as exc:
        raise PreflightError("provider total_cost_usd is unavailable") from exc
    if not cost.is_finite() or cost < 0:
        raise PreflightError("provider total_cost_usd is unavailable")
    return cost


def _validate_receipt_external(
    command_prefix: Sequence[str],
    *,
    request_path: Path,
    receipt_path: Path,
    transcript_root: Path,
) -> dict[str, Any]:
    command = [
        *command_prefix,
        "validate-receipt",
        "--request",
        str(request_path),
        "--receipt",
        str(receipt_path),
        "--transcript-root",
        str(transcript_root),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=120,
            shell=False,
            env=_unprivileged_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("RepoGround receipt validator could not run") from exc
    if len(completed.stdout) > MAX_VALIDATOR_OUTPUT_BYTES or len(completed.stderr) > MAX_VALIDATOR_OUTPUT_BYTES:
        raise PreflightError("RepoGround receipt validator output is oversized")
    if completed.returncode != 0:
        raise PreflightError("RepoGround receipt validation failed")
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError("RepoGround receipt validator returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("status") != "valid":
        raise PreflightError("RepoGround receipt validator did not confirm validity")
    return value


def _tool_requirement(receipt: Mapping[str, Any], *, treatment: bool) -> None:
    calls = receipt.get("tool_calls")
    if not isinstance(calls, list):
        raise PreflightError("receipt tool_calls are invalid")
    names = {item.get("name") for item in calls if isinstance(item, Mapping)}
    if treatment and not names.intersection(REPOBRIEF_ABSTRACT_TOOLS):
        raise PreflightError("treatment used no RepoBrief tool or resource")
    if not treatment and names.intersection(REPOBRIEF_ABSTRACT_TOOLS):
        raise PreflightError("baseline used a RepoBrief tool")


def _request_path(request_root: Path, request: Mapping[str, Any]) -> Path:
    matches = [
        path
        for path in _request_files(request_root)
        if _load_object(path).get("request_id") == request.get("request_id")
    ]
    if len(matches) != 1:
        raise PreflightError("cannot resolve unique planned request path")
    return matches[0]


def _receipt_path(evidence_root: Path, request: Mapping[str, Any]) -> Path:
    filename = hashlib.sha256(str(request["request_id"]).encode("utf-8")).hexdigest() + ".receipt.json"
    return evidence_root.resolve() / "receipts" / filename


def _executable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_executable_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise PreflightError("Claude executable must be a regular file")
    if metadata.st_size <= 0:
        raise PreflightError("Claude executable is empty")
    if metadata.st_size > runner.MAX_PROVIDER_EXECUTABLE_BYTES:
        raise PreflightError("Claude executable exceeds maximum size")
    if metadata.st_mode & 0o111 == 0:
        raise PreflightError("Claude executable is not executable")


def _claude_identity(claude: str) -> dict[str, Any]:
    executable = shutil.which(claude)
    if executable is None:
        raise PreflightError("Claude executable cannot be resolved")
    try:
        resolved = Path(executable).expanduser().resolve(strict=True)
        path_metadata = resolved.lstat()
    except (OSError, RuntimeError) as exc:
        raise PreflightError("Claude executable cannot be resolved safely") from exc
    if stat.S_ISLNK(path_metadata.st_mode):
        raise PreflightError("Claude executable resolved to a symbolic link")
    _validate_executable_metadata(path_metadata)
    expected_identity = _executable_file_identity(path_metadata)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise PreflightError("Claude executable cannot be opened safely") from exc
    digest = hashlib.sha256()
    total_bytes = 0
    try:
        try:
            opened_metadata = os.fstat(descriptor)
            _validate_executable_metadata(opened_metadata)
            if _executable_file_identity(opened_metadata) != expected_identity:
                raise PreflightError("Claude executable changed before hashing")
            while True:
                chunk = os.read(descriptor, EXECUTABLE_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > runner.MAX_PROVIDER_EXECUTABLE_BYTES:
                    raise PreflightError("Claude executable exceeds maximum size")
                digest.update(chunk)
            final_descriptor_metadata = os.fstat(descriptor)
        except OSError as exc:
            raise PreflightError("Claude executable cannot be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        final_path_metadata = resolved.lstat()
    except OSError as exc:
        raise PreflightError("Claude executable disappeared during hashing") from exc
    if (
        _executable_file_identity(final_descriptor_metadata) != expected_identity
        or _executable_file_identity(final_path_metadata) != expected_identity
        or total_bytes != path_metadata.st_size
    ):
        raise PreflightError("Claude executable changed during hashing")
    return {
        "command": claude,
        "resolved_path": str(resolved),
        "bytes": total_bytes,
        "sha256": digest.hexdigest(),
        "version": None,
        "version_probed": False,
    }


def authorize_dispatch(
    *,
    pair_id: str,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_out: Path | None,
    provider_binding: Mapping[str, Any],
    max_cost_usd: Decimal,
    validator_command: Sequence[str],
) -> dict[str, Any]:
    """Create one live provider dispatch authorization without launching a provider."""

    if (
        not max_cost_usd.is_finite()
        or max_cost_usd <= 0
        or max_cost_usd > MAX_PER_RUN_COST_USD
    ):
        raise PreflightError(f"max cost must be finite, > 0 and <= {MAX_PER_RUN_COST_USD}")
    if report_out is None:
        raise PreflightError("live dispatch authorization requires a durable report output")
    if not isinstance(provider_binding, Mapping) or provider_binding.get("mode") != "live_provider":
        raise PreflightError("live provider binding is invalid")
    baseline, treatment = load_pair(request_root, pair_id)
    provider_runner = provider_binding.get("runner")
    if (
        not isinstance(provider_runner, Mapping)
        or _canonical_json(provider_runner) != _canonical_json(treatment.get("runner"))
    ):
        raise PreflightError(
            "live provider binding does not match treatment runner contract"
        )
    binding = _dispatch_binding(
        baseline=baseline,
        treatment=treatment,
        request_root=request_root,
        repository_map=repository_map,
        state_root=state_root,
        transcript_root=transcript_root,
        evidence_root=evidence_root,
        report_out=report_out,
        claude="",
        max_cost_usd=max_cost_usd,
        validator_command=validator_command,
        synthetic=False,
        provider_binding=provider_binding,
    )
    ledger = _initialize_dispatch_ledger(binding=binding, state_root=state_root)
    report_persisted = False
    try:
        _assert_output_paths_available(
            baseline=baseline,
            treatment=treatment,
            transcript_root=transcript_root,
            evidence_root=evidence_root,
            report_out=report_out,
        )
        source = runner.load_repository_root(baseline, repository_map)
        before = source_state(source)
        _assert_source_matches_requested_commit(before, baseline)
        snapshot, snapshot_preparation_ms = prepare_snapshot(treatment)
        freshness, freshness_check_ms = probe_freshness(treatment)
        if freshness["status"] != "fresh":
            raise PreflightError(
                f"treatment snapshot is not fresh: {freshness['status']}"
            )
        after = source_state(source)
        _assert_source_unchanged(before, after)
        _assert_dispatch_binding_unchanged(
            binding,
            pair_id=pair_id,
            request_root=request_root,
            repository_map=repository_map,
            state_root=state_root,
            transcript_root=transcript_root,
            evidence_root=evidence_root,
            report_out=report_out,
            claude="",
            max_cost_usd=max_cost_usd,
            validator_command=validator_command,
            synthetic=False,
            provider_binding=provider_binding,
        )

        publication = _prepare_dispatch_publication(ledger, binding)
        report = {
            "kind": "repobrief.agent_benchmark_preflight_dispatch_authorization",
            "version": VERSION,
            "status": "authorized",
            "pair_id": pair_id,
            "synthetic_fixture": False,
            "dispatch_ledger": _dispatch_ledger_report_after_publication(ledger, publication),
            "request_sha256": {
                "baseline": _sha256_json(baseline),
                "treatment": _sha256_json(treatment),
            },
            "snapshot": {**snapshot, **freshness},
            "source_before": before,
            "source_after": after,
            "timings": {
                "snapshot_preparation_ms": snapshot_preparation_ms,
                "freshness_check_ms": freshness_check_ms,
            },
            "provider": dict(provider_binding),
            "default_promoted": False,
            "does_not_establish": list(DOES_NOT_ESTABLISH),
        }
        _bind_dispatch_report_evidence(publication, report)

        # Durable producer evidence must exist before the capability becomes
        # consumable.  A report/digest failure therefore leaves no authorization.
        _write_report_artifacts(report_out, report)
        report_persisted = True

        publication_source = source_state(source)
        _assert_source_unchanged(before, publication_source)
        _assert_dispatch_binding_unchanged(
            binding,
            pair_id=pair_id,
            request_root=request_root,
            repository_map=repository_map,
            state_root=state_root,
            transcript_root=transcript_root,
            evidence_root=evidence_root,
            report_out=report_out,
            claude="",
            max_cost_usd=max_cost_usd,
            validator_command=validator_command,
            synthetic=False,
            provider_binding=provider_binding,
        )
        _publish_dispatch_authorization(ledger, binding, prepared=publication)
        return report
    except BaseException as exc:
        cleanup_error: BaseException | None = None
        if report_persisted and ledger.get("authorization_sha256") is None:
            try:
                _remove_report_artifacts(report_out)
            except BaseException as report_cleanup_exc:
                cleanup_error = report_cleanup_exc
        _record_preflight_failure(ledger, cleanup_error or exc)
        if cleanup_error is not None:
            raise cleanup_error from exc
        raise

def execute_preflight(
    *,
    pair_id: str,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_out: Path | None = None,
    claude: str,
    max_cost_usd: Decimal,
    validator_command: Sequence[str],
    baseline_fixture: Path | None = None,
    treatment_fixture: Path | None = None,
) -> dict[str, Any]:
    if max_cost_usd <= 0 or max_cost_usd > MAX_PER_RUN_COST_USD:
        raise PreflightError(f"max cost must be > 0 and <= {MAX_PER_RUN_COST_USD}")
    if (baseline_fixture is None) != (treatment_fixture is None):
        raise PreflightError("fixtures must be supplied for both conditions or neither")
    synthetic = baseline_fixture is not None
    started_at = _utc_now()
    total_started = time.monotonic()
    baseline, treatment = load_pair(request_root, pair_id)
    binding = _dispatch_binding(
        baseline=baseline,
        treatment=treatment,
        request_root=request_root,
        repository_map=repository_map,
        state_root=state_root,
        transcript_root=transcript_root,
        evidence_root=evidence_root,
        report_out=report_out,
        claude=claude,
        max_cost_usd=max_cost_usd,
        validator_command=validator_command,
        synthetic=synthetic,
    )
    ledger = _initialize_dispatch_ledger(binding=binding, state_root=state_root)
    try:
        _assert_output_paths_available(
            baseline=baseline,
            treatment=treatment,
            transcript_root=transcript_root,
            evidence_root=evidence_root,
            report_out=report_out,
        )
        source = runner.load_repository_root(baseline, repository_map)
        before = source_state(source)
        _assert_source_matches_requested_commit(before, baseline)
        snapshot, snapshot_preparation_ms = prepare_snapshot(treatment)
        freshness, freshness_check_ms = probe_freshness(treatment)
        if freshness["status"] != "fresh":
            raise PreflightError(
                f"treatment snapshot is not fresh: {freshness['status']}"
            )
        claude_identity = (
            {
                "command": claude,
                "resolved_path": None,
                "bytes": None,
                "sha256": None,
                "version": "synthetic-fixture",
            }
            if synthetic
            else _claude_identity(claude)
        )
        authorization_source = source_state(source)
        _assert_source_unchanged(before, authorization_source)
        _assert_dispatch_binding_unchanged(
            binding,
            pair_id=pair_id,
            request_root=request_root,
            repository_map=repository_map,
            state_root=state_root,
            transcript_root=transcript_root,
            evidence_root=evidence_root,
            report_out=report_out,
            claude=claude,
            max_cost_usd=max_cost_usd,
            validator_command=validator_command,
            synthetic=synthetic,
        )
        _publish_dispatch_authorization(ledger, binding)

        ordered = sorted([baseline, treatment], key=lambda item: int(item["order"]))
        fixture_by_condition = {
            "baseline": baseline_fixture,
            "treatment": treatment_fixture,
        }
        receipts: dict[str, dict[str, Any]] = {}
        receipt_paths: dict[str, Path] = {}
        observed_costs: dict[str, Decimal] = {}
        validations: dict[str, dict[str, Any]] = {}
        agent_execution_ms = 0
        runner_execution_ms = 0
        for request in ordered:
            condition = str(request["condition"])
            _assert_dispatch_binding_unchanged(
                binding,
                pair_id=pair_id,
                request_root=request_root,
                repository_map=repository_map,
                state_root=state_root,
                transcript_root=transcript_root,
                evidence_root=evidence_root,
                report_out=report_out,
                claude=claude,
                max_cost_usd=max_cost_usd,
                validator_command=validator_command,
                synthetic=synthetic,
            )
            _record_dispatch_intent(
                ledger,
                request,
                synthetic=synthetic,
                max_cost_usd=max_cost_usd,
            )
            try:
                run_started = time.monotonic()
                output = runner.execute(
                    request,
                    request_root=request_root,
                    repository_map=repository_map,
                    state_root=state_root,
                    transcript_root=transcript_root,
                    claude=claude,
                    max_cost_usd=max_cost_usd,
                    stream_fixture=fixture_by_condition[condition],
                )
                runner_execution_ms += max(
                    int((time.monotonic() - run_started) * 1000), 0
                )
                if synthetic:
                    if output.get("kind") != runner.FIXTURE_REPORT_KIND:
                        raise PreflightError(
                            "fixture run did not return fixture report"
                        )
                    candidate = output.get("normalized_candidate")
                    if not isinstance(candidate, dict):
                        raise PreflightError(
                            "fixture report has no normalized candidate"
                        )
                    receipt = candidate
                else:
                    if output.get("kind") != runner.RECEIPT_KIND:
                        raise PreflightError("live run did not return real receipt")
                    receipt = output
                agent_execution_ms += int(receipt.get("duration_ms") or 0)
                _tool_requirement(receipt, treatment=condition == "treatment")
                receipt_path = _receipt_path(evidence_root, request)
                _write_private_exclusive(receipt_path, receipt)
                receipt_paths[condition] = receipt_path
                receipts[condition] = receipt
                observed_cost: Decimal | None = None
                if not synthetic:
                    validations[condition] = _validate_receipt_external(
                        validator_command,
                        request_path=_request_path(request_root, request),
                        receipt_path=receipt_path,
                        transcript_root=transcript_root,
                    )
                    observed_cost = _observed_cost(receipt, transcript_root)
                    observed_costs[condition] = observed_cost
                _record_condition_completed(
                    ledger,
                    request,
                    receipt,
                    synthetic=synthetic,
                    observed_cost=observed_cost,
                )
            except BaseException as exc:
                _record_condition_failure(ledger, request, transcript_root, exc)
                raise

        _assert_dispatch_binding_unchanged(
            binding,
            pair_id=pair_id,
            request_root=request_root,
            repository_map=repository_map,
            state_root=state_root,
            transcript_root=transcript_root,
            evidence_root=evidence_root,
            report_out=report_out,
            claude=claude,
            max_cost_usd=max_cost_usd,
            validator_command=validator_command,
            synthetic=synthetic,
        )
        total_observed = sum(observed_costs.values(), Decimal("0"))
        total_authorized = max_cost_usd * 2
        if not synthetic and total_observed > total_authorized:
            raise PreflightError(
                "total observed provider cost exceeds preflight ceiling"
            )
        after = source_state(source)
        _assert_source_unchanged(before, after)
        ended_at = _utc_now()
        total_time_to_answer_ms = max(
            int((time.monotonic() - total_started) * 1000), 0
        )
        _record_preflight_complete(
            ledger,
            total_observed=None if synthetic else total_observed,
            source_after=after,
        )

        report = {
            "kind": FIXTURE_REPORT_KIND if synthetic else REPORT_KIND,
            "version": VERSION,
            "status": "synthetic_only" if synthetic else "valid",
            "pair_id": pair_id,
            "synthetic_fixture": synthetic,
            "started_at": _iso(started_at),
            "ended_at": _iso(ended_at),
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "claude": claude_identity,
                "validator_command_sha256": _sha256_json(
                    list(validator_command)
                ),
            },
            "dispatch_ledger": _dispatch_ledger_report(ledger),
            "cost": {
                "per_run_authorized_usd": format(max_cost_usd, "f"),
                "total_authorized_usd": format(total_authorized, "f"),
                "baseline_observed_usd": (
                    None
                    if synthetic
                    else format(observed_costs["baseline"], "f")
                ),
                "treatment_observed_usd": (
                    None
                    if synthetic
                    else format(observed_costs["treatment"], "f")
                ),
                "total_observed_usd": (
                    None if synthetic else format(total_observed, "f")
                ),
            },
            "timings": {
                "snapshot_preparation_ms": snapshot_preparation_ms,
                "freshness_check_ms": freshness_check_ms,
                "agent_execution_ms": agent_execution_ms,
                "runner_execution_ms": runner_execution_ms,
                "total_time_to_answer_ms": total_time_to_answer_ms,
            },
            "snapshot": {**snapshot, **freshness},
            "source_before": before,
            "source_after": after,
            "runs": {
                condition: {
                    "request_id": request["request_id"],
                    "request_sha256": _sha256_json(request),
                    "receipt": str(receipt_paths[condition]),
                    "receipt_sha256": _sha256_json(receipts[condition]),
                    "transcript": receipts[condition]["transcript"],
                    "repoground_validation_sha256": (
                        None
                        if synthetic
                        else _sha256_json(validations[condition])
                    ),
                }
                for condition, request in (
                    ("baseline", baseline),
                    ("treatment", treatment),
                )
            },
            "default_promoted": False,
            "does_not_establish": list(DOES_NOT_ESTABLISH),
        }
        return report
    except BaseException as exc:
        _record_preflight_failure(ledger, exc)
        raise


def _command_array(path: Path) -> list[str]:
    value = _load_object(path) if path.suffix == ".json" else None
    if value is not None:
        command = value.get("command")
    else:
        command = None
    if not isinstance(command, list) or not command or not all(
        isinstance(item, str) and item for item in command
    ):
        raise PreflightError("validator command file must contain a non-empty command array")
    return command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one bounded RepoBrief live preflight pair.",
        allow_abbrev=False,
    )
    parser.add_argument("--pair-id", required=True)
    parser.add_argument("--request-root", required=True, type=Path)
    parser.add_argument("--repository-map", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--transcript-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--report-out", required=True, type=Path)
    parser.add_argument("--validator-command", required=True, type=Path)
    parser.add_argument("--claude-command", default="claude")
    parser.add_argument("--max-cost-usd", required=True)
    parser.add_argument("--baseline-stream-fixture", type=Path)
    parser.add_argument("--treatment-stream-fixture", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        max_cost = runner._require_cost(
            args.max_cost_usd,
            "max_cost_usd",
            maximum=MAX_PER_RUN_COST_USD,
        )
        report = execute_preflight(
            pair_id=args.pair_id,
            request_root=args.request_root,
            repository_map=args.repository_map,
            state_root=args.state_root,
            transcript_root=args.transcript_root,
            evidence_root=args.evidence_root,
            report_out=args.report_out,
            claude=args.claude_command,
            max_cost_usd=max_cost,
            validator_command=_command_array(args.validator_command),
            baseline_fixture=args.baseline_stream_fixture,
            treatment_fixture=args.treatment_stream_fixture,
        )
        _write_report_artifacts(args.report_out, report)
    except (PreflightError, runner.RunnerError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
