#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import stat as statmod
import sys
import tempfile

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

APP_NAME = "Grabowski"
HOME = Path.home().resolve()
STATE_DIR = HOME / ".local" / "state" / "grabowski"
POLICY_PATH = HOME / ".config" / "grabowski" / "access.json"
AUDIT_LOG = STATE_DIR / "write-audit.jsonl"
BUNDLE_REGISTRY = STATE_DIR / "rlens-latest-complete-bundles.tsv"

def _deployment_manifest_path() -> Path:
    executable = Path(sys.executable)
    if executable.parent.name == "bin" and executable.parent.parent.name == ".venv":
        return executable.parent.parent.parent / "deployment-manifest.json"
    return Path(__file__).resolve().parent / "deployment-manifest.json"


DEPLOYMENT_MANIFEST = _deployment_manifest_path()
EXPECTED_STABLE_RUNTIME = HOME / ".local" / "share" / "grabowski-mcp"
DEPLOYMENT_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONTRACT_BYTES = 64 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

mcp = FastMCP(APP_NAME)

READ_ANNOTATIONS = ToolAnnotations(
    title="Read local data",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
CREATE_ANNOTATIONS = ToolAnnotations(
    title="Create local text file",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
REPLACE_ANNOTATIONS = ToolAnnotations(
    title="Replace local text file",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)


def _load_policy() -> dict[str, Any]:
    try:
        raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Access policy missing: {POLICY_PATH}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Access policy is invalid JSON: {exc}") from exc

    required = {"read_roots", "write_roots", "max_read_bytes", "max_write_bytes"}
    missing = sorted(required.difference(raw))
    if missing:
        raise RuntimeError(f"Access policy missing keys: {missing}")
    return raw


def _roots(kind: str) -> list[Path]:
    policy = _load_policy()
    values = policy[f"{kind}_roots"]
    roots: list[Path] = []
    for value in values:
        root = Path(value).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise RuntimeError(f"Configured {kind} root is not a directory: {root}")
        roots.append(root)
    return roots


def _is_within(path: Path, roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _excluded_roots(kind: str) -> list[Path]:
    policy = _load_policy()
    values = policy.get(f"{kind}_excluded_roots", [])
    roots: list[Path] = []

    for value in values:
        root = Path(value).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise RuntimeError(
                f"Configured {kind} excluded root is not a directory: {root}"
            )
        roots.append(root)

    return roots


def _reject_sensitive(path: Path) -> None:
    policy = _load_policy()
    forbidden_components = set(policy.get("forbidden_components", []))
    forbidden_patterns = list(policy.get("forbidden_file_patterns", []))

    for component in path.parts:
        if component in forbidden_components:
            raise PermissionError(f"Forbidden path component: {component}")

    name = path.name
    for pattern in forbidden_patterns:
        if fnmatch(name, pattern):
            raise PermissionError(f"Forbidden file pattern: {pattern}")


def _reject_symlink_components(path: Path, allow_missing_leaf: bool = False) -> None:
    policy = _load_policy()
    if not policy.get("forbid_symlinks", True):
        return

    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current = current / part
        is_leaf = index == len(parts) - 1
        if current.is_symlink():
            raise PermissionError(f"Symlink paths are forbidden: {current}")
        if not current.exists():
            if allow_missing_leaf and is_leaf:
                return
            raise FileNotFoundError(str(current))


def _absolute_candidate(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Path must be absolute")
    _reject_sensitive(candidate)
    return candidate


def _resolve_existing(raw_path: str, kind: str) -> Path:
    candidate = _absolute_candidate(raw_path)
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not _is_within(resolved, _roots(kind)):
        raise PermissionError(f"Path is outside configured {kind} roots: {resolved}")
    return resolved


def _resolve_write_target(raw_path: str) -> tuple[Path, bool]:
    candidate = _absolute_candidate(raw_path)
    if candidate.exists() or candidate.is_symlink():
        _reject_symlink_components(candidate)
        resolved = candidate.resolve(strict=True)
        exists = True
    else:
        _reject_symlink_components(candidate, allow_missing_leaf=True)
        parent = candidate.parent.resolve(strict=True)
        resolved = parent / candidate.name
        exists = False

    if not _is_within(resolved, _roots("write")):
        raise PermissionError(f"Path is outside configured write roots: {resolved}")

    if _is_within(resolved, _excluded_roots("write")):
        raise PermissionError(f"Path is explicitly read-only: {resolved}")

    return resolved, exists


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_regular_text_file(path: Path, max_bytes: int) -> bytes:
    st = path.stat()
    if not statmod.S_ISREG(st.st_mode):
        raise ValueError(f"Not a regular file: {path}")
    if st.st_size > max_bytes:
        raise ValueError(f"File exceeds byte limit ({st.st_size} > {max_bytes})")
    data = path.read_bytes()
    if b"\x00" in data:
        raise ValueError("Binary/NUL-containing files are not allowed")
    return data


def _append_audit(record: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


_DEPLOYMENT_IDENTITY_KEYS = (
    "manifest_parse_valid",
    "manifest_schema_valid",
    "release_path_valid",
    "release_id_valid",
    "repo_head_valid",
    "stable_runtime_manifest_valid",
    "runtime_pointer_valid",
    "runtime_input_identity_valid",
    "lock_identity_valid",
    "source_snapshot_identity_valid",
    "source_identity_valid",
    "embedded_contract_valid",
    "entrypoint_contract_identity_valid",
    "entrypoint_path_valid",
    "release_python_identity_valid",
    "executable_identity_valid",
    "pip_identity_valid",
    "protocol_identity_valid",
    "python_runtime_identity_valid",
    "platform_identity_valid",
    "artifact_integrity_valid",
    "runtime_binding_valid",
    "environment_compatibility_valid",
)


def _false_deployment_metadata(base: dict[str, Any], **extra: Any) -> dict[str, Any]:
    result = {**base}
    for key in _DEPLOYMENT_IDENTITY_KEYS:
        result[key] = False
    result["provenance_valid"] = False
    result.update(extra)
    return result


def _path_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in "0123456789abcdef" for char in value)
    )


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and path.as_posix() != "."


def _manifest_schema_valid(raw: dict[str, Any]) -> bool:
    required = {
        "schema_version": int,
        "release_id": str,
        "repo_head": str,
        "entrypoint_contract": dict,
        "entrypoint_contract_sha256": str,
        "source_sha256": str,
        "source_sha256s": dict,
        "runtime_input_sha256": str,
        "runtime_lock_sha256": str,
        "snapshot_paths": dict,
        "immutable_release_path": str,
        "expected_stable_runtime_path": str,
        "release_python_path": str,
        "entrypoint_path": str,
        "module_paths": dict,
        "platform": str,
        "python_version": str,
        "python_implementation": str,
        "mcp_protocol_version": str,
        "created_at_unix": int,
        "completion_status": str,
        "executable": str,
        "pip_version": str,
    }
    for key, kind in required.items():
        value = raw.get(key)
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            return False
    if raw.get("schema_version") != 4 or raw.get("completion_status") != "complete":
        return False
    if not _is_hex(raw.get("repo_head"), 40):
        return False
    for key in (
        "entrypoint_contract_sha256",
        "source_sha256",
        "runtime_input_sha256",
        "runtime_lock_sha256",
    ):
        if not _is_hex(raw.get(key), 64):
            return False
    contract = raw.get("entrypoint_contract")
    if not isinstance(contract, dict):
        return False
    schema_version = contract.get("schema_version")
    expected_keys = {"schema_version", "mode", "module", "source", "expected_tools"}
    if schema_version == 2:
        expected_keys.add("supporting_sources")
    if schema_version not in {1, 2} or set(contract) != expected_keys:
        return False
    module = contract.get("module")
    source = contract.get("source")
    if (
        contract.get("mode") != "module"
        or not isinstance(module, str)
        or MODULE_RE.fullmatch(module) is None
        or not _safe_relative_path(source)
    ):
        return False
    tools = contract.get("expected_tools")
    if (
        not isinstance(tools, list)
        or not tools
        or not all(isinstance(item, str) and item for item in tools)
        or len(set(tools)) != len(tools)
    ):
        return False
    modules = {module}
    sources = {source}
    supporting_modules: set[str] = set()
    supporting = contract.get("supporting_sources", [])
    if not isinstance(supporting, list):
        return False
    for item in supporting:
        if not isinstance(item, dict) or set(item) != {"module", "source"}:
            return False
        item_module = item.get("module")
        item_source = item.get("source")
        if (
            not isinstance(item_module, str)
            or MODULE_RE.fullmatch(item_module) is None
            or item_module in modules
            or not _safe_relative_path(item_source)
            or item_source in sources
        ):
            return False
        modules.add(item_module)
        supporting_modules.add(item_module)
        sources.add(item_source)
    hashes = raw.get("source_sha256s")
    if (
        not isinstance(hashes, dict)
        or set(hashes) != modules
        or not all(_is_hex(value, 64) for value in hashes.values())
        or hashes.get(module) != raw.get("source_sha256")
    ):
        return False
    module_paths = raw.get("module_paths")
    if (
        not isinstance(module_paths, dict)
        or set(module_paths) != modules
        or not all(isinstance(value, str) and value for value in module_paths.values())
        or module_paths.get(module) != raw.get("entrypoint_path")
    ):
        return False
    snapshot_paths = raw.get("snapshot_paths")
    if not isinstance(snapshot_paths, dict) or set(snapshot_paths) != {
        "runtime_entrypoint", "runtime_input", "runtime_lock", "source",
        "supporting_sources",
    }:
        return False
    if not all(
        isinstance(snapshot_paths.get(key), str) and snapshot_paths.get(key)
        for key in ("runtime_entrypoint", "runtime_input", "runtime_lock", "source")
    ):
        return False
    support_paths = snapshot_paths.get("supporting_sources")
    if (
        not isinstance(support_paths, dict)
        or set(support_paths) != supporting_modules
        or not all(isinstance(value, str) and value for value in support_paths.values())
    ):
        return False
    created = raw.get("created_at_unix")
    return isinstance(created, int) and not isinstance(created, bool) and created > 0


def _read_bound_regular_file(
    recorded: Any,
    expected: Path,
    release_root: Path,
    *,
    max_bytes: int,
) -> bytes | None:
    """Read only the exact expected regular file after binding path and inode."""
    if not isinstance(recorded, str) or Path(recorded) != expected:
        return None
    fd: int | None = None
    try:
        release_real = release_root.resolve(strict=True)
        parent_real = expected.parent.resolve(strict=True)
        if not _path_inside(parent_real, release_real):
            return None
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(expected, flags)
        opened = os.fstat(fd)
        linked = os.stat(expected, follow_symlinks=False)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or not statmod.S_ISREG(linked.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_nlink != 1
            or opened.st_size > max_bytes
        ):
            return None
        resolved = expected.resolve(strict=True)
        if not _path_inside(resolved, release_real):
            return None
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        return data if len(data) <= max_bytes else None
    except (OSError, RuntimeError, ValueError):
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _deployment_metadata() -> dict[str, Any]:
    """Return fail-closed deployment evidence without leaking manifest errors."""
    try:
        return _deployment_metadata_impl()
    except Exception as exc:  # pragma: no cover - final status containment
        try:
            manifest_exists = DEPLOYMENT_MANIFEST.is_file()
        except OSError:
            manifest_exists = False
        return _false_deployment_metadata(
            {
                "manifest_path": str(DEPLOYMENT_MANIFEST),
                "manifest_exists": manifest_exists,
            },
            error_type=type(exc).__name__,
        )


def _deployment_metadata_impl() -> dict[str, Any]:
    manifest_path = DEPLOYMENT_MANIFEST
    base: dict[str, Any] = {
        "manifest_path": str(manifest_path),
        "manifest_exists": manifest_path.is_file(),
    }
    if not manifest_path.is_file():
        return _false_deployment_metadata(base)
    try:
        info = manifest_path.stat()
        if not statmod.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            return _false_deployment_metadata(base, error_type="UnsafeManifest")
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return _false_deployment_metadata(base, error_type=type(exc).__name__)
    if not isinstance(raw, dict):
        return _false_deployment_metadata(base, manifest_parse_valid=True)

    schema_valid = _manifest_schema_valid(raw)
    release_root = manifest_path.parent.resolve()
    snapshot_paths = raw.get("snapshot_paths") if isinstance(raw.get("snapshot_paths"), dict) else {}
    canonical_runtime = EXPECTED_STABLE_RUNTIME
    canonical_releases = canonical_runtime.parent / "grabowski-mcp-releases"

    stable_runtime_manifest_valid = (
        isinstance(raw.get("expected_stable_runtime_path"), str)
        and Path(raw["expected_stable_runtime_path"]) == canonical_runtime
    )
    release_path_valid = False
    try:
        release_path_valid = (
            isinstance(raw.get("immutable_release_path"), str)
            and Path(raw["immutable_release_path"]).resolve(strict=True) == release_root
            and release_root.parent == canonical_releases.resolve(strict=True)
        )
    except (OSError, RuntimeError):
        release_path_valid = False
    release_id_valid = isinstance(raw.get("release_id"), str) and raw.get("release_id") == release_root.name
    repo_head_valid = _is_hex(raw.get("repo_head"), 40)
    runtime_pointer_valid = False
    try:
        runtime_pointer_valid = (
            canonical_runtime.is_symlink()
            and canonical_runtime.resolve(strict=True) == release_root
        )
    except (OSError, RuntimeError):
        runtime_pointer_valid = False

    def snapshot_bytes(key: str, relative: str, limit: int = MAX_SNAPSHOT_BYTES) -> bytes | None:
        return _read_bound_regular_file(
            snapshot_paths.get(key), release_root / relative, release_root, max_bytes=limit
        )

    runtime_input_data = snapshot_bytes("runtime_input", "inputs/runtime.in")
    runtime_lock_data = snapshot_bytes("runtime_lock", "inputs/runtime.lock.txt")
    runtime_input_identity_valid = (
        runtime_input_data is not None
        and hashlib.sha256(runtime_input_data).hexdigest() == raw.get("runtime_input_sha256")
    )
    lock_identity_valid = (
        runtime_lock_data is not None
        and hashlib.sha256(runtime_lock_data).hexdigest() == raw.get("runtime_lock_sha256")
    )

    expected_contract = release_root / "inputs/runtime-entrypoint.json"
    contract_data = _read_bound_regular_file(
        snapshot_paths.get("runtime_entrypoint"),
        expected_contract,
        release_root,
        max_bytes=MAX_CONTRACT_BYTES,
    )
    contract_raw: dict[str, Any] | None = None
    if contract_data is not None:
        try:
            parsed = json.loads(contract_data.decode("utf-8"))
            if isinstance(parsed, dict):
                contract_raw = parsed
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    entrypoint_contract_identity_valid = (
        contract_data is not None
        and contract_raw is not None
        and hashlib.sha256(contract_data).hexdigest() == raw.get("entrypoint_contract_sha256")
        and _manifest_schema_valid({**raw, "entrypoint_contract": contract_raw})
    )
    embedded_contract_valid = isinstance(raw.get("entrypoint_contract"), dict) and raw.get("entrypoint_contract") == contract_raw

    contract_sources: list[tuple[str, str]] = []
    if contract_raw is not None:
        main_module = contract_raw.get("module")
        main_source = contract_raw.get("source")
        if (
            isinstance(main_module, str)
            and MODULE_RE.fullmatch(main_module) is not None
            and _safe_relative_path(main_source)
        ):
            contract_sources.append((main_module, main_source))
        supporting = contract_raw.get("supporting_sources", [])
        if isinstance(supporting, list):
            for item in supporting:
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("module"), str)
                    and MODULE_RE.fullmatch(item["module"]) is not None
                    and _safe_relative_path(item.get("source"))
                ):
                    contract_sources.append((item["module"], item["source"]))

    source_hashes = raw.get("source_sha256s")
    module_paths = raw.get("module_paths")
    supporting_snapshot_paths = snapshot_paths.get("supporting_sources")
    snapshot_identity_by_module: dict[str, bool] = {}
    module_identity_by_module: dict[str, bool] = {}
    module_origins: dict[str, Path] = {}

    for index, (module_name, source_name) in enumerate(contract_sources):
        recorded_snapshot = (
            snapshot_paths.get("source")
            if index == 0
            else (
                supporting_snapshot_paths.get(module_name)
                if isinstance(supporting_snapshot_paths, dict)
                else None
            )
        )
        snapshot_data = _read_bound_regular_file(
            recorded_snapshot,
            release_root / "inputs" / source_name,
            release_root,
            max_bytes=MAX_SNAPSHOT_BYTES,
        )
        expected_hash = (
            source_hashes.get(module_name)
            if isinstance(source_hashes, dict)
            else None
        )
        snapshot_identity_by_module[module_name] = (
            snapshot_data is not None
            and hashlib.sha256(snapshot_data).hexdigest() == expected_hash
        )

        origin: Path | None = None
        if module_name == "grabowski_mcp":
            try:
                origin = Path(__file__).resolve(strict=True)
            except (OSError, RuntimeError):
                origin = None
        else:
            try:
                spec = importlib.util.find_spec(module_name)
                if spec is not None and isinstance(spec.origin, str):
                    origin = Path(spec.origin).resolve(strict=True)
            except (ImportError, OSError, RuntimeError, ValueError):
                origin = None
        if origin is not None:
            module_origins[module_name] = origin
        recorded_module = (
            module_paths.get(module_name)
            if isinstance(module_paths, dict)
            else None
        )
        module_data = (
            _read_bound_regular_file(
                recorded_module,
                origin,
                release_root,
                max_bytes=MAX_SNAPSHOT_BYTES,
            )
            if origin is not None
            else None
        )
        module_identity_by_module[module_name] = (
            module_data is not None
            and hashlib.sha256(module_data).hexdigest() == expected_hash
        )

    source_snapshot_identity_valid = (
        bool(contract_sources)
        and len(snapshot_identity_by_module) == len(contract_sources)
        and all(snapshot_identity_by_module.values())
    )
    source_identity_valid = (
        bool(contract_sources)
        and len(module_identity_by_module) == len(contract_sources)
        and all(module_identity_by_module.values())
    )
    entrypoint_module = contract_sources[0][0] if contract_sources else None
    entrypoint_origin = (
        module_origins.get(entrypoint_module)
        if entrypoint_module is not None
        else None
    )
    entrypoint_path_valid = (
        entrypoint_origin is not None
        and raw.get("entrypoint_path") == str(entrypoint_origin)
        and isinstance(module_paths, dict)
        and module_paths.get(entrypoint_module) == str(entrypoint_origin)
        and module_identity_by_module.get(entrypoint_module, False)
    )

    release_python_identity_valid = False
    executable_identity_valid = False
    try:
        release_python = Path(str(raw.get("release_python_path")))
        expected_python = release_root / ".venv/bin/python"
        current_python = Path(sys.executable)
        release_python_identity_valid = (
            release_python == expected_python
            and release_python.exists()
            and release_python.resolve(strict=True) == current_python.resolve(strict=True)
        )
        executable_identity_valid = (
            isinstance(raw.get("executable"), str)
            and Path(raw["executable"]) == release_python
            and Path(raw["executable"]).resolve(strict=True) == current_python.resolve(strict=True)
        )
    except (OSError, RuntimeError, ValueError):
        pass

    try:
        pip_identity_valid = raw.get("pip_version") == f"pip {importlib.metadata.version('pip')}"
    except importlib.metadata.PackageNotFoundError:
        pip_identity_valid = False
    protocol_identity_valid = raw.get("mcp_protocol_version") in DEPLOYMENT_PROTOCOL_VERSIONS
    python_runtime_identity_valid = (
        raw.get("python_version") == platform.python_version()
        and raw.get("python_implementation") == platform.python_implementation()
    )
    platform_identity_valid = raw.get("platform") == platform.platform()

    artifact_integrity_valid = all((
        schema_valid,
        repo_head_valid,
        runtime_input_identity_valid,
        lock_identity_valid,
        source_snapshot_identity_valid,
        embedded_contract_valid,
        entrypoint_contract_identity_valid,
        protocol_identity_valid,
    ))
    runtime_binding_valid = all((
        release_path_valid,
        release_id_valid,
        stable_runtime_manifest_valid,
        runtime_pointer_valid,
        source_identity_valid,
        entrypoint_path_valid,
        release_python_identity_valid,
        executable_identity_valid,
        pip_identity_valid,
    ))
    environment_compatibility_valid = all((
        python_runtime_identity_valid,
        platform_identity_valid,
    ))
    provenance_valid = all((
        artifact_integrity_valid,
        runtime_binding_valid,
        environment_compatibility_valid,
    ))

    allowed = {
        key: raw.get(key)
        for key in (
            "schema_version", "release_id", "repo_head",
            "entrypoint_contract_sha256", "source_sha256",
            "source_sha256s", "runtime_input_sha256", "runtime_lock_sha256",
            "mcp_protocol_version", "python_version",
            "python_implementation", "platform", "executable",
            "pip_version", "created_at_unix", "completion_status",
        )
    }
    return {
        **base,
        "manifest_parse_valid": True,
        "manifest_schema_valid": schema_valid,
        "release_path_valid": release_path_valid,
        "release_id_valid": release_id_valid,
        "repo_head_valid": repo_head_valid,
        "stable_runtime_manifest_valid": stable_runtime_manifest_valid,
        "runtime_pointer_valid": runtime_pointer_valid,
        "runtime_input_identity_valid": runtime_input_identity_valid,
        "lock_identity_valid": lock_identity_valid,
        "source_snapshot_identity_valid": source_snapshot_identity_valid,
        "source_snapshot_identity_by_module": snapshot_identity_by_module,
        "source_identity_valid": source_identity_valid,
        "source_identity_by_module": module_identity_by_module,
        "embedded_contract_valid": embedded_contract_valid,
        "entrypoint_contract_identity_valid": entrypoint_contract_identity_valid,
        "entrypoint_path_valid": entrypoint_path_valid,
        "release_python_identity_valid": release_python_identity_valid,
        "executable_identity_valid": executable_identity_valid,
        "pip_identity_valid": pip_identity_valid,
        "protocol_identity_valid": protocol_identity_valid,
        "python_runtime_identity_valid": python_runtime_identity_valid,
        "platform_identity_valid": platform_identity_valid,
        "artifact_integrity_valid": artifact_integrity_valid,
        "runtime_binding_valid": runtime_binding_valid,
        "environment_compatibility_valid": environment_compatibility_valid,
        "provenance_valid": provenance_valid,
        **allowed,
    }


@mcp.tool(name="grabowski_status", annotations=READ_ANNOTATIONS)
def grabowski_status() -> dict[str, Any]:
    """Return Grabowski's bounded read/write policy and current local state."""
    policy = _load_policy()
    return {
        "service": "grabowski-mcp",
        "mode": policy.get("mode", "bounded-read-write"),
        "state_dir": str(STATE_DIR),
        "policy_path": str(POLICY_PATH),
        "read_roots": policy["read_roots"],
        "write_roots": policy["write_roots"],
        "write_excluded_roots": policy.get("write_excluded_roots", []),
        "latest_complete_bundles_path": str(BUNDLE_REGISTRY),
        "latest_complete_bundles_exists": BUNDLE_REGISTRY.is_file(),
        "deployment": _deployment_metadata(),
        "forbidden_capabilities": policy.get("forbidden_capabilities", []),
    }


@mcp.tool(name="grabowski_list_directory", annotations=READ_ANNOTATIONS)
def grabowski_list_directory(path: str, max_entries: int = 200) -> dict[str, Any]:
    """List one allowed directory without recursion or symlink traversal."""
    directory = _resolve_existing(path, "read")
    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    policy = _load_policy()
    hard_limit = int(policy.get("max_list_entries", 500))
    limit = min(max(1, int(max_entries)), hard_limit)
    entries: list[dict[str, Any]] = []

    for child in sorted(directory.iterdir(), key=lambda p: p.name):
        if len(entries) >= limit:
            break
        try:
            _reject_sensitive(child)
        except PermissionError:
            continue

        if child.is_symlink():
            kind = "symlink-blocked"
            size = None
        elif child.is_dir():
            kind = "directory"
            size = None
        elif child.is_file():
            kind = "file"
            size = child.stat().st_size
        else:
            kind = "other"
            size = None

        entries.append({"name": child.name, "type": kind, "size": size})

    return {
        "path": str(directory),
        "entries": entries,
        "returned": len(entries),
        "limit": limit,
    }


@mcp.tool(name="grabowski_stat", annotations=READ_ANNOTATIONS)
def grabowski_stat(path: str) -> dict[str, Any]:
    """Return metadata and SHA-256 for one allowed regular file."""
    target = _resolve_existing(path, "read")
    st = target.stat()
    result: dict[str, Any] = {
        "path": str(target),
        "type": "directory" if target.is_dir() else "file" if target.is_file() else "other",
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "mode": oct(statmod.S_IMODE(st.st_mode)),
    }
    if target.is_file():
        result["sha256"] = _sha256(target)
    return result


@mcp.tool(name="grabowski_read_text", annotations=READ_ANNOTATIONS)
def grabowski_read_text(path: str, start_line: int = 1, max_lines: int = 400) -> dict[str, Any]:
    """Read UTF-8 text from an allowed file and return a concurrency hash."""
    target = _resolve_existing(path, "read")
    policy = _load_policy()
    data = _ensure_regular_text_file(target, int(policy["max_read_bytes"]))
    text = data.decode("utf-8")
    lines = text.splitlines()

    start = max(1, int(start_line))
    count = min(max(1, int(max_lines)), 2000)
    selected = lines[start - 1 : start - 1 + count]

    return {
        "path": str(target),
        "sha256": hashlib.sha256(data).hexdigest(),
        "start_line": start,
        "end_line": start + len(selected) - 1 if selected else start - 1,
        "total_lines": len(lines),
        "text": "\n".join(selected),
    }


@mcp.tool(name="grabowski_create_text", annotations=CREATE_ANNOTATIONS)
def grabowski_create_text(path: str, content: str) -> dict[str, Any]:
    """Use this when a new UTF-8 text file must be created inside an allowed write root. It fails if the path already exists."""
    target, exists = _resolve_write_target(path)
    if exists:
        raise FileExistsError(f"Refusing to overwrite existing path: {target}")

    policy = _load_policy()
    encoded = content.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("NUL-containing content is not allowed")
    if len(encoded) > int(policy["max_write_bytes"]):
        raise ValueError("Content exceeds configured write limit")

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, 0o600)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    after_sha = _sha256(target)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "create",
        "path": str(target),
        "before_sha256": None,
        "after_sha256": after_sha,
        "bytes": len(encoded),
        "backup": None,
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_replace_text", annotations=REPLACE_ANNOTATIONS)
def grabowski_replace_text(path: str, content: str, expected_sha256: str) -> dict[str, Any]:
    """Use this when an existing allowed UTF-8 text file must be replaced atomically. The exact SHA-256 returned by grabowski_read_text or grabowski_stat is required."""
    target, exists = _resolve_write_target(path)
    if not exists:
        raise FileNotFoundError(f"Use grabowski_create_text for new files: {target}")

    policy = _load_policy()
    encoded = content.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("NUL-containing content is not allowed")
    if len(encoded) > int(policy["max_write_bytes"]):
        raise ValueError("Content exceeds configured write limit")

    _ensure_regular_text_file(target, int(policy["max_read_bytes"]))
    before_sha = _sha256(target)
    if expected_sha256 != before_sha:
        raise RuntimeError(
            f"SHA-256 precondition failed: expected {expected_sha256}, current {before_sha}"
        )

    mode = statmod.S_IMODE(target.stat().st_mode)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup_dir = STATE_DIR / "backups" / stamp
    backup_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    backup = backup_dir / f"{before_sha[:12]}-{target.name}"
    shutil.copy2(target, backup, follow_symlinks=False)
    os.chmod(backup, 0o600)

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, mode)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    after_sha = _sha256(target)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "replace",
        "path": str(target),
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "bytes": len(encoded),
        "backup": str(backup),
    }
    _append_audit(record)
    return record


@mcp.tool(name="latest_complete_bundles", annotations=READ_ANNOTATIONS)
def latest_complete_bundles() -> dict[str, Any]:
    """Return the curated latest-complete Lens/repoLens bundle registry."""
    if not BUNDLE_REGISTRY.is_file():
        return {
            "path": str(BUNDLE_REGISTRY),
            "exists": False,
            "rows": [],
        }

    data = _ensure_regular_text_file(BUNDLE_REGISTRY, 2_000_000)
    rows = []
    for line in data.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        rows.append(line.split("\t"))

    return {
        "path": str(BUNDLE_REGISTRY),
        "exists": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "rows": rows,
    }


if __name__ == "__main__":
    mcp.run()
