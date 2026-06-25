#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
import hashlib
import json
import os
import platform
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


def _false_deployment_metadata(base: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        **base,
        "manifest_parse_valid": False,
        "manifest_schema_valid": False,
        "release_path_valid": False,
        "runtime_pointer_valid": False,
        "source_identity_valid": False,
        "lock_identity_valid": False,
        "entrypoint_contract_identity_valid": False,
        "release_python_identity_valid": False,
        "python_runtime_identity_valid": False,
        "provenance_valid": False,
        **extra,
    }


def _path_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _deployment_metadata() -> dict[str, Any]:
    manifest_path = DEPLOYMENT_MANIFEST
    base: dict[str, Any] = {
        "manifest_path": str(manifest_path),
        "manifest_exists": manifest_path.is_file(),
    }
    if not manifest_path.is_file():
        return _false_deployment_metadata(base)

    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _false_deployment_metadata(base, error_type=type(exc).__name__)

    if not isinstance(raw, dict):
        return _false_deployment_metadata(base, manifest_parse_valid=True)

    required = {
        "schema_version",
        "release_id",
        "repo_head",
        "entrypoint_contract",
        "entrypoint_contract_sha256",
        "source_sha256",
        "runtime_input_sha256",
        "runtime_lock_sha256",
        "snapshot_paths",
        "immutable_release_path",
        "expected_stable_runtime_path",
        "release_python_path",
        "entrypoint_path",
        "platform",
        "python_version",
        "python_implementation",
        "mcp_protocol_version",
        "created_at_unix",
        "completion_status",
    }
    schema_valid = (
        isinstance(raw, dict)
        and raw.get("schema_version") == 3
        and raw.get("completion_status") == "complete"
        and required.issubset(raw)
    )

    release_root = manifest_path.parent.resolve()
    snapshot_paths = raw.get("snapshot_paths")
    stable_runtime = None
    if isinstance(raw.get("expected_stable_runtime_path"), str):
        stable_runtime = Path(raw["expected_stable_runtime_path"])

    release_path_valid = False
    try:
        releases_root = (
            stable_runtime.parent / "grabowski-mcp-releases"
            if stable_runtime is not None
            else None
        )
        release_path_valid = (
            isinstance(raw.get("immutable_release_path"), str)
            and Path(raw["immutable_release_path"]) == manifest_path.parent
            and releases_root is not None
            and release_root.parent.resolve() == releases_root.resolve()
        )
    except (OSError, RuntimeError):
        release_path_valid = False

    source_identity_valid = False
    if isinstance(raw, dict) and isinstance(raw.get("source_sha256"), str):
        try:
            source_identity_valid = (
                _sha256(Path(__file__).resolve()) == raw["source_sha256"]
            )
        except OSError:
            source_identity_valid = False

    lock_identity_valid = False
    if isinstance(snapshot_paths, dict):
        try:
            lock_path = Path(str(snapshot_paths.get("runtime_lock")))
            expected_lock = release_root / "inputs/runtime.lock.txt"
            lock_identity_valid = (
                lock_path == expected_lock
                and lock_path.is_file()
                and _path_inside(lock_path.resolve(), release_root)
                and _sha256(lock_path) == raw["runtime_lock_sha256"]
            )
        except OSError:
            lock_identity_valid = False

    entrypoint_contract_identity_valid = False
    if isinstance(snapshot_paths, dict):
        try:
            contract_path = Path(str(snapshot_paths.get("runtime_entrypoint")))
            expected_contract = release_root / "inputs/runtime-entrypoint.json"
            contract_raw = json.loads(contract_path.read_text(encoding="utf-8"))
            contract_valid = (
                isinstance(contract_raw, dict)
                and contract_raw.get("schema_version") == 1
                and contract_raw.get("mode") == "module"
                and isinstance(contract_raw.get("module"), str)
                and isinstance(contract_raw.get("expected_tools"), list)
            )
            entrypoint_contract_identity_valid = (
                contract_path == expected_contract
                and contract_path.is_file()
                and _path_inside(contract_path.resolve(), release_root)
                and _sha256(contract_path) == raw["entrypoint_contract_sha256"]
                and contract_valid
            )
        except (OSError, json.JSONDecodeError):
            entrypoint_contract_identity_valid = False

    runtime_pointer_valid = False
    try:
        runtime_pointer_valid = (
            stable_runtime is not None
            and stable_runtime.is_symlink()
            and stable_runtime.resolve() == release_root
        )
    except (OSError, RuntimeError):
        runtime_pointer_valid = False

    release_python_identity_valid = False
    try:
        release_python = Path(str(raw.get("release_python_path")))
        expected_python = release_root / ".venv/bin/python"
        release_python_identity_valid = (
            release_python == expected_python
            and release_python.exists()
            and release_python.resolve() == Path(sys.executable).resolve()
        )
    except (OSError, RuntimeError):
        release_python_identity_valid = False

    python_runtime_identity_valid = (
        raw.get("python_version") == platform.python_version()
        and raw.get("python_implementation") == platform.python_implementation()
    )

    provenance_valid = (
        schema_valid
        and release_path_valid
        and runtime_pointer_valid
        and source_identity_valid
        and lock_identity_valid
        and entrypoint_contract_identity_valid
        and release_python_identity_valid
        and python_runtime_identity_valid
    )

    allowed = {
        key: raw.get(key)
        for key in (
            "schema_version",
            "release_id",
            "repo_head",
            "entrypoint_contract_sha256",
            "source_sha256",
            "runtime_input_sha256",
            "runtime_lock_sha256",
            "mcp_protocol_version",
            "python_version",
            "python_implementation",
            "platform",
            "created_at_unix",
            "completion_status",
        )
    }
    return {
        **base,
        "manifest_parse_valid": True,
        "manifest_schema_valid": schema_valid,
        "release_path_valid": release_path_valid,
        "source_identity_valid": source_identity_valid,
        "lock_identity_valid": lock_identity_valid,
        "entrypoint_contract_identity_valid": entrypoint_contract_identity_valid,
        "release_python_identity_valid": release_python_identity_valid,
        "python_runtime_identity_valid": python_runtime_identity_valid,
        "runtime_pointer_valid": runtime_pointer_valid,
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
