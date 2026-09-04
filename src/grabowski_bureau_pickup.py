from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any, Literal

try:
    from typing_extensions import TypedDict
except ModuleNotFoundError:
    from typing import TypedDict

import grabowski_bureau_intake as bureau
import grabowski_bureau_leases as bureau_leases
import grabowski_nonconflict as nonconflict
import grabowski_resources as resources
import grabowski_work_admission as work_admission

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING

SCHEMA_VERSION = 1
STATE_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_BUREAU_PICKUP_ROOT",
        str(operator.STATE_DIR / "bureau-pickup"),
    )
).expanduser()
LEGACY_COORDINATION_ROOT = Path(
    os.environ.get("BUREAU_STATE_DIR", "~/.local/state/bureau")
).expanduser()
COORDINATION_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_BUREAU_COORDINATION_ROOT",
        str(LEGACY_COORDINATION_ROOT),
    )
).expanduser()
RUN_ID_RE = re.compile(r"^BUR-RUN-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
TERMINAL_BUREAU_TASK_STATES = frozenset(
    {"cancelled", "closed", "superseded", "verified"}
)
MACHINE_COMPLETION_BINDING_FIELDS = (
    "artifact_sha256",
    "connector_snapshot_receipt_sha256",
    "delivery_receipt_sha256",
    "deployment_receipt_sha256",
    "merge_commit",
    "receipt_sha256",
    "runtime_head",
    "runtime_release",
    "source_commit",
)
MAX_REQUEST_BYTES = 1024 * 1024
MAX_REGISTRY_TREE_BYTES = 16 * 1024 * 1024
MAX_CLAIM_REJECTION_CODE_BYTES = 128
MAX_CLAIM_REJECTION_VALUE_BYTES = 16 * 1024
MIN_LEASE_TTL_SECONDS = 120
MAX_LEASE_TTL_SECONDS = 3600
MAX_JOURNAL_REPLAY_RUNS = 4096
MAX_MCP_ERROR_ENVELOPE_BYTES = 16 * 1024
MCP_ERROR_ENVELOPE_MARKER = "GRABOWSKI_ERROR_ENVELOPE="


ACTIVE_EXECUTION_STATES = frozenset({"assigned", "running", "verifying"})
TERMINAL_EXECUTION_STATES = frozenset({"succeeded", "failed", "cancelled", "orphaned"})
EXECUTION_HEARTBEAT_MAX_AGE_SECONDS = 900
EXTERNAL_BINDING_FIELDS = ("external_system", "external_id", "external_state")
ACTIVE_EXTERNAL_STATES = frozenset({"queued", "running", "succeeded"})
BOUND_ACTIVITY_SUCCESSFUL_EXTERNAL_STATES = frozenset({"running", "succeeded"})
ORPHAN_RECONCILE_ERROR = "orphan-reconcile:stale-or-unbound-execution"
ORPHAN_RESUME_ERROR = "stale worker without external executor"
REGISTRY_BINDING_RECOVERY_KIND = "grabowski_bureau_pickup_registry_binding_recovery"
LEASE_IDENTITY_FIELDS = (
    "resource_key",
    "owner_id",
    "acquired_at_unix",
    "updated_at_unix",
    "expires_at_unix",
    "metadata_sha256",
)
def _bureau_pickup_error_message(
    code: str, details: dict[str, Any], summary: str | None
) -> str:
    prefix = summary or code
    envelope: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_bureau_pickup_error",
        "code": code,
        "details": details,
    }
    try:
        payload = json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        payload = json.dumps(
            {
                "schema_version": 1,
                "kind": "grabowski_bureau_pickup_error",
                "code": code,
                "details": {"serialization_failed": True},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    encoded = payload.encode("utf-8")
    if len(encoded) > MAX_MCP_ERROR_ENVELOPE_BYTES:
        payload = json.dumps(
            {
                "schema_version": 1,
                "kind": "grabowski_bureau_pickup_error",
                "code": code,
                "details": {
                    "truncated": True,
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    return f"{prefix}\n{MCP_ERROR_ENVELOPE_MARKER}{payload}"


class _RequiredBureauPickupRequest(TypedDict):
    worker_id: str
    capabilities: list[str]


class BureauPickupRequest(_RequiredBureauPickupRequest, total=False):
    __pydantic_config__ = {"extra": "forbid", "strict": True}

    task_id: str | None
    resource: str | None
    kind: str
    base_dir: str | None
    approval_source: str
    approval_level: Literal["operator", "break_glass"]
    lease_ttl_seconds: int
    create_workspace: bool
    repository_scope_manifests: dict[str, dict[str, Any]] | None
    nonconflict_proofs: dict[str, dict[str, Any]] | None
    registry_root: str


class BureauPickupOrphanReconcileRequest(TypedDict):
    __pydantic_config__ = {"extra": "forbid", "strict": True}

    run_id: str
    expected_registry_binding_sha256: str
    expected_coordination_sha256: str
    expected_lease_sha256: str

class ExplicitRegistryBindingIdentity(TypedDict):
    schema_version: int
    kind: str
    registry_root: str
    binding_sha256: str


class CanonicalRegistryBindingIdentity(ExplicitRegistryBindingIdentity):
    source_commit: str
    registry_tree_sha256: str
    launcher_sha256: str
    manifest_sha256: str
    inventory_path: str
    inventory_sha256: str


RegistryBindingIdentity = (
    ExplicitRegistryBindingIdentity | CanonicalRegistryBindingIdentity
)


class RegistryBinding(TypedDict):
    identity: RegistryBindingIdentity
    managed_runtime: Any | None
    explicit: bool
    legacy: bool


class BureauPickupError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        details: dict[str, Any] | None = None,
        summary: str | None = None,
    ) -> None:
        super().__init__(summary or code)
        self.code = code
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "details": self.details}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _runtime_error_details(
    exc: BaseException, **details: Any
) -> dict[str, Any]:
    return {
        "cause_code": getattr(exc, "code", None),
        "error_type": type(exc).__name__,
        **details,
    }


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return stable identity fields for one filesystem object.

    Directory link count, size and timestamps are mutable namespace
    metadata. They may
    change between stat and fstat when an unrelated process updates a shared
    ancestor such as /tmp, so they must not participate in path-to-fd binding.
    """
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _file_snapshot_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *_directory_identity(metadata),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise BureauPickupError("private-directory-nofollow-unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _open_existing_directory_chain(path: Path, *, label: str) -> int:
    """Open an existing absolute directory without following any symlink component."""
    normalized = _absolute_path(path)
    descriptor = os.open("/", _directory_flags())
    try:
        for component in normalized.parts[1:]:
            parent_descriptor = descriptor
            child_descriptor = -1
            try:
                child_descriptor = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=parent_descriptor,
                )
                linked = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                opened = os.fstat(child_descriptor)
                if (
                    not stat.S_ISDIR(linked.st_mode)
                    or stat.S_ISLNK(linked.st_mode)
                    or _directory_identity(linked) != _directory_identity(opened)
                ):
                    raise BureauPickupError(f"{label}-directory-unsafe")
            except FileNotFoundError:
                if child_descriptor >= 0:
                    os.close(child_descriptor)
                os.close(parent_descriptor)
                descriptor = -1
                raise BureauPickupError(f"{label}-missing") from None
            except BureauPickupError:
                if child_descriptor >= 0:
                    os.close(child_descriptor)
                os.close(parent_descriptor)
                descriptor = -1
                raise
            except OSError as exc:
                if child_descriptor >= 0:
                    os.close(child_descriptor)
                os.close(parent_descriptor)
                descriptor = -1
                raise BureauPickupError(
                    f"{label}-open-failed",
                    details={"error_type": type(exc).__name__, "component": component},
                ) from None
            os.close(parent_descriptor)
            descriptor = child_descriptor
        linked = normalized.lstat()
        opened = os.fstat(descriptor)
        if _directory_identity(linked) != _directory_identity(opened):
            raise BureauPickupError(f"{label}-directory-changed")
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _assert_private_directory_binding(
    descriptor: int,
    path: Path,
    *,
    label: str,
) -> None:
    try:
        linked = path.lstat()
    except FileNotFoundError:
        raise BureauPickupError(f"{label}-directory-missing") from None
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(linked.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or _directory_identity(opened) != _directory_identity(linked)
    ):
        raise BureauPickupError(f"{label}-directory-unsafe")


def _open_or_create_private_child(
    parent_descriptor: int,
    parent_path: Path,
    name: str,
    *,
    label: str,
    create: bool,
) -> tuple[Path, int]:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError(f"{label} directory name is invalid")
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise BureauPickupError(
                f"{label}-directory-create-failed",
                details={"error_type": type(exc).__name__},
            ) from None
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    except FileNotFoundError:
        raise BureauPickupError(f"{label}-directory-missing") from None
    except OSError as exc:
        raise BureauPickupError(
            f"{label}-directory-open-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    path = parent_path / name
    try:
        linked = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(linked.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or _directory_identity(linked) != _directory_identity(opened)
        ):
            raise BureauPickupError(f"{label}-directory-unsafe")
        _assert_private_directory_binding(descriptor, path, label=label)
        return path, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_run_directory(run_id: str, *, create: bool) -> tuple[Path, int]:
    if RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError("run_id is invalid")
    root = _absolute_path(STATE_ROOT)
    parent_descriptor = _open_existing_directory_chain(
        root.parent, label="pickup-state-parent"
    )
    root_descriptor = runs_descriptor = run_descriptor = -1
    keep_run_descriptor = False
    try:
        root_path, root_descriptor = _open_or_create_private_child(
            parent_descriptor,
            root.parent,
            root.name,
            label="pickup-root",
            create=create,
        )
        runs_path, runs_descriptor = _open_or_create_private_child(
            root_descriptor,
            root_path,
            "runs",
            label="pickup-runs",
            create=create,
        )
        run_path, run_descriptor = _open_or_create_private_child(
            runs_descriptor,
            runs_path,
            run_id,
            label="pickup-run",
            create=create,
        )
        _assert_private_directory_binding(root_descriptor, root_path, label="pickup-root")
        _assert_private_directory_binding(runs_descriptor, runs_path, label="pickup-runs")
        _assert_private_directory_binding(run_descriptor, run_path, label="pickup-run")
        keep_run_descriptor = True
        return run_path, run_descriptor
    finally:
        os.close(parent_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        if runs_descriptor >= 0:
            os.close(runs_descriptor)
        if run_descriptor >= 0 and not keep_run_descriptor:
            os.close(run_descriptor)


def _private_root() -> Path:
    root = _absolute_path(STATE_ROOT)
    parent_descriptor = _open_existing_directory_chain(
        root.parent, label="pickup-state-parent"
    )
    try:
        root_path, root_descriptor = _open_or_create_private_child(
            parent_descriptor,
            root.parent,
            root.name,
            label="pickup-root",
            create=True,
        )
        try:
            _assert_private_directory_binding(root_descriptor, root_path, label="pickup-root")
        finally:
            os.close(root_descriptor)
        return root_path
    finally:
        os.close(parent_descriptor)


def _default_coordination_root() -> Path:
    return _absolute_path(COORDINATION_ROOT)


def _legacy_coordination_root() -> Path:
    return _absolute_path(LEGACY_COORDINATION_ROOT)


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _validate_existing_private_directory(path: Path, *, label: str) -> None:
    descriptor = _open_existing_directory_chain(path, label=label)
    try:
        _assert_private_directory_binding(descriptor, path, label=label)
    finally:
        os.close(descriptor)


def _normalize_coordination_root(
    value: Any, *, registry_root: str, require_current_binding: bool = True
) -> str:
    raw = Path(_text(value, label="coordination_root", maximum=4096)).expanduser()
    if not raw.is_absolute():
        raise ValueError("coordination_root must be absolute")
    normalized = _absolute_path(raw)
    expected = _default_coordination_root()
    if require_current_binding and normalized != expected:
        raise BureauPickupError(
            "coordination-root-not-adapter-owned",
            details={"observed": str(normalized), "expected": str(expected)},
        )
    registry = Path(registry_root)
    if _paths_overlap(normalized, registry):
        raise BureauPickupError(
            "coordination-root-overlaps-registry",
            details={
                "coordination_root": str(normalized),
                "registry_root": str(registry),
            },
        )
    if os.path.lexists(normalized):
        _validate_existing_private_directory(
            normalized, label="pickup-coordination"
        )
    return str(normalized)


def _ensure_coordination_root(expected: str) -> str:
    normalized = Path(expected)
    if normalized != _default_coordination_root():
        raise BureauPickupError("coordination-root-binding-changed")
    parent = normalized.parent
    parent_descriptor = _open_existing_directory_chain(
        parent, label="pickup-coordination-parent"
    )
    coordination_descriptor = -1
    try:
        path, coordination_descriptor = _open_or_create_private_child(
            parent_descriptor,
            parent,
            normalized.name,
            label="pickup-coordination",
            create=True,
        )
        _assert_private_directory_binding(
            coordination_descriptor, path, label="pickup-coordination"
        )
        if path != normalized:
            raise BureauPickupError("coordination-root-binding-changed")
        return str(path)
    finally:
        if coordination_descriptor >= 0:
            os.close(coordination_descriptor)
        os.close(parent_descriptor)


def _run_directory(run_id: str) -> Path:
    path, descriptor = _open_run_directory(run_id, create=True)
    os.close(descriptor)
    return path


def _journal_target(path: Path) -> tuple[str, str]:
    normalized = _absolute_path(path)
    root = _absolute_path(STATE_ROOT)
    if (
        normalized.parent.parent.name != "runs"
        or normalized.parent.parent.parent != root
        or RUN_ID_RE.fullmatch(normalized.parent.name) is None
        or not normalized.name
        or normalized.name in {".", ".."}
        or "/" in normalized.name
        or "\\" in normalized.name
    ):
        raise BureauPickupError("pickup-artifact-path-invalid")
    return normalized.parent.name, normalized.name


def _read_private_bytes_at(
    directory_descriptor: int,
    directory_path: Path,
    name: str,
    *,
    label: str,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except FileNotFoundError:
        raise BureauPickupError(f"{label}-missing") from None
    except OSError as exc:
        raise BureauPickupError(
            f"{label}-open-failed", details={"error_type": type(exc).__name__}
        ) from None
    try:
        before = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise BureauPickupError(f"{label}-not-regular")
        if before.st_uid != os.getuid():
            raise BureauPickupError(f"{label}-owner-invalid")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise BureauPickupError(f"{label}-mode-invalid")
        if before.st_nlink != 1:
            raise BureauPickupError(f"{label}-hardlink-invalid")
        if _file_snapshot_identity(before) != _file_snapshot_identity(linked):
            raise BureauPickupError(f"{label}-binding-invalid")
        if before.st_size > MAX_REQUEST_BYTES:
            raise BureauPickupError(f"{label}-too-large")
        chunks: list[bytes] = []
        remaining = MAX_REQUEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        linked_after = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    finally:
        os.close(descriptor)
    if _file_snapshot_identity(before) != _file_snapshot_identity(
        after
    ) or _file_snapshot_identity(after) != _file_snapshot_identity(linked_after):
        raise BureauPickupError(f"{label}-changed-during-read")
    _assert_private_directory_binding(
        directory_descriptor, directory_path, label="pickup-run"
    )
    raw = b"".join(chunks)
    if len(raw) > MAX_REQUEST_BYTES or len(raw) != before.st_size:
        raise BureauPickupError(f"{label}-size-invalid")
    return raw


def _read_private_bytes(path: Path, *, label: str) -> bytes:
    run_id, name = _journal_target(path)
    directory_path, directory_descriptor = _open_run_directory(run_id, create=False)
    try:
        return _read_private_bytes_at(
            directory_descriptor,
            directory_path,
            name,
            label=label,
        )
    finally:
        os.close(directory_descriptor)


def _write_bound_json(path: Path, value: Any) -> str:
    raw = _canonical_json(value)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("pickup artifact exceeds the bounded limit")
    run_id, name = _journal_target(path)
    directory_path, directory_descriptor = _open_run_directory(run_id, create=True)
    try:
        try:
            existing = _read_private_bytes_at(
                directory_descriptor,
                directory_path,
                name,
                label="pickup-artifact",
            )
        except BureauPickupError as exc:
            if exc.code != "pickup-artifact-missing":
                raise
        else:
            if existing != raw:
                raise BureauPickupError(
                    "pickup-artifact-conflict", details={"path": str(path)}
                )
            return hashlib.sha256(raw).hexdigest()

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
        except FileExistsError:
            winner = _read_private_bytes_at(
                directory_descriptor,
                directory_path,
                name,
                label="pickup-artifact",
            )
            if winner != raw:
                raise BureauPickupError(
                    "pickup-artifact-conflict", details={"path": str(path)}
                ) from None
            return hashlib.sha256(raw).hexdigest()
        created_inode: tuple[int, int] | None = None
        try:
            created = os.fstat(descriptor)
            created_inode = (created.st_dev, created.st_ino)
            if (
                not stat.S_ISREG(created.st_mode)
                or created.st_uid != os.getuid()
                or stat.S_IMODE(created.st_mode) != 0o600
                or created.st_nlink != 1
            ):
                raise BureauPickupError("pickup-artifact-created-unsafe")
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            linked = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(linked.st_mode)
                or linked.st_uid != os.getuid()
                or stat.S_IMODE(linked.st_mode) != 0o600
                or linked.st_nlink != 1
                or (linked.st_dev, linked.st_ino) != created_inode
            ):
                raise BureauPickupError("pickup-artifact-publish-unsafe")
            os.fsync(directory_descriptor)
            _assert_private_directory_binding(
                directory_descriptor, directory_path, label="pickup-run"
            )
            linked_after = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False
            )
            if (linked_after.st_dev, linked_after.st_ino) != created_inode:
                raise BureauPickupError("pickup-artifact-publish-changed")
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            if created_inode is not None:
                try:
                    current = os.stat(
                        name, dir_fd=directory_descriptor, follow_symlinks=False
                    )
                    if (current.st_dev, current.st_ino) == created_inode:
                        os.unlink(name, dir_fd=directory_descriptor)
                        os.fsync(directory_descriptor)
                except OSError:
                    pass
            raise
        return hashlib.sha256(raw).hexdigest()
    finally:
        os.close(directory_descriptor)


def _read_bound_json(path: Path, *, label: str) -> dict[str, Any]:
    raw = _read_private_bytes(path, label=label)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise BureauPickupError(f"{label}-invalid") from None
    if not isinstance(value, dict):
        raise BureauPickupError(f"{label}-invalid")
    return value


def _text(value: Any, *, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    normalized = value.strip()
    if not normalized or "\x00" in normalized or len(normalized.encode()) > maximum:
        raise ValueError(f"{label} is empty, too large or contains NUL")
    return normalized


def _capabilities(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("capabilities must be a non-empty list")
    result = sorted({_text(item, label="capability", maximum=128) for item in value})
    return result


def _ttl(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("lease_ttl_seconds must be an integer")
    if not MIN_LEASE_TTL_SECONDS <= value <= MAX_LEASE_TTL_SECONDS:
        raise ValueError(
            f"lease_ttl_seconds must be between {MIN_LEASE_TTL_SECONDS} and "
            f"{MAX_LEASE_TTL_SECONDS}"
        )
    return value


def _normalize_scope_manifests(value: Any) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("repository_scope_manifests must be an object")
    result: dict[str, dict[str, Any]] = {}
    for key, scope in value.items():
        normalized_key = resources.normalize_resource_key(key)
        if not normalized_key.startswith("repo:"):
            raise ValueError("repository scope keys must be broad repo resources")
        if not isinstance(scope, dict):
            raise ValueError("repository scope manifest must be an object")
        result[normalized_key] = scope
    return result


def _normalize_nonconflict_proofs(value: Any) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("nonconflict_proofs must be an object")
    result: dict[str, dict[str, Any]] = {}
    for key, proof in value.items():
        normalized_key = (
            "other" if key == "other" else resources.normalize_resource_key(key)
        )
        if not isinstance(proof, dict):
            raise ValueError("nonconflict proof must be an object")
        result[normalized_key] = proof
    return result


def _normalize_registry_root(value: Any) -> str:
    raw = Path(_text(value, label="registry_root", maximum=4096)).expanduser()
    if not raw.is_absolute():
        raise ValueError("registry_root must be absolute")
    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("registry_root must resolve to an existing directory") from exc
    if not resolved.is_dir():
        raise ValueError("registry_root must resolve to an existing directory")
    return str(resolved)


def _canonical_registry_binding() -> RegistryBinding:
    try:
        managed = bureau._managed_runtime_binding()
        bureau._assert_managed_runtime_unchanged(managed)
    except (OSError, RuntimeError) as exc:
        raise BureauPickupError(
            "canonical-registry-binding-unavailable",
            details=_runtime_error_details(exc),
        ) from None
    identity = {
        "schema_version": SCHEMA_VERSION,
        "kind": "canonical-registry-binding",
        "registry_root": str(managed.registry_root),
        "source_commit": managed.source_commit,
        "registry_tree_sha256": managed.registry_tree_sha256,
        "launcher_sha256": managed.launcher.sha256,
        "manifest_sha256": managed.manifest.sha256,
        "inventory_path": str(managed.inventory.path),
        "inventory_sha256": managed.inventory.sha256,
    }
    identity["binding_sha256"] = _sha256(identity)
    _validate_registry_binding_identity(identity)
    return {
        "identity": identity,
        "managed_runtime": managed,
        "explicit": False,
        "legacy": False,
    }


def _explicit_registry_binding(registry_root: str) -> RegistryBinding:
    identity = {
        "schema_version": SCHEMA_VERSION,
        "kind": "explicit-registry-root",
        "registry_root": registry_root,
    }
    identity["binding_sha256"] = _sha256(identity)
    return {
        "identity": identity,
        "managed_runtime": None,
        "explicit": True,
        "legacy": False,
    }


def _observed_registry_tree_sha256(
    registry_root: Path, paths: list[str]
) -> str:
    digest = hashlib.sha256()
    total_bytes = 0
    for item in paths:
        relative = Path(item)
        try:
            snapshot = bureau._read_regular_file_snapshot(
                registry_root / relative,
                label="canonical-registry-tree-entry",
            )
        except (OSError, RuntimeError) as exc:
            raise BureauPickupError(
                "canonical-registry-tree-read-failed",
                details=_runtime_error_details(exc, path=item),
            ) from None
        total_bytes += len(snapshot.raw)
        if total_bytes > MAX_REGISTRY_TREE_BYTES:
            raise BureauPickupError(
                "canonical-registry-tree-too-large",
                details={
                    "limit_bytes": MAX_REGISTRY_TREE_BYTES,
                    "observed_bytes": total_bytes,
                    "path": item,
                },
            )
        encoded = relative.as_posix().encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(snapshot.raw).to_bytes(8, "big"))
        digest.update(snapshot.raw)
    return digest.hexdigest()


def _validate_registry_binding_identity(identity: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(identity, dict):
        raise BureauPickupError("registry-binding-invalid")
    if identity.get("schema_version") != SCHEMA_VERSION:
        raise BureauPickupError("registry-binding-schema-version-invalid")
    claimed = identity.get("binding_sha256")
    if not isinstance(claimed, str) or SHA256_RE.fullmatch(claimed) is None:
        raise BureauPickupError("registry-binding-digest-invalid")
    payload = dict(identity)
    payload.pop("binding_sha256", None)
    if _sha256(payload) != claimed:
        raise BureauPickupError("registry-binding-digest-mismatch")
    registry_root = _normalize_registry_root(identity.get("registry_root"))
    if registry_root != identity.get("registry_root"):
        raise BureauPickupError("registry-binding-root-drift")
    kind = identity.get("kind")
    if kind == "explicit-registry-root":
        expected = {
            "schema_version",
            "kind",
            "registry_root",
            "binding_sha256",
        }
        if set(identity) != expected:
            raise BureauPickupError("explicit-registry-binding-shape-invalid")
        return identity
    if kind != "canonical-registry-binding":
        raise BureauPickupError("registry-binding-kind-invalid")
    expected = {
        "schema_version",
        "kind",
        "registry_root",
        "source_commit",
        "registry_tree_sha256",
        "launcher_sha256",
        "manifest_sha256",
        "inventory_path",
        "inventory_sha256",
        "binding_sha256",
    }
    if set(identity) != expected:
        raise BureauPickupError("canonical-registry-binding-shape-invalid")
    source_commit = identity.get("source_commit")
    if (
        not isinstance(source_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
    ):
        raise BureauPickupError("canonical-registry-source-commit-invalid")
    # Launcher and manifest digests preserve deployment provenance only.
    # Journal replay must survive a later deployment rotation; the inventory
    # and Registry tree below remain the operative content-bound authority.
    for field in (
        "registry_tree_sha256",
        "launcher_sha256",
        "manifest_sha256",
        "inventory_sha256",
    ):
        value = identity.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise BureauPickupError(f"canonical-registry-{field}-invalid")
    inventory_path = Path(
        _text(identity.get("inventory_path"), label="inventory_path", maximum=4096)
    )
    expected_inventory_path = Path(registry_root) / ".bureau-runtime-snapshot.json"
    if inventory_path != expected_inventory_path:
        raise BureauPickupError("canonical-registry-inventory-path-invalid")
    try:
        inventory = bureau._read_regular_file_snapshot(
            inventory_path, label="canonical-registry-inventory"
        )
    except (OSError, RuntimeError) as exc:
        raise BureauPickupError(
            "canonical-registry-inventory-unavailable",
            details=_runtime_error_details(exc),
        ) from None
    if inventory.sha256 != identity["inventory_sha256"]:
        raise BureauPickupError("canonical-registry-inventory-drift")
    try:
        inventory_payload = json.loads(inventory.raw)
    except json.JSONDecodeError:
        raise BureauPickupError("canonical-registry-inventory-invalid") from None
    if not isinstance(inventory_payload, dict):
        raise BureauPickupError("canonical-registry-inventory-invalid")
    paths = inventory_payload.get("paths")
    if (
        inventory_payload.get("schema_version") != SCHEMA_VERSION
        or inventory_payload.get("kind") != "bureau_registry_snapshot"
        or not isinstance(paths, list)
        or not paths
        or any(
            not isinstance(item, str)
            or not item
            or Path(item).is_absolute()
            or ".." in Path(item).parts
            for item in paths
        )
        or len(paths) != len(set(paths))
    ):
        raise BureauPickupError("canonical-registry-inventory-invalid")
    if inventory_payload.get("source_commit") != source_commit:
        raise BureauPickupError("canonical-registry-source-commit-drift")
    if inventory_payload.get("tree_sha256") != identity["registry_tree_sha256"]:
        raise BureauPickupError("canonical-registry-tree-drift")
    observed_tree_sha256 = _observed_registry_tree_sha256(
        Path(registry_root), paths
    )
    if observed_tree_sha256 != identity["registry_tree_sha256"]:
        raise BureauPickupError(
            "canonical-registry-tree-drift",
            details={
                "expected_tree_sha256": identity["registry_tree_sha256"],
                "observed_tree_sha256": observed_tree_sha256,
            },
        )
    return identity


def _registry_binding_from_identity(
    identity: dict[str, Any],
) -> RegistryBinding:
    validated = _validate_registry_binding_identity(identity)
    return {
        "identity": validated,
        "managed_runtime": None,
        "explicit": validated["kind"] == "explicit-registry-root",
        "legacy": False,
    }


def _normalize_registry_binding_marker(value: Any) -> str | None:
    if value is None:
        return None
    marker = _text(value, label="registry_binding_sha256", maximum=64)
    if SHA256_RE.fullmatch(marker) is None:
        raise BureauPickupError("registry-binding-marker-invalid")
    return marker


def _read_journal_registry_binding(
    run_dir: Path,
    registry_root: str,
    *,
    expected_sha256: str | None,
) -> dict[str, Any]:
    try:
        identity = _read_bound_json(
            run_dir / "registry-binding.json", label="registry-binding"
        )
    except BureauPickupError as exc:
        if exc.code != "registry-binding-missing":
            raise
        if expected_sha256 is not None:
            raise
        binding = _explicit_registry_binding(registry_root)
        binding["legacy"] = True
        return binding
    binding = _registry_binding_from_identity(identity)
    if binding["identity"]["registry_root"] != registry_root:
        raise BureauPickupError("journal-registry-root-mismatch")
    if (
        expected_sha256 is not None
        and binding["identity"]["binding_sha256"] != expected_sha256
    ):
        raise BureauPickupError("journal-registry-binding-marker-mismatch")
    return binding


def _assert_registry_binding(binding: RegistryBinding) -> None:
    managed = binding.get("managed_runtime")
    if managed is None:
        _validate_registry_binding_identity(binding["identity"])
        return
    try:
        bureau._assert_managed_runtime_unchanged(managed)
    except (OSError, RuntimeError) as exc:
        raise BureauPickupError(
            "canonical-registry-binding-drift",
            details=_runtime_error_details(exc),
        ) from None
    _validate_registry_binding_identity(binding["identity"])


def _prepare_request(
    request: dict[str, Any],
) -> tuple[dict[str, Any], RegistryBinding]:
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    prepared = dict(request)
    if "registry_root" in request:
        registry_root = _normalize_registry_root(request["registry_root"])
        binding = _explicit_registry_binding(registry_root)
    else:
        binding = _canonical_registry_binding()
        registry_root = binding["identity"]["registry_root"]
    prepared["registry_root"] = registry_root
    return _normalize_request(prepared), binding


def _bound_bureau_call(binding: RegistryBinding, callback):
    _assert_registry_binding(binding)
    result = callback()
    _assert_registry_binding(binding)
    return result


def _task_document_path(request: dict[str, Any]) -> Path | None:
    task_id = request["task_id"]
    if task_id is None or TASK_ID_RE.fullmatch(task_id) is None:
        return None
    root = Path(request["registry_root"])
    path = root / "registry" / "tasks" / f"{task_id}.json"
    expected_parent = root / "registry" / "tasks"
    if path.parent != expected_parent:
        return None
    return path


def _machine_completion_closeout_latch(
    request: dict[str, Any],
) -> dict[str, Any] | None:
    """Return content-bound closeout evidence without asserting Bureau terminality."""
    path = _task_document_path(request)
    if path is None or not os.path.lexists(path):
        return None
    try:
        snapshot = bureau._read_regular_file_snapshot(
            path,
            label="bureau-machine-completion-task",
            max_bytes=MAX_REQUEST_BYTES,
        )
    except (OSError, RuntimeError) as exc:
        raise BureauPickupError(
            "bureau-machine-completion-task-unreadable",
            details=_runtime_error_details(exc, task_id=request["task_id"]),
        ) from None
    try:
        task = json.loads(snapshot.raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BureauPickupError(
            "bureau-machine-completion-task-invalid",
            details={"task_id": request["task_id"]},
        ) from None
    if not isinstance(task, dict) or task.get("id") != request["task_id"]:
        raise BureauPickupError(
            "bureau-machine-completion-task-binding-invalid",
            details={"task_id": request["task_id"]},
        )
    task_state = task.get("state")
    if not isinstance(task_state, str) or not task_state:
        raise BureauPickupError(
            "bureau-machine-completion-task-state-invalid",
            details={"task_id": request["task_id"]},
        )
    if task_state in TERMINAL_BUREAU_TASK_STATES:
        return None

    metadata = task.get("metadata")
    partial = metadata.get("partial_completion") if isinstance(metadata, dict) else None
    completion = partial.get("completion") if isinstance(partial, dict) else None
    verification = metadata.get("verification") if isinstance(metadata, dict) else None
    if not isinstance(completion, dict) or not isinstance(verification, dict):
        return None
    if completion.get("state") != "verified":
        return None
    verified_at = completion.get("verified_at")
    if (
        not isinstance(verified_at, str)
        or not verified_at
        or metadata.get("verified_at") != verified_at
    ):
        return None
    acceptance = task.get("acceptance")
    if not isinstance(acceptance, list) or not acceptance:
        return None
    acceptance_ids: list[str] = []
    normalized_acceptance_ids: list[str] = []
    for item in acceptance:
        identifier = item.get("id") if isinstance(item, dict) else None
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in acceptance_ids
        ):
            return None
        normalized_identifier = re.sub(
            r"[^a-z0-9]+", "_", identifier.lower()
        ).strip("_")
        if (
            not normalized_identifier
            or normalized_identifier in normalized_acceptance_ids
        ):
            return None
        acceptance_ids.append(identifier)
        normalized_acceptance_ids.append(normalized_identifier)
    acceptance_results = completion.get("acceptance_results")
    if (
        not isinstance(acceptance_results, dict)
        or len(acceptance_results) != len(acceptance_ids)
        or any(not isinstance(key, str) or not key for key in acceptance_results)
        or any(value is not True for value in acceptance_results.values())
    ):
        return None
    matched_result_keys: set[str] = set()
    for identifier in normalized_acceptance_ids:
        matches = [
            key
            for key in acceptance_results
            if key == identifier or key.startswith(f"{identifier}_")
        ]
        if len(matches) != 1 or matches[0] in matched_result_keys:
            return None
        matched_result_keys.add(matches[0])
    authority = verification.get("authority")
    task_sha256 = verification.get("task_sha256")
    plan_sha256 = verification.get("plan_sha256")
    if (
        not isinstance(authority, str)
        or not authority
        or not isinstance(task_sha256, str)
        or SHA256_RE.fullmatch(task_sha256) is None
        or not isinstance(plan_sha256, str)
        or SHA256_RE.fullmatch(plan_sha256) is None
    ):
        return None

    bound_evidence: dict[str, Any] = {}
    for field in MACHINE_COMPLETION_BINDING_FIELDS:
        if field not in completion or field not in verification:
            continue
        if completion[field] != verification[field]:
            return None
        value = completion[field]
        if isinstance(value, str) and value:
            bound_evidence[field] = value
    if not bound_evidence:
        return None
    strong_identity_fields = {"merge_commit", "runtime_head", "source_commit"}
    if not any(
        field.endswith("sha256") or field in strong_identity_fields
        for field in bound_evidence
    ):
        return None
    for field, value in bound_evidence.items():
        if field.endswith("sha256") and SHA256_RE.fullmatch(value) is None:
            return None
        if (
            field in {"merge_commit", "runtime_head", "source_commit"}
            and re.fullmatch(r"[0-9a-f]{40}", value) is None
        ):
            return None

    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": "bureau-machine-completion-closeout-latch",
        "task_id": request["task_id"],
        "observed_task_state": task_state,
        "task_document_sha256": snapshot.sha256,
        "completion_sha256": _sha256(completion),
        "verification_sha256": _sha256(verification),
        "verified_at": verified_at,
        "verification_authority": authority,
        "verification_task_sha256": task_sha256,
        "verification_plan_sha256": plan_sha256,
        "acceptance_result_count": len(acceptance_results),
        "acceptance_results_sha256": _sha256(acceptance_results),
        "bound_evidence": bound_evidence,
        "suppressed_effects": [
            "bureau_claim",
            "grabowski_resource_acquisition",
            "workspace_creation",
            "repeat_code_probe",
            "repeat_runtime_deployment",
            "repeat_connector_probe",
        ],
        "recommended_next_action": "terminalize-or-archive-through-bureau-lifecycle",
        "invalidates_when": [
            "task_document_sha256 changes",
            "completion.state is no longer verified",
            "completion and verification bindings diverge",
        ],
        "does_not_establish": [
            "a terminal Bureau task state",
            "permission to mutate the Bureau Registry",
            "completion independent of the bound task evidence",
        ],
    }
    return {**material, "latch_sha256": _sha256(material)}


def _normalize_request(
    request: dict[str, Any], *, allow_internal_bindings: bool = False
) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    allowed = {
        "worker_id",
        "capabilities",
        "task_id",
        "resource",
        "kind",
        "base_dir",
        "approval_source",
        "approval_level",
        "lease_ttl_seconds",
        "create_workspace",
        "repository_scope_manifests",
        "nonconflict_proofs",
        "registry_root",
    }
    if allow_internal_bindings:
        allowed.add("coordination_root")
    extra = sorted(set(request) - allowed)
    if extra:
        raise ValueError(f"unsupported request fields: {extra}")
    worker_id = _text(request.get("worker_id"), label="worker_id", maximum=200)
    raw_task_id = request.get("task_id")
    task_id = (
        None
        if raw_task_id is None
        else _text(raw_task_id, label="task_id", maximum=200)
    )
    kind = _text(
        request.get("kind", "interactive-agent"), label="kind", maximum=128
    )
    approval_source = _text(
        request.get("approval_source", "grabowski_bureau_pickup_execute"),
        label="approval_source",
        maximum=512,
    )
    approval_level = _text(
        request.get("approval_level", "operator"),
        label="approval_level",
        maximum=32,
    )
    if approval_level not in {"operator", "break_glass"}:
        raise ValueError("approval_level must be operator or break_glass")
    registry_root = _normalize_registry_root(
        request.get("registry_root", str(bureau.BUREAU_ROOT))
    )
    coordination_root = _normalize_coordination_root(
        request.get("coordination_root", str(_default_coordination_root())),
        registry_root=registry_root,
    )
    resource = request.get("resource")
    if resource is not None:
        resource = _text(resource, label="resource", maximum=512)
    base_dir = request.get("base_dir")
    if base_dir is not None:
        base_dir = str(Path(_text(base_dir, label="base_dir", maximum=4096)).expanduser())
        if not Path(base_dir).is_absolute():
            raise ValueError("base_dir must be absolute")
    create_workspace = request.get("create_workspace", True)
    if not isinstance(create_workspace, bool):
        raise ValueError("create_workspace must be boolean")
    return {
        "worker_id": worker_id,
        "capabilities": _capabilities(request.get("capabilities")),
        "task_id": task_id,
        "resource": resource,
        "kind": kind,
        "base_dir": base_dir,
        "approval_source": approval_source,
        "approval_level": approval_level,
        "registry_root": registry_root,
        "coordination_root": coordination_root,
        "lease_ttl_seconds": _ttl(request.get("lease_ttl_seconds", 900)),
        "create_workspace": create_workspace,
        "repository_scope_manifests": _normalize_scope_manifests(
            request.get("repository_scope_manifests")
        ),
        "nonconflict_proofs": _normalize_nonconflict_proofs(
            request.get("nonconflict_proofs")
        ),
    }


def _bureau_arguments(
    command: str, *, registry_root: str, coordination_root: str | None
) -> list[str]:
    arguments = ["--root", registry_root]
    if coordination_root is not None:
        arguments.extend(["--state-root", coordination_root])
    arguments.extend(["--json", "--json-envelope", command])
    return arguments


def _claim_intent(request: dict[str, Any]) -> dict[str, Any]:
    arguments = _bureau_arguments(
        "claim-intent",
        registry_root=request["registry_root"],
        coordination_root=request["coordination_root"],
    )
    arguments.extend(["--worker", request["worker_id"]])
    arguments.extend(["--kind", request["kind"]])
    if request["task_id"] is not None:
        arguments.extend(["--task-id", request["task_id"]])
    for capability in request["capabilities"]:
        arguments.extend(["--capability", capability])
    if request["resource"]:
        arguments.extend(["--resource", request["resource"]])
    if request["base_dir"]:
        arguments.extend(["--base-dir", request["base_dir"]])
    arguments.append(
        "--break-glass" if request["approval_level"] == "break_glass" else "--approve"
    )
    arguments.extend(["--approval-source", request["approval_source"]])
    return bureau._invoke_bureau(arguments, include_runtime_identity=True)


def _claim_intent_or_closeout(
    request: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    closeout_latch = _machine_completion_closeout_latch(request)
    if closeout_latch is not None:
        return None, closeout_latch
    ensured_coordination_root = _ensure_coordination_root(request["coordination_root"])
    if ensured_coordination_root != request["coordination_root"]:
        raise BureauPickupError("coordination-root-binding-changed")
    return _claim_intent(request), None


def _bounded_claim_rejection_value(value: Any) -> Any:
    raw = _canonical_json(value)
    if len(raw) <= MAX_CLAIM_REJECTION_VALUE_BYTES:
        return value
    return {
        "raw_omitted": True,
        "original_type": type(value).__name__,
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _claim_intent_rejection(payload: dict[str, Any]) -> BureauPickupError:
    status = payload.get("status")
    source_code = payload.get("code")
    token = source_code if isinstance(source_code, str) else status
    if (
        not isinstance(token, str)
        or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", token) is None
    ):
        error_code = "claim-intent-not-ready"
    else:
        candidate = (
            token if token.startswith("claim-intent-") else f"claim-intent-{token}"
        )
        error_code = (
            candidate
            if len(candidate) <= MAX_CLAIM_REJECTION_CODE_BYTES
            else "claim-intent-not-ready"
        )

    details: dict[str, Any] = {
        "status": _bounded_claim_rejection_value(status),
        "source_code": _bounded_claim_rejection_value(source_code),
    }
    if payload.get("kind") == "grabowski_bureau_intake_adapter_failure":
        details["adapter_failure"] = _bounded_claim_rejection_value(
            {
                key: payload[key]
                for key in (
                    "schema_version",
                    "effect_started",
                    "retryable",
                    "ambiguity",
                    "required_readback",
                    "details",
                )
                if key in payload
            }
        )
    if payload.get("kind") == "bureau_approval_required":
        approval = payload.get("approval")
        if isinstance(approval, dict):
            details["approval"] = _bounded_claim_rejection_value(approval)
    detail = payload.get("detail")
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except json.JSONDecodeError:
            pass
    if detail is not None:
        details["detail"] = _bounded_claim_rejection_value(detail)

    runtime_identity = payload.get("runtime_identity")
    if isinstance(runtime_identity, dict):
        summary: dict[str, Any] = {}
        compatibility = runtime_identity.get("compatibility")
        if isinstance(compatibility, dict):
            summary["compatibility"] = compatibility
        registry = runtime_identity.get("registry")
        if isinstance(registry, dict):
            summary["registry"] = {
                key: registry.get(key)
                for key in (
                    "root",
                    "head",
                    "origin_main",
                    "head_equals_origin_main",
                    "dirty",
                )
                if key in registry
            }
        manifest = runtime_identity.get("manifest")
        if isinstance(manifest, dict):
            canonical_registry = manifest.get("canonical_registry")
            summary["manifest"] = {
                "source_commit": manifest.get("source_commit"),
                "canonical_registry_source_commit": (
                    canonical_registry.get("source_commit")
                    if isinstance(canonical_registry, dict)
                    else None
                ),
            }
        if summary:
            details["runtime_identity"] = _bounded_claim_rejection_value(summary)
    return BureauPickupError(error_code, details=details)


def _validate_claim_intent_resource_keys(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(key, str) for key in value):
        raise BureauPickupError(
            "claim-intent-resource-set-invalid",
            details={
                "effect_started": False,
                "required_readback": ["claim-intent"],
                "resource_lease_contract_version": (
                    resources.RESOURCE_LEASE_CONTRACT_CURRENT_VERSION
                ),
            },
        )
    if value != sorted(set(value)):
        raise BureauPickupError(
            "claim-intent-resource-set-invalid",
            details={
                "effect_started": False,
                "required_readback": ["claim-intent"],
                "resource_lease_contract_version": (
                    resources.RESOURCE_LEASE_CONTRACT_CURRENT_VERSION
                ),
            },
        )
    for index, key in enumerate(value):
        key_sha256 = hashlib.sha256(key.encode("utf-8")).hexdigest()
        try:
            normalized = resources.normalize_resource_key(key)
        except ValueError as exc:
            raise BureauPickupError(
                "claim-intent-resource-key-invalid",
                details={
                    "effect_started": False,
                    "required_readback": ["claim-intent"],
                    "resource_key_index": index,
                    "resource_key_sha256": key_sha256,
                    "error_type": type(exc).__name__,
                    "resource_lease_contract_version": (
                        resources.RESOURCE_LEASE_CONTRACT_CURRENT_VERSION
                    ),
                },
            ) from None
        if normalized != key:
            raise BureauPickupError(
                "claim-intent-resource-key-noncanonical",
                details={
                    "effect_started": False,
                    "required_readback": ["claim-intent"],
                    "resource_key_index": index,
                    "resource_key_sha256": key_sha256,
                    "normalized_resource_key_sha256": hashlib.sha256(
                        normalized.encode("utf-8")
                    ).hexdigest(),
                    "resource_lease_contract_version": (
                        resources.RESOURCE_LEASE_CONTRACT_CURRENT_VERSION
                    ),
                },
            )
    return value


def _validate_intent_result(
    payload: dict[str, Any], request: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    status = payload.get("status")
    existing = status in {"existing-assignment", "existing-terminal"}
    if status == "claim-intent":
        intent = payload.get("intent")
    elif existing:
        envelope = payload.get("envelope")
        intent = envelope.get("claim_intent") if isinstance(envelope, dict) else None
    else:
        raise _claim_intent_rejection(payload)
    if not isinstance(intent, dict):
        raise BureauPickupError("claim-intent-missing")
    if RUN_ID_RE.fullmatch(str(intent.get("run_id", ""))) is None:
        raise BureauPickupError("claim-intent-run-id-invalid")
    selected_task_id = intent.get("task_id")
    if (
        not isinstance(selected_task_id, str)
        or TASK_ID_RE.fullmatch(selected_task_id) is None
    ):
        raise BureauPickupError("claim-intent-task-id-invalid")
    if request["task_id"] is not None and selected_task_id != request["task_id"]:
        raise BureauPickupError("claim-intent-task-mismatch")
    if intent.get("worker_id") != request["worker_id"]:
        raise BureauPickupError("claim-intent-worker-mismatch")
    digest = intent.get("intent_sha256")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise BureauPickupError("claim-intent-digest-invalid")
    _validate_claim_intent_resource_keys(intent.get("required_resource_keys"))
    if intent.get("lease_owner_id") != f"bureau-run:{intent['run_id']}":
        raise BureauPickupError("claim-intent-owner-invalid")
    expires_at = intent.get("expires_at_unix")
    if not isinstance(expires_at, int):
        raise BureauPickupError("claim-intent-expiry-invalid")
    if not existing and expires_at <= int(time.time()):
        raise BureauPickupError("claim-intent-expired")
    return intent, existing


def _lease_metadata(intent: dict[str, Any], *, group: str) -> dict[str, Any]:
    return {
        "task_id": intent["task_id"],
        "run_id": intent["run_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "pickup_schema_version": SCHEMA_VERSION,
        "pickup_group": group,
        "resource_lease_contract_version": (
            resources.RESOURCE_LEASE_CONTRACT_CURRENT_VERSION
        ),
    }


def _intent_repository_scope_manifest(
    intent: dict[str, Any], resource_key: str
) -> dict[str, Any]:
    repository = resource_key.removeprefix("repo:")
    workspace = intent.get("workspace")
    if not isinstance(workspace, dict):
        raise BureauPickupError(
            "repository-scope-required",
            details={
                "resource_key": resource_key,
                "reason": "claim-intent-workspace-missing",
            },
        )
    if workspace.get("repository") != repository:
        raise BureauPickupError(
            "claim-intent-workspace-repository-mismatch",
            details={"resource_key": resource_key},
        )
    return {
        "schema_version": 1,
        "repository": repository,
        "task_id": intent["task_id"],
        "base_head": workspace.get("source_head_at_intent"),
        "head": workspace.get("source_head_at_intent"),
        "branch": workspace.get("workspace_branch"),
        "worktree": workspace.get("workspace_path"),
        "effects": ["write"],
        "paths": [repository],
        "components": [],
        "runtime_resources": [],
        "processes": [],
        "deployments": [],
        "migrations": [],
        "generated_artifacts": [],
        "shared_gates": [],
    }


def _bounded_work_admission_evidence(assessment: Any) -> dict[str, Any]:
    if not isinstance(assessment, dict):
        return {"assessment_present": False}
    evidence: dict[str, Any] = {"assessment_present": True}
    for key, limit in (
        ("kind", 128),
        ("repository", 1024),
        ("operation", 256),
        ("decision", 64),
        ("next_action", 1024),
    ):
        value = assessment.get(key)
        if isinstance(value, str) and value:
            evidence[key] = value[:limit]
    schema_version = assessment.get("schema_version")
    if isinstance(schema_version, int) and not isinstance(schema_version, bool):
        evidence["schema_version"] = schema_version
    assessment_sha256 = assessment.get("assessment_sha256")
    if isinstance(assessment_sha256, str) and SHA256_RE.fullmatch(assessment_sha256):
        evidence["assessment_sha256"] = assessment_sha256
    blocker_codes = assessment.get("blocker_codes")
    if isinstance(blocker_codes, list):
        evidence["blocker_codes"] = [
            value[:128]
            for value in blocker_codes[:16]
            if isinstance(value, str) and value
        ]
    raw_blockers = assessment.get("blockers")
    if isinstance(raw_blockers, list):
        evidence["blocker_count"] = len(raw_blockers)
        evidence["blockers_truncated"] = len(raw_blockers) > 16
        blockers: list[dict[str, str]] = []
        for raw in raw_blockers[:16]:
            if not isinstance(raw, dict):
                continue
            bounded: dict[str, str] = {}
            for key, limit in (
                ("code", 128),
                ("detail", 1024),
                ("path", 1024),
                ("state", 128),
                ("checkout_key", 256),
                ("owner_id", 256),
                ("resource_key", 1024),
            ):
                value = raw.get(key)
                if isinstance(value, str) and value:
                    bounded[key] = value[:limit]
            if bounded:
                blockers.append(bounded)
        evidence["blockers"] = blockers
    return evidence


def _acquisition_groups(
    intent: dict[str, Any], request: dict[str, Any]
) -> list[dict[str, Any]]:
    keys = list(intent["required_resource_keys"])
    bureau_keys = bureau_leases.bureau_resource_keys(keys)
    remaining = [key for key in keys if key not in bureau_keys]
    repo_keys = [key for key in remaining if key.startswith("repo:")]
    other_keys = [key for key in remaining if not key.startswith("repo:")]
    groups: list[dict[str, Any]] = []
    if bureau_keys:
        metadata = _lease_metadata(intent, group="bureau")
        metadata["bureau_expected_state"] = intent["intent_sha256"]
        groups.append(
            {
                "name": "bureau",
                "resource_keys": bureau_keys,
                "metadata": metadata,
                "nonconflict_proof": None,
                "ttl_seconds": (
                    min(request["lease_ttl_seconds"], 300)
                    if {
                        bureau_leases.BUREAU_WORKTREE_ADMIN_KEY,
                        bureau_leases.BUREAU_MERGE_GATE_KEY,
                    }.intersection(bureau_keys)
                    else request["lease_ttl_seconds"]
                ),
            }
        )
    for key in repo_keys:
        if resources.scoped_repository_resource_root(key) is not None:
            groups.append(
                {
                    "name": key,
                    "resource_keys": [key],
                    "metadata": _lease_metadata(intent, group=key),
                    "nonconflict_proof": request["nonconflict_proofs"].get(key),
                    "ttl_seconds": request["lease_ttl_seconds"],
                }
            )
            continue
        scope = request["repository_scope_manifests"].get(key)
        if scope is None:
            if not request["create_workspace"]:
                raise BureauPickupError(
                    "repository-scope-required", details={"resource_key": key}
                )
            scope = _intent_repository_scope_manifest(intent, key)
        metadata = _lease_metadata(intent, group=key)
        metadata["scope_manifest"] = scope
        metadata["scope_manifest_complete"] = True
        groups.append(
            {
                "name": key,
                "resource_keys": [key],
                "metadata": metadata,
                "nonconflict_proof": request["nonconflict_proofs"].get(key),
                "ttl_seconds": request["lease_ttl_seconds"],
            }
        )
    if other_keys:
        groups.append(
            {
                "name": "other",
                "resource_keys": other_keys,
                "metadata": _lease_metadata(intent, group="other"),
                "nonconflict_proof": request["nonconflict_proofs"].get("other"),
                "ttl_seconds": request["lease_ttl_seconds"],
            }
        )
    return groups


def _preflight_acquisition_groups(
    intent: dict[str, Any], request: dict[str, Any]
) -> list[dict[str, Any]]:
    """Build and validate the effect-free lease plan before journaling intent."""
    try:
        groups = _acquisition_groups(intent, request)
        for group in groups:
            metadata = group["metadata"]
            scope = metadata.get("scope_manifest")
            normalized_scope: dict[str, Any] | None = None
            if scope is not None:
                normalized_scope = nonconflict.normalize_scope_manifest(scope)
                broad_repository_keys = [
                    key
                    for key in group["resource_keys"]
                    if key.startswith("repo:")
                    and resources.scoped_repository_resource_root(key) is None
                ]
                expected_key = f"repo:{normalized_scope['repository']}"
                if broad_repository_keys and broad_repository_keys != [expected_key]:
                    raise ValueError(
                        "scope_manifest repository must match acquisition resource key"
                    )
                metadata["scope_manifest"] = normalized_scope
            proof = group["nonconflict_proof"]
            if proof is None:
                continue
            validated_proof = nonconflict.validate_public_proof(proof)
            expected_keys = sorted(group["resource_keys"])
            if validated_proof["requesting_owner"] != intent["lease_owner_id"]:
                raise nonconflict.NonConflictDenied(
                    "owner-drift",
                    "non-conflict proof owner does not match the claim intent",
                )
            if validated_proof["resource_keys"] != expected_keys:
                raise nonconflict.NonConflictDenied(
                    "resource-drift",
                    "non-conflict proof resources do not match the acquisition group",
                )
            expected_purpose = (
                f"Bureau coordinated pickup {intent['run_id']} group {group['name']}"
            )
            if (
                validated_proof["purpose_sha256"]
                != hashlib.sha256(expected_purpose.encode("utf-8")).hexdigest()
            ):
                raise nonconflict.NonConflictDenied(
                    "purpose-drift",
                    "non-conflict proof purpose does not match the acquisition group",
                )
            if normalized_scope is None:
                raise nonconflict.NonConflictDenied(
                    "requested-scope-missing",
                    "non-conflict exception requires metadata.scope_manifest",
                )
            if metadata.get("scope_manifest_complete") is not True:
                raise nonconflict.NonConflictDenied(
                    "requested-scope-unattested",
                    "requesting owner did not attest that the scope manifest is complete",
                )
            requested_scope = nonconflict.validate_resource_scope_binding(
                expected_keys, normalized_scope
            )
            if requested_scope != validated_proof["requested_scope"]:
                raise nonconflict.NonConflictDenied(
                    "scope-drift",
                    "requested scope changed after proof creation",
                )
            requested_ttl_seconds = group["ttl_seconds"]
            if type(requested_ttl_seconds) is not int or requested_ttl_seconds <= 0:
                raise ValueError("requested_ttl_seconds must be a positive integer")
            if (
                requested_ttl_seconds > nonconflict.MAX_PROOF_TTL_SECONDS
                or int(time.time()) + requested_ttl_seconds
                > validated_proof["expires_at_unix"]
            ):
                raise nonconflict.NonConflictDenied(
                    "lease-outlives-proof",
                    "requested lease would outlive the non-conflict proof",
                )
            group["nonconflict_proof"] = validated_proof
        return groups
    except BureauPickupError as exc:
        exc.details.setdefault("effect_started", False)
        exc.details.setdefault("required_readback", ["claim-intent"])
        raise
    except Exception as exc:
        raise BureauPickupError(
            "lease-acquisition-preflight-failed",
            details={
                "effect_started": False,
                "required_readback": ["claim-intent"],
                "error_type": type(exc).__name__,
            },
        ) from exc


def _validate_acquired_group(
    owner_id: str, group: dict[str, Any], result: dict[str, Any]
) -> None:
    if result.get("owner_id") != owner_id:
        raise BureauPickupError(
            "lease-acquisition-owner-mismatch",
            details={"group": group["name"]},
        )
    leases = result.get("leases")
    if not isinstance(leases, list):
        raise BureauPickupError(
            "lease-acquisition-snapshots-invalid",
            details={"group": group["name"]},
        )
    observed: dict[str, dict[str, Any]] = {}
    for lease in leases:
        if not isinstance(lease, dict) or not isinstance(lease.get("resource_key"), str):
            raise BureauPickupError(
                "lease-acquisition-snapshot-invalid",
                details={"group": group["name"]},
            )
        key = lease["resource_key"]
        if key in observed or lease.get("owner_id") != owner_id:
            raise BureauPickupError(
                "lease-acquisition-snapshot-binding-invalid",
                details={"group": group["name"], "resource_key": key},
            )
        observed[key] = lease
    expected = sorted(group["resource_keys"])
    if sorted(observed) != expected:
        raise BureauPickupError(
            "lease-acquisition-resource-set-mismatch",
            details={"group": group["name"], "expected": expected, "observed": sorted(observed),
            },
        )


def _acquire_groups(
    intent: dict[str, Any],
    request: dict[str, Any],
    run_dir: Path,
    *,
    groups: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    acquired: list[dict[str, Any]] = []
    owner_id = intent["lease_owner_id"]
    if groups is None:
        groups = _acquisition_groups(intent, request)
    try:
        for index, group in enumerate(groups, start=1):
            result = resources.acquire_resources(
                owner_id,
                group["resource_keys"],
                purpose=f"Bureau coordinated pickup {intent['run_id']} group {group['name']}",
                ttl_seconds=group["ttl_seconds"],
                metadata=group["metadata"],
                nonconflict_proof=group["nonconflict_proof"],
            )
            entry = {
                "group": group["name"],
                "resource_keys": group["resource_keys"],
                "result": result,
            }
            acquired.append(entry)
            _validate_acquired_group(owner_id, group, result)
            _write_bound_json(run_dir / f"lease-acquired-{index:02d}.json", entry)
    except Exception as exc:
        released = _compensate_acquisitions(owner_id, acquired, run_dir)
        details: dict[str, Any] = {
            "error_type": type(exc).__name__,
            "acquired_group_count": len(acquired),
            "compensation": released,
        }
        summary = None
        if isinstance(exc, work_admission.WorkAdmissionBlocked):
            summary = "lease-acquisition-work-admission-blocked"
            details.update(
                {
                    "cause_code": "work-admission-blocked",
                    "work_admission": _bounded_work_admission_evidence(
                        exc.assessment
                    ),
                }
            )
        raise BureauPickupError(
            "lease-acquisition-failed",
            details=details,
            summary=summary,
        ) from exc
    flattened = [
        lease
        for entry in acquired
        for lease in entry["result"].get("leases", [])
        if isinstance(lease, dict)
    ]
    result = {
        "schema_version": SCHEMA_VERSION,
        "owner_id": owner_id,
        "task_id": intent["task_id"],
        "run_id": intent["run_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "resource_lease_contract_version": (
            resources.RESOURCE_LEASE_CONTRACT_CURRENT_VERSION
        ),
        "resource_keys": intent["required_resource_keys"],
        "leases": flattened,
        "groups": acquired,
    }
    result["acquisition_sha256"] = _sha256(result)
    _write_bound_json(run_dir / "acquisition.json", result)
    return result


def _compensate_acquisitions(
    owner_id: str, acquired: list[dict[str, Any]], run_dir: Path
) -> dict[str, Any]:
    keys = sorted(
        {
            key
            for entry in acquired
            for key in entry.get("resource_keys", [])
            if isinstance(key, str)
        }
    )
    if not keys:
        return {"required": False, "released": []}
    try:
        result = resources.release_resources(owner_id, keys)
        payload = {"required": True, "status": "released", "result": result}
    except Exception as exc:
        payload = {
            "required": True,
            "status": "release-failed",
            "error_type": type(exc).__name__,
            "resource_keys": keys,
        }
    _write_bound_json(run_dir / "compensation.json", payload)
    return payload


def _lease_binding(intent: dict[str, Any], run_dir: Path) -> Path:
    path = run_dir / "lease-binding.json"
    _write_bound_json(
        path,
        {"owner_id": intent["lease_owner_id"], "task_id": intent["task_id"]},
    )
    return path


def _commit_claim(
    intent: dict[str, Any], request: dict[str, Any], run_dir: Path
) -> dict[str, Any]:
    intent_path = run_dir / "intent.json"
    arguments = _bureau_arguments(
        "claim-commit",
        registry_root=request["registry_root"],
        coordination_root=request["coordination_root"],
    )
    arguments.extend(["--intent", str(intent_path)])
    if intent["required_resource_keys"]:
        lease_path = _lease_binding(intent, run_dir)
        arguments.extend(["--lease-binding", str(lease_path)])
    if request["create_workspace"]:
        arguments.append("--workspace")
    return bureau._invoke_bureau(
        arguments,
        mutation=True,
        required_readback=[
            f"bureau_run:{intent['run_id']}",
            f"grabowski_leases:{intent['lease_owner_id']}",
        ],
    )


def _coordination_status(
    run_id: str, *, registry_root: str, coordination_root: str | None,
    activity_id: str | None = None,
) -> dict[str, Any]:
    arguments = [
        *_bureau_arguments(
            "claim-coordination-status",
            registry_root=registry_root,
            coordination_root=coordination_root,
        ),
        run_id,
    ]
    if activity_id is not None:
        arguments.extend(["--activity-id", activity_id])
    return bureau._invoke_bureau(arguments)


def _definitive_missing_run(payload: dict[str, Any]) -> bool:
    return (
        payload.get("status") != "coordinated"
        and payload.get("run") is None
        and payload.get("code")
        in {
            "unknown-run",
            "state-error-unknown-run",
        }
    )


def _validate_claim_readback(
    payload: dict[str, Any],
    intent: dict[str, Any],
    acquisition: dict[str, Any],
) -> dict[str, Any]:
    if payload.get("status") != "coordinated":
        raise BureauPickupError(
            "claim-readback-not-coordinated",
            details={"status": payload.get("status")},
        )
    run = payload.get("run")
    if not isinstance(run, dict):
        raise BureauPickupError("claim-readback-run-missing")
    expected_run = {
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "worker_id": intent["worker_id"],
    }
    mismatches = {
        key: {"expected": expected, "observed": run.get(key)}
        for key, expected in expected_run.items()
        if run.get(key) != expected
    }
    if mismatches:
        raise BureauPickupError(
            "claim-readback-run-binding-mismatch", details={"mismatches": mismatches}
        )
    if payload.get("claim_intent_sha256") != intent["intent_sha256"]:
        raise BureauPickupError("claim-readback-intent-mismatch")
    expected_acquisition = {
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "owner_id": intent["lease_owner_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "resource_keys": intent["required_resource_keys"],
    }
    acquisition_mismatches = {
        key: {"expected": expected, "observed": acquisition.get(key)}
        for key, expected in expected_acquisition.items()
        if acquisition.get(key) != expected
    }
    if acquisition_mismatches:
        raise BureauPickupError(
            "claim-readback-acquisition-binding-mismatch",
            details={"mismatches": acquisition_mismatches},
        )
    expected_keys = intent["required_resource_keys"]
    release = payload.get("release")
    if not isinstance(release, dict):
        raise BureauPickupError("claim-readback-release-missing")
    release_mismatches = {}
    expected_required = bool(expected_keys)
    if release.get("required") is not expected_required:
        release_mismatches["required"] = {
            "expected": expected_required,
            "observed": release.get("required"),
        }
    expected_release = {
        "owner_id": intent["lease_owner_id"],
        "resource_keys": expected_keys,
        "claim_intent_sha256": intent["intent_sha256"],
    }
    release_mismatches.update(
        {
            key: {"expected": expected, "observed": release.get(key)}
            for key, expected in expected_release.items()
            if release.get(key) != expected
        }
    )
    if release_mismatches:
        raise BureauPickupError(
            "claim-readback-release-binding-mismatch",
            details={"mismatches": release_mismatches},
        )
    if payload.get("blocking") is not False:
        raise BureauPickupError(
            "claim-readback-blocking-or-incomplete",
            details={"blocking": payload.get("blocking")},
        )
    return run


def _recover_after_commit(
    intent: dict[str, Any],
    acquisition: dict[str, Any],
    run_dir: Path,
    *,
    registry_root: str,
    coordination_root: str,
    registry_binding: dict[str, Any],
) -> dict[str, Any]:
    try:
        status = _bound_bureau_call(
            registry_binding,
            lambda: _coordination_status(
                intent["run_id"],
                registry_root=registry_root,
                coordination_root=coordination_root,
            ),
        )
        _write_bound_json(run_dir / "commit-readback.json", status)
    except Exception as exc:
        failure = {
            "status": "recovery-required",
            "readback_error_type": type(exc).__name__,
            "readback_error_code": (
                exc.code if isinstance(exc, BureauPickupError) else None
            ),
            "lease_owner_id": intent["lease_owner_id"],
            "resource_keys": intent["required_resource_keys"],
            "does_not_establish": [
                "a bound Bureau run",
                "permission to release leases",
                "safe retry without another readback",
            ],
        }
        try:
            _write_bound_json(run_dir / "commit-readback-failure.json", failure)
        except Exception:
            pass
        return failure
    if _definitive_missing_run(status):
        return {
            "status": "commit-not-applied",
            "coordination": status,
            "compensation": _compensate_acquisitions(
                intent["lease_owner_id"], acquisition["groups"], run_dir
            ),
        }
    try:
        run = _validate_claim_readback(status, intent, acquisition)
    except BureauPickupError as exc:
        failure = {
            "status": "recovery-required",
            "readback_error_type": type(exc).__name__,
            "readback_error_code": exc.code,
            "lease_owner_id": intent["lease_owner_id"],
            "resource_keys": intent["required_resource_keys"],
            "does_not_establish": [
                "a bound Bureau run",
                "permission to release leases",
                "safe retry without another readback",
            ],
        }
        _write_bound_json(run_dir / "commit-readback-failure.json", failure)
        return failure
    return {
        "status": "recovered",
        "run": run,
        "coordination": status,
        "coordination_sha256": _sha256(status),
        "acquisition": acquisition,
    }


def _lease_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    # Resource CAS mutation helpers accept exactly the canonical lease snapshot
    # fields.  reclaimed_from_owner is historical provenance, not lease identity
    # for renew/rebind CAS.
    return {key: value[key] for key in LEASE_IDENTITY_FIELDS}


def _owner_lease_matches_snapshot(
    expected: dict[str, Any], observed: dict[str, Any]
) -> bool:
    """Exact owner-lease identity vs stored snapshot; missing leases are caller-handled."""
    for field in LEASE_IDENTITY_FIELDS:
        if expected.get(field) != observed.get(field):
            return False
    if "reclaimed_from_owner" in expected or "reclaimed_from_owner" in observed:
        if expected.get("reclaimed_from_owner") != observed.get("reclaimed_from_owner"):
            return False
    return True


def _owner_lease_matches_terminal_lineage(
    expected: dict[str, Any], observed: dict[str, Any]
) -> bool:
    """Bind terminal release to owner lineage while allowing valid renewal/reacquire."""
    return all(
        expected.get(field) == observed.get(field)
        for field in ("resource_key", "owner_id", "metadata_sha256")
    )


def _lease_timestamp(value: dict[str, Any], field: str) -> int | None:
    timestamp = value.get(field)
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        return None
    return timestamp


def _foreign_lease_is_strict_successor(
    expected: dict[str, Any], observed: dict[str, Any]
) -> bool:
    """Prove that a foreign lease began strictly after the stored owner lease expired."""
    if expected.get("resource_key") != observed.get("resource_key"):
        return False
    expected_owner = expected.get("owner_id")
    observed_owner = observed.get("owner_id")
    if (
        not isinstance(expected_owner, str)
        or not expected_owner
        or not isinstance(observed_owner, str)
        or not observed_owner
        or observed_owner == expected_owner
    ):
        return False
    expected_acquired = _lease_timestamp(expected, "acquired_at_unix")
    expected_updated = _lease_timestamp(expected, "updated_at_unix")
    expected_expires = _lease_timestamp(expected, "expires_at_unix")
    observed_acquired = _lease_timestamp(observed, "acquired_at_unix")
    observed_updated = _lease_timestamp(observed, "updated_at_unix")
    observed_expires = _lease_timestamp(observed, "expires_at_unix")
    if None in {
        expected_acquired,
        expected_updated,
        expected_expires,
        observed_acquired,
        observed_updated,
        observed_expires,
    }:
        return False
    assert expected_acquired is not None
    assert expected_updated is not None
    assert expected_expires is not None
    assert observed_acquired is not None
    assert observed_updated is not None
    assert observed_expires is not None
    if (
        expected_updated < expected_acquired
        or expected_updated >= expected_expires
        or expected_expires <= expected_acquired
    ):
        return False
    if (
        observed_updated < observed_acquired
        or observed_updated >= observed_expires
        or observed_expires <= observed_acquired
    ):
        return False
    return observed_acquired > expected_expires

def _journal_run_ids() -> list[str]:
    root = _absolute_path(STATE_ROOT)
    parent_descriptor = _open_existing_directory_chain(
        root.parent, label="pickup-state-parent"
    )
    root_descriptor = runs_descriptor = -1
    try:
        try:
            root_path, root_descriptor = _open_or_create_private_child(
                parent_descriptor,
                root.parent,
                root.name,
                label="pickup-root",
                create=False,
            )
            runs_path, runs_descriptor = _open_or_create_private_child(
                root_descriptor,
                root_path,
                "runs",
                label="pickup-runs",
                create=False,
            )
        except BureauPickupError as exc:
            if exc.code in {
                "pickup-root-directory-missing",
                "pickup-runs-directory-missing",
            }:
                return []
            raise
        _assert_private_directory_binding(root_descriptor, root_path, label="pickup-root")
        _assert_private_directory_binding(runs_descriptor, runs_path, label="pickup-runs")
        names = os.listdir(runs_descriptor)
        if len(names) > MAX_JOURNAL_REPLAY_RUNS:
            raise BureauPickupError(
                "existing-assignment-journal-scan-too-large",
                details={"limit": MAX_JOURNAL_REPLAY_RUNS, "observed": len(names)},
            )
        return sorted(
            (name for name in names if RUN_ID_RE.fullmatch(name) is not None),
            reverse=True,
        )
    finally:
        os.close(parent_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        if runs_descriptor >= 0:
            os.close(runs_descriptor)


def _claim_rejection_allows_journal_replay(
    error: BureauPickupError, request: dict[str, Any]
) -> bool:
    if error.code in {
        "claim-intent-runtime-drift-blocked",
        "claim-intent-stale-runtime-blocked",
    }:
        return True
    if error.code != "claim-intent-state-error":
        return False
    detail = error.details.get("detail")
    if not isinstance(detail, str):
        return False
    prefix = f"request binding mismatch for existing assignment {request['task_id']}: "
    if not detail.startswith(prefix):
        return False
    digests = detail[len(prefix) :]
    match = re.fullmatch(
        r"expected=([0-9a-f]{64}) actual=([0-9a-f]{64})", digests
    )
    return match is not None and match.group(1) != match.group(2)


def _journaled_existing_assignment_after_claim_rejection(
    request: dict[str, Any],
    registry_binding: RegistryBinding,
) -> tuple[dict[str, Any], RegistryBinding, dict[str, Any], dict[str, Any]] | None:
    if not registry_binding["explicit"]:
        return None
    candidates: list[
        tuple[dict[str, Any], RegistryBinding, dict[str, Any], dict[str, Any], Path]
    ] = []
    for run_id in _journal_run_ids():
        run_dir = _absolute_path(STATE_ROOT) / "runs" / run_id
        try:
            stored_payload = _read_bound_json(run_dir / "request.json", label="request")
        except BureauPickupError as exc:
            if exc.code.startswith("request-"):
                continue
            raise
        stored_payload = dict(stored_payload)
        binding_marker = _normalize_registry_binding_marker(
            stored_payload.pop("registry_binding_sha256", None)
        )
        if "coordination_root" not in stored_payload:
            if Path(request["coordination_root"]) != _legacy_coordination_root():
                continue
            stored_payload["coordination_root"] = request["coordination_root"]
        if "registry_root" in stored_payload:
            try:
                _normalize_registry_root(stored_payload["registry_root"])
            except ValueError as exc:
                if isinstance(exc.__cause__, (FileNotFoundError, NotADirectoryError)):
                    continue
                raise
        stored_request = _normalize_request(
            stored_payload, allow_internal_bindings=True
        )
        if stored_request != request:
            continue
        stored_binding = _read_journal_registry_binding(
            run_dir,
            stored_request["registry_root"],
            expected_sha256=binding_marker,
        )
        if stored_binding["identity"] != registry_binding["identity"]:
            raise BureauPickupError(
                "existing-assignment-registry-binding-mismatch",
                details={"run_id": run_id},
            )
        intent = _read_bound_json(run_dir / "intent.json", label="intent")
        synthetic = {
            "status": "existing-assignment",
            "run": {"run_id": run_id, "state": "assigned"},
            "envelope": {"claim_intent": intent},
        }
        validated_intent, _existing = _validate_intent_result(
            synthetic, stored_request
        )
        if validated_intent["run_id"] != run_id:
            raise BureauPickupError("existing-assignment-journal-run-mismatch")
        acquisition = _read_bound_json(
            run_dir / "acquisition.json", label="acquisition"
        )
        _validate_acquisition(acquisition)
        if acquisition.get("claim_intent_sha256") != intent["intent_sha256"]:
            raise BureauPickupError("existing-assignment-acquisition-mismatch")
        candidates.append(
            (synthetic, stored_binding, stored_request, acquisition, run_dir)
        )
    if not candidates:
        return None
    if len(candidates) != 1:
        raise BureauPickupError(
            "existing-assignment-journal-ambiguous",
            details={
                "task_id": request["task_id"],
                "worker_id": request["worker_id"],
                "candidate_run_ids": [item[0]["run"]["run_id"] for item in candidates],
            },
        )
    synthetic, stored_binding, stored_request, acquisition, _run_dir = candidates[0]
    intent = synthetic["envelope"]["claim_intent"]
    coordination = _bound_bureau_call(
        stored_binding,
        lambda: _coordination_status(
            intent["run_id"],
            registry_root=stored_request["registry_root"],
            coordination_root=stored_request["coordination_root"],
        ),
    )
    try:
        _validate_claim_readback(coordination, intent, acquisition)
    except BureauPickupError as exc:
        if exc.code != "claim-readback-blocking-or-incomplete":
            raise
    run = coordination.get("run")
    if not isinstance(run, dict):
        raise BureauPickupError("claim-readback-run-missing")
    synthetic["status"] = (
        "existing-assignment"
        if run.get("state") in {"assigned", "running", "verifying"}
        else "existing-terminal"
    )
    synthetic["run"] = run
    return synthetic, stored_binding, stored_request, coordination



def _request_without_registry_root(request: dict[str, Any]) -> dict[str, Any]:
    payload = dict(request)
    payload.pop("registry_root", None)
    return payload


def _registry_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        snapshot = bureau._read_regular_file_snapshot(
            path, label=label, max_bytes=MAX_REQUEST_BYTES
        )
    except (OSError, RuntimeError) as exc:
        raise BureauPickupError(
            f"{label}-read-failed", details=_runtime_error_details(exc, path=str(path))
        ) from None
    try:
        value = json.loads(snapshot.raw)
    except json.JSONDecodeError:
        raise BureauPickupError(f"{label}-invalid") from None
    if not isinstance(value, dict):
        raise BureauPickupError(f"{label}-invalid")
    return value


def _registry_successor_proof(
    stored_binding: RegistryBinding, current_binding: RegistryBinding
) -> dict[str, Any]:
    stored = _validate_registry_binding_identity(stored_binding["identity"])
    current = _validate_registry_binding_identity(current_binding["identity"])
    if (
        stored.get("kind") != "canonical-registry-binding"
        or current.get("kind") != "canonical-registry-binding"
    ):
        raise BureauPickupError("orphan-recovery-requires-canonical-registry")
    before = stored["source_commit"]
    after = current["source_commit"]
    if before != after:
        lines = bureau._git_identity_lines(
            bureau_leases.BUREAU_REPOSITORY_ROOT,
            "merge-base",
            "--is-ancestor",
            before,
            after,
        )
        if lines is None:
            raise BureauPickupError(
                "orphan-recovery-registry-source-not-ancestor",
                details={"stored_source_commit": before, "current_source_commit": after,
                },
            )
    return {
        "repository": str(bureau_leases.BUREAU_REPOSITORY_ROOT),
        "stored_source_commit": before,
        "current_source_commit": after,
        "stored_registry_binding_sha256": stored["binding_sha256"],
        "current_registry_binding_sha256": current["binding_sha256"],
        "ancestor_proven": True,
    }


def _authoritative_task_spec_for_recovery(
    registry_task: dict[str, Any],
    *,
    task_id: str,
    coordination_root: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if coordination_root is None:
        return registry_task, {"kind": "legacy-git-bootstrap", "revision": None}
    state_root = Path(coordination_root)
    state_db = state_root / "bureau.sqlite3"
    try:
        metadata = os.lstat(state_db)
    except FileNotFoundError:
        raise BureauPickupError(
            "orphan-recovery-state-db-missing", details={"path": str(state_db)}
        ) from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BureauPickupError(
            "orphan-recovery-state-db-unsafe", details={"path": str(state_db)}
        )
    try:
        connection = sqlite3.connect(
            f"file:{state_db}?mode=ro", uri=True, timeout=5
        )
        connection.row_factory = sqlite3.Row
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name IN ('task_specs','task_spec_revisions')"
                )
            }
            if tables != {"task_specs", "task_spec_revisions"}:
                raise BureauPickupError("orphan-recovery-task-spec-schema-drift")
            count = int(connection.execute("SELECT COUNT(*) FROM task_specs").fetchone()[0])
            if count == 0:
                return registry_task, {
                    "kind": "legacy-git-bootstrap",
                    "revision": None,
                }
            row = connection.execute(
                "SELECT p.current_revision AS current_revision, "
                "p.spec_sha256 AS pointer_sha256, "
                "r.revision AS revision, r.parent_revision AS parent_revision, "
                "r.spec_sha256 AS revision_sha256, r.spec_json AS spec_json "
                "FROM task_specs p JOIN task_spec_revisions r "
                "ON r.task_id=p.task_id AND r.revision=p.current_revision "
                "WHERE p.task_id=?",
                (task_id,),
            ).fetchone()
        finally:
            connection.close()
    except BureauPickupError:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
        raise BureauPickupError(
            "orphan-recovery-task-spec-read-failed",
            details={"path": str(state_db), "error_type": type(exc).__name__},
        ) from exc
    if row is None:
        raise BureauPickupError(
            "orphan-recovery-authoritative-task-missing",
            details={"task_id": task_id},
        )
    revision = int(row["revision"])
    current_revision = int(row["current_revision"])
    parent = row["parent_revision"]
    parent_revision = None if parent is None else int(parent)
    pointer_sha256 = row["pointer_sha256"]
    revision_sha256 = row["revision_sha256"]
    if (
        revision < 1
        or current_revision != revision
        or parent_revision != (None if revision == 1 else revision - 1)
        or not isinstance(pointer_sha256, str)
        or SHA256_RE.fullmatch(pointer_sha256) is None
        or pointer_sha256 != revision_sha256
    ):
        raise BureauPickupError("orphan-recovery-task-spec-pointer-drift")
    try:
        spec = json.loads(str(row["spec_json"]))
    except (TypeError, json.JSONDecodeError) as exc:
        raise BureauPickupError("orphan-recovery-task-spec-json-invalid") from exc
    if not isinstance(spec, dict) or spec.get("id") != task_id:
        raise BureauPickupError("orphan-recovery-task-spec-id-drift")
    if _sha256(spec) != revision_sha256:
        raise BureauPickupError("orphan-recovery-task-spec-digest-drift")
    return spec, {
        "kind": "bureau-state-store-task-specs",
        "revision": revision,
        "spec_sha256": revision_sha256,
        "state_db": str(state_db),
    }


def _current_registry_revision_proof(
    current_binding: RegistryBinding,
    intent: dict[str, Any],
    *,
    coordination_root: str | None = None,
) -> dict[str, Any]:
    identity = _validate_registry_binding_identity(current_binding["identity"])
    if identity.get("kind") != "canonical-registry-binding":
        raise BureauPickupError("orphan-recovery-requires-canonical-registry")
    task_id = intent["task_id"]
    root = Path(identity["registry_root"])
    task = _registry_json(
        root / "registry" / "tasks" / f"{task_id}.json",
        label="orphan-recovery-task",
    )
    if task.get("id") != task_id:
        raise BureauPickupError("orphan-recovery-task-id-drift")
    task, task_authority = _authoritative_task_spec_for_recovery(
        task, task_id=task_id, coordination_root=coordination_root
    )
    revision = json.loads(json.dumps(task))
    revision.pop("state", None)
    metadata = revision.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("verification", None)
        if not metadata:
            revision.pop("metadata", None)
    task_sha256 = _sha256(revision)
    initiative_id = task.get("initiative")
    if (
        not isinstance(initiative_id, str)
        or TASK_ID_RE.fullmatch(initiative_id) is None
    ):
        raise BureauPickupError("orphan-recovery-initiative-invalid")
    initiative = _registry_json(
        root / "registry" / "initiatives" / f"{initiative_id}.json",
        label="orphan-recovery-initiative",
    )
    if initiative.get("id") != initiative_id:
        raise BureauPickupError("orphan-recovery-initiative-id-drift")
    plan = initiative.get("current_plan") or {}
    if not isinstance(plan, dict):
        raise BureauPickupError("orphan-recovery-plan-invalid")
    plan_sha256 = _sha256(plan)
    if task_sha256 != intent.get("task_sha256"):
        raise BureauPickupError(
            "orphan-recovery-task-drift",
            details={
                "expected_task_sha256": intent.get("task_sha256"),
                "observed_task_sha256": task_sha256,
            },
        )
    if plan_sha256 != intent.get("plan_sha256"):
        raise BureauPickupError(
            "orphan-recovery-plan-drift",
            details={
                "expected_plan_sha256": intent.get("plan_sha256"),
                "observed_plan_sha256": plan_sha256,
            },
        )
    task_state = task.get("state")
    if not isinstance(task_state, str) or not task_state:
        raise BureauPickupError("orphan-recovery-task-state-invalid")
    if task_state in TERMINAL_BUREAU_TASK_STATES:
        raise BureauPickupError(
            "orphan-recovery-task-terminal",
            details={"task_id": task_id, "task_state": task_state},
        )
    return {
        "task_id": task_id,
        "initiative_id": initiative_id,
        "task_sha256": task_sha256,
        "plan_sha256": plan_sha256,
        "task_state": task_state,
        "task_authority": task_authority,
    }


def _journal_run_identity(run_dir: Path, intent: dict[str, Any]) -> dict[str, Any]:
    committed = _read_bound_json(run_dir / "commit-result.json", label="commit-result")
    envelope = committed.get("envelope")
    run = committed.get("run")
    if not isinstance(envelope, dict) or not isinstance(run, dict):
        raise BureauPickupError("orphan-recovery-journal-commit-invalid")
    envelope_sha256 = _sha256(envelope)
    workspace = intent.get("workspace")
    expected = {
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "worker_id": intent["worker_id"],
        "task_sha256": intent["task_sha256"],
        "plan_sha256": intent["plan_sha256"],
        "workspace_path": workspace.get("workspace_path") if isinstance(workspace, dict) else None,
        "workspace_branch": workspace.get("workspace_branch") if isinstance(workspace, dict) else None,
    }
    mismatches = {
        key: {"expected": value, "observed": run.get(key)}
        for key, value in expected.items()
        if run.get(key) != value
    }
    if mismatches:
        raise BureauPickupError(
            "orphan-recovery-journal-run-drift", details={"mismatches": mismatches}
        )
    attempt = run.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise BureauPickupError("orphan-recovery-journal-attempt-invalid")
    return {
        **expected,
        "attempt": attempt,
        "envelope_sha256": envelope_sha256,
    }


def _validate_recoverable_orphan(
    coordination: dict[str, Any],
    intent: dict[str, Any],
    acquisition: dict[str, Any],
    journal_identity: dict[str, Any],
) -> dict[str, Any]:
    if coordination.get("status") != "coordinated":
        raise BureauPickupError(
            "orphan-recovery-coordination-unavailable",
            details={"status": coordination.get("status"), "code": coordination.get("code"),
            },
        )
    run = coordination.get("run")
    if not isinstance(run, dict):
        raise BureauPickupError("orphan-recovery-run-missing")
    expected = {
        key: journal_identity[key]
        for key in (
            "run_id",
            "task_id",
            "worker_id",
            "task_sha256",
            "plan_sha256",
            "envelope_sha256",
            "attempt",
            "workspace_path",
            "workspace_branch",
        )
    }
    mismatches = {
        key: {"expected": value, "observed": run.get(key)}
        for key, value in expected.items()
        if run.get(key) != value
    }
    if mismatches:
        raise BureauPickupError(
            "orphan-recovery-run-identity-drift", details={"mismatches": mismatches}
        )
    if run.get("state") != "orphaned" or run.get("error") != ORPHAN_RESUME_ERROR:
        raise BureauPickupError(
            "orphan-recovery-run-not-eligible",
            details={"state": run.get("state"), "error": run.get("error")},
        )
    if any(
        run.get(field) is not None
        for field in (
            "external_system",
            "external_id",
            "external_state",
            "external_observed_at",
        )
    ):
        raise BureauPickupError("orphan-recovery-external-binding-present")
    reservations = run.get("reservations")
    if reservations not in (None, []):
        raise BureauPickupError("orphan-recovery-reservations-present")
    if coordination.get("claim_intent_sha256") != intent["intent_sha256"]:
        raise BureauPickupError("orphan-recovery-intent-drift")
    release = coordination.get("release")
    if not isinstance(release, dict):
        raise BureauPickupError("orphan-recovery-release-binding-missing")
    expected_release = {
        "owner_id": intent["lease_owner_id"],
        "resource_keys": intent["required_resource_keys"],
        "claim_intent_sha256": intent["intent_sha256"],
    }
    if any(release.get(key) != value for key, value in expected_release.items()):
        raise BureauPickupError("orphan-recovery-release-binding-drift")
    if (
        acquisition.get("run_id") != intent["run_id"]
        or acquisition.get("task_id") != intent["task_id"]
    ):
        raise BureauPickupError("orphan-recovery-acquisition-run-drift")
    if (
        acquisition.get("owner_id") != intent["lease_owner_id"]
        or acquisition.get("claim_intent_sha256") != intent["intent_sha256"]
    ):
        raise BureauPickupError("orphan-recovery-acquisition-owner-drift")
    return run


def _journaled_orphan_recovery_candidate(
    request: dict[str, Any], current_binding: RegistryBinding
) -> dict[str, Any] | None:
    if current_binding["explicit"]:
        return None
    candidates: list[dict[str, Any]] = []
    requested_identity = _request_without_registry_root(request)
    for run_id in _journal_run_ids():
        run_dir = _absolute_path(STATE_ROOT) / "runs" / run_id
        try:
            stored_payload = _read_bound_json(run_dir / "request.json", label="request")
        except BureauPickupError as exc:
            if exc.code.startswith("request-"):
                continue
            raise
        stored_payload = dict(stored_payload)
        marker = _normalize_registry_binding_marker(
            stored_payload.pop("registry_binding_sha256", None)
        )
        if "coordination_root" not in stored_payload:
            if Path(request["coordination_root"]) != _legacy_coordination_root():
                continue
            stored_payload["coordination_root"] = request["coordination_root"]
        try:
            stored_request = _normalize_request(
                stored_payload, allow_internal_bindings=True
            )
        except ValueError:
            continue
        if _request_without_registry_root(stored_request) != requested_identity:
            continue
        intent = _read_bound_json(run_dir / "intent.json", label="intent")
        synthetic = {
            "status": "existing-assignment",
            "run": {"run_id": run_id, "state": "orphaned"},
            "envelope": {"claim_intent": intent},
        }
        validated_intent, _ = _validate_intent_result(synthetic, stored_request)
        if validated_intent["run_id"] != run_id:
            raise BureauPickupError("orphan-recovery-journal-run-mismatch")
        try:
            acquisition = _read_bound_json(
                run_dir / "acquisition.json", label="acquisition"
            )
            journal_identity = _journal_run_identity(run_dir, validated_intent)
        except BureauPickupError as exc:
            if exc.code in {
                "acquisition-missing",
                "commit-result-missing",
            }:
                continue
            raise
        _validate_acquisition(acquisition)
        coordination = _bound_bureau_call(
            current_binding,
            lambda: _coordination_status(
                run_id,
                registry_root=request["registry_root"],
                coordination_root=request["coordination_root"],
            ),
        )
        run = coordination.get("run") if isinstance(coordination, dict) else None
        state = run.get("state") if isinstance(run, dict) else None
        already_resumed = state in ACTIVE_EXECUTION_STATES
        if not already_resumed and state != "orphaned":
            continue
        stored_binding = _read_journal_registry_binding(
            run_dir,
            stored_request["registry_root"],
            expected_sha256=marker,
        )
        if stored_binding["identity"].get("kind") != "canonical-registry-binding":
            raise BureauPickupError(
                "orphan-recovery-requires-canonical-registry",
                details={"run_id": run_id},
            )
        if already_resumed:
            _validate_resumed_run(
                coordination, validated_intent, acquisition, journal_identity
            )
        elif state == "orphaned":
            _validate_recoverable_orphan(
                coordination, validated_intent, acquisition, journal_identity
            )
        else:
            continue
        candidates.append(
            {
                "run_dir": run_dir,
                "stored_request": stored_request,
                "stored_binding": stored_binding,
                "intent": validated_intent,
                "acquisition": acquisition,
                "journal_identity": journal_identity,
                "coordination": coordination,
                "already_resumed": already_resumed,
            }
        )
    if not candidates:
        return None
    if len(candidates) != 1:
        raise BureauPickupError(
            "orphan-recovery-journal-ambiguous",
            details={
                "task_id": request["task_id"],
                "worker_id": request["worker_id"],
                "candidate_run_ids": [item["intent"]["run_id"] for item in candidates],
            },
        )
    return candidates[0]


def _validated_registry_recovery_receipt(
    value: dict[str, Any],
    *,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    digest = value.get("receipt_sha256")
    payload = dict(value)
    payload.pop("receipt_sha256", None)
    if (
        not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        or _sha256(payload) != digest
    ):
        raise BureauPickupError("orphan-recovery-registry-receipt-digest-drift")
    intent = candidate["intent"]
    journal_identity = candidate["journal_identity"]
    expected = {
        "schema_version": SCHEMA_VERSION,
        "kind": REGISTRY_BINDING_RECOVERY_KIND,
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "worker_id": intent["worker_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "task_sha256": intent["task_sha256"],
        "plan_sha256": intent["plan_sha256"],
        "envelope_sha256": journal_identity["envelope_sha256"],
        "stored_registry_binding_sha256": candidate["stored_binding"]["identity"][
            "binding_sha256"
        ],
    }
    drift = {
        field: {"expected": expected_value, "observed": value.get(field)}
        for field, expected_value in expected.items()
        if value.get(field) != expected_value
    }
    if drift:
        raise BureauPickupError(
            "orphan-recovery-registry-receipt-identity-drift",
            details={"drift": drift},
        )
    ancestry = value.get("ancestry")
    current_binding_sha256 = value.get("current_registry_binding_sha256")
    current_source_commit = (
        ancestry.get("current_source_commit") if isinstance(ancestry, dict) else None
    )
    if (
        not isinstance(current_binding_sha256, str)
        or SHA256_RE.fullmatch(current_binding_sha256) is None
        or not isinstance(current_source_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", current_source_commit) is None
    ):
        raise BureauPickupError("orphan-recovery-registry-receipt-lineage-invalid")
    predecessor = value.get("predecessor_receipt_sha256")
    if predecessor is not None and (
        not isinstance(predecessor, str) or SHA256_RE.fullmatch(predecessor) is None
    ):
        raise BureauPickupError("orphan-recovery-registry-receipt-lineage-invalid")
    return value


def _registry_recovery_receipt_chain(
    candidate: dict[str, Any],
) -> list[dict[str, Any]]:
    run_dir = candidate["run_dir"]
    try:
        names = sorted(os.listdir(run_dir))
    except OSError as exc:
        raise BureauPickupError(
            "orphan-recovery-registry-receipt-read-failed",
            details=_runtime_error_details(exc),
        ) from exc
    matching = [
        name
        for name in names
        if name == "registry-binding-recovery.json"
        or re.fullmatch(r"registry-binding-recovery-[0-9a-f]{16}\.json", name)
    ]
    if not matching:
        return []
    if len(matching) > 64:
        raise BureauPickupError(
            "orphan-recovery-registry-receipt-chain-too-large",
            details={"count": len(matching), "limit": 64},
        )
    by_digest: dict[str, dict[str, Any]] = {}
    for name in matching:
        receipt = _validated_registry_recovery_receipt(
            _read_bound_json(run_dir / name, label="registry-binding-recovery"),
            candidate=candidate,
        )
        digest = receipt["receipt_sha256"]
        if digest in by_digest and by_digest[digest] != receipt:
            raise BureauPickupError("orphan-recovery-registry-receipt-digest-collision")
        by_digest[digest] = receipt
    roots = [
        receipt
        for receipt in by_digest.values()
        if receipt.get("predecessor_receipt_sha256") is None
    ]
    if len(roots) != 1:
        raise BureauPickupError(
            "orphan-recovery-registry-receipt-lineage-drift",
            details={"root_count": len(roots)},
        )
    ordered = [roots[0]]
    seen = {roots[0]["receipt_sha256"]}
    while len(seen) < len(by_digest):
        children = [
            receipt
            for receipt in by_digest.values()
            if receipt.get("predecessor_receipt_sha256") == ordered[-1]["receipt_sha256"]
            and receipt["receipt_sha256"] not in seen
        ]
        if len(children) != 1:
            raise BureauPickupError(
                "orphan-recovery-registry-receipt-lineage-drift",
                details={"child_count": len(children)},
            )
        ordered.append(children[0])
        seen.add(children[0]["receipt_sha256"])
    return ordered


def _ensure_registry_binding_recovery_receipt(
    candidate: dict[str, Any],
    current_binding: RegistryBinding,
    ancestry: dict[str, Any],
    revision: dict[str, Any],
) -> dict[str, Any]:
    intent = candidate["intent"]
    journal_identity = candidate["journal_identity"]
    chain = _registry_recovery_receipt_chain(candidate)
    current_binding_sha256 = current_binding["identity"]["binding_sha256"]
    if (
        chain
        and chain[-1].get("current_registry_binding_sha256") == current_binding_sha256
    ):
        return chain[-1]
    if any(
        existing.get("current_registry_binding_sha256") == current_binding_sha256
        for existing in chain[:-1]
    ):
        raise BureauPickupError(
            "orphan-recovery-registry-receipt-lineage-drift",
            details={"reason": "registry-binding-rollback"},
        )

    predecessor = chain[-1] if chain else None
    if predecessor is not None:
        prior_source = predecessor["ancestry"]["current_source_commit"]
        current_source = ancestry["current_source_commit"]
        if prior_source != current_source:
            lines = bureau._git_identity_lines(
                bureau_leases.BUREAU_REPOSITORY_ROOT,
                "merge-base",
                "--is-ancestor",
                prior_source,
                current_source,
            )
            if lines is None:
                raise BureauPickupError(
                    "orphan-recovery-registry-receipt-lineage-drift",
                    details={
                        "prior_source_commit": prior_source,
                        "current_source_commit": current_source,
                    },
                )

    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": REGISTRY_BINDING_RECOVERY_KIND,
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "worker_id": intent["worker_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "task_sha256": intent["task_sha256"],
        "plan_sha256": intent["plan_sha256"],
        "envelope_sha256": journal_identity["envelope_sha256"],
        "stored_registry_binding_sha256": candidate["stored_binding"]["identity"][
            "binding_sha256"
        ],
        "current_registry_binding_sha256": current_binding_sha256,
        "predecessor_receipt_sha256": (
            predecessor["receipt_sha256"] if predecessor is not None else None
        ),
        "ancestry": ancestry,
        "current_revision": revision,
        "history_preserved": [
            "registry-binding.json",
            "request.json",
            "intent.json",
            "acquisition.json",
        ],
    }
    receipt["receipt_sha256"] = _sha256(receipt)
    path = (
        candidate["run_dir"] / "registry-binding-recovery.json"
        if predecessor is None
        else candidate["run_dir"]
        / f"registry-binding-recovery-{current_binding_sha256[:16]}.json"
    )
    if os.path.lexists(path):
        existing = _validated_registry_recovery_receipt(
            _read_bound_json(path, label="registry-binding-recovery"),
            candidate=candidate,
        )
        if existing != receipt:
            raise BureauPickupError("orphan-recovery-registry-receipt-drift")
        return existing
    _write_bound_json(path, receipt)
    return receipt


def _current_lease_metadata_identity(
    resource_key: str, expected_metadata: dict[str, Any]
) -> dict[str, Any]:
    key = resources.normalize_resource_key(resource_key)
    try:
        with resources._resource_readonly_sqlite(resources.RESOURCE_DB) as connection:
            resources._validate_resource_schema_current(connection)
            row = connection.execute(
                "SELECT metadata_sha256, metadata_json FROM leases WHERE resource_key=?",
                (key,),
            ).fetchone()
    except Exception as exc:
        raise BureauPickupError(
            "orphan-recovery-lease-metadata-read-failed",
            details={"resource_key": key, "error_type": type(exc).__name__},
        ) from exc
    if row is None:
        raise BureauPickupError(
            "orphan-recovery-lease-readback-missing", details={"resource_key": key}
        )
    try:
        observed = json.loads(row["metadata_json"])
    except (json.JSONDecodeError, TypeError) as exc:
        raise BureauPickupError(
            "orphan-recovery-lease-metadata-invalid", details={"resource_key": key}
        ) from exc
    if not isinstance(observed, dict):
        raise BureauPickupError(
            "orphan-recovery-lease-metadata-invalid", details={"resource_key": key}
        )
    _, observed_sha256 = resources._metadata(observed)
    if observed_sha256 != row["metadata_sha256"]:
        raise BureauPickupError(
            "orphan-recovery-lease-metadata-integrity-drift",
            details={"resource_key": key},
        )
    sanitized = bureau_leases.sanitize_bureau_metadata([key], dict(expected_metadata))
    expected = {} if sanitized is None else sanitized
    observed_identity = resources._lease_identity_metadata(
        observed, preserve_task_attempt=False
    )
    expected_identity = resources._lease_identity_metadata(
        expected, preserve_task_attempt=False
    )
    if observed_identity != expected_identity:
        raise BureauPickupError(
            "orphan-recovery-lease-metadata-identity-drift",
            details={"resource_key": key},
        )
    return observed_identity


def _orphan_recovery_original_leases(
    intent: dict[str, Any], acquisition: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    by_key = {
        item["resource_key"]: item
        for item in acquisition.get("leases", [])
        if isinstance(item, dict) and isinstance(item.get("resource_key"), str)
    }
    if sorted(by_key) != intent["required_resource_keys"]:
        raise BureauPickupError("orphan-recovery-lease-journal-incomplete")
    return by_key


def _reacquire_orphaned_assignment_leases(
    intent: dict[str, Any],
    request: dict[str, Any],
    acquisition: dict[str, Any],
    run_dir: Path,
) -> dict[str, Any]:
    original_by_key = _orphan_recovery_original_leases(intent, acquisition)
    groups = _acquisition_groups(intent, request)
    expected_metadata_by_key = {
        key: group["metadata"]
        for group in groups
        for key in group["resource_keys"]
    }
    now = resources._now()
    plans: list[dict[str, Any]] = []
    for group in groups:
        keys = list(group["resource_keys"])
        purpose = f"Bureau coordinated pickup {intent['run_id']} group {group['name']}"
        for key in keys:
            original = original_by_key[key]
            if original.get("purpose") != purpose:
                raise BureauPickupError(
                    "orphan-recovery-lease-purpose-drift",
                    details={"resource_key": key, "group": group["name"]},
                )
        live: list[dict[str, Any]] = []
        expired: list[dict[str, Any]] = []
        for key in keys:
            observed = resources.inspect_resource(key)
            if observed is not None:
                if observed.get("owner_id") != intent["lease_owner_id"]:
                    raise BureauPickupError(
                        "orphan-recovery-lease-foreign-owner",
                        details={"resource_key": key, "owner_id": observed.get("owner_id"),
                        },
                    )
                if observed.get("purpose") != purpose:
                    raise BureauPickupError(
                        "orphan-recovery-live-lease-binding-drift",
                        details={"resource_key": key},
                    )
                if observed.get("metadata_sha256") != original_by_key[key].get(
                    "metadata_sha256"
                ):
                    _current_lease_metadata_identity(key, group["metadata"])
                live.append(observed)
                continue
            persisted = _persisted_resource_lease(key)
            if persisted is None:
                raise BureauPickupError(
                    "orphan-recovery-expired-lease-history-missing",
                    details={"resource_key": key},
                )
            if persisted.get("owner_id") != intent["lease_owner_id"]:
                raise BureauPickupError(
                    "orphan-recovery-lease-foreign-owner",
                    details={"resource_key": key, "owner_id": persisted.get("owner_id"),
                    },
                )
            if persisted.get("purpose") != purpose or persisted.get(
                "metadata_sha256"
            ) != original_by_key[key].get("metadata_sha256"):
                raise BureauPickupError(
                    "orphan-recovery-lease-history-drift",
                    details={"resource_key": key},
                )
            if persisted["expires_at_unix"] > now:
                raise BureauPickupError(
                    "orphan-recovery-lease-readback-drift",
                    details={"resource_key": key},
                )
            expired.append(persisted)
        short = [
            item for item in live if item.get("expires_at_unix", 0) < now + 60
        ]
        if short:
            raise BureauPickupError(
                "orphan-recovery-live-lease-too-short",
                details={
                    "group": group["name"],
                    "resource_keys": [item["resource_key"] for item in short],
                },
            )
        plans.append(
            {
                "group": group,
                "purpose": purpose,
                "expired": expired,
            }
        )

    # Do not mutate an early group until every group has passed lineage and
    # ownership validation. Recovery installs internal guards here; normalized
    # external requests cannot supply these callable values.
    pre_effect_guard = request.get("_orphan_recovery_pre_effect_guard")
    if pre_effect_guard is not None:
        if not callable(pre_effect_guard):
            raise BureauPickupError("orphan-recovery-run-guard-invalid")
        pre_effect_guard()

    actions: list[dict[str, Any]] = []
    rebound_after_snapshots: list[dict[str, Any]] = []

    def _raise_compensated_lease_effect_failure(exc: Exception) -> None:
        compensation: dict[str, Any] = {
            "required": True,
            "status": "pending",
            "resource_keys": [
                item["resource_key"] for item in rebound_after_snapshots
            ],
            "cause_code": getattr(exc, "code", None),
            "error_type": type(exc).__name__,
        }
        try:
            released = resources.release_resources(
                intent["lease_owner_id"],
                [item["resource_key"] for item in rebound_after_snapshots],
                expected_leases=rebound_after_snapshots,
            )
            compensation.update({"status": "released", "result": released})
        except Exception as release_exc:
            compensation.update(
                {
                    "status": "release-failed",
                    "release_error_type": type(release_exc).__name__,
                }
            )
        compensation["receipt_sha256"] = _sha256(compensation)
        _write_bound_json(
            run_dir / "orphan-lease-recovery-compensation.json", compensation
        )
        raise BureauPickupError(
            "orphan-recovery-lease-effect-failed",
            details={
                "cause_code": getattr(exc, "code", None),
                "error_type": type(exc).__name__,
                "effect_count": len(actions),
                "compensation": compensation,
            },
        ) from exc

    try:
        for index, plan in enumerate(plans, start=1):
            group = plan["group"]
            purpose = plan["purpose"]
            expired = plan["expired"]
            if not expired:
                continue
            expired_keys = [item["resource_key"] for item in expired]
            result = resources.rebind_same_owner_resources(
                intent["lease_owner_id"],
                expired_keys,
                purpose=purpose,
                ttl_seconds=group["ttl_seconds"],
                metadata=group["metadata"],
                expected_current_leases=[_lease_snapshot(item) for item in expired],
                expected_original_leases=[
                    _lease_snapshot(original_by_key[key]) for key in expired_keys
                ],
            )
            result_leases = result.get("leases")
            if not isinstance(result_leases, list):
                raise BureauPickupError(
                    "orphan-recovery-lease-rebind-result-invalid",
                    details={"group": group["name"]},
                )
            after = [
                _lease_snapshot(item)
                for item in result_leases
                if isinstance(item, dict)
                and item.get("resource_key") in expired_keys
            ]
            if sorted(item["resource_key"] for item in after) != sorted(expired_keys):
                raise BureauPickupError(
                    "orphan-recovery-lease-rebind-result-invalid",
                    details={"group": group["name"]},
                )
            rebound_after_snapshots.extend(after)
            rebound_group = {**group, "resource_keys": expired_keys}
            _validate_acquired_group(
                intent["lease_owner_id"], rebound_group, result
            )
            effect = {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_orphan_lease_effect",
                "run_id": intent["run_id"],
                "task_id": intent["task_id"],
                "owner_id": intent["lease_owner_id"],
                "claim_intent_sha256": intent["intent_sha256"],
                "group": group["name"],
                "method": "same-owner-rebind",
                "resource_keys": expired_keys,
                "before": [_lease_snapshot(item) for item in expired],
                "after": after,
            }
            effect["receipt_sha256"] = _sha256(effect)
            _write_bound_json(
                run_dir / f"orphan-lease-effect-{index:02d}.json", effect
            )
            actions.append(
                {
                    "group": group["name"],
                    "method": "same-owner-rebind",
                    "resource_keys": expired_keys,
                    "effect_receipt_sha256": effect["receipt_sha256"],
                }
            )

        post_effect_guard = request.get("_orphan_recovery_post_effect_guard")
        if post_effect_guard is not None:
            if not callable(post_effect_guard):
                raise BureauPickupError("orphan-recovery-post-effect-guard-invalid")
            post_effect_guard()
    except Exception as exc:
        if not rebound_after_snapshots:
            raise
        _raise_compensated_lease_effect_failure(exc)

    current_leases: list[dict[str, Any]] = []
    try:
        for key in intent["required_resource_keys"]:
            observed = resources.inspect_resource(key)
            original = original_by_key[key]
            if observed is None:
                raise BureauPickupError(
                    "orphan-recovery-lease-readback-missing",
                    details={"resource_key": key},
                )
            if observed.get("owner_id") != intent["lease_owner_id"]:
                raise BureauPickupError(
                    "orphan-recovery-lease-foreign-owner",
                    details={
                        "resource_key": key,
                        "owner_id": observed.get("owner_id"),
                    },
                )
            if observed.get("metadata_sha256") != original.get("metadata_sha256"):
                _current_lease_metadata_identity(key, expected_metadata_by_key[key])
            if observed.get("expires_at_unix", 0) < resources._now() + 60:
                raise BureauPickupError(
                    "orphan-recovery-lease-too-short", details={"resource_key": key}
                )
            current_leases.append(_lease_snapshot(observed))
    except Exception as exc:
        if not rebound_after_snapshots:
            raise
        _raise_compensated_lease_effect_failure(exc)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_orphan_lease_recovery",
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "owner_id": intent["lease_owner_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "resource_keys": intent["required_resource_keys"],
        "actions": actions,
        "lease_identities": [
            {
                "resource_key": item["resource_key"],
                "owner_id": item["owner_id"],
                "metadata_sha256": item["metadata_sha256"],
            }
            for item in current_leases
        ],
    }
    receipt["receipt_sha256"] = _sha256(receipt)
    path = run_dir / "orphan-lease-recovery.json"
    if os.path.lexists(path):
        existing = _read_bound_json(path, label="orphan-lease-recovery")
        existing_digest = existing.get("receipt_sha256")
        existing_payload = dict(existing)
        existing_payload.pop("receipt_sha256", None)
        if (
            not isinstance(existing_digest, str)
            or SHA256_RE.fullmatch(existing_digest) is None
            or _sha256(existing_payload) != existing_digest
        ):
            raise BureauPickupError("orphan-recovery-lease-receipt-digest-drift")
        stable_fields = (
            "schema_version",
            "kind",
            "run_id",
            "task_id",
            "owner_id",
            "claim_intent_sha256",
            "resource_keys",
        )
        if any(existing.get(field) != receipt.get(field) for field in stable_fields):
            raise BureauPickupError("orphan-recovery-lease-receipt-drift")
        return existing
    _write_bound_json(path, receipt)
    return receipt


def _resume_orphaned_run(
    request: dict[str, Any],
    intent: dict[str, Any],
    run: dict[str, Any],
    envelope_sha256: str,
    *,
    revision_proof: dict[str, Any],
) -> dict[str, Any]:
    arguments = _bureau_arguments(
        "orphan-resume",
        registry_root=request["registry_root"],
        coordination_root=request["coordination_root"],
    )
    arguments.extend(
        [
            intent["run_id"],
            "--worker",
            intent["worker_id"],
            "--expected-updated-at",
            str(run["updated_at"]),
            "--expected-task-sha256",
            revision_proof["task_sha256"],
            "--expected-plan-sha256",
            revision_proof["plan_sha256"],
            "--expected-envelope-sha256",
            envelope_sha256,
        ]
    )
    return bureau._invoke_bureau(
        arguments,
        mutation=True,
        required_readback=[
            f"bureau_run:{intent['run_id']}",
            f"grabowski_leases:{intent['lease_owner_id']}",
        ],
    )


def _validate_resumed_run(
    coordination: dict[str, Any],
    intent: dict[str, Any],
    acquisition: dict[str, Any],
    journal_identity: dict[str, Any],
) -> dict[str, Any]:
    run = _validate_claim_readback(coordination, intent, acquisition)
    expected = {
        key: journal_identity[key]
        for key in (
            "run_id",
            "task_id",
            "worker_id",
            "task_sha256",
            "plan_sha256",
            "envelope_sha256",
            "attempt",
            "workspace_path",
            "workspace_branch",
        )
    }
    mismatches = {
        key: {"expected": value, "observed": run.get(key)}
        for key, value in expected.items()
        if run.get(key) != value
    }
    if mismatches:
        raise BureauPickupError(
            "orphan-recovery-resumed-run-drift", details={"mismatches": mismatches}
        )
    if run.get("state") not in ACTIVE_EXECUTION_STATES or run.get("error") is not None:
        raise BureauPickupError(
            "orphan-recovery-resume-readback-not-active",
            details={"state": run.get("state"), "error": run.get("error")},
        )
    _require_active_execution_binding(
        coordination, action="orphan-recovery-resume-readback"
    )
    return run


def _recover_orphaned_journal_before_claim(
    request: dict[str, Any],
    current_binding: RegistryBinding,
    request_sha256: str,
) -> dict[str, Any] | None:
    candidate = _journaled_orphan_recovery_candidate(request, current_binding)
    if candidate is None:
        return None
    closeout_latch = _bound_bureau_call(
        current_binding, lambda: _machine_completion_closeout_latch(request)
    )
    if closeout_latch is not None:
        return _closeout_latched_response(
            request, current_binding, request_sha256, closeout_latch
        )
    intent = candidate["intent"]
    acquisition = candidate["acquisition"]
    journal_identity = candidate["journal_identity"]
    ancestry = _registry_successor_proof(candidate["stored_binding"], current_binding)
    revision = _current_registry_revision_proof(
        current_binding,
        intent,
        coordination_root=request["coordination_root"],
    )
    binding_receipt = _ensure_registry_binding_recovery_receipt(
        candidate, current_binding, ancestry, revision
    )
    _assert_registry_binding(current_binding)
    already_resumed = candidate.get("already_resumed") is True
    pre_resume: dict[str, Any] | None = None
    run: dict[str, Any] | None = None

    post_lease_readback: dict[str, Any] | None = None
    post_lease_run: dict[str, Any] | None = None
    post_lease_revision: dict[str, Any] | None = None

    def _guard_recovery_authority(*, post_effect: bool) -> None:
        nonlocal pre_resume, run, post_lease_readback
        nonlocal post_lease_run, post_lease_revision
        _assert_registry_binding(current_binding)
        current_revision = _current_registry_revision_proof(
            current_binding,
            intent,
            coordination_root=request["coordination_root"],
        )
        observed = _bound_bureau_call(
            current_binding,
            lambda: _coordination_status(
                intent["run_id"],
                registry_root=request["registry_root"],
                coordination_root=request["coordination_root"],
            ),
        )
        if already_resumed:
            validated = _validate_resumed_run(
                observed, intent, acquisition, journal_identity
            )
        else:
            validated = _validate_recoverable_orphan(
                observed, intent, acquisition, journal_identity
            )
        if post_effect:
            post_lease_readback = observed
            post_lease_run = validated
            post_lease_revision = current_revision
        else:
            pre_resume = observed
            run = validated

    lease_request = dict(candidate["stored_request"])
    lease_request["_orphan_recovery_pre_effect_guard"] = lambda: (
        _guard_recovery_authority(post_effect=False)
    )
    lease_request["_orphan_recovery_post_effect_guard"] = lambda: (
        _guard_recovery_authority(post_effect=True)
    )
    lease_receipt = _reacquire_orphaned_assignment_leases(
        intent, lease_request, acquisition, candidate["run_dir"]
    )
    if (
        pre_resume is None
        or run is None
        or post_lease_readback is None
        or post_lease_run is None
        or post_lease_revision is None
    ):
        raise BureauPickupError("orphan-recovery-run-guard-missing")
    resume_result: dict[str, Any] | None = None
    resume_error: Exception | None = None
    if already_resumed:
        readback = post_lease_readback
        _validate_resumed_run(readback, intent, acquisition, journal_identity)
        resume_result = {"status": "already-active", "run": readback.get("run")}
    else:
        try:
            resume_result = _bound_bureau_call(
                current_binding,
                lambda: _resume_orphaned_run(
                    request,
                    intent,
                    post_lease_run,
                    journal_identity["envelope_sha256"],
                    revision_proof=post_lease_revision,
                ),
            )
        except Exception as exc:
            resume_error = exc
        try:
            readback = _bound_bureau_call(
                current_binding,
                lambda: _coordination_status(
                    intent["run_id"],
                    registry_root=request["registry_root"],
                    coordination_root=request["coordination_root"],
                ),
            )
        except Exception as exc:
            raise BureauPickupError(
                "orphan-recovery-resume-outcome-unknown",
                details={
                    "resume_error_type": type(resume_error).__name__ if resume_error else None,
                    "readback_error_type": type(exc).__name__,
                    "lease_retained": bool(intent["required_resource_keys"]),
                },
            ) from exc
    observed_run = readback.get("run") if isinstance(readback, dict) else None
    if (
        isinstance(observed_run, dict)
        and observed_run.get("state") in ACTIVE_EXECUTION_STATES
    ):
        _validate_resumed_run(readback, intent, acquisition, journal_identity)
    else:
        raise BureauPickupError(
            "orphan-recovery-resume-failed",
            details={
                "resume_error_type": type(resume_error).__name__ if resume_error else None,
                "resume_status": resume_result.get("status") if isinstance(resume_result, dict) else None,
                "readback_sha256": _sha256(readback),
                "observed_state": observed_run.get("state") if isinstance(observed_run, dict) else None,
                "lease_retained": bool(intent["required_resource_keys"]),
                "duplicate_run_created": False,
            },
        )
    success = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_orphan_recovery",
        "status": "resumed-existing-assignment",
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "worker_id": intent["worker_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "registry_binding_recovery_receipt_sha256": binding_receipt["receipt_sha256"],
        "lease_recovery_receipt_sha256": lease_receipt["receipt_sha256"],
        "run_readback_sha256": _sha256(readback),
        "response_loss_recovered": resume_error is not None,
        "resume_effect_skipped_already_active": already_resumed,
    }
    success["receipt_sha256"] = _sha256(success)
    success_path = candidate["run_dir"] / "orphan-recovery.json"
    if os.path.lexists(success_path):
        persisted_success = _read_bound_json(
            success_path, label="orphan-recovery"
        )
        persisted_digest = persisted_success.get("receipt_sha256")
        persisted_payload = dict(persisted_success)
        persisted_payload.pop("receipt_sha256", None)
        stable_success = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_orphan_recovery",
            "run_id": intent["run_id"],
            "task_id": intent["task_id"],
            "worker_id": intent["worker_id"],
            "claim_intent_sha256": intent["intent_sha256"],
        }
        if (
            not isinstance(persisted_digest, str)
            or SHA256_RE.fullmatch(persisted_digest) is None
            or _sha256(persisted_payload) != persisted_digest
            or any(
                persisted_success.get(field) != value
                for field, value in stable_success.items()
            )
        ):
            raise BureauPickupError("orphan-recovery-receipt-drift")
        success = persisted_success
    else:
        _write_bound_json(success_path, success)
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup",
        "status": "resumed-existing-assignment",
        "request_sha256": request_sha256,
        "registry_binding_sha256": current_binding["identity"]["binding_sha256"],
        "registry_binding_kind": current_binding["identity"]["kind"],
        "registry_binding_source": "journal-successor-recovery",
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "lease_owner_id": intent["lease_owner_id"],
        "resource_keys": intent["required_resource_keys"],
        "claim_intent_sha256": intent["intent_sha256"],
        "acquisition_sha256": acquisition["acquisition_sha256"],
        "commit": resume_result,
        "recovery": readback,
        "run_readback_sha256": _sha256(readback),
        "orphan_recovery_receipt_sha256": success["receipt_sha256"],
        "journal": str(candidate["run_dir"]),
        "does_not_establish": [
            "task completion",
            "automatic lease release",
            "ownership of an unjournaled assignment",
        ],
    }
    bureau._audit(
        "bureau-pickup-orphan-resume",
        result,
        run_id=intent["run_id"],
        task_id=intent["task_id"],
    )
    return result


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None

def _parse_utc_timestamp(value: Any) -> tuple[datetime | None, str | None]:
    if not isinstance(value, str) or not value.strip():
        return None, "heartbeat_missing"
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None, "heartbeat_malformed"
    if parsed.tzinfo is None:
        return None, "heartbeat_timezone_missing"
    return parsed.astimezone(timezone.utc), None

def _external_binding_projection(run: dict[str, Any]) -> dict[str, Any]:
    values = {
        field: _optional_text(run.get(field)) for field in EXTERNAL_BINDING_FIELDS
    }
    present_fields = [field for field, item in values.items() if item is not None]
    missing_fields = [field for field, item in values.items() if item is None]
    present = bool(present_fields)
    complete = present and not missing_fields
    return {
        "present": present,
        "complete": complete,
        "external_system": values["external_system"],
        "external_id": values["external_id"],
        "external_state": values["external_state"],
        "present_fields": present_fields,
        "missing_fields": missing_fields if present else [],
    }

def _execution_binding_does_not_establish() -> list[str]:
    return [
        "process liveness beyond reported heartbeat evidence",
        "permission to release foreign leases",
        "workspace cleanup authority",
        "task verification",
        "automatic global reconcile authority",
    ]

def _classify_execution_binding(
    run: Any, *, now: datetime | None = None
) -> dict[str, Any]:
    """Classify whether a coordinated Bureau run has fresh execution evidence."""
    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    else:
        observed_at = observed_at.astimezone(timezone.utc)

    reason_codes: list[str] = []
    missing_bindings: list[str] = []
    # Demote from a candidate; only intact fresh evidence remains actively_bound.
    classification = "actively_bound"
    heartbeat_at: str | None = None
    heartbeat_age_seconds: int | None = None
    heartbeat_parse_error: str | None = None
    worker_id: str | None = None
    state: str | None = None
    run_id: str | None = None
    external = {
        "present": False,
        "complete": False,
        "external_system": None,
        "external_id": None,
        "external_state": None,
        "present_fields": [],
        "missing_fields": [],
    }

    def demote(next_classification: str) -> None:
        nonlocal classification
        rank = {
            "actively_bound": 0,
            "unbound": 1,
            "stale": 2,
            "attention_required": 3,
        }
        if rank[next_classification] > rank[classification]:
            classification = next_classification

    if not isinstance(run, dict):
        reason_codes.append("run_missing")
        missing_bindings.append("run")
        demote("attention_required")
    else:
        run_id = _optional_text(run.get("run_id"))
        state = _optional_text(run.get("state"))
        worker_id = _optional_text(run.get("worker_id"))
        external = _external_binding_projection(run)
        if run_id is None:
            reason_codes.append("run_id_missing")
            missing_bindings.append("run_id")
            demote("attention_required")
        if state is None:
            reason_codes.append("state_missing")
            missing_bindings.append("state")
            demote("attention_required")
        elif state in TERMINAL_EXECUTION_STATES:
            reason_codes.append("state_not_active")
            demote("unbound")
        elif state not in ACTIVE_EXECUTION_STATES:
            reason_codes.append("state_unknown")
            demote("attention_required")
        if worker_id is None:
            reason_codes.append("worker_id_missing")
            missing_bindings.append("worker_id")
            demote("unbound")
        raw_heartbeat = run.get("heartbeat_at")
        if raw_heartbeat is None or (
            isinstance(raw_heartbeat, str) and not raw_heartbeat.strip()
        ):
            heartbeat_parse_error = "heartbeat_missing"
            reason_codes.append("heartbeat_missing")
            missing_bindings.append("heartbeat_at")
            demote("unbound")
        elif not isinstance(raw_heartbeat, str):
            heartbeat_parse_error = "heartbeat_malformed"
            reason_codes.append("heartbeat_malformed")
            demote("attention_required")
        else:
            heartbeat_at = raw_heartbeat.strip()
            parsed, parse_error = _parse_utc_timestamp(heartbeat_at)
            if parse_error is not None:
                heartbeat_parse_error = parse_error
                reason_codes.append(parse_error)
                demote("attention_required")
            else:
                assert parsed is not None
                age = (observed_at - parsed).total_seconds()
                if age < 0:
                    heartbeat_age_seconds = int(age)
                    reason_codes.append("heartbeat_future")
                    demote("attention_required")
                else:
                    heartbeat_age_seconds = int(age)
                    if age > EXECUTION_HEARTBEAT_MAX_AGE_SECONDS:
                        reason_codes.append("heartbeat_stale")
                        demote("stale")
        if external["present"] and not external["complete"]:
            reason_codes.append("external_binding_incomplete")
            missing_bindings.extend(
                field
                for field in external["missing_fields"]
                if field not in missing_bindings
            )
            demote("attention_required")
        elif external["complete"]:
            external_state = external["external_state"]
            if external_state not in ACTIVE_EXTERNAL_STATES:
                reason_codes.append("external_state_invalid")
                demote("attention_required")
            elif state in ACTIVE_EXECUTION_STATES:
                if state == "verifying":
                    if external_state != "succeeded":
                        reason_codes.append("external_state_inconsistent")
                        demote("attention_required")
                elif external_state == "succeeded":
                    reason_codes.append("external_state_inconsistent")
                    demote("attention_required")

        if classification == "actively_bound":
            reason_codes.append("execution_actively_bound")
        elif not reason_codes:
            reason_codes.append("execution_unbound")

    # Prefer a single primary classification; keep reason codes stable/sorted unique.
    ordered_reasons: list[str] = []
    for code in reason_codes:
        if code not in ordered_reasons:
            ordered_reasons.append(code)

    actively_bound = classification == "actively_bound"
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_execution_binding",
        "classification": classification,
        "actively_bound": actively_bound,
        "run_id": run_id,
        "state": state,
        "worker_id": worker_id,
        "heartbeat_at": heartbeat_at,
        "heartbeat_age_seconds": heartbeat_age_seconds,
        "heartbeat_parse_error": heartbeat_parse_error,
        "heartbeat_max_age_seconds": EXECUTION_HEARTBEAT_MAX_AGE_SECONDS,
        "observed_at": observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "external_binding": external,
        "missing_bindings": missing_bindings,
        "reason_codes": ordered_reasons,
        "does_not_establish": _execution_binding_does_not_establish(),
    }

def _require_active_execution_binding(
    coordination: dict[str, Any], *, action: str
) -> dict[str, Any]:
    run = coordination.get("run")
    binding = _classify_execution_binding(run)
    if binding["actively_bound"]:
        return binding
    run_dict = run if isinstance(run, dict) else {}
    raise BureauPickupError(
        "existing-assignment-execution-not-bound",
        details={
            "action": action,
            "run_id": binding.get("run_id") or run_dict.get("run_id"),
            "state": binding.get("state") or run_dict.get("state"),
            "heartbeat_age_seconds": binding.get("heartbeat_age_seconds"),
            "heartbeat_parse_error": binding.get("heartbeat_parse_error"),
            "missing_bindings": binding.get("missing_bindings"),
            "reason_codes": binding.get("reason_codes"),
            "execution_binding": binding,
            "does_not_establish": binding.get("does_not_establish"),
        },
    )

def _persisted_resource_lease(resource_key: str) -> dict[str, Any] | None:
    """Read one persisted lease row without treating expiry as authority.

    Public inspect_resource deliberately hides expired rows.  Existing-assignment
    recovery still needs the expired row as provenance before restoring the same
    owner.  This helper is read-only; the later rebind performs the authoritative
    CAS inside the resource store transaction.
    """
    key = resources.normalize_resource_key(resource_key)
    try:
        with resources._resource_readonly_sqlite(
            resources.RESOURCE_DB
        ) as connection:
            if (
                resources._resource_schema_version(connection)
                != resources.RESOURCE_CURRENT_SCHEMA_VERSION
            ):
                raise RuntimeError("Resource database schema is not current")
            resources._validate_resource_schema_current(connection)
            row = connection.execute(
                "SELECT resource_key, owner_id, purpose, acquired_at_unix, "
                "updated_at_unix, expires_at_unix, metadata_sha256 "
                "FROM leases WHERE resource_key=?",
                (key,),
            ).fetchone()
    except Exception as exc:
        raise BureauPickupError(
            "existing-assignment-lease-history-read-failed",
            details={
                "resource_key": key,
                "error_type": type(exc).__name__,
            },
        ) from exc
    if row is None:
        return None
    try:
        value = dict(row)
        snapshot = _lease_snapshot(value)
        purpose = value["purpose"]
    except (KeyError, TypeError, ValueError) as exc:
        raise BureauPickupError(
            "existing-assignment-lease-history-invalid",
            details={
                "resource_key": key,
                "error_type": type(exc).__name__,
            },
        ) from exc
    if snapshot.get("resource_key") != key:
        raise BureauPickupError(
            "existing-assignment-lease-history-invalid",
            details={"resource_key": key, "reason": "resource-key-drift"},
        )
    if (
        not isinstance(snapshot.get("owner_id"), str)
        or not isinstance(purpose, str)
        or not purpose
        or any(
            type(snapshot.get(field)) is not int
            for field in (
                "acquired_at_unix",
                "updated_at_unix",
                "expires_at_unix",
            )
        )
        or not (
            snapshot["acquired_at_unix"]
            <= snapshot["updated_at_unix"]
            < snapshot["expires_at_unix"]
        )
        or not isinstance(snapshot.get("metadata_sha256"), str)
        or SHA256_RE.fullmatch(snapshot["metadata_sha256"]) is None
    ):
        raise BureauPickupError(
            "existing-assignment-lease-history-invalid",
            details={"resource_key": key},
        )
    return {**snapshot, "purpose": purpose}


def _existing_assignment_repair_external_binding(
    run: dict[str, Any],
) -> dict[str, Any]:
    fields = (
        "external_system",
        "external_id",
        "external_state",
        "external_observed_at",
    )
    snapshot = {field: run.get(field) for field in fields}
    if all(value is None for value in snapshot.values()):
        return {"external_unbound": True, **snapshot}
    if any(value is None for value in snapshot.values()):
        raise BureauPickupError(
            "existing-assignment-lease-repair-external-binding-incomplete",
            details={
                "present_fields": [
                    field for field, value in snapshot.items() if value is not None
                ],
                "missing_fields": [
                    field for field, value in snapshot.items() if value is None
                ],
            },
        )
    if any(
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        for value in snapshot.values()
    ):
        raise BureauPickupError(
            "existing-assignment-lease-repair-external-binding-invalid"
        )
    external_state = snapshot["external_state"]
    run_state = run.get("state")
    if external_state not in ACTIVE_EXTERNAL_STATES:
        raise BureauPickupError(
            "existing-assignment-lease-repair-external-state-invalid",
            details={"external_state": external_state},
        )
    if (run_state == "verifying") != (external_state == "succeeded"):
        raise BureauPickupError(
            "existing-assignment-lease-repair-external-state-inconsistent",
            details={"run_state": run_state, "external_state": external_state},
        )
    observed_at, parse_error = _parse_utc_timestamp(snapshot["external_observed_at"])
    if parse_error is not None:
        raise BureauPickupError(
            "existing-assignment-lease-repair-external-observation-invalid",
            details={"parse_error": parse_error},
        )
    assert observed_at is not None
    age = (datetime.now(timezone.utc) - observed_at).total_seconds()
    if age < 0 or age > EXECUTION_HEARTBEAT_MAX_AGE_SECONDS:
        raise BureauPickupError(
            "existing-assignment-lease-repair-external-observation-not-current",
            details={"age_seconds": int(age)},
        )
    return {"external_unbound": False, **snapshot}


def _validated_existing_assignment_repair_acquisition(
    intent: dict[str, Any], acquisition: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    _validate_acquisition(acquisition)
    expected_acquisition = {
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "owner_id": intent["lease_owner_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "resource_keys": intent["required_resource_keys"],
    }
    acquisition_mismatches = {
        key: {"expected": value, "observed": acquisition.get(key)}
        for key, value in expected_acquisition.items()
        if acquisition.get(key) != value
    }
    if acquisition_mismatches:
        raise BureauPickupError(
            "existing-assignment-lease-repair-acquisition-drift",
            details={"mismatches": acquisition_mismatches},
        )
    acquisition_leases = acquisition.get("leases")
    if not isinstance(acquisition_leases, list):
        raise BureauPickupError(
            "existing-assignment-lease-repair-acquisition-leases-invalid"
        )
    leases_by_key: dict[str, dict[str, Any]] = {}
    for lease in acquisition_leases:
        if (
            not isinstance(lease, dict)
            or not isinstance(lease.get("resource_key"), str)
            or lease.get("owner_id") != intent["lease_owner_id"]
        ):
            raise BureauPickupError(
                "existing-assignment-lease-repair-acquisition-lease-drift"
            )
        key = lease["resource_key"]
        if key in leases_by_key:
            raise BureauPickupError(
                "existing-assignment-lease-repair-acquisition-lease-set-drift"
            )
        leases_by_key[key] = lease
    if sorted(leases_by_key) != intent["required_resource_keys"]:
        raise BureauPickupError(
            "existing-assignment-lease-repair-acquisition-lease-set-drift"
        )
    return leases_by_key


def _existing_assignment_repair_authority(
    coordination: dict[str, Any],
    intent: dict[str, Any],
    acquisition: dict[str, Any],
    run_dir: Path,
    registry_binding: RegistryBinding,
    *,
    coordination_root: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if coordination.get("status") != "coordinated":
        raise BureauPickupError(
            "existing-assignment-lease-repair-not-coordinated",
            details={"status": coordination.get("status")},
        )
    run = coordination.get("run")
    if not isinstance(run, dict):
        raise BureauPickupError("existing-assignment-lease-repair-run-missing")
    if run.get("state") not in ACTIVE_EXECUTION_STATES or run.get("error") is not None:
        raise BureauPickupError(
            "existing-assignment-lease-repair-run-not-active",
            details={"state": run.get("state"), "error": run.get("error")},
        )

    journal_identity = _journal_run_identity(run_dir, intent)
    expected_run = {
        key: journal_identity[key]
        for key in (
            "run_id",
            "task_id",
            "worker_id",
            "task_sha256",
            "plan_sha256",
            "envelope_sha256",
        )
    }
    mismatches = {
        key: {"expected": value, "observed": run.get(key)}
        for key, value in expected_run.items()
        if run.get(key) != value
    }
    if mismatches:
        raise BureauPickupError(
            "existing-assignment-lease-repair-run-identity-drift",
            details={"mismatches": mismatches},
        )

    _validated_existing_assignment_repair_acquisition(intent, acquisition)
    if coordination.get("claim_intent_sha256") != intent["intent_sha256"]:
        raise BureauPickupError("existing-assignment-lease-repair-intent-drift")
    release = coordination.get("release")
    expected_release = {
        "required": bool(intent["required_resource_keys"]),
        "owner_id": intent["lease_owner_id"],
        "resource_keys": intent["required_resource_keys"],
        "claim_intent_sha256": intent["intent_sha256"],
    }
    if not isinstance(release, dict):
        raise BureauPickupError(
            "existing-assignment-lease-repair-release-binding-missing"
        )
    release_mismatches = {
        key: {"expected": value, "observed": release.get(key)}
        for key, value in expected_release.items()
        if release.get(key) != value
    }
    if release_mismatches:
        raise BureauPickupError(
            "existing-assignment-lease-repair-release-binding-drift",
            details={"mismatches": release_mismatches},
        )

    binding = _classify_execution_binding(run)
    if binding["classification"] not in {"actively_bound", "stale"}:
        raise BureauPickupError(
            "existing-assignment-execution-not-bound",
            details={
                "action": "repair-existing-assignment-lease-binding",
                "run_id": run.get("run_id"),
                "state": run.get("state"),
                "heartbeat_age_seconds": binding.get("heartbeat_age_seconds"),
                "heartbeat_parse_error": binding.get("heartbeat_parse_error"),
                "missing_bindings": binding.get("missing_bindings"),
                "reason_codes": binding.get("reason_codes"),
                "execution_binding": binding,
                "does_not_establish": binding.get("does_not_establish"),
            },
        )
    external = _existing_assignment_repair_external_binding(run)
    _bound_bureau_call(
        registry_binding,
        lambda: _current_registry_revision_proof(
            registry_binding,
            intent,
            coordination_root=coordination_root,
        ),
    )
    return journal_identity, external


def _lease_repair_receipt_sha256(receipt: dict[str, Any]) -> str:
    claimed = receipt.get("receipt_sha256")
    payload = dict(receipt)
    payload.pop("receipt_sha256", None)
    if (
        not isinstance(claimed, str)
        or SHA256_RE.fullmatch(claimed) is None
        or _sha256(payload) != claimed
    ):
        raise BureauPickupError("existing-assignment-lease-repair-receipt-invalid")
    return claimed


def _validated_lease_repair_receipt(
    run_dir: Path, filename: str, receipt: dict[str, Any]
) -> dict[str, Any]:
    _lease_repair_receipt_sha256(receipt)
    _write_bound_json(run_dir / filename, receipt)
    persisted = _read_bound_json(
        run_dir / filename, label=filename.removesuffix(".json")
    )
    if persisted != receipt:
        raise BureauPickupError("existing-assignment-lease-repair-receipt-drift")
    return persisted


def _validated_persisted_lease_repair_external_binding(
    value: Any,
) -> dict[str, Any]:
    expected_keys = {
        "external_unbound",
        "external_system",
        "external_id",
        "external_state",
        "external_observed_at",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-invalid",
            details={"reason": "external-binding-fields"},
        )
    external_unbound = value["external_unbound"]
    fields = (
        "external_system",
        "external_id",
        "external_state",
        "external_observed_at",
    )
    if type(external_unbound) is not bool:
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-invalid",
            details={"reason": "external-unbound-invalid"},
        )
    if external_unbound:
        if any(value[field] is not None for field in fields):
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-invalid",
                details={"reason": "external-unbound-conflict"},
            )
        return dict(value)
    if any(
        not isinstance(value[field], str)
        or not value[field]
        or value[field] != value[field].strip()
        or "\x00" in value[field]
        for field in fields
    ):
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-invalid",
            details={"reason": "external-binding-invalid"},
        )
    if value["external_state"] not in ACTIVE_EXTERNAL_STATES:
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-invalid",
            details={"reason": "external-state-invalid"},
        )
    _, parse_error = _parse_utc_timestamp(value["external_observed_at"])
    if parse_error is not None:
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-invalid",
            details={"reason": "external-observation-invalid"},
        )
    return dict(value)


def _valid_lease_repair_resource_keys(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
        and value == sorted(set(value))
    )


def _validated_lease_repair_generation(
    value: Any,
    generation_sha256: Any,
    intent: dict[str, Any],
) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) != len(intent["required_resource_keys"])
        or not isinstance(generation_sha256, str)
        or SHA256_RE.fullmatch(generation_sha256) is None
    ):
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-generation-invalid"
        )
    expected_fields = set(LEASE_IDENTITY_FIELDS)
    generation: list[dict[str, Any]] = []
    resource_keys: list[str] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-generation-invalid"
            )
        resource_key = item.get("resource_key")
        owner_id = item.get("owner_id")
        metadata_sha256 = item.get("metadata_sha256")
        acquired_at = _lease_timestamp(item, "acquired_at_unix")
        updated_at = _lease_timestamp(item, "updated_at_unix")
        expires_at = _lease_timestamp(item, "expires_at_unix")
        if (
            not isinstance(resource_key, str)
            or not resource_key
            or owner_id != intent["lease_owner_id"]
            or not isinstance(metadata_sha256, str)
            or SHA256_RE.fullmatch(metadata_sha256) is None
            or acquired_at is None
            or updated_at is None
            or expires_at is None
            or acquired_at > updated_at
            or updated_at >= expires_at
        ):
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-generation-invalid"
            )
        generation.append(dict(item))
        resource_keys.append(resource_key)
    if (
        resource_keys != intent["required_resource_keys"]
        or resource_keys != sorted(set(resource_keys))
        or _sha256(generation) != generation_sha256
    ):
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-generation-invalid"
        )
    return generation


def _current_lease_repair_generation(
    intent: dict[str, Any], *, required: bool
) -> list[dict[str, Any]] | None:
    generation: list[dict[str, Any]] = []
    now = resources._now()
    for resource_key in intent["required_resource_keys"]:
        observed = resources.inspect_resource(resource_key)
        if not isinstance(observed, dict) or observed.get("owner_id") != intent[
            "lease_owner_id"
        ]:
            if required:
                raise BureauPickupError(
                    "existing-assignment-lease-repair-generation-unavailable",
                    details={"resource_key": resource_key},
                )
            return None
        try:
            snapshot = _lease_snapshot(observed)
        except (KeyError, TypeError) as exc:
            if required:
                raise BureauPickupError(
                    "existing-assignment-lease-repair-generation-unavailable",
                    details={"resource_key": resource_key},
                ) from exc
            return None
        expires_at = _lease_timestamp(snapshot, "expires_at_unix")
        if expires_at is None or expires_at <= now:
            if required:
                raise BureauPickupError(
                    "existing-assignment-lease-repair-generation-unavailable",
                    details={"resource_key": resource_key},
                )
            return None
        generation.append(snapshot)
    generation_sha256 = _sha256(generation)
    return _validated_lease_repair_generation(
        generation, generation_sha256, intent
    )


def _persist_lease_repair_receipt(
    run_dir: Path, legacy_filename: str, receipt: dict[str, Any]
) -> dict[str, Any]:
    receipt_sha256 = _lease_repair_receipt_sha256(receipt)
    immutable_filename = f"lease-repair-obligation-{receipt_sha256}.json"
    persisted = _validated_lease_repair_receipt(
        run_dir, immutable_filename, receipt
    )
    legacy_path = run_dir / legacy_filename
    legacy_label = legacy_filename.removesuffix(".json")
    try:
        legacy = _read_bound_json(legacy_path, label=legacy_label)
    except BureauPickupError as exc:
        if exc.code != f"{legacy_label}-missing":
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-invalid",
                details={"filename": legacy_filename, "cause_code": exc.code},
            ) from exc
        _write_bound_json(legacy_path, persisted)
    else:
        _lease_repair_receipt_sha256(legacy)
    return persisted


def _validate_existing_assignment_lease_repair_receipt(
    filename: str,
    expected_kind: str | None,
    receipt: dict[str, Any],
    run_dir: Path,
    intent: dict[str, Any],
    request: dict[str, Any],
    acquisition: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    _lease_repair_receipt_sha256(receipt)
    observed_kind = receipt.get("kind")
    allowed_kinds = {
        "grabowski_bureau_pickup_lease_reacquire",
        "grabowski_bureau_pickup_lease_rebind",
    }
    if (
        observed_kind not in allowed_kinds
        or (expected_kind is not None and observed_kind != expected_kind)
    ):
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-invalid",
            details={"filename": filename, "reason": "kind-mismatch"},
        )
    journal_identity = _journal_run_identity(run_dir, intent)
    leases_by_key = _validated_existing_assignment_repair_acquisition(
        intent, acquisition
    )
    common_fields = {
        "schema_version",
        "kind",
        "run_id",
        "task_id",
        "worker_id",
        "task_sha256",
        "plan_sha256",
        "envelope_sha256",
        "claim_intent_sha256",
        "external_binding",
        "resource_keys",
        "lease_generation",
        "lease_generation_sha256",
        "receipt_sha256",
    }
    expected_fields = common_fields | (
        {"groups"}
        if observed_kind == "grabowski_bureau_pickup_lease_reacquire"
        else {"group", "metadata_sha256"}
    )
    if set(receipt) != expected_fields:
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-invalid",
            details={
                "filename": filename,
                "expected_fields": sorted(expected_fields),
                "observed_fields": sorted(receipt),
            },
        )
    expected_binding = {
        "schema_version": SCHEMA_VERSION,
        "kind": observed_kind,
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "worker_id": intent["worker_id"],
        "task_sha256": intent["task_sha256"],
        "plan_sha256": intent["plan_sha256"],
        "envelope_sha256": journal_identity["envelope_sha256"],
        "claim_intent_sha256": intent["intent_sha256"],
    }
    binding_mismatches = {
        key: {"expected": value, "observed": receipt.get(key)}
        for key, value in expected_binding.items()
        if receipt.get(key) != value
    }
    if binding_mismatches:
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-binding-mismatch",
            details={"filename": filename, "mismatches": binding_mismatches},
        )
    external = _validated_persisted_lease_repair_external_binding(
        receipt["external_binding"]
    )
    if not _valid_lease_repair_resource_keys(receipt["resource_keys"]):
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-resource-mismatch"
        )
    _validated_lease_repair_generation(
        receipt["lease_generation"],
        receipt["lease_generation_sha256"],
        intent,
    )
    groups = _acquisition_groups(intent, request)
    groups_by_name = {group["name"]: group for group in groups}
    if len(groups_by_name) != len(groups):
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-resource-mismatch",
            details={"reason": "acquisition-groups-ambiguous"},
        )

    if observed_kind == "grabowski_bureau_pickup_lease_reacquire":
        receipt_groups = receipt["groups"]
        if not isinstance(receipt_groups, list) or not receipt_groups:
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-resource-mismatch"
            )
        seen_groups: set[str] = set()
        rebound_keys: list[str] = []
        for receipt_group in receipt_groups:
            expected_group_fields = {
                "group",
                "resource_keys",
                "reacquired_resource_keys",
                "method",
            }
            if (
                not isinstance(receipt_group, dict)
                or set(receipt_group) != expected_group_fields
            ):
                raise BureauPickupError(
                    "existing-assignment-lease-repair-receipt-resource-mismatch"
                )
            group_name = receipt_group["group"]
            method = receipt_group["method"]
            if not isinstance(group_name, str) or not isinstance(method, str):
                raise BureauPickupError(
                    "existing-assignment-lease-repair-receipt-resource-mismatch"
                )
            group = groups_by_name.get(group_name)
            reacquired_keys = receipt_group["reacquired_resource_keys"]
            if (
                group is None
                or group_name in seen_groups
                or receipt_group["resource_keys"] != group["resource_keys"]
                or not _valid_lease_repair_resource_keys(reacquired_keys)
                or not reacquired_keys
                or not set(reacquired_keys).issubset(group["resource_keys"])
                or method not in {"acquire", "same-owner-rebind"}
            ):
                raise BureauPickupError(
                    "existing-assignment-lease-repair-receipt-resource-mismatch"
                )
            expected_purpose = (
                f"Bureau coordinated pickup {intent['run_id']} group {group_name}"
            )
            if any(
                leases_by_key[key].get("purpose") != expected_purpose
                for key in group["resource_keys"]
            ):
                raise BureauPickupError(
                    "existing-assignment-lease-repair-receipt-resource-mismatch"
                )
            seen_groups.add(group_name)
            rebound_keys.extend(reacquired_keys)
        if (
            receipt["resource_keys"] != sorted(rebound_keys)
            or len(rebound_keys) != len(set(rebound_keys))
        ):
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-resource-mismatch"
            )
    else:
        metadata_sha256 = receipt["metadata_sha256"]
        if len(groups) != 1:
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-resource-mismatch"
            )
        group = groups[0]
        expected_metadata_values = [
            lease.get("metadata_sha256") for lease in leases_by_key.values()
        ]
        if (
            receipt["group"] != group["name"]
            or receipt["resource_keys"] != group["resource_keys"]
            or any(
                not isinstance(value, str) or SHA256_RE.fullmatch(value) is None
                for value in expected_metadata_values
            )
            or len(set(expected_metadata_values)) != 1
            or not isinstance(metadata_sha256, str)
            or SHA256_RE.fullmatch(metadata_sha256) is None
            or metadata_sha256 != expected_metadata_values[0]
        ):
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-resource-mismatch"
            )
    return receipt, journal_identity, external


def _read_existing_assignment_lease_repair_obligation(
    run_dir: Path,
    intent: dict[str, Any],
    request: dict[str, Any],
    acquisition: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    specs: list[tuple[Path, str | None]] = [
        (run_dir / "lease-reacquire.json", "grabowski_bureau_pickup_lease_reacquire"),
        (run_dir / "lease-rebind.json", "grabowski_bureau_pickup_lease_rebind"),
    ]
    specs.extend(
        (path, None)
        for path in sorted(run_dir.glob("lease-repair-obligation-*.json"))
    )
    by_sha256: dict[str, tuple[str, str | None, dict[str, Any]]] = {}
    for path, expected_kind in specs:
        filename = path.name
        label = filename.removesuffix(".json")
        try:
            receipt = _read_bound_json(path, label=label)
        except BureauPickupError as exc:
            if exc.code == f"{label}-missing":
                continue
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-invalid",
                details={"filename": filename, "cause_code": exc.code},
            ) from exc
        receipt_sha256 = _lease_repair_receipt_sha256(receipt)
        if expected_kind is None:
            expected_filename = f"lease-repair-obligation-{receipt_sha256}.json"
            if filename != expected_filename:
                raise BureauPickupError(
                    "existing-assignment-lease-repair-receipt-invalid",
                    details={"filename": filename, "reason": "filename-binding"},
                )
        elif receipt.get("kind") != expected_kind:
            raise BureauPickupError(
                "existing-assignment-lease-repair-receipt-invalid",
                details={"filename": filename, "reason": "kind-mismatch"},
            )
        prior = by_sha256.get(receipt_sha256)
        if prior is not None:
            if prior[2] != receipt:
                raise BureauPickupError(
                    "existing-assignment-lease-repair-receipt-invalid",
                    details={"filename": filename, "reason": "digest-alias-conflict"},
                )
            continue
        by_sha256[receipt_sha256] = (filename, expected_kind, receipt)
    if not by_sha256:
        return None

    validated = [
        _validate_existing_assignment_lease_repair_receipt(
            filename, expected_kind, receipt, run_dir, intent, request, acquisition
        )
        for filename, expected_kind, receipt in by_sha256.values()
    ]
    current_generation = _current_lease_repair_generation(intent, required=False)
    if current_generation is None:
        return None
    current_generation_sha256 = _sha256(current_generation)
    matching = [
        item
        for item in validated
        if item[0]["lease_generation_sha256"] == current_generation_sha256
        and item[0]["lease_generation"] == current_generation
    ]
    if len(matching) > 1:
        raise BureauPickupError(
            "existing-assignment-lease-repair-receipt-ambiguous",
            details={
                "receipt_sha256": sorted(item[0]["receipt_sha256"] for item in matching)
            },
        )
    if not matching:
        return None
    return matching[0]

def _lease_repair_activity_id(receipt_sha256: str) -> str:
    if SHA256_RE.fullmatch(receipt_sha256) is None:
        raise BureauPickupError("existing-assignment-lease-repair-receipt-invalid")
    return f"lease-repair:{receipt_sha256}"


def _bound_activity_binding(
    intent: dict[str, Any],
    journal_identity: dict[str, Any],
    external: dict[str, Any],
    activity_id: str,
) -> dict[str, Any]:
    if external["external_unbound"]:
        external_binding = {"status": "explicitly-unbound"}
    else:
        external_binding = {
            "status": "bound",
            "external_system": external["external_system"],
            "external_id": external["external_id"],
            "external_state": external["external_state"],
            "external_observed_at": external["external_observed_at"],
        }
    return {
        "activity_id": activity_id,
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "worker_id": intent["worker_id"],
        "task_sha256": intent["task_sha256"],
        "plan_sha256": intent["plan_sha256"],
        "envelope_sha256": journal_identity["envelope_sha256"],
        "external_binding": external_binding,
    }


def _read_lease_repair_activity_status(
    intent: dict[str, Any],
    request: dict[str, Any],
    registry_binding: RegistryBinding,
    activity_id: str,
    *,
    heartbeat_error: Exception | None = None,
) -> dict[str, Any]:
    try:
        return _bound_bureau_call(
            registry_binding,
            lambda: _coordination_status(
                intent["run_id"],
                registry_root=request["registry_root"],
                coordination_root=request["coordination_root"],
                activity_id=activity_id,
            ),
        )
    except Exception as exc:
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-outcome-unknown",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "rebind_required": True,
                "lease_mutation_committed": True,
                "heartbeat_error_type": (
                    type(heartbeat_error).__name__ if heartbeat_error else None
                ),
                "readback_error_type": type(exc).__name__,
            },
        ) from exc


def _validate_lease_repair_activity_status(
    readback: Any,
    intent: dict[str, Any],
    acquisition: dict[str, Any],
    journal_identity: dict[str, Any],
    external: dict[str, Any],
    activity_id: str,
    *,
    action: str,
) -> dict[str, Any]:
    if not isinstance(readback, dict) or _adapter_outcome_unknown(
        readback, run_id=intent["run_id"]
    ):
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-outcome-unknown",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "rebind_required": True,
                "lease_mutation_committed": True,
                "coordination": readback,
            },
        )
    if "bound_activity" not in readback:
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-outcome-unknown",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "rebind_required": True,
                "lease_mutation_committed": True,
                "definitively_missing": False,
            },
        )
    bound_activity_status = readback["bound_activity"]
    expected_status_keys = {
        "schema_version",
        "kind",
        "status",
        "run_id",
        "activity_id",
        "bound_activity",
    }
    expected_status_binding = {
        "schema_version": SCHEMA_VERSION,
        "kind": "bureau_bound_activity_status",
        "run_id": intent["run_id"],
        "activity_id": activity_id,
    }
    if not isinstance(bound_activity_status, dict):
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-readback-conflict",
            details={"run_id": intent["run_id"], "activity_id": activity_id},
        )
    status_mismatches = {
        key: {"expected": value, "observed": bound_activity_status.get(key)}
        for key, value in expected_status_binding.items()
        if bound_activity_status.get(key) != value
    }
    if set(bound_activity_status) != expected_status_keys or status_mismatches:
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-readback-conflict",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "expected_fields": sorted(expected_status_keys),
                "observed_fields": sorted(bound_activity_status),
                "mismatches": status_mismatches,
            },
        )
    status = bound_activity_status["status"]
    bound_activity = bound_activity_status["bound_activity"]
    if status == "missing":
        if bound_activity is not None:
            raise BureauPickupError(
                "existing-assignment-lease-repair-heartbeat-readback-conflict",
                details={"run_id": intent["run_id"], "activity_id": activity_id},
            )
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-readback-missing",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "rebind_required": True,
                "lease_mutation_committed": True,
                "definitively_missing": True,
            },
        )
    if status != "recorded" or not isinstance(bound_activity, dict):
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-readback-conflict",
            details={"run_id": intent["run_id"], "activity_id": activity_id},
        )
    expected_event_keys = {
        "kind",
        "source",
        "outcome",
        "activity",
        "evidence",
        "heartbeat_at",
    }
    expected_event_binding = {
        "kind": "bureau.bound_activity_heartbeat",
        "source": "bound-activity",
        "outcome": "succeeded",
    }
    event_mismatches = {
        key: {"expected": value, "observed": bound_activity.get(key)}
        for key, value in expected_event_binding.items()
        if bound_activity.get(key) != value
    }
    if set(bound_activity) != expected_event_keys or event_mismatches:
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-readback-conflict",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "expected_fields": sorted(expected_event_keys),
                "observed_fields": sorted(bound_activity),
                "mismatches": event_mismatches,
            },
        )
    expected_activity = _bound_activity_binding(
        intent, journal_identity, external, activity_id
    )
    activity = bound_activity["activity"]
    if activity != expected_activity:
        observed_activity = activity if isinstance(activity, dict) else {}
        activity_mismatches = {
            key: {"expected": value, "observed": observed_activity.get(key)}
            for key, value in expected_activity.items()
            if observed_activity.get(key) != value
        }
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-readback-conflict",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "mismatches": activity_mismatches,
            },
        )
    evidence = bound_activity["evidence"]
    evidence_error: str | None = None
    evidence_mismatches: dict[str, Any] = {}
    if not isinstance(evidence, dict):
        evidence_error = "evidence-not-object"
    elif external["external_unbound"]:
        expected_evidence = {
            "source": "exact-run-binding",
            "binding_status": "explicitly-unbound",
        }
        if evidence != expected_evidence:
            evidence_error = "unbound-evidence-mismatch"
            evidence_mismatches = {
                key: {"expected": value, "observed": evidence.get(key)}
                for key, value in expected_evidence.items()
                if evidence.get(key) != value
            }
            if set(evidence) != set(expected_evidence):
                evidence_mismatches["fields"] = {
                    "expected": sorted(expected_evidence),
                    "observed": sorted(evidence),
                }
    else:
        expected_evidence_keys = {
            "source",
            "external_system",
            "external_id",
            "observed_state",
            "observed_at",
        }
        if set(evidence) != expected_evidence_keys:
            evidence_error = "bound-evidence-fields-mismatch"
            evidence_mismatches["fields"] = {
                "expected": sorted(expected_evidence_keys),
                "observed": sorted(evidence),
            }
        expected_evidence_binding = {
            "source": "adapter.observe",
            "external_system": external["external_system"],
            "external_id": external["external_id"],
        }
        binding_mismatches = {
            key: {"expected": value, "observed": evidence.get(key)}
            for key, value in expected_evidence_binding.items()
            if evidence.get(key) != value
        }
        if binding_mismatches:
            evidence_error = evidence_error or "bound-evidence-binding-mismatch"
            evidence_mismatches.update(binding_mismatches)
        observed_state = evidence.get("observed_state")
        if observed_state not in BOUND_ACTIVITY_SUCCESSFUL_EXTERNAL_STATES:
            evidence_error = evidence_error or "bound-evidence-state-invalid"
            evidence_mismatches["observed_state"] = {
                "expected": sorted(BOUND_ACTIVITY_SUCCESSFUL_EXTERNAL_STATES),
                "observed": observed_state,
            }
        observed_at = evidence.get("observed_at")
        _, observed_at_parse_error = _parse_utc_timestamp(observed_at)
        if (
            observed_at_parse_error is not None
            or not isinstance(observed_at, str)
            or observed_at != observed_at.strip()
        ):
            evidence_error = evidence_error or "bound-evidence-observed-at-invalid"
            evidence_mismatches["observed_at"] = {
                "expected": "valid trimmed UTC timestamp",
                "observed": observed_at,
            }
        elif observed_at == external["external_observed_at"]:
            evidence_error = evidence_error or "bound-evidence-observed-at-stale"
            evidence_mismatches["observed_at"] = {
                "expected": "fresh timestamp distinct from external_observed_at",
                "observed": observed_at,
            }
    if evidence_error is not None:
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-readback-conflict",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "evidence_error": evidence_error,
                "mismatches": evidence_mismatches,
            },
        )
    heartbeat_at = bound_activity["heartbeat_at"]
    _, heartbeat_parse_error = _parse_utc_timestamp(heartbeat_at)
    if (
        heartbeat_parse_error is not None
        or not isinstance(heartbeat_at, str)
        or heartbeat_at != heartbeat_at.strip()
    ):
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-readback-conflict",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "heartbeat_parse_error": heartbeat_parse_error,
            },
        )
    run = _validate_claim_readback(readback, intent, acquisition)
    expected_run_binding = {
        key: expected_activity[key]
        for key in (
            "run_id",
            "task_id",
            "worker_id",
            "task_sha256",
            "plan_sha256",
            "envelope_sha256",
        )
    }
    expected_run_binding.update(
        {
            field: external[field]
            for field in (
                "external_system",
                "external_id",
                "external_state",
                "external_observed_at",
            )
        }
    )
    identity_mismatches = {
        key: {"expected": value, "observed": run.get(key)}
        for key, value in expected_run_binding.items()
        if run.get(key) != value
    }
    if identity_mismatches:
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-run-drift",
            details={"mismatches": identity_mismatches},
        )
    _require_active_execution_binding(readback, action=action)
    return readback


def _heartbeat_lease_repair(
    intent: dict[str, Any],
    request: dict[str, Any],
    acquisition: dict[str, Any],
    registry_binding: RegistryBinding,
    journal_identity: dict[str, Any],
    external: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    activity_id = _lease_repair_activity_id(receipt["receipt_sha256"])
    arguments = _bureau_arguments(
        "heartbeat",
        registry_root=request["registry_root"],
        coordination_root=request["coordination_root"],
    )
    arguments.extend(
        [
            intent["run_id"],
            "--bound-activity",
            "--activity-id",
            activity_id,
            "--task-id",
            intent["task_id"],
            "--worker",
            intent["worker_id"],
            "--task-sha256",
            intent["task_sha256"],
            "--plan-sha256",
            intent["plan_sha256"],
            "--envelope-sha256",
            journal_identity["envelope_sha256"],
        ]
    )
    if external["external_unbound"]:
        arguments.append("--external-unbound")
    else:
        for field in (
            "external_system",
            "external_id",
            "external_state",
            "external_observed_at",
        ):
            arguments.extend([f"--{field.replace('_', '-')}", external[field]])

    heartbeat_error: Exception | None = None
    try:
        heartbeat = _bound_bureau_call(
            registry_binding,
            lambda: bureau._invoke_bureau(
                arguments,
                mutation=True,
                required_readback=[
                    f"bureau_run:{intent['run_id']}",
                    f"bureau_bound_activity:{activity_id}",
                ],
            ),
        )
    except Exception as exc:
        heartbeat = None
        heartbeat_error = exc

    mutation_ambiguous = heartbeat_error is not None or not isinstance(heartbeat, dict)
    if isinstance(heartbeat, dict) and _adapter_outcome_unknown(
        heartbeat, run_id=intent["run_id"]
    ):
        mutation_ambiguous = True
    if (
        isinstance(heartbeat, dict)
        and not mutation_ambiguous
        and bureau._is_bureau_failure_payload(heartbeat)
    ):
        raise BureauPickupError(
            "existing-assignment-lease-repair-heartbeat-rejected",
            details={
                "run_id": intent["run_id"],
                "activity_id": activity_id,
                "heartbeat": heartbeat,
                "lease_mutation_committed": True,
            },
        )
    readback = _read_lease_repair_activity_status(
        intent,
        request,
        registry_binding,
        activity_id,
        heartbeat_error=heartbeat_error,
    )
    return _validate_lease_repair_activity_status(
        readback,
        intent,
        acquisition,
        journal_identity,
        external,
        activity_id,
        action="repair-existing-assignment-lease-heartbeat-readback",
    )


def _repair_existing_assignment_lease_binding(
    coordination: dict[str, Any],
    intent: dict[str, Any],
    request: dict[str, Any],
    acquisition: dict[str, Any],
    run_dir: Path,
    registry_binding: RegistryBinding,
) -> dict[str, Any] | bool:
    lease_state = coordination.get("lease")
    lease_error = lease_state.get("error") if isinstance(lease_state, dict) else None
    error_code = lease_error.get("code") if isinstance(lease_error, dict) else None
    if not (
        isinstance(lease_state, dict)
        and lease_state.get("status") == "active-binding-drift"
        and error_code
        in {
            "lease-expired",
            "lease-metadata-binding-mismatch",
            "lease-resources-missing",
        }
    ):
        return False
    journal_identity, external = _existing_assignment_repair_authority(
        coordination,
        intent,
        acquisition,
        run_dir,
        registry_binding,
        coordination_root=request["coordination_root"],
    )
    original_by_key = {
        item["resource_key"]: item
        for item in acquisition.get("leases", [])
        if isinstance(item, dict) and isinstance(item.get("resource_key"), str)
    }
    if sorted(original_by_key) != intent["required_resource_keys"]:
        raise BureauPickupError("existing-assignment-lease-journal-incomplete")
    groups = _acquisition_groups(intent, request)
    if not groups:
        return False

    def original_group(
        group: dict[str, Any],
    ) -> tuple[list[str], str, list[dict[str, Any]]]:
        keys = group["resource_keys"]
        purpose = f"Bureau coordinated pickup {intent['run_id']} group {group['name']}"
        original = [original_by_key[key] for key in keys]
        if any(item.get("purpose") != purpose for item in original):
            raise BureauPickupError(
                "existing-assignment-lease-purpose-journal-mismatch",
                details={"group": group["name"]},
            )
        return keys, purpose, original

    if error_code == "lease-expired":
        reacquired: list[dict[str, Any]] = []
        compensation_entries: list[dict[str, Any]] = []
        try:
            for index, group in enumerate(groups, start=1):
                keys, purpose, _original = original_group(group)
                expired_keys: list[str] = []
                expired_snapshots: list[dict[str, Any]] = []
                for key in keys:
                    observed = resources.inspect_resource(key)
                    if observed is not None:
                        if observed.get("owner_id") != intent["lease_owner_id"]:
                            raise BureauPickupError(
                                "existing-assignment-lease-foreign-owner",
                                details={
                                    "resource_key": key,
                                    "owner_id": observed.get("owner_id"),
                                },
                            )
                        if observed.get("purpose") != purpose or observed.get(
                            "metadata_sha256"
                        ) != original_by_key[key].get("metadata_sha256"):
                            raise BureauPickupError(
                                "existing-assignment-lease-live-binding-mismatch",
                                details={
                                    "group": group["name"],
                                    "resource_key": key,
                                },
                            )
                        continue
                    persisted = _persisted_resource_lease(key)
                    if persisted is None:
                        raise BureauPickupError(
                            "existing-assignment-expired-lease-history-missing",
                            details={
                                "group": group["name"],
                                "resource_key": key,
                            },
                        )
                    if persisted["expires_at_unix"] > resources._now():
                        raise BureauPickupError(
                            "existing-assignment-lease-current-readback-drift",
                            details={
                                "group": group["name"],
                                "resource_key": key,
                            },
                        )
                    if persisted.get("owner_id") != intent["lease_owner_id"]:
                        raise BureauPickupError(
                            "existing-assignment-lease-foreign-owner",
                            details={
                                "resource_key": key,
                                "owner_id": persisted.get("owner_id"),
                            },
                        )
                    if persisted.get("purpose") != purpose or persisted.get(
                        "metadata_sha256"
                    ) != original_by_key[key].get("metadata_sha256"):
                        raise BureauPickupError(
                            "existing-assignment-lease-history-binding-mismatch",
                            details={
                                "group": group["name"],
                                "resource_key": key,
                            },
                        )
                    expired_keys.append(key)
                    expired_snapshots.append(_lease_snapshot(persisted))
                if not expired_keys:
                    continue
                rebound_group = {**group, "resource_keys": expired_keys}
                result = resources.rebind_same_owner_resources(
                    intent["lease_owner_id"],
                    expired_keys,
                    purpose=purpose,
                    ttl_seconds=group["ttl_seconds"],
                    metadata=group["metadata"],
                    expected_current_leases=expired_snapshots,
                    expected_original_leases=[
                        _lease_snapshot(original_by_key[key]) for key in expired_keys
                    ],
                )
                _validate_acquired_group(
                    intent["lease_owner_id"], rebound_group, result
                )
                leases = result["leases"]
                expected_expired = {
                    item["resource_key"]: item for item in expired_snapshots
                }
                if any(
                    item.get("purpose") != purpose
                    or item.get("metadata_sha256")
                    != original_by_key[item["resource_key"]].get("metadata_sha256")
                    or _lease_snapshot(item)
                    == expected_expired.get(item["resource_key"])
                    for item in leases
                ):
                    raise BureauPickupError(
                        "existing-assignment-lease-reacquire-mismatch",
                        details={"group": group["name"]},
                    )
                entry = {
                    "group": group["name"],
                    "resource_keys": keys,
                    "reacquired_resource_keys": expired_keys,
                    "method": "same-owner-rebind",
                    "result": result,
                }
                reacquired.append(entry)
                compensation_entries.append(
                    {"group": group["name"], "resource_keys": expired_keys}
                )
                _write_bound_json(
                    run_dir / f"lease-reacquired-{index:02d}-{_sha256(entry)}.json", entry
                )
        except Exception as exc:
            compensation = _compensate_acquisitions(
                intent["lease_owner_id"], compensation_entries, run_dir
            )
            raise BureauPickupError(
                "existing-assignment-lease-reacquire-failed",
                details={
                    "error_type": type(exc).__name__,
                    "cause_code": getattr(exc, "code", None),
                    "reacquired_group_count": len(reacquired),
                    "compensation": compensation,
                },
            ) from exc
        if not reacquired:
            return False
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_lease_reacquire",
            "run_id": intent["run_id"],
            "task_id": intent["task_id"],
            "worker_id": intent["worker_id"],
            "task_sha256": intent["task_sha256"],
            "plan_sha256": intent["plan_sha256"],
            "envelope_sha256": journal_identity["envelope_sha256"],
            "claim_intent_sha256": intent["intent_sha256"],
            "external_binding": external,
            "groups": [
                {
                    "group": entry["group"],
                    "resource_keys": entry["resource_keys"],
                    "reacquired_resource_keys": entry["reacquired_resource_keys"],
                    "method": entry["method"],
                }
                for entry in reacquired
            ],
            "resource_keys": sorted(
                key for entry in reacquired for key in entry["reacquired_resource_keys"]
            ),
        }
        lease_generation = _current_lease_repair_generation(intent, required=True)
        receipt["lease_generation"] = lease_generation
        receipt["lease_generation_sha256"] = _sha256(lease_generation)
        receipt["receipt_sha256"] = _sha256(receipt)
        receipt = _persist_lease_repair_receipt(
            run_dir, "lease-reacquire.json", receipt
        )
        return _heartbeat_lease_repair(
            intent,
            request,
            acquisition,
            registry_binding,
            journal_identity,
            external,
            receipt,
        )

    if error_code == "lease-resources-missing":
        reacquired: list[dict[str, Any]] = []
        compensation_entries: list[dict[str, Any]] = []
        try:
            for index, group in enumerate(groups, start=1):
                keys, purpose, _original = original_group(group)
                missing_before: list[str] = []
                for key in keys:
                    observed = resources.inspect_resource(key)
                    if observed is None:
                        missing_before.append(key)
                        continue
                    if observed.get("owner_id") != intent["lease_owner_id"]:
                        raise BureauPickupError(
                            "existing-assignment-lease-foreign-owner",
                            details={
                                "resource_key": key,
                                "owner_id": observed.get("owner_id"),
                            },
                        )
                    if observed.get("purpose") != purpose or observed.get(
                        "metadata_sha256"
                    ) != original_by_key[key].get("metadata_sha256"):
                        raise BureauPickupError(
                            "existing-assignment-lease-live-binding-mismatch",
                            details={"group": group["name"], "resource_key": key},
                        )
                if not missing_before:
                    continue
                result = resources.acquire_resources(
                    intent["lease_owner_id"],
                    keys,
                    purpose=purpose,
                    ttl_seconds=group["ttl_seconds"],
                    metadata=group["metadata"],
                    nonconflict_proof=group["nonconflict_proof"],
                )
                preserved = {
                    item.get("resource_key") if isinstance(item, dict) else item
                    for item in result.get("preserved", [])
                }
                mutated_keys = [
                    key for key in missing_before if key not in preserved
                ]
                _validate_acquired_group(intent["lease_owner_id"], group, result)
                leases = result["leases"]
                if any(
                    item.get("purpose") != purpose
                    or item.get("metadata_sha256")
                    != original_by_key[item["resource_key"]].get("metadata_sha256")
                    for item in leases
                ):
                    raise BureauPickupError(
                        "existing-assignment-lease-reacquire-mismatch",
                        details={"group": group["name"]},
                    )
                if not mutated_keys:
                    continue
                entry = {
                    "group": group["name"],
                    "resource_keys": keys,
                    "reacquired_resource_keys": mutated_keys,
                    "method": "acquire",
                    "result": result,
                }
                reacquired.append(entry)
                if mutated_keys:
                    compensation_entries.append(
                        {"group": group["name"], "resource_keys": mutated_keys}
                    )
                _write_bound_json(run_dir / f"lease-reacquired-{index:02d}-{_sha256(entry)}.json", entry)
        except Exception as exc:
            compensation = _compensate_acquisitions(
                intent["lease_owner_id"], compensation_entries, run_dir
            )
            raise BureauPickupError(
                "existing-assignment-lease-reacquire-failed",
                details={
                    "error_type": type(exc).__name__,
                    "cause_code": getattr(exc, "code", None),
                    "reacquired_group_count": len(reacquired),
                    "compensation": compensation,
                },
            ) from exc
        if not reacquired:
            return False
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_lease_reacquire",
            "run_id": intent["run_id"],
            "task_id": intent["task_id"],
            "worker_id": intent["worker_id"],
            "task_sha256": intent["task_sha256"],
            "plan_sha256": intent["plan_sha256"],
            "envelope_sha256": journal_identity["envelope_sha256"],
            "claim_intent_sha256": intent["intent_sha256"],
            "external_binding": external,
            "groups": [
                {
                    "group": entry["group"],
                    "resource_keys": entry["resource_keys"],
                    "reacquired_resource_keys": entry["reacquired_resource_keys"],
                    "method": entry["method"],
                }
                for entry in reacquired
            ],
            "resource_keys": sorted(
                key for entry in reacquired for key in entry["reacquired_resource_keys"]
            ),
        }
        lease_generation = _current_lease_repair_generation(intent, required=True)
        receipt["lease_generation"] = lease_generation
        receipt["lease_generation_sha256"] = _sha256(lease_generation)
        receipt["receipt_sha256"] = _sha256(receipt)
        receipt = _persist_lease_repair_receipt(
            run_dir, "lease-reacquire.json", receipt
        )
        return _heartbeat_lease_repair(
            intent,
            request,
            acquisition,
            registry_binding,
            journal_identity,
            external,
            receipt,
        )

    if len(groups) != 1:
        return False
    group = groups[0]
    keys, purpose, _original = original_group(group)
    current_by_key: dict[str, dict[str, Any]] = {}
    for key in keys:
        observed = resources.inspect_resource(key)
        if observed is None:
            raise BureauPickupError(
                "existing-assignment-lease-missing",
                details={"resource_key": key},
            )
        if observed.get("owner_id") != intent["lease_owner_id"]:
            raise BureauPickupError(
                "existing-assignment-lease-foreign-owner",
                details={"resource_key": key, "owner_id": observed.get("owner_id")},
            )
        current_by_key[key] = observed
    if any(
        current_by_key[key]["acquired_at_unix"]
        <= original_by_key[key]["expires_at_unix"]
        for key in keys
    ):
        return False
    result = resources.rebind_same_owner_resources(
        intent["lease_owner_id"],
        keys,
        purpose=purpose,
        ttl_seconds=group["ttl_seconds"],
        metadata=group["metadata"],
        expected_current_leases=[_lease_snapshot(current_by_key[key]) for key in keys],
        expected_original_leases=[
            _lease_snapshot(original_by_key[key]) for key in keys
        ],
    )
    _validate_acquired_group(intent["lease_owner_id"], group, result)
    if any(
        item.get("purpose") != purpose
        or item.get("metadata_sha256")
        != original_by_key[item["resource_key"]].get("metadata_sha256")
        or _lease_snapshot(item)
        == _lease_snapshot(current_by_key[item["resource_key"]])
        for item in result["leases"]
    ):
        raise BureauPickupError("existing-assignment-lease-rebind-mismatch")
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_lease_rebind",
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "worker_id": intent["worker_id"],
        "task_sha256": intent["task_sha256"],
        "plan_sha256": intent["plan_sha256"],
        "envelope_sha256": journal_identity["envelope_sha256"],
        "claim_intent_sha256": intent["intent_sha256"],
        "external_binding": external,
        "group": group["name"],
        "resource_keys": keys,
        "metadata_sha256": result["metadata_sha256"],
    }
    lease_generation = _current_lease_repair_generation(intent, required=True)
    receipt["lease_generation"] = lease_generation
    receipt["lease_generation_sha256"] = _sha256(lease_generation)
    receipt["receipt_sha256"] = _sha256(receipt)
    receipt = _persist_lease_repair_receipt(run_dir, "lease-rebind.json", receipt)
    return _heartbeat_lease_repair(
        intent,
        request,
        acquisition,
        registry_binding,
        journal_identity,
        external,
        receipt,
    )


def _closeout_latched_response(
    request: dict[str, Any],
    registry_binding: RegistryBinding,
    request_sha256: str,
    closeout_latch: dict[str, Any],
) -> dict[str, Any]:
    task_id = request["task_id"]
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_closeout_latched",
        "status": "closeout-only",
        "effect_started": False,
        "retryable": False,
        "ambiguity": False,
        "request_sha256": request_sha256,
        "registry_binding_sha256": registry_binding["identity"]["binding_sha256"],
        "registry_binding_kind": registry_binding["identity"]["kind"],
        "task_id": task_id,
        "latch": closeout_latch,
        "required_readback": [f"bureau_task:{task_id}"],
    }
    bureau._audit(
        "bureau-pickup-closeout-latched",
        result,
        task_id=task_id,
    )
    return result


@mcp.tool(name="grabowski_bureau_pickup_execute", annotations=MUTATING)
def grabowski_bureau_pickup_execute(
    request: BureauPickupRequest,
) -> dict[str, Any]:
    """Coordinate one Bureau claim with owner-bound Grabowski leases and recovery."""
    normalized, registry_binding = _prepare_request(request)
    operator._require_operator_mutation(
        "terminal_execute", path=normalized["registry_root"]
    )
    operator._require_operator_mutation(
        "terminal_execute", path=normalized["coordination_root"]
    )
    operator._require_operator_mutation("resource_lease")
    request_sha256 = _sha256(normalized)
    orphan_recovery = _recover_orphaned_journal_before_claim(
        normalized, registry_binding, request_sha256
    )
    if orphan_recovery is not None:
        return orphan_recovery
    intent_payload, closeout_latch = _bound_bureau_call(
        registry_binding,
        lambda: _claim_intent_or_closeout(normalized),
    )
    if closeout_latch is not None:
        return _closeout_latched_response(
            normalized, registry_binding, request_sha256, closeout_latch
        )
    cached_coordination: dict[str, Any] | None = None
    try:
        intent, existing = _validate_intent_result(intent_payload, normalized)
    except BureauPickupError as exc:
        if not _claim_rejection_allows_journal_replay(exc, normalized):
            raise
        replay = _journaled_existing_assignment_after_claim_rejection(
            normalized, registry_binding
        )
        if replay is None:
            raise
        intent_payload, registry_binding, normalized, cached_coordination = replay
        request_sha256 = _sha256(normalized)
        intent, existing = _validate_intent_result(intent_payload, normalized)
    if normalized["task_id"] is None and not existing:
        selected_request = {**normalized, "task_id": intent["task_id"]}
        selected_closeout_latch = _bound_bureau_call(
            registry_binding,
            lambda: _machine_completion_closeout_latch(selected_request),
        )
        if selected_closeout_latch is not None:
            return _closeout_latched_response(
                selected_request,
                registry_binding,
                request_sha256,
                selected_closeout_latch,
            )
    acquisition_groups = (
        None if existing else _preflight_acquisition_groups(intent, normalized)
    )
    run_dir = _run_directory(intent["run_id"])
    if existing:
        stored_request_payload = _read_bound_json(
            run_dir / "request.json", label="request"
        )
        stored_request_payload = dict(stored_request_payload)
        stored_binding_sha256 = _normalize_registry_binding_marker(
            stored_request_payload.pop("registry_binding_sha256", None)
        )
        if "coordination_root" not in stored_request_payload:
            if Path(normalized["coordination_root"]) != _legacy_coordination_root():
                raise BureauPickupError(
                    "legacy-assignment-retry-requires-status",
                    details={"run_id": intent["run_id"]},
                )
            stored_request_payload = {
                **stored_request_payload,
                "coordination_root": normalized["coordination_root"],
            }
        stored_request = _normalize_request(
            stored_request_payload, allow_internal_bindings=True
        )
        stored_registry_binding = _read_journal_registry_binding(
            run_dir,
            stored_request["registry_root"],
            expected_sha256=stored_binding_sha256,
        )
        if registry_binding["explicit"]:
            if stored_registry_binding["identity"] != registry_binding["identity"]:
                raise BureauPickupError(
                    "existing-assignment-registry-binding-mismatch"
                )
        else:
            registry_binding = stored_registry_binding
            normalized = {
                **normalized,
                "registry_root": stored_request["registry_root"],
            }
            request_sha256 = _sha256(normalized)
        if stored_request != normalized:
            raise BureauPickupError("existing-assignment-request-mismatch")
        stored_intent = _read_bound_json(run_dir / "intent.json", label="intent")
        if stored_intent.get("intent_sha256") != intent["intent_sha256"]:
            raise BureauPickupError("existing-assignment-intent-mismatch")
        acquisition = _read_bound_json(
            run_dir / "acquisition.json", label="acquisition"
        )
        _validate_acquisition(acquisition)
        if acquisition.get("claim_intent_sha256") != intent["intent_sha256"]:
            raise BureauPickupError("existing-assignment-acquisition-mismatch")
        repair_obligation = _read_existing_assignment_lease_repair_obligation(
            run_dir, intent, normalized, acquisition
        )
        if repair_obligation is not None:
            receipt, journal_identity, external = repair_obligation
            activity_id = _lease_repair_activity_id(receipt["receipt_sha256"])
            coordination = _read_lease_repair_activity_status(
                intent, normalized, registry_binding, activity_id
            )
            coordination = _validate_lease_repair_activity_status(
                coordination,
                intent,
                acquisition,
                journal_identity,
                external,
                activity_id,
                action="resume-existing-assignment-after-lease-repair",
            )
        else:
            coordination = cached_coordination
            if coordination is None:
                coordination = _bound_bureau_call(
                    registry_binding,
                    lambda: _coordination_status(
                        intent["run_id"],
                        registry_root=normalized["registry_root"],
                        coordination_root=normalized["coordination_root"],
                    ),
                )
            try:
                _validate_claim_readback(coordination, intent, acquisition)
            except BureauPickupError as exc:
                if exc.code != "claim-readback-blocking-or-incomplete":
                    raise
                repaired = _repair_existing_assignment_lease_binding(
                    coordination,
                    intent,
                    normalized,
                    acquisition,
                    run_dir,
                    registry_binding,
                )
                if not repaired:
                    raise
                coordination = repaired
                _validate_claim_readback(coordination, intent, acquisition)
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup",
            "status": intent_payload["status"],
            "request_sha256": request_sha256,
            "registry_binding_sha256": registry_binding["identity"]["binding_sha256"],
            "registry_binding_kind": registry_binding["identity"]["kind"],
            "registry_binding_source": (
                "legacy-journal-explicit-registry-root"
                if registry_binding["legacy"]
                else "journal-bound"
            ),
            "run_id": intent["run_id"],
            "task_id": intent["task_id"],
            "lease_owner_id": intent["lease_owner_id"],
            "resource_keys": intent["required_resource_keys"],
            "claim_intent_sha256": intent["intent_sha256"],
            "acquisition_sha256": acquisition["acquisition_sha256"],
            "commit": intent_payload,
            "recovery": coordination,
            "run_readback_sha256": _sha256(coordination),
            "journal": str(run_dir),
            "does_not_establish": [
                "ownership of an unjournaled assignment",
                "task completion",
                "automatic lease release",
            ],
        }
        bureau._audit(
            "bureau-pickup-retry",
            result,
            run_id=intent["run_id"],
            task_id=intent["task_id"],
        )
        return result
    _write_bound_json(
        run_dir / "registry-binding.json", registry_binding["identity"]
    )
    _write_bound_json(
        run_dir / "request.json",
        {
            **normalized,
            "registry_binding_sha256": registry_binding["identity"][
                "binding_sha256"
            ],
        },
    )
    _write_bound_json(run_dir / "intent-result.json", intent_payload)
    _write_bound_json(run_dir / "intent.json", intent)
    acquisition = _acquire_groups(
        intent,
        normalized,
        run_dir,
        groups=acquisition_groups,
    )
    try:
        commit = _bound_bureau_call(
            registry_binding, lambda: _commit_claim(intent, normalized, run_dir)
        )
    except Exception as exc:
        commit = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_commit_exception",
            "status": "unknown",
            "effect_started": True,
            "ambiguity": True,
            "error_type": type(exc).__name__,
            "required_readback": [
                f"bureau_run:{intent['run_id']}",
                f"grabowski_leases:{intent['lease_owner_id']}",
            ],
        }
    _write_bound_json(run_dir / "commit-result.json", commit)
    successful_commit = commit.get("status") in {
        "claimed",
        "existing-assignment",
        "existing-terminal",
    }
    if successful_commit:
        recovered = _recover_after_commit(
            intent,
            acquisition,
            run_dir,
            registry_root=normalized["registry_root"],
            coordination_root=normalized["coordination_root"],
            registry_binding=registry_binding,
        )
    elif (
        commit.get("effect_started") is False
        and commit.get("ambiguity") is not True
    ) or commit.get("status") == "explicit-registry-root-required":
        recovered = {
            "status": "commit-not-applied",
            "commit": commit,
            "compensation": _compensate_acquisitions(
                intent["lease_owner_id"], acquisition["groups"], run_dir
            ),
        }
    else:
        recovered = _recover_after_commit(
            intent,
            acquisition,
            run_dir,
            registry_root=normalized["registry_root"],
            coordination_root=normalized["coordination_root"],
            registry_binding=registry_binding,
        )
    result_status = (
        commit["status"]
        if successful_commit and recovered["status"] == "recovered"
        else recovered["status"]
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup",
        "status": result_status,
        "request_sha256": request_sha256,
        "registry_binding_sha256": registry_binding["identity"]["binding_sha256"],
        "registry_binding_kind": registry_binding["identity"]["kind"],
        "registry_binding_source": "request-bound",
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "commit": commit,
        "recovery": recovered,
        "journal": str(run_dir),
    }
    if recovered["status"] == "recovered":
        result.update(
            {
                "lease_owner_id": intent["lease_owner_id"],
                "resource_keys": intent["required_resource_keys"],
                "claim_intent_sha256": intent["intent_sha256"],
                "acquisition_sha256": acquisition["acquisition_sha256"],
                "run_readback_sha256": recovered["coordination_sha256"],
                "does_not_establish": [
                    "task completion",
                    "merge readiness",
                    "deployment authority",
                    "automatic lease release",
                ],
            }
        )
    bureau._audit(
        "bureau-pickup-execute",
        result,
        run_id=intent["run_id"],
        task_id=intent["task_id"],
    )
    if recovered["status"] == "recovered":
        return result
    code = (
        "claim-commit-not-applied"
        if recovered["status"] == "commit-not-applied"
        else "claim-commit-recovery-required"
    )
    raise BureauPickupError(code, details={"result": result})


def _install_bureau_pickup_mcp_error_boundary() -> None:
    manager = getattr(mcp, "_tool_manager", None)
    get_tool = getattr(manager, "get_tool", None)
    if not callable(get_tool):
        return
    tool = get_tool("grabowski_bureau_pickup_execute")
    original = getattr(tool, "fn", None)
    if not callable(original):
        raise RuntimeError("Bureau pickup MCP tool function is unavailable")
    if getattr(original, "_grabowski_pickup_error_boundary", False):
        return

    def bounded(request: BureauPickupRequest) -> dict[str, Any]:
        try:
            return original(request)
        except BureauPickupError as exc:
            raise RuntimeError(
                _bureau_pickup_error_message(exc.code, exc.details, str(exc))
            ) from exc

    bounded._grabowski_pickup_error_boundary = True  # type: ignore[attr-defined]
    tool.fn = bounded


_install_bureau_pickup_mcp_error_boundary()


def _journal_available(run_id: str) -> bool:
    try:
        _path, descriptor = _open_run_directory(run_id, create=False)
    except BureauPickupError as exc:
        if exc.code in {
            "pickup-root-directory-missing",
            "pickup-runs-directory-missing",
            "pickup-run-directory-missing",
        }:
            return False
        raise
    os.close(descriptor)
    return True


def _current_root_binding(
    registry_binding: dict[str, Any], *, source: str
) -> dict[str, Any]:
    default_registry = registry_binding["identity"]["registry_root"]
    default_coordination = _normalize_coordination_root(
        str(_default_coordination_root()), registry_root=default_registry
    )
    legacy_fallback_allowed = Path(default_coordination) != _legacy_coordination_root()
    return {
        "registry_root": default_registry,
        "registry_binding": registry_binding,
        "coordination_root": default_coordination,
        "source": (
            source
            if legacy_fallback_allowed
            else source.removesuffix("-with-legacy-fallback")
        ),
        "legacy_fallback_allowed": legacy_fallback_allowed,
    }


def _root_binding_for_run(run_id: str) -> dict[str, Any]:
    if not _journal_available(run_id):
        return _current_root_binding(
            _canonical_registry_binding(),
            source="current-canonical-with-legacy-fallback",
        )
    run_dir = STATE_ROOT / "runs" / run_id
    try:
        stored = _read_bound_json(run_dir / "request.json", label="request")
    except BureauPickupError as exc:
        if exc.code != "request-missing":
            raise
        legacy_registry = _normalize_registry_root(str(bureau.BUREAU_ROOT))
        return _current_root_binding(
            _explicit_registry_binding(legacy_registry),
            source="legacy-missing-request-with-legacy-fallback",
        )
    stored_binding_sha256 = _normalize_registry_binding_marker(
        stored.get("registry_binding_sha256")
    )
    legacy_registry = _normalize_registry_root(str(bureau.BUREAU_ROOT))
    registry_root = _normalize_registry_root(
        stored.get("registry_root", legacy_registry)
    )
    registry_binding = _read_journal_registry_binding(
        run_dir, registry_root, expected_sha256=stored_binding_sha256
    )
    if "coordination_root" not in stored:
        return {
            "registry_root": registry_root,
            "registry_binding": registry_binding,
            "coordination_root": None,
            "source": "legacy-journal-implicit-state",
            "legacy_fallback_allowed": False,
        }
    coordination_root = _normalize_coordination_root(
        stored["coordination_root"],
        registry_root=registry_root,
        require_current_binding=False,
    )
    return {
        "registry_root": registry_root,
        "registry_binding": registry_binding,
        "coordination_root": coordination_root,
        "source": (
            "legacy-journal-explicit-registry-root"
            if registry_binding["legacy"]
            else "journal-bound"
        ),
        "legacy_fallback_allowed": False,
    }


def _coordination_status_for_binding(
    run_id: str, binding: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _bound_bureau_call(
        binding["registry_binding"],
        lambda: _coordination_status(
            run_id,
            registry_root=binding["registry_root"],
            coordination_root=binding["coordination_root"],
        ),
    )
    if not binding["legacy_fallback_allowed"] or not _definitive_missing_run(payload):
        return payload, binding
    legacy_payload = _bound_bureau_call(
        binding["registry_binding"],
        lambda: _coordination_status(
            run_id,
            registry_root=binding["registry_root"],
            coordination_root=None,
        ),
    )
    if _definitive_missing_run(legacy_payload):
        return payload, binding
    return legacy_payload, {
        **binding,
        "coordination_root": None,
        "source": "legacy-implicit-fallback",
        "legacy_fallback_allowed": False,
    }


@mcp.tool(name="grabowski_bureau_pickup_status", annotations=READ_ONLY)
def grabowski_bureau_pickup_status(run_id: str) -> dict[str, Any]:
    """Read one coordinated Bureau run and its owner-bound lease state."""
    normalized_run_id = _text(run_id, label="run_id", maximum=128)
    if RUN_ID_RE.fullmatch(normalized_run_id) is None:
        raise ValueError("run_id is invalid")
    binding = _root_binding_for_run(normalized_run_id)
    payload, effective_binding = _coordination_status_for_binding(
        normalized_run_id, binding
    )
    run = payload.get("run") if isinstance(payload, dict) else None
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_status",
        "run_id": normalized_run_id,
        "registry_root": effective_binding["registry_root"],
        "coordination_root": effective_binding["coordination_root"],
        "root_binding_source": effective_binding["source"],
        "registry_binding_sha256": effective_binding["registry_binding"]["identity"][
            "binding_sha256"
        ],
        "coordination": payload,
        "coordination_sha256": _coordination_cas_sha256(payload),
        "execution_binding": _classify_execution_binding(run),
        "journal_available": _journal_available(normalized_run_id),
    }



def _validate_acquisition(acquisition: dict[str, Any]) -> None:
    claimed = acquisition.get("acquisition_sha256")
    if not isinstance(claimed, str) or SHA256_RE.fullmatch(claimed) is None:
        raise BureauPickupError("acquisition-digest-invalid")
    payload = dict(acquisition)
    payload.pop("acquisition_sha256", None)
    if _sha256(payload) != claimed:
        raise BureauPickupError("acquisition-digest-mismatch")
    contract_version = acquisition.get("resource_lease_contract_version")
    if (
        contract_version is not None
        and contract_version != resources.RESOURCE_LEASE_CONTRACT_CURRENT_VERSION
    ):
        raise BureauPickupError("acquisition-resource-lease-contract-unsupported")
    keys = acquisition.get("resource_keys")
    if not isinstance(keys, list) or keys != sorted(set(keys)):
        raise BureauPickupError("acquisition-resource-set-invalid")
    if acquisition.get("owner_id") != f"bureau-run:{acquisition.get('run_id')}":
        raise BureauPickupError("acquisition-owner-invalid")


def _verify_release_binding(
    run_id: str, status: dict[str, Any], acquisition: dict[str, Any]
) -> tuple[str, list[str], list[str]]:
    if status.get("status") != "coordinated":
        raise BureauPickupError("terminal-readback-unavailable")
    run = status.get("run")
    if not isinstance(run, dict) or run.get("run_id") != run_id:
        raise BureauPickupError("terminal-run-binding-invalid")
    run_state = run.get("state")
    if run_state in ACTIVE_EXECUTION_STATES:
        raise BureauPickupError("run-still-active", details={"state": run_state})
    if not _run_is_terminal(run):
        raise BureauPickupError("run-not-terminal", details={"state": run_state})
    release = status.get("release")
    if not isinstance(release, dict) or release.get("required") is not True:
        raise BureauPickupError("lease-release-not-required")
    owner_id = release.get("owner_id")
    keys = release.get("resource_keys")
    if owner_id != acquisition.get("owner_id"):
        raise BureauPickupError("lease-release-owner-mismatch")
    if keys != acquisition.get("resource_keys"):
        raise BureauPickupError("lease-release-resource-mismatch")
    if release.get("claim_intent_sha256") != acquisition.get("claim_intent_sha256"):
        raise BureauPickupError("lease-release-intent-mismatch")
    if not isinstance(keys, list):
        raise BureauPickupError("lease-release-resource-set-invalid")
    expected_by_key = {
        lease["resource_key"]: lease
        for lease in acquisition.get("leases", [])
        if isinstance(lease, dict) and isinstance(lease.get("resource_key"), str)
    }
    release_keys: list[str] = []
    preserved_keys: list[str] = []
    for key in keys:
        expected = expected_by_key.get(key)
        if expected is None:
            raise BureauPickupError("lease-release-snapshot-missing")
        observed = resources.inspect_resource(key)
        if observed is None:
            preserved_keys.append(key)
            continue
        if observed.get("owner_id") != owner_id:
            if _foreign_lease_is_strict_successor(expected, observed):
                preserved_keys.append(key)
                continue
            raise BureauPickupError(
                "lease-release-foreign-owner", details={"resource_key": key}
            )
        if not _owner_lease_matches_terminal_lineage(expected, observed):
            raise BureauPickupError(
                "lease-release-metadata-drift", details={"resource_key": key}
            )
        release_keys.append(key)
    return owner_id, release_keys, preserved_keys


def _terminal_release_lease_projection(value: Any, resource_keys: Any) -> Any:
    if not isinstance(value, dict):
        return value
    status = value.get("status")
    error = value.get("error")
    expected_keys = (
        {key for key in resource_keys if isinstance(key, str)}
        if isinstance(resource_keys, list)
        else set()
    )
    if status == "terminal-released-or-expired" and isinstance(error, dict):
        code = error.get("code")
        details = error.get("details")
        if code == "lease-expired" and isinstance(details, dict):
            resource_key = details.get("resource_key")
            expires_at = details.get("expires_at_unix")
            if (
                resource_key in expected_keys
                and isinstance(expires_at, int)
                and not isinstance(expires_at, bool)
            ):
                return {
                    "status": status,
                    "terminal_owner_lease_state": "unavailable",
                }
        if code == "lease-resources-missing" and isinstance(details, dict):
            missing = details.get("missing")
            if (
                isinstance(missing, list)
                and missing
                and all(isinstance(key, str) for key in missing)
                and len(missing) == len(set(missing))
                and set(missing).issubset(expected_keys)
            ):
                return {
                    "status": status,
                    "terminal_owner_lease_state": "unavailable",
                }
    if not isinstance(error, dict):
        stable_error = error
    else:
        details = error.get("details")
        stable_details = (
            {key: item for key, item in details.items() if key != "required_after_unix"}
            if isinstance(details, dict)
            else details
        )
        stable_error = {
            "code": error.get("code"),
            "message": error.get("message"),
            "details": stable_details,
        }
    return {"status": status, "error": stable_error}


def _terminal_release_readback_projection(status: dict[str, Any]) -> dict[str, Any]:
    release = status.get("release")
    resource_keys = release.get("resource_keys") if isinstance(release, dict) else None
    return {
        "status": status.get("status"),
        "blocking": status.get("blocking"),
        "claim_intent_sha256": status.get("claim_intent_sha256"),
        "run": status.get("run"),
        "release": release,
        "stored_lease_binding": status.get("stored_lease_binding"),
        "lease": _terminal_release_lease_projection(status.get("lease"), resource_keys),
    }


def _coordination_cas_sha256(status: dict[str, Any]) -> str:
    """Hash coordination semantics while excluding observation-only lease fields."""
    return _sha256(_terminal_release_readback_projection(status))


def _write_or_reuse_terminal_readback(
    path: Path, current: dict[str, Any]
) -> dict[str, Any]:
    try:
        existing = _read_bound_json(path, label="terminal-readback")
    except BureauPickupError as exc:
        if exc.code != "terminal-readback-missing":
            raise
        _write_bound_json(path, current)
        return current
    if _terminal_release_readback_projection(
        existing
    ) != _terminal_release_readback_projection(current):
        raise BureauPickupError(
            "terminal-readback-drift", details={"path": str(path)}
        )
    return existing


@mcp.tool(name="grabowski_bureau_pickup_release", annotations=MUTATING)
def grabowski_bureau_pickup_release(run_id: str) -> dict[str, Any]:
    """Release exactly one terminal coordinated run's unchanged Grabowski leases."""
    normalized_run_id = _text(run_id, label="run_id", maximum=128)
    binding = _root_binding_for_run(normalized_run_id)
    registry_root = binding["registry_root"]
    operator._require_operator_mutation(
        "terminal_execute", path=registry_root
    )
    coordination_effect_root = (
        Path(binding["coordination_root"])
        if binding["coordination_root"] is not None
        else _legacy_coordination_root()
    )
    operator._require_operator_mutation(
        "terminal_execute", path=str(coordination_effect_root)
    )
    operator._require_operator_mutation("resource_lease")
    run_dir = _run_directory(normalized_run_id)
    acquisition = _read_bound_json(run_dir / "acquisition.json", label="acquisition")
    _validate_acquisition(acquisition)
    existing_release_path = run_dir / "release-result.json"
    if existing_release_path.is_file() and not existing_release_path.is_symlink():
        remaining_existing: dict[str, dict[str, Any]] = {}
        for key in acquisition["resource_keys"]:
            observed = resources.inspect_resource(key)
            if (
                observed is not None
                and observed.get("owner_id") == acquisition["owner_id"]
            ):
                remaining_existing[key] = observed
        if not remaining_existing:
            saved_release = _read_bound_json(
                existing_release_path, label="release-result"
            )
            preserved_keys = saved_release.get("preserved_resource_keys", [])
            released_keys = saved_release.get("released_resource_keys", [])
            if not isinstance(preserved_keys, list) or not all(
                isinstance(key, str) for key in preserved_keys
            ):
                raise BureauPickupError("lease-release-result-invalid")
            if not isinstance(released_keys, list) or not all(
                isinstance(key, str) for key in released_keys
            ):
                raise BureauPickupError("lease-release-result-invalid")
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_release",
                "status": "already-released",
                "run_id": normalized_run_id,
                "registry_root": binding["registry_root"],
                "coordination_root": binding["coordination_root"],
                "root_binding_source": binding["source"],
                "registry_binding_sha256": binding["registry_binding"]["identity"][
                    "binding_sha256"
                ],
                "owner_id": acquisition["owner_id"],
                "resource_keys": acquisition["resource_keys"],
                "released_resource_keys": released_keys,
                "preserved_resource_keys": preserved_keys,
                "release": saved_release,
                "journal": str(run_dir),
            }
    status, effective_binding = _coordination_status_for_binding(
        normalized_run_id, binding
    )
    owner_id, keys, preserved_keys = _verify_release_binding(
        normalized_run_id, status, acquisition
    )
    terminal_readback = _write_or_reuse_terminal_readback(
        run_dir / "terminal-readback.json", status
    )
    if keys:
        result = {
            **resources.release_resources(owner_id, keys),
            "released_resource_keys": keys,
            "preserved_resource_keys": preserved_keys,
        }
    else:
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "no-op",
            "owner_id": owner_id,
            "released": [],
            "released_resource_keys": [],
            "preserved_resource_keys": preserved_keys,
        }
    _write_bound_json(run_dir / "release-result.json", result)
    remaining: dict[str, dict[str, Any]] = {}
    for key in keys:
        observed = resources.inspect_resource(key)
        if observed is not None and observed.get("owner_id") == owner_id:
            remaining[key] = observed
    if remaining:
        raise BureauPickupError(
            "lease-release-incomplete", details={"resource_keys": sorted(remaining)}
        )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_release",
        "status": "released",
        "run_id": normalized_run_id,
        "registry_root": effective_binding["registry_root"],
        "coordination_root": effective_binding["coordination_root"],
        "root_binding_source": effective_binding["source"],
        "registry_binding_sha256": effective_binding["registry_binding"][
            "identity"
        ]["binding_sha256"],
        "owner_id": owner_id,
        "resource_keys": acquisition["resource_keys"],
        "released_resource_keys": keys,
        "preserved_resource_keys": preserved_keys,
        "release": result,
        "terminal_readback_sha256": _sha256(terminal_readback),
        "journal": str(run_dir),
        "does_not_establish": [
            "workspace cleanup authority",
            "foreign lease release authority",
            "task verification",
        ],
    }
    bureau._audit(
        "bureau-pickup-release", payload, run_id=normalized_run_id
    )
    return payload

def _normalize_sha256_digest(value: Any, *, label: str) -> str:
    digest = _text(value, label=label, maximum=64)
    if SHA256_RE.fullmatch(digest) is None:
        raise ValueError(f"{label} is invalid")
    return digest

def _normalize_orphan_reconcile_request(
    request: dict[str, Any],
) -> dict[str, str]:
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    allowed = {
        "run_id",
        "expected_registry_binding_sha256",
        "expected_coordination_sha256",
        "expected_lease_sha256",
    }
    extra = sorted(set(request) - allowed)
    if extra:
        raise ValueError(f"unsupported request fields: {extra}")
    run_id = _text(request.get("run_id"), label="run_id", maximum=128)
    if RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError("run_id is invalid")
    return {
        "run_id": run_id,
        "expected_registry_binding_sha256": _normalize_sha256_digest(
            request.get("expected_registry_binding_sha256"),
            label="expected_registry_binding_sha256",
        ),
        "expected_coordination_sha256": _normalize_sha256_digest(
            request.get("expected_coordination_sha256"),
            label="expected_coordination_sha256",
        ),
        "expected_lease_sha256": _normalize_sha256_digest(
            request.get("expected_lease_sha256"),
            label="expected_lease_sha256",
        ),
    }

def _fail_bureau_run(
    run_id: str,
    *,
    registry_root: str,
    coordination_root: str | None,
    error: str,
) -> dict[str, Any]:
    arguments = _bureau_arguments(
        "fail",
        registry_root=registry_root,
        coordination_root=coordination_root,
    )
    arguments.extend([run_id, "--error", error])
    return bureau._invoke_bureau(
        arguments,
        mutation=True,
        required_readback=[f"bureau_run:{run_id}"],
    )

def _adapter_outcome_unknown(payload: dict[str, Any], *, run_id: str) -> bool:
    if payload.get("kind") != "grabowski_bureau_intake_adapter_failure":
        return False
    if payload.get("ambiguity") is True or payload.get("effect_started") is True:
        return True
    return payload.get("code") in {
        "bureau-runtime-timeout",
        "bureau-output-invalid",
        "bureau-output-too-large",
        "bureau-runtime-unavailable",
    }

def _run_is_terminal(run: Any) -> bool:
    if not isinstance(run, dict):
        return False
    state = run.get("state")
    return isinstance(state, str) and state in TERMINAL_EXECUTION_STATES

def _read_orphan_pre_effect_coordination_digest(run_dir: Path) -> str | None:
    path = run_dir / "orphan-pre-effect.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        payload = _read_bound_json(path, label="orphan-pre-effect")
    except BureauPickupError:
        return None
    digest = payload.get("observed_coordination_sha256")
    if isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None:
        return digest
    return None

def _write_orphan_pre_effect(
    run_dir: Path,
    *,
    run_id: str,
    observed_coordination_sha256: str,
    normalized: dict[str, str],
) -> None:
    _write_bound_json(
        run_dir / "orphan-pre-effect.json",
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_orphan_pre_effect",
            "run_id": run_id,
            "observed_coordination_sha256": observed_coordination_sha256,
            "expected_coordination_sha256": normalized["expected_coordination_sha256"],
            "expected_registry_binding_sha256": normalized[
                "expected_registry_binding_sha256"
            ],
            "expected_lease_sha256": normalized["expected_lease_sha256"],
        },
    )

def _assert_owner_leases_same_lineage_or_absent(
    acquisition: dict[str, Any],
) -> None:
    owner_id = acquisition["owner_id"]
    expected_by_key = {
        lease["resource_key"]: lease
        for lease in acquisition.get("leases", [])
        if isinstance(lease, dict) and isinstance(lease.get("resource_key"), str)
    }
    for key in acquisition["resource_keys"]:
        expected = expected_by_key.get(key)
        if expected is None:
            raise BureauPickupError(
                "orphan-reconcile-lease-snapshot-missing",
                details={"resource_key": key},
            )
        observed = resources.inspect_resource(key)
        if observed is None:
            continue
        if observed.get("owner_id") != owner_id:
            if _foreign_lease_is_strict_successor(expected, observed):
                continue
            raise BureauPickupError(
                "orphan-reconcile-foreign-lease",
                details={
                    "resource_key": key,
                    "owner_id": observed.get("owner_id"),
                    "expected_owner_id": owner_id,
                    "lineage_proof": "not-strictly-after-historical-expiry",
                    "does_not_establish": _execution_binding_does_not_establish(),
                },
            )
        if not _owner_lease_matches_terminal_lineage(expected, observed):
            raise BureauPickupError(
                "orphan-reconcile-lease-metadata-drift",
                details={"resource_key": key},
            )

def grabowski_bureau_pickup_orphan_reconcile(
    request: BureauPickupOrphanReconcileRequest,
) -> dict[str, Any]:
    """Terminalize exactly one unbound coordinated run and release its owner leases."""
    normalized = _normalize_orphan_reconcile_request(request)
    run_id = normalized["run_id"]
    binding = _root_binding_for_run(run_id)
    registry_root = binding["registry_root"]
    mutation_registry_root = bureau._prepare_registry_root(
        str(bureau.BUREAU_ROOT), refresh=True, mutation=True
    )
    coordination_effect_root = (
        Path(binding["coordination_root"])
        if binding["coordination_root"] is not None
        else _legacy_coordination_root()
    )
    operator._require_operator_mutation(
        "terminal_execute", path=str(coordination_effect_root)
    )
    operator._require_operator_mutation("resource_lease")

    observed_registry_sha256 = binding["registry_binding"]["identity"]["binding_sha256"]
    if observed_registry_sha256 != normalized["expected_registry_binding_sha256"]:
        raise BureauPickupError(
            "orphan-reconcile-registry-digest-mismatch",
            details={
                "run_id": run_id,
                "expected": normalized["expected_registry_binding_sha256"],
                "observed": observed_registry_sha256,
                "effect_started": False,
                "does_not_establish": _execution_binding_does_not_establish(),
            },
        )

    run_dir = _run_directory(run_id)
    acquisition = _read_bound_json(run_dir / "acquisition.json", label="acquisition")
    _validate_acquisition(acquisition)
    if acquisition.get("acquisition_sha256") != normalized["expected_lease_sha256"]:
        raise BureauPickupError(
            "orphan-reconcile-lease-digest-mismatch",
            details={
                "run_id": run_id,
                "expected": normalized["expected_lease_sha256"],
                "observed": acquisition.get("acquisition_sha256"),
                "effect_started": False,
                "does_not_establish": _execution_binding_does_not_establish(),
            },
        )

    receipt_path = run_dir / "orphan-reconcile.json"
    if receipt_path.is_file() and not receipt_path.is_symlink():
        existing_receipt = _read_bound_json(receipt_path, label="orphan-reconcile")
        if (
            existing_receipt.get("expected_registry_binding_sha256")
            == normalized["expected_registry_binding_sha256"]
            and existing_receipt.get("expected_coordination_sha256")
            == normalized["expected_coordination_sha256"]
            and existing_receipt.get("expected_lease_sha256")
            == normalized["expected_lease_sha256"]
            and existing_receipt.get("run_id") == run_id
            and existing_receipt.get("status") in {"reconciled", "already-reconciled"}
        ):
            payload = {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_orphan_reconcile",
                "status": "already-reconciled",
                "run_id": run_id,
                "registry_root": registry_root,
                "coordination_root": binding["coordination_root"],
                "root_binding_source": binding["source"],
                "registry_binding_sha256": observed_registry_sha256,
                "expected_registry_binding_sha256": normalized[
                    "expected_registry_binding_sha256"
                ],
                "expected_coordination_sha256": normalized[
                    "expected_coordination_sha256"
                ],
                "expected_lease_sha256": normalized["expected_lease_sha256"],
                "receipt": existing_receipt,
                "journal": str(run_dir),
                "effect_started": False,
                "does_not_establish": _execution_binding_does_not_establish(),
            }
            return payload

    status, effective_binding = _coordination_status_for_binding(run_id, binding)
    if not isinstance(status, dict):
        raise BureauPickupError(
            "orphan-reconcile-status-invalid",
            details={"run_id": run_id, "effect_started": False},
        )
    if status.get("kind") == "grabowski_bureau_intake_adapter_failure":
        if _adapter_outcome_unknown(status, run_id=run_id):
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_orphan_reconcile",
                "status": "outcome_unknown",
                "run_id": run_id,
                "required_readback": [f"bureau_run:{run_id}"],
                "readback_required": True,
                "coordination": status,
                "effect_started": bool(status.get("effect_started")),
                "does_not_establish": _execution_binding_does_not_establish(),
            }
        raise BureauPickupError(
            "orphan-reconcile-status-unavailable",
            details={
                "run_id": run_id,
                "coordination": status,
                "effect_started": False,
            },
        )

    observed_coordination_sha256 = _coordination_cas_sha256(status)
    run = status.get("run")
    execution_binding = _classify_execution_binding(run)
    already_terminal = _run_is_terminal(run)

    if not already_terminal:
        if observed_coordination_sha256 != normalized["expected_coordination_sha256"]:
            raise BureauPickupError(
                "orphan-reconcile-coordination-digest-mismatch",
                details={
                    "run_id": run_id,
                    "expected": normalized["expected_coordination_sha256"],
                    "observed": observed_coordination_sha256,
                    "effect_started": False,
                    "execution_binding": execution_binding,
                    "does_not_establish": _execution_binding_does_not_establish(),
                },
            )
        if execution_binding["classification"] == "attention_required":
            raise BureauPickupError(
                "orphan-reconcile-execution-attention-required",
                details={
                    "run_id": run_id,
                    "execution_binding": execution_binding,
                    "effect_started": False,
                    "does_not_establish": _execution_binding_does_not_establish(),
                },
            )
        if execution_binding["actively_bound"]:
            raise BureauPickupError(
                "orphan-reconcile-execution-actively-bound",
                details={
                    "run_id": run_id,
                    "execution_binding": execution_binding,
                    "effect_started": False,
                    "does_not_establish": _execution_binding_does_not_establish(),
                },
            )
        if status.get("status") != "coordinated":
            raise BureauPickupError(
                "orphan-reconcile-not-coordinated",
                details={
                    "run_id": run_id,
                    "status": status.get("status"),
                    "effect_started": False,
                },
            )
        _assert_owner_leases_same_lineage_or_absent(acquisition)
        # Persist pre-effect digest before any fail mutation for later terminal CAS.
        _write_orphan_pre_effect(
            run_dir,
            run_id=run_id,
            observed_coordination_sha256=observed_coordination_sha256,
            normalized=normalized,
        )
        fail_result = _bound_bureau_call(
            effective_binding["registry_binding"],
            lambda: _fail_bureau_run(
                run_id,
                registry_root=mutation_registry_root,
                coordination_root=effective_binding["coordination_root"],
                error=ORPHAN_RECONCILE_ERROR,
            ),
        )
        if not isinstance(fail_result, dict):
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_orphan_reconcile",
                "status": "outcome_unknown",
                "run_id": run_id,
                "required_readback": [f"bureau_run:{run_id}"],
                "readback_required": True,
                "effect_started": True,
                "does_not_establish": _execution_binding_does_not_establish(),
            }
        if _adapter_outcome_unknown(fail_result, run_id=run_id):
            _write_bound_json(run_dir / "orphan-fail-unknown.json", fail_result)
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_orphan_reconcile",
                "status": "outcome_unknown",
                "run_id": run_id,
                "required_readback": sorted(
                    set(fail_result.get("required_readback") or [])
                    | {f"bureau_run:{run_id}"}
                ),
                "readback_required": True,
                "fail": fail_result,
                "effect_started": True,
                "does_not_establish": _execution_binding_does_not_establish(),
            }
        if not (fail_result.get("run_id") == run_id and _run_is_terminal(fail_result)):
            # Authoritative fail must yield an explicit terminal state.
            _write_bound_json(run_dir / "orphan-fail-unknown.json", fail_result)
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_orphan_reconcile",
                "status": "outcome_unknown",
                "run_id": run_id,
                "required_readback": [f"bureau_run:{run_id}"],
                "readback_required": True,
                "fail": fail_result,
                "effect_started": True,
                "does_not_establish": _execution_binding_does_not_establish(),
            }
        _write_bound_json(run_dir / "orphan-fail-result.json", fail_result)
        status, effective_binding = _coordination_status_for_binding(
            run_id, effective_binding
        )
        run = status.get("run") if isinstance(status, dict) else None
        execution_binding = _classify_execution_binding(run)
        if not _run_is_terminal(run):
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_orphan_reconcile",
                "status": "outcome_unknown",
                "run_id": run_id,
                "required_readback": [f"bureau_run:{run_id}"],
                "readback_required": True,
                "coordination": status,
                "execution_binding": execution_binding,
                "effect_started": True,
                "does_not_establish": _execution_binding_does_not_establish(),
            }
    else:
        # Already terminal: bind expected digest to current terminal or journaled pre-effect.
        if status.get("status") != "coordinated":
            raise BureauPickupError(
                "orphan-reconcile-not-coordinated",
                details={
                    "run_id": run_id,
                    "status": status.get("status"),
                    "effect_started": False,
                },
            )
        allowed_coordination_digests = {observed_coordination_sha256}
        pre_effect_digest = _read_orphan_pre_effect_coordination_digest(run_dir)
        if pre_effect_digest is not None:
            allowed_coordination_digests.add(pre_effect_digest)
        if (
            normalized["expected_coordination_sha256"]
            not in allowed_coordination_digests
        ):
            raise BureauPickupError(
                "orphan-reconcile-coordination-digest-mismatch",
                details={
                    "run_id": run_id,
                    "expected": normalized["expected_coordination_sha256"],
                    "observed": observed_coordination_sha256,
                    "allowed": sorted(allowed_coordination_digests),
                    "effect_started": False,
                    "execution_binding": execution_binding,
                    "does_not_establish": _execution_binding_does_not_establish(),
                },
            )
        _assert_owner_leases_same_lineage_or_absent(acquisition)

    if not isinstance(status, dict) or status.get("status") != "coordinated":
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_orphan_reconcile",
            "status": "outcome_unknown",
            "run_id": run_id,
            "required_readback": [f"bureau_run:{run_id}"],
            "readback_required": True,
            "coordination": status,
            "effect_started": True,
            "does_not_establish": _execution_binding_does_not_establish(),
        }

    terminal_readback = _write_or_reuse_terminal_readback(
        run_dir / "terminal-readback.json", status
    )
    release_result = grabowski_bureau_pickup_release(run_id)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_orphan_reconcile_receipt",
        "status": "reconciled",
        "run_id": run_id,
        "expected_registry_binding_sha256": normalized[
            "expected_registry_binding_sha256"
        ],
        "expected_coordination_sha256": normalized["expected_coordination_sha256"],
        "expected_lease_sha256": normalized["expected_lease_sha256"],
        "observed_coordination_sha256": observed_coordination_sha256,
        "terminal_readback_sha256": _sha256(terminal_readback),
        "release_status": release_result.get("status"),
        "preserved_resource_keys": release_result.get(
            "preserved_resource_keys", []
        ),
        "execution_binding": execution_binding,
        "preserves": [
            "dirty worktree content",
            "branch identity",
            "unrelated leases",
        ],
        "does_not_establish": _execution_binding_does_not_establish(),
    }
    receipt["receipt_sha256"] = _sha256(receipt)
    _write_bound_json(receipt_path, receipt)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_orphan_reconcile",
        "status": "reconciled",
        "run_id": run_id,
        "registry_root": effective_binding["registry_root"],
        "coordination_root": effective_binding["coordination_root"],
        "root_binding_source": effective_binding["source"],
        "registry_binding_sha256": effective_binding["registry_binding"]["identity"][
            "binding_sha256"
        ],
        "expected_registry_binding_sha256": normalized[
            "expected_registry_binding_sha256"
        ],
        "expected_coordination_sha256": normalized["expected_coordination_sha256"],
        "expected_lease_sha256": normalized["expected_lease_sha256"],
        "execution_binding": execution_binding,
        "terminal_readback_sha256": receipt["terminal_readback_sha256"],
        "release": release_result,
        "receipt": receipt,
        "journal": str(run_dir),
        "effect_started": True,
        "does_not_establish": _execution_binding_does_not_establish(),
    }
    bureau._audit("bureau-pickup-orphan-reconcile", payload, run_id=run_id)
    return payload
