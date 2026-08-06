from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

try:
    from typing_extensions import TypedDict
except ModuleNotFoundError:
    from typing import TypedDict

import grabowski_bureau_intake as bureau
import grabowski_bureau_leases as bureau_leases
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
    task_id: str


class BureauPickupRequest(_RequiredBureauPickupRequest, total=False):
    __pydantic_config__ = {"extra": "forbid", "strict": True}

    resource: str | None
    kind: str
    base_dir: str | None
    approval_source: str
    lease_ttl_seconds: int
    create_workspace: bool
    repository_scope_manifests: dict[str, dict[str, Any]] | None
    nonconflict_proofs: dict[str, dict[str, Any]] | None
    registry_root: str


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
    if (
        _file_snapshot_identity(before) != _file_snapshot_identity(after)
        or _file_snapshot_identity(after) != _file_snapshot_identity(linked_after)
    ):
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
    if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
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
    if TASK_ID_RE.fullmatch(task_id) is None:
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
        if not isinstance(identifier, str) or not identifier or identifier in acceptance_ids:
            return None
        normalized_identifier = re.sub(
            r"[^a-z0-9]+", "_", identifier.lower()
        ).strip("_")
        if not normalized_identifier or normalized_identifier in normalized_acceptance_ids:
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
        if field in {"merge_commit", "runtime_head", "source_commit"} and re.fullmatch(
            r"[0-9a-f]{40}", value
        ) is None:
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
    task_id = _text(request.get("task_id"), label="task_id", maximum=200)
    kind = _text(
        request.get("kind", "interactive-agent"), label="kind", maximum=128
    )
    approval_source = _text(
        request.get("approval_source", "grabowski_bureau_pickup_execute"),
        label="approval_source",
        maximum=512,
    )
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
    arguments.extend(["--task-id", request["task_id"]])
    for capability in request["capabilities"]:
        arguments.extend(["--capability", capability])
    if request["resource"]:
        arguments.extend(["--resource", request["resource"]])
    if request["base_dir"]:
        arguments.extend(["--base-dir", request["base_dir"]])
    arguments.extend(["--approve", "--approval-source", request["approval_source"]])
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
    if not isinstance(token, str) or re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*", token
    ) is None:
        error_code = "claim-intent-not-ready"
    else:
        candidate = token if token.startswith("claim-intent-") else f"claim-intent-{token}"
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
    if intent.get("task_id") != request["task_id"]:
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
            details={"group": group["name"], "expected": expected, "observed": sorted(observed)},
        )


def _acquire_groups(
    intent: dict[str, Any], request: dict[str, Any], run_dir: Path
) -> dict[str, Any]:
    acquired: list[dict[str, Any]] = []
    owner_id = intent["lease_owner_id"]
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
    run_id: str, *, registry_root: str, coordination_root: str | None
) -> dict[str, Any]:
    return bureau._invoke_bureau(
        [
            *_bureau_arguments(
                "claim-coordination-status",
                registry_root=registry_root,
                coordination_root=coordination_root,
            ),
            run_id,
        ]
    )


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
    return {
        key: value[key]
        for key in (
            "resource_key",
            "owner_id",
            "acquired_at_unix",
            "updated_at_unix",
            "expires_at_unix",
            "metadata_sha256",
        )
    }


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


def _journaled_existing_assignment_after_runtime_drift(
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


def _repair_existing_assignment_lease_binding(
    coordination: dict[str, Any],
    intent: dict[str, Any],
    request: dict[str, Any],
    acquisition: dict[str, Any],
    run_dir: Path,
) -> bool:
    lease_state = coordination.get("lease")
    lease_error = lease_state.get("error") if isinstance(lease_state, dict) else None
    error_code = lease_error.get("code") if isinstance(lease_error, dict) else None
    if not (
        isinstance(lease_state, dict)
        and lease_state.get("status") == "active-binding-drift"
        and error_code
        in {"lease-expired", "lease-metadata-binding-mismatch", "lease-resources-missing"}
    ):
        return False
    run = coordination.get("run")
    if not isinstance(run, dict) or run.get("state") not in {
        "assigned",
        "running",
        "verifying",
    }:
        return False
    release = coordination.get("release")
    if not isinstance(release, dict):
        return False
    expected_release = {
        "owner_id": intent["lease_owner_id"],
        "resource_keys": intent["required_resource_keys"],
        "claim_intent_sha256": intent["intent_sha256"],
    }
    if any(release.get(key) != value for key, value in expected_release.items()):
        return False
    original_by_key = {
        item["resource_key"]: item
        for item in acquisition.get("leases", [])
        if isinstance(item, dict) and isinstance(item.get("resource_key"), str)
    }
    if sorted(original_by_key) != intent["required_resource_keys"]:
        raise BureauPickupError("existing-assignment-lease-journal-incomplete")
    groups = _acquisition_groups(intent, request)
    if len(groups) != 1:
        return False
    group = groups[0]
    keys = group["resource_keys"]
    purpose = f"Bureau coordinated pickup {intent['run_id']} group {group['name']}"
    original = [original_by_key[key] for key in keys]
    if any(item.get("purpose") != purpose for item in original):
        raise BureauPickupError(
            "existing-assignment-lease-purpose-journal-mismatch",
            details={"group": group["name"]},
        )
    if error_code in {"lease-expired", "lease-resources-missing"}:
        result = resources.acquire_resources(
            intent["lease_owner_id"],
            keys,
            purpose=purpose,
            ttl_seconds=group["ttl_seconds"],
            metadata=group["metadata"],
            nonconflict_proof=group["nonconflict_proof"],
        )
        _validate_acquired_group(intent["lease_owner_id"], group, result)
        leases = result["leases"]
        if any(
            item.get("purpose") != purpose
            or item.get("metadata_sha256")
            != original_by_key[item["resource_key"]].get("metadata_sha256")
            for item in leases
        ):
            raise BureauPickupError("existing-assignment-lease-reacquire-mismatch")
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_lease_reacquire",
            "run_id": intent["run_id"],
            "task_id": intent["task_id"],
            "claim_intent_sha256": intent["intent_sha256"],
            "group": group["name"],
            "resource_keys": keys,
            "metadata_sha256": original[0]["metadata_sha256"],
        }
        receipt["receipt_sha256"] = _sha256(receipt)
        _write_bound_json(run_dir / "lease-reacquire.json", receipt)
        return True
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
        expected_original_leases=[_lease_snapshot(original_by_key[key]) for key in keys],
    )
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_lease_rebind",
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "group": group["name"],
        "resource_keys": keys,
        "metadata_sha256": result["metadata_sha256"],
    }
    receipt["receipt_sha256"] = _sha256(receipt)
    _write_bound_json(run_dir / "lease-rebind.json", receipt)
    return True


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
    intent_payload, closeout_latch = _bound_bureau_call(
        registry_binding,
        lambda: _claim_intent_or_closeout(normalized),
    )
    if closeout_latch is not None:
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_closeout_latched",
            "status": "closeout-only",
            "effect_started": False,
            "retryable": False,
            "ambiguity": False,
            "request_sha256": request_sha256,
            "registry_binding_sha256": registry_binding["identity"][
                "binding_sha256"
            ],
            "registry_binding_kind": registry_binding["identity"]["kind"],
            "task_id": normalized["task_id"],
            "latch": closeout_latch,
            "required_readback": [f"bureau_task:{normalized['task_id']}"],
        }
        bureau._audit(
            "bureau-pickup-closeout-latched",
            result,
            task_id=normalized["task_id"],
        )
        return result
    cached_coordination: dict[str, Any] | None = None
    try:
        intent, existing = _validate_intent_result(intent_payload, normalized)
    except BureauPickupError as exc:
        if exc.code not in {
            "claim-intent-runtime-drift-blocked",
            "claim-intent-stale-runtime-blocked",
        }:
            raise
        replay = _journaled_existing_assignment_after_runtime_drift(
            normalized, registry_binding
        )
        if replay is None:
            raise
        intent_payload, registry_binding, normalized, cached_coordination = replay
        request_sha256 = _sha256(normalized)
        intent, existing = _validate_intent_result(intent_payload, normalized)
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
            )
            if not repaired:
                raise
            coordination = _bound_bureau_call(
                registry_binding,
                lambda: _coordination_status(
                    intent["run_id"],
                    registry_root=normalized["registry_root"],
                    coordination_root=normalized["coordination_root"],
                ),
            )
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
    acquisition = _acquire_groups(intent, normalized, run_dir)
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
    legacy_fallback_allowed = (
        Path(default_coordination) != _legacy_coordination_root()
    )
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
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_status",
        "run_id": normalized_run_id,
        "registry_root": effective_binding["registry_root"],
        "coordination_root": effective_binding["coordination_root"],
        "root_binding_source": effective_binding["source"],
        "registry_binding_sha256": effective_binding["registry_binding"][
            "identity"
        ]["binding_sha256"],
        "coordination": payload,
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
) -> tuple[str, list[str]]:
    if status.get("status") != "coordinated":
        raise BureauPickupError("terminal-readback-unavailable")
    run = status.get("run")
    if not isinstance(run, dict) or run.get("run_id") != run_id:
        raise BureauPickupError("terminal-run-binding-invalid")
    if run.get("state") in {"assigned", "running", "verifying"}:
        raise BureauPickupError(
            "run-still-active", details={"state": run.get("state")}
        )
    release = status.get("release")
    if not isinstance(release, dict) or release.get("required") is not True:
        raise BureauPickupError("lease-release-not-required")
    owner_id = release.get("owner_id")
    keys = release.get("resource_keys")
    if owner_id != acquisition.get("owner_id"):
        raise BureauPickupError("lease-release-owner-mismatch")
    if keys != acquisition.get("resource_keys"):
        raise BureauPickupError("lease-release-resource-mismatch")
    if release.get("claim_intent_sha256") != acquisition.get(
        "claim_intent_sha256"
    ):
        raise BureauPickupError("lease-release-intent-mismatch")
    if not isinstance(keys, list):
        raise BureauPickupError("lease-release-resource-set-invalid")
    expected_by_key = {
        lease["resource_key"]: lease
        for lease in acquisition.get("leases", [])
        if isinstance(lease, dict) and isinstance(lease.get("resource_key"), str)
    }
    for key in keys:
        observed = resources.inspect_resource(key)
        if observed is None:
            continue
        expected = expected_by_key.get(key)
        if expected is None:
            raise BureauPickupError("lease-release-snapshot-missing")
        if observed.get("owner_id") != owner_id:
            raise BureauPickupError(
                "lease-release-foreign-owner", details={"resource_key": key}
            )
        if observed.get("metadata_sha256") != expected.get("metadata_sha256"):
            raise BureauPickupError(
                "lease-release-metadata-drift", details={"resource_key": key}
            )
    return owner_id, keys


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
            if observed is not None and observed.get("owner_id") == acquisition[
                "owner_id"
            ]:
                remaining_existing[key] = observed
        if not remaining_existing:
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
                "release": _read_bound_json(
                    existing_release_path, label="release-result"
                ),
                "journal": str(run_dir),
            }
    status, effective_binding = _coordination_status_for_binding(
        normalized_run_id, binding
    )
    owner_id, keys = _verify_release_binding(
        normalized_run_id, status, acquisition
    )
    terminal_readback = _write_or_reuse_terminal_readback(
        run_dir / "terminal-readback.json", status
    )
    result = resources.release_resources(owner_id, keys)
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
        "resource_keys": keys,
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
