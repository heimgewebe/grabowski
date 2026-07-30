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
MAX_REQUEST_BYTES = 1024 * 1024
MIN_LEASE_TTL_SECONDS = 120
MAX_LEASE_TTL_SECONDS = 3600


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


class BureauPickupError(RuntimeError):
    def __init__(self, code: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(code)
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


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
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
        if _directory_identity(before) != _directory_identity(linked):
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
        _directory_identity(before) != _directory_identity(after)
        or _directory_identity(after) != _directory_identity(linked_after)
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


def _claim_intent_rejection(payload: dict[str, Any]) -> BureauPickupError:
    status = payload.get("status")
    source_code = payload.get("code")
    token = source_code if isinstance(source_code, str) else status
    if not isinstance(token, str) or re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*", token
    ) is None:
        error_code = "claim-intent-not-ready"
    elif token.startswith("claim-intent-"):
        error_code = token
    else:
        error_code = f"claim-intent-{token}"

    details: dict[str, Any] = {
        "status": status,
        "source_code": source_code,
    }
    if payload.get("kind") == "grabowski_bureau_intake_adapter_failure":
        details["adapter_failure"] = {
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
    detail = payload.get("detail")
    if isinstance(detail, str):
        try:
            details["detail"] = json.loads(detail)
        except json.JSONDecodeError:
            details["detail"] = detail
    elif detail is not None:
        details["detail"] = detail

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
            details["runtime_identity"] = summary
    return BureauPickupError(error_code, details=details)


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
    keys = intent.get("required_resource_keys")
    if not isinstance(keys, list) or keys != sorted(set(keys)):
        raise BureauPickupError("claim-intent-resource-set-invalid")
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
    }


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
            raise BureauPickupError(
                "repository-scope-required", details={"resource_key": key}
            )
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
        raise BureauPickupError(
            "lease-acquisition-failed",
            details={
                "error_type": type(exc).__name__,
                "acquired_group_count": len(acquired),
                "compensation": released,
            },
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
) -> dict[str, Any]:
    try:
        status = _coordination_status(
            intent["run_id"],
            registry_root=registry_root,
            coordination_root=coordination_root,
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


@mcp.tool(name="grabowski_bureau_pickup_execute", annotations=MUTATING)
def grabowski_bureau_pickup_execute(
    request: BureauPickupRequest,
) -> dict[str, Any]:
    """Coordinate one Bureau claim with owner-bound Grabowski leases and recovery."""
    normalized = _normalize_request(request)
    operator._require_operator_mutation(
        "terminal_execute", path=normalized["registry_root"]
    )
    operator._require_operator_mutation(
        "terminal_execute", path=normalized["coordination_root"]
    )
    operator._require_operator_mutation("resource_lease")
    ensured_coordination_root = _ensure_coordination_root(
        normalized["coordination_root"]
    )
    if ensured_coordination_root != normalized["coordination_root"]:
        raise BureauPickupError("coordination-root-binding-changed")
    request_sha256 = _sha256(normalized)
    intent_payload = _claim_intent(normalized)
    intent, existing = _validate_intent_result(intent_payload, normalized)
    run_dir = _run_directory(intent["run_id"])
    if existing:
        stored_request_payload = _read_bound_json(
            run_dir / "request.json", label="request"
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
        coordination = _coordination_status(
            intent["run_id"],
            registry_root=normalized["registry_root"],
            coordination_root=normalized["coordination_root"],
        )
        _validate_claim_readback(coordination, intent, acquisition)
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup",
            "status": intent_payload["status"],
            "request_sha256": request_sha256,
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
    _write_bound_json(run_dir / "request.json", normalized)
    _write_bound_json(run_dir / "intent-result.json", intent_payload)
    _write_bound_json(run_dir / "intent.json", intent)
    acquisition = _acquire_groups(intent, normalized, run_dir)
    try:
        commit = _commit_claim(intent, normalized, run_dir)
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


def _current_root_binding(default_registry: str, *, source: str) -> dict[str, Any]:
    default_coordination = _normalize_coordination_root(
        str(_default_coordination_root()), registry_root=default_registry
    )
    legacy_fallback_allowed = (
        Path(default_coordination) != _legacy_coordination_root()
    )
    return {
        "registry_root": default_registry,
        "coordination_root": default_coordination,
        "source": (
            source
            if legacy_fallback_allowed
            else source.removesuffix("-with-legacy-fallback")
        ),
        "legacy_fallback_allowed": legacy_fallback_allowed,
    }


def _root_binding_for_run(run_id: str) -> dict[str, Any]:
    default_registry = _normalize_registry_root(str(bureau.BUREAU_ROOT))
    if not _journal_available(run_id):
        return _current_root_binding(
            default_registry, source="current-default-with-legacy-fallback"
        )
    try:
        stored = _read_bound_json(
            STATE_ROOT / "runs" / run_id / "request.json", label="request"
        )
    except BureauPickupError as exc:
        if exc.code == "request-missing":
            return _current_root_binding(
                default_registry, source="missing-request-with-legacy-fallback"
            )
        raise
    registry_root = _normalize_registry_root(
        stored.get("registry_root", default_registry)
    )
    if "coordination_root" not in stored:
        return {
            "registry_root": registry_root,
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
        "coordination_root": coordination_root,
        "source": "journal-bound",
        "legacy_fallback_allowed": False,
    }


def _coordination_status_for_binding(
    run_id: str, binding: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _coordination_status(
        run_id,
        registry_root=binding["registry_root"],
        coordination_root=binding["coordination_root"],
    )
    if not binding["legacy_fallback_allowed"] or not _definitive_missing_run(payload):
        return payload, binding
    legacy_payload = _coordination_status(
        run_id,
        registry_root=binding["registry_root"],
        coordination_root=None,
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
            if observed is not None:
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
    _write_bound_json(run_dir / "terminal-readback.json", status)
    owner_id, keys = _verify_release_binding(
        normalized_run_id, status, acquisition
    )
    result = resources.release_resources(owner_id, keys)
    _write_bound_json(run_dir / "release-result.json", result)
    remaining: dict[str, dict[str, Any]] = {}
    for key in keys:
        observed = resources.inspect_resource(key)
        if observed is not None:
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
        "owner_id": owner_id,
        "resource_keys": keys,
        "release": result,
        "terminal_readback_sha256": _sha256(status),
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
