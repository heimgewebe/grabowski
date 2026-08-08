from __future__ import annotations

import ast
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Iterator, Literal

try:
    from typing_extensions import TypedDict
except ModuleNotFoundError:
    from typing import TypedDict

try:
    from pydantic import StrictInt
except ModuleNotFoundError:
    StrictInt = int

import grabowski_bureau_leases as bureau_runtime
import grabowski_mcp as base
import grabowski_resources as resources

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING

SCHEMA_VERSION = 1
ARTIFACT_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_BUREAU_INTAKE_ROOT",
        str(operator.STATE_DIR / "bureau-intake"),
    )
).expanduser()
BUREAU_ROOT = bureau_runtime.BUREAU_CONTROL_ROOT
MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30
PROPOSAL_ID_RE = re.compile(r"^[0-9a-f]{64}$")
MANAGED_LAUNCHER_MARKER = b"# managed-by: heimgewebe-bureau-runtime-v1\n"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_RUNTIME_BINDING_BYTES = 4 * 1024 * 1024


def _prepare_registry_root(
    registry_root: str,
    *,
    refresh: bool,
    mutation: bool,
) -> str:
    resolved = Path(registry_root).expanduser().resolve()
    shared_root = bureau_runtime.BUREAU_REPOSITORY_ROOT.resolve()
    control_root = bureau_runtime.BUREAU_CONTROL_ROOT.resolve()
    if resolved == shared_root:
        raise bureau_runtime.BureauLeaseContractError(
            "shared-workbench-registry-root-forbidden",
            details={"required_root": str(control_root)},
        )
    if mutation:
        operator._require_operator_mutation(
            "terminal_execute", path=str(resolved)
        )
    if resolved == control_root:
        if refresh:
            bureau_runtime.refresh_bureau_control_checkout()
        else:
            bureau_runtime.inspect_bureau_control_checkout(require_current=True)
    return str(resolved)


class BureauCandidateIdSelector(TypedDict):
    __pydantic_config__ = {"extra": "forbid", "strict": True}

    kind: Literal["candidate_id"]
    candidate_id: str


class BureauEventIdSelector(TypedDict):
    __pydantic_config__ = {"extra": "forbid", "strict": True}

    kind: Literal["event_id"]
    event_id: int


class BureauIdempotencyKeySelector(TypedDict):
    __pydantic_config__ = {"extra": "forbid", "strict": True}

    kind: Literal["idempotency_key"]
    idempotency_key: str


@dataclass(frozen=True)
class RegularFileSnapshot:
    path: Path
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str
    raw: bytes

    @property
    def identity(self) -> tuple[int, int, int, int, int, int, str]:
        return (
            self.device,
            self.inode,
            self.mode,
            self.size,
            self.mtime_ns,
            self.ctime_ns,
            self.sha256,
        )


@dataclass(frozen=True)
class ManagedBureauRuntime:
    launcher: RegularFileSnapshot
    manifest: RegularFileSnapshot
    inventory: RegularFileSnapshot
    registry_root: Path
    source_commit: str
    registry_tree_sha256: str


def _managed_launcher_path() -> Path:
    return bureau_runtime.BUREAU_RUNTIME_ROOT.parent.parent / "bin/bureau"


def _deployment_manifest_path() -> Path:
    return bureau_runtime.BUREAU_RUNTIME_ROOT / "deployment-manifest.json"


def _snapshot_from_fd(
    descriptor: int,
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_RUNTIME_BINDING_BYTES,
) -> RegularFileSnapshot:
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise bureau_runtime.BureauLeaseContractError(
            f"{label}-fstat-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    if not stat.S_ISREG(before.st_mode):
        raise bureau_runtime.BureauLeaseContractError(f"{label}-not-regular")
    if before.st_size > max_bytes:
        raise bureau_runtime.BureauLeaseContractError(f"{label}-too-large")
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
    except OSError as exc:
        raise bureau_runtime.BureauLeaseContractError(
            f"{label}-read-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    raw = b"".join(chunks)
    if len(raw) > max_bytes:
        raise bureau_runtime.BureauLeaseContractError(f"{label}-too-large")
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    path_identity = (
        path_metadata.st_dev,
        path_metadata.st_ino,
        path_metadata.st_mode,
        path_metadata.st_size,
        path_metadata.st_mtime_ns,
        path_metadata.st_ctime_ns,
    )
    if (
        before_identity != after_identity
        or after_identity != path_identity
        or len(raw) != after.st_size
        or not stat.S_ISREG(path_metadata.st_mode)
    ):
        raise bureau_runtime.BureauLeaseContractError(f"{label}-changed-during-read")
    return RegularFileSnapshot(
        path=path,
        device=after.st_dev,
        inode=after.st_ino,
        mode=after.st_mode,
        size=after.st_size,
        mtime_ns=after.st_mtime_ns,
        ctime_ns=after.st_ctime_ns,
        sha256=hashlib.sha256(raw).hexdigest(),
        raw=raw,
    )


def _open_regular_file_snapshot(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_RUNTIME_BINDING_BYTES,
) -> tuple[int, RegularFileSnapshot]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise bureau_runtime.BureauLeaseContractError(
            f"{label}-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    try:
        snapshot = _snapshot_from_fd(
            descriptor,
            path,
            label=label,
            max_bytes=max_bytes,
        )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, snapshot


def _read_regular_file_snapshot(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_RUNTIME_BINDING_BYTES,
) -> RegularFileSnapshot:
    descriptor, snapshot = _open_regular_file_snapshot(
        path,
        label=label,
        max_bytes=max_bytes,
    )
    os.close(descriptor)
    return snapshot


def _literal_launcher_assignment(tree: ast.Module, name: str) -> ast.expr:
    matches: list[ast.expr] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            matches.append(node.value)
    if len(matches) != 1:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-binding-invalid",
            details={"assignment": name, "count": len(matches)},
        )
    return matches[0]


def _launcher_assignment_values(tree: ast.Module, name: str) -> list[ast.expr]:
    matches: list[ast.expr] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            matches.append(node.value)
    return matches


def _parse_managed_launcher_binding(
    launcher: RegularFileSnapshot,
) -> tuple[Path, str, str]:
    if MANAGED_LAUNCHER_MARKER not in launcher.raw[:512]:
        raise bureau_runtime.BureauLeaseContractError("managed-launcher-marker-missing")
    try:
        launcher_text = launcher.raw.decode("utf-8")
        tree = ast.parse(launcher_text, filename=str(launcher.path), mode="exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-syntax-invalid",
            details={"error_type": type(exc).__name__},
        ) from None
    manifest_expr = _literal_launcher_assignment(tree, "manifest_path")
    if not (
        isinstance(manifest_expr, ast.Call)
        and isinstance(manifest_expr.func, ast.Name)
        and manifest_expr.func.id == "Path"
        and len(manifest_expr.args) == 1
        and not manifest_expr.keywords
        and isinstance(manifest_expr.args[0], ast.Constant)
        and isinstance(manifest_expr.args[0].value, str)
    ):
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-manifest-path-binding-invalid"
        )
    legacy = _launcher_assignment_values(tree, "expected_manifest_sha256")
    payload = _launcher_assignment_values(tree, "manifest_digest_field")
    if bool(legacy) == bool(payload):
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-binding-invalid",
            details={
                "reason": "manifest-digest-binding-ambiguous",
                "legacy_count": len(legacy),
                "payload_count": len(payload),
            },
        )
    if legacy:
        if len(legacy) != 1:
            raise bureau_runtime.BureauLeaseContractError(
                "managed-launcher-binding-invalid",
                details={"assignment": "expected_manifest_sha256", "count": len(legacy)},
            )
        digest_expr = legacy[0]
        if not (
            isinstance(digest_expr, ast.Constant)
            and isinstance(digest_expr.value, str)
            and SHA256_RE.fullmatch(digest_expr.value)
        ):
            raise bureau_runtime.BureauLeaseContractError(
                "managed-launcher-manifest-digest-binding-invalid"
            )
        return (
            Path(manifest_expr.args[0].value),
            "manifest-sha256-v1",
            digest_expr.value,
        )
    if len(payload) != 1:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-binding-invalid",
            details={"assignment": "manifest_digest_field", "count": len(payload)},
        )
    field_expr = payload[0]
    if not (
        isinstance(field_expr, ast.Constant)
        and field_expr.value == "manifest_payload_sha256"
    ):
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-manifest-payload-digest-field-invalid"
        )
    return (
        Path(manifest_expr.args[0].value),
        "manifest-payload-sha256-v2",
        field_expr.value,
    )


def _validate_manifest_payload_binding(
    manifest_raw: bytes, manifest: dict[str, Any], *, field: str
) -> None:
    canonical = (
        json.dumps(
            manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if manifest_raw != canonical:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-manifest-payload-not-canonical"
        )
    payload = dict(manifest)
    expected = payload.pop(field, None)
    if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-manifest-payload-digest-invalid"
        )
    rendered_payload = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if hashlib.sha256(rendered_payload).hexdigest() != expected:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-manifest-payload-digest-mismatch"
        )


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _private_root() -> Path:
    ARTIFACT_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(ARTIFACT_ROOT, 0o700)
    return ARTIFACT_ROOT


def _write_bound_json(path: Path, value: Any) -> str:
    raw = _canonical_json(value)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("JSON input exceeds the bounded adapter limit")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != raw:
            raise RuntimeError(f"bound adapter artifact conflicts: {path}")
        return _sha256(raw)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return _sha256(raw)


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} is not a regular file")
    raw = path.read_bytes()
    if len(raw) > MAX_OUTPUT_BYTES:
        raise RuntimeError(f"{label} exceeds the bounded adapter limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def _managed_runtime_binding() -> ManagedBureauRuntime:
    launcher_path = _managed_launcher_path()
    manifest_path = _deployment_manifest_path()
    launcher = _read_regular_file_snapshot(launcher_path, label="managed-launcher")
    if launcher.mode & 0o111 == 0:
        raise bureau_runtime.BureauLeaseContractError("managed-launcher-not-executable")
    configured_manifest, manifest_binding_kind, manifest_binding_value = (
        _parse_managed_launcher_binding(launcher)
    )
    if configured_manifest != manifest_path:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-manifest-path-mismatch"
        )
    manifest = _read_regular_file_snapshot(
        manifest_path,
        label="deployment-manifest",
    )
    try:
        manifest_value = json.loads(manifest.raw)
        if manifest_binding_kind == "manifest-sha256-v1":
            if manifest.sha256 != manifest_binding_value:
                raise bureau_runtime.BureauLeaseContractError(
                    "managed-launcher-manifest-digest-mismatch"
                )
        elif manifest_binding_kind == "manifest-payload-sha256-v2":
            _validate_manifest_payload_binding(
                manifest.raw, manifest_value, field=manifest_binding_value
            )
        else:  # pragma: no cover - parser owns the closed binding vocabulary
            raise bureau_runtime.BureauLeaseContractError(
                "managed-launcher-manifest-binding-kind-unsupported"
            )
        if (
            manifest_value["schema_version"] != 1
            or manifest_value["kind"] != "bureau_runtime_deployment"
        ):
            raise ValueError("unsupported deployment manifest")
        if Path(manifest_value["launcher_path"]) != launcher_path:
            raise ValueError("deployment manifest launcher path mismatch")
        source_commit = manifest_value["source_commit"]
        registry_tree_sha256 = manifest_value["canonical_registry_tree_sha256"]
        inventory_sha256 = manifest_value["canonical_registry_inventory_sha256"]
        if not SOURCE_COMMIT_RE.fullmatch(source_commit):
            raise ValueError("invalid source commit")
        if not SHA256_RE.fullmatch(registry_tree_sha256):
            raise ValueError("invalid Registry tree digest")
        if not SHA256_RE.fullmatch(inventory_sha256):
            raise ValueError("invalid Registry inventory digest")
        configured_registry_root = Path(manifest_value["canonical_registry_root"])
        configured_inventory_path = Path(
            manifest_value["canonical_registry_inventory_path"]
        )
        if (
            not configured_registry_root.is_absolute()
            or not configured_inventory_path.is_absolute()
        ):
            raise ValueError("canonical Registry paths must be absolute")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "deployment-manifest-invalid",
            details={"error_type": type(exc).__name__},
        ) from None
    try:
        registry_root = configured_registry_root.resolve(strict=True)
    except OSError as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-root-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if registry_root != configured_registry_root:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-root-symlink-traversal"
        )
    try:
        inventory_path = configured_inventory_path.resolve(strict=True)
    except OSError as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-inventory-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if inventory_path != configured_inventory_path:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-inventory-symlink-traversal"
        )
    configured_snapshots_root = (
        bureau_runtime.BUREAU_RUNTIME_ROOT / "registry-snapshots"
    )
    try:
        snapshots_root = configured_snapshots_root.resolve(strict=True)
    except OSError as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-snapshots-root-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if snapshots_root != configured_snapshots_root or not snapshots_root.is_dir():
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-snapshots-root-invalid"
        )
    if not registry_root.is_dir() or not registry_root.is_relative_to(snapshots_root):
        raise bureau_runtime.BureauLeaseContractError("canonical-registry-root-invalid")
    if inventory_path.parent != registry_root:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-inventory-path-invalid"
        )
    inventory = _read_regular_file_snapshot(
        inventory_path,
        label="canonical-registry-inventory",
    )
    if inventory.sha256 != inventory_sha256:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-inventory-digest-mismatch"
        )
    try:
        inventory_value = json.loads(inventory.raw)
        paths = inventory_value["paths"]
        if (
            inventory_value["schema_version"] != 1
            or inventory_value["kind"] != "bureau_registry_snapshot"
            or inventory_value["source_commit"] != source_commit
            or inventory_value["tree_sha256"] != registry_tree_sha256
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
            raise ValueError("invalid canonical Registry inventory")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-inventory-invalid",
            details={"error_type": type(exc).__name__},
        ) from None
    return ManagedBureauRuntime(
        launcher=launcher,
        manifest=manifest,
        inventory=inventory,
        registry_root=registry_root,
        source_commit=source_commit,
        registry_tree_sha256=registry_tree_sha256,
    )


def _assert_snapshot_unchanged(
    expected: RegularFileSnapshot,
    *,
    label: str,
) -> None:
    observed = _read_regular_file_snapshot(expected.path, label=f"{label}-readback")
    if observed.identity != expected.identity:
        raise bureau_runtime.BureauLeaseContractError(f"{label}-changed-during-call")


def _assert_managed_runtime_unchanged(binding: ManagedBureauRuntime) -> None:
    _assert_snapshot_unchanged(binding.launcher, label="managed-launcher")
    _assert_snapshot_unchanged(binding.manifest, label="deployment-manifest")
    _assert_snapshot_unchanged(
        binding.inventory,
        label="canonical-registry-inventory",
    )
    try:
        observed_root = binding.registry_root.resolve(strict=True)
    except OSError as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-root-readback-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    if observed_root != binding.registry_root or not observed_root.is_dir():
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-root-changed-during-call"
        )


@contextmanager
def _bound_launcher_fd(
    binding: ManagedBureauRuntime,
) -> Iterator[tuple[int, str]]:
    descriptor, observed = _open_regular_file_snapshot(
        binding.launcher.path,
        label="managed-launcher-exec",
    )
    try:
        if observed.identity != binding.launcher.identity:
            raise bureau_runtime.BureauLeaseContractError(
                "managed-launcher-changed-before-exec"
            )
        proc_fd_path = f"/proc/self/fd/{descriptor}"
        if not Path("/proc/self/fd").is_dir():
            raise bureau_runtime.BureauLeaseContractError(
                "managed-launcher-fd-exec-unavailable"
            )
        yield descriptor, proc_fd_path
    finally:
        os.close(descriptor)


def _adapter_failure(
    code: str,
    *,
    details: dict[str, Any] | None = None,
    effect_started: bool = False,
    ambiguity: bool = False,
    required_readback: list[str] | None = None,
    retryable: bool | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_intake_adapter_failure",
        "code": code,
        "effect_started": effect_started,
        "retryable": (
            code in {"bureau-runtime-timeout", "bureau-runtime-unavailable"}
            if retryable is None
            else retryable
        ),
        "ambiguity": ambiguity,
        "required_readback": sorted(set(required_readback or [])),
        "details": details or {},
    }


def _invoke_bureau(
    arguments: list[str],
    *,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
    mutation: bool = False,
    required_readback: list[str] | None = None,
    include_runtime_identity: bool = False,
) -> dict[str, Any]:
    readback = sorted(set(required_readback or []))
    try:
        runtime = bureau_runtime._contract_runtime()
        managed_runtime = _managed_runtime_binding()
    except (OSError, RuntimeError, bureau_runtime.BureauLeaseContractError) as exc:
        return _adapter_failure(
            "bureau-runtime-unavailable",
            details={"error_type": type(exc).__name__},
        )
    try:
        bureau_runtime._assert_contract_runtime_unchanged(runtime)
        _assert_managed_runtime_unchanged(managed_runtime)
    except (OSError, RuntimeError, bureau_runtime.BureauLeaseContractError) as exc:
        return _adapter_failure(
            "bureau-runtime-drift",
            details={"error_type": type(exc).__name__},
            retryable=False,
        )
    try:
        with _bound_launcher_fd(managed_runtime) as (launcher_fd, launcher_argument):
            completed = subprocess.run(
                [
                    str(runtime["python_launcher"]),
                    "-I",
                    launcher_argument,
                    *arguments,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=bureau_runtime.BUREAU_RUNTIME_ROOT,
                env=bureau_runtime._safe_environment(),
                pass_fds=(launcher_fd,),
            )
    except subprocess.TimeoutExpired:
        return _adapter_failure(
            "bureau-runtime-timeout",
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=not mutation,
        )
    except bureau_runtime.BureauLeaseContractError as exc:
        return _adapter_failure(
            "bureau-runtime-drift",
            details={"error_type": type(exc).__name__},
            retryable=False,
        )
    except OSError as exc:
        return _adapter_failure(
            "bureau-runtime-unavailable",
            details={"error_type": type(exc).__name__},
        )
    try:
        bureau_runtime._assert_contract_runtime_unchanged(runtime)
        _assert_managed_runtime_unchanged(managed_runtime)
    except (OSError, RuntimeError, bureau_runtime.BureauLeaseContractError) as exc:
        return _adapter_failure(
            "bureau-runtime-drift",
            details={"error_type": type(exc).__name__},
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    stdout = completed.stdout.encode("utf-8")
    stderr = completed.stderr.encode("utf-8")
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
        return _adapter_failure(
            "bureau-output-too-large",
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    if completed.returncode != 0 and not completed.stdout.strip() and completed.stderr.strip():
        return _adapter_failure(
            "bureau-command-rejected",
            details={
                "returncode": completed.returncode,
                "stdout_sha256": _sha256(stdout),
                "stderr_sha256": _sha256(stderr),
            },
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return _adapter_failure(
            "bureau-output-invalid",
            details={
                "returncode": completed.returncode,
                "stdout_sha256": _sha256(stdout),
                "stderr_sha256": _sha256(stderr),
            },
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    if not isinstance(value, dict):
        return _adapter_failure(
            "bureau-output-invalid",
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    payload = value.get("result", value)
    if not isinstance(payload, dict):
        return _adapter_failure(
            "bureau-output-invalid",
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    if include_runtime_identity:
        runtime_identity = value.get("runtime_identity")
        if isinstance(runtime_identity, dict) and "runtime_identity" not in payload:
            payload = {**payload, "runtime_identity": runtime_identity}
    return payload


def _audit(operation: str, payload: dict[str, Any], **extra: Any) -> None:
    base._append_audit(
        {
            "operation": operation,
            "bureau_result_kind": payload.get("kind"),
            "bureau_status": payload.get("status"),
            "bureau_code": payload.get("code"),
            "effect_started": bool(payload.get("effect_started")),
            "ambiguity": bool(payload.get("ambiguity")),
            **extra,
        }
    )


def _proposal_directory(proposal_id: str) -> Path:
    if not PROPOSAL_ID_RE.fullmatch(proposal_id):
        raise ValueError("proposal_id must be a lowercase SHA-256 digest")
    return _private_root() / "proposals" / proposal_id


@mcp.tool(name="grabowski_bureau_candidate_record", annotations=MUTATING)
def grabowski_bureau_candidate_record(request: dict[str, Any]) -> dict[str, Any]:
    """Record one source-bound Bureau candidate through the canonical typed intake contract."""
    operator._require_operator_mutation("terminal_execute")
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    raw = _canonical_json(request)
    request_id = _sha256(raw)
    request_path = _private_root() / "requests" / f"{request_id}.json"
    _write_bound_json(request_path, request)
    payload = _invoke_bureau(
        [
            "--json",
            "--json-envelope",
            "operator-candidate-record",
            "--request",
            str(request_path),
        ],
        mutation=True,
        required_readback=["candidate_by_idempotency_key"],
    )
    idempotency_key = request.get("idempotency_key")
    required_readback = payload.get("required_readback")
    if (
        payload.get("ambiguity") is True
        and isinstance(required_readback, list)
        and "candidate_by_idempotency_key" in required_readback
        and isinstance(idempotency_key, str)
        and idempotency_key.strip()
        and "\x00" not in idempotency_key
    ):
        payload = {
            **payload,
            "readback_selector": {
                "kind": "idempotency_key",
                "idempotency_key": idempotency_key.strip(),
            },
        }
    _audit("bureau-candidate-record", payload, request_sha256=request_id)
    return {**payload, "adapter_request_sha256": request_id}


@mcp.tool(name="grabowski_bureau_candidate_assess", annotations=READ_ONLY)
def grabowski_bureau_candidate_assess(
    selector: (
        BureauCandidateIdSelector
        | BureauEventIdSelector
        | BureauIdempotencyKeySelector
        | None
    ) = None,
    expected_initiative: str = "",
    expected_task_id: str = "",
    candidate_id: str = "",
    event_id: StrictInt = 0,
    idempotency_key: str = "",
    initiative: str = "",
    task_id: str = "",
) -> dict[str, Any]:
    """Assess one explicitly selected operator-intake candidate read-only.

    ``expected_initiative`` and ``expected_task_id`` are optional binding checks;
    they are never candidate selectors. ``candidate_id``, ``event_id``,
    ``idempotency_key``, ``initiative`` and ``task_id`` remain accepted only as a
    compatibility bridge for connector
    catalogs cached before the typed ``selector`` contract was published.
    """

    if not isinstance(candidate_id, str):
        raise ValueError("candidate_id must be text")
    legacy_candidate_id = candidate_id.strip()
    if "\x00" in legacy_candidate_id:
        raise ValueError("candidate_id contains NUL")
    if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id < 0:
        raise ValueError("event_id must be a non-negative integer")
    if not isinstance(idempotency_key, str):
        raise ValueError("idempotency_key must be text")
    legacy_idempotency_key = idempotency_key.strip()
    if "\x00" in legacy_idempotency_key:
        raise ValueError("idempotency_key contains NUL")
    legacy_selector_count = (
        int(bool(legacy_candidate_id))
        + int(event_id > 0)
        + int(bool(legacy_idempotency_key))
    )
    if selector is not None and legacy_selector_count:
        raise ValueError("provide selector or one legacy selector, not both")
    if selector is None:
        if legacy_selector_count != 1:
            raise ValueError(
                "provide selector or exactly one legacy selector: "
                "candidate_id, event_id or idempotency_key; "
                "initiative and task_id are binding checks"
            )
        selector = (
            {"kind": "candidate_id", "candidate_id": legacy_candidate_id}
            if legacy_candidate_id
            else (
                {"kind": "event_id", "event_id": event_id}
                if event_id > 0
                else {
                    "kind": "idempotency_key",
                    "idempotency_key": legacy_idempotency_key,
                }
            )
        )
    if not isinstance(selector, dict):
        raise ValueError("selector must be an object")

    def binding_value(current: str, legacy: str, *, label: str) -> str:
        if not isinstance(current, str) or not isinstance(legacy, str):
            raise ValueError(f"{label} must be text")
        normalized = current.strip()
        normalized_legacy = legacy.strip()
        if "\x00" in normalized or "\x00" in normalized_legacy:
            raise ValueError(f"{label} contains NUL")
        if normalized and normalized_legacy and normalized != normalized_legacy:
            raise ValueError(f"conflicting {label} values")
        return normalized or normalized_legacy

    initiative_binding = binding_value(
        expected_initiative,
        initiative,
        label="initiative binding",
    )
    task_binding = binding_value(
        expected_task_id,
        task_id,
        label="task binding",
    )

    selector_kind = selector.get("kind")
    arguments = ["--json", "--json-envelope", "operator-candidate-assess"]
    if selector_kind == "candidate_id":
        if set(selector) != {"kind", "candidate_id"}:
            raise ValueError("candidate_id selector fields are invalid")
        selector_value = selector["candidate_id"]
        if not isinstance(selector_value, str):
            raise ValueError("candidate_id must be text")
        candidate_id = selector_value.strip()
        if not candidate_id or "\x00" in candidate_id:
            raise ValueError("candidate_id is empty or contains NUL")
        arguments.extend(["--candidate-id", candidate_id])
    elif selector_kind == "idempotency_key":
        if set(selector) != {"kind", "idempotency_key"}:
            raise ValueError("idempotency_key selector fields are invalid")
        selector_value = selector["idempotency_key"]
        if not isinstance(selector_value, str):
            raise ValueError("idempotency_key must be text")
        selector_idempotency_key = selector_value.strip()
        if not selector_idempotency_key or "\x00" in selector_idempotency_key:
            raise ValueError("idempotency_key is empty or contains NUL")
        arguments.extend(["--idempotency-key", selector_idempotency_key])
    elif selector_kind == "event_id":
        if set(selector) != {"kind", "event_id"}:
            raise ValueError("event_id selector fields are invalid")
        selector_value = selector["event_id"]
        if (
            not isinstance(selector_value, int)
            or isinstance(selector_value, bool)
            or selector_value <= 0
        ):
            raise ValueError("event_id must be a positive integer")
        arguments.extend(["--event-id", str(selector_value)])
    else:
        raise ValueError(
            "selector kind must be candidate_id, event_id or idempotency_key"
        )
    for value, option in (
        (initiative_binding, "--initiative"),
        (task_binding, "--task-id"),
    ):
        if value:
            arguments.extend([option, value])
    return _invoke_bureau(arguments)


@mcp.tool(name="grabowski_bureau_task_propose", annotations=MUTATING)
def grabowski_bureau_task_propose(
    task_json: dict[str, Any],
    publishing_task_id: str,
    candidate_id: str = "",
    event_id: int = 0,
    unresolved_fields: list[str] | None = None,
    placeholder_justification: str = "",
    registry_root: str = str(BUREAU_ROOT),
) -> dict[str, Any]:
    """Create an immutable Bureau task proposal artifact without changing Registry or Queue truth."""
    operator._require_operator_mutation(
        "terminal_execute",
        path=str(Path(registry_root).expanduser().resolve()),
    )
    resolved_root = _prepare_registry_root(
        registry_root, refresh=True, mutation=False
    )
    if bool(candidate_id) == bool(event_id):
        raise ValueError("provide exactly one of candidate_id or event_id")
    if not isinstance(task_json, dict):
        raise ValueError("task_json must be an object")
    request = {
        "task_json": task_json,
        "publishing_task_id": publishing_task_id,
        "candidate_id": candidate_id,
        "event_id": event_id,
        "unresolved_fields": sorted(set(unresolved_fields or [])),
        "placeholder_justification": placeholder_justification,
        "registry_root": resolved_root,
    }
    proposal_id = _sha256(_canonical_json(request))
    directory = _proposal_directory(proposal_id)
    task_path = directory / "task.json"
    plan_path = directory / "plan.json"
    result_path = directory / "proposal-result.json"
    _write_bound_json(task_path, task_json)
    if plan_path.exists():
        if plan_path.is_symlink() or not plan_path.is_file():
            raise RuntimeError("proposal plan is not a regular file")
        os.chmod(plan_path, 0o600)
        preview = _invoke_bureau(
            [
                "--root",
                request["registry_root"],
                "--json",
                "--json-envelope",
                "operator-task-publish",
                "--plan",
                str(plan_path),
                "--preview",
            ]
        )
        if preview.get("kind") != "bureau_task_publication_preview":
            return {
                **preview,
                "adapter_proposal_id": proposal_id,
                "idempotent_adapter_replay": True,
            }
        result = (
            _read_json_object(result_path, label="proposal result")
            if result_path.exists()
            else {
                "schema_version": SCHEMA_VERSION,
                "kind": "bureau_task_proposal_result",
                "status": "existing",
                "proposal_sha256": preview.get("proposal_sha256"),
                "effect_started": False,
            }
        )
        return {
            **result,
            "adapter_proposal_id": proposal_id,
            "idempotent_adapter_replay": True,
            "publication_preview": preview,
        }
    arguments = [
        "--root",
        request["registry_root"],
        "--json",
        "--json-envelope",
        "operator-task-propose",
        "--task-json",
        str(task_path),
        "--publishing-task-id",
        publishing_task_id,
        "--write-plan",
        str(plan_path),
    ]
    arguments.extend(
        ["--candidate-id", candidate_id]
        if candidate_id
        else ["--event-id", str(event_id)]
    )
    for field in request["unresolved_fields"]:
        arguments.extend(["--unresolved-field", field])
    if placeholder_justification:
        arguments.extend(["--placeholder-justification", placeholder_justification])
    payload = _invoke_bureau(
        arguments,
        mutation=True,
        required_readback=["proposal_artifact"],
    )
    if payload.get("kind") == "bureau_task_proposal_result" and plan_path.exists():
        os.chmod(plan_path, 0o600)
        _write_bound_json(result_path, payload)
    _audit("bureau-task-propose", payload, proposal_id=proposal_id)
    return {
        **payload,
        "adapter_proposal_id": proposal_id,
        "idempotent_adapter_replay": False,
    }


@mcp.tool(name="grabowski_bureau_task_review", annotations=MUTATING)
def grabowski_bureau_task_review(
    proposal_id: str,
    reviewer: str,
    proposal_sha256: str,
    registry_root: str = str(BUREAU_ROOT),
) -> dict[str, Any]:
    """Review one exact Bureau proposal digest without changing Registry, Queue or publication truth."""
    operator._require_operator_mutation(
        "terminal_execute",
        path=str(Path(registry_root).expanduser().resolve()),
    )
    resolved_root = _prepare_registry_root(
        registry_root, refresh=True, mutation=False
    )
    if not reviewer.strip():
        raise ValueError("reviewer must not be empty")
    if not SHA256_RE.fullmatch(proposal_sha256):
        raise ValueError("proposal_sha256 must be a lowercase SHA-256 digest")
    plan_path = _proposal_directory(proposal_id) / "plan.json"
    if not plan_path.is_file() or plan_path.is_symlink():
        raise FileNotFoundError(f"unknown proposal: {proposal_id}")
    payload = _invoke_bureau(
        [
            "--root",
            resolved_root,
            "--json",
            "--json-envelope",
            "operator-task-review",
            "--plan",
            str(plan_path),
            "--reviewer",
            reviewer,
            "--proposal-sha256",
            proposal_sha256,
        ],
        mutation=True,
        required_readback=["proposal_artifact"],
    )
    _audit(
        "bureau-task-review",
        payload,
        proposal_id=proposal_id,
        proposal_sha256=proposal_sha256,
        reviewer=reviewer,
    )
    return {**payload, "adapter_proposal_id": proposal_id}


@mcp.tool(name="grabowski_bureau_task_publish_preview", annotations=READ_ONLY)
def grabowski_bureau_task_publish_preview(
    proposal_id: str,
    registry_root: str = str(BUREAU_ROOT),
) -> dict[str, Any]:
    """Validate one immutable Bureau proposal and report its exact publication resources without effects."""
    plan_path = _proposal_directory(proposal_id) / "plan.json"
    if not plan_path.is_file() or plan_path.is_symlink():
        raise FileNotFoundError(f"unknown proposal: {proposal_id}")
    resolved_root = _prepare_registry_root(
        registry_root, refresh=False, mutation=False
    )
    return _invoke_bureau(
        [
            "--root",
            resolved_root,
            "--json",
            "--json-envelope",
            "operator-task-publish",
            "--plan",
            str(plan_path),
            "--preview",
        ]
    )


@mcp.tool(name="grabowski_bureau_task_publish", annotations=MUTATING)
def grabowski_bureau_task_publish(
    proposal_id: str,
    registry_root: str = str(BUREAU_ROOT),
    lease_ttl_seconds: int = 240,
) -> dict[str, Any]:
    """Acquire exact short Bureau leases, publish one reviewed task branch and PR, then release on a clear outcome."""
    operator._require_operator_mutation(
        "terminal_execute",
        path=str(Path(registry_root).expanduser().resolve()),
    )
    resolved_root = _prepare_registry_root(
        registry_root, refresh=True, mutation=False
    )
    operator._require_operator_mutation("resource_lease")
    if lease_ttl_seconds < 90 or lease_ttl_seconds > 300:
        raise ValueError("lease_ttl_seconds must be between 90 and 300")
    directory = _proposal_directory(proposal_id)
    plan_path = directory / "plan.json"
    if not plan_path.is_file() or plan_path.is_symlink():
        raise FileNotFoundError(f"unknown proposal: {proposal_id}")
    plan = _read_json_object(plan_path, label="proposal plan")
    publishing_task_id = plan.get("publishing_task_id")
    proposal_sha256 = plan.get("proposal_sha256")
    if not isinstance(publishing_task_id, str) or not isinstance(proposal_sha256, str):
        return _adapter_failure("proposal-binding-invalid")
    owner_id = f"bureau-publication:{proposal_sha256[:24]}"
    binding_path = directory / "lease-binding.json"
    receipt_path = directory / "publication-receipt.json"
    workspace_root = directory / "workspaces"
    _write_bound_json(
        binding_path, {"owner_id": owner_id, "task_id": publishing_task_id}
    )
    apply_arguments = [
        "--root",
        resolved_root,
        "--json",
        "--json-envelope",
        "operator-task-publish",
        "--plan",
        str(plan_path),
        "--apply",
        "--lease-binding",
        str(binding_path),
        "--resource-db",
        str(resources.RESOURCE_DB),
        "--workspace-root",
        str(workspace_root),
        "--receipt",
        str(receipt_path),
    ]
    if receipt_path.is_file() and not receipt_path.is_symlink():
        payload = _invoke_bureau(apply_arguments, timeout_seconds=30)
        _audit(
            "bureau-task-publish-receipt-replay",
            payload,
            proposal_id=proposal_id,
            owner_id=owner_id,
        )
        return {
            **payload,
            "adapter_proposal_id": proposal_id,
            "lease_owner_id": owner_id,
            "leases_acquired": False,
            "leases_released": True,
            "idempotent_adapter_replay": True,
        }
    preview = grabowski_bureau_task_publish_preview(proposal_id, resolved_root)
    if (
        preview.get("kind") != "bureau_task_publication_preview"
        or preview.get("status") != "ready"
    ):
        return preview
    resource_keys = preview.get("required_resource_keys")
    if (
        not isinstance(resource_keys, list)
        or len(resource_keys) != 2
        or any(not isinstance(key, str) for key in resource_keys)
    ):
        return _adapter_failure("publication-resource-contract-invalid")
    metadata = {
        "task_id": publishing_task_id,
        "operation": "registry-publication",
        "proposal_sha256": proposal_sha256,
        "bureau_phase": "work",
    }
    try:
        acquired = resources.acquire_resources(
            owner_id,
            resource_keys,
            purpose=f"Publish reviewed Bureau proposal {proposal_sha256}",
            ttl_seconds=lease_ttl_seconds,
            metadata=metadata,
        )
    except Exception as exc:
        payload = _adapter_failure(
            "publication-lease-acquire-failed",
            details={"error_type": type(exc).__name__, "resource_keys": resource_keys},
        )
        _audit(
            "bureau-task-publish", payload, proposal_id=proposal_id, owner_id=owner_id
        )
        return {
            **payload,
            "adapter_proposal_id": proposal_id,
            "lease_owner_id": owner_id,
        }
    base._append_audit(
        {
            "operation": "bureau-publication-resource-acquire",
            "owner_id": owner_id,
            "resource_keys": resource_keys,
            "proposal_sha256": proposal_sha256,
            "expires_at_unix": acquired["expires_at_unix"],
            "bureau_contract": acquired.get("bureau_contract"),
        }
    )
    payload = _invoke_bureau(
        apply_arguments,
        timeout_seconds=120,
        mutation=True,
        required_readback=[
            "publication_receipt",
            "remote_branch",
            "pull_request",
            "resource_leases",
        ],
    )
    receipt_readback_attempted = False
    if bool(payload.get("ambiguity")) and receipt_path.is_file():
        os.chmod(receipt_path, 0o600)
        receipt_readback_attempted = True
        replay = _invoke_bureau(apply_arguments, timeout_seconds=30)
        if replay.get("status") == "published" and not bool(replay.get("ambiguity")):
            payload = {**replay, "ambiguity_reconciled": "receipt-replay"}
    release_requested = not bool(payload.get("ambiguity"))
    leases_released = False
    release_error: dict[str, Any] | None = None
    if release_requested:
        try:
            released = resources.release_resources(owner_id, resource_keys)
            leases_released = len(released["released"]) == len(resource_keys)
            base._append_audit(
                {
                    "operation": "bureau-publication-resource-release",
                    "owner_id": owner_id,
                    "resource_keys": [
                        item["resource_key"] for item in released["released"]
                    ],
                    "proposal_sha256": proposal_sha256,
                }
            )
        except Exception as exc:
            release_error = {"error_type": type(exc).__name__}
    payload = {
        **payload,
        "receipt_readback_attempted": receipt_readback_attempted,
    }
    if payload.get("status") == "published" and receipt_path.is_file():
        os.chmod(receipt_path, 0o600)
        receipt = _read_json_object(receipt_path, label="publication receipt")
        payload = {
            **payload,
            "adapter_receipt_sha256": _sha256(_canonical_json(receipt)),
        }
    if release_error is not None:
        payload = {
            **payload,
            "cleanup_incomplete": True,
            "lease_release_error": release_error,
            "required_readback": sorted(
                set(payload.get("required_readback", [])) | {"resource_leases"}
            ),
        }
    _audit("bureau-task-publish", payload, proposal_id=proposal_id, owner_id=owner_id)
    return {
        **payload,
        "adapter_proposal_id": proposal_id,
        "lease_owner_id": owner_id,
        "lease_expires_at_unix": acquired["expires_at_unix"],
        "leases_acquired": True,
        "leases_released": leases_released,
        "idempotent_adapter_replay": False,
        "required_resource_keys": resource_keys,
    }
