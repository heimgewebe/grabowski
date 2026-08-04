from __future__ import annotations

import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Iterator

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows only
    _fcntl = None

BUREAU_REPOSITORY_ROOT = Path("/home/alex/repos/bureau")
BUREAU_WORKTREE_ROOT = Path("/home/alex/repos/.bureau-worktrees")
BUREAU_CONTROL_ROOT = BUREAU_WORKTREE_ROOT / "control-main"
BUREAU_CONTROL_BRANCH = "ops/bureau-control-main"
BUREAU_CONTROL_UPSTREAM = "origin/main"
BUREAU_CANONICAL_REMOTE_URL = "git@github.com:heimgewebe/bureau.git"
BUREAU_CONTROL_LOCK_PATH = (
    Path.home() / ".local/state/grabowski/bureau-control-refresh.lock"
)
BUREAU_RUNTIME_ROOT = Path("/home/alex/.local/share/bureau")
BUREAU_MANAGED_LAUNCHER = Path("/home/alex/.local/bin/bureau")
BUREAU_CONTRACT_PYTHON = Path(sys.executable)
BUREAU_CONTRACT_EXECUTABLE = BUREAU_RUNTIME_ROOT / "venv/bin/bureau"
BROAD_BUREAU_REPOSITORY_KEY = f"repo:{BUREAU_REPOSITORY_ROOT}"
BUREAU_MERGE_GATE_KEY = f"path:{BUREAU_REPOSITORY_ROOT}/.bureau-scopes/merge-main"
BUREAU_WORKTREE_ADMIN_KEY = (
    f"path:{BUREAU_REPOSITORY_ROOT}/.bureau-scopes/worktree-admin"
)
BUREAU_RUNTIME_SERVICE_KEY = "service:bureau-status-capsule"
CONTRACT_SCHEMA_VERSION = 2
CONTRACT_KIND = "bureau_lease_diagnostics"
CONTRACT_TIMEOUT_SECONDS = 5
MAX_CONTRACT_FILE_BYTES = 16 * 1024 * 1024
MAX_EFFECT_GATE_TTL_SECONDS = 300
_ALLOWED_PHASES = {"work", "worktree-admin", "merge", "emergency-recovery"}
_RELEASE_DIRECTORY_RE = re.compile(r"^venv-(?P<commit>[0-9a-f]{40})$")
_EXPECTED_HEAD_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SCHEDULER_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MANAGED_LAUNCHER_MARKER = b"# managed-by: heimgewebe-bureau-runtime-v1\n"
_CONTRACT_MODULE_NAMES = ("bureau.cli", "bureau.lease_contract")
_CONTRACT_WRAPPER = r"""
import hashlib
import importlib
import json
from pathlib import Path
import sys

binding = json.loads(sys.argv[1])

def digest(path_string):
    return hashlib.sha256(Path(path_string).read_bytes()).hexdigest()

def verify_files():
    for relative_path, expected in binding["package_files"].items():
        if digest(expected["path"]) != expected["sha256"]:
            raise RuntimeError("bound Bureau package file changed")

verify_files()
cli = importlib.import_module("bureau.cli")
lease_contract = importlib.import_module("bureau.lease_contract")
for module_name, module in (("bureau.cli", cli), ("bureau.lease_contract", lease_contract)):
    loaded = Path(module.__file__).resolve()
    expected = Path(binding["module_paths"][module_name]).resolve()
    if loaded != expected:
        raise RuntimeError("unexpected Bureau contract module path")
verify_files()
returncode = cli.main(sys.argv[2:])
verify_files()
raise SystemExit(returncode)
"""


class BureauLeaseContractError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(f"Bureau lease contract rejected acquisition: {code}")
        self.code = code
        self.details = details or {}


def _control_git_environment() -> dict[str, str]:
    environment = {
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "GIT_TERMINAL_PROMPT": "0",
    }
    for key in ("SSH_AUTH_SOCK", "GIT_SSH_COMMAND"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _run_control_git(
    repository: Path,
    arguments: list[str],
    *,
    timeout_seconds: int = 60,
) -> str:
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(repository),
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=_control_git_environment(),
        )
    except subprocess.TimeoutExpired as exc:
        raise BureauLeaseContractError(
            "control-checkout-git-timeout",
            details={"operation": arguments[0] if arguments else "unknown"},
        ) from exc
    except OSError as exc:
        raise BureauLeaseContractError(
            "control-checkout-git-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if completed.returncode != 0:
        raise BureauLeaseContractError(
            "control-checkout-git-rejected",
            details={
                "operation": arguments[0] if arguments else "unknown",
                "returncode": completed.returncode,
                "stdout_sha256": hashlib.sha256(
                    completed.stdout.encode("utf-8")
                ).hexdigest(),
                "stderr_sha256": hashlib.sha256(
                    completed.stderr.encode("utf-8")
                ).hexdigest(),
            },
        )
    return completed.stdout.strip()


@contextmanager
def _bureau_control_lock() -> Iterator[None]:
    lock_api = _fcntl
    if (
        lock_api is None
        or not hasattr(os, "getuid")
        or not hasattr(os, "O_CLOEXEC")
    ):
        raise BureauLeaseContractError(
            "control-checkout-lock-unavailable",
            details={"platform": sys.platform},
        )
    parent = BUREAU_CONTROL_LOCK_PATH.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = parent.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise BureauLeaseContractError("control-checkout-lock-root-unsafe")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(BUREAU_CONTROL_LOCK_PATH, flags, 0o600)
    try:
        lock_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_uid != os.getuid()
            or stat.S_IMODE(lock_metadata.st_mode) != 0o600
            or lock_metadata.st_nlink != 1
        ):
            raise BureauLeaseContractError("control-checkout-lock-unsafe")
        lock_api.flock(descriptor, lock_api.LOCK_EX)
        yield
    finally:
        try:
            lock_api.flock(descriptor, lock_api.LOCK_UN)
        finally:
            os.close(descriptor)


def _validated_bureau_repository_root() -> Path:
    try:
        repository_root = BUREAU_REPOSITORY_ROOT.resolve(strict=True)
    except OSError as exc:
        raise BureauLeaseContractError(
            "bureau-repository-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if not repository_root.is_dir():
        raise BureauLeaseContractError("bureau-repository-path-invalid")
    remote_url = _run_control_git(
        repository_root, ["remote", "get-url", "origin"]
    )
    if remote_url != BUREAU_CANONICAL_REMOTE_URL:
        raise BureauLeaseContractError("control-checkout-remote-mismatch")
    return repository_root


def _control_checkout_missing() -> bool:
    if not os.path.lexists(BUREAU_CONTROL_ROOT):
        return True
    metadata = BUREAU_CONTROL_ROOT.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BureauLeaseContractError("control-checkout-path-occupied")
    return False


def _control_worktree_registered(repository_root: Path) -> bool:
    listing = _run_control_git(
        repository_root, ["worktree", "list", "--porcelain"]
    )
    expected = f"worktree {BUREAU_CONTROL_ROOT}"
    return any(line == expected for line in listing.splitlines())


def _prepare_bureau_worktree_root() -> Path:
    BUREAU_WORKTREE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = BUREAU_WORKTREE_ROOT.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise BureauLeaseContractError("control-worktree-root-unsafe")
    resolved = BUREAU_WORKTREE_ROOT.resolve(strict=True)
    if resolved != BUREAU_WORKTREE_ROOT:
        raise BureauLeaseContractError("control-worktree-root-path-mismatch")
    return resolved


def _recreate_bureau_control_checkout(repository_root: Path) -> dict[str, Any]:
    if not _control_checkout_missing():
        raise BureauLeaseContractError("control-checkout-already-present")
    _prepare_bureau_worktree_root()
    if _control_worktree_registered(repository_root):
        _run_control_git(
            repository_root,
            [
                "worktree",
                "remove",
                "--force",
                "--force",
                str(BUREAU_CONTROL_ROOT),
            ],
            timeout_seconds=60,
        )
    _run_control_git(
        repository_root,
        [
            "worktree",
            "add",
            "--force",
            "--force",
            "-B",
            BUREAU_CONTROL_BRANCH,
            str(BUREAU_CONTROL_ROOT),
            BUREAU_CONTROL_UPSTREAM,
        ],
        timeout_seconds=120,
    )
    _run_control_git(
        BUREAU_CONTROL_ROOT,
        [
            "branch",
            "--set-upstream-to",
            BUREAU_CONTROL_UPSTREAM,
            BUREAU_CONTROL_BRANCH,
        ],
    )
    return inspect_bureau_control_checkout(require_current=True)


def inspect_bureau_control_checkout(*, require_current: bool = True) -> dict[str, Any]:
    try:
        control_root = BUREAU_CONTROL_ROOT.resolve(strict=True)
        repository_root = BUREAU_REPOSITORY_ROOT.resolve(strict=True)
        expected_common_dir = (repository_root / ".git").resolve(strict=True)
    except OSError as exc:
        raise BureauLeaseContractError(
            "control-checkout-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if control_root != BUREAU_CONTROL_ROOT or not control_root.is_dir():
        raise BureauLeaseContractError("control-checkout-path-invalid")
    common_dir = Path(
        _run_control_git(
            control_root,
            ["rev-parse", "--path-format=absolute", "--git-common-dir"],
        )
    ).resolve(strict=True)
    if common_dir != expected_common_dir:
        raise BureauLeaseContractError("control-checkout-common-dir-mismatch")
    remote_url = _run_control_git(control_root, ["remote", "get-url", "origin"])
    if remote_url != BUREAU_CANONICAL_REMOTE_URL:
        raise BureauLeaseContractError("control-checkout-remote-mismatch")
    branch = _run_control_git(control_root, ["symbolic-ref", "--short", "HEAD"])
    if branch != BUREAU_CONTROL_BRANCH:
        raise BureauLeaseContractError(
            "control-checkout-branch-mismatch",
            details={"observed_branch": branch},
        )
    upstream = _run_control_git(
        control_root,
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
    )
    if upstream != BUREAU_CONTROL_UPSTREAM:
        raise BureauLeaseContractError(
            "control-checkout-upstream-mismatch",
            details={"observed_upstream": upstream},
        )
    status = _run_control_git(
        control_root,
        ["status", "--porcelain=v1", "--untracked-files=normal"],
    )
    if status:
        raise BureauLeaseContractError(
            "control-checkout-dirty",
            details={"status_sha256": hashlib.sha256(status.encode()).hexdigest()},
        )
    head = _run_control_git(control_root, ["rev-parse", "HEAD"])
    remote_head = _run_control_git(
        control_root, ["rev-parse", "refs/remotes/origin/main"]
    )
    if (
        _EXPECTED_HEAD_RE.fullmatch(head) is None
        or _EXPECTED_HEAD_RE.fullmatch(remote_head) is None
    ):
        raise BureauLeaseContractError("control-checkout-head-invalid")
    if require_current and head != remote_head:
        raise BureauLeaseContractError(
            "control-checkout-stale",
            details={"head": head, "origin_main": remote_head},
        )
    return {
        "schema_version": 1,
        "kind": "bureau_control_checkout",
        "status": "current" if head == remote_head else "stale",
        "repository_root": str(repository_root),
        "control_root": str(control_root),
        "branch": branch,
        "upstream": upstream,
        "head": head,
        "origin_main": remote_head,
        "dirty": False,
    }


def refresh_bureau_control_checkout() -> dict[str, Any]:
    with _bureau_control_lock():
        repository_root = _validated_bureau_repository_root()
        missing = _control_checkout_missing()
        before = (
            None
            if missing
            else inspect_bureau_control_checkout(require_current=False)
        )
        _run_control_git(
            repository_root,
            [
                "fetch",
                "--no-tags",
                "origin",
                "+refs/heads/main:refs/remotes/origin/main",
            ],
            timeout_seconds=120,
        )
        if missing:
            after = _recreate_bureau_control_checkout(repository_root)
        else:
            _run_control_git(
                BUREAU_CONTROL_ROOT,
                ["merge", "--ff-only", "--no-edit", "origin/main"],
                timeout_seconds=60,
            )
            after = inspect_bureau_control_checkout(require_current=True)
    previous_head = None if before is None else before["head"]
    return {
        **after,
        "updated": missing or previous_head != after["head"],
        "previous_head": previous_head,
        "recreated": missing,
    }


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resource_path(key: str) -> Path | None:
    kind, separator, value = key.partition(":")
    if separator != ":" or kind not in {"path", "repo"}:
        return None
    return Path(value)


def is_bureau_resource_key(key: str) -> bool:
    if key in {BROAD_BUREAU_REPOSITORY_KEY, BUREAU_RUNTIME_SERVICE_KEY}:
        return True
    path = _resource_path(key)
    if path is None:
        return False
    return _path_is_within(path, BUREAU_REPOSITORY_ROOT) or _path_is_within(
        path, BUREAU_WORKTREE_ROOT
    )


def bureau_resource_keys(keys: Iterable[str]) -> list[str]:
    return sorted({key for key in keys if is_bureau_resource_key(key)})


def _phase(keys: list[str], metadata: dict[str, Any] | None) -> str:
    requested = None if metadata is None else metadata.get("bureau_phase")
    if BUREAU_MERGE_GATE_KEY in keys and BUREAU_WORKTREE_ADMIN_KEY in keys:
        raise BureauLeaseContractError("mixed-effect-gates-forbidden")
    inferred = "work"
    if BUREAU_MERGE_GATE_KEY in keys:
        inferred = "merge"
    elif BUREAU_WORKTREE_ADMIN_KEY in keys:
        inferred = "worktree-admin"
    if requested is None:
        return inferred
    if not isinstance(requested, str) or requested not in _ALLOWED_PHASES:
        raise BureauLeaseContractError("invalid-phase")
    if inferred != "work" and requested != inferred:
        raise BureauLeaseContractError(
            "phase-does-not-match-effect-gate",
            details={"expected_phase": inferred, "provided_phase": requested},
        )
    return requested


def _bounded_text(
    metadata: dict[str, Any] | None,
    key: str,
    *,
    maximum_bytes: int,
) -> str | None:
    value = None if metadata is None else metadata.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise BureauLeaseContractError(f"invalid-{key.replace('_', '-')}")
    normalized = value.strip()
    if not normalized or len(normalized.encode("utf-8")) > maximum_bytes or "\x00" in normalized:
        raise BureauLeaseContractError(f"invalid-{key.replace('_', '-')}")
    return normalized


def _sha256_token(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def sanitize_bureau_metadata(
    resource_keys: Iterable[str], metadata: dict[str, Any] | None
) -> dict[str, Any] | None:
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    sanitized = dict(metadata)
    if not bureau_resource_keys(resource_keys):
        return sanitized
    for key in ("bureau_justification", "bureau_expected_state"):
        value = sanitized.get(key)
        if isinstance(value, str) and value.strip():
            sanitized[key] = _sha256_token(value.strip())
    return sanitized


def _safe_environment() -> dict[str, str]:
    return {
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": "/dev/null/grabowski-bureau-contract",
    }


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _regular_file_snapshot(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_CONTRACT_FILE_BYTES,
) -> tuple[dict[str, Any], bytes]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise BureauLeaseContractError(f"{label}-nofollow-unavailable")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BureauLeaseContractError(
            f"{label}-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BureauLeaseContractError(f"{label}-not-regular")
        if before.st_size > max_bytes:
            raise BureauLeaseContractError(f"{label}-too-large")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        os.lseek(descriptor, 0, os.SEEK_SET)
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        linked = path.lstat()
    except BureauLeaseContractError:
        raise
    except OSError as exc:
        raise BureauLeaseContractError(
            f"{label}-read-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > max_bytes:
        raise BureauLeaseContractError(f"{label}-too-large")
    if (
        _metadata_identity(before) != _metadata_identity(after)
        or _metadata_identity(after) != _metadata_identity(linked)
        or len(raw) != after.st_size
        or not stat.S_ISREG(linked.st_mode)
        or stat.S_ISLNK(linked.st_mode)
    ):
        raise BureauLeaseContractError(f"{label}-changed-during-read")
    return (
        {
            "path": str(path),
            "device": after.st_dev,
            "inode": after.st_ino,
            "mode": after.st_mode,
            "nlink": after.st_nlink,
            "uid": after.st_uid,
            "gid": after.st_gid,
            "size": after.st_size,
            "mtime_ns": after.st_mtime_ns,
            "ctime_ns": after.st_ctime_ns,
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        raw,
    )


def _regular_file_identity(path: Path, *, label: str) -> dict[str, Any]:
    identity, _raw = _regular_file_snapshot(path, label=label)
    return identity


def _contract_module_path(release_root: Path, module_name: str) -> Path:
    relative = Path(*module_name.split(".")).with_suffix(".py")
    candidates = sorted(
        release_root.glob(f"lib/python*/site-packages/{relative.as_posix()}")
    )
    if len(candidates) != 1:
        raise BureauLeaseContractError(
            "contract-module-layout-invalid",
            details={"module": module_name, "candidate_count": len(candidates)},
        )
    candidate = candidates[0]
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise BureauLeaseContractError(
            "contract-module-unavailable",
            details={"module": module_name, "error_type": type(exc).__name__},
        ) from None
    if resolved != candidate or not _path_is_within(resolved, release_root):
        raise BureauLeaseContractError(
            "contract-module-path-invalid", details={"module": module_name}
        )
    return resolved




def _contract_package_paths(release_root: Path) -> dict[str, Path]:
    roots = sorted(release_root.glob("lib/python*/site-packages/bureau"))
    if len(roots) != 1:
        raise BureauLeaseContractError(
            "contract-package-layout-invalid",
            details={"candidate_count": len(roots)},
        )
    package_root = roots[0]
    try:
        resolved_root = package_root.resolve(strict=True)
    except OSError as exc:
        raise BureauLeaseContractError(
            "contract-package-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if resolved_root != package_root or package_root.is_symlink():
        raise BureauLeaseContractError("contract-package-path-invalid")
    paths: dict[str, Path] = {}
    for candidate in sorted(package_root.rglob("*.py")):
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise BureauLeaseContractError(
                "contract-package-file-unavailable",
                details={"error_type": type(exc).__name__},
            ) from None
        if (
            resolved != candidate
            or candidate.is_symlink()
            or not _path_is_within(resolved, package_root)
        ):
            raise BureauLeaseContractError("contract-package-file-path-invalid")
        relative = candidate.relative_to(package_root.parent).as_posix()
        paths[relative] = resolved
    if not paths:
        raise BureauLeaseContractError("contract-package-empty")
    return paths


def _package_sha256(identities: dict[str, dict[str, Any]]) -> str:
    encoded = "".join(
        f"{relative}\0{identities[relative]['sha256']}\n"
        for relative in sorted(identities)
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

def _managed_package_paths(release_root: Path) -> dict[str, Path]:
    pyproject = release_root / "pyproject.toml"
    package_root = release_root / "src/bureau"
    if (
        release_root.is_symlink()
        or not release_root.is_dir()
        or pyproject.is_symlink()
        or not pyproject.is_file()
        or package_root.is_symlink()
        or not package_root.is_dir()
    ):
        raise BureauLeaseContractError("contract-managed-package-layout-invalid")
    candidates = [pyproject]
    for entry in sorted(package_root.rglob("*")):
        try:
            linked = entry.lstat()
            resolved = entry.resolve(strict=True)
        except OSError as exc:
            raise BureauLeaseContractError(
                "contract-managed-package-entry-unavailable",
                details={"error_type": type(exc).__name__},
            ) from None
        if (
            stat.S_ISLNK(linked.st_mode)
            or resolved != entry
            or not _path_is_within(resolved, release_root)
        ):
            raise BureauLeaseContractError(
                "contract-managed-package-entry-invalid",
                details={"relative_path": entry.relative_to(release_root).as_posix()},
            )
        if stat.S_ISDIR(linked.st_mode):
            continue
        if not stat.S_ISREG(linked.st_mode) or entry.suffix != ".py":
            raise BureauLeaseContractError(
                "contract-managed-package-entry-invalid",
                details={"relative_path": entry.relative_to(release_root).as_posix()},
            )
        candidates.append(entry)
    paths: dict[str, Path] = {}
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise BureauLeaseContractError(
                "contract-managed-package-file-unavailable",
                details={"error_type": type(exc).__name__},
            ) from None
        if (
            resolved != candidate
            or candidate.is_symlink()
            or not candidate.is_file()
            or not _path_is_within(resolved, release_root)
        ):
            raise BureauLeaseContractError("contract-managed-package-file-invalid")
        paths[candidate.relative_to(release_root).as_posix()] = resolved
    if len(paths) < 2:
        raise BureauLeaseContractError("contract-managed-package-empty")
    return paths


def _managed_bureau_cycle_package_paths(release_root: Path) -> dict[str, Path]:
    pyproject = release_root / "pyproject.toml"
    package_roots = (release_root / "src/bureau", release_root / "src/bureau_cycle")
    systemd_root = release_root / "ops/systemd"
    required_paths = (pyproject, *package_roots, systemd_root)
    if (
        release_root.is_symlink()
        or not release_root.is_dir()
        or pyproject.is_symlink()
        or not pyproject.is_file()
        or any(path.is_symlink() or not path.is_dir() for path in package_roots)
        or systemd_root.is_symlink()
        or not systemd_root.is_dir()
    ):
        raise BureauLeaseContractError("contract-managed-package-layout-invalid")
    for required in required_paths:
        try:
            resolved = required.resolve(strict=True)
        except OSError as exc:
            raise BureauLeaseContractError(
                "contract-managed-package-file-unavailable",
                details={"error_type": type(exc).__name__},
            ) from None
        if resolved != required or not _path_is_within(resolved, release_root):
            raise BureauLeaseContractError("contract-managed-package-file-invalid")
    candidates = [pyproject]
    for package_root in package_roots:
        candidates.extend(sorted(package_root.rglob("*.py")))
    candidates.extend(
        entry for entry in sorted(systemd_root.rglob("*")) if entry.is_file()
    )
    paths: dict[str, Path] = {}
    for candidate in candidates:
        try:
            linked = candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise BureauLeaseContractError(
                "contract-managed-package-file-unavailable",
                details={"error_type": type(exc).__name__},
            ) from None
        if (
            stat.S_ISLNK(linked.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or resolved != candidate
            or not _path_is_within(resolved, release_root)
        ):
            raise BureauLeaseContractError(
                "contract-managed-package-file-invalid",
                details={"relative_path": candidate.relative_to(release_root).as_posix()},
            )
        paths[candidate.relative_to(release_root).as_posix()] = resolved
    return paths


def _managed_scheduler_names(release_root: Path) -> tuple[str, ...]:
    module = release_root / "src/bureau/runtime_identity.py"
    _identity, raw = _regular_file_snapshot(
        module, label="contract-managed-scheduler-identity"
    )
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=str(module), mode="exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise BureauLeaseContractError(
            "contract-managed-scheduler-binding-invalid",
            details={"reason": "syntax-invalid", "error_type": type(exc).__name__},
        ) from None
    matches: list[ast.expr] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "SCHEDULER_NAMES":
            matches.append(node.value)
    if len(matches) != 1:
        raise BureauLeaseContractError(
            "contract-managed-scheduler-binding-invalid",
            details={"reason": "assignment-count-invalid", "count": len(matches)},
        )
    try:
        value = ast.literal_eval(matches[0])
    except (ValueError, TypeError, SyntaxError):
        raise BureauLeaseContractError(
            "contract-managed-scheduler-binding-invalid",
            details={"reason": "literal-invalid"},
        ) from None
    if (
        not isinstance(value, tuple)
        or not value
        or not all(
            isinstance(name, str) and _SCHEDULER_NAME_RE.fullmatch(name)
            for name in value
        )
        or len(set(value)) != len(value)
    ):
        raise BureauLeaseContractError(
            "contract-managed-scheduler-binding-invalid",
            details={"reason": "value-invalid"},
        )
    return value


def _managed_bureau_scheduler_package_paths(
    release_root: Path,
) -> dict[str, Path]:
    pyproject = release_root / "pyproject.toml"
    package_roots = (release_root / "src/bureau", release_root / "src/bureau_cycle")
    systemd_root = release_root / "ops/systemd"
    required_paths = (pyproject, *package_roots, systemd_root)
    if (
        release_root.is_symlink()
        or not release_root.is_dir()
        or pyproject.is_symlink()
        or not pyproject.is_file()
        or any(path.is_symlink() or not path.is_dir() for path in package_roots)
        or systemd_root.is_symlink()
        or not systemd_root.is_dir()
    ):
        raise BureauLeaseContractError("contract-managed-package-layout-invalid")
    for required in required_paths:
        try:
            resolved = required.resolve(strict=True)
        except OSError as exc:
            raise BureauLeaseContractError(
                "contract-managed-package-file-unavailable",
                details={"error_type": type(exc).__name__},
            ) from None
        if resolved != required or not _path_is_within(resolved, release_root):
            raise BureauLeaseContractError("contract-managed-package-file-invalid")
    scheduler_names = _managed_scheduler_names(release_root)
    scheduler_paths = [
        *(systemd_root / f"{name}.service" for name in scheduler_names),
        *(systemd_root / f"{name}.timer" for name in scheduler_names),
        *(systemd_root / "libexec" / name for name in scheduler_names),
    ]
    expected_systemd = {
        path.relative_to(systemd_root).as_posix() for path in scheduler_paths
    }
    actual_systemd = {
        path.relative_to(systemd_root).as_posix()
        for path in systemd_root.rglob("*")
        if path.is_file()
    }
    if actual_systemd != expected_systemd:
        raise BureauLeaseContractError(
            "contract-managed-scheduler-layout-invalid",
            details={
                "expected_file_count": len(expected_systemd),
                "observed_file_count": len(actual_systemd),
            },
        )
    candidates = [pyproject]
    for package_root in package_roots:
        candidates.extend(sorted(package_root.rglob("*.py")))
    candidates.extend(scheduler_paths)
    paths: dict[str, Path] = {}
    for candidate in candidates:
        try:
            linked = candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise BureauLeaseContractError(
                "contract-managed-package-file-unavailable",
                details={"error_type": type(exc).__name__},
            ) from None
        if (
            stat.S_ISLNK(linked.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or resolved != candidate
            or not _path_is_within(resolved, release_root)
        ):
            raise BureauLeaseContractError(
                "contract-managed-package-file-invalid",
                details={"relative_path": candidate.relative_to(release_root).as_posix()},
            )
        paths[candidate.relative_to(release_root).as_posix()] = resolved
    return paths


def _managed_package_snapshot(
    paths: dict[str, Path],
    *,
    include_executable_marker: bool = False,
    preserve_order: bool = False,
) -> tuple[str, dict[str, dict[str, Any]]]:
    digest = hashlib.sha256()
    identities: dict[str, dict[str, Any]] = {}
    relatives = paths if preserve_order else sorted(paths)
    for relative in relatives:
        identity, content = _regular_file_snapshot(
            paths[relative], label="contract-package-file"
        )
        identities[relative] = identity
        raw_relative = relative.encode("utf-8")
        digest.update(len(raw_relative).to_bytes(4, "big"))
        digest.update(raw_relative)
        if include_executable_marker:
            digest.update(b"x" if identity["mode"] & 0o111 else b"-")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest(), identities


def _managed_package_tree_sha256(
    paths: dict[str, Path], *, include_executable_marker: bool = False
) -> str:
    digest, _identities = _managed_package_snapshot(
        paths, include_executable_marker=include_executable_marker
    )
    return digest


def _managed_package_contract(
    release_root: Path, expected_sha256: str
) -> tuple[str, bool, dict[str, Path], dict[str, dict[str, Any]]]:
    legacy_error: BureauLeaseContractError | None = None
    try:
        legacy_paths = _managed_package_paths(release_root)
        legacy_sha256, legacy_identities = _managed_package_snapshot(legacy_paths)
    except BureauLeaseContractError as exc:
        legacy_error = exc
        legacy_paths = {}
        legacy_sha256 = ""
        legacy_identities = {}
    if legacy_sha256 == expected_sha256:
        return "legacy-python-package-v1", False, legacy_paths, legacy_identities
    cycle_error: BureauLeaseContractError | None = None
    try:
        cycle_paths = _managed_bureau_cycle_package_paths(release_root)
        cycle_sha256, cycle_identities = _managed_package_snapshot(
            cycle_paths,
            include_executable_marker=True,
            preserve_order=True,
        )
    except BureauLeaseContractError as exc:
        cycle_error = exc
    else:
        if cycle_sha256 == expected_sha256:
            return "bureau-cycle-systemd-v2", True, cycle_paths, cycle_identities
    try:
        scheduler_paths = _managed_bureau_scheduler_package_paths(release_root)
        scheduler_sha256, scheduler_identities = _managed_package_snapshot(
            scheduler_paths,
            include_executable_marker=True,
            preserve_order=True,
        )
    except BureauLeaseContractError:
        if legacy_error is not None and cycle_error is not None:
            raise legacy_error from None
        raise BureauLeaseContractError("contract-managed-package-digest-invalid") from None
    if scheduler_sha256 != expected_sha256:
        raise BureauLeaseContractError("contract-managed-package-digest-invalid")
    return (
        "bureau-scheduler-fragments-v3",
        True,
        scheduler_paths,
        scheduler_identities,
    )


def _literal_launcher_assignment(tree: ast.Module, name: str) -> ast.expr:
    matches: list[ast.expr] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            matches.append(node.value)
    if len(matches) != 1:
        raise BureauLeaseContractError(
            "contract-managed-launcher-binding-invalid",
            details={"assignment": name, "count": len(matches)},
        )
    return matches[0]


def _parse_managed_launcher_binding(
    launcher_raw: bytes, launcher_path: Path
) -> tuple[Path, str]:
    if _MANAGED_LAUNCHER_MARKER not in launcher_raw[:512]:
        raise BureauLeaseContractError(
            "contract-managed-launcher-binding-invalid",
            details={"reason": "marker-missing"},
        )
    try:
        launcher_text = launcher_raw.decode("utf-8")
        tree = ast.parse(launcher_text, filename=str(launcher_path), mode="exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise BureauLeaseContractError(
            "contract-managed-launcher-binding-invalid",
            details={"reason": "syntax-invalid", "error_type": type(exc).__name__},
        ) from None
    manifest_expr = _literal_launcher_assignment(tree, "manifest_path")
    digest_expr = _literal_launcher_assignment(tree, "expected_manifest_sha256")
    if not (
        isinstance(manifest_expr, ast.Call)
        and isinstance(manifest_expr.func, ast.Name)
        and manifest_expr.func.id == "Path"
        and len(manifest_expr.args) == 1
        and not manifest_expr.keywords
        and isinstance(manifest_expr.args[0], ast.Constant)
        and isinstance(manifest_expr.args[0].value, str)
    ):
        raise BureauLeaseContractError(
            "contract-managed-launcher-binding-invalid",
            details={"reason": "manifest-path-expression-invalid"},
        )
    if not (
        isinstance(digest_expr, ast.Constant)
        and isinstance(digest_expr.value, str)
        and _SHA256_RE.fullmatch(digest_expr.value)
    ):
        raise BureauLeaseContractError(
            "contract-managed-launcher-binding-invalid",
            details={"reason": "manifest-digest-expression-invalid"},
        )
    return Path(manifest_expr.args[0].value), digest_expr.value


def _managed_contract_runtime() -> dict[str, Any]:
    manifest_path = BUREAU_RUNTIME_ROOT / "deployment-manifest.json"
    manifest_identity, manifest_raw = _regular_file_snapshot(
        manifest_path, label="contract-runtime-manifest"
    )
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BureauLeaseContractError(
            "contract-runtime-manifest-invalid",
            details={"error_type": type(exc).__name__},
        ) from None
    if not isinstance(manifest, dict):
        raise BureauLeaseContractError("contract-runtime-manifest-invalid")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("kind") != "bureau_runtime_deployment"
    ):
        raise BureauLeaseContractError("contract-runtime-manifest-contract-invalid")
    source_commit = manifest.get("source_commit")
    release_id = manifest.get("release_id")
    if (
        not isinstance(source_commit, str)
        or _EXPECTED_HEAD_RE.fullmatch(source_commit) is None
        or not isinstance(release_id, str)
        or not release_id.startswith(f"{source_commit[:12]}-src")
    ):
        raise BureauLeaseContractError("contract-runtime-manifest-identity-invalid")
    try:
        runtime_root = BUREAU_RUNTIME_ROOT.resolve(strict=True)
        configured = BUREAU_MANAGED_LAUNCHER
        executable = configured.resolve(strict=True)
        release_value = Path(manifest["immutable_release_path"])
        module_value = Path(manifest["module_path"])
        launcher_value = Path(manifest["launcher_path"])
        if not all(
            value.is_absolute()
            for value in (release_value, module_value, launcher_value)
        ):
            raise BureauLeaseContractError(
                "contract-managed-runtime-path-not-absolute"
            )
        release_root = release_value.resolve(strict=True)
        module_path = module_value.resolve(strict=True)
        configured_manifest_path = launcher_value.resolve(strict=True)
        python_launcher = BUREAU_CONTRACT_PYTHON
        python_interpreter = python_launcher.resolve(strict=True)
        python_environment = python_launcher.parent.parent / "pyvenv.cfg"
    except (OSError, KeyError, TypeError) as exc:
        raise BureauLeaseContractError(
            "contract-managed-runtime-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    releases_root = runtime_root / "releases"
    if (
        BUREAU_RUNTIME_ROOT.is_symlink()
        or runtime_root != BUREAU_RUNTIME_ROOT
        or configured.is_symlink()
        or executable != configured
        or launcher_value.is_symlink()
        or configured_manifest_path != launcher_value
        or configured_manifest_path != executable
        or release_value.is_symlink()
        or release_root != release_value
        or release_root.parent != releases_root
        or release_root.name != release_id
        or module_value.is_symlink()
        or module_path != module_value
        or module_path != release_root / "src/bureau/runtime_identity.py"
        or not _path_is_within(module_path, release_root)
        or not os.access(executable, os.X_OK)
        or not python_launcher.is_absolute()
        or not os.access(python_launcher, os.X_OK)
        or python_environment.is_symlink()
        or not python_environment.is_file()
    ):
        raise BureauLeaseContractError("contract-managed-runtime-path-invalid")
    module_identity, module_raw = _regular_file_snapshot(
        module_path, label="contract-bureau-runtime-identity"
    )
    module_sha256 = manifest.get("module_sha256")
    if (
        not isinstance(module_sha256, str)
        or hashlib.sha256(module_raw).hexdigest() != module_sha256
    ):
        raise BureauLeaseContractError("contract-managed-module-digest-invalid")
    launcher_identity, launcher_raw = _regular_file_snapshot(
        executable, label="contract-contract-executable"
    )
    configured_manifest, configured_manifest_sha256 = (
        _parse_managed_launcher_binding(launcher_raw, executable)
    )
    expected_manifest_sha256 = manifest_identity["sha256"]
    if (
        configured_manifest != manifest_path
        or configured_manifest_sha256 != expected_manifest_sha256
    ):
        raise BureauLeaseContractError(
            "contract-managed-launcher-binding-invalid",
            details={"reason": "manifest-binding-mismatch"},
        )
    package_tree_sha256 = manifest.get("package_tree_sha256")
    if not isinstance(package_tree_sha256, str):
        raise BureauLeaseContractError("contract-managed-package-digest-invalid")
    (
        managed_package_contract,
        managed_package_executable_marker,
        package_paths,
        package_identities,
    ) = _managed_package_contract(release_root, package_tree_sha256)
    component_paths = {
        "contract_executable": executable,
        "runtime_manifest": manifest_path,
        "python_interpreter": python_interpreter,
        "python_environment": python_environment,
        "bureau_runtime_identity": module_path,
    }
    identities = {
        "contract_executable": launcher_identity,
        "runtime_manifest": manifest_identity,
        "python_interpreter": _regular_file_identity(
            python_interpreter, label="contract-python-interpreter"
        ),
        "python_environment": _regular_file_identity(
            python_environment, label="contract-python-environment"
        ),
        "bureau_runtime_identity": module_identity,
    }
    return {
        "runtime_kind": "managed-manifest",
        "configured": configured,
        "configured_target": executable,
        "release_root": release_root,
        "release_commit": source_commit,
        "python_launcher": python_launcher,
        "python_launcher_target": python_interpreter,
        "module_paths": {},
        "component_paths": component_paths,
        "identities": identities,
        "package_paths": package_paths,
        "package_identities": package_identities,
        "managed_package_tree_sha256": package_tree_sha256,
        "managed_package_contract": managed_package_contract,
        "managed_package_executable_marker": managed_package_executable_marker,
    }


def _contract_runtime() -> dict[str, Any]:
    manifest_path = BUREAU_RUNTIME_ROOT / "deployment-manifest.json"
    if manifest_path.exists():
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise BureauLeaseContractError("contract-runtime-manifest-not-regular")
        return _managed_contract_runtime()
    return _legacy_contract_runtime()


def _descriptor_identity(descriptor: int) -> dict[str, Any]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise BureauLeaseContractError("contract-launcher-descriptor-not-regular")
    digest = hashlib.sha256()
    offset = 0
    while offset < metadata.st_size:
        chunk = os.pread(descriptor, min(65536, metadata.st_size - offset), offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if offset != metadata.st_size:
        raise BureauLeaseContractError("contract-launcher-descriptor-short-read")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": digest.hexdigest(),
    }


def _open_bound_launcher(runtime: dict[str, Any]) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise BureauLeaseContractError("contract-launcher-nofollow-unavailable")
    try:
        descriptor = os.open(
            runtime["configured"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError as exc:
        raise BureauLeaseContractError(
            "contract-launcher-open-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    try:
        observed = _descriptor_identity(descriptor)
        expected = runtime["identities"]["contract_executable"]
        for key in ("device", "inode", "size", "mtime_ns", "sha256"):
            if observed[key] != expected[key]:
                raise BureauLeaseContractError("contract-launcher-descriptor-mismatch")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _legacy_contract_runtime() -> dict[str, Any]:
    configured = BUREAU_CONTRACT_EXECUTABLE
    if not configured.is_absolute():
        raise BureauLeaseContractError("contract-executable-not-absolute")
    try:
        executable = configured.resolve(strict=True)
        runtime_root = BUREAU_RUNTIME_ROOT.resolve(strict=True)
    except OSError as exc:
        raise BureauLeaseContractError(
            "contract-executable-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    release_root = executable.parent.parent
    release_match = _RELEASE_DIRECTORY_RE.fullmatch(release_root.name)
    if (
        release_match is None
        or release_root.parent != runtime_root
        or executable != release_root / "bin/bureau"
    ):
        raise BureauLeaseContractError("contract-release-path-invalid")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise BureauLeaseContractError("contract-executable-not-executable")

    try:
        first_line = executable.read_bytes().splitlines()[0].decode("utf-8")
    except (OSError, UnicodeDecodeError, IndexError):
        raise BureauLeaseContractError("contract-executable-shebang-invalid") from None
    python_launcher = release_root / "bin/python3"
    if first_line != f"#!{python_launcher}":
        raise BureauLeaseContractError("contract-executable-shebang-mismatch")
    try:
        python_interpreter = python_launcher.resolve(strict=True)
    except OSError as exc:
        raise BureauLeaseContractError(
            "contract-python-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if not os.access(python_launcher, os.X_OK):
        raise BureauLeaseContractError("contract-python-not-executable")

    module_paths = {
        name: _contract_module_path(release_root, name)
        for name in _CONTRACT_MODULE_NAMES
    }
    package_paths = _contract_package_paths(release_root)
    component_paths = {
        "contract_executable": executable,
        "python_interpreter": python_interpreter,
        "pyvenv_config": release_root / "pyvenv.cfg",
        **{name.replace(".", "_"): path for name, path in module_paths.items()},
    }
    identities = {
        name: _regular_file_identity(path, label=f"contract-{name.replace('_', '-')}")
        for name, path in component_paths.items()
    }
    package_identities = {
        relative: _regular_file_identity(path, label="contract-package-file")
        for relative, path in package_paths.items()
    }
    try:
        configured_target = configured.resolve(strict=True)
        launcher_target = python_launcher.resolve(strict=True)
    except OSError as exc:
        raise BureauLeaseContractError(
            "contract-runtime-link-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    return {
        "runtime_kind": "legacy-venv",
        "configured": configured,
        "configured_target": configured_target,
        "release_root": release_root,
        "release_commit": release_match.group("commit"),
        "python_launcher": python_launcher,
        "python_launcher_target": launcher_target,
        "module_paths": module_paths,
        "component_paths": component_paths,
        "identities": identities,
        "package_paths": package_paths,
        "package_identities": package_identities,
    }


def _assert_contract_runtime_unchanged(runtime: dict[str, Any]) -> None:
    try:
        configured_target = runtime["configured"].resolve(strict=True)
        launcher_target = runtime["python_launcher"].resolve(strict=True)
    except OSError as exc:
        raise BureauLeaseContractError(
            "contract-runtime-readback-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    if configured_target != runtime["configured_target"]:
        raise BureauLeaseContractError("contract-release-changed-during-check")
    if launcher_target != runtime["python_launcher_target"]:
        raise BureauLeaseContractError("contract-python-changed-during-check")
    for name, path in runtime["component_paths"].items():
        observed = _regular_file_identity(
            path, label=f"contract-{name.replace('_', '-')}-readback"
        )
        if observed != runtime["identities"][name]:
            raise BureauLeaseContractError(
                "contract-component-changed-during-check", details={"component": name}
            )
    if runtime["runtime_kind"] == "managed-manifest":
        managed_package_contract = runtime["managed_package_contract"]
        if managed_package_contract == "legacy-python-package-v1":
            observed_paths = _managed_package_paths(runtime["release_root"])
        elif managed_package_contract == "bureau-cycle-systemd-v2":
            observed_paths = _managed_bureau_cycle_package_paths(
                runtime["release_root"]
            )
        elif managed_package_contract == "bureau-scheduler-fragments-v3":
            observed_paths = _managed_bureau_scheduler_package_paths(
                runtime["release_root"]
            )
        else:
            raise BureauLeaseContractError("contract-managed-package-contract-invalid")
        if set(observed_paths) != set(runtime["package_paths"]):
            raise BureauLeaseContractError(
                "contract-package-set-changed-during-check"
            )
        observed_digest, observed_identities = _managed_package_snapshot(
            observed_paths,
            include_executable_marker=runtime["managed_package_executable_marker"],
            preserve_order=(
                managed_package_contract
                in {"bureau-cycle-systemd-v2", "bureau-scheduler-fragments-v3"}
            ),
        )
        if observed_digest != runtime["managed_package_tree_sha256"]:
            raise BureauLeaseContractError(
                "contract-package-tree-changed-during-check"
            )
        for relative, observed in observed_identities.items():
            if observed != runtime["package_identities"][relative]:
                raise BureauLeaseContractError(
                    "contract-package-changed-during-check",
                    details={"relative_path": relative},
                )
    else:
        for relative, path in runtime["package_paths"].items():
            observed = _regular_file_identity(
                path, label="contract-package-file-readback"
            )
            if observed != runtime["package_identities"][relative]:
                raise BureauLeaseContractError(
                    "contract-package-changed-during-check",
                    details={"relative_path": relative},
                )


def _json_object(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise BureauLeaseContractError(
            "contract-output-invalid-json",
            details={"stdout_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()},
        ) from None
    if not isinstance(value, dict):
        raise BureauLeaseContractError("contract-output-not-object")
    return value


def _contract_payload(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("kind") == CONTRACT_KIND:
        return value
    expected_keys = {"schema_version", "result", "runtime_identity"}
    if set(value) != expected_keys:
        raise BureauLeaseContractError(
            "contract-envelope-shape-invalid",
            details={
                "missing_keys": sorted(expected_keys - set(value)),
                "extra_keys": sorted(set(value) - expected_keys),
            },
        )
    if value.get("schema_version") != 1:
        raise BureauLeaseContractError("contract-envelope-schema-version-mismatch")
    result = value.get("result")
    if not isinstance(result, dict):
        raise BureauLeaseContractError("contract-envelope-result-invalid")
    identity = value.get("runtime_identity")
    if not isinstance(identity, dict) or identity.get("schema_version") != 1:
        raise BureauLeaseContractError("contract-runtime-identity-invalid")
    if identity.get("kind") != "bureau_runtime_identity":
        raise BureauLeaseContractError("contract-runtime-identity-kind-mismatch")
    manifest = identity.get("manifest")
    if not isinstance(manifest, dict) or manifest.get("valid") is not True:
        raise BureauLeaseContractError("contract-runtime-manifest-invalid")
    source_commit = manifest.get("source_commit")
    if (
        not isinstance(source_commit, str)
        or _EXPECTED_HEAD_RE.fullmatch(source_commit) is None
    ):
        raise BureauLeaseContractError("contract-runtime-source-commit-invalid")
    registry = identity.get("registry")
    registry_valid = (
        isinstance(registry, dict)
        and registry.get("available") is True
        and registry.get("bureau_project") is True
        and registry.get("dirty") is False
        and registry.get("role") == "canonical-runtime-snapshot"
        and registry.get("head_equals_origin_main") is True
        and registry.get("head") == source_commit
        and registry.get("origin_main") == source_commit
    )
    if not registry_valid:
        raise BureauLeaseContractError("contract-runtime-registry-invalid")
    return result


def enforce_bureau_lease_contract(
    resource_keys: Iterable[str],
    *,
    ttl_seconds: int,
    metadata: dict[str, Any] | None,
) -> dict[str, Any] | None:
    keys = bureau_resource_keys(resource_keys)
    if not keys:
        return None
    phase = _phase(keys, metadata)
    justification = _bounded_text(
        metadata, "bureau_justification", maximum_bytes=512
    )
    expected_head = _bounded_text(
        metadata, "bureau_expected_head", maximum_bytes=128
    )
    expected_state = _bounded_text(
        metadata, "bureau_expected_state", maximum_bytes=512
    )
    if phase in {"merge", "worktree-admin", "emergency-recovery"}:
        if ttl_seconds > MAX_EFFECT_GATE_TTL_SECONDS:
            raise BureauLeaseContractError(
                "effect-gate-ttl-exceeds-maximum",
                details={"maximum_ttl_seconds": MAX_EFFECT_GATE_TTL_SECONDS},
            )
    if phase == "emergency-recovery":
        if keys != [BROAD_BUREAU_REPOSITORY_KEY]:
            raise BureauLeaseContractError(
                "emergency-recovery-requires-broad-repository-key"
            )
        if justification is None:
            raise BureauLeaseContractError(
                "emergency-recovery-justification-required"
            )
        if expected_head is None and expected_state is None:
            raise BureauLeaseContractError(
                "emergency-recovery-boundary-required"
            )
    runtime = _contract_runtime()
    component_sha256 = {
        name: identity["sha256"]
        for name, identity in runtime["identities"].items()
    }
    contract_arguments = ["--json", "lease-contract"]
    for key in keys:
        contract_arguments.extend(["--resource-key", key])
    contract_arguments.extend(["--phase", phase, "--ttl-seconds", str(ttl_seconds)])
    if justification is not None:
        contract_arguments.extend(["--justification", _sha256_token(justification)])
    if expected_head is not None:
        contract_arguments.extend(["--expected-head", expected_head])
    if expected_state is not None:
        contract_arguments.extend(["--expected-state", _sha256_token(expected_state)])
    descriptor = -1
    try:
        if runtime["runtime_kind"] == "legacy-venv":
            wrapper_binding = json.dumps(
                {
                    "module_paths": {
                        name: str(path) for name, path in runtime["module_paths"].items()
                    },
                    "package_files": {
                        relative: {
                            "path": str(runtime["package_paths"][relative]),
                            "sha256": identity["sha256"],
                        }
                        for relative, identity in runtime["package_identities"].items()
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            argv = [
                str(runtime["python_launcher"]),
                "-I",
                "-c",
                _CONTRACT_WRAPPER,
                wrapper_binding,
                *contract_arguments,
            ]
            pass_fds: tuple[int, ...] = ()
        else:
            descriptor = _open_bound_launcher(runtime)
            argv = [
                str(runtime["python_launcher"]),
                "-I",
                f"/proc/self/fd/{descriptor}",
                *contract_arguments,
            ]
            pass_fds = (descriptor,)
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=CONTRACT_TIMEOUT_SECONDS,
            env=_safe_environment(),
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BureauLeaseContractError(
            "contract-invocation-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _assert_contract_runtime_unchanged(runtime)
    stdout_sha256 = hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest()
    stderr_sha256 = hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest()
    if completed.returncode != 0:
        raise BureauLeaseContractError(
            "contract-command-failed",
            details={
                "returncode": completed.returncode,
                "stdout_sha256": stdout_sha256,
                "stderr_sha256": stderr_sha256,
            },
        )
    output = _json_object(completed.stdout)
    value = _contract_payload(output)
    if value.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise BureauLeaseContractError("contract-schema-version-mismatch")
    if value.get("kind") != CONTRACT_KIND:
        raise BureauLeaseContractError("contract-kind-mismatch")
    returned_keys = value.get("resource_keys")
    if returned_keys != keys:
        raise BureauLeaseContractError("contract-resource-set-mismatch")
    if value.get("phase") != phase:
        raise BureauLeaseContractError("contract-phase-mismatch")
    if value.get("ttl_seconds") != ttl_seconds:
        raise BureauLeaseContractError("contract-ttl-mismatch")
    if value.get("required_merge_gate") != BUREAU_MERGE_GATE_KEY:
        raise BureauLeaseContractError("contract-merge-gate-mismatch")
    if value.get("required_worktree_admin_gate") != BUREAU_WORKTREE_ADMIN_KEY:
        raise BureauLeaseContractError("contract-worktree-admin-gate-mismatch")
    if value.get("global_repo_lease") != BROAD_BUREAU_REPOSITORY_KEY:
        raise BureauLeaseContractError("contract-global-repo-key-mismatch")
    expected_state_token = _sha256_token(expected_state) if expected_state else None
    expected_boundary_present = bool(
        expected_state_token
        or (expected_head is not None and _EXPECTED_HEAD_RE.fullmatch(expected_head))
    )
    if value.get("justification_present") is not (justification is not None):
        raise BureauLeaseContractError("contract-justification-binding-mismatch")
    if value.get("expected_head") != expected_head:
        raise BureauLeaseContractError("contract-expected-head-mismatch")
    if value.get("expected_state") != expected_state_token:
        raise BureauLeaseContractError("contract-expected-state-mismatch")
    if value.get("expected_boundary_present") is not expected_boundary_present:
        raise BureauLeaseContractError("contract-expected-boundary-mismatch")
    findings = value.get("findings")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise BureauLeaseContractError("contract-findings-invalid")
    finding_codes = []
    for item in findings:
        code = item.get("code")
        if not isinstance(code, str) or not code:
            raise BureauLeaseContractError("contract-finding-code-invalid")
        finding_codes.append(code)
    if value.get("healthy") is not True:
        raise BureauLeaseContractError(
            "contract-unhealthy",
            details={"finding_codes": sorted(set(finding_codes))},
        )
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "kind": CONTRACT_KIND,
        "phase": phase,
        "resource_keys": keys,
        "ttl_seconds": ttl_seconds,
        "finding_codes": sorted(set(finding_codes)),
        "contract_stdout_sha256": stdout_sha256,
        "contract_release_commit": runtime["release_commit"],
        "contract_component_sha256": component_sha256,
        "contract_package_sha256": _package_sha256(runtime["package_identities"]),
        "contract_package_file_count": len(runtime["package_identities"]),
        "contract_executable_sha256": component_sha256["contract_executable"],
    }


def enforce_bureau_lease_renewal(
    resource_keys: Iterable[str], *, ttl_seconds: int
) -> dict[str, Any] | None:
    keys = bureau_resource_keys(resource_keys)
    if not keys:
        return None
    forbidden = sorted(
        set(keys)
        & {
            BROAD_BUREAU_REPOSITORY_KEY,
            BUREAU_MERGE_GATE_KEY,
            BUREAU_WORKTREE_ADMIN_KEY,
        }
    )
    if forbidden:
        raise BureauLeaseContractError(
            "bureau-effect-lease-renewal-forbidden",
            details={"resource_keys": forbidden},
        )
    return enforce_bureau_lease_contract(
        keys, ttl_seconds=ttl_seconds, metadata=None
    )
