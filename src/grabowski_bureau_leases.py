from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Iterable

BUREAU_REPOSITORY_ROOT = Path("/home/alex/repos/bureau")
BUREAU_WORKTREE_ROOT = Path("/home/alex/repos/.bureau-worktrees")
BUREAU_RUNTIME_ROOT = Path("/home/alex/.local/share/bureau")
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
MAX_EFFECT_GATE_TTL_SECONDS = 300
_ALLOWED_PHASES = {"work", "worktree-admin", "merge", "emergency-recovery"}
_RELEASE_DIRECTORY_RE = re.compile(r"^venv-(?P<commit>[0-9a-f]{40})$")
_EXPECTED_HEAD_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
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


def _regular_file_identity(path: Path, *, label: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as exc:
        raise BureauLeaseContractError(
            f"{label}-unavailable",
            details={"error_type": type(exc).__name__},
        ) from None
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise BureauLeaseContractError(f"{label}-not-regular")
    return {
        "path": str(path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


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

def _contract_runtime() -> dict[str, Any]:
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
    for relative, path in runtime["package_paths"].items():
        observed = _regular_file_identity(path, label="contract-package-file-readback")
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
    runtime = _contract_runtime()
    component_sha256 = {
        name: identity["sha256"]
        for name, identity in runtime["identities"].items()
    }
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
        "--json",
        "lease-contract",
    ]
    for key in keys:
        argv.extend(["--resource-key", key])
    argv.extend(["--phase", phase, "--ttl-seconds", str(ttl_seconds)])
    if justification is not None:
        argv.extend(["--justification", _sha256_token(justification)])
    if expected_head is not None:
        argv.extend(["--expected-head", expected_head])
    if expected_state is not None:
        argv.extend(["--expected-state", _sha256_token(expected_state)])
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=CONTRACT_TIMEOUT_SECONDS,
            env=_safe_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BureauLeaseContractError(
            "contract-invocation-failed",
            details={"error_type": type(exc).__name__},
        ) from None
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
    value = _json_object(completed.stdout)
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
