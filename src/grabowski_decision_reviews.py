from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterator

import grabowski_job_origin as job_origin
import grabowski_coding_agent_catalog_data as catalog_data


STATE_ROOT = Path.home() / ".local" / "state" / "grabowski"
JOBS_ROOT = STATE_ROOT / "jobs"
LOCKS_ROOT = STATE_ROOT / "decision-review-locks"
BINDING_KIND = "grabowski_decision_bound_review"
BINDING_SCHEMA_VERSION = 1
RESULT_KIND = "grabowski_decision_bound_review_result"
RESULT_SCHEMA_VERSION = 1
RESULT_PREFIX = "GRABOWSKI_DECISION_REVIEW_V1="
MAX_JOB_DIRECTORIES = 10_000
MAX_METADATA_BYTES = 256 * 1024
MAX_FINALIZATION_BYTES = 256 * 1024
MAX_STDOUT_TAIL_BYTES = 256 * 1024
MAX_ROLE_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_REVIEW_ROLE_MODULE_BYTES = 1024 * 1024
REVIEW_ROLE_MODULE = "grabowski_agent_role"
REVIEW_ROLE_SANDBOX = "bubblewrap-minimal-root-read-only-worktree-v1"
REVIEW_ROLE_PYTHON = os.path.abspath(sys.executable)
REVIEW_ROLE_RELEASE_ROOT = Path.home() / ".local/share/grabowski-mcp-releases"
REVIEW_ROLE_LAUNCHER_PREFIX = (
    REVIEW_ROLE_PYTHON,
    "-I",
    "-m",
    REVIEW_ROLE_MODULE,
)
_REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SLOT_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")
_UNIT_RE = re.compile(r"grabowski-job-([0-9a-f]{12})\Z")
_REVIEW_ROLE_RELEASE_ID_RE = re.compile(
    r"[0-9a-f]{12}-srcset[0-9a-f]{12}-lock[0-9a-f]{12}-contract[0-9a-f]{12}"
    r"(?:-attempt[1-9][0-9]{0,2})?\Z"
)
_REVIEW_ROLE_PYTHON_DIR_RE = re.compile(r"python[0-9]+\.[0-9]+\Z")
_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "repo",
        "pr",
        "head_sha",
        "base_sha",
        "diff_sha256",
        "slot",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "repo",
        "pr",
        "head_sha",
        "base_sha",
        "diff_sha256",
        "slot",
        "verdict",
        "material_findings",
    }
)
_TERMINAL_STATUSES = frozenset(
    {"succeeded", "failed", "timed_out", "signalled", "terminated_unclear"}
)
_PRE_RESULT_INFRASTRUCTURE_STATUSES = frozenset(
    {"failed", "timed_out", "signalled", "terminated_unclear"}
)
_VERDICTS = frozenset({"PASS_THIS_REVISION", "REJECT_THIS_REVISION"})


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _agent_role_command_sha256(value: Any) -> str:
    """Match grabowski_agent_role.digest for cross-module argv receipts."""
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _review_role_module_identity() -> tuple[str, str] | None:
    """Bind reviewer provenance to the server-installed role module bytes."""
    module_path = Path(__file__).with_name(f"{REVIEW_ROLE_MODULE}.py")
    try:
        metadata = module_path.lstat()
        payload = module_path.read_bytes()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        return None
    return (
        str(module_path.resolve(strict=False)),
        hashlib.sha256(payload).hexdigest(),
    )


def _historical_review_role_module_matches(
    value: Any, *, expected_sha256: str
) -> bool:
    """Accept immutable prior-release role modules only when bytes still match."""

    if (
        not isinstance(value, str)
        or not value
        or not isinstance(expected_sha256, str)
        or _SHA256_RE.fullmatch(expected_sha256) is None
    ):
        return False
    path = Path(value).expanduser()
    if not path.is_absolute():
        return False
    try:
        root_path = REVIEW_ROLE_RELEASE_ROOT.expanduser()
        if root_path.is_symlink():
            return False
        root_metadata = root_path.stat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
        ):
            return False
        root = root_path.resolve(strict=True)
        resolved = path.resolve(strict=True)
        if resolved != path:
            return False
        relative = resolved.relative_to(root)
        metadata = resolved.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or metadata.st_size > MAX_REVIEW_ROLE_MODULE_BYTES
        ):
            return False
        payload = resolved.read_bytes()
    except (FileNotFoundError, OSError, ValueError):
        return False

    parts = relative.parts
    if (
        len(parts) != 6
        or _REVIEW_ROLE_RELEASE_ID_RE.fullmatch(parts[0]) is None
        or parts[1:3] != (".venv", "lib")
        or _REVIEW_ROLE_PYTHON_DIR_RE.fullmatch(parts[3]) is None
        or parts[4:] != ("site-packages", f"{REVIEW_ROLE_MODULE}.py")
    ):
        return False
    return hmac.compare_digest(hashlib.sha256(payload).hexdigest(), expected_sha256)


def normalize_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
        raise ValueError("decision review binding has an invalid shape")
    if value.get("schema_version") != BINDING_SCHEMA_VERSION or isinstance(
        value.get("schema_version"), bool
    ):
        raise ValueError("decision review binding schema_version must be integer 1")
    if value.get("kind") != BINDING_KIND:
        raise ValueError(f"decision review binding kind must be {BINDING_KIND}")
    repo = value.get("repo")
    if not isinstance(repo, str) or _REPO_RE.fullmatch(repo.strip()) is None:
        raise ValueError("decision review repo must have owner/repo form")
    pr = value.get("pr")
    if isinstance(pr, bool) or not isinstance(pr, int) or pr <= 0:
        raise ValueError("decision review pr must be a positive integer")
    head_sha = value.get("head_sha")
    base_sha = value.get("base_sha")
    diff_sha256 = value.get("diff_sha256")
    if not isinstance(head_sha, str) or _SHA40_RE.fullmatch(head_sha.lower()) is None:
        raise ValueError("decision review head_sha must be a 40 character SHA")
    if not isinstance(base_sha, str) or _SHA40_RE.fullmatch(base_sha.lower()) is None:
        raise ValueError("decision review base_sha must be a 40 character SHA")
    if not isinstance(diff_sha256, str) or _SHA256_RE.fullmatch(diff_sha256.lower()) is None:
        raise ValueError("decision review diff_sha256 must be a 64 character SHA-256")
    slot = value.get("slot")
    if not isinstance(slot, str) or _SLOT_RE.fullmatch(slot.strip()) is None:
        raise ValueError("decision review slot must be a bounded identifier")
    return {
        "schema_version": BINDING_SCHEMA_VERSION,
        "kind": BINDING_KIND,
        "repo": repo.strip().lower(),
        "pr": pr,
        "head_sha": head_sha.lower(),
        "base_sha": base_sha.lower(),
        "diff_sha256": diff_sha256.lower(),
        "slot": slot.strip().lower(),
    }


def result_contract(binding: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_binding(binding)
    return {
        "prefix": RESULT_PREFIX,
        "required_result": {
            "schema_version": RESULT_SCHEMA_VERSION,
            "kind": RESULT_KIND,
            "repo": normalized["repo"],
            "pr": normalized["pr"],
            "head_sha": normalized["head_sha"],
            "base_sha": normalized["base_sha"],
            "diff_sha256": normalized["diff_sha256"],
            "slot": normalized["slot"],
            "verdict": "PASS_THIS_REVISION | REJECT_THIS_REVISION",
            "material_findings": "integer >= 0; PASS requires 0, REJECT requires >0",
        },
        "rule": (
            "emit exactly one final marker line; infrastructure failures may emit no marker, "
            "but every declared slot still requires a later successful PASS and any material "
            "REJECT remains merge-blocking"
        ),
    }


def _lock_key(binding: dict[str, Any]) -> str:
    normalized = normalize_binding(binding)
    return sha256_json(
        {
            "repo": normalized["repo"],
            "pr": normalized["pr"],
            "head_sha": normalized["head_sha"],
        }
    )


@contextmanager
def decision_review_lock(binding: dict[str, Any]) -> Iterator[None]:
    key = _lock_key(binding)
    root = LOCKS_ROOT
    if root.exists() and root.is_symlink():
        raise PermissionError("decision review lock root may not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / f"{key}.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_private_json(path: Path, max_bytes: int) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{path.name} is not one regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError(f"{path.name} must be private")
    if metadata.st_size > max_bytes:
        raise ValueError(f"{path.name} is too large")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must be an object")
    return value


def _read_stdout_tail(path: Path) -> tuple[str, str]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("stdout.log is not one regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("stdout.log must be private")
    if metadata.st_size > MAX_STDOUT_TAIL_BYTES:
        raise ValueError("stdout.log exceeds the decision review output limit")
    payload = path.read_bytes()
    if len(payload) > MAX_STDOUT_TAIL_BYTES:
        raise ValueError("stdout.log exceeds the decision review output limit")
    return payload.decode("utf-8", errors="replace"), hashlib.sha256(payload).hexdigest()


def _raw_binding_targets_pr_head(value: Any, expected: dict[str, Any]) -> bool:
    if not isinstance(value, dict):
        return False
    repo = value.get("repo")
    pr = value.get("pr")
    head_sha = value.get("head_sha")
    return (
        isinstance(repo, str)
        and repo.strip().lower() == expected["repo"]
        and isinstance(pr, int)
        and not isinstance(pr, bool)
        and pr == expected["pr"]
        and isinstance(head_sha, str)
        and head_sha.strip().lower() == expected["head_sha"]
    )


def _proven_not_started(metadata: dict[str, Any]) -> bool:
    terminalization = metadata.get("terminalization_evidence")
    launcher = metadata.get("launcher_evidence")
    return (
        metadata.get("final_status") == "launch_failed"
        and metadata.get("dispatch_outcome") == "not_started"
        and isinstance(terminalization, dict)
        and terminalization.get("source") == "systemd-run-launch"
        and terminalization.get("query_valid") is True
        and terminalization.get("final_status") == "launch_failed"
        and terminalization.get("systemd_visible") is False
        and isinstance(launcher, dict)
        and isinstance(launcher.get("returncode"), int)
        and not isinstance(launcher.get("returncode"), bool)
        and launcher["returncode"] != 0
    )


def _validated_origin_binding(directory: Path) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    unit = directory.name
    if _UNIT_RE.fullmatch(unit) is None:
        raise ValueError("job unit is invalid")
    metadata = _read_private_json(directory / "metadata.json", MAX_METADATA_BYTES)
    try:
        origin = job_origin.validate_origin(
            metadata.get("origin"),
            metadata.get("origin_sha256"),
            expected_unit=unit,
        )
    except ValueError as exc:
        raise ValueError(f"job origin invalid: {exc}") from exc
    for key in ("unit", "job_id", "owner", "argv_sha256", "scope"):
        if metadata.get(key) != origin.get(key):
            raise ValueError(f"job metadata {key} binding mismatch")
    scope = origin.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("job origin scope is invalid")
    raw_binding = scope.get("decision_bound_review")
    if raw_binding is None:
        return metadata, None, None
    binding = normalize_binding(raw_binding)
    origin_cwd = scope.get("cwd")
    if not isinstance(origin_cwd, str) or not origin_cwd:
        raise ValueError("job origin cwd is invalid")
    provenance = _normalize_review_role_provenance(
        scope.get("decision_review_provenance"), binding, cwd=origin_cwd
    )
    if provenance is None:
        exact_argv = metadata.get("argv")
        if (
            isinstance(exact_argv, list)
            and all(isinstance(item, str) for item in exact_argv)
            and sha256_json(exact_argv) == origin.get("argv_sha256")
        ):
            provenance = review_role_provenance(
                exact_argv, binding, cwd=Path(origin_cwd)
            )
    return metadata, binding, provenance


def _validated_finalization(directory: Path, metadata: dict[str, Any]) -> dict[str, Any] | None:
    path = directory / "finalization.json"
    try:
        receipt = _read_private_json(path, MAX_FINALIZATION_BYTES)
    except FileNotFoundError:
        return None
    payload_sha256 = receipt.get("payload_sha256")
    material = {key: value for key, value in receipt.items() if key != "payload_sha256"}
    expected_payload = sha256_json(material)
    if not isinstance(payload_sha256, str) or not hmac.compare_digest(
        payload_sha256, expected_payload
    ):
        raise ValueError("job finalization payload hash mismatch")
    status = receipt.get("final_status")
    if status not in _TERMINAL_STATUSES:
        raise ValueError("job finalization status is not terminal")
    if receipt.get("unit") != directory.name:
        raise ValueError("job finalization unit mismatch")
    if receipt.get("job_id") != metadata.get("job_id"):
        raise ValueError("job finalization job_id mismatch")
    if receipt.get("argv_sha256") != metadata.get("argv_sha256"):
        raise ValueError("job finalization argv hash mismatch")
    contract = metadata.get("finalization_contract")
    if not isinstance(contract, dict):
        raise ValueError("decision-bound review requires a finalization contract")
    if receipt.get("contract_sha256") != contract.get("contract_sha256"):
        raise ValueError("job finalization contract hash mismatch")
    return receipt


def _parse_result_marker(stdout_text: str, binding: dict[str, Any]) -> dict[str, Any] | None:
    marker_lines = [
        line[len(RESULT_PREFIX) :]
        for line in stdout_text.splitlines()
        if line.startswith(RESULT_PREFIX)
    ]
    if not marker_lines:
        return None
    if len(marker_lines) != 1:
        raise ValueError("decision review output must contain exactly one result marker")
    try:
        result = json.loads(marker_lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError("decision review result marker is invalid JSON") from exc
    if not isinstance(result, dict) or set(result) != _RESULT_FIELDS:
        raise ValueError("decision review result marker has an invalid shape")
    if result.get("schema_version") != RESULT_SCHEMA_VERSION or isinstance(
        result.get("schema_version"), bool
    ):
        raise ValueError("decision review result schema_version must be integer 1")
    if result.get("kind") != RESULT_KIND:
        raise ValueError(f"decision review result kind must be {RESULT_KIND}")
    expected = normalize_binding(binding)
    for key in ("repo", "pr", "head_sha", "base_sha", "diff_sha256", "slot"):
        actual = result.get(key)
        if isinstance(actual, str) and key in {"repo", "head_sha", "base_sha", "diff_sha256", "slot"}:
            actual = actual.strip().lower()
        if actual != expected[key]:
            raise ValueError(f"decision review result {key} mismatch")
    verdict = result.get("verdict")
    findings = result.get("material_findings")
    if verdict not in _VERDICTS:
        raise ValueError("decision review verdict is invalid")
    if isinstance(findings, bool) or not isinstance(findings, int) or findings < 0:
        raise ValueError("decision review material_findings must be an integer >= 0")
    if verdict == "PASS_THIS_REVISION" and findings != 0:
        raise ValueError("decision review PASS requires zero material findings")
    if verdict == "REJECT_THIS_REVISION" and findings <= 0:
        raise ValueError("decision review REJECT requires at least one material finding")
    return {
        **expected,
        "verdict": verdict,
        "material_findings": findings,
    }


def _agent_role_receipt_sha256(value: dict[str, Any]) -> str:
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    payload = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _review_route_evidence(command: list[str]) -> dict[str, Any] | None:
    try:
        catalog = json.loads(catalog_data.CATALOG_JSON)
    except (AttributeError, json.JSONDecodeError):
        return None
    routes = catalog.get("routes")
    models = catalog.get("models")
    if not isinstance(routes, list) or not isinstance(models, dict):
        return None
    matches: list[dict[str, Any]] = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        prefix = route.get("argv_prefix")
        if (
            route.get("enabled") is not True
            or route.get("review_only") is not True
            or route.get("contrast_only") is True
            or "independent-review" not in route.get("task_classes", [])
            or not isinstance(prefix, list)
            or not prefix
            or any(not isinstance(item, str) or not item for item in prefix)
            or len(command) != len(prefix) + 1
            or command[: len(prefix)] != prefix
            or not command[-1].strip()
            or command[-1].startswith("-")
        ):
            continue
        model_id = route.get("model")
        model = models.get(model_id) if isinstance(model_id, str) else None
        provider_family = model.get("provider_family") if isinstance(model, dict) else None
        route_id = route.get("id")
        independence_group = route.get("independence_group")
        if not all(
            isinstance(value, str) and value
            for value in (route_id, model_id, provider_family, independence_group)
        ):
            continue
        matches.append(
            {
                "route_id": route_id,
                "model": model_id,
                "provider_family": provider_family,
                "independence_group": independence_group,
                "argv_prefix_sha256": sha256_json(prefix),
            }
        )
    if len(matches) != 1:
        return None
    return matches[0]


def review_role_provenance(
    argv: list[str], binding: dict[str, Any], *, cwd: Path
) -> dict[str, Any] | None:
    """Derive server-owned reviewer provenance from the pre-redaction launch argv."""
    normalized = normalize_binding(binding)
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        return None
    if (
        len(argv) < 20
        or tuple(argv[:4]) != REVIEW_ROLE_LAUNCHER_PREFIX
        or argv.count("--") != 1
    ):
        return None
    separator = argv.index("--")
    options = argv[4:separator]
    required_order = [
        "--role",
        "--repository",
        "--expected-head",
        "--expected-base-head",
        "--expected-diff-sha256",
        "--expected-dirty",
        "--output",
    ]
    if len(options) != len(required_order) * 2 or options[::2] != required_order:
        return None
    values = dict(zip(options[::2], options[1::2], strict=True))
    if values["--role"] != "review":
        return None
    if values["--expected-head"].lower() != normalized["head_sha"]:
        return None
    if values["--expected-base-head"].lower() != normalized["base_sha"]:
        return None
    workspace_diff = values["--expected-diff-sha256"].lower()
    if _SHA256_RE.fullmatch(workspace_diff) is None or values["--expected-dirty"] != "false":
        return None
    repository = Path(values["--repository"]).expanduser()
    if not repository.is_absolute():
        repository = cwd / repository
    if repository.resolve(strict=False) != cwd.resolve(strict=False):
        return None
    output = Path(values["--output"]).expanduser()
    if not output.is_absolute():
        output = cwd / output
    reviewer_command = argv[separator + 1 :]
    if not reviewer_command:
        return None
    review_route = _review_route_evidence(reviewer_command)
    if review_route is None:
        return None
    module_identity = _review_role_module_identity()
    if module_identity is None:
        return None
    runner_module_path, runner_module_sha256 = module_identity
    material = {
        "schema_version": 1,
        "kind": "grabowski_decision_review_provenance",
        "role": "review",
        "runner_python": REVIEW_ROLE_PYTHON,
        "runner_isolated": True,
        "runner_module": REVIEW_ROLE_MODULE,
        "runner_module_path": runner_module_path,
        "runner_module_sha256": runner_module_sha256,
        "sandbox": REVIEW_ROLE_SANDBOX,
        "repository": str(repository.resolve(strict=False)),
        "head_sha": normalized["head_sha"],
        "base_sha": normalized["base_sha"],
        "workspace_diff_sha256": workspace_diff,
        "expected_dirty": False,
        "role_receipt_path": str(output.resolve(strict=False)),
        "reviewer_command_sha256": _agent_role_command_sha256(reviewer_command),
        "review_route": review_route,
        "binding_sha256": sha256_json(normalized),
    }
    return {**material, "provenance_sha256": sha256_json(material)}


def _normalize_review_role_provenance(
    value: Any, binding: dict[str, Any], *, cwd: str
) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("decision review provenance is invalid")
    required = {
        "schema_version", "kind", "role", "runner_python", "runner_isolated",
        "runner_module", "runner_module_path", "runner_module_sha256", "sandbox",
        "repository", "head_sha", "base_sha", "workspace_diff_sha256",
        "expected_dirty", "role_receipt_path", "reviewer_command_sha256",
        "review_route", "binding_sha256", "provenance_sha256",
    }
    if set(value) != required:
        raise ValueError("decision review provenance has an invalid shape")
    material = {key: item for key, item in value.items() if key != "provenance_sha256"}
    if value.get("provenance_sha256") != sha256_json(material):
        raise ValueError("decision review provenance digest mismatch")
    normalized = normalize_binding(binding)
    module_identity = _review_role_module_identity()
    if module_identity is None:
        raise ValueError("trusted decision review role module is unavailable")
    runner_module_path, runner_module_sha256 = module_identity
    recorded_module_path = value.get("runner_module_path")
    recorded_module_sha256 = value.get("runner_module_sha256")
    module_identity_matches = (
        recorded_module_sha256 == runner_module_sha256
        and (
            recorded_module_path == runner_module_path
            or _historical_review_role_module_matches(
                recorded_module_path,
                expected_sha256=runner_module_sha256,
            )
        )
    )
    if (
        value.get("schema_version") != 1
        or value.get("kind") != "grabowski_decision_review_provenance"
        or value.get("role") != "review"
        or value.get("runner_python") != REVIEW_ROLE_PYTHON
        or value.get("runner_isolated") is not True
        or value.get("runner_module") != REVIEW_ROLE_MODULE
        or not module_identity_matches
        or value.get("sandbox") != REVIEW_ROLE_SANDBOX
        or value.get("head_sha") != normalized["head_sha"]
        or value.get("base_sha") != normalized["base_sha"]
        or value.get("expected_dirty") is not False
        or value.get("binding_sha256") != sha256_json(normalized)
    ):
        raise ValueError("decision review provenance binding mismatch")
    repository = value.get("repository")
    receipt_path = value.get("role_receipt_path")
    workspace_diff = value.get("workspace_diff_sha256")
    command_sha = value.get("reviewer_command_sha256")
    route = value.get("review_route")
    if (
        not isinstance(repository, str)
        or Path(repository).resolve(strict=False) != Path(cwd).resolve(strict=False)
        or not isinstance(receipt_path, str)
        or not Path(receipt_path).is_absolute()
        or not isinstance(workspace_diff, str)
        or _SHA256_RE.fullmatch(workspace_diff) is None
        or not isinstance(command_sha, str)
        or _SHA256_RE.fullmatch(command_sha) is None
        or not isinstance(route, dict)
    ):
        raise ValueError("decision review provenance fields are invalid")
    for key in ("route_id", "model", "provider_family", "independence_group", "argv_prefix_sha256"):
        if not isinstance(route.get(key), str) or not route[key]:
            raise ValueError("decision review route provenance is invalid")
    return value


def _validated_review_role_evidence(
    metadata: dict[str, Any], binding: dict[str, Any], provenance: dict[str, Any] | None
) -> dict[str, Any] | None:
    if provenance is None:
        return None
    receipt = _read_private_json(Path(provenance["role_receipt_path"]), MAX_ROLE_RECEIPT_BYTES)
    expected_receipt_sha256 = _agent_role_receipt_sha256(receipt)
    if receipt.get("receipt_sha256") != expected_receipt_sha256:
        raise ValueError("decision review role receipt digest mismatch")
    workspace_diff = provenance["workspace_diff_sha256"]
    expected_fields = {
        "schema_version": 1,
        "role": "review",
        "expected_head": binding["head_sha"],
        "expected_base_head": binding["base_sha"],
        "expected_diff_sha256": workspace_diff,
        "expected_dirty": False,
        "head_before": binding["head_sha"],
        "head_after": binding["head_sha"],
        "diff_after": workspace_diff,
        "worktree_dirty_after": False,
        "sandbox": REVIEW_ROLE_SANDBOX,
        "review_receipt_generated_by": REVIEW_ROLE_MODULE,
        "argv_sha256": provenance["reviewer_command_sha256"],
    }
    for key, expected_value in expected_fields.items():
        if receipt.get(key) != expected_value:
            raise ValueError(f"decision review role receipt {key} mismatch")
    verdict = receipt.get("verdict")
    findings = receipt.get("findings")
    failure_classification = receipt.get("failure_classification")
    result: dict[str, Any] | None = None
    if verdict == "PASS" and findings == [] and receipt.get("returncode") == 0 and failure_classification == "passed":
        result = {**normalize_binding(binding), "verdict": "PASS_THIS_REVISION", "material_findings": 0}
    elif (
        verdict in {"NEEDS_CHANGE", "BLOCK"}
        and isinstance(findings, list) and findings
        and all(isinstance(item, dict) for item in findings)
        and failure_classification == "review_verdict"
    ):
        result = {**normalize_binding(binding), "verdict": "REJECT_THIS_REVISION", "material_findings": len(findings)}
    return {
        "role_verified": True,
        "route_verified": True,
        "independence_verified": True,
        "role_receipt_sha256": expected_receipt_sha256,
        "review_route": provenance["review_route"],
        "result": result,
    }


def _binding_matches_pr_head(
    binding: dict[str, Any], expected: dict[str, Any]
) -> bool:
    return (
        binding["repo"] == expected["repo"]
        and binding["pr"] == expected["pr"]
        and binding["head_sha"] == expected["head_sha"]
    )


def _attempt_started_after(candidate: dict[str, Any], prior: dict[str, Any]) -> bool:
    candidate_created = candidate.get("created_at_unix")
    prior_created = prior.get("created_at_unix")
    if (
        isinstance(candidate_created, bool)
        or not isinstance(candidate_created, int)
        or candidate_created < 0
        or isinstance(prior_created, bool)
        or not isinstance(prior_created, int)
        or prior_created < 0
    ):
        return False
    if candidate_created != prior_created:
        return candidate_created > prior_created

    candidate_ns = candidate.get("started_at_unix_ns")
    prior_ns = prior.get("started_at_unix_ns")
    if (
        isinstance(candidate_ns, bool)
        or not isinstance(candidate_ns, int)
        or candidate_ns < 0
        or isinstance(prior_ns, bool)
        or not isinstance(prior_ns, int)
        or prior_ns < 0
        or candidate_ns // 1_000_000_000 != candidate_created
        or prior_ns // 1_000_000_000 != prior_created
    ):
        return False
    return candidate_ns > prior_ns


def reconcile(
    *,
    repo: str,
    pr: int,
    head_sha: str,
    base_sha: str,
    diff_sha256: str,
    equivalent_diff_sha256s: list[str] | tuple[str, ...] | None = None,
    defer_diff_identity: bool = False,
    jobs_root: Path | None = None,
) -> dict[str, Any]:
    expected = normalize_binding(
        {
            "schema_version": BINDING_SCHEMA_VERSION,
            "kind": BINDING_KIND,
            "repo": repo,
            "pr": pr,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "diff_sha256": diff_sha256,
            "slot": "merge-gate-probe",
        }
    )
    expected.pop("slot")
    if not isinstance(defer_diff_identity, bool):
        raise ValueError("decision review defer_diff_identity must be boolean")
    aliases = [] if equivalent_diff_sha256s is None else equivalent_diff_sha256s
    if not isinstance(aliases, (list, tuple)):
        raise ValueError("decision review equivalent diff digests must be a list or tuple")
    accepted_diff_sha256s = {expected["diff_sha256"]}
    for alias in aliases:
        if (
            not isinstance(alias, str)
            or _SHA256_RE.fullmatch(alias.strip().lower()) is None
        ):
            raise ValueError("decision review equivalent diff digest must be SHA-256")
        accepted_diff_sha256s.add(alias.strip().lower())
    accepted_diff_sha256s_projection = sorted(accepted_diff_sha256s)
    root = JOBS_ROOT if jobs_root is None else Path(jobs_root)
    errors: list[str] = []
    attempts: list[dict[str, Any]] = []
    if not root.exists():
        return {
            "schema_version": 1,
            "kind": "grabowski_decision_review_reconciliation",
            "status": "not_applicable",
            "binding": expected,
            "binding_sha256": sha256_json(expected),
            "accepted_diff_sha256s": accepted_diff_sha256s_projection,
            "accepted_diff_sha256s_sha256": sha256_json(accepted_diff_sha256s_projection),
            "attempt_count": 0,
            "slot_count": 0,
            "slots": [],
            "errors": [],
            "does_not_establish": [
                "review_quality",
                "semantic_correctness",
                "reviews_started_outside_grabowski_job_start",
            ],
        }
    if root.is_symlink() or not root.is_dir():
        errors.append("decision_review_jobs_root_invalid")
        directories: list[Path] = []
    else:
        directories = []
        with os.scandir(root) as entries:
            for entry in entries:
                if _UNIT_RE.fullmatch(entry.name) is None:
                    continue
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                directories.append(Path(entry.path))
        directories.sort(key=lambda item: item.name)
        if len(directories) > MAX_JOB_DIRECTORIES:
            errors.append("decision_review_job_inventory_truncated")
            directories = directories[:MAX_JOB_DIRECTORIES]

    for directory in directories:
        raw_targets_pr_head = False
        try:
            raw_metadata = _read_private_json(directory / "metadata.json", MAX_METADATA_BYTES)
            raw_scope = raw_metadata.get("scope")
            raw_review_binding = (
                raw_scope.get("decision_bound_review")
                if isinstance(raw_scope, dict)
                else None
            )
            raw_targets_pr_head = _raw_binding_targets_pr_head(
                raw_review_binding, expected
            )
            metadata, binding, provenance = _validated_origin_binding(directory)
        except (FileNotFoundError, OSError, ValueError) as exc:
            if raw_targets_pr_head:
                errors.append(f"decision_review_origin_invalid:{directory.name}:{type(exc).__name__}")
            continue
        if binding is None or not _binding_matches_pr_head(binding, expected):
            continue

        attempt: dict[str, Any] = {
            "unit": directory.name,
            "slot": binding["slot"],
            "origin_sha256": metadata.get("origin_sha256"),
            "created_at_unix": metadata["origin"].get("created_at_unix"),
            "started_at_unix_ns": metadata["scope"].get("started_at_unix_ns"),
            "terminal": False,
            "terminal_status": None,
            "classification": "unresolved",
            "verdict": None,
            "material_findings": None,
            "result_sha256": None,
            "stdout_tail_sha256": None,
            "review_role_verified": False,
            "review_route_verified": False,
            "review_route_id": None,
            "review_provider_family": None,
            "independence_verified": False,
            "review_role_receipt_sha256": None,
            "diff_identity_deferred": False,
        }
        if binding["base_sha"] != expected["base_sha"]:
            errors.append(f"decision_review_base_sha_drift:{directory.name}")
            attempt["classification"] = "binding_drift"
            attempts.append(attempt)
            continue
        diff_binding_drift = False
        if binding["diff_sha256"] not in accepted_diff_sha256s:
            if defer_diff_identity:
                attempt["diff_identity_deferred"] = True
            else:
                diff_binding_drift = True
        if _proven_not_started(metadata):
            attempt["terminal"] = True
            attempt["terminal_status"] = "launch_failed"
            if diff_binding_drift:
                errors.append(f"decision_review_diff_sha256_drift:{directory.name}")
                attempt["classification"] = "binding_drift"
            else:
                attempt["classification"] = "infrastructure_error"
            attempts.append(attempt)
            continue
        try:
            finalization = _validated_finalization(directory, metadata)
        except (FileNotFoundError, OSError, ValueError) as exc:
            errors.append(f"decision_review_finalization_invalid:{directory.name}:{type(exc).__name__}")
            attempt["classification"] = "invalid_finalization"
            attempts.append(attempt)
            continue
        if finalization is None:
            errors.append(f"decision_review_not_terminal:{directory.name}")
            attempt["classification"] = "not_terminal"
            attempts.append(attempt)
            continue
        attempt["terminal"] = True
        attempt["terminal_status"] = finalization["final_status"]
        try:
            stdout_text, stdout_tail_sha256 = _read_stdout_tail(directory / "stdout.log")
            attempt["stdout_tail_sha256"] = stdout_tail_sha256
        except (FileNotFoundError, OSError, ValueError) as exc:
            errors.append(f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}")
            attempt["classification"] = "invalid_result"
            attempts.append(attempt)
            continue
        try:
            role_evidence = _validated_review_role_evidence(metadata, binding, provenance)
        except FileNotFoundError as exc:
            # A drifted diff binding is repairable only when a valid provenance-
            # bound role receipt proves that no semantic review result exists.
            # Missing role evidence cannot establish that narrow condition.
            if diff_binding_drift:
                errors.append(f"decision_review_diff_sha256_drift:{directory.name}")
                attempt["classification"] = "binding_drift"
                attempts.append(attempt)
                continue
            # A non-success terminal provenance-bound reviewer whose role
            # receipt was never created has no semantic review result. Treat
            # only the known pre-result termination states like the existing
            # no-marker infrastructure path so a later exact-bound PASS can
            # supersede them. A succeeded reviewer missing its create-only
            # receipt is contradictory and remains fail-closed, as do malformed,
            # unreadable or binding-invalid receipts below.
            if attempt["terminal_status"] in _PRE_RESULT_INFRASTRUCTURE_STATUSES:
                attempt["classification"] = "infrastructure_error"
                attempts.append(attempt)
                continue
            errors.append(
                f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}"
            )
            attempt["classification"] = "invalid_result"
            attempts.append(attempt)
            continue
        except (OSError, ValueError) as exc:
            errors.append(f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}")
            attempt["classification"] = "invalid_result"
            attempts.append(attempt)
            continue
        if role_evidence is not None:
            attempt["review_role_verified"] = role_evidence["role_verified"]
            attempt["review_route_verified"] = role_evidence["route_verified"]
            attempt["independence_verified"] = role_evidence["independence_verified"]
            attempt["review_role_receipt_sha256"] = role_evidence["role_receipt_sha256"]
            review_route = role_evidence.get("review_route")
            if isinstance(review_route, dict):
                attempt["review_route_id"] = review_route.get("route_id")
                attempt["review_provider_family"] = review_route.get("provider_family")
            result = role_evidence["result"]
        else:
            try:
                result = _parse_result_marker(stdout_text, binding)
            except ValueError as exc:
                errors.append(f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}")
                attempt["classification"] = "invalid_result"
                attempts.append(attempt)
                continue
        if result is not None:
            attempt["result_sha256"] = sha256_json(result)
            attempt["verdict"] = result["verdict"]
            attempt["material_findings"] = result["material_findings"]
        if diff_binding_drift:
            # Never accept a semantic PASS/REJECT for an unproven diff identity.
            # A terminal failed reviewer with no formal semantic result is
            # different: it established no review decision at all, so it may be
            # superseded by a later exact-bound PASS in the same slot.
            if (
                result is None
                and attempt["terminal_status"] in _PRE_RESULT_INFRASTRUCTURE_STATUSES
            ):
                attempt["classification"] = "infrastructure_error"
                attempts.append(attempt)
                continue
            errors.append(f"decision_review_diff_sha256_drift:{directory.name}")
            attempt["classification"] = "binding_drift"
            attempts.append(attempt)
            continue
        if result is None:
            # A terminal reviewer that produced no decision marker did not
            # establish a semantic review outcome. Treat that attempt as
            # retryable infrastructure evidence rather than permanently
            # poisoning the slot. The slot still blocks below until a later
            # PASS exists, while any material REJECT remains globally blocking.
            attempt["classification"] = "infrastructure_error"
            attempts.append(attempt)
            continue
        if result["verdict"] == "REJECT_THIS_REVISION":
            attempt["classification"] = "material_reject"
            errors.append(f"decision_review_material_reject:{binding['slot']}:{directory.name}")
        elif finalization["final_status"] != "succeeded":
            attempt["classification"] = "pass_from_failed_job"
            errors.append(f"decision_review_pass_from_failed_job:{directory.name}")
        else:
            attempt["classification"] = "pass"
        attempts.append(attempt)

    slots: list[dict[str, Any]] = []
    for slot in sorted({str(item["slot"]) for item in attempts}):
        slot_attempts = [item for item in attempts if item["slot"] == slot]
        passes = [item for item in slot_attempts if item["classification"] == "pass"]
        independent_passes = [
            item for item in passes if item.get("independence_verified") is True
        ]
        rejects = [
            item for item in slot_attempts if item["classification"] == "material_reject"
        ]
        unresolved = [
            item
            for item in slot_attempts
            if item["classification"]
            not in {"pass", "material_reject", "infrastructure_error"}
        ]
        infrastructure = [
            item
            for item in slot_attempts
            if item["classification"] == "infrastructure_error"
        ]
        unsuperseded_infrastructure = []
        for infrastructure_attempt in infrastructure:
            if not any(
                _attempt_started_after(pass_attempt, infrastructure_attempt)
                for pass_attempt in passes
            ):
                unsuperseded_infrastructure.append(infrastructure_attempt)
        if not passes and not rejects:
            errors.append(f"decision_review_slot_without_pass:{slot}")
        for infrastructure_attempt in unsuperseded_infrastructure:
            errors.append(
                "decision_review_infrastructure_not_superseded:"
                f"{slot}:{infrastructure_attempt['unit']}"
            )
        slots.append(
            {
                "slot": slot,
                "attempt_count": len(slot_attempts),
                "pass_count": len(passes),
                "independent_pass_count": len(independent_passes),
                "material_reject_count": len(rejects),
                "infrastructure_error_count": len(infrastructure),
                "unresolved_count": len(unresolved),
                "units_sha256": sha256_json(sorted(item["unit"] for item in slot_attempts)),
            }
        )

    errors = sorted(set(errors))
    status = "not_applicable" if not attempts and not errors else "blocked" if errors else "settled"
    attempts_projection = [
        {
            key: item[key]
            for key in (
                "unit",
                "slot",
                "origin_sha256",
                "created_at_unix",
                "started_at_unix_ns",
                "terminal",
                "terminal_status",
                "classification",
                "verdict",
                "material_findings",
                "result_sha256",
                "stdout_tail_sha256",
                "review_role_verified",
                "review_route_verified",
                "review_route_id",
                "review_provider_family",
                "independence_verified",
                "review_role_receipt_sha256",
                "diff_identity_deferred",
            )
        }
        for item in sorted(attempts, key=lambda item: (str(item["slot"]), str(item["unit"])))
    ]
    return {
        "schema_version": 1,
        "kind": "grabowski_decision_review_reconciliation",
        "status": status,
        "binding": expected,
        "binding_sha256": sha256_json(expected),
        "accepted_diff_sha256s": accepted_diff_sha256s_projection,
        "accepted_diff_sha256s_sha256": sha256_json(accepted_diff_sha256s_projection),
        "attempt_count": len(attempts_projection),
        "slot_count": len(slots),
        "slots": slots,
        "deferred_diff_identity_count": sum(
            1 for item in attempts_projection if item["diff_identity_deferred"]
        ),
        "attempts": attempts_projection,
        "attempts_sha256": sha256_json(attempts_projection),
        "errors": errors,
        "read_by_merge_guard": bool(attempts_projection),
        "does_not_establish": [
            "review_quality",
            "semantic_correctness",
            "reviews_started_outside_grabowski_job_start",
            "absence_of_same_uid_out_of_band_file_tampering",
        ],
    }
