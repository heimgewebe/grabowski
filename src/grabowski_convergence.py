from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable
import zipfile


SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_MANIFEST_BYTES = 64 * 1024
MAX_PROFILE_BYTES = 2 * 1024 * 1024
MAX_CONTRACT_TREE_BYTES = 4 * 1024 * 1024
BUNDLE_SCHEMA_VERSION = 1
BUNDLE_KIND = "grabowski.convergence_runtime_bundle"
RESILIENCE_PROFILE_MEMBER = "regelkreis/contracts/profiles/resilience.v2.json"
ALLOWED_CHANGE_RISKS = frozenset({"R0", "R1", "R2", "R3"})
ALLOWED_TARGET_CRITICALITIES = frozenset(
    {"optional", "supporting", "essential", "foundational", "unknown"}
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
ALLOWED_STATUSES = frozenset(
    {
        "transition_allowed",
        "evidence_missing",
        "conflicting_evidence",
        "source_stale",
        "blocked",
        "terminally_closed",
    }
)
STATUS_EXIT_CODES = {
    "transition_allowed": 0,
    "terminally_closed": 0,
    "evidence_missing": 2,
    "conflicting_evidence": 4,
    "source_stale": 5,
    "blocked": 6,
}
COMMON_ASSESSMENT_KEYS = frozenset(
    {
        "assessment_id",
        "blocked_by",
        "conflicts",
        "missing_evidence",
        "profile_sha256",
        "schema_version",
        "status",
    }
)
EXPECTED_ASSESSMENT_KEYS_BY_VERSION = {
    1: COMMON_ASSESSMENT_KEYS | {"risk_level"},
    2: COMMON_ASSESSMENT_KEYS
    | {"change_risk", "target_criticality", "profile_id", "profile_cell_id"},
}
ASSESSMENT_STRING_FIELDS_BY_VERSION = {
    1: ("risk_level",),
    2: ("change_risk", "target_criticality", "profile_id", "profile_cell_id"),
}
GitRunner = Callable[[Path, list[str]], dict[str, Any]]
EvaluatorRunner = Callable[[Path, list[str]], dict[str, Any]]


class ConvergenceInputError(ValueError):
    pass


class ConvergenceExecutionError(RuntimeError):
    pass


def _protocol_repo() -> Path:
    configured = os.environ.get("GRABOWSKI_CONVERGENCE_PROTOCOL_REPO")
    value = Path(configured).expanduser() if configured else Path.home() / "repos" / "konvergenzregelkreis"
    if not value.is_absolute():
        raise ConvergenceInputError("convergence protocol repository must be absolute")
    return value.resolve()


def _protocol_executable(repo: Path) -> Path:
    configured = os.environ.get("GRABOWSKI_CONVERGENCE_EXECUTABLE")
    value = Path(configured).expanduser() if configured else repo / ".venv" / "bin" / "regelkreis"
    if not value.is_absolute():
        raise ConvergenceInputError("convergence executable must be absolute")
    return value


def _bundle_root() -> Path:
    configured = os.environ.get("GRABOWSKI_CONVERGENCE_BUNDLE_ROOT")
    value = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".local" / "share" / "grabowski" / "convergence-bundles"
    )
    if not value.is_absolute():
        raise ConvergenceInputError("convergence bundle root must be absolute")
    return value.absolute()


def _bundle_manifest_path(expected_head: str) -> Path:
    return _bundle_root() / expected_head / "manifest.json"


def _json_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConvergenceInputError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ConvergenceInputError(f"{label} must contain a JSON object")
    return value


def _read_profile_from_wheel(wheel_bytes: bytes, member: str) -> tuple[dict[str, Any], bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            matches = [item for item in archive.infolist() if item.filename == member]
            if len(matches) != 1:
                raise ConvergenceInputError(
                    "convergence wheel must contain exactly one resilience profile member"
                )
            info = matches[0]
            if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_PROFILE_BYTES:
                raise ConvergenceInputError("convergence resilience profile size is invalid")
            profile_bytes = archive.read(info)
    except zipfile.BadZipFile as exc:
        raise ConvergenceInputError("convergence wheel is not a valid zip archive") from exc
    if len(profile_bytes) != info.file_size:
        raise ConvergenceInputError("convergence resilience profile read is incomplete")
    profile = _json_object(profile_bytes, label="convergence resilience profile")
    if (
        profile.get("schema_version") != 2
        or profile.get("profile_id") != "resilience-matrix-v2"
        or not isinstance(profile.get("cells"), list)
    ):
        raise ConvergenceInputError("convergence resilience profile contract mismatch")
    return profile, profile_bytes


def _materialize_contract_root(wheel_bytes: bytes, target: Path) -> str:
    contract_prefix = "regelkreis/contracts/"
    total = 0
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.startswith(contract_prefix):
                    continue
                relative = info.filename.removeprefix(contract_prefix)
                parts = Path(relative).parts
                if (
                    len(parts) != 2
                    or parts[0] not in {"protocol", "profiles"}
                    or not parts[1].endswith(".json")
                    or Path(relative).is_absolute()
                    or ".." in parts
                    or relative in seen
                ):
                    raise ConvergenceInputError(
                        "convergence wheel contract member path is invalid"
                    )
                if info.file_size <= 0 or total + info.file_size > MAX_CONTRACT_TREE_BYTES:
                    raise ConvergenceInputError(
                        "convergence wheel contract tree exceeds the accepted bound"
                    )
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise ConvergenceInputError(
                        "convergence wheel contract member read is incomplete"
                    )
                destination = target.joinpath(*parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600,
                )
                try:
                    view = memoryview(data)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise ConvergenceExecutionError(
                                "short convergence contract materialization write"
                            )
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                total += len(data)
                seen.add(relative)
                records.append(
                    {
                        "path": relative,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data),
                    }
                )
    except zipfile.BadZipFile as exc:
        raise ConvergenceInputError("convergence wheel is not a valid zip archive") from exc
    if not any(record["path"].startswith("protocol/") for record in records):
        raise ConvergenceInputError("convergence wheel has no protocol contracts")
    if not any(record["path"].startswith("profiles/") for record in records):
        raise ConvergenceInputError("convergence wheel has no evidence profiles")
    return hashlib.sha256(
        json.dumps(
            sorted(records, key=lambda item: item["path"]),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _load_runtime_bundle(expected_head: str) -> dict[str, Any] | None:
    expected_head = _validate_git_oid(expected_head, label="expected_protocol_head")
    manifest_path = _bundle_manifest_path(expected_head)
    if not os.path.lexists(manifest_path):
        return None
    bundle_dir = manifest_path.parent
    try:
        root_info = _bundle_root().lstat()
        dir_info = bundle_dir.lstat()
    except OSError as exc:
        raise ConvergenceInputError(f"convergence bundle path cannot be inspected: {exc}") from exc
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise ConvergenceInputError("convergence bundle root must be a real directory")
    if not stat.S_ISDIR(dir_info.st_mode) or stat.S_ISLNK(dir_info.st_mode):
        raise ConvergenceInputError("convergence bundle directory must be a real directory")

    manifest_bytes = _read_regular_file(
        manifest_path, maximum=MAX_BUNDLE_MANIFEST_BYTES, label="convergence bundle manifest"
    )
    manifest = _json_object(manifest_bytes, label="convergence bundle manifest")
    required = {
        "schema_version",
        "kind",
        "protocol_head",
        "wheel_filename",
        "wheel_sha256",
        "profile_member",
        "profile_sha256",
    }
    if set(manifest) != required:
        raise ConvergenceInputError("convergence bundle manifest fields are invalid")
    if (
        manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION
        or manifest.get("kind") != BUNDLE_KIND
        or manifest.get("protocol_head") != expected_head
    ):
        raise ConvergenceInputError("convergence bundle manifest identity mismatch")
    wheel_filename = manifest.get("wheel_filename")
    if (
        not isinstance(wheel_filename, str)
        or not wheel_filename.endswith(".whl")
        or Path(wheel_filename).name != wheel_filename
    ):
        raise ConvergenceInputError("convergence bundle wheel filename is invalid")
    wheel_sha256 = _validate_sha256(manifest.get("wheel_sha256"), label="wheel_sha256")
    profile_sha256 = _validate_sha256(manifest.get("profile_sha256"), label="profile_sha256")
    if manifest.get("profile_member") != RESILIENCE_PROFILE_MEMBER:
        raise ConvergenceInputError("convergence bundle profile member is unsupported")

    wheel_path = bundle_dir / wheel_filename
    wheel_bytes = _read_regular_file(
        wheel_path, maximum=MAX_BUNDLE_BYTES, label="convergence wheel"
    )
    if hashlib.sha256(wheel_bytes).hexdigest() != wheel_sha256:
        raise ConvergenceInputError("convergence wheel SHA-256 mismatch")
    profile, profile_bytes = _read_profile_from_wheel(
        wheel_bytes, RESILIENCE_PROFILE_MEMBER
    )
    if hashlib.sha256(profile_bytes).hexdigest() != profile_sha256:
        raise ConvergenceInputError("convergence resilience profile SHA-256 mismatch")
    identity_sha256 = hashlib.sha256(
        manifest_bytes + b"\0" + wheel_bytes
    ).hexdigest()
    return {
        "manifest_path": str(manifest_path),
        "bundle_dir": str(bundle_dir),
        "protocol_head": expected_head,
        "wheel_path": str(wheel_path),
        "wheel_sha256": wheel_sha256,
        "profile_sha256": profile_sha256,
        "profile": profile,
        "wheel_bytes": wheel_bytes,
        "identity_sha256": identity_sha256,
    }


def _system_plan_material(context: dict[str, Any] | None) -> dict[str, Any]:
    if context is None:
        return {
            "schema_version": 1,
            "kind": "grabowski.system_convergence_plan",
            "status": "unclassified",
            "change_risk": None,
            "target_criticality": None,
            "protocol_head": None,
            "profile_id": None,
            "profile_cell_id": None,
            "profile_sha256": None,
            "protocol_source": None,
            "required_effects": [],
            "required_verifications": [],
            "required_closure_fields": [],
            "requires_resilience_evidence": None,
            "requires_independent_recovery": None,
            "systemic_closure_gate": "undetermined",
            "hard_gate_required": None,
            "criticality_resolution_required": False,
            "admission_blocking": False,
            "next_action": "classify change risk before claiming high-risk systemic convergence",
            "does_not_establish": [
                "task state",
                "execution authority",
                "merge authorization",
                "deployment truth",
                "systemic convergence",
            ],
        }
    if not isinstance(context, dict):
        raise ConvergenceInputError("system_convergence must be an object or null")
    required = {"change_risk", "target_criticality", "expected_protocol_head"}
    if set(context) != required:
        raise ConvergenceInputError("system_convergence fields are invalid")
    change_risk = context.get("change_risk")
    target_criticality = context.get("target_criticality")
    if change_risk not in ALLOWED_CHANGE_RISKS:
        raise ConvergenceInputError("change_risk must be one of R0, R1, R2, R3")
    if target_criticality not in ALLOWED_TARGET_CRITICALITIES:
        raise ConvergenceInputError("target_criticality is unsupported")
    expected_head = _validate_git_oid(
        context.get("expected_protocol_head"), label="expected_protocol_head"
    )
    bundle = _load_runtime_bundle(expected_head)
    if bundle is None:
        raise ConvergenceExecutionError(
            "immutable convergence runtime bundle is unavailable for the requested protocol head"
        )
    cells = bundle["profile"]["cells"]
    matches = [
        cell
        for cell in cells
        if isinstance(cell, dict)
        and cell.get("change_risk") == change_risk
        and cell.get("target_criticality") == target_criticality
    ]
    if len(matches) != 1:
        raise ConvergenceExecutionError(
            "convergence resilience profile does not contain exactly one requested matrix cell"
        )
    cell = matches[0]
    for field in ("required_effects", "required_verifications", "required_closure_fields"):
        value = cell.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ConvergenceExecutionError(f"convergence profile cell field {field} is invalid")
    for field in ("requires_resilience_evidence", "requires_independent_recovery"):
        if not isinstance(cell.get(field), bool):
            raise ConvergenceExecutionError(f"convergence profile cell field {field} is invalid")
    cell_id = cell.get("cell_id")
    if not isinstance(cell_id, str) or not cell_id:
        raise ConvergenceExecutionError("convergence profile cell id is invalid")

    criticality_resolution_required = (
        change_risk in {"R2", "R3"} and target_criticality == "unknown"
    )
    if criticality_resolution_required:
        systemic_closure_gate = "classification_required"
        hard_gate_required: bool | None = True if change_risk == "R3" else None
    elif change_risk == "R3" or (
        change_risk == "R2" and target_criticality in {"essential", "foundational"}
    ):
        systemic_closure_gate = "hard"
        hard_gate_required = True
    elif change_risk == "R2":
        systemic_closure_gate = "assessment_required"
        hard_gate_required = False
    else:
        systemic_closure_gate = "not_required"
        hard_gate_required = False

    return {
        "schema_version": 1,
        "kind": "grabowski.system_convergence_plan",
        "status": "planned",
        "change_risk": change_risk,
        "target_criticality": target_criticality,
        "protocol_head": expected_head,
        "profile_id": bundle["profile"]["profile_id"],
        "profile_cell_id": cell_id,
        "profile_sha256": bundle["profile_sha256"],
        "protocol_source": "immutable_bundle",
        "bundle_identity_sha256": bundle["identity_sha256"],
        "wheel_sha256": bundle["wheel_sha256"],
        "required_effects": list(cell["required_effects"]),
        "required_verifications": list(cell["required_verifications"]),
        "required_closure_fields": list(cell["required_closure_fields"]),
        "requires_resilience_evidence": cell["requires_resilience_evidence"],
        "requires_independent_recovery": cell["requires_independent_recovery"],
        "systemic_closure_gate": systemic_closure_gate,
        "hard_gate_required": hard_gate_required,
        "criticality_resolution_required": criticality_resolution_required,
        "admission_blocking": False,
        "next_action": (
            "resolve target criticality before systemic closure"
            if criticality_resolution_required
            else "collect the planned evidence and require terminally_closed before systemic closure"
            if systemic_closure_gate == "hard"
            else "collect the planned evidence; ordinary delivery may close independently of systemic convergence"
            if systemic_closure_gate == "assessment_required"
            else "use ordinary delivery closeout; no universal convergence gate is required"
        ),
        "does_not_establish": [
            "task state",
            "execution authority",
            "merge authorization",
            "deployment truth",
            "evidence satisfaction",
            "systemic convergence",
        ],
    }


def build_system_convergence_plan(
    context: dict[str, Any] | None,
) -> dict[str, Any]:
    material = _system_plan_material(context)
    return {**material, "plan_sha256": _sha256_canonical(material)}


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ConvergenceInputError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_git_oid(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or GIT_OID_RE.fullmatch(value) is None:
        raise ConvergenceInputError(f"{label} must be a lowercase 40- or 64-character Git object id")
    return value


def _read_regular_file(path: Path, *, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConvergenceInputError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ConvergenceInputError(f"{label} must be a regular file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise ConvergenceInputError(f"{label} size is outside the accepted bound")
        chunks: list[bytes] = []
        size = 0
        while size <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > maximum:
        raise ConvergenceInputError(f"{label} exceeds the accepted bound")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ConvergenceInputError(f"{label} changed while being read")
    return data


def _read_bound_request(path_value: Any, expected_sha256: str) -> tuple[Path, bytes]:
    if not isinstance(path_value, str) or not path_value.strip():
        raise ConvergenceInputError("request_path must be a non-empty absolute path")
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        raise ConvergenceInputError("request_path must be absolute")
    data = _read_regular_file(path, maximum=MAX_REQUEST_BYTES, label="request_path")
    actual_sha256 = hashlib.sha256(data).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ConvergenceInputError(
            "request_path SHA-256 does not match expected_request_sha256"
        )
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConvergenceInputError("request_path is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ConvergenceInputError("request_path must contain a JSON object")
    return path.resolve(), data


def _run_checked(runner: Callable[[Path, list[str]], dict[str, Any]], cwd: Path, argv: list[str], *, label: str) -> dict[str, Any]:
    result = runner(cwd, argv)
    if not isinstance(result, dict):
        raise ConvergenceExecutionError(f"{label} runner returned a non-object")
    returncode = result.get("returncode")
    stdout = result.get("stdout")
    stderr = result.get("stderr")
    if not isinstance(returncode, int) or not isinstance(stdout, str) or not isinstance(stderr, str):
        raise ConvergenceExecutionError(f"{label} runner returned an invalid shape")
    return result


def _validate_protocol_identity(
    runner: GitRunner,
    repo: Path,
    executable: Path,
    expected_head: str,
) -> tuple[str, str]:
    if not repo.is_dir():
        raise ConvergenceInputError("convergence protocol repository does not exist")
    executable_bytes = _read_regular_file(
        executable,
        maximum=MAX_EXECUTABLE_BYTES,
        label="convergence executable",
    )
    executable_sha256 = hashlib.sha256(executable_bytes).hexdigest()

    head_result = _run_checked(runner, repo, ["rev-parse", "HEAD"], label="protocol head")
    if head_result["returncode"] != 0:
        raise ConvergenceExecutionError(head_result["stderr"] or "protocol head lookup failed")
    observed_head = head_result["stdout"].strip()
    if observed_head != expected_head:
        raise ConvergenceInputError(
            f"convergence protocol head mismatch: observed={observed_head} expected={expected_head}"
        )
    status_result = _run_checked(
        runner,
        repo,
        ["status", "--porcelain=v1", "--untracked-files=normal"],
        label="protocol status",
    )
    if status_result["returncode"] != 0:
        raise ConvergenceExecutionError(status_result["stderr"] or "protocol status lookup failed")
    if status_result["stdout"].strip():
        raise ConvergenceInputError("convergence protocol repository is dirty")
    return observed_head, executable_sha256


def _validate_assessment(value: Any, returncode: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConvergenceExecutionError("convergence evaluator returned an unexpected assessment shape")
    schema_version = value.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in EXPECTED_ASSESSMENT_KEYS_BY_VERSION
    ):
        raise ConvergenceExecutionError("convergence evaluator schema version is unsupported")
    if set(value) != EXPECTED_ASSESSMENT_KEYS_BY_VERSION[schema_version]:
        raise ConvergenceExecutionError("convergence evaluator returned an unexpected assessment shape")
    status_value = value.get("status")
    if not isinstance(status_value, str) or status_value not in ALLOWED_STATUSES:
        raise ConvergenceExecutionError("convergence evaluator returned an unsupported status")
    if STATUS_EXIT_CODES[status_value] != returncode:
        raise ConvergenceExecutionError("convergence evaluator status and exit code disagree")
    for field in ("blocked_by", "conflicts", "missing_evidence"):
        items = value.get(field)
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise ConvergenceExecutionError(f"convergence evaluator field {field} is invalid")
    for field in (
        "assessment_id",
        "profile_sha256",
        *ASSESSMENT_STRING_FIELDS_BY_VERSION[schema_version],
    ):
        if not isinstance(value.get(field), str) or not value[field]:
            raise ConvergenceExecutionError(f"convergence evaluator field {field} is invalid")
    if SHA256_RE.fullmatch(value["profile_sha256"]) is None:
        raise ConvergenceExecutionError("convergence evaluator field profile_sha256 is invalid")
    return value


def _default_evaluator_runner(
    cwd: Path,
    argv: list[str],
    *,
    extra_environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = {
        "HOME": str(Path.home()),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
    }
    if extra_environment:
        env.update(extra_environment)
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "convergence evaluator timed out"}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout[: 1024 * 1024],
        "stderr": completed.stderr[: 64 * 1024],
    }


def assess(
    parameters: dict[str, Any],
    runner: GitRunner,
    evaluator_runner: EvaluatorRunner | None = None,
) -> dict[str, Any]:
    expected_request_sha256 = _validate_sha256(
        parameters.get("expected_request_sha256"), label="expected_request_sha256"
    )
    expected_protocol_head = _validate_git_oid(
        parameters.get("expected_protocol_head"), label="expected_protocol_head"
    )
    request_path, request_bytes = _read_bound_request(
        parameters.get("request_path"), expected_request_sha256
    )
    bundle = _load_runtime_bundle(expected_protocol_head)
    temporary_contract_root = None
    if bundle is not None:
        protocol_source = "immutable_bundle"
        repo: Path | None = None
        observed_head = expected_protocol_head
        executable_sha256 = bundle["wheel_sha256"]
        evaluation_cwd = Path(bundle["bundle_dir"])
        temporary_contract_root = tempfile.TemporaryDirectory(
            prefix="grabowski-convergence-contracts-"
        )
        materialized_contract_root = Path(temporary_contract_root.name)
        contracts_sha256 = _materialize_contract_root(
            bundle["wheel_bytes"], materialized_contract_root
        )
        evaluation_argv = [
            sys.executable,
            "-m",
            "regelkreis.cli",
            "evaluate",
            str(request_path),
            "--contract-root",
            str(materialized_contract_root),
        ]
        if evaluator_runner is None:
            def selected_runner(cwd: Path, argv: list[str]) -> dict[str, Any]:
                return _default_evaluator_runner(
                    cwd,
                    argv,
                    extra_environment={"PYTHONPATH": bundle["wheel_path"]},
                )
        else:
            selected_runner = evaluator_runner
    else:
        protocol_source = "verified_checkout"
        repo = _protocol_repo()
        executable = _protocol_executable(repo)
        observed_head, executable_sha256 = _validate_protocol_identity(
            runner, repo, executable, expected_protocol_head
        )
        evaluation_cwd = repo
        evaluation_argv = [str(executable), "evaluate", str(request_path)]
        selected_runner = evaluator_runner or _default_evaluator_runner
    try:
        result = _run_checked(
            selected_runner,
            evaluation_cwd,
            evaluation_argv,
            label="convergence evaluation",
        )
    finally:
        if temporary_contract_root is not None:
            temporary_contract_root.cleanup()
    if result["returncode"] not in set(STATUS_EXIT_CODES.values()):
        detail = result["stderr"].strip() or f"unexpected exit code {result['returncode']}"
        raise ConvergenceExecutionError(f"convergence evaluation failed: {detail}")
    try:
        parsed = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        raise ConvergenceExecutionError("convergence evaluator returned invalid JSON") from exc
    assessment = _validate_assessment(parsed, result["returncode"])
    if bundle is not None:
        post_bundle = _load_runtime_bundle(expected_protocol_head)
        if (
            post_bundle is None
            or post_bundle["identity_sha256"] != bundle["identity_sha256"]
            or post_bundle["wheel_sha256"] != executable_sha256
        ):
            raise ConvergenceExecutionError(
                "convergence runtime bundle identity changed during evaluation"
            )
    else:
        assert repo is not None
        post_head, post_executable_sha256 = _validate_protocol_identity(
            runner, repo, executable, expected_protocol_head
        )
        if post_head != observed_head or post_executable_sha256 != executable_sha256:
            raise ConvergenceExecutionError(
                "convergence protocol identity changed during evaluation"
            )
    closure_allowed = assessment["status"] == "terminally_closed"
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski.convergence_assessment",
        "request_path": str(request_path),
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "protocol_repo": str(repo) if repo is not None else None,
        "protocol_head": observed_head,
        "protocol_source": protocol_source,
        "bundle_manifest_path": (bundle["manifest_path"] if bundle is not None else None),
        "bundle_identity_sha256": (bundle["identity_sha256"] if bundle is not None else None),
        "contracts_sha256": (contracts_sha256 if bundle is not None else None),
        "executable_sha256": executable_sha256,
        "assessment": assessment,
        "closure_allowed": closure_allowed,
        "decision": "allow_closure" if closure_allowed else "block_closure",
        "does_not_establish": [
            "task state",
            "merge authorization",
            "deployment truth beyond supplied receipts",
            "runtime truth beyond supplied receipts",
            "Bureau completion",
            "Chronik persistence",
        ],
    }


ALLOWED_CHANGE_CLASSES = frozenset(
    {
        "documentation",
        "contract",
        "application",
        "runtime",
        "infrastructure",
        "security",
        "data",
        "lifecycle",
        "product_outcome",
    }
)
ALLOWED_SOURCE_STATES = frozenset({"current", "stale", "unknown"})
ALLOWED_EVIDENCE_AUTHORITIES = frozenset({"supplied", "authoritative_receipts"})
ALLOWED_EFFECT_KINDS = frozenset(
    {"commit", "pull_request", "merge", "artifact", "deployment", "configuration_change"}
)
ALLOWED_VERIFICATION_KINDS = frozenset(
    {
        "deterministic_regeneration",
        "tests",
        "review",
        "independent_review",
        "ci",
        "deployment_identity",
        "runtime_identity",
        "service_health",
        "smoke_test",
        "negative_control",
        "consumer_compatibility",
        "recovery",
        "product_outcome",
    }
)
ISO_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _validate_iso_datetime(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or ISO_DATETIME_RE.fullmatch(value) is None:
        raise ConvergenceInputError(f"{label} must be an explicit valid ISO 8601 date-time string")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConvergenceInputError(f"{label} must be a non-empty string")
    return value.strip()


PR_CLOSURE_PROFILE_ID = "pr-closure-v1"
PR_CLOSURE_EVIDENCE_CATEGORIES = ("pr_merge", "deployment_live", "obligation", "checkout")


def _sha256_canonical(val: Any) -> str:
    encoded = json.dumps(val, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_pr_closure_profile(
    evidence: dict[str, Any] | None = None,
    *,
    evidence_authority: str = "supplied",
    source_state: str | None = None,
) -> dict[str, Any]:
    """
    Builds a PR closure evidence profile binding PR/merge, deployment/live,
    obligation, and checkout evidence categories.

    Trust boundary & provenance non-claim:
    - Default `evidence_authority` is 'supplied'. Caller-supplied evidence cannot,
      by itself, yield `source_state=current` or terminal closure.
    - Setting `evidence_authority='authoritative_receipts'` preserves the caller-provided
      authority designation and requires an explicit `source_state` ('current', 'stale', or 'unknown').
      The builder only preserves this caller-provided designation and does NOT cryptographically verify provenance.
    - Category status dictionaries (e.g. pr_merge.status='merged', deployment_live.status='live')
      are descriptive supplied coverage only and MUST NEVER synthesize effect or verification receipts.
      Only protocol-compatible raw effects, verifications, and closure participate in evaluator evidence.
    """
    if evidence is None:
        evidence = {}
    if not isinstance(evidence, dict):
        raise ConvergenceInputError("evidence must be a dictionary")

    authority = evidence.get("evidence_authority") or evidence_authority
    if authority not in ALLOWED_EVIDENCE_AUTHORITIES:
        raise ConvergenceInputError(
            f"evidence_authority must be 'supplied' or 'authoritative_receipts', got '{authority}'"
        )

    profile_categories: dict[str, dict[str, Any]] = {}
    blocked_by: list[str] = []
    conflicts: list[str] = []
    missing_evidence: list[str] = []
    claims: list[str] = []
    source_refs: list[dict[str, str]] = []
    effects: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []

    raw_effects = evidence.get("effects")
    if isinstance(raw_effects, list):
        for idx, item in enumerate(raw_effects):
            if not isinstance(item, dict):
                raise ConvergenceInputError(f"effects[{idx}] must be a dictionary")
            if item.get("schema_version") != 1:
                raise ConvergenceInputError(f"effects[{idx}].schema_version must be 1")
            kind = _text(item.get("kind"), f"effects[{idx}].kind")
            if kind not in ALLOWED_EFFECT_KINDS:
                raise ConvergenceInputError(f"effects[{idx}].kind '{kind}' is not a valid v1 effect kind")
            ref = _text(item.get("evidence_ref"), f"effects[{idx}].evidence_ref")
            subj_sha = _validate_sha256(item.get("subject_sha256"), label=f"effects[{idx}].subject_sha256")
            effects.append({
                "schema_version": 1,
                "kind": kind,
                "evidence_ref": ref,
                "subject_sha256": subj_sha,
            })
            source_refs.append({"kind": f"effect:{kind}", "ref": ref, "subject_sha256": subj_sha})

    raw_verifications = evidence.get("verifications")
    if isinstance(raw_verifications, list):
        for idx, item in enumerate(raw_verifications):
            if not isinstance(item, dict):
                raise ConvergenceInputError(f"verifications[{idx}] must be a dictionary")
            if item.get("schema_version") != 1:
                raise ConvergenceInputError(f"verifications[{idx}].schema_version must be 1")
            kind = _text(item.get("kind"), f"verifications[{idx}].kind")
            if kind not in ALLOWED_VERIFICATION_KINDS:
                raise ConvergenceInputError(f"verifications[{idx}].kind '{kind}' is not a valid v1 verification kind")
            ref = _text(item.get("evidence_ref"), f"verifications[{idx}].evidence_ref")
            subj_sha = _validate_sha256(item.get("subject_sha256"), label=f"verifications[{idx}].subject_sha256")
            result = _text(item.get("result"), f"verifications[{idx}].result")
            if result not in ("pass", "fail", "unknown"):
                raise ConvergenceInputError(f"verifications[{idx}].result must be pass, fail, or unknown")
            verifications.append({
                "schema_version": 1,
                "kind": kind,
                "result": result,
                "evidence_ref": ref,
                "subject_sha256": subj_sha,
            })
            source_refs.append({"kind": f"verification:{kind}", "ref": ref, "subject_sha256": subj_sha})

    raw_source_refs = evidence.get("source_refs")
    if isinstance(raw_source_refs, list):
        for idx, item in enumerate(raw_source_refs):
            if isinstance(item, dict):
                k = _text(item.get("kind"), f"source_refs[{idx}].kind")
                r = _text(item.get("ref"), f"source_refs[{idx}].ref")
                s = _validate_sha256(item.get("subject_sha256"), label=f"source_refs[{idx}].subject_sha256")
                source_refs.append({"kind": k, "ref": r, "subject_sha256": s})

    raw_closure = evidence.get("closure") if isinstance(evidence, dict) else None
    if raw_closure is not None:
        if not isinstance(raw_closure, dict):
            raise ConvergenceInputError("closure must be a dictionary")
        if raw_closure.get("schema_version") != 1:
            raise ConvergenceInputError("closure.schema_version must be 1")

    merge_effect = next((e for e in effects if e["kind"] == "merge"), None)
    deploy_effect = next((e for e in effects if e["kind"] == "deployment"), None)
    has_deploy_identity_pass = any(v["kind"] == "deployment_identity" and v["result"] == "pass" for v in verifications)

    has_obligation_ref = isinstance(raw_closure, dict) and bool(raw_closure.get("bureau_task_ref"))
    has_checkout_cleanup = (
        isinstance(raw_closure, dict)
        and isinstance(raw_closure.get("cleanup_evidence"), list)
        and len(raw_closure.get("cleanup_evidence")) > 0
    )

    # Category 1: pr_merge
    pr_data = evidence.get("pr_merge")
    if isinstance(pr_data, dict):
        status = pr_data.get("status", "unknown")
        ref = pr_data.get("evidence_ref") or f"github-pr:{pr_data.get('repository', 'repo')}#{pr_data.get('pr_number', 0)}"
        subj_sha = pr_data.get("subject_sha256")
        if subj_sha is not None:
            _validate_sha256(subj_sha, label="pr_merge.subject_sha256")
            source_refs.append({"kind": "git_commit", "ref": ref, "subject_sha256": subj_sha})

        if status == "conflicted":
            conflicts.append(f"pr_merge:{ref}")
            blocked_by.append("conflicting_evidence:pr_merge")
            profile_categories["pr_merge"] = {"status": "conflicted", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "stale":
            blocked_by.append("source_stale:pr_merge")
            profile_categories["pr_merge"] = {"status": "stale", "ref": ref, "subject_sha256": subj_sha or ""}
        elif merge_effect:
            claims.append(f"Supplied PR merge evidence: {merge_effect['evidence_ref']}")
            profile_categories["pr_merge"] = {
                "status": "supplied" if status in ("merged", "pass") else status,
                "ref": merge_effect["evidence_ref"],
                "subject_sha256": merge_effect["subject_sha256"],
            }
        else:
            missing_evidence.append("pr_merge")
            blocked_by.append("evidence_missing:pr_merge")
            profile_categories["pr_merge"] = {
                "status": status if status not in ("merged", "pass") else "supplied",
                "ref": ref,
                "subject_sha256": subj_sha or "",
            }
    else:
        if merge_effect:
            claims.append(f"Supplied PR merge evidence: {merge_effect['evidence_ref']}")
            profile_categories["pr_merge"] = {
                "status": "supplied",
                "ref": merge_effect["evidence_ref"],
                "subject_sha256": merge_effect["subject_sha256"],
            }
        else:
            missing_evidence.append("pr_merge")
            blocked_by.append("evidence_missing:pr_merge")
            profile_categories["pr_merge"] = {"status": "missing", "ref": "", "subject_sha256": ""}

    # Category 2: deployment_live
    deploy_data = evidence.get("deployment_live")
    if isinstance(deploy_data, dict):
        status = deploy_data.get("status", "unknown")
        ref = deploy_data.get("evidence_ref") or f"grabowski-release:{deploy_data.get('release_id', 'unknown')}"
        subj_sha = deploy_data.get("subject_sha256")
        if subj_sha is not None:
            _validate_sha256(subj_sha, label="deployment_live.subject_sha256")
            source_refs.append({"kind": "artifact", "ref": ref, "subject_sha256": subj_sha})

        if status == "conflicted":
            conflicts.append(f"deployment_live:{ref}")
            blocked_by.append("conflicting_evidence:deployment_live")
            profile_categories["deployment_live"] = {"status": "conflicted", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "stale":
            blocked_by.append("source_stale:deployment_live")
            profile_categories["deployment_live"] = {"status": "stale", "ref": ref, "subject_sha256": subj_sha or ""}
        elif deploy_effect and has_deploy_identity_pass:
            claims.append(f"Supplied deployment evidence: {deploy_effect['evidence_ref']}")
            profile_categories["deployment_live"] = {
                "status": "supplied" if status in ("live", "pass") else status,
                "ref": deploy_effect["evidence_ref"],
                "subject_sha256": deploy_effect["subject_sha256"],
            }
        else:
            missing_evidence.append("deployment_live")
            blocked_by.append("evidence_missing:deployment_live")
            profile_categories["deployment_live"] = {
                "status": status if status not in ("live", "pass") else "supplied",
                "ref": ref,
                "subject_sha256": subj_sha or "",
            }
    else:
        if deploy_effect and has_deploy_identity_pass:
            claims.append(f"Supplied deployment evidence: {deploy_effect['evidence_ref']}")
            profile_categories["deployment_live"] = {
                "status": "supplied",
                "ref": deploy_effect["evidence_ref"],
                "subject_sha256": deploy_effect["subject_sha256"],
            }
        else:
            missing_evidence.append("deployment_live")
            blocked_by.append("evidence_missing:deployment_live")
            profile_categories["deployment_live"] = {"status": "missing", "ref": "", "subject_sha256": ""}

    # Category 3: obligation
    ob_data = evidence.get("obligation")
    if isinstance(ob_data, dict):
        status = ob_data.get("status", "unknown")
        ref = ob_data.get("evidence_ref") or ob_data.get("bureau_task_ref") or f"obligation:{ob_data.get('obligation_id', 'unknown')}"
        subj_sha = ob_data.get("subject_sha256")
        if subj_sha is not None:
            _validate_sha256(subj_sha, label="obligation.subject_sha256")
            source_refs.append({"kind": "obligation", "ref": ref, "subject_sha256": subj_sha})

        if status == "conflicted":
            conflicts.append(f"obligation:{ref}")
            blocked_by.append("conflicting_evidence:obligation")
            profile_categories["obligation"] = {"status": "conflicted", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "stale":
            blocked_by.append("source_stale:obligation")
            profile_categories["obligation"] = {"status": "stale", "ref": ref, "subject_sha256": subj_sha or ""}
        elif has_obligation_ref:
            ob_ref = raw_closure["bureau_task_ref"]
            claims.append(f"Supplied obligation evidence: {ob_ref}")
            profile_categories["obligation"] = {
                "status": "supplied" if status in ("completed", "closed", "pass") else status,
                "ref": ob_ref,
                "subject_sha256": subj_sha or "",
            }
        else:
            missing_evidence.append("obligation")
            blocked_by.append("evidence_missing:obligation")
            profile_categories["obligation"] = {
                "status": status if status not in ("completed", "closed", "pass") else "supplied",
                "ref": ref,
                "subject_sha256": subj_sha or "",
            }
    else:
        if has_obligation_ref:
            ob_ref = raw_closure["bureau_task_ref"]
            claims.append(f"Supplied obligation evidence: {ob_ref}")
            profile_categories["obligation"] = {"status": "supplied", "ref": ob_ref, "subject_sha256": ""}
        else:
            missing_evidence.append("obligation")
            blocked_by.append("evidence_missing:obligation")
            profile_categories["obligation"] = {"status": "missing", "ref": "", "subject_sha256": ""}

    # Category 4: checkout
    chk_data = evidence.get("checkout")
    if isinstance(chk_data, dict):
        status = chk_data.get("status", "unknown")
        ref = chk_data.get("evidence_ref") or f"grabowski:checkout:{chk_data.get('checkout_key', 'unknown')}"
        subj_sha = chk_data.get("subject_sha256")
        if subj_sha is not None:
            _validate_sha256(subj_sha, label="checkout.subject_sha256")
            source_refs.append({"kind": "checkout", "ref": ref, "subject_sha256": subj_sha})

        if chk_data.get("dirty") or status == "dirty":
            conflicts.append(f"checkout_dirty:{ref}")
            blocked_by.append("checkout_dirty")
            profile_categories["checkout"] = {"status": "dirty", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "conflicted":
            conflicts.append(f"checkout:{ref}")
            blocked_by.append("conflicting_evidence:checkout")
            profile_categories["checkout"] = {"status": "conflicted", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "stale":
            blocked_by.append("source_stale:checkout")
            profile_categories["checkout"] = {"status": "stale", "ref": ref, "subject_sha256": subj_sha or ""}
        elif has_checkout_cleanup:
            chk_ref = raw_closure["cleanup_evidence"][0]
            claims.append(f"Supplied checkout cleanup evidence: {chk_ref}")
            profile_categories["checkout"] = {
                "status": "supplied" if status in ("cleaned", "archived", "pass") else status,
                "ref": chk_ref,
                "subject_sha256": subj_sha or "",
            }
        else:
            missing_evidence.append("checkout")
            blocked_by.append("evidence_missing:checkout")
            profile_categories["checkout"] = {
                "status": status if status not in ("cleaned", "archived", "pass") else "supplied",
                "ref": ref,
                "subject_sha256": subj_sha or "",
            }
    else:
        if has_checkout_cleanup:
            chk_ref = raw_closure["cleanup_evidence"][0]
            claims.append(f"Supplied checkout cleanup evidence: {chk_ref}")
            profile_categories["checkout"] = {"status": "supplied", "ref": chk_ref, "subject_sha256": ""}
        else:
            missing_evidence.append("checkout")
            blocked_by.append("evidence_missing:checkout")
            profile_categories["checkout"] = {"status": "missing", "ref": "", "subject_sha256": ""}

    dedup_refs: list[dict[str, str]] = []
    seen_ref_keys: set[str] = set()
    for sref in source_refs:
        rk = f"{sref['kind']}:{sref['ref']}:{sref['subject_sha256']}"
        if rk not in seen_ref_keys:
            seen_ref_keys.add(rk)
            dedup_refs.append(sref)

    return {
        "profile_id": PR_CLOSURE_PROFILE_ID,
        "categories": profile_categories,
        "blocked_by": sorted(set(blocked_by)),
        "conflicts": sorted(set(conflicts)),
        "missing_evidence": sorted(set(missing_evidence)),
        "claims": claims,
        "source_refs": dedup_refs,
        "effects": effects,
        "verifications": verifications,
    }


def build_pr_closure_assessment_request(
    evidence: dict[str, Any] | None = None,
    *,
    risk_level: str = "R2",
    assessment_id: str | None = None,
    observed_at: str | None = None,
    change_class: str = "lifecycle",
    evidence_authority: str = "supplied",
    source_state: str | None = None,
) -> dict[str, Any]:
    """
    Builds a deterministic assessment request suitable for the convergence evaluator.
    Requires an explicit valid ISO 8601 date-time observation.
    Never invents missing evidence or synthesizes closure from category status strings.

    Trust boundary & provenance non-claim:
    - Default `evidence_authority` is 'supplied'. Supplying evidence forces `source_state='unknown'`
      (unless stale evidence forces 'stale') and adds 'supplied_evidence_requires_authoritative_read'
      to `blocked_by`, preventing caller-supplied data from by itself evaluating terminally closed.
    - Setting `evidence_authority='authoritative_receipts'` requires an explicit `source_state`
      ('current', 'stale', or 'unknown'). The builder preserves the caller-provided authority
      designation and does NOT cryptographically verify provenance.
    """
    observed_at = _validate_iso_datetime(observed_at, label="observed_at")
    if risk_level not in ("R0", "R1", "R2", "R3"):
        raise ConvergenceInputError("risk_level must be one of R0, R1, R2, R3")
    if change_class not in ALLOWED_CHANGE_CLASSES:
        raise ConvergenceInputError(f"change_class must be one of {sorted(ALLOWED_CHANGE_CLASSES)}")

    if evidence is None:
        evidence = {}

    authority = evidence.get("evidence_authority") or evidence_authority
    if authority not in ALLOWED_EVIDENCE_AUTHORITIES:
        raise ConvergenceInputError(
            f"evidence_authority must be 'supplied' or 'authoritative_receipts', got '{authority}'"
        )

    source_st = evidence.get("source_state") or source_state

    profile = build_pr_closure_profile(
        evidence,
        evidence_authority=authority,
        source_state=source_st,
    )

    categories_sha = _sha256_canonical(profile["categories"])
    if not assessment_id:
        assessment_id = f"pr-closure-{categories_sha[:16]}"

    blocked_by = list(profile["blocked_by"])

    if authority == "supplied":
        if "supplied_evidence_requires_authoritative_read" not in blocked_by:
            blocked_by.append("supplied_evidence_requires_authoritative_read")
        if any("source_stale" in item for item in blocked_by) or source_st == "stale":
            effective_source_state = "stale"
        else:
            effective_source_state = "unknown"
    else:  # authoritative_receipts
        if source_st is None or source_st not in ALLOWED_SOURCE_STATES:
            raise ConvergenceInputError(
                "authoritative_receipts requires an explicit source_state argument ('current', 'stale', or 'unknown')"
            )
        effective_source_state = source_st

    does_not_establish = [
        "automatic_merge_authority",
        "automatic_deploy_authority",
        "unverified_runtime_truth",
        "unread_evidence_validity",
        "bureau_mutation",
    ]

    claims = list(profile["claims"])
    source_refs = list(profile["source_refs"])
    if not source_refs:
        input_sha = hashlib.sha256(categories_sha.encode("utf-8")).hexdigest()
        source_refs = [{
            "kind": "assessment_input",
            "ref": f"grabowski:assessment-request-input:{assessment_id}",
            "subject_sha256": input_sha,
        }]
        claims.append("Bound to request input parameters (input-binding reference only; does not establish source truth)")
        does_not_establish.append("source_truth_from_input_binding")

    if not claims:
        claims = ["No positive evidence claims read"]

    request: dict[str, Any] = {
        "schema_version": 1,
        "assessment_id": assessment_id,
        "risk_level": risk_level,
        "classification": {
            "schema_version": 1,
            "change_class": change_class,
            "semantic_change": "material",
            "blocked_by": sorted(set(blocked_by)),
        },
        "observation": {
            "schema_version": 1,
            "observation_id": f"obs-{assessment_id}",
            "observed_at": observed_at,
            "source_state": effective_source_state,
            "claims": claims,
            "does_not_establish": sorted(set(does_not_establish)),
            "source_refs": source_refs,
        },
        "effects": profile["effects"],
        "verifications": profile["verifications"],
    }

    raw_closure = evidence.get("closure") if isinstance(evidence, dict) else None
    if isinstance(raw_closure, dict):
        cls_id = raw_closure.get("closure_id") or f"closure-{assessment_id}"
        cls_status = raw_closure.get("status", "proposed")
        if cls_status not in ("proposed", "closed"):
            raise ConvergenceInputError("closure.status must be proposed or closed")
        closure_dict: dict[str, Any] = {
            "schema_version": 1,
            "closure_id": _text(cls_id, "closure.closure_id"),
            "status": cls_status,
            "residual_risks": raw_closure.get("residual_risks") if isinstance(raw_closure.get("residual_risks"), list) else [],
        }
        if raw_closure.get("bureau_task_ref") is not None:
            closure_dict["bureau_task_ref"] = _text(raw_closure["bureau_task_ref"], "closure.bureau_task_ref")
        if raw_closure.get("chronik_event_ref") is not None:
            closure_dict["chronik_event_ref"] = _text(raw_closure["chronik_event_ref"], "closure.chronik_event_ref")
        if isinstance(raw_closure.get("cleanup_evidence"), list):
            closure_dict["cleanup_evidence"] = [_text(item, "closure.cleanup_evidence") for item in raw_closure["cleanup_evidence"]]
        request["closure"] = closure_dict

    return request


def build_pr_closure_request(
    evidence: dict[str, Any] | None = None,
    *,
    risk_level: str = "R2",
    assessment_id: str | None = None,
    observed_at: str | None = None,
    change_class: str = "lifecycle",
    evidence_authority: str = "supplied",
    source_state: str | None = None,
) -> tuple[dict[str, Any], bytes, str]:
    """
    Emits a deterministic hash-bound (request_dict, request_bytes, request_sha256) tuple.
    """
    request_dict = build_pr_closure_assessment_request(
        evidence,
        risk_level=risk_level,
        assessment_id=assessment_id,
        observed_at=observed_at,
        change_class=change_class,
        evidence_authority=evidence_authority,
        source_state=source_state,
    )
    request_bytes = json.dumps(
        request_dict, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    return request_dict, request_bytes, request_sha256


BLUE_GREEN_PROFILE_ID = "blue-green-deployment-cutover-v1"
BLUE_GREEN_EVIDENCE_CATEGORIES = (
    "deployment_receipt",
    "green_readiness",
    "snapshot_rebind",
    "effect_terminalization",
    "runtime_identity",
)


def build_blue_green_deployment_profile(
    receipt: dict[str, Any] | None = None,
    *,
    evidence_authority: str = "supplied",
    source_state: str | None = None,
) -> dict[str, Any]:
    """Build a convergence evidence profile from one blue-green deployment receipt.

    The profile binds runtime, names, schemas/sentinels, snapshot rebind and
    Bedienvertrag evidence already present in the receipt. It never synthesizes
    missing cutover success and does not authorize deployment.
    """
    if receipt is None:
        receipt = {}
    if not isinstance(receipt, dict):
        raise ConvergenceInputError("blue-green receipt must be a dictionary")
    authority = receipt.get("evidence_authority") or evidence_authority
    if authority not in ALLOWED_EVIDENCE_AUTHORITIES:
        raise ConvergenceInputError(
            f"evidence_authority must be 'supplied' or 'authoritative_receipts', got '{authority}'"
        )
    categories: dict[str, dict[str, Any]] = {}
    blocked_by: list[str] = []
    missing_evidence: list[str] = []
    conflicts: list[str] = []
    claims: list[str] = []
    source_refs: list[dict[str, str]] = []
    effects: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []

    receipt_kind = receipt.get("kind")
    receipt_sha = receipt.get("receipt_sha256")
    outcome = receipt.get("outcome")
    if receipt_kind != "grabowski_blue_green_deployment_receipt":
        missing_evidence.append("deployment_receipt")
        blocked_by.append("evidence_missing:deployment_receipt")
        categories["deployment_receipt"] = {"status": "missing"}
    elif not isinstance(receipt_sha, str) or SHA256_RE.fullmatch(receipt_sha) is None:
        conflicts.append("deployment_receipt:receipt_sha256")
        blocked_by.append("conflicting_evidence:deployment_receipt")
        categories["deployment_receipt"] = {"status": "conflicted"}
    else:
        unsigned = dict(receipt)
        unsigned.pop("receipt_sha256", None)
        material = json.dumps(
            unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if hashlib.sha256(material).hexdigest() != receipt_sha:
            conflicts.append("deployment_receipt:hash_mismatch")
            blocked_by.append("conflicting_evidence:deployment_receipt")
            categories["deployment_receipt"] = {
                "status": "conflicted",
                "ref": f"grabowski:blue-green-receipt:{receipt.get('cutover_id', 'unknown')}",
                "subject_sha256": receipt_sha,
            }
        else:
            categories["deployment_receipt"] = {
                "status": "present",
                "outcome": outcome,
                "phase": receipt.get("phase"),
                "ref": f"grabowski:blue-green-receipt:{receipt.get('cutover_id')}",
                "subject_sha256": receipt_sha,
            }
            source_refs.append(
                {
                    "kind": "deployment_receipt",
                    "ref": categories["deployment_receipt"]["ref"],
                    "subject_sha256": receipt_sha,
                }
            )
            claims.append(
                f"Bound blue-green deployment receipt for cutover {receipt.get('cutover_id')}"
            )
            effects.append(
                {
                    "schema_version": 1,
                    "kind": "deployment",
                    "evidence_ref": categories["deployment_receipt"]["ref"],
                    "subject_sha256": receipt_sha,
                }
            )

    readiness = receipt.get("green_readiness")
    if not isinstance(readiness, dict) or readiness.get("ready") is not True:
        missing_evidence.append("green_readiness")
        blocked_by.append("evidence_missing:green_readiness")
        categories["green_readiness"] = {"status": "missing"}
    else:
        readiness_sha = _sha256_canonical(readiness)
        categories["green_readiness"] = {
            "status": "ready",
            "names_sha256": readiness.get("names_sha256"),
            "bedienvertrag_matches": readiness.get("bedienvertrag_matches"),
            "subject_sha256": readiness_sha,
        }
        claims.append("Green runtime matched manifest/tools/schemas/sentinel/Bedienvertrag")
        verifications.append(
            {
                "schema_version": 1,
                "kind": "runtime_identity",
                "result": "pass",
                "evidence_ref": "green_readiness",
                "subject_sha256": readiness_sha,
            }
        )
        source_refs.append(
            {
                "kind": "green_readiness",
                "ref": "green_readiness",
                "subject_sha256": readiness_sha,
            }
        )

    snapshot = receipt.get("snapshot_rebind")
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("verified") is not True
        or not isinstance(snapshot.get("receipt_sha256"), str)
        or SHA256_RE.fullmatch(snapshot.get("receipt_sha256") or "") is None
    ):
        missing_evidence.append("snapshot_rebind")
        blocked_by.append("evidence_missing:snapshot_rebind")
        categories["snapshot_rebind"] = {"status": "missing"}
    else:
        categories["snapshot_rebind"] = {
            "status": "matched",
            "receipt_sha256": snapshot["receipt_sha256"],
            "cutover_binding": snapshot.get("cutover_binding"),
        }
        claims.append("Connector snapshot rebind was part of the cutover")
        verifications.append(
            {
                "schema_version": 1,
                "kind": "consumer_compatibility",
                "result": "pass",
                "evidence_ref": "snapshot_rebind",
                "subject_sha256": snapshot["receipt_sha256"],
            }
        )
        source_refs.append(
            {
                "kind": "snapshot_rebind",
                "ref": "snapshot_rebind",
                "subject_sha256": snapshot["receipt_sha256"],
            }
        )

    terminalization = receipt.get("effect_terminalization")
    if not isinstance(terminalization, dict) or not isinstance(
        terminalization.get("terminalized_count"), int
    ):
        missing_evidence.append("effect_terminalization")
        blocked_by.append("evidence_missing:effect_terminalization")
        categories["effect_terminalization"] = {"status": "missing"}
    else:
        term_sha = _sha256_canonical(terminalization)
        categories["effect_terminalization"] = {
            "status": "present",
            "terminalized_count": terminalization.get("terminalized_count"),
            "remaining_read_count": terminalization.get("remaining_read_count"),
            "subject_sha256": term_sha,
        }
        claims.append(
            "Only effect-bearing blue calls were terminalized; long-lived reads were not required to drain"
        )
        verifications.append(
            {
                "schema_version": 1,
                "kind": "recovery",
                "result": "pass",
                "evidence_ref": "effect_terminalization",
                "subject_sha256": term_sha,
            }
        )

    runtime_fields = (
        receipt.get("green_release_id"),
        receipt.get("expected_head"),
        receipt.get("names_sha256"),
        receipt.get("agent_instructions_sha256"),
    )
    if any(not isinstance(item, str) or not item for item in runtime_fields):
        missing_evidence.append("runtime_identity")
        blocked_by.append("evidence_missing:runtime_identity")
        categories["runtime_identity"] = {"status": "missing"}
    else:
        runtime_subject = _sha256_canonical(
            {
                "green_release_id": receipt["green_release_id"],
                "expected_head": receipt["expected_head"],
                "names_sha256": receipt["names_sha256"],
                "agent_instructions_sha256": receipt["agent_instructions_sha256"],
                "schema_sentinels": receipt.get("schema_sentinels"),
            }
        )
        categories["runtime_identity"] = {
            "status": "bound",
            "green_release_id": receipt["green_release_id"],
            "expected_head": receipt["expected_head"],
            "subject_sha256": runtime_subject,
        }
        claims.append("Deployment receipt bound runtime, names, schemas/sentinels and Bedienvertrag")
        verifications.append(
            {
                "schema_version": 1,
                "kind": "deployment_identity",
                "result": "pass",
                "evidence_ref": "runtime_identity",
                "subject_sha256": runtime_subject,
            }
        )

    if outcome not in {"completed"}:
        blocked_by.append(f"deployment_outcome:{outcome or 'missing'}")

    if authority == "supplied":
        blocked_by.append("supplied_evidence_requires_authoritative_read")
        effective_source_state = "stale" if source_state == "stale" else "unknown"
    else:
        if source_state is None or source_state not in ALLOWED_SOURCE_STATES:
            raise ConvergenceInputError(
                "authoritative_receipts requires an explicit source_state "
                "('current', 'stale', or 'unknown')"
            )
        effective_source_state = source_state

    return {
        "schema_version": 1,
        "profile_id": BLUE_GREEN_PROFILE_ID,
        "evidence_categories": list(BLUE_GREEN_EVIDENCE_CATEGORIES),
        "categories": categories,
        "blocked_by": sorted(set(blocked_by)),
        "conflicts": sorted(set(conflicts)),
        "missing_evidence": sorted(set(missing_evidence)),
        "claims": claims,
        "source_refs": source_refs,
        "effects": effects,
        "verifications": verifications,
        "source_state": effective_source_state,
        "evidence_authority": authority,
        "does_not_establish": [
            "automatic_deploy_authority",
            "connector platform identity",
            "unread runtime truth",
        ],
    }


def build_blue_green_assessment_request(
    receipt: dict[str, Any] | None = None,
    *,
    risk_level: str = "R2",
    assessment_id: str | None = None,
    observed_at: str | None = None,
    change_class: str = "runtime",
    evidence_authority: str = "supplied",
    source_state: str | None = None,
) -> dict[str, Any]:
    """Build one deterministic convergence assessment request for blue-green cutover closure."""
    observed_at = _validate_iso_datetime(observed_at, label="observed_at")
    if risk_level not in ("R0", "R1", "R2", "R3"):
        raise ConvergenceInputError("risk_level must be one of R0, R1, R2, R3")
    if change_class not in ALLOWED_CHANGE_CLASSES:
        raise ConvergenceInputError(
            f"change_class must be one of {sorted(ALLOWED_CHANGE_CLASSES)}"
        )
    profile = build_blue_green_deployment_profile(
        receipt,
        evidence_authority=evidence_authority,
        source_state=source_state,
    )
    categories_sha = _sha256_canonical(profile["categories"])
    if not assessment_id:
        assessment_id = f"blue-green-{categories_sha[:16]}"
    request = {
        "schema_version": 1,
        "assessment_id": assessment_id,
        "risk_level": risk_level,
        "classification": {
            "schema_version": 1,
            "change_class": change_class,
            "semantic_change": "material",
            "blocked_by": list(profile["blocked_by"]),
        },
        "observation": {
            "schema_version": 1,
            "observation_id": f"obs-{assessment_id}",
            "observed_at": observed_at,
            "source_state": profile["source_state"],
            "claims": list(profile["claims"])
            or ["No positive blue-green evidence claims read"],
            "does_not_establish": list(profile["does_not_establish"]),
            "source_refs": list(profile["source_refs"])
            or [
                {
                    "kind": "assessment_input",
                    "ref": f"grabowski:assessment-request-input:{assessment_id}",
                    "subject_sha256": categories_sha,
                }
            ],
        },
        "effects": profile["effects"],
        "verifications": profile["verifications"],
    }
    return request


