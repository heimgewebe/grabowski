from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping

import grabowski_private_io as private_io
from grabowski_grips import run_grip
from grabowski_operator_obligation import list_obligations, status_obligation


SCHEMA_VERSION = 1
TASK_ID = "GRABOWSKI-OPERATOR-SURFACE-V1-T060"
MAX_RECORDS = 100
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
DEFAULT_TASK_DB = Path.home() / ".local" / "state" / "grabowski" / "tasks.sqlite3"
DEFAULT_DEPLOYMENT_MANIFEST = Path.home() / ".local" / "share" / "grabowski-mcp" / "deployment-manifest.json"
DEFAULT_BUREAU_EXECUTABLE = Path.home() / ".local" / "bin" / "bureau"
SOURCE_ORDER = {"operator_obligation": 0, "bureau_attention": 1}
BUREAU_ATTENTION_GROUPS = (
    "stale_running",
    "current_outcome_unknown",
    "recent_failed",
    "legacy_outcome_unavailable",
    "historical_failed",
)
BUREAU_CURRENT_ATTENTION_GROUPS = frozenset(
    {"stale_running", "current_outcome_unknown", "recent_failed"}
)
BUREAU_GROUP_ORDER = {group: index for index, group in enumerate(BUREAU_ATTENTION_GROUPS)}
SIGNAL_FIELDS = frozenset(
    {
        "failure_evidence",
        "expected_evidence",
        "blocking_evidence",
        "superseding_evidence",
        "resolution_evidence",
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class ConvergenceBackfillError(RuntimeError):
    pass


class ConvergenceBackfillInputError(ValueError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_text(value: Any, *, label: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConvergenceBackfillInputError(f"{label} must be a non-empty string")
    normalized = value.strip()
    if len(normalized.encode("utf-8")) > maximum:
        raise ConvergenceBackfillInputError(f"{label} exceeds the size bound")
    return normalized


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ConvergenceBackfillInputError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_git_oid(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or GIT_OID_RE.fullmatch(value) is None:
        raise ConvergenceBackfillInputError(
            f"{label} must be a lowercase 40- or 64-character Git object id"
        )
    return value


def _normalize_evidence_overrides(
    value: Mapping[str, Mapping[str, Mapping[str, str]]] | None,
) -> dict[str, dict[str, dict[str, str]]]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConvergenceBackfillInputError("evidence_overrides must be an object")
    normalized: dict[str, dict[str, dict[str, str]]] = {}
    for raw_record_id, raw_signals in value.items():
        record_id = _bounded_text(raw_record_id, label="evidence_overrides record_id", maximum=512)
        if not isinstance(raw_signals, Mapping) or not raw_signals:
            raise ConvergenceBackfillInputError(f"evidence_overrides[{record_id}] must be a non-empty object")
        signals: dict[str, dict[str, str]] = {}
        for raw_field, raw_evidence in raw_signals.items():
            if raw_field not in SIGNAL_FIELDS:
                raise ConvergenceBackfillInputError(f"unsupported evidence override field: {raw_field}")
            if not isinstance(raw_evidence, Mapping) or set(raw_evidence) != {"reference", "sha256"}:
                raise ConvergenceBackfillInputError(
                    f"evidence_overrides[{record_id}].{raw_field} must contain reference and sha256"
                )
            signals[raw_field] = {
                "reference": _bounded_text(
                    raw_evidence["reference"],
                    label=f"evidence_overrides[{record_id}].{raw_field}.reference",
                ),
                "sha256": _validate_sha256(
                    raw_evidence["sha256"],
                    label=f"evidence_overrides[{record_id}].{raw_field}.sha256",
                ),
            }
        normalized[record_id] = dict(sorted(signals.items()))
    return dict(sorted(normalized.items()))


def _runtime_binding(manifest_path: Path) -> dict[str, str]:
    try:
        value = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConvergenceBackfillError(f"deployment manifest is unreadable: {manifest_path}") from exc
    if not isinstance(value, dict):
        raise ConvergenceBackfillError("deployment manifest must be an object")
    return {
        "release_id": _bounded_text(value.get("release_id"), label="deployment release_id", maximum=512),
        "repo_head": _validate_git_oid(value.get("repo_head"), label="deployment repo_head"),
    }


def _obligation_candidates(limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    inventory = list_obligations({"state": "attention", "limit": limit})
    integrity_errors = inventory.get("integrity_errors")
    if integrity_errors:
        raise ConvergenceBackfillError(f"operator obligation inventory has integrity errors: {integrity_errors}")
    records = inventory.get("records")
    if not isinstance(records, list):
        raise ConvergenceBackfillError("operator obligation inventory is malformed")
    candidates: list[dict[str, Any]] = []
    for item in records:
        obligation_id = _bounded_text(item.get("obligation_id"), label="obligation_id", maximum=128)
        status = status_obligation(obligation_id)
        record_id = f"operator-obligation:{obligation_id}"
        open_sha = _validate_sha256(status.get("open_file_sha256"), label=f"{record_id}.open_file_sha256")
        close_sha_raw = status.get("close_file_sha256")
        close_sha = None if close_sha_raw is None else _validate_sha256(close_sha_raw, label=f"{record_id}.close_file_sha256")
        source_identity = {"open_file_sha256": open_sha, "close_file_sha256": close_sha}
        state = _bounded_text(status.get("state"), label=f"{record_id}.state", maximum=64)
        next_action = status.get("next_action") or status.get("recommended_next_action") or ""
        blocking_evidence = None
        if state == "blocked":
            blocking_evidence = (
                f"operator-obligation-close:{close_sha}:"
                f"next_action_sha256:{hashlib.sha256(str(next_action).encode('utf-8')).hexdigest()}"
            )
        classifier_input = {
            "record_id": record_id,
            "observed_state": state,
            "failure_evidence": None,
            "expected_evidence": None,
            "blocking_evidence": blocking_evidence,
            "superseding_evidence": None,
            "resolution_evidence": None,
        }
        candidates.append(
            {
                "source_kind": "operator_obligation",
                "record_id": record_id,
                "observed_state": state,
                "source_observed_at": status.get("closed_at") or status.get("created_at"),
                "source_content_sha256": _sha256(source_identity),
                "open_file_sha256": open_sha,
                "close_file_sha256": close_sha,
                "objective": status.get("objective"),
                "classifier_input": classifier_input,
            }
        )
    return candidates, {
        "state_filter": "attention",
        "returned": len(candidates),
        "scan_truncated": bool(inventory.get("scan_truncated")),
        "integrity_errors": [],
    }



def _bureau_package_tree_sha256(release_path: Path) -> str:
    pyproject = release_path / "pyproject.toml"
    package = release_path / "src" / "bureau"
    if pyproject.is_symlink() or not pyproject.is_file() or package.is_symlink() or not package.is_dir():
        raise ConvergenceBackfillError("Bureau immutable release package tree is incomplete")
    digest = hashlib.sha256()
    for path in [pyproject, *sorted(package.rglob("*.py"))]:
        if path.is_symlink() or not path.is_file():
            raise ConvergenceBackfillError("Bureau immutable release package tree contains an unsafe entry")
        relative = path.relative_to(release_path).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()

def _bureau_runtime_identity(executable: Path) -> dict[str, Any]:
    executable = Path(executable)
    if not executable.is_absolute():
        raise ConvergenceBackfillError("Bureau executable must be absolute")
    try:
        executable_metadata = executable.lstat()
    except OSError as exc:
        raise ConvergenceBackfillError("Bureau executable is unreadable") from exc
    if (
        not stat.S_ISREG(executable_metadata.st_mode)
        or stat.S_ISLNK(executable_metadata.st_mode)
        or executable_metadata.st_uid != os.getuid()
        or stat.S_IMODE(executable_metadata.st_mode) & 0o022
    ):
        raise ConvergenceBackfillError("Bureau executable is unsafe")
    try:
        result = subprocess.run(
            [str(executable), "--json", "runtime-identity"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConvergenceBackfillError("Bureau runtime identity invocation failed") from exc
    if result.returncode != 0:
        raise ConvergenceBackfillError("Bureau runtime identity returned a non-zero status")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ConvergenceBackfillError("Bureau runtime identity returned invalid JSON") from exc
    identity = payload.get("runtime_identity") if isinstance(payload, dict) else None
    manifest = identity.get("manifest") if isinstance(identity, dict) else None
    state = identity.get("state") if isinstance(identity, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("valid") is not True
        or not isinstance(state, dict)
        or state.get("integrity") != "ok"
    ):
        raise ConvergenceBackfillError("Bureau runtime identity is not valid and state-integrity healthy")
    release_path = Path(_bounded_text(manifest.get("immutable_release_path"), label="Bureau immutable_release_path", maximum=4096))
    if not release_path.is_absolute() or release_path.is_symlink() or not release_path.is_dir():
        raise ConvergenceBackfillError("Bureau immutable release path is unsafe")
    source_commit = _validate_git_oid(manifest.get("source_commit"), label="Bureau source_commit")
    release_id = _bounded_text(manifest.get("release_id"), label="Bureau release_id", maximum=512)
    package_tree_sha256 = _validate_sha256(
        manifest.get("package_tree_sha256"), label="Bureau package_tree_sha256"
    )
    manifest_sha256 = _validate_sha256(manifest.get("sha256"), label="Bureau manifest_sha256")
    return {
        "release_id": release_id,
        "source_commit": source_commit,
        "package_tree_sha256": package_tree_sha256,
        "manifest_sha256": manifest_sha256,
        "immutable_release_path": str(release_path),
        "state_path": _bounded_text(state.get("path"), label="Bureau state path", maximum=4096),
        "state_schema_version": state.get("schema_version"),
    }


def _run_bureau_attention_classifier(
    *,
    task_db: Path,
    now_unix: int,
    horizon_seconds: int,
    limit: int,
    bureau_executable: Path,
) -> dict[str, Any]:
    runtime = _bureau_runtime_identity(bureau_executable)
    release_path = Path(runtime["immutable_release_path"])
    package_path = release_path / "src" / "bureau"
    cycle_module = package_path / "cycle_contract.py"
    if cycle_module.is_symlink() or not cycle_module.is_file():
        raise ConvergenceBackfillError("Bureau immutable release lacks cycle_contract.py")
    expected_tree_sha256 = runtime["package_tree_sha256"]
    if _bureau_package_tree_sha256(release_path) != expected_tree_sha256:
        raise ConvergenceBackfillError("Bureau immutable release package-tree digest mismatch before attention classification")
    script = (
        "import json,sys; from pathlib import Path; "
        "sys.path.insert(0, sys.argv[1]); "
        "from bureau.cycle_contract import classify_task_attention; "
        "print(json.dumps(classify_task_attention(Path(sys.argv[2]), "
        "now_unix=int(sys.argv[3]), horizon_seconds=int(sys.argv[4]), limit=int(sys.argv[5])), "
        "ensure_ascii=False, sort_keys=True))"
    )
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                script,
                str(release_path / "src"),
                str(Path(task_db)),
                str(now_unix),
                str(horizon_seconds),
                str(limit),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConvergenceBackfillError("Bureau attention classifier invocation failed") from exc
    if result.returncode != 0:
        raise ConvergenceBackfillError("Bureau attention classifier returned a non-zero status")
    if _bureau_package_tree_sha256(release_path) != expected_tree_sha256:
        raise ConvergenceBackfillError("Bureau immutable release package-tree digest mismatch after attention classification")
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ConvergenceBackfillError("Bureau attention classifier returned invalid JSON") from exc
    if not isinstance(output, dict) or output.get("available") is not True:
        raise ConvergenceBackfillError("Bureau attention classifier did not return an available projection")
    return {"runtime": runtime, "output": output}


def _bureau_attention_candidates(
    task_db: Path,
    *,
    observation_unix: int,
    horizon_seconds: int,
    load_limit: int,
    bureau_executable: Path,
    provider: Callable[..., dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    classified = provider(
        task_db=Path(task_db),
        now_unix=observation_unix,
        horizon_seconds=horizon_seconds,
        limit=load_limit,
        bureau_executable=Path(bureau_executable),
    )
    runtime = classified.get("runtime")
    output = classified.get("output")
    if not isinstance(runtime, dict) or not isinstance(output, dict):
        raise ConvergenceBackfillError("Bureau attention provider returned an invalid shape")
    counts = output.get("counts")
    items = output.get("items")
    if not isinstance(counts, dict) or not isinstance(items, dict):
        raise ConvergenceBackfillError("Bureau attention projection lacks counts or items")
    candidates: list[dict[str, Any]] = []
    omitted_lower_bound = 0
    bounded_counts: dict[str, int] = {}
    for group in BUREAU_ATTENTION_GROUPS:
        raw_count = counts.get(group)
        group_items = items.get(group)
        if not isinstance(raw_count, int) or isinstance(raw_count, bool) or raw_count < 0:
            raise ConvergenceBackfillError(f"Bureau attention count is invalid for {group}")
        if not isinstance(group_items, list):
            raise ConvergenceBackfillError(f"Bureau attention items are invalid for {group}")
        bounded_counts[group] = raw_count
        omitted_lower_bound += max(0, raw_count - len(group_items))
        for raw_item in group_items:
            if not isinstance(raw_item, dict):
                raise ConvergenceBackfillError(f"Bureau attention item is invalid for {group}")
            task_id = _bounded_text(raw_item.get("task_id"), label=f"bureau-attention:{group}.task_id", maximum=512)
            updated_at_unix = raw_item.get("updated_at_unix")
            age_seconds = raw_item.get("age_seconds")
            if (
                not isinstance(updated_at_unix, int)
                or isinstance(updated_at_unix, bool)
                or not isinstance(age_seconds, int)
                or isinstance(age_seconds, bool)
                or age_seconds < 0
            ):
                raise ConvergenceBackfillError(f"Bureau attention timestamps are invalid for {task_id}")
            record_id = f"bureau-attention:{group}:{task_id}"
            source_material = {
                "group": group,
                "task": raw_item,
                "bureau_source_commit": runtime.get("source_commit"),
                "observation_unix": observation_unix,
                "attention_horizon_seconds": horizon_seconds,
            }
            failure_evidence = None
            blocking_evidence = None
            if group in {"recent_failed", "historical_failed"}:
                failure_evidence = f"{record_id}:source_sha256:{_sha256(source_material)}"
            elif group == "stale_running":
                blocking_evidence = f"{record_id}:source_sha256:{_sha256(source_material)}"
            candidates.append(
                {
                    "source_kind": "bureau_attention",
                    "record_id": record_id,
                    "observed_state": _bounded_text(raw_item.get("state"), label=f"{record_id}.state", maximum=64),
                    "source_observed_at_unix": updated_at_unix,
                    "source_content_sha256": _sha256(source_material),
                    "bureau_attention_group": group,
                    "bureau_current_attention": group in BUREAU_CURRENT_ATTENTION_GROUPS,
                    "task_id": task_id,
                    "unit": raw_item.get("unit"),
                    "age_seconds": age_seconds,
                    "classifier_input": {
                        "record_id": record_id,
                        "observed_state": _bounded_text(raw_item.get("state"), label=f"{record_id}.state", maximum=64),
                        "failure_evidence": failure_evidence,
                        "expected_evidence": None,
                        "blocking_evidence": blocking_evidence,
                        "superseding_evidence": None,
                        "resolution_evidence": None,
                    },
                }
            )
    return candidates, {
        "authority": "bureau.cycle_contract.classify_task_attention",
        "bureau_runtime": runtime,
        "task_db": output.get("task_db"),
        "observation_unix": observation_unix,
        "attention_horizon_seconds": output.get("attention_horizon_seconds"),
        "task_count": output.get("task_count"),
        "current_attention_count": output.get("current_attention_count"),
        "counts": bounded_counts,
        "loaded": len(candidates),
        "scan_truncated": omitted_lower_bound > 0,
        "known_omitted_count_lower_bound": omitted_lower_bound,
    }


def _apply_evidence_overrides(
    selected: list[dict[str, Any]],
    overrides: dict[str, dict[str, dict[str, str]]],
) -> None:
    selected_ids = {item["record_id"] for item in selected}
    unknown = sorted(set(overrides) - selected_ids)
    if unknown:
        raise ConvergenceBackfillInputError(
            f"evidence overrides reference records outside the selected bounded snapshot: {unknown}"
        )
    for item in selected:
        signals = overrides.get(item["record_id"])
        if not signals:
            continue
        item["explicit_evidence_overrides"] = signals
        for field, evidence in signals.items():
            item["classifier_input"][field] = (
                f"{evidence['reference']}:evidence_sha256:{evidence['sha256']}"
            )


def build_projection(
    *,
    max_records: int = MAX_RECORDS,
    task_db: Path = DEFAULT_TASK_DB,
    deployment_manifest: Path = DEFAULT_DEPLOYMENT_MANIFEST,
    bureau_executable: Path = DEFAULT_BUREAU_EXECUTABLE,
    observation_unix: int | None = None,
    attention_horizon_seconds: int = 3 * 60 * 60,
    evidence_overrides: Mapping[str, Mapping[str, Mapping[str, str]]] | None = None,
    generated_at: str | None = None,
    runtime_binding: Mapping[str, str] | None = None,
    classifier: Callable[[str, dict[str, Any]], dict[str, Any]] = run_grip,
    bureau_attention_provider: Callable[..., dict[str, Any]] = _run_bureau_attention_classifier,
) -> dict[str, Any]:
    if not isinstance(max_records, int) or isinstance(max_records, bool) or not 1 <= max_records <= MAX_RECORDS:
        raise ConvergenceBackfillInputError(f"max_records must be between 1 and {MAX_RECORDS}")
    if not isinstance(attention_horizon_seconds, int) or isinstance(attention_horizon_seconds, bool) or attention_horizon_seconds < 60:
        raise ConvergenceBackfillInputError("attention_horizon_seconds must be at least 60")
    selected_observation_unix = int(time.time()) if observation_unix is None else observation_unix
    if not isinstance(selected_observation_unix, int) or isinstance(selected_observation_unix, bool) or selected_observation_unix < 0:
        raise ConvergenceBackfillInputError("observation_unix must be a non-negative integer")
    overrides = _normalize_evidence_overrides(evidence_overrides)
    runtime = (
        {
            "release_id": _bounded_text(runtime_binding.get("release_id"), label="runtime_binding.release_id", maximum=512),
            "repo_head": _validate_git_oid(runtime_binding.get("repo_head"), label="runtime_binding.repo_head"),
        }
        if runtime_binding is not None
        else _runtime_binding(Path(deployment_manifest))
    )
    obligations, obligation_bounds = _obligation_candidates(max_records)
    bureau, bureau_bounds = _bureau_attention_candidates(
        Path(task_db),
        observation_unix=selected_observation_unix,
        horizon_seconds=attention_horizon_seconds,
        load_limit=max_records,
        bureau_executable=Path(bureau_executable),
        provider=bureau_attention_provider,
    )
    candidates = obligations + bureau
    candidates.sort(
        key=lambda item: (
            SOURCE_ORDER[item["source_kind"]],
            BUREAU_GROUP_ORDER.get(str(item.get("bureau_attention_group")), -1),
            item["record_id"],
        )
    )
    selected = candidates[:max_records]
    _apply_evidence_overrides(selected, overrides)
    classifier_records = [dict(item["classifier_input"]) for item in selected]
    classified = classifier("convergence-state-classify", {"records": classifier_records})
    if not isinstance(classified, dict) or classified.get("status") != "passed":
        raise ConvergenceBackfillError("convergence-state-classify did not return a passed receipt")
    output = classified.get("output")
    receipt = classified.get("receipt")
    if not isinstance(output, dict) or not isinstance(receipt, dict):
        raise ConvergenceBackfillError("classifier receipt shape is invalid")
    classified_records = output.get("records")
    classification_counts = output.get("counts")
    if not isinstance(classified_records, list) or not isinstance(classification_counts, dict):
        raise ConvergenceBackfillError("classifier output lacks records or counts")
    expected_record_ids = [record["record_id"] for record in classifier_records]
    classified_record_ids = [
        record.get("record_id") if isinstance(record, dict) else None
        for record in classified_records
    ]
    if classified_record_ids != expected_record_ids:
        raise ConvergenceBackfillError(
            "classifier output record identities do not match the selected bounded snapshot"
        )
    source_records = []
    per_source_evidence_references = []
    for item in selected:
        source_records.append({key: value for key, value in item.items() if key != "classifier_input"})
        classifier_input = item["classifier_input"]
        per_source_evidence_references.append(
            {
                "record_id": item["record_id"],
                "source_kind": item["source_kind"],
                "source_content_sha256": item["source_content_sha256"],
                "evidence": {
                    field: classifier_input[field]
                    for field in sorted(SIGNAL_FIELDS)
                    if classifier_input.get(field) is not None
                },
            }
        )
    selected_source_counts: dict[str, int] = {}
    for item in source_records:
        selected_source_counts[item["source_kind"]] = selected_source_counts.get(item["source_kind"], 0) + 1
    known_omitted = (
        max(0, len(candidates) - max_records)
        + int(bureau_bounds["known_omitted_count_lower_bound"])
        + (1 if obligation_bounds["scan_truncated"] else 0)
    )
    source_bounds = {
        "max_records": max_records,
        "selected_count": len(selected),
        "selected_source_counts": dict(sorted(selected_source_counts.items())),
        "operator_obligations": obligation_bounds,
        "bureau_attention": bureau_bounds,
        "selection_truncated": bool(
            len(candidates) > max_records
            or obligation_bounds["scan_truncated"]
            or bureau_bounds["scan_truncated"]
        ),
        "known_omitted_count_lower_bound": known_omitted,
    }
    conflicted_record_ids = sorted(
        str(record.get("record_id"))
        for record in classified_records
        if isinstance(record, dict) and record.get("classification") == "conflicted"
    )
    summary = {
        "classification_counts": classification_counts,
        "integrity_errors": [],
        "truncation": {
            "selection_truncated": source_bounds["selection_truncated"],
            "known_omitted_count_lower_bound": source_bounds["known_omitted_count_lower_bound"],
        },
        "conflicted_record_ids": conflicted_record_ids,
        "per_source_evidence_references": per_source_evidence_references,
    }
    deterministic_material = {
        "schema_version": SCHEMA_VERSION,
        "task_id": TASK_ID,
        "runtime": runtime,
        "source_bounds": source_bounds,
        "source_records": source_records,
        "classifier_output": {
            "schema_version": output.get("schema_version"),
            "authority": output.get("authority"),
            "records": classified_records,
            "counts": classification_counts,
            "decision_required_count": output.get("decision_required_count"),
            "does_not_establish": output.get("does_not_establish"),
        },
        "summary": summary,
        "evidence_overrides": overrides,
    }
    return {
        **deterministic_material,
        "generated_at": generated_at or _utc_now(),
        "classifier_grip": receipt.get("grip"),
        "classifier_parameters_sha256": receipt.get("parameters_sha256"),
        "classifier_output_sha256": receipt.get("output_sha256"),
        "classifier_receipt_sha256": classified.get("receipt_sha256"),
        "deterministic_projection_sha256": _sha256(deterministic_material),
        "no_history_mutation": True,
        "does_not_establish": [
            "task_completion",
            "automatic_closeout",
            "safe_retry",
            "root_cause",
            "priority_change",
        ],
    }


def _ensure_private_directory(directory: Path) -> None:
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ConvergenceBackfillError(f"unsafe private projection directory: {directory}")


def _private_file_sha256(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_ARTIFACT_BYTES
        ):
            raise ConvergenceBackfillError(f"unsafe convergence backfill projection: {path}")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ConvergenceBackfillError(f"short convergence backfill projection read: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
        )
        after_identity = (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        )
        if before_identity != after_identity:
            raise ConvergenceBackfillError(f"convergence backfill projection changed during read: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def write_projection_create_only(path: Path, projection: dict[str, Any]) -> dict[str, Any]:
    path = Path(path)
    if not path.is_absolute():
        raise ConvergenceBackfillInputError("projection path must be absolute")
    _ensure_private_directory(path.parent)
    encoded = (json.dumps(projection, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    requested_sha256 = hashlib.sha256(encoded).hexdigest()
    created = private_io.publish_private_create_only_json(
        path.parent,
        path,
        projection,
        max_bytes=MAX_ARTIFACT_BYTES,
        label="convergence backfill projection",
    )
    published_sha256 = _private_file_sha256(path)
    return {
        "created": created,
        "path": str(path),
        "requested_projection_sha256": requested_sha256,
        "published_file_sha256": published_sha256,
        "matches_requested": published_sha256 == requested_sha256,
        "deterministic_projection_sha256": projection.get("deterministic_projection_sha256"),
        "bytes": len(encoded),
    }
