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
from typing import Any, Iterator

import grabowski_job_origin as job_origin


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
_REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SLOT_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")
_UNIT_RE = re.compile(r"grabowski-job-([0-9a-f]{12})\Z")
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


def _validated_origin_binding(directory: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
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
        return metadata, None
    return metadata, normalize_binding(raw_binding)


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


def _binding_matches_pr_head(
    binding: dict[str, Any], expected: dict[str, Any]
) -> bool:
    return (
        binding["repo"] == expected["repo"]
        and binding["pr"] == expected["pr"]
        and binding["head_sha"] == expected["head_sha"]
    )


def reconcile(
    *,
    repo: str,
    pr: int,
    head_sha: str,
    base_sha: str,
    diff_sha256: str,
    equivalent_diff_sha256s: list[str] | tuple[str, ...] | None = None,
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
            metadata, binding = _validated_origin_binding(directory)
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
            "created_at_unix": metadata.get("created_at_unix"),
            "terminal": False,
            "terminal_status": None,
            "classification": "unresolved",
            "verdict": None,
            "material_findings": None,
            "result_sha256": None,
            "stdout_tail_sha256": None,
        }
        if binding["base_sha"] != expected["base_sha"]:
            errors.append(f"decision_review_base_sha_drift:{directory.name}")
            attempt["classification"] = "binding_drift"
            attempts.append(attempt)
            continue
        if binding["diff_sha256"] not in accepted_diff_sha256s:
            errors.append(f"decision_review_diff_sha256_drift:{directory.name}")
            attempt["classification"] = "binding_drift"
            attempts.append(attempt)
            continue
        if _proven_not_started(metadata):
            attempt["terminal"] = True
            attempt["terminal_status"] = "launch_failed"
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
            result = _parse_result_marker(stdout_text, binding)
        except (FileNotFoundError, OSError, ValueError) as exc:
            errors.append(f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}")
            attempt["classification"] = "invalid_result"
            attempts.append(attempt)
            continue
        if result is None:
            if finalization["final_status"] == "succeeded":
                errors.append(f"decision_review_success_missing_result:{directory.name}")
                attempt["classification"] = "missing_result"
            else:
                attempt["classification"] = "infrastructure_error"
            attempts.append(attempt)
            continue
        attempt["result_sha256"] = sha256_json(result)
        attempt["verdict"] = result["verdict"]
        attempt["material_findings"] = result["material_findings"]
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
        if not passes and not rejects:
            errors.append(f"decision_review_slot_without_pass:{slot}")
        slots.append(
            {
                "slot": slot,
                "attempt_count": len(slot_attempts),
                "pass_count": len(passes),
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
                "terminal",
                "terminal_status",
                "classification",
                "verdict",
                "material_findings",
                "result_sha256",
                "stdout_tail_sha256",
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
