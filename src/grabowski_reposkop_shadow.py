from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

import grabowski_mcp as base
import grabowski_operator_core as operator
import grabowski_reposkop_context as reposkop_context
import grabowski_reposkop_effectiveness as reposkop_effectiveness


REPOSKOP_BIN = Path(
    os.environ.get(
        "GRABOWSKI_REPOSKOP_BIN",
        str(operator.HOME / ".local/bin/reposkop"),
    )
).expanduser()
SHADOW_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_REPOSKOP_SHADOW_ROOT",
        str(operator.STATE_DIR / "reposkop-checkout-shadow"),
    )
).expanduser()
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
TIMEOUT_SECONDS = 20
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
REASON_CODE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
CONTINUITY_STATES = frozenset(
    {"intact", "explainable_drift", "identity_break", "inconclusive"}
)
BEFORE_OPERATION = "reposkop-checkout-shadow-before-observed"
TERMINAL_OPERATION = "reposkop-checkout-shadow-terminal-observed"


class ReposkopShadowError(RuntimeError):
    def __init__(self, message: str, *, category: str = "shadow_internal_error") -> None:
        super().__init__(message)
        self.category = category


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_bytes(value).rstrip(b"\n"))


def _validate_task_id(task_id: str) -> str:
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise ValueError("task_id is invalid")
    return task_id


def _task_key(task_id: str) -> str:
    return hashlib.sha256(_validate_task_id(task_id).encode("utf-8")).hexdigest()


def _paths(root: Path, task_id: str) -> dict[str, Path]:
    key = _task_key(task_id)
    return {
        "before_artifact": root / f"{key}.before.reposkop.json",
        "before_binding": root / f"{key}.before.binding.json",
        "before_audit": root / f"{key}.before.audit.json",
        "terminal_artifact": root / f"{key}.continuity.reposkop.json",
        "terminal_binding": root / f"{key}.terminal.binding.json",
        "terminal_audit": root / f"{key}.terminal.audit.json",
    }


def _ensure_root() -> Path:
    root = base._state_subdir(SHADOW_ROOT)
    metadata = root.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ReposkopShadowError(
            "Reposkop shadow root violates its private-directory contract",
            category="evidence_storage_error",
        )
    return root


def _read_private_json(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = base._read_private_evidence(path, max_bytes=MAX_EVIDENCE_BYTES)
    try:
        value = json.loads(payload.decode("utf-8"), parse_constant=_reject_nonfinite)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReposkopShadowError(
            "Reposkop shadow evidence is not canonical JSON",
            category="evidence_integrity_error",
        ) from exc
    if not isinstance(value, dict):
        raise ReposkopShadowError(
            "Reposkop shadow evidence is not an object",
            category="evidence_integrity_error",
        )
    if payload != _canonical_bytes(value):
        raise ReposkopShadowError(
            "Reposkop shadow evidence is not canonical",
            category="evidence_integrity_error",
        )
    return value, payload


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is unsupported: {value}")


def _write_or_match(path: Path, payload: bytes) -> None:
    try:
        base._write_private_create_only(path, payload)
    except FileExistsError:
        _value, existing = _read_private_json(path)
        if existing != payload:
            raise ReposkopShadowError(
                "Reposkop shadow evidence identity conflict",
                category="evidence_integrity_error",
            )


def _binding_payload(material: dict[str, Any]) -> dict[str, Any]:
    return {**material, "evidence_sha256": _sha256_json(material)}


def _validate_binding(
    value: dict[str, Any], *, task_id: str, phase: str
) -> dict[str, Any]:
    digest = value.get("evidence_sha256")
    material = {key: item for key, item in value.items() if key != "evidence_sha256"}
    if (
        value.get("schema_version") != 1
        or value.get("kind") != "grabowski.reposkop_checkout_shadow_evidence"
        or value.get("task_id") != task_id
        or value.get("phase") != phase
        or value.get("decision_effect") is not False
        or value.get("effect_authorized") is not False
        or not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        or digest != _sha256_json(material)
    ):
        raise ReposkopShadowError(
            "Reposkop shadow binding failed validation",
            category="evidence_integrity_error",
        )
    return value


def _workspace_eligible_for_before(workspace: str) -> Path | None:
    candidate = Path(workspace)
    if not candidate.is_absolute() or candidate.is_symlink():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    marker = resolved / ".git"
    if (
        resolved != candidate
        or not resolved.is_dir()
        or marker.is_symlink()
        or not (marker.is_file() or marker.is_dir())
    ):
        return None
    return resolved


def _workspace_observable(workspace: str) -> Path | None:
    candidate = Path(workspace)
    if not candidate.is_absolute() or candidate.is_symlink():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if resolved != candidate or not resolved.is_dir():
        return None
    return resolved


def _open_expected_artifact(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        linked = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size > MAX_ARTIFACT_BYTES
        ):
            raise ReposkopShadowError(
                "Reposkop expected observation violates its file contract",
                category="evidence_integrity_error",
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _sha256_descriptor(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if offset != size:
        raise ReposkopShadowError(
            "Reposkop expected observation could not be read exactly",
            category="evidence_integrity_error",
        )
    return digest.hexdigest()


def _validate_expected_artifact_binding(
    path: Path,
    descriptor: int,
    *,
    expected_identity: tuple[int, int],
    expected_size: int,
    expected_sha256: str,
) -> None:
    opened = os.fstat(descriptor)
    linked = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or (opened.st_dev, opened.st_ino) != expected_identity
        or (linked.st_dev, linked.st_ino) != expected_identity
        or opened.st_size != expected_size
        or linked.st_size != expected_size
        or stat.S_IMODE(opened.st_mode) != 0o600
        or _sha256_descriptor(descriptor, expected_size) != expected_sha256
    ):
        raise ReposkopShadowError(
            "Reposkop expected observation changed during continuity capture",
            category="evidence_integrity_error",
        )


def _run_reposkop(
    command: str,
    target: Path,
    *,
    purpose: str,
    expected_artifact: Path | None = None,
) -> tuple[dict[str, Any], str]:
    executable_descriptor, executable_sha256 = (
        reposkop_context._open_validated_executable(REPOSKOP_BIN)
    )
    target_descriptor: int | None = None
    expected_descriptor: int | None = None
    expected_identity: tuple[int, int] | None = None
    expected_size: int | None = None
    expected_sha256: str | None = None
    try:
        target_descriptor = reposkop_context._open_validated_target_directory(target)
        target_stat = os.fstat(target_descriptor)
        target_identity = (target_stat.st_dev, target_stat.st_ino)
        argv = [
            f"/proc/self/fd/{executable_descriptor}",
            command,
            f"/proc/self/fd/{target_descriptor}",
        ]
        pass_fds = [executable_descriptor, target_descriptor]
        if expected_artifact is not None:
            expected_descriptor = _open_expected_artifact(expected_artifact)
            expected_stat = os.fstat(expected_descriptor)
            expected_identity = (expected_stat.st_dev, expected_stat.st_ino)
            expected_size = expected_stat.st_size
            expected_sha256 = _sha256_descriptor(
                expected_descriptor, expected_size
            )
            # Reposkop's canonical loader intentionally opens --expected with
            # O_NOFOLLOW, so /proc/self/fd is not part of that CLI contract.
            # Keep our validated fd open and verify its exact path binding
            # immediately after Reposkop has consumed the private 0600 file.
            argv.extend(["--expected", str(expected_artifact)])
        argv.extend(
            ["--role", "grabowski_workspace", "--purpose", purpose, "--json"]
        )
        result = reposkop_context._run_bounded_process(
            argv,
            cwd=operator.HOME,
            timeout_seconds=TIMEOUT_SECONDS,
            stdout_limit=MAX_ARTIFACT_BYTES,
            stderr_limit=MAX_STDERR_BYTES,
            pass_fds=tuple(pass_fds),
        )
        if (
            expected_artifact is not None
            and expected_descriptor is not None
            and expected_identity is not None
            and expected_size is not None
            and expected_sha256 is not None
        ):
            _validate_expected_artifact_binding(
                expected_artifact,
                expected_descriptor,
                expected_identity=expected_identity,
                expected_size=expected_size,
                expected_sha256=expected_sha256,
            )
    finally:
        if expected_descriptor is not None:
            os.close(expected_descriptor)
        if target_descriptor is not None:
            os.close(target_descriptor)
        os.close(executable_descriptor)
    if result["timed_out"]:
        raise ReposkopShadowError(
            "Reposkop shadow command timed out",
            category="capability_timeout",
        )
    if result["stdout_limit_exceeded"] or result["stderr_limit_exceeded"]:
        raise ReposkopShadowError(
            "Reposkop shadow command exceeded a bounded output limit",
            category="capability_output_limit",
        )
    if result["returncode"] != 0:
        stderr = str(result.get("stderr") or "").lower()
        category = (
            "capability_unavailable"
            if result["returncode"] == 2
            and ("invalid choice" in stderr or "usage:" in stderr)
            else "capability_execution_error"
        )
        raise ReposkopShadowError(
            "Reposkop shadow command failed",
            category=category,
        )
    _path, post_executable_sha256 = reposkop_context._validate_executable(
        REPOSKOP_BIN
    )
    if post_executable_sha256 != executable_sha256:
        raise ReposkopShadowError(
            "Reposkop executable identity changed during shadow capture",
            category="executable_integrity_error",
        )
    post_target_descriptor = reposkop_context._open_validated_target_directory(target)
    try:
        post_target = os.fstat(post_target_descriptor)
        if (post_target.st_dev, post_target.st_ino) != target_identity:
            raise ReposkopShadowError(
                "Reposkop target identity changed during shadow capture",
                category="target_identity_changed",
            )
    finally:
        os.close(post_target_descriptor)
    stdout_data = result.get("stdout_data")
    if not isinstance(stdout_data, bytes):
        raise ReposkopShadowError(
            "Reposkop shadow stdout bytes are unavailable",
            category="capability_execution_error",
        )
    try:
        artifact = json.loads(
            stdout_data.decode("utf-8"), parse_constant=_reject_nonfinite
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReposkopShadowError(
            "Reposkop shadow output is not valid JSON",
            category="artifact_invalid",
        ) from exc
    if not isinstance(artifact, dict):
        raise ReposkopShadowError(
            "Reposkop shadow output is not an object",
            category="artifact_invalid",
        )
    return artifact, executable_sha256


def _validate_digest(value: dict[str, Any], field: str) -> str:
    digest = value.get(field)
    material = {key: item for key, item in value.items() if key != field}
    if (
        not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        or digest != _sha256_json(material)
    ):
        raise ReposkopShadowError(
            f"Reposkop {field} failed validation",
            category="artifact_invalid",
        )
    return digest


def _validate_authority(value: Any, *, domain: str) -> None:
    if value != {"producer": "reposkop", "domain": domain, "claim": "canonical"}:
        raise ReposkopShadowError(
            "Reposkop artifact authority is unsupported",
            category="artifact_invalid",
        )


def _validate_observation(
    value: Any,
    *,
    workspace: Path,
    purpose: str,
    require_complete: bool,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReposkopShadowError(
            "Reposkop observation is not an object",
            category="artifact_invalid",
        )
    _validate_authority(value.get("authority"), domain="local_checkout_identity")
    target = value.get("target")
    role = value.get("role")
    if (
        value.get("schema_version") != 2
        or value.get("kind") != "reposkop_checkout_observation"
        or not isinstance(target, dict)
        or target.get("path") != str(workspace)
        or target.get("purpose") != purpose
        or not isinstance(role, dict)
        or role.get("value") != "grabowski_workspace"
    ):
        raise ReposkopShadowError(
            "Reposkop observation binding is invalid",
            category="artifact_invalid",
        )
    if require_complete and (
        value.get("observation_complete") is not True
        or value.get("is_git_checkout") is not True
    ):
        raise ReposkopShadowError(
            "Reposkop BEFORE observation is unavailable",
            category="observation_unavailable",
        )
    _validate_digest(value, "observation_sha256")
    return value


def _stable_codes(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 64:
        raise ReposkopShadowError(
            "Reposkop reason-code shape is invalid",
            category="artifact_invalid",
        )
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or REASON_CODE_RE.fullmatch(item) is None:
            raise ReposkopShadowError(
                "Reposkop reason code is invalid",
                category="artifact_invalid",
            )
        result.append(item)
    if result != sorted(set(result)):
        raise ReposkopShadowError(
            "Reposkop reason codes are not canonical",
            category="artifact_invalid",
        )
    return result


def _measurement_class(state: str) -> str:
    if state == "identity_break":
        return "identity_break"
    if state in {"intact", "explainable_drift"}:
        return "intact/explainable_drift"
    return "inconclusive/unavailable"


def _validate_continuity(
    value: Any,
    *,
    before: dict[str, Any],
    workspace: Path,
    purpose: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReposkopShadowError(
            "Reposkop continuity is not an object",
            category="artifact_invalid",
        )
    _validate_authority(value.get("authority"), domain="local_checkout_continuity")
    state = value.get("state")
    transition = value.get("transition")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != "reposkop_checkout_continuity"
        or value.get("effect_authorized") is not False
        or state not in CONTINUITY_STATES
        or not isinstance(transition, dict)
        or value.get("transition_validation", {}).get("valid") is not True
    ):
        raise ReposkopShadowError(
            "Reposkop continuity contract is invalid",
            category="artifact_invalid",
        )
    _validate_authority(transition.get("authority"), domain="local_checkout_transition")
    if (
        transition.get("schema_version") != 1
        or transition.get("kind") != "reposkop_checkout_transition"
        or transition.get("effect_authorized") is not False
        or transition.get("before") != before
    ):
        raise ReposkopShadowError(
            "Reposkop transition contract is invalid",
            category="artifact_invalid",
        )
    before_digest = _validate_digest(before, "observation_sha256")
    after = _validate_observation(
        transition.get("after"),
        workspace=workspace,
        purpose=purpose,
        require_complete=False,
    )
    after_digest = after["observation_sha256"]
    transition_digest = _validate_digest(transition, "transition_sha256")
    continuity_digest = _validate_digest(value, "continuity_sha256")
    if (
        transition.get("before_observation_sha256") != before_digest
        or transition.get("after_observation_sha256") != after_digest
        or value.get("transition_sha256") != transition_digest
    ):
        raise ReposkopShadowError(
            "Reposkop continuity digest binding is invalid",
            category="artifact_invalid",
        )
    _stable_codes(value.get("reason_codes"))
    _stable_codes(transition.get("anomaly_codes"))
    return {
        "before_observation_sha256": before_digest,
        "after_observation_sha256": after_digest,
        "transition_sha256": transition_digest,
        "continuity_sha256": continuity_digest,
        "continuity_state": state,
        "measurement_class": _measurement_class(str(state)),
        "reason_codes": list(value["reason_codes"]),
        "anomaly_codes": list(transition["anomaly_codes"]),
    }


def _failure_category(error: BaseException) -> str:
    if isinstance(error, ReposkopShadowError):
        return error.category
    if isinstance(error, FileNotFoundError):
        return "target_or_capability_unavailable"
    if isinstance(error, PermissionError):
        return "permission_unavailable"
    return "shadow_internal_error"


def _append_event_once(path: Path | None, event: dict[str, Any]) -> str | None:
    if path is not None and path.exists():
        marker, _payload = _read_private_json(path)
        if (
            marker.get("schema_version") != 1
            or marker.get("kind") != "grabowski.reposkop_checkout_shadow_audit_binding"
            or marker.get("event_sha256") != _sha256_json(event)
            or not isinstance(marker.get("audit_ref"), str)
        ):
            raise ReposkopShadowError(
                "Reposkop shadow audit binding is invalid",
                category="evidence_integrity_error",
            )
        return str(marker["audit_ref"])
    try:
        audit_ref = reposkop_effectiveness.append_event(event)
    except Exception:
        return None
    if path is not None:
        marker = {
            "schema_version": 1,
            "kind": "grabowski.reposkop_checkout_shadow_audit_binding",
            "event_sha256": _sha256_json(event),
            "audit_ref": audit_ref,
            "decision_effect": False,
        }
        try:
            _write_or_match(path, _canonical_bytes(marker))
        except Exception:
            return audit_ref
    return audit_ref


def _public_summary(binding: dict[str, Any], audit_ref: str | None) -> dict[str, Any]:
    return {
        key: binding.get(key)
        for key in (
            "phase",
            "status",
            "task_id",
            "evaluation_id",
            "reposkop_cohort",
            "before_observation_sha256",
            "after_observation_sha256",
            "transition_sha256",
            "continuity_sha256",
            "continuity_state",
            "measurement_class",
            "failure_category",
            "evidence_sha256",
            "decision_effect",
            "effect_authorized",
        )
        if key in binding
    } | {"audit_ref": audit_ref}


def _existing_terminal_audit_summary(
    *,
    task_id: str,
    terminalization_sha256: str,
    lifecycle_receipt_sha256: str,
) -> dict[str, Any] | None:
    found = reposkop_effectiveness.find_event_by_identity(
        {
            "operation": TERMINAL_OPERATION,
            "task_id": task_id,
            "terminalization_sha256": terminalization_sha256,
            "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        },
        synchronize=False,
    )
    if found is None:
        return None
    record = found.get("record")
    audit_ref = found.get("audit_ref")
    if (
        not isinstance(record, dict)
        or not isinstance(audit_ref, str)
        or record.get("operation") != TERMINAL_OPERATION
        or record.get("task_id") != task_id
        or record.get("terminalization_sha256") != terminalization_sha256
        or record.get("lifecycle_receipt_sha256") != lifecycle_receipt_sha256
        or record.get("shadow_phase") != "terminal"
        or record.get("shadow_status") not in {"completed", "unavailable"}
        or record.get("attempted") is not True
        or record.get("measurement_only") is not True
        or record.get("decision_effect") is not False
        or record.get("effect_authorized") is not False
    ):
        raise ReposkopShadowError(
            "existing Reposkop terminal audit event failed validation",
            category="evidence_integrity_error",
        )
    evidence_sha256 = record.get("shadow_evidence_sha256")
    if (
        not isinstance(evidence_sha256, str)
        or SHA256_RE.fullmatch(evidence_sha256) is None
    ):
        raise ReposkopShadowError(
            "existing Reposkop terminal audit evidence digest is invalid",
            category="evidence_integrity_error",
        )
    binding = {
        "phase": "terminal",
        "status": record["shadow_status"],
        "task_id": task_id,
        "evaluation_id": record.get("evaluation_id"),
        "reposkop_cohort": record.get("reposkop_cohort"),
        "before_observation_sha256": record.get("before_observation_sha256"),
        "after_observation_sha256": record.get("after_observation_sha256"),
        "transition_sha256": record.get("transition_sha256"),
        "continuity_sha256": record.get("continuity_sha256"),
        "continuity_state": record.get("continuity_state"),
        "measurement_class": record.get("measurement_class"),
        "failure_category": record.get("failure_category"),
        "evidence_sha256": evidence_sha256,
        "decision_effect": False,
        "effect_authorized": False,
    }
    return _public_summary(binding, audit_ref)


def capture_before_best_effort(
    *,
    task_id: str,
    workspace: str,
    evaluation_id: str | None,
    reposkop_cohort: str | None,
) -> dict[str, Any] | None:
    candidate = _workspace_eligible_for_before(workspace)
    if candidate is None:
        return None
    purpose = f"grabowski-task-shadow:{_task_key(task_id)[:32]}"
    root: Path | None = None
    paths: dict[str, Path] | None = None
    binding: dict[str, Any]
    try:
        root = _ensure_root()
        paths = _paths(root, task_id)
        if paths["before_binding"].exists():
            binding_value, _payload = _read_private_json(paths["before_binding"])
            binding = _validate_binding(
                binding_value, task_id=task_id, phase="before"
            )
        else:
            observation, executable_sha256 = _run_reposkop(
                "inspect", candidate, purpose=purpose
            )
            observation = _validate_observation(
                observation,
                workspace=candidate,
                purpose=purpose,
                require_complete=True,
            )
            artifact_payload = _canonical_bytes(observation)
            _write_or_match(paths["before_artifact"], artifact_payload)
            material = {
                "schema_version": 1,
                "kind": "grabowski.reposkop_checkout_shadow_evidence",
                "phase": "before",
                "status": "completed",
                "task_id": task_id,
                "evaluation_id": evaluation_id,
                "reposkop_cohort": reposkop_cohort,
                "workspace": str(candidate),
                "purpose": purpose,
                "captured_at_unix": int(time.time()),
                "before_observation_sha256": observation["observation_sha256"],
                "artifact_file_sha256": _sha256_bytes(artifact_payload),
                "reposkop_executable_sha256": executable_sha256,
                "decision_effect": False,
                "effect_authorized": False,
            }
            binding = _binding_payload(material)
            _write_or_match(paths["before_binding"], _canonical_bytes(binding))
    except Exception as exc:
        failure_category = _failure_category(exc)
        material = {
            "schema_version": 1,
            "kind": "grabowski.reposkop_checkout_shadow_evidence",
            "phase": "before",
            "status": "unavailable",
            "task_id": task_id,
            "evaluation_id": evaluation_id,
            "reposkop_cohort": reposkop_cohort,
            "workspace": str(candidate),
            "purpose": purpose,
            "captured_at_unix": int(time.time()),
            "failure_category": failure_category,
            "measurement_class": "inconclusive/unavailable",
            "decision_effect": False,
            "effect_authorized": False,
        }
        binding = _binding_payload(material)
        if root is not None and paths is not None:
            try:
                _write_or_match(paths["before_binding"], _canonical_bytes(binding))
            except Exception:
                pass
    event = {
        "timestamp_unix": binding["captured_at_unix"],
        "operation": BEFORE_OPERATION,
        "task_id": task_id,
        "evaluation_id": evaluation_id,
        "reposkop_cohort": reposkop_cohort,
        "shadow_phase": "before",
        "shadow_status": binding["status"],
        "attempted": True,
        "before_observation_sha256": binding.get("before_observation_sha256"),
        "shadow_evidence_sha256": binding["evidence_sha256"],
        "failure_category": binding.get("failure_category"),
        "continuity_state": None,
        "measurement_class": binding.get("measurement_class"),
        "reason_codes": [],
        "anomaly_codes": [],
        "measurement_only": True,
        "decision_effect": False,
        "effect_authorized": False,
    }
    try:
        audit_ref = _append_event_once(
            paths["before_audit"] if paths is not None else None,
            event,
        )
    except Exception:
        audit_ref = None
    return _public_summary(binding, audit_ref)


def _before_summary_value(before_summary: dict[str, Any] | None, key: str) -> Any:
    if not isinstance(before_summary, dict):
        return None
    return before_summary.get(key)


def prepare_terminal_best_effort(
    *,
    task_id: str,
    before_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_task_id(task_id)
    before_binding: dict[str, Any] | None = None
    try:
        root = _ensure_root()
        paths = _paths(root, task_id)
        before_value, _payload = _read_private_json(paths["before_binding"])
        before_binding = _validate_binding(
            before_value, task_id=task_id, phase="before"
        )
        if before_binding.get("status") != "completed":
            raise ReposkopShadowError(
                "Reposkop BEFORE shadow is unavailable",
                category="before_unavailable",
            )
        if isinstance(before_summary, dict):
            for key in (
                "evaluation_id",
                "reposkop_cohort",
                "before_observation_sha256",
                "evidence_sha256",
            ):
                supplied = before_summary.get(key)
                expected = (
                    before_binding.get("evidence_sha256")
                    if key == "evidence_sha256"
                    else before_binding.get(key)
                )
                if supplied is not None and supplied != expected:
                    raise ReposkopShadowError(
                        "Reposkop BEFORE summary lost its private binding",
                        category="evidence_integrity_error",
                    )
        workspace = _workspace_observable(str(before_binding.get("workspace") or ""))
        if workspace is None:
            raise ReposkopShadowError(
                "Reposkop shadow workspace is no longer observable",
                category="workspace_unavailable",
            )
        purpose = str(before_binding.get("purpose") or "")
        before, before_payload = _read_private_json(paths["before_artifact"])
        before = _validate_observation(
            before,
            workspace=workspace,
            purpose=purpose,
            require_complete=True,
        )
        if (
            _sha256_bytes(before_payload)
            != before_binding.get("artifact_file_sha256")
            or before["observation_sha256"]
            != before_binding.get("before_observation_sha256")
        ):
            raise ReposkopShadowError(
                "Reposkop BEFORE artifact lost its binding",
                category="evidence_integrity_error",
            )
        continuity, executable_sha256 = _run_reposkop(
            "continuity",
            workspace,
            purpose=purpose,
            expected_artifact=paths["before_artifact"],
        )
        result = _validate_continuity(
            continuity,
            before=before,
            workspace=workspace,
            purpose=purpose,
        )
        artifact_payload = _canonical_bytes(continuity)
        _write_or_match(paths["terminal_artifact"], artifact_payload)
        material = {
            "schema_version": 1,
            "kind": "grabowski.reposkop_checkout_shadow_evidence",
            "phase": "terminal_prepare",
            "status": "completed",
            "task_id": task_id,
            "evaluation_id": before_binding.get("evaluation_id"),
            "reposkop_cohort": before_binding.get("reposkop_cohort"),
            "captured_at_unix": int(time.time()),
            "before_evidence_sha256": before_binding["evidence_sha256"],
            **result,
            "artifact_file_sha256": _sha256_bytes(artifact_payload),
            "reposkop_executable_sha256": executable_sha256,
            "decision_effect": False,
            "effect_authorized": False,
        }
    except Exception as exc:
        failure_category = _failure_category(exc)
        fallback = before_binding or {}
        evaluation_id = fallback.get("evaluation_id")
        reposkop_cohort = fallback.get("reposkop_cohort")
        before_evidence_sha256 = fallback.get("evidence_sha256")
        before_observation_sha256 = fallback.get("before_observation_sha256")
        if evaluation_id is None:
            evaluation_id = _before_summary_value(before_summary, "evaluation_id")
        if reposkop_cohort is None:
            reposkop_cohort = _before_summary_value(before_summary, "reposkop_cohort")
        if before_evidence_sha256 is None:
            before_evidence_sha256 = _before_summary_value(before_summary, "evidence_sha256")
        if before_observation_sha256 is None:
            before_observation_sha256 = _before_summary_value(
                before_summary, "before_observation_sha256"
            )
        material = {
            "schema_version": 1,
            "kind": "grabowski.reposkop_checkout_shadow_evidence",
            "phase": "terminal_prepare",
            "status": "unavailable",
            "task_id": task_id,
            "evaluation_id": evaluation_id,
            "reposkop_cohort": reposkop_cohort,
            "captured_at_unix": int(time.time()),
            "before_evidence_sha256": before_evidence_sha256,
            "before_observation_sha256": before_observation_sha256,
            "failure_category": failure_category,
            "continuity_state": "inconclusive",
            "measurement_class": "inconclusive/unavailable",
            "reason_codes": [f"shadow.{failure_category}"],
            "anomaly_codes": [],
            "decision_effect": False,
            "effect_authorized": False,
        }
    return _binding_payload(material)


def _validated_terminal_prepare(
    value: dict[str, Any], *, task_id: str
) -> dict[str, Any]:
    prepared = _validate_binding(value, task_id=task_id, phase="terminal_prepare")
    if prepared.get("status") not in {"completed", "unavailable"}:
        raise ReposkopShadowError(
            "Reposkop terminal prepare status is invalid",
            category="evidence_integrity_error",
        )
    if prepared.get("status") == "completed":
        state = prepared.get("continuity_state")
        if state not in CONTINUITY_STATES:
            raise ReposkopShadowError(
                "Reposkop terminal prepare continuity state is invalid",
                category="evidence_integrity_error",
            )
        for field in (
            "before_observation_sha256",
            "after_observation_sha256",
            "transition_sha256",
            "continuity_sha256",
            "artifact_file_sha256",
            "reposkop_executable_sha256",
        ):
            item = prepared.get(field)
            if not isinstance(item, str) or SHA256_RE.fullmatch(item) is None:
                raise ReposkopShadowError(
                    "Reposkop terminal prepare digest is invalid",
                    category="evidence_integrity_error",
                )
        _stable_codes(prepared.get("reason_codes"))
        _stable_codes(prepared.get("anomaly_codes"))
    else:
        if prepared.get("continuity_state") != "inconclusive":
            raise ReposkopShadowError(
                "Reposkop unavailable terminal prepare must be inconclusive",
                category="evidence_integrity_error",
            )
        if prepared.get("measurement_class") != "inconclusive/unavailable":
            raise ReposkopShadowError(
                "Reposkop unavailable terminal prepare class is invalid",
                category="evidence_integrity_error",
            )
        failure_category = prepared.get("failure_category")
        if not isinstance(failure_category, str) or not failure_category:
            raise ReposkopShadowError(
                "Reposkop unavailable terminal prepare lacks a failure category",
                category="evidence_integrity_error",
            )
    return prepared


def _finalize_terminal_under_identity_lock(
    *,
    task_id: str,
    terminalization_sha256: str,
    lifecycle_receipt_sha256: str,
    prepared: dict[str, Any],
) -> dict[str, Any] | None:
    # A peer can append and crash after our outer pre-sync but before we acquire
    # this identity stripe. Catch up that short tail while serialization is held.
    reposkop_effectiveness.sync_event_identity_index()
    existing_audit = _existing_terminal_audit_summary(
        task_id=task_id,
        terminalization_sha256=terminalization_sha256,
        lifecycle_receipt_sha256=lifecycle_receipt_sha256,
    )
    if existing_audit is not None:
        return existing_audit
    material = {
        "schema_version": 1,
        "kind": "grabowski.reposkop_checkout_shadow_evidence",
        "phase": "terminal",
        "status": prepared["status"],
        "task_id": task_id,
        "evaluation_id": prepared.get("evaluation_id"),
        "reposkop_cohort": prepared.get("reposkop_cohort"),
        "captured_at_unix": int(prepared["captured_at_unix"]),
        "terminal_observed_at_unix": int(prepared["captured_at_unix"]),
        "terminalization_sha256": terminalization_sha256,
        "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        "before_evidence_sha256": prepared.get("before_evidence_sha256"),
        "before_observation_sha256": prepared.get("before_observation_sha256"),
        "after_observation_sha256": prepared.get("after_observation_sha256"),
        "transition_sha256": prepared.get("transition_sha256"),
        "continuity_sha256": prepared.get("continuity_sha256"),
        "artifact_file_sha256": prepared.get("artifact_file_sha256"),
        "continuity_state": prepared.get("continuity_state"),
        "measurement_class": prepared.get("measurement_class"),
        "reason_codes": list(prepared.get("reason_codes") or []),
        "anomaly_codes": list(prepared.get("anomaly_codes") or []),
        "failure_category": prepared.get("failure_category"),
        "reposkop_executable_sha256": prepared.get("reposkop_executable_sha256"),
        "prepare_evidence_sha256": prepared["evidence_sha256"],
        "decision_effect": False,
        "effect_authorized": False,
    }
    binding = _binding_payload(material)
    audit_binding = binding
    paths: dict[str, Path] | None = None
    try:
        root = _ensure_root()
        paths = _paths(root, task_id)
        if prepared["status"] == "completed":
            _artifact_value, artifact_payload = _read_private_json(
                paths["terminal_artifact"]
            )
            if _sha256_bytes(artifact_payload) != prepared.get("artifact_file_sha256"):
                raise ReposkopShadowError(
                    "Reposkop terminal continuity artifact lost its prepare binding",
                    category="evidence_integrity_error",
                )
        if paths["terminal_binding"].exists():
            existing_value, _payload = _read_private_json(paths["terminal_binding"])
            existing = _validate_binding(
                existing_value, task_id=task_id, phase="terminal"
            )
            if existing != binding:
                raise ReposkopShadowError(
                    "Reposkop terminal shadow binding conflicts with terminal truth",
                    category="evidence_integrity_error",
                )
            binding = existing
            audit_binding = existing
        else:
            _write_or_match(paths["terminal_binding"], _canonical_bytes(binding))
    except Exception as exc:
        # The continuity observation may have succeeded while its private terminal
        # binding became unavailable. Do not report that case as completed: keep
        # the private evidence absent and emit an independent public unavailable
        # event so effectiveness metrics cannot silently lose the failure.
        failure_category = _failure_category(exc)
        unavailable_material = {
            "schema_version": 1,
            "kind": "grabowski.reposkop_checkout_shadow_evidence",
            "phase": "terminal",
            "status": "unavailable",
            "task_id": task_id,
            "evaluation_id": prepared.get("evaluation_id"),
            "reposkop_cohort": prepared.get("reposkop_cohort"),
            "captured_at_unix": int(prepared["captured_at_unix"]),
            "terminal_observed_at_unix": int(prepared["captured_at_unix"]),
            "terminalization_sha256": terminalization_sha256,
            "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
            "before_evidence_sha256": prepared.get("before_evidence_sha256"),
            "before_observation_sha256": prepared.get("before_observation_sha256"),
            "after_observation_sha256": None,
            "transition_sha256": None,
            "continuity_sha256": None,
            "artifact_file_sha256": prepared.get("artifact_file_sha256"),
            "continuity_state": "inconclusive",
            "measurement_class": "inconclusive/unavailable",
            "reason_codes": [f"shadow.{failure_category}"],
            "anomaly_codes": [],
            "failure_category": failure_category,
            "reposkop_executable_sha256": prepared.get("reposkop_executable_sha256"),
            "prepare_evidence_sha256": prepared["evidence_sha256"],
            "decision_effect": False,
            "effect_authorized": False,
        }
        audit_binding = _binding_payload(unavailable_material)
        paths = None
    event = {
        "timestamp_unix": audit_binding["terminal_observed_at_unix"],
        "operation": TERMINAL_OPERATION,
        "task_id": task_id,
        "evaluation_id": audit_binding.get("evaluation_id"),
        "reposkop_cohort": audit_binding.get("reposkop_cohort"),
        "shadow_phase": "terminal",
        "shadow_status": audit_binding["status"],
        "attempted": True,
        "terminalization_sha256": terminalization_sha256,
        "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        "before_observation_sha256": audit_binding.get("before_observation_sha256"),
        "after_observation_sha256": audit_binding.get("after_observation_sha256"),
        "transition_sha256": audit_binding.get("transition_sha256"),
        "continuity_sha256": audit_binding.get("continuity_sha256"),
        "artifact_file_sha256": audit_binding.get("artifact_file_sha256"),
        "continuity_state": audit_binding.get("continuity_state"),
        "measurement_class": audit_binding.get("measurement_class"),
        "reason_codes": list(audit_binding.get("reason_codes") or []),
        "anomaly_codes": list(audit_binding.get("anomaly_codes") or []),
        "failure_category": audit_binding.get("failure_category"),
        "shadow_evidence_sha256": audit_binding["evidence_sha256"],
        "measurement_only": True,
        "decision_effect": False,
        "effect_authorized": False,
    }
    try:
        audit_ref = _append_event_once(
            paths["terminal_audit"] if paths is not None else None,
            event,
        )
        if audit_ref is not None:
            reposkop_effectiveness.sync_event_identity_index()
    except Exception:
        audit_ref = None
    return _public_summary(audit_binding, audit_ref)



def finalize_terminal_best_effort(
    *,
    task_id: str,
    terminalization_sha256: str,
    lifecycle_receipt_sha256: str,
    prepared: dict[str, Any],
) -> dict[str, Any] | None:
    try:
        _validate_task_id(task_id)
        if (
            SHA256_RE.fullmatch(terminalization_sha256) is None
            or SHA256_RE.fullmatch(lifecycle_receipt_sha256) is None
        ):
            return None
        prepared = _validated_terminal_prepare(dict(prepared), task_id=task_id)
        # Synchronize outside the striped identity lock: bootstrap or a large crash tail
        # must never consume the stripe's short lock budget.
        reposkop_effectiveness.sync_event_identity_index()
        identity = {
            "operation": TERMINAL_OPERATION,
            "task_id": task_id,
            "terminalization_sha256": terminalization_sha256,
            "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        }
        with reposkop_effectiveness.event_identity_lock(identity):
            return _finalize_terminal_under_identity_lock(
                task_id=task_id,
                terminalization_sha256=terminalization_sha256,
                lifecycle_receipt_sha256=lifecycle_receipt_sha256,
                prepared=prepared,
            )
    except Exception:
        return None

def capture_terminal_best_effort(
    *,
    task_id: str,
    terminalization_sha256: str,
    lifecycle_receipt_sha256: str,
) -> dict[str, Any] | None:
    prepared = prepare_terminal_best_effort(task_id=task_id)
    return finalize_terminal_best_effort(
        task_id=task_id,
        terminalization_sha256=terminalization_sha256,
        lifecycle_receipt_sha256=lifecycle_receipt_sha256,
        prepared=prepared,
    )
