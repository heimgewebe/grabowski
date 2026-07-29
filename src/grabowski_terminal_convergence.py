from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

SCHEMA_VERSION = 1
EXECUTION_IDENTITY_SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"[0-9a-f]{64}")
FAILURE_CLASSES = frozenset({
    "completed",
    "running",
    "retry_safe_failure",
    "retry_exhausted",
    "outcome_unknown",
    "stale_process",
    "non_retryable_failure",
    "evidence_drift",
    "observation_denied",
})
TERMINAL_FAILURE_STATES = frozenset({"failed", "timed_out", "signalled", "interrupted"})
RETRY_SOURCE_STATES = frozenset(
    {"failed", "timed_out", "signalled", "interrupted", "outcome_unknown"}
)
RETRY_SUCCESSOR_SUPPORT_STATES = frozenset({"launching", "running", "completed"})
TASK_ID_RE = re.compile(r"[0-9a-f]{24}\Z")


class TerminalConvergenceError(ValueError):
    pass


@dataclass(frozen=True)
class TerminalFailureClassification:
    reason_class: str
    retryable: bool
    automatic_resume_allowed: bool
    owner_decision_required: bool
    terminal_evidence_required: bool
    lease_evidence_required: bool
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "reason_class": self.reason_class,
            "retryable": self.retryable,
            "automatic_resume_allowed": self.automatic_resume_allowed,
            "owner_decision_required": self.owner_decision_required,
            "terminal_evidence_required": self.terminal_evidence_required,
            "lease_evidence_required": self.lease_evidence_required,
            "reason": self.reason,
        }


def classify_terminal_failure(
    *,
    current_state: str,
    observed_state: str,
    resume_policy: str,
    terminal_evidence_valid: bool,
    lease_evidence_valid: bool,
    retry_count: int = 0,
    retry_limit: int = 1,
    observation_denied: bool = False,
) -> dict[str, Any]:
    if not isinstance(current_state, str) or not isinstance(observed_state, str):
        raise TerminalConvergenceError("task states must be strings")
    if not isinstance(resume_policy, str) or not resume_policy:
        raise TerminalConvergenceError("resume_policy must be a non-empty string")
    if not isinstance(terminal_evidence_valid, bool) or not isinstance(lease_evidence_valid, bool):
        raise TerminalConvergenceError("evidence flags must be boolean")
    if isinstance(retry_count, bool) or not isinstance(retry_count, int) or retry_count < 0:
        raise TerminalConvergenceError("retry_count must be a non-negative integer")
    if isinstance(retry_limit, bool) or not isinstance(retry_limit, int) or retry_limit < 1:
        raise TerminalConvergenceError("retry_limit must be a positive integer")

    if observation_denied:
        result = TerminalFailureClassification(
            "observation_denied", False, False, True, True, True,
            "authoritative task observation was denied",
        )
    elif observed_state == "running":
        result = TerminalFailureClassification(
            "running", False, False, False, False, False,
            "task is still running",
        )
    elif observed_state == "completed":
        result = TerminalFailureClassification(
            "completed", False, False, False, True, False,
            "task completed and must converge through terminal evidence",
        )
    elif observed_state == "outcome_unknown":
        result = TerminalFailureClassification(
            "outcome_unknown", False, False, True, True, True,
            "outcome_unknown requires authoritative verification before retry",
        )
    elif current_state == "running" and observed_state in {"interrupted", "failed", "timed_out", "signalled"} and not terminal_evidence_valid:
        result = TerminalFailureClassification(
            "stale_process", False, False, True, True, True,
            "process disappeared without valid terminal evidence",
        )
    elif not terminal_evidence_valid or not lease_evidence_valid:
        result = TerminalFailureClassification(
            "evidence_drift", False, False, True, True, True,
            "terminal or lease evidence does not match the current task binding",
        )
    elif resume_policy != "retry-safe":
        result = TerminalFailureClassification(
            "non_retryable_failure", False, False, True, True, True,
            "task resume policy does not permit automatic retry",
        )
    elif retry_count >= retry_limit:
        result = TerminalFailureClassification(
            "retry_exhausted", False, False, True, True, True,
            "retry budget is exhausted",
        )
    elif observed_state in TERMINAL_FAILURE_STATES:
        result = TerminalFailureClassification(
            "retry_safe_failure", True, True, False, True, True,
            "verified retry-safe terminal failure may be resumed",
        )
    else:
        result = TerminalFailureClassification(
            "non_retryable_failure", False, False, True, True, True,
            "observed state is not eligible for automatic retry",
        )
    return result.to_json()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def task_execution_identity(
    *,
    host: str,
    argv_sha256: str,
    cwd: str,
    resource_keys: list[str],
    runtime_seconds: int,
    cpu_weight: int,
    io_weight: int,
    memory_max_bytes: int | None,
    chronik_outbox_enabled: bool,
    chronik_outbox_state_root: str | None,
    chronik_context: dict[str, Any] | None,
    execution_backend: str,
    systemd_scope: str,
) -> dict[str, Any]:
    material = {
        "schema_version": EXECUTION_IDENTITY_SCHEMA_VERSION,
        "host": host,
        "argv_sha256": argv_sha256,
        "cwd": cwd,
        "resource_keys": sorted(set(resource_keys)),
        "runtime_seconds": runtime_seconds,
        "cpu_weight": cpu_weight,
        "io_weight": io_weight,
        "memory_max_bytes": memory_max_bytes,
        "chronik_outbox_enabled": chronik_outbox_enabled,
        "chronik_outbox_state_root": chronik_outbox_state_root,
        "chronik_context": chronik_context,
        "execution_backend": execution_backend,
        "systemd_scope": systemd_scope,
    }
    return {
        **material,
        "identity_sha256": hashlib.sha256(
            _canonical_json(material).encode("utf-8")
        ).hexdigest(),
    }


def attention_execution_identity(record: dict[str, Any]) -> str | None:
    required = (
        "host",
        "argv_sha256",
        "cwd",
        "runtime_seconds",
        "cpu_weight",
        "io_weight",
        "chronik_outbox_enabled",
        "chronik_outbox_state_root",
        "chronik_context_json",
        "execution_backend",
        "systemd_scope",
    )
    identity_signals = (
        "host",
        "cwd",
        "resource_keys_json",
        "resource_keys",
        "runtime_seconds",
        "execution_backend",
        "systemd_scope",
    )
    if not any(key in record for key in identity_signals):
        return None
    if any(key not in record for key in required):
        raise TerminalConvergenceError("attention execution identity is incomplete")
    host = record["host"]
    argv_sha256 = record["argv_sha256"]
    cwd = record["cwd"]
    if not isinstance(host, str) or not host:
        raise TerminalConvergenceError("attention execution identity host is invalid")
    if not isinstance(argv_sha256, str) or SHA256_RE.fullmatch(argv_sha256) is None:
        raise TerminalConvergenceError("attention execution identity argv hash is invalid")
    if not isinstance(cwd, str) or not cwd:
        raise TerminalConvergenceError("attention execution identity cwd is invalid")
    raw_resources = record.get("resource_keys_json")
    if raw_resources is None:
        raw_resources = record.get("resource_keys", [])
    elif isinstance(raw_resources, str):
        try:
            raw_resources = json.loads(raw_resources)
        except json.JSONDecodeError as exc:
            raise TerminalConvergenceError(
                "attention execution identity resource keys are invalid"
            ) from exc
    if not isinstance(raw_resources, list) or any(
        not isinstance(value, str) or not value for value in raw_resources
    ):
        raise TerminalConvergenceError(
            "attention execution identity resource keys are invalid"
        )
    integer_fields = ("runtime_seconds", "cpu_weight", "io_weight")
    for key in integer_fields:
        value = record[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TerminalConvergenceError(
                f"attention execution identity {key} is invalid"
            )
    memory_max_bytes = record.get("memory_max_bytes")
    if memory_max_bytes is not None and (
        isinstance(memory_max_bytes, bool)
        or not isinstance(memory_max_bytes, int)
        or memory_max_bytes < 0
    ):
        raise TerminalConvergenceError(
            "attention execution identity memory limit is invalid"
        )
    chronik_outbox_enabled = record["chronik_outbox_enabled"]
    if chronik_outbox_enabled not in {0, 1, False, True}:
        raise TerminalConvergenceError(
            "attention execution identity Chronik flag is invalid"
        )
    chronik_state_root = record["chronik_outbox_state_root"]
    if chronik_state_root is not None and not isinstance(chronik_state_root, str):
        raise TerminalConvergenceError(
            "attention execution identity Chronik state root is invalid"
        )
    raw_chronik_context = record["chronik_context_json"]
    if raw_chronik_context is None:
        chronik_context = None
    elif isinstance(raw_chronik_context, str):
        try:
            chronik_context = json.loads(raw_chronik_context)
        except json.JSONDecodeError as exc:
            raise TerminalConvergenceError(
                "attention execution identity Chronik context is invalid"
            ) from exc
    else:
        raise TerminalConvergenceError(
            "attention execution identity Chronik context is invalid"
        )
    execution_backend = record["execution_backend"]
    systemd_scope = record["systemd_scope"]
    if not isinstance(execution_backend, str) or not execution_backend:
        raise TerminalConvergenceError(
            "attention execution identity backend is invalid"
        )
    if not isinstance(systemd_scope, str) or not systemd_scope:
        raise TerminalConvergenceError(
            "attention execution identity systemd scope is invalid"
        )
    return task_execution_identity(
        host=host,
        argv_sha256=argv_sha256,
        cwd=cwd,
        resource_keys=raw_resources,
        runtime_seconds=record["runtime_seconds"],
        cpu_weight=record["cpu_weight"],
        io_weight=record["io_weight"],
        memory_max_bytes=memory_max_bytes,
        chronik_outbox_enabled=bool(chronik_outbox_enabled),
        chronik_outbox_state_root=chronik_state_root,
        chronik_context=chronik_context,
        execution_backend=execution_backend,
        systemd_scope=systemd_scope,
    )["identity_sha256"]


def persisted_retry_binding(record: dict[str, Any]) -> dict[str, Any] | None:
    raw_launcher = record.get("launcher_json")
    if raw_launcher is None:
        raw_launcher = record.get("launcher")
    if raw_launcher is None:
        return None
    if isinstance(raw_launcher, str):
        try:
            launcher = json.loads(raw_launcher)
        except json.JSONDecodeError as exc:
            raise TerminalConvergenceError("persisted task launcher is invalid") from exc
    elif isinstance(raw_launcher, dict):
        launcher = raw_launcher
    else:
        raise TerminalConvergenceError("persisted task launcher is invalid")
    binding = launcher.get("retry_binding")
    if binding is None:
        return None
    if not isinstance(binding, dict):
        raise TerminalConvergenceError("persisted retry binding is invalid")
    required = {
        "schema_version",
        "kind",
        "source_task_id",
        "source_attempt",
        "source_state",
        "source_resume_policy",
        "source_lifecycle_receipt_sha256",
        "source_terminalization_sha256",
        "source_execution_identity_sha256",
        "named_state_change",
        "observed_at_unix",
        "does_not_establish",
        "context_sha256",
    }
    if set(binding) != required:
        raise TerminalConvergenceError("persisted retry binding shape is invalid")
    material = {key: binding[key] for key in required - {"context_sha256"}}
    context_sha256 = binding["context_sha256"]
    if (
        not isinstance(context_sha256, str)
        or SHA256_RE.fullmatch(context_sha256) is None
        or hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()
        != context_sha256
    ):
        raise TerminalConvergenceError("persisted retry binding integrity is invalid")
    if binding["schema_version"] != 1 or binding["kind"] != "grabowski_named_terminal_retry":
        raise TerminalConvergenceError("persisted retry binding contract is invalid")
    source_task_id = binding["source_task_id"]
    source_attempt = binding["source_attempt"]
    source_state = binding["source_state"]
    source_resume_policy = binding["source_resume_policy"]
    if not isinstance(source_task_id, str) or TASK_ID_RE.fullmatch(source_task_id) is None:
        raise TerminalConvergenceError("persisted retry source task is invalid")
    if isinstance(source_attempt, bool) or not isinstance(source_attempt, int) or source_attempt < 1:
        raise TerminalConvergenceError("persisted retry source attempt is invalid")
    if source_state not in RETRY_SOURCE_STATES:
        raise TerminalConvergenceError("persisted retry source state is invalid")
    if not isinstance(source_resume_policy, str) or not source_resume_policy:
        raise TerminalConvergenceError("persisted retry source policy is invalid")
    for key in (
        "source_lifecycle_receipt_sha256",
        "source_terminalization_sha256",
        "source_execution_identity_sha256",
    ):
        value = binding[key]
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise TerminalConvergenceError(f"persisted retry {key} is invalid")
    named_state_change = binding["named_state_change"]
    if not isinstance(named_state_change, str) or not named_state_change.strip():
        raise TerminalConvergenceError("persisted retry state change is invalid")
    observed_at_unix = binding["observed_at_unix"]
    if (
        isinstance(observed_at_unix, bool)
        or not isinstance(observed_at_unix, int)
        or observed_at_unix < 0
    ):
        raise TerminalConvergenceError("persisted retry observation time is invalid")
    non_claims = binding["does_not_establish"]
    if not isinstance(non_claims, list) or any(
        not isinstance(item, str) or not item for item in non_claims
    ):
        raise TerminalConvergenceError("persisted retry non-claims are invalid")
    return dict(binding)


def converge_attention_records(
    records: list[dict[str, Any]],
    *,
    attention_task_ids: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(records, list):
        raise TerminalConvergenceError("attention records must be a list")
    groups: dict[str, list[dict[str, Any]]] = {}
    for index, raw in enumerate(records):
        if not isinstance(raw, dict):
            raise TerminalConvergenceError(f"attention record {index} must be an object")
        task_id = raw.get("task_id")
        attempt = raw.get("attempt")
        outcome = raw.get("lifecycle_receipt_sha256")
        if not isinstance(task_id, str) or not task_id:
            raise TerminalConvergenceError(f"attention record {index} task_id is invalid")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise TerminalConvergenceError(f"attention record {index} attempt is invalid")
        if outcome is not None and (not isinstance(outcome, str) or len(outcome) != 64):
            raise TerminalConvergenceError(f"attention record {index} lifecycle receipt is invalid")
        updated_at = raw.get("updated_at_unix", 0)
        if isinstance(updated_at, bool) or not isinstance(updated_at, int) or updated_at < 0:
            raise TerminalConvergenceError(f"attention record {index} updated_at_unix is invalid")
        groups.setdefault(task_id, []).append(dict(raw))

    if attention_task_ids is None:
        scoped_task_ids = set(groups)
    else:
        if not isinstance(attention_task_ids, set) or any(
            not isinstance(task_id, str) or not task_id
            for task_id in attention_task_ids
        ):
            raise TerminalConvergenceError(
                "attention_task_ids must be a set of non-empty strings"
            )
        scoped_task_ids = set(attention_task_ids)
        missing_task_ids = scoped_task_ids - set(groups)
        if missing_task_ids:
            raise TerminalConvergenceError(
                "attention scope references missing task records"
            )

    current: list[dict[str, Any]] = []
    historical: list[dict[str, Any]] = []
    for task_id in sorted(groups):
        ordered = sorted(
            groups[task_id],
            key=lambda item: (
                int(item["attempt"]),
                int(item.get("updated_at_unix") or 0),
                str(item.get("lifecycle_receipt_sha256") or ""),
            ),
        )
        winner = ordered[-1]
        current.append(winner)
        winner_binding = (winner["attempt"], winner.get("lifecycle_receipt_sha256"))
        seen_bindings: set[tuple[Any, Any]] = {winner_binding}
        for item in reversed(ordered[:-1]):
            binding = (item["attempt"], item.get("lifecycle_receipt_sha256"))
            if binding in seen_bindings:
                classification = "duplicate"
            elif int(item["attempt"]) < int(winner["attempt"]):
                classification = "superseded"
            else:
                classification = "already_satisfied"
            seen_bindings.add(binding)
            if task_id in scoped_task_ids:
                historical.append(
                    {**item, "convergence_classification": classification}
                )
    current_by_task = {str(item["task_id"]): item for item in current}
    verified_retry_edges: dict[str, dict[str, Any]] = {}
    verified_identities: set[str] = set()
    for successor in current:
        binding = persisted_retry_binding(successor)
        if binding is None:
            continue
        source_task_id = str(binding["source_task_id"])
        if source_task_id not in scoped_task_ids:
            continue
        successor_task_id = str(successor["task_id"])
        support_successor = successor_task_id not in scoped_task_ids
        successor_state = successor.get("state")
        if (
            support_successor
            and successor_state not in RETRY_SUCCESSOR_SUPPORT_STATES
        ):
            raise TerminalConvergenceError(
                "persisted retry successor state is not support-eligible"
            )
        if support_successor and successor_state == "completed":
            lifecycle_receipt = successor.get("lifecycle_receipt_sha256")
            terminalization = successor.get("terminalization_sha256")
            terminalized_at = successor.get("terminalized_at_unix")
            if (
                not isinstance(lifecycle_receipt, str)
                or SHA256_RE.fullmatch(lifecycle_receipt) is None
                or not isinstance(terminalization, str)
                or SHA256_RE.fullmatch(terminalization) is None
                or isinstance(terminalized_at, bool)
                or not isinstance(terminalized_at, int)
                or terminalized_at < int(binding["observed_at_unix"])
            ):
                raise TerminalConvergenceError(
                    "completed retry successor terminal evidence is invalid"
                )
        if source_task_id == successor_task_id:
            raise TerminalConvergenceError("persisted retry binding is self-referential")
        source = current_by_task.get(source_task_id)
        if source is None:
            raise TerminalConvergenceError("persisted retry source task is not current attention")
        if source_task_id in verified_retry_edges:
            raise TerminalConvergenceError("persisted retry source has multiple successors")
        source_identity = attention_execution_identity(source)
        successor_identity = attention_execution_identity(successor)
        if source_identity is None or successor_identity is None:
            raise TerminalConvergenceError("persisted retry execution identity is unavailable")
        if (
            source_identity != successor_identity
            or binding["source_execution_identity_sha256"] != source_identity
        ):
            raise TerminalConvergenceError("persisted retry execution identity is stale")
        source_checks = {
            "source_attempt": int(source["attempt"]),
            "source_state": source.get("state"),
            "source_resume_policy": source.get("resume_policy"),
            "source_lifecycle_receipt_sha256": source.get(
                "lifecycle_receipt_sha256"
            ),
            "source_terminalization_sha256": source.get(
                "terminalization_sha256"
            ),
        }
        for key, expected in source_checks.items():
            if binding[key] != expected:
                raise TerminalConvergenceError(
                    f"persisted retry {key} binding is stale"
                )
        source_terminalized_at = source.get("terminalized_at_unix")
        if source_terminalized_at is not None and (
            isinstance(source_terminalized_at, bool)
            or not isinstance(source_terminalized_at, int)
            or source_terminalized_at < 0
            or source_terminalized_at > int(binding["observed_at_unix"])
        ):
            raise TerminalConvergenceError(
                "persisted retry source terminal time is invalid"
            )
        successor_created_at = successor.get("created_at_unix")
        if successor_created_at is not None and (
            isinstance(successor_created_at, bool)
            or not isinstance(successor_created_at, int)
            or successor_created_at < int(binding["observed_at_unix"])
        ):
            raise TerminalConvergenceError(
                "persisted retry successor predates its retry evidence"
            )
        verified_retry_edges[source_task_id] = {
            "successor_task_id": successor_task_id,
            "execution_identity_sha256": source_identity,
            "retry_context_sha256": binding["context_sha256"],
        }
        verified_identities.add(source_identity)

    globally_seen: set[str] = set()
    for source_task_id in verified_retry_edges:
        if source_task_id in globally_seen:
            continue
        current_path: set[str] = set()
        cursor = source_task_id
        while cursor in verified_retry_edges:
            if cursor in current_path:
                raise TerminalConvergenceError("persisted retry bindings contain a cycle")
            if cursor in globally_seen:
                break
            current_path.add(cursor)
            globally_seen.add(cursor)
            cursor = str(verified_retry_edges[cursor]["successor_task_id"])

    converged_current = [
        item
        for item in current
        if str(item["task_id"]) in scoped_task_ids
        and str(item["task_id"]) not in verified_retry_edges
    ]
    for source_task_id in sorted(verified_retry_edges):
        edge = verified_retry_edges[source_task_id]
        historical.append(
            {
                **current_by_task[source_task_id],
                "convergence_classification": "superseded_by_verified_retry",
                "execution_identity_sha256": edge[
                    "execution_identity_sha256"
                ],
                "successor_task_id": edge["successor_task_id"],
                "retry_context_sha256": edge["retry_context_sha256"],
                "retry_binding_verified": True,
                "success_claimed": False,
            }
        )

    classifications = (
        "duplicate",
        "superseded",
        "already_satisfied",
        "superseded_by_verified_retry",
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "current": sorted(converged_current, key=lambda item: str(item["task_id"])),
        "historical": historical,
        "raw_count": sum(
            1 for item in records if str(item["task_id"]) in scoped_task_ids
        ),
        "support_record_count": sum(
            1 for item in records if str(item["task_id"]) not in scoped_task_ids
        ),
        "current_count": len(converged_current),
        "converged_count": len(historical),
        "execution_identity_group_count": len(verified_identities),
        "verified_retry_edge_count": len(verified_retry_edges),
        "classification_counts": {
            name: sum(
                1
                for item in historical
                if item["convergence_classification"] == name
            )
            for name in classifications
        },
    }
