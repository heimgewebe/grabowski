from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable, Iterable


EVIDENCE_KIND = "grabowski.managed_cargo_cache_evidence"
CACHE_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
KNOWN_STATES = frozenset(
    {
        "launching",
        "running",
        "completed",
        "failed",
        "cancelled",
        "timed_out",
        "signalled",
        "outcome_unknown",
        "interrupted",
    }
)
MAX_TASK_REFS_PER_ENTRY = 64


PROTECTING_STATES = frozenset(
    {
        "launching",
        "running",
        "outcome_unknown",
        "interrupted",
    }
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _target_binding(
    argv: Any,
    cache_root: Path,
) -> tuple[str | None, str | None, dict[str, Any] | None]:
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        return None, "task argv is not a string list", None
    values = [
        item.removeprefix("CARGO_TARGET_DIR=")
        for item in argv
        if item.startswith("CARGO_TARGET_DIR=")
    ]
    unique = sorted(set(values))
    if not unique:
        return None, None, None
    if len(unique) != 1:
        return None, "task has conflicting CARGO_TARGET_DIR bindings", None
    raw = unique[0]
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        return None, "managed Cargo target binding is not an absolute normalized path", None
    try:
        relative = path.relative_to(cache_root)
    except ValueError:
        return None, None, None
    if len(relative.parts) != 2 or relative.parts[1] != "target":
        return None, "CARGO_TARGET_DIR below managed Cargo root has an unsupported shape", None
    key = relative.parts[0]
    if CACHE_KEY_RE.fullmatch(key) is None:
        return (
            None,
            None,
            {
                "cache_path": str(cache_root / key),
                "target_path": str(path),
                "reason": "non_identity_cache_name",
            },
        )
    return key, None, None


def build_evidence(
    records: Iterable[dict[str, Any]],
    *,
    cache_root: Path,
    repository_identity_resolver: Callable[[dict[str, Any]], str | None] | None = None,
    max_entries: int = 256,
) -> dict[str, Any]:
    """Project persisted task truth into bounded managed-Cargo protection evidence."""
    if max_entries < 1:
        raise ValueError("max_entries must be positive")
    root = cache_root.expanduser()
    grouped: dict[str, dict[str, Any]] = {}
    observation_errors: list[str] = []
    unclassified_bindings: list[dict[str, Any]] = []

    for record in records:
        task_id = str(record.get("task_id", ""))
        state = str(record.get("state", ""))
        updated_at = record.get("updated_at_unix")
        if not task_id:
            observation_errors.append("task record without task_id")
            continue
        if not isinstance(updated_at, int) or isinstance(updated_at, bool) or updated_at < 0:
            observation_errors.append(f"task {task_id}: invalid updated_at_unix")
            continue
        argv = record.get("argv")
        key, binding_error, unclassified = _target_binding(argv, root)
        if binding_error is not None:
            observation_errors.append(f"task {task_id}: {binding_error}")
            continue
        if unclassified is not None:
            unclassified_bindings.append(
                {
                    **unclassified,
                    "task_id": task_id,
                    "state": state,
                    "updated_at_unix": updated_at,
                }
            )
            continue
        if key is None:
            continue

        unknown_state = state not in KNOWN_STATES
        protected = state in PROTECTING_STATES or unknown_state
        reasons: list[str] = []
        if protected:
            reasons.append(f"task_state:{state or 'unknown'}")
        if unknown_state:
            observation_errors.append(f"task {task_id}: unknown task state {state!r}")

        repo_id: str | None = None
        if repository_identity_resolver is not None:
            try:
                repo_id = repository_identity_resolver(record)
            except Exception as exc:  # Projection must fail closed, not disappear a task.
                observation_errors.append(
                    f"task {task_id}: repository identity observation failed ({type(exc).__name__})"
                )
        if repo_id is not None and CACHE_KEY_RE.fullmatch(repo_id) is None:
            observation_errors.append(f"task {task_id}: repository identity is invalid")
            repo_id = None

        entry = grouped.setdefault(
            key,
            {
                "cache_key": key,
                "cache_path": str(root / key),
                "protected": False,
                "last_used_at_unix": updated_at,
                "repository_identity_sha256": repo_id,
                "reasons": [],
                "task_refs": [],
                "_repo_ids": set(),
            },
        )
        entry["protected"] = bool(entry["protected"] or protected)
        entry["last_used_at_unix"] = max(int(entry["last_used_at_unix"]), updated_at)
        entry["reasons"].extend(reasons)
        if repo_id is not None:
            entry["_repo_ids"].add(repo_id)
        entry["task_refs"].append(
            {
                "task_id": task_id,
                "state": state,
                "updated_at_unix": updated_at,
            }
        )

    entries: list[dict[str, Any]] = []
    for key in sorted(grouped):
        entry = grouped[key]
        repo_ids = sorted(entry.pop("_repo_ids"))
        if len(repo_ids) == 1:
            entry["repository_identity_sha256"] = repo_ids[0]
        elif len(repo_ids) > 1:
            entry["repository_identity_sha256"] = None
            entry["protected"] = True
            entry["reasons"].append("repository_provenance_conflict")
            observation_errors.append(f"cache {key}: conflicting repository identities")
        else:
            entry["repository_identity_sha256"] = None
        refs_by_id: dict[str, dict[str, Any]] = {}
        for ref in entry["task_refs"]:
            current = refs_by_id.get(ref["task_id"])
            if current is None or (ref["updated_at_unix"], ref["state"]) > (
                current["updated_at_unix"],
                current["state"],
            ):
                refs_by_id[ref["task_id"]] = ref
        all_refs = list(refs_by_id.values())
        selected_refs = sorted(
            all_refs,
            key=lambda ref: (-ref["updated_at_unix"], ref["task_id"]),
        )[:MAX_TASK_REFS_PER_ENTRY]
        entry["task_ref_count"] = len(all_refs)
        entry["protecting_task_ref_count"] = sum(
            1
            for ref in all_refs
            if ref["state"] in PROTECTING_STATES or ref["state"] not in KNOWN_STATES
        )
        entry["oldest_task_ref_updated_at_unix"] = min(
            (ref["updated_at_unix"] for ref in all_refs),
            default=None,
        )
        entry["newest_task_ref_updated_at_unix"] = max(
            (ref["updated_at_unix"] for ref in all_refs),
            default=None,
        )
        entry["task_refs_truncated"] = len(all_refs) > MAX_TASK_REFS_PER_ENTRY
        entry["task_refs"] = sorted(selected_refs, key=lambda ref: ref["task_id"])
        entry["reasons"] = sorted(set(entry["reasons"]))
        entries.append(entry)

    total_entry_count = len(entries)
    truncated = total_entry_count > max_entries
    if truncated:
        entries = entries[:max_entries]
        observation_errors.append(
            f"evidence truncated: {total_entry_count} cache identities exceed max_entries={max_entries}"
        )
    all_errors = sorted(set(observation_errors))
    error_count = len(all_errors)
    errors = all_errors[:max_entries]
    all_unclassified_bindings = sorted(
        unclassified_bindings,
        key=lambda item: (item["cache_path"], item["task_id"], item["updated_at_unix"]),
    )
    total_unclassified_binding_count = len(all_unclassified_bindings)
    returned_unclassified_bindings = all_unclassified_bindings[:max_entries]
    core = {
        "schema_version": 1,
        "kind": EVIDENCE_KIND,
        "complete": error_count == 0 and not truncated,
        "entries": entries,
        "unclassified_bindings": returned_unclassified_bindings,
        "total_unclassified_binding_count": total_unclassified_binding_count,
        "unclassified_bindings_truncated": (
            total_unclassified_binding_count > len(returned_unclassified_bindings)
        ),
        "observation_errors": errors,
        "observation_error_count": error_count,
        "observation_errors_truncated": error_count > len(errors),
        "total_entry_count": total_entry_count,
        "returned_entry_count": len(entries),
        "truncated": truncated,
        "does_not_establish": [
            "cache deletion authority",
            "managed-build cache identity outside exact CARGO_TARGET_DIR bindings",
            "absence of non-Grabowski consumers",
            "repository identity for historical tasks unless separately persisted",
        ],
    }
    return {**core, "evidence_sha256": _sha256_json(core)}
