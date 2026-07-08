from __future__ import annotations

from typing import Any

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

RECALL_KIND = "grabowski_operator_recall_item"
MAX_RECALL_TEXT_CHARS = 500
MAX_EVIDENCE_REFS = 20
RECALL_DOES_NOT_ESTABLISH = (
    "free_form_chat_memory",
    "policy_oracle",
    "root_cause",
    "task_completion",
    "merge_readiness",
    "live_routing_change",
    "heimlern_live_update",
)
SUPPORTED_SOURCE_KEYS = (
    "receipts",
    "prs",
    "bureau_tasks",
    "friction_records",
)
SUPPORTED_EVIDENCE_TYPES = {
    "receipt",
    "pr",
    "bureau_task",
    "friction_record",
}


def _bounded_text(value: Any, *, label: str, max_chars: int = MAX_RECALL_TEXT_CHARS) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = operator._redact(value).strip()
    if not text:
        raise ValueError(f"{label} must be non-empty")
    if "\x00" in text:
        raise ValueError(f"{label} must not contain NUL")
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text


def _optional_bounded_text(value: Any, *, max_chars: int = MAX_RECALL_TEXT_CHARS) -> str | None:
    if not isinstance(value, str):
        return None
    text = operator._redact(value).strip()
    if not text:
        return None
    if "\x00" in text:
        return None
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text


def _evidence_ref(evidence_type: str, evidence_id: Any, **extra: Any) -> dict[str, Any]:
    if evidence_type not in SUPPORTED_EVIDENCE_TYPES:
        raise ValueError("evidence type is unsupported")
    evidence_id_text = _bounded_text(str(evidence_id) if evidence_id is not None else "", label="evidence id", max_chars=160)
    ref: dict[str, Any] = {
        "type": evidence_type,
        "id": evidence_id_text,
    }
    for key in ("repo", "url", "sha256", "head_sha", "path"):
        value = _optional_bounded_text(extra.get(key), max_chars=240)
        if value:
            ref[key] = value
    return ref


def _normalize_evidence_refs(evidence_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(evidence_refs, list) or not evidence_refs:
        raise ValueError("recall item requires at least one evidence reference")
    if len(evidence_refs) > MAX_EVIDENCE_REFS:
        raise ValueError("recall item has too many evidence references")
    normalized: list[dict[str, Any]] = []
    for index, ref in enumerate(evidence_refs):
        if not isinstance(ref, dict):
            raise ValueError(f"evidence reference {index} must be an object")
        normalized.append(
            _evidence_ref(
                str(ref.get("type", "")),
                ref.get("id"),
                repo=ref.get("repo"),
                url=ref.get("url"),
                sha256=ref.get("sha256"),
                head_sha=ref.get("head_sha"),
                path=ref.get("path"),
            )
        )
    return normalized


def build_recall_item(
    *,
    topic: str,
    situation: str,
    attempt: str,
    result: str,
    learned_rule: str,
    evidence_refs: list[dict[str, Any]],
    source: str,
) -> dict[str, Any]:
    """Build one evidence-bound operator recall item.

    This function intentionally rejects free-form memories without concrete
    evidence refs. Recall items are derived records, not policy oracles.
    """
    return {
        "schema_version": 1,
        "kind": RECALL_KIND,
        "source": _bounded_text(source, label="source", max_chars=80),
        "topic": _bounded_text(topic, label="topic", max_chars=120),
        "situation": _bounded_text(situation, label="situation"),
        "attempt": _bounded_text(attempt, label="attempt"),
        "result": _bounded_text(result, label="result"),
        "learned_rule": _bounded_text(learned_rule, label="learned_rule"),
        "evidence_refs": _normalize_evidence_refs(evidence_refs),
        "does_not_establish": list(RECALL_DOES_NOT_ESTABLISH),
    }


def _receipt_recall(record: dict[str, Any]) -> dict[str, Any] | None:
    receipt_id = record.get("receipt_id") or record.get("id") or record.get("receipt_sha256")
    if not receipt_id:
        return None
    status = _optional_bounded_text(record.get("status"), max_chars=80) or "unknown"
    phase = _optional_bounded_text(record.get("phase"), max_chars=120) or "unknown phase"
    operation = _optional_bounded_text(record.get("operation"), max_chars=160) or phase
    return build_recall_item(
        source="receipt",
        topic=f"receipt: {operation}",
        situation=f"A Grabowski receipt recorded phase {phase}.",
        attempt=f"Operator action or grip attempted {operation}.",
        result=f"Receipt status: {status}.",
        learned_rule="Use the referenced receipt as bounded evidence; do not treat it as free-form memory.",
        evidence_refs=[_evidence_ref("receipt", receipt_id, sha256=record.get("receipt_sha256"), path=record.get("path"))],
    )


def _pr_recall(record: dict[str, Any]) -> dict[str, Any] | None:
    number = record.get("number") or record.get("pr")
    repo = _optional_bounded_text(record.get("repo"), max_chars=160)
    if number is None or not repo:
        return None
    title = _optional_bounded_text(record.get("title"), max_chars=180) or f"PR {number}"
    state = _optional_bounded_text(record.get("state"), max_chars=80) or "unknown"
    url = record.get("url")
    return build_recall_item(
        source="pr",
        topic=f"pr: {repo}#{number}",
        situation=f"Pull request {repo}#{number} was observed: {title}.",
        attempt="Operator work was represented by a GitHub pull request.",
        result=f"PR state: {state}.",
        learned_rule="Use the PR reference as evidence for what changed; verify current head before reusing the lesson.",
        evidence_refs=[_evidence_ref("pr", f"{repo}#{number}", repo=repo, url=url, head_sha=record.get("head_sha") or record.get("headRefOid"))],
    )


def _bureau_task_recall(record: dict[str, Any]) -> dict[str, Any] | None:
    task_id = record.get("id") or record.get("task_id")
    if not task_id:
        return None
    title = _optional_bounded_text(record.get("title"), max_chars=180) or str(task_id)
    state = _optional_bounded_text(record.get("state"), max_chars=80) or "unknown"
    goal = _optional_bounded_text(record.get("goal"), max_chars=240) or title
    return build_recall_item(
        source="bureau_task",
        topic=f"bureau task: {task_id}",
        situation=f"Bureau task {task_id} tracked: {title}.",
        attempt=goal,
        result=f"Task state: {state}.",
        learned_rule="Use Bureau task state as registry evidence only; do not infer completion without verification fields.",
        evidence_refs=[_evidence_ref("bureau_task", task_id, path=record.get("path"))],
    )


def _friction_record_recall(record: dict[str, Any]) -> dict[str, Any] | None:
    event_id = record.get("event_id")
    if not event_id:
        return None
    kind = _optional_bounded_text(record.get("kind"), max_chars=80) or "unknown"
    operation = _optional_bounded_text(record.get("operation"), max_chars=160) or "unknown operation"
    symptom = _optional_bounded_text(record.get("symptom"), max_chars=240) or "unknown symptom"
    resolved = record.get("resolved") is True
    return build_recall_item(
        source="friction_record",
        topic=f"friction: {kind}",
        situation=f"Friction event {event_id} affected {operation}.",
        attempt=f"Operator encountered symptom: {symptom}.",
        result="Resolved." if resolved else "Unresolved or not proven resolved.",
        learned_rule="Use friction recall as a routing hint, not as root-cause proof or permission to act.",
        evidence_refs=[_evidence_ref("friction_record", event_id)],
    )


def export_operator_recall(sources: dict[str, Any], *, limit: int = 50) -> dict[str, Any]:
    if not isinstance(sources, dict):
        raise ValueError("sources must be an object")
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")
    builders = {
        "receipts": _receipt_recall,
        "prs": _pr_recall,
        "bureau_tasks": _bureau_task_recall,
        "friction_records": _friction_record_recall,
    }
    items: list[dict[str, Any]] = []
    rejected_sources: list[dict[str, Any]] = []
    source_counts: dict[str, int] = {}
    for key in SUPPORTED_SOURCE_KEYS:
        raw_records = sources.get(key, [])
        if raw_records is None:
            raw_records = []
        if not isinstance(raw_records, list):
            raise ValueError(f"{key} must be a list")
        source_counts[key] = len(raw_records)
        builder = builders[key]
        for index, record in enumerate(raw_records):
            if not isinstance(record, dict):
                rejected_sources.append({"source": key, "index": index, "reason": "not_object"})
                continue
            item = builder(record)
            if item is None:
                rejected_sources.append({"source": key, "index": index, "reason": "missing_concrete_evidence_ref"})
                continue
            items.append(item)
            if len(items) >= limit:
                break
        if len(items) >= limit:
            break
    return {
        "schema_version": 1,
        "kind": "grabowski_operator_recall_export",
        "authority": "derived_evidence_records",
        "limit": limit,
        "source_counts": source_counts,
        "returned": len(items),
        "rejected_source_count": len(rejected_sources),
        "rejected_sources": rejected_sources[:MAX_EVIDENCE_REFS],
        "items": items,
        "heimlern_offline_learning": {
            "allowed": True,
            "mode": "offline_proposal_only",
            "does_not_establish": ["live_routing_change", "merge_policy_change", "task_completion"],
        },
        "does_not_establish": list(RECALL_DOES_NOT_ESTABLISH),
    }


@mcp.tool(name="grabowski_operator_recall_export", annotations=READ_ONLY)
def grabowski_operator_recall_export(sources: dict[str, Any], limit: int = 50) -> dict[str, Any]:
    """Export evidence-bound operator recall items from provided source records."""
    return export_operator_recall(sources, limit=limit)
