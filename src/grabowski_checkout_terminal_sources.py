from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

import grabowski_bureau_leases as bureau_leases
import grabowski_checkouts as checkouts
import grabowski_operator_obligation as operator_obligation


SCHEMA_VERSION = checkouts.TERMINAL_RECONCILIATION_SCHEMA_VERSION
TERMINAL_TASK_STATES = frozenset({"verified", "cancelled", "obsolete", "rejected"})
GITHUB_ISSUE_SOURCE_RE = re.compile(
    r"(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#(?P<number>[1-9][0-9]*):(?P<suffix>[^\x00]+)\Z"
)


def _terminal_evidence(core: dict[str, Any]) -> dict[str, Any]:
    return {**core, "evidence_sha256": checkouts._sha256_json(core)}


def _github_json(arguments: list[str], *, timeout_seconds: int = 30) -> Any:
    completed = subprocess.run(
        ["gh", *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
        env=checkouts.operator._safe_environment(),
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or "GitHub observation failed")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("GitHub observation returned invalid JSON") from exc


def bureau_task_terminal_evidence(source_id: str) -> dict[str, Any]:
    if not isinstance(source_id, str) or not source_id.strip():
        raise ValueError("bureau task source id is invalid")
    control = bureau_leases.inspect_bureau_control_checkout(require_current=True)
    github_main = _github_json(["api", "repos/heimgewebe/bureau/commits/main"])
    if not isinstance(github_main, dict) or github_main.get("sha") != control["head"]:
        raise RuntimeError("Bureau control checkout is not bound to current GitHub main")
    control_root = Path(control["control_root"])
    task_path = f"registry/tasks/{source_id}.json"
    raw = checkouts._git_read(
        control_root,
        ["show", f"{control['head']}:{task_path}"],
    ).stdout
    try:
        task = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Bureau task source is invalid JSON") from exc
    if not isinstance(task, dict) or task.get("id") != source_id:
        raise RuntimeError("Bureau task source identity differs")
    state = task.get("state")
    if state not in TERMINAL_TASK_STATES:
        raise RuntimeError(f"Bureau task source is not terminal: {state}")
    registry_tree = checkouts._git_read(
        control_root,
        ["rev-parse", f"{control['head']}:registry"],
    ).stdout.strip()
    return _terminal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "bureau_task",
            "source_id": source_id,
            "terminal_state": state,
            "registry_commit": control["head"],
            "registry_tree": registry_tree,
            "task_json_sha256": checkouts._sha256_json(task),
            "task_file_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        }
    )


def work_lane_terminal_evidence(source_id: str) -> dict[str, Any]:
    if not isinstance(source_id, str) or re.fullmatch(r"[0-9a-f]{32}", source_id) is None:
        raise ValueError("work lane source id must be a 32-character lowercase hex lane id")
    # Import lazily so checkout lifecycle observation does not create an import
    # cycle with work acquisition. The work-lane reader verifies its own receipt.
    import grabowski_work_acquire as work_acquire

    record = work_acquire._read_state(
        work_acquire._state_root() / f"{source_id}.json"
    )
    if not isinstance(record, dict) or record.get("lane_id") != source_id:
        raise RuntimeError("work lane source receipt is missing or bound to another lane")
    assessment = work_acquire._terminal_closeout_assessment(record)
    if assessment is None:
        raise RuntimeError("work lane source has no terminal closeout evidence")
    closeout_state = assessment["closeout_state"]
    assessment_sha256 = assessment["assessment_sha256"]
    audit_event = work_acquire._terminal_closeout_audit_event(record, assessment)
    audit_record_sha256 = work_acquire._find_terminal_closeout_audit(audit_event)
    if audit_record_sha256 is None:
        raise RuntimeError("work lane terminal closeout audit is missing")
    return _terminal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "work_lane",
            "source_id": source_id,
            "terminal_state": closeout_state,
            "lane_receipt_sha256": record.get("receipt_sha256"),
            "assessment_sha256": assessment_sha256,
            "terminal_closeout_audit_record_sha256": audit_record_sha256,
        }
    )


def operator_obligation_terminal_evidence(source_id: str) -> dict[str, Any]:
    status = operator_obligation.status_obligation(source_id)
    terminal = status.get("work_complete") is True or status.get("attention_class") == "historical"
    if not terminal or status.get("continuation_required") is not False:
        raise RuntimeError("operator obligation source still requires continuation")
    return _terminal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "operator_obligation",
            "source_id": source_id,
            "terminal_state": status.get("state"),
            "attention_class": status.get("attention_class"),
            "resolution_disposition": status.get("resolution_disposition"),
            "open_file_sha256": status.get("open_file_sha256"),
            "close_file_sha256": status.get("close_file_sha256"),
            "resolution_file_sha256": status.get("resolution_file_sha256"),
        }
    )


def thread_focus_terminal_evidence(source_id: str) -> dict[str, Any]:
    listed = operator_obligation.list_obligations(
        {
            "state": "all",
            "thread_id": source_id,
            "limit": operator_obligation.MAX_LIST_LIMIT,
            "summary_only": False,
        }
    )
    if listed.get("scan_truncated") is True or listed.get("integrity_errors"):
        raise RuntimeError("thread focus obligation evidence is incomplete")
    if listed.get("attention_required") is True or not listed.get("records"):
        raise RuntimeError("thread focus source still requires continuation or has no receipt")
    statuses = [
        operator_obligation.status_obligation(record["obligation_id"])
        for record in listed["records"]
    ]
    if any(status.get("continuation_required") is not False for status in statuses):
        raise RuntimeError("thread focus source has a current obligation")
    if not any(status.get("work_complete") is True for status in statuses):
        raise RuntimeError("thread focus source has no acceptance-bound completion")
    records = sorted(
        [
            {
                "obligation_id": status["obligation_id"],
                "state": status.get("state"),
                "attention_class": status.get("attention_class"),
                "open_file_sha256": status.get("open_file_sha256"),
                "close_file_sha256": status.get("close_file_sha256"),
                "resolution_file_sha256": status.get("resolution_file_sha256"),
            }
            for status in statuses
        ],
        key=lambda item: item["obligation_id"],
    )
    return _terminal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "thread_focus",
            "source_id": source_id,
            "terminal_state": "completed_without_current_obligation",
            "obligations": records,
            "obligation_set_sha256": checkouts._sha256_json(records),
        }
    )


def github_issue_terminal_evidence(source_id: str) -> dict[str, Any]:
    match = GITHUB_ISSUE_SOURCE_RE.fullmatch(source_id)
    if match is None:
        raise ValueError("GitHub issue source id must be repository#number:suffix")
    repository = match.group("repo")
    number = int(match.group("number"))
    issue = _github_json(
        [
            "issue",
            "view",
            str(number),
            "--repo",
            repository,
            "--json",
            "number,state,url,closedAt,updatedAt",
        ]
    )
    if not isinstance(issue, dict) or issue.get("number") != number:
        raise RuntimeError("GitHub issue source identity differs")
    if issue.get("state") != "CLOSED" or not issue.get("closedAt"):
        raise RuntimeError("GitHub issue source is not closed")
    return _terminal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "github_issue",
            "source_id": source_id,
            "repository": repository,
            "issue_number": number,
            "terminal_state": "CLOSED",
            "closed_at": issue.get("closedAt"),
            "updated_at": issue.get("updatedAt"),
            "url": issue.get("url"),
        }
    )


_OBSERVERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "bureau_task": bureau_task_terminal_evidence,
    "operator_obligation": operator_obligation_terminal_evidence,
    "thread_focus": thread_focus_terminal_evidence,
    "github_issue": github_issue_terminal_evidence,
    "work_lane": work_lane_terminal_evidence,
}


def source_terminal_evidence(binding: dict[str, Any]) -> dict[str, Any]:
    source = binding.get("source")
    if not isinstance(source, dict):
        raise RuntimeError("checkout lifecycle source binding is missing")
    kind = source.get("kind")
    source_id = source.get("id")
    if not isinstance(kind, str) or not isinstance(source_id, str):
        raise RuntimeError("checkout lifecycle source binding is invalid")
    if frozenset(_OBSERVERS) != checkouts.TERMINAL_EVIDENCE_SOURCE_KINDS:
        raise RuntimeError("checkout terminal evidence observer contract drift")
    observer = _OBSERVERS.get(kind)
    if observer is None:
        if kind == "automation":
            raise RuntimeError(
                "automation checkout lifecycle source has no immutable terminal evidence contract; "
                "checkout absence, retention expiry and lease absence do not establish terminality"
            )
        raise RuntimeError(f"unsupported checkout lifecycle source kind: {kind}")
    evidence = observer(source_id)
    if evidence.get("kind") != kind or evidence.get("source_id") != source_id:
        raise RuntimeError("source terminal evidence is bound to another source")
    claimed = evidence.get("evidence_sha256")
    core = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    if claimed != checkouts._sha256_json(core):
        raise RuntimeError("source terminal evidence digest is invalid")
    return evidence
