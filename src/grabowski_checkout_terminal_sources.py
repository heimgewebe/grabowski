from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
from typing import Any, Callable
from urllib.parse import urlsplit

import grabowski_bureau_leases as bureau_leases
import grabowski_checkouts as checkouts
import grabowski_operator_obligation as operator_obligation


SCHEMA_VERSION = checkouts.TERMINAL_RECONCILIATION_SCHEMA_VERSION
TERMINAL_TASK_STATES = frozenset({"verified", "cancelled", "superseded"})
GITHUB_ISSUE_SOURCE_RE = re.compile(
    r"(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#(?P<number>[1-9][0-9]*)(?::(?P<suffix>[^\x00]+))?\Z"
)
BUREAU_TASK_SPEC_SCAN_LIMIT = 4096
BUREAU_TASK_SPEC_SCHEMA = {
    "task_specs": {"task_id", "current_revision", "spec_sha256"},
    "task_spec_revisions": {
        "task_id",
        "revision",
        "parent_revision",
        "spec_sha256",
        "spec_json",
    },
}


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


def _bureau_state_root() -> Path:
    legacy_root = Path(
        os.environ.get("BUREAU_STATE_DIR", "~/.local/state/bureau")
    ).expanduser()
    configured = Path(
        os.environ.get("GRABOWSKI_BUREAU_COORDINATION_ROOT", str(legacy_root))
    ).expanduser()
    return Path(os.path.abspath(os.fspath(configured)))


def _bureau_state_store_path() -> Path:
    return _bureau_state_root() / "bureau.sqlite3"


def _bureau_task_spec_digest(spec: dict[str, Any]) -> str:
    canonical = json.dumps(
        spec,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _bureau_state_store_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
    )


def _bureau_state_store_entry_identity(
    root_descriptor: int, name: str, *, required: bool
) -> tuple[int, ...] | None:
    try:
        metadata = os.stat(
            name,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        if required:
            raise RuntimeError("Bureau TaskSpec StateStore is unavailable") from exc
        return None
    except OSError as exc:
        raise RuntimeError("Bureau TaskSpec StateStore could not be inspected safely") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError("Bureau TaskSpec StateStore is unsafe")
    return _bureau_state_store_identity(metadata)


def _bureau_state_store_snapshot(root_descriptor: int) -> dict[str, tuple[int, ...] | None]:
    return {
        "database": _bureau_state_store_entry_identity(
            root_descriptor, "bureau.sqlite3", required=True
        ),
        "wal": _bureau_state_store_entry_identity(
            root_descriptor, "bureau.sqlite3-wal", required=False
        ),
        "shm": _bureau_state_store_entry_identity(
            root_descriptor, "bureau.sqlite3-shm", required=False
        ),
    }


def _open_bureau_state_root() -> tuple[Path, int]:
    root = _bureau_state_root()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise RuntimeError("Bureau TaskSpec StateStore root is unavailable or unsafe") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise RuntimeError("Bureau TaskSpec StateStore root is unsafe")
    return root, descriptor


def _current_bureau_task_specs() -> list[dict[str, Any]]:
    _root, root_descriptor = _open_bureau_state_root()
    connection: sqlite3.Connection | None = None
    try:
        before = _bureau_state_store_snapshot(root_descriptor)
        pinned_path = f"/proc/self/fd/{root_descriptor}/bureau.sqlite3"
        connection = sqlite3.connect(
            "file:" + pinned_path + "?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        if _bureau_state_store_snapshot(root_descriptor) != before:
            raise RuntimeError("Bureau TaskSpec StateStore identity changed")
        for table, required in BUREAU_TASK_SPEC_SCHEMA.items():
            observed = {
                str(row["name"])
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            if not required.issubset(observed):
                raise RuntimeError("Bureau TaskSpec StateStore schema is incomplete")
        rows = connection.execute(
            "SELECT p.task_id,p.current_revision,p.spec_sha256 AS pointer_sha256,"
            "r.revision,r.parent_revision,r.spec_sha256 AS revision_sha256,r.spec_json "
            "FROM task_specs p JOIN task_spec_revisions r "
            "ON r.task_id=p.task_id AND r.revision=p.current_revision "
            "ORDER BY p.task_id LIMIT ?",
            (BUREAU_TASK_SPEC_SCAN_LIMIT + 1,),
        ).fetchall()
        if _bureau_state_store_snapshot(root_descriptor) != before:
            raise RuntimeError("Bureau TaskSpec StateStore identity changed")
        if len(rows) > BUREAU_TASK_SPEC_SCAN_LIMIT:
            raise RuntimeError("Bureau TaskSpec StateStore scan is incomplete")
        result: list[dict[str, Any]] = []
        for row in rows:
            task_id = row["task_id"]
            revision = row["current_revision"]
            parent_revision = row["parent_revision"]
            pointer_sha256 = row["pointer_sha256"]
            revision_sha256 = row["revision_sha256"]
            if (
                not isinstance(task_id, str)
                or not task_id
                or isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision < 1
                or row["revision"] != revision
                or parent_revision != (None if revision == 1 else revision - 1)
                or not isinstance(pointer_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", pointer_sha256) is None
                or pointer_sha256 != revision_sha256
            ):
                raise RuntimeError("Bureau TaskSpec current pointer is invalid")
            try:
                spec = json.loads(str(row["spec_json"]))
            except json.JSONDecodeError as exc:
                raise RuntimeError("Bureau TaskSpec revision JSON is invalid") from exc
            if (
                not isinstance(spec, dict)
                or spec.get("id") != task_id
                or _bureau_task_spec_digest(spec) != pointer_sha256
            ):
                raise RuntimeError("Bureau TaskSpec revision digest or identity differs")
            result.append(
                {
                    "task_id": task_id,
                    "revision": revision,
                    "spec_sha256": pointer_sha256,
                    "spec": spec,
                }
            )
        return result
    finally:
        if connection is not None:
            connection.close()
        os.close(root_descriptor)

def _blocked_followup_checkout_key(
    record: dict[str, Any], *, expected_checkout_key: str | None = None
) -> str:
    worktree_receipt = record.get("worktree_receipt")
    lifecycle = (
        worktree_receipt.get("lifecycle")
        if isinstance(worktree_receipt, dict)
        else None
    )
    checkout_key = lifecycle.get("checkout_key") if isinstance(lifecycle, dict) else None
    if checkout_key is not None:
        if (
            not isinstance(checkout_key, str)
            or re.fullmatch(r"[0-9a-f]{64}", checkout_key) is None
        ):
            raise RuntimeError("work lane durable followup checkout binding is invalid")
        if expected_checkout_key is not None and checkout_key != expected_checkout_key:
            raise RuntimeError("work lane durable followup checkout binding differs")
        return checkout_key
    if (
        isinstance(expected_checkout_key, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_checkout_key) is not None
    ):
        return expected_checkout_key
    raise RuntimeError("work lane durable followup checkout binding is missing")

def _bureau_blocked_followup_binding(
    source_id: str,
    *,
    record: dict[str, Any],
    assessment: dict[str, Any],
    audit_record_sha256: str,
    expected_followup_id: str | None = None,
    expected_checkout_key: str | None = None,
) -> dict[str, Any]:
    if assessment.get("closeout_state") != "blocked_with_durable_followup":
        raise RuntimeError("Bureau durable followup binding requires blocked closeout")
    if expected_followup_id is not None and (
        not isinstance(expected_followup_id, str)
        or not expected_followup_id
        or expected_followup_id != expected_followup_id.strip()
    ):
        raise RuntimeError("Bureau durable followup id is invalid")
    reason_codes = assessment.get("reason_codes")
    if (
        not isinstance(reason_codes, list)
        or "durable_followup_bound" not in reason_codes
    ):
        raise RuntimeError("legacy durable followup binding is not evidenced")
    expected = {
        "lane_id": source_id,
        "lane_receipt_sha256": record.get("receipt_sha256"),
        "lane_assessment_sha256": assessment.get("assessment_sha256"),
        "lane_terminal_audit_sha256": audit_record_sha256,
        "lane_terminal_head": assessment.get("terminal_head_sha"),
        "checkout_key": _blocked_followup_checkout_key(
            record, expected_checkout_key=expected_checkout_key
        ),
    }
    if any(not isinstance(value, str) or not value for value in expected.values()):
        raise RuntimeError("legacy durable followup reproduction evidence is incomplete")
    matches: list[dict[str, Any]] = []
    for current in _current_bureau_task_specs():
        if (
            expected_followup_id is not None
            and current["task_id"] != expected_followup_id
        ):
            continue
        task = current["spec"]
        metadata = task.get("metadata")
        reproduction = (
            metadata.get("reproduction") if isinstance(metadata, dict) else None
        )
        if not isinstance(reproduction, dict):
            continue
        if any(reproduction.get(key) != value for key, value in expected.items()):
            continue
        state = task.get("state")
        if not isinstance(state, str) or not state:
            raise RuntimeError("Bureau durable followup TaskSpec state is invalid")
        matches.append(
            {
                "task_id": current["task_id"],
                "revision": current["revision"],
                "spec_sha256": current["spec_sha256"],
                "state": state,
            }
        )
    if not matches:
        raise RuntimeError("Bureau durable followup binding is missing")
    if len(matches) != 1:
        raise RuntimeError("Bureau durable followup binding is ambiguous")
    match = matches[0]
    binding_core = {
        "kind": "bureau_current_task_spec_reproduction",
        "task_id": match["task_id"],
        "task_revision": match["revision"],
        "task_spec_sha256": match["spec_sha256"],
        "task_state": match["state"],
        "reproduction": expected,
        "does_not_establish": [
            "followup_completion",
            "lease_release_authority",
            "archive_or_cleanup_authority",
            "branch_or_ref_deletion_authority",
        ],
    }
    return {
        "checkout_key": expected["checkout_key"],
        "durable_followup_id": match["task_id"],
        "durable_followup_binding": {
            **binding_core,
            "binding_sha256": checkouts._sha256_json(binding_core),
        },
    }



def blocked_followup_binding_valid(
    source_evidence: dict[str, Any],
    checkout_key: str,
    *,
    require_terminal_task: bool = False,
) -> bool:
    if (
        not isinstance(checkout_key, str)
        or re.fullmatch(r"[0-9a-f]{64}", checkout_key) is None
        or source_evidence.get("terminal_state") != "blocked_with_durable_followup"
        or source_evidence.get("lease_release_ready") is not False
        or source_evidence.get("checkout_key") != checkout_key
    ):
        return False
    evidence_sha256 = source_evidence.get("evidence_sha256")
    evidence_core = {
        key: value
        for key, value in source_evidence.items()
        if key != "evidence_sha256"
    }
    if (
        not isinstance(evidence_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", evidence_sha256) is None
        or checkouts._sha256_json(evidence_core) != evidence_sha256
    ):
        return False
    source_id = source_evidence.get("source_id")
    terminal_head = source_evidence.get("terminal_head_sha")
    followup_id = source_evidence.get("durable_followup_id")
    if (
        not isinstance(source_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", source_id) is None
        or not isinstance(terminal_head, str)
        or checkouts.GIT_OBJECT_RE.fullmatch(terminal_head) is None
        or not isinstance(followup_id, str)
        or followup_id != followup_id.strip()
        or not followup_id
        or len(followup_id) > 512
        or any(character in followup_id for character in "\r\n\x00")
    ):
        return False
    for field in (
        "lane_receipt_sha256",
        "assessment_sha256",
        "terminal_closeout_audit_record_sha256",
    ):
        value = source_evidence.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            return False
    binding = source_evidence.get("durable_followup_binding")
    if not isinstance(binding, dict):
        return False
    claimed = binding.get("binding_sha256")
    if not isinstance(claimed, str) or re.fullmatch(r"[0-9a-f]{64}", claimed) is None:
        return False
    material = {key: value for key, value in binding.items() if key != "binding_sha256"}
    if checkouts._sha256_json(material) != claimed:
        return False
    if binding.get("kind") != "bureau_current_task_spec_reproduction":
        return False
    revision = binding.get("task_revision")
    spec_sha256 = binding.get("task_spec_sha256")
    state = binding.get("task_state")
    reproduction = binding.get("reproduction")
    if (
        binding.get("task_id") != followup_id
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or not isinstance(spec_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", spec_sha256) is None
        or not isinstance(state, str)
        or not state
        or (require_terminal_task and state not in TERMINAL_TASK_STATES)
        or not isinstance(reproduction, dict)
    ):
        return False
    expected_reproduction = {
        "lane_id": source_id,
        "lane_receipt_sha256": source_evidence["lane_receipt_sha256"],
        "lane_assessment_sha256": source_evidence["assessment_sha256"],
        "lane_terminal_audit_sha256": source_evidence[
            "terminal_closeout_audit_record_sha256"
        ],
        "lane_terminal_head": terminal_head,
        "checkout_key": checkout_key,
    }
    return reproduction == expected_reproduction

def _bureau_json(
    arguments: list[str],
    *,
    control_root: Path,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    state_root = _bureau_state_root()

    runtime = bureau_leases._contract_runtime()
    bureau_leases._assert_contract_runtime_unchanged(runtime)
    contract_arguments = [
        "--state-root",
        str(state_root),
        "--json",
        *arguments,
    ]
    descriptor = -1
    try:
        if runtime["runtime_kind"] == "legacy-venv":
            wrapper_binding = json.dumps(
                {
                    "module_paths": {
                        name: str(path)
                        for name, path in runtime["module_paths"].items()
                    },
                    "package_files": {
                        relative: {
                            "path": str(runtime["package_paths"][relative]),
                            "sha256": identity["sha256"],
                        }
                        for relative, identity in runtime[
                            "package_identities"
                        ].items()
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            argv = [
                str(runtime["python_launcher"]),
                "-I",
                "-c",
                bureau_leases._CONTRACT_WRAPPER,
                wrapper_binding,
                *contract_arguments,
            ]
            pass_fds: tuple[int, ...] = ()
        else:
            descriptor = bureau_leases._open_bound_launcher(runtime)
            argv = [
                str(runtime["python_launcher"]),
                "-I",
                f"/proc/self/fd/{descriptor}",
                *contract_arguments,
            ]
            pass_fds = (descriptor,)
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            cwd=str(control_root),
            env=bureau_leases._safe_environment(),
            pass_fds=pass_fds,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    bureau_leases._assert_contract_runtime_unchanged(runtime)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or "Bureau status projection failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Bureau status projection returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Bureau status projection returned an invalid payload")
    return payload


def _bureau_task_projection(
    source_id: str, *, control_root: Path
) -> dict[str, Any]:
    payload = _bureau_json(
        ["status-projection", "--skip-github"],
        control_root=control_root,
    )
    if payload.get("schema_version") != 1:
        raise RuntimeError("Bureau status projection envelope schema is unsupported")
    result = payload.get("result")
    if not isinstance(result, dict) or result.get("schema_version") != 1:
        raise RuntimeError("Bureau status projection result schema is unsupported")
    tasks = result.get("tasks")
    if not isinstance(tasks, list):
        raise RuntimeError("Bureau status projection has no authoritative task list")
    matches = [
        item
        for item in tasks
        if isinstance(item, dict) and item.get("task_id") == source_id
    ]
    if not matches:
        raise RuntimeError(f"Bureau status projection task is missing: {source_id}")
    if len(matches) != 1:
        raise RuntimeError(f"Bureau status projection task is ambiguous: {source_id}")
    task = matches[0]
    state = task.get("effective_state")
    if not isinstance(state, str):
        raise RuntimeError("Bureau status projection effective state is invalid")
    if state not in TERMINAL_TASK_STATES:
        raise RuntimeError(f"Bureau task source is not terminal: {state}")
    registry_state = task.get("registry_state")
    task_spec_state = task.get("task_spec_state")
    if registry_state is not None and not isinstance(registry_state, str):
        raise RuntimeError("Bureau status projection registry state is invalid")
    if task_spec_state is not None and not isinstance(task_spec_state, str):
        raise RuntimeError("Bureau status projection TaskSpec state is invalid")
    return {
        "task_id": source_id,
        "effective_state": state,
        "registry_state": registry_state,
        "task_spec_state": task_spec_state,
    }


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
    projection = _bureau_task_projection(source_id, control_root=control_root)
    post_control = bureau_leases.inspect_bureau_control_checkout(require_current=True)
    if (
        post_control.get("head") != control["head"]
        or post_control.get("control_root") != control["control_root"]
    ):
        raise RuntimeError("Bureau control checkout changed during terminal observation")
    post_github_main = _github_json(["api", "repos/heimgewebe/bureau/commits/main"])
    if (
        not isinstance(post_github_main, dict)
        or post_github_main.get("sha") != control["head"]
    ):
        raise RuntimeError("Bureau control checkout changed during terminal observation")
    if projection["registry_state"] != task.get("state"):
        raise RuntimeError(
            "Bureau status projection registry state differs from inspected control revision"
        )
    registry_tree = checkouts._git_read(
        control_root,
        ["rev-parse", f"{control['head']}:registry"],
    ).stdout.strip()
    return _terminal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "bureau_task",
            "source_id": source_id,
            "terminal_state": projection["effective_state"],
            "git_registry_state": task.get("state"),
            "projected_registry_state": projection["registry_state"],
            "task_spec_state": projection["task_spec_state"],
            "task_projection_sha256": checkouts._sha256_json(projection),
            "registry_commit": control["head"],
            "registry_tree": registry_tree,
            "task_json_sha256": checkouts._sha256_json(task),
            "task_file_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        }
    )


def work_lane_terminal_evidence(
    source_id: str, *, expected_checkout_key: str | None = None
) -> dict[str, Any]:
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

    outcome_projection: dict[str, Any] = {}
    # Legacy terminal receipts predate the canonical lane input envelope. Keep
    # their established evidence shape while strictly validating current lanes.
    if "inputs" in record or "created_at_unix" in record:
        inputs = record.get("inputs")
        source_binding = inputs.get("source") if isinstance(inputs, dict) else None
        if (
            not isinstance(source_binding, dict)
            or set(source_binding) != {"kind", "id"}
            or not isinstance(source_binding.get("kind"), str)
            or not source_binding["kind"]
            or not isinstance(source_binding.get("id"), str)
            or not source_binding["id"]
        ):
            raise RuntimeError(
                "work lane source receipt has no authoritative original source binding"
            )
        started_at_unix = record.get("created_at_unix")
        closed_at_unix = assessment.get("observed_at_unix")
        if (
            isinstance(started_at_unix, bool)
            or not isinstance(started_at_unix, int)
            or started_at_unix < 0
            or isinstance(closed_at_unix, bool)
            or not isinstance(closed_at_unix, int)
            or closed_at_unix < started_at_unix
        ):
            raise RuntimeError(
                "work lane source receipt has invalid start or closeout time evidence"
            )
        outcome_projection = {
            "source_binding": {
                "kind": source_binding["kind"],
                "id": source_binding["id"],
            },
            "started_at_unix": started_at_unix,
            "closed_at_unix": closed_at_unix,
        }

    followup_projection: dict[str, Any] = {}
    if closeout_state == "blocked_with_durable_followup":
        # Capacity release is a narrower authority than lane terminalization.
        # A caller-supplied follow-up id is therefore not sufficient: resolve
        # every capacity-release candidate against the current digest-bound
        # Bureau TaskSpec reproduction. Legacy assessments without a persisted
        # id may still resolve uniquely by their exact lane reproduction.
        followup_projection = _bureau_blocked_followup_binding(
            source_id,
            record=record,
            assessment=assessment,
            audit_record_sha256=audit_record_sha256,
            expected_followup_id=assessment.get("durable_followup_id"),
            expected_checkout_key=expected_checkout_key,
        )

    return _terminal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "work_lane",
            "source_id": source_id,
            "terminal_state": closeout_state,
            **outcome_projection,
            **followup_projection,
            "lane_receipt_sha256": record.get("receipt_sha256"),
            "assessment_sha256": assessment_sha256,
            "terminal_head_sha": assessment.get("terminal_head_sha"),
            "lease_release_ready": assessment.get("lease_release_ready"),
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


THREAD_FOCUS_WORK_LANE_SCAN_LIMIT = 4096
THREAD_FOCUS_COMPLETING_WORK_LANE_STATES = frozenset({"pr_merged", "deployed", "no_change_proven"})


def _thread_focus_terminal_work_lane_evidence(source_id: str) -> dict[str, Any]:
    import grabowski_work_acquire as work_acquire

    root = work_acquire._state_root()
    if not root.exists():
        raise RuntimeError("thread focus source has no acceptance-bound completion")
    paths = sorted(root.glob("*.json"))
    if len(paths) > THREAD_FOCUS_WORK_LANE_SCAN_LIMIT:
        raise RuntimeError("thread focus work-lane evidence scan is incomplete")

    lane_evidence: list[dict[str, Any]] = []
    for path in paths:
        record = work_acquire._read_state(path)
        if not isinstance(record, dict):
            raise RuntimeError("thread focus work-lane evidence scan is incomplete")
        lane_id = record.get("lane_id")
        if not isinstance(lane_id, str) or re.fullmatch(r"[0-9a-f]{32}", lane_id) is None:
            raise RuntimeError("thread focus work-lane identity is invalid")
        if path.name != f"{lane_id}.json":
            raise RuntimeError("thread focus work-lane canonical identity is invalid")
        inputs = record.get("inputs")
        source = inputs.get("source") if isinstance(inputs, dict) else None
        if source != {"kind": "thread_focus", "id": source_id}:
            continue
        terminal = work_lane_terminal_evidence(lane_id)
        if terminal.get("source_binding") != source:
            raise RuntimeError("thread focus work-lane source binding changed")
        if terminal.get("terminal_state") not in THREAD_FOCUS_COMPLETING_WORK_LANE_STATES:
            raise RuntimeError(
                "thread focus work lane is terminal but does not establish completion"
            )
        lane_evidence.append(terminal)

    if not lane_evidence:
        raise RuntimeError("thread focus source has no acceptance-bound completion")

    lanes = sorted(
        [
            {
                "lane_id": item["source_id"],
                "terminal_state": item["terminal_state"],
                "terminal_head_sha": item.get("terminal_head_sha"),
                "assessment_sha256": item["assessment_sha256"],
                "terminal_closeout_audit_record_sha256": item[
                    "terminal_closeout_audit_record_sha256"
                ],
                "evidence_sha256": item["evidence_sha256"],
            }
            for item in lane_evidence
        ],
        key=lambda item: item["lane_id"],
    )
    return _terminal_evidence(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "thread_focus",
            "source_id": source_id,
            "terminal_state": "completed_without_current_obligation",
            "completion_basis": "terminal_work_lanes",
            "work_lanes": lanes,
            "work_lane_set_sha256": checkouts._sha256_json(lanes),
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
    if listed.get("attention_required") is True:
        raise RuntimeError("thread focus source still requires continuation")
    if not listed.get("records"):
        return _thread_focus_terminal_work_lane_evidence(source_id)
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


def _parse_github_issue_source_id(source_id: str) -> tuple[str, int]:
    if not isinstance(source_id, str) or not source_id or source_id != source_id.strip():
        raise ValueError(
            "GitHub issue source id must be repository#number or repository#number:suffix or a strict github.com issue URL"
        )
    match = GITHUB_ISSUE_SOURCE_RE.fullmatch(source_id)
    if match is not None:
        return match.group("repo"), int(match.group("number"))

    try:
        parsed = urlsplit(source_id)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "GitHub issue source id must be repository#number or repository#number:suffix or a strict github.com issue URL"
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "GitHub issue source id must be repository#number or repository#number:suffix or a strict github.com issue URL"
        )
    path_match = re.fullmatch(
        r"/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/issues/(?P<number>[1-9][0-9]*)/?",
        parsed.path,
    )
    if path_match is None:
        raise ValueError(
            "GitHub issue source id must be repository#number or repository#number:suffix or a strict github.com issue URL"
        )
    repository = f"{path_match.group('owner')}/{path_match.group('repo')}"
    number = int(path_match.group("number"))
    canonical_url = f"https://github.com/{repository}/issues/{number}"
    if source_id not in {canonical_url, canonical_url + "/"}:
        raise ValueError(
            "GitHub issue source id must be repository#number or repository#number:suffix or a strict github.com issue URL"
        )
    return repository, number


def github_issue_terminal_evidence(source_id: str) -> dict[str, Any]:
    repository, number = _parse_github_issue_source_id(source_id)
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
    expected_url = f"https://github.com/{repository}/issues/{number}"
    issue_url = issue.get("url")
    if (
        not isinstance(issue_url, str)
        or issue_url.rstrip("/").casefold() != expected_url.casefold()
    ):
        raise RuntimeError("GitHub issue source identity differs")
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

# One historical checkout generation used the pre-canonical spelling below.
# Treat only that witnessed spelling as an alias; absence of source evidence
# still fails closed through the canonical observer.
_LEGACY_SOURCE_KIND_ALIASES = {
    "operator-obligation": "operator_obligation",
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
    canonical_kind = _LEGACY_SOURCE_KIND_ALIASES.get(kind, kind)
    observer = _OBSERVERS.get(canonical_kind)
    if observer is None:
        if kind == "automation":
            raise RuntimeError(
                "automation checkout lifecycle source has no immutable terminal evidence contract; "
                "checkout absence, retention expiry and lease absence do not establish terminality"
            )
        raise RuntimeError(f"unsupported checkout lifecycle source kind: {kind}")
    if canonical_kind == "work_lane" and observer is work_lane_terminal_evidence:
        evidence = work_lane_terminal_evidence(
            source_id,
            expected_checkout_key=binding.get("checkout_key"),
        )
    else:
        evidence = observer(source_id)
    if evidence.get("kind") != canonical_kind or evidence.get("source_id") != source_id:
        raise RuntimeError("source terminal evidence is bound to another source")
    claimed = evidence.get("evidence_sha256")
    core = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    if claimed != checkouts._sha256_json(core):
        raise RuntimeError("source terminal evidence digest is invalid")
    if canonical_kind != kind:
        evidence = _terminal_evidence({**core, "source_kind_alias": kind})
    return evidence
