"""A narrow, fail-closed lane for repairing invalid deployment provenance.

The integrity gate is correct: a runtime whose deployment provenance is invalid
must not carry out normal effects.  But the gate used to close over its own
repair path as well -- self-deploy, ``grabowski_power_run`` and every ordinary
mutation all derive authority from the same provenance that had just been
declared invalid.  A single bad release therefore locked the system out of the
only action that could fix it.

This module breaks that circularity without weakening the gate.  It exposes one
action -- replace the deployed runtime with a build of an exact, verified commit
-- and derives its authority from evidence that is *independent* of the runtime
under repair:

* the audit chain is valid and writable,
* the kill switch is clear,
* local backup and restore evidence is fresh,
* the privileged broker is fully healthy,
* the caller names an exact target commit,
* the source repository is clean and revision-bound to that commit,
* the expected head is the head actually used,
* the target commit's own contract validates under its own canonical schema,
* no competing deployment mutation is in flight,
* no foreign lease or writer collides with the source.

Deliberate limits:

* The lane refuses to run when the runtime is *not* integrity-invalid, so it can
  never be used to route around gates that currently apply.
* It grants no shell, command or power authority.  Its only effect is a
  revision-bound deployment of the named commit.
* It does not consult ``provenance_valid`` for authority -- only to establish
  that a repair is warranted at all.
* After a successful repair the ordinary gates apply again unchanged; nothing
  here is sticky.
"""

from __future__ import annotations

import fcntl
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid
from typing import Annotated, Any

try:
    from mcp.server.fastmcp import Context
except ImportError:  # pragma: no cover - exercised only without the mcp package
    Context = Any
from mcp.types import ToolAnnotations
from pydantic import Field

import grabowski_mcp as base
import grabowski_operator_core as operator
import grabowski_privileged as privileged
import grabowski_recovery as recovery
import grabowski_self_deploy as self_deploy


mcp = operator.mcp

READ_ONLY = ToolAnnotations(
    title="Assess the deployment provenance repair lane",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

MUTATING = ToolAnnotations(
    title="Repair invalid deployment provenance from an exact verified commit",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

ExpectedHead = self_deploy.ExpectedHead
SourceRepository = self_deploy.SourceRepository
SourceLeaseOwner = self_deploy.SourceLeaseOwner
DelaySeconds = Annotated[int, Field(ge=5, le=60)]

SCHEMA_VERSION = 1
GATE_KIND = "grabowski_provenance_recovery_gate"

#: Deployment integrity flags whose failure this lane is allowed to repair.
REPAIRABLE_INTEGRITY_FLAGS = (
    "manifest_schema_valid",
    "entrypoint_contract_identity_valid",
    "artifact_integrity_valid",
    "provenance_valid",
)

CONTRACT_RELATIVE = "config/runtime-entrypoint.json"
CANONICAL_VALIDATOR_RELATIVE = "src/grabowski_runtime_contract.py"


class ProvenanceRecoveryDenied(PermissionError):
    """The recovery lane refused to act; ``reasons`` names every failed check."""

    def __init__(self, reasons: list[str], evidence: dict[str, Any]) -> None:
        super().__init__("provenance recovery denied: " + ",".join(reasons))
        self.reasons = list(reasons)
        self.evidence = evidence


def _git_bytes(repository: Path, *args: str) -> bytes | None:
    """Read a blob out of a git revision without touching the working tree."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            env=operator._safe_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


_VALIDATOR_DRIVER = """
import json, sys, types

payload = json.loads(sys.stdin.read())
namespace = {"__name__": "grabowski_runtime_contract_candidate"}
try:
    exec(compile(payload["validator"], "grabowski_runtime_contract.py", "exec"), namespace)
    contract_error = namespace["contract_error"]
    canonical_module = namespace["CANONICAL_VALIDATOR_MODULE"]
except BaseException as exc:
    print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
    raise SystemExit(0)

try:
    raw = json.loads(payload["contract"])
    error = contract_error(raw)
    if error is None:
        # Validated above, so these are typed accesses: .get() here could
        # smuggle None into the deployed-module set.
        deployed = {raw["module"]} | {
            item["module"] for item in raw.get("supporting_sources", [])
        }
    else:
        deployed = set()
except BaseException as exc:
    print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
    raise SystemExit(0)

print(json.dumps({
    "error": None,
    "contract_error": error,
    "canonical_module": canonical_module,
    "deploys_canonical_validator": canonical_module in deployed,
}))
"""

VALIDATOR_ISOLATION_TIMEOUT_SECONDS = 20


def _isolated_contract_verdict(
    validator_bytes: bytes, contract_bytes: bytes
) -> dict[str, Any]:
    """Run the candidate validator out of process and return only its verdict.

    Nothing from the target revision executes in the operator process: the
    subprocess receives source text on stdin and answers with JSON, so a
    malicious or merely broken candidate can at worst produce an unusable
    verdict.
    """
    try:
        payload = json.dumps(
            {
                "validator": validator_bytes.decode("utf-8"),
                "contract": contract_bytes.decode("utf-8"),
            }
        )
    except UnicodeDecodeError as exc:
        return {"error": f"candidate sources are not valid UTF-8: {exc}"}
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-c", _VALIDATOR_DRIVER],
            input=payload,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=VALIDATOR_ISOLATION_TIMEOUT_SECONDS,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except subprocess.TimeoutExpired:
        return {"error": "candidate validator exceeded its evaluation timeout"}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"error": f"candidate validator could not be evaluated: {exc}"}
    if completed.returncode != 0:
        return {"error": f"candidate validator exited {completed.returncode}"}
    try:
        verdict = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"error": "candidate validator produced no usable verdict"}
    if not isinstance(verdict, dict):
        return {"error": "candidate validator verdict was not an object"}
    return verdict


def _target_contract_evidence(repository: Path, expected_head: str) -> dict[str, Any]:
    """Validate the target commit's contract with that commit's own schema.

    Repairing into a second self-inconsistent release would only move the
    deadlock, so the target is judged before it is ever built.
    """
    evidence: dict[str, Any] = {
        "contract_readable": False,
        "validator_readable": False,
        "contract_valid": False,
        "validator_is_deployed": False,
        "error": None,
    }
    contract_bytes = _git_bytes(
        repository, "show", f"{expected_head}:{CONTRACT_RELATIVE}"
    )
    if contract_bytes is None:
        evidence["error"] = "target commit has no runtime entrypoint contract"
        return evidence
    evidence["contract_readable"] = True

    validator_bytes = _git_bytes(
        repository, "show", f"{expected_head}:{CANONICAL_VALIDATOR_RELATIVE}"
    )
    if validator_bytes is None:
        evidence["error"] = "target commit ships no canonical contract validator"
        return evidence
    evidence["validator_readable"] = True

    # The candidate validator is *not* executed in this process.  This tool is
    # read-only and reachable while a gate would ultimately deny recovery, so
    # running an arbitrary origin/main revision's module-scope code here would
    # let assessment alone cause side effects in the live operator.  Run it in a
    # short-lived, resource-bounded subprocess instead and trust only its JSON.
    verdict = _isolated_contract_verdict(validator_bytes, contract_bytes)
    if verdict.get("error"):
        evidence["error"] = f"target canonical validator is unusable: {verdict['error']}"
        return evidence
    if verdict.get("contract_error"):
        evidence["error"] = f"target contract is invalid: {verdict['contract_error']}"
        return evidence
    evidence["contract_valid"] = True
    if not verdict.get("deploys_canonical_validator"):
        evidence["error"] = (
            f"target contract does not deploy {verdict.get('canonical_module')}; "
            "the repaired runtime could not validate itself"
        )
        return evidence
    evidence["validator_is_deployed"] = True
    return evidence


def _competing_deployment_evidence() -> dict[str, Any]:
    """Detect an in-flight deployment that this lane must not race."""
    evidence: dict[str, Any] = {
        "deploy_lock_free": False,
        "inflight_deploy_jobs": [],
        "error": None,
    }
    lock_path = Path.home() / ".local/state/grabowski/deploy.lock"
    if not lock_path.exists():
        evidence["deploy_lock_free"] = True
    else:
        try:
            with open(lock_path, "r+b") as handle:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    evidence["deploy_lock_free"] = True
                except OSError:
                    evidence["deploy_lock_free"] = False
        except OSError as exc:
            evidence["error"] = f"deploy lock is unreadable: {exc}"
            return evidence

    try:
        jobs_root = operator._jobs_root()
        index = self_deploy._deploy_index(jobs_root)
        if index.get("pending_unit"):
            evidence["inflight_deploy_jobs"] = [index["pending_unit"]]
    except (OSError, RuntimeError, ValueError) as exc:
        evidence["error"] = f"deployment job index is unreadable: {exc}"
    return evidence


def _blockade_evidence(repository: Path | None) -> dict[str, Any]:
    """Check typed operator blockades, which must still stop this lane.

    The kill switch is not the only way an operator halts mutations.  A typed
    blockade is a deliberate "stop touching this" instruction, and a repair lane
    that ignored it would be a hole in the blockade system rather than a
    bounded escape from the integrity gate.  Blockade evaluation does not read
    deployment provenance, so consulting it here is not circular.
    """
    evidence: dict[str, Any] = {"allows_mutation": False, "error": None}
    try:
        base._require_blockade_allows_mutation(
            "durable_job",
            repo=str(repository) if repository is not None else None,
        )
        evidence["allows_mutation"] = True
    except PermissionError as exc:
        evidence["error"] = str(exc)
    except (RuntimeError, ValueError, OSError) as exc:
        evidence["error"] = f"blockade evaluation failed: {exc}"
    return evidence


def _volatile_gate_recheck(repository: Path | None) -> dict[str, Any]:
    """Re-read the gates that can change between assessment and dispatch."""
    kill_switch = base._kill_switch_state()
    blockade = _blockade_evidence(repository)
    competing = _competing_deployment_evidence()
    checks = {
        "kill_switch_clear": not bool(kill_switch.get("engaged")),
        "no_blocking_operator_blockade": bool(blockade["allows_mutation"]),
        "no_competing_deployment": (
            bool(competing.get("deploy_lock_free"))
            and not competing.get("inflight_deploy_jobs")
            and competing.get("error") is None
        ),
    }
    return {
        "checked_at_unix": int(time.time()),
        "checks": checks,
        "reasons": sorted(name for name, passed in checks.items() if not passed),
        "operator_blockade": blockade,
        "competing_deployment": competing,
    }


def _integrity_evidence() -> dict[str, Any]:
    """Establish that a repair is warranted, without deriving authority from it."""
    deployment = base._deployment_metadata()
    failed = [
        flag
        for flag in REPAIRABLE_INTEGRITY_FLAGS
        if deployment.get(flag) is not True
    ]
    return {
        "repair_warranted": bool(failed),
        "failed_integrity_flags": failed,
        "release_id": deployment.get("release_id"),
        "repo_head": deployment.get("repo_head"),
        "completion_status": deployment.get("completion_status"),
    }


def evaluate_gate(
    expected_head: str,
    source_repository: str | None = None,
    source_lease_owner_id: str | None = None,
) -> dict[str, Any]:
    """Evaluate every independent precondition of the repair lane, read-only.

    Returns the full evidence set with ``allowed`` and ``reasons``; never
    raises for a failed check, so an operator can inspect a blocked lane.
    """
    audit = base._verify_audit_log(base.AUDIT_LOG)
    kill_switch = base._kill_switch_state()
    local_backup = recovery._fresh_text_marker(recovery.BACKUP_SUCCESS)
    broker = privileged.grabowski_privileged_broker_status()
    integrity = _integrity_evidence()

    source_error: str | None = None
    source_identity: dict[str, Any] | None = None
    repository: Path | None = None
    try:
        repository, _runner, source_identity = self_deploy._deployment_source_preflight(
            expected_head,
            source_repository,
            source_lease_owner_id,
        )
    except (RuntimeError, ValueError, OSError, PermissionError) as exc:
        source_error = str(exc)

    target = (
        _target_contract_evidence(repository, expected_head)
        if repository is not None
        else {"error": "source repository was not established"}
    )
    competing = _competing_deployment_evidence()
    blockade = _blockade_evidence(repository)

    checks = {
        # The lane exists only to repair a runtime that is actually broken.
        "repair_warranted": bool(integrity["repair_warranted"]),
        # Independent evidence -- none of it derives from the invalid runtime.
        "audit_chain_valid": bool(audit.get("valid")),
        "audit_writable": bool(audit.get("audit_writable", audit.get("valid"))),
        "kill_switch_clear": not bool(kill_switch.get("engaged")),
        "no_blocking_operator_blockade": bool(blockade["allows_mutation"]),
        "local_backup_fresh": bool(local_backup.get("valid")),
        "privileged_broker_ready": bool(broker.get("ready")),
        # Revision binding of the repair target.
        "source_identity_bound": source_error is None,
        "target_contract_valid": bool(target.get("contract_valid")),
        "target_deploys_canonical_validator": bool(
            target.get("validator_is_deployed")
        ),
        # Nothing else may be mutating the deployment concurrently.
        "no_competing_deployment": (
            bool(competing.get("deploy_lock_free"))
            and not competing.get("inflight_deploy_jobs")
            and competing.get("error") is None
        ),
    }
    reasons = sorted(name for name, passed in checks.items() if not passed)

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": GATE_KIND,
        "checked_at_unix": int(time.time()),
        "allowed": not reasons,
        "reasons": reasons,
        "checks": checks,
        "expected_head": expected_head,
        "runtime_integrity": integrity,
        "audit": {
            "valid": bool(audit.get("valid")),
            "writable": bool(audit.get("audit_writable", audit.get("valid"))),
            "records": audit.get("records"),
            "last_record_sha256": audit.get("last_record_sha256"),
        },
        "kill_switch": {"engaged": bool(kill_switch.get("engaged"))},
        "local_backup": {
            "valid": bool(local_backup.get("valid")),
            "age_seconds": local_backup.get("age_seconds"),
        },
        "privileged_broker": {"ready": bool(broker.get("ready"))},
        "source_identity": source_identity,
        "source_error": source_error,
        "target_contract": target,
        "competing_deployment": competing,
        "operator_blockade": blockade,
        "authority_model": {
            "derives_from_runtime_provenance": False,
            "grants_shell_authority": False,
            "grants_power_worker_authority": False,
            "effect_scope": "runtime-rebuild-and-activation-of-expected-head",
        },
        "does_not_establish": [
            "that the target commit is functionally correct",
            "that normal mutation authority is restored before a successful repair",
            "server recovery freshness, which remains a separate gate",
        ],
    }


@mcp.tool(
    name="grabowski_recovery_provenance_assess", annotations=READ_ONLY
)
def grabowski_recovery_provenance_assess(
    expected_head: ExpectedHead,
    source_repository: SourceRepository | None = None,
    source_lease_owner_id: SourceLeaseOwner | None = None,
) -> dict[str, Any]:
    """Report whether the provenance repair lane would admit this exact commit."""
    # Access-policy capability only.  This check reads the active profile and
    # never consults deployment provenance, so requiring it here restricts the
    # lane without reintroducing the circularity it exists to break.
    operator._require_operator_capability("audit_verify")
    return evaluate_gate(expected_head, source_repository, source_lease_owner_id)


@mcp.tool(
    name="grabowski_recovery_provenance_repair", annotations=MUTATING
)
def grabowski_recovery_provenance_repair(
    expected_head: ExpectedHead,
    source_repository: SourceRepository | None = None,
    source_lease_owner_id: SourceLeaseOwner | None = None,
    delay_seconds: DelaySeconds = 8,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Rebuild and activate the runtime from an exact commit, fail-closed.

    The only privileged action this lane can take.  It grants no shell, command
    or power-worker authority, and refuses unless the deployed runtime is
    actually integrity-invalid.
    """
    # Access-policy capabilities only.  Deliberately not
    # _require_operator_mutation: that binds to the blockade *and* provenance
    # path this lane exists to repair.  Blockades are evaluated explicitly in
    # the gate instead, so an operator blockade still stops the lane.
    operator._require_operator_capability("durable_job")
    operator._require_operator_capability("git_cli")
    # Serialize on the same lock the ordinary self-deploy scheduler uses.
    # Without it, two concurrent recovery requests could each observe a clear
    # deploy index, then both reserve a unit and start duplicate deployments.
    with self_deploy._deploy_schedule_lock():
        return _repair_under_schedule_lock(
            expected_head, source_repository, source_lease_owner_id, delay_seconds
        )


def _repair_under_schedule_lock(
    expected_head: str,
    source_repository: str | None,
    source_lease_owner_id: str | None,
    delay_seconds: int,
) -> dict[str, Any]:
    """Gate, reserve and dispatch, all under the deploy schedule lock."""
    gate = evaluate_gate(expected_head, source_repository, source_lease_owner_id)
    if not gate["allowed"]:
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "provenance-recovery-denied",
                "expected_head": expected_head,
                "reasons": gate["reasons"],
                "gate": gate,
            }
        )
        raise ProvenanceRecoveryDenied(gate["reasons"], gate)

    # Authority comes from the gate above, not from _require_operator_mutation:
    # that path binds to the very provenance this lane exists to repair.  The
    # audit chain is still required, and was verified as part of the gate.
    base._require_valid_audit_chain()

    source_identity = gate["source_identity"]
    repository = Path(source_identity["repository"])
    canonical_repository = Path(source_identity["canonical_repository"])
    runner = repository / self_deploy.RUNNER_RELATIVE_PATH
    command = self_deploy._deploy_command(
        repository,
        runner,
        expected_head,
        delay_seconds,
        canonical_repository=canonical_repository,
        source_kind=source_identity["source_kind"],
        source_identity_sha256=source_identity["identity_sha256"],
    )

    intent = {
        "timestamp_unix": int(time.time()),
        "operation": "provenance-recovery-intent",
        "expected_head": expected_head,
        "failed_integrity_flags": gate["runtime_integrity"]["failed_integrity_flags"],
        "source_identity_sha256": source_identity["identity_sha256"],
        "gate": gate,
    }
    intent_sha256 = base._append_audit_with_digest(intent)

    # Re-check the volatile gates immediately before dispatch.  Evaluating the
    # full gate takes measurable time (git reads, broker probe), and a kill
    # switch, a blockade or a competing deployment can appear inside that
    # window.  These three are cheap, so there is no reason to act on a stale
    # reading of them.
    volatile = _volatile_gate_recheck(repository)
    if volatile["reasons"]:
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "provenance-recovery-aborted-before-dispatch",
                "expected_head": expected_head,
                "reasons": volatile["reasons"],
                "intent_sha256": intent_sha256,
            }
        )
        raise ProvenanceRecoveryDenied(volatile["reasons"], {**gate, "recheck": volatile})

    jobs_root = operator._jobs_root()
    reserved_unit = self_deploy.DEPLOY_JOB_PREFIX + uuid.uuid4().hex[:12]
    self_deploy._write_deploy_index(
        jobs_root,
        units=self_deploy._deploy_index(jobs_root)["units"],
        pending_unit=reserved_unit,
    )
    try:
        job = operator._start_job(
            command,
            cwd=str(repository),
            runtime_seconds=3_600,
            finalization_expected_head=expected_head,
            reserved_unit=reserved_unit,
            allow_reserved_runtime_deploy=True,
            invoker_tool="grabowski_recovery_provenance_repair",
        )
    except Exception:
        # Re-read rather than restoring the snapshot taken before _start_job:
        # another deploy may have finished and removed itself meanwhile, and
        # writing back the stale unit list would resurrect it.
        self_deploy._write_deploy_index(
            jobs_root,
            units=self_deploy._deploy_index(jobs_root)["units"],
            pending_unit=None,
        )
        raise
    self_deploy._write_deploy_index(
        jobs_root,
        units=[*self_deploy._deploy_index(jobs_root)["units"], reserved_unit],
        pending_unit=None,
    )

    scheduled = {
        "timestamp_unix": int(time.time()),
        "operation": "provenance-recovery-scheduled",
        "expected_head": expected_head,
        "unit": job["unit"],
        "argv_sha256": job["argv_sha256"],
        "source_identity_sha256": source_identity["identity_sha256"],
    }
    scheduled_sha256 = base._append_audit_with_digest(scheduled)

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_provenance_recovery_receipt",
        "expected_head": expected_head,
        "gate": gate,
        "job": job,
        "intent_sha256": intent_sha256,
        "scheduled_sha256": scheduled_sha256,
        "post_state_readback_required": True,
        "next_action": (
            "re-read grabowski_deployment_identity once the job reaches a terminal "
            "state; normal gates apply again as soon as provenance is valid"
        ),
        "does_not_establish": [
            "that the deployment has completed",
            "that the repaired runtime is integrity-valid before readback",
        ],
    }
