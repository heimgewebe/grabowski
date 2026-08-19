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
* the kill switch is clear and no typed operator blockade applies,
* a local backup freshness marker is present (a marker -- not a proven restore),
* the privileged broker is fully healthy,
* the caller names an exact target commit,
* the source repository is clean and revision-bound to that commit,
* the expected head is the head actually used,
* the target commit ships the byte-identical canonical schema this process runs,
  and its contract validates under that schema,
* no competing deployment mutation is in flight,
* no foreign lease or writer collides with the source.

Nothing here executes code from the target commit or from the runtime under
repair.  A read path that could be made to act merely by being consulted would
not be a read path; see ``_target_contract_evidence``.

Deliberate limits:

* The lane refuses unless the runtime is *proven* integrity-invalid.  Unknown or
  unreadable integrity is indeterminate, and indeterminate is not a warrant.
* It grants no shell, command or power authority.  Its only effect is a
  revision-bound deployment of the named commit.
* It does not consult ``provenance_valid`` for authority -- only to establish
  that a repair is warranted at all.
* After a successful repair the ordinary gates apply again unchanged; nothing
  here is sticky.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
from pathlib import Path
import stat
import subprocess
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
import grabowski_midcutover_resume as midcutover
import grabowski_operator_core as operator
import grabowski_privileged as privileged
import grabowski_recovery as recovery
import grabowski_runtime_contract as runtime_contract
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
RESUME_GATE_KIND = "grabowski_midcutover_resume_gate"
MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH = (
    self_deploy.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH
)

#: Deployment integrity flags whose failure this lane is allowed to repair.
REPAIRABLE_INTEGRITY_FLAGS = (
    "manifest_schema_valid",
    "entrypoint_contract_identity_valid",
    "artifact_integrity_valid",
    "provenance_valid",
)

CONTRACT_RELATIVE = "config/runtime-entrypoint.json"


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


#: The canonical validator's identity is fixed here, in trusted code.  Reading
#: it out of the candidate would let the artifact under review decide what
#: counts as proof that its own schema is present.
CANONICAL_VALIDATOR_MODULE = "grabowski_runtime_contract"
CANONICAL_VALIDATOR_SOURCE = "src/grabowski_runtime_contract.py"


#: Root-provisioned trust anchor for the canonical contract schema.  It must sit
#: outside both the release under repair and the mutable working checkout: the
#: release's own copy is exactly the artifact whose integrity is in question,
#: and a same-UID repo file is not an authority, only a convenience.
TRUST_ANCHOR = Path("/etc/grabowski/runtime-contract-schema.py")


def _verified_trust_anchor(path: Path = TRUST_ANCHOR) -> dict[str, Any]:
    """Read the schema trust anchor only if its provenance is mechanically sound.

    Checked, not assumed: the file and every parent directory must be root-owned
    and not group- or world-writable, the file must be a single-link regular
    file and not a symlink.  Anything else means the operator's own uid could
    have written it, which would make "trusted" a claim rather than a property.
    """
    evidence: dict[str, Any] = {
        "path": str(path),
        "present": False,
        "verified": False,
        "reason": None,
        "sha256": None,
    }
    try:
        if path.is_symlink():
            evidence["reason"] = "anchor is a symlink"
            return evidence
        info = path.lstat()
        evidence["present"] = True
        if not stat.S_ISREG(info.st_mode):
            evidence["reason"] = "anchor is not a regular file"
            return evidence
        if info.st_nlink != 1:
            evidence["reason"] = "anchor has multiple hard links"
            return evidence
        if info.st_uid != 0:
            evidence["reason"] = f"anchor is not root-owned (uid {info.st_uid})"
            return evidence
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            evidence["reason"] = "anchor is group- or world-writable"
            return evidence
        for parent in path.parents:
            parent_info = parent.lstat()
            if stat.S_ISLNK(parent_info.st_mode):
                evidence["reason"] = f"anchor parent {parent} is a symlink"
                return evidence
            if not stat.S_ISDIR(parent_info.st_mode):
                evidence["reason"] = f"anchor parent {parent} is not a directory"
                return evidence
            if parent_info.st_uid != 0:
                evidence["reason"] = f"anchor parent {parent} is not root-owned"
                return evidence
            if parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                evidence["reason"] = f"anchor parent {parent} is writable by others"
                return evidence
            if parent == Path("/"):
                break
        data = path.read_bytes()
    except OSError as exc:
        evidence["reason"] = f"anchor is unreadable: {exc}"
        return evidence
    evidence["verified"] = True
    evidence["sha256"] = hashlib.sha256(data).hexdigest()
    evidence["source"] = data
    return evidence


def _target_contract_evidence(repository: Path, expected_head: str) -> dict[str, Any]:
    """Judge the target commit's contract without ever executing that commit.

    The earlier design loaded the target revision's own validator so a commit
    would be judged by the schema of its own epoch.  That guarantee is real, but
    the price was executing arbitrary repository code -- and this function is
    reached from a ``read_only`` tool that runs even when a gate will ultimately
    deny recovery.  A subprocess did not fix that: same UID, same filesystem, so
    a candidate could still write files, spawn processes or reach the network
    merely by being assessed.

    The anti-skew guarantee is preserved differently: both the candidate schema
    and the validator module already loaded in this process are compared
    byte-for-byte with an independently provisioned root-owned trust anchor.
    Only when all three identities match may this process use its already-loaded
    validator functions.  Any difference is indeterminate and is never resolved
    by executing the candidate.
    """
    evidence: dict[str, Any] = {
        "contract_readable": False,
        "validator_readable": False,
        "validator_matches_trusted_schema": False,
        "contract_valid": False,
        "validator_is_deployed": False,
        "indeterminate": False,
        "executed_candidate_code": False,
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
        repository, "show", f"{expected_head}:{CANONICAL_VALIDATOR_SOURCE}"
    )
    if validator_bytes is None:
        evidence["error"] = "target commit ships no canonical contract validator"
        return evidence
    evidence["validator_readable"] = True

    anchor = _verified_trust_anchor()
    evidence["trust_anchor"] = {
        key: value for key, value in anchor.items() if key != "source"
    }
    if not anchor["verified"]:
        # Fail closed rather than fall back to the release's own copy or the
        # mutable checkout: an authority that the repaired system could have
        # written is not an authority.
        evidence["indeterminate"] = True
        evidence["error"] = (
            "no independently verified contract schema trust anchor "
            f"({anchor['reason']}); the repair lane will not authorise against "
            "a validator the runtime under repair could have written"
        )
        return evidence
    trusted = anchor["source"]
    evidence["target_validator_sha256"] = hashlib.sha256(validator_bytes).hexdigest()
    evidence["trusted_validator_sha256"] = hashlib.sha256(trusted).hexdigest()
    if validator_bytes != trusted:
        # Not a rejection: the target may be perfectly fine.  This process simply
        # is not the right judge of a schema it does not implement, and it will
        # not run the candidate to find out.
        evidence["indeterminate"] = True
        evidence["error"] = (
            "target ships a different canonical contract schema than this "
            "runtime; a schema change must be reviewed and deployed through the "
            "ordinary path rather than judged by executing the candidate"
        )
        return evidence
    evidence["validator_matches_trusted_schema"] = True

    # The runtime may be in this lane precisely because artifact integrity is
    # broken.  Therefore the verifier already imported by this process cannot be
    # trusted merely because it is named grabowski_runtime_contract.  Bind its
    # exact source bytes to the independent root-owned anchor before calling it.
    try:
        running_validator = Path(runtime_contract.__file__).read_bytes()
    except (OSError, TypeError) as exc:
        evidence["indeterminate"] = True
        evidence["error"] = f"running canonical validator is unreadable: {exc}"
        return evidence
    evidence["running_validator_sha256"] = hashlib.sha256(running_validator).hexdigest()
    evidence["running_validator_matches_trust_anchor"] = running_validator == trusted
    if running_validator != trusted:
        evidence["indeterminate"] = True
        evidence["error"] = (
            "the running canonical validator does not match the independent "
            "root-owned trust anchor; this process cannot safely judge a repair target"
        )
        return evidence

    try:
        raw = json.loads(contract_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        evidence["error"] = f"target contract is not valid JSON: {exc}"
        return evidence

    error = runtime_contract.contract_error(raw)
    if error is not None:
        evidence["error"] = f"target contract is invalid: {error}"
        return evidence
    evidence["contract_valid"] = True

    deployed_modules = set(runtime_contract.contract_modules(raw))
    if CANONICAL_VALIDATOR_MODULE not in deployed_modules:
        evidence["error"] = (
            f"target contract does not deploy {CANONICAL_VALIDATOR_MODULE}; "
            "the repaired runtime could not validate itself"
        )
        return evidence
    sources = runtime_contract.contract_module_sources(raw)
    if sources.get(CANONICAL_VALIDATOR_MODULE) != CANONICAL_VALIDATOR_SOURCE:
        evidence["error"] = (
            f"target contract maps {CANONICAL_VALIDATOR_MODULE} to "
            f"{sources.get(CANONICAL_VALIDATOR_MODULE)!r} instead of the "
            f"canonical {CANONICAL_VALIDATOR_SOURCE!r}"
        )
        return evidence
    evidence["validator_is_deployed"] = True
    return evidence


def _competing_deployment_evidence(
    command: list[str] | None = None, *, prune: bool = False
) -> dict[str, Any]:
    """Detect an in-flight deployment that this lane must not race.

    This used to consult only ``pending_unit``.  That field exists to cover the
    window *before* a job starts and is cleared the instant it does, so between
    a successful dispatch and the job's own completion the index read as empty
    and a second identical repair could start a second job against the same
    runtime.  The reservation and the started-unit list are both in-flight
    evidence, and both are read here now -- through the same classification the
    scheduler uses, so there is one answer to "is something already running"
    rather than two that can disagree.
    """
    evidence: dict[str, Any] = {
        "deploy_lock_free": False,
        "inflight_deploy_jobs": [],
        "idempotent_match": None,
        "pruned_units": [],
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

    indexed = self_deploy.inflight_runtime_job_evidence(command, prune=prune)
    evidence["inflight_deploy_jobs"] = list(indexed["blocking_units"])
    evidence["inflight_units"] = list(indexed["inflight_units"])
    evidence["idempotent_match"] = indexed["idempotent_match"]
    evidence["pruned_units"] = list(indexed["pruned_units"])
    if indexed["error"] is not None:
        evidence["error"] = indexed["error"]
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


def _volatile_gate_recheck(
    repository: Path | None, command: list[str] | None = None
) -> dict[str, Any]:
    """Re-read the gates that can change between assessment and dispatch."""
    kill_switch = base._kill_switch_state()
    blockade = _blockade_evidence(repository)
    # Carries the exact argv: the recheck runs under the schedule lock, which is
    # where an identical intent that started meanwhile must be recognised as
    # ours rather than dispatched a second time.
    competing = _competing_deployment_evidence(command, prune=True)
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
    """Classify runtime integrity as valid, invalid or indeterminate.

    "Not True" is not the same as "proven broken".  A flag can be absent because
    the metadata probe itself failed -- unreadable manifest, partial deployment,
    an error containment path -- and treating that as a positive finding of
    corruption would let a transient read failure authorise a deployment.

    Only an explicit ``False`` warrants repair.  Anything unknown is
    indeterminate and fails closed: the lane declines rather than guesses.
    """
    deployment = base._deployment_metadata()
    invalid: list[str] = []
    unknown: list[str] = []
    for flag in REPAIRABLE_INTEGRITY_FLAGS:
        value = deployment.get(flag)
        if value is False:
            invalid.append(flag)
        elif value is not True:
            unknown.append(flag)

    if unknown:
        state = "indeterminate"
    elif invalid:
        state = "invalid"
    else:
        state = "valid"

    return {
        # Only a proven defect is a warrant; indeterminate never is.
        "repair_warranted": state == "invalid",
        "integrity_state": state,
        "failed_integrity_flags": invalid,
        "indeterminate_integrity_flags": unknown,
        "release_id": deployment.get("release_id"),
        "repo_head": deployment.get("repo_head"),
        "completion_status": deployment.get("completion_status"),
    }


def _resume_effect_repository() -> Path:
    """The repository scope the mid-cutover resume actually acts under."""
    return self_deploy.CANONICAL_REPOSITORY


def _resume_source_preflight(
    expected_head: str,
    source_repository: str | None,
    source_lease_owner_id: str | None,
) -> tuple[Path, Path, dict[str, Any]]:
    """Bind resume execution to one exact clean source for the cutover head.

    A mid-cutover completion is intentionally allowed to finish an older,
    already-switched revision after ``origin/main`` has advanced.  Therefore
    this preflight shares the deployment source's path/common-dir/lease
    invariants but does *not* require ``origin/main == expected_head``.
    """
    if (
        not isinstance(expected_head, str)
        or not 40 <= len(expected_head) <= 64
        or any(character not in "0123456789abcdef" for character in expected_head)
    ):
        raise ValueError("expected_head must be a lowercase Git object ID")

    canonical = self_deploy._validated_repository_path(
        self_deploy.CANONICAL_REPOSITORY,
        label="canonical repository",
    )
    repository = (
        canonical
        if source_repository is None
        else self_deploy._validated_repository_path(
            Path(source_repository).expanduser(),
            label="source repository",
        )
    )
    self_deploy._assert_not_repoground_managed_source(repository)

    canonical_common = self_deploy._git_common_directory(canonical)
    source_common = (
        canonical_common
        if repository == canonical
        else self_deploy._git_common_directory(repository)
    )
    if source_common != canonical_common:
        raise RuntimeError(
            "source repository does not share the canonical Git common directory"
        )

    head = self_deploy._required_stdout(
        self_deploy._git_result(repository, "rev-parse", "--verify", "HEAD"),
        "resume source HEAD lookup",
    )
    branch = self_deploy._required_stdout(
        self_deploy._git_result(repository, "rev-parse", "--abbrev-ref", "HEAD"),
        "resume source branch lookup",
    )
    status = self_deploy._required_stdout(
        self_deploy._git_result(
            repository,
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        ),
        "resume source working-tree status",
    )

    source_kind = "canonical-main" if repository == canonical else "detached-worktree"
    expected_branch = "main" if source_kind == "canonical-main" else "HEAD"
    if head != expected_head:
        raise RuntimeError(f"HEAD drift: expected {expected_head}, found {head}")
    if branch != expected_branch:
        raise RuntimeError(
            f"{source_kind} source has invalid branch state: "
            f"expected {expected_branch}, found {branch}"
        )
    if status:
        raise RuntimeError("source repository is dirty")

    runner = repository / MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH
    if runner.is_symlink() or not runner.is_file():
        raise RuntimeError(f"mid-cutover resume runner is unavailable: {runner}")
    committed_runner = _git_bytes(
        repository,
        "show",
        f"{expected_head}:{MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH.as_posix()}",
    )
    if committed_runner is None:
        raise RuntimeError("expected head has no mid-cutover resume runner")
    try:
        runner_bytes = runner.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"mid-cutover resume runner is unreadable: {exc}") from exc
    if runner_bytes != committed_runner:
        raise RuntimeError("mid-cutover resume runner does not match expected head")

    if source_kind == "detached-worktree" and source_lease_owner_id is None:
        raise ValueError("detached resume source requires source_lease_owner_id")
    lease_evidence = self_deploy._source_lease_evidence(
        repository, source_lease_owner_id
    )
    identity = {
        "schema_version": 1,
        "kind": "grabowski_midcutover_resume_source_identity",
        "source_kind": source_kind,
        "repository": str(repository),
        "canonical_repository": str(canonical),
        "git_common_directory": str(source_common),
        "head": head,
        "clean": True,
        "runner_relative_path": MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH.as_posix(),
        "runner_sha256": hashlib.sha256(runner_bytes).hexdigest(),
        "lease_evidence": lease_evidence,
    }
    return repository, runner, {
        **identity,
        "identity_sha256": self_deploy._source_identity_sha256(identity),
    }


def _recovery_lane(expected_head: str) -> dict[str, Any]:
    """Classify which recovery lane the durable blue-green state admits.

    Reading this costs nothing and changes nothing, so it is evaluated for every
    assessment -- including the ones that will be denied.  An operator who
    cannot see *why* a lane is closed will reach for a wider tool.
    """
    try:
        return midcutover.classify_from_durable_state(expected_head=expected_head)
    except Exception as exc:  # noqa: BLE001 - a broken classifier is fail-closed
        return {
            "schema_version": midcutover.SCHEMA_VERSION,
            "kind": midcutover.KIND,
            "lane": midcutover.LANE_FAIL_CLOSED,
            "checks": {"classification_available": False},
            "reasons": ["classification_available"],
            "error": type(exc).__name__,
            "resume_binding": None,
        }


def evaluate_resume_gate(expected_head: str) -> dict[str, Any]:
    """Evaluate the mid-cutover resume lane, read-only.

    The independent evidence is deliberately the same set the deployment repair
    lane requires -- audit chain, kill switch, blockade, broker, no competing
    deployment -- because the resume is just as privileged an effect.  What it
    does *not* require is a build source, a target contract or a clean working
    tree: it deploys nothing.  Its target is fixed by a receipt that was written
    before the runtime broke, which is exactly why it can be trusted while the
    runtime cannot.
    """
    audit = base._verify_audit_log(base.AUDIT_LOG)
    kill_switch = base._kill_switch_state()
    broker = privileged.grabowski_privileged_broker_status()
    integrity = _integrity_evidence()
    # The same scope the dispatch will re-check.  An assessment that evaluated a
    # narrower blockade scope than the execution would report a lane as open and
    # then have it close underneath the operator.
    blockade = _blockade_evidence(_resume_effect_repository())
    competing = _competing_deployment_evidence()
    lane = _recovery_lane(expected_head)
    resume_binding = lane.get("resume_binding")
    resume_phase = (
        resume_binding.get("resume_phase")
        if isinstance(resume_binding, dict)
        else None
    )
    start_warrant = bool(integrity["repair_warranted"])
    completion_warrant = bool(
        lane.get("lane") == midcutover.LANE_MID_CUTOVER_RESUME
        and resume_phase
        in {
            midcutover.PHASE_PROMOTE_POINTER,
            midcutover.PHASE_SELECT_CANONICAL,
            midcutover.PHASE_RETIRE_GREEN,
            midcutover.PHASE_CLOSEOUT,
        }
    )

    checks = {
        "start_or_completion_warrant": start_warrant or completion_warrant,
        "audit_chain_valid": bool(audit.get("valid")),
        "audit_writable": bool(audit.get("audit_writable", audit.get("valid"))),
        "kill_switch_clear": not bool(kill_switch.get("engaged")),
        "no_blocking_operator_blockade": bool(blockade["allows_mutation"]),
        "privileged_broker_ready": bool(broker.get("ready")),
        "no_competing_deployment": (
            bool(competing.get("deploy_lock_free"))
            and not competing.get("inflight_deploy_jobs")
            and competing.get("error") is None
        ),
        "mid_cutover_resume_classified": (
            lane.get("lane") == midcutover.LANE_MID_CUTOVER_RESUME
        ),
        "resume_binding_available": isinstance(resume_binding, dict)
        and isinstance(resume_binding.get("binding_sha256"), str),
    }
    reasons = sorted(name for name, passed in checks.items() if not passed)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESUME_GATE_KIND,
        "checked_at_unix": int(time.time()),
        "allowed": not reasons,
        "reasons": reasons,
        "checks": checks,
        "expected_head": expected_head,
        "recovery_lane": lane,
        "resume_binding": resume_binding,
        "runtime_integrity": integrity,
        "start_warrant": start_warrant,
        "completion_warrant": completion_warrant,
        "audit": {
            "valid": bool(audit.get("valid")),
            "writable": bool(audit.get("audit_writable", audit.get("valid"))),
            "last_record_sha256": audit.get("last_record_sha256"),
        },
        "kill_switch": {"engaged": bool(kill_switch.get("engaged"))},
        "privileged_broker": {"ready": bool(broker.get("ready"))},
        "operator_blockade": blockade,
        "competing_deployment": competing,
        "authority_model": {
            "derives_from_runtime_provenance": False,
            "grants_shell_authority": False,
            "grants_power_worker_authority": False,
            "grants_new_deployment_authority": False,
            "effect_scope": "canonical-promotion-of-the-already-switched-green-release",
        },
        "does_not_establish": [
            "that a new deployment may be started",
            "that the connector snapshot is rebound to green",
            "that the green runtime is functionally correct",
            "platform connector catalog publication",
        ],
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
    lane = _recovery_lane(expected_head)

    checks = {
        # A scheduled deployment recovery starts a *new* productive cutover.
        # Doing that while an already-switched cutover is still unresolved would
        # stack a fresh promotion on top of an unfinished one -- the exact state
        # the mid-cutover lane exists to resolve instead.
        "scheduled_deploy_lane_admitted": (
            lane.get("lane") == midcutover.LANE_SCHEDULED_DEPLOY
        ),
        # The lane exists only to repair a runtime that is *proven* broken;
        # indeterminate integrity is not a warrant (see _integrity_evidence).
        "repair_warranted": bool(integrity["repair_warranted"]),
        # Independent evidence -- none of it derives from the invalid runtime.
        "audit_chain_valid": bool(audit.get("valid")),
        "audit_writable": bool(audit.get("audit_writable", audit.get("valid"))),
        "kill_switch_clear": not bool(kill_switch.get("engaged")),
        "no_blocking_operator_blockade": bool(blockade["allows_mutation"]),
        # Named for what is actually checked: a freshness marker, not a proven
        # restore.  Restore provability lives in the separate server-recovery
        # gate, which this lane deliberately does not require.
        "local_backup_marker_fresh": bool(local_backup.get("valid")),
        "privileged_broker_ready": bool(broker.get("ready")),
        # Revision binding of the repair target.
        "source_identity_bound": source_error is None,
        "target_contract_valid": bool(target.get("contract_valid")),
        "target_deploys_canonical_validator": bool(
            target.get("validator_is_deployed")
        ),
        # An unjudgeable target is not an approved target.
        "target_schema_judgeable": not bool(target.get("indeterminate")),
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
        "recovery_lane": lane,
        "runtime_integrity": integrity,
        "audit": {
            "valid": bool(audit.get("valid")),
            "writable": bool(audit.get("audit_writable", audit.get("valid"))),
            "records": audit.get("records"),
            "last_record_sha256": audit.get("last_record_sha256"),
        },
        "kill_switch": {"engaged": bool(kill_switch.get("engaged"))},
        "local_backup_marker": {
            "fresh": bool(local_backup.get("valid")),
            "age_seconds": local_backup.get("age_seconds"),
            "proves": "a recent successful backup run wrote its marker",
            "does_not_prove": "that a restore was performed or verified",
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
            "that any candidate code was executed to reach this verdict",
            "restore readiness; only a backup freshness marker is checked here",
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
    """Report which recovery lane -- if any -- would admit this exact commit."""
    # Access-policy capability only.  This check reads the active profile and
    # never consults deployment provenance, so requiring it here restricts the
    # lane without reintroducing the circularity it exists to break.
    operator._require_operator_capability("audit_verify")
    gate = evaluate_gate(expected_head, source_repository, source_lease_owner_id)
    lane = gate["recovery_lane"]
    # The deployment gate stays exactly where callers already read it. The
    # resume verdict is added beside it, because a deployment-source verdict
    # about an operation that builds nothing would otherwise read as a refusal
    # of the lane that is actually open.
    resume_gate = (
        evaluate_resume_gate(expected_head)
        if lane.get("lane") == midcutover.LANE_MID_CUTOVER_RESUME
        else None
    )
    return {
        **gate,
        "recovery_lane_kind": lane.get("lane"),
        "resume_gate": resume_gate,
        "dispatch_lane": (
            midcutover.LANE_MID_CUTOVER_RESUME
            if resume_gate is not None and resume_gate["allowed"]
            else (
                midcutover.LANE_SCHEDULED_DEPLOY
                if gate["allowed"]
                else midcutover.LANE_FAIL_CLOSED
            )
        ),
    }


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
    """Repair an integrity-invalid runtime through exactly one classified lane.

    Two operations live behind this one tool, and the durable state -- never the
    caller -- decides which:

    * ``scheduled_deploy_recovery`` rebuilds and activates the named commit.
    * ``mid_cutover_resume`` continues one already-switched blue-green cutover
      to canonical.  It builds nothing and can reach no target other than the
      one its bound receipt already proved.

    Keeping both behind one tool, with no new input, is deliberate twice over.
    The transport gate already exempts exactly this tool name so a broken
    runtime can reach its own repair; a second exempt tool would widen that hole
    for no gain.  And the published connector contract is mid-convergence: an
    added parameter would change the complete tool-schema identity and force a
    fresh publication cycle for a recovery convenience nobody needs.  The lane
    is therefore never selectable from the outside -- callers read it back from
    grabowski_recovery_provenance_assess instead.

    Grants no shell, command or power-worker authority, and refuses unless the
    deployed runtime is actually integrity-invalid.
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
        lane = _recovery_lane(expected_head)
        if lane.get("lane") == midcutover.LANE_MID_CUTOVER_RESUME:
            if source_repository is None and source_lease_owner_id is None:
                return _resume_under_schedule_lock(expected_head)
            return _resume_under_schedule_lock(
                expected_head, source_repository, source_lease_owner_id
            )
        return _repair_under_schedule_lock(
            expected_head, source_repository, source_lease_owner_id, delay_seconds
        )


def _resume_under_schedule_lock(
    expected_head: str,
    source_repository: str | None = None,
    source_lease_owner_id: str | None = None,
) -> dict[str, Any]:
    """Gate, source-bind and dispatch the mid-cutover resume under the deploy lock."""
    gate = evaluate_resume_gate(expected_head)
    if not gate["allowed"]:
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "midcutover-resume-denied",
                "expected_head": expected_head,
                "reasons": gate["reasons"],
                "gate": gate,
            }
        )
        raise ProvenanceRecoveryDenied(gate["reasons"], gate)

    base._require_valid_audit_chain()

    try:
        repository, runner, source_identity = _resume_source_preflight(
            expected_head, source_repository, source_lease_owner_id
        )
    except (RuntimeError, ValueError, OSError, PermissionError) as exc:
        reason = "resume_source_identity_bound"
        source_gate = {
            **gate,
            "allowed": False,
            "reasons": [reason],
            "source_identity": None,
            "source_error": str(exc),
        }
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "midcutover-resume-source-denied",
                "expected_head": expected_head,
                "reasons": [reason],
                "source_error": str(exc),
            }
        )
        raise ProvenanceRecoveryDenied([reason], source_gate) from exc

    resume_binding = gate["resume_binding"]
    command = self_deploy._midcutover_resume_command(
        repository,
        runner,
        expected_head,
        resume_binding["cutover_id"],
        resume_binding["binding_sha256"],
    )

    intent = {
        "timestamp_unix": int(time.time()),
        "operation": "midcutover-resume-intent",
        "expected_head": expected_head,
        "cutover_id": resume_binding["cutover_id"],
        "resumed_receipt_sha256": resume_binding["resumed_receipt_sha256"],
        "resume_binding_sha256": resume_binding["binding_sha256"],
        "classification_sha256": gate["recovery_lane"].get("classification_sha256"),
        "source_identity_sha256": source_identity["identity_sha256"],
        "gate": gate,
    }
    intent_sha256 = base._append_audit_with_digest(intent)

    volatile = _volatile_gate_recheck(_resume_effect_repository(), command)
    # Absent evidence is not a match: a recheck that carries no competing-job
    # projection means nothing was recognised as ours, which must dispatch
    # normally rather than silently coalesce onto nothing.
    already_running = (volatile.get("competing_deployment") or {}).get(
        "idempotent_match"
    )
    if already_running is not None and not volatile["reasons"]:
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "midcutover-resume-coalesced",
                "expected_head": expected_head,
                "cutover_id": resume_binding["cutover_id"],
                "unit": already_running["unit"],
                "intent_sha256": intent_sha256,
            }
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_midcutover_resume_receipt",
            "lane": midcutover.LANE_MID_CUTOVER_RESUME,
            "expected_head": expected_head,
            "cutover_id": resume_binding["cutover_id"],
            "gate": gate,
            "job": already_running,
            "already_dispatched": True,
            "intent_sha256": intent_sha256,
            "source_identity_sha256": source_identity["identity_sha256"],
            "post_state_readback_required": True,
            "next_action": (
                "this exact resume is already running; read back its durable job "
                "and the resume receipt rather than starting another"
            ),
            "does_not_establish": [
                "that the running resume has completed",
                "that a second dispatch would have been safe",
            ],
        }
    if volatile["reasons"]:
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "midcutover-resume-aborted-before-dispatch",
                "expected_head": expected_head,
                "reasons": volatile["reasons"],
                "intent_sha256": intent_sha256,
            }
        )
        raise ProvenanceRecoveryDenied(
            volatile["reasons"], {**gate, "recheck": volatile}
        )

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
            reserved_unit=reserved_unit,
            allow_reserved_runtime_deploy=True,
            invoker_tool="grabowski_recovery_provenance_repair",
        )
    except operator.JobDispatchUnknown as exc:
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "midcutover-resume-dispatch-outcome-unknown",
                "expected_head": expected_head,
                "cutover_id": resume_binding["cutover_id"],
                "unit": exc.unit,
                "evidence": exc.evidence,
                "intent_sha256": intent_sha256,
            }
        )
        raise
    except Exception:
        try:
            self_deploy._write_deploy_index(
                jobs_root,
                units=self_deploy._deploy_index(jobs_root)["units"],
                pending_unit=None,
            )
        except Exception:  # noqa: BLE001 - the start failure is the real error
            pass
        raise

    post_dispatch_warnings: list[str] = list(job.get("post_dispatch_warnings") or [])
    try:
        scheduled_sha256 = base._append_audit_with_digest(
            {
                "timestamp_unix": int(time.time()),
                "operation": "midcutover-resume-scheduled",
                "expected_head": expected_head,
                "cutover_id": resume_binding["cutover_id"],
                "unit": job["unit"],
                "argv_sha256": job["argv_sha256"],
                "source_identity_sha256": source_identity["identity_sha256"],
            }
        )
    except Exception as exc:  # noqa: BLE001 - effect already dispatched
        scheduled_sha256 = None
        post_dispatch_warnings.append(f"scheduled audit append failed: {exc}")
    try:
        self_deploy._write_deploy_index(
            jobs_root,
            units=[*self_deploy._deploy_index(jobs_root)["units"], reserved_unit],
            pending_unit=None,
        )
    except Exception as exc:  # noqa: BLE001 - effect already dispatched
        post_dispatch_warnings.append(
            f"deploy index bookkeeping failed, pending_unit may be stale: {exc}"
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_midcutover_resume_receipt",
        "lane": midcutover.LANE_MID_CUTOVER_RESUME,
        "expected_head": expected_head,
        "cutover_id": resume_binding["cutover_id"],
        "resumed_receipt_sha256": resume_binding["resumed_receipt_sha256"],
        "resume_binding_sha256": resume_binding["binding_sha256"],
        "source_identity_sha256": source_identity["identity_sha256"],
        "gate": gate,
        "job": job,
        "intent_sha256": intent_sha256,
        "scheduled_sha256": scheduled_sha256,
        "post_dispatch_warnings": post_dispatch_warnings,
        "post_state_readback_required": True,
        "next_action": (
            "read back the routing selector and grabowski_deployment_identity once "
            "the job reaches a terminal state; the durable resume receipt is the "
            "authority on the outcome"
        ),
        "does_not_establish": [
            "that the resume has completed",
            "that the connector snapshot was rebound to green",
            "that a new deployment was performed",
        ],
    }


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

    # Deterministic across retries of the same repair, so a caller that lost the
    # response can correlate a re-request with what actually ran.
    # Components are fixed-width hex digests, so ":" cannot introduce ambiguity.
    repair_intent_id = hashlib.sha256(
        ":".join(
            [
                expected_head,
                str(source_identity["identity_sha256"]),
                operator._argv_hash(command),
            ]
        ).encode("utf-8")
    ).hexdigest()

    intent = {
        "timestamp_unix": int(time.time()),
        "operation": "provenance-recovery-intent",
        "repair_intent_id": repair_intent_id,
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
    volatile = _volatile_gate_recheck(repository, command)
    # Absent evidence is not a match: a recheck that carries no competing-job
    # projection means nothing was recognised as ours, which must dispatch
    # normally rather than silently coalesce onto nothing.
    already_running = (volatile.get("competing_deployment") or {}).get(
        "idempotent_match"
    )
    if already_running is not None and not volatile["reasons"]:
        # This exact intent is already in flight.  Starting a second job would
        # be the historically observed double dispatch, so the existing one is
        # returned instead: same argv, same target, same receipt lineage.
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "provenance-recovery-coalesced",
                "expected_head": expected_head,
                "unit": already_running["unit"],
                "intent_sha256": intent_sha256,
            }
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_provenance_recovery_receipt",
            "expected_head": expected_head,
            "gate": gate,
            "job": already_running,
            "already_dispatched": True,
            "intent_sha256": intent_sha256,
            "repair_intent_id": repair_intent_id,
            "post_state_readback_required": True,
            "next_action": (
                "this exact repair is already running; read back its durable job "
                "and the deployment identity rather than starting another"
            ),
            "does_not_establish": [
                "that the running repair has completed",
                "that a second dispatch would have been safe",
            ],
        }
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
    except operator.JobDispatchUnknown as exc:
        # A job may be running.  Releasing the reservation here would let a
        # second repair start alongside it, and reporting a clean failure would
        # be a lie about an effect that may already exist.  Keep the
        # reservation, record the ambiguity, and make the operator read back.
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "provenance-recovery-dispatch-outcome-unknown",
                "expected_head": expected_head,
                "repair_intent_id": repair_intent_id,
                "unit": exc.unit,
                "evidence": exc.evidence,
                "intent_sha256": intent_sha256,
            }
        )
        raise
    except Exception:
        # Definitive non-start, so the reservation must go.  Re-read rather than
        # restoring the snapshot taken before the attempt: another deploy may
        # have finished and removed itself meanwhile, and writing back the stale
        # unit list would resurrect it.
        try:
            self_deploy._write_deploy_index(
                jobs_root,
                units=self_deploy._deploy_index(jobs_root)["units"],
                pending_unit=None,
            )
        except Exception:  # noqa: BLE001 - the start failure is the real error
            pass
        raise

    # The effect now exists.  From here on nothing may raise: an exception after
    # a successful start would report "did not happen" about a deployment that
    # is already running, which is the worst possible answer to give an operator
    # about an integrity repair.  Record the effect first, then do bookkeeping
    # best-effort and surface any failure as a warning on the receipt.
    scheduled = {
        "timestamp_unix": int(time.time()),
        "operation": "provenance-recovery-scheduled",
        "expected_head": expected_head,
        "repair_intent_id": repair_intent_id,
        "unit": job["unit"],
        "argv_sha256": job["argv_sha256"],
        "source_identity_sha256": source_identity["identity_sha256"],
    }
    post_dispatch_warnings: list[str] = list(job.get("post_dispatch_warnings") or [])
    try:
        scheduled_sha256 = base._append_audit_with_digest(scheduled)
    except Exception as exc:  # noqa: BLE001 - effect already dispatched
        scheduled_sha256 = None
        post_dispatch_warnings.append(f"scheduled audit append failed: {exc}")
    try:
        self_deploy._write_deploy_index(
            jobs_root,
            units=[*self_deploy._deploy_index(jobs_root)["units"], reserved_unit],
            pending_unit=None,
        )
    except Exception as exc:  # noqa: BLE001 - effect already dispatched
        post_dispatch_warnings.append(
            f"deploy index bookkeeping failed, pending_unit may be stale: {exc}"
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_provenance_recovery_receipt",
        "expected_head": expected_head,
        "gate": gate,
        "job": job,
        "intent_sha256": intent_sha256,
        "scheduled_sha256": scheduled_sha256,
        "repair_intent_id": repair_intent_id,
        "post_dispatch_warnings": post_dispatch_warnings,
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
