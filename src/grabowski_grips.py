from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable
from urllib.parse import urlsplit

import grabowski_repobrief
import grabowski_grip_orchestration
import grabowski_convergence
import grabowski_client_snapshot
import grabowski_operator_obligation
import grabowski_worktree_ensure

Receipt = dict[str, Any]
CommandRunner = Callable[[Path, list[str]], dict[str, Any]]
GithubRunner = Callable[[Path, list[str]], dict[str, Any]]


@dataclass(frozen=True)
class GripSpec:
    name: str
    version: str
    summary: str
    effect: str
    required_parameters: tuple[str, ...]
    acceptance_ids: tuple[str, ...]
    runner: str
    uses_github: bool = False


GRIP_RECEIPT_KIND = "grabowski.operator_grip_receipt"
GRIP_RECEIPT_SCHEMA_VERSION = 1
READ_ONLY = "read_only"
MUTATING = "mutating"
INTRINSIC_PROTECTED_BRANCHES = frozenset({"main", "master"})
REMOTE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
WORKTREE_HYGIENE_CONFIRMATION = "reconcile-terminal-worktrees"
WORKTREE_HYGIENE_MAX_ACTIONS = 8
WORKTREE_HYGIENE_MAX_CANDIDATES = 32

SITUATION_ACCEPTANCE_IDS = (
    "situation-readonly",
    "core-state-fields",
    "snapshot-digest",
    "next-safe-grip",
    "tests",
)
SITUATION_CHECK_REPO_STATE = "repo_state"
SITUATION_CHECK_PR_STATE = "pr_state"
SITUATION_CHECK_SNAPSHOT_DIGEST = "snapshot_digest"
SITUATION_CHECK_NEXT_SAFE_GRIP = "next_safe_grip"
SITUATION_NON_CLAIMS = (
    "does not refresh connectors",
    "does not mutate repositories",
    "does not dispatch work",
    "does not complete Bureau tasks",
    "does not establish Bureau truth",
)


GRIP_SPECS: dict[str, GripSpec] = {
    "repo-orient": GripSpec(
        name="repo-orient",
        version="1.0",
        summary="Orient on a Git checkout without mutating it.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="repo_orient",
    ),
    "pr-check-readiness": GripSpec(
        name="pr-check-readiness",
        version="1.0",
        summary="Check whether a checkout is shaped like a publishable PR branch.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="pr_check_readiness",
    ),
    "worktree-orient": GripSpec(
        name="worktree-orient",
        version="1.0",
        summary="Orient on Git worktrees without mutating them.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=("worktree-orient-grip", "dirty-and-stale-visible", "next-safe-grip", "focused-tests"),
        runner="worktree_orient",
    ),
    "worktree-ensure": GripSpec(
        name="worktree-ensure",
        version="1.0",
        summary="Ensure one exact lease-bound Git worktree with durable idempotent recovery.",
        effect=MUTATING,
        required_parameters=(
            "repo",
            "base_head",
            "branch",
            "target_path",
            "lease_owner_id",
            "purpose",
            "retention_until_unix",
            "source_kind",
            "source_id",
            "artifact_class",
            "idempotency_key",
        ),
        acceptance_ids=(
            "typed-inputs",
            "lease-bound",
            "idempotent-replay",
            "post-state-readback",
            "durable-receipt",
        ),
        runner="worktree_ensure",
    ),
    "worktree-hygiene-reconcile": GripSpec(
        name="worktree-hygiene-reconcile",
        version="1.0",
        summary="Reconcile owned or exactly merge-proven terminal worktrees through recovery-first archival and typed cleanup.",
        effect=MUTATING,
        required_parameters=("repo", "owner_id", "apply_cleanup", "confirmation"),
        acceptance_ids=(
            "owner-or-exact-merge-proof-bound",
            "merged-pr-head-bound",
            "dirty-and-coordinated-fail-closed",
            "recovery-before-cleanup",
            "typed-dry-run-before-apply",
            "bounded-actions",
        ),
        runner="worktree_hygiene_reconcile",
        uses_github=True,
    ),
    "post-merge-sync": GripSpec(
        name="post-merge-sync",
        version="1.0",
        summary="Plan post-merge local synchronization as a dry-run grip.",
        effect=READ_ONLY,
        required_parameters=("repo", "target_branch"),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="post_merge_sync",
    ),
    "situation": GripSpec(
        name="situation",
        version="1.0",
        summary="Summarize repo, PR, Bureau and grip context without mutating anything.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=SITUATION_ACCEPTANCE_IDS,
        runner="situation",
        uses_github=True,
    ),
    "scout": GripSpec(
        name="scout",
        version="1.0",
        summary="Report only actionable changes across repository, PR and runtime signals.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=("only-changes", "pr-and-runtime-drift", "disable-switch", "no-mutation"),
        runner="scout",
        uses_github=True,
    ),
    "runtime-deploy-check": GripSpec(
        name="runtime-deploy-check",
        version="1.0",
        summary="Check whether one registered runtime deployment adapter is ready without scheduling a deployment.",
        effect=READ_ONLY,
        required_parameters=("adapter", "expected_head"),
        acceptance_ids=("registered-adapter", "expected-head-bound", "deploy-preflight-readonly"),
        runner="runtime_deploy_check",
    ),
    "task-attention-decision": GripSpec(
        name="task-attention-decision",
        version="1.0",
        summary="Record one create-only, outcome-bound attention decision for the current task attempt.",
        effect=MUTATING,
        required_parameters=(
            "task_id",
            "decision",
            "expected_attempt",
            "expected_unit",
            "expected_authoritative_unit",
            "expected_argv_sha256",
            "expected_execution_envelope_sha256",
            "outcome_receipt_sha256",
            "authority",
            "evidence_ref",
        ),
        acceptance_ids=(
            "current-task-outcome-bound",
            "create-only-decision",
            "idempotent-replay",
            "task-store-unchanged",
        ),
        runner="task_attention_decision",
    ),
    "task-attention-reconciliation": GripSpec(
        name="task-attention-reconciliation",
        version="1.0",
        summary="Classify a bounded attention-task snapshot from outcome and create-only decision evidence.",
        effect=READ_ONLY,
        required_parameters=(),
        acceptance_ids=(
            "bounded-task-snapshot",
            "decision-evidence-validated",
            "conservative-classification",
            "no-probes-or-mutation",
        ),
        runner="task_attention_reconciliation",
    ),
    "connector-snapshot-bind": GripSpec(
        name="connector-snapshot-bind",
        version="1.0",
        summary="Bind one client-declared connector tool snapshot to the current server release and tool contract.",
        effect=MUTATING,
        required_parameters=(
            "client_id",
            "session_id",
            "observed_tool_count",
            "observed_names_sha256",
            "observed_release_id",
            "observed_agent_instructions_sha256",
        ),
        acceptance_ids=(
            "client-declaration-bounded",
            "server-tool-contract-bound",
            "release-bound",
            "private-receipt-persisted",
        ),
        runner="connector_snapshot_bind",
    ),
    "convergence-assess": GripSpec(
        name="convergence-assess",
        version="1.0",
        summary="Evaluate one hash-bound convergence request with the pinned external protocol before closure.",
        effect=READ_ONLY,
        required_parameters=("request_path", "expected_request_sha256", "expected_protocol_head"),
        acceptance_ids=(
            "protocol-identity-bound",
            "request-hash-bound",
            "deterministic-assessment",
            "terminal-closure-gate",
        ),
        runner="convergence_assess",
    ),
    "gate-evidence-preflight": GripSpec(
        name="gate-evidence-preflight",
        version="1.0",
        summary="Prepare bounded evidence for one fail-closed gate without granting execution authority.",
        effect=READ_ONLY,
        required_parameters=(
            "gate_owner",
            "policy_boundary",
            "target",
            "scope",
            "expected_identity",
            "evidence",
            "attempt",
        ),
        acceptance_ids=(
            "typed-gate-input",
            "required-evidence-visible",
            "changed-retry-bound",
            "no-policy-authority",
        ),
        runner="gate_evidence_preflight",
    ),
    "convergence-state-classify": GripSpec(
        name="convergence-state-classify",
        version="1.0",
        summary="Classify bounded historical states from explicit evidence without rewriting history.",
        effect=READ_ONLY,
        required_parameters=("records",),
        acceptance_ids=(
            "bounded-records",
            "evidence-only-classification",
            "contradictions-visible",
            "no-history-mutation",
        ),
        runner="convergence_state_classify",
    ),
    "mechanic-loop": GripSpec(
        name="mechanic-loop",
        version="1.0",
        summary="Run a bounded sequence of normal receipt-bound grips.",
        effect=MUTATING,
        required_parameters=("actions",),
        acceptance_ids=("normal-grips-only", "scope-visible", "receipt-per-grip"),
        runner="mechanic_loop",
        uses_github=True,
    ),
    "captain-preflight": GripSpec(
        name="captain-preflight",
        version="1.2",
        summary="Evaluate Captain authority gates for high-impact actions without executing privileged mutations.",
        effect=READ_ONLY,
        required_parameters=("actions",),
        acceptance_ids=("high-impact-marked", "recovery-or-irreversibility", "target-change-record"),
        runner="captain_preflight",
    ),
    "captain-run": GripSpec(
        name="captain-run",
        version="1.1",
        summary="Execute action-specific Captain operations when autonomy gates are satisfied.",
        effect=MUTATING,
        required_parameters=("actions",),
        acceptance_ids=("captain-gates-pass", "execution-intent-bound", "trusted-owner-autonomy", "receipt-bound-execution"),
        runner="captain_run",
        uses_github=True,
    ),
    "operator-obligation-open": GripSpec(
        name="operator-obligation-open",
        version="1.0",
        summary="Open a durable acceptance-bound operator obligation before nontrivial work.",
        effect=MUTATING,
        required_parameters=("obligation_id", "objective", "acceptance"),
        acceptance_ids=("durable-open", "acceptance-bound", "response-remains-open"),
        runner="operator_obligation_open",
    ),
    "operator-obligation-list": GripSpec(
        name="operator-obligation-list",
        version="1.0",
        summary="List bounded operator obligations so interrupted work can be resumed.",
        effect=READ_ONLY,
        required_parameters=(),
        acceptance_ids=("bounded-list", "origin-filter", "continuation-attention"),
        runner="operator_obligation_list",
    ),
    "operator-obligation-status": GripSpec(
        name="operator-obligation-status",
        version="1.0",
        summary="Read whether an operator obligation still requires continuation.",
        effect=READ_ONLY,
        required_parameters=("obligation_id",),
        acceptance_ids=("integrity-bound-read", "continuation-decision", "no-completion-inference"),
        runner="operator_obligation_status",
    ),
    "operator-obligation-close": GripSpec(
        name="operator-obligation-close",
        version="1.0",
        summary="Close an operator obligation only as completed, explicitly blocked, or durably delegated.",
        effect=MUTATING,
        required_parameters=("obligation_id", "outcome", "evidence"),
        acceptance_ids=(
            "open-binding",
            "delegation-live-observation",
            "terminal-shape",
            "create-only-close",
            "response-end-decision",
        ),
        runner="operator_obligation_close",
    ),
    "branch-publish": GripSpec(
        name="branch-publish",
        version="1.0",
        summary="Publish the current HEAD to a work branch with expected-head verification.",
        effect=MUTATING,
        required_parameters=("repo", "branch", "expected_head"),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="branch_publish",
    ),
    "pr-create-or-update": GripSpec(
        name="pr-create-or-update",
        version="1.2",
        summary="Create or update an open PR with exact published-head and draft-state verification.",
        effect=MUTATING,
        required_parameters=("repo", "branch", "base", "expected_head", "title"),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="pr_create_or_update",
        uses_github=True,
    ),
}


GRIP_SURFACE_ALLOWLIST = frozenset(
    {
        "repo-orient",
        "worktree-orient",
        "worktree-ensure",
        "worktree-hygiene-reconcile",
        "situation",
        "scout",
        "runtime-deploy-check",
        "task-attention-decision",
        "task-attention-reconciliation",
        "connector-snapshot-bind",
        "convergence-assess",
        "gate-evidence-preflight",
        "convergence-state-classify",
        "mechanic-loop",
        "captain-preflight",
        "captain-run",
        "pr-check-readiness",
        "post-merge-sync",
        "operator-obligation-open",
        "operator-obligation-list",
        "operator-obligation-status",
        "operator-obligation-close",
        "branch-publish",
        "pr-create-or-update",
    }
)
GRIP_SURFACE_PROFILES = {"observer", "operator", "captain"}
GRIP_SURFACE_MUTATING_PROFILES = {"operator", "captain"}
GRIP_SURFACE_TARGETS = {
    "repo-orient": "repository checkout",
    "worktree-orient": "repository worktree inventory",
    "worktree-ensure": "one exact repository worktree",
    "worktree-hygiene-reconcile": "terminal repository worktree lifecycle",
    "situation": "repository and PR situation snapshot",
    "scout": "change-only repository, PR and runtime drift signal",
    "runtime-deploy-check": "registered runtime deployment adapter readiness",
    "task-attention-decision": "one create-only current-attempt attention decision",
    "task-attention-reconciliation": "bounded attention-task evidence classification",
    "connector-snapshot-bind": "one connector client snapshot receipt",
    "convergence-assess": "one hash-bound convergence closure assessment",
    "gate-evidence-preflight": "one fail-closed gate evidence preparation",
    "convergence-state-classify": "bounded historical convergence state records",
    "mechanic-loop": "bounded normal grip action sequence",
    "captain-preflight": "high-impact Captain action preflight only",
    "captain-run": "action-specific high-impact Captain execution",
    "pr-check-readiness": "pull request readiness evidence",
    "post-merge-sync": "post-merge local checkout sync",
    "operator-obligation-open": "one durable operator obligation open record",
    "operator-obligation-list": "bounded operator obligation continuation inventory",
    "operator-obligation-status": "one integrity-bound operator obligation status",
    "operator-obligation-close": "one create-only operator obligation terminal record",
    "branch-publish": "git branch publication",
    "pr-create-or-update": "GitHub pull request metadata",
}
GRIP_SURFACE_RECOVERY_PATHS = {
    READ_ONLY: "rerun the grip with the same inputs; no local recovery should be required",
    MUTATING: "inspect the emitted receipt, verify target/scope, then use git/GitHub rollback or retry from the recorded head",
}
MECHANIC_NORMAL_GRIPS = frozenset(
    {
        "repo-orient",
        "worktree-orient",
        "worktree-ensure",
        "situation",
        "scout",
        "runtime-deploy-check",
        "convergence-assess",
        "gate-evidence-preflight",
        "convergence-state-classify",
        "pr-check-readiness",
        "post-merge-sync",
        "branch-publish",
        "pr-create-or-update",
    }
)
CAPTAIN_HIGH_IMPACT_ACTIONS = frozenset(
    {
        "pr-merge",
        "runtime-deploy",
        "service-restart",
        "fleet-mutation",
        "cleanup-apply",
    }
)
GRIP_SURFACE_CAPTAIN_ONLY = frozenset({"captain-preflight", "captain-run"})
MECHANIC_FORBIDDEN_EFFECTS = tuple(sorted(CAPTAIN_HIGH_IMPACT_ACTIONS | {"force-push", "secret-mutation", "database-migration", "privileged-broker-mutation"}))
GRIP_RISK_LEVELS = {
    name: (
        "high"
        if name in GRIP_SURFACE_CAPTAIN_ONLY or name == "worktree-hygiene-reconcile"
        else "medium"
        if spec.effect == MUTATING
        else "low"
    )
    for name, spec in GRIP_SPECS.items()
}
MECHANIC_MAX_ACTIONS = 10
CAPTAIN_MAX_ACTIONS = 10
CAPTAIN_SCOPE_RECOMMENDED_KEYS = ("allowed_effects", "forbidden_effects", "boundaries", "max_targets")
CAPTAIN_WILDCARD_TOKENS = frozenset({"*", "all", "any", "every", "wildcard"})
CAPTAIN_GENERIC_OPERATIONS = frozenset({"mutate", "change", "update", "apply", "operate", "do", "run"})
CAPTAIN_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
CAPTAIN_GATE_IDS = (
    "high-impact-marked",
    "target-bound",
    "scope-bound",
    "target-change-record",
    "recovery-or-irreversibility",
    "status-projection-fresh",
    "evidence-digest-bound",
    "execution-authority-present",
    "review-evidence-present",
    "diff-bound",
    "ci-green",
    "autonomy-policy",
    "human-authorization-present",
)
CAPTAIN_EXECUTABLE_ACTIONS = frozenset({"pr-merge", "runtime-deploy"})
CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY = "act_unless_irreversible_or_ambiguous"
CAPTAIN_AUTHORITY_CONTRACT_VERSION = 1
CAPTAIN_ACTION_EVIDENCE_SCHEMA_VERSION = 1
CAPTAIN_AUTHORITY_CONTRACT_SURFACES = frozenset({"captain-preflight", "captain-run"})
CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT = 4096
CAPTAIN_POST_MERGE_VERIFY_ATTEMPTS = 3
CAPTAIN_POST_MERGE_VERIFY_DELAYS_SECONDS = (0.5, 1.0)
RUNTIME_DEPLOY_ADAPTER_GRABOWSKI_SELF = "grabowski-self"
RUNTIME_DEPLOY_ADAPTERS = frozenset({RUNTIME_DEPLOY_ADAPTER_GRABOWSKI_SELF})
RUNTIME_DEPLOY_GRABOWSKI_SERVICE = "grabowski-mcp"
RUNTIME_DEPLOY_GRABOWSKI_REPO = "heimgewebe/grabowski"
RUNTIME_DEPLOY_GRABOWSKI_TARGET = "heim-pc"
RUNTIME_DEPLOY_DEFAULT_DELAY_SECONDS = 8
RUNTIME_DEPLOY_MIN_DELAY_SECONDS = 5
RUNTIME_DEPLOY_MAX_DELAY_SECONDS = 60
CAPTAIN_PREFLIGHT_SETTLE_ATTEMPTS = 3
CAPTAIN_PREFLIGHT_SETTLE_DELAYS_SECONDS = (0.5, 1.0)
CAPTAIN_PREFLIGHT_TRANSIENT_ERRORS = frozenset({
    "pr_mergeable_not_confirmed_before_execution",
    "pr_merge_state_not_clean_before_execution",
})
CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION = 1
CAPTAIN_STATUS_PROJECTION_ALLOWLISTED_SOURCES = frozenset({
    "bureau status-projection",
    "grabowski status-projection",
    "captain status-projection",
})
# Compatibility alias for older receipts/tests; new callers should use source_allowlisted.
CAPTAIN_STATUS_PROJECTION_TRUSTED_SOURCES = CAPTAIN_STATUS_PROJECTION_ALLOWLISTED_SOURCES
CAPTAIN_STATUS_PROJECTION_MAX_AGE_SECONDS = 3600
CAPTAIN_STATUS_PROJECTION_CLOCK_SKEW_TOLERANCE_SECONDS = 300
CAPTAIN_EXECUTION_INTENT_KIND = "grabowski_captain_execution_intent"
CAPTAIN_EXECUTION_INTENT_SCHEMA_VERSION = 1
CAPTAIN_EXECUTION_INTENT_MAX_AGE_SECONDS = 600
CAPTAIN_EXECUTION_INTENT_CLOCK_SKEW_TOLERANCE_SECONDS = 120
CAPTAIN_EXECUTION_INTENT_FIELDS = (
    "schema_version",
    "kind",
    "action",
    "target_sha256",
    "expected_head",
    "expected_base",
    "evidence_sha256",
    "actor",
    "context",
    "issued_at",
)
CAPTAIN_EXECUTION_INTENT_ACTION_FIELDS = {
    "pr-merge": ("expected_base_sha",),
}
CAPTAIN_EXECUTION_INTENT_EVIDENCE_KEYS = (
    "actions_sha256",
    "status_projection_sha256",
    "diff_sha256",
    "review_evidence_sha256",
    "ci_evidence_sha256",
    "authorization_sha256",
)
CAPTAIN_BASE_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
CAPTAIN_DOES_NOT_ESTABLISH = (
    "automatic_merge_authority",
    "automatic_deploy_authority",
    "service_restart_safety",
    "fleet_mutation_safety",
    "cleanup_safety",
    "runtime_correctness",
    "semantic_correctness",
    "review_completeness",
    "production_safety",
    "privileged_execution",
)
CAPTAIN_EXECUTION_DOES_NOT_ESTABLISH = tuple(
    "privileged_execution_outside_this_receipt" if claim == "privileged_execution" else claim
    for claim in CAPTAIN_DOES_NOT_ESTABLISH
    if claim != "automatic_merge_authority"
)
CAPTAIN_NON_CLAIMS = (
    "captain-preflight never mutates; captain-run executes only actions in the explicit executable allowlist",
    "does not treat status projection as runtime truth; projection is evidence only",
    "does not treat CI green as production safety",
    "does not treat review approval as semantic correctness",
    "does not grant execution because allow_execution, execution_authority or any other single parameter is set",
    "trusted-owner autonomy requires the explicit autonomy_policy and still blocks irreversible or ambiguous actions",
    "human authorization is recorded evidence, never an automatic execution release",
    "captain-run requires a fresh action-bound execution_intent; receipts never echo raw intent, actor or context values",
)
CAPTAIN_NO_MUTATION_REASON = (
    "captain-preflight is read-only authority evaluation; it never mutates. "
    "Use captain-run for action-specific execution after the same evidence gates pass."
)



def _captain_authority_contract(surface: str) -> dict[str, Any]:
    if surface not in CAPTAIN_AUTHORITY_CONTRACT_SURFACES:
        raise ValueError(f"unknown Captain authority contract surface: {surface}")
    return {
        "schema_version": CAPTAIN_AUTHORITY_CONTRACT_VERSION,
        "surface": surface,
        "required_gates": list(CAPTAIN_GATE_IDS),
        "executable_action_allowlist": sorted(CAPTAIN_EXECUTABLE_ACTIONS),
        "terms": {
            "evaluation_authority": {
                "meaning": "permission to evaluate Captain evidence gates and emit a read-only receipt",
                "surfaces": ["captain-preflight", "captain-run"],
                "effects": ["read-only gate evaluation", "receipt construction"],
                "does_not_grant": ["merge", "deploy", "service_restart", "fleet_mutation", "cleanup"],
            },
            "execution_authority": {
                "meaning": "one explicit prerequisite for an implemented captain-run executor",
                "evidence_field": "execution_authority",
                "gate": "execution-authority-present",
                "required_with": [
                    "allow_execution=true",
                    "all Captain gates pass",
                    "exactly one action",
                    "implemented executor",
                    "expected_head and target binding",
                    "fresh action-bound execution_intent",
                    "post-execution verification",
                ],
                "does_not_grant_by_itself": ["execution", "mutation", "merge", "deploy", "service_restart", "fleet_mutation", "cleanup"],
            },
            "execution_intent": {
                "meaning": "a fresh structured intent that binds action, canonical target digest, expected head, expected base, decisive evidence digests, actor/context and a plausibility-checked UTC timestamp before any executor call",
                "parameter": "execution_intent",
                "check": "execution-intent-bound",
                "surfaces": ["captain-run"],
                "required_fields": list(CAPTAIN_EXECUTION_INTENT_FIELDS),
                "action_specific_required_fields": {
                    action: list(fields)
                    for action, fields in CAPTAIN_EXECUTION_INTENT_ACTION_FIELDS.items()
                },
                "evidence_digests": list(CAPTAIN_EXECUTION_INTENT_EVIDENCE_KEYS),
                "freshness": {
                    "max_age_seconds": CAPTAIN_EXECUTION_INTENT_MAX_AGE_SECONDS,
                    "clock_skew_tolerance_seconds": CAPTAIN_EXECUTION_INTENT_CLOCK_SKEW_TOLERANCE_SECONDS,
                },
                "does_not_grant_by_itself": ["execution", "mutation", "merge", "deploy", "service_restart", "fleet_mutation", "cleanup"],
            },
        },
        "release_conditions": {
            "captain_preflight": ["never executes", "top-level status remains blocked by design"],
            "captain_run": [
                "allow_execution must be true",
                "same evidence gates must pass",
                "action must be in executable_action_allowlist",
                "a fresh execution_intent must bind action, canonical target digest, expected head, expected base and decisive evidence digests",
                "executor must verify the target before and after mutation",
            ],
        },
        "non_claims": [
            "allow_execution alone is never sufficient",
            "execution_authority evidence alone is never sufficient",
            "execution_intent alone is never sufficient",
            "trusted-owner autonomy is limited to reversible, target-bound implemented executors",
            "unsupported high-impact actions remain blocked",
            "receipts never echo raw execution_intent, actor or context values; only normalized fields and digests",
        ],
    }

class GripPreflightError(ValueError):
    pass


class GripActionError(RuntimeError):
    pass


def _json_compatible(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return {
        "__non_json_type__": f"{type(value).__module__}.{type(value).__qualname__}",
        "repr": repr(value),
    }


def canonical_json(value: Any) -> str:
    return json.dumps(_json_compatible(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _default_command_runner(repo: Path, argv: list[str]) -> dict[str, Any]:
    command = ["git", "--no-optional-locks", "-C", str(repo), *argv]
    env = os.environ.copy()
    exact_deny = {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_EXEC_PATH",
        "GIT_CONFIG",
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_ALLOW_PROTOCOL",
        "PAGER",
    }
    for key in tuple(env):
        if key in exact_deny or key.startswith("GIT_CONFIG_"):
            env.pop(key, None)
    command_config = (
        ("core.fsmonitor", "false"),
        ("core.hooksPath", "/dev/null"),
        ("protocol.ext.allow", "never"),
    )
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_COUNT": str(len(command_config)),
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GIT_ALLOW_PROTOCOL": "ssh",
            "GIT_SSH_COMMAND": "/usr/bin/ssh -F /dev/null -oBatchMode=yes -oProxyCommand=none -oPermitLocalCommand=no -oClearAllForwardings=yes",
            "GIT_SSH_VARIANT": "ssh",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
        }
    )
    for index, (key, value) in enumerate(command_config):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": (exc.stdout or "").rstrip("\n") if isinstance(exc.stdout, str) else "",
            "stderr": "git command timed out after 30 seconds",
            "argv": command,
        }
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.rstrip("\n"),
        "stderr": completed.stderr.rstrip("\n"),
        "argv": command,
    }


def _default_github_runner(repo: Path, argv: list[str]) -> dict[str, Any]:
    command = ["gh", *argv]
    env = os.environ.copy()
    for key in (
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_ASKPASS",
        "PAGER",
    ):
        env.pop(key, None)
    env.update({"GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "PAGER": "cat"})
    try:
        completed = subprocess.run(
            command,
            cwd=repo,
            text=False,
            capture_output=True,
            check=False,
            timeout=30,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        stdout_bytes = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr_bytes = exc.stderr if isinstance(exc.stderr, bytes) else b""
        partial_stderr = stderr_bytes.decode("utf-8", errors="replace").rstrip("\n")
        timeout_message = "gh command timed out after 30 seconds"
        if partial_stderr:
            timeout_message += f"; partial stderr: {partial_stderr}"
        return {
            "returncode": 124,
            "stdout": stdout_bytes.decode("utf-8", errors="replace").rstrip("\n"),
            "stderr": timeout_message,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "argv": command,
        }
    stdout_bytes = completed.stdout
    stderr_bytes = completed.stderr
    return {
        "returncode": completed.returncode,
        "stdout": stdout_bytes.decode("utf-8", errors="replace").rstrip("\n"),
        "stderr": stderr_bytes.decode("utf-8", errors="replace").rstrip("\n"),
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "argv": command,
    }


def _new_receipt(spec: GripSpec, parameters: dict[str, Any]) -> Receipt:
    return {
        "kind": GRIP_RECEIPT_KIND,
        "schema_version": GRIP_RECEIPT_SCHEMA_VERSION,
        "grip": {
            "name": spec.name,
            "version": spec.version,
            "effect": spec.effect,
        },
        "status": "running",
        "phase": "preflight",
        "started_at": utc_now(),
        "ended_at": None,
        "parameters_sha256": sha256_json(parameters),
        "acceptance_ids": list(spec.acceptance_ids),
        "checks": [],
        "output_sha256": None,
    }


def _finish(receipt: Receipt, status: str, phase: str, output: dict[str, Any] | None = None) -> dict[str, Any]:
    output = output or {}
    receipt["status"] = status
    receipt["phase"] = phase
    receipt["ended_at"] = utc_now()
    receipt["output_sha256"] = sha256_json(output)
    receipt["receipt_sha256"] = sha256_json({k: v for k, v in receipt.items() if k != "receipt_sha256"})
    return {
        "status": status,
        "receipt_sha256": receipt["receipt_sha256"],
        "receipt": receipt,
        "output": output,
    }


def _check(receipt: Receipt, check_id: str, status: str, detail: str) -> None:
    receipt["checks"].append({"id": check_id, "status": status, "detail": detail})


def _repo_path(parameters: dict[str, Any]) -> Path:
    raw = parameters.get("repo")
    if not isinstance(raw, str) or not raw.strip():
        raise GripPreflightError("repo parameter must be a non-empty string")
    return Path(raw).expanduser().resolve()


def _require_parameters(spec: GripSpec, parameters: dict[str, Any]) -> None:
    missing = [name for name in spec.required_parameters if name not in parameters]
    if missing:
        raise GripPreflightError(f"missing required parameters: {', '.join(missing)}")


def _git(repo: Path, runner: CommandRunner, argv: list[str]) -> dict[str, Any]:
    result = runner(repo, argv)
    if int(result.get("returncode", 1)) != 0:
        message = result.get("stderr") or result.get("stdout") or "git command failed"
        raise GripActionError(str(message))
    return result


def _git_optional(repo: Path, runner: CommandRunner, argv: list[str]) -> dict[str, Any]:
    return runner(repo, argv)


def _github(repo: Path, runner: GithubRunner, argv: list[str]) -> dict[str, Any]:
    result = runner(repo, argv)
    if int(result.get("returncode", 1)) != 0:
        message = result.get("stderr") or result.get("stdout") or "gh command failed"
        raise GripActionError(str(message))
    return result


def _json_stdout(result: dict[str, Any]) -> Any:
    raw = str(result.get("stdout", "")).strip()
    if not raw:
        raise GripActionError("expected JSON output from gh command")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GripActionError("invalid JSON output from gh command") from exc


def _orient(repo: Path, runner: CommandRunner) -> dict[str, Any]:
    root = _git(repo, runner, ["rev-parse", "--show-toplevel"])["stdout"]
    branch = _git(repo, runner, ["rev-parse", "--abbrev-ref", "HEAD"])["stdout"]
    head = _git(repo, runner, ["rev-parse", "HEAD"])["stdout"]
    status = _git(repo, runner, ["status", "--short", "--branch"])["stdout"]
    upstream = _git_optional(repo, runner, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    lines = [line for line in status.splitlines() if line]
    body = [line for line in lines[1:] if line]
    return {
        "repo": str(repo),
        "root": root,
        "branch": branch,
        "head": head,
        "dirty": bool(body),
        "status_header": lines[0] if lines else "",
        "status_entries": body,
        "upstream": upstream.get("stdout") if upstream.get("returncode") == 0 else None,
    }


def _run_repo_orient(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    repo = _repo_path(parameters)
    if not repo.exists():
        _check(receipt, "repo_exists", "fail", str(repo))
        raise GripPreflightError(f"repo does not exist: {repo}")
    _check(receipt, "repo_exists", "pass", str(repo))
    orientation = _orient(repo, runner)
    expected = parameters.get("expected_branch")
    if isinstance(expected, str) and expected:
        matches = orientation["branch"] == expected
        _check(
            receipt,
            "expected_branch",
            "pass" if matches else "fail",
            f"actual={orientation['branch']} expected={expected}",
        )
        orientation["expected_branch_match"] = matches
        if not matches:
            raise GripPreflightError(
                f"expected_branch mismatch: actual={orientation['branch']} expected={expected}"
            )
    else:
        _check(receipt, "expected_branch", "skip", "no expected_branch parameter")
        orientation["expected_branch_match"] = None
    try:
        rb = grabowski_repobrief.context(repo, runner, orientation, parameters)
    except Exception as exc:
        rb = {"available": False, "status": "error", "reason": str(exc)}
    orientation["repobrief_context"] = rb
    rb_status = str(rb.get("status") or "unknown")
    rb_check = "pass" if rb.get("available") else ("skip" if rb_status == "excluded" else "warn")
    _check(receipt, "repobrief_context", rb_check, rb_status)
    return orientation


def _check_results(parameters: dict[str, Any]) -> dict[str, str]:
    raw = parameters.get("check_results", {})
    if not isinstance(raw, dict):
        raise GripPreflightError("check_results must be a dictionary of check name to state")
    result: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise GripPreflightError("check_results must map strings to strings")
        result[key] = value.lower()
    return result

def _is_hex_sha(value: Any, *, lengths: tuple[int, ...]) -> bool:
    if not isinstance(value, str) or len(value) not in lengths:
        return False
    hex_digits = set("0123456789abcdef")
    return all(char in hex_digits for char in value.lower())

def _is_sha256_hex(value: Any) -> bool:
    return _is_hex_sha(value, lengths=(64,))


def _normalize_40_sha(value: Any) -> str | None:
    if not _is_hex_sha(value, lengths=(40,)):
        return None
    return str(value).lower()


def _returncode(result: dict[str, Any]) -> int:
    try:
        return int(result.get("returncode", 1))
    except (TypeError, ValueError):
        return 1


def _command_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _command_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return _command_text(value).encode("utf-8", errors="replace")


def _bounded_command_output(value: Any, *, limit: int = CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT) -> str:
    if limit <= 0:
        return ""
    if isinstance(value, bytes):
        if len(value) <= limit:
            return value.decode("utf-8", errors="replace")
        suffix = f"...[truncated {len(value) - limit} bytes]"
        suffix_bytes = suffix.encode("utf-8")
        if len(suffix_bytes) >= limit:
            return value[:limit].decode("utf-8", errors="replace")
        prefix = value[: limit - len(suffix_bytes)].decode("utf-8", errors="replace")
        return f"{prefix}{suffix}"
    text = _command_text(value)
    if len(text) <= limit:
        return text
    suffix = f"...[truncated {len(text) - limit} chars]"
    if len(suffix) >= limit:
        return text[:limit]
    return f"{text[: limit - len(suffix)]}{suffix}"


def _command_result_info(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        stderr = f"command runner returned non-object result: {type(result).__name__}"
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": _bounded_command_output(stderr),
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_sha256": hashlib.sha256(_command_bytes(stderr)).hexdigest(),
            "stdout_truncated": False,
            "stderr_truncated": len(stderr) > CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT,
            "schema_warning": "result_not_mapping",
        }
    raw_stdout = result.get("stdout", "")
    raw_stderr = result.get("stderr", "")
    stdout_bytes = _command_bytes(raw_stdout)
    stderr_bytes = _command_bytes(raw_stderr)
    info: dict[str, Any] = {
        "returncode": _returncode(result),
        "stdout": _bounded_command_output(raw_stdout),
        "stderr": _bounded_command_output(raw_stderr),
        "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "stdout_truncated": len(stdout_bytes) > CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT,
        "stderr_truncated": len(stderr_bytes) > CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT,
    }
    if "returncode" not in result:
        info["schema_warning"] = "returncode_missing"
    elif not isinstance(result.get("returncode"), int) or isinstance(result.get("returncode"), bool):
        info["schema_warning"] = "returncode_not_integer"
    return info


def _captain_sleep(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


def _external_review_evidence_errors(evidence: Any, *, expected_head: str | None) -> list[str]:
    """Validate optional legacy external-review diagnostics."""
    if not isinstance(evidence, dict):
        return ["external review evidence must be a structured object"]
    errors: list[str] = []
    head_sha = evidence.get("head_sha")
    if not _is_hex_sha(head_sha, lengths=(40,)):
        errors.append("head_sha must be a 40 character hex SHA")
    elif expected_head is not None and head_sha != expected_head:
        errors.append("head_sha does not match expected_head")
    if not _is_hex_sha(evidence.get("diff_sha256"), lengths=(64,)):
        errors.append("diff_sha256 must be a 64 character hex SHA")
    reviews = evidence.get("reviews")
    if not isinstance(reviews, list) or not reviews or not all(isinstance(item, dict) for item in reviews):
        errors.append("reviews must be a non-empty list of review objects")
    elif not any(item.get("verdict") for item in reviews):
        errors.append("at least one review must include a verdict")
    if evidence.get("external_reviews_triaged") is not True:
        errors.append("external_reviews_triaged must be true")
    findings = evidence.get("findings", [])
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        errors.append("findings must be a list of finding objects")
    return errors


def _self_review_audit_errors(
    evidence: Any,
    *,
    expected_head: str | None,
    expected_diff_sha256: str | None = None,
    expected_base_sha: str | None = None,
    expected_repo: str | None = None,
    expected_pr: int | None = None,
) -> list[str]:
    if not isinstance(evidence, dict):
        return ["self-review audit must be a structured object"]
    errors: list[str] = []
    if evidence.get("schema_version") != 1 or isinstance(evidence.get("schema_version"), bool):
        errors.append("schema_version must be integer 1")
    if evidence.get("kind") != "grabowski_self_review_audit":
        errors.append("kind must be grabowski_self_review_audit")
    if evidence.get("review_tier") not in {
        "documentation",
        "very_small",
        "standard",
        "important_repo",
        "high_critical",
    }:
        errors.append("review_tier is missing or invalid")
    repo = evidence.get("repo")
    if not isinstance(repo, str) or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo.strip()) is None:
        errors.append("repo must have owner/repo form")
    elif expected_repo is not None and repo.strip().lower() != expected_repo.strip().lower():
        errors.append("repo does not match PR target")
    pr_number = evidence.get("pr")
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0:
        errors.append("pr must be a positive integer")
    elif expected_pr is not None and pr_number != expected_pr:
        errors.append("pr does not match PR target")
    generated_at = evidence.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at.strip():
        errors.append("generated_at must be an RFC3339 timestamp with timezone")
    else:
        try:
            parsed_generated_at = datetime.fromisoformat(generated_at.strip().replace("Z", "+00:00"))
        except ValueError:
            parsed_generated_at = None
        if parsed_generated_at is None or parsed_generated_at.tzinfo is None:
            errors.append("generated_at must be an RFC3339 timestamp with timezone")
    head_sha = evidence.get("head_sha")
    if not _is_hex_sha(head_sha, lengths=(40,)):
        errors.append("head_sha must be a 40 character hex SHA")
    elif expected_head is not None and head_sha != expected_head:
        errors.append("head_sha does not match expected_head")
    base_sha = evidence.get("base_sha")
    if expected_base_sha is not None:
        if not _is_hex_sha(base_sha, lengths=(40,)):
            errors.append("base_sha must be a 40 character hex SHA")
        elif base_sha != expected_base_sha:
            errors.append("base_sha does not match expected_base_sha")
    elif base_sha is not None and not _is_hex_sha(base_sha, lengths=(40,)):
        errors.append("base_sha must be a 40 character hex SHA when provided")
    diff_sha256 = evidence.get("diff_sha256")
    if not _is_hex_sha(diff_sha256, lengths=(64,)):
        errors.append("diff_sha256 must be a 64 character hex SHA")
    elif expected_diff_sha256 is not None and diff_sha256 != expected_diff_sha256:
        errors.append("diff_sha256 does not match expected diff")
    if evidence.get("gate_verdict") != "PASS":
        errors.append("gate_verdict must be PASS")
    if evidence.get("self_review_gate_valid") is not True:
        errors.append("self_review_gate_valid must be true")
    if evidence.get("all_findings_triaged") is not True:
        errors.append("all_findings_triaged must be true")
    minimum = evidence.get("minimum_review_iterations")
    actual = evidence.get("actual_review_iterations")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or not 1 <= minimum <= 5:
        errors.append("minimum_review_iterations must be an integer from 1 to 5")
    if isinstance(actual, bool) or not isinstance(actual, int) or actual < 1:
        errors.append("actual_review_iterations must be a positive integer")
    elif isinstance(minimum, int) and not isinstance(minimum, bool) and actual < minimum:
        errors.append("actual_review_iterations is below required minimum")
    remaining = evidence.get("material_findings_remaining")
    if isinstance(remaining, bool) or not isinstance(remaining, int) or remaining < 0:
        errors.append("material_findings_remaining must be an integer >= 0")
    elif remaining > 0:
        if evidence.get("residual_risk_accepted") is not True:
            errors.append("material findings remain without accepted residual risk")
        reason = evidence.get("residual_risk_reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append("accepted residual risk requires a reason")
    if evidence.get("tuning_signal") != "observe":
        errors.append("tuning_signal must be observe for merge evidence")
    return errors


def _string_list_parameter(parameters: dict[str, Any], name: str, default: list[str] | None = None) -> list[str]:
    raw = parameters.get(name, default or [])
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise GripPreflightError(f"{name} must be a list of strings")
    return raw




def _parse_worktree_porcelain(value: str) -> list[dict[str, str | bool | list[str]]]:
    entries: list[dict[str, str | bool | list[str]]] = []
    current: dict[str, str | bool | list[str]] | None = None

    for raw_line in value.splitlines():
        if not raw_line:
            continue

        if raw_line.startswith("worktree "):
            if current is not None:
                entries.append(current)
            current = {"path": raw_line[len("worktree ") :]}
            continue

        if current is None:
            continue

        if raw_line.startswith("HEAD "):
            current["head"] = raw_line[len("HEAD ") :]
        elif raw_line.startswith("branch "):
            current["branch"] = raw_line[len("branch ") :].removeprefix("refs/heads/")
        elif raw_line == "detached":
            current["detached"] = True
        elif raw_line == "bare":
            current["bare"] = True
        elif raw_line == "locked":
            current["locked"] = True
            current["locked_reason"] = ""
        elif raw_line.startswith("locked "):
            current["locked"] = True
            current["locked_reason"] = raw_line.removeprefix("locked ")
        elif raw_line == "prunable":
            current["prunable"] = True
            current["prunable_reason"] = ""
        elif raw_line.startswith("prunable "):
            current["prunable"] = True
            current["prunable_reason"] = raw_line.removeprefix("prunable ")
        else:
            unknown = current.get("unknown_fields")
            if not isinstance(unknown, list):
                unknown = []
                current["unknown_fields"] = unknown
            unknown.append(raw_line)

    if current is not None:
        entries.append(current)

    return entries


def _worktree_status(path: Path, runner: CommandRunner) -> dict[str, Any]:
    status = _git_optional(path, runner, ["status", "--short", "--branch"])
    try:
        returncode = int(status.get("returncode", 1))
    except (TypeError, ValueError):
        returncode = 1
    status_available = returncode == 0
    stdout_raw = status.get("stdout") if status_available else ""
    stdout = stdout_raw if isinstance(stdout_raw, str) else ""
    lines = [line for line in stdout.splitlines() if line] if status_available else []
    body = [line for line in lines[1:] if line]
    error_raw = status.get("stderr") or status.get("stdout") or "git status failed"
    if not isinstance(error_raw, str):
        error_raw = f"git status failed with non-text output ({type(error_raw).__name__})"
    return {
        "path": str(path),
        "dirty": bool(body) if status_available else None,
        "status_header": lines[0] if lines else "",
        "status_entries": body,
        "status_available": status_available,
        "status_error": "" if status_available else error_raw,
        "status_returncode": returncode,
    }


def _run_worktree_orient(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    repo = _repo_path(parameters)
    if not repo.exists():
        _check(receipt, "repo_exists", "fail", str(repo))
        raise GripPreflightError(f"repo does not exist: {repo}")
    _check(receipt, "repo_exists", "pass", str(repo))

    try:
        protected = _string_list_parameter(parameters, "protected_branches", ["main", "master"])
    except GripPreflightError as exc:
        _check(receipt, "protected_branches_valid", "fail", str(exc))
        raise
    if not protected:
        _check(receipt, "protected_branches_valid", "fail", "empty list")
        raise GripPreflightError("protected_branches must not be empty")
    invalid_protected = [item for item in protected if not item or item != item.strip() or item.startswith("refs/")]
    if invalid_protected:
        _check(receipt, "protected_branches_valid", "fail", "branch names must be non-empty trimmed short names")
        raise GripPreflightError("protected_branches entries must be non-empty trimmed short branch names")
    if len(set(protected)) != len(protected):
        _check(receipt, "protected_branches_valid", "fail", "duplicate branch names")
        raise GripPreflightError("protected_branches entries must be unique")
    _check(receipt, "protected_branches_valid", "pass", ", ".join(protected))

    worktree_result = _git(repo, runner, ["worktree", "list", "--porcelain"])
    raw = worktree_result.get("stdout")
    if not isinstance(raw, str):
        raise GripActionError("git worktree porcelain output must be text")
    entries = _parse_worktree_porcelain(raw)
    _check(receipt, "worktree_list", "pass" if entries else "warn", f"count={len(entries)}")

    worktrees: list[dict[str, Any]] = []
    active_feature_worktrees: list[str] = []
    clean_feature_worktrees: list[str] = []
    dirty_worktrees: list[str] = []
    unobservable_worktrees: list[str] = []
    detached_worktrees: list[str] = []
    prunable_worktrees: list[str] = []
    locked_worktrees: list[str] = []
    bare_worktrees: list[str] = []
    stale_candidates: list[str] = []
    cleanup_candidates: list[dict[str, Any]] = []
    cleanup_candidate_index: dict[str, dict[str, Any]] = {}
    stale_candidate_seen: set[str] = set()

    canonical_checkout: str | None = None
    canonical_checkout_reason: str | None = None
    repo_resolved = repo.resolve()

    def same_resolved_path(path_value: str) -> bool:
        try:
            return Path(path_value).expanduser().resolve() == repo_resolved
        except OSError:
            return False

    def add_cleanup_candidate(path_value: str, branch: str | None, reason: str) -> None:
        if not path_value:
            return
        if path_value not in stale_candidate_seen:
            stale_candidate_seen.add(path_value)
            stale_candidates.append(path_value)

        existing = cleanup_candidate_index.get(path_value)
        if existing is not None:
            reasons = existing.setdefault("reasons", [])
            if reason not in reasons:
                reasons.append(reason)
                existing["reason"] = "; ".join(reasons)
            if branch and not existing.get("branch"):
                existing["branch"] = branch
            return

        record: dict[str, Any] = {
            "path": path_value,
            "branch": branch,
            "reason": reason,
            "reasons": [reason],
            "cleanup_allowed": False,
        }
        cleanup_candidate_index[path_value] = record
        cleanup_candidates.append(record)

    for entry in entries:
        path_value = str(entry.get("path", ""))
        branch = entry.get("branch") if isinstance(entry.get("branch"), str) else None
        detached = bool(entry.get("detached"))
        bare = bool(entry.get("bare"))
        locked = bool(entry.get("locked"))
        prunable = bool(entry.get("prunable"))

        status = (
            _worktree_status(Path(path_value), runner)
            if path_value
            else {
                "dirty": None,
                "status_available": False,
                "status_error": "missing worktree path",
                "status_returncode": 1,
            }
        )
        status_available = bool(status.get("status_available"))
        dirty = status.get("dirty") is True

        is_protected = branch in protected if branch else False
        is_feature = bool(branch and branch not in protected)

        record = {
            **entry,
            **status,
            "branch": branch,
            "is_protected": is_protected,
            "is_feature": is_feature,
            "is_canonical": False,
            "is_cleanup_candidate": False,
        }

        if same_resolved_path(path_value) and canonical_checkout is None:
            canonical_checkout = path_value
            canonical_checkout_reason = "matches requested repo path"
            record["is_canonical"] = True

        if detached and path_value:
            detached_worktrees.append(path_value)
        if bare and path_value:
            bare_worktrees.append(path_value)
        if locked and path_value:
            locked_worktrees.append(path_value)
        if prunable and path_value:
            prunable_worktrees.append(path_value)
        if not status_available and path_value:
            unobservable_worktrees.append(path_value)
        if dirty and path_value:
            dirty_worktrees.append(path_value)

        if is_feature and path_value:
            active_feature_worktrees.append(path_value)
            if status_available and not dirty:
                clean_feature_worktrees.append(path_value)

        if prunable and path_value:
            if status_available:
                add_cleanup_candidate(
                    path_value,
                    branch,
                    str(entry.get("prunable_reason") or "git marks worktree prunable"),
                )
                record["is_cleanup_candidate"] = True
            else:
                record["classification_degraded_reason"] = "prunable marker present but status unavailable"

        worktrees.append(record)

    if canonical_checkout is None:
        for protected_branch in protected:
            for record in worktrees:
                if record.get("path") and record.get("branch") == protected_branch:
                    canonical_checkout = str(record.get("path"))
                    canonical_checkout_reason = "first protected branch worktree by protected_branches order"
                    record["is_canonical"] = True
                    break
            if canonical_checkout is not None:
                break

    if canonical_checkout is None and worktrees:
        canonical_checkout = str(worktrees[0].get("path"))
        canonical_checkout_reason = "fallback to first listed worktree"
        worktrees[0]["is_canonical"] = True

    unavailable_count = len(unobservable_worktrees)
    _check(
        receipt,
        "worktree_status_read",
        "pass" if unavailable_count == 0 else "warn",
        f"unavailable={unavailable_count} observed={len(worktrees) - unavailable_count}",
    )
    _check(
        receipt,
        "status_unavailable_count",
        "pass" if unavailable_count == 0 else "warn",
        str(unavailable_count),
    )
    _check(
        receipt,
        "classification_degraded",
        "warn" if unavailable_count else "pass",
        "status unavailable for some worktrees" if unavailable_count else "all listed worktrees classified",
    )

    blocked_by_worktree_review = bool(cleanup_candidates or unobservable_worktrees)
    if blocked_by_worktree_review:
        next_safe_grip = {
            "name": None,
            "parameters": None,
            "reason": "manual review is required before cleanup or unknown-status worktree handling; no automatic next grip is recommended",
            "effect": READ_ONLY,
        }
    elif len(active_feature_worktrees) == 1 and len(clean_feature_worktrees) == 1:
        next_safe_grip = {
            "name": "pr-check-readiness",
            "parameters": {"repo": clean_feature_worktrees[0]},
            "reason": "one clean feature worktree is the unambiguous next read-only PR readiness target",
            "effect": READ_ONLY,
        }
    elif len(clean_feature_worktrees) > 1:
        next_safe_grip = {
            "name": None,
            "parameters": None,
            "reason": "multiple clean feature worktrees exist; choose a target manually",
            "effect": READ_ONLY,
        }
    else:
        next_safe_grip = {
            "name": None,
            "parameters": None,
            "reason": "no unambiguous clean PR worktree target",
            "effect": READ_ONLY,
        }

    return {
        "repo": str(repo),
        "canonical_checkout": canonical_checkout,
        "canonical_checkout_reason": canonical_checkout_reason,
        "active_feature_worktrees": active_feature_worktrees,
        "clean_feature_worktrees": clean_feature_worktrees,
        "detached_worktrees": detached_worktrees,
        "dirty_worktrees": dirty_worktrees,
        "unobservable_worktrees": unobservable_worktrees,
        "prunable_worktrees": prunable_worktrees,
        "locked_worktrees": locked_worktrees,
        "bare_worktrees": bare_worktrees,
        "stale_candidates": stale_candidates,
        "cleanup_candidates": cleanup_candidates,
        "cleanup_candidate_count": len(cleanup_candidates),
        "worktrees": worktrees,
        "next_safe_grip": next_safe_grip,
    }




def _grip_catalog_snapshot() -> dict[str, Any]:
    return {
        "receipt_kind": GRIP_RECEIPT_KIND,
        "receipt_schema_version": GRIP_RECEIPT_SCHEMA_VERSION,
        "grips": {
            name: {
                "name": spec.name,
                "version": spec.version,
                "summary": spec.summary,
                "effect": spec.effect,
                "required_parameters": list(spec.required_parameters),
                "acceptance_ids": list(spec.acceptance_ids),
                "runner": spec.runner,
                "uses_github": spec.uses_github,
            }
            for name, spec in sorted(GRIP_SPECS.items())
        },
    }


def _grip_catalog_digest() -> str:
    return sha256_json(_grip_catalog_snapshot())


def _bool_parameter(parameters: dict[str, Any], name: str, default: bool) -> bool:
    value = parameters.get(name, default)
    if not isinstance(value, bool):
        raise GripPreflightError(f"{name} must be a boolean when provided")
    return value


def _source_object(parameters: dict[str, Any], name: str) -> dict[str, Any]:
    value = parameters.get(name)
    if value is None:
        return {"available": False, "reason": f"{name} parameter not provided"}
    if not isinstance(value, dict):
        raise GripPreflightError(f"{name} must be an object when provided")
    return {"available": True, "value": value}


def _source_list(parameters: dict[str, Any], name: str) -> dict[str, Any]:
    value = parameters.get(name)
    if value is None:
        return {"available": False, "items": [], "reason": f"{name} parameter not provided"}
    if not isinstance(value, list):
        raise GripPreflightError(f"{name} must be a list when provided")
    return {"available": True, "items": value}


def _truncate_reason(value: Any, limit: int = 500) -> str:
    text = str(value).strip()
    return text[:limit] if text else "unknown"


def _check_rollup_summary(checks: Any) -> dict[str, Any]:
    states: list[str] = []
    check_results: dict[str, str] = {}
    if isinstance(checks, list):
        for item in checks:
            if not isinstance(item, dict):
                continue
            state = item.get("conclusion") or item.get("status") or item.get("state")
            if not isinstance(state, str):
                continue
            states.append(state)
            name = item.get("name") or item.get("context") or item.get("workflowName")
            if isinstance(name, str) and name.strip():
                check_results[name] = state
    counter = Counter(states)
    return {
        "check_state_counts": {state: counter[state] for state in sorted(counter)},
        "check_results": dict(sorted(check_results.items())),
    }


def _valid_pr_candidate(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        isinstance(value.get("number"), int)
        and isinstance(value.get("headRefName"), str)
        and bool(value.get("headRefName"))
        and isinstance(value.get("headRefOid"), str)
        and bool(value.get("headRefOid"))
    )


def _summarize_pr_candidate(value: dict[str, Any]) -> dict[str, Any]:
    check_summary = _check_rollup_summary(value.get("statusCheckRollup"))
    return {
        "number": value.get("number"),
        "url": value.get("url"),
        "state": value.get("state"),
        "base": value.get("baseRefName"),
        "head": value.get("headRefName"),
        "head_oid": value.get("headRefOid"),
        "is_draft": value.get("isDraft"),
        "mergeable": value.get("mergeable"),
        **check_summary,
    }


def _lookup_open_prs_for_branch(
    repo: Path,
    branch: str,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    if branch == "HEAD":
        return {
            "available": False,
            "ambiguous": False,
            "count": 0,
            "reason": "detached HEAD; PR lookup by branch skipped",
        }

    pr_result = github_runner(
        repo,
        [
            "pr",
            "list",
            "--head",
            branch,
            "--state",
            "open",
            "--json",
            "number,url,state,baseRefName,headRefName,headRefOid,isDraft,mergeable,statusCheckRollup",
        ],
    )
    if int(pr_result.get("returncode", 1)) != 0:
        return {
            "available": False,
            "ambiguous": False,
            "count": 0,
            "reason": _truncate_reason(
                pr_result.get("stderr") or pr_result.get("stdout") or "PR lookup unavailable"
            ),
        }

    raw = str(pr_result.get("stdout", "")).strip()
    try:
        parsed = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        return {
            "available": False,
            "ambiguous": False,
            "count": 0,
            "reason": "PR lookup returned invalid JSON",
        }
    if not isinstance(parsed, list):
        return {
            "available": False,
            "ambiguous": False,
            "count": 0,
            "reason": "PR lookup returned non-list JSON",
        }

    candidates = [_summarize_pr_candidate(item) for item in parsed if _valid_pr_candidate(item)]
    if not candidates:
        reason = "no open PR for current branch" if not parsed else "PR lookup returned incomplete PR object"
        return {"available": False, "ambiguous": False, "count": 0, "reason": reason}
    if len(candidates) == 1:
        return {"available": True, "ambiguous": False, "count": 1, **candidates[0]}
    return {
        "available": True,
        "ambiguous": True,
        "count": len(candidates),
        "reason": "multiple open PRs for current branch",
        "candidates": [
            {"number": item.get("number"), "url": item.get("url"), "head_oid": item.get("head_oid")}
            for item in candidates
        ],
    }


def _situation_digest_info(parameters: dict[str, Any], receipt: Receipt) -> dict[str, Any]:
    digest = _grip_catalog_digest()
    expected_digest = parameters.get("expected_grip_catalog_sha256")
    stale_warning = None
    if expected_digest is not None:
        if not _is_hex_sha(expected_digest, lengths=(64,)):
            raise GripPreflightError(
                "expected_grip_catalog_sha256 must be a 64 character hex SHA when provided"
            )
        if expected_digest != digest:
            stale_warning = "expected grip catalog digest differs from runtime grip catalog digest"
    _check(
        receipt,
        SITUATION_CHECK_SNAPSHOT_DIGEST,
        "warn" if stale_warning else "pass",
        stale_warning or digest,
    )
    return {
        "generated_at": utc_now(),
        "grip_catalog_sha256": digest,
        "expected_grip_catalog_sha256": expected_digest,
        "stale_warning": stale_warning,
        "source_identity": {
            "module": __name__,
            "receipt_kind": GRIP_RECEIPT_KIND,
            "receipt_schema_version": GRIP_RECEIPT_SCHEMA_VERSION,
            "grip_count": len(GRIP_SPECS),
        },
    }


def _build_situation_bureau_section(parameters: dict[str, Any]) -> dict[str, Any]:
    return {
        "task": _source_object(parameters, "bureau_task"),
        "run": _source_object(parameters, "bureau_run"),
        "blockers": _source_list(parameters, "blockers"),
    }


def _determine_situation_next_safe_grip(
    repo: Path,
    orientation: dict[str, Any],
    pr_summary: dict[str, Any],
) -> dict[str, Any]:
    if orientation["dirty"]:
        return {
            "name": "repo-orient",
            "parameters": {"repo": str(repo), "expected_branch": orientation["branch"]},
            "reason": "checkout is dirty; stay read-only until the dirty state is reviewed",
            "preconditions": ["same repo path", "same branch"],
            "does_not_establish": list(SITUATION_NON_CLAIMS),
        }
    if pr_summary.get("ambiguous"):
        return {
            "name": None,
            "parameters": None,
            "reason": "multiple open PRs match the current branch; choose the PR explicitly first",
            "preconditions": ["one PR target is selected explicitly"],
            "does_not_establish": list(SITUATION_NON_CLAIMS),
        }
    if pr_summary.get("available"):
        parameters: dict[str, Any] = {
            "repo": str(repo),
            "expected_head": orientation["head"],
            "self_review_required": True,
        }
        check_results = pr_summary.get("check_results")
        if isinstance(check_results, dict) and check_results:
            parameters["check_results"] = check_results
        return {
            "name": "pr-check-readiness",
            "parameters": parameters,
            "reason": "open PR exists for current branch and checkout is clean",
            "preconditions": [
                "PR head is re-read before acting",
                "checks, current diff hash and self-review audit are re-read before readiness can pass",
            ],
            "does_not_establish": list(SITUATION_NON_CLAIMS),
        }
    return {
        "name": "worktree-orient",
        "parameters": {"repo": str(repo)},
        "reason": "no open PR was observed; orient worktrees before choosing an action target",
        "preconditions": ["worktree list remains readable"],
        "does_not_establish": list(SITUATION_NON_CLAIMS),
    }


def _run_situation(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    repo = _repo_path(parameters)
    if not repo.exists():
        _check(receipt, "repo_exists", "fail", str(repo))
        raise GripPreflightError(f"repo does not exist: {repo}")
    _check(receipt, "repo_exists", "pass", str(repo))

    include_pr = _bool_parameter(parameters, "include_pr", True)
    orientation = _orient(repo, runner)
    _check(
        receipt,
        SITUATION_CHECK_REPO_STATE,
        "pass" if not orientation["dirty"] else "warn",
        f"branch={orientation['branch']} dirty={orientation['dirty']}",
    )
    digest_info = _situation_digest_info(parameters, receipt)

    pr_summary = (
        _lookup_open_prs_for_branch(repo, str(orientation["branch"]), github_runner)
        if include_pr
        else {"available": False, "ambiguous": False, "count": 0, "reason": "PR lookup skipped"}
    )
    _check(
        receipt,
        SITUATION_CHECK_PR_STATE,
        "pass" if pr_summary.get("available") and not pr_summary.get("ambiguous") else "warn",
        str(pr_summary.get("number") or pr_summary.get("reason")),
    )

    next_safe = _determine_situation_next_safe_grip(repo, orientation, pr_summary)
    _check(receipt, SITUATION_CHECK_NEXT_SAFE_GRIP, "pass", str(next_safe["name"]))

    return {
        "repo": orientation,
        "pr": pr_summary,
        "bureau": _build_situation_bureau_section(parameters),
        "jobs": _source_list(parameters, "jobs"),
        "snapshot_digest": digest_info,
        "next_safe_grip": next_safe,
        "non_claims": list(SITUATION_NON_CLAIMS),
    }

def _run_pr_check_readiness(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    orientation = _run_repo_orient(spec, parameters, receipt, runner)
    protected = parameters.get("protected_branches", ["main", "master"])
    if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
        raise GripPreflightError("protected_branches must be a list of strings")
    branch_is_work = orientation["branch"] not in set(protected)
    upstream_set = orientation["upstream"] is not None
    clean_required = _bool_parameter(parameters, "require_clean", False)
    clean_ok = not orientation["dirty"] if clean_required else True
    blocking_reasons: list[str] = []
    warnings: list[str] = []
    _check(
        receipt,
        "work_branch",
        "pass" if branch_is_work else "fail",
        f"branch={orientation['branch']}",
    )
    if not branch_is_work:
        blocking_reasons.append("protected branch is not a PR work branch")
    _check(
        receipt,
        "upstream",
        "pass" if upstream_set else "warn",
        orientation["upstream"] or "no upstream configured",
    )
    if not upstream_set:
        warnings.append("no upstream configured")
    _check(
        receipt,
        "cleanliness",
        "pass" if clean_ok else "fail",
        "clean required" if clean_required else "clean not required",
    )
    if not clean_ok:
        blocking_reasons.append("worktree is dirty")
    expected_head = parameters.get("expected_head")
    if expected_head is not None:
        expected_head = _sha_parameter(parameters, "expected_head")
        head_ok = orientation["head"] == expected_head
        _check(receipt, "expected_head", "pass" if head_ok else "fail", f"actual={orientation['head']} expected={expected_head}")
        if not head_ok:
            blocking_reasons.append("expected_head mismatch")
    required_checks = _string_list_parameter(parameters, "required_checks")
    check_results = _check_results(parameters)
    missing_checks = [name for name in required_checks if name not in check_results]
    failing_checks = [name for name in required_checks if check_results.get(name) not in (None, "success", "pass", "passed")]
    if required_checks:
        checks_ok = not missing_checks and not failing_checks
        detail = f"required={required_checks} missing={missing_checks} failing={failing_checks}"
        _check(receipt, "required_checks", "pass" if checks_ok else "fail", detail)
        if missing_checks:
            blocking_reasons.append("required checks missing")
        if failing_checks:
            blocking_reasons.append("required checks failing")
    else:
        _check(receipt, "required_checks", "skip", "no required_checks parameter")
    review_decision = parameters.get("review_decision")
    if review_decision is not None:
        if not isinstance(review_decision, str):
            raise GripPreflightError("review_decision must be a string when provided")
        normalized_review = review_decision.upper()
        status = "pass" if normalized_review == "APPROVED" else "warn"
        _check(receipt, "review_decision", status, normalized_review or "empty")
        warnings.append("review_decision is deprecated advisory metadata and never satisfies or blocks self-review")
    unresolved_findings = _string_list_parameter(parameters, "unresolved_findings")
    if unresolved_findings:
        _check(receipt, "unresolved_findings", "fail", ", ".join(unresolved_findings))
        blocking_reasons.append("unresolved review findings")
    else:
        _check(receipt, "unresolved_findings", "pass", "none")
    requested_self_review_required = _bool_parameter(
        parameters, "self_review_required", True
    )
    self_review_required = True
    if not requested_self_review_required:
        warnings.append(
            "self_review_required=false is deprecated and ignored; PR readiness always requires self-review"
        )
    self_review_audit = parameters.get("self_review_audit")
    expected_head_for_review = str(orientation["head"])
    raw_expected_review_diff = parameters.get("expected_diff_sha256")
    expected_review_diff: str | None = None
    if raw_expected_review_diff is not None:
        if not isinstance(raw_expected_review_diff, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", raw_expected_review_diff):
            raise GripPreflightError("expected_diff_sha256 must be a 64 character hex SHA when provided")
        expected_review_diff = raw_expected_review_diff.lower()
    if self_review_required and expected_review_diff is None:
        _check(receipt, "self_review_diff_binding", "fail", "expected_diff_sha256 is required")
        blocking_reasons.append("self-review diff binding missing")
    elif expected_review_diff is not None:
        _check(receipt, "self_review_diff_binding", "pass", expected_review_diff)
    else:
        _check(receipt, "self_review_diff_binding", "skip", "self-review not required")
    if self_review_required and not self_review_audit:
        _check(receipt, "self_review_audit", "fail", "self-review required but no audit provided")
        blocking_reasons.append("self-review audit missing")
    elif self_review_audit is not None:
        evidence_errors = _self_review_audit_errors(
            self_review_audit,
            expected_head=expected_head_for_review,
            expected_diff_sha256=expected_review_diff,
        )
        if evidence_errors:
            _check(receipt, "self_review_audit", "fail", "; ".join(evidence_errors))
            blocking_reasons.append("self-review audit invalid")
        else:
            _check(receipt, "self_review_audit", "pass", "diff-bound self-review audit provided")
    else:
        _check(receipt, "self_review_audit", "skip", "not requested on this readiness probe")
    if parameters.get("external_review_required") is True:
        warnings.append("external_review_required is deprecated and ignored; use self_review_required")
    external_review_evidence = parameters.get("external_review_evidence")
    if external_review_evidence is not None:
        legacy_errors = _external_review_evidence_errors(
            external_review_evidence, expected_head=expected_head_for_review
        )
        status = "warn" if legacy_errors else "pass"
        detail = "; ".join(legacy_errors) if legacy_errors else "optional diagnostic evidence provided"
        _check(receipt, "external_review_evidence", status, detail)
        warnings.append("external review evidence is optional and never satisfies self-review")
    else:
        _check(receipt, "external_review_evidence", "skip", "optional and absent")
    ready = branch_is_work and upstream_set and clean_ok and not blocking_reasons
    verdict = "ready" if ready else "blocked"
    return {
        "ready": ready,
        "verdict": verdict,
        "blocking_reasons": blocking_reasons,
        "warnings": warnings,
        "orientation": orientation,
        "protected_branches": protected,
        "require_clean": clean_required,
        "required_checks": required_checks,
        "check_results": check_results,
        "unresolved_findings": unresolved_findings,
        "self_review_required": self_review_required,
        "expected_diff_sha256": expected_review_diff,
        "external_review_required": False,
    }


def _string_parameter(parameters: dict[str, Any], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value.strip():
        raise GripPreflightError(f"{name} parameter must be a non-empty string")
    return value.strip()


def _sha_parameter(parameters: dict[str, Any], name: str) -> str:
    value = _string_parameter(parameters, name)
    hex_digits = set("0123456789abcdef")
    if len(value) not in (40, 64) or any(char not in hex_digits for char in value.lower()):
        raise GripPreflightError(f"{name} parameter must be a 40 or 64 character hex SHA")
    return value


def _runtime_deploy_expected_head(parameters: dict[str, Any]) -> str:
    value = _sha_parameter(parameters, "expected_head")
    if len(value) != 40:
        raise GripPreflightError("expected_head parameter must be a 40 character Git commit SHA")
    return value.lower()


def _runtime_deploy_adapter(parameters: dict[str, Any]) -> str:
    adapter = _string_parameter(parameters, "adapter")
    if adapter not in RUNTIME_DEPLOY_ADAPTERS:
        raise GripPreflightError(
            f"adapter is not registered: {adapter}; expected one of {sorted(RUNTIME_DEPLOY_ADAPTERS)}"
        )
    return adapter


def _runtime_deploy_source_parameters(
    parameters: dict[str, Any],
) -> tuple[str | None, str | None]:
    source_repository = parameters.get("source_repository")
    source_owner = parameters.get("source_lease_owner_id")
    if (source_repository is None) != (source_owner is None):
        raise GripPreflightError(
            "source_repository and source_lease_owner_id must be provided together"
        )
    if source_repository is None:
        return None, None
    repository = _string_parameter(parameters, "source_repository")
    owner = _string_parameter(parameters, "source_lease_owner_id")
    if not Path(repository).expanduser().is_absolute():
        raise GripPreflightError("source_repository must be an absolute path")
    if re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", owner) is None:
        raise GripPreflightError("source_lease_owner_id is invalid")
    return repository, owner


def _runtime_deploy_delay_seconds(parameters: dict[str, Any]) -> int:
    value = parameters.get("delay_seconds", RUNTIME_DEPLOY_DEFAULT_DELAY_SECONDS)
    if isinstance(value, bool) or not isinstance(value, int):
        raise GripPreflightError("delay_seconds must be an integer when provided")
    if not RUNTIME_DEPLOY_MIN_DELAY_SECONDS <= value <= RUNTIME_DEPLOY_MAX_DELAY_SECONDS:
        raise GripPreflightError(
            f"delay_seconds must be between {RUNTIME_DEPLOY_MIN_DELAY_SECONDS} and {RUNTIME_DEPLOY_MAX_DELAY_SECONDS}"
        )
    return value


def _runtime_deploy_self_preflight(
    expected_head: str,
    source_repository: str | None = None,
    source_lease_owner_id: str | None = None,
) -> dict[str, Any]:
    import grabowski_self_deploy

    repository, runner, source_identity = grabowski_self_deploy._deployment_source_preflight(
        expected_head,
        source_repository,
        source_lease_owner_id,
    )
    return {
        "adapter": RUNTIME_DEPLOY_ADAPTER_GRABOWSKI_SELF,
        "repository": str(repository),
        "runner": str(runner),
        "job_root": str(grabowski_self_deploy.DEPLOY_JOB_ROOT),
        "job_prefix": grabowski_self_deploy.DEPLOY_JOB_PREFIX,
        "expected_head": expected_head,
        "source_kind": source_identity["source_kind"],
        "source_identity_sha256": source_identity["identity_sha256"],
        "source_lease_resource_key": source_identity["lease_evidence"].get("resource_key"),
        "source_lease_metadata_sha256": (
            source_identity["lease_evidence"].get("lease") or {}
        ).get("metadata_sha256"),
        "target": {
            "service": RUNTIME_DEPLOY_GRABOWSKI_SERVICE,
            "runtime_target": RUNTIME_DEPLOY_GRABOWSKI_TARGET,
        },
        "ready": True,
    }


def _runtime_deploy_self_schedule(
    expected_head: str,
    delay_seconds: int,
    source_repository: str | None = None,
    source_lease_owner_id: str | None = None,
) -> dict[str, Any]:
    import grabowski_self_deploy

    return grabowski_self_deploy.grabowski_runtime_deploy_schedule(
        expected_head,
        delay_seconds,
        source_repository,
        source_lease_owner_id,
    )


def _runtime_deploy_self_expected_argv_sha256(
    preflight: dict[str, Any],
    expected_head: str,
    delay_seconds: int,
) -> str:
    import grabowski_self_deploy

    source_kind = str(preflight["source_kind"])
    source_identity_sha256 = str(preflight["source_identity_sha256"])
    command = grabowski_self_deploy._deploy_command(
        Path(str(preflight["repository"])),
        Path(str(preflight["runner"])),
        expected_head,
        delay_seconds,
        canonical_repository=grabowski_self_deploy.CANONICAL_REPOSITORY,
        source_kind=source_kind,
        source_identity_sha256=source_identity_sha256,
    )
    return grabowski_self_deploy._deploy_command_sha256(command)


def _run_connector_snapshot_bind(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    try:
        output = grabowski_client_snapshot.bind_snapshot(parameters)
    except grabowski_client_snapshot.ClientSnapshotError as exc:
        _check(receipt, "client-declaration-bounded", "fail", str(exc))
        raise GripPreflightError(str(exc)) from exc
    except OSError as exc:
        _check(
            receipt,
            "private-receipt-persisted",
            "fail",
            type(exc).__name__,
        )
        raise GripActionError("client snapshot persistence failed") from exc
    _check(receipt, "client-declaration-bounded", "pass", output["client_declaration_sha256"])
    _check(
        receipt,
        "server-tool-contract-bound",
        "pass" if output["verified"] else "fail",
        output["state"],
    )
    _check(receipt, "release-bound", "pass" if output["verified"] else "fail", output["state"])
    _check(receipt, "private-receipt-persisted", "pass", output["receipt_sha256"])
    if not output["verified"]:
        output["receipt_status"] = "blocked"
        output["decision"] = "blocked"
        output["blocked_reasons"] = ["connector_snapshot_mismatch"]
    return output


def _run_convergence_assess(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    try:
        output = grabowski_convergence.assess(parameters, runner)
    except grabowski_convergence.ConvergenceInputError as exc:
        _check(receipt, "protocol-identity-bound", "fail", str(exc))
        raise GripPreflightError(str(exc)) from exc
    except grabowski_convergence.ConvergenceExecutionError as exc:
        _check(receipt, "deterministic-assessment", "fail", str(exc))
        raise GripActionError(str(exc)) from exc
    _check(receipt, "protocol-identity-bound", "pass", output["protocol_head"])
    _check(receipt, "request-hash-bound", "pass", output["request_sha256"])
    assessment = output["assessment"]
    _check(
        receipt,
        "deterministic-assessment",
        "pass",
        f"assessment_id={assessment['assessment_id']}; status={assessment['status']}",
    )
    closure_allowed = output["closure_allowed"] is True
    _check(
        receipt,
        "terminal-closure-gate",
        "pass" if closure_allowed else "fail",
        assessment["status"],
    )
    return {**output, "receipt_status": "passed" if closure_allowed else "blocked"}


_GATE_EVIDENCE_CATEGORIES = (
    "leases",
    "dirty_state",
    "running_work",
    "receipt",
    "acceptance",
    "post_state_readback",
)
_GATE_EVIDENCE_STATES = frozenset({"satisfied", "missing", "not_required", "unknown"})
_CONVERGENCE_RECORD_KEYS = frozenset({
    "record_id",
    "observed_state",
    "failure_evidence",
    "expected_evidence",
    "blocking_evidence",
    "superseding_evidence",
    "resolution_evidence",
})
_CONVERGENCE_SIGNAL_FIELDS = (
    ("failure_evidence", "defect"),
    ("expected_evidence", "expected"),
    ("blocking_evidence", "blocked"),
    ("superseding_evidence", "superseded"),
    ("resolution_evidence", "resolved"),
)


def _bounded_contract_text(value: Any, *, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise GripPreflightError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        raise GripPreflightError(f"{field} must be non-empty and at most {maximum} characters")
    return normalized


def _strict_contract_object(
    value: Any,
    *,
    field: str,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GripPreflightError(f"{field} must be an object")
    keys = set(value)
    missing = sorted(required - keys)
    extra = sorted(keys - required - optional)
    if missing or extra:
        raise GripPreflightError(f"{field} has invalid keys: missing={missing}; extra={extra}")
    return dict(value)


def _gate_identity_object(parameters: dict[str, Any], field: str) -> dict[str, Any]:
    value = parameters[field]
    if not isinstance(value, dict) or not value or len(value) > 16:
        raise GripPreflightError(f"{field} must be a non-empty object with at most 16 fields")
    normalized: dict[str, Any] = {}
    for key, item in sorted(value.items()):
        normalized_key = _bounded_contract_text(key, field=f"{field} key", maximum=64)
        if isinstance(item, str):
            normalized[normalized_key] = _bounded_contract_text(
                item, field=f"{field}.{key}", maximum=512
            )
        elif isinstance(item, bool):
            normalized[normalized_key] = item
        elif isinstance(item, int):
            if not -(2**63) <= item < 2**63:
                raise GripPreflightError(f"{field}.{key} integer is outside the signed 64-bit range")
            normalized[normalized_key] = item
        else:
            raise GripPreflightError(
                f"{field}.{key} must be a string, integer, or boolean scalar"
            )
    return normalized


def _run_gate_evidence_preflight(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    gate_owner = _bounded_contract_text(parameters["gate_owner"], field="gate_owner", maximum=256)
    policy_boundary = _bounded_contract_text(parameters["policy_boundary"], field="policy_boundary")
    target = _gate_identity_object(parameters, "target")
    scope = _gate_identity_object(parameters, "scope")
    expected_identity = _gate_identity_object(parameters, "expected_identity")
    evidence = _strict_contract_object(
        parameters["evidence"],
        field="evidence",
        required=frozenset(_GATE_EVIDENCE_CATEGORIES),
    )
    normalized_evidence: list[dict[str, str]] = []
    missing: list[str] = []
    for category in _GATE_EVIDENCE_CATEGORIES:
        item = _strict_contract_object(
            evidence[category],
            field=f"evidence.{category}",
            required=frozenset({"status", "reference"}),
        )
        status = _bounded_contract_text(item["status"], field=f"evidence.{category}.status", maximum=32)
        if status not in _GATE_EVIDENCE_STATES:
            raise GripPreflightError(f"evidence.{category}.status is invalid")
        reference = _bounded_contract_text(
            item["reference"], field=f"evidence.{category}.reference", maximum=1024
        )
        normalized_evidence.append({
            "category": category,
            "status": status,
            "reference_sha256": hashlib.sha256(reference.encode("utf-8")).hexdigest(),
        })
        if status in {"missing", "unknown"}:
            missing.append(category)

    attempt = _strict_contract_object(
        parameters["attempt"],
        field="attempt",
        required=frozenset({"prior_attempt", "evidence_changed", "change_reference"}),
    )
    prior_attempt = attempt["prior_attempt"]
    evidence_changed = attempt["evidence_changed"]
    if not isinstance(prior_attempt, bool) or not isinstance(evidence_changed, bool):
        raise GripPreflightError("attempt prior_attempt and evidence_changed must be booleans")
    if evidence_changed and not prior_attempt:
        raise GripPreflightError(
            "attempt.evidence_changed must be false when prior_attempt is false"
        )
    change_reference = attempt["change_reference"]
    if evidence_changed:
        change_reference = _bounded_contract_text(
            change_reference, field="attempt.change_reference", maximum=1024
        )
        change_reference_sha256: str | None = hashlib.sha256(change_reference.encode("utf-8")).hexdigest()
    else:
        if change_reference is not None and change_reference != "":
            raise GripPreflightError("attempt.change_reference must be empty when evidence_changed is false")
        change_reference_sha256 = None
    unchanged_retry = prior_attempt and not evidence_changed
    ready = not missing and not unchanged_retry

    _check(receipt, "typed-gate-input", "pass", sha256_json({
        "gate_owner": gate_owner,
        "policy_boundary": policy_boundary,
        "target": target,
        "scope": scope,
        "expected_identity": expected_identity,
    }))
    _check(
        receipt,
        "required-evidence-visible",
        "pass" if not missing else "fail",
        "complete" if not missing else ",".join(missing),
    )
    _check(
        receipt,
        "changed-retry-bound",
        "pass" if not unchanged_retry else "fail",
        "first_attempt_or_evidence_changed" if not unchanged_retry else "unchanged_retry_rejected",
    )
    _check(receipt, "no-policy-authority", "pass", "evidence_preparation_only")

    blocked_reasons = [f"missing_evidence:{item}" for item in missing]
    if unchanged_retry:
        blocked_reasons.append("unchanged_retry_rejected")
    return {
        "schema_version": 1,
        "authority": "evidence_preparation_only",
        "decision": "evidence_prepared" if ready else "blocked",
        "ready_for_gate_evaluation": ready,
        "gate_owner": gate_owner,
        "policy_boundary": policy_boundary,
        "target_sha256": sha256_json(target),
        "scope_sha256": sha256_json(scope),
        "expected_identity_sha256": sha256_json(expected_identity),
        "evidence": normalized_evidence,
        "missing_evidence": missing,
        "attempt": {
            "prior_attempt": prior_attempt,
            "evidence_changed": evidence_changed,
            "change_reference_sha256": change_reference_sha256,
        },
        "blocked_reasons": blocked_reasons,
        "preparation_steps": [
            "run the narrow read-only preflight for each missing or unknown evidence category",
            "collect only named evidence references and bind them to the same target identity",
            "re-read leases, dirty state and running work immediately before any effect",
            "define a post-state readback bound to the same target identity",
        ],
        "retry_policy": "no unchanged retry; retry only after a named evidence or target-state change",
        "does_not_establish": [
            "execution_authority",
            "policy_bypass",
            "safe_mutation_retry",
            "root_cause",
            "gate_pass",
        ],
        "receipt_status": "passed" if ready else "blocked",
    }


def _optional_evidence_reference(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _bounded_contract_text(value, field=field, maximum=1024)


def _classify_convergence_signals(signals: set[str]) -> tuple[str, str]:
    if not signals:
        return "unknown", "no decisive evidence reference was supplied"
    if "resolved" in signals:
        if "superseded" in signals:
            return "conflicted", "both resolved and superseded terminal evidence are present"
        return "resolved", "resolution evidence closes earlier nonterminal signals"
    if "superseded" in signals:
        if "expected" in signals:
            return "conflicted", "expected and superseded evidence express different meanings"
        return "superseded", "a replacing issue, pull request or receipt is evidenced"
    if "expected" in signals and "blocked" in signals:
        return "conflicted", "expected-red and policy-block evidence are both present"
    if "expected" in signals:
        return "expected", "expected-red evidence explains any accompanying failure signal"
    if "blocked" in signals:
        return "blocked", "policy or environmental gate evidence explains any accompanying failure signal"
    return "defect", "failure evidence remains without a stronger explanatory or terminal signal"


def _run_convergence_state_classify(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    records = parameters["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= 100:
        raise GripPreflightError("records must contain between 1 and 100 objects")
    seen: set[str] = set()
    classified: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for index, raw in enumerate(records):
        record = _strict_contract_object(
            raw,
            field=f"records[{index}]",
            required=_CONVERGENCE_RECORD_KEYS,
        )
        record_id = _bounded_contract_text(record["record_id"], field=f"records[{index}].record_id", maximum=256)
        if record_id in seen:
            raise GripPreflightError(f"duplicate record_id: {record_id}")
        seen.add(record_id)
        observed_state = _bounded_contract_text(
            record["observed_state"], field=f"records[{index}].observed_state", maximum=128
        )
        signals: set[str] = set()
        evidence_digests: dict[str, str] = {}
        for field, signal in _CONVERGENCE_SIGNAL_FIELDS:
            reference = _optional_evidence_reference(record[field], field=f"records[{index}].{field}")
            if reference is not None:
                signals.add(signal)
                evidence_digests[field] = hashlib.sha256(reference.encode("utf-8")).hexdigest()
        classification, reason = _classify_convergence_signals(signals)
        counts[classification] += 1
        classified.append({
            "record_id": record_id,
            "observed_state": observed_state,
            "classification": classification,
            "reason": reason,
            "signals": sorted(signals),
            "evidence_sha256s": dict(sorted(evidence_digests.items())),
            "requires_decision": classification in {"unknown", "conflicted", "defect", "blocked"},
        })

    conflicted = counts["conflicted"]
    _check(receipt, "bounded-records", "pass", f"count={len(classified)}")
    _check(receipt, "evidence-only-classification", "pass", sha256_json(classified))
    _check(
        receipt,
        "contradictions-visible",
        "pass",
        f"conflicted={conflicted}",
    )
    _check(receipt, "no-history-mutation", "pass", "read_only_projection")
    return {
        "schema_version": 1,
        "authority": "read_only_evidence_projection",
        "records": classified,
        "counts": {key: counts.get(key, 0) for key in (
            "defect", "expected", "blocked", "superseded", "resolved", "unknown", "conflicted"
        )},
        "decision_required_count": sum(
            1 for item in classified if item["requires_decision"]
        ),
        "does_not_establish": [
            "task_completion",
            "history_rewrite",
            "automatic_closeout",
            "root_cause",
            "priority_change",
        ],
        "receipt_status": "passed",
    }


def _run_runtime_deploy_check(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    adapter = _runtime_deploy_adapter(parameters)
    expected_head = _runtime_deploy_expected_head(parameters)
    source_repository, source_lease_owner_id = _runtime_deploy_source_parameters(parameters)
    _check(receipt, "registered-adapter", "pass", adapter)
    _check(receipt, "expected-head-bound", "pass", expected_head)
    try:
        if adapter == RUNTIME_DEPLOY_ADAPTER_GRABOWSKI_SELF:
            preflight = (
                _runtime_deploy_self_preflight(expected_head)
                if source_repository is None
                else _runtime_deploy_self_preflight(
                    expected_head,
                    source_repository,
                    source_lease_owner_id,
                )
            )
        else:  # pragma: no cover - guarded by the adapter registry
            raise GripPreflightError(f"no runtime deploy preflight implementation for adapter: {adapter}")
    except (GripPreflightError, OSError, RuntimeError, ValueError) as exc:
        _check(receipt, "deploy-preflight-readonly", "fail", str(exc))
        return {
            "adapter": adapter,
            "expected_head": expected_head,
            "source_repository": source_repository,
            "source_lease_owner_id": source_lease_owner_id,
            "ready": False,
            "receipt_status": "blocked",
            "blocking_reasons": [str(exc)],
            "mutation_attempted": False,
            "non_claims": [
                "does not schedule or execute a deployment",
                "does not establish CI, review or production correctness",
            ],
        }
    _check(receipt, "deploy-preflight-readonly", "pass", "registered adapter preflight passed without mutation")
    return {
        **preflight,
        "receipt_status": "passed",
        "blocking_reasons": [],
        "mutation_attempted": False,
        "non_claims": [
            "does not schedule or execute a deployment",
            "does not establish CI, review or production correctness",
        ],
    }


def _short_branch_name(parameters: dict[str, Any], name: str) -> str:
    branch = _string_parameter(parameters, name)
    if branch.startswith("refs/"):
        raise GripPreflightError(f"{name} parameter must be a short branch name, not a ref")
    if ":" in branch or branch.startswith("-"):
        raise GripPreflightError(f"{name} parameter must be a safe short branch name")
    return branch



def _run_worktree_ensure(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec
    import grabowski_friction
    import grabowski_resources

    try:
        output = grabowski_worktree_ensure.ensure_worktree(
            parameters,
            runner,
            grabowski_resources.inspect_resource,
            record_friction=grabowski_friction.record_friction_event,
            resolve_friction=grabowski_friction.resolve_friction,
        )
    except grabowski_worktree_ensure.WorktreeEnsurePreflight as exc:
        _check(receipt, "worktree_ensure_preflight", "fail", str(exc))
        raise GripPreflightError(str(exc)) from exc
    except grabowski_worktree_ensure.WorktreeEnsureAction as exc:
        _check(receipt, "worktree_ensure_action", "fail", str(exc))
        raise GripActionError(str(exc)) from exc

    result_state = str(output.get("result_state") or "UNKNOWN")
    _check(
        receipt,
        "worktree_ensure_result",
        "pass" if result_state in {"CREATED", "ALREADY_CORRECT"} else "fail",
        result_state,
    )
    _check(
        receipt,
        "durable_receipt",
        "pass" if output.get("durable_receipt_sha256") else "fail",
        str(output.get("durable_receipt_path") or "missing"),
    )
    return output

def _lookup_merged_pr_for_checkout(
    repo: Path,
    *,
    branch: str,
    head: str,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    result = github_runner(
        repo,
        [
            "pr",
            "list",
            "--head",
            branch,
            "--state",
            "merged",
            "--limit",
            "20",
            "--json",
            "number,url,state,baseRefName,headRefName,headRefOid,mergedAt",
        ],
    )
    if int(result.get("returncode", 1)) != 0:
        return {
            "status": "unavailable",
            "reason": _truncate_reason(
                result.get("stderr") or result.get("stdout") or "merged PR lookup unavailable"
            ),
        }
    raw = str(result.get("stdout", "")).strip()
    try:
        parsed = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        return {"status": "unavailable", "reason": "merged PR lookup returned invalid JSON"}
    if not isinstance(parsed, list):
        return {"status": "unavailable", "reason": "merged PR lookup returned non-list JSON"}
    exact = [
        item
        for item in parsed
        if isinstance(item, dict)
        and item.get("state") == "MERGED"
        and item.get("headRefName") == branch
        and item.get("headRefOid") == head
        and isinstance(item.get("number"), int)
        and isinstance(item.get("url"), str)
        and isinstance(item.get("mergedAt"), str)
        and item.get("mergedAt")
    ]
    if len(exact) == 1:
        item = exact[0]
        return {
            "status": "exact_merged",
            "number": item["number"],
            "url": item["url"],
            "base_ref": item.get("baseRefName"),
            "head_ref": branch,
            "head_oid": head,
            "merged_at": item["mergedAt"],
        }
    if len(exact) > 1:
        return {
            "status": "ambiguous",
            "reason": "multiple merged PRs match the exact branch and head",
            "numbers": sorted(item["number"] for item in exact),
        }
    return {
        "status": "not_terminal",
        "reason": "no merged PR matches both the checkout branch and exact checkout head",
    }


def _worktree_hygiene_owner(item: dict[str, Any]) -> tuple[str | None, bool]:
    lifecycle = item.get("lifecycle") if isinstance(item.get("lifecycle"), dict) else {}
    owners = {
        record.get("owner_id")
        for key in ("retention", "binding", "latest_archive")
        for record in [lifecycle.get(key)]
        if isinstance(record, dict) and isinstance(record.get("owner_id"), str)
    }
    if len(owners) > 1:
        return None, True
    return (next(iter(owners)) if owners else None), False


def _run_worktree_hygiene_reconcile(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    del spec, runner
    import grabowski_checkouts

    repo = _repo_path(parameters)
    owner_id = _string_parameter(parameters, "owner_id")
    confirmation = _string_parameter(parameters, "confirmation")
    apply_cleanup = parameters.get("apply_cleanup")
    if not isinstance(apply_cleanup, bool):
        raise GripPreflightError("apply_cleanup must be boolean")
    if confirmation != WORKTREE_HYGIENE_CONFIRMATION:
        raise GripPreflightError(
            f"confirmation must be exactly {WORKTREE_HYGIENE_CONFIRMATION!r}"
        )
    max_actions = parameters.get("max_actions", WORKTREE_HYGIENE_MAX_ACTIONS)
    if (
        isinstance(max_actions, bool)
        or not isinstance(max_actions, int)
        or not 1 <= max_actions <= WORKTREE_HYGIENE_MAX_ACTIONS
    ):
        raise GripPreflightError(
            f"max_actions must be an integer between 1 and {WORKTREE_HYGIENE_MAX_ACTIONS}"
        )

    inventory = grabowski_checkouts.checkout_inventory(
        repo, include_processes=True, include_tasks=True, include_resources=True
    )
    candidates: list[dict[str, Any]] = []
    ownership_conflicts: list[str] = []
    foreign_owned_count = 0
    adopted_unowned_count = 0
    for item in inventory.get("worktrees", []):
        if not isinstance(item, dict):
            continue
        observed_owner, conflict = _worktree_hygiene_owner(item)
        if conflict:
            ownership_conflicts.append(str(item.get("path")))
            continue
        if observed_owner == owner_id:
            candidates.append({**item, "_hygiene_owner_mode": "owned"})
            continue
        if observed_owner is None and item.get("lifecycle_state") == "unclassified_clean":
            candidates.append({**item, "_hygiene_owner_mode": "adopt_unowned_after_terminal_proof"})
            continue
        if observed_owner is not None:
            foreign_owned_count += 1
    candidates.sort(key=lambda item: str(item.get("path")))

    archived: list[dict[str, Any]] = []
    cleanup_plans: list[dict[str, Any]] = []
    cleaned: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    github_queries = 0
    actions = 0
    now = int(time.time())

    for item in candidates:
        path = str(item.get("path"))
        state = str(item.get("lifecycle_state"))
        owner_mode = str(item.get("_hygiene_owner_mode"))
        head = item.get("head")
        branch = item.get("branch")
        lifecycle = item.get("lifecycle") if isinstance(item.get("lifecycle"), dict) else {}
        archive = lifecycle.get("latest_archive") if isinstance(lifecycle.get("latest_archive"), dict) else None

        if actions >= max_actions:
            skipped.append({"path": path, "reason": "max_actions_reached", "state": state})
            continue
        if item.get("is_main"):
            skipped.append({"path": path, "reason": "main_worktree", "state": state})
            continue
        if item.get("status", {}).get("dirty") is not False:
            skipped.append({"path": path, "reason": "dirty_or_unobservable", "state": state})
            continue
        if item.get("coordination", {}).get("blocking"):
            skipped.append({"path": path, "reason": "active_coordination", "state": state})
            continue

        if state == "cleanup_candidate" and archive is not None:
            dry = grabowski_checkouts.grabowski_checkout_cleanup(
                repo=str(repo),
                checkout_path=path,
                owner_id=owner_id,
                dry_run=True,
                archive_id=archive.get("archive_id"),
                expected_head=head,
                expected_branch=branch,
            )
            plan = dry["plan"]
            actions += 1
            cleanup_plans.append({
                "path": path,
                "plan_id": dry["dry_run_record"]["plan_id"],
                "plan_sha256": plan["plan_sha256"],
                "safe_to_apply": plan["safe_to_apply"],
            })
            if apply_cleanup and plan["safe_to_apply"] is True:
                if actions >= max_actions:
                    skipped.append({
                        "path": path,
                        "reason": "cleanup_apply_deferred_by_action_bound",
                        "state": state,
                    })
                    continue
                applied = grabowski_checkouts.grabowski_checkout_cleanup(
                    repo=str(repo),
                    checkout_path=path,
                    owner_id=owner_id,
                    dry_run=False,
                    plan_id=dry["dry_run_record"]["plan_id"],
                    expected_plan_sha256=plan["plan_sha256"],
                    confirmation="remove-linked-checkout",
                )
                cleaned.append({
                    "path": path,
                    "archive_id": plan["archive_id"],
                    "plan_id": dry["dry_run_record"]["plan_id"],
                    "plan_sha256": plan["plan_sha256"],
                    "applied_at_unix": applied["applied_at_unix"],
                })
                actions += 1
            continue

        if state not in {"retained", "unclassified_clean"}:
            skipped.append({"path": path, "reason": "state_not_archive_candidate", "state": state})
            continue
        if not isinstance(branch, str) or not branch or not isinstance(head, str):
            skipped.append({"path": path, "reason": "branch_or_head_unavailable", "state": state})
            continue
        if github_queries >= WORKTREE_HYGIENE_MAX_CANDIDATES:
            skipped.append({"path": path, "reason": "github_query_bound_reached", "state": state})
            continue
        github_queries += 1
        terminal = _lookup_merged_pr_for_checkout(
            repo, branch=branch, head=head, github_runner=github_runner
        )
        if terminal.get("status") != "exact_merged":
            skipped.append({
                "path": path,
                "reason": "terminality_not_proven",
                "state": state,
                "terminal_evidence": terminal,
            })
            continue
        if owner_mode == "adopt_unowned_after_terminal_proof":
            adopted_unowned_count += 1
        retention = lifecycle.get("retention") if isinstance(lifecycle.get("retention"), dict) else {}
        existing_until = retention.get("retention_until_unix")
        retention_until = max(
            now + grabowski_checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS + 3600,
            existing_until if isinstance(existing_until, int) else 0,
        )
        result = grabowski_checkouts.grabowski_checkout_archive(
            repo=str(repo),
            checkout_path=path,
            owner_id=owner_id,
            purpose=(
                "terminal worktree hygiene: exact merged PR "
                f"#{terminal['number']} head {head}"
            ),
            retention_until_unix=retention_until,
            expected_head=head,
            expected_branch=branch,
        )
        archived.append({
            "path": path,
            "archive_id": result["archive"]["archive_id"],
            "head": head,
            "branch": branch,
            "merged_pr": terminal,
            "ownership_mode": owner_mode,
            "cleanup_not_before_unix": (
                result["archive"]["created_at_unix"]
                + grabowski_checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS
            ),
        })
        actions += 1

    _check(
        receipt,
        "owner_bound",
        "pass",
        (
            f"candidates={len(candidates)} adopted_unowned={adopted_unowned_count} "
            f"foreign_owned={foreign_owned_count} conflicts={len(ownership_conflicts)}"
        ),
    )
    _check(receipt, "bounded_actions", "pass", f"actions={actions} max={max_actions}")
    _check(
        receipt,
        "fail_closed_skips",
        "pass",
        f"skipped={len(skipped)} ownership_conflicts={len(ownership_conflicts)}",
    )
    return {
        "owner_id": owner_id,
        "repository": str(repo),
        "apply_cleanup": apply_cleanup,
        "actions": actions,
        "github_queries": github_queries,
        "archived": archived,
        "cleanup_plans": cleanup_plans,
        "cleaned": cleaned,
        "skipped": skipped,
        "ownership_conflicts": sorted(ownership_conflicts),
        "adopted_unowned_count": adopted_unowned_count,
        "foreign_owned_count": foreign_owned_count,
        "inventory_sha256": inventory.get("inventory_sha256"),
        "does_not_establish": [
            "permission_to_delete_branches",
            "terminality_without_exact_merged_pr_or_existing_archive",
            "cleanup_before_24_hour_archive_grace",
            "authority_over_foreign_owners",
        ],
    }


def _run_post_merge_sync(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    target = _string_parameter(parameters, "target_branch")
    dry_run = parameters.get("dry_run", True)
    if dry_run is not True:
        _check(receipt, "dry_run_only", "fail", "post-merge-sync foundation grip is dry-run only")
        raise GripPreflightError("post-merge-sync is dry-run only in GRIP-001")
    _check(receipt, "dry_run_only", "pass", "no mutation will be executed")
    orientation = _run_repo_orient(spec, parameters, receipt, runner)
    commands = [
        ["git", "fetch", "origin"],
        ["git", "switch", target],
        ["git", "pull", "--ff-only"],
    ]
    return {
        "dry_run": True,
        "orientation": orientation,
        "target_branch": target,
        "planned_commands": commands,
    }


def _reject_branch_publish_configuration(
    repo: Path,
    remote: str,
    receipt: Receipt,
    runner: CommandRunner,
) -> None:
    escaped_remote = re.escape(remote)
    pattern = (
        rf"^(remote\.{escaped_remote}\.(push|pushurl|mirror|receivepack)"
        rf"|push\.(pushoption|followtags|gpgsign|recursesubmodules))$"
    )
    result = _git_optional(repo, runner, ["config", "--get-regexp", pattern])
    returncode = int(result.get("returncode", 1))
    stdout = str(result.get("stdout", "")).strip()
    if returncode == 1 and not stdout:
        _check(receipt, "push_configuration", "pass", "no semantic push configuration")
        return
    if returncode != 0:
        _check(receipt, "push_configuration", "fail", "git config query failed")
        raise GripPreflightError("branch-publish could not verify Git push configuration")
    if stdout:
        _check(receipt, "push_configuration", "fail", "semantic push configuration present")
        raise GripPreflightError(
            "branch-publish refuses repository or user configuration that can alter push semantics"
        )
    _check(receipt, "push_configuration", "pass", "no semantic push configuration")


def _remote_target_identity(url: str) -> tuple[str, str, str, bool] | None:
    if not url or any(character.isspace() or ord(character) < 32 for character in url):
        return None
    is_ssh = False
    ssh_user = ""
    if "://" in url:
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            return None
        if not host or parsed.password is not None or parsed.query or parsed.fragment:
            return None
        scheme = parsed.scheme.casefold()
        is_ssh = scheme in {"ssh", "git+ssh", "ssh+git"}
        if is_ssh:
            ssh_user = parsed.username or ""
        default_port = {
            "http": 80,
            "https": 443,
            "ssh": 22,
            "git+ssh": 22,
            "ssh+git": 22,
        }.get(scheme)
        host_identity = host.casefold()
        if port is not None and port != default_port:
            host_identity = f"{host_identity}:{port}"
        path = parsed.path.lstrip("/")
    else:
        match = re.fullmatch(r"(?:([^/@:]+)@)?([^/:]+):(.+)", url)
        if match is None:
            return None
        ssh_user = match.group(1) or ""
        host_identity = match.group(2).casefold()
        path = match.group(3).lstrip("/")
        is_ssh = True
    if host_identity.startswith("-") or ssh_user.startswith("-"):
        return None
    path = path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or path in {".", ".."}:
        return None
    return host_identity, path, ssh_user, is_ssh


def _validate_branch_publish_remote_target(
    repo: Path,
    remote: str,
    receipt: Receipt,
    runner: CommandRunner,
) -> None:
    configured = _git_optional(repo, runner, ["config", "--get-all", f"remote.{remote}.url"])
    configured_urls = (
        str(configured.get("stdout", "")).splitlines()
        if int(configured.get("returncode", 1)) == 0
        else []
    )
    if len(configured_urls) != 1:
        _check(receipt, "push_remote_target", "fail", "configured_url_count_not_one")
        raise GripPreflightError(
            "branch-publish requires exactly one configured URL for the selected remote"
        )
    effective = _git_optional(repo, runner, ["remote", "get-url", "--push", "--all", remote])
    effective_urls = (
        str(effective.get("stdout", "")).splitlines()
        if int(effective.get("returncode", 1)) == 0
        else []
    )
    if len(effective_urls) != 1:
        _check(receipt, "push_remote_target", "fail", "effective_url_count_not_one")
        raise GripPreflightError(
            "branch-publish requires exactly one effective URL for the selected remote"
        )
    configured_identity = _remote_target_identity(configured_urls[0])
    effective_identity = _remote_target_identity(effective_urls[0])
    if configured_identity is None or effective_identity is None:
        _check(receipt, "push_remote_target", "fail", "unsupported_network_target")
        raise GripPreflightError("branch-publish requires a supported network target")
    if not effective_identity[3]:
        _check(receipt, "push_remote_target", "fail", "effective_target_not_ssh")
        raise GripPreflightError("branch-publish requires one effective SSH remote target")
    same_repository = effective_identity[:2] == configured_identity[:2]
    configured_ssh_user = configured_identity[2] if configured_identity[3] else ""
    effective_ssh_user = effective_identity[2]
    same_user_contract = (
        effective_ssh_user == configured_ssh_user
        if configured_identity[3]
        else effective_ssh_user in {"", "git"}
    )
    if not same_repository or not same_user_contract:
        _check(receipt, "push_remote_target", "fail", "url_rewrite_changed_identity")
        raise GripPreflightError(
            "branch-publish refuses URL rewrite configuration that changes the push target"
        )
    detail = "identity_preserving_ssh_rewrite" if effective_urls[0] != configured_urls[0] else "single_ssh_target"
    _check(receipt, "push_remote_target", "pass", detail)


def _run_branch_publish(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    branch = _short_branch_name(parameters, "branch")
    expected_head = _sha_parameter(parameters, "expected_head")
    remote = parameters.get("remote", "origin")
    if not isinstance(remote, str) or not remote.strip():
        raise GripPreflightError("remote parameter must be a non-empty string")
    remote = remote.strip()
    if remote in {".", ".."} or not REMOTE_NAME_RE.fullmatch(remote):
        raise GripPreflightError("remote parameter must be a configured remote name")
    protected = parameters.get("protected_branches", ["main", "master"])
    if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
        raise GripPreflightError("protected_branches must be a list of strings")
    effective_protected = INTRINSIC_PROTECTED_BRANCHES | set(protected)
    if branch in effective_protected:
        _check(receipt, "protected_branch", "fail", f"branch={branch}")
        raise GripPreflightError("branch-publish refuses protected branches")
    _check(receipt, "protected_branch", "pass", f"branch={branch}")
    repo = _repo_path(parameters)
    _reject_branch_publish_configuration(repo, remote, receipt, runner)
    _validate_branch_publish_remote_target(repo, remote, receipt, runner)
    orientation = _run_repo_orient(spec, parameters, receipt, runner)
    if orientation["branch"] != branch:
        _check(
            receipt,
            "publish_branch",
            "fail",
            f"actual={orientation['branch']} target={branch}",
        )
        raise GripPreflightError(
            f"branch mismatch: actual={orientation['branch']} target={branch}"
        )
    _check(receipt, "publish_branch", "pass", branch)
    if orientation["head"] != expected_head:
        _check(
            receipt,
            "expected_head",
            "fail",
            f"actual={orientation['head']} expected={expected_head}",
        )
        raise GripPreflightError(
            f"expected_head mismatch: actual={orientation['head']} expected={expected_head}"
        )
    _check(receipt, "expected_head", "pass", expected_head)
    allow_dirty = bool(parameters.get("allow_dirty", False))
    if orientation["dirty"] and not allow_dirty:
        _check(receipt, "clean_worktree", "fail", "dirty worktree")
        raise GripPreflightError("branch-publish requires a clean worktree unless allow_dirty=true")
    _check(receipt, "clean_worktree", "pass" if not orientation["dirty"] else "warn", "clean" if not orientation["dirty"] else "allow_dirty=true")
    ref = f"refs/heads/{branch}"
    push = _git(
        repo=Path(orientation["root"]),
        runner=runner,
        argv=[
            "-c",
            f"remote.{remote}.mirror=false",
            "-c",
            f"remote.{remote}.receivepack=git-receive-pack",
            "-c",
            "push.followTags=false",
            "-c",
            "push.pushOption=",
            "-c",
            "push.gpgSign=false",
            "-c",
            "push.recurseSubmodules=no",
            "push",
            remote,
            f"HEAD:refs/heads/{branch}",
        ],
    )
    remote_result = _git(repo=Path(orientation["root"]), runner=runner, argv=["ls-remote", remote, ref])
    remote_line = str(remote_result.get("stdout", "")).splitlines()[0] if remote_result.get("stdout") else ""
    remote_head = remote_line.split()[0] if remote_line.split() else ""
    if remote_head != expected_head:
        _check(receipt, "remote_head", "fail", f"actual={remote_head} expected={expected_head}")
        raise GripActionError("remote head did not match expected_head after push")
    _check(receipt, "remote_head", "pass", remote_head)
    return {
        "branch": branch,
        "head": expected_head,
        "remote": remote,
        "ref": ref,
        "remote_head": remote_head,
        "push_stdout": push.get("stdout", ""),
        "push_stderr": push.get("stderr", ""),
    }


def _open_pr_from_stdout(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, list):
        raise GripActionError("unexpected PR lookup output")
    if len(value) > 1:
        raise GripActionError("multiple open PRs found for branch")
    if not value:
        return None
    item = value[0]
    if not isinstance(item, dict):
        raise GripActionError("unexpected PR lookup item")
    return item


def _run_pr_create_or_update(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    repo = _repo_path(parameters)
    branch = _short_branch_name(parameters, "branch")
    base = _short_branch_name(parameters, "base")
    title = _string_parameter(parameters, "title")
    expected_head = _sha_parameter(parameters, "expected_head")
    body_value = parameters.get("body", "")
    if body_value is None:
        body = ""
    elif isinstance(body_value, str):
        body = body_value
    else:
        raise GripPreflightError("body parameter must be a string when provided")
    requested_draft: bool | None = None
    if "draft" in parameters:
        requested_draft = _bool_parameter(parameters, "draft", False)
    protected = parameters.get("protected_branches", ["main", "master"])
    if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
        raise GripPreflightError("protected_branches must be a list of strings")
    if branch in set(protected):
        _check(receipt, "protected_head_branch", "fail", f"branch={branch}")
        raise GripPreflightError("pr-create-or-update refuses protected head branches")
    _check(receipt, "protected_head_branch", "pass", f"branch={branch}")
    orientation = _run_repo_orient(spec, parameters, receipt, runner)
    if orientation["branch"] != branch:
        _check(receipt, "head_branch", "fail", f"actual={orientation['branch']} expected={branch}")
        raise GripPreflightError(f"branch mismatch: actual={orientation['branch']} expected={branch}")
    _check(receipt, "head_branch", "pass", branch)
    if orientation["head"] != expected_head:
        _check(receipt, "expected_head", "fail", f"actual={orientation['head']} expected={expected_head}")
        raise GripPreflightError(f"expected_head mismatch: actual={orientation['head']} expected={expected_head}")
    _check(receipt, "expected_head", "pass", expected_head)
    allow_dirty = bool(parameters.get("allow_dirty", False))
    if orientation["dirty"] and not allow_dirty:
        _check(receipt, "clean_worktree", "fail", "dirty worktree")
        raise GripPreflightError("pr-create-or-update requires a clean worktree unless allow_dirty=true")
    _check(
        receipt,
        "clean_worktree",
        "pass" if not orientation["dirty"] else "warn",
        "clean" if not orientation["dirty"] else "allow_dirty=true",
    )
    remote = parameters.get("remote", "origin")
    if not isinstance(remote, str) or not remote.strip():
        raise GripPreflightError("remote parameter must be a non-empty string")
    remote = remote.strip()
    remote_ref = f"refs/heads/{branch}"
    remote_result = _git(repo, runner, ["ls-remote", remote, remote_ref])
    remote_line = str(remote_result.get("stdout", "")).splitlines()[0] if remote_result.get("stdout") else ""
    remote_head = remote_line.split()[0] if remote_line.split() else ""
    if remote_head != expected_head:
        _check(receipt, "remote_head", "fail", f"actual={remote_head} expected={expected_head}")
        raise GripPreflightError("remote branch does not match expected_head")
    _check(receipt, "remote_head", "pass", remote_head)
    lookup = _json_stdout(_github(
        repo,
        github_runner,
        [
            "pr",
            "list",
            "--head",
            branch,
            "--state",
            "open",
            "--json",
            "number,url,baseRefName,headRefName,headRefOid,isDraft",
        ],
    ))
    existing = _open_pr_from_stdout(lookup)
    if existing is not None:
        if existing.get("baseRefName") != base:
            _check(receipt, "base_branch", "fail", f"actual={existing.get('baseRefName')} expected={base}")
            raise GripPreflightError("existing PR base does not match requested base")
        if existing.get("headRefOid") != expected_head:
            _check(receipt, "pr_head", "fail", f"actual={existing.get('headRefOid')} expected={expected_head}")
            raise GripPreflightError("existing PR head does not match expected_head")
        existing_draft = existing.get("isDraft")
        if not isinstance(existing_draft, bool):
            _check(receipt, "existing_pr_draft_state", "fail", f"actual={existing_draft!r}")
            raise GripActionError("existing PR draft state is unavailable")
        _check(receipt, "existing_pr_draft_state", "pass", f"draft={existing_draft}")
        draft = existing_draft if requested_draft is None else requested_draft
        _check(receipt, "existing_pr", "pass", str(existing.get("number")))
        edit_args = ["pr", "edit", str(existing["number"]), "--title", title]
        if body:
            edit_args.extend(["--body", body])
        _github(repo, github_runner, edit_args)
        if requested_draft is None:
            _check(receipt, "pr_draft_transition", "skip", f"request omitted; preserved draft={draft}")
        elif existing_draft != draft:
            ready_args = ["pr", "ready", str(existing["number"])]
            if draft:
                ready_args.append("--undo")
            _github(repo, github_runner, ready_args)
            _check(receipt, "pr_draft_transition", "pass", f"draft={draft}")
        else:
            _check(receipt, "pr_draft_transition", "skip", f"already draft={draft}")
        action = "updated"
        view_target = str(existing["number"])
    else:
        _check(receipt, "existing_pr", "skip", "no open PR for branch")
        draft = False if requested_draft is None else requested_draft
        create_args = [
            "pr",
            "create",
            "--base",
            base,
            "--head",
            branch,
            "--title",
            title,
            "--body",
            body,
        ]
        if draft:
            create_args.append("--draft")
        _github(repo, github_runner, create_args)
        _check(receipt, "pr_draft_transition", "skip", f"created draft={draft}")
        action = "created"
        view_target = branch
    viewed = _json_stdout(_github(
        repo,
        github_runner,
        [
            "pr",
            "view",
            view_target,
            "--json",
            "number,url,state,baseRefName,headRefName,headRefOid,isDraft,mergeable",
        ],
    ))
    if not isinstance(viewed, dict):
        raise GripActionError("unexpected PR view output")
    if viewed.get("baseRefName") != base or viewed.get("headRefName") != branch or viewed.get("headRefOid") != expected_head:
        _check(receipt, "pr_verify", "fail", json.dumps(viewed, sort_keys=True))
        raise GripActionError("PR verification did not match requested branch/base/head")
    _check(receipt, "pr_verify", "pass", str(viewed.get("number")))
    viewed_draft = viewed.get("isDraft")
    if not isinstance(viewed_draft, bool):
        _check(receipt, "pr_draft_state", "fail", f"actual={viewed_draft!r}")
        raise GripActionError("PR draft state is unavailable during verification")
    if viewed_draft is not draft:
        _check(receipt, "pr_draft_state", "fail", f"actual={viewed_draft!r} expected={draft}")
        raise GripActionError("PR draft verification did not match requested state")
    _check(receipt, "pr_draft_state", "pass", f"draft={draft}")
    return {
        "action": action,
        "pr": viewed,
        "branch": branch,
        "base": base,
        "head": expected_head,
        "draft": draft,
        "draft_requested": requested_draft,
    }


def _github_repo_from_remote_url(value: str) -> str | None:
    text = value.strip()
    if text.endswith(".git"):
        text = text[:-4]
    if text.startswith("git@github.com:"):
        path = text.removeprefix("git@github.com:")
    else:
        marker = "github.com/"
        if marker not in text:
            return None
        path = text.split(marker, 1)[1]
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts[:2]):
        return None
    return f"{parts[0]}/{parts[1]}"


def _scout_bool(parameters: dict[str, Any], name: str, default: bool = False) -> bool:
    value = parameters.get(name, default)
    if not isinstance(value, bool):
        raise GripPreflightError(f"{name} must be a boolean when provided")
    return value


def _scout_string_list(parameters: dict[str, Any], name: str) -> list[str]:
    value = parameters.get(name, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise GripPreflightError(f"{name} must be a list of non-empty strings when provided")
    return [item.strip() for item in value]


def _scout_change(category: str, summary: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"category": category, "summary": summary, "details": details}


def _scout_pr_changes(pr_items: Any, *, branch: str, head: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if not isinstance(pr_items, list):
        return changes
    for item in pr_items:
        if not isinstance(item, dict):
            continue
        number = item.get("number")
        title = item.get("title")
        pr_branch = item.get("headRefName")
        pr_head = item.get("headRefOid")
        merge_state = item.get("mergeStateStatus")
        if item.get("isDraft") is True:
            changes.append(_scout_change("pr_drift", "open PR is still draft", {"number": number, "title": title}))
        if isinstance(merge_state, str) and merge_state not in {"CLEAN", "UNKNOWN", ""}:
            changes.append(_scout_change("pr_drift", "open PR merge state changed", {"number": number, "merge_state": merge_state}))
        if pr_branch == branch and isinstance(pr_head, str) and pr_head and pr_head != head:
            changes.append(_scout_change("pr_drift", "local branch head differs from open PR head", {"number": number, "local_head": head, "pr_head": pr_head}))
    return changes


def _run_scout(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    if _scout_bool(parameters, "disabled", False):
        _check(receipt, "disable-switch", "pass", "scout disabled by parameter")
        return {"enabled": False, "changes": [], "change_count": 0, "non_claims": ["disabled scout performs no observation"]}

    repo = _repo_path(parameters)
    if not repo.exists() or not repo.is_dir():
        raise GripPreflightError(f"repo does not exist: {repo}")
    _check(receipt, "disable-switch", "pass", "scout enabled")
    _check(receipt, "no-mutation", "pass", "uses read-only git and gh observations only")

    _git(repo, runner, ["rev-parse", "--show-toplevel"])
    branch = _git(repo, runner, ["rev-parse", "--abbrev-ref", "HEAD"])["stdout"]
    head = _git(repo, runner, ["rev-parse", "HEAD"])["stdout"]
    origin_main_result = _git_optional(repo, runner, ["rev-parse", "origin/main"])
    origin_main = str(origin_main_result.get("stdout", "")).strip() if int(origin_main_result.get("returncode", 1)) == 0 else ""
    changes: list[dict[str, Any]] = []

    runtime_head = parameters.get("runtime_head")
    if runtime_head is not None:
        if not isinstance(runtime_head, str) or not re.fullmatch(r"[0-9a-f]{40,64}", runtime_head):
            raise GripPreflightError("runtime_head must be a 40-64 character lowercase hex string when provided")
        if origin_main and runtime_head != origin_main:
            changes.append(_scout_change("runtime_main_drift", "runtime head differs from origin/main", {"runtime_head": runtime_head, "origin_main": origin_main}))

    upstream = _git_optional(repo, runner, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    if int(upstream.get("returncode", 1)) == 0:
        upstream_name = str(upstream.get("stdout", "")).strip()
        counts = _git_optional(repo, runner, ["rev-list", "--left-right", "--count", f"{upstream_name}...HEAD"])
        if int(counts.get("returncode", 1)) == 0:
            parts = str(counts.get("stdout", "")).split()
            if len(parts) == 2 and all(part.isdigit() for part in parts):
                behind, ahead = (int(parts[0]), int(parts[1]))
                if ahead > 0:
                    changes.append(_scout_change("unpushed_branch", "local branch has commits not present upstream", {"branch": branch, "upstream": upstream_name, "ahead": ahead, "behind": behind}))

    remote = _git_optional(repo, runner, ["remote", "get-url", "origin"])
    github_repo = parameters.get("github_repo")
    if github_repo is None and int(remote.get("returncode", 1)) == 0:
        github_repo = _github_repo_from_remote_url(str(remote.get("stdout", "")))
    if github_repo is not None:
        if not isinstance(github_repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", github_repo):
            raise GripPreflightError("github_repo must have owner/repo form when provided")
        pr_result = _github(repo, github_runner, ["pr", "list", "--repo", github_repo, "--state", "open", "--json", "number,title,headRefName,headRefOid,isDraft,mergeStateStatus,updatedAt"])
        changes.extend(_scout_pr_changes(_json_stdout(pr_result), branch=branch, head=head))

    for raw_path in _scout_string_list(parameters, "receipt_paths"):
        candidate = Path(raw_path)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise GripPreflightError("receipt_paths entries must be relative paths inside the repository")
        if not (repo / candidate).is_file():
            changes.append(_scout_change("missing_receipt", "expected receipt file is missing", {"path": candidate.as_posix()}))

    _check(receipt, "only-changes", "pass", f"changes={len(changes)}")
    _check(receipt, "pr-and-runtime-drift", "pass", "scout evaluated PR, runtime, branch and receipt signals")
    return {
        "enabled": True,
        "change_count": len(changes),
        "changes": changes,
        "non_claims": [
            "does not mutate repositories",
            "does not refresh runtime state",
            "does not close or merge pull requests",
            "does not create receipts",
        ],
    }



def _mechanic_bool(parameters: dict[str, Any], name: str, default: bool = False) -> bool:
    value = parameters.get(name, default)
    if not isinstance(value, bool):
        raise GripPreflightError(f"{name} must be a boolean when provided")
    return value


def _relative_receipt_path(value: Any, *, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GripPreflightError(f"{context}.receipt_path must be a non-empty relative path")
    candidate = Path(value.strip())
    if candidate.is_absolute() or ".." in candidate.parts:
        raise GripPreflightError(f"{context}.receipt_path must stay inside the repository")
    if ".git" in candidate.parts:
        raise GripPreflightError(f"{context}.receipt_path must not target .git")
    if not candidate.parts or candidate.parts[0] != "receipts":
        raise GripPreflightError(f"{context}.receipt_path must stay under receipts/")
    return candidate.as_posix()


def _bound_mapping(value: Any, *, context: str, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise GripPreflightError(f"{context}.{name} must be a non-empty object")
    return dict(value)


def _normal_action_name(item: dict[str, Any], *, index: int) -> str:
    raw = item.get("action")
    if not isinstance(raw, str) or not raw.strip():
        raise GripPreflightError(f"actions[{index}].action must be a non-empty string")
    action_name = raw.strip()
    alias = item.get("grip")
    if alias is not None:
        if not isinstance(alias, str) or not alias.strip():
            raise GripPreflightError(f"actions[{index}].grip alias must be a non-empty string when provided")
        if alias.strip() != action_name:
            raise GripPreflightError(f"actions[{index}].grip alias must match action")
    return action_name


def _validate_mechanic_target_matches_parameters(
    action_name: str,
    parameters: dict[str, Any],
    target: dict[str, Any],
    *,
    index: int,
) -> None:
    if action_name == "branch-publish":
        branch = parameters.get("branch")
        if target.get("branch") != branch:
            raise GripPreflightError(f"actions[{index}].target.branch must match parameters.branch")
        remote = target.get("remote")
        if remote is not None and remote != "origin":
            raise GripPreflightError(f"actions[{index}].target.remote must be origin for branch-publish")
    if action_name == "pr-create-or-update":
        for key in ("base", "head", "branch"):
            if key in target and key in parameters and target.get(key) != parameters.get(key):
                raise GripPreflightError(f"actions[{index}].target.{key} must match parameters.{key}")
    if action_name == "runtime-deploy-check":
        adapter = _runtime_deploy_adapter(parameters)
        expected_head = _runtime_deploy_expected_head(parameters)
        if target.get("adapter") != adapter:
            raise GripPreflightError(f"actions[{index}].target.adapter must match parameters.adapter")
        if target.get("expected_head") != expected_head:
            raise GripPreflightError(f"actions[{index}].target.expected_head must match parameters.expected_head")
        source_repository, source_lease_owner_id = _runtime_deploy_source_parameters(parameters)
        if target.get("source_repository") != source_repository:
            raise GripPreflightError(
                f"actions[{index}].target.source_repository must match parameters.source_repository"
            )
        if target.get("source_lease_owner_id") != source_lease_owner_id:
            raise GripPreflightError(
                f"actions[{index}].target.source_lease_owner_id must match parameters.source_lease_owner_id"
            )

        def one_concrete_alias(keys: tuple[str, ...], label: str) -> tuple[str, str]:
            selected: list[tuple[str, str]] = []
            for key in keys:
                value = target.get(key)
                if value is None:
                    continue
                if not isinstance(value, str) or not value.strip():
                    raise GripPreflightError(
                        f"actions[{index}].target.{key} must be a non-empty string when provided"
                    )
                selected.append((key, value.strip()))
            if len(selected) != 1:
                names = " or ".join(keys)
                raise GripPreflightError(
                    f"actions[{index}].target requires exactly one concrete {names} for {label}"
                )
            return selected[0]

        origin_key, origin_value = one_concrete_alias(("repo", "service"), "runtime-deploy-check")
        runtime_key, runtime_value = one_concrete_alias(
            ("environment", "runtime_target"), "runtime-deploy-check"
        )
        expected_origin = (
            RUNTIME_DEPLOY_GRABOWSKI_REPO
            if origin_key == "repo"
            else RUNTIME_DEPLOY_GRABOWSKI_SERVICE
        )
        if origin_value != expected_origin:
            raise GripPreflightError(
                f"actions[{index}].target.{origin_key} does not match the registered {adapter} adapter"
            )
        if runtime_value != RUNTIME_DEPLOY_GRABOWSKI_TARGET:
            raise GripPreflightError(
                f"actions[{index}].target.{runtime_key} does not match the registered {adapter} adapter"
            )
        for key in ("repo", "service", "environment", "runtime_target"):
            parameter_value = parameters.get(key)
            if parameter_value is not None and target.get(key) != parameter_value:
                raise GripPreflightError(f"actions[{index}].target.{key} must match parameters.{key}")


def _mechanic_actions(parameters: dict[str, Any]) -> list[dict[str, Any]]:
    value = parameters.get("actions")
    if not isinstance(value, list) or not value:
        raise GripPreflightError("actions must be a non-empty list")
    if len(value) > MECHANIC_MAX_ACTIONS:
        raise GripPreflightError(f"actions may contain at most {MECHANIC_MAX_ACTIONS} entries")
    actions: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise GripPreflightError(f"actions[{index}] must be an object")
        action_name = _normal_action_name(item, index=index)
        if action_name == "mechanic-loop" or action_name in GRIP_SURFACE_CAPTAIN_ONLY:
            raise GripPreflightError(f"actions[{index}].action is not dispatchable by mechanic-loop: {action_name}")
        if action_name in CAPTAIN_HIGH_IMPACT_ACTIONS:
            raise GripPreflightError(f"actions[{index}].action requires Captain: {action_name}")
        if action_name not in MECHANIC_NORMAL_GRIPS:
            raise GripPreflightError(f"actions[{index}].action is not a normal mechanic action: {action_name}")
        spec = GRIP_SPECS.get(action_name)
        if spec is None:
            raise GripPreflightError(f"actions[{index}].action is not dispatchable by mechanic-loop: {action_name}")
        parameters_value = item.get("parameters", {})
        if not isinstance(parameters_value, dict):
            raise GripPreflightError(f"actions[{index}].parameters must be an object when provided")
        allow_mutation = item.get("allow_mutation", False)
        if not isinstance(allow_mutation, bool):
            raise GripPreflightError(f"actions[{index}].allow_mutation must be a boolean when provided")
        target = _bound_mapping(item.get("target"), context=f"actions[{index}]", name="target")
        scope = _bound_mapping(item.get("scope"), context=f"actions[{index}]", name="scope")
        receipt_path = _relative_receipt_path(item.get("receipt_path"), context=f"actions[{index}]")
        risk_level = item.get("risk_level", "normal")
        if risk_level != "normal":
            raise GripPreflightError(f"actions[{index}].risk_level must be normal for mechanic actions")
        forbidden = scope.get("forbidden_effects")
        if forbidden is not None and (not isinstance(forbidden, list) or not all(isinstance(entry, str) for entry in forbidden)):
            raise GripPreflightError(f"actions[{index}].scope.forbidden_effects must be a list of strings when provided")
        _validate_mechanic_target_matches_parameters(action_name, parameters_value, target, index=index)
        actions.append(
            {
                "index": index,
                "action": action_name,
                "grip": action_name,
                "parameters": dict(parameters_value),
                "allow_mutation": allow_mutation,
                "target": target,
                "scope": scope,
                "receipt_path": receipt_path,
                "risk_level": risk_level,
                "effect": spec.effect,
                "envelope": {
                    "schema_version": 1,
                    "role": "mechanic",
                    "action": action_name,
                    "target": target,
                    "scope": scope,
                    "risk_level": "normal",
                    "requires_captain": False,
                    "receipt_required": True,
                    "receipt_path": receipt_path,
                    "created_at": utc_now(),
                },
            }
        )
    return actions


def _mechanic_record_sha256(record: dict[str, Any]) -> str:
    return sha256_json({key: value for key, value in record.items() if key != "receipt_sha256"})


def _mechanic_child_error_record(
    action: dict[str, Any],
    child: Any,
    *,
    error: str,
) -> dict[str, Any]:
    mechanic_receipt = {
        "schema_version": 1,
        "role": "mechanic",
        "action": action["action"],
        "target": action["target"],
        "scope": action["scope"],
        "status": "blocked",
        "child_receipt_error": error,
        "receipt_path": action["receipt_path"],
        "does_not_establish": [
            "merge_readiness",
            "runtime_correctness",
            "review_completeness",
            "deployment_safety",
        ],
    }
    mechanic_receipt["receipt_sha256"] = _mechanic_record_sha256(mechanic_receipt)
    return {
        "index": action["index"],
        "action": action["action"],
        "grip": action["grip"],
        "effect": action["effect"],
        "target": action["target"],
        "scope": action["scope"],
        "risk_level": action["risk_level"],
        "allow_mutation": action["allow_mutation"],
        "receipt_path": action["receipt_path"],
        "receipt_sha256": mechanic_receipt["receipt_sha256"],
        "child_receipt_sha256": None,
        "receipt_status": "blocked",
        "receipt_phase": None,
        "receipt_error": error,
        "envelope": action["envelope"],
        "mechanic_receipt": mechanic_receipt,
        "receipt": child.get("receipt") if isinstance(child, dict) else None,
        "output": child.get("output", {}) if isinstance(child, dict) else {},
    }


def _run_mechanic_loop(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    return grabowski_grip_orchestration.run_mechanic_loop(sys.modules[__name__], spec, parameters, receipt, runner, github_runner)


def _captain_wildcardish(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    stripped = value.strip().lower()
    return not stripped or stripped in CAPTAIN_WILDCARD_TOKENS or "*" in stripped or "?" in stripped


def _captain_target_string(target: dict[str, Any], key: str, *, index: int) -> str:
    value = target.get(key)
    if not isinstance(value, str) or not value.strip():
        raise GripPreflightError(f"actions[{index}].target.{key} must be a non-empty string")
    return value.strip()


def _captain_validate_repo_slug(value: str, *, context: str) -> None:
    if _captain_wildcardish(value) or CAPTAIN_REPO_SLUG_RE.fullmatch(value) is None:
        raise GripPreflightError(f"{context} must name exactly one owner/repo")
    owner, repo = value.split("/", 1)
    for segment, label in ((owner, "owner"), (repo, "repo")):
        if len(segment) > 100 or segment in {".", ".."} or set(segment) <= {"."}:
            raise GripPreflightError(f"{context}.{label} segment is not a bounded repository slug")


def _captain_concrete_string(target: dict[str, Any], key: str, *, index: int, action_name: str) -> str:
    value = _captain_target_string(target, key, index=index)
    if _captain_wildcardish(value):
        raise GripPreflightError(
            f"actions[{index}].target.{key} must name one concrete {action_name} target, not a wildcard"
        )
    return value


def _captain_base_branch(target: dict[str, Any], key: str, *, index: int) -> str:
    value = _captain_concrete_string(target, key, index=index, action_name="pr-merge")
    if not CAPTAIN_BASE_BRANCH_RE.fullmatch(value):
        raise GripPreflightError(f"actions[{index}].target.{key} must be a safe short branch name")
    if value.lower().startswith("refs/"):
        raise GripPreflightError(f"actions[{index}].target.{key} must be a short branch name, not a ref")
    if value.startswith("-") or ":" in value or ".." in value or "@{" in value:
        raise GripPreflightError(f"actions[{index}].target.{key} must be a safe short branch name")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        raise GripPreflightError(f"actions[{index}].target.{key} must not contain whitespace or control characters")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise GripPreflightError(f"actions[{index}].target.{key} must not contain empty or relative path segments")
    if any(segment.startswith(".") or segment.endswith(".") or segment.endswith(".lock") for segment in segments):
        raise GripPreflightError(f"actions[{index}].target.{key} must be a safe short branch name")
    if value.endswith("/"):
        raise GripPreflightError(f"actions[{index}].target.{key} must be a safe short branch name")
    return value


def _captain_optional_string(target: dict[str, Any], key: str, *, index: int, action_name: str) -> str | None:
    if key not in target or target.get(key) is None:
        return None
    return _captain_concrete_string(target, key, index=index, action_name=action_name)


def _captain_exactly_one_target_key(target: dict[str, Any], keys: tuple[str, ...], *, index: int, action_name: str) -> tuple[str, str]:
    present: list[tuple[str, str]] = []
    for key in keys:
        value = _captain_optional_string(target, key, index=index, action_name=action_name)
        if value is not None:
            present.append((key, value))
    if len(present) != 1:
        names = " or ".join(keys)
        raise GripPreflightError(f"actions[{index}].target requires exactly one concrete {names} for {action_name}")
    return present[0]


def _captain_runtime_deploy_binding_errors(
    *,
    adapter: Any,
    origin_key: str,
    origin_value: Any,
    runtime_value: Any,
) -> list[str]:
    errors: list[str] = []
    if adapter != RUNTIME_DEPLOY_ADAPTER_GRABOWSKI_SELF:
        errors.append("runtime_deploy_adapter_must_be_grabowski_self")
    if origin_key == "repo":
        if origin_value != RUNTIME_DEPLOY_GRABOWSKI_REPO:
            errors.append("runtime_deploy_repo_does_not_match_grabowski_self_adapter")
    elif origin_value != RUNTIME_DEPLOY_GRABOWSKI_SERVICE:
        errors.append("runtime_deploy_service_does_not_match_grabowski_self_adapter")
    if runtime_value != RUNTIME_DEPLOY_GRABOWSKI_TARGET:
        errors.append("runtime_deploy_target_does_not_match_local_grabowski_runtime")
    return errors


def _validate_captain_target(action_name: str, target: dict[str, Any], *, index: int) -> None:
    if action_name == "pr-merge":
        repo = _captain_target_string(target, "repo", index=index)
        _captain_validate_repo_slug(repo, context=f"actions[{index}].target.repo")
        pr = target.get("pr")
        if type(pr) is not int or pr <= 0:
            raise GripPreflightError(f"actions[{index}].target.pr must be a positive integer")
        _captain_base_branch(target, "base", index=index)
    elif action_name == "runtime-deploy":
        origin_key, runtime_origin = _captain_exactly_one_target_key(
            target, ("repo", "service"), index=index, action_name="runtime-deploy"
        )
        if origin_key == "repo":
            _captain_validate_repo_slug(runtime_origin, context=f"actions[{index}].target.repo")
        runtime_key, runtime_target = _captain_exactly_one_target_key(
            target, ("environment", "runtime_target"), index=index, action_name="runtime-deploy"
        )
        adapter = _captain_concrete_string(target, "adapter", index=index, action_name="runtime-deploy")
        if adapter not in RUNTIME_DEPLOY_ADAPTERS:
            raise GripPreflightError(
                f"actions[{index}].target.adapter is not registered; expected one of {sorted(RUNTIME_DEPLOY_ADAPTERS)}"
            )
        binding_errors = _captain_runtime_deploy_binding_errors(
            adapter=adapter,
            origin_key=origin_key,
            origin_value=runtime_origin,
            runtime_value=runtime_target,
        )
        source_repository = _captain_optional_string(
            target, "source_repository", index=index, action_name="runtime-deploy"
        )
        source_owner = _captain_optional_string(
            target, "source_lease_owner_id", index=index, action_name="runtime-deploy"
        )
        if (source_repository is None) != (source_owner is None):
            raise GripPreflightError(
                f"actions[{index}].target source_repository and source_lease_owner_id must be provided together"
            )
        if source_repository is not None and not Path(source_repository).expanduser().is_absolute():
            raise GripPreflightError(
                f"actions[{index}].target.source_repository must be an absolute path"
            )
        if source_owner is not None and re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", source_owner) is None:
            raise GripPreflightError(
                f"actions[{index}].target.source_lease_owner_id is invalid"
            )
        if binding_errors:
            raise GripPreflightError(
                f"actions[{index}].target is not bound to the registered {adapter} adapter: "
                + ", ".join(binding_errors)
            )
    elif action_name == "service-restart":
        _captain_concrete_string(target, "host", index=index, action_name="service-restart")
        _captain_concrete_string(target, "unit", index=index, action_name="service-restart")
    elif action_name == "fleet-mutation":
        _captain_concrete_string(target, "fleet_target", index=index, action_name="fleet-mutation")
        operation = _captain_concrete_string(target, "operation", index=index, action_name="fleet-mutation")
        if operation.strip().lower() in CAPTAIN_GENERIC_OPERATIONS:
            raise GripPreflightError(f"actions[{index}].target.operation must be an explicit operation, not a generic verb")
    elif action_name == "cleanup-apply":
        _captain_concrete_string(target, "cleanup_target", index=index, action_name="cleanup-apply")
        repo = _captain_optional_string(target, "repo", index=index, action_name="cleanup-apply")
        checkout_path = _captain_optional_string(target, "checkout_path", index=index, action_name="cleanup-apply")
        if repo is None and checkout_path is None:
            raise GripPreflightError(f"actions[{index}].target requires repo or checkout_path for cleanup-apply")
        if repo is not None:
            _captain_validate_repo_slug(repo, context=f"actions[{index}].target.repo")


def _captain_action_evidence_item(
    name: str,
    *,
    required_fields: tuple[str, ...],
    binds: tuple[str, ...],
    purpose: str,
    required_values: dict[str, Any] | None = None,
    required_one_of: tuple[tuple[str, ...], ...] = (),
    required_parameters: tuple[str, ...] = (),
    parameter_bindings: dict[str, Any] | None = None,
    required_when: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "name": name,
        "required_fields": list(required_fields),
        "binds": list(binds),
        "purpose": purpose,
    }
    if required_values:
        item["required_values"] = dict(required_values)
    if required_one_of:
        item["required_one_of"] = [list(group) for group in required_one_of]
    if required_parameters:
        item["required_parameters"] = list(required_parameters)
    if parameter_bindings:
        item["parameter_bindings"] = dict(parameter_bindings)
    if required_when is not None:
        item["required_when"] = required_when
    return item


def _captain_action_evidence_schema(action_name: str, target: dict[str, Any], risk: dict[str, Any]) -> dict[str, Any]:
    common_bindings = ("actions_sha256", "action_sha256", "target_sha256")
    common_evidence = [
        _captain_action_evidence_item(
            "status_projection",
            required_fields=("schema_version", "source", "healthy", "generated_at"),
            required_values={"healthy": True},
            required_one_of=(("receipt_ref",), ("run_id",), ("nonce",)),
            required_parameters=("status_projection_sha256",),
            parameter_bindings={
                "status_projection_sha256": {
                    "algorithm": "sha256",
                    "covers": "status_projection",
                },
            },
            binds=("status_projection_sha256", *common_bindings),
            purpose="observed-state projection evidence with replay metadata and a top-level hash binding; not runtime truth",
        ),
    ]
    schema: dict[str, Any] = {
        "schema_version": CAPTAIN_ACTION_EVIDENCE_SCHEMA_VERSION,
        "action": action_name,
        "target_binding": {},
        "required_evidence": common_evidence,
        "digest_bindings": list(common_bindings),
        "risk_binding": {
            "irreversibility": risk.get("irreversibility"),
            "requires_recovery_path": risk.get("irreversibility") == "reversible",
            "requires_irreversibility_record": risk.get("irreversibility") == "irreversible",
        },
        "does_not_establish": [
            "execution_authority",
            "deployment_safety",
            "service_restart_safety",
            "fleet_mutation_safety",
            "cleanup_safety",
        ],
    }
    if action_name == "pr-merge":
        schema["target_binding"] = {"repo": target.get("repo"), "pr": target.get("pr"), "base": target.get("base")}
        schema["head_binding"] = {"parameter": "expected_head", "required": True}
        schema["base_sha_binding"] = {"parameter": "expected_base_sha", "required": True}
        schema["diff_binding"] = {"parameter": "diff_sha256", "required": True}
        schema["required_evidence"].extend([
            _captain_action_evidence_item(
                "review_evidence",
                required_fields=(
                    "schema_version",
                    "kind",
                    "repo",
                    "pr",
                    "generated_at",
                    "head_sha",
                    "base_sha",
                    "diff_sha256",
                    "review_tier",
                    "gate_verdict",
                    "self_review_gate_valid",
                    "minimum_review_iterations",
                    "actual_review_iterations",
                    "all_findings_triaged",
                    "material_findings_remaining",
                    "tuning_signal",
                ),
                required_values={
                    "schema_version": 1,
                    "kind": "grabowski_self_review_audit",
                    "gate_verdict": "PASS",
                    "self_review_gate_valid": True,
                    "all_findings_triaged": True,
                    "tuning_signal": "observe",
                },
                binds=("expected_head", "expected_base_sha", "diff_sha256", *common_bindings),
                purpose="diff-bound self-review audit for the exact PR head and base commit, including risk-scaled review depth",
            ),
            _captain_action_evidence_item(
                "ci_evidence",
                required_fields=("state", "head_sha", "source"),
                required_values={"state": "passed"},
                binds=("expected_head", *common_bindings),
                purpose="green CI evidence for the exact PR head",
            ),
            _captain_action_evidence_item(
                "human_authorization",
                required_fields=("authorized_by",),
                required_one_of=(("statement",), ("reference",)),
                binds=common_bindings,
                purpose="explicit human authorization evidence when trusted-owner autonomy does not apply",
                required_when="trusted_owner_autonomy_does_not_apply",
            ),
        ])
    elif action_name == "runtime-deploy":
        origin_key = "repo" if isinstance(target.get("repo"), str) and target.get("repo", "").strip() else "service"
        runtime_key = (
            "environment"
            if isinstance(target.get("environment"), str) and target.get("environment", "").strip()
            else "runtime_target"
        )
        schema["target_binding"] = {
            origin_key: target.get(origin_key),
            runtime_key: target.get(runtime_key),
        }
        if target.get("source_repository") is not None:
            schema["target_binding"].update({
                "source_repository": target.get("source_repository"),
                "source_lease_owner_id": target.get("source_lease_owner_id"),
            })
        schema["required_evidence"].extend([
            _captain_action_evidence_item(
                "deployment_boundary",
                required_fields=(origin_key, runtime_key, "deployment_scope"),
                binds=("target_sha256", "action_sha256"),
                purpose="bounded deployment target and environment evidence",
            ),
            _captain_action_evidence_item(
                "rollback_plan",
                required_fields=("strategy", "operator_or_receipt_ref"),
                binds=("target_sha256", "action_sha256"),
                purpose="rollback or recovery evidence before runtime mutation",
            ),
        ])
    elif action_name == "service-restart":
        schema["target_binding"] = {"host": target.get("host"), "unit": target.get("unit")}
        schema["required_evidence"].extend([
            _captain_action_evidence_item(
                "restart_budget",
                required_fields=("max_attempts", "window", "stop_condition"),
                binds=("target_sha256", "action_sha256"),
                purpose="bounded restart attempt budget",
            ),
            _captain_action_evidence_item(
                "recovery_path",
                required_fields=("recovery_path",),
                binds=("target_sha256", "action_sha256"),
                purpose="operator recovery path for the host/unit",
                required_when="risk.irreversibility == reversible",
            ),
        ])
    elif action_name == "fleet-mutation":
        schema["target_binding"] = {"fleet_target": target.get("fleet_target"), "operation": target.get("operation")}
        schema["required_evidence"].extend([
            _captain_action_evidence_item(
                "dry_run_or_projection",
                required_fields=("operation", "expected_delta", "affected_targets"),
                binds=("target_sha256", "action_sha256"),
                purpose="bounded projected fleet mutation evidence before effect",
            ),
            _captain_action_evidence_item(
                "recovery_or_irreversibility",
                required_fields=(),
                required_one_of=(("recovery_path",), ("irreversibility_record",)),
                binds=("target_sha256", "action_sha256"),
                purpose="explicit recovery or irreversible-risk evidence",
            ),
        ])
    elif action_name == "cleanup-apply":
        location_keys = tuple(
            key
            for key in ("repo", "checkout_path")
            if isinstance(target.get(key), str) and target.get(key, "").strip()
        )
        schema["target_binding"] = {
            "cleanup_target": target.get("cleanup_target"),
            **{key: target.get(key) for key in location_keys},
        }
        schema["required_evidence"].extend([
            _captain_action_evidence_item(
                "dry_run_or_projection",
                required_fields=("cleanup_target", "expected_deletions_or_changes", *location_keys),
                binds=("target_sha256", "action_sha256"),
                purpose="bounded cleanup projection before destructive apply",
            ),
            _captain_action_evidence_item(
                "recovery_or_irreversibility",
                required_fields=(),
                required_one_of=(("recovery_path",), ("irreversibility_record",)),
                binds=("target_sha256", "action_sha256"),
                purpose="explicit recovery or irreversible-risk evidence",
            ),
        ])
    return schema


def _non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(entry, str) and entry.strip() for entry in value)


def _captain_scope_findings(scope: dict[str, Any], *, index: int) -> list[str]:
    findings: list[str] = []
    for key in ("allowed_effects", "forbidden_effects"):
        value = scope.get(key)
        if value is not None and not _non_empty_string_list(value):
            findings.append(f"actions[{index}].scope.{key} must be a non-empty list of non-empty strings")
    boundaries = scope.get("boundaries")
    if boundaries is not None:
        if isinstance(boundaries, str):
            if not boundaries.strip():
                findings.append(f"actions[{index}].scope.boundaries must not be blank")
        elif isinstance(boundaries, (dict, list)):
            if not boundaries:
                findings.append(f"actions[{index}].scope.boundaries must not be empty")
        else:
            findings.append(f"actions[{index}].scope.boundaries must be a non-empty string, object or list")
    max_targets = scope.get("max_targets")
    if max_targets is not None and (isinstance(max_targets, bool) or not isinstance(max_targets, int) or max_targets < 1):
        findings.append(f"actions[{index}].scope.max_targets must be a positive integer")
    if not any(key in scope for key in CAPTAIN_SCOPE_RECOMMENDED_KEYS):
        findings.append(f"actions[{index}].scope declares none of {', '.join(CAPTAIN_SCOPE_RECOMMENDED_KEYS)}")
    has_effect_boundary = _non_empty_string_list(scope.get("allowed_effects")) or _non_empty_string_list(scope.get("forbidden_effects"))
    has_named_boundary = False
    if isinstance(boundaries, str):
        has_named_boundary = bool(boundaries.strip())
    elif isinstance(boundaries, (dict, list)):
        has_named_boundary = bool(boundaries)
    if not (has_effect_boundary or has_named_boundary):
        findings.append(
            f"actions[{index}].scope must contain allowed_effects, forbidden_effects or boundaries; max_targets alone is not enough"
        )
    return findings


def _captain_action_index(action: dict[str, Any]) -> int:
    index = action.get("index")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        envelope = action.get("envelope")
        if isinstance(envelope, dict):
            envelope_index = envelope.get("index")
            if not isinstance(envelope_index, bool) and isinstance(envelope_index, int) and envelope_index >= 0:
                return envelope_index
        raise GripPreflightError("Captain action record is missing a non-negative integer index")
    return index


def _captain_action_digest_material(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "index": _captain_action_index(action),
        "role": "captain",
        "action": action["action"],
        "high_impact": True,
        "target": action["target"],
        "scope": action["scope"],
        "target_change_required": action["target_change_required"],
        "target_change": action["target_change"],
        "risk": action["risk"],
        "irreversibility_record": action["irreversibility_record"],
        "receipt_path": action["receipt_path"],
    }


def _captain_action_sha256(action: dict[str, Any]) -> str:
    return sha256_json(_captain_action_digest_material(action))


def _captain_target_sha256(target: dict[str, Any]) -> str:
    return sha256_json(target)


def _captain_actions_sha256(actions: list[dict[str, Any]]) -> str:
    return sha256_json([
        {
            "index": _captain_action_index(action),
            "action": action["action"],
            "action_sha256": action["action_sha256"],
            "target_sha256": action["target_sha256"],
        }
        for action in actions
    ])


def _captain_attach_action_digests(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for action in actions:
        action["target_sha256"] = _captain_target_sha256(action["target"])
        action["action_sha256"] = _captain_action_sha256(action)
        action["envelope"]["target_sha256"] = action["target_sha256"]
        action["envelope"]["action_sha256"] = action["action_sha256"]
    actions_sha256 = _captain_actions_sha256(actions)
    for action in actions:
        action["actions_sha256"] = actions_sha256
        action["envelope"]["actions_sha256"] = actions_sha256
    return actions


def _captain_mapping_or_empty(item: dict[str, Any], key: str) -> dict[str, Any]:
    value = item.get(key)
    return value if isinstance(value, dict) else {}

def _captain_actions(parameters: dict[str, Any], *, gate_native_validation: bool = False) -> list[dict[str, Any]]:
    value = parameters.get("actions")
    if not isinstance(value, list) or not value:
        raise GripPreflightError("actions must be a non-empty list")
    if len(value) > CAPTAIN_MAX_ACTIONS:
        raise GripPreflightError(f"actions may contain at most {CAPTAIN_MAX_ACTIONS} entries")
    actions: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise GripPreflightError(f"actions[{index}] must be an object")
        action_name = _normal_action_name(item, index=index)
        if action_name == "mechanic-loop" or action_name in GRIP_SURFACE_CAPTAIN_ONLY:
            raise GripPreflightError(f"actions[{index}].action must not nest orchestration grips: {action_name}")
        if action_name in MECHANIC_NORMAL_GRIPS:
            raise GripPreflightError(f"actions[{index}].action is a normal mechanic action, not a Captain high-impact action: {action_name}")
        if action_name not in CAPTAIN_HIGH_IMPACT_ACTIONS:
            raise GripPreflightError(f"actions[{index}].action must be an explicit high-impact Captain action")
        if item.get("high_impact") is not True:
            raise GripPreflightError(f"actions[{index}].high_impact must be true")
        role = item.get("role")
        if role is not None and role != "captain":
            raise GripPreflightError(f"actions[{index}].role must be captain when provided")
        target_findings: list[str] = []
        scope_findings: list[str] = []
        risk_findings: list[str] = []
        target_change_findings: list[str] = []
        try:
            target = _bound_mapping(item.get("target"), context=f"actions[{index}]", name="target")
            _validate_captain_target(action_name, target, index=index)
        except GripPreflightError as exc:
            if not gate_native_validation:
                raise
            target = _captain_mapping_or_empty(item, "target")
            target_findings.append(str(exc))
        try:
            scope = _bound_mapping(item.get("scope"), context=f"actions[{index}]", name="scope")
            scope_findings = _captain_scope_findings(scope, index=index)
        except GripPreflightError as exc:
            if not gate_native_validation:
                raise
            scope = _captain_mapping_or_empty(item, "scope")
            scope_findings.append(str(exc))
        try:
            risk = _bound_mapping(item.get("risk"), context=f"actions[{index}]", name="risk")
        except GripPreflightError as exc:
            if not gate_native_validation:
                raise
            risk = _captain_mapping_or_empty(item, "risk")
            risk_findings.append(str(exc))
        recovery_path = risk.get("recovery_path")
        irreversibility = risk.get("irreversibility")
        if irreversibility is not None and irreversibility not in {"reversible", "irreversible"}:
            risk_findings.append(f"actions[{index}].risk.irreversibility must be reversible or irreversible")
        has_recovery_path = isinstance(recovery_path, str) and bool(recovery_path.strip())
        if irreversibility == "reversible" and not has_recovery_path:
            risk_findings.append(f"actions[{index}].risk.recovery_path is required for reversible actions")
        irreversibility_record = item.get("irreversibility_record")
        if irreversibility == "irreversible" and (not isinstance(irreversibility_record, dict) or not irreversibility_record):
            risk_findings.append(f"actions[{index}].irreversibility_record is required for irreversible actions")
        if not has_recovery_path and irreversibility != "irreversible":
            risk_findings.append(f"actions[{index}].risk requires recovery_path or irreversible risk record")
        if risk_findings and not gate_native_validation:
            raise GripPreflightError(risk_findings[0])
        target_change_required = item.get("target_change_required", False)
        if not isinstance(target_change_required, bool):
            target_change_findings.append(f"actions[{index}].target_change_required must be a boolean when provided")
            target_change_required = False
        target_change = item.get("target_change")
        if target_change is not None:
            if not isinstance(target_change, dict):
                target_change_findings.append(f"actions[{index}].target_change must be an object or null")
                target_change = None
            elif not target_change:
                target_change_findings.append(f"actions[{index}].target_change must be a non-empty object when provided")
        if target_change_required and target_change is None:
            target_change_findings.append(f"actions[{index}].target_change record is required")
        if target_change_findings and not gate_native_validation:
            raise GripPreflightError(target_change_findings[0])
        receipt_path = _relative_receipt_path(item.get("receipt_path"), context=f"actions[{index}]")
        actions.append(
            {
                "index": index,
                "action": action_name,
                "high_impact": True,
                "role": "captain",
                "target": target,
                "scope": scope,
                "target_findings": target_findings,
                "scope_findings": scope_findings,
                "risk_findings": risk_findings,
                "target_change_findings": target_change_findings,
                "risk": risk,
                "recovery_path": risk.get("recovery_path"),
                "irreversibility": risk.get("irreversibility"),
                "requires_status_projection": True,
                "target_change_required": target_change_required,
                "target_change": target_change,
                "irreversibility_record": irreversibility_record,
                "evidence_schema": _captain_action_evidence_schema(action_name, target, risk),
                "receipt_path": receipt_path,
                "execution": "not-performed",
                "envelope": {
                    "schema_version": 1,
                    "index": index,
                    "role": "captain",
                    "action": action_name,
                    "high_impact": True,
                    "target": target,
                    "scope": scope,
                    "target_change_required": target_change_required,
                    "target_change": target_change,
                    "risk": risk,
                    "irreversibility_record": irreversibility_record,
                    "receipt_path": receipt_path,
                    "created_at": utc_now(),
                },
            }
        )
    return _captain_attach_action_digests(actions)


def _captain_gate(gate_id: str, status: str, reason: str, details: Any = None) -> dict[str, Any]:
    gate: dict[str, Any] = {"id": gate_id, "status": status, "reason": reason}
    if details is not None:
        gate["details"] = details
    return gate


def _captain_now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_captain_projection_generated_at(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _captain_status_projection_gate(parameters: dict[str, Any], actions: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    fresh = _mechanic_bool(parameters, "status_projection_fresh", False)
    projection = parameters.get("status_projection")
    source = parameters.get("status_projection_source")
    declared_sha = parameters.get("status_projection_sha256")
    info: dict[str, Any] = {
        "used": False,
        "fresh": fresh,
        "source": None,
        "source_allowlisted": False,
        "source_trusted": False,
        "allowlisted_sources": sorted(CAPTAIN_STATUS_PROJECTION_ALLOWLISTED_SOURCES),
        "sha256": None,
        "schema_version": None,
        "generated_at": None,
        "max_age_seconds": CAPTAIN_STATUS_PROJECTION_MAX_AGE_SECONDS,
        "clock_skew_tolerance_seconds": CAPTAIN_STATUS_PROJECTION_CLOCK_SKEW_TOLERANCE_SECONDS,
        "age_seconds": None,
        "projection_source": None,
        "replay_reference": None,
        "replay_reference_kind": None,
    }
    problems: list[str] = []
    if projection is None:
        problems.append("fresh_status_projection_unavailable")
    elif not isinstance(projection, dict) or not projection:
        problems.append("status_projection_not_a_non_empty_object")
    else:
        info["used"] = True
        if not isinstance(source, str) or not source.strip():
            problems.append("status_projection_source_missing")
        else:
            source_name = source.strip()
            info["source"] = source_name
            if source_name not in CAPTAIN_STATUS_PROJECTION_ALLOWLISTED_SOURCES:
                problems.append("status_projection_source_untrusted")
            else:
                info["source_allowlisted"] = True
                info["source_trusted"] = True
        schema_version = projection.get("schema_version")
        info["schema_version"] = schema_version
        if schema_version != CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION:
            problems.append("status_projection_schema_version_invalid")
        projection_source = projection.get("source")
        if not isinstance(projection_source, str) or not projection_source.strip():
            problems.append("status_projection_source_missing_in_projection")
        else:
            projection_source_name = projection_source.strip()
            info["projection_source"] = projection_source_name
            if info["source"] is not None and projection_source_name != info["source"]:
                problems.append("status_projection_source_mismatch")
        healthy = projection.get("healthy")
        if "healthy" not in projection:
            problems.append("status_projection_healthy_missing")
        elif not isinstance(healthy, bool):
            problems.append("status_projection_healthy_invalid")
        elif healthy is not True:
            problems.append("status_projection_unhealthy")
        generated_at = projection.get("generated_at")
        parsed_generated_at = _parse_captain_projection_generated_at(generated_at)
        if parsed_generated_at is None:
            problems.append("status_projection_generated_at_invalid")
        else:
            info["generated_at"] = parsed_generated_at.isoformat().replace("+00:00", "Z")
            age_seconds = (_captain_now_utc() - parsed_generated_at).total_seconds()
            info["age_seconds"] = int(age_seconds)
            if age_seconds < -CAPTAIN_STATUS_PROJECTION_CLOCK_SKEW_TOLERANCE_SECONDS:
                problems.append("status_projection_generated_at_in_future")
            elif age_seconds > CAPTAIN_STATUS_PROJECTION_MAX_AGE_SECONDS:
                problems.append("status_projection_stale_by_generated_at")
        replay_reference_kind = None
        replay_reference = None
        for key in ("receipt_ref", "run_id", "nonce"):
            value = projection.get(key)
            if isinstance(value, str) and value.strip():
                replay_reference_kind = key
                replay_reference = value.strip()
                break
        if replay_reference is None:
            problems.append("status_projection_replay_reference_missing")
        else:
            info["replay_reference"] = replay_reference
            info["replay_reference_kind"] = replay_reference_kind
        if declared_sha is None:
            problems.append("status_projection_sha256_missing")
        elif not _is_sha256_hex(declared_sha):
            problems.append("status_projection_sha256_invalid")
        elif declared_sha != sha256_json(projection):
            problems.append("status_projection_sha256_mismatch")
        else:
            info["sha256"] = declared_sha
        problems.extend(_captain_evidence_digest_binding_errors(projection, evidence_name="status_projection", actions=actions))
        if not fresh:
            problems.append("fresh_status_projection_unavailable")
    if problems:
        return (
            _captain_gate(
                "status-projection-fresh",
                "blocked",
                "status projection is missing, stale, unhealthy, not from an allowlisted source label, missing replay reference metadata or not hash-bound; projection is required evidence",
                problems,
            ),
            info,
        )
    return (
        _captain_gate(
            "status-projection-fresh",
            "pass",
            "fresh status projection with allowlisted source label, schema, replay reference metadata and matching sha256; evidence only, not runtime truth",
        ),
        info,
    )


def _captain_evidence_digest_binding_errors(
    evidence: dict[str, Any],
    *,
    evidence_name: str,
    actions: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    expected_actions_sha256 = _captain_actions_sha256(actions)
    valid_action_sha256s = {str(action["action_sha256"]) for action in actions}
    valid_target_sha256s = {str(action["target_sha256"]) for action in actions}
    declared_actions = evidence.get("actions_sha256")
    if declared_actions is not None:
        if not _is_sha256_hex(declared_actions):
            errors.append(f"{evidence_name}.actions_sha256 must be a SHA-256 hex digest")
        elif declared_actions != expected_actions_sha256:
            errors.append(f"{evidence_name}.actions_sha256 mismatch")
    declared_action = evidence.get("action_sha256")
    if declared_action is not None:
        if not _is_sha256_hex(declared_action):
            errors.append(f"{evidence_name}.action_sha256 must be a SHA-256 hex digest")
        elif declared_action not in valid_action_sha256s:
            errors.append(f"{evidence_name}.action_sha256 mismatch")
    declared_target = evidence.get("target_sha256")
    if declared_target is not None:
        if not _is_sha256_hex(declared_target):
            errors.append(f"{evidence_name}.target_sha256 must be a SHA-256 hex digest")
        elif declared_target not in valid_target_sha256s:
            errors.append(f"{evidence_name}.target_sha256 mismatch")
    return errors


def _captain_evidence_digest_gate(parameters: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, Any]:
    problems: list[str] = []
    projection = parameters.get("status_projection")
    if isinstance(projection, dict):
        problems.extend(_captain_evidence_digest_binding_errors(projection, evidence_name="status_projection", actions=actions))
    for name in ("execution_authority", "review_evidence", "ci_evidence", "human_authorization"):
        evidence = parameters.get(name)
        if isinstance(evidence, dict):
            problems.extend(_captain_evidence_digest_binding_errors(evidence, evidence_name=name, actions=actions))
    if problems:
        return _captain_gate(
            "evidence-digest-bound",
            "blocked",
            "Captain evidence digest binding does not match the requested action envelope",
            problems,
        )
    bound_sources = []
    for name in ("status_projection", "execution_authority", "review_evidence", "ci_evidence", "human_authorization"):
        evidence = parameters.get(name)
        if isinstance(evidence, dict) and any(key in evidence for key in ("actions_sha256", "action_sha256", "target_sha256")):
            bound_sources.append(name)
    return _captain_gate(
        "evidence-digest-bound",
        "pass",
        "Captain evidence action/target digest bindings are absent or match the requested envelope",
        {
            "actions_sha256": _captain_actions_sha256(actions),
            "bound_sources": sorted(bound_sources),
            "target_sha256s": [action["target_sha256"] for action in actions],
        },
    )

def _captain_evidence_object(parameters: dict[str, Any], name: str) -> dict[str, Any] | None:
    value = parameters.get(name)
    if isinstance(value, dict) and value:
        return value
    return None


def _captain_execution_authority_gate(parameters: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, Any]:
    if _captain_trusted_owner_autonomy_ready(parameters, actions):
        return _captain_gate(
            "execution-authority-present",
            "pass",
            "trusted-owner autonomy supplies execution authority for reversible target-bound actions",
        )
    evidence = _captain_evidence_object(parameters, "execution_authority")
    if evidence is None:
        return _captain_gate(
            "execution-authority-present",
            "blocked",
            "execution_authority evidence object is missing; allow_execution alone never grants execution authority",
            ["execution_authority_missing"],
        )
    problems = []
    if not isinstance(evidence.get("granted_by"), str) or not evidence["granted_by"].strip():
        problems.append("execution_authority.granted_by must be a non-empty string")
    if not isinstance(evidence.get("reference"), str) or not evidence["reference"].strip():
        problems.append("execution_authority.reference must be a non-empty string")
    problems.extend(_captain_evidence_digest_binding_errors(evidence, evidence_name="execution_authority", actions=actions))
    if problems:
        return _captain_gate("execution-authority-present", "blocked", "execution_authority evidence is incomplete or digest-bound to another action", problems)
    return _captain_gate(
        "execution-authority-present",
        "pass",
        "execution authority evidence recorded as one execution prerequisite; it never grants execution by itself",
    )


def _captain_review_evidence_gate(parameters: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = parameters.get("review_evidence")
    expected_head = parameters.get("expected_head")
    if not _is_hex_sha(expected_head, lengths=(40,)):
        return _captain_gate(
            "review-evidence-present",
            "blocked",
            "expected_head must be present as a 40 character hex SHA for Captain evidence binding",
            ["expected_head_missing_or_invalid"],
        )
    if evidence is None:
        return _captain_gate(
            "review-evidence-present",
            "blocked",
            "review_evidence is missing",
            ["review_evidence_missing"],
        )
    expected_diff = parameters.get("diff_sha256")
    expected_base_sha = parameters.get("expected_base_sha")
    pr_merge_targets = [
        action.get("target")
        for action in actions
        if action.get("action") == "pr-merge" and isinstance(action.get("target"), dict)
    ]
    if not pr_merge_targets:
        return _captain_gate(
            "review-evidence-present",
            "pass",
            "self-review audit is not applicable because no pr-merge action is requested",
        )
    if len(pr_merge_targets) != 1:
        return _captain_gate(
            "review-evidence-present",
            "blocked",
            "one self-review audit can bind exactly one pr-merge action",
            ["pr_merge_review_target_count_invalid"],
        )
    if not _is_hex_sha(expected_base_sha, lengths=(40,)):
        return _captain_gate(
            "review-evidence-present",
            "blocked",
            "expected_base_sha must be present as a 40 character hex SHA for PR merge review binding",
            ["expected_base_sha_missing_or_invalid"],
        )
    pr_target = pr_merge_targets[0]
    expected_repo = pr_target.get("repo")
    expected_pr = pr_target.get("pr")
    errors = _self_review_audit_errors(
        evidence,
        expected_head=expected_head if isinstance(expected_head, str) else None,
        expected_diff_sha256=expected_diff if isinstance(expected_diff, str) else None,
        expected_base_sha=expected_base_sha if isinstance(expected_base_sha, str) else None,
        expected_repo=expected_repo if isinstance(expected_repo, str) else None,
        expected_pr=expected_pr if isinstance(expected_pr, int) and not isinstance(expected_pr, bool) else None,
    )
    errors.extend(_captain_evidence_digest_binding_errors(evidence, evidence_name="review_evidence", actions=actions))
    if errors:
        return _captain_gate("review-evidence-present", "blocked", "self-review audit is invalid or digest-bound to another action", errors)
    return _captain_gate(
        "review-evidence-present",
        "pass",
        "diff-bound self-review audit records sufficient review depth and terminal triage; it is not posted to the PR",
    )


def _captain_diff_bound_gate(parameters: dict[str, Any]) -> dict[str, Any]:
    diff_sha = parameters.get("diff_sha256")
    if not _is_sha256_hex(diff_sha):
        return _captain_gate(
            "diff-bound",
            "blocked",
            "diff_sha256 must be a valid SHA-256 hex digest binding the reviewed diff",
            ["diff_binding_missing_or_invalid"],
        )
    evidence = parameters.get("review_evidence")
    if isinstance(evidence, dict) and _is_sha256_hex(evidence.get("diff_sha256")) and evidence["diff_sha256"] != diff_sha:
        return _captain_gate("diff-bound", "blocked", "diff_sha256 does not match review_evidence.diff_sha256", ["diff_sha256_mismatch"])
    return _captain_gate("diff-bound", "pass", "decision is bound to one reviewed diff hash")


def _captain_ci_gate(parameters: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = _captain_evidence_object(parameters, "ci_evidence")
    if evidence is None:
        return _captain_gate("ci-green", "blocked", "ci_evidence is missing", ["ci_evidence_missing"])
    problems = []
    if evidence.get("state") != "passed":
        problems.append("ci_evidence.state must be passed")
    if not _is_hex_sha(evidence.get("head_sha"), lengths=(40,)):
        problems.append("ci_evidence.head_sha must be a 40 character hex SHA")
    if not isinstance(evidence.get("source"), str) or not evidence["source"].strip():
        problems.append("ci_evidence.source must be a non-empty string")
    review = parameters.get("review_evidence")
    expected_head = parameters.get("expected_head")
    if _is_hex_sha(expected_head, lengths=(40,)) and evidence.get("head_sha") != expected_head:
        problems.append("ci_evidence.head_sha does not match expected_head")
    if (
        not problems
        and isinstance(review, dict)
        and _is_hex_sha(review.get("head_sha"), lengths=(40,))
        and review["head_sha"] != evidence.get("head_sha")
    ):
        problems.append("ci_evidence.head_sha does not match review_evidence.head_sha")
    problems.extend(_captain_evidence_digest_binding_errors(evidence, evidence_name="ci_evidence", actions=actions))
    if problems:
        return _captain_gate("ci-green", "blocked", "CI evidence is missing or not green for the bound head", problems)
    return _captain_gate("ci-green", "pass", "CI is green for the bound head; CI proves those jobs only, not production safety")


def _captain_trusted_owner_autonomy_ready(parameters: dict[str, Any], actions: list[dict[str, Any]]) -> bool:
    return (
        parameters.get("trusted_owner_mode") is True
        and parameters.get("autonomy_policy") == CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY
        and bool(actions)
        and all(action.get("irreversibility") == "reversible" for action in actions)
        and all(action.get("action") in CAPTAIN_EXECUTABLE_ACTIONS for action in actions)
    )


def _captain_autonomy_policy_gate(parameters: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, Any]:
    trusted_owner_mode = _mechanic_bool(parameters, "trusted_owner_mode", False)
    autonomy_policy = parameters.get("autonomy_policy")
    if autonomy_policy is not None and autonomy_policy != CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY:
        return _captain_gate(
            "autonomy-policy",
            "blocked",
            "autonomy_policy is not an accepted trusted-owner policy",
            ["autonomy_policy_invalid"],
        )
    if not trusted_owner_mode:
        return _captain_gate(
            "autonomy-policy",
            "pass",
            "manual evidence mode; trusted-owner autonomy is not requested",
        )
    if autonomy_policy != CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY:
        return _captain_gate(
            "autonomy-policy",
            "blocked",
            "trusted_owner_mode requires the explicit autonomy policy",
            ["trusted_owner_autonomy_policy_missing"],
        )
    unsupported = [str(action.get("action")) for action in actions if action.get("action") not in CAPTAIN_EXECUTABLE_ACTIONS]
    if unsupported:
        return _captain_gate(
            "autonomy-policy",
            "blocked",
            "trusted-owner autonomy requires an implemented Captain executor",
            [f"captain_executor_unavailable:{name}" for name in unsupported],
        )
    irreversible = [str(action.get("action")) for action in actions if action.get("irreversibility") == "irreversible"]
    if irreversible:
        return _captain_gate(
            "autonomy-policy",
            "blocked",
            "trusted-owner autonomy does not cover irreversible Captain actions",
            ["irreversible_action_requires_human_authorization"],
        )
    ambiguous = [
        str(action.get("action"))
        for action in actions
        if action.get("irreversibility") not in {"reversible", "irreversible"}
    ]
    if ambiguous:
        return _captain_gate(
            "autonomy-policy",
            "blocked",
            "trusted-owner autonomy requires explicit reversible irreversibility records",
            ["ambiguous_reversibility_requires_human_authorization"],
        )
    return _captain_gate(
        "autonomy-policy",
        "pass",
        "trusted-owner autonomy accepted for reversible, target-bound Captain actions",
        {"policy": CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY},
    )


def _captain_human_authorization_gate(parameters: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, Any]:
    if _captain_trusted_owner_autonomy_ready(parameters, actions):
        return _captain_gate(
            "human-authorization-present",
            "pass",
            "trusted-owner autonomy supplies execution authority without a per-action human approval ritual",
        )
    evidence = _captain_evidence_object(parameters, "human_authorization")
    if evidence is None:
        return _captain_gate(
            "human-authorization-present",
            "blocked",
            "human_authorization evidence is missing",
            ["human_authorization_missing"],
        )
    problems = []
    if not isinstance(evidence.get("authorized_by"), str) or not evidence["authorized_by"].strip():
        problems.append("human_authorization.authorized_by must be a non-empty string")
    if not any(isinstance(evidence.get(key), str) and evidence[key].strip() for key in ("statement", "reference")):
        problems.append("human_authorization requires statement or reference")
    problems.extend(_captain_evidence_digest_binding_errors(evidence, evidence_name="human_authorization", actions=actions))
    if problems:
        return _captain_gate("human-authorization-present", "blocked", "human_authorization evidence is incomplete or digest-bound to another action", problems)
    return _captain_gate(
        "human-authorization-present",
        "pass",
        "human authorization is recorded as evidence; it is not an automatic execution release",
    )


def _captain_action_record(
    action: dict[str, Any],
    *,
    gate_decision: str,
    projection_info: dict[str, Any],
    status: str = "blocked",
    decision: str = "blocked",
    execution: str = "not-performed",
    execution_result: dict[str, Any] | None = None,
    execution_intent_sha256: str | None = None,
    does_not_establish: tuple[str, ...] = CAPTAIN_DOES_NOT_ESTABLISH,
) -> dict[str, Any]:
    captain_receipt = {
        "schema_version": 1,
        "role": "captain",
        "action": action["action"],
        "high_impact": True,
        "target": action["target"],
        "target_sha256": action["target_sha256"],
        "action_sha256": action["action_sha256"],
        "actions_sha256": action["actions_sha256"],
        "scope": action["scope"],
        "risk": action["risk"],
        "recovery_path": action["recovery_path"],
        "irreversibility": action["irreversibility"],
        "irreversibility_record": action["irreversibility_record"],
        "target_change_required": action["target_change_required"],
        "target_change": action["target_change"],
        "evidence_schema": action["evidence_schema"],
        "status_projection_sha256": projection_info.get("sha256"),
        "status": status,
        "decision": decision,
        "gate_decision": gate_decision,
        "execution": execution,
        "receipt_path": action["receipt_path"],
        "does_not_establish": list(does_not_establish),
    }
    if execution_result is not None:
        captain_receipt["execution_result_sha256"] = sha256_json(execution_result)
    if execution_intent_sha256 is not None:
        captain_receipt["execution_intent_sha256"] = execution_intent_sha256
    captain_receipt["receipt_sha256"] = _mechanic_record_sha256(captain_receipt)
    record = {**action, "captain_receipt": captain_receipt, "receipt_sha256": captain_receipt["receipt_sha256"], "execution": execution}
    if execution_result is not None:
        record["execution_result"] = execution_result
    return record


def _captain_authority_gates(
    parameters: dict[str, Any],
    actions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    action_names = ", ".join(action["action"] for action in actions)
    target_findings = [finding for action in actions for finding in action.get("target_findings", [])]
    scope_findings = [finding for action in actions for finding in action.get("scope_findings", [])]
    risk_findings = [finding for action in actions for finding in action.get("risk_findings", [])]
    target_change_findings = [finding for action in actions for finding in action.get("target_change_findings", [])]
    projection_gate, projection_info = _captain_status_projection_gate(parameters, actions)
    gates = [
        _captain_gate("high-impact-marked", "pass", f"all requested actions are marked high-impact: {action_names}"),
        (
            _captain_gate("target-bound", "blocked", "target must be a concrete, action-specific record", target_findings)
            if target_findings
            else _captain_gate("target-bound", "pass", "every action carries a concrete, action-specific target")
        ),
        (
            _captain_gate("scope-bound", "blocked", "scope must declare visible effect boundaries", scope_findings)
            if scope_findings
            else _captain_gate("scope-bound", "pass", "every action declares a visible scope with effect boundaries")
        ),
        (
            _captain_gate("target-change-record", "blocked", "target change records must be explicit objects or null", target_change_findings)
            if target_change_findings
            else _captain_gate("target-change-record", "pass", "target changes are explicit records or null")
        ),
        (
            _captain_gate("recovery-or-irreversibility", "blocked", "risk records must include recovery or irreversibility evidence", risk_findings)
            if risk_findings
            else _captain_gate("recovery-or-irreversibility", "pass", "risk records include recovery or irreversibility; a precondition, not proof of safe execution")
        ),
        projection_gate,
        _captain_evidence_digest_gate(parameters, actions),
        _captain_execution_authority_gate(parameters, actions),
        _captain_review_evidence_gate(parameters, actions),
        _captain_diff_bound_gate(parameters),
        _captain_ci_gate(parameters, actions),
        _captain_autonomy_policy_gate(parameters, actions),
        _captain_human_authorization_gate(parameters, actions),
    ]
    return gates, projection_info


def _captain_blocked_reasons(gates: list[dict[str, Any]]) -> list[str]:
    blocked_reasons: list[str] = []
    for gate in gates:
        if gate["status"] == "pass":
            continue
        details = gate.get("details")
        if isinstance(details, list) and details:
            blocked_reasons.extend(str(entry) for entry in details)
        else:
            blocked_reasons.append(f"{gate['id']}: {gate['reason']}")
    return blocked_reasons


def _captain_intent_canonical_hex_status(value: Any, *, length: int) -> str:
    if not isinstance(value, str) or len(value) != length:
        return "invalid"
    lowered = value.lower()
    if any(char not in "0123456789abcdef" for char in lowered):
        return "invalid"
    if value != lowered:
        return "not_canonical"
    return "ok"


def _captain_execution_intent_expected_base(action: dict[str, Any]) -> str | None:
    target = action.get("target")
    if not isinstance(target, dict):
        return None
    if action.get("action") == "pr-merge":
        base = target.get("base")
    elif action.get("action") == "runtime-deploy":
        base = next(
            (
                target.get(key)
                for key in ("environment", "runtime_target")
                if isinstance(target.get(key), str) and target.get(key).strip()
            ),
            None,
        )
    else:
        base = None
    if isinstance(base, str) and base.strip():
        return base
    return None


def _captain_execution_intent_authorization_sha256(parameters: dict[str, Any]) -> str:
    """Bind the complete authorization mode without exposing raw evidence."""
    return sha256_json(
        {
            "execution_authority": parameters.get("execution_authority"),
            "human_authorization": parameters.get("human_authorization"),
            "trusted_owner_mode": parameters.get("trusted_owner_mode") is True,
            "autonomy_policy": parameters.get("autonomy_policy"),
        }
    )


def _captain_execution_intent_expected_evidence(
    parameters: dict[str, Any],
    actions: list[dict[str, Any]],
) -> dict[str, str | None]:
    projection = parameters.get("status_projection")
    review = parameters.get("review_evidence")
    ci = parameters.get("ci_evidence")
    diff = parameters.get("diff_sha256")
    return {
        "actions_sha256": _captain_actions_sha256(actions),
        "status_projection_sha256": sha256_json(projection) if isinstance(projection, dict) and projection else None,
        "diff_sha256": diff if _is_sha256_hex(diff) else None,
        "review_evidence_sha256": sha256_json(review) if isinstance(review, dict) and review else None,
        "ci_evidence_sha256": sha256_json(ci) if isinstance(ci, dict) and ci else None,
        "authorization_sha256": _captain_execution_intent_authorization_sha256(parameters),
    }


def _captain_execution_intent_review(
    parameters: dict[str, Any],
    actions: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    """Validate the captain-run execution_intent binding fail-closed.

    Returns a receipt-safe info record plus error codes. The info record never
    echoes raw intent, actor or context values: only fixed error codes, digests
    and fields whose values were verified equal to the bound request.
    """
    intent = parameters.get("execution_intent")
    info: dict[str, Any] = {
        "required": True,
        "present": intent is not None,
        "valid": False,
        "kind": None,
        "schema_version": None,
        "intent_sha256": sha256_json(intent) if intent is not None else None,
        "action": None,
        "target_sha256": None,
        "expected_head": None,
        "expected_base": None,
        "expected_base_sha": None,
        "evidence_sha256": {key: None for key in CAPTAIN_EXECUTION_INTENT_EVIDENCE_KEYS},
        "actor_sha256": None,
        "context_sha256": None,
        "issued_at": None,
        "age_seconds": None,
        "max_age_seconds": CAPTAIN_EXECUTION_INTENT_MAX_AGE_SECONDS,
        "clock_skew_tolerance_seconds": CAPTAIN_EXECUTION_INTENT_CLOCK_SKEW_TOLERANCE_SECONDS,
        "errors": [],
    }
    errors: list[str] = []
    if intent is None:
        errors.append("execution_intent_missing")
        info["errors"] = list(errors)
        return info, errors
    if not isinstance(intent, dict) or not intent:
        errors.append("execution_intent_malformed")
        info["errors"] = list(errors)
        return info, errors
    action_name = (
        str(actions[0].get("action"))
        if len(actions) == 1 and isinstance(actions[0], dict)
        else ""
    )
    action_fields = CAPTAIN_EXECUTION_INTENT_ACTION_FIELDS.get(action_name, ())
    required_intent_fields = (*CAPTAIN_EXECUTION_INTENT_FIELDS, *action_fields)
    allowed_intent_fields = frozenset(required_intent_fields)
    for name in required_intent_fields:
        if name not in intent:
            errors.append(f"execution_intent_field_missing:{name}")
    if any(key not in allowed_intent_fields for key in intent):
        errors.append("execution_intent_unknown_fields_present")
    schema_version = intent.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != CAPTAIN_EXECUTION_INTENT_SCHEMA_VERSION:
        if "schema_version" in intent:
            errors.append("execution_intent_schema_version_invalid")
    else:
        info["schema_version"] = CAPTAIN_EXECUTION_INTENT_SCHEMA_VERSION
    if intent.get("kind") != CAPTAIN_EXECUTION_INTENT_KIND:
        if "kind" in intent:
            errors.append("execution_intent_kind_invalid")
    else:
        info["kind"] = CAPTAIN_EXECUTION_INTENT_KIND
    if "actor" in intent:
        actor = intent.get("actor")
        info["actor_sha256"] = sha256_json(actor)
        if not isinstance(actor, dict) or not actor or not isinstance(actor.get("id"), str) or not actor["id"].strip():
            errors.append("execution_intent_actor_invalid")
    if "context" in intent:
        context = intent.get("context")
        info["context_sha256"] = sha256_json(context)
        if not isinstance(context, dict) or not context:
            errors.append("execution_intent_context_invalid")
    if "issued_at" in intent:
        issued_at = intent.get("issued_at")
        parsed_issued_at = (
            _parse_captain_projection_generated_at(issued_at)
            if isinstance(issued_at, str) and issued_at.strip()
            else None
        )
        if parsed_issued_at is None:
            errors.append("execution_intent_issued_at_invalid")
        else:
            info["issued_at"] = parsed_issued_at.isoformat().replace("+00:00", "Z")
            age_seconds = (_captain_now_utc() - parsed_issued_at).total_seconds()
            info["age_seconds"] = int(age_seconds)
            if age_seconds < -CAPTAIN_EXECUTION_INTENT_CLOCK_SKEW_TOLERANCE_SECONDS:
                errors.append("execution_intent_issued_at_in_future")
            elif age_seconds > CAPTAIN_EXECUTION_INTENT_MAX_AGE_SECONDS:
                errors.append("execution_intent_issued_at_stale")
    if len(actions) != 1:
        errors.append("execution_intent_requires_exactly_one_action")
        info["errors"] = list(errors)
        return info, errors
    action = actions[0]
    if "action" in intent:
        declared_action = intent.get("action")
        if not isinstance(declared_action, str) or not declared_action.strip():
            errors.append("execution_intent_field_invalid:action")
        elif declared_action != action["action"]:
            errors.append("execution_intent_action_drift")
        else:
            info["action"] = declared_action
    if "target_sha256" in intent:
        declared_target = intent.get("target_sha256")
        target_status = _captain_intent_canonical_hex_status(declared_target, length=64)
        if target_status == "invalid":
            errors.append("execution_intent_field_invalid:target_sha256")
        elif target_status == "not_canonical":
            errors.append("execution_intent_field_not_canonical:target_sha256")
        elif declared_target != action["target_sha256"]:
            errors.append("execution_intent_target_drift")
        else:
            info["target_sha256"] = declared_target
    if "expected_head" in intent:
        declared_head = intent.get("expected_head")
        head_status = _captain_intent_canonical_hex_status(declared_head, length=40)
        expected_head = _normalize_40_sha(parameters.get("expected_head"))
        if head_status == "invalid":
            errors.append("execution_intent_field_invalid:expected_head")
        elif head_status == "not_canonical":
            errors.append("execution_intent_field_not_canonical:expected_head")
        elif expected_head is None:
            errors.append("execution_intent_head_unverifiable")
        elif declared_head != expected_head:
            errors.append("execution_intent_head_drift")
        else:
            info["expected_head"] = declared_head
    if "expected_base" in intent:
        declared_base = intent.get("expected_base")
        expected_base = _captain_execution_intent_expected_base(action)
        if not isinstance(declared_base, str) or not declared_base.strip():
            errors.append("execution_intent_field_invalid:expected_base")
        elif expected_base is None:
            errors.append("execution_intent_base_unverifiable")
        elif declared_base != expected_base:
            errors.append("execution_intent_base_drift")
        else:
            info["expected_base"] = declared_base
    if action["action"] == "pr-merge" and "expected_base_sha" in intent:
        declared_base_sha = intent.get("expected_base_sha")
        base_sha_status = _captain_intent_canonical_hex_status(
            declared_base_sha, length=40
        )
        expected_base_sha = _normalize_40_sha(parameters.get("expected_base_sha"))
        if base_sha_status == "invalid":
            errors.append("execution_intent_field_invalid:expected_base_sha")
        elif base_sha_status == "not_canonical":
            errors.append("execution_intent_field_not_canonical:expected_base_sha")
        elif expected_base_sha is None:
            errors.append("execution_intent_base_sha_unverifiable")
        elif declared_base_sha != expected_base_sha:
            errors.append("execution_intent_base_sha_drift")
        else:
            info["expected_base_sha"] = declared_base_sha
    if "evidence_sha256" in intent:
        declared_evidence = intent.get("evidence_sha256")
        if not isinstance(declared_evidence, dict) or not declared_evidence:
            errors.append("execution_intent_field_invalid:evidence_sha256")
        else:
            if any(key not in CAPTAIN_EXECUTION_INTENT_EVIDENCE_KEYS for key in declared_evidence):
                errors.append("execution_intent_evidence_unknown_keys_present")
            expected_evidence = _captain_execution_intent_expected_evidence(parameters, actions)
            for key in CAPTAIN_EXECUTION_INTENT_EVIDENCE_KEYS:
                if key not in declared_evidence:
                    errors.append(f"execution_intent_evidence_missing:{key}")
                    continue
                declared_value = declared_evidence.get(key)
                value_status = _captain_intent_canonical_hex_status(declared_value, length=64)
                if value_status == "invalid":
                    errors.append(f"execution_intent_evidence_invalid:{key}")
                    continue
                if value_status == "not_canonical":
                    errors.append(f"execution_intent_evidence_not_canonical:{key}")
                    continue
                expected_value = expected_evidence.get(key)
                if expected_value is None:
                    errors.append(f"execution_intent_evidence_unverifiable:{key}")
                elif declared_value != expected_value:
                    errors.append(f"execution_intent_evidence_drift:{key}")
                else:
                    info["evidence_sha256"][key] = declared_value
    info["valid"] = not errors
    info["errors"] = list(errors)
    return info, errors


def _captain_execution_cwd(parameters: dict[str, Any]) -> Path:
    raw = parameters.get("local_repo")
    if isinstance(raw, str) and raw.strip():
        return Path(raw).expanduser().resolve()
    return Path.cwd().resolve()


def _captain_pr_view(
    repo_path: Path,
    github_runner: GithubRunner,
    *,
    repo_slug: str,
    pr_number: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    view_args = [
        "pr",
        "view",
        pr_number,
        "--repo",
        repo_slug,
        "--json",
        "number,state,mergedAt,mergeCommit,headRefOid,baseRefName,baseRefOid,isDraft,mergeable,mergeStateStatus",
    ]
    try:
        view_result = github_runner(repo_path, view_args)
    except Exception as exc:  # pragma: no cover - defensive receipt boundary
        view_result = {"returncode": 1, "stdout": "", "stderr": f"gh pr view runner exception: {type(exc).__name__}: {exc}"}
    info = {"command": ["gh", *view_args], **_command_result_info(view_result)}
    if info["returncode"] != 0:
        raw_error = info.get("stderr") or info.get("stdout")
        info["error"] = raw_error if raw_error else "gh pr view failed"
        return None, info
    try:
        viewed = _json_stdout(view_result)
    except GripActionError as exc:
        info["error"] = str(exc)
        return None, info
    if not isinstance(viewed, dict):
        info["error"] = "unexpected PR view output"
        return None, info
    return viewed, info


def _captain_pr_merge_preflight_errors(
    viewed: dict[str, Any],
    *,
    expected_head: str,
    expected_base: str,
    expected_base_sha: str,
) -> list[str]:
    errors: list[str] = []
    required = ("state", "isDraft", "headRefOid", "baseRefName", "baseRefOid", "mergeable", "mergeStateStatus")
    for key in required:
        if key not in viewed:
            errors.append(f"pr_view_missing_{key}")
    if errors:
        return errors
    if viewed.get("state") == "MERGED":
        errors.append("pr_already_merged_before_execution")
    elif viewed.get("state") != "OPEN":
        errors.append("pr_not_open_before_execution")
    if viewed.get("isDraft") is not False:
        errors.append("pr_draft_state_not_confirmed_before_execution")
    observed_head = _normalize_40_sha(viewed.get("headRefOid"))
    if observed_head != expected_head:
        errors.append("pr_head_does_not_match_expected_head_before_execution")
    if viewed.get("baseRefName") != expected_base:
        errors.append("pr_base_does_not_match_expected_base_before_execution")
    observed_base_sha = _normalize_40_sha(viewed.get("baseRefOid"))
    if observed_base_sha != expected_base_sha:
        errors.append("pr_base_sha_does_not_match_expected_base_sha_before_execution")
    if viewed.get("mergeable") != "MERGEABLE":
        errors.append("pr_mergeable_not_confirmed_before_execution")
    if viewed.get("mergeStateStatus") != "CLEAN":
        errors.append("pr_merge_state_not_clean_before_execution")
    return errors


def _captain_pr_view_is_settling(viewed: dict[str, Any]) -> bool:
    return viewed.get("mergeable") == "UNKNOWN" or viewed.get("mergeStateStatus") == "UNKNOWN"




def _captain_retry_delay(delays: tuple[float, ...], attempt: int) -> float:
    if attempt <= 1 or not delays:
        return 0.0
    return delays[min(attempt - 2, len(delays) - 1)]


def _captain_preflight_errors_are_transient(viewed: dict[str, Any], errors: list[str]) -> bool:
    return bool(errors) and set(errors).issubset(CAPTAIN_PREFLIGHT_TRANSIENT_ERRORS) and _captain_pr_view_is_settling(viewed)

def _captain_pr_merge_preflight_view(
    repo_path: Path,
    github_runner: GithubRunner,
    *,
    repo_slug: str,
    pr_number: str,
    expected_head: str,
    expected_base: str,
    expected_base_sha: str,
) -> tuple[dict[str, Any] | None, dict[str, Any], list[str]]:
    attempts: list[dict[str, Any]] = []
    last_viewed: dict[str, Any] | None = None
    last_info: dict[str, Any] = {}
    last_errors: list[str] = ["pr_pre_execution_view_not_attempted"]
    for attempt in range(1, CAPTAIN_PREFLIGHT_SETTLE_ATTEMPTS + 1):
        if attempt > 1:
            _captain_sleep(_captain_retry_delay(CAPTAIN_PREFLIGHT_SETTLE_DELAYS_SECONDS, attempt))
        viewed, info = _captain_pr_view(repo_path, github_runner, repo_slug=repo_slug, pr_number=pr_number)
        attempt_record = dict(info)
        attempt_record["attempt"] = attempt
        attempts.append(attempt_record)
        last_info = info
        if viewed is None:
            last_errors = [str(info.get("error") or "pr_pre_execution_view_failed")]
            if attempt < CAPTAIN_PREFLIGHT_SETTLE_ATTEMPTS:
                continue
            break
        last_viewed = viewed
        last_errors = _captain_pr_merge_preflight_errors(
            viewed,
            expected_head=expected_head,
            expected_base=expected_base,
            expected_base_sha=expected_base_sha,
        )
        if not last_errors:
            summary = {
                "attempt_count": len(attempts),
                "attempts": attempts,
                "settled": True,
                "last_error": None,
                "error_codes_seen": [],
            }
            return viewed, summary, []
        if not _captain_preflight_errors_are_transient(viewed, last_errors):
            break
    summary = {
        "attempt_count": len(attempts),
        "attempts": attempts,
        "settled": False,
        "last_error": "; ".join(last_errors),
        "error_codes_seen": sorted(set(last_errors)),
        "last_viewed": last_viewed,
        "last_view_result": last_info,
    }
    return last_viewed, summary, last_errors


def _captain_merge_commit_oid(viewed: dict[str, Any]) -> str | None:
    merge_commit = viewed.get("mergeCommit")
    if not isinstance(merge_commit, dict):
        return None
    return _normalize_40_sha(merge_commit.get("oid"))


def _captain_pr_merge_verify_errors(viewed: dict[str, Any], *, expected_head: str, expected_base: str) -> list[str]:
    errors: list[str] = []
    required = ("state", "headRefOid", "baseRefName")
    for key in required:
        if key not in viewed:
            errors.append(f"pr_verify_missing_{key}")
    if errors:
        return errors
    if viewed.get("state") != "MERGED":
        errors.append("pr_not_merged_after_execution")
        return errors
    if "mergeCommit" not in viewed:
        errors.append("pr_verify_missing_mergeCommit")
        return errors
    observed_head = _normalize_40_sha(viewed.get("headRefOid"))
    if observed_head != expected_head:
        errors.append("merged_pr_head_does_not_match_expected_head")
    if viewed.get("baseRefName") != expected_base:
        errors.append("merged_pr_base_does_not_match_expected_base")
    if _captain_merge_commit_oid(viewed) is None:
        errors.append("merged_pr_merge_commit_oid_missing_or_invalid")
    return errors


def _captain_pr_merge_post_view(
    repo_path: Path,
    github_runner: GithubRunner,
    *,
    repo_slug: str,
    pr_number: str,
    expected_head: str,
    expected_base: str,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[str], dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    last_viewed: dict[str, Any] | None = None
    last_errors: list[str] = ["post_merge_view_not_attempted"]
    all_errors: set[str] = set()
    for attempt in range(1, CAPTAIN_POST_MERGE_VERIFY_ATTEMPTS + 1):
        if attempt > 1:
            _captain_sleep(_captain_retry_delay(CAPTAIN_POST_MERGE_VERIFY_DELAYS_SECONDS, attempt))
        viewed, info = _captain_pr_view(repo_path, github_runner, repo_slug=repo_slug, pr_number=pr_number)
        attempt_record = dict(info)
        attempt_record["attempt"] = attempt
        attempts.append(attempt_record)
        if viewed is None:
            last_errors = [str(info.get("error") or "gh pr view failed after merge")]
            all_errors.update(last_errors)
            continue
        last_viewed = viewed
        last_errors = _captain_pr_merge_verify_errors(viewed, expected_head=expected_head, expected_base=expected_base)
        all_errors.update(last_errors)
        if not last_errors:
            summary = {
                "attempt_count": len(attempts),
                "last_error": None,
                "error_codes_seen": sorted(all_errors),
                "last_viewed": viewed,
                "verified": True,
            }
            return viewed, attempts, [], summary
    summary = {
        "attempt_count": len(attempts),
        "last_error": "; ".join(last_errors),
        "error_codes_seen": sorted(all_errors or set(last_errors)),
        "last_viewed": last_viewed,
        "verified": False,
    }
    return last_viewed, attempts, last_errors, summary


CAPTAIN_PR_MERGE_METHOD_PREFERENCE = (
    ("merge", "allow_merge_commit", "--merge"),
    ("squash", "allow_squash_merge", "--squash"),
    ("rebase", "allow_rebase_merge", "--rebase"),
)


def _captain_repository_merge_policy(
    repo_path: Path,
    github_runner: GithubRunner,
    *,
    repo_slug: str,
) -> tuple[dict[str, Any] | None, dict[str, Any], list[str]]:
    policy_args = [
        "api",
        f"repos/{repo_slug}",
        "--jq",
        "{allow_merge_commit,allow_squash_merge,allow_rebase_merge}",
    ]
    try:
        policy_result = github_runner(repo_path, policy_args)
    except Exception as exc:  # pragma: no cover - defensive receipt boundary
        policy_result = {
            "returncode": 1,
            "stdout": "",
            "stderr": f"gh api runner exception: {type(exc).__name__}: {exc}",
        }
    info = {"command": ["gh", *policy_args], **_command_result_info(policy_result)}
    if info["returncode"] != 0:
        raw_error = info.get("stderr") or info.get("stdout") or "gh api repository policy failed"
        info["error"] = raw_error
        return None, info, ["repository_merge_policy_query_failed"]
    try:
        raw_policy = _json_stdout(policy_result)
    except GripActionError as exc:
        info["error"] = str(exc)
        return None, info, ["repository_merge_policy_invalid_json"]
    if not isinstance(raw_policy, dict):
        info["error"] = "unexpected repository merge policy output"
        return None, info, ["repository_merge_policy_not_mapping"]

    settings: dict[str, bool] = {}
    invalid_fields: list[str] = []
    for _method, field, _flag in CAPTAIN_PR_MERGE_METHOD_PREFERENCE:
        value = raw_policy.get(field)
        if not isinstance(value, bool):
            invalid_fields.append(field)
        else:
            settings[field] = value
    if invalid_fields:
        info["invalid_fields"] = invalid_fields
        return None, info, [f"repository_merge_policy_invalid_fields:{','.join(invalid_fields)}"]

    allowed_methods = [
        method
        for method, field, _flag in CAPTAIN_PR_MERGE_METHOD_PREFERENCE
        if settings[field]
    ]
    if not allowed_methods:
        return None, info, ["repository_all_merge_methods_disabled"]
    selected_method, selected_field, selected_flag = next(
        (method, field, flag)
        for method, field, flag in CAPTAIN_PR_MERGE_METHOD_PREFERENCE
        if settings[field]
    )
    policy = {
        "settings": settings,
        "allowed_methods": allowed_methods,
        "selected_method": selected_method,
        "selected_policy_field": selected_field,
        "selected_flag": selected_flag,
        "preference_order": [method for method, _field, _flag in CAPTAIN_PR_MERGE_METHOD_PREFERENCE],
    }
    return policy, info, []


def _run_captain_pr_merge(
    repo_path: Path,
    action: dict[str, Any],
    parameters: dict[str, Any],
    github_runner: GithubRunner,
) -> dict[str, Any]:
    expected_head = _normalize_40_sha(_string_parameter(parameters, "expected_head"))
    if expected_head is None:
        raise GripPreflightError("expected_head must be a 40 character hex SHA for pr-merge execution")
    expected_base_sha = _normalize_40_sha(_string_parameter(parameters, "expected_base_sha"))
    if expected_base_sha is None:
        raise GripPreflightError("expected_base_sha must be a 40 character hex SHA for pr-merge execution")
    target = action["target"]
    repo_slug = str(target["repo"])
    pr_number = str(target["pr"])
    expected_base = str(target["base"])
    execution_result: dict[str, Any] = {
        "action": "pr-merge",
        "repo": repo_slug,
        "pr": target["pr"],
        "expected_head": expected_head,
        "expected_base": expected_base,
        "expected_base_sha": expected_base_sha,
        "execution_attempted": False,
        "execution_invoked": False,
        "command_returned": False,
        "remote_mutation_observed": False,
        "preflight_passed": False,
        "verification_passed": False,
    }
    pre_view, preflight_summary, preflight_errors = _captain_pr_merge_preflight_view(
        repo_path,
        github_runner,
        repo_slug=repo_slug,
        pr_number=pr_number,
        expected_head=expected_head,
        expected_base=expected_base,
        expected_base_sha=expected_base_sha,
    )
    execution_result["pre_view"] = pre_view
    execution_result["preflight_view_summary"] = preflight_summary
    if pre_view is None:
        execution_result["preflight_errors"] = preflight_errors
        detail = "; ".join(preflight_errors) if preflight_errors else "pr_pre_execution_view_failed"
        execution_result["verification_error"] = f"pre-execution PR view failed; merge not attempted: {detail}"
        return execution_result
    if preflight_errors:
        execution_result["preflight_errors"] = preflight_errors
        execution_result["verification_error"] = "pre-execution PR state did not match the bound target; merge not attempted"
        return execution_result
    merge_policy, merge_policy_query, merge_policy_errors = _captain_repository_merge_policy(
        repo_path,
        github_runner,
        repo_slug=repo_slug,
    )
    execution_result["merge_policy_query"] = merge_policy_query
    execution_result["merge_policy"] = merge_policy
    if merge_policy_errors or merge_policy is None:
        execution_result["preflight_errors"] = merge_policy_errors
        detail = "; ".join(merge_policy_errors) if merge_policy_errors else "repository_merge_policy_unavailable"
        execution_result["verification_error"] = f"repository merge policy unavailable; merge not attempted: {detail}"
        return execution_result
    execution_result["preflight_passed"] = True
    merge_args = [
        "pr",
        "merge",
        pr_number,
        "--repo",
        repo_slug,
        merge_policy["selected_flag"],
        "--match-head-commit",
        expected_head,
    ]
    execution_result["execution_invoked"] = True
    execution_result["merge_command"] = ["gh", *merge_args]
    try:
        merge_result = github_runner(repo_path, merge_args)
        execution_result["command_returned"] = True
        execution_result["execution_attempted"] = True
    except Exception as exc:  # pragma: no cover - defensive receipt boundary
        execution_result["runner_exception"] = f"{type(exc).__name__}: {_bounded_command_output(str(exc), limit=512)}"
        merge_result = {"returncode": 1, "stdout": "", "stderr": f"gh pr merge runner exception: {type(exc).__name__}: {exc}"}
    merge_info = _command_result_info(merge_result)
    execution_result["merge_result"] = merge_info
    execution_result["merge_returncode"] = merge_info["returncode"]
    execution_result["merge_stdout"] = merge_info["stdout"]
    execution_result["merge_stderr"] = merge_info["stderr"]
    viewed, view_attempts, verify_errors, verify_summary = _captain_pr_merge_post_view(
        repo_path,
        github_runner,
        repo_slug=repo_slug,
        pr_number=pr_number,
        expected_head=expected_head,
        expected_base=expected_base,
    )
    execution_result["verify_view_attempts"] = view_attempts
    execution_result["verify_view_summary"] = verify_summary
    execution_result["verified_pr"] = viewed
    execution_result["remote_mutation_observed"] = not verify_errors and viewed is not None
    if merge_info["returncode"] != 0:
        if verify_errors:
            execution_result["post_verify_errors"] = ["merge_command_failed", *verify_errors]
            execution_result["verification_error"] = "merge_command_failed; " + "; ".join(verify_errors)
        else:
            execution_result["verification_error"] = "merge_command_failed_but_pr_observed_merged"
            execution_result["post_verify_errors"] = ["merge_command_failed_but_pr_observed_merged"]
        return execution_result
    if verify_errors:
        execution_result["post_verify_errors"] = verify_errors
        execution_result["verification_error"] = "; ".join(verify_errors)
        return execution_result
    execution_result["verification_passed"] = True
    return execution_result


def _captain_runtime_deploy_target_errors(
    action: dict[str, Any],
    parameters: dict[str, Any],
) -> list[str]:
    target = action["target"]
    origin_key = "repo" if isinstance(target.get("repo"), str) and target.get("repo") else "service"
    runtime_key = (
        "environment"
        if isinstance(target.get("environment"), str) and target.get("environment")
        else "runtime_target"
    )
    errors = _captain_runtime_deploy_binding_errors(
        adapter=target.get("adapter"),
        origin_key=origin_key,
        origin_value=target.get(origin_key),
        runtime_value=target.get(runtime_key),
    )
    try:
        source_repository, source_owner = _runtime_deploy_source_parameters(parameters)
    except GripPreflightError as exc:
        errors.append(str(exc))
        return errors
    if target.get("source_repository") != source_repository:
        errors.append("runtime_deploy_source_repository_target_mismatch")
    if target.get("source_lease_owner_id") != source_owner:
        errors.append("runtime_deploy_source_lease_owner_target_mismatch")
    return errors


def _runtime_deploy_schedule_errors(
    schedule: Any,
    *,
    expected_head: str,
    expected_delay_seconds: int,
    expected_argv_sha256: str,
    expected_job_root: str,
    expected_job_prefix: str,
    expected_source_identity_sha256: str,
) -> list[str]:
    if not isinstance(schedule, dict):
        return ["runtime_deploy_scheduler_returned_non_object"]
    errors: list[str] = []
    if schedule.get("scheduled") is not True:
        errors.append("runtime_deploy_not_scheduled")
    if schedule.get("expected_head") != expected_head:
        errors.append("runtime_deploy_schedule_head_mismatch")
    already_scheduled = schedule.get("already_scheduled")
    if not isinstance(already_scheduled, bool):
        errors.append("runtime_deploy_schedule_reuse_state_missing")
    if schedule.get("requested_delay_seconds") != expected_delay_seconds:
        errors.append("runtime_deploy_schedule_requested_delay_mismatch")
    effective_delay_seconds = schedule.get("delay_seconds")
    if isinstance(effective_delay_seconds, bool) or not isinstance(effective_delay_seconds, int):
        errors.append("runtime_deploy_schedule_effective_delay_invalid")
    elif not RUNTIME_DEPLOY_MIN_DELAY_SECONDS <= effective_delay_seconds <= RUNTIME_DEPLOY_MAX_DELAY_SECONDS:
        errors.append("runtime_deploy_schedule_effective_delay_invalid")
    elif already_scheduled is False and effective_delay_seconds != expected_delay_seconds:
        errors.append("runtime_deploy_schedule_delay_mismatch")
    unit = schedule.get("unit")
    unit_pattern = rf"{re.escape(expected_job_prefix)}[0-9a-f]{{12}}"
    if not isinstance(unit, str) or re.fullmatch(unit_pattern, unit) is None:
        errors.append("runtime_deploy_schedule_unit_missing_or_unbound")
    argv_sha256 = schedule.get("argv_sha256")
    if not isinstance(argv_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", argv_sha256) is None:
        errors.append("runtime_deploy_schedule_argv_hash_missing_or_invalid")
    elif argv_sha256 != expected_argv_sha256:
        errors.append("runtime_deploy_schedule_argv_hash_mismatch")
    if schedule.get("source_identity_sha256") != expected_source_identity_sha256:
        errors.append("runtime_deploy_schedule_source_identity_mismatch")
    source_identity = schedule.get("source_identity")
    if not isinstance(source_identity, dict) or source_identity.get("identity_sha256") != expected_source_identity_sha256:
        errors.append("runtime_deploy_schedule_source_identity_missing_or_unbound")
    if schedule.get("expected_connector_disconnect") is not True:
        errors.append("runtime_deploy_disconnect_contract_missing")
    if schedule.get("status_tool") != "grabowski_job_status":
        errors.append("runtime_deploy_status_tool_missing")
    if schedule.get("logs_tool") != "grabowski_job_logs":
        errors.append("runtime_deploy_logs_tool_missing")
    path_values: dict[str, Path] = {}
    for key in ("metadata_path", "stdout_path", "stderr_path"):
        value = schedule.get(key)
        if not isinstance(value, str) or not value.startswith("/"):
            errors.append(f"runtime_deploy_{key}_missing_or_unbound")
            continue
        path_values[key] = Path(value)
    if isinstance(unit, str) and len(path_values) == 3:
        expected_names = {
            "metadata_path": "metadata.json",
            "stdout_path": "stdout.log",
            "stderr_path": "stderr.log",
        }
        expected_parent = Path(expected_job_root) / unit
        if any(path.parent != expected_parent for path in path_values.values()):
            errors.append("runtime_deploy_schedule_paths_not_bound_to_unit")
        for key, expected_name in expected_names.items():
            if path_values[key].name != expected_name:
                errors.append(f"runtime_deploy_{key}_filename_invalid")
    return errors


def _run_captain_runtime_deploy(
    action: dict[str, Any],
    parameters: dict[str, Any],
) -> dict[str, Any]:
    expected_head = _runtime_deploy_expected_head(parameters)
    delay_seconds = _runtime_deploy_delay_seconds(parameters)
    target = action["target"]
    execution_result: dict[str, Any] = {
        "action": "runtime-deploy",
        "adapter": target.get("adapter"),
        "target": target,
        "expected_head": expected_head,
        "delay_seconds": delay_seconds,
        "execution_attempted": False,
        "execution_invoked": False,
        "command_returned": False,
        "remote_mutation_observed": False,
        "local_mutation_observed": False,
        "preflight_passed": False,
        "verification_passed": False,
        "verification_scope": "schedule-registration",
        "deployment_completion_verified": False,
    }
    source_repository, source_lease_owner_id = _runtime_deploy_source_parameters(parameters)
    target_errors = _captain_runtime_deploy_target_errors(action, parameters)
    if target_errors:
        execution_result["preflight_errors"] = target_errors
        execution_result["verification_error"] = "; ".join(target_errors)
        return execution_result
    try:
        preflight = (
            _runtime_deploy_self_preflight(expected_head)
            if source_repository is None
            else _runtime_deploy_self_preflight(
                expected_head,
                source_repository,
                source_lease_owner_id,
            )
        )
    except (GripPreflightError, OSError, RuntimeError, ValueError) as exc:
        execution_result["preflight_errors"] = [str(exc)]
        execution_result["verification_error"] = f"runtime deploy preflight failed; deployment not scheduled: {exc}"
        return execution_result
    execution_result["preflight"] = preflight
    execution_result["preflight_passed"] = True
    execution_result["execution_invoked"] = True
    execution_result["execution_attempted"] = True
    try:
        schedule = (
            _runtime_deploy_self_schedule(expected_head, delay_seconds)
            if source_repository is None
            else _runtime_deploy_self_schedule(
                expected_head,
                delay_seconds,
                source_repository,
                source_lease_owner_id,
            )
        )
        execution_result["command_returned"] = True
    except Exception as exc:  # pragma: no cover - defensive receipt boundary
        execution_result["runner_exception"] = (
            f"{type(exc).__name__}: {_bounded_command_output(str(exc), limit=512)}"
        )
        execution_result["mutation_outcome_unknown"] = True
        execution_result["local_mutation_outcome_unknown"] = True
        execution_result["verification_error"] = (
            "runtime deploy scheduling raised an exception; a job may already have been registered"
        )
        return execution_result
    execution_result["schedule"] = schedule
    effective_delay = schedule.get("delay_seconds") if isinstance(schedule, dict) else None
    expected_schedule_hash = (
        _runtime_deploy_self_expected_argv_sha256(preflight, expected_head, effective_delay)
        if isinstance(effective_delay, int) and not isinstance(effective_delay, bool)
        else ""
    )
    schedule_errors = _runtime_deploy_schedule_errors(
        schedule,
        expected_head=expected_head,
        expected_delay_seconds=delay_seconds,
        expected_argv_sha256=expected_schedule_hash,
        expected_job_root=str(preflight["job_root"]),
        expected_job_prefix=str(preflight["job_prefix"]),
        expected_source_identity_sha256=str(preflight["source_identity_sha256"]),
    )
    if schedule_errors:
        execution_result["post_verify_errors"] = schedule_errors
        execution_result["mutation_outcome_unknown"] = True
        execution_result["local_mutation_outcome_unknown"] = True
        execution_result["verification_error"] = "; ".join(schedule_errors)
        return execution_result
    execution_result["deployment_scheduled"] = True
    execution_result["scheduled_unit"] = schedule["unit"]
    execution_result["already_scheduled"] = schedule["already_scheduled"]
    execution_result["new_job_registered"] = not schedule["already_scheduled"]
    execution_result["local_mutation_observed"] = not schedule["already_scheduled"]
    execution_result["verification_passed"] = True
    execution_result["next_verification"] = {
        "status_tool": schedule["status_tool"],
        "logs_tool": schedule["logs_tool"],
        "unit": schedule["unit"],
        "expected_head": expected_head,
        "source_identity_sha256": schedule["source_identity_sha256"],
    }
    execution_result["non_claims"] = [
        "schedule verification does not claim that the delayed deployment has completed",
        "remote_mutation_observed refers to deployment completion, not local durable-job registration",
        "runtime identity must be checked after the connector reconnects",
    ]
    return execution_result


def _run_task_attention_decision(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    import grabowski_task_attention

    try:
        output = grabowski_task_attention.record_decision(parameters)
    except grabowski_task_attention.TaskAttentionInputError as exc:
        raise GripPreflightError(str(exc)) from exc
    except grabowski_task_attention.TaskAttentionConflictError as exc:
        _check(receipt, "current-task-outcome-bound", "fail", str(exc))
        return {
            "receipt_status": "blocked",
            "decision": "blocked",
            "blocked_reasons": ["attention_decision_conflict"],
            "error": str(exc),
        }
    except (
        grabowski_task_attention.TaskAttentionIntegrityError,
        grabowski_task_attention.TaskAttentionError,
        OSError,
    ) as exc:
        _check(receipt, "current-task-outcome-bound", "fail", type(exc).__name__)
        raise GripActionError("task attention decision evidence is invalid or unavailable") from exc
    _check(receipt, "current-task-outcome-bound", "pass", output["outcome_receipt_sha256"])
    _check(receipt, "create-only-decision", "pass", output["file_sha256"])
    _check(
        receipt,
        "idempotent-replay",
        "pass",
        "replayed" if output["replayed"] else "created",
    )
    _check(receipt, "task-store-unchanged", "pass", output["task_binding"]["argv_sha256"])
    return {**output, "receipt_status": "passed"}


def _run_task_attention_reconciliation(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    import grabowski_task_attention

    try:
        output = grabowski_task_attention.reconcile_attention(parameters)
    except grabowski_task_attention.TaskAttentionInputError as exc:
        raise GripPreflightError(str(exc)) from exc
    except (grabowski_task_attention.TaskAttentionError, OSError) as exc:
        raise GripActionError("task attention reconciliation failed closed") from exc
    _check(
        receipt,
        "bounded-task-snapshot",
        "pass",
        f"returned={output['pagination']['returned']};total={output['total_attention']}",
    )
    _check(
        receipt,
        "decision-evidence-validated",
        "pass",
        sha256_json(output["records"]),
    )
    _check(
        receipt,
        "conservative-classification",
        "pass",
        sha256_json(output["classification_counts"]),
    )
    _check(receipt, "no-probes-or-mutation", "pass", "read_only_task_snapshot_and_receipts")
    return {**output, "receipt_status": "passed"}


def _run_operator_obligation_open(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    try:
        output = grabowski_operator_obligation.open_obligation(parameters)
    except grabowski_operator_obligation.OperatorObligationInputError as exc:
        raise GripPreflightError(str(exc)) from exc
    except grabowski_operator_obligation.OperatorObligationConflictError as exc:
        _check(receipt, "durable_open", "fail", str(exc))
        return {
            "receipt_status": "blocked",
            "decision": "blocked",
            "blocked_reasons": ["obligation_id_conflict"],
            "error": str(exc),
        }
    except grabowski_operator_obligation.OperatorObligationError as exc:
        raise GripActionError(str(exc)) from exc
    _check(receipt, "durable_open", "pass", output["open_file_sha256"])
    _check(receipt, "acceptance_bound", "pass", output["material_sha256"])
    _check(receipt, "response_remains_open", "pass", "response_may_end=false")
    return {**output, "receipt_status": "passed"}


def _run_operator_obligation_list(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    try:
        output = grabowski_operator_obligation.list_obligations(parameters)
    except grabowski_operator_obligation.OperatorObligationInputError as exc:
        raise GripPreflightError(str(exc)) from exc
    except grabowski_operator_obligation.OperatorObligationError as exc:
        raise GripActionError(str(exc)) from exc
    _check(receipt, "bounded_list", "pass", f"record_count={output['record_count']}")
    _check(
        receipt,
        "origin_filter",
        "pass",
        f"repo={output['repo_filter'] is not None}; thread={output['thread_id_filter'] is not None}",
    )
    _check(
        receipt,
        "continuation_attention",
        "warn" if output["attention_required"] else "pass",
        output["recommended_next_action"],
    )
    return {**output, "receipt_status": "passed"}


def _run_operator_obligation_status(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    if set(parameters) != {"obligation_id"}:
        raise GripPreflightError("operator-obligation-status accepts only obligation_id")
    try:
        output = grabowski_operator_obligation.status_obligation(parameters["obligation_id"])
    except grabowski_operator_obligation.OperatorObligationInputError as exc:
        raise GripPreflightError(str(exc)) from exc
    except FileNotFoundError as exc:
        _check(receipt, "obligation_exists", "fail", "obligation record not found")
        return {
            "receipt_status": "blocked",
            "decision": "blocked",
            "blocked_reasons": ["obligation_not_found"],
            "error": str(exc),
        }
    except grabowski_operator_obligation.OperatorObligationError as exc:
        raise GripActionError(str(exc)) from exc
    _check(receipt, "integrity_bound_read", "pass", output["open_file_sha256"])
    _check(
        receipt,
        "continuation_decision",
        "pass",
        f"state={output['state']}; response_may_end={str(output['response_may_end']).lower()}",
    )
    _check(
        receipt,
        "no_completion_inference",
        "pass",
        f"work_complete={str(output['work_complete']).lower()}",
    )
    return {**output, "receipt_status": "passed"}


def _observe_operator_systemd_job(identifier: str) -> dict[str, Any]:
    import grabowski_operator_core as operator

    return operator.grabowski_job_status(identifier)


def _observe_operator_task(identifier: str) -> dict[str, Any]:
    import grabowski_tasks as tasks

    return tasks.grabowski_task_status(identifier)


def _observe_operator_workspace(identifier: str) -> dict[str, Any]:
    import grabowski_agent_workspace as workspace

    return workspace.grabowski_agent_workspace_status(identifier)


def _operator_delegation_observation(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"kind", "id"}:
        raise GripPreflightError("delegated close requires delegation with exactly kind and id")
    kind = value.get("kind")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise GripPreflightError("delegation.id must be a non-empty string")
    identifier = identifier.strip()

    observation_tool: str
    live_status: str
    identity_material: dict[str, Any]
    if kind == "systemd_job":
        observation_tool = "grabowski_job_status"
        observed = _observe_operator_systemd_job(identifier)
        if not isinstance(observed, dict):
            raise GripPreflightError("delegation observation returned a non-object")
        live_status = str(observed.get("final_status") or "")
        metadata = observed.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        identity_material = {
            "kind": kind,
            "id": identifier,
            "unit": observed.get("unit"),
            "job_id": metadata.get("job_id"),
            "origin_sha256": metadata.get("origin_sha256"),
            "argv_sha256": metadata.get("argv_sha256"),
            "status": live_status,
        }
        if live_status not in {"launch_submitted", "running"}:
            raise GripPreflightError(
                f"delegated systemd job is not live: status={live_status or 'unknown'}"
            )
        for field in ("unit", "job_id", "origin_sha256", "argv_sha256"):
            if not isinstance(identity_material[field], str) or not identity_material[field]:
                raise GripPreflightError(f"delegated systemd job observation lacks {field}")
        if not _is_sha256_hex(identity_material["origin_sha256"]):
            raise GripPreflightError("delegated systemd job origin receipt is invalid")
        if not _is_sha256_hex(identity_material["argv_sha256"]):
            raise GripPreflightError("delegated systemd job argv identity is invalid")
    elif kind == "grabowski_task":
        observation_tool = "grabowski_task_status"
        observed = _observe_operator_task(identifier)
        if not isinstance(observed, dict):
            raise GripPreflightError("delegation observation returned a non-object")
        live_status = str(observed.get("state") or "")
        identity_material = {
            "kind": kind,
            "id": identifier,
            "task_id": observed.get("task_id"),
            "unit": observed.get("unit"),
            "attempt": observed.get("attempt"),
            "argv_sha256": observed.get("argv_sha256"),
            "updated_at_unix": observed.get("updated_at_unix"),
            "status": live_status,
        }
        if live_status not in {"launching", "running"}:
            raise GripPreflightError(
                f"delegated Grabowski task is not live: status={live_status or 'unknown'}"
            )
        if identity_material["task_id"] != identifier:
            raise GripPreflightError("delegated Grabowski task identity mismatch")
        if not isinstance(identity_material["unit"], str) or not identity_material["unit"]:
            raise GripPreflightError("delegated Grabowski task unit is missing")
        if not isinstance(identity_material["attempt"], int) or isinstance(identity_material["attempt"], bool):
            raise GripPreflightError("delegated Grabowski task attempt is invalid")
        if not _is_sha256_hex(identity_material["argv_sha256"]):
            raise GripPreflightError("delegated Grabowski task argv identity is invalid")
        if not isinstance(identity_material["updated_at_unix"], int) or isinstance(identity_material["updated_at_unix"], bool):
            raise GripPreflightError("delegated Grabowski task observation time is invalid")
    elif kind == "agent_workspace":
        observation_tool = "grabowski_agent_workspace_status"
        observed = _observe_operator_workspace(identifier)
        if not isinstance(observed, dict):
            raise GripPreflightError("delegation observation returned a non-object")
        raw_tasks = observed.get("tasks")
        raw_tasks = raw_tasks if isinstance(raw_tasks, dict) else {}
        task_states: dict[str, dict[str, Any]] = {}
        active_roles: list[str] = []
        for role in ("writer", "tests", "review"):
            task = raw_tasks.get(role)
            task = task if isinstance(task, dict) else {}
            state = str(task.get("state") or "")
            task_states[role] = {
                "task_id": task.get("task_id"),
                "state": state,
                "terminal": task.get("terminal"),
            }
            if state in {"launching", "running"}:
                active_roles.append(role)
        live_status = "running"
        identity_material = {
            "kind": kind,
            "id": identifier,
            "workspace_id": observed.get("workspace_id"),
            "creation_state": observed.get("creation_state"),
            "expected_base_head": observed.get("expected_base_head"),
            "closed": observed.get("closed"),
            "writer_terminal_failure": observed.get("writer_terminal_failure"),
            "active_roles": active_roles,
            "tasks": task_states,
            "status": live_status,
        }
        if identity_material["workspace_id"] != identifier:
            raise GripPreflightError("delegated workspace identity mismatch")
        if identity_material["creation_state"] != "ready":
            raise GripPreflightError("delegated workspace is not ready")
        if identity_material["closed"] is not False:
            raise GripPreflightError("delegated workspace is already closed or its state is unclear")
        if identity_material["writer_terminal_failure"] is True:
            raise GripPreflightError("delegated workspace has a terminal writer failure")
        if not active_roles:
            raise GripPreflightError("delegated workspace has no live role task")
        expected_base_head = identity_material["expected_base_head"]
        if not isinstance(expected_base_head, str) or _normalize_40_sha(expected_base_head) is None:
            raise GripPreflightError("delegated workspace base identity is invalid")
    else:
        raise GripPreflightError("delegation.kind must be systemd_job, grabowski_task, or agent_workspace")

    observed_at = utc_now()
    identity_sha256 = sha256_json(identity_material)
    delegation_material = {
        "kind": str(kind),
        "id": identifier,
        "observation_tool": observation_tool,
        "status": live_status,
        "observed_at": observed_at,
        "identity_sha256": identity_sha256,
    }
    return {
        **delegation_material,
        "observation_receipt_sha256": sha256_json(delegation_material),
    }


def _run_operator_obligation_close(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    del spec, runner
    dispatch_parameters = dict(parameters)
    if dispatch_parameters.get("outcome") == "delegated":
        try:
            dispatch_parameters["delegation"] = _operator_delegation_observation(
                dispatch_parameters.get("delegation")
            )
        except (GripPreflightError, OSError, RuntimeError, ValueError) as exc:
            _check(receipt, "delegation_live_observation", "fail", str(exc))
            return {
                "receipt_status": "blocked",
                "decision": "blocked",
                "blocked_reasons": ["delegation_not_live_or_unverifiable"],
                "error": str(exc),
                "continuation_required": True,
                "response_may_end": False,
                "work_complete": False,
            }
        _check(
            receipt,
            "delegation_live_observation",
            "pass",
            dispatch_parameters["delegation"]["observation_receipt_sha256"],
        )
    else:
        _check(receipt, "delegation_live_observation", "skip", "outcome is not delegated")
    try:
        output = grabowski_operator_obligation.close_obligation(dispatch_parameters)
    except grabowski_operator_obligation.OperatorObligationInputError as exc:
        raise GripPreflightError(str(exc)) from exc
    except FileNotFoundError as exc:
        _check(receipt, "open_binding", "fail", "obligation open record not found")
        return {
            "receipt_status": "blocked",
            "decision": "blocked",
            "blocked_reasons": ["obligation_not_found"],
            "error": str(exc),
        }
    except grabowski_operator_obligation.OperatorObligationConflictError as exc:
        _check(receipt, "create_only_close", "fail", str(exc))
        return {
            "receipt_status": "blocked",
            "decision": "blocked",
            "blocked_reasons": ["terminal_close_conflict"],
            "error": str(exc),
        }
    except grabowski_operator_obligation.OperatorObligationError as exc:
        raise GripActionError(str(exc)) from exc
    _check(receipt, "open_binding", "pass", output["open_file_sha256"])
    _check(receipt, "terminal_shape", "pass", output["state"])
    _check(receipt, "create_only_close", "pass", output["close_file_sha256"])
    _check(
        receipt,
        "response_end_decision",
        "pass",
        f"response_may_end={str(output['response_may_end']).lower()}; work_complete={str(output['work_complete']).lower()}",
    )
    return {**output, "receipt_status": "passed"}


def _run_captain_preflight(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    return grabowski_grip_orchestration.run_captain_preflight(sys.modules[__name__], spec, parameters, receipt, runner)


def _run_captain_run(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    return grabowski_grip_orchestration.run_captain_run(sys.modules[__name__], spec, parameters, receipt, runner, github_runner)


_RUNNERS = {
    "repo_orient": _run_repo_orient,
    "pr_check_readiness": _run_pr_check_readiness,
    "worktree_orient": _run_worktree_orient,
    "worktree_ensure": _run_worktree_ensure,
    "worktree_hygiene_reconcile": _run_worktree_hygiene_reconcile,
    "post_merge_sync": _run_post_merge_sync,
    "situation": _run_situation,
    "scout": _run_scout,
    "runtime_deploy_check": _run_runtime_deploy_check,
    "task_attention_decision": _run_task_attention_decision,
    "task_attention_reconciliation": _run_task_attention_reconciliation,
    "connector_snapshot_bind": _run_connector_snapshot_bind,
    "convergence_assess": _run_convergence_assess,
    "gate_evidence_preflight": _run_gate_evidence_preflight,
    "convergence_state_classify": _run_convergence_state_classify,
    "operator_obligation_open": _run_operator_obligation_open,
    "operator_obligation_list": _run_operator_obligation_list,
    "operator_obligation_status": _run_operator_obligation_status,
    "operator_obligation_close": _run_operator_obligation_close,
    "mechanic_loop": _run_mechanic_loop,
    "captain_preflight": _run_captain_preflight,
    "captain_run": _run_captain_run,
    "branch_publish": _run_branch_publish,
    "pr_create_or_update": _run_pr_create_or_update,
}


def run_grip(
    name: str,
    parameters: dict[str, Any] | None = None,
    *,
    allow_mutation: bool = False,
    command_runner: CommandRunner | None = None,
    github_runner: GithubRunner | None = None,
) -> dict[str, Any]:
    parameters = dict(parameters or {})
    spec = GRIP_SPECS.get(name)
    if spec is None:
        fallback = GripSpec(
            name=name,
            version="0",
            summary="unknown grip",
            effect=READ_ONLY,
            required_parameters=(),
            acceptance_ids=(),
            runner="unknown",
        )
        receipt = _new_receipt(fallback, parameters)
        _check(receipt, "known_grip", "fail", f"unknown grip: {name}")
        return _finish(receipt, "blocked", "preflight", {"error": f"unknown grip: {name}"})

    receipt = _new_receipt(spec, parameters)
    _check(receipt, "known_grip", "pass", spec.summary)
    try:
        _require_parameters(spec, parameters)
        _check(receipt, "required_parameters", "pass", ", ".join(spec.required_parameters))
        if spec.effect == MUTATING and not allow_mutation:
            _check(receipt, "mutation_allowed", "fail", "allow_mutation is false")
            output: dict[str, Any] = {
                "error": "mutating grip requires allow_mutation=true",
                "decision": "blocked",
                "blocked_reasons": ["mutation_permission_missing"],
                "requires_allow_mutation": True,
            }
            if spec.name == "captain-run":
                output["authority_contract"] = _captain_authority_contract("captain-run")
            return _finish(receipt, "blocked", "preflight", output)
        _check(receipt, "mutation_allowed", "pass", f"effect={spec.effect}")
        action = _RUNNERS[spec.runner]
        command = command_runner or _default_command_runner
        if spec.uses_github:
            output = action(
                spec,
                parameters,
                receipt,
                command,
                github_runner or _default_github_runner,
            )
        else:
            output = action(spec, parameters, receipt, command)
        final_status = "passed"
        if isinstance(output, dict):
            requested_status = output.get("receipt_status")
            if requested_status in {"passed", "blocked", "failed"}:
                final_status = requested_status
        return _finish(receipt, final_status, "action", output)
    except GripPreflightError as exc:
        return _finish(receipt, "blocked", "preflight", {"error": str(exc)})
    except GripActionError as exc:
        return _finish(receipt, "failed", "action", {"error": str(exc)})


def _surface_availability(spec: GripSpec, profile: str) -> dict[str, Any]:
    if spec.name not in GRIP_SURFACE_ALLOWLIST:
        return {
            "available": False,
            "reason": "not exposed by grip surface allowlist",
            "requires_allow_mutation": False,
        }
    if spec.name in GRIP_SURFACE_CAPTAIN_ONLY and profile != "captain":
        return {
            "available": False,
            "reason": f"profile {profile} cannot run captain-only grips",
            "requires_allow_mutation": False,
        }
    if spec.effect == MUTATING and profile not in GRIP_SURFACE_MUTATING_PROFILES:
        return {
            "available": False,
            "reason": f"profile {profile} cannot run mutating grips",
            "requires_allow_mutation": True,
        }
    return {
        "available": True,
        "reason": "allowed by current grip surface profile",
        "requires_allow_mutation": spec.effect == MUTATING,
    }


def _surface_grip_contract(spec: GripSpec, profile: str) -> dict[str, Any]:
    availability = _surface_availability(spec, profile)
    required = ", ".join(spec.required_parameters) or "none"
    return {
        "name": spec.name,
        "version": spec.version,
        "summary": spec.summary,
        "purpose": spec.summary,
        "target": GRIP_SURFACE_TARGETS.get(spec.name, "narrow Grabowski grip target"),
        "scope": "observation only" if spec.effect == READ_ONLY else "bounded write through a named grip runner",
        "effect": spec.effect,
        "effect_class": "read-only" if spec.effect == READ_ONLY else "mutating",
        "risk": GRIP_RISK_LEVELS.get(spec.name, "medium"),
        "recovery_path": GRIP_SURFACE_RECOVERY_PATHS[spec.effect],
        "preconditions": [
            f"required parameters: {required}",
            "grip name is present in GRIP_SURFACE_ALLOWLIST",
            "mutating grips require allow_mutation=true and an eligible profile",
        ],
        "required_parameters": list(spec.required_parameters),
        "acceptance_ids": list(spec.acceptance_ids),
        "uses_github": spec.uses_github,
        "profile": profile,
        "availability": availability,
        "expected_receipt_shape": {
            "kind": GRIP_RECEIPT_KIND,
            "schema_version": GRIP_RECEIPT_SCHEMA_VERSION,
            "required_top_level_fields": [
                "kind",
                "schema_version",
                "grip",
                "parameters_sha256",
                "status",
                "phase",
                "checks",
                "output",
            ],
            "mutating_receipt_contract": "mutating grips must return a blocked, failed or passed receipt; they may not bypass run_grip",
        },
    }


def grip_risk_level(name: str) -> str:
    return GRIP_RISK_LEVELS.get(name, "medium")


def _validate_surface_profile(profile: str) -> str:
    if profile not in GRIP_SURFACE_PROFILES:
        raise GripPreflightError(
            f"unknown grip surface profile: {profile}; expected one of {sorted(GRIP_SURFACE_PROFILES)}"
        )
    return profile


def list_grips(profile: str = "operator") -> list[dict[str, Any]]:
    profile = _validate_surface_profile(profile)
    return [
        _surface_grip_contract(spec, profile)
        for spec in sorted(GRIP_SPECS.values(), key=lambda item: item.name)
        if spec.name in GRIP_SURFACE_ALLOWLIST
    ]


def grip_list(profile: str = "operator") -> dict[str, Any]:
    profile = _validate_surface_profile(profile)
    return {
        "profile": profile,
        "allowlist": sorted(GRIP_SURFACE_ALLOWLIST),
        "grips": list_grips(profile),
        "non_claims": [
            "does not expose generic shell execution",
            "does not grant mutation without allow_mutation",
            "does not replace receipt review",
        ],
    }


def _blocked_surface_receipt(name: str, parameters: dict[str, Any], reason: str) -> dict[str, Any]:
    spec = GripSpec(
        name=name,
        version="0",
        summary="grip surface dispatch rejected",
        effect=READ_ONLY,
        required_parameters=(),
        acceptance_ids=("grip-run-allowlist",),
        runner="surface_reject",
    )
    receipt = _new_receipt(spec, parameters)
    _check(receipt, "surface_allowlist", "fail", reason)
    return _finish(receipt, "blocked", "preflight", {"error": reason})


def grip_run(
    name: str,
    parameters: dict[str, Any] | None = None,
    *,
    profile: str = "operator",
    allow_mutation: bool = False,
    command_runner: CommandRunner | None = None,
    github_runner: GithubRunner | None = None,
) -> dict[str, Any]:
    parameters = dict(parameters or {})
    try:
        profile = _validate_surface_profile(profile)
    except GripPreflightError as exc:
        return _blocked_surface_receipt(name, parameters, str(exc))
    spec = GRIP_SPECS.get(name)
    if spec is None or name not in GRIP_SURFACE_ALLOWLIST:
        return _blocked_surface_receipt(name, parameters, f"grip is not exposed by surface allowlist: {name}")
    availability = _surface_availability(spec, profile)
    if not availability["available"]:
        return _blocked_surface_receipt(name, parameters, str(availability["reason"]))
    return run_grip(
        name,
        parameters,
        allow_mutation=allow_mutation,
        command_runner=command_runner,
        github_runner=github_runner,
    )
