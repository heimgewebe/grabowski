#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Iterable


CATALOG_SCHEMA_VERSION = 1
CONTEXT_SCHEMA_VERSION = 1


TOOL_PROFILES: dict[str, dict[str, Any]] = {
    "grabowski_status": {
        "category": "context",
        "purpose": "Read policy, deployment provenance and the current bounded operating mode.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_context": {
        "category": "context",
        "purpose": "Return a task-oriented live operator context and explicit drift findings.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grip_list": {
        "category": "grip-surface",
        "purpose": "List allowlisted receipt-bound Grabowski grips with profile visibility and expected receipt shape.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grip_run": {
        "category": "grip-surface",
        "purpose": "Dispatch one allowlisted Grabowski grip and return its receipt-bound result.",
        "risk_class": "medium",
        "effects": ["grip-dispatch", "command-dependent"],
        "reversibility": "receipt-dependent",
    },
    "grabowski_list_directory": {
        "category": "filesystem",
        "purpose": "List one allowed directory without recursive traversal.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_stat": {
        "category": "filesystem",
        "purpose": "Read metadata and a content hash for one allowed path.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_read_text": {
        "category": "filesystem",
        "purpose": "Read bounded UTF-8 text and obtain a concurrency hash.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_secret_inspect": {
        "category": "secret",
        "purpose": "Inspect metadata and bounded listings under explicit secret roots without returning content.",
        "risk_class": "medium",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_secret_reveal": {
        "category": "secret",
        "purpose": "Break-glass reveal of bounded secret text with hash, justification and explicit context-exposure acknowledgement.",
        "risk_class": "high",
        "effects": ["secret-content-return"],
        "reversibility": "not-applicable",
    },
    "grabowski_secret_use": {
        "category": "secret",
        "purpose": "Run one argv-only command with a secret supplied through a file descriptor or restricted temporary path.",
        "risk_class": "high",
        "effects": ["process-start", "secret-use", "command-dependent"],
        "reversibility": "command-dependent",
    },
    "grabowski_secret_export": {
        "category": "secret",
        "purpose": "Create one local 0600 copy of a secret under configured export roots with a source hash precondition.",
        "risk_class": "high",
        "effects": ["secret-copy-create"],
        "reversibility": "manual-delete",
    },
    "grabowski_browser_profile_read": {
        "category": "secret",
        "purpose": "Read bounded browser profile metadata and text, with binary databases kept metadata-only.",
        "risk_class": "high",
        "effects": ["profile-content-return"],
        "reversibility": "not-applicable",
    },
    "grabowski_create_text": {
        "category": "filesystem",
        "purpose": "Create one new UTF-8 file atomically inside an allowed write root.",
        "risk_class": "medium",
        "effects": ["file-create"],
        "reversibility": "manual-or-git",
    },
    "grabowski_replace_text": {
        "category": "filesystem",
        "purpose": "Replace one UTF-8 file atomically after a hash precondition and retain a backup.",
        "risk_class": "medium",
        "effects": ["file-replace", "backup-create"],
        "reversibility": "backup-and-git",
    },
    "grabowski_remove_path": {
        "category": "filesystem",
        "purpose": "Remove one regular file or empty directory into quarantine after a typed precondition.",
        "risk_class": "medium",
        "effects": ["file-remove", "directory-remove", "quarantine-create"],
        "reversibility": "quarantine-restore",
    },
    "grabowski_restore_removed_path": {
        "category": "audit",
        "purpose": "Restore one path from an audited reversible filesystem removal.",
        "risk_class": "medium",
        "effects": ["file-create", "directory-create"],
        "reversibility": "new-remove-operation",
    },
    "grabowski_destroy_path": {
        "category": "filesystem",
        "purpose": "Irreversibly remove one regular file or empty directory with a separate explicit capability.",
        "risk_class": "high",
        "effects": ["file-delete", "directory-delete"],
        "reversibility": "irreversible",
    },
    "grabowski_rollback_text": {
        "category": "audit",
        "purpose": "Restore a quarantined preimage from an audited replace transaction.",
        "risk_class": "medium",
        "effects": ["file-replace", "backup-create"],
        "reversibility": "audit-rollback",
    },
    "grabowski_verify_audit": {
        "category": "audit",
        "purpose": "Verify the tamper-evident write audit hash chain.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_audit_query": {
        "category": "audit",
        "purpose": "Query bounded safe fields from the fully verified audit segment chain.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_audit_trace": {
        "category": "audit",
        "purpose": "Trace one exact audit anchor through bounded one-hop evidence correlations without claiming causality.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_audit_analyze": {
        "category": "audit",
        "purpose": "Compute bounded descriptive statistics from the fully verified audit segment chain.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "latest_complete_bundles": {
        "category": "knowledge",
        "purpose": "Read latest RepoGround publications with canonical catalog precedence.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_bundle_discover": {
        "category": "knowledge",
        "purpose": "Discover current RepoGround bundles from the canonical publication catalog.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_bundle_status": {
        "category": "knowledge",
        "purpose": "Read bounded manifest, health, and sidecar status for one RepoGround bundle.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_freshness_check": {
        "category": "knowledge",
        "purpose": "Compare one RepoGround bundle source commit with the current local repository HEAD.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_preflight": {
        "category": "knowledge",
        "purpose": "Run bounded RepoGround consumption preflight for a selected bundle.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_query": {
        "category": "knowledge",
        "purpose": "Run a bounded read-only RepoGround query and normalize snippets and ranges.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_query_existing_index": {
        "category": "knowledge",
        "purpose": "Query a prebuilt RepoGround index without refreshing or mutating the bundle.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_range_get": {
        "category": "knowledge",
        "purpose": "Resolve one bounded RepoGround range reference without refreshing source artifacts.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_context_pack": {
        "category": "knowledge",
        "purpose": "Build a bounded RepoGround context pack for agent handoff and Bureau receipts.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_context_compose": {
        "category": "knowledge",
        "purpose": "Compose deterministic diff-bound RepoGround change context under a hard context budget.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_find_symbol": {
        "category": "knowledge",
        "purpose": "Find bounded Python symbol definitions in an existing RepoGround bundle.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_get_callers": {
        "category": "knowledge",
        "purpose": "Read S1 callers while preserving unresolved references separately.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "repoground_get_callees": {
        "category": "knowledge",
        "purpose": "Read S1 callees while preserving S0 call sites separately.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_terminal_run": {
        "category": "command",
        "purpose": "Run one bounded non-interactive command as the current user.",
        "risk_class": "variable",
        "effects": ["command-dependent"],
        "reversibility": "command-dependent",
    },
    "grabowski_job_start": {
        "category": "command",
        "purpose": "Start a durable bounded background command as a transient user service.",
        "risk_class": "variable",
        "effects": ["process-start", "state-create", "command-dependent"],
        "reversibility": "job-cancel-and-command-dependent",
    },
    "grabowski_job_status": {
        "category": "command",
        "purpose": "Read durable metadata and current service state for one Grabowski job.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_job_notification_list": {
        "category": "command",
        "purpose": "List persistent operator-outbox receipts for completed durable jobs.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_job_notification_ack": {
        "category": "command",
        "purpose": "Acknowledge one exact persistent operator-outbox receipt.",
        "risk_class": "medium",
        "effects": ["state-create"],
        "reversibility": "receipt-retained",
    },
    "grabowski_job_logs": {
        "category": "command",
        "purpose": "Read redacted persistent output for one Grabowski job.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_job_cancel": {
        "category": "command",
        "purpose": "Stop one Grabowski-owned background job.",
        "risk_class": "medium",
        "effects": ["process-stop"],
        "reversibility": "restart-job",
    },
    "grabowski_git": {
        "category": "version-control",
        "purpose": "Run Git in one repository; generic push is limited to one explicit unprotected branch ref.",
        "risk_class": "variable",
        "effects": ["git-dependent"],
        "reversibility": "git-dependent",
    },
    "grabowski_git_branch": {
        "category": "version-control",
        "purpose": "Create or switch local branches through a typed, audited branch operation.",
        "risk_class": "medium",
        "effects": ["git-reference-change", "working-tree-switch"],
        "reversibility": "git-branch-switch",
    },
    "grabowski_checkout_inventory": {
        "category": "checkout-lifecycle",
        "purpose": "Return deterministic linked-checkout inventory with retention, task, process and resource coordination state.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_checkout_retain": {
        "category": "checkout-lifecycle",
        "purpose": "Assign explicit retention ownership to one temporary linked Git checkout.",
        "risk_class": "medium",
        "effects": ["state-create", "resource-lease"],
        "reversibility": "retention-update",
    },
    "grabowski_checkout_archive": {
        "category": "checkout-lifecycle",
        "purpose": "Archive one clean temporary linked Git checkout by creating durable recovery refs without deleting branches.",
        "risk_class": "medium",
        "effects": ["git-reference-create", "state-create", "resource-lease"],
        "reversibility": "git-worktree-add-from-recovery-ref",
    },
    "grabowski_checkout_cleanup": {
        "category": "checkout-lifecycle",
        "purpose": "Plan or apply cleanup for an archived linked checkout; apply requires a persisted dry run.",
        "risk_class": "high",
        "effects": ["working-tree-remove", "state-change", "resource-lease"],
        "reversibility": "git-worktree-add-from-recovery-ref",
    },
    "grabowski_github": {
        "category": "remote-version-control",
        "purpose": "Run GitHub CLI operations with output redaction.",
        "risk_class": "variable",
        "effects": ["remote-dependent"],
        "reversibility": "operation-dependent",
    },
    "grabowski_user_service": {
        "category": "service",
        "purpose": "Inspect or control one user-level systemd service.",
        "risk_class": "high",
        "effects": ["service-state-change"],
        "reversibility": "inverse-service-action",
    },
    "grabowski_tmux_list": {
        "category": "session",
        "purpose": "List tmux sessions visible to the current user.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_tmux_capture": {
        "category": "session",
        "purpose": "Read text from one tmux pane.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_tmux_send": {
        "category": "session",
        "purpose": "Send literal input to one tmux pane, optionally followed by Enter.",
        "risk_class": "high",
        "effects": ["interactive-input", "command-dependent"],
        "reversibility": "command-dependent",
    },
    "grabowski_process_list": {
        "category": "process",
        "purpose": "List current-user processes with optional regular-expression filtering.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_process_signal": {
        "category": "process",
        "purpose": "Signal one process owned by the current user.",
        "risk_class": "high",
        "effects": ["process-signal", "possible-process-stop"],
        "reversibility": "usually-not-reversible",
    },
    "grabowski_ports": {
        "category": "diagnostics",
        "purpose": "List listening TCP and UDP sockets.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_privileged_action_reference": {
        "category": "privileged-reference",
        "purpose": "Create a non-executable reference contract for a future external privileged action.",
        "risk_class": "medium",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_power_run": {
        "category": "privileged-execution",
        "purpose": "Run one audited root command through the recovery-gated power broker.",
        "risk_class": "critical",
        "effects": ["root-command-dependent", "host-state-change"],
        "reversibility": "command-dependent-with-recovery-evidence",
    },
    "grabowski_fleet_list": {
        "category": "fleet",
        "purpose": "Return the validated local and SSH host registry.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_fleet_run": {
        "category": "fleet",
        "purpose": "Run one bounded argv command on one registered local or SSH host.",
        "risk_class": "variable",
        "effects": ["remote-command-dependent"],
        "reversibility": "command-dependent",
    },
    "grabowski_juno_status": {
        "category": "device-worker",
        "purpose": "Read bounded health and job evidence from the paired Juno device worker.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_juno_pair": {
        "category": "device-worker",
        "purpose": "Pair one exact Juno session after local consent and explicit escalation.",
        "risk_class": "high",
        "effects": [
            "device-key-create",
            "local-secret-create-or-replace",
            "receipt-create",
        ],
        "reversibility": "remove-both-pairing-files-and-restart",
    },
    "grabowski_juno_run": {
        "category": "device-worker",
        "purpose": "Run one bounded digest-bound job on the paired Juno device worker.",
        "risk_class": "high",
        "effects": ["device-job-execute", "device-state-change", "receipt-create"],
        "reversibility": "job-dependent-with-local-stop-switch",
    },
    "ipad_capability_manifest": {
        "category": "device-storage",
        "purpose": "Return the bounded iPad/Juno storage capability manifest without exposing bookmark bytes.",
        "risk_class": "medium",
        "effects": ["device-job-execute", "receipt-create"],
        "reversibility": "not-applicable-device-job-and-receipt-retained",
    },
    "ipad_storage_inventory": {
        "category": "device-storage",
        "purpose": "Inventory current Juno sandbox paths and user-granted document-provider scopes.",
        "risk_class": "medium",
        "effects": ["device-job-execute", "receipt-create"],
        "reversibility": "not-applicable-device-job-and-receipt-retained",
    },
    "ipad_storage_grant_status": {
        "category": "device-storage",
        "purpose": "Observe exact grant identity, provider hint, path evidence and recorded limitations.",
        "risk_class": "medium",
        "effects": ["device-job-execute", "receipt-create"],
        "reversibility": "not-applicable-device-job-and-receipt-retained",
    },
    "ipad_permission_probe": {
        "category": "device-storage",
        "purpose": "Verify that one exact grant, evidence hash, provider and agent instance still resolve.",
        "risk_class": "medium",
        "effects": ["device-job-execute", "receipt-create"],
        "reversibility": "not-applicable-device-job-and-receipt-retained",
    },
    "ipad_file_stat": {
        "category": "device-storage",
        "purpose": "Stat one exact granted iPad path without reading file contents.",
        "risk_class": "medium",
        "effects": ["device-job-execute", "receipt-create"],
        "reversibility": "not-applicable-device-job-and-receipt-retained",
    },
    "ipad_directory_list": {
        "category": "device-storage",
        "purpose": "List one granted directory without recursive traversal or content transfer.",
        "risk_class": "medium",
        "effects": ["device-job-execute", "receipt-create"],
        "reversibility": "not-applicable-device-job-and-receipt-retained",
    },
    "ipad_file_read": {
        "category": "device-storage",
        "purpose": "Read one exact granted iPad file with size and SHA-256 evidence.",
        "risk_class": "high",
        "effects": [
            "device-job-execute",
            "device-file-content-return",
            "receipt-create",
        ],
        "reversibility": "not-applicable-device-job-and-receipt-retained",
    },
    "ipad_file_create": {
        "category": "device-storage",
        "purpose": "Create one create-only file bound to agent instance, grant evidence, provider, path and payload hash.",
        "risk_class": "high",
        "effects": ["device-job-execute", "device-file-create", "receipt-create"],
        "reversibility": "manual-exact-file-removal-not-exposed",
    },
    "ipad_file_replace": {
        "category": "device-storage",
        "purpose": "Perform one hash-bound same-directory replace with immediate preimage recheck and post-readback inside one exact locally granted scope.",
        "risk_class": "high",
        "effects": [
            "device-job-execute",
            "device-file-replace",
            "temporary-file-create",
            "receipt-create",
        ],
        "reversibility": "preimage-dependent-not-automatically-retained",
    },
    "grabowski_operation_list": {
        "category": "operation",
        "purpose": "List validated named multi-step operations.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_operation_plan": {
        "category": "operation",
        "purpose": "Render a named operation and rollback path without executing it.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_operation_run": {
        "category": "operation",
        "purpose": "Run a named preflight/action/postflight operation with rollback after failure.",
        "risk_class": "high",
        "effects": ["multi-host-command-dependent", "rollback-possible"],
        "reversibility": "recipe-dependent",
    },
    "grabowski_privileged_broker_status": {
        "category": "privileged-reference",
        "purpose": "Inspect the root-owned privileged broker installation without executing it.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_recovery_status": {
        "category": "recovery",
        "purpose": "Evaluate the fail-closed recovery gate for power-worker activation.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_recovery_server_probe": {
        "category": "recovery",
        "purpose": "Produce fresh server recovery evidence.",
        "risk_class": "high",
        "effects": ["recovery-marker-write"],
        "reversibility": "new-snapshot-retained",
    },
    "grabowski_operator_blockade_status": {
        "category": "recovery",
        "purpose": "Evaluate scoped typed, legacy and environment blockades for one action context.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_operator_blockade_engage": {
        "category": "recovery",
        "purpose": "Create one canonical typed operator blockade through the dedicated create-only lifecycle.",
        "risk_class": "high",
        "effects": ["blockade-marker-create", "audit-record"],
        "reversibility": "evidence-bound-disarm",
    },
    "grabowski_operator_blockade_disarm": {
        "category": "recovery",
        "purpose": "Quarantine one exact typed blockade after live audit, deployment, recovery and broker evidence passes.",
        "risk_class": "high",
        "effects": ["blockade-marker-quarantine", "audit-record"],
        "reversibility": "hash-bound-restore-on-failure",
    },
    "grabowski_operator_blockade_migrate_legacy": {
        "category": "recovery",
        "purpose": "Migrate one exact typed legacy blockade into the root-owned authority domain without opening a mutation gap.",
        "risk_class": "high",
        "effects": ["blockade-marker-create", "blockade-marker-remove", "audit-record"],
        "reversibility": "create-first-fail-closed-dual-marker",
    },
    "grabowski_friction_record": {
        "category": "operations-observability",
        "purpose": "Record one bounded operator-friction event for later analysis.",
        "risk_class": "medium",
        "effects": ["state-append", "audit-record"],
        "reversibility": "append-only-observation",
    },
    "grabowski_friction_resolve": {
        "category": "operations-observability",
        "purpose": "Append evidence-bound closeout decisions for friction events or classes without rewriting history.",
        "risk_class": "medium",
        "effects": ["state-append", "audit-record"],
        "reversibility": "append-only-decision",
    },
    "grabowski_friction_summary": {
        "category": "operations-observability",
        "purpose": "Summarize recent bounded operator-friction events.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_execution_shape": {
        "category": "operations-observability",
        "purpose": "Recommend one bounded execution shape from typed inputs and evidence-bound friction fingerprints without executing it.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_execution_outcome_record": {
        "category": "operations-observability",
        "purpose": "Append secret-free predicted-versus-actual routing outcomes for shadow evaluation.",
        "risk_class": "medium",
        "effects": ["state-append", "audit-record"],
        "reversibility": "append-only-observation",
    },
    "grabowski_execution_governor_summary": {
        "category": "operations-observability",
        "purpose": "Summarize evidence thresholds, time decay and circuit-breaker state without enabling live routing.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_agent_bootstrap": {
        "category": "operations-observability",
        "purpose": "Return a release-evidence-bound adaptive agent entry capsule without authorizing execution.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_call_shape_check": {
        "category": "operations-observability",
        "purpose": "Deterministically lint one proposed tool-call shape before execution.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_connector_transport_diagnostics": {
        "category": "operations-observability",
        "purpose": "Run bounded read-only diagnostics for connector transport failures.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_operator_recall_export": {
        "category": "operations-observability",
        "purpose": "Export evidence-ref-bound operator recall items from caller-supplied receipt, PR, Bureau task and friction records without verifying source truth.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_task_start": {
        "category": "task",
        "purpose": "Start a persistent local or fleet task in its own systemd unit.",
        "risk_class": "variable",
        "effects": ["process-start", "state-create", "command-dependent"],
        "reversibility": "cancel-or-command-dependent",
    },
    "grabowski_task_status": {
        "category": "task",
        "purpose": "Observe one persistent task and refresh its recorded state.",
        "risk_class": "low",
        "effects": ["state-refresh"],
        "reversibility": "not-applicable",
    },
    "grabowski_task_logs": {
        "category": "task",
        "purpose": "Read redacted journal output for one local or fleet task.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_task_cancel": {
        "category": "task",
        "purpose": "Stop one task process group while retaining its persistent record.",
        "risk_class": "medium",
        "effects": ["process-stop", "state-change"],
        "reversibility": "resume-policy-dependent",
    },
    "grabowski_task_resume": {
        "category": "task",
        "purpose": "Recreate a missing or stopped task unit from its persistent record.",
        "risk_class": "variable",
        "effects": ["process-start", "state-change", "command-dependent"],
        "reversibility": "cancel-or-command-dependent",
    },
    "grabowski_task_list": {
        "category": "task",
        "purpose": "List recent persistent task records with optional state filtering.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_task_archive_list": {
        "category": "task-archive",
        "purpose": "List immutable task archive segments through a bounded manifest-verified catalog.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_task_archive_read": {
        "category": "task-archive",
        "purpose": "Read one fully integrity-verified immutable task archive segment with bounded pagination.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_task_reconcile_check": {
        "category": "task",
        "purpose": "Preview reconcile effects for persistent task records without mutating state.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_task_reconcile_refresh": {
        "category": "task",
        "purpose": "Refresh persistent task records and release terminal leases without resuming processes.",
        "risk_class": "medium",
        "effects": ["state-refresh", "lease-release"],
        "reversibility": "conditional",
    },
    "grabowski_task_reconcile_resume": {
        "category": "task",
        "purpose": "Resume bounded retry-safe tasks after reconcile verification.",
        "risk_class": "high",
        "effects": ["state-refresh", "lease-release", "possible-process-start"],
        "reversibility": "conditional",
    },
    "grabowski_task_reconcile": {
        "category": "task",
        "purpose": "Legacy compatibility entrypoint; refreshes state only and never resumes processes.",
        "risk_class": "medium",
        "effects": ["state-refresh", "lease-release"],
        "reversibility": "conditional",
    },
    "grabowski_resource_nonconflict_assess": {
        "category": "resource",
        "purpose": "Assess and audit complete, attested same-repository scopes; issue a short hash-bound proof only when every conflict axis is disjoint.",
        "risk_class": "medium",
        "effects": ["audit-append", "proof-issue"],
        "reversibility": "proof-expiry",
    },
    "grabowski_resource_reconcile_obsolete_path_leases": {
        "category": "resource",
        "purpose": "Release only unchanged exact path leases after an authoritative workspace-close or current successful durable-task outcome proves terminal owner work.",
        "risk_class": "high",
        "effects": ["lease-remove", "audit-append", "terminal-evidence-verify"],
        "reversibility": "resource-reacquire",
    },
    "grabowski_resource_acquire": {
        "category": "resource",
        "purpose": "Atomically acquire typed resource leases for one owner.",
        "risk_class": "medium",
        "effects": ["lease-create", "possible-expired-lease-reclaim"],
        "reversibility": "resource-release",
    },
    "grabowski_resource_renew": {
        "category": "resource",
        "purpose": "Renew live resource leases owned by one owner.",
        "risk_class": "medium",
        "effects": ["lease-update"],
        "reversibility": "lease-expiry-or-release",
    },
    "grabowski_resource_release": {
        "category": "resource",
        "purpose": "Release owner-bound resource leases with an explicit force override.",
        "risk_class": "high",
        "effects": ["lease-remove", "possible-force-release"],
        "reversibility": "resource-reacquire",
    },
    "grabowski_resource_inspect": {
        "category": "resource",
        "purpose": "Inspect one typed resource lease without returning private metadata.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_resource_list": {
        "category": "resource",
        "purpose": "List bounded typed resource leases with optional owner filtering.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_artifact_stat": {
        "category": "artifact",
        "purpose": "Read regular-file size and SHA-256 on one registered fleet host.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_artifact_push": {
        "category": "artifact",
        "purpose": "Push one hash-bound regular file to a registered SSH fleet host.",
        "risk_class": "high",
        "effects": ["remote-file-create-or-replace", "temporary-file-create"],
        "reversibility": "destination-preimage-dependent",
    },
    "grabowski_artifact_pull": {
        "category": "artifact",
        "purpose": "Pull one hash-bound regular file from a registered SSH fleet host.",
        "risk_class": "high",
        "effects": ["local-file-create-or-replace", "temporary-file-create"],
        "reversibility": "destination-preimage-dependent",
    },
}


TOOL_PROFILES.update(
    {
        "grabowski_browser_worker_start": {
            "category": "browser-worker",
            "purpose": "Start an agent-owned browser with a loopback-only "
            "debugging endpoint.",
            "risk_class": "high",
            "effects": ["process-start", "profile-create-or-use", "loopback-listener"],
            "reversibility": "worker-stop",
        },
        "grabowski_browser_worker_stored_form_action": {
            "category": "browser-worker",
            "purpose": "Use browser-managed stored form data on one exact local-device origin without returning field contents.",
            "risk_class": "high",
            "effects": ["browser-input", "form-submit", "local-device-state-change"],
            "reversibility": "target-dependent; fields cleared on failed or unobserved submission",
        },
        "grabowski_browser_worker_status": {
            "category": "browser-worker",
            "purpose": "Observe one isolated browser worker and reconcile "
            "terminal leases.",
            "risk_class": "low",
            "effects": ["state-refresh", "possible-lease-release"],
            "reversibility": "not-applicable",
        },
        "grabowski_browser_worker_stop": {
            "category": "browser-worker",
            "purpose": "Stop one isolated browser worker and clean ephemeral state.",
            "risk_class": "medium",
            "effects": ["process-stop", "lease-release", "ephemeral-state-remove"],
            "reversibility": "worker-restart",
        },
        "grabowski_browser_worker_list": {
            "category": "browser-worker",
            "purpose": "List current or historical browser workers with fresh read-only active observation.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_gui_worker_start": {
            "category": "gui-worker",
            "purpose": "Start an argv-only GUI worker on an isolated Xvfb display.",
            "risk_class": "high",
            "effects": ["process-start", "display-create", "ephemeral-state-create"],
            "reversibility": "worker-stop",
        },
        "grabowski_gui_worker_status": {
            "category": "gui-worker",
            "purpose": "Observe one isolated GUI worker and reconcile terminal leases.",
            "risk_class": "low",
            "effects": ["state-refresh", "possible-lease-release"],
            "reversibility": "not-applicable",
        },
        "grabowski_gui_worker_stop": {
            "category": "gui-worker",
            "purpose": "Stop one isolated GUI worker and clean ephemeral XDG state.",
            "risk_class": "medium",
            "effects": ["process-stop", "lease-release", "ephemeral-state-remove"],
            "reversibility": "worker-restart",
        },
        "grabowski_gui_worker_list": {
            "category": "gui-worker",
            "purpose": "List current or historical GUI workers with fresh read-only active observation.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
    }
)


TOOL_PROFILES.update(
    {
        "grabowski_runtime_health": {
            "category": "context",
            "purpose": "Read minimal deployment, audit and kill-switch health without path inventories.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_deployment_identity": {
            "category": "context",
            "purpose": "Read bounded runtime identity and integrity flags without local paths.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_contract_drift": {
            "category": "context",
            "purpose": "Read bounded runtime-contract and capability-catalog drift.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_checkout_summary": {
            "category": "version-control",
            "purpose": "Read a bounded summary of Grabowski repository worktrees.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_git_status": {
            "category": "version-control",
            "purpose": "Read fixed short Git status for one allowed repository.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_git_diff": {
            "category": "version-control",
            "purpose": "Read a bounded staged or unstaged Git diff without external helpers.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_git_log": {
            "category": "version-control",
            "purpose": "Read a bounded fixed-format Git commit log.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_git_show": {
            "category": "version-control",
            "purpose": "Read one bounded Git revision without external diff or textconv helpers.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_github_pr_view": {
            "category": "remote-version-control",
            "purpose": "Read bounded GitHub pull-request metadata without body or comments.",
            "risk_class": "low",
            "effects": ["remote-read"],
            "reversibility": "not-applicable",
        },
        "grabowski_github_checks": {
            "category": "remote-version-control",
            "purpose": "Read bounded GitHub pull-request check results.",
            "risk_class": "low",
            "effects": ["remote-read"],
            "reversibility": "not-applicable",
        },
        "grabowski_service_status": {
            "category": "service",
            "purpose": "Read a fixed property set for one user-level systemd unit.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_service_logs": {
            "category": "service",
            "purpose": "Read bounded redacted journal lines for one user-level systemd unit.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
    }
)


TOOL_PROFILES.update(
    {
        "grabowski_runtime_deploy_schedule": {
            "category": "deployment",
            "purpose": "Schedule a validated delayed deployment from the canonical main checkout.",
            "risk_class": "high",
            "effects": [
                "background-job-start",
                "runtime-deploy",
                "service-restart",
                "remote-package-read",
            ],
            "reversibility": "deployment-rollback",
        },
    }
)


TOOL_PROFILES.update(
    {
        "grabowski_agent_workspace_create": {
            "category": "agent-workspace",
            "purpose": "Create one explicitly requested advisory contrast workspace while ChatGPT/Grabowski remains the authoritative writer.",
            "risk_class": "high",
            "effects": [
                "worktree-create",
                "branch-create",
                "task-start",
                "tmux-session-create",
                "lease-create",
            ],
            "reversibility": "close-and-preserved-worktree",
        },
        "grabowski_agent_workspace_status": {
            "category": "agent-workspace",
            "purpose": "Derive workspace state from Grabowski tasks, Git and tmux without treating pane state as success.",
            "risk_class": "low",
            "effects": ["task-state-refresh"],
            "reversibility": "not-applicable",
        },
        "grabowski_agent_workspace_attach": {
            "category": "agent-workspace",
            "purpose": "Return the exact attach command for an existing non-authoritative tmux workspace UI.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_agent_workspace_collect": {
            "category": "agent-workspace",
            "purpose": "Freeze advisory contrast evidence, run read-only tests and review, and write a head- and diff-bound receipt.",
            "risk_class": "high",
            "effects": ["task-start", "receipt-create", "task-state-refresh"],
            "reversibility": "preserved-worktree-and-receipts",
        },
        "grabowski_agent_workspace_role_retry": {
            "category": "agent-workspace",
            "purpose": "Retry one collected-but-not-closed read-only role once with an explicit replacement command bound to the frozen writer snapshot.",
            "risk_class": "high",
            "effects": ["task-start", "receipt-create", "task-state-refresh"],
            "reversibility": "preserved-worktree-and-receipts",
        },
        "grabowski_agent_workspace_writer_handoff": {
            "category": "agent-workspace",
            "purpose": "Start one operator-bound replacement contrast writer after a proven terminal failure without granting authoritative writer status.",
            "risk_class": "high",
            "effects": ["task-start", "receipt-create", "task-state-refresh"],
            "reversibility": "preserved-worktree-and-receipts",
        },
        "grabowski_agent_workspace_close": {
            "category": "agent-workspace",
            "purpose": "Close one collected workspace while preserving its branch and writer worktree.",
            "risk_class": "high",
            "effects": [
                "possible-task-stop",
                "tmux-session-remove",
                "lease-release",
                "receipt-create",
            ],
            "reversibility": "preserved-worktree-and-branch",
        },
        "grabowski_agent_workspace_observe": {
            "category": "agent-workspace",
            "purpose": "Read one bounded immutable workspace event timeline and emit a facts/inferences/proposals process report.",
            "risk_class": "low",
            "effects": ["task-state-refresh"],
            "reversibility": "not-applicable",
        },
        "grabowski_agent_workspace_optimize": {
            "category": "agent-workspace",
            "purpose": "Derive advisory cross-workspace optimization proposals from at least two immutable reports.",
            "risk_class": "low",
            "effects": ["task-state-refresh"],
            "reversibility": "not-applicable",
        },
        "grabowski_agent_workspace_cleanup_plan": {
            "category": "agent-workspace",
            "purpose": "Inventory closed workspace checkout cleanup eligibility while preserving manifests, receipts and event logs.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_agent_workspace_reconcile_stale": {
            "category": "agent-workspace",
            "purpose": "Mark one provably inactive stale workspace abandoned without stopping tasks, releasing resources or removing its checkout.",
            "risk_class": "high",
            "effects": ["receipt-create", "workspace-event-append", "audit-append"],
            "reversibility": "historical-evidence-retained",
        },
        "grabowski_agent_workspace_reconcile_idle_tmux": {
            "category": "agent-workspace",
            "purpose": (
                "Remove only the exact non-authoritative idle tmux session from one "
                "provably inactive stale workspace, then invoke the existing "
                "non-destructive stale reconciliation."
            ),
            "risk_class": "high",
            "effects": [
                "audit-append",
                "receipt-create",
                "tmux-session-remove",
                "workspace-event-append",
            ],
            "reversibility": "historical-evidence-retained",
        },
        "grabowski_agent_workspace_cleanup": {
            "category": "agent-workspace",
            "purpose": "Create durable recovery refs and remove one eligible closed writer checkout without deleting workspace evidence.",
            "risk_class": "high",
            "effects": [
                "checkout-archive",
                "recovery-ref-create",
                "worktree-remove",
                "receipt-create",
            ],
            "reversibility": "restore-from-checkout-archive",
        },
        "grabowski_coding_agent_catalog": {
            "category": "agent-workspace",
            "purpose": "Read the validated canonical coding-model, harness, route and quota inventory without probing or executing external agents.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_coding_agent_route": {
            "category": "agent-workspace",
            "purpose": "Keep every authoritative implementation on grabowski-primary and rank external routes only for independent review.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_agent_execution_route": {
            "category": "agent-workspace",
            "purpose": "Return direct_operator for every authoritative task and optionally describe explicitly requested advisory contrast or competition candidates.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_agent_competition_start": {
            "category": "agent-workspace",
            "purpose": "Start one durable advisory-only external competitor or contrast programmer against a commit-bound context packet with a frozen runner and isolated provider workspace.",
            "risk_class": "medium",
            "effects": ["state-create", "durable-task-start", "external-model-call"],
            "reversibility": "task-cancel-and-state-retain",
        },
        "grabowski_agent_competition_status": {
            "category": "agent-workspace",
            "purpose": "Read one external candidate task and validate its immutable advisory receipt.",
            "risk_class": "low",
            "effects": ["task-state-refresh"],
            "reversibility": "not-applicable",
        },
        "grabowski_agent_competition_compare": {
            "category": "agent-workspace",
            "purpose": "Generate a deterministic contrast matrix, consensus signals and validation opportunities from exactly two bound external candidates.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
    }
)


TOOL_PROFILES.update(
    {
        "grabowski_bureau_candidate_record": {
            "category": "bureau",
            "purpose": "Record one source-bound candidate through Bureau's canonical append-only operator intake contract.",
            "risk_class": "medium",
            "effects": ["bureau_live_register_append", "private_adapter_artifact"],
            "reversibility": "append-only-domain-event",
        },
        "grabowski_bureau_candidate_assess": {
            "category": "bureau",
            "purpose": "Assess one Bureau candidate read-only against current Registry and Live Register truth.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_bureau_task_propose": {
            "category": "bureau",
            "purpose": "Create one immutable reviewed Bureau task proposal artifact without Registry or Queue mutation.",
            "risk_class": "medium",
            "effects": ["private_proposal_artifact"],
            "reversibility": "artifact-preserving",
        },
        "grabowski_bureau_task_review": {
            "category": "bureau",
            "purpose": "Review one exact Bureau proposal digest and create reviewed-plan approval evidence without Registry, Queue or publication mutation.",
            "risk_class": "medium",
            "effects": ["private_proposal_artifact"],
            "reversibility": "artifact-preserving-idempotent-review",
        },
        "grabowski_bureau_task_publish_preview": {
            "category": "bureau",
            "purpose": "Validate one Bureau task proposal and return exact publication resources without effects.",
            "risk_class": "low",
            "effects": [],
            "reversibility": "not-applicable",
        },
        "grabowski_bureau_task_publish": {
            "category": "bureau",
            "purpose": "Acquire exact short Bureau leases and publish one reviewed task branch and pull request with bounded readback.",
            "risk_class": "high",
            "effects": [
                "resource_lease",
                "git_branch",
                "remote_branch",
                "pull_request",
            ],
            "reversibility": "git-and-github-recovery",
        },
    }
)


PROFILE_CATEGORIES: dict[str, set[str] | None] = {
    "concise": None,
    "repository-work": {
        "context",
        "filesystem",
        "audit",
        "knowledge",
        "command",
        "version-control",
        "remote-version-control",
        "checkout-lifecycle",
        "fleet",
        "operation",
        "task",
        "recovery",
        "resource",
        "artifact",
        "bureau",
        "browser-worker",
        "gui-worker",
        "agent-workspace",
    },
    "host-operations": {
        "context",
        "command",
        "service",
        "session",
        "process",
        "diagnostics",
        "checkout-lifecycle",
        "privileged-reference",
        "fleet",
        "operation",
        "task",
        "recovery",
        "resource",
        "artifact",
        "browser-worker",
        "gui-worker",
    },
    "full": None,
}


def _fallback_profile(tool_name: str) -> dict[str, Any]:
    return {
        "category": "unclassified",
        "purpose": f"Unclassified capability for {tool_name}.",
        "risk_class": "unclassified",
        "effects": ["unknown"],
        "reversibility": "unknown",
    }


def capability_records(
    expected_tools: Iterable[str],
    *,
    descriptions: dict[str, str] | None = None,
    read_only: dict[str, bool] | None = None,
) -> list[dict[str, Any]]:
    description_map = descriptions or {}
    read_only_map = read_only or {}
    records: list[dict[str, Any]] = []
    for name in expected_tools:
        profile = dict(TOOL_PROFILES.get(name, _fallback_profile(name)))
        records.append(
            {
                "id": name,
                "tool": name,
                "purpose": profile.pop("purpose"),
                "description": description_map.get(name, ""),
                "read_only": read_only_map.get(name),
                **profile,
            }
        )
    return records


def classify_contract(expected_tools: Iterable[str]) -> dict[str, list[str]]:
    names = list(expected_tools)
    expected = set(names)
    catalogued = set(TOOL_PROFILES)
    return {
        "missing_profiles": sorted(expected - catalogued),
        "orphan_profiles": sorted(catalogued - expected),
        "duplicate_tools": sorted({name for name in names if names.count(name) > 1}),
    }


def filter_capabilities(
    records: list[dict[str, Any]],
    profile: str,
) -> list[dict[str, Any]]:
    if profile not in PROFILE_CATEGORIES:
        raise ValueError(f"profile must be one of {sorted(PROFILE_CATEGORIES)}")
    categories = PROFILE_CATEGORIES[profile]
    if categories is None:
        selected = records
    else:
        selected = [item for item in records if item["category"] in categories]
    if profile == "concise":
        return [
            {
                "tool": item["tool"],
                "category": item["category"],
                "purpose": item["purpose"],
                "risk_class": item["risk_class"],
            }
            for item in selected
        ]
    return selected
