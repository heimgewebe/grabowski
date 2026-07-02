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
    "latest_complete_bundles": {
        "category": "knowledge",
        "purpose": "Read the curated latest-complete Lens and repoLens bundle registry.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "rlens_bundle_discover": {
        "category": "knowledge",
        "purpose": "Discover current rLens/repoLens bundles from the immutable local merges area.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "rlens_bundle_status": {
        "category": "knowledge",
        "purpose": "Read bounded manifest, health and sidecar status for one rLens bundle.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "rlens_freshness_check": {
        "category": "knowledge",
        "purpose": "Compare one rLens bundle commit with the current local repository HEAD.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "rlens_context_pack": {
        "category": "knowledge",
        "purpose": "Build a bounded rLens context pack for agent handoff and Bureau receipts.",
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
        "purpose": "Run Git in one repository with protected-main force-push protection.",
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
    "grabowski_friction_record": {
        "category": "operations-observability",
        "purpose": "Record one bounded operator-friction event for later analysis.",
        "risk_class": "medium",
        "effects": ["state-append", "audit-record"],
        "reversibility": "append-only-observation",
    },
    "grabowski_friction_summary": {
        "category": "operations-observability",
        "purpose": "Summarize recent bounded operator-friction events.",
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
{'grabowski_browser_worker_start': {'category': 'browser-worker',
                                    'purpose': 'Start an agent-owned browser with a loopback-only '
                                               'debugging endpoint.',
                                    'risk_class': 'high',
                                    'effects': ['process-start',
                                                'profile-create-or-use',
                                                'loopback-listener'],
                                    'reversibility': 'worker-stop'},
 'grabowski_browser_worker_status': {'category': 'browser-worker',
                                     'purpose': 'Observe one isolated browser worker and reconcile '
                                                'terminal leases.',
                                     'risk_class': 'low',
                                     'effects': ['state-refresh', 'possible-lease-release'],
                                     'reversibility': 'not-applicable'},
 'grabowski_browser_worker_stop': {'category': 'browser-worker',
                                   'purpose': 'Stop one isolated browser worker and clean '
                                              'ephemeral state.',
                                   'risk_class': 'medium',
                                   'effects': ['process-stop',
                                               'lease-release',
                                               'ephemeral-state-remove'],
                                   'reversibility': 'worker-restart'},
 'grabowski_browser_worker_list': {'category': 'browser-worker',
                                   'purpose': 'List isolated agent-owned browser workers.',
                                   'risk_class': 'low',
                                   'effects': [],
                                   'reversibility': 'not-applicable'},
 'grabowski_gui_worker_start': {'category': 'gui-worker',
                                'purpose': 'Start an argv-only GUI worker on an isolated Xvfb '
                                           'display.',
                                'risk_class': 'high',
                                'effects': ['process-start',
                                            'display-create',
                                            'ephemeral-state-create'],
                                'reversibility': 'worker-stop'},
 'grabowski_gui_worker_status': {'category': 'gui-worker',
                                 'purpose': 'Observe one isolated GUI worker and reconcile '
                                            'terminal leases.',
                                 'risk_class': 'low',
                                 'effects': ['state-refresh', 'possible-lease-release'],
                                 'reversibility': 'not-applicable'},
 'grabowski_gui_worker_stop': {'category': 'gui-worker',
                               'purpose': 'Stop one isolated GUI worker and clean ephemeral XDG '
                                          'state.',
                               'risk_class': 'medium',
                               'effects': ['process-stop',
                                           'lease-release',
                                           'ephemeral-state-remove'],
                               'reversibility': 'worker-restart'},
 'grabowski_gui_worker_list': {'category': 'gui-worker',
                               'purpose': 'List isolated GUI workers.',
                               'risk_class': 'low',
                               'effects': [],
                               'reversibility': 'not-applicable'}}

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
        "browser-worker",
        "gui-worker",
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
        "duplicate_tools": sorted(
            {name for name in names if names.count(name) > 1}
        ),
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
