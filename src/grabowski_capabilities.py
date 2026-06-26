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
        "purpose": "Reveal bounded secret text only with an exact SHA-256 precondition.",
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
}


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
    },
    "host-operations": {
        "context",
        "command",
        "service",
        "session",
        "process",
        "diagnostics",
        "privileged-reference",
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
