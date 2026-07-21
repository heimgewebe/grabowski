#!/usr/bin/env python3
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
import base64
import fcntl
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import stat as statmod
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid

from mcp.server.fastmcp import FastMCP

try:
    from mcp.server.fastmcp import Context
except ImportError:
    fastmcp_module = sys.modules.get("mcp.server.fastmcp")
    if getattr(fastmcp_module, "__file__", None) is not None:
        raise
    Context = Any  # Isolated tests install an intentionally minimal module double.
from mcp.types import ToolAnnotations

import grabowski_consumer_surface as consumer_surface
import grabowski_client_snapshot
import grabowski_lifecycle_read_surface as lifecycle_read_surface
import grabowski_blockades as blockade_policy
import grabowski_blockade_store as blockade_store

import grabowski_grips
import grabowski_merge_guard
import grabowski_repoground_catalog as repoground_catalog

APP_NAME = "Grabowski"
DEPLOYMENT_MANIFEST_SCHEMA_VERSION = 6
RESERVED_DEPLOYMENT_SNAPSHOT_INPUTS = frozenset({
    "runtime-entrypoint.json",
    "runtime.in",
    "runtime.lock.txt",
})
AGENT_INSTRUCTIONS_SCHEMA_VERSION = 1
AGENT_INSTRUCTIONS_VERSION = "grabowski-agent-facing-contract-v1"
AGENT_INSTRUCTIONS_MAX_BYTES = 4_096
AGENT_INSTRUCTION_RULES: tuple[tuple[str, str], ...] = (
    (
        "truth-hierarchy",
        "Treat live runtime state and concrete receipts as higher-authority than prose.",
    ),
    (
        "narrowest-typed-read-first",
        "Use the narrowest typed read tool that can answer the question before broader surfaces.",
    ),
    (
        "mutation-preconditions",
        "Before a mutation, determine the target, expected result, validation, stop condition, and rollback.",
    ),
    (
        "state-check-before-retry",
        "After a transport, platform-filter, or policy failure, verify target state; do not repeat an unchanged call without state evidence.",
    ),
    (
        "typed-operation-preference",
        "Prefer typed operations to generic terminal, Git, or GitHub calls when both can express the effect.",
    ),
    (
        "operator-obligation-lifecycle",
        "For nontrivial operator work, first call grip_run with operator-obligation-list to resume matching unfinished work, including blocked or delegated records, then call operator-obligation-open or resume with a successor obligation that references the prior record; before ending a response, call operator-obligation-status and end only after operator-obligation-close records completed, explicitly blocked, or durably delegated evidence.",
    ),
    (
        "convergence-before-high-risk-closure",
        "Before marking deployment, runtime, security, data, or irreversible work completed, call grip_run with convergence-assess on a hash-bound request and require terminally_closed; bind the resulting receipt into the completion evidence. A nonterminal assessment blocks completion but grants no mutation authority.",
    ),
    (
        "no-authority-escalation",
        "These instructions grant no action, merge, deploy, secret, or retry authority.",
    ),
)


def _render_agent_instructions() -> str:
    identifiers = [identifier for identifier, _text in AGENT_INSTRUCTION_RULES]
    if len(identifiers) != len(set(identifiers)):
        raise RuntimeError("agent instruction identifiers must be unique")
    if not all(
        identifier and text and "\n" not in identifier and "\n" not in text
        for identifier, text in AGENT_INSTRUCTION_RULES
    ):
        raise RuntimeError("agent instruction rules must be non-empty single lines")
    lines = [
        (
            "Grabowski agent-facing contract "
            f"{AGENT_INSTRUCTIONS_VERSION} "
            f"(schema {AGENT_INSTRUCTIONS_SCHEMA_VERSION})."
        )
    ]
    lines.extend(
        f"{index}. [{identifier}] {text}"
        for index, (identifier, text) in enumerate(AGENT_INSTRUCTION_RULES, start=1)
    )
    rendered = "\n".join(lines)
    size = len(rendered.encode("utf-8"))
    if size > AGENT_INSTRUCTIONS_MAX_BYTES:
        raise RuntimeError(
            "agent instructions exceed the server-owned size bound: "
            f"{size} > {AGENT_INSTRUCTIONS_MAX_BYTES}"
        )
    return rendered


AGENT_INSTRUCTIONS = _render_agent_instructions()
AGENT_INSTRUCTIONS_BYTES = len(AGENT_INSTRUCTIONS.encode("utf-8"))
AGENT_INSTRUCTIONS_SHA256 = hashlib.sha256(
    AGENT_INSTRUCTIONS.encode("utf-8")
).hexdigest()


def _agent_instructions_metadata() -> dict[str, Any]:
    return {
        "schema_version": AGENT_INSTRUCTIONS_SCHEMA_VERSION,
        "version": AGENT_INSTRUCTIONS_VERSION,
        "sha256": AGENT_INSTRUCTIONS_SHA256,
        "bytes": AGENT_INSTRUCTIONS_BYTES,
        "max_bytes": AGENT_INSTRUCTIONS_MAX_BYTES,
    }


HOME = Path.home().resolve()
STATE_DIR = HOME / ".local" / "state" / "grabowski"
POLICY_PATH = HOME / ".config" / "grabowski" / "access.json"
AUDIT_LOG = STATE_DIR / "write-audit.jsonl"
QUARANTINE_DIR = STATE_DIR / "quarantine"
CANONICAL_KILL_SWITCH_PATH = Path(
    "/var/lib/grabowski/operator-blockade/operator-kill-switch"
)
KILL_SWITCH_PATH = CANONICAL_KILL_SWITCH_PATH
LEGACY_KILL_SWITCH_PATH = STATE_DIR / "operator-kill-switch"
BLOCKADE_AUTHORITY_UID = 0
BLOCKADE_MARKER_MODE = 0o644
BUNDLE_REGISTRY = STATE_DIR / "repoground-latest-complete-bundles.tsv"
REPOGROUND_PUBLICATION_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_REPOGROUND_PUBLICATION_ROOT",
        str(HOME / "repos" / "manifest-publications" / "bundles"),
    )
).expanduser()
MERGES_ROOT = HOME / "repos" / "merges"
AUDIT_SCHEMA_VERSION = 2
AUDIT_SEGMENT_SCHEMA_VERSION = 1
MAX_AUDIT_BYTES = 16 * 1024 * 1024
MAX_AUDIT_RECORD_BYTES = 128 * 1024
AUDIT_ROTATION_RESERVE_BYTES = 256 * 1024
MAX_AUDIT_SEGMENTS = 4096
MAX_AUDIT_EVIDENCE_BYTES = 1024 * 1024
MAX_AUDIT_SEGMENT_CACHE_ENTRIES = 256
AUDIT_APPEND_LOCK = threading.RLock()
AUDIT_SEGMENT_CACHE_LOCK = threading.RLock()
AUDIT_SEGMENT_VERIFICATION_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
AUDIT_LOCK_TIMEOUT_SECONDS = 5.0
AUDIT_LOCK_POLL_SECONDS = 0.02
BASE_CAPABILITIES = (
    "file_read",
    "file_write",
    "friction_record",
    "audit_verify",
    "rollback_text",
    "bundle_registry",
)
SECRET_CAPABILITIES = (
    "secret_inspect",
    "secret_reveal",
    "secret_use",
    "secret_export",
    "browser_profile_read",
)
OPERATOR_CAPABILITIES = (
    "terminal_execute",
    "durable_job",
    "git_cli",
    "github_cli",
    "user_service_control",
    "tmux_interaction",
    "process_inspect",
    "process_signal",
    "port_inspect",
    "privileged_reference",
    "power_execute",
    "resource_lease",
    "artifact_transfer",
    "browser_worker",
    "gui_worker",
)
RESERVED_DISABLED_CAPABILITIES = (
    "file_delete",
    "file_destroy",
    "file_move",
    "chmod",
    "chown",
    "secret_read",
)
ALL_CAPABILITIES = (
    BASE_CAPABILITIES
    + SECRET_CAPABILITIES
    + OPERATOR_CAPABILITIES
    + RESERVED_DISABLED_CAPABILITIES
)

TOOL_CAPABILITY_REQUIREMENTS = {
    "grabowski_status": (),
    "grabowski_context": (),
    "grip_list": ("file_read",),
    "grip_run": ("terminal_execute",),
    "grabowski_list_directory": ("file_read",),
    "grabowski_stat": ("file_read",),
    "grabowski_read_text": ("file_read",),
    "grabowski_secret_inspect": ("secret_inspect",),
    "grabowski_secret_reveal": ("secret_reveal",),
    "grabowski_secret_use": ("secret_use",),
    "grabowski_secret_export": ("secret_export",),
    "grabowski_browser_profile_read": ("browser_profile_read",),
    "grabowski_create_text": ("file_write",),
    "grabowski_replace_text": ("file_write",),
    "grabowski_remove_path": ("file_delete",),
    "grabowski_restore_removed_path": ("file_delete",),
    "grabowski_destroy_path": ("file_destroy",),
    "grabowski_rollback_text": ("rollback_text",),
    "grabowski_verify_audit": ("audit_verify",),
    "latest_complete_bundles": ("bundle_registry",),
    "repoground_bundle_discover": ("bundle_registry",),
    "repoground_bundle_status": ("bundle_registry",),
    "repoground_freshness_check": ("bundle_registry",),
    "repoground_preflight": ("bundle_registry",),
    "repoground_query": ("bundle_registry",),
    "repoground_query_existing_index": ("bundle_registry",),
    "repoground_range_get": ("bundle_registry",),
    "repoground_context_pack": ("bundle_registry",),
    "repoground_context_compose": ("bundle_registry",),
    "repoground_find_symbol": ("bundle_registry",),
    "repoground_get_callers": ("bundle_registry",),
    "repoground_get_callees": ("bundle_registry",),
    "grabowski_runtime_health": (),
    "grabowski_deployment_identity": (),
    "grabowski_contract_drift": (),
    "grabowski_checkout_summary": (),
    "grabowski_git_status": (),
    "grabowski_git_diff": (),
    "grabowski_git_log": (),
    "grabowski_git_show": (),
    "grabowski_github_pr_view": ("github_cli",),
    "grabowski_github_checks": ("github_cli",),
    "grabowski_service_status": ("user_service_control",),
    "grabowski_service_logs": ("user_service_control",),
    "grabowski_runtime_deploy_schedule": ("durable_job", "git_cli"),
    "grabowski_agent_workspace_create": (
        "durable_job",
        "git_cli",
        "resource_lease",
        "tmux_interaction",
    ),
    "grabowski_agent_workspace_status": ("durable_job", "git_cli", "tmux_interaction"),
    "grabowski_agent_workspace_attach": ("tmux_interaction",),
    "grabowski_agent_workspace_collect": ("durable_job", "git_cli"),
    "grabowski_agent_workspace_role_retry": ("durable_job", "git_cli"),
    "grabowski_agent_workspace_writer_handoff": ("durable_job", "git_cli", "resource_lease"),
    "grabowski_agent_workspace_close": (
        "durable_job",
        "resource_lease",
        "tmux_interaction",
    ),
    "grabowski_agent_workspace_observe": ("durable_job", "git_cli"),
    "grabowski_agent_workspace_optimize": ("durable_job", "git_cli"),
    "grabowski_agent_workspace_cleanup_plan": (
        "durable_job",
        "git_cli",
        "resource_lease",
        "tmux_interaction",
    ),
    "grabowski_agent_workspace_reconcile_stale": (
        "durable_job",
        "git_cli",
        "resource_lease",
        "tmux_interaction",
    ),
    "grabowski_agent_workspace_reconcile_idle_tmux": (
        "durable_job",
        "git_cli",
        "resource_lease",
        "tmux_interaction",
    ),
    "grabowski_agent_workspace_cleanup": ("git_cli", "resource_lease"),
    "grabowski_agent_execution_route": (),
    "grabowski_coding_agent_catalog": (),
    "grabowski_coding_agent_route": (),
    "grabowski_agent_competition_start": ("durable_job", "git_cli"),
    "grabowski_agent_competition_status": ("durable_job",),
    "grabowski_agent_competition_compare": ("durable_job",),
    "grabowski_terminal_run": ("terminal_execute",),
    "grabowski_job_start": ("durable_job",),
    "grabowski_job_status": ("durable_job",),
    "grabowski_job_notification_list": ("durable_job",),
    "grabowski_job_notification_ack": ("durable_job",),
    "grabowski_job_logs": ("durable_job",),
    "grabowski_job_cancel": ("durable_job",),
    "grabowski_git": ("git_cli",),
    "grabowski_git_branch": ("git_cli",),
    "grabowski_checkout_inventory": ("git_cli",),
    "grabowski_checkout_retain": ("git_cli", "resource_lease"),
    "grabowski_checkout_archive": ("git_cli", "resource_lease"),
    "grabowski_checkout_cleanup": ("git_cli", "resource_lease"),
    "grabowski_github": ("github_cli",),
    "grabowski_user_service": ("user_service_control",),
    "grabowski_tmux_list": ("tmux_interaction",),
    "grabowski_tmux_capture": ("tmux_interaction",),
    "grabowski_tmux_send": ("tmux_interaction",),
    "grabowski_process_list": ("process_inspect",),
    "grabowski_process_signal": ("process_signal",),
    "grabowski_ports": ("port_inspect",),
    "grabowski_privileged_action_reference": ("privileged_reference",),
    "grabowski_power_run": ("power_execute",),
    "grabowski_fleet_list": ("terminal_execute",),
    "grabowski_fleet_run": ("terminal_execute",),
    "grabowski_juno_status": ("terminal_execute",),
    "grabowski_juno_pair": ("terminal_execute",),
    "grabowski_juno_run": ("terminal_execute",),
    "ipad_capability_manifest": ("terminal_execute",),
    "ipad_storage_inventory": ("terminal_execute",),
    "ipad_storage_grant_status": ("terminal_execute",),
    "ipad_permission_probe": ("terminal_execute",),
    "ipad_file_stat": ("terminal_execute",),
    "ipad_directory_list": ("terminal_execute",),
    "ipad_file_read": ("terminal_execute",),
    "ipad_file_create": ("terminal_execute",),
    "ipad_file_replace": ("terminal_execute",),
    "grabowski_operation_list": ("terminal_execute",),
    "grabowski_operation_plan": ("terminal_execute",),
    "grabowski_operation_run": ("terminal_execute",),
    "grabowski_privileged_broker_status": ("privileged_reference",),
    "grabowski_task_start": ("durable_job",),
    "grabowski_task_status": ("durable_job",),
    "grabowski_task_logs": ("durable_job",),
    "grabowski_task_cancel": ("durable_job",),
    "grabowski_task_resume": ("durable_job",),
    "grabowski_task_list": ("durable_job",),
    "grabowski_task_archive_list": ("file_read",),
    "grabowski_task_archive_read": ("file_read",),
    "grabowski_task_reconcile_check": ("durable_job",),
    "grabowski_task_reconcile_refresh": ("durable_job",),
    "grabowski_task_reconcile_resume": ("durable_job",),
    "grabowski_recovery_status": ("audit_verify",),
    "grabowski_recovery_server_probe": ("file_write", "secret_use", "terminal_execute"),
    "grabowski_operator_blockade_status": ("audit_verify",),
    "grabowski_operator_blockade_engage": ("audit_verify", "file_write"),
    "grabowski_operator_blockade_disarm": ("audit_verify", "file_move"),
    "grabowski_operator_blockade_migrate_legacy": ("audit_verify", "file_move"),
    "grabowski_friction_record": ("friction_record",),
    "grabowski_friction_resolve": ("friction_record",),
    "grabowski_friction_summary": (),
    "grabowski_execution_shape": (),
    "grabowski_execution_outcome_record": ("friction_record",),
    "grabowski_execution_governor_summary": (),
    "grabowski_agent_bootstrap": (),
    "grabowski_call_shape_check": (),
    "grabowski_connector_transport_diagnostics": ("user_service_control",),
    "grabowski_operator_recall_export": (),
    "grabowski_resource_nonconflict_assess": ("resource_lease",),
    "grabowski_resource_reconcile_obsolete_path_leases": ("resource_lease",),
    "grabowski_resource_acquire": ("resource_lease",),
    "grabowski_resource_renew": ("resource_lease",),
    "grabowski_resource_release": ("resource_lease",),
    "grabowski_resource_inspect": ("resource_lease",),
    "grabowski_resource_list": ("resource_lease",),
    "grabowski_task_reconcile": ("durable_job",),
    "grabowski_artifact_stat": ("artifact_transfer",),
    "grabowski_artifact_push": ("artifact_transfer",),
    "grabowski_artifact_pull": ("artifact_transfer",),
    "grabowski_browser_worker_start": ("browser_worker",),
    "grabowski_browser_worker_stored_form_action": ("browser_worker",),
    "grabowski_browser_worker_status": ("browser_worker",),
    "grabowski_browser_worker_stop": ("browser_worker",),
    "grabowski_browser_worker_list": ("browser_worker",),
    "grabowski_gui_worker_start": ("gui_worker",),
    "grabowski_gui_worker_status": ("gui_worker",),
    "grabowski_gui_worker_stop": ("gui_worker",),
    "grabowski_gui_worker_list": ("gui_worker",),
    "grabowski_bureau_candidate_record": ("terminal_execute",),
    "grabowski_bureau_candidate_assess": (),
    "grabowski_bureau_task_propose": ("terminal_execute",),
    "grabowski_bureau_task_review": ("terminal_execute",),
    "grabowski_bureau_task_publish_preview": (),
    "grabowski_bureau_task_publish": ("resource_lease", "terminal_execute"),
}

OPERATOR_CAPABILITY_REQUIREMENT_TOOLS = {
    "grabowski_bureau_candidate_record",
    "grabowski_bureau_task_propose",
    "grabowski_bureau_task_review",
    "grabowski_bureau_task_publish",
    "grabowski_github_pr_view",
    "grabowski_github_checks",
    "grabowski_service_status",
    "grabowski_service_logs",
    "grabowski_runtime_deploy_schedule",
    "grabowski_agent_workspace_create",
    "grabowski_agent_workspace_status",
    "grabowski_agent_workspace_attach",
    "grabowski_agent_workspace_collect",
    "grabowski_agent_workspace_role_retry",
    "grabowski_agent_workspace_writer_handoff",
    "grabowski_agent_workspace_close",
    "grabowski_agent_workspace_observe",
    "grabowski_agent_workspace_optimize",
    "grabowski_agent_workspace_cleanup_plan",
    "grabowski_agent_workspace_reconcile_stale",
    "grabowski_agent_workspace_reconcile_idle_tmux",
    "grabowski_agent_workspace_cleanup",
    "grabowski_agent_competition_start",
    "grabowski_agent_competition_status",
    "grabowski_agent_competition_compare",
    "grabowski_terminal_run",
    "grabowski_job_start",
    "grabowski_job_status",
    "grabowski_job_notification_list",
    "grabowski_job_notification_ack",
    "grabowski_job_logs",
    "grabowski_job_cancel",
    "grabowski_git",
    "grabowski_git_branch",
    "grabowski_checkout_inventory",
    "grabowski_checkout_retain",
    "grabowski_checkout_archive",
    "grabowski_checkout_cleanup",
    "grabowski_github",
    "grabowski_user_service",
    "grabowski_tmux_list",
    "grabowski_tmux_capture",
    "grabowski_tmux_send",
    "grabowski_process_list",
    "grabowski_process_signal",
    "grabowski_ports",
    "grabowski_privileged_action_reference",
    "grabowski_power_run",
    "grabowski_fleet_list",
    "grabowski_fleet_run",
    "grabowski_juno_status",
    "grabowski_juno_pair",
    "grabowski_juno_run",
    "ipad_capability_manifest",
    "ipad_storage_inventory",
    "ipad_storage_grant_status",
    "ipad_permission_probe",
    "ipad_file_stat",
    "ipad_directory_list",
    "ipad_file_read",
    "ipad_file_create",
    "ipad_file_replace",
    "grabowski_operation_list",
    "grabowski_operation_plan",
    "grabowski_operation_run",
    "grabowski_privileged_broker_status",
    "grabowski_connector_transport_diagnostics",
    "grabowski_task_start",
    "grabowski_task_status",
    "grabowski_task_logs",
    "grabowski_task_cancel",
    "grabowski_task_resume",
    "grabowski_task_list",
    "grabowski_task_reconcile_check",
    "grabowski_task_reconcile_refresh",
    "grabowski_task_reconcile_resume",
    "grabowski_resource_nonconflict_assess",
    "grabowski_resource_reconcile_obsolete_path_leases",
    "grabowski_resource_acquire",
    "grabowski_resource_renew",
    "grabowski_resource_release",
    "grabowski_resource_inspect",
    "grabowski_resource_list",
    "grabowski_task_reconcile",
    "grabowski_artifact_stat",
    "grabowski_artifact_push",
    "grabowski_artifact_pull",
    "grabowski_browser_worker_start",
    "grabowski_browser_worker_stored_form_action",
    "grabowski_browser_worker_status",
    "grabowski_browser_worker_stop",
    "grabowski_browser_worker_list",
    "grabowski_gui_worker_start",
    "grabowski_gui_worker_status",
    "grabowski_gui_worker_stop",
    "grabowski_gui_worker_list",
}
DEFAULT_SECRET_USE_TIMEOUT_SECONDS = 30
DEFAULT_SECRET_USE_OUTPUT_BYTES = 250_000
SECRET_FD_PLACEHOLDER = "{SECRET_FD_PATH}"
SHELL_EXECUTABLES = {"sh", "bash", "dash", "zsh", "ksh", "fish"}
SECRET_USE_ENV_ALLOWLIST = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "TERM",
    "TZ",
}
SESSION_RISK_LEVELS = ("low", "medium", "high")
SESSION_RISK_ORDER = {name: index for index, name in enumerate(SESSION_RISK_LEVELS)}
SESSION_ESCALATION_MAX_SECONDS = 7 * 24 * 60 * 60


SENSITIVE_ENV_PARTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "COOKIE",
    "CREDENTIAL",
    "AUTHORIZATION",
    "API_KEY",
    "APIKEY",
)
TOP_LEVEL_POLICY_FIELDS = {
    "version",
    "mode",
    "active_profile",
    "read_roots",
    "write_roots",
    "write_excluded_roots",
    "secret_roots",
    "browser_profile_roots",
    "secret_export_roots",
    "max_read_bytes",
    "max_write_bytes",
    "max_list_entries",
    "max_secret_use_output_bytes",
    "max_secret_use_seconds",
    "forbid_symlinks",
    "forbidden_components",
    "forbidden_file_patterns",
    "forbidden_capabilities",
    "forbidden_hosts",
    "allowed_grips",
    "max_risk_level",
    "capability_definitions",
    "profiles",
    "trusted_owner",
}
PROFILE_POLICY_FIELDS = {
    "description",
    "read_roots",
    "write_roots",
    "write_excluded_roots",
    "secret_roots",
    "browser_profile_roots",
    "secret_export_roots",
    "max_read_bytes",
    "max_write_bytes",
    "max_list_entries",
    "max_secret_use_output_bytes",
    "max_secret_use_seconds",
    "capabilities",
    "allowed_grips",
    "forbidden_hosts",
    "max_risk_level",
    "trusted_owner",
}
ROOT_LIST_FIELDS = {
    "read_roots",
    "write_roots",
    "write_excluded_roots",
    "secret_roots",
    "browser_profile_roots",
    "secret_export_roots",
}
V2_ONLY_POLICY_FIELDS = {
    "secret_roots",
    "browser_profile_roots",
    "secret_export_roots",
    "max_secret_use_output_bytes",
    "max_secret_use_seconds",
}
LIMIT_FIELDS = {
    "max_read_bytes",
    "max_write_bytes",
    "max_list_entries",
    "max_secret_use_output_bytes",
    "max_secret_use_seconds",
}
_SECRET_KEY_PREFIX = "s" + "k-"
_OPENAI_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"(?:(?:proj|svcacct|admin)-[A-Za-z0-9._-]{20,}|[A-Za-z0-9]{24,})(?![A-Za-z0-9._-])"
)
_ANTHROPIC_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"ant-[A-Za-z0-9._-]{20,}(?![A-Za-z0-9._-])"
)
SECRET_REDACTIONS = (
    (_OPENAI_SECRET_PATTERN, "<REDACTED_OPENAI_KEY>"),
    (_ANTHROPIC_SECRET_PATTERN, "<REDACTED_ANTHROPIC_KEY>"),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{12,}=*", re.I),
        "Bearer <REDACTED>",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.S,
        ),
        "<REDACTED_PRIVATE_KEY>",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "<REDACTED_AWS_ACCESS_KEY_ID>",
    ),
    (
        re.compile(
            r"(?im)^(\s*[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|"
            r"PRIVATE_KEY|CLIENT_KEY_DATA|AWS_ACCESS_KEY_ID|"
            r"AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)"
            r"[A-Z0-9_]*\s*[:=]\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
    (
        re.compile(
            r"(?im)^(\s*(?:token|password|client-key-data|client-certificate-data|"
            r"aws_access_key_id|aws_secret_access_key|aws_session_token)"
            r"\s*[:=]\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
)


def _deployment_manifest_path() -> Path:
    executable = Path(sys.executable)
    if executable.parent.name == "bin" and executable.parent.parent.name == ".venv":
        return executable.parent.parent.parent / "deployment-manifest.json"
    return Path(__file__).resolve().parent / "deployment-manifest.json"


DEPLOYMENT_MANIFEST = _deployment_manifest_path()
EXPECTED_STABLE_RUNTIME = HOME / ".local" / "share" / "grabowski-mcp"
DEPLOYMENT_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONTRACT_BYTES = 64 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

mcp = FastMCP(APP_NAME, instructions=AGENT_INSTRUCTIONS)

READ_ANNOTATIONS = ToolAnnotations(
    title="Read local data",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
SECRET_REVEAL_ANNOTATIONS = ToolAnnotations(
    title="Reveal secret content",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
CREATE_ANNOTATIONS = ToolAnnotations(
    title="Create local text file",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
REPLACE_ANNOTATIONS = ToolAnnotations(
    title="Replace local text file",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)
REMOVE_ANNOTATIONS = ToolAnnotations(
    title="Remove local filesystem entry",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)


def _load_policy() -> dict[str, Any]:
    try:
        raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Access policy missing: {POLICY_PATH}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Access policy is invalid JSON: {exc}") from exc

    _validate_policy(raw)
    return raw


def _validate_string_list(
    value: Any,
    *,
    label: str,
    unique: bool = True,
) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"Access policy {label} must be a list of strings")
    if any(not item for item in value):
        raise RuntimeError(f"Access policy {label} contains an empty string")
    if unique and len(value) != len(set(value)):
        raise RuntimeError(f"Access policy {label} contains duplicates")
    return value


def _validate_root_values(value: Any, *, label: str) -> None:
    roots = _validate_string_list(value, label=label)
    for root in roots:
        path = _policy_path(root)
        if not path.is_absolute():
            raise RuntimeError(
                f"Access policy {label} root must be absolute after expansion: {root}"
            )


def _validate_limit_value(value: Any, *, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RuntimeError(f"Invalid access policy limit: {label}")


def _validate_capability_list(value: Any, *, label: str) -> None:
    capabilities = _validate_string_list(value, label=label)
    unknown = sorted(set(capabilities) - set(ALL_CAPABILITIES))
    if unknown:
        raise RuntimeError(f"Unknown access capabilities in {label}: {unknown}")


def _validate_allowed_grips(value: Any, *, label: str) -> None:
    grips = _validate_string_list(value, label=label)
    allowed = set(grabowski_grips.GRIP_SURFACE_ALLOWLIST) | {"*"}
    unknown = sorted(set(grips) - allowed)
    if unknown:
        raise RuntimeError(f"Unknown allowed grips in {label}: {unknown}")
    if "*" in grips and len(grips) != 1:
        raise RuntimeError(f"Access policy {label} may use '*' only by itself")


def _validate_forbidden_hosts(value: Any, *, label: str) -> None:
    hosts = _validate_string_list(value, label=label)
    for host in hosts:
        if any(ord(char) < 33 or ord(char) == 127 for char in host):
            raise RuntimeError(f"Access policy {label} contains an invalid host")
        if any(char in host for char in "/:@"):
            raise RuntimeError(f"Access policy {label} hosts must be bare hostnames")


def _validate_risk_level(value: Any, *, label: str) -> None:
    if value not in SESSION_RISK_ORDER:
        raise RuntimeError(
            f"Access policy {label} must be one of {list(SESSION_RISK_LEVELS)}"
        )


def _validate_policy(policy: Any) -> None:
    if not isinstance(policy, dict):
        raise RuntimeError("Access policy must be an object")

    unknown = sorted(set(policy) - TOP_LEVEL_POLICY_FIELDS)
    if unknown:
        raise RuntimeError(f"Unknown access policy fields: {unknown}")

    version = policy.get("version", 1)
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version not in {1, 2}
    ):
        raise RuntimeError("Access policy version must be 1 or 2")
    if version == 1 and V2_ONLY_POLICY_FIELDS & set(policy):
        raise RuntimeError("Typed secret/browser policy fields require version 2")

    required = {"read_roots", "write_roots", "max_read_bytes", "max_write_bytes"}
    if version == 2:
        required.update(
            {
                "write_excluded_roots",
                "secret_roots",
                "browser_profile_roots",
                "secret_export_roots",
                "max_list_entries",
                "forbid_symlinks",
                "forbidden_components",
                "forbidden_file_patterns",
                "forbidden_capabilities",
            }
        )
    missing = sorted(required.difference(policy))
    if missing:
        raise RuntimeError(f"Access policy missing keys: {missing}")

    if "mode" in policy and not isinstance(policy["mode"], str):
        raise RuntimeError("Access policy mode must be a string")
    if "active_profile" in policy and not isinstance(policy["active_profile"], str):
        raise RuntimeError("Access policy active_profile must be a string")
    if "trusted_owner" in policy and not isinstance(policy["trusted_owner"], bool):
        raise RuntimeError("Access policy trusted_owner must be a boolean")

    for key in ROOT_LIST_FIELDS:
        if key in policy:
            _validate_root_values(policy[key], label=key)

    for key in LIMIT_FIELDS:
        if key in policy:
            _validate_limit_value(policy[key], label=key)

    if "forbid_symlinks" in policy and not isinstance(policy["forbid_symlinks"], bool):
        raise RuntimeError("Access policy forbid_symlinks must be a boolean")

    for key in ("forbidden_components", "forbidden_file_patterns"):
        if key in policy:
            _validate_string_list(policy[key], label=key)

    if "forbidden_capabilities" in policy:
        _validate_capability_list(
            policy["forbidden_capabilities"],
            label="forbidden_capabilities",
        )
    if "allowed_grips" in policy:
        _validate_allowed_grips(policy["allowed_grips"], label="allowed_grips")
    if "forbidden_hosts" in policy:
        _validate_forbidden_hosts(policy["forbidden_hosts"], label="forbidden_hosts")
    if "max_risk_level" in policy:
        _validate_risk_level(policy["max_risk_level"], label="max_risk_level")

    definitions = policy.get("capability_definitions", {})
    if definitions is not None:
        if not isinstance(definitions, dict):
            raise RuntimeError("Access policy capability_definitions must be an object")
        unknown_definitions = sorted(set(definitions) - set(ALL_CAPABILITIES))
        if unknown_definitions:
            raise RuntimeError(f"Unknown capability definitions: {unknown_definitions}")
        if not all(isinstance(value, str) and value for value in definitions.values()):
            raise RuntimeError("Capability definitions must be non-empty strings")

    profiles = policy.get("profiles")
    if profiles is None:
        return
    if not isinstance(profiles, dict) or not profiles:
        raise RuntimeError("Access policy profiles must be a non-empty object")
    active = policy.get("active_profile", policy.get("mode"))
    if not isinstance(active, str) or active not in profiles:
        raise RuntimeError(f"Active access profile is not defined: {active!r}")

    for name, profile in profiles.items():
        if not isinstance(name, str) or not name:
            raise RuntimeError("Access profile names must be non-empty strings")
        if not isinstance(profile, dict):
            raise RuntimeError(f"Access profile is not an object: {name}")
        unknown_profile = sorted(set(profile) - PROFILE_POLICY_FIELDS)
        if unknown_profile:
            raise RuntimeError(
                f"Unknown access profile fields in {name}: {unknown_profile}"
            )
        if version == 1 and V2_ONLY_POLICY_FIELDS & set(profile):
            raise RuntimeError(
                f"Typed secret/browser profile fields require version 2: {name}"
            )
        if version == 2:
            profile_required = {
                "description",
                "read_roots",
                "write_roots",
                "write_excluded_roots",
                "secret_roots",
                "browser_profile_roots",
                "secret_export_roots",
                "capabilities",
            }
            missing_profile = sorted(profile_required.difference(profile))
            if missing_profile:
                raise RuntimeError(
                    f"Access profile {name} missing fields: {missing_profile}"
                )
        if "description" in profile and not isinstance(profile["description"], str):
            raise RuntimeError(f"Access profile {name} description must be a string")
        if "trusted_owner" in profile and not isinstance(
            profile["trusted_owner"], bool
        ):
            raise RuntimeError(f"Access profile {name} trusted_owner must be a boolean")
        for key in ROOT_LIST_FIELDS:
            if key in profile:
                _validate_root_values(profile[key], label=f"profile {name} {key}")
        for key in LIMIT_FIELDS:
            if key in profile:
                _validate_limit_value(profile[key], label=f"profile {name} {key}")
        if "capabilities" in profile:
            _validate_capability_list(
                profile["capabilities"],
                label=f"profile {name} capabilities",
            )
            capabilities = set(profile["capabilities"])
            if capabilities & {
                "secret_inspect",
                "secret_reveal",
                "secret_use",
                "secret_export",
            }:
                if not _profile_root_values(policy, profile, "secret_roots"):
                    raise RuntimeError(
                        f"Access profile {name} enables secret capabilities "
                        "without secret_roots"
                    )
            if "secret_export" in capabilities and not _profile_root_values(
                policy,
                profile,
                "secret_export_roots",
            ):
                raise RuntimeError(
                    f"Access profile {name} enables secret_export without "
                    "secret_export_roots"
                )
            if "browser_profile_read" in capabilities and not _profile_root_values(
                policy,
                profile,
                "browser_profile_roots",
            ):
                raise RuntimeError(
                    f"Access profile {name} enables browser_profile_read without "
                    "browser_profile_roots"
                )
        if "allowed_grips" in profile:
            _validate_allowed_grips(
                profile["allowed_grips"], label=f"profile {name} allowed_grips"
            )
        if "forbidden_hosts" in profile:
            _validate_forbidden_hosts(
                profile["forbidden_hosts"], label=f"profile {name} forbidden_hosts"
            )
        if "max_risk_level" in profile:
            _validate_risk_level(
                profile["max_risk_level"], label=f"profile {name} max_risk_level"
            )


def _profile_root_values(
    policy: dict[str, Any],
    profile: dict[str, Any],
    key: str,
) -> list[str]:
    value = profile.get(key, policy.get(key, []))
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _legacy_profile(policy: dict[str, Any]) -> dict[str, Any]:
    forbidden = set(policy.get("forbidden_capabilities", []))
    return {
        "name": policy.get("mode", "bounded-read-write"),
        "read_roots": policy.get("read_roots", []),
        "write_roots": policy.get("write_roots", []),
        "write_excluded_roots": policy.get("write_excluded_roots", []),
        "secret_roots": policy.get("secret_roots", []),
        "browser_profile_roots": policy.get("browser_profile_roots", []),
        "secret_export_roots": policy.get("secret_export_roots", []),
        "max_read_bytes": policy.get("max_read_bytes"),
        "max_write_bytes": policy.get("max_write_bytes"),
        "max_list_entries": policy.get("max_list_entries"),
        "max_secret_use_output_bytes": policy.get(
            "max_secret_use_output_bytes",
            DEFAULT_SECRET_USE_OUTPUT_BYTES,
        ),
        "max_secret_use_seconds": policy.get(
            "max_secret_use_seconds",
            DEFAULT_SECRET_USE_TIMEOUT_SECONDS,
        ),
        "capabilities": [
            capability
            for capability in BASE_CAPABILITIES
            if capability not in forbidden
        ],
        "allowed_grips": policy.get("allowed_grips", ["*"]),
        "forbidden_hosts": policy.get("forbidden_hosts", []),
        "max_risk_level": policy.get("max_risk_level", "high"),
        "trusted_owner": bool(policy.get("trusted_owner", False)),
    }


def _active_profile(policy: dict[str, Any]) -> dict[str, Any]:
    profiles = policy.get("profiles")
    if not isinstance(profiles, dict):
        return _legacy_profile(policy)

    active = policy.get("active_profile", policy.get("mode"))
    if not isinstance(active, str) or active not in profiles:
        raise RuntimeError(f"Active access profile is not defined: {active!r}")
    profile = profiles[active]
    if not isinstance(profile, dict):
        raise RuntimeError(f"Access profile is not an object: {active}")
    return {"name": active, **profile}


def _trusted_owner_enabled(policy: dict[str, Any] | None = None) -> bool:
    source = _load_policy() if policy is None else policy
    profile = _active_profile(source)
    return bool(profile.get("trusted_owner", source.get("trusted_owner", False)))


def _profile_values(policy: dict[str, Any], key: str) -> Any:
    profile = _active_profile(policy)
    if key in profile:
        return profile[key]
    return policy.get(key)


def _profile_string_list(
    policy: dict[str, Any], key: str, default: list[str]
) -> list[str]:
    value = _profile_values(policy, key)
    if value is None:
        return list(default)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"Access policy {key} must be a list of strings")
    return value


def _profile_risk_level(policy: dict[str, Any]) -> str:
    value = _profile_values(policy, "max_risk_level") or "high"
    if value not in SESSION_RISK_ORDER:
        raise RuntimeError("Access policy max_risk_level is invalid")
    return value


def _session_profile_contract(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    source = _load_policy() if policy is None else policy
    profile = _active_profile(source)
    allowed_grips = _profile_string_list(source, "allowed_grips", ["*"])
    forbidden_hosts = _profile_string_list(source, "forbidden_hosts", [])
    max_risk_level = _profile_risk_level(source)
    return {
        "profile": profile["name"],
        "read_roots": _profile_values(source, "read_roots") or [],
        "write_roots": _profile_values(source, "write_roots") or [],
        "allowed_grips": allowed_grips,
        "forbidden_hosts": forbidden_hosts,
        "max_risk_level": max_risk_level,
        "does_not_establish": [
            "automatic_high_impact_authority",
            "host_reachability",
            "grip_execution_success",
        ],
    }


def _risk_allowed(risk: str, max_risk_level: str) -> bool:
    return SESSION_RISK_ORDER[risk] <= SESSION_RISK_ORDER[max_risk_level]


def _session_grip_policy_decision(
    name: str,
    parameters: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = _load_policy() if policy is None else policy
    contract = _session_profile_contract(source)
    allowed_grips = set(contract["allowed_grips"])
    risk = grabowski_grips.grip_risk_level(name)
    allowed_by_name = "*" in allowed_grips or name in allowed_grips
    allowed_by_risk = _risk_allowed(risk, contract["max_risk_level"])
    escalation_required = risk == "high"
    escalation_valid = True
    escalation_error = None
    if escalation_required:
        try:
            _validate_session_escalation((parameters or {}).get("session_escalation"))
        except RuntimeError as exc:
            escalation_valid = False
            escalation_error = str(exc)
    return {
        "allowed": allowed_by_name and allowed_by_risk and escalation_valid,
        "grip": name,
        "risk": risk,
        "allowed_by_name": allowed_by_name,
        "allowed_by_risk": allowed_by_risk,
        "escalation_required": escalation_required,
        "escalation_valid": escalation_valid,
        "escalation_error": escalation_error,
        "session_profile": contract,
    }


def _validate_session_escalation(value: Any) -> None:
    if not isinstance(value, dict):
        raise RuntimeError(
            "session_escalation is required for high-risk grip execution"
        )
    required = {"target", "reason", "expires_at_unix"}
    missing = sorted(required - set(value))
    if missing:
        raise RuntimeError(f"session_escalation missing fields: {missing}")
    if not isinstance(value.get("target"), (str, dict)) or not value.get("target"):
        raise RuntimeError("session_escalation.target must be non-empty")
    if not isinstance(value.get("reason"), str) or not value.get("reason").strip():
        raise RuntimeError("session_escalation.reason must be non-empty")
    expires = value.get("expires_at_unix")
    if not isinstance(expires, int) or isinstance(expires, bool):
        raise RuntimeError("session_escalation.expires_at_unix must be an integer")
    now = int(time.time())
    if expires <= now:
        raise RuntimeError("session_escalation.expires_at_unix is expired")
    if expires > now + SESSION_ESCALATION_MAX_SECONDS:
        raise RuntimeError(
            "session_escalation.expires_at_unix is too far in the future"
        )
    has_recovery = isinstance(value.get("recovery"), dict) and bool(value["recovery"])
    has_irreversibility = isinstance(value.get("irreversibility"), dict) and bool(
        value["irreversibility"]
    )
    if not (has_recovery or has_irreversibility):
        raise RuntimeError(
            "session_escalation requires recovery or irreversibility metadata"
        )


def _host_candidates_from_token(token: str) -> set[str]:
    candidates: set[str] = set()
    parsed = urllib.parse.urlparse(token)
    if parsed.hostname:
        candidates.add(parsed.hostname.lower())
    if ":" in token and "/" not in token.split(":", 1)[0]:
        left = token.split(":", 1)[0]
        if "@" in left:
            left = left.rsplit("@", 1)[1]
        if left and not left.startswith("-"):
            candidates.add(left.lower())
    if "@" in token and "/" not in token:
        candidates.add(token.rsplit("@", 1)[1].lower())
    if re.fullmatch(r"[A-Za-z0-9_.-]+", token) and "." in token:
        candidates.add(token.lower())
    return candidates


def _token_matches_forbidden_host(token: str, forbidden: set[str]) -> str | None:
    normalized = token.lower()
    if normalized in forbidden:
        return normalized
    candidates = _host_candidates_from_token(token)
    blocked = sorted(candidates & forbidden)
    return blocked[0] if blocked else None


def _reject_forbidden_hosts_in_argv(
    argv: list[str], *, policy: dict[str, Any] | None = None
) -> None:
    source_policy = policy or _load_policy()
    forbidden = {
        host.lower()
        for host in _profile_string_list(source_policy, "forbidden_hosts", [])
    }
    if not forbidden:
        return
    for token in argv:
        blocked = _token_matches_forbidden_host(token, forbidden)
        if blocked:
            raise PermissionError(f"Forbidden host in command arguments: {blocked}")


def _policy_limit(policy: dict[str, Any], key: str) -> int:
    value = _profile_values(policy, key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RuntimeError(f"Invalid access policy limit: {key}")
    return value


def _effective_capabilities(policy: dict[str, Any]) -> set[str]:
    profile = _active_profile(policy)
    capabilities = profile.get("capabilities")
    if not isinstance(capabilities, list):
        capabilities = _legacy_profile(policy)["capabilities"]
    forbidden = set(policy.get("forbidden_capabilities", []))
    return {
        capability
        for capability in capabilities
        if isinstance(capability, str) and capability not in forbidden
    }


def _root_values(policy: dict[str, Any], key: str) -> list[str]:
    values = _profile_values(policy, key) or []
    if not isinstance(values, list):
        raise RuntimeError(f"Access policy {key} must be a list")
    return [value for value in values if isinstance(value, str) and value]


def _configured_roots(key: str, policy: dict[str, Any] | None = None) -> list[Path]:
    source = _load_policy() if policy is None else policy
    return [
        _policy_path(value).resolve(strict=False) for value in _root_values(source, key)
    ]


def _secret_root_values(policy: dict[str, Any]) -> list[str]:
    return _root_values(policy, "secret_roots")


def _browser_profile_root_values(policy: dict[str, Any]) -> list[str]:
    return _root_values(policy, "browser_profile_roots")


def _secret_export_root_values(policy: dict[str, Any]) -> list[str]:
    return _root_values(policy, "secret_export_roots")


def _secret_roots(policy: dict[str, Any] | None = None) -> list[Path]:
    return _configured_roots("secret_roots", policy)


def _browser_profile_roots(policy: dict[str, Any] | None = None) -> list[Path]:
    return _configured_roots("browser_profile_roots", policy)


def _secret_export_roots(policy: dict[str, Any] | None = None) -> list[Path]:
    return _configured_roots("secret_export_roots", policy)


def _path_is_secret(path: Path, policy: dict[str, Any] | None = None) -> bool:
    return _is_within(path, _secret_roots(policy))


def _path_is_browser_profile(path: Path, policy: dict[str, Any] | None = None) -> bool:
    return _is_within(path, _browser_profile_roots(policy))


def _path_is_sensitive(path: Path, policy: dict[str, Any] | None = None) -> bool:
    return _path_is_secret(path, policy) or _path_is_browser_profile(path, policy)


def _effective_operator_capabilities(policy: dict[str, Any]) -> set[str]:
    forbidden = set(policy.get("forbidden_capabilities", []))
    profiles = policy.get("profiles")
    if isinstance(profiles, dict):
        profile = _active_profile(policy)
        raw = profile.get("capabilities", [])
        capabilities = {item for item in raw if isinstance(item, str)}
    else:
        capabilities = set(OPERATOR_CAPABILITIES)
    return {
        capability
        for capability in capabilities
        if capability in OPERATOR_CAPABILITIES and capability not in forbidden
    }


def _effective_capabilities_for_tool(tool: str, policy: dict[str, Any]) -> set[str]:
    effective = set(_effective_capabilities(policy))
    if tool in OPERATOR_CAPABILITY_REQUIREMENT_TOOLS:
        effective |= _effective_operator_capabilities(policy)
    return effective


def _capability_requirement_summary(
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = _load_policy() if policy is None else policy
    missing: list[dict[str, Any]] = []
    guarded = {
        tool: required
        for tool, required in TOOL_CAPABILITY_REQUIREMENTS.items()
        if required
    }
    for tool, required in sorted(guarded.items()):
        effective = _effective_capabilities_for_tool(tool, source)
        missing_capabilities = [
            capability for capability in required if capability not in effective
        ]
        if missing_capabilities:
            missing.append(
                {
                    "tool": tool,
                    "missing_capabilities": missing_capabilities,
                }
            )
    return {
        "known_tool_requirements": len(TOOL_CAPABILITY_REQUIREMENTS),
        "registered_tool_requirements": len(TOOL_CAPABILITY_REQUIREMENTS),
        "guarded_tool_requirements": len(guarded),
        "operator_semantics_tool_count": len(OPERATOR_CAPABILITY_REQUIREMENT_TOOLS),
        "unguarded_registered_tools": [
            tool
            for tool, required in sorted(TOOL_CAPABILITY_REQUIREMENTS.items())
            if not required
        ],
        "missing_enabled_requirements": missing,
        "missing_count": len(missing),
        "does_not_establish": [
            "tool_behavior_correctness",
            "successful_execution",
            "runtime_client_snapshot_freshness",
        ],
    }


def _require_capability(capability: str) -> None:
    policy = _load_policy()
    if capability not in _effective_capabilities(policy):
        raise PermissionError(f"Access capability is not enabled: {capability}")


def _canonical_marker_contract() -> tuple[int, int, bool]:
    # Tests may bind the canonical path to an owner-private fixture. Production
    # always uses the immutable absolute constant and therefore the root-owned
    # authority contract.
    if KILL_SWITCH_PATH == CANONICAL_KILL_SWITCH_PATH:
        return BLOCKADE_AUTHORITY_UID, BLOCKADE_MARKER_MODE, False
    return os.getuid(), 0o600, True


def _observe_blockade_marker(
    marker_path: Path,
    *,
    label: str,
    expected_uid: int,
    expected_mode: int,
    require_private_parent: bool,
    host: str,
) -> tuple[list[blockade_policy.BlockadeRecord], dict[str, Any]]:
    records: list[blockade_policy.BlockadeRecord] = []
    diagnostic: dict[str, Any] = {
        "label": label,
        "path": str(marker_path),
        "present": marker_path.exists() or marker_path.is_symlink(),
        "source": None,
        "error": None,
        "marker_file_sha256": None,
        "marker_record_sha256": None,
    }
    if not diagnostic["present"]:
        return records, diagnostic
    try:
        snapshot = blockade_store.read_blockade_marker(
            marker_path,
            expected_marker_path=marker_path,
            expected_uid=expected_uid,
            expected_mode=expected_mode,
            require_private_parent=require_private_parent,
        )
    except Exception as exc:
        try:
            metadata = os.lstat(marker_path)
        except OSError as observation_error:
            identity = {
                "strict_error": type(exc).__name__,
                "lstat_error": type(observation_error).__name__,
                "path": str(marker_path),
                "label": label,
            }
            digest = hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest()
            engaged_at = datetime.fromtimestamp(0, timezone.utc)
            diagnostic["source"] = f"{label}_observation_uncertain"
            diagnostic["error"] = (
                f"{type(exc).__name__}: {exc}; "
                f"{type(observation_error).__name__}: {observation_error}"
            )[:500]
        else:
            identity = {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "mode": metadata.st_mode,
                "nlink": metadata.st_nlink,
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
                "label": label,
            }
            digest = hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest()
            engaged_at = datetime.fromtimestamp(metadata.st_ctime, timezone.utc)
            diagnostic["source"] = f"{label}_unsafe_file"
            diagnostic["error"] = f"{type(exc).__name__}: {exc}"[:500]
        records.append(
            blockade_policy.legacy_marker_record(
                marker_path=str(marker_path),
                marker_sha256=digest,
                engaged_at=engaged_at,
                host=host,
            )
        )
        diagnostic["marker_file_sha256"] = digest
        return records, diagnostic
    records.append(snapshot.record)
    diagnostic["source"] = f"{label}_typed"
    diagnostic["marker_file_sha256"] = snapshot.file_sha256
    diagnostic["marker_record_sha256"] = snapshot.record_sha256
    return records, diagnostic


def _operator_blockade_records() -> tuple[
    tuple[blockade_policy.BlockadeRecord, ...], dict[str, Any]
]:
    records: list[blockade_policy.BlockadeRecord] = []
    diagnostics: dict[str, Any] = {
        "marker_error": None,
        "marker_source": None,
        "canonical": None,
        "legacy": None,
    }
    host = platform.node() or "unknown-host"
    env_value = os.environ.get("GRABOWSKI_OPERATOR_KILL_SWITCH", "")
    env_engaged = env_value.lower() in {"1", "true", "yes", "on"}
    if env_engaged:
        records.append(
            blockade_policy.environment_stop_record(
                value_sha256=hashlib.sha256(env_value.encode("utf-8")).hexdigest(),
                engaged_at=datetime.fromtimestamp(0, timezone.utc),
                host=host,
            )
        )

    canonical_uid, canonical_mode, canonical_private = _canonical_marker_contract()
    canonical_records, canonical_diagnostic = _observe_blockade_marker(
        KILL_SWITCH_PATH,
        label="canonical",
        expected_uid=canonical_uid,
        expected_mode=canonical_mode,
        require_private_parent=canonical_private,
        host=host,
    )
    records.extend(canonical_records)
    diagnostics["canonical"] = canonical_diagnostic

    if LEGACY_KILL_SWITCH_PATH != KILL_SWITCH_PATH:
        legacy_records, legacy_diagnostic = _observe_blockade_marker(
            LEGACY_KILL_SWITCH_PATH,
            label="legacy",
            expected_uid=os.getuid(),
            expected_mode=0o600,
            require_private_parent=True,
            host=host,
        )
        records.extend(legacy_records)
        diagnostics["legacy"] = legacy_diagnostic
    else:
        diagnostics["legacy"] = {
            "label": "legacy",
            "path": str(LEGACY_KILL_SWITCH_PATH),
            "present": False,
            "source": "same_as_canonical",
            "error": None,
        }

    observed = [
        item
        for item in (diagnostics["canonical"], diagnostics["legacy"])
        if isinstance(item, dict) and item.get("present")
    ]
    sources = [str(item.get("source")) for item in observed if item.get("source")]
    errors = [str(item.get("error")) for item in observed if item.get("error")]
    diagnostics["marker_source"] = "+".join(sources) if sources else None
    diagnostics["marker_error"] = "; ".join(errors)[:1000] if errors else None
    return tuple(records), diagnostics


def _kill_switch_state() -> dict[str, Any]:
    records, diagnostics = _operator_blockade_records()
    active = tuple(record for record in records if record.active_at())
    postures = [record.posture for record in active]
    effective = (
        max(postures, key=blockade_policy.POSTURE_ORDER.__getitem__)
        if postures
        else None
    )
    globally_engaged = any(
        record.scope.kind == "global"
        and record.posture in {"mutation_freeze", "hard_stop"}
        for record in active
    )
    return {
        "engaged": globally_engaged,
        "present": bool(active),
        "environment": any(record.source == "environment" for record in active),
        "path": str(KILL_SWITCH_PATH),
        "path_exists": KILL_SWITCH_PATH.exists() or KILL_SWITCH_PATH.is_symlink(),
        "canonical_path": str(KILL_SWITCH_PATH),
        "canonical_path_exists": KILL_SWITCH_PATH.exists()
        or KILL_SWITCH_PATH.is_symlink(),
        "legacy_path": str(LEGACY_KILL_SWITCH_PATH),
        "legacy_path_exists": (
            LEGACY_KILL_SWITCH_PATH.exists() or LEGACY_KILL_SWITCH_PATH.is_symlink()
        ),
        "effective_posture": effective,
        "records": [record.to_mapping() for record in active],
        "record_sha256s": [record.sha256 for record in active],
        "diagnostics": diagnostics,
    }


def _require_valid_audit_chain() -> None:
    audit = _verify_audit_log(AUDIT_LOG)
    if not audit["valid"]:
        raise RuntimeError(f"Audit log verification failed: {audit['error']}")


def _require_blockade_allows_mutation(
    capability: str,
    *,
    path: str | None = None,
    task_id: str | None = None,
    owner_id: str | None = None,
    repo: str | None = None,
    service: str | None = None,
    host: str | None = None,
    fresh_preflight: bool = False,
    allow_blockade_lifecycle: bool = False,
    opaque_command: bool = False,
) -> None:
    if not isinstance(opaque_command, bool):
        raise ValueError("opaque_command must be boolean")
    if allow_blockade_lifecycle and path not in {
        str(KILL_SWITCH_PATH),
        str(LEGACY_KILL_SWITCH_PATH),
    }:
        raise PermissionError("blockade lifecycle authority is marker-path bound")
    records, _diagnostics = _operator_blockade_records()
    if opaque_command:
        strong_opaque_scopes = sorted(
            {
                f"{record.scope.kind}:{record.scope.value}"
                for record in records
                if record.active_at()
                and record.scope.kind in {"path", "repo"}
                and record.posture
                in {"preflight_required", "mutation_freeze", "hard_stop"}
            }
        )
        if strong_opaque_scopes:
            raise PermissionError(
                "opaque command execution cannot prove isolation from active "
                "path/repo blockades: " + ",".join(strong_opaque_scopes)
            )
    decision = blockade_policy.evaluate_blockades(
        records,
        blockade_policy.ActionContext(
            action_class="mutate",
            path=path,
            capability=capability,
            task_id=task_id,
            owner_id=owner_id,
            repo=repo,
            service=service,
            host=host or platform.node() or "unknown-host",
            fresh_preflight=fresh_preflight,
        ),
    )
    if not decision.allowed:
        raise PermissionError(
            "Grabowski operator kill switch/blockade denies mutation: "
            + ",".join(decision.reasons)
        )


def _require_mutations_enabled(
    capability: str,
    *,
    path: str | None = None,
    task_id: str | None = None,
    owner_id: str | None = None,
    repo: str | None = None,
    service: str | None = None,
    host: str | None = None,
    fresh_preflight: bool = False,
    allow_blockade_lifecycle: bool = False,
    opaque_command: bool = False,
) -> None:
    _require_capability(capability)
    _require_blockade_allows_mutation(
        capability,
        path=path,
        task_id=task_id,
        owner_id=owner_id,
        repo=repo,
        service=service,
        host=host,
        fresh_preflight=fresh_preflight,
        allow_blockade_lifecycle=allow_blockade_lifecycle,
        opaque_command=opaque_command,
    )
    _require_valid_audit_chain()


def _policy_path(value: str) -> Path:
    if not isinstance(value, str) or not value:
        raise RuntimeError("Configured policy path must be a non-empty string")
    return Path(value.replace("${HOME}", str(HOME))).expanduser()


def _roots(kind: str, *, ignore_missing: bool = False) -> list[Path]:
    policy = _load_policy()
    values = _profile_values(policy, f"{kind}_roots")
    roots: list[Path] = []
    for value in values:
        configured = _policy_path(value)
        try:
            root = configured.resolve(strict=True)
        except FileNotFoundError:
            if ignore_missing:
                continue
            raise
        if not root.is_dir():
            raise RuntimeError(f"Configured {kind} root is not a directory: {root}")
        roots.append(root)
    return roots


def _is_within(path: Path, roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _excluded_roots(kind: str) -> list[Path]:
    policy = _load_policy()
    values = _profile_values(policy, f"{kind}_excluded_roots") or []
    roots: list[Path] = []

    for value in values:
        root = _policy_path(value).resolve(strict=True)
        if not root.is_dir():
            raise RuntimeError(
                f"Configured {kind} excluded root is not a directory: {root}"
            )
        roots.append(root)

    return roots


def _reject_sensitive(path: Path) -> None:
    policy = _load_policy()
    if _trusted_owner_enabled(policy):
        return
    forbidden_components = set(policy.get("forbidden_components", []))
    forbidden_patterns = list(policy.get("forbidden_file_patterns", []))

    for component in path.parts:
        if component in forbidden_components:
            raise PermissionError(f"Forbidden path component: {component}")

    name = path.name
    for pattern in forbidden_patterns:
        if fnmatch(name, pattern):
            raise PermissionError(f"Forbidden file pattern: {pattern}")


def _reject_symlink_components(path: Path, allow_missing_leaf: bool = False) -> None:
    policy = _load_policy()
    if not policy.get("forbid_symlinks", True):
        return

    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current = current / part
        is_leaf = index == len(parts) - 1
        if current.is_symlink():
            raise PermissionError(f"Symlink paths are forbidden: {current}")
        if not current.exists():
            if allow_missing_leaf and is_leaf:
                return
            raise FileNotFoundError(str(current))


def _absolute_candidate(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Path must be absolute")
    _reject_sensitive(candidate)
    return candidate


def _resolve_existing(raw_path: str, kind: str) -> Path:
    candidate = _absolute_candidate(raw_path)
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not _is_within(resolved, _roots(kind)):
        raise PermissionError(f"Path is outside configured {kind} roots: {resolved}")
    if _path_is_sensitive(resolved) and not _trusted_owner_enabled():
        raise PermissionError(
            "Path is inside configured secret/browser roots; use dedicated tools."
        )
    return resolved


def _resolve_write_target(raw_path: str) -> tuple[Path, bool]:
    candidate = _absolute_candidate(raw_path)
    if candidate.exists() or candidate.is_symlink():
        _reject_symlink_components(candidate)
        resolved = candidate.resolve(strict=True)
        exists = True
    else:
        _reject_symlink_components(candidate, allow_missing_leaf=True)
        parent = candidate.parent.resolve(strict=True)
        resolved = parent / candidate.name
        exists = False

    if not _is_within(resolved, _roots("write")):
        raise PermissionError(f"Path is outside configured write roots: {resolved}")

    trusted_owner = _trusted_owner_enabled()
    if _is_within(resolved, _excluded_roots("write")) and not trusted_owner:
        raise PermissionError(f"Path is explicitly read-only: {resolved}")

    if _path_is_sensitive(resolved) and not trusted_owner:
        raise PermissionError(
            "Path is inside configured secret/browser roots; use dedicated tools."
        )

    if _canonical_operator_marker_target(resolved):
        raise PermissionError(
            f"Canonical operator blockade marker requires typed lifecycle tools: {resolved}"
        )

    if _protected_generic_write_target(resolved) and not trusted_owner:
        raise PermissionError(f"Path is protected from generic mutation: {resolved}")

    return resolved, exists


def _validate_removal_type(expected_type: str) -> str:
    if expected_type not in {"file", "empty_directory"}:
        raise ValueError("expected_type must be 'file' or 'empty_directory'")
    return expected_type


def _removal_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
    )


def _verify_same_removal_target(
    target: Path, identity: tuple[int, int, int, int, int]
) -> None:
    current = os.stat(target, follow_symlinks=False)
    if _removal_identity(current) != identity:
        raise RuntimeError("Removal target changed before mutation")


def _removal_snapshot(
    target: Path,
    expected_type: str,
    expected_sha256: str | None,
) -> dict[str, Any]:
    expected = _validate_removal_type(expected_type)
    info = os.stat(target, follow_symlinks=False)
    mode = info.st_mode
    if expected == "file":
        if not statmod.S_ISREG(mode):
            raise ValueError(f"Removal target is not a regular file: {target}")
        if expected_sha256 is None:
            raise ValueError("expected_sha256 is required for file removal")
        _validate_sha256(expected_sha256, "expected_sha256")
        policy = _load_policy()
        snapshot = _read_bound_regular_bytes(
            target,
            _policy_limit(policy, "max_read_bytes"),
        )
        if snapshot["sha256"] != expected_sha256:
            raise RuntimeError(
                "SHA-256 precondition failed: "
                f"expected {expected_sha256}, current {snapshot['sha256']}"
            )
        return {
            "type": "file",
            "sha256": snapshot["sha256"],
            "bytes": snapshot["size"],
            "mode": statmod.S_IMODE(info.st_mode),
            "identity": _removal_identity(info),
        }

    if not statmod.S_ISDIR(mode):
        raise ValueError(f"Removal target is not a directory: {target}")
    if expected_sha256 is not None:
        raise ValueError("expected_sha256 must be omitted for empty_directory removal")
    if any(target.iterdir()):
        raise ValueError(f"Directory is not empty: {target}")
    return {
        "type": "empty_directory",
        "sha256": None,
        "bytes": 0,
        "mode": statmod.S_IMODE(info.st_mode),
        "identity": _removal_identity(info),
    }


def _new_holding_path(target: Path) -> Path:
    for _attempt in range(20):
        candidate = (
            target.parent / f".{target.name}.grabowski-remove-{uuid.uuid4().hex[:12]}"
        )
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise RuntimeError(f"Could not allocate removal holding path for {target}")


def _move_to_holding(target: Path, snapshot: dict[str, Any]) -> Path:
    holding = _new_holding_path(target)
    os.replace(target, holding)
    _fsync_directory(target.parent)
    try:
        _verify_same_removal_target(holding, snapshot["identity"])
        if snapshot["type"] == "file":
            if _sha256(holding) != snapshot["sha256"]:
                raise RuntimeError("Removal target hash changed before mutation")
        elif any(holding.iterdir()):
            raise RuntimeError("Directory changed before removal")
    except Exception:
        try:
            if not target.exists() and not target.is_symlink():
                os.replace(holding, target)
                _fsync_directory(target.parent)
        finally:
            pass
        raise
    return holding


def _quarantine_removed_entry(
    holding: Path,
    snapshot: dict[str, Any],
    transaction_dir: Path,
) -> Path:
    if snapshot["type"] == "file":
        quarantine = transaction_dir / f"removed-{snapshot['sha256'][:12]}"
        shutil.copy2(holding, quarantine, follow_symlinks=False)
        os.chmod(quarantine, 0o600)
        if _sha256(quarantine) != snapshot["sha256"]:
            raise RuntimeError("Quarantined removal hash mismatch")
        return quarantine

    quarantine = transaction_dir / "removed-empty-directory"
    quarantine.mkdir(mode=0o700)
    return quarantine


def _remove_holding_entry(holding: Path, snapshot: dict[str, Any]) -> None:
    if snapshot["type"] == "file":
        holding.unlink()
    else:
        holding.rmdir()
    _fsync_directory(holding.parent)


def _audit_quarantine_path(raw_path: Any, expected_type: str) -> Path:
    if not isinstance(raw_path, str):
        raise ValueError("Audit transaction has no quarantine preimage")
    path = Path(raw_path)
    if path.is_symlink():
        raise ValueError(f"Quarantine preimage is a symlink: {path}")
    if expected_type == "file" and not path.is_file():
        raise ValueError(f"Quarantine preimage is not a regular file: {path}")
    if expected_type == "empty_directory" and not path.is_dir():
        raise ValueError(f"Quarantine preimage is not a directory: {path}")
    quarantine_root = _state_subdir(QUARANTINE_DIR)
    resolved = path.resolve(strict=True)
    if not _path_inside(resolved, quarantine_root):
        raise PermissionError("Quarantine preimage is outside Grabowski state")
    return resolved


def _canonical_operator_marker_target(path: Path) -> bool:
    candidate = path.resolve(strict=False)
    return candidate in {
        KILL_SWITCH_PATH.resolve(strict=False),
        LEGACY_KILL_SWITCH_PATH.resolve(strict=False),
    }


def _protected_generic_write_target(path: Path) -> bool:
    protected = [
        POLICY_PATH,
        KILL_SWITCH_PATH,
        LEGACY_KILL_SWITCH_PATH,
        STATE_DIR,
        AUDIT_LOG,
        QUARANTINE_DIR,
        HOME / "repos" / "merges",
        HOME / ".config" / "tunnel-client",
        DEPLOYMENT_MANIFEST,
        EXPECTED_STABLE_RUNTIME / "inputs" / "runtime-entrypoint.json",
    ]
    candidate = path.resolve(strict=False)
    return any(
        _path_inside(candidate, root.resolve(strict=False)) for root in protected
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_regular_text_file(path: Path, max_bytes: int) -> bytes:
    st = path.stat()
    if not statmod.S_ISREG(st.st_mode):
        raise ValueError(f"Not a regular file: {path}")
    if st.st_size > max_bytes:
        raise ValueError(f"File exceeds byte limit ({st.st_size} > {max_bytes})")
    data = path.read_bytes()
    if b"\x00" in data:
        raise ValueError("Binary/NUL-containing files are not allowed")
    return data


def _validate_sha256(value: str, label: str = "sha256") -> str:
    if not (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _redact_sensitive_text(
    text: str,
    extra_secrets: list[str] | None = None,
) -> tuple[str, int]:
    result = text
    redactions = 0
    for pattern, replacement in SECRET_REDACTIONS:
        result, count = pattern.subn(replacement, result)
        redactions += count

    for secret in sorted(set(extra_secrets or []), key=len, reverse=True):
        if not secret:
            continue
        count = result.count(secret)
        if count:
            result = result.replace(secret, "<REDACTED>")
            redactions += count

    return result, redactions


def _nofollow_kind_and_size(path: Path) -> tuple[str, int | None]:
    info = os.stat(path, follow_symlinks=False)
    mode = info.st_mode
    if statmod.S_ISLNK(mode):
        return "symlink-blocked", None
    if statmod.S_ISDIR(mode):
        return "directory", None
    if statmod.S_ISREG(mode):
        return "file", info.st_size
    return "other", None


def _nofollow_metadata(path: Path) -> os.stat_result:
    return os.stat(path, follow_symlinks=False)


def _validate_opened_regular(
    opened: os.stat_result,
    linked: os.stat_result,
    max_bytes: int,
) -> None:
    if not statmod.S_ISREG(opened.st_mode):
        raise ValueError("Not a regular file")
    if not statmod.S_ISREG(linked.st_mode):
        raise PermissionError("Path is not bound to a regular file")
    if opened.st_dev != linked.st_dev or opened.st_ino != linked.st_ino:
        raise PermissionError("Path changed while opening file")
    if opened.st_nlink != 1:
        raise PermissionError("Hard-linked sensitive files are not supported")
    if opened.st_size > max_bytes:
        raise ValueError(f"File exceeds byte limit ({opened.st_size} > {max_bytes})")


def _validate_same_regular_snapshot(
    before: os.stat_result,
    after_open: os.stat_result,
    after_link: os.stat_result,
) -> None:
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after_open.st_dev,
        after_open.st_ino,
        after_open.st_size,
        after_open.st_mtime_ns,
        after_open.st_ctime_ns,
    )
    linked_identity = (
        after_link.st_dev,
        after_link.st_ino,
        after_link.st_size,
        after_link.st_mtime_ns,
        after_link.st_ctime_ns,
    )
    if before_identity != after_identity or before_identity != linked_identity:
        raise RuntimeError("File changed while being read")


def _read_bound_regular_bytes(path: Path, max_bytes: int) -> dict[str, Any]:
    fd: int | None = None
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        linked = os.stat(path, follow_symlinks=False)
        _validate_opened_regular(opened, linked, max_bytes)

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ValueError(f"File exceeds byte limit ({len(data)} > {max_bytes})")

        after_open = os.fstat(fd)
        after_link = os.stat(path, follow_symlinks=False)
        _validate_same_regular_snapshot(opened, after_open, after_link)
        digest = hashlib.sha256(data).hexdigest()
        return {
            "data": data,
            "sha256": digest,
            "size": len(data),
            "mode": statmod.S_IMODE(opened.st_mode),
            "mtime_ns": opened.st_mtime_ns,
            "ctime_ns": opened.st_ctime_ns,
            "dev": opened.st_dev,
            "ino": opened.st_ino,
        }
    finally:
        if fd is not None:
            os.close(fd)


def _minimum_policy_limit(policy: dict[str, Any], *keys: str) -> int:
    return min(_policy_limit(policy, key) for key in keys)


def _policy_limit_or_default(
    policy: dict[str, Any],
    key: str,
    default: int,
) -> int:
    value = _profile_values(policy, key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RuntimeError(f"Invalid access policy limit: {key}")
    return value


def _resolve_rooted_existing(raw_path: str, roots: list[Path], label: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Path must be absolute")
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not _is_within(resolved, roots):
        raise PermissionError(f"Path is outside configured {label} roots: {resolved}")
    return resolved


def _resolve_secret_existing(raw_path: str) -> Path:
    return _resolve_rooted_existing(raw_path, _secret_roots(), "secret")


def _resolve_browser_profile_existing(raw_path: str) -> Path:
    return _resolve_rooted_existing(
        raw_path,
        _browser_profile_roots(),
        "browser profile",
    )


def _remote_destination_syntax(raw_path: str) -> bool:
    if "://" in raw_path:
        return True
    if raw_path.startswith("/"):
        return False
    return re.match(r"^[A-Za-z0-9_.-]+(?:@[A-Za-z0-9_.-]+)?:", raw_path) is not None


def _resolve_secret_export_target(raw_path: str) -> Path:
    if _remote_destination_syntax(raw_path):
        raise ValueError("Secret export destination must be a local filesystem path")
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Secret export destination must be absolute")
    if candidate.exists() or candidate.is_symlink():
        _reject_symlink_components(candidate)
        raise FileExistsError(f"Refusing to overwrite existing path: {candidate}")
    _reject_symlink_components(candidate, allow_missing_leaf=True)
    parent = candidate.parent.resolve(strict=True)
    resolved = parent / candidate.name
    policy = _load_policy()
    if not _is_within(resolved, _secret_export_roots(policy)):
        raise PermissionError(
            f"Destination is outside configured secret export roots: {resolved}"
        )
    return resolved


def _atomic_create_bytes(target: Path, data: bytes, mode: int = 0o600) -> None:
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target)
        _fsync_directory(target.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _secret_text_snapshot(
    path: Path,
    *,
    expected_sha256: str | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    policy = _load_policy()
    byte_limit = _policy_limit(policy, "max_read_bytes")
    if max_bytes is not None:
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes < 1
        ):
            raise ValueError("max_bytes must be a positive integer")
        byte_limit = min(byte_limit, max_bytes)
    snapshot = _read_bound_regular_bytes(path, byte_limit)
    if expected_sha256 is not None:
        _validate_sha256(expected_sha256, "expected_sha256")
        if snapshot["sha256"] != expected_sha256:
            raise RuntimeError(
                "SHA-256 precondition failed: "
                f"expected {expected_sha256}, current {snapshot['sha256']}"
            )
    data = snapshot["data"]
    if b"\x00" in data:
        raise ValueError("Binary/NUL-containing secret files are not revealable")
    text = data.decode("utf-8")
    redacted, redaction_count = _redact_sensitive_text(text)
    return {
        **snapshot,
        "text": text,
        "redacted_text": redacted,
        "redaction_count": redaction_count,
    }


def _secret_redaction_values(data: bytes) -> list[str]:
    decoded = data.decode("utf-8", errors="replace")
    values = {decoded}
    stripped = decoded.strip()
    if stripped:
        values.add(stripped)
    for line in decoded.splitlines():
        stripped_line = line.strip()
        if stripped_line:
            values.add(stripped_line)
    if data:
        b64 = base64.b64encode(data).decode("ascii")
        urlsafe = base64.urlsafe_b64encode(data).decode("ascii")
        values.update({b64, b64.rstrip("="), urlsafe, urlsafe.rstrip("=")})
        values.add(urllib.parse.quote_from_bytes(data, safe=""))
    return sorted((value for value in values if value), key=len, reverse=True)


def _redact_secret_output(text: str, secret_data: bytes) -> tuple[str, int]:
    return _redact_sensitive_text(text, _secret_redaction_values(secret_data))


def _limit_text(text: str, max_output_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_output_bytes:
        return text, False
    clipped = encoded[:max_output_bytes].decode("utf-8", errors="replace")
    return clipped + "\n<OUTPUT_TRUNCATED>", True


def _contains_secret_variant(text: str, secret_data: bytes) -> bool:
    return any(
        secret and secret in text for secret in _secret_redaction_values(secret_data)
    )


def _reject_secret_variants_in_text(text: str, secret_data: bytes, label: str) -> None:
    if _contains_secret_variant(text, secret_data):
        raise PermissionError(
            f"Secret value or encoded secret value may not appear in {label}"
        )


def _argv_sha256(argv: list[str]) -> str:
    encoded = json.dumps(
        argv,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _resolve_secret_use_cwd(cwd: str | None) -> Path:
    candidate = HOME if cwd is None else Path(cwd).expanduser()
    if not candidate.is_absolute():
        raise ValueError("cwd must be absolute")
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"cwd is not a directory: {resolved}")
    if not _is_within(resolved, _roots("read")):
        raise PermissionError(f"cwd is outside configured read roots: {resolved}")
    if _path_is_sensitive(resolved):
        raise PermissionError("cwd may not be inside secret/browser roots")
    if _protected_generic_write_target(resolved):
        raise PermissionError("cwd may not be inside protected operator roots")
    return resolved


def _resolve_executable(value: str, cwd: Path) -> str:
    candidate = Path(value).expanduser()
    if "/" in value:
        if not candidate.is_absolute():
            candidate = cwd / candidate
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise PermissionError(f"Executable is not runnable: {resolved}")
        return str(resolved)
    resolved = shutil.which(value)
    if resolved is None:
        raise FileNotFoundError(f"Executable not found: {value}")
    path = Path(resolved).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise PermissionError(f"Executable is not runnable: {path}")
    return str(path)


def _looks_like_shell_c_flag(value: str) -> bool:
    return value.startswith("-") and "c" in value[1:]


def _validate_secret_use_argv(
    argv: Any,
    *,
    cwd: Path,
    secret_data: bytes,
) -> list[str]:
    if isinstance(argv, str):
        raise ValueError("argv must be a list, not a shell string")
    if not isinstance(argv, list) or not argv:
        raise ValueError("argv must be a non-empty list")
    if not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must contain non-empty strings")
    if not any(SECRET_FD_PLACEHOLDER in item for item in argv):
        raise ValueError(f"argv must include {SECRET_FD_PLACEHOLDER}")
    for index, item in enumerate(argv):
        _reject_secret_variants_in_text(item, secret_data, f"argv[{index}]")
    executable_name = Path(argv[0]).name
    if executable_name == "eval" or "eval" in argv:
        raise PermissionError("eval is not allowed for secret_use")
    if executable_name in SHELL_EXECUTABLES:
        if any(_looks_like_shell_c_flag(item) for item in argv[1:]):
            raise PermissionError("shell command mode is not allowed for secret_use")
    if executable_name == "env":
        for item in argv[1:]:
            if "=" in item and not item.startswith("-"):
                continue
            nested_name = Path(item).name
            if nested_name in SHELL_EXECUTABLES:
                raise PermissionError("env-to-shell is not allowed for secret_use")
            if nested_name == "eval":
                raise PermissionError("eval is not allowed for secret_use")
            if item == "--":
                continue
            break
    command = [_resolve_executable(argv[0], cwd), *argv[1:]]
    return command


def _secret_use_environment(
    extra_environment: dict[str, str] | None,
    secret_data: bytes,
) -> dict[str, str]:
    environment: dict[str, str] = {}
    for key in SECRET_USE_ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            _reject_secret_variants_in_text(value, secret_data, f"environment[{key}]")
            environment[key] = value
    environment["HOME"] = str(HOME)
    if extra_environment is None:
        return environment
    if not isinstance(extra_environment, dict):
        raise ValueError("environment must be an object")
    redaction_values = _secret_redaction_values(secret_data)
    for key, value in extra_environment.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("environment keys and values must be strings")
        if key not in SECRET_USE_ENV_ALLOWLIST:
            raise PermissionError(f"Environment key is not allowlisted: {key}")
        if any(part in key.upper() for part in SENSITIVE_ENV_PARTS):
            raise PermissionError(f"Sensitive environment key is not allowed: {key}")
        if any(secret and secret in value for secret in redaction_values):
            raise PermissionError(
                "Secret value or encoded secret value may not be placed in environment"
            )
        environment[key] = value
    return environment


def _materialize_secret_reference(data: bytes) -> dict[str, Any]:
    memfd_create = getattr(os, "memfd_create", None)
    if callable(memfd_create):
        fd = memfd_create("grabowski-secret", getattr(os, "MFD_CLOEXEC", 0))
        try:
            os.write(fd, data)
            os.lseek(fd, 0, os.SEEK_SET)
        except BaseException:
            os.close(fd)
            raise
        return {
            "fd": fd,
            "path": f"/proc/self/fd/{fd}",
            "temporary": None,
            "transport": "memfd",
        }

    root = _state_subdir(STATE_DIR / "secret-use")
    fd, temporary_name = tempfile.mkstemp(prefix="secret-", dir=str(root))
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {
        "fd": None,
        "path": str(temporary),
        "temporary": temporary,
        "transport": "temporary-file",
    }


def _cleanup_secret_reference(reference: dict[str, Any]) -> None:
    fd = reference.get("fd")
    if isinstance(fd, int):
        try:
            os.close(fd)
        except OSError:
            pass
    temporary = reference.get("temporary")
    if isinstance(temporary, Path):
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float = 3.0,
) -> tuple[bytes, bytes]:
    if process.poll() is not None:
        return process.communicate()
    os.killpg(process.pid, signal.SIGTERM)
    try:
        return process.communicate(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        return process.communicate()


def _read_limited_process_pipes(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> tuple[bytes, bytes, bool, bool, bool]:
    import selectors

    started = time.monotonic()
    timed_out = False
    stdout_truncated = False
    stderr_truncated = False
    buffers: dict[Any, bytearray] = {}
    selector = selectors.DefaultSelector()

    def append_limited(pipe: Any, chunk: bytes) -> None:
        nonlocal stdout_truncated, stderr_truncated
        if not chunk or pipe not in buffers:
            return
        buf = buffers[pipe]
        keep = 0
        if len(buf) < max_output_bytes:
            keep = min(len(chunk), max_output_bytes - len(buf))
            buf.extend(chunk[:keep])
        if len(chunk) > keep:
            if pipe is process.stdout:
                stdout_truncated = True
            else:
                stderr_truncated = True

    for pipe in (process.stdout, process.stderr):
        if pipe is None:
            continue
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
        buffers[pipe] = bytearray()

    while selector.get_map():
        remaining = timeout_seconds - (time.monotonic() - started)
        if remaining <= 0:
            timed_out = True
            stdout_tail, stderr_tail = _terminate_process_group(process)
            append_limited(process.stdout, stdout_tail)
            append_limited(process.stderr, stderr_tail)
            break
        for key, _events in selector.select(timeout=min(0.2, remaining)):
            pipe = key.fileobj
            chunk = os.read(pipe.fileno(), 8192)
            if not chunk:
                selector.unregister(pipe)
                continue
            append_limited(pipe, chunk)
        if process.poll() is not None:
            continue
    if process.poll() is None and not timed_out:
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(process)
    else:
        process.wait(timeout=0)
    stdout = bytes(buffers.get(process.stdout, b""))
    stderr = bytes(buffers.get(process.stderr, b""))
    selector.close()
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            pipe.close()
    return stdout, stderr, timed_out, stdout_truncated, stderr_truncated


def _run_secret_command(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    pass_fd: int | None,
    timeout_seconds: int,
    max_output_bytes: int,
    secret_data: bytes,
) -> dict[str, Any]:
    started = time.monotonic()
    pass_fds = () if pass_fd is None else (pass_fd,)
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=pass_fds,
        start_new_session=True,
    )
    stdout_raw, stderr_raw, timed_out, stdout_truncated, stderr_truncated = (
        _read_limited_process_pipes(
            process,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
    )

    stdout_text, stdout_redactions = _redact_secret_output(
        stdout_raw.decode("utf-8", errors="replace"),
        secret_data,
    )
    stderr_text, stderr_redactions = _redact_secret_output(
        stderr_raw.decode("utf-8", errors="replace"),
        secret_data,
    )
    stdout_text, stdout_late_truncated = _limit_text(stdout_text, max_output_bytes)
    stderr_text, stderr_late_truncated = _limit_text(stderr_text, max_output_bytes)
    return {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_truncated": stdout_truncated or stdout_late_truncated,
        "stderr_truncated": stderr_truncated or stderr_late_truncated,
        "redaction_count": stdout_redactions + stderr_redactions,
    }


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_root() -> Path:
    if STATE_DIR.is_symlink():
        raise PermissionError(f"State directory may not be a symlink: {STATE_DIR}")
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = STATE_DIR.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError(f"State root is not a directory: {root}")
    return root


def _state_subdir(path: Path) -> Path:
    root = _state_root()
    if path.is_symlink():
        raise PermissionError(f"State subdirectory may not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = path.resolve(strict=True)
    if not _path_inside(resolved, root):
        raise PermissionError(f"State subdirectory escaped state root: {resolved}")
    return resolved


def _new_transaction_dir(operation: str, target: Path) -> tuple[str, Path]:
    root = _state_subdir(QUARANTINE_DIR)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    transaction_id = f"{stamp}-{uuid.uuid4().hex[:12]}"
    directory = root / transaction_id
    directory.mkdir(mode=0o700)
    _write_json_evidence(
        directory / "intent.json",
        {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "operation": operation,
            "path": str(target),
            "created_at": _utc_timestamp(),
        },
    )
    return transaction_id, directory


def _write_json_evidence(path: Path, payload: dict[str, Any]) -> None:
    data = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)



def _audit_record_hash(record: dict[str, Any]) -> str:
    material = {key: value for key, value in record.items() if key != "record_sha256"}
    encoded = json.dumps(
        material,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _raw_line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _audit_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _validate_audit_file_contract(
    opened: os.stat_result,
    linked: os.stat_result,
) -> None:
    if (
        not statmod.S_ISREG(opened.st_mode)
        or not statmod.S_ISREG(linked.st_mode)
        or opened.st_dev != linked.st_dev
        or opened.st_ino != linked.st_ino
        or opened.st_uid != os.getuid()
        or opened.st_gid != os.getgid()
        or opened.st_nlink != 1
        or statmod.S_IMODE(opened.st_mode) != 0o600
    ):
        raise PermissionError("Audit log does not satisfy its file contract")
    if opened.st_size > MAX_AUDIT_BYTES:
        raise ValueError("audit-log-too-large")


def _read_audit_descriptor(descriptor: int, path: Path) -> bytes:
    before = os.fstat(descriptor)
    linked_before = os.stat(path, follow_symlinks=False)
    _validate_audit_file_contract(before, linked_before)
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    after = os.fstat(descriptor)
    linked_after = os.stat(path, follow_symlinks=False)
    if (
        len(data) != before.st_size
        or _audit_file_identity(before) != _audit_file_identity(after)
        or _audit_file_identity(before) != _audit_file_identity(linked_after)
    ):
        raise RuntimeError("Audit log changed while being read")
    return data


def _audit_parent(path: Path) -> Path:
    parent = path.parent
    if parent == STATE_DIR:
        _state_root()
    if parent.is_symlink():
        raise PermissionError("Audit parent directory may not be a symlink")
    metadata = os.stat(parent, follow_symlinks=False)
    if (
        not statmod.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or statmod.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise PermissionError(
            "Audit parent directory does not satisfy its file contract"
        )
    return parent


def _audit_storage_paths(path: Path) -> dict[str, Path]:
    parent = path.parent
    return {
        "segments": parent / "audit-segments",
        "manifests": parent / "audit-segment-manifests",
        "archive": parent / "audit-archive",
        "legacy_receipts": parent / "audit-rotation-receipts",
        "coordination_lock": parent / f"{path.name}.lock",
    }


def _ensure_private_audit_directory(path: Path) -> Path:
    if path.is_symlink():
        raise PermissionError("Audit evidence directory may not be a symlink")
    try:
        path.mkdir(mode=0o700)
        _fsync_directory(path.parent)
    except FileExistsError:
        pass
    metadata = os.stat(path, follow_symlinks=False)
    if (
        not statmod.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or statmod.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PermissionError("Audit evidence directory does not satisfy its contract")
    return path


def _acquire_flock(descriptor: int, *, exclusive: bool) -> None:
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    deadline = time.monotonic() + AUDIT_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Audit lock acquisition timed out") from exc
            time.sleep(min(AUDIT_LOCK_POLL_SECONDS, remaining))


@contextmanager
def _audit_coordination_lock(path: Path, *, exclusive: bool):
    parent = _audit_parent(path)
    lock_path = _audit_storage_paths(path)["coordination_lock"]
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        try:
            descriptor = os.open(lock_path, flags)
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    lock_path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                created = True
            except FileExistsError:
                descriptor = os.open(lock_path, flags)
    except OSError as exc:
        raise PermissionError("Audit coordination lock cannot be opened safely") from exc
    try:
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            _fsync_directory(parent)
        opened = os.fstat(descriptor)
        linked = os.stat(lock_path, follow_symlinks=False)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or not statmod.S_ISREG(linked.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_uid != os.getuid()
            or opened.st_gid != os.getgid()
            or opened.st_nlink != 1
            or statmod.S_IMODE(opened.st_mode) != 0o600
        ):
            raise PermissionError("Audit coordination lock violates its file contract")
        _acquire_flock(descriptor, exclusive=exclusive)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _acquire_audit_descriptor_lock(
    descriptor: int,
    path: Path,
    *,
    exclusive: bool,
) -> None:
    _acquire_flock(descriptor, exclusive=exclusive)
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(path, follow_symlinks=False)
        _validate_audit_file_contract(opened, linked)
    except BaseException:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        raise


def _close_audit_descriptor(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _open_audit_read_target(path: Path) -> int | None:
    _audit_parent(path)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PermissionError(
            "Audit log cannot be opened safely for verification"
        ) from exc
    try:
        _acquire_audit_descriptor_lock(
            descriptor,
            path,
            exclusive=False,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_audit_bytes(path: Path, data: bytes, *, exists: bool) -> dict[str, Any]:
    if not exists:
        return {
            "valid": True,
            "path": str(path),
            "exists": False,
            "records": 0,
            "legacy_records": 0,
            "v2_records": 0,
            "last_record_sha256": None,
            "active_bytes": 0,
            "error": None,
        }
    lines = data.splitlines()
    previous: str | None = None
    legacy_records = 0
    v2_records = 0
    records = 0
    seen_v2_record = False
    for index, line in enumerate(lines, start=1):
        if not line:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "active_bytes": len(data),
                "error": f"blank-line-{index}",
            }
        records += 1
        try:
            parsed = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "active_bytes": len(data),
                "error": f"line-{index}:{type(exc).__name__}",
            }
        if not isinstance(parsed, dict):
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "active_bytes": len(data),
                "error": f"line-{index}:not-object",
            }
        stored_hash = parsed.get("record_sha256")
        if stored_hash is None:
            if seen_v2_record:
                return {
                    "valid": False,
                    "path": str(path),
                    "exists": True,
                    "records": records,
                    "legacy_records": legacy_records,
                    "v2_records": v2_records,
                    "last_record_sha256": previous,
                    "active_bytes": len(data),
                    "error": f"line-{index}:legacy-record-after-v2",
                }
            legacy_records += 1
            previous = _raw_line_hash(line)
            continue
        if not (
            isinstance(stored_hash, str)
            and len(stored_hash) == 64
            and all(char in "0123456789abcdef" for char in stored_hash)
        ):
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "active_bytes": len(data),
                "error": f"line-{index}:invalid-record-hash",
            }
        if parsed.get("previous_record_sha256") != previous:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "active_bytes": len(data),
                "error": f"line-{index}:previous-hash-mismatch",
            }
        if parsed.get("sequence") != records:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "active_bytes": len(data),
                "error": f"line-{index}:sequence-mismatch",
            }
        expected_hash = _audit_record_hash(parsed)
        if expected_hash != stored_hash:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "active_bytes": len(data),
                "error": f"line-{index}:record-hash-mismatch",
            }
        v2_records += 1
        seen_v2_record = True
        previous = stored_hash

    return {
        "valid": True,
        "path": str(path),
        "exists": True,
        "records": records,
        "legacy_records": legacy_records,
        "v2_records": v2_records,
        "last_record_sha256": previous,
        "active_bytes": len(data),
        "error": None,
    }


def _verify_audit_descriptor(path: Path, descriptor: int) -> dict[str, Any]:
    try:
        data = _read_audit_descriptor(descriptor, path)
    except (OSError, PermissionError, RuntimeError, ValueError) as exc:
        return {
            "valid": False,
            "path": str(path),
            "exists": True,
            "records": 0,
            "legacy_records": 0,
            "v2_records": 0,
            "last_record_sha256": None,
            "active_bytes": 0,
            "error": str(exc),
        }
    return _verify_audit_bytes(path, data, exists=True)


def _read_audit_file(path: Path) -> tuple[bytes, dict[str, Any]]:
    descriptor = _open_audit_read_target(path)
    if descriptor is None:
        return b"", _verify_audit_bytes(path, b"", exists=False)
    try:
        data = _read_audit_descriptor(descriptor, path)
        return data, _verify_audit_bytes(path, data, exists=True)
    finally:
        _close_audit_descriptor(descriptor)


def _first_audit_record(data: bytes) -> dict[str, Any] | None:
    lines = data.splitlines()
    if not lines:
        return None
    parsed = json.loads(lines[0].decode("utf-8"))
    return parsed if isinstance(parsed, dict) else None


def _safe_audit_evidence_path(
    active_path: Path,
    value: Any,
    *,
    allowed_directory_names: tuple[str, ...],
) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("audit-chain-path-invalid")
    candidate = Path(value)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise ValueError("audit-chain-path-invalid")
    parent = candidate.parent.resolve(strict=True)
    allowed = {
        (active_path.parent / name).resolve(strict=True)
        for name in allowed_directory_names
        if (active_path.parent / name).is_dir()
    }
    if parent not in allowed:
        raise ValueError("audit-chain-path-outside-evidence-roots")
    return candidate


def _private_evidence_identity(path: Path, *, max_bytes: int) -> tuple[int, ...]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(path, follow_symlinks=False)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or not statmod.S_ISREG(linked.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_uid != os.getuid()
            or opened.st_gid != os.getgid()
            or opened.st_nlink != 1
            or statmod.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size > max_bytes
        ):
            raise PermissionError("Audit evidence file violates its contract")
        return _audit_file_identity(opened)
    finally:
        os.close(descriptor)


def _segment_cache_key(
    path: Path,
    expected: dict[str, Any],
) -> tuple[Any, ...]:
    segment_identity = _private_evidence_identity(path, max_bytes=MAX_AUDIT_BYTES)
    manifest_path = expected.get("manifest_path")
    manifest_identity = (
        _private_evidence_identity(
            manifest_path,
            max_bytes=MAX_AUDIT_EVIDENCE_BYTES,
        )
        if isinstance(manifest_path, Path)
        else None
    )
    binding = (
        expected.get("sha256"),
        expected.get("bytes"),
        expected.get("records"),
        expected.get("legacy_records"),
        expected.get("v2_records"),
        expected.get("last_record_sha256"),
        str(manifest_path) if manifest_path is not None else None,
        expected.get("manifest_sha256"),
        bool(expected.get("compatibility")),
    )
    return (
        str(path),
        segment_identity,
        manifest_identity,
        binding,
    )


def _segment_cache_get(key: tuple[Any, ...]) -> dict[str, Any] | None:
    with AUDIT_SEGMENT_CACHE_LOCK:
        cached = AUDIT_SEGMENT_VERIFICATION_CACHE.get(key)
        if cached is None:
            return None
        return {
            "status": dict(cached["status"]),
            "sha256": cached["sha256"],
            "first_record": (
                dict(cached["first_record"])
                if isinstance(cached.get("first_record"), dict)
                else None
            ),
        }


def _segment_cache_put(
    key: tuple[Any, ...],
    *,
    status: dict[str, Any],
    sha256: str,
    first_record: dict[str, Any] | None,
) -> None:
    with AUDIT_SEGMENT_CACHE_LOCK:
        if len(AUDIT_SEGMENT_VERIFICATION_CACHE) >= MAX_AUDIT_SEGMENT_CACHE_ENTRIES:
            AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
        AUDIT_SEGMENT_VERIFICATION_CACHE[key] = {
            "status": dict(status),
            "sha256": sha256,
            "first_record": dict(first_record) if first_record is not None else None,
        }


def _read_private_evidence(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(path, follow_symlinks=False)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or not statmod.S_ISREG(linked.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_uid != os.getuid()
            or opened.st_gid != os.getgid()
            or opened.st_nlink != 1
            or statmod.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size > max_bytes
        ):
            raise PermissionError("Audit evidence file violates its contract")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        linked_after = os.stat(path, follow_symlinks=False)
        if (
            len(data) != opened.st_size
            or _audit_file_identity(opened) != _audit_file_identity(after)
            or _audit_file_identity(opened) != _audit_file_identity(linked_after)
        ):
            raise RuntimeError("Audit evidence changed while being read")
        return data
    finally:
        os.close(descriptor)


def _audit_predecessor_binding(
    active_path: Path,
    record: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not record:
        return None
    operation = record.get("operation")
    if operation == "audit-segment-genesis-v1":
        return {
            "path": _safe_audit_evidence_path(
                active_path,
                record.get("archived_audit_path"),
                allowed_directory_names=("audit-segments", "audit-archive"),
            ),
            "sha256": record.get("archived_audit_sha256"),
            "bytes": record.get("archived_audit_bytes"),
            "records": record.get("archived_audit_records"),
            "legacy_records": record.get("archived_audit_legacy_records"),
            "v2_records": record.get("archived_audit_v2_records"),
            "last_record_sha256": record.get("archived_last_record_sha256"),
            "manifest_path": _safe_audit_evidence_path(
                active_path,
                record.get("segment_manifest_path"),
                allowed_directory_names=("audit-segment-manifests",),
            ),
            "manifest_sha256": record.get("segment_manifest_sha256"),
            "compatibility": False,
        }
    if operation == "audit-capacity-rotation-v1":
        return {
            "path": _safe_audit_evidence_path(
                active_path,
                record.get("archived_audit_path"),
                allowed_directory_names=("audit-segments", "audit-archive"),
            ),
            "sha256": record.get("archived_audit_sha256"),
            "bytes": record.get("archived_audit_bytes"),
            "records": record.get("archived_audit_records"),
            "legacy_records": None,
            "v2_records": None,
            "last_record_sha256": record.get("archived_last_record_sha256"),
            "manifest_path": None,
            "manifest_sha256": None,
            "compatibility": True,
        }
    if operation == "audit-rotation-genesis":
        return {
            "path": _safe_audit_evidence_path(
                active_path,
                record.get("archived_audit_path"),
                allowed_directory_names=("audit-segments", "audit-archive"),
            ),
            "sha256": record.get("archived_audit_sha256"),
            "bytes": record.get("archived_audit_bytes"),
            "records": record.get("archived_audit_records"),
            "legacy_records": None,
            "v2_records": None,
            "last_record_sha256": record.get("archived_audit_last_record_sha256"),
            "manifest_path": _safe_audit_evidence_path(
                active_path,
                record.get("rotation_manifest_path"),
                allowed_directory_names=("audit-rotation-receipts",),
            ),
            "manifest_sha256": record.get("rotation_manifest_sha256"),
            "compatibility": True,
        }
    return None


def _validate_segment_manifest(
    binding: dict[str, Any],
    *,
    segment_status: dict[str, Any],
    segment_bytes: bytes,
) -> None:
    manifest_path = binding.get("manifest_path")
    manifest_sha256 = binding.get("manifest_sha256")
    if manifest_path is None:
        return
    manifest_data = _read_private_evidence(
        manifest_path,
        max_bytes=MAX_AUDIT_EVIDENCE_BYTES,
    )
    if hashlib.sha256(manifest_data).hexdigest() != manifest_sha256:
        raise ValueError("audit-segment-manifest-sha256-mismatch")
    try:
        manifest = json.loads(manifest_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("audit-segment-manifest-invalid") from exc
    if not isinstance(manifest, dict):
        raise ValueError("audit-segment-manifest-invalid")
    if manifest.get("kind") == "grabowski_audit_segment_manifest":
        expected = {
            "schema_version": AUDIT_SEGMENT_SCHEMA_VERSION,
            "kind": "grabowski_audit_segment_manifest",
            "segment_path": str(binding["path"]),
            "segment_sha256": binding["sha256"],
            "segment_bytes": len(segment_bytes),
            "records": segment_status["records"],
            "legacy_records": segment_status["legacy_records"],
            "v2_records": segment_status["v2_records"],
            "last_record_sha256": segment_status["last_record_sha256"],
            "created_at": manifest.get("created_at"),
        }
        if manifest != expected or not isinstance(manifest.get("created_at"), str):
            raise ValueError("audit-segment-manifest-binding-mismatch")
        return
    if manifest.get("kind") == "grabowski_audit_rotation":
        if (
            manifest.get("archive_path") != str(binding["path"])
            or manifest.get("archive_sha256") != binding["sha256"]
            or manifest.get("source_records") != segment_status["records"]
            or manifest.get("source_last_record_sha256")
            != segment_status["last_record_sha256"]
        ):
            raise ValueError("audit-legacy-rotation-manifest-binding-mismatch")
        return
    raise ValueError("audit-segment-manifest-kind-invalid")


def _read_audit_chain_unlocked(
    path: Path,
    *,
    use_segment_cache: bool = True,
) -> tuple[list[tuple[Path, bytes, dict[str, Any]]], bool]:
    components: list[tuple[Path, bytes, dict[str, Any]]] = []
    seen: set[Path] = set()
    current = path
    expected: dict[str, Any] | None = None
    compatibility_evidence = False
    for _ in range(MAX_AUDIT_SEGMENTS + 1):
        resolved = current.resolve(strict=False)
        if resolved in seen:
            raise ValueError("audit-segment-cycle")
        seen.add(resolved)
        cached: dict[str, Any] | None = None
        cache_key: tuple[Any, ...] | None = None
        if expected is not None and use_segment_cache:
            cache_key = _segment_cache_key(current, expected)
            cached = _segment_cache_get(cache_key)
        if cached is not None:
            data = b""
            status = cached["status"]
            observed_sha = str(cached["sha256"])
            first_record = cached.get("first_record")
        else:
            data, status = _read_audit_file(current)
            if not status["valid"]:
                if expected is None and current == path:
                    raise ValueError(str(status["error"]))
                raise ValueError(f"audit-segment-invalid:{status['error']}")
            observed_sha = hashlib.sha256(data).hexdigest()
            first_record = _first_audit_record(data)
        if expected is not None:
            if observed_sha != expected.get("sha256"):
                raise ValueError("audit-segment-sha256-mismatch")
            expected_bytes = expected.get("bytes")
            observed_bytes = int(status.get("active_bytes") or 0)
            if expected_bytes is not None and expected_bytes != observed_bytes:
                raise ValueError("audit-segment-byte-count-mismatch")
            if status["records"] != expected.get("records"):
                raise ValueError("audit-segment-record-count-mismatch")
            if status["last_record_sha256"] != expected.get("last_record_sha256"):
                raise ValueError("audit-segment-last-hash-mismatch")
            if (
                expected.get("legacy_records") is not None
                and status["legacy_records"] != expected.get("legacy_records")
            ):
                raise ValueError("audit-segment-legacy-count-mismatch")
            if (
                expected.get("v2_records") is not None
                and status["v2_records"] != expected.get("v2_records")
            ):
                raise ValueError("audit-segment-v2-count-mismatch")
            if cached is None:
                _validate_segment_manifest(
                    expected,
                    segment_status=status,
                    segment_bytes=data,
                )
                if use_segment_cache and cache_key is not None:
                    _segment_cache_put(
                        cache_key,
                        status=status,
                        sha256=observed_sha,
                        first_record=first_record,
                    )
            compatibility_evidence = compatibility_evidence or bool(
                expected.get("compatibility")
            )
        components.append((current, data, status))
        binding = _audit_predecessor_binding(path, first_record)
        if binding is None:
            return components, compatibility_evidence
        current = binding["path"]
        expected = binding
    raise ValueError("audit-segment-limit-exceeded")


def _audit_capacity_status(
    path: Path,
    audit: dict[str, Any],
) -> dict[str, Any]:
    active_bytes = int(audit.get("active_bytes") or 0)
    remaining = max(0, MAX_AUDIT_BYTES - active_bytes)
    threshold = max(0, MAX_AUDIT_BYTES - AUDIT_ROTATION_RESERVE_BYTES)
    rotation_required = bool(audit.get("exists")) and active_bytes >= threshold
    configuration_valid = (
        MAX_AUDIT_BYTES
        > AUDIT_ROTATION_RESERVE_BYTES + MAX_AUDIT_RECORD_BYTES + 4096
    )
    try:
        free_bytes = shutil.disk_usage(path.parent).free
    except OSError:
        free_bytes = 0
    minimum_free_bytes = (
        active_bytes
        + AUDIT_ROTATION_RESERVE_BYTES
        + MAX_AUDIT_RECORD_BYTES
        + 4096
    )
    writable = (
        bool(audit.get("valid"))
        and configuration_valid
        and free_bytes >= minimum_free_bytes
    )
    if not audit.get("valid"):
        state = "invalid"
    elif not configuration_valid:
        state = "configuration_invalid"
    elif free_bytes < minimum_free_bytes:
        state = "storage_exhausted"
    elif rotation_required:
        state = "rotation_required"
    else:
        state = "ready"
    return {
        "audit_writable": writable,
        "audit_state": state,
        "active_bytes": active_bytes,
        "max_bytes": MAX_AUDIT_BYTES,
        "remaining_bytes": remaining,
        "reserve_bytes": AUDIT_ROTATION_RESERVE_BYTES,
        "max_record_bytes": MAX_AUDIT_RECORD_BYTES,
        "rotation_threshold_bytes": threshold,
        "rotation_required": rotation_required,
        "filesystem_free_bytes": free_bytes,
        "minimum_free_bytes": minimum_free_bytes,
    }


def _verify_audit_log_unlocked(path: Path = AUDIT_LOG) -> dict[str, Any]:
    try:
        components, compatibility_evidence = _read_audit_chain_unlocked(path)
        if not components:
            status = _verify_audit_bytes(path, b"", exists=False)
            status.update(
                {
                    "total_records": 0,
                    "total_legacy_records": 0,
                    "total_v2_records": 0,
                    "archived_segment_count": 0,
                    "chain_valid": True,
                    "legacy_rotation_compatibility": False,
                }
            )
        else:
            status = dict(components[0][2])
            status.update(
                {
                    "total_records": sum(item[2]["records"] for item in components),
                    "total_legacy_records": sum(
                        item[2]["legacy_records"] for item in components
                    ),
                    "total_v2_records": sum(
                        item[2]["v2_records"] for item in components
                    ),
                    "archived_segment_count": len(components) - 1,
                    "chain_valid": True,
                    "legacy_rotation_compatibility": compatibility_evidence,
                }
            )
        status.update(_audit_capacity_status(path, status))
        return status
    except (OSError, PermissionError, RuntimeError, ValueError) as exc:
        status = {
            "valid": False,
            "path": str(path),
            "exists": path.exists(),
            "records": 0,
            "legacy_records": 0,
            "v2_records": 0,
            "last_record_sha256": None,
            "active_bytes": 0,
            "total_records": 0,
            "total_legacy_records": 0,
            "total_v2_records": 0,
            "archived_segment_count": 0,
            "chain_valid": False,
            "legacy_rotation_compatibility": False,
            "error": str(exc),
        }
        status.update(_audit_capacity_status(path, status))
        return status


def _verify_audit_log(path: Path = AUDIT_LOG) -> dict[str, Any]:
    try:
        lock_path = _audit_storage_paths(path)["coordination_lock"]
        if not path.exists() and not lock_path.exists():
            return _verify_audit_log_unlocked(path)
        with _audit_coordination_lock(path, exclusive=False):
            return _verify_audit_log_unlocked(path)
    except (OSError, PermissionError, RuntimeError, ValueError) as exc:
        status = {
            "valid": False,
            "path": str(path),
            "exists": path.exists(),
            "records": 0,
            "legacy_records": 0,
            "v2_records": 0,
            "last_record_sha256": None,
            "active_bytes": 0,
            "total_records": 0,
            "total_legacy_records": 0,
            "total_v2_records": 0,
            "archived_segment_count": 0,
            "chain_valid": False,
            "legacy_rotation_compatibility": False,
            "error": str(exc),
        }
        status.update(_audit_capacity_status(path, status))
        return status


def _open_audit_append_target(path: Path) -> tuple[int, bool]:
    parent = _audit_parent(path)
    flags = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                created = True
            except FileExistsError:
                descriptor = os.open(path, flags)
    except OSError as exc:
        raise PermissionError("Audit log cannot be opened safely for append") from exc

    try:
        if created:
            os.fchmod(descriptor, 0o600)
        _acquire_audit_descriptor_lock(
            descriptor,
            path,
            exclusive=True,
        )
        if created:
            _fsync_directory(parent)
        return descriptor, created
    except BaseException:
        os.close(descriptor)
        raise


def _require_audit_descriptor_bound(descriptor: int, path: Path) -> None:
    opened = os.fstat(descriptor)
    try:
        linked = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise PermissionError("Audit log path changed during append") from exc
    _validate_audit_file_contract(opened, linked)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("Audit append made no forward progress")
        remaining = remaining[written:]


def _rollback_audit_descriptor(descriptor: int, expected_size: int) -> None:
    os.ftruncate(descriptor, expected_size)
    os.fsync(descriptor)
    if os.fstat(descriptor).st_size != expected_size:
        raise RuntimeError("Audit append rollback size postflight mismatch")


def _canonical_json_line(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _enriched_audit_record(
    record: dict[str, Any],
    status: dict[str, Any],
) -> tuple[dict[str, Any], bytes]:
    enriched = {**record}
    enriched.setdefault("timestamp", _utc_timestamp())
    enriched["audit_schema_version"] = AUDIT_SCHEMA_VERSION
    enriched["sequence"] = int(status["records"]) + 1
    enriched["previous_record_sha256"] = status["last_record_sha256"]
    enriched["record_sha256"] = _audit_record_hash(enriched)
    payload = _canonical_json_line(enriched)
    if len(payload) > MAX_AUDIT_RECORD_BYTES:
        raise ValueError("Audit record would exceed its byte limit")
    return enriched, payload


def _write_private_create_only(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != len(data):
            raise RuntimeError("Audit evidence write size mismatch")
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _rotate_audit_segment(
    path: Path,
    descriptor: int,
    status: dict[str, Any],
    *,
    next_record_bytes: int,
) -> None:
    _require_audit_descriptor_bound(descriptor, path)
    data = _read_audit_descriptor(descriptor, path)
    if not data or status["records"] <= 0:
        raise ValueError("Audit log would exceed its byte limit")
    segment_sha256 = hashlib.sha256(data).hexdigest()
    paths = _audit_storage_paths(path)
    segment_dir = _ensure_private_audit_directory(paths["segments"])
    manifest_dir = _ensure_private_audit_directory(paths["manifests"])
    timestamp = re.sub(r"[^0-9A-Za-z]+", "", _utc_timestamp())
    unique = uuid.uuid4().hex[:12]
    stem = f"{path.stem}-{timestamp}-{segment_sha256[:12]}-{unique}"
    segment_path = segment_dir / f"{stem}.jsonl"
    manifest_path = manifest_dir / f"{stem}.json"
    manifest = {
        "schema_version": AUDIT_SEGMENT_SCHEMA_VERSION,
        "kind": "grabowski_audit_segment_manifest",
        "segment_path": str(segment_path),
        "segment_sha256": segment_sha256,
        "segment_bytes": len(data),
        "records": status["records"],
        "legacy_records": status["legacy_records"],
        "v2_records": status["v2_records"],
        "last_record_sha256": status["last_record_sha256"],
        "created_at": _utc_timestamp(),
    }
    manifest_data = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    manifest_sha256 = hashlib.sha256(manifest_data).hexdigest()
    genesis = {
        "operation": "audit-segment-genesis-v1",
        "reason": "capacity-threshold",
        "segment_schema_version": AUDIT_SEGMENT_SCHEMA_VERSION,
        "archived_audit_path": str(segment_path),
        "archived_audit_sha256": segment_sha256,
        "archived_audit_bytes": len(data),
        "archived_audit_records": status["records"],
        "archived_audit_legacy_records": status["legacy_records"],
        "archived_audit_v2_records": status["v2_records"],
        "archived_last_record_sha256": status["last_record_sha256"],
        "segment_manifest_path": str(manifest_path),
        "segment_manifest_sha256": manifest_sha256,
        "timestamp": _utc_timestamp(),
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "sequence": 1,
        "previous_record_sha256": None,
    }
    genesis["record_sha256"] = _audit_record_hash(genesis)
    genesis_data = _canonical_json_line(genesis)
    if (
        len(genesis_data)
        + next_record_bytes
        + AUDIT_ROTATION_RESERVE_BYTES
        > MAX_AUDIT_BYTES
    ):
        raise ValueError("Audit log would exceed its byte limit")
    _write_private_create_only(segment_path, data)
    _write_private_create_only(manifest_path, manifest_data)
    temporary_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.rotation-",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    replaced = False
    try:
        os.fchmod(temporary_descriptor, 0o600)
        _write_all(temporary_descriptor, genesis_data)
        os.fsync(temporary_descriptor)
        if os.fstat(temporary_descriptor).st_size != len(genesis_data):
            raise RuntimeError("Audit rotation genesis size mismatch")
        _require_audit_descriptor_bound(descriptor, path)
        os.replace(temporary_path, path)
        replaced = True
        _fsync_directory(path.parent)
    finally:
        os.close(temporary_descriptor)
        if not replaced:
            try:
                temporary_path.unlink()
                _fsync_directory(path.parent)
            except FileNotFoundError:
                pass


def _append_payload(descriptor: int, path: Path, payload: bytes) -> None:
    current_size = os.fstat(descriptor).st_size
    if current_size + len(payload) > MAX_AUDIT_BYTES:
        raise ValueError("Audit log would exceed its byte limit")
    _require_audit_descriptor_bound(descriptor, path)
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        _require_audit_descriptor_bound(descriptor, path)
        appended = os.fstat(descriptor)
        if appended.st_size != current_size + len(payload):
            raise RuntimeError("Audit append size postflight mismatch")
    except BaseException:
        try:
            _rollback_audit_descriptor(descriptor, current_size)
        except BaseException as rollback_error:
            raise RuntimeError(
                "Audit append failed and rollback did not complete"
            ) from rollback_error
        raise


def _append_audit(record: dict[str, Any]) -> None:
    with AUDIT_APPEND_LOCK:
        if AUDIT_LOG.is_symlink():
            raise PermissionError(f"Audit log may not be a symlink: {AUDIT_LOG}")
        with _audit_coordination_lock(AUDIT_LOG, exclusive=True):
            descriptor: int | None = None
            try:
                chain_status = _verify_audit_log_unlocked(AUDIT_LOG)
                if not chain_status["valid"]:
                    chain_error = str(chain_status["error"])
                    if (
                        "file contract" in chain_error
                        or "parent directory" in chain_error
                        or "symlink" in chain_error
                    ):
                        raise PermissionError(chain_error)
                    raise RuntimeError(
                        f"Audit log verification failed: {chain_error}"
                    )
                descriptor, _created = _open_audit_append_target(AUDIT_LOG)
                status = _verify_audit_descriptor(AUDIT_LOG, descriptor)
                if not status["valid"]:
                    raise RuntimeError(
                        f"Audit log verification failed: {status['error']}"
                    )
                _enriched, payload = _enriched_audit_record(record, status)
                current_size = os.fstat(descriptor).st_size
                needs_rotation = (
                    current_size > 0
                    and current_size
                    + len(payload)
                    + AUDIT_ROTATION_RESERVE_BYTES
                    > MAX_AUDIT_BYTES
                )
                if needs_rotation:
                    if (
                        MAX_AUDIT_BYTES
                        <= AUDIT_ROTATION_RESERVE_BYTES
                        + MAX_AUDIT_RECORD_BYTES
                        + 4096
                    ):
                        raise ValueError("Audit log would exceed its byte limit")
                    _rotate_audit_segment(
                        AUDIT_LOG,
                        descriptor,
                        status,
                        next_record_bytes=len(payload),
                    )
                    _close_audit_descriptor(descriptor)
                    descriptor = None
                    descriptor, _created = _open_audit_append_target(AUDIT_LOG)
                    status = _verify_audit_descriptor(AUDIT_LOG, descriptor)
                    if not status["valid"]:
                        raise RuntimeError(
                            f"Audit rotation verification failed: {status['error']}"
                        )
                    _enriched, payload = _enriched_audit_record(record, status)
                elif current_size + len(payload) > MAX_AUDIT_BYTES:
                    raise ValueError("Audit log would exceed its byte limit")
                _append_payload(descriptor, AUDIT_LOG, payload)
            finally:
                if descriptor is not None:
                    _close_audit_descriptor(descriptor)


def _audit_records() -> list[dict[str, Any]]:
    with _audit_coordination_lock(AUDIT_LOG, exclusive=False):
        components, _compatibility = _read_audit_chain_unlocked(
            AUDIT_LOG,
            use_segment_cache=False,
        )
        records: list[dict[str, Any]] = []
        for _path, data, _status in reversed(components):
            for line in data.splitlines():
                parsed = json.loads(line.decode("utf-8"))
                if isinstance(parsed, dict):
                    records.append(parsed)
        return records


def _find_transaction_record(transaction_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{12}", transaction_id):
        raise ValueError("Invalid transaction_id")
    for record in reversed(_audit_records()):
        if record.get("transaction_id") == transaction_id:
            return record
    raise ValueError(f"Transaction not found in audit log: {transaction_id}")


_DEPLOYMENT_IDENTITY_KEYS = (
    "manifest_parse_valid",
    "manifest_schema_valid",
    "release_path_valid",
    "release_id_valid",
    "repo_head_valid",
    "stable_runtime_manifest_valid",
    "runtime_pointer_valid",
    "runtime_input_identity_valid",
    "lock_identity_valid",
    "source_snapshot_identity_valid",
    "source_identity_valid",
    "embedded_contract_valid",
    "entrypoint_contract_identity_valid",
    "agent_instructions_identity_valid",
    "entrypoint_path_valid",
    "release_python_identity_valid",
    "executable_identity_valid",
    "pip_identity_valid",
    "protocol_identity_valid",
    "python_runtime_identity_valid",
    "platform_identity_valid",
    "artifact_integrity_valid",
    "runtime_binding_valid",
    "environment_compatibility_valid",
)


def _false_deployment_metadata(base: dict[str, Any], **extra: Any) -> dict[str, Any]:
    result = {**base}
    for key in _DEPLOYMENT_IDENTITY_KEYS:
        result[key] = False
    result["provenance_valid"] = False
    result.update(extra)
    return result


def _path_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _is_lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in "0123456789abcdef" for char in value)
    )


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and path.as_posix() != "."


def _valid_agent_instructions_identity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {
            "schema_version",
            "version",
            "sha256",
            "bytes",
            "max_bytes",
        }
        and value.get("schema_version") == AGENT_INSTRUCTIONS_SCHEMA_VERSION
        and value.get("version") == AGENT_INSTRUCTIONS_VERSION
        and _is_lower_hex(value.get("sha256"), 64)
        and isinstance(value.get("bytes"), int)
        and not isinstance(value.get("bytes"), bool)
        and 0 < value["bytes"] <= AGENT_INSTRUCTIONS_MAX_BYTES
        and value.get("max_bytes") == AGENT_INSTRUCTIONS_MAX_BYTES
    )


def _manifest_schema_valid(raw: dict[str, Any]) -> bool:
    required = {
        "schema_version": int,
        "release_id": str,
        "repo_head": str,
        "entrypoint_contract": dict,
        "entrypoint_contract_sha256": str,
        "agent_instructions": dict,
        "source_sha256": str,
        "source_sha256s": dict,
        "runtime_asset_sha256s": dict,
        "runtime_asset_paths": dict,
        "runtime_input_sha256": str,
        "runtime_lock_sha256": str,
        "snapshot_paths": dict,
        "immutable_release_path": str,
        "expected_stable_runtime_path": str,
        "release_python_path": str,
        "entrypoint_path": str,
        "module_paths": dict,
        "platform": str,
        "python_version": str,
        "python_implementation": str,
        "mcp_protocol_version": str,
        "created_at_unix": int,
        "completion_status": str,
        "executable": str,
        "pip_version": str,
    }
    for key, kind in required.items():
        value = raw.get(key)
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            return False
    if (
        raw.get("schema_version") != DEPLOYMENT_MANIFEST_SCHEMA_VERSION
        or raw.get("completion_status") != "complete"
    ):
        return False
    if not _is_lower_hex(raw.get("repo_head"), 40):
        return False
    for key in (
        "entrypoint_contract_sha256",
        "source_sha256",
        "runtime_input_sha256",
        "runtime_lock_sha256",
    ):
        if not _is_lower_hex(raw.get(key), 64):
            return False
    if not _valid_agent_instructions_identity(raw.get("agent_instructions")):
        return False
    contract = raw.get("entrypoint_contract")
    if not isinstance(contract, dict):
        return False
    schema_version = contract.get("schema_version")
    expected_keys = {"schema_version", "mode", "module", "source", "expected_tools"}
    if schema_version in {2, 3}:
        expected_keys.add("supporting_sources")
    if schema_version == 3:
        expected_keys.add("runtime_assets")
    if schema_version not in {1, 2, 3} or set(contract) != expected_keys:
        return False
    module = contract.get("module")
    source = contract.get("source")
    if (
        contract.get("mode") != "module"
        or not isinstance(module, str)
        or MODULE_RE.fullmatch(module) is None
        or not _safe_relative_path(source)
    ):
        return False
    tools = contract.get("expected_tools")
    if (
        not isinstance(tools, list)
        or not tools
        or not all(isinstance(item, str) and item for item in tools)
        or len(set(tools)) != len(tools)
    ):
        return False
    modules = {module}
    sources = {source}
    supporting_modules: set[str] = set()
    supporting = contract.get("supporting_sources", [])
    if not isinstance(supporting, list):
        return False
    for item in supporting:
        if not isinstance(item, dict) or set(item) != {"module", "source"}:
            return False
        item_module = item.get("module")
        item_source = item.get("source")
        if (
            not isinstance(item_module, str)
            or MODULE_RE.fullmatch(item_module) is None
            or item_module in modules
            or not _safe_relative_path(item_source)
            or item_source in sources
        ):
            return False
        modules.add(item_module)
        supporting_modules.add(item_module)
        sources.add(item_source)

    runtime_asset_destinations: set[str] = set()
    runtime_asset_sources: set[str] = set()
    runtime_assets = contract.get("runtime_assets", [])
    if not isinstance(runtime_assets, list):
        return False
    for item in runtime_assets:
        if not isinstance(item, dict) or set(item) != {"source", "destination"}:
            return False
        asset_source = item.get("source")
        destination = item.get("destination")
        if (
            not _safe_relative_path(asset_source)
            or not _safe_relative_path(destination)
            or asset_source in sources
            or asset_source in runtime_asset_sources
            or Path(asset_source).as_posix() in RESERVED_DEPLOYMENT_SNAPSHOT_INPUTS
            or destination in runtime_asset_destinations
        ):
            return False
        destination_path = Path(destination)
        if (
            destination_path.parts[0] in {".venv", "inputs"}
            or destination in {"deployment-manifest.json", "deployment-incomplete.json"}
            or any(
                destination_path in Path(existing).parents
                or Path(existing) in destination_path.parents
                for existing in runtime_asset_destinations
            )
        ):
            return False
        runtime_asset_sources.add(asset_source)
        runtime_asset_destinations.add(destination)

    hashes = raw.get("source_sha256s")
    if (
        not isinstance(hashes, dict)
        or set(hashes) != modules
        or not all(_is_lower_hex(value, 64) for value in hashes.values())
        or hashes.get(module) != raw.get("source_sha256")
    ):
        return False
    asset_hashes = raw.get("runtime_asset_sha256s")
    if (
        not isinstance(asset_hashes, dict)
        or set(asset_hashes) != runtime_asset_destinations
        or not all(_is_lower_hex(value, 64) for value in asset_hashes.values())
    ):
        return False
    asset_paths = raw.get("runtime_asset_paths")
    if (
        not isinstance(asset_paths, dict)
        or set(asset_paths) != runtime_asset_destinations
        or not all(isinstance(value, str) and value for value in asset_paths.values())
    ):
        return False
    module_paths = raw.get("module_paths")
    if (
        not isinstance(module_paths, dict)
        or set(module_paths) != modules
        or not all(isinstance(value, str) and value for value in module_paths.values())
        or module_paths.get(module) != raw.get("entrypoint_path")
    ):
        return False
    snapshot_paths = raw.get("snapshot_paths")
    if not isinstance(snapshot_paths, dict) or set(snapshot_paths) != {
        "runtime_entrypoint",
        "runtime_input",
        "runtime_lock",
        "source",
        "supporting_sources",
        "runtime_assets",
    }:
        return False
    if not all(
        isinstance(snapshot_paths.get(key), str) and snapshot_paths.get(key)
        for key in ("runtime_entrypoint", "runtime_input", "runtime_lock", "source")
    ):
        return False
    support_paths = snapshot_paths.get("supporting_sources")
    if (
        not isinstance(support_paths, dict)
        or set(support_paths) != supporting_modules
        or not all(isinstance(value, str) and value for value in support_paths.values())
    ):
        return False
    runtime_asset_snapshot_paths = snapshot_paths.get("runtime_assets")
    if (
        not isinstance(runtime_asset_snapshot_paths, dict)
        or set(runtime_asset_snapshot_paths) != runtime_asset_destinations
        or not all(
            isinstance(value, str) and value
            for value in runtime_asset_snapshot_paths.values()
        )
    ):
        return False
    created = raw.get("created_at_unix")
    return isinstance(created, int) and not isinstance(created, bool) and created > 0


def _read_bound_regular_file(
    recorded: Any,
    expected: Path,
    release_root: Path,
    *,
    max_bytes: int,
) -> bytes | None:
    """Read only the exact expected regular file after binding path and inode."""
    if not isinstance(recorded, str) or Path(recorded) != expected:
        return None
    fd: int | None = None
    try:
        release_real = release_root.resolve(strict=True)
        parent_real = expected.parent.resolve(strict=True)
        if not _path_inside(parent_real, release_real):
            return None
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(expected, flags)
        opened = os.fstat(fd)
        linked = os.stat(expected, follow_symlinks=False)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or not statmod.S_ISREG(linked.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_nlink != 1
            or opened.st_size > max_bytes
        ):
            return None
        resolved = expected.resolve(strict=True)
        if not _path_inside(resolved, release_real):
            return None
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        return data if len(data) <= max_bytes else None
    except (OSError, RuntimeError, ValueError):
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _deployment_metadata() -> dict[str, Any]:
    """Return fail-closed deployment evidence without leaking manifest errors."""
    try:
        return _deployment_metadata_impl()
    except Exception as exc:  # pragma: no cover - final status containment
        try:
            manifest_exists = DEPLOYMENT_MANIFEST.is_file()
        except OSError:
            manifest_exists = False
        return _false_deployment_metadata(
            {
                "manifest_path": str(DEPLOYMENT_MANIFEST),
                "manifest_exists": manifest_exists,
            },
            error_type=type(exc).__name__,
        )


def _deployment_metadata_impl() -> dict[str, Any]:
    manifest_path = DEPLOYMENT_MANIFEST
    base: dict[str, Any] = {
        "manifest_path": str(manifest_path),
        "manifest_exists": manifest_path.is_file(),
    }
    if not manifest_path.is_file():
        return _false_deployment_metadata(base)
    try:
        info = manifest_path.stat()
        if not statmod.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            return _false_deployment_metadata(base, error_type="UnsafeManifest")
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return _false_deployment_metadata(base, error_type=type(exc).__name__)
    if not isinstance(raw, dict):
        return _false_deployment_metadata(base, manifest_parse_valid=True)

    schema_valid = _manifest_schema_valid(raw)
    agent_instructions_identity_valid = (
        raw.get("agent_instructions") == _agent_instructions_metadata()
    )
    release_root = manifest_path.parent.resolve()
    snapshot_paths = (
        raw.get("snapshot_paths") if isinstance(raw.get("snapshot_paths"), dict) else {}
    )
    canonical_runtime = EXPECTED_STABLE_RUNTIME
    canonical_releases = canonical_runtime.parent / "grabowski-mcp-releases"

    stable_runtime_manifest_valid = (
        isinstance(raw.get("expected_stable_runtime_path"), str)
        and Path(raw["expected_stable_runtime_path"]) == canonical_runtime
    )
    release_path_valid = False
    try:
        release_path_valid = (
            isinstance(raw.get("immutable_release_path"), str)
            and Path(raw["immutable_release_path"]).resolve(strict=True) == release_root
            and release_root.parent == canonical_releases.resolve(strict=True)
        )
    except (OSError, RuntimeError):
        release_path_valid = False
    release_id_valid = (
        isinstance(raw.get("release_id"), str)
        and raw.get("release_id") == release_root.name
    )
    repo_head_valid = _is_lower_hex(raw.get("repo_head"), 40)
    runtime_pointer_valid = False
    try:
        runtime_pointer_valid = (
            canonical_runtime.is_symlink()
            and canonical_runtime.resolve(strict=True) == release_root
        )
    except (OSError, RuntimeError):
        runtime_pointer_valid = False

    def snapshot_bytes(
        key: str, relative: str, limit: int = MAX_SNAPSHOT_BYTES
    ) -> bytes | None:
        return _read_bound_regular_file(
            snapshot_paths.get(key),
            release_root / relative,
            release_root,
            max_bytes=limit,
        )

    runtime_input_data = snapshot_bytes("runtime_input", "inputs/runtime.in")
    runtime_lock_data = snapshot_bytes("runtime_lock", "inputs/runtime.lock.txt")
    runtime_input_identity_valid = runtime_input_data is not None and hashlib.sha256(
        runtime_input_data
    ).hexdigest() == raw.get("runtime_input_sha256")
    lock_identity_valid = runtime_lock_data is not None and hashlib.sha256(
        runtime_lock_data
    ).hexdigest() == raw.get("runtime_lock_sha256")

    expected_contract = release_root / "inputs/runtime-entrypoint.json"
    contract_data = _read_bound_regular_file(
        snapshot_paths.get("runtime_entrypoint"),
        expected_contract,
        release_root,
        max_bytes=MAX_CONTRACT_BYTES,
    )
    contract_raw: dict[str, Any] | None = None
    if contract_data is not None:
        try:
            parsed = json.loads(contract_data.decode("utf-8"))
            if isinstance(parsed, dict):
                contract_raw = parsed
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    entrypoint_contract_identity_valid = (
        contract_data is not None
        and contract_raw is not None
        and hashlib.sha256(contract_data).hexdigest()
        == raw.get("entrypoint_contract_sha256")
        and _manifest_schema_valid({**raw, "entrypoint_contract": contract_raw})
    )
    embedded_contract_valid = (
        isinstance(raw.get("entrypoint_contract"), dict)
        and raw.get("entrypoint_contract") == contract_raw
    )

    contract_sources: list[tuple[str, str]] = []
    contract_assets: list[tuple[str, str]] = []
    if contract_raw is not None:
        main_module = contract_raw.get("module")
        main_source = contract_raw.get("source")
        if (
            isinstance(main_module, str)
            and MODULE_RE.fullmatch(main_module) is not None
            and _safe_relative_path(main_source)
        ):
            contract_sources.append((main_module, main_source))
        supporting = contract_raw.get("supporting_sources", [])
        if isinstance(supporting, list):
            for item in supporting:
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("module"), str)
                    and MODULE_RE.fullmatch(item["module"]) is not None
                    and _safe_relative_path(item.get("source"))
                ):
                    contract_sources.append((item["module"], item["source"]))
        runtime_assets = contract_raw.get("runtime_assets", [])
        if isinstance(runtime_assets, list):
            for item in runtime_assets:
                if (
                    isinstance(item, dict)
                    and _safe_relative_path(item.get("source"))
                    and _safe_relative_path(item.get("destination"))
                ):
                    contract_assets.append((item["source"], item["destination"]))

    source_hashes = raw.get("source_sha256s")
    module_paths = raw.get("module_paths")
    supporting_snapshot_paths = snapshot_paths.get("supporting_sources")
    snapshot_identity_by_module: dict[str, bool] = {}
    module_identity_by_module: dict[str, bool] = {}
    module_origins: dict[str, Path] = {}

    for index, (module_name, source_name) in enumerate(contract_sources):
        recorded_snapshot = (
            snapshot_paths.get("source")
            if index == 0
            else (
                supporting_snapshot_paths.get(module_name)
                if isinstance(supporting_snapshot_paths, dict)
                else None
            )
        )
        snapshot_data = _read_bound_regular_file(
            recorded_snapshot,
            release_root / "inputs" / source_name,
            release_root,
            max_bytes=MAX_SNAPSHOT_BYTES,
        )
        expected_hash = (
            source_hashes.get(module_name) if isinstance(source_hashes, dict) else None
        )
        snapshot_identity_by_module[module_name] = (
            snapshot_data is not None
            and hashlib.sha256(snapshot_data).hexdigest() == expected_hash
        )

        origin: Path | None = None
        if module_name == "grabowski_mcp":
            try:
                origin = Path(__file__).resolve(strict=True)
            except (OSError, RuntimeError):
                origin = None
        else:
            try:
                spec = importlib.util.find_spec(module_name)
                if spec is not None and isinstance(spec.origin, str):
                    origin = Path(spec.origin).resolve(strict=True)
            except (ImportError, OSError, RuntimeError, ValueError):
                origin = None
        if origin is not None:
            module_origins[module_name] = origin
        recorded_module = (
            module_paths.get(module_name) if isinstance(module_paths, dict) else None
        )
        module_data = (
            _read_bound_regular_file(
                recorded_module,
                origin,
                release_root,
                max_bytes=MAX_SNAPSHOT_BYTES,
            )
            if origin is not None
            else None
        )
        module_identity_by_module[module_name] = (
            module_data is not None
            and hashlib.sha256(module_data).hexdigest() == expected_hash
        )

    runtime_asset_hashes = raw.get("runtime_asset_sha256s")
    runtime_asset_paths = raw.get("runtime_asset_paths")
    runtime_asset_snapshot_paths = snapshot_paths.get("runtime_assets")
    runtime_asset_snapshot_identity_by_destination: dict[str, bool] = {}
    runtime_asset_identity_by_destination: dict[str, bool] = {}
    for asset_source, destination in contract_assets:
        expected_hash = (
            runtime_asset_hashes.get(destination)
            if isinstance(runtime_asset_hashes, dict)
            else None
        )
        snapshot_data = _read_bound_regular_file(
            runtime_asset_snapshot_paths.get(destination)
            if isinstance(runtime_asset_snapshot_paths, dict)
            else None,
            release_root / "inputs" / asset_source,
            release_root,
            max_bytes=MAX_SNAPSHOT_BYTES,
        )
        runtime_asset_snapshot_identity_by_destination[destination] = (
            snapshot_data is not None
            and hashlib.sha256(snapshot_data).hexdigest() == expected_hash
        )
        installed_data = _read_bound_regular_file(
            runtime_asset_paths.get(destination)
            if isinstance(runtime_asset_paths, dict)
            else None,
            release_root / destination,
            release_root,
            max_bytes=MAX_SNAPSHOT_BYTES,
        )
        runtime_asset_identity_by_destination[destination] = (
            installed_data is not None
            and hashlib.sha256(installed_data).hexdigest() == expected_hash
        )

    runtime_asset_snapshot_identity_valid = (
        len(runtime_asset_snapshot_identity_by_destination) == len(contract_assets)
        and all(runtime_asset_snapshot_identity_by_destination.values())
    )
    runtime_asset_identity_valid = (
        len(runtime_asset_identity_by_destination) == len(contract_assets)
        and all(runtime_asset_identity_by_destination.values())
    )
    source_snapshot_identity_valid = (
        bool(contract_sources)
        and len(snapshot_identity_by_module) == len(contract_sources)
        and all(snapshot_identity_by_module.values())
    )
    source_identity_valid = (
        bool(contract_sources)
        and len(module_identity_by_module) == len(contract_sources)
        and all(module_identity_by_module.values())
    )
    entrypoint_module = contract_sources[0][0] if contract_sources else None
    entrypoint_origin = (
        module_origins.get(entrypoint_module) if entrypoint_module is not None else None
    )
    entrypoint_path_valid = (
        entrypoint_origin is not None
        and raw.get("entrypoint_path") == str(entrypoint_origin)
        and isinstance(module_paths, dict)
        and module_paths.get(entrypoint_module) == str(entrypoint_origin)
        and module_identity_by_module.get(entrypoint_module, False)
    )

    release_python_identity_valid = False
    executable_identity_valid = False
    try:
        release_python = Path(str(raw.get("release_python_path")))
        expected_python = release_root / ".venv/bin/python"
        current_python = Path(sys.executable)
        release_python_identity_valid = (
            release_python == expected_python
            and release_python.exists()
            and release_python.resolve(strict=True)
            == current_python.resolve(strict=True)
        )
        executable_identity_valid = (
            isinstance(raw.get("executable"), str)
            and Path(raw["executable"]) == release_python
            and Path(raw["executable"]).resolve(strict=True)
            == current_python.resolve(strict=True)
        )
    except (OSError, RuntimeError, ValueError):
        pass

    try:
        pip_identity_valid = (
            raw.get("pip_version") == f"pip {importlib.metadata.version('pip')}"
        )
    except importlib.metadata.PackageNotFoundError:
        pip_identity_valid = False
    protocol_identity_valid = (
        raw.get("mcp_protocol_version") in DEPLOYMENT_PROTOCOL_VERSIONS
    )
    python_runtime_identity_valid = (
        raw.get("python_version") == platform.python_version()
        and raw.get("python_implementation") == platform.python_implementation()
    )
    platform_identity_valid = raw.get("platform") == platform.platform()

    artifact_integrity_valid = all(
        (
            schema_valid,
            repo_head_valid,
            runtime_input_identity_valid,
            lock_identity_valid,
            source_snapshot_identity_valid,
            runtime_asset_snapshot_identity_valid,
            embedded_contract_valid,
            entrypoint_contract_identity_valid,
            agent_instructions_identity_valid,
            protocol_identity_valid,
        )
    )
    runtime_binding_valid = all(
        (
            release_path_valid,
            release_id_valid,
            stable_runtime_manifest_valid,
            runtime_pointer_valid,
            source_identity_valid,
            runtime_asset_identity_valid,
            entrypoint_path_valid,
            release_python_identity_valid,
            executable_identity_valid,
            pip_identity_valid,
        )
    )
    environment_compatibility_valid = all(
        (
            python_runtime_identity_valid,
            platform_identity_valid,
        )
    )
    provenance_valid = all(
        (
            artifact_integrity_valid,
            runtime_binding_valid,
            environment_compatibility_valid,
        )
    )

    allowed = {
        key: raw.get(key)
        for key in (
            "schema_version",
            "release_id",
            "repo_head",
            "entrypoint_contract_sha256",
            "agent_instructions",
            "source_sha256",
            "source_sha256s",
            "runtime_asset_sha256s",
            "runtime_input_sha256",
            "runtime_lock_sha256",
            "mcp_protocol_version",
            "python_version",
            "python_implementation",
            "platform",
            "executable",
            "pip_version",
            "created_at_unix",
            "completion_status",
        )
    }
    return {
        **base,
        "manifest_parse_valid": True,
        "manifest_schema_valid": schema_valid,
        "release_path_valid": release_path_valid,
        "release_id_valid": release_id_valid,
        "repo_head_valid": repo_head_valid,
        "stable_runtime_manifest_valid": stable_runtime_manifest_valid,
        "runtime_pointer_valid": runtime_pointer_valid,
        "runtime_input_identity_valid": runtime_input_identity_valid,
        "lock_identity_valid": lock_identity_valid,
        "source_snapshot_identity_valid": source_snapshot_identity_valid,
        "source_snapshot_identity_by_module": snapshot_identity_by_module,
        "runtime_asset_snapshot_identity_valid": runtime_asset_snapshot_identity_valid,
        "runtime_asset_snapshot_identity_by_destination": (
            runtime_asset_snapshot_identity_by_destination
        ),
        "source_identity_valid": source_identity_valid,
        "source_identity_by_module": module_identity_by_module,
        "runtime_asset_identity_valid": runtime_asset_identity_valid,
        "runtime_asset_identity_by_destination": runtime_asset_identity_by_destination,
        "embedded_contract_valid": embedded_contract_valid,
        "entrypoint_contract_identity_valid": entrypoint_contract_identity_valid,
        "agent_instructions_identity_valid": agent_instructions_identity_valid,
        "entrypoint_path_valid": entrypoint_path_valid,
        "release_python_identity_valid": release_python_identity_valid,
        "executable_identity_valid": executable_identity_valid,
        "pip_identity_valid": pip_identity_valid,
        "protocol_identity_valid": protocol_identity_valid,
        "python_runtime_identity_valid": python_runtime_identity_valid,
        "platform_identity_valid": platform_identity_valid,
        "artifact_integrity_valid": artifact_integrity_valid,
        "runtime_binding_valid": runtime_binding_valid,
        "environment_compatibility_valid": environment_compatibility_valid,
        "provenance_valid": provenance_valid,
        **allowed,
    }


def _runtime_tool_contract_summary(
    deployment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expected: list[str] = []
    manifest_error: str | None = None
    try:
        payload = json.loads(
            _ensure_regular_text_file(DEPLOYMENT_MANIFEST, 2_000_000).decode("utf-8")
        )
        contract = payload.get("entrypoint_contract", {})
        raw_expected = contract.get("expected_tools", [])
        if not isinstance(raw_expected, list) or not all(
            isinstance(item, str) for item in raw_expected
        ):
            raise ValueError("deployment manifest expected_tools is not a string list")
        expected = sorted(set(raw_expected))
    except Exception as exc:
        manifest_error = f"{type(exc).__name__}: {exc}"

    manager = getattr(mcp, "_tool_manager", None)
    raw_registered = getattr(manager, "_tools", {})
    registered = (
        sorted(str(name) for name in raw_registered)
        if isinstance(raw_registered, dict)
        else []
    )

    def names_sha256(names: list[str]) -> str:
        return hashlib.sha256(
            json.dumps(
                names,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    expected_set = set(expected)
    registered_set = set(registered)
    expected_names_sha256 = names_sha256(expected)
    registered_names_sha256 = names_sha256(registered)
    runtime_matches = manifest_error is None and expected_set == registered_set
    deployment = _deployment_metadata() if deployment is None else deployment
    release_id = deployment.get("release_id")
    repo_head = deployment.get("repo_head")
    if (
        runtime_matches
        and isinstance(release_id, str)
        and release_id
        and isinstance(repo_head, str)
        and re.fullmatch(r"[0-9a-f]{40}", repo_head) is not None
    ):
        client_snapshot = grabowski_client_snapshot.snapshot_status(
            expected_tool_count=len(registered),
            expected_names_sha256=registered_names_sha256,
            expected_release_id=release_id,
            expected_repo_head=repo_head,
            expected_agent_instructions_sha256=AGENT_INSTRUCTIONS_SHA256,
        )
    else:
        client_snapshot = {
            "state": "server_contract_invalid",
            "observable": False,
            "fresh": False,
            "matched": False,
            "recommended_next_action": (
                "repair the server tool or deployment contract before binding a client snapshot"
            ),
            "does_not_establish": [
                "platform-enforced client snapshot identity",
                "client instruction compliance",
                "resistance to compromised same-uid code",
            ],
        }
    return {
        "expected_tool_count": len(expected),
        "registered_tool_count": len(registered),
        "name_hash_contract": "sha256-json-sorted-utf8-v1",
        "expected_names_sha256": expected_names_sha256,
        "registered_names_sha256": registered_names_sha256,
        "runtime_matches_deployment_contract": runtime_matches,
        "missing_from_runtime": sorted(expected_set - registered_set)[:50],
        "unexpected_in_runtime": sorted(registered_set - expected_set)[:50],
        "manifest_error": manifest_error,
        "client_snapshot": client_snapshot,
        "client_snapshot_observable": bool(client_snapshot.get("observable")),
        "client_snapshot_verification_model": client_snapshot.get("verification_model"),
        "refresh_required_when_client_count_or_hash_differs": True,
    }


def _operator_relay_protocol() -> dict[str, Any]:
    return {
        "name": "Operator Relay v0",
        "doc_path": "docs/blocked-action-protocol-v0.md",
        "rule": "ChatGPT stays operator and handles bounded work first. Delegate only when a helper adds useful scale or independent contrast.",
        "control_loop": [
            "typed_grabowski_tool",
            "grabowski_micro_task",
            "receipt_before_next_step",
        ],
        "execution_priority": [
            "chatgpt_operator",
            "claude",
            "codex",
            "agy",
            "cline",
        ],
        "coding_agent_priority": [
            "claude",
            "codex",
            "agy",
            "cline",
        ],
        "workspace_execution_model": {
            "default": "adaptive_operator_routing",
            "lane_owner": "chatgpt_operator",
            "operator_self_serves_lanes": ["captain", "writer", "tests", "review"],
            "role_evidence_isolated": True,
            "workspace_not_universal": True,
            "direct_operator_for": [
                "small_low_risk_fix",
                "simple_document_change",
                "bounded_deterministic_edit",
            ],
            "full_workspace_for": [
                "runtime_or_security_change",
                "long_or_multi_file_implementation",
                "parallel_or_foreign_state",
                "connector_or_execution_state_uncertainty",
            ],
            "external_agent_delegation": "adaptive_opt_in",
            "delegation_triggers": [
                "high_novelty_design_space",
                "independent_contrast",
                "multiple_plausible_implementations",
                "security_schema_or_concurrency_risk",
                "capacity_fallback",
            ],
            "external_programming_modes": ["competitor", "contrast"],
            "max_external_candidates": 2,
            "external_candidate_authority": "advisory_only",
            "automatic_patch_apply": False,
            "automatic_winner_selection": False,
        },
        "operator_first_for": [
            "task_decomposition",
            "bounded_code_change",
            "integration",
            "critical_self_review",
            "recovery",
        ],
        "routing_roles": {
            "complex_code_task": "chatgpt_operator_adaptive_workspace_external_competition_when_high_value",
            "quick_light_reasoning": "chatgpt_operator_external_opt_in_agy_print",
            "local_micro_reasoning": "ollama_api_qwen_coder",
            "shell_or_git_grip": "grabowski_task",
            "security_or_architecture_review": "chatgpt_operator_external_opt_in_claude",
            "session_resume": "tmux_first_agy_when_useful",
            "memory_prioritization": "bureau",
            "patch_file_relay": "operator_patch_relay",
            "patch_fallback": "aider_no_auto_commit",
            "audit": "grabowski_git",
            "repo_state_context": "steuerboard_operator_report",
        },
        "does_not_establish": [
            "new_privileges",
            "automatic_merge",
            "automatic_push",
            "automatic_deploy",
            "free_shell_as_default_path",
            "durable_agent_autonomy",
            "steuerboard_report_action_approval",
        ],
    }


STATUS_VIEWS = consumer_surface.CONSUMER_VIEWS
STATUS_VIEW_ALIASES = consumer_surface.CONSUMER_VIEW_ALIASES


def _normalize_status_view(value: str) -> str:
    return consumer_surface.normalize_view(value)


def _project_status_fields(
    payload: dict[str, Any],
    fields: list[str] | None,
) -> dict[str, Any]:
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=(
            "schema_version",
            "view",
            "healthy",
            "warnings",
            "recommended_next_action",
            "does_not_establish",
        ),
    )


def _coding_agent_catalog_health() -> dict[str, Any]:
    try:
        import grabowski_coding_agent_router

        return grabowski_coding_agent_router.coding_agent_catalog_health()
    except Exception as exc:  # pragma: no cover - defensive status boundary
        return {
            "ready": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:512],
        }


def _operator_system_overview(
    *,
    runtime_healthy: bool,
    client_snapshot: dict[str, Any],
    coding_agent_catalog: dict[str, Any],
) -> dict[str, Any]:
    tasks: dict[str, Any] = {
        "available": False,
        "projection_counts": {},
        "unknown_state_count": None,
    }
    leases: dict[str, Any] = {"available": False, "active_count": None}
    obligations: dict[str, Any] = {
        "available": False,
        "attention_count": None,
        "integrity_error_count": None,
    }
    errors: list[dict[str, str]] = []
    try:
        import grabowski_tasks

        task_payload = grabowski_tasks.grabowski_task_list(
            limit=1,
            view="minimal",
        )
        tasks = {
            "available": True,
            "state_counts": task_payload.get("state_counts", {}),
            "projection_counts": task_payload.get("projection_counts", {}),
            "projection_counts_overlap": task_payload.get("projection_counts_overlap"),
            "unknown_state_count": task_payload.get("unknown_state_count"),
            "snapshot_complete": task_payload.get("state_counts_complete"),
        }
    except Exception as exc:  # pragma: no cover - defensive status boundary
        errors.append({"component": "tasks", "error": type(exc).__name__})
    try:
        import grabowski_resources

        active_count = grabowski_resources.count_resources(
            include_expired=False,
        )
        leases = {
            "available": True,
            "active_count": active_count,
            "count_complete": True,
            "may_be_truncated": False,
        }
    except Exception as exc:  # pragma: no cover - defensive status boundary
        errors.append({"component": "leases", "error": type(exc).__name__})
    try:
        import grabowski_operator_obligation

        obligation_limit = 100
        obligation_payload = grabowski_operator_obligation.list_obligations(
            {
                "state": "attention",
                "limit": obligation_limit,
                "summary_only": True,
            }
        )
        obligations = {
            "available": True,
            "attention_count": obligation_payload.get("record_count"),
            "integrity_error_count": len(
                obligation_payload.get("integrity_errors", [])
            ),
            "scan_truncated": obligation_payload.get("scan_truncated"),
            "bounded_limit": obligation_limit,
        }
    except Exception as exc:  # pragma: no cover - defensive status boundary
        errors.append(
            {"component": "operator_obligations", "error": type(exc).__name__}
        )

    snapshot_observable = bool(client_snapshot.get("observable"))
    coding_agent_catalog_ready = coding_agent_catalog.get("ready") is True
    unknown_state_count = tasks.get("unknown_state_count")
    truth_model_ready = tasks.get("available") is True and unknown_state_count == 0
    components_observable = (
        not errors
        and leases.get("available") is True
        and not leases.get("may_be_truncated")
        and obligations.get("available") is True
        and not obligations.get("scan_truncated")
    )
    operator_ready = (
        runtime_healthy
        and coding_agent_catalog_ready
        and snapshot_observable
        and truth_model_ready
        and components_observable
    )
    if not runtime_healthy:
        next_action = "repair runtime integrity before operator mutation"
    elif not coding_agent_catalog_ready:
        next_action = "repair coding-agent catalog semantics before routed execution"
    elif not snapshot_observable:
        next_action = str(
            client_snapshot.get(
                "recommended_next_action",
                "bind the current connector client snapshot",
            )
        )
    elif not tasks.get("available"):
        next_action = "restore task projection observability"
    elif errors:
        next_action = "restore observability for the unavailable overview components"
    elif leases.get("may_be_truncated") or obligations.get("scan_truncated"):
        next_action = "narrow or extend bounded component projections before relying on the overview"
    elif unknown_state_count:
        next_action = "resolve unknown task states before relying on projections"
    elif obligations.get("integrity_error_count"):
        next_action = "inspect operator obligation integrity errors"
    elif obligations.get("attention_count"):
        next_action = "resume or close the highest-priority operator obligation"
    elif (tasks.get("projection_counts") or {}).get("attention", 0):
        next_action = "inspect the highest-priority attention task"
    else:
        next_action = "none"
    source_registry = {
        "grabowski_runtime": {
            "authority": "deployment manifest and audit log",
            "observation_state": "observed",
            "freshness": "current status call",
        },
        "task_store": {
            "authority": "Grabowski task database",
            "observation_state": (
                "observed" if tasks.get("available") else "unavailable"
            ),
            "freshness": "single bounded read snapshot",
        },
        "resource_leases": {
            "authority": "Grabowski resource lease database",
            "observation_state": (
                "observed" if leases.get("available") else "unavailable"
            ),
            "freshness": "current bounded query",
        },
        "operator_obligations": {
            "authority": "operator obligation store",
            "observation_state": (
                "observed" if obligations.get("available") else "unavailable"
            ),
            "freshness": "current bounded scan",
        },
        "bureau": {
            "authority": "Bureau",
            "observation_state": "target_required",
            "required_binding": ["bureau task or obligation id"],
            "freshness": "not inferred by global status",
        },
        "github_ci": {
            "authority": "GitHub pull request and checks",
            "observation_state": "target_required",
            "required_binding": ["repository", "pull request"],
            "freshness": "must be read live for the selected target",
        },
        "repobrief": {
            "authority": "RepoGround bundle receipts",
            "observation_state": "target_required",
            "required_binding": ["repository", "bundle stem"],
            "freshness": "must be verified against the selected source commit",
        },
        "systemkatalog": {
            "authority": "Systemkatalog",
            "observation_state": "target_required",
            "required_binding": ["system identity"],
            "freshness": "not inferred by global status",
        },
        "chronik": {
            "authority": "Chronik operation receipts",
            "observation_state": "target_required",
            "required_binding": ["operation or receipt identity"],
            "freshness": "receipt-bound per operation",
        },
    }
    return {
        "schema_version": 1,
        "operator_ready": operator_ready,
        "readiness": {
            "runtime_ready": runtime_healthy,
            "coding_agent_catalog_ready": coding_agent_catalog_ready,
            "connector_snapshot_ready": snapshot_observable,
            "truth_model_ready": truth_model_ready,
            "components_observable": components_observable,
        },
        "runtime": {"healthy": runtime_healthy},
        "coding_agent_catalog": coding_agent_catalog,
        "connector": {
            "state": client_snapshot.get("state"),
            "observable": snapshot_observable,
            "fresh": client_snapshot.get("fresh"),
            "matched": client_snapshot.get("matched"),
            "verification_model": client_snapshot.get("verification_model"),
        },
        "tasks": tasks,
        "leases": leases,
        "operator_obligations": obligations,
        "source_registry": source_registry,
        "component_errors": errors,
        "recommended_next_action": next_action,
        "does_not_establish": [
            "platform-enforced client snapshot identity",
            "task output correctness",
            "that attention work is safe to retry unchanged",
            "future mutation authority",
        ],
    }


@mcp.tool(name="grabowski_status", annotations=READ_ANNOTATIONS)
def grabowski_status(
    view: str = "minimal",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Return a consumer-shaped Grabowski status with opt-in evidence detail."""
    selected_view = _normalize_status_view(view)
    policy = _load_policy()
    active_profile = _active_profile(policy)
    deployment = _deployment_metadata()
    tool_contract = _runtime_tool_contract_summary(deployment)
    coding_agent_catalog = _coding_agent_catalog_health()
    audit = _verify_audit_log(AUDIT_LOG)
    audit_writable = bool(audit.get("audit_writable", audit.get("valid")))
    kill_switch = _kill_switch_state()
    integrity_fields = (
        "manifest_parse_valid",
        "manifest_schema_valid",
        "repo_head_valid",
        "agent_instructions_identity_valid",
        "runtime_binding_valid",
        "environment_compatibility_valid",
        "provenance_valid",
        "artifact_integrity_valid",
    )
    integrity = {key: bool(deployment.get(key)) for key in integrity_fields}
    warnings: list[dict[str, Any]] = []
    if deployment.get("completion_status") != "complete" or not all(integrity.values()):
        warnings.append(
            {
                "code": "deployment_integrity_incomplete",
                "failed_checks": sorted(
                    key for key, value in integrity.items() if not value
                ),
            }
        )
    if not bool(audit.get("valid")):
        warnings.append({"code": "audit_invalid", "error": audit.get("error")})
    elif not audit_writable:
        warnings.append(
            {
                "code": "audit_not_writable",
                "state": audit.get("audit_state"),
                "remaining_bytes": audit.get("remaining_bytes"),
            }
        )
    if bool(audit.get("rotation_required")):
        warnings.append(
            {
                "code": "audit_rotation_required",
                "active_bytes": audit.get("active_bytes"),
                "rotation_threshold_bytes": audit.get("rotation_threshold_bytes"),
            }
        )
    if bool(kill_switch.get("engaged")):
        warnings.append({"code": "kill_switch_engaged"})
    if not bool(tool_contract.get("runtime_matches_deployment_contract")):
        warnings.append({"code": "runtime_tool_contract_drift"})
    if coding_agent_catalog.get("ready") is not True:
        warnings.append(
            {
                "code": "coding_agent_catalog_invalid",
                "error_type": coding_agent_catalog.get("error_type"),
                "detail": coding_agent_catalog.get("error"),
            }
        )
    if not bool(deployment.get("agent_instructions_identity_valid")):
        warnings.append({"code": "agent_instructions_drift"})
    client_snapshot = tool_contract.get("client_snapshot", {})
    if not bool(tool_contract.get("client_snapshot_observable")):
        snapshot_state = str(client_snapshot.get("state", "unavailable"))
        warnings.append(
            {
                "code": f"client_snapshot_{snapshot_state}",
                "verification_model": client_snapshot.get("verification_model"),
                "detail": client_snapshot.get(
                    "recommended_next_action",
                    "bind the connector client snapshot to the current server contract",
                ),
            }
        )
    healthy = (
        deployment.get("completion_status") == "complete"
        and all(integrity.values())
        and bool(audit.get("valid"))
        and audit_writable
        and not bool(kill_switch.get("engaged"))
        and bool(tool_contract.get("runtime_matches_deployment_contract"))
    )
    system_overview: dict[str, Any] | None = None
    if selected_view in {"standard", "evidence"}:
        system_overview = _operator_system_overview(
            runtime_healthy=healthy,
            client_snapshot=client_snapshot,
            coding_agent_catalog=coding_agent_catalog,
        )
    if bool(audit.get("valid")) and not audit_writable:
        recommended_next_action = "restore audit writability before operator mutation"
    elif not healthy:
        recommended_next_action = "repair runtime integrity before operator mutation"
    elif coding_agent_catalog.get("ready") is not True:
        recommended_next_action = (
            "repair coding-agent catalog semantics before routed execution"
        )
    elif not bool(client_snapshot.get("observable")):
        recommended_next_action = str(
            client_snapshot.get(
                "recommended_next_action",
                "bind the current connector client snapshot",
            )
        )
    elif system_overview is not None:
        recommended_next_action = str(system_overview["recommended_next_action"])
    elif warnings:
        recommended_next_action = "inspect warnings before mutation"
    else:
        recommended_next_action = "none"
    base_payload: dict[str, Any] = {
        "schema_version": 2,
        "view": selected_view,
        "service": "grabowski-mcp",
        "healthy": healthy,
        "mode": policy.get("mode", "bounded-read-write"),
        "active_profile": active_profile["name"],
        "access_profiles": sorted(policy.get("profiles", {})),
        "runtime": {
            "release_id": deployment.get("release_id"),
            "repo_head": deployment.get("repo_head"),
            "completion_status": deployment.get("completion_status"),
            "integrity": integrity,
        },
        "tool_contract": {
            "expected_tool_count": tool_contract.get("expected_tool_count"),
            "registered_tool_count": tool_contract.get("registered_tool_count"),
            "name_hash_contract": tool_contract.get("name_hash_contract"),
            "expected_names_sha256": tool_contract.get("expected_names_sha256"),
            "registered_names_sha256": tool_contract.get("registered_names_sha256"),
            "runtime_matches_deployment_contract": tool_contract.get(
                "runtime_matches_deployment_contract"
            ),
            "client_snapshot_observable": tool_contract.get(
                "client_snapshot_observable"
            ),
            "client_snapshot": client_snapshot,
            "refresh_required_when_client_count_or_hash_differs": tool_contract.get(
                "refresh_required_when_client_count_or_hash_differs"
            ),
        },
        "coding_agent_catalog": coding_agent_catalog,
        "agent_instructions": {
            **_agent_instructions_metadata(),
            "runtime_matches_deployment_manifest": deployment.get(
                "agent_instructions_identity_valid"
            ),
            "client_compliance_observable": False,
        },
        "warnings": warnings,
        "recommended_next_action": recommended_next_action,
        "evidence_refs": {
            "release_id": deployment.get("release_id"),
            "repo_head": deployment.get("repo_head"),
            "audit_last_record_sha256": audit.get("last_record_sha256"),
            "agent_instructions_sha256": AGENT_INSTRUCTIONS_SHA256,
        },
        "does_not_establish": [
            "platform-enforced client snapshot identity",
            "client_instruction_compliance",
            "resistance to compromised same-uid code",
            "individual_tool_behavior_correctness",
            "future_action_authority",
        ],
    }
    if selected_view in {"standard", "evidence"}:
        assert system_overview is not None
        operating_protocol = _operator_relay_protocol()
        workspace_model = operating_protocol.get("workspace_execution_model", {})
        base_payload.update(
            {
                "system_overview": system_overview,
                "capabilities": sorted(_effective_capabilities(policy)),
                "roots": {
                    "read": _profile_values(policy, "read_roots"),
                    "write": _profile_values(policy, "write_roots"),
                    "write_excluded": _profile_values(policy, "write_excluded_roots")
                    or [],
                },
                "kill_switch": kill_switch,
                "audit": {
                    "valid": audit.get("valid"),
                    "writable": audit_writable,
                    "state": audit.get("audit_state"),
                    "records": audit.get("records"),
                    "total_records": audit.get("total_records"),
                    "archived_segment_count": audit.get("archived_segment_count"),
                    "active_bytes": audit.get("active_bytes"),
                    "max_bytes": audit.get("max_bytes"),
                    "remaining_bytes": audit.get("remaining_bytes"),
                    "reserve_bytes": audit.get("reserve_bytes"),
                    "rotation_required": audit.get("rotation_required"),
                    "last_record_sha256": audit.get("last_record_sha256"),
                    "error": audit.get("error"),
                },
                "operating_protocol": {
                    "name": operating_protocol.get("name"),
                    "control_loop": operating_protocol.get("control_loop", []),
                    "external_agent_delegation": workspace_model.get(
                        "external_agent_delegation"
                    ),
                    "automatic_patch_apply": workspace_model.get(
                        "automatic_patch_apply"
                    ),
                    "automatic_winner_selection": workspace_model.get(
                        "automatic_winner_selection"
                    ),
                    "does_not_establish": operating_protocol.get(
                        "does_not_establish", []
                    ),
                },
            }
        )
    if selected_view == "evidence":
        base_payload.update(
            {
                "operating_protocol": _operator_relay_protocol(),
                "trusted_owner": _trusted_owner_enabled(policy),
                "state_dir": str(STATE_DIR),
                "policy_path": str(POLICY_PATH),
                "read_roots": _profile_values(policy, "read_roots"),
                "write_roots": _profile_values(policy, "write_roots"),
                "write_excluded_roots": _profile_values(policy, "write_excluded_roots")
                or [],
                "secret_roots": _secret_root_values(policy),
                "browser_profile_roots": _browser_profile_root_values(policy),
                "secret_export_roots": _secret_export_root_values(policy),
                "latest_complete_bundles_path": str(BUNDLE_REGISTRY),
                "latest_complete_bundles_exists": BUNDLE_REGISTRY.is_file(),
                "deployment": deployment,
                "tool_contract_evidence": tool_contract,
                "capability_requirements": _capability_requirement_summary(policy),
                "forbidden_capabilities": policy.get("forbidden_capabilities", []),
            }
        )
    return _project_status_fields(base_payload, fields)


@mcp.tool(name="grabowski_list_directory", annotations=READ_ANNOTATIONS)
def grabowski_list_directory(path: str, max_entries: int = 200) -> dict[str, Any]:
    """List one allowed directory without recursion or symlink traversal."""
    _require_capability("file_read")
    directory = _resolve_existing(path, "read")
    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    policy = _load_policy()
    hard_limit = _policy_limit(policy, "max_list_entries")
    limit = min(max(1, int(max_entries)), hard_limit)
    entries: list[dict[str, Any]] = []

    for child in sorted(directory.iterdir(), key=lambda p: p.name):
        if len(entries) >= limit:
            break
        try:
            _reject_sensitive(child)
        except PermissionError:
            continue

        kind, size = _nofollow_kind_and_size(child)
        if kind != "symlink-blocked":
            if _path_is_secret(child.resolve(strict=False)):
                kind = "secret-root"
                size = None
            elif _path_is_browser_profile(child.resolve(strict=False)):
                kind = "browser-profile-root"
                size = None

        entries.append({"name": child.name, "type": kind, "size": size})

    return {
        "path": str(directory),
        "entries": entries,
        "returned": len(entries),
        "limit": limit,
    }


@mcp.tool(name="grabowski_stat", annotations=READ_ANNOTATIONS)
def grabowski_stat(path: str) -> dict[str, Any]:
    """Return metadata and SHA-256 for one allowed regular file."""
    _require_capability("file_read")
    target = _resolve_existing(path, "read")
    st = _nofollow_metadata(target)
    kind = (
        "directory"
        if statmod.S_ISDIR(st.st_mode)
        else "file"
        if statmod.S_ISREG(st.st_mode)
        else "other"
    )
    result: dict[str, Any] = {
        "path": str(target),
        "type": kind,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "mode": oct(statmod.S_IMODE(st.st_mode)),
    }
    if kind == "file":
        result["sha256"] = _sha256(target)
    return result


@mcp.tool(name="grabowski_read_text", annotations=READ_ANNOTATIONS)
def grabowski_read_text(
    path: str, start_line: int = 1, max_lines: int = 400
) -> dict[str, Any]:
    """Read UTF-8 text from an allowed file and return a concurrency hash."""
    _require_capability("file_read")
    target = _resolve_existing(path, "read")
    policy = _load_policy()
    data = _ensure_regular_text_file(
        target,
        _policy_limit(policy, "max_read_bytes"),
    )
    text = data.decode("utf-8")
    lines = text.splitlines()

    start = max(1, int(start_line))
    count = min(max(1, int(max_lines)), 2000)
    selected = lines[start - 1 : start - 1 + count]

    return {
        "path": str(target),
        "sha256": hashlib.sha256(data).hexdigest(),
        "start_line": start,
        "end_line": start + len(selected) - 1 if selected else start - 1,
        "total_lines": len(lines),
        "text": "\n".join(selected),
    }


@mcp.tool(name="grabowski_secret_inspect", annotations=READ_ANNOTATIONS)
def grabowski_secret_inspect(path: str, max_entries: int = 100) -> dict[str, Any]:
    """Inspect one configured secret path without returning file content."""
    _require_capability("secret_inspect")
    target = _resolve_secret_existing(path)
    st = _nofollow_metadata(target)
    kind = (
        "directory"
        if statmod.S_ISDIR(st.st_mode)
        else "file"
        if statmod.S_ISREG(st.st_mode)
        else "other"
    )
    result: dict[str, Any] = {
        "path": str(target),
        "type": kind,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
        "mode": oct(statmod.S_IMODE(st.st_mode)),
        "content_returned": False,
    }
    if kind == "file":
        policy = _load_policy()
        snapshot = _read_bound_regular_bytes(
            target,
            _policy_limit(policy, "max_read_bytes"),
        )
        result.update(
            {
                "sha256": snapshot["sha256"],
                "race_checked": True,
            }
        )
        return result

    if kind != "directory":
        return result

    policy = _load_policy()
    hard_limit = _policy_limit(policy, "max_list_entries")
    limit = min(max(1, int(max_entries)), hard_limit)
    entries: list[dict[str, Any]] = []
    for child in sorted(target.iterdir(), key=lambda p: p.name):
        if len(entries) >= limit:
            break
        child_kind, size = _nofollow_kind_and_size(child)
        entries.append(
            {
                "name": child.name,
                "type": child_kind,
                "size": size,
            }
        )

    result.update(
        {
            "entries": entries,
            "returned": len(entries),
            "limit": limit,
        }
    )
    return result


@mcp.tool(name="grabowski_secret_reveal", annotations=SECRET_REVEAL_ANNOTATIONS)
def grabowski_secret_reveal(
    path: str,
    expected_sha256: str,
    max_bytes: int | None = None,
    justification: str = "",
    acknowledge_context_exposure: bool = False,
) -> dict[str, Any]:
    """Break-glass reveal after hash, justification and exposure acknowledgement."""
    _require_capability("secret_reveal")
    _require_valid_audit_chain()
    _validate_sha256(expected_sha256, "expected_sha256")
    target = _resolve_secret_existing(path)
    snapshot = _secret_text_snapshot(
        target,
        expected_sha256=expected_sha256,
        max_bytes=max_bytes,
    )
    trusted_owner = _trusted_owner_enabled()
    if not trusted_owner and not acknowledge_context_exposure:
        raise PermissionError(
            "Secret reveal requires explicit context-exposure acknowledgement"
        )
    if trusted_owner and not justification.strip():
        justification = "trusted-owner implicit reveal"
    if not isinstance(justification, str) or not justification.strip():
        raise ValueError("Secret reveal requires a non-empty justification")
    if len(justification.encode("utf-8")) > 1000 or "\x00" in justification:
        raise ValueError("Secret reveal justification is too large or contains NUL")
    if _redact_sensitive_text(justification)[0] != justification:
        raise ValueError(
            "Secret reveal justification appears to contain secret material"
        )
    justification_sha256 = hashlib.sha256(justification.encode("utf-8")).hexdigest()
    exposure_mode = (
        "trusted-owner-policy" if trusted_owner else "explicit-acknowledgement"
    )
    transaction_id, transaction_dir = _new_transaction_dir("secret-reveal", target)
    active_profile = _active_profile(_load_policy())
    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "secret-reveal",
        "path": str(target),
        "sha256": snapshot["sha256"],
        "size": snapshot["size"],
        "profile": active_profile["name"],
        "capability": "secret_reveal",
        "justification_sha256": justification_sha256,
        "context_exposure_acknowledged": bool(acknowledge_context_exposure),
        "exposure_mode": exposure_mode,
        "postflight": {
            "sha256_precondition_valid": True,
            "race_checked": True,
            "content_returned": True,
        },
    }
    _write_json_evidence(transaction_dir / "reveal.json", evidence)
    _append_audit(
        {
            "timestamp": _utc_timestamp(),
            "operation": "secret-reveal",
            "transaction_id": transaction_id,
            "path": str(target),
            "before_sha256": None,
            "after_sha256": snapshot["sha256"],
            "bytes": snapshot["size"],
            "backup": None,
            "profile": active_profile["name"],
            "capability": "secret_reveal",
            "justification_sha256": justification_sha256,
            "context_exposure_acknowledged": bool(acknowledge_context_exposure),
            "exposure_mode": exposure_mode,
            "postflight": evidence["postflight"],
            "quarantine": {"directory": str(transaction_dir), "preimage_path": None},
            "rollback": {
                "available": False,
                "reason": "secret reveal has no rollback artifact",
                "created_sha256": None,
            },
        }
    )
    return {
        "path": str(target),
        "sha256": snapshot["sha256"],
        "size": snapshot["size"],
        "race_checked": True,
        "content_returned": True,
        "transaction_id": transaction_id,
        "text": snapshot["text"],
        "audit_record_sha256": _verify_audit_log(AUDIT_LOG)["last_record_sha256"],
    }


@mcp.tool(name="grabowski_secret_use", annotations=CREATE_ANNOTATIONS)
def grabowski_secret_use(
    source_path: str,
    expected_source_sha256: str,
    argv: list[str],
    cwd: str | None = None,
    timeout_seconds: int = DEFAULT_SECRET_USE_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_SECRET_USE_OUTPUT_BYTES,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run one argv-only command with a secret exposed only through an fd/path."""
    _require_mutations_enabled("secret_use")
    _validate_sha256(expected_source_sha256, "expected_source_sha256")
    source = _resolve_secret_existing(source_path)
    policy = _load_policy()
    snapshot = _read_bound_regular_bytes(
        source,
        _policy_limit(policy, "max_read_bytes"),
    )
    if snapshot["sha256"] != expected_source_sha256:
        raise RuntimeError(
            "SHA-256 precondition failed: "
            f"expected {expected_source_sha256}, current {snapshot['sha256']}"
        )

    hard_timeout = _policy_limit_or_default(
        policy,
        "max_secret_use_seconds",
        DEFAULT_SECRET_USE_TIMEOUT_SECONDS,
    )
    hard_output = _policy_limit_or_default(
        policy,
        "max_secret_use_output_bytes",
        DEFAULT_SECRET_USE_OUTPUT_BYTES,
    )
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
        or timeout_seconds > hard_timeout
    ):
        raise ValueError(f"timeout_seconds must be between 1 and {hard_timeout}")
    if (
        not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or max_output_bytes < 1
        or max_output_bytes > hard_output
    ):
        raise ValueError(f"max_output_bytes must be between 1 and {hard_output}")

    working_directory = _resolve_secret_use_cwd(cwd)
    command_template = _validate_secret_use_argv(
        argv,
        cwd=working_directory,
        secret_data=snapshot["data"],
    )
    child_environment = _secret_use_environment(environment, snapshot["data"])
    reference = _materialize_secret_reference(snapshot["data"])
    command = [
        item.replace(SECRET_FD_PLACEHOLDER, str(reference["path"]))
        for item in command_template
    ]
    try:
        result = _run_secret_command(
            command,
            cwd=working_directory,
            environment=child_environment,
            pass_fd=reference["fd"],
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            secret_data=snapshot["data"],
        )
    finally:
        _cleanup_secret_reference(reference)

    transaction_id, transaction_dir = _new_transaction_dir("secret-use", source)
    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "secret-use",
        "source_path": str(source),
        "source_sha256": snapshot["sha256"],
        "source_size": snapshot["size"],
        "argv_sha256": _argv_sha256(command_template),
        "cwd": str(working_directory),
        "secret_transport": reference["transport"],
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "stdout_truncated": result["stdout_truncated"],
        "stderr_truncated": result["stderr_truncated"],
        "redaction_count": result["redaction_count"],
    }
    _write_json_evidence(transaction_dir / "use.json", evidence)
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "secret-use",
        "transaction_id": transaction_id,
        "path": str(source),
        "source_path": str(source),
        "before_sha256": None,
        "after_sha256": snapshot["sha256"],
        "bytes": snapshot["size"],
        "backup": None,
        "argv_sha256": _argv_sha256(command_template),
        "cwd": str(working_directory),
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": None,
        },
        "rollback": {
            "available": False,
            "reason": "secret use has no rollback artifact",
            "created_sha256": None,
        },
    }
    _append_audit(record)
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "source_path": str(source),
        "source_sha256": snapshot["sha256"],
        "source_size": snapshot["size"],
        "argv_sha256": _argv_sha256(command_template),
        "cwd": str(working_directory),
        "secret_transport": reference["transport"],
        **result,
        "audit_record_sha256": _verify_audit_log(AUDIT_LOG)["last_record_sha256"],
    }


@mcp.tool(name="grabowski_secret_export", annotations=CREATE_ANNOTATIONS)
def grabowski_secret_export(
    source_path: str,
    destination_path: str,
    expected_source_sha256: str,
) -> dict[str, Any]:
    """Atomically export one secret to a configured local destination root."""
    _require_mutations_enabled("secret_export")
    _validate_sha256(expected_source_sha256, "expected_source_sha256")
    source = _resolve_secret_existing(source_path)
    target = _resolve_secret_export_target(destination_path)
    policy = _load_policy()
    snapshot = _read_bound_regular_bytes(
        source,
        _minimum_policy_limit(policy, "max_read_bytes", "max_write_bytes"),
    )
    if snapshot["sha256"] != expected_source_sha256:
        raise RuntimeError(
            "SHA-256 precondition failed: "
            f"expected {expected_source_sha256}, current {snapshot['sha256']}"
        )

    transaction_id, transaction_dir = _new_transaction_dir(
        "secret-export",
        target,
    )
    created_target = False
    try:
        _atomic_create_bytes(target, snapshot["data"], mode=0o600)
        created_target = True
        written = _read_bound_regular_bytes(
            target,
            _minimum_policy_limit(policy, "max_read_bytes", "max_write_bytes"),
        )
        if written["sha256"] != snapshot["sha256"]:
            raise RuntimeError("Secret export hash mismatch")
        mode = statmod.S_IMODE(os.stat(target, follow_symlinks=False).st_mode)
        if mode != 0o600:
            raise RuntimeError(f"Secret export mode mismatch: {oct(mode)}")
    except Exception:
        if created_target:
            try:
                target.unlink()
                _fsync_directory(target.parent)
            except FileNotFoundError:
                pass
        raise

    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "secret-export",
        "source_path": str(source),
        "destination_path": str(target),
        "source_sha256": snapshot["sha256"],
        "destination_sha256": written["sha256"],
        "bytes": written["size"],
        "mode": oct(mode),
    }
    _write_json_evidence(transaction_dir / "export.json", evidence)
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "secret-export",
        "transaction_id": transaction_id,
        "path": str(target),
        "source_path": str(source),
        "before_sha256": None,
        "after_sha256": written["sha256"],
        "bytes": written["size"],
        "backup": None,
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": None,
        },
        "rollback": {
            "available": False,
            "reason": "secret export is create-only",
            "created_sha256": written["sha256"],
        },
    }
    _append_audit(record)
    return {
        **evidence,
        "audit_record_sha256": _verify_audit_log(AUDIT_LOG)["last_record_sha256"],
    }


@mcp.tool(name="grabowski_browser_profile_read", annotations=READ_ANNOTATIONS)
def grabowski_browser_profile_read(
    path: str,
    start_line: int = 1,
    max_lines: int = 200,
    max_entries: int = 100,
) -> dict[str, Any]:
    """Read bounded metadata/text under configured browser profile roots."""
    _require_capability("browser_profile_read")
    target = _resolve_browser_profile_existing(path)
    st = _nofollow_metadata(target)
    kind = (
        "directory"
        if statmod.S_ISDIR(st.st_mode)
        else "file"
        if statmod.S_ISREG(st.st_mode)
        else "other"
    )
    result: dict[str, Any] = {
        "path": str(target),
        "type": kind,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
        "mode": oct(statmod.S_IMODE(st.st_mode)),
    }
    if kind == "directory":
        policy = _load_policy()
        hard_limit = _policy_limit(policy, "max_list_entries")
        limit = min(max(1, int(max_entries)), hard_limit)
        entries: list[dict[str, Any]] = []
        for child in sorted(target.iterdir(), key=lambda p: p.name):
            if len(entries) >= limit:
                break
            child_kind, size = _nofollow_kind_and_size(child)
            entries.append({"name": child.name, "type": child_kind, "size": size})
        result.update(
            {
                "entries": entries,
                "returned": len(entries),
                "limit": limit,
                "content_returned": False,
            }
        )
        return result
    if kind != "file":
        result["content_returned"] = False
        return result

    policy = _load_policy()
    snapshot = _read_bound_regular_bytes(
        target,
        _policy_limit(policy, "max_read_bytes"),
    )
    result.update({"sha256": snapshot["sha256"], "race_checked": True})
    binary_suffixes = {
        ".db",
        ".sqlite",
        ".sqlite3",
        ".ldb",
        ".log",
        ".pma",
        ".ico",
        ".png",
        ".jpg",
        ".jpeg",
    }
    if target.suffix.lower() in binary_suffixes or b"\x00" in snapshot["data"]:
        result.update(
            {
                "content_returned": False,
                "metadata_only_reason": "binary-browser-profile-file",
            }
        )
        return result
    try:
        text = snapshot["data"].decode("utf-8")
    except UnicodeDecodeError:
        result.update(
            {
                "content_returned": False,
                "metadata_only_reason": "non-utf8-browser-profile-file",
            }
        )
        return result
    lines = text.splitlines()
    start = max(1, int(start_line))
    count = min(max(1, int(max_lines)), 1000)
    selected = lines[start - 1 : start - 1 + count]
    selected_text, redaction_count = _redact_sensitive_text("\n".join(selected))
    result.update(
        {
            "content_returned": True,
            "start_line": start,
            "end_line": start + len(selected) - 1 if selected else start - 1,
            "total_lines": len(lines),
            "text": selected_text,
            "redaction_count": redaction_count,
        }
    )
    return result


@mcp.tool(name="grabowski_create_text", annotations=CREATE_ANNOTATIONS)
def grabowski_create_text(path: str, content: str) -> dict[str, Any]:
    """Use this when a new UTF-8 text file must be created inside an allowed write root. It fails if the path already exists."""
    target, exists = _resolve_write_target(path)
    _require_mutations_enabled("file_write", path=str(target))
    if exists:
        raise FileExistsError(f"Refusing to overwrite existing path: {target}")

    policy = _load_policy()
    encoded = content.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("NUL-containing content is not allowed")
    if len(encoded) > _policy_limit(policy, "max_write_bytes"):
        raise ValueError("Content exceeds configured write limit")

    transaction_id, transaction_dir = _new_transaction_dir("create", target)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, 0o600)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    after_sha = _sha256(target)
    rollback = {
        "available": False,
        "reason": "create rollback would require file_delete capability",
        "created_sha256": after_sha,
    }
    _write_json_evidence(
        transaction_dir / "rollback.json",
        {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "operation": "create",
            "path": str(target),
            "after_sha256": after_sha,
            "rollback": rollback,
        },
    )
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "create",
        "transaction_id": transaction_id,
        "path": str(target),
        "before_sha256": None,
        "after_sha256": after_sha,
        "bytes": len(encoded),
        "backup": None,
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": None,
        },
        "rollback": rollback,
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_replace_text", annotations=REPLACE_ANNOTATIONS)
def grabowski_replace_text(
    path: str, content: str, expected_sha256: str
) -> dict[str, Any]:
    """Use this when an existing allowed UTF-8 text file must be replaced atomically. The exact SHA-256 returned by grabowski_read_text or grabowski_stat is required."""
    target, exists = _resolve_write_target(path)
    _require_mutations_enabled("file_write", path=str(target))
    if not exists:
        raise FileNotFoundError(f"Use grabowski_create_text for new files: {target}")

    policy = _load_policy()
    encoded = content.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("NUL-containing content is not allowed")
    if len(encoded) > _policy_limit(policy, "max_write_bytes"):
        raise ValueError("Content exceeds configured write limit")

    _ensure_regular_text_file(target, _policy_limit(policy, "max_read_bytes"))
    before_sha = _sha256(target)
    if expected_sha256 != before_sha:
        raise RuntimeError(
            f"SHA-256 precondition failed: expected {expected_sha256}, current {before_sha}"
        )

    mode = statmod.S_IMODE(target.stat().st_mode)
    transaction_id, transaction_dir = _new_transaction_dir("replace", target)
    quarantine = transaction_dir / f"before-{before_sha[:12]}.txt"
    shutil.copy2(target, quarantine, follow_symlinks=False)
    os.chmod(quarantine, 0o600)
    if _sha256(quarantine) != before_sha:
        raise RuntimeError("Quarantine preimage hash mismatch")

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, mode)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    after_sha = _sha256(target)
    rollback = {
        "available": True,
        "tool": "grabowski_rollback_text",
        "transaction_id": transaction_id,
        "expected_current_sha256": after_sha,
        "restore_sha256": before_sha,
        "quarantine_path": str(quarantine),
    }
    _write_json_evidence(
        transaction_dir / "rollback.json",
        {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "operation": "replace",
            "path": str(target),
            "before_sha256": before_sha,
            "after_sha256": after_sha,
            "rollback": rollback,
        },
    )
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "replace",
        "transaction_id": transaction_id,
        "path": str(target),
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "bytes": len(encoded),
        "backup": str(quarantine),
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": str(quarantine),
            "preimage_sha256": before_sha,
        },
        "rollback": rollback,
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_remove_path", annotations=REMOVE_ANNOTATIONS)
def grabowski_remove_path(
    path: str,
    expected_type: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Remove one allowed regular file or empty directory into quarantine for audit-backed restoration."""
    target, exists = _resolve_write_target(path)
    _require_mutations_enabled("file_delete", path=str(target))
    if not exists:
        raise FileNotFoundError(f"Removal target is missing: {target}")
    snapshot = _removal_snapshot(target, expected_type, expected_sha256)
    transaction_id, transaction_dir = _new_transaction_dir("remove", target)

    holding: Path | None = None
    try:
        holding = _move_to_holding(target, snapshot)
        quarantine = _quarantine_removed_entry(holding, snapshot, transaction_dir)
        _remove_holding_entry(holding, snapshot)
        holding = None
    except Exception:
        if holding is not None and holding.exists() and not target.exists():
            os.replace(holding, target)
            _fsync_directory(target.parent)
        raise

    rollback = {
        "available": True,
        "tool": "grabowski_restore_removed_path",
        "transaction_id": transaction_id,
        "expected_current_absent": True,
        "restore_sha256": snapshot["sha256"],
        "restore_type": snapshot["type"],
        "quarantine_path": str(quarantine),
    }
    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "remove",
        "path": str(target),
        "path_type": snapshot["type"],
        "before_sha256": snapshot["sha256"],
        "after_sha256": None,
        "bytes": snapshot["bytes"],
        "mode": oct(snapshot["mode"]),
        "rollback": rollback,
    }
    _write_json_evidence(transaction_dir / "remove.json", evidence)
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "remove",
        "transaction_id": transaction_id,
        "path": str(target),
        "path_type": snapshot["type"],
        "before_sha256": snapshot["sha256"],
        "after_sha256": None,
        "bytes": snapshot["bytes"],
        "mode": oct(snapshot["mode"]),
        "backup": str(quarantine),
        "capability": "file_delete",
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": str(quarantine),
            "preimage_sha256": snapshot["sha256"],
            "path_type": snapshot["type"],
            "mode": oct(snapshot["mode"]),
        },
        "rollback": rollback,
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_restore_removed_path", annotations=REMOVE_ANNOTATIONS)
def grabowski_restore_removed_path(transaction_id: str) -> dict[str, Any]:
    """Restore one path from a reversible audited filesystem removal transaction."""
    _require_capability("file_delete")
    source = _find_transaction_record(transaction_id)
    if source.get("operation") != "remove":
        raise ValueError("Only remove transactions can be restored")

    raw_path = source.get("path")
    if not isinstance(raw_path, str):
        raise ValueError("Audit transaction has no target path")
    target, exists = _resolve_write_target(raw_path)
    _require_mutations_enabled("file_delete", path=str(target))
    if exists:
        raise FileExistsError(f"Restore target already exists: {target}")

    path_type = _validate_removal_type(str(source.get("path_type")))
    quarantine_info = source.get("quarantine")
    if not isinstance(quarantine_info, dict):
        raise ValueError("Audit transaction has no quarantine metadata")
    quarantine = _audit_quarantine_path(
        quarantine_info.get("preimage_path"),
        path_type,
    )
    before_sha = source.get("before_sha256")
    if path_type == "file":
        if not isinstance(before_sha, str):
            raise ValueError("Audit transaction has no file preimage hash")
        _validate_sha256(before_sha, "before_sha256")
        if _sha256(quarantine) != before_sha:
            raise RuntimeError("Quarantine preimage hash mismatch")
    elif any(quarantine.iterdir()):
        raise RuntimeError("Quarantine directory preimage is not empty")

    mode_text = quarantine_info.get("mode", source.get("mode"))
    if not isinstance(mode_text, str) or not re.fullmatch(r"0o[0-7]{3,4}", mode_text):
        raise ValueError("Audit transaction has invalid restore mode")
    restore_mode = int(mode_text, 8)

    restore_id, restore_dir = _new_transaction_dir("restore-remove", target)
    if path_type == "file":
        data = quarantine.read_bytes()
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.grabowski-restore.",
            dir=str(target.parent),
        )
        try:
            os.fchmod(fd, restore_mode)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_name, target)
            os.chmod(target, restore_mode)
            _fsync_directory(target.parent)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
        restored_sha = _sha256(target)
        if restored_sha != before_sha:
            raise RuntimeError("Restored file hash mismatch")
        restored_bytes = target.stat().st_size
    else:
        target.mkdir(mode=restore_mode)
        os.chmod(target, restore_mode)
        _fsync_directory(target.parent)
        restored_sha = None
        restored_bytes = 0

    record = {
        "timestamp": _utc_timestamp(),
        "operation": "restore-remove",
        "transaction_id": restore_id,
        "restored_transaction_id": transaction_id,
        "path": str(target),
        "path_type": path_type,
        "before_sha256": None,
        "after_sha256": restored_sha,
        "bytes": restored_bytes,
        "mode": oct(restore_mode),
        "backup": None,
        "capability": "file_delete",
        "quarantine": {
            "directory": str(restore_dir),
            "preimage_path": None,
            "path_type": path_type,
        },
        "rollback": {
            "available": False,
            "reason": "restored removals require a new explicit remove operation",
            "created_sha256": restored_sha,
        },
    }
    _write_json_evidence(
        restore_dir / "restore.json",
        {
            "schema_version": 1,
            "transaction_id": restore_id,
            "operation": "restore-remove",
            "restored_transaction_id": transaction_id,
            "path": str(target),
            "path_type": path_type,
            "after_sha256": restored_sha,
            "bytes": restored_bytes,
        },
    )
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_destroy_path", annotations=REMOVE_ANNOTATIONS)
def grabowski_destroy_path(
    path: str,
    expected_type: str,
    confirmation: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Irreversibly remove one allowed regular file or empty directory with a separate explicit capability."""
    _require_capability("file_destroy")
    if confirmation != "permanently-delete":
        raise ValueError("confirmation must be exactly 'permanently-delete'")
    target, exists = _resolve_write_target(path)
    _require_mutations_enabled("file_destroy", path=str(target))
    if not exists:
        raise FileNotFoundError(f"Destroy target is missing: {target}")
    snapshot = _removal_snapshot(target, expected_type, expected_sha256)
    transaction_id, transaction_dir = _new_transaction_dir("destroy", target)

    holding: Path | None = None
    try:
        holding = _move_to_holding(target, snapshot)
        _remove_holding_entry(holding, snapshot)
        holding = None
    except Exception:
        if holding is not None and holding.exists() and not target.exists():
            os.replace(holding, target)
            _fsync_directory(target.parent)
        raise

    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "destroy",
        "path": str(target),
        "path_type": snapshot["type"],
        "before_sha256": snapshot["sha256"],
        "after_sha256": None,
        "bytes": snapshot["bytes"],
        "mode": oct(snapshot["mode"]),
        "rollback": {
            "available": False,
            "reason": "irreversible removal was explicitly requested",
            "destroyed_sha256": snapshot["sha256"],
        },
    }
    _write_json_evidence(transaction_dir / "destroy.json", evidence)
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "destroy",
        "transaction_id": transaction_id,
        "path": str(target),
        "path_type": snapshot["type"],
        "before_sha256": snapshot["sha256"],
        "after_sha256": None,
        "bytes": snapshot["bytes"],
        "mode": oct(snapshot["mode"]),
        "backup": None,
        "capability": "file_destroy",
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": None,
            "path_type": snapshot["type"],
        },
        "rollback": evidence["rollback"],
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_rollback_text", annotations=REPLACE_ANNOTATIONS)
def grabowski_rollback_text(transaction_id: str) -> dict[str, Any]:
    """Restore the quarantined preimage for one audited replace transaction."""
    _require_capability("rollback_text")
    source = _find_transaction_record(transaction_id)
    if source.get("operation") != "replace":
        raise ValueError("Only replace transactions can be rolled back")

    raw_path = source.get("path")
    if not isinstance(raw_path, str):
        raise ValueError("Audit transaction has no target path")
    target, exists = _resolve_write_target(raw_path)
    _require_mutations_enabled("rollback_text", path=str(target))
    if not exists:
        raise FileNotFoundError(f"Rollback target is missing: {target}")

    before_sha = source.get("before_sha256")
    after_sha = source.get("after_sha256")
    if not isinstance(before_sha, str) or not isinstance(after_sha, str):
        raise ValueError("Audit transaction has invalid hashes")
    current_sha = _sha256(target)
    if current_sha != after_sha:
        raise RuntimeError(
            f"Rollback precondition failed: expected current {after_sha}, "
            f"found {current_sha}"
        )

    quarantine_info = source.get("quarantine")
    quarantine_path: Path | None = None
    if isinstance(quarantine_info, dict) and isinstance(
        quarantine_info.get("preimage_path"),
        str,
    ):
        quarantine_path = Path(quarantine_info["preimage_path"])
    elif isinstance(source.get("backup"), str):
        quarantine_path = Path(str(source["backup"]))
    if quarantine_path is None:
        raise ValueError("Audit transaction has no quarantine preimage")
    if quarantine_path.is_symlink() or not quarantine_path.is_file():
        raise ValueError(
            f"Quarantine preimage is not a regular file: {quarantine_path}"
        )
    quarantine_root = _state_subdir(QUARANTINE_DIR)
    if not _path_inside(quarantine_path.resolve(strict=True), quarantine_root):
        raise PermissionError("Quarantine preimage is outside Grabowski state")
    if _sha256(quarantine_path) != before_sha:
        raise RuntimeError("Quarantine preimage hash mismatch")

    mode = statmod.S_IMODE(target.stat().st_mode)
    rollback_id, rollback_dir = _new_transaction_dir("rollback", target)
    postimage = rollback_dir / f"rolled-back-current-{after_sha[:12]}.txt"
    shutil.copy2(target, postimage, follow_symlinks=False)
    os.chmod(postimage, 0o600)

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(quarantine_path.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, mode)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    restored_sha = _sha256(target)
    if restored_sha != before_sha:
        raise RuntimeError("Rollback restore hash mismatch")
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "rollback",
        "transaction_id": rollback_id,
        "rolled_back_transaction_id": transaction_id,
        "path": str(target),
        "before_sha256": after_sha,
        "after_sha256": restored_sha,
        "bytes": target.stat().st_size,
        "backup": str(postimage),
        "quarantine": {
            "directory": str(rollback_dir),
            "preimage_path": str(postimage),
            "preimage_sha256": after_sha,
        },
        "rollback": {
            "available": True,
            "tool": "grabowski_rollback_text",
            "transaction_id": rollback_id,
            "expected_current_sha256": restored_sha,
            "restore_sha256": after_sha,
            "quarantine_path": str(postimage),
        },
    }
    _write_json_evidence(
        rollback_dir / "rollback.json",
        {
            "schema_version": 1,
            "transaction_id": rollback_id,
            "operation": "rollback",
            "rolled_back_transaction_id": transaction_id,
            "path": str(target),
            "before_sha256": after_sha,
            "after_sha256": restored_sha,
        },
    )
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_verify_audit", annotations=READ_ANNOTATIONS)
def grabowski_verify_audit() -> dict[str, Any]:
    """Verify the tamper-evident write audit hash chain."""
    _require_capability("audit_verify")
    return _verify_audit_log(AUDIT_LOG)


_BUNDLE_MANIFEST_SUFFIX = "_merge.bundle.manifest.json"
_BUNDLE_HEALTH_SUFFIX = "_merge.bundle_health.post.json"
_BUNDLE_SURFACE_SUFFIX = "_merge.bundle_surface_validation.json"
_BUNDLE_OUTPUT_HEALTH_SUFFIX = "_merge.output_health.json"
BUNDLE_REGISTRY_HEADER = (
    "repo",
    "stem",
    "latest_mtime",
    "has_agent_reading_pack",
    "canonical_md",
    "bundle_manifest",
    "output_health",
    "agent_reading_pack",
)
_REPOGROUND_STEM_RE = re.compile(r"[A-Za-z0-9_.-]{1,160}\Z")
_REPOGROUND_REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")


def _repoground_json(path: Path, *, max_bytes: int = 2_000_000) -> dict[str, Any]:
    data = _ensure_regular_text_file(path, max_bytes)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid RepoGround JSON artifact: {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"RepoGround artifact must be a JSON object: {path.name}")
    return value


def _repoground_validate_repo(repo: str | None) -> str | None:
    if repo is None or repo == "":
        return None
    if not isinstance(repo, str) or not _REPOGROUND_REPO_RE.fullmatch(repo):
        raise ValueError("repo must be a simple repository name")
    return repo


def _repoground_validate_stem(stem: str) -> str:
    if not isinstance(stem, str) or not _REPOGROUND_STEM_RE.fullmatch(stem):
        raise ValueError("stem must be a simple RepoGround bundle stem")
    return stem


def _repoground_repo_from_stem(stem: str) -> str:
    if "-full-max-" in stem:
        return stem.split("-full-max-", 1)[0]
    if "-max-" in stem:
        return stem.split("-max-", 1)[0]
    return stem.split("-", 1)[0]


def _repoground_stem_from_manifest(path: Path) -> str:
    name = path.name
    if not name.endswith(_BUNDLE_MANIFEST_SUFFIX):
        raise ValueError("not a RepoGround bundle manifest")
    return name[: -len(_BUNDLE_MANIFEST_SUFFIX)]


def _repoground_path_is_bounded(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _repoground_manifest_catalog_info(path: Path) -> dict[str, Any]:
    stem = _repoground_stem_from_manifest(path)
    resolved = path.resolve(strict=False)
    canonical_root = REPOGROUND_PUBLICATION_ROOT.resolve(strict=False)
    if _repoground_path_is_bounded(resolved, canonical_root):
        relative = resolved.relative_to(canonical_root)
        parts = relative.parts
        if len(parts) == 4:
            repo_id, ref, run_id, _name = parts
            owner, separator, repo = repo_id.partition("__")
            if (
                separator
                and _REPOGROUND_REPO_RE.fullmatch(owner)
                and _REPOGROUND_REPO_RE.fullmatch(repo)
            ):
                return {
                    "authority": "canonical_publication",
                    "publication_root": str(canonical_root),
                    "owner": owner,
                    "repo": repo,
                    "repo_id": repo_id,
                    "ref": ref,
                    "publication_run_id": run_id,
                    "stem": stem,
                }
    legacy_root = MERGES_ROOT.resolve(strict=False)
    if _repoground_path_is_bounded(resolved, legacy_root):
        return {
            "authority": "legacy_merges_fallback",
            "publication_root": str(legacy_root),
            "repo": _repoground_repo_from_stem(stem),
            "repo_id": None,
            "ref": None,
            "publication_run_id": None,
            "stem": stem,
        }
    raise PermissionError(
        "RepoGround manifest path is outside configured catalog roots"
    )


def _repoground_manifest_path(stem: str) -> Path:
    stem = _repoground_validate_stem(stem)
    resolution = repoground_catalog.resolve_catalog(
        REPOGROUND_PUBLICATION_ROOT, MERGES_ROOT, stem=stem
    )
    selected = resolution.get("selected")
    if (
        resolution.get("available")
        and isinstance(selected, list)
        and len(selected) == 1
    ):
        manifest_path = selected[0].get("manifest_path")
        if isinstance(manifest_path, str):
            return Path(manifest_path)
    reason = resolution.get("reason")
    if reason in {"ambiguous_stem", "ambiguous_publication"}:
        raise ValueError(str(reason))
    return MERGES_ROOT / f"{stem}{_BUNDLE_MANIFEST_SUFFIX}"


def _repoground_sidecar_path(
    stem: str,
    suffix: str,
    *,
    manifest_path: Path | None = None,
) -> Path:
    selected_manifest = manifest_path or _repoground_manifest_path(stem)
    return selected_manifest.parent / f"{stem}{suffix}"


def _repoground_sidecar_status(path: Path, *, keys: tuple[str, ...]) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        return {"exists": False, "path": str(path)}
    doc = _repoground_json(path)
    result: dict[str, Any] = {"exists": True, "path": str(path)}
    for key in keys:
        if key in doc:
            result[key] = doc[key]
    return result


def _repoground_output_health_status(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        return {"exists": False, "path": str(path)}
    doc = _repoground_json(path)
    result: dict[str, Any] = {"exists": True, "path": str(path)}
    for key in ("verdict", "run_id", "created_at", "warnings", "dependencies"):
        if key in doc:
            result[key] = doc[key]
    checks = doc.get("checks")
    if isinstance(checks, dict):
        status = checks.get("range_ref_resolution_status")
        if isinstance(status, str):
            result["range_ref_resolution_status"] = status
        resolution = checks.get("range_ref_resolution")
        if isinstance(resolution, dict):
            bounded = {
                key: resolution[key]
                for key in ("status", "reason", "validation")
                if key in resolution
            }
            if bounded:
                result["range_ref_resolution"] = bounded
    return result


def _repoground_manifest_snapshot_provenance(
    doc: dict[str, Any], repo: str
) -> dict[str, Any]:
    """Return explicit source-repository provenance from a RepoGround manifest.

    ``generator.runtime.git_commit`` describes the RepoGround code that
    produced the bundle.  It is not the commit of the scanned repository.  The
    freshness check may only compare a commit to the live repository when the
    manifest exposes explicit snapshot/source provenance for that repository.
    """
    provenance = doc.get("snapshotProvenance")
    if not isinstance(provenance, dict):
        provenance = doc.get("snapshot_provenance")
    if not isinstance(provenance, dict):
        return {"available": False, "reason": "snapshot_provenance_absent"}

    repositories = provenance.get("repositories")
    if not isinstance(repositories, list):
        return {"available": False, "reason": "snapshot_repositories_absent"}

    fallback: dict[str, Any] | None = None
    for item in repositories:
        if not isinstance(item, dict):
            continue
        if fallback is None:
            fallback = item
        names = [
            item.get("repo"),
            item.get("repository"),
            item.get("repo_id"),
            item.get("name"),
        ]
        if repo in {value for value in names if isinstance(value, str)}:
            fallback = item
            break
    if fallback is None:
        return {"available": False, "reason": "snapshot_repository_entry_absent"}

    commit = (
        fallback.get("git_commit") or fallback.get("commit") or fallback.get("head")
    )
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        return {
            "available": False,
            "reason": "snapshot_repository_commit_absent",
            "repository": {
                key: fallback.get(key)
                for key in (
                    "repo",
                    "repository",
                    "repo_id",
                    "name",
                    "ref",
                    "remote_ref",
                )
                if key in fallback
            },
        }
    result: dict[str, Any] = {
        "available": True,
        "git_commit": commit.lower(),
        "repository": {
            key: fallback.get(key)
            for key in ("repo", "repository", "repo_id", "name", "ref", "remote_ref")
            if key in fallback
        },
    }
    if isinstance(fallback.get("git_dirty"), bool):
        result["git_dirty"] = fallback.get("git_dirty")
    return result


def _repoground_manifest_summary(path: Path) -> dict[str, Any]:
    stem = _repoground_stem_from_manifest(path)
    catalog = _repoground_manifest_catalog_info(path)
    repo = str(catalog["repo"])
    record, rejection = repoground_catalog.inspect_candidate(
        path, REPOGROUND_PUBLICATION_ROOT, MERGES_ROOT
    )
    doc = record.get("document") if isinstance(record, dict) else _repoground_json(path)
    assert isinstance(doc, dict)
    artifacts = doc.get("artifacts") if isinstance(doc.get("artifacts"), list) else []
    roles = sorted(
        item.get("role")
        for item in artifacts
        if isinstance(item, dict) and isinstance(item.get("role"), str)
    )
    runtime = (doc.get("generator") or {}).get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    snapshot = (
        record.get("source_provenance")
        if isinstance(record, dict)
        else _repoground_manifest_snapshot_provenance(doc, repo)
    )
    if not isinstance(snapshot, dict):
        snapshot = {"available": False, "reason": "snapshot_provenance_absent"}
    source_commit = snapshot.get("git_commit") if snapshot.get("available") else None
    source_dirty = snapshot.get("git_dirty") if snapshot.get("available") else None
    stat = path.stat()
    health_path = _repoground_sidecar_path(
        stem, _BUNDLE_HEALTH_SUFFIX, manifest_path=path
    )
    health = _repoground_sidecar_status(
        health_path,
        keys=("status", "evidence_level", "range_ref_resolution_status"),
    )
    manifest_sha = (
        record.get("manifest_sha256")
        if isinstance(record, dict)
        else _repoground_file_sha256(path)
    )
    created_at = doc.get("created_at") or doc.get("generatedAt")
    return {
        "repo": repo,
        "repo_id": catalog.get("repo_id"),
        "owner": catalog.get("owner"),
        "stem": stem,
        "manifest_path": str(path),
        "manifest_sha256": manifest_sha,
        "publication_authority": catalog["authority"],
        "publication_root": catalog["publication_root"],
        "publication_ref": catalog["ref"],
        "publication_run_id": catalog["publication_run_id"],
        "manifest_mtime_unix": int(stat.st_mtime),
        "run_id": doc.get("run_id"),
        "created_at": created_at,
        "artifact_count": len(artifacts),
        "artifact_roles": roles,
        "git_commit": source_commit,
        "git_dirty": source_dirty,
        "source_provenance": snapshot,
        "generator_runtime": {
            "git_commit": runtime.get("git_commit"),
            "git_dirty": runtime.get("git_dirty"),
            "module": runtime.get("module"),
            "package_root": runtime.get("package_root"),
        },
        "post_emit_health": health,
        "output_health": _repoground_output_health_status(
            _repoground_sidecar_path(
                stem, _BUNDLE_OUTPUT_HEALTH_SUFFIX, manifest_path=path
            )
        ),
        "catalog_healthy": record is not None,
        "catalog_rejection_reason": (
            rejection.get("reason") if isinstance(rejection, dict) else None
        ),
    }


def _repoground_catalog_resolution(
    repo: str | None = None, stem: str | None = None
) -> dict[str, Any]:
    return repoground_catalog.resolve_catalog(
        REPOGROUND_PUBLICATION_ROOT, MERGES_ROOT, repo=repo, stem=stem
    )


def _repoground_canonical_manifests(repo: str | None) -> list[Path]:
    resolution = _repoground_catalog_resolution(repo)
    return [
        Path(item["manifest_path"])
        for item in resolution.get("selected", [])
        if item.get("authority") == "canonical_publication"
        and isinstance(item.get("manifest_path"), str)
    ]


def _repoground_legacy_manifests(repo: str | None) -> list[Path]:
    resolution = _repoground_catalog_resolution(repo)
    return [
        Path(item["manifest_path"])
        for item in resolution.get("selected", [])
        if item.get("authority") == "legacy_merges_fallback"
        and isinstance(item.get("manifest_path"), str)
    ]


def _repoground_iter_manifests(repo: str | None = None) -> list[Path]:
    repo = _repoground_validate_repo(repo)
    resolution = _repoground_catalog_resolution(repo)
    return [
        Path(item["manifest_path"])
        for item in resolution.get("selected", [])
        if isinstance(item.get("manifest_path"), str)
    ]


def _repoground_latest_manifest_by_repo() -> dict[str, Path]:
    resolution = _repoground_catalog_resolution()
    aliases = (
        resolution.get("aliases") if isinstance(resolution.get("aliases"), dict) else {}
    )
    latest: dict[str, Path] = {}
    for item in resolution.get("selected", []):
        path = item.get("manifest_path")
        repo = item.get("repo")
        repo_id = item.get("repo_id")
        if not isinstance(path, str) or not isinstance(repo, str):
            continue
        key = (
            repo_id
            if len(aliases.get(repo, [])) > 1 and isinstance(repo_id, str)
            else repo
        )
        latest[str(key)] = Path(path)
    return latest


def _repoground_manifest_registry_row(path: Path) -> list[str]:
    summary = _repoground_manifest_summary(path)
    stem = str(summary["stem"])
    repo = str(summary["repo"])
    artifact_roles = set(summary.get("artifact_roles") or [])

    def display(candidate: Path) -> str:
        try:
            relative = candidate.resolve(strict=False).relative_to(
                (HOME / "repos").resolve(strict=False)
            )
            return "./" + relative.as_posix()
        except ValueError:
            return str(candidate)

    def sidecar(suffix: str) -> str:
        return display(path.parent / f"{stem}{suffix}")

    created_at = summary.get("created_at")
    if not isinstance(created_at, str) or not created_at:
        created_at = datetime.fromtimestamp(
            int(summary["manifest_mtime_unix"]), timezone.utc
        ).isoformat()
    return [
        repo,
        stem,
        created_at,
        "yes" if "agent_reading_pack" in artifact_roles else "no",
        sidecar("_merge.md"),
        display(path),
        sidecar(_BUNDLE_OUTPUT_HEALTH_SUFFIX),
        sidecar("_merge.agent_reading_pack.md"),
    ]


def _repoground_registry_row_status(row: list[str]) -> dict[str, Any]:
    status: dict[str, Any] = {
        "valid": False,
        "header": False,
        "is_header": False,
        "reason": None,
        "stem": None,
        "repo": row[0] if row else None,
        "manifest_exists": False,
    }
    if not row:
        status["reason"] = "empty_row"
        return status
    if len(row) == len(BUNDLE_REGISTRY_HEADER) and tuple(row) == BUNDLE_REGISTRY_HEADER:
        status.update({"valid": True, "header": True, "is_header": True})
        return status
    if len(row) != len(BUNDLE_REGISTRY_HEADER):
        status["reason"] = "invalid_row_shape"
        return status
    try:
        stem = _repoground_validate_stem(row[1])
        resolution = _repoground_catalog_resolution(row[0], stem)
    except ValueError:
        status["reason"] = "invalid_stem_or_repo"
        return status
    selected = resolution.get("selected")
    exists = bool(
        resolution.get("available")
        and isinstance(selected, list)
        and len(selected) == 1
        and Path(str(selected[0].get("manifest_path"))).is_file()
    )
    status.update(
        {
            "valid": exists,
            "stem": stem,
            "repo": row[0],
            "manifest_exists": exists,
            "reason": None
            if exists
            else str(resolution.get("reason") or "manifest_unavailable"),
            "manifest_sha256": (selected[0].get("manifest_sha256") if exists else None),
        }
    )
    return status


def _repoground_git(repo_path: Path, args: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


@mcp.tool(name="repoground_bundle_discover", annotations=READ_ANNOTATIONS)
def repoground_bundle_discover(
    repo: str | None = None, max_candidates: int = 20
) -> dict[str, Any]:
    """Discover healthy RepoGround bundles from one deterministic publication catalog."""
    _require_capability("bundle_registry")
    if not isinstance(max_candidates, int) or not 1 <= max_candidates <= 100:
        raise ValueError("max_candidates must be between 1 and 100")
    repo_filter = _repoground_validate_repo(repo)
    resolution = _repoground_catalog_resolution(repo_filter)
    manifests = [
        Path(item["manifest_path"])
        for item in resolution.get("selected", [])[:max_candidates]
        if isinstance(item.get("manifest_path"), str)
    ]
    candidates = [_repoground_manifest_summary(path) for path in manifests]
    canonical_count = sum(
        candidate.get("publication_authority") == "canonical_publication"
        for candidate in candidates
    )
    legacy_count = sum(
        candidate.get("publication_authority") == "legacy_merges_fallback"
        for candidate in candidates
    )
    if canonical_count:
        authority = "canonical_publication_catalog"
    elif legacy_count:
        authority = "legacy_merges_fallback"
    else:
        authority = "publication_unavailable"
    rejected = resolution.get("rejected")
    if not isinstance(rejected, list):
        rejected = []
    return {
        "kind": "grabowski.repoground_bundle_discovery",
        "schema_version": 3,
        "catalog": {
            "authority": authority,
            "canonical_root": str(REPOGROUND_PUBLICATION_ROOT),
            "canonical_root_exists": REPOGROUND_PUBLICATION_ROOT.is_dir()
            and not REPOGROUND_PUBLICATION_ROOT.is_symlink(),
            "legacy_root": str(MERGES_ROOT),
            "legacy_root_exists": MERGES_ROOT.is_dir() and not MERGES_ROOT.is_symlink(),
            "canonical_candidate_count": canonical_count,
            "legacy_fallback_candidate_count": legacy_count,
            "selection_reason": resolution.get("reason"),
            "aliases": resolution.get("aliases"),
        },
        "merges_root": str(MERGES_ROOT),
        "repo_filter": repo_filter,
        "exists": bool(candidates),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "rejected_candidate_count": len(rejected),
        "rejected_candidates": rejected[:max_candidates],
        "registry_cache": {
            "path": str(BUNDLE_REGISTRY),
            "exists": BUNDLE_REGISTRY.is_file(),
            "authority": "non_authoritative_cache",
        },
        "does_not_establish": [
            "bundle_freshness_against_live_repo",
            "repo_understood",
            "claims_true",
            "runtime_correctness",
        ],
    }


@mcp.tool(name="repoground_bundle_status", annotations=READ_ANNOTATIONS)
def repoground_bundle_status(stem: str) -> dict[str, Any]:
    """Return bounded status for one uniquely identified RepoGround bundle."""
    _require_capability("bundle_registry")
    stem = _repoground_validate_stem(stem)
    inspection = repoground_catalog.inspect_stem(
        REPOGROUND_PUBLICATION_ROOT, MERGES_ROOT, stem
    )
    if not inspection.get("available"):
        return {
            "kind": "grabowski.repoground_bundle_status",
            "schema_version": 2,
            "stem": stem,
            "exists": False,
            "reason": inspection.get("reason"),
            "matches": inspection.get("matches", []),
        }
    record = inspection.get("record") if inspection.get("healthy") else None
    rejection = inspection.get("rejection") if not inspection.get("healthy") else None
    raw_path = (
        record.get("manifest_path")
        if isinstance(record, dict)
        else inspection.get("manifest_path")
    )
    manifest_path = Path(raw_path) if isinstance(raw_path, str) else None
    if (
        manifest_path is None
        or not manifest_path.is_file()
        or manifest_path.is_symlink()
    ):
        return {
            "kind": "grabowski.repoground_bundle_status",
            "schema_version": 2,
            "stem": stem,
            "exists": False,
            "reason": "bundle_manifest_missing",
        }
    try:
        summary = _repoground_manifest_summary(manifest_path)
    except (OSError, ValueError, PermissionError) as exc:
        return {
            "kind": "grabowski.repoground_bundle_status",
            "schema_version": 2,
            "stem": stem,
            "exists": True,
            "manifest_path": str(manifest_path),
            "catalog_healthy": False,
            "catalog_rejection": rejection,
            "reason": str(inspection.get("reason") or type(exc).__name__),
        }
    surface = _repoground_sidecar_status(
        _repoground_sidecar_path(
            stem, _BUNDLE_SURFACE_SUFFIX, manifest_path=manifest_path
        ),
        keys=("status", "bundle_run_id"),
    )
    output_health = _repoground_output_health_status(
        _repoground_sidecar_path(
            stem, _BUNDLE_OUTPUT_HEALTH_SUFFIX, manifest_path=manifest_path
        )
    )
    return {
        "kind": "grabowski.repoground_bundle_status",
        "schema_version": 2,
        "exists": True,
        **summary,
        "catalog_healthy": inspection.get("healthy") is True,
        "catalog_rejection": rejection,
        "bundle_surface_validation": surface,
        "output_health": output_health,
        "authority": "artifact_metadata_only",
        "does_not_establish": [
            "bundle_freshness_against_live_repo",
            "repo_understood",
            "claims_true",
            "review_complete",
            "runtime_correctness",
        ],
    }


def _repoground_freshness_source(
    repo: str, status: dict[str, Any]
) -> tuple[Path, str, str | None]:
    provenance = status.get("source_provenance")
    repository = provenance.get("repository") if isinstance(provenance, dict) else None
    source_name = repository.get("name") if isinstance(repository, dict) else None
    publication_ref = status.get("publication_ref")
    if (
        status.get("publication_authority") == "canonical_publication"
        and isinstance(source_name, str)
        and re.fullmatch(r"[A-Za-z0-9._-]{1,255}", source_name)
    ):
        source_root = (HOME / "repos" / ".repoground-sources").resolve(strict=False)
        candidate = source_root / source_name
        try:
            resolved = candidate.resolve(strict=False)
        except RuntimeError:
            resolved = candidate
        if (
            resolved != source_root
            and source_root in resolved.parents
            and candidate.is_dir()
            and not candidate.is_symlink()
        ):
            ref = publication_ref if isinstance(publication_ref, str) else None
            return candidate, "publication_source_checkout", ref
    return (HOME / "repos" / repo).resolve(strict=False), "conventional_checkout", None


@mcp.tool(name="repoground_freshness_check", annotations=READ_ANNOTATIONS)
def repoground_freshness_check(repo: str, stem: str | None = None) -> dict[str, Any]:
    """Compare one healthy RepoGround publication with its local source identity."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    if stem is not None and stem != "":
        stem = _repoground_validate_stem(stem)
    else:
        stem = None
    resolution = _repoground_catalog_resolution(repo, stem)
    selected = resolution.get("selected")
    if (
        not resolution.get("available")
        or not isinstance(selected, list)
        or len(selected) != 1
    ):
        missing_reason = (
            "no_bundle_found"
            if stem is None and resolution.get("reason") == "publication_unavailable"
            else str(resolution.get("reason") or "no_bundle_found")
        )
        return {
            "kind": "grabowski.repoground_freshness_check",
            "schema_version": 3,
            "repo": repo,
            "stem": stem,
            "freshness": "unknown",
            "freshness_status": "publication_unavailable",
            "reason": missing_reason,
            "rejected_candidates": resolution.get("rejected", []),
            "ambiguous_candidates": resolution.get("ambiguous_candidates", []),
        }
    selected_record = selected[0]
    selected_stem = str(selected_record["stem"])
    manifest_path = Path(str(selected_record["manifest_path"]))
    status = _repoground_manifest_summary(manifest_path)
    bundle_commit = status.get("git_commit")
    bundle_dirty = status.get("git_dirty")
    source_repo = str(status.get("repo") or repo)
    repo_path, source_kind, source_ref = _repoground_freshness_source(
        source_repo, status
    )
    live: dict[str, Any] = {
        "repo_path": str(repo_path),
        "source_kind": source_kind,
        "exists": repo_path.is_dir(),
    }
    if not repo_path.is_dir() or repo_path.is_symlink():
        freshness = "fresh_dirty_unverified" if bundle_dirty else "unknown"
        freshness_status = "dirty_overlay" if bundle_dirty else "source_unavailable"
        reason = (
            "publication_source_dirty" if bundle_dirty else "repo_missing_or_invalid"
        )
    else:
        checkout_rc, checkout_head, checkout_err = _repoground_git(
            repo_path, ["rev-parse", "HEAD"]
        )
        dirty_rc, dirty_out, dirty_err = _repoground_git(
            repo_path, ["status", "--porcelain"]
        )
        comparison_head = checkout_head if checkout_rc == 0 else None
        comparison_ref = "HEAD"
        remote_err = ""
        if source_kind == "publication_source_checkout" and source_ref:
            remote_ref = f"origin/{source_ref}"
            remote_rc, remote_head, remote_err = _repoground_git(
                repo_path, ["rev-parse", remote_ref]
            )
            if remote_rc == 0:
                comparison_head = remote_head
                comparison_ref = remote_ref
        live.update(
            {
                "head_returncode": checkout_rc,
                "checkout_head": checkout_head if checkout_rc == 0 else None,
                "head": comparison_head,
                "comparison_ref": comparison_ref,
                "dirty_returncode": dirty_rc,
                "dirty": bool(dirty_out) if dirty_rc == 0 else None,
                "error": checkout_err or dirty_err or remote_err or None,
            }
        )
        if checkout_rc != 0 or dirty_rc != 0 or not isinstance(comparison_head, str):
            freshness = "fresh_dirty_unverified" if bundle_dirty else "unknown"
            freshness_status = "dirty_overlay" if bundle_dirty else "source_unavailable"
            reason = "publication_source_dirty" if bundle_dirty else "git_unavailable"
        elif not isinstance(bundle_commit, str):
            freshness = "unknown"
            freshness_status = "provenance_missing"
            reason = "bundle_source_commit_unavailable"
        elif live["dirty"] or bundle_dirty:
            freshness = "fresh_dirty_unverified"
            freshness_status = "dirty_overlay"
            reason = "dirty_source_or_publication_overlay"
        elif bundle_commit != comparison_head:
            freshness = "stale_head"
            freshness_status = "stale"
            reason = "bundle_commit_differs_from_live_head"
        else:
            freshness = "fresh_exact"
            freshness_status = "fresh"
            reason = "bundle_commit_matches_clean_live_head"
    return {
        "kind": "grabowski.repoground_freshness_check",
        "schema_version": 3,
        "repo": repo,
        "stem": selected_stem,
        "bundle": {
            "exists": True,
            "manifest_path": status.get("manifest_path"),
            "manifest_sha256": status.get("manifest_sha256"),
            "publication_authority": status.get("publication_authority"),
            "repo_id": status.get("repo_id"),
            "ref": status.get("publication_ref"),
            "git_commit": bundle_commit,
            "git_dirty": bundle_dirty,
            "source_provenance": status.get("source_provenance"),
            "generator_runtime": status.get("generator_runtime"),
            "post_emit_health": status.get("post_emit_health"),
            "output_health": status.get("output_health"),
        },
        "live_repo": live,
        "freshness": freshness,
        "freshness_status": freshness_status,
        "reason": reason,
        "does_not_establish": [
            "dirty_worktree_identity",
            "runtime_correctness",
            "repo_understood",
            "claims_true",
        ],
    }


_REPOGROUND_TASK_PROFILE_RE = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")


def _repoground_validate_task_profile(task_profile: str) -> str:
    if not isinstance(task_profile, str) or not _REPOGROUND_TASK_PROFILE_RE.fullmatch(
        task_profile
    ):
        raise ValueError("task_profile must be a simple RepoGround task profile")
    return task_profile


def _repoground_file_sha256(path: Path) -> str:
    return hashlib.sha256(_ensure_regular_text_file(path, 2_000_000)).hexdigest()


def _repoground_agent_preflight(
    task_profile: str, manifest_path: Path
) -> dict[str, Any]:
    """Run RepoGround's agent-consumption preflight when the local CLI is available."""
    repoground_repo = (HOME / "repos" / "repoground").resolve(strict=False)
    if not repoground_repo.is_dir() or repoground_repo.is_symlink():
        return {
            "status": "unknown",
            "available": False,
            "reason": "repoground_repo_missing_or_invalid",
        }
    command = [
        "python3",
        "-B",
        "-m",
        "merger.repoground.cli.main",
        "agent-consumption",
        "preflight",
        "--task-profile",
        task_profile,
        "--bundle-manifest",
        str(manifest_path),
    ]
    completed = subprocess.run(
        command,
        cwd=repoground_repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env={
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    stdout = completed.stdout[:500_000]
    stderr = completed.stderr[:20_000]
    if completed.returncode not in {0, 1} or not stdout.strip():
        return {
            "status": "unknown",
            "available": True,
            "returncode": completed.returncode,
            "stderr": _redact_sensitive_text(stderr)[0],
            "reason": "repoground_preflight_failed",
        }
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "status": "unknown",
            "available": True,
            "returncode": completed.returncode,
            "reason": "repoground_preflight_invalid_json",
        }
    if not isinstance(value, dict):
        return {
            "status": "unknown",
            "available": True,
            "returncode": completed.returncode,
            "reason": "repoground_preflight_non_object",
        }
    value["available"] = True
    value["returncode"] = completed.returncode
    return value


def _repoground_repo() -> tuple[Path | None, dict[str, Any] | None]:
    repoground_repo = (HOME / "repos" / "repoground").resolve(strict=False)
    if not repoground_repo.is_dir() or repoground_repo.is_symlink():
        return None, {
            "available": False,
            "status": "unknown",
            "reason": "repoground_repo_missing_or_invalid",
            "repoground_repo": str(repoground_repo),
        }
    return repoground_repo, None


def _repoground_core_json(
    operation: str,
    manifest_path: Path,
    payload: dict[str, Any],
    *,
    timeout: int = 30,
) -> dict[str, Any]:
    repoground_repo, unavailable_result = _repoground_repo()
    if unavailable_result is not None:
        return unavailable_result
    assert repoground_repo is not None
    script = r"""
import json
import sys
from merger.repoground.core import bundle_access, mcp_tools

operation = sys.argv[1]
manifest = sys.argv[2]
payload = json.loads(sys.stdin.read() or "{}")

if operation == "query_existing_index":
    result = bundle_access.query_existing_index(
        manifest,
        payload.get("query", ""),
        k=payload.get("k", 10),
        filters=payload.get("filters") or {},
        resolve_evidence=payload.get("resolve_evidence", False),
        project_sources=payload.get("project_sources", False),
    )
elif operation == "range_get":
    result = bundle_access.range_get(manifest, payload.get("range_ref"))
elif operation == "find_symbol":
    result = mcp_tools.find_symbol(
        bundle_manifest=manifest,
        name=payload.get("name"),
        kind=payload.get("kind"),
        path=payload.get("path"),
        k=payload.get("k", 25),
    )
elif operation == "get_callers":
    result = mcp_tools.get_callers(
        bundle_manifest=manifest,
        name=payload.get("name"),
        path=payload.get("path"),
        k=payload.get("k", 25),
    )
elif operation == "get_callees":
    result = mcp_tools.get_callees(
        bundle_manifest=manifest,
        name=payload.get("name"),
        path=payload.get("path"),
        k=payload.get("k", 25),
    )
elif operation == "agent_impact_context":
    from pathlib import Path
    from merger.repoground.core.agent_impact_adapter import RepoGroundAgentImpactAdapter
    from merger.repoground.core.readonly_adapter import SnapshotRegistration
    manifest_path = Path(manifest).resolve()
    adapter = RepoGroundAgentImpactAdapter(
        config_path=manifest_path,
        allowed_roots=(manifest_path.parent,),
        snapshots=(SnapshotRegistration("selected", manifest_path),),
    )
    result = adapter.agent_impact_context(
        "selected",
        target_path=payload.get("target_path"),
        target_symbol=payload.get("target_symbol"),
        changed_paths=payload.get("changed_paths"),
        mode=payload.get("mode", "impact"),
        max_items=payload.get("max_items", 25),
        include_query_context=payload.get("include_query_context", True),
    )
else:
    raise SystemExit(f"unknown operation: {operation}")

print(json.dumps(result, sort_keys=True))
"""
    completed = subprocess.run(
        ["python3", "-B", "-c", script, operation, str(manifest_path)],
        cwd=repoground_repo,
        check=False,
        input=json.dumps(payload, sort_keys=True),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env={
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    stdout = completed.stdout[:500_000]
    stderr = completed.stderr[:20_000]
    if completed.returncode not in {0, 1} or not stdout.strip():
        return {
            "available": False,
            "status": "unknown",
            "returncode": completed.returncode,
            "stderr": _redact_sensitive_text(stderr)[0],
            "reason": "repoground_access_failed",
        }
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "available": False,
            "status": "unknown",
            "returncode": completed.returncode,
            "reason": "repoground_access_invalid_json",
        }
    if not isinstance(value, dict):
        return {
            "available": False,
            "status": "unknown",
            "returncode": completed.returncode,
            "reason": "repoground_access_non_object",
        }
    value.setdefault("available", value.get("status") == "available")
    value["returncode"] = completed.returncode
    return value


def _repoground_query_existing_index(
    manifest_path: Path,
    query: str,
    *,
    k: int,
    filters: dict[str, Any] | None,
    resolve_evidence: bool,
    project_sources: bool,
) -> dict[str, Any]:
    return _repoground_core_json(
        "query_existing_index",
        manifest_path,
        {
            "query": query,
            "k": k,
            "filters": filters or {},
            "resolve_evidence": resolve_evidence,
            "project_sources": project_sources,
        },
    )


def _repoground_range_get(
    manifest_path: Path, range_ref: dict[str, Any]
) -> dict[str, Any]:
    return _repoground_core_json(
        "range_get",
        manifest_path,
        {"range_ref": range_ref},
    )


def _repoground_find_symbol(
    manifest_path: Path,
    *,
    name: str,
    kind: str | None,
    path: str | None,
    k: int,
) -> dict[str, Any]:
    return _repoground_core_json(
        "find_symbol",
        manifest_path,
        {"name": name, "kind": kind, "path": path, "k": k},
    )


def _repoground_get_callers(
    manifest_path: Path,
    *,
    name: str,
    path: str | None,
    k: int,
) -> dict[str, Any]:
    return _repoground_core_json(
        "get_callers",
        manifest_path,
        {"name": name, "path": path, "k": k},
    )


def _repoground_get_callees(
    manifest_path: Path,
    *,
    name: str,
    path: str | None,
    k: int,
) -> dict[str, Any]:
    return _repoground_core_json(
        "get_callees",
        manifest_path,
        {"name": name, "path": path, "k": k},
    )


def _repoground_text_excerpt(value: Any, *, max_chars: int = 1200) -> str | None:
    if not isinstance(value, str):
        return None
    return value[:max_chars]


def _repoground_list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [
        item
        for item in (value if isinstance(value, list) else [])
        if isinstance(item, dict)
    ]


def _repoground_extract_query_hits(payload: Any) -> tuple[list[dict[str, Any]], str]:
    if isinstance(payload, list):
        return _repoground_list_of_dicts(payload), "bare_results_array"
    if not isinstance(payload, dict):
        return [], "non_object"
    resolved = payload.get("resolved_evidence")
    if isinstance(resolved, dict):
        resolved_hits = resolved.get("hits")
        if isinstance(resolved_hits, list):
            return _repoground_list_of_dicts(resolved_hits), "resolved_evidence.hits"
    direct_results = payload.get("results")
    if isinstance(direct_results, list):
        return _repoground_list_of_dicts(direct_results), "top_level_results"
    query_result = payload.get("query_result")
    if isinstance(query_result, list):
        return _repoground_list_of_dicts(query_result), "query_result_array"
    if isinstance(query_result, dict):
        nested_results = query_result.get("results")
        if isinstance(nested_results, list):
            return _repoground_list_of_dicts(nested_results), "query_result.results"
    return [], "no_results_array"


def _repoground_source_projection_items(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    projection = payload.get("source_citation_projection")
    if not isinstance(projection, dict):
        return []
    return _repoground_list_of_dicts(projection.get("items"))


def _repoground_range_identity_from_hit(hit: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("range_ref", "derived_range_ref", "content_range_ref"):
        value = hit.get(key)
        if isinstance(value, dict):
            return value
    return None


def _repoground_query_snippets(
    payload: Any, *, max_snippets: int = 5
) -> dict[str, Any]:
    projection_items = _repoground_source_projection_items(payload)
    snippets: list[dict[str, Any]] = []
    ranges: list[dict[str, Any]] = []
    if projection_items:
        for item in projection_items[:max_snippets]:
            source_range = (
                item.get("source_range")
                if isinstance(item.get("source_range"), dict)
                else None
            )
            snippet = {
                "ordinal": item.get("ordinal", len(snippets)),
                "path": item.get("path"),
                "chunk_id": item.get("chunk_id"),
                "text_excerpt": _repoground_text_excerpt(item.get("text_excerpt")),
                "range_status": item.get("range_status"),
                "citation_status": item.get("citation_status"),
                "citation_id": item.get("citation_id"),
                "citation_range": item.get("citation_range")
                if isinstance(item.get("citation_range"), dict)
                else None,
                "canonical_authority": item.get("canonical_authority")
                if isinstance(item.get("canonical_authority"), dict)
                else None,
                "live_repo_address": item.get("live_repo_address")
                if isinstance(item.get("live_repo_address"), dict)
                else None,
                "live_repo_address_status": item.get("live_repo_address_status"),
                "source_range": source_range,
            }
            snippets.append(snippet)
            if source_range is not None:
                ranges.append(source_range)
        return {
            "source_shape": "source_citation_projection.items",
            "hit_count": len(projection_items),
            "snippets": snippets,
            "ranges": ranges,
        }

    hits, shape = _repoground_extract_query_hits(payload)
    for ordinal, hit in enumerate(hits[:max_snippets]):
        range_ref = _repoground_range_identity_from_hit(hit)
        source_range = (
            hit.get("source_range")
            if isinstance(hit.get("source_range"), dict)
            else None
        )
        canonical_authority = (
            hit.get("canonical_authority")
            if isinstance(hit.get("canonical_authority"), dict)
            else None
        )
        live_repo_address = (
            hit.get("live_repo_address")
            if isinstance(hit.get("live_repo_address"), dict)
            else None
        )
        text = _repoground_text_excerpt(
            hit.get("text_excerpt")
            if isinstance(hit.get("text_excerpt"), str)
            else hit.get("text")
            if isinstance(hit.get("text"), str)
            else hit.get("content")
            if isinstance(hit.get("content"), str)
            else hit.get("snippet")
        )
        snippet = {
            "ordinal": ordinal,
            "path": hit.get("source_path") or hit.get("path"),
            "chunk_id": hit.get("chunk_id"),
            "score": hit.get("score"),
            "text_excerpt": text,
            "range_ref": range_ref,
            "source_range": source_range,
            "line_range": hit.get("line_range")
            if isinstance(hit.get("line_range"), dict)
            else None,
            "citation_id": hit.get("citation_id"),
            "citation_status": hit.get("citation_status"),
            "citation_verified": hit.get("citation_verified"),
            "canonical_authority": canonical_authority,
            "live_repo_address": live_repo_address,
            "live_repo_address_status": hit.get("live_repo_address_status"),
        }
        snippets.append(snippet)
        if source_range is not None:
            ranges.append(source_range)
        elif range_ref is not None:
            ranges.append(range_ref)
    return {
        "source_shape": shape,
        "hit_count": len(hits),
        "snippets": snippets,
        "ranges": ranges,
    }


def _repoground_context_evidence_status(
    query: str | None,
    query_context: dict[str, Any],
    snippets: list[dict[str, Any]],
    ranges: list[dict[str, Any]],
) -> tuple[str, str | None]:
    if not query:
        return "skipped", "query_not_provided"
    if not query_context.get("available", False):
        reason = (
            query_context.get("reason")
            or query_context.get("status")
            or "query_unavailable"
        )
        return "unavailable", str(reason)
    citation_count = sum(
        1
        for snippet in snippets
        if isinstance(snippet.get("citation_id"), str) and snippet.get("citation_id")
    )
    if snippets and (ranges or citation_count):
        return "available", None
    return "degraded", "resolved_evidence_missing_snippets_ranges_or_citations"


def _repoground_context_citation_ids(snippets: list[dict[str, Any]]) -> list[str]:
    ids = []
    for snippet in snippets:
        citation_id = snippet.get("citation_id")
        if isinstance(citation_id, str) and citation_id and citation_id not in ids:
            ids.append(citation_id)
    return ids


def _repoground_selected_manifest_for_repo(
    repo: str,
    stem: str | None,
) -> tuple[dict[str, Any], str | None, Path | None, dict[str, Any] | None]:
    resolution = _repoground_catalog_resolution(repo, stem)
    selected = resolution.get("selected")
    if (
        not resolution.get("available")
        or not isinstance(selected, list)
        or len(selected) != 1
    ):
        error_reason = str(resolution.get("reason") or "no_bundle_available")
        bundle_repo: str | None = None
        if stem:
            inspection = repoground_catalog.inspect_stem(
                REPOGROUND_PUBLICATION_ROOT, MERGES_ROOT, stem
            )
            inspected = inspection.get("record")
            if isinstance(inspected, dict):
                candidate_repo = inspected.get("repo")
                candidate_repo_id = inspected.get("repo_id")
                matches = (
                    candidate_repo_id == repo
                    if "__" in repo
                    else candidate_repo == repo
                )
                if not matches:
                    error_reason = "bundle_repo_mismatch"
                    bundle_repo = (
                        str(candidate_repo_id)
                        if "__" in repo and isinstance(candidate_repo_id, str)
                        else str(candidate_repo)
                        if isinstance(candidate_repo, str)
                        else None
                    )
        elif error_reason == "publication_unavailable":
            error_reason = "no_bundle_available"
        freshness = {
            "kind": "grabowski.repoground_freshness_check",
            "schema_version": 3,
            "repo": repo,
            "stem": stem,
            "freshness": "unknown",
            "freshness_status": "publication_unavailable",
            "reason": error_reason,
            "rejected_candidates": resolution.get("rejected", []),
            "ambiguous_candidates": resolution.get("ambiguous_candidates", []),
        }
        return (
            freshness,
            stem,
            None,
            {
                "kind": "grabowski.repoground_selection",
                "schema_version": 2,
                "repo": repo,
                "stem": stem,
                "available": False,
                "freshness": freshness,
                "reason": error_reason,
                "bundle_repo": bundle_repo,
                "rejected_candidates": resolution.get("rejected", []),
                "ambiguous_candidates": resolution.get("ambiguous_candidates", []),
            },
        )
    record = selected[0]
    selected_stem = str(record["stem"])
    manifest_path = Path(str(record["manifest_path"]))
    freshness = repoground_freshness_check(repo, selected_stem)
    freshness_bundle = freshness.get("bundle")
    freshness_sha = (
        freshness_bundle.get("manifest_sha256")
        if isinstance(freshness_bundle, dict)
        else None
    )
    if freshness_sha != record.get("manifest_sha256"):
        return (
            freshness,
            selected_stem,
            None,
            {
                "kind": "grabowski.repoground_selection",
                "schema_version": 2,
                "repo": repo,
                "stem": selected_stem,
                "available": False,
                "reason": "catalog_selection_changed",
                "expected_manifest_sha256": record.get("manifest_sha256"),
                "observed_manifest_sha256": freshness_sha,
            },
        )
    return freshness, selected_stem, manifest_path, None


@mcp.tool(name="repoground_preflight", annotations=READ_ANNOTATIONS)
def repoground_preflight(
    repo: str,
    task_profile: str = "basic_repo_question",
    stem: str | None = None,
) -> dict[str, Any]:
    """Return bounded RepoGround preflight for an agent task profile."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    task_profile = _repoground_validate_task_profile(task_profile)
    freshness, selected_stem, manifest_path, selection_error = (
        _repoground_selected_manifest_for_repo(repo, stem)
    )
    if selection_error is not None:
        return {
            "kind": "grabowski.repoground_preflight",
            "schema_version": 1,
            "repo": repo,
            "task_profile": task_profile,
            "stem": selected_stem,
            "available": False,
            "freshness": freshness,
            "reason": selection_error.get("reason"),
            "bundle_repo": selection_error.get("bundle_repo"),
            "does_not_establish": [
                "actual_agent_reading",
                "answer_correct",
                "repo_understood",
                "claims_true",
                "runtime_correctness",
            ],
        }
    assert isinstance(manifest_path, Path)
    assert isinstance(selected_stem, str)
    preflight = _repoground_agent_preflight(task_profile, manifest_path)
    preflight_status = (
        preflight.get("status")
        if isinstance(preflight.get("status"), str)
        else "unknown"
    )
    return {
        "kind": "grabowski.repoground_preflight",
        "schema_version": 1,
        "repo": repo,
        "task_profile": task_profile,
        "stem": selected_stem,
        "available": preflight.get("available", False),
        "status": preflight_status,
        "freshness": freshness,
        "preflight": {
            "available": preflight.get("available", False),
            "status": preflight_status,
            "required_reading": preflight.get("required_reading"),
            "answer_compliance_template": preflight.get("answer_compliance_template"),
            "does_not_establish": preflight.get("does_not_establish"),
            "error_reason": preflight.get("reason"),
        },
        "does_not_establish": [
            "actual_agent_reading",
            "answer_correct",
            "repo_understood",
            "claims_true",
            "test_sufficiency",
            "review_complete",
            "runtime_correctness",
        ],
    }


@mcp.tool(name="repoground_query", annotations=READ_ANNOTATIONS)
def repoground_query(
    repo: str,
    query: str,
    task_profile: str = "basic_repo_question",
    stem: str | None = None,
    k: int = 5,
    filters: dict[str, Any] | None = None,
    max_snippets: int = 5,
) -> dict[str, Any]:
    """Run a bounded read-only RepoGround query and normalize result shapes."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    task_profile = _repoground_validate_task_profile(task_profile)
    if not isinstance(query, str) or not query.strip() or len(query) > 500:
        raise ValueError("query must be a non-empty string up to 500 characters")
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= 100:
        raise ValueError("k must be an integer between 1 and 100")
    if filters is not None and not isinstance(filters, dict):
        raise ValueError("filters must be an object when provided")
    if (
        not isinstance(max_snippets, int)
        or isinstance(max_snippets, bool)
        or not 1 <= max_snippets <= 20
    ):
        raise ValueError("max_snippets must be an integer between 1 and 20")

    freshness, selected_stem, manifest_path, selection_error = (
        _repoground_selected_manifest_for_repo(repo, stem)
    )
    if selection_error is not None:
        return {
            "kind": "grabowski.repoground_query",
            "schema_version": 1,
            "repo": repo,
            "task_profile": task_profile,
            "stem": selected_stem,
            "query": query,
            "k": k,
            "available": False,
            "freshness": freshness,
            "reason": selection_error.get("reason"),
            "bundle_repo": selection_error.get("bundle_repo"),
            "query_shape": "unavailable",
            "normalized_query_shape": "unavailable",
            "hit_count": 0,
            "snippets": [],
            "ranges": [],
            "raw_results_included": False,
            "does_not_establish": [
                "actual_agent_reading",
                "answer_correct",
                "repo_understood",
                "claims_true",
                "runtime_correctness",
            ],
        }
    assert isinstance(manifest_path, Path)
    assert isinstance(selected_stem, str)
    repoground_result = _repoground_query_existing_index(
        manifest_path,
        query,
        k=k,
        filters=filters or {},
        resolve_evidence=True,
        project_sources=True,
    )
    snippets = _repoground_query_snippets(repoground_result, max_snippets=max_snippets)
    query_result = (
        repoground_result.get("query_result")
        if isinstance(repoground_result, dict)
        else None
    )
    result_count = None
    if isinstance(query_result, dict):
        if isinstance(query_result.get("count"), int):
            result_count = query_result.get("count")
        elif isinstance(query_result.get("results"), list):
            result_count = len(query_result["results"])
    available = repoground_result.get("status") == "available"
    return {
        "kind": "grabowski.repoground_query",
        "schema_version": 1,
        "repo": repo,
        "task_profile": task_profile,
        "stem": selected_stem,
        "query": query,
        "k": k,
        "filters": filters or {},
        "available": available,
        "status": repoground_result.get("status", "unknown"),
        "freshness": freshness,
        "query_shape": snippets["source_shape"],
        "normalized_query_shape": snippets["source_shape"],
        "hit_count": snippets["hit_count"],
        "result_count": result_count,
        "snippets": snippets["snippets"],
        "ranges": snippets["ranges"],
        "repoground_status": {
            "kind": repoground_result.get("kind"),
            "status": repoground_result.get("status"),
            "error_code": repoground_result.get("error_code"),
            "reason": repoground_result.get("reason"),
            "returncode": repoground_result.get("returncode"),
        },
        "mutation_boundary": repoground_result.get("mutation_boundary")
        or {"writes": [], "read_paths_do_not_refresh": True},
        "evidence_resolution_used": repoground_result.get("evidence_resolution_used"),
        "raw_results_included": False,
        "does_not_establish": [
            "actual_agent_reading",
            "answer_correct",
            "repo_understood",
            "claims_true",
            "test_sufficiency",
            "review_complete",
            "runtime_correctness",
        ],
    }


@mcp.tool(name="repoground_query_existing_index", annotations=READ_ANNOTATIONS)
def repoground_query_existing_index(
    repo: str,
    query: str,
    k: int = 5,
    stem: str | None = None,
    filters: dict[str, Any] | None = None,
    resolve_evidence: bool = True,
    project_sources: bool = True,
) -> dict[str, Any]:
    """Query a prebuilt RepoGround index without refreshing the bundle."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    if not isinstance(query, str) or not query.strip() or len(query) > 500:
        raise ValueError("query must be a non-empty string up to 500 characters")
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= 100:
        raise ValueError("k must be an integer between 1 and 100")
    if filters is not None and not isinstance(filters, dict):
        raise ValueError("filters must be an object when provided")
    if not isinstance(resolve_evidence, bool):
        raise ValueError("resolve_evidence must be a boolean")
    if not isinstance(project_sources, bool):
        raise ValueError("project_sources must be a boolean")

    freshness, selected_stem, manifest_path, selection_error = (
        _repoground_selected_manifest_for_repo(repo, stem)
    )
    if selection_error is not None:
        return {
            "kind": "grabowski.repoground_query_existing_index",
            "schema_version": 1,
            "repo": repo,
            "stem": selected_stem,
            "query": query,
            "k": k,
            "available": False,
            "freshness": freshness,
            "reason": selection_error.get("reason"),
            "bundle_repo": selection_error.get("bundle_repo"),
            "query_shape": "unavailable",
            "normalized_query_shape": "unavailable",
            "hit_count": 0,
            "snippets": [],
            "ranges": [],
            "raw_results_included": False,
            "resolve_evidence": resolve_evidence,
            "project_sources": project_sources,
            "does_not_establish": [
                "actual_agent_reading",
                "answer_correct",
                "repo_understood",
                "claims_true",
                "runtime_correctness",
            ],
        }
    assert isinstance(manifest_path, Path)
    assert isinstance(selected_stem, str)
    repoground_result = _repoground_query_existing_index(
        manifest_path,
        query,
        k=k,
        filters=filters or {},
        resolve_evidence=resolve_evidence,
        project_sources=project_sources,
    )
    snippets = _repoground_query_snippets(repoground_result, max_snippets=k)
    query_result = (
        repoground_result.get("query_result")
        if isinstance(repoground_result, dict)
        else None
    )
    result_count = None
    if isinstance(query_result, dict):
        if isinstance(query_result.get("count"), int):
            result_count = query_result.get("count")
        elif isinstance(query_result.get("results"), list):
            result_count = len(query_result["results"])
    available = repoground_result.get("status") == "available"
    return {
        "kind": "grabowski.repoground_query_existing_index",
        "schema_version": 1,
        "repo": repo,
        "stem": selected_stem,
        "query": query,
        "k": k,
        "filters": filters or {},
        "available": available,
        "status": repoground_result.get("status", "unknown"),
        "freshness": freshness,
        "query_shape": snippets["source_shape"],
        "normalized_query_shape": snippets["source_shape"],
        "hit_count": snippets["hit_count"],
        "result_count": result_count,
        "snippets": snippets["snippets"],
        "ranges": snippets["ranges"],
        "repoground_status": {
            "kind": repoground_result.get("kind"),
            "status": repoground_result.get("status"),
            "error_code": repoground_result.get("error_code"),
            "reason": repoground_result.get("reason"),
            "returncode": repoground_result.get("returncode"),
        },
        "mutation_boundary": repoground_result.get("mutation_boundary")
        or {"writes": [], "read_paths_do_not_refresh": True},
        "evidence_resolution_used": repoground_result.get("evidence_resolution_used"),
        "raw_results_included": False,
        "resolve_evidence": resolve_evidence,
        "project_sources": project_sources,
        "does_not_establish": [
            "actual_agent_reading",
            "answer_correct",
            "repo_understood",
            "claims_true",
            "test_sufficiency",
            "review_complete",
            "runtime_correctness",
        ],
    }


@mcp.tool(name="repoground_range_get", annotations=READ_ANNOTATIONS)
def repoground_range_get(
    repo: str,
    range_ref: dict[str, Any],
    stem: str | None = None,
) -> dict[str, Any]:
    """Resolve one bounded RepoGround range reference without live workspace reads."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    if not isinstance(range_ref, dict):
        raise ValueError("range_ref must be an object")
    freshness, selected_stem, manifest_path, selection_error = (
        _repoground_selected_manifest_for_repo(repo, stem)
    )
    if selection_error is not None:
        return {
            "kind": "grabowski.repoground_range_get",
            "schema_version": 1,
            "repo": repo,
            "stem": selected_stem,
            "available": False,
            "freshness": freshness,
            "reason": selection_error.get("reason"),
            "bundle_repo": selection_error.get("bundle_repo"),
            "range_ref": range_ref,
            "range": None,
            "does_not_establish": [
                "answer_correct",
                "repo_understood",
                "claims_true",
                "runtime_correctness",
            ],
        }
    assert isinstance(manifest_path, Path)
    assert isinstance(selected_stem, str)
    repoground_result = _repoground_range_get(manifest_path, range_ref)
    range_value = (
        repoground_result.get("range") if isinstance(repoground_result, dict) else None
    )
    if (
        isinstance(range_value, dict)
        and isinstance(range_value.get("text"), str)
        and len(range_value["text"]) > 4000
    ):
        range_value = dict(range_value)
        range_value["text"] = range_value["text"][:4000]
        range_value["text_truncated"] = True
    return {
        "kind": "grabowski.repoground_range_get",
        "schema_version": 1,
        "repo": repo,
        "stem": selected_stem,
        "available": repoground_result.get("status") == "available",
        "status": repoground_result.get("status", "unknown"),
        "freshness": freshness,
        "range_ref": range_ref,
        "range": range_value,
        "repoground_status": {
            "kind": repoground_result.get("kind"),
            "status": repoground_result.get("status"),
            "error_code": repoground_result.get("error_code"),
            "reason": repoground_result.get("reason"),
            "returncode": repoground_result.get("returncode"),
        },
        "mutation_boundary": repoground_result.get("mutation_boundary")
        or {"writes": [], "read_paths_do_not_refresh": True},
        "does_not_establish": [
            "answer_correct",
            "repo_understood",
            "claims_true",
            "test_sufficiency",
            "review_complete",
            "runtime_correctness",
        ],
    }


@mcp.tool(name="repoground_context_pack", annotations=READ_ANNOTATIONS)
def repoground_context_pack(
    repo: str,
    task_profile: str = "basic_repo_question",
    stem: str | None = None,
    query: str | None = None,
    k: int = 5,
    max_snippets: int = 5,
) -> dict[str, Any]:
    """Build a bounded RepoGround context pack for agent handoff and Bureau receipts."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    task_profile = _repoground_validate_task_profile(task_profile)
    if query is not None and not isinstance(query, str):
        raise ValueError("query must be a string when supplied")
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= 100:
        raise ValueError("k must be an integer between 1 and 100")
    freshness, selected_stem, manifest_path, selection_error = (
        _repoground_selected_manifest_for_repo(repo, stem)
    )
    if selection_error is not None:
        return {
            "kind": "grabowski.repoground_context_pack",
            "schema_version": 1,
            "repo": repo,
            "task_profile": task_profile,
            "stem": selected_stem,
            "available": False,
            "freshness": freshness,
            "reason": selection_error.get("reason"),
            "bundle_repo": selection_error.get("bundle_repo"),
            "bounded_evidence": {
                "query": query,
                "normalized_query_shape": "unavailable",
                "hit_count": 0,
                "snippets": [],
                "ranges": [],
            },
            "does_not_establish": [
                "actual_agent_reading",
                "repo_understood",
                "claims_true",
                "runtime_correctness",
            ],
        }
    assert isinstance(manifest_path, Path)
    assert isinstance(selected_stem, str)
    status = repoground_bundle_status(selected_stem)
    manifest_sha = (
        _repoground_file_sha256(manifest_path) if manifest_path.is_file() else None
    )
    preflight = _repoground_agent_preflight(task_profile, manifest_path)
    preflight_status = (
        preflight.get("status")
        if isinstance(preflight.get("status"), str)
        else "unknown"
    )
    generated_at = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    live = (
        freshness.get("live_repo")
        if isinstance(freshness.get("live_repo"), dict)
        else {}
    )
    bundle = (
        freshness.get("bundle") if isinstance(freshness.get("bundle"), dict) else {}
    )

    if query:
        query_context = repoground_query(
            repo,
            query,
            task_profile=task_profile,
            stem=selected_stem,
            k=k,
            max_snippets=max_snippets,
        )
    else:
        query_context = {
            "available": False,
            "status": "skipped",
            "reason": "query_not_provided",
            "query_shape": "query_not_requested",
            "normalized_query_shape": "query_not_requested",
            "hit_count": 0,
            "result_count": None,
            "snippets": [],
            "ranges": [],
            "raw_results_included": False,
        }
    snippets = _repoground_list_of_dicts(query_context.get("snippets"))
    ranges = _repoground_list_of_dicts(query_context.get("ranges"))
    evidence_status, evidence_reason = _repoground_context_evidence_status(
        query, query_context, snippets, ranges
    )
    citation_ids = _repoground_context_citation_ids(snippets)
    bounded_evidence = {
        "query": query,
        "k": k if query else None,
        "normalized_query_shape": query_context.get("normalized_query_shape")
        or query_context.get("query_shape"),
        "resolved_evidence_status": evidence_status,
        "degradation_reason": evidence_reason,
        "hit_count": query_context.get("hit_count", 0),
        "result_count": query_context.get("result_count"),
        "snippet_count": len(snippets),
        "range_count": len(ranges),
        "citation_count": len(citation_ids),
        "citation_ids": citation_ids,
        "snippets": snippets,
        "ranges": ranges,
        "query_status": query_context.get("status"),
        "query_available": query_context.get("available", False),
    }
    context_ref = {
        "schema_version": 1,
        "repo": repo,
        "stem": selected_stem,
        "manifest_sha256": manifest_sha,
        "bundle_commit": bundle.get("git_commit"),
        "live_commit_at_claim": live.get("head"),
        "freshness_status": freshness.get(
            "freshness_status", freshness.get("freshness", "unknown")
        ),
        "task_profile": task_profile,
        "preflight_status": preflight_status,
        "query_shape": bounded_evidence["normalized_query_shape"],
        "snippet_count": len(snippets),
        "range_count": len(ranges),
        "citation_count": len(citation_ids),
        "resolved_evidence_status": evidence_status,
        "source": "grabowski.repoground_context_pack",
        "generated_at": generated_at,
        "does_not_establish": [
            "actual_agent_reading",
            "answer_correct",
            "repo_understood",
            "claims_true",
            "review_complete",
            "runtime_correctness",
        ],
    }
    return {
        "kind": "grabowski.repoground_context_pack",
        "schema_version": 1,
        "repo": repo,
        "task_profile": task_profile,
        "stem": selected_stem,
        "available": True,
        "context_ref": context_ref,
        "freshness": freshness,
        "bundle_status": {
            "exists": status.get("exists"),
            "artifact_count": status.get("artifact_count"),
            "artifact_roles": status.get("artifact_roles"),
            "post_emit_health": status.get("post_emit_health"),
            "bundle_surface_validation": status.get("bundle_surface_validation"),
            "output_health": status.get("output_health"),
        },
        "preflight": {
            "available": preflight.get("available", False),
            "status": preflight_status,
            "required_reading": preflight.get("required_reading"),
            "answer_compliance_template": preflight.get("answer_compliance_template"),
            "does_not_establish": preflight.get("does_not_establish"),
            "error_reason": preflight.get("reason"),
        },
        "query_context": {
            "available": query_context.get("available", False),
            "status": query_context.get("status"),
            "reason": query_context.get("reason"),
            "query": query,
            "query_shape": query_context.get("query_shape"),
            "hit_count": query_context.get("hit_count", 0),
            "result_count": query_context.get("result_count"),
            "repoground_status": query_context.get("repoground_status"),
            "raw_results_included": False,
        },
        "bounded_evidence": bounded_evidence,
        "snippets": snippets,
        "ranges": ranges,
        "access_wrappers": {
            "preflight": "repoground_preflight",
            "query": "repoground_query_existing_index",
            "range": "repoground_range_get",
            "context_pack": "repoground_context_pack",
            "raw_canonical_dump_included": False,
        },
        "agent_handoff": {
            "default_surface": "bounded_context_pack",
            "raw_canonical_dump_included": False,
            "requires_answer_compliance": preflight_status in {"pass", "warn"},
            "recommended_next_step": "Use required_reading, snippets/ranges, and answer_compliance_template; cite returned ranges instead of raw dumps.",
        },
        "does_not_establish": [
            "actual_agent_reading",
            "answer_correct",
            "repo_understood",
            "claims_true",
            "test_sufficiency",
            "review_complete",
            "runtime_correctness",
        ],
    }


_REPOGROUND_REVISION_RE = re.compile(r"[A-Za-z0-9_./@{}^~:+-]{1,200}\Z")
_REPOGROUND_SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")


def _repoground_validate_revision(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("-")
        or not _REPOGROUND_REVISION_RE.fullmatch(value)
    ):
        raise ValueError(f"{label} must be a bounded Git revision")
    return value


def _repoground_working_repo(repo: str) -> Path:
    root = (HOME / "repos").resolve(strict=False)
    candidate = root / repo
    resolved = candidate.resolve(strict=False)
    if (
        resolved == root
        or root not in resolved.parents
        or not candidate.is_dir()
        or candidate.is_symlink()
    ):
        raise ValueError("repository checkout is missing or invalid")
    return candidate


def _repoground_resolve_commit(repo_path: Path, revision: str) -> str:
    rc, out, _err = _repoground_git(repo_path, ["rev-parse", "--verify", f"{revision}^{{commit}}"])
    if rc != 0 or not re.fullmatch(r"[a-f0-9]{40}", out):
        raise ValueError(f"Git revision could not be resolved: {revision}")
    return out


def _repoground_revision_changes(
    repo_path: Path, base_commit: str, target_commit: str
) -> tuple[list[dict[str, Any]], str]:
    rc, names, err = _repoground_git(
        repo_path,
        ["diff", "--name-status", "--find-renames", "--no-ext-diff", base_commit, target_commit, "--"],
    )
    if rc != 0:
        raise ValueError(f"Git diff name-status failed: {err or rc}")
    changes: list[dict[str, Any]] = []
    for raw in names.splitlines():
        parts = raw.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0]
        if status.startswith(("R", "C")) and len(parts) >= 3:
            changes.append({"status": status, "previous_path": parts[1], "path": parts[2]})
        else:
            changes.append({"status": status, "path": parts[1]})
    changes.sort(key=lambda item: (str(item.get("path")), str(item.get("previous_path", ""))))
    rc, raw_delta, err = _repoground_git(
        repo_path,
        ["diff", "--raw", "--full-index", "--no-abbrev", "--no-ext-diff", base_commit, target_commit, "--"],
    )
    if rc != 0:
        raise ValueError(f"Git diff identity failed: {err or rc}")
    identity = json.dumps(
        {
            "schema_version": 1,
            "base_commit": base_commit,
            "target_commit": target_commit,
            "name_status": names,
            "raw_tree_delta": raw_delta,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return changes, hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _repoground_dirty_overlay(repo_path: Path) -> dict[str, Any]:
    rc, status, err = _repoground_git(repo_path, ["status", "--porcelain=v1", "--untracked-files=normal"])
    entries = [line for line in status.splitlines() if line]
    return {
        "available": rc == 0,
        "dirty": bool(entries) if rc == 0 else None,
        "entry_count": len(entries) if rc == 0 else None,
        "status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest() if rc == 0 else None,
        "included_in_revision_diff": False,
        "error": err or None if rc != 0 else None,
    }


def _repoground_agent_impact_context(
    manifest_path: Path, *, changed_paths: list[str], max_items: int
) -> dict[str, Any]:
    return _repoground_core_json(
        "agent_impact_context",
        manifest_path,
        {
            "changed_paths": changed_paths,
            "mode": "impact",
            "max_items": max_items,
            "include_query_context": True,
        },
    )


def _repoground_manifest_surface_metadata(manifest_path: Path) -> dict[str, dict[str, Any]]:
    manifest = _repoground_json(manifest_path)
    roles = {
        "agent_entry_manifest",
        "pr_delta_cards_jsonl",
        "citation_map_jsonl",
        "python_symbol_index_json",
        "python_call_graph_json",
        "architecture_graph_json",
        "relation_cards_jsonl",
    }
    result: dict[str, dict[str, Any]] = {}
    for artifact in manifest.get("artifacts", []):
        if not isinstance(artifact, dict) or artifact.get("role") not in roles:
            continue
        role = str(artifact["role"])
        result[role] = {
            key: artifact.get(key)
            for key in ("role", "path", "bytes", "sha256", "contract", "authority", "risk_class")
            if artifact.get(key) is not None
        }
    return dict(sorted(result.items()))


def _repoground_authority_rules(preflight: dict[str, Any]) -> list[dict[str, Any]]:
    required_reading = preflight.get("required_reading")
    if isinstance(required_reading, list):
        return [item for item in required_reading if isinstance(item, dict)]
    if not isinstance(required_reading, dict):
        return []
    rules: list[dict[str, Any]] = []
    for group, priority in (
        ("missing_required", 400),
        ("required", 300),
        ("missing_recommended", 200),
        ("recommended", 100),
    ):
        roles = required_reading.get(group)
        if not isinstance(roles, list):
            continue
        for role in roles:
            if isinstance(role, str) and role:
                rules.append(
                    {
                        "artifact_role": role,
                        "requirement": group,
                        "authority": "required_reading_protocol",
                        "priority": priority,
                    }
                )
    rules.sort(key=lambda item: (-int(item["priority"]), str(item["artifact_role"])))
    return rules


def _repoground_gate_evidence(
    preflight: dict[str, Any], bundle_status: dict[str, Any]
) -> list[dict[str, Any]]:
    gates = [
        {
            "gate": "agent_consumption_preflight",
            "status": preflight.get("status", "unknown"),
            "authority": "repoground_preflight",
        }
    ]
    for key in ("post_emit_health", "bundle_surface_validation", "output_health"):
        value = bundle_status.get(key)
        if isinstance(value, dict):
            gates.append(
                {
                    "gate": key,
                    "status": value.get("status", value.get("verdict", "unknown")),
                    "authority": "bundle_status",
                }
            )
    return gates


def _repoground_json_bytes(value: Any) -> int:
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


_REPOGROUND_CONTEXT_LANE_CONFIG: dict[str, dict[str, int]] = {
    "direct_changes": {"priority": 100, "max_items": 16, "min_items": 1},
    "related_tests": {"priority": 95, "max_items": 8, "min_items": 1},
    "gate_evidence": {"priority": 90, "max_items": 6, "min_items": 1},
    "authority_ordered_rules": {"priority": 85, "max_items": 8, "min_items": 1},
    "target_symbols": {"priority": 80, "max_items": 8, "min_items": 1},
    "causal_relations": {"priority": 75, "max_items": 8, "min_items": 1},
    "recommended_first_reads": {"priority": 70, "max_items": 5, "min_items": 1},
    "supporting_context": {"priority": 65, "max_items": 5, "min_items": 1},
    "entrypoints": {"priority": 60, "max_items": 5, "min_items": 0},
    "live_ranges": {"priority": 55, "max_items": 5, "min_items": 1},
    "source_ranges": {"priority": 50, "max_items": 5, "min_items": 0},
    "citations": {"priority": 45, "max_items": 5, "min_items": 0},
    "entry_manifest": {"priority": 40, "max_items": 1, "min_items": 0},
    "pr_delta_cards": {"priority": 35, "max_items": 1, "min_items": 0},
    "gaps": {"priority": 30, "max_items": 8, "min_items": 1},
    "query_snippets": {"priority": 20, "max_items": 5, "min_items": 0},
}


def _repoground_dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _repoground_context_lane_policy(
    lane_values: dict[str, list[Any]],
) -> tuple[
    list[tuple[str, list[Any]]],
    dict[str, int],
    dict[str, int],
    dict[str, int],
]:
    configured = set(_REPOGROUND_CONTEXT_LANE_CONFIG)
    supplied = set(lane_values)
    if supplied != configured:
        missing = sorted(configured - supplied)
        unknown = sorted(supplied - configured)
        raise RuntimeError(
            "RepoGround context lane configuration mismatch: "
            f"missing={missing}, unknown={unknown}"
        )
    lane_order = sorted(
        _REPOGROUND_CONTEXT_LANE_CONFIG,
        key=lambda name: (-_REPOGROUND_CONTEXT_LANE_CONFIG[name]["priority"], name),
    )
    lanes = [(name, lane_values[name]) for name in lane_order]
    limits = {
        name: _REPOGROUND_CONTEXT_LANE_CONFIG[name]["max_items"] for name in lane_order
    }
    minimums = {
        name: _REPOGROUND_CONTEXT_LANE_CONFIG[name]["min_items"] for name in lane_order
    }
    priorities = {
        name: _REPOGROUND_CONTEXT_LANE_CONFIG[name]["priority"] for name in lane_order
    }
    return lanes, limits, minimums, priorities


def _repoground_budget_context(
    lanes: list[tuple[str, list[Any]]],
    limit: int,
    *,
    lane_item_limits: dict[str, int] | None = None,
    lane_min_items: dict[str, int] | None = None,
) -> tuple[dict[str, list[Any]], dict[str, dict[str, int]], int]:
    context: dict[str, list[Any]] = {}
    counts: dict[str, dict[str, int]] = {}
    limits = lane_item_limits or {}
    minimums = lane_min_items or {}
    considered_by_lane: dict[str, list[Any]] = {}
    for name, items in lanes:
        item_limit = limits.get(name)
        minimum = minimums.get(name, 0)
        if isinstance(item_limit, bool) or (
            isinstance(item_limit, int) and item_limit < 0
        ):
            raise ValueError(
                f"lane item limit for {name!r} must be a non-negative integer"
            )
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
            raise ValueError(
                f"lane minimum for {name!r} must be a non-negative integer"
            )
        considered = items[:item_limit] if isinstance(item_limit, int) else items
        considered_by_lane[name] = considered
        counts[name] = {
            "available": len(items),
            "considered": len(considered),
            "included": 0,
            "policy_omitted": len(items) - len(considered),
            "budget_omitted": len(considered),
        }

    used_bytes = _repoground_json_bytes(context)

    def append_if_fits(name: str, item: Any) -> bool:
        nonlocal used_bytes
        item_bytes = _repoground_json_bytes(item)
        if name in context:
            delta = item_bytes + (1 if context[name] else 0)
        else:
            delta = (
                (1 if context else 0)
                + _repoground_json_bytes(name)
                + 3
                + item_bytes
            )
        if used_bytes + delta > limit:
            return False
        context.setdefault(name, []).append(item)
        used_bytes += delta
        counts[name]["included"] += 1
        counts[name]["budget_omitted"] -= 1
        return True

    # Only lanes with an explicit minimum receive guaranteed coverage attempts. This
    # protects semantic essentials without letting low-priority metadata invert the
    # priority order merely because it happens to be non-empty.
    for name, _items in lanes:
        considered = considered_by_lane[name]
        minimum = min(minimums.get(name, 0), len(considered))
        for item in considered[:minimum]:
            if not append_if_fits(name, item):
                break

    # Spend the remaining budget in deterministic priority order. Within each lane we
    # retain prefix semantics: once the next item does not fit, later items are skipped.
    for name, _items in lanes:
        considered = considered_by_lane[name]
        included = counts[name]["included"]
        for item in considered[included:]:
            if not append_if_fits(name, item):
                break

    # Preserve the previous best-effort output shape for empty or excluded lanes, but
    # only after useful evidence has had a chance to consume the budget.
    for name, _items in lanes:
        if name in context:
            continue
        delta = (1 if context else 0) + _repoground_json_bytes(name) + 3
        if used_bytes + delta <= limit:
            context[name] = []
            used_bytes += delta

    exact_used_bytes = _repoground_json_bytes(context)
    if exact_used_bytes != used_bytes:
        raise RuntimeError(
            "RepoGround context byte accounting mismatch: "
            f"incremental={used_bytes}, exact={exact_used_bytes}"
        )
    return context, counts, exact_used_bytes


def _repoground_evidence_uses_coherent_source(value: Any, source: str) -> bool:
    if isinstance(value, dict):
        if value.get("source") == source and value.get("status") == "coherent":
            return True
        return any(
            _repoground_evidence_uses_coherent_source(item, source)
            for item in value.values()
        )
    if isinstance(value, list):
        return any(
            _repoground_evidence_uses_coherent_source(item, source) for item in value
        )
    return False


@mcp.tool(name="repoground_context_compose", annotations=READ_ANNOTATIONS)
def repoground_context_compose(
    repo: str,
    base_revision: str,
    target_revision: str,
    task_profile: str = "change_impact",
    context_budget_bytes: int = 12000,
    expected_diff_sha256: str | None = None,
    stem: str | None = None,
    query: str | None = None,
) -> dict[str, Any]:
    """Compose deterministic, diff-bound RepoGround change context under a hard payload budget."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    task_profile = _repoground_validate_task_profile(task_profile)
    base_revision = _repoground_validate_revision(base_revision, label="base_revision")
    target_revision = _repoground_validate_revision(target_revision, label="target_revision")
    if not isinstance(context_budget_bytes, int) or isinstance(context_budget_bytes, bool) or not 512 <= context_budget_bytes <= 100_000:
        raise ValueError("context_budget_bytes must be an integer between 512 and 100000")
    if expected_diff_sha256 is not None and (
        not isinstance(expected_diff_sha256, str)
        or not _REPOGROUND_SHA256_RE.fullmatch(expected_diff_sha256)
    ):
        raise ValueError("expected_diff_sha256 must be a lowercase SHA-256 hex digest")
    if query is not None and (not isinstance(query, str) or not query.strip() or len(query) > 500):
        raise ValueError("query must be a non-empty string up to 500 characters when provided")

    repo_path = _repoground_working_repo(repo)
    base_commit = _repoground_resolve_commit(repo_path, base_revision)
    target_commit = _repoground_resolve_commit(repo_path, target_revision)
    changes, diff_sha256 = _repoground_revision_changes(repo_path, base_commit, target_commit)
    dirty_overlay = _repoground_dirty_overlay(repo_path)
    change_identity = {
        "repo": repo,
        "base_revision": base_revision,
        "target_revision": target_revision,
        "base_commit": base_commit,
        "target_commit": target_commit,
        "diff_sha256": diff_sha256,
        "diff_binding_kind": "git_tree_delta_v1",
        "expected_diff_sha256": expected_diff_sha256,
        "diff_binding_verified": expected_diff_sha256 is None or expected_diff_sha256 == diff_sha256,
        "changed_path_count": len(changes),
    }
    blocked_context, blocked_lane_counts, blocked_used_bytes = _repoground_budget_context(
        [("direct_changes", changes)], context_budget_bytes
    )
    if expected_diff_sha256 is not None and expected_diff_sha256 != diff_sha256:
        return {
            "kind": "grabowski.repoground_context_compose",
            "schema_version": 1,
            "available": False,
            "status": "blocked",
            "reason": "diff_sha256_mismatch",
            "change_identity": change_identity,
            "dirty_overlay": dirty_overlay,
            "context": blocked_context,
            "context_budget": {
                "requested_bytes": context_budget_bytes,
                "effective_limit_bytes": context_budget_bytes,
                "used_bytes": blocked_used_bytes,
                "remaining_bytes": max(0, context_budget_bytes - blocked_used_bytes),
                "hard_limit_applies_to": "context",
                "lane_counts": blocked_lane_counts,
            },
            "retrieval_lanes": {"used": ["direct_changes"], "skipped": ["agent_impact", "query_context", "entry_manifest", "pr_delta_cards", "symbol_navigation", "call_graph", "citation", "live_evidence"]},
            "stop_criteria": {"triggered": ["diff_sha256_mismatch"], "available": ["publication_unavailable", "impact_context_blocked", "budget_exhausted"]},
            "does_not_establish": ["truth", "completeness", "patch_correctness", "test_sufficiency", "merge_readiness", "runtime_behavior"],
        }

    freshness, selected_stem, manifest_path, selection_error = _repoground_selected_manifest_for_repo(repo, stem)
    if selection_error is not None or manifest_path is None:
        return {
            "kind": "grabowski.repoground_context_compose",
            "schema_version": 1,
            "available": False,
            "status": "unavailable",
            "reason": (selection_error or {}).get("reason", "publication_unavailable"),
            "change_identity": change_identity,
            "dirty_overlay": dirty_overlay,
            "context": blocked_context,
            "context_budget": {
                "requested_bytes": context_budget_bytes,
                "effective_limit_bytes": context_budget_bytes,
                "used_bytes": blocked_used_bytes,
                "remaining_bytes": max(0, context_budget_bytes - blocked_used_bytes),
                "hard_limit_applies_to": "context",
                "lane_counts": blocked_lane_counts,
            },
            "retrieval_lanes": {"used": ["direct_changes"], "skipped": ["agent_impact", "query_context", "entry_manifest", "pr_delta_cards", "symbol_navigation", "call_graph", "citation", "live_evidence"]},
            "stop_criteria": {"triggered": ["publication_unavailable"], "available": ["diff_sha256_mismatch", "impact_context_blocked", "budget_exhausted"]},
            "does_not_establish": ["truth", "completeness", "patch_correctness", "test_sufficiency", "merge_readiness", "runtime_behavior"],
        }

    changed_paths = [str(item["path"]) for item in changes]
    effective_query = query.strip() if isinstance(query, str) else " ".join(changed_paths[:8]) or None
    baseline = repoground_context_pack(
        repo,
        task_profile=task_profile,
        stem=selected_stem,
        query=effective_query,
        k=min(max(len(changed_paths), 1), 10),
        max_snippets=_REPOGROUND_CONTEXT_LANE_CONFIG["query_snippets"]["max_items"],
    )
    baseline_bytes = _repoground_json_bytes(baseline)
    compact_target_bytes = max(1, (baseline_bytes * 2) // 3)
    effective_limit = min(context_budget_bytes, compact_target_bytes)
    impact = _repoground_agent_impact_context(
        manifest_path,
        changed_paths=changed_paths,
        max_items=min(max(len(changed_paths) * 4, 8), 50),
    ) if changed_paths else {"status": "skipped", "gaps": []}
    surfaces = _repoground_manifest_surface_metadata(manifest_path)
    preflight = baseline.get("preflight") if isinstance(baseline.get("preflight"), dict) else {}
    bundle_status = baseline.get("bundle_status") if isinstance(baseline.get("bundle_status"), dict) else {}
    evidence = baseline.get("bounded_evidence") if isinstance(baseline.get("bounded_evidence"), dict) else {}
    authority_rules = _repoground_authority_rules(preflight)
    gate_evidence = _repoground_gate_evidence(preflight, bundle_status)
    impact_status = str(impact.get("status", "unknown"))
    source_statuses = _repoground_dict_items(impact.get("source_statuses")) if isinstance(impact, dict) else []
    symbol_available = any(item.get("source") == "python_symbol_index_json" and item.get("status") == "available" for item in source_statuses)
    causal_relations = _repoground_dict_items(impact.get("relations")) if isinstance(impact, dict) else []

    edit_context = impact.get("edit_context") if isinstance(impact, dict) and isinstance(impact.get("edit_context"), dict) else {}
    lane_values: dict[str, list[Any]] = {
        "direct_changes": changes,
        "related_tests": _repoground_dict_items(impact.get("related_tests")) if isinstance(impact, dict) else [],
        "gate_evidence": gate_evidence,
        "authority_ordered_rules": authority_rules,
        "entry_manifest": [surfaces["agent_entry_manifest"]] if "agent_entry_manifest" in surfaces else [],
        "pr_delta_cards": [surfaces["pr_delta_cards_jsonl"]] if "pr_delta_cards_jsonl" in surfaces else [],
        "target_symbols": _repoground_dict_items(impact.get("target_symbols")) if isinstance(impact, dict) else [],
        "causal_relations": causal_relations,
        "live_ranges": _repoground_dict_items(evidence.get("ranges")),
        "citations": [{"citation_id": item} for item in evidence.get("citation_ids", []) if isinstance(item, str)] if isinstance(evidence.get("citation_ids"), list) else [],
        "gaps": _repoground_dict_items(impact.get("gaps")) if isinstance(impact, dict) else [],
        "entrypoints": _repoground_dict_items(impact.get("entrypoints")) if isinstance(impact, dict) else [],
        "recommended_first_reads": _repoground_dict_items(edit_context.get("recommended_first_reads")),
        "supporting_context": _repoground_dict_items(impact.get("supporting_context")) if isinstance(impact, dict) else [],
        "source_ranges": _repoground_dict_items(impact.get("source_ranges")) if isinstance(impact, dict) else [],
        "query_snippets": _repoground_dict_items(evidence.get("snippets")),
    }
    lanes, lane_item_limits, lane_min_items, lane_priorities = _repoground_context_lane_policy(lane_values)
    context, lane_counts, used_bytes = _repoground_budget_context(
        lanes,
        effective_limit,
        lane_item_limits=lane_item_limits,
        lane_min_items=lane_min_items,
    )
    used = ["direct_changes"]
    if impact_status not in {"skipped", "unavailable", "unknown"}:
        used.append("agent_impact")
    if effective_query and baseline.get("available"):
        used.append("query_context")
    if symbol_available:
        used.append("symbol_navigation")
    call_graph_used = _repoground_evidence_uses_coherent_source(
        context.get("causal_relations", []), "python_call_graph_json"
    )
    if call_graph_used:
        used.append("call_graph")
    if "citation_map_jsonl" in surfaces or context.get("citations"):
        used.append("citation")
    if context.get("live_ranges"):
        used.append("live_evidence")
    if "agent_entry_manifest" in surfaces:
        used.append("entry_manifest")
    if "pr_delta_cards_jsonl" in surfaces:
        used.append("pr_delta_cards")
    all_lanes = ["direct_changes", "agent_impact", "query_context", "entry_manifest", "pr_delta_cards", "symbol_navigation", "call_graph", "citation", "live_evidence"]
    skipped = [name for name in all_lanes if name not in used]
    triggered: list[str] = []
    if impact_status == "blocked":
        triggered.append("impact_context_blocked")
    budget_exhausted_lanes = [
        name for name, value in lane_counts.items() if value["budget_omitted"] > 0
    ]
    policy_limited_lanes = [
        name for name, value in lane_counts.items() if value["policy_omitted"] > 0
    ]
    if budget_exhausted_lanes:
        triggered.append("budget_exhausted")
    return {
        "kind": "grabowski.repoground_context_compose",
        "schema_version": 1,
        "available": True,
        "status": "available" if not triggered else "degraded",
        "repo": repo,
        "task_profile": task_profile,
        "stem": selected_stem,
        "change_identity": change_identity,
        "dirty_overlay": dirty_overlay,
        "freshness": freshness,
        "context_budget": {
            "requested_bytes": context_budget_bytes,
            "effective_limit_bytes": effective_limit,
            "used_bytes": used_bytes,
            "remaining_bytes": max(0, effective_limit - used_bytes),
            "hard_limit_applies_to": "context",
            "lane_counts": lane_counts,
        },
        "compactness": {
            "general_context_pack_bytes": baseline_bytes,
            "target_max_ratio": 0.666667,
            "target_max_bytes": compact_target_bytes,
            "composed_context_bytes": used_bytes,
            "smaller_than_general_context_pack": used_bytes < baseline_bytes,
            "ratio": round(used_bytes / baseline_bytes, 6) if baseline_bytes else None,
        },
        "sampling_policy": {
            "kind": "deterministic_priority_lane_caps_v2",
            "allocation_strategy": "minimum_coverage_then_priority_fill_v1",
            "lane_item_limits": lane_item_limits,
            "lane_min_items": lane_min_items,
            "lane_order_used": [name for name, _items in lanes],
            "effective_priorities": lane_priorities,
            "policy_limited_lanes": policy_limited_lanes,
            "budget_exhausted_lanes": budget_exhausted_lanes,
            "does_not_establish": ["complete_lane_coverage", "all_relevant_context_used"],
        },
        "context": context,
        "retrieval_lanes": {"used": used, "skipped": skipped},
        "source_surfaces": surfaces,
        "stop_criteria": {
            "triggered": triggered,
            "available": ["diff_sha256_mismatch", "publication_unavailable", "impact_context_blocked", "budget_exhausted"],
        },
        "does_not_establish": [
            "truth",
            "completeness",
            "patch_correctness",
            "test_sufficiency",
            "test_coverage",
            "review_completeness",
            "merge_readiness",
            "runtime_behavior",
            "regression_absence",
        ],
    }


def _repoground_validate_navigation_input(
    *,
    name: str,
    path: str | None,
    k: int,
) -> tuple[str, str | None, int]:
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name) > 500
        or "\x00" in name
    ):
        raise ValueError("name must be a bounded non-empty string")
    if path is not None:
        parts = path.split("/") if isinstance(path, str) else []
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 2048
            or "\x00" in path
            or "\\" in path
            or path.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError("path must be a normalized repository-relative POSIX path")
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= 200:
        raise ValueError("k must be an integer between 1 and 200")
    return name.strip(), path, k


def _repoground_navigation_unavailable(
    *,
    tool: str,
    repo: str,
    stem: str | None,
    freshness: dict[str, Any],
    selection_error: dict[str, Any],
) -> dict[str, Any]:
    return {
        "kind": f"grabowski.{tool}",
        "schema_version": 1,
        "repo": repo,
        "stem": stem,
        "available": False,
        "status": "unavailable",
        "freshness": freshness,
        "reason": selection_error.get("reason"),
        "bundle_repo": selection_error.get("bundle_repo"),
        "result": None,
        "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
        "does_not_establish": [
            "complete_call_graph",
            "runtime_reachability",
            "repo_understood",
            "claims_true",
            "runtime_correctness",
        ],
    }


def _repoground_navigation_response(
    *,
    tool: str,
    repo: str,
    stem: str,
    freshness: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    status = result.get("status", "unknown")
    return {
        "kind": f"grabowski.{tool}",
        "schema_version": 1,
        "repo": repo,
        "stem": stem,
        "available": status == "available",
        "status": status,
        "freshness": freshness,
        "result": result,
        "mutation_boundary": result.get("mutation_boundary")
        or {"writes": [], "read_paths_do_not_refresh": True},
        "does_not_establish": result.get("does_not_establish")
        or [
            "complete_call_graph",
            "runtime_reachability",
            "repo_understood",
            "claims_true",
            "runtime_correctness",
        ],
    }


@mcp.tool(name="repoground_find_symbol", annotations=READ_ANNOTATIONS)
def repoground_find_symbol(
    repo: str,
    name: str,
    stem: str | None = None,
    kind: str | None = None,
    path: str | None = None,
    k: int = 25,
) -> dict[str, Any]:
    """Find bounded Python symbol definitions in an existing RepoGround bundle."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    name, path, k = _repoground_validate_navigation_input(name=name, path=path, k=k)
    if kind is not None and kind not in {"class", "function", "async_function"}:
        raise ValueError("kind must be class, function, async_function, or null")
    freshness, selected_stem, manifest_path, selection_error = (
        _repoground_selected_manifest_for_repo(repo, stem)
    )
    if selection_error is not None:
        return _repoground_navigation_unavailable(
            tool="repoground_find_symbol",
            repo=repo,
            stem=selected_stem,
            freshness=freshness,
            selection_error=selection_error,
        )
    assert isinstance(manifest_path, Path)
    assert isinstance(selected_stem, str)
    result = _repoground_find_symbol(
        manifest_path,
        name=name,
        kind=kind,
        path=path,
        k=k,
    )
    return _repoground_navigation_response(
        tool="repoground_find_symbol",
        repo=repo,
        stem=selected_stem,
        freshness=freshness,
        result=result,
    )


@mcp.tool(name="repoground_get_callers", annotations=READ_ANNOTATIONS)
def repoground_get_callers(
    repo: str,
    name: str,
    stem: str | None = None,
    path: str | None = None,
    k: int = 25,
) -> dict[str, Any]:
    """Return S1 callers and separately visible unresolved references."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    name, path, k = _repoground_validate_navigation_input(name=name, path=path, k=k)
    freshness, selected_stem, manifest_path, selection_error = (
        _repoground_selected_manifest_for_repo(repo, stem)
    )
    if selection_error is not None:
        return _repoground_navigation_unavailable(
            tool="repoground_get_callers",
            repo=repo,
            stem=selected_stem,
            freshness=freshness,
            selection_error=selection_error,
        )
    assert isinstance(manifest_path, Path)
    assert isinstance(selected_stem, str)
    result = _repoground_get_callers(
        manifest_path,
        name=name,
        path=path,
        k=k,
    )
    return _repoground_navigation_response(
        tool="repoground_get_callers",
        repo=repo,
        stem=selected_stem,
        freshness=freshness,
        result=result,
    )


@mcp.tool(name="repoground_get_callees", annotations=READ_ANNOTATIONS)
def repoground_get_callees(
    repo: str,
    name: str,
    stem: str | None = None,
    path: str | None = None,
    k: int = 25,
) -> dict[str, Any]:
    """Return S1 callees while retaining S0 call sites separately."""
    _require_capability("bundle_registry")
    repo = _repoground_validate_repo(repo) or ""
    name, path, k = _repoground_validate_navigation_input(name=name, path=path, k=k)
    freshness, selected_stem, manifest_path, selection_error = (
        _repoground_selected_manifest_for_repo(repo, stem)
    )
    if selection_error is not None:
        return _repoground_navigation_unavailable(
            tool="repoground_get_callees",
            repo=repo,
            stem=selected_stem,
            freshness=freshness,
            selection_error=selection_error,
        )
    assert isinstance(manifest_path, Path)
    assert isinstance(selected_stem, str)
    result = _repoground_get_callees(
        manifest_path,
        name=name,
        path=path,
        k=k,
    )
    return _repoground_navigation_response(
        tool="repoground_get_callees",
        repo=repo,
        stem=selected_stem,
        freshness=freshness,
        result=result,
    )


@mcp.tool(name="grip_list", annotations=READ_ANNOTATIONS)
def grip_list(profile: str = "operator") -> dict[str, Any]:
    """Return the first-class allowed Grabowski grip surface."""
    _require_capability("file_read")
    result = grabowski_grips.grip_list(profile)
    result["session_profile"] = _session_profile_contract()
    return result


@mcp.tool(name="grip_run", annotations=CREATE_ANNOTATIONS)
def grip_run(
    name: str,
    parameters: dict[str, Any] | None = None,
    profile: str = "operator",
    allow_mutation: bool = False,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Run one allowlisted Grabowski grip and return its receipt-bound result."""
    _require_capability("terminal_execute")
    if allow_mutation:
        _require_mutations_enabled("terminal_execute")
    raw_parameters = parameters or {}
    reserved_server_parameters = sorted(
        {
            "_server_runtime_actor_identity",
            "_server_task_lease_delegation",
        }.intersection(raw_parameters)
    )
    if reserved_server_parameters:
        return grabowski_grips._blocked_surface_receipt(
            name,
            raw_parameters,
            "caller supplied reserved server parameter: "
            + ",".join(reserved_server_parameters),
        )
    decision = _session_grip_policy_decision(name, raw_parameters)
    if not decision["allowed"]:
        return grabowski_grips._blocked_surface_receipt(
            name,
            raw_parameters,
            f"session profile blocks grip: {decision}",
        )
    dispatch_parameters = dict(raw_parameters)
    dispatch_parameters.pop("session_escalation", None)
    if name == "captain-run":
        if ctx is None:
            return grabowski_grips._blocked_surface_receipt(
                name,
                raw_parameters,
                "server runtime actor identity is unavailable",
            )
        session_profile = decision.get("session_profile")
        actor_profile = (
            session_profile.get("profile")
            if isinstance(session_profile, dict)
            else _session_profile_contract()["profile"]
        )
        try:
            actor_identity = grabowski_merge_guard.issue_server_runtime_actor_identity(
                ctx.session,
                profile=str(actor_profile),
            )
            dispatch_parameters["_server_runtime_actor_identity"] = actor_identity
            execution_intent = dispatch_parameters.get("execution_intent")
            context = (
                execution_intent.get("context")
                if isinstance(execution_intent, dict)
                else None
            )
            requested_lease_owner = (
                context.get("lease_owner_id") if isinstance(context, dict) else None
            )
            if (
                isinstance(requested_lease_owner, str)
                and re.fullmatch(r"task:[0-9a-f]{24}", requested_lease_owner)
                is not None
            ):
                import grabowski_tasks

                task_evidence = grabowski_tasks.server_task_lease_delegation_evidence(
                    requested_lease_owner
                )
                dispatch_parameters["_server_task_lease_delegation"] = (
                    grabowski_merge_guard.issue_server_task_lease_delegation(
                        actor_identity,
                        task_evidence,
                        captain_request_sha256_value=(
                            grabowski_merge_guard.captain_request_sha256(
                                dispatch_parameters
                            )
                        ),
                    )
                )
        except (ImportError, RuntimeError, TypeError, ValueError) as exc:
            return grabowski_grips._blocked_surface_receipt(
                name,
                raw_parameters,
                f"server runtime lease identity failed: {type(exc).__name__}",
            )
    if name == "connector-snapshot-bind":
        deployment = _deployment_metadata()
        tool_contract = _runtime_tool_contract_summary(deployment)
        dispatch_parameters["_server_tool_contract"] = {
            "registered_tool_count": tool_contract.get("registered_tool_count"),
            "registered_names_sha256": tool_contract.get("registered_names_sha256"),
            "runtime_matches_deployment_contract": tool_contract.get(
                "runtime_matches_deployment_contract"
            ),
        }
        dispatch_parameters["_server_runtime"] = {
            "release_id": deployment.get("release_id"),
            "repo_head": deployment.get("repo_head"),
        }
        dispatch_parameters["_server_agent_instructions_sha256"] = (
            AGENT_INSTRUCTIONS_SHA256
        )
    return grabowski_grips.grip_run(
        name,
        dispatch_parameters,
        profile=profile,
        allow_mutation=allow_mutation,
    )


@mcp.tool(name="grabowski_task_archive_list", annotations=READ_ANNOTATIONS)
def grabowski_task_archive_list(
    limit: int = 20,
    cursor: str | None = None,
    view: str = "minimal",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List immutable task archive segments through a bounded verified catalog."""
    _require_capability("file_read")
    return lifecycle_read_surface.task_archive_list(
        limit=limit,
        cursor=cursor,
        view=view,
        fields=fields,
    )


@mcp.tool(name="grabowski_task_archive_read", annotations=READ_ANNOTATIONS)
def grabowski_task_archive_read(
    segment_id: str,
    limit: int = 20,
    cursor: str | None = None,
    view: str = "standard",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Read one fully verified immutable task archive segment with pagination."""
    _require_capability("file_read")
    return lifecycle_read_surface.task_archive_read(
        segment_id,
        limit=limit,
        cursor=cursor,
        view=view,
        fields=fields,
    )


@mcp.tool(name="latest_complete_bundles", annotations=READ_ANNOTATIONS)
def latest_complete_bundles() -> dict[str, Any]:
    """Return latest healthy RepoGround publications from one catalog resolution."""
    _require_capability("bundle_registry")
    rows: list[list[str]] = []
    sha256: str | None = None
    if BUNDLE_REGISTRY.is_file():
        data = _ensure_regular_text_file(BUNDLE_REGISTRY, 2_000_000)
        sha256 = hashlib.sha256(data).hexdigest()
        for line in data.decode("utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            rows.append(line.split("\t"))
    row_status = [_repoground_registry_row_status(row) for row in rows]
    stale_rows = [
        item
        for item in row_status
        if item.get("is_header") is not True and not item.get("valid")
    ]
    valid_registry_rows = [
        row
        for row, status in zip(rows, row_status)
        if status.get("is_header") is not True and status.get("valid") is True
    ]

    catalog_resolution = _repoground_catalog_resolution()
    selected_records = catalog_resolution.get("selected")
    if not isinstance(selected_records, list):
        selected_records = []
    aliases = catalog_resolution.get("aliases")
    if not isinstance(aliases, dict):
        aliases = {}
    canonical_catalog_present = any(bool(values) for values in aliases.values())
    selected_by_repo: dict[str, dict[str, Any]] = {}
    for item in selected_records:
        repo = item.get("repo")
        repo_id = item.get("repo_id")
        if not isinstance(repo, str):
            continue
        key = (
            str(repo_id)
            if len(aliases.get(repo, [])) > 1 and isinstance(repo_id, str)
            else repo
        )
        selected_by_repo[key] = item
    discovered_paths: list[Path] = []
    discovered: list[list[str]] = []
    discovery_needed = canonical_catalog_present or not rows or bool(stale_rows)
    if discovery_needed:
        for repo_key, item in sorted(selected_by_repo.items()):
            manifest_path = item.get("manifest_path")
            if not isinstance(manifest_path, str):
                continue
            path = Path(manifest_path)
            row = _repoground_manifest_registry_row(path)
            row[0] = repo_key
            discovered_paths.append(path)
            discovered.append(row)

    canonical_count = sum(
        item.get("authority") == "canonical_publication" for item in selected_records
    )
    legacy_count = sum(
        item.get("authority") == "legacy_merges_fallback" for item in selected_records
    )
    if canonical_catalog_present:
        effective_rows = discovered
        authority = (
            "canonical_live_discovery"
            if canonical_count
            else "canonical_publication_unavailable"
        )
    elif not rows:
        effective_rows = discovered
        authority = "live_discovery" if discovered else "publication_unavailable"
    elif stale_rows:
        registry_repos = {row[0] for row in valid_registry_rows if row}
        discovery_additions = [
            row for row in discovered if row and row[0] not in registry_repos
        ]
        effective_rows = [*valid_registry_rows, *discovery_additions]
        authority = (
            "merged_registry_live_discovery"
            if discovered
            else "registry_cache_valid_rows"
        )
    else:
        effective_rows = rows
        authority = "registry_cache"
    rejected = catalog_resolution.get("rejected")
    if not isinstance(rejected, list):
        rejected = []
    return {
        "path": str(BUNDLE_REGISTRY),
        "exists": BUNDLE_REGISTRY.is_file(),
        "sha256": sha256,
        "rows": effective_rows,
        "registry_rows": rows,
        "registry_row_status": row_status,
        "stale_registry_row_count": len(stale_rows),
        "live_discovery_used": discovery_needed,
        "live_discovery_row_count": len(discovered),
        "canonical_publication_row_count": canonical_count,
        "legacy_fallback_row_count": legacy_count,
        "selected_manifests": [
            repoground_catalog.public_candidate(item) for item in selected_records
        ],
        "rejected_candidate_count": len(rejected),
        "rejected_candidates": rejected,
        "catalog": {
            "canonical_root": str(REPOGROUND_PUBLICATION_ROOT),
            "legacy_root": str(MERGES_ROOT),
            "canonical_precedes_registry_and_legacy": True,
            "canonical_catalog_present": canonical_catalog_present,
            "aliases": aliases,
            "selection_reason": catalog_resolution.get("reason"),
        },
        "authority": authority,
        "does_not_establish": [
            "bundle_freshness_against_live_repo",
            "repo_understood",
            "claims_true",
            "runtime_correctness",
        ],
    }


if __name__ == "__main__":
    mcp.run()
