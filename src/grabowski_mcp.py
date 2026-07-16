#!/usr/bin/env python3
from __future__ import annotations

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
from mcp.types import ToolAnnotations

import grabowski_consumer_surface as consumer_surface
import grabowski_blockades as blockade_policy
import grabowski_blockade_store as blockade_store

import grabowski_grips

APP_NAME = "Grabowski"
DEPLOYMENT_MANIFEST_SCHEMA_VERSION = 5
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
AGENT_INSTRUCTIONS_SHA256 = hashlib.sha256(AGENT_INSTRUCTIONS.encode("utf-8")).hexdigest()


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
KILL_SWITCH_PATH = STATE_DIR / "operator-kill-switch"
BUNDLE_REGISTRY = STATE_DIR / "rlens-latest-complete-bundles.tsv"
MERGES_ROOT = HOME / "repos" / "merges"
AUDIT_SCHEMA_VERSION = 2
MAX_AUDIT_BYTES = 16 * 1024 * 1024
AUDIT_APPEND_LOCK = threading.RLock()
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
    'grabowski_status': (),
    'grabowski_context': (),
    'grip_list': ('file_read',),
    'grip_run': ('terminal_execute',),
    'grabowski_list_directory': ('file_read',),
    'grabowski_stat': ('file_read',),
    'grabowski_read_text': ('file_read',),
    'grabowski_secret_inspect': ('secret_inspect',),
    'grabowski_secret_reveal': ('secret_reveal',),
    'grabowski_secret_use': ('secret_use',),
    'grabowski_secret_export': ('secret_export',),
    'grabowski_browser_profile_read': ('browser_profile_read',),
    'grabowski_create_text': ('file_write',),
    'grabowski_replace_text': ('file_write',),
    'grabowski_remove_path': ('file_delete',),
    'grabowski_restore_removed_path': ('file_delete',),
    'grabowski_destroy_path': ('file_destroy',),
    'grabowski_rollback_text': ('rollback_text',),
    'grabowski_verify_audit': ('audit_verify',),
    'latest_complete_bundles': ('bundle_registry',),
    'rlens_bundle_discover': ('bundle_registry',),
    'rlens_bundle_status': ('bundle_registry',),
    'rlens_freshness_check': ('bundle_registry',),
    'rlens_preflight': ('bundle_registry',),
    'rlens_query': ('bundle_registry',),
    'rlens_query_existing_index': ('bundle_registry',),
    'rlens_range_get': ('bundle_registry',),
    'rlens_context_pack': ('bundle_registry',),
    'grabowski_runtime_health': (),
    'grabowski_deployment_identity': (),
    'grabowski_contract_drift': (),
    'grabowski_checkout_summary': (),
    'grabowski_git_status': (),
    'grabowski_git_diff': (),
    'grabowski_git_log': (),
    'grabowski_git_show': (),
    'grabowski_github_pr_view': ('github_cli',),
    'grabowski_github_checks': ('github_cli',),
    'grabowski_service_status': ('user_service_control',),
    'grabowski_service_logs': ('user_service_control',),
    'grabowski_runtime_deploy_schedule': ('durable_job', 'git_cli'),
    'grabowski_agent_workspace_create': ('durable_job', 'git_cli', 'resource_lease', 'tmux_interaction'),
    'grabowski_agent_workspace_status': ('durable_job', 'git_cli', 'tmux_interaction'),
    'grabowski_agent_workspace_attach': ('tmux_interaction',),
    'grabowski_agent_workspace_collect': ('durable_job', 'git_cli'),
    'grabowski_agent_workspace_role_retry': ('durable_job', 'git_cli'),
    'grabowski_agent_workspace_close': ('durable_job', 'resource_lease', 'tmux_interaction'),
    'grabowski_agent_workspace_observe': ('durable_job', 'git_cli'),
    'grabowski_agent_workspace_optimize': ('durable_job', 'git_cli'),
    'grabowski_agent_workspace_cleanup_plan': ('durable_job', 'git_cli', 'resource_lease', 'tmux_interaction'),
    'grabowski_agent_workspace_reconcile_stale': ('durable_job', 'git_cli', 'resource_lease', 'tmux_interaction'),
    'grabowski_agent_workspace_cleanup': ('git_cli', 'resource_lease'),
    'grabowski_agent_execution_route': (),
    'grabowski_agent_competition_start': ('durable_job', 'git_cli'),
    'grabowski_agent_competition_status': ('durable_job',),
    'grabowski_agent_competition_compare': ('durable_job',),
    'grabowski_terminal_run': ('terminal_execute',),
    'grabowski_job_start': ('durable_job',),
    'grabowski_job_status': ('durable_job',),
    'grabowski_job_notification_list': ('durable_job',),
    'grabowski_job_notification_ack': ('durable_job',),
    'grabowski_job_logs': ('durable_job',),
    'grabowski_job_cancel': ('durable_job',),
    'grabowski_git': ('git_cli',),
    'grabowski_git_branch': ('git_cli',),
    'grabowski_checkout_inventory': ('git_cli',),
    'grabowski_checkout_retain': ('git_cli', 'resource_lease'),
    'grabowski_checkout_archive': ('git_cli', 'resource_lease'),
    'grabowski_checkout_cleanup': ('git_cli', 'resource_lease'),
    'grabowski_github': ('github_cli',),
    'grabowski_user_service': ('user_service_control',),
    'grabowski_tmux_list': ('tmux_interaction',),
    'grabowski_tmux_capture': ('tmux_interaction',),
    'grabowski_tmux_send': ('tmux_interaction',),
    'grabowski_process_list': ('process_inspect',),
    'grabowski_process_signal': ('process_signal',),
    'grabowski_ports': ('port_inspect',),
    'grabowski_privileged_action_reference': ('privileged_reference',),
    'grabowski_power_run': ('power_execute',),
    'grabowski_fleet_list': ('terminal_execute',),
    'grabowski_fleet_run': ('terminal_execute',),
    'grabowski_juno_status': ('terminal_execute',),
    'grabowski_juno_pair': ('terminal_execute',),
    'grabowski_juno_run': ('terminal_execute',),
    'ipad_capability_manifest': ('terminal_execute',),
    'ipad_storage_inventory': ('terminal_execute',),
    'ipad_storage_grant_status': ('terminal_execute',),
    'ipad_permission_probe': ('terminal_execute',),
    'ipad_file_stat': ('terminal_execute',),
    'ipad_directory_list': ('terminal_execute',),
    'ipad_file_read': ('terminal_execute',),
    'ipad_file_create': ('terminal_execute',),
    'ipad_file_replace': ('terminal_execute',),
    'grabowski_operation_list': ('terminal_execute',),
    'grabowski_operation_plan': ('terminal_execute',),
    'grabowski_operation_run': ('terminal_execute',),
    'grabowski_privileged_broker_status': ('privileged_reference',),
    'grabowski_task_start': ('durable_job',),
    'grabowski_task_status': ('durable_job',),
    'grabowski_task_logs': ('durable_job',),
    'grabowski_task_cancel': ('durable_job',),
    'grabowski_task_resume': ('durable_job',),
    'grabowski_task_list': ('durable_job',),
    'grabowski_task_reconcile_check': ('durable_job',),
    'grabowski_task_reconcile_refresh': ('durable_job',),
    'grabowski_task_reconcile_resume': ('durable_job',),
    'grabowski_recovery_status': ('audit_verify',),
    'grabowski_recovery_server_probe': ('file_write', 'secret_use', 'terminal_execute'),
    'grabowski_operator_blockade_status': ('audit_verify',),
    'grabowski_operator_blockade_engage': ('audit_verify', 'file_write'),
    'grabowski_operator_blockade_disarm': ('audit_verify', 'file_move'),
    'grabowski_friction_record': ('friction_record',),
    'grabowski_friction_resolve': ('friction_record',),
    'grabowski_friction_summary': (),
    'grabowski_execution_shape': (),
    'grabowski_execution_outcome_record': ('friction_record',),
    'grabowski_execution_governor_summary': (),
    'grabowski_agent_bootstrap': (),
    'grabowski_call_shape_check': (),
    'grabowski_connector_transport_diagnostics': ('user_service_control',),
    'grabowski_operator_recall_export': (),
    'grabowski_resource_nonconflict_assess': ('resource_lease',),
    'grabowski_resource_reconcile_obsolete_path_leases': ('resource_lease',),
    'grabowski_resource_acquire': ('resource_lease',),
    'grabowski_resource_renew': ('resource_lease',),
    'grabowski_resource_release': ('resource_lease',),
    'grabowski_resource_inspect': ('resource_lease',),
    'grabowski_resource_list': ('resource_lease',),
    'grabowski_task_reconcile': ('durable_job',),
    'grabowski_artifact_stat': ('artifact_transfer',),
    'grabowski_artifact_push': ('artifact_transfer',),
    'grabowski_artifact_pull': ('artifact_transfer',),
    'grabowski_browser_worker_start': ('browser_worker',),
    'grabowski_browser_worker_status': ('browser_worker',),
    'grabowski_browser_worker_stop': ('browser_worker',),
    'grabowski_browser_worker_list': ('browser_worker',),
    'grabowski_gui_worker_start': ('gui_worker',),
    'grabowski_gui_worker_status': ('gui_worker',),
    'grabowski_gui_worker_stop': ('gui_worker',),
    'grabowski_gui_worker_list': ('gui_worker',),
}

OPERATOR_CAPABILITY_REQUIREMENT_TOOLS = {
    'grabowski_github_pr_view',
    'grabowski_github_checks',
    'grabowski_service_status',
    'grabowski_service_logs',
    'grabowski_runtime_deploy_schedule',
    'grabowski_agent_workspace_create',
    'grabowski_agent_workspace_status',
    'grabowski_agent_workspace_attach',
    'grabowski_agent_workspace_collect',
    'grabowski_agent_workspace_role_retry',
    'grabowski_agent_workspace_close',
    'grabowski_agent_workspace_observe',
    'grabowski_agent_workspace_optimize',
    'grabowski_agent_workspace_cleanup_plan',
    'grabowski_agent_workspace_reconcile_stale',
    'grabowski_agent_workspace_cleanup',
    'grabowski_agent_competition_start',
    'grabowski_agent_competition_status',
    'grabowski_agent_competition_compare',
    'grabowski_terminal_run',
    'grabowski_job_start',
    'grabowski_job_status',
    'grabowski_job_notification_list',
    'grabowski_job_notification_ack',
    'grabowski_job_logs',
    'grabowski_job_cancel',
    'grabowski_git',
    'grabowski_git_branch',
    'grabowski_checkout_inventory',
    'grabowski_checkout_retain',
    'grabowski_checkout_archive',
    'grabowski_checkout_cleanup',
    'grabowski_github',
    'grabowski_user_service',
    'grabowski_tmux_list',
    'grabowski_tmux_capture',
    'grabowski_tmux_send',
    'grabowski_process_list',
    'grabowski_process_signal',
    'grabowski_ports',
    'grabowski_privileged_action_reference',
    'grabowski_power_run',
    'grabowski_fleet_list',
    'grabowski_fleet_run',
    'grabowski_juno_status',
    'grabowski_juno_pair',
    'grabowski_juno_run',
    'ipad_capability_manifest',
    'ipad_storage_inventory',
    'ipad_storage_grant_status',
    'ipad_permission_probe',
    'ipad_file_stat',
    'ipad_directory_list',
    'ipad_file_read',
    'ipad_file_create',
    'ipad_file_replace',
    'grabowski_operation_list',
    'grabowski_operation_plan',
    'grabowski_operation_run',
    'grabowski_privileged_broker_status',
    'grabowski_connector_transport_diagnostics',
    'grabowski_task_start',
    'grabowski_task_status',
    'grabowski_task_logs',
    'grabowski_task_cancel',
    'grabowski_task_resume',
    'grabowski_task_list',
    'grabowski_task_reconcile_check',
    'grabowski_task_reconcile_refresh',
    'grabowski_task_reconcile_resume',
    'grabowski_resource_nonconflict_assess',
    'grabowski_resource_reconcile_obsolete_path_leases',
    'grabowski_resource_acquire',
    'grabowski_resource_renew',
    'grabowski_resource_release',
    'grabowski_resource_inspect',
    'grabowski_resource_list',
    'grabowski_task_reconcile',
    'grabowski_artifact_stat',
    'grabowski_artifact_push',
    'grabowski_artifact_pull',
    'grabowski_browser_worker_start',
    'grabowski_browser_worker_status',
    'grabowski_browser_worker_stop',
    'grabowski_browser_worker_list',
    'grabowski_gui_worker_start',
    'grabowski_gui_worker_status',
    'grabowski_gui_worker_stop',
    'grabowski_gui_worker_list',
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
        raise RuntimeError(f"Access policy {label} must be one of {list(SESSION_RISK_LEVELS)}")


def _validate_policy(policy: Any) -> None:
    if not isinstance(policy, dict):
        raise RuntimeError("Access policy must be an object")

    unknown = sorted(set(policy) - TOP_LEVEL_POLICY_FIELDS)
    if unknown:
        raise RuntimeError(f"Unknown access policy fields: {unknown}")

    version = policy.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool) or version not in {1, 2}:
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
            raise RuntimeError(
                f"Unknown capability definitions: {unknown_definitions}"
            )
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
        if "trusted_owner" in profile and not isinstance(profile["trusted_owner"], bool):
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
            if capabilities & {"secret_inspect", "secret_reveal", "secret_use", "secret_export"}:
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
            _validate_allowed_grips(profile["allowed_grips"], label=f"profile {name} allowed_grips")
        if "forbidden_hosts" in profile:
            _validate_forbidden_hosts(profile["forbidden_hosts"], label=f"profile {name} forbidden_hosts")
        if "max_risk_level" in profile:
            _validate_risk_level(profile["max_risk_level"], label=f"profile {name} max_risk_level")


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


def _profile_string_list(policy: dict[str, Any], key: str, default: list[str]) -> list[str]:
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
        raise RuntimeError("session_escalation is required for high-risk grip execution")
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
        raise RuntimeError("session_escalation.expires_at_unix is too far in the future")
    has_recovery = isinstance(value.get("recovery"), dict) and bool(value["recovery"])
    has_irreversibility = isinstance(value.get("irreversibility"), dict) and bool(value["irreversibility"])
    if not (has_recovery or has_irreversibility):
        raise RuntimeError("session_escalation requires recovery or irreversibility metadata")


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


def _reject_forbidden_hosts_in_argv(argv: list[str], *, policy: dict[str, Any] | None = None) -> None:
    source_policy = policy or _load_policy()
    forbidden = {host.lower() for host in _profile_string_list(source_policy, "forbidden_hosts", [])}
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
        _policy_path(value).resolve(strict=False)
        for value in _root_values(source, key)
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


def _capability_requirement_summary(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    source = _load_policy() if policy is None else policy
    missing: list[dict[str, Any]] = []
    guarded = {
        tool: required
        for tool, required in TOOL_CAPABILITY_REQUIREMENTS.items()
        if required
    }
    for tool, required in sorted(guarded.items()):
        effective = _effective_capabilities_for_tool(tool, source)
        missing_capabilities = [capability for capability in required if capability not in effective]
        if missing_capabilities:
            missing.append({
                "tool": tool,
                "missing_capabilities": missing_capabilities,
            })
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


def _operator_blockade_records() -> tuple[tuple[blockade_policy.BlockadeRecord, ...], dict[str, Any]]:
    records: list[blockade_policy.BlockadeRecord] = []
    diagnostics: dict[str, Any] = {"marker_error": None, "marker_source": None}
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
    marker_present = KILL_SWITCH_PATH.exists() or KILL_SWITCH_PATH.is_symlink()
    if marker_present:
        try:
            snapshot = blockade_store.read_blockade_marker(
                KILL_SWITCH_PATH,
                expected_marker_path=KILL_SWITCH_PATH,
            )
            records.append(snapshot.record)
            diagnostics["marker_source"] = "typed"
            diagnostics["marker_file_sha256"] = snapshot.file_sha256
            diagnostics["marker_record_sha256"] = snapshot.record_sha256
        except Exception as exc:
            try:
                metadata = os.lstat(KILL_SWITCH_PATH)
            except OSError as observation_error:
                identity = {
                    "strict_error": type(exc).__name__,
                    "lstat_error": type(observation_error).__name__,
                    "path": str(KILL_SWITCH_PATH),
                }
                digest = hashlib.sha256(
                    json.dumps(
                        identity, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
                records.append(
                    blockade_policy.legacy_marker_record(
                        marker_path=str(KILL_SWITCH_PATH),
                        marker_sha256=digest,
                        engaged_at=datetime.fromtimestamp(0, timezone.utc),
                        host=host,
                    )
                )
                diagnostics["marker_source"] = "marker_observation_uncertain"
                diagnostics["marker_error"] = (
                    f"{type(exc).__name__}: {exc}; "
                    f"{type(observation_error).__name__}: {observation_error}"
                )[:500]
                diagnostics["marker_file_sha256"] = digest
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
                }
                digest = hashlib.sha256(
                    json.dumps(
                        identity, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
                records.append(
                    blockade_policy.legacy_marker_record(
                        marker_path=str(KILL_SWITCH_PATH),
                        marker_sha256=digest,
                        engaged_at=datetime.fromtimestamp(
                            metadata.st_ctime, timezone.utc
                        ),
                        host=host,
                    )
                )
                diagnostics["marker_source"] = "legacy_file"
                diagnostics["marker_error"] = f"{type(exc).__name__}: {exc}"[:500]
                diagnostics["marker_file_sha256"] = digest
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
    if allow_blockade_lifecycle and path != str(KILL_SWITCH_PATH):
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
                "path/repo blockades: "
                + ",".join(strong_opaque_scopes)
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


def _verify_same_removal_target(target: Path, identity: tuple[int, int, int, int, int]) -> None:
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
            target.parent
            / f".{target.name}.grabowski-remove-{uuid.uuid4().hex[:12]}"
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
    return path.resolve(strict=False) == KILL_SWITCH_PATH.resolve(strict=False)


def _protected_generic_write_target(path: Path) -> bool:
    protected = [
        POLICY_PATH,
        STATE_DIR,
        AUDIT_LOG,
        QUARANTINE_DIR,
        HOME / "repos" / "merges",
        HOME / ".config" / "tunnel-client",
        DEPLOYMENT_MANIFEST,
        EXPECTED_STABLE_RUNTIME / "inputs" / "runtime-entrypoint.json",
    ]
    candidate = path.resolve(strict=False)
    return any(_path_inside(candidate, root.resolve(strict=False)) for root in protected)


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
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
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
    return any(secret and secret in text for secret in _secret_redaction_values(secret_data))


def _reject_secret_variants_in_text(text: str, secret_data: bytes, label: str) -> None:
    if _contains_secret_variant(text, secret_data):
        raise PermissionError(f"Secret value or encoded secret value may not appear in {label}")


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
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
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
    material = {
        key: value
        for key, value in record.items()
        if key != "record_sha256"
    }
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


def _acquire_audit_descriptor_lock(
    descriptor: int,
    path: Path,
    *,
    exclusive: bool,
) -> None:
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    deadline = time.monotonic() + AUDIT_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
            break
        except BlockingIOError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Audit lock acquisition timed out") from exc
            time.sleep(min(AUDIT_LOCK_POLL_SECONDS, remaining))
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
            "error": str(exc),
        }
    return _verify_audit_bytes(path, data, exists=True)


def _verify_audit_log_unlocked(path: Path = AUDIT_LOG) -> dict[str, Any]:
    descriptor: int | None = None
    try:
        descriptor = _open_audit_read_target(path)
        if descriptor is None:
            return _verify_audit_bytes(path, b"", exists=False)
        return _verify_audit_descriptor(path, descriptor)
    except (OSError, PermissionError, RuntimeError, ValueError) as exc:
        return {
            "valid": False,
            "path": str(path),
            "exists": path.exists(),
            "records": 0,
            "legacy_records": 0,
            "v2_records": 0,
            "last_record_sha256": None,
            "error": str(exc),
        }
    finally:
        if descriptor is not None:
            _close_audit_descriptor(descriptor)


def _verify_audit_log(path: Path = AUDIT_LOG) -> dict[str, Any]:
    return _verify_audit_log_unlocked(path)


def _open_audit_append_target(path: Path) -> tuple[int, bool]:
    parent = _audit_parent(path)
    flags = (
        os.O_RDWR
        | os.O_APPEND
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
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


def _append_audit(record: dict[str, Any]) -> None:
    with AUDIT_APPEND_LOCK:
        if AUDIT_LOG.is_symlink():
            raise PermissionError(f"Audit log may not be a symlink: {AUDIT_LOG}")
        descriptor, _created = _open_audit_append_target(AUDIT_LOG)
        try:
            status = _verify_audit_descriptor(AUDIT_LOG, descriptor)
            if not status["valid"]:
                raise RuntimeError(
                    f"Audit log verification failed: {status['error']}"
                )

            enriched = {**record}
            enriched.setdefault("timestamp", _utc_timestamp())
            enriched["audit_schema_version"] = AUDIT_SCHEMA_VERSION
            enriched["sequence"] = int(status["records"]) + 1
            enriched["previous_record_sha256"] = status["last_record_sha256"]
            enriched["record_sha256"] = _audit_record_hash(enriched)
            payload = (
                json.dumps(
                    enriched,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            current_size = os.fstat(descriptor).st_size
            if current_size + len(payload) > MAX_AUDIT_BYTES:
                raise ValueError("Audit log would exceed its byte limit")
            _require_audit_descriptor_bound(descriptor, AUDIT_LOG)
            try:
                _write_all(descriptor, payload)
                os.fsync(descriptor)
                _require_audit_descriptor_bound(descriptor, AUDIT_LOG)
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
        finally:
            _close_audit_descriptor(descriptor)


def _audit_records() -> list[dict[str, Any]]:
    descriptor = _open_audit_read_target(AUDIT_LOG)
    if descriptor is None:
        return []
    try:
        data = _read_audit_descriptor(descriptor, AUDIT_LOG)
        status = _verify_audit_bytes(AUDIT_LOG, data, exists=True)
        if not status["valid"]:
            raise RuntimeError(f"Audit log verification failed: {status['error']}")
        records = []
        for line in data.splitlines():
            parsed = json.loads(line.decode("utf-8"))
            if isinstance(parsed, dict):
                records.append(parsed)
        return records
    finally:
        _close_audit_descriptor(descriptor)


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
        and set(value) == {
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
    if schema_version == 2:
        expected_keys.add("supporting_sources")
    if schema_version not in {1, 2} or set(contract) != expected_keys:
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
    hashes = raw.get("source_sha256s")
    if (
        not isinstance(hashes, dict)
        or set(hashes) != modules
        or not all(_is_lower_hex(value, 64) for value in hashes.values())
        or hashes.get(module) != raw.get("source_sha256")
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
        "runtime_entrypoint", "runtime_input", "runtime_lock", "source",
        "supporting_sources",
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
    snapshot_paths = raw.get("snapshot_paths") if isinstance(raw.get("snapshot_paths"), dict) else {}
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
    release_id_valid = isinstance(raw.get("release_id"), str) and raw.get("release_id") == release_root.name
    repo_head_valid = _is_lower_hex(raw.get("repo_head"), 40)
    runtime_pointer_valid = False
    try:
        runtime_pointer_valid = (
            canonical_runtime.is_symlink()
            and canonical_runtime.resolve(strict=True) == release_root
        )
    except (OSError, RuntimeError):
        runtime_pointer_valid = False

    def snapshot_bytes(key: str, relative: str, limit: int = MAX_SNAPSHOT_BYTES) -> bytes | None:
        return _read_bound_regular_file(
            snapshot_paths.get(key), release_root / relative, release_root, max_bytes=limit
        )

    runtime_input_data = snapshot_bytes("runtime_input", "inputs/runtime.in")
    runtime_lock_data = snapshot_bytes("runtime_lock", "inputs/runtime.lock.txt")
    runtime_input_identity_valid = (
        runtime_input_data is not None
        and hashlib.sha256(runtime_input_data).hexdigest() == raw.get("runtime_input_sha256")
    )
    lock_identity_valid = (
        runtime_lock_data is not None
        and hashlib.sha256(runtime_lock_data).hexdigest() == raw.get("runtime_lock_sha256")
    )

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
        and hashlib.sha256(contract_data).hexdigest() == raw.get("entrypoint_contract_sha256")
        and _manifest_schema_valid({**raw, "entrypoint_contract": contract_raw})
    )
    embedded_contract_valid = isinstance(raw.get("entrypoint_contract"), dict) and raw.get("entrypoint_contract") == contract_raw

    contract_sources: list[tuple[str, str]] = []
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
            source_hashes.get(module_name)
            if isinstance(source_hashes, dict)
            else None
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
            module_paths.get(module_name)
            if isinstance(module_paths, dict)
            else None
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
        module_origins.get(entrypoint_module)
        if entrypoint_module is not None
        else None
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
            and release_python.resolve(strict=True) == current_python.resolve(strict=True)
        )
        executable_identity_valid = (
            isinstance(raw.get("executable"), str)
            and Path(raw["executable"]) == release_python
            and Path(raw["executable"]).resolve(strict=True) == current_python.resolve(strict=True)
        )
    except (OSError, RuntimeError, ValueError):
        pass

    try:
        pip_identity_valid = raw.get("pip_version") == f"pip {importlib.metadata.version('pip')}"
    except importlib.metadata.PackageNotFoundError:
        pip_identity_valid = False
    protocol_identity_valid = raw.get("mcp_protocol_version") in DEPLOYMENT_PROTOCOL_VERSIONS
    python_runtime_identity_valid = (
        raw.get("python_version") == platform.python_version()
        and raw.get("python_implementation") == platform.python_implementation()
    )
    platform_identity_valid = raw.get("platform") == platform.platform()

    artifact_integrity_valid = all((
        schema_valid,
        repo_head_valid,
        runtime_input_identity_valid,
        lock_identity_valid,
        source_snapshot_identity_valid,
        embedded_contract_valid,
        entrypoint_contract_identity_valid,
        agent_instructions_identity_valid,
        protocol_identity_valid,
    ))
    runtime_binding_valid = all((
        release_path_valid,
        release_id_valid,
        stable_runtime_manifest_valid,
        runtime_pointer_valid,
        source_identity_valid,
        entrypoint_path_valid,
        release_python_identity_valid,
        executable_identity_valid,
        pip_identity_valid,
    ))
    environment_compatibility_valid = all((
        python_runtime_identity_valid,
        platform_identity_valid,
    ))
    provenance_valid = all((
        artifact_integrity_valid,
        runtime_binding_valid,
        environment_compatibility_valid,
    ))

    allowed = {
        key: raw.get(key)
        for key in (
            "schema_version", "release_id", "repo_head",
            "entrypoint_contract_sha256", "agent_instructions", "source_sha256",
            "source_sha256s", "runtime_input_sha256", "runtime_lock_sha256",
            "mcp_protocol_version", "python_version",
            "python_implementation", "platform", "executable",
            "pip_version", "created_at_unix", "completion_status",
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
        "source_identity_valid": source_identity_valid,
        "source_identity_by_module": module_identity_by_module,
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


def _runtime_tool_contract_summary() -> dict[str, Any]:
    expected: list[str] = []
    manifest_error: str | None = None
    try:
        payload = json.loads(
            _ensure_regular_text_file(DEPLOYMENT_MANIFEST, 2_000_000).decode(
                "utf-8"
            )
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
    return {
        "expected_tool_count": len(expected),
        "registered_tool_count": len(registered),
        "name_hash_contract": "sha256-json-sorted-utf8-v1",
        "expected_names_sha256": names_sha256(expected),
        "registered_names_sha256": names_sha256(registered),
        "runtime_matches_deployment_contract": (
            manifest_error is None and expected_set == registered_set
        ),
        "missing_from_runtime": sorted(expected_set - registered_set)[:50],
        "unexpected_in_runtime": sorted(registered_set - expected_set)[:50],
        "manifest_error": manifest_error,
        "client_snapshot_observable": False,
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
    tool_contract = _runtime_tool_contract_summary()
    audit = _verify_audit_log(AUDIT_LOG)
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
        warnings.append({
            "code": "deployment_integrity_incomplete",
            "failed_checks": sorted(key for key, value in integrity.items() if not value),
        })
    if not bool(audit.get("valid")):
        warnings.append({"code": "audit_invalid", "error": audit.get("error")})
    if bool(kill_switch.get("engaged")):
        warnings.append({"code": "kill_switch_engaged"})
    if not bool(tool_contract.get("runtime_matches_deployment_contract")):
        warnings.append({"code": "runtime_tool_contract_drift"})
    if not bool(deployment.get("agent_instructions_identity_valid")):
        warnings.append({"code": "agent_instructions_drift"})
    if not bool(tool_contract.get("client_snapshot_observable")):
        warnings.append({
            "code": "client_snapshot_unobservable",
            "detail": "server runtime cannot prove the connector's frozen client tool view",
        })
    healthy = (
        deployment.get("completion_status") == "complete"
        and all(integrity.values())
        and bool(audit.get("valid"))
        and not bool(kill_switch.get("engaged"))
        and bool(tool_contract.get("runtime_matches_deployment_contract"))
    )
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
            "runtime_matches_deployment_contract": tool_contract.get(
                "runtime_matches_deployment_contract"
            ),
            "client_snapshot_observable": tool_contract.get("client_snapshot_observable"),
            "refresh_required_when_client_count_or_hash_differs": tool_contract.get(
                "refresh_required_when_client_count_or_hash_differs"
            ),
        },
        "agent_instructions": {
            **_agent_instructions_metadata(),
            "runtime_matches_deployment_manifest": deployment.get(
                "agent_instructions_identity_valid"
            ),
            "client_compliance_observable": False,
        },
        "warnings": warnings,
        "recommended_next_action": (
            "inspect warnings before mutation" if warnings else "none"
        ),
        "evidence_refs": {
            "release_id": deployment.get("release_id"),
            "repo_head": deployment.get("repo_head"),
            "audit_last_record_sha256": audit.get("last_record_sha256"),
            "agent_instructions_sha256": AGENT_INSTRUCTIONS_SHA256,
        },
        "does_not_establish": [
            "client_snapshot_freshness",
            "client_instruction_compliance",
            "individual_tool_behavior_correctness",
            "future_action_authority",
        ],
    }
    if selected_view in {"standard", "evidence"}:
        operating_protocol = _operator_relay_protocol()
        workspace_model = operating_protocol.get("workspace_execution_model", {})
        base_payload.update({
            "capabilities": sorted(_effective_capabilities(policy)),
            "roots": {
                "read": _profile_values(policy, "read_roots"),
                "write": _profile_values(policy, "write_roots"),
                "write_excluded": _profile_values(policy, "write_excluded_roots") or [],
            },
            "kill_switch": kill_switch,
            "audit": {
                "valid": audit.get("valid"),
                "records": audit.get("records"),
                "last_record_sha256": audit.get("last_record_sha256"),
                "error": audit.get("error"),
            },
            "operating_protocol": {
                "name": operating_protocol.get("name"),
                "control_loop": operating_protocol.get("control_loop", []),
                "external_agent_delegation": workspace_model.get(
                    "external_agent_delegation"
                ),
                "automatic_patch_apply": workspace_model.get("automatic_patch_apply"),
                "automatic_winner_selection": workspace_model.get(
                    "automatic_winner_selection"
                ),
                "does_not_establish": operating_protocol.get(
                    "does_not_establish", []
                ),
            },
        })
    if selected_view == "evidence":
        base_payload.update({
            "operating_protocol": _operator_relay_protocol(),
            "trusted_owner": _trusted_owner_enabled(policy),
            "state_dir": str(STATE_DIR),
            "policy_path": str(POLICY_PATH),
            "read_roots": _profile_values(policy, "read_roots"),
            "write_roots": _profile_values(policy, "write_roots"),
            "write_excluded_roots": _profile_values(policy, "write_excluded_roots") or [],
            "secret_roots": _secret_root_values(policy),
            "browser_profile_roots": _browser_profile_root_values(policy),
            "secret_export_roots": _secret_export_root_values(policy),
            "latest_complete_bundles_path": str(BUNDLE_REGISTRY),
            "latest_complete_bundles_exists": BUNDLE_REGISTRY.is_file(),
            "deployment": deployment,
            "tool_contract_evidence": tool_contract,
            "capability_requirements": _capability_requirement_summary(policy),
            "forbidden_capabilities": policy.get("forbidden_capabilities", []),
        })
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
    kind = "directory" if statmod.S_ISDIR(st.st_mode) else "file" if statmod.S_ISREG(st.st_mode) else "other"
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
def grabowski_read_text(path: str, start_line: int = 1, max_lines: int = 400) -> dict[str, Any]:
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
    kind = "directory" if statmod.S_ISDIR(st.st_mode) else "file" if statmod.S_ISREG(st.st_mode) else "other"
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
        raise PermissionError("Secret reveal requires explicit context-exposure acknowledgement")
    if trusted_owner and not justification.strip():
        justification = "trusted-owner implicit reveal"
    if not isinstance(justification, str) or not justification.strip():
        raise ValueError("Secret reveal requires a non-empty justification")
    if len(justification.encode("utf-8")) > 1000 or "\x00" in justification:
        raise ValueError("Secret reveal justification is too large or contains NUL")
    if _redact_sensitive_text(justification)[0] != justification:
        raise ValueError("Secret reveal justification appears to contain secret material")
    justification_sha256 = hashlib.sha256(justification.encode("utf-8")).hexdigest()
    exposure_mode = "trusted-owner-policy" if trusted_owner else "explicit-acknowledgement"
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
    _append_audit({
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
    })
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
    kind = "directory" if statmod.S_ISDIR(st.st_mode) else "file" if statmod.S_ISREG(st.st_mode) else "other"
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
def grabowski_replace_text(path: str, content: str, expected_sha256: str) -> dict[str, Any]:
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
        raise ValueError(f"Quarantine preimage is not a regular file: {quarantine_path}")
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
_RLENS_STEM_RE = re.compile(r"[A-Za-z0-9_.-]{1,160}\Z")
_RLENS_REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")


def _rlens_json(path: Path, *, max_bytes: int = 2_000_000) -> dict[str, Any]:
    data = _ensure_regular_text_file(path, max_bytes)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid rLens JSON artifact: {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"rLens artifact must be a JSON object: {path.name}")
    return value


def _rlens_validate_repo(repo: str | None) -> str | None:
    if repo is None or repo == "":
        return None
    if not isinstance(repo, str) or not _RLENS_REPO_RE.fullmatch(repo):
        raise ValueError("repo must be a simple repository name")
    return repo


def _rlens_validate_stem(stem: str) -> str:
    if not isinstance(stem, str) or not _RLENS_STEM_RE.fullmatch(stem):
        raise ValueError("stem must be a simple rLens bundle stem")
    return stem


def _rlens_repo_from_stem(stem: str) -> str:
    if "-full-max-" in stem:
        return stem.split("-full-max-", 1)[0]
    if "-max-" in stem:
        return stem.split("-max-", 1)[0]
    return stem.split("-", 1)[0]


def _rlens_stem_from_manifest(path: Path) -> str:
    name = path.name
    if not name.endswith(_BUNDLE_MANIFEST_SUFFIX):
        raise ValueError("not an rLens bundle manifest")
    return name[: -len(_BUNDLE_MANIFEST_SUFFIX)]


def _rlens_manifest_path(stem: str) -> Path:
    stem = _rlens_validate_stem(stem)
    path = MERGES_ROOT / f"{stem}{_BUNDLE_MANIFEST_SUFFIX}"
    try:
        resolved = path.resolve(strict=False)
    except RuntimeError as exc:
        raise PermissionError("Invalid rLens manifest path") from exc
    root = MERGES_ROOT.resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise PermissionError("rLens manifest path escaped merges root")
    return path


def _rlens_sidecar_path(stem: str, suffix: str) -> Path:
    return MERGES_ROOT / f"{stem}{suffix}"


def _rlens_sidecar_status(path: Path, *, keys: tuple[str, ...]) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        return {"exists": False, "path": str(path)}
    doc = _rlens_json(path)
    result: dict[str, Any] = {"exists": True, "path": str(path)}
    for key in keys:
        if key in doc:
            result[key] = doc[key]
    return result


def _rlens_output_health_status(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        return {"exists": False, "path": str(path)}
    doc = _rlens_json(path)
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


def _rlens_manifest_snapshot_provenance(doc: dict[str, Any], repo: str) -> dict[str, Any]:
    """Return explicit source-repository provenance from a RepoBrief manifest.

    ``generator.runtime.git_commit`` describes the Lenskit/rLens code that
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

    commit = fallback.get("git_commit") or fallback.get("commit") or fallback.get("head")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        return {
            "available": False,
            "reason": "snapshot_repository_commit_absent",
            "repository": {
                key: fallback.get(key)
                for key in ("repo", "repository", "repo_id", "name", "ref", "remote_ref")
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


def _rlens_manifest_summary(path: Path) -> dict[str, Any]:
    stem = _rlens_stem_from_manifest(path)
    repo = _rlens_repo_from_stem(stem)
    doc = _rlens_json(path)
    artifacts = doc.get("artifacts") if isinstance(doc.get("artifacts"), list) else []
    roles = sorted(
        item.get("role") for item in artifacts
        if isinstance(item, dict) and isinstance(item.get("role"), str)
    )
    runtime = (doc.get("generator") or {}).get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    snapshot = _rlens_manifest_snapshot_provenance(doc, repo)
    source_commit = snapshot.get("git_commit") if snapshot.get("available") else None
    source_dirty = snapshot.get("git_dirty") if snapshot.get("available") else None
    stat = path.stat()
    health_path = _rlens_sidecar_path(stem, _BUNDLE_HEALTH_SUFFIX)
    health = _rlens_sidecar_status(
        health_path,
        keys=("status", "evidence_level", "range_ref_resolution_status"),
    )
    return {
        "repo": repo,
        "stem": stem,
        "manifest_path": str(path),
        "manifest_mtime_unix": int(stat.st_mtime),
        "run_id": doc.get("run_id"),
        "created_at": doc.get("created_at"),
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
        "output_health": _rlens_output_health_status(
            _rlens_sidecar_path(stem, _BUNDLE_OUTPUT_HEALTH_SUFFIX)
        ),
    }


def _rlens_iter_manifests(repo: str | None = None) -> list[Path]:
    repo = _rlens_validate_repo(repo)
    if not MERGES_ROOT.is_dir() or MERGES_ROOT.is_symlink():
        return []
    manifests = [
        path for path in MERGES_ROOT.glob(f"*{_BUNDLE_MANIFEST_SUFFIX}")
        if path.is_file() and not path.is_symlink()
    ]
    if repo is not None:
        manifests = [
            path for path in manifests
            if _rlens_repo_from_stem(_rlens_stem_from_manifest(path)) == repo
        ]
    manifests.sort(key=lambda p: (p.stat().st_mtime, p.name), reverse=True)
    return manifests


def _rlens_latest_manifest_by_repo() -> dict[str, Path]:
    latest: dict[str, Path] = {}
    latest_key: dict[str, tuple[float, str]] = {}
    for path in _rlens_iter_manifests(None):
        stem = _rlens_stem_from_manifest(path)
        repo = _rlens_repo_from_stem(stem)
        key = (path.stat().st_mtime, path.name)
        if repo not in latest or key > latest_key[repo]:
            latest[repo] = path
            latest_key[repo] = key
    return latest


def _rlens_manifest_registry_row(path: Path) -> list[str]:
    summary = _rlens_manifest_summary(path)
    stem = str(summary["stem"])
    repo = str(summary["repo"])
    artifact_roles = set(summary.get("artifact_roles") or [])
    def rel(suffix: str) -> str:
        return "./merges/" + stem + suffix
    return [
        repo,
        stem,
        datetime.fromtimestamp(int(summary["manifest_mtime_unix"]), timezone.utc).isoformat(),
        "yes" if "agent_reading_pack" in artifact_roles else "no",
        rel("_merge.md"),
        rel(_BUNDLE_MANIFEST_SUFFIX),
        rel(_BUNDLE_OUTPUT_HEALTH_SUFFIX),
        rel("_merge.agent_reading_pack.md"),
    ]


def _rlens_registry_row_status(row: list[str]) -> dict[str, Any]:
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
    if len(row) < len(BUNDLE_REGISTRY_HEADER):
        status["reason"] = "short_row"
        return status
    try:
        stem = _rlens_validate_stem(row[1])
    except ValueError:
        status["reason"] = "invalid_stem"
        return status
    manifest_path = _rlens_manifest_path(stem)
    exists = manifest_path.is_file() and not manifest_path.is_symlink()
    status.update({
        "valid": exists,
        "stem": stem,
        "repo": row[0],
        "manifest_exists": exists,
        "reason": None if exists else "manifest_missing",
    })
    return status


def _rlens_git(repo_path: Path, args: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


@mcp.tool(name="rlens_bundle_discover", annotations=READ_ANNOTATIONS)
def rlens_bundle_discover(repo: str | None = None, max_candidates: int = 20) -> dict[str, Any]:
    """Discover current rLens/repoLens bundles from the immutable local merges area."""
    _require_capability("bundle_registry")
    if not isinstance(max_candidates, int) or not 1 <= max_candidates <= 100:
        raise ValueError("max_candidates must be between 1 and 100")
    manifests = _rlens_iter_manifests(repo)
    candidates = [_rlens_manifest_summary(path) for path in manifests[:max_candidates]]
    return {
        "kind": "grabowski.rlens_bundle_discovery",
        "schema_version": 1,
        "merges_root": str(MERGES_ROOT),
        "repo_filter": _rlens_validate_repo(repo),
        "exists": MERGES_ROOT.is_dir() and not MERGES_ROOT.is_symlink(),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "registry_cache": {
            "path": str(BUNDLE_REGISTRY),
            "exists": BUNDLE_REGISTRY.is_file(),
            "authority": "legacy_cache",
        },
        "does_not_establish": [
            "bundle_freshness_against_live_repo",
            "repo_understood",
            "claims_true",
            "runtime_correctness",
        ],
    }


@mcp.tool(name="rlens_bundle_status", annotations=READ_ANNOTATIONS)
def rlens_bundle_status(stem: str) -> dict[str, Any]:
    """Return bounded manifest, health and sidecar status for one rLens bundle."""
    _require_capability("bundle_registry")
    stem = _rlens_validate_stem(stem)
    manifest_path = _rlens_manifest_path(stem)
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return {"kind": "grabowski.rlens_bundle_status", "stem": stem, "exists": False}
    summary = _rlens_manifest_summary(manifest_path)
    surface = _rlens_sidecar_status(
        _rlens_sidecar_path(stem, _BUNDLE_SURFACE_SUFFIX),
        keys=("status", "bundle_run_id"),
    )
    output_health = _rlens_output_health_status(
        _rlens_sidecar_path(stem, _BUNDLE_OUTPUT_HEALTH_SUFFIX)
    )
    return {
        "kind": "grabowski.rlens_bundle_status",
        "schema_version": 1,
        "exists": True,
        **summary,
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


@mcp.tool(name="rlens_freshness_check", annotations=READ_ANNOTATIONS)
def rlens_freshness_check(repo: str, stem: str | None = None) -> dict[str, Any]:
    """Compare one rLens bundle commit with the current local repository HEAD."""
    _require_capability("bundle_registry")
    repo = _rlens_validate_repo(repo) or ""
    if stem is None or stem == "":
        manifests = _rlens_iter_manifests(repo)
        if not manifests:
            return {
                "kind": "grabowski.rlens_freshness_check",
                "repo": repo,
                "freshness": "unknown",
                "reason": "no_bundle_found",
            }
        stem = _rlens_stem_from_manifest(manifests[0])
    stem = _rlens_validate_stem(stem)
    status = rlens_bundle_status(stem)
    bundle_commit = status.get("git_commit") if status.get("exists") else None
    bundle_dirty = status.get("git_dirty") if status.get("exists") else None
    repo_path = (HOME / "repos" / repo).resolve(strict=False)
    live: dict[str, Any] = {"repo_path": str(repo_path), "exists": repo_path.is_dir()}
    if not repo_path.is_dir() or repo_path.is_symlink():
        freshness = "unknown"
        reason = "repo_missing_or_invalid"
    else:
        head_rc, head, head_err = _rlens_git(repo_path, ["rev-parse", "HEAD"])
        dirty_rc, dirty_out, dirty_err = _rlens_git(repo_path, ["status", "--porcelain"])
        live.update({
            "head_returncode": head_rc,
            "head": head if head_rc == 0 else None,
            "dirty_returncode": dirty_rc,
            "dirty": bool(dirty_out) if dirty_rc == 0 else None,
            "error": head_err or dirty_err or None,
        })
        if head_rc != 0 or dirty_rc != 0:
            freshness = "unknown"
            reason = "git_unavailable"
        elif not isinstance(bundle_commit, str):
            freshness = "unknown"
            reason = "bundle_source_commit_unavailable"
        elif bundle_commit != head:
            freshness = "stale_head"
            reason = "bundle_commit_differs_from_live_head"
        elif live["dirty"] or bundle_dirty:
            freshness = "fresh_dirty_unverified"
            reason = "commit_matches_but_dirty_worktree_identity_is_not_proven"
        else:
            freshness = "fresh_exact"
            reason = "bundle_commit_matches_clean_live_head"
    return {
        "kind": "grabowski.rlens_freshness_check",
        "schema_version": 1,
        "repo": repo,
        "stem": stem,
        "bundle": {
            "exists": status.get("exists", False),
            "git_commit": bundle_commit,
            "git_dirty": bundle_dirty,
            "source_provenance": status.get("source_provenance"),
            "generator_runtime": status.get("generator_runtime"),
            "post_emit_health": status.get("post_emit_health"),
        },
        "live_repo": live,
        "freshness": freshness,
        "reason": reason,
        "does_not_establish": [
            "dirty_worktree_identity",
            "runtime_correctness",
            "repo_understood",
            "claims_true",
        ],
    }



_RLENS_TASK_PROFILE_RE = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z")


def _rlens_validate_task_profile(task_profile: str) -> str:
    if not isinstance(task_profile, str) or not _RLENS_TASK_PROFILE_RE.fullmatch(task_profile):
        raise ValueError("task_profile must be a simple rLens task profile")
    return task_profile


def _rlens_file_sha256(path: Path) -> str:
    return hashlib.sha256(_ensure_regular_text_file(path, 2_000_000)).hexdigest()


def _rlens_agent_preflight(task_profile: str, manifest_path: Path) -> dict[str, Any]:
    """Run Lenskit's own agent-consumption preflight when the local CLI is available."""
    lenskit_repo = (HOME / "repos" / "lenskit").resolve(strict=False)
    if not lenskit_repo.is_dir() or lenskit_repo.is_symlink():
        return {
            "status": "unknown",
            "available": False,
            "reason": "lenskit_repo_missing_or_invalid",
        }
    command = [
        "python3",
        "-m",
        "merger.lenskit.cli.main",
        "agent-consumption",
        "preflight",
        "--task-profile",
        task_profile,
        "--bundle-manifest",
        str(manifest_path),
    ]
    completed = subprocess.run(
        command,
        cwd=lenskit_repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    stdout = completed.stdout[:500_000]
    stderr = completed.stderr[:20_000]
    if completed.returncode not in {0, 1} or not stdout.strip():
        return {
            "status": "unknown",
            "available": True,
            "returncode": completed.returncode,
            "stderr": _redact_sensitive_text(stderr)[0],
            "reason": "lenskit_preflight_failed",
        }
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "status": "unknown",
            "available": True,
            "returncode": completed.returncode,
            "reason": "lenskit_preflight_invalid_json",
        }
    if not isinstance(value, dict):
        return {
            "status": "unknown",
            "available": True,
            "returncode": completed.returncode,
            "reason": "lenskit_preflight_non_object",
        }
    value["available"] = True
    value["returncode"] = completed.returncode
    return value



def _rlens_lenskit_repo() -> tuple[Path | None, dict[str, Any] | None]:
    lenskit_repo = (HOME / "repos" / "lenskit").resolve(strict=False)
    if not lenskit_repo.is_dir() or lenskit_repo.is_symlink():
        return None, {
            "available": False,
            "status": "unknown",
            "reason": "lenskit_repo_missing_or_invalid",
            "lenskit_repo": str(lenskit_repo),
        }
    return lenskit_repo, None


def _rlens_lenskit_core_json(
    operation: str,
    manifest_path: Path,
    payload: dict[str, Any],
    *,
    timeout: int = 30,
) -> dict[str, Any]:
    lenskit_repo, unavailable_result = _rlens_lenskit_repo()
    if unavailable_result is not None:
        return unavailable_result
    assert lenskit_repo is not None
    script = r'''
import json
import sys
from merger.lenskit.core import repobrief_access

operation = sys.argv[1]
manifest = sys.argv[2]
payload = json.loads(sys.stdin.read() or "{}")

if operation == "query_existing_index":
    result = repobrief_access.query_existing_index(
        manifest,
        payload.get("query", ""),
        k=payload.get("k", 10),
        filters=payload.get("filters") or {},
        resolve_evidence=payload.get("resolve_evidence", False),
        project_sources=payload.get("project_sources", False),
    )
elif operation == "range_get":
    result = repobrief_access.range_get(manifest, payload.get("range_ref"))
else:
    raise SystemExit(f"unknown operation: {operation}")

print(json.dumps(result, sort_keys=True))
'''
    completed = subprocess.run(
        ["python3", "-c", script, operation, str(manifest_path)],
        cwd=lenskit_repo,
        check=False,
        input=json.dumps(payload, sort_keys=True),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    stdout = completed.stdout[:500_000]
    stderr = completed.stderr[:20_000]
    if completed.returncode not in {0, 1} or not stdout.strip():
        return {
            "available": False,
            "status": "unknown",
            "returncode": completed.returncode,
            "stderr": _redact_sensitive_text(stderr)[0],
            "reason": "lenskit_repobrief_access_failed",
        }
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "available": False,
            "status": "unknown",
            "returncode": completed.returncode,
            "reason": "lenskit_repobrief_access_invalid_json",
        }
    if not isinstance(value, dict):
        return {
            "available": False,
            "status": "unknown",
            "returncode": completed.returncode,
            "reason": "lenskit_repobrief_access_non_object",
        }
    value.setdefault("available", value.get("status") == "available")
    value["returncode"] = completed.returncode
    return value


def _rlens_lenskit_query_existing_index(
    manifest_path: Path,
    query: str,
    *,
    k: int,
    filters: dict[str, Any] | None,
    resolve_evidence: bool,
    project_sources: bool,
) -> dict[str, Any]:
    return _rlens_lenskit_core_json(
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


def _rlens_lenskit_range_get(manifest_path: Path, range_ref: dict[str, Any]) -> dict[str, Any]:
    return _rlens_lenskit_core_json(
        "range_get",
        manifest_path,
        {"range_ref": range_ref},
    )


def _rlens_text_excerpt(value: Any, *, max_chars: int = 1200) -> str | None:
    if not isinstance(value, str):
        return None
    return value[:max_chars]


def _rlens_list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in (value if isinstance(value, list) else []) if isinstance(item, dict)]


def _rlens_extract_query_hits(payload: Any) -> tuple[list[dict[str, Any]], str]:
    if isinstance(payload, list):
        return _rlens_list_of_dicts(payload), "bare_results_array"
    if not isinstance(payload, dict):
        return [], "non_object"
    resolved = payload.get("resolved_evidence")
    if isinstance(resolved, dict):
        resolved_hits = resolved.get("hits")
        if isinstance(resolved_hits, list):
            return _rlens_list_of_dicts(resolved_hits), "resolved_evidence.hits"
    direct_results = payload.get("results")
    if isinstance(direct_results, list):
        return _rlens_list_of_dicts(direct_results), "top_level_results"
    query_result = payload.get("query_result")
    if isinstance(query_result, list):
        return _rlens_list_of_dicts(query_result), "query_result_array"
    if isinstance(query_result, dict):
        nested_results = query_result.get("results")
        if isinstance(nested_results, list):
            return _rlens_list_of_dicts(nested_results), "query_result.results"
    return [], "no_results_array"


def _rlens_source_projection_items(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    projection = payload.get("source_citation_projection")
    if not isinstance(projection, dict):
        return []
    return _rlens_list_of_dicts(projection.get("items"))


def _rlens_range_identity_from_hit(hit: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("range_ref", "derived_range_ref", "content_range_ref"):
        value = hit.get(key)
        if isinstance(value, dict):
            return value
    return None


def _rlens_query_snippets(payload: Any, *, max_snippets: int = 5) -> dict[str, Any]:
    projection_items = _rlens_source_projection_items(payload)
    snippets: list[dict[str, Any]] = []
    ranges: list[dict[str, Any]] = []
    if projection_items:
        for item in projection_items[:max_snippets]:
            source_range = item.get("source_range") if isinstance(item.get("source_range"), dict) else None
            snippet = {
                "ordinal": item.get("ordinal", len(snippets)),
                "path": item.get("path"),
                "chunk_id": item.get("chunk_id"),
                "text_excerpt": _rlens_text_excerpt(item.get("text_excerpt")),
                "range_status": item.get("range_status"),
                "citation_status": item.get("citation_status"),
                "citation_id": item.get("citation_id"),
                "citation_range": item.get("citation_range") if isinstance(item.get("citation_range"), dict) else None,
                "canonical_authority": item.get("canonical_authority") if isinstance(item.get("canonical_authority"), dict) else None,
                "live_repo_address": item.get("live_repo_address") if isinstance(item.get("live_repo_address"), dict) else None,
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

    hits, shape = _rlens_extract_query_hits(payload)
    for ordinal, hit in enumerate(hits[:max_snippets]):
        range_ref = _rlens_range_identity_from_hit(hit)
        source_range = hit.get("source_range") if isinstance(hit.get("source_range"), dict) else None
        canonical_authority = hit.get("canonical_authority") if isinstance(hit.get("canonical_authority"), dict) else None
        live_repo_address = hit.get("live_repo_address") if isinstance(hit.get("live_repo_address"), dict) else None
        text = _rlens_text_excerpt(
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
            "line_range": hit.get("line_range") if isinstance(hit.get("line_range"), dict) else None,
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




def _rlens_context_evidence_status(query: str | None, query_context: dict[str, Any], snippets: list[dict[str, Any]], ranges: list[dict[str, Any]]) -> tuple[str, str | None]:
    if not query:
        return "skipped", "query_not_provided"
    if not query_context.get("available", False):
        reason = query_context.get("reason") or query_context.get("status") or "query_unavailable"
        return "unavailable", str(reason)
    citation_count = sum(1 for snippet in snippets if isinstance(snippet.get("citation_id"), str) and snippet.get("citation_id"))
    if snippets and (ranges or citation_count):
        return "available", None
    return "degraded", "resolved_evidence_missing_snippets_ranges_or_citations"


def _rlens_context_citation_ids(snippets: list[dict[str, Any]]) -> list[str]:
    ids = []
    for snippet in snippets:
        citation_id = snippet.get("citation_id")
        if isinstance(citation_id, str) and citation_id and citation_id not in ids:
            ids.append(citation_id)
    return ids


def _rlens_selected_manifest_for_repo(
    repo: str,
    stem: str | None,
) -> tuple[dict[str, Any], str | None, Path | None, dict[str, Any] | None]:
    freshness = rlens_freshness_check(repo, stem)
    selected_stem = freshness.get("stem")
    if not isinstance(selected_stem, str):
        return freshness, None, None, {
            "kind": "grabowski.rlens_selection",
            "schema_version": 1,
            "repo": repo,
            "available": False,
            "freshness": freshness,
            "reason": "no_bundle_available",
        }
    status = rlens_bundle_status(selected_stem)
    status_repo = status.get("repo") if isinstance(status, dict) else None
    if status.get("exists") and status_repo != repo:
        return freshness, selected_stem, None, {
            "kind": "grabowski.rlens_selection",
            "schema_version": 1,
            "repo": repo,
            "stem": selected_stem,
            "available": False,
            "freshness": freshness,
            "reason": "bundle_repo_mismatch",
            "bundle_repo": status_repo,
        }
    return freshness, selected_stem, _rlens_manifest_path(selected_stem), None


@mcp.tool(name="rlens_preflight", annotations=READ_ANNOTATIONS)
def rlens_preflight(
    repo: str,
    task_profile: str = "basic_repo_question",
    stem: str | None = None,
) -> dict[str, Any]:
    """Return bounded rLens/RepoBrief preflight for an agent task profile."""
    _require_capability("bundle_registry")
    repo = _rlens_validate_repo(repo) or ""
    task_profile = _rlens_validate_task_profile(task_profile)
    freshness, selected_stem, manifest_path, selection_error = _rlens_selected_manifest_for_repo(repo, stem)
    if selection_error is not None:
        return {
            "kind": "grabowski.rlens_preflight",
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
    preflight = _rlens_agent_preflight(task_profile, manifest_path)
    preflight_status = preflight.get("status") if isinstance(preflight.get("status"), str) else "unknown"
    return {
        "kind": "grabowski.rlens_preflight",
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





@mcp.tool(name="rlens_query", annotations=READ_ANNOTATIONS)
def rlens_query(
    repo: str,
    query: str,
    task_profile: str = "basic_repo_question",
    stem: str | None = None,
    k: int = 5,
    filters: dict[str, Any] | None = None,
    max_snippets: int = 5,
) -> dict[str, Any]:
    """Run a bounded read-only RepoBrief query and normalize result shapes."""
    _require_capability("bundle_registry")
    repo = _rlens_validate_repo(repo) or ""
    task_profile = _rlens_validate_task_profile(task_profile)
    if not isinstance(query, str) or not query.strip() or len(query) > 500:
        raise ValueError("query must be a non-empty string up to 500 characters")
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= 100:
        raise ValueError("k must be an integer between 1 and 100")
    if filters is not None and not isinstance(filters, dict):
        raise ValueError("filters must be an object when provided")
    if not isinstance(max_snippets, int) or isinstance(max_snippets, bool) or not 1 <= max_snippets <= 20:
        raise ValueError("max_snippets must be an integer between 1 and 20")

    freshness, selected_stem, manifest_path, selection_error = _rlens_selected_manifest_for_repo(repo, stem)
    if selection_error is not None:
        return {
            "kind": "grabowski.rlens_query",
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
    lenskit_result = _rlens_lenskit_query_existing_index(
        manifest_path,
        query,
        k=k,
        filters=filters or {},
        resolve_evidence=True,
        project_sources=True,
    )
    snippets = _rlens_query_snippets(lenskit_result, max_snippets=max_snippets)
    query_result = lenskit_result.get("query_result") if isinstance(lenskit_result, dict) else None
    result_count = None
    if isinstance(query_result, dict):
        if isinstance(query_result.get("count"), int):
            result_count = query_result.get("count")
        elif isinstance(query_result.get("results"), list):
            result_count = len(query_result["results"])
    available = lenskit_result.get("status") == "available"
    return {
        "kind": "grabowski.rlens_query",
        "schema_version": 1,
        "repo": repo,
        "task_profile": task_profile,
        "stem": selected_stem,
        "query": query,
        "k": k,
        "filters": filters or {},
        "available": available,
        "status": lenskit_result.get("status", "unknown"),
        "freshness": freshness,
        "query_shape": snippets["source_shape"],
        "normalized_query_shape": snippets["source_shape"],
        "hit_count": snippets["hit_count"],
        "result_count": result_count,
        "snippets": snippets["snippets"],
        "ranges": snippets["ranges"],
        "lenskit_status": {
            "kind": lenskit_result.get("kind"),
            "status": lenskit_result.get("status"),
            "error_code": lenskit_result.get("error_code"),
            "reason": lenskit_result.get("reason"),
            "returncode": lenskit_result.get("returncode"),
        },
        "mutation_boundary": lenskit_result.get("mutation_boundary") or {"writes": [], "read_paths_do_not_refresh": True},
        "evidence_resolution_used": lenskit_result.get("evidence_resolution_used"),
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


@mcp.tool(name="rlens_query_existing_index", annotations=READ_ANNOTATIONS)
def rlens_query_existing_index(
    repo: str,
    query: str,
    k: int = 5,
    stem: str | None = None,
    filters: dict[str, Any] | None = None,
    resolve_evidence: bool = True,
    project_sources: bool = True,
) -> dict[str, Any]:
    """Compatibility wrapper for querying a prebuilt RepoBrief index without refresh."""
    _require_capability("bundle_registry")
    repo = _rlens_validate_repo(repo) or ""
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

    freshness, selected_stem, manifest_path, selection_error = _rlens_selected_manifest_for_repo(repo, stem)
    if selection_error is not None:
        return {
            "kind": "grabowski.rlens_query_existing_index",
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
    lenskit_result = _rlens_lenskit_query_existing_index(
        manifest_path,
        query,
        k=k,
        filters=filters or {},
        resolve_evidence=resolve_evidence,
        project_sources=project_sources,
    )
    snippets = _rlens_query_snippets(lenskit_result, max_snippets=k)
    query_result = lenskit_result.get("query_result") if isinstance(lenskit_result, dict) else None
    result_count = None
    if isinstance(query_result, dict):
        if isinstance(query_result.get("count"), int):
            result_count = query_result.get("count")
        elif isinstance(query_result.get("results"), list):
            result_count = len(query_result["results"])
    available = lenskit_result.get("status") == "available"
    return {
        "kind": "grabowski.rlens_query_existing_index",
        "schema_version": 1,
        "repo": repo,
        "stem": selected_stem,
        "query": query,
        "k": k,
        "filters": filters or {},
        "available": available,
        "status": lenskit_result.get("status", "unknown"),
        "freshness": freshness,
        "query_shape": snippets["source_shape"],
        "normalized_query_shape": snippets["source_shape"],
        "hit_count": snippets["hit_count"],
        "result_count": result_count,
        "snippets": snippets["snippets"],
        "ranges": snippets["ranges"],
        "lenskit_status": {
            "kind": lenskit_result.get("kind"),
            "status": lenskit_result.get("status"),
            "error_code": lenskit_result.get("error_code"),
            "reason": lenskit_result.get("reason"),
            "returncode": lenskit_result.get("returncode"),
        },
        "mutation_boundary": lenskit_result.get("mutation_boundary") or {"writes": [], "read_paths_do_not_refresh": True},
        "evidence_resolution_used": lenskit_result.get("evidence_resolution_used"),
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


@mcp.tool(name="rlens_range_get", annotations=READ_ANNOTATIONS)
def rlens_range_get(
    repo: str,
    range_ref: dict[str, Any],
    stem: str | None = None,
) -> dict[str, Any]:
    """Resolve one bounded RepoBrief range_ref without reading live workspace files."""
    _require_capability("bundle_registry")
    repo = _rlens_validate_repo(repo) or ""
    if not isinstance(range_ref, dict):
        raise ValueError("range_ref must be an object")
    freshness, selected_stem, manifest_path, selection_error = _rlens_selected_manifest_for_repo(repo, stem)
    if selection_error is not None:
        return {
            "kind": "grabowski.rlens_range_get",
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
    lenskit_result = _rlens_lenskit_range_get(manifest_path, range_ref)
    range_value = lenskit_result.get("range") if isinstance(lenskit_result, dict) else None
    if isinstance(range_value, dict) and isinstance(range_value.get("text"), str) and len(range_value["text"]) > 4000:
        range_value = dict(range_value)
        range_value["text"] = range_value["text"][:4000]
        range_value["text_truncated"] = True
    return {
        "kind": "grabowski.rlens_range_get",
        "schema_version": 1,
        "repo": repo,
        "stem": selected_stem,
        "available": lenskit_result.get("status") == "available",
        "status": lenskit_result.get("status", "unknown"),
        "freshness": freshness,
        "range_ref": range_ref,
        "range": range_value,
        "lenskit_status": {
            "kind": lenskit_result.get("kind"),
            "status": lenskit_result.get("status"),
            "error_code": lenskit_result.get("error_code"),
            "reason": lenskit_result.get("reason"),
            "returncode": lenskit_result.get("returncode"),
        },
        "mutation_boundary": lenskit_result.get("mutation_boundary") or {"writes": [], "read_paths_do_not_refresh": True},
        "does_not_establish": [
            "answer_correct",
            "repo_understood",
            "claims_true",
            "test_sufficiency",
            "review_complete",
            "runtime_correctness",
        ],
    }


@mcp.tool(name="rlens_context_pack", annotations=READ_ANNOTATIONS)
def rlens_context_pack(
    repo: str,
    task_profile: str = "basic_repo_question",
    stem: str | None = None,
    query: str | None = None,
    k: int = 5,
    max_snippets: int = 5,
) -> dict[str, Any]:
    """Build a bounded rLens context pack for agent handoff and Bureau receipts."""
    _require_capability("bundle_registry")
    repo = _rlens_validate_repo(repo) or ""
    task_profile = _rlens_validate_task_profile(task_profile)
    if query is not None and not isinstance(query, str):
        raise ValueError("query must be a string when supplied")
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= 100:
        raise ValueError("k must be an integer between 1 and 100")
    freshness, selected_stem, manifest_path, selection_error = _rlens_selected_manifest_for_repo(repo, stem)
    if selection_error is not None:
        return {
            "kind": "grabowski.rlens_context_pack",
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
    status = rlens_bundle_status(selected_stem)
    manifest_sha = _rlens_file_sha256(manifest_path) if manifest_path.is_file() else None
    preflight = _rlens_agent_preflight(task_profile, manifest_path)
    preflight_status = preflight.get("status") if isinstance(preflight.get("status"), str) else "unknown"
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    live = freshness.get("live_repo") if isinstance(freshness.get("live_repo"), dict) else {}
    bundle = freshness.get("bundle") if isinstance(freshness.get("bundle"), dict) else {}

    if query:
        query_context = rlens_query(
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
    snippets = _rlens_list_of_dicts(query_context.get("snippets"))
    ranges = _rlens_list_of_dicts(query_context.get("ranges"))
    evidence_status, evidence_reason = _rlens_context_evidence_status(query, query_context, snippets, ranges)
    citation_ids = _rlens_context_citation_ids(snippets)
    bounded_evidence = {
        "query": query,
        "k": k if query else None,
        "normalized_query_shape": query_context.get("normalized_query_shape") or query_context.get("query_shape"),
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
        "freshness_status": freshness.get("freshness", "unknown"),
        "task_profile": task_profile,
        "preflight_status": preflight_status,
        "query_shape": bounded_evidence["normalized_query_shape"],
        "snippet_count": len(snippets),
        "range_count": len(ranges),
        "citation_count": len(citation_ids),
        "resolved_evidence_status": evidence_status,
        "source": "grabowski.rlens_context_pack",
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
        "kind": "grabowski.rlens_context_pack",
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
            "lenskit_status": query_context.get("lenskit_status"),
            "raw_results_included": False,
        },
        "bounded_evidence": bounded_evidence,
        "snippets": snippets,
        "ranges": ranges,
        "access_wrappers": {
            "preflight": "rlens_preflight",
            "query": "rlens_query_existing_index",
            "range": "rlens_range_get",
            "context_pack": "rlens_context_pack",
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
) -> dict[str, Any]:
    """Run one allowlisted Grabowski grip and return its receipt-bound result."""
    _require_capability("terminal_execute")
    if allow_mutation:
        _require_mutations_enabled("terminal_execute")
    raw_parameters = parameters or {}
    decision = _session_grip_policy_decision(name, raw_parameters)
    if not decision["allowed"]:
        return grabowski_grips._blocked_surface_receipt(
            name,
            raw_parameters,
            f"session profile blocks grip: {decision}",
        )
    dispatch_parameters = dict(raw_parameters)
    dispatch_parameters.pop("session_escalation", None)
    return grabowski_grips.grip_run(
        name,
        dispatch_parameters,
        profile=profile,
        allow_mutation=allow_mutation,
    )


@mcp.tool(name="latest_complete_bundles", annotations=READ_ANNOTATIONS)
def latest_complete_bundles() -> dict[str, Any]:
    """Return the curated latest-complete Lens/repoLens bundle registry."""
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
    row_status = [_rlens_registry_row_status(row) for row in rows]
    stale_rows = [item for item in row_status if item.get("is_header") is not True and not item.get("valid")]
    valid_legacy_rows = [
        row for row, status in zip(rows, row_status)
        if status.get("is_header") is not True and status.get("valid") is True
    ]
    discovery_needed = not rows or bool(stale_rows)
    discovered: list[list[str]] = []
    if discovery_needed:
        discovered = [
            _rlens_manifest_registry_row(path)
            for _repo, path in sorted(_rlens_latest_manifest_by_repo().items())
        ]
    if not rows:
        effective_rows = discovered
        authority = "live_discovery"
    elif stale_rows:
        legacy_repos = {row[0] for row in valid_legacy_rows if row}
        discovery_additions = [row for row in discovered if row and row[0] not in legacy_repos]
        effective_rows = [*valid_legacy_rows, *discovery_additions]
        authority = "merged_legacy_live_discovery" if discovered else "legacy_cache_valid_rows"
    else:
        effective_rows = rows
        authority = "legacy_cache"
    return {
        "path": str(BUNDLE_REGISTRY),
        "exists": BUNDLE_REGISTRY.is_file(),
        "sha256": sha256,
        "rows": effective_rows,
        "legacy_rows": rows,
        "legacy_row_status": row_status,
        "stale_legacy_row_count": len(stale_rows),
        "live_discovery_row_count": len(discovered),
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
