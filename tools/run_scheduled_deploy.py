#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import deploy_runtime as deploy_core
import deploy_runtime_dual as deploy_dual
import grabowski_midcutover_resume as midcutover

OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
SOURCE_KINDS = frozenset({"canonical-main", "detached-worktree"})
MAX_CAPTURE_BYTES = 65_536
MAX_MANIFEST_BYTES = 2_000_000
MAX_FINALIZATION_RECEIPT_BYTES = 64 * 1024
FINALIZATION_KIND = "grabowski_runtime_deploy_finalization"
SIDECAR_INSTALLER_RELATIVE_PATH = Path("tools/install_coding_agent_router_cli.py")
SIDECAR_RECONCILIATION_KIND = "grabowski_runtime_sidecar_reconciliation"
EARLY_DISPATCHER_SAMPLE_COUNT = 2
EARLY_DISPATCHER_SAMPLE_INTERVAL_SECONDS = 0.05
DEPLOYMENT_CONTENTION_RETRY_DELAYS_SECONDS = (5, 10, 20)
DEPLOYMENT_CONTENTION_MAX_ATTEMPTS = (
    len(DEPLOYMENT_CONTENTION_RETRY_DELAYS_SECONDS) + 1
)


class DeploymentContentionDeferred(RuntimeError):
    """The cheap read-only preflight observed contention or uncertainty."""


class SidecarInstallOutstanding(RuntimeError):
    """The runtime is live but one required sidecar reconciliation did not settle."""


class BlueGreenDeploymentIncomplete(RuntimeError):
    """The productive cutover produced a durable non-completed receipt."""


class MidCutoverResumeIncomplete(RuntimeError):
    """The staged mid-cutover resume produced a durable non-completed receipt."""


class RecoveryClassificationBlocked(RuntimeError):
    """The durable state classifies into neither lane, so nothing may run."""


#: How a resume outcome maps onto the *deployed* job finalization contract.
#: outcome_unknown cannot be expressed there for a resume -- that state requires
#: a blue-green summary bound to this job's own expected head with an
#: unpersisted receipt -- so the ambiguity is carried by the failure_type and by
#: the durable resume receipt instead of being silently flattened into "failed".
RESUME_FINALIZATION_FAILURE_TYPES = {
    "completed": "MidCutoverPrerequisiteRecovered",
    "outcome_unknown": "MidCutoverResumeOutcomeUnknown",
    "denied": "MidCutoverResumeDenied",
    "failed_pre_resume": "MidCutoverResumeFailedPreResume",
}


def _resume_finalization_failure_type(resume_result: dict[str, Any]) -> str:
    outcome = str(resume_result.get("outcome") or "")
    receipt_persisted = resume_result.get("receipt_persisted") is True
    if outcome in {"completed", "outcome_unknown"} and not receipt_persisted:
        # The effect happened but its evidence did not land. That is strictly
        # more ambiguous than either outcome on its own.
        return "MidCutoverResumeReceiptUnpersisted"
    return RESUME_FINALIZATION_FAILURE_TYPES.get(
        outcome, "MidCutoverResumeOutcomeUnknown"
    )


REPOGROUND_MANAGED_SOURCE_ROOT = Path.home() / "repos" / ".repoground-sources"
FINALIZATION_ENV = {
    "job_id": "GRABOWSKI_JOB_ID",
    "unit": "GRABOWSKI_JOB_UNIT",
    "argv_sha256": "GRABOWSKI_JOB_ARGV_SHA256",
    "expected_head": "GRABOWSKI_JOB_EXPECTED_HEAD",
    "metadata": "GRABOWSKI_JOB_METADATA_PATH",
    "stdout": "GRABOWSKI_JOB_STDOUT_PATH",
    "stderr": "GRABOWSKI_JOB_STDERR_PATH",
    "finalization": "GRABOWSKI_JOB_FINALIZATION_PATH",
}


def canonical_json_sha256(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def load_finalization_binding() -> dict[str, Any] | None:
    values = {key: os.environ.get(name) for key, name in FINALIZATION_ENV.items()}
    present = {key for key, value in values.items() if value is not None}
    if not present:
        return None
    if present != set(values):
        raise RuntimeError("incomplete job finalization binding")
    assert all(isinstance(value, str) for value in values.values())
    job_id = values["job_id"]
    unit = values["unit"]
    argv_sha256 = values["argv_sha256"]
    expected_head = values["expected_head"]
    if not re.fullmatch(r"[0-9a-f]{12}", job_id or ""):
        raise RuntimeError("invalid job finalization job_id")
    if unit != f"grabowski-job-{job_id}":
        raise RuntimeError("invalid job finalization unit binding")
    if not re.fullmatch(r"[0-9a-f]{64}", argv_sha256 or ""):
        raise RuntimeError("invalid job finalization argv_sha256")
    if not OBJECT_ID_RE.fullmatch(expected_head or ""):
        raise RuntimeError("invalid job finalization expected_head")
    receipt_paths = {key: values[key] for key in ("metadata", "stdout", "stderr", "finalization")}
    finalization = Path(receipt_paths["finalization"])
    if not finalization.is_absolute() or finalization.name != "finalization.json":
        raise RuntimeError("invalid job finalization receipt path")
    parent = finalization.parent
    if parent.is_symlink() or not parent.is_dir() or parent.resolve(strict=True) != parent:
        raise RuntimeError("invalid job finalization receipt directory")
    expected_paths = {
        "metadata": str(parent / "metadata.json"),
        "stdout": str(parent / "stdout.log"),
        "stderr": str(parent / "stderr.log"),
        "finalization": str(parent / "finalization.json"),
    }
    if receipt_paths != expected_paths:
        raise RuntimeError("job finalization receipt paths do not share one job directory")
    return {
        "schema_version": 1,
        "kind": FINALIZATION_KIND,
        "job_id": job_id,
        "unit": unit,
        "argv_sha256": argv_sha256,
        "expected_head": expected_head,
        "receipt_paths": receipt_paths,
    }


def write_finalization_receipt(
    binding: dict[str, Any],
    *,
    final_status: str,
    repo_head: str | None,
    release_id: str | None,
    failure_type: str | None,
    blue_green: dict[str, Any] | None = None,
) -> Path:
    if final_status not in {"completed", "failed", "outcome_unknown"}:
        raise ValueError("invalid finalization status")
    completion_status = {
        "completed": "complete",
        "failed": "failed",
        "outcome_unknown": "outcome_unknown",
    }[final_status]
    material = {
        **binding,
        "final_status": final_status,
        "completion_status": completion_status,
        "repo_head": repo_head,
        "release_id": release_id,
        "failure_type": failure_type,
        "blue_green": blue_green,
        "blue_green_receipt_sha256": (
            blue_green.get("receipt_sha256")
            if isinstance(blue_green, dict)
            else None
        ),
        "blind_retry_allowed": False if final_status == "outcome_unknown" else None,
        "timestamp_unix": int(time.time()),
    }
    payload = {**material, "payload_sha256": canonical_json_sha256(material)}
    data = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > MAX_FINALIZATION_RECEIPT_BYTES:
        raise RuntimeError("job finalization receipt exceeds size bound")
    path = Path(binding["receipt_paths"]["finalization"])
    temp = path.parent / f".{path.name}.{os.getpid()}.tmp"
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    published = False
    try:
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(temp, path, follow_symlinks=False)
        published = True
        directory_descriptor = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        if published:
            try:
                path.unlink()
                directory_descriptor = os.open(
                    path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                )
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
            except OSError:
                pass
        raise
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    return path


def emit(phase: str, **fields: Any) -> None:
    print(json.dumps({"timestamp_unix": int(time.time()), "phase": phase, **fields}, ensure_ascii=False, sort_keys=True), flush=True)


def git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "PAGER": "cat", "NO_COLOR": "1"})
    for key in ("GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_ASKPASS", "SSH_ASKPASS"):
        environment.pop(key, None)
    return environment


def child_environment() -> dict[str, str]:
    environment = git_environment()
    for name in FINALIZATION_ENV.values():
        environment.pop(name, None)
    return environment


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def read_limited_process_pipes(process: subprocess.Popen[bytes], *, timeout_seconds: int, max_output_bytes: int) -> tuple[bytes, bytes, bool, bool, bool]:
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
        buffer = buffers[pipe]
        keep = 0
        if len(buffer) < max_output_bytes:
            keep = min(len(chunk), max_output_bytes - len(buffer))
            buffer.extend(chunk[:keep])
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
            terminate_process_group(process)
            break
        for key, _events in selector.select(timeout=min(0.2, remaining)):
            pipe = key.fileobj
            chunk = os.read(pipe.fileno(), 8192)
            if not chunk:
                selector.unregister(pipe)
                continue
            append_limited(pipe, chunk)

    if process.poll() is None and not timed_out:
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group(process)
    elif process.poll() is not None:
        process.wait(timeout=0)

    stdout = bytes(buffers.get(process.stdout, b""))
    stderr = bytes(buffers.get(process.stderr, b""))
    selector.close()
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            pipe.close()
    return stdout, stderr, timed_out, stdout_truncated, stderr_truncated


def run_capture(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int = 30,
    environment: dict[str, str] | None = None,
) -> str:
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment if environment is not None else git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    stdout_raw, stderr_raw, timed_out, stdout_truncated, stderr_truncated = read_limited_process_pipes(process, timeout_seconds=timeout, max_output_bytes=MAX_CAPTURE_BYTES)
    stdout = stdout_raw.decode("utf-8", errors="replace")
    stderr = stderr_raw.decode("utf-8", errors="replace")
    if timed_out:
        raise RuntimeError("command timed out")
    if stdout_truncated or stderr_truncated:
        raise RuntimeError("command output exceeded the preflight bound")
    if process.returncode != 0:
        raise RuntimeError(stderr.strip() or stdout.strip() or "command failed")
    return stdout.strip()


def _json_command(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int = 60,
) -> dict[str, Any]:
    raw = run_capture(
        argv,
        cwd=cwd,
        timeout=timeout,
        environment=child_environment(),
    )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("sidecar installer returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("sidecar installer JSON root is not an object")
    return value


def _sidecar_digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RuntimeError(f"sidecar {label} digest is invalid")
    return value


def _sidecar_controller_contract_valid(value: dict[str, Any]) -> bool:
    """Exact controller-integrator contract required for sidecar receipts."""
    return (
        value.get("decision") == "controller"
        and value.get("controller") == "grabowski-primary"
        and value.get("primary_role") == "controller-integrator"
        and value.get("delegated_scoped_writers_allowed") is True
        and value.get("controller_integration_required") is True
        and value.get("single_mutating_writer") is True
        and value.get("single_mutating_writer_scope")
        == "overlapping-resource-lane"
        and value.get("external_primary_writer_forbidden") is False
        and value.get("automatic_execution_authorized") is True
    )


def reconcile_coding_agent_sidecars(
    repo: Path,
    live: dict[str, Any],
) -> dict[str, Any]:
    installer = repo / SIDECAR_INSTALLER_RELATIVE_PATH
    metadata = installer.lstat()
    if (
        installer.is_symlink()
        or not installer.is_file()
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise RuntimeError("sidecar installer source is unsafe")
    python = Path(sys.executable)
    if not python.is_absolute() or not os.access(python, os.X_OK):
        raise RuntimeError("sidecar installer Python is not executable")

    applied = _json_command(
        [str(python), str(installer), "--apply"],
        cwd=repo,
    )
    if (
        applied.get("kind") != "coding-agent-router-cli-install-receipt"
        or applied.get("status") != "installed"
        or applied.get("installed") is not True
        or applied.get("runtime_catalog_source") != "deployment_catalog"
        or applied.get("automatic_execution_authorized") is not True
        or applied.get("rollback_performed") is not False
    ):
        raise RuntimeError("sidecar apply receipt is invalid")
    readback = applied.get("readback")
    if (
        not isinstance(readback, dict)
        or readback.get("catalog_sha256") != applied.get("runtime_catalog_sha256")
        or not _sidecar_controller_contract_valid(readback)
    ):
        raise RuntimeError("sidecar apply readback is invalid")

    checked = _json_command(
        [str(python), str(installer), "--check"],
        cwd=repo,
    )
    if (
        checked.get("kind") != "coding-agent-router-cli-install-check"
        or checked.get("installed") is not True
        or checked.get("runtime_catalog_source") != "deployment_catalog"
        or not _sidecar_controller_contract_valid(checked)
        or checked.get("catalog_sha256") != checked.get("runtime_catalog_sha256")
    ):
        raise RuntimeError("sidecar post-install check is invalid")

    wrapper_sha256 = _sidecar_digest(
        checked.get("wrapper_sha256"), label="wrapper"
    )
    scheduler_sha256 = _sidecar_digest(
        checked.get("scheduler_sha256"), label="scheduler"
    )
    runtime_catalog_sha256 = _sidecar_digest(
        checked.get("runtime_catalog_sha256"), label="runtime catalog"
    )
    if (
        applied.get("wrapper_sha256") != wrapper_sha256
        or applied.get("scheduler_sha256") != scheduler_sha256
        or applied.get("runtime_catalog_sha256") != runtime_catalog_sha256
    ):
        raise RuntimeError("sidecar apply and check identities differ")

    material = {
        "schema_version": 1,
        "kind": SIDECAR_RECONCILIATION_KIND,
        "status": "installed",
        "repo_head": live.get("repo_head"),
        "release_id": live.get("release_id"),
        "wrapper_sha256": wrapper_sha256,
        "scheduler_sha256": scheduler_sha256,
        "runtime_catalog_sha256": runtime_catalog_sha256,
        "apply_receipt_sha256": canonical_json_sha256(applied),
        "check_receipt_sha256": canonical_json_sha256(checked),
        "automatic_execution_authorized": True,
    }
    return {**material, "evidence_sha256": canonical_json_sha256(material)}


def _validated_repository_path(repo: Path, *, label: str) -> Path:
    if not repo.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    if repo.is_symlink() or not repo.is_dir():
        raise RuntimeError(f"{label} is unavailable: {repo}")
    resolved = repo.resolve(strict=True)
    if resolved != repo:
        raise RuntimeError(f"{label} must not traverse a symlink or relative segment")
    return resolved


def repoground_managed_source_roots() -> tuple[Path, ...]:
    roots = [REPOGROUND_MANAGED_SOURCE_ROOT]
    configured = os.environ.get("REPOGROUND_SOURCE_ROOT")
    if configured:
        configured_root = Path(configured)
        if not configured_root.is_absolute():
            raise RuntimeError("RepoGround managed source root must be an absolute path")
        roots.append(configured_root)
    return tuple(dict.fromkeys(root.resolve(strict=False) for root in roots))


def assert_not_repoground_managed_source(repo: Path) -> None:
    """Reject deploy execution from RepoGround publisher-owned source checkouts."""
    resolved_repo = repo.resolve(strict=False)
    for resolved_root in repoground_managed_source_roots():
        try:
            resolved_repo.relative_to(resolved_root)
        except ValueError:
            continue
        raise RuntimeError(
            "RepoGround-managed source repository cannot be used as a deploy source: "
            f"{repo}"
        )


def _git_prefix(repo: Path) -> list[str]:
    return [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.file.allow=never",
        "-C",
        str(repo),
    ]


def _git_common_directory(repo: Path) -> Path:
    raw = run_capture(
        [*_git_prefix(repo), "rev-parse", "--git-common-dir"],
        cwd=repo,
    )
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = repo / candidate
    if candidate.is_symlink():
        raise RuntimeError("git common directory may not be a symlink")
    resolved = candidate.resolve(strict=True)
    if resolved != candidate or not resolved.is_dir():
        raise RuntimeError("git common directory must be an exact real directory")
    return resolved


def verify_repository(
    repo: Path,
    canonical_repo: Path,
    source_kind: str,
    expected_head: str,
) -> None:
    if not OBJECT_ID_RE.fullmatch(expected_head):
        raise ValueError("expected_head must be a lowercase Git object ID")
    if source_kind not in SOURCE_KINDS:
        raise ValueError("source_kind is invalid")
    source = _validated_repository_path(repo, label="source repository")
    assert_not_repoground_managed_source(source)
    canonical = _validated_repository_path(
        canonical_repo,
        label="canonical repository",
    )
    source_common = _git_common_directory(source)
    canonical_common = (
        source_common if source == canonical else _git_common_directory(canonical)
    )
    if source_common != canonical_common:
        raise RuntimeError("source repository does not share the canonical Git common directory")
    expected_kind = "canonical-main" if source == canonical else "detached-worktree"
    if source_kind != expected_kind:
        raise RuntimeError(
            f"source kind drift: expected {expected_kind}, found {source_kind}"
        )
    git_prefix = _git_prefix(source)
    head = run_capture([*git_prefix, "rev-parse", "--verify", "HEAD"], cwd=source)
    branch = run_capture([*git_prefix, "rev-parse", "--abbrev-ref", "HEAD"], cwd=source)
    origin_main = run_capture(
        [*git_prefix, "rev-parse", "--verify", "refs/remotes/origin/main"],
        cwd=source,
    )
    status = run_capture(
        [*git_prefix, "status", "--porcelain=v1", "--untracked-files=normal"],
        cwd=source,
    )
    if head != expected_head:
        raise RuntimeError(f"HEAD drift: expected {expected_head}, found {head}")
    expected_branch = "main" if source_kind == "canonical-main" else "HEAD"
    if branch != expected_branch:
        raise RuntimeError(
            f"{source_kind} source has invalid branch state: expected {expected_branch}, found {branch}"
        )
    if origin_main != expected_head:
        raise RuntimeError(f"origin/main drift: expected {expected_head}, found {origin_main}")
    if status:
        raise RuntimeError("source repository is dirty")


def observe_tunnel_dispatcher_contention() -> dict[str, Any]:
    """Observe two bounded samples without draining, stopping, or signalling."""
    observed_at_unix_ns = time.time_ns()
    nonclaims = [
        "that_the_dispatcher_remains_idle_after_observation",
        "permission_to_stop_or_signal_dispatcher_work",
        "replacement_of_the_final_stable_drain_gate",
    ]
    samples: list[dict[str, Any]] = []
    for index in range(EARLY_DISPATCHER_SAMPLE_COUNT):
        sample_time_ns = time.time_ns()
        metrics_text = deploy_dual.core.http_text(deploy_dual.TUNNEL_METRICS_URL)
        if metrics_text is None:
            return {
                "schema_version": 1,
                "kind": "grabowski_tunnel_dispatcher_contention_observation",
                "observed_at_unix_ns": observed_at_unix_ns,
                "state": "unknown",
                "reason": "metrics-unavailable",
                "samples": samples,
                "does_not_establish": nonclaims,
            }
        try:
            observed = deploy_dual._parse_tunnel_drain_metrics(metrics_text)
        except deploy_dual.core.DeployError as exc:
            return {
                "schema_version": 1,
                "kind": "grabowski_tunnel_dispatcher_contention_observation",
                "observed_at_unix_ns": observed_at_unix_ns,
                "state": "unknown",
                "reason": "metrics-invalid",
                "error_type": type(exc).__name__,
                "error_phase": exc.phase,
                "samples": samples,
                "does_not_establish": nonclaims,
            }
        samples.append(
            {
                "observed_at_unix_ns": sample_time_ns,
                "metrics": {name: observed[name] for name in sorted(observed)},
                "stability": deploy_dual._tunnel_drain_stability_snapshot(observed),
            }
        )
        if index + 1 < EARLY_DISPATCHER_SAMPLE_COUNT:
            time.sleep(EARLY_DISPATCHER_SAMPLE_INTERVAL_SECONDS)

    first = samples[0]
    last = samples[-1]
    first_stability = first["stability"]
    last_stability = last["stability"]
    if (
        first_stability["process_start_time_seconds"]
        != last_stability["process_start_time_seconds"]
    ):
        return {
            "schema_version": 1,
            "kind": "grabowski_tunnel_dispatcher_contention_observation",
            "observed_at_unix_ns": observed_at_unix_ns,
            "state": "unknown",
            "reason": "dispatcher-generation-drift",
            "samples": samples,
            "does_not_establish": nonclaims,
        }
    regressed = {
        name: {
            "first": first_stability[name],
            "last": last_stability[name],
        }
        for name in deploy_dual.TUNNEL_DRAIN_COUNTER_NAMES
        if last_stability[name] < first_stability[name]
    }
    if regressed:
        return {
            "schema_version": 1,
            "kind": "grabowski_tunnel_dispatcher_contention_observation",
            "observed_at_unix_ns": observed_at_unix_ns,
            "state": "unknown",
            "reason": "dispatcher-counter-regression",
            "regressed_counters": regressed,
            "samples": samples,
            "does_not_establish": nonclaims,
        }

    busy_samples: list[dict[str, Any]] = []
    for sample in samples:
        metrics = sample["metrics"]
        # ants.Pool.Running() counts live worker goroutines, including workers
        # parked idle in the pool. It is therefore diagnostic capacity state,
        # not authoritative in-flight command evidence. Command admission and
        # completion are proven by the queue plus conserved poll/enqueue/final
        # response counters, and by their stability across bounded samples.
        mismatch = deploy_dual._tunnel_drain_idle_mismatch(metrics)
        if mismatch:
            busy_samples.append(
                {
                    "observed_at_unix_ns": sample["observed_at_unix_ns"],
                    "mismatch": mismatch,
                }
            )
    if busy_samples:
        return {
            "schema_version": 1,
            "kind": "grabowski_tunnel_dispatcher_contention_observation",
            "observed_at_unix_ns": observed_at_unix_ns,
            "state": "busy",
            "reason": "dispatcher-work-observed",
            "busy_samples": busy_samples,
            "samples": samples,
            "does_not_establish": nonclaims,
        }
    if first_stability != last_stability:
        return {
            "schema_version": 1,
            "kind": "grabowski_tunnel_dispatcher_contention_observation",
            "observed_at_unix_ns": observed_at_unix_ns,
            "state": "busy",
            "reason": "dispatcher-activity-between-samples",
            "samples": samples,
            "does_not_establish": nonclaims,
        }
    return {
        "schema_version": 1,
        "kind": "grabowski_tunnel_dispatcher_contention_observation",
        "observed_at_unix_ns": observed_at_unix_ns,
        "state": "idle",
        "reason": "two-stable-idle-samples",
        "samples": samples,
        "does_not_establish": nonclaims,
    }




def deployment_contention_preflight(
    *,
    expected_head: str,
    source_identity_sha256: str,
) -> dict[str, Any]:
    lock = deploy_core.observe_deployment_lock_availability(
        deploy_core.DEFAULT_LOCK_FILE,
        state_root=deploy_core.DEFAULT_STATE_ROOT,
    )
    try:
        dispatcher = observe_tunnel_dispatcher_contention()
    except Exception as exc:
        dispatcher = {
            "schema_version": 1,
            "kind": "grabowski_tunnel_dispatcher_contention_observation",
            "state": "unknown",
            "reason": "advisory-probe-failed",
            "error_type": type(exc).__name__,
            "does_not_establish": [
                "dispatcher_idle",
                "root_cause",
                "permission_to_skip_final_admission_and_drain",
            ],
        }
    # Dispatcher activity is advisory here. The apply path now engages a
    # source-bound operator admission marker before the authoritative drain,
    # so normal connector traffic must not starve validation indefinitely.
    # The deployment lock remains an early hard serialization gate.
    decision = "proceed" if lock.get("state") == "available" else "defer"
    material = {
        "schema_version": 1,
        "kind": "grabowski_runtime_deploy_contention_preflight",
        "expected_head": expected_head,
        "source_identity_sha256": source_identity_sha256,
        "observed_at_unix_ns": time.time_ns(),
        "lock": lock,
        "dispatcher": dispatcher,
        "decision": decision,
        "validation_started": False,
        "final_lock_and_drain_gates_required": True,
        "dispatcher_activity_advisory_before_final_admission": True,
        "does_not_establish": [
            "that_contention_will_not_appear_later",
            "deployment_authority",
            "permission_to_interrupt_foreign_work",
            "replacement_of_post_validation_mutation_gates",
        ],
    }
    return {**material, "evidence_sha256": canonical_json_sha256(material)}




def wait_for_deployment_window(
    *,
    repo: Path,
    canonical_repo: Path,
    source_kind: str,
    expected_head: str,
    source_identity_sha256: str,
) -> dict[str, Any]:
    """Retry only explicit contention deferrals before validation begins."""
    max_attempts = DEPLOYMENT_CONTENTION_MAX_ATTEMPTS
    for attempt in range(1, max_attempts + 1):
        verify_repository(repo, canonical_repo, source_kind, expected_head)
        emit(
            "repository-preflight-complete",
            expected_head=expected_head,
            source_kind=source_kind,
            source_identity_sha256=source_identity_sha256,
            contention_attempt=attempt,
            contention_max_attempts=max_attempts,
        )
        contention = deployment_contention_preflight(
            expected_head=expected_head,
            source_identity_sha256=source_identity_sha256,
        )
        decision = contention.get("decision")
        retry_delay_seconds = (
            DEPLOYMENT_CONTENTION_RETRY_DELAYS_SECONDS[attempt - 1]
            if attempt <= len(DEPLOYMENT_CONTENTION_RETRY_DELAYS_SECONDS)
            else None
        )
        observation = {
            **contention,
            "contention_attempt": attempt,
            "contention_max_attempts": max_attempts,
            "retry_delay_seconds": (
                retry_delay_seconds if decision == "defer" else None
            ),
        }
        emit("deployment-contention-preflight-complete", **observation)
        if decision == "proceed":
            return observation
        if decision != "defer":
            raise RuntimeError(
                "deployment contention preflight returned an invalid decision"
            )
        if retry_delay_seconds is None:
            emit(
                "deployment-contention-retry-exhausted",
                contention_attempt=attempt,
                contention_max_attempts=max_attempts,
                expected_head=expected_head,
                source_identity_sha256=source_identity_sha256,
                evidence_sha256=contention.get("evidence_sha256"),
                lock_state=contention.get("lock", {}).get("state"),
                dispatcher_state=contention.get("dispatcher", {}).get("state"),
            )
            raise DeploymentContentionDeferred(
                "deployment contention preflight exhausted its bounded retries: "
                f"attempts={max_attempts}, "
                f"lock={contention.get('lock', {}).get('state')}, "
                f"dispatcher={contention.get('dispatcher', {}).get('state')}"
            )
        emit(
            "deployment-contention-deferred",
            contention_attempt=attempt,
            contention_max_attempts=max_attempts,
            retry_delay_seconds=retry_delay_seconds,
            expected_head=expected_head,
            source_identity_sha256=source_identity_sha256,
            evidence_sha256=contention.get("evidence_sha256"),
            lock_state=contention.get("lock", {}).get("state"),
            dispatcher_state=contention.get("dispatcher", {}).get("state"),
        )
        time.sleep(retry_delay_seconds)
    raise AssertionError("unreachable deployment contention retry state")


def run_streamed(argv: list[str], *, cwd: Path, timeout_seconds: int, phase: str) -> None:
    emit(f"{phase}-start", argv=argv)
    process = subprocess.Popen(argv, cwd=cwd, env=child_environment(), stdin=subprocess.DEVNULL, stdout=None, stderr=None, start_new_session=True)
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        terminate_process_group(process)
        emit(f"{phase}-timeout", timeout_seconds=timeout_seconds)
        raise RuntimeError(f"{phase} timed out")
    emit(f"{phase}-complete", returncode=returncode)
    if returncode != 0:
        raise RuntimeError(f"{phase} failed with return code {returncode}")


def verify_live_manifest(expected_head: str) -> dict[str, Any]:
    manifest = Path.home() / ".local/share/grabowski-mcp/deployment-manifest.json"
    if not manifest.is_file():
        raise RuntimeError("live deployment manifest is missing")
    if manifest.stat().st_size > MAX_MANIFEST_BYTES:
        raise RuntimeError("live deployment manifest exceeds its size bound")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if payload.get("repo_head") != expected_head:
        raise RuntimeError("live deployment manifest does not match expected head")
    if payload.get("completion_status") != "complete":
        raise RuntimeError("live deployment is not complete")
    release_id = payload.get("release_id")
    if (
        not isinstance(release_id, str)
        or not release_id
        or len(release_id.encode("utf-8")) > 512
    ):
        raise RuntimeError("live deployment release_id is invalid")
    return {
        "release_id": release_id,
        "repo_head": payload.get("repo_head"),
        "completion_status": payload.get("completion_status"),
    }


def _blue_green_summary(result: dict[str, Any]) -> dict[str, Any]:
    receipt = result.get("receipt")
    if not isinstance(receipt, dict):
        raise RuntimeError("productive blue-green result lacks a receipt")
    summary = {
        "schema_version": 1,
        "kind": "grabowski_scheduled_blue_green_summary",
        "receipt_sha256": receipt.get("receipt_sha256"),
        "receipt_path": result.get("receipt_path"),
        "receipt_persisted": result.get(
            "receipt_persisted", result.get("receipt_path") is not None
        ),
        "receipt_persistence_error_type": result.get(
            "receipt_persistence_error_type"
        ),
        "blind_retry_allowed": False
        if result.get("receipt_persisted") is False
        else None,
        "outcome": receipt.get("outcome"),
        "expected_head": receipt.get("expected_head"),
        "source_identity_sha256": receipt.get("source_identity_sha256"),
        "blue_release_id": receipt.get("blue_release_id"),
        "green_release_id": receipt.get("green_release_id"),
        "green_readiness_sha256": (
            canonical_json_sha256(receipt["green_readiness"])
            if isinstance(receipt.get("green_readiness"), dict)
            else None
        ),
        "selector_switch_sha256": (
            receipt.get("selector_switch", {}).get("selector_sha256")
            if isinstance(receipt.get("selector_switch"), dict)
            else None
        ),
        "snapshot_rebind_receipt_sha256": (
            receipt.get("snapshot_rebind", {}).get("receipt_sha256")
            if isinstance(receipt.get("snapshot_rebind"), dict)
            else None
        ),
        "operator_drain_observation_sha256": (
            receipt.get("effect_terminalization", {}).get(
                "operator_observation_sha256"
            )
            if isinstance(receipt.get("effect_terminalization"), dict)
            else None
        ),
        "final_selector_sha256": (
            receipt.get("final_routing", {}).get("selector_sha256")
            if isinstance(receipt.get("final_routing"), dict)
            else None
        ),
        "authoritative_readback_sha256": (
            receipt.get("authoritative_readback", {}).get("readback_sha256")
            if isinstance(receipt.get("authoritative_readback"), dict)
            else None
        ),
    }
    return {**summary, "summary_sha256": canonical_json_sha256(summary)}


def classify_recovery_before_deploy(*, repo: Path, execution_head: str) -> dict[str, Any]:
    """Decide whether this run must continue a cutover instead of starting one.

    This is the bridge that makes the fix reachable by the runtime it fixes.

    The deployed operator is immutable: whatever release is serving MCP knows
    only the dispatch it shipped with, and that dispatch has exactly one
    outward-facing effect -- start *this* runner out of the verified source
    checkout. So the classification has to live here. Once a merged checkout is
    in place, the old operator's unchanged repair tool reaches the new
    classifier through the one hop it already performs, with no new MCP surface
    and no change to the running runtime.

    Two revisions meet here and must not be confused:

    ``execution_head``
        the revision this runner's code comes from -- the merged head, supplied
        by the existing self-deploy source contract.
    ``resume_target_head``
        the revision the stranded cutover is about -- read only from the
        authentic receipt, selector and release lineage.

    Deploying ``execution_head`` and resuming ``resume_target_head`` are
    different operations on different revisions. The caller names the first and
    never the second.
    """
    classification = deploy_dual.classify_midcutover_resume(
        expected_head=execution_head,
        receipt_root=None,
    )
    lane = classification.get("lane")
    if lane != midcutover.LANE_MID_CUTOVER_RESUME:
        # The classifier was asked about execution_head. A resumable cutover
        # about a *different* head is still a resumable cutover, so ask again
        # with the head the lineage itself names.
        open_target = _open_cutover_target_head(classification)
        if open_target is not None and open_target != execution_head:
            classification = deploy_dual.classify_midcutover_resume(
                expected_head=open_target,
                receipt_root=None,
            )
            lane = classification.get("lane")
    if lane == midcutover.LANE_SCHEDULED_DEPLOY:
        return {
            "lane": lane,
            "resume_required": False,
            "deploy_allowed": True,
            "execution_head": execution_head,
            "resume_target_head": None,
            "classification_sha256": classification.get("classification_sha256"),
        }
    if lane != midcutover.LANE_MID_CUTOVER_RESUME:
        # Neither lane is open.  A deployment is an effect, and an unclassified
        # state is not a licence to take one: the ordinary path must never be
        # the fallback for "we could not tell".
        return {
            "lane": lane,
            "resume_required": False,
            "deploy_allowed": False,
            "execution_head": execution_head,
            "resume_target_head": None,
            "reasons": classification.get("reasons"),
            "classification_sha256": classification.get("classification_sha256"),
        }
    binding = classification["resume_binding"]
    return {
        "lane": lane,
        "resume_required": True,
        "deploy_allowed": False,
        "execution_head": execution_head,
        "resume_target_head": binding["target_head"],
        "resume_phase": binding["resume_phase"],
        "cutover_id": binding["cutover_id"],
        "resume_binding_sha256": binding["binding_sha256"],
        "classification_sha256": classification.get("classification_sha256"),
        "classification": classification,
    }


def _open_cutover_target_head(classification: dict[str, Any]) -> str | None:
    """The head named by the one unresolved post-switch cutover, if there is one."""
    receipt = classification.get("receipt")
    if isinstance(receipt, dict) and isinstance(receipt.get("expected_head"), str):
        return receipt["expected_head"]
    evidence = classification.get("evidence")
    if not isinstance(evidence, dict):
        return None
    open_ids = evidence.get("unresolved_post_switch_cutover_ids")
    if not isinstance(open_ids, list) or len(open_ids) != 1:
        return None
    loaded = midcutover.load_receipts(deploy_dual.BLUE_GREEN_RECEIPT_ROOT)
    for candidate in midcutover.unresolved_post_switch_receipts(loaded["receipts"]):
        head = candidate.get("expected_head")
        if isinstance(head, str):
            return head
    return None


def run_midcutover_resume(*, repo: Path, decision: dict[str, Any]) -> dict[str, Any]:
    """Continue the stranded cutover; deploy nothing."""
    result = deploy_dual.resume_production_blue_green_cutover(
        repo=repo,
        expected_head=decision["resume_target_head"],
        require_resume_binding_sha256=decision["resume_binding_sha256"],
    )
    receipt = result.get("receipt") or {}
    summary = {
        "schema_version": 1,
        "kind": "grabowski_scheduled_midcutover_resume_summary",
        "receipt_sha256": receipt.get("receipt_sha256"),
        "receipt_path": result.get("receipt_path"),
        "outcome": result.get("outcome"),
        "resume_phase": receipt.get("resume_phase"),
        "resumed_cutover_id": receipt.get("resumed_cutover_id"),
        "resume_target_head": decision["resume_target_head"],
        "execution_head": decision["execution_head"],
    }
    summary["summary_sha256"] = canonical_json_sha256(summary)
    emit("midcutover-resume-receipt", **summary)
    return {**result, "summary": summary}


def run_productive_blue_green(
    *,
    repo: Path,
    expected_head: str,
    source_identity_sha256: str,
) -> dict[str, Any]:
    try:
        result = deploy_dual.run_production_blue_green_cutover(
            repo=repo,
            expected_head=expected_head,
            source_identity_sha256=source_identity_sha256,
        )
    except deploy_dual.ProductionBlueGreenReceiptPersistenceError as exc:
        result = {
            "receipt": exc.receipt,
            "receipt_path": None,
            "receipt_sha256": exc.receipt_sha256,
            "receipt_persisted": False,
            "receipt_persistence_error_type": exc.persistence_error_type,
            "outcome": exc.outcome,
            "error": None,
        }
        summary = _blue_green_summary(result)
        emit("blue-green-receipt-persistence-failed", **summary)
        return {**result, "summary": summary}
    result = {**result, "receipt_persisted": True}
    summary = _blue_green_summary(result)
    emit("blue-green-receipt", **summary)
    return {**result, "summary": summary}


def run_resume_only(
    recovery_decision: dict[str, Any], *, binding: dict[str, Any] | None
) -> int:
    """Continue the stranded cutover and stop; deploy nothing.

    A stranded cutover is a precondition, not a deployment. Resuming it and
    deploying the requested head are two effects on two revisions; collapsing
    them into one job would make the outcome unreconstructable, so this run ends
    after the resume and the controller starts the ordinary deploy separately.
    """

    resume_result = run_midcutover_resume(
        repo=Path(recovery_decision["repo"]), decision=recovery_decision
    )
    outcome = resume_result.get("outcome")
    failure_type = _resume_finalization_failure_type(resume_result)
    emit(
        "midcutover-recovery-terminal",
        resume_outcome=outcome,
        failure_type=failure_type,
        resume_target_head=recovery_decision["resume_target_head"],
        execution_head=recovery_decision["execution_head"],
        requested_head_deployment_performed=False,
        effect_applied=outcome in {"completed", "outcome_unknown"},
        retry_requires_reclassification=True,
        receipt_sha256=(resume_result.get("receipt") or {}).get(
            "receipt_sha256"
        ),
        authority="durable mid-cutover resume receipt",
    )
    if binding is not None:
        # The deployed finalization contract has no terminal state for
        # "the prerequisite was recovered but the requested head was not
        # deployed": completed demands this job's expected head *and* a
        # real release id, and outcome_unknown demands a blue-green
        # summary bound to that same head with an unpersisted receipt.
        # Neither is true here, and claiming either would be a lie about
        # a deployment that did not happen. The job therefore terminates
        # as a typed non-success whose failure_type names exactly what
        # occurred, and the durable bgcr receipt stays the authority on
        # the recovery itself.
        write_finalization_receipt(
            binding,
            final_status="failed",
            repo_head=None,
            release_id=None,
            failure_type=failure_type,
            blue_green=None,
        )
    return 0 if outcome == "completed" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--canonical-repo", type=Path, required=True)
    parser.add_argument("--source-kind", choices=sorted(SOURCE_KINDS), required=True)
    parser.add_argument("--source-identity-sha256", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--delay-seconds", type=int, required=True)
    args = parser.parse_args()
    repo = args.repo
    if not 5 <= args.delay_seconds <= 60:
        raise ValueError("delay_seconds must be between 5 and 60")
    if re.fullmatch(r"[0-9a-f]{64}", args.source_identity_sha256) is None:
        raise ValueError("source_identity_sha256 must be a lowercase SHA-256")
    binding: dict[str, Any] | None = None
    blue_green_result: dict[str, Any] | None = None
    live: dict[str, Any] | None = None
    try:
        binding = load_finalization_binding()
        if binding is not None and binding["expected_head"] != args.expected_head:
            raise RuntimeError("job finalization expected_head does not match runner arguments")
        assert_not_repoground_managed_source(repo)
        emit(
            "scheduled",
            repo=str(repo),
            canonical_repo=str(args.canonical_repo),
            source_kind=args.source_kind,
            source_identity_sha256=args.source_identity_sha256,
            expected_head=args.expected_head,
            delay_seconds=args.delay_seconds,
        )
        time.sleep(args.delay_seconds)
        wait_for_deployment_window(
            repo=repo,
            canonical_repo=args.canonical_repo,
            source_kind=args.source_kind,
            expected_head=args.expected_head,
            source_identity_sha256=args.source_identity_sha256,
        )
        run_streamed(["make", "validate"], cwd=repo, timeout_seconds=1_200, phase="validate")
        verify_repository(
            repo,
            args.canonical_repo,
            args.source_kind,
            args.expected_head,
        )
        recovery_decision = classify_recovery_before_deploy(
            repo=repo, execution_head=args.expected_head
        )
        emit("recovery-classification", **{
            key: value
            for key, value in recovery_decision.items()
            if key != "classification"
        })
        if recovery_decision["resume_required"]:
            return run_resume_only(
                {**recovery_decision, "repo": str(repo)}, binding=binding
            )
        if not recovery_decision.get("deploy_allowed"):
            raise RecoveryClassificationBlocked(
                "recovery classification is fail-closed; no deployment may start: "
                + ",".join(recovery_decision.get("reasons") or ["unclassified"])
            )
        blue_green_result = run_productive_blue_green(
            repo=repo,
            expected_head=args.expected_head,
            source_identity_sha256=args.source_identity_sha256,
        )
        if blue_green_result.get("outcome") != "completed":
            raise BlueGreenDeploymentIncomplete(
                "productive blue-green cutover did not complete; inspect its durable receipt"
            )
        primary_receipt_unpersisted = (
            blue_green_result.get("receipt_persisted") is False
        )
        live = verify_live_manifest(args.expected_head)
        verify_repository(
            repo,
            args.canonical_repo,
            args.source_kind,
            args.expected_head,
        )
        try:
            sidecars = reconcile_coding_agent_sidecars(repo, live)
        except Exception as sidecar_error:
            emit(
                "runtime-deployed-sidecar-outstanding",
                repo_head=live["repo_head"],
                release_id=live["release_id"],
                sidecar_status="outstanding",
                sidecar_error_type=type(sidecar_error).__name__,
            )
            raise SidecarInstallOutstanding(
                "runtime deployed but coding-agent sidecar reconciliation is outstanding"
            ) from sidecar_error
        verify_repository(
            repo,
            args.canonical_repo,
            args.source_kind,
            args.expected_head,
        )
        live = verify_live_manifest(args.expected_head)
        emit("coding-agent-sidecars-complete", **sidecars)
        emit(
            "complete",
            **live,
            coding_agent_sidecars=sidecars,
            blue_green=blue_green_result["summary"],
        )
        if binding is not None:
            write_finalization_receipt(
                binding,
                final_status=(
                    "outcome_unknown" if primary_receipt_unpersisted else "completed"
                ),
                repo_head=live["repo_head"],
                release_id=live["release_id"],
                failure_type=(
                    "ProductionBlueGreenReceiptPersistenceError"
                    if primary_receipt_unpersisted
                    else None
                ),
                blue_green=blue_green_result["summary"],
            )
        if primary_receipt_unpersisted:
            emit(
                "runtime-applied-primary-receipt-outstanding",
                repo_head=live["repo_head"],
                release_id=live["release_id"],
                blue_green=blue_green_result["summary"],
                blind_retry_allowed=False,
            )
            return 1
        return 0
    except Exception as exc:
        unresolved_without_primary_receipt = (
            isinstance(blue_green_result, dict)
            and blue_green_result.get("outcome") in ("completed", "outcome_unknown")
            and blue_green_result.get("receipt_persisted") is False
        )
        if binding is not None:
            try:
                write_finalization_receipt(
                    binding,
                    final_status=(
                        "outcome_unknown"
                        if unresolved_without_primary_receipt
                        else "failed"
                    ),
                    repo_head=(
                        live.get("repo_head")
                        if unresolved_without_primary_receipt and isinstance(live, dict)
                        else None
                    ),
                    release_id=(
                        live.get("release_id")
                        if unresolved_without_primary_receipt and isinstance(live, dict)
                        else None
                    ),
                    failure_type=type(exc).__name__,
                    blue_green=(
                        blue_green_result.get("summary")
                        if isinstance(blue_green_result, dict)
                        else None
                    ),
                )
            except Exception as receipt_exc:
                emit("finalization-receipt-failed", error_type=type(receipt_exc).__name__)
        emit("failed", error_type=type(exc).__name__, error=str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
