from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

import grabowski_coding_agent_router as router

MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
COMMAND_TIMEOUT_SECONDS = 20


class CodingAgentRouterCliError(RuntimeError):
    pass


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _clean_environment(catalog: dict[str, Any]) -> dict[str, str]:
    environment = dict(os.environ)
    for name in catalog["policy"].get("forbidden_api_key_env", []):
        environment.pop(name, None)
    environment["NO_COLOR"] = "1"
    return environment


def _run_metadata(
    argv: list[str], catalog: dict[str, Any], *, timeout: int = COMMAND_TIMEOUT_SECONDS
) -> dict[str, Any]:
    if not argv or not Path(argv[0]).is_absolute():
        return {"ok": False, "error_type": "non_absolute_executable"}
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=_clean_environment(catalog),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error_type": type(exc).__name__}
    stdout = result.stdout[: MAX_COMMAND_OUTPUT_BYTES + 1]
    stderr = result.stderr[: MAX_COMMAND_OUTPUT_BYTES + 1]
    if len(stdout) > MAX_COMMAND_OUTPUT_BYTES or len(stderr) > MAX_COMMAND_OUTPUT_BYTES:
        return {"ok": False, "error_type": "output_limit"}
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }


def _resolve_executable(binary: Any) -> str | None:
    if not isinstance(binary, str) or not binary:
        return None
    found = shutil.which(binary)
    if not found:
        return None
    try:
        resolved = Path(found).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        return None
    return str(resolved)


def _run_harness_metadata(
    harnesses: dict[str, Any],
    harness: str,
    arguments: list[str],
    catalog: dict[str, Any],
) -> dict[str, Any]:
    record = harnesses.get(harness, {})
    executable = record.get("binary") if isinstance(record, dict) else None
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        return {"ok": False, "error_type": "binary_unavailable"}
    return _run_metadata([executable, *arguments], catalog)


def _binary_versions(catalog: dict[str, Any]) -> dict[str, Any]:
    commands = {
        "codex": ["--version"],
        "claude": ["--version"],
        "agy": ["--version"],
        "grok": ["--version"],
        "jules": ["version"],
        "cline": ["--version"],
        "qwen-code": ["--version"],
        "aider": ["--version"],
        "goose": ["--version"],
    }
    result: dict[str, Any] = {}
    for harness, specification in catalog["harnesses"].items():
        path = _resolve_executable(specification.get("binary"))
        record: dict[str, Any] = {
            "binary": path,
            "available": harness == "grabowski" or path is not None,
        }
        if path is not None and harness in commands:
            observed = _run_metadata([path, *commands[harness]], catalog)
            record["version_ok"] = observed.get("ok") is True
            version_text = str(
                observed.get("stdout") or observed.get("stderr") or ""
            )
            record["version"] = version_text.strip().splitlines()[:3]
        result[harness] = record
    return result


def _claude_auth_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    auth_method: str | None = None
    if value.get("authMethod") == "claude.ai":
        auth_method = "claude.ai"
    subscription_type: str | None = None
    raw_subscription = value.get("subscriptionType")
    if raw_subscription == "pro":
        subscription_type = "pro"
    elif raw_subscription == "max":
        subscription_type = "max"
    elif raw_subscription == "team":
        subscription_type = "team"
    elif raw_subscription == "enterprise":
        subscription_type = "enterprise"
    return {
        "logged_in": value.get("loggedIn") is True,
        "auth_method": auth_method,
        "subscription_type": subscription_type,
    }


def _configured_models(catalog: dict[str, Any], harness: str) -> list[str]:
    return sorted(
        {
            str(route["model"])
            for route in catalog["routes"]
            if route.get("harness") == harness
        }
    )


def _probe(catalog: dict[str, Any]) -> dict[str, Any]:
    harnesses = _binary_versions(catalog)
    providers: dict[str, Any] = {}

    providers["codex"] = {
        "available": harnesses.get("codex", {}).get("available") is True,
        "models": _configured_models(catalog, "codex"),
    }

    claude_status = _run_harness_metadata(
        harnesses, "claude", ["auth", "status"], catalog
    )
    claude_auth: dict[str, Any] = {}
    if claude_status.get("ok") is True:
        try:
            value = json.loads(str(claude_status.get("stdout", "")))
        except json.JSONDecodeError:
            value = None
        claude_auth = _claude_auth_summary(value)
    providers["claude"] = {
        "available": harnesses.get("claude", {}).get("available") is True,
        "auth": claude_auth,
        "models": _configured_models(catalog, "claude"),
    }

    agy = _run_harness_metadata(harnesses, "agy", ["models"], catalog)
    providers["agy"] = {
        "available": harnesses.get("agy", {}).get("available") is True,
        "models": (
            [line.strip() for line in str(agy.get("stdout", "")).splitlines() if line.strip()]
            if agy.get("ok") is True
            else []
        ),
    }

    grok_status = _run_harness_metadata(
        harnesses, "grok", ["models"], catalog
    )
    grok_models: list[str] = []
    if grok_status.get("ok") is True:
        active = False
        for line in str(grok_status.get("stdout", "")).splitlines():
            clean = line.strip()
            if clean == "Available models:":
                active = True
                continue
            if active and clean.startswith("*"):
                grok_models.append(clean[1:].strip().split(" ", 1)[0])
    providers["grok"] = {
        "available": harnesses.get("grok", {}).get("available") is True,
        "logged_in": "logged in with grok.com"
        in str(grok_status.get("stdout", "")).lower(),
        "models": grok_models,
    }

    jules = _run_harness_metadata(
        harnesses, "jules", ["remote", "list", "--repo"], catalog
    )
    providers["jules"] = {
        "available": harnesses.get("jules", {}).get("available") is True,
        "authenticated": jules.get("ok") is True
        and bool(str(jules.get("stdout", "")).strip()),
        "repository_count": len(
            [line for line in str(jules.get("stdout", "")).splitlines() if line.strip()]
        ),
    }
    providers["cline"] = {
        "available": harnesses.get("cline", {}).get("available") is True,
        "config": {"free_entitlement_verified": False},
    }

    ollama_path = _resolve_executable("ollama")
    ollama = (
        _run_metadata([ollama_path, "list"], catalog)
        if ollama_path is not None
        else {"ok": False, "error_type": "binary_unavailable"}
    )
    local_models: list[str] = []
    if ollama.get("ok") is True:
        for line in str(ollama.get("stdout", "")).splitlines()[1:]:
            values = line.split()
            if values:
                local_models.append(values[0])
    providers["ollama"] = {
        "available": ollama_path is not None,
        "models": local_models,
        "loaded_models": [],
    }
    providers["local_harnesses"] = {
        key: harnesses.get(key, {}) for key in ("qwen-code", "aider", "goose")
    }

    verified_quota_pools: list[str] = []
    if providers["grok"].get("logged_in") is True:
        verified_quota_pools.append("grok-com")
    if providers["jules"].get("authenticated") is True:
        verified_quota_pools.append("jules-account")
    body = {
        "schema_version": 2,
        "observed_at": _iso_now(),
        "harnesses": harnesses,
        "providers": providers,
        "verified_quota_pools": verified_quota_pools,
        "api_key_environment_scrubbed": catalog["policy"].get(
            "forbidden_api_key_env", []
        ),
        "model_invocations": 0,
        "paid_api_requests_authorized": 0,
    }
    return {**body, "catalog_probe_sha256": _canonical_sha256(body)}


def _default_state(catalog_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "updated_at": _iso_now(),
        "catalog_sha256": catalog_sha256,
        "catalog": {},
        "pools": {},
        "routes": {},
        "history": {},
    }


def _load_mutable_state(catalog_sha256: str) -> dict[str, Any]:
    value = router._load_state()
    if not value:
        return _default_state(catalog_sha256)
    if value.get("schema_version") != 2:
        raise CodingAgentRouterCliError("router state schema_version must be 2")
    for key in ("catalog", "pools", "routes", "history"):
        if not isinstance(value.get(key, {}), dict):
            raise CodingAgentRouterCliError(f"router state {key} must be an object")
        value.setdefault(key, {})
    if value.get("catalog_sha256") != catalog_sha256:
        reset = _default_state(catalog_sha256)
        reset["history"] = value["history"]
        return reset
    return value


def _state_target_identity(path: Path) -> tuple[int, int] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise CodingAgentRouterCliError(
            "router state target must be an owned single-link regular file"
        )
    return metadata.st_dev, metadata.st_ino


def _atomic_write_private_json(path: Path, value: dict[str, Any]) -> None:
    path = path.expanduser()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_metadata = parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise CodingAgentRouterCliError(
            "router state parent is not a private user-owned directory"
        )
    initial_target = _state_target_identity(path)
    payload = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    if len(payload) > router.MAX_STATE_BYTES:
        raise CodingAgentRouterCliError("router state exceeds the size limit")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise CodingAgentRouterCliError("temporary router state is not owned regular file")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if _state_target_identity(path) != initial_target:
            raise CodingAgentRouterCliError("router state target changed before replace")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _write_probe(probe: dict[str, Any], validation: dict[str, Any]) -> None:
    observed_at = probe.get("observed_at")
    if router._parse_time(observed_at) is None:
        raise CodingAgentRouterCliError("probe observed_at must be timezone-aware")
    verified_pools = probe.get("verified_quota_pools", [])
    if (
        not isinstance(verified_pools, list)
        or any(not isinstance(pool_id, str) for pool_id in verified_pools)
        or len(set(verified_pools)) != len(verified_pools)
        or any(
            pool_id not in {"grok-com", "jules-account"}
            for pool_id in verified_pools
        )
    ):
        raise CodingAgentRouterCliError("probe verified_quota_pools is invalid")
    state = _load_mutable_state(str(validation["catalog_sha256"]))
    state["catalog"] = probe
    state["catalog_sha256"] = validation["catalog_sha256"]
    for pool_id in ("grok-com", "jules-account"):
        pool = state["pools"].get(pool_id)
        if pool_id in verified_pools:
            state["pools"].setdefault(pool_id, {})["verified_at"] = observed_at
        elif isinstance(pool, dict):
            pool.pop("verified_at", None)
    state["updated_at"] = _iso_now()
    _atomic_write_private_json(router._state_path(), state)


def _status(catalog: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    state = router._load_state()
    bound = bool(state) and state.get("catalog_sha256") == validation["catalog_sha256"]
    fresh = bound and router._state_catalog_fresh(state)
    return {
        "schema_version": 2,
        "validation": validation,
        "catalog_source": validation.get("catalog_source"),
        "catalog_fresh": fresh,
        "live_catalog": state.get("catalog", {}) if isinstance(state, dict) else {},
        "pools": {
            key: router._effective_pool(key, catalog, state)
            for key in catalog["quota_pools"]
        }
        if isinstance(state, dict)
        else {},
        "route_stats": state.get("routes", {}) if isinstance(state, dict) else {},
        "automatic_execution_authorized": False,
        "authoritative_work": "direct_operator",
        "external_agent_authority": "advisory_review_or_explicit_contrast_only",
    }


def _bounded_nonnegative_number(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise CodingAgentRouterCliError(f"{label} must be a nonnegative finite number")
    return float(value)


def _observe(
    arguments: argparse.Namespace,
    catalog: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    route = router._route_map(catalog).get(arguments.route)
    if route is None or route.get("controller") is True:
        raise CodingAgentRouterCliError("observe requires a known external route")
    duration = _bounded_nonnegative_number(arguments.duration_seconds, "duration_seconds")
    rework = _bounded_nonnegative_number(arguments.rework_minutes, "rework_minutes")
    reported_cost = _bounded_nonnegative_number(
        arguments.reported_cost_usd, "reported_cost_usd"
    )
    remaining_ratio = _bounded_nonnegative_number(
        arguments.remaining_ratio, "remaining_ratio"
    )
    if remaining_ratio is not None and remaining_ratio > 1:
        raise CodingAgentRouterCliError(
            "remaining_ratio must be between zero and one"
        )
    if arguments.reset_at is not None and router._parse_time(arguments.reset_at) is None:
        raise CodingAgentRouterCliError(
            "reset_at must be a timezone-aware timestamp"
        )
    state = _load_mutable_state(str(validation["catalog_sha256"]))
    record = state["routes"].setdefault(arguments.route, {})
    counters: dict[str, int] = {}
    for field in ("runs", "successes", "failures"):
        value = record.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CodingAgentRouterCliError(
                f"existing route counter {field} is invalid"
            )
        counters[field] = value
    record["runs"] = counters["runs"] + 1
    record["last_outcome"] = arguments.outcome
    record["last_observed_at"] = _iso_now()
    if arguments.outcome == "success":
        record["successes"] = counters["successes"] + 1
    else:
        record["failures"] = counters["failures"] + 1
    if duration is not None:
        record["last_duration_seconds"] = duration
    if rework is not None:
        observations = record.get("rework_observations", 0)
        previous_average = record.get("average_rework_minutes", 0.0)
        if (
            isinstance(observations, bool)
            or not isinstance(observations, int)
            or observations < 0
            or isinstance(previous_average, bool)
            or not isinstance(previous_average, (int, float))
            or not math.isfinite(float(previous_average))
            or float(previous_average) < 0
        ):
            raise CodingAgentRouterCliError("existing rework history is invalid")
        record["average_rework_minutes"] = (
            float(previous_average) * observations + rework
        ) / (observations + 1)
        record["rework_observations"] = observations + 1
    if reported_cost is not None:
        record["last_reported_cost_usd"] = reported_cost
    boundary = datetime.now(timezone.utc)
    for pool_id in route["quota_pools"]:
        pool = state["pools"].setdefault(pool_id, {})
        if arguments.outcome == "success":
            pool["status"] = "available"
            pool["last_success_at"] = _iso_now()
            for field in ("blocked_reason", "cooldown_until", "reset_at"):
                pool.pop(field, None)
        elif arguments.outcome == "rate_limit":
            pool["status"] = "cooldown"
            pool.pop("blocked_reason", None)
            pool.pop("reset_at", None)
            pool["cooldown_until"] = (boundary + timedelta(minutes=15)).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z")
        elif arguments.outcome == "quota_exhausted":
            pool["status"] = "exhausted"
            pool.pop("blocked_reason", None)
            pool.pop("cooldown_until", None)
            pool["reset_at"] = arguments.reset_at or (
                boundary + timedelta(hours=5)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        elif arguments.outcome == "auth_error":
            pool["status"] = "blocked"
            pool.pop("cooldown_until", None)
            pool.pop("reset_at", None)
            pool["blocked_reason"] = "authentication error"
        elif arguments.outcome == "transient":
            pool["status"] = "cooldown"
            pool.pop("blocked_reason", None)
            pool.pop("reset_at", None)
            pool["cooldown_until"] = (boundary + timedelta(minutes=5)).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z")
        if remaining_ratio is not None:
            pool["remaining_ratio"] = remaining_ratio
        pool["updated_at"] = _iso_now()
    state["updated_at"] = _iso_now()
    _atomic_write_private_json(router._state_path(), state)
    return {"recorded": True, "route": arguments.route, "route_state": record}


def _set_quota(
    arguments: argparse.Namespace,
    catalog: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    if arguments.pool not in catalog["quota_pools"]:
        raise CodingAgentRouterCliError("set-quota requires a known quota pool")
    if arguments.remaining_ratio is not None and not 0 <= arguments.remaining_ratio <= 1:
        raise CodingAgentRouterCliError("remaining_ratio must be between zero and one")
    for key in ("active_sessions", "used_tasks"):
        value = getattr(arguments, key)
        if value is not None and value < 0:
            raise CodingAgentRouterCliError(f"{key} must be nonnegative")
    for key in ("reset_at", "cooldown_until"):
        value = getattr(arguments, key)
        if value is not None and router._parse_time(value) is None:
            raise CodingAgentRouterCliError(f"{key} must be a timezone-aware timestamp")
    state = _load_mutable_state(str(validation["catalog_sha256"]))
    pool = state["pools"].setdefault(arguments.pool, {})
    if arguments.status in {"unknown", "available"}:
        for field in (
            "blocked_reason",
            "cooldown_until",
            "remaining_ratio",
            "reset_at",
        ):
            pool.pop(field, None)
    elif arguments.status == "constrained":
        for field in ("blocked_reason", "cooldown_until", "reset_at"):
            pool.pop(field, None)
    elif arguments.status == "cooldown":
        pool.pop("blocked_reason", None)
        pool.pop("reset_at", None)
    elif arguments.status == "exhausted":
        pool.pop("blocked_reason", None)
        pool.pop("cooldown_until", None)
    elif arguments.status == "blocked":
        pool.pop("cooldown_until", None)
        pool.pop("reset_at", None)
    pool["status"] = arguments.status
    for key in (
        "remaining_ratio",
        "reset_at",
        "cooldown_until",
        "active_sessions",
        "used_tasks",
    ):
        value = getattr(arguments, key)
        if value is not None:
            pool[key] = value
    if arguments.verified_now:
        pool["verified_at"] = _iso_now()
    pool["updated_at"] = _iso_now()
    state["updated_at"] = _iso_now()
    _atomic_write_private_json(router._state_path(), state)
    return {"updated": True, "pool": arguments.pool, "pool_state": pool}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Direct-first coding-agent metadata and advisory router."
    )
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    probe = commands.add_parser("probe")
    probe.add_argument("--no-write", action="store_true")
    commands.add_parser("inventory")
    commands.add_parser("status")

    recommend = commands.add_parser("recommend")
    recommend.add_argument("--task-class", required=True)
    recommend.add_argument("--changed-files", type=int, default=1)
    recommend.add_argument("--duration-minutes", type=int, default=30)
    recommend.add_argument("--novelty", choices=["low", "medium", "high"], default="medium")
    recommend.add_argument("--risk-flag", action="append", default=[])
    recommend.add_argument("--latency-priority", action="store_true")
    recommend.add_argument("--need-review", action="store_true")

    observe = commands.add_parser("observe")
    observe.add_argument("--route", required=True)
    observe.add_argument(
        "--outcome",
        required=True,
        choices=[
            "success",
            "rate_limit",
            "quota_exhausted",
            "auth_error",
            "transient",
            "quality_failure",
        ],
    )
    observe.add_argument("--remaining-ratio", type=float)
    observe.add_argument("--reset-at")
    observe.add_argument("--duration-seconds", type=float)
    observe.add_argument("--rework-minutes", type=float)
    observe.add_argument("--reported-cost-usd", type=float)

    quota = commands.add_parser("set-quota")
    quota.add_argument("--pool", required=True)
    quota.add_argument(
        "--status",
        required=True,
        choices=["unknown", "available", "constrained", "cooldown", "exhausted", "blocked"],
    )
    quota.add_argument("--remaining-ratio", type=float)
    quota.add_argument("--reset-at")
    quota.add_argument("--cooldown-until")
    quota.add_argument("--active-sessions", type=int)
    quota.add_argument("--used-tasks", type=int)
    quota.add_argument("--verified-now", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        catalog, validation = router._load_catalog()
        if arguments.command == "validate":
            output: dict[str, Any] = validation
        elif arguments.command == "probe":
            output = _probe(catalog)
            if not arguments.no_write:
                _write_probe(output, validation)
        elif arguments.command == "inventory":
            output = router.grabowski_coding_agent_catalog(include_disabled=True)
        elif arguments.command == "status":
            output = _status(catalog, validation)
        elif arguments.command == "recommend":
            output = router.grabowski_coding_agent_route(
                task_class=arguments.task_class,
                changed_files=arguments.changed_files,
                duration_minutes=arguments.duration_minutes,
                novelty=arguments.novelty,
                risk_flags=arguments.risk_flag,
                latency_priority=arguments.latency_priority,
                need_review=arguments.need_review,
            )
        elif arguments.command == "observe":
            output = _observe(arguments, catalog, validation)
        elif arguments.command == "set-quota":
            output = _set_quota(arguments, catalog, validation)
        else:
            raise CodingAgentRouterCliError("unsupported command")
        print(json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "error": "coding_agent_router_cli_failed_closed",
                    "error_type": type(exc).__name__,
                    "automatic_execution_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
