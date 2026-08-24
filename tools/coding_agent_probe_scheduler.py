#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator


DEFAULT_ROUTER = Path.home() / "bin" / "agent-route"
DEFAULT_STATE = (
    Path.home()
    / ".local"
    / "state"
    / "grabowski"
    / "coding-agent-router"
    / "state.json"
)
DEFAULT_STATE_DIR = DEFAULT_STATE.parent
DEFAULT_ROUTER_DIGEST = (
    Path.home() / ".config" / "grabowski" / "coding-agent-probe-scheduler-router.sha256"
)
DEFAULT_LOCK = DEFAULT_STATE_DIR / "probe-scheduler.lock"
DEFAULT_RECEIPT = DEFAULT_STATE_DIR / "probe-scheduler-receipt.json"
DEFAULT_FAILURE = DEFAULT_STATE_DIR / "probe-scheduler-failure.json"
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_ROUTER_BYTES = 2 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
IO_CHUNK_BYTES = 64 * 1024
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
SPECIAL_PERMISSION_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
PROCESS_TERMINATION_GRACE_SECONDS = 2
PROBE_DIGEST_DOMAIN = b"grabowski-coding-agent-probe-v3"
PROBE_DIGEST_FIELDS = (
    "schema_version",
    "observed_at",
    "harnesses",
    "providers",
    "verified_quota_pools",
    "api_key_environment_scrubbed",
    "model_invocations",
    "paid_api_requests_authorized",
)
PROBE_VERIFIABLE_QUOTA_POOLS = (
    "grok-com",
    "jules-account",
    "opencode-free",
    "openrouter-ox-alpha-preview",
    "openhands-account",
)
SENSITIVE_PROBE_FIELD_TOKENS = (
    "password",
    "passwd",
    "token",
    "secret",
    "credential",
    "api_key",
    "apikey",
)
ALLOWED_SENSITIVE_METADATA_FIELDS = frozenset({"api_key_environment_scrubbed"})
FORBIDDEN_API_KEY_ENV = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "AZURE_OPENAI_API_KEY",
)
EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "OPENROUTER_API_KEY",
)
DEFAULT_CODEX_SESSIONS_ROOT = Path.home() / ".codex" / "sessions"
CODEX_QUOTA_POOL = "openai-agentic"
CODEX_QUOTA_SOURCE = "codex-rollout-rate-limits-v1"
CODEX_APP_SERVER_SOURCE = "codex-app-server-account-rate-limits-v1"
CODEX_SPARK_MODEL = "gpt-5.3-codex-spark"
CODEX_SPARK_QUOTA_POOL = "openai-codex-spark"
CODEX_SPARK_LIMIT_ID = "codex_bengalfox"
CODEX_SPARK_LIMIT_NAME = "GPT-5.3-Codex-Spark"
CODEX_ALLOWED_PLAN_TYPES = frozenset({"prolite"})
MAX_CODEX_DAY_DIRECTORIES = 4
MAX_CODEX_DIRECTORY_ENTRIES = 512
MAX_CODEX_ROLLOUT_FILES = 128
MAX_CODEX_ROLLOUT_BYTES = 16 * 1024 * 1024
MAX_CODEX_ROLLOUT_TAIL_BYTES = 256 * 1024
MAX_CODEX_ROLLOUT_SCAN_BYTES = 32 * 1024 * 1024
MAX_CODEX_QUOTA_AGE_SECONDS = 36 * 60 * 60


class ProbeSchedulerError(RuntimeError):
    pass


class LockBusy(ProbeSchedulerError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def assert_probe_digest_safe(value: Any, *, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for raw_key, nested in value.items():
            key = str(raw_key)
            normalized = key.casefold().replace("-", "_")
            if (
                key not in ALLOWED_SENSITIVE_METADATA_FIELDS
                and any(
                    normalized == token
                    or normalized.startswith(f"{token}_")
                    or normalized.endswith(f"_{token}")
                    for token in SENSITIVE_PROBE_FIELD_TOKENS
                )
            ):
                location = ".".join((*path, key))
                raise ProbeSchedulerError(
                    f"probe digest payload contains sensitive field: {location}"
                )
            assert_probe_digest_safe(nested, path=(*path, key))
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            assert_probe_digest_safe(nested, path=(*path, str(index)))


def probe_digest(value: dict[str, Any]) -> str:
    missing = [field for field in PROBE_DIGEST_FIELDS if field not in value]
    if missing:
        raise ProbeSchedulerError(
            f"probe digest payload is missing fields: {', '.join(missing)}"
        )
    projection = {field: value[field] for field in PROBE_DIGEST_FIELDS}
    assert_probe_digest_safe(projection)
    payload = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(PROBE_DIGEST_DOMAIN, payload, hashlib.sha256).hexdigest()


def value_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _owned_directory(path: Path, *, label: str) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022
    ):
        raise ProbeSchedulerError(f"{label} is not an owned real directory")
    return True


def _bounded_directory_entries(path: Path) -> list[Path]:
    entries: list[Path] = []
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                if len(entries) >= MAX_CODEX_DIRECTORY_ENTRIES:
                    raise ProbeSchedulerError(
                        "Codex sessions directory exceeds the bounded entry limit"
                    )
                entries.append(Path(entry.path))
    except OSError as exc:
        raise ProbeSchedulerError(
            "cannot enumerate Codex sessions directory"
        ) from exc
    return sorted(entries, key=lambda item: item.name, reverse=True)


def _codex_rollout_candidates(root: Path) -> list[Path]:
    if not _owned_directory(root, label="Codex sessions root"):
        return []
    day_directories: list[Path] = []
    for year in _bounded_directory_entries(root):
        if not year.name.isdigit() or len(year.name) != 4:
            continue
        if not _owned_directory(year, label="Codex sessions year"):
            continue
        for month in _bounded_directory_entries(year):
            if not month.name.isdigit() or len(month.name) != 2:
                continue
            if not _owned_directory(month, label="Codex sessions month"):
                continue
            for day in _bounded_directory_entries(month):
                if not day.name.isdigit() or len(day.name) != 2:
                    continue
                if not _owned_directory(day, label="Codex sessions day"):
                    continue
                day_directories.append(day)
                if len(day_directories) >= MAX_CODEX_DAY_DIRECTORIES:
                    break
            if len(day_directories) >= MAX_CODEX_DAY_DIRECTORIES:
                break
        if len(day_directories) >= MAX_CODEX_DAY_DIRECTORIES:
            break
    candidates: list[tuple[int, Path]] = []
    for day in day_directories:
        for entry in _bounded_directory_entries(day):
            if not entry.name.startswith("rollout-") or entry.suffix != ".jsonl":
                continue
            try:
                metadata = entry.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o077
                or not 1 <= metadata.st_size <= MAX_CODEX_ROLLOUT_BYTES
            ):
                continue
            candidates.append((metadata.st_mtime_ns, entry))
    candidates.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
    return [path for _mtime, path in candidates[:MAX_CODEX_ROLLOUT_FILES]]


def _read_codex_rollout_tail(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProbeSchedulerError("cannot open Codex rollout receipt") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 1 <= before.st_size <= MAX_CODEX_ROLLOUT_BYTES
        ):
            raise ProbeSchedulerError("Codex rollout receipt is unsafe")
        offset = max(0, before.st_size - MAX_CODEX_ROLLOUT_TAIL_BYTES)
        os.lseek(descriptor, offset, os.SEEK_SET)
        remaining = before.st_size - offset
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, IO_CHUNK_BYTES))
            if not chunk:
                raise ProbeSchedulerError("Codex rollout receipt ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev, before.st_ino, before.st_mode, before.st_uid,
        before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev, after.st_ino, after.st_mode, after.st_uid,
        after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise ProbeSchedulerError("Codex rollout receipt changed while being read")
    payload = b"".join(chunks)
    if offset:
        separator = payload.find(b"\n")
        payload = b"" if separator < 0 else payload[separator + 1 :]
    return payload


def _codex_quota_window(
    value: Any,
    *,
    label: str,
    observed_at: datetime,
    now: datetime,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    used_percent = value.get("used_percent")
    resets_at = value.get("resets_at")
    window_minutes = value.get("window_minutes")
    if (
        isinstance(used_percent, bool)
        or not isinstance(used_percent, (int, float))
        or not math.isfinite(float(used_percent))
        or not 0 <= float(used_percent) <= 100
        or isinstance(resets_at, bool)
        or not isinstance(resets_at, int)
        or isinstance(window_minutes, bool)
        or not isinstance(window_minutes, int)
        or not 0 < window_minutes <= 30 * 24 * 60
    ):
        return None
    try:
        reset_at = datetime.fromtimestamp(resets_at, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    latest_plausible_reset = observed_at + timedelta(minutes=window_minutes + 5)
    if reset_at <= now or reset_at > latest_plausible_reset:
        return None
    reset_text = (
        reset_at.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    return {
        "label": label,
        "remaining_ratio": round(
            max(0.0, 1.0 - float(used_percent) / 100.0), 12
        ),
        "used_percent": float(used_percent),
        "reset_at": reset_text,
        "reset_at_unix": resets_at,
        "window_minutes": window_minutes,
    }


def _codex_quota_event(
    value: Any, *, now: datetime, line_sha256: str
) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("type") != "event_msg":
        return None
    observed_at = parse_time(value.get("timestamp"))
    payload = value.get("payload")
    rate_limits = payload.get("rate_limits") if isinstance(payload, dict) else None
    if observed_at is None or not isinstance(rate_limits, dict):
        return None
    age_seconds = (now - observed_at).total_seconds()
    if not 0 <= age_seconds <= MAX_CODEX_QUOTA_AGE_SECONDS:
        return None
    if rate_limits.get("limit_id") != "codex":
        return None
    windows: list[dict[str, Any]] = []
    for label in ("primary", "secondary", "individual_limit"):
        raw_window = rate_limits.get(label)
        if raw_window is None:
            continue
        window = _codex_quota_window(
            raw_window, label=label, observed_at=observed_at, now=now
        )
        if window is None:
            return None
        windows.append(window)
    if not windows:
        return None
    limiting_window = min(
        windows,
        key=lambda item: (
            float(item["remaining_ratio"]),
            -int(item["reset_at_unix"]),
        ),
    )
    reached_type = rate_limits.get("rate_limit_reached_type")
    if reached_type is not None and not isinstance(reached_type, str):
        return None
    spend_control_reached = rate_limits.get("spend_control_reached")
    if spend_control_reached not in {None, True, False}:
        return None
    credits = rate_limits.get("credits")
    purchased_credits_available: bool | None = None
    if isinstance(credits, dict) and isinstance(credits.get("has_credits"), bool):
        purchased_credits_available = credits["has_credits"]
    status = (
        "exhausted"
        if any(float(item["used_percent"]) >= 100 for item in windows)
        or bool(reached_type)
        or spend_control_reached is True
        else "available"
    )
    plan_type = rate_limits.get("plan_type")
    if not isinstance(plan_type, str) or not plan_type or len(plan_type) > 64:
        plan_type = None
    core = {
        "schema_version": 1,
        "pool": CODEX_QUOTA_POOL,
        "source": CODEX_QUOTA_SOURCE,
        "status": status,
        "remaining_ratio": limiting_window["remaining_ratio"],
        "used_percent": limiting_window["used_percent"],
        "reset_at": limiting_window["reset_at"],
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "window_minutes": limiting_window["window_minutes"],
        "limiting_window": limiting_window["label"],
        "limits": windows,
        "plan_type": plan_type,
        "purchased_credits_available": purchased_credits_available,
        "paid_fallback_authorized": False,
        "model_invocations": 0,
        "source_line_sha256": line_sha256,
    }
    return {**core, "observation_sha256": value_sha256(core)}


def collect_codex_quota_observation(
    root: Path, *, now: datetime | None = None
) -> dict[str, Any]:
    boundary = (now or utc_now()).astimezone(timezone.utc)
    best: tuple[datetime, dict[str, Any]] | None = None
    try:
        candidates = _codex_rollout_candidates(root)
    except (OSError, ProbeSchedulerError):
        candidates = []
    scanned_bytes = 0
    for path in candidates:
        try:
            payload = _read_codex_rollout_tail(path)
        except ProbeSchedulerError:
            continue
        if scanned_bytes + len(payload) > MAX_CODEX_ROLLOUT_SCAN_BYTES:
            break
        scanned_bytes += len(payload)
        for line in reversed(payload.splitlines()):
            if not line or len(line) > MAX_COMMAND_OUTPUT_BYTES:
                continue
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            observation = _codex_quota_event(
                value, now=boundary, line_sha256=bytes_sha256(line)
            )
            if observation is None:
                continue
            observed = parse_time(observation["observed_at"])
            assert observed is not None
            if best is None or observed > best[0]:
                best = observed, observation
            break
    if best is not None:
        return best[1]
    core = {
        "schema_version": 1,
        "pool": CODEX_QUOTA_POOL,
        "source": CODEX_QUOTA_SOURCE,
        "status": "unknown",
        "reason": "no_fresh_provider_quota_receipt",
        "observed_at": iso_now(),
        "paid_fallback_authorized": False,
        "model_invocations": 0,
    }
    return {**core, "observation_sha256": value_sha256(core)}



def _unknown_codex_direct_observation(pool: str, reason: str) -> dict[str, Any]:
    core = {
        "schema_version": 1,
        "pool": pool,
        "source": CODEX_APP_SERVER_SOURCE,
        "status": "unknown",
        "reason": reason,
        "observed_at": iso_now(),
        "paid_fallback_authorized": False,
        "model_invocations": 0,
    }
    return {**core, "observation_sha256": value_sha256(core)}


def _provider_limit_observation(
    *,
    pool: str,
    limit_id: str,
    value: dict[str, Any],
    observed_at: str,
    expected_limit_name: str | None = None,
) -> dict[str, Any]:
    if value.get("limitId") != limit_id:
        raise ProbeSchedulerError("Codex provider limit id mismatch")
    if expected_limit_name is not None and value.get("limitName") != expected_limit_name:
        raise ProbeSchedulerError("Codex provider limit name mismatch")
    plan_type = value.get("planType")
    if plan_type not in CODEX_ALLOWED_PLAN_TYPES:
        raise ProbeSchedulerError("Codex provider plan type is not allowlisted")
    windows: list[dict[str, Any]] = []
    for label in ("primary", "secondary"):
        raw_window = value.get(label)
        if raw_window is None:
            if label == "primary":
                raise ProbeSchedulerError("Codex provider primary limit is missing")
            continue
        if not isinstance(raw_window, dict):
            raise ProbeSchedulerError("Codex provider limit window is invalid")
        used_percent = raw_window.get("usedPercent")
        resets_at = raw_window.get("resetsAt")
        window_minutes = raw_window.get("windowDurationMins")
        if (
            isinstance(used_percent, bool)
            or not isinstance(used_percent, (int, float))
            or not 0 <= float(used_percent) <= 100
            or isinstance(resets_at, bool)
            or not isinstance(resets_at, int)
            or resets_at <= 0
            or isinstance(window_minutes, bool)
            or not isinstance(window_minutes, int)
            or window_minutes <= 0
        ):
            raise ProbeSchedulerError("Codex provider limit window is invalid")
        remaining_ratio = max(0.0, 1.0 - float(used_percent) / 100.0)
        windows.append(
            {
                "label": label,
                "remaining_ratio": remaining_ratio,
                "used_percent": float(used_percent),
                "reset_at": datetime.fromtimestamp(resets_at, timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "reset_at_unix": resets_at,
                "window_minutes": window_minutes,
            }
        )
    limiting_window = min(
        windows,
        key=lambda item: (
            float(item["remaining_ratio"]),
            -int(item["reset_at_unix"]),
        ),
    )
    reached_type = value.get("rateLimitReachedType")
    if reached_type is not None and not isinstance(reached_type, str):
        raise ProbeSchedulerError("Codex provider reached type is invalid")
    credits = value.get("credits")
    if pool == CODEX_SPARK_QUOTA_POOL:
        if credits is not None:
            raise ProbeSchedulerError("Spark provider limit unexpectedly exposes credits")
    elif isinstance(credits, dict):
        if credits.get("hasCredits") is not False or credits.get("unlimited") is not False:
            raise ProbeSchedulerError("Codex purchased-credit state is not eligible for automatic routing")
    elif credits is not None:
        raise ProbeSchedulerError("Codex provider credit state is invalid")
    status = (
        "exhausted"
        if any(float(item["used_percent"]) >= 100 for item in windows)
        or bool(reached_type)
        else "available"
    )
    core = {
        "schema_version": 1,
        "pool": pool,
        "source": CODEX_APP_SERVER_SOURCE,
        "status": status,
        "remaining_ratio": limiting_window["remaining_ratio"],
        "used_percent": limiting_window["used_percent"],
        "reset_at": limiting_window["reset_at"],
        "observed_at": observed_at,
        "window_minutes": limiting_window["window_minutes"],
        "limiting_window": limiting_window["label"],
        "limits": [
            {key: item[key] for key in ("label", "remaining_ratio", "used_percent", "reset_at", "window_minutes")}
            for item in windows
        ],
        "plan_type": plan_type,
        "provider_limit_id": limit_id,
        "paid_fallback_authorized": False,
        "model_invocations": 0,
    }
    return {**core, "observation_sha256": value_sha256(core)}


def parse_codex_app_server_observations(
    model_result: dict[str, Any],
    rate_limit_result: dict[str, Any],
    *,
    observed_at: str | None = None,
) -> dict[str, dict[str, Any]]:
    stamp = observed_at or iso_now()
    models = model_result.get("data")
    if not isinstance(models, list):
        raise ProbeSchedulerError("Codex model list is invalid")
    spark = [
        item
        for item in models
        if isinstance(item, dict) and item.get("id") == CODEX_SPARK_MODEL
    ]
    spark_efforts = spark[0].get("supportedReasoningEfforts") if len(spark) == 1 else None
    if (
        len(spark) != 1
        or spark[0].get("model") != CODEX_SPARK_MODEL
        or spark[0].get("hidden") is not False
        or spark[0].get("displayName") != CODEX_SPARK_LIMIT_NAME
        or not isinstance(spark_efforts, list)
        or any(
            not isinstance(item, dict)
            or not isinstance(item.get("reasoningEffort"), str)
            for item in spark_efforts
        )
        or "low" not in {item["reasoningEffort"] for item in spark_efforts}
    ):
        raise ProbeSchedulerError("Spark model identity is not live-visible")
    by_limit = rate_limit_result.get("rateLimitsByLimitId")
    if not isinstance(by_limit, dict):
        raise ProbeSchedulerError("Codex provider rate-limit map is invalid")
    main_value = by_limit.get("codex")
    spark_value = by_limit.get(CODEX_SPARK_LIMIT_ID)
    if not isinstance(main_value, dict) or not isinstance(spark_value, dict):
        raise ProbeSchedulerError("Codex provider required rate limits are missing")
    reset_credits = rate_limit_result.get("rateLimitResetCredits")
    if not isinstance(reset_credits, dict):
        raise ProbeSchedulerError("Codex rate-limit reset-credit state is missing")
    available_count = reset_credits.get("availableCount")
    if isinstance(available_count, bool) or not isinstance(available_count, int) or available_count != 0:
        raise ProbeSchedulerError("Codex rate-limit reset credits are not eligible for automatic routing")
    main = _provider_limit_observation(
        pool=CODEX_QUOTA_POOL,
        limit_id="codex",
        value=main_value,
        observed_at=stamp,
    )
    spark_observation = _provider_limit_observation(
        pool=CODEX_SPARK_QUOTA_POOL,
        limit_id=CODEX_SPARK_LIMIT_ID,
        value=spark_value,
        observed_at=stamp,
        expected_limit_name=CODEX_SPARK_LIMIT_NAME,
    )
    if main["plan_type"] != spark_observation["plan_type"]:
        raise ProbeSchedulerError("Codex main and Spark plan types differ")
    return {CODEX_QUOTA_POOL: main, CODEX_SPARK_QUOTA_POOL: spark_observation}

def read_json(path: Path, *, required: bool = True) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if required:
            raise ProbeSchedulerError(f"missing JSON file: {path}") from None
        return {}, b""
    except OSError as exc:
        raise ProbeSchedulerError(f"cannot open JSON file: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProbeSchedulerError(f"JSON path is not a regular file: {path}")
        if before.st_uid != os.getuid():
            raise ProbeSchedulerError(f"JSON file has an unexpected owner: {path}")
        if before.st_size < 0 or before.st_size > MAX_STATE_BYTES:
            raise ProbeSchedulerError(f"JSON file exceeds the size limit: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, IO_CHUNK_BYTES))
            if not chunk:
                raise ProbeSchedulerError(f"JSON file ended early: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ProbeSchedulerError(f"JSON file grew while being read: {path}")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise ProbeSchedulerError(f"JSON file changed while being read: {path}")
    payload = b"".join(chunks)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeSchedulerError(f"invalid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ProbeSchedulerError(f"JSON root is not an object: {path}")
    return value, payload


def read_expected_router_sha256(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise ProbeSchedulerError(f"router digest pin is missing: {path}") from None
    except OSError as exc:
        raise ProbeSchedulerError(f"cannot open router digest pin: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProbeSchedulerError("router digest pin must be a regular file")
        if before.st_uid != os.getuid():
            raise ProbeSchedulerError("router digest pin has an unexpected owner")
        if before.st_mode & 0o077:
            raise ProbeSchedulerError("router digest pin must be private")
        if before.st_mode & SPECIAL_PERMISSION_BITS:
            raise ProbeSchedulerError("router digest pin has unsafe special mode bits")
        if before.st_size < 64 or before.st_size > 128:
            raise ProbeSchedulerError("router digest pin has an invalid size")
        payload = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if len(payload) != before.st_size or identity_before != identity_after:
        raise ProbeSchedulerError("router digest pin changed while being read")
    try:
        digest = payload.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ProbeSchedulerError("router digest pin is not ASCII") from exc
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ProbeSchedulerError("router digest pin is invalid")
    return digest


def atomic_write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
        mode=PRIVATE_DIRECTORY_MODE,
    )
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        directory_descriptor = os.open(path.parent, directory_flags)
    except OSError as exc:
        raise ProbeSchedulerError(
            f"cannot open private output directory: {path.parent}"
        ) from exc
    temporary_descriptor = -1
    temporary_name = ""
    try:
        directory_metadata = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory_metadata.st_mode):
            raise ProbeSchedulerError("private output parent is not a directory")
        if directory_metadata.st_uid != os.getuid():
            raise ProbeSchedulerError("private output parent has an unexpected owner")
        os.fchmod(directory_descriptor, PRIVATE_DIRECTORY_MODE)
        payload = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        temporary_descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
            text=True,
        )
        temporary_name = Path(temporary).name
        os.fchmod(temporary_descriptor, PRIVATE_FILE_MODE)
        handle = os.fdopen(temporary_descriptor, "w", encoding="utf-8")
        temporary_descriptor = -1
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        temporary_name = ""
        os.fsync(directory_descriptor)
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        os.close(directory_descriptor)


def safe_unlink(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ProbeSchedulerError(f"refusing to remove unsafe path: {path}")
    try:
        path.unlink()
    except FileNotFoundError:
        pass


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ProbeSchedulerError("probe scheduler lock is unsafe")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusy("probe scheduler is already running") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def validated_router(
    path: Path, expected_sha256: str
) -> Iterator[tuple[str, str, int]]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise ProbeSchedulerError(f"router executable is missing: {path}") from None
    except OSError as exc:
        raise ProbeSchedulerError(f"cannot open router executable: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProbeSchedulerError("router executable must be a regular file")
        if before.st_uid != os.getuid():
            raise ProbeSchedulerError("router executable has an unexpected owner")
        if before.st_mode & 0o022:
            raise ProbeSchedulerError("router executable is group- or world-writable")
        if before.st_mode & SPECIAL_PERMISSION_BITS:
            raise ProbeSchedulerError("router executable has unsafe special mode bits")
        if before.st_mode & 0o111 == 0:
            raise ProbeSchedulerError("router executable is not executable")
        if before.st_size < 1 or before.st_size > MAX_ROUTER_BYTES:
            raise ProbeSchedulerError("router executable exceeds the size limit")
        payload = os.read(descriptor, before.st_size + 1)
        if len(payload) != before.st_size:
            raise ProbeSchedulerError("router executable changed while being read")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise ProbeSchedulerError("router executable changed while being read")
        actual_sha256 = bytes_sha256(payload)
        if actual_sha256 != expected_sha256:
            raise ProbeSchedulerError("router executable does not match its digest pin")
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield f"/proc/self/fd/{descriptor}", actual_sha256, descriptor
    finally:
        os.close(descriptor)


def sanitized_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in FORBIDDEN_API_KEY_ENV:
        environment.pop(name, None)
    environment["GRABOWSKI_PROBE_SCHEDULER"] = "1"
    environment["NO_COLOR"] = "1"
    return environment


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    # run_json_command starts the child with start_new_session=True. After Popen
    # returns, the child PID is therefore also the stable session and process
    # group ID. Do not call poll() or wait() before the final group signal:
    # reaping the leader could release that numeric ID for reuse.
    process_group_id = process.pid
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except ProcessLookupError:
        try:
            process.wait(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        return

    # Preserve the unreaped group leader for the complete grace period. This
    # both pins the numeric process-group ID and gives descendants their full
    # opportunity to handle SIGTERM even when the leader exits immediately.
    time.sleep(PROCESS_TERMINATION_GRACE_SECONDS)
    try:
        os.killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass


def bounded_output_read_size(buffered_bytes: int) -> int:
    remaining_capacity = max(0, MAX_COMMAND_OUTPUT_BYTES - buffered_bytes)
    return min(IO_CHUNK_BYTES, remaining_capacity + 1)


def collect_bounded_process_output(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: int,
    command_name: str,
) -> tuple[bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        raise ProbeSchedulerError("command pipes were not created")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, data=name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command_name, timeout_seconds)
            for key, _ in selector.select(timeout=min(remaining, 0.25)):
                buffer = buffers[key.data]
                chunk_size = bounded_output_read_size(len(buffer))
                try:
                    chunk = os.read(key.fileobj.fileno(), chunk_size)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(buffer) + len(chunk) > MAX_COMMAND_OUTPUT_BYTES:
                    raise ProbeSchedulerError(
                        f"command output exceeded the limit: {command_name}"
                    )
                buffer.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0 and process.poll() is None:
            raise subprocess.TimeoutExpired(command_name, timeout_seconds)
        process.wait(timeout=max(remaining, 0.001))
        return bytes(buffers["stdout"]), bytes(buffers["stderr"])
    finally:
        selector.close()




def _open_private_codex_metadata_source(
    source: Path,
    *,
    label: str,
    required: bool,
) -> int | None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        source_fd = os.open(source, flags)
    except FileNotFoundError:
        if required:
            raise ProbeSchedulerError(f"{label} is missing")
        return None
    except OSError as exc:
        raise ProbeSchedulerError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(source_fd)
        linked = source.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) & 0o077
            or opened.st_size > MAX_ROUTER_BYTES
        ):
            raise ProbeSchedulerError(f"{label} is not a private owned regular file")
        return source_fd
    except BaseException:
        os.close(source_fd)
        raise


@contextmanager
def temporary_codex_metadata_home(
    *,
    state_directory: Path,
    source_codex_home: Path,
) -> Iterator[tuple[Path, tuple[int, ...]]]:
    if not _owned_directory(state_directory, label="coding-agent state directory"):
        raise ProbeSchedulerError("coding-agent state directory is missing")
    try:
        source_home_metadata = source_codex_home.lstat()
    except FileNotFoundError as exc:
        raise ProbeSchedulerError("Codex home is missing") from exc
    if (
        not stat.S_ISDIR(source_home_metadata.st_mode)
        or stat.S_ISLNK(source_home_metadata.st_mode)
        or source_home_metadata.st_uid != os.getuid()
    ):
        raise ProbeSchedulerError("Codex home is not an owned real directory")
    descriptors: list[int] = []
    temporary = Path(
        tempfile.mkdtemp(prefix=".codex-metadata-", dir=state_directory)
    )
    try:
        os.chmod(temporary, PRIVATE_DIRECTORY_MODE)
        for name, required in (("auth.json", True), ("config.toml", False)):
            descriptor = _open_private_codex_metadata_source(
                source_codex_home / name,
                label=f"Codex {name} metadata source",
                required=required,
            )
            if descriptor is None:
                continue
            descriptors.append(descriptor)
            target = f"/proc/self/fd/{descriptor}"
            os.symlink(target, temporary / name)
            linked = (temporary / name).lstat()
            if not stat.S_ISLNK(linked.st_mode) or os.readlink(temporary / name) != target:
                raise ProbeSchedulerError(f"Codex {name} metadata descriptor link is invalid")
        yield temporary, tuple(descriptors)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass

def _codex_app_server_read_response(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    buffer: bytearray,
    *,
    response_id: int,
    deadline: float,
    total_bytes: list[int],
) -> dict[str, Any]:
    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        events = selector.select(min(remaining, 0.2))
        if not events:
            if process.poll() is not None:
                raise ProbeSchedulerError("Codex app-server exited before metadata response")
            continue
        for key, _mask in events:
            chunk = os.read(key.fileobj.fileno(), IO_CHUNK_BYTES)
            if not chunk:
                if process.poll() is not None:
                    raise ProbeSchedulerError("Codex app-server closed metadata stream")
                continue
            total_bytes[0] += len(chunk)
            if total_bytes[0] > MAX_COMMAND_OUTPUT_BYTES:
                raise ProbeSchedulerError("Codex app-server metadata exceeds byte limit")
            buffer.extend(chunk)
            while b"\n" in buffer:
                line, _, rest = buffer.partition(b"\n")
                buffer[:] = rest
                if not line:
                    continue
                try:
                    value = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ProbeSchedulerError("Codex app-server returned invalid JSON") from exc
                if not isinstance(value, dict):
                    raise ProbeSchedulerError("Codex app-server response is not an object")
                if value.get("id") != response_id:
                    continue
                if value.get("error") is not None:
                    raise ProbeSchedulerError("Codex app-server metadata request failed")
                result = value.get("result")
                if not isinstance(result, dict):
                    raise ProbeSchedulerError("Codex app-server metadata result is invalid")
                return result
    raise ProbeSchedulerError("Codex app-server metadata request timed out")


def collect_codex_app_server_observations(
    codex_binary: Path,
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    state_directory: Path,
    source_codex_home: Path,
) -> dict[str, dict[str, Any]]:
    unknown = {
        CODEX_QUOTA_POOL: _unknown_codex_direct_observation(
            CODEX_QUOTA_POOL, "direct_provider_metadata_unavailable"
        ),
        CODEX_SPARK_QUOTA_POOL: _unknown_codex_direct_observation(
            CODEX_SPARK_QUOTA_POOL, "direct_provider_metadata_unavailable"
        ),
    }
    try:
        path = codex_binary.resolve(strict=True)
        metadata = path.stat()
        if (
            not path.is_absolute()
            or not stat.S_ISREG(metadata.st_mode)
            or not os.access(path, os.X_OK)
        ):
            return unknown
        codex_home_context = temporary_codex_metadata_home(
            state_directory=state_directory,
            source_codex_home=source_codex_home,
        )
        temporary_codex_home, codex_metadata_fds = codex_home_context.__enter__()
        child_environment = dict(environment)
        child_environment["CODEX_HOME"] = str(temporary_codex_home)
        child_environment["CODEX_SQLITE_HOME"] = str(temporary_codex_home)
        process = subprocess.Popen(
            [str(path), "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=child_environment,
            start_new_session=True,
            close_fds=True,
            pass_fds=codex_metadata_fds,
        )
    except (OSError, RuntimeError, ProbeSchedulerError):
        try:
            codex_home_context.__exit__(None, None, None)
        except (NameError, OSError):
            pass
        return unknown
    assert process.stdin is not None and process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    buffer = bytearray()
    total_bytes = [0]
    deadline = time.monotonic() + timeout_seconds

    def send(value: dict[str, Any]) -> None:
        payload = canonical_bytes(value) + b"\n"
        if len(payload) > 64 * 1024:
            raise ProbeSchedulerError("Codex app-server request is too large")
        process.stdin.write(payload)
        process.stdin.flush()

    try:
        send(
            {
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "grabowski-coding-agent-probe",
                        "version": "1",
                    },
                    "capabilities": {"experimentalApi": True},
                },
            }
        )
        _codex_app_server_read_response(
            process,
            selector,
            buffer,
            response_id=1,
            deadline=deadline,
            total_bytes=total_bytes,
        )
        send({"method": "initialized"})
        send(
            {
                "id": 2,
                "method": "model/list",
                "params": {"limit": 100, "cursor": None, "includeHidden": True},
            }
        )
        model_result = _codex_app_server_read_response(
            process,
            selector,
            buffer,
            response_id=2,
            deadline=deadline,
            total_bytes=total_bytes,
        )
        send({"id": 3, "method": "account/rateLimits/read", "params": None})
        rate_result = _codex_app_server_read_response(
            process,
            selector,
            buffer,
            response_id=3,
            deadline=deadline,
            total_bytes=total_bytes,
        )
        return parse_codex_app_server_observations(model_result, rate_result)
    except (BrokenPipeError, OSError, ProbeSchedulerError):
        return unknown
    finally:
        selector.close()
        try:
            process.stdin.close()
        except OSError:
            pass
        terminate_process_group(process)
        process.stdout.close()
        codex_home_context.__exit__(None, None, None)

def run_json_command(
    argv: list[str],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    pass_fds: tuple[int, ...] = (),
) -> dict[str, Any]:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            pass_fds=pass_fds,
            bufsize=0,
            start_new_session=True,
        )
        try:
            stdout, _stderr = collect_bounded_process_output(
                process,
                timeout_seconds=timeout_seconds,
                command_name=argv[-1],
            )
        except BaseException:
            terminate_process_group(process)
            raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeSchedulerError(f"command failed to execute: {argv[-1]}") from exc
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
    if process.returncode != 0:
        raise ProbeSchedulerError(
            f"command returned nonzero status for {argv[-1]} "
            f"(exit {process.returncode})"
        )
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeSchedulerError(f"command did not return JSON: {argv[-1]}") from exc
    if not isinstance(value, dict):
        raise ProbeSchedulerError(f"command JSON root is not an object: {argv[-1]}")
    return value


def validate_probe(probe: dict[str, Any]) -> None:
    if probe.get("schema_version") != 2:
        raise ProbeSchedulerError("probe schema_version is invalid")
    observed_at = parse_time(probe.get("observed_at"))
    if observed_at is None:
        raise ProbeSchedulerError("probe observed_at is invalid")
    age_seconds = (utc_now() - observed_at).total_seconds()
    if not -300 <= age_seconds <= 300:
        raise ProbeSchedulerError("probe observed_at is outside the bounded window")
    digest = probe.get("catalog_probe_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ProbeSchedulerError("probe digest is invalid")
    digest_input = dict(probe)
    digest_input.pop("catalog_probe_sha256", None)
    if digest != probe_digest(digest_input):
        raise ProbeSchedulerError("probe digest does not match its payload")
    expected_fields = set(PROBE_DIGEST_FIELDS) | {"catalog_probe_sha256"}
    if set(probe) != expected_fields:
        raise ProbeSchedulerError("probe fields do not match the exact metadata-only schema")
    assert_probe_digest_safe(digest_input)
    for field in ("model_invocations", "paid_api_requests_authorized"):
        value = probe.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value != 0:
            raise ProbeSchedulerError(f"probe {field} must be integer zero")
    scrubbed_environment = probe.get("api_key_environment_scrubbed")
    if (
        not isinstance(scrubbed_environment, list)
        or any(not isinstance(name, str) for name in scrubbed_environment)
        or len(set(scrubbed_environment)) != len(scrubbed_environment)
        or set(scrubbed_environment) != set(EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV)
    ):
        raise ProbeSchedulerError("probe api_key_environment_scrubbed is invalid")
    if not isinstance(probe.get("providers"), dict):
        raise ProbeSchedulerError("probe providers are missing")
    verified_pools = probe.get("verified_quota_pools", [])
    if (
        not isinstance(verified_pools, list)
        or any(not isinstance(pool_id, str) for pool_id in verified_pools)
        or len(set(verified_pools)) != len(verified_pools)
        or any(
            pool_id not in PROBE_VERIFIABLE_QUOTA_POOLS
            for pool_id in verified_pools
        )
    ):
        raise ProbeSchedulerError("probe verified_quota_pools is invalid")


def _expected_probe_pools(
    before: dict[str, Any],
    probe: dict[str, Any],
    *,
    catalog_changed: bool,
) -> dict[str, Any]:
    pools = {} if catalog_changed else json.loads(
        json.dumps(before.get("pools", {}), sort_keys=True)
    )
    if not isinstance(pools, dict):
        raise ProbeSchedulerError("router pool state before probe is invalid")
    verified_pools = set(probe.get("verified_quota_pools", []))
    for pool_id in PROBE_VERIFIABLE_QUOTA_POOLS:
        existing = pools.get(pool_id)
        if pool_id in verified_pools:
            if existing is not None and not isinstance(existing, dict):
                raise ProbeSchedulerError("verified pool state before probe is invalid")
            pools[pool_id] = {
                **(existing if isinstance(existing, dict) else {}),
                "verified_at": probe["observed_at"],
            }
        elif isinstance(existing, dict):
            existing.pop("verified_at", None)
    return pools


def validate_state_after_probe(
    before: dict[str, Any],
    after: dict[str, Any],
    probe: dict[str, Any],
) -> None:
    if after.get("schema_version") != 2:
        raise ProbeSchedulerError("router state schema_version is invalid")
    if after.get("catalog") != probe:
        raise ProbeSchedulerError("router state is not bound to the probe output")
    if after.get("history", {}) != before.get("history", {}):
        raise ProbeSchedulerError("probe changed router history")
    before_catalog_sha256 = before.get("catalog_sha256")
    after_catalog_sha256 = after.get("catalog_sha256")
    if not isinstance(after_catalog_sha256, str) or not after_catalog_sha256:
        raise ProbeSchedulerError("router state catalog_sha256 is invalid")
    catalog_changed = before_catalog_sha256 != after_catalog_sha256
    expected_routes = {} if catalog_changed else before.get("routes", {})
    if not isinstance(expected_routes, dict):
        raise ProbeSchedulerError("router route history before probe is invalid")
    if after.get("routes", {}) != expected_routes:
        reason = (
            "probe did not reset route history after catalog change"
            if catalog_changed
            else "probe changed route outcome history"
        )
        raise ProbeSchedulerError(reason)
    expected_pools = _expected_probe_pools(
        before, probe, catalog_changed=catalog_changed
    )
    if after.get("pools", {}) != expected_pools:
        reason = (
            "probe did not reset pool state after catalog change"
            if catalog_changed
            else "probe changed pool state beyond verified timestamps"
        )
        raise ProbeSchedulerError(reason)
    if not isinstance(after.get("routes", {}), dict):
        raise ProbeSchedulerError("router route history is invalid")
    if not isinstance(after.get("pools", {}), dict):
        raise ProbeSchedulerError("router pool state is invalid")


def quota_update_plan(
    router_invocation: str,
    observation: dict[str, Any],
    current_state: dict[str, Any],
    *,
    now: datetime | None = None,
    force_unknown: bool = False,
) -> dict[str, Any] | None:
    pool_id = observation.get("pool")
    if pool_id not in {CODEX_QUOTA_POOL, CODEX_SPARK_QUOTA_POOL}:
        raise ProbeSchedulerError("Codex quota observation pool is invalid")
    status = observation.get("status")
    if status in {"available", "exhausted"}:
        remaining = observation.get("remaining_ratio")
        reset_at = observation.get("reset_at")
        if (
            isinstance(remaining, bool)
            or not isinstance(remaining, (int, float))
            or not 0 <= float(remaining) <= 1
            or parse_time(reset_at) is None
        ):
            raise ProbeSchedulerError("Codex quota observation is invalid")
        return {
            "pool": pool_id,
            "reason": "fresh_provider_observation",
            "argv": [
                router_invocation,
                "set-quota",
                "--pool",
                pool_id,
                "--status",
                str(status),
                "--remaining-ratio",
                format(float(remaining), ".12g"),
                "--reset-at",
                str(reset_at),
                "--verified-now",
            ],
        }
    if status != "unknown":
        return None
    pools = current_state.get("pools")
    pool = pools.get(pool_id) if isinstance(pools, dict) else None
    if force_unknown:
        if isinstance(pool, dict) and (
            pool.get("status") == "unknown"
            and "remaining_ratio" not in pool
            and "reset_at" not in pool
        ):
            return None
        return {
            "pool": pool_id,
            "reason": "provider_metadata_unavailable_to_unknown",
            "argv": [
                router_invocation,
                "set-quota",
                "--pool",
                pool_id,
                "--status",
                "unknown",
                "--verified-now",
            ],
        }
    reset_at = parse_time(pool.get("reset_at")) if isinstance(pool, dict) else None
    boundary = (now or utc_now()).astimezone(timezone.utc)
    if reset_at is None or reset_at > boundary:
        return None
    return {
        "pool": pool_id,
        "reason": "expired_reset_to_unknown",
        "argv": [
            router_invocation,
            "set-quota",
            "--pool",
            pool_id,
            "--status",
            "unknown",
            "--verified-now",
        ],
    }


def validate_state_after_quota_update(
    before: dict[str, Any],
    after: dict[str, Any],
    observation: dict[str, Any],
    result: dict[str, Any],
) -> None:
    pool_id = observation.get("pool")
    if pool_id not in {CODEX_QUOTA_POOL, CODEX_SPARK_QUOTA_POOL}:
        raise ProbeSchedulerError("Codex quota observation pool is invalid")
    if result.get("updated") is not True or result.get("pool") != pool_id:
        raise ProbeSchedulerError("router quota update result is invalid")
    pool_state = result.get("pool_state")
    if not isinstance(pool_state, dict):
        raise ProbeSchedulerError("router quota update pool state is invalid")
    expected_status = observation.get("status")
    if expected_status not in {"available", "exhausted"}:
        expected_status = "unknown"
    if (
        pool_state.get("status") != expected_status
        or parse_time(pool_state.get("verified_at")) is None
        or parse_time(pool_state.get("updated_at")) is None
    ):
        raise ProbeSchedulerError("router quota update does not match observation")
    if expected_status in {"available", "exhausted"}:
        if (
            pool_state.get("remaining_ratio") != observation.get("remaining_ratio")
            or pool_state.get("reset_at") != observation.get("reset_at")
        ):
            raise ProbeSchedulerError("router quota update does not match observation")
    elif any(field in pool_state for field in ("remaining_ratio", "reset_at")):
        raise ProbeSchedulerError("quota reset retained stale quota fields")
    for field in ("schema_version", "catalog_sha256", "catalog", "routes", "history"):
        if after.get(field) != before.get(field):
            raise ProbeSchedulerError(f"quota update changed router {field}")
    expected_pools = json.loads(json.dumps(before.get("pools", {}), sort_keys=True))
    if not isinstance(expected_pools, dict):
        raise ProbeSchedulerError("router pool state before quota update is invalid")
    expected_pools[pool_id] = pool_state
    if after.get("pools") != expected_pools:
        raise ProbeSchedulerError("quota update changed unrelated pool state")


def validate_status(status_value: dict[str, Any]) -> None:
    if status_value.get("schema_version") != 2:
        raise ProbeSchedulerError("router status schema_version is invalid")
    if status_value.get("catalog_fresh") is not True:
        raise ProbeSchedulerError("router status does not confirm a fresh catalog")
    if status_value.get("automatic_execution_authorized") is not False:
        raise ProbeSchedulerError("router status unexpectedly authorizes execution")


def bounded_failure(exc: BaseException) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "coding-agent-probe-scheduler-failure",
        "status": "failed",
        "failed_at": iso_now(),
        "error_type": type(exc).__name__,
        "error": "probe_scheduler_failed_closed",
        "automatic_execution_authorized": False,
        "model_invocations": 0,
        "paid_api_requests_authorized": 0,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Refresh advisory coding-agent runtime metadata without model execution."
    )
    result.add_argument("--router", type=Path, default=DEFAULT_ROUTER)
    result.add_argument(
        "--router-sha256-file", type=Path, default=DEFAULT_ROUTER_DIGEST
    )
    result.add_argument("--state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    result.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    result.add_argument("--failure", type=Path, default=DEFAULT_FAILURE)
    result.add_argument(
        "--codex-sessions-root", type=Path, default=DEFAULT_CODEX_SESSIONS_ROOT
    )
    result.add_argument("--timeout-seconds", type=int, default=120)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.timeout_seconds < 1 or arguments.timeout_seconds > 300:
        print("timeout-seconds must be between 1 and 300", file=sys.stderr)
        return 2
    try:
        expected_router_sha256 = read_expected_router_sha256(
            arguments.router_sha256_file
        )
        with (
            exclusive_lock(arguments.lock),
            validated_router(arguments.router, expected_router_sha256) as router,
        ):
            router_invocation, router_sha256, router_descriptor = router
            before, before_bytes = read_json(arguments.state, required=False)
            environment = sanitized_environment()
            before_probe = before
            before_probe_bytes = before_bytes
            spark_preclear: dict[str, Any] | None = None
            existing_pools = before.get("pools")
            existing_spark = (
                existing_pools.get(CODEX_SPARK_QUOTA_POOL)
                if isinstance(existing_pools, dict)
                else None
            )
            if isinstance(existing_spark, dict) and (
                existing_spark.get("status") != "unknown"
                or "remaining_ratio" in existing_spark
                or "reset_at" in existing_spark
            ):
                preclear_observation = _unknown_codex_direct_observation(
                    CODEX_SPARK_QUOTA_POOL, "provider_metadata_refresh_started"
                )
                preclear_plan = quota_update_plan(
                    router_invocation,
                    preclear_observation,
                    before,
                    force_unknown=True,
                )
                if preclear_plan is not None:
                    preclear_result = run_json_command(
                        preclear_plan["argv"],
                        environment=environment,
                        timeout_seconds=arguments.timeout_seconds,
                        pass_fds=(router_descriptor,),
                    )
                    before_probe, before_probe_bytes = read_json(arguments.state)
                    validate_state_after_quota_update(
                        before, before_probe, preclear_observation, preclear_result
                    )
                    spark_preclear = {
                        "reason": "provider_metadata_refresh_started_to_unknown",
                        "result": preclear_result,
                    }
            probe = run_json_command(
                [router_invocation, "probe"],
                environment=environment,
                timeout_seconds=arguments.timeout_seconds,
                pass_fds=(router_descriptor,),
            )
            validate_probe(probe)
            after_probe, after_probe_bytes = read_json(arguments.state)
            validate_state_after_probe(before_probe, after_probe, probe)
            rollout_observation = collect_codex_quota_observation(
                arguments.codex_sessions_root
            )
            codex_provider = probe.get("providers", {}).get("codex", {})
            codex_harness = probe.get("harnesses", {}).get("codex", {})
            configured_codex_models = codex_provider.get("models", [])
            spark_configured = (
                isinstance(configured_codex_models, list)
                and CODEX_SPARK_MODEL in configured_codex_models
            )
            direct_observations: dict[str, dict[str, Any]] = {}
            if spark_configured:
                codex_binary = codex_harness.get("binary")
                if isinstance(codex_binary, str) and codex_binary:
                    direct_observations = collect_codex_app_server_observations(
                        Path(codex_binary),
                        environment=environment,
                        timeout_seconds=min(arguments.timeout_seconds, 30),
                        state_directory=arguments.state.parent,
                        source_codex_home=Path.home() / ".codex",
                    )
                else:
                    direct_observations = {
                        CODEX_QUOTA_POOL: _unknown_codex_direct_observation(
                            CODEX_QUOTA_POOL, "codex_binary_unavailable"
                        ),
                        CODEX_SPARK_QUOTA_POOL: _unknown_codex_direct_observation(
                            CODEX_SPARK_QUOTA_POOL, "codex_binary_unavailable"
                        ),
                    }
            direct_main = direct_observations.get(CODEX_QUOTA_POOL, {})
            quota_observation = (
                direct_main
                if direct_main.get("status") in {"available", "exhausted"}
                else rollout_observation
            )
            quota_observations: dict[str, dict[str, Any]] = {
                CODEX_QUOTA_POOL: quota_observation
            }
            if spark_configured:
                spark_observation = direct_observations.get(
                    CODEX_SPARK_QUOTA_POOL,
                    _unknown_codex_direct_observation(
                        CODEX_SPARK_QUOTA_POOL, "direct_provider_metadata_unavailable"
                    ),
                )
                quota_observations[CODEX_SPARK_QUOTA_POOL] = spark_observation

            after = after_probe
            after_bytes = after_probe_bytes
            quota_updates: dict[str, dict[str, Any]] = {}
            for pool_id in (CODEX_QUOTA_POOL, CODEX_SPARK_QUOTA_POOL):
                observation = quota_observations.get(pool_id)
                if observation is None:
                    continue
                quota_plan = quota_update_plan(
                    router_invocation,
                    observation,
                    after,
                    force_unknown=(
                        pool_id == CODEX_SPARK_QUOTA_POOL and spark_configured
                    ),
                )
                if quota_plan is None:
                    continue
                quota_result = run_json_command(
                    quota_plan["argv"],
                    environment=environment,
                    timeout_seconds=arguments.timeout_seconds,
                    pass_fds=(router_descriptor,),
                )
                next_state, next_bytes = read_json(arguments.state)
                validate_state_after_quota_update(
                    after, next_state, observation, quota_result
                )
                quota_updates[pool_id] = {
                    "reason": quota_plan["reason"],
                    "result": quota_result,
                }
                after, after_bytes = next_state, next_bytes

            status_value = run_json_command(
                [router_invocation, "status"],
                environment=environment,
                timeout_seconds=arguments.timeout_seconds,
                pass_fds=(router_descriptor,),
            )
            validate_status(status_value)
            for pool_id, update in quota_updates.items():
                observation = quota_observations[pool_id]
                effective_pool = status_value.get("pools", {}).get(pool_id)
                expected_status = observation.get("status")
                if expected_status not in {"available", "exhausted"}:
                    expected_status = "unknown"
                if (
                    not isinstance(effective_pool, dict)
                    or effective_pool.get("status") != expected_status
                ):
                    raise ProbeSchedulerError(
                        "router status does not confirm the Codex quota update"
                    )
                if expected_status in {"available", "exhausted"} and (
                    effective_pool.get("remaining_ratio")
                    != observation["remaining_ratio"]
                    or effective_pool.get("reset_at") != observation["reset_at"]
                ):
                    raise ProbeSchedulerError(
                        "router status does not confirm the Codex quota update"
                    )
                if expected_status == "unknown" and any(
                    field in effective_pool for field in ("remaining_ratio", "reset_at")
                ):
                    raise ProbeSchedulerError(
                        "router status retained stale Codex quota fields"
                    )
            main_update = quota_updates.get(CODEX_QUOTA_POOL)
            receipt = {
                "schema_version": 1,
                "kind": "coding-agent-probe-scheduler-receipt",
                "status": "ok",
                "completed_at": iso_now(),
                "router": str(arguments.router),
                "router_sha256": router_sha256,
                "router_sha256_pin": str(arguments.router_sha256_file),
                "catalog_sha256": after["catalog_sha256"],
                "state": str(arguments.state),
                "state_sha256_before": bytes_sha256(before_bytes),
                "state_sha256_after_preclear": bytes_sha256(before_probe_bytes),
                "state_sha256_after_probe": bytes_sha256(after_probe_bytes),
                "state_sha256_after": bytes_sha256(after_bytes),
                "history_sha256": value_sha256(after.get("history", {})),
                "quota_observation": quota_observation,
                "quota_state_updated": main_update is not None,
                "quota_update_reason": (
                    main_update["reason"] if main_update is not None else None
                ),
                "quota_observations": quota_observations,
                "quota_updates": {
                    pool_id: {"reason": update["reason"]}
                    for pool_id, update in quota_updates.items()
                },
                "spark_configured": spark_configured,
                "spark_preclear": (
                    {"reason": spark_preclear["reason"]}
                    if spark_preclear is not None
                    else None
                ),
                "catalog_probe_sha256": probe["catalog_probe_sha256"],
                "observed_at": probe["observed_at"],
                "status_readback": {
                    "catalog_fresh": True,
                    "automatic_execution_authorized": False,
                },
                "invocation_policy": "metadata-only",
                "model_invocations": 0,
                "paid_api_requests_authorized": 0,
                "api_key_environment_removed_count": len(FORBIDDEN_API_KEY_ENV),
                "does_not_establish": [
                    "provider quota after the observation timestamp",
                    "quota for providers without fresh receipt metadata",
                    "provider-side authenticity beyond same-uid local receipt storage",
                    "future route availability",
                    "execution authority",
                ],
            }
            atomic_write_private(arguments.receipt, receipt)
            safe_unlink(arguments.failure)
            print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
            return 0
    except LockBusy:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "coding-agent-probe-scheduler-receipt",
                    "status": "skipped-lock-busy",
                    "automatic_execution_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as exc:
        failure = bounded_failure(exc)
        try:
            atomic_write_private(arguments.failure, failure)
        except Exception:
            pass
        print(
            json.dumps(failure, sort_keys=True, separators=(",", ":")), file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
