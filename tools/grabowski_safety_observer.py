#!/usr/bin/env python3
"""Local, privacy-preserving observability for Grabowski/OpenAI tool failures.

The observer never retries tool calls and never attempts to alter platform safeguards.
It correlates local tunnel/operator evidence with explicitly recorded upstream events.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

STATE_DIR = Path.home() / ".local/state/grabowski/safety-observer"
EVENTS_PATH = STATE_DIR / "events.jsonl"
SNAPSHOTS_PATH = STATE_DIR / "snapshots.jsonl"
CURSOR_PATH = STATE_DIR / "cursor.json"
DEDUP_PATH = STATE_DIR / "dedup.json"
STATUS_PATH = STATE_DIR / "status.json"
REPORT_PATH = STATE_DIR / "report.md"
LOCK_PATH = STATE_DIR / "observer.lock"
METRICS_URL = "http://127.0.0.1:18080/metrics"
UNITS = ("grabowski-operator.service", "tunnel-client-grabowski.service")

EVENT_KINDS = {
    "upstream_policy_block",
    "connector_session_terminated",
    "local_tool_error",
    "tunnel_transport_error",
    "schema_or_snapshot_drift",
    "expected_service_restart",
    "account_warning",
    "account_restriction",
    "manual_note",
}
OPERATION_CLASSES = {"read", "write", "admin", "secret", "unknown"}
SEVERITY = {"info", "warning", "high", "critical"}

SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization|api[_-]?key|token|secret|password)\s*[:=]\s*\S+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.I),
)

DYNAMIC_PATTERNS = (
    (re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b"), "<TIME>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.I), "<ID>"),
    (re.compile(r"\b(?:cmd|wfr|tunnel)_[A-Za-z0-9_/-]{12,}\b"), "<ID>"),
    (re.compile(r"\b[0-9a-f]{24,}\b", re.I), "<ID>"),
    (
        re.compile(
            r'(?i)("(?:request_id|cmd_request_id|rpc_request_id|session_id|tunnel_id|time)"\s*:\s*")[^"]+("?)'
        ),
        r"\1<ID>\2",
    ),
)

BENIGN_TUNNEL_PATTERNS = (
    re.compile(r"oauth discovery", re.I),
    re.compile(r"received signal.*terminated", re.I),
    re.compile(r"harpoon server stopped.*context canceled", re.I),
    re.compile(r"failed to release dispatcher worker pool", re.I),
    re.compile(r"dispatcher received mcp upstream error; posted error response", re.I),
    re.compile(r"127\.0\.0\.1:18181.*connection refused", re.I),
    re.compile(r"response gap enqueued=", re.I),
)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def redact(text: str, limit: int = 500) -> str:
    value = text.replace("\x00", " ").replace("\r", " ").replace("\n", " ").strip()
    for pattern in SECRET_PATTERNS:
        value = pattern.sub("<REDACTED>", value)
    for pattern, replacement in DYNAMIC_PATTERNS:
        value = pattern.sub(replacement, value)
    value = re.sub(r"\s+", " ", value)
    return value[:limit]


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    records.append(value)
    except FileNotFoundError:
        pass
    return records


def classify_severity(kind: str, operation_class: str) -> str:
    if kind in {"account_restriction"}:
        return "critical"
    if kind in {"account_warning"}:
        return "high"
    if kind == "upstream_policy_block":
        return "warning" if operation_class == "read" else "high"
    if kind in {"connector_session_terminated", "tunnel_transport_error"}:
        return "warning"
    if kind == "expected_service_restart":
        return "info"
    return "info"


def record_event(
    *,
    kind: str,
    source: str,
    tool: str = "",
    operation_class: str = "unknown",
    message: str = "",
    payload_hash: str = "",
    severity: str | None = None,
    evidence: dict[str, Any] | None = None,
    deduplicate: bool = False,
) -> dict[str, Any] | None:
    if kind not in EVENT_KINDS:
        raise ValueError(f"unsupported event kind: {kind}")
    if operation_class not in OPERATION_CLASSES:
        raise ValueError(f"unsupported operation class: {operation_class}")
    actual_severity = severity or classify_severity(kind, operation_class)
    if actual_severity not in SEVERITY:
        raise ValueError(f"unsupported severity: {actual_severity}")

    sanitized_message = redact(message)
    fingerprint_source = "|".join(
        [kind, source, tool, operation_class, payload_hash, sanitized_message]
    )
    fingerprint = sha256_text(fingerprint_source)
    if deduplicate:
        dedup = load_json(DEDUP_PATH, {})
        previous = dedup.get(fingerprint)
        if previous:
            try:
                if utc_now() - parse_time(previous) < dt.timedelta(hours=1):
                    return None
            except (TypeError, ValueError):
                pass
        dedup[fingerprint] = iso()
        cutoff = utc_now() - dt.timedelta(days=30)
        dedup = {
            key: value
            for key, value in dedup.items()
            if isinstance(value, str)
            and _safe_after(value, cutoff)
        }
        atomic_json(DEDUP_PATH, dedup)

    event = {
        "schema_version": 1,
        "timestamp": iso(),
        "kind": kind,
        "severity": actual_severity,
        "source": redact(source, 100),
        "tool": redact(tool, 150),
        "operation_class": operation_class,
        "payload_hash": payload_hash[:64],
        "message": sanitized_message,
        "fingerprint": fingerprint,
        "evidence": evidence or {},
    }
    append_jsonl(EVENTS_PATH, event)
    return event


def _safe_after(value: str, cutoff: dt.datetime) -> bool:
    try:
        return parse_time(value) >= cutoff
    except (TypeError, ValueError):
        return False


def run(argv: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def service_state(unit: str) -> dict[str, str]:
    result = run(
        [
            "systemctl",
            "--user",
            "show",
            unit,
            "--property=LoadState,ActiveState,SubState,NRestarts,ExecMainStatus",
        ]
    )
    values: dict[str, str] = {"unit": unit, "returncode": str(result.returncode)}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    if result.stderr:
        values["stderr"] = redact(result.stderr, 250)
    return values


def fetch_metrics() -> tuple[str, dict[str, float]]:
    request = urllib.request.Request(METRICS_URL, headers={"User-Agent": "grabowski-safety-observer/1"})
    with urllib.request.urlopen(request, timeout=5) as response:
        text = response.read(2_000_000).decode("utf-8", errors="replace")
    metrics: dict[str, float] = {}
    response_count = 0.0
    non_success_count = 0.0
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name_and_labels, separator, raw_value = line.rpartition(" ")
        if not separator:
            continue
        try:
            value = float(raw_value)
        except ValueError:
            continue
        metric_name = name_and_labels.split("{", 1)[0]
        if metric_name in {
            "commands_enqueued_total",
            "commands_polled_total",
            "commands_queue_length",
            "dispatcher_worker_pool_occupancy",
            "commands_poll_last_successful_timestamp_seconds",
        }:
            metrics[metric_name] = value
        if metric_name == "http_client_request_body_size_bytes_count":
            if 'http_request_method="POST"' in name_and_labels and '/response"' in name_and_labels:
                if 'http_response_status_code="200"' in name_and_labels:
                    response_count += value
                else:
                    non_success_count += value
    metrics["response_posts_200_total"] = response_count
    metrics["response_posts_non_200_total"] = non_success_count
    return text, metrics


def journal_records(since_unix: int) -> Iterable[dict[str, Any]]:
    argv = ["journalctl", "--user"]
    for unit in UNITS:
        argv.extend(["-u", unit])
    argv.extend(["--since", f"@{since_unix}", "--no-pager", "--output=json"])
    result = run(argv, timeout=25)
    if result.returncode != 0:
        record_event(
            kind="local_tool_error",
            source="observer",
            tool="journalctl",
            operation_class="read",
            message=result.stderr or f"journalctl exited {result.returncode}",
            deduplicate=True,
        )
        return []
    parsed: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            parsed.append(item)
    return parsed


def classify_journal_event(
    unit: str,
    message: str,
    *,
    services_active: bool,
) -> tuple[str, str] | None:
    lower = message.lower()
    if "oauth discovery" in lower and services_active and (
        "invalid metadata" in lower
        or "protected resource metadata" in lower
        or "www-authenticate probe failed" in lower
    ):
        return None
    if (
        ("received signal" in lower and "terminated" in lower)
        or ("harpoon server stopped" in lower and "context canceled" in lower)
    ):
        return "expected_service_restart", "info"
    if "connect: connection refused" in lower and "127.0.0.1:18181" in lower:
        if services_active:
            return "expected_service_restart", "info"
        return "tunnel_transport_error", "warning"
    if "dispatcher received mcp upstream error; posted error response" in lower:
        match = re.search(r"status[_ ]?code[^0-9]*(\d{3})", lower)
        status_code = int(match.group(1)) if match else 0
        if 400 <= status_code < 500:
            return "local_tool_error", "info"
        return "connector_session_terminated", "warning"
    if "failed to post response to control plane" in lower:
        return "connector_session_terminated", "warning"
    if "tunnel" in unit:
        return "tunnel_transport_error", "warning"
    return "local_tool_error", "info"


def is_actionable_event(event: dict[str, Any]) -> bool:
    if event.get("kind") == "expected_service_restart":
        return False
    if event.get("kind") != "tunnel_transport_error":
        return True
    message = str(event.get("message", ""))
    return not any(pattern.search(message) for pattern in BENIGN_TUNNEL_PATTERNS)


def collect() -> dict[str, Any]:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    now = utc_now()
    cursor = load_json(CURSOR_PATH, {})
    since_unix = int(cursor.get("journal_since_unix", now.timestamp() - 600))
    prior_snapshots = load_jsonl(SNAPSHOTS_PATH)
    previous_metrics = (
        prior_snapshots[-1].get("metrics", {})
        if prior_snapshots and isinstance(prior_snapshots[-1].get("metrics"), dict)
        else {}
    )
    snapshot: dict[str, Any] = {
        "schema_version": 2,
        "timestamp": iso(now),
        "services": [service_state(unit) for unit in UNITS],
        "metrics": {},
        "metrics_delta": {},
        "suppressed_journal_records": 0,
    }
    services_active = all(
        service.get("ActiveState") == "active" for service in snapshot["services"]
    )

    for service in snapshot["services"]:
        if service.get("ActiveState") != "active":
            record_event(
                kind="tunnel_transport_error",
                source="systemd",
                tool=service.get("unit", ""),
                operation_class="read",
                message=(
                    f"service state {service.get('ActiveState', 'unknown')}/"
                    f"{service.get('SubState', 'unknown')}"
                ),
                evidence={
                    "nrestarts": service.get("NRestarts", ""),
                    "exec_main_status": service.get("ExecMainStatus", ""),
                },
                deduplicate=True,
            )

    try:
        _, metrics = fetch_metrics()
        snapshot["metrics"] = metrics
        enqueued = metrics.get("commands_enqueued_total", 0.0)
        polled = metrics.get("commands_polled_total", 0.0)
        responses = metrics.get("response_posts_200_total", 0.0)
        queue = metrics.get("commands_queue_length", 0.0)
        last_poll = metrics.get("commands_poll_last_successful_timestamp_seconds", 0.0)
        if enqueued - polled > 5 or queue > 5:
            record_event(
                kind="tunnel_transport_error",
                source="metrics",
                tool="secure-mcp-tunnel",
                operation_class="read",
                message=f"queue/backlog anomaly enqueued={enqueued:g} polled={polled:g} queue={queue:g}",
                evidence={"enqueued": enqueued, "polled": polled, "queue": queue},
                deduplicate=True,
            )
        if previous_metrics:
            delta_enqueued = max(
                0.0,
                enqueued - float(previous_metrics.get("commands_enqueued_total", enqueued)),
            )
            delta_responses = max(
                0.0,
                responses - float(previous_metrics.get("response_posts_200_total", responses)),
            )
            delta_non_success = max(
                0.0,
                metrics.get("response_posts_non_200_total", 0.0)
                - float(previous_metrics.get("response_posts_non_200_total", 0.0)),
            )
            snapshot["metrics_delta"] = {
                "commands_enqueued": delta_enqueued,
                "response_posts_200": delta_responses,
                "response_posts_non_200": delta_non_success,
            }
            if delta_non_success > 0:
                record_event(
                    kind="connector_session_terminated",
                    source="metrics",
                    tool="secure-mcp-tunnel",
                    operation_class="read",
                    message=f"non-success response posts increased by {delta_non_success:g}",
                    evidence={"response_posts_non_200_delta": delta_non_success},
                    deduplicate=True,
                )
            elif delta_enqueued - delta_responses > 5:
                record_event(
                    kind="connector_session_terminated",
                    source="metrics",
                    tool="secure-mcp-tunnel",
                    operation_class="read",
                    message=(
                        f"interval response gap enqueued_delta={delta_enqueued:g} "
                        f"response_posts_200_delta={delta_responses:g}"
                    ),
                    evidence={
                        "enqueued_delta": delta_enqueued,
                        "response_posts_200_delta": delta_responses,
                    },
                    deduplicate=True,
                )
        if last_poll and now.timestamp() - last_poll > 120:
            record_event(
                kind="tunnel_transport_error",
                source="metrics",
                tool="secure-mcp-tunnel",
                operation_class="read",
                message=f"last successful poll is {int(now.timestamp() - last_poll)} seconds old",
                evidence={"last_poll_timestamp": last_poll},
                deduplicate=True,
            )
    except Exception as exc:  # observation must not crash the timer
        snapshot["metrics_error"] = redact(f"{type(exc).__name__}: {exc}")
        record_event(
            kind="tunnel_transport_error",
            source="metrics",
            tool="secure-mcp-tunnel",
            operation_class="read",
            message=snapshot["metrics_error"],
            deduplicate=True,
        )

    interesting = re.compile(
        r"(?i)\b(error|failed|failure|timeout|timed out|terminated|denied|blocked|forbidden|unauthorized|429|401|403)\b"
    )
    for item in journal_records(since_unix):
        message = str(item.get("MESSAGE", ""))
        priority_raw = str(item.get("PRIORITY", "6"))
        try:
            priority = int(priority_raw)
        except ValueError:
            priority = 6
        if priority <= 4 or interesting.search(message):
            unit = str(item.get("_SYSTEMD_USER_UNIT") or item.get("_SYSTEMD_UNIT") or "journal")
            classification = classify_journal_event(
                unit,
                message,
                services_active=services_active,
            )
            if classification is None:
                snapshot["suppressed_journal_records"] += 1
                continue
            kind, severity = classification
            record_event(
                kind=kind,
                source="journal",
                tool=unit,
                operation_class="read",
                message=message,
                severity=severity,
                evidence={"priority": priority},
                deduplicate=True,
            )

    append_jsonl(SNAPSHOTS_PATH, snapshot)
    atomic_json(CURSOR_PATH, {"journal_since_unix": int(now.timestamp()) - 5, "last_collect": iso(now)})
    status = build_status(now)
    atomic_json(STATUS_PATH, status)
    REPORT_PATH.write_text(render_report(status), encoding="utf-8")
    os.chmod(REPORT_PATH, 0o600)
    return status


def build_status(now: dt.datetime | None = None) -> dict[str, Any]:
    current = now or utc_now()
    events = load_jsonl(EVENTS_PATH)
    recent_24h_raw = [
        event for event in events if _event_after(event, current - dt.timedelta(hours=24))
    ]
    recent_7d_raw = [
        event for event in events if _event_after(event, current - dt.timedelta(days=7))
    ]
    recent_24h = [event for event in recent_24h_raw if is_actionable_event(event)]
    recent_7d = [event for event in recent_7d_raw if is_actionable_event(event)]
    counts_24h = Counter(str(event.get("kind", "unknown")) for event in recent_24h)
    counts_7d = Counter(str(event.get("kind", "unknown")) for event in recent_7d)
    raw_counts_24h = Counter(str(event.get("kind", "unknown")) for event in recent_24h_raw)
    severity_24h = Counter(str(event.get("severity", "info")) for event in recent_24h)

    risk = "green"
    reasons: list[str] = []
    if counts_24h.get("account_restriction", 0):
        risk = "red"
        reasons.append("account restriction recorded")
    elif counts_7d.get("account_warning", 0):
        risk = "red"
        reasons.append("account warning recorded within 7 days")
    elif severity_24h.get("critical", 0) or severity_24h.get("high", 0) >= 2:
        risk = "red"
        reasons.append("multiple high/critical incidents within 24 hours")
    elif counts_24h.get("upstream_policy_block", 0) >= 3:
        risk = "amber"
        reasons.append("repeated upstream policy blocks within 24 hours")
    elif counts_24h.get("connector_session_terminated", 0) or counts_24h.get("tunnel_transport_error", 0):
        risk = "amber"
        reasons.append("connector or transport instability within 24 hours")
    elif counts_24h.get("upstream_policy_block", 0):
        risk = "amber"
        reasons.append("upstream policy block recorded within 24 hours")
    else:
        reasons.append("no recent elevated incidents recorded")

    blocked_pairs = Counter(
        (str(event.get("tool", "")), str(event.get("payload_hash", "")))
        for event in recent_24h
        if event.get("kind") == "upstream_policy_block"
    )
    circuit_breakers = [
        {"tool": tool, "payload_hash": payload_hash, "count": count}
        for (tool, payload_hash), count in blocked_pairs.items()
        if count >= 2
    ]

    return {
        "schema_version": 1,
        "generated_at": iso(current),
        "risk": risk,
        "reasons": reasons,
        "counts_24h": dict(sorted(counts_24h.items())),
        "counts_24h_raw": dict(sorted(raw_counts_24h.items())),
        "suppressed_non_actionable_24h": len(recent_24h_raw) - len(recent_24h),
        "counts_7d": dict(sorted(counts_7d.items())),
        "severity_24h": dict(sorted(severity_24h.items())),
        "circuit_breakers": circuit_breakers,
        "policy": {
            "automatic_retry_after_upstream_block": False,
            "same_fingerprint_retry_limit_24h": 1,
            "store_raw_tool_arguments": False,
            "alter_platform_safeguards": False,
        },
        "epistemic_gap": (
            "Upstream blocks are invisible to local tunnel logs unless explicitly recorded; "
            "OpenAI's internal classifier reason and account-level risk score are not exposed."
        ),
    }


def _event_after(event: dict[str, Any], cutoff: dt.datetime) -> bool:
    value = event.get("timestamp")
    return isinstance(value, str) and _safe_after(value, cutoff)


def render_report(status: dict[str, Any]) -> str:
    events = load_jsonl(EVENTS_PATH)
    actionable = [event for event in events if is_actionable_event(event)]
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for event in actionable:
        key = (
            str(event.get("fingerprint", "")),
            str(event.get("kind", "")),
            str(event.get("tool", "")),
            str(event.get("message", "")),
        )
        item = grouped.setdefault(key, {"event": event, "count": 0})
        item["event"] = event
        item["count"] += 1
    recent = sorted(
        grouped.values(),
        key=lambda item: str(item["event"].get("timestamp", "")),
    )[-20:]
    lines = [
        "# Grabowski Safety Observer",
        "",
        f"Generated: {status['generated_at']}",
        f"Risk: **{status['risk']}**",
        "",
        "## Reasons",
    ]
    lines.extend(f"- {reason}" for reason in status.get("reasons", []))
    lines.extend(["", "## Counts (24h)"])
    counts = status.get("counts_24h", {})
    if counts:
        lines.extend(f"- {key}: {value}" for key, value in counts.items())
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            f"Suppressed non-actionable lifecycle/probe incidents (24h): {status.get('suppressed_non_actionable_24h', 0)}",
            "",
            "## Circuit breakers",
        ]
    )
    breakers = status.get("circuit_breakers", [])
    if breakers:
        for item in breakers:
            lines.append(
                f"- {item['tool']} / {item['payload_hash'][:12]}: {item['count']} blocks; do not auto-retry"
            )
    else:
        lines.append("- none")
    lines.extend(["", "## Recent incidents"])
    if recent:
        for item in reversed(recent):
            event = item["event"]
            suffix = f" | x{item['count']}" if item["count"] > 1 else ""
            lines.append(
                "- {timestamp} | {severity} | {kind} | {tool} | {message}{suffix}".format(
                    timestamp=event.get("timestamp", ""),
                    severity=event.get("severity", ""),
                    kind=event.get("kind", ""),
                    tool=event.get("tool", ""),
                    message=event.get("message", ""),
                    suffix=suffix,
                )
            )
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Operating rule",
            "",
            "An upstream policy block is evidence to stop and reclassify the operation, not a signal to retry with disguised wording.",
            "Raw arguments, secrets, conversation text, and file contents are not stored.",
            "",
            "## Epistemic gap",
            "",
            str(status.get("epistemic_gap", "")),
            "",
        ]
    )
    return "\n".join(lines)


def command_record(args: argparse.Namespace) -> int:
    event = record_event(
        kind=args.kind,
        source=args.source,
        tool=args.tool,
        operation_class=args.operation_class,
        message=args.message,
        payload_hash=args.payload_hash,
        severity=args.severity,
        evidence={"user_confirmed": bool(args.user_confirmed)},
    )
    status = build_status()
    atomic_json(STATUS_PATH, status)
    REPORT_PATH.write_text(render_report(status), encoding="utf-8")
    os.chmod(REPORT_PATH, 0o600)
    print(json.dumps(event, ensure_ascii=False, sort_keys=True))
    return 0


def command_report(_: argparse.Namespace) -> int:
    status = build_status()
    atomic_json(STATUS_PATH, status)
    report = render_report(status)
    REPORT_PATH.write_text(report, encoding="utf-8")
    os.chmod(REPORT_PATH, 0o600)
    print(report)
    return 0


def command_health(_: argparse.Namespace) -> int:
    status = build_status()
    print(json.dumps(status, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if status["risk"] != "red" else 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("collect")
    sub.add_parser("report")
    sub.add_parser("health")
    record = sub.add_parser("record")
    record.add_argument("--kind", required=True, choices=sorted(EVENT_KINDS))
    record.add_argument("--source", required=True)
    record.add_argument("--tool", default="")
    record.add_argument("--operation-class", default="unknown", choices=sorted(OPERATION_CLASSES))
    record.add_argument("--payload-hash", default="")
    record.add_argument("--message", default="")
    record.add_argument("--severity", choices=sorted(SEVERITY))
    record.add_argument("--user-confirmed", action="store_true")
    return root


def main() -> int:
    args = parser().parse_args()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if args.command == "collect":
            status = collect()
            print(json.dumps(status, ensure_ascii=False, sort_keys=True))
            return 0
        if args.command == "record":
            return command_record(args)
        if args.command == "report":
            return command_report(args)
        if args.command == "health":
            return command_health(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
