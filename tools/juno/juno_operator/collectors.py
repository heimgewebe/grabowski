from __future__ import annotations

import itertools
import json
import os
import platform
import shutil
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .models import CollectorResult, utc_now
from .paths import discover_storage_roots

MAX_HTTP_BYTES = 128 * 1024
MAX_ENTRIES = 100
ALLOWED_TARGETS: dict[str, dict[str, Any]] = {
    "juno-agent": {
        "kind": "http",
        "url": "http://127.0.0.1:8765/health",
    },
    "heim-pc-ssh": {
        "kind": "tcp",
        "host": "100.68.88.111",
        "port": 22,
    },
    "heim-pc-https": {
        "kind": "tcp",
        "host": "100.68.88.111",
        "port": 443,
    },
}
ALLOWED_TARGET_FIELDS = {
    "id",
    "label",
    "kind",
    "url",
    "host",
    "port",
    "timeout_seconds",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def collect_runtime(project_root: Path) -> CollectorResult:
    data = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "project_root": str(project_root.resolve()),
        "process_id": os.getpid(),
    }
    return CollectorResult("juno-runtime", "healthy", utc_now(), data)


def _entry_type(path: Path) -> str:
    try:
        if path.is_symlink():
            return "symlink"
        if path.is_dir():
            return "directory"
        if path.is_file():
            return "file"
    except OSError:
        pass
    return "other"


def _bounded_entries(path: Path) -> tuple[list[dict[str, Any]], bool]:
    entries: list[dict[str, Any]] = []
    iterator = path.iterdir()
    observed = list(itertools.islice(iterator, MAX_ENTRIES + 1))
    truncated = len(observed) > MAX_ENTRIES
    for entry in sorted(observed[:MAX_ENTRIES], key=lambda item: item.name.casefold()):
        try:
            metadata = entry.lstat()
            entry_type = _entry_type(entry)
            entries.append(
                {
                    "name": entry.name,
                    "type": entry_type,
                    "size_bytes": metadata.st_size if entry_type == "file" else None,
                    "mtime_unix": int(metadata.st_mtime),
                }
            )
        except OSError as exc:
            entries.append(
                {
                    "name": entry.name,
                    "type": "unreadable",
                    "error": type(exc).__name__,
                }
            )
    return entries, truncated


def collect_storage(
    project_root: Path,
    *,
    local_config_path: Path | None = None,
) -> CollectorResult:
    roots: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        discovered_roots = discover_storage_roots(
            project_root,
            local_config_path=local_config_path,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return CollectorResult(
            "storage",
            "warning",
            utc_now(),
            {"roots": []},
            errors=(f"local storage root catalog invalid: {exc}",),
        )
    for label, path in discovered_roots:
        record: dict[str, Any] = {
            "label": label,
            "path": str(path),
            "readable": os.access(path, os.R_OK),
            "writable_hint": os.access(path, os.W_OK),
        }
        try:
            usage = shutil.disk_usage(path)
            record["disk"] = {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "free_ratio": (
                    round(usage.free / usage.total, 4) if usage.total else None
                ),
            }
        except OSError as exc:
            record["disk_error"] = f"{type(exc).__name__}: {exc}"
        try:
            entries, truncated = _bounded_entries(path)
        except OSError as exc:
            entries = []
            truncated = False
            record["list_error"] = f"{type(exc).__name__}: {exc}"
            warnings.append(f"{label} could not be listed")
        record["entries"] = entries
        record["entry_count_observed"] = len(entries)
        record["entries_truncated"] = truncated
        roots.append(record)

    if not roots:
        return CollectorResult(
            "storage",
            "unknown",
            utc_now(),
            {"roots": []},
            errors=("no readable storage roots discovered",),
        )

    low_space = any(
        isinstance(root.get("disk"), dict)
        and isinstance(root["disk"].get("free_ratio"), float)
        and root["disk"]["free_ratio"] < 0.1
        for root in roots
    )
    if low_space:
        warnings.append("less than 10 percent free space")
    status = "warning" if warnings else "healthy"
    return CollectorResult(
        "storage",
        status,
        utc_now(),
        {"roots": roots},
        tuple(warnings),
    )


def load_targets(config_path: Path) -> list[dict[str, Any]]:
    try:
        document = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("target config schema must be version 1")
    if set(document) != {"schema_version", "targets"}:
        raise ValueError("target config contains unknown fields")
    targets = document.get("targets")
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for target in targets:
        if (
            not isinstance(target, dict)
            or not isinstance(target.get("id"), str)
            or target.get("kind") not in {"tcp", "http"}
        ):
            raise ValueError("invalid target entry")
        if set(target) - ALLOWED_TARGET_FIELDS:
            raise ValueError("target contains unknown fields")

        target_id = target["id"]
        expected = ALLOWED_TARGETS.get(target_id)
        if expected is None:
            raise ValueError("target is not in the fixed allowlist")
        if target_id in seen:
            raise ValueError("duplicate target id")
        seen.add(target_id)

        for field, expected_value in expected.items():
            if target.get(field) != expected_value:
                raise ValueError(
                    f"target {target_id} does not match its fixed endpoint"
                )

        label = target.get("label", target_id)
        if not isinstance(label, str) or not label or len(label) > 120:
            raise ValueError("target label is invalid")
        timeout = target.get("timeout_seconds", 3)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0.2 <= float(timeout) <= 10.0
        ):
            raise ValueError("target timeout is outside the bounded contract")
        normalized.append(dict(target))
    return normalized


def _tcp_probe(target: dict[str, Any]) -> dict[str, Any]:
    host = str(target["host"])
    port = int(target["port"])
    timeout = float(target.get("timeout_seconds", 3))
    with socket.create_connection((host, port), timeout=timeout) as connection:
        peer = connection.getpeername()
    return {"reachable": True, "peer": [str(peer[0]), int(peer[1])]}


def _http_probe(target: dict[str, Any]) -> dict[str, Any]:
    url = str(target["url"])
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("unsafe target URL")
    timeout = float(target.get("timeout_seconds", 3))
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "JunoOperator/0.1"},
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect,
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(MAX_HTTP_BYTES + 1)
            if len(payload) > MAX_HTTP_BYTES:
                raise ValueError("response exceeds maximum size")
            content_type = response.headers.get("Content-Type", "")
            result: dict[str, Any] = {
                "reachable": True,
                "status_code": int(response.status),
                "content_type": content_type,
                "bytes": len(payload),
            }
            if "json" in content_type.lower():
                try:
                    decoded = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    result["json_valid"] = False
                else:
                    result["json_valid"] = True
                    if isinstance(decoded, dict):
                        allowed_health_fields = {
                            "service",
                            "status",
                            "started_at",
                            "observed_at",
                            "paired",
                            "state_persistent",
                            "secret_source",
                        }
                        result["selected_fields"] = {
                            key: decoded[key]
                            for key in sorted(allowed_health_fields & decoded.keys())
                        }
            return result
    except urllib.error.HTTPError as exc:
        return {
            "reachable": True,
            "status_code": int(exc.code),
            "http_error": True,
        }


def collect_targets(config_path: Path) -> CollectorResult:
    try:
        targets = load_targets(config_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return CollectorResult(
            "targets",
            "warning",
            utc_now(),
            {"targets": []},
            errors=(str(exc),),
        )

    results: list[dict[str, Any]] = []
    unhealthy = 0
    for target in targets:
        item: dict[str, Any] = {
            "id": target["id"],
            "label": target.get("label", target["id"]),
            "kind": target["kind"],
        }
        try:
            result = (
                _tcp_probe(target)
                if target["kind"] == "tcp"
                else _http_probe(target)
            )
            item["result"] = result
            status_code = result.get("status_code")
            if isinstance(status_code, int) and not 200 <= status_code < 300:
                item["status"] = "warning"
                unhealthy += 1
            else:
                item["status"] = "healthy"
        except (OSError, ValueError, urllib.error.URLError) as exc:
            item["status"] = "unreachable"
            item["error"] = f"{type(exc).__name__}: {exc}"
            unhealthy += 1
        results.append(item)

    status = "healthy" if not unhealthy else "warning"
    warnings = () if not unhealthy else (f"{unhealthy} target(s) need attention",)
    return CollectorResult(
        "targets",
        status,
        utc_now(),
        {"targets": results},
        warnings,
    )
