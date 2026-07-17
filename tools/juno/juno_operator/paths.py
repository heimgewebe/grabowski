from __future__ import annotations

import glob
import json
import os
from pathlib import Path
from typing import Any

LOCAL_ROOT_SCHEMA_VERSION = 1
MAX_LOCAL_ROOTS = 20
MAX_LABEL_CHARS = 120
MAX_PATH_CHARS = 4096
ALLOWED_LOCAL_ROOT_PREFIXES = (
    "/private/var/mobile/Containers/Shared/AppGroup/",
    "/private/var/mobile/Containers/Data/Application/",
    "/private/var/mobile/Library/Mobile Documents/",
)


def _safe_resolve(path: Path) -> Path | None:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    try:
        if not resolved.is_dir() or not os.access(resolved, os.R_OK):
            return None
    except OSError:
        return None
    return resolved


def _document_ancestor(start: Path) -> Path | None:
    resolved = _safe_resolve(start)
    if resolved is None:
        return None
    for candidate in (resolved, *resolved.parents):
        if candidate.name == "Documents":
            return candidate
    return None


def _validate_local_root_path(value: Any) -> Path:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_CHARS:
        raise ValueError("local storage root path is invalid")
    if "\x00" in value or not value.startswith(ALLOWED_LOCAL_ROOT_PREFIXES):
        raise ValueError("local storage root path is outside allowed iPad document domains")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("local storage root path must be absolute and normalized")
    if path.name != "File Provider Storage" and "Documents" not in path.parts:
        raise ValueError("local storage root path is not a document-provider root")
    return path


def load_local_storage_roots(config_path: Path) -> list[tuple[str, Path]]:
    try:
        document = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if not isinstance(document, dict) or document.get("schema_version") != LOCAL_ROOT_SCHEMA_VERSION:
        raise ValueError("local storage root config schema must be version 1")
    if set(document) != {"schema_version", "roots"}:
        raise ValueError("local storage root config contains unknown fields")
    roots = document.get("roots")
    if not isinstance(roots, list) or len(roots) > MAX_LOCAL_ROOTS:
        raise ValueError("local storage roots must be a bounded list")

    normalized: list[tuple[str, Path]] = []
    labels: set[str] = set()
    raw_paths: set[str] = set()
    for record in roots:
        if not isinstance(record, dict) or set(record) != {"label", "path"}:
            raise ValueError("local storage root entry is invalid")
        label = record.get("label")
        if not isinstance(label, str) or not label or len(label) > MAX_LABEL_CHARS:
            raise ValueError("local storage root label is invalid")
        path = _validate_local_root_path(record.get("path"))
        marker = os.fspath(path)
        if label in labels or marker in raw_paths:
            raise ValueError("local storage root entry is duplicated")
        labels.add(label)
        raw_paths.add(marker)
        normalized.append((label, path))
    return normalized


def discover_storage_roots(
    project_root: Path,
    local_config_path: Path | None = None,
) -> list[tuple[str, Path]]:
    candidates: list[tuple[str, Path]] = []
    juno_documents = _document_ancestor(project_root)
    if juno_documents is not None:
        candidates.append(("Juno-Dokumente", juno_documents))

    if local_config_path is not None:
        candidates.extend(load_local_storage_roots(local_config_path))

    fixed_patterns = [
        (
            "Auf meinem iPad",
            "/private/var/mobile/Containers/Shared/AppGroup/*/File Provider Storage",
        ),
        (
            "iCloud Drive",
            "/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs",
        ),
        (
            "Pythonista iCloud",
            "/private/var/mobile/Library/Mobile Documents/"
            "iCloud~com~omz-software~Pythonista3/Documents",
        ),
        (
            "vault-gewebe",
            "/private/var/mobile/Containers/Data/Application/*/Documents/vault-gewebe",
        ),
    ]
    for label, pattern in fixed_patterns:
        for raw_path in sorted(glob.glob(pattern)):
            candidates.append((label, Path(raw_path)))

    unique: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for label, candidate in candidates:
        resolved = _safe_resolve(candidate)
        if resolved is None:
            continue
        marker = os.fspath(resolved)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append((label, resolved))
    return unique


def project_paths(project_root: Path) -> dict[str, Path]:
    root = project_root.expanduser().resolve()
    return {
        "root": root,
        "config": root / "config" / "targets.json",
        "local_storage_roots": root / "config" / "storage-roots.local.json",
        "state": root / "state",
        "cache": root / "state" / "latest.json",
        "dashboard": root / "dashboard.html",
        "incidents": root / "incidents",
    }
