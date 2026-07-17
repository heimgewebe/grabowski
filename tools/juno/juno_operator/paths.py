from __future__ import annotations

import glob
import os
from pathlib import Path


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


def discover_storage_roots(project_root: Path) -> list[tuple[str, Path]]:
    candidates: list[tuple[str, Path]] = []
    juno_documents = _document_ancestor(project_root)
    if juno_documents is not None:
        candidates.append(("Juno-Dokumente", juno_documents))

    fixed_patterns = [
        ("Auf meinem iPad", "/private/var/mobile/Containers/Shared/AppGroup/*/File Provider Storage"),
        ("iCloud Drive", "/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs"),
        ("Pythonista iCloud", "/private/var/mobile/Library/Mobile Documents/iCloud~com~omz-software~Pythonista3/Documents"),
        ("vault-gewebe", "/private/var/mobile/Containers/Data/Application/*/Documents/vault-gewebe"),
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
        "state": root / "state",
        "cache": root / "state" / "latest.json",
        "dashboard": root / "dashboard.html",
        "incidents": root / "incidents",
    }
