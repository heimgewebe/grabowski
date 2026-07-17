from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .collectors import collect_runtime, collect_storage, collect_targets
from .models import Snapshot, utc_now
from .paths import project_paths
from .render import render

SCHEMA_VERSION = 1


def _atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_text(path: Path, text: str) -> None:
    _atomic_bytes(path, text.encode("utf-8"))


def _atomic_json(path: Path, value: Any) -> None:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    _atomic_text(path, payload)


def refresh(project_root: Path | str = ".") -> tuple[Snapshot, Path]:
    paths = project_paths(Path(project_root))
    snapshot = Snapshot(
        schema_version=SCHEMA_VERSION,
        generated_at=utc_now(),
        results=(
            collect_runtime(paths["root"]),
            collect_storage(
                paths["root"],
                local_config_path=paths["local_storage_roots"],
            ),
            collect_targets(paths["config"]),
        ),
    )
    _atomic_json(paths["cache"], snapshot.to_dict())
    render(snapshot, paths["dashboard"])
    return snapshot, paths["dashboard"]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def create_incident(project_root: Path | str = ".") -> Path:
    paths = project_paths(Path(project_root))
    snapshot, dashboard = refresh(paths["root"])
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination = paths["incidents"] / f"incident-{timestamp}"
    destination.mkdir(parents=True, exist_ok=False)

    snapshot_path = destination / "snapshot.json"
    _atomic_json(snapshot_path, snapshot.to_dict())

    warning_count = sum(
        len(item.warnings) + len(item.errors) for item in snapshot.results
    )
    summary_path = destination / "summary.md"
    _atomic_text(
        summary_path,
        "# Juno Operator Incident\n\n"
        f"- Erzeugt: {snapshot.generated_at}\n"
        f"- Gesamtzustand: {snapshot.overall_status}\n"
        f"- Hinweise/Fehler: {warning_count}\n"
        "- Modus: read-only collectors; nur dieses Incident-Paket wurde geschrieben\n",
    )

    dashboard_copy = destination / "dashboard.html"
    _atomic_bytes(dashboard_copy, dashboard.read_bytes())

    artifacts = [snapshot_path, summary_path, dashboard_copy]
    checksums = {
        artifact.name: {
            "sha256": _sha256(artifact),
            "bytes": artifact.stat().st_size,
        }
        for artifact in artifacts
    }
    _atomic_json(destination / "checksums.json", checksums)
    _atomic_json(
        destination / "manifest.json",
        {
            "schema_version": 1,
            "created_at": snapshot.generated_at,
            "overall_status": snapshot.overall_status,
            "artifacts": sorted([*checksums, "checksums.json"]),
            "privacy": (
                "No secrets, environment dump, file contents or recursive "
                "private-folder scans are collected."
            ),
        },
    )
    return destination
