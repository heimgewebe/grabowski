#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Iterable

SCHEMA_VERSION = 1
KIND = "grabowski_process_reference_observation"
ALLOWED_ROOTS = (
    Path("/home/alex/repos/.weltgewebe-worktrees"),
    Path("/home/alex/worktrees"),
    Path("/home/alex/repos/.semantah-worktrees"),
    Path("/home/alex/repos/.heimlern-worktrees"),
    Path("/home/alex/repos/.operator-redundancy-worktrees"),
    Path("/home/alex/repos/.hauski-worktrees"),
    Path("/home/alex/repos/.worktree-target-quarantine"),
)
MAX_ROOTS = 256
EXPECTED_TARGET_UID = 1000
MAX_REFERENCES = 64
MAX_PROCESS_LIMIT = 65_536
MAX_FD_LIMIT = 1_000_000
LINK_KINDS = ("cwd", "exe", "root")


class ObservationError(ValueError):
    pass


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _bounded_integer(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ObservationError(f"{label} is invalid")
    return value


def _path_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


def _validate_root(raw: Any, *, target_uid: int) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ObservationError("root must be a non-empty path")
    path = Path(raw)
    if not path.is_absolute() or os.path.normpath(raw) != raw:
        raise ObservationError("root must be canonical and absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ObservationError(f"root cannot be inspected: {raw}") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ObservationError(f"root is not a regular directory: {raw}")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ObservationError(f"root cannot be resolved: {raw}") from exc
    if resolved != path:
        raise ObservationError(f"root is not canonical: {raw}")
    if metadata.st_uid != target_uid:
        raise ObservationError(f"root owner differs from target_uid: {raw}")
    if not any(_path_within(path, allowed) for allowed in ALLOWED_ROOTS):
        raise ObservationError(f"root is outside the allowed prefixes: {raw}")
    return path


def normalize_request(value: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "target_uid",
        "roots",
        "max_processes",
        "max_file_descriptors",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ObservationError("request keys are invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ObservationError("request schema_version is unsupported")
    target_uid = _bounded_integer(
        value.get("target_uid"), label="target_uid", minimum=0, maximum=2**31 - 1
    )
    if target_uid != EXPECTED_TARGET_UID:
        raise ObservationError("target_uid is not the configured workstation owner")
    roots_value = value.get("roots")
    if not isinstance(roots_value, list) or not 1 <= len(roots_value) <= MAX_ROOTS:
        raise ObservationError("roots must be a non-empty bounded list")
    roots = sorted({_validate_root(raw, target_uid=target_uid) for raw in roots_value}, key=str)
    if len(roots) != len(roots_value):
        raise ObservationError("roots must not contain duplicates")
    return {
        "schema_version": SCHEMA_VERSION,
        "target_uid": target_uid,
        "roots": roots,
        "max_processes": _bounded_integer(
            value.get("max_processes"),
            label="max_processes",
            minimum=1,
            maximum=MAX_PROCESS_LIMIT,
        ),
        "max_file_descriptors": _bounded_integer(
            value.get("max_file_descriptors"),
            label="max_file_descriptors",
            minimum=1,
            maximum=MAX_FD_LIMIT,
        ),
    }


def _matching_root(raw_path: str, roots: Iterable[Path]) -> tuple[Path, Path] | None:
    if not raw_path.startswith("/"):
        return None
    clean = raw_path.removesuffix(" (deleted)")
    normalized = Path(os.path.normpath(clean))
    for root in roots:
        if _path_within(normalized, root):
            return root, normalized
    return None


def _record_reference(
    records: dict[tuple[int, int, str, str, str], dict[str, Any]],
    *,
    pid: int,
    uid: int,
    kind: str,
    raw_path: str,
    roots: list[Path],
) -> bool:
    match = _matching_root(raw_path, roots)
    if match is None:
        return True
    root, path = match
    key = (pid, uid, kind, str(root), str(path))
    if key not in records and len(records) >= MAX_REFERENCES:
        return False
    records[key] = {
        "pid": pid,
        "uid": uid,
        "kind": kind,
        "root": str(root),
        "path": str(path),
    }
    return True


def observe_process_references(
    request: dict[str, Any],
    *,
    proc_root: Path = Path("/proc"),
) -> dict[str, Any]:
    normalized = normalize_request(request)
    roots: list[Path] = normalized["roots"]
    process_count = 0
    fd_count = 0
    complete = True
    errors: set[str] = set()
    references: dict[tuple[int, int, str, str, str], dict[str, Any]] = {}

    try:
        process_entries = sorted(
            (entry for entry in proc_root.iterdir() if entry.name.isdigit()),
            key=lambda entry: int(entry.name),
        )
    except OSError as exc:
        raise ObservationError("proc root cannot be listed") from exc

    stop = False
    for entry in process_entries:
        process_count += 1
        if process_count > normalized["max_processes"]:
            complete = False
            errors.add("process-limit-exceeded")
            break
        pid = int(entry.name)
        try:
            uid = entry.stat().st_uid
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            complete = False
            errors.add("process-permission")
            continue
        except OSError as exc:
            complete = False
            errors.add(f"process-stat:{exc.errno}")
            continue

        for kind in LINK_KINDS:
            try:
                raw_path = os.readlink(entry / kind)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                complete = False
                errors.add(f"{kind}-permission")
                continue
            except OSError as exc:
                complete = False
                errors.add(f"{kind}-readlink:{exc.errno}")
                continue
            if not _record_reference(
                references,
                pid=pid,
                uid=uid,
                kind=kind,
                raw_path=raw_path,
                roots=roots,
            ):
                complete = False
                errors.add("reference-limit-exceeded")
                stop = True
                break

        try:
            descriptors = sorted(
                (item for item in (entry / "fd").iterdir() if item.name.isdigit()),
                key=lambda item: int(item.name),
            )
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            complete = False
            errors.add("fd-permission")
            continue
        except OSError as exc:
            complete = False
            errors.add(f"fd-list:{exc.errno}")
            continue

        for descriptor in descriptors:
            fd_count += 1
            if fd_count > normalized["max_file_descriptors"]:
                complete = False
                errors.add("file-descriptor-limit-exceeded")
                stop = True
                break
            try:
                raw_path = os.readlink(descriptor)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                complete = False
                errors.add("fd-readlink-permission")
                continue
            except OSError as exc:
                complete = False
                errors.add(f"fd-readlink:{exc.errno}")
                continue
            if not _record_reference(
                references,
                pid=pid,
                uid=uid,
                kind="fd",
                raw_path=raw_path,
                roots=roots,
            ):
                complete = False
                errors.add("reference-limit-exceeded")
                stop = True
                break
        if stop:
            break

    material = {
        "kind": KIND,
        "schema_version": SCHEMA_VERSION,
        "complete": complete,
        "target_uid": normalized["target_uid"],
        "roots": [str(root) for root in roots],
        "process_count": min(process_count, normalized["max_processes"]),
        "open_file_descriptors_checked": min(
            fd_count, normalized["max_file_descriptors"]
        ),
        "path_references": [references[key] for key in sorted(references)],
        "errors": sorted(errors),
    }
    return {**material, "observation_sha256": _canonical_sha256(material)}


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if os.geteuid() != 0:
        raise PermissionError("process reference observer must run as root")
    if len(arguments) != 1:
        raise ObservationError("exactly one JSON request argument is required")
    try:
        value = json.loads(arguments[0])
    except json.JSONDecodeError as exc:
        raise ObservationError("request JSON is invalid") from exc
    print(json.dumps(observe_process_references(value), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ObservationError, PermissionError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)
