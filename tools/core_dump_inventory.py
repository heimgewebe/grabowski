#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

MAX_ERRORS = 100


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_regular(path: Path, expected: os.stat_result) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink < 1
            or _identity(opened) != _identity(expected)
            or _identity(linked) != _identity(expected)
        ):
            raise OSError("core candidate changed before hashing")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        rebound = path.lstat()
        if _identity(opened) != _identity(after) or _identity(opened) != _identity(rebound):
            raise OSError("core candidate changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _bounded_error(
    errors: list[dict[str, str]],
    *,
    path: Path,
    error: BaseException,
) -> bool:
    if len(errors) >= MAX_ERRORS:
        return False
    errors.append({"path": str(path), "error": str(error)[:240]})
    return True


def inventory(
    roots: list[Path],
    *,
    max_depth: int,
    hash_max_bytes: int,
) -> dict[str, Any]:
    if not 0 <= max_depth <= 20:
        raise ValueError("max-depth must be between 0 and 20")
    if not 0 <= hash_max_bytes <= 2 * 1024 * 1024 * 1024:
        raise ValueError("hash-max-bytes is out of range")

    records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    error_count = 0
    resolved_roots: list[str] = []
    for root in roots:
        raw = Path(os.path.abspath(os.fspath(root.expanduser())))
        metadata = raw.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"root must be a non-symlink directory: {raw}")
        resolved = raw.resolve(strict=True)
        if resolved != raw:
            raise ValueError(f"root contains a symlink component: {raw}")
        resolved_roots.append(str(resolved))
        root_depth = len(resolved.parts)
        for current, directories, files in os.walk(resolved, followlinks=False):
            current_path = Path(current)
            depth = len(current_path.parts) - root_depth
            retained_directories: list[str] = []
            if depth < max_depth:
                for name in directories:
                    candidate = current_path / name
                    try:
                        child = candidate.lstat()
                        if stat.S_ISDIR(child.st_mode) and not stat.S_ISLNK(child.st_mode):
                            retained_directories.append(name)
                    except OSError as exc:
                        error_count += 1
                        _bounded_error(errors, path=candidate, error=exc)
            directories[:] = retained_directories

            for name in files:
                if not name.startswith("core"):
                    continue
                path = current_path / name
                try:
                    candidate = path.lstat()
                    if stat.S_ISLNK(candidate.st_mode) or not stat.S_ISREG(candidate.st_mode):
                        continue
                    record: dict[str, Any] = {
                        "path": str(path),
                        "root": str(resolved),
                        "apparent_bytes": candidate.st_size,
                        "allocated_bytes": candidate.st_blocks * 512,
                        "mtime_ns": candidate.st_mtime_ns,
                        "mode": oct(stat.S_IMODE(candidate.st_mode)),
                    }
                    if candidate.st_size <= hash_max_bytes:
                        record["sha256"] = _hash_regular(path, candidate)
                    else:
                        record["sha256"] = None
                        record["hash_omitted_reason"] = "file_exceeds_hash_max_bytes"
                    records.append(record)
                except OSError as exc:
                    error_count += 1
                    _bounded_error(errors, path=path, error=exc)
    records.sort(key=lambda item: item["path"])
    return {
        "schema_version": 1,
        "roots": resolved_roots,
        "max_depth": max_depth,
        "hash_max_bytes": hash_max_bytes,
        "count": len(records),
        "total_apparent_bytes": sum(item["apparent_bytes"] for item in records),
        "total_allocated_bytes": sum(item["allocated_bytes"] for item in records),
        "files": records,
        "error_count": error_count,
        "errors": errors,
        "errors_truncated": error_count > len(errors),
        "does_not_establish": [
            "crash_root_cause",
            "safe_deletion",
            "complete_host_inventory_outside_explicit_roots",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--hash-max-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    try:
        result = inventory(
            args.roots,
            max_depth=args.max_depth,
            hash_max_bytes=args.hash_max_bytes,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
