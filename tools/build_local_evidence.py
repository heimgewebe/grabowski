#!/usr/bin/env python3

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fnmatch import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
from typing import Any
import uuid


SCHEMA_VERSION = 1
BUILDER_VERSION = "1.0.0"
MAX_JOB_BYTES = 64 * 1024
MAX_PATCH_BYTES = 2_000_000
MAX_ALLOWED_PATHS = 200
MAX_REFERENCE_TERMS = 25
MAX_REFERENCES_PER_CATEGORY = 500
MAX_REFERENCE_FILE_BYTES = 2_000_000
MAX_REFERENCE_TOTAL_BYTES = 50_000_000
MAX_UNTRACKED_FILE_BYTES = 2_000_000
MAX_UNTRACKED_TOTAL_BYTES = 10_000_000
MAX_VISIBLE_CHANGES = 5_000
MAX_PATCH_PATHS = 1_000
MAX_PATCH_ARGUMENT_BYTES = 200_000
MAX_UNTRACKED_RECORDS = 1_000
JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
HEAD_RE = re.compile(r"^[0-9a-fA-F]{40}$")
JOB_FIELDS = {
    "schema_version",
    "job_id",
    "mode",
    "repo",
    "task",
    "expected_branch",
    "expected_head",
    "allowed_paths",
    "max_patch_bytes",
}
DEFAULT_FORBIDDEN_COMPONENTS = {
    ".git",
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".password-store",
    ".local/share/keyrings",
}
DEFAULT_FORBIDDEN_PATTERNS = {
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
}
_SECRET_KEY_PREFIX = "s" + "k-"
_OPENAI_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"(?:(?:proj|svcacct|admin)-[A-Za-z0-9._-]{20,}|[A-Za-z0-9]{24,})(?![A-Za-z0-9._-])"
)
_ANTHROPIC_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"ant-[A-Za-z0-9._-]{20,}(?![A-Za-z0-9._-])"
)
REDACTIONS = (
    (_OPENAI_SECRET_PATTERN, "<REDACTED_OPENAI_KEY>"),
    (_ANTHROPIC_SECRET_PATTERN, "<REDACTED_ANTHROPIC_KEY>"),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{12,}=*", re.I),
        "Bearer <REDACTED>",
    ),
    (
        re.compile(
            r"-----BEGIN [^-]*PRIVATE KEY-----.*?"
            r"-----END [^-]*PRIVATE KEY-----",
            re.S,
        ),
        "<REDACTED_PRIVATE_KEY>",
    ),
    (
        re.compile(
            r"(?im)^([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY)"
            r"[A-Z0-9_]*\s*=\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
)


class EvidenceError(RuntimeError):
    pass


class JobValidationError(EvidenceError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_bytes(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise EvidenceError(f"Refusing to overwrite artifact: {path}")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, payload: Any) -> None:
    _write_bytes(path, _json_bytes(payload))


def _absolute_path(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path


def _reject_symlink_components(path: Path, *, allow_missing: bool = False) -> None:
    candidate = _absolute_path(path)
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise EvidenceError(f"Symlink path component is forbidden: {current}")
        if not current.exists():
            if allow_missing:
                return
            raise EvidenceError(f"Path component does not exist: {current}")


def _ensure_directory_tree(path: Path) -> Path:
    candidate = _absolute_path(path)
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise EvidenceError(f"Symlink path component is forbidden: {current}")
        if current.exists():
            if not current.is_dir():
                raise EvidenceError(
                    f"Directory component is not a directory: {current}"
                )
            continue
        current.mkdir(mode=0o700)
    return candidate


def _load_job(path: Path) -> dict[str, Any]:
    path = _absolute_path(path)
    _reject_symlink_components(path)
    if not path.is_file():
        raise JobValidationError(f"Job must be a regular file: {path}")
    if path.stat().st_size > MAX_JOB_BYTES:
        raise JobValidationError(f"Job exceeds {MAX_JOB_BYTES} bytes")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JobValidationError(f"Job is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise JobValidationError("Job must be a JSON object")
    unknown = set(payload) - JOB_FIELDS
    if unknown:
        raise JobValidationError(f"Unknown job fields: {sorted(unknown)}")
    required = {
        "schema_version",
        "job_id",
        "mode",
        "repo",
        "task",
        "expected_branch",
        "expected_head",
        "allowed_paths",
        "max_patch_bytes",
    }
    missing = required - set(payload)
    if missing:
        raise JobValidationError(f"Missing job fields: {sorted(missing)}")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise JobValidationError("schema_version must be 1")
    if not isinstance(payload["job_id"], str) or not JOB_ID_RE.fullmatch(
        payload["job_id"]
    ):
        raise JobValidationError("job_id has an invalid format")
    if payload["mode"] != "repo-evidence":
        raise JobValidationError("mode must be repo-evidence")
    if not isinstance(payload["repo"], str) or not payload["repo"]:
        raise JobValidationError("repo must be a non-empty string")
    if not isinstance(payload["task"], str) or not payload["task"].strip():
        raise JobValidationError("task must contain non-whitespace text")
    if len(payload["task"]) > 10_000:
        raise JobValidationError("task exceeds 10000 characters")
    branch = payload["expected_branch"]
    if not isinstance(branch, str) or not branch or len(branch) > 255:
        raise JobValidationError("expected_branch is invalid")
    head = payload["expected_head"]
    if not isinstance(head, str) or not HEAD_RE.fullmatch(head):
        raise JobValidationError("expected_head must be a full 40-character SHA")
    max_patch = payload["max_patch_bytes"]
    if (
        not isinstance(max_patch, int)
        or isinstance(max_patch, bool)
        or not 1 <= max_patch <= MAX_PATCH_BYTES
    ):
        raise JobValidationError(
            f"max_patch_bytes must be between 1 and {MAX_PATCH_BYTES}"
        )
    payload["allowed_paths"] = _normalize_allowed_paths(payload["allowed_paths"])
    payload["expected_head"] = head.lower()
    return payload


def _normalize_allowed_paths(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_ALLOWED_PATHS:
        raise JobValidationError(
            f"allowed_paths must be an array with at most {MAX_ALLOWED_PATHS} items"
        )
    normalized: list[str] = []
    for raw in value:
        if not isinstance(raw, str) or not raw or len(raw) > 4096:
            raise JobValidationError("allowed_paths entries must be non-empty strings")
        if "\x00" in raw or "\\" in raw:
            raise JobValidationError(
                "allowed_paths entries contain forbidden characters"
            )
        path = PurePosixPath(raw)
        if path.is_absolute() or ".." in path.parts:
            raise JobValidationError(
                "allowed_paths entries must be relative and confined"
            )
        canonical = path.as_posix().rstrip("/") or "."
        if canonical in normalized:
            raise JobValidationError(f"Duplicate allowed path: {canonical}")
        normalized.append(canonical)
    return sorted(normalized)


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _resolve_existing_root(raw: str, label: str) -> Path:
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        raise EvidenceError(f"{label} must be absolute")
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise EvidenceError(f"{label} is not a directory: {resolved}")
    return resolved


def _resolve_repo(raw: str) -> Path:
    repo_root = _resolve_existing_root(
        os.environ.get("GRABOWSKI_REPO_ROOT", str(Path.home() / "repos")),
        "GRABOWSKI_REPO_ROOT",
    )
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        raise JobValidationError("repo must be an absolute path")
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir() or not _is_within(resolved, repo_root):
        raise JobValidationError(f"repo is outside configured root: {resolved}")
    return resolved


def _prepare_output(raw: str, job_id: str) -> tuple[Path, Path]:
    workspace_root_raw = os.environ.get(
        "GRABOWSKI_WORKSPACE_ROOT",
        str(Path.home() / "grabowski-workspace" / "jobs"),
    )
    workspace_root = Path(workspace_root_raw).expanduser()
    if not workspace_root.is_absolute():
        raise EvidenceError("GRABOWSKI_WORKSPACE_ROOT must be absolute")
    workspace_root = _ensure_directory_tree(workspace_root).resolve(strict=True)

    output = Path(raw).expanduser()
    if not output.is_absolute():
        raise EvidenceError("output must be absolute")
    _reject_symlink_components(output.parent)
    output_parent = output.parent.resolve(strict=True)
    final = output_parent / output.name
    if not _is_within(final, workspace_root):
        raise EvidenceError(f"output is outside configured workspace root: {final}")
    if final.exists() or final.is_symlink():
        raise EvidenceError(f"output already exists: {final}")
    temporary = output_parent / f".{job_id}.tmp-{uuid.uuid4().hex}"
    temporary.mkdir(mode=0o700)
    return temporary, final


def _load_sensitive_rules() -> tuple[set[str], set[str]]:
    components = set(DEFAULT_FORBIDDEN_COMPONENTS)
    patterns = set(DEFAULT_FORBIDDEN_PATTERNS)
    policy_raw = os.environ.get(
        "GRABOWSKI_POLICY_PATH",
        str(Path.home() / ".config" / "grabowski" / "access.json"),
    )
    policy = Path(policy_raw).expanduser()
    if not policy.exists():
        return components, patterns
    _reject_symlink_components(policy)
    if not policy.is_file() or policy.stat().st_size > MAX_JOB_BYTES:
        raise EvidenceError(f"Policy path is not a bounded regular file: {policy}")
    try:
        payload = json.loads(policy.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"Policy is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EvidenceError("Policy must be a JSON object")
    raw_components = payload.get("forbidden_components", [])
    raw_patterns = payload.get("forbidden_file_patterns", [])
    if not isinstance(raw_components, list) or not isinstance(raw_patterns, list):
        raise EvidenceError("Policy path rules must be arrays")
    if any(not isinstance(item, str) or not item for item in raw_components):
        raise EvidenceError(
            "Policy forbidden_components entries must be non-empty strings"
        )
    if any(not isinstance(item, str) or not item for item in raw_patterns):
        raise EvidenceError(
            "Policy forbidden_file_patterns entries must be non-empty strings"
        )
    for item in raw_components:
        component = PurePosixPath(item)
        if component.is_absolute() or ".." in component.parts:
            raise EvidenceError(
                "Policy forbidden_components entries must be confined relative paths"
            )
    components.update(raw_components)
    patterns.update(raw_patterns)
    return components, patterns


def _contains_component_sequence(path: PurePosixPath, raw: str) -> bool:
    sequence = PurePosixPath(raw).parts
    if not sequence:
        return False
    width = len(sequence)
    return any(
        path.parts[index : index + width] == sequence
        for index in range(len(path.parts) - width + 1)
    )


def _is_sensitive(
    relative_path: str,
    components: set[str],
    patterns: set[str],
) -> bool:
    path = PurePosixPath(relative_path)
    if any(_contains_component_sequence(path, item) for item in components):
        return True
    return any(fnmatch(path.name, pattern) for pattern in patterns)


def _path_allowed(path: str, allowed_paths: list[str]) -> bool:
    if not allowed_paths or "." in allowed_paths:
        return True
    return any(path == root or path.startswith(root + "/") for root in allowed_paths)


class GitReader:
    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.commands: list[dict[str, Any]] = []

    def run(
        self,
        arguments: list[str],
        *,
        accepted_returncodes: tuple[int, ...] = (0,),
    ) -> bytes:
        environment = os.environ.copy()
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["LC_ALL"] = "C"
        completed = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.commands.append(
            {
                "argv": ["git", "-C", str(self.repo), *arguments],
                "cwd": str(self.repo),
                "returncode": completed.returncode,
                "stdout_bytes": len(completed.stdout),
                "stdout_sha256": _sha256(completed.stdout),
                "stderr_bytes": len(completed.stderr),
                "stderr_sha256": _sha256(completed.stderr),
            }
        )
        if completed.returncode not in accepted_returncodes:
            message = completed.stderr.decode("utf-8", errors="replace").strip()
            raise EvidenceError(message or f"Git command failed: {arguments}")
        return completed.stdout


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _parse_status(data: bytes) -> list[dict[str, Any]]:
    records = data.split(b"\0")
    entries: list[dict[str, Any]] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise EvidenceError("Unexpected git status porcelain record")
        code = record[:2].decode("ascii", errors="replace")
        path = record[3:].decode("utf-8", errors="replace")
        entry: dict[str, Any] = {
            "path": path,
            "index_status": code[0],
            "worktree_status": code[1],
            "untracked": code == "??",
        }
        if code[0] in {"R", "C"} or code[1] in {"R", "C"}:
            if index >= len(records) or not records[index]:
                raise EvidenceError("Rename status record is incomplete")
            entry["original_path"] = records[index].decode("utf-8", errors="replace")
            index += 1
        entries.append(entry)
    return entries


def _branch(reader: GitReader) -> str | None:
    raw = reader.run(
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        accepted_returncodes=(0, 1),
    )
    value = _decode(raw).strip()
    return value or None


def _upstream(reader: GitReader) -> str | None:
    raw = reader.run(
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        accepted_returncodes=(0, 128),
    )
    value = _decode(raw).strip()
    return value or None


def _snapshot(
    reader: GitReader,
    allowed_paths: list[str],
    components: set[str],
    patterns: set[str],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    top = Path(_decode(reader.run(["rev-parse", "--show-toplevel"])).strip()).resolve()
    if top != reader.repo:
        raise JobValidationError(
            f"repo must identify the Git toplevel exactly: {reader.repo} != {top}"
        )
    head = _decode(reader.run(["rev-parse", "HEAD"])).strip().lower()
    branch = _branch(reader)
    upstream = _upstream(reader)
    raw_entries = _parse_status(
        reader.run(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    )
    counters = {
        "sensitive_omitted": 0,
        "outside_allowed_omitted": 0,
        "change_limit_omitted": 0,
    }
    visible: list[dict[str, Any]] = []
    for entry in raw_entries:
        paths = [entry["path"]]
        if "original_path" in entry:
            paths.append(entry["original_path"])
        if any(_is_sensitive(path, components, patterns) for path in paths):
            counters["sensitive_omitted"] += 1
            continue
        if not all(_path_allowed(path, allowed_paths) for path in paths):
            counters["outside_allowed_omitted"] += 1
            continue
        if len(visible) >= MAX_VISIBLE_CHANGES:
            counters["change_limit_omitted"] += 1
            continue
        visible.append(entry)
    state = {
        "schema_version": SCHEMA_VERSION,
        "repo": str(reader.repo),
        "head": head,
        "branch": branch,
        "upstream": upstream,
        "dirty": bool(raw_entries),
        "visible_change_count": len(visible),
        "sensitive_change_count_omitted": counters["sensitive_omitted"],
        "outside_allowed_change_count_omitted": counters["outside_allowed_omitted"],
        "change_limit_count_omitted": counters["change_limit_omitted"],
    }
    return state, visible, counters


def _redact(text: str) -> tuple[str, int]:
    result = text
    count = 0
    for pattern, replacement in REDACTIONS:
        result, matches = pattern.subn(replacement, result)
        count += matches
    return result, count


def _tracked_paths(entries: list[dict[str, Any]]) -> list[str]:
    return sorted({entry["path"] for entry in entries if not entry["untracked"]})


def _select_patch_paths(
    entries: list[dict[str, Any]],
    limitations: list[str],
) -> list[str]:
    selected: list[str] = []
    argument_bytes = 0
    omitted = 0
    for path in _tracked_paths(entries):
        encoded_bytes = len(os.fsencode(path)) + 1
        if (
            len(selected) >= MAX_PATCH_PATHS
            or argument_bytes + encoded_bytes > MAX_PATCH_ARGUMENT_BYTES
        ):
            omitted += 1
            continue
        selected.append(path)
        argument_bytes += encoded_bytes
    if omitted:
        limitations.append(
            f"{omitted} tracked patch path(s) exceeded the path or argument budget and were omitted."
        )
    return selected


def _read_patch_source(reader: GitReader, tracked_paths: list[str]) -> bytes:
    if not tracked_paths:
        return b""
    return reader.run(
        [
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
            "--",
            *tracked_paths,
        ]
    )


def _verify_untracked_sources(repo: Path, payload: dict[str, Any]) -> bool:
    for record in payload["records"]:
        relative = _safe_relative_artifact_path(record["path"])
        source = repo.joinpath(*relative.parts)
        reason = record.get("reason")
        if reason == "symlink":
            if not source.is_symlink():
                return False
            continue
        if reason == "not-regular-file":
            if source.is_file() or source.is_symlink():
                return False
            continue
        if not source.is_file() or source.is_symlink():
            return False
        if source.stat().st_size != record.get("source_bytes"):
            return False
        expected_hash = record.get("source_sha256")
        if expected_hash is not None and _sha256(source.read_bytes()) != expected_hash:
            return False
    return True


def _verify_reference_sources(repo: Path, hashes: dict[str, str]) -> bool:
    for raw_path, expected_hash in hashes.items():
        relative = _safe_relative_artifact_path(raw_path)
        source = repo.joinpath(*relative.parts)
        if source.is_symlink() or not source.is_file():
            return False
        if _sha256(source.read_bytes()) != expected_hash:
            return False
    return True


def _build_patch(
    reader: GitReader,
    entries: list[dict[str, Any]],
    max_bytes: int,
    limitations: list[str],
) -> tuple[bytes, str, list[str]]:
    tracked_paths = _select_patch_paths(entries, limitations)
    raw = _read_patch_source(reader, tracked_paths)
    text, redactions = _redact(_decode(raw))
    if redactions:
        limitations.append(
            f"Patch content contained {redactions} secret-like value(s) and was redacted."
        )
    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        marker = b"\n# GRABOWSKI_PATCH_TRUNCATED\n"
        prefix = encoded[: max(0, max_bytes - len(marker))]
        prefix = prefix.decode("utf-8", errors="ignore").encode("utf-8")
        encoded = prefix + marker
        limitations.append(
            f"Patch exceeded max_patch_bytes={max_bytes} and was explicitly truncated."
        )
    return encoded, _sha256(raw), tracked_paths


def _safe_relative_artifact_path(raw: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise EvidenceError(f"Unsafe repository-relative path: {raw!r}")
    return path


def _capture_untracked(
    repo: Path,
    entries: list[dict[str, Any]],
    bundle_root: Path,
    limitations: list[str],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    total_bytes = 0
    candidates = sorted(
        (item for item in entries if item["untracked"]),
        key=lambda item: item["path"],
    )
    omitted_records = max(0, len(candidates) - MAX_UNTRACKED_RECORDS)
    if omitted_records:
        limitations.append(
            f"{omitted_records} untracked file record(s) exceeded the record budget and were omitted."
        )
    for entry in candidates[:MAX_UNTRACKED_RECORDS]:
        raw_path = entry["path"]
        relative = _safe_relative_artifact_path(raw_path)
        source = repo.joinpath(*relative.parts)
        record: dict[str, Any] = {"path": raw_path, "captured": False}
        if source.is_symlink():
            record["reason"] = "symlink"
            limitations.append(f"Untracked symlink content was omitted: {raw_path}")
            records.append(record)
            continue
        if not source.is_file():
            record["reason"] = "not-regular-file"
            limitations.append(
                f"Untracked non-regular file content was omitted: {raw_path}"
            )
            records.append(record)
            continue
        size = source.stat().st_size
        record["source_bytes"] = size
        if size > MAX_UNTRACKED_FILE_BYTES:
            record["reason"] = "file-size-limit"
            limitations.append(
                f"Untracked file exceeded {MAX_UNTRACKED_FILE_BYTES} bytes and was omitted: {raw_path}"
            )
            records.append(record)
            continue
        if total_bytes + size > MAX_UNTRACKED_TOTAL_BYTES:
            record["reason"] = "total-size-limit"
            limitations.append(
                f"Untracked content reached the {MAX_UNTRACKED_TOTAL_BYTES}-byte total budget; omitted: {raw_path}"
            )
            records.append(record)
            continue
        data = source.read_bytes()
        record["source_sha256"] = _sha256(data)
        if b"\x00" in data:
            record["reason"] = "binary-content"
            limitations.append(f"Untracked binary content was omitted: {raw_path}")
            records.append(record)
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            record["reason"] = "non-utf8-content"
            limitations.append(f"Untracked non-UTF-8 content was omitted: {raw_path}")
            records.append(record)
            continue
        redacted, redactions = _redact(text)
        artifact = bundle_root / "untracked" / Path(*relative.parts)
        artifact.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        encoded = redacted.encode("utf-8")
        _write_bytes(artifact, encoded)
        total_bytes += size
        record.update(
            {
                "captured": True,
                "artifact": artifact.relative_to(bundle_root).as_posix(),
                "artifact_bytes": len(encoded),
                "artifact_sha256": _sha256(encoded),
                "redactions": redactions,
            }
        )
        if redactions:
            limitations.append(
                f"Untracked file contained {redactions} secret-like value(s) and was redacted: {raw_path}"
            )
        records.append(record)
    return {
        "schema_version": SCHEMA_VERSION,
        "captured_bytes_before_redaction": total_bytes,
        "records": records,
    }


def _category(path: str) -> str | None:
    name = PurePosixPath(path).name
    if (
        path.startswith("tests/")
        or name.startswith("test_")
        or any(marker in name for marker in (".test.", ".spec."))
    ):
        return "tests"
    if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
        return "workflows"
    if path.startswith("contracts/") or name.endswith(".schema.json"):
        return "contracts"
    if path.startswith("docs/") or name.lower().startswith("readme"):
        return "docs"
    return None


def _reference_terms(entries: list[dict[str, Any]]) -> list[str]:
    terms: set[str] = set()
    for entry in entries:
        path = PurePosixPath(entry["path"])
        for candidate in (path.name, path.stem):
            if len(candidate) >= 3:
                terms.add(candidate)
    return sorted(terms)[:MAX_REFERENCE_TERMS]


def _build_references(
    reader: GitReader,
    entries: list[dict[str, Any]],
    allowed_paths: list[str],
    components: set[str],
    patterns: set[str],
    limitations: list[str],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    reasons: dict[str, set[str]] = {}
    source_hashes: dict[str, str] = {}
    for entry in entries:
        reasons.setdefault(entry["path"], set()).add("changed-path")

    terms = _reference_terms(entries)
    all_terms = sorted(
        {
            candidate
            for entry in entries
            for candidate in (
                PurePosixPath(entry["path"]).name,
                PurePosixPath(entry["path"]).stem,
            )
            if len(candidate) >= 3
        }
    )
    if len(all_terms) > len(terms):
        limitations.append(
            f"Reference search terms were capped at {MAX_REFERENCE_TERMS}."
        )

    tracked = reader.run(["ls-files", "-z"]).split(b"\0")
    total_bytes = 0
    oversized = 0
    symlinks = 0
    budget_exhausted = False
    for item in tracked:
        if not item:
            continue
        path = item.decode("utf-8", errors="replace")
        if _category(path) is None:
            continue
        if not _path_allowed(path, allowed_paths):
            continue
        if _is_sensitive(path, components, patterns):
            continue
        absolute = reader.repo / path
        if absolute.is_symlink():
            symlinks += 1
            continue
        if not absolute.is_file():
            continue
        size = absolute.stat().st_size
        if size > MAX_REFERENCE_FILE_BYTES:
            oversized += 1
            continue
        if total_bytes + size > MAX_REFERENCE_TOTAL_BYTES:
            budget_exhausted = True
            break
        data = absolute.read_bytes()
        source_hashes[path] = _sha256(data)
        total_bytes += len(data)
        for term in terms:
            if term.encode("utf-8") in data:
                reasons.setdefault(path, set()).add(f"mentions:{term}")

    if oversized:
        limitations.append(
            f"{oversized} reference candidate file(s) exceeded "
            f"{MAX_REFERENCE_FILE_BYTES} bytes and were skipped."
        )
    if symlinks:
        limitations.append(
            f"{symlinks} tracked symlink reference candidate(s) were skipped."
        )
    if budget_exhausted:
        limitations.append(
            f"Reference scanning stopped at the {MAX_REFERENCE_TOTAL_BYTES}-byte budget."
        )

    result: dict[str, list[dict[str, Any]]] = {
        "tests": [],
        "workflows": [],
        "contracts": [],
        "docs": [],
    }
    capped: set[str] = set()
    for path in sorted(reasons):
        category = _category(path)
        if category is None:
            continue
        records = result[category]
        if len(records) >= MAX_REFERENCES_PER_CATEGORY:
            capped.add(category)
            continue
        records.append({"path": path, "reasons": sorted(reasons[path])})
    for category in sorted(capped):
        limitations.append(
            f"{category} references exceeded the cap of {MAX_REFERENCES_PER_CATEGORY}."
        )
    return result, source_hashes


def _artifact_record(path: Path, root: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha256(data),
        "bytes": len(data),
    }


def _hash_manifest(root: Path) -> bytes:
    lines = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative == "hashes.sha256":
            continue
        lines.append(f"{_sha256(path.read_bytes())}  {relative}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def build(job_path: Path, output_raw: str) -> tuple[Path, dict[str, Any]]:
    started_at = _utc_now()
    job = _load_job(job_path)
    repo = _resolve_repo(job["repo"])
    temporary, output = _prepare_output(output_raw, job["job_id"])
    published = False
    try:
        reader = GitReader(repo)
        limitations: list[str] = []
        components, patterns = _load_sensitive_rules()

        redacted_task, task_redactions = _redact(job["task"])
        if task_redactions:
            job["task"] = redacted_task
            limitations.append(
                f"Job task contained {task_redactions} secret-like value(s) and was redacted."
            )

        state_before, visible_entries, counters = _snapshot(
            reader,
            job["allowed_paths"],
            components,
            patterns,
        )
        status = "complete"
        if state_before["branch"] != job["expected_branch"]:
            status = "rejected"
            limitations.append(
                "Expected branch does not match the observed branch; no patch or references were built."
            )
        if state_before["head"] != job["expected_head"]:
            status = "rejected"
            limitations.append(
                "Expected head does not match the observed head; no patch or references were built."
            )
        if counters["sensitive_omitted"]:
            status = "partial" if status == "complete" else status
            limitations.append(
                f"{counters['sensitive_omitted']} sensitive-path change(s) were omitted."
            )
        if counters["outside_allowed_omitted"]:
            status = "partial" if status == "complete" else status
            limitations.append(
                f"{counters['outside_allowed_omitted']} change(s) outside allowed_paths were omitted."
            )

        if counters["change_limit_omitted"]:
            status = "partial" if status == "complete" else status
            limitations.append(
                f"{counters['change_limit_omitted']} change(s) exceeded the visible change budget and were omitted."
            )
        _write_json(temporary / "job.json", job)
        patch = b""
        patch_source_sha256 = _sha256(b"")
        patch_paths: list[str] = []
        references = {"tests": [], "workflows": [], "contracts": [], "docs": []}
        reference_source_hashes: dict[str, str] = {}
        untracked = {
            "schema_version": SCHEMA_VERSION,
            "captured_bytes_before_redaction": 0,
            "records": [],
        }
        if status != "rejected":
            patch, patch_source_sha256, patch_paths = _build_patch(
                reader,
                visible_entries,
                job["max_patch_bytes"],
                limitations,
            )
            references, reference_source_hashes = _build_references(
                reader,
                visible_entries,
                job["allowed_paths"],
                components,
                patterns,
                limitations,
            )
            untracked = _capture_untracked(
                repo, visible_entries, temporary, limitations
            )
            if limitations and status == "complete":
                status = "partial"

        state_after, after_entries, after_counters = _snapshot(
            reader,
            job["allowed_paths"],
            components,
            patterns,
        )
        status_stable = (
            state_before == state_after
            and visible_entries == after_entries
            and counters == after_counters
        )
        patch_source_stable = True
        untracked_sources_stable = True
        reference_sources_stable = True
        if status != "rejected":
            patch_source_stable = (
                _sha256(_read_patch_source(reader, patch_paths)) == patch_source_sha256
            )
            untracked_sources_stable = _verify_untracked_sources(repo, untracked)
            reference_sources_stable = _verify_reference_sources(
                repo,
                reference_source_hashes,
            )

        stable = (
            status_stable
            and patch_source_stable
            and untracked_sources_stable
            and reference_sources_stable
        )
        if not status_stable:
            limitations.append("Git identity or status changed during collection.")
        if not patch_source_stable:
            limitations.append("Tracked patch source changed during collection.")
        if not untracked_sources_stable:
            limitations.append(
                "At least one untracked source changed during collection."
            )
        if not reference_sources_stable:
            limitations.append(
                "At least one scanned reference source changed during collection."
            )
        if not stable and status != "rejected":
            status = "partial"
            limitations.append(
                "Artifacts do not represent one fully stable repository snapshot."
            )

        repo_state = {
            **state_before,
            "status_stable": status_stable,
            "patch_source_stable": patch_source_stable,
            "untracked_sources_stable": untracked_sources_stable,
            "reference_sources_stable": reference_sources_stable,
            "stable_during_collection": stable,
            "state_after": state_after,
        }
        _write_json(temporary / "repo-state.json", repo_state)
        _write_json(
            temporary / "changed-paths.json",
            {
                "schema_version": SCHEMA_VERSION,
                "entries": visible_entries,
                "sensitive_change_count_omitted": counters["sensitive_omitted"],
                "outside_allowed_change_count_omitted": counters[
                    "outside_allowed_omitted"
                ],
                "change_limit_count_omitted": counters["change_limit_omitted"],
            },
        )
        _write_bytes(temporary / "diff.patch", patch)
        _write_json(temporary / "untracked-files.json", untracked)
        references_dir = temporary / "references"
        references_dir.mkdir(mode=0o700)
        for category in ("tests", "workflows", "contracts", "docs"):
            _write_json(
                references_dir / f"{category}.json",
                {
                    "schema_version": SCHEMA_VERSION,
                    "category": category,
                    "complete": False,
                    "records": references[category],
                },
            )

        limitations = sorted(set(limitations))
        limitation_lines = (
            ["# Local Evidence Limitations", ""]
            + (
                [f"- {item}" for item in limitations]
                if limitations
                else ["- None detected by the builder."]
            )
            + [
                "",
                "Reference lists are deterministic candidates, not a proof of complete impact coverage.",
            ]
        )
        _write_bytes(
            temporary / "limitations.md",
            ("\n".join(limitation_lines) + "\n").encode("utf-8"),
        )
        _write_json(
            temporary / "provenance.json",
            {
                "schema_version": SCHEMA_VERSION,
                "builder_version": BUILDER_VERSION,
                "generated_at": _utc_now(),
                "python_version": platform.python_version(),
                "platform": platform.platform(),
                "repo_root_policy": os.environ.get(
                    "GRABOWSKI_REPO_ROOT", str(Path.home() / "repos")
                ),
                "workspace_root_policy": os.environ.get(
                    "GRABOWSKI_WORKSPACE_ROOT",
                    str(Path.home() / "grabowski-workspace" / "jobs"),
                ),
                "patch_source_sha256": patch_source_sha256,
                "patch_paths": patch_paths,
                "reference_source_sha256s": reference_source_hashes,
                "commands": reader.commands,
            },
        )

        artifact_paths = sorted(
            path
            for path in temporary.rglob("*")
            if path.is_file() and path.name not in {"result.json", "hashes.sha256"}
        )
        result = {
            "schema_version": SCHEMA_VERSION,
            "job_id": job["job_id"],
            "status": status,
            "repo": str(repo),
            "head": state_before["head"],
            "branch": state_before["branch"],
            "artifacts": [_artifact_record(path, temporary) for path in artifact_paths],
            "limitations": limitations,
            "started_at": started_at,
            "finished_at": _utc_now(),
        }
        _write_json(temporary / "result.json", result)
        _write_bytes(temporary / "hashes.sha256", _hash_manifest(temporary))
        os.replace(temporary, output)
        published = True
        return output, result
    finally:
        if not published and temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a bounded, read-only local evidence bundle for one Git repo."
    )
    parser.add_argument(
        "--job", required=True, help="Path to local-evidence-job.v1 JSON"
    )
    parser.add_argument("--output", required=True, help="New bundle directory")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        output, result = build(Path(args.job).expanduser(), args.output)
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        print(f"local-evidence: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "output": str(output),
                "job_id": result["job_id"],
                "status": result["status"],
                "head": result["head"],
                "branch": result["branch"],
            },
            sort_keys=True,
        )
    )
    return 2 if result["status"] == "rejected" else 0


if __name__ == "__main__":
    raise SystemExit(main())
