from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import time
from typing import Any

import grabowski_agent_workspace as workspace
import grabowski_operator_core as operator
import grabowski_tasks as tasks

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING

COMPETITION_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_AGENT_COMPETITION_ROOT",
        str(operator.STATE_DIR / "agent-competitions"),
    )
).expanduser()
RUNNER = Path(__file__).resolve().parent.parent / "tools" / "external_programming_candidate.py"
PROVIDERS = {"claude", "agy"}
MODES = {"competitor", "contrast"}
TASK_KINDS = {"code", "docs", "analysis", "operations"}
NOVELTY = {"low", "medium", "high"}
RISK_FLAGS = {
    "security", "runtime", "deployment", "schema", "concurrency", "data_migration",
    "privilege", "external_api", "cross_repo", "destructive", "user_data",
}
DEFAULT_FORBIDDEN_COMPONENTS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", "build", "dist", "target",
})
SENSITIVE_EXACT_COMPONENTS = frozenset({
    "secret", "secrets", "credential", "credentials", "private_key", "cookies",
    "login data", "web data", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
})
SENSITIVE_NAME_TOKENS = frozenset({"secret", "secrets", "token", "tokens", "credential", "credentials"})
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx")
SOURCE_CODE_SUFFIXES = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts", ".go",
    ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift",
    ".scala", ".sh", ".bash", ".zsh", ".fish", ".sql", ".css", ".scss", ".html",
})
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
TEMP_STATE_RE = re.compile(r"^\.(?P<target>[A-Za-z0-9._-]{1,100})\.(?P<pid>[0-9]+)\.(?P<nonce>[0-9a-f]{16})\.tmp$")
MAX_CONTEXT_BYTES = 500_000
MAX_CONTEXT_FILE_BYTES = 120_000
MAX_RECEIPT_BYTES = 2_000_000
MAX_RUNNER_BYTES = 2_000_000
REQUEST_LOCK_TIMEOUT_SECONDS = 10.0
REQUEST_LOCK_POLL_SECONDS = 0.05
START_RECONCILE_WINDOW_SECONDS = 300
START_RECONCILE_PAGE_LIMIT = 100
START_RECONCILE_MAX_PAGES = 5
COMPETITION_TEMP_STALE_SECONDS = 300
COMPETITION_TEMP_SWEEP_LIMIT = 64


class AgentCompetitionError(ValueError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _strict_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise AgentCompetitionError(f"{label} must be boolean")
    return value


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_stale_competition_temps(
    directory: Path,
    *,
    now_unix: int | None = None,
) -> dict[str, int]:
    current = int(time.time()) if now_unix is None else now_unix
    inspected = 0
    removed = 0
    errors = 0
    try:
        metadata = directory.lstat()
    except OSError:
        return {"inspected": 0, "removed": 0, "errors": 1}
    if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
        return {"inspected": 0, "removed": 0, "errors": 1}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(directory, flags)
    except OSError:
        return {"inspected": 0, "removed": 0, "errors": 1}
    changed = False
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if inspected >= COMPETITION_TEMP_SWEEP_LIMIT:
                    break
                match = TEMP_STATE_RE.fullmatch(entry.name)
                if match is None:
                    continue
                inspected += 1
                try:
                    temp_status = entry.stat(follow_symlinks=False)
                    if (
                        not entry.is_file(follow_symlinks=False)
                        or temp_status.st_uid != os.getuid()
                        or stat.S_IMODE(temp_status.st_mode) != 0o600
                        or current - int(temp_status.st_mtime) < COMPETITION_TEMP_STALE_SECONDS
                    ):
                        continue
                    target_name = match.group("target")
                    try:
                        target_status = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        target_status = None
                    if target_status is not None and not stat.S_ISREG(target_status.st_mode):
                        continue
                    os.unlink(entry.name, dir_fd=directory_fd)
                    removed += 1
                    changed = True
                except OSError:
                    errors += 1
        if changed:
            os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return {"inspected": inspected, "removed": removed, "errors": errors}


def _budget_contract(
    provider: str,
    max_budget_usd: float,
    *,
    hard_limit_required: bool,
) -> dict[str, Any]:
    hard_limit = provider == "claude"
    if hard_limit_required and not hard_limit:
        raise AgentCompetitionError(
            f"provider {provider} cannot enforce a hard USD budget; choose Claude or disable hard budget enforcement"
        )
    return {
        "requested_max_usd": float(max_budget_usd),
        "enforcement": "provider_cli_hard_limit" if hard_limit else "not_supported_by_provider",
        "hard_limit": hard_limit,
        "hard_limit_required": hard_limit_required,
        "timeout_is_not_budget": not hard_limit,
    }


def _validate_budget_contract(value: Any, *, provider: str) -> dict[str, Any]:
    required = {
        "requested_max_usd", "enforcement", "hard_limit",
        "hard_limit_required", "timeout_is_not_budget",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise AgentCompetitionError("candidate budget contract shape is invalid")
    requested = value["requested_max_usd"]
    if (
        isinstance(requested, bool)
        or not isinstance(requested, (int, float))
        or not math.isfinite(float(requested))
        or not 0 < float(requested) <= 10
    ):
        raise AgentCompetitionError("candidate budget contract amount is invalid")
    expected_hard = provider == "claude"
    expected_enforcement = "provider_cli_hard_limit" if expected_hard else "not_supported_by_provider"
    if (
        value["enforcement"] != expected_enforcement
        or value["hard_limit"] is not expected_hard
        or type(value["hard_limit_required"]) is not bool
        or value["timeout_is_not_budget"] is not (not expected_hard)
        or (value["hard_limit_required"] and not expected_hard)
    ):
        raise AgentCompetitionError("candidate budget contract semantics are invalid")
    return value


def _competition_id(provider: str, mode: str, task_sha256: str, request_id: str) -> str:
    request_digest = _sha256_bytes(request_id.encode("utf-8"))[:10]
    return f"gac-{provider}-{mode}-{task_sha256[:10]}-{request_digest}"


def _competition_root() -> Path:
    root = COMPETITION_ROOT.expanduser()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
        raise AgentCompetitionError("agent competition root must be a private non-symlink directory")
    return root.resolve(strict=True)


def _competition_dir(identifier: str) -> Path:
    clean = workspace._required_string(identifier, "competition_id", max_length=100)
    if re.fullmatch(r"gac-(claude|agy)-(competitor|contrast)-[0-9a-f]{10}-[0-9a-f]{10}", clean) is None:
        raise AgentCompetitionError("competition_id has an invalid format")
    return _competition_root() / clean


@contextmanager
def _competition_request_lock(identifier: str):
    clean = workspace._required_string(identifier, "competition_id", max_length=100)
    path = _competition_root() / f".{clean}.lock"
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        path.is_symlink()
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_nlink != 1
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise AgentCompetitionError("competition request lock is unsafe")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise AgentCompetitionError("competition request lock descriptor is unsafe")
        deadline = time.monotonic() + REQUEST_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise AgentCompetitionError("competition request lock timed out") from exc
                time.sleep(REQUEST_LOCK_POLL_SECONDS)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _atomic_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    parent_metadata = path.parent.lstat()
    if path.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_mode & 0o077:
        raise AgentCompetitionError("state parent must be a private non-symlink directory")
    _cleanup_stale_competition_temps(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    published = False
    temporary_metadata: os.stat_result | None = None
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_metadata = temporary.lstat()
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise AgentCompetitionError(f"state file already exists: {path.name}") from exc
        published = True
        _fsync_directory(path.parent)
        try:
            os.unlink(temporary)
            _fsync_directory(path.parent)
        except OSError:
            published_metadata = path.lstat()
            if (
                temporary_metadata.st_dev == published_metadata.st_dev
                and temporary_metadata.st_ino == published_metadata.st_ino
            ):
                os.unlink(path)
                published = False
                _fsync_directory(path.parent)
            raise
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_nlink != 1
            or metadata.st_dev != temporary_metadata.st_dev
            or metadata.st_ino != temporary_metadata.st_ino
        ):
            try:
                current = path.lstat()
                if current.st_dev == temporary_metadata.st_dev and current.st_ino == temporary_metadata.st_ino:
                    os.unlink(path)
                    published = False
                    _fsync_directory(path.parent)
            except FileNotFoundError:
                published = False
            raise AgentCompetitionError("published state file failed inode integrity validation")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
            _fsync_directory(path.parent)
        except FileNotFoundError:
            pass
        if published:
            try:
                metadata = path.lstat()
            except FileNotFoundError as exc:
                raise AgentCompetitionError("published state file disappeared") from exc
            if metadata.st_nlink != 1:
                if (
                    temporary_metadata is not None
                    and metadata.st_dev == temporary_metadata.st_dev
                    and metadata.st_ino == temporary_metadata.st_ino
                ):
                    os.unlink(path)
                    _fsync_directory(path.parent)
                raise AgentCompetitionError("published state file did not retain single-link integrity")


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _atomic_bytes(path, data)


def _load_regular_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    required_mode: int | None,
) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError as exc:
        raise AgentCompetitionError(f"{label} does not exist") from exc
    except OSError as exc:
        raise AgentCompetitionError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (required_mode is not None and stat.S_IMODE(before.st_mode) != required_mode)
            or before.st_size > max_bytes
        ):
            raise AgentCompetitionError(f"{label} must be one bounded regular file")
        chunks = bytearray()
        while len(chunks) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > max_bytes:
            raise AgentCompetitionError(f"{label} exceeds byte limit")
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or after.st_size != len(chunks)
            or after.st_nlink != 1
        ):
            raise AgentCompetitionError(f"{label} changed while being read")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def _load_private_json(path: Path, *, label: str, max_bytes: int = MAX_RECEIPT_BYTES) -> dict[str, Any]:
    raw = _load_regular_bytes(path, label=label, max_bytes=max_bytes, required_mode=0o600)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentCompetitionError(f"cannot parse {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise AgentCompetitionError(f"{label} is not a JSON object")
    return value


def _validate_competition_directory(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise AgentCompetitionError("competition directory does not exist") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AgentCompetitionError("competition directory must be private and symlink-free")
    return path.resolve(strict=True)


def _git_environment() -> dict[str, str]:
    allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    environment.setdefault("LANG", "C.UTF-8")
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return environment


def _git(repo: Path, args: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "git",
            "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false",
            "-c", "diff.external=",
            "-c", "diff.trustExitCode=false",
            "-c", "protocol.file.allow=never",
            *args,
        ],
        cwd=repo,
        capture_output=True,
        check=False,
        timeout=timeout,
        env=_git_environment(),
    )


def _commit_blob(repo: Path, head: str, relative: str) -> bytes:
    listing = _git(repo, ["ls-tree", "-z", head, "--", relative])
    if listing.returncode != 0:
        raise AgentCompetitionError(f"cannot resolve context path at expected_head: {relative}")
    records = [record for record in listing.stdout.split(b"\x00") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise AgentCompetitionError(f"context path is not one tracked blob at expected_head: {relative}")
    metadata, raw_path = records[0].split(b"\t", 1)
    fields = metadata.split()
    if len(fields) != 3 or fields[1] != b"blob" or re.fullmatch(rb"[0-9a-f]{40,64}", fields[2]) is None:
        raise AgentCompetitionError(f"context path metadata is invalid at expected_head: {relative}")
    try:
        observed_path = raw_path.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentCompetitionError(f"context path is not UTF-8 at expected_head: {relative}") from exc
    if observed_path != relative:
        raise AgentCompetitionError(f"context path identity mismatch at expected_head: {relative}")
    blob = _git(repo, ["cat-file", "blob", fields[2].decode("ascii")])
    if blob.returncode != 0:
        raise AgentCompetitionError(f"cannot read context blob at expected_head: {relative}")
    return blob.stdout


def _normalize_relative(value: Any, *, label: str) -> str:
    clean = workspace._required_string(value, label, max_length=500)
    path = PurePosixPath(clean)
    if path.is_absolute() or clean.startswith("./") or any(part in {"", ".", ".."} for part in path.parts):
        raise AgentCompetitionError(f"{label} must be a normalized relative path")
    return path.as_posix()


def _path_in_scope(path: str, roots: list[str]) -> bool:
    item = PurePosixPath(path)
    return any(item == PurePosixPath(root) or PurePosixPath(root) in item.parents for root in roots)


def _path_has_default_forbidden_component(path: str) -> bool:
    return any(part.casefold() in DEFAULT_FORBIDDEN_COMPONENTS for part in PurePosixPath(path).parts)


def _path_is_sensitive(path: str) -> bool:
    for raw_part in PurePosixPath(path).parts:
        part = raw_part.casefold()
        if part == ".env" or part.startswith(".env."):
            return True
        if part in SENSITIVE_EXACT_COMPONENTS or part.endswith(SENSITIVE_SUFFIXES):
            return True
        suffix = PurePosixPath(part).suffix
        stem = part.rsplit(".", 1)[0]
        tokens = {token for token in re.split(r"[^a-z0-9]+", stem) if token}
        if suffix not in SOURCE_CODE_SUFFIXES and tokens & SENSITIVE_NAME_TOKENS:
            return True
    return False


def _repository(repository: str, expected_head: str) -> tuple[Path, str]:
    repo = Path(workspace._required_string(repository, "repository", max_length=4096)).expanduser().resolve(strict=True)
    top = _git(repo, ["rev-parse", "--show-toplevel"])
    if top.returncode != 0 or Path(top.stdout.decode().strip()).resolve(strict=True) != repo:
        raise AgentCompetitionError("repository must be a Git worktree root")
    head = workspace._required_string(expected_head, "expected_head", max_length=40).lower()
    if SHA40_RE.fullmatch(head) is None:
        raise AgentCompetitionError("expected_head must be a full lowercase Git SHA")
    observed = _git(repo, ["rev-parse", "HEAD^{commit}"])
    if observed.returncode != 0 or observed.stdout.decode().strip().lower() != head:
        raise AgentCompetitionError("repository HEAD does not match expected_head")
    status = _git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=normal"])
    if status.returncode != 0 or status.stdout:
        raise AgentCompetitionError("repository must be clean before external candidate generation")
    return repo, head


def _context(
    repo: Path,
    head: str,
    context_paths: list[str],
    allowed: list[str],
    forbidden: list[str],
) -> list[dict[str, Any]]:
    if not isinstance(context_paths, list) or not context_paths or len(context_paths) > 40:
        raise AgentCompetitionError("context_paths must contain between 1 and 40 entries")
    result: list[dict[str, Any]] = []
    total = 0
    seen: set[str] = set()
    for index, raw in enumerate(context_paths):
        relative = _normalize_relative(raw, label=f"context_paths[{index}]")
        if relative in seen:
            raise AgentCompetitionError("context_paths contains duplicates")
        seen.add(relative)
        if not _path_in_scope(relative, allowed) or _path_in_scope(relative, forbidden):
            raise AgentCompetitionError(f"context path is outside declared scope: {relative}")
        if _path_has_default_forbidden_component(relative):
            raise AgentCompetitionError(f"default-forbidden context path is not exportable: {relative}")
        if _path_is_sensitive(relative):
            raise AgentCompetitionError(f"sensitive-looking context path is not exportable: {relative}")
        raw_bytes = _commit_blob(repo, head, relative)
        if len(raw_bytes) > MAX_CONTEXT_FILE_BYTES:
            raise AgentCompetitionError(f"context file exceeds per-file byte limit: {relative}")
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AgentCompetitionError(f"context file is not UTF-8 text: {relative}") from exc
        redact = getattr(operator, "_redact", None)
        if callable(redact) and redact(text) != text:
            raise AgentCompetitionError(f"context file contains secret-like content: {relative}")
        total += len(raw_bytes)
        if total > MAX_CONTEXT_BYTES:
            raise AgentCompetitionError("combined context exceeds byte limit")
        result.append({"path": relative, "sha256": _sha256_bytes(raw_bytes), "text": text})
    return result


def _scope(values: list[str] | None, *, label: str, nonempty: bool) -> list[str]:
    if not isinstance(values, list) or (nonempty and not values) or len(values) > 50:
        raise AgentCompetitionError(f"{label} has an invalid size")
    normalized = [_normalize_relative(item, label=f"{label}[{index}]") for index, item in enumerate(values)]
    if len(set(normalized)) != len(normalized):
        raise AgentCompetitionError(f"{label} contains duplicates")
    return normalized


def _validated_start_intent(identifier: str) -> dict[str, Any]:
    intent = _load_private_json(
        _competition_dir(identifier) / "start-intent.json",
        label="competition start intent",
    )
    common = {
        "schema_version", "kind", "competition_id", "request_id", "request_fingerprint",
        "packet_sha256", "command_sha256", "created_at", "state", "start_intent_sha256",
    }
    version = intent.get("schema_version")
    required = common if version == 1 else common | {"created_at_unix"}
    if version not in {1, 2} or set(intent) != required:
        raise AgentCompetitionError("competition start intent shape is invalid")
    observed_hash = intent["start_intent_sha256"]
    unsigned = {key: value for key, value in intent.items() if key != "start_intent_sha256"}
    if (
        not isinstance(observed_hash, str)
        or SHA256_RE.fullmatch(observed_hash) is None
        or observed_hash != _sha256_json(unsigned)
        or intent["kind"] != "external_programming_competition_start_intent"
        or intent["competition_id"] != identifier
        or not isinstance(intent["request_id"], str)
        or REQUEST_ID_RE.fullmatch(intent["request_id"]) is None
        or intent["state"] != "prepared"
        or not isinstance(intent["created_at"], str)
        or not intent["created_at"].strip()
    ):
        raise AgentCompetitionError("competition start intent contract is invalid")
    if version == 2 and (
        isinstance(intent["created_at_unix"], bool)
        or not isinstance(intent["created_at_unix"], int)
        or intent["created_at_unix"] <= 0
    ):
        raise AgentCompetitionError("competition start intent created_at_unix is invalid")
    for field in ("request_fingerprint", "packet_sha256", "command_sha256"):
        value = intent[field]
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise AgentCompetitionError(f"competition start intent {field} is invalid")
    return intent


def _write_start_outcome(
    identifier: str,
    intent: dict[str, Any],
    *,
    state: str,
    task_id: str | None = None,
    task_unit: str | None = None,
    cancel_state: str = "not_attempted",
) -> dict[str, Any]:
    if state not in {"task_start_outcome_unknown", "manifest_publish_failed"}:
        raise AgentCompetitionError("competition start outcome state is invalid")
    if cancel_state not in {"not_attempted", "confirmed", "unconfirmed"}:
        raise AgentCompetitionError("competition start outcome cancel_state is invalid")
    if state == "manifest_publish_failed" and (not isinstance(task_id, str) or not task_id):
        raise AgentCompetitionError("manifest publish failure requires a task_id")
    if state == "task_start_outcome_unknown" and (task_id is not None or task_unit is not None):
        raise AgentCompetitionError("unknown task start outcome may not claim task identity")
    outcome = {
        "schema_version": 1,
        "kind": "external_programming_competition_start_outcome",
        "competition_id": identifier,
        "request_id": intent["request_id"],
        "request_fingerprint": intent["request_fingerprint"],
        "packet_sha256": intent["packet_sha256"],
        "start_intent_sha256": intent["start_intent_sha256"],
        "state": state,
        "task_id": task_id,
        "task_unit": task_unit,
        "cancel_state": cancel_state,
        "recorded_at": workspace._utc(),
    }
    outcome["start_outcome_sha256"] = _sha256_json(outcome)
    _atomic_json(_competition_dir(identifier) / "start-outcome.json", outcome)
    return outcome


def _validated_start_outcome(identifier: str, intent: dict[str, Any]) -> dict[str, Any] | None:
    path = _competition_dir(identifier) / "start-outcome.json"
    if not path.exists() and not path.is_symlink():
        return None
    outcome = _load_private_json(path, label="competition start outcome")
    required = {
        "schema_version", "kind", "competition_id", "request_id", "request_fingerprint",
        "packet_sha256", "start_intent_sha256", "state", "task_id", "task_unit",
        "cancel_state", "recorded_at", "start_outcome_sha256",
    }
    if set(outcome) != required:
        raise AgentCompetitionError("competition start outcome shape is invalid")
    observed_hash = outcome["start_outcome_sha256"]
    unsigned = {key: value for key, value in outcome.items() if key != "start_outcome_sha256"}
    if (
        not isinstance(observed_hash, str)
        or SHA256_RE.fullmatch(observed_hash) is None
        or observed_hash != _sha256_json(unsigned)
        or outcome["schema_version"] != 1
        or outcome["kind"] != "external_programming_competition_start_outcome"
        or outcome["competition_id"] != identifier
        or outcome["request_id"] != intent["request_id"]
        or outcome["request_fingerprint"] != intent["request_fingerprint"]
        or outcome["packet_sha256"] != intent["packet_sha256"]
        or outcome["start_intent_sha256"] != intent["start_intent_sha256"]
        or outcome["state"] not in {"task_start_outcome_unknown", "manifest_publish_failed"}
        or outcome["cancel_state"] not in {"not_attempted", "confirmed", "unconfirmed"}
        or not isinstance(outcome["recorded_at"], str)
        or not outcome["recorded_at"].strip()
    ):
        raise AgentCompetitionError("competition start outcome contract is invalid")
    if outcome["state"] == "task_start_outcome_unknown":
        if outcome["task_id"] is not None or outcome["task_unit"] is not None or outcome["cancel_state"] != "not_attempted":
            raise AgentCompetitionError("unknown task start outcome overclaims task identity")
    elif not isinstance(outcome["task_id"], str) or not outcome["task_id"]:
        raise AgentCompetitionError("manifest publish failure task identity is invalid")
    return outcome


def _validated_packet(identifier: str) -> dict[str, Any]:
    packet = _load_private_json(_competition_dir(identifier) / "packet.json", label="candidate packet")
    common = {
        "schema_version", "kind", "competition_id", "request_id", "request_fingerprint",
        "provider", "mode", "repository", "expected_head", "task", "task_sha256",
        "runner_sha256", "allowed_paths", "forbidden_paths", "context", "primary_summary",
        "packet_nonce", "created_at", "packet_sha256",
    }
    version = packet.get("schema_version")
    required = common if version == 1 else common | {"budget_contract"}
    if version not in {1, 2} or set(packet) != required:
        raise AgentCompetitionError("candidate packet shape is invalid")
    packet_hash = packet["packet_sha256"]
    unsigned_packet = {key: value for key, value in packet.items() if key != "packet_sha256"}
    if (
        not isinstance(packet_hash, str)
        or SHA256_RE.fullmatch(packet_hash) is None
        or packet_hash != _sha256_json(unsigned_packet)
        or packet["kind"] != "external_programming_candidate_packet"
        or packet["competition_id"] != identifier
        or packet["provider"] not in PROVIDERS
        or packet["mode"] not in MODES
        or not isinstance(packet["request_id"], str)
        or REQUEST_ID_RE.fullmatch(packet["request_id"]) is None
        or not isinstance(packet["request_fingerprint"], str)
        or SHA256_RE.fullmatch(packet["request_fingerprint"]) is None
        or not isinstance(packet["expected_head"], str)
        or SHA40_RE.fullmatch(packet["expected_head"]) is None
        or not isinstance(packet["runner_sha256"], str)
        or SHA256_RE.fullmatch(packet["runner_sha256"]) is None
    ):
        raise AgentCompetitionError("candidate packet contract is invalid")
    task = packet["task"]
    if (
        not isinstance(task, str)
        or not task.strip()
        or len(task.encode("utf-8")) > 16_000
        or not isinstance(packet["task_sha256"], str)
        or SHA256_RE.fullmatch(packet["task_sha256"]) is None
        or packet["task_sha256"] != _sha256_bytes(task.encode("utf-8"))
    ):
        raise AgentCompetitionError("candidate packet task binding is invalid")
    repository = packet["repository"]
    if (
        not isinstance(repository, str)
        or "\x00" in repository
        or not Path(repository).is_absolute()
    ):
        raise AgentCompetitionError("candidate packet repository is invalid")
    allowed = _scope(packet["allowed_paths"], label="candidate packet allowed_paths", nonempty=True)
    forbidden = _scope(packet["forbidden_paths"], label="candidate packet forbidden_paths", nonempty=False)
    rejected_allowed = [
        path for path in allowed
        if _path_has_default_forbidden_component(path) or _path_is_sensitive(path)
    ]
    if rejected_allowed:
        raise AgentCompetitionError(f"candidate packet allowed paths are non-exportable: {rejected_allowed}")
    context = packet["context"]
    if not isinstance(context, list) or not 1 <= len(context) <= 40:
        raise AgentCompetitionError("candidate packet context size is invalid")
    total_context = 0
    seen: set[str] = set()
    for index, item in enumerate(context):
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "text"}:
            raise AgentCompetitionError(f"candidate packet context item is invalid: {index}")
        path = _normalize_relative(item["path"], label=f"candidate packet context[{index}].path")
        if path in seen:
            raise AgentCompetitionError("candidate packet context paths contain duplicates")
        seen.add(path)
        if not _path_in_scope(path, allowed) or _path_in_scope(path, forbidden):
            raise AgentCompetitionError(f"candidate packet context path is outside scope: {path}")
        if _path_has_default_forbidden_component(path) or _path_is_sensitive(path):
            raise AgentCompetitionError(f"candidate packet context path is non-exportable: {path}")
        text = item["text"]
        digest = item["sha256"]
        if (
            not isinstance(text, str)
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
        ):
            raise AgentCompetitionError(f"candidate packet context content is invalid: {path}")
        raw = text.encode("utf-8")
        total_context += len(raw)
        if (
            len(raw) > MAX_CONTEXT_FILE_BYTES
            or total_context > MAX_CONTEXT_BYTES
            or digest != _sha256_bytes(raw)
        ):
            raise AgentCompetitionError("candidate packet context content is too large or hash-mismatched")
    summary = packet["primary_summary"]
    nonce = packet["packet_nonce"]
    if (
        not isinstance(summary, str)
        or "\x00" in summary
        or len(summary.encode("utf-8")) > 32_000
        or not isinstance(nonce, str)
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or not isinstance(packet["created_at"], str)
        or not packet["created_at"].strip()
    ):
        raise AgentCompetitionError("candidate packet auxiliary fields are invalid")
    if version == 2:
        _validate_budget_contract(packet["budget_contract"], provider=packet["provider"])
    return {**packet, "allowed_paths": allowed, "forbidden_paths": forbidden}


def _start_reconciliation(identifier: str, intent: dict[str, Any]) -> dict[str, Any]:
    if intent.get("schema_version") != 2:
        return {"state": "legacy_intent_not_reconcilable", "matches": [], "task": None}
    expected_created = intent["created_at_unix"]
    directory = _competition_dir(identifier)
    expected_resource = f"path:{directory}"
    matches: list[dict[str, Any]] = []
    cursor: str | None = None
    scan_complete = False
    for _page in range(START_RECONCILE_MAX_PAGES):
        try:
            listed = tasks.grabowski_task_list(
                limit=START_RECONCILE_PAGE_LIMIT,
                view="standard",
                cursor=cursor,
            )
        except Exception:
            return {"state": "task_registry_unavailable", "matches": [], "task": None}
        records = listed.get("tasks") if isinstance(listed, dict) else None
        pagination = listed.get("pagination") if isinstance(listed, dict) else None
        if not isinstance(records, list) or not isinstance(pagination, dict):
            return {"state": "task_registry_invalid", "matches": [], "task": None}
        reached_lower_bound = False
        for record in records:
            if not isinstance(record, dict):
                return {"state": "task_registry_invalid", "matches": [], "task": None}
            created = record.get("created_at_unix")
            if isinstance(created, bool) or not isinstance(created, int):
                return {"state": "task_registry_invalid", "matches": [], "task": None}
            if created < expected_created:
                reached_lower_bound = True
                continue
            resources = record.get("resource_keys")
            if (
                record.get("host") == "heim-pc"
                and record.get("resume_policy") == "never"
                and record.get("argv_sha256") == intent["command_sha256"]
                and record.get("cwd") == str(directory)
                and resources == [expected_resource]
                and created <= expected_created + START_RECONCILE_WINDOW_SECONDS
                and isinstance(record.get("task_id"), str)
                and record["task_id"]
            ):
                matches.append(record)
        has_more = pagination.get("has_more")
        next_cursor = pagination.get("next_cursor")
        if type(has_more) is not bool:
            return {"state": "task_registry_invalid", "matches": [], "task": None}
        if reached_lower_bound or not has_more:
            scan_complete = True
            break
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
            return {"state": "task_registry_invalid", "matches": [], "task": None}
        cursor = next_cursor
    if not scan_complete:
        return {
            "state": "scan_limit_exceeded",
            "matches": [item["task_id"] for item in matches],
            "task": None,
        }
    if len(matches) == 1:
        return {"state": "unique_match", "matches": [matches[0]["task_id"]], "task": matches[0]}
    return {
        "state": "no_match" if not matches else "ambiguous_matches",
        "matches": [item["task_id"] for item in matches],
        "task": None,
    }


def _manifest_from_task(
    identifier: str,
    packet: dict[str, Any],
    intent: dict[str, Any],
    task_record: dict[str, Any],
) -> dict[str, Any]:
    task_id = task_record.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        raise AgentCompetitionError("reconciled durable task identity is invalid")
    manifest: dict[str, Any] = {
        "schema_version": 2 if packet["schema_version"] == 2 else 1,
        "kind": "external_programming_competition_manifest",
        "competition_id": identifier,
        "request_id": packet["request_id"],
        "request_fingerprint": packet["request_fingerprint"],
        "provider": packet["provider"],
        "mode": packet["mode"],
        "repository": packet["repository"],
        "expected_head": packet["expected_head"],
        "task_sha256": packet["task_sha256"],
        "packet_sha256": packet["packet_sha256"],
        "runner_sha256": packet["runner_sha256"],
        "start_intent_sha256": intent["start_intent_sha256"],
        "task_id": task_id,
        "task_unit": task_record.get("unit"),
        "created_at": workspace._utc(),
        "authority": "advisory_only",
        "automatic_apply": False,
    }
    if packet["schema_version"] == 2:
        manifest["budget_contract"] = packet["budget_contract"]
    manifest["manifest_sha256"] = _sha256_json(manifest)
    return manifest


def _validated_manifest(identifier: str) -> dict[str, Any]:
    manifest = _load_private_json(_competition_dir(identifier) / "manifest.json", label="competition manifest")
    common = {
        "schema_version", "kind", "competition_id", "request_id", "request_fingerprint",
        "provider", "mode", "repository", "expected_head", "task_sha256", "packet_sha256",
        "runner_sha256", "start_intent_sha256", "task_id", "task_unit", "created_at", "authority",
        "automatic_apply", "manifest_sha256",
    }
    version = manifest.get("schema_version")
    required = common if version == 1 else common | {"budget_contract"}
    if version not in {1, 2} or set(manifest) != required:
        raise AgentCompetitionError("competition manifest shape is invalid")
    observed_hash = manifest["manifest_sha256"]
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if not isinstance(observed_hash, str) or SHA256_RE.fullmatch(observed_hash) is None or observed_hash != _sha256_json(unsigned):
        raise AgentCompetitionError("competition manifest hash is invalid")
    if manifest["kind"] != "external_programming_competition_manifest":
        raise AgentCompetitionError("competition manifest contract is invalid")
    if (
        manifest["competition_id"] != identifier
        or manifest["provider"] not in PROVIDERS
        or manifest["mode"] not in MODES
        or not isinstance(manifest["request_id"], str)
        or REQUEST_ID_RE.fullmatch(manifest["request_id"]) is None
    ):
        raise AgentCompetitionError("competition manifest identity is invalid")
    if manifest["authority"] != "advisory_only" or manifest["automatic_apply"] is not False:
        raise AgentCompetitionError("competition manifest authority is invalid")
    for field in (
        "expected_head", "task_sha256", "packet_sha256", "runner_sha256",
        "request_fingerprint", "start_intent_sha256",
    ):
        pattern = SHA40_RE if field == "expected_head" else SHA256_RE
        value = manifest[field]
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise AgentCompetitionError(f"competition manifest {field} is invalid")
    if version == 2:
        _validate_budget_contract(manifest["budget_contract"], provider=manifest["provider"])
    packet = _validated_packet(identifier)
    bindings = {
        "competition_id": identifier,
        "request_id": manifest["request_id"],
        "request_fingerprint": manifest["request_fingerprint"],
        "provider": manifest["provider"],
        "mode": manifest["mode"],
        "repository": manifest["repository"],
        "expected_head": manifest["expected_head"],
        "task_sha256": manifest["task_sha256"],
        "packet_sha256": manifest["packet_sha256"],
        "runner_sha256": manifest["runner_sha256"],
    }
    for field, expected in bindings.items():
        if packet.get(field) != expected:
            raise AgentCompetitionError(f"candidate packet binding mismatch: {field}")
    if packet["schema_version"] != version:
        raise AgentCompetitionError("candidate packet schema does not match manifest")
    if version == 2 and packet.get("budget_contract") != manifest["budget_contract"]:
        raise AgentCompetitionError("candidate packet budget binding mismatch")
    directory = _validate_competition_directory(_competition_dir(identifier))
    frozen_runner = _load_regular_bytes(
        directory / "runner.py",
        label="frozen candidate runner",
        max_bytes=MAX_RUNNER_BYTES,
        required_mode=0o600,
    )
    if _sha256_bytes(frozen_runner) != manifest["runner_sha256"]:
        raise AgentCompetitionError("frozen candidate runner hash is invalid")
    _validate_competition_directory(directory / "provider-workspace")
    intent = _validated_start_intent(identifier)
    if (
        intent["start_intent_sha256"] != manifest["start_intent_sha256"]
        or intent["request_id"] != manifest["request_id"]
        or intent["request_fingerprint"] != manifest["request_fingerprint"]
        or intent["packet_sha256"] != manifest["packet_sha256"]
    ):
        raise AgentCompetitionError("competition start intent binding is invalid")
    return manifest


def _receipt_patch_paths(patch: str) -> list[str]:
    paths: list[str] = []
    for line in patch.splitlines():
        if not line.startswith("diff --git "):
            continue
        parts = line.split(" ")
        if len(parts) != 4 or not parts[2].startswith("a/") or not parts[3].startswith("b/"):
            raise AgentCompetitionError("candidate receipt patch has an unsupported diff header")
        left = _normalize_relative(parts[2][2:], label="candidate receipt patch path")
        right = _normalize_relative(parts[3][2:], label="candidate receipt patch path")
        if left != right:
            raise AgentCompetitionError("candidate receipt patch may not contain renames or copies")
        paths.append(left)
    if patch and not paths:
        raise AgentCompetitionError("candidate receipt non-empty patch contains no diff headers")
    if "GIT binary patch" in patch or "Binary files " in patch:
        raise AgentCompetitionError("candidate receipt patch may not contain binary data")
    return sorted(set(paths))


def _bounded_string_list(
    value: Any,
    *,
    label: str,
    max_items: int,
    max_length: int,
) -> list[str]:
    if not isinstance(value, list) or len(value) > max_items:
        raise AgentCompetitionError(f"candidate receipt {label} is invalid")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > max_length or "\x00" in item:
            raise AgentCompetitionError(f"candidate receipt {label} is invalid")
        result.append(item)
    return result


def _validate_receipt_candidate(candidate: Any, packet: dict[str, Any]) -> dict[str, Any]:
    required = {
        "approach_id", "approach_summary", "assumptions", "design_invariants", "tradeoffs",
        "risks", "proposed_tests", "changed_paths", "patch", "contrast_observations",
        "confidence", "patch_paths", "patch_sha256", "patch_check", "patch_rejection",
    }
    if not isinstance(candidate, dict) or set(candidate) != required:
        raise AgentCompetitionError("candidate receipt candidate shape is invalid")
    approach_id = candidate["approach_id"]
    approach_summary = candidate["approach_summary"]
    if (
        not isinstance(approach_id, str)
        or not approach_id.strip()
        or len(approach_id) > 120
        or "\x00" in approach_id
        or not isinstance(approach_summary, str)
        or not approach_summary.strip()
        or len(approach_summary) > 4000
        or "\x00" in approach_summary
    ):
        raise AgentCompetitionError("candidate receipt approach fields are invalid")
    _bounded_string_list(candidate["assumptions"], label="assumptions", max_items=20, max_length=1000)
    _bounded_string_list(candidate["design_invariants"], label="design_invariants", max_items=20, max_length=1000)
    _bounded_string_list(candidate["tradeoffs"], label="tradeoffs", max_items=20, max_length=1000)
    _bounded_string_list(candidate["risks"], label="risks", max_items=20, max_length=1000)
    _bounded_string_list(candidate["proposed_tests"], label="proposed_tests", max_items=30, max_length=1000)
    _bounded_string_list(
        candidate["contrast_observations"],
        label="contrast_observations",
        max_items=20,
        max_length=1200,
    )
    if candidate["confidence"] not in {"low", "medium", "high"}:
        raise AgentCompetitionError("candidate receipt confidence is invalid")
    changed_raw = candidate["changed_paths"]
    if not isinstance(changed_raw, list) or len(changed_raw) > 50:
        raise AgentCompetitionError("candidate receipt changed_paths is invalid")
    changed_paths = [
        _normalize_relative(item, label="candidate receipt changed path")
        for item in changed_raw
    ]
    if len(set(changed_paths)) != len(changed_paths):
        raise AgentCompetitionError("candidate receipt changed_paths contains duplicates")
    allowed = packet.get("allowed_paths")
    forbidden = packet.get("forbidden_paths")
    if not isinstance(allowed, list) or not isinstance(forbidden, list):
        raise AgentCompetitionError("candidate packet path scope is invalid")
    for path in changed_paths:
        if not _path_in_scope(path, allowed) or _path_in_scope(path, forbidden):
            raise AgentCompetitionError(f"candidate receipt changed path is outside scope: {path}")
        if _path_has_default_forbidden_component(path) or _path_is_sensitive(path):
            raise AgentCompetitionError(f"candidate receipt changed path is non-exportable: {path}")
    patch = candidate["patch"]
    patch_hash = candidate["patch_sha256"]
    if not isinstance(patch, str) or len(patch.encode("utf-8")) > 300_000:
        raise AgentCompetitionError("candidate receipt patch is invalid")
    if not isinstance(patch_hash, str) or patch_hash != _sha256_bytes(patch.encode("utf-8")):
        raise AgentCompetitionError("candidate receipt patch hash is invalid")
    parsed_patch_paths = _receipt_patch_paths(patch)
    recorded_patch_paths = candidate["patch_paths"]
    if not isinstance(recorded_patch_paths, list):
        raise AgentCompetitionError("candidate receipt patch_paths is invalid")
    normalized_patch_paths = [
        _normalize_relative(item, label="candidate receipt patch path")
        for item in recorded_patch_paths
    ]
    if normalized_patch_paths != parsed_patch_paths:
        raise AgentCompetitionError("candidate receipt patch_paths do not match patch headers")
    if not set(parsed_patch_paths).issubset(set(changed_paths)):
        raise AgentCompetitionError("candidate receipt patch paths are not declared in changed_paths")
    for path in parsed_patch_paths:
        if _path_has_default_forbidden_component(path) or _path_is_sensitive(path):
            raise AgentCompetitionError(f"candidate receipt patch path is non-exportable: {path}")
    patch_check = candidate["patch_check"]
    if (
        not isinstance(patch_check, dict)
        or set(patch_check) != {"attempted", "applies", "returncode", "stderr_sha256", "syntax_accepted"}
        or type(patch_check["attempted"]) is not bool
        or type(patch_check["applies"]) is not bool
        or type(patch_check["syntax_accepted"]) is not bool
        or (
            patch_check["returncode"] is not None
            and (isinstance(patch_check["returncode"], bool) or not isinstance(patch_check["returncode"], int))
        )
        or (
            patch_check["stderr_sha256"] is not None
            and (
                not isinstance(patch_check["stderr_sha256"], str)
                or SHA256_RE.fullmatch(patch_check["stderr_sha256"]) is None
            )
        )
        or patch_check["attempted"] != bool(patch)
        or (not patch and patch_check["applies"])
    ):
        raise AgentCompetitionError("candidate receipt patch_check is invalid")
    rejection = candidate["patch_rejection"]
    if rejection is not None:
        if (
            not isinstance(rejection, dict)
            or set(rejection) != {
                "rejected", "reason", "original_patch_sha256", "original_patch_size_bytes"
            }
            or rejection["rejected"] is not True
            or not isinstance(rejection["reason"], str)
            or not rejection["reason"].strip()
            or len(rejection["reason"]) > 1000
            or not isinstance(rejection["original_patch_sha256"], str)
            or SHA256_RE.fullmatch(rejection["original_patch_sha256"]) is None
            or isinstance(rejection["original_patch_size_bytes"], bool)
            or not isinstance(rejection["original_patch_size_bytes"], int)
            or not 0 <= rejection["original_patch_size_bytes"] <= 300_000
            or patch
            or patch_check["syntax_accepted"] is not False
        ):
            raise AgentCompetitionError("candidate receipt patch_rejection is invalid")
    elif patch_check["syntax_accepted"] is not True:
        raise AgentCompetitionError("candidate receipt patch syntax state is invalid")
    return candidate

def _validate_receipt_snapshot(
    value: Any,
    *,
    label: str,
    expected_head: str,
    expected_context_count: int,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"head", "commit_bound", "context_count", "worktree_clean_required"}
        or value["head"] != expected_head
        or value["commit_bound"] is not True
        or isinstance(value["context_count"], bool)
        or value["context_count"] != expected_context_count
        or value["worktree_clean_required"] is not False
    ):
        raise AgentCompetitionError(f"candidate receipt {label} snapshot is invalid")
    return value


def _validate_receipt_execution(receipt: dict[str, Any], packet: dict[str, Any]) -> None:
    for field in ("prompt_sha256", "command_sha256", "stdout_sha256", "stderr_sha256"):
        value = receipt[field]
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise AgentCompetitionError(f"candidate receipt {field} is invalid")
    version = receipt["provider_version"]
    if not isinstance(version, str) or not version.strip() or len(version) > 300 or "\x00" in version:
        raise AgentCompetitionError("candidate receipt provider_version is invalid")
    command = receipt["command_shape"]
    if (
        not isinstance(command, list)
        or not 1 <= len(command) <= 40
        or any(not isinstance(item, str) or not item or len(item) > 20000 or "\x00" in item for item in command)
        or command[0] != receipt["provider"]
        or receipt["command_sha256"] != _sha256_json(command)
    ):
        raise AgentCompetitionError("candidate receipt command_shape is invalid")
    if receipt["provider"] == "claude":
        if len(command) < 4 or command[1:4] != ["-p", "--output-format", "json"] or "--tools=" not in command:
            raise AgentCompetitionError("candidate receipt Claude command shape is invalid")
    elif command[:4] != ["agy", "--mode", "plan", "--sandbox"]:
        raise AgentCompetitionError("candidate receipt agy command shape is invalid")
    if receipt["provider_cwd_kind"] != "isolated_provider_workspace" or receipt["prompt_in_argv"] is not False:
        raise AgentCompetitionError("candidate receipt provider isolation fields are invalid")
    returncode = receipt["returncode"]
    runtime_seconds = receipt["runtime_seconds"]
    if (
        isinstance(returncode, bool)
        or returncode != 0
        or isinstance(runtime_seconds, bool)
        or not isinstance(runtime_seconds, (int, float))
        or not math.isfinite(float(runtime_seconds))
        or not 0 <= float(runtime_seconds) <= 4000
    ):
        raise AgentCompetitionError("candidate receipt execution outcome is invalid")
    expected_context_count = len(packet.get("context", []))
    before = _validate_receipt_snapshot(
        receipt["before"],
        label="before",
        expected_head=packet["expected_head"],
        expected_context_count=expected_context_count,
    )
    after = _validate_receipt_snapshot(
        receipt["after"],
        label="after",
        expected_head=packet["expected_head"],
        expected_context_count=expected_context_count,
    )
    if before != after:
        raise AgentCompetitionError("candidate receipt snapshots disagree")
    does_not_establish = receipt["does_not_establish"]
    required_nonclaims = {"correctness", "test_pass", "review_pass", "merge_readiness", "preferred_candidate"}
    if (
        not isinstance(does_not_establish, list)
        or len(set(does_not_establish)) != len(does_not_establish)
        or any(not isinstance(item, str) or not item or len(item) > 100 for item in does_not_establish)
        or not required_nonclaims.issubset(set(does_not_establish))
    ):
        raise AgentCompetitionError("candidate receipt nonclaims are invalid")
    budget_contract = None
    if receipt.get("schema_version") == 2:
        budget_contract = _validate_budget_contract(
            receipt.get("budget_contract"),
            provider=receipt["provider"],
        )
        if packet.get("budget_contract") != budget_contract:
            raise AgentCompetitionError("candidate receipt budget binding mismatch")
    total_cost = receipt.get("total_cost_usd")
    if total_cost is not None and (
        isinstance(total_cost, bool)
        or not isinstance(total_cost, (int, float))
        or not math.isfinite(float(total_cost))
        or not 0 <= float(total_cost) <= 100
        or (
            budget_contract is not None
            and budget_contract["hard_limit"]
            and float(total_cost) > float(budget_contract["requested_max_usd"]) + 1e-9
        )
    ):
        raise AgentCompetitionError("candidate receipt total_cost_usd is invalid")


def _receipt(identifier: str, manifest: dict[str, Any] | None = None) -> dict[str, Any] | None:
    path = _competition_dir(identifier) / "receipt.json"
    if not path.exists() and not path.is_symlink():
        return None
    bound_manifest = _validated_manifest(identifier) if manifest is None else manifest
    receipt = _load_private_json(path, label="candidate receipt")
    observed_hash = receipt.get("receipt_sha256")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if not isinstance(observed_hash, str) or SHA256_RE.fullmatch(observed_hash) is None or observed_hash != _sha256_json(unsigned):
        raise AgentCompetitionError("candidate receipt hash is invalid")
    common = {
        "schema_version", "kind", "competition_id", "request_id", "request_fingerprint",
        "provider", "mode", "repository", "expected_head", "task_sha256", "packet_sha256",
        "runner_sha256", "prompt_sha256", "provider_version", "command_shape",
        "provider_cwd_kind", "command_sha256", "prompt_in_argv", "returncode", "runtime_seconds",
        "stdout_sha256", "stderr_sha256", "before", "after", "candidate", "authority",
        "automatic_apply", "automatic_commit", "automatic_merge", "automatic_deploy",
        "does_not_establish", "receipt_sha256",
    }
    version = receipt.get("schema_version")
    required = common if version == 1 else common | {"budget_contract"}
    allowed = required | {"total_cost_usd", "output_wrapper"}
    receipt_fields = set(receipt)
    if version not in {1, 2} or not required <= receipt_fields <= allowed:
        raise AgentCompetitionError("candidate receipt shape is invalid")
    if receipt["kind"] != "external_programming_candidate_receipt":
        raise AgentCompetitionError("candidate receipt contract is invalid")
    if version != bound_manifest["schema_version"]:
        raise AgentCompetitionError("candidate receipt schema does not match manifest")
    bindings = {
        "competition_id": identifier,
        "request_id": bound_manifest["request_id"],
        "request_fingerprint": bound_manifest["request_fingerprint"],
        "provider": bound_manifest["provider"],
        "mode": bound_manifest["mode"],
        "repository": bound_manifest["repository"],
        "expected_head": bound_manifest["expected_head"],
        "task_sha256": bound_manifest["task_sha256"],
        "packet_sha256": bound_manifest["packet_sha256"],
        "runner_sha256": bound_manifest["runner_sha256"],
    }
    for field, expected in bindings.items():
        if receipt.get(field) != expected:
            raise AgentCompetitionError(f"candidate receipt binding mismatch: {field}")
    if version == 2 and receipt["budget_contract"] != bound_manifest["budget_contract"]:
        raise AgentCompetitionError("candidate receipt budget does not match manifest")
    if receipt["authority"] != "advisory_only" or any(
        receipt[field] is not False
        for field in ("automatic_apply", "automatic_commit", "automatic_merge", "automatic_deploy")
    ):
        raise AgentCompetitionError("candidate receipt authority is invalid")
    wrapper = receipt.get("output_wrapper")
    if wrapper is not None:
        if (
            not isinstance(wrapper, dict)
            or set(wrapper) != {
                "kind", "discarded_prefix_bytes", "discarded_suffix_bytes", "discarded_wrapper_sha256",
            }
            or wrapper["kind"] not in {
                "provider_envelope", "none", "exact_json_fence", "single_json_fence_with_discarded_wrapper",
            }
            or isinstance(wrapper["discarded_prefix_bytes"], bool)
            or not isinstance(wrapper["discarded_prefix_bytes"], int)
            or not 0 <= wrapper["discarded_prefix_bytes"] <= 4096
            or isinstance(wrapper["discarded_suffix_bytes"], bool)
            or not isinstance(wrapper["discarded_suffix_bytes"], int)
            or not 0 <= wrapper["discarded_suffix_bytes"] <= 4096
            or not isinstance(wrapper["discarded_wrapper_sha256"], str)
            or SHA256_RE.fullmatch(wrapper["discarded_wrapper_sha256"]) is None
        ):
            raise AgentCompetitionError("candidate receipt output wrapper is invalid")
    directory = _validate_competition_directory(_competition_dir(identifier))
    packet = _validated_packet(identifier)
    provider_workspace = _validate_competition_directory(directory / "provider-workspace")
    entries = sorted(item.name for item in provider_workspace.iterdir())
    if entries != ["prompt.txt"]:
        raise AgentCompetitionError("candidate provider workspace contents are invalid")
    prompt = _load_regular_bytes(
        provider_workspace / "prompt.txt",
        label="candidate provider prompt",
        max_bytes=750_000,
        required_mode=0o600,
    )
    if _sha256_bytes(prompt) != receipt["prompt_sha256"]:
        raise AgentCompetitionError("candidate provider prompt hash is invalid")
    _validate_receipt_execution(receipt, packet)
    _validate_receipt_candidate(receipt["candidate"], packet)
    return receipt



def _workspace_route_shadow_calibration(
    input_facts: dict[str, Any], recommended_mode: str
) -> dict[str, Any]:
    """Compare current-cohort outcomes without changing the deterministic route."""
    try:
        import grabowski_agent_workspace_observer as observer

        snapshot = observer.workspace_metrics_snapshot(limit=50)
    except Exception as exc:
        return {
            "schema_version": 1,
            "mode": "shadow_only",
            "integrity_valid": False,
            "eligible": False,
            "reason": "workspace_metrics_unavailable",
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
            "recommended_mode": recommended_mode,
            "applied_to_live_route": False,
            "execution_authorized": False,
        }

    def median(values: list[float]) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        middle = len(ordered) // 2
        if len(ordered) % 2:
            return ordered[middle]
        return (ordered[middle - 1] + ordered[middle]) / 2

    comparable: list[tuple[dict[str, Any], str]] = []
    discarded_record_count = 0
    current_risk_tier = workspace._route_decision(input_facts).get("risk_tier")
    for record in snapshot.get("route_records", []):
        if not isinstance(record, dict):
            discarded_record_count += 1
            continue
        route = record.get("route_evidence")
        if not isinstance(route, dict):
            discarded_record_count += 1
            continue
        actual_route = route.get("actual_route")
        prior = route.get("input_facts")
        if not isinstance(actual_route, str) or not actual_route:
            discarded_record_count += 1
            continue
        if not isinstance(prior, dict):
            discarded_record_count += 1
            continue
        prior_risk_flags = prior.get("risk_flags")
        if (
            not isinstance(prior_risk_flags, list)
            or any(not isinstance(item, str) for item in prior_risk_flags)
        ):
            discarded_record_count += 1
            continue
        if (
            route.get("schema_version") == 2
            and route.get("route_policy_version") == workspace.ROUTE_POLICY_VERSION
            and route.get("risk_tier") == current_risk_tier
            and prior.get("task_kind") == input_facts["task_kind"]
            and prior.get("novelty") == input_facts["novelty"]
            and sorted(prior_risk_flags) == input_facts["risk_flags"]
        ):
            comparable.append((record, actual_route))
    routes: dict[str, dict[str, Any]] = {}
    for record, actual_route in comparable:
        aggregate = routes.setdefault(
            actual_route,
            {
                "route": actual_route,
                "workspace_count": 0,
                "closed_count": 0,
                "successful_close_count": 0,
                "platform_friction_workspace_count": 0,
                "quality_signal_workspace_count": 0,
                "close_seconds": [],
                "source_report_sha256": [],
            },
        )
        aggregate["workspace_count"] += 1
        aggregate["closed_count"] += record.get("closed") is True
        aggregate["successful_close_count"] += record.get("closure_outcome") == "successful"
        aggregate["platform_friction_workspace_count"] += bool(
            record.get("workspace_friction_classes")
        )
        aggregate["quality_signal_workspace_count"] += bool(
            record.get("quality_signal_classes")
        )
        timing = record.get("timing")
        close_seconds = timing.get("close_complete_seconds") if isinstance(timing, dict) else None
        if isinstance(close_seconds, (int, float)) and not isinstance(close_seconds, bool):
            aggregate["close_seconds"].append(float(close_seconds))
        report_sha256 = record.get("report_sha256")
        if isinstance(report_sha256, str):
            aggregate["source_report_sha256"].append(report_sha256)
    route_summaries: list[dict[str, Any]] = []
    for route, aggregate in sorted(routes.items()):
        closed = aggregate.pop("closed_count")
        success = aggregate.pop("successful_close_count")
        close_values = aggregate.pop("close_seconds")
        route_summaries.append({
            **aggregate,
            "closed_count": closed,
            "successful_close_count": success,
            "completion_ratio": closed / aggregate["workspace_count"],
            "closed_success_ratio": success / closed if closed else None,
            "median_close_seconds": median(close_values),
        })
    minimum_evidence = 5
    integrity_valid = snapshot.get("integrity_valid") is True
    body = {
        "schema_version": 1,
        "mode": "shadow_only",
        "integrity_valid": integrity_valid,
        "snapshot_sha256": snapshot.get("snapshot_sha256"),
        "cohort": snapshot.get("current_cohort"),
        "friction_fingerprint_sha256": (
            snapshot.get("friction_fingerprint_sha256") if integrity_valid else None
        ),
        "comparison_key": {
            "route_policy_version": workspace.ROUTE_POLICY_VERSION,
            "risk_tier": workspace._route_decision(input_facts).get("risk_tier"),
            "task_kind": input_facts["task_kind"],
            "novelty": input_facts["novelty"],
            "risk_flags": input_facts["risk_flags"],
        },
        "recommended_mode": recommended_mode,
        "comparable_workspace_count": len(comparable),
        "discarded_record_count": discarded_record_count,
        "minimum_evidence": minimum_evidence,
        "eligible": bool(
            integrity_valid
            and len(comparable) >= minimum_evidence
            and len(route_summaries) >= 2
        ),
        "route_summaries": route_summaries,
        "applied_to_live_route": False,
        "execution_authorized": False,
        "automatic_promotion": False,
        "does_not_establish": [
            "causality",
            "route_superiority",
            "execution_authority",
            "permission_to_change_route_thresholds",
        ],
    }
    return {**body, "calibration_sha256": _sha256_json(body)}


@mcp.tool(name="grabowski_agent_execution_route", annotations=READ_ONLY)
def grabowski_agent_execution_route(
    task_kind: str,
    changed_file_estimate: int,
    expected_duration_minutes: int,
    novelty: str,
    risk_flags: list[str] | None = None,
    connector_instability: bool = False,
    parallel_work: bool | None = None,
    user_requested_external: bool = False,
    available_external_agents: list[str] | None = None,
    concurrent_external_activity: bool | None = None,
    parallelization_candidate: bool = False,
    decision_fork: bool = False,
    architecture_hypotheses: int = 1,
) -> dict[str, Any]:
    """Recommend a lean R0-R3 route without authorizing parallel writers."""
    kind = workspace._required_string(task_kind, "task_kind", max_length=32)
    if kind not in TASK_KINDS:
        raise AgentCompetitionError(
            f"task_kind must be one of {sorted(TASK_KINDS)}"
        )
    if (
        isinstance(changed_file_estimate, bool)
        or not isinstance(changed_file_estimate, int)
        or not 0 <= changed_file_estimate <= 10000
    ):
        raise AgentCompetitionError(
            "changed_file_estimate must be an integer between 0 and 10000"
        )
    if (
        isinstance(expected_duration_minutes, bool)
        or not isinstance(expected_duration_minutes, int)
        or not 0 <= expected_duration_minutes <= 10080
    ):
        raise AgentCompetitionError(
            "expected_duration_minutes must be an integer between 0 and 10080"
        )
    novelty_value = workspace._required_string(
        novelty, "novelty", max_length=16
    )
    if novelty_value not in NOVELTY:
        raise AgentCompetitionError(
            f"novelty must be one of {sorted(NOVELTY)}"
        )
    flags = [] if risk_flags is None else risk_flags
    if not isinstance(flags, list) or len(flags) > len(RISK_FLAGS):
        raise AgentCompetitionError("risk_flags is invalid")
    normalized_flags = sorted(
        set(
            workspace._required_string(
                item, "risk_flag", max_length=32
            )
            for item in flags
        )
    )
    unknown_flags = sorted(set(normalized_flags) - RISK_FLAGS)
    if unknown_flags:
        raise AgentCompetitionError(f"unknown risk_flags: {unknown_flags}")
    connector_flag = _strict_bool(
        connector_instability, "connector_instability"
    )
    legacy_parallel = (
        None
        if parallel_work is None
        else _strict_bool(parallel_work, "parallel_work")
    )
    concurrent_flag = (
        None
        if concurrent_external_activity is None
        else _strict_bool(
            concurrent_external_activity, "concurrent_external_activity"
        )
    )
    if (
        legacy_parallel is not None
        and concurrent_flag is not None
        and legacy_parallel != concurrent_flag
    ):
        raise AgentCompetitionError(
            "parallel_work and concurrent_external_activity disagree"
        )
    resolved_concurrent = bool(
        concurrent_flag
        if concurrent_flag is not None
        else legacy_parallel
        if legacy_parallel is not None
        else False
    )
    parallel_candidate = _strict_bool(
        parallelization_candidate, "parallelization_candidate"
    )
    decision_fork_flag = _strict_bool(decision_fork, "decision_fork")
    external_requested = _strict_bool(
        user_requested_external, "user_requested_external"
    )
    if (
        isinstance(architecture_hypotheses, bool)
        or not isinstance(architecture_hypotheses, int)
        or not 1 <= architecture_hypotheses <= 4
    ):
        raise AgentCompetitionError(
            "architecture_hypotheses must be between 1 and 4"
        )
    if available_external_agents is None:
        normalized_agents = [
            provider
            for provider in ("claude", "agy")
            if shutil.which(provider)
        ]
    else:
        agents = available_external_agents
        if not isinstance(agents, list) or len(agents) > 10:
            raise AgentCompetitionError(
                "available_external_agents is invalid"
            )
        requested_agents = {
            workspace._required_string(
                item, "external_agent", max_length=32
            )
            for item in agents
        }
        unsupported = sorted(requested_agents - PROVIDERS)
        if unsupported:
            raise AgentCompetitionError(
                f"unsupported external agents: {unsupported}"
            )
        normalized_agents = [
            provider
            for provider in ("claude", "agy")
            if provider in requested_agents
        ]
    input_facts = {
        "task_kind": kind,
        "changed_file_estimate": changed_file_estimate,
        "expected_duration_minutes": expected_duration_minutes,
        "novelty": novelty_value,
        "risk_flags": normalized_flags,
        "connector_instability": connector_flag,
        "concurrent_external_activity": resolved_concurrent,
        "parallelization_candidate": parallel_candidate,
        "decision_fork": decision_fork_flag,
        "architecture_hypotheses": architecture_hypotheses,
        "user_requested_external": external_requested,
        "available_external_agents": normalized_agents,
    }
    decision = workspace._route_decision(input_facts)
    score = int(decision["score"])
    mode = str(decision["execution_mode"])
    candidate_plan = list(decision["external_candidates"])
    design_space = bool(decision["design_space"])
    external_available = list(input_facts["available_external_agents"])
    trivial_work = bool(decision["trivial_work"])
    result = {
        "schema_version": 2,
        "route_policy_version": decision["route_policy_version"],
        "risk_tier": decision["risk_tier"],
        "score": score,
        "execution_mode": mode,
        "full_workspace": mode.startswith("full_workspace")
        or mode.startswith("workspace_with_"),
        "external_candidates": candidate_plan,
        "max_external_candidates": 2,
        "external_results_are_advisory": True,
        "automatic_patch_apply": False,
        "automatic_winner_selection": False,
        "operator_remains_integrator": True,
        "roles_remain_isolated": mode != "direct_operator",
        "single_mutating_writer": True,
        "parallel_writer_pilot": decision["parallel_writer_pilot"],
        "input_facts": input_facts,
        "trivial_work": trivial_work,
        "deviation_requires_reason": True,
        "rationale": {
            "task_kind": kind,
            "risk_tier": decision["risk_tier"],
            "novelty": novelty_value,
            "risk_flags": normalized_flags,
            "connector_instability": connector_flag,
            "concurrent_external_activity": resolved_concurrent,
            "parallelization_candidate": parallel_candidate,
            "decision_fork": decision_fork_flag,
            "architecture_hypotheses": architecture_hypotheses,
            "design_space_benefits_from_contrast": design_space,
            "contrast_eligible": decision["contrast_eligible"],
            "competition_eligible": decision["competition_eligible"],
            "external_agents_available": external_available,
        },
        "stop_conditions": [
            "external candidate exceeds scope or context limits",
            "bound commit or exported context becomes unavailable or mismatched",
            "candidate attempts mutation or returns unstructured output",
            "additional candidate would repeat an already represented approach",
            "parallel writer assessment lacks a two-shard conflict-domain proof",
        ],
        "does_not_establish": [
            "execution_authority",
            "candidate_correctness",
            "merge_readiness",
            "need_for_external_agents",
            "parallel_writer_safety",
            "workspace_group_availability",
        ],
    }
    recommendation_contract = {
        "schema_version": result["schema_version"],
        "route_policy_version": result["route_policy_version"],
        "risk_tier": result["risk_tier"],
        "score": score,
        "execution_mode": mode,
        "input_facts": input_facts,
        "external_candidates": candidate_plan,
        "parallel_writer_pilot": result["parallel_writer_pilot"],
    }
    result["recommendation_id"] = _sha256_json(recommendation_contract)
    result["shadow_calibration"] = _workspace_route_shadow_calibration(
        input_facts, mode
    )
    return result


@mcp.tool(name="grabowski_agent_competition_start", annotations=MUTATING)
def grabowski_agent_competition_start(
    request_id: str,
    provider: str,
    mode: str,
    repository: str,
    expected_head: str,
    task: str,
    allowed_paths: list[str],
    context_paths: list[str],
    forbidden_paths: list[str] | None = None,
    primary_summary: str = "",
    timeout_seconds: int = 900,
    max_budget_usd: float = 2.0,
    require_hard_budget: bool = False,
) -> dict[str, Any]:
    """Start one durable advisory-only external competitor or contrast programmer."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_capability("git_cli")
    request_value = workspace._required_string(request_id, "request_id", max_length=80)
    if REQUEST_ID_RE.fullmatch(request_value) is None:
        raise AgentCompetitionError("request_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,79}")
    provider_value = workspace._required_string(provider, "provider", max_length=16)
    mode_value = workspace._required_string(mode, "mode", max_length=16)
    if provider_value not in PROVIDERS or mode_value not in MODES:
        raise AgentCompetitionError("provider or mode is unsupported")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 30 <= timeout_seconds <= 3600:
        raise AgentCompetitionError("timeout_seconds must be between 30 and 3600")
    if isinstance(max_budget_usd, bool) or not isinstance(max_budget_usd, (int, float)) or not 0 < float(max_budget_usd) <= 10:
        raise AgentCompetitionError("max_budget_usd must be in (0, 10]")
    hard_budget_required = _strict_bool(require_hard_budget, "require_hard_budget")
    budget_contract = _budget_contract(
        provider_value,
        float(max_budget_usd),
        hard_limit_required=hard_budget_required,
    )
    repo, head = _repository(repository, expected_head)
    task_value = workspace._required_string(task, "task", max_length=16000)
    if not isinstance(primary_summary, str) or len(primary_summary.encode("utf-8")) > 32000 or "\x00" in primary_summary:
        raise AgentCompetitionError("primary_summary is invalid")
    summary = primary_summary.strip()
    allowed = _scope(allowed_paths, label="allowed_paths", nonempty=True)
    forbidden = _scope([] if forbidden_paths is None else forbidden_paths, label="forbidden_paths", nonempty=False)
    default_forbidden_allowed = [path for path in allowed if _path_has_default_forbidden_component(path)]
    if default_forbidden_allowed:
        raise AgentCompetitionError(
            f"default-forbidden allowed paths are not exportable: {default_forbidden_allowed}"
        )
    sensitive_allowed = [path for path in allowed if _path_is_sensitive(path)]
    if sensitive_allowed:
        raise AgentCompetitionError(f"sensitive-looking allowed paths are not exportable: {sensitive_allowed}")
    contexts = _context(repo, head, context_paths, allowed, forbidden)
    executable = shutil.which(provider_value)
    if not executable:
        raise AgentCompetitionError(f"provider executable is unavailable: {provider_value}")
    runner_bytes = _load_regular_bytes(
        RUNNER,
        label="external candidate runner source",
        max_bytes=MAX_RUNNER_BYTES,
        required_mode=None,
    )
    runner_sha256 = _sha256_bytes(runner_bytes)
    task_sha256 = _sha256_bytes(task_value.encode("utf-8"))
    request_contract = {
        "request_id": request_value,
        "provider": provider_value,
        "mode": mode_value,
        "repository": str(repo),
        "expected_head": head,
        "task_sha256": task_sha256,
        "runner_sha256": runner_sha256,
        "task": task_value,
        "allowed_paths": allowed,
        "forbidden_paths": forbidden,
        "context": [{"path": item["path"], "sha256": item["sha256"]} for item in contexts],
        "primary_summary": summary,
        "timeout_seconds": timeout_seconds,
        "budget_contract": budget_contract,
    }
    request_fingerprint = _sha256_json(request_contract)
    identifier = _competition_id(provider_value, mode_value, task_sha256, request_value)
    with _competition_request_lock(identifier):
        directory = _competition_dir(identifier)
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            _validate_competition_directory(directory)
            manifest_path = directory / "manifest.json"
            intent_path = directory / "start-intent.json"
            if manifest_path.exists() or manifest_path.is_symlink():
                existing = _validated_manifest(identifier)
                expected_existing_fingerprint = request_fingerprint
                if existing["schema_version"] == 1:
                    legacy_request_contract = dict(request_contract)
                    legacy_request_contract.pop("budget_contract")
                    legacy_request_contract["max_budget_usd"] = float(max_budget_usd)
                    expected_existing_fingerprint = _sha256_json(legacy_request_contract)
                if existing["request_fingerprint"] != expected_existing_fingerprint:
                    raise AgentCompetitionError("request_id already exists with a different competition contract")
                return {
                    "competition_id": identifier,
                    "request_id": request_value,
                    "provider": existing["provider"],
                    "mode": existing["mode"],
                    "task_id": existing["task_id"],
                    "packet_sha256": existing["packet_sha256"],
                    "budget_contract": existing.get("budget_contract"),
                    "status_tool": "grabowski_agent_competition_status",
                    "already_started": True,
                    "automatic_apply": False,
                    "does_not_establish": ["candidate_success", "candidate_correctness", "preferred_candidate"],
                }
            if intent_path.exists() or intent_path.is_symlink():
                intent = _validated_start_intent(identifier)
                expected_intent_fingerprint = request_fingerprint
                if intent["schema_version"] == 1:
                    legacy_request_contract = dict(request_contract)
                    legacy_request_contract.pop("budget_contract")
                    legacy_request_contract["max_budget_usd"] = float(max_budget_usd)
                    expected_intent_fingerprint = _sha256_json(legacy_request_contract)
                if intent["request_fingerprint"] != expected_intent_fingerprint:
                    raise AgentCompetitionError("request_id already exists with a different unresolved start intent")
                reconciliation = _start_reconciliation(identifier, intent)
                reconciled_task = reconciliation.get("task")
                if isinstance(reconciled_task, dict):
                    packet = _validated_packet(identifier)
                    if (
                        packet["request_fingerprint"] != request_fingerprint
                        or packet.get("budget_contract") != budget_contract
                    ):
                        raise AgentCompetitionError("reconciled packet does not match the requested competition contract")
                    manifest = _manifest_from_task(identifier, packet, intent, reconciled_task)
                    _atomic_json(directory / "manifest.json", manifest)
                    return {
                        "competition_id": identifier,
                        "request_id": request_value,
                        "provider": packet["provider"],
                        "mode": packet["mode"],
                        "task_id": reconciled_task["task_id"],
                        "packet_sha256": packet["packet_sha256"],
                        "budget_contract": packet["budget_contract"],
                        "status_tool": "grabowski_agent_competition_status",
                        "already_started": True,
                        "start_reconciled": True,
                        "automatic_apply": False,
                        "does_not_establish": ["candidate_success", "candidate_correctness", "preferred_candidate"],
                    }
                raise AgentCompetitionError(
                    "competition start outcome is unresolved; task reconciliation="
                    + reconciliation["state"]
                )
            raise AgentCompetitionError("competition directory already exists without a valid manifest or start intent")
        directory = _validate_competition_directory(directory)
        frozen_runner_path = directory / "runner.py"
        _atomic_bytes(frozen_runner_path, runner_bytes)
        provider_workspace = directory / "provider-workspace"
        os.mkdir(provider_workspace, 0o700)
        _validate_competition_directory(provider_workspace)
        packet: dict[str, Any] = {
            "schema_version": 2,
            "kind": "external_programming_candidate_packet",
            "competition_id": identifier,
            "request_id": request_value,
            "request_fingerprint": request_fingerprint,
            "provider": provider_value,
            "mode": mode_value,
            "repository": str(repo),
            "expected_head": head,
            "task": task_value,
            "task_sha256": task_sha256,
            "runner_sha256": runner_sha256,
            "allowed_paths": allowed,
            "forbidden_paths": forbidden,
            "context": contexts,
            "primary_summary": summary,
            "budget_contract": budget_contract,
            "packet_nonce": secrets.token_hex(16),
            "created_at": workspace._utc(),
        }
        packet["packet_sha256"] = _sha256_json(packet)
        packet_path = directory / "packet.json"
        receipt_path = directory / "receipt.json"
        raw_path = directory / "raw-output.json"
        stderr_path = directory / "stderr.txt"
        _atomic_json(packet_path, packet)
        command = [
            "/usr/bin/python3", str(frozen_runner_path),
            "--packet", str(packet_path),
            "--output", str(receipt_path),
            "--raw-output", str(raw_path),
            "--stderr-output", str(stderr_path),
            "--timeout-seconds", str(timeout_seconds),
            "--max-budget-usd", format(float(max_budget_usd), "g"),
        ]
        start_intent = {
            "schema_version": 2,
            "kind": "external_programming_competition_start_intent",
            "competition_id": identifier,
            "request_id": request_value,
            "request_fingerprint": request_fingerprint,
            "packet_sha256": packet["packet_sha256"],
            "command_sha256": _sha256_json(command),
            "created_at": workspace._utc(),
            "created_at_unix": int(time.time()),
            "state": "prepared",
        }
        start_intent["start_intent_sha256"] = _sha256_json(start_intent)
        _atomic_json(directory / "start-intent.json", start_intent)
        task_record: dict[str, Any] | None = None
        start_reconciled = False
        try:
            task_start = tasks.grabowski_task_start(
                host="heim-pc",
                argv=command,
                cwd=str(directory),
                runtime_seconds=timeout_seconds + 180,
                resume_policy="never",
                cpu_weight=80,
                io_weight=80,
                memory_max_bytes=2 * 1024 * 1024 * 1024,
                resource_keys=[f"path:{directory}"],
            )
        except Exception:
            reconciliation = _start_reconciliation(identifier, start_intent)
            candidate = reconciliation.get("task")
            if isinstance(candidate, dict):
                task_record = candidate
                start_reconciled = True
            else:
                _write_start_outcome(
                    identifier,
                    start_intent,
                    state="task_start_outcome_unknown",
                )
                raise
        else:
            candidate = task_start.get("task") if isinstance(task_start, dict) else None
            if isinstance(candidate, dict) and isinstance(candidate.get("task_id"), str):
                task_record = candidate
            else:
                reconciliation = _start_reconciliation(identifier, start_intent)
                reconciled = reconciliation.get("task")
                if isinstance(reconciled, dict):
                    task_record = reconciled
                    start_reconciled = True
                else:
                    _write_start_outcome(
                        identifier,
                        start_intent,
                        state="task_start_outcome_unknown",
                    )
                    raise AgentCompetitionError(
                        "durable task start outcome is unknown; reconciliation="
                        + reconciliation["state"]
                    )
        assert task_record is not None
        manifest = _manifest_from_task(identifier, packet, start_intent, task_record)
        try:
            _atomic_json(directory / "manifest.json", manifest)
        except Exception:
            try:
                published_manifest = _validated_manifest(identifier)
            except Exception:
                published_manifest = None
            if (
                isinstance(published_manifest, dict)
                and published_manifest.get("manifest_sha256") == manifest["manifest_sha256"]
                and published_manifest.get("task_id") == task_record["task_id"]
            ):
                return {
                    "competition_id": identifier,
                    "request_id": request_value,
                    "provider": provider_value,
                    "mode": mode_value,
                    "task_id": task_record["task_id"],
                    "packet_sha256": packet["packet_sha256"],
                    "budget_contract": budget_contract,
                    "status_tool": "grabowski_agent_competition_status",
                    "already_started": False,
                    "start_reconciled": start_reconciled,
                    "manifest_publish_readback_recovered": True,
                    "automatic_apply": False,
                    "does_not_establish": ["candidate_success", "candidate_correctness", "preferred_candidate"],
                }
            cancel_state = "unconfirmed"
            try:
                cancel_result = tasks.grabowski_task_cancel(task_record["task_id"])
                cancelled_task = cancel_result.get("task") if isinstance(cancel_result, dict) else None
                cancel_probe = cancel_result.get("result") if isinstance(cancel_result, dict) else None
                if (
                    isinstance(cancelled_task, dict)
                    and cancelled_task.get("state") == "cancelled"
                    and isinstance(cancel_probe, dict)
                    and cancel_probe.get("returncode") == 0
                ):
                    cancel_state = "confirmed"
            except Exception:
                pass
            _write_start_outcome(
                identifier,
                start_intent,
                state="manifest_publish_failed",
                task_id=task_record["task_id"],
                task_unit=task_record.get("unit"),
                cancel_state=cancel_state,
            )
            raise
        return {
            "competition_id": identifier,
            "request_id": request_value,
            "provider": provider_value,
            "mode": mode_value,
            "task_id": task_record["task_id"],
            "packet_sha256": packet["packet_sha256"],
            "budget_contract": budget_contract,
            "status_tool": "grabowski_agent_competition_status",
            "already_started": False,
            "start_reconciled": start_reconciled,
            "automatic_apply": False,
            "does_not_establish": ["candidate_success", "candidate_correctness", "preferred_candidate"],
        }


@mcp.tool(name="grabowski_agent_competition_status", annotations=READ_ONLY)
def grabowski_agent_competition_status(competition_id: str) -> dict[str, Any]:
    """Read one candidate lifecycle with deterministic phases and fail-closed reconciliation evidence."""
    operator._require_operator_capability("durable_job")
    directory = _competition_dir(competition_id)
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists() and not manifest_path.is_symlink():
        intent = _validated_start_intent(competition_id)
        outcome = _validated_start_outcome(competition_id, intent)
        reconciliation = _start_reconciliation(competition_id, intent)
        bounded_task = None
        task_id = outcome["task_id"] if outcome is not None else None
        if task_id is None and isinstance(reconciliation.get("task"), dict):
            task_id = reconciliation["task"].get("task_id")
        if isinstance(task_id, str):
            task_status = tasks.grabowski_task_status(task_id)
            bounded_task = {
                key: task_status.get(key)
                for key in ("task_id", "unit", "attempt", "state", "updated_at_unix", "resume_policy")
                if key in task_status
            }
        if outcome is not None:
            lifecycle_state = outcome["state"]
            next_action = {
                "task_start_outcome_unknown": "retry the same request only after one exact task reconciliation match exists",
                "manifest_publish_failed": "verify the recorded task cancellation or terminal state",
            }[lifecycle_state]
        elif reconciliation["state"] == "unique_match":
            lifecycle_state = "task_start_reconciled_manifest_missing"
            next_action = "retry the identical start request to publish the bound manifest"
        else:
            lifecycle_state = "start_prepared_outcome_unresolved"
            next_action = "inspect task reconciliation evidence; duplicate start remains blocked"
        return {
            "schema_version": 2,
            "competition_id": competition_id,
            "request_id": intent["request_id"],
            "lifecycle_state": lifecycle_state,
            "phase": "start_reconciliation",
            "manifest_present": False,
            "task": bounded_task,
            "start_reconciliation": {
                "state": reconciliation["state"],
                "matching_task_ids": reconciliation["matches"],
            },
            "cancel_state": outcome["cancel_state"] if outcome is not None else "not_attempted",
            "receipt_present": False,
            "candidate": None,
            "candidate_ready": False,
            "retry_blocked": reconciliation["state"] != "unique_match",
            "next_action": next_action,
            "authority": "advisory_only",
            "automatic_apply": False,
            "does_not_establish": [
                "task_not_started", "task_terminal", "correctness", "test_pass", "review_pass", "preferred_candidate",
            ],
        }
    manifest = _validated_manifest(competition_id)
    task_status = tasks.grabowski_task_status(manifest["task_id"])
    receipt = _receipt(competition_id, manifest)
    task_state = task_status.get("state")
    if receipt is not None:
        lifecycle_state = "candidate_receipt_ready"
        phase = "receipt_ready"
    elif task_state in {"launching", "running"}:
        lifecycle_state = "provider_running"
        phase = "provider_execution"
    elif task_state == "completed":
        lifecycle_state = "candidate_output_missing_or_invalid"
        phase = "candidate_validation"
    elif task_state in {"failed", "cancelled", "timed_out", "signalled", "outcome_unknown"}:
        lifecycle_state = f"provider_{task_state}"
        phase = "provider_terminal"
    else:
        lifecycle_state = "task_observed"
        phase = "task_observation"
    bounded_task = {
        key: task_status.get(key)
        for key in ("task_id", "unit", "attempt", "state", "updated_at_unix", "resume_policy")
        if key in task_status
    }
    return {
        "schema_version": 2,
        "competition_id": competition_id,
        "request_id": manifest["request_id"],
        "provider": manifest["provider"],
        "mode": manifest["mode"],
        "repository": manifest["repository"],
        "expected_head": manifest["expected_head"],
        "task_sha256": manifest["task_sha256"],
        "budget_contract": manifest.get("budget_contract"),
        "lifecycle_state": lifecycle_state,
        "phase": phase,
        "manifest_present": True,
        "task": bounded_task,
        "receipt_present": receipt is not None,
        "candidate": _candidate_summary(receipt) if receipt is not None else None,
        "candidate_ready": receipt is not None and task_state == "completed",
        "retry_blocked": True,
        "authority": "advisory_only",
        "automatic_apply": False,
        "does_not_establish": ["correctness", "test_pass", "review_pass", "preferred_candidate"],
    }


def _candidate_summary(receipt: dict[str, Any]) -> dict[str, Any]:
    candidate = receipt["candidate"]
    return {
        "competition_id": receipt["competition_id"],
        "provider": receipt["provider"],
        "mode": receipt["mode"],
        "approach_id": candidate["approach_id"],
        "approach_summary": candidate["approach_summary"],
        "confidence": candidate["confidence"],
        "changed_paths": candidate["changed_paths"],
        "patch_sha256": candidate["patch_sha256"],
        "patch_size_bytes": len(candidate["patch"].encode("utf-8")),
        "patch_available": bool(candidate["patch"]),
        "patch_applies": candidate["patch_check"]["applies"],
        "patch_syntax_accepted": candidate["patch_check"].get("syntax_accepted", True),
        "patch_rejection": candidate.get("patch_rejection"),
        "assumptions": candidate["assumptions"],
        "design_invariants": candidate["design_invariants"],
        "tradeoffs": candidate["tradeoffs"],
        "risks": candidate["risks"],
        "proposed_tests": candidate["proposed_tests"],
        "contrast_observations": candidate["contrast_observations"],
        "receipt_sha256": receipt["receipt_sha256"],
    }


@mcp.tool(name="grabowski_agent_competition_compare", annotations=READ_ONLY)
def grabowski_agent_competition_compare(competition_ids: list[str]) -> dict[str, Any]:
    """Generate a deterministic contrast matrix from exactly two bound candidates."""
    operator._require_operator_capability("durable_job")
    if not isinstance(competition_ids, list) or len(competition_ids) != 2:
        raise AgentCompetitionError("competition_ids must contain exactly 2 entries")
    if len(set(competition_ids)) != len(competition_ids):
        raise AgentCompetitionError("competition_ids must be unique")
    receipts: list[dict[str, Any]] = []
    for identifier in competition_ids:
        manifest = _validated_manifest(identifier)
        receipt = _receipt(identifier, manifest)
        if receipt is None:
            raise AgentCompetitionError(f"candidate receipt is not ready: {identifier}")
        receipts.append(receipt)
    bindings = {(item["repository"], item["expected_head"], item["task_sha256"]) for item in receipts}
    if len(bindings) != 1:
        raise AgentCompetitionError("candidate receipts do not share repository, head and task binding")
    candidates = [_candidate_summary(item) for item in receipts]
    path_sets = [set(item["changed_paths"]) for item in candidates]
    risk_sets = [set(item["risks"]) for item in candidates]
    invariant_sets = [set(item["design_invariants"]) for item in candidates]
    test_sets = [set(item["proposed_tests"]) for item in candidates]
    test_counter: Counter[str] = Counter(
        test
        for item in candidates
        for test in set(item["proposed_tests"])
    )
    shared_paths = sorted(set.intersection(*path_sets)) if path_sets else []
    all_paths = sorted(set.union(*path_sets)) if path_sets else []
    shared_risks = sorted(set.intersection(*risk_sets)) if risk_sets else []
    shared_invariants = sorted(set.intersection(*invariant_sets)) if invariant_sets else []
    pairwise = []
    for left_index, left in enumerate(candidates):
        for right in candidates[left_index + 1 :]:
            left_paths = set(left["changed_paths"])
            right_paths = set(right["changed_paths"])
            left_risks = set(left["risks"])
            right_risks = set(right["risks"])
            left_tests = set(left["proposed_tests"])
            right_tests = set(right["proposed_tests"])
            union = left_paths | right_paths
            both_patches_available = bool(left["patch_available"] and right["patch_available"])
            pairwise.append({
                "left": left["competition_id"],
                "right": right["competition_id"],
                "shared_paths": sorted(left_paths & right_paths),
                "unique_left_paths": sorted(left_paths - right_paths),
                "unique_right_paths": sorted(right_paths - left_paths),
                "shared_risks": sorted(left_risks & right_risks),
                "unique_left_risks": sorted(left_risks - right_risks),
                "unique_right_risks": sorted(right_risks - left_risks),
                "shared_tests": sorted(left_tests & right_tests),
                "unique_left_tests": sorted(left_tests - right_tests),
                "unique_right_tests": sorted(right_tests - left_tests),
                "path_jaccard": round(len(left_paths & right_paths) / len(union), 6) if union else None,
                "both_patches_available": both_patches_available,
                "same_patch": (
                    both_patches_available
                    and left["patch_sha256"] == right["patch_sha256"]
                ),
            })
    insights: list[dict[str, Any]] = []
    if shared_paths:
        insights.append({
            "kind": "implementation_consensus",
            "evidence": shared_paths,
            "interpretation": "both candidates converge on these code surfaces; inspect them first but do not treat convergence as correctness",
        })
    divergent_paths = sorted(set(all_paths) - set(shared_paths))
    if divergent_paths:
        insights.append({
            "kind": "architectural_divergence",
            "evidence": divergent_paths,
            "interpretation": "candidates disagree on implementation boundaries; compare coupling, rollback and test cost before choosing",
        })
    if shared_risks:
        insights.append({
            "kind": "shared_risk",
            "evidence": shared_risks,
            "interpretation": "convert repeated independent risks into explicit tests or invariants",
        })
    if shared_invariants:
        insights.append({
            "kind": "shared_invariant",
            "evidence": shared_invariants,
            "interpretation": "preserve these constraints in the integrated implementation and review evidence",
        })
    repeated_tests = sorted(test for test, count in test_counter.items() if count >= 2)
    if repeated_tests:
        insights.append({
            "kind": "validation_consensus",
            "evidence": repeated_tests,
            "interpretation": "multiple candidates independently request these checks; prioritize them in the deterministic test role",
        })
    applying = [
        item["competition_id"]
        for item in candidates
        if item["patch_available"] and item["patch_applies"]
    ]
    nonapplying = [
        item["competition_id"]
        for item in candidates
        if item["patch_available"] and not item["patch_applies"]
    ]
    not_proposed = [
        item["competition_id"]
        for item in candidates
        if not item["patch_available"]
    ]
    if nonapplying:
        insights.append({
            "kind": "patch_applicability_gap",
            "evidence": nonapplying,
            "interpretation": "use these candidates for reasoning only unless the operator reconstructs and validates their changes",
        })
    result = {
        "schema_version": 2,
        "kind": "external_programming_contrast_matrix",
        "repository": receipts[0]["repository"],
        "expected_head": receipts[0]["expected_head"],
        "task_sha256": receipts[0]["task_sha256"],
        "candidate_count": len(candidates),
        "candidates": candidates,
        "pairwise_contrasts": pairwise,
        "consensus": {
            "changed_paths": shared_paths,
            "risks": shared_risks,
            "design_invariants": shared_invariants,
            "proposed_tests": repeated_tests,
        },
        "divergence": {
            "changed_paths": divergent_paths,
            "unique_risks_by_candidate": {
                item["competition_id"]: sorted(risk_sets[index] - set(shared_risks))
                for index, item in enumerate(candidates)
            },
            "unique_tests_by_candidate": {
                item["competition_id"]: sorted(test_sets[index] - set(repeated_tests))
                for index, item in enumerate(candidates)
            },
            "assumptions_by_candidate": {item["competition_id"]: item["assumptions"] for item in candidates},
            "tradeoffs_by_candidate": {item["competition_id"]: item["tradeoffs"] for item in candidates},
            "contrast_observations_by_candidate": {item["competition_id"]: item["contrast_observations"] for item in candidates},
        },
        "patch_applicability": {
            "applying": applying,
            "nonapplying": nonapplying,
            "not_proposed": not_proposed,
        },
        "insights": insights,
        "integration_rule": "operator selects explicit insights; normal isolated Writer reimplements or imports them, then deterministic Tests and independent Review validate the resulting frozen diff",
        "winner_selected": False,
        "automatic_apply": False,
        "automatic_merge": False,
        "does_not_establish": ["candidate_correctness", "causal_superiority", "test_pass", "review_pass", "merge_readiness"],
    }
    result["comparison_sha256"] = _sha256_json(result)
    return result
