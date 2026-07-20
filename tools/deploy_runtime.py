#!/usr/bin/env python3

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import stat as statmod
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator, NoReturn


SERVICE = "tunnel-client-grabowski.service"
PROFILE_NAME = "grabowski"
HEALTH_URL = "http://127.0.0.1:18080/healthz"
READY_URL = "http://127.0.0.1:18080/readyz"
HOME = Path.home()
TOOLING_PYYAML_VERSION = "6.0.3"
DEFAULT_PROFILE_PATH = HOME / ".config/tunnel-client/grabowski.yaml"
DEFAULT_STATE_ROOT = HOME / ".local/state/grabowski"
DEFAULT_LOCK_FILE = DEFAULT_STATE_ROOT / "deploy.lock"
RUNTIME_INPUT_RELATIVE = Path("requirements/runtime.in")
RUNTIME_LOCK_RELATIVE = Path("requirements/runtime.lock.txt")
ENTRYPOINT_CONTRACT_RELATIVE = Path("config/runtime-entrypoint.json")
RESERVED_SNAPSHOT_INPUT_PATHS = frozenset({
    ENTRYPOINT_CONTRACT_RELATIVE.name,
    RUNTIME_INPUT_RELATIVE.name,
    RUNTIME_LOCK_RELATIVE.name,
})
RELEASES_DIR_NAME = "grabowski-mcp-releases"
MANIFEST_NAME = "deployment-manifest.json"
INCOMPLETE_MARKER = "deployment-incomplete.json"
MANIFEST_SCHEMA_VERSION = 6
AGENT_INSTRUCTIONS_SCHEMA_VERSION = 1
AGENT_INSTRUCTIONS_MAX_BYTES = 4_096
AGENT_INSTRUCTIONS_HEADER_RE = re.compile(
    r"^Grabowski agent-facing contract "
    r"(?P<version>[a-z0-9][a-z0-9-]{0,127}) "
    r"\(schema (?P<schema>[1-9][0-9]*)\)\.$"
)
MCP_PROTOCOL_VERSIONS = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
ALLOWED_VENV_BASE_DISTS = {"pip", "setuptools", "wheel"}
TIMEOUTS = {
    "git": 10,
    "systemd_query": 10,
    "service_stop": 30,
    "service_start": 30,
    "mcp_probe": 20,
    "package_install": 180,
    "python": 20,
    "journal": 10,
}
PIN_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9!+_.-]*)(?:\s*\\)?$"
)
HASH_RE = re.compile(r"^--hash=sha256:[0-9a-f]{64}(?:\s*\\)?$")
MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
SECRET_WORD_RE = re.compile(
    r"(token|secret|password|passwd|apikey|api-key|authorization|bearer)",
    re.IGNORECASE,
)


class DeployError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        phase: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.phase = phase
        self.details = details or {}


def fail(message: str, *, phase: str | None = None, details: dict[str, Any] | None = None) -> NoReturn:
    raise DeployError(message, phase=phase, details=details)


def redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for item in argv:
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        if SECRET_WORD_RE.search(item):
            redacted.append("<redacted>")
            if "=" not in item:
                hide_next = True
            continue
        redacted.append(item)
    return redacted


def redact_text(text: str, *, limit: int = 4000) -> str:
    lines = []
    for line in text.splitlines()[-80:]:
        if SECRET_WORD_RE.search(line):
            lines.append("<redacted>")
        else:
            lines.append(line)
    return "\n".join(lines)[-limit:]


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value, limit=500)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): redact_value(item)
            for key, item in value.items()
            if not SECRET_WORD_RE.search(str(key))
        }
    return value


def safe_error_summary(exc: BaseException) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "type": type(exc).__name__,
        "message": redact_text(str(exc), limit=500),
    }
    if isinstance(exc, DeployError):
        if exc.phase is not None:
            summary["phase"] = exc.phase
        if exc.details:
            safe_details: dict[str, Any] = {}
            for key, value in exc.details.items():
                if key == "argv" and isinstance(value, list):
                    safe_details[key] = redact_argv([str(item) for item in value])
                elif key == "timeout_seconds":
                    safe_details[key] = value
                elif isinstance(value, str):
                    safe_details[key] = redact_text(value, limit=500)
                else:
                    safe_details[key] = redact_value(value)
            summary["details"] = safe_details
    if isinstance(exc, subprocess.CalledProcessError):
        summary["returncode"] = exc.returncode
        if isinstance(exc.cmd, list):
            summary["argv"] = redact_argv([str(item) for item in exc.cmd])
    if isinstance(exc, subprocess.TimeoutExpired):
        summary["timeout_seconds"] = exc.timeout
        if isinstance(exc.cmd, list):
            summary["argv"] = redact_argv([str(item) for item in exc.cmd])
    return summary


def summarize_result(value: Any) -> Any:
    if isinstance(value, subprocess.CompletedProcess):
        return {"returncode": value.returncode}
    if isinstance(value, PointerState):
        return pointer_to_dict(value)
    if isinstance(value, ReadinessResult):
        return {
            "ok": value.ok,
            "service": value.service,
            "health": value.health,
            "readiness": value.readiness,
            "main_pid": value.main_pid,
            "journal": value.journal,
        }
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return value
    return repr(value)


def run(
    argv: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            check=check,
            text=True,
            capture_output=capture,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        fail(
            "Externer Befehl hat sein Timeout überschritten.",
            phase="command-timeout",
            details={
                "argv": redact_argv(argv),
                "timeout_seconds": timeout,
                "cwd": str(cwd) if cwd else None,
            },
        )
        raise AssertionError from exc


def run_bytes(
    argv: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
) -> bytes:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        fail(
            "Externer Befehl hat sein Timeout überschritten.",
            phase="command-timeout",
            details={
                "argv": redact_argv(argv),
                "timeout_seconds": timeout,
                "cwd": str(cwd) if cwd else None,
            },
        )
        raise AssertionError from exc
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        fail(f"{label} fehlt: {path}")


def path_is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def normalize_managed_path(
    path: Path,
    *,
    allowed_root: Path,
    cwd: Path | None = None,
) -> Path:
    expanded = path.expanduser()
    base = cwd if cwd is not None else Path.cwd()
    candidate = expanded if expanded.is_absolute() else base / expanded
    normalized = Path(os.path.abspath(os.fspath(candidate)))
    try:
        allowed_real = allowed_root.expanduser().resolve(strict=True)
    except OSError as exc:
        fail(f"Erlaubter Root ist nicht validierbar: {allowed_root}")
        raise AssertionError from exc
    try:
        parent_real = normalized.parent.resolve(strict=True)
    except OSError as exc:
        fail(f"Managed-Path-Parent fehlt: {normalized.parent}")
        raise AssertionError from exc
    if not path_is_within(parent_real, allowed_real):
        fail(
            "Managed-Path-Parent liegt außerhalb des erlaubten Roots: "
            f"{parent_real}"
        )
    return parent_real / normalized.name


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_pinned_requirement(line: str, *, allow_continuation: bool) -> tuple[str, str]:
    match = PIN_RE.match(line)
    if not match:
        fail(f"Requirement ist nicht exakt gepinnt: {line}")
    if line.rstrip().endswith("\\") and not allow_continuation:
        fail(f"Requirement darf keine Fortsetzung haben: {line}")
    return normalize_package_name(match.group(1)), match.group(2)


def parse_pinned_input_file(path: Path, *, label: str = "Pinned-Input") -> dict[str, str]:
    require_file(path, label)
    pins: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-") or "://" in stripped or stripped.startswith("git+"):
            fail(f"Nicht erlaubte Pin-Option in {label}: {stripped}")
        name, version = parse_pinned_requirement(stripped, allow_continuation=False)
        if name in pins:
            fail(f"Doppeltes Paket in {label}: {name}")
        pins[name] = version
    if not pins:
        fail(f"{label} enthält keine gepinnten Pakete")
    return pins


def parse_runtime_input(path: Path) -> dict[str, str]:
    pins = parse_pinned_input_file(path, label="Runtime-Input")
    if pins.get("mcp") != "1.27.2":
        fail("runtime.in muss mcp==1.27.2 enthalten")
    return pins


def parse_pinned_lock_file(path: Path, *, label: str = "Pinned-Lockfile") -> dict[str, str]:
    require_file(path, label)
    locked: dict[str, str] = {}
    current_name: str | None = None
    current_requirement: str | None = None
    current_version: str | None = None
    hashes = 0
    continuation_open = False

    def close_block() -> None:
        nonlocal current_name, current_requirement, current_version, hashes, continuation_open
        if current_name is None:
            return
        if hashes == 0:
            fail(f"Runtime-Lockblock ohne SHA-256-Hashes: {current_requirement}")
        if continuation_open:
            fail(f"Runtime-Lockblock endet mit offener Fortsetzung: {current_requirement}")
        if current_name in locked:
            fail(f"Doppeltes Paket im Runtime-Lock: {current_name}")
        assert current_version is not None
        locked[current_name] = current_version
        current_name = None
        current_requirement = None
        current_version = None
        hashes = 0
        continuation_open = False

    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if raw[:1].isspace():
            if current_name is None:
                fail(f"Fortsetzungszeile ohne Requirement: {raw!r}")
            if stripped.startswith("#"):
                continue
            if not continuation_open:
                fail(f"Hashzeile ohne offene Requirement-Fortsetzung: {stripped}")
            if not HASH_RE.match(stripped):
                fail(f"Nicht erlaubte Fortsetzungsoption im Lock: {stripped}")
            hashes += 1
            continuation_open = stripped.endswith("\\")
            continue
        close_block()
        if stripped.startswith(("-e", "--", "-c", "-r")) or "://" in stripped or stripped.startswith("git+"):
            fail(f"Nicht erlaubte Runtime-Lock-Anforderung: {stripped}")
        if not stripped.endswith("\\"):
            fail(f"Lock-Requirement benötigt eine Hash-Fortsetzung: {stripped}")
        current_name, current_version = parse_pinned_requirement(
            stripped,
            allow_continuation=True,
        )
        current_requirement = stripped
        continuation_open = True
    close_block()

    if not locked:
        fail(f"{label} enthält keine Anforderungen")
    return locked


def parse_runtime_lock(path: Path) -> dict[str, str]:
    locked = parse_pinned_lock_file(path, label="Runtime-Lockfile")
    if locked.get("mcp") != "1.27.2":
        fail("Runtime-Lock muss mcp==1.27.2 enthalten")
    return locked


@dataclass(frozen=True)
class RuntimeSource:
    module: str
    source: Path

    def to_manifest(self) -> dict[str, str]:
        return {"module": self.module, "source": self.source.as_posix()}


@dataclass(frozen=True)
class RuntimeAsset:
    source: Path
    destination: Path

    def to_manifest(self) -> dict[str, str]:
        return {
            "source": self.source.as_posix(),
            "destination": self.destination.as_posix(),
        }


@dataclass(frozen=True)
class RuntimeContract:
    schema_version: int
    mode: str
    expected_tools: tuple[str, ...]
    source: Path
    module: str
    supporting_sources: tuple[RuntimeSource, ...] = ()
    runtime_assets: tuple[RuntimeAsset, ...] = ()

    @property
    def sources(self) -> tuple[RuntimeSource, ...]:
        return (
            RuntimeSource(module=self.module, source=self.source),
            *self.supporting_sources,
        )

    def to_manifest(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "expected_tools": list(self.expected_tools),
            "source": self.source.as_posix(),
            "module": self.module,
        }
        if self.schema_version >= 2:
            result["supporting_sources"] = [
                item.to_manifest() for item in self.supporting_sources
            ]
        if self.schema_version >= 3:
            result["runtime_assets"] = [
                item.to_manifest() for item in self.runtime_assets
            ]
        return result

    def command_argv(self, release_path: Path, python_exe: Path) -> list[str]:
        return [str(python_exe), "-m", self.module]

    def describe(self) -> str:
        return f"python -m {self.module}"


def _relative_path(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{label} muss ein repository-relativer Pfad sein: {value}")
    return path


def load_contract_bytes(data: bytes) -> RuntimeContract:
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"Runtime-Entry-Point-Contract ist ungültig: {exc}")
    if not isinstance(raw, dict):
        fail("Runtime-Entry-Point-Contract ist kein Objekt")
    schema_version = raw.get("schema_version")
    if schema_version not in {1, 2, 3}:
        fail("Runtime-Entry-Point-Contract benötigt schema_version 1, 2 oder 3")
    mode = raw.get("mode")
    if mode != "module":
        fail(f"Nicht unterstützter Entry-Point-Modus: {mode!r}")
    tools = raw.get("expected_tools")
    if not isinstance(tools, list) or not tools or not all(isinstance(item, str) and item for item in tools):
        fail("Runtime-Entry-Point-Contract benötigt expected_tools als nichtleere Stringliste")
    source = _relative_path(str(raw.get("source", "")), "source")
    if source.as_posix() == ".":
        fail("Runtime-Entry-Point-Contract benötigt source")
    module = raw.get("module")
    if not isinstance(module, str) or not MODULE_RE.fullmatch(module):
        fail(f"Ungültiges Modul im Runtime-Entry-Point-Contract: {module!r}")
    raw_supporting = raw.get("supporting_sources", [])
    if schema_version == 1 and raw_supporting:
        fail("supporting_sources benötigt schema_version 2")
    if not isinstance(raw_supporting, list):
        fail("supporting_sources muss eine Liste sein")
    supporting: list[RuntimeSource] = []
    seen_modules = {module}
    seen_paths = {source}
    for index, item in enumerate(raw_supporting):
        if not isinstance(item, dict) or set(item) != {"module", "source"}:
            fail(f"supporting_sources[{index}] ist ungültig")
        supporting_module = item.get("module")
        if not isinstance(supporting_module, str) or not MODULE_RE.fullmatch(supporting_module):
            fail(f"Ungültiges supporting_sources-Modul: {supporting_module!r}")
        supporting_path = _relative_path(str(item.get("source", "")), f"supporting_sources[{index}].source")
        if supporting_path.as_posix() == ".":
            fail(f"supporting_sources[{index}] benötigt source")
        if supporting_module in seen_modules or supporting_path in seen_paths:
            fail("Doppeltes Runtime-Modul oder doppelter Runtime-Quellpfad")
        seen_modules.add(supporting_module)
        seen_paths.add(supporting_path)
        supporting.append(RuntimeSource(module=supporting_module, source=supporting_path))

    raw_assets = raw.get("runtime_assets", [])
    if schema_version < 3 and raw_assets:
        fail("runtime_assets benötigt schema_version 3")
    if not isinstance(raw_assets, list):
        fail("runtime_assets muss eine Liste sein")
    runtime_assets: list[RuntimeAsset] = []
    seen_asset_sources: set[Path] = set()
    seen_asset_destinations: set[Path] = set()
    for index, item in enumerate(raw_assets):
        if not isinstance(item, dict) or set(item) != {"source", "destination"}:
            fail(f"runtime_assets[{index}] ist ungültig")
        asset_source = _relative_path(
            str(item.get("source", "")), f"runtime_assets[{index}].source"
        )
        asset_destination = _relative_path(
            str(item.get("destination", "")),
            f"runtime_assets[{index}].destination",
        )
        if asset_source.as_posix() == "." or asset_destination.as_posix() == ".":
            fail(f"runtime_assets[{index}] benötigt source und destination")
        if asset_source.as_posix() in RESERVED_SNAPSHOT_INPUT_PATHS:
            fail(f"runtime_assets[{index}] verwendet einen reservierten Snapshot-Quellpfad")
        if asset_source in seen_paths or asset_source in seen_asset_sources:
            fail("Doppelter Runtime-Quellpfad")
        if asset_destination in seen_asset_destinations:
            fail("Doppeltes Runtime-Asset-Ziel")
        if any(
            asset_destination in existing.parents or existing in asset_destination.parents
            for existing in seen_asset_destinations
        ):
            fail("Überlappende Runtime-Asset-Ziele")
        if asset_destination.parts[0] in {".venv", "inputs"} or asset_destination.as_posix() in {
            MANIFEST_NAME,
            INCOMPLETE_MARKER,
        }:
            fail(f"runtime_assets[{index}] verwendet ein reserviertes Ziel")
        seen_asset_sources.add(asset_source)
        seen_asset_destinations.add(asset_destination)
        runtime_assets.append(
            RuntimeAsset(source=asset_source, destination=asset_destination)
        )

    return RuntimeContract(
        schema_version=schema_version,
        mode="module",
        module=module,
        source=source,
        expected_tools=tuple(tools),
        supporting_sources=tuple(supporting),
        runtime_assets=tuple(runtime_assets),
    )


def load_contract(path: Path) -> RuntimeContract:
    require_file(path, "Runtime-Entry-Point-Contract")
    return load_contract_bytes(path.read_bytes())


@dataclass(frozen=True)
class Snapshot:
    repo_head: str
    dirty: bool
    contract: RuntimeContract
    contract_bytes: bytes
    runtime_input_bytes: bytes
    runtime_lock_bytes: bytes
    source_bytes: bytes
    supporting_source_bytes: dict[str, bytes] = field(default_factory=dict)
    runtime_asset_bytes: dict[str, bytes] = field(default_factory=dict)

    @property
    def contract_sha256(self) -> str:
        return sha256_bytes(self.contract_bytes)

    @property
    def runtime_input_sha256(self) -> str:
        return sha256_bytes(self.runtime_input_bytes)

    @property
    def runtime_lock_sha256(self) -> str:
        return sha256_bytes(self.runtime_lock_bytes)

    @property
    def source_sha256(self) -> str:
        return sha256_bytes(self.source_bytes)

    @property
    def source_sha256s(self) -> dict[str, str]:
        values = {self.contract.module: self.source_sha256}
        values.update(
            {module: sha256_bytes(data) for module, data in self.supporting_source_bytes.items()}
        )
        return dict(sorted(values.items()))

    @property
    def runtime_asset_sha256s(self) -> dict[str, str]:
        return dict(
            sorted(
                (destination, sha256_bytes(data))
                for destination, data in self.runtime_asset_bytes.items()
            )
        )

    @property
    def source_set_sha256(self) -> str:
        value: Any = self.source_sha256s
        if self.runtime_asset_sha256s:
            value = {
                "runtime_assets": self.runtime_asset_sha256s,
                "sources": self.source_sha256s,
            }
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return sha256_bytes(encoded)


def git_head(repo: Path) -> str:
    result = run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture=True,
        timeout=TIMEOUTS["git"],
    )
    return result.stdout.strip()


def repo_dirty(repo: Path) -> bool:
    result = run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture=True,
        timeout=TIMEOUTS["git"],
    )
    return bool(result.stdout.strip())


def require_clean_repo(repo: Path) -> str:
    if repo_dirty(repo):
        fail("Repository enthält uncommittete Änderungen.")
    return git_head(repo)


def git_show(repo: Path, head: str, path: Path) -> bytes:
    return run_bytes(
        ["git", "show", f"{head}:{path.as_posix()}"],
        cwd=repo,
        timeout=TIMEOUTS["git"],
    )


def snapshot_from_git(repo: Path) -> Snapshot:
    repo_head = require_clean_repo(repo)
    contract_bytes = git_show(repo, repo_head, ENTRYPOINT_CONTRACT_RELATIVE)
    contract = load_contract_bytes(contract_bytes)
    return Snapshot(
        repo_head=repo_head,
        dirty=False,
        contract=contract,
        contract_bytes=contract_bytes,
        runtime_input_bytes=git_show(repo, repo_head, RUNTIME_INPUT_RELATIVE),
        runtime_lock_bytes=git_show(repo, repo_head, RUNTIME_LOCK_RELATIVE),
        source_bytes=git_show(repo, repo_head, contract.source),
        supporting_source_bytes={item.module: git_show(repo, repo_head, item.source) for item in contract.supporting_sources},
        runtime_asset_bytes={
            item.destination.as_posix(): git_show(repo, repo_head, item.source)
            for item in contract.runtime_assets
        },
    )


def snapshot_from_worktree(repo: Path) -> Snapshot:
    repo_head = git_head(repo)
    dirty = repo_dirty(repo)
    contract_path = repo / ENTRYPOINT_CONTRACT_RELATIVE
    contract_bytes = contract_path.read_bytes()
    contract = load_contract_bytes(contract_bytes)
    return Snapshot(
        repo_head=repo_head,
        dirty=dirty,
        contract=contract,
        contract_bytes=contract_bytes,
        runtime_input_bytes=(repo / RUNTIME_INPUT_RELATIVE).read_bytes(),
        runtime_lock_bytes=(repo / RUNTIME_LOCK_RELATIVE).read_bytes(),
        source_bytes=(repo / contract.source).read_bytes(),
        supporting_source_bytes={
            item.module: (repo / item.source).read_bytes()
            for item in contract.supporting_sources
        },
        runtime_asset_bytes={
            item.destination.as_posix(): (repo / item.source).read_bytes()
            for item in contract.runtime_assets
        },
    )


@contextmanager
def deployment_lock(
    lock_path: Path,
    *,
    state_root: Path = DEFAULT_STATE_ROOT,
) -> Iterator[None]:
    if state_root.is_symlink():
        fail(f"Deployment-State-Root darf kein Symlink sein: {state_root}")
    try:
        state_root_real = state_root.expanduser().resolve(strict=True)
    except OSError as exc:
        fail(f"Deployment-State-Root ist nicht validierbar: {state_root}")
        raise AssertionError from exc
    root_stat = state_root_real.stat()
    if not statmod.S_ISDIR(root_stat.st_mode):
        fail(f"Deployment-State-Root ist kein Verzeichnis: {state_root_real}")
    if root_stat.st_uid != os.getuid():
        fail("Deployment-State-Root gehört nicht dem aktuellen Benutzer")

    safe_lock = normalize_managed_path(lock_path, allowed_root=state_root_real)
    if safe_lock.parent != state_root_real:
        fail("Deployment-Lock muss direkt im Grabowski-State-Root liegen")
    if safe_lock.is_symlink():
        fail(f"Deployment-Lock darf kein Symlink sein: {safe_lock}")

    dir_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        dir_flags |= os.O_DIRECTORY
    dir_fd = os.open(state_root_real, dir_flags)
    fd: int | None = None
    try:
        flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(safe_lock.name, flags, 0o600, dir_fd=dir_fd)
        except OSError as exc:
            fail(
                "Deployment-Lock konnte nicht sicher geöffnet werden",
                phase="deployment-lock-open",
                details={"error_type": type(exc).__name__},
            )
            raise AssertionError from exc

        info = os.fstat(fd)
        if not statmod.S_ISREG(info.st_mode):
            fail("Deployment-Lock ist keine reguläre Datei")
        if info.st_uid != os.getuid():
            fail("Deployment-Lock gehört nicht dem aktuellen Benutzer")
        if info.st_nlink != 1:
            fail("Deployment-Lock darf keine Hardlinks besitzen")
        os.fchmod(fd, 0o600)
        verified = os.fstat(fd)
        if statmod.S_IMODE(verified.st_mode) != 0o600:
            fail("Deployment-Lock hat nicht den erwarteten Modus 0600")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            fail(f"Ein anderes Deployment hält bereits den Lock: {safe_lock}")
            raise AssertionError from exc

        linked = os.stat(safe_lock.name, dir_fd=dir_fd, follow_symlinks=False)
        locked = os.fstat(fd)
        if (
            not statmod.S_ISREG(linked.st_mode)
            or linked.st_dev != locked.st_dev
            or linked.st_ino != locked.st_ino
            or linked.st_nlink != 1
        ):
            fail("Deployment-Lock-Verzeichniseintrag wurde ausgetauscht")

        payload = (
            json.dumps(
                {"pid": os.getpid(), "acquired_at_unix": int(time.time())},
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, payload)
        os.fsync(fd)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(dir_fd)


def releases_root_for(runtime: Path) -> Path:
    releases_root = runtime.parent / RELEASES_DIR_NAME
    if releases_root.parent != runtime.parent:
        fail("Releases-Root besitzt nicht denselben Parent wie Runtime")
    if releases_root.is_symlink():
        fail(f"Releases-Root darf kein Symlink sein: {releases_root}")
    if releases_root.exists() and not releases_root.is_dir():
        fail(f"Releases-Root ist kein Verzeichnis: {releases_root}")
    return releases_root


def release_id_base(snapshot: Snapshot) -> str:
    return (
        f"{snapshot.repo_head[:12]}"
        f"-srcset{snapshot.source_set_sha256[:12]}"
        f"-lock{snapshot.runtime_lock_sha256[:12]}"
        f"-contract{snapshot.contract_sha256[:12]}"
    )


def allocate_release_path(releases_root: Path, snapshot: Snapshot) -> tuple[str, Path]:
    releases_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    base = release_id_base(snapshot)
    for attempt in range(1000):
        release_id = base if attempt == 0 else f"{base}-attempt{attempt}"
        release_path = releases_root / release_id
        try:
            release_path.mkdir(mode=0o700)
        except FileExistsError:
            continue
        return release_id, release_path
    fail(f"Keine freie Release-ID für {base}")


def write_snapshot_inputs(snapshot: Snapshot, release_path: Path) -> dict[str, Any]:
    inputs = release_path / "inputs"
    source_path = inputs / snapshot.contract.source
    source_path.parent.mkdir(parents=True, exist_ok=True)
    inputs.mkdir(parents=True, exist_ok=True)
    files = {
        "runtime_entrypoint": inputs / ENTRYPOINT_CONTRACT_RELATIVE.name,
        "runtime_input": inputs / RUNTIME_INPUT_RELATIVE.name,
        "runtime_lock": inputs / RUNTIME_LOCK_RELATIVE.name,
        "source": source_path,
    }
    files["runtime_entrypoint"].write_bytes(snapshot.contract_bytes)
    files["runtime_input"].write_bytes(snapshot.runtime_input_bytes)
    files["runtime_lock"].write_bytes(snapshot.runtime_lock_bytes)
    files["source"].write_bytes(snapshot.source_bytes)
    supporting_paths = {}
    supporting_by_module = {item.module: item for item in snapshot.contract.supporting_sources}
    for module, data in snapshot.supporting_source_bytes.items():
        item = supporting_by_module[module]
        target = inputs / item.source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        supporting_paths[module] = str(target)
    runtime_asset_paths: dict[str, str] = {}
    assets_by_destination = {
        item.destination.as_posix(): item for item in snapshot.contract.runtime_assets
    }
    if set(snapshot.runtime_asset_bytes) != set(assets_by_destination):
        fail("Runtime-Asset-Snapshot stimmt nicht mit dem Runtime-Vertrag überein")
    for destination, data in snapshot.runtime_asset_bytes.items():
        item = assets_by_destination[destination]
        target = inputs / item.source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        runtime_asset_paths[destination] = str(target)
    result = {key: str(path) for key, path in files.items()}
    result["supporting_sources"] = dict(sorted(supporting_paths.items()))
    result["runtime_assets"] = dict(sorted(runtime_asset_paths.items()))
    return result


def active_virtualenv_prefix() -> Path | None:
    prefix = Path(sys.prefix).resolve(strict=False)
    base_prefix = Path(sys.base_prefix).resolve(strict=False)
    if prefix == base_prefix:
        return None
    return prefix


def runtime_venv_builder_python() -> Path:
    candidates = [
        Path(value)
        for value in (
            getattr(sys, "_base_executable", ""),
            sys.executable,
        )
        if isinstance(value, str) and value
    ]
    active_prefix = active_virtualenv_prefix()
    rejected: list[str] = []
    for candidate in candidates:
        if not candidate.is_absolute():
            rejected.append(str(candidate))
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            rejected.append(str(candidate))
            continue
        if active_prefix is not None and path_is_within(resolved, active_prefix):
            rejected.append(str(resolved))
            continue
        return resolved
    fail(
        "Kein sicherer Basis-Python für Runtime-Venv-Erzeugung gefunden.",
        phase="venv-builder-python",
        details={"rejected_candidates": rejected},
    )


def pip_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_INDEX_URL",
        "PIP_TRUSTED_HOST",
    ):
        env.pop(key, None)
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_NO_INPUT"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def python_json(python_exe: Path, code: str) -> Any:
    result = run(
        [str(python_exe), "-c", code],
        capture=True,
        timeout=TIMEOUTS["python"],
        env=pip_env(),
    )
    return json.loads(result.stdout)


def site_packages_path(python_exe: Path) -> Path:
    value = python_json(
        python_exe,
        "import json,sysconfig; print(json.dumps(sysconfig.get_paths()['purelib']))",
    )
    return Path(value)


def installed_distributions(python_exe: Path) -> dict[str, str]:
    return python_json(
        python_exe,
        (
            "import importlib.metadata,json; "
            "print(json.dumps({d.metadata['Name']: d.version "
            "for d in importlib.metadata.distributions() if d.metadata.get('Name')}, "
            "sort_keys=True))"
        ),
    )


def verify_installed_distributions(python_exe: Path, lock_path: Path) -> None:
    locked = parse_runtime_lock(lock_path)
    installed_raw = installed_distributions(python_exe)
    installed = {
        normalize_package_name(name): version
        for name, version in installed_raw.items()
    }
    allowed = set(locked) | ALLOWED_VENV_BASE_DISTS
    unexpected = sorted(set(installed) - allowed)
    if unexpected:
        fail("Unerwartete installierte Distributionen: " + ", ".join(unexpected))
    missing = sorted(set(locked) - set(installed))
    if missing:
        fail("Runtime-Lockpakete fehlen in der Venv: " + ", ".join(missing))
    mismatched = sorted(
        f"{name}=={installed[name]} != {locked[name]}"
        for name in locked
        if installed.get(name) != locked[name]
    )
    if mismatched:
        fail("Installierte Versionen weichen vom Lock ab: " + ", ".join(mismatched))


def module_destination(
    site_packages: Path,
    module: str,
    *,
    create_packages: bool = True,
) -> Path:
    parts = module.split(".")
    if len(parts) == 1:
        return site_packages / f"{parts[0]}.py"
    package_root = site_packages
    for part in parts[:-1]:
        package_root = package_root / part
        if create_packages:
            package_root.mkdir(exist_ok=True)
        init = package_root / "__init__.py"
        if create_packages and not init.exists():
            init.write_text("", encoding="utf-8")
    return package_root / f"{parts[-1]}.py"


def install_runtime_sources(
    snapshot: Snapshot,
    release_path: Path,
    python_exe: Path,
) -> dict[str, Path]:
    site_packages = site_packages_path(python_exe)
    payloads = {snapshot.contract.module: snapshot.source_bytes}
    payloads.update(snapshot.supporting_source_bytes)
    installed: dict[str, Path] = {}
    for module, data in payloads.items():
        destination = module_destination(site_packages, module)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        run(
            [str(python_exe), "-m", "py_compile", str(destination)],
            timeout=TIMEOUTS["python"],
            env=pip_env(),
        )
        installed[module] = destination
    return installed


def install_runtime_assets(
    snapshot: Snapshot,
    release_path: Path,
) -> dict[str, Path]:
    expected = {
        item.destination.as_posix(): item for item in snapshot.contract.runtime_assets
    }
    if set(snapshot.runtime_asset_bytes) != set(expected):
        fail("Runtime-Asset-Snapshot stimmt nicht mit dem Runtime-Vertrag überein")
    installed: dict[str, Path] = {}
    for destination, item in sorted(expected.items()):
        target = release_path / item.destination
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            fail(f"Runtime-Asset-Ziel existiert bereits: {target}")
        target.write_bytes(snapshot.runtime_asset_bytes[destination])
        target.chmod(0o600)
        if sha256(target) != snapshot.runtime_asset_sha256s[destination]:
            fail(f"Runtime-Asset konnte nicht hashgetreu installiert werden: {destination}")
        installed[destination] = target
    return installed


def is_within(path: Path, root: Path) -> bool:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def import_module_path(python_exe: Path, module: str) -> Path:
    code = (
        "import importlib.util,json; "
        f"spec=importlib.util.find_spec({module!r}); "
        "print(json.dumps(None if spec is None else spec.origin))"
    )
    origin = python_json(python_exe, code)
    if not isinstance(origin, str):
        fail(f"Modul {module!r} ist in der Release-Venv nicht importierbar")
    return Path(origin)


def verify_entrypoint_importable(release_path: Path, python_exe: Path, contract: RuntimeContract) -> Path:
    module_path = import_module_path(python_exe, contract.module)
    if not (
        is_within(module_path, release_path / ".venv")
        or is_within(module_path, release_path)
    ):
        fail(
            f"Modul {contract.module!r} liegt außerhalb des Releases: {module_path}"
        )
    return module_path


def send_json(proc: subprocess.Popen[bytes], payload: dict[str, Any]) -> None:
    if proc.stdin is None:
        fail("MCP-Probe besitzt kein stdin.")
    raw = (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    proc.stdin.write(raw)
    proc.stdin.flush()


def wait_for_id(
    proc: subprocess.Popen[bytes],
    wanted_id: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    if proc.stdout is None:
        fail("MCP-Probe besitzt kein stdout.")

    deadline = time.monotonic() + timeout_seconds
    seen: list[str] = []

    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([proc.stdout], [], [], remaining)
        if not ready:
            break

        line = proc.stdout.readline()
        if not line:
            break

        decoded = line.decode("utf-8", errors="replace").rstrip("\n")
        seen.append(decoded)

        try:
            message = json.loads(decoded)
        except json.JSONDecodeError as exc:
            fail(f"MCP-Server schrieb Nicht-JSON auf stdout: {decoded!r}")
            raise AssertionError from exc

        if message.get("id") == wanted_id:
            return message

    fail(
        f"Keine MCP-Antwort auf JSON-RPC-ID {wanted_id}; "
        f"empfangen: {seen!r}"
    )


def stop_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def _valid_agent_instructions_identity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {
            "schema_version",
            "version",
            "sha256",
            "bytes",
            "max_bytes",
        }
        and value.get("schema_version") == AGENT_INSTRUCTIONS_SCHEMA_VERSION
        and isinstance(value.get("version"), str)
        and AGENT_INSTRUCTIONS_HEADER_RE.fullmatch(
            "Grabowski agent-facing contract "
            f"{value.get('version')} "
            f"(schema {value.get('schema_version')})."
        )
        is not None
        and _is_lower_hex(value.get("sha256"), 64)
        and isinstance(value.get("bytes"), int)
        and not isinstance(value.get("bytes"), bool)
        and 0 < value["bytes"] <= AGENT_INSTRUCTIONS_MAX_BYTES
        and value.get("max_bytes") == AGENT_INSTRUCTIONS_MAX_BYTES
    )


def agent_instructions_identity(instructions: Any) -> dict[str, Any]:
    if not isinstance(instructions, str) or not instructions:
        fail("MCP initialize enthält keine Agentenanweisungen")
    encoded = instructions.encode("utf-8")
    if len(encoded) > AGENT_INSTRUCTIONS_MAX_BYTES:
        fail(
            "MCP-Agentenanweisungen überschreiten die Größenbegrenzung: "
            f"{len(encoded)} > {AGENT_INSTRUCTIONS_MAX_BYTES}"
        )
    first_line = instructions.splitlines()[0]
    match = AGENT_INSTRUCTIONS_HEADER_RE.fullmatch(first_line)
    if match is None:
        fail("MCP-Agentenanweisungen besitzen keinen versionierten Vertragskopf")
    schema_version = int(match.group("schema"))
    if schema_version != AGENT_INSTRUCTIONS_SCHEMA_VERSION:
        fail(
            "MCP-Agentenanweisungen besitzen eine nicht unterstützte Schema-Version: "
            f"{schema_version}"
        )
    identity = {
        "schema_version": schema_version,
        "version": match.group("version"),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
        "max_bytes": AGENT_INSTRUCTIONS_MAX_BYTES,
    }
    if not _valid_agent_instructions_identity(identity):
        fail("MCP-Agentenanweisungsidentität ist ungültig")
    return identity


@dataclass(frozen=True)
class MCPProbeResult:
    protocol_version: str
    agent_instructions: dict[str, Any]


def probe_mcp(
    release_path: Path,
    python_exe: Path,
    contract: RuntimeContract,
) -> MCPProbeResult:
    last_error: Exception | None = None

    for version in MCP_PROTOCOL_VERSIONS:
        with tempfile.TemporaryFile() as stderr_file:
            proc = subprocess.Popen(
                contract.command_argv(release_path, python_exe),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                cwd=str(release_path),
                bufsize=0,
                env=pip_env(),
            )

            try:
                send_json(
                    proc,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": version,
                            "capabilities": {},
                            "clientInfo": {
                                "name": "grabowski-deploy-probe",
                                "version": "1.0",
                            },
                        },
                    },
                )
                initialized = wait_for_id(proc, 1, TIMEOUTS["mcp_probe"])
                if "error" in initialized:
                    raise DeployError(
                        f"initialize({version}) meldete {initialized['error']}"
                    )

                initialize_result = initialized.get("result", {})
                negotiated = initialize_result.get("protocolVersion")
                if not isinstance(negotiated, str):
                    raise DeployError(
                        f"Ungültige initialize-Antwort: {initialized!r}"
                    )
                instructions = agent_instructions_identity(
                    initialize_result.get("instructions")
                )

                send_json(
                    proc,
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    },
                )
                send_json(
                    proc,
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/list",
                        "params": {},
                    },
                )
                listed = wait_for_id(proc, 2, TIMEOUTS["mcp_probe"])
                if "error" in listed:
                    raise DeployError(
                        f"tools/list meldete {listed['error']}"
                    )

                tools = listed.get("result", {}).get("tools")
                if not isinstance(tools, list):
                    raise DeployError(
                        f"tools/list enthält keine Liste: {listed!r}"
                    )

                names = {
                    item.get("name")
                    for item in tools
                    if isinstance(item, dict)
                }
                missing = sorted(set(contract.expected_tools) - names)
                if missing:
                    raise DeployError(
                        "MCP-Probe vermisst Werkzeuge: "
                        + ", ".join(missing)
                    )

                stop_process(proc)
                return MCPProbeResult(
                    protocol_version=negotiated,
                    agent_instructions=instructions,
                )

            except Exception as exc:
                last_error = exc
                stop_process(proc)
                stderr_file.seek(0)
                stderr_tail = stderr_file.read().decode(
                    "utf-8",
                    errors="replace",
                )
                if stderr_tail:
                    print(
                        f"MCP-Probe stderr ({version}):\n{redact_text(stderr_tail)}",
                        file=sys.stderr,
                    )

    fail(f"MCP-Probe fehlgeschlagen: {last_error}")


def python_provenance(python_exe: Path) -> dict[str, str]:
    data = python_json(
        python_exe,
        (
            "import json,platform,sys; "
            "print(json.dumps({"
            "'python_version': platform.python_version(),"
            "'python_implementation': platform.python_implementation(),"
            "'platform': platform.platform(),"
            "'executable': sys.executable"
            "}, sort_keys=True))"
        ),
    )
    pip = run(
        [str(python_exe), "-m", "pip", "--version"],
        capture=True,
        timeout=TIMEOUTS["python"],
        env=pip_env(),
    ).stdout.strip()
    data["pip_version"] = pip.split(" from ", 1)[0]
    return data


@dataclass
class BuildResult:
    release_id: str
    release_path: Path
    python_exe: Path
    entrypoint_path: Path
    protocol_version: str
    provenance: dict[str, str]
    agent_instructions: dict[str, Any]


def mark_incomplete(release_path: Path, phase: str, exc: BaseException) -> None:
    marker = {
        "schema_version": 1,
        "completion_status": "incomplete",
        "phase": phase,
        "error": safe_error_summary(exc),
        "created_at_unix": int(time.time()),
    }
    try:
        (release_path / INCOMPLETE_MARKER).write_text(
            json.dumps(marker, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def build_release(
    snapshot: Snapshot,
    releases_root: Path,
    stable_runtime: Path,
) -> BuildResult:
    release_id, release_path = allocate_release_path(releases_root, snapshot)
    phase = "inputs"
    try:
        input_paths = write_snapshot_inputs(snapshot, release_path)
        runtime_input = release_path / "inputs" / RUNTIME_INPUT_RELATIVE.name
        runtime_lock = release_path / "inputs" / RUNTIME_LOCK_RELATIVE.name
        direct_pins = parse_runtime_input(runtime_input)
        locked_pins = parse_runtime_lock(runtime_lock)
        missing_direct = sorted(set(direct_pins) - set(locked_pins))
        if missing_direct:
            fail("Direkte Pins fehlen im Lock: " + ", ".join(missing_direct))
        mismatched_direct = sorted(
            f"{name}=={direct_pins[name]} != {locked_pins[name]}"
            for name in direct_pins
            if name in locked_pins and direct_pins[name] != locked_pins[name]
        )
        if mismatched_direct:
            fail(
                "Direkte Pins weichen vom Lock ab: "
                + ", ".join(mismatched_direct)
            )

        phase = "venv"
        venv = release_path / ".venv"
        run(
            [str(runtime_venv_builder_python()), "-m", "venv", str(venv)],
            timeout=TIMEOUTS["python"],
            env=pip_env(),
        )
        venv_python = venv / "bin" / "python"

        phase = "package-install"
        run(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--isolated",
                "--disable-pip-version-check",
                "--no-input",
                "--require-hashes",
                "--no-deps",
                "--only-binary=:all:",
                "--index-url",
                "https://pypi.org/simple",
                "-r",
                str(runtime_lock),
            ],
            timeout=TIMEOUTS["package_install"],
            env=pip_env(),
        )
        run(
            [str(venv_python), "-m", "pip", "check"],
            timeout=TIMEOUTS["python"],
            env=pip_env(),
        )
        verify_installed_distributions(venv_python, runtime_lock)

        phase = "runtime-source"
        installed_modules = install_runtime_sources(
            snapshot, release_path, venv_python
        )
        module_paths: dict[str, Path] = {}
        for item in snapshot.contract.sources:
            imported = import_module_path(venv_python, item.module)
            expected = installed_modules[item.module]
            if imported.resolve() != expected.resolve():
                fail(
                    "Installiertes Runtime-Modul weicht von der "
                    f"Importauflösung ab: {item.module}"
                )
            module_paths[item.module] = imported
        entrypoint_path = module_paths[snapshot.contract.module]

        phase = "runtime-assets"
        runtime_asset_paths = install_runtime_assets(snapshot, release_path)

        phase = "mcp-probe"
        probe = probe_mcp(release_path, venv_python, snapshot.contract)
        provenance = python_provenance(venv_python)

        phase = "manifest"
        write_manifest(
            release_path,
            release_id=release_id,
            snapshot=snapshot,
            stable_runtime=stable_runtime,
            input_paths=input_paths,
            entrypoint_path=entrypoint_path,
            module_paths=module_paths,
            runtime_asset_paths=runtime_asset_paths,
            protocol_version=probe.protocol_version,
            agent_instructions=probe.agent_instructions,
            provenance=provenance,
        )
        return BuildResult(
            release_id=release_id,
            release_path=release_path,
            python_exe=venv_python,
            entrypoint_path=entrypoint_path,
            protocol_version=probe.protocol_version,
            provenance=provenance,
            agent_instructions=probe.agent_instructions,
        )
    except Exception as exc:
        mark_incomplete(release_path, phase, exc)
        raise


def _atomic_write_private_json(path: Path, value: dict[str, Any]) -> None:
    parent = path.parent
    directory_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(parent, directory_flags)
    except OSError as exc:
        fail(f"Manifest-Verzeichnis ist nicht sicher verfügbar: {parent}")
        raise AssertionError from exc
    temporary_name = f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    descriptor = -1
    published = False
    try:
        parent_info = os.fstat(directory_fd)
        if (
            not statmod.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.getuid()
        ):
            fail("Manifest-Verzeichnis muss ein eigenes reales Verzeichnis sein")
        try:
            existing = os.stat(
                path.name, dir_fd=directory_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not statmod.S_ISREG(existing.st_mode)
            or existing.st_uid != os.getuid()
            or existing.st_nlink != 1
        ):
            fail("Deployment-Manifest-Ziel ist nicht sicher ersetzbar")

        payload = (
            json.dumps(value, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            temporary_name, flags, 0o600, dir_fd=directory_fd
        )
        created = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(created.st_mode)
            or created.st_uid != os.getuid()
            or created.st_nlink != 1
        ):
            fail("Temporäres Deployment-Manifest ist nicht sicher")
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                fail("Deployment-Manifest konnte nicht vollständig geschrieben werden")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        published = True
        os.fsync(directory_fd)
        verified = os.stat(
            path.name, dir_fd=directory_fd, follow_symlinks=False
        )
        if (
            not statmod.S_ISREG(verified.st_mode)
            or verified.st_uid != os.getuid()
            or verified.st_nlink != 1
            or statmod.S_IMODE(verified.st_mode) != 0o600
            or verified.st_size != len(payload)
        ):
            fail("Deployment-Manifest wurde nicht als private reguläre Datei publiziert")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def write_manifest(
    release_path: Path,
    *,
    release_id: str,
    snapshot: Snapshot,
    stable_runtime: Path,
    input_paths: dict[str, Any],
    entrypoint_path: Path,
    module_paths: dict[str, Path],
    runtime_asset_paths: dict[str, Path],
    protocol_version: str,
    agent_instructions: dict[str, Any],
    provenance: dict[str, str],
) -> None:
    if not _valid_agent_instructions_identity(agent_instructions):
        fail("Deployment-Manifest benötigt eine gültige Agentenanweisungsidentität")
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "release_id": release_id,
        "repo_head": snapshot.repo_head,
        "entrypoint_contract": snapshot.contract.to_manifest(),
        "entrypoint_contract_sha256": snapshot.contract_sha256,
        "agent_instructions": agent_instructions,
        "source_sha256": snapshot.source_sha256,
        "source_sha256s": snapshot.source_sha256s,
        "runtime_asset_sha256s": snapshot.runtime_asset_sha256s,
        "runtime_asset_paths": {
            destination: str(path)
            for destination, path in sorted(runtime_asset_paths.items())
        },
        "runtime_input_sha256": snapshot.runtime_input_sha256,
        "runtime_lock_sha256": snapshot.runtime_lock_sha256,
        "snapshot_paths": input_paths,
        "immutable_release_path": str(release_path),
        "expected_stable_runtime_path": str(stable_runtime),
        "release_python_path": str(release_path / ".venv/bin/python"),
        "entrypoint_path": str(entrypoint_path),
        "module_paths": {module: str(path) for module, path in sorted(module_paths.items())},
        "mcp_protocol_version": protocol_version,
        "created_at_unix": int(time.time()),
        "completion_status": "complete",
        **provenance,
    }
    path = release_path / MANIFEST_NAME
    _atomic_write_private_json(path, manifest)


def read_manifest(runtime_or_release: Path) -> dict[str, Any]:
    path = runtime_or_release / MANIFEST_NAME
    require_file(path, "Deployment-Manifest")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"Deployment-Manifest ist ungültig: {exc}")
    if not isinstance(data, dict):
        fail("Deployment-Manifest ist kein Objekt.")
    return data


def _is_lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in "0123456789abcdef" for char in value)
    )


def validate_manifest_schema(manifest: dict[str, Any]) -> list[str]:
    required = {
        "schema_version": int,
        "release_id": str,
        "repo_head": str,
        "entrypoint_contract": dict,
        "entrypoint_contract_sha256": str,
        "agent_instructions": dict,
        "source_sha256": str,
        "source_sha256s": dict,
        "runtime_asset_sha256s": dict,
        "runtime_asset_paths": dict,
        "runtime_input_sha256": str,
        "runtime_lock_sha256": str,
        "snapshot_paths": dict,
        "immutable_release_path": str,
        "expected_stable_runtime_path": str,
        "release_python_path": str,
        "entrypoint_path": str,
        "module_paths": dict,
        "platform": str,
        "python_version": str,
        "python_implementation": str,
        "mcp_protocol_version": str,
        "created_at_unix": int,
        "completion_status": str,
        "executable": str,
        "pip_version": str,
    }
    errors: list[str] = []
    for key, kind in required.items():
        value = manifest.get(key)
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            errors.append(key)
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        errors.append("schema_version")
    if manifest.get("completion_status") != "complete":
        errors.append("completion_status")
    if manifest.get("mcp_protocol_version") not in MCP_PROTOCOL_VERSIONS:
        errors.append("mcp_protocol_version")
    if not _is_lower_hex(manifest.get("repo_head"), 40):
        errors.append("repo_head")
    for key in (
        "entrypoint_contract_sha256",
        "source_sha256",
        "runtime_input_sha256",
        "runtime_lock_sha256",
    ):
        if not _is_lower_hex(manifest.get(key), 64):
            errors.append(key)
    if not _valid_agent_instructions_identity(manifest.get("agent_instructions")):
        errors.append("agent_instructions")

    contract = manifest.get("entrypoint_contract")
    modules: set[str] = set()
    main_module: str | None = None
    supporting_modules: set[str] = set()
    runtime_asset_destinations: set[str] = set()
    if not isinstance(contract, dict):
        errors.append("entrypoint_contract")
    else:
        schema_version = contract.get("schema_version")
        if schema_version not in {1, 2, 3} or contract.get("mode") != "module":
            errors.append("entrypoint_contract")
        main_module = contract.get("module")
        if not isinstance(main_module, str) or not MODULE_RE.fullmatch(main_module):
            errors.append("entrypoint_contract")
            main_module = None
        else:
            modules.add(main_module)
        if not isinstance(contract.get("source"), str):
            errors.append("entrypoint_contract")
        tools = contract.get("expected_tools")
        if (
            not isinstance(tools, list)
            or not tools
            or not all(isinstance(item, str) and item for item in tools)
            or len(set(tools)) != len(tools)
        ):
            errors.append("entrypoint_contract")
        seen_paths = {contract.get("source")}
        supporting = contract.get("supporting_sources", [])
        if schema_version == 1 and supporting:
            errors.append("entrypoint_contract")
        if not isinstance(supporting, list):
            errors.append("entrypoint_contract")
        else:
            for item in supporting:
                if not isinstance(item, dict) or set(item) != {"module", "source"}:
                    errors.append("entrypoint_contract")
                    continue
                module = item.get("module")
                source = item.get("source")
                if (
                    not isinstance(module, str)
                    or not MODULE_RE.fullmatch(module)
                    or module in modules
                    or not isinstance(source, str)
                    or source in seen_paths
                ):
                    errors.append("entrypoint_contract")
                    continue
                modules.add(module)
                supporting_modules.add(module)
                seen_paths.add(source)

        runtime_assets = contract.get("runtime_assets", [])
        if schema_version in {1, 2} and runtime_assets:
            errors.append("entrypoint_contract")
        if not isinstance(runtime_assets, list):
            errors.append("entrypoint_contract")
        else:
            seen_asset_sources: set[str] = set()
            for item in runtime_assets:
                if not isinstance(item, dict) or set(item) != {"source", "destination"}:
                    errors.append("entrypoint_contract")
                    continue
                asset_source = item.get("source")
                destination = item.get("destination")
                source_path = Path(asset_source) if isinstance(asset_source, str) else None
                destination_path = Path(destination) if isinstance(destination, str) else None
                if (
                    source_path is None
                    or destination_path is None
                    or source_path.is_absolute()
                    or destination_path.is_absolute()
                    or ".." in source_path.parts
                    or ".." in destination_path.parts
                    or source_path.as_posix() == "."
                    or destination_path.as_posix() == "."
                    or asset_source in seen_paths
                    or asset_source in seen_asset_sources
                    or source_path.as_posix() in RESERVED_SNAPSHOT_INPUT_PATHS
                    or destination in runtime_asset_destinations
                    or destination_path.parts[0] in {".venv", "inputs"}
                    or destination_path.as_posix() in {MANIFEST_NAME, INCOMPLETE_MARKER}
                ):
                    errors.append("entrypoint_contract")
                    continue
                if any(
                    destination_path in Path(existing).parents
                    or Path(existing) in destination_path.parents
                    for existing in runtime_asset_destinations
                ):
                    errors.append("entrypoint_contract")
                    continue
                seen_asset_sources.add(asset_source)
                runtime_asset_destinations.add(destination)

    source_hashes = manifest.get("source_sha256s")
    if (
        not isinstance(source_hashes, dict)
        or set(source_hashes) != modules
        or not all(
            isinstance(module, str) and _is_lower_hex(value, 64)
            for module, value in source_hashes.items()
        )
        or (main_module is not None and source_hashes.get(main_module) != manifest.get("source_sha256"))
    ):
        errors.append("source_sha256s")

    runtime_asset_hashes = manifest.get("runtime_asset_sha256s")
    if (
        not isinstance(runtime_asset_hashes, dict)
        or set(runtime_asset_hashes) != runtime_asset_destinations
        or not all(_is_lower_hex(value, 64) for value in runtime_asset_hashes.values())
    ):
        errors.append("runtime_asset_sha256s")

    runtime_asset_paths = manifest.get("runtime_asset_paths")
    if (
        not isinstance(runtime_asset_paths, dict)
        or set(runtime_asset_paths) != runtime_asset_destinations
        or not all(isinstance(value, str) and value for value in runtime_asset_paths.values())
    ):
        errors.append("runtime_asset_paths")

    module_paths = manifest.get("module_paths")
    if (
        not isinstance(module_paths, dict)
        or set(module_paths) != modules
        or not all(isinstance(value, str) and value for value in module_paths.values())
    ):
        errors.append("module_paths")

    snapshot_paths = manifest.get("snapshot_paths")
    if not isinstance(snapshot_paths, dict) or set(snapshot_paths) != {
        "runtime_entrypoint",
        "runtime_input",
        "runtime_lock",
        "source",
        "supporting_sources",
        "runtime_assets",
    }:
        errors.append("snapshot_paths")
    else:
        scalar_keys = ("runtime_entrypoint", "runtime_input", "runtime_lock", "source")
        supporting_paths = snapshot_paths.get("supporting_sources")
        runtime_asset_snapshot_paths = snapshot_paths.get("runtime_assets")
        if (
            not all(isinstance(snapshot_paths.get(key), str) for key in scalar_keys)
            or not isinstance(supporting_paths, dict)
            or set(supporting_paths) != supporting_modules
            or not all(isinstance(value, str) and value for value in supporting_paths.values())
            or not isinstance(runtime_asset_snapshot_paths, dict)
            or set(runtime_asset_snapshot_paths) != runtime_asset_destinations
            or not all(
                isinstance(value, str) and value
                for value in runtime_asset_snapshot_paths.values()
            )
        ):
            errors.append("snapshot_paths")

    created = manifest.get("created_at_unix")
    if not isinstance(created, int) or isinstance(created, bool) or created <= 0:
        errors.append("created_at_unix")
    return sorted(set(errors))


def verify_manifest(
    runtime_or_release: Path,
    *,
    snapshot: Snapshot,
    stable_runtime: Path | None = None,
    expected_agent_instructions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = read_manifest(runtime_or_release)
    schema_errors = validate_manifest_schema(manifest)
    if schema_errors:
        fail("Deployment-Manifest ist nicht schema-valid: " + ", ".join(schema_errors))
    expected = {
        "repo_head": snapshot.repo_head,
        "source_sha256": snapshot.source_sha256,
        "source_sha256s": snapshot.source_sha256s,
        "runtime_asset_sha256s": snapshot.runtime_asset_sha256s,
        "runtime_input_sha256": snapshot.runtime_input_sha256,
        "runtime_lock_sha256": snapshot.runtime_lock_sha256,
        "entrypoint_contract_sha256": snapshot.contract_sha256,
        "entrypoint_contract": snapshot.contract.to_manifest(),
    }
    if expected_agent_instructions is not None:
        if not _valid_agent_instructions_identity(expected_agent_instructions):
            fail("Erwartete Agentenanweisungsidentität ist ungültig")
        expected["agent_instructions"] = expected_agent_instructions
    if stable_runtime is not None:
        expected["expected_stable_runtime_path"] = str(stable_runtime)
    for key, value in expected.items():
        if manifest.get(key) != value:
            fail(
                f"Manifest-Feld {key} weicht ab: "
                f"{manifest.get(key)!r} != {value!r}"
            )
    release_path = runtime_or_release.resolve(strict=True)
    if manifest.get("release_id") != release_path.name:
        fail("Manifest-Release-ID entspricht nicht dem Releaseverzeichnis")
    if Path(str(manifest.get("immutable_release_path"))).resolve(strict=True) != release_path:
        fail("Manifest-Releasepfad entspricht nicht dem realen Release")
    expected_asset_paths = {
        item.destination.as_posix(): str(release_path / item.destination)
        for item in snapshot.contract.runtime_assets
    }
    if manifest.get("runtime_asset_paths") != expected_asset_paths:
        fail("Manifest-Runtime-Asset-Pfade entsprechen nicht dem Release")
    release_python = release_path / ".venv/bin/python"
    if Path(str(manifest.get("release_python_path"))) != release_python:
        fail("Manifest-Release-Pythonpfad entspricht nicht dem Release")
    if Path(str(manifest.get("executable"))) != release_python:
        fail("Manifest-Executable entspricht nicht dem Release-Python")
    return manifest


def require_manifest_snapshot_path(
    manifest: dict[str, Any],
    key: str,
    expected: Path,
    release_path: Path,
) -> Path:
    raw_paths = manifest.get("snapshot_paths")
    if not isinstance(raw_paths, dict):
        fail("Deployment-Manifest enthält keine Snapshotpfade")
    value = raw_paths.get(key)
    if not isinstance(value, str):
        fail(f"Deployment-Manifest enthält keinen Snapshotpfad {key}")
    actual = Path(value)
    if actual != expected:
        fail(f"Snapshotpfad {key} weicht ab: {actual} != {expected}")
    require_file(actual, f"Snapshot {key}")
    try:
        actual.resolve(strict=True).relative_to(release_path.resolve(strict=True))
    except (OSError, ValueError) as exc:
        fail(f"Snapshotpfad {key} liegt außerhalb des Releases: {actual}")
        raise AssertionError from exc
    return actual


def verify_final_release_artifacts(
    release_path: Path,
    runtime: Path,
    contract: RuntimeContract,
    *,
    snapshot: Snapshot,
    manifest: dict[str, Any],
    process: dict[str, Any],
) -> None:
    if not runtime.is_symlink():
        fail("Finaler Runtimepfad ist kein Symlink")
    real_release = runtime.resolve(strict=True)
    if real_release != release_path.resolve(strict=True):
        fail(
            "Finaler Runtime-Symlink zeigt nicht mehr auf das ausgewählte Release: "
            f"{runtime} -> {real_release}"
        )
    manifest_path = real_release / MANIFEST_NAME
    require_file(manifest_path, "Deployment-Manifest")
    if Path(str(manifest.get("immutable_release_path"))) != real_release:
        fail("Manifest behauptet ein anderes immutable_release_path")

    input_root = real_release / "inputs"
    contract_path = require_manifest_snapshot_path(
        manifest,
        "runtime_entrypoint",
        input_root / ENTRYPOINT_CONTRACT_RELATIVE.name,
        real_release,
    )
    runtime_input_path = require_manifest_snapshot_path(
        manifest,
        "runtime_input",
        input_root / RUNTIME_INPUT_RELATIVE.name,
        real_release,
    )
    runtime_lock_path = require_manifest_snapshot_path(
        manifest,
        "runtime_lock",
        input_root / RUNTIME_LOCK_RELATIVE.name,
        real_release,
    )
    source_path = require_manifest_snapshot_path(
        manifest,
        "source",
        input_root / snapshot.contract.source,
        real_release,
    )

    checks = {
        contract_path: snapshot.contract_sha256,
        runtime_input_path: snapshot.runtime_input_sha256,
        runtime_lock_path: snapshot.runtime_lock_sha256,
        source_path: snapshot.source_sha256,
    }
    raw_snapshot_paths = manifest.get("snapshot_paths")
    supporting_paths = (
        raw_snapshot_paths.get("supporting_sources", {})
        if isinstance(raw_snapshot_paths, dict)
        else {}
    )
    for item in snapshot.contract.supporting_sources:
        expected_path = input_root / item.source
        if supporting_paths.get(item.module) != str(expected_path):
            fail(f"Snapshotpfad für Runtime-Modul {item.module} weicht ab")
        require_file(expected_path, f"Snapshot {item.module}")
        try:
            expected_path.resolve(strict=True).relative_to(real_release)
        except (OSError, ValueError) as exc:
            fail(f"Snapshotpfad für {item.module} liegt außerhalb des Releases")
            raise AssertionError from exc
        checks[expected_path] = snapshot.source_sha256s[item.module]

    runtime_asset_snapshot_paths = (
        raw_snapshot_paths.get("runtime_assets", {})
        if isinstance(raw_snapshot_paths, dict)
        else {}
    )
    runtime_asset_paths = manifest.get("runtime_asset_paths")
    if not isinstance(runtime_asset_paths, dict):
        fail("Manifest enthält keine Runtime-Asset-Pfade")
    for item in snapshot.contract.runtime_assets:
        destination = item.destination.as_posix()
        expected_snapshot = input_root / item.source
        if runtime_asset_snapshot_paths.get(destination) != str(expected_snapshot):
            fail(f"Snapshotpfad für Runtime-Asset {destination} weicht ab")
        require_file(expected_snapshot, f"Snapshot Runtime-Asset {destination}")
        try:
            expected_snapshot.resolve(strict=True).relative_to(real_release)
        except (OSError, ValueError) as exc:
            fail(f"Snapshotpfad für Runtime-Asset {destination} liegt außerhalb des Releases")
            raise AssertionError from exc
        installed_asset = real_release / item.destination
        if runtime_asset_paths.get(destination) != str(installed_asset):
            fail(f"Manifestpfad für Runtime-Asset {destination} weicht ab")
        require_file(installed_asset, f"Runtime-Asset {destination}")
        try:
            installed_asset.resolve(strict=True).relative_to(real_release)
        except (OSError, ValueError) as exc:
            fail(f"Runtime-Asset {destination} liegt außerhalb des Releases")
            raise AssertionError from exc
        expected_hash = snapshot.runtime_asset_sha256s[destination]
        checks[expected_snapshot] = expected_hash
        checks[installed_asset] = expected_hash
    for path, expected_hash in checks.items():
        if sha256(path) != expected_hash:
            fail(f"Finales Releaseartefakt driftete nach Aktivierung: {path}")

    release_python = real_release / ".venv/bin/python"
    if Path(str(manifest.get("release_python_path"))) != release_python:
        fail("Manifest-Release-Pythonpfad entspricht nicht dem realen Release")
    require_file(release_python, "Release-Python")

    imported_module = verify_entrypoint_importable(
        real_release,
        release_python,
        contract,
    )
    require_file(imported_module, "Importiertes Modul")
    expected_module = module_destination(
        site_packages_path(release_python),
        contract.module,
        create_packages=False,
    )
    require_file(expected_module, "Erwartetes Release-Modul")
    if imported_module.resolve(strict=True) != expected_module.resolve(strict=True):
        fail(
            "Importierter Modulpfad entspricht nicht dem erwarteten "
            f"Release-Ziel: {imported_module} != {expected_module}"
        )
    entrypoint_value = manifest.get("entrypoint_path")
    if not isinstance(entrypoint_value, str):
        fail("Manifest enthält keinen Entry-Point-Pfad")
    if Path(entrypoint_value).resolve(strict=True) != imported_module.resolve(strict=True):
        fail("Manifest-Entry-Point entspricht nicht der aktuellen Modulauflösung")
    if sha256(imported_module) != snapshot.source_sha256:
        fail("Importierte Moduldatei entspricht nicht dem Source-Snapshot")
    module_paths = manifest.get("module_paths")
    if not isinstance(module_paths, dict):
        fail("Manifest enthält keine Runtime-Modulpfade")
    if module_paths.get(contract.module) != str(imported_module):
        fail("Manifest-Modulpfad weicht für den Entry-Point ab")
    site_packages = site_packages_path(release_python)
    for item in contract.supporting_sources:
        imported_support = import_module_path(release_python, item.module)
        expected_support = module_destination(
            site_packages, item.module, create_packages=False
        )
        require_file(expected_support, f"Erwartetes Release-Modul {item.module}")
        if imported_support.resolve(strict=True) != expected_support.resolve(strict=True):
            fail(f"Importierter Modulpfad weicht ab: {item.module}")
        if module_paths.get(item.module) != str(imported_support):
            fail(f"Manifest-Modulpfad weicht ab: {item.module}")
        if sha256(imported_support) != snapshot.source_sha256s[item.module]:
            fail(f"Importiertes Runtime-Modul driftete: {item.module}")

    process_exe_value = process.get("exe") if isinstance(process, dict) else None
    if (
        process_exe_value is not None
        and Path(str(process_exe_value)).resolve() != release_python.resolve()
    ):
        fail("Laufender Pythonprozess entspricht nicht dem Release-Python")


@dataclass(frozen=True)
class EntryPoint:
    mode: str
    python: Path
    module: str

    def compatible_with(self, contract: RuntimeContract) -> bool:
        return self.mode == contract.mode and self.module == contract.module

    def describe(self) -> str:
        return f"{self.python} -m {self.module}"


def recursive_values_for_key(value: Any, key: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for item_key, item_value in value.items():
            if item_key == key:
                found.append(item_value)
            found.extend(recursive_values_for_key(item_value, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(recursive_values_for_key(item, key))
    return found


def yaml_profile_command(profile_path: Path) -> list[str]:
    require_file(profile_path, "Tunnelprofil")
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        fail("PyYAML ist für strukturierte Profilprüfung erforderlich")
        raise AssertionError from exc
    if getattr(yaml, "__version__", None) != TOOLING_PYYAML_VERSION:
        fail(
            "PyYAML-Version für strukturierte Profilprüfung ist nicht "
            f"reproduzierbar: {getattr(yaml, '__version__', None)!r}"
        )
    try:
        data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    except Exception as exc:
        mark = getattr(exc, "problem_mark", None)
        details: dict[str, Any] = {"error_type": type(exc).__name__}
        if mark is not None:
            details["line"] = getattr(mark, "line", 0) + 1
            details["column"] = getattr(mark, "column", 0) + 1
        fail("Tunnelprofil ist kein gültiges YAML", details=details)
    commands = recursive_values_for_key(data, "command")
    string_commands = [item for item in commands if isinstance(item, str)]
    list_commands = [item for item in commands if isinstance(item, list)]
    if len(string_commands) + len(list_commands) != 1:
        fail("Tunnelprofil enthält nicht genau einen strukturierten command")
    if string_commands:
        return shlex.split(string_commands[0])
    values = list_commands[0]
    if not all(isinstance(item, str) for item in values):
        fail("Tunnelprofil-command-Liste enthält Nicht-String-Werte")
    return list(values)


def profile_entrypoint(profile_path: Path, runtime: Path) -> EntryPoint:
    argv = yaml_profile_command(profile_path)
    if len(argv) != 3:
        fail("Tunnelprofil-command entspricht nicht dem Modul-Entry-Point")
    expected_python = runtime / ".venv/bin/python"
    if argv[0] != str(expected_python):
        fail("Tunnelprofil verwendet nicht den stabilen Runtime-Pythonpfad")
    if argv[1] == "-m" and len(argv) == 3:
        if not MODULE_RE.match(argv[2]):
            fail(f"Tunnelprofil verwendet ein ungültiges Modul: {argv[2]}")
        return EntryPoint(mode="module", python=expected_python, module=argv[2])
    fail("Tunnelprofil-command entspricht nicht dem Modul-Entry-Point")


def require_profile_matches_contract(profile_path: Path, runtime: Path, contract: RuntimeContract) -> EntryPoint:
    live = profile_entrypoint(profile_path, runtime)
    if not live.compatible_with(contract):
        fail(
            "Live-Profil und Branch-Runtimevertrag passen nicht zusammen: "
            f"Profil={live.describe()} Branch={contract.describe()}"
        )
    return live


@dataclass(frozen=True)
class ServiceObservation:
    query_valid: bool
    load_state: str | None
    active_state: str | None
    sub_state: str | None
    main_pid: int | None
    returncode: int

    @property
    def confirmed_active(self) -> bool:
        return (
            self.query_valid
            and self.load_state == "loaded"
            and self.active_state == "active"
            and self.main_pid is not None
            and self.main_pid > 0
        )

    @property
    def confirmed_inactive(self) -> bool:
        return (
            self.query_valid
            and self.load_state == "loaded"
            and self.active_state in {"inactive", "failed"}
            and self.main_pid == 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "returncode": self.returncode,
            "query_valid": self.query_valid,
            "LoadState": self.load_state,
            "ActiveState": self.active_state,
            "SubState": self.sub_state,
            "MainPID": self.main_pid,
            "confirmed_active": self.confirmed_active,
            "confirmed_inactive": self.confirmed_inactive,
        }


def observe_service() -> ServiceObservation:
    result = run(
        [
            "systemctl", "--user", "show", SERVICE,
            "-p", "LoadState",
            "-p", "ActiveState",
            "-p", "SubState",
            "-p", "MainPID",
            "--no-pager",
        ],
        capture=True,
        check=False,
        timeout=TIMEOUTS["systemd_query"],
    )
    fields: dict[str, str] = {}
    duplicate = False
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in fields:
            duplicate = True
        fields[key] = value
    required = {"LoadState", "ActiveState", "SubState", "MainPID"}
    main_pid: int | None = None
    try:
        main_pid = int(fields["MainPID"])
        if main_pid < 0:
            main_pid = None
    except (KeyError, ValueError):
        main_pid = None
    query_valid = (
        result.returncode == 0
        and not duplicate
        and set(fields) == required
        and main_pid is not None
    )
    return ServiceObservation(
        query_valid=query_valid,
        load_state=fields.get("LoadState"),
        active_state=fields.get("ActiveState"),
        sub_state=fields.get("SubState"),
        main_pid=main_pid,
        returncode=result.returncode,
    )


def service_active() -> bool:
    return observe_service().confirmed_active


def service_state() -> dict[str, Any]:
    return observe_service().to_dict()


def wait_until_confirmed_inactive(timeout_seconds: int) -> ServiceObservation:
    deadline = time.monotonic() + timeout_seconds
    last = observe_service()
    while time.monotonic() < deadline:
        if last.confirmed_inactive:
            return last
        time.sleep(0.2)
        last = observe_service()
    return last


def service_main_pid() -> int:
    observation = observe_service()
    if not observation.confirmed_active or observation.main_pid is None:
        fail(f"{SERVICE} besitzt keine bestätigte aktive MainPID.")
    return observation.main_pid


def http_text(url: str) -> str | None:
    result = run(
        ["curl", "-fsS", "--max-time", "2", url],
        check=False,
        capture=True,
        timeout=5,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def journal_tail() -> str:
    result = run(
        [
            "journalctl",
            "--user",
            "-u",
            SERVICE,
            "-n",
            "40",
            "--no-pager",
        ],
        check=False,
        capture=True,
        timeout=TIMEOUTS["journal"],
    )
    return redact_text(result.stdout + result.stderr)


@dataclass
class ReadinessResult:
    ok: bool
    service: dict[str, Any]
    health: str | None
    readiness: str | None
    main_pid: int | None
    journal: str = ""


def readiness_probe(*, include_journal: bool = False) -> ReadinessResult:
    observation = observe_service()
    health = http_text(HEALTH_URL)
    readiness = http_text(READY_URL)
    ok = (
        observation.confirmed_active
        and health == "live"
        and readiness == "ready"
    )
    return ReadinessResult(
        ok=ok,
        service=observation.to_dict(),
        health=health,
        readiness=readiness,
        main_pid=observation.main_pid,
        journal=journal_tail() if include_journal and not ok else "",
    )


def wait_until_ready(timeout_seconds: int) -> ReadinessResult:
    deadline = time.monotonic() + timeout_seconds
    last = readiness_probe()
    while time.monotonic() < deadline:
        last = readiness_probe()
        if last.ok:
            return last
        time.sleep(1)
    return readiness_probe(include_journal=True)


def child_pids(pid: int, proc_root: Path = Path("/proc")) -> list[int]:
    task_root = proc_root / str(pid) / "task"
    try:
        task_dirs = sorted(
            (item for item in task_root.iterdir() if item.name.isdigit()),
            key=lambda item: int(item.name),
        )
    except FileNotFoundError:
        return []

    children: set[int] = set()
    for task_dir in task_dirs:
        try:
            text = (task_dir / "children").read_text(encoding="utf-8").strip()
        except (FileNotFoundError, ProcessLookupError):
            # Threads can disappear between listing task/ and reading children.
            continue
        children.update(int(value) for value in text.split())
    return sorted(children)


def descendant_pids(
    root_pid: int,
    proc_root: Path = Path("/proc"),
) -> list[int]:
    result: list[int] = []
    pending = [root_pid]
    seen = {root_pid}
    while pending:
        current = pending.pop()
        for child in child_pids(current, proc_root):
            if child in seen:
                continue
            seen.add(child)
            result.append(child)
            pending.append(child)
    return result


def process_argv(pid: int, proc_root: Path = Path("/proc")) -> list[str]:
    path = proc_root / str(pid) / "cmdline"
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return []
    return [
        item.decode("utf-8", errors="replace")
        for item in raw.split(b"\0")
        if item
    ]


def process_exe(pid: int, proc_root: Path = Path("/proc")) -> Path | None:
    path = proc_root / str(pid) / "exe"
    try:
        return Path(os.readlink(path))
    except OSError:
        return None


def verify_systemd_tunnel_process(
    *,
    main_pid: int | None = None,
    proc_root: Path = Path("/proc"),
) -> int:
    pid = service_main_pid() if main_pid is None else main_pid
    argv = process_argv(pid, proc_root)
    expected_a = [str(HOME / ".local/bin/tunnel-client"), "run", "--profile", PROFILE_NAME]
    expected_b = [str(HOME / ".local/bin/tunnel-client"), "run", f"--profile={PROFILE_NAME}"]
    if tuple(argv) not in {tuple(expected_a), tuple(expected_b)}:
        fail("systemd-MainPID verwendet nicht exakt den erwarteten Tunnel-Client")
    return pid


def argv_matches_entrypoint(argv: list[str], runtime: Path, contract: RuntimeContract) -> bool:
    if len(argv) != 3 or argv[1] != "-m":
        return False
    return (
        Path(argv[0]).resolve() == (runtime / ".venv/bin/python").resolve()
        and argv[2] == contract.module
    )


def argv_matches_profile_entrypoint(argv: list[str], entrypoint: EntryPoint) -> bool:
    return (
        entrypoint.mode == "module"
        and len(argv) == 3
        and argv[0] == str(entrypoint.python)
        and argv[1] == "-m"
        and argv[2] == entrypoint.module
    )


def verify_running_profile_entrypoint(
    entrypoint: EntryPoint,
    *,
    main_pid: int | None = None,
    proc_root: Path = Path("/proc"),
) -> dict[str, Any]:
    root_pid = verify_systemd_tunnel_process(main_pid=main_pid, proc_root=proc_root)
    expected_python_resolved = entrypoint.python.resolve()
    for pid in descendant_pids(root_pid, proc_root):
        argv = process_argv(pid, proc_root)
        if not argv_matches_profile_entrypoint(argv, entrypoint):
            continue
        exe = process_exe(pid, proc_root)
        if exe is None or exe.resolve() != expected_python_resolved:
            continue
        return {"pid": pid, "argv": redact_argv(argv)}
    fail("Kein laufender MCP-Prozess verwendet exakt den vorherigen Profil-Entry-Point")


def verify_running_entrypoint(
    runtime: Path,
    contract: RuntimeContract,
    *,
    main_pid: int | None = None,
    proc_root: Path = Path("/proc"),
    release_hint: Path | None = None,
) -> dict[str, Any]:
    root_pid = verify_systemd_tunnel_process(main_pid=main_pid, proc_root=proc_root)
    expected_python = runtime / ".venv/bin/python"
    expected_python_resolved = expected_python.resolve()
    expected_root = release_hint or runtime.resolve()

    for pid in descendant_pids(root_pid, proc_root):
        argv = process_argv(pid, proc_root)
        if not argv_matches_entrypoint(argv, runtime, contract):
            continue
        exe = process_exe(pid, proc_root)
        if exe is None or exe.resolve() != expected_python_resolved:
            continue
        entrypoint_path = verify_entrypoint_importable(
            expected_root,
            expected_python,
            contract,
        )
        return {
            "pid": pid,
            "entrypoint_path": str(entrypoint_path),
            "exe": str(exe),
            "argv": redact_argv(argv),
        }

    fail("Kein laufender MCP-Prozess verwendet exakt den erwarteten Entry-Point")


def verify_running_runtime(
    release_path: Path,
    runtime: Path,
    contract: RuntimeContract,
    *,
    main_pid: int | None = None,
    proc_root: Path = Path("/proc"),
) -> dict[str, Any]:
    if not runtime.is_symlink():
        fail("Stabiler Runtimepfad ist kein Symlink")
    if runtime.resolve() != release_path.resolve():
        fail(
            "Stabiler Runtime-Symlink zeigt nicht auf das ausgewählte Release: "
            f"{runtime} -> {runtime.resolve()}"
        )
    return verify_running_entrypoint(
        runtime,
        contract,
        main_pid=main_pid,
        proc_root=proc_root,
        release_hint=release_path,
    )


def verify_runtime_identity(
    release_path: Path,
    runtime: Path,
    contract: RuntimeContract,
    *,
    snapshot: Snapshot,
    agent_instructions: dict[str, Any],
) -> dict[str, Any]:
    process = verify_running_runtime(release_path, runtime, contract)
    manifest = verify_manifest(
        release_path,
        snapshot=snapshot,
        stable_runtime=runtime,
        expected_agent_instructions=agent_instructions,
    )
    verify_final_release_artifacts(
        release_path,
        runtime,
        contract,
        snapshot=snapshot,
        manifest=manifest,
        process=process,
    )
    return {"process": process, "manifest": manifest}


@dataclass
class PointerState:
    kind: str
    path: Path
    target: Path | None = None
    dev: int | None = None
    ino: int | None = None


def directory_identity(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    if not statmod.S_ISDIR(st.st_mode):
        fail(f"Erwartetes Verzeichnis fehlt oder ist kein Verzeichnis: {path}")
    return (st.st_dev, st.st_ino)


def capture_pointer(runtime: Path) -> PointerState:
    if runtime.is_symlink():
        return PointerState("symlink", runtime, runtime.readlink())
    if runtime.exists():
        if not runtime.is_dir():
            fail(f"Runtimepfad ist weder Verzeichnis noch Symlink: {runtime}")
        dev, ino = directory_identity(runtime)
        return PointerState("directory", runtime, dev=dev, ino=ino)
    return PointerState("missing", runtime)


def require_runtime_replaceable(
    runtime: Path,
    *,
    allowed_root: Path = HOME,
    cwd: Path | None = None,
) -> Path:
    runtime = normalize_managed_path(
        runtime,
        allowed_root=allowed_root,
        cwd=cwd,
    )
    if not runtime.parent.is_dir() or not os.access(runtime.parent, os.W_OK):
        fail(f"Runtime-Parent ist nicht schreibbar: {runtime.parent}")
    capture_pointer(runtime)
    releases_root_for(runtime)
    return runtime


def unique_sibling(path: Path, suffix: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for attempt in range(1000):
        candidate = path.with_name(
            f"{path.name}.{suffix}.{stamp}"
            if attempt == 0
            else f"{path.name}.{suffix}.{stamp}.{attempt}"
        )
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    fail(f"Kein freier Pfad neben {path} für {suffix}")


def atomic_symlink_replace(runtime: Path, target: Path) -> None:
    temporary = runtime.with_name(f".{runtime.name}.next.{os.getpid()}")
    try:
        os.symlink(str(target), temporary)
        os.replace(temporary, runtime)
    finally:
        try:
            if temporary.is_symlink() or temporary.exists():
                temporary.unlink()
        except FileNotFoundError:
            pass


@dataclass
class ActivationState:
    """Single owner of every reversible pointer mutation during activation."""

    runtime: Path
    release_path: Path
    previous: PointerState
    legacy_backup: Path | None = None
    legacy_renamed: bool = False
    symlink_replaced: bool = False
    steps: list[str] = field(default_factory=list)

    def record(self, step: str) -> None:
        self.steps.append(step)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime": str(self.runtime),
            "release_path": str(self.release_path),
            "previous_pointer": pointer_to_dict(self.previous),
            "legacy_backup": str(self.legacy_backup) if self.legacy_backup else None,
            "legacy_renamed": self.legacy_renamed,
            "symlink_replaced": self.symlink_replaced,
            "steps": list(self.steps),
        }


def activate_pointer(state: ActivationState) -> None:
    """Perform the pointer swap, recording each step; never roll back here.

    Recovery is the responsibility of ``restore_pointer`` using the state this
    function records. No hidden internal rollback is performed so that a failure
    between the directory rename and the symlink replace is observable and
    repairable by the explicit rollback owner.
    """
    runtime = state.runtime
    previous = state.previous
    if previous.kind == "directory":
        legacy_backup = unique_sibling(runtime, "legacy")
        runtime.rename(legacy_backup)
        state.legacy_backup = legacy_backup
        state.legacy_renamed = True
        state.record("legacy-directory-renamed")
        atomic_symlink_replace(runtime, state.release_path)
        state.symlink_replaced = True
        state.record("symlink-replaced")
        return
    if previous.kind in {"symlink", "missing"}:
        atomic_symlink_replace(runtime, state.release_path)
        state.symlink_replaced = True
        state.record("symlink-replaced")
        return
    fail(f"Nicht unterstützter Pointerzustand: {previous.kind}")


def restore_pointer(state: ActivationState) -> None:
    """Idempotently restore the original pointer recorded in ``state``.

    If the runtime pointer already matches the captured original exactly it is
    accepted as-is. Otherwise the original is rebuilt from the activation state,
    and legacy directory restoration is confirmed by device/inode identity.
    """
    runtime = state.runtime
    previous = state.previous
    current = capture_pointer(runtime)
    if pointer_states_equal(current, previous):
        if previous.kind == "directory":
            if directory_identity(runtime) != (previous.dev, previous.ino):
                fail("Wiederhergestelltes Verzeichnis hat falsche Geräte-/Inode-Identität")
        return
    if previous.kind == "directory":
        backup = state.legacy_backup
        if backup is None or not backup.exists():
            fail("Legacy-Backup fehlt für Rollback")
        if directory_identity(backup) != (previous.dev, previous.ino):
            fail("Legacy-Backup hat nicht die ursprüngliche Verzeichnisidentität")
        if runtime.exists() or runtime.is_symlink():
            failed_pointer = unique_sibling(runtime, "failed-pointer")
            runtime.rename(failed_pointer)
        backup.rename(runtime)
        if directory_identity(runtime) != (previous.dev, previous.ino):
            fail("Wiederhergestelltes Verzeichnis hat falsche Geräte-/Inode-Identität")
        return
    if previous.kind == "symlink":
        assert previous.target is not None
        atomic_symlink_replace(runtime, previous.target)
        return
    if previous.kind == "missing":
        if runtime.exists() or runtime.is_symlink():
            runtime.unlink()
        return
    fail(f"Nicht unterstützter Rollback-Pointerzustand: {previous.kind}")


@dataclass
class RollbackState:
    original_error: dict[str, Any]
    phase: str
    previous_pointer: dict[str, Any]
    stop_returncode: int | None = None
    inactive_after_stop: bool | None = None
    pointer_restore: str | None = None
    start_returncode: int | None = None
    readiness_ok: bool | None = None
    restored_identity: str | None = None
    final_pointer: dict[str, Any] | None = None
    final_service: dict[str, Any] | None = None
    phases: dict[str, Any] = field(default_factory=dict)
    errors: list[Any] = field(default_factory=list)

    def message(self) -> str:
        payload = {
            "original_error": self.original_error,
            "phase": self.phase,
            "previous_pointer": self.previous_pointer,
            "stop_returncode": self.stop_returncode,
            "inactive_after_stop": self.inactive_after_stop,
            "pointer_restore": self.pointer_restore,
            "start_returncode": self.start_returncode,
            "readiness_ok": self.readiness_ok,
            "restored_identity": self.restored_identity,
            "final_pointer": self.final_pointer,
            "final_service": self.final_service,
            "rollback_phases": self.phases,
            "rollback_errors": self.errors,
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def pointer_to_dict(pointer: PointerState) -> dict[str, Any]:
    return {
        "kind": pointer.kind,
        "path": str(pointer.path),
        "target": str(pointer.target) if pointer.target is not None else None,
        "dev": pointer.dev,
        "ino": pointer.ino,
    }


def pointer_states_equal(actual: PointerState, expected: PointerState) -> bool:
    return (
        actual.kind == expected.kind
        and actual.path == expected.path
        and actual.target == expected.target
        and actual.dev == expected.dev
        and actual.ino == expected.ino
    )


def verify_pointer_state(runtime: Path, expected: PointerState) -> PointerState:
    actual = capture_pointer(runtime)
    if not pointer_states_equal(actual, expected):
        fail(
            "Pointerzustand entspricht nach Wiederherstellung nicht dem "
            "ursprünglichen Zustand",
            phase="rollback-pointer-verification",
            details={
                "actual": pointer_to_dict(actual),
                "expected": pointer_to_dict(expected),
            },
        )
    return actual


def rollback_step(
    state: RollbackState,
    name: str,
    callback,
) -> tuple[Any | None, BaseException | None]:
    try:
        value = callback()
    except Exception as exc:
        summary = safe_error_summary(exc)
        state.phases[name] = {"ok": False, "error": summary}
        state.errors.append({"phase": name, "error": summary})
        return None, exc
    state.phases[name] = {"ok": True, "result": summarize_result(value)}
    return value, None


def finalize_rollback_state(state: RollbackState, runtime: Path) -> None:
    pointer, _ = rollback_step(
        state,
        "rollback-final-pointer",
        lambda: capture_pointer(runtime),
    )
    if isinstance(pointer, PointerState):
        state.final_pointer = pointer_to_dict(pointer)
    service, _ = rollback_step(
        state,
        "rollback-final-service-state",
        service_state,
    )
    if isinstance(service, dict):
        state.final_service = service


def rollback_after_failure(
    original: BaseException,
    *,
    activation: ActivationState,
    timeout_seconds: int,
    phase: str,
    contract: RuntimeContract | None = None,
    recovery_entrypoint: EntryPoint | None = None,
) -> NoReturn:
    runtime = activation.runtime
    previous = activation.previous
    state = RollbackState(
        original_error=safe_error_summary(original),
        phase=phase,
        previous_pointer=pointer_to_dict(previous),
    )

    def abort(message: str) -> NoReturn:
        finalize_rollback_state(state, runtime)
        raise DeployError(message + state.message()) from original

    stop_result, _ = rollback_step(
        state,
        "rollback-stop-command",
        lambda: run(
            ["systemctl", "--user", "stop", SERVICE],
            check=False,
            capture=True,
            timeout=TIMEOUTS["service_stop"],
        ),
    )
    if isinstance(stop_result, subprocess.CompletedProcess):
        state.stop_returncode = stop_result.returncode

    inactive, inactive_error = rollback_step(
        state,
        "rollback-service-state-after-stop",
        lambda: wait_until_confirmed_inactive(TIMEOUTS["service_stop"]),
    )
    state.inactive_after_stop = (
        inactive.confirmed_inactive
        if isinstance(inactive, ServiceObservation) and inactive_error is None
        else None
    )
    if not isinstance(inactive, ServiceObservation) or not inactive.confirmed_inactive:
        state.errors.append(
            {
                "phase": "rollback-service-state-after-stop",
                "message": (
                    "Dienstzustand ist nicht bestätigt inaktiv "
                    "(aktiv/aktivierend/unbekannt); "
                    "keine Pointermutation im Rollback"
                ),
            }
        )
        abort("Kritischer Rollbackabbruch: ")

    _, restore_error = rollback_step(
        state,
        "rollback-pointer-restore",
        lambda: restore_pointer(activation),
    )
    if restore_error is not None:
        state.pointer_restore = "failed"
        abort("Kritischer Rollbackabbruch nach Restorefehler: ")
    state.pointer_restore = "restored"

    _, verify_error = rollback_step(
        state,
        "rollback-pointer-verification",
        lambda: verify_pointer_state(runtime, previous),
    )
    if verify_error is not None:
        state.pointer_restore = "verification-failed"
        abort("Kritischer Rollbackabbruch nach Pointerverifikationsfehler: ")

    start_result, start_error = rollback_step(
        state,
        "rollback-start-command",
        lambda: run(
            ["systemctl", "--user", "start", SERVICE],
            check=False,
            capture=True,
            timeout=TIMEOUTS["service_start"],
        ),
    )
    if isinstance(start_result, subprocess.CompletedProcess):
        state.start_returncode = start_result.returncode
    if start_error is not None or not isinstance(start_result, subprocess.CompletedProcess):
        abort("Deployment fehlgeschlagen; Rollbackstart scheiterte; Rollbackzustand: ")
    if start_result.returncode != 0:
        state.errors.append(
            {
                "phase": "rollback-start-command",
                "message": "Start der wiederhergestellten Runtime fehlgeschlagen",
            }
        )
        abort("Deployment fehlgeschlagen; Rollbackzustand: ")

    readiness, readiness_error = rollback_step(
        state,
        "rollback-readiness",
        lambda: wait_until_ready(timeout_seconds),
    )
    if isinstance(readiness, ReadinessResult):
        state.readiness_ok = readiness.ok
    if readiness_error is not None or not isinstance(readiness, ReadinessResult):
        abort("Deployment fehlgeschlagen; Rollbackreadiness scheiterte; Rollbackzustand: ")
    if not readiness.ok:
        state.errors.append(
            {
                "phase": "rollback-readiness",
                "message": "Wiederhergestellte Runtime wurde nicht ready",
            }
        )
        abort("Deployment fehlgeschlagen; Rollbackzustand: ")

    if recovery_entrypoint is not None:
        _, identity_error = rollback_step(
            state,
            "rollback-identity",
            lambda: verify_running_profile_entrypoint(recovery_entrypoint),
        )
    elif contract is not None:
        _, identity_error = rollback_step(
            state,
            "rollback-identity",
            lambda: verify_running_entrypoint(runtime, contract),
        )
    else:
        identity_error = None
        state.phases["rollback-identity"] = {"ok": True, "result": "skipped"}
    if identity_error is not None:
        state.restored_identity = "failed"
        abort("Deployment fehlgeschlagen; Rollbackidentität scheiterte; Rollbackzustand: ")
    state.restored_identity = "verified"

    finalize_rollback_state(state, runtime)
    raise DeployError("Deployment fehlgeschlagen; Rollbackzustand: " + state.message()) from original


def verify_apply_snapshot_unchanged(repo: Path, snapshot: Snapshot, release_path: Path) -> None:
    if repo_dirty(repo):
        fail("Repository driftete vor Aktivierung: Arbeitsbaum ist dirty")
    if git_head(repo) != snapshot.repo_head:
        fail("Repository driftete vor Aktivierung: HEAD weicht ab")
    input_root = release_path / "inputs"
    checks = {
        input_root / ENTRYPOINT_CONTRACT_RELATIVE.name: snapshot.contract_sha256,
        input_root / RUNTIME_INPUT_RELATIVE.name: snapshot.runtime_input_sha256,
        input_root / RUNTIME_LOCK_RELATIVE.name: snapshot.runtime_lock_sha256,
        input_root / snapshot.contract.source: snapshot.source_sha256,
    }
    for item in snapshot.contract.supporting_sources:
        checks[input_root / item.source] = snapshot.source_sha256s[item.module]
    for item in snapshot.contract.runtime_assets:
        destination = item.destination.as_posix()
        checks[input_root / item.source] = snapshot.runtime_asset_sha256s[destination]
    for path, expected in checks.items():
        if sha256(path) != expected:
            fail(f"Release-Snapshot driftete vor Aktivierung: {path}")


def deploy(
    repo: Path,
    runtime: Path,
    profile_path: Path,
    *,
    timeout_seconds: int,
) -> None:
    snapshot = snapshot_from_git(repo)
    runtime = require_runtime_replaceable(runtime)
    live_entrypoint = require_profile_matches_contract(profile_path, runtime, snapshot.contract)
    initial_service = observe_service()
    if not initial_service.confirmed_active:
        fail(
            f"{SERVICE} ist vor dem Deployment nicht bestätigt aktiv.",
            details={"service": initial_service.to_dict()},
        )

    build = build_release(snapshot, releases_root_for(runtime), runtime)
    verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)
    verify_manifest(
        build.release_path,
        snapshot=snapshot,
        stable_runtime=runtime,
        expected_agent_instructions=build.agent_instructions,
    )

    previous = capture_pointer(runtime)
    activation = ActivationState(
        runtime=runtime,
        release_path=build.release_path,
        previous=previous,
    )
    phase = "stop"

    try:
        stop_result = run(
            ["systemctl", "--user", "stop", SERVICE],
            check=False,
            capture=True,
            timeout=TIMEOUTS["service_stop"],
        )
        observation = wait_until_confirmed_inactive(TIMEOUTS["service_stop"])
        if not observation.confirmed_inactive:
            fail(
                "Dienst wurde nach Stopversuch nicht als inaktiv bestätigt; "
                "keine Pointermutation",
                phase="stop",
                details={
                    "stop_returncode": stop_result.returncode,
                    "service": observation.to_dict(),
                },
            )

        phase = "pre-activation-revalidation"
        verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)
        require_profile_matches_contract(profile_path, runtime, snapshot.contract)

        phase = "activate-pointer"
        activate_pointer(activation)

        phase = "start"
        start_result = run(
            ["systemctl", "--user", "start", SERVICE],
            check=False,
            capture=True,
            timeout=TIMEOUTS["service_start"],
        )
        if start_result.returncode != 0:
            fail("Neue Runtime konnte nicht gestartet werden", phase="start")

        phase = "readiness"
        readiness = wait_until_ready(timeout_seconds)
        if not readiness.ok:
            fail(
                "Neue Runtime wurde nicht rechtzeitig live und ready.",
                phase="readiness",
                details={
                    "service": readiness.service,
                    "health": readiness.health,
                    "readiness": readiness.readiness,
                    "main_pid": readiness.main_pid,
                    "journal": readiness.journal,
                },
            )

        phase = "identity"
        identity = verify_runtime_identity(
            build.release_path,
            runtime,
            snapshot.contract,
            snapshot=snapshot,
            agent_instructions=build.agent_instructions,
        )

        print("PASS: Deployment erfolgreich")
        print(f"Repo-HEAD:       {snapshot.repo_head}")
        print(f"Release-ID:      {build.release_id}")
        print(f"Source-SHA256:   {snapshot.source_sha256}")
        print(f"Lock-SHA256:     {snapshot.runtime_lock_sha256}")
        print(f"Entry-Point:     {snapshot.contract.describe()}")
        print(f"MCP-Protokoll:   {build.protocol_version}")
        if build.agent_instructions:
            print(
                "Agent-Vertrag:  "
                f"{build.agent_instructions.get('version')} "
                f"{build.agent_instructions.get('sha256')}"
            )
        print(f"Runtime-PID:     {identity['process']['pid']}")
        print(f"Runtime:         {runtime}")
        print(f"Release:         {build.release_path}")
        print(f"Legacy-Backup:   {activation.legacy_backup}")

    except Exception as original:
        print(
            "PRIMARY-DEPLOY-ERROR: "
            + json.dumps(safe_error_summary(original), sort_keys=True),
            file=sys.stderr,
        )
        rollback_after_failure(
            original,
            activation=activation,
            timeout_seconds=timeout_seconds,
            phase=phase,
            contract=snapshot.contract,
            recovery_entrypoint=live_entrypoint,
        )


def preflight_apply(repo: Path, runtime: Path, profile_path: Path) -> None:
    snapshot = snapshot_from_git(repo)
    runtime = require_runtime_replaceable(runtime)
    require_profile_matches_contract(profile_path, runtime, snapshot.contract)


def check(repo: Path, runtime: Path) -> None:
    snapshot = snapshot_from_worktree(repo)
    with tempfile.TemporaryDirectory(prefix="grabowski-mcp-check.") as directory:
        check_runtime = Path(directory) / runtime.name
        releases_root = Path(directory) / RELEASES_DIR_NAME
        build = build_release(snapshot, releases_root, check_runtime)
        verify_manifest(
            build.release_path,
            snapshot=snapshot,
            stable_runtime=check_runtime,
            expected_agent_instructions=build.agent_instructions,
        )
        print("PASS: Deployment-Check ist dependency-locked")
        print(f"Repo-HEAD:       {snapshot.repo_head}")
        print(f"Arbeitsbaum:     {'dirty' if snapshot.dirty else 'clean'}")
        print(f"Release-ID:      {build.release_id}")
        print(f"Source-SHA256:   {snapshot.source_sha256}")
        print(f"Lock-SHA256:     {snapshot.runtime_lock_sha256}")
        print(f"Entry-Point:     {snapshot.contract.describe()}")
        print(f"Python:          {build.provenance['python_version']}")
        print(f"MCP-Protokoll:   {build.protocol_version}")
        if build.agent_instructions:
            print(
                "Agent-Vertrag:  "
                f"{build.agent_instructions.get('version')} "
                f"{build.agent_instructions.get('sha256')}"
            )


def absolute_no_resolve(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded
    return Path.cwd() / expanded


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy Grabowski atomically from immutable releases."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--runtime",
        type=Path,
        default=HOME / ".local/share/grabowski-mcp",
    )
    parser.add_argument(
        "--profile-path",
        type=Path,
        default=DEFAULT_PROFILE_PATH,
    )
    parser.add_argument(
        "--lock-file",
        type=Path,
        default=DEFAULT_LOCK_FILE,
    )
    parser.add_argument("--timeout", type=int, default=40)

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    runtime = absolute_no_resolve(args.runtime)
    profile_path = absolute_no_resolve(args.profile_path)
    lock_file = absolute_no_resolve(args.lock_file)

    try:
        if args.check:
            check(repo, runtime)
        else:
            preflight_apply(repo, runtime, profile_path)
            with deployment_lock(lock_file):
                deploy(
                    repo,
                    runtime,
                    profile_path,
                    timeout_seconds=args.timeout,
                )
    except DeployError as exc:
        print(
            "STOP: "
            + json.dumps(safe_error_summary(exc), sort_keys=True, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1
    except subprocess.CalledProcessError as exc:
        print(
            "STOP: "
            + json.dumps(safe_error_summary(exc), sort_keys=True, ensure_ascii=False),
            file=sys.stderr,
        )
        return exc.returncode or 1
    except Exception as exc:
        print(
            "STOP: "
            + json.dumps(safe_error_summary(exc), sort_keys=True, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
