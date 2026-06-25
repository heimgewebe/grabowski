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
import shutil
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
DEFAULT_LOCK_FILE = HOME / ".local/state/grabowski/deploy.lock"
RUNTIME_INPUT_RELATIVE = Path("requirements/runtime.in")
RUNTIME_LOCK_RELATIVE = Path("requirements/runtime.lock.txt")
ENTRYPOINT_CONTRACT_RELATIVE = Path("config/runtime-entrypoint.json")
RELEASES_DIR_NAME = "grabowski-mcp-releases"
MANIFEST_NAME = "deployment-manifest.json"
INCOMPLETE_MARKER = "deployment-incomplete.json"
MANIFEST_SCHEMA_VERSION = 3
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


def parse_runtime_input(path: Path) -> dict[str, str]:
    require_file(path, "Runtime-Input")
    pins: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-") or "://" in stripped or stripped.startswith("git+"):
            fail(f"Nicht erlaubte runtime.in-Option: {stripped}")
        name, version = parse_pinned_requirement(stripped, allow_continuation=False)
        if name in pins:
            fail(f"Doppeltes Paket in runtime.in: {name}")
        pins[name] = version
    if pins.get("mcp") != "1.27.2":
        fail("runtime.in muss mcp==1.27.2 enthalten")
    return pins


def parse_runtime_lock(path: Path) -> dict[str, str]:
    require_file(path, "Runtime-Lockfile")
    locked: dict[str, str] = {}
    current_name: str | None = None
    current_requirement: str | None = None
    current_version: str | None = None
    hashes = 0

    def close_block() -> None:
        nonlocal current_name, current_requirement, current_version, hashes
        if current_name is None:
            return
        if hashes == 0:
            fail(f"Runtime-Lockblock ohne SHA-256-Hashes: {current_requirement}")
        if current_name in locked:
            fail(f"Doppeltes Paket im Runtime-Lock: {current_name}")
        assert current_version is not None
        locked[current_name] = current_version
        current_name = None
        current_requirement = None
        current_version = None
        hashes = 0

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
            if not HASH_RE.match(stripped):
                fail(f"Nicht erlaubte Fortsetzungsoption im Lock: {stripped}")
            hashes += 1
            continue
        close_block()
        if stripped.startswith(("-e", "--", "-c", "-r")) or "://" in stripped or stripped.startswith("git+"):
            fail(f"Nicht erlaubte Runtime-Lock-Anforderung: {stripped}")
        current_name, current_version = parse_pinned_requirement(
            stripped,
            allow_continuation=True,
        )
        current_requirement = stripped
    close_block()

    if not locked:
        fail("Runtime-Lock enthält keine Anforderungen")
    if locked.get("mcp") != "1.27.2":
        fail("Runtime-Lock muss mcp==1.27.2 enthalten")
    return locked


@dataclass(frozen=True)
class RuntimeContract:
    schema_version: int
    mode: str
    expected_tools: tuple[str, ...]
    source: Path
    module: str

    def to_manifest(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "expected_tools": list(self.expected_tools),
            "source": self.source.as_posix(),
            "module": self.module,
        }

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
    if raw.get("schema_version") != 1:
        fail("Runtime-Entry-Point-Contract benötigt schema_version 1")
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
    if not isinstance(module, str) or not MODULE_RE.match(module):
        fail(f"Ungültiges Modul im Runtime-Entry-Point-Contract: {module!r}")
    return RuntimeContract(
        schema_version=1,
        mode="module",
        module=module,
        source=source,
        expected_tools=tuple(tools),
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
    )


@contextmanager
def deployment_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            fail(f"Ein anderes Deployment hält bereits den Lock: {lock_path}")
            raise AssertionError from exc

        handle.seek(0)
        handle.truncate()
        handle.write(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "acquired_at_unix": int(time.time()),
                },
                sort_keys=True,
            )
            + "\n"
        )
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
        f"-src{snapshot.source_sha256[:12]}"
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


def write_snapshot_inputs(snapshot: Snapshot, release_path: Path) -> dict[str, str]:
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
    return {key: str(path) for key, path in files.items()}


def pip_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_NO_INPUT"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
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


def install_runtime_source(snapshot: Snapshot, release_path: Path, python_exe: Path) -> Path:
    destination = module_destination(
        site_packages_path(python_exe),
        snapshot.contract.module,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(snapshot.source_bytes)
    run(
        [str(python_exe), "-m", "py_compile", str(destination)],
        timeout=TIMEOUTS["python"],
        env=pip_env(),
    )
    return destination


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


def probe_mcp(release_path: Path, python_exe: Path, contract: RuntimeContract) -> str:
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

                negotiated = initialized.get("result", {}).get(
                    "protocolVersion"
                )
                if not isinstance(negotiated, str):
                    raise DeployError(
                        f"Ungültige initialize-Antwort: {initialized!r}"
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
                return negotiated

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
            [sys.executable, "-m", "venv", str(venv)],
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
        installed_entrypoint = install_runtime_source(snapshot, release_path, venv_python)
        entrypoint_path = verify_entrypoint_importable(
            release_path,
            venv_python,
            snapshot.contract,
        )
        if entrypoint_path.resolve() != installed_entrypoint.resolve():
            fail(
                "Installierter Entry-Point weicht von der Importauflösung ab: "
                f"{installed_entrypoint} != {entrypoint_path}"
            )

        phase = "mcp-probe"
        protocol_version = probe_mcp(release_path, venv_python, snapshot.contract)
        provenance = python_provenance(venv_python)

        phase = "manifest"
        write_manifest(
            release_path,
            release_id=release_id,
            snapshot=snapshot,
            stable_runtime=stable_runtime,
            input_paths=input_paths,
            entrypoint_path=entrypoint_path,
            protocol_version=protocol_version,
            provenance=provenance,
        )
        return BuildResult(
            release_id=release_id,
            release_path=release_path,
            python_exe=venv_python,
            entrypoint_path=entrypoint_path,
            protocol_version=protocol_version,
            provenance=provenance,
        )
    except Exception as exc:
        mark_incomplete(release_path, phase, exc)
        raise


def write_manifest(
    release_path: Path,
    *,
    release_id: str,
    snapshot: Snapshot,
    stable_runtime: Path,
    input_paths: dict[str, str],
    entrypoint_path: Path,
    protocol_version: str,
    provenance: dict[str, str],
) -> None:
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "release_id": release_id,
        "repo_head": snapshot.repo_head,
        "entrypoint_contract": snapshot.contract.to_manifest(),
        "entrypoint_contract_sha256": snapshot.contract_sha256,
        "source_sha256": snapshot.source_sha256,
        "runtime_input_sha256": snapshot.runtime_input_sha256,
        "runtime_lock_sha256": snapshot.runtime_lock_sha256,
        "snapshot_paths": input_paths,
        "immutable_release_path": str(release_path),
        "expected_stable_runtime_path": str(stable_runtime),
        "release_python_path": str(release_path / ".venv/bin/python"),
        "entrypoint_path": str(entrypoint_path),
        "mcp_protocol_version": protocol_version,
        "created_at_unix": int(time.time()),
        "completion_status": "complete",
        **provenance,
    }
    path = release_path / MANIFEST_NAME
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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


def validate_manifest_schema(manifest: dict[str, Any]) -> list[str]:
    required = {
        "schema_version": int,
        "release_id": str,
        "repo_head": str,
        "entrypoint_contract": dict,
        "entrypoint_contract_sha256": str,
        "source_sha256": str,
        "runtime_input_sha256": str,
        "runtime_lock_sha256": str,
        "snapshot_paths": dict,
        "immutable_release_path": str,
        "expected_stable_runtime_path": str,
        "release_python_path": str,
        "entrypoint_path": str,
        "platform": str,
        "python_version": str,
        "python_implementation": str,
        "mcp_protocol_version": str,
        "created_at_unix": int,
        "completion_status": str,
    }
    errors: list[str] = []
    for key, kind in required.items():
        if not isinstance(manifest.get(key), kind):
            errors.append(key)
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        errors.append("schema_version")
    if manifest.get("completion_status") != "complete":
        errors.append("completion_status")
    return errors


def verify_manifest(
    runtime_or_release: Path,
    *,
    snapshot: Snapshot,
    stable_runtime: Path | None = None,
) -> dict[str, Any]:
    manifest = read_manifest(runtime_or_release)
    schema_errors = validate_manifest_schema(manifest)
    if schema_errors:
        fail("Deployment-Manifest ist nicht schema-valid: " + ", ".join(schema_errors))
    expected = {
        "repo_head": snapshot.repo_head,
        "source_sha256": snapshot.source_sha256,
        "runtime_input_sha256": snapshot.runtime_input_sha256,
        "runtime_lock_sha256": snapshot.runtime_lock_sha256,
        "entrypoint_contract_sha256": snapshot.contract_sha256,
    }
    if stable_runtime is not None:
        expected["expected_stable_runtime_path"] = str(stable_runtime)
    for key, value in expected.items():
        if manifest.get(key) != value:
            fail(
                f"Manifest-Feld {key} weicht ab: "
                f"{manifest.get(key)!r} != {value!r}"
            )
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


def service_active() -> bool:
    result = run(
        ["systemctl", "--user", "is-active", "--quiet", SERVICE],
        check=False,
        timeout=TIMEOUTS["systemd_query"],
    )
    return result.returncode == 0


def service_state() -> dict[str, Any]:
    result = run(
        [
            "systemctl",
            "--user",
            "show",
            SERVICE,
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "MainPID",
            "--no-pager",
        ],
        capture=True,
        check=False,
        timeout=TIMEOUTS["systemd_query"],
    )
    data: dict[str, Any] = {"returncode": result.returncode}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = value
    return data


def service_main_pid() -> int:
    result = run(
        [
            "systemctl",
            "--user",
            "show",
            SERVICE,
            "-p",
            "MainPID",
            "--value",
        ],
        capture=True,
        timeout=TIMEOUTS["systemd_query"],
    )
    try:
        pid = int(result.stdout.strip())
    except ValueError as exc:
        fail(f"Ungültige MainPID: {result.stdout!r}")
        raise AssertionError from exc
    if pid <= 0:
        fail(f"{SERVICE} besitzt keine aktive MainPID.")
    return pid


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
    state = service_state()
    main_pid: int | None = None
    try:
        main_pid = int(str(state.get("MainPID", "0")))
    except ValueError:
        main_pid = None
    health = http_text(HEALTH_URL)
    readiness = http_text(READY_URL)
    ok = (
        state.get("ActiveState") == "active"
        and health == "live"
        and readiness == "ready"
    )
    return ReadinessResult(
        ok=ok,
        service=state,
        health=health,
        readiness=readiness,
        main_pid=main_pid,
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
    path = proc_root / str(pid) / "task" / str(pid) / "children"
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return []
    return [int(value) for value in text.split()] if text else []


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
) -> dict[str, Any]:
    process = verify_running_runtime(release_path, runtime, contract)
    manifest = verify_manifest(
        release_path,
        snapshot=snapshot,
        stable_runtime=runtime,
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


def capture_pointer(runtime: Path) -> PointerState:
    if runtime.is_symlink():
        return PointerState("symlink", runtime, runtime.readlink())
    if runtime.exists():
        if not runtime.is_dir():
            fail(f"Runtimepfad ist weder Verzeichnis noch Symlink: {runtime}")
        return PointerState("directory", runtime)
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


def activate_pointer(runtime: Path, release_path: Path, previous: PointerState) -> Path | None:
    legacy_backup: Path | None = None
    if previous.kind == "directory":
        legacy_backup = unique_sibling(runtime, "legacy")
        runtime.rename(legacy_backup)
        try:
            atomic_symlink_replace(runtime, release_path)
        except Exception:
            if not runtime.exists() and legacy_backup.exists():
                legacy_backup.rename(runtime)
            raise
        return legacy_backup
    if previous.kind in {"symlink", "missing"}:
        atomic_symlink_replace(runtime, release_path)
        return None
    fail(f"Nicht unterstützter Pointerzustand: {previous.kind}")


def restore_pointer(
    runtime: Path,
    previous: PointerState,
    legacy_backup: Path | None,
) -> None:
    if previous.kind == "directory":
        if legacy_backup is None or not legacy_backup.exists():
            fail("Legacy-Backup fehlt für Rollback")
        if runtime.exists() or runtime.is_symlink():
            failed_pointer = unique_sibling(runtime, "failed-pointer")
            runtime.rename(failed_pointer)
        legacy_backup.rename(runtime)
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
    previous_pointer: dict[str, str | None]
    stop_returncode: int | None = None
    inactive_after_stop: bool | None = None
    pointer_restore: str | None = None
    start_returncode: int | None = None
    readiness_ok: bool | None = None
    restored_identity: str | None = None
    final_pointer: dict[str, str | None] | None = None
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


def pointer_to_dict(pointer: PointerState) -> dict[str, str | None]:
    return {
        "kind": pointer.kind,
        "path": str(pointer.path),
        "target": str(pointer.target) if pointer.target is not None else None,
    }


def pointer_states_equal(actual: PointerState, expected: PointerState) -> bool:
    return (
        actual.kind == expected.kind
        and actual.path == expected.path
        and actual.target == expected.target
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
    runtime: Path,
    previous: PointerState,
    legacy_backup: Path | None,
    timeout_seconds: int,
    phase: str,
    contract: RuntimeContract | None = None,
    recovery_entrypoint: EntryPoint | None = None,
) -> NoReturn:
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
        lambda: not service_active(),
    )
    state.inactive_after_stop = inactive if inactive_error is None else None
    if inactive is not True:
        state.errors.append(
            {
                "phase": "rollback-service-state-after-stop",
                "message": (
                    "Dienstzustand ist aktiv oder unbekannt; "
                    "keine Pointermutation im Rollback"
                ),
            }
        )
        abort("Kritischer Rollbackabbruch: ")

    _, restore_error = rollback_step(
        state,
        "rollback-pointer-restore",
        lambda: restore_pointer(runtime, previous, legacy_backup),
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
    if not service_active():
        fail(f"{SERVICE} ist vor dem Deployment nicht aktiv.")

    build = build_release(snapshot, releases_root_for(runtime), runtime)
    verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)
    verify_manifest(build.release_path, snapshot=snapshot, stable_runtime=runtime)

    previous = capture_pointer(runtime)
    legacy_backup: Path | None = None
    pointer_changed = False
    phase = "stop"

    try:
        stop_result = run(
            ["systemctl", "--user", "stop", SERVICE],
            check=False,
            capture=True,
            timeout=TIMEOUTS["service_stop"],
        )
        if service_active():
            fail(
                "Dienst blieb nach Stopversuch aktiv; keine Pointermutation",
                phase="stop",
                details={"stop_returncode": stop_result.returncode},
            )

        phase = "activate-pointer"
        legacy_backup = activate_pointer(runtime, build.release_path, previous)
        pointer_changed = True

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
        )

        print("PASS: Deployment erfolgreich")
        print(f"Repo-HEAD:       {snapshot.repo_head}")
        print(f"Release-ID:      {build.release_id}")
        print(f"Source-SHA256:   {snapshot.source_sha256}")
        print(f"Lock-SHA256:     {snapshot.runtime_lock_sha256}")
        print(f"Entry-Point:     {snapshot.contract.describe()}")
        print(f"MCP-Protokoll:   {build.protocol_version}")
        print(f"Runtime-PID:     {identity['process']['pid']}")
        print(f"Runtime:         {runtime}")
        print(f"Release:         {build.release_path}")
        print(f"Legacy-Backup:   {legacy_backup}")

    except Exception as original:
        rollback_after_failure(
            original,
            runtime=runtime,
            previous=previous,
            legacy_backup=legacy_backup,
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
        verify_manifest(build.release_path, snapshot=snapshot, stable_runtime=check_runtime)
        print("PASS: Deployment-Check ist dependency-locked")
        print(f"Repo-HEAD:       {snapshot.repo_head}")
        print(f"Arbeitsbaum:     {'dirty' if snapshot.dirty else 'clean'}")
        print(f"Release-ID:      {build.release_id}")
        print(f"Source-SHA256:   {snapshot.source_sha256}")
        print(f"Lock-SHA256:     {snapshot.runtime_lock_sha256}")
        print(f"Entry-Point:     {snapshot.contract.describe()}")
        print(f"Python:          {build.provenance['python_version']}")
        print(f"MCP-Protokoll:   {build.protocol_version}")


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
    runtime = normalize_managed_path(args.runtime, allowed_root=HOME)
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
        if exc.details:
            print(
                f"STOP: {exc} | details={json.dumps(exc.details, sort_keys=True, ensure_ascii=False)}",
                file=sys.stderr,
            )
        else:
            print(f"STOP: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(
            f"STOP: Befehl fehlgeschlagen: {redact_argv([str(item) for item in exc.cmd])}",
            file=sys.stderr,
        )
        return exc.returncode or 1
    except Exception as exc:
        print(
            "STOP: Unerwarteter Fehler: "
            + json.dumps(safe_error_summary(exc), sort_keys=True, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
