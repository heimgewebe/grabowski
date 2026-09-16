from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
from typing import Iterable

BWRAP = Path(os.environ.get("GRABOWSKI_BWRAP_BIN", "/usr/bin/bwrap"))
TAIL_BYTES = 12000
MAX_WRITABLE_SCOPE_ENTRIES = 100_000
_GIT_COMMAND_CONFIG = (
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
)


class AgentSandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedSandboxCommand:
    command: tuple[str, ...]
    extra_read_only: tuple[tuple[Path, Path], ...] = ()
    extra_read_write: tuple[tuple[Path, Path], ...] = ()
    extra_directories: tuple[Path, ...] = ()
    profile: str | None = None
    probe_executable: str | None = None


CLAUDE_PROFILE = "claude-cli-readonly-auth-v1"
CLAUDE_SANDBOX_EXECUTABLE = Path("/opt/grabowski-external/claude")
CLAUDE_SANDBOX_CONFIG_DIR = Path("/tmp/.claude")
CODEX_PROFILE = "codex-cli-dedicated-durable-auth-v1"
CODEX_SANDBOX_EXECUTABLE = Path("/opt/grabowski-external/codex")
CODEX_SANDBOX_CONFIG_DIR = Path("/tmp/.codex")
CODEX_SANDBOX_CODE_MODE_HOST = Path("/opt/grabowski-external/codex-code-mode-host")
CODEX_SANDBOX_AUTH_LOCK = Path("/tmp/.grabowski-codex-auth.lock")
GROK_PROFILE = "grok-cli-readonly-auth-v1"
GROK_SANDBOX_EXECUTABLE = Path("/opt/grabowski-external/grok")
GROK_SANDBOX_CONFIG_DIR = Path("/tmp/.grok")
_CODEX_WORKSPACE_WRITE_PROTECTED_CONFIG = (
    "sandbox_workspace_write.exclude_slash_tmp=true",
    "sandbox_workspace_write.exclude_tmpdir_env_var=true",
)
_CODEX_WORKSPACE_WRITE_PROTECTED_KEYS = frozenset(
    {
        "sandbox_workspace_write",
        "sandbox_workspace_write.exclude_slash_tmp",
        "sandbox_workspace_write.exclude_tmpdir_env_var",
    }
)
_CODEX_AUTH_SERIALIZED_LAUNCH_SOURCE = """\
import fcntl
import subprocess
import sys

with open(sys.argv[1], "rb+") as lock_file:
    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
    completed = subprocess.run(sys.argv[2:], check=False)
raise SystemExit(completed.returncode if completed.returncode >= 0 else 128 - completed.returncode)
"""


def _private_regular_file(path: Path, field: str) -> Path:
    resolved = _safe_existing_path(path, field, directory=False)
    metadata = resolved.stat()
    if metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AgentSandboxError(f"{field} must be one owner-private regular file")
    return resolved


def _private_directory(path: Path, field: str, *, create: bool = False) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise AgentSandboxError(f"{field} must be an absolute non-symlink path")
    if create and not candidate.exists():
        try:
            candidate.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise AgentSandboxError(f"{field} cannot be created safely") from exc
    resolved = _safe_existing_path(candidate, field, directory=True)
    metadata = resolved.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AgentSandboxError(f"{field} must be an owner-private directory")
    return resolved


def _private_lock_descriptor(path: Path, field: str) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AgentSandboxError(f"{field} is not safely openable") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise AgentSandboxError(f"{field} must be one owner-private regular file")
    return descriptor


def _codex_sandbox_auth_files(auth_root: Path) -> tuple[Path, Path]:
    candidate = auth_root.expanduser()
    normal_host_root = (Path.home() / ".codex").absolute()
    candidate_absolute = candidate.absolute()
    if candidate_absolute == normal_host_root or candidate_absolute.is_relative_to(
        normal_host_root
    ):
        raise AgentSandboxError(
            "Codex dedicated auth root must be separate from the normal host ~/.codex"
        )
    if not candidate.exists():
        raise AgentSandboxError(
            "Codex dedicated auth root is missing; create it owner-private (mode 0700) "
            "and provision an independent login with "
            f"CODEX_HOME={candidate} codex login --device-auth"
        )
    dedicated_root = _private_directory(candidate, "Codex dedicated auth root")
    auth_file = _private_regular_file(
        dedicated_root / "auth.json", "Codex dedicated auth"
    )
    normal_host_auth = normal_host_root / "auth.json"
    normal_host_auth_file: Path | None = None
    if os.path.lexists(normal_host_auth):
        try:
            resolved_host_auth = normal_host_auth.resolve(strict=True)
            if stat.S_ISREG(resolved_host_auth.stat().st_mode):
                normal_host_auth_file = resolved_host_auth
        except OSError:
            normal_host_auth_file = None
    if (
        normal_host_auth_file is not None
        and (
            os.path.samefile(normal_host_auth_file, auth_file)
            or normal_host_auth_file.read_bytes() == auth_file.read_bytes()
        )
    ):
        raise AgentSandboxError(
            "Codex dedicated auth matches the normal host credential; provision an "
            "independent login instead of copying or linking ~/.codex/auth.json"
        )
    lock_path = dedicated_root / ".auth.lock"
    lock_descriptor = _private_lock_descriptor(lock_path, "Codex dedicated auth lock")
    os.close(lock_descriptor)
    return auth_file, lock_path


def _resolved_executable(value: str, field: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        located = shutil.which(value)
        if located is None:
            raise AgentSandboxError(f"{field} is unavailable: {value}")
        candidate = Path(located)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise AgentSandboxError(f"{field} is not safely resolvable: {value}") from exc
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise AgentSandboxError(f"{field} must resolve to an executable regular file")
    return resolved


def _owner_controlled_executable(value: str, field: str) -> Path:
    resolved = _resolved_executable(value, field)
    metadata = resolved.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AgentSandboxError(
            f"{field} must be owner-controlled and not group/world-writable"
        )
    return resolved


def _owner_controlled_directory(path: Path, field: str) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise AgentSandboxError(f"{field} must be an absolute non-symlink path")
    resolved = _safe_existing_path(candidate, field, directory=True)
    metadata = resolved.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AgentSandboxError(
            f"{field} must be owner-controlled and not group/world-writable"
        )
    return resolved


def _canonical_grok_executable() -> Path:
    """Resolve only the owner-controlled versioned native Grok binary."""
    bin_directory = Path.home() / ".grok" / "bin"
    controlled_bin = _owner_controlled_directory(bin_directory, "Grok binary directory")
    canonical = controlled_bin / "grok"
    try:
        linked = canonical.lstat()
    except OSError as exc:
        raise AgentSandboxError("Grok canonical executable is unavailable") from exc
    if linked.st_uid != os.getuid() or not stat.S_ISLNK(linked.st_mode):
        raise AgentSandboxError("Grok canonical executable must be an owner-controlled symlink")
    executable = _owner_controlled_executable(str(canonical), "Grok executable")
    suffix = executable.name.removeprefix("grok-")
    allowed = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if (
        executable.parent != controlled_bin
        or not executable.name.startswith("grok-")
        or not suffix
        or not suffix[0].isalnum()
        or len(executable.name) > 85
        or any(character not in allowed for character in suffix)
    ):
        raise AgentSandboxError("Grok executable must stay inside the versioned native binary directory")
    return executable


def _grok_command_for_headless_execution(command: list[str]) -> tuple[str, ...]:
    """Turn the catalogued Grok route into its non-interactive single-turn form."""
    if len(command) == 4 and command[1] == "--model" and not command[-1].startswith("-"):
        return (*command[:-1], "-p", command[-1])
    return tuple(command)


def _codex_command_with_protected_tmp(command: list[str]) -> tuple[str, ...]:
    """Keep model-generated Codex commands away from the durable auth mount."""
    index = 1
    while index < len(command):
        item = command[index]
        assignment: str | None = None
        if item in {"-c", "--config"}:
            if index + 1 < len(command):
                assignment = command[index + 1]
                index += 2
            else:
                index += 1
        elif item.startswith("--config="):
            assignment = item.removeprefix("--config=")
            index += 1
        elif item.startswith("-c") and item != "-c":
            assignment = item[2:].removeprefix("=")
            index += 1
        else:
            index += 1
        if assignment is None:
            continue
        key = assignment.split("=", 1)[0].strip()
        if key in _CODEX_WORKSPACE_WRITE_PROTECTED_KEYS:
            raise AgentSandboxError(
                "Codex workspace-write /tmp exclusions are controlled by Grabowski"
            )
    hardened = [command[0]]
    for assignment in _CODEX_WORKSPACE_WRITE_PROTECTED_CONFIG:
        hardened.extend(["-c", assignment])
    hardened.extend(command[1:])
    return tuple(hardened)


def prepare_external_agent_command(command: list[str]) -> PreparedSandboxCommand:
    """Resolve supported external agents into explicit sandbox bindings."""
    if not command:
        raise AgentSandboxError("sandbox command must be non-empty")
    executable_name = Path(command[0]).name
    if executable_name not in {"claude", "codex", "grok"}:
        return PreparedSandboxCommand(tuple(command))
    if executable_name == "grok":
        grok_command = _grok_command_for_headless_execution(command)
        executable_override = os.environ.get("GRABOWSKI_GROK_BIN")
        executable = (
            _owner_controlled_executable(executable_override, "Grok executable")
            if executable_override
            else _canonical_grok_executable()
        )
        auth_root = Path(
            os.environ.get("GRABOWSKI_GROK_AUTH_ROOT", str(Path.home() / ".grok"))
        ).expanduser()
        controlled_auth_root = _owner_controlled_directory(auth_root, "Grok auth root")
        auth_file = _private_regular_file(controlled_auth_root / "auth.json", "Grok auth")
        return PreparedSandboxCommand(
            command=(str(GROK_SANDBOX_EXECUTABLE), *grok_command[1:]),
            extra_read_only=(
                (executable, GROK_SANDBOX_EXECUTABLE),
                (auth_file, GROK_SANDBOX_CONFIG_DIR / "auth.json"),
            ),
            extra_directories=(
                Path("/opt"),
                Path("/opt/grabowski-external"),
                GROK_SANDBOX_CONFIG_DIR,
            ),
            profile=GROK_PROFILE,
            probe_executable=str(GROK_SANDBOX_EXECUTABLE),
        )
    if executable_name == "codex":
        codex_command = _codex_command_with_protected_tmp(command)
        executable_override = os.environ.get("GRABOWSKI_CODEX_BIN")
        executable = _resolved_executable(executable_override or command[0], "Codex executable")
        auth_root = Path(
            os.environ.get(
                "GRABOWSKI_CODEX_AUTH_ROOT",
                str(Path.home() / ".local/state/grabowski/codex-auth"),
            )
        ).expanduser()
        sandbox_auth_file, sandbox_auth_lock = _codex_sandbox_auth_files(auth_root)
        bindings: list[tuple[Path, Path]] = [
            (executable, CODEX_SANDBOX_EXECUTABLE),
        ]
        code_mode_host = executable.parent / "codex-code-mode-host"
        if code_mode_host.exists():
            bindings.append(
                (
                    _resolved_executable(str(code_mode_host), "Codex code mode host"),
                    CODEX_SANDBOX_CODE_MODE_HOST,
                )
            )
        return PreparedSandboxCommand(
            command=(
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                _CODEX_AUTH_SERIALIZED_LAUNCH_SOURCE,
                str(CODEX_SANDBOX_AUTH_LOCK),
                str(CODEX_SANDBOX_EXECUTABLE),
                *codex_command[1:],
            ),
            extra_read_only=tuple(bindings),
            extra_read_write=(
                (sandbox_auth_file, CODEX_SANDBOX_CONFIG_DIR / "auth.json"),
                (sandbox_auth_lock, CODEX_SANDBOX_AUTH_LOCK),
            ),
            extra_directories=(
                Path("/opt"),
                Path("/opt/grabowski-external"),
                CODEX_SANDBOX_CONFIG_DIR,
            ),
            profile=CODEX_PROFILE,
            probe_executable=str(CODEX_SANDBOX_EXECUTABLE),
        )
    executable_override = os.environ.get("GRABOWSKI_CLAUDE_BIN")
    executable = _resolved_executable(executable_override or command[0], "Claude executable")
    auth_root = Path(
        os.environ.get("GRABOWSKI_CLAUDE_AUTH_ROOT", str(Path.home() / ".claude"))
    ).expanduser()
    credentials = _private_regular_file(auth_root / ".credentials.json", "Claude credentials")
    bindings: list[tuple[Path, Path]] = [
        (executable, CLAUDE_SANDBOX_EXECUTABLE),
        (credentials, CLAUDE_SANDBOX_CONFIG_DIR / ".credentials.json"),
    ]
    for source, target, field in (
        (auth_root / "settings.json", CLAUDE_SANDBOX_CONFIG_DIR / "settings.json", "Claude settings"),
        (Path(os.environ.get("GRABOWSKI_CLAUDE_ROOT_CONFIG", str(Path.home() / ".claude.json"))).expanduser(), Path("/tmp/.claude.json"), "Claude root config"),
    ):
        if source.exists():
            bindings.append((_private_regular_file(source, field), target))
    return PreparedSandboxCommand(
        command=(str(CLAUDE_SANDBOX_EXECUTABLE), *command[1:]),
        extra_read_only=tuple(bindings),
        extra_directories=(Path("/opt"), Path("/opt/grabowski-external"), CLAUDE_SANDBOX_CONFIG_DIR),
        profile=CLAUDE_PROFILE,
    )


def _git_command_environment() -> dict[str, str]:
    """Return command-scope Git overrides safe to expose to external agents."""
    environment = {"GIT_CONFIG_COUNT": str(len(_GIT_COMMAND_CONFIG))}
    for index, (key, value) in enumerate(_GIT_COMMAND_CONFIG):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


def safe_git_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    """Return a non-interactive Git environment with executable helpers disabled."""
    environment = dict(os.environ if base is None else base)
    environment.update(
        {
            "LC_ALL": "C",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_ALLOW_PROTOCOL": "ssh:https:file",
        }
    )
    environment.update(_git_command_environment())
    return environment


def runtime_sandbox_argv(arguments: list[str]) -> list[str]:
    """Bind execution to the validated, resolved bubblewrap binary."""
    if not arguments:
        raise AgentSandboxError("sandbox argv is empty")
    result = list(arguments)
    result[0] = str(require_bwrap())
    return result


@dataclass(frozen=True)
class BoundedCapture:
    returncode: int
    stdout_bytes: int
    stderr_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_tail: str
    stderr_tail: str
    stdout_content: bytes | None
    stdout_content_exceeded: bool
    stdout_limit_exceeded: bool
    stderr_limit_exceeded: bool

    @property
    def output_limit_exceeded(self) -> bool:
        return self.stdout_limit_exceeded or self.stderr_limit_exceeded


def require_bwrap() -> Path:
    if not BWRAP.is_absolute() or BWRAP.is_symlink() or not BWRAP.is_file() or not os.access(BWRAP, os.X_OK):
        raise AgentSandboxError(f"bubblewrap unavailable: {BWRAP}")
    return BWRAP.resolve(strict=True)


def _safe_existing_path(value: Path, field: str, *, directory: bool | None = None) -> Path:
    if not value.is_absolute() or value.is_symlink():
        raise AgentSandboxError(f"{field} must be an absolute non-symlink path")
    resolved = value.resolve(strict=True)
    metadata = resolved.stat()
    if directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise AgentSandboxError(f"{field} must be a directory")
    if directory is False and not stat.S_ISREG(metadata.st_mode):
        raise AgentSandboxError(f"{field} must be a regular file")
    return resolved


def _bind_file(arguments: list[str], source: str, target: str | None = None) -> None:
    path = Path(source)
    if path.is_file() and not path.is_symlink():
        arguments.extend(["--ro-bind", source, target or source])


def _bind_fixed_system_file(
    arguments: list[str], source: str, target: str | None = None
) -> None:
    """Resolve one trusted fixed host path and bind its regular file read-only."""
    path = Path(source)
    if not path.is_absolute():
        return
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return
    if not stat.S_ISREG(metadata.st_mode):
        return
    arguments.extend(["--ro-bind", str(resolved), target or source])


def _bind_dir(arguments: list[str], source: str, target: str | None = None) -> None:
    path = Path(source)
    if path.is_dir() and not path.is_symlink():
        arguments.extend(["--ro-bind", source, target or source])


def _validate_writable_tree(target: Path) -> None:
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise AgentSandboxError(f"writable path is not stable: {target}") from exc
    if stat.S_ISREG(metadata.st_mode):
        if metadata.st_nlink != 1:
            raise AgentSandboxError(f"writable path contains a hardlinked file: {target}")
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise AgentSandboxError(f"writable path must be a regular file or directory: {target}")
    root_device = metadata.st_dev
    pending = [target]
    observed = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    observed += 1
                    if observed > MAX_WRITABLE_SCOPE_ENTRIES:
                        raise AgentSandboxError(
                            f"writable path exceeds {MAX_WRITABLE_SCOPE_ENTRIES} entries: {target}"
                        )
                    try:
                        item = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise AgentSandboxError(f"writable path is not stable: {entry.path}") from exc
                    if item.st_dev != root_device:
                        raise AgentSandboxError(
                            f"writable path crosses a filesystem boundary: {entry.path}"
                        )
                    if stat.S_ISLNK(item.st_mode):
                        continue
                    if stat.S_ISDIR(item.st_mode):
                        pending.append(Path(entry.path))
                        continue
                    if not stat.S_ISREG(item.st_mode):
                        raise AgentSandboxError(
                            f"writable path contains a non-regular entry: {entry.path}"
                        )
                    if item.st_nlink != 1:
                        raise AgentSandboxError(
                            f"writable path contains a hardlinked file: {entry.path}"
                        )
        except AgentSandboxError:
            raise
        except OSError as exc:
            raise AgentSandboxError(f"writable path is not stable: {directory}") from exc


def _grosser_adler_inbox_root() -> Path:
    configured = os.environ.get("GROSSER_ADLER_STATE_ROOT")
    if configured:
        state_root = Path(configured).expanduser()
    else:
        state_home = Path(
            os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))
        ).expanduser()
        state_root = state_home / "grosser-adler"
    return state_root / "worktree-inboxes"


def _grabowski_work_lane_root() -> Path:
    configured = os.environ.get("GRABOWSKI_WORK_LANE_ROOT")
    if configured:
        return Path(configured).expanduser()
    state_home = Path(
        os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))
    ).expanduser()
    return state_home / "grabowski" / "work-lanes"


def _json_sha256(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _authenticated_work_lane_target(worktree: Path, lane_id: str) -> bool:
    """Authenticate one untrusted lane id through Grabowski-owned state."""
    receipt_path = _grabowski_work_lane_root() / f"{lane_id}.json"
    try:
        root = _grabowski_work_lane_root()
        root_info = root.lstat()
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) & 0o077
        ):
            return False
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(receipt_path, flags)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > 1_048_576
            ):
                return False
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    return False
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        receipt = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(receipt, dict):
        return False
    if (
        receipt.get("kind") != "grabowski.work_lane"
        or receipt.get("schema_version") != 1
        or receipt.get("lane_id") != lane_id
        or receipt.get("state") != "ready"
        or receipt.get("terminal_closeout") is not None
    ):
        return False
    supplied_receipt_sha = receipt.get("receipt_sha256")
    material = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if (
        not isinstance(supplied_receipt_sha, str)
        or supplied_receipt_sha != _json_sha256(material)
    ):
        return False
    inputs = receipt.get("inputs")
    if (
        not isinstance(inputs, dict)
        or receipt.get("inputs_sha256") != _json_sha256(inputs)
    ):
        return False
    if (
        inputs.get("lane_id") != lane_id
        or inputs.get("lease_owner_id") != f"lane:{lane_id}"
    ):
        return False
    target_path = inputs.get("target_path")
    if not isinstance(target_path, str):
        return False
    try:
        authenticated_target = Path(target_path).expanduser().resolve(strict=True)
    except OSError:
        return False
    return authenticated_target == worktree


def _adler_inbox_sandbox_binding(worktree: Path) -> tuple[tuple[tuple[Path, Path], ...], tuple[Path, ...]]:
    """Expose only one exact worktree inbox target read-only when safely present.

    The worktree-local pointer is Grabowski metadata.  A missing, dangling or
    malformed pointer is deliberately non-blocking: it means unknown Adler
    evidence, never "no findings".
    """
    pointer = worktree / ".adler" / "inbox.json"
    try:
        metadata = pointer.lstat()
        if (
            not stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            return (), ()
        raw_target = os.readlink(pointer)
        target = Path(raw_target)
        root = _grosser_adler_inbox_root().absolute()
        if not target.is_absolute() or target.parent != root:
            return (), ()
        name = target.name
        if (
            not name.endswith(".json")
            or len(name) != 37
            or len(name[:-5]) != 32
            or any(ch not in "0123456789abcdef" for ch in name[:-5])
        ):
            return (), ()
        if not _authenticated_work_lane_target(worktree, name[:-5]):
            return (), ()
        source = _private_regular_file(target, "Großer Adler worktree inbox")
    except (OSError, AgentSandboxError):
        return (), ()
    reserved = {Path("/tmp"), Path("/usr"), Path("/etc"), Path("/proc"), Path("/dev")}
    directories = tuple(
        parent
        for parent in reversed(target.parents)
        if parent != Path("/") and parent not in reserved
    )
    return ((source, target),), directories


def _normalized_writable_paths(worktree: Path, values: Iterable[Path]) -> list[Path]:
    candidates: list[Path] = []
    for value in values:
        target = _safe_existing_path(value, "writable_path")
        try:
            target.relative_to(worktree)
        except ValueError as exc:
            raise AgentSandboxError(f"writable path escapes workspace: {target}") from exc
        if target == worktree:
            raise AgentSandboxError("whole-workspace writable bind is not allowed")
        metadata = target.stat()
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise AgentSandboxError(f"writable path must be a regular file or directory: {target}")
        candidates.append(target)
    unique = sorted(set(candidates), key=lambda item: (len(item.parts), str(item)))
    collapsed: list[Path] = []
    for candidate in unique:
        if any(candidate == parent or candidate.is_relative_to(parent) for parent in collapsed):
            continue
        collapsed.append(candidate)
    for candidate in collapsed:
        _validate_writable_tree(candidate)
    return collapsed


def minimal_sandbox_argv(
    *,
    workspace: Path,
    command: list[str],
    workspace_writable: bool,
    writable_paths: Iterable[Path] = (),
    git_common_dir: Path | None = None,
    extra_read_only: Iterable[tuple[Path, Path]] = (),
    extra_read_only_data_fds: Iterable[tuple[int, Path]] = (),
    extra_read_write: Iterable[tuple[Path, Path]] = (),
    extra_directories: Iterable[Path] = (),
) -> list[str]:
    """Build the sandbox argv without requiring bubblewrap on the build host.

    Availability is checked immediately before execution by ``require_bwrap``.
    This keeps contract tests pure while production remains fail-closed.
    """
    if not command or any(not isinstance(item, str) or not item or "\x00" in item for item in command):
        raise AgentSandboxError("sandbox command must be a non-empty argv list")
    worktree = _safe_existing_path(workspace, "workspace", directory=True)
    common = None if git_common_dir is None else _safe_existing_path(
        git_common_dir,
        "git_common_dir",
        directory=True,
    )
    writable = _normalized_writable_paths(worktree, writable_paths)
    adler_read_only, adler_directories = _adler_inbox_sandbox_binding(worktree)
    if workspace_writable and not writable:
        raise AgentSandboxError("writer sandbox requires at least one bounded writable path")
    if not workspace_writable and writable:
        raise AgentSandboxError("read-only sandbox may not declare writable paths")
    arguments = [
        str(BWRAP),
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
    ]
    if Path("/usr/lib64").exists():
        arguments.extend(["--symlink", "usr/lib64", "/lib64"])
    arguments.extend(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc"])
    normalized_directories: list[str] = []
    for value in (*adler_directories, *tuple(extra_directories)):
        raw = str(value)
        path = Path(raw)
        if not path.is_absolute() or raw in {"/", "/proc", "/dev", "/usr", "/etc"} or "\x00" in raw or ".." in path.parts:
            raise AgentSandboxError("extra sandbox directory must be a safe absolute path")
        normalized_directories.append(raw.rstrip("/"))
    for directory in sorted(set(normalized_directories), key=lambda item: (len(Path(item).parts), item)):
        arguments.extend(["--dir", directory])
    for path in (
        "/etc/ld.so.cache",
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/host.conf",
        "/etc/gai.conf",
    ):
        _bind_file(arguments, path)
    _bind_fixed_system_file(arguments, "/etc/resolv.conf")
    _bind_dir(arguments, "/etc/ssl/certs")
    arguments.extend(["--ro-bind", str(worktree), str(worktree)])
    for target in writable:
        arguments.extend(["--bind", str(target), str(target)])
    if common is not None and common != worktree:
        arguments.extend(["--ro-bind", str(common), str(common)])
    seen_targets = {str(worktree), *(str(item) for item in writable)}
    if common is not None:
        seen_targets.add(str(common))
    for source_value, target_value in (*adler_read_only, *tuple(extra_read_only)):
        source = _safe_existing_path(source_value, "extra_read_only source")
        if not target_value.is_absolute() or "\x00" in str(target_value):
            raise AgentSandboxError("extra_read_only target must be absolute")
        target = str(target_value)
        if target in seen_targets:
            raise AgentSandboxError(f"duplicate sandbox target: {target}")
        seen_targets.add(target)
        arguments.extend(["--ro-bind", str(source), target])
    for fd_value, target_value in extra_read_only_data_fds:
        if isinstance(fd_value, bool) or not isinstance(fd_value, int) or fd_value < 0:
            raise AgentSandboxError("extra_read_only_data_fds fd must be a non-negative integer")
        target_path = Path(target_value)
        target_raw = str(target_path)
        if (
            not target_path.is_absolute()
            or "\x00" in target_raw
            or ".." in target_path.parts
            or target_path == Path("/tmp")
            or not target_path.is_relative_to(Path("/tmp"))
        ):
            raise AgentSandboxError(
                "extra_read_only_data_fds target must be a file path below /tmp"
            )
        target = target_raw
        if target in seen_targets:
            raise AgentSandboxError(f"duplicate sandbox target: {target}")
        seen_targets.add(target)
        arguments.extend(["--perms", "0400", "--ro-bind-data", str(fd_value), target])
    for source_value, target_value in extra_read_write:
        source = _private_regular_file(source_value, "extra_read_write source")
        target_path = Path(target_value)
        if (
            not target_path.is_absolute()
            or "\x00" in str(target_path)
            or target_path == Path("/tmp")
            or not target_path.is_relative_to(Path("/tmp"))
        ):
            raise AgentSandboxError(
                "extra_read_write target must be a private file path below /tmp"
            )
        target = str(target_path)
        if target in seen_targets:
            raise AgentSandboxError(f"duplicate sandbox target: {target}")
        seen_targets.add(target)
        arguments.extend(["--bind", str(source), target])
    arguments.extend(
        [
            "--clearenv",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--setenv",
            "GIT_TERMINAL_PROMPT",
            "0",
            "--setenv",
            "GIT_OPTIONAL_LOCKS",
            "0",
        ]
    )
    for key, value in _git_command_environment().items():
        arguments.extend(["--setenv", key, value])
    arguments.extend(
        [
            "--chdir",
            str(worktree),
            "--",
            *command,
        ]
    )
    return arguments


def _append_tail(buffer: bytearray, chunk: bytes, limit: int = TAIL_BYTES) -> None:
    buffer.extend(chunk)
    if len(buffer) > limit:
        del buffer[:-limit]


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_bounded_capture(
    argv: list[str],
    *,
    stdout_limit: int,
    stderr_limit: int,
    stdout_content_limit: int = 0,
    stdin_content: bytes | None = None,
) -> BoundedCapture:
    """Drain both streams while optionally supplying bounded caller-owned stdin bytes."""
    if stdout_limit <= 0 or stderr_limit <= 0 or stdout_content_limit < 0:
        raise ValueError("capture limits must be positive")
    if stdin_content is not None and not isinstance(stdin_content, bytes):
        raise TypeError("stdin_content must be bytes or None")
    stdin_file = None
    if stdin_content is not None:
        stdin_file = tempfile.TemporaryFile()
        try:
            stdin_file.write(stdin_content)
            stdin_file.flush()
            stdin_file.seek(0)
        except BaseException:
            stdin_file.close()
            raise
    try:
        process = subprocess.Popen(
            argv,
            stdin=stdin_file if stdin_file is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    finally:
        if stdin_file is not None:
            stdin_file.close()
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        process.wait()
        raise AgentSandboxError("could not create bounded output pipes")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    counts = {"stdout": 0, "stderr": 0}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    hashes = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    tails = {"stdout": bytearray(), "stderr": bytearray()}
    stdout_content = bytearray()
    stdout_content_exceeded = False
    exceeded = {"stdout": False, "stderr": False}
    killed = False
    try:
        while selector.get_map():
            events = selector.select(timeout=1.0)
            if not events and process.poll() is not None:
                _kill_process_group(process)
                for registered in list(selector.get_map().values()):
                    stream_to_close = registered.fileobj
                    try:
                        selector.unregister(stream_to_close)
                    except Exception:
                        pass
                    stream_to_close.close()
                break
            for key, _ in events:
                stream = key.fileobj
                name = key.data
                chunk = os.read(stream.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                counts[name] += len(chunk)
                hashes[name].update(chunk)
                _append_tail(tails[name], chunk)
                if counts[name] > limits[name]:
                    exceeded[name] = True
                if name == "stdout" and stdout_content_limit:
                    if len(stdout_content) + len(chunk) <= stdout_content_limit:
                        stdout_content.extend(chunk)
                    else:
                        stdout_content_exceeded = True
                        stdout_content.clear()
                if any(exceeded.values()) and not killed:
                    _kill_process_group(process)
                    killed = True
                    for registered in list(selector.get_map().values()):
                        stream_to_close = registered.fileobj
                        try:
                            selector.unregister(stream_to_close)
                        except Exception:
                            pass
                        stream_to_close.close()
                    break
            if killed:
                break
        try:
            returncode = process.wait(timeout=5 if killed else None)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            returncode = process.wait(timeout=5)
    finally:
        selector.close()
        _kill_process_group(process)
        if process.poll() is None:
            process.wait()
    return BoundedCapture(
        returncode=returncode,
        stdout_bytes=counts["stdout"],
        stderr_bytes=counts["stderr"],
        stdout_sha256=hashes["stdout"].hexdigest(),
        stderr_sha256=hashes["stderr"].hexdigest(),
        stdout_tail=bytes(tails["stdout"]).decode("utf-8", errors="replace"),
        stderr_tail=bytes(tails["stderr"]).decode("utf-8", errors="replace"),
        stdout_content=(bytes(stdout_content) if stdout_content_limit and not stdout_content_exceeded else None),
        stdout_content_exceeded=stdout_content_exceeded,
        stdout_limit_exceeded=exceeded["stdout"],
        stderr_limit_exceeded=exceeded["stderr"],
    )
