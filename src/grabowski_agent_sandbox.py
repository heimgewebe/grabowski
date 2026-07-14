from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
from typing import Iterable

BWRAP = Path(os.environ.get("GRABOWSKI_BWRAP_BIN", "/usr/bin/bwrap"))
TAIL_BYTES = 12000
MAX_WRITABLE_SCOPE_ENTRIES = 100_000


class AgentSandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedSandboxCommand:
    command: tuple[str, ...]
    extra_read_only: tuple[tuple[Path, Path], ...] = ()
    extra_directories: tuple[Path, ...] = ()
    profile: str | None = None


CLAUDE_PROFILE = "claude-cli-readonly-auth-v1"
CLAUDE_SANDBOX_EXECUTABLE = Path("/opt/grabowski-external/claude")
CLAUDE_SANDBOX_CONFIG_DIR = Path("/tmp/.claude")


def _private_regular_file(path: Path, field: str) -> Path:
    resolved = _safe_existing_path(path, field, directory=False)
    metadata = resolved.stat()
    if metadata.st_uid != os.getuid() or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AgentSandboxError(f"{field} must be one owner-private regular file")
    return resolved


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


def prepare_external_agent_command(command: list[str]) -> PreparedSandboxCommand:
    """Resolve supported external agents into explicit, read-only sandbox bindings."""
    if not command:
        raise AgentSandboxError("sandbox command must be non-empty")
    if Path(command[0]).name != "claude":
        return PreparedSandboxCommand(tuple(command))
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


def safe_git_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    """Return a non-interactive Git environment with executable helpers disabled."""
    environment = dict(os.environ if base is None else base)
    command_config = [
        ("core.hooksPath", "/dev/null"),
        ("core.fsmonitor", "false"),
    ]
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
            "GIT_CONFIG_COUNT": str(len(command_config)),
        }
    )
    for index, (key, value) in enumerate(command_config):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
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
    for value in extra_directories:
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
    for source_value, target_value in extra_read_only:
        source = _safe_existing_path(source_value, "extra_read_only source")
        if not target_value.is_absolute() or "\x00" in str(target_value):
            raise AgentSandboxError("extra_read_only target must be absolute")
        target = str(target_value)
        if target in seen_targets:
            raise AgentSandboxError(f"duplicate sandbox target: {target}")
        seen_targets.add(target)
        arguments.extend(["--ro-bind", str(source), target])
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
) -> BoundedCapture:
    """Drain both streams without imposing RLIMIT_FSIZE on the child workload."""
    if stdout_limit <= 0 or stderr_limit <= 0 or stdout_content_limit < 0:
        raise ValueError("capture limits must be positive")
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
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
