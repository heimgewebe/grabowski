from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from typing import Any

from grabowski_agent_sandbox import minimal_sandbox_argv, prepare_external_agent_command, runtime_sandbox_argv, safe_git_environment, run_bounded_capture

SHA40 = __import__("re").compile(r"^[0-9a-f]{40}$")
SHA256 = __import__("re").compile(r"^[0-9a-f]{64}$")
MAX_ROLE_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_REVIEW_JSON_BYTES = 1024 * 1024
MAX_GROK_REVIEW_STREAM_BYTES = 2 * 1024 * 1024
MAX_UNTRACKED_FILE_BYTES = 16 * 1024 * 1024
MAX_UNTRACKED_TOTAL_BYTES = 64 * 1024 * 1024
SANDBOX_LABEL = "bubblewrap-minimal-root-read-only-worktree-v1"
TOOLCHAIN_PROBE_OUTPUT_LIMIT = 64 * 1024
TOOLCHAIN_PROBE_CONTRACT = "role-toolchain-probe-v2"
REVIEW_DOCUMENT_CONTRACT = "review-document-wrapper-v2"
GROK_REVIEW_STREAM_CONTRACT = "grok-streaming-json-readonly-review-v1"
GROK_REVIEW_TOOL_NAMES = frozenset({"run_terminal_command"})
GROK_REVIEW_TOOLS = "run_terminal_cmd"
GROK_REVIEW_MAX_TURNS = 8
GROK_REVIEW_EVENT_TYPES = frozenset(
    {
        "text",
        "thought",
        "usage",
        "available_commands",
        "tool_call",
        "tool_call_update",
        "max_turns_reached",
        "end",
    }
)
GROK_REVIEW_ALLOW_RULES = (
    "Bash(git status --short --branch*)",
    "Bash(git diff --no-ext-diff --no-textconv*)",
    "Bash(git cat-file blob*)",
    "Bash(git rev-parse*)",
    "Bash(git merge-base*)",
    "Bash(git ls-files*)",
)
GROK_REVIEW_DENY_RULES = (
    "Bash(*;*)",
    "Bash(*&*)",
    "Bash(*&&*)",
    "Bash(*||*)",
    "Bash(*|*)",
    "Bash(*`*)",
    "Bash(*$*)",
    "Bash(*>*)",
    "Bash(*<*)",
    "Bash(*.grok*)",
    "Bash(*auth.json*)",
    "Bash(*--ext-diff*)",
    "Bash(*--textconv*)",
    "Bash(*--no-index*)",
    "Bash(*--output*)",
)
GROK_REVIEW_PROMPT_SUFFIX = (
    "\n\nGrabowski review contract: inspect the repository with at least one of the "
    "available read-only tools before deciding. Do not modify files or state. "
    "Your final response must end with exactly one JSON object containing "
    "verdict (PASS, NEEDS_CHANGE, or BLOCK) and findings (an array of objects). "
    "PASS requires an empty findings array; non-PASS requires at least one finding. "
    "Do not wrap the final JSON object in Markdown or code fences. "
    "For repository inspection, use only these safe command forms: "
    "git status --short --branch; git diff --no-ext-diff --no-textconv ...; "
    "git cat-file blob REV:path; git rev-parse ...; git merge-base ...; "
    "git ls-files ...."
)
PYTHON_EXECUTABLE_NAMES = frozenset(
    {"python", "python3"} | {f"python3.{minor}" for minor in range(0, 20)}
)
_EXECUTABLE_PROBE_SOURCE = (
    "import json, shutil, sys\n"
    "executable = sys.argv[1]\n"
    "resolved = shutil.which(executable)\n"
    "sys.stdout.write(json.dumps({\n"
    "    'executable_found': resolved is not None,\n"
    "    'resolved_executable': resolved,\n"
    "}))\n"
)
_MODULE_PROBE_SOURCE = (
    "import importlib.machinery, json, os, pathlib, sys, sysconfig\n"
    "module = sys.argv[1]\n"
    "invoked_executable = pathlib.Path(sys.argv[2])\n"
    "version = f'python{sys.version_info.major}.{sys.version_info.minor}'\n"
    "environment_root = invoked_executable.parent.parent\n"
    "search_paths = [os.getcwd(), *sys.path]\n"
    "for key in ('purelib', 'platlib'):\n"
    "    candidate = sysconfig.get_paths().get(key)\n"
    "    if candidate:\n"
    "        search_paths.append(candidate)\n"
    "search_paths.extend([\n"
    "    str(environment_root / 'lib' / version / 'site-packages'),\n"
    "    str(environment_root / 'lib64' / version / 'site-packages'),\n"
    "])\n"
    "search_paths = list(dict.fromkeys(path for path in search_paths if path))\n"
    "try:\n"
    "    spec = importlib.machinery.BuiltinImporter.find_spec(module)\n"
    "    if spec is None:\n"
    "        spec = importlib.machinery.FrozenImporter.find_spec(module)\n"
    "    if spec is None:\n"
    "        spec = importlib.machinery.PathFinder.find_spec(module, search_paths)\n"
    "except (ImportError, ValueError, ModuleNotFoundError, TypeError):\n"
    "    spec = None\n"
    "sys.stdout.write(json.dumps({'module_found': spec is not None}))\n"
)


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        stderr=subprocess.STDOUT,
        timeout=30,
        env=safe_git_environment(),
    )


def git_text(repo: Path, *args: str) -> str:
    return git(repo, *args).decode("utf-8", errors="surrogateescape").strip()


def safe_untracked_file(root: Path, relative: PurePosixPath) -> Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise RuntimeError(f"unsafe untracked path: {relative}")
    current = root
    for part in relative.parts:
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"untracked path crosses a symlink: {relative}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError(f"untracked path must be one regular non-hardlinked file: {relative}")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"untracked path escapes repository: {relative}") from exc
    return resolved


def current_binding(repo: Path, base: str) -> tuple[str, str, bool]:
    head = git_text(repo, "rev-parse", "HEAD").lower()
    committed = git(repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", f"{base}...{head}")
    working = git(repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD")
    raw = git(repo, "ls-files", "--others", "--exclude-standard", "-z")
    untracked: list[dict[str, Any]] = []
    dirty = bool(working)
    total = 0
    for raw_relative in [item for item in raw.split(b"\x00") if item]:
        relative = PurePosixPath(os.fsdecode(raw_relative))
        target = safe_untracked_file(repo, relative)
        size = target.stat().st_size
        if size > MAX_UNTRACKED_FILE_BYTES:
            raise RuntimeError(f"untracked file exceeds safety boundary: {relative}")
        total += size
        if total > MAX_UNTRACKED_TOTAL_BYTES:
            raise RuntimeError("untracked files exceed aggregate safety boundary")
        untracked.append(
            {
                "path": relative.as_posix(),
                "size": size,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
        )
        dirty = True
    return head, digest(
        {
            "base_head": base,
            "head": head,
            "branch": git_text(repo, "branch", "--show-current"),
            "committed_diff_sha256": hashlib.sha256(committed).hexdigest(),
            "working_diff_sha256": hashlib.sha256(working).hexdigest(),
            "untracked": untracked,
        }
    ), dirty


def write_receipt(path: Path, payload: dict[str, Any], *, create_only: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise PermissionError("role receipt target must be one owner-controlled regular file")
        if create_only:
            raise FileExistsError("role attempt receipt already exists")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            handle = os.fdopen(descriptor, "w", encoding="utf-8")
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        with handle:
            json.dump(payload, handle, ensure_ascii=True, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if create_only:
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError as exc:
                raise FileExistsError("role attempt receipt already exists") from exc
            temporary.unlink()
        else:
            os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _declared_virtualenv_binding(repo: Path, command: list[str]) -> tuple[list[tuple[Path, Path]], list[Path]]:
    """Bind one explicitly invoked Python virtualenv read-only, never a broad home tree."""
    if not command:
        return [], []
    executable = Path(command[0]).expanduser()
    if not executable.is_absolute():
        return [], []
    try:
        declared = executable.resolve(strict=True)
        repo_root = repo.resolve(strict=True)
    except OSError:
        return [], []
    candidates = [executable.parent.parent, declared.parent.parent]
    declared_root = next(
        (
            candidate
            for candidate in candidates
            if (candidate / "pyvenv.cfg").is_file()
        ),
        None,
    )
    if declared_root is None:
        return [], []
    source_root = declared_root.resolve(strict=True)
    target_root = declared_root.absolute()
    if source_root == repo_root or source_root.is_relative_to(repo_root):
        return [], []
    if source_root == Path("/") or source_root.is_relative_to(Path("/usr")):
        return [], []
    directories = [
        parent
        for parent in reversed(target_root.parents)
        if parent != Path("/") and parent.is_dir()
    ]
    return [(source_root, target_root)], directories


def sandbox_argv(repo: Path, command: list[str], *, declared_command: list[str] | None = None) -> list[str]:
    common_raw = git_text(repo, "rev-parse", "--git-common-dir")
    common = Path(common_raw)
    if not common.is_absolute():
        common = (repo / common).resolve(strict=True)
    declared = command if declared_command is None else declared_command
    prepared = prepare_external_agent_command(declared)
    actual_command = list(prepared.command) if declared_command is None else command
    venv_read_only, venv_directories = _declared_virtualenv_binding(repo, declared)
    return minimal_sandbox_argv(
        workspace=repo,
        command=actual_command,
        workspace_writable=False,
        git_common_dir=common,
        extra_read_only=(*prepared.extra_read_only, *venv_read_only),
        extra_read_write=prepared.extra_read_write,
        extra_directories=(*prepared.extra_directories, *venv_directories),
    )


def declared_python_module(command: list[str]) -> str | None:
    """Return one safe top-level module declared by a literal Python ``-m`` call."""
    if len(command) < 3 or Path(command[0]).name not in PYTHON_EXECUTABLE_NAMES or command[1] != "-m":
        return None
    module = command[2]
    if not module or module.startswith("-") or "/" in module or "\x00" in module:
        return None
    return module.split(".", 1)[0]


def _probe_json_from_argv(
    sandbox_arguments: list[str],
) -> tuple[dict[str, Any] | None, str | None, int | None]:
    try:
        completed = run_bounded_capture(
            runtime_sandbox_argv(sandbox_arguments),
            stdout_limit=TOOLCHAIN_PROBE_OUTPUT_LIMIT,
            stderr_limit=TOOLCHAIN_PROBE_OUTPUT_LIMIT,
            stdout_content_limit=TOOLCHAIN_PROBE_OUTPUT_LIMIT,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"[:4000], None
    if (
        completed.returncode != 0
        or completed.output_limit_exceeded
        or completed.stdout_content is None
        or completed.stdout_content_exceeded
    ):
        return None, "toolchain probe did not complete cleanly", completed.returncode
    try:
        payload = json.loads(completed.stdout_content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"toolchain probe returned invalid JSON: {exc}", completed.returncode
    if not isinstance(payload, dict):
        return None, "toolchain probe returned a non-object payload", completed.returncode
    return payload, None, completed.returncode


def _probe_json(repo: Path, command: list[str]) -> tuple[dict[str, Any] | None, str | None, int | None]:
    return _probe_json_from_argv(sandbox_argv(repo, command))


def _probe_json_for_declared_command(
    repo: Path, command: list[str], declared_command: list[str]
) -> tuple[dict[str, Any] | None, str | None, int | None]:
    return _probe_json_from_argv(
        sandbox_argv(repo, command, declared_command=declared_command)
    )


def _sandbox_probe_python() -> str:
    """Return a Python interpreter present in the minimal ``/usr`` sandbox.

    The MCP service may itself run from a private virtualenv below ``$HOME``.
    That path is intentionally absent from role sandboxes and therefore may not
    be used as the probe runner.
    """
    usr_root = Path("/usr")
    candidates = [Path(sys.executable), Path("/usr/bin/python3")]
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if not resolved.is_relative_to(usr_root):
            continue
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
    raise RuntimeError("no Python interpreter is available inside the minimal role sandbox")


def toolchain_probe(repo: Path, command: list[str]) -> dict[str, Any]:
    """Resolve declared prerequisites inside the exact read-only role sandbox."""
    prepared = prepare_external_agent_command(command)
    executable = prepared.probe_executable or prepared.command[0]
    module = declared_python_module(command)
    result: dict[str, Any] = {
        "executable": executable,
        "resolved_executable": None,
        "declared_python_module": module,
        "passed": False,
        "missing_executable": False,
        "missing_python_module": False,
        "probe_error": None,
        "external_agent_profile": prepared.profile,
    }
    executable_probe = [
        _sandbox_probe_python(),
        "-I",
        "-S",
        "-c",
        _EXECUTABLE_PROBE_SOURCE,
        executable,
    ]
    venv_read_only, _venv_directories = _declared_virtualenv_binding(repo, command)
    if prepared.profile is None and not venv_read_only:
        executable_payload, error, returncode = _probe_json(repo, executable_probe)
    else:
        executable_payload, error, returncode = _probe_json_for_declared_command(
            repo, executable_probe, command
        )
    if error is not None or executable_payload is None:
        result["probe_error"] = error
        result["probe_returncode"] = returncode
        result["failure_classification"] = "toolchain_probe_error"
        return result
    resolved = executable_payload.get("resolved_executable")
    executable_found = (
        executable_payload.get("executable_found") is True
        and isinstance(resolved, str)
        and bool(resolved)
    )
    result["resolved_executable"] = resolved if executable_found else None
    if not executable_found:
        result.update(
            {
                "missing_executable": True,
                "probe_returncode": returncode,
                "failure_classification": "environment_toolchain_failure",
            }
        )
        return result
    module_found = True
    if module is not None:
        module_probe = [
            resolved,
            "-I",
            "-S",
            "-c",
            _MODULE_PROBE_SOURCE,
            module,
            resolved,
        ]
        if prepared.profile is None and not venv_read_only:
            module_payload, module_error, module_returncode = _probe_json(repo, module_probe)
        else:
            module_payload, module_error, module_returncode = _probe_json_for_declared_command(
                repo, module_probe, command
            )
        if module_error is not None or module_payload is None:
            result["probe_error"] = module_error
            result["probe_returncode"] = module_returncode
            result["failure_classification"] = "toolchain_probe_error"
            return result
        module_found = module_payload.get("module_found") is True
        returncode = module_returncode
    result.update(
        {
            "passed": module_found,
            "missing_python_module": module is not None and not module_found,
            "probe_returncode": returncode,
            "failure_classification": (
                "passed" if module_found else "environment_toolchain_failure"
            ),
        }
    )
    return result


def _normalize_review_object(
    review: Any,
) -> tuple[str | None, list[dict[str, Any]] | None, str | None, bool]:
    """Normalize only the historically common empty-object findings shape."""
    if not isinstance(review, dict):
        return None, None, "review stdout must be one JSON object", False
    verdict = review.get("verdict")
    findings = review.get("findings")
    normalized_empty_object = findings == {}
    if normalized_empty_object:
        findings = []
    if verdict not in {"PASS", "NEEDS_CHANGE", "BLOCK"}:
        return None, None, "review object must contain a valid verdict", normalized_empty_object
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        return None, None, "review findings must be a list of objects or an empty object", normalized_empty_object
    return verdict, findings, None, normalized_empty_object


def _grok_streaming_review_command(
    prepared_command: tuple[str, ...],
    *,
    expected_head: str,
    expected_base_head: str,
) -> tuple[str, ...]:
    """Run Grok reviews as bounded read-only tool sessions with event evidence."""
    if SHA40.fullmatch(expected_head) is None or SHA40.fullmatch(expected_base_head) is None:
        raise RuntimeError("Grok review requires exact bound head and base revisions")
    command = list(prepared_command)
    if command.count("-p") != 1:
        raise RuntimeError("Grok review command must contain exactly one single-turn prompt")
    prompt_index = command.index("-p")
    if prompt_index != len(command) - 2:
        raise RuntimeError("Grok review prompt must be the final command argument")
    controlled = {
        "--always-approve",
        "--yolo",
        "--dangerously-skip-permissions",
        "--permission-mode",
        "--allow",
        "--deny",
        "--disable-web-search",
        "--no-subagents",
        "--sandbox",
        "--tools",
        "--disallowed-tools",
        "--output-format",
        "--max-turns",
        "--json-schema",
    }
    if any(
        item in controlled
        or any(item.startswith(f"{option}=") for option in controlled)
        for item in command
    ):
        raise RuntimeError("Grok review execution framing is controlled by Grabowski")
    prompt = (
        command[-1]
        + GROK_REVIEW_PROMPT_SUFFIX
        + " The bound head is "
        + expected_head.lower()
        + " and the bound base is "
        + expected_base_head.lower()
        + ". Run one Git command per tool call. Do not use shell control operators, "
          "redirections, command substitution, or pipes. Do not use git log. The revision binding is "
          "already known; do not rediscover it. Inspect the complete bound diff in one "
          "separate tool call using exactly: git diff --no-ext-diff --no-textconv "
        + expected_base_head.lower()
        + "..."
        + expected_head.lower()
        + ". Treat the complete bound diff as primary evidence. Use additional safe Git "
          "reads only as separate tool calls when one specific material uncertainty cannot be "
          "resolved from the diff. Hard limit: at most four tool calls total. Never repeat a "
          "command. Do not request name-status after reading the complete diff. Do not re-read "
          "an entire changed file unless that specific material uncertainty requires it. Reserve "
          "the final turn for the required JSON verdict. After the bounded inspection, stop "
          "reading and immediately return the final JSON. If material uncertainty remains, "
          "return NEEDS_CHANGE or BLOCK instead of consuming more turns."
    )
    command[-1] = prompt
    review_flags = [
        "--disable-web-search",
        "--no-subagents",
        "--sandbox",
        "read-only",
        "--tools",
        GROK_REVIEW_TOOLS,
    ]
    for rule in GROK_REVIEW_ALLOW_RULES:
        review_flags.extend(["--allow", rule])
    for rule in GROK_REVIEW_DENY_RULES:
        review_flags.extend(["--deny", rule])
    review_flags.extend(
        [
            "--output-format",
            "streaming-json",
            "--max-turns",
            str(GROK_REVIEW_MAX_TURNS),
        ]
    )
    command[prompt_index:prompt_index] = review_flags
    return tuple(command)


def _review_sandbox_argv(
    repo: Path,
    command: list[str],
    *,
    expected_head: str,
    expected_base_head: str,
) -> tuple[list[str], str | None]:
    if Path(command[0]).name != "grok":
        return sandbox_argv(repo, command), None
    prepared = prepare_external_agent_command(command)
    actual = list(
        _grok_streaming_review_command(
            prepared.command,
            expected_head=expected_head,
            expected_base_head=expected_base_head,
        )
    )
    return (
        sandbox_argv(repo, actual, declared_command=command),
        GROK_REVIEW_STREAM_CONTRACT,
    )


def _terminal_json_object(text: str) -> dict[str, Any] | None:
    """Return the unique JSON object suffix of terminal assistant text."""
    stripped = text.rstrip()
    candidates: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    for index, character in enumerate(stripped):
        if character != "{":
            continue
        try:
            value, consumed = decoder.raw_decode(stripped[index:])
        except json.JSONDecodeError:
            continue
        if stripped[index + consumed :].strip():
            continue
        if isinstance(value, dict):
            candidates.append(value)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _safe_grok_git_read_command(command: str) -> bool:
    """Accept only shell-free, read-only Git command forms used by Grok reviews."""
    shell_expansion_markers = (
        "\n", "\r", ";", "&", "|", "`", "$", ">", "<",
        "*", "?", "[", "]", "{", "}",
    )
    if not command or any(marker in command for marker in shell_expansion_markers):
        return False
    if ".grok" in command or "auth.json" in command:
        return False
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return False
    if any(".grok" in argument or "auth.json" in argument for argument in argv):
        return False
    if len(argv) < 2 or argv[0] != "git":
        return False
    for argument in argv[2:]:
        path_value = argument.split("=", 1)[-1]
        if path_value.startswith(("/", "~")) or ".." in PurePosixPath(path_value).parts:
            return False
    subcommand = argv[1]
    if subcommand == "status":
        return argv == ["git", "status", "--short", "--branch"]
    if subcommand == "diff":
        if argv[:4] != ["git", "diff", "--no-ext-diff", "--no-textconv"]:
            return False
        forbidden_diff_options = ("--ext-diff", "--textconv", "--no-index")
        if any(item in forbidden_diff_options or item.startswith("--output") for item in argv[4:]):
            return False
        return True
    if subcommand == "cat-file":
        return len(argv) == 4 and argv[:3] == ["git", "cat-file", "blob"]
    if subcommand == "ls-files":
        separator_seen = False
        for argument in argv[2:]:
            if argument == "--":
                if separator_seen:
                    return False
                separator_seen = True
                continue
            if not separator_seen and argument.startswith("-"):
                return False
        return True
    return subcommand in {"rev-parse", "merge-base"}


def _extract_grok_stream_review_document(
    raw: bytes,
) -> tuple[bytes | None, str | None, dict[str, Any]]:
    metadata: dict[str, Any] = {
        "review_provider_stream_contract": GROK_REVIEW_STREAM_CONTRACT,
        "review_provider_stream_bytes": len(raw),
        "review_provider_stream_sha256": hashlib.sha256(raw).hexdigest(),
    }
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return None, f"Grok review stream is not valid UTF-8: {exc}", metadata
    events: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            return None, f"Grok review stream line {line_number} is invalid JSON: {exc}", metadata
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            return None, f"Grok review stream line {line_number} is not a typed object", metadata
        events.append(event)
    metadata["review_provider_stream_events"] = len(events)
    if not events:
        return None, "Grok review stream is empty", metadata

    tool_names: dict[str, str] = {}
    tool_commands: dict[str, str] = {}
    completed_tools: list[str] = []
    completed_commands: list[str] = []
    completed_call_ids: set[str] = set()
    last_completed_index = -1
    end_events: list[tuple[int, dict[str, Any]]] = []
    for index, event in enumerate(events):
        event_type = event.get("type")
        if event_type not in GROK_REVIEW_EVENT_TYPES:
            return None, f"Grok review stream used unsupported event type: {event_type}", metadata
        if event_type == "tool_call":
            call_id = event.get("toolCallId")
            tool_name = event.get("toolName")
            if not isinstance(call_id, str) or not call_id or not isinstance(tool_name, str):
                return None, "Grok review tool_call is missing identity", metadata
            if call_id in tool_names:
                return None, "Grok review reused a tool call identity", metadata
            if tool_name not in GROK_REVIEW_TOOL_NAMES:
                return None, f"Grok review used disallowed tool: {tool_name}", metadata
            raw_input = event.get("rawInput")
            tool_command = raw_input.get("command") if isinstance(raw_input, dict) else None
            if not isinstance(tool_command, str) or not _safe_grok_git_read_command(tool_command):
                return None, "Grok review requested a non-read-only Git command", metadata
            tool_names[call_id] = tool_name
            tool_commands[call_id] = tool_command
        elif event_type == "tool_call_update" and event.get("status") in {"failed", "cancelled"}:
            call_id = event.get("toolCallId")
            if not isinstance(call_id, str) or call_id not in tool_names:
                return None, "Grok review failed or cancelled an unknown tool call", metadata
            return None, "Grok review repository tool call did not complete", metadata
        elif event_type == "tool_call_update" and event.get("status") == "completed":
            call_id = event.get("toolCallId")
            if not isinstance(call_id, str) or call_id not in tool_names:
                return None, "Grok review completed an unknown tool call", metadata
            if call_id in completed_call_ids:
                return None, "Grok review completed a tool call more than once", metadata
            tool_name = tool_names[call_id]
            raw_output = event.get("rawOutput")
            if not isinstance(raw_output, dict) or raw_output.get("exit_code") != 0:
                return None, "Grok review Git command did not succeed", metadata
            observed_command = raw_output.get("command")
            if observed_command != tool_commands[call_id]:
                return None, "Grok review Git command changed between request and completion", metadata
            completed_tools.append(tool_name)
            completed_commands.append(tool_commands[call_id])
            completed_call_ids.add(call_id)
            last_completed_index = index
        elif event_type == "end":
            end_events.append((index, event))
    metadata["review_provider_completed_tool_calls"] = len(completed_tools)
    metadata["review_provider_completed_tools"] = completed_tools
    metadata["review_provider_completed_commands"] = completed_commands
    if not completed_tools:
        return None, "Grok review completed no read-only repository tool call", metadata
    if set(tool_names) != completed_call_ids:
        return None, "Grok review left a repository tool call incomplete", metadata
    if len(end_events) != 1 or end_events[0][0] != len(events) - 1:
        return None, "Grok review stream must end with exactly one end event", metadata
    end_event = end_events[0][1]
    if end_event.get("stopReason") != "end_turn":
        return None, "Grok review stream did not finish with end_turn", metadata
    turns = end_event.get("num_turns")
    if not isinstance(turns, int) or isinstance(turns, bool) or turns < 2:
        return None, "Grok review stream did not establish a tool-using multi-turn review", metadata
    metadata["review_provider_num_turns"] = turns

    terminal_text = "".join(
        event.get("data", "")
        for event in events[last_completed_index + 1 : -1]
        if event.get("type") == "text" and isinstance(event.get("data"), str)
    )
    metadata["review_provider_terminal_text_sha256"] = hashlib.sha256(
        terminal_text.encode("utf-8")
    ).hexdigest()
    review = _terminal_json_object(terminal_text)
    if review is None:
        return None, "Grok review terminal text has no unique JSON object suffix", metadata
    metadata["review_provider_terminal_object_sha256"] = digest(review)
    return canonical(review).encode("utf-8"), None, metadata


def parse_review_document(
    raw: bytes,
) -> tuple[str | None, list[dict[str, Any]] | None, str | None, dict[str, Any]]:
    """Turn bounded agent output into a canonical Grabowski review document."""
    metadata: dict[str, Any] = {
        "review_document_contract": REVIEW_DOCUMENT_CONTRACT,
        "review_document_bytes": len(raw),
        "review_document_sha256": hashlib.sha256(raw).hexdigest(),
        "review_document_normalizations": [],
        "review_receipt_generated_by": "grabowski_agent_role",
    }
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return None, None, f"review stdout is not valid UTF-8: {exc}", metadata
    try:
        review = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, None, f"review stdout is not one JSON object: {exc}", metadata
    verdict, findings, error, normalized_empty_object = _normalize_review_object(review)
    if normalized_empty_object:
        metadata["review_document_normalizations"] = [
            "findings_empty_object_to_empty_list"
        ]
    metadata["review_findings_normalized"] = normalized_empty_object
    metadata["review_document_object_sha256"] = digest(review) if isinstance(review, dict) else None
    return verdict, findings, error, metadata


def classify_result(role: str, command: list[str], repo: Path, payload: dict[str, Any]) -> str:
    """Classify one final role result without trusting user-controlled output text."""
    returncode = payload.get("returncode")
    if payload.get("error") == "read-only role observed writer mutation":
        return "writer_binding_violation"
    if payload.get("error") == "role stdout or stderr exceeded the bounded capture limit":
        return "output_limit_exceeded"
    if role == "review":
        verdict = payload.get("verdict")
        if verdict in {"NEEDS_CHANGE", "BLOCK"}:
            return "review_verdict"
        if verdict == "PASS" and returncode == 0:
            return "passed"
    elif returncode == 0:
        return "passed"
    if isinstance(returncode, int) and not isinstance(returncode, bool) and returncode != 0:
        probe = toolchain_probe(repo, command)
        payload["post_failure_toolchain_probe"] = probe
        if probe.get("failure_classification") == "environment_toolchain_failure":
            return "environment_toolchain_failure"
    if role == "review":
        if payload.get("verdict") == "INVALID" or returncode == 126:
            return "invalid_review_output"
        return "review_execution_failure"
    return "semantic_test_failure"

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("tests", "review"), required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-base-head", required=True)
    parser.add_argument("--expected-diff-sha256", required=True)
    parser.add_argument("--expected-dirty", choices=("true", "false"), required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    repo = Path(args.repository).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    if (
        not command
        or SHA40.fullmatch(args.expected_head) is None
        or SHA40.fullmatch(args.expected_base_head) is None
        or SHA256.fullmatch(args.expected_diff_sha256) is None
    ):
        parser.error("invalid command or binding")
    expected_dirty = args.expected_dirty == "true"
    before_head, before_diff, before_dirty = current_binding(repo, args.expected_base_head)
    if (
        before_head != args.expected_head
        or before_diff != args.expected_diff_sha256
        or before_dirty != expected_dirty
    ):
        raise RuntimeError("writer binding changed before read-only role start")
    review_provider_contract: str | None = None
    if args.role == "review":
        role_sandbox_argv, review_provider_contract = _review_sandbox_argv(
            repo,
            command,
            expected_head=args.expected_head,
            expected_base_head=args.expected_base_head,
        )
    else:
        role_sandbox_argv = sandbox_argv(repo, command)
    review_content_limit = 0
    if args.role == "review":
        review_content_limit = (
            MAX_GROK_REVIEW_STREAM_BYTES
            if review_provider_contract == GROK_REVIEW_STREAM_CONTRACT
            else MAX_REVIEW_JSON_BYTES
        )
    completed = run_bounded_capture(
        runtime_sandbox_argv(role_sandbox_argv),
        stdout_limit=MAX_ROLE_OUTPUT_BYTES,
        stderr_limit=MAX_ROLE_OUTPUT_BYTES,
        stdout_content_limit=review_content_limit,
    )
    after_head, after_diff, after_dirty = current_binding(repo, args.expected_base_head)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "role": args.role,
        "expected_head": args.expected_head,
        "expected_base_head": args.expected_base_head,
        "expected_diff_sha256": args.expected_diff_sha256,
        "expected_dirty": expected_dirty,
        "head_before": before_head,
        "head_after": after_head,
        "diff_after": after_diff,
        "worktree_dirty_after": after_dirty,
        "argv_sha256": digest(command),
        "returncode": completed.returncode,
        "stdout_sha256": completed.stdout_sha256,
        "stderr_sha256": completed.stderr_sha256,
        "stdout_bytes": completed.stdout_bytes,
        "stderr_bytes": completed.stderr_bytes,
        "stdout_tail": completed.stdout_tail,
        "stderr_tail": completed.stderr_tail,
        "output_limit_bytes": MAX_ROLE_OUTPUT_BYTES,
        "review_content_limit_bytes": review_content_limit if args.role == "review" else None,
        "sandbox": SANDBOX_LABEL,
    }
    if completed.output_limit_exceeded:
        payload["returncode"] = 124
        payload["error"] = "role stdout or stderr exceeded the bounded capture limit"
    if after_head != before_head or after_diff != before_diff or after_dirty != before_dirty:
        payload["returncode"] = 125
        payload["error"] = "read-only role observed writer mutation"
    if args.role == "review":
        if completed.stdout_content_exceeded or completed.stdout_content is None:
            payload.update({
                "review_document_contract": REVIEW_DOCUMENT_CONTRACT,
                "review_document_bytes": completed.stdout_bytes,
                "review_document_sha256": completed.stdout_sha256,
                "review_document_normalizations": [],
                "review_findings_normalized": False,
                "review_receipt_generated_by": "grabowski_agent_role",
            })
            payload["returncode"] = 126
            payload["verdict"] = "INVALID"
            payload["findings"] = []
            payload["error"] = f"review stdout exceeds {review_content_limit} bytes"
        else:
            review_document = completed.stdout_content
            provider_error: str | None = None
            if review_provider_contract == GROK_REVIEW_STREAM_CONTRACT:
                review_document, provider_error, provider_metadata = (
                    _extract_grok_stream_review_document(completed.stdout_content)
                )
                payload.update(provider_metadata)
            if provider_error is not None or review_document is None:
                verdict = None
                findings = None
                review_error = provider_error
                document_metadata = {
                    "review_document_contract": REVIEW_DOCUMENT_CONTRACT,
                    "review_document_bytes": 0,
                    "review_document_sha256": None,
                    "review_document_normalizations": [],
                    "review_findings_normalized": False,
                    "review_receipt_generated_by": "grabowski_agent_role",
                }
            else:
                verdict, findings, review_error, document_metadata = parse_review_document(
                    review_document
                )
            payload.update(document_metadata)
            if review_error is not None or verdict is None or findings is None:
                payload["returncode"] = 126
                payload["verdict"] = "INVALID"
                payload["findings"] = []
                payload["error"] = review_error
            else:
                payload["verdict"] = verdict
                payload["findings"] = findings
                if verdict == "PASS" and findings:
                    payload["returncode"] = 126
                    payload["error"] = "PASS review may not contain findings"
                elif verdict != "PASS" and not findings:
                    payload["returncode"] = 126
                    payload["error"] = "non-PASS review must contain findings"
    payload["failure_classification"] = classify_result(args.role, command, repo, payload)
    stable = dict(payload)
    payload["receipt_sha256"] = digest(stable)
    write_receipt(output, payload, create_only=True)
    return int(payload["returncode"])


if __name__ == "__main__":
    raise SystemExit(main())
