#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

try:
    from plain_llm_review_contract import (
        PLAIN_LLM_ALLOWED_ENVIRONMENT_KEYS,
        PLAIN_LLM_ENVIRONMENT_POLICY,
        PLAIN_LLM_MAX_EVIDENCE_BYTES,
        PLAIN_LLM_MAX_RAW_REVIEW_BYTES,
        PLAIN_LLM_MAX_TRANSMITTED_PROMPT_BYTES,
        PLAIN_LLM_OX_ALPHA_CONTEXT_ATTESTATIONS,
        PLAIN_LLM_OX_ALPHA_MODEL,
        PLAIN_LLM_PROVIDERS,
        PLAIN_LLM_REVIEW_GATE_AUTHORITY,
        PLAIN_LLM_REVIEW_INPUT_MODE,
        PLAIN_LLM_REVIEW_SOURCE_PREFIX,
        build_plain_llm_review_prompt,
        plain_llm_review_payload_sha256,
    )
except ModuleNotFoundError:  # importlib-based tests load from the repo root
    from tools.plain_llm_review_contract import (
        PLAIN_LLM_ALLOWED_ENVIRONMENT_KEYS,
        PLAIN_LLM_ENVIRONMENT_POLICY,
        PLAIN_LLM_MAX_EVIDENCE_BYTES,
        PLAIN_LLM_MAX_RAW_REVIEW_BYTES,
        PLAIN_LLM_MAX_TRANSMITTED_PROMPT_BYTES,
        PLAIN_LLM_OX_ALPHA_CONTEXT_ATTESTATIONS,
        PLAIN_LLM_OX_ALPHA_MODEL,
        PLAIN_LLM_PROVIDERS,
        PLAIN_LLM_REVIEW_GATE_AUTHORITY,
        PLAIN_LLM_REVIEW_INPUT_MODE,
        PLAIN_LLM_REVIEW_SOURCE_PREFIX,
        build_plain_llm_review_prompt,
        plain_llm_review_payload_sha256,
    )

VERDICTS = {"PASS", "NEEDS_CHANGE", "BLOCK"}
PROVIDERS = set(PLAIN_LLM_PROVIDERS)
OX_ALPHA_MODEL = PLAIN_LLM_OX_ALPHA_MODEL
OX_ALPHA_CONTEXT_ATTESTATIONS = PLAIN_LLM_OX_ALPHA_CONTEXT_ATTESTATIONS
OX_ALPHA_PROMPT_MESSAGE = (
    "Review the complete prompt in the attached file and return only its "
    "requested JSON object."
)
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MAX_PROMPT_BYTES = 500_000
DEFAULT_MAX_REVIEW_BYTES = PLAIN_LLM_MAX_RAW_REVIEW_BYTES
MAX_PACKET_MANIFEST_BYTES = 64_000
# Linux rejects a single exec argument at 128 KiB including its terminator.
# Keep enough headroom for platform and encoding details while Gemini still
# requires the complete prompt in one --print argument.
GEMINI_MAX_ARG_PROMPT_BYTES = 120_000
MAX_WORKSPACE_CLEANUP_ENTRIES = 1_024
MAX_WORKSPACE_CLEANUP_DEPTH = 32
# Any inherited credential can silently move an account-backed CLI onto a
# metered API route, so the sweep is by suffix as well as by exact name.
BILLABLE_API_ENV_SUFFIXES = ("_API_KEY", "_API_TOKEN", "_AUTH_TOKEN")
BILLABLE_API_ENV = {
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GROK_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "XAI_API_KEY",
}
GIT_CONTEXT_ENV = {
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
}
PROVIDER_ENV_ALLOWLIST = PLAIN_LLM_ALLOWED_ENVIRONMENT_KEYS
SESSION_ENV = frozenset(
    {
        "DBUS_SESSION_BUS_ADDRESS",
        "DISPLAY",
        "SSH_AGENT_PID",
        "SSH_AUTH_SOCK",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
    }
)
ACCOUNT_CONFIGURATION_ROOT_KEYS = frozenset(
    {"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"}
)
FINDING_SEVERITIES = {"low", "medium", "high", "critical"}


class PlainReviewError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def canonical_sha256(value: Any) -> str:
    return sha256_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )


def read_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    expected: os.stat_result | None = None,
) -> bytes:
    if max_bytes < 0:
        raise PlainReviewError(f"cannot read {label}: byte limit is negative")
    descriptor = -1
    try:
        expected = expected or path.lstat()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(expected.st_mode)
            or expected.st_nlink != 1
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not stat.S_ISREG(linked.st_mode)
            or linked.st_nlink != 1
            or not _same_completed_file(expected, opened)
            or not _same_completed_file(opened, linked)
        ):
            raise PlainReviewError(
                f"cannot read {label}: input is not the same stable regular file"
            )
        if opened.st_size > max_bytes:
            raise PlainReviewError(
                f"cannot read {label}: file exceeds {max_bytes} bytes"
            )
        chunks: list[bytes] = []
        observed_bytes = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, max_bytes + 1 - observed_bytes),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed_bytes += len(chunk)
            if observed_bytes > max_bytes:
                raise PlainReviewError(
                    f"cannot read {label}: file exceeds {max_bytes} bytes"
                )
        completed = os.fstat(descriptor)
        linked_after = path.lstat()
        if (
            not _same_completed_file(opened, completed)
            or not _same_completed_file(opened, linked_after)
        ):
            raise PlainReviewError(
                f"cannot read {label}: input changed while it was read"
            )
        return b"".join(chunks)
    except (OSError, ValueError) as exc:
        raise PlainReviewError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def read_text(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    expected: os.stat_result | None = None,
) -> str:
    try:
        return read_bytes(
            path,
            label=label,
            max_bytes=max_bytes,
            expected=expected,
        ).decode("utf-8")
    except UnicodeError as exc:
        raise PlainReviewError(f"cannot read {label} as UTF-8: {exc}") from exc


def load_json(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    expected: os.stat_result | None = None,
) -> dict[str, Any]:
    try:
        data = json.loads(
            read_text(
                path,
                label=label,
                max_bytes=max_bytes,
                expected=expected,
            )
        )
    except json.JSONDecodeError as exc:
        raise PlainReviewError(f"cannot parse {label} as JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PlainReviewError(f"{label} is not a JSON object")
    return data


def is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_packet_file(
    manifest_path: Path,
    value: Any,
    *,
    label: str,
) -> tuple[Path, os.stat_result]:
    if not isinstance(value, str) or not value.strip():
        raise PlainReviewError(f"manifest {label} is missing or not a string")
    raw = Path(value)
    path = raw if raw.is_absolute() else manifest_path.parent / raw
    try:
        resolved = path.resolve(strict=True)
        packet_dir = manifest_path.parent.resolve(strict=True)
    except OSError as exc:
        raise PlainReviewError(f"cannot resolve manifest {label}: {exc}") from exc
    if not is_inside(resolved, packet_dir):
        raise PlainReviewError(
            f"manifest {label} escapes external review packet directory"
        )
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise PlainReviewError(f"cannot resolve manifest {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise PlainReviewError(f"manifest {label} is not a regular file")
    return resolved, metadata


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != 1:
        raise PlainReviewError("manifest schema_version is not 1")
    if manifest.get("kind") != "external_review_packet":
        raise PlainReviewError(
            "manifest kind is not 'external_review_packet'"
        )
    repo = manifest.get("repo")
    if not isinstance(repo, str) or not repo.strip():
        raise PlainReviewError("manifest repo is missing")
    if _contains_unicode_surrogate(repo):
        raise PlainReviewError("manifest repo contains an invalid Unicode surrogate")
    pr = manifest.get("pr")
    if isinstance(pr, bool) or not isinstance(pr, int) or pr <= 0:
        raise PlainReviewError("manifest pr is not a positive integer")
    if not _is_hex(manifest.get("head_sha"), 40):
        raise PlainReviewError("manifest head_sha is not a 40-character hex digest")
    for key in ("diff_sha256", "prompt_sha256"):
        if not _is_hex(manifest.get(key), 64):
            raise PlainReviewError(
                f"manifest {key} is not a 64-character hex digest"
            )
    for key in ("diff_path", "prompt_path"):
        value = manifest.get(key)
        if not isinstance(value, str) or not value.strip():
            raise PlainReviewError(f"manifest {key} is missing")
        if "\x00" in value or _contains_unicode_surrogate(value):
            raise PlainReviewError(f"manifest {key} contains invalid path text")


def build_plain_prompt(
    packet_prompt: str,
    diff_text: str,
    prompt_nonce: str,
) -> str:
    try:
        return build_plain_llm_review_prompt(
            packet_prompt, diff_text, prompt_nonce
        )
    except ValueError as exc:
        raise PlainReviewError(str(exc)) from exc


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", value)


def _contains_unicode_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_finding(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PlainReviewError(f"plain review finding {index} is not an object")
    allowed_fields = {"severity", "summary", "file", "line", "fix"}
    unknown_fields = sorted(set(value) - allowed_fields)
    if unknown_fields:
        raise PlainReviewError(
            f"plain review finding {index} has unknown fields: "
            + ", ".join(unknown_fields)
        )
    severity = value.get("severity")
    if severity not in FINDING_SEVERITIES:
        raise PlainReviewError(
            f"plain review finding {index} severity is missing or invalid"
        )
    summary = value.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise PlainReviewError(
            f"plain review finding {index} summary is missing"
        )
    if _contains_unicode_surrogate(summary):
        raise PlainReviewError(
            f"plain review finding {index} summary contains an invalid "
            "Unicode surrogate"
        )
    for key in ("file", "fix"):
        field = value.get(key)
        if field is not None and (
            not isinstance(field, str) or not field.strip()
        ):
            raise PlainReviewError(
                f"plain review finding {index} {key} is not a nonempty string"
            )
        if field is not None and _contains_unicode_surrogate(field):
            raise PlainReviewError(
                f"plain review finding {index} {key} contains an invalid "
                "Unicode surrogate"
            )
    line = value.get("line")
    if line is not None and (
        isinstance(line, bool) or not isinstance(line, int) or line <= 0
    ):
        raise PlainReviewError(
            f"plain review finding {index} line is not a positive integer"
        )
    return value


def parse_review_json(stdout: str) -> dict[str, Any]:
    text = strip_ansi(stdout).strip()
    fence = re.fullmatch(
        r"```(?:json)?\s*(.*?)\s*```",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if fence:
        text = fence.group(1).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PlainReviewError(
            f"plain review output JSON is invalid: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise PlainReviewError("plain review output JSON is not an object")
    if set(parsed) != {"verdict", "finding_count", "findings"}:
        raise PlainReviewError(
            "plain review output must contain only verdict, finding_count, and findings"
        )
    verdict = parsed.get("verdict")
    if verdict not in VERDICTS:
        raise PlainReviewError("plain review verdict is missing or invalid")
    finding_count = parsed.get("finding_count")
    if (
        isinstance(finding_count, bool)
        or not isinstance(finding_count, int)
        or finding_count < 0
    ):
        raise PlainReviewError(
            "plain review finding_count is not an integer >= 0"
        )
    findings = parsed.get("findings")
    if not isinstance(findings, list):
        raise PlainReviewError("plain review findings is not a list")
    validated = [
        _validate_finding(finding, index)
        for index, finding in enumerate(findings, start=1)
    ]
    if finding_count != len(validated):
        raise PlainReviewError(
            "plain review finding_count does not match findings length"
        )
    if verdict == "PASS" and finding_count != 0:
        raise PlainReviewError("plain review PASS must not contain findings")
    if verdict != "PASS" and finding_count == 0:
        raise PlainReviewError(
            "plain review non-PASS verdict must contain at least one finding"
        )
    parsed["findings"] = validated
    return parsed


def build_provider_argv(
    *,
    provider: str,
    executable: str,
    model: str | None,
    prompt: str | None,
    prompt_path: Path | None,
    timeout_seconds: int,
) -> list[str]:
    if provider == "gemini":
        if prompt is None:
            raise PlainReviewError("Gemini plain review prompt is missing")
        _validate_provider_prompt_transport(
            provider,
            prompt.encode("utf-8"),
        )
        argv = [
            executable,
            f"--print-timeout={timeout_seconds}s",
            "--mode",
            "plan",
            "--sandbox",
            "--disable-slash-commands",
        ]
        if model:
            argv.extend(["--model", model])
        argv.extend(["--print", prompt])
        return argv
    if provider == "grok":
        if prompt_path is None:
            raise PlainReviewError("Grok plain review prompt file is missing")
        argv = [
            executable,
            "--disable-web-search",
            "--no-memory",
            "--no-subagents",
            "--max-turns",
            "1",
            "--permission-mode",
            "plan",
            "--tools=",
            "--output-format",
            "plain",
            "--verbatim",
            "--prompt-file",
            str(prompt_path),
        ]
        if model:
            argv.extend(["--model", model])
        return argv
    if provider == "ox-alpha":
        if prompt_path is None:
            raise PlainReviewError("Ox Alpha plain review prompt file is missing")
        if model != OX_ALPHA_MODEL:
            raise PlainReviewError(
                f"Ox Alpha plain review requires exact model {OX_ALPHA_MODEL}"
            )
        return [
            executable,
            "run",
            "--pure",
            "--agent",
            "plan",
            "--model",
            OX_ALPHA_MODEL,
            "--file",
            str(prompt_path),
            OX_ALPHA_PROMPT_MESSAGE,
        ]
    raise PlainReviewError(f"unsupported plain review provider: {provider}")


def _validate_provider_prompt_transport(
    provider: str,
    prompt_bytes: bytes,
) -> None:
    if (
        provider == "gemini"
        and len(prompt_bytes) > GEMINI_MAX_ARG_PROMPT_BYTES
    ):
        raise PlainReviewError(
            "Gemini plain review prompt exceeds the safe single-argument "
            "transport limit: "
            f"{len(prompt_bytes)} bytes > {GEMINI_MAX_ARG_PROMPT_BYTES}"
        )


def is_billable_api_variable(key: str) -> bool:
    return key in BILLABLE_API_ENV or key.endswith(BILLABLE_API_ENV_SUFFIXES)


def _validate_inherited_environment_text(
    inherited: dict[str, str],
) -> None:
    for key, value in inherited.items():
        if _contains_unicode_surrogate(key):
            raise PlainReviewError(
                "inherited environment contains an invalid variable name"
            )
        if (
            key in PROVIDER_ENV_ALLOWLIST
            and _contains_unicode_surrogate(value)
        ):
            raise PlainReviewError(
                f"inherited environment {key} contains an invalid value"
            )


def sanitized_environment() -> tuple[
    dict[str, str], list[str], list[str], list[str]
]:
    inherited = dict(os.environ)
    _validate_inherited_environment_text(inherited)
    environment = {
        key: value
        for key, value in inherited.items()
        if key in PROVIDER_ENV_ALLOWLIST
    }
    removed_billable = sorted(
        key for key in inherited if is_billable_api_variable(key)
    )
    removed_git_context = sorted(key for key in inherited if key in GIT_CONTEXT_ENV)
    removed_session = sorted(key for key in inherited if key in SESSION_ENV)
    environment.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    environment.setdefault("LANG", "C.UTF-8")
    environment["GIT_ASKPASS"] = "/bin/false"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["NO_COLOR"] = "1"
    return environment, removed_billable, removed_git_context, removed_session


def _trusted_executable_owner_ids() -> set[int]:
    # In user-namespaced runtimes the filesystem root owner can be mapped to a
    # synthetic uid even though it still represents the root trust boundary.
    return {0, os.getuid(), Path("/").stat().st_uid}


def _validate_path_ancestry(path: Path, *, label: str) -> None:
    """Reject path components another local user could replace."""
    trusted_owners = _trusted_executable_owner_ids()
    child = path
    try:
        child_metadata = child.lstat()
        directory = child.parent
        while True:
            metadata = directory.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink < 1
                or metadata.st_uid not in trusted_owners
                or (
                    metadata.st_mode & 0o022
                    and not metadata.st_mode & stat.S_ISVTX
                )
                or (
                    metadata.st_mode & stat.S_ISVTX
                    and child_metadata.st_uid not in trusted_owners
                )
            ):
                raise PlainReviewError(
                    f"{label} has unsafe path ancestry: {directory}"
                )
            if directory.parent == directory:
                return
            child = directory
            child_metadata = metadata
            directory = child.parent
    except OSError as exc:
        raise PlainReviewError(
            f"{label} path ancestry is unavailable: {exc}"
        ) from exc


def _validate_account_configuration_roots(
    environment: dict[str, str],
    *,
    expected: dict[str, os.stat_result] | None = None,
) -> dict[str, os.stat_result]:
    """Pin every account-configuration root to trusted local ancestry."""
    observed: dict[str, os.stat_result] = {}
    for key in sorted(ACCOUNT_CONFIGURATION_ROOT_KEYS):
        raw = environment.get(key)
        if key == "HOME" and not raw:
            raise PlainReviewError("account configuration HOME is unavailable")
        if raw is None:
            continue
        if not raw or "\x00" in raw or not Path(raw).is_absolute():
            raise PlainReviewError(
                f"account configuration {key} is missing or not absolute"
            )
        root = Path(os.path.abspath(raw))
        descriptor = -1
        try:
            descriptor = os.open(root, _parent_directory_open_flags())
            linked = root.lstat()
            opened = os.fstat(descriptor)
            if (
                stat.S_ISLNK(linked.st_mode)
                or not stat.S_ISDIR(linked.st_mode)
                or linked.st_uid != os.getuid()
                or linked.st_nlink < 1
                or linked.st_mode & 0o022
                or not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.getuid()
                or opened.st_nlink < 1
                or opened.st_mode & 0o022
                or not _same_file_identity(linked, opened)
            ):
                raise PlainReviewError(
                    f"account configuration {key} identity is unsafe"
                )
            _validate_path_ancestry(
                root,
                label=f"account configuration {key}",
            )
            expected_identity = (expected or {}).get(key)
            if expected_identity is not None and not _same_file_identity(
                expected_identity,
                opened,
            ):
                raise PlainReviewError(
                    f"account configuration {key} identity drifted"
                )
            observed[key] = opened
        except PlainReviewError:
            raise
        except OSError as exc:
            raise PlainReviewError(
                f"account configuration {key} is unavailable: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    if expected is not None and set(observed) != set(expected):
        raise PlainReviewError("account configuration roots changed before launch")
    return observed


def _validated_executable(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        if _contains_unicode_surrogate(os.fspath(resolved)):
            raise PlainReviewError(
                f"{label} resolved path contains invalid Unicode text"
            )
        metadata = resolved.stat()
        linked = resolved.lstat()
    except PlainReviewError:
        raise
    except OSError as exc:
        raise PlainReviewError(f"{label} is unavailable: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022
        or not os.access(resolved, os.X_OK)
        or stat.S_ISLNK(linked.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (linked.st_dev, linked.st_ino)
    ):
        raise PlainReviewError(
            f"{label} must be an owner-controlled executable regular file"
        )
    _validate_path_ancestry(resolved, label=label)
    return resolved


def resolve_provider_executable(
    *,
    provider: str,
    executable: str,
    environment: dict[str, str],
) -> str:
    if not executable or "\x00" in executable:
        raise PlainReviewError("provider executable is missing or invalid")
    if provider == "grok":
        home_raw = environment.get("HOME")
        if not home_raw or not Path(home_raw).is_absolute() or "\x00" in home_raw:
            raise PlainReviewError("Grok native binary home is unavailable")
        try:
            home = Path(home_raw).resolve(strict=True)
            bin_directory = home / ".grok" / "bin"
            bin_metadata = bin_directory.lstat()
            resolved_bin_directory = bin_directory.resolve(strict=True)
            canonical = bin_directory / "grok"
            canonical_metadata = canonical.lstat()
            native = canonical.resolve(strict=True)
        except OSError as exc:
            raise PlainReviewError(f"Grok native binary is unavailable: {exc}") from exc
        native = _validated_executable(native, label="Grok native binary")
        if (
            not stat.S_ISDIR(bin_metadata.st_mode)
            or bin_metadata.st_uid != os.getuid()
            or bin_metadata.st_mode & 0o022
            or resolved_bin_directory != bin_directory
            or canonical_metadata.st_uid != os.getuid()
            or not stat.S_ISLNK(canonical_metadata.st_mode)
            or native.parent != resolved_bin_directory
            or re.fullmatch(
                r"grok-[A-Za-z0-9][A-Za-z0-9._-]{0,79}", native.name
            )
            is None
        ):
            raise PlainReviewError("Grok native binary identity is invalid")
        if "/" in executable:
            try:
                requested: Path | None = Path(executable).expanduser().resolve(
                    strict=True
                )
            except OSError as exc:
                raise PlainReviewError(
                    f"requested Grok executable is unavailable: {exc}"
                ) from exc
        else:
            located = shutil.which(executable, path=environment["PATH"])
            requested = (
                Path(located).resolve(strict=True) if located is not None else None
            )
        if requested != native:
            raise PlainReviewError(
                "Grok review requires the canonical owner-controlled native binary"
            )
        return str(native)

    if "/" in executable:
        candidate = Path(executable).expanduser()
    else:
        located = shutil.which(executable, path=environment["PATH"])
        if located is None:
            raise PlainReviewError(
                f"provider executable is unavailable: {executable}"
            )
        candidate = Path(located)
    return str(_validated_executable(candidate, label="provider executable"))


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise PlainReviewError(
                "provider process group did not terminate"
            ) from exc


def run_bounded_process(
    argv: list[str],
    *,
    executable: str,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            executable=executable,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise PlainReviewError(f"cannot start provider executable: {exc}") from exc
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise PlainReviewError("could not create bounded provider output pipes")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    failure: str | None = None
    descendants_killed = False
    deadline = started + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0 and failure is None:
                failure = "provider timed out"
                _kill_process_group(process)
            if process.poll() is not None and not descendants_killed:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                descendants_killed = True
            events = selector.select(timeout=max(0.0, min(0.2, remaining)))
            if not events and process.poll() is not None:
                for registered in list(selector.get_map().values()):
                    stream = registered.fileobj
                    try:
                        selector.unregister(stream)
                    except Exception:
                        pass
                    stream.close()
                break
            for key, _ in events:
                stream = key.fileobj
                name = key.data
                chunk = os.read(stream.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                remaining_capacity = max_output_bytes - len(buffers[name])
                if remaining_capacity > 0:
                    buffers[name].extend(chunk[:remaining_capacity])
                if len(chunk) > remaining_capacity and failure is None:
                    failure = f"provider {name} exceeds byte limit"
                    _kill_process_group(process)
        returncode = process.poll()
        if returncode is None and failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "provider timed out"
            else:
                try:
                    returncode = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    failure = "provider timed out"
        if returncode is None:
            _kill_process_group(process)
            returncode = process.wait(timeout=5)
    finally:
        selector.close()
        _kill_process_group(process)
        if process.poll() is None:
            process.wait(timeout=5)
    if failure is not None:
        raise PlainReviewError(failure)
    decoded: dict[str, str] = {}
    for name, payload in buffers.items():
        try:
            decoded[name] = bytes(payload).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PlainReviewError(
                f"provider {name} is not valid UTF-8"
            ) from exc
    return subprocess.CompletedProcess(
        argv,
        returncode,
        decoded["stdout"],
        decoded["stderr"],
    )


def verify_provider_workspace(
    root: Path,
    *,
    prompt_path: Path | None,
    expected_prompt: bytes,
) -> None:
    expected_entries = [] if prompt_path is None else [prompt_path.name]
    try:
        observed_entries = sorted(item.name for item in root.iterdir())
    except OSError as exc:
        raise PlainReviewError(f"cannot inspect provider workspace: {exc}") from exc
    if observed_entries != expected_entries:
        raise PlainReviewError("provider modified its isolated workspace")
    if prompt_path is None:
        return
    try:
        metadata = prompt_path.lstat()
    except OSError as exc:
        raise PlainReviewError(f"cannot verify ephemeral Grok prompt: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise PlainReviewError("provider changed the ephemeral Grok prompt")
    observed = read_bytes(
        prompt_path,
        label="ephemeral Grok prompt",
        max_bytes=len(expected_prompt),
        expected=metadata,
    )
    if observed != expected_prompt:
        raise PlainReviewError("provider changed the ephemeral Grok prompt")


def _validated_provider_temporary_base() -> Path:
    """Resolve a base where another local user cannot replace our workspace."""
    descriptor = -1
    try:
        root = Path(os.path.abspath(tempfile.gettempdir()))
        descriptor = os.open(root, _parent_directory_open_flags())
        linked = root.lstat()
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(linked.st_mode)
            or not _is_trusted_ancestry_directory(linked)
            or not _is_trusted_ancestry_directory(opened)
            or not _same_file_identity(linked, opened)
        ):
            raise PlainReviewError("provider temporary base is unsafe")
        _validate_path_ancestry(root, label="provider temporary base")
        return root
    except PlainReviewError:
        raise
    except OSError as exc:
        raise PlainReviewError(
            f"provider temporary base is unavailable: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verify_private_workspace_identity(
    root: Path,
    *,
    expected_identity: os.stat_result | None = None,
) -> os.stat_result:
    """Bind the private provider workspace to a trusted path and inode."""
    root = Path(os.path.abspath(root))
    descriptor = -1
    try:
        descriptor = os.open(root, _parent_directory_open_flags())
        linked = root.lstat()
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(linked.st_mode)
            or not _same_file_identity(linked, opened)
            or linked.st_uid != os.getuid()
            or linked.st_nlink < 1
            or stat.S_IMODE(linked.st_mode) != 0o700
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink < 1
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise PlainReviewError("provider workspace identity is unsafe")
        if expected_identity is not None and not _same_file_identity(
            expected_identity,
            opened,
        ):
            raise PlainReviewError("provider workspace identity drifted")
        _validate_path_ancestry(root, label="provider workspace")
        return opened
    except PlainReviewError:
        raise
    except OSError as exc:
        raise PlainReviewError(
            f"provider workspace identity is unavailable: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _clear_workspace_descriptor(
    descriptor: int,
    *,
    remaining_entries: list[int],
    depth: int = 0,
) -> None:
    """Remove workspace contents without following links or reopening the root."""
    if depth > MAX_WORKSPACE_CLEANUP_DEPTH:
        raise PlainReviewError("provider workspace cleanup is too deep")
    try:
        try:
            prompt_metadata = os.stat(
                "plain-review-prompt.txt",
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            prompt_metadata = None
        if prompt_metadata is not None and not stat.S_ISDIR(
            prompt_metadata.st_mode
        ):
            if remaining_entries[0] <= 0:
                raise PlainReviewError(
                    "provider workspace cleanup is too large"
                )
            remaining_entries[0] -= 1
            os.unlink("plain-review-prompt.txt", dir_fd=descriptor)
        with os.scandir(descriptor) as entries:
            names: list[str] = []
            for entry in entries:
                names.append(entry.name)
                if len(names) > remaining_entries[0]:
                    raise PlainReviewError(
                        "provider workspace cleanup is too large"
                    )
    except OSError as exc:
        raise PlainReviewError(
            f"cannot inspect original provider workspace: {exc}"
        ) from exc
    for name in names:
        if remaining_entries[0] <= 0:
            raise PlainReviewError("provider workspace cleanup is too large")
        remaining_entries[0] -= 1
        child_descriptor = -1
        try:
            linked = os.stat(
                name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISDIR(linked.st_mode):
                child_descriptor = os.open(
                    name,
                    _parent_directory_open_flags(),
                    dir_fd=descriptor,
                )
                opened = os.fstat(child_descriptor)
                if not _same_file_identity(linked, opened):
                    raise PlainReviewError(
                        "provider workspace cleanup identity drifted"
                    )
                _clear_workspace_descriptor(
                    child_descriptor,
                    remaining_entries=remaining_entries,
                    depth=depth + 1,
                )
                os.close(child_descriptor)
                child_descriptor = -1
                current = os.stat(
                    name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if not _same_file_identity(linked, current):
                    raise PlainReviewError(
                        "provider workspace cleanup identity drifted"
                    )
                os.rmdir(name, dir_fd=descriptor)
            else:
                os.unlink(name, dir_fd=descriptor)
        except PlainReviewError:
            raise
        except OSError as exc:
            raise PlainReviewError(
                f"cannot clear original provider workspace: {exc}"
            ) from exc
        finally:
            if child_descriptor >= 0:
                try:
                    os.close(child_descriptor)
                except OSError:
                    pass


def _discard_open_provider_workspace(
    descriptor: int,
    *,
    expected_identity: os.stat_result,
) -> None:
    """Clear and remove the exact workspace inode, even after a rename."""
    opened = os.fstat(descriptor)
    if not _same_file_identity(expected_identity, opened):
        raise PlainReviewError("provider workspace descriptor identity drifted")
    _clear_workspace_descriptor(
        descriptor,
        remaining_entries=[MAX_WORKSPACE_CLEANUP_ENTRIES],
    )
    if os.fstat(descriptor).st_nlink == 0:
        return
    try:
        linked_path = os.readlink(f"/proc/self/fd/{descriptor}")
    except OSError as exc:
        raise PlainReviewError(
            f"cannot locate original provider workspace: {exc}"
        ) from exc
    current_path = Path(linked_path)
    if not current_path.is_absolute():
        raise PlainReviewError("original provider workspace path is invalid")
    _validate_path_ancestry(
        current_path,
        label="original provider workspace cleanup",
    )
    parent_descriptor = -1
    try:
        parent_descriptor = os.open(
            current_path.parent,
            _parent_directory_open_flags(),
        )
        parent_linked = current_path.parent.lstat()
        parent_opened = os.fstat(parent_descriptor)
        linked = os.stat(
            current_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            stat.S_ISLNK(parent_linked.st_mode)
            or not _is_trusted_ancestry_directory(parent_linked)
            or not _is_trusted_ancestry_directory(parent_opened)
            or not _same_file_identity(parent_linked, parent_opened)
            or not stat.S_ISDIR(linked.st_mode)
            or linked.st_uid != os.getuid()
            or not _same_file_identity(expected_identity, linked)
        ):
            raise PlainReviewError(
                "original provider workspace cleanup identity drifted"
            )
        os.rmdir(current_path.name, dir_fd=parent_descriptor)
        try:
            os.fsync(parent_descriptor)
        except OSError:
            pass
    except PlainReviewError:
        raise
    except OSError as exc:
        raise PlainReviewError(
            f"cannot remove original provider workspace: {exc}"
        ) from exc
    finally:
        if parent_descriptor >= 0:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass


def run_provider(
    prompt: str,
    *,
    provider: str,
    executable: str,
    model: str | None,
    timeout_seconds: int,
    max_review_bytes: int,
) -> tuple[
    subprocess.CompletedProcess[str],
    list[str],
    list[str],
    list[str],
    list[str],
    list[str],
    str,
]:
    (
        environment,
        removed_billable,
        removed_git_context,
        removed_session,
    ) = sanitized_environment()
    account_configuration_roots = _validate_account_configuration_roots(
        environment
    )
    resolved_executable = resolve_provider_executable(
        provider=provider,
        executable=executable,
        environment=environment,
    )
    temporary_base = _validated_provider_temporary_base()
    with tempfile.TemporaryDirectory(
        prefix="grabowski-plain-review-",
        dir=temporary_base,
    ) as isolated_directory:
        isolated_root = Path(isolated_directory)
        isolated_identity = _verify_private_workspace_identity(isolated_root)
        workspace_descriptor = os.open(
            isolated_root,
            _parent_directory_open_flags(),
        )
        try:
            if not _same_file_identity(
                isolated_identity,
                os.fstat(workspace_descriptor),
            ):
                raise PlainReviewError(
                    "provider workspace descriptor identity drifted"
                )
            provider_prompt_path: Path | None = None
            provider_prompt: str | None = prompt
            if provider in {"grok", "ox-alpha"}:
                provider_prompt_path = isolated_root / "plain-review-prompt.txt"
                write_text_create_only(
                    provider_prompt_path,
                    prompt,
                    label="ephemeral Grok prompt",
                )
                provider_prompt = None
            argv = build_provider_argv(
                provider=provider,
                executable=resolved_executable,
                model=model,
                prompt=provider_prompt,
                prompt_path=provider_prompt_path,
                timeout_seconds=timeout_seconds,
            )
            expected_prompt = prompt.encode("utf-8")
            verify_provider_workspace(
                isolated_root,
                prompt_path=provider_prompt_path,
                expected_prompt=expected_prompt,
            )
            _verify_private_workspace_identity(
                isolated_root,
                expected_identity=isolated_identity,
            )
            _validate_account_configuration_roots(
                environment,
                expected=account_configuration_roots,
            )
            try:
                completed = run_bounded_process(
                    argv,
                    executable=resolved_executable,
                    cwd=isolated_root,
                    timeout_seconds=(
                        timeout_seconds + 15
                        if provider == "gemini"
                        else timeout_seconds
                    ),
                    max_output_bytes=max_review_bytes,
                    environment=environment,
                )
            finally:
                _verify_private_workspace_identity(
                    isolated_root,
                    expected_identity=isolated_identity,
                )
                verify_provider_workspace(
                    isolated_root,
                    prompt_path=provider_prompt_path,
                    expected_prompt=expected_prompt,
                )
        finally:
            try:
                _discard_open_provider_workspace(
                    workspace_descriptor,
                    expected_identity=isolated_identity,
                )
            finally:
                os.close(workspace_descriptor)
    return (
        completed,
        argv,
        removed_billable,
        removed_git_context,
        removed_session,
        sorted(environment),
        resolved_executable,
    )


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _is_private_created_file(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
    )


def _validate_private_packet_input(
    path: Path,
    expected: os.stat_result,
    *,
    label: str,
) -> os.stat_result:
    """Bind one provider input to a private packet directory and file."""
    parent_descriptor = -1
    try:
        parent_descriptor = os.open(
            path.parent,
            _parent_directory_open_flags(),
        )
        parent_opened = os.fstat(parent_descriptor)
        parent_linked = path.parent.lstat()
        linked = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not _same_file_identity(parent_opened, parent_linked)
            or stat.S_ISLNK(parent_linked.st_mode)
            or not stat.S_ISDIR(parent_linked.st_mode)
            or parent_linked.st_uid != os.getuid()
            or stat.S_IMODE(parent_linked.st_mode) != 0o700
            or not stat.S_ISDIR(parent_opened.st_mode)
            or parent_opened.st_uid != os.getuid()
            or parent_opened.st_nlink < 1
            or stat.S_IMODE(parent_opened.st_mode) != 0o700
        ):
            raise PlainReviewError(
                f"{label} directory is not private and owner-controlled"
            )
        if (
            not _is_private_created_file(expected)
            or stat.S_IMODE(expected.st_mode) != 0o600
            or not _is_private_created_file(linked)
            or stat.S_IMODE(linked.st_mode) != 0o600
            or not _same_completed_file(expected, linked)
        ):
            raise PlainReviewError(
                f"{label} is not a private single-link regular file"
            )
        _validate_path_ancestry(path, label=label)
        return linked
    except PlainReviewError:
        raise
    except OSError as exc:
        raise PlainReviewError(f"cannot validate {label}: {exc}") from exc
    finally:
        if parent_descriptor >= 0:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass


def _discard_failed_create(
    parent_descriptor: int,
    name: str,
    created: os.stat_result,
) -> None:
    """Best-effort removal of the exact inode created by this helper."""
    try:
        linked = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not _is_private_created_file(linked)
            or not _same_file_identity(created, linked)
        ):
            return
        os.unlink(name, dir_fd=parent_descriptor)
        try:
            os.fsync(parent_descriptor)
        except OSError:
            pass
    except OSError:
        pass


def _same_completed_file(
    created: os.stat_result,
    linked: os.stat_result,
) -> bool:
    return (
        _same_file_identity(created, linked)
        and created.st_ctime_ns == linked.st_ctime_ns
        and created.st_mtime_ns == linked.st_mtime_ns
        and created.st_size == linked.st_size
    )


def _is_owner_controlled_directory(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_nlink >= 1
        and metadata.st_mode & 0o022 == 0
    )


def _is_trusted_ancestry_directory(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid in _trusted_executable_owner_ids()
        and metadata.st_nlink >= 1
        and (
            metadata.st_mode & 0o022 == 0
            or metadata.st_mode & stat.S_ISVTX != 0
        )
    )


def _parent_directory_open_flags() -> int:
    parent_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    return parent_flags


def _discard_created_directories(
    directories: list[tuple[Path, os.stat_result]],
) -> None:
    """Best-effort removal of empty directories created by this run."""
    while directories:
        directory, created = directories.pop()
        parent_descriptor = -1
        try:
            linked = directory.lstat()
            if (
                not _is_owner_controlled_directory(linked)
                or not _same_file_identity(created, linked)
            ):
                continue
            _validate_path_ancestry(
                directory,
                label="created artifact directory cleanup",
            )
            parent_descriptor = os.open(
                directory.parent,
                _parent_directory_open_flags(),
            )
            parent_linked = directory.parent.lstat()
            parent_opened = os.fstat(parent_descriptor)
            linked_from_parent = os.stat(
                directory.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                stat.S_ISLNK(parent_linked.st_mode)
                or not _is_trusted_ancestry_directory(parent_linked)
                or not _is_trusted_ancestry_directory(parent_opened)
                or not _same_file_identity(parent_opened, parent_linked)
                or not _is_owner_controlled_directory(linked_from_parent)
                or not _same_file_identity(created, linked_from_parent)
            ):
                continue
            os.rmdir(directory.name, dir_fd=parent_descriptor)
            try:
                os.fsync(parent_descriptor)
            except OSError:
                pass
        except (OSError, PlainReviewError):
            pass
        finally:
            if parent_descriptor >= 0:
                try:
                    os.close(parent_descriptor)
                except OSError:
                    pass


def _sync_created_directory_entry(
    directory: Path,
    created: os.stat_result,
    *,
    label: str,
) -> None:
    """Persist one mkdir entry through its verified containing directory."""
    parent_descriptor = -1
    try:
        parent_descriptor = os.open(
            directory.parent,
            _parent_directory_open_flags(),
        )
        parent_linked = directory.parent.lstat()
        parent_opened = os.fstat(parent_descriptor)
        linked_from_parent = os.stat(
            directory.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _validate_path_ancestry(
            directory.parent,
            label=f"{label} created parent",
        )
        if (
            stat.S_ISLNK(parent_linked.st_mode)
            or not _is_trusted_ancestry_directory(parent_linked)
            or not _is_trusted_ancestry_directory(parent_opened)
            or not _same_file_identity(parent_opened, parent_linked)
            or not _is_owner_controlled_directory(linked_from_parent)
            or not _same_file_identity(created, linked_from_parent)
        ):
            raise PlainReviewError(
                f"cannot write {label}: created parent identity drifted"
            )
        os.fsync(parent_descriptor)
    finally:
        if parent_descriptor >= 0:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass


def _ensure_private_parent_directories(
    path: Path,
    *,
    label: str,
) -> list[tuple[Path, os.stat_result]]:
    """Create missing parents as 0700 and return their exact identities."""
    parent = Path(os.path.abspath(path.parent))
    missing: list[Path] = []
    cursor = parent
    try:
        while True:
            try:
                existing = cursor.lstat()
                break
            except FileNotFoundError:
                missing.append(cursor)
                if cursor.parent == cursor:
                    raise PlainReviewError(
                        f"cannot write {label}: parent root is unavailable"
                    )
                cursor = cursor.parent
        if stat.S_ISLNK(existing.st_mode) or (
            cursor != parent
            and not _is_trusted_ancestry_directory(existing)
        ):
            raise PlainReviewError(
                f"cannot write {label}: unsafe parent ancestry"
            )
        _validate_path_ancestry(cursor, label=f"{label} parent")
    except OSError as exc:
        raise PlainReviewError(f"cannot write {label}: {exc}") from exc

    created_directories: list[tuple[Path, os.stat_result]] = []
    try:
        for directory in reversed(missing):
            created = False
            try:
                os.mkdir(directory, 0o700)
                created = True
            except FileExistsError:
                pass
            metadata = directory.lstat()
            if created:
                created_directories.append((directory, metadata))
                os.chmod(directory, 0o700)
                secured = directory.lstat()
                if not _same_file_identity(metadata, secured):
                    raise PlainReviewError(
                        f"cannot write {label}: created parent identity drifted"
                    )
                metadata = secured
                created_directories[-1] = (directory, metadata)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not _is_owner_controlled_directory(metadata)
            ):
                raise PlainReviewError(
                    f"cannot write {label}: unsafe created parent identity"
                )
            if created:
                _sync_created_directory_entry(
                    directory,
                    metadata,
                    label=label,
                )
        _validate_path_ancestry(parent, label=f"{label} parent")
        return created_directories
    except BaseException as exc:
        _discard_created_directories(created_directories)
        if isinstance(exc, PlainReviewError):
            raise
        if isinstance(exc, OSError):
            raise PlainReviewError(f"cannot write {label}: {exc}") from exc
        raise


def _open_owner_controlled_parent(
    path: Path,
    *,
    label: str,
) -> tuple[int, os.stat_result]:
    path = Path(os.path.abspath(path))
    try:
        parent_descriptor = os.open(
            path.parent,
            _parent_directory_open_flags(),
        )
    except OSError as exc:
        raise PlainReviewError(f"cannot write {label}: {exc}") from exc

    try:
        parent_linked = path.parent.lstat()
        parent_opened = os.fstat(parent_descriptor)
        if (
            not _is_owner_controlled_directory(parent_opened)
            or not _is_owner_controlled_directory(parent_linked)
            or stat.S_ISLNK(parent_linked.st_mode)
            or not _same_file_identity(parent_opened, parent_linked)
        ):
            raise PlainReviewError(
                f"cannot write {label}: unsafe parent identity"
            )
        _validate_path_ancestry(path.parent, label=f"{label} parent")
        return parent_descriptor, parent_opened
    except BaseException:
        try:
            os.close(parent_descriptor)
        except OSError:
            pass
        raise


def write_text_create_only(
    path: Path,
    text: str,
    *,
    label: str,
    created_directories: list[tuple[Path, os.stat_result]] | None = None,
) -> os.stat_result:
    path = Path(os.path.abspath(path))
    local_created_directories = _ensure_private_parent_directories(
        path,
        label=label,
    )
    try:
        parent_descriptor, parent_opened = _open_owner_controlled_parent(
            path,
            label=label,
        )
    except BaseException:
        _discard_created_directories(local_created_directories)
        raise
    descriptor = -1
    handle = None
    created: os.stat_result | None = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                path.name,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError as exc:
            raise PlainReviewError(f"{label} already exists: {path}") from exc

        os.fchmod(descriptor, 0o600)
        created = os.fstat(descriptor)
        linked = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not _is_private_created_file(created)
            or not _same_file_identity(created, linked)
        ):
            raise PlainReviewError(
                f"cannot write {label}: unsafe created path identity"
            )

        handle = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = -1
        primary_error: BaseException | None = None
        try:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException as exc:
            primary_error = exc
        try:
            handle.close()
        except BaseException as exc:
            if primary_error is None:
                primary_error = exc
        if primary_error is not None:
            raise primary_error
        handle = None

        parent_after = path.parent.lstat()
        linked_after = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not _is_owner_controlled_directory(parent_after)
            or stat.S_ISLNK(parent_after.st_mode)
            or not _same_file_identity(parent_opened, parent_after)
            or not _is_private_created_file(linked_after)
            or not _same_file_identity(created, linked_after)
        ):
            raise PlainReviewError(
                f"cannot write {label}: created path identity drifted"
            )
        os.fsync(parent_descriptor)
        if created_directories is not None:
            created_directories.extend(local_created_directories)
        return linked_after
    except BaseException as exc:
        if created is not None:
            _discard_failed_create(
                parent_descriptor,
                path.name,
                created,
            )
        _discard_created_directories(local_created_directories)
        if isinstance(exc, PlainReviewError):
            raise
        if isinstance(exc, OSError):
            raise PlainReviewError(f"cannot write {label}: {exc}") from exc
        raise
    finally:
        if handle is not None:
            try:
                handle.close()
            except BaseException:
                pass
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(parent_descriptor)
        except OSError:
            pass


def discard_created_paths(
    paths: list[tuple[Path, os.stat_result]],
    directories: list[tuple[Path, os.stat_result]] | None = None,
) -> None:
    """Remove only paths this run created with O_EXCL, restoring the prior state.

    A failed provider run must not leave a partial artifact behind: it would be
    mistaken for evidence and would permanently block a create-only retry on the
    same output path.
    """
    while paths:
        path, created = paths.pop()
        try:
            parent_descriptor, _ = _open_owner_controlled_parent(
                path,
                label="created artifact cleanup",
            )
        except PlainReviewError:
            continue
        try:
            try:
                linked = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError:
                continue
            if (
                _is_private_created_file(linked)
                and _same_completed_file(created, linked)
            ):
                _discard_failed_create(
                    parent_descriptor,
                    path.name,
                    linked,
                )
        finally:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass
    if directories is not None:
        _discard_created_directories(directories)


def ensure_distinct_output_paths(paths: list[Path]) -> None:
    try:
        normalized = [path.resolve(strict=False) for path in paths]
    except OSError as exc:
        raise PlainReviewError(f"cannot resolve output path: {exc}") from exc
    if len(set(normalized)) != len(normalized):
        raise PlainReviewError(
            "evidence, raw review, and transmitted prompt paths must be distinct"
        )


def validate_output_artifact_paths(
    output_path: Path,
    raw_review_path: Path,
    transmitted_prompt_path: Path,
) -> None:
    labelled_paths = (
        ("evidence output", output_path),
        ("raw review output", raw_review_path),
        ("transmitted prompt output", transmitted_prompt_path),
    )
    for label, path in labelled_paths:
        path_text = os.fspath(path)
        if "\x00" in path_text or _contains_unicode_surrogate(path_text):
            raise PlainReviewError(f"{label} contains invalid path text")
    try:
        artifact_root = output_path.parent.resolve(strict=False)
        resolved_paths = {
            label: path.resolve(strict=False)
            for label, path in labelled_paths[1:]
        }
    except (OSError, RuntimeError) as exc:
        raise PlainReviewError(f"cannot resolve output artifact path: {exc}") from exc
    for label, resolved in resolved_paths.items():
        if resolved == artifact_root or artifact_root not in resolved.parents:
            raise PlainReviewError(
                f"{label} must stay inside the evidence artifact directory"
            )


def build_evidence(
    *,
    manifest: dict[str, Any],
    provider: str,
    executable: str,
    model: str | None,
    prompt_sha256: str,
    prompt_bytes: int,
    prompt_path: Path,
    raw_review_path: Path,
    completed: subprocess.CompletedProcess[str],
    argv: list[str],
    removed_billable_environment: list[str],
    removed_git_context_environment: list[str],
    removed_session_environment: list[str],
    passed_environment_keys: list[str],
    resolved_executable: str,
    review: dict[str, Any],
    prompt_nonce: str,
    context_attestation: str | None,
) -> dict[str, Any]:
    verdict = review["verdict"]
    finding_count = review["finding_count"]
    pass_without_findings = verdict == "PASS" and finding_count == 0
    source = (
        f"{PLAIN_LLM_REVIEW_SOURCE_PREFIX}{provider}:{model or 'default'}"
    )
    return {
        "schema_version": 1,
        "kind": "external_review",
        "repo": manifest["repo"],
        "pr": manifest["pr"],
        "head_sha": manifest["head_sha"],
        "diff_sha256": manifest["diff_sha256"],
        "prompt_sha256": prompt_sha256,
        "prompt_includes_diff": True,
        "prompt_transmitted": True,
        "review_input": {
            "mode": PLAIN_LLM_REVIEW_INPUT_MODE,
            "repo": manifest["repo"],
            "pr": manifest["pr"],
            "head_sha": manifest["head_sha"],
            "diff_sha256": manifest["diff_sha256"],
            "transport": (
                "prompt_file"
                if provider in {"grok", "ox-alpha"}
                else "argv"
            ),
            "account_transport": "account_cli",
            "provider": provider,
            "requested_model": model or "default",
            "model_identity_attestation": "requested_not_provider_attested",
            "executable": resolved_executable,
            "requested_executable": executable,
            "executable_identity": (
                "canonical_native_owner_controlled"
                if provider == "grok"
                else "owner_regular_executable_not_group_world_writable"
            ),
            "packet_prompt_sha256": manifest["prompt_sha256"],
            "prompt_sha256": prompt_sha256,
            "prompt_nonce": prompt_nonce,
            "prompt_argument_exposure": provider == "gemini",
            "ephemeral_prompt_file": provider in {"grok", "ox-alpha"},
            "context_attestation": context_attestation,
            "paid_fallback_policy": (
                "disabled_by_exact_model"
                if provider == "ox-alpha"
                else "not_established_by_adapter"
            ),
            "transmitted_prompt_bytes": prompt_bytes,
            "transmitted_prompt_path": str(
                Path(os.path.abspath(prompt_path))
            ),
            "raw_review_path": str(
                Path(os.path.abspath(raw_review_path))
            ),
            "isolated_working_directory": True,
            "local_repository_context_provided": False,
            "web_search_policy": (
                "disabled_by_cli"
                if provider == "grok"
                else "forbidden_by_prompt_unverified"
            ),
            "memory_policy": (
                "disabled_by_cli"
                if provider == "grok"
                else "new_single_turn_no_resume"
            ),
            "quota_attestation": "not_established_by_adapter",
            "review_gate_authority": PLAIN_LLM_REVIEW_GATE_AUTHORITY,
            "environment_policy": PLAIN_LLM_ENVIRONMENT_POLICY,
            "environment_passed_keys": sorted(passed_environment_keys),
            "session_environment_removed": sorted(
                removed_session_environment
            ),
            "session_bus_exposed": False,
            "stdin_policy": "null_device",
            "process_group_isolated": True,
            "provider_output_limit_enforcement": "kill_process_group",
            "workspace_readback": "unchanged",
            "billable_api_environment_removed": sorted(
                removed_billable_environment
            ),
            "git_context_environment_removed": sorted(
                removed_git_context_environment
            ),
        },
        "reviews": [
            {
                "source": source,
                "provider": provider,
                "model": model or "default",
                "transport": "account_cli",
                "execution_mode": "single_turn",
                "tool_policy": (
                    "sandboxed_plan_mode"
                    if provider == "gemini"
                    else (
                        "empty_tools_plan_mode"
                        if provider == "grok"
                        else "opencode_pure_plan_agent"
                    )
                ),
                "argv_sha256": canonical_sha256(argv),
                "stdout_sha256": sha256_text(completed.stdout),
                "stderr_sha256": sha256_text(completed.stderr),
                "review_sha256": sha256_text(completed.stdout),
                "parsed_review_sha256": plain_llm_review_payload_sha256(
                    verdict=verdict,
                    finding_count=finding_count,
                    findings=review["findings"],
                ),
                "verdict": verdict,
                "finding_count": finding_count,
                "findings": review["findings"],
            }
        ],
        "external_reviews_triaged": pass_without_findings,
        "findings": [],
    }


def run_from_manifest(
    *,
    manifest_path: Path,
    output_path: Path,
    raw_review_path: Path | None,
    transmitted_prompt_path: Path | None,
    provider: str,
    executable: str,
    model: str | None,
    timeout_seconds: int,
    max_prompt_bytes: int,
    max_review_bytes: int = DEFAULT_MAX_REVIEW_BYTES,
    context_attestation: str | None = None,
) -> dict[str, Any]:
    if provider not in PROVIDERS:
        raise PlainReviewError(f"unsupported plain review provider: {provider}")
    if provider == "ox-alpha":
        if context_attestation not in OX_ALPHA_CONTEXT_ATTESTATIONS:
            raise PlainReviewError(
                "Ox Alpha plain review requires an explicit safe context "
                "attestation: public-context, synthetic-context, or "
                "non-sensitive-context"
            )
        if model is not None and model != OX_ALPHA_MODEL:
            raise PlainReviewError(
                f"Ox Alpha plain review requires exact model {OX_ALPHA_MODEL}"
            )
        model = OX_ALPHA_MODEL
    elif context_attestation is not None:
        raise PlainReviewError(
            "context attestation is only valid for the Ox Alpha provider"
        )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise PlainReviewError("timeout seconds must be a positive integer")
    if (
        isinstance(max_prompt_bytes, bool)
        or not isinstance(max_prompt_bytes, int)
        or max_prompt_bytes <= 0
    ):
        raise PlainReviewError("max prompt bytes must be a positive integer")
    if max_prompt_bytes > PLAIN_LLM_MAX_TRANSMITTED_PROMPT_BYTES:
        raise PlainReviewError(
            "max prompt bytes exceeds the retained transmitted prompt gate "
            f"limit of {PLAIN_LLM_MAX_TRANSMITTED_PROMPT_BYTES} bytes"
        )
    if (
        isinstance(max_review_bytes, bool)
        or not isinstance(max_review_bytes, int)
        or max_review_bytes <= 0
    ):
        raise PlainReviewError("max review bytes must be a positive integer")
    if max_review_bytes > PLAIN_LLM_MAX_RAW_REVIEW_BYTES:
        raise PlainReviewError(
            "max review bytes exceeds the retained raw review gate limit of "
            f"{PLAIN_LLM_MAX_RAW_REVIEW_BYTES} bytes"
        )
    _validate_inherited_environment_text(dict(os.environ))
    if (
        not isinstance(executable, str)
        or not executable
        or "\x00" in executable
        or _contains_unicode_surrogate(executable)
    ):
        raise PlainReviewError("provider executable is missing or invalid")
    if model is not None and (
        not isinstance(model, str)
        or not model.strip()
        or "\x00" in model
        or _contains_unicode_surrogate(model)
    ):
        raise PlainReviewError("provider model label is missing or invalid")
    raw_path = raw_review_path or output_path.with_suffix(".review.txt")
    sent_prompt_path = (
        transmitted_prompt_path or output_path.with_suffix(".prompt.txt")
    )
    validate_output_artifact_paths(output_path, raw_path, sent_prompt_path)
    ensure_distinct_output_paths(
        [output_path, raw_path, sent_prompt_path]
    )
    try:
        manifest_path = manifest_path.resolve(strict=True)
        manifest_expected = manifest_path.lstat()
    except OSError as exc:
        raise PlainReviewError(
            f"cannot resolve external review manifest: {exc}"
        ) from exc
    manifest_expected = _validate_private_packet_input(
        manifest_path,
        manifest_expected,
        label="external review manifest",
    )
    manifest = load_json(
        manifest_path,
        label="external review manifest",
        max_bytes=MAX_PACKET_MANIFEST_BYTES,
        expected=manifest_expected,
    )
    validate_manifest(manifest)
    diff_path, diff_expected = resolve_packet_file(
        manifest_path, manifest["diff_path"], label="diff_path"
    )
    packet_prompt_path, prompt_expected = resolve_packet_file(
        manifest_path, manifest["prompt_path"], label="prompt_path"
    )
    diff_expected = _validate_private_packet_input(
        diff_path,
        diff_expected,
        label="diff file",
    )
    prompt_expected = _validate_private_packet_input(
        packet_prompt_path,
        prompt_expected,
        label="prompt file",
    )
    diff_bytes = read_bytes(
        diff_path,
        label="diff file",
        max_bytes=max_prompt_bytes,
        expected=diff_expected,
    )
    if sha256_bytes(diff_bytes) != manifest["diff_sha256"]:
        raise PlainReviewError("diff file sha256 does not match manifest")
    packet_prompt = read_text(
        packet_prompt_path,
        label="prompt file",
        max_bytes=max_prompt_bytes,
        expected=prompt_expected,
    )
    if sha256_text(packet_prompt) != manifest["prompt_sha256"]:
        raise PlainReviewError("prompt file sha256 does not match manifest")
    try:
        diff_text = diff_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PlainReviewError(
            f"diff file is not valid UTF-8: {exc}"
        ) from exc
    prompt_nonce = secrets.token_hex(16)
    prompt = build_plain_prompt(
        packet_prompt, diff_text, prompt_nonce
    )
    prompt_bytes = prompt.encode("utf-8")
    if len(prompt_bytes) > max_prompt_bytes:
        raise PlainReviewError(
            "plain review prompt is too large for transport: "
            f"{len(prompt_bytes)} bytes > {max_prompt_bytes}"
        )
    _validate_provider_prompt_transport(provider, prompt_bytes)
    if output_path.exists():
        raise PlainReviewError(f"evidence output already exists: {output_path}")
    if raw_path.exists():
        raise PlainReviewError(f"raw review output already exists: {raw_path}")
    if sent_prompt_path.exists():
        raise PlainReviewError(
            f"transmitted prompt output already exists: {sent_prompt_path}"
        )
    # Paths created by this run, discarded again if the run fails before the
    # provider returned a structurally valid review.
    created_paths: list[tuple[Path, os.stat_result]] = []
    created_directories: list[tuple[Path, os.stat_result]] = []
    try:
        sent_prompt_identity = write_text_create_only(
            sent_prompt_path,
            prompt,
            label="transmitted prompt output",
            created_directories=created_directories,
        )
        created_paths.append((sent_prompt_path, sent_prompt_identity))
        (
            completed,
            argv,
            removed_billable,
            removed_git_context,
            removed_session,
            passed_environment_keys,
            resolved_executable,
        ) = run_provider(
            prompt,
            provider=provider,
            executable=executable,
            model=model,
            timeout_seconds=timeout_seconds,
            max_review_bytes=max_review_bytes,
        )
        stdout_bytes = len(completed.stdout.encode("utf-8"))
        stderr_bytes = len(completed.stderr.encode("utf-8"))
        if stdout_bytes > max_review_bytes or stderr_bytes > max_review_bytes:
            raise PlainReviewError(
                f"{provider} CLI output exceeds {max_review_bytes} bytes "
                f"(stdout={stdout_bytes}, stderr={stderr_bytes})"
            )
        if completed.stdout:
            raw_identity = write_text_create_only(
                raw_path,
                completed.stdout,
                label="raw review output",
                created_directories=created_directories,
            )
            created_paths.append((raw_path, raw_identity))
        if completed.returncode != 0:
            raise PlainReviewError(
                f"{provider} CLI exited with {completed.returncode}; "
                f"stdout_sha256={sha256_text(completed.stdout)}; "
                f"stderr_sha256={sha256_text(completed.stderr)}"
            )
        if not completed.stdout.strip():
            raise PlainReviewError(f"{provider} CLI returned empty stdout")
        review = parse_review_json(completed.stdout)
    except BaseException:
        discard_created_paths(created_paths, created_directories)
        raise
    # The provider answered with a valid review, so the transmitted prompt and
    # raw response are the forensic record and are kept even if publication
    # below fails.
    created_paths.clear()
    created_directories.clear()
    evidence = build_evidence(
        manifest=manifest,
        provider=provider,
        executable=executable,
        model=model,
        prompt_sha256=sha256_text(prompt),
        prompt_bytes=len(prompt_bytes),
        prompt_path=sent_prompt_path,
        raw_review_path=raw_path,
        completed=completed,
        argv=argv,
        removed_billable_environment=removed_billable,
        removed_git_context_environment=removed_git_context,
        removed_session_environment=removed_session,
        passed_environment_keys=passed_environment_keys,
        resolved_executable=resolved_executable,
        review=review,
        prompt_nonce=prompt_nonce,
        context_attestation=context_attestation,
    )
    evidence_text = (
        json.dumps(
            evidence,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    try:
        evidence_bytes = evidence_text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PlainReviewError(
            "external review evidence contains invalid Unicode text"
        ) from exc
    if len(evidence_bytes) > PLAIN_LLM_MAX_EVIDENCE_BYTES:
        raise PlainReviewError(
            "serialized external review evidence exceeds the gate limit of "
            f"{PLAIN_LLM_MAX_EVIDENCE_BYTES} bytes"
        )
    write_text_create_only(
        output_path,
        evidence_text,
        label="evidence output",
    )
    return evidence


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def review_byte_limit(value: str) -> int:
    parsed = positive_int(value)
    if parsed > PLAIN_LLM_MAX_RAW_REVIEW_BYTES:
        raise argparse.ArgumentTypeError(
            "must not exceed the retained raw review gate limit of "
            f"{PLAIN_LLM_MAX_RAW_REVIEW_BYTES} bytes"
        )
    return parsed


def prompt_byte_limit(value: str) -> int:
    parsed = positive_int(value)
    if parsed > PLAIN_LLM_MAX_TRANSMITTED_PROMPT_BYTES:
        raise argparse.ArgumentTypeError(
            "must not exceed the retained transmitted prompt gate limit of "
            f"{PLAIN_LLM_MAX_TRANSMITTED_PROMPT_BYTES} bytes"
        )
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run a single-turn, tool-constrained advisory external review "
            "for a pr_review_gate packet."
        )
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--provider", required=True, choices=sorted(PROVIDERS)
    )
    parser.add_argument("--executable")
    parser.add_argument("--model")
    parser.add_argument("--context-attestation")
    parser.add_argument("--raw-review-output")
    parser.add_argument("--transmitted-prompt-output")
    parser.add_argument(
        "--timeout-seconds",
        type=positive_int,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--max-prompt-bytes",
        type=prompt_byte_limit,
        default=DEFAULT_MAX_PROMPT_BYTES,
    )
    parser.add_argument(
        "--max-review-bytes",
        type=review_byte_limit,
        default=DEFAULT_MAX_REVIEW_BYTES,
    )
    args = parser.parse_args(argv)
    executable = args.executable or {
        "gemini": "agy",
        "grok": "grok",
        "ox-alpha": "opencode",
    }[args.provider]
    try:
        evidence = run_from_manifest(
            manifest_path=Path(args.manifest),
            output_path=Path(args.output),
            raw_review_path=(
                Path(args.raw_review_output)
                if args.raw_review_output
                else None
            ),
            transmitted_prompt_path=(
                Path(args.transmitted_prompt_output)
                if args.transmitted_prompt_output
                else None
            ),
            provider=args.provider,
            executable=executable,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
            max_prompt_bytes=args.max_prompt_bytes,
            max_review_bytes=args.max_review_bytes,
            context_attestation=args.context_attestation,
        )
    except (PlainReviewError, subprocess.TimeoutExpired) as exc:
        print(
            json.dumps(
                {"ok": False, "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                "evidence": str(Path(args.output)),
                "provider": args.provider,
                "verdict": evidence["reviews"][0]["verdict"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
