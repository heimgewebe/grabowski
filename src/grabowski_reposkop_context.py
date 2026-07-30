from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Any, Iterator

import grabowski_audit_query as audit_query
import grabowski_mcp as base

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
MUTATING = operator.MUTATING
HOME = operator.HOME
STATE_DIR = operator.STATE_DIR
REPOSKOP_BIN = Path(
    os.environ.get("GRABOWSKI_REPOSKOP_BIN", str(HOME / ".local/bin/reposkop"))
).expanduser()
RECEIPT_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_REPOSKOP_RECEIPT_ROOT",
        str(STATE_DIR / "reposkop-context"),
    )
).expanduser()
PURPOSE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_EXECUTABLE_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 512 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_AUDIT_SCAN_RECORDS = 100_000
RECEIPT_KIND = "grabowski.reposkop_context_usage_receipt"
AUDIT_OPERATION = "reposkop-context-usage-publication"
AUDIT_PUBLICATION_CONTRACT = "audit-before-create-exact-bytes-v1"
AUDIT_RECOVERY_CONTRACT = "audit-recovered-existing-exact-bytes-v1"
AUDIT_CONTRACTS = frozenset({AUDIT_PUBLICATION_CONTRACT, AUDIT_RECOVERY_CONTRACT})
TOOL_KIND = "grabowski_reposkop_context"
SCHEMA_VERSION = 1


class ReposkopContextError(RuntimeError):
    pass


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_executable_directory(path: Path, *, trusted_uids: set[int]) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ReposkopContextError(
            f"Reposkop executable ancestor is missing: {path}"
        ) from exc
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in trusted_uids
        or (mode & 0o022 and not mode & stat.S_ISVTX)
    ):
        raise ReposkopContextError(
            "Reposkop executable ancestor failed directory, ownership, symlink or writable-mode checks: "
            f"{path}"
        )


def _validate_executable_ancestors(path: Path) -> None:
    if ".." in path.parts:
        raise ReposkopContextError(
            "Reposkop executable path may not contain parent traversal"
        )
    trusted_uids = {0, os.getuid()}
    current = Path(path.anchor)
    _validate_executable_directory(current, trusted_uids=trusted_uids)
    for component in path.parts[1:-1]:
        current /= component
        _validate_executable_directory(current, trusted_uids=trusted_uids)


def _validate_executable(path: Path) -> tuple[Path, str]:
    if not path.is_absolute() or path.is_symlink():
        raise ReposkopContextError(
            "Reposkop executable must be an absolute non-symlink path"
        )
    _validate_executable_ancestors(path)
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise ReposkopContextError(f"Reposkop executable is missing: {path}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_EXECUTABLE_BYTES
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise ReposkopContextError(
            "Reposkop executable failed ownership, type, link, size, execute or group/world-write checks"
        )
    return path, _sha256_file(path)


def _validate_target(value: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ReposkopContextError("repo must be one absolute path")
    target = Path(value)
    if target.is_symlink():
        raise ReposkopContextError("repo may not be a symlink")
    try:
        metadata = target.stat()
    except FileNotFoundError as exc:
        raise ReposkopContextError(f"repo does not exist: {target}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReposkopContextError("repo must be a directory")
    return target.resolve(strict=True)


def _validate_purpose(value: str) -> str:
    if not isinstance(value, str) or PURPOSE_RE.fullmatch(value) is None:
        raise ReposkopContextError(
            "purpose must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
        )
    return value


def _required_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReposkopContextError(f"Reposkop report has invalid {label}")
    return value


def _is_schema_version_one(value: Any) -> bool:
    return type(value) is int and value == 1


def _reject_nonfinite_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is unsupported: {value}")


def _validate_report(report: Any, *, target: Path, purpose: str) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ReposkopContextError("Reposkop report must be a JSON object")
    if (
        report.get("kind") != "reposkop_coherence_report"
        or not _is_schema_version_one(report.get("schema_version"))
    ):
        raise ReposkopContextError("Reposkop report kind or schema is unsupported")
    if report.get("effect_authorized") is not False:
        raise ReposkopContextError("Reposkop report must keep effect_authorized=false")
    observation = report.get("observation")
    projection = report.get("projection")
    if not isinstance(observation, dict) or not isinstance(projection, dict):
        raise ReposkopContextError(
            "Reposkop report is missing observation or projection"
        )
    if (
        observation.get("kind") != "reposkop_checkout_observation"
        or not _is_schema_version_one(observation.get("schema_version"))
    ):
        raise ReposkopContextError(
            "Reposkop observation kind or schema is unsupported"
        )
    if (
        projection.get("kind") != "reposkop_coherence_projection"
        or not _is_schema_version_one(projection.get("schema_version"))
    ):
        raise ReposkopContextError(
            "Reposkop projection kind or schema is unsupported"
        )
    if projection.get("effect_authorized") is not False:
        raise ReposkopContextError(
            "Reposkop projection must keep effect_authorized=false"
        )
    identities = observation.get("identities")
    if not isinstance(identities, dict):
        raise ReposkopContextError("Reposkop observation is missing identities")
    if identities.get("path") != str(target) or identities.get("purpose") != purpose:
        raise ReposkopContextError(
            "Reposkop report target or purpose does not match the request"
        )
    _required_sha256(
        observation.get("observation_sha256"), label="observation_sha256"
    )
    _required_sha256(
        projection.get("projection_sha256"), label="projection_sha256"
    )
    _required_sha256(report.get("report_sha256"), label="report_sha256")
    return report


def _kill_process_group(process: subprocess.Popen[bytes], *, pgid: int | None = None) -> None:
    # With start_new_session=True the child pid is the session/process-group id.
    # Descendants may outlive the leader, so always signal the recorded pgid.
    target = pgid if pgid is not None else process.pid
    try:
        os.killpg(target, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _close_selector_streams(selector: selectors.BaseSelector) -> None:
    for registered in list(selector.get_map().values()):
        stream = registered.fileobj
        try:
            selector.unregister(stream)
        except KeyError:
            pass
        if not stream.closed:
            stream.close()


def _run_bounded_process(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    stdout_limit: int,
    stderr_limit: int,
) -> dict[str, Any]:
    if timeout_seconds <= 0 or stdout_limit <= 0 or stderr_limit <= 0:
        raise ValueError("Reposkop process limits must be positive")
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=operator._safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    process_group_id = process.pid
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process, pgid=process_group_id)
        process.wait()
        raise ReposkopContextError("Reposkop bounded output pipes are unavailable")
    selector = selectors.DefaultSelector()
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    counts = {"stdout": 0, "stderr": 0}
    exceeded = {"stdout": False, "stderr": False}
    for name, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    deadline = started + timeout_seconds
    timed_out = False
    killed = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                if not killed:
                    _kill_process_group(process, pgid=process_group_id)
                    killed = True
                _close_selector_streams(selector)
                break
            events = selector.select(timeout=min(0.25, remaining))
            for key, _mask in events:
                stream = key.fileobj
                name = key.data
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                counts[name] += len(chunk)
                capacity = max(0, limits[name] - len(buffers[name]))
                if capacity:
                    buffers[name].extend(chunk[:capacity])
                if counts[name] > limits[name]:
                    exceeded[name] = True
            if any(exceeded.values()):
                if not killed:
                    _kill_process_group(process, pgid=process_group_id)
                    killed = True
                _close_selector_streams(selector)
                break
            if process.poll() is not None and not events:
                for registered in list(selector.get_map().values()):
                    stream = registered.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if chunk:
                        name = registered.data
                        counts[name] += len(chunk)
                        capacity = max(0, limits[name] - len(buffers[name]))
                        if capacity:
                            buffers[name].extend(chunk[:capacity])
                        if counts[name] > limits[name]:
                            exceeded[name] = True
                        continue
                    selector.unregister(stream)
                    stream.close()
                if any(exceeded.values()):
                    if not killed:
                        _kill_process_group(process, pgid=process_group_id)
                        killed = True
                    _close_selector_streams(selector)
                    break
        returncode = process.poll()
        if returncode is None:
            if killed:
                returncode = process.wait()
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    _kill_process_group(process, pgid=process_group_id)
                    killed = True
                    returncode = process.wait()
                else:
                    try:
                        returncode = process.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        _kill_process_group(process, pgid=process_group_id)
                        killed = True
                        returncode = process.wait()
    finally:
        selector.close()
        # Always terminate the session process group. Background descendants may
        # close/redirect inherited pipes and otherwise outlive a successful child
        # exit past the documented command bound (no permanent process).
        _kill_process_group(process, pgid=process_group_id)
        if process.poll() is None:
            process.wait()
        for stream in streams.values():
            if not stream.closed:
                stream.close()
    return {
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout_data": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]).decode("utf-8", errors="replace"),
        "stdout_bytes": counts["stdout"],
        "stderr_bytes": counts["stderr"],
        "stdout_limit_exceeded": exceeded["stdout"],
        "stderr_limit_exceeded": exceeded["stderr"],
    }


def _run_reposkop(
    target: Path, purpose: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    executable, executable_sha256 = _validate_executable(REPOSKOP_BIN)
    result = _run_bounded_process(
        [str(executable), "report", str(target), "--purpose", purpose, "--json"],
        cwd=HOME,
        timeout_seconds=20,
        stdout_limit=MAX_REPORT_BYTES,
        stderr_limit=MAX_STDERR_BYTES,
    )
    if result["timed_out"]:
        raise ReposkopContextError("Reposkop report timed out")
    if result["stdout_limit_exceeded"]:
        raise ReposkopContextError(
            "Reposkop report exceeded the streaming stdout byte limit"
        )
    if result["stderr_limit_exceeded"]:
        raise ReposkopContextError(
            "Reposkop report exceeded the streaming stderr byte limit"
        )
    if result["returncode"] != 0:
        raise ReposkopContextError(
            f"Reposkop report failed with returncode {result['returncode']}: "
            f"{str(result['stderr'])[:1000]}"
        )
    post_executable, post_executable_sha256 = _validate_executable(REPOSKOP_BIN)
    if post_executable != executable or post_executable_sha256 != executable_sha256:
        raise ReposkopContextError(
            "Reposkop executable identity changed during report execution"
        )
    stdout_data = result.get("stdout_data")
    if not isinstance(stdout_data, bytes):
        raise ReposkopContextError("Reposkop report stdout bytes are unavailable")
    try:
        stdout = stdout_data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReposkopContextError(
            "Reposkop report output is not valid UTF-8"
        ) from exc
    try:
        report = json.loads(
            stdout, parse_constant=_reject_nonfinite_json_constant
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ReposkopContextError(
            "Reposkop report output is not valid JSON"
        ) from exc
    return _validate_report(report, target=target, purpose=purpose), {
        "path": str(executable),
        "sha256": executable_sha256,
    }


def _resolve_exact_write_target(
    path: Path, *, allow_missing_parents: bool = False
) -> tuple[Path, bool]:
    resolved, exists = base._resolve_write_target(
        str(path), allow_missing_parents=allow_missing_parents
    )
    if resolved != path:
        raise ReposkopContextError(
            f"Reposkop write target resolved unexpectedly: {path}"
        )
    return resolved, exists


def _validate_binding_write_scope(
    binding: dict[str, Any], *, allow_missing_parents: bool = False
) -> None:
    for key in ("receipt_path", "pending_path", "lock_path"):
        path = binding[key]
        resolved, _exists = _resolve_exact_write_target(
            path, allow_missing_parents=allow_missing_parents
        )
        if resolved.parent != RECEIPT_ROOT:
            raise ReposkopContextError(
                f"Reposkop derived write target escaped its root: {key}"
            )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _validate_directory_path_binding(
    descriptor: int, path: Path, *, label: str
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    try:
        linked = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ReposkopContextError(
            f"{label} changed during descriptor binding"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(linked.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (linked.st_dev, linked.st_ino)
    ):
        raise ReposkopContextError(f"{label} identity is unsafe")
    return metadata


def _open_directory_descriptor(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ReposkopContextError(
            "Reposkop receipt directory path must be absolute without parent traversal"
        )
    flags = _directory_open_flags()
    try:
        descriptor = os.open(path.anchor, flags)
    except OSError as exc:
        raise ReposkopContextError(
            "Reposkop receipt directory root could not be opened safely"
        ) from exc
    try:
        for component in path.parts[1:]:
            try:
                child_descriptor = os.open(
                    component, flags, dir_fd=descriptor
                )
            except OSError as exc:
                raise ReposkopContextError(
                    "Reposkop receipt directory component could not be opened safely"
                ) from exc
            try:
                metadata = os.fstat(child_descriptor)
                linked = os.stat(
                    component,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_ISLNK(linked.st_mode)
                    or (metadata.st_dev, metadata.st_ino)
                    != (linked.st_dev, linked.st_ino)
                ):
                    raise ReposkopContextError(
                        "Reposkop receipt directory component identity is unsafe"
                    )
            except BaseException:
                os.close(child_descriptor)
                raise
            os.close(descriptor)
            descriptor = child_descriptor

        _validate_directory_path_binding(
            descriptor, path, label="Reposkop receipt directory"
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_directory_component_name(component: str) -> None:
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or "\x00" in component
    ):
        raise ReposkopContextError(
            "Reposkop receipt directory component is invalid"
        )


def _open_relative_receipt_directory(
    parent_descriptor: int,
    component: str,
    *,
    require_private: bool = True,
) -> int:
    _validate_directory_component_name(component)
    try:
        descriptor = os.open(
            component, _directory_open_flags(), dir_fd=parent_descriptor
        )
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ReposkopContextError(
            "Reposkop receipt directory component could not be opened safely"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        linked = os.stat(
            component,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (linked.st_dev, linked.st_ino)
        ):
            raise ReposkopContextError(
                "Reposkop receipt directory component identity is unsafe"
            )
        if require_private and (
            metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ReposkopContextError(
                "Reposkop receipt directory has unsafe ownership or mode"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _authorized_write_root(path: Path) -> Path:
    candidates = [
        root
        for root in base._roots("write")
        if path == root or root in path.parents
    ]
    if not candidates:
        raise ReposkopContextError(
            "Reposkop receipt root is outside configured write roots"
        )
    return max(candidates, key=lambda root: len(root.parts))


def _open_from_write_root(
    write_root_descriptor: int,
    components: tuple[str, ...],
    *,
    private_from_index: int,
) -> int:
    descriptor = os.dup(write_root_descriptor)
    try:
        for index, component in enumerate(components):
            child_descriptor = _open_relative_receipt_directory(
                descriptor,
                component,
                require_private=index >= private_from_index,
            )
            os.close(descriptor)
            descriptor = child_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _close_created_directory_records(
    records: list[tuple[int, str]],
) -> None:
    while records:
        parent_descriptor, _component = records.pop()
        os.close(parent_descriptor)


def _rollback_created_directories(
    records: list[tuple[int, str]],
) -> None:
    first_error: OSError | None = None
    while records:
        parent_descriptor, component = records.pop()
        try:
            os.rmdir(component, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        except OSError as exc:
            if first_error is None:
                first_error = exc
        finally:
            os.close(parent_descriptor)
    if first_error is not None:
        raise ReposkopContextError(
            "Reposkop could not roll back directories created outside the authorized path"
        ) from first_error


def _ensure_receipt_root() -> None:
    root_path, _root_exists = _resolve_exact_write_target(
        RECEIPT_ROOT, allow_missing_parents=True
    )
    write_root = _authorized_write_root(root_path)
    try:
        components = root_path.relative_to(write_root).parts
    except ValueError as exc:
        raise ReposkopContextError(
            "Reposkop receipt root could not be made relative to its write root"
        ) from exc

    private_from_index = len(components)
    cursor = write_root
    for index, component in enumerate(components):
        cursor /= component
        if cursor.is_symlink():
            raise ReposkopContextError(
                "Reposkop receipt root path may not contain symlinks"
            )
        if not cursor.exists():
            private_from_index = index
            break

    write_root_descriptor = _open_directory_descriptor(write_root)
    created_directories: list[tuple[int, str]] = []
    try:
        try:
            _validate_directory_path_binding(
                write_root_descriptor,
                write_root,
                label="Reposkop authorized write root",
            )
            for index, component in enumerate(components):
                parent_descriptor = _open_from_write_root(
                    write_root_descriptor,
                    components[:index],
                    private_from_index=private_from_index,
                )
                child_descriptor: int | None = None
                verification_descriptor: int | None = None
                try:
                    try:
                        child_descriptor = _open_relative_receipt_directory(
                            parent_descriptor,
                            component,
                            require_private=(
                                index >= private_from_index
                                or index == len(components) - 1
                            ),
                        )
                    except FileNotFoundError:
                        if index < private_from_index:
                            raise ReposkopContextError(
                                "Reposkop existing receipt ancestor disappeared before creation"
                            )
                        _validate_directory_path_binding(
                            write_root_descriptor,
                            write_root,
                            label="Reposkop authorized write root",
                        )
                        rollback_descriptor = os.dup(parent_descriptor)
                        try:
                            os.mkdir(
                                component, mode=0o700, dir_fd=parent_descriptor
                            )
                        except FileExistsError:
                            os.close(rollback_descriptor)
                        except OSError as exc:
                            os.close(rollback_descriptor)
                            raise ReposkopContextError(
                                "Reposkop receipt directory could not be created relative to its authorized root"
                            ) from exc
                        except BaseException:
                            os.close(rollback_descriptor)
                            raise
                        else:
                            created_directories.append(
                                (rollback_descriptor, component)
                            )
                        child_descriptor = _open_relative_receipt_directory(
                            parent_descriptor,
                            component,
                            require_private=True,
                        )
                        os.fsync(child_descriptor)
                        os.fsync(parent_descriptor)

                    if child_descriptor is None:
                        raise ReposkopContextError(
                            "Reposkop receipt directory descriptor is unavailable"
                        )
                    try:
                        verification_descriptor = _open_from_write_root(
                            write_root_descriptor,
                            components[: index + 1],
                            private_from_index=private_from_index,
                        )
                    except Exception as exc:
                        raise ReposkopContextError(
                            "Reposkop receipt directory left its authorized write-root path during creation"
                        ) from exc
                    observed = os.fstat(child_descriptor)
                    verified = os.fstat(verification_descriptor)
                    if (observed.st_dev, observed.st_ino) != (
                        verified.st_dev,
                        verified.st_ino,
                    ):
                        raise ReposkopContextError(
                            "Reposkop receipt directory left its authorized write-root path during creation"
                        )
                finally:
                    if verification_descriptor is not None:
                        os.close(verification_descriptor)
                    if child_descriptor is not None:
                        os.close(child_descriptor)
                    os.close(parent_descriptor)

            try:
                root_descriptor = _open_from_write_root(
                    write_root_descriptor,
                    components,
                    private_from_index=private_from_index,
                )
            except Exception as exc:
                raise ReposkopContextError(
                    "Reposkop receipt root left its authorized write-root path during creation"
                ) from exc
            try:
                _validate_receipt_root_descriptor(root_descriptor)
                os.fsync(root_descriptor)
                _validate_directory_path_binding(
                    write_root_descriptor,
                    write_root,
                    label="Reposkop authorized write root",
                )
            finally:
                os.close(root_descriptor)
        except BaseException as exc:
            try:
                _rollback_created_directories(created_directories)
            except ReposkopContextError as rollback_exc:
                raise rollback_exc from exc
            if isinstance(exc, ReposkopContextError):
                raise
            if isinstance(exc, Exception):
                raise ReposkopContextError(
                    "Reposkop receipt-root creation failed safely and was rolled back"
                ) from exc
            raise
        else:
            _close_created_directory_records(created_directories)
    finally:
        os.close(write_root_descriptor)


def _receipt_root_components() -> tuple[Path, Path, tuple[str, ...]]:
    root_path, exists = _resolve_exact_write_target(RECEIPT_ROOT)
    if not exists:
        raise ReposkopContextError("Reposkop receipt root is missing")
    write_root = _authorized_write_root(root_path)
    try:
        components = root_path.relative_to(write_root).parts
    except ValueError as exc:
        raise ReposkopContextError(
            "Reposkop receipt root could not be made relative to its write root"
        ) from exc
    return root_path, write_root, components


def _validate_receipt_root_descriptor(descriptor: int) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ReposkopContextError(
            "Reposkop receipt root descriptor has unsafe ownership, type or mode"
        )
    try:
        linked = RECEIPT_ROOT.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ReposkopContextError(
            "Reposkop receipt root disappeared after descriptor binding"
        ) from exc
    if stat.S_ISLNK(linked.st_mode) or (linked.st_dev, linked.st_ino) != (
        metadata.st_dev,
        metadata.st_ino,
    ):
        raise ReposkopContextError(
            "Reposkop receipt root path identity changed after descriptor binding"
        )
    # Path must still resolve under configured write roots (catches rename out of scope).
    try:
        root_path, write_root, _components = _receipt_root_components()
    except ReposkopContextError as exc:
        raise ReposkopContextError(
            "Reposkop receipt root left its authorized write-root path"
        ) from exc
    if write_root not in root_path.parents and root_path != write_root:
        raise ReposkopContextError(
            "Reposkop receipt root left its authorized write-root path"
        )
    return metadata


def _open_receipt_root_under_write_root() -> tuple[int, int]:
    """Open receipt root only by walking from an authorized write-root descriptor.

    Existing intermediate ancestors may use normal shared modes (e.g. 0755 under
    ${HOME}). Only the final receipt-root component must be owner-private 0700.
    """
    root_path, write_root, components = _receipt_root_components()
    write_root_descriptor = _open_directory_descriptor(write_root)
    try:
        _validate_directory_path_binding(
            write_root_descriptor,
            write_root,
            label="Reposkop authorized write root",
        )
        if components:
            # Only the leaf receipt directory is required to be private 0700.
            private_from_index = max(0, len(components) - 1)
            receipt_descriptor = _open_from_write_root(
                write_root_descriptor,
                components,
                private_from_index=private_from_index,
            )
        else:
            receipt_descriptor = os.dup(write_root_descriptor)
        try:
            _validate_receipt_root_descriptor(receipt_descriptor)
            return write_root_descriptor, receipt_descriptor
        except BaseException:
            os.close(receipt_descriptor)
            raise
    except BaseException:
        os.close(write_root_descriptor)
        raise


@contextmanager
def _publication_receipt_root() -> Iterator[int]:
    """Re-anchor the receipt root for each mutating publication step."""
    write_root_descriptor, receipt_descriptor = _open_receipt_root_under_write_root()
    try:
        yield receipt_descriptor
    finally:
        os.close(receipt_descriptor)
        os.close(write_root_descriptor)


@contextmanager
def _receipt_root_descriptor() -> Iterator[int]:
    write_root_descriptor, receipt_descriptor = _open_receipt_root_under_write_root()
    try:
        yield receipt_descriptor
    finally:
        os.close(receipt_descriptor)
        os.close(write_root_descriptor)


def _entry_exists(root_descriptor: int, path: Path) -> bool:
    if path.parent != RECEIPT_ROOT:
        raise ReposkopContextError("Reposkop receipt entry escaped its bound root")
    try:
        os.stat(path.name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ReposkopContextError(
            "Reposkop receipt entry could not be inspected relative to its root"
        ) from exc
    return True


def _fsync_directory(root_descriptor: int) -> None:
    os.fsync(root_descriptor)


def _receipt_identity(
    report: dict[str, Any], *, target: Path, purpose: str, executable_sha256: str
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "target_path": str(target),
        "purpose": purpose,
        "reposkop_executable_sha256": executable_sha256,
        "observation_sha256": report["observation"]["observation_sha256"],
        "projection_sha256": report["projection"]["projection_sha256"],
    }


def _receipt_payload(
    identity: dict[str, Any], *, usage_key_sha256: str
) -> dict[str, Any]:
    return {
        "kind": RECEIPT_KIND,
        **identity,
        "usage_key_sha256": usage_key_sha256,
        "effect_authorized": False,
        "does_not_establish": [
            "task_or_queue_truth",
            "pull_request_or_remote_freshness",
            "cleanup_or_mutation_authority",
            "decision_change_or_product_value",
        ],
    }


def _usage_binding(
    report: dict[str, Any], *, target: Path, purpose: str, executable: dict[str, str]
) -> dict[str, Any]:
    identity = _receipt_identity(
        report,
        target=target,
        purpose=purpose,
        executable_sha256=executable["sha256"],
    )
    usage_key_sha256 = _sha256_bytes(_canonical_json(identity))
    receipt_path = RECEIPT_ROOT / f"{usage_key_sha256}.json"
    payload = _receipt_payload(identity, usage_key_sha256=usage_key_sha256)
    data = _canonical_json(payload)
    if len(data) > MAX_RECEIPT_BYTES:
        raise ReposkopContextError("Reposkop usage receipt exceeds its byte limit")
    return {
        "identity": identity,
        "usage_key_sha256": usage_key_sha256,
        "receipt_path": receipt_path,
        "pending_path": RECEIPT_ROOT / f".{usage_key_sha256}.pending",
        "lock_path": RECEIPT_ROOT / f".{usage_key_sha256}.lock",
        "payload": payload,
        "data": data,
        "receipt_sha256": _sha256_bytes(data),
    }


def _validate_regular_metadata(
    metadata: os.stat_result,
    *,
    label: str,
    allowed_links: set[int],
    expected_size: int | None = None,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink not in allowed_links
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > MAX_RECEIPT_BYTES
        or (expected_size is not None and metadata.st_size != expected_size)
    ):
        raise ReposkopContextError(f"{label} has unsafe metadata")


def _read_exact_regular(
    path: Path,
    expected_data: bytes,
    *,
    label: str,
    root_descriptor: int,
    allowed_links: set[int] | None = None,
    sync_data: bool = False,
) -> tuple[os.stat_result, str]:
    if path.parent != RECEIPT_ROOT:
        raise ReposkopContextError(f"{label} escaped its bound receipt root")
    links = {1} if allowed_links is None else allowed_links
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=root_descriptor)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ReposkopContextError(f"{label} could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        _validate_regular_metadata(
            before,
            label=label,
            allowed_links=links,
            expected_size=len(expected_data),
        )
        data = b""
        while len(data) <= MAX_RECEIPT_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_RECEIPT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ReposkopContextError(f"{label} changed during read")
        if data != expected_data:
            raise ReposkopContextError(f"{label} content does not match its binding")
        if sync_data:
            os.fsync(descriptor)
            durable = os.fstat(descriptor)
            if (
                durable.st_dev,
                durable.st_ino,
                durable.st_size,
                durable.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise ReposkopContextError(f"{label} changed while being synced")
            after = durable
    finally:
        os.close(descriptor)
    try:
        linked = os.stat(
            path.name,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise ReposkopContextError(f"{label} disappeared after read") from exc
    if (linked.st_dev, linked.st_ino) != (after.st_dev, after.st_ino):
        raise ReposkopContextError(f"{label} path identity changed after read")
    return after, _sha256_bytes(data)


@contextmanager
def _receipt_lock(lock_path: Path, *, root_descriptor: int) -> Iterator[None]:
    if lock_path.parent != RECEIPT_ROOT:
        raise ReposkopContextError("Reposkop receipt lock escaped its bound root")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            lock_path.name,
            flags,
            0o600,
            dir_fd=root_descriptor,
        )
    except OSError as exc:
        raise ReposkopContextError("Reposkop receipt lock could not be opened") from exc
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ReposkopContextError("Reposkop receipt lock has unsafe metadata")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _audit_record(
    binding: dict[str, Any],
    *,
    recorded_at: str,
    publication_contract: str,
) -> dict[str, Any]:
    if publication_contract not in AUDIT_CONTRACTS:
        raise ReposkopContextError("Reposkop audit publication contract is invalid")
    identity = binding["identity"]
    record: dict[str, Any] = {
        "timestamp": recorded_at,
        "operation": AUDIT_OPERATION,
        "path": str(binding["receipt_path"]),
        "repo": identity["target_path"],
        "purpose": identity["purpose"],
        "transaction_id": binding["usage_key_sha256"],
        "after_sha256": binding["receipt_sha256"],
        "bytes": len(binding["data"]),
        "reposkop_executable_sha256": identity["reposkop_executable_sha256"],
        "observation_sha256": identity["observation_sha256"],
        "projection_sha256": identity["projection_sha256"],
        "effect_authorized": False,
        "publication_contract": publication_contract,
    }
    if publication_contract == AUDIT_RECOVERY_CONTRACT:
        record["recovery"] = {
            "kind": "existing-exact-receipt-audit-rebinding",
            "receipt_observed_before_audit": True,
        }
    return record


def _audit_contract_matches(record: dict[str, Any]) -> bool:
    publication_contract = record.get("publication_contract")
    recovery = record.get("recovery")
    if publication_contract == AUDIT_PUBLICATION_CONTRACT:
        return recovery is None
    if publication_contract == AUDIT_RECOVERY_CONTRACT:
        return recovery == {
            "kind": "existing-exact-receipt-audit-rebinding",
            "receipt_observed_before_audit": True,
        }
    return False


def _audit_record_matches(record: dict[str, Any], binding: dict[str, Any]) -> bool:
    identity = binding["identity"]
    return (
        record.get("operation") == AUDIT_OPERATION
        and record.get("path") == str(binding["receipt_path"])
        and record.get("repo") == identity["target_path"]
        and record.get("purpose") == identity["purpose"]
        and record.get("transaction_id") == binding["usage_key_sha256"]
        and record.get("after_sha256") == binding["receipt_sha256"]
        and record.get("bytes") == len(binding["data"])
        and record.get("reposkop_executable_sha256")
        == identity["reposkop_executable_sha256"]
        and record.get("observation_sha256") == identity["observation_sha256"]
        and record.get("projection_sha256") == identity["projection_sha256"]
        and record.get("effect_authorized") is False
        and _audit_contract_matches(record)
    )


def _find_audit_binding(binding: dict[str, Any]) -> dict[str, str] | None:
    snapshot = audit_query.capture_verified_audit_snapshot()
    scanned = 0
    for segment in reversed(snapshot.segments):
        data = audit_query._load_snapshot_segment(segment)
        for raw_line in reversed(data.splitlines()):
            if scanned >= MAX_AUDIT_SCAN_RECORDS:
                return None
            scanned += 1
            try:
                record = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ReposkopContextError(
                    "Verified audit snapshot yielded an invalid record"
                ) from exc
            if not isinstance(record, dict):
                raise ReposkopContextError(
                    "Verified audit snapshot yielded a non-object record"
                )
            if not _audit_record_matches(record, binding):
                continue
            digest = audit_query._record_evidence_digest(record, raw_line)
            recorded_at = record.get("timestamp")
            if not isinstance(recorded_at, str) or not recorded_at:
                raise ReposkopContextError(
                    "Reposkop audit binding is missing its timestamp"
                )
            publication_contract = record.get("publication_contract")
            if not isinstance(publication_contract, str):
                raise ReposkopContextError(
                    "Reposkop audit binding is missing its publication contract"
                )
            return {
                "audit_ref": f"audit-record-sha256:{digest}",
                "recorded_at": recorded_at,
                "publication_contract": publication_contract,
            }
    return None


def _append_audit_binding(
    binding: dict[str, Any], *, publication_contract: str
) -> dict[str, str]:
    recorded_at = datetime.now(timezone.utc).isoformat()
    digest = base._append_audit_with_digest(
        _audit_record(
            binding,
            recorded_at=recorded_at,
            publication_contract=publication_contract,
        )
    )
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise ReposkopContextError("Reposkop audit binding digest is invalid")
    return {
        "audit_ref": f"audit-record-sha256:{digest}",
        "recorded_at": recorded_at,
        "publication_contract": publication_contract,
    }


def _discard_recoverable_pending(
    binding: dict[str, Any], *, root_descriptor: int
) -> None:
    pending_path = binding["pending_path"]
    if _entry_exists(root_descriptor, binding["receipt_path"]):
        raise ReposkopContextError(
            "Reposkop pending receipt cannot be replaced after publication"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            pending_path.name,
            flags,
            dir_fd=root_descriptor,
        )
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ReposkopContextError(
            "Reposkop pending receipt could not be inspected for recovery"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        expected = binding["data"]
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size >= len(expected)
        ):
            raise ReposkopContextError(
                "Reposkop pending receipt is not safely recoverable"
            )
        observed = bytearray()
        while len(observed) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(observed))
            if not chunk:
                break
            observed.extend(chunk)
        post_read = os.fstat(descriptor)
        if (
            post_read.st_size != metadata.st_size
            or bytes(observed) != expected[: metadata.st_size]
        ):
            raise ReposkopContextError(
                "Reposkop pending receipt is not the exact expected byte prefix"
            )
        try:
            linked = os.stat(
                pending_path.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if (linked.st_dev, linked.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ReposkopContextError(
                "Reposkop pending receipt path changed during recovery"
            )
        try:
            os.unlink(pending_path.name, dir_fd=root_descriptor)
        except FileNotFoundError:
            return
        _fsync_directory(root_descriptor)
    finally:
        os.close(descriptor)


def _create_pending(binding: dict[str, Any], *, root_descriptor: int) -> None:
    del root_descriptor  # re-anchor immediately before the leaf create
    with _publication_receipt_root() as live_root:
        _create_pending_on_descriptor(binding, root_descriptor=live_root)


def _create_pending_on_descriptor(
    binding: dict[str, Any], *, root_descriptor: int
) -> None:
    pending_path = binding["pending_path"]
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(
            pending_path.name,
            flags,
            0o600,
            dir_fd=root_descriptor,
        )
    except FileExistsError:
        try:
            _read_exact_regular(
                pending_path,
                binding["data"],
                label="Reposkop pending receipt",
                root_descriptor=root_descriptor,
                sync_data=True,
            )
        except ReposkopContextError:
            _discard_recoverable_pending(
                binding,
                root_descriptor=root_descriptor,
            )
            try:
                descriptor = os.open(
                    pending_path.name,
                    flags,
                    0o600,
                    dir_fd=root_descriptor,
                )
            except FileExistsError as exc:
                raise ReposkopContextError(
                    "Reposkop pending receipt changed during recovery"
                ) from exc
            except OSError as exc:
                raise ReposkopContextError(
                    "Reposkop pending receipt could not be recreated"
                ) from exc
        else:
            return
    except OSError as exc:
        raise ReposkopContextError(
            "Reposkop pending receipt could not be created"
        ) from exc
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(binding["data"])
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("short write")
            written += count
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(pending_path.name, dir_fd=root_descriptor)
            _fsync_directory(root_descriptor)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    _read_exact_regular(
        pending_path,
        binding["data"],
        label="Reposkop pending receipt",
        root_descriptor=root_descriptor,
    )


def _recover_linked_pending(
    binding: dict[str, Any], *, root_descriptor: int
) -> bool:
    receipt_path = binding["receipt_path"]
    pending_path = binding["pending_path"]
    if not _entry_exists(root_descriptor, receipt_path) or not _entry_exists(
        root_descriptor, pending_path
    ):
        return False
    receipt_metadata, _receipt_sha = _read_exact_regular(
        receipt_path,
        binding["data"],
        label="Reposkop usage receipt",
        allowed_links={1, 2},
        root_descriptor=root_descriptor,
    )
    pending_metadata, _pending_sha = _read_exact_regular(
        pending_path,
        binding["data"],
        label="Reposkop pending receipt",
        allowed_links={1, 2},
        root_descriptor=root_descriptor,
    )
    if (receipt_metadata.st_dev, receipt_metadata.st_ino) != (
        pending_metadata.st_dev,
        pending_metadata.st_ino,
    ):
        raise ReposkopContextError(
            "Reposkop receipt and pending file do not share one publication inode"
        )
    os.unlink(pending_path.name, dir_fd=root_descriptor)
    _fsync_directory(root_descriptor)
    _read_exact_regular(
        receipt_path,
        binding["data"],
        label="Reposkop usage receipt",
        root_descriptor=root_descriptor,
    )
    return True


def _publish_receipt(binding: dict[str, Any], *, root_descriptor: int) -> None:
    del root_descriptor  # callers may pass a prior fd; publication always re-anchors
    receipt_path = binding["receipt_path"]
    pending_path = binding["pending_path"]
    with _publication_receipt_root() as live_root:
        if _recover_linked_pending(binding, root_descriptor=live_root):
            return
        if _entry_exists(live_root, receipt_path):
            _read_exact_regular(
                receipt_path,
                binding["data"],
                label="Reposkop usage receipt",
                root_descriptor=live_root,
            )
            _fsync_directory(live_root)
            _read_exact_regular(
                receipt_path,
                binding["data"],
                label="Reposkop usage receipt",
                root_descriptor=live_root,
            )
            return
    # Leaf create re-anchors independently so a rename cannot use a stale dir_fd.
    _create_pending(binding, root_descriptor=-1)
    with _publication_receipt_root() as live_root:
        try:
            os.link(
                pending_path.name,
                receipt_path.name,
                src_dir_fd=live_root,
                dst_dir_fd=live_root,
                follow_symlinks=False,
            )
        except FileExistsError:
            _recover_linked_pending(binding, root_descriptor=live_root)
            if _entry_exists(live_root, pending_path):
                raise ReposkopContextError(
                    "Reposkop receipt publication collided with a different file"
                )
            return
        except OSError as exc:
            raise ReposkopContextError("Reposkop receipt publication failed") from exc
        _recover_linked_pending(binding, root_descriptor=live_root)


def _record_usage(
    binding: dict[str, Any], *, root_descriptor: int
) -> dict[str, Any]:
    with _receipt_lock(
        binding["lock_path"],
        root_descriptor=root_descriptor,
    ):
        _validate_receipt_root_descriptor(root_descriptor)
        existing = _entry_exists(root_descriptor, binding["receipt_path"])
        if existing:
            _read_exact_regular(
                binding["receipt_path"],
                binding["data"],
                label="Reposkop usage receipt",
                allowed_links={1, 2},
                root_descriptor=root_descriptor,
            )
        audit_binding = _find_audit_binding(binding)
        audit_preexisted = audit_binding is not None
        recovered_audit_binding = bool(existing and audit_binding is None)
        if audit_binding is None:
            audit_binding = _append_audit_binding(
                binding,
                publication_contract=(
                    AUDIT_RECOVERY_CONTRACT
                    if existing
                    else AUDIT_PUBLICATION_CONTRACT
                ),
            )
        # Re-open receipt root from the authorized write root immediately before
        # mutation so a same-UID rename out of write roots cannot publish via a
        # stale dir_fd that still points at the moved inode.
        write_root_descriptor, live_root = _open_receipt_root_under_write_root()
        try:
            _publish_receipt(binding, root_descriptor=live_root)
            _validate_receipt_root_descriptor(live_root)
            _read_exact_regular(
                binding["receipt_path"],
                binding["data"],
                label="Reposkop usage receipt",
                root_descriptor=live_root,
            )
        finally:
            os.close(live_root)
            os.close(write_root_descriptor)
        verified_audit = _find_audit_binding(binding)
        if verified_audit is None:
            raise ReposkopContextError(
                "Reposkop usage receipt audit postflight is missing"
            )
        return {
            "path": str(binding["receipt_path"]),
            "sha256": binding["receipt_sha256"],
            "usage_key_sha256": binding["usage_key_sha256"],
            "recorded_at": verified_audit["recorded_at"],
            "replayed": existing,
            "recovered_publication": bool(audit_preexisted and not existing),
            "recovered_audit_binding": recovered_audit_binding,
            "audit_contract": verified_audit["publication_contract"],
            "audit_ref": verified_audit["audit_ref"],
        }


def _context_result(
    *,
    target: Path,
    purpose: str,
    report: dict[str, Any],
    executable: dict[str, str],
    usage_receipt: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": TOOL_KIND,
        "target": {"path": str(target), "purpose": purpose},
        "reposkop": executable,
        "report": report,
        "usage_receipt": usage_receipt,
        "effect_authorized": False,
        "does_not_establish": [
            "task_or_queue_truth",
            "pull_request_or_remote_freshness",
            "cleanup_or_mutation_authority",
            "decision_change_or_product_value",
        ],
    }


@mcp.tool(name="grabowski_reposkop_context", annotations=MUTATING)
def grabowski_reposkop_context(
    repo: str,
    purpose: str = "grabowski-repo-state-context",
) -> dict[str, Any]:
    """Run one target-bound Reposkop report and persist a deduplicated usage receipt."""
    try:
        base._require_capability("file_read")
        target = _validate_target(repo)
        target = base._resolve_existing(str(target), "read")
        selected_purpose = _validate_purpose(purpose)
        operator._require_operator_mutation(
            "terminal_execute", path=str(target), host="heim-pc"
        )
        report, executable = _run_reposkop(target, selected_purpose)
        binding = _usage_binding(
            report,
            target=target,
            purpose=selected_purpose,
            executable=executable,
        )
        root_path, _root_exists = _resolve_exact_write_target(
            RECEIPT_ROOT, allow_missing_parents=True
        )
        _validate_binding_write_scope(binding, allow_missing_parents=True)
        base._require_mutations_enabled(
            "file_write", path=str(root_path), host="heim-pc"
        )
        for key in ("receipt_path", "pending_path", "lock_path"):
            base._require_mutations_enabled(
                "file_write", path=str(binding[key]), host="heim-pc"
            )
        _ensure_receipt_root()
        post_root_path, _post_root_exists = _resolve_exact_write_target(RECEIPT_ROOT)
        if post_root_path != root_path:
            raise ReposkopContextError(
                "Reposkop receipt root identity changed during policy preflight"
            )
        _validate_binding_write_scope(binding)
        with _receipt_root_descriptor() as root_descriptor:
            usage_receipt = _record_usage(
                binding,
                root_descriptor=root_descriptor,
            )
            _validate_receipt_root_descriptor(root_descriptor)
        return _context_result(
            target=target,
            purpose=selected_purpose,
            report=report,
            executable=executable,
            usage_receipt=usage_receipt,
        )
    except ReposkopContextError as exc:
        raise ValueError(str(exc)) from exc
