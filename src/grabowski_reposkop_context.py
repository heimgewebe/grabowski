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


def _validate_executable(path: Path) -> tuple[Path, str]:
    if not path.is_absolute() or path.is_symlink():
        raise ReposkopContextError(
            "Reposkop executable must be an absolute non-symlink path"
        )
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
        or not os.access(path, os.X_OK)
    ):
        raise ReposkopContextError(
            "Reposkop executable failed ownership, type, link, size or mode checks"
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


def _validate_report(report: Any, *, target: Path, purpose: str) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ReposkopContextError("Reposkop report must be a JSON object")
    if (
        report.get("kind") != "reposkop_coherence_report"
        or report.get("schema_version") != 1
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
        or observation.get("schema_version") != 1
    ):
        raise ReposkopContextError(
            "Reposkop observation kind or schema is unsupported"
        )
    if (
        projection.get("kind") != "reposkop_coherence_projection"
        or projection.get("schema_version") != 1
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


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
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
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
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
                    _kill_process_group(process)
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
                    _kill_process_group(process)
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
                        _kill_process_group(process)
                        killed = True
                    _close_selector_streams(selector)
                    break
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            returncode = process.wait(timeout=5)
    finally:
        selector.close()
        if process.poll() is None:
            _kill_process_group(process)
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
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
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


def _ensure_receipt_root() -> None:
    if RECEIPT_ROOT.is_symlink():
        raise ReposkopContextError("Reposkop receipt root may not be a symlink")
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = RECEIPT_ROOT.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ReposkopContextError(
            "Reposkop receipt root has unsafe ownership, type or mode"
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
    allowed_links: set[int] | None = None,
) -> tuple[os.stat_result, str]:
    links = {1} if allowed_links is None else allowed_links
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
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
    finally:
        os.close(descriptor)
    try:
        linked = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ReposkopContextError(f"{label} disappeared after read") from exc
    if (linked.st_dev, linked.st_ino) != (after.st_dev, after.st_ino):
        raise ReposkopContextError(f"{label} path identity changed after read")
    return after, _sha256_bytes(data)


@contextmanager
def _receipt_lock(lock_path: Path) -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
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


def _create_pending(binding: dict[str, Any]) -> None:
    pending_path = binding["pending_path"]
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(pending_path, flags, 0o600)
    except FileExistsError:
        _read_exact_regular(
            pending_path,
            binding["data"],
            label="Reposkop pending receipt",
        )
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
            pending_path.unlink()
            _fsync_directory(RECEIPT_ROOT)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    _read_exact_regular(
        pending_path,
        binding["data"],
        label="Reposkop pending receipt",
    )


def _recover_linked_pending(binding: dict[str, Any]) -> bool:
    receipt_path = binding["receipt_path"]
    pending_path = binding["pending_path"]
    if not receipt_path.exists() or not pending_path.exists():
        return False
    receipt_metadata, _receipt_sha = _read_exact_regular(
        receipt_path,
        binding["data"],
        label="Reposkop usage receipt",
        allowed_links={1, 2},
    )
    pending_metadata, _pending_sha = _read_exact_regular(
        pending_path,
        binding["data"],
        label="Reposkop pending receipt",
        allowed_links={1, 2},
    )
    if (receipt_metadata.st_dev, receipt_metadata.st_ino) != (
        pending_metadata.st_dev,
        pending_metadata.st_ino,
    ):
        raise ReposkopContextError(
            "Reposkop receipt and pending file do not share one publication inode"
        )
    pending_path.unlink()
    _fsync_directory(RECEIPT_ROOT)
    _read_exact_regular(
        receipt_path,
        binding["data"],
        label="Reposkop usage receipt",
    )
    return True


def _publish_receipt(binding: dict[str, Any]) -> None:
    receipt_path = binding["receipt_path"]
    pending_path = binding["pending_path"]
    if _recover_linked_pending(binding):
        return
    if receipt_path.exists():
        _read_exact_regular(
            receipt_path,
            binding["data"],
            label="Reposkop usage receipt",
        )
        return
    _create_pending(binding)
    try:
        os.link(pending_path, receipt_path, follow_symlinks=False)
    except FileExistsError:
        _recover_linked_pending(binding)
        if pending_path.exists():
            raise ReposkopContextError(
                "Reposkop receipt publication collided with a different file"
            )
        return
    except OSError as exc:
        raise ReposkopContextError("Reposkop receipt publication failed") from exc
    _recover_linked_pending(binding)


def _record_usage(binding: dict[str, Any]) -> dict[str, Any]:
    with _receipt_lock(binding["lock_path"]):
        existing = binding["receipt_path"].exists()
        if existing:
            _read_exact_regular(
                binding["receipt_path"],
                binding["data"],
                label="Reposkop usage receipt",
                allowed_links={1, 2},
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
        _publish_receipt(binding)
        _read_exact_regular(
            binding["receipt_path"],
            binding["data"],
            label="Reposkop usage receipt",
        )
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
        usage_receipt = _record_usage(binding)
        return _context_result(
            target=target,
            purpose=selected_purpose,
            report=report,
            executable=executable,
            usage_receipt=usage_receipt,
        )
    except ReposkopContextError as exc:
        raise ValueError(str(exc)) from exc
