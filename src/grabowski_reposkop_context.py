from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

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
RECEIPT_KIND = "grabowski.reposkop_context_usage_receipt"
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
        raise ReposkopContextError("Reposkop executable must be an absolute non-symlink path")
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
        raise ReposkopContextError("purpose must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
    return value


def _required_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ReposkopContextError(f"Reposkop report has invalid {label}")
    return value


def _validate_report(report: Any, *, target: Path, purpose: str) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ReposkopContextError("Reposkop report must be a JSON object")
    if report.get("kind") != "reposkop_coherence_report" or report.get("schema_version") != 1:
        raise ReposkopContextError("Reposkop report kind or schema is unsupported")
    if report.get("effect_authorized") is not False:
        raise ReposkopContextError("Reposkop report must keep effect_authorized=false")
    observation = report.get("observation")
    projection = report.get("projection")
    if not isinstance(observation, dict) or not isinstance(projection, dict):
        raise ReposkopContextError("Reposkop report is missing observation or projection")
    if projection.get("effect_authorized") is not False:
        raise ReposkopContextError("Reposkop projection must keep effect_authorized=false")
    identities = observation.get("identities")
    if not isinstance(identities, dict):
        raise ReposkopContextError("Reposkop observation is missing identities")
    if identities.get("path") != str(target) or identities.get("purpose") != purpose:
        raise ReposkopContextError("Reposkop report target or purpose does not match the request")
    _required_sha256(observation.get("observation_sha256"), label="observation_sha256")
    _required_sha256(projection.get("projection_sha256"), label="projection_sha256")
    _required_sha256(report.get("report_sha256"), label="report_sha256")
    return report


def _run_reposkop(target: Path, purpose: str) -> tuple[dict[str, Any], dict[str, Any]]:
    executable, executable_sha256 = _validate_executable(REPOSKOP_BIN)
    result = operator._run(
        [str(executable), "report", str(target), "--purpose", purpose, "--json"],
        cwd=HOME,
        timeout_seconds=20,
        max_output_bytes=MAX_REPORT_BYTES,
    )
    if result.get("returncode") != 0:
        raise ReposkopContextError(
            f"Reposkop report failed with returncode {result.get('returncode')}: "
            f"{str(result.get('stderr', ''))[:1000]}"
        )
    post_executable, post_executable_sha256 = _validate_executable(REPOSKOP_BIN)
    if post_executable != executable or post_executable_sha256 != executable_sha256:
        raise ReposkopContextError("Reposkop executable identity changed during report execution")
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ReposkopContextError("Reposkop report output is missing or exceeds the byte limit")
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ReposkopContextError("Reposkop report output is not valid JSON") from exc
    return _validate_report(report, target=target, purpose=purpose), {
        "path": str(executable),
        "sha256": executable_sha256,
    }


def _ensure_receipt_root() -> None:
    if RECEIPT_ROOT.is_symlink():
        raise ReposkopContextError("Reposkop receipt root may not be a symlink")
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = RECEIPT_ROOT.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ReposkopContextError("Reposkop receipt root has unsafe ownership or type")
    os.chmod(RECEIPT_ROOT, 0o700)


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


def _read_existing_receipt(path: Path, identity: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if path.is_symlink():
        raise ReposkopContextError("Reposkop usage receipt may not be a symlink")
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > 64 * 1024
    ):
        raise ReposkopContextError("Reposkop usage receipt has unsafe metadata")
    data = path.read_bytes()
    try:
        receipt = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReposkopContextError("Reposkop usage receipt is invalid") from exc
    if not isinstance(receipt, dict) or receipt.get("kind") != RECEIPT_KIND:
        raise ReposkopContextError("Reposkop usage receipt kind is invalid")
    for key, expected in identity.items():
        if receipt.get(key) != expected:
            raise ReposkopContextError(f"Reposkop usage receipt identity drift: {key}")
    return receipt, _sha256_bytes(data)


def _usage_binding(
    report: dict[str, Any], *, target: Path, purpose: str, executable: dict[str, str]
) -> tuple[dict[str, Any], str, Path]:
    identity = _receipt_identity(
        report,
        target=target,
        purpose=purpose,
        executable_sha256=executable["sha256"],
    )
    usage_key_sha256 = _sha256_bytes(_canonical_json(identity))
    receipt_path = RECEIPT_ROOT / f"{usage_key_sha256}.json"
    return identity, usage_key_sha256, receipt_path


def _record_usage(
    report: dict[str, Any],
    *,
    identity: dict[str, Any],
    usage_key_sha256: str,
    receipt_path: Path,
) -> dict[str, Any]:
    _ensure_receipt_root()
    if receipt_path.exists():
        receipt, receipt_sha256 = _read_existing_receipt(receipt_path, identity)
        return {
            "path": str(receipt_path),
            "sha256": receipt_sha256,
            "usage_key_sha256": usage_key_sha256,
            "recorded_at": receipt["recorded_at"],
            "replayed": True,
        }
    payload = {
        "kind": RECEIPT_KIND,
        **identity,
        "usage_key_sha256": usage_key_sha256,
        "report_sha256": report["report_sha256"],
        "report_generated_at": report.get("generated_at"),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "effect_authorized": False,
        "does_not_establish": [
            "task_or_queue_truth",
            "pull_request_or_remote_freshness",
            "cleanup_or_mutation_authority",
            "decision_change_or_product_value",
        ],
    }
    data = _canonical_json(payload)
    try:
        descriptor = os.open(
            receipt_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        receipt, receipt_sha256 = _read_existing_receipt(receipt_path, identity)
        return {
            "path": str(receipt_path),
            "sha256": receipt_sha256,
            "usage_key_sha256": usage_key_sha256,
            "recorded_at": receipt["recorded_at"],
            "replayed": True,
        }
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        directory_descriptor = os.open(RECEIPT_ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        try:
            receipt_path.unlink()
        except OSError:
            pass
        raise
    receipt_sha256 = _sha256_bytes(data)
    audit_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "reposkop-context-usage-record",
        "path": str(receipt_path),
        "repo": identity["target_path"],
        "purpose": identity["purpose"],
        "after_sha256": receipt_sha256,
        "bytes": len(data),
        "usage_key_sha256": usage_key_sha256,
        "reposkop_executable_sha256": identity["reposkop_executable_sha256"],
        "observation_sha256": identity["observation_sha256"],
        "projection_sha256": identity["projection_sha256"],
        "report_sha256": report["report_sha256"],
        "effect_authorized": False,
    }
    try:
        audit_record_sha256 = base._append_audit_with_digest(audit_record)
    except BaseException:
        try:
            receipt_path.unlink()
            directory_descriptor = os.open(
                RECEIPT_ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            pass
        raise
    return {
        "path": str(receipt_path),
        "sha256": receipt_sha256,
        "usage_key_sha256": usage_key_sha256,
        "recorded_at": payload["recorded_at"],
        "replayed": False,
        "audit_ref": f"audit-record-sha256:{audit_record_sha256}",
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
        identity, usage_key_sha256, receipt_path = _usage_binding(
            report,
            target=target,
            purpose=selected_purpose,
            executable=executable,
        )
        base._require_mutations_enabled(
            "file_write", path=str(receipt_path), host="heim-pc"
        )
        usage_receipt = _record_usage(
            report,
            identity=identity,
            usage_key_sha256=usage_key_sha256,
            receipt_path=receipt_path,
        )
        return _context_result(
            target=target,
            purpose=selected_purpose,
            report=report,
            executable=executable,
            usage_receipt=usage_receipt,
        )
    except ReposkopContextError as exc:
        raise ValueError(str(exc)) from exc
