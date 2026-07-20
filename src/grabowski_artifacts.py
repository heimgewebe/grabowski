from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid
from collections.abc import Callable
from typing import Any

import grabowski_fleet as fleet
import grabowski_mcp as base
import grabowski_resources as resources
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REMOTE_PATH_RE = re.compile(r"/[A-Za-z0-9._/+@=-]{1,4095}\Z")
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024
MAX_ERROR_INPUT_CHARS = 16 * 1024
MAX_ERROR_DETAIL_CHARS = 2048
_NO_DESTINATION_HASH = "-"
_AUTHORIZATION_RE = re.compile(
    r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)([^\s,;]+)"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b((?:api[_-]?key|access[_-]?key|access[_-]?token|password|passwd|secret|token)"
    r"\b[\"']?\s*[:=]\s*[\"']?)([^\"'\s,;]+)"
)
_URI_CREDENTIAL_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9+.-]*://)([^/\s:@]+):([^@/\s]+)@"
)
_TOKEN_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


class ArtifactTransferError(RuntimeError):
    """Bounded operator-facing artifact transport failure."""


def _redact_transfer_detail(
    value: object,
    *,
    redactor: Callable[[str], str] | None = None,
) -> str:
    """Return one bounded diagnostic without relying on operator internals."""
    try:
        text = str(value)
    except Exception:
        text = "artifact transport failed"
    text = text[:MAX_ERROR_INPUT_CHARS]
    if redactor is not None:
        try:
            text = str(redactor(text))[:MAX_ERROR_INPUT_CHARS]
        except Exception:
            text = "artifact transport failed"
    text = _AUTHORIZATION_RE.sub(r"\1[REDACTED]", text)
    text = _SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)
    text = _URI_CREDENTIAL_RE.sub(r"\1[REDACTED]@", text)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    home = str(Path.home())
    if home and home != "/":
        text = text.replace(home, "~")
    text = " ".join(text.replace("\x00", " ").split())
    if not text:
        text = "artifact transport failed"
    if len(text) > MAX_ERROR_DETAIL_CHARS:
        text = f"{text[: MAX_ERROR_DETAIL_CHARS - 1]}…"
    return text


def _transfer_error(operation: str, error: BaseException) -> ArtifactTransferError:
    if isinstance(error, ArtifactTransferError):
        return ArtifactTransferError(_redact_transfer_detail(error))
    if isinstance(error, FileExistsError):
        detail = "destination already exists"
    elif isinstance(error, FileNotFoundError):
        detail = "file not found"
    elif isinstance(error, TimeoutError):
        detail = "operation timed out"
    else:
        detail = _redact_transfer_detail(error)
    return ArtifactTransferError(f"Artifact {operation} failed: {detail}")


def _command_error(label: str, result: object) -> ArtifactTransferError:
    if isinstance(result, dict):
        detail = result.get("stderr") or result.get("stdout") or "command failed"
    else:
        detail = "command returned an invalid result"
    return ArtifactTransferError(f"{label} failed: {_redact_transfer_detail(detail)}")

_REMOTE_STAT_SCRIPT = r'''import hashlib,json,os,stat,sys
p=sys.argv[1]
def check_components(path):
 if not os.path.isabs(path): raise RuntimeError("path must be absolute")
 current=os.path.sep
 for part in [item for item in path.split(os.path.sep) if item]:
  current=os.path.join(current,part)
  metadata=os.lstat(current)
  if stat.S_ISLNK(metadata.st_mode): raise RuntimeError("symlink path component")
try:
 check_components(p)
 s=os.lstat(p)
 if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode):
  raise RuntimeError("artifact is not a regular non-symlink file")
 if s.st_size > int(sys.argv[2]):
  raise RuntimeError("artifact exceeds size limit")
 h=hashlib.sha256()
 with open(p,"rb",buffering=0) as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 print(json.dumps({"exists":True,"size":s.st_size,"sha256":h.hexdigest()},sort_keys=True))
except FileNotFoundError:
 print(json.dumps({"exists":False},sort_keys=True))
'''

_REMOTE_PUBLISH_SCRIPT = r'''import hashlib,json,os,stat,sys
source,destination,expected_source,mode,expected_destination=sys.argv[1:6]
def check_components(path,missing_leaf=False):
 if not os.path.isabs(path): raise RuntimeError("path must be absolute")
 current=os.path.sep
 parts=[p for p in path.split(os.path.sep) if p]
 for i,part in enumerate(parts):
  current=os.path.join(current,part)
  try: s=os.lstat(current)
  except FileNotFoundError:
   if missing_leaf and i==len(parts)-1: return
   raise
  if stat.S_ISLNK(s.st_mode): raise RuntimeError("symlink path component")
def digest(path):
 s=os.lstat(path)
 if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode):
  raise RuntimeError("artifact is not a regular non-symlink file")
 h=hashlib.sha256()
 with open(path,"rb",buffering=0) as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest(),s.st_size
check_components(source)
check_components(destination,True)
actual_source,size=digest(source)
if actual_source!=expected_source: raise RuntimeError("temporary source hash mismatch")
try:
 actual_destination,_=digest(destination)
 destination_exists=True
except FileNotFoundError:
 actual_destination=None
 destination_exists=False
if mode=="create":
 if expected_destination!="-": raise RuntimeError("invalid create destination precondition")
 if destination_exists: raise RuntimeError("destination already exists")
elif mode=="replace":
 if expected_destination=="-": raise RuntimeError("missing replacement destination precondition")
 if not destination_exists: raise RuntimeError("destination is missing")
 if actual_destination!=expected_destination: raise RuntimeError("destination hash precondition failed")
else: raise RuntimeError("invalid publication mode")
os.replace(source,destination)
fd=os.open(os.path.dirname(destination),os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
print(json.dumps({"size":size,"sha256":actual_source,"mode":mode},sort_keys=True))
'''

_REMOTE_UNLINK_SCRIPT = r'''import os,stat,sys
p=sys.argv[1]
try:
 s=os.lstat(p)
 if stat.S_ISREG(s.st_mode) and not stat.S_ISLNK(s.st_mode): os.unlink(p)
except FileNotFoundError: pass
'''


def _validate_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_mode(
    create_only: bool,
    expected_destination_sha256: str | None,
) -> tuple[str, str]:
    if not isinstance(create_only, bool):
        raise ValueError("create_only must be boolean")
    if create_only:
        if expected_destination_sha256 is not None:
            raise ValueError("create-only publication may not include a destination hash")
        return "create", _NO_DESTINATION_HASH
    if expected_destination_sha256 is None:
        raise ValueError("replacement requires expected_destination_sha256")
    return "replace", _validate_sha256(
        expected_destination_sha256, "expected_destination_sha256"
    )


def _hash_file(path: Path) -> tuple[str, int]:
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Artifact must be a regular non-symlink file")
    if metadata.st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("Artifact exceeds the configured size limit")
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    current = os.lstat(path)
    identity = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    current_identity = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    if identity != current_identity:
        raise RuntimeError("Artifact changed while being hashed")
    return digest.hexdigest(), metadata.st_size


def _local_source(raw_path: str) -> Path:
    target = base._resolve_existing(raw_path, "read")
    if base._path_is_secret(target) or base._path_is_browser_profile(target):
        raise PermissionError("Artifact transport may not read secret or browser-profile roots")
    _hash_file(target)
    return target


def _local_destination(raw_path: str) -> tuple[Path, bool]:
    target, exists = base._resolve_write_target(raw_path)
    if base._path_is_secret(target) or base._path_is_browser_profile(target):
        raise PermissionError("Artifact transport may not write secret or browser-profile roots")
    if exists:
        _hash_file(target)
    return target, exists


def _remote_path(raw_path: str) -> str:
    if not isinstance(raw_path, str) or REMOTE_PATH_RE.fullmatch(raw_path) is None:
        raise ValueError("Remote artifact path must be an absolute conservative path")
    normalized = os.path.normpath(raw_path)
    if normalized != raw_path or "\x00" in normalized:
        raise ValueError("Remote artifact path is not canonical")
    parts = Path(normalized).parts
    if "merges" in parts and "repos" in parts:
        repos_index = parts.index("repos")
        if repos_index + 1 < len(parts) and parts[repos_index + 1] == "merges":
            raise PermissionError("Remote repos/merges is immutable")
    return normalized


def _remote_resource_key(host: str, path: str) -> str:
    identity = hashlib.sha256(f"{host}\0{path}".encode("utf-8")).hexdigest()
    return f"service:artifact-path-{identity}"


def _local_stat(path: Path) -> dict[str, Any]:
    digest, size = _hash_file(path)
    return {"exists": True, "path": str(path), "size": size, "sha256": digest}


def _remote_run(host: str, argv: list[str], timeout_seconds: int = 60) -> dict[str, Any]:
    try:
        envelope = fleet.run_fleet_host(
            host,
            argv,
            timeout_seconds=timeout_seconds,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
    except Exception as exc:
        raise _transfer_error("remote operation", exc) from None
    if not isinstance(envelope, dict) or not isinstance(envelope.get("result"), dict):
        raise ArtifactTransferError("Remote artifact operation returned an invalid result")
    result = envelope["result"]
    if result.get("returncode") != 0:
        raise _command_error("Remote artifact operation", result)
    return result


def _remote_stat(host: str, path: str) -> dict[str, Any]:
    remote = _remote_path(path)
    result = _remote_run(
        host,
        ["python3", "-c", _REMOTE_STAT_SCRIPT, remote, str(MAX_ARTIFACT_BYTES)],
    )
    try:
        value = json.loads(result["stdout"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Remote artifact stat returned invalid JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("exists"), bool):
        raise RuntimeError("Remote artifact stat returned an invalid contract")
    if value["exists"]:
        _validate_sha256(value.get("sha256"), "remote sha256")
        if not isinstance(value.get("size"), int):
            raise RuntimeError("Remote artifact stat omitted size")
    return {**value, "path": remote, "host": host}


def _scp(host: str, source: str, destination: str, *, upload: bool) -> dict[str, Any]:
    target = fleet.fleet_host(host)
    if target["transport"] != "ssh":
        raise ValueError("SCP transport requires a registered SSH fleet host")
    scp = shutil.which("scp")
    if not scp:
        raise RuntimeError("OpenSSH scp client is not installed")
    if upload:
        arguments = [source, f"{target['target']}:{destination}"]
    else:
        arguments = [f"{target['target']}:{source}", destination]
    return operator._run(
        [
            scp,
            "-q",
            "-o",
            "BatchMode=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            f"ConnectTimeout={target['connect_timeout_seconds']}",
            "--",
            *arguments,
        ],
        cwd=operator.HOME,
        timeout_seconds=operator._timeout(120),
        max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
    )


def _remote_cleanup(host: str, path: str) -> None:
    try:
        _remote_run(host, ["python3", "-c", _REMOTE_UNLINK_SCRIPT, path], 30)
    except Exception:
        pass


def _copy_to_temporary(source: Path, temporary: Path) -> tuple[str, int]:
    source_hash, source_size = _hash_file(source)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with source.open("rb", buffering=0) as input_handle, os.fdopen(
            descriptor, "wb", buffering=0, closefd=False
        ) as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            os.fsync(output_handle.fileno())
    finally:
        os.close(descriptor)
    temporary_hash, temporary_size = _hash_file(temporary)
    if temporary_hash != source_hash or temporary_size != source_size:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("Temporary artifact copy failed hash verification")
    return source_hash, source_size


def _publish_local(
    temporary: Path,
    destination: Path,
    *,
    mode: str,
    expected_destination_sha256: str,
    expected_source_sha256: str,
) -> dict[str, Any]:
    temporary_hash, size = _hash_file(temporary)
    if temporary_hash != expected_source_sha256:
        raise RuntimeError("Temporary artifact hash mismatch")
    try:
        current_hash, _ = _hash_file(destination)
        destination_exists = True
    except FileNotFoundError:
        current_hash = None
        destination_exists = False
    if mode == "create":
        if destination_exists:
            raise FileExistsError(str(destination))
    elif not destination_exists:
        raise FileNotFoundError(str(destination))
    elif current_hash != expected_destination_sha256:
        raise RuntimeError("Destination hash precondition failed")
    os.replace(temporary, destination)
    directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"size": size, "sha256": temporary_hash, "mode": mode}


def artifact_stat(host: str, path: str) -> dict[str, Any]:
    target = fleet.fleet_host(host)
    if target["transport"] == "local":
        try:
            local = _local_source(path)
        except FileNotFoundError:
            return {"host": host, "transport": "local", "path": path, "exists": False}
        return {"host": host, "transport": "local", **_local_stat(local)}
    return {"transport": "ssh", **_remote_stat(host, path)}


def artifact_push(
    host: str,
    source_path: str,
    destination_path: str,
    expected_source_sha256: str,
    *,
    create_only: bool = True,
    expected_destination_sha256: str | None = None,
) -> dict[str, Any]:
    source = _local_source(source_path)
    expected_source = _validate_sha256(expected_source_sha256, "expected_source_sha256")
    actual_source, size = _hash_file(source)
    if actual_source != expected_source:
        raise RuntimeError("Source hash precondition failed")
    target = fleet.fleet_host(host)
    if target["transport"] != "ssh":
        raise ValueError("artifact_push destination must be a registered SSH host")
    destination = _remote_path(destination_path)
    mode, expected_destination = _validate_mode(
        create_only, expected_destination_sha256
    )
    owner = f"artifact:{uuid.uuid4().hex}"
    resource_key = _remote_resource_key(host, destination)
    resources.acquire_resources(
        owner,
        [resource_key],
        purpose=f"artifact push to {host}",
        ttl_seconds=300,
        metadata={"host": host, "direction": "push"},
    )
    temporary = f"{destination}.grabowski-{uuid.uuid4().hex}.tmp"
    try:
        scp_result = _scp(host, str(source), temporary, upload=True)
        if not isinstance(scp_result, dict) or scp_result.get("returncode") != 0:
            raise _command_error("SCP upload", scp_result)
        publish = _remote_run(
            host,
            [
                "python3",
                "-c",
                _REMOTE_PUBLISH_SCRIPT,
                temporary,
                destination,
                expected_source,
                mode,
                expected_destination,
            ],
            60,
        )
        try:
            result = json.loads(publish.get("stdout", ""))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ArtifactTransferError(
                "Remote artifact publish returned invalid JSON"
            ) from exc
        if (
            not isinstance(result, dict)
            or result.get("sha256") != expected_source
            or result.get("size") != size
            or result.get("mode") != mode
        ):
            raise ArtifactTransferError(
                "Remote artifact publish returned an invalid integrity receipt"
            )
    except Exception:
        _remote_cleanup(host, temporary)
        raise
    finally:
        resources.release_resources(owner, [resource_key])
    return {
        "direction": "push",
        "source": {"host": "local", "path": str(source), "sha256": actual_source},
        "destination": {"host": host, "path": destination},
        "size": size,
        "sha256": result["sha256"],
        "mode": mode,
        "scp_returncode": scp_result["returncode"],
    }


def artifact_pull(
    host: str,
    source_path: str,
    destination_path: str,
    expected_source_sha256: str,
    *,
    create_only: bool = True,
    expected_destination_sha256: str | None = None,
) -> dict[str, Any]:
    target = fleet.fleet_host(host)
    if target["transport"] != "ssh":
        raise ValueError("artifact_pull source must be a registered SSH host")
    source = _remote_path(source_path)
    expected_source = _validate_sha256(expected_source_sha256, "expected_source_sha256")
    remote = _remote_stat(host, source)
    if not remote["exists"] or remote["sha256"] != expected_source:
        raise RuntimeError("Remote source hash precondition failed")
    destination, _ = _local_destination(destination_path)
    mode, expected_destination = _validate_mode(
        create_only, expected_destination_sha256
    )
    owner = f"artifact:{uuid.uuid4().hex}"
    resource_key = f"path:{destination}"
    resources.acquire_resources(
        owner,
        [resource_key],
        purpose=f"artifact pull from {host}",
        ttl_seconds=300,
        metadata={"host": host, "direction": "pull"},
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.grabowski-",
        suffix=".tmp",
        dir=destination.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    try:
        scp_result = _scp(host, source, str(temporary), upload=False)
        if not isinstance(scp_result, dict) or scp_result.get("returncode") != 0:
            raise _command_error("SCP download", scp_result)
        downloaded_hash, downloaded_size = _hash_file(temporary)
        if downloaded_hash != expected_source or downloaded_size != remote["size"]:
            raise RuntimeError("Downloaded artifact failed source verification")
        published = _publish_local(
            temporary,
            destination,
            mode=mode,
            expected_destination_sha256=expected_destination,
            expected_source_sha256=expected_source,
        )
    finally:
        temporary.unlink(missing_ok=True)
        resources.release_resources(owner, [resource_key])
    return {
        "direction": "pull",
        "source": {"host": host, "path": source, "sha256": expected_source},
        "destination": {"host": "local", "path": str(destination)},
        "size": published["size"],
        "sha256": published["sha256"],
        "mode": mode,
        "scp_returncode": scp_result["returncode"],
    }


def _audit_transfer(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp_unix": int(__import__("time").time()),
        "operation": f"artifact-{result['direction']}",
        "source_host": result["source"]["host"],
        "source_path": result["source"]["path"],
        "destination_host": result["destination"]["host"],
        "destination_path": result["destination"]["path"],
        "sha256": result["sha256"],
        "size": result["size"],
        "mode": result["mode"],
    }


@mcp.tool(name="grabowski_artifact_stat", annotations=READ_ONLY)
def grabowski_artifact_stat(host: str, path: str) -> dict[str, Any]:
    """Return regular-file metadata and SHA-256 for one local or fleet artifact."""
    operator._require_operator_capability("artifact_transfer")
    try:
        return artifact_stat(host, path)
    except Exception as exc:
        raise _transfer_error("stat", exc) from None


@mcp.tool(name="grabowski_artifact_push", annotations=MUTATING)
def grabowski_artifact_push(
    host: str,
    source_path: str,
    destination_path: str,
    expected_source_sha256: str,
    create_only: bool = True,
    expected_destination_sha256: str | None = None,
) -> dict[str, Any]:
    """Push one hash-bound local regular file to a registered SSH fleet host."""
    operator._require_operator_mutation(
        "artifact_transfer", path=destination_path, host=host
    )
    try:
        result = artifact_push(
            host,
            source_path,
            destination_path,
            expected_source_sha256,
            create_only=create_only,
            expected_destination_sha256=expected_destination_sha256,
        )
    except Exception as exc:
        raise _transfer_error("push", exc) from None
    base._append_audit(_audit_transfer(result))
    return result


@mcp.tool(name="grabowski_artifact_pull", annotations=MUTATING)
def grabowski_artifact_pull(
    host: str,
    source_path: str,
    destination_path: str,
    expected_source_sha256: str,
    create_only: bool = True,
    expected_destination_sha256: str | None = None,
) -> dict[str, Any]:
    """Pull one hash-bound regular file from a registered SSH fleet host."""
    operator._require_operator_mutation(
        "artifact_transfer", path=destination_path, host=host
    )
    try:
        result = artifact_pull(
            host,
            source_path,
            destination_path,
            expected_source_sha256,
            create_only=create_only,
            expected_destination_sha256=expected_destination_sha256,
        )
    except Exception as exc:
        raise _transfer_error("pull", exc) from None
    base._append_audit(_audit_transfer(result))
    return result
