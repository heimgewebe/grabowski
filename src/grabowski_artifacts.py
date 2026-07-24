from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import stat
import tempfile
import time
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
TEXT_ARTIFACT_PROFILE = "git-diff.v1"
TEXT_ARTIFACT_SCHEMA = "git-diff-artifact.v1"
TEXT_ARTIFACT_ROOT = Path.home() / ".local/state/grabowski/text-artifacts"
MAX_TEXT_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_TEXT_ARTIFACT_CHUNK_BYTES = 256 * 1024
MAX_TEXT_ARTIFACT_RECEIPT_BYTES = 64 * 1024
ARTIFACT_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
SAFE_FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.txt\Z")
_PRIVATE_KEY_BEGIN = "-----" + "BEGIN "
_PRIVATE_KEY_END = "PRIVATE " + "KEY-----"
_PRIVATE_KEY_MARKERS = tuple(
    _PRIVATE_KEY_BEGIN + kind + _PRIVATE_KEY_END
    for kind in ("OPENSSH ", "RSA ", "EC ", "")
)
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
_TRACEBACK_MARKER = "Traceback (most recent call last):"
_TRACEBACK_EXCEPTION_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:\s*(?P<detail>.*)$")
_TOKEN_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


class ArtifactTransferError(RuntimeError):
    """Bounded operator-facing artifact transport failure."""


def _condense_python_traceback(text: str) -> str:
    """Reduce remote Python tracebacks to their controlled final diagnostic."""
    if _TRACEBACK_MARKER not in text:
        return text
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        match = _TRACEBACK_EXCEPTION_RE.fullmatch(line)
        if match is not None:
            return match.group("detail") or "artifact transport failed"
    return "artifact transport failed"


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
    text = _condense_python_traceback(text)
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



def _canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("Text artifact root is not a regular directory")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError("Text artifact root is not private and owner-controlled")


def _private_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _private_directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_private_directory_path(path: Path) -> tuple[int, tuple[int, ...]]:
    try:
        descriptor = os.open(path, _private_directory_flags())
    except OSError as exc:
        raise ArtifactTransferError("Text artifact directory open failed") from exc
    try:
        opened = os.fstat(descriptor)
        linked = os.lstat(path)
        identity = _private_identity(opened)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or identity != _private_identity(linked)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise ArtifactTransferError(
                "Text artifact directory is not one private owner-controlled directory"
            )
        return descriptor, identity
    except Exception:
        os.close(descriptor)
        raise


def _open_private_directory_at(
    parent_descriptor: int,
    name: str,
) -> tuple[int, tuple[int, ...]]:
    try:
        descriptor = os.open(name, _private_directory_flags(), dir_fd=parent_descriptor)
    except OSError as exc:
        raise ArtifactTransferError("Text artifact directory open failed") from exc
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        identity = _private_identity(opened)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or identity != _private_identity(linked)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise ArtifactTransferError(
                "Text artifact directory is not one private owner-controlled directory"
            )
        return descriptor, identity
    except Exception:
        os.close(descriptor)
        raise


def _verify_private_directory_path(
    descriptor: int,
    path: Path,
    expected_identity: tuple[int, ...],
) -> None:
    try:
        opened = os.fstat(descriptor)
        linked = os.lstat(path)
    except OSError as exc:
        raise ArtifactTransferError("Text artifact directory changed while reading") from exc
    if (
        _private_identity(opened) != expected_identity
        or _private_identity(linked) != expected_identity
    ):
        raise ArtifactTransferError("Text artifact directory changed while reading")


def _verify_private_directory_at(
    parent_descriptor: int,
    name: str,
    descriptor: int,
    expected_identity: tuple[int, ...],
) -> None:
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise ArtifactTransferError("Text artifact directory changed while reading") from exc
    if (
        _private_identity(opened) != expected_identity
        or _private_identity(linked) != expected_identity
    ):
        raise ArtifactTransferError("Text artifact directory changed while reading")


def _open_private_regular_file_at(
    directory_descriptor: int,
    name: str,
    *,
    max_bytes: int,
) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        raise ArtifactTransferError("Text artifact file open failed") from exc
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or _private_identity(opened) != _private_identity(linked)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size > max_bytes
        ):
            raise ArtifactTransferError(
                "Text artifact file is not one private owner-controlled regular file"
            )
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _verify_private_regular_file_at(
    directory_descriptor: int,
    name: str,
    descriptor: int,
    expected: os.stat_result,
) -> None:
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise ArtifactTransferError("Text artifact file changed while reading") from exc
    identity = _private_identity(expected)
    if _private_identity(opened) != identity or _private_identity(linked) != identity:
        raise ArtifactTransferError("Text artifact file changed while reading")


def _read_private_regular_file_at(
    directory_descriptor: int,
    name: str,
    *,
    max_bytes: int,
) -> tuple[bytes, str, int]:
    descriptor, before = _open_private_regular_file_at(
        directory_descriptor, name, max_bytes=max_bytes
    )
    try:
        remaining = before.st_size
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        while remaining:
            block = os.read(descriptor, min(remaining, 64 * 1024))
            if not block:
                raise ArtifactTransferError("Text artifact file ended before its declared size")
            chunks.append(block)
            digest.update(block)
            remaining -= len(block)
        data = b"".join(chunks)
        _verify_private_regular_file_at(
            directory_descriptor, name, descriptor, before
        )
        return data, digest.hexdigest(), before.st_size
    finally:
        os.close(descriptor)


def _hash_and_read_private_regular_file_at(
    directory_descriptor: int,
    name: str,
    *,
    max_bytes: int,
    offset: int,
    chunk_size: int,
) -> tuple[str, int, bytes]:
    descriptor, before = _open_private_regular_file_at(
        directory_descriptor, name, max_bytes=max_bytes
    )
    try:
        remaining = before.st_size
        digest = hashlib.sha256()
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise ArtifactTransferError("Text artifact file ended before its declared size")
            digest.update(block)
            remaining -= len(block)
        payload = os.pread(descriptor, min(chunk_size, before.st_size - offset), offset)
        _verify_private_regular_file_at(
            directory_descriptor, name, descriptor, before
        )
        return digest.hexdigest(), before.st_size, payload
    finally:
        os.close(descriptor)


def _validate_commit_sha(value: str, label: str) -> str:
    if not isinstance(value, str) or COMMIT_SHA_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a full lowercase Git commit SHA")
    return value


def _validate_artifact_id(value: str) -> str:
    if not isinstance(value, str) or ARTIFACT_ID_RE.fullmatch(value) is None:
        raise ValueError("artifact_id must be 32 lowercase hexadecimal characters")
    return value


def _run_git(
    repository: Path,
    arguments: list[str],
    *,
    timeout_seconds: int = 60,
    max_output_bytes: int = 64 * 1024,
) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is not installed")
    completed = subprocess.run(
        [git, "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=timeout_seconds,
        env={
            "HOME": str(operator.HOME),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
    )
    if completed.returncode != 0:
        detail = completed.stderr[:max_output_bytes].decode("utf-8", errors="replace")
        raise ArtifactTransferError(
            f"Git command failed: {_redact_transfer_detail(detail)}"
        )
    if len(completed.stdout) > max_output_bytes:
        raise ArtifactTransferError("Git metadata output exceeded its bound")
    return completed.stdout


def _resolve_git_repository(raw_path: str) -> Path:
    repository = base._resolve_existing(raw_path, "read")
    if base._path_is_secret(repository) or base._path_is_browser_profile(repository):
        raise PermissionError("Text artifact export may not read protected roots")
    if not repository.is_dir():
        raise ValueError("repository must be a directory")
    top_level = _run_git(
        repository, ["rev-parse", "--show-toplevel"], max_output_bytes=4096
    ).decode("utf-8").strip()
    resolved = Path(top_level).resolve(strict=True)
    if resolved != repository.resolve(strict=True):
        raise ValueError("repository must name the Git worktree root exactly")
    return resolved


def _verify_commit(repository: Path, commit: str, label: str) -> str:
    value = _validate_commit_sha(commit, label)
    resolved = _run_git(
        repository,
        ["rev-parse", "--verify", f"{value}^{{commit}}"],
        max_output_bytes=4096,
    ).decode("ascii").strip()
    if resolved != value:
        raise RuntimeError(f"{label} did not resolve to the exact requested commit")
    return value


def _safe_slug(value: str, fallback: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return (slug or fallback)[:80]


def _artifact_filename(
    repository: Path,
    base_commit: str,
    head_commit: str,
    pull_request_number: int | None,
) -> str:
    name = _safe_slug(repository.name, "repository")
    if pull_request_number is not None:
        if isinstance(pull_request_number, bool) or not isinstance(
            pull_request_number, int
        ) or pull_request_number < 1:
            raise ValueError("pull_request_number must be a positive integer")
        filename = f"{name}-pr-{pull_request_number}-{head_commit[:12]}-diff.txt"
    else:
        filename = f"{name}-{base_commit[:12]}..{head_commit[:12]}-diff.txt"
    if SAFE_FILENAME_RE.fullmatch(filename) is None:
        raise RuntimeError("Generated text artifact filename is invalid")
    return filename


def _validate_diff_safety(data: bytes) -> str:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ArtifactTransferError("Generated diff is not valid UTF-8") from exc
    if "\x00" in text:
        raise ArtifactTransferError("Generated diff contains NUL bytes")
    if any(marker in text for marker in _PRIVATE_KEY_MARKERS):
        raise PermissionError("Generated diff contains a private-key marker")
    if _AUTHORIZATION_RE.search(text) is not None:
        raise PermissionError("Generated diff contains an authorization credential")
    if any(pattern.search(text) is not None for pattern in _TOKEN_PATTERNS):
        raise PermissionError("Generated diff contains a high-confidence secret token")
    return text


def _write_git_diff(
    repository: Path,
    base_commit: str,
    head_commit: str,
    destination: Path,
) -> int:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is not installed")
    stderr_path = destination.with_suffix(".stderr")
    total = 0
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + 120
    try:
        with destination.open("xb", buffering=0) as output, stderr_path.open(
            "xb", buffering=0
        ) as error_output:
            process = subprocess.Popen(
                [
                    git,
                    "-c",
                    "color.ui=false",
                    "-c",
                    "core.quotepath=true",
                    "-C",
                    str(repository),
                    "diff",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    "--no-textconv",
                    base_commit,
                    head_commit,
                    "--",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=error_output,
                shell=False,
                close_fds=True,
                env={
                    "HOME": str(operator.HOME),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                },
            )
            if process.stdout is None:
                raise RuntimeError("Git diff stdout is unavailable")
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Git diff generation timed out")
                events = selector.select(timeout=min(1.0, remaining))
                if not events:
                    continue
                for key, _ in events:
                    block = os.read(key.fd, 1024 * 1024)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(block)
                    if total > MAX_TEXT_ARTIFACT_BYTES:
                        raise ArtifactTransferError(
                            "Generated diff exceeds the size limit"
                        )
                    output.write(block)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Git diff generation timed out")
            returncode = process.wait(timeout=remaining)
            output.flush()
            os.fsync(output.fileno())
        if returncode != 0:
            detail = stderr_path.read_bytes()[:64 * 1024].decode(
                "utf-8", errors="replace"
            )
            raise ArtifactTransferError(
                f"Git diff failed: {_redact_transfer_detail(detail)}"
            )
    except Exception:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        destination.unlink(missing_ok=True)
        raise
    finally:
        selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()
        stderr_path.unlink(missing_ok=True)
    return total


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", buffering=0, closefd=False) as handle:
            handle.write(data)
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


def publish_text_artifact(
    profile: str,
    repository: str,
    base_commit: str,
    head_commit: str,
    *,
    pull_request_number: int | None = None,
) -> dict[str, Any]:
    if profile != TEXT_ARTIFACT_PROFILE:
        raise ValueError(f"profile must be {TEXT_ARTIFACT_PROFILE}")
    repo = _resolve_git_repository(repository)
    base_sha = _verify_commit(repo, base_commit, "base_commit")
    head_sha = _verify_commit(repo, head_commit, "head_commit")
    filename = _artifact_filename(repo, base_sha, head_sha, pull_request_number)
    _ensure_private_directory(TEXT_ARTIFACT_ROOT)
    artifact_id = uuid.uuid4().hex
    temporary_directory = TEXT_ARTIFACT_ROOT / f".{artifact_id}.tmp"
    final_directory = TEXT_ARTIFACT_ROOT / artifact_id
    os.mkdir(temporary_directory, 0o700)
    diff_path = temporary_directory / filename
    try:
        size = _write_git_diff(repo, base_sha, head_sha, diff_path)
        if size != diff_path.stat().st_size:
            raise RuntimeError("Generated diff size changed unexpectedly")
        os.chmod(diff_path, 0o600)
        data = diff_path.read_bytes()
        _validate_diff_safety(data)
        diff_sha256, verified_size = _hash_file(diff_path)
        if verified_size != size:
            raise RuntimeError("Generated diff failed size verification")
        generated_at = int(time.time())
        receipt = {
            "schema": TEXT_ARTIFACT_SCHEMA,
            "profile": profile,
            "artifact_id": artifact_id,
            "repository": repo.name,
            "repository_path_sha256": hashlib.sha256(
                str(repo).encode("utf-8")
            ).hexdigest(),
            "base_commit": base_sha,
            "head_commit": head_sha,
            "pull_request_number": pull_request_number,
            "filename": filename,
            "diff_sha256": diff_sha256,
            "byte_size": size,
            "generated_at_unix": generated_at,
            "encoding": "utf-8",
            "format": "unified-diff",
        }
        receipt_bytes = _canonical_json_bytes(receipt)
        receipt_path = temporary_directory / "receipt.json"
        _atomic_write(receipt_path, receipt_bytes)
        receipt_sha256, _ = _hash_file(receipt_path)
        directory = os.open(temporary_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        os.replace(temporary_directory, final_directory)
        root_descriptor = os.open(TEXT_ARTIFACT_ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(root_descriptor)
        finally:
            os.close(root_descriptor)
    except Exception:
        shutil.rmtree(temporary_directory, ignore_errors=True)
        raise
    result = {
        **receipt,
        "receipt_sha256": receipt_sha256,
        "transport": {
            "reader": "grabowski_text_artifact_read",
            "encoding": "base64",
            "max_chunk_bytes": MAX_TEXT_ARTIFACT_CHUNK_BYTES,
            "requires": ["expected_artifact_sha256", "expected_receipt_sha256"],
        },
    }
    try:
        base._append_audit(
            {
                "timestamp_unix": int(time.time()),
                "operation": "text-artifact-publish",
                "profile": profile,
                "artifact_id": artifact_id,
                "repository_path_sha256": receipt["repository_path_sha256"],
                "base_commit": base_sha,
                "head_commit": head_sha,
                "sha256": diff_sha256,
                "size": size,
                "receipt_sha256": receipt_sha256,
            }
        )
    except Exception as audit_error:
        try:
            shutil.rmtree(final_directory)
            root_descriptor = os.open(
                TEXT_ARTIFACT_ROOT, os.O_RDONLY | os.O_DIRECTORY
            )
            try:
                os.fsync(root_descriptor)
            finally:
                os.close(root_descriptor)
            if final_directory.exists():
                raise ArtifactTransferError(
                    "Text artifact audit failed and rollback was not durable"
                )
        except Exception as rollback_error:
            raise ArtifactTransferError(
                "Text artifact audit failed and rollback could not be verified"
            ) from rollback_error
        raise ArtifactTransferError(
            "Text artifact audit failed; publication was rolled back"
        ) from audit_error
    return result


def _validated_text_artifact_receipt(
    receipt_bytes: bytes,
    *,
    artifact_id: str,
) -> dict[str, Any]:
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactTransferError("Text artifact receipt is invalid") from exc
    if not isinstance(receipt, dict) or receipt_bytes != _canonical_json_bytes(receipt):
        raise ArtifactTransferError("Text artifact receipt is not canonical JSON")
    required = {
        "schema",
        "profile",
        "artifact_id",
        "repository",
        "repository_path_sha256",
        "base_commit",
        "head_commit",
        "pull_request_number",
        "filename",
        "diff_sha256",
        "byte_size",
        "generated_at_unix",
        "encoding",
        "format",
    }
    if set(receipt) != required:
        raise ArtifactTransferError("Text artifact receipt fields are invalid")
    if (
        receipt.get("schema") != TEXT_ARTIFACT_SCHEMA
        or receipt.get("profile") != TEXT_ARTIFACT_PROFILE
        or receipt.get("artifact_id") != artifact_id
        or receipt.get("encoding") != "utf-8"
        or receipt.get("format") != "unified-diff"
    ):
        raise ArtifactTransferError("Text artifact receipt binding is invalid")
    repository = receipt.get("repository")
    if not isinstance(repository, str) or not repository or len(repository) > 255:
        raise ArtifactTransferError("Text artifact repository identity is invalid")
    _validate_sha256(receipt.get("repository_path_sha256"), "repository_path_sha256")
    _validate_commit_sha(receipt.get("base_commit"), "base_commit")
    _validate_commit_sha(receipt.get("head_commit"), "head_commit")
    pull_request_number = receipt.get("pull_request_number")
    if pull_request_number is not None and (
        isinstance(pull_request_number, bool)
        or not isinstance(pull_request_number, int)
        or pull_request_number < 1
    ):
        raise ArtifactTransferError("Text artifact pull request binding is invalid")
    generated_at = receipt.get("generated_at_unix")
    if isinstance(generated_at, bool) or not isinstance(generated_at, int) or generated_at < 1:
        raise ArtifactTransferError("Text artifact timestamp is invalid")
    filename = receipt.get("filename")
    if not isinstance(filename, str) or SAFE_FILENAME_RE.fullmatch(filename) is None:
        raise ArtifactTransferError("Text artifact filename is invalid")
    declared_size = receipt.get("byte_size")
    if (
        isinstance(declared_size, bool)
        or not isinstance(declared_size, int)
        or not 0 <= declared_size <= MAX_TEXT_ARTIFACT_BYTES
    ):
        raise ArtifactTransferError("Text artifact size is invalid")
    _validate_sha256(receipt.get("diff_sha256"), "diff_sha256")
    return receipt


def read_text_artifact(
    artifact_id: str,
    expected_artifact_sha256: str,
    expected_receipt_sha256: str,
    *,
    offset: int = 0,
    max_bytes: int = MAX_TEXT_ARTIFACT_CHUNK_BYTES,
) -> dict[str, Any]:
    identity = _validate_artifact_id(artifact_id)
    expected_artifact = _validate_sha256(
        expected_artifact_sha256, "expected_artifact_sha256"
    )
    expected_receipt = _validate_sha256(
        expected_receipt_sha256, "expected_receipt_sha256"
    )
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes < 1
        or max_bytes > MAX_TEXT_ARTIFACT_CHUNK_BYTES
    ):
        raise ValueError(
            f"max_bytes must be between 1 and {MAX_TEXT_ARTIFACT_CHUNK_BYTES}"
        )

    root_descriptor, root_identity = _open_private_directory_path(TEXT_ARTIFACT_ROOT)
    try:
        artifact_descriptor, artifact_identity = _open_private_directory_at(
            root_descriptor, identity
        )
        try:
            receipt_bytes, receipt_sha256, _ = _read_private_regular_file_at(
                artifact_descriptor,
                "receipt.json",
                max_bytes=MAX_TEXT_ARTIFACT_RECEIPT_BYTES,
            )
            if receipt_sha256 != expected_receipt:
                raise ArtifactTransferError(
                    "Text artifact receipt hash precondition failed"
                )
            receipt = _validated_text_artifact_receipt(
                receipt_bytes, artifact_id=identity
            )
            size = receipt["byte_size"]
            if offset > size:
                raise ValueError("offset exceeds artifact size")
            diff_sha256, observed_size, payload = (
                _hash_and_read_private_regular_file_at(
                    artifact_descriptor,
                    receipt["filename"],
                    max_bytes=MAX_TEXT_ARTIFACT_BYTES,
                    offset=offset,
                    chunk_size=max_bytes,
                )
            )
            if (
                diff_sha256 != receipt["diff_sha256"]
                or diff_sha256 != expected_artifact
                or observed_size != size
            ):
                raise ArtifactTransferError(
                    "Text artifact integrity verification failed"
                )
            _verify_private_directory_at(
                root_descriptor,
                identity,
                artifact_descriptor,
                artifact_identity,
            )
        finally:
            os.close(artifact_descriptor)
        _verify_private_directory_path(
            root_descriptor, TEXT_ARTIFACT_ROOT, root_identity
        )
    finally:
        os.close(root_descriptor)

    next_offset = offset + len(payload)
    return {
        "schema": "text-artifact-chunk.v1",
        "artifact_id": artifact_id,
        "filename": receipt["filename"],
        "offset": offset,
        "chunk_size": len(payload),
        "chunk_sha256": hashlib.sha256(payload).hexdigest(),
        "artifact_size": size,
        "artifact_sha256": receipt["diff_sha256"],
        "receipt_sha256": receipt_sha256,
        "transport_encoding": "base64",
        "content_encoding": "utf-8",
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "next_offset": next_offset if next_offset < size else None,
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

@mcp.tool(name="grabowski_text_artifact_publish", annotations=MUTATING)
def grabowski_text_artifact_publish(
    profile: str,
    repository: str,
    base_commit: str,
    head_commit: str,
    pull_request_number: int | None = None,
) -> dict[str, Any]:
    """Publish one immutable commit-bound UTF-8 text artifact and receipt."""
    operator._require_operator_mutation(
        "artifact_transfer", path=str(TEXT_ARTIFACT_ROOT), host="heim-pc"
    )
    try:
        return publish_text_artifact(
            profile,
            repository,
            base_commit,
            head_commit,
            pull_request_number=pull_request_number,
        )
    except Exception as exc:
        raise _transfer_error("text publish", exc) from None


@mcp.tool(name="grabowski_text_artifact_read", annotations=READ_ONLY)
def grabowski_text_artifact_read(
    artifact_id: str,
    expected_artifact_sha256: str,
    expected_receipt_sha256: str,
    offset: int = 0,
    max_bytes: int = MAX_TEXT_ARTIFACT_CHUNK_BYTES,
) -> dict[str, Any]:
    """Read one hash-pinned bounded chunk from a published text artifact."""
    operator._require_operator_capability("artifact_transfer")
    try:
        return read_text_artifact(
            artifact_id,
            expected_artifact_sha256,
            expected_receipt_sha256,
            offset=offset,
            max_bytes=max_bytes,
        )
    except Exception as exc:
        raise _transfer_error("text read", exc) from None
