#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import importlib.util
import http.client
import json
import os
from pathlib import Path
import stat as statmod
import subprocess
import sys
import tempfile
import time
from typing import Iterator
from urllib.parse import urlsplit


DEFAULT_SERVICE = "tunnel-client-grabowski.service"
DEFAULT_PROFILE = "grabowski"
DEFAULT_MODULE = "grabowski_operator"
DEFAULT_RUNTIME_ROOT = Path.home() / ".local/share/grabowski-mcp"
DEFAULT_STATE_DIR = Path.home() / ".local/state/grabowski"
DEFAULT_HEALTH_URL = "http://127.0.0.1:18080/healthz"
DEFAULT_READY_URL = "http://127.0.0.1:18080/readyz"


class WatchdogError(RuntimeError):
    pass


class LockBusy(WatchdogError):
    pass


@dataclass(frozen=True)
class IntegrityResult:
    """Whether the runtime that is alive is also operative.

    ``valid`` means: every check this probe actually performs passed.  It is not
    a claim of ``provenance_valid``.

    Proven here (all from data -- JSON structure, byte equality, SHA-256):
    manifest present, parseable and complete; contract snapshot hash matches the
    manifest; embedded contract equals the snapshotted contract; every installed
    module hashes to its recorded ``source_sha256s`` entry; every runtime asset
    hashes to its recorded entry.

    Deliberately *not* proven: python/executable binding, platform identity,
    protocol identity, agent-instruction identity, and the release-path and
    pointer checks the runtime performs.  Those need the release's own view.

    So a ``valid`` result narrows the possibilities; it does not certify the
    runtime.  ``scope`` names this explicitly, and callers must not translate it
    into "healthy" without saying which scope they mean.
    """

    valid: bool
    reason: str | None = None
    release_id: str | None = None
    scope: str = "manifest-and-installed-artifact-hashes"


@dataclass(frozen=True)
class ProbeResult:
    status: str
    reasons: tuple[str, ...] = ()
    main_pid: int | None = None
    operator_pid: int | None = None
    process_age_seconds: float | None = None
    integrity: IntegrityResult | None = None


@dataclass
class WatchdogState:
    consecutive_failures: int = 0
    restart_timestamps: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class Decision:
    action: str
    state: WatchdogState


def emit(event: str, **fields: object) -> None:
    payload = {
        "event": event,
        "timestamp": int(time.time()),
        **fields,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def parse_systemctl_show(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value
    return result


def service_properties(service: str) -> dict[str, str]:
    try:
        completed = subprocess.run(
            [
                "systemctl",
                "--user",
                "show",
                service,
                "--no-pager",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WatchdogError("systemctl-query-failed") from exc
    properties = parse_systemctl_show(completed.stdout)
    if set(properties) != {"ActiveState", "SubState", "MainPID"}:
        raise WatchdogError("systemctl-query-incomplete")
    return properties


def read_cmdline(proc_root: Path, pid: int) -> list[str]:
    raw = (proc_root / str(pid) / "cmdline").read_bytes()
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part]


def read_ppid(proc_root: Path, pid: int) -> int:
    for line in (proc_root / str(pid) / "status").read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        if line.startswith("PPid:"):
            return int(line.split(":", 1)[1].strip())
    raise WatchdogError("proc-status-missing-ppid")


def descendant_pids(proc_root: Path, root_pid: int) -> set[int]:
    children: dict[int, list[int]] = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            ppid = read_ppid(proc_root, pid)
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, WatchdogError):
            continue
        children.setdefault(ppid, []).append(pid)

    descendants: set[int] = set()
    pending = list(children.get(root_pid, []))
    while pending:
        pid = pending.pop()
        if pid in descendants:
            continue
        descendants.add(pid)
        pending.extend(children.get(pid, []))
    return descendants


def process_age_seconds(proc_root: Path, pid: int) -> float:
    stat_text = (proc_root / str(pid) / "stat").read_text(
        encoding="utf-8", errors="replace"
    )
    closing = stat_text.rfind(")")
    if closing < 0:
        raise WatchdogError("proc-stat-malformed")
    fields = stat_text[closing + 2 :].split()
    if len(fields) <= 19:
        raise WatchdogError("proc-stat-incomplete")
    start_ticks = int(fields[19])
    uptime = float((proc_root / "uptime").read_text(encoding="ascii").split()[0])
    ticks_per_second = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    return max(0.0, uptime - (start_ticks / ticks_per_second))


def main_identity_ok(proc_root: Path, pid: int, profile: str) -> bool:
    try:
        argv = read_cmdline(proc_root, pid)
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return False
    return (
        len(argv) == 4
        and Path(argv[0]).name == "tunnel-client"
        and argv[1:] == ["run", "--profile", profile]
    )


def operator_candidates(
    proc_root: Path,
    main_pid: int,
    runtime_root: Path,
    expected_module: str,
) -> list[int]:
    expected_argv0 = runtime_root / ".venv/bin/python"
    try:
        expected_exe = expected_argv0.resolve(strict=True)
    except OSError:
        return []

    candidates: list[int] = []
    for pid in sorted(descendant_pids(proc_root, main_pid)):
        try:
            argv = read_cmdline(proc_root, pid)
            exe = (proc_root / str(pid) / "exe").resolve(strict=True)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue
        if (
            argv == [str(expected_argv0), "-m", expected_module]
            and exe == expected_exe
        ):
            candidates.append(pid)
    return candidates


def http_probe(url: str, expected_body: str, timeout: float) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise WatchdogError("non-loopback-health-url")
    if parsed.username is not None or parsed.password is not None:
        raise WatchdogError("credentialed-health-url")
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(128).decode("utf-8", errors="replace").strip()
        return response.status == 200 and body == expected_body
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


MAX_INTEGRITY_FILE_BYTES = 8 * 1024 * 1024

#: Trusted source of the canonical contract schema.  This is operator-controlled
#: repository code, deployed the same way this watchdog is -- deliberately NOT
#: the release under test, whose schema module is exactly the artifact whose
#: trustworthiness is in question.
DEFAULT_TRUSTED_SCHEMA = Path.home() / "repos/grabowski/src/grabowski_runtime_contract.py"
CANONICAL_SCHEMA_MODULE = "grabowski_runtime_contract"


def _trusted_contract_schema(path: Path):
    """Load the canonical schema from a trusted path, or return None.

    Loading trusted repository code is not the same as executing the release: the
    artifact under test never runs here.  If the trusted copy is unavailable the
    probe degrades honestly rather than falling back to the release's copy.
    """
    try:
        if path.is_symlink() or not path.is_file():
            return None
        spec = importlib.util.spec_from_file_location(
            "grabowski_runtime_contract_trusted", path
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, "manifest_errors"):
            return None
        return module
    except Exception:  # noqa: BLE001 - a broken trusted copy must not kill the watchdog
        return None


def _sha256_file(path: Path) -> str | None:
    """Hash a regular file without following symlinks out of the release."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_INTEGRITY_FILE_BYTES:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def probe_integrity(
    runtime_root: Path, *, trusted_schema_path: Path = DEFAULT_TRUSTED_SCHEMA
) -> IntegrityResult:
    """Report whether the deployed runtime is integrity-valid, fail-closed.

    This never executes anything from the release.  An earlier version imported
    the release's own schema module so that the watchdog and the runtime could
    not disagree -- but a watchdog that executes the artifact it is judging is
    not an independent observer.  Measured against that version: a release whose
    schema module called ``os._exit`` terminated the watchdog outright (so the
    integrity exit code never fired), and one containing an infinite loop hung
    it forever.  ``except Exception`` catches neither.

    Everything below is therefore computed from *data*: JSON structure, byte
    equality and SHA-256 over files.  That is both safe and strictly more than
    the previous version proved, because the installed module and runtime asset
    hashes are now verified against the manifest rather than assumed.
    """
    manifest_path = runtime_root / "deployment-manifest.json"
    if (runtime_root / "deployment-incomplete.json").exists():
        return IntegrityResult(False, "deployment-incomplete")
    if not manifest_path.is_file():
        return IntegrityResult(False, "manifest-missing")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return IntegrityResult(False, "manifest-unreadable")
    if not isinstance(raw, dict):
        return IntegrityResult(False, "manifest-not-an-object")

    release_id = raw.get("release_id") if isinstance(raw.get("release_id"), str) else None
    if raw.get("completion_status") != "complete":
        return IntegrityResult(False, "deployment-incomplete", release_id)

    contract = raw.get("entrypoint_contract")
    if not isinstance(contract, dict):
        return IntegrityResult(False, "entrypoint-contract-missing", release_id)

    snapshot_paths = raw.get("snapshot_paths")
    if not isinstance(snapshot_paths, dict):
        return IntegrityResult(False, "snapshot-paths-missing", release_id)
    recorded = snapshot_paths.get("runtime_entrypoint")
    if not isinstance(recorded, str):
        return IntegrityResult(False, "contract-snapshot-path-missing", release_id)
    recorded_path = Path(recorded)
    try:
        contract_bytes = recorded_path.read_bytes()
    except OSError:
        reason = (
            "contract-snapshot-unreadable"
            if recorded_path.exists()
            else "contract-snapshot-path-stale"
        )
        return IntegrityResult(False, reason, release_id)
    if hashlib.sha256(contract_bytes).hexdigest() != raw.get("entrypoint_contract_sha256"):
        return IntegrityResult(False, "contract-hash-drift", release_id)
    try:
        snapshotted = json.loads(contract_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return IntegrityResult(False, "contract-snapshot-unparsable", release_id)
    if snapshotted != contract:
        return IntegrityResult(False, "embedded-contract-drift", release_id)

    # Schema validity, judged by the *trusted* copy of the canonical schema.
    # Byte-comparing the release's copy against the trusted one first means a
    # release that ships a different schema is reported as unjudgeable rather
    # than silently trusted -- and the release's copy is still never executed.
    schema = _trusted_contract_schema(trusted_schema_path)
    if schema is None:
        schema_state = "unverified-no-trusted-schema"
    else:
        installed = None
        if isinstance(module_paths_probe := raw.get("module_paths"), dict):
            recorded_schema = module_paths_probe.get(CANONICAL_SCHEMA_MODULE)
            if isinstance(recorded_schema, str):
                try:
                    installed = Path(recorded_schema).read_bytes()
                except OSError:
                    installed = None
        try:
            trusted_bytes = trusted_schema_path.read_bytes()
        except OSError:
            trusted_bytes = None
        if installed is None or trusted_bytes is None:
            schema_state = "unverified-schema-unreadable"
        elif installed != trusted_bytes:
            schema_state = "unverified-schema-differs"
        else:
            errors = schema.manifest_errors(raw)
            if errors:
                if "entrypoint_contract" in errors:
                    return IntegrityResult(
                        False, "entrypoint-contract-invalid", release_id
                    )
                return IntegrityResult(
                    False,
                    "manifest-schema-invalid:" + ",".join(errors[:8]),
                    release_id,
                )
            schema_state = "verified"

    # Installed artifact identity: pure hashing, no import, no execution.
    source_hashes = raw.get("source_sha256s")
    module_paths = raw.get("module_paths")
    if not isinstance(source_hashes, dict) or not isinstance(module_paths, dict):
        return IntegrityResult(False, "module-identity-fields-missing", release_id)
    if set(source_hashes) != set(module_paths):
        return IntegrityResult(False, "module-identity-sets-disagree", release_id)
    for module, expected in sorted(source_hashes.items()):
        observed = _sha256_file(Path(module_paths[module]))
        if observed is None:
            return IntegrityResult(False, f"module-unreadable:{module}", release_id)
        if observed != expected:
            return IntegrityResult(False, f"module-hash-drift:{module}", release_id)

    asset_hashes = raw.get("runtime_asset_sha256s")
    asset_paths = raw.get("runtime_asset_paths")
    if not isinstance(asset_hashes, dict) or not isinstance(asset_paths, dict):
        return IntegrityResult(False, "runtime-asset-fields-missing", release_id)
    if set(asset_hashes) != set(asset_paths):
        return IntegrityResult(False, "runtime-asset-sets-disagree", release_id)
    for destination, expected in sorted(asset_hashes.items()):
        observed = _sha256_file(Path(asset_paths[destination]))
        if observed is None:
            return IntegrityResult(False, f"asset-unreadable:{destination}", release_id)
        if observed != expected:
            return IntegrityResult(False, f"asset-hash-drift:{destination}", release_id)

    return IntegrityResult(
        True, None, release_id, scope=f"manifest+artifact-hashes;schema={schema_state}"
    )


def probe_runtime(
    *,
    service: str,
    profile: str,
    expected_module: str,
    runtime_root: Path,
    health_url: str,
    ready_url: str,
    startup_grace: float,
    http_timeout: float,
    proc_root: Path = Path("/proc"),
) -> ProbeResult:
    try:
        properties = service_properties(service)
    except WatchdogError as exc:
        return ProbeResult(status="indeterminate", reasons=(str(exc),))

    try:
        main_pid = int(properties["MainPID"])
    except (KeyError, ValueError):
        return ProbeResult(status="indeterminate", reasons=("invalid-main-pid",))

    if (
        properties.get("ActiveState") != "active"
        or properties.get("SubState") != "running"
        or main_pid <= 0
    ):
        return ProbeResult(status="inactive", main_pid=main_pid or None)

    reasons: list[str] = []
    if not main_identity_ok(proc_root, main_pid, profile):
        reasons.append("main-identity-mismatch")

    try:
        age = process_age_seconds(proc_root, main_pid)
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, WatchdogError):
        return ProbeResult(
            status="indeterminate",
            reasons=("main-process-age-unavailable",),
            main_pid=main_pid,
        )

    operators = operator_candidates(
        proc_root,
        main_pid,
        runtime_root,
        expected_module,
    )
    if len(operators) != 1:
        reasons.append(f"operator-count-{len(operators)}")

    try:
        if not http_probe(health_url, "live", http_timeout):
            reasons.append("health-failed")
        if not http_probe(ready_url, "ready", http_timeout):
            reasons.append("readiness-failed")
    except WatchdogError as exc:
        return ProbeResult(
            status="indeterminate",
            reasons=(str(exc),),
            main_pid=main_pid,
            operator_pid=operators[0] if len(operators) == 1 else None,
            process_age_seconds=age,
        )

    if not reasons:
        # Process and transport are alive.  That is not the same as operative:
        # a runtime whose deployment provenance is invalid still answers
        # /healthz while refusing every normal effect, so reporting it as
        # healthy would be semantically wrong.
        # Transport liveness alone is not operative health; a runtime can
        # answer /healthz while refusing every effect.
        integrity = probe_integrity(runtime_root)
        if not integrity.valid:
            return ProbeResult(
                status="integrity_invalid",
                reasons=(f"integrity-{integrity.reason}",),
                main_pid=main_pid,
                operator_pid=operators[0],
                process_age_seconds=age,
                integrity=integrity,
            )
        return ProbeResult(
            status="healthy",
            main_pid=main_pid,
            operator_pid=operators[0],
            process_age_seconds=age,
            integrity=integrity,
        )
    if age < startup_grace:
        return ProbeResult(
            status="startup_grace",
            reasons=tuple(reasons),
            main_pid=main_pid,
            operator_pid=operators[0] if len(operators) == 1 else None,
            process_age_seconds=age,
        )
    return ProbeResult(
        status="unhealthy",
        reasons=tuple(reasons),
        main_pid=main_pid,
        operator_pid=operators[0] if len(operators) == 1 else None,
        process_age_seconds=age,
    )


def ensure_state_dir(path: Path) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise WatchdogError("state-dir-is-symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not statmod.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise WatchdogError("unsafe-state-dir")
    os.chmod(path, 0o700)
    return path.resolve(strict=True)


def _open_owned_regular(path: Path, *, create: bool) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    info = os.fstat(fd)
    if not statmod.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        os.close(fd)
        raise WatchdogError("unsafe-lock-file")
    os.fchmod(fd, 0o600)
    return fd


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    fd = _open_owned_regular(path, create=True)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusy("watchdog-already-running") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


@contextmanager
def deployment_shared_lock(path: Path) -> Iterator[bool]:
    fd = _open_owned_regular(path, create=True)
    acquired = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            acquired = False
        yield acquired
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load_state(path: Path) -> WatchdogState:
    if not path.exists():
        return WatchdogState()
    if path.is_symlink():
        raise WatchdogError("state-file-is-symlink")
    info = path.stat()
    if not statmod.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise WatchdogError("unsafe-state-file")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WatchdogError("invalid-state-file") from exc
    failures = raw.get("consecutive_failures")
    timestamps = raw.get("restart_timestamps")
    if (
        not isinstance(failures, int)
        or failures < 0
        or not isinstance(timestamps, list)
        or any(not isinstance(item, int) or item < 0 for item in timestamps)
    ):
        raise WatchdogError("invalid-state-shape")
    return WatchdogState(failures, list(timestamps))


def save_state(path: Path, state: WatchdogState) -> None:
    payload = (
        json.dumps(
            {
                "consecutive_failures": state.consecutive_failures,
                "restart_timestamps": state.restart_timestamps,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def decide_failure(
    state: WatchdogState,
    *,
    now: int,
    failure_threshold: int,
    max_restarts: int,
    restart_window: int,
) -> Decision:
    recent = [item for item in state.restart_timestamps if item > now - restart_window]
    failures = state.consecutive_failures + 1
    if failures < failure_threshold:
        return Decision("observe", WatchdogState(failures, recent))
    if len(recent) >= max_restarts:
        return Decision("budget-exhausted", WatchdogState(failures, recent))
    recent.append(now)
    return Decision("restart", WatchdogState(0, recent))


def restart_service(service: str) -> None:
    try:
        subprocess.run(
            ["systemctl", "--user", "restart", service],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WatchdogError("service-restart-failed") from exc


def run_watchdog(args: argparse.Namespace) -> int:
    if args.failure_threshold < 1 or args.max_restarts < 1:
        raise WatchdogError("invalid-restart-policy")
    if args.restart_window < 1 or args.startup_grace < 0:
        raise WatchdogError("invalid-time-policy")

    state_dir = ensure_state_dir(args.state_dir)
    state_path = state_dir / "watchdog-state.json"
    watchdog_lock = state_dir / "watchdog.lock"
    deploy_lock = state_dir / "deploy.lock"

    with exclusive_lock(watchdog_lock):
        with deployment_shared_lock(deploy_lock) as deployment_clear:
            if not deployment_clear:
                emit("grabowski.watchdog.skipped", reason="deployment-in-progress")
                return 0

            state = load_state(state_path)
            probe = probe_runtime(
                service=args.service,
                profile=args.profile,
                expected_module=args.expected_module,
                runtime_root=args.runtime_root,
                health_url=args.health_url,
                ready_url=args.ready_url,
                startup_grace=args.startup_grace,
                http_timeout=args.http_timeout,
            )

            common = {
                "service": args.service,
                "status": probe.status,
                "reasons": list(probe.reasons),
                "main_pid": probe.main_pid,
                "operator_pid": probe.operator_pid,
            }
            if probe.integrity is not None:
                common["integrity"] = {
                    "valid": probe.integrity.valid,
                    "reason": probe.integrity.reason,
                    "release_id": probe.integrity.release_id,
                    "scope": probe.integrity.scope,
                    # State the limit inline so a consumer of these events
                    # cannot mistake the verdict for full provenance.
                    "does_not_establish": [
                        "provenance_valid",
                        "python, executable, platform or protocol identity",
                        "agent instruction identity",
                    ],
                }

            if probe.status == "integrity_invalid":
                # Restarting cannot repair a bad manifest, and a restart loop
                # would only hide the fault.  Report it as degraded and name the
                # repair path instead.
                emit(
                    "grabowski.watchdog.integrity-invalid",
                    remediation="grabowski_recovery_provenance_repair",
                    **common,
                )
                return 5

            if probe.status == "healthy":
                state.consecutive_failures = 0
                state.restart_timestamps = [
                    item
                    for item in state.restart_timestamps
                    if item > int(time.time()) - args.restart_window
                ]
                save_state(state_path, state)
                emit("grabowski.watchdog.healthy", **common)
                return 0

            if probe.status in {"inactive", "startup_grace"}:
                emit("grabowski.watchdog.skipped", **common)
                return 0

            if probe.status == "indeterminate":
                emit("grabowski.watchdog.indeterminate", **common)
                return 2

            if args.check_only:
                emit("grabowski.watchdog.unhealthy", **common)
                return 1

            decision = decide_failure(
                state,
                now=int(time.time()),
                failure_threshold=args.failure_threshold,
                max_restarts=args.max_restarts,
                restart_window=args.restart_window,
            )
            save_state(state_path, decision.state)

            if decision.action == "observe":
                emit(
                    "grabowski.watchdog.failure-observed",
                    **common,
                    consecutive_failures=decision.state.consecutive_failures,
                    threshold=args.failure_threshold,
                )
                return 1

            if decision.action == "budget-exhausted":
                emit(
                    "grabowski.watchdog.restart-budget-exhausted",
                    **common,
                    restarts_in_window=len(decision.state.restart_timestamps),
                    restart_window=args.restart_window,
                )
                return 3

            restart_service(args.service)
            deadline = time.monotonic() + args.recovery_timeout
            final_probe = probe
            while time.monotonic() < deadline:
                time.sleep(1)
                final_probe = probe_runtime(
                    service=args.service,
                    profile=args.profile,
                    expected_module=args.expected_module,
                    runtime_root=args.runtime_root,
                    health_url=args.health_url,
                    ready_url=args.ready_url,
                    startup_grace=0,
                    http_timeout=args.http_timeout,
                )
                if final_probe.status == "healthy":
                    emit(
                        "grabowski.watchdog.recovered",
                        service=args.service,
                        main_pid=final_probe.main_pid,
                        operator_pid=final_probe.operator_pid,
                        restarts_in_window=len(decision.state.restart_timestamps),
                    )
                    return 0

            failed_state = decision.state
            failed_state.consecutive_failures = 1
            save_state(state_path, failed_state)
            emit(
                "grabowski.watchdog.restart-unhealthy",
                service=args.service,
                status=final_probe.status,
                reasons=list(final_probe.reasons),
                restarts_in_window=len(failed_state.restart_timestamps),
            )
            return 4


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Grabowski semantic runtime watchdog")
    result.add_argument("--service", default=DEFAULT_SERVICE)
    result.add_argument("--profile", default=DEFAULT_PROFILE)
    result.add_argument("--expected-module", default=DEFAULT_MODULE)
    result.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    result.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    result.add_argument("--health-url", default=DEFAULT_HEALTH_URL)
    result.add_argument("--ready-url", default=DEFAULT_READY_URL)
    result.add_argument("--failure-threshold", type=int, default=3)
    result.add_argument("--max-restarts", type=int, default=3)
    result.add_argument("--restart-window", type=int, default=900)
    result.add_argument("--startup-grace", type=float, default=20)
    result.add_argument("--http-timeout", type=float, default=2)
    result.add_argument("--recovery-timeout", type=float, default=20)
    result.add_argument("--check-only", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        return run_watchdog(parser().parse_args(argv))
    except LockBusy as exc:
        emit("grabowski.watchdog.skipped", reason=str(exc))
        return 0
    except WatchdogError as exc:
        emit("grabowski.watchdog.error", reason=str(exc))
        return 2
    except Exception as exc:
        emit("grabowski.watchdog.error", reason=type(exc).__name__)
        return 2


if __name__ == "__main__":
    sys.exit(main())
