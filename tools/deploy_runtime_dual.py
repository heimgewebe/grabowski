#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from typing import Any, NoReturn
from urllib.parse import urlsplit

import deploy_runtime as core


TUNNEL_SERVICE = "tunnel-client-grabowski.service"
OPERATOR_SERVICE = "grabowski-operator.service"
OPERATOR_HTTP_ARGUMENTS = (
    "--transport",
    "streamable-http",
    "--host",
    "127.0.0.1",
    "--port",
    "18181",
)


@dataclass(frozen=True)
class ProfileTopology:
    kind: str
    legacy_entrypoint: core.EntryPoint | None = None
    server_url_count: int = 0


@dataclass(frozen=True)
class DualReadiness:
    ok: bool
    operator: core.ServiceObservation
    tunnel: core.ServiceObservation
    health: str | None
    readiness: str | None
    journal: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "operator": self.operator.to_dict(),
            "tunnel": self.tunnel.to_dict(),
            "health": self.health,
            "readiness": self.readiness,
            "journal": self.journal,
        }


def _load_yaml(profile_path: Path) -> Any:
    core.require_file(profile_path, "Tunnelprofil")
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        core.fail("PyYAML ist für strukturierte Profilprüfung erforderlich")
        raise AssertionError from exc
    if getattr(yaml, "__version__", None) != core.TOOLING_PYYAML_VERSION:
        core.fail(
            "PyYAML-Version für strukturierte Profilprüfung ist nicht "
            f"reproduzierbar: {getattr(yaml, '__version__', None)!r}"
        )
    try:
        return yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    except Exception as exc:
        mark = getattr(exc, "problem_mark", None)
        details: dict[str, Any] = {"error_type": type(exc).__name__}
        if mark is not None:
            details["line"] = getattr(mark, "line", 0) + 1
            details["column"] = getattr(mark, "column", 0) + 1
        core.fail("Tunnelprofil ist kein gültiges YAML", details=details)


def _server_url_count(data: Any) -> int:
    if not isinstance(data, dict):
        return 0
    mcp = data.get("mcp")
    if not isinstance(mcp, dict) or "server_urls" not in mcp:
        return 0
    values = mcp.get("server_urls")
    if not isinstance(values, list) or len(values) != 1:
        core.fail("Tunnelprofil mcp.server_urls muss genau einen Eintrag enthalten")
    item = values[0]
    if isinstance(item, str):
        url = item
    elif isinstance(item, dict):
        url = item.get("url")
    else:
        core.fail("Tunnelprofil enthält einen ungültigen server_urls-Eintrag")
    if not isinstance(url, str) or not url.strip():
        core.fail("Tunnelprofil server_urls-Eintrag benötigt eine URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        core.fail("Tunnelprofil server_urls-Eintrag ist keine gültige URL")
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or port != 18181 or parsed.path.rstrip("/") != "/mcp" or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None):
        core.fail("Tunnelprofil server_urls ist nicht der gebundene Loopback-Operator")
    return 1


def profile_topology(profile_path: Path, runtime: Path) -> ProfileTopology:
    data = _load_yaml(profile_path)
    commands = core.recursive_values_for_key(data, "command")
    string_commands = [item for item in commands if isinstance(item, str)]
    list_commands = [item for item in commands if isinstance(item, list)]
    typed_commands = len(string_commands) + len(list_commands)
    if typed_commands != len(commands):
        core.fail("Tunnelprofil enthält einen ungültig typisierten command")
    if typed_commands > 1:
        core.fail("Tunnelprofil enthält mehr als einen strukturierten command")

    server_url_count = _server_url_count(data)
    if typed_commands and server_url_count:
        core.fail("Tunnelprofil mischt command- und server_urls-Topologie")
    if typed_commands == 0 and server_url_count == 0:
        core.fail("Tunnelprofil enthält weder command noch server_urls")

    if server_url_count:
        return ProfileTopology("url", server_url_count=server_url_count)

    if string_commands:
        argv = shlex.split(string_commands[0])
    else:
        values = list_commands[0]
        if not all(isinstance(item, str) for item in values):
            core.fail("Tunnelprofil-command-Liste enthält Nicht-String-Werte")
        argv = list(values)
    if len(argv) != 3:
        core.fail("Tunnelprofil-command entspricht nicht dem Modul-Entry-Point")
    expected_python = runtime / ".venv/bin/python"
    if argv[0] != str(expected_python):
        core.fail("Tunnelprofil verwendet nicht den stabilen Runtime-Pythonpfad")
    if argv[1] != "-m" or core.MODULE_RE.fullmatch(argv[2]) is None:
        core.fail("Tunnelprofil-command entspricht nicht dem Modul-Entry-Point")
    return ProfileTopology(
        "legacy-stdio",
        legacy_entrypoint=core.EntryPoint(
            mode="module",
            python=expected_python,
            module=argv[2],
        ),
    )


def require_topology_matches_contract(
    topology: ProfileTopology,
    runtime: Path,
    contract: core.RuntimeContract,
) -> None:
    if topology.kind == "legacy-stdio":
        entrypoint = topology.legacy_entrypoint
        if entrypoint is None or not entrypoint.compatible_with(contract):
            core.fail(
                "Live-Profil und Branch-Runtimevertrag passen nicht zusammen"
            )
        return
    if topology.kind != "url":
        core.fail("Unbekannte Deploymenttopologie")
    verify_operator_unit_entrypoint(runtime, contract)


def observe_service(unit: str) -> core.ServiceObservation:
    result = core.run(
        [
            "systemctl",
            "--user",
            "show",
            unit,
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "MainPID",
            "--no-pager",
        ],
        capture=True,
        check=False,
        timeout=core.TIMEOUTS["systemd_query"],
    )
    fields: dict[str, str] = {}
    duplicate = False
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in fields:
            duplicate = True
        fields[key] = value
    required = {"LoadState", "ActiveState", "SubState", "MainPID"}
    main_pid: int | None = None
    try:
        main_pid = int(fields["MainPID"])
        if main_pid < 0:
            main_pid = None
    except (KeyError, ValueError):
        main_pid = None
    valid = (
        result.returncode == 0
        and not duplicate
        and set(fields) == required
        and main_pid is not None
    )
    return core.ServiceObservation(
        query_valid=valid,
        load_state=fields.get("LoadState"),
        active_state=fields.get("ActiveState"),
        sub_state=fields.get("SubState"),
        main_pid=main_pid,
        returncode=result.returncode,
    )


def wait_for_service(
    unit: str,
    *,
    active: bool,
    timeout_seconds: int,
) -> core.ServiceObservation:
    deadline = time.monotonic() + timeout_seconds
    last = observe_service(unit)
    while time.monotonic() < deadline:
        matched = last.confirmed_active if active else last.confirmed_inactive
        if matched:
            return last
        time.sleep(0.2)
        last = observe_service(unit)
    return last


def require_service_active(unit: str) -> core.ServiceObservation:
    observation = observe_service(unit)
    if not observation.confirmed_active:
        core.fail(
            f"{unit} ist nicht bestätigt aktiv",
            details={"service": observation.to_dict()},
        )
    return observation


def _service_main_pid(unit: str) -> int:
    observation = require_service_active(unit)
    if observation.main_pid is None:
        core.fail(f"{unit} besitzt keine bestätigte MainPID")
    return observation.main_pid


def verify_tunnel_process() -> dict[str, Any]:
    pid = _service_main_pid(TUNNEL_SERVICE)
    argv = core.process_argv(pid)
    expected_a = [
        str(core.HOME / ".local/bin/tunnel-client"),
        "run",
        "--profile",
        core.PROFILE_NAME,
    ]
    expected_b = [
        str(core.HOME / ".local/bin/tunnel-client"),
        "run",
        f"--profile={core.PROFILE_NAME}",
    ]
    if tuple(argv) not in {tuple(expected_a), tuple(expected_b)}:
        core.fail("Tunnel-Service verwendet nicht exakt den erwarteten Client")
    return {"pid": pid, "argv": core.redact_argv(argv)}


def expected_operator_argv(
    runtime: Path,
    contract: core.RuntimeContract,
) -> list[str]:
    return [
        str(runtime / ".venv/bin/python"),
        "-m",
        contract.module,
        *OPERATOR_HTTP_ARGUMENTS,
    ]


def _parse_systemd_execstart(value: str) -> list[str]:
    matches = re.findall(r"argv\[\]=(.*?)\s;\signore_errors=", value)
    if len(matches) != 1:
        core.fail("Operator-Service besitzt keinen eindeutigen ExecStart")
    try:
        argv = shlex.split(matches[0])
    except ValueError:
        core.fail("Operator-Service ExecStart ist nicht strukturiert parsebar")
    if not argv:
        core.fail("Operator-Service ExecStart ist leer")
    return argv


def operator_unit_argv() -> list[str]:
    result = core.run(
        [
            "systemctl",
            "--user",
            "show",
            OPERATOR_SERVICE,
            "--no-pager",
            "--property=ExecStart",
        ],
        capture=True,
        check=False,
        timeout=core.TIMEOUTS["systemd_query"],
    )
    if result.returncode != 0:
        core.fail("Operator-Service ExecStart konnte nicht gelesen werden")
    lines = [line for line in result.stdout.splitlines() if line.startswith("ExecStart=")]
    if len(lines) != 1:
        core.fail("Operator-Service liefert keinen eindeutigen ExecStart")
    return _parse_systemd_execstart(lines[0].removeprefix("ExecStart="))


def verify_operator_unit_entrypoint(
    runtime: Path,
    contract: core.RuntimeContract,
) -> dict[str, Any]:
    argv = operator_unit_argv()
    expected = expected_operator_argv(runtime, contract)
    if argv != expected:
        core.fail("Operator-Service ExecStart weicht vom Runtimevertrag ab")
    return {"argv": core.redact_argv(argv)}


def verify_operator_process(
    runtime: Path,
    contract: core.RuntimeContract,
    *,
    release_hint: Path | None = None,
) -> dict[str, Any]:
    pid = _service_main_pid(OPERATOR_SERVICE)
    argv = core.process_argv(pid)
    expected = expected_operator_argv(runtime, contract)
    if argv != expected:
        core.fail("Operator-Prozess verwendet nicht exakt den erwarteten Entry-Point")
    expected_python = runtime / ".venv/bin/python"
    executable = core.process_exe(pid)
    if executable is None or executable.resolve() != expected_python.resolve():
        core.fail("Operator-Prozess verwendet nicht den stabilen Runtime-Python")
    entrypoint_path = core.verify_entrypoint_importable(
        release_hint or runtime.resolve(),
        expected_python,
        contract,
    )
    return {
        "pid": pid,
        "entrypoint_path": str(entrypoint_path),
        "exe": str(executable),
        "argv": core.redact_argv(argv),
    }


def journal_tail(unit: str) -> str:
    result = core.run(
        ["journalctl", "--user", "-u", unit, "-n", "40", "--no-pager"],
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["journal"],
    )
    return core.redact_text(result.stdout + result.stderr)


def readiness_probe(*, include_journal: bool = False) -> DualReadiness:
    operator = observe_service(OPERATOR_SERVICE)
    tunnel = observe_service(TUNNEL_SERVICE)
    health = core.http_text(core.HEALTH_URL)
    readiness = core.http_text(core.READY_URL)
    ok = (
        operator.confirmed_active
        and tunnel.confirmed_active
        and health == "live"
        and readiness == "ready"
    )
    journal = ""
    if include_journal and not ok:
        journal = (
            f"[{OPERATOR_SERVICE}]\n{journal_tail(OPERATOR_SERVICE)}\n"
            f"[{TUNNEL_SERVICE}]\n{journal_tail(TUNNEL_SERVICE)}"
        )
    return DualReadiness(ok, operator, tunnel, health, readiness, journal)


def wait_until_ready(timeout_seconds: int) -> DualReadiness:
    deadline = time.monotonic() + timeout_seconds
    last = readiness_probe()
    while time.monotonic() < deadline:
        if last.ok:
            return last
        time.sleep(0.25)
        last = readiness_probe()
    return readiness_probe(include_journal=True)


def stop_service(unit: str) -> core.ServiceObservation:
    result = core.run(
        ["systemctl", "--user", "stop", unit],
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["service_stop"],
    )
    observation = wait_for_service(
        unit,
        active=False,
        timeout_seconds=core.TIMEOUTS["service_stop"],
    )
    if not observation.confirmed_inactive:
        core.fail(
            f"{unit} wurde nach Stopversuch nicht bestätigt inaktiv",
            details={
                "stop_returncode": result.returncode,
                "service": observation.to_dict(),
            },
        )
    return observation


def start_service(unit: str) -> core.ServiceObservation:
    result = core.run(
        ["systemctl", "--user", "start", unit],
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["service_start"],
    )
    if result.returncode != 0:
        core.fail(f"{unit} konnte nicht gestartet werden")
    observation = wait_for_service(
        unit,
        active=True,
        timeout_seconds=core.TIMEOUTS["service_start"],
    )
    if not observation.confirmed_active:
        core.fail(
            f"{unit} wurde nach Start nicht bestätigt aktiv",
            details={"service": observation.to_dict()},
        )
    return observation


def verify_url_runtime_identity(
    release_path: Path,
    runtime: Path,
    contract: core.RuntimeContract,
    *,
    snapshot: core.Snapshot,
) -> dict[str, Any]:
    if not runtime.is_symlink() or runtime.resolve() != release_path.resolve():
        core.fail("Stabiler Runtime-Symlink zeigt nicht auf das ausgewählte Release")
    process = verify_operator_process(
        runtime,
        contract,
        release_hint=release_path,
    )
    manifest = core.verify_manifest(
        release_path,
        snapshot=snapshot,
        stable_runtime=runtime,
    )
    core.verify_final_release_artifacts(
        release_path,
        runtime,
        contract,
        snapshot=snapshot,
        manifest=manifest,
        process=process,
    )
    return {"process": process, "manifest": manifest}


def _error_summary(error: BaseException) -> dict[str, Any]:
    return core.safe_error_summary(error)


def rollback_url(
    original: BaseException,
    *,
    activation: core.ActivationState,
    contract: core.RuntimeContract,
    timeout_seconds: int,
) -> NoReturn:
    phases: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []

    def step(name: str, callback) -> tuple[bool, Any | None]:
        try:
            value = callback()
        except Exception as exc:
            summary = _error_summary(exc)
            phases[name] = {"ok": False, "error": summary}
            errors.append({"phase": name, "error": summary})
            return False, None
        phases[name] = {"ok": True, "result": core.summarize_result(value)}
        return True, value

    tunnel_ok, tunnel = step("stop-tunnel", lambda: stop_service(TUNNEL_SERVICE))
    operator_ok, operator = step("stop-operator", lambda: stop_service(OPERATOR_SERVICE))
    if not (tunnel_ok and isinstance(tunnel, core.ServiceObservation) and tunnel.confirmed_inactive and operator_ok and isinstance(operator, core.ServiceObservation) and operator.confirmed_inactive):
        payload = {"original": _error_summary(original), "phases": phases, "errors": errors, "pointer_restore": "not-attempted"}
        raise core.DeployError("Kritischer Rollbackabbruch vor Pointermutation: " + json.dumps(payload, sort_keys=True)) from original

    restore_ok, _ = step("restore-pointer", lambda: core.restore_pointer(activation))
    verify_ok, _ = step("verify-pointer", lambda: core.verify_pointer_state(activation.runtime, activation.previous))
    if not restore_ok or not verify_ok:
        payload = {"original": _error_summary(original), "phases": phases, "errors": errors, "pointer_restore": "failed"}
        raise core.DeployError("Kritischer Rollbackabbruch nach Pointerfehler: " + json.dumps(payload, sort_keys=True)) from original

    operator_start_ok, started_operator = step("start-operator", lambda: start_service(OPERATOR_SERVICE))
    identity_ok = False
    identity = None
    if operator_start_ok and started_operator is not None:
        identity_ok, identity = step("verify-operator", lambda: verify_operator_process(activation.runtime, contract))
    tunnel_start_ok = False
    started_tunnel = None
    if identity_ok and identity is not None:
        tunnel_start_ok, started_tunnel = step("start-tunnel", lambda: start_service(TUNNEL_SERVICE))
    ready_ok = False
    ready = None
    if tunnel_start_ok and started_tunnel is not None:
        ready_ok, ready = step("readiness", lambda: wait_until_ready(timeout_seconds))
        if ready_ok and isinstance(ready, DualReadiness) and not ready.ok:
            errors.append({"phase": "readiness", "message": "Wiederhergestellte Runtime wurde nicht ready", "result": ready.to_dict()})
            ready_ok = False

    payload = {
        "original": _error_summary(original),
        "phases": phases,
        "errors": errors,
        "pointer_restore": "restored",
        "operator_identity": "verified" if identity_ok and identity is not None else "failed",
        "readiness": "verified" if ready_ok and isinstance(ready, DualReadiness) and ready.ok else "failed",
    }
    raise core.DeployError("Deployment fehlgeschlagen; Zwei-Dienste-Rollbackzustand: " + json.dumps(payload, sort_keys=True)) from original


def preflight_url(
    repo: Path,
    runtime: Path,
    profile_path: Path,
) -> tuple[core.Snapshot, Path, ProfileTopology]:
    snapshot = core.snapshot_from_git(repo)
    runtime = core.require_runtime_replaceable(runtime)
    topology = profile_topology(profile_path, runtime)
    require_topology_matches_contract(topology, runtime, snapshot.contract)
    if topology.kind != "url":
        return snapshot, runtime, topology
    require_service_active(OPERATOR_SERVICE)
    require_service_active(TUNNEL_SERVICE)
    verify_operator_process(runtime, snapshot.contract)
    verify_tunnel_process()
    return snapshot, runtime, topology


def deploy_url(
    repo: Path,
    runtime: Path,
    profile_path: Path,
    *,
    timeout_seconds: int,
) -> None:
    snapshot, runtime, topology = preflight_url(repo, runtime, profile_path)
    if topology.kind == "legacy-stdio":
        core.deploy(
            repo,
            runtime,
            profile_path,
            timeout_seconds=timeout_seconds,
        )
        return

    build = core.build_release(
        snapshot,
        core.releases_root_for(runtime),
        runtime,
    )
    core.verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)
    core.verify_manifest(
        build.release_path,
        snapshot=snapshot,
        stable_runtime=runtime,
    )
    activation = core.ActivationState(
        runtime=runtime,
        release_path=build.release_path,
        previous=core.capture_pointer(runtime),
    )
    phase = "stop-tunnel"
    try:
        stop_service(TUNNEL_SERVICE)
        phase = "stop-operator"
        stop_service(OPERATOR_SERVICE)

        phase = "pre-activation-revalidation"
        core.verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)
        current_topology = profile_topology(profile_path, runtime)
        if current_topology.kind != "url":
            core.fail("Tunnelprofil-Topologie driftete vor Aktivierung")
        require_topology_matches_contract(
            current_topology,
            runtime,
            snapshot.contract,
        )

        phase = "activate-pointer"
        core.activate_pointer(activation)

        phase = "start-operator"
        start_service(OPERATOR_SERVICE)
        verify_operator_process(
            runtime,
            snapshot.contract,
            release_hint=build.release_path,
        )

        phase = "start-tunnel"
        start_service(TUNNEL_SERVICE)
        verify_tunnel_process()

        phase = "readiness"
        readiness = wait_until_ready(timeout_seconds)
        if not readiness.ok:
            core.fail(
                "Neue Runtime wurde nicht rechtzeitig live und ready",
                phase="readiness",
                details=readiness.to_dict(),
            )

        phase = "identity"
        identity = verify_url_runtime_identity(
            build.release_path,
            runtime,
            snapshot.contract,
            snapshot=snapshot,
        )

        print("PASS: Zwei-Dienste-Deployment erfolgreich")
        print(f"Repo-HEAD:       {snapshot.repo_head}")
        print(f"Release-ID:      {build.release_id}")
        print(f"Source-SHA256:   {snapshot.source_sha256}")
        print(f"Lock-SHA256:     {snapshot.runtime_lock_sha256}")
        print(f"Entry-Point:     {snapshot.contract.describe()}")
        print(f"MCP-Protokoll:   {build.protocol_version}")
        print(f"Runtime-PID:     {identity['process']['pid']}")
        print(f"Runtime:         {runtime}")
        print(f"Release:         {build.release_path}")
        print(f"Legacy-Backup:   {activation.legacy_backup}")
    except Exception as original:
        print(
            "PRIMARY-DEPLOY-ERROR: "
            + json.dumps(_error_summary(original), sort_keys=True),
            file=sys.stderr,
        )
        rollback_url(
            original,
            activation=activation,
            contract=snapshot.contract,
            timeout_seconds=timeout_seconds,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy Grabowski for legacy or dual-service topology."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--runtime",
        type=Path,
        default=core.HOME / ".local/share/grabowski-mcp",
    )
    parser.add_argument(
        "--profile-path",
        type=Path,
        default=core.DEFAULT_PROFILE_PATH,
    )
    parser.add_argument(
        "--lock-file",
        type=Path,
        default=core.DEFAULT_LOCK_FILE,
    )
    parser.add_argument("--timeout", type=int, default=40)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    runtime = core.absolute_no_resolve(args.runtime)
    profile_path = core.absolute_no_resolve(args.profile_path)
    lock_file = core.absolute_no_resolve(args.lock_file)
    try:
        if args.check:
            core.check(repo, runtime)
        elif args.preflight:
            snapshot, _, topology = preflight_url(repo, runtime, profile_path)
            print("PASS: Deployment-Preflight erfolgreich")
            print(f"Repo-HEAD:       {snapshot.repo_head}")
            print(f"Topologie:       {topology.kind}")
            print(f"Entry-Point:     {snapshot.contract.describe()}")
        else:
            preflight_url(repo, runtime, profile_path)
            with core.deployment_lock(lock_file):
                deploy_url(
                    repo,
                    runtime,
                    profile_path,
                    timeout_seconds=args.timeout,
                )
    except core.DeployError as exc:
        print(
            "STOP: "
            + json.dumps(
                _error_summary(exc),
                sort_keys=True,
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1
    except subprocess.CalledProcessError as exc:
        print(
            "STOP: "
            + json.dumps(
                _error_summary(exc),
                sort_keys=True,
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return exc.returncode or 1
    except Exception as exc:
        print(
            "STOP: "
            + json.dumps(
                _error_summary(exc),
                sort_keys=True,
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
