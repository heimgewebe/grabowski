#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import nullcontext
import ctypes
import ctypes.util
from dataclasses import dataclass, field
import errno
import hashlib
from importlib import import_module
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat as statmod
import shlex
import socket
import subprocess
import sys
import time
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import deploy_runtime as core

SOURCE_MODULE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_MODULE_ROOT))
deployment_observer = import_module("grabowski_deployment_observer")
client_snapshot = import_module("grabowski_client_snapshot")
connector_contract = import_module("grabowski_connector_contract")
transport_ingress = import_module("grabowski_transport_ingress")
midcutover = import_module("grabowski_midcutover_resume")


@dataclass(frozen=True)
class WatchdogHostAsset:
    source: Path
    target: Path
    mode: int
    unit: str | None = None
    reloads_systemd: bool = False


@dataclass(frozen=True)
class WatchdogHostAssetPreimage:
    asset: WatchdogHostAsset
    existed: bool
    content: bytes | None
    mode: int | None
    identity: tuple[int, int] | None


@dataclass(frozen=True)
class WatchdogHostAssetProjection:
    repo_head: str
    preimages: tuple[WatchdogHostAssetPreimage, ...]
    expected: dict[str, bytes]
    changed_targets: tuple[str, ...]
    asset_set_sha256: str
    tunnel_operator_dependency_preimage: dict[str, tuple[str, ...]] | None = None


TUNNEL_SERVICE = "tunnel-client-grabowski.service"
OPERATOR_SERVICE = "grabowski-operator.service"
TRANSPORT_INGRESS_SERVICE = "grabowski-transport-ingress.service"
SAFETY_OBSERVER_SERVICE = "grabowski-safety-observer.service"
SAFETY_OBSERVER_UNIT_RELATIVE = Path("systemd/grabowski-safety-observer.service.example")
SAFETY_OBSERVER_UNIT_PATH = core.HOME / ".config/systemd/user/grabowski-safety-observer.service"
TUNNEL_OPERATOR_DEPENDENCY_RELATIVE = Path(
    "systemd/tunnel-client-grabowski.service.d/70-operator-dependency.conf.example"
)
TUNNEL_OPERATOR_DEPENDENCY_PATH = (
    core.HOME
    / ".config/systemd/user/tunnel-client-grabowski.service.d/70-operator-dependency.conf"
)
TUNNEL_OPERATOR_DEPENDENCY_EXPECTED_DIRECTIVES = {
    "Unit": {
        "Wants": TRANSPORT_INGRESS_SERVICE,
        "After": TRANSPORT_INGRESS_SERVICE,
        "PartOf": TRANSPORT_INGRESS_SERVICE,
    }
}
TUNNEL_OPERATOR_DEPENDENCY_EFFECTIVE_PROPERTIES = (
    "LoadState",
    "Wants",
    "After",
    "PartOf",
    "BindsTo",
    "DropInPaths",
)
WATCHDOG_HOST_ASSET_MAX_BYTES = 1_048_576
WATCHDOG_HOST_ASSETS = (
    WatchdogHostAsset(
        source=Path("tools/grabowski_transport_ingress.py"),
        target=core.HOME / ".local/libexec/grabowski/grabowski_transport_ingress.py",
        mode=0o700,
    ),
    WatchdogHostAsset(
        source=Path("systemd/grabowski-transport-ingress.service.example"),
        target=core.HOME / ".config/systemd/user/grabowski-transport-ingress.service",
        mode=0o600,
        unit=TRANSPORT_INGRESS_SERVICE,
    ),
    WatchdogHostAsset(
        source=Path("tools/watchdog_admission_recovery.py"),
        target=(
            core.HOME
            / ".local/libexec/grabowski/watchdog_admission_recovery.py"
        ),
        mode=0o600,
    ),
    WatchdogHostAsset(
        source=Path("tools/component_watchdog.py"),
        target=core.HOME / ".local/libexec/grabowski/component_watchdog.py",
        mode=0o700,
    ),
    WatchdogHostAsset(
        source=TUNNEL_OPERATOR_DEPENDENCY_RELATIVE,
        target=TUNNEL_OPERATOR_DEPENDENCY_PATH,
        mode=0o600,
        reloads_systemd=True,
    ),
    WatchdogHostAsset(
        source=Path("systemd/grabowski-operator-watchdog.service.example"),
        target=core.HOME / ".config/systemd/user/grabowski-operator-watchdog.service",
        mode=0o600,
        unit="grabowski-operator-watchdog.service",
    ),
    WatchdogHostAsset(
        source=Path("systemd/grabowski-operator-watchdog.timer.example"),
        target=core.HOME / ".config/systemd/user/grabowski-operator-watchdog.timer",
        mode=0o600,
        unit="grabowski-operator-watchdog.timer",
    ),
    WatchdogHostAsset(
        source=Path("systemd/grabowski-tunnel-watchdog.service.example"),
        target=core.HOME / ".config/systemd/user/grabowski-tunnel-watchdog.service",
        mode=0o600,
        unit="grabowski-tunnel-watchdog.service",
    ),
    WatchdogHostAsset(
        source=Path("systemd/grabowski-tunnel-watchdog.timer.example"),
        target=core.HOME / ".config/systemd/user/grabowski-tunnel-watchdog.timer",
        mode=0o600,
        unit="grabowski-tunnel-watchdog.timer",
    ),
    WatchdogHostAsset(
        source=Path("systemd/grabowski-runtime-retention.service.example"),
        target=core.HOME / ".config/systemd/user/grabowski-runtime-retention.service",
        mode=0o600,
        unit="grabowski-runtime-retention.service",
    ),
    WatchdogHostAsset(
        source=Path("systemd/grabowski-runtime-retention.timer.example"),
        target=core.HOME / ".config/systemd/user/grabowski-runtime-retention.timer",
        mode=0o600,
        unit="grabowski-runtime-retention.timer",
    ),
)
OBSERVER_FORBIDDEN_RELATIONS = {
    "Wants",
    "Requires",
    "Requisite",
    "BindsTo",
    "PartOf",
    "Upholds",
    "Conflicts",
    "OnFailure",
    "OnSuccess",
    "PropagatesReloadTo",
    "ReloadPropagatedFrom",
    "PropagatesStopTo",
    "StopPropagatedFrom",
    "JoinsNamespaceOf",
}
OBSERVER_HIDDEN_RELATIONS = {"Upholds"}
OBSERVER_EFFECTIVE_RELATIONS = OBSERVER_FORBIDDEN_RELATIONS - OBSERVER_HIDDEN_RELATIONS
OBSERVER_EXPECTED_AFTER = (OPERATOR_SERVICE, TUNNEL_SERVICE)
OBSERVER_EXPECTED_EXEC_START = (
    "/usr/bin/python3 %h/.local/libexec/grabowski-safety-observer.py collect"
)
OBSERVER_EXPECTED_DIRECTIVES = {
    "Unit": {
        "Description": "Grabowski safety and connector incident observer",
        "After": " ".join(OBSERVER_EXPECTED_AFTER),
    },
    "Service": {
        "Type": "oneshot",
        "ExecStart": OBSERVER_EXPECTED_EXEC_START,
        "TimeoutStartSec": "60",
        "MemoryMax": "512M",
        "TasksMax": "50",
        "UMask": "0077",
        "NoNewPrivileges": "true",
        "PrivateTmp": "true",
        "ProtectSystem": "strict",
        "ProtectHome": "read-only",
        "ProtectKernelTunables": "true",
        "ProtectControlGroups": "true",
        "ReadWritePaths": "%h/.local/state/grabowski/safety-observer",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "RestrictNamespaces": "true",
        "SystemCallArchitectures": "native",
        "LockPersonality": "true",
        "MemoryDenyWriteExecute": "true",
    },
}
OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES = {
    "Type": "oneshot",
    "RemainAfterExit": "no",
    "TimeoutStartUSec": "1min",
    "MemoryMax": str(512 * 1024 * 1024),
    "TasksMax": "50",
    "UMask": "0077",
    "NoNewPrivileges": "yes",
    "PrivateTmp": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "read-only",
    "ProtectKernelTunables": "yes",
    "ProtectControlGroups": "yes",
    "RestrictNamespaces": "yes",
    "SystemCallArchitectures": "native",
    "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes",
}
OBSERVER_EXPECTED_EFFECTIVE_SETS = {
    "ReadWritePaths": {
        str(core.HOME / ".local/state/grabowski/safety-observer"),
    },
    "RestrictAddressFamilies": {"AF_UNIX", "AF_INET", "AF_INET6"},
}
OBSERVER_USER_CAPABILITY_INCOMPATIBLE_DIRECTIVES = frozenset(
    {"PrivateDevices", "ProtectKernelModules", "ProtectKernelLogs"}
)
OBSERVER_SAFETY_REPAIR_MARKER = "observer_safety_repair_retained_v1"
OPERATOR_LISTENER_HOST = "127.0.0.1"
OPERATOR_LISTENER_PORT = 18181
GREEN_OPERATOR_LISTENER_PORT = 18182
TRANSPORT_INGRESS_LISTENER_PORT = 18180
TRANSPORT_INGRESS_AUTH_HEADER = "X-Grabowski-Ingress-Auth"
TRANSPORT_CONNECTOR_TOKEN_PATH = core.HOME / ".local/state/grabowski/transport-connectors/primary.token"
LEGACY_TUNNEL_OPERATOR_PORT = OPERATOR_LISTENER_PORT
TUNNEL_TARGET_PORTS = frozenset({LEGACY_TUNNEL_OPERATOR_PORT, TRANSPORT_INGRESS_LISTENER_PORT})
TRANSPORT_INGRESS_HEALTH_URL = f"http://127.0.0.1:{TRANSPORT_INGRESS_LISTENER_PORT}/_grabowski/transport-ingress"
TRANSPORT_INGRESS_HEALTH_TIMEOUT_SECONDS = 5.0
TRANSPORT_INGRESS_HEALTH_POLL_INTERVAL_SECONDS = 0.1
OPERATOR_LISTENER_REQUIRED_SAMPLES = 2
TUNNEL_METRICS_URL = core.HEALTH_URL.rsplit("/", 1)[0] + "/metrics"
TUNNEL_DRAIN_QUEUE_GAUGE_NAME = "commands_queue_length"
TUNNEL_DRAIN_WORKER_GAUGE_NAME = "dispatcher_worker_pool_occupancy"
TUNNEL_DRAIN_DIRECT_COUNTER_NAMES = (
    "commands_polled_total",
    "commands_enqueued_total",
)
TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME = "commands_final_responses_total"
TUNNEL_DRAIN_RESPONSE_HISTOGRAM_COUNT_NAME = "command_end_to_end_latency_milliseconds_count"
TUNNEL_DRAIN_COUNTER_NAMES = (
    *TUNNEL_DRAIN_DIRECT_COUNTER_NAMES,
    TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME,
)
TUNNEL_DRAIN_IDENTITY_NAMES = ("process_start_time_seconds",)
TUNNEL_DRAIN_STABILITY_NAMES = TUNNEL_DRAIN_COUNTER_NAMES + TUNNEL_DRAIN_IDENTITY_NAMES
OPERATOR_ADMISSION_MARKER_PATH = (
    core.DEFAULT_STATE_ROOT / "deployment-admission-drain.json"
)
OPERATOR_ADMISSION_STATUS_PATH = "/_grabowski/deployment-admission"
OPERATOR_ADMISSION_STATUS_URL = (
    f"http://{OPERATOR_LISTENER_HOST}:{OPERATOR_LISTENER_PORT}"
    f"{OPERATOR_ADMISSION_STATUS_PATH}"
)


def _operator_admission_status_url(port: int) -> str:
    """The admission status endpoint of one specific operator process.

    The marker itself is a file every grabowski operator reads, so engaging it
    closes admission everywhere at once.  The *readback*, though, is per
    process, and during a mid-cutover resume the process that matters is the
    transient green one: it is what the public route points at.
    """
    if port not in {OPERATOR_LISTENER_PORT, GREEN_OPERATOR_LISTENER_PORT}:
        core.fail("Admission readback port is outside the blue-green contract")
    return f"http://{OPERATOR_LISTENER_HOST}:{port}{OPERATOR_ADMISSION_STATUS_PATH}"
OPERATOR_ADMISSION_MARKER_KIND = "grabowski_deployment_admission_drain"
#: Mirrors grabowski_operator.DEPLOYMENT_ADMISSION_HEAD_RE so a marker written
#: here is always readable by the gate that consumes it.
OPERATOR_ADMISSION_HEAD_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
OPERATOR_ADMISSION_MARKER_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "token",
        "expected_head",
        "source_identity_sha256",
        "created_at_unix",
        "expires_at_unix",
    }
)
OPERATOR_ADMISSION_MARKER_MAX_LIFETIME_SECONDS = 1800
OPERATOR_ADMISSION_MAX_TIMEOUT_SECONDS = 120
# Bootstrap only for marker-aware predecessor runtimes that expose total calls
# but not the effect-aware classification added by this release.
OPERATOR_ADMISSION_BOOTSTRAP_DRAIN_SECONDS = 300
OPERATOR_ADMISSION_EFFECT_CLASSIFICATION = "readOnlyHint-true-is-read-only-v1"
OPERATOR_ADMISSION_DYNAMIC_TIMEOUT_WINDOWS = 6
OPERATOR_ADMISSION_STOP_OPERATIONS = 6
OPERATOR_ADMISSION_START_OPERATIONS = 4
OPERATOR_ADMISSION_SYSTEMD_QUERY_WINDOWS = 12
OPERATOR_ADMISSION_RECOVERY_MARGIN_SECONDS = 120
OPERATOR_ADMISSION_REQUIRED_IDLE_SAMPLES = 2
OPERATOR_ADMISSION_PROBE_SECONDS = 30
TUNNEL_DRAIN_DIRECT_METRIC_NAMES = (
    TUNNEL_DRAIN_QUEUE_GAUGE_NAME,
    TUNNEL_DRAIN_WORKER_GAUGE_NAME,
    *TUNNEL_DRAIN_DIRECT_COUNTER_NAMES,
    *TUNNEL_DRAIN_IDENTITY_NAMES,
)
TUNNEL_DRAIN_REQUIRED_IDLE_SAMPLES = 3
TUNNEL_DRAIN_SAMPLE_INTERVAL_SECONDS = 0.1
OPERATOR_HTTP_ARGUMENTS = (
    "--transport",
    "streamable-http",
    "--host",
    OPERATOR_LISTENER_HOST,
    "--port",
    str(OPERATOR_LISTENER_PORT),
)
GREEN_OPERATOR_UNIT_PREFIX = "grabowski-green-operator-"
GREEN_OPERATOR_UNIT_RE = re.compile(
    rf"{GREEN_OPERATOR_UNIT_PREFIX}[0-9a-f]{{12}}\.service\Z"
)
GREEN_INHERITED_OPERATOR_ENV_KEYS = (
    "GRABOWSKI_SERVER_RECOVERY_HOST",
    "GRABOWSKI_SERVER_RECOVERY_TARGET",
)


@dataclass(frozen=True)
class ProfileTopology:
    kind: str
    legacy_entrypoint: core.EntryPoint | None = None
    server_url_count: int = 0
    server_url_port: int | None = None


@dataclass(frozen=True)
class TunnelProfileCutover:
    before: bytes
    before_sha256: str
    before_identity: tuple[int, int]
    after_sha256: str
    mode: int
    before_port: int
    after_port: int


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


_OBSERVER_UNIT_HORIZONTAL_WHITESPACE = " \t"
# LF (line separator) and HT (intentionally supported for indentation/trimming)
# are the only C0 control bytes admitted into a unit-file input; everything
# else -- including VT/FF/CR/NUL, which Python's generic str.strip() and
# str.splitlines() would silently normalize away -- must fail closed instead
# of being interpreted differently by us than by systemd's own byte parser.
_OBSERVER_UNIT_ALLOWED_CONTROL_BYTES = frozenset({0x09, 0x0A})


def _validate_observer_unit_control_bytes(data: bytes) -> None:
    for byte in data:
        if byte in _OBSERVER_UNIT_ALLOWED_CONTROL_BYTES:
            continue
        if byte < 0x20 or byte == 0x7F:
            core.fail(
                "Safety-Observer-Unit enthält ein nicht erlaubtes Steuerzeichen",
                phase="observer-unit-contract",
                details={"byte": f"0x{byte:02x}"},
            )


def _parse_observer_unit_directives(data: bytes) -> dict[tuple[str, str], str]:
    _validate_observer_unit_control_bytes(data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        core.fail(
            "Safety-Observer-Unit ist kein gültiges UTF-8",
            phase="observer-unit-source",
            details={"error_type": type(exc).__name__},
        )
    directives: dict[tuple[str, str], str] = {}
    sections_seen: set[str] = set()
    section: str | None = None
    for raw_line in text.split("\n"):
        line = raw_line.strip(_OBSERVER_UNIT_HORIZONTAL_WHITESPACE)
        # systemd resolves physical-line continuations before interpreting
        # comments. Reject them before comment handling so a commented
        # backslash cannot make our parser and systemd see different input.
        if line.endswith("\\"):
            core.fail(
                "Safety-Observer-Unit darf keine Zeilenfortsetzungen enthalten",
                phase="observer-unit-contract",
            )
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                core.fail(
                    "Safety-Observer-Unit enthält einen ungültigen Abschnitt",
                    phase="observer-unit-contract",
                )
            section = line[1:-1].strip(_OBSERVER_UNIT_HORIZONTAL_WHITESPACE)
            if section not in OBSERVER_EXPECTED_DIRECTIVES:
                core.fail(
                    "Safety-Observer-Unit enthält einen nicht erlaubten Abschnitt",
                    phase="observer-unit-contract",
                    details={"section": section},
                )
            if section in sections_seen:
                core.fail(
                    "Safety-Observer-Unit enthält einen doppelten Abschnitt",
                    phase="observer-unit-contract",
                    details={"section": section},
                )
            sections_seen.add(section)
            continue
        key, separator, value = line.partition("=")
        key = key.strip(_OBSERVER_UNIT_HORIZONTAL_WHITESPACE)
        value = value.strip(_OBSERVER_UNIT_HORIZONTAL_WHITESPACE)
        if section is None or not separator or not key:
            core.fail(
                "Safety-Observer-Unit enthält eine ungültige aktive Direktive",
                phase="observer-unit-contract",
            )
        pair = (section, key)
        if pair in directives:
            core.fail(
                "Safety-Observer-Unit enthält eine doppelte aktive Direktive",
                phase="observer-unit-contract",
                details={"section": section, "directive": key},
            )
        expected_value = OBSERVER_EXPECTED_DIRECTIVES[section].get(key)
        if expected_value is None:
            core.fail(
                "Safety-Observer-Unit enthält eine nicht erlaubte aktive Direktive",
                phase="observer-unit-contract",
                details={"section": section, "directive": key},
            )
        if value != expected_value:
            core.fail(
                "Safety-Observer-Unit enthält einen unerwarteten Direktivenwert",
                phase="observer-unit-contract",
                details={"section": section, "directive": key},
            )
        directives[pair] = value
    if sections_seen != set(OBSERVER_EXPECTED_DIRECTIVES):
        core.fail(
            "Safety-Observer-Unit enthält nicht exakt die erwarteten Abschnitte",
            phase="observer-unit-contract",
        )
    return directives


def _validate_observer_unit_bytes(data: bytes) -> bytes:
    if not data.endswith(b"\n"):
        core.fail("Safety-Observer-Unit benötigt einen abschließenden Zeilenumbruch")
    directives = _parse_observer_unit_directives(data)
    expected = {
        (section, key): value
        for section, section_directives in OBSERVER_EXPECTED_DIRECTIVES.items()
        for key, value in section_directives.items()
    }
    if directives != expected:
        core.fail(
            "Safety-Observer-Unit enthält nicht exakt den erwarteten Direktivenvertrag",
            phase="observer-unit-contract",
        )
    return data


def _observer_unit_bytes(repo: Path, repo_head: str) -> bytes:
    try:
        data = core.git_show(repo, repo_head, SAFETY_OBSERVER_UNIT_RELATIVE)
    except (OSError, subprocess.CalledProcessError) as exc:
        core.fail(
            "Safety-Observer-Unit konnte nicht aus dem gebundenen Commit gelesen werden",
            phase="observer-unit-source",
            details={"error_type": type(exc).__name__, "repo_head": repo_head},
        )
    return _validate_observer_unit_bytes(data)


def _parse_effective_exec_start(value: str) -> tuple[str, list[str]]:
    if not value.startswith("{ ") or not value.endswith(" }"):
        core.fail(
            "Effektiver Safety-Observer ExecStart ist nicht eindeutig lesbar",
            phase="observer-unit-readback",
        )
    fields: dict[str, str] = {}
    for item in value[2:-2].split(" ; "):
        key, separator, field_value = item.partition("=")
        if separator:
            fields[key] = field_value
    try:
        argv = shlex.split(fields["argv[]"])
    except (KeyError, ValueError) as exc:
        core.fail(
            "Effektiver Safety-Observer ExecStart ist nicht eindeutig lesbar",
            phase="observer-unit-readback",
            details={"error_type": type(exc).__name__},
        )
    return fields.get("path", ""), argv


def _observer_unit_relations(target: Path) -> dict[str, list[str]]:
    properties = sorted(OBSERVER_EFFECTIVE_RELATIONS)
    effective_properties = sorted(OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES)
    effective_set_properties = sorted(OBSERVER_EXPECTED_EFFECTIVE_SETS)
    argv = ["systemctl", "--user", "show", target.name]
    argv.extend(f"--property={item}" for item in properties)
    argv.extend(f"--property={item}" for item in effective_properties)
    argv.extend(f"--property={item}" for item in effective_set_properties)
    argv.extend(
        [
            "--property=After",
            "--property=ExecStart",
            "--property=FragmentPath",
            "--property=DropInPaths",
        ]
    )
    result = core.run(
        argv,
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["systemd_query"],
    )
    if result.returncode != 0:
        core.fail(
            "Safety-Observer-Unit konnte nach daemon-reload nicht gelesen werden",
            phase="observer-unit-readback",
            details={
                "returncode": result.returncode,
                "stderr": result.stderr.strip(),
            },
        )
    values: dict[str, list[str]] = {}
    fragment = ""
    drop_ins: list[str] | None = None
    after: list[str] | None = None
    exec_start: str | None = None
    effective: dict[str, str] = {}
    effective_sets: dict[str, set[str]] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        if key == "FragmentPath":
            fragment = value
        elif key == "DropInPaths":
            drop_ins = value.split()
        elif key == "After":
            after = value.split()
        elif key == "ExecStart":
            exec_start = value
        elif key in OBSERVER_EFFECTIVE_RELATIONS:
            values[key] = value.split()
        elif key in OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES:
            effective[key] = value
        elif key in OBSERVER_EXPECTED_EFFECTIVE_SETS:
            try:
                effective_sets[key] = set(shlex.split(value))
            except ValueError as exc:
                core.fail(
                    "Effektive Safety-Observer-Set-Eigenschaft ist nicht lesbar",
                    phase="observer-unit-readback",
                    details={"property": key, "error_type": type(exc).__name__},
                )
    missing_properties = sorted(OBSERVER_EFFECTIVE_RELATIONS.difference(values))
    missing_properties.extend(
        sorted(set(OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES).difference(effective))
    )
    missing_properties.extend(
        sorted(set(OBSERVER_EXPECTED_EFFECTIVE_SETS).difference(effective_sets))
    )
    if after is None:
        missing_properties.append("After")
    if exec_start is None:
        missing_properties.append("ExecStart")
    if drop_ins is None:
        missing_properties.append("DropInPaths")
    if missing_properties:
        core.fail(
            "Safety-Observer-Relationen konnten nicht vollständig gelesen werden",
            phase="observer-unit-readback",
            details={"missing_properties": missing_properties},
        )
    if Path(fragment) != target:
        core.fail(
            "systemd verwendet nicht die kanonische Safety-Observer-Unit",
            phase="observer-unit-readback",
            details={"fragment_path": fragment},
        )
    if drop_ins:
        core.fail(
            "Safety-Observer-Drop-ins sind für den Order-only-Vertrag nicht zulässig",
            phase="observer-unit-readback",
            details={"drop_in_count": len(drop_ins)},
        )
    if not set(OBSERVER_EXPECTED_AFTER).issubset(after or []):
        core.fail(
            "Effektives Safety-Observer After enthält nicht beide Runtime-Dienste",
            phase="observer-unit-readback",
        )
    exec_path, exec_argv = _parse_effective_exec_start(exec_start or "")
    expected_argv = [
        "/usr/bin/python3",
        str(core.HOME / ".local/libexec/grabowski-safety-observer.py"),
        "collect",
    ]
    if exec_path != expected_argv[0] or exec_argv != expected_argv:
        core.fail(
            "Effektiver Safety-Observer ExecStart weicht vom kanonischen Einstieg ab",
            phase="observer-unit-readback",
        )
    for key, expected_value in OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES.items():
        if effective.get(key) != expected_value:
            core.fail(
                "Effektive Safety-Observer-Ausführungsgrenzen oder Härtung weichen ab",
                phase="observer-unit-readback",
                details={"property": key},
            )
    for key, expected_values in OBSERVER_EXPECTED_EFFECTIVE_SETS.items():
        if effective_sets.get(key) != expected_values:
            core.fail(
                "Effektive Safety-Observer-Pfad- oder Adressgrenzen weichen ab",
                phase="observer-unit-readback",
                details={"property": key},
            )
    runtime_units = {OPERATOR_SERVICE, TUNNEL_SERVICE}
    for key, units in values.items():
        if runtime_units.intersection(units):
            core.fail(
                "Safety-Observer aktiviert oder koppelt weiterhin Runtime-Dienste",
                phase="observer-unit-readback",
                details={"directive": key},
            )
    return values

@dataclass(frozen=True)
class _ObserverDirectoryEdge:
    parent_fd: int
    name: str
    child_fd: int


def _require_parent_mapping(
    parent: Path,
    directory_fd: int,
    edges: list[_ObserverDirectoryEdge] | None = None,
) -> os.stat_result:
    opened = os.fstat(directory_fd)
    for edge in edges or []:
        child = os.fstat(edge.child_fd)
        try:
            linked = os.stat(
                edge.name,
                dir_fd=edge.parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            core.fail(
                "Safety-Observer-Unit-Verzeichnis driftete; Verzeichniskette driftete während der Installation",
                phase="observer-unit-parent-drift",
                details={"component": edge.name, "error_type": type(exc).__name__},
            )
        if (
            not statmod.S_ISDIR(child.st_mode)
            or not statmod.S_ISDIR(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != (child.st_dev, child.st_ino)
        ):
            core.fail(
                "Safety-Observer-Unit-Verzeichnis driftete; Verzeichniskette driftete während der Installation",
                phase="observer-unit-parent-drift",
                details={"component": edge.name},
            )
    try:
        mapped = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        core.fail(
            "Safety-Observer-Unit-Verzeichnis driftete während der Installation",
            phase="observer-unit-parent-drift",
            details={"error_type": type(exc).__name__},
        )
    if (
        not statmod.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.getuid()
        or mapped.st_dev != opened.st_dev
        or mapped.st_ino != opened.st_ino
    ):
        core.fail(
            "Safety-Observer-Unit-Verzeichnis driftete während der Installation",
            phase="observer-unit-parent-drift",
        )
    return opened


def _open_observer_unit_directory(
    parent: Path,
) -> tuple[int, list[int], list[_ObserverDirectoryEdge]]:
    if not parent.is_absolute():
        core.fail(
            "Safety-Observer-Unit-Verzeichnis muss absolut sein",
            phase="observer-unit-parent",
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    edges: list[_ObserverDirectoryEdge] = []
    try:
        current_fd = os.open("/", flags)
        descriptors.append(current_fd)
        for component in parent.parts[1:]:
            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                try:
                    child_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError as exc:
                    core.fail(
                        "Safety-Observer-Unit-Verzeichniskomponente konnte nicht sicher geöffnet werden",
                        phase="observer-unit-parent",
                        details={"component": component, "error_type": type(exc).__name__},
                    )
            except OSError as exc:
                core.fail(
                    "Safety-Observer-Unit-Verzeichniskomponente konnte nicht sicher geöffnet werden",
                    phase="observer-unit-parent",
                    details={"component": component, "error_type": type(exc).__name__},
                )
            child_info = os.fstat(child_fd)
            if not statmod.S_ISDIR(child_info.st_mode):
                os.close(child_fd)
                core.fail(
                    "Safety-Observer-Unit-Verzeichniskomponente ist kein Verzeichnis",
                    phase="observer-unit-parent",
                    details={"component": component},
                )
            descriptors.append(child_fd)
            edges.append(_ObserverDirectoryEdge(current_fd, component, child_fd))
            current_fd = child_fd
        _require_parent_mapping(parent, current_fd, edges)
        return current_fd, descriptors, edges
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise

def _require_owned_regular(info: os.stat_result, message: str) -> None:
    if (
        not statmod.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
    ):
        core.fail(message, phase="observer-unit-target")


def _read_observer_unit_at(
    directory_fd: int,
    name: str,
) -> tuple[bytes | None, os.stat_result | None]:
    try:
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None, None
    _require_owned_regular(
        linked,
        "Safety-Observer-Unit ist keine eindeutige benutzereigene Datei",
    )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        core.fail(
            "Safety-Observer-Unit konnte nicht sicher geöffnet werden",
            phase="observer-unit-target",
            details={"error_type": type(exc).__name__},
        )
    try:
        opened = os.fstat(descriptor)
        _require_owned_regular(
            opened,
            "Safety-Observer-Unit ist keine eindeutige benutzereigene Datei",
        )
        if (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino):
            core.fail(
                "Safety-Observer-Unit driftete während des Öffnens",
                phase="observer-unit-target-drift",
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        verified = os.fstat(descriptor)
        try:
            remapped = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            core.fail(
                "Safety-Observer-Unit driftete während des Lesens",
                phase="observer-unit-target-drift",
            )
        if (
            (verified.st_dev, verified.st_ino) != (opened.st_dev, opened.st_ino)
            or (remapped.st_dev, remapped.st_ino) != (opened.st_dev, opened.st_ino)
            or verified.st_nlink != 1
        ):
            core.fail(
                "Safety-Observer-Unit driftete während des Lesens",
                phase="observer-unit-target-drift",
            )
        return b"".join(chunks), verified
    finally:
        os.close(descriptor)


RENAME_NOREPLACE = 1 << 0
RENAME_EXCHANGE = 1 << 1


def _load_renameat2():
    library_name = ctypes.util.find_library("c")
    if library_name is None:
        return None
    try:
        libc = ctypes.CDLL(library_name, use_errno=True)
        function = libc.renameat2
    except (OSError, AttributeError):
        return None
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    return function


_RENAMEAT2 = _load_renameat2()


def _renameat2(
    old_dir_fd: int,
    old_name: str,
    new_dir_fd: int,
    new_name: str,
    flags: int,
) -> None:
    if _RENAMEAT2 is None:
        core.fail(
            "renameat2 ist für die atomare Safety-Observer-Veröffentlichung "
            "nicht verfügbar",
            phase="observer-unit-renameat2-unavailable",
        )
    ctypes.set_errno(0)
    result = _RENAMEAT2(
        ctypes.c_int(old_dir_fd),
        os.fsencode(old_name),
        ctypes.c_int(new_dir_fd),
        os.fsencode(new_name),
        ctypes.c_uint(flags),
    )
    if result == 0:
        return
    captured_errno = ctypes.get_errno()
    if captured_errno == errno.ENOSYS:
        core.fail(
            "renameat2 wird vom Kernel nicht unterstützt",
            phase="observer-unit-renameat2-unavailable",
            details={"errno": captured_errno},
        )
    raise OSError(captured_errno, os.strerror(captured_errno), new_name)


def _same_observer_entry(
    before: os.stat_result | None,
    after: os.stat_result | None,
) -> bool:
    if before is None or after is None:
        return before is after
    # renameat2 legitimately changes ctime. All identity-, ownership-, mode-
    # and content-relevant metadata remains stable and is checked explicitly.
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
    )


def _atomic_publish_observer_unit(
    directory_fd: int,
    incoming_name: str,
    target_name: str,
    target_info: os.stat_result | None,
    target_content: bytes | None,
    incoming_info: os.stat_result,
    expected: bytes,
) -> dict[str, str | None]:
    if target_info is None:
        try:
            _renameat2(
                directory_fd,
                incoming_name,
                directory_fd,
                target_name,
                RENAME_NOREPLACE,
            )
        except OSError as exc:
            # The unique incoming artifact is deliberately retained. Deleting
            # it by name here would reintroduce a cleanup TOCTOU race.
            core.fail(
                "Safety-Observer-Unit-Ziel wurde gleichzeitig angelegt",
                phase="observer-unit-target-drift",
                details={
                    "error_type": type(exc).__name__,
                    "errno": exc.errno,
                    "retained_incoming_name": incoming_name,
                },
            )
        os.fsync(directory_fd)
        published, published_info = _read_observer_unit_at(
            directory_fd,
            target_name,
        )
        if (
            published != expected
            or not _same_observer_entry(incoming_info, published_info)
        ):
            core.fail(
                "Safety-Observer-Unit-Ziel driftete nach atomarer Veröffentlichung",
                phase="observer-unit-target-drift",
            )
        return {"retained_name": None, "retained_sha256": None}

    if target_content is None:
        core.fail(
            "Safety-Observer-Unit-Zielinhalt fehlt vor atomarem Austausch",
            phase="observer-unit-target-drift",
        )

    try:
        _renameat2(
            directory_fd,
            incoming_name,
            directory_fd,
            target_name,
            RENAME_EXCHANGE,
        )
    except OSError as exc:
        core.fail(
            "Safety-Observer-Unit-Austausch schlug fehl",
            phase="observer-unit-target-drift",
            details={
                "error_type": type(exc).__name__,
                "errno": exc.errno,
                "retained_incoming_name": incoming_name,
            },
        )

    # Never exchange back after drift. A second actor could replace the target
    # between detection and rollback, causing the rollback to move or delete a
    # third object. Instead, preserve the displaced entry under a hidden,
    # unique name and verify both resulting mappings without further mutation.
    retained_name = (
        f".{target_name}.retained-{secrets.token_hex(12)}"
    )
    try:
        _renameat2(
            directory_fd,
            incoming_name,
            directory_fd,
            retained_name,
            RENAME_NOREPLACE,
        )
    except OSError as exc:
        core.fail(
            "Verdrängte Safety-Observer-Unit konnte nicht sicher bewahrt werden",
            phase="observer-unit-retention",
            details={
                "error_type": type(exc).__name__,
                "errno": exc.errno,
                "retained_incoming_name": incoming_name,
                "retained_candidate_name": retained_name,
            },
        )
    os.fsync(directory_fd)

    published, published_info = _read_observer_unit_at(
        directory_fd,
        target_name,
    )
    retained, retained_info = _read_observer_unit_at(
        directory_fd,
        retained_name,
    )
    if (
        published != expected
        or not _same_observer_entry(incoming_info, published_info)
    ):
        core.fail(
            "Safety-Observer-Unit-Ziel driftete während der Retention",
            phase="observer-unit-target-drift",
            details={"retained_name": retained_name},
        )
    if (
        retained != target_content
        or not _same_observer_entry(target_info, retained_info)
    ):
        core.fail(
            "Verdrängte Safety-Observer-Unit driftete während der Retention",
            phase="observer-unit-target-drift",
            details={"retained_name": retained_name},
        )
    return {
        "retained_name": retained_name,
        "retained_sha256": hashlib.sha256(target_content).hexdigest(),
    }


def _verify_safety_observer_executes(unit_name: str) -> dict[str, str]:
    start_result = core.run(
        ["systemctl", "--user", "start", unit_name],
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["service_start"],
    )
    if start_result.returncode != 0:
        core.fail(
            "Safety-Observer-Unit konnte nicht erfolgreich ausgeführt werden",
            phase="observer-unit-execution",
            details={
                "returncode": start_result.returncode,
                "stderr": start_result.stderr.strip(),
            },
        )
    status_result = core.run(
        [
            "systemctl",
            "--user",
            "show",
            unit_name,
            "--property=Result",
            "--property=ActiveState",
            "--property=SubState",
        ],
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["systemd_query"],
    )
    if status_result.returncode != 0:
        core.fail(
            "Safety-Observer-Ausführungszustand konnte nicht gelesen werden",
            phase="observer-unit-execution-readback",
            details={
                "returncode": status_result.returncode,
                "stderr": status_result.stderr.strip(),
            },
        )
    values: dict[str, str] = {}
    for line in status_result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    expected = {
        "Result": "success",
        "ActiveState": "inactive",
        "SubState": "dead",
    }
    if values != expected:
        core.fail(
            "Safety-Observer-Ausführung endete nicht kanonisch erfolgreich",
            phase="observer-unit-execution-readback",
            details={"properties": values},
        )
    return values


def _validate_tunnel_operator_dependency_bytes(data: bytes) -> bytes:
    if not data.endswith(b"\n"):
        core.fail(
            "Tunnel-Operator-Drop-in benötigt einen abschließenden Zeilenumbruch",
            phase="watchdog-host-asset-dependency-source",
        )
    for byte in data:
        if byte in _OBSERVER_UNIT_ALLOWED_CONTROL_BYTES:
            continue
        if byte < 0x20 or byte == 0x7F:
            core.fail(
                "Tunnel-Operator-Drop-in enthält ein nicht erlaubtes Steuerzeichen",
                phase="watchdog-host-asset-dependency-source",
                details={"byte": f"0x{byte:02x}"},
            )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        core.fail(
            "Tunnel-Operator-Drop-in ist kein gültiges UTF-8",
            phase="watchdog-host-asset-dependency-source",
            details={"error_type": type(exc).__name__},
        )
    directives: dict[tuple[str, str], str] = {}
    section: str | None = None
    sections_seen: set[str] = set()
    for raw_line in text.split("\n"):
        line = raw_line.strip(_OBSERVER_UNIT_HORIZONTAL_WHITESPACE)
        if line.endswith("\\"):
            core.fail(
                "Tunnel-Operator-Drop-in darf keine Zeilenfortsetzungen enthalten",
                phase="watchdog-host-asset-dependency-source",
            )
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            if line != "[Unit]" or "Unit" in sections_seen:
                core.fail(
                    "Tunnel-Operator-Drop-in enthält einen unerwarteten Abschnitt",
                    phase="watchdog-host-asset-dependency-source",
                )
            section = "Unit"
            sections_seen.add(section)
            continue
        key, separator, value = line.partition("=")
        key = key.strip(_OBSERVER_UNIT_HORIZONTAL_WHITESPACE)
        value = value.strip(_OBSERVER_UNIT_HORIZONTAL_WHITESPACE)
        if section != "Unit" or not separator or not key:
            core.fail(
                "Tunnel-Operator-Drop-in enthält eine ungültige aktive Direktive",
                phase="watchdog-host-asset-dependency-source",
            )
        pair = (section, key)
        expected_value = TUNNEL_OPERATOR_DEPENDENCY_EXPECTED_DIRECTIVES[section].get(key)
        if pair in directives or expected_value is None or value != expected_value:
            core.fail(
                "Tunnel-Operator-Drop-in weicht vom erlaubten Abhängigkeitsvertrag ab",
                phase="watchdog-host-asset-dependency-source",
                details={"directive": key},
            )
        directives[pair] = value
    expected = {
        (section_name, key): value
        for section_name, section_directives in TUNNEL_OPERATOR_DEPENDENCY_EXPECTED_DIRECTIVES.items()
        for key, value in section_directives.items()
    }
    if sections_seen != {"Unit"} or directives != expected:
        core.fail(
            "Tunnel-Operator-Drop-in enthält nicht exakt den erwarteten Abhängigkeitsvertrag",
            phase="watchdog-host-asset-dependency-source",
        )
    return data


def _watchdog_host_asset_bytes(
    repo: Path,
    repo_head: str,
    asset: WatchdogHostAsset,
) -> bytes:
    try:
        data = core.git_show(repo, repo_head, asset.source)
    except Exception as exc:
        core.fail(
            "Watchdog-Host-Asset konnte nicht aus dem gebundenen Git-Stand gelesen werden",
            phase="watchdog-host-asset-source",
            details={
                "source": asset.source.as_posix(),
                "repo_head": repo_head,
                "error_type": type(exc).__name__,
            },
        )
    if not data or len(data) > WATCHDOG_HOST_ASSET_MAX_BYTES:
        core.fail(
            "Watchdog-Host-Asset hat eine unzulässige Größe",
            phase="watchdog-host-asset-source",
            details={"source": asset.source.as_posix(), "bytes": len(data)},
        )
    if asset.source == TUNNEL_OPERATOR_DEPENDENCY_RELATIVE:
        return _validate_tunnel_operator_dependency_bytes(data)
    return data


def _read_watchdog_host_asset(
    asset: WatchdogHostAsset,
) -> WatchdogHostAssetPreimage:
    target = asset.target
    try:
        linked = target.lstat()
    except FileNotFoundError:
        return WatchdogHostAssetPreimage(asset, False, None, None, None)
    if (
        not statmod.S_ISREG(linked.st_mode)
        or linked.st_uid != os.getuid()
        or linked.st_nlink != 1
        or linked.st_size > WATCHDOG_HOST_ASSET_MAX_BYTES
    ):
        core.fail(
            "Watchdog-Host-Asset-Ziel ist keine eindeutige benutzereigene reguläre Datei",
            phase="watchdog-host-asset-target",
            details={"target": str(target)},
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        core.fail(
            "Watchdog-Host-Asset-Ziel konnte nicht sicher geöffnet werden",
            phase="watchdog-host-asset-target",
            details={"target": str(target), "error_type": type(exc).__name__},
        )
    try:
        opened = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            core.fail(
                "Watchdog-Host-Asset-Ziel driftete während des sicheren Öffnens",
                phase="watchdog-host-asset-target-drift",
                details={"target": str(target)},
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, WATCHDOG_HOST_ASSET_MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > WATCHDOG_HOST_ASSET_MAX_BYTES:
                core.fail(
                    "Watchdog-Host-Asset-Ziel überschreitet die Größenbegrenzung",
                    phase="watchdog-host-asset-target",
                    details={"target": str(target)},
                )
        content = b"".join(chunks)
    finally:
        os.close(descriptor)
    return WatchdogHostAssetPreimage(
        asset=asset,
        existed=True,
        content=content,
        mode=statmod.S_IMODE(linked.st_mode),
        identity=(linked.st_dev, linked.st_ino),
    )


def _watchdog_target_matches_preimage(
    directory_fd: int,
    name: str,
    preimage: WatchdogHostAssetPreimage,
) -> bool:
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return not preimage.existed
    if not preimage.existed or preimage.identity is None:
        return False
    return (
        statmod.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and info.st_nlink == 1
        and (info.st_dev, info.st_ino) == preimage.identity
    )


def _atomic_write_watchdog_host_asset(
    asset: WatchdogHostAsset,
    data: bytes,
    mode: int,
    preimage: WatchdogHostAssetPreimage,
) -> None:
    if not data or len(data) > WATCHDOG_HOST_ASSET_MAX_BYTES:
        core.fail("Ungültiger Watchdog-Host-Asset-Payload", phase="watchdog-host-asset-write")
    directory_fd, directory_fds, directory_edges = _open_observer_unit_directory(
        asset.target.parent
    )
    incoming_name = f".{asset.target.name}.incoming-{secrets.token_hex(12)}"
    descriptor = -1
    published = False
    preserve_incoming = False
    try:
        _require_parent_mapping(asset.target.parent, directory_fd, directory_edges)
        if not _watchdog_target_matches_preimage(directory_fd, asset.target.name, preimage):
            core.fail(
                "Watchdog-Host-Asset-Ziel driftete vor atomarer Veröffentlichung",
                phase="watchdog-host-asset-target-drift",
                details={"target": str(asset.target)},
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(incoming_name, flags, 0o600, dir_fd=directory_fd)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                core.fail(
                    "Watchdog-Host-Asset konnte nicht vollständig geschrieben werden",
                    phase="watchdog-host-asset-write",
                )
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        incoming = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(incoming.st_mode)
            or incoming.st_uid != os.getuid()
            or incoming.st_nlink != 1
            or statmod.S_IMODE(incoming.st_mode) != mode
        ):
            core.fail(
                "Temporäres Watchdog-Host-Asset ist nicht sicher",
                phase="watchdog-host-asset-write",
            )
        _require_parent_mapping(asset.target.parent, directory_fd, directory_edges)
        if not _watchdog_target_matches_preimage(directory_fd, asset.target.name, preimage):
            core.fail(
                "Watchdog-Host-Asset-Ziel driftete unmittelbar vor Veröffentlichung",
                phase="watchdog-host-asset-target-drift",
                details={"target": str(asset.target)},
            )
        if preimage.existed:
            _renameat2(
                directory_fd,
                incoming_name,
                directory_fd,
                asset.target.name,
                RENAME_EXCHANGE,
            )
            preserve_incoming = True
            try:
                published_info = os.stat(
                    asset.target.name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                displaced_info = os.stat(
                    incoming_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                core.fail(
                    "Watchdog-Host-Asset-Austausch konnte nicht sicher verifiziert werden",
                    phase="watchdog-host-asset-target-drift",
                    details={
                        "target": str(asset.target),
                        "retained_incoming_name": incoming_name,
                        "error_type": type(exc).__name__,
                    },
                )
            if (
                (published_info.st_dev, published_info.st_ino)
                != (incoming.st_dev, incoming.st_ino)
                or preimage.identity is None
                or (displaced_info.st_dev, displaced_info.st_ino) != preimage.identity
            ):
                core.fail(
                    "Watchdog-Host-Asset-Ziel driftete während des atomaren Austauschs; verdrängtes Objekt wurde erhalten",
                    phase="watchdog-host-asset-target-drift",
                    details={
                        "target": str(asset.target),
                        "retained_incoming_name": incoming_name,
                    },
                )
            os.unlink(incoming_name, dir_fd=directory_fd)
            preserve_incoming = False
        else:
            try:
                _renameat2(
                    directory_fd,
                    incoming_name,
                    directory_fd,
                    asset.target.name,
                    RENAME_NOREPLACE,
                )
            except OSError as exc:
                core.fail(
                    "Watchdog-Host-Asset-Ziel wurde gleichzeitig angelegt",
                    phase="watchdog-host-asset-target-drift",
                    details={
                        "target": str(asset.target),
                        "error_type": type(exc).__name__,
                        "errno": exc.errno,
                    },
                )
        published = True
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published and not preserve_incoming:
            try:
                os.unlink(incoming_name, dir_fd=directory_fd)
            except OSError:
                pass
        for opened_fd in reversed(directory_fds):
            try:
                os.close(opened_fd)
            except OSError:
                pass
    installed = _read_watchdog_host_asset(asset)
    if (
        not installed.existed
        or installed.content != data
        or installed.mode != mode
    ):
        core.fail(
            "Watchdog-Host-Asset stimmt nach Installation nicht exakt",
            phase="watchdog-host-asset-readback",
            details={"target": str(asset.target)},
        )


def _remove_watchdog_host_asset(
    preimage: WatchdogHostAssetPreimage,
) -> None:
    asset = preimage.asset
    current = _read_watchdog_host_asset(asset)
    if not current.existed or current.identity is None:
        core.fail(
            "Watchdog-Host-Asset fehlt vor Rücksicherung",
            phase="watchdog-host-asset-rollback",
            details={"target": str(asset.target)},
        )
    directory_fd, directory_fds, directory_edges = _open_observer_unit_directory(
        asset.target.parent
    )
    try:
        _require_parent_mapping(asset.target.parent, directory_fd, directory_edges)
        if not _watchdog_target_matches_preimage(directory_fd, asset.target.name, current):
            core.fail(
                "Watchdog-Host-Asset driftete vor Entfernung",
                phase="watchdog-host-asset-rollback",
                details={"target": str(asset.target)},
            )
        os.unlink(asset.target.name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        for opened_fd in reversed(directory_fds):
            try:
                os.close(opened_fd)
            except OSError:
                pass


def _systemd_daemon_reload() -> None:
    result = core.run(
        ["systemctl", "--user", "daemon-reload"],
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["service_start"],
    )
    if result.returncode != 0:
        core.fail(
            "systemd daemon-reload für Watchdog-Host-Assets fehlgeschlagen",
            phase="watchdog-host-asset-daemon-reload",
            details={"returncode": result.returncode},
        )


def verify_watchdog_systemd_fragments(
    assets: tuple[WatchdogHostAsset, ...] = WATCHDOG_HOST_ASSETS,
) -> dict[str, str]:
    fragments: dict[str, str] = {}
    for asset in assets:
        if asset.unit is None:
            continue
        result = core.run(
            [
                "systemctl",
                "--user",
                "show",
                asset.unit,
                "--property=FragmentPath",
                "--value",
            ],
            check=False,
            capture=True,
            timeout=core.TIMEOUTS["systemd_query"],
        )
        fragment = result.stdout.strip() if result.returncode == 0 else ""
        if not fragment or Path(fragment).resolve() != asset.target.resolve():
            core.fail(
                "systemd verwendet nicht das kanonisch projizierte Watchdog-Asset",
                phase="watchdog-host-asset-systemd-readback",
                details={
                    "unit": asset.unit,
                    "expected": str(asset.target),
                    "observed": fragment,
                    "returncode": result.returncode,
                },
            )
        fragments[asset.unit] = fragment
    return fragments


def _tunnel_operator_dependency_asset(
    assets: tuple[WatchdogHostAsset, ...] = WATCHDOG_HOST_ASSETS,
) -> WatchdogHostAsset | None:
    matches = tuple(
        asset for asset in assets if asset.source == TUNNEL_OPERATOR_DEPENDENCY_RELATIVE
    )
    if len(matches) > 1:
        core.fail(
            "Tunnel-Operator-Drop-in ist im Host-Asset-Satz nicht eindeutig",
            phase="watchdog-host-asset-contract",
        )
    return matches[0] if matches else None


def observe_tunnel_operator_dependency(
    assets: tuple[WatchdogHostAsset, ...] = WATCHDOG_HOST_ASSETS,
) -> dict[str, tuple[str, ...]]:
    if _tunnel_operator_dependency_asset(assets) is None:
        return {}
    properties = TUNNEL_OPERATOR_DEPENDENCY_EFFECTIVE_PROPERTIES
    argv = ["systemctl", "--user", "show", TUNNEL_SERVICE]
    argv.extend(f"--property={name}" for name in properties)
    result = core.run(
        argv,
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["systemd_query"],
    )
    observed: dict[str, tuple[str, ...]] = {}
    duplicates: list[str] = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in properties:
                continue
            if key in observed:
                duplicates.append(key)
                continue
            observed[key] = tuple(sorted(value.split()))
    missing = [name for name in properties if name not in observed]
    if result.returncode != 0 or duplicates or missing:
        details: dict[str, Any] = {
            "returncode": result.returncode,
            "missing_properties": missing,
            "duplicate_properties": sorted(set(duplicates)),
            "observed": observed,
        }
        if result.stderr.strip():
            details["stderr"] = result.stderr.strip()
        if result.stdout.strip():
            details["stdout"] = result.stdout.strip()
        core.fail(
            "Tunnel-Operator-Abhängigkeit konnte nicht eindeutig aus systemd gelesen werden",
            phase="watchdog-host-asset-dependency-readback",
            details=details,
        )
    return observed


def verify_tunnel_operator_dependency(
    assets: tuple[WatchdogHostAsset, ...] = WATCHDOG_HOST_ASSETS,
) -> dict[str, tuple[str, ...]]:
    asset = _tunnel_operator_dependency_asset(assets)
    if asset is None:
        return {}
    observed = observe_tunnel_operator_dependency(assets)
    violations: list[str] = []
    if observed["LoadState"] != ("loaded",):
        violations.append("LoadState")
    for name in ("Wants", "After"):
        if TRANSPORT_INGRESS_SERVICE not in observed[name]:
            violations.append(name)
    if observed["PartOf"] != (TRANSPORT_INGRESS_SERVICE,):
        violations.append("PartOf")
    if TRANSPORT_INGRESS_SERVICE in observed["BindsTo"]:
        violations.append("BindsTo")
    expected_dropin = str(asset.target.resolve())
    loaded_dropins = {str(Path(path).resolve()) for path in observed["DropInPaths"]}
    if expected_dropin not in loaded_dropins:
        violations.append("DropInPaths")
    if violations:
        core.fail(
            "Tunnel-Operator-Abhängigkeit ist nicht exakt wirksam",
            phase="watchdog-host-asset-dependency-readback",
            details={
                "violations": violations,
                "expected_dropin": expected_dropin,
                "observed": observed,
            },
        )
    return observed


def verify_tunnel_operator_dependency_preimage(
    expected: dict[str, tuple[str, ...]],
    assets: tuple[WatchdogHostAsset, ...],
) -> dict[str, tuple[str, ...]]:
    observed = observe_tunnel_operator_dependency(assets)
    if observed != expected:
        core.fail(
            "Tunnel-Operator-Abhängigkeit wurde nach Rücksicherung nicht exakt wiederhergestellt",
            phase="watchdog-host-asset-dependency-rollback-readback",
            details={"expected": expected, "observed": observed},
        )
    return observed


def _watchdog_asset_set_sha256(
    assets: tuple[WatchdogHostAsset, ...],
    expected: dict[str, bytes],
) -> str:
    payload = [
        {
            "source": asset.source.as_posix(),
            "target": str(asset.target),
            "mode": oct(asset.mode),
            "unit": asset.unit,
            "reloads_systemd": asset.reloads_systemd,
            "sha256": hashlib.sha256(expected[str(asset.target)]).hexdigest(),
        }
        for asset in assets
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def restore_watchdog_host_assets(
    projection: WatchdogHostAssetProjection,
) -> None:
    changed = set(projection.changed_targets)
    if not changed:
        return
    systemd_reload_required = False
    for preimage in reversed(projection.preimages):
        target_key = str(preimage.asset.target)
        if target_key not in changed:
            continue
        expected = projection.expected[target_key]
        current = _read_watchdog_host_asset(preimage.asset)
        if (
            not current.existed
            or current.content != expected
            or current.mode != preimage.asset.mode
        ):
            core.fail(
                "Watchdog-Host-Asset driftete; Rücksicherung verweigert",
                phase="watchdog-host-asset-rollback",
                details={"target": target_key},
            )
        if preimage.existed:
            assert preimage.content is not None and preimage.mode is not None
            _atomic_write_watchdog_host_asset(
                preimage.asset,
                preimage.content,
                preimage.mode,
                current,
            )
        else:
            _remove_watchdog_host_asset(current)
        systemd_reload_required = systemd_reload_required or (
            preimage.asset.unit is not None or preimage.asset.reloads_systemd
        )
    if systemd_reload_required:
        _systemd_daemon_reload()
        restored_assets = tuple(
            preimage.asset
            for preimage in projection.preimages
            if preimage.existed
        )
        verify_watchdog_systemd_fragments(restored_assets)
        if projection.tunnel_operator_dependency_preimage is not None:
            verify_tunnel_operator_dependency_preimage(
                projection.tunnel_operator_dependency_preimage,
                tuple(preimage.asset for preimage in projection.preimages),
            )


def install_watchdog_host_assets(
    repo: Path,
    snapshot: core.Snapshot,
    *,
    assets: tuple[WatchdogHostAsset, ...] = WATCHDOG_HOST_ASSETS,
) -> WatchdogHostAssetProjection:
    if not assets:
        core.fail("Watchdog-Host-Asset-Satz darf nicht leer sein")
    expected: dict[str, bytes] = {}
    preimages: list[WatchdogHostAssetPreimage] = []
    seen_targets: set[Path] = set()
    for asset in assets:
        if not asset.target.is_absolute() or asset.target in seen_targets:
            core.fail(
                "Watchdog-Host-Asset-Ziele müssen absolut und eindeutig sein",
                phase="watchdog-host-asset-contract",
            )
        if asset.mode not in {0o600, 0o700}:
            core.fail(
                "Watchdog-Host-Asset verwendet einen unzulässigen Dateimodus",
                phase="watchdog-host-asset-contract",
            )
        seen_targets.add(asset.target)
        expected[str(asset.target)] = _watchdog_host_asset_bytes(
            repo, snapshot.repo_head, asset
        )
        preimages.append(_read_watchdog_host_asset(asset))
    dependency_asset = _tunnel_operator_dependency_asset(assets)
    dependency_preimage = (
        observe_tunnel_operator_dependency(assets)
        if dependency_asset is not None
        else None
    )
    changed: list[str] = []
    projection = WatchdogHostAssetProjection(
        repo_head=snapshot.repo_head,
        preimages=tuple(preimages),
        expected=expected,
        changed_targets=(),
        asset_set_sha256=_watchdog_asset_set_sha256(assets, expected),
        tunnel_operator_dependency_preimage=dependency_preimage,
    )
    try:
        for preimage in preimages:
            asset = preimage.asset
            data = expected[str(asset.target)]
            if (
                preimage.existed
                and preimage.content == data
                and preimage.mode == asset.mode
            ):
                continue
            try:
                _atomic_write_watchdog_host_asset(asset, data, asset.mode, preimage)
            except Exception as write_error:
                try:
                    current = _read_watchdog_host_asset(asset)
                except Exception:
                    # A failed state interrogation must never hide the original
                    # publication failure. Conservatively include the target in
                    # rollback scope because publication may already have happened.
                    changed.append(str(asset.target))
                else:
                    if (
                        current.existed
                        and current.content == data
                        and current.mode == asset.mode
                    ):
                        changed.append(str(asset.target))
                raise write_error
            changed.append(str(asset.target))
        projection = WatchdogHostAssetProjection(
            repo_head=snapshot.repo_head,
            preimages=tuple(preimages),
            expected=expected,
            changed_targets=tuple(changed),
            asset_set_sha256=_watchdog_asset_set_sha256(assets, expected),
            tunnel_operator_dependency_preimage=dependency_preimage,
        )
        changed_set = set(changed)
        systemd_reload_required = any(
            (preimage.asset.unit is not None or preimage.asset.reloads_systemd)
            and str(preimage.asset.target) in changed_set
            for preimage in preimages
        )
        if systemd_reload_required:
            _systemd_daemon_reload()
        verify_watchdog_systemd_fragments(assets)
        try:
            verify_tunnel_operator_dependency(assets)
        except core.DeployError:
            if (
                systemd_reload_required
                or not any(asset.reloads_systemd for asset in assets)
            ):
                raise
            _systemd_daemon_reload()
            verify_watchdog_systemd_fragments(assets)
            verify_tunnel_operator_dependency(assets)
        for asset in assets:
            installed = _read_watchdog_host_asset(asset)
            if (
                not installed.existed
                or installed.content != expected[str(asset.target)]
                or installed.mode != asset.mode
            ):
                core.fail(
                    "Watchdog-Host-Asset driftete während des finalen Readbacks",
                    phase="watchdog-host-asset-readback",
                    details={"target": str(asset.target)},
                )
        return projection
    except Exception as original:
        if changed:
            partial = WatchdogHostAssetProjection(
                repo_head=snapshot.repo_head,
                preimages=tuple(preimages),
                expected=expected,
                changed_targets=tuple(changed),
                asset_set_sha256=_watchdog_asset_set_sha256(assets, expected),
                tunnel_operator_dependency_preimage=dependency_preimage,
            )
            try:
                restore_watchdog_host_assets(partial)
            except Exception as rollback_error:
                core.fail(
                    "Watchdog-Host-Asset-Installation und Rücksicherung schlugen fehl",
                    phase="watchdog-host-asset-rollback",
                    details={
                        "install_error": str(original),
                        "rollback_error": str(rollback_error),
                    },
                )
        raise


def install_safety_observer_unit(
    repo: Path,
    snapshot: core.Snapshot,
    *,
    target: Path = SAFETY_OBSERVER_UNIT_PATH,
) -> dict[str, Any]:
    expected = _observer_unit_bytes(repo, snapshot.repo_head)
    parent = target.parent
    directory_fd, directory_fds, directory_edges = _open_observer_unit_directory(parent)
    try:
        _require_parent_mapping(parent, directory_fd, directory_edges)
        current, target_info = _read_observer_unit_at(directory_fd, target.name)
        changed = (
            current != expected
            or target_info is None
            or statmod.S_IMODE(target_info.st_mode) != 0o644
        )
        publication: dict[str, str | None] = {
            "retained_name": None,
            "retained_sha256": None,
        }
        if changed:
            incoming_name = (
                f".{target.name}.incoming-{secrets.token_hex(12)}"
            )
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
            )
            descriptor = os.open(
                incoming_name,
                flags,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                view = memoryview(expected)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        core.fail(
                            "Safety-Observer-Unit konnte nicht vollständig geschrieben werden"
                        )
                    view = view[written:]
                os.fchmod(descriptor, 0o644)
                os.fsync(descriptor)
                incoming_info = os.fstat(descriptor)
                _require_owned_regular(
                    incoming_info,
                    "Temporäre Safety-Observer-Unit ist nicht sicher",
                )
            finally:
                os.close(descriptor)
            _require_parent_mapping(parent, directory_fd, directory_edges)
            publication = _atomic_publish_observer_unit(
                directory_fd,
                incoming_name,
                target.name,
                target_info,
                current,
                incoming_info,
                expected,
            )
        installed, installed_info = _read_observer_unit_at(
            directory_fd,
            target.name,
        )
        if (
            installed != expected
            or installed_info is None
            or statmod.S_IMODE(installed_info.st_mode) != 0o644
        ):
            core.fail("Safety-Observer-Unit stimmt nach Installation nicht exakt")
        _require_parent_mapping(parent, directory_fd, directory_edges)
        reload_result = core.run(
            ["systemctl", "--user", "daemon-reload"],
            check=False,
            capture=True,
            timeout=core.TIMEOUTS["service_start"],
        )
        if reload_result.returncode != 0:
            core.fail(
                "systemd daemon-reload für Safety-Observer fehlgeschlagen",
                phase="observer-unit-daemon-reload",
                details={"returncode": reload_result.returncode},
            )
        relations = _observer_unit_relations(target)
        execution = _verify_safety_observer_executes(target.name)
        final_bytes, final_info = _read_observer_unit_at(
            directory_fd,
            target.name,
        )
        if (
            final_bytes != expected
            or not _same_observer_entry(installed_info, final_info)
            or final_info is None
            or statmod.S_IMODE(final_info.st_mode) != 0o644
        ):
            core.fail(
                "Safety-Observer-Unit driftete während des systemd-Readbacks",
                phase="observer-unit-target-drift",
            )
        _require_parent_mapping(parent, directory_fd, directory_edges)
        retained_name = publication["retained_name"]
        return {
            "changed": changed,
            "path": str(target),
            "repo_head": snapshot.repo_head,
            "sha256": hashlib.sha256(expected).hexdigest(),
            "retained_path": (
                str(parent / retained_name)
                if retained_name is not None
                else None
            ),
            "retained_sha256": publication["retained_sha256"],
            "relations": relations,
            "execution": execution,
        }
    finally:
        for descriptor in reversed(directory_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass


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
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or port not in TUNNEL_TARGET_PORTS or parsed.path.rstrip("/") != "/mcp" or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None):
        core.fail("Tunnelprofil server_urls ist weder der gebundene Legacy-Operator noch der signierte Loopback-Ingress")
    return 1


def _server_url_port(data: Any) -> int | None:
    if not isinstance(data, dict):
        return None
    mcp = data.get("mcp")
    if not isinstance(mcp, dict):
        return None
    values = mcp.get("server_urls")
    if not isinstance(values, list) or len(values) != 1:
        return None
    item = values[0]
    url = item if isinstance(item, str) else item.get("url") if isinstance(item, dict) else None
    if not isinstance(url, str):
        return None
    try:
        return urlsplit(url).port
    except ValueError:
        return None


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
    server_url_port = _server_url_port(data)
    if typed_commands and server_url_count:
        core.fail("Tunnelprofil mischt command- und server_urls-Topologie")
    if typed_commands == 0 and server_url_count == 0:
        core.fail("Tunnelprofil enthält weder command noch server_urls")

    if server_url_count:
        return ProfileTopology(
            "url", server_url_count=server_url_count, server_url_port=server_url_port
        )

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


def _profile_bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _profile_regular_metadata(profile_path: Path) -> os.stat_result:
    linked = profile_path.lstat()
    if (
        statmod.S_ISLNK(linked.st_mode)
        or not statmod.S_ISREG(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or linked.st_nlink != 1
        or statmod.S_IMODE(linked.st_mode) & 0o022
        or linked.st_size > 1_048_576
    ):
        core.fail("Tunnelprofil ist keine sichere eigentümerkontrollierte Datei")
    return linked


def _read_profile_revision(profile_path: Path) -> tuple[bytes, os.stat_result]:
    linked = _profile_regular_metadata(profile_path)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(profile_path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino):
            core.fail("Tunnelprofil driftete während des sicheren Öffnens")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 1_048_576:
                core.fail("Tunnelprofil überschreitet die Größenbegrenzung")
        verified = os.fstat(descriptor)
        remapped = profile_path.lstat()
        if (
            (verified.st_dev, verified.st_ino) != (linked.st_dev, linked.st_ino)
            or (remapped.st_dev, remapped.st_ino) != (linked.st_dev, linked.st_ino)
            or verified.st_size != total
            or verified.st_mtime_ns != linked.st_mtime_ns
        ):
            core.fail("Tunnelprofil driftete während des sicheren Lesens")
        return b"".join(chunks), verified
    finally:
        os.close(descriptor)


def _descriptor_bound_profile_write(
    profile_path: Path,
    value: bytes,
    *,
    mode: int,
    expected_identity: tuple[int, int],
    expected_sha256: str,
) -> None:
    parent_linked = profile_path.parent.lstat()
    if statmod.S_ISLNK(parent_linked.st_mode) or not statmod.S_ISDIR(parent_linked.st_mode):
        core.fail("Tunnelprofil-Verzeichnis ist nicht sicher")
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.open(profile_path.parent, directory_flags)
    descriptor = -1
    try:
        parent_opened = os.fstat(directory_fd)
        if (parent_opened.st_dev, parent_opened.st_ino) != (
            parent_linked.st_dev,
            parent_linked.st_ino,
        ):
            core.fail("Tunnelprofil-Verzeichnis driftete während des Öffnens")
        linked = os.stat(
            profile_path.name, dir_fd=directory_fd, follow_symlinks=False
        )
        if (
            not statmod.S_ISREG(linked.st_mode)
            or linked.st_uid != os.geteuid()
            or linked.st_nlink != 1
            or statmod.S_IMODE(linked.st_mode) & 0o022
            or linked.st_size > 1_048_576
        ):
            core.fail("Tunnelprofil ist vor dem descriptorgebundenen Commit unsicher")
        flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(profile_path.name, flags, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        opened_identity = (opened.st_dev, opened.st_ino)
        if opened_identity != expected_identity or opened_identity != (
            linked.st_dev,
            linked.st_ino,
        ):
            core.fail("Tunnelprofil driftete vor dem descriptorgebundenen Commit")
        current = bytearray()
        offset = 0
        while True:
            chunk = os.pread(descriptor, 65536, offset)
            if not chunk:
                break
            current.extend(chunk)
            offset += len(chunk)
            if len(current) > 1_048_576:
                core.fail("Tunnelprofil überschreitet die Größenbegrenzung")
        before_write = os.stat(
            profile_path.name, dir_fd=directory_fd, follow_symlinks=False
        )
        if (before_write.st_dev, before_write.st_ino) != expected_identity:
            core.fail("Tunnelprofil driftete vor dem descriptorgebundenen Commit")
        if (
            _profile_bytes_sha256(bytes(current)) != expected_sha256
            or statmod.S_IMODE(opened.st_mode) != mode
        ):
            core.fail("Tunnelprofil-Preimage stimmt vor dem Commit nicht überein")
        view = memoryview(value)
        offset = 0
        while view:
            written = os.pwrite(descriptor, view, offset)
            if written <= 0:
                core.fail("Tunnelprofil wurde nicht vollständig geschrieben")
            view = view[written:]
            offset += written
        os.ftruncate(descriptor, len(value))
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        installed = os.fstat(descriptor)
        installed_value = bytearray()
        offset = 0
        while True:
            chunk = os.pread(descriptor, 65536, offset)
            if not chunk:
                break
            installed_value.extend(chunk)
            offset += len(chunk)
            if len(installed_value) > 1_048_576:
                core.fail("Installiertes Tunnelprofil überschreitet die Größenbegrenzung")
        remapped = os.stat(
            profile_path.name, dir_fd=directory_fd, follow_symlinks=False
        )
        if (remapped.st_dev, remapped.st_ino) != expected_identity:
            core.fail(
                "Tunnelprofilpfad driftete während des descriptorgebundenen Commits; fremder Pfadzustand blieb unangetastet"
            )
        if (
            (installed.st_dev, installed.st_ino) != expected_identity
            or bytes(installed_value) != value
            or installed.st_size != len(value)
            or statmod.S_IMODE(installed.st_mode) != mode
        ):
            core.fail(
                "Tunnelprofil-Commit konnte am gebundenen Inode nicht verifiziert werden"
            )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _transport_ingress_auth_reference() -> str:
    return f"{TRANSPORT_INGRESS_AUTH_HEADER}: file:{TRANSPORT_CONNECTOR_TOKEN_PATH}"


def _transport_ingress_auth_block() -> bytes:
    return (
        "  extra_headers:\n"
        f'    "{TRANSPORT_INGRESS_AUTH_HEADER}": "file:{TRANSPORT_CONNECTOR_TOKEN_PATH}"\n'
    ).encode("utf-8")


def _plain_profile_key(line: bytes, *, indent: int) -> str:
    if b"\r" in line:
        core.fail("Tunnelprofil verwendet nicht-kanonische Zeilenenden")
    prefix = b" " * indent
    if not line.startswith(prefix):
        core.fail("Tunnelprofil enthält eine unerwartete YAML-Einrückung")
    content = line[indent:].rstrip(b"\n")
    if not content or content.startswith((b" ", b"\t")) or b":" not in content:
        core.fail("Tunnelprofil enthält einen mehrdeutigen YAML-Schlüssel")
    raw_key = content.split(b":", 1)[0]
    allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
    if not raw_key or any(byte not in allowed for byte in raw_key):
        core.fail("Tunnelprofil enthält einen nicht-kanonischen YAML-Schlüssel")
    try:
        return raw_key.decode("ascii")
    except UnicodeDecodeError:
        core.fail("Tunnelprofil enthält einen nicht-ASCII YAML-Schlüssel")
        raise AssertionError


def _mcp_profile_block_bounds(value: bytes) -> tuple[int, int]:
    mcp_start: int | None = None
    mcp_end: int | None = None
    offset = 0
    for line in value.splitlines(keepends=True):
        stripped = line.strip()
        if not stripped or line.lstrip(b" ").startswith(b"#"):
            offset += len(line)
            continue
        if line.startswith((b" ", b"\t")):
            offset += len(line)
            continue
        key = _plain_profile_key(line, indent=0)
        if key == "mcp":
            if mcp_start is not None or line != b"mcp:\n":
                core.fail("Tunnelprofil-mcp-Block ist nicht eindeutig kanonisch")
            mcp_start = offset + len(line)
        elif mcp_start is not None and mcp_end is None:
            mcp_end = offset
        offset += len(line)
    if mcp_start is None:
        core.fail("Tunnelprofil besitzt keinen kanonischen mcp-Block")
    return mcp_start, len(value) if mcp_end is None else mcp_end


def _mcp_direct_children(block: bytes) -> list[tuple[str, bytes]]:
    children: list[tuple[str, bytes]] = []
    for line in block.splitlines(keepends=True):
        stripped = line.strip()
        if not stripped or line.lstrip(b" ").startswith(b"#"):
            continue
        leading = line[: len(line) - len(line.lstrip(b" \t"))]
        if b"\t" in leading:
            core.fail("Tunnelprofil-mcp-Block verwendet Tab-Einrückung")
        indent = len(leading)
        if indent == 2:
            children.append((_plain_profile_key(line, indent=2), line))
        elif indent < 4:
            core.fail("Tunnelprofil-mcp-Block verwendet mehrdeutige Einrückung")
    return children


def _add_transport_ingress_auth(before: bytes) -> bytes:
    start, end = _mcp_profile_block_bounds(before)
    block = before[start:end]
    expected = _transport_ingress_auth_block()
    auth_children = [line for key, line in _mcp_direct_children(block) if key == "extra_headers"]
    if auth_children:
        if auth_children == [b"  extra_headers:\n"] and block.count(expected) == 1:
            return before
        core.fail("Tunnelprofil besitzt fremde MCP-Extra-Header; Ingress-Auth wird nicht blind überschrieben")
    return before[:start] + expected + before[start:]


def require_transport_ingress_auth_profile(profile_path: Path) -> None:
    raw = profile_path.read_bytes()
    start, end = _mcp_profile_block_bounds(raw)
    block = raw[start:end]
    expected = _transport_ingress_auth_block()
    auth_children = [line for key, line in _mcp_direct_children(block) if key == "extra_headers"]
    if auth_children != [b"  extra_headers:\n"] or block.count(expected) != 1:
        core.fail("Tunnelprofil authentisiert den signierten Ingress nicht exakt")


def capture_tunnel_profile_cutover(profile_path: Path, runtime: Path) -> TunnelProfileCutover:
    before, linked = _read_profile_revision(profile_path)
    topology = profile_topology(profile_path, runtime)
    if topology.kind != "url" or topology.server_url_port not in TUNNEL_TARGET_PORTS:
        core.fail("Tunnelprofil besitzt keine cutover-fähige URL-Topologie")
    before_port = int(topology.server_url_port)
    if before_port == TRANSPORT_INGRESS_LISTENER_PORT:
        after = before
    else:
        legacy = b"http://127.0.0.1:18181/mcp"
        target = b"http://127.0.0.1:18180/mcp"
        if before.count(legacy) != 1:
            core.fail("Legacy-Tunnelziel ist nicht exakt einmal im Profil gebunden")
        after = before.replace(legacy, target, 1)
    after = _add_transport_ingress_auth(after)
    return TunnelProfileCutover(
        before=before,
        before_sha256=_profile_bytes_sha256(before),
        before_identity=(linked.st_dev, linked.st_ino),
        after_sha256=_profile_bytes_sha256(after),
        mode=statmod.S_IMODE(linked.st_mode),
        before_port=before_port,
        after_port=TRANSPORT_INGRESS_LISTENER_PORT,
    )


def apply_tunnel_profile_cutover(profile_path: Path, cutover: TunnelProfileCutover) -> dict[str, Any]:
    current, current_info = _read_profile_revision(profile_path)
    digest = _profile_bytes_sha256(current)
    if (current_info.st_dev, current_info.st_ino) != cutover.before_identity:
        core.fail("Tunnelprofil-Identität driftete seit dem Cutover-Preflight")
    if digest == cutover.after_sha256:
        return {"changed": False, "profile_sha256": digest, "port": cutover.after_port}
    if digest != cutover.before_sha256:
        core.fail("Tunnelprofil driftete vor dem signierten Ingress-Cutover")
    legacy = b"http://127.0.0.1:18181/mcp"
    target = b"http://127.0.0.1:18180/mcp"
    if cutover.before_port == TRANSPORT_INGRESS_LISTENER_PORT:
        replacement = current
    else:
        if current.count(legacy) != 1:
            core.fail("Legacy-Tunnelziel driftete vor dem Cutover")
        replacement = current.replace(legacy, target, 1)
    replacement = _add_transport_ingress_auth(replacement)
    if _profile_bytes_sha256(replacement) != cutover.after_sha256:
        core.fail("Tunnelprofil-Cutover stimmt nicht mit dem Preflight überein")
    _descriptor_bound_profile_write(
        profile_path,
        replacement,
        mode=cutover.mode,
        expected_identity=cutover.before_identity,
        expected_sha256=cutover.before_sha256,
    )
    installed, _ = _read_profile_revision(profile_path)
    if _profile_bytes_sha256(installed) != cutover.after_sha256:
        core.fail("Tunnelprofil-Cutover-Readback ist inkonsistent")
    return {"changed": replacement != current, "profile_sha256": cutover.after_sha256, "port": cutover.after_port}


def restore_tunnel_profile_cutover(profile_path: Path, cutover: TunnelProfileCutover) -> dict[str, Any]:
    current, current_info = _read_profile_revision(profile_path)
    digest = _profile_bytes_sha256(current)
    if (current_info.st_dev, current_info.st_ino) != cutover.before_identity:
        core.fail(
            "Tunnelprofil-Identität driftete während des Rollbacks; fremder Zustand wird nicht überschrieben"
        )
    if digest == cutover.before_sha256:
        return {"restored": False, "profile_sha256": digest, "port": cutover.before_port}
    if digest != cutover.after_sha256:
        core.fail("Tunnelprofil driftete während des Rollbacks; fremder Zustand wird nicht überschrieben")
    _descriptor_bound_profile_write(
        profile_path,
        cutover.before,
        mode=cutover.mode,
        expected_identity=cutover.before_identity,
        expected_sha256=cutover.after_sha256,
    )
    restored, _ = _read_profile_revision(profile_path)
    if _profile_bytes_sha256(restored) != cutover.before_sha256:
        core.fail("Tunnelprofil-Rollback-Readback ist inkonsistent")
    return {"restored": True, "profile_sha256": cutover.before_sha256, "port": cutover.before_port}


def require_transport_ingress_health(
    *, timeout_seconds: float = TRANSPORT_INGRESS_HEALTH_TIMEOUT_SECONDS
) -> dict[str, Any]:
    request = Request(TRANSPORT_INGRESS_HEALTH_URL, headers={"Cache-Control": "no-store", "Accept": "application/json"}, method="GET")
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    last_error_type: str | None = None
    last_error: str | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        attempts += 1
        try:
            with urlopen(request, timeout=max(0.01, min(2.0, remaining))) as response:
                status = int(response.status)
                raw = response.read(8193)
        except HTTPError as exc:
            core.fail(
                "Signierter Transport-Ingress lieferte keinen gültigen Health-Status",
                details={"error_type": type(exc).__name__, "http_status": exc.code},
            )
        except (URLError, TimeoutError, OSError) as exc:
            last_error_type = type(exc).__name__
            message = core.redact_text(str(exc)).strip()
            last_error = message[:256] if message else last_error_type
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(TRANSPORT_INGRESS_HEALTH_POLL_INTERVAL_SECONDS, remaining))
            continue
        if status != 200 or len(raw) > 8192:
            core.fail(
                "Signierter Transport-Ingress lieferte keinen gültigen Health-Status",
                details={"attempts": attempts, "http_status": status},
            )
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            core.fail(
                "Transport-Ingress-Health ist kein gültiges JSON",
                details={"attempts": attempts, "error_type": type(exc).__name__},
            )
        if not isinstance(value, dict) or value.get("healthy") is not True or value.get("assertion_version") != "signed-one-call-v1":
            core.fail(
                "Transport-Ingress-Health entspricht nicht dem One-Call-Vertrag",
                details={"attempts": attempts},
            )
        return value
    core.fail(
        "Signierter Transport-Ingress ist nicht erreichbar",
        details={
            "attempts": attempts,
            "error_type": last_error_type or "ReadinessTimeout",
            "last_error": last_error or "readiness deadline elapsed",
        },
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


def require_operator_listener(
    *,
    timeout_seconds: int = core.TIMEOUTS["service_start"],
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    consecutive = 0
    attempts = 0
    last_error: str | None = None
    while time.monotonic() < deadline:
        attempts += 1
        remaining = max(0.1, deadline - time.monotonic())
        try:
            with socket.create_connection(
                (OPERATOR_LISTENER_HOST, OPERATOR_LISTENER_PORT),
                timeout=min(0.5, remaining),
            ):
                consecutive += 1
                last_error = None
        except OSError as exc:
            consecutive = 0
            last_error = f"{type(exc).__name__}: {exc}"
        else:
            if consecutive >= OPERATOR_LISTENER_REQUIRED_SAMPLES:
                return {
                    "host": OPERATOR_LISTENER_HOST,
                    "port": OPERATOR_LISTENER_PORT,
                    "successful_samples": consecutive,
                    "attempts": attempts,
                }
        time.sleep(0.1)
    core.fail(
        "Operator-Listener ist nicht bestätigt erreichbar",
        phase="operator-listener",
        details={
            "host": OPERATOR_LISTENER_HOST,
            "port": OPERATOR_LISTENER_PORT,
            "required_consecutive_samples": OPERATOR_LISTENER_REQUIRED_SAMPLES,
            "successful_consecutive_samples": consecutive,
            "attempts": attempts,
            "last_error": last_error,
        },
    )


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


def _parse_tunnel_drain_metrics(text: str) -> dict[str, float]:
    observed: dict[str, float] = {}
    duplicates: list[str] = []
    response_series_seen: set[str] = set()
    final_response_count = 0.0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        metric, separator, value_text = line.rpartition(" ")
        if not separator:
            continue
        if (
            metric.startswith(TUNNEL_DRAIN_RESPONSE_HISTOGRAM_COUNT_NAME + "{")
            and 'latency_type="enqueue_to_response"' in metric
        ):
            if metric in response_series_seen:
                duplicates.append(TUNNEL_DRAIN_RESPONSE_HISTOGRAM_COUNT_NAME)
                continue
            response_series_seen.add(metric)
            try:
                value = float(value_text)
            except ValueError:
                core.fail(
                    "Tunnel-Drain-Metrik ist nicht numerisch",
                    phase="tunnel-drain-metrics",
                    details={"metric": TUNNEL_DRAIN_RESPONSE_HISTOGRAM_COUNT_NAME},
                )
            if not math.isfinite(value) or value < 0:
                core.fail(
                    "Tunnel-Drain-Metrik hat einen unzulässigen Wert",
                    phase="tunnel-drain-metrics",
                    details={
                        "metric": TUNNEL_DRAIN_RESPONSE_HISTOGRAM_COUNT_NAME,
                        "value": value_text,
                    },
                )
            final_response_count += value
            continue
        for name in TUNNEL_DRAIN_DIRECT_METRIC_NAMES:
            if not (metric == name or metric.startswith(name + "{")):
                continue
            if name in observed:
                duplicates.append(name)
                continue
            try:
                value = float(value_text)
            except ValueError:
                core.fail(
                    "Tunnel-Drain-Metrik ist nicht numerisch",
                    phase="tunnel-drain-metrics",
                    details={"metric": name},
                )
            if not math.isfinite(value) or value < 0:
                core.fail(
                    "Tunnel-Drain-Metrik hat einen unzulässigen Wert",
                    phase="tunnel-drain-metrics",
                    details={"metric": name, "value": value_text},
                )
            observed[name] = value
    missing = [name for name in TUNNEL_DRAIN_DIRECT_METRIC_NAMES if name not in observed]
    if duplicates or missing:
        core.fail(
            "Tunnel-Drain-Metriken sind nicht eindeutig vollständig",
            phase="tunnel-drain-metrics",
            details={
                "duplicate_metrics": sorted(set(duplicates)),
                "missing_metrics": missing,
                "observed": observed,
            },
        )
    observed[TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME] = final_response_count
    return observed


def _tunnel_drain_idle_mismatch(
    observed: dict[str, float], *, admission_active: bool = False
) -> dict[str, float]:
    enqueued = observed["commands_enqueued_total"]
    polled = observed["commands_polled_total"]
    final_responses = observed[TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME]
    response_gap = enqueued - final_responses
    mismatch: dict[str, float] = {}
    if observed[TUNNEL_DRAIN_QUEUE_GAUGE_NAME] != 0:
        mismatch[TUNNEL_DRAIN_QUEUE_GAUGE_NAME] = observed[TUNNEL_DRAIN_QUEUE_GAUGE_NAME]
    if polled != enqueued:
        mismatch["commands_polled_total"] = polled
        mismatch["commands_enqueued_total"] = enqueued
    if response_gap < 0 or (response_gap != 0 and not admission_active):
        mismatch[TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME] = final_responses
        mismatch["commands_enqueued_total"] = enqueued
    return mismatch


def _deployment_source_identity_sha256(snapshot: core.Snapshot) -> str:
    payload = {
        "repo_head": snapshot.repo_head,
        "contract_sha256": snapshot.contract_sha256,
        "runtime_input_sha256": snapshot.runtime_input_sha256,
        "runtime_lock_sha256": snapshot.runtime_lock_sha256,
        "source_sha256s": snapshot.source_sha256s,
        "runtime_asset_sha256s": snapshot.runtime_asset_sha256s,
    }
    return hashlib.sha256(
        json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    ).hexdigest()


def _secure_admission_marker_payload(path: Path) -> dict[str, Any] | None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        core.fail(
            "Deployment-Admission-Marker konnte nicht sicher geöffnet werden",
            phase="operator-admission-marker",
            details={"error_type": type(exc).__name__},
        )
    try:
        metadata = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or statmod.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > 4096
        ):
            core.fail(
                "Deployment-Admission-Marker ist nicht sicher lesbar",
                phase="operator-admission-marker",
            )
        chunks: list[bytes] = []
        remaining = 4097
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > 4096:
            core.fail(
                "Deployment-Admission-Marker überschreitet das Größenlimit",
                phase="operator-admission-marker",
            )
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        core.fail(
            "Deployment-Admission-Marker ist ungültig",
            phase="operator-admission-marker",
            details={"error_type": type(exc).__name__},
        )
    if not isinstance(value, dict) or set(value) != OPERATOR_ADMISSION_MARKER_KEYS:
        core.fail(
            "Deployment-Admission-Marker hat ein ungültiges Schema",
            phase="operator-admission-marker",
        )
    created = value.get("created_at_unix")
    expires = value.get("expires_at_unix")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != OPERATOR_ADMISSION_MARKER_KIND
        or not isinstance(value.get("token"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["token"]) is None
        or not isinstance(value.get("expected_head"), str)
        or re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", value["expected_head"])
        is None
        or not isinstance(value.get("source_identity_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["source_identity_sha256"]) is None
        or not isinstance(created, int)
        or isinstance(created, bool)
        or not isinstance(expires, int)
        or isinstance(expires, bool)
        or expires <= created
        or expires - created > OPERATOR_ADMISSION_MARKER_MAX_LIFETIME_SECONDS
    ):
        core.fail(
            "Deployment-Admission-Marker enthält ungültige Werte",
            phase="operator-admission-marker",
        )
    return value


def _fsync_parent(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_private_admission_marker(path: Path, value: dict[str, Any]) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor = os.open(path.parent, flags)
    descriptor = -1
    try:
        parent_linked = path.parent.lstat()
        parent_opened = os.fstat(parent_descriptor)
        if (
            not statmod.S_ISDIR(parent_opened.st_mode)
            or statmod.S_ISLNK(parent_linked.st_mode)
            or parent_opened.st_uid != os.getuid()
            or (parent_linked.st_dev, parent_linked.st_ino)
            != (parent_opened.st_dev, parent_opened.st_ino)
        ):
            core.fail(
                "Deployment-Admission-Marker-Elternverzeichnis ist unsicher",
                phase="operator-admission-marker",
            )
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                path.name, create_flags, 0o600, dir_fd=parent_descriptor
            )
        except FileExistsError:
            core.fail(
                "Deployment-Admission-Marker existiert bereits",
                phase="operator-admission-marker",
            )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                core.fail(
                    "Deployment-Admission-Marker konnte nicht vollständig geschrieben werden",
                    phase="operator-admission-marker",
                )
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        linked = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_nlink != 1
            or statmod.S_IMODE(opened.st_mode) != 0o600
        ):
            core.fail(
                "Deployment-Admission-Marker-Bindung driftete",
                phase="operator-admission-marker",
            )
        os.fsync(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _operator_admission_marker_lifetime_seconds(timeout_seconds: int) -> int:
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
    ):
        core.fail(
            "Deployment-Admission-Timeout muss positiv und ganzzahlig sein",
            phase="operator-admission-marker",
        )
    if timeout_seconds > OPERATOR_ADMISSION_MAX_TIMEOUT_SECONDS:
        core.fail(
            "Deployment-Admission-Timeout überschreitet das unterstützte Maximum",
            phase="operator-admission-marker",
            details={
                "timeout_seconds": timeout_seconds,
                "maximum_timeout_seconds": OPERATOR_ADMISSION_MAX_TIMEOUT_SECONDS,
            },
        )
    bootstrap_extra_seconds = max(
        0, OPERATOR_ADMISSION_BOOTSTRAP_DRAIN_SECONDS - timeout_seconds
    )
    required = (
        timeout_seconds * OPERATOR_ADMISSION_DYNAMIC_TIMEOUT_WINDOWS
        + bootstrap_extra_seconds
        + OPERATOR_ADMISSION_STOP_OPERATIONS
        * 2
        * core.TIMEOUTS["service_stop"]
        + OPERATOR_ADMISSION_START_OPERATIONS
        * 2
        * core.TIMEOUTS["service_start"]
        + OPERATOR_ADMISSION_SYSTEMD_QUERY_WINDOWS
        * core.TIMEOUTS["systemd_query"]
        + OPERATOR_ADMISSION_RECOVERY_MARGIN_SECONDS
    )
    if required > OPERATOR_ADMISSION_MARKER_MAX_LIFETIME_SECONDS:
        core.fail(
            "Deployment-Admission-Marker kann den vollständigen Deployment- und Recovery-Ablauf nicht abdecken",
            phase="operator-admission-marker",
            details={
                "timeout_seconds": timeout_seconds,
                "dynamic_timeout_windows": OPERATOR_ADMISSION_DYNAMIC_TIMEOUT_WINDOWS,
                "stop_operations": OPERATOR_ADMISSION_STOP_OPERATIONS,
                "start_operations": OPERATOR_ADMISSION_START_OPERATIONS,
                "systemd_query_windows": OPERATOR_ADMISSION_SYSTEMD_QUERY_WINDOWS,
                "recovery_margin_seconds": OPERATOR_ADMISSION_RECOVERY_MARGIN_SECONDS,
                "required_lifetime_seconds": required,
                "maximum_lifetime_seconds": OPERATOR_ADMISSION_MARKER_MAX_LIFETIME_SECONDS,
            },
        )
    return required


def _runtime_deploy_observer_job() -> tuple[Path, dict[str, Any]] | None:
    unit = os.environ.get("GRABOWSKI_JOB_UNIT")
    directory_text = os.environ.get("GRABOWSKI_JOB_DIRECTORY")
    metadata_text = os.environ.get("GRABOWSKI_JOB_METADATA_PATH")
    if unit is None and metadata_text is None:
        return None
    if (
        not isinstance(unit, str)
        or deployment_observer.UNIT_RE.fullmatch(unit) is None
        or not isinstance(directory_text, str)
        or not directory_text
        or not isinstance(metadata_text, str)
        or not metadata_text
    ):
        core.fail(
            "Deployment-Observer-Jobbindung ist ungültig",
            phase="operator-admission-observer",
        )
    directory = Path(directory_text)
    metadata_path = Path(metadata_text)
    if (
        not directory.is_absolute()
        or directory.name != unit
        or directory.is_symlink()
        or not metadata_path.is_absolute()
        or metadata_path != directory / "metadata.json"
        or metadata_path.is_symlink()
    ):
        core.fail(
            "Deployment-Observer-Metadatenpfad driftete",
            phase="operator-admission-observer",
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(metadata_path, flags)
    except OSError as exc:
        core.fail(
            "Deployment-Observer-Metadaten konnten nicht geöffnet werden",
            phase="operator-admission-observer",
            details={"error_type": type(exc).__name__},
        )
    try:
        file_metadata = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(file_metadata.st_mode)
            or file_metadata.st_uid != os.getuid()
            or file_metadata.st_nlink != 1
            or statmod.S_IMODE(file_metadata.st_mode) != 0o600
            or file_metadata.st_size > 2 * 1024 * 1024
        ):
            core.fail(
                "Deployment-Observer-Metadaten sind unsicher",
                phase="operator-admission-observer",
            )
        chunks: list[bytes] = []
        remaining = 2 * 1024 * 1024 + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > 2 * 1024 * 1024:
            core.fail(
                "Deployment-Observer-Metadaten sind zu groß",
                phase="operator-admission-observer",
            )
    finally:
        os.close(descriptor)
    try:
        metadata = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        core.fail(
            "Deployment-Observer-Metadaten sind ungültig",
            phase="operator-admission-observer",
            details={"error_type": type(exc).__name__},
        )
    if not isinstance(metadata, dict) or metadata.get("unit") != unit:
        core.fail(
            "Deployment-Observer-Metadaten sind nicht jobgebunden",
            phase="operator-admission-observer",
        )
    return directory, metadata


def _activate_runtime_deploy_observer(marker: dict[str, Any]) -> dict[str, Any] | None:
    job = _runtime_deploy_observer_job()
    if job is None:
        return None
    directory, metadata = job
    contract = metadata.get("deployment_observer_contract")
    if contract is None:
        return None
    failure_stage = "build_binding"
    try:
        binding = deployment_observer.build_activation_binding(
            contract,
            metadata=metadata,
            marker=marker,
        )
        failure_stage = "activation_path"
        path = deployment_observer.activation_path(directory)
        failure_stage = "create_activation"
        deployment_observer.create_activation(path, binding)
        failure_stage = "read_activation"
        observed = deployment_observer.read_activation(path)
        failure_stage = "validate_activation"
        deployment_observer.validate_activation_binding(
            observed,
            contract_value=contract,
            metadata=metadata,
            marker=marker,
        )
    except (OSError, PermissionError, TypeError, ValueError) as exc:
        core.fail(
            "Deployment-Observer-Aktivierung scheiterte",
            phase="operator-admission-observer",
            details={
                "error_type": type(exc).__name__,
                "failure_stage": failure_stage,
            },
        )
    return {
        "unit": binding["unit"],
        "contract_sha256": binding["contract_sha256"],
        "binding_sha256": binding["binding_sha256"],
        "expires_at_unix": binding["expires_at_unix"],
    }


def engage_operator_deployment_admission(
    snapshot: core.Snapshot,
    *,
    timeout_seconds: int,
    source_identity_sha256: str | None = None,
) -> dict[str, Any]:
    """Close admission for a deployment that owns a build snapshot.

    Signature and authority are unchanged: the deployment path still derives
    both the expected head and, by default, the source identity from the
    snapshot it is deploying.  The receipt-bound resume needs the same effect
    without a snapshot, and gets it through the separate entry point below
    rather than by loosening this one.
    """
    return _engage_operator_deployment_admission(
        expected_head=snapshot.repo_head,
        source_identity_sha256=(
            _deployment_source_identity_sha256(snapshot)
            if source_identity_sha256 is None
            else source_identity_sha256
        ),
        timeout_seconds=timeout_seconds,
    )


def engage_receipt_bound_deployment_admission(
    *,
    expected_head: str,
    source_identity_sha256: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Close admission for the mid-cutover resume, which owns no snapshot.

    The resume promotes a release that was built by an earlier deployment, so
    there is no snapshot here to derive an identity from.  Both values are
    therefore named explicitly and both come from the hash-bound cutover
    receipt -- never from a caller and never defaulted.  This is a separate
    function precisely so the ordinary deployment signature stays exactly as
    narrow as it was: nothing that already calls the deployment path can reach
    the snapshot-free variant by omitting an argument.
    """
    if not isinstance(expected_head, str) or not isinstance(
        source_identity_sha256, str
    ):
        raise ValueError("receipt-bound admission requires explicit string evidence")
    return _engage_operator_deployment_admission(
        expected_head=expected_head,
        source_identity_sha256=source_identity_sha256,
        timeout_seconds=timeout_seconds,
    )


def _engage_operator_deployment_admission(
    *,
    expected_head: str,
    source_identity_sha256: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    if OPERATOR_ADMISSION_HEAD_RE.fullmatch(expected_head or "") is None:
        raise ValueError("deployment admission expected_head is invalid")
    marker_expected_head = expected_head
    marker_source_identity_sha256 = source_identity_sha256
    if re.fullmatch(r"[0-9a-f]{64}", marker_source_identity_sha256 or "") is None:
        raise ValueError("source_identity_sha256 must be a lowercase SHA-256")
    now = int(time.time())
    existing = _secure_admission_marker_payload(OPERATOR_ADMISSION_MARKER_PATH)
    if existing is not None:
        expires = existing.get("expires_at_unix")
        if not isinstance(expires, int) or isinstance(expires, bool) or expires > now:
            core.fail(
                "Ein aktiver oder unklarer Deployment-Admission-Marker existiert bereits",
                phase="operator-admission-marker",
            )
        release_operator_deployment_admission(existing)
    lifetime = _operator_admission_marker_lifetime_seconds(timeout_seconds)
    marker = {
        "schema_version": 1,
        "kind": OPERATOR_ADMISSION_MARKER_KIND,
        "token": secrets.token_hex(32),
        "expected_head": marker_expected_head,
        "source_identity_sha256": marker_source_identity_sha256,
        "created_at_unix": now,
        "expires_at_unix": now + lifetime,
    }
    _create_private_admission_marker(OPERATOR_ADMISSION_MARKER_PATH, marker)
    try:
        _activate_runtime_deploy_observer(marker)
    except Exception:
        release_operator_deployment_admission(marker)
        raise
    observed = _secure_admission_marker_payload(OPERATOR_ADMISSION_MARKER_PATH)
    if observed != marker:
        core.fail(
            "Deployment-Admission-Marker-Readback driftete",
            phase="operator-admission-marker",
        )
    return marker


def release_operator_deployment_admission(marker: dict[str, Any]) -> None:
    path = OPERATOR_ADMISSION_MARKER_PATH
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor = os.open(path.parent, flags)
    descriptor = -1
    try:
        file_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path.name, file_flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            core.fail(
                "Deployment-Admission-Marker fehlt vor Freigabe",
                phase="operator-admission-marker-release",
                details={"reason": "marker-missing"},
            )
        opened = os.fstat(descriptor)
        linked = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not statmod.S_ISREG(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or statmod.S_IMODE(opened.st_mode) != 0o600
        ):
            core.fail(
                "Deployment-Admission-Marker-Bindung ist vor Freigabe unsicher",
                phase="operator-admission-marker-release",
            )
        chunks: list[bytes] = []
        remaining = 4097
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > 4096:
            core.fail(
                "Deployment-Admission-Marker ist vor Freigabe zu groß",
                phase="operator-admission-marker-release",
            )
        try:
            observed = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            core.fail(
                "Deployment-Admission-Marker ist vor Freigabe ungültig",
                phase="operator-admission-marker-release",
            )
        if (
            not isinstance(observed, dict)
            or observed.get("token") != marker.get("token")
            or observed.get("expected_head") != marker.get("expected_head")
            or observed.get("source_identity_sha256")
            != marker.get("source_identity_sha256")
        ):
            core.fail(
                "Deployment-Admission-Marker gehört einem anderen Lauf",
                phase="operator-admission-marker-release",
            )
        linked_again = os.stat(
            path.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (linked_again.st_dev, linked_again.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            core.fail(
                "Deployment-Admission-Marker driftete vor Freigabe",
                phase="operator-admission-marker-release",
            )
        os.unlink(path.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)
    if path.exists() or path.is_symlink():
        core.fail(
            "Deployment-Admission-Marker blieb nach Freigabe vorhanden",
            phase="operator-admission-marker-release",
        )


def _operator_admission_observation(
    port: int = OPERATOR_LISTENER_PORT,
) -> dict[str, Any] | None:
    request = Request(
        _operator_admission_status_url(port),
        headers={"Cache-Control": "no-store", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=2) as response:
            status = int(response.status)
            raw = response.read(8193)
    except HTTPError as exc:
        if exc.code == 404:
            return None
        core.fail(
            "Operator-Admission-Readback lieferte einen unerwarteten HTTP-Status",
            phase="operator-admission-drain",
            details={"http_status": exc.code},
        )
    except (URLError, TimeoutError, OSError) as exc:
        core.fail(
            "Operator-Admission-Readback war transportseitig nicht erreichbar",
            phase="operator-admission-drain",
            details={
                "failure_class": "transport",
                "error_type": type(exc).__name__,
            },
        )
    if status != 200:
        core.fail(
            "Operator-Admission-Readback lieferte einen unerwarteten HTTP-Status",
            phase="operator-admission-drain",
            details={"http_status": status},
        )
    if len(raw) > 8192:
        core.fail(
            "Operator-Admission-Readback überschreitet das Größenlimit",
            phase="operator-admission-drain",
        )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        core.fail(
            "Operator-Admission-Readback ist kein gültiges JSON",
            phase="operator-admission-drain",
            details={"error_type": type(exc).__name__},
        )
    if not isinstance(value, dict):
        core.fail(
            "Operator-Admission-Readback muss ein Objekt sein",
            phase="operator-admission-drain",
        )
    return value


def _operator_admission_call_counts(
    observed: dict[str, Any], *, phase: str = "operator-admission-drain"
) -> dict[str, Any]:
    active_calls = observed.get("active_tool_calls")
    if (
        not isinstance(active_calls, int)
        or isinstance(active_calls, bool)
        or active_calls < 0
    ):
        core.fail(
            "Operator-Admission-Readback enthält keine gültige aktive Call-Zahl",
            phase=phase,
            details={"observation": observed},
        )
    blocking = observed.get("drain_blocking_tool_calls")
    read_only = observed.get("read_only_active_tool_calls")
    classification = observed.get("effect_classification")
    effect_fields_present = (
        blocking is not None or read_only is not None or classification is not None
    )
    if not effect_fields_present:
        return {
            "effect_aware": False,
            "active_tool_calls": active_calls,
            "blocking_tool_calls": active_calls,
            "read_only_active_tool_calls": None,
        }
    # Compatibility with the immediately preceding #686 runtime: it exposes
    # both additive counters but predates the explicit classification tag.
    # Validate those counters, then remain conservative until the new runtime
    # is active by treating every in-flight call as deployment-blocking.
    if classification is None and blocking is not None and read_only is not None:
        if (
            not isinstance(blocking, int)
            or isinstance(blocking, bool)
            or blocking < 0
            or not isinstance(read_only, int)
            or isinstance(read_only, bool)
            or read_only < 0
            or blocking + read_only != active_calls
        ):
            core.fail(
                "Operator-Admission-Legacy-Zähler sind inkonsistent",
                phase=phase,
                details={"observation": observed},
            )
        return {
            "effect_aware": False,
            "active_tool_calls": active_calls,
            "blocking_tool_calls": active_calls,
            "read_only_active_tool_calls": read_only,
        }
    if (
        classification != OPERATOR_ADMISSION_EFFECT_CLASSIFICATION
        or not isinstance(blocking, int)
        or isinstance(blocking, bool)
        or blocking < 0
        or not isinstance(read_only, int)
        or isinstance(read_only, bool)
        or read_only < 0
        or blocking + read_only != active_calls
    ):
        core.fail(
            "Operator-Admission-Effektklassifikation ist inkonsistent",
            phase=phase,
            details={"observation": observed},
        )
    return {
        "effect_aware": True,
        "active_tool_calls": active_calls,
        "blocking_tool_calls": blocking,
        "read_only_active_tool_calls": read_only,
    }


def wait_for_operator_deployment_admission(
    marker: dict[str, Any],
    *,
    timeout_seconds: int,
    port: int = OPERATOR_LISTENER_PORT,
) -> dict[str, Any]:
    probe_seconds = min(timeout_seconds, OPERATOR_ADMISSION_PROBE_SECONDS)
    probe_deadline = time.monotonic() + probe_seconds
    probe_attempts = 0
    transport_retries = 0
    last_transport_error: dict[str, Any] | None = None
    first: dict[str, Any] | None = None
    while True:
        probe_attempts += 1
        try:
            first = _operator_admission_observation(port)
        except core.DeployError as exc:
            if not (
                exc.phase == "operator-admission-drain"
                and exc.details.get("failure_class") == "transport"
            ):
                raise
            transport_retries += 1
            last_transport_error = _error_summary(exc)
            remaining = probe_deadline - time.monotonic()
            if remaining <= 0:
                core.fail(
                    "Operator-Admission-Readback blieb transportseitig nicht erreichbar",
                    phase="operator-admission-drain",
                    details={
                        "failure_class": "transport",
                        "probe_attempts": probe_attempts,
                        "transport_retries": transport_retries,
                        "probe_seconds": probe_seconds,
                        "last_error": last_transport_error,
                    },
                )
            time.sleep(min(0.2, remaining))
            continue
        if first is None:
            return {
                "supported": False,
                "reason": "operator-runtime-precedes-admission-contract",
                "probe_attempts": probe_attempts,
                "transport_retries": transport_retries,
                "does_not_establish": [
                    "safe_continuous_admission",
                    "absence_of_inflight_commands",
                ],
            }
        break
    initial_counts = _operator_admission_call_counts(first)
    initial_blocking_tool_calls = initial_counts["blocking_tool_calls"]
    extended_existing_call_drain = (
        initial_counts["effect_aware"] and initial_blocking_tool_calls > 0
    )
    if not initial_counts["effect_aware"]:
        drain_timeout_seconds = max(
            timeout_seconds, OPERATOR_ADMISSION_BOOTSTRAP_DRAIN_SECONDS
        )
    elif extended_existing_call_drain:
        # The admission marker already rejects every new deployment-blocking
        # tool call. A blocker visible in the first marker-bound readback therefore
        # predates quiescence and may finish safely without widening admission.
        # Use the existing supported maximum only for that bounded drain window.
        drain_timeout_seconds = OPERATOR_ADMISSION_MAX_TIMEOUT_SECONDS
    else:
        drain_timeout_seconds = timeout_seconds
    deadline = time.monotonic() + drain_timeout_seconds
    consecutive_idle = 0
    attempts = 0
    last = first
    while True:
        attempts += 1
        observed = first if attempts == 1 else _operator_admission_observation(port)
        if observed is None:
            consecutive_idle = 0
        else:
            last = observed
            call_counts = _operator_admission_call_counts(observed)
            active_calls = call_counts["active_tool_calls"]
            drain_blocking_calls = call_counts["blocking_tool_calls"]
            valid = (
                observed.get("valid") is True
                and observed.get("active") is True
                and observed.get("state") == "active"
                and observed.get("admission_gate_installed") is True
                and observed.get("token") == marker.get("token")
                and observed.get("expected_head") == marker.get("expected_head")
                and observed.get("source_identity_sha256")
                == marker.get("source_identity_sha256")
            )
            if not valid:
                core.fail(
                    "Operator bestätigte den Deployment-Admission-Marker nicht",
                    phase="operator-admission-drain",
                    details={"observation": observed},
                )
            consecutive_idle = (
                consecutive_idle + 1 if drain_blocking_calls == 0 else 0
            )
            if consecutive_idle >= OPERATOR_ADMISSION_REQUIRED_IDLE_SAMPLES:
                return {
                    "supported": True,
                    "effect_aware": call_counts["effect_aware"],
                    "blocking_tool_calls": drain_blocking_calls,
                    "active_tool_calls": active_calls,
                    "read_only_active_tool_calls": call_counts["read_only_active_tool_calls"],
                    "drain_timeout_seconds": drain_timeout_seconds,
                    "initial_blocking_tool_calls": initial_blocking_tool_calls,
                    "extended_existing_call_drain": extended_existing_call_drain,
                    "probe_attempts": probe_attempts,
                    "transport_retries": transport_retries,
                    "attempts": attempts,
                    "consecutive_idle_samples": consecutive_idle,
                    "observation": observed,
                }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.2, remaining))
    core.fail(
        "Operator-Admission wurde nicht rechtzeitig leer",
        phase="operator-admission-drain",
        details={
            "attempts": attempts,
            "drain_timeout_seconds": drain_timeout_seconds,
            "bootstrap_mode": not initial_counts["effect_aware"],
            "initial_blocking_tool_calls": initial_blocking_tool_calls,
            "extended_existing_call_drain": extended_existing_call_drain,
            "last_observation": last,
        },
    )


def verify_operator_deployment_admission(
    marker: dict[str, Any],
    *,
    port: int = OPERATOR_LISTENER_PORT,
) -> dict[str, Any]:
    observed = _operator_admission_observation(port)
    call_counts = (
        _operator_admission_call_counts(
            observed, phase="operator-admission-final-guard"
        )
        if isinstance(observed, dict)
        else None
    )
    if (
        observed is None
        or observed.get("valid") is not True
        or observed.get("active") is not True
        or observed.get("admission_gate_installed") is not True
        or observed.get("token") != marker.get("token")
        or observed.get("expected_head") != marker.get("expected_head")
        or observed.get("source_identity_sha256")
        != marker.get("source_identity_sha256")
        or call_counts is None
        or call_counts["blocking_tool_calls"] != 0
    ):
        core.fail(
            "Operator-Admission-Finalprüfung scheiterte",
            phase="operator-admission-final-guard",
            details={"observation": observed, "call_counts": call_counts},
        )
    return {**observed, "admission_call_counts": call_counts}


def _tunnel_drain_counter_snapshot(observed: dict[str, float]) -> dict[str, float]:
    return {name: observed[name] for name in TUNNEL_DRAIN_COUNTER_NAMES}


def _tunnel_drain_stability_snapshot(observed: dict[str, float]) -> dict[str, float]:
    return {name: observed[name] for name in TUNNEL_DRAIN_STABILITY_NAMES}


def _require_tunnel_drain_counters_not_regressed(
    previous: dict[str, float],
    current: dict[str, float],
) -> None:
    regressed = {
        name: {"previous": previous[name], "current": current[name]}
        for name in TUNNEL_DRAIN_COUNTER_NAMES
        if current[name] < previous[name]
    }
    if regressed:
        core.fail(
            "Tunnel-Drain-Zähler gingen während des Stabilitätsbeweises zurück",
            phase="tunnel-drain-pre-stop",
            details={"regressed_counters": regressed},
        )


def wait_for_tunnel_dispatcher_idle(
    *, timeout_seconds: int, admission_active: bool = False
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    consecutive_idle = 0
    attempts = 0
    last_observed: dict[str, float] = {}
    last_idle_stability: dict[str, float] | None = None
    last_valid_counters: dict[str, float] | None = None
    expected_process_start_time: float | None = None
    last_error: dict[str, Any] | None = None
    while True:
        attempts += 1
        metrics_text = core.http_text(TUNNEL_METRICS_URL)
        if metrics_text is None:
            consecutive_idle = 0
            last_idle_stability = None
            last_error = {"reason": "metrics-unavailable"}
        else:
            try:
                observed = _parse_tunnel_drain_metrics(metrics_text)
            except core.DeployError as exc:
                consecutive_idle = 0
                last_idle_stability = None
                last_error = _error_summary(exc)
            else:
                last_observed = observed
                stability = _tunnel_drain_stability_snapshot(observed)
                counters = _tunnel_drain_counter_snapshot(observed)
                if last_valid_counters is not None:
                    _require_tunnel_drain_counters_not_regressed(
                        last_valid_counters,
                        counters,
                    )
                last_valid_counters = counters
                process_start_time = stability["process_start_time_seconds"]
                if expected_process_start_time is None:
                    expected_process_start_time = process_start_time
                elif process_start_time != expected_process_start_time:
                    core.fail(
                        "Tunnel-Prozess wechselte während des Drain-Stabilitätsbeweises",
                        phase="tunnel-drain-pre-stop",
                        details={
                            "expected_process_start_time_seconds": expected_process_start_time,
                            "observed_process_start_time_seconds": process_start_time,
                        },
                    )
                idle = not _tunnel_drain_idle_mismatch(
                    observed, admission_active=admission_active
                )
                comparable_stability = (
                    {
                        "process_start_time_seconds": process_start_time,
                        "pending_final_responses": (
                            counters["commands_enqueued_total"]
                            - counters[TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME]
                        ),
                    }
                    if admission_active
                    else stability
                )
                if not idle:
                    consecutive_idle = 0
                    last_idle_stability = None
                elif (
                    last_idle_stability is None
                    or comparable_stability != last_idle_stability
                ):
                    consecutive_idle = 1
                    last_idle_stability = comparable_stability
                else:
                    consecutive_idle += 1
                last_error = None
                if consecutive_idle >= TUNNEL_DRAIN_REQUIRED_IDLE_SAMPLES:
                    return {
                        "attempts": attempts,
                        "consecutive_idle_samples": consecutive_idle,
                        "metrics": observed,
                        "stability": stability,
                        "admission_active": admission_active,
                    }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(TUNNEL_DRAIN_SAMPLE_INTERVAL_SECONDS, remaining))
    core.fail(
        "Tunnel-Dispatcher wurde vor geplantem Stop nicht stabil leer",
        phase="tunnel-drain-pre-stop",
        details={
            "attempts": attempts,
            "required_consecutive_idle_samples": TUNNEL_DRAIN_REQUIRED_IDLE_SAMPLES,
            "last_observed": last_observed,
            "last_idle_stability": last_idle_stability or {},
            "last_valid_counters": last_valid_counters or {},
            "expected_process_start_time_seconds": expected_process_start_time,
            "last_error": last_error,
            "admission_active": admission_active,
        },
    )






def verify_tunnel_drain_final_guard(
    expected_stability: dict[str, float],
    *,
    admission_active: bool = False,
) -> dict[str, float]:
    metrics_text = core.http_text(TUNNEL_METRICS_URL)
    if metrics_text is None:
        core.fail(
            "Tunnel-Drain-Finalprüfung konnte Metriken nicht lesen",
            phase="tunnel-drain-final-guard",
            details={"reason": "metrics-unavailable"},
        )
    try:
        observed = _parse_tunnel_drain_metrics(metrics_text)
    except core.DeployError as exc:
        core.fail(
            "Tunnel-Drain-Finalprüfung konnte Metriken nicht sicher auswerten",
            phase="tunnel-drain-final-guard",
            details={"metrics_error": _error_summary(exc)},
        )
    busy = _tunnel_drain_idle_mismatch(
        observed, admission_active=admission_active
    )
    stability = _tunnel_drain_stability_snapshot(observed)
    if admission_active:
        changed_stability = {}
        if expected_stability.get("process_start_time_seconds") != stability[
            "process_start_time_seconds"
        ]:
            changed_stability["process_start_time_seconds"] = {
                "expected": expected_stability.get("process_start_time_seconds"),
                "observed": stability["process_start_time_seconds"],
            }
        expected_enqueued = expected_stability.get("commands_enqueued_total")
        expected_final_responses = expected_stability.get(
            TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME
        )
        if (
            isinstance(expected_enqueued, (int, float))
            and not isinstance(expected_enqueued, bool)
            and isinstance(expected_final_responses, (int, float))
            and not isinstance(expected_final_responses, bool)
        ):
            expected_response_gap = expected_enqueued - expected_final_responses
            observed_response_gap = (
                stability["commands_enqueued_total"]
                - stability[TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME]
            )
            if observed_response_gap != expected_response_gap:
                changed_stability["pending_final_responses"] = {
                    "expected": expected_response_gap,
                    "observed": observed_response_gap,
                }
        else:
            changed_stability["pending_final_responses"] = {
                "expected": "numeric-counter-pair",
                "observed": None,
            }
        for name in TUNNEL_DRAIN_COUNTER_NAMES:
            expected = expected_stability.get(name)
            if not isinstance(expected, (int, float)) or stability[name] < expected:
                changed_stability[name] = {
                    "expected_minimum": expected,
                    "observed": stability[name],
                }
    else:
        changed_stability = {
            name: {"expected": expected_stability.get(name), "observed": stability[name]}
            for name in TUNNEL_DRAIN_STABILITY_NAMES
            if expected_stability.get(name) != stability[name]
        }
    if busy or changed_stability:
        core.fail(
            "Tunnel wurde zwischen Drain-Beweis und geplantem Stop wieder aktiv",
            phase="tunnel-drain-final-guard",
            details={
                "busy_metrics": busy,
                "changed_stability": changed_stability,
            },
        )
    return observed






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
    agent_instructions: dict[str, Any],
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
        expected_agent_instructions=agent_instructions,
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
    admission_marker: dict[str, Any] | None = None,
    profile_path: Path | None = None,
    profile_cutover: TunnelProfileCutover | None = None,
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
    if profile_cutover is not None:
        step("stop-transport-ingress", lambda: stop_service(TRANSPORT_INGRESS_SERVICE))
    profile_restore_ok = True
    if profile_path is not None and profile_cutover is not None:
        profile_restore_ok, _ = step(
            "restore-tunnel-profile",
            lambda: restore_tunnel_profile_cutover(profile_path, profile_cutover),
        )
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
    listener_ok = False
    listener = None
    if identity_ok and identity is not None:
        listener_ok, listener = step("operator-listener", lambda: require_operator_listener(timeout_seconds=timeout_seconds))
    admission_ok = admission_marker is None
    admission = None
    if listener_ok and listener is not None and admission_marker is not None:
        admission_ok, admission = step(
            "operator-admission-replacement-guard",
            lambda: verify_operator_deployment_admission(admission_marker),
        )
        if not admission_ok:
            step(
                "stop-operator-after-admission-failure",
                lambda: stop_service(OPERATOR_SERVICE),
            )
    tunnel_start_ok = False
    started_tunnel = None
    ingress_ready = profile_restore_ok
    if (
        profile_restore_ok
        and profile_cutover is not None
        and profile_cutover.before_port == TRANSPORT_INGRESS_LISTENER_PORT
    ):
        ingress_ok, _ = step("start-transport-ingress", lambda: start_service(TRANSPORT_INGRESS_SERVICE))
        if ingress_ok:
            ingress_ok, _ = step("transport-ingress-health", require_transport_ingress_health)
        ingress_ready = ingress_ok
    if (
        listener_ok
        and listener is not None
        and admission_ok
        and profile_restore_ok
        and ingress_ready
    ):
        tunnel_start_ok, started_tunnel = step("start-tunnel", lambda: start_service(TUNNEL_SERVICE))
        if tunnel_start_ok and started_tunnel is not None and admission_marker is not None:
            admission_ok, admission = step(
                "operator-admission-post-tunnel-guard",
                lambda: verify_operator_deployment_admission(admission_marker),
            )
            if not admission_ok:
                step(
                    "stop-tunnel-after-admission-drift",
                    lambda: stop_service(TUNNEL_SERVICE),
                )
                step(
                    "stop-operator-after-admission-drift",
                    lambda: stop_service(OPERATOR_SERVICE),
                )
                tunnel_start_ok = False
                started_tunnel = None
    ready_ok = False
    ready = None
    if tunnel_start_ok and started_tunnel is not None:
        ready_ok, ready = step("readiness", lambda: wait_until_ready(timeout_seconds))
        if ready_ok and isinstance(ready, DualReadiness) and not ready.ok:
            errors.append({"phase": "readiness", "message": "Wiederhergestellte Runtime wurde nicht ready", "result": ready.to_dict()})
            ready_ok = False

    admission_release = "not-requested"
    if (
        admission_marker is not None
        and identity_ok
        and identity is not None
        and ready_ok
        and isinstance(ready, DualReadiness)
        and ready.ok
    ):
        released_ok, _ = step(
            "release-admission",
            lambda: release_operator_deployment_admission(admission_marker),
        )
        admission_release = "released" if released_ok else "failed"

    payload = {
        "original": _error_summary(original),
        "phases": phases,
        "errors": errors,
        "pointer_restore": "restored",
        "operator_identity": "verified" if identity_ok and identity is not None else "failed",
        "operator_admission": "verified" if admission_ok else "failed",
        "tunnel_profile_restore": "verified" if profile_restore_ok else "failed",
        "readiness": "verified" if ready_ok and isinstance(ready, DualReadiness) and ready.ok else "failed",
        "admission_release": admission_release,
    }
    raise core.DeployError("Deployment fehlgeschlagen; Zwei-Dienste-Rollbackzustand: " + json.dumps(payload, sort_keys=True)) from original






def _preflight_source_topology(
    repo: Path,
    runtime: Path,
    profile_path: Path,
    *,
    expected_head: str | None = None,
) -> tuple[core.Snapshot, Path, ProfileTopology]:
    snapshot = core.snapshot_from_git(repo)
    if expected_head is not None and snapshot.repo_head != expected_head:
        core.fail(
            "Deployment source HEAD differs from expected_head",
            phase="expected-head",
            details={
                "expected_head": expected_head,
                "observed_head": snapshot.repo_head,
            },
        )
    runtime = core.require_runtime_replaceable(runtime)
    topology = profile_topology(profile_path, runtime)
    require_topology_matches_contract(topology, runtime, snapshot.contract)
    return snapshot, runtime, topology


def _bootstrap_recovery_service_units(
    topology: ProfileTopology,
) -> tuple[str, ...]:
    if topology.kind != "url":
        core.fail(
            "Bootstrap recovery requires the URL runtime topology",
            phase="bootstrap-recovery-topology",
        )
    units = [OPERATOR_SERVICE]
    if topology.server_url_port == TRANSPORT_INGRESS_LISTENER_PORT:
        units.append(TRANSPORT_INGRESS_SERVICE)
    units.append(TUNNEL_SERVICE)
    return tuple(units)


def _bootstrap_recovery_service_observations(
    topology: ProfileTopology,
) -> tuple[tuple[str, ...], dict[str, core.ServiceObservation]]:
    units = _bootstrap_recovery_service_units(topology)
    observations = {unit: observe_service(unit) for unit in units}
    ambiguous = {
        unit: observation.to_dict()
        for unit, observation in observations.items()
        if not (observation.confirmed_active or observation.confirmed_inactive)
    }
    if ambiguous:
        core.fail(
            "Bootstrap recovery predecessor service state is not safely observable",
            phase="bootstrap-recovery-predecessor-state",
            details={"services": ambiguous},
        )
    return units, observations


def bootstrap_recovery_predecessor_state(
    topology: ProfileTopology,
) -> tuple[str, dict[str, dict[str, Any]]]:
    units, observations = _bootstrap_recovery_service_observations(topology)
    if all(observation.confirmed_active for observation in observations.values()):
        state = "active"
    elif observations[OPERATOR_SERVICE].confirmed_inactive:
        # Once the operator is authoritatively down it cannot admit new Grabowski
        # effects. Residual transport services are quiesced by the out-of-release
        # recovery path itself before pointer activation.
        state = "operator-inactive"
    else:
        core.fail(
            "Bootstrap recovery refuses a mixed predecessor while the operator remains active",
            phase="bootstrap-recovery-predecessor-state",
            details={
                "services": {
                    unit: observations[unit].to_dict() for unit in units
                }
            },
        )
    return state, {
        unit: observations[unit].to_dict() for unit in units
    }


def _require_bootstrap_recovery_predecessor_inactive(
    topology: ProfileTopology,
) -> dict[str, dict[str, Any]]:
    units, observations = _bootstrap_recovery_service_observations(topology)
    if not all(observation.confirmed_inactive for observation in observations.values()):
        core.fail(
            "Bootstrap recovery predecessor runtime is not fully inactive before cutover",
            phase="bootstrap-recovery-predecessor-final-guard",
            details={
                "services": {
                    unit: observations[unit].to_dict() for unit in units
                }
            },
        )
    return {unit: observations[unit].to_dict() for unit in units}


def quiesce_bootstrap_recovery_predecessor(
    topology: ProfileTopology,
) -> dict[str, dict[str, Any]]:
    state, observations = bootstrap_recovery_predecessor_state(topology)
    if state != "operator-inactive":
        core.fail(
            "Bootstrap recovery predecessor no longer requires out-of-band quiescence",
            phase="bootstrap-recovery-quiesce",
            details={"services": observations},
        )
    for unit in reversed(_bootstrap_recovery_service_units(topology)):
        stop_service(unit)
    return _require_bootstrap_recovery_predecessor_inactive(topology)


def preflight_url(
    repo: Path,
    runtime: Path,
    profile_path: Path,
    *,
    expected_head: str | None = None,
) -> tuple[core.Snapshot, Path, ProfileTopology]:
    snapshot, runtime, topology = _preflight_source_topology(
        repo, runtime, profile_path, expected_head=expected_head
    )
    if topology.kind != "url":
        return snapshot, runtime, topology
    require_service_active(OPERATOR_SERVICE)
    require_service_active(TUNNEL_SERVICE)
    verify_operator_process(runtime, snapshot.contract)
    require_operator_listener()
    verify_tunnel_process()
    return snapshot, runtime, topology


def preflight_bootstrap_recovery_url(
    repo: Path,
    runtime: Path,
    profile_path: Path,
    *,
    expected_head: str,
) -> tuple[
    core.Snapshot,
    Path,
    ProfileTopology,
    str,
    dict[str, dict[str, Any]],
]:
    snapshot, runtime, topology = _preflight_source_topology(
        repo, runtime, profile_path, expected_head=expected_head
    )
    predecessor_state, observations = bootstrap_recovery_predecessor_state(topology)
    if predecessor_state == "active":
        verify_operator_process(runtime, snapshot.contract)
        require_operator_listener()
        verify_tunnel_process()
    return snapshot, runtime, topology, predecessor_state, observations


def deploy_url(
    repo: Path,
    runtime: Path,
    profile_path: Path,
    *,
    timeout_seconds: int,
    expected_head: str | None = None,
    bootstrap_recovery: bool = False,
) -> None:
    if bootstrap_recovery:
        if expected_head is None:
            core.fail(
                "Bootstrap recovery requires expected_head",
                phase="bootstrap-recovery-contract",
            )
        (
            snapshot,
            runtime,
            topology,
            predecessor_mode,
            bootstrap_predecessor,
        ) = preflight_bootstrap_recovery_url(
            repo,
            runtime,
            profile_path,
            expected_head=expected_head,
        )
    else:
        snapshot, runtime, topology = preflight_url(
            repo,
            runtime,
            profile_path,
            expected_head=expected_head,
        )
        predecessor_mode = "active"
        bootstrap_predecessor = {}
    bootstrap_full_down = bootstrap_recovery and predecessor_mode == "operator-inactive"
    profile_cutover = (
        capture_tunnel_profile_cutover(profile_path, runtime)
        if topology.kind == "url" and topology.server_url_port in TUNNEL_TARGET_PORTS
        else None
    )
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
        expected_agent_instructions=build.agent_instructions,
    )
    activation = core.ActivationState(
        runtime=runtime,
        release_path=build.release_path,
        previous=core.capture_pointer(runtime),
    )
    watchdog_projection = install_watchdog_host_assets(repo, snapshot)
    try:
        observer_repair = install_safety_observer_unit(repo, snapshot)
    except Exception as original:
        try:
            restore_watchdog_host_assets(watchdog_projection)
        except Exception as rollback_error:
            core.fail(
                "Safety-Observer-Installation scheiterte und Watchdog-Host-Assets konnten nicht rückgesichert werden",
                phase="watchdog-host-asset-rollback",
                details={
                    "observer_error": str(original),
                    "watchdog_rollback_error": str(rollback_error),
                },
            )
        raise
    phase = "post-host-assets-snapshot-revalidation"
    admission_marker: dict[str, Any] | None = None
    admission_proof: dict[str, Any] = {"supported": False}
    drain_proof: dict[str, Any] = {}
    final_drain_metrics: dict[str, float] = {}
    activation_attempted = False
    try:
        core.verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)
        if bootstrap_full_down:
            phase = "bootstrap-recovery-quiesce"
            bootstrap_predecessor = quiesce_bootstrap_recovery_predecessor(topology)
        else:
            phase = "operator-admission-engage"
            admission_marker = engage_operator_deployment_admission(
                snapshot, timeout_seconds=timeout_seconds
            )
            phase = "operator-admission-drain"
            admission_proof = wait_for_operator_deployment_admission(
                admission_marker, timeout_seconds=timeout_seconds
            )
            admission_active = admission_proof.get("supported") is True
            phase = "tunnel-drain-pre-stop"
            drain_proof = wait_for_tunnel_dispatcher_idle(
                timeout_seconds=timeout_seconds, admission_active=admission_active
            )
            if admission_active:
                phase = "operator-admission-final-guard"
                verify_operator_deployment_admission(admission_marker)
            phase = "tunnel-drain-final-guard"
            final_drain_metrics = verify_tunnel_drain_final_guard(
                drain_proof["stability"], admission_active=admission_active
            )
            if admission_active:
                phase = "operator-admission-final-guard"
                verify_operator_deployment_admission(admission_marker)
            phase = "stop-tunnel"
            stop_service(TUNNEL_SERVICE)
            if profile_cutover is not None:
                phase = "stop-transport-ingress"
                stop_service(TRANSPORT_INGRESS_SERVICE)
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
        if bootstrap_full_down:
            phase = "bootstrap-recovery-predecessor-final-guard"
            bootstrap_predecessor = _require_bootstrap_recovery_predecessor_inactive(
                topology
            )

        phase = "activate-pointer"
        activation_attempted = True
        core.activate_pointer(activation)

        phase = "start-operator"
        start_service(OPERATOR_SERVICE)
        verify_operator_process(
            runtime,
            snapshot.contract,
            release_hint=build.release_path,
        )
        phase = "operator-listener"
        require_operator_listener(timeout_seconds=timeout_seconds)
        if admission_marker is not None:
            phase = "operator-admission-replacement-guard"
            verify_operator_deployment_admission(admission_marker)

        if profile_cutover is not None:
            phase = "initialize-ingress-selector"
            initialize_canonical_ingress_selector(
                release_path=build.release_path,
                cutover_id=f"recovery-{snapshot.repo_head[:12]}",
            )
            phase = "start-transport-ingress"
            start_service(TRANSPORT_INGRESS_SERVICE)
            require_service_active(TRANSPORT_INGRESS_SERVICE)
            require_transport_ingress_health()
            phase = "cutover-tunnel-profile"
            apply_tunnel_profile_cutover(profile_path, profile_cutover)
            cutover_topology = profile_topology(profile_path, runtime)
            if cutover_topology.kind != "url" or cutover_topology.server_url_port != TRANSPORT_INGRESS_LISTENER_PORT:
                core.fail("Tunnelprofil ist nach Cutover nicht an den signierten Ingress gebunden")
            require_transport_ingress_auth_profile(profile_path)

        phase = "start-tunnel"
        start_service(TUNNEL_SERVICE)
        verify_tunnel_process()
        if admission_marker is not None:
            phase = "operator-admission-post-tunnel-guard"
            verify_operator_deployment_admission(admission_marker)

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
            agent_instructions=build.agent_instructions,
        )
        if admission_marker is not None:
            phase = "operator-admission-release"
            release_operator_deployment_admission(admission_marker)
            admission_marker = None

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
        print(f"Watchdog-Assets: {watchdog_projection.asset_set_sha256}")
        if bootstrap_full_down:
            print("Bootstrap:       predecessor=operator-inactive; transport-quiesced")
            print(
                "Bootstrap-Units: "
                + ",".join(sorted(bootstrap_predecessor))
            )
        else:
            print(
                "Tunnel-Drain:    "
                f"attempts={drain_proof['attempts']} "
                f"stable={drain_proof['consecutive_idle_samples']} "
                f"admission={admission_proof.get('supported')} "
                f"final_queue={final_drain_metrics['commands_queue_length']:g} "
                f"final_responses={final_drain_metrics[TUNNEL_DRAIN_FINAL_RESPONSE_COUNTER_NAME]:g} "
                f"workers_observed={final_drain_metrics['dispatcher_worker_pool_occupancy']:g}"
            )
        print(f"Legacy-Backup:   {activation.legacy_backup}")
    except Exception as original:
        watchdog_rollback_error: Exception | None = None
        try:
            restore_watchdog_host_assets(watchdog_projection)
        except Exception as rollback_error:
            watchdog_rollback_error = rollback_error
        primary_error = _error_summary(original)
        primary_error.setdefault("phase", phase)
        primary_error["deploy_phase"] = phase
        observer_repair_evidence = {
            "marker": OBSERVER_SAFETY_REPAIR_MARKER,
            "retained": True,
            "repo_head": observer_repair["repo_head"],
            "sha256": observer_repair["sha256"],
            "changed": bool(observer_repair["changed"]),
        }
        if observer_repair.get("retained_path") is not None:
            observer_repair_evidence["retained_path"] = observer_repair[
                "retained_path"
            ]
            observer_repair_evidence["retained_sha256"] = observer_repair[
                "retained_sha256"
            ]
        primary_error["observer_safety_repair"] = observer_repair_evidence
        primary_error["watchdog_host_assets"] = {
            "repo_head": watchdog_projection.repo_head,
            "asset_set_sha256": watchdog_projection.asset_set_sha256,
            "changed_targets": list(watchdog_projection.changed_targets),
            "rollback": (
                "failed" if watchdog_rollback_error is not None else "restored"
            ),
        }
        if watchdog_rollback_error is not None:
            primary_error["watchdog_host_assets"]["rollback_error"] = str(
                watchdog_rollback_error
            )
        print(
            "PRIMARY-DEPLOY-ERROR: "
            + json.dumps(primary_error, sort_keys=True),
            file=sys.stderr,
        )
        rollback_original = original
        if watchdog_rollback_error is not None:
            rollback_original = core.DeployError(
                "Deployment und Watchdog-Host-Asset-Rücksicherung fehlgeschlagen: "
                f"{original}; watchdog rollback: {watchdog_rollback_error}"
            )
        if bootstrap_full_down and not activation_attempted:
            if admission_marker is not None:
                release_operator_deployment_admission(admission_marker)
                admission_marker = None
            if watchdog_rollback_error is not None:
                raise rollback_original from original
            raise original
        pre_stop_phases = {
            "operator-admission-engage",
            "operator-admission-drain",
            "operator-admission-final-guard",
            "tunnel-drain-pre-stop",
            "tunnel-drain-final-guard",
        }
        if phase in pre_stop_phases:
            if admission_marker is not None:
                release_operator_deployment_admission(admission_marker)
                admission_marker = None
            if watchdog_rollback_error is not None:
                raise rollback_original from original
            raise original
        rollback_url(
            rollback_original,
            activation=activation,
            contract=snapshot.contract,
            timeout_seconds=timeout_seconds,
            admission_marker=admission_marker,
            profile_path=profile_path,
            profile_cutover=profile_cutover,
        )



def _green_operator_unit(cutover_id: str) -> str:
    digest = hashlib.sha256(cutover_id.encode("utf-8")).hexdigest()[:12]
    return f"{GREEN_OPERATOR_UNIT_PREFIX}{digest}.service"


def _require_green_unit(unit: str) -> str:
    if not isinstance(unit, str) or GREEN_OPERATOR_UNIT_RE.fullmatch(unit) is None:
        core.fail("Transient green operator unit identity is invalid")
    return unit


def _green_confirmed_inactive(observation: core.ServiceObservation) -> bool:
    return observation.confirmed_inactive or (
        observation.query_valid
        and observation.load_state == "not-found"
        and observation.active_state == "inactive"
        and observation.main_pid == 0
    )


def _require_loopback_listener(port: int, *, timeout_seconds: int) -> dict[str, Any]:
    if port not in {OPERATOR_LISTENER_PORT, GREEN_OPERATOR_LISTENER_PORT}:
        core.fail("Operator listener port is outside the blue-green contract")
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    consecutive = 0
    last_error: str | None = None
    while time.monotonic() < deadline:
        attempts += 1
        try:
            with socket.create_connection(
                (OPERATOR_LISTENER_HOST, port), timeout=0.5
            ):
                consecutive += 1
                last_error = None
        except OSError as exc:
            consecutive = 0
            last_error = type(exc).__name__
        if consecutive >= OPERATOR_LISTENER_REQUIRED_SAMPLES:
            return {
                "host": OPERATOR_LISTENER_HOST,
                "port": port,
                "attempts": attempts,
                "successful_samples": consecutive,
            }
        time.sleep(0.1)
    core.fail(
        "Operator listener did not become ready",
        phase="green-listener" if port == GREEN_OPERATOR_LISTENER_PORT else "operator-listener",
        details={"port": port, "attempts": attempts, "last_error": last_error},
    )


def _canonical_operator_green_environment() -> dict[str, str]:
    """Read the live canonical operator's non-secret recovery configuration."""
    result = core.run(
        [
            "systemctl",
            "--user",
            "show",
            OPERATOR_SERVICE,
            "--property=Environment",
            "--value",
        ],
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["systemd_query"],
    )
    if result.returncode != 0:
        core.fail(
            "Canonical operator environment could not be read for green parity",
            phase="start-green",
            details={"returncode": result.returncode},
        )
    try:
        entries = shlex.split(result.stdout)
    except ValueError as exc:
        core.fail(
            "Canonical operator environment is not parseable for green parity",
            phase="start-green",
            details={"error_type": type(exc).__name__},
        )
    observed: dict[str, str] = {}
    for entry in entries:
        if "=" not in entry:
            continue
        key, value = entry.split("=", 1)
        if key not in GREEN_INHERITED_OPERATOR_ENV_KEYS:
            continue
        if not value or any(character in value for character in "\r\n\x00"):
            core.fail(
                "Canonical operator recovery environment is invalid",
                phase="start-green",
                details={"environment_key": key},
            )
        if len(value.encode("utf-8")) > 1024:
            core.fail(
                "Canonical operator recovery environment is oversized",
                phase="start-green",
                details={"environment_key": key},
            )
        observed[key] = value
    return observed


def _start_green_operator(
    *,
    unit: str,
    release_path: Path,
    contract: core.RuntimeContract,
    timeout_seconds: int,
) -> dict[str, Any]:
    name = _require_green_unit(unit)
    existing = observe_service(name)
    if not _green_confirmed_inactive(existing):
        core.fail(
            "Transient green operator unit already exists or is ambiguous",
            phase="start-green",
            details={"service": existing.to_dict()},
        )
    python = release_path / ".venv/bin/python"
    argv = [
        str(python),
        "-m",
        contract.module,
        "--transport",
        "streamable-http",
        "--host",
        OPERATOR_LISTENER_HOST,
        "--port",
        str(GREEN_OPERATOR_LISTENER_PORT),
    ]
    green_environment = _canonical_operator_green_environment()
    command = [
        "systemd-run",
        "--user",
        f"--unit={name}",
        "--collect",
        "--quiet",
        "--property=Type=exec",
        "--property=Restart=no",
        "--property=KillMode=mixed",
        "--property=UMask=0077",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        (
            "--property=ReadWritePaths="
            f"{core.HOME / '.local/state/grabowski'} "
            f"{core.HOME / 'repos'} "
            f"{core.HOME / 'grabowski-workspace'}"
        ),
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "--property=LockPersonality=yes",
        "--property=MemoryDenyWriteExecute=yes",
        "--property=RestrictRealtime=yes",
        "--property=LimitCORE=0",
        "--property=SystemCallArchitectures=native",
        "--setenv=PYTHONUNBUFFERED=1",
        *[
            f"--setenv={key}={green_environment[key]}"
            for key in GREEN_INHERITED_OPERATOR_ENV_KEYS
            if key in green_environment
        ],
        "--",
        *argv,
    ]
    result = core.run(
        command,
        check=False,
        capture=True,
        timeout=core.TIMEOUTS["service_start"],
    )
    if result.returncode != 0:
        core.fail(
            "Transient green operator could not be started",
            phase="start-green",
            details={"returncode": result.returncode},
        )
    observation = wait_for_service(
        name, active=True, timeout_seconds=core.TIMEOUTS["service_start"]
    )
    if not observation.confirmed_active or observation.main_pid is None:
        core.fail(
            "Transient green operator is not confirmed active",
            phase="start-green",
            details={"service": observation.to_dict()},
        )
    actual_argv = core.process_argv(observation.main_pid)
    if actual_argv != argv:
        core.fail(
            "Transient green operator argv differs from the immutable release",
            phase="start-green",
        )
    executable = core.process_exe(observation.main_pid)
    if executable is None or executable.resolve() != python.resolve():
        core.fail(
            "Transient green operator executable differs from the immutable release",
            phase="start-green",
        )
    listener = _require_loopback_listener(
        GREEN_OPERATOR_LISTENER_PORT, timeout_seconds=timeout_seconds
    )
    return {
        "started": True,
        "unit": name,
        "pid": observation.main_pid,
        "release_path": str(release_path),
        "listener": listener,
        "argv_sha256": hashlib.sha256(
            json.dumps(argv, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "inherited_environment_keys": sorted(green_environment),
    }


def _stop_green_operator(unit: str) -> dict[str, Any]:
    name = _require_green_unit(unit)
    before = observe_service(name)
    after_stop = before
    if not _green_confirmed_inactive(before):
        result = core.run(
            ["systemctl", "--user", "stop", name],
            check=False,
            capture=True,
            timeout=core.TIMEOUTS["service_stop"],
        )
        after_stop = observe_service(name)
        if result.returncode != 0 and not _green_confirmed_inactive(after_stop):
            core.fail(
                "Transient green operator stop failed",
                phase="retire-green",
                details={
                    "returncode": result.returncode,
                    "service": after_stop.to_dict(),
                },
            )
    deadline = time.monotonic() + core.TIMEOUTS["service_stop"]
    after = after_stop
    while not _green_confirmed_inactive(after) and time.monotonic() < deadline:
        time.sleep(0.2)
        after = observe_service(name)
    if not _green_confirmed_inactive(after):
        core.fail(
            "Transient green operator is not confirmed inactive",
            phase="retire-green",
            details={"service": after.to_dict()},
        )
    return {"retired": True, "unit": name, "service": after.to_dict()}


def _probe_release_runtime(
    *,
    release_path: Path,
    port: int,
    auth_mode: str,
    expected_release_id: str,
    expected_repo_head: str,
    expected_agent_instructions_sha256: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    if port not in {TRANSPORT_INGRESS_LISTENER_PORT, GREEN_OPERATOR_LISTENER_PORT}:
        core.fail("Runtime readiness probe port is outside the cutover contract")
    argv = [
        str(release_path / ".venv/bin/python"),
        "-m",
        "grabowski_client_snapshot",
        "probe-runtime",
        "--runtime-root",
        str(release_path),
        "--mcp-url",
        f"http://127.0.0.1:{port}/mcp",
        "--connector-token-file",
        str(TRANSPORT_CONNECTOR_TOKEN_PATH),
        "--auth-mode",
        auth_mode,
        "--expected-release-id",
        expected_release_id,
        "--expected-repo-head",
        expected_repo_head,
        "--expected-agent-instructions-sha256",
        expected_agent_instructions_sha256,
        "--timeout-seconds",
        str(min(timeout_seconds, 60)),
    ]
    result = core.run(
        argv,
        check=False,
        capture=True,
        timeout=min(timeout_seconds + 10, 70),
    )
    if result.returncode != 0:
        core.fail(
            "Runtime MCP readiness probe failed",
            phase="green-readiness",
            details={"returncode": result.returncode},
        )
    try:
        value = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError) as exc:
        core.fail(
            "Runtime MCP readiness probe returned invalid JSON",
            phase="green-readiness",
            details={"error_type": type(exc).__name__},
        )
    if not isinstance(value, dict) or value.get("ready") is not True:
        core.fail(
            "Runtime MCP readiness did not bind manifest/tools/schemas/instructions",
            phase="green-readiness",
            details={"readiness": value if isinstance(value, dict) else None},
        )
    return value


def _release_complete_schema_identity(
    *,
    release_path: Path,
    expected_tool_count: int,
    expected_names_sha256: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Derive the complete tool-schema identity from the immutable target release."""
    python = release_path / ".venv/bin/python"
    code = (
        "import json, grabowski_operator, grabowski_mcp; "
        "print(json.dumps(grabowski_mcp._runtime_connector_observed_tools(), sort_keys=True))"
    )
    result = core.run(
        [str(python), "-c", code],
        check=False,
        capture=True,
        cwd=release_path,
        timeout=min(timeout_seconds + 10, 70),
    )
    if result.returncode != 0:
        core.fail(
            "Target release schema identity derivation failed",
            phase="snapshot-authenticity-preflight",
            details={"returncode": result.returncode},
        )
    try:
        artifact = json.loads(result.stdout)
        _, _, metadata = connector_contract.parse_observed_artifact(
            artifact, label="target release schema artifact"
        )
    except (UnicodeError, json.JSONDecodeError, connector_contract.ConnectorContractError) as exc:
        core.fail(
            "Target release schema identity is invalid",
            phase="snapshot-authenticity-preflight",
            details={"error_type": type(exc).__name__},
        )
    if (
        metadata.get("complete_schema_observable") is not True
        or metadata.get("complete_schema_count") != expected_tool_count
        or metadata.get("name_count") != expected_tool_count
        or metadata.get("names_sha256") != expected_names_sha256
    ):
        core.fail(
            "Target release schema identity does not match the bound runtime contract",
            phase="snapshot-authenticity-preflight",
            details={
                "expected_tool_count": expected_tool_count,
                "target_tool_count": metadata.get("complete_schema_count"),
                "expected_names_sha256": expected_names_sha256,
                "target_names_sha256": metadata.get("names_sha256"),
            },
        )
    return metadata


def _selector_summary(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "selector_sha256": value.get("selector_sha256"),
        "generation": value.get("generation"),
        "selected_slot": value.get("selected_slot"),
        "upstream_port": value.get("upstream_port"),
        "runtime_binding_sha256": value.get("runtime_binding_sha256"),
        "cutover_id": value.get("cutover_id"),
        "previous_selector_sha256": value.get("previous_selector_sha256"),
        "release_id": value.get("runtime_binding", {}).get("release_id"),
        "repo_head": value.get("runtime_binding", {}).get("repo_head"),
    }


def _require_selector_authority(
    *,
    expected_selector_sha256: str,
    expected_slot: str,
    expected_binding_sha256: str,
) -> dict[str, Any]:
    selector = transport_ingress.read_routing_selector()
    health = require_transport_ingress_health()
    matched = (
        selector.get("selector_sha256") == expected_selector_sha256
        and selector.get("selected_slot") == expected_slot
        and selector.get("runtime_binding_sha256") == expected_binding_sha256
        and health.get("selector_authoritative") is True
        and health.get("selector_sha256") == expected_selector_sha256
        and health.get("selected_slot") == expected_slot
        and health.get("runtime_binding_sha256") == expected_binding_sha256
        and health.get("upstream_port")
        == transport_ingress.ROUTING_SLOTS[expected_slot]
    )
    if not matched:
        core.fail(
            "Ingress routing selector authoritative readback failed",
            phase="selector-readback",
            details={
                "selector": _selector_summary(selector),
                "health": {
                    key: health.get(key)
                    for key in (
                        "selector_authoritative",
                        "selector_sha256",
                        "selected_slot",
                        "upstream_port",
                        "runtime_binding_sha256",
                    )
                },
            },
        )
    material = {
        "authoritative": True,
        "selector": _selector_summary(selector),
        "ingress": {
            "selector_sha256": health.get("selector_sha256"),
            "selector_generation": health.get("selector_generation"),
            "selected_slot": health.get("selected_slot"),
            "upstream_port": health.get("upstream_port"),
            "runtime_binding_sha256": health.get("runtime_binding_sha256"),
            "release_id": health.get("release_id"),
            "repo_head": health.get("repo_head"),
        },
    }
    return {
        **material,
        "readback_sha256": hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest(),
    }


def observe_authoritative_routing() -> dict[str, Any]:
    """Read back whatever the ingress is authoritatively serving right now.

    Used on every abnormal exit of both the cutover and the resume, so it must
    answer rather than raise: a receipt that says "the readback failed" is worth
    more to an operator than an exception that says nothing at all.
    """
    try:
        selector = transport_ingress.read_routing_selector()
        return _require_selector_authority(
            expected_selector_sha256=selector["selector_sha256"],
            expected_slot=selector["selected_slot"],
            expected_binding_sha256=selector["runtime_binding_sha256"],
        )
    except Exception as exc:
        summary: dict[str, Any] | None = None
        try:
            summary = _selector_summary(transport_ingress.read_routing_selector())
        except Exception:
            pass
        return {
            "authoritative": False,
            "selector": summary,
            "error_type": type(exc).__name__,
            "requires_operator_recovery": True,
        }


@dataclass
class CanonicalPromotionProgress:
    """Irreversibility markers, each set *before* the effect it names.

    A promotion that reported "nothing happened" about a pointer it had already
    replaced would be the single worst answer available, so the marker is set
    first and cleared never.
    """

    pointer_promoted: bool = False
    canonical_selected: bool = False
    selector: dict[str, Any] | None = None


def promote_green_release_to_canonical(
    *,
    runtime: Path,
    release_path: Path,
    contract: core.RuntimeContract,
    green_binding: dict[str, str],
    activation: core.ActivationState | None,
    expected_green_selector_sha256: str,
    expected_green_binding_sha256: str,
    cutover_id: str,
    timeout_seconds: int,
    progress: CanonicalPromotionProgress,
    snapshot_effect_guard: Any | None = None,
) -> dict[str, Any]:
    """The one canonical promotion sequence, shared by cutover and resume.

    Both the productive cutover and the receipt-bound resume arrive at the same
    place -- green is serving, canonical must become green -- so they must get
    there by the same code.  Two implementations of this sequence would be two
    sets of ordering guarantees, and only one of them would be tested.

    Ordering is the guarantee: the stable pointer moves first, the canonical
    operator is proven to run the promoted release, and only a compare-and-swap
    that carries the exact green predecessor may select canonical.  Green stays
    the authoritative route for the entire operator restart.
    """
    # Immediately before the first irreversible effect, not merely at the start
    # of the phase: the deployment lock keeps other deploys out, but the
    # selector is a separate authority and a stale reading of it must not be
    # what a pointer swap is justified by.
    _require_selector_authority(
        expected_selector_sha256=expected_green_selector_sha256,
        expected_slot="green",
        expected_binding_sha256=expected_green_binding_sha256,
    )
    if activation is None:
        # A resume whose pointer was already promoted by an earlier attempt.
        # Re-running the swap would be a second irreversible effect for a state
        # that is already correct, so the step is skipped -- not faked.
        progress.pointer_promoted = True
    else:
        progress.pointer_promoted = True
        pointer_guard = (
            snapshot_effect_guard("pointer")
            if callable(snapshot_effect_guard)
            else nullcontext()
        )
        with pointer_guard:
            core.activate_pointer(activation)
    pointer_readback = midcutover.observe_stable_pointer(
        runtime, core.releases_root_for(runtime)
    )
    if (
        pointer_readback.get("error") is not None
        or pointer_readback.get("pointer_kind") != "symlink"
        or pointer_readback.get("release_id") != green_binding["release_id"]
        or pointer_readback.get("repo_head") != green_binding["repo_head"]
    ):
        core.fail(
            "Stable pointer promotion did not read back the exact target release",
            phase="canonical-promotion-pointer-readback",
            details={"pointer_readback": pointer_readback},
        )
    selector_guard = (
        snapshot_effect_guard("selector")
        if callable(snapshot_effect_guard)
        else nullcontext()
    )
    with selector_guard:
        # Admission stays engaged through the complete promotion where the caller
        # engaged it: while it is active neither the old canonical process nor the
        # transient green may admit a new normal tool call, so no effect can start
        # on green and then be cut off by retirement.
        stop_service(OPERATOR_SERVICE)
        ingress = observe_service(TRANSPORT_INGRESS_SERVICE)
        if not ingress.confirmed_active:
            start_service(TRANSPORT_INGRESS_SERVICE)
        _require_selector_authority(
            expected_selector_sha256=expected_green_selector_sha256,
            expected_slot="green",
            expected_binding_sha256=expected_green_binding_sha256,
        )
        start_service(OPERATOR_SERVICE)
        process = verify_operator_process(runtime, contract, release_hint=release_path)
        listener = _require_loopback_listener(
            OPERATOR_LISTENER_PORT, timeout_seconds=timeout_seconds
        )
        try:
            canonical = transport_ingress.publish_routing_selector(
                expected_selector_sha256=expected_green_selector_sha256,
                selected_slot="canonical",
                runtime_binding=green_binding,
                cutover_id=cutover_id,
            )
        except Exception:
            # The atomic replace may have landed even when its durable readback
            # failed. Only an unchanged, readable predecessor proves nothing moved.
            try:
                observed = transport_ingress.read_routing_selector()
            except Exception:
                progress.canonical_selected = True
            else:
                if observed.get("selector_sha256") != expected_green_selector_sha256:
                    progress.selector = observed
                    progress.canonical_selected = True
            raise
    progress.selector = canonical
    progress.canonical_selected = True
    final_readback = _require_selector_authority(
        expected_selector_sha256=canonical["selector_sha256"],
        expected_slot="canonical",
        expected_binding_sha256=canonical["runtime_binding_sha256"],
    )
    # Keep the already-verified green runtime available and admission closed
    # until canonical proves full MCP readiness through ingress.  Only the exact
    # read-only minimal status probe is drain-neutral.
    canonical_readiness = _probe_release_runtime(
        release_path=release_path,
        port=TRANSPORT_INGRESS_LISTENER_PORT,
        auth_mode="ingress",
        expected_release_id=green_binding["release_id"],
        expected_repo_head=green_binding["repo_head"],
        expected_agent_instructions_sha256=green_binding[
            "agent_instructions_sha256"
        ],
        timeout_seconds=timeout_seconds,
    )
    return {
        "promoted": True,
        "selector": canonical,
        "final_routing": _selector_summary(canonical),
        "authoritative_readback": final_readback,
        "canonical_readiness_sha256": _json_sha256(canonical_readiness),
        "operator": {"pid": process["pid"], "listener": listener},
        "activation_steps": list(activation.steps) if activation is not None else [],
        "pointer_activated_now": activation is not None,
        "pointer_readback": pointer_readback,
    }


@dataclass
class ProductionBlueGreenRuntime:
    repo: Path
    runtime: Path
    snapshot: core.Snapshot
    build: core.BuildResult
    activation: core.ActivationState
    blue_manifest: dict[str, Any]
    blue_binding: dict[str, str]
    green_binding: dict[str, str]
    selector_before: dict[str, Any]
    cutover_id: str
    timeout_seconds: int
    green_unit: str
    watchdog_projection: WatchdogHostAssetProjection | None = None
    observer_repair: dict[str, Any] | None = None
    admission_marker: dict[str, Any] | None = None
    green_started: bool = False
    connector_switched: bool = False
    current_selector: dict[str, Any] | None = None
    green_readiness: dict[str, Any] | None = None
    platform_publication: dict[str, Any] | None = None
    source_complete_schema_sha256: str | None = None
    snapshot_rebind_mode: str = "external_client"
    deployment_source_identity_sha256: str | None = None
    promotion_progress: CanonicalPromotionProgress = field(
        default_factory=CanonicalPromotionProgress
    )

    def start_green(self) -> dict[str, Any]:
        core.verify_apply_snapshot_unchanged(
            self.repo, self.snapshot, self.build.release_path
        )
        self.watchdog_projection = install_watchdog_host_assets(
            self.repo, self.snapshot
        )
        self.observer_repair = install_safety_observer_unit(
            self.repo, self.snapshot
        )
        # From this point forward the start call may already have created the
        # transient systemd unit even if a later service/argv/exe/listener
        # verification raises. Mark the possible effect before dispatch so the
        # pre-cutover rollback always attempts authoritative Green retirement.
        self.green_started = True
        result = _start_green_operator(
            unit=self.green_unit,
            release_path=self.build.release_path,
            contract=self.snapshot.contract,
            timeout_seconds=self.timeout_seconds,
        )
        return result

    def verify_green(self) -> dict[str, Any]:
        target_schema = _release_complete_schema_identity(
            release_path=self.build.release_path,
            expected_tool_count=len(self.snapshot.contract.expected_tools),
            expected_names_sha256=self.green_binding["registered_names_sha256"],
            timeout_seconds=self.timeout_seconds,
        )
        readiness = _probe_release_runtime(
            release_path=self.build.release_path,
            port=GREEN_OPERATOR_LISTENER_PORT,
            auth_mode="connector",
            expected_release_id=self.build.release_id,
            expected_repo_head=self.snapshot.repo_head,
            expected_agent_instructions_sha256=self.build.agent_instructions[
                "sha256"
            ],
            timeout_seconds=self.timeout_seconds,
        )
        if (
            readiness.get("complete_schema_count")
            != len(self.snapshot.contract.expected_tools)
            or readiness.get("complete_schema_sha256")
            != target_schema.get("complete_schema_sha256")
        ):
            core.fail(
                "Green complete schema identity differs from the exact target release",
                phase="snapshot-authenticity-preflight",
                details={
                    "target_complete_schema_sha256": target_schema.get(
                        "complete_schema_sha256"
                    ),
                    "green_complete_schema_sha256": readiness.get(
                        "complete_schema_sha256"
                    ),
                    "blue_continuity_complete_schema_sha256": self.source_complete_schema_sha256,
                },
            )
        self.green_readiness = readiness
        return readiness

    def _blue_platform_publication_contract(self) -> dict[str, Any]:
        if self.source_complete_schema_sha256 is None:
            core.fail(
                "Blue complete schema identity is unavailable for platform publication recovery",
                phase="platform-publication-preflight",
            )
        return client_snapshot._platform_publication_contract(
            registered_tool_count=len(self.snapshot.contract.expected_tools),
            registered_names_sha256=self.blue_binding["registered_names_sha256"],
            complete_schema_count=len(self.snapshot.contract.expected_tools),
            complete_schema_sha256=self.source_complete_schema_sha256,
        )

    def prepare_platform_publication(self) -> dict[str, Any]:
        if self.green_readiness is None:
            core.fail(
                "Green readiness is unavailable for platform publication preparation",
                phase="platform-publication-preflight",
            )
        result = client_snapshot.prepare_platform_publication_for_runtime(
            registered_tool_count=len(self.snapshot.contract.expected_tools),
            registered_names_sha256=self.green_binding["registered_names_sha256"],
            complete_schema_count=self.green_readiness["complete_schema_count"],
            complete_schema_sha256=self.green_readiness["complete_schema_sha256"],
            cutover_id=self.cutover_id,
        )
        self.platform_publication = result
        return result

    def activate_platform_publication(self) -> dict[str, Any]:
        publication = self.platform_publication
        if not isinstance(publication, dict):
            core.fail(
                "Platform publication preflight evidence is unavailable",
                phase="platform-publication-activation",
            )
        request_id = publication.get("request_id")
        if request_id is None:
            return {
                "state": publication.get("state"),
                "request_id": None,
                "activation_required": False,
            }
        if publication.get("state") != "pending_activation":
            return {
                "state": publication.get("state"),
                "request_id": request_id,
                "activation_required": False,
            }
        activated = client_snapshot.activate_platform_publication_request(
            request_id=request_id
        )
        self.platform_publication = {**publication, "activation": activated}
        return activated

    def rollback_platform_publication(self) -> dict[str, Any]:
        publication = self.platform_publication
        if (
            not isinstance(publication, dict)
            or publication.get("state") != "pending_activation"
            or publication.get("reused") is True
            or publication.get("request_id") is None
        ):
            return {"state": "no_prepared_request_effect"}
        return client_snapshot.rollback_platform_publication_request(
            request_id=publication["request_id"],
            active_contract=self._blue_platform_publication_contract(),
        )

    def close_blue_mutations(self) -> dict[str, Any]:
        if self.deployment_source_identity_sha256 is None:
            self.admission_marker = engage_operator_deployment_admission(
                self.snapshot, timeout_seconds=self.timeout_seconds
            )
        else:
            self.admission_marker = engage_operator_deployment_admission(
                self.snapshot,
                timeout_seconds=self.timeout_seconds,
                source_identity_sha256=self.deployment_source_identity_sha256,
            )
        return {
            "closed": True,
            "marker_sha256": hashlib.sha256(
                json.dumps(
                    self.admission_marker,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "expected_head": self.admission_marker["expected_head"],
            "source_identity_sha256": self.admission_marker[
                "source_identity_sha256"
            ],
        }

    def terminalize_blue_effects(self) -> dict[str, Any]:
        if self.admission_marker is None:
            core.fail("Blue operator admission marker is not engaged")
        drained = wait_for_operator_deployment_admission(
            self.admission_marker, timeout_seconds=self.timeout_seconds
        )
        final = verify_operator_deployment_admission(self.admission_marker)
        observation = drained.get("observation")
        return {
            **drained,
            "terminalized_count": drained.get("initial_blocking_tool_calls", 0),
            "remaining_read_count": drained.get("read_only_active_tool_calls"),
            "operator_observation_sha256": hashlib.sha256(
                json.dumps(
                    observation,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "final_guard_sha256": hashlib.sha256(
                json.dumps(final, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest(),
            "registry_authority": "grabowski_operator_cross_process_status",
        }

    def switch_connector(self) -> dict[str, Any]:
        current_sha = self.selector_before["selector_sha256"]
        try:
            selected = transport_ingress.publish_routing_selector(
                expected_selector_sha256=current_sha,
                selected_slot="green",
                runtime_binding=self.green_binding,
                cutover_id=self.cutover_id,
            )
        except Exception:
            # The atomic replace may have succeeded even when its durable
            # readback failed.  Only an unchanged, readable predecessor proves
            # this is still a pre-switch failure; every other state is
            # externally ambiguous and must prohibit automatic rollback.
            try:
                observed = transport_ingress.read_routing_selector()
            except Exception:
                self.connector_switched = True
            else:
                if observed.get("selector_sha256") != current_sha:
                    self.current_selector = observed
                    self.connector_switched = True
            raise
        self.current_selector = selected
        self.connector_switched = True
        readback = _require_selector_authority(
            expected_selector_sha256=selected["selector_sha256"],
            expected_slot="green",
            expected_binding_sha256=selected["runtime_binding_sha256"],
        )
        connector_readiness = _probe_release_runtime(
            release_path=self.build.release_path,
            port=TRANSPORT_INGRESS_LISTENER_PORT,
            auth_mode="ingress",
            expected_release_id=self.build.release_id,
            expected_repo_head=self.snapshot.repo_head,
            expected_agent_instructions_sha256=self.build.agent_instructions[
                "sha256"
            ],
            timeout_seconds=self.timeout_seconds,
        )
        return {
            "switched": True,
            **_selector_summary(selected),
            "authoritative_readback": readback,
            "connector_readiness_sha256": hashlib.sha256(
                json.dumps(
                    connector_readiness,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }

    def rebind_snapshot(
        self, cutover_id: str, cutover_generation: int
    ) -> dict[str, Any]:
        if self.green_readiness is None:
            core.fail("Green readiness is unavailable for snapshot rebind")
        if self.snapshot_rebind_mode == "external_client":
            rebind = client_snapshot.rebind_authentic_snapshot_for_cutover
        elif self.snapshot_rebind_mode == "server_loopback_continuity":
            rebind = client_snapshot.rebind_server_loopback_snapshot_for_cutover
        else:
            core.fail(
                "Blue-green snapshot rebind mode is invalid",
                phase="snapshot-authenticity-preflight",
                details={"snapshot_rebind_mode": self.snapshot_rebind_mode},
            )
        result = rebind(
            cutover_id=cutover_id,
            cutover_generation=cutover_generation,
            current_release_id=self.blue_binding["release_id"],
            current_repo_head=self.blue_binding["repo_head"],
            green_release_id=self.green_binding["release_id"],
            green_repo_head=self.green_binding["repo_head"],
            registered_tool_count=len(self.snapshot.contract.expected_tools),
            registered_names_sha256=self.green_binding[
                "registered_names_sha256"
            ],
            agent_instructions_sha256=self.green_binding[
                "agent_instructions_sha256"
            ],
            green_readiness=self.green_readiness,
        )
        return {**result, "platform_publication": self.platform_publication}

    def retire_blue(self) -> dict[str, Any]:
        if not self.connector_switched or self.current_selector is None:
            core.fail("Connector is not confirmed green before canonical promotion")
        core.verify_apply_snapshot_unchanged(
            self.repo, self.snapshot, self.build.release_path
        )
        promotion = promote_green_release_to_canonical(
            runtime=self.runtime,
            release_path=self.build.release_path,
            contract=self.snapshot.contract,
            green_binding=self.green_binding,
            activation=self.activation,
            expected_green_selector_sha256=self.current_selector["selector_sha256"],
            expected_green_binding_sha256=self.current_selector[
                "runtime_binding_sha256"
            ],
            cutover_id=self.cutover_id,
            timeout_seconds=self.timeout_seconds,
            progress=self.promotion_progress,
        )
        canonical = promotion["selector"]
        self.current_selector = canonical
        final_readback = promotion["authoritative_readback"]
        green_retirement = _stop_green_operator(self.green_unit)
        self.green_started = False
        admission_release = None
        if self.admission_marker is not None:
            admission_release = release_operator_deployment_admission(
                self.admission_marker
            )
            self.admission_marker = None
        require_service_active(TRANSPORT_INGRESS_SERVICE)
        require_service_active(TUNNEL_SERVICE)
        identity = verify_url_runtime_identity(
            self.build.release_path,
            self.runtime,
            self.snapshot.contract,
            snapshot=self.snapshot,
            agent_instructions=self.build.agent_instructions,
        )
        return {
            "retired": True,
            "blue_operator_replaced": True,
            "green_retirement": green_retirement,
            "admission_release": admission_release,
            "final_routing": promotion["final_routing"],
            "authoritative_readback": final_readback,
            "canonical_readiness_sha256": promotion["canonical_readiness_sha256"],
            "runtime_identity": {
                "pid": identity["process"]["pid"],
                "release_id": identity["manifest"]["release_id"],
                "repo_head": identity["manifest"]["repo_head"],
            },
        }

    def rollback_green(self) -> dict[str, Any]:
        if self.connector_switched:
            core.fail(
                "Automatic rollback is forbidden after connector switch",
                phase="post-cutover-rollback-forbidden",
            )
        result: dict[str, Any] = {"blue_preserved": True}
        if self.admission_marker is not None:
            release_operator_deployment_admission(self.admission_marker)
            self.admission_marker = None
            result["admission_released"] = True
        if self.green_started:
            result["green"] = _stop_green_operator(self.green_unit)
            self.green_started = False
        if self.watchdog_projection is not None:
            restore_watchdog_host_assets(self.watchdog_projection)
            result["watchdog_host_assets"] = "restored"
        return result

    def authoritative_readback(self) -> dict[str, Any]:
        return observe_authoritative_routing()


def prepare_production_blue_green_runtime(
    repo: Path,
    runtime: Path,
    profile_path: Path,
    *,
    expected_head: str,
    cutover_id: str,
    timeout_seconds: int,
    deployment_source_identity_sha256: str | None = None,
) -> ProductionBlueGreenRuntime:
    snapshot, runtime, topology = preflight_url(
        repo,
        runtime,
        profile_path,
        expected_head=expected_head,
    )
    if (
        topology.kind != "url"
        or topology.server_url_port != TRANSPORT_INGRESS_LISTENER_PORT
    ):
        core.fail(
            "Productive blue-green deployment requires signed ingress topology",
            phase="blue-green-topology",
        )
    require_service_active(TRANSPORT_INGRESS_SERVICE)
    blue_manifest = core.read_manifest(runtime)
    blue_binding, _ = transport_ingress._read_runtime_binding(
        runtime / core.MANIFEST_NAME
    )
    selector_before = transport_ingress.read_routing_selector()
    if (
        selector_before.get("selected_slot") != "canonical"
        or selector_before.get("runtime_binding") != blue_binding
    ):
        core.fail(
            "Productive blue-green deployment requires canonical blue selector",
            phase="selector-preflight",
            details={"selector": _selector_summary(selector_before)},
        )
    _require_selector_authority(
        expected_selector_sha256=selector_before["selector_sha256"],
        expected_slot="canonical",
        expected_binding_sha256=selector_before["runtime_binding_sha256"],
    )
    build = core.build_release(
        snapshot, core.releases_root_for(runtime), runtime
    )
    core.verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)
    core.verify_manifest(
        build.release_path,
        snapshot=snapshot,
        stable_runtime=runtime,
        expected_agent_instructions=build.agent_instructions,
    )
    green_binding, _ = transport_ingress._read_runtime_binding(
        build.release_path / core.MANIFEST_NAME
    )
    if (
        blue_binding["registered_names_sha256"]
        != green_binding["registered_names_sha256"]
        or blue_binding["agent_instructions_sha256"]
        != green_binding["agent_instructions_sha256"]
    ):
        core.fail(
            "No authentic prior connector declaration covers the changed green surface",
            phase="snapshot-authenticity-preflight",
        )
    blue_entrypoint = blue_manifest.get("entrypoint_contract")
    blue_tools = (
        blue_entrypoint.get("expected_tools")
        if isinstance(blue_entrypoint, dict)
        else None
    )
    green_tools = list(snapshot.contract.expected_tools)
    if (
        not isinstance(blue_tools, list)
        or any(not isinstance(name, str) for name in blue_tools)
        or sorted(blue_tools) != sorted(green_tools)
    ):
        core.fail(
            "Blue and green tool-name continuity is unavailable",
            phase="snapshot-authenticity-preflight",
        )
    snapshot_status = client_snapshot.snapshot_status(
        expected_tool_count=len(blue_tools),
        expected_names_sha256=blue_binding["registered_names_sha256"],
        expected_release_id=blue_binding["release_id"],
        expected_repo_head=blue_binding["repo_head"],
        expected_agent_instructions_sha256=blue_binding[
            "agent_instructions_sha256"
        ],
    )
    receipt_sha256 = snapshot_status.get("receipt_sha256")
    client_declaration_sha256 = snapshot_status.get("client_declaration_sha256")
    receipt_evidence_valid = (
        isinstance(receipt_sha256, str)
        and isinstance(client_declaration_sha256, str)
        and len(set(receipt_sha256)) > 1
        and len(set(client_declaration_sha256)) > 1
    )
    external_snapshot_usable = (
        snapshot_status.get("external_client_snapshot_observable") is True
        and snapshot_status.get("external_client_schema_observable") is True
        and snapshot_status.get("client_observed_release_id")
        == blue_binding["release_id"]
        and snapshot_status.get("external_client_complete_schema_observable")
        is True
        and snapshot_status.get("external_client_complete_schema_count")
        == len(blue_tools)
        and isinstance(
            snapshot_status.get("external_client_complete_schema_sha256"), str
        )
        and receipt_evidence_valid
    )
    loopback_snapshot_usable = (
        snapshot_status.get("server_loopback_observable") is True
        and snapshot_status.get("server_loopback_schema_observable") is True
        and snapshot_status.get("server_loopback_schema_contract_matches") is True
        and snapshot_status.get("client_observed_release_id")
        == blue_binding["release_id"]
        and snapshot_status.get("server_loopback_complete_schema_observable")
        is True
        and snapshot_status.get("server_loopback_complete_schema_count")
        == len(blue_tools)
        and isinstance(
            snapshot_status.get("server_loopback_complete_schema_sha256"), str
        )
        and receipt_evidence_valid
    )
    if external_snapshot_usable:
        snapshot_rebind_mode = "external_client"
        source_complete_schema_sha256 = snapshot_status[
            "external_client_complete_schema_sha256"
        ]
    elif loopback_snapshot_usable:
        # A verified Blue loopback receipt may prove that Green preserves the
        # exact already-serving surface.  It never proves platform publication;
        # that independent status remains stale/mismatched until externally
        # observed evidence converges.
        snapshot_rebind_mode = "server_loopback_continuity"
        source_complete_schema_sha256 = snapshot_status[
            "server_loopback_complete_schema_sha256"
        ]
    else:
        core.fail(
            "Authentic Blue connector continuity snapshot is unavailable",
            phase="snapshot-authenticity-preflight",
            details={
                "state": snapshot_status.get("state"),
                "observation_scope": snapshot_status.get("observation_scope"),
                "client_observed_release_id": snapshot_status.get(
                    "client_observed_release_id"
                ),
                "expected_blue_release_id": blue_binding["release_id"],
                "external_schema_observable": snapshot_status.get(
                    "external_client_schema_observable"
                ),
                "server_loopback_schema_observable": snapshot_status.get(
                    "server_loopback_schema_observable"
                ),
            },
        )
    activation = core.ActivationState(
        runtime=runtime,
        release_path=build.release_path,
        previous=core.capture_pointer(runtime),
    )
    return ProductionBlueGreenRuntime(
        repo=repo,
        runtime=runtime,
        snapshot=snapshot,
        build=build,
        activation=activation,
        blue_manifest=blue_manifest,
        blue_binding=blue_binding,
        green_binding=green_binding,
        selector_before=selector_before,
        cutover_id=cutover_id,
        timeout_seconds=timeout_seconds,
        green_unit=_green_operator_unit(cutover_id),
        current_selector=selector_before,
        source_complete_schema_sha256=source_complete_schema_sha256,
        snapshot_rebind_mode=snapshot_rebind_mode,
        deployment_source_identity_sha256=deployment_source_identity_sha256,
    )


def initialize_canonical_ingress_selector(
    *,
    release_path: Path,
    cutover_id: str,
) -> dict[str, Any]:
    """Explicit bootstrap/recovery initialization while ingress is stopped."""
    binding, _ = transport_ingress._read_runtime_binding(
        release_path / core.MANIFEST_NAME
    )
    try:
        current = transport_ingress.read_routing_selector()
        expected = current["selector_sha256"]
    except transport_ingress.IngressConfigurationError:
        if (
            transport_ingress.DEFAULT_SELECTOR_FILE.exists()
            or transport_ingress.DEFAULT_SELECTOR_FILE.is_symlink()
        ):
            raise
        expected = None
    return transport_ingress.publish_routing_selector(
        expected_selector_sha256=expected,
        selected_slot="canonical",
        runtime_binding=binding,
        cutover_id=cutover_id,
    )


BLUE_GREEN_RECEIPT_ROOT = (
    core.DEFAULT_STATE_ROOT / "blue-green-deployment-receipts"
)
BLUE_GREEN_RECEIPT_MAX_BYTES = 256 * 1024


class ProductionBlueGreenReceiptPersistenceError(RuntimeError):
    """The cutover outcome is known in memory but its primary receipt was not persisted."""

    def __init__(self, receipt: dict[str, Any], cause: BaseException) -> None:
        self.receipt = dict(receipt)
        self.receipt_sha256 = str(receipt.get("receipt_sha256") or "")
        self.outcome = str(receipt.get("outcome") or "")
        self.persistence_error_type = type(cause).__name__
        super().__init__(
            "productive blue-green cutover receipt persistence failed after outcome observation"
        )


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _persist_production_blue_green_receipt(
    receipt: dict[str, Any],
) -> dict[str, str]:
    return _persist_blue_green_receipt_document(
        receipt, identifier=receipt.get("cutover_id"), label="cutover id"
    )


def _persist_blue_green_receipt_document(
    receipt: dict[str, Any],
    *,
    identifier: Any,
    label: str,
) -> dict[str, str]:
    root = BLUE_GREEN_RECEIPT_ROOT
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = root.lstat()
    if (
        statmod.S_ISLNK(metadata.st_mode)
        or not statmod.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or statmod.S_IMODE(metadata.st_mode) & 0o077
        or root.resolve(strict=True) != root
    ):
        core.fail(
            "Blue-green receipt directory is not private and owner-controlled",
            phase="blue-green-receipt",
        )
    cutover_id = identifier
    if (
        not isinstance(cutover_id, str)
        or re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", cutover_id) is None
    ):
        core.fail(f"Blue-green receipt {label} is invalid")
    encoded = (
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    if len(encoded) > BLUE_GREEN_RECEIPT_MAX_BYTES:
        core.fail("Blue-green receipt exceeds its size bound")
    path = root / f"{cutover_id}.json"
    create_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    created = False
    try:
        descriptor = os.open(path, create_flags, 0o600)
    except FileExistsError:
        descriptor = None
    else:
        created = True
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("blue-green receipt write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_parent(path)

    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.getuid()
            or statmod.S_IMODE(opened.st_mode) & 0o077
            or opened.st_size > BLUE_GREEN_RECEIPT_MAX_BYTES
        ):
            core.fail(
                "Blue-green receipt file is not private and owner-controlled",
                phase="blue-green-receipt",
            )
        observed = os.read(descriptor, BLUE_GREEN_RECEIPT_MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if observed != encoded:
        core.fail(
            (
                "Blue-green receipt readback mismatch"
                if created
                else "Blue-green cutover id already binds different receipt evidence"
            ),
            phase="blue-green-receipt",
        )
    return {
        "path": str(path),
        "receipt_sha256": str(receipt["receipt_sha256"]),
    }


def _blue_green_observation(
    observations: list[dict[str, Any]],
    *,
    phase: str,
    details: dict[str, Any] | None = None,
) -> None:
    material = {
        "phase": phase,
        "observed_at_unix": int(time.time()),
        "details": details or {},
    }
    observations.append({**material, "observation_sha256": _json_sha256(material)})


def _production_blue_green_receipt(
    *,
    runtime: ProductionBlueGreenRuntime,
    source_identity_sha256: str,
    phase: str,
    outcome: str,
    observations: list[dict[str, Any]],
    green_readiness: dict[str, Any] | None,
    drain: dict[str, Any] | None,
    selector_switch: dict[str, Any] | None,
    snapshot_rebind: dict[str, Any] | None,
    retirement: dict[str, Any] | None,
    readback: dict[str, Any] | None,
    recovery: dict[str, Any] | None,
) -> dict[str, Any]:
    material = {
        "schema_version": 1,
        "kind": "grabowski_blue_green_deployment_receipt",
        "cutover_id": runtime.cutover_id,
        "cutover_generation": 1,
        "expected_head": runtime.snapshot.repo_head,
        "source_identity_sha256": source_identity_sha256,
        "runtime_snapshot_source_identity_sha256": (
            _deployment_source_identity_sha256(runtime.snapshot)
        ),
        "blue_release_id": runtime.blue_binding["release_id"],
        "green_release_id": runtime.green_binding["release_id"],
        "names_sha256": runtime.green_binding["registered_names_sha256"],
        "agent_instructions_sha256": runtime.green_binding[
            "agent_instructions_sha256"
        ],
        "schema_sentinels": sorted(connector_contract.REQUIRED_SCHEMA_SENTINELS),
        "phase": phase,
        "outcome": outcome,
        "green_readiness": green_readiness,
        "selector_switch": selector_switch,
        "snapshot_rebind": snapshot_rebind,
        "effect_terminalization": drain,
        "retirement": retirement,
        "final_routing": (
            retirement.get("final_routing")
            if isinstance(retirement, dict)
            else None
        ),
        "authoritative_readback": readback,
        "observations": observations,
        "recovery": recovery,
        "preserves": [
            "source_identity",
            "deployment_lock",
            "contention_preflight",
            "watchdog_assets",
            "transport_oauth",
            "signed_mutation_assertions",
            "sidecar_reconciliation",
            "runtime_manifest_and_provenance",
            "audit_and_recovery_gates",
        ],
        "does_not_establish": [
            "that the external client refreshed against green",
            "application success of settled admitted mutations",
            "absence of long-lived read calls at blue retirement",
        ],
    }
    return {**material, "receipt_sha256": _json_sha256(material)}


def _production_blue_green_preflight_failure_receipt(
    *,
    cutover_id: str,
    expected_head: str,
    source_identity_sha256: str,
    error: dict[str, Any],
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    material = {
        "schema_version": 1,
        "kind": "grabowski_blue_green_deployment_receipt",
        "cutover_id": cutover_id,
        "cutover_generation": 1,
        "expected_head": expected_head,
        "source_identity_sha256": source_identity_sha256,
        "runtime_snapshot_source_identity_sha256": None,
        "blue_release_id": None,
        "green_release_id": None,
        "names_sha256": None,
        "agent_instructions_sha256": None,
        "schema_sentinels": sorted(connector_contract.REQUIRED_SCHEMA_SENTINELS),
        "phase": "failed_pre_cutover",
        "outcome": "failed_pre_cutover",
        "green_readiness": None,
        "selector_switch": None,
        "snapshot_rebind": None,
        "effect_terminalization": None,
        "retirement": None,
        "final_routing": None,
        "authoritative_readback": None,
        "observations": observations,
        "recovery": {
            "action": "repair_preflight_evidence_and_retry",
            "blue_preserved": True,
            "connector_switch_attempted": False,
            "error": error,
        },
        "preserves": [
            "source_identity",
            "deployment_lock",
            "transport_oauth",
            "signed_mutation_assertions",
            "runtime_manifest_and_provenance",
        ],
        "does_not_establish": [
            "green runtime readiness",
            "connector switch",
            "client snapshot rebind",
            "deployment completion",
        ],
    }
    return {**material, "receipt_sha256": _json_sha256(material)}


def run_production_blue_green_cutover(
    *,
    repo: Path,
    expected_head: str,
    source_identity_sha256: str,
    timeout_seconds: int = 40,
    runtime: Path | None = None,
    profile_path: Path | None = None,
    lock_file: Path | None = None,
    cutover_id: str | None = None,
) -> dict[str, Any]:
    """Run the normal productive receipt-bound cutover under the deploy lock."""
    if re.fullmatch(r"[0-9a-f]{64}", source_identity_sha256 or "") is None:
        raise ValueError("source_identity_sha256 must be a lowercase SHA-256")
    identifier = cutover_id or f"bgc-{secrets.token_hex(8)}"
    if re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", identifier) is None:
        raise ValueError("cutover_id is invalid")
    target_runtime = runtime or (core.HOME / ".local/share/grabowski-mcp")
    target_profile = profile_path or core.DEFAULT_PROFILE_PATH
    target_lock = lock_file or core.DEFAULT_LOCK_FILE
    observations: list[dict[str, Any]] = []
    context: ProductionBlueGreenRuntime | None = None
    phase = "prepare"
    green_readiness: dict[str, Any] | None = None
    drain: dict[str, Any] | None = None
    selector_switch: dict[str, Any] | None = None
    snapshot_rebind: dict[str, Any] | None = None
    retirement: dict[str, Any] | None = None
    readback: dict[str, Any] | None = None
    recovery: dict[str, Any] | None = None
    outcome = "failed_pre_cutover"
    error: dict[str, Any] | None = None
    with core.deployment_lock(target_lock):
        try:
            context = prepare_production_blue_green_runtime(
                repo,
                target_runtime,
                target_profile,
                expected_head=expected_head,
                cutover_id=identifier,
                timeout_seconds=timeout_seconds,
                deployment_source_identity_sha256=source_identity_sha256,
            )
        except Exception as exc:
            error = _error_summary(exc)
            _blue_green_observation(
                observations,
                phase="failed_pre_cutover",
                details={"error_type": error.get("type")},
            )
            receipt = _production_blue_green_preflight_failure_receipt(
                cutover_id=identifier,
                expected_head=expected_head,
                source_identity_sha256=source_identity_sha256,
                error=error,
                observations=observations,
            )
            persisted = _persist_production_blue_green_receipt(receipt)
            return {
                "receipt": receipt,
                "receipt_path": persisted["path"],
                "receipt_sha256": persisted["receipt_sha256"],
                "outcome": "failed_pre_cutover",
                "error": error,
            }
        _blue_green_observation(observations, phase=phase)
        try:
            phase = "start_green"
            started = context.start_green()
            _blue_green_observation(
                observations, phase=phase, details={"start": started}
            )
            phase = "verify_green"
            green_readiness = context.verify_green()
            _blue_green_observation(
                observations,
                phase=phase,
                details={
                    "ready": True,
                    "readiness_sha256": _json_sha256(green_readiness),
                },
            )
            phase = "platform_publication_preflight"
            platform_publication = context.prepare_platform_publication()
            _blue_green_observation(
                observations,
                phase=phase,
                details={
                    "state": platform_publication.get("state"),
                    "request_id": platform_publication.get("request_id"),
                    "contract_sha256": (
                        platform_publication.get("contract", {}).get("tool_contract_sha256")
                        if isinstance(platform_publication.get("contract"), dict)
                        else None
                    ),
                },
            )
            phase = "pre_cutover_ready"
            closed = context.close_blue_mutations()
            drain = context.terminalize_blue_effects()
            _blue_green_observation(
                observations,
                phase=phase,
                details={
                    "close": closed,
                    "drain_sha256": _json_sha256(drain),
                },
            )
            phase = "cutover"
            selector_switch = context.switch_connector()
            phase = "platform_publication_activation"
            publication_activation = context.activate_platform_publication()
            _blue_green_observation(
                observations,
                phase=phase,
                details={
                    "state": publication_activation.get("state"),
                    "request_id": publication_activation.get("request_id"),
                },
            )
            phase = "snapshot_rebind"
            snapshot_rebind = context.rebind_snapshot(identifier, 1)
            _blue_green_observation(
                observations,
                phase=phase,
                details={
                    "selector_sha256": selector_switch.get("selector_sha256"),
                    "snapshot_receipt_sha256": snapshot_rebind.get(
                        "receipt_sha256"
                    ),
                },
            )
            phase = "retire_blue"
            retirement = context.retire_blue()
            readback = context.authoritative_readback()
            if readback.get("authoritative") is not True:
                core.fail(
                    "Final canonical routing readback is not authoritative",
                    phase="final-routing-readback",
                )
            _blue_green_observation(
                observations,
                phase=phase,
                details={
                    "final_selector_sha256": retirement.get(
                        "final_routing", {}
                    ).get("selector_sha256"),
                    "readback_sha256": readback.get("readback_sha256"),
                },
            )
            phase = "completed"
            outcome = "completed"
            _blue_green_observation(observations, phase=phase)
        except Exception as exc:
            error = _error_summary(exc)
            if context.connector_switched:
                outcome = "outcome_unknown"
                phase = "outcome_unknown"
                readback = context.authoritative_readback()
                recovery = {
                    "action": "readback_active_runtime_and_recover",
                    "automatic_rollback_forbidden": True,
                    "error": error,
                }
            else:
                try:
                    rollback = context.rollback_green()
                    publication_rollback = context.rollback_platform_publication()
                    outcome = "rolled_back"
                    phase = "rolled_back"
                    readback = context.authoritative_readback()
                    recovery = {
                        "action": "retry_from_clean_blue",
                        "blue_preserved": True,
                        "rollback": rollback,
                        "platform_publication_rollback": publication_rollback,
                        "error": error,
                    }
                except Exception as rollback_error:
                    outcome = "outcome_unknown"
                    phase = "outcome_unknown"
                    readback = context.authoritative_readback()
                    recovery = {
                        "action": "inspect_blue_and_green_runtimes",
                        "automatic_rollback_forbidden": True,
                        "error": error,
                        "rollback_error": _error_summary(rollback_error),
                    }
            _blue_green_observation(
                observations,
                phase=phase,
                details={
                    "error_type": error.get("type") if isinstance(error, dict) else None,
                    "readback_sha256": (
                        readback.get("readback_sha256")
                        if isinstance(readback, dict)
                        else None
                    ),
                },
            )
    assert context is not None
    receipt = _production_blue_green_receipt(
        runtime=context,
        source_identity_sha256=source_identity_sha256,
        phase=phase,
        outcome=outcome,
        observations=observations,
        green_readiness=green_readiness,
        drain=drain,
        selector_switch=selector_switch,
        snapshot_rebind=snapshot_rebind,
        retirement=retirement,
        readback=readback,
        recovery=recovery,
    )
    try:
        persisted = _persist_production_blue_green_receipt(receipt)
    except Exception as exc:
        # All runtime effects and the authoritative readback have already been
        # classified into the hash-bound receipt above.  Preserve that evidence
        # across a storage failure so the scheduled wrapper cannot collapse an
        # applied or ambiguous cutover into a generic retryable failure.
        raise ProductionBlueGreenReceiptPersistenceError(receipt, exc) from exc
    return {
        "receipt": receipt,
        "receipt_path": persisted["path"],
        "receipt_sha256": persisted["receipt_sha256"],
        "receipt_persisted": True,
        "outcome": outcome,
        "error": error,
    }






MIDCUTOVER_RESUME_RECEIPT_KIND = midcutover.RESUME_RECEIPT_KIND
MIDCUTOVER_RESUME_ID_PREFIX = "bgcr-"


class MidCutoverResumeDenied(RuntimeError):
    """The durable state does not admit a receipt-bound mid-cutover resume."""

    def __init__(self, classification: dict[str, Any]) -> None:
        self.classification = classification
        super().__init__(
            "mid-cutover resume denied: "
            + ",".join(classification.get("reasons") or ["unclassified"])
        )


RELEASE_SNAPSHOT_CONTRACT_KEY = "runtime_entrypoint"

_HISTORICAL_CONTRACT_REQUIRED = {
    1: frozenset({"schema_version", "mode", "module", "source", "expected_tools"}),
    2: frozenset(
        {
            "schema_version",
            "mode",
            "module",
            "source",
            "expected_tools",
            "supporting_sources",
        }
    ),
    3: frozenset(
        {
            "schema_version",
            "mode",
            "module",
            "source",
            "expected_tools",
            "supporting_sources",
            "runtime_assets",
        }
    ),
    4: frozenset(
        {
            "schema_version",
            "mode",
            "module",
            "source",
            "expected_tools",
            "supporting_sources",
            "runtime_assets",
            "spawn_dependencies",
        }
    ),
}
_HISTORICAL_CONTRACT_OPTIONAL = {4: frozenset({"browser_operator_default"})}
_HISTORICAL_MODULE_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z"
)


def _historical_contract_path(value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        core.fail(
            f"Historical runtime contract {label} is invalid",
            phase="midcutover-resume-preflight",
        )
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != value
        or value == "."
    ):
        core.fail(
            f"Historical runtime contract {label} is not a canonical relative path",
            phase="midcutover-resume-preflight",
        )
    return Path(value)


def _decode_historical_runtime_contract(raw: Any) -> core.RuntimeContract:
    """Decode immutable v1-v4 contracts without consulting the live checkout schema."""
    if not isinstance(raw, dict):
        core.fail(
            "Green release contract snapshot is not an object",
            phase="midcutover-resume-preflight",
        )
    version = raw.get("schema_version")
    if isinstance(version, bool) or version not in _HISTORICAL_CONTRACT_REQUIRED:
        core.fail(
            "Green release contract schema version is unsupported",
            phase="midcutover-resume-preflight",
            details={"schema_version": version},
        )
    required = _HISTORICAL_CONTRACT_REQUIRED[version]
    optional = _HISTORICAL_CONTRACT_OPTIONAL.get(version, frozenset())
    if frozenset(raw) - required - optional or required - frozenset(raw):
        core.fail(
            "Green release contract fields do not match their schema version",
            phase="midcutover-resume-preflight",
            details={
                "missing": sorted(required - frozenset(raw)),
                "unknown": sorted(frozenset(raw) - required - optional),
            },
        )
    if raw.get("mode") != "module":
        core.fail(
            "Green release contract mode is unsupported",
            phase="midcutover-resume-preflight",
            details={"mode": raw.get("mode")},
        )
    module = raw.get("module")
    if not isinstance(module, str) or _HISTORICAL_MODULE_RE.fullmatch(module) is None:
        core.fail(
            "Green release contract module is invalid",
            phase="midcutover-resume-preflight",
        )
    source = _historical_contract_path(raw.get("source"), label="source")
    expected_tools = raw.get("expected_tools")
    if (
        not isinstance(expected_tools, list)
        or not expected_tools
        or any(not isinstance(name, str) or not name for name in expected_tools)
        or len(set(expected_tools)) != len(expected_tools)
    ):
        core.fail(
            "Green release contract expected_tools are invalid",
            phase="midcutover-resume-preflight",
        )
    supporting: list[core.RuntimeSource] = []
    known_modules = {module}
    known_sources = {source.as_posix()}
    for index, item in enumerate(raw.get("supporting_sources", [])):
        if not isinstance(item, dict) or set(item) != {"module", "source"}:
            core.fail(
                "Green release supporting source is invalid",
                phase="midcutover-resume-preflight",
                details={"index": index},
            )
        item_module = item.get("module")
        item_source = _historical_contract_path(
            item.get("source"), label=f"supporting_sources[{index}].source"
        )
        if (
            not isinstance(item_module, str)
            or _HISTORICAL_MODULE_RE.fullmatch(item_module) is None
            or item_module in known_modules
            or item_source.as_posix() in known_sources
        ):
            core.fail(
                "Green release supporting source identity is invalid",
                phase="midcutover-resume-preflight",
                details={"index": index},
            )
        supporting.append(core.RuntimeSource(item_module, item_source))
        known_modules.add(item_module)
        known_sources.add(item_source.as_posix())
    assets: list[core.RuntimeAsset] = []
    asset_sources: set[str] = set()
    asset_destinations: set[str] = set()
    for index, item in enumerate(raw.get("runtime_assets", [])):
        if not isinstance(item, dict) or set(item) != {"source", "destination"}:
            core.fail(
                "Green release runtime asset is invalid",
                phase="midcutover-resume-preflight",
                details={"index": index},
            )
        item_source = _historical_contract_path(
            item.get("source"), label=f"runtime_assets[{index}].source"
        )
        destination = _historical_contract_path(
            item.get("destination"), label=f"runtime_assets[{index}].destination"
        )
        if (
            item_source.as_posix() in known_sources | asset_sources
            or destination.as_posix() in asset_destinations
        ):
            core.fail(
                "Green release runtime asset identity is duplicated",
                phase="midcutover-resume-preflight",
                details={"index": index},
            )
        assets.append(core.RuntimeAsset(item_source, destination))
        asset_sources.add(item_source.as_posix())
        asset_destinations.add(destination.as_posix())
    dependencies: list[core.RuntimeSpawnDependency] = []
    seen_dependencies: set[tuple[str, str, str]] = set()
    for index, item in enumerate(raw.get("spawn_dependencies", [])):
        if not isinstance(item, dict) or set(item) != {
            "kind",
            "launcher_module",
            "spawned_module",
        }:
            core.fail(
                "Green release spawn dependency is invalid",
                phase="midcutover-resume-preflight",
                details={"index": index},
            )
        identity = (
            item.get("kind"),
            item.get("launcher_module"),
            item.get("spawned_module"),
        )
        if (
            identity[0] != "python_module"
            or identity[1] not in known_modules
            or identity[2] not in known_modules
            or identity in seen_dependencies
        ):
            core.fail(
                "Green release spawn dependency identity is invalid",
                phase="midcutover-resume-preflight",
                details={"index": index},
            )
        dependencies.append(core.RuntimeSpawnDependency(*identity))
        seen_dependencies.add(identity)
    browser_default = raw.get("browser_operator_default")
    if browser_default is not None and not isinstance(browser_default, dict):
        core.fail(
            "Green release browser operator default is invalid",
            phase="midcutover-resume-preflight",
        )
    contract = core.RuntimeContract(
        schema_version=version,
        mode="module",
        module=module,
        source=source,
        expected_tools=tuple(expected_tools),
        supporting_sources=tuple(supporting),
        runtime_assets=tuple(assets),
        spawn_dependencies=tuple(dependencies),
        browser_operator_default=(
            json.loads(json.dumps(browser_default))
            if browser_default is not None
            else None
        ),
    )
    if contract.to_manifest() != raw:
        core.fail(
            "Green release contract cannot be losslessly decoded",
            phase="midcutover-resume-preflight",
        )
    return contract


def _receipt_bound_release_contract(
    release_path: Path,
    *,
    expected_release_id: str,
    expected_repo_head: str,
) -> tuple[core.RuntimeContract, dict[str, Any]]:
    """Derive the promoted contract from the release itself, not from a checkout.

    The first draft parsed the green contract with *this checkout's* canonical
    validator.  That silently made recovery time-limited: once main moves past
    the stranded cutover -- which it will, because the stranded cutover is what
    blocks deploys -- a still-valid green release would stop being resumable
    for a reason that has nothing to do with green.  Recovery may not expire
    because the repository moved on.

    The authority is therefore the artifact chain, which is fixed and cannot
    move:

    * the receipt names ``green_release_id`` and is hash-bound,
    * the release id itself commits to the contract digest in its
      ``-contract<12>`` component and to the head in its prefix,
    * the release ships the immutable contract bytes it was built from, whose
      digest must equal both the manifest's ``entrypoint_contract_sha256`` and
      that release-id component,
    * the manifest's projected ``entrypoint_contract`` must agree with those
      bytes.

    The immutable validator shipped and hash-bound inside that same release is
    the schema authority.  The live checkout's validator is never consulted,
    so later repository evolution cannot reinterpret an older legitimate
    release.  Only the validator is evaluated here; target runtime code is not
    started or invoked by this decoder.
    """
    evidence: dict[str, Any] = {"release_path": str(release_path)}
    manifest = core.read_manifest(release_path)
    if manifest.get("release_id") != expected_release_id:
        core.fail(
            "Green release manifest names a different release id",
            phase="midcutover-resume-preflight",
            details={"manifest_release_id": manifest.get("release_id")},
        )
    if manifest.get("repo_head") != expected_repo_head:
        core.fail(
            "Green release manifest names a different repository head",
            phase="midcutover-resume-preflight",
            details={"manifest_repo_head": manifest.get("repo_head")},
        )
    if manifest.get("completion_status") != "complete":
        core.fail(
            "Resumed green release is not a complete deployment artifact",
            phase="midcutover-resume-preflight",
            details={"completion_status": manifest.get("completion_status")},
        )
    declared = manifest.get("entrypoint_contract_sha256")
    if not isinstance(declared, str) or re.fullmatch(r"[0-9a-f]{64}", declared) is None:
        core.fail(
            "Green release manifest carries no contract digest",
            phase="midcutover-resume-preflight",
        )
    # One grammar for every layer: an -attemptN retry release is a legitimate
    # release, and a decoder that anchored on -contract<12> would have refused
    # to resume one for a reason that has nothing to do with the cutover.
    identity = midcutover.parse_release_id(expected_release_id)
    if identity is None:
        core.fail(
            "Green release id is not a canonical release identifier",
            phase="midcutover-resume-preflight",
            details={"release_id": expected_release_id},
        )
    if not declared.startswith(identity["contract12"]):
        core.fail(
            "Green release id does not commit to the manifest contract digest",
            phase="midcutover-resume-preflight",
            details={"entrypoint_contract_sha256": declared},
        )
    # The identifier commits to the head as well, and until now only the
    # contract half of that claim was actually checked.
    if not expected_repo_head.startswith(identity["head12"]):
        core.fail(
            "Green release id does not commit to the resumed repository head",
            phase="midcutover-resume-preflight",
            details={
                "release_head12": identity["head12"],
                "expected_repo_head": expected_repo_head,
            },
        )
    snapshot_paths = manifest.get("snapshot_paths")
    contract_path = (
        snapshot_paths.get(RELEASE_SNAPSHOT_CONTRACT_KEY)
        if isinstance(snapshot_paths, dict)
        else None
    )
    if not isinstance(contract_path, str):
        core.fail(
            "Green release manifest carries no immutable contract snapshot path",
            phase="midcutover-resume-preflight",
        )
    contract_file = core.require_manifest_snapshot_path(
        manifest,
        RELEASE_SNAPSHOT_CONTRACT_KEY,
        Path(contract_path),
        release_path,
    )
    contract_bytes = contract_file.read_bytes()
    observed = core.sha256_bytes(contract_bytes)
    if observed != declared:
        core.fail(
            "Green release contract snapshot does not match its declared digest",
            phase="midcutover-resume-preflight",
            details={"observed_sha256": observed, "declared_sha256": declared},
        )
    try:
        raw = json.loads(contract_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        core.fail(
            "Green release contract snapshot is not valid JSON",
            phase="midcutover-resume-preflight",
            details={"error_type": type(exc).__name__},
        )
    projected = manifest.get("entrypoint_contract")
    if not isinstance(projected, dict) or projected != raw:
        core.fail(
            "Green release manifest contract disagrees with its immutable snapshot",
            phase="midcutover-resume-preflight",
        )
    module_paths = manifest.get("module_paths")
    source_sha256s = manifest.get("source_sha256s")
    validator_path_text = (
        module_paths.get("grabowski_runtime_contract")
        if isinstance(module_paths, dict)
        else None
    )
    validator_sha256 = (
        source_sha256s.get("grabowski_runtime_contract")
        if isinstance(source_sha256s, dict)
        else None
    )
    if (
        not isinstance(validator_path_text, str)
        or not isinstance(validator_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", validator_sha256) is None
    ):
        core.fail(
            "Green release carries no immutable historical contract validator",
            phase="midcutover-resume-preflight",
        )
    try:
        validator_candidate = Path(validator_path_text)
        validator_metadata = validator_candidate.lstat()
        if statmod.S_ISLNK(validator_metadata.st_mode):
            raise OSError("historical validator path is a symlink")
        validator_path = validator_candidate.resolve(strict=True)
        validator_path.relative_to(release_path.resolve(strict=True))
        if (
            not statmod.S_ISREG(validator_metadata.st_mode)
            or validator_metadata.st_uid != os.getuid()
            or validator_metadata.st_size > 1024 * 1024
        ):
            raise OSError("historical validator file is unsafe")
        validator_bytes = validator_path.read_bytes()
    except (OSError, ValueError) as exc:
        core.fail(
            "Green release historical contract validator is unavailable",
            phase="midcutover-resume-preflight",
            details={"error_type": type(exc).__name__},
        )
    if core.sha256_bytes(validator_bytes) != validator_sha256:
        core.fail(
            "Green release historical contract validator hash mismatch",
            phase="midcutover-resume-preflight",
        )
    historical_validator = core.load_contract_validator_bytes(validator_bytes)
    try:
        historical_validator.validate_contract(raw)
    except Exception as exc:  # noqa: BLE001 - version-bound validator is authoritative
        core.fail(
            "Green release contract fails its immutable historical schema",
            phase="midcutover-resume-preflight",
            details={"error_type": type(exc).__name__},
        )
    contract = _decode_historical_runtime_contract(raw)
    evidence.update(
        {
            "release_id": expected_release_id,
            "repo_head": expected_repo_head,
            "entrypoint_contract_sha256": declared,
            "release_identity": identity,
            "entrypoint_contract_path": str(contract_file),
            "schema_version": contract.schema_version,
            "mode": contract.mode,
            "module": contract.module,
            "source": contract.source.as_posix(),
            "expected_tool_count": len(contract.expected_tools),
            "decoded_contract_sha256": _json_sha256(contract.to_manifest()),
            "historical_validator_path": str(validator_path),
            "historical_validator_sha256": validator_sha256,
            "judged_by_checkout": False,
            "executed_release_code": False,
            "historical_validator_executed": True,
        }
    )
    return contract, evidence


CANONICAL_OPERATOR_LIVE = "canonical_operator_live"
CANONICAL_OPERATOR_ABSENT = "canonical_operator_absent"
CANONICAL_OPERATOR_AMBIGUOUS = "canonical_operator_ambiguous"


def _listener_present(port: int, *, timeout_seconds: float = 1.0) -> bool:
    """Soft listener probe used only as classification evidence."""
    try:
        with socket.create_connection(
            (OPERATOR_LISTENER_HOST, port), timeout=timeout_seconds
        ):
            return True
    except OSError:
        return False


def classify_canonical_admission_topology() -> dict[str, Any]:
    """Decide whether the old canonical operator can still be drained.

    Once green is publicly selected, the old canonical process is no longer
    load-bearing, and it may well be gone -- that is a normal consequence of the
    failure that stranded the cutover, not a new fault.  Requiring it to be
    alive would make recovery depend on the health of the thing being replaced.

    Three states, and only three:

    ``canonical_operator_live``
        The unit is confirmed active and its admission status answers.  Drain
        it properly.
    ``canonical_operator_absent``
        The unit is confirmed inactive *and* nothing listens on its port.  There
        is no process that could admit a mutation, so there is nothing to close.
    ``canonical_operator_ambiguous``
        Anything else -- active but unreachable, inactive with a live listener,
        an unusable service query.  Fail closed: an unknown admission state is
        not an empty one.
    """
    observation = observe_service(OPERATOR_SERVICE)
    listener = _listener_present(OPERATOR_LISTENER_PORT)
    status_reachable: bool | None = None
    status_error: str | None = None
    if observation.confirmed_active:
        try:
            _operator_admission_observation(OPERATOR_LISTENER_PORT)
            status_reachable = True
        except core.DeployError as exc:
            status_reachable = False
            status_error = str(exc.details.get("failure_class") or exc.phase or "")
    if observation.confirmed_active and status_reachable:
        topology = CANONICAL_OPERATOR_LIVE
    elif observation.confirmed_inactive and not listener:
        topology = CANONICAL_OPERATOR_ABSENT
    else:
        topology = CANONICAL_OPERATOR_AMBIGUOUS
    return {
        "topology": topology,
        "service": observation.to_dict(),
        "listener_present": listener,
        "admission_status_reachable": status_reachable,
        "admission_status_error": status_error,
        "does_not_establish": [
            "that no effect is in flight on green",
            "that the canonical operator will stay in this state",
        ],
    }


@dataclass
class MidCutoverResumeRuntime:
    """The exact continuation of one already-switched blue-green cutover.

    Every field is derived from durable evidence of that cutover.  The class
    owns no build, allocates no release identity and never writes the routing
    selector except through the CAS that carries the exact predecessor hash.
    """

    repo: Path
    runtime: Path
    release_path: Path
    contract: core.RuntimeContract
    contract_evidence: dict[str, Any]
    green_binding: dict[str, str]
    classification: dict[str, Any]
    resume_binding: dict[str, Any]
    timeout_seconds: int
    green_unit: str
    selector_before: dict[str, Any]
    cutover_generation: int
    blue_repo_head: str
    receipt_root: Path
    admission_marker: dict[str, Any] | None = None
    admission_topology: dict[str, Any] | None = None
    activation: core.ActivationState | None = None
    current_selector: dict[str, Any] | None = None
    promotion_progress: CanonicalPromotionProgress = field(
        default_factory=CanonicalPromotionProgress
    )
    green_proven: bool = False
    green_readiness: dict[str, Any] | None = None
    snapshot_rebind: dict[str, Any] | None = None
    effect_snapshot_receipt_sha256: str | None = None
    effect_snapshot_state: str | None = None

    @property
    def cutover_id(self) -> str:
        return str(self.resume_binding["cutover_id"])

    @property
    def pointer_promoted(self) -> bool:
        return self.promotion_progress.pointer_promoted

    @property
    def canonical_selected(self) -> bool:
        return self.promotion_progress.canonical_selected

    def snapshot_effect_guard(self, effect: str) -> Any:
        """Bind one recovery effect to the exact classified snapshot."""
        readiness = self.resume_binding.get("green_readiness")
        if not isinstance(readiness, dict):
            core.fail(
                "Resume binding carries no snapshot guard readiness",
                phase=f"midcutover-{effect}-snapshot-cas",
            )
        expected_receipt = self.effect_snapshot_receipt_sha256 or str(
            self.resume_binding["classified_snapshot_receipt_sha256"]
        )
        expected_state = self.effect_snapshot_state or str(
            self.resume_binding["snapshot_binding_state"]
        )
        canonical_state = {
            midcutover.SNAPSHOT_BINDING_PENDING: (
                client_snapshot.SNAPSHOT_BINDING_PREDECESSOR
            ),
            midcutover.SNAPSHOT_BINDING_DONE: (
                client_snapshot.SNAPSHOT_BINDING_REBOUND
            ),
        }.get(expected_state)
        if canonical_state is None:
            core.fail(
                "Resume binding carries no effect-safe snapshot state",
                phase=f"midcutover-{effect}-snapshot-cas",
            )
        return client_snapshot.cutover_snapshot_effect_guard(
            cutover_id=self.cutover_id,
            cutover_generation=self.cutover_generation,
            source_release_id=str(self.resume_binding["blue_release_id"]),
            source_repo_head=self.blue_repo_head,
            target_release_id=self.green_binding["release_id"],
            target_repo_head=self.green_binding["repo_head"],
            source_evidence_time=int(self.resume_binding["source_evidence_time"]),
            publication_request_id=str(
                self.resume_binding["publication_request_id"]
            ),
            registered_tool_count=int(
                self.resume_binding["registered_tool_count"]
            ),
            registered_names_sha256=str(
                self.resume_binding["registered_names_sha256"]
            ),
            agent_instructions_sha256=str(
                self.resume_binding["agent_instructions_sha256"]
            ),
            green_readiness=readiness,
            expected_state=canonical_state,
            source_snapshot_receipt_sha256=str(
                self.resume_binding["source_snapshot_receipt_sha256"]
            ),
            source_client_declaration_sha256=str(
                self.resume_binding["source_client_declaration_sha256"]
            ),
            classified_snapshot_receipt_sha256=expected_receipt,
        )

    def verify_green_serving(self) -> dict[str, Any]:
        """Prove green authoritatively, before anything irreversible happens.

        A mid-cutover invariant with no counterpart in the ordinary cutover:
        there, green is a release this process just built and started.  Here it
        is a process someone else started, that the public route already points
        at, and that this run is about to make canonical.  A release manifest on
        disk and a TCP listener are not evidence that *that* process serves
        *that* release -- only a full MCP identity probe is, and it must come
        before the pointer moves, not after.
        """
        readback = _require_selector_authority(
            expected_selector_sha256=self.resume_binding["expected_selector_sha256"],
            expected_slot="green",
            expected_binding_sha256=self.resume_binding[
                "expected_runtime_binding_sha256"
            ],
        )
        readiness = _probe_release_runtime(
            release_path=self.release_path,
            port=GREEN_OPERATOR_LISTENER_PORT,
            auth_mode="connector",
            expected_release_id=self.green_binding["release_id"],
            expected_repo_head=self.green_binding["repo_head"],
            expected_agent_instructions_sha256=self.green_binding[
                "agent_instructions_sha256"
            ],
            timeout_seconds=self.timeout_seconds,
        )
        self.green_proven = True
        self.green_readiness = readiness
        return {
            "green_serving": True,
            "authoritative_readback": readback,
            "green_readiness_sha256": _json_sha256(readiness),
            "proves": [
                "the green process serves the exact resumed release and head",
                "the ingress route is authoritatively bound to that release",
            ],
        }

    def close_mutations(self) -> dict[str, Any]:
        """Close admission on the process the public route actually points at.

        Green is the publicly selected operator for the whole of a mid-cutover
        state, so green is what must stop admitting before promotion -- an
        earlier draft skipped admission entirely when the old canonical unit was
        gone, which left green free to admit a mutation that retirement would
        then cut off mid-effect.

        The marker is one file every grabowski operator reads, so engaging it
        closes both processes at once; only the *readback* is per process. The
        canonical topology therefore no longer decides whether to close, just
        whether the canonical side can also be guarded. Ambiguity still fails
        closed: an unknown admission state is not an empty one.
        """
        topology = classify_canonical_admission_topology()
        self.admission_topology = topology
        kind = topology["topology"]
        if kind == CANONICAL_OPERATOR_AMBIGUOUS:
            core.fail(
                "Canonical operator admission state is ambiguous",
                phase="midcutover-admission-topology",
                details=topology,
            )
        with self.snapshot_effect_guard("admission-engage"):
            self.admission_marker = engage_receipt_bound_deployment_admission(
                expected_head=self.green_binding["repo_head"],
                source_identity_sha256=str(
                    self.resume_binding["source_identity_sha256"]
                ),
                timeout_seconds=self.timeout_seconds,
            )
        return {
            "closed": True,
            "topology": kind,
            "drain_target_port": GREEN_OPERATOR_LISTENER_PORT,
            "canonical_guard_available": kind == CANONICAL_OPERATOR_LIVE,
            "marker_sha256": _json_sha256(self.admission_marker),
            "expected_head": self.admission_marker["expected_head"],
        }

    def terminalize_effects(self) -> dict[str, Any]:
        if self.admission_marker is None:
            core.fail(
                "Green effects cannot be terminalized without an engaged marker",
                phase="midcutover-admission-drain",
            )
        # Drain green: it is the process the ingress selector routes to, so it
        # is where an in-flight mutation would be.
        drained = wait_for_operator_deployment_admission(
            self.admission_marker,
            timeout_seconds=self.timeout_seconds,
            port=GREEN_OPERATOR_LISTENER_PORT,
        )
        if drained.get("supported") is not True:
            core.fail(
                "Green operator does not support the deployment admission contract",
                phase="midcutover-admission-drain",
                details={"drain": drained},
            )
        final = verify_operator_deployment_admission(
            self.admission_marker, port=GREEN_OPERATOR_LISTENER_PORT
        )
        canonical_guard = None
        if (self.admission_topology or {}).get("topology") == CANONICAL_OPERATOR_LIVE:
            # The old canonical process is not publicly routed, but while it is
            # alive it can still be reached directly, so guard it too.
            canonical_guard = _json_sha256(
                verify_operator_deployment_admission(
                    self.admission_marker, port=OPERATOR_LISTENER_PORT
                )
            )
        return {
            "drain_target_port": GREEN_OPERATOR_LISTENER_PORT,
            "canonical_guard_sha256": canonical_guard,
            **drained,
            "final_guard_sha256": _json_sha256(final),
            "registry_authority": "grabowski_operator_cross_process_status",
        }

    @property
    def resume_phase(self) -> str:
        return str(self.resume_binding["resume_phase"])

    def reprobe_green(self) -> dict[str, Any]:
        """Prove green again in the last moment before the pointer moves.

        The first proof happens before the drain, and draining takes time. A
        green process that died in that window would otherwise be promoted to
        canonical on the strength of a stale proof, so the proof is taken again
        with nothing but the pointer swap left to do.
        """
        readiness = _probe_release_runtime(
            release_path=self.release_path,
            port=GREEN_OPERATOR_LISTENER_PORT,
            auth_mode="connector",
            expected_release_id=self.green_binding["release_id"],
            expected_repo_head=self.green_binding["repo_head"],
            expected_agent_instructions_sha256=self.green_binding[
                "agent_instructions_sha256"
            ],
            timeout_seconds=self.timeout_seconds,
        )
        return {
            "green_still_serving": True,
            "green_readiness_sha256": _json_sha256(readiness),
        }

    def rebind_snapshot(self) -> dict[str, Any]:
        """Finish the step the original cutover died on.

        The stranded cutover switched the selector, activated Publication-v2 and
        then failed here. A resume that promoted canonical without doing this
        would report the cutover as completed while the contract it broke stayed
        broken -- and its own receipt would say so, in does_not_establish, while
        the lineage was already marked resolved.

        The authorising evidence is the Publication-v2 request that cutover
        created; the rebind itself re-derives every value and refuses if the
        request does not name this exact cutover and this exact green contract.
        """
        if self.green_readiness is None:
            core.fail(
                "Snapshot rebind requires an authoritative green readiness proof",
                phase="midcutover-snapshot-rebind",
            )
        scope = (self.classification["evidence"]["snapshot_observation"] or {}).get(
            "observation_scope"
        )
        if scope not in {
            client_snapshot.OBSERVATION_SCOPE_EXTERNAL_CLIENT,
            client_snapshot.OBSERVATION_SCOPE_SERVER_LOOPBACK,
        }:
            core.fail(
                "Bound client snapshot observation scope is not resumable",
                phase="midcutover-snapshot-rebind",
                details={"observation_scope": scope},
            )
        result = client_snapshot.rebind_snapshot_for_midcutover_recovery(
            cutover_id=self.cutover_id,
            cutover_generation=self.cutover_generation,
            # The predecessor identity the rebind must match is the one the
            # persisted snapshot actually carries, not a reconstruction of it.
            current_release_id=str(self.resume_binding["blue_release_id"]),
            current_repo_head=self.blue_repo_head,
            green_release_id=self.green_binding["release_id"],
            green_repo_head=self.green_binding["repo_head"],
            registered_tool_count=len(self.contract.expected_tools),
            registered_names_sha256=self.green_binding["registered_names_sha256"],
            agent_instructions_sha256=self.green_binding[
                "agent_instructions_sha256"
            ],
            green_readiness=self.green_readiness,
            observation_scope=str(scope),
            source_snapshot_receipt_sha256=str(
                self.resume_binding["source_snapshot_receipt_sha256"]
            ),
            source_client_declaration_sha256=str(
                self.resume_binding["source_client_declaration_sha256"]
            ),
            classified_snapshot_receipt_sha256=str(
                self.resume_binding["classified_snapshot_receipt_sha256"]
            ),
            receipt_root=self.receipt_root,
        )
        # Read the effect back before this run relies on it. A rebind that
        # returned but did not persist would otherwise let S1 proceed on a
        # snapshot that still names the predecessor.
        readback = midcutover.observe_client_snapshot_binding(
            cutover_id=self.cutover_id,
            cutover_generation=self.cutover_generation,
            blue_release_id=self.resume_binding["blue_release_id"],
            blue_repo_head=self.blue_repo_head,
            green_release_id=self.green_binding["release_id"],
            target_head=self.green_binding["repo_head"],
            source_evidence_time=int(
                self.resume_binding["source_evidence_time"]
            ),
            publication_request_id=str(
                self.resume_binding["publication_request_id"]
            ),
            registered_tool_count=len(self.contract.expected_tools),
            registered_names_sha256=self.green_binding[
                "registered_names_sha256"
            ],
            agent_instructions_sha256=self.green_binding[
                "agent_instructions_sha256"
            ],
            green_readiness=self.green_readiness,
        )
        if (
            readback.get("state") != midcutover.SNAPSHOT_BINDING_DONE
            or readback.get("snapshot_receipt_sha256") != result.get("receipt_sha256")
            or readback.get("source_snapshot_receipt_sha256")
            != self.resume_binding["source_snapshot_receipt_sha256"]
            or readback.get("source_client_declaration_sha256")
            != self.resume_binding["source_client_declaration_sha256"]
        ):
            core.fail(
                "Snapshot rebind readback does not bind this cutover lineage",
                phase="midcutover-snapshot-rebind",
                details={"readback": readback},
            )
        self.snapshot_rebind = result
        self.effect_snapshot_receipt_sha256 = str(result["receipt_sha256"])
        self.effect_snapshot_state = midcutover.SNAPSHOT_BINDING_DONE
        return {
            "rebound": True,
            "readback_state": readback.get("state"),
            "readback_receipt_sha256": readback.get("snapshot_receipt_sha256"),
            "receipt_sha256": result.get("receipt_sha256"),
            "source_snapshot_receipt_sha256": result.get(
                "source_snapshot_receipt_sha256"
            ),
            "source_client_declaration_sha256": result.get(
                "source_client_declaration_sha256"
            ),
            "classified_snapshot_receipt_sha256": result.get(
                "classified_snapshot_receipt_sha256"
            ),
            "source_release_id": result.get("source_release_id"),
            "source_repo_head": result.get("source_repo_head"),
            "target_release_id": result.get("target_release_id"),
            "target_repo_head": result.get("target_repo_head"),
            "schema_changed": result.get("schema_changed"),
            "publication_schema_transition": result.get(
                "publication_schema_transition"
            ),
            "publication_schema_transition_sha256": (
                result.get("publication_schema_transition") or {}
            ).get("transition_sha256"),
            "observation_scope": result.get("observation_scope"),
        }

    def adopted_snapshot_rebind(self) -> dict[str, Any] | None:
        """Rebind evidence an earlier phase of *this* lineage already produced.

        A resume continuing from S1 or later did not perform the rebind, but the
        cutover contract still requires proof that it happened. The proof is on
        disk, and the classifier already bound it to this cutover, so the receipt
        carries it forward instead of recording a hole that would make an
        otherwise complete resume unable to retire its own lineage.
        """
        observation = self.classification["evidence"].get("snapshot_observation")
        if (
            not isinstance(observation, dict)
            or observation.get("state") != midcutover.SNAPSHOT_BINDING_DONE
        ):
            return None
        return {
            "rebound": True,
            "adopted_from_durable_snapshot": True,
            "receipt_sha256": observation.get("snapshot_receipt_sha256"),
            "source_snapshot_receipt_sha256": observation.get(
                "source_snapshot_receipt_sha256"
            ),
            "source_client_declaration_sha256": observation.get(
                "source_client_declaration_sha256"
            ),
            "classified_snapshot_receipt_sha256": observation.get(
                "classified_snapshot_receipt_sha256"
            ),
            "source_release_id": observation.get("source_release_id"),
            "source_repo_head": observation.get("source_repo_head"),
            "target_release_id": observation.get("target_release_id"),
            "target_repo_head": observation.get("target_repo_head"),
            "publication_schema_transition_sha256": observation.get(
                "transition_sha256"
            ),
            "observation_scope": observation.get("observation_scope"),
        }

    def cold_snapshot_observation(self) -> dict[str, Any]:
        """Reconstruct S0 from disk after success, failure, or process loss."""
        readiness = self.resume_binding.get("green_readiness")
        if not isinstance(readiness, dict):
            return {
                "state": midcutover.SNAPSHOT_BINDING_UNREADABLE,
                "error": "resume binding carries no green readiness evidence",
            }
        return midcutover.observe_client_snapshot_binding(
            cutover_id=self.cutover_id,
            cutover_generation=self.cutover_generation,
            blue_release_id=str(self.resume_binding["blue_release_id"]),
            blue_repo_head=self.blue_repo_head,
            green_release_id=self.green_binding["release_id"],
            target_head=self.green_binding["repo_head"],
            source_evidence_time=int(self.resume_binding["source_evidence_time"]),
            publication_request_id=str(
                self.resume_binding["publication_request_id"]
            ),
            registered_tool_count=int(
                self.resume_binding["registered_tool_count"]
            ),
            registered_names_sha256=str(
                self.resume_binding["registered_names_sha256"]
            ),
            agent_instructions_sha256=str(
                self.resume_binding["agent_instructions_sha256"]
            ),
            green_readiness=readiness,
        )

    def promote_canonical(self) -> dict[str, Any]:
        """Run the shared canonical promotion against the resumed green release."""
        if not self.green_proven:
            core.fail(
                "Canonical promotion requires an authoritative green readiness proof",
                phase="midcutover-promote-canonical",
            )
        if self.resume_phase in {
            midcutover.PHASE_REBIND_SNAPSHOT,
            midcutover.PHASE_PROMOTE_POINTER,
        }:
            self.reprobe_green()
            # Compare-and-swap on the pointer, not just on the selector: the
            # deployment lock keeps other deploys out, but it says nothing about
            # what the pointer became while this run was draining.
            # Root containment belongs here most of all: the classifier ran
            # minutes ago, and the window between it and this swap is exactly
            # where a same-named unmanaged release could appear.
            observed = midcutover.observe_stable_pointer(
                self.runtime, core.releases_root_for(self.runtime)
            )
            expected_blue = self.classification["receipt"]["blue_release_id"]
            if (
                observed.get("error") is not None
                or observed.get("pointer_kind") != "symlink"
                or observed.get("release_id") != expected_blue
                or observed.get("repo_head") != self.blue_repo_head
                or observed.get("completion_status") != "complete"
            ):
                core.fail(
                    "Stable pointer is no longer the predecessor this resume classified",
                    phase="midcutover-pointer-cas",
                    details={
                        "expected_predecessor_release_id": expected_blue,
                        "expected_predecessor_repo_head": self.blue_repo_head,
                        "observed": observed,
                    },
                )
            self.activation = core.ActivationState(
                runtime=self.runtime,
                release_path=self.release_path,
                previous=core.capture_pointer(self.runtime),
            )
        else:
            # Phase S2 or later: an earlier resume already promoted the pointer. The
            # promotion continues from there rather than repeating an applied
            # effect.
            self.activation = None
            self.promotion_progress.pointer_promoted = True
        promotion = promote_green_release_to_canonical(
            runtime=self.runtime,
            release_path=self.release_path,
            contract=self.contract,
            green_binding=self.green_binding,
            activation=self.activation,
            expected_green_selector_sha256=self.resume_binding[
                "expected_selector_sha256"
            ],
            expected_green_binding_sha256=self.resume_binding[
                "expected_runtime_binding_sha256"
            ],
            cutover_id=self.cutover_id,
            timeout_seconds=self.timeout_seconds,
            progress=self.promotion_progress,
            snapshot_effect_guard=self.snapshot_effect_guard,
        )
        self.current_selector = promotion["selector"]
        return promotion

    def adopt_applied_promotion(self) -> dict[str, Any]:
        """Record a promotion an earlier resume already applied.

        Phases S2 and S3 begin with canonical routing already published and the
        pointer already moved. Those are facts on disk, verified by the
        classifier before this object existed; marking them here lets the
        remaining steps run without re-applying an irreversible effect and
        without pretending it never happened.
        """
        observed = transport_ingress.read_routing_selector()
        expected_selector = self.resume_binding["expected_selector_sha256"]
        expected_binding = self.resume_binding["expected_runtime_binding_sha256"]
        ancestry = self.resume_binding["switch_selector_sha256"]
        if (
            observed.get("selector_sha256") != expected_selector
            or observed.get("runtime_binding_sha256") != expected_binding
            or observed.get("cutover_id") != self.cutover_id
            or observed.get("selected_slot") != "canonical"
            # The decisive binding: this canonical selector must be the direct
            # successor of *our* green selector.  Verifying a selector against
            # its own hash only proves it is internally consistent, which any
            # foreign writer's selector also is.
            or observed.get("previous_selector_sha256") != ancestry
        ):
            core.fail(
                "Canonical selector does not continue this resume lineage",
                phase="midcutover-adopt-promotion",
                details={
                    "observed": _selector_summary(observed),
                    "expected_selector_sha256": expected_selector,
                    "expected_previous_selector_sha256": ancestry,
                },
            )
        self.promotion_progress.pointer_promoted = True
        self.promotion_progress.canonical_selected = True
        self.green_proven = True
        self.current_selector = observed
        readback = _require_selector_authority(
            expected_selector_sha256=expected_selector,
            expected_slot="canonical",
            expected_binding_sha256=expected_binding,
        )
        return {"adopted": True, "authoritative_readback": readback}

    def reconcile_admission_marker(self) -> dict[str, Any]:
        """Clear a marker this lineage left behind -- and only such a marker.

        A resume that retired green and then failed to release admission leaves
        the runtime globally closed to mutations. The next run must finish that
        cleanup rather than report completion over it. Ownership is proved by
        the marker's own binding, so a marker belonging to somebody else's
        deployment is never touched; it makes this run fail closed instead.
        """
        observed = _secure_admission_marker_payload(OPERATOR_ADMISSION_MARKER_PATH)
        if observed is None:
            return {"state": "absent", "cleanup_performed": False}
        expected_head = self.green_binding["repo_head"]
        expected_identity = str(self.resume_binding["source_identity_sha256"])
        if (
            observed.get("expected_head") != expected_head
            or observed.get("source_identity_sha256") != expected_identity
        ):
            core.fail(
                "An unrelated deployment admission marker is active",
                phase="midcutover-admission-cleanup",
                details={
                    "observed_expected_head": observed.get("expected_head"),
                    "expected_head": expected_head,
                },
            )
        with self.snapshot_effect_guard("admission-cleanup"):
            release_operator_deployment_admission(observed)
        residue = _secure_admission_marker_payload(OPERATOR_ADMISSION_MARKER_PATH)
        if residue is not None:
            core.fail(
                "Deployment admission marker is still present after release",
                phase="midcutover-admission-cleanup",
            )
        self.admission_marker = None
        return {
            "state": "released",
            "cleanup_performed": True,
            "verified_absent": True,
        }

    def retire_green(self) -> dict[str, Any]:
        if not self.canonical_selected:
            core.fail(
                "Green retirement requires a proven canonical promotion",
                phase="midcutover-retire-green",
            )
        with self.snapshot_effect_guard("retire-green"):
            retirement = _stop_green_operator(self.green_unit)
            admission_release = None
            if self.admission_marker is not None:
                admission_release = release_operator_deployment_admission(
                    self.admission_marker
                )
                self.admission_marker = None
        return {**retirement, "admission_release": admission_release}

    def final_readback(self) -> dict[str, Any]:
        require_service_active(TRANSPORT_INGRESS_SERVICE)
        require_service_active(TUNNEL_SERVICE)
        manifest = core.read_manifest(self.runtime)
        binding, binding_sha256 = transport_ingress._read_runtime_binding(
            self.runtime / core.MANIFEST_NAME
        )
        if (
            binding != self.green_binding
            or binding_sha256 != self.resume_binding["expected_runtime_binding_sha256"]
        ):
            core.fail(
                "Promoted runtime binding does not match the resumed green identity",
                phase="midcutover-final-readback",
                details={"observed_runtime_binding_sha256": binding_sha256},
            )
        pointer = midcutover.observe_stable_pointer(
            self.runtime, core.releases_root_for(self.runtime)
        )
        snapshot = self.cold_snapshot_observation()
        selector = transport_ingress.read_routing_selector()
        green_unit = observe_green_operator_unit(self.green_unit)
        admission = _secure_admission_marker_payload(OPERATOR_ADMISSION_MARKER_PATH)
        if (
            manifest.get("completion_status") != "complete"
            or manifest.get("release_id") != self.green_binding["release_id"]
            or manifest.get("repo_head") != self.green_binding["repo_head"]
            or pointer.get("error") is not None
            or pointer.get("pointer_kind") != "symlink"
            or pointer.get("pointer_target_release_id")
            != self.green_binding["release_id"]
            or pointer.get("release_id") != self.green_binding["release_id"]
            or pointer.get("repo_head") != self.green_binding["repo_head"]
            or pointer.get("completion_status") != "complete"
            or snapshot.get("state") != midcutover.SNAPSHOT_BINDING_DONE
            or selector.get("selected_slot") != "canonical"
            or selector.get("cutover_id") != self.cutover_id
            or selector.get("runtime_binding_sha256")
            != self.resume_binding["expected_runtime_binding_sha256"]
            or selector.get("previous_selector_sha256")
            != self.resume_binding["switch_selector_sha256"]
            or selector.get("generation")
            != int(self.resume_binding["switch_generation"]) + 1
            or selector.get("runtime_binding", {}).get("release_id")
            != self.green_binding["release_id"]
            or selector.get("runtime_binding", {}).get("repo_head")
            != self.green_binding["repo_head"]
            or green_unit.get("active") is not False
            or green_unit.get("unit") != self.green_unit
            or green_unit.get("error") is not None
            or admission is not None
        ):
            core.fail(
                "Final mid-cutover readback is not terminal for this lineage",
                phase="midcutover-final-readback",
                details={
                    "pointer": pointer,
                    "snapshot": snapshot,
                    "selector": _selector_summary(selector),
                    "green_unit": green_unit,
                    "admission_marker_present": admission is not None,
                },
            )
        return {
            "runtime_binding_sha256": binding_sha256,
            "release_id": manifest.get("release_id"),
            "repo_head": manifest.get("repo_head"),
            "completion_status": manifest.get("completion_status"),
            "pointer": pointer,
            "snapshot": snapshot,
            "selector": _selector_summary(selector),
            "green_unit": green_unit,
            "admission_marker_state": "absent",
        }

    def release_admission_best_effort(self) -> dict[str, Any]:
        """Give back the admission gate on a pre-effect abort.

        Deliberately not a rollback: nothing is reverted here.  Leaving the gate
        engaged after a refusal would keep the runtime closed for mutations for
        no reason, which is a denial of service rather than a safety property.
        """
        if self.admission_marker is None:
            return {"released": True, "reason": "no_marker_engaged", "clean": True}
        try:
            release_operator_deployment_admission(self.admission_marker)
        except Exception as exc:  # noqa: BLE001 - abort path must stay reportable
            # A marker that could not be released is a residual effect of this
            # run.  Reporting the state as unchanged would understate it.
            return {
                "released": False,
                "clean": False,
                "cleanup_required": True,
                "marker_expected_head": self.admission_marker.get("expected_head"),
                "marker_source_identity_sha256": self.admission_marker.get(
                    "source_identity_sha256"
                ),
                "error": type(exc).__name__,
            }
        self.admission_marker = None
        return {"released": True, "clean": True}

    def authoritative_readback(self) -> dict[str, Any]:
        return observe_authoritative_routing()


def classify_midcutover_resume(
    *,
    expected_head: str,
    runtime: Path | None = None,
    receipt_root: Path | None = None,
) -> dict[str, Any]:
    """Classify the live durable state; read-only and safe to call anywhere.

    The verdict comes from the same module the MCP recovery surface uses, so the
    gate an operator sees and the gate the runner enforces cannot drift apart.
    """
    target_runtime = runtime or (core.HOME / ".local/share/grabowski-mcp")
    return midcutover.classify_from_durable_state(
        expected_head=expected_head,
        selector_path=transport_ingress.DEFAULT_SELECTOR_FILE,
        receipt_root=(
            receipt_root if receipt_root is not None else BLUE_GREEN_RECEIPT_ROOT
        ),
        releases_root=core.releases_root_for(target_runtime),
        runtime_path=target_runtime,
        pointer_releases_root=core.releases_root_for(target_runtime),
        green_unit_observer=observe_green_operator_unit,
    )


def observe_green_operator_unit(unit: str) -> dict[str, Any]:
    """Three-valued state of one transient green unit.

    Without this the classifier could never see a retired green, so the closeout
    phase would be unreachable outside tests -- a state machine whose last step
    only exists on paper. Only a confirmed inactive unit counts as retired;
    an unreadable service query is ambiguous and stays ambiguous.
    """
    observation = observe_service(_require_green_unit(unit))
    if _green_confirmed_inactive(observation):
        active: bool | None = False
    elif observation.confirmed_active:
        active = True
    else:
        active = None
    return {
        "unit": unit,
        "active": active,
        "service": observation.to_dict(),
        "does_not_establish": ["that no effect is in flight on green"],
    }


def prepare_midcutover_resume_runtime(
    repo: Path,
    runtime: Path,
    *,
    expected_head: str,
    timeout_seconds: int,
    receipt_root: Path | None = None,
    require_resume_binding_sha256: str | None = None,
) -> MidCutoverResumeRuntime:
    """Bind one already-switched cutover, or refuse; never build a release."""
    classification = classify_midcutover_resume(
        expected_head=expected_head,
        runtime=runtime,
        receipt_root=receipt_root,
    )
    if (
        classification.get("lane") != midcutover.LANE_MID_CUTOVER_RESUME
        or not isinstance(classification.get("resume_binding"), dict)
    ):
        raise MidCutoverResumeDenied(classification)
    resume_binding = classification["resume_binding"]
    if (
        require_resume_binding_sha256 is not None
        and resume_binding.get("binding_sha256") != require_resume_binding_sha256
    ):
        # The authorising operator named one exact cutover.  If the durable
        # state now classifies a different one, that is a new decision, not a
        # continuation of the approved one.
        raise MidCutoverResumeDenied(
            {
                **classification,
                "lane": midcutover.LANE_FAIL_CLOSED,
                "reasons": sorted(
                    {*(classification.get("reasons") or []), "resume_binding_drifted"}
                ),
                "authorized_resume_binding_sha256": require_resume_binding_sha256,
            }
        )
    if (
        re.fullmatch(
            r"[0-9a-f]{64}", str(resume_binding.get("source_identity_sha256") or "")
        )
        is None
    ):
        core.fail(
            "Resumed cutover receipt carries no scheduler source identity",
            phase="midcutover-resume-preflight",
        )
    require_service_active(TRANSPORT_INGRESS_SERVICE)
    releases_root = core.releases_root_for(runtime)
    release_path = releases_root / resume_binding["expected_release_id"]
    resolved_root = releases_root.resolve(strict=True)
    try:
        resolved_release = release_path.resolve(strict=True)
    except OSError as exc:
        core.fail(
            "Resumed green release path is unavailable",
            phase="midcutover-resume-preflight",
            details={"error_type": type(exc).__name__},
        )
    if resolved_release.parent != resolved_root:
        # A release id is an identifier, not a path fragment: whatever it names
        # must sit directly inside the releases root and nowhere else.
        core.fail(
            "Resumed green release resolves outside the releases root",
            phase="midcutover-resume-preflight",
            details={
                "releases_root": str(resolved_root),
                "resolved_release": str(resolved_release),
            },
        )
    contract, contract_evidence = _receipt_bound_release_contract(
        release_path,
        expected_release_id=str(resume_binding["expected_release_id"]),
        expected_repo_head=expected_head,
    )
    green_binding, green_binding_sha256 = transport_ingress._read_runtime_binding(
        release_path / core.MANIFEST_NAME
    )
    if (
        green_binding_sha256 != resume_binding["expected_runtime_binding_sha256"]
        or green_binding["release_id"] != resume_binding["expected_release_id"]
        or green_binding["repo_head"] != expected_head
    ):
        core.fail(
            "Resumed green release identity does not match the bound cutover receipt",
            phase="midcutover-resume-preflight",
            details={
                "observed_runtime_binding_sha256": green_binding_sha256,
                "expected_runtime_binding_sha256": resume_binding[
                    "expected_runtime_binding_sha256"
                ],
            },
        )
    selector_before = transport_ingress.read_routing_selector()
    if selector_before.get("selector_sha256") != resume_binding[
        "expected_selector_sha256"
    ]:
        core.fail(
            "Routing selector moved between classification and resume preflight",
            phase="midcutover-resume-preflight",
            details={"selector": _selector_summary(selector_before)},
        )
    snapshot_observation = classification["evidence"].get("snapshot_observation") or {}
    blue_repo_head = str(resume_binding.get("blue_repo_head") or "")
    if (
        resume_binding["resume_phase"] == midcutover.PHASE_REBIND_SNAPSHOT
        and re.fullmatch(r"[0-9a-f]{40,64}", blue_repo_head) is None
    ):
        core.fail(
            "Bound client snapshot carries no usable predecessor head",
            phase="midcutover-resume-preflight",
            details={"bound_repo_head": snapshot_observation.get("bound_repo_head")},
        )
    return MidCutoverResumeRuntime(
        repo=repo,
        runtime=runtime,
        blue_repo_head=blue_repo_head,
        receipt_root=(
            receipt_root if receipt_root is not None else BLUE_GREEN_RECEIPT_ROOT
        ),
        cutover_generation=int(resume_binding["cutover_generation"]),
        release_path=release_path,
        contract=contract,
        contract_evidence=contract_evidence,
        green_binding=green_binding,
        classification=classification,
        resume_binding=resume_binding,
        timeout_seconds=timeout_seconds,
        green_unit=_green_operator_unit(resume_binding["cutover_id"]),
        selector_before=selector_before,
    )


def _midcutover_resume_receipt(
    *,
    resume_id: str,
    resume_binding: dict[str, Any],
    classification_sha256: str | None,
    contract_evidence: dict[str, Any] | None,
    phase: str,
    outcome: str,
    observations: list[dict[str, Any]],
    green_serving: dict[str, Any] | None,
    snapshot_rebind: dict[str, Any] | None,
    drain: dict[str, Any] | None,
    pointer_promotion: dict[str, Any] | None,
    canonical_operator: dict[str, Any] | None,
    selector_switch: dict[str, Any] | None,
    final_routing: dict[str, Any] | None,
    retirement: dict[str, Any] | None,
    admission_state: dict[str, Any] | None,
    final_state: dict[str, Any] | None,
    readback: dict[str, Any] | None,
    recovery: dict[str, Any] | None,
) -> dict[str, Any]:
    material = {
        "schema_version": 1,
        "kind": MIDCUTOVER_RESUME_RECEIPT_KIND,
        "resume_id": resume_id,
        "resumed_cutover_id": resume_binding.get("cutover_id"),
        "resumed_receipt_sha256": resume_binding.get("resumed_receipt_sha256"),
        "resume_binding_sha256": resume_binding.get("binding_sha256"),
        "resume_binding": dict(resume_binding),
        "classification_sha256": classification_sha256,
        # The head this receipt is *about* is the cutover's target, never the
        # revision the recovery code was executed from.
        "expected_head": resume_binding.get("target_head")
        or resume_binding.get("expected_head"),
        "resume_phase": resume_binding.get("resume_phase"),
        "source_identity_sha256": resume_binding.get("source_identity_sha256"),
        "green_release_id": resume_binding.get("expected_release_id"),
        "resumed_selector_sha256": resume_binding.get("expected_selector_sha256"),
        "resumed_generation": resume_binding.get("expected_generation"),
        "target_contract": contract_evidence,
        "phase": phase,
        "outcome": outcome,
        "green_serving": green_serving,
        "snapshot_rebind": snapshot_rebind,
        "effect_terminalization": drain,
        "pointer_promotion": pointer_promotion,
        "canonical_operator": canonical_operator,
        "selector_switch": selector_switch,
        "final_routing": final_routing,
        "retirement": retirement,
        "admission_state": admission_state,
        "final_state": final_state,
        "authoritative_readback": readback,
        "observations": observations,
        "recovery": recovery,
        "preserves": [
            "blue_green_receipt_lineage",
            "deployment_lock",
            "routing_selector_compare_and_swap",
            "runtime_manifest_and_provenance",
            "audit_and_recovery_gates",
        ],
        "does_not_establish": [
            "that a new deployment was performed",
            "that the external client refreshed against green",
            "platform connector catalog publication",
        ],
    }
    return {**material, "receipt_sha256": _json_sha256(material)}


def _persist_midcutover_resume_receipt(receipt: dict[str, Any]) -> dict[str, str]:
    return _persist_blue_green_receipt_document(
        receipt, identifier=receipt.get("resume_id"), label="resume id"
    )


def _persist_midcutover_resume_result(
    receipt: dict[str, Any],
    *,
    outcome: str,
    error: dict[str, Any] | None,
) -> dict[str, Any]:
    """Persist every resume outcome under one typed failure contract."""
    try:
        persisted = _persist_midcutover_resume_receipt(receipt)
    except Exception as exc:
        raise ProductionBlueGreenReceiptPersistenceError(receipt, exc) from exc
    return {
        "receipt": receipt,
        "receipt_path": persisted["path"],
        "receipt_sha256": persisted["receipt_sha256"],
        "receipt_persisted": True,
        "outcome": outcome,
        "error": error,
    }


def _fresh_resume_classification_after_prepare_failure(
    *,
    expected_head: str,
    runtime: Path,
    receipt_root: Path | None,
) -> dict[str, Any]:
    """Reconstruct durable progress when no effect context could be returned."""
    try:
        return classify_midcutover_resume(
            expected_head=expected_head,
            runtime=runtime,
            receipt_root=receipt_root,
        )
    except Exception as exc:  # noqa: BLE001 - unreadable evidence is fail-closed
        return {
            "schema_version": midcutover.SCHEMA_VERSION,
            "kind": midcutover.KIND,
            "lane": midcutover.LANE_FAIL_CLOSED,
            "checks": {"fresh_classification_available": False},
            "reasons": ["fresh_classification_available"],
            "error": _error_summary(exc),
            "resume_binding": None,
            "evidence": {
                "snapshot_binding_state": midcutover.SNAPSHOT_BINDING_UNREADABLE,
                "snapshot_observation": {
                    "state": midcutover.SNAPSHOT_BINDING_UNREADABLE,
                    "error": type(exc).__name__,
                },
            },
        }


def _early_resume_failure_state(
    classification: dict[str, Any],
    *,
    expected_head: str,
    denied: bool,
    error: dict[str, Any] | None,
) -> tuple[dict[str, Any], str, str, dict[str, Any]]:
    """Classify a refusal before ``MidCutoverResumeRuntime`` existed.

    Preparing the effect runtime is read-only, but the lineage may already have
    reached S1-S4 in an earlier process.  Therefore the absence of an in-memory
    context says nothing about durable effects; only a fresh classifier may
    authorize the narrow S0/predecessor ``unchanged`` claim.
    """
    resume_binding = classification.get("resume_binding")
    binding = (
        dict(resume_binding)
        if isinstance(resume_binding, dict)
        else {
            "cutover_id": None,
            "resumed_receipt_sha256": None,
            "binding_sha256": None,
            "expected_head": expected_head,
            "source_identity_sha256": None,
            "expected_release_id": None,
            "expected_selector_sha256": None,
            "expected_generation": None,
        }
    )
    evidence = classification.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    snapshot = evidence.get("snapshot_observation")
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    snapshot_state = evidence.get("snapshot_binding_state") or snapshot.get("state")
    resume_phase = binding.get("resume_phase")
    confirmed_pre_s0 = bool(
        classification.get("lane") == midcutover.LANE_MID_CUTOVER_RESUME
        and resume_phase == midcutover.PHASE_REBIND_SNAPSHOT
        and snapshot_state == midcutover.SNAPSHOT_BINDING_PENDING
    )
    durable_progress = bool(
        snapshot_state == midcutover.SNAPSHOT_BINDING_DONE
        or resume_phase
        in {
            midcutover.PHASE_PROMOTE_POINTER,
            midcutover.PHASE_SELECT_CANONICAL,
            midcutover.PHASE_RETIRE_GREEN,
            midcutover.PHASE_CLOSEOUT,
        }
    )
    ambiguous_snapshot = snapshot_state in {
        midcutover.SNAPSHOT_BINDING_FOREIGN,
        midcutover.SNAPSHOT_BINDING_UNREADABLE,
    }
    if confirmed_pre_s0:
        outcome = "failed_pre_resume"
        phase = "failed_pre_resume"
        recovery = {
            "action": "repair_preflight_evidence_and_retry",
            "blue_green_state_unchanged": True,
            "automatic_rollback_forbidden": True,
            "snapshot_binding_state": snapshot_state,
            "blind_retry_allowed": False,
            "fresh_classification_required": True,
            "classification": classification,
            "error": error,
        }
    elif durable_progress or ambiguous_snapshot or not denied:
        outcome = "outcome_unknown"
        phase = "outcome_unknown"
        recovery = {
            "action": "readback_active_runtime_and_recover",
            "automatic_rollback_forbidden": True,
            "blue_rollback_forbidden": True,
            "snapshot_binding_state": snapshot_state,
            "snapshot_rebind_applied": (
                snapshot_state == midcutover.SNAPSHOT_BINDING_DONE
            ),
            "blind_retry_allowed": False,
            "fresh_classification_required": True,
            "classification": classification,
            "error": error,
        }
    else:
        outcome = "denied"
        phase = "denied"
        recovery = {
            "action": "repair_or_reclassify_recovery_evidence",
            "automatic_rollback_forbidden": True,
            "snapshot_binding_state": snapshot_state,
            "blind_retry_allowed": False,
            "fresh_classification_required": True,
            "classification": classification,
            "error": error,
        }
    return binding, phase, outcome, recovery


def resume_production_blue_green_cutover(
    *,
    repo: Path,
    expected_head: str,
    timeout_seconds: int = 40,
    runtime: Path | None = None,
    lock_file: Path | None = None,
    receipt_root: Path | None = None,
    resume_id: str | None = None,
    require_resume_binding_sha256: str | None = None,
) -> dict[str, Any]:
    """Continue exactly one already-switched cutover to canonical, under the lock.

    This is not a deployment.  It builds nothing, allocates no release identity
    and admits no target other than the one the bound receipt already proved.
    After the first irreversible effect no automatic corrective action is taken:
    an ambiguous mid-resume state is reported as ``outcome_unknown`` with its
    complete evidence, never repaired by guessing.
    """
    identifier = resume_id or f"{MIDCUTOVER_RESUME_ID_PREFIX}{secrets.token_hex(8)}"
    if re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", identifier) is None:
        raise ValueError("resume_id is invalid")
    target_runtime = runtime or (core.HOME / ".local/share/grabowski-mcp")
    target_lock = lock_file or core.DEFAULT_LOCK_FILE
    observations: list[dict[str, Any]] = []
    context: MidCutoverResumeRuntime | None = None
    phase = "classify"
    green_serving: dict[str, Any] | None = None
    snapshot_rebind: dict[str, Any] | None = None
    drain: dict[str, Any] | None = None
    pointer_promotion: dict[str, Any] | None = None
    canonical_operator: dict[str, Any] | None = None
    selector_switch: dict[str, Any] | None = None
    retirement: dict[str, Any] | None = None
    admission_state: dict[str, Any] | None = None
    final_state: dict[str, Any] | None = None
    readback: dict[str, Any] | None = None
    recovery: dict[str, Any] | None = None
    outcome = "denied"
    error: dict[str, Any] | None = None
    with core.deployment_lock(target_lock):
        try:
            context = prepare_midcutover_resume_runtime(
                repo,
                target_runtime,
                expected_head=expected_head,
                timeout_seconds=timeout_seconds,
                receipt_root=receipt_root,
                require_resume_binding_sha256=require_resume_binding_sha256,
            )
        except MidCutoverResumeDenied as exc:
            fresh = _fresh_resume_classification_after_prepare_failure(
                expected_head=expected_head,
                runtime=target_runtime,
                receipt_root=receipt_root,
            )
            binding, early_phase, early_outcome, early_recovery = (
                _early_resume_failure_state(
                    fresh,
                    expected_head=expected_head,
                    denied=True,
                    error={
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "initial_classification": exc.classification,
                    },
                )
            )
            _blue_green_observation(
                observations,
                phase=early_phase,
                details={
                    "reasons": fresh.get("reasons"),
                    "snapshot_binding_state": early_recovery.get(
                        "snapshot_binding_state"
                    ),
                },
            )
            receipt = _midcutover_resume_receipt(
                resume_id=identifier,
                resume_binding=binding,
                classification_sha256=fresh.get("classification_sha256"),
                contract_evidence=None,
                phase=early_phase,
                outcome=early_outcome,
                observations=observations,
                green_serving=None,
                snapshot_rebind=None,
                drain=None,
                pointer_promotion=None,
                canonical_operator=None,
                selector_switch=None,
                final_routing=None,
                retirement=None,
                admission_state=None,
                final_state=None,
                readback=None,
                recovery=early_recovery,
            )
            return _persist_midcutover_resume_result(
                receipt, outcome=early_outcome, error=None
            )
        except Exception as exc:
            error = _error_summary(exc)
            fresh = _fresh_resume_classification_after_prepare_failure(
                expected_head=expected_head,
                runtime=target_runtime,
                receipt_root=receipt_root,
            )
            binding, early_phase, early_outcome, early_recovery = (
                _early_resume_failure_state(
                    fresh,
                    expected_head=expected_head,
                    denied=False,
                    error=error,
                )
            )
            _blue_green_observation(
                observations,
                phase=early_phase,
                details={
                    "error_type": error.get("type"),
                    "snapshot_binding_state": early_recovery.get(
                        "snapshot_binding_state"
                    ),
                },
            )
            receipt = _midcutover_resume_receipt(
                resume_id=identifier,
                resume_binding=binding,
                classification_sha256=fresh.get("classification_sha256"),
                contract_evidence=None,
                phase=early_phase,
                outcome=early_outcome,
                observations=observations,
                green_serving=None,
                snapshot_rebind=None,
                drain=None,
                pointer_promotion=None,
                canonical_operator=None,
                selector_switch=None,
                final_routing=None,
                retirement=None,
                admission_state=None,
                final_state=None,
                readback=None,
                recovery=early_recovery,
            )
            return _persist_midcutover_resume_result(
                receipt, outcome=early_outcome, error=error
            )
        _blue_green_observation(
            observations,
            phase=phase,
            details={
                "cutover_id": context.cutover_id,
                "classification_sha256": context.classification.get(
                    "classification_sha256"
                ),
            },
        )
        try:
            resume_phase = context.resume_phase
            _blue_green_observation(
                observations, phase="resume_phase", details={"phase": resume_phase}
            )
            promotion_pending = resume_phase in {
                midcutover.PHASE_REBIND_SNAPSHOT,
                midcutover.PHASE_PROMOTE_POINTER,
                midcutover.PHASE_SELECT_CANONICAL,
            }
            if promotion_pending:
                phase = "verify_green_serving"
                green_serving = context.verify_green_serving()
                _blue_green_observation(
                    observations,
                    phase=phase,
                    details={
                        "green_readiness_sha256": green_serving.get(
                            "green_readiness_sha256"
                        )
                    },
                )
                if resume_phase == midcutover.PHASE_REBIND_SNAPSHOT:
                    phase = "rebind_snapshot"
                    snapshot_rebind = context.rebind_snapshot()
                    _blue_green_observation(
                        observations,
                        phase=phase,
                        details={
                            "receipt_sha256": snapshot_rebind.get("receipt_sha256"),
                            "schema_changed": snapshot_rebind.get("schema_changed"),
                        },
                    )
                phase = "close_mutations"
                closed = context.close_mutations()
                drain = context.terminalize_effects()
                _blue_green_observation(
                    observations,
                    phase=phase,
                    details={"close": closed, "drain_sha256": _json_sha256(drain)},
                )
                phase = "promote_canonical"
                promotion = context.promote_canonical()
                pointer_promotion = {
                    "promoted": True,
                    "release_path": str(context.release_path),
                    "steps": promotion["activation_steps"],
                    "pointer_activated_now": promotion["pointer_activated_now"],
                }
                canonical_operator = promotion["operator"]
                selector_switch = {
                    "switched": True,
                    **promotion["final_routing"],
                    "authoritative_readback": promotion["authoritative_readback"],
                    "canonical_readiness_sha256": promotion[
                        "canonical_readiness_sha256"
                    ],
                }
                _blue_green_observation(
                    observations,
                    phase=phase,
                    details={
                        "selector_sha256": selector_switch.get("selector_sha256"),
                        "generation": selector_switch.get("generation"),
                    },
                )
            else:
                # Canonical already carries this lineage; the pointer and the
                # selector are applied effects, not work to repeat.
                phase = "adopt_applied_promotion"
                adoption = context.adopt_applied_promotion()
                _blue_green_observation(
                    observations, phase=phase, details={"adopted": True}
                )
            if resume_phase == midcutover.PHASE_RETIRE_GREEN:
                # A later run cannot inherit the previous attempt's drain: that
                # marker may be gone, expired or somebody else's. Green still
                # holds whatever it admitted before the switch, so the proof is
                # taken again here, from scratch.
                phase = "close_mutations"
                closed = context.close_mutations()
                drain = context.terminalize_effects()
                _blue_green_observation(
                    observations,
                    phase=phase,
                    details={"close": closed, "drain_sha256": _json_sha256(drain)},
                )
            if resume_phase != midcutover.PHASE_CLOSEOUT:
                phase = "retire_green"
                retirement = context.retire_green()
                _blue_green_observation(
                    observations, phase=phase, details={"retired": True}
                )
            else:
                retirement = {
                    "retired": True,
                    "adopted_from_durable_unit_state": True,
                    "unit": context.green_unit,
                }
            phase = "reconcile_admission"
            admission_state = context.reconcile_admission_marker()
            _blue_green_observation(
                observations, phase=phase, details=dict(admission_state)
            )
            phase = "final_readback"
            final_state = context.final_readback()
            readback = context.authoritative_readback()
            if readback.get("authoritative") is not True:
                core.fail(
                    "Final canonical routing readback is not authoritative",
                    phase="final-routing-readback",
                )
            _blue_green_observation(
                observations,
                phase=phase,
                details={"readback_sha256": readback.get("readback_sha256")},
            )
            # Prove the would-be terminal receipt before declaring success. A
            # malformed closeout after S0-S4 is an applied-effect ambiguity,
            # not a completed recovery, and must flow through the same
            # outcome_unknown path as any other post-effect failure.
            terminal_probe = _midcutover_resume_receipt(
                resume_id=identifier,
                resume_binding=context.resume_binding,
                classification_sha256=context.classification.get(
                    "classification_sha256"
                ),
                contract_evidence=context.contract_evidence,
                phase="completed",
                outcome="completed",
                observations=observations,
                green_serving=green_serving,
                snapshot_rebind=(
                    snapshot_rebind
                    or context.snapshot_rebind
                    or context.adopted_snapshot_rebind()
                ),
                drain=drain,
                pointer_promotion=pointer_promotion,
                canonical_operator=canonical_operator,
                selector_switch=selector_switch,
                final_routing=(
                    _selector_summary(context.current_selector)
                    if isinstance(context.current_selector, dict)
                    else None
                ),
                retirement=retirement,
                admission_state=admission_state,
                final_state=final_state,
                readback=readback,
                recovery=None,
            )
            loaded = midcutover.load_receipts(context.receipt_root)
            original = [
                value
                for value in loaded.get("receipts", [])
                if value.get("kind") == midcutover.CUTOVER_RECEIPT_KIND
                and value.get("receipt_sha256")
                == context.resume_binding.get("resumed_receipt_sha256")
            ]
            if (
                loaded.get("unreadable")
                or len(original) != 1
                or not midcutover._lineage_resolved([terminal_probe], original[0])
            ):
                core.fail(
                    "Terminal resume receipt does not prove the original cutover lineage",
                    phase="midcutover-terminal-receipt-readback",
                )
            phase = "completed"
            outcome = "completed"
            _blue_green_observation(observations, phase=phase)
        except Exception as exc:
            error = _error_summary(exc)
            try:
                readback = context.authoritative_readback()
            except Exception as readback_exc:  # noqa: BLE001 - preserve original failure
                readback = {
                    "authoritative": False,
                    "error": _error_summary(readback_exc),
                }
            try:
                cold_snapshot = context.cold_snapshot_observation()
            except Exception as snapshot_exc:  # noqa: BLE001 - ambiguity is evidence
                cold_snapshot = {
                    "state": midcutover.SNAPSHOT_BINDING_UNREADABLE,
                    "error": str(snapshot_exc),
                }
            snapshot_state = cold_snapshot.get("state")
            s0_applied = snapshot_state == midcutover.SNAPSHOT_BINDING_DONE
            if s0_applied and snapshot_rebind is None:
                snapshot_rebind = {
                    "rebound": True,
                    "adopted_from_durable_snapshot": True,
                    "receipt_sha256": cold_snapshot.get(
                        "snapshot_receipt_sha256"
                    ),
                    "publication_schema_transition_sha256": cold_snapshot.get(
                        "transition_sha256"
                    ),
                    "observation_scope": cold_snapshot.get("observation_scope"),
                }
            durable_effect_or_ambiguity = bool(
                context.pointer_promoted
                or context.canonical_selected
                or s0_applied
                or snapshot_state
                in {
                    midcutover.SNAPSHOT_BINDING_FOREIGN,
                    midcutover.SNAPSHOT_BINDING_UNREADABLE,
                }
            )
            if durable_effect_or_ambiguity:
                # An irreversible effect exists.  Rolling anything back here --
                # least of all to blue -- would replace a knowable ambiguity with
                # an invented one.  Record and stop.
                outcome = "outcome_unknown"
                phase = "outcome_unknown"
                recovery = {
                    "action": "readback_active_runtime_and_recover",
                    "automatic_rollback_forbidden": True,
                    "blue_rollback_forbidden": True,
                    "pointer_promoted": context.pointer_promoted,
                    "canonical_selected": context.canonical_selected,
                    "snapshot_binding_state": snapshot_state,
                    "snapshot_rebind_applied": s0_applied,
                    "next_resume_phase": (
                        midcutover.PHASE_PROMOTE_POINTER
                        if s0_applied
                        and not context.pointer_promoted
                        and not context.canonical_selected
                        else None
                    ),
                    "blind_retry_allowed": False,
                    "fresh_classification_required": True,
                    "snapshot_rollback_forbidden": s0_applied,
                    "residual_green_unit": (
                        context.green_unit if retirement is None else None
                    ),
                    "error": error,
                }
            else:
                outcome = "failed_pre_resume"
                phase = "failed_pre_resume"
                recovery = {
                    "action": "reclassify_and_retry_resume",
                    "blue_green_state_unchanged": True,
                    "automatic_rollback_forbidden": True,
                    "snapshot_binding_state": snapshot_state,
                    "blind_retry_allowed": False,
                    "fresh_classification_required": True,
                    "admission": context.release_admission_best_effort(),
                    "error": error,
                }
            _blue_green_observation(
                observations,
                phase=phase,
                details={
                    "error_type": error.get("type") if isinstance(error, dict) else None,
                    "readback_sha256": (
                        readback.get("readback_sha256")
                        if isinstance(readback, dict)
                        else None
                    ),
                },
            )
    assert context is not None
    receipt = _midcutover_resume_receipt(
        resume_id=identifier,
        resume_binding=context.resume_binding,
        classification_sha256=context.classification.get("classification_sha256"),
        contract_evidence=context.contract_evidence,
        phase=phase,
        outcome=outcome,
        observations=observations,
        green_serving=green_serving,
        snapshot_rebind=(
            snapshot_rebind
            or context.snapshot_rebind
            or context.adopted_snapshot_rebind()
        ),
        drain=drain,
        pointer_promotion=pointer_promotion,
        canonical_operator=canonical_operator,
        selector_switch=selector_switch,
        final_routing=(
            _selector_summary(context.current_selector)
            if isinstance(context.current_selector, dict)
            else None
        ),
        retirement=retirement,
        admission_state=admission_state,
        final_state=final_state,
        readback=readback,
        recovery=recovery,
    )
    return _persist_midcutover_resume_result(receipt, outcome=outcome, error=error)


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
    parser.add_argument(
        "--expected-head",
        help="Require this exact source HEAD at the apply snapshot boundary.",
    )
    parser.add_argument(
        "--bootstrap-recovery",
        action="store_true",
        help=(
            "Allow exact-head recovery when the predecessor operator is confirmed "
            "inactive; residual transport services are quiesced fail-closed. "
            "Requires --apply and --expected-head."
        ),
    )
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
        expected_head = getattr(args, "expected_head", None)
        bootstrap_recovery = bool(getattr(args, "bootstrap_recovery", False))
        if expected_head is not None:
            if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", expected_head) is None:
                raise ValueError("--expected-head must be a lowercase Git object ID")
            if not args.apply:
                raise ValueError("--expected-head is only valid with --apply")
        if bootstrap_recovery and (not args.apply or expected_head is None):
            raise ValueError(
                "--bootstrap-recovery requires --apply and --expected-head"
            )
        if args.check:
            core.check(repo, runtime)
        elif args.preflight:
            snapshot, _, topology = preflight_url(repo, runtime, profile_path)
            print("PASS: Deployment-Preflight erfolgreich")
            print(f"Repo-HEAD:       {snapshot.repo_head}")
            print(f"Topologie:       {topology.kind}")
            print(f"Entry-Point:     {snapshot.contract.describe()}")
        else:
            if not bootstrap_recovery:
                preflight_url(
                    repo,
                    runtime,
                    profile_path,
                    expected_head=expected_head,
                )
            with core.deployment_lock(lock_file):
                deploy_url(
                    repo,
                    runtime,
                    profile_path,
                    timeout_seconds=args.timeout,
                    expected_head=expected_head,
                    bootstrap_recovery=bootstrap_recovery,
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
