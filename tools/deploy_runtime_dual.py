#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
from dataclasses import dataclass
import errno
import hashlib
from importlib import import_module
import json
import math
import os
from pathlib import Path
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
TRANSPORT_INGRESS_LISTENER_PORT = 18180
TRANSPORT_INGRESS_AUTH_HEADER = "X-Grabowski-Ingress-Auth"
TRANSPORT_CONNECTOR_TOKEN_PATH = core.HOME / ".local/state/grabowski/transport-connectors/primary.token"
LEGACY_TUNNEL_OPERATOR_PORT = OPERATOR_LISTENER_PORT
TUNNEL_TARGET_PORTS = frozenset({LEGACY_TUNNEL_OPERATOR_PORT, TRANSPORT_INGRESS_LISTENER_PORT})
TRANSPORT_INGRESS_HEALTH_URL = f"http://127.0.0.1:{TRANSPORT_INGRESS_LISTENER_PORT}/_grabowski/transport-ingress"
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
OPERATOR_ADMISSION_STATUS_URL = (
    f"http://{OPERATOR_LISTENER_HOST}:{OPERATOR_LISTENER_PORT}"
    "/_grabowski/deployment-admission"
)
OPERATOR_ADMISSION_MARKER_KIND = "grabowski_deployment_admission_drain"
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
        f'  extra_headers:\n    - "{_transport_ingress_auth_reference()}"\n'
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


def require_transport_ingress_health() -> dict[str, Any]:
    request = Request(TRANSPORT_INGRESS_HEALTH_URL, headers={"Cache-Control": "no-store", "Accept": "application/json"}, method="GET")
    try:
        with urlopen(request, timeout=2) as response:
            status = int(response.status)
            raw = response.read(8193)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        core.fail("Signierter Transport-Ingress ist nicht erreichbar", details={"error_type": type(exc).__name__})
    if status != 200 or len(raw) > 8192:
        core.fail("Signierter Transport-Ingress lieferte keinen gültigen Health-Status")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        core.fail("Transport-Ingress-Health ist kein gültiges JSON", details={"error_type": type(exc).__name__})
    if not isinstance(value, dict) or value.get("healthy") is not True or value.get("assertion_version") != "signed-one-call-v1":
        core.fail("Transport-Ingress-Health entspricht nicht dem One-Call-Vertrag")
    return value


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
    try:
        binding = deployment_observer.build_activation_binding(
            contract,
            metadata=metadata,
            marker=marker,
        )
        path = deployment_observer.activation_path(directory)
        deployment_observer.create_activation(path, binding)
        observed = deployment_observer.read_activation(path)
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
            details={"error_type": type(exc).__name__},
        )
    return {
        "unit": binding["unit"],
        "contract_sha256": binding["contract_sha256"],
        "binding_sha256": binding["binding_sha256"],
        "expires_at_unix": binding["expires_at_unix"],
    }


def engage_operator_deployment_admission(
    snapshot: core.Snapshot, *, timeout_seconds: int
) -> dict[str, Any]:
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
        "expected_head": snapshot.repo_head,
        "source_identity_sha256": _deployment_source_identity_sha256(snapshot),
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


def _operator_admission_observation() -> dict[str, Any] | None:
    request = Request(
        OPERATOR_ADMISSION_STATUS_URL,
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
    marker: dict[str, Any], *, timeout_seconds: int
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
            first = _operator_admission_observation()
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
    drain_timeout_seconds = (
        timeout_seconds
        if initial_counts["effect_aware"]
        else max(timeout_seconds, OPERATOR_ADMISSION_BOOTSTRAP_DRAIN_SECONDS)
    )
    deadline = time.monotonic() + drain_timeout_seconds
    consecutive_idle = 0
    attempts = 0
    last = first
    while True:
        attempts += 1
        observed = first if attempts == 1 else _operator_admission_observation()
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
            "last_observation": last,
        },
    )


def verify_operator_deployment_admission(
    marker: dict[str, Any],
) -> dict[str, Any]:
    observed = _operator_admission_observation()
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
    require_operator_listener()
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
    try:
        core.verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)
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

        phase = "activate-pointer"
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
        phase = "operator-admission-replacement-guard"
        verify_operator_deployment_admission(admission_marker)

        if profile_cutover is not None:
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
