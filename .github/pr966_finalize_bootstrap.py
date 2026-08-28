#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "tools" / "grabowski_privileged_broker.py"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    return text.replace(old, new, 1)


def replace_def(text: str, name: str, next_name: str, replacement: str) -> str:
    start = text.find(f"def {name}(")
    end = text.find(f"\ndef {next_name}(", start)
    if start < 0 or end < 0:
        raise SystemExit(f"function boundary missing: {name} -> {next_name}")
    return text[:start] + replacement.rstrip() + "\n\n" + text[end + 1:]


broker = BROKER.read_text(encoding="utf-8")
broker = replace_once(
    broker,
    'PACKAGE_UPDATE_STAGE_LOCK = STATE / "package-update-stage.lock"\n',
    'PACKAGE_UPDATE_STAGE_LOCK = STATE / "package-update-stage.lock"\n'
    'PACKAGE_UPDATE_APPLY_CONSUMED_ROOT = STATE / "package-update-apply-consumed"\n',
    "consumption root constant",
)

broker = replace_def(
    broker,
    "_argv_mentions_package_stage",
    "_package_stage_operation",
    r'''def _argv_mentions_package_stage(argv: object) -> bool:
    if not isinstance(argv, list):
        return False
    root = str(PACKAGE_UPDATE_STAGE_ROOT)
    prefix = root + os.sep
    for value in argv:
        if not isinstance(value, str) or "\x00" in value:
            continue
        # Fail closed on lexical descendants before canonical parsing so that
        # alternate spellings cannot opt out of the package-stage guard.
        if value == root or value.startswith(prefix):
            return True
        if not os.path.isabs(value):
            continue
        normalized = os.path.normpath(value)
        try:
            if os.path.commonpath((root, normalized)) == root:
                return True
        except ValueError:
            continue
    return False


def _expected_package_dpkg_preflight_argv(paths: list[str]) -> list[str]:
    return [
        "/usr/bin/dpkg",
        "--simulate",
        "--refuse-downgrade",
        "--force-confold",
        "--install",
        *paths,
    ]


def _expected_package_apt_systemd_argv(plan_id: str, paths: list[str]) -> list[str]:
    capture = f"/run/heim-pc-package-update-captures/{plan_id}"
    return [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--collect",
        "--pipe",
        f"--unit=heim-pc-package-update-{plan_id}.service",
        "--property=Type=exec",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateMounts=yes",
        "--property=PrivateNetwork=yes",
        f"--property=BindPaths={capture}:/run",
        "--property=ProtectProc=invisible",
        "--property=ProcSubset=pid",
        "--property=BindReadOnlyPaths=/dev/null:/run/systemd/private /dev/null:/run/dbus/system_bus_socket",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectControlGroups=yes",
        "--property=PrivateDevices=yes",
        "--property=RestrictNamespaces=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectClock=yes",
        "--property=LockPersonality=yes",
        "--property=CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_SYS_BOOT CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_TIME CAP_SYS_TTY_CONFIG",
        "--property=MemoryDenyWriteExecute=no",
        "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "--property=IPAddressDeny=any",
        "--",
        "/usr/bin/dpkg",
        "--refuse-downgrade",
        "--force-confold",
        "--install",
        *paths,
    ]''',
)

broker = replace_def(
    broker,
    "_package_stage_operation",
    "_ensure_package_state_root",
    r'''def _package_stage_operation(argv: object) -> dict[str, object] | None:
    """Classify package-stage argv for additional fail-closed broker guards."""
    if not _argv_mentions_package_stage(argv):
        return None
    if not isinstance(argv, list) or not argv:
        raise PermissionError("package stage operation argv is invalid")
    root = str(PACKAGE_UPDATE_STAGE_ROOT)
    if argv == ["/usr/bin/stat", "-f", "-c", "%a:%S", root]:
        return {"kind": "readback", "plan_id": None, "package_paths": [], "exact_evidence": False}
    if _package_output_evidence_allowed(argv) and argv[0] == "/usr/bin/sha256sum":
        bindings = [_package_stage_binding(value) for value in argv[1:]]
        plan_ids = {binding[0] for binding in bindings if binding is not None}
        if len(plan_ids) != 1 or any(binding is None or binding[2] is None for binding in bindings):
            raise PermissionError("package hash readback paths are not exact stage files")
        return {
            "kind": "readback",
            "plan_id": next(iter(plan_ids)),
            "package_paths": list(argv[1:]),
            "exact_evidence": False,
        }
    if argv[0] == "/usr/bin/install":
        bindings = [binding for value in argv[1:] if (binding := _package_stage_binding(value)) is not None]
        if not bindings:
            raise PermissionError("package install mentions stage root without a canonical stage binding")
        if len({binding[0] for binding in bindings}) != 1:
            raise PermissionError("package install spans multiple plans")
        return {"kind": "mutation", "plan_id": bindings[0][0], "package_paths": [], "exact_evidence": False}
    if argv[0] == "/usr/bin/rm":
        bindings = [binding for value in argv[1:] if (binding := _package_stage_binding(value)) is not None]
        if not bindings or len({binding[0] for binding in bindings}) != 1:
            raise PermissionError("package cleanup stage binding is invalid")
        return {"kind": "mutation", "plan_id": bindings[0][0], "package_paths": [], "exact_evidence": False}
    if argv[0] == "/usr/bin/dpkg":
        file_bindings = [
            (value, binding)
            for value in argv[1:]
            if (binding := _package_stage_binding(value)) is not None and binding[2] is not None
        ]
        if (
            not file_bindings
            or any(binding[1] != "debs" for _, binding in file_bindings)
            or len({binding[0] for _, binding in file_bindings}) != 1
        ):
            raise PermissionError("dpkg package stage execution is not exact-file bound")
        plan_id = file_bindings[0][1][0]
        paths = [value for value, _ in file_bindings]
        if argv != _expected_package_dpkg_preflight_argv(paths):
            raise PermissionError("dpkg package stage preflight argv is not the exact released simulation")
        return {
            "kind": "preflight",
            "operation": "apt_preflight",
            "plan_id": plan_id,
            "package_paths": paths,
            "exact_evidence": True,
        }
    if argv[0] == "/usr/bin/systemd-run":
        file_bindings = [
            (value, binding)
            for value in argv[1:]
            if (binding := _package_stage_binding(value)) is not None and binding[2] is not None
        ]
        if (
            not file_bindings
            or any(binding[1] != "debs" for _, binding in file_bindings)
            or len({binding[0] for _, binding in file_bindings}) != 1
        ):
            raise PermissionError("package systemd dpkg paths are not exact stage DEBs")
        plan_id = file_bindings[0][1][0]
        paths = [value for value, _ in file_bindings]
        if argv != _expected_package_apt_systemd_argv(plan_id, paths):
            raise PermissionError("package systemd execution is not the exact synchronous local APT apply")
        return {
            "kind": "apply",
            "operation": "apt_apply",
            "plan_id": plan_id,
            "package_paths": paths,
            "exact_evidence": True,
        }
    if argv[:2] in (["/usr/bin/snap", "ack"], ["/usr/bin/snap", "install"]):
        if len(argv) != 3:
            raise PermissionError("snap package stage execution has unexpected arguments")
        binding = _package_stage_binding(argv[2])
        if binding is None or binding[1] != "snaps" or binding[2] is None:
            raise PermissionError("snap package stage execution is not exact-file bound")
        return {
            "kind": "apply",
            "operation": "snap_ack" if argv[1] == "ack" else "snap_install",
            "plan_id": binding[0],
            "package_paths": [argv[2]],
            "exact_evidence": True,
        }
    raise PermissionError("unclassified package stage operation is forbidden")''',
)

broker = replace_def(
    broker,
    "_read_package_hash_evidence",
    "_sha256_regular_root_file",
    r'''def _read_package_output_evidence(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    if (
        path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o640 or metadata.st_nlink != 1
        or metadata.st_size > 64 * 1024
    ):
        raise PermissionError("package output evidence file is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("kind") != OUTPUT_EVIDENCE_KIND:
        raise ValueError("package output evidence schema is invalid")
    digest = value.get("evidence_sha256")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or canonical_sha256(unsigned) != digest
    ):
        raise ValueError("package output evidence digest is invalid")
    return value


def _read_package_hash_evidence(path: Path) -> dict[str, object]:
    value = _read_package_output_evidence(path)
    paths = value.get("package_paths")
    hashes = value.get("package_sha256")
    plan_id = value.get("package_plan_id")
    if (
        not isinstance(paths, list) or not paths or not isinstance(hashes, dict)
        or set(hashes) != set(paths) or len(hashes) != len(paths) or not isinstance(plan_id, str)
        or PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None
    ):
        raise ValueError("package hash evidence package binding is invalid")
    for raw_path, digest_value in hashes.items():
        binding = _package_stage_binding(raw_path)
        if binding is None or binding[0] != plan_id or binding[2] is None:
            raise ValueError("package hash evidence contains an unsafe path")
        if not isinstance(digest_value, str) or re.fullmatch(r"[0-9a-f]{64}", digest_value) is None:
            raise ValueError("package hash evidence contains an invalid digest")
    return value''',
)

broker = replace_def(
    broker,
    "_find_package_apply_evidence",
    "_package_output_evidence_allowed",
    r'''def _package_evidence_candidates() -> list[Path]:
    metadata = OUTPUT_EVIDENCE_ROOT.lstat()
    if (
        OUTPUT_EVIDENCE_ROOT.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise PermissionError("package output evidence root is unsafe")
    candidates: list[Path] = []
    with os.scandir(OUTPUT_EVIDENCE_ROOT) as entries:
        for entry in entries:
            if len(candidates) >= MAX_OUTPUT_EVIDENCE_FILES:
                raise PermissionError("package output evidence inventory exceeds bound")
            if entry.name.endswith(".json") and entry.is_file(follow_symlinks=False):
                candidates.append(Path(entry.path))
    return candidates


def _find_package_apply_evidence(
    operation: dict[str, object], *, peer_uid: int, peer_unit: str
) -> dict[str, object]:
    required_paths = operation.get("package_paths")
    plan_id = operation.get("plan_id")
    if not isinstance(required_paths, list) or not required_paths or not isinstance(plan_id, str):
        raise PermissionError("package operation lacks exact stage paths")
    now = int(time.time())
    valid: list[dict[str, object]] = []
    for path in _package_evidence_candidates():
        try:
            value = _read_package_hash_evidence(path)
        except (OSError, PermissionError, ValueError, json.JSONDecodeError):
            continue
        timestamp = value.get("timestamp_unix")
        evidence_paths = value.get("package_paths")
        if (
            value.get("peer_uid") != peer_uid
            or value.get("peer_unit") != peer_unit
            or value.get("package_plan_id") != plan_id
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or timestamp > now + 5
            or now - timestamp > PACKAGE_OUTPUT_EVIDENCE_MAX_AGE_SECONDS
            or not isinstance(evidence_paths, list)
            or any(path_value not in evidence_paths for path_value in required_paths)
        ):
            continue
        valid.append(value)
    if not valid:
        raise PermissionError("no fresh root-owned package hash evidence matches operation")
    valid.sort(key=lambda item: (int(item["timestamp_unix"]), str(item["request_id"])), reverse=True)
    evidence = valid[0]
    hashes = evidence["package_sha256"]
    assert isinstance(hashes, dict)
    for raw_path in required_paths:
        expected = hashes.get(raw_path)
        if not isinstance(expected, str) or _sha256_regular_root_file(Path(raw_path)) != expected:
            raise PermissionError("package stage bytes changed after authenticated hash readback")
    return evidence


def _argv_sha256(argv: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _find_package_preflight_evidence(
    operation: dict[str, object],
    *,
    guard_evidence: dict[str, object],
    peer_uid: int,
    peer_unit: str,
) -> dict[str, object]:
    required_paths = operation.get("package_paths")
    plan_id = operation.get("plan_id")
    guard_sha256 = guard_evidence.get("evidence_sha256")
    guard_timestamp = guard_evidence.get("timestamp_unix")
    if (
        operation.get("operation") != "apt_apply"
        or not isinstance(required_paths, list)
        or not required_paths
        or not isinstance(plan_id, str)
        or not isinstance(guard_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", guard_sha256) is None
        or isinstance(guard_timestamp, bool)
        or not isinstance(guard_timestamp, int)
    ):
        raise PermissionError("APT apply lacks authenticated preflight binding inputs")
    expected_argv_sha256 = _argv_sha256(_expected_package_dpkg_preflight_argv(required_paths))
    now = int(time.time())
    valid: list[dict[str, object]] = []
    for path in _package_evidence_candidates():
        try:
            value = _read_package_output_evidence(path)
        except (OSError, PermissionError, ValueError, json.JSONDecodeError):
            continue
        timestamp = value.get("timestamp_unix")
        if (
            value.get("package_preflight_completed") is not True
            or value.get("package_plan_id") != plan_id
            or value.get("package_paths") != required_paths
            or value.get("package_preflight_guard_evidence_sha256") != guard_sha256
            or value.get("argv_sha256") != expected_argv_sha256
            or value.get("peer_uid") != peer_uid
            or value.get("peer_unit") != peer_unit
            or value.get("returncode") != 0
            or value.get("timed_out") is not False
            or value.get("stdout_truncated") is not False
            or value.get("stderr_truncated") is not False
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or timestamp < guard_timestamp
            or timestamp > now + 5
            or now - timestamp > PACKAGE_OUTPUT_EVIDENCE_MAX_AGE_SECONDS
        ):
            continue
        valid.append(value)
    if not valid:
        raise PermissionError("no fresh authenticated successful APT preflight matches apply")
    valid.sort(key=lambda item: (int(item["timestamp_unix"]), str(item["request_id"])), reverse=True)
    return valid[0]


def _package_apply_consumption_binding(
    operation: dict[str, object],
    *,
    guard_evidence: dict[str, object],
    argv: list[str],
) -> dict[str, object]:
    plan_id = operation.get("plan_id")
    paths = operation.get("package_paths")
    guard_sha256 = guard_evidence.get("evidence_sha256")
    if (
        operation.get("kind") != "apply"
        or not isinstance(plan_id, str)
        or PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None
        or not isinstance(paths, list)
        or not paths
        or any(not isinstance(path, str) or _package_stage_binding(path) is None for path in paths)
        or not isinstance(guard_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", guard_sha256) is None
    ):
        raise PermissionError("package apply consumption binding is invalid")
    return {
        "schema_version": 1,
        "package_plan_id": plan_id,
        "package_paths": list(paths),
        "package_guard_evidence_sha256": guard_sha256,
        "argv_sha256": _argv_sha256(argv),
    }


def _package_apply_consumption_path(binding: dict[str, object]) -> Path:
    return PACKAGE_UPDATE_APPLY_CONSUMED_ROOT / f"{canonical_sha256(binding)}.json"


def _ensure_package_apply_consumption_root() -> None:
    _ensure_package_state_root()
    try:
        PACKAGE_UPDATE_APPLY_CONSUMED_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = PACKAGE_UPDATE_APPLY_CONSUMED_ROOT.lstat()
    if (
        PACKAGE_UPDATE_APPLY_CONSUMED_ROOT.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink < 1
    ):
        raise PermissionError("package apply consumption root is unsafe")


def _assert_package_apply_not_consumed(
    operation: dict[str, object],
    *,
    guard_evidence: dict[str, object],
    argv: list[str],
) -> dict[str, object]:
    binding = _package_apply_consumption_binding(
        operation, guard_evidence=guard_evidence, argv=argv
    )
    _ensure_package_apply_consumption_root()
    path = _package_apply_consumption_path(binding)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return binding
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise PermissionError("package apply consumption marker is unsafe")
    raise PermissionError("package apply guard evidence was already consumed for this exact operation")


def _consume_package_apply(binding: dict[str, object]) -> dict[str, str]:
    _ensure_package_apply_consumption_root()
    path = _package_apply_consumption_path(binding)
    record: dict[str, object] = {
        **binding,
        "package_apply_completed": True,
        "timestamp_unix": int(time.time()),
    }
    record["record_sha256"] = canonical_sha256(record)
    raw = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise PermissionError(
            "package apply guard evidence was already consumed for this exact operation"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise PermissionError("package apply consumption marker is unsafe")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("package apply consumption marker write was incomplete")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        PACKAGE_UPDATE_APPLY_CONSUMED_ROOT,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"path": str(path), "sha256": str(record["record_sha256"])}''',
)

broker = replace_once(
    broker,
    '    package_guard_evidence: dict[str, object] | None = None,\n) -> dict[str, str]:',
    '    package_guard_evidence: dict[str, object] | None = None,\n'
    '    package_preflight_evidence: dict[str, object] | None = None,\n'
    ') -> dict[str, str]:',
    "evidence function signature",
)
broker = replace_once(
    broker,
    '        "stdout_truncated", "timestamp_unix",\n',
    '        "stdout_truncated", "stderr_truncated", "timestamp_unix",\n',
    "evidence required stderr",
)
broker = replace_once(
    broker,
    '        or record.get("stdout_truncated") is not False\n',
    '        or record.get("stdout_truncated") is not False\n'
    '        or record.get("stderr_truncated") is not False\n',
    "evidence stderr gate",
)
broker = replace_once(
    broker,
    '        "stdout_truncated": record["stdout_truncated"],\n'
    '        "timestamp_unix": record["timestamp_unix"],\n',
    '        "stdout_truncated": record["stdout_truncated"],\n'
    '        "stderr_truncated": record["stderr_truncated"],\n'
    '        "timestamp_unix": record["timestamp_unix"],\n',
    "evidence stderr field",
)

broker = replace_once(
    broker,
    '''    if package_operation is not None:
        if package_operation.get("kind") != "apply":
            raise ValueError("package completion evidence requires an apply operation")
        plan_id = package_operation.get("plan_id")
        package_paths = package_operation.get("package_paths")
        guard_sha256 = (package_guard_evidence or {}).get("evidence_sha256")
        if (
            not isinstance(plan_id, str) or PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None
            or not isinstance(package_paths, list) or not package_paths
            or any(not isinstance(path, str) or _package_stage_binding(path) is None for path in package_paths)
            or not isinstance(guard_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", guard_sha256) is None
        ):
            raise ValueError("package completion evidence binding is invalid")
        evidence["package_plan_id"] = plan_id
        evidence["package_paths"] = list(package_paths)
        evidence["package_apply_completed"] = True
        evidence["package_apply_guard_evidence_sha256"] = guard_sha256
        evidence["package_exact_evidence"] = package_operation.get("exact_evidence") is True
''',
    '''    if package_operation is not None:
        kind = package_operation.get("kind")
        if kind not in {"preflight", "apply"}:
            raise ValueError("package completion evidence requires a preflight or apply operation")
        plan_id = package_operation.get("plan_id")
        package_paths = package_operation.get("package_paths")
        guard_sha256 = (package_guard_evidence or {}).get("evidence_sha256")
        if (
            not isinstance(plan_id, str) or PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None
            or not isinstance(package_paths, list) or not package_paths
            or any(not isinstance(path, str) or _package_stage_binding(path) is None for path in package_paths)
            or not isinstance(guard_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", guard_sha256) is None
        ):
            raise ValueError("package completion evidence binding is invalid")
        evidence["package_plan_id"] = plan_id
        evidence["package_paths"] = list(package_paths)
        evidence["package_operation"] = package_operation.get("operation")
        evidence["package_exact_evidence"] = package_operation.get("exact_evidence") is True
        if kind == "preflight":
            evidence["package_preflight_completed"] = True
            evidence["package_preflight_guard_evidence_sha256"] = guard_sha256
        else:
            evidence["package_apply_completed"] = True
            evidence["package_apply_guard_evidence_sha256"] = guard_sha256
            if package_operation.get("operation") == "apt_apply":
                preflight_sha256 = (package_preflight_evidence or {}).get("evidence_sha256")
                if (
                    not isinstance(preflight_sha256, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preflight_sha256) is None
                ):
                    raise ValueError("APT apply completion evidence lacks authenticated preflight")
                evidence["package_apply_preflight_evidence_sha256"] = preflight_sha256
''',
    "package completion evidence body",
)

broker = replace_def(
    broker,
    "_execute_broker_command",
    "_resolve_broker_execution",
    r'''def _execute_broker_command(
    *,
    reference: dict[str, object],
    execution: dict[str, object],
    operator_peer: dict[str, object] | None,
) -> dict[str, object]:
    argv = execution["argv"]
    timeout = execution["timeout_seconds"]
    cwd = execution.get("cwd")
    package_operation = _package_stage_operation(argv) if reference.get("action") == POWER_ACTION else None
    package_identity_before: dict[str, tuple[int, ...]] | None = None
    package_guard_evidence: dict[str, object] | None = None
    package_preflight_evidence: dict[str, object] | None = None
    package_consumption_binding: dict[str, object] | None = None
    package_consumption: dict[str, str] | None = None
    context = _package_stage_lock() if package_operation is not None else nullcontext()
    with context:
        if (
            package_operation is not None
            and package_operation.get("kind") == "readback"
            and _package_output_evidence_allowed(argv)
        ):
            package_identity_before = _package_output_identity_snapshot(argv)
        if package_operation is not None and package_operation.get("kind") in {"preflight", "apply"}:
            if operator_peer is None:
                raise PermissionError("package preflight/apply requires validated operator peer")
            peer_fields = _operator_peer_audit_fields(operator_peer)
            package_guard_evidence = _find_package_apply_evidence(
                package_operation,
                peer_uid=int(peer_fields["peer_uid"]),
                peer_unit=str(peer_fields["peer_unit"]),
            )
            if package_operation.get("kind") == "apply":
                if package_operation.get("operation") == "apt_apply":
                    package_preflight_evidence = _find_package_preflight_evidence(
                        package_operation,
                        guard_evidence=package_guard_evidence,
                        peer_uid=int(peer_fields["peer_uid"]),
                        peer_unit=str(peer_fields["peer_unit"]),
                    )
                package_consumption_binding = _assert_package_apply_not_consumed(
                    package_operation,
                    guard_evidence=package_guard_evidence,
                    argv=argv,
                )
        started = time.monotonic()
        process = subprocess.Popen(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            stdout_bytes, stderr_bytes = _communicate_after_timeout(
                action=reference.get("action"), process=process,
            )
        stdout = stdout_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr = stderr_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        record = {
            **_base_audit_record(reference, execution, started),
            **(_operator_peer_audit_fields(operator_peer) if operator_peer is not None else {}),
            "returncode": None if timed_out else process.returncode,
            "timed_out": timed_out,
            "stdout_truncated": len(stdout_bytes) > MAX_OUTPUT_BYTES,
            "stderr_truncated": len(stderr_bytes) > MAX_OUTPUT_BYTES,
        }
        if reference["action"] == POWER_ACTION:
            record.update({
                "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
                "stdout_bytes": len(stdout_bytes),
                "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
                "stderr_bytes": len(stderr_bytes),
            })
        if package_operation is not None:
            record["package_stage_guard"] = str(package_operation.get("kind"))
            record["package_stage_plan_id"] = package_operation.get("plan_id")
            record["package_stage_operation"] = package_operation.get("operation")
        if package_guard_evidence is not None:
            record["package_guard_evidence_sha256"] = package_guard_evidence.get("evidence_sha256")
            record["package_guard_evidence_request_id"] = package_guard_evidence.get("request_id")
            if package_operation is not None and package_operation.get("kind") == "apply":
                record["package_apply_evidence_sha256"] = package_guard_evidence.get("evidence_sha256")
                record["package_apply_evidence_request_id"] = package_guard_evidence.get("request_id")
        if package_preflight_evidence is not None:
            record["package_apply_preflight_evidence_sha256"] = package_preflight_evidence.get("evidence_sha256")
            record["package_apply_preflight_evidence_request_id"] = package_preflight_evidence.get("request_id")

        consumption_error: Exception | None = None
        if (
            package_operation is not None
            and package_operation.get("kind") == "apply"
            and record["returncode"] == 0
            and record["timed_out"] is False
        ):
            if package_consumption_binding is None:
                raise RuntimeError("package apply has no replay-consumption binding")
            try:
                package_consumption = _consume_package_apply(package_consumption_binding)
                record["package_apply_consumed_sha256"] = package_consumption["sha256"]
            except (OSError, PermissionError, RuntimeError, ValueError) as exc:
                consumption_error = exc
                record["package_apply_consumption_error"] = type(exc).__name__

        append_audit(record)
        if consumption_error is not None:
            raise PermissionError(
                "package apply succeeded but replay-consumption marker could not be committed"
            ) from consumption_error

        output_evidence = None
        output_evidence_status = "not-applicable"
        readback_retry_safe = False
        if package_identity_before is not None:
            readback_retry_safe = True
            output_evidence_status = "unavailable"
            if (
                record["returncode"] == 0
                and record["timed_out"] is False
                and record["stdout_truncated"] is False
                and record["stderr_truncated"] is False
            ):
                try:
                    package_identity_after = _package_output_identity_snapshot(argv)
                    if package_identity_after != package_identity_before:
                        raise PermissionError("package readback identity changed during execution")
                    output_evidence = _write_output_evidence(
                        record, argv=argv, stdout_bytes=stdout_bytes
                    )
                    output_evidence_status = "published"
                except (OSError, PermissionError, RuntimeError, ValueError):
                    output_evidence = None
                    output_evidence_status = "unavailable"
        elif package_operation is not None and package_operation.get("kind") in {"preflight", "apply"}:
            output_evidence_status = "unavailable"
            if (
                record["returncode"] == 0
                and record["timed_out"] is False
                and record["stdout_truncated"] is False
                and record["stderr_truncated"] is False
            ):
                try:
                    output_evidence = _write_output_evidence(
                        record,
                        argv=argv,
                        stdout_bytes=stdout_bytes,
                        package_operation=package_operation,
                        package_guard_evidence=package_guard_evidence,
                        package_preflight_evidence=package_preflight_evidence,
                    )
                    output_evidence_status = "published"
                except (OSError, PermissionError, RuntimeError, ValueError):
                    output_evidence = None
                    output_evidence_status = "unavailable"
    return {
        "stdout": stdout,
        "stderr": stderr,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "record": record,
        "timed_out": timed_out,
        "returncode": None if timed_out else process.returncode,
        "output_evidence": output_evidence,
        "output_evidence_status": output_evidence_status,
        "readback_retry_safe": readback_retry_safe,
        "package_apply_consumption": package_consumption,
    }''',
)

BROKER.write_text(broker, encoding="utf-8")
