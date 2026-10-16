#!/usr/bin/env python3
"""Authorize one RepoBrief Codex benchmark pair without launching the provider.

This adapter keeps the shared pair/manifest/budget/repository/ledger contract in
the preflight core while binding the exact Codex runner, executable and ChatGPT
subscription gate.  It creates one fail-closed dispatch authorization only; it
does not execute a benchmark request and never grants retry authority.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any


SOURCE_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024
CODEX_CREDENTIAL_COMMITMENT_KIND = "grabowski.codex_credential_commitment"
CODEX_CREDENTIAL_COMMITMENT_DOMAIN = "grabowski.codex-credential-commitment.v1"

ENTRYPOINT_BOOTSTRAP_KIND = "grabowski.python_c_source_bootstrap"
ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION = 1
ENTRYPOINT_BOOTSTRAP_NAME = "repobrief_agent_benchmark_source_bootstrap.py"
ENTRYPOINT_BOOTSTRAP_PATH = Path(__file__).with_name(ENTRYPOINT_BOOTSTRAP_NAME)


def _open_absolute_regular_nofollow(path: Path, *, label: str) -> int:
    requested = path.expanduser()
    if not requested.is_absolute():
        raise RuntimeError(f"{label} path must be absolute")
    parts = requested.parts
    if (
        len(parts) < 2
        or parts[0] != os.sep
        or any(part in {"", ".", ".."} for part in parts[1:])
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise RuntimeError(f"{label} path is not safely openable")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directories: list[int] = []
    try:
        current = os.open(os.sep, directory_flags)
        directories.append(current)
        for component in parts[1:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            directories.append(current)
            if not stat.S_ISDIR(os.fstat(current).st_mode):
                raise RuntimeError(f"{label} parent path is not a directory")
        return os.open(parts[-1], file_flags, dir_fd=current)
    except OSError as exc:
        raise RuntimeError(f"{label} path must be symlink-free") from exc
    finally:
        for directory_fd in reversed(directories):
            os.close(directory_fd)


def _read_source_snapshot(path: Path) -> tuple[bytes, dict[str, Any]]:
    requested = path.expanduser()
    before = requested.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"cannot safely load {path.name}")
    if before.st_size <= 0 or before.st_size > SOURCE_SNAPSHOT_MAX_BYTES:
        raise RuntimeError(f"cannot safely load {path.name}")
    descriptor = _open_absolute_regular_nofollow(requested, label=f"{path.name} source")
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise RuntimeError(f"{path.name} changed before load")
        data = bytearray()
        while len(data) <= SOURCE_SNAPSHOT_MAX_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, SOURCE_SNAPSHOT_MAX_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after_descriptor = os.fstat(descriptor)
        try:
            descriptor_path = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError as exc:
            raise RuntimeError(f"{path.name} opened path cannot be bound") from exc
        if (
            not os.path.isabs(descriptor_path)
            or descriptor_path.endswith(" (deleted)")
            or os.path.normpath(descriptor_path) != os.path.normpath(str(requested))
        ):
            raise RuntimeError(f"{path.name} opened path is unavailable")
        after = requested.lstat()
        if (
            len(data) != opened.st_size
            or len(data) > SOURCE_SNAPSHOT_MAX_BYTES
            or (
                after_descriptor.st_dev,
                after_descriptor.st_ino,
                after_descriptor.st_size,
            )
            != (opened.st_dev, opened.st_ino, opened.st_size)
            or (after.st_dev, after.st_ino, after.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
        ):
            raise RuntimeError(f"{path.name} changed during load")
        resolved = Path(descriptor_path)
        return bytes(data), {
            "path": str(resolved),
            "name": resolved.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    finally:
        os.close(descriptor)


_CAPTURED_ENTRYPOINT_ACTIVE = (
    globals().get("__grabowski_captured_entrypoint_active__") is True
)
_CAPTURED_ENTRYPOINT_RAW = globals().get("__grabowski_captured_entrypoint_raw__")
_CAPTURED_ENTRYPOINT_IDENTITY = globals().get(
    "__grabowski_captured_entrypoint_identity__"
)
_ENTRYPOINT_BOOTSTRAP_RAW = globals().get("__grabowski_entrypoint_bootstrap_raw__")
_ENTRYPOINT_BOOTSTRAP_IDENTITY = globals().get(
    "__grabowski_entrypoint_bootstrap_identity__"
)


def _validated_captured_self_source(
    raw: Any, identity: Any, source: Path
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(raw, (bytes, bytearray)) or not isinstance(identity, dict):
        raise RuntimeError("captured Codex preflight source binding is invalid")
    data = bytes(raw)
    resolved = source.expanduser().resolve()
    expected = {
        "path": str(resolved),
        "name": resolved.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if identity != expected:
        raise RuntimeError("captured Codex preflight source identity mismatch")
    return data, expected


def _validated_entrypoint_bootstrap_context(
    raw: Any, identity: Any
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(raw, (bytes, bytearray)) or not isinstance(identity, dict):
        raise RuntimeError("immutable Codex preflight bootstrap binding is missing")
    data = bytes(raw)
    expected = {
        "schema_version": ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION,
        "kind": ENTRYPOINT_BOOTSTRAP_KIND,
        "name": ENTRYPOINT_BOOTSTRAP_NAME,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if identity != expected:
        raise RuntimeError("immutable Codex preflight bootstrap identity mismatch")
    return data, expected


if __name__ == "__main__":
    if not _CAPTURED_ENTRYPOINT_ACTIVE:
        raise RuntimeError(
            "Codex preflight must be started through the immutable source bootstrap"
        )
    _ENTRYPOINT_BOOTSTRAP_RAW, _ENTRYPOINT_BOOTSTRAP_IDENTITY = (
        _validated_entrypoint_bootstrap_context(
            _ENTRYPOINT_BOOTSTRAP_RAW, _ENTRYPOINT_BOOTSTRAP_IDENTITY
        )
    )
    _SELF_SOURCE_RAW, _SELF_SOURCE_IDENTITY = _validated_captured_self_source(
        _CAPTURED_ENTRYPOINT_RAW,
        _CAPTURED_ENTRYPOINT_IDENTITY,
        Path(__file__),
    )
else:
    _SELF_SOURCE_RAW, _SELF_SOURCE_IDENTITY = _read_source_snapshot(Path(__file__))


def _load(name: str, path: Path) -> Any:
    raw, identity = _read_source_snapshot(path)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
        _after_raw, after_identity = _read_source_snapshot(path)
        if after_identity != identity:
            raise RuntimeError(f"{path.name} changed while being loaded")
    except BaseException:
        sys.modules.pop(name, None)
        raise
    module.__grabowski_source_identity__ = dict(identity)
    return module


CORE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_preflight_core.py")
CODEX_RUNNER_PATH = Path(__file__).with_name(
    "repobrief_agent_benchmark_codex_runner.py"
)
core = _load("repobrief_agent_benchmark_preflight_core_for_codex", CORE_PATH)
codex_runner = _load(
    "repobrief_agent_benchmark_codex_runner_for_authorization", CODEX_RUNNER_PATH
)
core._register_startup_code_identity(core.__grabowski_source_identity__)
core._register_startup_code_identity(_SELF_SOURCE_IDENTITY)
core._register_startup_code_identity(codex_runner.__grabowski_source_identity__)
if _ENTRYPOINT_BOOTSTRAP_IDENTITY is not None:
    core._register_startup_bootstrap_identity(_ENTRYPOINT_BOOTSTRAP_IDENTITY)


def _credential_commitment_sha256(credential_data: bytes, nonce: str) -> str:
    credential_sha256 = hashlib.sha256(credential_data).hexdigest()
    payload = json.dumps(
        {
            "domain": CODEX_CREDENTIAL_COMMITMENT_DOMAIN,
            "nonce": nonce,
            "credential_sha256": credential_sha256,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _codex_credential_commitment(credential_data: bytes) -> dict[str, Any]:
    nonce = secrets.token_hex(16)
    return {
        "schema_version": 1,
        "kind": CODEX_CREDENTIAL_COMMITMENT_KIND,
        "nonce": nonce,
        "commitment_sha256": _credential_commitment_sha256(credential_data, nonce),
    }


def _validated_codex_provider_binding(
    codex_command: str, codex_command_sha256: str
) -> dict[str, Any]:
    executable = codex_runner.validate_executable(
        codex_command, codex_command_sha256, require_read_only_mount=True
    )
    codex_runner.validate_toolchain(executable)
    auth_data = codex_runner.validate_chatgpt_subscription(executable)
    metadata = Path(executable).lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise codex_runner.RunnerError("Codex executable identity is invalid")
    return {
        "mode": "live_provider",
        "runner": {
            "execution_contract": codex_runner.EXECUTION_CONTRACT,
            "provider": codex_runner.PROVIDER,
            "model": codex_runner.MODEL,
            "sampling": codex_runner.SAMPLING,
        },
        "codex": {
            "path": executable,
            "bytes": metadata.st_size,
            "sha256": codex_command_sha256,
        },
        "authentication": {
            "mode": "chatgpt_subscription",
            "credential_digest_public": False,
            "credential_bytes": len(auth_data),
            "commitment": _codex_credential_commitment(auth_data),
        },
    }


def authorize_pair(
    *,
    pair_id: str,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_out: Path | None,
    codex_command: str,
    codex_command_sha256: str,
    max_cost_usd: Decimal,
    validator_command: list[str],
) -> dict[str, Any]:
    if _ENTRYPOINT_BOOTSTRAP_IDENTITY is None:
        raise core.PreflightError(
            "Codex preflight authorization requires immutable source bootstrap"
        )
    core._register_startup_bootstrap_identity(_ENTRYPOINT_BOOTSTRAP_IDENTITY)
    # Before core creates a one-shot ledger, verify effective nested mounts.
    # Merely having a read-only /home parent is insufficient.
    baseline, treatment = core.load_pair(request_root, pair_id)
    source = core.runner.load_repository_root(baseline, repository_map)
    repobrief = treatment.get("repobrief")
    if not isinstance(repobrief, dict) or not isinstance(
        repobrief.get("manifest"), str
    ):
        raise core.PreflightError("live Codex treatment manifest is unavailable")
    # Resolve launcher aliases before the mount gate; the provider binding
    # is checked again afterwards and must name this same canonical target.
    try:
        resolved_codex = Path(codex_command).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise core.PreflightError("live Codex launcher resolution failed") from exc
    codex_runner.validate_live_immutable_mounts(
        source=source,
        codex=resolved_codex,
        request_root=request_root,
        repository_map=repository_map,
        manifest=Path(repobrief["manifest"]),
        state_root=state_root,
        transcript_root=transcript_root,
        evidence_root=evidence_root,
        report_root=None if report_out is None else report_out.parent,
    )
    provider_binding = _validated_codex_provider_binding(
        codex_command, codex_command_sha256
    )
    if provider_binding.get("codex", {}).get("path") != str(resolved_codex):
        raise core.PreflightError(
            "live Codex launcher identity changed after mount check"
        )
    return core.authorize_dispatch(
        pair_id=pair_id,
        request_root=request_root,
        repository_map=repository_map,
        state_root=state_root,
        transcript_root=transcript_root,
        evidence_root=evidence_root,
        report_out=report_out,
        provider_binding=provider_binding,
        max_cost_usd=max_cost_usd,
        validator_command=validator_command,
    )


def _require_external_provider_one_shot(*, pair_id: str) -> None:
    """Keep paired live dispatch closed until a trusted external verifier exists.

    Internal authorize_pair(), cost flags, credentials and root-systemd
    admission cannot confer separate single-use spending authorization.
    No canonical verifier is currently wired to this entrypoint.
    """
    raise core.PreflightError(
        "external one-shot provider authorization verifier is unavailable"
    )


def _paired_terminal_path(report_out: Path, *, failed: bool = False) -> Path:
    """Create-only durable pair result distinct from the authorization report."""
    return report_out.with_name(
        report_out.stem + (".pair-failed.json" if failed else ".pair-result.json")
    )


def _persist_pair_artifact(
    path: Path, value: dict[str, Any], *, digest: bool = False
) -> None:
    """Create an immutable private artifact without following untrusted paths.

    The provider can write to the epoch output mounts before it exits, so
    post-provider finalization must never use Path.resolve()/mkdir on a
    provider-supplied symlink. The verified parent dirfd pins the destination.
    """
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise core.PreflightError("paired artifact path is unsafe")
    raw = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if not raw or len(raw) > 8 * 1024 * 1024:
        raise core.PreflightError("paired artifact exceeds private output limit")
    parent, descriptor = codex_runner._open_private_directory(path.parent)
    try:
        codex_runner._directory_fd_matches(parent, descriptor)
        codex_runner._assert_absent(descriptor, path.name)
        if digest:
            codex_runner._assert_absent(descriptor, path.name + ".sha256")
        codex_runner._write_private_dirfd(descriptor, path.name, raw)
        if digest:
            checksum = (f"{hashlib.sha256(raw).hexdigest()}  {path.name}\n").encode(
                "ascii"
            )
            codex_runner._write_private_dirfd(
                descriptor, path.name + ".sha256", checksum
            )
        codex_runner._directory_fd_matches(parent, descriptor)
    finally:
        os.close(descriptor)


def _validated_condition_receipt(
    *,
    request: dict[str, Any],
    receipt: Any,
    request_root: Path,
    evidence_root: Path,
    transcript_root: Path,
    validator_command: list[str],
) -> dict[str, Any]:
    """Validate the exact live condition and its external cost-bearing evidence."""
    if (
        not isinstance(receipt, dict)
        or receipt.get("kind") != codex_runner.base.RECEIPT_KIND
        or receipt.get("status") != "success"
        or receipt.get("request_id") != request.get("request_id")
        or receipt.get("request_sha256") != core._sha256_json(request)
        or receipt.get("exit_code") != 0
        or receipt.get("error") is not None
    ):
        raise core.PreflightError("paired live receipt is missing or mismatched")
    core._tool_requirement(receipt, treatment=request.get("condition") == "treatment")
    filename = (
        hashlib.sha256(str(request["request_id"]).encode("utf-8")).hexdigest()
        + ".receipt.json"
    )
    path = evidence_root / "receipts" / filename
    _persist_pair_artifact(path, receipt)
    validated = core._validate_receipt_external(
        validator_command,
        request_path=core._request_path(request_root, request),
        receipt_path=path,
        transcript_root=transcript_root,
    )
    observed = core._observed_cost(receipt, transcript_root)
    if not observed.is_finite() or observed < 0:
        raise core.PreflightError("paired live cost is not verified")
    return {
        "receipt_sha256": core._sha256_json(receipt),
        "receipt_path": str(path),
        "validator_sha256": core._sha256_json(validated),
        "observed_cost_usd": format(observed, "f"),
    }


def _attest_completed_pair_ledger(
    *,
    baseline: dict[str, Any],
    ordered: list[dict[str, Any]],
    state_root: Path,
    results: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Read back the runner-owned, immutable five-event ledger without rewriting it."""
    loaded = codex_runner._load_preflight_dispatch_authorization(baseline, state_root)
    state = codex_runner._validated_dispatch_event_state(
        baseline, state_root, loaded["authorization"]
    )
    conditions = [str(request["condition"]) for request in ordered]
    if (
        len(conditions) != 2
        or set(conditions) != {"baseline", "treatment"}
        or state["condition_intents"] != conditions
        or state["condition_outcomes"]
        != {"baseline": "condition-completed", "treatment": "condition-completed"}
        or state["pending_condition"] is not None
        or state["terminal_failure"]
        or state["next_sequence"] != 5
    ):
        raise core.PreflightError("paired dispatch ledger is not fully terminal")
    events = Path(state["events_root"])
    for index, request in enumerate(ordered, start=1):
        condition = str(request["condition"])
        event = codex_runner.base._load_object_bytes(
            codex_runner._read_bound_regular_file(
                events / f"{2 * index:04d}-condition-completed.json",
                label="paired condition terminal event",
                max_bytes=codex_runner.MAX_DISPATCH_EVENT_BYTES,
            ),
            label="paired condition terminal event",
        )
        payload = event.get("payload")
        if (
            not isinstance(payload, dict)
            or payload.get("condition") != condition
            or payload.get("receipt_sha256") != results[condition]["receipt_sha256"]
        ):
            raise core.PreflightError("paired terminal ledger receipt binding mismatch")
    return {
        "root": str(state["pair_root"]),
        "event_count": state["next_sequence"],
        "final_event_sha256": state["previous_event_sha256"],
        "authorization_sha256": core._sha256_json(loaded["authorization"]),
        "retry_permitted": False,
    }


def execute_authorized_pair(
    *,
    pair_id: str,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_out: Path,
    codex_command: str,
    codex_command_sha256: str,
    max_cost_usd: Decimal,
    validator_command: list[str],
) -> dict[str, Any]:
    """Run the two exact conditions within one trusted root-systemd main PID.

    A distinct external one-shot verifier is required before any internal
    authorization or provider intent. The current installation deliberately
    has no such verifier, so the live path stops closed at that boundary.
    """
    if _ENTRYPOINT_BOOTSTRAP_IDENTITY is None:
        raise core.PreflightError(
            "paired dispatch requires immutable preflight bootstrap"
        )
    _require_external_provider_one_shot(pair_id=pair_id)

    authorization: dict[str, Any] | None = None
    requests: dict[str, str] = {}
    results: dict[str, dict[str, Any]] = {}
    try:
        baseline, treatment = core.load_pair(request_root, pair_id)
        authorization = authorize_pair(
            pair_id=pair_id,
            request_root=request_root,
            repository_map=repository_map,
            state_root=state_root,
            transcript_root=transcript_root,
            evidence_root=evidence_root,
            report_out=report_out,
            codex_command=codex_command,
            codex_command_sha256=codex_command_sha256,
            max_cost_usd=max_cost_usd,
            validator_command=validator_command,
        )
        requests = {
            "baseline": core._sha256_json(baseline),
            "treatment": core._sha256_json(treatment),
        }
        if (
            not isinstance(authorization, dict)
            or authorization.get("status") != "authorized"
            or authorization.get("pair_id") != pair_id
            or authorization.get("request_sha256") != requests
        ):
            raise core.PreflightError("paired dispatch authorization identity mismatch")
        arguments = argparse.Namespace(
            request_root=request_root,
            repository_map=repository_map,
            state_root=state_root,
            transcript_root=transcript_root,
            provider_evidence_root=evidence_root,
            codex_command=codex_command,
            codex_command_sha256=codex_command_sha256,
            allow_live_provider=True,
            stream_fixture=None,
            stderr_fixture=None,
            fixture_returncode=0,
        )
        ordered = sorted(
            (baseline, treatment), key=lambda request: int(request["order"])
        )
        for request in ordered:
            condition = str(request["condition"])
            receipt = codex_runner.execute(request, arguments)
            results[condition] = _validated_condition_receipt(
                request=request,
                receipt=receipt,
                request_root=request_root,
                evidence_root=evidence_root,
                transcript_root=transcript_root,
                validator_command=validator_command,
            )
            # There must be no second provider intent if the first receipt,
            # external validator, or cost report is incomplete.
        if set(results) != {"baseline", "treatment"}:
            raise core.PreflightError("paired dispatch is incomplete")
        observed = sum(
            (Decimal(result["observed_cost_usd"]) for result in results.values()),
            Decimal("0"),
        )
        authorized_total = max_cost_usd * 2
        if not observed.is_finite() or observed > authorized_total:
            raise core.PreflightError("paired provider cost exceeds authorized budget")
        ledger = _attest_completed_pair_ledger(
            baseline=baseline,
            ordered=ordered,
            state_root=state_root,
            results=results,
        )
        # Runner and ledger readbacks must agree before any final success claim.
        source_before = authorization.get("source_after")
        if not isinstance(source_before, dict):
            raise core.PreflightError("paired source baseline evidence is missing")
        source_after = core.source_state(
            core.runner.load_repository_root(baseline, repository_map)
        )
        core._assert_source_unchanged(source_before, source_after)
        report = {
            "kind": "repobrief.codex_same_unit_pair_result",
            "status": "valid",
            "pair_id": pair_id,
            "request_sha256": requests,
            "runs": results,
            "cost": {
                "total_observed_usd": format(observed, "f"),
                "total_authorized_usd": format(authorized_total, "f"),
            },
            "dispatch_ledger": ledger,
            "source_after_sha256": core._sha256_json(source_after),
            "retry_permitted": False,
            "default_promoted": False,
        }
        _persist_pair_artifact(_paired_terminal_path(report_out), report, digest=True)
        return report
    except BaseException as exc:
        # A prior authorized pair can have consumed zero, one or two intents.
        # Preserve a separate create-only failure artifact, never retry or
        # misreport a successful individual runner event as complete pair QC.
        if authorization is not None:
            failure = {
                "kind": "repobrief.codex_same_unit_pair_result",
                "status": "failed",
                "pair_id": pair_id,
                "request_sha256": requests,
                "verified_receipts": results,
                "failure": core._error_evidence(exc),
                "retry_permitted": False,
                "default_promoted": False,
            }
            try:
                _persist_pair_artifact(
                    _paired_terminal_path(report_out, failed=True),
                    failure,
                    digest=True,
                )
            except BaseException as persistence_error:
                raise core.PreflightError(
                    "paired failure could not be terminalized durably"
                ) from persistence_error
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorize one exact RepoBrief Codex benchmark pair.",
        allow_abbrev=False,
    )
    parser.add_argument("--pair-id", required=True)
    parser.add_argument("--request-root", required=True, type=Path)
    parser.add_argument("--repository-map", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--transcript-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--report-out", required=True, type=Path)
    parser.add_argument("--validator-command", required=True, type=Path)
    parser.add_argument("--codex-command", required=True)
    parser.add_argument("--codex-command-sha256", required=True)
    parser.add_argument("--max-cost-usd", required=True)
    parser.add_argument("--execute-pair", action="store_true")
    parser.add_argument("--allow-live-provider", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        try:
            max_cost = Decimal(args.max_cost_usd)
        except InvalidOperation as exc:
            raise core.PreflightError("max cost is not a decimal") from exc
        if args.execute_pair != args.allow_live_provider:
            raise core.PreflightError(
                "paired execution requires an explicit provider opt-in"
            )
        dispatch = execute_authorized_pair if args.execute_pair else authorize_pair
        report = dispatch(
            pair_id=args.pair_id,
            request_root=args.request_root,
            repository_map=args.repository_map,
            state_root=args.state_root,
            transcript_root=args.transcript_root,
            evidence_root=args.evidence_root,
            report_out=args.report_out,
            codex_command=args.codex_command,
            codex_command_sha256=args.codex_command_sha256,
            max_cost_usd=max_cost,
            validator_command=core._command_array(args.validator_command),
        )
    except (core.PreflightError, codex_runner.RunnerError) as exc:
        print(
            json.dumps({"status": "error", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
