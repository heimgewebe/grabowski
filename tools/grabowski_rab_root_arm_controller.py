#!/usr/bin/python3
"""Fail-closed root launcher for one frozen RAB position, not a socket grant.

This entrypoint is inert in developer checkouts. A dedicated, disabled-by-default
rootbroker action must point to an independently installed, root-owned copy.
Only PID 1 starts the Codex arm; no unprivileged JSON grant can start it.

The separate arm runner, credential/tool sandbox and root installation are NOT
included in this patch. Without those verified installed files no provider
process can start. Never substitute a direct Codex invocation.
"""

from __future__ import annotations

from datetime import datetime
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import time
from typing import Any

_INSTALLED_SELF = Path("/usr/local/libexec/grabowski-rab-root-arm-controller")
_INSTALLED_CORE = Path("/usr/local/lib/grabowski/grabowski_rab_provider_one_shot.py")
_INSTALLED_RUNNER = Path("/usr/local/libexec/grabowski-rab-arm-exec")
_INSTALLED_CODEX = Path("/usr/local/libexec/grabowski-rab-codex")
_INSTALLED_MCP = Path("/usr/local/libexec/grabowski-rab-mcp")
_POLICY_ROOT = Path("/etc/grabowski/rab-arm")
_CREDENTIAL_ROOT = _POLICY_ROOT / "credentials"
_REQUEST_ROOT = _POLICY_ROOT / "requests"
_STATE_ROOT = Path("/var/lib/grabowski/rab-arm")
_INPUT_ROOT = _STATE_ROOT / "input-projections"
_FROZEN_INPUT_EPOCH = Path(".local/state/grabowski/rab-six-case-epoch-20261010-b3e93e2f7f")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TARGET = re.compile(r"([0-9a-f]{64}):([01])\Z")
_MAX_POLICY_BYTES = 16384
_MAX_ARM_SECONDS = 300
_FROZEN_PLAN_SHA256 = "2795584ac0c100cdceb6ed2c7eb42b883de2099b2a3d33ac51dbe9987655f10c"
_INPUT_PROJECTION = _INPUT_ROOT / ("plan-" + _FROZEN_PLAN_SHA256)
# The official Codex CLI 0.163.0 is 296865480 bytes on the target host.
# Hash from a fixed fd in chunks; never load that executable into RAM.
_MAX_INSTALLED_BYTES = 512 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
# Pop!_OS uses /usr/bin; the installed NixOS system exposes the same
# root-managed systemd executables through its immutable system profile.
_SYSTEMD_RUN = (
    "/usr/bin/systemd-run"
    if Path("/usr/bin/systemd-run").is_file()
    else "/run/current-system/sw/bin/systemd-run"
)
_SYSTEMCTL = (
    "/usr/bin/systemctl"
    if Path("/usr/bin/systemctl").is_file()
    else "/run/current-system/sw/bin/systemctl"
)
# Frozen NixOS input is a daemon-installed, root-owned, read-only Nix store
# projection, rather than a mutable owner-home or ad hoc /var/lib copy.
if _SYSTEMD_RUN == "/run/current-system/sw/bin/systemd-run":
    _INPUT_PROJECTION = Path(
        "/nix/store/d94g4fnrar2n1xwmp5dy4q9j6zfjw6cr-rab-original-inputs-plan-2795584ac0c1"
    )
_VERSION = 2


class ArmDenied(RuntimeError):
    """Start denied. Ambiguous attempts are never automatically replayed."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _request_sha(value: Any) -> str:
    # Frozen RepoBrief requests use UTF-8, not the root-policy's ASCII JSON.
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha(raw)


def _hex(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _pair_policy(value: Any) -> dict[str, Any]:
    """One pair, two different PID 1 units, no shared MainPID/InvocationID."""
    required = {
        "schema_version",
        "kind",
        "epoch_sha256",
        "plan_sha256",
        "pair_id",
        "provider",
        "mode",
        "model",
        "reasoning",
        "max_exec_per_arm",
        "max_wall_seconds",
        "installed_sha256",
        "positions",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ArmDenied("root pair policy has unknown or missing keys")
    if type(value["schema_version"]) is not int or value["schema_version"] != _VERSION:
        raise ArmDenied("root pair schema is invalid")
    if value["kind"] != "rab.root_controlled_separate_arms":
        raise ArmDenied("root pair kind is invalid")
    if (
        not all(_hex(value[k]) for k in ("epoch_sha256", "plan_sha256"))
        or value["plan_sha256"] != _FROZEN_PLAN_SHA256
    ):
        raise ArmDenied("root pair plan identity is invalid")
    try:
        pair = value["pair_id"].encode("utf-8", "strict")
    except (AttributeError, UnicodeError) as exc:
        raise ArmDenied("root pair id must be UTF-8") from exc
    if not 0 < len(pair) <= 256 or any(ord(ch) < 32 for ch in value["pair_id"]):
        raise ArmDenied("root pair id is not bounded")
    if (
        value["provider"] != "openai-codex-cli"
        or value["mode"] != "chatgpt_subscription"
        or value["model"] != "gpt-6-astra"
        or value["reasoning"] != "medium"
        or type(value["max_exec_per_arm"]) is not int
        or value["max_exec_per_arm"] != 1
        or type(value["max_wall_seconds"]) is not int
        or value["max_wall_seconds"] != _MAX_ARM_SECONDS
    ):
        raise ArmDenied("root pair provider or execution budget is invalid")
    installed = value["installed_sha256"]
    if (
        not isinstance(installed, dict)
        or set(installed) != {"controller", "core", "runner", "codex", "mcp"}
        or not all(_hex(sha) for sha in installed.values())
    ):
        raise ArmDenied("root installed byte manifest is incomplete")
    positions = value["positions"]
    if not isinstance(positions, list) or len(positions) != 2:
        raise ArmDenied("root pair needs exactly two positions")
    seen: set[str] = set()
    for idx, position in enumerate(positions):
        if (
            not isinstance(position, dict)
            or set(position) != {"index", "arm", "slot_id", "request_sha256"}
            or type(position["index"]) is not int
            or position["index"] != idx
            or position["arm"] not in {"baseline", "treatment"}
            or position["arm"] in seen
            or not _hex(position["slot_id"])
            or not _hex(position["request_sha256"])
        ):
            raise ArmDenied("root position identity or ordering is invalid")
        seen.add(position["arm"])
    if (
        seen != {"baseline", "treatment"}
        or positions[0]["slot_id"] == positions[1]["slot_id"]
        or positions[0]["request_sha256"] == positions[1]["request_sha256"]
    ):
        raise ArmDenied("root pair arms or slots are not unique")
    return value


def _token(policy: dict[str, Any], index: int) -> str:
    if type(index) is not int or index not in (0, 1):
        raise ArmDenied("root position index is invalid")
    # Exclude mutable installed/launcher fields: a policy revision cannot
    # turn an ambiguous already-consumed request into another usable slot.
    return _sha(
        _canonical(
            {
                "epoch_sha256": policy["epoch_sha256"],
                "pair_id": policy["pair_id"],
                "slot_id": policy["positions"][index]["slot_id"],
            }
        )
    )


def _unit(policy: dict[str, Any], index: int) -> str:
    # Derived only from frozen identities, never supplied by the caller.
    return "grabowski-rab-" + _token(policy, index)[:16] + ".service"


def _pair_state_directory(policy: dict[str, Any]) -> str:
    """One private systemd StateDirectory for both PID1 units of one pair.

    Each arm has its own unit, invocation and spent marker. Their existing
    preflight ledger and provider evidence must nonetheless survive arm 1.
    The independent two-unit DynamicUser host probe verified this state
    mechanism; it does not authorize any provider start.
    """
    identity = {
        "epoch_sha256": policy["epoch_sha256"],
        "pair_id": policy["pair_id"],
    }
    return "grabowski-rab-pair-" + _sha(_canonical(identity))[:16]


def _attest_provider_reply(
    policy: dict[str, Any],
    index: int,
    request: dict[str, Any],
    observation: dict[str, Any],
    transcript: bytes,
    receipt_function: Any,
) -> dict[str, str]:
    """Recompute the Codex success receipt from actual JSONL in the ROOT issuer.

    A trusted installed parser is loaded independently of the per-arm process.
    Neither its returned evidence hashes nor this pure helper grant a start.
    """
    _pair_policy(policy)
    if type(index) is not int or index not in (0, 1):
        raise ArmDenied("root provider result index is invalid")
    position = policy["positions"][index]
    request_sha = _request_sha(request)
    request_id = request.get("request_id")
    expected_keys = {
        "schema_version", "kind", "unit", "pair_id", "slot_id",
        "arm", "request_sha256", "runner_receipt_sha256",
        "runner_receipt_bytes", "runner_receipt", "provider_outcome_status",
    }
    if (
        not isinstance(request_id, str)
        or not request_id
        or not isinstance(observation, dict)
        or set(observation) != expected_keys
        or type(observation["schema_version"]) is not int
        or observation["schema_version"] != 1
        or observation["kind"] != "rab.unverified_single_arm_runner_observation"
        or observation["unit"] != _unit(policy, index)
        or observation["pair_id"] != policy["pair_id"]
        or observation["slot_id"] != position["slot_id"]
        or observation["arm"] != position["arm"]
        or observation["request_sha256"] != position["request_sha256"]
        or request_sha != position["request_sha256"]
        or request.get("pair_id") != policy["pair_id"]
        or request.get("condition") != position["arm"]
        or observation["provider_outcome_status"] != "unverified"
        or not _hex(observation["runner_receipt_sha256"])
        or type(observation["runner_receipt_bytes"]) is not int
        or not 0 < observation["runner_receipt_bytes"] <= 1_048_576
        or not isinstance(observation["runner_receipt"], dict)
        or not isinstance(transcript, bytes)
        or not 0 < len(transcript) <= 16 * 1024 * 1024
        or not callable(receipt_function)
    ):
        raise ArmDenied("root provider receipt observation is not qualified")
    result = observation["runner_receipt"]
    artifact = hashlib.sha256(request_id.encode("utf-8", "strict")).hexdigest() + ".jsonl"
    descriptor = result.get("transcript")
    if (
        result.get("status") != "success"
        or result.get("request_id") != request_id
        or result.get("request_sha256") != request_sha
        or result.get("exit_code") != 0
        or result.get("error") is not None
        or not isinstance(descriptor, dict)
        or descriptor.get("artifact") != artifact
        or descriptor.get("storage") != "artifact"
        or descriptor.get("inline") is not None
        or descriptor.get("sha256") != _sha(transcript)
        or descriptor.get("bytes") != len(transcript)
    ):
        raise ArmDenied("root provider transcript reference does not match")
    try:
        captured = (
            json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False)
            + "\n"
        ).encode("utf-8", "strict")
        if (
            len(captured) != observation["runner_receipt_bytes"]
            or _sha(_canonical(result)) != observation["runner_receipt_sha256"]
        ):
            raise ArmDenied("root normalized result bytes or digest mismatch")
        started = datetime.fromisoformat(result["started_at"].replace("Z", "+00:00"))
        ended = datetime.fromisoformat(result["ended_at"].replace("Z", "+00:00"))
        if started.tzinfo is None or ended.tzinfo is None or ended < started:
            raise ArmDenied("root provider timestamps are not qualified")
        recomputed = receipt_function(request, transcript, artifact, 0, started, ended)
        if _canonical(recomputed) != _canonical(result):
            raise ArmDenied("root replay of actual Codex JSONL disagrees with runner")
    except (ArmDenied, OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError) as exc:
        raise ArmDenied("root provider result cannot be independently validated") from exc
    except Exception as exc:
        raise ArmDenied("independent root provider normalization refused the transcript") from exc
    return {
        "provider_receipt_sha256": observation["runner_receipt_sha256"],
        "transcript_sha256": _sha(transcript),
    }


def _attest_provider_stderr(
    request: dict[str, Any],
    transcript: bytes,
    raw_stderr: bytes,
    diagnostics_bytes: bytes,
    policy_bytes: bytes,
    classifier: Any,
) -> dict[str, str]:
    """Root checks actual stderr, stored capture and Codex policy independently.

    A normalized success receipt by itself cannot prove that the provider's
    error stream, capture limits and persistence also passed qualification.
    This shares the pinned runner's classifier, not its success assertion.
    """
    request_id = request.get("request_id") if isinstance(request, dict) else None
    if (
        not isinstance(request_id, str)
        or not request_id
        or not isinstance(transcript, bytes)
        or not 0 < len(transcript) <= 16 * 1024 * 1024
        or not isinstance(raw_stderr, bytes)
        or len(raw_stderr) > 256 * 1024
        or not callable(classifier)
    ):
        raise ArmDenied("root stderr proof inputs are invalid")
    try:
        diagnostic = _bounded_policy_json(diagnostics_bytes, max_bytes=1_048_576)
        policy = _bounded_policy_json(policy_bytes, max_bytes=1_048_576)
        stem = hashlib.sha256(request_id.encode("utf-8", "strict")).hexdigest()
        request_sha = _request_sha(request)
        stdout = {
            "artifact": stem + ".jsonl",
            "sha256": _sha(transcript),
            "bytes": len(transcript),
            "overflow": False,
        }
        stderr = {
            "artifact": stem + ".stderr",
            "sha256": _sha(raw_stderr),
            "bytes": len(raw_stderr),
            "overflow": False,
        }
        interpreted = classifier(raw_stderr)
        if not isinstance(interpreted, dict) or interpreted.get("allowed") is not True:
            raise ArmDenied("Codex stderr classification denied")
        expected = {"artifact": stem + ".stderr", **interpreted, "overflow": False}
        for value, kind in (
            (diagnostic, "repobrief.codex_provider_capture"),
            (policy, "repobrief.codex_stderr_policy"),
        ):
            if (
                value.get("kind") != kind
                or value.get("request_id") != request_id
                or value.get("request_sha256") != request_sha
                or value.get("provider") != "openai-codex-cli"
                or value.get("model") != "gpt-6-astra"
                or value.get("synthetic_fixture") is not False
                or type(value.get("returncode")) is not int
                or value["returncode"] != 0
                or value.get("capture_error") is not None
                or value.get("started_at") != diagnostic.get("started_at")
                or value.get("ended_at") != diagnostic.get("ended_at")
                or value.get("stdout") != stdout
            ):
                raise ArmDenied("root provider capture or policy identity invalid")
        if (
            diagnostic.get("stderr") != stderr
            or diagnostic.get("semantic_interpretation") != "not_performed"
            or policy.get("capture_diagnostics_sha256") != _sha(diagnostics_bytes)
            or policy.get("stderr") != expected
            or policy.get("version") != diagnostic.get("version")
            or policy.get("version") != "1.0"
        ):
            raise ArmDenied("root stderr policy does not match raw diagnostics")
    except ArmDenied:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise ArmDenied("root stderr could not be independently qualified") from exc
    except Exception as exc:
        raise ArmDenied("root Codex stderr classifier rejected the capture") from exc
    return {"stderr_policy_sha256": _sha(policy_bytes)}


def _write_once(fd: int, filename: str, value: dict[str, Any]) -> None:
    if "/" in filename or filename in {"", ".", ".."}:
        raise ArmDenied("root receipt filename is unsafe")
    raw = _canonical(value) + b"\n"
    if len(raw) > _MAX_POLICY_BYTES:
        raise ArmDenied("root receipt exceeds byte budget")
    try:
        handle = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=fd,
        )
    except FileExistsError as exc:
        raise ArmDenied("root slot already consumed or outcome unknown") from exc
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(handle, remaining)
            if written <= 0:
                raise ArmDenied("root receipt write did not progress")
            remaining = remaining[written:]
        os.fsync(handle)
    finally:
        os.close(handle)
    os.fsync(fd)


def _first_receipt(policy: dict[str, Any], fd: int, core: Any) -> dict[str, Any]:
    first = policy["positions"][0]
    token = _token(policy, 0)
    intent = core._read_root_file(fd, "spent-" + token + ".json")
    expected_intent = {
        "schema_version": _VERSION,
        "kind": "rab.root_arm_start_consumed",
        "policy_sha256": _sha(_canonical(policy)),
        "token_sha256": token,
        "index": 0,
        "arm": first["arm"],
        "slot_id": first["slot_id"],
        "request_sha256": first["request_sha256"],
        "unit": _unit(policy, 0),
    }
    if intent != expected_intent:
        raise ArmDenied("first root intent is not the expected pair")
    try:
        receipt = core._read_root_file(fd, "completed-" + token + ".json")
    except OSError as exc:
        raise ArmDenied("first arm root lifecycle receipt is missing") from exc
    if (
        not isinstance(receipt, dict)
        or set(receipt)
        != {
            "schema_version",
            "kind",
            "policy_sha256",
            "token_sha256",
            "unit",
            "invocation_id",
            "result",
            "main_pid",
            "cgroup_empty",
            "provider_outcome_status",
            "provider_receipt_sha256",
            "transcript_sha256",
            "stderr_policy_sha256",
        }
        or type(receipt.get("schema_version")) is not int
        or receipt["schema_version"] != _VERSION
        or receipt["kind"] != "rab.root_arm_lifecycle_observation"
        or receipt["policy_sha256"] != expected_intent["policy_sha256"]
        or receipt["token_sha256"] != token
        or receipt["unit"] != expected_intent["unit"]
        or not isinstance(receipt["invocation_id"], str)
        or re.fullmatch("[0-9a-f]{32}", receipt["invocation_id"]) is None
        or receipt["result"] != "success"
        or type(receipt["main_pid"]) is not int
        or receipt["main_pid"] != 0
        or receipt["cgroup_empty"] is not True
        # A root-owned lifecycle receipt alone proves neither a real provider
        # response nor usable provider results. The separate outcome issuer
        # does not exist yet: unverified must NEVER enable arm 2.
        or receipt["provider_outcome_status"] != "verified_by_root_issuer"
        or not _hex(receipt["provider_receipt_sha256"])
        or not _hex(receipt["transcript_sha256"])
        or not _hex(receipt["stderr_policy_sha256"])
    ):
        raise ArmDenied("first root lifecycle receipt is absent or unqualified")
    # The independently issued success proof does not itself authorize
    # the second model start. Root must deliberately release that exact
    # second slot, bound to the final first receipt's immutable digest.
    next_slot = policy["positions"][1]["slot_id"]
    try:
        release = core._read_root_file(fd, "release-" + next_slot + ".json")
    except OSError as exc:
        raise ArmDenied("second arm lacks independent root release") from exc
    expected_release = {
        "schema_version": _VERSION,
        "kind": "rab.root_arm_second_release",
        "policy_sha256": expected_intent["policy_sha256"],
        "pair_id": policy["pair_id"],
        "slot_id": next_slot,
        "first_token_sha256": token,
        "first_receipt_sha256": _sha(_canonical(receipt)),
    }
    if release != expected_release or type(release.get("schema_version")) is not int:
        raise ArmDenied("second arm root release is not bound to first outcome")
    return receipt


def _consume_position(policy: dict[str, Any], index: int, fd: int, core: Any) -> str:
    """Durably consume BEFORE any systemd/credential start; never auto-retry."""
    _pair_policy(policy)
    if index == 1:
        # Unlike the old socket, second arm has a DIFFERENT unit and PID.
        # Only root's post-exit lifecycle attestation connects the two.
        _first_receipt(policy, fd, core)
    position = policy["positions"][index]
    token = _token(policy, index)
    _write_once(
        fd,
        "spent-" + token + ".json",
        {
            "schema_version": _VERSION,
            "kind": "rab.root_arm_start_consumed",
            "policy_sha256": _sha(_canonical(policy)),
            "token_sha256": token,
            "index": index,
            "arm": position["arm"],
            "slot_id": position["slot_id"],
            "request_sha256": position["request_sha256"],
            "unit": _unit(policy, index),
        },
    )
    return token


def _unit_argv(policy: dict[str, Any], index: int) -> list[str]:
    """Strict root-authored systemd-249 command, no caller argv or shell."""
    _pair_policy(policy)
    pos = policy["positions"][index]
    unit = _unit(policy, index)
    pair_state = _pair_state_directory(policy)
    home = "/var/lib/" + pair_state
    input_projection = _INPUT_PROJECTION
    output_names = ("state", "transcripts", "evidence", "reports")
    outputs = tuple(home + "/epoch/" + name for name in output_names)
    unit_prefix = unit.removesuffix(".service")
    scratch_tmp, scratch_var = unit_prefix + "-tmp", unit_prefix + "-var"
    credential = _CREDENTIAL_ROOT / ("epoch-" + policy["epoch_sha256"] + ".auth")
    pair_file = _POLICY_ROOT / ("epoch-" + policy["epoch_sha256"] + ".json")
    request_file = _REQUEST_ROOT / ("slot-" + pos["slot_id"] + ".json")
    runtime_file = _POLICY_ROOT / ("epoch-" + policy["epoch_sha256"] + ".runtime.json")
    properties = [
        "Type=exec",
        "NotifyAccess=none",
        "RemainAfterExit=yes",
        "PIDFile=",
        "DynamicUser=yes",
        "PrivateTmp=yes",
        "PrivateIPC=yes",
        "PrivateDevices=yes",
        "DevicePolicy=closed",
        "Delegate=no",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        # Reuse the host-qualified nine-writable-mount systemd geometry:
        # four private epoch outputs, two independent /run scratch mounts,
        # and isolated pseudo-device filesystems. Mask physical state aliases.
        f"RuntimeDirectory={scratch_tmp} {scratch_var}",
        "RuntimeDirectoryMode=0700",
        f"BindPaths=/run/{scratch_tmp}:/tmp /run/{scratch_var}:/var/tmp "
        f"/var/lib/private/{pair_state}:{home}",
        # PID1 binds only the root-controlled curated home projection. The
        # original /home/alex (mode 0700) is never traversed by DynamicUser.
        f"BindReadOnlyPaths={input_projection}:/home/alex",
        # Linux user namespaces require writing the nested uid_map under
        # /proc. NixOS systemd ReadOnlyPaths=/proc returns EROFS *before*
        # the trusted bwrap can create its private, sandboxed proc mount.
        # The real PID1 zero-capability test passed with /run and /sys RO.
        # Preserve the original stronger Pop!_OS unit profile unchanged.
        f"ReadOnlyPaths=/run /run/{scratch_tmp} /run/{scratch_var} "
        f"{home} {home}/repos "
        + ("/sys" if _SYSTEMD_RUN.startswith("/run/current-system/sw/bin/")
           else "/proc /sys"),
        "InaccessiblePaths=-/run/user -/run/docker -/mnt/backup "
        "-/dev/hugepages /var/lib/private "
        f"-{_INPUT_ROOT}",
        f"ReadWritePaths={' '.join(outputs)}",
        "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777",
        "ProtectControlGroups=yes",
        # On NixOS, ProtectKernelTunables/Logs=yes mounts locked-down
        # procfs overlays. Real PID1 probes show these prevent the already
        # required nested bwrap from mounting its own PID-namespace procfs.
        # Keep DynamicUser, NoNewPrivileges, empty capabilities, private
        # devices, strict readonly host filesystem and nested seccomp.
        # Pop!_OS retains both original kernel protection properties.
        ("ProtectKernelTunables=no" if _SYSTEMD_RUN.startswith("/run/current-system/sw/bin/")
         else "ProtectKernelTunables=yes"),
        "ProtectKernelModules=yes",
        ("ProtectKernelLogs=no" if _SYSTEMD_RUN.startswith("/run/current-system/sw/bin/")
         else "ProtectKernelLogs=yes"),
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "UMask=0077",
        # Neither the calling root terminal nor sensitive model stderr/stdout
        # may be forwarded to a public journal/TTY.
        "StandardInput=null",
        "StandardOutput=null",
        "StandardError=null",
        # The 300-second model wall clock is enforced by the provider runner;
        # PID 1 also needs a bounded 120s envelope for preparation and closeout.
        f"RuntimeMaxSec={policy['max_wall_seconds'] + 120}",
        "MemoryMax=512M",
        "TasksMax=128",
        f"StateDirectory={' '.join(f'{pair_state}/epoch/{name}' for name in output_names)} "
        f"{pair_state}/repos",
        "StateDirectoryMode=0700",
        f"Environment=HOME={home}",
        # PID1 loads only root-installed fixed inputs. The dynamic-user child
        # cannot choose another policy, request, executable or model.
        f"LoadCredential=auth.json:{credential}",
        f"LoadCredential=pair.json:{pair_file}",
        f"LoadCredential=request.json:{request_file}",
        f"LoadCredential=runtime.json:{runtime_file}",
    ]
    return [
        _SYSTEMD_RUN,
        "--system",
        "--no-block",
        "--unit=" + unit,
        *(f"--property={p}" for p in properties),
        "--",
        str(_INSTALLED_RUNNER),
        "--epoch-sha256",
        policy["epoch_sha256"],
        "--pair-id",
        policy["pair_id"],
        "--slot-id",
        pos["slot_id"],
        "--arm",
        pos["arm"],
    ]


def _digest_verified_fd(descriptor: int, size: int) -> str:
    """Hash a fixed regular-file fd in bounded chunks, failing on short reads."""
    if type(size) is not int or not 0 < size <= _MAX_INSTALLED_BYTES:
        raise ArmDenied("installed program size is invalid")
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        part = os.read(descriptor, min(_HASH_CHUNK_BYTES, remaining))
        if not part:
            raise ArmDenied("installed program ended during hash verification")
        digest.update(part)
        remaining -= len(part)
    return digest.hexdigest()


def _verify_root_owned_file(path: Path, expected_sha256: str) -> None:
    """Pin installed executable bytes through root-only, non-symlink handles."""
    if not _hex(expected_sha256) or not path.is_absolute():
        raise ArmDenied("installed code digest or path is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", flags)
    try:
        for index, part in enumerate(path.parts[1:-1]):
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            # NixOS uses mode 1775 on /nix/store (nixbld group). Only
            # this exact root-owned directory may have writable mode bits,
            # and only while the kernel mount is actually read-only.
            immutable_store_parent = (
                index == 1
                and path.parts[:3] == ("/", "nix", "store")
                and bool(
                    os.statvfs("/nix/store").f_flag
                    & getattr(os, "ST_RDONLY", 1)
                )
            )
            if info.st_uid != 0 or (
                info.st_mode & 0o022 and not immutable_store_parent
            ):
                raise ArmDenied("installed program parent is mutable")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent,
        )
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != 0
                or before.st_nlink != 1
                or before.st_mode & 0o022
                or not 0 < before.st_size <= _MAX_INSTALLED_BYTES
            ):
                raise ArmDenied("installed program has unsafe ownership")
            actual_sha256 = _digest_verified_fd(descriptor, before.st_size)
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or actual_sha256 != expected_sha256
            ):
                raise ArmDenied("installed program bytes changed or digest mismatched")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ArmDenied("installed program unavailable") from exc
    finally:
        os.close(parent)


def _require_input_projection(policy: dict[str, Any]) -> None:
    """Require the original frozen plan in a root-owned readable home projection.

    Pre-spend guard: PID1 may bind only immutable root-controlled bytes, never
    the owner-private original home or a writable alias of the input tree.
    """
    root = _INPUT_PROJECTION
    try:
        info = root.lstat()
    except OSError as exc:
        raise ArmDenied("root input projection is not installed") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or (info.st_mode & 0o005) != 0o005
    ):
        raise ArmDenied("root input projection is not immutable and readable")
    _verify_root_owned_file(
        root / _FROZEN_INPUT_EPOCH / "plan.json", _FROZEN_PLAN_SHA256
    )


def _bounded_policy_json(
    raw: bytes, *, max_bytes: int = _MAX_POLICY_BYTES
) -> dict[str, Any]:
    """Bound C/Python JSON decoder depth before parsing policies or arm outputs."""
    if (
        not isinstance(raw, bytes)
        or type(max_bytes) is not int
        or not 0 < max_bytes <= 1_048_576
        or not 0 < len(raw) <= max_bytes
    ):
        raise ArmDenied("root policy JSON byte budget invalid")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise ArmDenied("root policy JSON is not UTF-8") from exc
    depth = 0
    quoted = False
    escaped = False
    for ch in text:
        if quoted:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch in "[{":
            depth += 1
            if depth > 32:
                raise ArmDenied("root policy JSON nesting budget exceeded")
        elif ch in "]}":
            depth -= 1
            if depth < 0:
                raise ArmDenied("root policy JSON has unbalanced brackets")
    if depth != 0 or quoted:
        raise ArmDenied("root policy JSON is incomplete")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, val in pairs:
            if key in obj:
                raise ArmDenied("root policy has duplicate JSON keys")
            obj[key] = val
        return obj

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ArmDenied("root policy JSON has non-finite numbers")
        return number

    def reject_constant(_: str) -> Any:
        raise ArmDenied("root policy JSON has non-finite numbers")

    try:
        return json.loads(
            text,
            object_pairs_hook=no_duplicates,
            parse_float=finite_float,
            parse_constant=reject_constant,
        )
    except (ValueError, OverflowError, RecursionError) as exc:
        raise ArmDenied("root policy JSON cannot be decoded") from exc


def _read_policy_bootstrap(epoch: str) -> dict[str, Any]:
    """Bootstrap only root-owned JSON; importing the core happens after hash check."""
    folder = _POLICY_ROOT
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in folder.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ArmDenied("root policy parent is mutable")
        filename = "epoch-" + epoch + ".json"
        file_fd = os.open(
            filename,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=fd,
        )
        try:
            first = os.fstat(file_fd)
            if (
                not stat.S_ISREG(first.st_mode)
                or first.st_uid != 0
                or first.st_nlink != 1
                or first.st_mode & 0o022
                or not 0 < first.st_size <= _MAX_POLICY_BYTES
            ):
                raise ArmDenied("root policy is not immutable")
            raw = os.read(file_fd, _MAX_POLICY_BYTES + 1)
            end = os.fstat(file_fd)
            if len(raw) != first.st_size or first.st_mtime_ns != end.st_mtime_ns:
                raise ArmDenied("root policy changed during admission")
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise ArmDenied("root policy cannot be read") from exc
    finally:
        os.close(fd)

    result = _pair_policy(_bounded_policy_json(raw))
    if result["epoch_sha256"] != epoch:
        raise ArmDenied("root policy filename and epoch mismatch")
    return result


def _verified_core(policy: dict[str, Any]) -> Any:
    files = {
        "controller": _INSTALLED_SELF,
        "core": _INSTALLED_CORE,
        "runner": _INSTALLED_RUNNER,
        "codex": _INSTALLED_CODEX,
        "mcp": _INSTALLED_MCP,
    }
    if Path(__file__).absolute() != _INSTALLED_SELF:
        raise ArmDenied("controller is not the installed root program")
    for key, path in files.items():
        _verify_root_owned_file(path, policy["installed_sha256"][key])
    spec = importlib.util.spec_from_file_location(
        "rab_installed_root_core", _INSTALLED_CORE
    )
    if spec is None or spec.loader is None:
        raise ArmDenied("verified root core cannot be imported")
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    return core


def _qualified_credential(policy: dict[str, Any]) -> None:
    """Only check ownership before CAS; PID 1 loads the secret after CAS."""
    path = _CREDENTIAL_ROOT / ("epoch-" + policy["epoch_sha256"] + ".auth")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            nxt = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            os.close(parent)
            parent = nxt
            info = os.fstat(parent)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ArmDenied("root credential parent is mutable")
        fd = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_nlink != 1
                or info.st_mode & 0o077
                or not 0 < info.st_size <= 1_048_576
            ):
                raise ArmDenied("root credential is missing or not private")
        finally:
            os.close(fd)
    except OSError as exc:
        raise ArmDenied("root credential unavailable") from exc
    finally:
        os.close(parent)


def _qualified_arm_inputs(policy: dict[str, Any], index: int, core: Any) -> None:
    """Root-owned request/runtime must exist and match BEFORE slot consumption."""
    position = policy["positions"][index]
    try:
        request_fd = core._secure_directory(_REQUEST_ROOT)
        try:
            request = core._read_root_file(
                request_fd, "slot-" + position["slot_id"] + ".json"
            )
        finally:
            os.close(request_fd)
        runtime_fd = core._secure_directory(_POLICY_ROOT)
        try:
            runtime = core._read_root_file(
                runtime_fd, "epoch-" + policy["epoch_sha256"] + ".runtime.json"
            )
        finally:
            os.close(runtime_fd)
    except (OSError, core.ProviderGrantDenied) as exc:
        raise ArmDenied("root-owned request or runtime credential is missing") from exc
    if (
        _request_sha(request) != position["request_sha256"]
        or request.get("pair_id") != policy["pair_id"]
        or request.get("condition") != position["arm"]
        or not isinstance(request.get("runner"), dict)
        or request["runner"].get("model") != policy["model"]
        or request["runner"].get("provider") != policy["provider"]
    ):
        raise ArmDenied("root request source or arm identity differs from policy")
    required = {
        "schema_version", "kind", "codex_runner_sha256",
        "base_runner_sha256", "codex_bootstrap_sha256", "request_root",
        "repository_map", "state_root", "transcript_root",
        "provider_evidence_root",
    }
    if (
        not isinstance(runtime, dict)
        or set(runtime) != required
        or type(runtime["schema_version"]) is not int
        or runtime["schema_version"] != 1
        or runtime["kind"] != "rab.root_installed_single_arm_runtime"
        or not all(_hex(runtime[name]) for name in (
            "codex_runner_sha256", "base_runner_sha256",
            "codex_bootstrap_sha256",
        ))
    ):
        raise ArmDenied("root runtime manifest is incomplete")
    for name in (
        "request_root", "repository_map", "state_root",
        "transcript_root", "provider_evidence_root",
    ):
        value = runtime[name]
        if (
            not isinstance(value, str)
            or len(value) > 1024
            or not value.startswith("/")
            or "//" in value
            or ".." in Path(value).parts
        ):
            raise ArmDenied("root runtime path is not a bounded absolute input")
    for filename, sha_field in (
        ("grabowski-rab-codex-runner", "codex_runner_sha256"),
        ("repobrief_agent_benchmark_runner.py", "base_runner_sha256"),
        ("repobrief_agent_benchmark_source_bootstrap.py", "codex_bootstrap_sha256"),
    ):
        _verify_root_owned_file(
            Path("/usr/local/libexec") / filename,
            runtime[sha_field],
        )


def _read_dynamic_arm_artifact(
    policy: dict[str, Any], leaf: str, filename: str, *, max_bytes: int
) -> tuple[bytes, int]:
    """Root reads only a fixed file from the physical DynamicUser private state.

    The public StateDirectory path is overmounted only inside systemd's
    namespace. Following it from the root issuer after unit exit would see
    a different (possibly empty) tree; use the physical root-owned parent.
    """
    patterns = {
        "state": r"unverified-[0-9a-f]{64}\.json",
        "transcripts": r"[0-9a-f]{64}\.jsonl",
        "evidence": r"[0-9a-f]{64}\.(?:stderr|provider\.json|stderr-policy\.json)",
    }
    budgets = {
        "state": {1_048_576},
        "transcripts": {16 * 1024 * 1024},
        "evidence": {256 * 1024, 1_048_576},
    }
    if (
        leaf not in patterns
        or not isinstance(filename, str)
        or re.fullmatch(patterns[leaf], filename) is None
        or type(max_bytes) is not int
        or max_bytes not in budgets[leaf]
        or (max_bytes == 256 * 1024) != filename.endswith(".stderr")
    ):
        raise ArmDenied("root provider artifact selector is invalid")
    pieces = ("var", "lib", "private", _pair_state_directory(policy), "epoch", leaf)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open("/", flags)
    try:
        for part in pieces:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                raise ArmDenied("root provider artifact parent is writable by outsiders")
        handle = os.open(
            filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            before = os.fstat(handle)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_mode & 0o077
                or before.st_uid == 0
                or before.st_size > max_bytes
                or (before.st_size == 0 and not filename.endswith(".stderr"))
            ):
                raise ArmDenied("root provider artifact ownership or size invalid")
            raw = bytearray()
            while len(raw) < before.st_size:
                chunk = os.read(handle, min(1024 * 1024, before.st_size - len(raw)))
                if not chunk:
                    raise ArmDenied("root provider artifact read ended early")
                raw.extend(chunk)
            after = os.fstat(handle)
            if (
                (before.st_dev, before.st_ino, before.st_mode,
                 before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                !=
                (after.st_dev, after.st_ino, after.st_mode,
                 after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            ):
                raise ArmDenied("root provider artifact changed during read")
            return bytes(raw), before.st_uid
        finally:
            os.close(handle)
    except OSError as exc:
        raise ArmDenied("root provider artifact cannot be safely opened") from exc
    finally:
        os.close(parent)


def _verify_completed_provider_capture(
    policy: dict[str, Any], index: int, core: Any
) -> dict[str, str]:
    """Root replays the trusted pinned parser over a completed arm's RAW JSONL.

    This is deliberately after systemd's clean no-descendants readback. It
    never trusts a transient process-exit code or tool-supplied success string.
    """
    position = policy["positions"][index]
    pair = _pair_state_directory(policy)
    home = "/var/lib/" + pair
    request_fd = core._secure_directory(_REQUEST_ROOT)
    runtime_fd = core._secure_directory(_POLICY_ROOT)
    try:
        request = core._read_root_file(
            request_fd, "slot-" + position["slot_id"] + ".json"
        )
        runtime = core._read_root_file(
            runtime_fd, "epoch-" + policy["epoch_sha256"] + ".runtime.json"
        )
    finally:
        os.close(request_fd)
        os.close(runtime_fd)
    paths = {
        "state_root": home + "/epoch/state",
        "transcript_root": home + "/epoch/transcripts",
        "provider_evidence_root": home + "/epoch/evidence",
    }
    if (
        not isinstance(runtime, dict)
        or any(runtime.get(key) != val for key, val in paths.items())
        or _request_sha(request) != position["request_sha256"]
    ):
        raise ArmDenied("root verifier state or request differs from fixed pair")
    observation_bytes, uid = _read_dynamic_arm_artifact(
        policy, "state", "unverified-" + position["slot_id"] + ".json",
        max_bytes=1_048_576,
    )
    observation = _bounded_policy_json(observation_bytes, max_bytes=1_048_576)
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        raise ArmDenied("root verified request identifier is missing")
    filename = hashlib.sha256(request_id.encode("utf-8", "strict")).hexdigest() + ".jsonl"
    stream, stream_uid = _read_dynamic_arm_artifact(
        policy, "transcripts", filename, max_bytes=16 * 1024 * 1024
    )
    if uid != stream_uid:
        raise ArmDenied("root provider output owners differ between transcript and result")
    codex_path = Path("/usr/local/libexec/grabowski-rab-codex-runner")
    base_path = Path("/usr/local/libexec/repobrief_agent_benchmark_runner.py")
    _verify_root_owned_file(codex_path, runtime["codex_runner_sha256"])
    _verify_root_owned_file(base_path, runtime["base_runner_sha256"])
    # No provider command is run: import only the exactly pinned normalizer.
    namespace = runpy.run_path(str(codex_path), run_name="rab_root_capture_verifier")
    normalized = _attest_provider_reply(
        policy, index, request, observation, stream, namespace.get("receipt")
    )
    stem = hashlib.sha256(request_id.encode("utf-8", "strict")).hexdigest()
    stderr, stderr_uid = _read_dynamic_arm_artifact(
        policy, "evidence", stem + ".stderr", max_bytes=256 * 1024
    )
    diagnostics, diagnostic_uid = _read_dynamic_arm_artifact(
        policy, "evidence", stem + ".provider.json", max_bytes=1_048_576
    )
    policy_raw, policy_uid = _read_dynamic_arm_artifact(
        policy, "evidence", stem + ".stderr-policy.json", max_bytes=1_048_576
    )
    if any(owner != uid for owner in (stderr_uid, diagnostic_uid, policy_uid)):
        raise ArmDenied("root provider output owner differs across persisted evidence")
    stderr_proof = _attest_provider_stderr(
        request, stream, stderr, diagnostics, policy_raw,
        namespace.get("classify_stderr"),
    )
    detail = _bounded_policy_json(diagnostics, max_bytes=1_048_576)
    original = observation["runner_receipt"]
    if (
        detail.get("started_at") != original.get("started_at")
        or detail.get("ended_at") != original.get("ended_at")
    ):
        raise ArmDenied("root captured provider timestamps mismatch")
    return {**normalized, **stderr_proof}


def _root_outcome(
    policy: dict[str, Any], index: int, fd: int, token: str,
    *, core: Any | None = None,
) -> None:
    """Root stops verified PID1, replays raw provider JSONL and issues one release."""
    name = _unit(policy, index)
    group = Path("/sys/fs/cgroup/system.slice") / name
    wanted = (
        "Id", "LoadState", "ActiveState", "SubState", "Result", "MainPID",
        "ControlGroup", "InvocationID", "Type", "RemainAfterExit", "KillMode",
        "DynamicUser", "NoNewPrivileges", "StandardInput", "StandardOutput",
        "StandardError",
    )
    deadline = time.monotonic() + policy["max_wall_seconds"] + 135
    observed: dict[str, str] | None = None

    def no_descendants() -> bool:
        if not group.exists():
            return True
        try:
            live = (group / "cgroup.procs").read_bytes()
            threads = (group / "cgroup.threads").read_bytes()
        except OSError as exc:
            raise ArmDenied("root cgroup descendant count is unreadable") from exc
        return not live.strip() and not threads.strip()

    try:
        while True:
            if time.monotonic() > deadline:
                raise ArmDenied("root PID1 arm execution exceeded bounded wait")
            show = subprocess.run(
                [_SYSTEMCTL, "show", name, *(f"--property={k}" for k in wanted)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
            )
            if show.returncode != 0 or len(show.stdout) > 8192:
                raise ArmDenied("root PID1 readback is unavailable")
            values: dict[str, str] = {}
            try:
                for line in show.stdout.decode("ascii", "strict").splitlines():
                    key, sep, val = line.partition("=")
                    if not sep or key in values or key not in wanted:
                        raise ArmDenied("root PID1 fields are ambiguous")
                    values[key] = val
            except UnicodeError as exc:
                raise ArmDenied("root PID1 fields must be ASCII") from exc
            if (
                set(values) != set(wanted)
                or values["Id"] != name
                or values["LoadState"] != "loaded"
                or values["Type"] != "exec"
                or values["RemainAfterExit"] != "yes"
                or values["KillMode"] != "control-group"
                or values["DynamicUser"] != "yes"
                or values["NoNewPrivileges"] != "yes"
                or values["StandardInput"] != "null"
                or values["StandardOutput"] != "null"
                or values["StandardError"] != "null"
                or values["ControlGroup"] != "/system.slice/" + name
            ):
                raise ArmDenied("root PID1 security or unit identity is unqualified")
            if values["ActiveState"] == "active" and values["SubState"] == "exited":
                if (
                    values["Result"] != "success"
                    or values["MainPID"] != "0"
                    or re.fullmatch("[0-9a-f]{32}", values["InvocationID"]) is None
                ):
                    raise ArmDenied("root PID1 completed service has invalid result")
                if not no_descendants():
                    raise ArmDenied("root cgroup still has descendant processes")
                observed = values
                break
            if values["ActiveState"] not in {"active", "activating"} or values["SubState"] not in {
                "running", "start", "start-pre", "condition", "auto-restart"
            }:
                raise ArmDenied("root PID1 service exited unsuccessfully or unobservably")
            time.sleep(0.25)
    finally:
        # RemainAfterExit retains the transient unit for reliable PID1 readback.
        # Always stop it, including failed, timed-out or ambiguous attempts.
        try:
            stopped = subprocess.run(
                [_SYSTEMCTL, "stop", name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ArmDenied("root PID1 unit cleanup could not be confirmed") from exc
        if stopped.returncode != 0:
            raise ArmDenied("root PID1 unit cleanup failed")
    if observed is None or not no_descendants():
        raise ArmDenied("root PID1 lifecycle completion cannot be attested")
    proof: dict[str, str] | None = None
    proof_error: Exception | None = None
    if core is not None:
        # Never report provider success from systemd exit alone. The original
        # root-owned controller reads DynamicUser output only after a clean
        # stop, validates exact stream bytes and replays the pinned parser.
        try:
            proof = _verify_completed_provider_capture(policy, index, core)
        except Exception as exc:
            proof_error = exc
    completed = {
        "schema_version": _VERSION,
        "kind": "rab.root_arm_lifecycle_observation",
        "policy_sha256": _sha(_canonical(policy)),
        "token_sha256": token,
        "unit": name,
        "invocation_id": observed["InvocationID"],
        "result": observed["Result"],
        "main_pid": 0,
        "cgroup_empty": True,
        "provider_outcome_status": (
            "verified_by_root_issuer" if proof is not None else "unverified"
        ),
        "provider_receipt_sha256": (
            proof["provider_receipt_sha256"] if proof is not None else None
        ),
        "transcript_sha256": (
            proof["transcript_sha256"] if proof is not None else None
        ),
        "stderr_policy_sha256": (
            proof["stderr_policy_sha256"] if proof is not None else None
        ),
    }
    _write_once(fd, "completed-" + token + ".json", completed)
    if core is not None and proof is None:
        raise ArmDenied("root provider result remains unverified; slot spent") from proof_error
    if core is not None and index == 0:
        next_slot = policy["positions"][1]["slot_id"]
        _write_once(
            fd, "release-" + next_slot + ".json",
            {
                "schema_version": _VERSION,
                "kind": "rab.root_arm_second_release",
                "policy_sha256": _sha(_canonical(policy)),
                "pair_id": policy["pair_id"],
                "slot_id": next_slot,
                "first_token_sha256": token,
                "first_receipt_sha256": _sha(_canonical(completed)),
            },
        )


def _require_independent_tool_isolation(_policy: dict[str, Any]) -> None:
    """No credential may reach a model until its tools provably cannot use it.

    This must be replaced only by an installed, independently reviewed root
    qualification that denies credential reads, tool-network egress and
    unapproved additional Codex processes. A source test/mock is insufficient.
    """
    raise ArmDenied("installed credential/tool isolation qualification unavailable")


def execute_one(target: str) -> None:
    """Broker-only root effect: one attempt, consumes even if service fails."""
    if os.geteuid() != 0:
        raise ArmDenied("only the installed rootbroker may launch RAB")
    match = _TARGET.fullmatch(target)
    if match is None:
        raise ArmDenied("root arm target must be exact epoch:index")
    epoch, raw_index = match.groups()
    index = int(raw_index)
    policy = _read_policy_bootstrap(epoch)
    core = _verified_core(policy)
    _qualified_credential(policy)
    # Root's valid policy and CAS cannot isolate the credential from a same-UID
    # tool child. Block before any spent marker, unit, or model process.
    _require_independent_tool_isolation(policy)
    _qualified_arm_inputs(policy, index, core)
    _require_input_projection(policy)
    try:
        state_fd = core._secure_directory(_STATE_ROOT)
    except (OSError, core.ProviderGrantDenied) as exc:
        raise ArmDenied("root arm state directory unavailable") from exc
    try:
        # Serialize root dispatch while a unit is alive, even across pairs.
        # flock is only a concurrency guard. O_EXCL is the durable replay gate.
        lock_fd = os.open(
            ".root-arm-lock",
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=state_fd,
        )
        try:
            info = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o077
            ):
                raise ArmDenied("root dispatch lock is unsafe")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            token = _consume_position(policy, index, state_fd, core)
            try:
                completed = subprocess.run(
                    _unit_argv(policy, index),
                    cwd="/",
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=policy["max_wall_seconds"] + 180,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ArmDenied("root systemd dispatch uncertain, slot spent") from exc
            if completed.returncode != 0:
                raise ArmDenied("root systemd dispatch failed, slot spent")
            _root_outcome(policy, index, state_fd, token, core=core)
        finally:
            os.close(lock_fd)
    finally:
        os.close(state_fd)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="exact frozen epoch digest and arm index")
    args = parser.parse_args(argv)
    try:
        execute_one(args.target)
    except (ArmDenied, OSError, subprocess.SubprocessError, ValueError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
