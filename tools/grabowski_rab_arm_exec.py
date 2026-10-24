#!/usr/bin/python3
"""Fixed per-arm RAB process started solely by a root-owned systemd unit.

This adapter does not issue one-shot grants, certify provider outcomes, or
authorize the second arm. The existing Codex runner retains all of its live
preflight, external-provider and tool-isolation gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PAIR_LIMIT = 256
_CREDENTIAL_LIMIT = 1_048_576
_RESULT_LIMIT = 1_048_576
_INSTALLED_CODEX = Path("/usr/local/libexec/grabowski-rab-codex")
_INSTALLED_CODEX_RUNNER = Path("/usr/local/libexec/grabowski-rab-codex-runner")
_INSTALLED_BASE_RUNNER = Path("/usr/local/libexec/repobrief_agent_benchmark_runner.py")
_INSTALLED_BOOTSTRAP = Path("/usr/local/libexec/repobrief_agent_benchmark_source_bootstrap.py")
_PLAN_SHA256 = "2795584ac0c100cdceb6ed2c7eb42b883de2099b2a3d33ac51dbe9987655f10c"


class ArmExecDenied(RuntimeError):
    """Deny the exact arm. Failed or uncertain attempts are not replayable."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _unit(epoch: str, pair_id: str, slot_id: str) -> str:
    token = _sha(_canonical({"epoch_sha256": epoch, "pair_id": pair_id, "slot_id": slot_id}))
    return "grabowski-rab-" + token[:16] + ".service"


def _admit_target(epoch: str, pair_id: str, slot_id: str, arm: str) -> str:
    if (
        not isinstance(epoch, str) or _SHA.fullmatch(epoch) is None
        or not isinstance(slot_id, str) or _SHA.fullmatch(slot_id) is None
        or not isinstance(pair_id, str)
        or arm not in {"baseline", "treatment"}
    ):
        raise ArmExecDenied("single-arm target is invalid")
    try:
        pair_raw = pair_id.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ArmExecDenied("single-arm pair encoding is invalid") from exc
    if not 0 < len(pair_raw) <= _PAIR_LIMIT or any(ord(ch) < 32 for ch in pair_id):
        raise ArmExecDenied("single-arm pair length or controls are invalid")
    return _unit(epoch, pair_id, slot_id)


def _systemd_credential_dir(unit: str) -> int:
    """The caller must inhabit the exact PID1-created, unprivileged unit."""
    if os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise ArmExecDenied("root and mismatched user processes cannot execute an arm")
    if os.environ.get("CREDENTIALS_DIRECTORY") != "/run/credentials/" + unit:
        raise ArmExecDenied("the fixed systemd credential directory is unavailable")
    try:
        if Path("/proc/self/cgroup").read_text(encoding="ascii").strip() != "0::/system.slice/" + unit:
            raise ArmExecDenied("the kernel cgroup differs from the frozen arm")
        fields = dict(
            line.split(":", 1) for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines()
            if ":" in line
        )
        if fields.get("NoNewPrivs", "").strip() != "1" or any(
            int(fields.get(cap, "-1").strip(), 16) != 0
            for cap in ("CapEff", "CapPrm", "CapAmb")
        ):
            raise ArmExecDenied("kernel privilege restrictions are missing")
        for number in (0, 1, 2):
            if os.readlink("/proc/self/fd/" + str(number)) != "/dev/null":
                raise ArmExecDenied("privileged stdio was inherited")
        return os.open(
            os.environ["CREDENTIALS_DIRECTORY"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        raise ArmExecDenied("systemd process identity cannot be attested") from exc


def _credential(fd: int, name: str) -> dict[str, Any]:
    if name not in {"pair.json", "request.json", "runtime.json"}:
        raise ArmExecDenied("unexpected credential name")
    try:
        item = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd
        )
        try:
            before = os.fstat(item)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_mode & 0o022
                or not 0 < before.st_size <= _CREDENTIAL_LIMIT
            ):
                raise ArmExecDenied("systemd credential file is unqualified")
            raw = os.read(item, _CREDENTIAL_LIMIT + 1)
            after = os.fstat(item)
            if (
                len(raw) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise ArmExecDenied("systemd credential file changed during reading")
        finally:
            os.close(item)
        result = json.loads(raw)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ArmExecDenied("systemd credential cannot be safely read") from exc
    if not isinstance(result, dict):
        raise ArmExecDenied("systemd credential is not a JSON object")
    return result


def _verify_pair(policy: dict[str, Any], request: dict[str, Any], *,
                 epoch: str, pair_id: str, slot_id: str, arm: str) -> None:
    required = {
        "schema_version", "kind", "epoch_sha256", "plan_sha256", "pair_id",
        "provider", "mode", "model", "reasoning", "max_exec_per_arm",
        "max_wall_seconds", "installed_sha256", "positions",
    }
    if set(policy) != required or (
        type(policy["schema_version"]) is not int or policy["schema_version"] != 2
        or policy["kind"] != "rab.root_controlled_separate_arms"
        or policy["plan_sha256"] != _PLAN_SHA256
        or policy["epoch_sha256"] != epoch or policy["pair_id"] != pair_id
        or policy["provider"] != "openai-codex-cli" or policy["mode"] != "chatgpt_subscription"
        or policy["model"] != "gpt-6-astra" or policy["reasoning"] != "medium"
        or type(policy["max_exec_per_arm"]) is not int or policy["max_exec_per_arm"] != 1
        or type(policy["max_wall_seconds"]) is not int or policy["max_wall_seconds"] != 300
    ):
        raise ArmExecDenied("frozen root pair policy does not match this arm")
    positions = policy["positions"]
    if not isinstance(positions, list) or len(positions) != 2:
        raise ArmExecDenied("root pair has the wrong number of arms")
    matches = [
        p for p in positions
        if isinstance(p, dict) and p.get("slot_id") == slot_id and p.get("arm") == arm
    ]
    if len(matches) != 1 or type(matches[0].get("index")) is not int or matches[0]["index"] not in (0, 1):
        raise ArmExecDenied("unit's exact slot is not root-authorized")
    match = matches[0]
    if (
        set(match) != {"index", "arm", "slot_id", "request_sha256"}
        or any(not isinstance(p, dict) for p in positions)
        or positions[match["index"]] != match
        or _sha(_canonical(request)) != match["request_sha256"]
        or request.get("pair_id") != pair_id
        or request.get("condition") != arm
        or not isinstance(request.get("runner"), dict)
        or request["runner"].get("model") != "gpt-6-astra"
        or request["runner"].get("provider") != "openai-codex-cli"
    ):
        raise ArmExecDenied("request bytes, slot, or model differ from the root policy")
    budget = request.get("budgets")
    if (
        not isinstance(budget, dict)
        or type(budget.get("wall_seconds")) is not int
        or not 1 <= budget["wall_seconds"] <= 300
    ):
        raise ArmExecDenied("provider budget is outside the frozen arm limit")


def _root_owned_digest(path: Path, sha256: str, *, max_bytes: int) -> None:
    """Use exact installed paths and root-owned regular bytes, never a tool path."""
    if not isinstance(sha256, str) or _SHA.fullmatch(sha256) is None:
        raise ArmExecDenied("installed digest is invalid")
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o022 or not 0 < info.st_size <= max_bytes
        ):
            raise ArmExecDenied("installed binary is not root-owned and immutable")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != sha256:
            raise ArmExecDenied("installed binary digest mismatch")
    except OSError as exc:
        raise ArmExecDenied("installed binary cannot be verified") from exc


def _verified_bootstrap_text(expected_sha256: str) -> str:
    # The Codex runner intentionally refuses direct invocation. Capture the
    # canonical existing bootstrap bytes before placing them in Python -c.
    _root_owned_digest(_INSTALLED_BOOTSTRAP, expected_sha256, max_bytes=1024 * 1024)
    try:
        source = _INSTALLED_BOOTSTRAP.read_bytes()
        if _sha(source) != expected_sha256:
            raise ArmExecDenied("installed immutable bootstrap changed")
        return source.decode("utf-8", "strict")
    except (OSError, UnicodeError) as exc:
        raise ArmExecDenied("installed immutable Codex bootstrap unavailable") from exc


def _runner_args(runtime: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    required = {
        "schema_version", "kind", "codex_runner_sha256",
        "base_runner_sha256", "codex_bootstrap_sha256", "request_root", "repository_map", "state_root",
        "transcript_root", "provider_evidence_root",
    }
    if (
        set(runtime) != required
        or type(runtime["schema_version"]) is not int or runtime["schema_version"] != 1
        or runtime["kind"] != "rab.root_installed_single_arm_runtime"
    ):
        raise ArmExecDenied("root runtime credential has missing or unknown keys")
    sha = policy.get("installed_sha256")
    if not isinstance(sha, dict) or not isinstance(sha.get("codex"), str):
        raise ArmExecDenied("root binary policy is incomplete")
    _root_owned_digest(_INSTALLED_CODEX, sha["codex"], max_bytes=512 * 1024 * 1024)
    _root_owned_digest(_INSTALLED_CODEX_RUNNER, runtime["codex_runner_sha256"], max_bytes=16 * 1024 * 1024)
    _root_owned_digest(_INSTALLED_BASE_RUNNER, runtime["base_runner_sha256"], max_bytes=16 * 1024 * 1024)
    bootstrap = _verified_bootstrap_text(runtime["codex_bootstrap_sha256"])
    arguments = [sys.executable, "-I", "-B", "-c", bootstrap, str(_INSTALLED_CODEX_RUNNER)]
    for field in ("request_root", "repository_map", "state_root", "transcript_root", "provider_evidence_root"):
        path = runtime[field]
        if (
            not isinstance(path, str) or not path.startswith("/")
            or "//" in path or ".." in Path(path).parts or len(path) > 1024
        ):
            raise ArmExecDenied("root-controlled runtime path is unsafe")
        arguments.extend(("--" + field.replace("_", "-"), path))
    return arguments + [
        "--codex-command", str(_INSTALLED_CODEX),
        "--codex-command-sha256", sha["codex"],
        "--allow-live-provider",
    ]


def _write_result(state_path: str, slot_id: str, result: dict[str, Any]) -> None:
    """Atomic create-only output. This is explicitly NOT a provider attestation."""
    try:
        fd = os.open(state_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ArmExecDenied("arm output directory is not private")
            raw = _canonical(result) + b"\n"
            if len(raw) > _RESULT_LIMIT:
                raise ArmExecDenied("arm result is too large")
            out = os.open(
                "unverified-" + slot_id + ".json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=fd,
            )
            try:
                if os.write(out, raw) != len(raw):
                    raise ArmExecDenied("arm result output was incomplete")
                os.fsync(out)
            finally:
                os.close(out)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ArmExecDenied("arm result could not be committed once") from exc


def execute(epoch: str, pair_id: str, slot_id: str, arm: str) -> None:
    unit = _admit_target(epoch, pair_id, slot_id, arm)
    credentials = _systemd_credential_dir(unit)
    try:
        policy = _credential(credentials, "pair.json")
        request = _credential(credentials, "request.json")
        runtime = _credential(credentials, "runtime.json")
    finally:
        os.close(credentials)
    _verify_pair(policy, request, epoch=epoch, pair_id=pair_id, slot_id=slot_id, arm=arm)
    argv = _runner_args(runtime, policy)
    # Root owns the spent marker before PID1 launches us. The existing
    # provider runner must still accept its independently verified one-shot
    # authorization; this adapter does not override either old HOLD.
    with tempfile.TemporaryFile(mode="w+b") as stdout, tempfile.TemporaryFile(mode="w+b") as stderr:
        try:
            outcome = subprocess.run(
                argv, input=_canonical(request), stdout=stdout, stderr=stderr,
                check=False, timeout=390, cwd="/", shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ArmExecDenied("Codex runner outcome is uncertain and must not retry") from exc
        if outcome.returncode != 0:
            raise ArmExecDenied("existing Codex runner denied or failed this arm")
        stdout.seek(0, os.SEEK_END)
        amount = stdout.tell()
        if not 0 < amount <= _RESULT_LIMIT:
            raise ArmExecDenied("Codex runner produced no bounded receipt")
        stdout.seek(0)
        try:
            runner_receipt = json.loads(stdout.read(_RESULT_LIMIT + 1))
        except (UnicodeError, ValueError) as exc:
            raise ArmExecDenied("Codex runner receipt is invalid JSON") from exc
        if (
            not isinstance(runner_receipt, dict)
            or runner_receipt.get("status") != "success"
            or runner_receipt.get("request_id") != request.get("request_id")
            or runner_receipt.get("request_sha256") != _sha(_canonical(request))
        ):
            raise ArmExecDenied("Codex runner success is not bound to this exact request")
        _write_result(runtime["state_root"], slot_id, {
            "schema_version": 1,
            "kind": "rab.unverified_single_arm_runner_observation",
            "unit": unit, "pair_id": pair_id, "slot_id": slot_id,
            "arm": arm, "request_sha256": _sha(_canonical(request)),
            "runner_receipt_sha256": _sha(_canonical(runner_receipt)),
            "runner_receipt_bytes": amount,
            # Root must independently verify immutable provider evidence
            # before issuing a second-arm release.
            "provider_outcome_status": "unverified",
        })


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--epoch-sha256", required=True)
    parser.add_argument("--pair-id", required=True)
    parser.add_argument("--slot-id", required=True)
    parser.add_argument("--arm", required=True, choices=("baseline", "treatment"))
    args = parser.parse_args(argv)
    try:
        execute(args.epoch_sha256, args.pair_id, args.slot_id, args.arm)
    except (ArmExecDenied, OSError, subprocess.SubprocessError, ValueError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
