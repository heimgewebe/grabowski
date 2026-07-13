#!/usr/bin/env python3
"""Run exactly one cost-bounded RepoBrief benchmark preflight pair.

The preflight proves runner/provider compatibility only. It cannot dispatch the
full benchmark or establish RepoBrief usefulness.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from typing import Any

MODULE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_runner.py")
SPEC = importlib.util.spec_from_file_location("repobrief_agent_benchmark_runner", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load RepoBrief benchmark runner")
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

REPORT_KIND = "repobrief.agent_benchmark_live_preflight"
FIXTURE_REPORT_KIND = "repobrief.agent_benchmark_preflight_fixture_report"
VERSION = "1.0"
MAX_PER_RUN_COST_USD = Decimal("1.00")
MAX_TOTAL_COST_USD = Decimal("2.00")
MAX_REQUEST_FILES = 128
MAX_MCP_LINE_BYTES = 4 * 1024 * 1024
MAX_VALIDATOR_OUTPUT_BYTES = 256 * 1024
REPOBRIEF_ABSTRACT_TOOLS = {
    "ask_context",
    "grounding_verify",
    "live_freshness",
    "repobrief_resource_read",
}
DOES_NOT_ESTABLISH = (
    "repobrief_usefulness",
    "benchmark_completion",
    "provider_reliability_beyond_preflight",
    "answer_correctness_outside_selected_case",
    "default_promotion",
    "permission_to_dispatch_full_benchmark",
)


class PreflightError(ValueError):
    """The preflight contract or evidence is invalid."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _load_object(path: Path, *, maximum: int = runner.MAX_REQUEST_BYTES) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PreflightError(f"cannot read {path}") from exc
    if not raw or len(raw) > maximum:
        raise PreflightError(f"{path} is empty or oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError(f"{path} is not one UTF-8 JSON object") from exc
    if not isinstance(value, dict):
        raise PreflightError(f"{path} must contain one JSON object")
    return value


def _write_private_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    data = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _request_files(request_root: Path) -> list[Path]:
    if request_root.is_symlink():
        raise PreflightError("request root must not be a symlink")
    root = request_root.expanduser().resolve()
    if not root.is_dir():
        raise PreflightError("request root is not a directory")
    files = sorted(root.glob("*.json"))
    if len(files) > MAX_REQUEST_FILES:
        raise PreflightError("request root exceeds planned request limit")
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise PreflightError("request root contains an unsafe JSON entry")
    return files


def load_pair(request_root: Path, pair_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for path in _request_files(request_root):
        value = _load_object(path)
        if value.get("pair_id") == pair_id:
            matches.append(value)
    if len(matches) != 2:
        raise PreflightError(f"pair must contain exactly two planned requests, got {len(matches)}")
    by_condition = {str(item.get("condition")): item for item in matches}
    if set(by_condition) != {"baseline", "treatment"}:
        raise PreflightError("pair must contain baseline and treatment")
    baseline = by_condition["baseline"]
    treatment = by_condition["treatment"]
    runner.validate_request(baseline)
    runner.validate_request(treatment)
    _validate_pair(baseline, treatment)
    runner.load_planned_request(baseline, request_root)
    runner.load_planned_request(treatment, request_root)
    return baseline, treatment


def _validate_pair(baseline: Mapping[str, Any], treatment: Mapping[str, Any]) -> None:
    same_fields = (
        "pair_id",
        "case_id",
        "repetition",
        "taskset_id",
        "taskset_sha256",
        "prompt",
        "budgets",
        "runner",
        "repository",
    )
    for field in same_fields:
        if baseline.get(field) != treatment.get(field):
            raise PreflightError(f"paired requests disagree on {field}")
    if baseline.get("condition") != "baseline" or treatment.get("condition") != "treatment":
        raise PreflightError("pair conditions are invalid")
    if baseline.get("session_id") == treatment.get("session_id"):
        raise PreflightError("paired requests reuse session identity")
    if baseline.get("workspace_id") == treatment.get("workspace_id"):
        raise PreflightError("paired requests reuse workspace identity")
    orders = sorted([int(baseline.get("order", 0)), int(treatment.get("order", 0))])
    if orders != [1, 2]:
        raise PreflightError("pair order must contain 1 and 2")


def _git(command: Sequence[str], *, cwd: Path) -> str:
    environment = runner._git_environment()
    try:
        completed = subprocess.run(
            ["git", *command],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError(f"Git readback failed: {command[0]}") from exc
    return completed.stdout.strip()


def source_state(source: Path) -> dict[str, Any]:
    root = source.expanduser().resolve()
    if not root.is_dir() or not (root / ".git").exists():
        raise PreflightError("source root is not a Git checkout")
    head = _git(["rev-parse", "HEAD"], cwd=root)
    status = _git(["status", "--porcelain=v1", "--untracked-files=all"], cwd=root)
    index_path = Path(_git(["rev-parse", "--git-path", "index"], cwd=root))
    if not index_path.is_absolute():
        index_path = (root / index_path).resolve()
    try:
        index_bytes = index_path.read_bytes()
    except OSError as exc:
        raise PreflightError("cannot read Git index for integrity binding") from exc
    return {
        "root": str(root),
        "head": head,
        "clean": status == "",
        "status_sha256": _sha256_bytes(status.encode("utf-8")),
        "index_sha256": _sha256_bytes(index_bytes),
    }


def _assert_source_unchanged(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    for field in ("root", "head", "clean", "status_sha256", "index_sha256"):
        if before.get(field) != after.get(field):
            raise PreflightError(f"source checkout changed during preflight: {field}")


def prepare_snapshot(treatment: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    started = time.monotonic()
    binding = treatment.get("repobrief")
    if not isinstance(binding, Mapping):
        raise PreflightError("treatment request has no RepoBrief binding")
    manifest = Path(str(binding.get("manifest", ""))).expanduser().resolve()
    try:
        data = manifest.read_bytes()
    except OSError as exc:
        raise PreflightError("bound RepoBrief manifest is unavailable") from exc
    expected = str(binding.get("manifest_sha256", ""))
    actual = _sha256_bytes(data)
    if actual != expected:
        raise PreflightError("bound RepoBrief manifest SHA-256 mismatch")
    elapsed = max(int((time.monotonic() - started) * 1000), 0)
    return {
        "manifest": str(manifest),
        "manifest_sha256": actual,
        "snapshot_reused": True,
        "snapshot_rebuilt": False,
    }, elapsed


def _readline_with_timeout(stream, *, timeout_seconds: float) -> bytes:
    ready, _, _ = select.select([stream], [], [], timeout_seconds)
    if not ready:
        raise PreflightError("RepoBrief MCP response timed out")
    line = stream.readline(MAX_MCP_LINE_BYTES + 1)
    if not line:
        raise PreflightError("RepoBrief MCP closed before responding")
    if len(line) > MAX_MCP_LINE_BYTES:
        raise PreflightError("RepoBrief MCP response is oversized")
    return line


def _rpc(process: subprocess.Popen, message: Mapping[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    if process.stdin is None or process.stdout is None:
        raise PreflightError("RepoBrief MCP pipes are unavailable")
    process.stdin.write((_canonical_json(message) + "\n").encode("utf-8"))
    process.stdin.flush()
    raw = _readline_with_timeout(process.stdout, timeout_seconds=timeout_seconds)
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError("RepoBrief MCP returned invalid JSON") from exc
    if not isinstance(response, dict) or response.get("id") != message.get("id"):
        raise PreflightError("RepoBrief MCP response identity mismatch")
    if "error" in response:
        raise PreflightError("RepoBrief MCP returned a JSON-RPC error")
    result = response.get("result")
    if not isinstance(result, dict):
        raise PreflightError("RepoBrief MCP result is not an object")
    return result


def probe_freshness(treatment: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    binding = treatment.get("repobrief")
    if not isinstance(binding, Mapping):
        raise PreflightError("treatment request has no RepoBrief binding")
    command = binding.get("mcp_command")
    if not isinstance(command, list) or not command or not all(
        isinstance(item, str) and item for item in command
    ):
        raise PreflightError("treatment MCP command is invalid")
    environment = runner._provider_environment()
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=environment,
        )
    except OSError as exc:
        raise PreflightError("RepoBrief MCP could not be started") from exc
    try:
        _rpc(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "repobrief-live-preflight", "version": VERSION},
                },
            },
            timeout_seconds=20,
        )
        result = _rpc(
            process,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "live_freshness",
                    "arguments": {"bundle_manifest": str(binding.get("manifest"))},
                },
            },
            timeout_seconds=30,
        )
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        stderr = b"" if process.stderr is None else process.stderr.read(runner.MAX_STDERR_BYTES + 1)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    if stderr:
        raise PreflightError(
            f"RepoBrief MCP stderr is non-empty: {_sha256_bytes(stderr)} ({len(stderr)} bytes)"
        )
    structured = result.get("structuredContent")
    if result.get("isError") is not False or not isinstance(structured, dict):
        raise PreflightError("RepoBrief MCP freshness call failed")
    status = structured.get("status")
    elapsed = max(int((time.monotonic() - started) * 1000), 0)
    return {
        "status": status,
        "reason": structured.get("reason"),
        "result_sha256": _sha256_json(structured),
        "stale_blocked": status != "fresh",
    }, elapsed


def _transcript_result(receipt: Mapping[str, Any], transcript_root: Path) -> Mapping[str, Any]:
    transcript = receipt.get("transcript")
    if not isinstance(transcript, Mapping):
        raise PreflightError("receipt transcript contract is missing")
    artifact = transcript.get("artifact")
    if not isinstance(artifact, str) or not artifact:
        raise PreflightError("receipt transcript artifact is missing")
    path = (transcript_root.expanduser().resolve() / artifact).resolve()
    try:
        path.relative_to(transcript_root.expanduser().resolve())
    except ValueError as exc:
        raise PreflightError("receipt transcript escapes transcript root") from exc
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PreflightError("receipt transcript cannot be read") from exc
    if _sha256_bytes(raw) != transcript.get("sha256") or len(raw) != transcript.get("bytes"):
        raise PreflightError("receipt transcript binding mismatch")
    messages = runner.parse_jsonl(raw)
    return runner._single_message(messages, message_type="result")


def _observed_cost(receipt: Mapping[str, Any], transcript_root: Path) -> Decimal:
    result = _transcript_result(receipt, transcript_root)
    value = result.get("total_cost_usd")
    try:
        cost = Decimal(str(value))
    except Exception as exc:
        raise PreflightError("provider total_cost_usd is unavailable") from exc
    if not cost.is_finite() or cost < 0:
        raise PreflightError("provider total_cost_usd is unavailable")
    return cost


def _validate_receipt_external(
    command_prefix: Sequence[str],
    *,
    request_path: Path,
    receipt_path: Path,
    transcript_root: Path,
) -> dict[str, Any]:
    command = [
        *command_prefix,
        "validate-receipt",
        "--request",
        str(request_path),
        "--receipt",
        str(receipt_path),
        "--transcript-root",
        str(transcript_root),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=120,
            shell=False,
            env=runner._provider_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("Lenskit receipt validator could not run") from exc
    if len(completed.stdout) > MAX_VALIDATOR_OUTPUT_BYTES or len(completed.stderr) > MAX_VALIDATOR_OUTPUT_BYTES:
        raise PreflightError("Lenskit receipt validator output is oversized")
    if completed.returncode != 0:
        raise PreflightError("Lenskit receipt validation failed")
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError("Lenskit receipt validator returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("status") != "valid":
        raise PreflightError("Lenskit receipt validator did not confirm validity")
    return value


def _tool_requirement(receipt: Mapping[str, Any], *, treatment: bool) -> None:
    calls = receipt.get("tool_calls")
    if not isinstance(calls, list):
        raise PreflightError("receipt tool_calls are invalid")
    names = {item.get("name") for item in calls if isinstance(item, Mapping)}
    if treatment and not names.intersection(REPOBRIEF_ABSTRACT_TOOLS):
        raise PreflightError("treatment used no RepoBrief tool or resource")
    if not treatment and names.intersection(REPOBRIEF_ABSTRACT_TOOLS):
        raise PreflightError("baseline used a RepoBrief tool")


def _request_path(request_root: Path, request: Mapping[str, Any]) -> Path:
    matches = [
        path
        for path in _request_files(request_root)
        if _load_object(path).get("request_id") == request.get("request_id")
    ]
    if len(matches) != 1:
        raise PreflightError("cannot resolve unique planned request path")
    return matches[0]


def _receipt_path(evidence_root: Path, request: Mapping[str, Any]) -> Path:
    filename = hashlib.sha256(str(request["request_id"]).encode("utf-8")).hexdigest() + ".receipt.json"
    return evidence_root.resolve() / "receipts" / filename


def _claude_version(claude: str) -> str:
    try:
        completed = subprocess.run(
            [claude, "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
            env=runner._provider_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("Claude version probe failed") from exc
    version = completed.stdout.strip()
    if not version or len(version) > 500 or completed.stderr:
        raise PreflightError("Claude version probe returned invalid output")
    return version


def execute_preflight(
    *,
    pair_id: str,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    claude: str,
    max_cost_usd: Decimal,
    validator_command: Sequence[str],
    baseline_fixture: Path | None = None,
    treatment_fixture: Path | None = None,
) -> dict[str, Any]:
    if max_cost_usd <= 0 or max_cost_usd > MAX_PER_RUN_COST_USD:
        raise PreflightError(f"max cost must be > 0 and <= {MAX_PER_RUN_COST_USD}")
    fixtures = (baseline_fixture, treatment_fixture)
    if (baseline_fixture is None) != (treatment_fixture is None):
        raise PreflightError("fixtures must be supplied for both conditions or neither")
    synthetic = baseline_fixture is not None
    started_at = _utc_now()
    total_started = time.monotonic()
    baseline, treatment = load_pair(request_root, pair_id)
    source = runner.load_repository_root(baseline, repository_map)
    before = source_state(source)
    snapshot, snapshot_preparation_ms = prepare_snapshot(treatment)
    freshness, freshness_check_ms = probe_freshness(treatment)
    if freshness["status"] != "fresh":
        raise PreflightError(f"treatment snapshot is not fresh: {freshness['status']}")
    version = "synthetic-fixture" if synthetic else _claude_version(claude)

    ordered = sorted([baseline, treatment], key=lambda item: int(item["order"]))
    fixture_by_condition = {
        "baseline": baseline_fixture,
        "treatment": treatment_fixture,
    }
    receipts: dict[str, dict[str, Any]] = {}
    receipt_paths: dict[str, Path] = {}
    observed_costs: dict[str, Decimal] = {}
    agent_execution_ms = 0
    for request in ordered:
        condition = str(request["condition"])
        run_started = time.monotonic()
        output = runner.execute(
            request,
            request_root=request_root,
            repository_map=repository_map,
            state_root=state_root,
            transcript_root=transcript_root,
            claude=claude,
            max_cost_usd=max_cost_usd,
            stream_fixture=fixture_by_condition[condition],
        )
        agent_execution_ms += max(int((time.monotonic() - run_started) * 1000), 0)
        if synthetic:
            if output.get("kind") != runner.FIXTURE_REPORT_KIND:
                raise PreflightError("fixture run did not return fixture report")
            candidate = output.get("normalized_candidate")
            if not isinstance(candidate, dict):
                raise PreflightError("fixture report has no normalized candidate")
            receipt = candidate
        else:
            if output.get("kind") != runner.RECEIPT_KIND:
                raise PreflightError("live run did not return real receipt")
            receipt = output
        _tool_requirement(receipt, treatment=condition == "treatment")
        receipt_path = _receipt_path(evidence_root, request)
        _write_private_exclusive(receipt_path, receipt)
        receipt_paths[condition] = receipt_path
        receipts[condition] = receipt
        if not synthetic:
            _validate_receipt_external(
                validator_command,
                request_path=_request_path(request_root, request),
                receipt_path=receipt_path,
                transcript_root=transcript_root,
            )
            observed_costs[condition] = _observed_cost(receipt, transcript_root)

    total_observed = sum(observed_costs.values(), Decimal("0"))
    if not synthetic and total_observed > MAX_TOTAL_COST_USD:
        raise PreflightError("total observed provider cost exceeds preflight ceiling")
    after = source_state(source)
    _assert_source_unchanged(before, after)
    ended_at = _utc_now()
    total_time_to_answer_ms = max(int((time.monotonic() - total_started) * 1000), 0)

    report = {
        "kind": FIXTURE_REPORT_KIND if synthetic else REPORT_KIND,
        "version": VERSION,
        "status": "synthetic_only" if synthetic else "valid",
        "pair_id": pair_id,
        "synthetic_fixture": synthetic,
        "started_at": _iso(started_at),
        "ended_at": _iso(ended_at),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "claude_version": version,
        },
        "cost": {
            "per_run_authorized_usd": format(max_cost_usd, "f"),
            "total_authorized_usd": format(MAX_TOTAL_COST_USD, "f"),
            "baseline_observed_usd": None if synthetic else format(observed_costs["baseline"], "f"),
            "treatment_observed_usd": None if synthetic else format(observed_costs["treatment"], "f"),
            "total_observed_usd": None if synthetic else format(total_observed, "f"),
        },
        "timings": {
            "snapshot_preparation_ms": snapshot_preparation_ms,
            "freshness_check_ms": freshness_check_ms,
            "agent_execution_ms": agent_execution_ms,
            "total_time_to_answer_ms": total_time_to_answer_ms,
        },
        "snapshot": {**snapshot, **freshness},
        "source_before": before,
        "source_after": after,
        "runs": {
            condition: {
                "request_id": request["request_id"],
                "request_sha256": _sha256_json(request),
                "receipt": str(receipt_paths[condition]),
                "receipt_sha256": _sha256_json(receipts[condition]),
                "transcript": receipts[condition]["transcript"],
            }
            for condition, request in (("baseline", baseline), ("treatment", treatment))
        },
        "default_promoted": False,
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }
    return report


def _command_array(path: Path) -> list[str]:
    value = _load_object(path) if path.suffix == ".json" else None
    if value is not None:
        command = value.get("command")
    else:
        command = None
    if not isinstance(command, list) or not command or not all(
        isinstance(item, str) and item for item in command
    ):
        raise PreflightError("validator command file must contain a non-empty command array")
    return command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one bounded RepoBrief live preflight pair.")
    parser.add_argument("--pair-id", required=True)
    parser.add_argument("--request-root", required=True, type=Path)
    parser.add_argument("--repository-map", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--transcript-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--report-out", required=True, type=Path)
    parser.add_argument("--validator-command", required=True, type=Path)
    parser.add_argument("--claude-command", default="claude")
    parser.add_argument("--max-cost-usd", required=True)
    parser.add_argument("--baseline-stream-fixture", type=Path)
    parser.add_argument("--treatment-stream-fixture", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        max_cost = runner._require_cost(
            args.max_cost_usd,
            "max_cost_usd",
            maximum=MAX_PER_RUN_COST_USD,
        )
        report = execute_preflight(
            pair_id=args.pair_id,
            request_root=args.request_root,
            repository_map=args.repository_map,
            state_root=args.state_root,
            transcript_root=args.transcript_root,
            evidence_root=args.evidence_root,
            claude=args.claude_command,
            max_cost_usd=max_cost,
            validator_command=_command_array(args.validator_command),
            baseline_fixture=args.baseline_stream_fixture,
            treatment_fixture=args.treatment_stream_fixture,
        )
        _write_private_exclusive(args.report_out.expanduser().resolve(), report)
    except (PreflightError, runner.RunnerError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
