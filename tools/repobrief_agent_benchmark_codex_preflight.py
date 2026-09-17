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
import importlib.util
import json
from pathlib import Path
import stat
import sys
from typing import Any


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CORE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_preflight_core.py")
CODEX_RUNNER_PATH = Path(__file__).with_name("repobrief_agent_benchmark_codex_runner.py")
core = _load("repobrief_agent_benchmark_preflight_core_for_codex", CORE_PATH)
codex_runner = _load("repobrief_agent_benchmark_codex_runner_for_authorization", CODEX_RUNNER_PATH)


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
    provider_binding = _validated_codex_provider_binding(
        codex_command, codex_command_sha256
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        try:
            max_cost = Decimal(args.max_cost_usd)
        except InvalidOperation as exc:
            raise core.PreflightError("max cost is not a decimal") from exc
        report = authorize_pair(
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
        core._write_report_artifacts(args.report_out, report)
    except (core.PreflightError, codex_runner.RunnerError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
