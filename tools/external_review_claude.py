#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

VERDICTS = {"PASS", "NEEDS_CHANGE", "BLOCK"}
DEFAULT_TIMEOUT_MINUTES = 30


class ClaudeReviewError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ClaudeReviewError(f"cannot read {label}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ClaudeReviewError(f"cannot parse {label} as JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ClaudeReviewError(f"{label} is not a JSON object")
    return value


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_packet_file(manifest_path: Path, raw: Any, *, label: str) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ClaudeReviewError(f"manifest {label} is missing or not a string")
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = manifest_path.parent / candidate
    try:
        resolved = candidate.resolve(strict=True)
        packet_dir = manifest_path.parent.resolve(strict=True)
    except OSError as exc:
        raise ClaudeReviewError(f"cannot resolve manifest {label}: {exc}") from exc
    if not _is_inside(resolved, packet_dir):
        raise ClaudeReviewError(f"manifest {label} escapes external review packet directory")
    if not resolved.is_file():
        raise ClaudeReviewError(f"manifest {label} is not a regular file")
    return resolved


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != 1:
        raise ClaudeReviewError("manifest schema_version is not 1")
    if manifest.get("kind") != "external_review_packet":
        raise ClaudeReviewError("manifest kind is not external_review_packet")
    for key in ("repo", "head_sha", "diff_sha256", "prompt_sha256", "diff_path", "prompt_path"):
        if not manifest.get(key):
            raise ClaudeReviewError(f"manifest {key} is missing")
    pr = manifest.get("pr")
    if isinstance(pr, bool) or not isinstance(pr, int) or pr <= 0:
        raise ClaudeReviewError("manifest pr is not a positive integer")


def run_checked(argv: list[str], *, cwd: Path, timeout_seconds: int, text: bool = True) -> subprocess.CompletedProcess[Any]:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=text,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        stderr = completed.stderr if text else completed.stderr.decode("utf-8", errors="replace")
        stdout = completed.stdout if text else completed.stdout.decode("utf-8", errors="replace")
        detail = (stderr or stdout or "").strip()
        raise ClaudeReviewError(f"command exited with {completed.returncode}: {detail}")
    return completed


def current_repo_name(repo: Path) -> str:
    completed = run_checked(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        cwd=repo,
        timeout_seconds=60,
    )
    value = completed.stdout.strip()
    if not value:
        raise ClaudeReviewError("cannot determine repository name")
    return value


def current_pr_head(repo: Path, pr: int) -> str:
    completed = run_checked(
        ["gh", "pr", "view", str(pr), "--json", "headRefOid", "--jq", ".headRefOid"],
        cwd=repo,
        timeout_seconds=60,
    )
    value = completed.stdout.strip()
    if not value:
        raise ClaudeReviewError("cannot determine current PR head")
    return value


def current_pr_diff_sha256(repo: Path, pr: int) -> str:
    completed = run_checked(
        ["gh", "pr", "diff", str(pr)],
        cwd=repo,
        timeout_seconds=180,
        text=False,
    )
    return sha256_bytes(completed.stdout)


def parse_review_json(stdout: str) -> tuple[str, list[Any]]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ClaudeReviewError(f"Claude ultrareview output is not valid JSON: {exc}") from exc

    explicit_verdict: str | None = None
    if isinstance(payload, list):
        findings = payload
    elif isinstance(payload, dict):
        raw_verdict = payload.get("verdict")
        if raw_verdict is not None:
            if raw_verdict not in VERDICTS:
                raise ClaudeReviewError("Claude ultrareview verdict is invalid")
            explicit_verdict = raw_verdict
        findings = None
        for key in ("bugs", "findings", "issues"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                findings = candidate
                break
        if findings is None:
            count = payload.get("finding_count")
            if count == 0 and explicit_verdict == "PASS":
                findings = []
            else:
                raise ClaudeReviewError("Claude ultrareview JSON has no recognized findings list")
    else:
        raise ClaudeReviewError("Claude ultrareview JSON is neither an object nor a list")

    verdict = explicit_verdict or ("PASS" if not findings else "NEEDS_CHANGE")
    if findings and verdict == "PASS":
        raise ClaudeReviewError("Claude ultrareview reports findings with PASS verdict")
    if not findings and verdict in {"NEEDS_CHANGE", "BLOCK"}:
        raise ClaudeReviewError("Claude ultrareview reports a blocking verdict without findings")
    return verdict, findings


def run_from_manifest(
    *,
    manifest_path: Path,
    repo: Path,
    output_path: Path,
    raw_stdout_path: Path | None,
    raw_stderr_path: Path | None,
    claude_bin: str,
    timeout_minutes: int,
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve(strict=True)
    repo = repo.resolve(strict=True)
    if not repo.is_dir():
        raise ClaudeReviewError("repo is not a directory")

    manifest = load_json(manifest_path, label="external review manifest")
    validate_manifest(manifest)
    diff_path = resolve_packet_file(manifest_path, manifest["diff_path"], label="diff_path")
    prompt_path = resolve_packet_file(manifest_path, manifest["prompt_path"], label="prompt_path")
    if sha256_bytes(diff_path.read_bytes()) != manifest["diff_sha256"]:
        raise ClaudeReviewError("packet diff sha256 does not match manifest")
    if sha256_bytes(prompt_path.read_bytes()) != manifest["prompt_sha256"]:
        raise ClaudeReviewError("packet prompt sha256 does not match manifest")

    pr = manifest["pr"]
    expected_head = manifest["head_sha"]
    if current_repo_name(repo) != manifest["repo"]:
        raise ClaudeReviewError("repository name does not match manifest")
    if current_pr_head(repo, pr) != expected_head:
        raise ClaudeReviewError("current PR head does not match manifest before review")
    if current_pr_diff_sha256(repo, pr) != manifest["diff_sha256"]:
        raise ClaudeReviewError("current PR diff does not match manifest before review")

    version = run_checked([claude_bin, "--version"], cwd=repo, timeout_seconds=60).stdout.strip()
    if not version:
        raise ClaudeReviewError("Claude CLI version output is empty")
    command = [claude_bin, "ultrareview", str(pr), "--json", "--timeout", str(timeout_minutes)]
    completed = subprocess.run(
        command,
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_minutes * 60 + 60,
    )
    raw_stdout = completed.stdout or ""
    raw_stderr = completed.stderr or ""
    if completed.returncode != 0:
        detail = (raw_stderr or raw_stdout).strip()
        raise ClaudeReviewError(f"Claude ultrareview exited with {completed.returncode}: {detail}")
    if not raw_stdout.strip():
        raise ClaudeReviewError("Claude ultrareview returned empty stdout")

    verdict, findings = parse_review_json(raw_stdout)
    if current_pr_head(repo, pr) != expected_head:
        raise ClaudeReviewError("current PR head changed during review")
    if current_pr_diff_sha256(repo, pr) != manifest["diff_sha256"]:
        raise ClaudeReviewError("current PR diff changed during review")

    stdout_path = raw_stdout_path or output_path.with_suffix(".review.json")
    stderr_path = raw_stderr_path or output_path.with_suffix(".stderr.txt")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text(raw_stdout, encoding="utf-8")
    stderr_path.write_text(raw_stderr, encoding="utf-8")

    pass_without_findings = verdict == "PASS" and not findings
    evidence = {
        "schema_version": 1,
        "kind": "external_review",
        "repo": manifest["repo"],
        "pr": pr,
        "head_sha": expected_head,
        "diff_sha256": manifest["diff_sha256"],
        "prompt_sha256": manifest["prompt_sha256"],
        "prompt_includes_diff": False,
        "prompt_transmitted": False,
        "review_input": {
            "mode": "claude_ultrareview_pr",
            "repo": manifest["repo"],
            "pr": pr,
            "head_sha": expected_head,
            "diff_sha256": manifest["diff_sha256"],
        },
        "reviews": [
            {
                "source": "claude-cli:ultrareview",
                "tool": "claude-code",
                "tool_version": version,
                "command": command,
                "exit_code": completed.returncode,
                "json_ok": True,
                "review_sha256": sha256_bytes(raw_stdout.encode("utf-8")),
                "stderr_sha256": sha256_bytes(raw_stderr.encode("utf-8")),
                "verdict": verdict,
                "finding_count": len(findings),
            }
        ],
        "external_reviews_triaged": pass_without_findings,
        "findings": [],
        "raw_review_path": str(stdout_path),
        "raw_stderr_path": str(stderr_path),
        "raw_findings": findings,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Claude CLI ultrareview for a pr_review_gate packet.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--raw-stdout")
    parser.add_argument("--raw-stderr")
    parser.add_argument("--claude-bin", default="claude")
    parser.add_argument("--timeout-minutes", type=positive_int, default=DEFAULT_TIMEOUT_MINUTES)
    args = parser.parse_args(argv)
    try:
        evidence = run_from_manifest(
            manifest_path=Path(args.manifest),
            repo=Path(args.repo),
            output_path=Path(args.output),
            raw_stdout_path=Path(args.raw_stdout) if args.raw_stdout else None,
            raw_stderr_path=Path(args.raw_stderr) if args.raw_stderr else None,
            claude_bin=args.claude_bin,
            timeout_minutes=args.timeout_minutes,
        )
    except (ClaudeReviewError, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "evidence": str(Path(args.output)), "verdict": evidence["reviews"][0]["verdict"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
