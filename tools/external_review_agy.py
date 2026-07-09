#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

VERDICTS = {"PASS", "NEEDS_CHANGE", "BLOCK"}
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MAX_PROMPT_BYTES = 500_000


class AgyReviewError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AgyReviewError(f"cannot read {label}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AgyReviewError(f"cannot parse {label} as JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AgyReviewError(f"{label} is not a JSON object")
    return data


def is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_packet_file(manifest_path: Path, value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise AgyReviewError(f"manifest {label} is missing or not a string")
    raw = Path(value)
    path = raw if raw.is_absolute() else manifest_path.parent / raw
    try:
        resolved = path.resolve(strict=True)
        packet_dir = manifest_path.parent.resolve(strict=True)
    except OSError as exc:
        raise AgyReviewError(f"cannot resolve manifest {label}: {exc}") from exc
    if not is_inside(resolved, packet_dir):
        raise AgyReviewError(f"manifest {label} escapes external review packet directory")
    if not resolved.is_file():
        raise AgyReviewError(f"manifest {label} is not a regular file")
    return resolved


def validate_manifest(manifest: dict[str, Any]) -> None:
    required = {
        "schema_version": 1,
        "kind": "external_review_packet",
    }
    for key, expected in required.items():
        if manifest.get(key) != expected:
            raise AgyReviewError(f"manifest {key} is not {expected!r}")
    for key in ("repo", "head_sha", "diff_sha256", "prompt_sha256", "diff_path", "prompt_path"):
        if not manifest.get(key):
            raise AgyReviewError(f"manifest {key} is missing")
    pr = manifest.get("pr")
    if isinstance(pr, bool) or not isinstance(pr, int) or pr <= 0:
        raise AgyReviewError("manifest pr is not a positive integer")


def build_agy_prompt(packet_prompt: str, diff_text: str) -> str:
    return (
        packet_prompt.rstrip()
        + "\n\nReturn only compact JSON with this shape:\n"
        + '{"verdict":"PASS|NEEDS_CHANGE|BLOCK","finding_count":0,"findings":[]}'
        + "\nRules: findings must be concrete material issues visible in the diff. "
        + "Do not include generic risk reminders as findings.\n\n"
        + "--- BEGIN DIFF ---\n"
        + diff_text
        + "\n--- END DIFF ---\n"
    )


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", value)


def parse_review_json(stdout: str) -> dict[str, Any]:
    text = strip_ansi(stdout).strip()
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise AgyReviewError("agy review output does not contain a JSON object")
        try:
            parsed = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise AgyReviewError(f"agy review output JSON is invalid: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AgyReviewError("agy review output JSON is not an object")
    verdict = parsed.get("verdict")
    if verdict not in VERDICTS:
        raise AgyReviewError("agy review verdict is missing or invalid")
    finding_count = parsed.get("finding_count")
    if isinstance(finding_count, bool) or not isinstance(finding_count, int) or finding_count < 0:
        raise AgyReviewError("agy review finding_count is not an integer >= 0")
    findings = parsed.get("findings")
    if not isinstance(findings, list):
        raise AgyReviewError("agy review findings is not a list")
    return parsed


def run_agy(
    prompt: str,
    *,
    gemini_bin: str,
    model: str | None,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    argv = [gemini_bin, f"--print-timeout={timeout_seconds}s"]
    if model:
        argv.extend(["--model", model])
    argv.extend(["--print", prompt])
    return subprocess.run(
        argv,
        check=False,
        text=True,
        capture_output=True,
        timeout=timeout_seconds + 15,
    )


def build_evidence(
    *,
    manifest: dict[str, Any],
    prompt_sha256: str,
    review_sha256: str,
    review: dict[str, Any],
    source: str,
    raw_review_path: Path,
) -> dict[str, Any]:
    verdict = review["verdict"]
    finding_count = review["finding_count"]
    pass_without_findings = verdict == "PASS" and finding_count == 0
    return {
        "schema_version": 1,
        "kind": "external_review",
        "repo": manifest["repo"],
        "pr": manifest["pr"],
        "head_sha": manifest["head_sha"],
        "diff_sha256": manifest["diff_sha256"],
        "prompt_sha256": prompt_sha256,
        "prompt_includes_diff": True,
        "reviews": [
            {
                "source": source,
                "review_sha256": review_sha256,
                "verdict": verdict,
                "finding_count": finding_count,
            }
        ],
        "external_reviews_triaged": pass_without_findings,
        "findings": [],
        "raw_review_path": str(raw_review_path),
        "raw_findings": review.get("findings", []),
    }


def run_from_manifest(
    *,
    manifest_path: Path,
    output_path: Path,
    raw_review_path: Path | None,
    gemini_bin: str,
    model: str | None,
    timeout_seconds: int,
    max_prompt_bytes: int,
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve(strict=True)
    manifest = load_json(manifest_path, label="external review manifest")
    validate_manifest(manifest)
    diff_path = resolve_packet_file(manifest_path, manifest["diff_path"], label="diff_path")
    prompt_path = resolve_packet_file(manifest_path, manifest["prompt_path"], label="prompt_path")
    diff_bytes = diff_path.read_bytes()
    actual_diff_sha256 = sha256_bytes(diff_bytes)
    if actual_diff_sha256 != manifest["diff_sha256"]:
        raise AgyReviewError("diff file sha256 does not match manifest")
    packet_prompt = prompt_path.read_text(encoding="utf-8")
    packet_prompt_sha256 = sha256_text(packet_prompt)
    if packet_prompt_sha256 != manifest["prompt_sha256"]:
        raise AgyReviewError("prompt file sha256 does not match manifest")
    prompt = build_agy_prompt(packet_prompt, diff_bytes.decode("utf-8", errors="replace"))
    prompt_bytes = prompt.encode("utf-8")
    if len(prompt_bytes) > max_prompt_bytes:
        raise AgyReviewError(
            f"agy prompt is too large for argv transport: {len(prompt_bytes)} bytes > {max_prompt_bytes}"
        )
    completed = run_agy(prompt, gemini_bin=gemini_bin, model=model, timeout_seconds=timeout_seconds)
    if completed.returncode != 0:
        raise AgyReviewError(f"agy exited with {completed.returncode}: {strip_ansi(completed.stderr or completed.stdout).strip()}")
    if not completed.stdout.strip():
        raise AgyReviewError("agy returned empty stdout")
    review = parse_review_json(completed.stdout)
    raw_path = raw_review_path or output_path.with_suffix(".review.txt")
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(completed.stdout, encoding="utf-8")
    evidence = build_evidence(
        manifest=manifest,
        prompt_sha256=sha256_text(prompt),
        review_sha256=sha256_text(completed.stdout),
        review=review,
        source=f"agy:{model or 'default'}",
        raw_review_path=raw_path,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run agy/Gemini external review for a pr_review_gate packet.")
    parser.add_argument("--manifest", required=True, help="external review manifest JSON from pr_review_gate")
    parser.add_argument("--output", required=True, help="external review evidence JSON to create/replace")
    parser.add_argument("--raw-review-output", help="optional path for raw agy stdout")
    parser.add_argument("--gemini-bin", default="gemini")
    parser.add_argument("--model")
    parser.add_argument("--timeout-seconds", type=positive_int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-prompt-bytes", type=positive_int, default=DEFAULT_MAX_PROMPT_BYTES)
    args = parser.parse_args(argv)
    try:
        evidence = run_from_manifest(
            manifest_path=Path(args.manifest),
            output_path=Path(args.output),
            raw_review_path=Path(args.raw_review_output) if args.raw_review_output else None,
            gemini_bin=args.gemini_bin,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
            max_prompt_bytes=args.max_prompt_bytes,
        )
    except (AgyReviewError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "evidence": str(Path(args.output)), "verdict": evidence["reviews"][0]["verdict"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
