#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import subprocess
import sys

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import external_review_plain as plain  # noqa: E402

AntigravityReviewError = plain.PlainReviewError
DEFAULT_MAX_PROMPT_BYTES = plain.DEFAULT_MAX_PROMPT_BYTES
DEFAULT_MAX_REVIEW_BYTES = plain.DEFAULT_MAX_REVIEW_BYTES
DEFAULT_TIMEOUT_SECONDS = plain.DEFAULT_TIMEOUT_SECONDS


def build_antigravity_prompt(
    packet_prompt: str,
    diff_text: str,
    prompt_nonce: str | None = None,
) -> str:
    """Preserve the historical two-argument prompt-builder entry point.

    An omitted nonce is generated freshly rather than defaulted to a constant,
    so a legacy two-argument caller still gets unguessable diff fences.
    """
    return plain.build_plain_prompt(
        packet_prompt,
        diff_text,
        prompt_nonce or secrets.token_hex(16),
    )


parse_review_json = plain.parse_review_json
sha256_bytes = plain.sha256_bytes
sha256_text = plain.sha256_text


def run_from_manifest(
    *,
    manifest_path: Path,
    output_path: Path,
    raw_review_path: Path | None,
    antigravity_bin: str,
    model: str | None,
    timeout_seconds: int,
    max_prompt_bytes: int,
    max_review_bytes: int = DEFAULT_MAX_REVIEW_BYTES,
) -> dict[str, object]:
    """Compatibility entry point for the former Gemini-only adapter."""
    return plain.run_from_manifest(
        manifest_path=manifest_path,
        output_path=output_path,
        raw_review_path=raw_review_path,
        transmitted_prompt_path=None,
        provider="gemini",
        executable=antigravity_bin,
        model=model,
        timeout_seconds=timeout_seconds,
        max_prompt_bytes=max_prompt_bytes,
        max_review_bytes=max_review_bytes,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compatibility wrapper for Gemini plain-LLM external review. "
            "New callers should use external_review_plain.py."
        )
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--raw-review-output")
    parser.add_argument(
        "--antigravity-bin",
        "--gemini-bin",
        dest="antigravity_bin",
        default="agy",
    )
    parser.add_argument("--model")
    parser.add_argument(
        "--timeout-seconds",
        type=plain.positive_int,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--max-prompt-bytes",
        type=plain.positive_int,
        default=DEFAULT_MAX_PROMPT_BYTES,
    )
    parser.add_argument(
        "--max-review-bytes",
        type=plain.positive_int,
        default=DEFAULT_MAX_REVIEW_BYTES,
    )
    args = parser.parse_args(argv)
    try:
        evidence = run_from_manifest(
            manifest_path=Path(args.manifest),
            output_path=Path(args.output),
            raw_review_path=(
                Path(args.raw_review_output)
                if args.raw_review_output
                else None
            ),
            antigravity_bin=args.antigravity_bin,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
            max_prompt_bytes=args.max_prompt_bytes,
            max_review_bytes=args.max_review_bytes,
        )
    except (AntigravityReviewError, subprocess.TimeoutExpired) as exc:
        print(
            json.dumps(
                {"ok": False, "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                "evidence": str(Path(args.output)),
                "provider": "gemini",
                "verdict": evidence["reviews"][0]["verdict"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
