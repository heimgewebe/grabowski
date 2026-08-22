#!/usr/bin/env python3
"""Read-only M1 evidence for Grabowski public tool-surface usage.

This analyzer derives aggregate mutation-tool counts from the existing verified
Grabowski audit chain. It does not create a second telemetry store and it does
not claim read-only tool usage when no durable call evidence exists for it.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Iterable, Iterator

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCHEMA_VERSION = 1
DEFAULT_WINDOW_HOURS = 24 * 7
DEFAULT_TOP = 40
MAX_TOP = 200
MAX_WINDOW_HOURS = 24 * 365
READ_ANNOTATION_NAMES = {
    "READ_ANNOTATIONS",
    "READ_ONLY",
    "LOCAL_READ",
    "REMOTE_READ",
}
WRITE_ANNOTATION_NAMES = {
    "CREATE_ANNOTATIONS",
    "REPLACE_ANNOTATIONS",
    "REMOVE_ANNOTATIONS",
    "SECRET_REVEAL_ANNOTATIONS",
    "SECRET_USE_ANNOTATIONS",
    "MUTATING",
    "DEPLOY_MUTATING",
}
MUTATION_USAGE_EVIDENCE_GAPS = {
    "grabowski_recovery_provenance_repair": (
        "Successful integrity repair deliberately bypasses transport roundtrip evidence, "
        "so it does not emit effect-admission; any admission count for this tool does "
        "not establish successful recovery mutation usage."
    )
}


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def clean_repository_head(repo: Path) -> str:
    head = git(repo, "rev-parse", "HEAD")
    dirty = git(repo, "status", "--porcelain", "--untracked-files=normal")
    if dirty:
        raise RuntimeError(
            "tool-surface usage analysis requires a clean repository checkout"
        )
    return head


def require_stable_repository_head(repo: Path, expected_head: str) -> None:
    observed_head = clean_repository_head(repo)
    if observed_head != expected_head:
        raise RuntimeError(
            "repository HEAD changed during tool-surface usage analysis: "
            f"expected {expected_head}, observed {observed_head}"
        )


def _audit_query_module() -> Any:
    """Load the existing audit verifier only for live-report execution."""

    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    import grabowski_audit_query

    return grabowski_audit_query


def _annotation_symbol(value: ast.AST) -> str | None:
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        return value.attr
    return None


def _tool_declaration(node: ast.AST) -> tuple[str, str, str] | None:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        function = decorator.func
        if not isinstance(function, ast.Attribute) or function.attr != "tool":
            continue
        tool_name: str | None = None
        annotation_symbol: str | None = None
        for keyword in decorator.keywords:
            if (
                keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                tool_name = keyword.value.value
            elif keyword.arg == "annotations":
                annotation_symbol = _annotation_symbol(keyword.value)
        if tool_name is None:
            continue
        if annotation_symbol in READ_ANNOTATION_NAMES:
            mode = "read_only"
        elif annotation_symbol in WRITE_ANNOTATION_NAMES:
            mode = "mutating"
        else:
            mode = "unknown"
        return tool_name, mode, annotation_symbol or "unknown"
    return None


def tool_declarations(repo: Path) -> dict[str, dict[str, Any]]:
    declarations: dict[str, dict[str, Any]] = {}
    for path in sorted((repo / "src").glob("*.py")):
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            declaration = _tool_declaration(node)
            if declaration is None:
                continue
            tool_name, mode, annotation_symbol = declaration
            record = {
                "tool": tool_name,
                "mode": mode,
                "annotation_symbol": annotation_symbol,
                "source": path.relative_to(repo).as_posix(),
                "line": int(getattr(node, "lineno", 0)),
            }
            previous = declarations.get(tool_name)
            if previous is not None and previous != record:
                raise RuntimeError(f"duplicate public tool declaration: {tool_name}")
            declarations[tool_name] = record
    return declarations


def expected_tools(repo: Path) -> list[str]:
    contract = json.loads(
        (repo / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
    )
    tools = contract.get("expected_tools")
    if not isinstance(tools, list) or not all(isinstance(item, str) for item in tools):
        raise RuntimeError("runtime-entrypoint expected_tools is invalid")
    if len(tools) != len(set(tools)):
        raise RuntimeError("runtime-entrypoint expected_tools must be unique")
    return list(tools)


def iter_verified_raw_records(snapshot: Any) -> Iterator[dict[str, Any]]:
    """Yield raw objects from bytes already bound by a verified audit snapshot.

    Archived segments are re-hashed by the existing audit loader before use.
    The active segment is the byte snapshot captured during verification. No raw
    field is returned by the final report unless explicitly aggregated.
    """

    audit_query = _audit_query_module()
    for segment in snapshot.segments:
        data = audit_query._load_snapshot_segment(segment)
        lines = data.splitlines()
        if len(lines) != segment.records:
            raise RuntimeError("verified audit segment record count changed")
        for raw_line in lines:
            try:
                record = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("verified audit record cannot be decoded") from exc
            if not isinstance(record, dict):
                raise RuntimeError("verified audit record is not an object")
            yield record


def summarize_effect_admissions(
    records: Iterable[dict[str, Any]],
    *,
    cutoff_unix: int,
    until_unix: int,
    expected: list[str],
    declarations: dict[str, dict[str, Any]],
    top: int,
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    missing_tool_attribution = 0
    matched = 0
    minimum_timestamp: int | None = None
    maximum_timestamp: int | None = None

    for record in records:
        timestamp = record.get("timestamp_unix")
        if (
            type(timestamp) is not int
            or timestamp < cutoff_unix
            or timestamp > until_unix
        ):
            continue
        if record.get("operation") != "effect-admission":
            continue
        matched += 1
        minimum_timestamp = (
            timestamp
            if minimum_timestamp is None
            else min(minimum_timestamp, timestamp)
        )
        maximum_timestamp = (
            timestamp
            if maximum_timestamp is None
            else max(maximum_timestamp, timestamp)
        )
        tool = record.get("tool")
        if isinstance(tool, str) and tool:
            counts[tool] += 1
        else:
            missing_tool_attribution += 1

    expected_set = set(expected)
    expected_declarations = {
        name: declarations[name] for name in expected if name in declarations
    }
    missing_declarations = sorted(expected_set - set(expected_declarations))
    staged_unpublished = sorted(set(declarations) - expected_set)
    unknown_annotation_tools = sorted(
        name
        for name, declaration in expected_declarations.items()
        if declaration["mode"] == "unknown"
    )
    mutating_tools = sorted(
        name
        for name, declaration in expected_declarations.items()
        if declaration["mode"] == "mutating"
    )
    read_only_tools = sorted(
        name
        for name, declaration in expected_declarations.items()
        if declaration["mode"] == "read_only"
    )
    observed_expected = sorted(name for name in expected if counts[name] > 0)
    mutation_usage_gap_tools = sorted(
        name for name in mutating_tools if name in MUTATION_USAGE_EVIDENCE_GAPS
    )
    measurable_mutating_tools = sorted(
        name for name in mutating_tools if name not in MUTATION_USAGE_EVIDENCE_GAPS
    )
    observed_mutating = sorted(
        name for name in measurable_mutating_tools if counts[name] > 0
    )
    unobserved_mutating = sorted(
        name for name in measurable_mutating_tools if counts[name] == 0
    )
    unexpected_admissions = sorted(name for name in counts if name not in expected_set)

    return {
        "effect_admission_count": matched,
        "tool_attribution_missing_count": missing_tool_attribution,
        "time_range_unix": {
            "minimum": minimum_timestamp,
            "maximum": maximum_timestamp,
        },
        "surface": {
            "expected_tool_count": len(expected),
            "declared_expected_tool_count": len(expected_declarations),
            "read_only_tool_count": len(read_only_tools),
            "mutating_tool_count": len(mutating_tools),
            "mutation_usage_measurable_tool_count": len(measurable_mutating_tools),
            "mutation_usage_gap_tool_count": len(mutation_usage_gap_tools),
            "mutation_usage_gap_tools": mutation_usage_gap_tools,
            "unknown_annotation_tool_count": len(unknown_annotation_tools),
            "missing_declarations": missing_declarations,
            "unknown_annotation_tools": unknown_annotation_tools,
            "staged_unpublished_tools": staged_unpublished,
        },
        "mutation_usage": {
            "observed_expected_tool_count": len(observed_expected),
            "observed_mutating_tool_count": len(observed_mutating),
            "unobserved_mutating_tool_count": len(unobserved_mutating),
            "unobserved_mutating_tools": unobserved_mutating,
            "unexpected_admission_tools": unexpected_admissions,
            "top_mutation_admissions": [
                {"tool": name, "count": count}
                for name, count in counts.most_common(top)
            ],
            "rare_mutation_tools": [
                {"tool": name, "count": counts[name]}
                for name in sorted(counts)
                if counts[name] <= 2
            ],
        },
        "evidence_gaps": [
            {
                "kind": "read_only_tool_usage",
                "reason": (
                    "The durable effect-admission audit records mutation admission, "
                    "not ordinary read-only tool invocations."
                ),
                "needed_for": (
                    "treating absence of a public tool from this report as evidence "
                    "for P9 removal"
                ),
            },
            *[
                {
                    "kind": "mutation_tool_usage",
                    "tool": name,
                    "reason": MUTATION_USAGE_EVIDENCE_GAPS[name],
                    "needed_for": (
                        "classifying this mutation tool as observed or unobserved usage"
                    ),
                }
                for name in mutation_usage_gap_tools
            ],
        ],
        "does_not_establish": [
            "successful domain effects from admission counts",
            "read-only tool usage or non-usage",
            "tool redundancy",
            "safe public tool removal",
            "causality or user intent",
        ],
    }


def build_report(
    repo: Path,
    *,
    window_hours: int,
    top: int,
    now_unix: int | None = None,
) -> dict[str, Any]:
    repo = repo.resolve()
    if not 1 <= window_hours <= MAX_WINDOW_HOURS:
        raise ValueError(f"window_hours must be between 1 and {MAX_WINDOW_HOURS}")
    if not 1 <= top <= MAX_TOP:
        raise ValueError(f"top must be between 1 and {MAX_TOP}")
    observed_now = int(time.time()) if now_unix is None else int(now_unix)
    cutoff_unix = observed_now - window_hours * 3600
    repo_head = clean_repository_head(repo)
    audit_query = _audit_query_module()
    snapshot = audit_query.capture_verified_audit_snapshot()
    declarations = tool_declarations(repo)
    expected = expected_tools(repo)
    summary = summarize_effect_admissions(
        iter_verified_raw_records(snapshot),
        cutoff_unix=cutoff_unix,
        until_unix=observed_now,
        expected=expected,
        declarations=declarations,
        top=top,
    )
    require_stable_repository_head(repo, repo_head)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_tool_surface_usage_v1",
        "authority": "derived_from_verified_grabowski_audit_chain",
        "repository": str(repo),
        "repo_head": repo_head,
        "repo_dirty": False,
        "observed_at_unix": observed_now,
        "window_hours": window_hours,
        "cutoff_unix": cutoff_unix,
        "audit": {
            "chain_content_sha256": snapshot.chain_content_sha256,
            "chain_materialization_sha256": snapshot.chain_materialization_sha256,
            "last_record_sha256": snapshot.last_record_sha256,
            "total_records": snapshot.total_records,
            "segment_count": len(snapshot.segments),
        },
        **summary,
    }
    digest_material = dict(report)
    report["report_sha256"] = sha256_json(digest_material)
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Derive aggregate Grabowski mutation-tool usage from verified audit evidence."
    )
    result.add_argument("--repo", type=Path, default=ROOT)
    result.add_argument("--window-hours", type=int, default=DEFAULT_WINDOW_HOURS)
    result.add_argument("--top", type=int, default=DEFAULT_TOP)
    result.add_argument("--now-unix", type=int)
    result.add_argument("--output", type=Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    report = build_report(
        arguments.repo,
        window_hours=arguments.window_hours,
        top=arguments.top,
        now_unix=arguments.now_unix,
    )
    encoded = canonical_json_bytes(report)
    if arguments.output is not None:
        arguments.output.write_bytes(encoded)
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
