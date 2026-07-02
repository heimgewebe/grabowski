#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

TERMINAL_STATUSES = {"fixed", "accepted", "false_positive", "deferred_with_reason", "not_applicable"}
STOP_REASONS = {"clean_pass", "diminishing_returns", "residual_only_with_reason", "small_trivial_change"}
CODEX_MARKERS = ("codex", "chatgpt-codex")
CLAUDE_MARKERS = ("claude", "anthropic")
RISK_PATH_MARKERS = ("auth", "access", "security", "deploy", "runtime", "systemd", "migration", "database", "policy", "capabilit", "operator", "mcp", "privileged", "audit", "rollback", "secret", "broker")
RISK_PATH_PREFIXES = (
    "src/grabowski_mcp.py",
    "src/grabowski_operator.py",
    "src/grabowski_privileged.py",
    "src/grabowski_recovery.py",
    "src/grabowski_self_deploy.py",
    "tools/pr_review_gate.py",
)
PR_FIELDS = ("number", "title", "state", "isDraft", "mergeStateStatus", "headRefOid", "baseRefOid", "url", "reviewDecision", "changedFiles", "additions", "deletions", "files", "reviews", "latestReviews", "comments")
CHECK_FIELDS = ("bucket", "completedAt", "description", "event", "link", "name", "startedAt", "state", "workflow")


class GateInputError(RuntimeError):
    pass


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1", "GH_PAGER": "cat", "NO_COLOR": "1"})
    return env


def _run_json(repo: Path, argv: list[str], *, allow_nonzero: bool = False) -> Any:
    completed = subprocess.run(argv, cwd=repo, check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_env(), timeout=90)
    if completed.returncode != 0 and not allow_nonzero:
        raise RuntimeError(completed.stderr.strip() or f"command failed: {' '.join(argv)}")
    if not completed.stdout.strip():
        return [] if allow_nonzero else {}
    return json.loads(completed.stdout)


def _flatten_github_pages(raw: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for page in raw:
            if isinstance(page, list):
                items.extend(item for item in page if isinstance(item, dict))
            elif isinstance(page, dict):
                items.append(page)
    elif isinstance(raw, dict):
        items.append(raw)
    return items


def load_pr_state(repo: Path, pr: int) -> dict[str, Any]:
    view = _run_json(repo, ["gh", "pr", "view", str(pr), "--json", ",".join(PR_FIELDS)])
    checks = _run_json(repo, ["gh", "pr", "checks", str(pr), "--json", ",".join(CHECK_FIELDS)], allow_nonzero=True)
    repo_info = _run_json(repo, ["gh", "repo", "view", "--json", "nameWithOwner"])
    name = repo_info.get("nameWithOwner") if isinstance(repo_info, dict) else None
    review_comments: list[dict[str, Any]] = []
    pr_reviews: list[dict[str, Any]] = []
    if isinstance(name, str) and "/" in name:
        raw_review_comments = _run_json(repo, ["gh", "api", f"repos/{name}/pulls/{pr}/comments", "--paginate", "--slurp"], allow_nonzero=True)
        review_comments = _flatten_github_pages(raw_review_comments)
        raw_pr_reviews = _run_json(repo, ["gh", "api", f"repos/{name}/pulls/{pr}/reviews", "--paginate", "--slurp"], allow_nonzero=True)
        pr_reviews = _flatten_github_pages(raw_pr_reviews)
    return {"pr": view, "checks": checks, "reviewComments": review_comments, "prReviews": pr_reviews}


def _actor_text(item: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("author", "user", "actor"):
        actor = item.get(key)
        if isinstance(actor, dict):
            for field in ("login", "name"):
                value = actor.get(field)
                if isinstance(value, str):
                    parts.append(value)
        elif isinstance(actor, str):
            parts.append(actor)
    return " ".join(parts).lower()


def _has_marker(items: list[dict[str, Any]], markers: tuple[str, ...]) -> bool:
    return any(any(marker in _actor_text(item) for marker in markers) for item in items)


def _item_head_sha(item: dict[str, Any]) -> str:
    for key in ("commit_id", "commitId", "commitOID", "commitOid"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    commit = item.get("commit")
    if isinstance(commit, dict):
        for key in ("oid", "id"):
            value = commit.get(key)
            if isinstance(value, str):
                return value
    return ""


def _current_head_items(pr: dict[str, Any], items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    head = pr.get("headRefOid")
    if not isinstance(head, str) or not head:
        return []
    return [item for item in items if _item_head_sha(item) == head]


def _review_items(pr: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for bucket in ("reviews", "latestReviews", "comments", "reviewComments", "prReviews"):
        raw = pr.get(bucket)
        if isinstance(raw, list):
            items.extend(item for item in raw if isinstance(item, dict))
    return items


def _paths(pr: dict[str, Any]) -> list[str]:
    raw = pr.get("files")
    paths: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                value = item.get("path") or item.get("filename")
            else:
                value = item
            if isinstance(value, str):
                paths.append(value)
    return paths


def _is_risk_path(path: str) -> bool:
    normalized = path.lower().lstrip("./")
    return any(normalized == prefix or normalized.startswith(prefix.rstrip("/") + "/") for prefix in RISK_PATH_PREFIXES) or any(marker in normalized for marker in RISK_PATH_MARKERS)


def classify_complexity(pr: dict[str, Any], self_review: dict[str, Any] | None) -> dict[str, Any]:
    changed_files = int(pr.get("changedFiles") or 0)
    changed_lines = int(pr.get("additions") or 0) + int(pr.get("deletions") or 0)
    reasons: list[str] = []
    if changed_files > 15:
        reasons.append("many files")
    if changed_lines > 500:
        reasons.append("large diff")
    if any(_is_risk_path(path) for path in _paths(pr)):
        reasons.append("risk path touched")
    if isinstance(self_review, dict):
        uncertainty = self_review.get("uncertainty")
        if isinstance(uncertainty, (int, float)) and float(uncertainty) > 0.35:
            reasons.append("high review uncertainty")
        material = self_review.get("material_findings_after_first_review")
        if isinstance(material, int) and material > 3:
            reasons.append("many material findings after first review")
    return {"complex": bool(reasons), "reasons": reasons, "changed_files": changed_files, "changed_lines": changed_lines}


def load_self_review(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise GateInputError("self-review must be a JSON object")
    return payload


def _terminal(item: dict[str, Any]) -> bool:
    status = item.get("status")
    if status not in TERMINAL_STATUSES:
        return False
    if status in {"accepted", "deferred_with_reason"} and not item.get("reason"):
        return False
    severity = str(item.get("severity") or "").lower()
    strong = severity in {"p0", "p1", "high", "critical"}
    if (item.get("materiality") == "blocking" or strong) and status in {"accepted", "deferred_with_reason"}:
        return False
    return True


def evaluate_review_gate(state: dict[str, Any], *, self_review: dict[str, Any] | None = None) -> dict[str, Any]:
    pr = state.get("pr") if isinstance(state.get("pr"), dict) else {}
    if isinstance(pr, dict):
        extra_reviews = {key: state[key] for key in ("reviewComments", "prReviews") if isinstance(state.get(key), list)}
        if extra_reviews:
            pr = {**pr, **extra_reviews}
    checks = state.get("checks") if isinstance(state.get("checks"), list) else []
    all_review_items = _review_items(pr)
    items = _current_head_items(pr, all_review_items)
    codex_seen = _has_marker(items, CODEX_MARKERS)
    claude_seen = _has_marker(items, CLAUDE_MARKERS)
    complexity = classify_complexity(pr, self_review)
    failures: list[str] = []
    warnings: list[str] = []

    if pr.get("state") == "CLOSED":
        failures.append("PR is closed")
    if pr.get("state") == "MERGED":
        failures.append("PR is already merged")
    if pr.get("isDraft") is True:
        failures.append("PR is draft")
    if not codex_seen:
        codex = self_review.get("codex_review") if isinstance(self_review, dict) else None
        if isinstance(codex, dict) and codex.get("unavailable_reason"):
            warnings.append("Codex review unavailable but explained")
        else:
            failures.append("Codex review was not observed")

    if self_review is None:
        failures.append("Grabowski self-review evidence is missing")
    else:
        head_sha = pr.get("headRefOid")
        if not head_sha:
            failures.append("PR headRefOid is missing")
        elif self_review.get("head_sha") != head_sha:
            failures.append("self-review head_sha mismatch")
        if self_review.get("diff_reviewed") is not True:
            failures.append("self-review does not assert diff_reviewed=true")
        if self_review.get("all_findings_triaged") is not True:
            failures.append("self-review does not assert all_findings_triaged=true")
        iterations = self_review.get("review_iterations")
        if not isinstance(iterations, list) or not iterations:
            failures.append("self-review has no review_iterations")
        if self_review.get("stop_reason") not in STOP_REASONS:
            failures.append("self-review stop_reason is missing or invalid")
        findings = self_review.get("findings", [])
        if not isinstance(findings, list):
            failures.append("self-review findings is not a list")
        else:
            for index, finding in enumerate(findings):
                if not isinstance(finding, dict) or not _terminal(finding):
                    failures.append(f"finding {index} is not terminally triaged")
        remaining = self_review.get("material_findings_remaining")
        residual = self_review.get("residual_risk")
        accepted_residual = isinstance(residual, dict) and residual.get("accepted") is True and bool(residual.get("reason"))
        if isinstance(remaining, int) and remaining > 0 and not accepted_residual:
            failures.append("material findings remain without accepted residual-risk reason")

    claude = self_review.get("claude_review") if isinstance(self_review, dict) else None
    claude_required = complexity["complex"] or (isinstance(claude, dict) and claude.get("required") is True)
    claude_not_required = isinstance(claude, dict) and claude.get("required") is False and bool(claude.get("reason"))
    if claude_required and not claude_seen:
        failures.append("Claude review is required but not observed on current head")
    if not claude_required and not claude_not_required:
        warnings.append("Claude non-requirement reason is not recorded")

    if not checks:
        failures.append("no status checks observed")
    blocking_checks = [
        check for check in checks
        if isinstance(check, dict) and check.get("bucket") != "pass"
    ]
    if blocking_checks:
        failures.append(f"{len(blocking_checks)} non-green check(s)")

    return {
        "schema_version": 1,
        "verdict": "PASS" if not failures else "BLOCK",
        "failures": failures,
        "warnings": warnings,
        "repo_pr": {"number": pr.get("number"), "title": pr.get("title"), "url": pr.get("url"), "head_sha": pr.get("headRefOid"), "base_sha": pr.get("baseRefOid")},
        "review_sources": {"codex_seen": codex_seen, "claude_seen": claude_seen, "review_item_count": len(all_review_items), "current_head_review_item_count": len(items)},
        "complexity": complexity,
    }


def resolve_inside_repo(repo: Path, raw: str | None) -> Path | None:
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = repo / candidate
    resolved = candidate.resolve()
    root = repo.resolve()
    if resolved != root and root not in resolved.parents:
        raise GateInputError("self-review path must stay inside repo")
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--self-review")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    try:
        self_review = load_self_review(resolve_inside_repo(repo, args.self_review))
        result = evaluate_review_gate(load_pr_state(repo, args.pr), self_review=self_review)
    except Exception as exc:
        result = {"schema_version": 1, "verdict": "BLOCK", "failures": [str(exc)], "warnings": []}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["verdict"])
        for item in result.get("failures", []):
            print(f"BLOCK: {item}")
        for item in result.get("warnings", []):
            print(f"WARN: {item}")
    return 0 if result.get("verdict") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
