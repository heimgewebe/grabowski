#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

TERMINAL_STATUSES = {"fixed", "accepted", "false_positive", "deferred_with_reason", "not_applicable"}
STOP_REASONS = {"clean_pass", "diminishing_returns", "residual_only_with_reason", "small_trivial_change"}
STRONG_SEVERITIES = {"p0", "p1", "high", "critical"}
BLOCKING_REVIEW_STATES = {"CHANGES_REQUESTED", "DISMISSED", "PENDING"}
EXPECTED_CHECK_NAMES = ("validate (3.10)", "validate (3.12)")
TRUSTED_CODEX_ACTORS = {"chatgpt-codex-connector", "chatgpt-codex-connector[bot]"}
TRUSTED_CLAUDE_ACTORS = {"claude[bot]", "claude-code[bot]", "anthropic[bot]"}
EXTERNAL_REVIEW_VERDICTS = {"PASS", "NEEDS_CHANGE", "BLOCK"}
RISK_PATH_MARKERS = (
    "auth",
    "access",
    "security",
    "deploy",
    "runtime",
    "systemd",
    "migration",
    "database",
    "policy",
    "capabilit",
    "operator",
    "mcp",
    "privileged",
    "audit",
    "rollback",
    "secret",
    "broker",
)
RISK_PATH_PREFIXES = (
    "src/grabowski_mcp.py",
    "src/grabowski_operator.py",
    "src/grabowski_privileged.py",
    "src/grabowski_recovery.py",
    "src/grabowski_self_deploy.py",
    "src/grabowski_tasks.py",
    "src/grabowski_checkouts.py",
    "src/grabowski_operations.py",
    "src/grabowski_artifacts.py",
    "tools/pr_review_gate.py",
)
PR_FIELDS = (
    "number",
    "title",
    "state",
    "isDraft",
    "mergeStateStatus",
    "mergeable",
    "headRefOid",
    "baseRefOid",
    "url",
    "reviewDecision",
    "changedFiles",
    "additions",
    "deletions",
    "files",
    "reviews",
    "latestReviews",
    "comments",
)
CHECK_FIELDS = ("bucket", "completedAt", "description", "event", "link", "name", "startedAt", "state", "workflow")
MAX_EVIDENCE_BYTES = 1_000_000


class GateInputError(RuntimeError):
    pass


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1", "GH_PAGER": "cat", "NO_COLOR": "1"})
    return env


def _command_label(argv: list[str]) -> str:
    visible = argv[:4]
    suffix = " ..." if len(argv) > 4 else ""
    return " ".join(visible) + suffix


def _brief_error(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) > 240:
        return collapsed[:237] + "..."
    return collapsed


def _run_json(repo: Path, argv: list[str], *, allow_nonzero: bool = False) -> Any:
    text = _run_text(repo, argv, allow_nonzero=allow_nonzero)
    if not text.strip():
        return [] if allow_nonzero else {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"command did not return JSON: {_command_label(argv)}") from exc


def _run_text(repo: Path, argv: list[str], *, allow_nonzero: bool = False) -> str:
    if argv and argv[0] == "gh" and shutil.which("gh") is None:
        raise GateInputError("gh CLI is not available in PATH")
    try:
        completed = subprocess.run(
            argv,
            cwd=repo,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_env(),
            timeout=90,
        )
    except subprocess.TimeoutExpired as exc:
        timeout = int(exc.timeout or 90)
        raise RuntimeError(f"command timed out after {timeout}s: {_command_label(argv)}") from exc
    if completed.returncode != 0 and not allow_nonzero:
        detail = _brief_error(completed.stderr)
        raise RuntimeError(detail or f"command failed: {_command_label(argv)}")
    return completed.stdout


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    pr_diff_sha256: str | None = None
    try:
        pr_diff_sha256 = _sha256_text(_run_text(repo, ["gh", "pr", "diff", str(pr)]))
    except RuntimeError:
        pr_diff_sha256 = None
    return {
        "pr": view,
        "checks": checks,
        "reviewComments": review_comments,
        "prReviews": pr_reviews,
        "repoName": name,
        "pr_diff_sha256": pr_diff_sha256,
    }


def _actor_logins(item: dict[str, Any]) -> set[str]:
    logins: set[str] = set()
    for key in ("author", "user", "actor"):
        actor = item.get(key)
        if isinstance(actor, dict):
            value = actor.get("login")
            if isinstance(value, str) and value.strip():
                logins.add(value.strip().lower())
        elif isinstance(actor, str) and actor.strip():
            logins.add(actor.strip().lower())
    return logins


def _review_state(item: dict[str, Any]) -> str:
    value = item.get("state")
    if isinstance(value, str):
        return value.strip().upper()
    return ""


def _trusted_review_items(items: list[dict[str, Any]], trusted_actors: set[str]) -> list[dict[str, Any]]:
    return [item for item in items if bool(_actor_logins(item) & trusted_actors)]


def _blocking_review_states(items: list[dict[str, Any]], trusted_actors: set[str]) -> list[str]:
    states = {state for item in _trusted_review_items(items, trusted_actors) if (state := _review_state(item)) in BLOCKING_REVIEW_STATES}
    return sorted(states)


def _has_trusted_actor(items: list[dict[str, Any]], trusted_actors: set[str]) -> bool:
    return any(_review_state(item) not in BLOCKING_REVIEW_STATES for item in _trusted_review_items(items, trusted_actors))


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
    for bucket in ("reviews", "latestReviews", "prReviews"):
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


def _load_json_file(path: Path | None, *, label: str) -> dict[str, Any] | None:
    if path is None:
        return None
    if not path.is_file():
        raise GateInputError(f"{label} file does not exist: {path}")
    size = path.stat().st_size
    if size > MAX_EVIDENCE_BYTES:
        raise GateInputError(f"{label} file exceeds {MAX_EVIDENCE_BYTES} bytes: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateInputError(f"{label} file is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise GateInputError(f"{label} must be a JSON object")
    return payload


def load_self_review(path: Path | None) -> dict[str, Any] | None:
    return _load_json_file(path, label="self-review")


def load_claude_evidence(path: Path | None) -> dict[str, Any] | None:
    return _load_json_file(path, label="Claude evidence")


def load_external_review_evidence(path: Path | None) -> dict[str, Any] | None:
    return _load_json_file(path, label="external review evidence")


def _normalize_sha256(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if len(normalized) != 64:
        return None
    if not all(char in "0123456789abcdef" for char in normalized):
        return None
    return normalized


def _valid_sha256(value: Any) -> bool:
    return _normalize_sha256(value) is not None


def _claude_ultrareview_command_matches(command: Any, pr_number: Any) -> bool:
    if not isinstance(command, list) or len(command) < 3:
        return False
    if not all(isinstance(item, str) for item in command):
        return False
    if Path(command[0]).name != "claude" or command[1] != "ultrareview":
        return False

    seen_json = False
    seen_timeout = False
    seen_pr = False
    index = 2
    while index < len(command):
        value = command[index]
        if value == "--json":
            if seen_json:
                return False
            seen_json = True
            index += 1
            continue
        if value == "--timeout":
            if seen_timeout or index + 1 >= len(command):
                return False
            timeout_value = command[index + 1]
            if timeout_value.startswith("-") or not timeout_value.isdigit():
                return False
            seen_timeout = True
            index += 2
            continue
        if value.startswith("--timeout="):
            if seen_timeout:
                return False
            timeout_value = value.split("=", 1)[1]
            if not timeout_value.isdigit():
                return False
            seen_timeout = True
            index += 1
            continue
        if value.startswith("-"):
            return False
        if seen_pr or value != str(pr_number):
            return False
        seen_pr = True
        index += 1
    return seen_pr and seen_json and seen_timeout


def _claude_cli_evidence_failures(pr: dict[str, Any], evidence: Any, *, repo_name: str | None = None) -> list[str]:
    if evidence is None:
        return []
    if not isinstance(evidence, dict):
        return ["evidence is not a JSON object"]
    failures: list[str] = []
    head = pr.get("headRefOid")
    pr_number = pr.get("number")
    schema_version = evidence.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version != 1:
        failures.append("schema_version is not integer 1")
    if evidence.get("kind") != "claude_ultrareview":
        failures.append("kind is not claude_ultrareview")
    if repo_name is not None and evidence.get("repo") != repo_name:
        failures.append("repo mismatch")
    evidence_pr = evidence.get("pr")
    if pr_number is not None and (isinstance(evidence_pr, bool) or not isinstance(evidence_pr, int) or evidence_pr != pr_number):
        failures.append("pr number mismatch")
    if not isinstance(head, str) or not head:
        failures.append("PR headRefOid is missing")
    else:
        if evidence.get("head_sha") != head:
            failures.append("head_sha mismatch")
        if evidence.get("expected_head_sha") != head:
            failures.append("expected_head_sha mismatch")
    if evidence.get("tool") != "claude-code":
        failures.append("tool is not claude-code")
    if not isinstance(evidence.get("tool_version"), str) or not evidence.get("tool_version"):
        failures.append("tool_version is missing")
    if not _claude_ultrareview_command_matches(evidence.get("command"), pr_number):
        failures.append("command is not claude ultrareview for this PR")
    if evidence.get("exit_code") != 0:
        failures.append(f"exit_code is {evidence.get('exit_code')}, not 0")
    if evidence.get("json_ok") is not True:
        failures.append("json_ok is not true")
    if evidence.get("verdict") != "PASS":
        failures.append(f"verdict is {evidence.get('verdict')}, not PASS")
    if evidence.get("finding_count") != 0:
        failures.append(f"finding_count is {evidence.get('finding_count')}, not 0")
    if evidence.get("findings_triaged") is not True:
        failures.append("findings_triaged is not true")
    for key in ("stdout_sha256", "stderr_sha256"):
        if not _valid_sha256(evidence.get(key)):
            failures.append(f"{key} is missing or invalid")
    return failures


def _material_findings_remaining(self_review: dict[str, Any], failures: list[str]) -> int | None:
    if "material_findings_remaining" not in self_review:
        failures.append("self-review material_findings_remaining is missing")
        return None
    remaining = self_review.get("material_findings_remaining")
    if isinstance(remaining, bool) or not isinstance(remaining, int):
        failures.append("self-review material_findings_remaining must be an integer")
        return None
    if remaining < 0:
        failures.append("self-review material_findings_remaining must not be negative")
        return None
    return remaining


def _terminal(item: dict[str, Any]) -> bool:
    status = item.get("status")
    if status not in TERMINAL_STATUSES:
        return False
    if status in {"accepted", "deferred_with_reason"} and not item.get("reason"):
        return False
    severity = str(item.get("severity") or "").lower()
    strong = severity in STRONG_SEVERITIES
    materiality = str(item.get("materiality") or "").lower()
    if (materiality == "blocking" or strong) and status in {"accepted", "deferred_with_reason"}:
        return False
    return True


def _valid_iteration(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    n = item.get("n")
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        return False
    summary = item.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return False
    material = item.get("material_findings")
    if isinstance(material, bool) or not isinstance(material, int) or material < 0:
        return False
    return True


def _legacy_external_finding_failures(external_review: dict[str, Any]) -> list[str]:
    findings = external_review.get("findings", [])
    if not isinstance(findings, list):
        return ["external_review.findings is not a list"]
    failures: list[str] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or not _terminal(finding):
            failures.append(f"external_review finding {index} is not terminally triaged")
    return failures


def _external_review_count(external_review: Any) -> int | None:
    if not isinstance(external_review, dict):
        return None
    reviews = external_review.get("reviews")
    if isinstance(reviews, list):
        return len(reviews)
    return None


def _external_review_failures(
    state: dict[str, Any],
    pr: dict[str, Any],
    external_review: Any,
    *,
    required: bool,
    repo_name: str | None = None,
) -> list[str]:
    if external_review is None:
        return ["external review is required but evidence is missing"] if required else []
    if not isinstance(external_review, dict):
        return ["external review evidence is not a JSON object"]

    failures: list[str] = []
    head = pr.get("headRefOid")
    pr_number = pr.get("number")

    if required and external_review.get("required") is False:
        failures.append("external_review.required=false cannot disable required external review")
    schema_version = external_review.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version != 1:
        failures.append("schema_version is not integer 1")
    if external_review.get("kind") != "external_review":
        failures.append("kind is not external_review")
    if repo_name is not None and external_review.get("repo") != repo_name:
        failures.append("repo mismatch")
    evidence_pr = external_review.get("pr")
    if pr_number is not None and (isinstance(evidence_pr, bool) or not isinstance(evidence_pr, int) or evidence_pr != pr_number):
        failures.append("pr number mismatch")
    if not isinstance(head, str) or not head:
        failures.append("PR headRefOid is missing")
    elif external_review.get("head_sha") != head:
        failures.append("head_sha mismatch")

    diff_sha256 = external_review.get("diff_sha256")
    if not _valid_sha256(diff_sha256):
        failures.append("diff_sha256 is missing or invalid")
    else:
        current_diff_sha256 = state.get("pr_diff_sha256")
        if not _valid_sha256(current_diff_sha256):
            failures.append("current PR diff hash is unavailable")
        elif _normalize_sha256(diff_sha256) != _normalize_sha256(current_diff_sha256):
            failures.append("diff_sha256 mismatch")
    if not _valid_sha256(external_review.get("prompt_sha256")):
        failures.append("prompt_sha256 is missing or invalid")
    if external_review.get("prompt_includes_diff") is not True:
        failures.append("prompt_includes_diff is not true")

    reviews = external_review.get("reviews")
    reported_external_findings = 0
    if not isinstance(reviews, list):
        failures.append("reviews is not a list")
    elif required and not reviews:
        failures.append("reviews must be non-empty when required")
    elif isinstance(reviews, list):
        for index, review in enumerate(reviews):
            if not isinstance(review, dict):
                failures.append(f"review {index} is not a JSON object")
                continue
            source = review.get("source")
            if not isinstance(source, str) or not source.strip():
                failures.append(f"review {index} source is missing")
            if not _valid_sha256(review.get("review_sha256")):
                failures.append(f"review {index} review_sha256 is missing or invalid")
            verdict = review.get("verdict")
            if verdict not in EXTERNAL_REVIEW_VERDICTS:
                failures.append(f"review {index} verdict is invalid")
            finding_count = review.get("finding_count")
            if isinstance(finding_count, bool) or not isinstance(finding_count, int) or finding_count < 0:
                failures.append(f"review {index} finding_count must be an integer >= 0")
            elif verdict == "PASS":
                reported_external_findings += finding_count
            elif verdict in {"NEEDS_CHANGE", "BLOCK"}:
                reported_external_findings += max(1, finding_count)

    if external_review.get("external_reviews_triaged") is not True:
        failures.append("external_reviews_triaged is not true")
    findings = external_review.get("findings")
    terminal_external_findings = 0
    if not isinstance(findings, list):
        failures.append("findings is not a list")
    else:
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict) or not _terminal(finding):
                failures.append(f"external_review finding {index} is not terminally triaged")
            else:
                terminal_external_findings += 1

    if isinstance(reviews, list):
        for index, review in enumerate(reviews):
            if not isinstance(review, dict):
                continue
            verdict = review.get("verdict")
            finding_count = review.get("finding_count")
            if (
                verdict in {"NEEDS_CHANGE", "BLOCK"}
                and isinstance(finding_count, int)
                and not isinstance(finding_count, bool)
                and finding_count >= 0
                and terminal_external_findings == 0
            ):
                failures.append(f"review {index} verdict is {verdict} without terminal finding coverage")
        if reported_external_findings > terminal_external_findings:
            failures.append(
                "external reviews report "
                f"{reported_external_findings} finding(s) but only "
                f"{terminal_external_findings} terminal finding(s) are recorded"
            )
    return failures


def evaluate_review_gate(
    state: dict[str, Any],
    *,
    self_review: dict[str, Any] | None = None,
    claude_evidence: dict[str, Any] | None = None,
    external_review_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pr = state.get("pr") if isinstance(state.get("pr"), dict) else {}
    if isinstance(pr, dict):
        extra_reviews = {key: state[key] for key in ("reviewComments", "prReviews") if isinstance(state.get(key), list)}
        if extra_reviews:
            pr = {**pr, **extra_reviews}
    checks = state.get("checks") if isinstance(state.get("checks"), list) else []
    all_review_items = _review_items(pr)
    items = _current_head_items(pr, all_review_items)
    codex_blocking_states = _blocking_review_states(items, TRUSTED_CODEX_ACTORS)
    claude_blocking_states = _blocking_review_states(items, TRUSTED_CLAUDE_ACTORS)
    codex_seen = _has_trusted_actor(items, TRUSTED_CODEX_ACTORS)
    claude_seen = _has_trusted_actor(items, TRUSTED_CLAUDE_ACTORS)
    repo_name = state.get("repoName") if isinstance(state.get("repoName"), str) else None
    claude_cli_failures = _claude_cli_evidence_failures(pr, claude_evidence, repo_name=repo_name)
    claude_cli_seen = claude_evidence is not None and not claude_cli_failures
    complexity = classify_complexity(pr, self_review)
    failures: list[str] = []
    warnings: list[str] = []

    if pr.get("state") == "CLOSED":
        failures.append("PR is closed")
    if pr.get("state") == "MERGED":
        failures.append("PR is already merged")
    if pr.get("isDraft") is True:
        failures.append("PR is draft")
    merge_state = pr.get("mergeStateStatus")
    if merge_state != "CLEAN":
        failures.append(f"GitHub mergeStateStatus is {merge_state}, not CLEAN")
    mergeable = pr.get("mergeable")
    if mergeable != "MERGEABLE":
        failures.append(f"GitHub mergeable is {mergeable}, not MERGEABLE")
    if codex_blocking_states:
        failures.append(f"Codex review has blocking state(s): {', '.join(codex_blocking_states)}")
    if claude_blocking_states:
        failures.append(f"Claude review has blocking state(s): {', '.join(claude_blocking_states)}")
    for failure in claude_cli_failures:
        failures.append(f"Claude CLI evidence invalid: {failure}")
    if not codex_seen and not codex_blocking_states:
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
        else:
            for index, iteration in enumerate(iterations):
                if not _valid_iteration(iteration):
                    failures.append(f"review_iteration {index} lacks required evidence")
        if self_review.get("stop_reason") not in STOP_REASONS:
            failures.append("self-review stop_reason is missing or invalid")
        findings = self_review.get("findings", [])
        if not isinstance(findings, list):
            failures.append("self-review findings is not a list")
        else:
            for index, finding in enumerate(findings):
                if not isinstance(finding, dict) or not _terminal(finding):
                    failures.append(f"finding {index} is not terminally triaged")
        remaining = _material_findings_remaining(self_review, failures)
        residual = self_review.get("residual_risk")
        accepted_residual = isinstance(residual, dict) and residual.get("accepted") is True and bool(residual.get("reason"))
        if remaining is not None and remaining > 0 and not accepted_residual:
            failures.append("material findings remain without accepted residual-risk reason")

    claude = self_review.get("claude_review") if isinstance(self_review, dict) else None
    claude_required = complexity["complex"] or (isinstance(claude, dict) and claude.get("required") is True)
    claude_not_required = isinstance(claude, dict) and claude.get("required") is False and bool(claude.get("reason"))
    if claude_required and not (claude_seen or claude_cli_seen) and not claude_blocking_states:
        failures.append("Claude review is required but not observed on current head")
    if not claude_required and not claude_not_required:
        warnings.append("Claude non-requirement reason is not recorded")

    deprecated_external_review = self_review.get("external_review") if isinstance(self_review, dict) else None
    external_review = external_review_evidence
    fallback_used = False
    if external_review is None and isinstance(deprecated_external_review, dict):
        if complexity["complex"]:
            warnings.append("Deprecated self_review.external_review ignored for complex PR; pass --external-review-evidence instead")
        elif deprecated_external_review.get("schema_version") == 1 or deprecated_external_review.get("kind") == "external_review":
            external_review = deprecated_external_review
            fallback_used = True
        elif deprecated_external_review.get("required") is False:
            for failure in _legacy_external_finding_failures(deprecated_external_review):
                failures.append(f"External review evidence invalid: {failure}")
    if fallback_used:
        warnings.append("Deprecated self_review.external_review fallback used; pass --external-review-evidence instead")

    external_required = complexity["complex"] or (isinstance(external_review, dict) and external_review.get("required") is True)
    for failure in _external_review_failures(state, pr, external_review, required=external_required, repo_name=repo_name):
        failures.append(f"External review evidence invalid: {failure}")

    if not checks:
        failures.append("no status checks observed")
    observed_expected_checks = {
        check.get("name")
        for check in checks
        if isinstance(check, dict) and check.get("name") in EXPECTED_CHECK_NAMES
    }
    missing_expected_checks = [name for name in EXPECTED_CHECK_NAMES if name not in observed_expected_checks]
    if missing_expected_checks:
        failures.append(f"expected check(s) missing: {', '.join(missing_expected_checks)}")
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
        "review_sources": {
            "codex_seen": codex_seen,
            "claude_seen": claude_seen,
            "claude_cli_seen": claude_cli_seen,
            "external_review_required": external_required,
            "external_reviews_received": _external_review_count(external_review),
            "review_item_count": len(all_review_items),
            "current_head_review_item_count": len(items),
        },
        "complexity": complexity,
    }


def resolve_inside_repo(repo: Path, raw: str | None, *, label: str = "self-review") -> Path | None:
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = repo / candidate
    resolved = candidate.resolve()
    root = repo.resolve()
    if resolved != root and root not in resolved.parents:
        raise GateInputError(f"{label} path must stay inside repo")
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--self-review")
    parser.add_argument("--claude-evidence")
    parser.add_argument("--external-review-evidence")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    try:
        self_review = load_self_review(resolve_inside_repo(repo, args.self_review, label="self-review"))
        claude_evidence = load_claude_evidence(resolve_inside_repo(repo, args.claude_evidence, label="Claude evidence"))
        external_review_evidence = load_external_review_evidence(resolve_inside_repo(repo, args.external_review_evidence, label="external review evidence"))
        result = evaluate_review_gate(
            load_pr_state(repo, args.pr),
            self_review=self_review,
            claude_evidence=claude_evidence,
            external_review_evidence=external_review_evidence,
        )
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
