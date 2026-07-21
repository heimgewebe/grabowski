#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

try:
    import pr_review_gate as gate
except ModuleNotFoundError:  # importlib-based tests load this file from the repo root
    from tools import pr_review_gate as gate


SCHEMA_VERSION = 1
AUDIT_KIND = "grabowski_self_review_audit"
STATUS_KIND = "grabowski_review_gate_status"
RESULT_KIND = "grabowski_review_gate_ci_result"
STATUS_CONTEXT = "Review evidence gate"
COMMENT_PREFIX = "/grabowski-review-evidence v1"
MAX_AUDIT_BYTES = 64 * 1024
MAX_STATUS_BYTES = 16 * 1024
MAX_STATUS_B64_BYTES = 32 * 1024
ALLOWED_WRITE_PERMISSIONS = frozenset({"admin", "maintain", "write", "push"})
REVIEW_TIER_RANK = {
    "documentation": 1,
    "very_small": 1,
    "standard": 2,
    "important_repo": 3,
    "high_critical": 4,
}
STATUS_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "repo",
        "pr",
        "head_sha",
        "diff_sha256",
        "audit_sha256",
        "gate_verdict",
        "self_review_gate_valid",
        "all_findings_triaged",
        "material_findings_remaining",
        "minimum_review_iterations",
        "actual_review_iterations",
        "review_tier",
        "tuning_signal",
    }
)
COMMENT_RE = re.compile(
    rf"\A{re.escape(COMMENT_PREFIX)}(?:\s+(?P<payload>[A-Za-z0-9+/=]+))?\s*\Z"
)
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CiEvidenceError(ValueError):
    pass


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _normalize_repo(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if REPO_RE.fullmatch(normalized) else None


def _normalize_git_sha(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if GIT_SHA_RE.fullmatch(normalized) else None


def _normalize_sha256(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if SHA256_RE.fullmatch(normalized) else None


def _required_audit_failures(audit: Any) -> list[str]:
    if not isinstance(audit, dict):
        return ["audit must be a JSON object"]

    failures: list[str] = []
    if audit.get("schema_version") != 1 or isinstance(audit.get("schema_version"), bool):
        failures.append("audit schema_version must be integer 1")
    if audit.get("kind") != AUDIT_KIND:
        failures.append(f"audit kind must be {AUDIT_KIND}")
    if _normalize_repo(audit.get("repo")) is None:
        failures.append("audit repo is invalid")
    if not _is_int(audit.get("pr")) or audit["pr"] <= 0:
        failures.append("audit pr must be a positive integer")
    if _normalize_git_sha(audit.get("head_sha")) is None:
        failures.append("audit head_sha is invalid")
    if _normalize_sha256(audit.get("diff_sha256")) is None:
        failures.append("audit diff_sha256 is invalid")
    if audit.get("gate_verdict") not in {"PASS", "BLOCK"}:
        failures.append("audit gate_verdict is invalid")
    if not isinstance(audit.get("self_review_gate_valid"), bool):
        failures.append("audit self_review_gate_valid must be boolean")
    if not isinstance(audit.get("all_findings_triaged"), bool):
        failures.append("audit all_findings_triaged must be boolean")
    if not _is_int(audit.get("material_findings_remaining")) or audit["material_findings_remaining"] < 0:
        failures.append("audit material_findings_remaining must be an integer >= 0")
    for field in ("minimum_review_iterations", "actual_review_iterations"):
        value = audit.get(field)
        if not _is_int(value) or value < 0:
            failures.append(f"audit {field} must be an integer >= 0")
    if audit.get("review_tier") not in REVIEW_TIER_RANK:
        failures.append("audit review_tier is invalid")
    if audit.get("tuning_signal") not in {"observe", "increase_depth", "repair_evidence"}:
        failures.append("audit tuning_signal is invalid")
    return failures


def build_status_projection(audit_bytes: bytes) -> dict[str, Any]:
    if len(audit_bytes) > MAX_AUDIT_BYTES:
        raise CiEvidenceError(f"audit exceeds {MAX_AUDIT_BYTES} bytes")
    try:
        audit = json.loads(audit_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CiEvidenceError("audit is not valid UTF-8 JSON") from exc

    failures = _required_audit_failures(audit)
    if failures:
        raise CiEvidenceError("; ".join(failures))

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": STATUS_KIND,
        "repo": _normalize_repo(audit["repo"]),
        "pr": audit["pr"],
        "head_sha": _normalize_git_sha(audit["head_sha"]),
        "diff_sha256": _normalize_sha256(audit["diff_sha256"]),
        "audit_sha256": hashlib.sha256(audit_bytes).hexdigest(),
        "gate_verdict": audit["gate_verdict"],
        "self_review_gate_valid": audit["self_review_gate_valid"],
        "all_findings_triaged": audit["all_findings_triaged"],
        "material_findings_remaining": audit["material_findings_remaining"],
        "minimum_review_iterations": audit["minimum_review_iterations"],
        "actual_review_iterations": audit["actual_review_iterations"],
        "review_tier": audit["review_tier"],
        "tuning_signal": audit["tuning_signal"],
    }


def canonical_status_bytes(status: dict[str, Any]) -> bytes:
    return (json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def encode_status_projection(status: dict[str, Any]) -> str:
    return base64.b64encode(canonical_status_bytes(status)).decode("ascii")


def _status_schema_failures(status: Any) -> list[str]:
    if not isinstance(status, dict):
        return ["status evidence must be a JSON object"]

    failures: list[str] = []
    keys = set(status)
    missing = sorted(STATUS_FIELDS - keys)
    unknown = sorted(keys - STATUS_FIELDS)
    if missing:
        failures.append("status evidence missing field(s): " + ", ".join(missing))
    if unknown:
        failures.append("status evidence has unknown field(s): " + ", ".join(unknown))
    if status.get("schema_version") != 1 or isinstance(status.get("schema_version"), bool):
        failures.append("status evidence schema_version must be integer 1")
    if status.get("kind") != STATUS_KIND:
        failures.append(f"status evidence kind must be {STATUS_KIND}")
    if _normalize_repo(status.get("repo")) is None:
        failures.append("status evidence repo is invalid")
    if not _is_int(status.get("pr")) or status.get("pr", 0) <= 0:
        failures.append("status evidence pr must be a positive integer")
    if _normalize_git_sha(status.get("head_sha")) is None:
        failures.append("status evidence head_sha is invalid")
    for field in ("diff_sha256", "audit_sha256"):
        if _normalize_sha256(status.get(field)) is None:
            failures.append(f"status evidence {field} is invalid")
    if status.get("gate_verdict") not in {"PASS", "BLOCK"}:
        failures.append("status evidence gate_verdict is invalid")
    if not isinstance(status.get("self_review_gate_valid"), bool):
        failures.append("status evidence self_review_gate_valid must be boolean")
    if not isinstance(status.get("all_findings_triaged"), bool):
        failures.append("status evidence all_findings_triaged must be boolean")
    if not _is_int(status.get("material_findings_remaining")) or status.get("material_findings_remaining", -1) < 0:
        failures.append("status evidence material_findings_remaining must be an integer >= 0")
    for field in ("minimum_review_iterations", "actual_review_iterations"):
        value = status.get(field)
        if not _is_int(value) or value < 0:
            failures.append(f"status evidence {field} must be an integer >= 0")
    if status.get("review_tier") not in REVIEW_TIER_RANK:
        failures.append("status evidence review_tier is invalid")
    if status.get("tuning_signal") not in {"observe", "increase_depth", "repair_evidence"}:
        failures.append("status evidence tuning_signal is invalid")
    return failures


def decode_status_projection(raw: str) -> dict[str, Any]:
    normalized = raw.strip()
    if not normalized:
        raise CiEvidenceError("status evidence is missing")
    if len(normalized.encode("ascii", errors="ignore")) > MAX_STATUS_B64_BYTES:
        raise CiEvidenceError(f"status evidence exceeds {MAX_STATUS_B64_BYTES} base64 bytes")
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CiEvidenceError("status evidence is not valid base64") from exc
    if len(decoded) > MAX_STATUS_BYTES:
        raise CiEvidenceError(f"decoded status evidence exceeds {MAX_STATUS_BYTES} bytes")
    try:
        status = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CiEvidenceError("status evidence is not valid UTF-8 JSON") from exc
    failures = _status_schema_failures(status)
    if failures:
        raise CiEvidenceError("; ".join(failures))
    return status


def parse_comment_status(body: str) -> dict[str, Any]:
    match = COMMENT_RE.fullmatch(body.strip())
    if match is None:
        raise CiEvidenceError("review evidence comment command is malformed")
    payload = match.group("payload")
    if not payload:
        raise CiEvidenceError("status evidence is missing")
    return decode_status_projection(payload)


def permission_allows_publish(permission: Any) -> bool:
    return isinstance(permission, str) and permission.strip().lower() in ALLOWED_WRITE_PERMISSIONS


def _comment_identity(comment: Any) -> tuple[int, str, str] | None:
    if not isinstance(comment, dict):
        return None
    body = comment.get("body")
    comment_id = comment.get("id", comment.get("databaseId"))
    user = comment.get("user", comment.get("author"))
    actor = user.get("login") if isinstance(user, dict) else None
    if (
        not isinstance(body, str)
        or not _is_int(comment_id)
        or not isinstance(actor, str)
        or not actor
    ):
        return None
    return comment_id, actor, body


def select_latest_authorized_command_comment_id(
    comments: list[Any],
    *,
    permission_lookup,
) -> int | None:
    candidates: list[tuple[int, str]] = []
    for comment in comments:
        identity = _comment_identity(comment)
        if identity is None:
            continue
        comment_id, actor, body = identity
        if not body.lstrip().startswith("/grabowski-review-evidence"):
            continue
        candidates.append((comment_id, actor))

    for comment_id, actor in reversed(candidates):
        if permission_allows_publish(permission_lookup(actor)):
            return comment_id
    return None


def command_comment_is_current_and_latest_authorized(
    comments: list[Any],
    *,
    current_comment_id: int,
    current_comment_body: str,
    permission_lookup,
) -> bool:
    current_body: str | None = None
    for comment in comments:
        identity = _comment_identity(comment)
        if identity is None:
            continue
        comment_id, _actor, body = identity
        if comment_id == current_comment_id:
            current_body = body
            break
    if current_body is None or current_body != current_comment_body:
        return False
    return (
        select_latest_authorized_command_comment_id(
            comments, permission_lookup=permission_lookup
        )
        == current_comment_id
    )


def evaluate_status_projection(
    status: dict[str, Any],
    *,
    repo_name: str,
    pr: dict[str, Any],
    diff_sha256: str,
    complexity: dict[str, Any],
) -> list[str]:
    failures = _status_schema_failures(status)
    if failures:
        return failures

    current_repo = _normalize_repo(repo_name)
    current_head = _normalize_git_sha(pr.get("headRefOid"))
    current_diff = _normalize_sha256(diff_sha256)
    if pr.get("state") != "OPEN":
        failures.append("PR is not open")
    if pr.get("isDraft") is True:
        failures.append("PR is draft")
    if _normalize_repo(status.get("repo")) != current_repo:
        failures.append("status evidence repo mismatch")
    if status.get("pr") != pr.get("number"):
        failures.append("status evidence PR number mismatch")
    if _normalize_git_sha(status.get("head_sha")) != current_head:
        failures.append("status evidence head_sha mismatch")
    if _normalize_sha256(status.get("diff_sha256")) != current_diff:
        failures.append("status evidence diff_sha256 mismatch")
    if status.get("gate_verdict") != "PASS":
        failures.append("status evidence gate_verdict is not PASS")
    if status.get("self_review_gate_valid") is not True:
        failures.append("status evidence self_review_gate_valid is not true")
    if status.get("all_findings_triaged") is not True:
        failures.append("status evidence all_findings_triaged is not true")
    if status.get("material_findings_remaining") != 0:
        failures.append("status evidence has material findings remaining")
    if status.get("actual_review_iterations", -1) < status.get("minimum_review_iterations", 0):
        failures.append("status evidence review depth is insufficient")

    current_minimum = complexity.get("minimum_self_review_iterations")
    if not _is_int(current_minimum) or current_minimum < 0:
        failures.append("current PR review depth could not be derived")
    elif status.get("minimum_review_iterations", -1) < current_minimum:
        failures.append("status evidence minimum review depth is stale or too weak")

    current_tier = complexity.get("review_tier")
    status_tier = status.get("review_tier")
    if current_tier not in REVIEW_TIER_RANK:
        failures.append("current PR review tier could not be derived")
    elif REVIEW_TIER_RANK.get(status_tier, 0) < REVIEW_TIER_RANK[current_tier]:
        failures.append("status evidence review tier is stale or too weak")
    if status.get("tuning_signal") != "observe":
        failures.append("status evidence tuning_signal is not observe")
    return failures


def _run_json(argv: list[str], *, stdin: bytes | None = None) -> Any:
    result = subprocess.run(
        argv,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CiEvidenceError(f"command failed: {' '.join(argv[:3])}: {detail[:500]}")
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise CiEvidenceError(f"command returned invalid JSON: {' '.join(argv[:3])}") from exc


def _run_bytes(argv: list[str]) -> bytes:
    result = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CiEvidenceError(f"command failed: {' '.join(argv[:3])}: {detail[:500]}")
    return result.stdout


def load_live_pr(repo_name: str, pr_number: int) -> dict[str, Any]:
    return _run_json(
        [
            "gh",
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo_name,
            "--json",
            "number,state,isDraft,headRefOid,baseRefOid,changedFiles,additions,deletions,files,url,title",
        ]
    )


def current_diff_sha256(repo_name: str, pr_number: int) -> str:
    diff = _run_bytes(["gh", "pr", "diff", str(pr_number), "--repo", repo_name])
    return hashlib.sha256(diff).hexdigest()


def collaborator_permission(repo_name: str, actor: str) -> str | None:
    payload = _run_json(
        ["gh", "api", f"repos/{repo_name}/collaborators/{actor}/permission"]
    )
    permission = payload.get("permission") if isinstance(payload, dict) else None
    return permission if isinstance(permission, str) else None


def current_comment_is_latest_authorized(
    repo_name: str,
    pr_number: int,
    *,
    comment_id: int,
    comment_body: str,
) -> bool:
    owner, name = repo_name.split("/", 1)
    query = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      comments(last: 100) {
        nodes { databaseId body author { login } }
      }
    }
  }
}
""".strip()
    payload = _run_json(
        [
            "gh",
            "api",
            "graphql",
            "-f",
            f"query={query}",
            "-F",
            f"owner={owner}",
            "-F",
            f"name={name}",
            "-F",
            f"number={pr_number}",
        ]
    )
    try:
        comments = payload["data"]["repository"]["pullRequest"]["comments"]["nodes"]
    except (KeyError, TypeError) as exc:
        raise CiEvidenceError("current PR comment window could not be read") from exc
    if not isinstance(comments, list):
        raise CiEvidenceError("current PR comment window is invalid")
    return command_comment_is_current_and_latest_authorized(
        comments,
        current_comment_id=comment_id,
        current_comment_body=comment_body,
        permission_lookup=lambda actor: collaborator_permission(repo_name, actor),
    )


def publish_commit_status(
    *,
    repo_name: str,
    head_sha: str,
    passed: bool,
    failure_count: int,
) -> None:
    target_url = None
    server_url = os.environ.get("GITHUB_SERVER_URL")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server_url and run_id:
        target_url = f"{server_url.rstrip('/')}/{repo_name}/actions/runs/{run_id}"
    payload: dict[str, Any] = {
        "state": "success" if passed else "failure",
        "context": STATUS_CONTEXT,
        "description": (
            "Current head/diff-bound review evidence passed"
            if passed
            else f"Review evidence blocked ({failure_count} validation failure(s))"
        ),
    }
    if target_url:
        payload["target_url"] = target_url
    _run_json(
        [
            "gh",
            "api",
            "--method",
            "POST",
            f"repos/{repo_name}/statuses/{head_sha}",
            "--input",
            "-",
        ],
        stdin=json.dumps(payload, sort_keys=True).encode("utf-8"),
    )


def _safe_result(
    *,
    repo_name: str,
    pr_number: int,
    pr: dict[str, Any] | None,
    diff_sha256: str | None,
    failures: list[str],
    status: dict[str, Any] | None,
    complexity: dict[str, Any] | None,
    authorized: bool,
    permission: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "repo": repo_name,
        "pr": pr_number,
        "head_sha": _normalize_git_sha(pr.get("headRefOid")) if isinstance(pr, dict) else None,
        "diff_sha256": _normalize_sha256(diff_sha256),
        "audit_sha256": _normalize_sha256(status.get("audit_sha256")) if isinstance(status, dict) else None,
        "review_tier": complexity.get("review_tier") if isinstance(complexity, dict) else None,
        "minimum_review_iterations": (
            complexity.get("minimum_self_review_iterations") if isinstance(complexity, dict) else None
        ),
        "authorized": authorized,
        "actor_permission": permission,
        "verdict": "PASS" if authorized and not failures else "BLOCK",
        "failures": failures,
        "private_evidence_included": False,
    }


def prepare_command(args: argparse.Namespace) -> int:
    audit_path = Path(args.audit)
    audit_bytes = audit_path.read_bytes()
    status = build_status_projection(audit_bytes)
    rendered = json.dumps(status, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with output.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
        except FileExistsError as exc:
            raise CiEvidenceError(f"status projection already exists: {output}") from exc
    if args.comment:
        print(f"{COMMENT_PREFIX} {encode_status_projection(status)}")
    elif args.base64:
        print(encode_status_projection(status))
    else:
        print(rendered, end="")
    return 0


def evaluate_comment_command(args: argparse.Namespace) -> int:
    repo_name = _normalize_repo(args.repo_name or os.environ.get("GITHUB_REPOSITORY"))
    if repo_name is None:
        raise CiEvidenceError("repository identity is missing or invalid")
    actor = args.actor or os.environ.get("GITHUB_ACTOR") or ""
    permission = collaborator_permission(repo_name, actor)
    authorized = permission_allows_publish(permission)
    if not authorized:
        result = _safe_result(
            repo_name=repo_name,
            pr_number=args.pr,
            pr=None,
            diff_sha256=None,
            failures=["actor is not authorized to publish review evidence status"],
            status=None,
            complexity=None,
            authorized=False,
            permission=permission,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    comment_body = os.environ.get(args.comment_body_env, "")
    if args.comment_id is not None and not current_comment_is_latest_authorized(
        repo_name,
        args.pr,
        comment_id=args.comment_id,
        comment_body=comment_body,
    ):
        result = _safe_result(
            repo_name=repo_name,
            pr_number=args.pr,
            pr=None,
            diff_sha256=None,
            failures=["comment is stale, edited, superseded, or outside the bounded authorization window"],
            status=None,
            complexity=None,
            authorized=True,
            permission=permission,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    pr = load_live_pr(repo_name, args.pr)
    diff_sha256 = current_diff_sha256(repo_name, args.pr)
    complexity = gate.classify_complexity(pr, None, repo_name=repo_name)
    failures: list[str] = []
    status: dict[str, Any] | None = None
    try:
        status = parse_comment_status(comment_body)
    except CiEvidenceError as exc:
        failures.append(str(exc))
    if status is not None:
        failures.extend(
            evaluate_status_projection(
                status,
                repo_name=repo_name,
                pr=pr,
                diff_sha256=diff_sha256,
                complexity=complexity,
            )
        )

    head_sha = _normalize_git_sha(pr.get("headRefOid"))
    if head_sha is None:
        failures.append("current PR head_sha is missing or invalid")
    if args.publish_status and head_sha is not None:
        publish_commit_status(
            repo_name=repo_name,
            head_sha=head_sha,
            passed=not failures,
            failure_count=len(failures),
        )

    result = _safe_result(
        repo_name=repo_name,
        pr_number=args.pr,
        pr=pr,
        diff_sha256=diff_sha256,
        failures=failures,
        status=status,
        complexity=complexity,
        authorized=True,
        permission=permission,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--audit", required=True)
    prepare.add_argument("--output")
    prepare.add_argument("--base64", action="store_true")
    prepare.add_argument("--comment", action="store_true")
    prepare.set_defaults(handler=prepare_command)

    evaluate = subparsers.add_parser("evaluate-comment")
    evaluate.add_argument("--pr", type=int, required=True)
    evaluate.add_argument("--repo-name")
    evaluate.add_argument("--actor")
    evaluate.add_argument("--comment-id", type=int)
    evaluate.add_argument("--comment-body-env", default="REVIEW_GATE_COMMENT_BODY")
    evaluate.add_argument("--publish-status", action="store_true")
    evaluate.set_defaults(handler=evaluate_comment_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (CiEvidenceError, OSError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": RESULT_KIND,
                    "verdict": "BLOCK",
                    "failures": [str(exc)],
                    "private_evidence_included": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
