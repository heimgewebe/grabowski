#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

import pr_review_gate


SCHEMA_VERSION = 1
EVIDENCE_KIND = "github_codex_review_settlement"
REQUEST_KIND = "grabowski_codex_review_request"
STATUS_CONTEXT = "Codex review settled"
MAX_ITEMS = 100
MAX_COMMENT_PAGES = 10
MAX_COMMENT_ITEMS = MAX_ITEMS * MAX_COMMENT_PAGES
TRUSTED_CODEX_ACTORS = frozenset(
    {"chatgpt-codex-connector", "chatgpt-codex-connector[bot]"}
)
TRUSTED_REQUEST_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
TRUSTED_REQUEST_ACTORS = frozenset(
    {"alexdermohr", "github-actions", "github-actions[bot]"}
)
ACCEPTED_REVIEW_STATES = frozenset({"APPROVED", "COMMENTED"})
BLOCKING_REVIEW_STATES = frozenset({"CHANGES_REQUESTED", "PENDING"})
REQUEST_RE = re.compile(
    r"<!--\s*grabowski-codex-review-request:v1\s*(\{.*?\})\s*-->",
    re.DOTALL,
)
_CODEX_CLEAN_FOOTER_PATTERN = (
    r"<details> <summary>ℹ️ About Codex in GitHub</summary>\n"
    r"<br/>\n\n"
    r"\[Your team has set up Codex to review pull requests in this repo\]"
    r"\(https://chatgpt\.com/codex/cloud/settings/general\)\. "
    r"Reviews are triggered when you\n"
    r"- Open a pull request for review\n"
    r"- Mark a draft as ready\n"
    r'- Comment "@codex review"\.\n\n'
    r"If Codex has suggestions, it will comment; otherwise it will react with 👍\."
    r"\n{2,6}"
    r"Codex can also answer questions or update the PR\. Try commenting "
    r'"@codex address that feedback"\.\n\n'
    r"</details>"
)
CLEAN_RESULT_RE = re.compile(
    r"\ACodex Review: Didn't find any major issues\. "
    r"(?:[^\n]{0,79}[.!?]|[^\n]{0,62}:[a-z0-9_+-]{1,16}:)\n\n"
    r"\*\*Reviewed commit:\*\* `([0-9a-f]{10,40})`\n\n"
    + _CODEX_CLEAN_FOOTER_PATTERN
    + r"\Z"
)
PROVIDER_UNAVAILABLE_BODIES = {
    "quota_exhausted": (
        (
            "You have reached your Codex usage limits for code reviews. "
            "You can see your limits in the "
            "[Codex usage dashboard](https://chatgpt.com/codex/cloud/settings/usage).\n"
            "To continue using code reviews, you can upgrade your account or add "
            "credits to your account and enable them for code reviews in your "
            "[settings](https://chatgpt.com/codex/cloud/settings/code-review)."
        ),
        (
            "You have reached your Codex usage limits for code reviews. "
            "You can see your limits in the "
            "[Codex usage dashboard](https://chatgpt.com/codex/cloud/settings/usage).\n\n"
            "To continue using code reviews, you can upgrade your account or add "
            "credits to your account and enable them for code reviews in your "
            "[settings](https://chatgpt.com/codex/cloud/settings/code-review)."
        ),
        (
            "You have reached your Codex usage limits for code reviews. "
            "You can see your limits in the "
            "[Codex usage dashboard](https://chatgpt.com/codex/usage).\n\n"
            "To continue using code reviews, you can upgrade your account or add "
            "credits to your account and enable them for code reviews in your "
            "[settings](https://chatgpt.com/codex/settings)."
        ),
    ),
    "account_not_connected": (
        "To use Codex here, [create a Codex account and connect to github]"
        "(https://chatgpt.com/codex/cloud/settings/connectors).",
    ),
    "repository_environment_missing": (
        "To use Codex here, [create an environment for this repo]"
        "(https://chatgpt.com/codex/cloud/settings/environments).",
    ),
}

SETTLEMENT_STATUS_CONTRACT = {
    "review_settled": {
        "status": "pass",
        "exit_code": 0,
        "github_state": "success",
        "description": "Current-head Codex review settled",
    },
    "optional_provider_unavailable": {
        "status": "pass",
        "exit_code": 0,
        "github_state": "success",
        "description": "Optional Codex review unavailable; merge gate unaffected",
    },
    "optional_not_requested": {
        "status": "pass",
        "exit_code": 0,
        "github_state": "success",
        "description": "Optional Codex review not requested",
    },
    "optional_review_pending": {
        "status": "pass",
        "exit_code": 0,
        "github_state": "success",
        "description": "Optional Codex review pending; merge gate unaffected",
    },
    "optional_review_findings": {
        "status": "block",
        "exit_code": 2,
        "github_state": "failure",
        "description": "Existing Codex findings require settlement before merge",
    },
    "required_request_missing": {
        "status": "pending",
        "exit_code": 3,
        "github_state": "pending",
        "description": "Current-head Codex review request required",
    },
    "required_review_pending": {
        "status": "pending",
        "exit_code": 3,
        "github_state": "pending",
        "description": "Required current-head Codex review is pending",
    },
    "required_provider_unavailable": {
        "status": "pending",
        "exit_code": 3,
        "github_state": "pending",
        "description": "Required Codex review is unavailable",
    },
    "visibility_blocked": {
        "status": "block",
        "exit_code": 2,
        "github_state": "failure",
        "description": "Codex review visibility is incomplete",
    },
    "required_review_blocked": {
        "status": "block",
        "exit_code": 2,
        "github_state": "failure",
        "description": "Required Codex review remains blocked",
    },
    "evaluator_exception": {
        "status": "block",
        "exit_code": 2,
        "github_state": "failure",
        "description": "Trusted Codex settlement evaluator failed",
    },
}


def _settlement_status_contract(status: str, status_code: str) -> dict[str, Any]:
    contract = SETTLEMENT_STATUS_CONTRACT.get(status_code)
    if contract is None or contract.get("status") != status:
        raise SettlementError(
            f"settlement status contract mismatch: status={status!r}, "
            f"status_code={status_code!r}"
        )
    return dict(contract)


GRAPHQL_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      number
      state
      isDraft
      headRefOid
      baseRefOid
      changedFiles
      additions
      deletions
      files(first: 100) {
        nodes { path }
        pageInfo { hasNextPage }
      }
      comments(last: 100) {
        nodes {
          databaseId
          body
          createdAt
          updatedAt
          url
          authorAssociation
          author { login }
          reactions(first: 100) {
            nodes { content createdAt user { login } }
            pageInfo { hasNextPage }
          }
        }
        pageInfo { hasPreviousPage startCursor }
      }
      reviews(last: 100) {
        nodes {
          databaseId
          state
          body
          submittedAt
          url
          author { login }
          commit { oid }
        }
        pageInfo { hasPreviousPage }
      }
      reviewThreads(first: 100) {
        nodes {
          id
          isResolved
          comments(first: 100) {
            nodes {
              databaseId
              createdAt
              author { login }
              commit { oid }
              pullRequestReview { databaseId }
            }
            pageInfo { hasNextPage }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  }
}
""".strip()


COMMENTS_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $before: String!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      comments(last: 100, before: $before) {
        nodes {
          databaseId
          body
          createdAt
          updatedAt
          url
          authorAssociation
          author { login }
          reactions(first: 100) {
            nodes { content createdAt user { login } }
            pageInfo { hasNextPage }
          }
        }
        pageInfo { hasPreviousPage startCursor }
      }
    }
  }
}
""".strip()


class SettlementError(RuntimeError):
    pass


def _normalize_codex_comment_body(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.split("\n")).rstrip("\n")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_repo(value: str) -> tuple[str, str, str]:
    if not isinstance(value, str):
        raise SettlementError("repository must be owner/name text")
    text = value.strip().lower()
    match = re.fullmatch(r"([a-z0-9_.-]+)/([a-z0-9_.-]+)", text)
    if match is None:
        raise SettlementError("repository must have owner/name form")
    return text, match.group(1), match.group(2)


def _actor_login(value: Any) -> str:
    if isinstance(value, dict):
        login = value.get("login")
        if isinstance(login, str):
            return login.strip().lower()
    if isinstance(value, str):
        return value.strip().lower()
    return ""


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _run(repo: Path, argv: list[str], *, input_text: str | None = None) -> str:
    if not argv or shutil.which(argv[0]) is None:
        raise SettlementError(f"required executable is unavailable: {argv[0] if argv else '<empty>'}")
    completed = subprocess.run(
        argv,
        cwd=repo,
        input=input_text,
        stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=90,
        env=pr_review_gate._env(),
    )
    if completed.returncode != 0:
        detail = " ".join(completed.stderr.split())
        raise SettlementError(detail[:500] or f"command failed: {' '.join(argv[:4])}")
    return completed.stdout


def _run_json(repo: Path, argv: list[str]) -> Any:
    text = _run(repo, argv)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SettlementError("command returned invalid JSON") from exc


def _collect_comments(
    repo: Path, owner: str, name: str, pr_number: int, initial: Any
) -> dict[str, Any]:
    if not isinstance(initial, dict):
        raise SettlementError("comments connection is missing")
    nodes = _list_nodes(initial, label="comments")
    page = initial.get("pageInfo")
    if not isinstance(page, dict):
        raise SettlementError("comments pageInfo is missing")
    pages = 1
    cursors: set[str] = set()
    seen_ids: set[int] = set()

    def remember(items: list[dict[str, Any]]) -> None:
        for item in items:
            comment_id = item.get("databaseId")
            if isinstance(comment_id, bool) or not isinstance(comment_id, int):
                raise SettlementError("comment databaseId is missing or invalid")
            if comment_id in seen_ids:
                raise SettlementError("comment pagination returned duplicate identities")
            seen_ids.add(comment_id)

    remember(nodes)
    while page.get("hasPreviousPage") is True:
        if pages >= MAX_COMMENT_PAGES:
            raise SettlementError(f"comments exceed the bounded {MAX_COMMENT_ITEMS}-item history")
        before = page.get("startCursor")
        if not isinstance(before, str) or not before or before in cursors:
            raise SettlementError("comments pagination cursor is missing or repeated")
        cursors.add(before)
        payload = _run_json(repo, ["gh","api","graphql","-f",f"query={COMMENTS_QUERY}","-F",f"owner={owner}","-F",f"name={name}","-F",f"number={pr_number}","-f",f"before={before}"])
        try:
            connection = payload["data"]["repository"]["pullRequest"]["comments"]
        except (KeyError, TypeError) as exc:
            raise SettlementError("GitHub GraphQL response lacks comment history") from exc
        if not isinstance(connection, dict):
            raise SettlementError("pull-request comments do not exist")
        older = _list_nodes(connection, label="comments")
        remember(older)
        nodes = [*older, *nodes]
        if len(nodes) > MAX_COMMENT_ITEMS:
            raise SettlementError(f"comments exceed the bounded {MAX_COMMENT_ITEMS}-item history")
        page = connection.get("pageInfo")
        if not isinstance(page, dict):
            raise SettlementError("comments pageInfo is missing")
        pages += 1
    if page.get("hasPreviousPage") is not False:
        raise SettlementError("comments pagination state is invalid")
    return {"nodes": nodes, "pageInfo": {"hasPreviousPage": False, "pages_loaded": pages}}


def _live_state(repo: Path, repository: str, pr_number: int) -> dict[str, Any]:
    _, owner, name = _normalize_repo(repository)
    payload = _run_json(
        repo,
        [
            "gh",
            "api",
            "graphql",
            "-f",
            f"query={GRAPHQL_QUERY}",
            "-F",
            f"owner={owner}",
            "-F",
            f"name={name}",
            "-F",
            f"number={pr_number}",
        ],
    )
    try:
        pull_request = payload["data"]["repository"]["pullRequest"]
    except (KeyError, TypeError) as exc:
        raise SettlementError("GitHub GraphQL response lacks pull-request state") from exc
    if not isinstance(pull_request, dict):
        raise SettlementError("pull request does not exist")
    pull_request = dict(pull_request)
    pull_request["comments"] = _collect_comments(repo, owner, name, pr_number, pull_request.get("comments"))
    diff_bytes = subprocess.run(
        ["gh", "pr", "diff", str(pr_number), "--repo", repository],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=90,
        env=pr_review_gate._env(),
    )
    if diff_bytes.returncode != 0:
        detail = diff_bytes.stderr.decode("utf-8", errors="replace")
        raise SettlementError("cannot read current PR diff: " + " ".join(detail.split())[:400])
    if not diff_bytes.stdout:
        raise SettlementError("current PR diff is empty")
    pull_request["diff_sha256"] = hashlib.sha256(diff_bytes.stdout).hexdigest()
    return pull_request


def _list_nodes(container: Any, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(container, dict):
        raise SettlementError(f"{label} connection is missing")
    nodes = container.get("nodes")
    if not isinstance(nodes, list) or not all(isinstance(item, dict) for item in nodes):
        raise SettlementError(f"{label} nodes are malformed")
    return [dict(item) for item in nodes]


def _truncation_errors(pr: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key, page_flag in (
        ("files", "hasNextPage"),
        ("comments", "hasPreviousPage"),
        ("reviews", "hasPreviousPage"),
        ("reviewThreads", "hasNextPage"),
    ):
        connection = pr.get(key)
        page = connection.get("pageInfo") if isinstance(connection, dict) else None
        if not isinstance(page, dict) or page.get(page_flag) is not False:
            errors.append(f"{key} exceeds or lacks the bounded {MAX_ITEMS}-item window")
    for thread in _list_nodes(pr.get("reviewThreads"), label="reviewThreads"):
        comments = thread.get("comments")
        page = comments.get("pageInfo") if isinstance(comments, dict) else None
        if not isinstance(page, dict) or page.get("hasNextPage") is not False:
            errors.append(f"review thread {thread.get('id')} exceeds the bounded comment window")
    for comment in _list_nodes(pr.get("comments"), label="comments"):
        reactions = comment.get("reactions")
        page = reactions.get("pageInfo") if isinstance(reactions, dict) else None
        if not isinstance(page, dict) or page.get("hasNextPage") is not False:
            errors.append(f"request comment {comment.get('databaseId')} exceeds the bounded reaction window")
    return errors


def _request_payload(repository: str, pr_number: int, head_sha: str, diff_sha256: str) -> dict[str, Any]:
    core = {
        "schema_version": SCHEMA_VERSION,
        "kind": REQUEST_KIND,
        "repo": repository,
        "pr": pr_number,
        "head_sha": head_sha,
        "diff_sha256": diff_sha256,
    }
    return {**core, "request_id": _sha256_json(core)[:32]}


def _request_body(payload: dict[str, Any]) -> str:
    return (
        "@codex review\n\n"
        "Please review the exact current pull-request head. Grabowski will accept only "
        "a Codex result bound to the head and diff recorded below.\n\n"
        "<!-- grabowski-codex-review-request:v1\n"
        + _canonical_json(payload)
        + "\n-->"
    )


def _parse_request(comment: dict[str, Any]) -> dict[str, Any] | None:
    body = comment.get("body")
    if not isinstance(body, str):
        return None
    match = REQUEST_RE.search(body)
    if match is None:
        return None
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _request_actor_allowed(comment: dict[str, Any]) -> bool:
    association = comment.get("authorAssociation")
    actor = _actor_login(comment.get("author"))
    return association in TRUSTED_REQUEST_ASSOCIATIONS or actor in TRUSTED_REQUEST_ACTORS


def _canonical_request_payload(
    value: Any,
    *,
    repository: str,
    pr_number: int,
) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "repo",
        "pr",
        "head_sha",
        "diff_sha256",
        "request_id",
    }:
        return None
    head_sha = value.get("head_sha")
    diff_sha256 = value.get("diff_sha256")
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("kind") != REQUEST_KIND
        or value.get("repo") != repository
        or value.get("pr") != pr_number
        or not isinstance(head_sha, str)
        or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None
        or not isinstance(diff_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", diff_sha256) is None
    ):
        return None
    core = {
        "schema_version": SCHEMA_VERSION,
        "kind": REQUEST_KIND,
        "repo": repository,
        "pr": pr_number,
        "head_sha": head_sha,
        "diff_sha256": diff_sha256,
    }
    if value.get("request_id") != _sha256_json(core)[:32]:
        return None
    return dict(value)


def _canonical_requests(
    pr: dict[str, Any],
    *,
    repository: str,
    pr_number: int,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for comment in _list_nodes(pr.get("comments"), label="comments"):
        if not _request_actor_allowed(comment):
            continue
        parsed = _canonical_request_payload(
            _parse_request(comment),
            repository=repository,
            pr_number=pr_number,
        )
        created = _parse_time(comment.get("createdAt"))
        effective = _parse_time(comment.get("updatedAt"))
        comment_id = comment.get("databaseId")
        if (
            parsed is None
            or created is None
            or effective is None
            or effective < created
            or isinstance(comment_id, bool)
            or not isinstance(comment_id, int)
        ):
            continue
        result.append(
            {
                **comment,
                "_created": effective,
                "_original_created": created,
                "_request": parsed,
            }
        )
    return sorted(result, key=lambda item: (item["_created"], item["databaseId"]))


def _matching_requests(pr: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in _canonical_requests(
            pr,
            repository=expected["repo"],
            pr_number=expected["pr"],
        )
        if item["_request"] == expected
    ]


def _current_head(pr: dict[str, Any]) -> str:
    value = pr.get("headRefOid")
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value.lower()) is None:
        raise SettlementError("pull request head SHA is missing or invalid")
    return value.lower()


def _current_base(pr: dict[str, Any]) -> str:
    value = pr.get("baseRefOid")
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value.lower()) is None:
        raise SettlementError("pull request base SHA is missing or invalid")
    return value.lower()


def _current_diff(pr: dict[str, Any]) -> str:
    value = pr.get("diff_sha256")
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value.lower()) is None:
        raise SettlementError("pull request diff SHA-256 is missing or invalid")
    return value.lower()


def _policy(pr: dict[str, Any], repository: str, *, explicitly_required: bool) -> dict[str, Any]:
    files = _list_nodes(pr.get("files"), label="files")
    view = {
        "changedFiles": pr.get("changedFiles"),
        "additions": pr.get("additions"),
        "deletions": pr.get("deletions"),
        "files": [{"path": item.get("path")} for item in files],
    }
    complexity = pr_review_gate.classify_complexity(view, None, repo_name=repository)
    policy_required = complexity.get("external_review_required") is True
    required = explicitly_required or policy_required
    reasons: list[str] = []
    if policy_required:
        reasons.append("pr_review_gate requires external review")
    if explicitly_required:
        reasons.insert(0, "explicitly required")
    return {
        "required": required,
        "external_review_required": policy_required,
        "self_review_required": complexity.get("self_review_required") is True,
        "minimum_self_review_iterations": complexity.get(
            "minimum_self_review_iterations"
        ),
        "review_tier": complexity.get("review_tier"),
        "complexity_reasons": list(complexity.get("reasons") or []),
        "reasons": list(dict.fromkeys(reasons)),
    }



def _clean_comment_completion(
    pr: dict[str, Any],
    *,
    request_time: datetime,
    head_sha: str,
) -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []
    for comment in _list_nodes(pr.get("comments"), label="comments"):
        actor = _actor_login(comment.get("author"))
        body = comment.get("body")
        created = _parse_time(comment.get("createdAt"))
        comment_id = comment.get("databaseId")
        if (
            actor not in TRUSTED_CODEX_ACTORS
            or not isinstance(body, str)
            or created is None
            or created < request_time
            or isinstance(comment_id, bool)
            or not isinstance(comment_id, int)
        ):
            continue
        match = CLEAN_RESULT_RE.fullmatch(_normalize_codex_comment_body(body))
        if match is None:
            continue
        reviewed_prefix = match.group(1)
        if not head_sha.startswith(reviewed_prefix):
            continue
        candidates.append(
            {
                **comment,
                "_actor": actor,
                "_created": created,
                "_reviewed_prefix": reviewed_prefix,
            }
        )
    if not candidates:
        return None
    selected = max(
        candidates,
        key=lambda item: (item["_created"], item["databaseId"]),
    )
    return {
        "mode": "clean_comment",
        "review_id": None,
        "comment_id": selected["databaseId"],
        "actor": selected["_actor"],
        "state": "CLEAN",
        "submitted_at": selected["createdAt"],
        "body_sha256": _sha256_text(str(selected.get("body") or "")),
        "url": selected.get("url"),
        "reviewed_commit_prefix": selected["_reviewed_prefix"],
        "accepted_state": True,
        "blocking_state": False,
    }


def _review_completion(
    pr: dict[str, Any],
    *,
    requests: list[dict[str, Any]],
    head_sha: str,
) -> dict[str, Any] | None:
    if not requests:
        raise SettlementError("review completion requires at least one request")
    request_time = max(item["_created"] for item in requests)
    candidates: list[dict[str, Any]] = []
    for review in _list_nodes(pr.get("reviews"), label="reviews"):
        actor = _actor_login(review.get("author"))
        commit = review.get("commit")
        commit_sha = commit.get("oid") if isinstance(commit, dict) else None
        submitted = _parse_time(review.get("submittedAt"))
        review_id = review.get("databaseId")
        state = str(review.get("state") or "").upper()
        if (
            actor not in TRUSTED_CODEX_ACTORS
            or commit_sha != head_sha
            or isinstance(review_id, bool)
            or not isinstance(review_id, int)
        ):
            continue
        if state == "PENDING":
            candidates.append(
                {
                    **review,
                    "_actor": actor,
                    "_submitted": None,
                    "_state": state,
                }
            )
            continue
        if submitted is None:
            continue
        candidates.append(
            {
                **review,
                "_actor": actor,
                "_submitted": submitted,
                "_state": state,
            }
        )

    def order(item: dict[str, Any]) -> tuple[datetime, int]:
        submitted = item["_submitted"]
        if not isinstance(submitted, datetime):
            raise SettlementError("submitted review ordering requires a timestamp")
        return submitted, item["databaseId"]

    selected: dict[str, Any] | None = None
    pending = [item for item in candidates if item["_state"] == "PENDING"]
    if pending:
        selected = max(pending, key=lambda item: item["databaseId"])
    else:
        blockers = [
            item for item in candidates if item["_state"] == "CHANGES_REQUESTED"
        ]
        if blockers:
            latest_blocker = max(blockers, key=order)
            approvals = [
                item
                for item in candidates
                if item["_state"] == "APPROVED"
                and order(item) > order(latest_blocker)
            ]
            if not approvals:
                selected = latest_blocker
    if selected is None:
        accepted = [
            item
            for item in candidates
            if item["_state"] in ACCEPTED_REVIEW_STATES
            and isinstance(item["_submitted"], datetime)
            and item["_submitted"] >= request_time
        ]
        if accepted:
            selected = max(accepted, key=order)

    if selected is not None:
        state = selected["_state"]
        return {
            "mode": "review",
            "review_id": selected["databaseId"],
            "actor": selected["_actor"],
            "state": state,
            "submitted_at": selected["submittedAt"],
            "body_sha256": _sha256_text(str(selected.get("body") or "")),
            "url": selected.get("url"),
            "accepted_state": state in ACCEPTED_REVIEW_STATES,
            "blocking_state": state in BLOCKING_REVIEW_STATES,
        }

    clean_comment = _clean_comment_completion(
        pr,
        request_time=request_time,
        head_sha=head_sha,
    )
    if clean_comment is not None:
        return clean_comment

    reaction_candidates: list[dict[str, Any]] = []
    for reacted_request in requests:
        request_comment_id = reacted_request["databaseId"]
        reactions = reacted_request.get("reactions")
        for reaction in _list_nodes(
            reactions,
            label=f"request {request_comment_id} reactions",
        ):
            actor = _actor_login(reaction.get("user"))
            created = _parse_time(reaction.get("createdAt"))
            if (
                actor in TRUSTED_CODEX_ACTORS
                and reaction.get("content") == "THUMBS_UP"
                and created is not None
                and created >= request_time
            ):
                reaction_candidates.append(
                    {
                        **reaction,
                        "_actor": actor,
                        "_created": created,
                        "_request_comment_id": request_comment_id,
                    }
                )
    if reaction_candidates:
        selected = min(
            reaction_candidates,
            key=lambda item: (
                item["_created"],
                item["_request_comment_id"],
                item["_actor"],
            ),
        )
        return {
            "mode": "reaction",
            "review_id": None,
            "comment_id": selected["_request_comment_id"],
            "actor": selected["_actor"],
            "state": "THUMBS_UP",
            "submitted_at": selected.get("createdAt"),
            "body_sha256": _sha256_text("THUMBS_UP"),
            "url": None,
            "accepted_state": True,
            "blocking_state": False,
        }
    return None


def _provider_unavailable_diagnostic(
    pr: dict[str, Any],
    *,
    requests: list[dict[str, Any]],
) -> dict[str, Any] | None:
    # Provider notices are diagnostics, never Codex review completions. One
    # exact canonical request prevents attribution to an ambiguous attempt.
    if len(requests) != 1:
        return None
    request = requests[0]
    request_time = request["_created"]
    candidates: list[dict[str, Any]] = []
    for comment in _list_nodes(pr.get("comments"), label="comments"):
        actor = _actor_login(comment.get("author"))
        body = comment.get("body")
        created = _parse_time(comment.get("createdAt"))
        comment_id = comment.get("databaseId")
        if (
            actor not in TRUSTED_CODEX_ACTORS
            or not isinstance(body, str)
            or created is None
            or created < request_time
            or isinstance(comment_id, bool)
            or not isinstance(comment_id, int)
        ):
            continue
        normalized = _normalize_codex_comment_body(body)
        reason_code = next(
            (
                reason
                for reason, expected_bodies in PROVIDER_UNAVAILABLE_BODIES.items()
                if normalized in expected_bodies
            ),
            None,
        )
        if reason_code is None:
            continue
        candidates.append(
            {
                **comment,
                "_actor": actor,
                "_created": created,
                "_normalized_body": normalized,
                "_reason_code": reason_code,
            }
        )
    if not candidates:
        return None
    selected = min(
        candidates,
        key=lambda item: (item["_created"], item["databaseId"]),
    )
    return {
        "mode": "provider_diagnostic",
        "comment_id": selected["databaseId"],
        "actor": selected["_actor"],
        "state": "UNAVAILABLE",
        "reason_code": selected["_reason_code"],
        "observed_at": selected["createdAt"],
        "body_sha256": _sha256_text(selected["_normalized_body"]),
        "url": selected.get("url"),
        "request_id": request["_request"]["request_id"],
        "request_comment_id": request["databaseId"],
        "does_not_establish": [
            "codex_review_performed",
            "codex_review_pass",
            "codex_review_settled",
            "provider_outage_root_cause",
        ],
    }

def _codex_threads(
    pr: dict[str, Any],
    *,
    head_sha: str | None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for thread in _list_nodes(pr.get("reviewThreads"), label="reviewThreads"):
        thread_id = thread.get("id")
        if not isinstance(thread_id, str) or not thread_id.strip():
            continue
        thread_id = thread_id.strip()
        comments = _list_nodes(
            thread.get("comments"), label=f"thread {thread_id} comments"
        )
        if not comments:
            continue
        root = comments[0]
        actor = _actor_login(root.get("author"))
        commit = root.get("commit")
        commit_sha = commit.get("oid") if isinstance(commit, dict) else None
        created = _parse_time(root.get("createdAt"))
        comment_id = root.get("databaseId")
        if (
            actor not in TRUSTED_CODEX_ACTORS
            or created is None
            or isinstance(comment_id, bool)
            or not isinstance(comment_id, int)
            or (head_sha is not None and commit_sha != head_sha)
        ):
            continue
        result.append(
            {
                "thread_id": thread_id,
                "is_resolved": thread.get("isResolved") is True,
                "codex_comment_ids": [comment_id],
                "commit_sha": commit_sha,
            }
        )
    return sorted(result, key=lambda item: item["thread_id"])


def evaluate(
    repo: Path,
    repository: str,
    pr_number: int,
    *,
    explicitly_required: bool = False,
) -> dict[str, Any]:
    repository, _, _ = _normalize_repo(repository)
    pr = _live_state(repo, repository, pr_number)
    visibility_errors = _truncation_errors(pr)
    errors = list(visibility_errors)
    head_sha = _current_head(pr)
    base_sha = _current_base(pr)
    diff_sha256 = _current_diff(pr)
    policy = _policy(pr, repository, explicitly_required=explicitly_required)
    expected_request = _request_payload(repository, pr_number, head_sha, diff_sha256)
    canonical_requests = _canonical_requests(
        pr, repository=repository, pr_number=pr_number
    )
    requests = [
        item for item in canonical_requests if item["_request"] == expected_request
    ]
    request = requests[0] if requests else None
    completion = (
        _review_completion(pr, requests=requests, head_sha=head_sha)
        if request is not None
        else None
    )
    provider_outcome = (
        _provider_unavailable_diagnostic(pr, requests=requests)
        if request is not None and completion is None
        else None
    )
    threads = _codex_threads(pr, head_sha=head_sha) if request is not None else []
    finding_debt_threads = _codex_threads(pr, head_sha=None)
    unresolved = [
        item["thread_id"]
        for item in finding_debt_threads
        if not item["is_resolved"]
    ]
    if completion is not None and completion["blocking_state"]:
        errors.append(f"Codex review state is blocking: {completion['state']}")
    if completion is not None and not completion["accepted_state"]:
        errors.append(f"Codex review state is unsupported: {completion['state']}")
    if unresolved:
        errors.append(f"{len(unresolved)} Codex review thread(s) remain unresolved")

    required = policy["required"]
    if visibility_errors:
        status, status_code = "block", "visibility_blocked"
    elif errors:
        status, status_code = (
            ("block", "required_review_blocked")
            if required
            else ("block", "optional_review_findings")
        )
    elif completion is not None:
        status, status_code = "pass", "review_settled"
    elif provider_outcome is not None:
        status, status_code = (
            ("pending", "required_provider_unavailable")
            if required
            else ("pass", "optional_provider_unavailable")
        )
    elif request is None:
        status, status_code = (
            ("pending", "required_request_missing")
            if required
            else ("pass", "optional_not_requested")
        )
    else:
        status, status_code = (
            ("pending", "required_review_pending")
            if required
            else ("pass", "optional_review_pending")
        )

    status_contract = _settlement_status_contract(status, status_code)
    exit_code = status_contract["exit_code"]
    github_state = status_contract["github_state"]
    description = status_contract["description"]

    settled = (
        status == "pass"
        and completion is not None
        and request is not None
        and not errors
    )
    review_performed = completion is not None
    does_not_establish = [
        "semantic_correctness_of_codex_findings",
        "absence_of_non_inline_review_findings_outside_the_bounded_review_body",
        "merge_authority",
    ]
    if provider_outcome is not None:
        does_not_establish.extend(
            [
                "provider_unavailability_is_codex_review_completion",
                "provider_unavailability_is_codex_review_pass",
            ]
        )
    generated_at = datetime.now(timezone.utc).isoformat()
    request_evidence = None
    if request is not None:
        request_evidence = {
            "comment_id": request["databaseId"],
            "request_id": expected_request["request_id"],
            "created_at": request["createdAt"],
            "effective_at": request["updatedAt"],
            "actor": _actor_login(request.get("author")),
            "author_association": request.get("authorAssociation"),
            "body_sha256": _sha256_text(str(request.get("body") or "")),
        }
    thread_ids = [item["thread_id"] for item in threads]
    evidence_core = {
        "schema_version": SCHEMA_VERSION,
        "kind": EVIDENCE_KIND,
        "generated_at": generated_at,
        "repo": repository,
        "pr": pr_number,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "diff_sha256": diff_sha256,
        "required": required,
        "required_reason": policy["reasons"],
        "review_tier": policy["review_tier"],
        "policy": policy,
        "request": request_evidence,
        "completion": completion,
        "provider_outcome": provider_outcome,
        "review_performed": review_performed,
        "finding_count": len(finding_debt_threads),
        "thread_ids": thread_ids,
        "thread_ids_sha256": _sha256_json(thread_ids),
        "unresolved_thread_ids": unresolved,
        "unresolved_thread_ids_sha256": _sha256_json(unresolved),
        "all_findings_triaged": not unresolved,
        "settled": settled,
        "status": status,
        "status_code": status_code,
        "exit_code": exit_code,
        "github_state": github_state,
        "description": description,
        "errors": errors,
        "does_not_establish": does_not_establish,
    }
    evidence = {**evidence_core, "evidence_sha256": _sha256_json(evidence_core)}
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "github_codex_review_settlement_result",
        "status": status,
        "status_code": status_code,
        "exit_code": exit_code,
        "github_state": github_state,
        "description": description,
        "required": required,
        "settled": settled,
        "head_sha": head_sha,
        "diff_sha256": diff_sha256,
        "request_present": request is not None,
        "completion_present": completion is not None,
        "provider_outcome_present": provider_outcome is not None,
        "review_performed": review_performed,
        "finding_count": len(finding_debt_threads),
        "unresolved_thread_count": len(unresolved),
        "errors": errors,
        "policy": policy,
        "evidence": evidence,
    }


def ensure_request(
    repo: Path,
    repository: str,
    pr_number: int,
    *,
    explicitly_required: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    repository, _, _ = _normalize_repo(repository)
    pr = _live_state(repo, repository, pr_number)
    errors = _truncation_errors(pr)
    if errors:
        raise SettlementError("; ".join(errors))
    if pr.get("state") != "OPEN" or pr.get("isDraft") is True:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "github_codex_review_request_result",
            "requested": False,
            "reason": "pull request is not open and ready",
        }
    policy = _policy(pr, repository, explicitly_required=explicitly_required)
    if not policy["required"] and not force:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "github_codex_review_request_result",
            "requested": False,
            "required": False,
            "reason": "policy does not require Codex review",
            "review_tier": policy["review_tier"],
        }
    head_sha = _current_head(pr)
    diff_sha256 = _current_diff(pr)
    payload = _request_payload(repository, pr_number, head_sha, diff_sha256)
    existing = _matching_requests(pr, payload)
    if existing:
        adequate = existing[0]
        edited_cutoffs = [
            item["_created"]
            for item in existing
            if item["_created"] > item["_original_created"]
        ]
        needs_fresh_request = False
        if edited_cutoffs:
            latest_edit = max(edited_cutoffs)
            completion = _review_completion(
                pr,
                requests=existing,
                head_sha=head_sha,
            )
            fresh = [
                item
                for item in existing
                if item["_created"] == item["_original_created"]
                and item["_created"] >= latest_edit
            ]
            if completion is None and not fresh:
                needs_fresh_request = True
            elif fresh:
                adequate = min(
                    fresh,
                    key=lambda item: (item["_created"], item["databaseId"]),
                )
        if not needs_fresh_request:
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "github_codex_review_request_result",
                "requested": False,
                "required": policy["required"],
                "reason": "current-head request already exists",
                "request_id": payload["request_id"],
                "comment_id": adequate["databaseId"],
                "head_sha": head_sha,
                "diff_sha256": diff_sha256,
            }
    response = _run_json(
        repo,
        [
            "gh",
            "api",
            "--method",
            "POST",
            f"repos/{repository}/issues/{pr_number}/comments",
            "-f",
            f"body={_request_body(payload)}",
        ],
    )
    comment_id = response.get("id") if isinstance(response, dict) else None
    if isinstance(comment_id, bool) or not isinstance(comment_id, int):
        raise SettlementError("GitHub did not return the created request comment id")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "github_codex_review_request_result",
        "requested": True,
        "required": policy["required"],
        "request_id": payload["request_id"],
        "comment_id": comment_id,
        "head_sha": head_sha,
        "diff_sha256": diff_sha256,
    }


def _write_create_only(path: Path, payload: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError as exc:
        raise SettlementError(f"output already exists: {path}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-path", type=Path, default=Path.cwd())
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--write-evidence")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("command", choices=("request", "evaluate"))
    args = parser.parse_args(argv)
    repo = args.repo_path.resolve()
    exit_code = 0
    try:
        if args.command == "request":
            result = ensure_request(
                repo,
                args.repository,
                args.pr,
                explicitly_required=args.require,
                force=args.force,
            )
        else:
            result = evaluate(
                repo,
                args.repository,
                args.pr,
                explicitly_required=args.require,
            )
            exit_code = result["exit_code"]
            if args.write_evidence:
                evidence_path = Path(args.write_evidence)
                if not evidence_path.is_absolute():
                    evidence_path = repo / evidence_path
                _write_create_only(evidence_path, result["evidence"])
                result["evidence_path"] = str(evidence_path.resolve())
    except Exception as exc:
        contract = _settlement_status_contract("block", "evaluator_exception")
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "github_codex_review_settlement_result",
            "status": "block",
            "status_code": "evaluator_exception",
            "exit_code": contract["exit_code"],
            "github_state": contract["github_state"],
            "description": contract["description"],
            "required": True,
            "settled": False,
            "errors": [str(exc)],
        }
        exit_code = contract["exit_code"]
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(result.get("status") or result.get("reason") or result.get("requested"))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
