"""Server-observed post-merge review and CI for a whole serving-to-target delta.

This module grants no authorization by itself. Captain must independently pass
its action gates and establish an ephemeral execution scope. Direct schedulers
cannot supply release review identifiers or PASS attestations.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import re
from typing import Any

REPOSITORY = "heimgewebe/grabowski"
GITHUB_HOST = "api.github.com"
CHECK_BYTES_LIMIT = 262_144
REQUIRED_CI_CHECKS = ("validate (3.10)", "validate (3.12)")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ReleaseAdmissionDenied(RuntimeError):
    """A post-merge release review or CI origin did not verify."""


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _fresh_github_checks(target_head: str) -> dict[str, Any]:
    """Read exact target-commit checks from GitHub, not caller CI declarations."""
    if not isinstance(target_head, str) or not _SHA40.fullmatch(target_head):
        raise ReleaseAdmissionDenied("release target commit is invalid")
    path = f"/repos/{REPOSITORY}/commits/{target_head}/check-runs?per_page=100"
    conn = http.client.HTTPSConnection(GITHUB_HOST, timeout=15)
    try:
        conn.request(
            "GET", path,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "grabowski-release-admission/1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response = conn.getresponse()
        if response.status != 200:
            raise ReleaseAdmissionDenied(f"authoritative CI lookup HTTP {response.status}")
        pagination = response.getheader("Link", "")
        if pagination and 'rel="next"' in pagination:
            raise ReleaseAdmissionDenied("authoritative CI check list is paginated")
        payload = response.read(CHECK_BYTES_LIMIT + 1)
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise ReleaseAdmissionDenied("authoritative CI lookup failed") from exc
    finally:
        conn.close()
    if len(payload) > CHECK_BYTES_LIMIT:
        raise ReleaseAdmissionDenied("authoritative CI payload exceeded bound")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReleaseAdmissionDenied("authoritative CI payload is invalid") from exc
    if not isinstance(data, dict):
        raise ReleaseAdmissionDenied("authoritative CI result is invalid")
    checks = data.get("check_runs")
    total = data.get("total_count")
    if (
        not isinstance(checks, list) or type(total) is not int
        or total != len(checks) or total > 100
    ):
        raise ReleaseAdmissionDenied("authoritative CI inventory incomplete")
    latest: dict[str, dict[str, Any]] = {}
    for check in checks:
        if not isinstance(check, dict):
            raise ReleaseAdmissionDenied("authoritative CI contains malformed check")
        name = check.get("name")
        if name not in REQUIRED_CI_CHECKS:
            continue
        app = check.get("app")
        run_id = check.get("id")
        if (
            not isinstance(app, dict) or app.get("slug") != "github-actions"
            or type(run_id) is not int or run_id <= 0
            or check.get("head_sha") != target_head
        ):
            raise ReleaseAdmissionDenied("required CI origin or commit mismatch")
        previous = latest.get(name)
        if previous is None or run_id > previous["id"]:
            latest[name] = {
                "name": name, "id": run_id, "status": check.get("status"),
                "conclusion": check.get("conclusion"), "head_sha": target_head,
            }
        elif run_id == previous["id"]:
            raise ReleaseAdmissionDenied("duplicate required CI identity")
    if set(latest) != set(REQUIRED_CI_CHECKS):
        raise ReleaseAdmissionDenied("required target-commit CI checks are missing")
    if any(
        check["status"] != "completed" or check["conclusion"] != "success"
        for check in latest.values()
    ):
        raise ReleaseAdmissionDenied("required target-commit CI is not green")
    ordered = [latest[name] for name in REQUIRED_CI_CHECKS]
    return {"checks": ordered, "checks_sha256": _sha256_json(ordered)}


def validate_independent_release_review(
    *, serving_head: str, target_head: str, diff_sha256: str,
    review_pr: int,
) -> dict[str, Any]:
    """Reconcile an actual role-bound independent review of the *whole* delta.

    The PR integer is a durable review-job namespace, not proof of a PR merge.
    The server checks job-origin provenance, isolated reviewer-role receipt and
    exact serving/head/diff identities; a generic PASS never counts.
    """
    if (
        not isinstance(serving_head, str) or not _SHA40.fullmatch(serving_head)
        or not isinstance(target_head, str) or not _SHA40.fullmatch(target_head)
        or not isinstance(diff_sha256, str) or not _SHA256.fullmatch(diff_sha256)
        or type(review_pr) is not int or review_pr <= 0
    ):
        raise ReleaseAdmissionDenied("release review identity is invalid")
    import grabowski_decision_reviews as decisions
    import grabowski_merge_guard as merge_guard

    try:
        reconciliation = decisions.reconcile(
            repo=REPOSITORY, pr=review_pr, head_sha=target_head,
            base_sha=serving_head, diff_sha256=diff_sha256,
            defer_diff_identity=False,
        )
        summary = merge_guard.independent_review_reconciliation_summary(reconciliation)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise ReleaseAdmissionDenied("independent release review reconciliation failed") from exc
    if (
        not isinstance(reconciliation, dict)
        or reconciliation.get("status") != "settled"
        or reconciliation.get("errors") != []
        or not isinstance(summary, dict)
        or summary.get("errors") != []
        or type(summary.get("pass_count")) is not int
        or summary["pass_count"] < 1
        or not summary.get("admissible_slots")
        or reconciliation.get("deferred_diff_identity_count") != 0
    ):
        raise ReleaseAdmissionDenied("authentic independent release R3 PASS is missing")
    binding = reconciliation.get("binding")
    if (
        not isinstance(binding, dict)
        or binding.get("repo") != REPOSITORY
        or binding.get("pr") != review_pr
        or binding.get("head_sha") != target_head
        or binding.get("base_sha") != serving_head
        or binding.get("diff_sha256") != diff_sha256
    ):
        raise ReleaseAdmissionDenied("release reviewer binding drift")
    return {
        "review_pr": review_pr,
        "review_binding_sha256": reconciliation.get("binding_sha256"),
        "review_attempts_sha256": reconciliation.get("attempts_sha256"),
        "independent_pass_count": summary["pass_count"],
        "admissible_slots": summary["admissible_slots"],
    }


def validate_release(
    *, serving_head: str, target_head: str, serving_release_id: str,
    serving_tree: str, target_tree: str, diff_sha256: str, review_pr: int,
) -> dict[str, Any]:
    """Recompute all external evidence on each authorization/dispatch check."""
    for value in (serving_head, target_head, serving_tree, target_tree):
        if not isinstance(value, str) or not _SHA40.fullmatch(value):
            raise ReleaseAdmissionDenied("release source/tree identity is invalid")
    if not isinstance(serving_release_id, str) or not serving_release_id.strip():
        raise ReleaseAdmissionDenied("serving release ID is invalid")
    if not isinstance(diff_sha256, str) or not _SHA256.fullmatch(diff_sha256):
        raise ReleaseAdmissionDenied("release diff identity is invalid")
    review = validate_independent_release_review(
        serving_head=serving_head, target_head=target_head,
        diff_sha256=diff_sha256, review_pr=review_pr,
    )
    checks = _fresh_github_checks(target_head)
    material = {
        "schema_version": 1,
        "kind": "grabowski_post_merge_release_review",
        "source": "server-observed",
        "repo": REPOSITORY,
        "serving_release_id": serving_release_id,
        "serving_head": serving_head,
        "target_head": target_head,
        "serving_tree": serving_tree,
        "target_tree": target_tree,
        "diff_sha256": diff_sha256,
        "review": review,
        "ci": checks,
    }
    return {
        **material,
        "release_review_identity_sha256": _sha256_json(material),
        "independent_review_required": True,
        "status": "authenticated-post-merge-r3-ci",
        "does_not_establish": [
            "historical pre-merge review authorization",
            "Captain runtime-deploy decision",
            "deployment execution or completion",
            "external connector publication",
        ],
    }
