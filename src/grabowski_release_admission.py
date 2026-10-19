"""Server-observed post-merge review and CI for a whole serving-to-target delta.

This module grants no authorization by itself. Captain must independently pass
its action gates and establish an ephemeral execution scope. Direct schedulers
cannot supply release review identifiers or PASS attestations.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

REPOSITORY = "heimgewebe/grabowski"
GITHUB_HOST = "api.github.com"
CHECK_BYTES_LIMIT = 262_144
REQUIRED_CI_CHECKS = ("validate (3.10)", "validate (3.12)")
CANONICAL_WORKFLOW_PATH = ".github/workflows/validate.yml"
MAX_GITHUB_ITEMS = 1_000
GITHUB_PAGE_SIZE = 100
# Only target application code and inert documentation can vary under
# ordinary post-merge CI admission. All other root files/trees can control
# make, Python test discovery, validation scripts or deployment checks.
# A change to those validation inputs needs a separate CI-policy transition.
VALIDATION_POLICY_REQUIRED_ROOTS = frozenset({
    ".github", ".gitignore", "AGENTS.md", "Makefile", "pyproject.toml",
    "config", "contracts", "deploy", "requirements", "systemd",
    "tests", "tmpfiles", "tools",
})
VALIDATION_POLICY_MUTABLE_ROOTS = frozenset({
    "src", "docs", "README.md", "CHANGELOG.md", "SECURITY.md",
    "GRABOWSKI.md", "OPERATOR_V2_REPORT.md",
})
MAX_VALIDATION_ROOT_ENTRIES = 256
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ReleaseAdmissionDenied(RuntimeError):
    """A post-merge release review or CI origin did not verify."""


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _github_token() -> str:
    """Resolve the existing trusted operator GitHub credential; never fall back to anonymous."""
    try:
        import grabowski_operator as operator

        # Reuse the operator's isolated, bounded gh-auth/keyring lookup. The
        # token remains process-local and never enters a receipt or URL.
        return operator._github_pr_view_auth_token(
            str(operator.TRUSTED_GITHUB_CLI_PATH), dict(os.environ), "github.com"
        )
    except Exception:
        # A credential helper may raise an exception carrying a token or its
        # subprocess output. Drop that exception before creating a public one.
        pass
    raise ReleaseAdmissionDenied("authenticated GitHub credential unavailable")


def _github_json(path: str, *, token: str) -> tuple[dict[str, Any], str]:
    """Bounded authenticated HTTPS read; responses remain untrusted until checked."""
    if not isinstance(token, str) or not token or any(not 33 <= ord(char) <= 126 for char in token):
        raise ReleaseAdmissionDenied("authenticated GitHub credential invalid")
    conn = http.client.HTTPSConnection(GITHUB_HOST, timeout=15)
    transport_failed = False
    try:
        conn.request(
            "GET", path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + token,
                "User-Agent": "grabowski-release-admission/2",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response = conn.getresponse()
        status = response.status
        if status == 200:
            link = response.getheader("Link", "") or ""
            payload = response.read(CHECK_BYTES_LIMIT + 1)
    except Exception:
        # Transport implementations can include an Authorization header in an
        # exception. Never retain that exception as a cause or context.
        transport_failed = True
    finally:
        try:
            conn.close()
        except Exception:
            # Cleanup failures may themselves disclose the bearer. Fail closed.
            transport_failed = True
    if transport_failed:
        raise ReleaseAdmissionDenied("authoritative CI lookup failed")
    if status != 200:
        raise ReleaseAdmissionDenied(f"authoritative CI lookup HTTP {status}")
    if len(payload) > CHECK_BYTES_LIMIT:
        raise ReleaseAdmissionDenied("authoritative CI payload exceeded bound")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReleaseAdmissionDenied("authoritative CI payload is invalid") from exc
    if not isinstance(data, dict) or not isinstance(link, str):
        raise ReleaseAdmissionDenied("authoritative CI result is malformed")
    return data, link


def _github_inventory(path: str, key: str, *, token: str) -> list[dict[str, Any]]:
    """Read all pages, fail closed on changed counts, missing pages and unsafe links."""
    collected: list[dict[str, Any]] = []
    observed_ids: set[int] = set()
    total: int | None = None
    for page in range(1, MAX_GITHUB_ITEMS // GITHUB_PAGE_SIZE + 1):
        suffix = "&" if "?" in path else "?"
        page_path = f"{path}{suffix}per_page={GITHUB_PAGE_SIZE}&page={page}"
        data, link = _github_json(page_path, token=token)
        items = data.get(key)
        count = data.get("total_count")
        if (
            type(count) is not int or count < 0 or count > MAX_GITHUB_ITEMS
            or not isinstance(items, list) or len(items) > GITHUB_PAGE_SIZE
            or (total is not None and count != total)
        ):
            raise ReleaseAdmissionDenied("authoritative CI inventory incomplete")
        total = count
        expected = min(GITHUB_PAGE_SIZE, total - len(collected))
        if len(items) != expected:
            raise ReleaseAdmissionDenied("authoritative CI pagination incomplete")
        for item in items:
            item_id = item.get("id") if isinstance(item, dict) else None
            if type(item_id) is not int or item_id <= 0 or item_id in observed_ids:
                raise ReleaseAdmissionDenied("authoritative CI page has invalid or duplicate IDs")
            observed_ids.add(item_id)
            collected.append(item)
        more = len(collected) < total
        links = re.findall(r'<([^>]+)>;\s*rel="next"', link)
        if more != bool(links) or len(links) > 1:
            raise ReleaseAdmissionDenied("authoritative CI pagination link mismatch")
        if more:
            next_url = urlsplit(links[0])
            current_url = urlsplit(f"https://{GITHUB_HOST}{path}")
            current_query = parse_qs(current_url.query)
            current_query.update({"per_page": [str(GITHUB_PAGE_SIZE)], "page": [str(page + 1)]})
            if (
                next_url.scheme != "https" or next_url.netloc != GITHUB_HOST
                or next_url.path != current_url.path
                or parse_qs(next_url.query) != current_query
                or next_url.fragment
            ):
                raise ReleaseAdmissionDenied("authoritative CI pagination destination mismatch")
        else:
            return collected
    raise ReleaseAdmissionDenied("authoritative CI pagination exceeds bound")


def _trusted_validate_workflow_blob(
    *, serving_head: str, target_head: str, token: str,
) -> str:
    """The target cannot redefine its own validation policy and grade itself.

    The actually serving source is our immutable CI-policy trust anchor. A
    changed workflow requires a separate authorization path, never green job
    names produced by that changed workflow.
    """
    prefix = f"/repos/{REPOSITORY}/contents/{CANONICAL_WORKFLOW_PATH}"
    blobs: list[str] = []
    for head in (serving_head, target_head):
        value, link = _github_json(f"{prefix}?ref={head}", token=token)
        blob = value.get("sha")
        if (
            link or value.get("path") != CANONICAL_WORKFLOW_PATH
            or value.get("type") != "file"
            or not isinstance(blob, str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", blob) is None
        ):
            raise ReleaseAdmissionDenied("trusted Validate workflow identity is unproved")
        blobs.append(blob)
    if blobs[0] != blobs[1]:
        raise ReleaseAdmissionDenied("trusted Validate workflow definition changed")
    return blobs[0]


def _trusted_validate_control_sources(
    *, serving_head: str, target_head: str, token: str,
) -> str:
    """Pin transitive Validate control inputs by Git tree identities.

    The workflow executes target-side Makefile, scripts, tests and their
    configuration. Comparing only the YAML leaves a target-self-grading P1.
    Every unexempted root blob/tree is therefore immutable relative to
    the actually serving commit; Git subtree OIDs cover all nested content.
    Application sources still require an independent whole-release review.
    """
    prefix = f"/repos/{REPOSITORY}/git/trees"
    observed: list[dict[str, tuple[str, str, str]]] = []
    for head in (serving_head, target_head):
        result, link = _github_json(f"{prefix}/{head}", token=token)
        rows = result.get("tree")
        if (
            link or result.get("sha") != head
            or result.get("truncated") is not False
            or not isinstance(rows, list)
            or not 0 < len(rows) <= MAX_VALIDATION_ROOT_ENTRIES
        ):
            raise ReleaseAdmissionDenied("trusted Validate control inventory is unproved")
        entries: dict[str, tuple[str, str, str]] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ReleaseAdmissionDenied("trusted Validate control entry is invalid")
            path, kind, mode, oid = (
                row.get("path"), row.get("type"),
                row.get("mode"), row.get("sha"),
            )
            if (
                not isinstance(path, str)
                or path in {"", ".", ".."} or "/" in path or "\\" in path
                or path in entries
                or kind not in {"blob", "tree"}
                or mode not in (
                    {"100644", "100755"} if kind == "blob" else {"040000"}
                )
                or not isinstance(oid, str)
                or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) is None
            ):
                raise ReleaseAdmissionDenied("trusted Validate control entry is invalid")
            entries[path] = kind, mode, oid
        if not VALIDATION_POLICY_REQUIRED_ROOTS.issubset(entries):
            raise ReleaseAdmissionDenied("trusted Validate control roots are missing")
        observed.append(entries)
    serving, target = observed
    if set(serving) != set(target):
        # A newly introduced root sitecustomize.py or script is itself an
        # untrusted validation input even if every known policy file matches.
        raise ReleaseAdmissionDenied("trusted Validate control paths changed")
    for path, old in serving.items():
        new = target[path]
        if path in VALIDATION_POLICY_MUTABLE_ROOTS:
            if old[:2] != new[:2]:
                raise ReleaseAdmissionDenied("trusted Validate control type changed")
        elif old != new:
            raise ReleaseAdmissionDenied("trusted Validate control sources changed")
    return _sha256_json({
        "policy_roots": {p: serving[p] for p in sorted(serving)
                         if p not in VALIDATION_POLICY_MUTABLE_ROOTS},
        "mutable_roots": sorted(VALIDATION_POLICY_MUTABLE_ROOTS),
    })


def _fresh_github_checks(target_head: str, *, serving_head: str) -> dict[str, Any]:
    """Bind green checks to the trusted immutable workflow, run, job and suite."""
    if (
        not isinstance(target_head, str) or not _SHA40.fullmatch(target_head)
        or not isinstance(serving_head, str) or not _SHA40.fullmatch(serving_head)
    ):
        raise ReleaseAdmissionDenied("release target or serving commit is invalid")
    token = _github_token()
    trusted_blob = _trusted_validate_workflow_blob(
        serving_head=serving_head, target_head=target_head, token=token,
    )
    trusted_control_sources_sha256 = _trusted_validate_control_sources(
        serving_head=serving_head, target_head=target_head, token=token,
    )
    prefix = f"/repos/{REPOSITORY}"
    workflow, link = _github_json(
        f"{prefix}/actions/workflows/validate.yml", token=token
    )
    workflow_id = workflow.get("id")
    if (
        link or type(workflow_id) is not int or workflow_id <= 0
        or workflow.get("path") != CANONICAL_WORKFLOW_PATH
        or workflow.get("state") != "active"
    ):
        raise ReleaseAdmissionDenied("canonical Validate workflow identity is invalid")

    runs = _github_inventory(
        f"{prefix}/actions/workflows/{workflow_id}/runs?head_sha={target_head}",
        "workflow_runs", token=token,
    )
    matching: list[dict[str, Any]] = []
    for run in runs:
        if (
            run.get("workflow_id") != workflow_id
            or run.get("path") != CANONICAL_WORKFLOW_PATH
            or run.get("head_sha") != target_head
        ):
            raise ReleaseAdmissionDenied("canonical Validate run origin or commit mismatch")
        if (
            run.get("event") == "push"
            and run.get("head_branch") == "main"
            and isinstance(run.get("repository"), dict)
            and run["repository"].get("full_name") == REPOSITORY
            and isinstance(run.get("head_repository"), dict)
            and run["head_repository"].get("full_name") == REPOSITORY
        ):
            matching.append(run)
    if not matching:
        raise ReleaseAdmissionDenied("canonical Validate push run is missing")
    def order(run: dict[str, Any]) -> tuple[int, int]:
        number, run_id = run.get("run_number"), run.get("id")
        if type(number) is not int or number <= 0 or type(run_id) is not int:
            raise ReleaseAdmissionDenied("canonical Validate run ordering is invalid")
        return number, run_id
    latest = max(matching, key=order)
    run_id = latest["id"]
    run, link = _github_json(f"{prefix}/actions/runs/{run_id}", token=token)
    attempt, suite_id = run.get("run_attempt"), run.get("check_suite_id")
    if (
        link or run.get("id") != run_id
        or run.get("workflow_id") != workflow_id
        or run.get("path") != CANONICAL_WORKFLOW_PATH
        or run.get("event") != "push"
        or run.get("head_branch") != "main"
        or not isinstance(run.get("repository"), dict)
        or run["repository"].get("full_name") != REPOSITORY
        or not isinstance(run.get("head_repository"), dict)
        or run["head_repository"].get("full_name") != REPOSITORY
        or run.get("head_sha") != target_head
        or run.get("run_number") != latest.get("run_number")
        or type(attempt) is not int or attempt <= 0
        or attempt != latest.get("run_attempt")
        or type(suite_id) is not int or suite_id <= 0
        or suite_id != latest.get("check_suite_id")
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise ReleaseAdmissionDenied("current canonical Validate run is not authenticated green")

    jobs = _github_inventory(f"{prefix}/actions/runs/{run_id}/jobs?filter=all", "jobs", token=token)
    selected: dict[str, dict[str, Any]] = {}
    for job in jobs:
        name = job.get("name")
        if name not in REQUIRED_CI_CHECKS:
            continue
        job_attempt = job.get("run_attempt")
        if (
            job.get("run_id") != run_id
            or job.get("head_sha") != target_head
            or type(job_attempt) is not int or not 1 <= job_attempt <= attempt
        ):
            raise ReleaseAdmissionDenied("canonical Validate job binding is invalid")
        previous = selected.get(name)
        if previous is None or job_attempt > previous["run_attempt"]:
            selected[name] = job
        elif job_attempt == previous["run_attempt"]:
            raise ReleaseAdmissionDenied("duplicate canonical Validate job identity")
    if set(selected) != set(REQUIRED_CI_CHECKS):
        raise ReleaseAdmissionDenied("required canonical Validate jobs are missing")

    ordered = []
    for name in REQUIRED_CI_CHECKS:
        job = selected[name]
        check_id = job["id"]
        # The job ID is the Check-Run ID. Fetch it directly rather than
        # enumerating unrelated checks on a busy commit (possibly >1,000).
        check, link = _github_json(f"{prefix}/check-runs/{check_id}", token=token)
        suite = check.get("check_suite") if isinstance(check, dict) else None
        app = check.get("app") if isinstance(check, dict) else None
        if (
            job.get("check_run_url") != f"https://{GITHUB_HOST}{prefix}/check-runs/{check_id}"
            or link or check.get("id") != check_id
            or job.get("status") != "completed" or job.get("conclusion") != "success"
            or not isinstance(check, dict)
            or check.get("name") != name
            or check.get("head_sha") != target_head
            or check.get("status") != "completed" or check.get("conclusion") != "success"
            or not isinstance(app, dict) or app.get("slug") != "github-actions"
            or not isinstance(suite, dict) or suite.get("id") != suite_id
        ):
            raise ReleaseAdmissionDenied("required canonical Validate job/check provenance is not green")
        ordered.append({
            "name": name, "id": check_id, "head_sha": target_head,
            "status": "completed", "conclusion": "success",
            "workflow_id": workflow_id, "run_id": run_id,
            "run_attempt": job["run_attempt"], "check_suite_id": suite_id,
        })
    workflow_identity = {
        "id": workflow_id, "path": CANONICAL_WORKFLOW_PATH,
        "trusted_blob_oid": trusted_blob,
        "trusted_control_sources_sha256": trusted_control_sources_sha256,
        "run_id": run_id, "run_attempt": attempt,
        "check_suite_id": suite_id, "event": "push", "head_branch": "main",
        "head_repository": REPOSITORY, "head_sha": target_head,
    }
    return {
        "checks": ordered,
        "workflow": workflow_identity,
        "checks_sha256": _sha256_json({"workflow": workflow_identity, "checks": ordered}),
    }


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
    checks = _fresh_github_checks(target_head, serving_head=serving_head)
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