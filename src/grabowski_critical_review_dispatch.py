"""Best-effort Claude subscription review at the signed first-party PR review start.

This only starts a read-only, exact-revision reviewer.  The ordinary five-axis
self-review remains mandatory; provider quota and pre-result auth failures
never create a synthetic independent PASS or a new independent-review policy.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterator


PROMPT = (
    "Independently review the complete frozen Git diff for correctness, "
    "regressions, security, concurrency, data integrity and recovery. "
    "Use only source evidence; identify concrete file/line findings and "
    "negative tests. Do not modify files. A genuine serious finding must "
    "be reported as NEEDS_CHANGE or BLOCK with concrete findings, "
    "not a generic risk reminder. Follow the review-role JSON schema."
)
SLOT = "independent-claude"


@contextmanager
def _one_revision_claim(binding: dict[str, Any], lock_root: Path) -> Iterator[None]:
    """Serialize lookup and start without deadlocking the existing PR job lock."""
    key = hashlib.sha256(json.dumps(
        binding, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    if lock_root.is_symlink():
        raise OSError("review lock root is a symlink")
    lock_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = lock_root / ("claude-auto-" + key + ".lock")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def maybe_start_claude_review(
    plan: dict[str, Any],
    *,
    route_selector: Callable[..., dict[str, Any]] | None = None,
    binding_reader: Callable[..., tuple[str, str, bool]] | None = None,
    reconcile: Callable[..., dict[str, Any]] | None = None,
    job_start: Callable[..., dict[str, Any]] | None = None,
    lock_root: Path | None = None,
) -> dict[str, Any]:
    """Attempt at most once per PR/base/head/diff; always return a diagnostic.

    A first-party review session has already been signed.  An unavailable
    external provider must never prevent that session or the ordinary
    controller review from continuing.  Existing decision-bound jobs retain
    their normal independent finding-debt semantics.
    """
    result: dict[str, Any] = {
        "kind": "grabowski.critical_claude_advisory_v1",
        "provider": "claude",
        "mandatory_external_pass": False,
        "independent_review_required": False,
        "additional_cost_authorized": False,
    }
    if not isinstance(plan, dict) or plan.get("kind") != "grabowski_first_party_review_plan":
        return {**result, "state": "not_applicable"}
    source = plan.get("binding")
    if not isinstance(source, dict) or source.get("review_purpose") != "pull_request":
        return {**result, "state": "not_applicable"}
    try:
        import grabowski_decision_reviews as reviews
        # Import only real production adapters; unit-injected read-only fakes
        # must not load the full MCP server or a local provider process.
        if route_selector is None:
            from grabowski_coding_agent_router import canonical_execution_route
            route_selector = canonical_execution_route
        if binding_reader is None:
            from grabowski_agent_role import current_binding
            binding_reader = current_binding
        if job_start is None:
            from grabowski_operator import grabowski_job_start
            job_start = grabowski_job_start

        binding = reviews.normalize_binding({
            "schema_version": 1,
            "kind": reviews.BINDING_KIND,
            "repo": source["repo"],
            "pr": source["pr"],
            "head_sha": source["head_sha"],
            "base_sha": source["base_sha"],
            "diff_sha256": source["diff_sha256"],
            "slot": SLOT,
        })
        repo = Path(plan["worktree"]).resolve(strict=True)
        selector = route_selector
        selected = selector(
            "critical-review", changed_files=1, duration_minutes=30,
            novelty="high", risk_flags=["high-risk"], need_review=True,
            verification_policy="independent_review", effect_profile="candidate",
        )
        candidates = [*selected.get("reviewers", []), *selected.get("review_fallbacks", [])]
        reviewer = next((item for item in candidates if (
            isinstance(item, dict)
            and item.get("route") == "claude-opus-5.5-high"
            and item.get("harness") == "claude"
            and item.get("review_only") is True
            and item.get("paid_only") is not True
            and item.get("execution_eligible_if_separately_authorized") is True
        )), None)
        if reviewer is None:
            return {**result, "state": "unavailable", "reason": "claude_subscription_review_not_eligible"}
        reader = binding_reader
        actual_head, workspace_diff, dirty = reader(repo, binding["base_sha"])
        if actual_head != binding["head_sha"] or dirty:
            return {**result, "state": "unavailable", "reason": "frozen_worktree_identity_not_clean"}
        inspect = reconcile or reviews.reconcile
        starter = job_start
        with _one_revision_claim(binding, lock_root or reviews.LOCKS_ROOT):
            history = inspect(
                repo=binding["repo"], pr=binding["pr"],
                head_sha=binding["head_sha"], base_sha=binding["base_sha"],
                diff_sha256=binding["diff_sha256"],
            )
            if not isinstance(history, dict) or not isinstance(history.get("attempts"), list):
                return {**result, "state": "unavailable", "reason": "review_history_unavailable"}
            if any(isinstance(item, dict) and item.get("slot") == SLOT
                   for item in history["attempts"]):
                return {**result, "state": "already_attempted"}
            if history.get("errors"):
                return {**result, "state": "unavailable", "reason": "existing_review_history_unsettled"}
            command = [
                reviews.REVIEW_ROLE_PYTHON, "-I", "-m", reviews.REVIEW_ROLE_MODULE,
                "--role", "review", "--repository", str(repo),
                "--expected-head", binding["head_sha"],
                "--expected-base-head", binding["base_sha"],
                "--expected-diff-sha256", workspace_diff,
                "--expected-dirty", "false",
                "--output", str(reviews.JOBS_ROOT / "reserved-claude-review.json"),
                "--", *reviewer["argv_prefix"], PROMPT,
            ]
            launched = starter(
                command, cwd=str(repo), runtime_seconds=1800,
                decision_review_binding=binding,
            )
            if not isinstance(launched, dict) or not isinstance(launched.get("unit"), str):
                return {**result, "state": "outcome_unknown", "reason": "review_start_receipt_incomplete"}
            return {
                **result, "state": "dispatched", "slot": SLOT,
                "route": reviewer["route"], "model": reviewer["model"],
                "unit": launched["unit"],
                "pr": binding["pr"], "head_sha": binding["head_sha"],
                "diff_sha256": binding["diff_sha256"],
            }
    except Exception as exc:
        # The signed first-party review must continue. Do not echo provider
        # errors (which can include account or source fragments).
        return {
            **result, "state": "unavailable",
            "reason": "review_start_or_history_failed",
            "error_type": type(exc).__name__,
            "automatic_retry": False,
        }
