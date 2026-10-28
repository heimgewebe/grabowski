"""Trusted producer of task-origin-bound self-review receipts.

The producer does not accept PASS markers, arbitrary review commands, arbitrary
signing keys or user-supplied task outcomes. Each phase must be the completed
Grabowski systemd task whose immutable argv is a trusted, read-only, networkless
review method. The separate authenticated semantic reviewer execution remains required:
a successful technical test suite cannot supply a substantive review.

Production callers must use plan_review() and seal_review(); dependency
injection is confined to the private _seal_review implementation and tests.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import subprocess
from typing import Any, Callable

import grabowski_self_review_execution as provenance

MAX_PLAN_BYTES = 128 * 1024  # Five pinned outer Python worker argv records exceed 32 KiB.
TASK_DB = Path.home() / ".local/state/grabowski/tasks.sqlite3"
CAPTURE_ROOT = provenance.CAPTURE_ROOT
OUTCOMES = provenance.OUTCOME_ROOT
RECEIPTS = provenance.RECEIPT_ROOT
SIGNERS = provenance.TRUSTED_SIGNERS
SIGNING_KEY = provenance.SIGNING_KEY
R3_ROOT = Path.home() / ".local/state/grabowski/release-self-review-audits"
MANAGED_REPOS_ROOT = Path.home() / "repos"
CANONICAL_REPO = Path.home() / "repos/grabowski"
SHA = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
TASK = re.compile(r"[a-f0-9]{24}\Z")
SUPPORTED_REPO = re.compile(r"heimgewebe/(?P<name>[A-Za-z0-9_.-]+)\Z")
METHODS = provenance.REQUIRED_AXES


def _read_command(repo: Path, arguments: list[str], *, timeout: int = 30) -> bytes:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *arguments],
            capture_output=True, timeout=timeout, check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise provenance.ReviewExecutionRejected("trusted source Git probe unavailable") from exc
    if completed.returncode != 0 or len(completed.stdout) > 1024 * 1024:
        raise provenance.ReviewExecutionRejected("trusted source Git probe failed")
    return completed.stdout


def _managed_repository_identity(
    repo: Path, *, expected_repo: str | None = None,
) -> tuple[Path, str]:
    """Resolve one supported checkout from Git common-dir and origin identity."""
    real = repo.resolve(strict=True)
    root = MANAGED_REPOS_ROOT.resolve(strict=True)
    try:
        top = Path(
            _read_command(real, ["rev-parse", "--show-toplevel"]).decode().strip()
        ).resolve(strict=True)
        common_raw = _read_command(real, ["rev-parse", "--git-common-dir"]).decode().strip()
        common = Path(common_raw)
        if not common.is_absolute():
            common = real / common
        common = common.resolve(strict=True)
    except (UnicodeError, OSError) as exc:
        raise provenance.ReviewExecutionRejected(
            "review source Git checkout identity invalid"
        ) from exc
    if top != real or common.name != ".git" or common.parent.parent != root:
        raise provenance.ReviewExecutionRejected("review source not a managed checkout")
    repository_name = common.parent.name
    canonical = root / repository_name
    # Grabowski owns one common worktree pool for all heimgewebe repos.
    # Keep repository-specific pools as an existing compatible layout.
    worktrees = {
        root / ".grabowski-worktrees",
        root / ("." + repository_name + "-worktrees"),
    }
    if real != canonical and real.parent not in worktrees:
        raise provenance.ReviewExecutionRejected("review source not a managed checkout")
    if common != (canonical / ".git").resolve(strict=True):
        raise provenance.ReviewExecutionRejected("review source Git common-dir mismatch")
    remote = _read_command(
        real, ["config", "--local", "--get", "remote.origin.url"],
    ).decode().strip()
    match = re.fullmatch(
        r"(?:git@github\.com:|ssh://git@github\.com/|https://github\.com/)"
        r"(?P<slug>heimgewebe/[A-Za-z0-9_.-]+)\.git",
        remote,
    )
    slug = match["slug"] if match is not None else None
    supported = SUPPORTED_REPO.fullmatch(slug or "")
    if (
        supported is None
        or supported["name"] != repository_name
        or (expected_repo is not None and slug != expected_repo)
    ):
        raise provenance.ReviewExecutionRejected("review source repository origin invalid")
    return real, slug


def _current_source(repo: Path, binding: dict[str, Any]) -> str:
    real, _slug = _managed_repository_identity(
        repo, expected_repo=binding.get("repo") if isinstance(binding, dict) else None,
    )
    head = _read_command(real, ["rev-parse", "HEAD"]).decode().strip()
    if head != binding["head_sha"]:
        raise provenance.ReviewExecutionRejected("review checkout head changed")
    if _read_command(real, ["status", "--porcelain", "--untracked-files=normal"]):
        raise provenance.ReviewExecutionRejected("review checkout not clean")
    if _read_command(real, ["cat-file", "-t", binding["base_sha"]]).strip() != b"commit":
        raise provenance.ReviewExecutionRejected("review base commit absent")
    raw = _read_command(
        real,
        [
            "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
            "--ignore-submodules=none", "--raw", "--abbrev=40", "-z",
            binding["base_sha"], binding["head_sha"], "--",
        ],
        timeout=60,
    )
    return hashlib.sha256(raw).hexdigest()


def _binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise provenance.ReviewExecutionRejected("review plan identity not an object")
    expected = {"repo", "pr", "base_sha", "head_sha", "diff_sha256", "review_batch_id", "review_purpose"}
    if value.get("review_purpose") == "post_merge_release":
        expected.add("release_binding")
    if (
        set(value) != expected
        or not isinstance(value.get("repo"), str)
        or SUPPORTED_REPO.fullmatch(value["repo"]) is None
        or type(value.get("pr")) is not int or value["pr"] <= 0
        or any(not isinstance(value.get(k), str) or SHA.fullmatch(value[k]) is None for k in ("base_sha", "head_sha"))
        or not isinstance(value.get("diff_sha256"), str)
        or HEX64.fullmatch(value["diff_sha256"]) is None
        or not isinstance(value.get("review_batch_id"), str)
        or provenance.ID.fullmatch(value["review_batch_id"]) is None
        or value.get("review_purpose") not in {"pull_request", "post_merge_release"}
    ):
        raise provenance.ReviewExecutionRejected("review plan revision/source identity invalid")
    if value["review_purpose"] == "post_merge_release":
        release = value["release_binding"]
        if (
            not isinstance(release, dict)
            or set(release) != {"serving_release_id", "serving_tree", "target_tree"}
            or not isinstance(release["serving_release_id"], str) or not release["serving_release_id"]
            or any(not isinstance(release[k], str) or SHA.fullmatch(release[k]) is None
                   for k in ("serving_tree", "target_tree"))
        ):
            raise provenance.ReviewExecutionRejected("review plan release binding invalid")
    return dict(value)


def _task_command(
    binding: dict[str, Any], axis: str, worktree: Path,
    *, bwrap: str, python: str,
) -> list[str]:
    if (
        axis not in provenance.METHOD_TEST_SUITE
        or provenance._BWRAP_NIX.fullmatch(bwrap) is None
        or provenance._PYTHON_NIX.fullmatch(python) is None
    ):
        raise provenance.ReviewExecutionRejected("review runtime binary not installed from Nix")
    return [
        # Only the trusted outer method is import-isolated; child unittest can load candidate sources.
        bwrap, *provenance._sandbox_bwrap_flags(str(worktree)), "--", python, "-I", "-B", "-c",
        provenance.trusted_phase_source(binding, axis, str(worktree)),
    ]


def plan_review(
    *, repo: Path, pr: int, base_sha: str, head_sha: str,
    diff_sha256: str, bwrap: str, python: str,
    purpose: str = "pull_request",
    release_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create unique, frozen task plan. Does not dispatch or grant PASS."""
    real, repo_slug = _managed_repository_identity(repo)
    if repo_slug != "heimgewebe/grabowski":
        raise provenance.ReviewExecutionRejected(
            "isolated technical review tasks are Grabowski-specific"
        )
    candidate = {
        "repo": repo_slug, "pr": pr, "base_sha": base_sha,
        "head_sha": head_sha, "diff_sha256": diff_sha256,
        "review_batch_id": secrets.token_hex(16), "review_purpose": purpose,
        **({"release_binding": release_binding} if purpose == "post_merge_release" else {}),
    }
    binding = _binding(candidate)
    if release_binding is not None and purpose != "post_merge_release":
        raise provenance.ReviewExecutionRejected("release fields given for PR audit")
    raw_identity = _current_source(real, binding)
    if purpose == "post_merge_release" and binding["diff_sha256"] != raw_identity:
        raise provenance.ReviewExecutionRejected("full serving-to-target raw diff binding invalid")
    tasks = {
        axis: _task_command(binding, axis, real, bwrap=bwrap, python=python)
        for axis in METHODS
    }
    return {
        "schema_version": 1, "kind": "grabowski_self_review_execution_plan",
        "binding": binding, "worktree": str(real),
        "source_raw_diff_sha256": raw_identity,
        "tasks": tasks,
        "does_not_establish": [
            "executed_phases", "task_completion", "semantic_review",
            "signed_attestations", "Captain_authorization",
        ],
    }


def plan_first_party_review(
    *, repo: Path, pr: int, base_sha: str, head_sha: str,
    diff_sha256: str, purpose: str = "pull_request",
    release_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Freeze a source-only plan for the authenticated first-party reviewer."""
    if purpose != "pull_request" or release_binding is not None:
        raise provenance.ReviewExecutionRejected(
            "first-party direct plan supports pull requests only"
        )
    real, repo_slug = _managed_repository_identity(repo)
    candidate = {
        "repo": repo_slug, "pr": pr, "base_sha": base_sha,
        "head_sha": head_sha, "diff_sha256": diff_sha256,
        "review_batch_id": secrets.token_hex(16), "review_purpose": purpose,
    }
    binding = _binding(candidate)
    raw_identity = _current_source(real, binding)
    return {
        "schema_version": 1,
        "kind": "grabowski_first_party_review_plan",
        "binding": binding,
        "worktree": str(real),
        "source_raw_diff_sha256": raw_identity,
        "does_not_establish": [
            "source_inspection", "semantic_review", "review_pass",
            "technical_tests", "Captain_authorization",
        ],
    }


def _task_row(task_db: Path, task_id: str) -> dict[str, Any]:
    if TASK.fullmatch(task_id) is None:
        raise provenance.ReviewExecutionRejected("review task ID invalid")
    metadata = task_db.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise provenance.ReviewExecutionRejected("server task database authority invalid")
    from urllib.parse import quote
    uri = "file:" + quote(str(task_db.resolve(strict=True)), safe="/") + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=4)
        connection.row_factory = sqlite3.Row
        with connection:
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute(
                "SELECT task_id, host, cwd, argv_json, argv_sha256, "
                "unit, state, attempt, lifecycle_receipt_sha256, "
                "execution_backend, systemd_scope FROM tasks WHERE task_id=?",
                (task_id,),
            ).fetchone()
        connection.close()
    except (sqlite3.Error, OSError) as exc:
        raise provenance.ReviewExecutionRejected("server task state unavailable") from exc
    if row is None:
        raise provenance.ReviewExecutionRejected("review task not registered by server")
    return dict(row)


def _signed_task_origin(
    task_id: str, argv: list[str], worktree: Path,
    *,
    task_db: Path, outcomes: Path, capture_root: Path,
) -> tuple[dict[str, str], bytes]:
    row = _task_row(task_db, task_id)
    argv_sha256 = hashlib.sha256(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    if (
        row["host"] != "heim-pc" or row["cwd"] != str(worktree)
        or row["state"] != "completed" or row["attempt"] != 1
        or row["argv_sha256"] != argv_sha256
        or row["argv_json"] != json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
        or row["unit"] != f"grabowski-task-{task_id}-a1.service"
        or row["execution_backend"] != "systemd-user"
        or row["systemd_scope"] != "user"
        or not isinstance(row["lifecycle_receipt_sha256"], str)
        or HEX64.fullmatch(row["lifecycle_receipt_sha256"]) is None
    ):
        raise provenance.ReviewExecutionRejected("server task origin does not match frozen plan")
    output_fd = provenance._private_dir(capture_root)
    try:
        directory = f".grabowski-task-output-{task_id}-a1"
        fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=output_fd,
        )
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise provenance.ReviewExecutionRejected("task output directory not private")
            output = provenance._private_read(fd, "stdout.log", limit=provenance.MAX_OUTPUT)
            stderr = provenance._private_read(
                fd, "stderr.log", limit=provenance.MAX_OUTPUT, allow_empty=True,
            )
        finally:
            os.close(fd)
    finally:
        os.close(output_fd)
    if (
        stderr or b"\nOK\n" not in output
        or re.search(rb"Ran [1-9][0-9]* tests? in ", output) is None
    ):
        raise provenance.ReviewExecutionRejected("review task output did not pass")
    # Bind a genuine, completed systemd task lifecycle receipt to its argv.
    outcome_fd = provenance._private_dir(outcomes)
    try:
        data = provenance._private_read(
            outcome_fd, task_id + ".json", limit=provenance.MAX_RECEIPT,
        )
    finally:
        os.close(outcome_fd)
    try:
        outcome = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise provenance.ReviewExecutionRejected("server task lifecycle JSON unavailable") from exc
    receipt = outcome.get("receipt_sha256") if isinstance(outcome, dict) else None
    if (
        not isinstance(outcome, dict)
        or receipt != row["lifecycle_receipt_sha256"]
        or receipt != provenance._digest({
            k: v for k, v in outcome.items() if k != "receipt_sha256"
        })
        or outcome.get("task_id") != task_id
        or outcome.get("argv_sha256") != argv_sha256
        or outcome.get("state") != "completed"
    ):
        raise provenance.ReviewExecutionRejected("server task outcome does not attest command")
    return {
        "id": task_id, "unit": row["unit"],
        "argv_sha256": argv_sha256,
        "lifecycle_receipt_sha256": receipt,
    }, output


def _private_signing_key(key: Path) -> None:
    metadata = key.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise provenance.ReviewExecutionRejected("self-review private signing key unsafe")
    parent = key.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise provenance.ReviewExecutionRejected("self-review signing key directory unsafe")


def _sign(message: bytes, *, key: Path, signers: Path) -> bytes:
    _private_signing_key(key)
    try:
        result = subprocess.run(
            [provenance._trusted_ssh_keygen(), "-Y", "sign", "-f", str(key), "-n", provenance.NAMESPACE],
            input=message, capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise provenance.ReviewExecutionRejected("self-review signer unavailable") from exc
    if result.returncode != 0:
        raise provenance.ReviewExecutionRejected("self-review origin signature failed")
    provenance._check_signature(message, result.stdout, signers)
    return result.stdout


def _create_only(fd: int, name: str, data: bytes) -> None:
    if not isinstance(name, str) or "/" in name or len(name) > 100:
        raise provenance.ReviewExecutionRejected("receipt path invalid")
    descriptor = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600, dir_fd=fd,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _ensure_private_root(path: Path) -> int:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return provenance._private_dir(path)


def _review_report(phase: Any, *, axis: str, sequence: int, head: str, base: str, repo: Path) -> dict[str, Any]:
    if not isinstance(phase, dict) or set(phase) != {"summary", "evidence_refs", "material_findings"}:
        raise provenance.ReviewExecutionRejected("semantic phase report is missing or incomplete")
    summary, refs, findings = (
        phase["summary"], phase["evidence_refs"], phase["material_findings"],
    )
    if (
        not isinstance(summary, str) or len(" ".join(summary.split())) < 80
        or not isinstance(refs, list) or not 1 <= len(refs) <= provenance.MAX_REFERENCES
        or type(findings) is not int or findings != 0
    ):
        raise provenance.ReviewExecutionRejected("semantic phase report not fully triaged")
    for reference in refs:
        provenance._source_reference(reference, head=head, base=base, repository=repo, read_source=None)
    return {
        "n": sequence, "axis": axis, "summary": summary,
        "evidence_refs": list(refs), "material_findings": 0,
    }


def _seal_review(
    plan: dict[str, Any],
    task_ids: dict[str, str],
    phase_reports: dict[str, dict[str, Any]] | None,
    *,
    key: Path, signers: Path, receipts: Path,
    task_db: Path, outcomes: Path, capture_root: Path,
    repository: Path,
    root_owned_signers: bool,
    source_observer: Callable[[Path, dict[str, Any]], str] = _current_source,
) -> dict[str, Any]:
    if phase_reports is not None:
        raise provenance.ReviewExecutionRejected("caller-provided semantic phase reports forbidden")
    if (
        not isinstance(plan, dict)
        or plan.get("schema_version") != 1
        or plan.get("kind") != "grabowski_self_review_execution_plan"
        or not isinstance(plan.get("tasks"), dict)
        or set(plan["tasks"]) != set(METHODS)
        or not isinstance(task_ids, dict) or set(task_ids) != set(METHODS)
        or len(set(task_ids.values())) != len(METHODS)
    ):
        raise provenance.ReviewExecutionRejected("review execution plan or five tasks incomplete")
    binding = _binding(plan.get("binding"))
    worktree_value = plan.get("worktree")
    if not isinstance(worktree_value, str) or not worktree_value.startswith("/"):
        raise provenance.ReviewExecutionRejected("review source worktree invalid")
    worktree = Path(worktree_value)
    if not isinstance(plan.get("source_raw_diff_sha256"), str) or (
        HEX64.fullmatch(plan["source_raw_diff_sha256"]) is None
        or source_observer(worktree, binding) != plan["source_raw_diff_sha256"]
    ):
        raise provenance.ReviewExecutionRejected("review source changed after task plan")
    if (
        binding["review_purpose"] == "post_merge_release"
        and binding["diff_sha256"] != plan["source_raw_diff_sha256"]
    ):
        raise provenance.ReviewExecutionRejected("R3 whole-delta review identity invalid")
    if not isinstance(repository, Path):
        raise provenance.ReviewExecutionRejected("review source repository invalid")
    semantic_reviews = provenance.verified_semantic_review_passes(
        binding, repository=repository,
    )
    signer = provenance._allowed_signers(signers, root_owned=root_owned_signers)
    root_fd = _ensure_private_root(receipts)
    try:
        phases: list[dict[str, Any]] = []
        refs: list[dict[str, str]] = []
        seen: set[str] = set()
        for sequence, axis in enumerate(METHODS, start=1):
            command = plan["tasks"][axis]
            if (
                not isinstance(command, list)
                or len(command) < 20
                or not isinstance(command[0], str)
                or not isinstance(command[-3], str)
            ):
                raise provenance.ReviewExecutionRejected("untrusted phase task argv")
            exact = _task_command(
                binding, axis, worktree, bwrap=command[0], python=command[-5],
            )
            if exact != command:
                raise provenance.ReviewExecutionRejected("review plan task command altered")
            task_id = task_ids[axis]
            task, output = _signed_task_origin(
                task_id, command, worktree,
                task_db=task_db, outcomes=outcomes, capture_root=capture_root,
            )
            observed_report = provenance.observed_phase_report(
                output, binding=binding, axis=axis,
            )
            # The real semantic reviewer role is independently reconciled,
            # including its full source-bound model output and findings.
            # Green technical source-inspection tasks are never review passes.
            semantic = semantic_reviews[axis]
            phase = semantic["phase"]
            if phase["summary"] in seen:
                raise provenance.ReviewExecutionRejected("review phase reports duplicated")
            seen.add(phase["summary"])
            argv_sha = task["argv_sha256"]
            nonce = secrets.token_hex(16)
            semantic_kind = semantic.get("provenance_kind", "v2_model_role")
            if semantic_kind not in {
                "v2_model_role", "first_party_authenticated_controller",
            }:
                raise provenance.ReviewExecutionRejected(
                    "review semantic provenance kind invalid"
                )
            semantic_field = (
                "semantic_first_party"
                if semantic_kind == "first_party_authenticated_controller"
                else "semantic_v2"
            )
            record = {
                "schema_version": 1, "kind": provenance.KIND,
                "producer": provenance.PRODUCER,
                "binding": binding, "n": sequence, "axis": axis,
                "review_pass_sha256": provenance._digest(phase),
                "evidence_refs_sha256": provenance._digest(phase["evidence_refs"]),
                "stdout_sha256": hashlib.sha256(output).hexdigest(),
                "source_raw_diff_sha256": plan["source_raw_diff_sha256"],
                "source_inspection_report_sha256": provenance._digest(observed_report),
                semantic_field: semantic["provenance"],
                "sandbox": "isolated-read-only",
                "sandbox_argv": command, "worktree_path": str(worktree),
                "isolation_sha256": provenance._digest({
                    "argv_sha256": argv_sha,
                    "isolation_policy": "bwrap-readonly-no-net-v1", "axis": axis,
                }),
                "exit_code": 0, "execution_nonce": nonce,
                "observed_at_unix": int(__import__("time").time()),
                "task": task,
            }
            provenance._task_outcome(record, outcomes, output, capture_root=capture_root)
            material = provenance._canonical(record)
            signature = _sign(material, key=key, signers=signer)
            receipt_id = secrets.token_hex(16)
            _create_only(root_fd, receipt_id + ".json", material)
            _create_only(root_fd, receipt_id + ".out", output)
            _create_only(root_fd, receipt_id + ".sig", signature)
            phases.append(phase)
            refs.append({
                "id": receipt_id,
                "receipt_sha256": hashlib.sha256(material).hexdigest(),
                "signature_sha256": hashlib.sha256(signature).hexdigest(),
                "output_sha256": hashlib.sha256(output).hexdigest(),
            })
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    if source_observer(worktree, binding) != plan["source_raw_diff_sha256"]:
        raise provenance.ReviewExecutionRejected("review source changed while sealing")
    audit = {
        "schema_version": 1, "kind": "grabowski_self_review_audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": binding["repo"], "pr": binding["pr"],
        "base_sha": binding["base_sha"], "head_sha": binding["head_sha"],
        "diff_sha256": binding["diff_sha256"],
        "review_policy_version": 5, "review_tier": "high_critical",
        "independent_review_required": False,
        "minimum_review_iterations": 5,
        "actual_review_iterations": len(phases),
        "review_pass_axes": [item["axis"] for item in phases],
        "review_pass_evidence_sha256": hashlib.sha256(provenance._canonical(phases)).hexdigest(),
        "review_batch_id": binding["review_batch_id"],
        "review_purpose": binding["review_purpose"],
        **(
            {"release_binding": binding["release_binding"]}
            if binding["review_purpose"] == "post_merge_release" else {}
        ),
        "review_iterations": phases, "review_pass_receipts": refs,
        # These zero counts originate in real V2 reviewer PASS verdicts;
        # technical unittest success cannot supply or override findings.
        "all_findings_triaged": all(phase["material_findings"] == 0 for phase in phases),
        "finding_count": sum(phase["material_findings"] for phase in phases),
        "material_findings_after_first_review": phases[0]["material_findings"],
        "material_findings_remaining": sum(phase["material_findings"] for phase in phases),
        "uncertainty": 0.5, "residual_risk_accepted": False,
        "residual_risk_reason": "", "gate_verdict": "PASS",
        "self_review_gate_valid": True, "tuning_signal": "observe",
        "source_raw_diff_sha256": plan["source_raw_diff_sha256"],
    }
    provenance._verify(
        audit, receipts=receipts, outcomes=outcomes, signers=signer,
        repository=repository, now_unix=int(__import__("time").time()),
        root_owned_signers=root_owned_signers, capture_root=capture_root,
    )
    if binding["review_purpose"] == "post_merge_release":
        release_index = {
            "repo": binding["repo"], "review_pr": binding["pr"],
            "serving_head": binding["base_sha"], "target_head": binding["head_sha"],
            "diff_sha256": binding["diff_sha256"],
            "serving_release_id": binding["release_binding"]["serving_release_id"],
            "serving_tree": binding["release_binding"]["serving_tree"],
            "target_tree": binding["release_binding"]["target_tree"],
        }
        index_name = provenance._digest(release_index) + ".json"
        dest_root = R3_ROOT
    else:
        index_name = binding["review_batch_id"] + ".json"
        dest_root = receipts / "batches"
    index_fd = _ensure_private_root(dest_root)
    try:
        _create_only(index_fd, index_name, provenance._canonical(audit))
        os.fsync(index_fd)
    finally:
        os.close(index_fd)
    return {
        "status": "sealed_and_verified",
        "review_batch_id": binding["review_batch_id"],
        "review_pass_count": len(phases),
        "review_audit_sha256": provenance._digest(audit),
        "audit_path": str(dest_root / index_name),
        "source_head": binding["head_sha"],
        "does_not_establish": ["Captain_merge", "runtime_deployment", "human_independent_review"],
    }


def seal_review(
    plan: dict[str, Any], task_ids: dict[str, str],
    phase_reports: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Production entrypoint: no caller-selected signer or evidence roots."""
    return _seal_review(
        plan, task_ids, phase_reports,
        key=SIGNING_KEY, signers=SIGNERS, receipts=RECEIPTS,
        task_db=TASK_DB, outcomes=OUTCOMES, capture_root=CAPTURE_ROOT,
        repository=CANONICAL_REPO, root_owned_signers=True,
    )


def _seal_first_party_review(
    plan: dict[str, Any], *, signers: Path, receipts: Path,
    first_party_root: Path, repository: Path,
    root_owned_signers: bool, now_unix: int | None = None,
) -> dict[str, Any]:
    """Seal only the already-signed controller session/read/axis records."""
    if (
        not isinstance(plan, dict)
        or plan.get("schema_version") != 1
        or plan.get("kind") != "grabowski_first_party_review_plan"
        or "tasks" in plan
    ):
        raise provenance.ReviewExecutionRejected("first-party direct plan invalid")
    signer = provenance._allowed_signers(
        signers, root_owned=root_owned_signers,
    )
    binding = _binding(plan.get("binding"))
    worktree_raw = plan.get("worktree")
    if not isinstance(worktree_raw, str) or not worktree_raw.startswith("/"):
        raise provenance.ReviewExecutionRejected("first-party direct worktree invalid")
    worktree, _slug = _managed_repository_identity(
        Path(worktree_raw), expected_repo=binding["repo"],
    )
    supplied, _supplied_slug = _managed_repository_identity(
        repository, expected_repo=binding["repo"],
    )
    if supplied != worktree:
        raise provenance.ReviewExecutionRejected(
            "first-party direct repository crossed plan"
        )
    source_raw = plan.get("source_raw_diff_sha256")
    if (
        not isinstance(source_raw, str)
        or HEX64.fullmatch(source_raw) is None
        or _current_source(worktree, binding) != source_raw
    ):
        raise provenance.ReviewExecutionRejected("first-party direct source drift")
    observed_at = int(__import__("time").time()) if now_unix is None else now_unix
    semantic_reviews = provenance.verified_first_party_semantic_review_passes(
        binding, repository=worktree, root=first_party_root, signers=signer,
        root_owned_signers=root_owned_signers, now_unix=observed_at,
    )
    phases: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    summaries: set[str] = set()
    for axis in METHODS:
        semantic = semantic_reviews[axis]
        phase = semantic["phase"]
        if phase["summary"] in summaries:
            raise provenance.ReviewExecutionRejected(
                "first-party direct phase summaries duplicated"
            )
        summaries.add(phase["summary"])
        phases.append(phase)
        refs.append({
            "kind": provenance.FIRST_PARTY_AUDIT_ORIGIN,
            "axis": axis,
            "repo": binding["repo"],
            "base_sha": binding["base_sha"],
            "head_sha": binding["head_sha"],
            "diff_sha256": binding["diff_sha256"],
            "binding_sha256": provenance._digest(binding),
            **semantic["provenance"],
        })
    audit = {
        "schema_version": 1,
        "kind": "grabowski_self_review_audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": binding["repo"], "pr": binding["pr"],
        "base_sha": binding["base_sha"], "head_sha": binding["head_sha"],
        "diff_sha256": binding["diff_sha256"],
        "review_policy_version": 5, "review_tier": "high_critical",
        "review_origin": provenance.FIRST_PARTY_AUDIT_ORIGIN,
        "independent_review_required": False,
        "minimum_review_iterations": 5,
        "actual_review_iterations": len(phases),
        "review_pass_axes": [item["axis"] for item in phases],
        "review_pass_evidence_sha256": hashlib.sha256(
            provenance._canonical(phases)
        ).hexdigest(),
        "review_batch_id": binding["review_batch_id"],
        "review_purpose": binding["review_purpose"],
        **(
            {"release_binding": binding["release_binding"]}
            if binding["review_purpose"] == "post_merge_release" else {}
        ),
        "review_iterations": phases,
        "review_pass_receipts": refs,
        "all_findings_triaged": True,
        "finding_count": 0,
        "material_findings_after_first_review": 0,
        "material_findings_remaining": 0,
        "uncertainty": 0.5,
        "residual_risk_accepted": False,
        "residual_risk_reason": "",
        "gate_verdict": "PASS",
        "self_review_gate_valid": True,
        "tuning_signal": "observe",
        "source_raw_diff_sha256": source_raw,
    }
    provenance._verify(
        audit, receipts=receipts, outcomes=OUTCOMES, signers=signer,
        repository=worktree, now_unix=observed_at,
        root_owned_signers=root_owned_signers,
        first_party_root=first_party_root,
    )
    destination = receipts / "batches"
    descriptor = _ensure_private_root(destination)
    try:
        name = binding["review_batch_id"] + ".json"
        _create_only(descriptor, name, provenance._canonical(audit))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "status": "sealed_and_verified",
        "review_batch_id": binding["review_batch_id"],
        "review_pass_count": len(phases),
        "review_audit_sha256": provenance._digest(audit),
        "audit_path": str(destination / name),
        "source_head": binding["head_sha"],
        "does_not_establish": [
            "technical_tests", "Captain_merge", "runtime_deployment",
            "human_independent_review",
        ],
    }


def seal_first_party_review(plan: dict[str, Any]) -> dict[str, Any]:
    """Production direct sealer with server-owned roots only."""
    worktree = plan.get("worktree") if isinstance(plan, dict) else None
    if not isinstance(worktree, str):
        raise provenance.ReviewExecutionRejected("first-party direct worktree absent")
    return _seal_first_party_review(
        plan, signers=SIGNERS, receipts=RECEIPTS,
        first_party_root=provenance.FIRST_PARTY_REVIEW_ROOT,
        repository=Path(worktree), root_owned_signers=True,
    )

def _require_installed_runtime(bwrap: str, python: str) -> None:
    """Only root-owned immutable executable entries may enter a trusted task plan."""
    for item, pattern in (
        (bwrap, provenance._BWRAP_NIX),
        (python, provenance._PYTHON_NIX),
    ):
        if not isinstance(item, str) or pattern.fullmatch(item) is None:
            raise provenance.ReviewExecutionRejected("trusted review Nix executable invalid")
        candidate = Path(item)
        link = candidate.lstat()
        if link.st_uid != 0 or (
            not stat.S_ISREG(link.st_mode) and not stat.S_ISLNK(link.st_mode)
        ):
            raise provenance.ReviewExecutionRejected("trusted review binary link authority invalid")
        target = candidate.resolve(strict=True)
        if not target.is_relative_to(Path("/nix/store")):
            raise provenance.ReviewExecutionRejected("trusted review binary escapes Nix store")
        metadata = target.stat()
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or not metadata.st_mode & stat.S_IXUSR
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise provenance.ReviewExecutionRejected("trusted review executable mutable or unavailable")


def _require_live_pr(binding: dict[str, Any]) -> None:
    """PR identity is observed from GitHub, not asserted by the sealing caller."""
    if binding["review_purpose"] != "pull_request":
        return
    try:
        observed = subprocess.run(
            [
                "gh", "pr", "view", str(binding["pr"]), "--repo",
                binding["repo"], "--json",
                "number,state,headRefOid,baseRefOid,headRefName,baseRefName",
            ],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise provenance.ReviewExecutionRejected("live PR observation unavailable") from exc
    if observed.returncode != 0 or len(observed.stdout) > 16384:
        raise provenance.ReviewExecutionRejected("live PR observation failed")
    try:
        item = json.loads(observed.stdout)
    except (TypeError, ValueError) as exc:
        raise provenance.ReviewExecutionRejected("live PR observation invalid") from exc
    if (
        not isinstance(item, dict)
        or item.get("number") != binding["pr"]
        or item.get("state") != "OPEN"
        or item.get("baseRefName") != "main"
        or item.get("baseRefOid") != binding["base_sha"]
        or item.get("headRefOid") != binding["head_sha"]
    ):
        raise provenance.ReviewExecutionRejected("live PR revision/base drift")


def _store_plan(plan: dict[str, Any]) -> Path:
    identifier = plan["binding"]["review_batch_id"]
    raw = provenance._canonical(plan)
    if len(raw) > MAX_PLAN_BYTES:
        raise provenance.ReviewExecutionRejected("review plan exceeds bounded private record budget")
    root = RECEIPTS / "plans"
    fd = _ensure_private_root(root)
    try:
        _create_only(fd, identifier + ".json", raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    return root / (identifier + ".json")


def _load_plan(identifier: str) -> dict[str, Any]:
    if not isinstance(identifier, str) or provenance.ID.fullmatch(identifier) is None:
        raise provenance.ReviewExecutionRejected("review batch id invalid")
    fd = provenance._private_dir(RECEIPTS / "plans")
    try:
        raw = provenance._private_read(fd, identifier + ".json", limit=MAX_PLAN_BYTES)
    finally:
        os.close(fd)
    try:
        plan = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise provenance.ReviewExecutionRejected("stored review plan malformed") from exc
    if (
        not isinstance(plan, dict)
        or provenance._canonical(plan) != raw
        or plan.get("binding", {}).get("review_batch_id") != identifier
    ):
        raise provenance.ReviewExecutionRejected("stored review plan identity changed")
    return plan


def main(argv: list[str] | None = None) -> int:
    """Durable operator CLI; only plan and seal, never a caller-declared PASS."""
    import argparse
    parser = argparse.ArgumentParser(description="Grabowski authentic review-task producer")
    commands = parser.add_subparsers(dest="operation", required=True)
    new = commands.add_parser("plan", help="Emit and preserve exact read-only task argv")
    for name in ("repo", "base", "head", "diff", "bwrap", "python"):
        new.add_argument("--" + name, required=True)
    new.add_argument("--pr", type=int, required=True)
    new.add_argument(
        "--purpose", choices=("pull_request", "post_merge_release"),
        default="pull_request",
    )
    for name in ("serving-release-id", "serving-tree", "target-tree"):
        new.add_argument("--" + name)
    first_party = commands.add_parser(
        "plan-firstparty",
        help="Freeze source-only review identity for authenticated MCP review",
    )
    for name in ("repo", "base", "head", "diff"):
        first_party.add_argument("--" + name, required=True)
    first_party.add_argument("--pr", type=int, required=True)
    existing = commands.add_parser("seal", help="Sign real completed task executions only")
    existing.add_argument("--batch-id", required=True)
    existing.add_argument("--task-ids-json", required=True)
    direct = commands.add_parser(
        "seal-firstparty", help="Seal existing signed first-party review records",
    )
    direct.add_argument("--batch-id", required=True)
    args = parser.parse_args(argv)
    if args.operation == "plan":
        _require_installed_runtime(args.bwrap, args.python)
        release = None
        if args.purpose == "post_merge_release":
            release = {
                "serving_release_id": args.serving_release_id,
                "serving_tree": args.serving_tree, "target_tree": args.target_tree,
            }
        elif any(x is not None for x in (
            args.serving_release_id, args.serving_tree, args.target_tree,
        )):
            raise provenance.ReviewExecutionRejected("PR review may not include release fields")
        new_plan = plan_review(
            repo=Path(args.repo), pr=args.pr, base_sha=args.base,
            head_sha=args.head, diff_sha256=args.diff,
            bwrap=args.bwrap, python=args.python, purpose=args.purpose,
            release_binding=release,
        )
        _require_live_pr(new_plan["binding"])
        stored = _store_plan(new_plan)
        # Never write the complete task plan to process output: its embedded
        # job arguments may contain operator-supplied material. The create-only
        # private plan is retrieved by an authorized task dispatcher.
        public_result = {
            "status": "planned_not_executed",
            "review_batch_id": new_plan["binding"]["review_batch_id"],
            "task_count": len(new_plan["tasks"]),
            "task_manifest_sha256": provenance._digest(new_plan["tasks"]),
            "does_not_establish": [
                "executed_phases", "task_completion", "semantic_review",
                "signed_attestations", "Captain_authorization",
            ],
        }
    elif args.operation == "plan-firstparty":
        new_plan = plan_first_party_review(
            repo=Path(args.repo), pr=args.pr, base_sha=args.base,
            head_sha=args.head, diff_sha256=args.diff,
        )
        _require_live_pr(new_plan["binding"])
        _store_plan(new_plan)
        public_result = {
            "status": "first_party_planned_not_executed",
            "review_batch_id": new_plan["binding"]["review_batch_id"],
            "repo": new_plan["binding"]["repo"],
            "does_not_establish": [
                "source_inspection", "semantic_review", "review_pass",
                "technical_tests", "Captain_authorization",
            ],
        }
    elif args.operation == "seal":
        plan = _load_plan(args.batch_id)
        _require_live_pr(plan["binding"])
        try:
            ids = json.loads(args.task_ids_json)
            reports = None
        except (UnicodeError, ValueError) as exc:
            raise provenance.ReviewExecutionRejected("phase task or review data invalid") from exc
        sealed = seal_review(plan, ids, reports)
        # Deliberately exclude arbitrary task output, private file paths and
        # semantic report text from logging and machine-readable stdout.
        public_result = {
            "status": "sealed_and_verified",
            "review_batch_id": args.batch_id,
            "review_pass_count": sealed["review_pass_count"],
            "review_audit_sha256": sealed["review_audit_sha256"],
            "source_head": sealed["source_head"],
        }
    else:
        plan = _load_plan(args.batch_id)
        _require_live_pr(plan["binding"])
        sealed = seal_first_party_review(plan)
        public_result = {
            "status": "sealed_and_verified",
            "review_batch_id": args.batch_id,
            "review_pass_count": sealed["review_pass_count"],
            "review_audit_sha256": sealed["review_audit_sha256"],
            "source_head": sealed["source_head"],
            "does_not_establish": ["technical_tests", "Captain_merge"],
        }
    print(json.dumps(public_result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())