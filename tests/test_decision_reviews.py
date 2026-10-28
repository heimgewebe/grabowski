from pathlib import Path
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import grabowski_decision_reviews as reviews
import grabowski_agent_role as agent_role
import grabowski_job_origin as job_origin


HEAD = "a" * 40
BASE = "b" * 40
DIFF = "c" * 64
ALIAS_DIFF = "d" * 64
REPO = "heimgewebe/vibe-lab"
PR = 350


def binding(slot: str, *, diff_sha256: str = DIFF) -> dict:
    return {
        "schema_version": 1,
        "kind": reviews.BINDING_KIND,
        "repo": REPO,
        "pr": PR,
        "head_sha": HEAD,
        "base_sha": BASE,
        "diff_sha256": diff_sha256,
        "slot": slot,
    }


def result(slot: str, verdict: str, findings: int, *, diff_sha256: str = DIFF) -> dict:
    return {
        "schema_version": 1,
        "kind": reviews.RESULT_KIND,
        "repo": REPO,
        "pr": PR,
        "head_sha": HEAD,
        "base_sha": BASE,
        "diff_sha256": diff_sha256,
        "slot": slot,
        "verdict": verdict,
        "material_findings": findings,
    }


def write_private(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")
    os.chmod(path, 0o600)


def python_rotation_fixture(
    root: Path, *, historical_module_bytes: bytes | None = None
) -> dict[str, Path]:
    current_python = root / "current-python"
    current_python.write_text("#!/bin/sh\n", encoding="utf-8")
    current_python.chmod(0o700)
    release_root = root / "releases"

    def release_python(release_id: str) -> Path:
        path = release_root / release_id / ".venv" / "bin" / "python"
        path.parent.mkdir(parents=True)
        path.symlink_to(current_python)
        return path

    current_release_python = release_python(
        "111111111111-srcset111111111111-lock111111111111-contract111111111111"
    )
    historical_release_python = release_python(
        "0123456789ab-srcset0123456789ab-lock0123456789ab-contract0123456789ab"
    )
    current_release_venv = current_release_python.parents[1]

    stable_root = root / "stable"
    stable_root.mkdir()
    (stable_root / ".venv").symlink_to(
        current_release_venv,
        target_is_directory=True,
    )
    stable_python = stable_root / ".venv" / "bin" / "python"

    historical_module = (
        historical_release_python.parents[1]
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
        / f"{reviews.REVIEW_ROLE_MODULE}.py"
    )
    if historical_module_bytes is not None:
        historical_module.parent.mkdir(parents=True)
        historical_module.write_bytes(historical_module_bytes)

    return {
        "current_python": current_python,
        "release_root": release_root,
        "current_release_python": current_release_python,
        "current_release_venv": current_release_venv,
        "historical_release_python": historical_release_python,
        "historical_module": historical_module,
        "stable_python": stable_python,
    }


def rotated_runner_provenance(provenance: dict, runner_python: Path) -> dict:
    rotated = dict(provenance)
    rotated["runner_python"] = str(runner_python)
    material = {
        key: value
        for key, value in rotated.items()
        if key != "provenance_sha256"
    }
    rotated["provenance_sha256"] = reviews.sha256_json(material)
    return rotated


def patch_rotation(
    fixture: dict[str, Path],
    runner_python: Path,
    *,
    bind_launcher: bool = False,
):
    values = {
        "REVIEW_ROLE_PYTHON": str(runner_python),
        "REVIEW_ROLE_STABLE_PYTHON": fixture["stable_python"],
        "REVIEW_ROLE_STABLE_VENV_TARGET": fixture["current_release_venv"],
        "REVIEW_ROLE_RELEASE_ROOT": fixture["release_root"],
    }
    if bind_launcher:
        values["REVIEW_ROLE_LAUNCHER_PREFIX"] = (
            str(runner_python),
            "-I",
            "-m",
            reviews.REVIEW_ROLE_MODULE,
        )
    return mock.patch.multiple(reviews, **values)


def make_job(
    jobs: Path,
    *,
    suffix: str,
    slot: str,
    terminal_status: str | None,
    review_result: dict | None,
    diff_sha256: str = DIFF,
    review_role: bool = False,
    attempt_bound: bool = False,
    legacy_role_receipt_parent: Path | None = None,
    origin_provenance: bool = True,
    attempt_epoch: int | None = None,
    metadata_argv_override: list[str] | None = None,
    created_at_unix: int = 1_787_000_000,
    started_at_unix_ns: int | None = None,
    role_command_override: list[str] | None = None,
) -> Path:
    unit = f"grabowski-job-{suffix}"
    directory = jobs / unit
    directory.mkdir(parents=True)
    os.chmod(directory, 0o700)
    normalized_binding = reviews.normalize_binding(
        binding(slot, diff_sha256=diff_sha256)
    )
    role_command = [
        "claude",
        "--model",
        "claude-opus-5-5",
        "--effort",
        "high",
        "--permission-mode",
        "plan",
        "Review the frozen revision",
    ]
    if role_command_override is not None:
        role_command = role_command_override
    role_receipt_path = (
        directory / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
        if attempt_bound else
        (legacy_role_receipt_parent or directory) / "review-role-receipt.json"
    )
    job_argv = (
        [
            reviews.REVIEW_ROLE_PYTHON,
            "-I",
            "-m",
            reviews.REVIEW_ROLE_MODULE,
            "--role",
            "review",
            "--repository",
            "/tmp/review",
            "--expected-head",
            HEAD,
            "--expected-base-head",
            BASE,
            "--expected-diff-sha256",
            "e" * 64,
            "--expected-dirty",
            "false",
            "--output",
            str(role_receipt_path),
            "--",
            *role_command,
        ]
        if review_role
        else ["python3", "-c", "print('review')"]
    )
    argv_sha = reviews.sha256_json(job_argv)
    scope = {
        "cwd": "/tmp/review",
        "argv_sha256": argv_sha,
        "runtime_seconds": 60,
        "decision_bound_review": normalized_binding,
    }
    if started_at_unix_ns is not None:
        scope["started_at_unix_ns"] = started_at_unix_ns
    if attempt_epoch is not None:
        scope["decision_review_attempt_epoch"] = attempt_epoch
    if review_role and origin_provenance:
        provenance = reviews.review_role_provenance(
            job_argv, normalized_binding, cwd=Path("/tmp/review"),
            attempt_directory=directory if attempt_bound else None,
        )
        assert provenance is not None
        scope["decision_review_provenance"] = provenance
    with (
        mock.patch.object(
            job_origin, "DECISION_REVIEW_ORDER_ROOT", jobs.parent / "decision-review-order"
        ),
        mock.patch.object(job_origin, "DECISION_REVIEW_JOBS_ROOT", jobs),
    ):
        origin, origin_sha = job_origin.build_origin(
            unit=unit,
            owner="uid:1000",
            argv_sha256=argv_sha,
            scope=scope,
            notify_on_done={"requested": False, "channels": []},
            created_at_unix=created_at_unix,
            started_at="2026-08-18T12:00:00Z",
            invoker_tool="grabowski_job_start",
        )
    contract_material = {
        "schema_version": 1,
        "kind": "grabowski_job_finalization",
        "unit": unit,
        "job_id": suffix,
        "argv_sha256": argv_sha,
        "receipt_paths": {
            "metadata": str(directory / "metadata.json"),
            "stdout": str(directory / "stdout.log"),
            "stderr": str(directory / "stderr.log"),
            "finalization": str(directory / "finalization.json"),
        },
    }
    contract = {
        **contract_material,
        "contract_sha256": reviews.sha256_json(contract_material),
    }
    metadata = {
        "schema_version": 2,
        "unit": unit,
        "job_id": suffix,
        "owner": "uid:1000",
        "scope": scope,
        "origin": origin,
        "origin_sha256": origin_sha,
        "argv": job_argv if metadata_argv_override is None else metadata_argv_override,
        "argv_sha256": argv_sha,
        "cwd": "/tmp/review",
        "created_at_unix": created_at_unix,
        "finalization_contract": contract,
    }
    write_private(directory / "metadata.json", json.dumps(metadata))
    marker = ""
    if review_result is not None:
        marker = reviews.RESULT_PREFIX + json.dumps(review_result, separators=(",", ":")) + "\n"
    write_private(directory / "stdout.log", marker)
    write_private(directory / "stderr.log", "")
    if review_role:
        role_receipt = {
            "schema_version": 1,
            "role": "review",
            "expected_head": HEAD,
            "expected_base_head": BASE,
            "expected_diff_sha256": "e" * 64,
            "expected_dirty": False,
            "head_before": HEAD,
            "head_after": HEAD,
            "diff_after": "e" * 64,
            "worktree_dirty_after": False,
            "argv_sha256": reviews.sha256_json(role_command),
            "returncode": 0,
            "sandbox": reviews.REVIEW_ROLE_SANDBOX,
            "review_receipt_generated_by": reviews.REVIEW_ROLE_MODULE,
            "verdict": "PASS",
            "findings": [],
            "failure_classification": "passed",
        }
        if attempt_bound:
            role_receipt["review_attempt_unit"] = unit
            role_receipt["review_attempt_origin_sha256"] = origin_sha
        role_receipt["receipt_sha256"] = reviews._agent_role_receipt_sha256(
            role_receipt
        )
        write_private(role_receipt_path, json.dumps(role_receipt))
    if terminal_status is not None:
        final_material = {
            **contract,
            "final_status": terminal_status,
            "completion_status": "complete" if terminal_status == "succeeded" else "failed",
            "failure_type": None if terminal_status == "succeeded" else terminal_status,
            "timestamp_unix": 1_787_000_100,
        }
        final = {
            **final_material,
            "payload_sha256": reviews.sha256_json(final_material),
        }
        write_private(directory / "finalization.json", json.dumps(final))
    return directory


ZERO_CLAUDE_SUBAGENTS = {
    "spawned": 0, "started_in_background": 0, "max_depth": 0,
    "spawned_by_subagents": 0, "completed": 0, "failed": 0,
    "requested": {"background": 0, "foreground": 0, "unset": 0},
    "refused": {"depth_limit": 0, "concurrency_limit": 0, "budget": 0},
    "killed": {"parent": 0, "user": 0, "system": 0},
    "by_type": {},
}


def stamp_claude_quota_429(directory: Path, *, envelope_updates: dict | None = None,
                           receipt_updates: dict | None = None) -> None:
    """Synthetic exact transcript and job-owned V2 receipt, no provider call."""
    receipt_path = directory / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    envelope = {
        "type": "result", "is_error": True, "terminal_reason": "api_error",
        "api_error_status": 429, "duration_api_ms": 0, "modelUsage": {},
        "permission_denials": [], "total_cost_usd": 0,
        "usage": {
            "input_tokens": 0, "output_tokens": 0, "iterations": [],
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
            "output_tokens_details": {"thinking_tokens": 0},
            "cache_creation": {
                "ephemeral_1h_input_tokens": 0, "ephemeral_5m_input_tokens": 0,
            },
            "service_tier": "standard", "speed": "standard",
            "inference_geo": "", "fallback_credit": None,
            "server_tool_use": {"web_search_requests": 0, "web_fetch_requests": 0},
        },
        "subagent_stats": ZERO_CLAUDE_SUBAGENTS,
        "result": "You've hit your weekly limit",
    }
    amendments = dict(envelope_updates or {})
    if "usage" in amendments and isinstance(amendments["usage"], dict):
        usage_amendments = amendments.pop("usage")
        envelope["usage"] = {**envelope["usage"], **usage_amendments}
    envelope.update(amendments)
    payload = (json.dumps(envelope, separators=(",", ":")) + "\n").encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    receipt.update({
        "verdict": "INVALID", "findings": [], "returncode": 126,
        "failure_classification": "invalid_review_output",
        "stdout_tail": payload.decode("utf-8"),
        "stdout_bytes": len(payload), "stdout_sha256": digest,
        "review_provider_envelope_bytes": len(payload),
        "review_provider_envelope_sha256": digest,
        "review_provider_contract": "claude-headless-bound-diff-json-v1",
        "review_document_bytes": 0, "review_document_sha256": None,
        "review_findings_normalized": False, "stderr_bytes": 0,
    })
    receipt.update(receipt_updates or {})
    receipt["receipt_sha256"] = reviews._agent_role_receipt_sha256(receipt)
    write_private(receipt_path, json.dumps(receipt))


class DecisionReviewReconciliationTests(unittest.TestCase):
    def test_rgpm_signed_v2_review_pass_cannot_grant_captain_authority(self) -> None:
        # Construct a valid foreign-namespace reviewer under the old, widened
        # unit matcher.  The actual reconciler must never accept that PASS.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            with (
                mock.patch.object(reviews, "_UNIT_RE", job_origin.UNIT_RE),
                mock.patch.object(
                    job_origin, "_DECISION_REVIEW_UNIT_RE", job_origin.UNIT_RE
                ),
            ):
                make_job(
                    jobs, suffix="rgpm-0123456789abcdef-01", slot="A",
                    terminal_status="succeeded",
                    review_result=result("A", "PASS_THIS_REVISION", 0),
                    review_role=True, attempt_bound=True, attempt_epoch=2,
                )
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertEqual(checked["attempt_count"], 0)
        self.assertIn(
            "decision_review_noncanonical_job_unverifiable", checked["errors"]
        )

    def test_genuine_rgpm_job_without_review_evidence_does_not_block(self) -> None:
        # RepoGround has its own signed job namespace, not R3 authority.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            unit = "grabowski-job-rgpm-0123456789abcdef-01"
            directory = jobs / unit
            directory.mkdir(mode=0o700)
            scope = {
                "cwd": "/tmp", "argv_sha256": "e" * 64,
                "runtime_seconds": 60,
            }
            origin, digest = job_origin.build_origin(
                unit=unit, owner=f"uid:{os.getuid()}",
                argv_sha256="e" * 64, scope=scope,
                notify_on_done={"requested": False, "channels": []},
                created_at_unix=1_787_000_000,
                started_at="2026-08-18T12:00:00Z",
                invoker_tool="grabowski_job_start",
            )
            metadata = {
                "unit": unit, "job_id": origin["job_id"],
                "owner": origin["owner"],
                "argv_sha256": origin["argv_sha256"],
                "scope": origin["scope"],
                "origin": origin, "origin_sha256": digest,
            }
            write_private(directory / "metadata.json", json.dumps(metadata))
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "not_applicable")
        self.assertEqual(checked["attempt_count"], 0)
        self.assertEqual(checked["errors"], [])

    def test_rgpm_origin_rebind_cannot_hide_retained_material_reject(self) -> None:
        # A hash-valid ordinary RepoGround origin alone does not authenticate
        # the absence of a former exact-revision R3 result. Preserve stdout.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa101", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            rejected = make_job(
                jobs, suffix="bbbbbbbbb102", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            self.assertEqual(self.reconcile(jobs)["status"], "blocked")
            preserved_stdout = (rejected / "stdout.log").read_bytes()
            foreign = jobs / "grabowski-job-rgpm-0123456789abcdef-01"
            rejected.rename(foreign)
            scope = {
                "cwd": "/tmp", "argv_sha256": "e" * 64,
                "runtime_seconds": 60,
            }
            rebound, digest = job_origin.build_origin(
                unit=foreign.name, owner=f"uid:{os.getuid()}",
                argv_sha256="e" * 64, scope=scope,
                notify_on_done={"requested": False, "channels": []},
                created_at_unix=1_787_000_000,
                started_at="2026-08-18T12:00:00Z",
                invoker_tool="grabowski_job_start",
            )
            write_private(foreign / "metadata.json", json.dumps({
                "unit": rebound["unit"], "job_id": rebound["job_id"],
                "owner": rebound["owner"],
                "argv_sha256": rebound["argv_sha256"],
                "scope": rebound["scope"],
                "origin": rebound, "origin_sha256": digest,
            }))
            self.assertEqual(
                preserved_stdout, (foreign / "stdout.log").read_bytes(),
            )
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        # Foreign evidence is inspected before canonical attempts; a strict
        # failure can abort the scan without claiming a partial attempt list.
        self.assertEqual(checked["attempt_count"], 0)
        self.assertIn(
            f"decision_review_unbound_result:{foreign.name}", checked["errors"],
        )

    def test_rgpm_missing_metadata_with_retained_reject_still_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa104", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            rejected = make_job(
                jobs, suffix="bbbbbbbbb105", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            original_stdout = (rejected / "stdout.log").read_bytes()
            foreign = jobs / "grabowski-job-rgpm-0123456789abcdef-03"
            rejected.rename(foreign)
            (foreign / "metadata.json").unlink()
            self.assertEqual(original_stdout, (foreign / "stdout.log").read_bytes())
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn(
            f"decision_review_unbound_result:{foreign.name}", checked["errors"],
        )

    def test_rgpm_ordinary_stdout_without_bound_evidence_stays_nonblocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa103", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            ordinary = jobs / "grabowski-job-rgpm-0123456789abcdef-02"
            ordinary.mkdir(mode=0o700)
            scope = {
                "cwd": "/tmp", "argv_sha256": "e" * 64,
                "runtime_seconds": 60,
            }
            signed, digest = job_origin.build_origin(
                unit=ordinary.name, owner=f"uid:{os.getuid()}",
                argv_sha256="e" * 64, scope=scope,
                notify_on_done={"requested": False, "channels": []},
                created_at_unix=1_787_000_000,
                started_at="2026-08-18T12:00:00Z",
                invoker_tool="grabowski_job_start",
            )
            write_private(ordinary / "metadata.json", json.dumps({
                "unit": signed["unit"], "job_id": signed["job_id"],
                "owner": signed["owner"],
                "argv_sha256": signed["argv_sha256"],
                "scope": signed["scope"],
                "origin": signed, "origin_sha256": digest,
            }))
            write_private(ordinary / "stdout.log", "ordinary RepoGround output\\n")
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "settled")
        self.assertEqual(checked["errors"], [])
        self.assertEqual(checked["attempt_count"], 1)

    def test_unrelated_historical_review_count_cannot_hide_material_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa901", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            make_job(
                jobs, suffix="bbbbbbbbb902", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            # A historic attempt count is not an admission budget. The bounded
            # full directory and metadata scan must still find the late REJECT.
            with mock.patch.object(reviews, "MAX_BOUND_REVIEW_JOBS", 1, create=True):
                checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertEqual(checked["attempt_count"], 2)
        self.assertEqual(checked["slots"][0]["material_reject_count"], 1)
        self.assertFalse(
            any("inventory_truncated" in error for error in checked["errors"]),
            checked["errors"],
        )

    def test_noncanonical_renamed_reject_blocks_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            reject = make_job(
                jobs, suffix="aaaaaaaaa111", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            reject.rename(jobs / "foreign-renamed-review")
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn("decision_review_noncanonical_job_directory", checked["errors"])
        self.assertEqual(checked["attempt_count"], 0)

    def test_noncanonical_missing_metadata_cannot_hide_retained_reject(self) -> None:
        # Renaming a former review to an arbitrary private bundle and removing
        # its metadata must not hide an otherwise unchanged material REJECT.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa506", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            rejected = make_job(
                jobs, suffix="bbbbbbbbb507", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            self.assertEqual(self.reconcile(jobs)["status"], "blocked")
            preserved_stdout = (rejected / "stdout.log").read_bytes()
            foreign = jobs / "renamed-retained-review-evidence"
            rejected.rename(foreign)
            (foreign / "metadata.json").unlink()
            # A readable-but-not-other-writable legacy mode must not erase
            # retained REJECT bytes or be interpreted as review authority.
            (foreign / "stdout.log").chmod(0o644)
            self.assertEqual(preserved_stdout, (foreign / "stdout.log").read_bytes())
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn(
            f"decision_review_unbound_result:{foreign.name}", checked["errors"],
        )

    def test_noncanonical_bundle_stdout_without_review_evidence_is_nonblocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa508", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            bundle = jobs / "report-bundle"
            bundle.mkdir(mode=0o700)
            write_private(bundle / "evaluation.json", "{}")
            write_private(bundle / "stdout.log", "unrelated report output\\n")
            # Historical power-worker logs used 0644 below an owner-private
            # job directory, so no other uid could traverse the parent.
            (bundle / "stdout.log").chmod(0o644)
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "settled")
        self.assertEqual(checked["errors"], [])

    def test_noncanonical_world_writable_stdout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa509", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            foreign = jobs / "report-bundle"
            foreign.mkdir(mode=0o700)
            write_private(foreign / "stdout.log", "ordinary output")
            (foreign / "stdout.log").chmod(0o666)
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn(
            f"decision_review_unbound_evidence_invalid:{foreign.name}:ValueError",
            checked["errors"],
        )

    def test_noncanonical_bundle_without_job_metadata_is_not_a_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            other = jobs / "report-bundle"
            other.mkdir(mode=0o700)
            write_private(other / "evaluation.json", "{}")
            make_job(
                jobs, suffix="aaaaaaaaa112", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "settled")
        self.assertEqual(checked["attempt_count"], 1)

    def test_noncanonical_symlink_never_hides_a_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            normal = make_job(
                jobs, suffix="aaaaaaaaa113", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            (jobs / "foreign-review-alias").symlink_to(
                normal, target_is_directory=True
            )
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn("decision_review_noncanonical_job_unverifiable", checked["errors"])

    def test_job_metadata_symlink_never_hides_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            passing = make_job(
                jobs, suffix="aaaaaaaaa114", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            rejected = make_job(
                jobs, suffix="bbbbbbbbb115", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            metadata = rejected / "metadata.json"
            metadata.unlink()
            metadata.symlink_to(passing / "metadata.json")
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertTrue(
            any("decision_review_origin_invalid" in e for e in checked["errors"])
        )

    def test_signed_pass_swapped_after_inventory_cannot_hide_reject(self) -> None:
        # Both files have authentic per-unit origin SHA and finalization.  The
        # only difference is the observed directory inode at inventory time.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            standby = root / "standby"
            standby.mkdir(mode=0o700)
            rejected = make_job(
                jobs, suffix="aaaaaaaaa119", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            replacement = make_job(
                standby, suffix="aaaaaaaaa119", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            real_open = os.open
            switched = [False]

            def swap_before_open(path, flags, *args, **kwargs):
                if (
                    not switched[0]
                    and path == rejected.name
                    and kwargs.get("dir_fd") is not None
                    and flags & os.O_DIRECTORY
                ):
                    rejected.rename(root / "moved-original-reject")
                    replacement.rename(rejected)
                    switched[0] = True
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(reviews.os, "open", side_effect=swap_before_open):
                checked = self.reconcile(jobs)
        self.assertTrue(switched[0])
        self.assertEqual(checked["status"], "blocked")
        self.assertIn(
            "decision_review_job_inventory_unverifiable", checked["errors"]
        )
        self.assertEqual(checked["attempt_count"], 0)

    def test_swapped_job_path_cannot_replace_pinned_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            rejected = make_job(
                jobs, suffix="aaaaaaaaa116", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            passing = make_job(
                jobs, suffix="bbbbbbbbb117", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            original_read = reviews._read_private_json
            switched = [False]

            def swap_then_read(path: Path, max_bytes: int, **kwargs):
                if (
                    not switched[0] and path == rejected / "metadata.json"
                    and kwargs.get("parent_fd") is not None
                ):
                    rejected.rename(jobs / "moved-original-review")
                    rejected.symlink_to(passing, target_is_directory=True)
                    switched[0] = True
                return original_read(path, max_bytes, **kwargs)

            with mock.patch.object(
                reviews, "_read_private_json", side_effect=swap_then_read
            ):
                checked = self.reconcile(jobs)
        self.assertTrue(switched[0])
        self.assertEqual(checked["status"], "blocked")
        self.assertEqual(checked["attempt_count"], 2)
        self.assertEqual(checked["slots"][0]["material_reject_count"], 1)

    def test_reserved_repoground_origin_without_review_does_not_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            unit = "grabowski-job-rgpm-1234567890abcdef-00"
            reserved = jobs / unit
            reserved.mkdir(mode=0o700)
            origin, digest = job_origin.build_origin(
                unit=unit,
                owner=f"uid:{os.getuid()}",
                argv_sha256="e" * 64,
                scope={
                    "cwd": "/tmp/review", "argv_sha256": "e" * 64,
                    "runtime_seconds": 60,
                },
                notify_on_done={"requested": False, "channels": []},
                created_at_unix=1_787_000_000,
                started_at="2026-08-18T12:00:00Z",
                invoker_tool="grabowski_job_start",
            )
            write_private(
                reserved / "metadata.json",
                json.dumps({**{key: origin[key] for key in (
                    "unit", "job_id", "owner", "argv_sha256", "scope"
                )}, "origin": origin, "origin_sha256": digest}),
            )
            make_job(
                jobs, suffix="aaaaaaaaa118", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "settled")
        self.assertEqual(checked["attempt_count"], 1)

    def test_large_registry_cannot_hide_late_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            for number in range(10_010):
                (jobs / f"grabowski-job-{number:012x}").mkdir(mode=0o700)
            make_job(jobs, suffix="fffffffffff0", slot="A", terminal_status="succeeded",
                     review_result=result("A", "PASS_THIS_REVISION", 0))
            make_job(jobs, suffix="fffffffffff1", slot="A", terminal_status="succeeded",
                     review_result=result("A", "REJECT_THIS_REVISION", 1))
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertEqual(checked["attempt_count"], 2)
        self.assertEqual(checked["slots"][0]["material_reject_count"], 1)
        self.assertFalse(any("inventory_truncated" in x for x in checked["errors"]))

    def test_inventory_hard_limit_never_reports_partial_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(jobs, suffix="000000000001", slot="A", terminal_status="succeeded",
                     review_result=result("A", "PASS_THIS_REVISION", 0))
            make_job(jobs, suffix="fffffffffff1", slot="A", terminal_status="succeeded",
                     review_result=result("A", "REJECT_THIS_REVISION", 1))
            (jobs / "grabowski-job-000000000002").mkdir(mode=0o700)
            with mock.patch.object(reviews, "MAX_JOB_DIRECTORIES", 2):
                checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn("decision_review_job_inventory_truncated", checked["errors"])
        self.assertEqual(checked["attempt_count"], 0)

    def test_inventory_aggregate_metadata_budget_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(jobs, suffix="fffffffffff2", slot="A", terminal_status="succeeded",
                     review_result=result("A", "PASS_THIS_REVISION", 0))
            with mock.patch.object(reviews, "MAX_TOTAL_METADATA_BYTES", 4):
                checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn("decision_review_metadata_aggregate_budget_exceeded", checked["errors"])
        self.assertEqual(checked["attempt_count"], 0)

    def test_v2_claude_429_blocks_until_exact_later_same_slot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = make_job(
                jobs, suffix="a88888888888", slot="claude",
                terminal_status="failed", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
            )
            stamp_claude_quota_429(failed)
            prior = self.reconcile(jobs)
            self.assertEqual(prior["status"], "blocked")
            self.assertIn("decision_review_slot_without_pass:claude", prior["errors"])
            self.assertEqual(prior["attempts"][0]["classification"], "infrastructure_error")
            self.assertTrue(prior["attempts"][0]["pre_result_quota_failure_verified"])
            self.assertEqual(prior["attempts"][0]["terminal_status"], "failed")
            self.assertTrue(prior["attempts"][0]["review_role_verified"])
            make_job(
                jobs, suffix="b99999999999", slot="claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1_787_000_200,
            )
            settled = self.reconcile(jobs)
        self.assertEqual(settled["status"], "settled")
        self.assertEqual(settled["errors"], [])
        self.assertEqual(settled["slots"][0]["independent_pass_count"], 1)
        self.assertEqual(settled["slots"][0]["infrastructure_error_count"], 1)

    def test_v2_429_known_reset_suffix_then_independent_pass_settles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = make_job(
                jobs, suffix="a88888888888", slot="claude",
                terminal_status="failed", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
            )
            stamp_claude_quota_429(
                failed, envelope_updates={
                    "result": "You've hit your weekly limit · resets Oct 13, 10am (UTC)"
                },
            )
            make_job(
                jobs, suffix="b99999999999", slot="claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1_787_000_200,
            )
            outcome = self.reconcile(jobs)
        self.assertEqual(outcome["status"], "settled")
        self.assertEqual(outcome["errors"], [])

    def test_v2_429_weekly_time_only_reset_requires_later_real_pass(self) -> None:
        # This exact 0-token Claude Pro 429 envelope was observed on
        # 2026-10-19: there is no date before the reset hour.
        # Zero review work is infrastructure, NOT independent PASS.
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = make_job(
                jobs, suffix="a88888888888", slot="claude",
                terminal_status="failed", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
            )
            stamp_claude_quota_429(
                failed, envelope_updates={
                    "result": "You've hit your weekly limit · resets 10am (UTC)"
                },
            )
            prior = self.reconcile(jobs)
            self.assertEqual(prior["status"], "blocked")
            self.assertEqual(prior["attempts"][0]["classification"], "infrastructure_error")
            self.assertEqual(prior["slots"][0]["independent_pass_count"], 0)
            make_job(
                jobs, suffix="b99999999999", slot="claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1_787_000_200,
            )
            settled = self.reconcile(jobs)
        self.assertEqual(settled["status"], "settled")
        self.assertEqual(settled["errors"], [])
        self.assertEqual(settled["slots"][0]["independent_pass_count"], 1)
        self.assertEqual(settled["slots"][0]["infrastructure_error_count"], 1)

    def test_v2_429_generic_pass_cannot_supersede_independent_claude(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="a11111111111", slot="claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1_787_000_000,
            )
            quota = make_job(
                jobs, suffix="b22222222222", slot="claude",
                terminal_status="failed", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1_787_000_100,
            )
            stamp_claude_quota_429(quota)
            make_job(
                jobs, suffix="c33333333333", slot="claude",
                terminal_status="succeeded",
                review_result=result("claude", "PASS_THIS_REVISION", 0),
                created_at_unix=1_787_000_200,
            )
            blocked = self.reconcile(jobs)
            self.assertEqual(blocked["status"], "blocked")
            self.assertIn(
                "decision_review_infrastructure_not_superseded:"
                "claude:grabowski-job-b22222222222",
                blocked["errors"],
            )
            make_job(
                jobs, suffix="d44444444444", slot="claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1_787_000_300,
            )
            settled = self.reconcile(jobs)
        self.assertEqual(settled["status"], "settled")
        self.assertEqual(settled["errors"], [])

    def test_v2_429_near_misses_remain_blocking_even_after_valid_pass(self) -> None:
        cases = [
            ("http_401", {"api_error_status": 401}, {}),
            ("nonzero_output", {"usage": {
                "input_tokens": 0, "output_tokens": 1,
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                "server_tool_use": {"web_search_requests": 0, "web_fetch_requests": 0},
            }}, {}),
            ("unknown_server_tool", {"usage": {
                "input_tokens": 0, "output_tokens": 0, "iterations": [],
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                "server_tool_use": {
                    "web_search_requests": 0, "web_fetch_requests": 0,
                    "code_execution_requests": 1,
                },
            }}, {}),
            ("server_tool_bool", {"usage": {
                "input_tokens": 0, "output_tokens": 0, "iterations": [],
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                "server_tool_use": {"web_search_requests": False, "web_fetch_requests": 0},
            }}, {}),
            ("subagent_request", {"subagent_stats": {
                **ZERO_CLAUDE_SUBAGENTS,
                "requested": {"background": 0, "foreground": 1, "unset": 0},
            }}, {}),
            ("subagent_refused", {"subagent_stats": {
                **ZERO_CLAUDE_SUBAGENTS,
                "refused": {"depth_limit": 0, "concurrency_limit": 0, "budget": 1},
            }}, {}),
            ("subagent_unknown", {"subagent_stats": {
                **ZERO_CLAUDE_SUBAGENTS, "queued_work": 1,
            }}, {}),
            ("subagent_unknown_non_integer", {"subagent_stats": {
                **ZERO_CLAUDE_SUBAGENTS, "queued_work": False,
            }}, {}),
            ("subagent_by_type", {"subagent_stats": {
                **ZERO_CLAUDE_SUBAGENTS, "by_type": {"succeeded": 1},
            }}, {}),
            ("semantic_subagent_unknown_zero", {"subagent_stats": {
                **ZERO_CLAUDE_SUBAGENTS, "REJECT_THIS_REVISION P1": 0,
            }}, {}),
            ("semantic_tool_unknown_zero", {"usage": {"server_tool_use": {
                "web_search_requests": 0, "web_fetch_requests": 0,
                "REJECT_THIS_REVISION P1": 0,
            }}}, {}),
            ("semantic_cache_unknown_zero", {"usage": {"cache_creation": {
                "ephemeral_1h_input_tokens": 0,
                "ephemeral_5m_input_tokens": 0,
                "REJECT_THIS_REVISION P1": 0,
            }}}, {}),
            ("semantic_thinking_unknown_zero", {"usage": {
                "output_tokens_details": {
                    "thinking_tokens": 0, "REJECT_THIS_REVISION P1": 0,
                },
            }}, {}),
            ("semantic_by_type_unknown_zero", {"subagent_stats": {
                **ZERO_CLAUDE_SUBAGENTS, "by_type": {"REJECT_THIS_REVISION P1": 0},
            }}, {}),
            ("subagent_missing_evidence", {"subagent_stats": {"spawned": 0}}, {}),
            ("thinking_activity", {"usage": {
                "output_tokens_details": {"thinking_tokens": 1},
            }}, {}),
            ("cache_activity", {"usage": {
                "cache_creation": {
                    "ephemeral_1h_input_tokens": 1, "ephemeral_5m_input_tokens": 0,
                },
            }}, {}),
            ("unknown_usage_activity", {"usage": {"future_activity": 1}}, {}),
            ("structured_review_payload", {
                "structured_output": {"verdict": "NEEDS_CHANGE", "findings": [{}]},
            }, {}),
            ("not_known_quota_error", {"result": "unexpected inference text"}, {}),
            ("same_line_material_reject", {
                "result": "You've hit your weekly limit. REJECT_THIS_REVISION: material findings present",
            }, {}),
            ("quota_reset_with_extra_text", {
                "result": "You've hit your weekly limit · resets Oct 13, 10am (UTC). REVIEW REJECT",
            }, {}),
            ("time_only_reset_with_extra_text", {
                "result": "You've hit your weekly limit · resets 10am (UTC). REVIEW REJECT",
            }, {}),
            ("time_only_reset_invalid_hour", {
                "result": "You've hit your weekly limit · resets 99am (UTC)",
            }, {}),
            ("time_only_reset_missing_timezone", {
                "result": "You've hit your weekly limit · resets 10am",
            }, {}),
            ("unknown_top_level_review_result", {
                "review_result": {"verdict": "REJECT_THIS_REVISION", "findings": [{"priority": "P1"}]},
            }, {}),
            ("unknown_provider_tool_history", {
                "provider_tool_calls": [{"name": "read_file", "result": "review evidence"}],
            }, {}),
            ("unexpected_cli_turns", {"num_turns": 100}, {}),
            ("semantic_usage_speed", {
                "usage": {"speed": "standard REJECT_THIS_REVISION P1"},
            }, {}),
            ("semantic_usage_tier", {
                "usage": {"service_tier": "standard REJECT_THIS_REVISION P1"},
            }, {}),
            ("semantic_usage_geo", {
                "usage": {"inference_geo": "REJECT_THIS_REVISION"},
            }, {}),
            ("semantic_session_id", {
                "session_id": "REJECT_THIS_REVISION P1",
            }, {}),
            ("semantic_uuid", {
                "uuid": "REJECT_THIS_REVISION P1",
            }, {}),
            ("actual_quota_result_newline", {
                "result": "You've hit your weekly limit\nmodel-produced text",
            }, {}),
            ("actual_quota_result_carriage", {
                "result": "You've hit your weekly limit\rmore text",
            }, {}),
            ("quota_result_control", {
                "result": "You've hit your weekly limit\tmore text",
            }, {}),
            ("quota_result_unicode_nel", {
                "result": "You've hit your weekly limit\u0085extra line",
            }, {}),
            ("quota_result_unicode_ls", {
                "result": "You've hit your weekly limit\u2028extra line",
            }, {}),
            ("quota_result_unicode_ps", {
                "result": "You've hit your weekly limit\u2029extra line",
            }, {}),
            ("quota_result_zero_width", {
                "result": "You've hit your weekly limit\u200bextra text",
            }, {}),
            ("provider_api_work", {"duration_api_ms": 1}, {}),
            ("provider_api_work_false", {"duration_api_ms": False}, {}),
            ("provider_api_work_missing", {"duration_api_ms": None}, {}),
            ("material_document", {}, {"review_document_bytes": 14}),
            ("unbound_envelope", {}, {"review_provider_envelope_sha256": "f" * 64}),
            ("ambiguous_report", {}, {"review_findings_normalized": True}),
            ("tool_use", {"usage": {
                "input_tokens": 0, "output_tokens": 0, "iterations": [],
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
                "server_tool_use": {"web_search_requests": 1, "web_fetch_requests": 0},
            }}, {}),
        ]
        for label, envelope_delta, receipt_delta in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                jobs = Path(temporary) / "jobs"
                jobs.mkdir(mode=0o700)
                failed = make_job(
                    jobs, suffix="a88888888888", slot="claude",
                    terminal_status="failed", review_result=None,
                    review_role=True, attempt_bound=True, attempt_epoch=2,
                )
                stamp_claude_quota_429(
                    failed, envelope_updates=envelope_delta, receipt_updates=receipt_delta,
                )
                make_job(
                    jobs, suffix="b99999999999", slot="claude",
                    terminal_status="succeeded", review_result=None,
                    review_role=True, attempt_bound=True, attempt_epoch=2,
                    created_at_unix=1_787_000_200,
                )
                outcome = self.reconcile(jobs)
                self.assertEqual(outcome["status"], "blocked")
                self.assertIn(
                    "decision_review_result_invalid:grabowski-job-a88888888888:InvalidReviewDocument",
                    outcome["errors"],
                )

    def test_v2_429_duplicate_json_result_cannot_hide_material_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = make_job(
                jobs, suffix="a88888888888", slot="claude",
                terminal_status="failed", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
            )
            stamp_claude_quota_429(failed)
            receipt_path = failed / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            original = receipt["stdout_tail"]
            key = json.dumps("result") + ":" + json.dumps("You've hit your weekly limit")
            malicious = json.dumps("result") + ":" + json.dumps("REJECT_THIS_REVISION P1")
            self.assertIn(key, original)
            modified = original.replace(key, malicious + "," + key, 1)
            payload = modified.encode("utf-8")
            digest = hashlib.sha256(payload).hexdigest()
            receipt.update({
                "stdout_tail": modified,
                "stdout_bytes": len(payload),
                "stdout_sha256": digest,
                "review_provider_envelope_bytes": len(payload),
                "review_provider_envelope_sha256": digest,
            })
            receipt["receipt_sha256"] = reviews._agent_role_receipt_sha256(receipt)
            write_private(receipt_path, json.dumps(receipt))
            make_job(
                jobs, suffix="b99999999999", slot="claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1_787_000_200,
            )
            outcome = self.reconcile(jobs)
            self.assertEqual(outcome["status"], "blocked")
            self.assertIn(
                "decision_review_result_invalid:"
                "grabowski-job-a88888888888:InvalidReviewDocument",
                outcome["errors"],
            )

    def test_review_role_provenance_uses_agent_role_command_hash_for_unicode_prompt(self) -> None:
        role_command = [
            "claude",
            "--model",
            "claude-opus-5-5",
            "--effort",
            "high",
            "--permission-mode",
            "plan",
            "Review transition → fail closed",
        ]
        role_receipt_path = Path("/tmp/review/role-receipt.json")
        job_argv = [
            reviews.REVIEW_ROLE_PYTHON,
            "-I",
            "-m",
            reviews.REVIEW_ROLE_MODULE,
            "--role",
            "review",
            "--repository",
            "/tmp/review",
            "--expected-head",
            HEAD,
            "--expected-base-head",
            BASE,
            "--expected-diff-sha256",
            "e" * 64,
            "--expected-dirty",
            "false",
            "--output",
            str(role_receipt_path),
            "--",
            *role_command,
        ]

        provenance = reviews.review_role_provenance(
            job_argv,
            reviews.normalize_binding(binding("independent-reviewer")),
            cwd=Path("/tmp/review"),
        )

        self.assertIsNotNone(provenance)
        assert provenance is not None
        self.assertEqual(
            agent_role.digest(role_command),
            provenance["reviewer_command_sha256"],
        )

    def reconcile(self, jobs: Path) -> dict:
        return reviews.reconcile(
            repo=REPO,
            pr=PR,
            head_sha=HEAD,
            base_sha=BASE,
            diff_sha256=DIFF,
            jobs_root=jobs,
        )

    def test_no_registered_reviews_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "not_applicable")
        self.assertEqual(reconciled["attempt_count"], 0)
        self.assertEqual(reconciled["errors"], [])

    def test_two_terminal_pass_slots_settle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(jobs, suffix="a00000000001", slot="A", terminal_status="succeeded", review_result=result("A", "PASS_THIS_REVISION", 0))
            make_job(jobs, suffix="b00000000002", slot="B", terminal_status="succeeded", review_result=result("B", "PASS_THIS_REVISION", 0))
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["slot_count"], 2)
        self.assertTrue(reconciled["read_by_merge_guard"])
        self.assertTrue(
            all("started_at_unix_ns" in attempt for attempt in reconciled["attempts"])
        )
        self.assertEqual(reconciled["errors"], [])

    def test_independent_named_generic_marker_is_not_proven_independent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000021",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=result("independent-reviewer", "PASS_THIS_REVISION", 0),
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        slot = reconciled["slots"][0]
        self.assertEqual(slot["pass_count"], 1)
        self.assertEqual(slot["independent_pass_count"], 0)
        self.assertFalse(reconciled["attempts"][0]["independence_verified"])

    def test_server_bound_read_only_reviewer_route_is_proven_independent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000022",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        slot = reconciled["slots"][0]
        self.assertEqual(slot["pass_count"], 1)
        self.assertEqual(slot["independent_pass_count"], 1)
        attempt = reconciled["attempts"][0]
        self.assertTrue(attempt["review_role_verified"])
        self.assertTrue(attempt["review_route_verified"])
        self.assertTrue(attempt["independence_verified"])
        self.assertEqual(attempt["review_route_id"], "claude-opus-5.5-high")
        self.assertEqual(attempt["review_provider_family"], "anthropic")


    def test_v1_role_receipt_in_shared_audit_directory_remains_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            shared = root / "shared-audit"
            shared.mkdir(mode=0o755)
            make_job(
                jobs, suffix="a00000000215", slot="independent-reviewer",
                terminal_status="succeeded", review_result=None, review_role=True,
                legacy_role_receipt_parent=shared,
            )
            receipt = shared / "review-role-receipt.json"
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            outcome = self.reconcile(jobs)
        self.assertEqual(outcome["status"], "settled")
        self.assertEqual(outcome["errors"], [])
        self.assertTrue(outcome["attempts"][0]["independence_verified"])

    def test_late_inplace_or_replaced_external_v1_role_receipt_blocks_first_settlement(self) -> None:
        # External legacy V1 reviewer receipts can live outside a job directory.
        # Job-child file snapshots alone do not detect late mutation of these
        # create-only independent-review results (P1 regression).
        for mutation in ("inplace", "replace"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    jobs = root / "jobs"
                    jobs.mkdir(mode=0o700)
                    shared = root / "shared-audit"
                    shared.mkdir(mode=0o755)
                    make_job(
                        jobs, suffix="a00000000221", slot="independent-reviewer",
                        terminal_status="succeeded", review_result=None, review_role=True,
                        legacy_role_receipt_parent=shared,
                    )
                    later = make_job(
                        jobs, suffix="b00000000222", slot="B",
                        terminal_status="succeeded",
                        review_result=result("B", "PASS_THIS_REVISION", 0),
                    )
                    receipt = shared / "review-role-receipt.json"
                    original_inode = receipt.stat().st_ino
                    original_validator = reviews._validated_origin_binding
                    mutated = False

                    def late_reject(directory, *args, **kwargs):
                        nonlocal mutated
                        if directory == later and not mutated:
                            value = json.loads(receipt.read_text(encoding="utf-8"))
                            value.update(
                                verdict="NEEDS_CHANGE",
                                findings=[{"severity": "P1", "summary": "late reject"}],
                                failure_classification="review_verdict",
                                returncode=1,
                            )
                            value["receipt_sha256"] = reviews._agent_role_receipt_sha256(value)
                            if mutation == "inplace":
                                write_private(receipt, json.dumps(value))
                                self.assertEqual(receipt.stat().st_ino, original_inode)
                            else:
                                replacement = shared / "replacement.json"
                                write_private(replacement, json.dumps(value))
                                replacement.replace(receipt)
                            mutated = True
                        return original_validator(directory, *args, **kwargs)

                    with mock.patch.object(
                        reviews, "_validated_origin_binding", side_effect=late_reject
                    ):
                        first = self.reconcile(jobs)
                    self.assertTrue(mutated)
                    self.assertEqual(first["status"], "blocked")
                    self.assertIn("decision_review_external_role_receipt_changed", first["errors"])
                    second = self.reconcile(jobs)
                    self.assertEqual(second["status"], "blocked")
                    self.assertTrue(any(
                        item.startswith("decision_review_material_reject:")
                        for item in second["errors"]
                    ))

    def test_late_created_external_v1_receipt_or_parent_blocks_first_scan(self) -> None:
        # A failed historical V1 reviewer may have no external receipt at
        # first inspection. Later publication must not be hidden by a PASS.
        for missing in ("file", "parent"):
            with self.subTest(missing=missing):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    jobs = root / "jobs"
                    jobs.mkdir(mode=0o700)
                    shared = root / "shared-audit"
                    shared.mkdir(mode=0o755)
                    make_job(
                        jobs, suffix="a00000000223", slot="independent-reviewer",
                        terminal_status="failed", review_result=None, review_role=True,
                        legacy_role_receipt_parent=shared,
                        created_at_unix=1_787_000_100,
                    )
                    later = make_job(
                        jobs, suffix="b00000000224", slot="independent-reviewer",
                        terminal_status="succeeded", review_result=None,
                        review_role=True, created_at_unix=1_787_000_200,
                    )
                    receipt = shared / "review-role-receipt.json"
                    original = json.loads(receipt.read_text(encoding="utf-8"))
                    receipt.unlink()
                    if missing == "parent":
                        shared.rmdir()
                    previous_validator = reviews._validated_origin_binding
                    published = False

                    def publish_late(directory, *args, **kwargs):
                        nonlocal published
                        if directory == later and not published:
                            value = dict(original)
                            value.update(
                                verdict="NEEDS_CHANGE",
                                findings=[{"severity": "P1", "summary": "late reject"}],
                                failure_classification="review_verdict",
                                returncode=1,
                            )
                            value["receipt_sha256"] = reviews._agent_role_receipt_sha256(value)
                            if missing == "parent":
                                shared.mkdir(mode=0o755)
                            write_private(receipt, json.dumps(value))
                            published = True
                        return previous_validator(directory, *args, **kwargs)

                    with mock.patch.object(
                        reviews, "_validated_origin_binding", side_effect=publish_late
                    ):
                        first = self.reconcile(jobs)
                    self.assertTrue(published)
                    self.assertEqual(first["status"], "blocked")
                    if missing == "file":
                        self.assertIn(
                            "decision_review_external_role_receipt_changed",
                            first["errors"],
                        )
                    else:
                        self.assertTrue(any(
                            error.startswith("decision_review_result_invalid:")
                            for error in first["errors"]
                        ))
                    second = self.reconcile(jobs)
                    self.assertEqual(second["status"], "blocked")
                    self.assertTrue(any(
                        error.startswith("decision_review_material_reject:")
                        for error in second["errors"]
                    ))

    def test_still_missing_external_v1_receipt_has_conservative_parent_policy(self) -> None:
        for missing in ("file", "parent"):
            with self.subTest(missing=missing):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    jobs = root / "jobs"
                    jobs.mkdir(mode=0o700)
                    shared = root / "shared-audit"
                    shared.mkdir(mode=0o755)
                    make_job(
                        jobs, suffix="a00000000225", slot="independent-reviewer",
                        terminal_status="failed", review_result=None, review_role=True,
                        legacy_role_receipt_parent=shared,
                        created_at_unix=1_787_000_100,
                    )
                    make_job(
                        jobs, suffix="b00000000226", slot="independent-reviewer",
                        terminal_status="succeeded", review_result=None,
                        review_role=True, created_at_unix=1_787_000_200,
                    )
                    receipt = shared / "review-role-receipt.json"
                    receipt.unlink()
                    if missing == "parent":
                        shared.rmdir()
                    result_state = self.reconcile(jobs)
                if missing == "file":
                    self.assertEqual(result_state["status"], "settled")
                    self.assertEqual(result_state["errors"], [])
                    self.assertEqual(result_state["slots"][0]["independent_pass_count"], 1)
                else:
                    self.assertEqual(result_state["status"], "blocked")
                    self.assertTrue(any(
                        error.startswith("decision_review_result_invalid:")
                        for error in result_state["errors"]
                    ))


    def test_v1_shared_parent_still_rejects_symlinks_hardlinks_and_fifos(self) -> None:
        for attack in ("symlink", "hardlink", "fifo"):
            with self.subTest(attack=attack):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    jobs = root / "jobs"
                    jobs.mkdir(mode=0o700)
                    shared = root / "shared-audit"
                    shared.mkdir(mode=0o755)
                    make_job(
                        jobs, suffix="a00000000216", slot="independent-reviewer",
                        terminal_status="succeeded", review_result=None, review_role=True,
                        legacy_role_receipt_parent=shared,
                    )
                    receipt = shared / "review-role-receipt.json"
                    if attack == "symlink":
                        other = shared / "other-private.json"
                        other.write_bytes(receipt.read_bytes())
                        os.chmod(other, 0o600)
                        receipt.unlink()
                        receipt.symlink_to(other)
                    elif attack == "hardlink":
                        os.link(receipt, shared / "extra-link")
                    else:
                        receipt.unlink()
                        os.mkfifo(receipt, 0o600)
                    outcome = self.reconcile(jobs)
                self.assertEqual(outcome["status"], "blocked")
                self.assertEqual(outcome["attempts"][0]["classification"], "invalid_result")
                self.assertTrue(any(error.startswith(
                    "decision_review_result_invalid:grabowski-job-a00000000216:"
                ) for error in outcome["errors"]))

    def test_v2_role_receipt_still_requires_private_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            directory = make_job(
                jobs, suffix="a00000000217", slot="independent-reviewer",
                terminal_status="succeeded", review_result=None, review_role=True,
                attempt_bound=True,
            )
            metadata = json.loads((directory / "metadata.json").read_text())
            os.chmod(directory, 0o755)
            with self.assertRaisesRegex(ValueError, "parent is not owner-private"):
                reviews._validated_review_role_evidence(
                    metadata, reviews.normalize_binding(binding("independent-reviewer")),
                    metadata["scope"]["decision_review_provenance"],
                )

    def test_historical_review_role_prior_module_digest_survives_upgrade_only_if_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir()
            directory = make_job(
                jobs, suffix="a00000000052", slot="independent-reviewer",
                terminal_status="succeeded", review_result=None, review_role=True,
            )
            metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
            provenance = dict(metadata["scope"]["decision_review_provenance"])
            historical_bytes = b"immutable-previous-release-reviewer-module"
            release_root = root / "releases"
            historical = (
                release_root
                / "0123456789ab-srcset0123456789ab-lock0123456789ab-contract0123456789ab"
                / ".venv" / "lib" / "python3.10" / "site-packages"
                / f"{reviews.REVIEW_ROLE_MODULE}.py"
            )
            historical.parent.mkdir(parents=True)
            historical.write_bytes(historical_bytes)
            provenance["runner_module_path"] = str(historical)
            provenance["runner_module_sha256"] = hashlib.sha256(historical_bytes).hexdigest()
            provenance["provenance_sha256"] = reviews.sha256_json({
                key: value for key, value in provenance.items() if key != "provenance_sha256"
            })
            with mock.patch.object(reviews, "REVIEW_ROLE_RELEASE_ROOT", release_root):
                self.assertEqual(
                    reviews._normalize_review_role_provenance(
                        provenance, reviews.normalize_binding(binding("independent-reviewer")),
                        cwd="/tmp/review",
                    ),
                    provenance,
                )
                historical.write_bytes(historical_bytes + b"tampered")
                with self.assertRaisesRegex(ValueError, "binding mismatch"):
                    reviews._normalize_review_role_provenance(
                        provenance, reviews.normalize_binding(binding("independent-reviewer")),
                        cwd="/tmp/review",
                    )

    def test_historical_review_role_path_rotation_accepts_identical_immutable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / "jobs"
            jobs.mkdir()
            directory = make_job(
                jobs,
                suffix="a00000000050",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
            )
            metadata = json.loads(
                (directory / "metadata.json").read_text(encoding="utf-8")
            )
            provenance = dict(
                metadata["scope"]["decision_review_provenance"]
            )
            release_root = root / "releases"
            historical_module = (
                release_root
                / (
                    "0123456789ab-srcset0123456789ab-lock0123456789ab-"
                    "contract0123456789ab"
                )
                / ".venv"
                / "lib"
                / "python3.10"
                / "site-packages"
                / f"{reviews.REVIEW_ROLE_MODULE}.py"
            )
            historical_module.parent.mkdir(parents=True)
            current_module = Path(reviews.__file__).with_name(
                f"{reviews.REVIEW_ROLE_MODULE}.py"
            )
            historical_module.write_bytes(current_module.read_bytes())
            provenance["runner_module_path"] = str(historical_module)
            material = {
                key: value
                for key, value in provenance.items()
                if key != "provenance_sha256"
            }
            provenance["provenance_sha256"] = reviews.sha256_json(material)

            with mock.patch.object(
                reviews, "REVIEW_ROLE_RELEASE_ROOT", release_root
            ):
                normalized = reviews._normalize_review_role_provenance(
                    provenance,
                    reviews.normalize_binding(binding("independent-reviewer")),
                    cwd="/tmp/review",
                )

            self.assertEqual(normalized, provenance)

    def test_historical_review_role_path_rotation_rejects_untrusted_or_changed_module(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / "jobs"
            jobs.mkdir()
            directory = make_job(
                jobs,
                suffix="a00000000051",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
            )
            metadata = json.loads(
                (directory / "metadata.json").read_text(encoding="utf-8")
            )
            original = dict(
                metadata["scope"]["decision_review_provenance"]
            )
            release_root = root / "releases"
            release_id = (
                "0123456789ab-srcset0123456789ab-lock0123456789ab-"
                "contract0123456789ab"
            )
            historical_module = (
                release_root
                / release_id
                / ".venv"
                / "lib"
                / "python3.10"
                / "site-packages"
                / f"{reviews.REVIEW_ROLE_MODULE}.py"
            )
            historical_module.parent.mkdir(parents=True)
            current_module = Path(reviews.__file__).with_name(
                f"{reviews.REVIEW_ROLE_MODULE}.py"
            )
            historical_module.write_bytes(current_module.read_bytes())

            def rotated(path: Path) -> dict:
                provenance = dict(original)
                provenance["runner_module_path"] = str(path)
                material = {
                    key: value
                    for key, value in provenance.items()
                    if key != "provenance_sha256"
                }
                provenance["provenance_sha256"] = reviews.sha256_json(material)
                return provenance

            outside = root / "outside" / f"{reviews.REVIEW_ROLE_MODULE}.py"
            outside.parent.mkdir()
            outside.write_bytes(current_module.read_bytes())
            historical_module.write_bytes(b"changed-review-role-module")
            loop_a = release_root / "loop-a"
            loop_b = release_root / "loop-b"
            loop_a.symlink_to(loop_b)
            loop_b.symlink_to(loop_a)

            with mock.patch.object(
                reviews, "REVIEW_ROLE_RELEASE_ROOT", release_root
            ):
                for provenance in (
                    rotated(Path("~missing-user/grabowski_agent_role.py")),
                    rotated(outside),
                    rotated(historical_module),
                    rotated(loop_a),
                ):
                    with self.subTest(path=provenance["runner_module_path"]):
                        with self.assertRaisesRegex(
                            ValueError,
                            "decision review provenance binding mismatch",
                        ):
                            reviews._normalize_review_role_provenance(
                                provenance,
                                reviews.normalize_binding(
                                    binding("independent-reviewer")
                                ),
                                cwd="/tmp/review",
                            )

    def test_historical_review_role_python_rotation_accepts_same_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / "jobs"
            jobs.mkdir()
            directory = make_job(
                jobs,
                suffix="a00000000052",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
            )
            metadata = json.loads(
                (directory / "metadata.json").read_text(encoding="utf-8")
            )
            original = dict(metadata["scope"]["decision_review_provenance"])
            fixture = python_rotation_fixture(root)

            with patch_rotation(
                fixture,
                fixture["stable_python"],
            ):
                for candidate in (
                    fixture["stable_python"],
                    fixture["historical_release_python"],
                ):
                    with self.subTest(path=candidate):
                        normalized = reviews._normalize_review_role_provenance(
                            rotated_runner_provenance(original, candidate),
                            reviews.normalize_binding(
                                binding("independent-reviewer")
                            ),
                            cwd="/tmp/review",
                        )
                        self.assertEqual(
                            normalized,
                            rotated_runner_provenance(original, candidate),
                        )

                other_venv = root / "other-venv"
                (other_venv / "bin").mkdir(parents=True)
                (other_venv / "bin" / "python").symlink_to(
                    fixture["current_python"]
                )
                stable_venv = fixture["stable_python"].parents[1]
                stable_venv.unlink()
                stable_venv.symlink_to(
                    other_venv, target_is_directory=True
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "decision review provenance binding mismatch",
                ):
                    reviews._normalize_review_role_provenance(
                        rotated_runner_provenance(
                            original, fixture["stable_python"]
                        ),
                        reviews.normalize_binding(
                            binding("independent-reviewer")
                        ),
                        cwd="/tmp/review",
                    )

    def test_historical_review_role_python_rotation_rejects_alias_or_other_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / "jobs"
            jobs.mkdir()
            directory = make_job(
                jobs,
                suffix="a00000000053",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
            )
            metadata = json.loads(
                (directory / "metadata.json").read_text(encoding="utf-8")
            )
            original = dict(metadata["scope"]["decision_review_provenance"])
            current_python = root / "current-python"
            current_python.write_text("#!/bin/sh\n", encoding="utf-8")
            current_python.chmod(0o700)
            other_python = root / "other-python"
            other_python.write_text("#!/bin/sh\n", encoding="utf-8")
            other_python.chmod(0o700)
            stable_python = root / "stable" / ".venv" / "bin" / "python"
            stable_python.parent.mkdir(parents=True)
            stable_python.symlink_to(current_python)
            release_root = root / "releases"
            release_id = (
                "0123456789ab-srcset0123456789ab-lock0123456789ab-"
                "contract0123456789ab"
            )
            bad_release_python = (
                release_root / release_id / ".venv" / "bin" / "python"
            )
            bad_release_python.parent.mkdir(parents=True)
            bad_release_python.symlink_to(other_python)
            outside_python = root / "outside" / "python"
            outside_python.parent.mkdir()
            outside_python.symlink_to(current_python)
            malformed_release_python = (
                release_root / "not-a-release" / ".venv" / "bin" / "python"
            )
            malformed_release_python.parent.mkdir(parents=True)
            malformed_release_python.symlink_to(current_python)

            def rotated(path: Path) -> dict:
                provenance = dict(original)
                provenance["runner_python"] = str(path)
                material = {
                    key: value
                    for key, value in provenance.items()
                    if key != "provenance_sha256"
                }
                provenance["provenance_sha256"] = reviews.sha256_json(material)
                return provenance

            with (
                mock.patch.object(reviews, "REVIEW_ROLE_PYTHON", str(current_python)),
                mock.patch.object(reviews, "REVIEW_ROLE_STABLE_PYTHON", stable_python),
                mock.patch.object(reviews, "REVIEW_ROLE_RELEASE_ROOT", release_root),
            ):
                for provenance in (
                    rotated(outside_python),
                    rotated(malformed_release_python),
                    rotated(bad_release_python),
                ):
                    with self.subTest(path=provenance["runner_python"]):
                        with self.assertRaisesRegex(
                            ValueError,
                            "decision review provenance binding mismatch",
                        ):
                            reviews._normalize_review_role_provenance(
                                provenance,
                                reviews.normalize_binding(
                                    binding("independent-reviewer")
                                ),
                                cwd="/tmp/review",
                            )


    def test_historical_review_role_python_rotation_rejects_noncanonical_release_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / "jobs"
            jobs.mkdir()
            directory = make_job(
                jobs,
                suffix="a00000000055",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
            )
            metadata = json.loads(
                (directory / "metadata.json").read_text(encoding="utf-8")
            )
            original = dict(metadata["scope"]["decision_review_provenance"])
            fixture = python_rotation_fixture(root)
            release_root = fixture["release_root"]

            symlink_parent_root = (
                release_root
                / (
                    "222222222222-srcset222222222222-lock222222222222-"
                    "contract222222222222"
                )
            )
            symlink_parent_root.mkdir(parents=True)
            actual_venv = root / "actual-venv"
            (actual_venv / "bin").mkdir(parents=True)
            (actual_venv / "bin" / "python").symlink_to(
                fixture["current_python"]
            )
            (symlink_parent_root / ".venv").symlink_to(
                actual_venv,
                target_is_directory=True,
            )
            symlink_parent_python = (
                symlink_parent_root / ".venv" / "bin" / "python"
            )

            python3_path = (
                release_root
                / (
                    "333333333333-srcset333333333333-lock333333333333-"
                    "contract333333333333"
                )
                / ".venv"
                / "bin"
                / "python3"
            )
            python3_path.parent.mkdir(parents=True)
            python3_path.symlink_to(fixture["current_python"])

            copied_python = (
                release_root
                / (
                    "444444444444-srcset444444444444-lock444444444444-"
                    "contract444444444444"
                )
                / ".venv"
                / "bin"
                / "python"
            )
            copied_python.parent.mkdir(parents=True)
            copied_python.write_bytes(fixture["current_python"].read_bytes())
            copied_python.chmod(0o700)
            self.assertNotEqual(
                copied_python.stat().st_ino,
                fixture["current_python"].stat().st_ino,
            )

            release_root_alias = root / "release-root-alias"
            release_root_alias.symlink_to(
                release_root, target_is_directory=True
            )
            aliased_release_python = (
                release_root_alias
                / fixture["historical_release_python"].relative_to(release_root)
            )

            cases = (
                (aliased_release_python, release_root_alias),
                (symlink_parent_python, release_root),
                (python3_path, release_root),
                (copied_python, release_root),
            )
            for candidate, candidate_root in cases:
                with self.subTest(path=candidate):
                    case_fixture = dict(fixture)
                    case_fixture["release_root"] = candidate_root
                    with patch_rotation(
                        case_fixture,
                        fixture["current_release_python"],
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "decision review provenance binding mismatch",
                        ):
                            reviews._normalize_review_role_provenance(
                                rotated_runner_provenance(
                                    original, candidate
                                ),
                                reviews.normalize_binding(
                                    binding("independent-reviewer")
                                ),
                                cwd="/tmp/review",
                            )

    def test_reviewer_provenance_requires_server_python_and_isolated_module(self) -> None:
        normalized = reviews.normalize_binding(binding("independent-reviewer"))
        receipt = "/tmp/review/review-role-receipt.json"
        trusted = [
            reviews.REVIEW_ROLE_PYTHON,
            "-I",
            "-m",
            reviews.REVIEW_ROLE_MODULE,
            "--role",
            "review",
            "--repository",
            "/tmp/review",
            "--expected-head",
            HEAD,
            "--expected-base-head",
            BASE,
            "--expected-diff-sha256",
            "e" * 64,
            "--expected-dirty",
            "false",
            "--output",
            receipt,
            "--",
            "claude",
            "--model",
            "claude-opus-5-5",
            "--effort",
            "high",
            "--permission-mode",
            "plan",
            "Review the frozen revision",
        ]
        self.assertIsNotNone(
            reviews.review_role_provenance(trusted, normalized, cwd=Path("/tmp/review"))
        )
        caller_python = ["/tmp/python3", *trusted[1:]]
        self.assertIsNone(
            reviews.review_role_provenance(
                caller_python, normalized, cwd=Path("/tmp/review")
            )
        )
        non_isolated = [trusted[0], *trusted[2:]]
        self.assertIsNone(
            reviews.review_role_provenance(
                non_isolated, normalized, cwd=Path("/tmp/review")
            )
        )

    def test_route_suffix_cannot_override_verified_reviewer_route(self) -> None:
        normalized = reviews.normalize_binding(binding("independent-reviewer"))
        receipt = "/tmp/review/review-role-receipt.json"
        job_argv = [
            reviews.REVIEW_ROLE_PYTHON,
            "-I",
            "-m",
            reviews.REVIEW_ROLE_MODULE,
            "--role",
            "review",
            "--repository",
            "/tmp/review",
            "--expected-head",
            HEAD,
            "--expected-base-head",
            BASE,
            "--expected-diff-sha256",
            "e" * 64,
            "--expected-dirty",
            "false",
            "--output",
            receipt,
            "--",
            "claude",
            "--model",
            "claude-opus-5-5",
            "--effort",
            "high",
            "--permission-mode",
            "plan",
            "--model",
            "sonnet",
            "Review the frozen revision",
        ]
        self.assertIsNone(
            reviews.review_role_provenance(
                job_argv, normalized, cwd=Path("/tmp/review")
            )
        )

    def test_exact_origin_bound_argv_bootstraps_reviewer_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000024",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                origin_provenance=False,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["slots"][0]["independent_pass_count"], 1)
        self.assertTrue(reconciled["attempts"][0]["independence_verified"])

    def test_historical_immutable_runner_bootstraps_missing_provenance_after_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            fixture = python_rotation_fixture(
                root,
                historical_module_bytes=Path(agent_role.__file__).read_bytes(),
            )

            with patch_rotation(
                fixture, fixture["historical_release_python"]
            ):
                make_job(
                    jobs,
                    suffix="a00000000026",
                    slot="independent-reviewer",
                    terminal_status="succeeded",
                    review_result=None,
                    review_role=True,
                    origin_provenance=False,
                )

            with patch_rotation(fixture, fixture["stable_python"], bind_launcher=True):
                reconciled = self.reconcile(jobs)
            self.assertEqual(reconciled["status"], "settled")
            self.assertEqual(reconciled["slots"][0]["independent_pass_count"], 1)
            self.assertEqual(reconciled["attempts"][0]["classification"], "pass")
            self.assertTrue(reconciled["attempts"][0]["independence_verified"])

            fixture["historical_module"].write_text(
                "# mismatched historical role module\n",
                encoding="utf-8",
            )
            with patch_rotation(fixture, fixture["stable_python"], bind_launcher=True):
                rejected = self.reconcile(jobs)
            self.assertEqual(rejected["status"], "blocked")
            self.assertEqual(rejected["slots"][0]["independent_pass_count"], 0)
            self.assertIn(
                "decision_review_slot_without_pass:independent-reviewer",
                rejected["errors"],
            )

    def test_missing_provenance_stable_alias_does_not_bootstrap_independence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            fixture = python_rotation_fixture(root)

            with patch_rotation(fixture, fixture["stable_python"], bind_launcher=True):
                make_job(
                    jobs,
                    suffix="a00000000028",
                    slot="independent-reviewer",
                    terminal_status="succeeded",
                    review_result=None,
                    review_role=True,
                    origin_provenance=False,
                )
                reconciled = self.reconcile(jobs)

        self.assertEqual(reconciled["status"], "blocked")
        self.assertEqual(
            reconciled["slots"][0]["independent_pass_count"], 0
        )
        self.assertIn(
            "decision_review_slot_without_pass:independent-reviewer",
            reconciled["errors"],
        )

    def test_redacted_or_changed_metadata_argv_cannot_bootstrap_independence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000025",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                origin_provenance=False,
                metadata_argv_override=[
                    reviews.REVIEW_ROLE_PYTHON,
                    "-I",
                    "-m",
                    reviews.REVIEW_ROLE_MODULE,
                    "<REDACTED>",
                ],
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertEqual(reconciled["slots"][0]["independent_pass_count"], 0)
        self.assertIn("decision_review_slot_without_pass:independent-reviewer", reconciled["errors"])

    def test_preflight_can_defer_unproven_diff_identity_without_claiming_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000023",
                slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0, diff_sha256=ALIAS_DIFF),
                diff_sha256=ALIAS_DIFF,
            )
            reconciled = reviews.reconcile(
                repo=REPO,
                pr=PR,
                head_sha=HEAD,
                base_sha=BASE,
                diff_sha256=DIFF,
                defer_diff_identity=True,
                jobs_root=jobs,
            )
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["accepted_diff_sha256s"], [DIFF])
        self.assertEqual(reconciled["deferred_diff_identity_count"], 1)
        self.assertTrue(reconciled["attempts"][0]["diff_identity_deferred"])

    def test_unproven_diff_alias_still_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000011",
                slot="A",
                terminal_status="succeeded",
                review_result=result(
                    "A",
                    "PASS_THIS_REVISION",
                    0,
                    diff_sha256=ALIAS_DIFF,
                ),
                diff_sha256=ALIAS_DIFF,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(
            any(
                error.startswith("decision_review_diff_sha256_drift:")
                for error in reconciled["errors"]
            )
        )

    def test_failed_generic_diff_drift_without_result_can_be_superseded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000047",
                slot="independent-reviewer",
                terminal_status="failed",
                review_result=None,
                diff_sha256=ALIAS_DIFF,
                created_at_unix=1_787_000_100,
            )
            make_job(
                jobs,
                suffix="a00000000048",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                created_at_unix=1_787_000_200,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["errors"], [])
        slot = reconciled["slots"][0]
        self.assertEqual(slot["infrastructure_error_count"], 1)
        self.assertEqual(slot["independent_pass_count"], 1)

    def test_failed_provenance_bound_diff_drift_without_result_can_be_superseded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            failed = make_job(
                jobs,
                suffix="a00000000045",
                slot="independent-reviewer",
                terminal_status="failed",
                review_result=None,
                diff_sha256=ALIAS_DIFF,
                review_role=True,
                created_at_unix=1_787_000_100,
            )
            role_receipt_path = failed / "review-role-receipt.json"
            role_receipt = json.loads(role_receipt_path.read_text(encoding="utf-8"))
            role_receipt.update(
                {
                    "returncode": 126,
                    "verdict": "INVALID",
                    "findings": [],
                    "failure_classification": "invalid_review_output",
                }
            )
            role_receipt["receipt_sha256"] = reviews._agent_role_receipt_sha256(
                role_receipt
            )
            write_private(role_receipt_path, json.dumps(role_receipt))
            make_job(
                jobs,
                suffix="a00000000046",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                created_at_unix=1_787_000_200,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["errors"], [])
        slot = reconciled["slots"][0]
        self.assertEqual(slot["infrastructure_error_count"], 1)
        self.assertEqual(slot["independent_pass_count"], 1)
        self.assertEqual(
            {item["classification"] for item in reconciled["attempts"]},
            {"infrastructure_error", "pass"},
        )

    def test_explicit_equivalent_diff_alias_settles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000012",
                slot="A",
                terminal_status="succeeded",
                review_result=result(
                    "A",
                    "PASS_THIS_REVISION",
                    0,
                    diff_sha256=ALIAS_DIFF,
                ),
                diff_sha256=ALIAS_DIFF,
            )
            make_job(
                jobs,
                suffix="b00000000013",
                slot="B",
                terminal_status="succeeded",
                review_result=result("B", "PASS_THIS_REVISION", 0),
            )
            reconciled = reviews.reconcile(
                repo=REPO,
                pr=PR,
                head_sha=HEAD,
                base_sha=BASE,
                diff_sha256=DIFF,
                equivalent_diff_sha256s=[ALIAS_DIFF],
                jobs_root=jobs,
            )
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["errors"], [])
        self.assertEqual(
            reconciled["accepted_diff_sha256s"],
            sorted([DIFF, ALIAS_DIFF]),
        )
        self.assertEqual(reconciled["slot_count"], 2)

    def test_material_reject_blocks_even_when_other_slot_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(jobs, suffix="a00000000003", slot="A", terminal_status="succeeded", review_result=result("A", "REJECT_THIS_REVISION", 1))
            make_job(jobs, suffix="b00000000004", slot="B", terminal_status="succeeded", review_result=result("B", "PASS_THIS_REVISION", 0))
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(any(error.startswith("decision_review_material_reject:a:") for error in reconciled["errors"]))

    def test_running_review_blocks_even_if_other_slot_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(jobs, suffix="a00000000005", slot="A", terminal_status=None, review_result=None)
            make_job(jobs, suffix="b00000000006", slot="B", terminal_status="succeeded", review_result=result("B", "PASS_THIS_REVISION", 0))
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(any(error.startswith("decision_review_not_terminal:") for error in reconciled["errors"]))

    def test_terminal_infrastructure_error_can_be_replaced_in_same_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(jobs, suffix="a00000000007", slot="A", terminal_status="failed", review_result=None, created_at_unix=1_787_000_100)
            make_job(jobs, suffix="a00000000008", slot="A", terminal_status="succeeded", review_result=result("A", "PASS_THIS_REVISION", 0), created_at_unix=1_787_000_200)
            make_job(jobs, suffix="b00000000009", slot="B", terminal_status="succeeded", review_result=result("B", "PASS_THIS_REVISION", 0))
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        a_slot = next(item for item in reconciled["slots"] if item["slot"] == "a")
        self.assertEqual(a_slot["infrastructure_error_count"], 1)
        self.assertEqual(a_slot["pass_count"], 1)

    def test_same_second_infrastructure_error_is_replaced_by_later_pass_with_ns_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            second = 1_787_000_100
            make_job(
                jobs,
                suffix="a00000000035",
                slot="A",
                terminal_status="failed",
                review_result=None,
                created_at_unix=second,
                started_at_unix_ns=second * 1_000_000_000 + 100_000_000,
            )
            make_job(
                jobs,
                suffix="a00000000036",
                slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
                created_at_unix=second,
                started_at_unix_ns=second * 1_000_000_000 + 200_000_000,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["errors"], [])

    def test_same_second_legacy_attempts_without_ns_evidence_stay_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            second = 1_787_000_100
            make_job(
                jobs,
                suffix="a00000000037",
                slot="A",
                terminal_status="failed",
                review_result=None,
                created_at_unix=second,
            )
            make_job(
                jobs,
                suffix="a00000000038",
                slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
                created_at_unix=second,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(
            any(
                error.startswith("decision_review_infrastructure_not_superseded:a:")
                for error in reconciled["errors"]
            )
        )

    def test_newer_missing_result_blocks_older_pass_until_later_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000030",
                slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
                created_at_unix=1_787_000_100,
            )
            make_job(
                jobs,
                suffix="a00000000031",
                slot="A",
                terminal_status="succeeded",
                review_result=None,
                created_at_unix=1_787_000_200,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(
            any(
                error.startswith("decision_review_infrastructure_not_superseded:a:")
                for error in reconciled["errors"]
            )
        )

    def test_succeeded_missing_result_can_be_replaced_by_later_proven_pass_in_same_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000031",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                created_at_unix=1_787_000_100,
            )
            make_job(
                jobs,
                suffix="a00000000032",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                created_at_unix=1_787_000_200,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["errors"], [])
        slot = reconciled["slots"][0]
        self.assertEqual(slot["independent_pass_count"], 1)
        self.assertEqual(slot["infrastructure_error_count"], 1)
        self.assertEqual(slot["unresolved_count"], 0)
        self.assertEqual(
            {item["classification"] for item in reconciled["attempts"]},
            {"infrastructure_error", "pass"},
        )

    def test_unsuccessful_missing_role_receipt_can_be_replaced_by_later_proven_pass(self) -> None:
        for terminal_status in ("failed", "timed_out", "signalled", "terminated_unclear"):
            with self.subTest(terminal_status=terminal_status):
                with tempfile.TemporaryDirectory() as tmp:
                    jobs = Path(tmp)
                    missing = make_job(
                        jobs,
                        suffix="a00000000039",
                        slot="independent-reviewer",
                        terminal_status=terminal_status,
                        review_result=None,
                        review_role=True,
                        created_at_unix=1_787_000_100,
                    )
                    (missing / "review-role-receipt.json").unlink()
                    make_job(
                        jobs,
                        suffix="a00000000040",
                        slot="independent-reviewer",
                        terminal_status="succeeded",
                        review_result=None,
                        review_role=True,
                        created_at_unix=1_787_000_200,
                    )
                    reconciled = self.reconcile(jobs)
                self.assertEqual(reconciled["status"], "settled")
                self.assertEqual(reconciled["errors"], [])
                slot = reconciled["slots"][0]
                self.assertEqual(slot["independent_pass_count"], 1)
                self.assertEqual(slot["infrastructure_error_count"], 1)
                self.assertEqual(slot["unresolved_count"], 0)
                self.assertEqual(
                    {item["classification"] for item in reconciled["attempts"]},
                    {"infrastructure_error", "pass"},
                )

    def test_succeeded_missing_role_receipt_stays_blocking_after_later_proven_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            missing = make_job(
                jobs,
                suffix="a00000000043",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                created_at_unix=1_787_000_100,
            )
            (missing / "review-role-receipt.json").unlink()
            make_job(
                jobs,
                suffix="a00000000044",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                created_at_unix=1_787_000_200,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(
            any(
                error.startswith(
                    "decision_review_result_invalid:grabowski-job-a00000000043:FileNotFoundError"
                )
                for error in reconciled["errors"]
            )
        )
        slot = reconciled["slots"][0]
        self.assertEqual(slot["independent_pass_count"], 1)
        self.assertEqual(slot["infrastructure_error_count"], 0)
        self.assertEqual(slot["unresolved_count"], 1)
        self.assertEqual(
            {item["classification"] for item in reconciled["attempts"]},
            {"invalid_result", "pass"},
        )

    def test_malformed_role_receipt_stays_blocking_after_later_proven_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            malformed = make_job(
                jobs,
                suffix="a00000000041",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                created_at_unix=1_787_000_100,
            )
            write_private(malformed / "review-role-receipt.json", "{}")
            make_job(
                jobs,
                suffix="a00000000042",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
                created_at_unix=1_787_000_200,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(
            any(
                error.startswith(
                    "decision_review_result_invalid:grabowski-job-a00000000041:ValueError"
                )
                for error in reconciled["errors"]
            )
        )
        slot = reconciled["slots"][0]
        self.assertEqual(slot["independent_pass_count"], 1)
        self.assertEqual(slot["infrastructure_error_count"], 0)
        self.assertEqual(slot["unresolved_count"], 1)

    def test_material_reject_remains_blocking_after_later_proven_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(
                jobs,
                suffix="a00000000033",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=result(
                    "independent-reviewer", "REJECT_THIS_REVISION", 1
                ),
            )
            make_job(
                jobs,
                suffix="a00000000034",
                slot="independent-reviewer",
                terminal_status="succeeded",
                review_result=None,
                review_role=True,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        slot = reconciled["slots"][0]
        self.assertEqual(slot["material_reject_count"], 1)
        self.assertEqual(slot["independent_pass_count"], 1)
        self.assertTrue(
            any(
                error.startswith(
                    "decision_review_material_reject:independent-reviewer:"
                )
                for error in reconciled["errors"]
            )
        )

    def test_later_pass_does_not_erase_prior_material_reject_in_same_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(jobs, suffix="a0000000000a", slot="A", terminal_status="succeeded", review_result=result("A", "REJECT_THIS_REVISION", 2))
            make_job(jobs, suffix="a0000000000b", slot="A", terminal_status="succeeded", review_result=result("A", "PASS_THIS_REVISION", 0))
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        a_slot = next(item for item in reconciled["slots"] if item["slot"] == "a")
        self.assertEqual(a_slot["material_reject_count"], 1)
        self.assertEqual(a_slot["pass_count"], 1)

    def test_success_without_structured_result_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            make_job(jobs, suffix="c0000000000c", slot="A", terminal_status="succeeded", review_result=None)
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertIn("decision_review_slot_without_pass:a", reconciled["errors"])
        self.assertFalse(
            any(
                error.startswith("decision_review_success_missing_result:")
                for error in reconciled["errors"]
            )
        )

    def test_oversized_stdout_blocks_instead_of_hiding_earlier_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            directory = make_job(
                jobs,
                suffix="d0000000000d",
                slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            marker = reviews.RESULT_PREFIX + json.dumps(
                result("A", "REJECT_THIS_REVISION", 1), separators=(",", ":")
            ) + "\n"
            write_private(
                directory / "stdout.log",
                marker + ("x" * reviews.MAX_STDOUT_TAIL_BYTES),
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(any(error.startswith("decision_review_result_invalid:") for error in reconciled["errors"]))

    def test_proven_not_started_attempt_can_be_replaced_in_same_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            directory = make_job(
                jobs,
                suffix="e0000000000e",
                slot="A",
                terminal_status=None,
                review_result=None,
                created_at_unix=1_787_000_100,
            )
            metadata_path = directory / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata.update(
                {
                    "final_status": "launch_failed",
                    "dispatch_outcome": "not_started",
                    "terminalization_evidence": {
                        "source": "systemd-run-launch",
                        "query_valid": True,
                        "final_status": "launch_failed",
                        "systemd_visible": False,
                    },
                    "launcher_evidence": {"returncode": 1},
                }
            )
            write_private(metadata_path, json.dumps(metadata))
            make_job(
                jobs,
                suffix="e0000000000f",
                slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
                created_at_unix=1_787_000_200,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        slot = next(item for item in reconciled["slots"] if item["slot"] == "a")
        self.assertEqual(slot["infrastructure_error_count"], 1)
        self.assertEqual(slot["pass_count"], 1)

    def test_exact_empty_prelaunch_footprints_do_not_block_valid_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa501", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            names = []
            for i in range(8):
                directory = jobs / f"grabowski-job-{0xabc000000000+i:012x}"
                directory.mkdir(mode=0o700)
                write_private(directory / "stdout.log", "")
                write_private(directory / "stderr.log", "")
                names.append(directory.name)
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "settled")
        self.assertEqual(checked["errors"], [])
        self.assertEqual(checked["attempt_count"], 1)
        self.assertEqual(checked["skipped_prelaunch_stub_count"], 8)
        self.assertEqual(
            checked["skipped_prelaunch_stub_units_sha256"],
            reviews.sha256_json(sorted(names)),
        )

    def test_late_foreign_directory_metadata_blocks_settlement(self) -> None:
        # A foreign child may gain suspicious review metadata after it was
        # inspected, without advancing the jobs root's timestamps.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            foreign = jobs / "foreign-review-holder"
            foreign.mkdir(mode=0o700)
            passed = make_job(
                jobs, suffix="aaaaaaaaa501", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            original = reviews._validated_origin_binding
            published = False

            def publish_after_foreign_scan(directory, *args, **kwargs):
                nonlocal published
                if directory == passed and not published:
                    write_private(
                        foreign / "metadata.json",
                        json.dumps({"scope": {"decision_bound_review": binding("A")}}),
                    )
                    published = True
                return original(directory, *args, **kwargs)

            with mock.patch.object(
                reviews, "_validated_origin_binding",
                side_effect=publish_after_foreign_scan,
            ):
                first = self.reconcile(jobs)
            self.assertTrue(published)
            self.assertEqual(first["status"], "blocked")
            self.assertIn("decision_review_job_directory_changed", first["errors"])
            second = self.reconcile(jobs)
            self.assertEqual(second["status"], "blocked")
            self.assertIn(
                "decision_review_noncanonical_job_directory", second["errors"],
            )

    def test_late_publication_inside_skipped_stub_blocks_settlement(self) -> None:
        # A child already classified as an exact prelaunch stub can publish
        # a material REJECT while the scanner processes a later PASS. Root
        # directory timestamps remain unchanged by those child writes.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            rejected = make_job(
                jobs, suffix="000000000001", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            parked = Path(temp) / "parked"
            parked.mkdir(mode=0o700)
            for item in list(rejected.iterdir()):
                os.replace(item, parked / item.name)
            write_private(rejected / "stdout.log", "")
            write_private(rejected / "stderr.log", "")
            passed = make_job(
                jobs, suffix="aaaaaaaaa501", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            original = reviews._validated_origin_binding
            published = False

            def publish_after_stub(directory, *args, **kwargs):
                nonlocal published
                if directory == passed and not published:
                    for item in list(parked.iterdir()):
                        if item.name in {"stdout.log", "stderr.log"}:
                            write_private(rejected / item.name, item.read_text())
                            item.unlink()
                        else:
                            os.replace(item, rejected / item.name)
                    published = True
                return original(directory, *args, **kwargs)

            with mock.patch.object(
                reviews, "_validated_origin_binding",
                side_effect=publish_after_stub,
            ):
                first = self.reconcile(jobs)
            self.assertTrue(published)
            self.assertEqual(first["status"], "blocked")
            self.assertIn("decision_review_job_directory_changed", first["errors"])
            second = self.reconcile(jobs)
            self.assertEqual(second["status"], "blocked")
            self.assertTrue(any(
                "decision_review" in error for error in second["errors"]
            ))

    def test_late_inplace_stdout_rewrite_blocks_first_settlement(self) -> None:
        # Unlike new directory entries, rewriting an existing stdout inode
        # leaves the containing job directory timestamps unchanged.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            earlier = make_job(
                jobs, suffix="aaaaaaaaa501", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            later = make_job(
                jobs, suffix="bbbbbbbbb502", slot="B",
                terminal_status="succeeded",
                review_result=result("B", "PASS_THIS_REVISION", 0),
            )
            stdout = earlier / "stdout.log"
            original_inode = stdout.stat().st_ino
            original = reviews._validated_origin_binding
            published = False

            def rewrite_earlier_stdout(directory, *args, **kwargs):
                nonlocal published
                if directory == later and not published:
                    write_private(
                        stdout,
                        reviews.RESULT_PREFIX + json.dumps(
                            result("A", "REJECT_THIS_REVISION", 1)
                        ) + "\n",
                    )
                    self.assertEqual(stdout.stat().st_ino, original_inode)
                    published = True
                return original(directory, *args, **kwargs)

            with mock.patch.object(
                reviews, "_validated_origin_binding",
                side_effect=rewrite_earlier_stdout,
            ):
                first = self.reconcile(jobs)
            self.assertTrue(published)
            self.assertEqual(first["status"], "blocked")
            self.assertIn("decision_review_job_file_changed", first["errors"])
            second = self.reconcile(jobs)
            self.assertEqual(second["status"], "blocked")

    def test_late_inplace_foreign_stdout_rewrite_blocks_settlement(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            foreign = jobs / "report-bundle"
            foreign.mkdir(mode=0o700)
            stdout = foreign / "stdout.log"
            write_private(stdout, "ordinary output\n")
            stdout.chmod(0o644)
            original_inode = stdout.stat().st_ino
            passed = make_job(
                jobs, suffix="aaaaaaaaa501", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            original = reviews._validated_origin_binding
            published = False

            def rewrite_foreign_stdout(directory, *args, **kwargs):
                nonlocal published
                if directory == passed and not published:
                    write_private(
                        stdout,
                        reviews.RESULT_PREFIX + json.dumps(
                            result("A", "REJECT_THIS_REVISION", 1)
                        ) + "\n",
                    )
                    stdout.chmod(0o644)
                    self.assertEqual(stdout.stat().st_ino, original_inode)
                    published = True
                return original(directory, *args, **kwargs)

            with mock.patch.object(
                reviews, "_validated_origin_binding",
                side_effect=rewrite_foreign_stdout,
            ):
                first = self.reconcile(jobs)
            self.assertTrue(published)
            self.assertEqual(first["status"], "blocked")
            self.assertIn("decision_review_job_file_changed", first["errors"])
            second = self.reconcile(jobs)
            self.assertEqual(second["status"], "blocked")
            self.assertIn(
                f"decision_review_unbound_result:{foreign.name}",
                second["errors"],
            )

    def test_foreign_role_receipts_share_bounded_aggregate(self) -> None:
        # Individually bounded role receipts must not bypass the total read
        # budget merely because each belongs to an ordinary/foreign job.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            for index in (1, 2):
                directory = jobs / (
                    f"grabowski-job-rgpm-0123456789abcdef-{index:02d}"
                )
                directory.mkdir(mode=0o700)
                write_private(directory / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME,
                              json.dumps({"expected_head": "0" * 40,
                                          "payload": "x" * 2500}))
                write_private(directory / "stdout.log", "")
            make_job(
                jobs, suffix="aaaaaaaaa501", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            with mock.patch.object(reviews, "MAX_TOTAL_METADATA_BYTES", 4096):
                checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertTrue(any(
            error.startswith("decision_review_unbound_evidence_invalid:")
            for error in checked["errors"]
        ))

    def test_only_exact_empty_prelaunch_footprints_are_exempt(self) -> None:
        variants = (
            "stdout_nonempty", "stderr_nonempty", "finalization",
            "role_receipt", "extra_file", "stdout_symlink", "stdout_fifo",
            "stdout_hardlink", "wrong_file_mode", "wrong_directory_mode",
            "missing_stdout", "missing_stderr",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temp:
                    jobs = Path(temp) / "jobs"
                    jobs.mkdir(mode=0o700)
                    make_job(
                        jobs, suffix="aaaaaaaaa501", slot="A",
                        terminal_status="succeeded",
                        review_result=result("A", "PASS_THIS_REVISION", 0),
                    )
                    directory = jobs / "grabowski-job-bbbbbbbbb502"
                    directory.mkdir(mode=0o700)
                    write_private(directory / "stdout.log", "")
                    write_private(directory / "stderr.log", "")
                    stdout = directory / "stdout.log"
                    stderr = directory / "stderr.log"
                    if variant == "stdout_nonempty":
                        write_private(stdout, "REJECT_THIS_REVISION")
                    elif variant == "stderr_nonempty":
                        write_private(stderr, "worker launched")
                    elif variant == "finalization":
                        write_private(directory / "finalization.json", "{}")
                    elif variant == "role_receipt":
                        write_private(directory / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME, "{}")
                    elif variant == "extra_file":
                        write_private(directory / "other.txt", "")
                    elif variant == "stdout_symlink":
                        stdout.unlink()
                        stdout.symlink_to(stderr)
                    elif variant == "stdout_fifo":
                        stdout.unlink()
                        os.mkfifo(stdout, 0o600)
                    elif variant == "stdout_hardlink":
                        os.link(stdout, Path(temp) / "other-hardlink")
                    elif variant == "wrong_file_mode":
                        stdout.chmod(0o644)
                    elif variant == "wrong_directory_mode":
                        directory.chmod(0o755)
                    elif variant == "missing_stdout":
                        stdout.unlink()
                    elif variant == "missing_stderr":
                        stderr.unlink()
                    checked = self.reconcile(jobs)
                self.assertEqual(checked["status"], "blocked")
                if variant == "wrong_directory_mode":
                    self.assertIn(
                        "decision_review_job_inventory_unverifiable", checked["errors"],
                    )
                else:
                    self.assertIn(
                        "decision_review_origin_invalid:grabowski-job-bbbbbbbbb502:",
                        " ".join(checked["errors"]),
                    )

    def test_unrecognizable_reject_origin_cannot_leave_a_prior_pass_settled(self) -> None:
        # Damage may erase every raw PR/head hint from the REJECT's metadata.
        # A separate valid PASS must never establish a settled verdict.
        for damaged in (None, "{}", "not-valid-json", '{"scope":{"decision_bound_review":null}}'):
            with self.subTest(damaged=damaged):
                with tempfile.TemporaryDirectory() as temp:
                    jobs = Path(temp) / "jobs"
                    jobs.mkdir(mode=0o700)
                    make_job(
                        jobs, suffix="aaaaaaaaa311", slot="A",
                        terminal_status="succeeded",
                        review_result=result("A", "PASS_THIS_REVISION", 0),
                    )
                    rejected = make_job(
                        jobs, suffix="bbbbbbbbb312", slot="A",
                        terminal_status="succeeded",
                        review_result=result("A", "REJECT_THIS_REVISION", 1),
                    )
                    before = self.reconcile(jobs)
                    self.assertEqual(before["status"], "blocked")
                    self.assertEqual(before["attempt_count"], 2)
                    if damaged is None:
                        (rejected / "metadata.json").unlink()
                    else:
                        write_private(rejected / "metadata.json", damaged)
                    checked = self.reconcile(jobs)
                self.assertEqual(checked["status"], "blocked")
                error_type = "FileNotFoundError" if damaged is None else "ValueError"
                self.assertIn(
                    f"decision_review_origin_invalid:grabowski-job-bbbbbbbbb312:{error_type}",
                    checked["errors"],
                )
                self.assertEqual(checked["attempt_count"], 1)

    def test_signed_nonreview_replacement_cannot_erase_material_reject(self) -> None:
        # A self-consistent ordinary origin can replace a review origin while
        # leaving an authentic REJECT marker in the unchanged job stdout.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa211", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            rejected = make_job(
                jobs, suffix="bbbbbbbbb212", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            before = self.reconcile(jobs)
            self.assertEqual(before["status"], "blocked")
            metadata_path = rejected / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            scope = dict(metadata["scope"])
            scope.pop("decision_bound_review", None)
            scope.pop("decision_review_provenance", None)
            scope.pop("decision_review_attempt_epoch", None)
            metadata["scope"] = scope
            metadata["origin"]["scope"] = scope
            metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
            write_private(metadata_path, json.dumps(metadata))
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertTrue(
            any("decision_review_unbound_result:" in e for e in checked["errors"])
        )

    def test_valid_foreign_review_rebinding_cannot_hide_local_reject(self) -> None:
        # A valid metadata+origin digest for another revision must not erase
        # the original decision still present in the same job's stdout.
        for drift in ({"pr": PR + 1}, {"head_sha": "d" * 40}):
            with self.subTest(drift=drift):
                with tempfile.TemporaryDirectory() as temp:
                    jobs = Path(temp) / "jobs"
                    jobs.mkdir(mode=0o700)
                    make_job(
                        jobs, suffix="aaaaaaaaa219", slot="A",
                        terminal_status="succeeded",
                        review_result=result("A", "PASS_THIS_REVISION", 0),
                    )
                    rejected = make_job(
                        jobs, suffix="bbbbbbbbb220", slot="A",
                        terminal_status="succeeded",
                        review_result=result("A", "REJECT_THIS_REVISION", 1),
                    )
                    if "head_sha" in drift:
                        # The normal result parser accepts normalized case.
                        upper = result("A", "REJECT_THIS_REVISION", 1)
                        upper["repo"] = upper["repo"].upper()
                        upper["head_sha"] = upper["head_sha"].upper()
                        write_private(
                            rejected / "stdout.log",
                            reviews.RESULT_PREFIX + json.dumps(upper) + "\n",
                        )
                    before = self.reconcile(jobs)
                    self.assertEqual(before["status"], "blocked")
                    metadata_path = rejected / "metadata.json"
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    scope = dict(metadata["scope"])
                    bound = dict(scope["decision_bound_review"])
                    bound.update(drift)
                    scope["decision_bound_review"] = bound
                    metadata["scope"] = scope
                    metadata["origin"]["scope"] = scope
                    metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
                    write_private(metadata_path, json.dumps(metadata))
                    checked = self.reconcile(jobs)
                self.assertEqual(checked["status"], "blocked")
                self.assertIn(
                    f"decision_review_unbound_result:{rejected.name}",
                    checked["errors"],
                )

    def test_signed_foreign_review_with_unavailable_historical_provenance_is_unrelated(self) -> None:
        # A genuine old reviewer from another repo cannot veto every other
        # repository solely because its old executable has rotated away.
        # An exact-bound result or role receipt must still be discovered.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa291", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            with mock.patch.dict(
                make_job.__globals__,
                {"REPO": "heimgewebe/other", "PR": PR + 1,
                 "HEAD": "d" * 40, "BASE": "e" * 40},
            ):
                foreign = make_job(
                    jobs, suffix="bbbbbbbbb292", slot="independent-reviewer",
                    terminal_status="succeeded", review_result=None,
                    review_role=True, attempt_bound=True, attempt_epoch=2,
                )
            metadata_path = foreign / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            scope = dict(metadata["scope"])
            provenance = dict(scope["decision_review_provenance"])
            provenance["runner_module_sha256"] = "f" * 64
            provenance["provenance_sha256"] = reviews.sha256_json({
                key: value for key, value in provenance.items()
                if key != "provenance_sha256"
            })
            scope["decision_review_provenance"] = provenance
            metadata["scope"] = scope
            metadata["origin"]["scope"] = scope
            metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
            write_private(metadata_path, json.dumps(metadata))
            checked = self.reconcile(jobs)
        self.assertEqual("settled", checked["status"])
        self.assertEqual([], checked["errors"])
        self.assertEqual(1, checked["attempt_count"])

    def test_signed_unbound_24m_log_is_scanned_for_retained_reject(self) -> None:
        # A real ordinary job emitted >22MiB on the productive operator.
        # We must inspect the entire bounded output, including a late REJECT.
        for retained_reject in (False, True):
            with self.subTest(retained_reject=retained_reject):
                with tempfile.TemporaryDirectory() as temp:
                    jobs = Path(temp) / "jobs"
                    jobs.mkdir(mode=0o700)
                    make_job(
                        jobs, suffix="aaaaaaaaa293", slot="A",
                        terminal_status="succeeded",
                        review_result=result("A", "PASS_THIS_REVISION", 0),
                    )
                    ordinary = jobs / "grabowski-job-bbbbbbbbb294"
                    ordinary.mkdir(mode=0o700)
                    scope = {
                        "cwd": "/tmp", "argv_sha256": "e" * 64,
                        "runtime_seconds": 60,
                    }
                    origin, digest = job_origin.build_origin(
                        unit=ordinary.name, owner=f"uid:{os.getuid()}",
                        argv_sha256="e" * 64, scope=scope,
                        notify_on_done={"requested": False, "channels": []},
                        created_at_unix=1_787_000_000,
                        started_at="2026-08-18T12:00:00Z",
                        invoker_tool="grabowski_job_start",
                    )
                    write_private(ordinary / "metadata.json", json.dumps({
                        "unit": ordinary.name, "job_id": origin["job_id"],
                        "owner": origin["owner"], "argv_sha256": origin["argv_sha256"],
                        "scope": scope, "origin": origin, "origin_sha256": digest,
                    }))
                    stdout = ordinary / "stdout.log"
                    with stdout.open("wb") as stream:
                        stream.truncate(24 * 1024 * 1024)
                        if retained_reject:
                            stream.seek(24 * 1024 * 1024 - 2048)
                            marker = (
                                "\n" + reviews.RESULT_PREFIX +
                                json.dumps(result("A", "REJECT_THIS_REVISION", 1))
                                + "\n"
                            )
                            stream.write(marker.encode("utf-8"))
                    os.chmod(stdout, 0o600)
                    checked = self.reconcile(jobs)
                if retained_reject:
                    self.assertEqual("blocked", checked["status"])
                    self.assertIn(
                        f"decision_review_unbound_result:{ordinary.name}",
                        checked["errors"],
                    )
                else:
                    self.assertEqual("settled", checked["status"])
                    self.assertEqual([], checked["errors"])

    def test_legitimate_unbound_job_with_stdout_does_not_block_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa213", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            ordinary = jobs / "grabowski-job-bbbbbbbbb214"
            ordinary.mkdir(mode=0o700)
            scope = {"cwd": "/tmp", "argv_sha256": "e" * 64, "runtime_seconds": 60}
            origin, digest = job_origin.build_origin(
                unit=ordinary.name, owner=f"uid:{os.getuid()}",
                argv_sha256="e" * 64, scope=scope,
                notify_on_done={"requested": False, "channels": []},
                created_at_unix=1_787_000_000,
                started_at="2026-08-18T12:00:00Z",
                invoker_tool="grabowski_job_start",
            )
            write_private(ordinary / "metadata.json", json.dumps({
                "unit": ordinary.name, "job_id": origin["job_id"],
                "owner": origin["owner"], "argv_sha256": origin["argv_sha256"],
                "scope": scope, "origin": origin, "origin_sha256": digest,
            }))
            # Unbound tasks can legitimately echo the marker *name* without
            # emitting a complete line-bound decision for this revision.
            write_private(
                ordinary / "stdout.log",
                reviews.RESULT_PREFIX + "not-valid-json\\n" +
                "ordinary job output GRABOWSKI_DECISION_REVIEW_V1=example\\n",
            )
            write_private(
                ordinary / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME,
                json.dumps({"expected_head": "d" * 40}),
            )
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "settled")
        self.assertEqual(checked["attempt_count"], 1)
        self.assertEqual(checked["errors"], [])

    def test_foreign_v2_receipt_matching_only_head_cannot_block_or_hide_reject(self) -> None:
        # An ordinary job's unauthenticated role receipt can name the same
        # HEAD but a different BASE and DIFF. It cannot deny an independent
        # review of this revision, unless residual exact-bound evidence exists.
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa241", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            ordinary = jobs / "grabowski-job-bbbbbbbbb242"
            ordinary.mkdir(mode=0o700)
            scope = {
                "cwd": "/tmp", "argv_sha256": "e" * 64,
                "runtime_seconds": 60,
            }
            origin, digest = job_origin.build_origin(
                unit=ordinary.name, owner=f"uid:{os.getuid()}",
                argv_sha256="e" * 64, scope=scope,
                notify_on_done={"requested": False, "channels": []},
                created_at_unix=1_787_000_000,
                started_at="2026-08-18T12:00:00Z",
                invoker_tool="grabowski_job_start",
            )
            write_private(ordinary / "metadata.json", json.dumps({
                "unit": ordinary.name, "job_id": origin["job_id"],
                "owner": origin["owner"], "argv_sha256": origin["argv_sha256"],
                "scope": scope, "origin": origin, "origin_sha256": digest,
            }))
            stdout = ordinary / "stdout.log"
            write_private(stdout, "")
            write_private(
                ordinary / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME,
                json.dumps({
                    "expected_head": HEAD,
                    "expected_base_head": "d" * 40,
                    "expected_diff_sha256": "e" * 64,
                }),
            )
            unrelated = self.reconcile(jobs)
            self.assertEqual(unrelated["status"], "settled")
            self.assertEqual(unrelated["errors"], [])
            self.assertEqual(unrelated["attempt_count"], 1)

            # If metadata was rebound but the genuine review stdout remains,
            # a material REJECT for this exact revision must still block.
            write_private(
                stdout,
                reviews.RESULT_PREFIX +
                json.dumps(result("A", "REJECT_THIS_REVISION", 1)) + "\n",
            )
            retained_reject = self.reconcile(jobs)
        self.assertEqual(retained_reject["status"], "blocked")
        self.assertIn(
            f"decision_review_unbound_result:{ordinary.name}",
            retained_reject["errors"],
        )

    def test_replaced_v2_origin_with_role_receipt_still_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa215", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            rejected = make_job(
                jobs, suffix="bbbbbbbbb216", slot="A",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
            )
            self.assertTrue((rejected / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME).is_file())
            metadata_path = rejected / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            scope = dict(metadata["scope"])
            for key in (
                "decision_bound_review", "decision_review_provenance",
                "decision_review_attempt_epoch",
            ):
                scope.pop(key, None)
            metadata["scope"] = scope
            metadata["origin"]["scope"] = scope
            metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
            write_private(metadata_path, json.dumps(metadata))
            # A surviving, exactly bound V2 role receipt stays blocking even
            # when stdout itself exceeds the ordinary-job inspection cap.
            with (rejected / "stdout.log").open("wb") as stream:
                stream.truncate(reviews.MAX_UNBOUND_STDOUT_BYTES + 1)
            os.chmod(rejected / "stdout.log", 0o600)
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn(
            f"decision_review_unbound_result:{rejected.name}", checked["errors"]
        )

    def test_preserved_material_reject_padded_after_origin_rewrite_stays_blocked(self) -> None:
        # A legitimate bound REJECT must not disappear solely because its
        # surviving stdout grows beyond the unrelated-job inspection limit.
        # Only synthetic private fixtures are modified, never real job data.
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa251", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            rejected = make_job(
                jobs, suffix="bbbbbbbbb252", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "REJECT_THIS_REVISION", 1),
            )
            self.assertEqual(self.reconcile(jobs)["status"], "blocked")
            metadata_path = rejected / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            scope = dict(metadata["scope"])
            for key in (
                "decision_bound_review", "decision_review_provenance",
                "decision_review_attempt_epoch",
            ):
                scope.pop(key, None)
            metadata["scope"] = scope
            metadata["origin"]["scope"] = scope
            metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
            write_private(metadata_path, json.dumps(metadata))
            stdout = rejected / "stdout.log"
            original = stdout.read_bytes()
            with stdout.open("ab") as stream:
                stream.truncate(reviews.MAX_UNBOUND_STDOUT_BYTES + 1)
            with stdout.open("rb") as stream:
                self.assertEqual(stream.read(len(original)), original)
            checked = self.reconcile(jobs)
        self.assertEqual(checked["status"], "blocked")
        self.assertTrue(any(
            error.startswith("decision_review_unbound_")
            for error in checked["errors"]
        ))

    def test_unbound_oversized_stdout_without_origin_proof_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="aaaaaaaaa217", slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            ordinary = jobs / "grabowski-job-bbbbbbbbb218"
            ordinary.mkdir(mode=0o700)
            scope = {"cwd": "/tmp", "argv_sha256": "e" * 64, "runtime_seconds": 60}
            origin, digest = job_origin.build_origin(
                unit=ordinary.name, owner=f"uid:{os.getuid()}",
                argv_sha256="e" * 64, scope=scope,
                notify_on_done={"requested": False, "channels": []},
                created_at_unix=1_787_000_000,
                started_at="2026-08-18T12:00:00Z",
                invoker_tool="grabowski_job_start",
            )
            write_private(ordinary / "metadata.json", json.dumps({
                "unit": ordinary.name, "job_id": origin["job_id"],
                "owner": origin["owner"], "argv_sha256": origin["argv_sha256"],
                "scope": scope, "origin": origin, "origin_sha256": digest,
            }))
            with (ordinary / "stdout.log").open("wb") as stream:
                stream.truncate(reviews.MAX_UNBOUND_STDOUT_BYTES + 1)
            os.chmod(ordinary / "stdout.log", 0o600)
            checked = self.reconcile(jobs)
        # Without a separately authenticated origin, this could be a former
        # reviewer whose retained material REJECT now lies beyond the limit.
        self.assertEqual(checked["status"], "blocked")
        self.assertIn(
            f"decision_review_unbound_evidence_invalid:{ordinary.name}:ValueError",
            checked["errors"],
        )

    def test_foreign_historical_origin_is_not_current_review(self) -> None:
        # A hash-valid foreign job may contain stale, currently unverifiable
        # semantic role provenance. It is not a review of this PR/head.
        # A surviving exact-bound REJECT must nevertheless remain visible.
        for retained_reject in (False, True):
            with self.subTest(retained_reject=retained_reject):
                with tempfile.TemporaryDirectory() as tmp:
                    jobs = Path(tmp) / "jobs"
                    jobs.mkdir(mode=0o700)
                    make_job(
                        jobs, suffix="aaaaaaaaa401", slot="A",
                        terminal_status="succeeded",
                        review_result=result("A", "PASS_THIS_REVISION", 0),
                    )
                    foreign = make_job(
                        jobs, suffix="bbbbbbbbb402", slot="A",
                        terminal_status="succeeded", review_result=None,
                    )
                    metadata_path = foreign / "metadata.json"
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    scope = dict(metadata["scope"])
                    bound = dict(scope["decision_bound_review"])
                    bound.update({
                        "repo": "heimgewebe/repoground",
                        "pr": 1357,
                        "head_sha": "f" * 40,
                        "base_sha": "e" * 40,
                    })
                    scope["decision_bound_review"] = bound
                    scope["decision_review_attempt_epoch"] = 2
                    scope["decision_review_provenance"] = {
                        "schema_version": 2, "obsolete_runner": "old-release",
                    }
                    metadata["scope"] = scope
                    metadata["origin"]["scope"] = scope
                    metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
                    write_private(metadata_path, json.dumps(metadata))
                    if retained_reject:
                        write_private(
                            foreign / "stdout.log",
                            reviews.RESULT_PREFIX +
                            json.dumps(result("A", "REJECT_THIS_REVISION", 1)) + "\n",
                        )
                    outcome = self.reconcile(jobs)
                if retained_reject:
                    self.assertEqual(outcome["status"], "blocked")
                    self.assertIn(
                        f"decision_review_unbound_result:{foreign.name}", outcome["errors"],
                    )
                else:
                    self.assertEqual(outcome["status"], "settled")
                    self.assertEqual(outcome["errors"], [])

    def test_ordinary_24mb_stdout_stream_preserves_late_reject(self) -> None:
        # Exercise the actual 24,092,538-byte failure size with no giant
        # in-memory test string; the marker may be the very last line.
        for retained_reject in (False, True):
            with self.subTest(retained_reject=retained_reject):
                with tempfile.TemporaryDirectory() as tmp:
                    jobs = Path(tmp) / "jobs"
                    jobs.mkdir(mode=0o700)
                    make_job(
                        jobs, suffix="aaaaaaaaa411", slot="A",
                        terminal_status="succeeded",
                        review_result=result("A", "PASS_THIS_REVISION", 0),
                    )
                    ordinary = jobs / "grabowski-job-bbbbbbbbb412"
                    ordinary.mkdir(mode=0o700)
                    scope = {
                        "cwd": "/tmp", "argv_sha256": "e" * 64,
                        "runtime_seconds": 60,
                    }
                    origin, digest = job_origin.build_origin(
                        unit=ordinary.name, owner=f"uid:{os.getuid()}",
                        argv_sha256="e" * 64, scope=scope,
                        notify_on_done={"requested": False, "channels": []},
                        created_at_unix=1_787_000_000,
                        started_at="2026-08-18T12:00:00Z",
                        invoker_tool="grabowski_job_start",
                    )
                    write_private(ordinary / "metadata.json", json.dumps({
                        "unit": ordinary.name, "job_id": origin["job_id"],
                        "owner": origin["owner"], "argv_sha256": origin["argv_sha256"],
                        "scope": scope, "origin": origin, "origin_sha256": digest,
                    }))
                    marker = (
                        b"\n" + reviews.RESULT_PREFIX.encode("ascii") +
                        json.dumps(result("A", "REJECT_THIS_REVISION", 1)).encode("ascii") +
                        b"\n"
                    ) if retained_reject else b""
                    with (ordinary / "stdout.log").open("wb") as stream:
                        stream.write(b"ordinary job output\n")
                        stream.seek(24_092_538 - len(marker))
                        stream.write(marker)
                        stream.truncate(24_092_538)
                    os.chmod(ordinary / "stdout.log", 0o600)
                    outcome = self.reconcile(jobs)
                if retained_reject:
                    self.assertEqual(outcome["status"], "blocked")
                    self.assertIn(
                        f"decision_review_unbound_result:{ordinary.name}",
                        outcome["errors"],
                    )
                else:
                    self.assertEqual(outcome["status"], "settled")
                    self.assertEqual(outcome["errors"], [])

    def test_malformed_targeted_registration_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp)
            directory = make_job(
                jobs,
                suffix="f00000000010",
                slot="A",
                terminal_status="succeeded",
                review_result=result("A", "PASS_THIS_REVISION", 0),
            )
            metadata_path = directory / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            del metadata["scope"]["decision_bound_review"]["slot"]
            write_private(metadata_path, json.dumps(metadata))
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertTrue(any(error.startswith("decision_review_origin_invalid:") for error in reconciled["errors"]))


    def test_job_owned_attempt_receipts_are_distinct_across_parallel_slots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            first = make_job(jobs, suffix="a11111111111", slot="A",
                             terminal_status="succeeded", review_result=None,
                             review_role=True, attempt_bound=True)
            second = make_job(jobs, suffix="b22222222222", slot="A",
                              terminal_status="succeeded", review_result=None,
                              review_role=True, attempt_bound=True)
            provider = make_job(jobs, suffix="c33333333333", slot="B",
                                terminal_status="succeeded", review_result=None,
                                review_role=True, attempt_bound=True)
            names = {str(p / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME) for p in (first, second, provider)}
            self.assertEqual(len(names), 3)
            output = self.reconcile(jobs)
        self.assertEqual(output["status"], "settled")
        self.assertEqual(output["attempt_count"], 3)
        self.assertTrue(all(slot["pass_count"] > 0 for slot in output["slots"]))

    def test_job_owned_attempt_receipt_swap_is_invalid_not_superseded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            first = make_job(jobs, suffix="a11111111111", slot="A",
                             terminal_status="succeeded", review_result=None,
                             review_role=True, attempt_bound=True)
            second = make_job(jobs, suffix="b22222222222", slot="A",
                              terminal_status="succeeded", review_result=None,
                              review_role=True, attempt_bound=True)
            name = reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
            write_private(second / name, (first / name).read_text(encoding="utf-8"))
            output = self.reconcile(jobs)
        self.assertEqual(output["status"], "blocked")
        self.assertIn("decision_review_result_invalid:grabowski-job-b22222222222:ValueError", output["errors"])

    def test_job_owned_attempt_path_tamper_is_not_an_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            first = make_job(jobs, suffix="a11111111111", slot="A",
                             terminal_status="succeeded", review_result=None,
                             review_role=True, attempt_bound=True)
            second = make_job(jobs, suffix="b22222222222", slot="A",
                              terminal_status="succeeded", review_result=None,
                              review_role=True, attempt_bound=True)
            metadata_path = second / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            provenance = metadata["scope"]["decision_review_provenance"]
            provenance["role_receipt_path"] = str(first / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME)
            provenance["provenance_sha256"] = reviews.sha256_json(
                {key: value for key, value in provenance.items() if key != "provenance_sha256"}
            )
            metadata["origin"]["scope"]["decision_review_provenance"] = provenance
            metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
            write_private(metadata_path, json.dumps(metadata))
            output = self.reconcile(jobs)
        self.assertEqual(output["status"], "blocked")
        self.assertTrue(any(error.startswith("decision_review_origin_invalid:grabowski-job-b22222222222:")
                            for error in output["errors"]))

    def test_job_owned_attempt_symlink_and_hardlink_receipts_are_invalid(self) -> None:
        for link_type in ("symlink", "hardlink"):
            with self.subTest(link_type=link_type):
                with tempfile.TemporaryDirectory() as temporary:
                    jobs = Path(temporary) / "jobs"
                    jobs.mkdir(mode=0o700)
                    first = make_job(jobs, suffix="a11111111111", slot="A",
                                     terminal_status="succeeded", review_result=None,
                                     review_role=True, attempt_bound=True)
                    second = make_job(jobs, suffix="b22222222222", slot="A",
                                      terminal_status="succeeded", review_result=None,
                                      review_role=True, attempt_bound=True)
                    path = second / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
                    path.unlink()
                    source = first / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
                    if link_type == "symlink":
                        path.symlink_to(source)
                    else:
                        os.link(source, path)
                    output = self.reconcile(jobs)
                self.assertEqual(output["status"], "blocked")
                self.assertTrue(any(error.startswith("decision_review_result_invalid:")
                                    for error in output["errors"]))

    def test_material_reject_in_job_owned_receipt_survives_later_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            first = make_job(jobs, suffix="a11111111111", slot="A",
                             terminal_status="failed", review_result=None,
                             review_role=True, attempt_bound=True)
            make_job(jobs, suffix="b22222222222", slot="A",
                     terminal_status="succeeded", review_result=None,
                     review_role=True, attempt_bound=True,
                     created_at_unix=1_787_000_200)
            path = first / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt.update({
                "verdict": "NEEDS_CHANGE",
                "findings": [{"severity": "P1", "evidence": "material security issue"}],
                "returncode": 1,
                "failure_classification": "review_verdict",
            })
            receipt["receipt_sha256"] = reviews._agent_role_receipt_sha256(receipt)
            write_private(path, json.dumps(receipt))
            output = self.reconcile(jobs)
        self.assertEqual(output["status"], "blocked")
        self.assertIn("decision_review_material_reject:a:grabowski-job-a11111111111", output["errors"])

    def test_v2_failed_missing_receipt_remains_blocked_after_later_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = make_job(
                jobs, suffix="a44444444444", slot="A",
                terminal_status="failed", review_result=None,
                review_role=True, attempt_bound=True,
            )
            (failed / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME).unlink()
            make_job(
                jobs, suffix="b55555555555", slot="A",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True,
                created_at_unix=1_787_000_200,
            )
            outcome = self.reconcile(jobs)
        self.assertEqual(outcome["status"], "blocked")
        self.assertIn(
            "decision_review_result_invalid:grabowski-job-a44444444444:FileNotFoundError",
            outcome["errors"],
        )
        attempts = {a["unit"]: a for a in outcome["attempts"]}
        self.assertEqual(attempts["grabowski-job-a44444444444"]["classification"], "invalid_result")
        self.assertEqual(attempts["grabowski-job-b55555555555"]["classification"], "pass")

    def test_v2_invalid_reviewer_document_survives_later_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            invalid = make_job(
                jobs, suffix="a66666666666", slot="A",
                terminal_status="failed", review_result=None,
                review_role=True, attempt_bound=True,
            )
            receipt_path = invalid / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt.update({
                "verdict": "INVALID",
                "findings": [],
                "returncode": 126,
                "failure_classification": "invalid_review_output",
            })
            receipt["receipt_sha256"] = reviews._agent_role_receipt_sha256(receipt)
            write_private(receipt_path, json.dumps(receipt))
            make_job(
                jobs, suffix="b77777777777", slot="A",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True,
                created_at_unix=1_787_000_200,
            )
            outcome = self.reconcile(jobs)
        self.assertEqual(outcome["status"], "blocked")
        self.assertIn(
            "decision_review_result_invalid:grabowski-job-a66666666666:InvalidReviewDocument",
            outcome["errors"],
        )
        attempts = {a["unit"]: a for a in outcome["attempts"]}
        self.assertEqual(attempts["grabowski-job-a66666666666"]["classification"], "invalid_result")
        self.assertEqual(attempts["grabowski-job-b77777777777"]["classification"], "pass")


    def test_v2_role_prelaunch_rejects_wrong_workspace_identity_without_job_registration(self) -> None:
        # Real committed Git bytes are not the composite role workspace identity.
        # Admission must fail BEFORE the job-owned review attempt is recorded.
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repository"
            repo.mkdir()
            def git(*arguments: str) -> str:
                return subprocess.run(
                    ["git", *arguments], cwd=repo, check=True,
                    capture_output=True, text=True,
                ).stdout.strip()
            git("init", "-q")
            git("config", "user.email", "review-test@example.invalid")
            git("config", "user.name", "Reviewer Test")
            (repo / "source.py").write_text("before\\n", encoding="utf-8")
            git("add", "source.py")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (repo / "source.py").write_text("after\\n", encoding="utf-8")
            git("add", "source.py")
            git("commit", "-qm", "head")
            head = git("rev-parse", "HEAD")
            actual_head, workspace_sha, dirty = agent_role.current_binding(repo, base)
            raw_sha = hashlib.sha256(agent_role.committed_diff(repo, base, head)).hexdigest()
            self.assertEqual(actual_head, head)
            self.assertFalse(dirty)
            self.assertNotEqual(raw_sha, workspace_sha)

            target = Path(temporary) / "jobs" / "grabowski-job-a11111111111"
            normalized = reviews.normalize_binding({
                **binding("independent-gemini"), "head_sha": head, "base_sha": base,
                "diff_sha256": "f" * 64,
            })
            argv = [
                reviews.REVIEW_ROLE_PYTHON, "-I", "-m", reviews.REVIEW_ROLE_MODULE,
                "--role", "review", "--repository", str(repo),
                "--expected-head", head, "--expected-base-head", base,
                "--expected-diff-sha256", raw_sha,
                "--expected-dirty", "false", "--output", "/tmp/preflight-placeholder.json",
                "--", "agy", "--model", "gemini-3.1-pro-high", "Review exact diff",
            ]
            with self.assertRaisesRegex(ValueError, "prelaunch.*identity"):
                reviews.bind_job_review_role_argv(
                    argv, normalized, cwd=repo, attempt_directory=target,
                )
            self.assertFalse(target.exists())
            self.assertFalse(target.parent.exists())

            valid = list(argv)
            valid[valid.index("--expected-diff-sha256") + 1] = workspace_sha
            accepted = reviews.bind_job_review_role_argv(
                valid, normalized, cwd=repo, attempt_directory=target,
            )
            self.assertEqual(
                accepted[accepted.index("--output") + 1],
                str(target / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME),
            )
            self.assertFalse(target.exists())

            # A later dirty tree or HEAD drift is independently rejected.
            (repo / "untracked.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "prelaunch.*identity"):
                reviews.bind_job_review_role_argv(
                    valid, normalized, cwd=repo, attempt_directory=target,
                )
            (repo / "untracked.txt").unlink()
            (repo / "source.py").write_text("newer\\n", encoding="utf-8")
            git("add", "source.py")
            git("commit", "-qm", "new head")
            with self.assertRaisesRegex(ValueError, "prelaunch.*identity"):
                reviews.bind_job_review_role_argv(
                    valid, normalized, cwd=repo, attempt_directory=target,
                )

    def test_v2_role_prelaunch_unknown_readback_fails_closed(self) -> None:
        normalized = reviews.normalize_binding(binding("independent-gemini"))
        argv = [
            reviews.REVIEW_ROLE_PYTHON, "-I", "-m", reviews.REVIEW_ROLE_MODULE,
            "--role", "review", "--repository", "/tmp/review",
            "--expected-head", HEAD, "--expected-base-head", BASE,
            "--expected-diff-sha256", "e" * 64,
            "--expected-dirty", "false", "--output", "/tmp/preflight-placeholder.json",
            "--", "agy", "--model", "gemini-3.1-pro-high", "Review exact diff",
        ]
        with mock.patch.object(agent_role, "current_binding", side_effect=RuntimeError("git unavailable")):
            with self.assertRaisesRegex(ValueError, "prelaunch.*unavailable"):
                reviews.bind_job_review_role_argv(
                    argv, normalized, cwd=Path("/tmp/review"),
                    attempt_directory=Path("/tmp/grabowski-job-a11111111111"),
                )

    def test_noncanonical_release_role_runner_is_rejected_before_start(self) -> None:
        command = [
            "/opt/grabowski-releases/release/.venv/bin/python", "-I",
            "-m", reviews.REVIEW_ROLE_MODULE,
            "--role", "review", "--output", "/tmp/shared-receipt.json",
        ]
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            reviews.bind_job_review_role_argv(
                command, reviews.normalize_binding(binding("A")),
                cwd=Path("/tmp/review"),
                attempt_directory=Path("/tmp/grabowski-job-a11111111111"),
            )
        generic = ["python3", "-c", "print('safe generic decision marker')"]
        self.assertEqual(
            reviews.bind_job_review_role_argv(
                generic, reviews.normalize_binding(binding("A")),
                cwd=Path("/tmp/review"),
                attempt_directory=Path("/tmp/grabowski-job-a11111111111"),
            ),
            generic,
        )

    def test_epoch_two_does_not_reconstruct_legacy_role_on_missing_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="b88888888888", slot="A",
                terminal_status="succeeded", review_result=None,
                review_role=True, origin_provenance=False,
                attempt_epoch=2,
            )
            outcome = self.reconcile(jobs)
        self.assertEqual(outcome["status"], "blocked")
        self.assertEqual(outcome["attempts"][0]["review_role_verified"], False)
        self.assertEqual(outcome["attempts"][0]["independence_verified"], False)

    def test_epoch_two_rejects_historical_v1_role_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="c99999999999", slot="A",
                terminal_status="succeeded", review_result=None,
                review_role=True, origin_provenance=True,
                attempt_bound=False, attempt_epoch=2,
            )
            outcome = self.reconcile(jobs)
        self.assertEqual(outcome["status"], "blocked")
        self.assertTrue(any(
            error.startswith("decision_review_origin_invalid:grabowski-job-c99999999999:")
            for error in outcome["errors"]
        ))

    def test_fifo_evidence_files_fail_without_blocking_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fifo = directory / "metadata.json"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(ValueError, "regular file"):
                reviews._read_private_json(fifo, 1024)
            fifo.unlink()
            fifo = directory / "stdout.log"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(ValueError, "regular file"):
                reviews._read_stdout_tail(fifo)

    def test_stdout_tail_does_not_follow_mid_read_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            trusted = directory / "stdout.log"
            trusted.write_bytes(b"trusted review marker")
            os.chmod(trusted, 0o600)
            # Keep a link to the opened inode so fstat(nlink == 1) holds
            # after the pathname is replaced with an unrelated symlink.
            held = directory / "held"
            os.link(trusted, held)
            outside = directory / "synthetic-secret"
            outside.write_bytes(b"SYNTHETIC_CROSS_FILE_READ")
            os.chmod(outside, 0o600)
            real_open = os.open
            swapped = False

            def swap_after_fd_open(name, flags, *args, **kwargs):
                nonlocal swapped
                descriptor = real_open(name, flags, *args, **kwargs)
                if name == "stdout.log" and not swapped:
                    trusted.unlink()
                    trusted.symlink_to(outside)
                    swapped = True
                return descriptor

            with mock.patch.object(reviews.os, "open", side_effect=swap_after_fd_open):
                content, digest = reviews._read_stdout_tail(trusted)
            self.assertTrue(swapped)
            self.assertEqual(content, "trusted review marker")
            self.assertEqual(digest, hashlib.sha256(b"trusted review marker").hexdigest())
            self.assertNotIn("SYNTHETIC_CROSS_FILE_READ", content)


    def test_named_provider_slot_family_identity_is_exact_not_substring(self) -> None:
        self.assertEqual(reviews._named_slot_provider_family("independent-gemini-pro"), "google")
        self.assertEqual(reviews._named_slot_provider_family("independent-grok-review"), "xai")
        self.assertEqual(reviews._named_slot_provider_family("independent-claude-review"), "anthropic")
        self.assertEqual(reviews._named_slot_provider_family("independent-codex-review"), "openai")
        self.assertIsNone(reviews._named_slot_provider_family("independent-reviewer"))
        self.assertIsNone(reviews._named_slot_provider_family("independent-geminix-review"))
        with self.assertRaisesRegex(ValueError, "conflicting reviewer providers"):
            reviews.normalize_binding(binding("independent-gemini-grok-review"))

    def test_named_provider_slot_rejects_other_canonical_independent_route(self) -> None:
        normalized = reviews.normalize_binding(binding("independent-gemini-pro"))
        role_command = [
            "claude", "--model", "claude-opus-5-5",
            "--effort", "high", "--permission-mode", "plan",
            "Review frozen code",
        ]
        argv = [
            reviews.REVIEW_ROLE_PYTHON, "-I", "-m", reviews.REVIEW_ROLE_MODULE,
            "--role", "review", "--repository", "/tmp/review",
            "--expected-head", HEAD, "--expected-base-head", BASE,
            "--expected-diff-sha256", "e" * 64,
            "--expected-dirty", "false", "--output", "/tmp/review-attempt.json",
            "--", *role_command,
        ]
        self.assertIsNone(reviews.review_role_provenance(
            argv, normalized, cwd=Path("/tmp/review"),
        ))
        with self.assertRaisesRegex(ValueError, "valid read-only reviewer"):
            reviews.bind_job_review_role_argv(
                argv, normalized, cwd=Path("/tmp/review"),
                attempt_directory=Path("/tmp/grabowski-job-a11111111111"),
            )
        self.assertIsNotNone(reviews.review_role_provenance(
            argv, reviews.normalize_binding(binding("independent-claude-review")),
            cwd=Path("/tmp/review"),
        ))

    def test_named_provider_slot_rejects_generic_pass_before_launch(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical independent reviewer"):
            reviews.bind_job_review_role_argv(
                ["python3", "-c", "print('structured review marker')"],
                reviews.normalize_binding(binding("independent-gemini-pro")),
                cwd=Path("/tmp/review"),
                attempt_directory=Path("/tmp/grabowski-job-a11111111111"),
            )
        generic = reviews.normalize_binding(binding("independent-reviewer"))
        command = ["python3", "-c", "print('generic review marker')"]
        self.assertEqual(reviews.bind_job_review_role_argv(
            command, generic, cwd=Path("/tmp/review"),
            attempt_directory=Path("/tmp/grabowski-job-a11111111111"),
        ), command)

    def test_historical_provider_mismatch_is_rejected_on_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            # Build a correctly origin-bound legacy-style witness under the
            # old no-slot-family regime. The new reader must reject it.
            with mock.patch.object(reviews, "_named_slot_provider_family", return_value=None):
                make_job(
                    jobs, suffix="a33333333333", slot="independent-gemini-pro",
                    terminal_status="succeeded", review_result=None,
                    review_role=True, attempt_bound=True,
                )
            result = self.reconcile(jobs)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any(
            x.startswith("decision_review_origin_invalid:grabowski-job-a33333333333:")
            for x in result["errors"]
        ))

    def test_generic_named_provider_pass_cannot_borrow_other_independent_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="a44444444444", slot="independent-gemini-pro",
                terminal_status="succeeded",
                review_result=result("independent-gemini-pro", "PASS_THIS_REVISION", 0),
            )
            make_job(
                jobs, suffix="b55555555555", slot="independent-reviewer",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "blocked")
        self.assertIn(
            "decision_review_named_provider_slot_without_independent_pass:independent-gemini-pro",
            reconciled["errors"],
        )
        slots = {item["slot"]: item for item in reconciled["slots"]}
        self.assertEqual(slots["independent-gemini-pro"]["pass_count"], 1)
        self.assertEqual(slots["independent-gemini-pro"]["independent_pass_count"], 0)
        self.assertEqual(slots["independent-reviewer"]["independent_pass_count"], 1)

    def test_provider_matched_named_review_slot_settles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            make_job(
                jobs, suffix="a66666666666", slot="independent-claude-review",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True,
            )
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        self.assertEqual(reconciled["slots"][0]["independent_pass_count"], 1)


if __name__ == "__main__":
    unittest.main()