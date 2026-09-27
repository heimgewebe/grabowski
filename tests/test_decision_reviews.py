from pathlib import Path
import json
import os
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


def make_job(
    jobs: Path,
    *,
    suffix: str,
    slot: str,
    terminal_status: str | None,
    review_result: dict | None,
    diff_sha256: str = DIFF,
    review_role: bool = False,
    origin_provenance: bool = True,
    metadata_argv_override: list[str] | None = None,
    created_at_unix: int = 1_787_000_000,
    started_at_unix_ns: int | None = None,
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
        "opus",
        "--effort",
        "high",
        "--permission-mode",
        "plan",
        "Review the frozen revision",
    ]
    role_receipt_path = directory / "review-role-receipt.json"
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
    if review_role and origin_provenance:
        provenance = reviews.review_role_provenance(
            job_argv, normalized_binding, cwd=Path("/tmp/review")
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


class DecisionReviewReconciliationTests(unittest.TestCase):
    def test_review_role_provenance_uses_agent_role_command_hash_for_unicode_prompt(self) -> None:
        role_command = [
            "claude",
            "--model",
            "opus",
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
        self.assertEqual(attempt["review_route_id"], "claude-opus-5-high")
        self.assertEqual(attempt["review_provider_family"], "anthropic")

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
            "opus",
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
            "opus",
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


if __name__ == "__main__":
    unittest.main()
