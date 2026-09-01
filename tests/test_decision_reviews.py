from pathlib import Path
import json
import os
import tempfile
import unittest

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import grabowski_decision_reviews as reviews
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
) -> Path:
    unit = f"grabowski-job-{suffix}"
    directory = jobs / unit
    directory.mkdir(parents=True)
    os.chmod(directory, 0o700)
    argv_sha = (suffix[0] if suffix[0] in "abcdef" else "d") * 64
    scope = {
        "cwd": "/tmp/review",
        "argv_sha256": argv_sha,
        "runtime_seconds": 60,
        "decision_bound_review": reviews.normalize_binding(
            binding(slot, diff_sha256=diff_sha256)
        ),
    }
    origin, origin_sha = job_origin.build_origin(
        unit=unit,
        owner="uid:1000",
        argv_sha256=argv_sha,
        scope=scope,
        notify_on_done={"requested": False, "channels": []},
        created_at_unix=1_787_000_000,
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
        "argv_sha256": argv_sha,
        "created_at_unix": 1_787_000_000,
        "finalization_contract": contract,
    }
    write_private(directory / "metadata.json", json.dumps(metadata))
    marker = ""
    if review_result is not None:
        marker = reviews.RESULT_PREFIX + json.dumps(review_result, separators=(",", ":")) + "\n"
    write_private(directory / "stdout.log", marker)
    write_private(directory / "stderr.log", "")
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
        self.assertEqual(reconciled["errors"], [])

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
            make_job(jobs, suffix="a00000000007", slot="A", terminal_status="failed", review_result=None)
            make_job(jobs, suffix="a00000000008", slot="A", terminal_status="succeeded", review_result=result("A", "PASS_THIS_REVISION", 0))
            make_job(jobs, suffix="b00000000009", slot="B", terminal_status="succeeded", review_result=result("B", "PASS_THIS_REVISION", 0))
            reconciled = self.reconcile(jobs)
        self.assertEqual(reconciled["status"], "settled")
        a_slot = next(item for item in reconciled["slots"] if item["slot"] == "a")
        self.assertEqual(a_slot["infrastructure_error_count"], 1)
        self.assertEqual(a_slot["pass_count"], 1)

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
        self.assertTrue(any(error.startswith("decision_review_success_missing_result:") for error in reconciled["errors"]))

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
