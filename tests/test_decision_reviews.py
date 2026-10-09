from pathlib import Path
import hashlib
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
    origin_provenance: bool = True,
    attempt_epoch: int | None = None,
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
        "claude-opus-5-5",
        "--effort",
        "high",
        "--permission-mode",
        "plan",
        "Review the frozen revision",
    ]
    role_receipt_path = directory / (
        reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME if attempt_bound
        else "review-role-receipt.json"
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


class DecisionReviewReconciliationTests(unittest.TestCase):
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
            jobs.mkdir()
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
            jobs.mkdir()
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


if __name__ == "__main__":
    unittest.main()
