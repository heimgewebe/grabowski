"""Recovery-only handoff for a settled predecessor of an unresolved cutover.

A had a completed canonical cutover but a later repairable finalization. B is
its unique signed successor, stalled after switching. A may yield to B's exact
resume, not authorize an ordinary deploy or hide an unrelated blocker.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_midcutover_resume as fixture
import test_pr1662_successor_terminal as cases
import test_provenance_recovery as recovery_fixture
import test_self_deploy as source

SD = source.SELF_DEPLOY
RECOVERY = recovery_fixture.provenance_recovery
A_UNIT = "grabowski-job-aabbaa112233"
B_UNIT = "grabowski-job-bb00bb112233"


class RecoveredSuccessorPredecessorTests(unittest.TestCase):
    def setUp(self):
        self.case = cases.CompletedSuccessorTerminalTests(
            "test_authentic_completed_resume_can_settle_predecessor_a"
        )
        self.case.setUp()
        self.a, self.b, self.resumed, self.fields = self.case._recovering_successor()
        self.binding = self.resumed["resume_binding"]
        self.assertIsNotNone(SD.midcutover._validated_resume_binding(self.binding))
        self.assertEqual(
            [self.b["cutover_id"]],
            [r["cutover_id"] for r in
             SD.midcutover.unresolved_post_switch_receipts([self.a, self.b])],
        )

    def test_authentic_incomplete_b_allows_only_its_exact_predecessor_handoff(self):
        self.assertTrue(SD._completed_predecessor_can_yield_to_recovery(
            self.a, [self.a, self.b], self.fields, self.binding
        ))
        self.case.a, self.case.fields = self.a, self.fields
        self.assertFalse(
            self.case.result(
                [self.a, self.b],
                release=fixture.GREEN_RELEASE, head=fixture.HEAD_GREEN,
            )[0],
            "normal deploy must still see A as not independently settled live",
        )

    def test_completed_grandparent_yields_only_through_authentic_successor_chain(self):
        older = cases.completed(
            "bgc-older-settled-grandparent", "9" * 40,
            "888888888888-srcset001122334455-lock556677889900-contractaabbccddeeff",
            self.a["blue_release_id"],
        )
        older_fields = {**self.fields, "expected_head": "9" * 40}
        chain = [older, self.a, self.b]
        self.assertTrue(
            SD._completed_predecessor_can_yield_to_recovery(
                older, chain, older_fields, self.binding
            ),
            "historical completed A0→A1 must not re-block B's only resume",
        )
        corrupted_middle = {**self.a, "final_routing": None}
        corrupted_middle["receipt_sha256"] = SD._sha256_json({
            key: val for key, val in corrupted_middle.items()
            if key != "receipt_sha256"
        })
        self.assertFalse(
            SD._completed_predecessor_can_yield_to_recovery(
                older, [older, corrupted_middle, self.b], older_fields,
                self.binding,
            ),
            "a missing canonical intermediate completion cannot bypass recovery",
        )

    def test_duplicate_producers_for_one_completed_release_are_ambiguous(self):
        conflicting = cases.completed(
            "bgc-competing-original-blue-producer", fixture.HEAD_BLUE,
            "777777777777-srcset001122334455-lock556677889900-contractaabbccddeeff",
            self.a["green_release_id"],
        )
        self.assertFalse(SD._completed_predecessor_can_yield_to_recovery(
            self.a, [self.a, conflicting, self.b], self.fields, self.binding
        ))

    def test_wrong_binding_tamper_foreign_or_fork_never_handoffs(self):
        foreign = fixture.cutover_receipt(
            cutover_id="bgc-foreign-not-b", outcome="outcome_unknown"
        )
        bad_sha = {**self.b, "receipt_sha256": "0" * 64}
        wrong_blue = {**self.b, "blue_release_id": fixture.GREEN_RELEASE}
        wrong_blue["receipt_sha256"] = SD._sha256_json({
            k: v for k, v in wrong_blue.items() if k != "receipt_sha256"
        })
        completed = {**self.b, "outcome": "completed", "phase": "completed"}
        completed["receipt_sha256"] = SD._sha256_json({
            k: v for k, v in completed.items() if k != "receipt_sha256"
        })
        for receipts, binding in (
            ([self.a, self.b], {**self.binding, "expected_head": "f" * 40}),
            ([self.a, bad_sha], self.binding),
            ([self.a, wrong_blue], self.binding),
            ([self.a, foreign], self.binding),
            ([self.a, self.b, foreign], self.binding),
            ([self.a, self.b, self.b], self.binding),
            ([self.a, completed], self.binding),
            ([self.b], self.binding),
        ):
            with self.subTest(receipts=len(receipts), key=binding["expected_head"]):
                self.assertFalse(SD._completed_predecessor_can_yield_to_recovery(
                    self.a, receipts, self.fields, binding
                ))

    def test_only_authenticated_private_completed_finalization_can_yield(self):
        with tempfile.TemporaryDirectory(prefix="pr1662-predecessor-") as tmp:
            root = Path(tmp)
            entry = root / A_UNIT
            entry.mkdir(mode=0o700)
            (root / B_UNIT).mkdir(mode=0o700)
            classified = {
                "kind": "deploy", "terminal": False, "fields": dict(self.fields),
                "metadata": {"unit": A_UNIT}, "status": {"final_status": "failed"},
            }
            def authenticated(entry, metadata, fields, status, *,
                              failure_type, allowed_outcomes):
                if (failure_type == "RuntimeError"
                        and allowed_outcomes == frozenset({"completed"})
                        and metadata.get("unit") == A_UNIT):
                    return self.a, [self.a, self.b]
                return None
            with (
                mock.patch.object(SD.operator, "_jobs_root", return_value=root),
                mock.patch.object(SD, "_deploy_index", return_value={
                    "units": [A_UNIT, B_UNIT], "pending_unit": None
                }),
                mock.patch.object(SD, "_classify_indexed_job", return_value=classified),
                mock.patch.object(SD, "_authenticated_persisted_incomplete_cutover",
                                  side_effect=authenticated) as validated,
            ):
                self.assertTrue(
                    SD._indexed_completed_predecessor_is_recovery_handoff(
                        A_UNIT, self.binding
                    )
                )
                self.assertTrue(validated.called)
                with mock.patch.object(
                    SD, "_authenticated_persisted_incomplete_cutover",
                    return_value=None,
                ):
                    self.assertFalse(
                        SD._indexed_completed_predecessor_is_recovery_handoff(
                            A_UNIT, self.binding
                        )
                    )
                with mock.patch.object(
                    SD, "_deploy_index", return_value={
                        "units": [A_UNIT, B_UNIT], "pending_unit": A_UNIT,
                    },
                ):
                    self.assertFalse(
                        SD._indexed_completed_predecessor_is_recovery_handoff(
                            A_UNIT, self.binding
                        )
                    )


    def test_real_private_completed_finalization_yields_only_to_matching_b(self):
        import hashlib
        import json

        repo = Path("/home/alex/repos/grabowski")
        with tempfile.TemporaryDirectory(prefix="pr1662-real-predecessor-") as tmp:
            root = Path(tmp) / "jobs"
            cutovers = Path(tmp) / "cutovers"
            root.mkdir(mode=0o700)
            cutovers.mkdir(mode=0o700)
            entry = root / A_UNIT
            entry.mkdir(mode=0o700)
            (root / B_UNIT).mkdir(mode=0o700)
            command = SD._deploy_command(
                repo, repo / SD.RUNNER_RELATIVE_PATH,
                fixture.HEAD_BLUE, 8,
                source_identity_sha256=fixture.SOURCE_IDENTITY_SHA256,
            )
            sha = SD._deploy_command_sha256(command)
            paths = {k: str(entry / name) for k, name in (
                ("metadata", "metadata.json"), ("stdout", "stdout.log"),
                ("stderr", "stderr.log"), ("finalization", "finalization.json"),
            )}
            metadata = {
                "unit": A_UNIT, "job_id": A_UNIT.removeprefix("grabowski-job-"),
                "argv": command, "argv_sha256": sha, "cwd": str(repo),
                "final_status": "launch_submitted",
                "finalization_contract": {
                    "kind": "grabowski_runtime_deploy_finalization",
                    "unit": A_UNIT, "job_id": A_UNIT.removeprefix("grabowski-job-"),
                    "argv_sha256": sha, "expected_head": fixture.HEAD_BLUE,
                    "receipt_paths": paths,
                },
            }
            for receipt in (self.a, self.b):
                receipt_path = cutovers / (receipt["cutover_id"] + ".json")
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                receipt_path.chmod(0o600)
            summary = source.RUNNER._blue_green_summary({
                "receipt": self.a, "receipt_persisted": True,
                "receipt_path": str(cutovers / (self.a["cutover_id"] + ".json")),
            })
            material = {
                "schema_version": 1,
                "kind": "grabowski_runtime_deploy_finalization",
                "unit": A_UNIT, "job_id": metadata["job_id"],
                "argv_sha256": sha, "expected_head": fixture.HEAD_BLUE,
                "receipt_paths": paths, "final_status": "failed",
                "completion_status": "failed", "repo_head": None,
                "release_id": None, "failure_type": "RuntimeError",
                "blue_green": summary,
                "blue_green_receipt_sha256": self.a["receipt_sha256"],
                "blind_retry_allowed": None, "timestamp_unix": 1000,
            }
            payload = {**material, "payload_sha256": SD._sha256_json(material)}
            raw = json.dumps(payload, sort_keys=True).encode()
            (entry / "finalization.json").write_bytes(raw)
            (entry / "finalization.json").chmod(0o600)
            status = {
                "final_status": "failed",
                "finalization_receipt": {
                    "valid": True, "state": "valid", "final_status": "failed",
                    "expected_head": fixture.HEAD_BLUE,
                    "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                    "payload_sha256": payload["payload_sha256"],
                    "blue_green_receipt_sha256": self.a["receipt_sha256"],
                    "blind_retry_allowed": None,
                },
            }
            load = SD.midcutover.load_receipts
            with (
                mock.patch.object(SD.operator, "_jobs_root", return_value=root),
                mock.patch.object(SD.operator, "_read_job_metadata",
                                  return_value=metadata),
                mock.patch.object(SD.operator, "grabowski_job_status",
                                  return_value=status),
                mock.patch.object(SD.operator, "_read_finalization_receipt_file",
                                  return_value={"ok": True, "raw": raw, "bytes": len(raw)},
                                  create=True) as private_reader,
                mock.patch.object(SD.midcutover, "load_receipts",
                                  side_effect=lambda: load(cutovers)),
                mock.patch.object(SD.base, "_deployment_metadata",
                                  return_value={"completion_status": "incomplete"},
                                  create=True),
                mock.patch.object(SD, "_deploy_index", return_value={
                    "units": [A_UNIT, B_UNIT], "pending_unit": None,
                }),
            ):
                self.assertFalse(
                    SD._classify_indexed_job(entry)["terminal"],
                    "ordinary deployment must see old A until B is settled",
                )
                self.assertTrue(
                    SD._indexed_completed_predecessor_is_recovery_handoff(
                        A_UNIT, self.binding
                    ),
                    "the verified owner-private finalized A must yield to B recovery",
                )
                private_reader.return_value = {
                    "ok": True, "raw": raw + b"corrupted", "bytes": len(raw) + 9,
                }
                self.assertFalse(
                    SD._indexed_completed_predecessor_is_recovery_handoff(
                        A_UNIT, self.binding
                    ),
                    "a broken private finalization digest must deny handoff",
                )


class RecoveryGateAllOrNothingTests(unittest.TestCase):
    def setUp(self):
        self.binding = {"schema_version": 2, "cutover_id": "bgc-exact",
                        "binding_sha256": "a" * 64}

    def _check(self, units, *, predecessor=True, b=True,
               ancestor_units=(A_UNIT,)):
        projection = {
            "blocking_units": list(units), "inflight_units": list(units),
            "idempotent_match": None, "ambiguous_identical_units": [],
            "pruned_units": [], "error": None,
        }
        with (
            mock.patch.object(RECOVERY.self_deploy,
                              "inflight_runtime_job_evidence",
                              return_value=projection, create=True),
            mock.patch.object(RECOVERY.self_deploy,
                              "_indexed_completed_predecessor_is_recovery_handoff",
                              side_effect=lambda unit, _: unit in ancestor_units and predecessor,
                              create=True),
            mock.patch.object(RECOVERY.self_deploy,
                              "_indexed_failed_deploy_is_cutover_handoff",
                              side_effect=lambda unit, _: unit == B_UNIT and b,
                              create=True),
            mock.patch.object(RECOVERY.self_deploy,
                              "_indexed_failed_resume_is_noeffect_handoff",
                              return_value=False, create=True),
            mock.patch.object(RECOVERY.self_deploy,
                              "_indexed_failed_scheduled_resume_is_handoff",
                              return_value=False, create=True),
        ):
            ordinary = RECOVERY._competing_deployment_evidence()
            resumed = RECOVERY._competing_deployment_evidence(
                resume_binding=self.binding
            )
        return ordinary, resumed

    def test_settled_a_and_exact_b_can_handoff_together_but_not_deploy(self):
        ordinary, resumed = self._check([A_UNIT, B_UNIT])
        self.assertEqual(ordinary["inflight_deploy_jobs"], [A_UNIT, B_UNIT])
        self.assertEqual(resumed["inflight_deploy_jobs"], [])
        self.assertEqual(resumed["recovery_handoff_units"], [A_UNIT, B_UNIT])

    def test_multiple_signed_ancestors_and_exact_b_handoff_atomically(self):
        older_unit = "grabowski-job-cc00cc112233"
        units = [A_UNIT, older_unit, B_UNIT]
        ordinary, resumed = self._check(
            units, ancestor_units=(A_UNIT, older_unit)
        )
        self.assertEqual(ordinary["inflight_deploy_jobs"], units)
        self.assertEqual(resumed["inflight_deploy_jobs"], [])
        self.assertEqual(resumed["recovery_handoff_units"], units)

    def test_no_b_or_foreign_or_unproved_a_blocks_full_recovery(self):
        for units, predecessor, b in (
            ([A_UNIT], True, True),
            ([A_UNIT, B_UNIT], False, True),
            ([A_UNIT, B_UNIT], True, False),
            ([A_UNIT, B_UNIT, "grabowski-job-cc00cc112233"], True, True),
        ):
            with self.subTest(units=units, predecessor=predecessor, b=b):
                ordinary, resumed = self._check(
                    units, predecessor=predecessor, b=b
                )
                self.assertEqual(ordinary["inflight_deploy_jobs"], units)
                self.assertEqual(resumed["inflight_deploy_jobs"], units)
                self.assertEqual(resumed["recovery_handoff_units"], [])


if __name__ == "__main__":
    unittest.main()