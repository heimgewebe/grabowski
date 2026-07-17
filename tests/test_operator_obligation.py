from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_operator_obligation as obligation


class OperatorObligationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "operator-obligations"
        self.environment = patch.dict(
            os.environ,
            {"GRABOWSKI_OPERATOR_OBLIGATION_ROOT": str(self.root)},
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @staticmethod
    def _open_parameters(obligation_id: str = "goo-example-work-0001") -> dict[str, object]:
        return {
            "obligation_id": obligation_id,
            "objective": "Complete the requested operator work with evidence.",
            "acceptance": [
                {"id": "implementation", "description": "Implementation exists."},
                {"id": "verification", "description": "Verification passed."},
            ],
            "origin": {
                "thread_id": "thread-17",
                "source": "chatgpt-via-grabowski",
                "repo": "/home/alex/repos/grabowski",
            },
            "references": [],
        }

    @staticmethod
    def _delegation(status: str) -> dict[str, str]:
        material = {
            "kind": "systemd_job",
            "id": "grabowski-job-17",
            "observation_tool": "grabowski_job_status",
            "status": status,
            "observed_at": "2026-07-15T14:00:00Z",
            "identity_sha256": "c" * 64,
        }
        return {
            **material,
            "observation_receipt_sha256": obligation._sha256(material),
        }

    @staticmethod
    def _passed_evidence() -> list[dict[str, str]]:
        return [
            {
                "acceptance_id": "implementation",
                "status": "passed",
                "source": "git",
                "reference": "commit:0123456789abcdef",
                "sha256": "1" * 64,
            },
            {
                "acceptance_id": "verification",
                "status": "passed",
                "source": "test",
                "reference": "python -m unittest tests.test_operator_obligation",
                "sha256": "2" * 64,
            },
        ]

    def test_open_is_private_idempotent_and_requires_continuation(self) -> None:
        first = obligation.open_obligation(self._open_parameters())
        second = obligation.open_obligation(self._open_parameters())
        status_value = obligation.status_obligation("goo-example-work-0001")

        self.assertTrue(first["created"])
        self.assertFalse(first["response_may_end"])
        self.assertTrue(first["continuation_required"])
        self.assertTrue(first["follow_up_required"])
        self.assertFalse(first["work_complete"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["open_file_sha256"], second["open_file_sha256"])
        self.assertEqual(status_value["state"], "open")
        self.assertEqual(
            status_value["missing_acceptance_ids"],
            ["implementation", "verification"],
        )
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        directory = self.root / "goo-example-work-0001"
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((directory / "open.json").stat().st_mode), 0o600)

    def test_list_finds_open_work_by_origin_without_claiming_completion(self) -> None:
        obligation.open_obligation(self._open_parameters())
        other = self._open_parameters("goo-other-thread-0002")
        other["origin"] = {"thread_id": "thread-99", "repo": "/other"}
        obligation.open_obligation(other)

        result = obligation.list_obligations(
            {
                "state": "open",
                "repo": "/home/alex/repos/grabowski",
                "thread_id": "thread-17",
                "limit": 10,
            }
        )

        self.assertEqual(1, result["record_count"])
        self.assertEqual("goo-example-work-0001", result["records"][0]["obligation_id"])
        self.assertTrue(result["records"][0]["continuation_required"])
        self.assertFalse(result["records"][0]["response_may_end"])
        self.assertTrue(result["attention_required"])

    def test_default_list_keeps_all_unfinished_work_visible(self) -> None:
        blocked = self._open_parameters("goo-blocked-work-0002")
        delegated = self._open_parameters("goo-delegated-work-0003")
        completed = self._open_parameters("goo-completed-work-0004")
        open_work = self._open_parameters("goo-open-work-0005")
        for parameters in (blocked, delegated, completed, open_work):
            obligation.open_obligation(parameters)
        obligation.close_obligation(
            {
                "obligation_id": "goo-blocked-work-0002",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "foreign-lease",
                        "detail": "Exact overlap remains active.",
                        "reference": "lease:owner-17",
                        "sha256": "3" * 64,
                    }
                ],
                "next_action": "Recheck the lease and open a successor obligation.",
            }
        )
        obligation.close_obligation(
            {
                "obligation_id": "goo-delegated-work-0003",
                "outcome": "delegated",
                "evidence": [],
                "delegation": self._delegation("running"),
                "next_action": "Observe the durable job and open a successor obligation.",
            }
        )
        obligation.close_obligation(
            {
                "obligation_id": "goo-completed-work-0004",
                "outcome": "completed",
                "evidence": self._passed_evidence(),
            }
        )

        result = obligation.list_obligations()
        explicit_attention = obligation.list_obligations({"state": "attention"})
        open_only = obligation.list_obligations({"state": "open"})
        states = {item["obligation_id"]: item["state"] for item in result["records"]}

        self.assertEqual("attention", result["state_filter"])
        self.assertEqual(result["records"], explicit_attention["records"])
        self.assertEqual(
            {
                "goo-blocked-work-0002": "blocked",
                "goo-delegated-work-0003": "delegated",
                "goo-open-work-0005": "open",
            },
            states,
        )
        self.assertEqual(
            ["goo-open-work-0005"],
            [item["obligation_id"] for item in open_only["records"]],
        )
        self.assertTrue(result["attention_required"])
        self.assertTrue(all(item["continuation_required"] for item in result["records"]))

        summary = obligation.list_obligations(
            {"state": "attention", "summary_only": True}
        )
        self.assertEqual(3, summary["record_count"])
        self.assertEqual([], summary["records"])
        self.assertTrue(summary["attention_required"])

    def test_list_reports_projection_drift_as_attention_integrity_error(self) -> None:
        obligation.open_obligation(self._open_parameters())
        original_status = obligation.status_obligation

        def incomplete_status(obligation_id: str) -> dict[str, object]:
            status = original_status(obligation_id)
            status.pop("work_complete")
            return status

        with patch.object(obligation, "status_obligation", side_effect=incomplete_status):
            result = obligation.list_obligations()

        self.assertEqual([], result["records"])
        self.assertEqual(
            [
                {
                    "obligation_id": "goo-example-work-0001",
                    "error": "OperatorObligationIntegrityError",
                }
            ],
            result["integrity_errors"],
        )
        self.assertTrue(result["attention_required"])
        self.assertEqual(
            "inspect integrity errors before relying on the affected obligations",
            result["recommended_next_action"],
        )

    def test_same_id_cannot_be_rebound_to_different_work(self) -> None:
        obligation.open_obligation(self._open_parameters())
        changed = self._open_parameters()
        changed["objective"] = "Different work"
        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.open_obligation(changed)

    def test_completed_close_requires_passed_evidence_for_every_acceptance(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "evidence": self._passed_evidence()[:1],
                }
            )
        self.assertEqual(
            obligation.status_obligation("goo-example-work-0001")["state"],
            "open",
        )

    def test_completed_close_rejects_unhashed_evidence(self) -> None:
        obligation.open_obligation(self._open_parameters())
        evidence = self._passed_evidence()
        evidence[0].pop("sha256")
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "evidence": evidence,
                }
            )
        self.assertEqual(
            obligation.status_obligation("goo-example-work-0001")["state"],
            "open",
        )

    def test_completed_close_is_create_only_and_reports_real_completion(self) -> None:
        obligation.open_obligation(self._open_parameters())
        parameters = {
            "obligation_id": "goo-example-work-0001",
            "outcome": "completed",
            "evidence": self._passed_evidence(),
        }
        first = obligation.close_obligation(parameters)
        second = obligation.close_obligation(parameters)

        self.assertTrue(first["created"])
        self.assertFalse(first["continuation_required"])
        self.assertTrue(first["response_may_end"])
        self.assertTrue(first["work_complete"])
        self.assertEqual(first["state"], "completed")
        self.assertTrue(second["replayed"])
        self.assertEqual(first["close_file_sha256"], second["close_file_sha256"])
        close_path = self.root / "goo-example-work-0001" / "close.json"
        self.assertEqual(stat.S_IMODE(close_path.stat().st_mode), 0o600)

    def test_reopening_same_obligation_preserves_terminal_state(self) -> None:
        parameters = self._open_parameters()
        obligation.open_obligation(parameters)
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                "evidence": self._passed_evidence(),
            }
        )

        replay = obligation.open_obligation(parameters)

        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["state"], "completed")
        self.assertTrue(replay["response_may_end"])
        self.assertTrue(replay["work_complete"])

    def test_blocked_close_requires_hashed_blocker_evidence(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "blocked",
                    "evidence": [],
                    "blockers": [
                        {
                            "code": "foreign-lease",
                            "detail": "An exact overlapping lease is active.",
                            "reference": "lease:owner-17",
                        }
                    ],
                    "next_action": "Wait for the exact lease to be released, then reorient.",
                }
            )

    def test_blocked_close_ends_chat_without_claiming_work_complete(self) -> None:
        obligation.open_obligation(self._open_parameters())
        result = obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [
                    {
                        "acceptance_id": "implementation",
                        "status": "partial",
                        "source": "git",
                        "reference": "worktree:dirty",
                    }
                ],
                "blockers": [
                    {
                        "code": "foreign-lease",
                        "detail": "An exact overlapping lease is active.",
                        "reference": "lease:owner-17",
                        "sha256": "3" * 64,
                    }
                ],
                "next_action": "Wait for the exact lease to be released, then reorient.",
            }
        )

        self.assertEqual(result["state"], "blocked")
        self.assertTrue(result["response_may_end"])
        self.assertTrue(result["continuation_required"])
        self.assertTrue(result["follow_up_required"])
        self.assertFalse(result["work_complete"])
        self.assertIn("does not establish", result["non_claims"][0])

    def test_delegated_close_requires_a_live_durable_reference(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "delegated",
                    "evidence": [],
                    "delegation": self._delegation("failed"),
                    "next_action": "Observe the job.",
                }
            )

        result = obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "delegated",
                "evidence": [],
                "delegation": self._delegation("running"),
                "next_action": "Observe the durable job and verify its final receipt.",
            }
        )
        self.assertEqual(result["state"], "delegated")
        self.assertTrue(result["continuation_required"])
        self.assertTrue(result["follow_up_required"])
        self.assertFalse(result["work_complete"])
        self.assertEqual(result["delegation"]["status"], "running")

    def test_delegation_receipt_hash_cannot_be_forged(self) -> None:
        obligation.open_obligation(self._open_parameters())
        forged = self._delegation("running")
        forged["identity_sha256"] = "d" * 64
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "delegated",
                    "evidence": [],
                    "delegation": forged,
                    "next_action": "Observe the durable job.",
                }
            )

    def test_conflicting_terminal_close_is_rejected(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                "evidence": self._passed_evidence(),
            }
        )
        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "blocked",
                    "evidence": [],
                    "blockers": [
                        {
                            "code": "late-blocker",
                            "detail": "A conflicting terminal claim appeared.",
                            "reference": "test",
                            "sha256": "4" * 64,
                        }
                    ],
                    "next_action": "Review manually.",
                }
            )

    def test_hardlinked_lock_fails_closed(self) -> None:
        obligation.open_obligation(self._open_parameters())
        os.link(self.root / ".lock", self.root / ".lock-copy")
        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.open_obligation(self._open_parameters("goo-second-work-0002"))

    def test_list_scan_is_bounded(self) -> None:
        obligation.open_obligation(self._open_parameters())
        for name in ("goo-extra-work-0002", "goo-extra-work-0003"):
            (self.root / name).mkdir(mode=0o700)
        with patch.object(obligation, "MAX_LIST_SCAN", 2):
            result = obligation.list_obligations({"state": "all", "limit": 10})
        self.assertTrue(result["scan_truncated"])
        self.assertTrue(result["attention_required"])

    def test_list_rejects_non_string_state(self) -> None:
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.list_obligations({"state": ["open"]})

    def test_tampered_unhashed_close_timestamp_fails_closed(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                "evidence": self._passed_evidence(),
            }
        )
        target = self.root / "goo-example-work-0001" / "close.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["closed_at"] = "2026-07-15T00:00:00Z"
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-example-work-0001")

    def test_tampered_timestamp_fails_closed_via_record_hash(self) -> None:
        obligation.open_obligation(self._open_parameters())
        target = self.root / "goo-example-work-0001" / "open.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["created_at"] = "2026-07-15T00:00:00Z"
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-example-work-0001")

    def test_tampered_open_record_fails_closed(self) -> None:
        obligation.open_obligation(self._open_parameters())
        target = self.root / "goo-example-work-0001" / "open.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["objective"] = "Tampered"
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-example-work-0001")


if __name__ == "__main__":
    unittest.main()
