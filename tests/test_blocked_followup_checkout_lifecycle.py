from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_checkout_terminal_reconciliation as reconciliation
import grabowski_checkout_terminal_sources as sources


LANE_ID = "2d325c001eca1492359c0eed72996cf8"
LANE_RECEIPT = "e75fc6419777bc995c2512827172e07150c0a9594168981a513730267111c9ef"
ASSESSMENT = "62671be60650fabf354769ec27d791a719d6e245fd7d7529fce305e730b18746"
AUDIT = "4d8d7a096706300f746976a0806a8ec665286be9b661f82a9eeea0a72fe4fdb3"
TERMINAL_HEAD = "eb98dacb4fb7cf8cc79d401bf8fcd52063a07fe0"
CHECKOUT_KEY = "b538ea19f8d43829602e39d10ca86deb001d0b2f987c16700a3da193caac8b04"
TASK_ID = "GRABOWSKI-OPERATOR-SURFACE-V1-FU-BLOCKED-FOLLOWUP-CHECKOUT-LIFECYCLE-20260924"
FINAL_PR_HEAD = "466e127218c4130f9db458d1b93fe32db70370b3"
MERGE_COMMIT = "85ebdd71846f8d6a2de1076745de20725ebcb48a"


class BlockedFollowupCheckoutLifecycleTests(unittest.TestCase):
    @staticmethod
    def _record() -> dict[str, object]:
        return {
            "lane_id": LANE_ID,
            "receipt_sha256": LANE_RECEIPT,
            "worktree_receipt": {
                "lifecycle": {
                    "checkout_key": CHECKOUT_KEY,
                }
            },
        }

    @staticmethod
    def _assessment() -> dict[str, object]:
        return {
            "closeout_state": "blocked_with_durable_followup",
            "assessment_sha256": ASSESSMENT,
            "terminal_head_sha": TERMINAL_HEAD,
            "reason_codes": ["durable_followup_bound"],
            "lease_release_ready": False,
        }

    @staticmethod
    def _reproduction() -> dict[str, object]:
        return {
            "checkout_key": CHECKOUT_KEY,
            "final_pr_head": FINAL_PR_HEAD,
            "lane_assessment_sha256": ASSESSMENT,
            "lane_id": LANE_ID,
            "lane_receipt_sha256": LANE_RECEIPT,
            "lane_terminal_audit_sha256": AUDIT,
            "lane_terminal_head": TERMINAL_HEAD,
            "merge_commit": MERGE_COMMIT,
            "pull_request": 1896,
            "repository": "heimgewebe/commonthing",
            "sole_preview_blocker": "work-lane-lease-release-not-ready",
            "terminal_preview_sha256": (
                "0fc7bdaf38545bfaa1354a2d9147e83aea3bea938c7561fba0613bc262764a64"
            ),
        }

    def _spec(self, task_id: str = TASK_ID) -> dict[str, object]:
        return {
            "id": task_id,
            "state": "ready",
            "metadata": {
                "reproduction": self._reproduction(),
            },
        }

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE task_spec_revisions(
                task_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                parent_revision INTEGER,
                spec_sha256 TEXT NOT NULL,
                spec_json TEXT NOT NULL,
                PRIMARY KEY(task_id, revision)
            );
            CREATE TABLE task_specs(
                task_id TEXT PRIMARY KEY,
                current_revision INTEGER NOT NULL,
                spec_sha256 TEXT NOT NULL
            );
            """
        )

    def _insert_current(
        self,
        connection: sqlite3.Connection,
        spec: dict[str, object],
        *,
        revision: int = 3,
        pointer_sha256: str | None = None,
    ) -> str:
        digest = sources._bureau_task_spec_digest(spec)
        connection.execute(
            "INSERT INTO task_spec_revisions"
            "(task_id,revision,parent_revision,spec_sha256,spec_json)"
            " VALUES(?,?,?,?,?)",
            (
                spec["id"],
                revision,
                None if revision == 1 else revision - 1,
                digest,
                json.dumps(
                    spec,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        connection.execute(
            "INSERT INTO task_specs(task_id,current_revision,spec_sha256)"
            " VALUES(?,?,?)",
            (spec["id"], revision, pointer_sha256 or digest),
        )
        return digest

    def _state_store(self, specs: list[dict[str, object]]) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        database = root / "bureau.sqlite3"
        connection = sqlite3.connect(database)
        try:
            self._create_schema(connection)
            for spec in specs:
                self._insert_current(connection, spec)
            connection.commit()
        finally:
            connection.close()
        database.chmod(0o600)
        return temporary, root

    def test_pr1896_legacy_receipt_binds_exact_current_followup_taskspec(self) -> None:
        temporary, root = self._state_store([self._spec()])
        self.addCleanup(temporary.cleanup)
        with patch.dict(
            os.environ,
            {
                "BUREAU_STATE_DIR": str(root),
                "GRABOWSKI_BUREAU_COORDINATION_ROOT": str(root),
            },
        ):
            result = sources._legacy_blocked_followup_binding(
                LANE_ID,
                record=self._record(),
                assessment=self._assessment(),
                audit_record_sha256=AUDIT,
            )

        self.assertEqual(TASK_ID, result["durable_followup_id"])
        self.assertEqual(CHECKOUT_KEY, result["checkout_key"])
        binding = result["durable_followup_binding"]
        self.assertEqual("bureau_current_task_spec_reproduction", binding["kind"])
        self.assertEqual(TASK_ID, binding["task_id"])
        self.assertEqual(3, binding["task_revision"])
        self.assertEqual("ready", binding["task_state"])
        self.assertEqual(
            {
                "lane_id": LANE_ID,
                "lane_receipt_sha256": LANE_RECEIPT,
                "lane_assessment_sha256": ASSESSMENT,
                "lane_terminal_audit_sha256": AUDIT,
                "lane_terminal_head": TERMINAL_HEAD,
                "checkout_key": CHECKOUT_KEY,
            },
            binding["reproduction"],
        )
        material = {
            key: value for key, value in binding.items() if key != "binding_sha256"
        }
        self.assertEqual(
            sources.checkouts._sha256_json(material),
            binding["binding_sha256"],
        )
        self.assertIn("followup_completion", binding["does_not_establish"])

    def test_legacy_binding_rejects_reproduction_drift(self) -> None:
        spec = self._spec()
        spec["metadata"]["reproduction"]["lane_assessment_sha256"] = "9" * 64
        temporary, root = self._state_store([spec])
        self.addCleanup(temporary.cleanup)
        with (
            patch.dict(
                os.environ,
                {
                    "BUREAU_STATE_DIR": str(root),
                    "GRABOWSKI_BUREAU_COORDINATION_ROOT": str(root),
                },
            ),
            self.assertRaisesRegex(RuntimeError, "binding is missing"),
        ):
            sources._legacy_blocked_followup_binding(
                LANE_ID,
                record=self._record(),
                assessment=self._assessment(),
                audit_record_sha256=AUDIT,
            )

    def test_legacy_binding_rejects_ambiguous_current_followup(self) -> None:
        temporary, root = self._state_store(
            [self._spec(), self._spec("GRABOWSKI-OTHER-FOLLOWUP-T001")]
        )
        self.addCleanup(temporary.cleanup)
        with (
            patch.dict(
                os.environ,
                {
                    "BUREAU_STATE_DIR": str(root),
                    "GRABOWSKI_BUREAU_COORDINATION_ROOT": str(root),
                },
            ),
            self.assertRaisesRegex(RuntimeError, "binding is ambiguous"),
        ):
            sources._legacy_blocked_followup_binding(
                LANE_ID,
                record=self._record(),
                assessment=self._assessment(),
                audit_record_sha256=AUDIT,
            )

    def test_taskspec_pointer_digest_drift_fails_closed(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        database = root / "bureau.sqlite3"
        connection = sqlite3.connect(database)
        try:
            self._create_schema(connection)
            self._insert_current(
                connection,
                self._spec(),
                pointer_sha256="f" * 64,
            )
            connection.commit()
        finally:
            connection.close()
        database.chmod(0o600)
        with (
            patch.dict(
                os.environ,
                {
                    "BUREAU_STATE_DIR": str(root),
                    "GRABOWSKI_BUREAU_COORDINATION_ROOT": str(root),
                },
            ),
            self.assertRaisesRegex(RuntimeError, "current pointer is invalid"),
        ):
            sources._current_bureau_task_specs()

    def test_taskspec_state_store_symlink_fails_closed(self) -> None:
        temporary, real_root = self._state_store([self._spec()])
        self.addCleanup(temporary.cleanup)
        alias_root = real_root / "alias"
        alias_root.mkdir()
        (alias_root / "bureau.sqlite3").symlink_to(real_root / "bureau.sqlite3")
        with (
            patch.dict(
                os.environ,
                {
                    "BUREAU_STATE_DIR": str(alias_root),
                    "GRABOWSKI_BUREAU_COORDINATION_ROOT": str(alias_root),
                },
            ),
            self.assertRaisesRegex(RuntimeError, "unsafe"),
        ):
            sources._current_bureau_task_specs()


    def test_taskspec_state_store_prefers_configured_coordination_root(self) -> None:
        default_temporary, default_root = self._state_store(
            [self._spec("GRABOWSKI-DEFAULT-ROOT-T001")]
        )
        coordination_temporary, coordination_root = self._state_store([self._spec()])
        self.addCleanup(default_temporary.cleanup)
        self.addCleanup(coordination_temporary.cleanup)
        with patch.dict(
            os.environ,
            {
                "BUREAU_STATE_DIR": str(default_root),
                "GRABOWSKI_BUREAU_COORDINATION_ROOT": str(coordination_root),
            },
        ):
            observed = sources._current_bureau_task_specs()
            self.assertEqual(
                coordination_root / "bureau.sqlite3",
                sources._bureau_state_store_path(),
            )
        self.assertEqual([TASK_ID], [item["task_id"] for item in observed])

    @staticmethod
    def _blocked_source_evidence(*, binding_sha256: str | None = None) -> dict[str, object]:
        binding_core = {
            "kind": "terminal_assessment",
            "durable_followup_id": TASK_ID,
            "assessment_sha256": ASSESSMENT,
            "terminal_closeout_audit_record_sha256": AUDIT,
            "does_not_establish": [
                "followup_completion",
                "lease_release_authority",
                "archive_or_cleanup_authority",
                "branch_or_ref_deletion_authority",
            ],
        }
        binding = {
            **binding_core,
            "binding_sha256": (
                binding_sha256
                or sources.checkouts._sha256_json(binding_core)
            ),
        }
        core = {
            "schema_version": 1,
            "kind": "work_lane",
            "source_id": LANE_ID,
            "terminal_state": "blocked_with_durable_followup",
            "checkout_key": CHECKOUT_KEY,
            "lane_receipt_sha256": LANE_RECEIPT,
            "assessment_sha256": ASSESSMENT,
            "terminal_head_sha": TERMINAL_HEAD,
            "lease_release_ready": False,
            "terminal_closeout_audit_record_sha256": AUDIT,
            "durable_followup_id": TASK_ID,
            "durable_followup_binding": binding,
        }
        return {
            **core,
            "evidence_sha256": sources.checkouts._sha256_json(core),
        }

    def test_blocked_followup_capacity_release_requires_terminal_head(self) -> None:
        for terminal_head in (None, "not-a-git-object"):
            with self.subTest(terminal_head=terminal_head):
                evidence = self._blocked_source_evidence()
                evidence["terminal_head_sha"] = terminal_head
                evidence["evidence_sha256"] = sources.checkouts._sha256_json(
                    {
                        key: value
                        for key, value in evidence.items()
                        if key != "evidence_sha256"
                    }
                )
                self.assertFalse(
                    reconciliation._blocked_followup_capacity_release_ready(
                        evidence,
                        CHECKOUT_KEY,
                    )
                )

    def test_present_blocked_followup_preview_releases_only_active_capacity(self) -> None:
        binding = {
            "checkout_key": CHECKOUT_KEY,
            "phase": "active",
            "repo_path": "/tmp/repo",
            "checkout_path": "/tmp/worktree",
            "expected_branch": "topic",
            "expected_head": TERMINAL_HEAD,
            "owner_id": "owner-a",
            "source": {"kind": "work_lane", "id": LANE_ID},
        }
        snapshot = {
            "binding": binding,
            "binding_sha256": "1" * 64,
            "retention": {
                "expected_head": TERMINAL_HEAD,
                "owner_id": "owner-a",
            },
            "retention_sha256": "2" * 64,
            "identity_catchup": None,
            "archive_count": 0,
        }
        checkout = {
            "mode": "present",
            "branch_head": TERMINAL_HEAD,
            "blockers": [],
            "status": {"dirty": False},
        }
        coordination = {
            "blocking": False,
            "resource_leases": [],
            "tasks": [],
            "processes": [],
        }
        evidence = self._blocked_source_evidence()
        with (
            patch.object(reconciliation, "_record", return_value=None),
            patch.object(reconciliation, "_snapshot", return_value=snapshot),
            patch.object(
                sources,
                "source_terminal_evidence",
                return_value=evidence,
            ),
            patch.object(
                reconciliation,
                "_terminal_checkout_observation",
                return_value=checkout,
            ),
            patch.object(
                reconciliation,
                "_coordination",
                return_value=coordination,
            ),
        ):
            preview = reconciliation._preview_state(CHECKOUT_KEY)

        self.assertEqual("ready", preview["status"])
        self.assertTrue(preview["safe_to_apply"])
        self.assertEqual([], preview["blockers"])
        self.assertFalse(preview["source_evidence"]["lease_release_ready"])
        self.assertEqual(TASK_ID, preview["source_evidence"]["durable_followup_id"])
        self.assertIn(
            "archive_or_cleanup_authority",
            preview["source_evidence"]["durable_followup_binding"]["does_not_establish"],
        )

    def test_present_blocked_followup_preview_rejects_tampered_binding(self) -> None:
        binding = {
            "checkout_key": CHECKOUT_KEY,
            "phase": "active",
            "repo_path": "/tmp/repo",
            "checkout_path": "/tmp/worktree",
            "expected_branch": "topic",
            "expected_head": TERMINAL_HEAD,
            "owner_id": "owner-a",
            "source": {"kind": "work_lane", "id": LANE_ID},
        }
        snapshot = {
            "binding": binding,
            "binding_sha256": "1" * 64,
            "retention": {
                "expected_head": TERMINAL_HEAD,
                "owner_id": "owner-a",
            },
            "retention_sha256": "2" * 64,
            "identity_catchup": None,
            "archive_count": 0,
        }
        checkout = {
            "mode": "present",
            "branch_head": TERMINAL_HEAD,
            "blockers": [],
            "status": {"dirty": False},
        }
        coordination = {
            "blocking": False,
            "resource_leases": [],
            "tasks": [],
            "processes": [],
        }
        evidence = self._blocked_source_evidence(binding_sha256="f" * 64)
        with (
            patch.object(reconciliation, "_record", return_value=None),
            patch.object(reconciliation, "_snapshot", return_value=snapshot),
            patch.object(
                sources,
                "source_terminal_evidence",
                return_value=evidence,
            ),
            patch.object(
                reconciliation,
                "_terminal_checkout_observation",
                return_value=checkout,
            ),
            patch.object(
                reconciliation,
                "_coordination",
                return_value=coordination,
            ),
        ):
            preview = reconciliation._preview_state(CHECKOUT_KEY)

        self.assertEqual("blocked", preview["status"])
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn(
            "work-lane-durable-followup-binding-missing",
            preview["blockers"],
        )


if __name__ == "__main__":
    unittest.main()
