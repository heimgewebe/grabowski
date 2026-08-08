from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types


import grabowski_checkouts as checkouts
import grabowski_checkout_terminal_reconciliation as reconciliation
import grabowski_checkout_terminal_sources as sources
import grabowski_lane_closeout as lane_closeout
import grabowski_work_acquire as work_acquire


class CheckoutTerminalReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.checkout = self.root / "worktrees" / "topic"
        self.checkout_db = self.root / "state" / "checkouts.sqlite3"
        self.archive_root = self.root / "state" / "archives"
        self.resource_db = self.root / "state" / "resources.sqlite3"
        self.task_db = self.root / "state" / "tasks.sqlite3"
        self.repo.mkdir()
        self._git("init", "-b", "main")
        self._git("config", "user.name", "Grabowski Test")
        self._git("config", "user.email", "grabowski@example.invalid")
        (self.repo / "README.md").write_text("initial\n", encoding="utf-8")
        self._git("add", "README.md")
        self._git("commit", "-m", "initial")
        self.head = self._git("rev-parse", "HEAD").stdout.strip()
        self._git("worktree", "add", "-b", "topic", str(self.checkout), "HEAD")
        self.patches = [
            patch.object(checkouts, "CHECKOUT_DB", self.checkout_db),
            patch.object(checkouts, "ARCHIVE_ROOT", self.archive_root),
            patch.object(checkouts, "CHECKOUT_LOCK", self.root / "state" / "checkouts.lock"),
            patch.object(checkouts.resources, "RESOURCE_DB", self.resource_db),
            patch.object(checkouts.tasks, "TASK_DB", self.task_db),
            patch.object(checkouts.operator, "_safe_environment", return_value=os.environ.copy()),
            patch.object(checkouts.operator, "_require_operator_mutation"),
            patch.object(checkouts.operator, "_require_operator_capability"),
            patch.object(checkouts.base, "_append_audit"),
            patch.object(checkouts, "_processes_under", return_value=[]),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def _git(self, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(cwd or self.repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _common_dir(self) -> Path:
        raw = Path(self._git("rev-parse", "--git-common-dir").stdout.strip())
        return (self.repo / raw).resolve() if not raw.is_absolute() else raw.resolve()

    def _missing_binding(
        self,
        *,
        source_kind: str = "bureau_task",
        source_id: str = "GRABOWSKI-OPERATOR-SURFACE-V1-T065",
        phase: str = "active",
    ) -> dict[str, object]:
        common_dir = self._common_dir()
        retained_until = int(time.time()) + 3600
        supported_kinds = checkouts.TERMINAL_EVIDENCE_SOURCE_KINDS
        fixture_kinds = (
            supported_kinds | {source_kind}
            if source_kind not in supported_kinds
            else supported_kinds
        )
        with patch.object(checkouts, "TERMINAL_EVIDENCE_SOURCE_KINDS", fixture_kinds):
            binding = checkouts._reserve_checkout_lifecycle(
                repo_common_dir=common_dir,
                repo_path=self.repo,
                checkout_path=self.checkout,
                owner_id="owner-a",
                purpose="terminal reconciliation fixture",
                source_kind=source_kind,
                source_id=source_id,
                artifact_class="implementation_worktree",
                retention_until_unix=retained_until,
                expected_head=self.head,
                expected_branch="topic",
            )
        checkouts._upsert_retention(
            checkout_key=str(binding["checkout_key"]),
            repo_common_dir=common_dir,
            repo_path=self.repo,
            checkout_path=self.checkout,
            owner_id="owner-a",
            purpose="terminal reconciliation fixture",
            retention_until_unix=retained_until,
            expected_head=self.head,
            expected_branch="topic",
        )
        if phase == "completed_retained":
            checkouts._mark_checkout_completed_retained(
                checkout_key=str(binding["checkout_key"]),
                owner_id="owner-a",
                expected_head=self.head,
                expected_branch="topic",
            )
        self._git("worktree", "remove", str(self.checkout))
        return checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]

    @staticmethod
    def _terminal_source_evidence(binding: dict[str, object]) -> dict[str, object]:
        source = binding["source"]
        assert isinstance(source, dict)
        core = {
            "schema_version": 1,
            "kind": source["kind"],
            "source_id": source["id"],
            "terminal_state": "verified",
        }
        return {**core, "evidence_sha256": checkouts._sha256_json(core)}

    def _preview(self, binding: dict[str, object]) -> dict[str, object]:
        with patch.object(
            sources,
            "source_terminal_evidence",
            side_effect=self._terminal_source_evidence,
        ):
            return reconciliation.preview(str(binding["checkout_key"]))

    def _apply(
        self,
        binding: dict[str, object],
        preview: dict[str, object],
    ) -> dict[str, object]:
        with patch.object(
            sources,
            "source_terminal_evidence",
            side_effect=self._terminal_source_evidence,
        ):
            return reconciliation.apply(
                str(binding["checkout_key"]),
                "owner-a",
                str(preview["preview_sha256"]),
                int(preview["preview_created_at_unix"]),
                reconciliation.CONFIRMATION,
            )

    def test_preview_and_apply_are_evidence_only(self) -> None:
        binding = self._missing_binding()
        preview = self._preview(binding)
        self.assertTrue(preview["safe_to_apply"])
        result = self._apply(binding, preview)
        self.assertEqual("applied", result["status"])
        after = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("externally_terminal_missing", after["phase"])
        self.assertIsNone(after["archived_at_unix"])
        self.assertEqual({}, checkouts._latest_archives([str(binding["checkout_key"])]))
        retained = checkouts._retention_records([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("owner-a", retained["owner_id"])
        self.assertEqual(["lifecycle_phase_transition"], result["receipt"]["effects"])
        self.assertIn(
            "archive_or_cleanup_authority",
            result["receipt"]["does_not_establish"],
        )
        self.assertEqual(2, len(result["lease_release"]["released"]))

    def test_preview_digest_binds_timestamp_and_expiry(self) -> None:
        binding = self._missing_binding()
        with (
            patch.object(
                sources,
                "source_terminal_evidence",
                side_effect=self._terminal_source_evidence,
            ),
            patch.object(checkouts, "_now", side_effect=[100, 101]),
        ):
            first = reconciliation.preview(str(binding["checkout_key"]))
            second = reconciliation.preview(str(binding["checkout_key"]))
        self.assertNotEqual(first["preview_sha256"], second["preview_sha256"])
        self.assertEqual(100, first["preview_created_at_unix"])
        self.assertEqual(100 + reconciliation.PREVIEW_TTL_SECONDS, first["preview_expires_at_unix"])

    def test_replay_is_idempotent(self) -> None:
        binding = self._missing_binding(phase="completed_retained")
        preview = self._preview(binding)
        first = self._apply(binding, preview)
        second = reconciliation.apply(
            str(binding["checkout_key"]),
            "owner-a",
            str(preview["preview_sha256"]),
            int(preview["preview_created_at_unix"]),
            reconciliation.CONFIRMATION,
        )
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(
            first["receipt"]["receipt_sha256"],
            second["receipt"]["receipt_sha256"],
        )

    def test_reappeared_checkout_invalidates_preview(self) -> None:
        binding = self._missing_binding()
        preview = self._preview(binding)
        self._git("worktree", "add", str(self.checkout), "topic")
        with patch.object(
            sources,
            "source_terminal_evidence",
            side_effect=self._terminal_source_evidence,
        ):
            with self.assertRaisesRegex(RuntimeError, "preview is stale"):
                reconciliation.apply(
                    str(binding["checkout_key"]),
                    "owner-a",
                    str(preview["preview_sha256"]),
                    int(preview["preview_created_at_unix"]),
                    reconciliation.CONFIRMATION,
                )

    def test_broken_symlink_at_bound_path_blocks_without_mutation(self) -> None:
        binding = self._missing_binding()
        self.checkout.symlink_to(
            self.root / "missing-target",
            target_is_directory=True,
        )
        preview = self._preview(binding)
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("checkout-path-symlink", preview["blockers"])
        self.assertTrue(preview["checkout_observation"]["checkout_exists"])
        with self.assertRaisesRegex(RuntimeError, "checkout-path-symlink"):
            self._apply(binding, preview)
        after = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("active", after["phase"])
        self.assertIsNone(reconciliation._record(str(binding["checkout_key"])))

    def test_binding_revision_drift_invalidates_preview(self) -> None:
        binding = self._missing_binding()
        preview = self._preview(binding)
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE lifecycle_bindings SET updated_at_unix=updated_at_unix+1 "
                "WHERE checkout_key=?",
                (binding["checkout_key"],),
            )
            connection.commit()
        with patch.object(
            sources,
            "source_terminal_evidence",
            side_effect=self._terminal_source_evidence,
        ):
            with self.assertRaisesRegex(RuntimeError, "preview is stale"):
                reconciliation.apply(
                    str(binding["checkout_key"]),
                    "owner-a",
                    str(preview["preview_sha256"]),
                    int(preview["preview_created_at_unix"]),
                    reconciliation.CONFIRMATION,
                )

    def test_foreign_lease_blocks_preview(self) -> None:
        binding = self._missing_binding()
        checkouts.resources.acquire_resources(
            "foreign-owner",
            [f"path:{self.checkout}"],
            purpose="foreign live checkout work",
            ttl_seconds=600,
        )
        preview = self._preview(binding)
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("active-coordination", preview["blockers"])

    def test_external_terminal_phase_never_becomes_cleanup_candidate(self) -> None:
        binding = self._missing_binding()
        preview = self._preview(binding)
        self._apply(binding, preview)
        current = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        record = {
            "checkout_key": binding["checkout_key"],
            "repo_common_dir": str(self._common_dir()),
            "repo_path": str(self.repo),
            "path": str(self.checkout),
            "head": self.head,
            "branch": "topic",
            "prunable": True,
            "bare": False,
            "detached": False,
            "is_main": False,
        }
        lifecycle = {
            "binding": current,
            "latest_archive": None,
            "retention": checkouts._retention_records([str(binding["checkout_key"])])[
                str(binding["checkout_key"])
            ],
        }
        decision = checkouts._checkout_lifecycle_decision(
            record,
            {"dirty": False, "status_sha256": None},
            lifecycle,
            {"blocking": False, "leases": [], "tasks": [], "processes": []},
            exists=False,
            now=int(time.time()),
        )
        self.assertEqual("externally_terminal_missing", decision["state"])
        self.assertEqual("terminal", decision["hygiene_mark"])
        self.assertNotIn("cleanup", decision["state"])

    def test_automation_source_fails_closed_without_absence_inference(self) -> None:
        binding = self._missing_binding(
            source_kind="automation",
            source_id="bureau-frontier-entblockung-20260806T1519Z",
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "automation checkout lifecycle source has no immutable terminal evidence contract",
        ):
            reconciliation.preview(str(binding["checkout_key"]))
        after = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("active", after["phase"])
        self.assertIsNone(reconciliation._record(str(binding["checkout_key"])))

    def test_source_dispatch_covers_all_supported_kinds(self) -> None:
        for kind in sorted(checkouts.TERMINAL_EVIDENCE_SOURCE_KINDS):
            source_id = f"source-{kind}"
            core = {
                "schema_version": 1,
                "kind": kind,
                "source_id": source_id,
                "terminal_state": "terminal",
            }
            evidence = {**core, "evidence_sha256": checkouts._sha256_json(core)}
            observer = unittest.mock.Mock(return_value=evidence)
            with patch.dict(sources._OBSERVERS, {kind: observer}):
                self.assertEqual(
                    evidence,
                    sources.source_terminal_evidence(
                        {"source": {"kind": kind, "id": source_id}}
                    ),
                )
            observer.assert_called_once_with(source_id)


    def test_work_lane_source_requires_explicit_terminal_closeout(self) -> None:
        lane_id = "a" * 32
        record = {
            "lane_id": lane_id,
            "state": "ready",
            "receipt_sha256": "b" * 64,
        }
        with patch.object(work_acquire, "_read_state", return_value=record):
            with self.assertRaisesRegex(
                RuntimeError, "no terminal closeout evidence"
            ):
                sources.work_lane_terminal_evidence(lane_id)

    def test_work_lane_source_accepts_bound_terminal_closeout(self) -> None:
        lane_id = "c" * 32
        assessment = lane_closeout.assess(lane_closeout.LaneCloseoutObservation(
            lane_id=lane_id, repository="/tmp/repo", workspace="/tmp/worktree",
            branch="feat/example", base_revision="a" * 40, writer_state="completed",
            task_active=False, process_active=False, lease_active=True, git_dirty=False,
            head_sha="b" * 40, remote_head_sha="b" * 40, ahead_commits=0, behind_commits=0,
            pr_number=1, pr_state="merged", pr_head_sha="b" * 40, merged_sha="b" * 40,
        ), observed_at_unix=200)
        record = {
            "lane_id": lane_id, "state": "ready", "receipt_sha256": "d" * 64,
            "terminal_closeout": {
                "schema_version": 1, "kind": "grabowski.work_lane_terminal_closeout",
                "closeout_state": assessment["closeout_state"],
                "assessment_sha256": assessment["assessment_sha256"], "assessment": assessment,
            },
        }
        with patch.object(work_acquire, "_read_state", return_value=record):
            evidence = sources.work_lane_terminal_evidence(lane_id)
        self.assertEqual(evidence["kind"], "work_lane")
        self.assertEqual(evidence["source_id"], lane_id)
        self.assertEqual(evidence["terminal_state"], "pr_merged")
        self.assertEqual(evidence["lane_receipt_sha256"], "d" * 64)
        self.assertEqual(evidence["assessment_sha256"], assessment["assessment_sha256"])
        self.assertEqual(
            evidence["evidence_sha256"],
            checkouts._sha256_json(
                {key: value for key, value in evidence.items() if key != "evidence_sha256"}
            ),
        )

    def test_operator_obligation_accepts_historical_resolution(self) -> None:
        status = {
            "state": "blocked",
            "attention_class": "historical",
            "resolution_disposition": "superseded",
            "continuation_required": False,
            "work_complete": False,
            "open_file_sha256": "a" * 64,
            "close_file_sha256": "b" * 64,
            "resolution_file_sha256": "c" * 64,
        }
        with patch.object(
            sources.operator_obligation,
            "status_obligation",
            return_value=status,
        ):
            evidence = sources.operator_obligation_terminal_evidence("goo-example")
        self.assertEqual("superseded", evidence["resolution_disposition"])

    def test_thread_focus_rejects_current_obligation(self) -> None:
        with patch.object(
            sources.operator_obligation,
            "list_obligations",
            return_value={
                "scan_truncated": False,
                "integrity_errors": [],
                "attention_required": True,
                "records": [{"obligation_id": "goo-current-thread"}],
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "requires continuation"):
                sources.thread_focus_terminal_evidence("thread-focus-id")

    def test_thread_focus_binds_completed_obligation_set(self) -> None:
        listed = {
            "scan_truncated": False,
            "integrity_errors": [],
            "attention_required": False,
            "records": [{"obligation_id": "goo-complete"}],
        }
        status = {
            "obligation_id": "goo-complete",
            "state": "completed",
            "attention_class": "completed",
            "continuation_required": False,
            "work_complete": True,
            "open_file_sha256": "a" * 64,
            "close_file_sha256": "b" * 64,
            "resolution_file_sha256": None,
        }
        with (
            patch.object(sources.operator_obligation, "list_obligations", return_value=listed),
            patch.object(sources.operator_obligation, "status_obligation", return_value=status),
        ):
            evidence = sources.thread_focus_terminal_evidence("thread-focus-id")
        self.assertEqual("completed_without_current_obligation", evidence["terminal_state"])
        self.assertEqual("goo-complete", evidence["obligations"][0]["obligation_id"])

    def test_bureau_task_binds_current_registry_head(self) -> None:
        task = {"id": "TASK-T001", "state": "verified"}
        raw = json.dumps(task)
        completed = subprocess.CompletedProcess(["git"], 0, stdout=raw, stderr="")
        tree = subprocess.CompletedProcess(["git"], 0, stdout="d" * 40 + "\n", stderr="")
        with (
            patch.object(
                sources.bureau_leases,
                "inspect_bureau_control_checkout",
                return_value={"head": "e" * 40, "control_root": str(self.repo)},
            ),
            patch.object(sources, "_github_json", return_value={"sha": "e" * 40}),
            patch.object(checkouts, "_git_read", side_effect=[completed, tree]),
        ):
            evidence = sources.bureau_task_terminal_evidence("TASK-T001")
        self.assertEqual("verified", evidence["terminal_state"])
        self.assertEqual("e" * 40, evidence["registry_commit"])

    def test_github_issue_requires_closed_state(self) -> None:
        with patch.object(
            sources,
            "_github_json",
            return_value={
                "number": 215,
                "state": "CLOSED",
                "url": "https://github.com/heimgewebe/grabowski/issues/215",
                "closedAt": "2026-07-18T00:00:00Z",
                "updatedAt": "2026-07-18T00:00:00Z",
            },
        ):
            evidence = sources.github_issue_terminal_evidence(
                "heimgewebe/grabowski#215:T002"
            )
        self.assertEqual("CLOSED", evidence["terminal_state"])
        with patch.object(
            sources,
            "_github_json",
            return_value={"number": 215, "state": "OPEN", "closedAt": None},
        ):
            with self.assertRaisesRegex(RuntimeError, "not closed"):
                sources.github_issue_terminal_evidence("heimgewebe/grabowski#215:T002")


if __name__ == "__main__":
    unittest.main()
