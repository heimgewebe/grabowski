from __future__ import annotations

from contextlib import contextmanager
import hashlib
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
        (self.repo / ".gitignore").write_text(
            ".review-audits/\nignored-local/\n", encoding="utf-8"
        )
        self._git("add", "README.md", ".gitignore")
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

    def _present_binding(
        self,
        *,
        source_kind: str = "work_lane",
        source_id: str = "a" * 32,
    ) -> dict[str, object]:
        binding = self._missing_binding(
            source_kind=source_kind,
            source_id=source_id,
        )
        self._git("worktree", "add", str(self.checkout), "topic")
        return binding

    def _advance_topic_branch(self) -> str:
        self._git("worktree", "add", str(self.checkout), "topic")
        (self.checkout / "later.txt").write_text("later\n", encoding="utf-8")
        self._git("add", "later.txt", cwd=self.checkout)
        self._git("commit", "-m", "later topic work", cwd=self.checkout)
        new_head = self._git("rev-parse", "HEAD", cwd=self.checkout).stdout.strip()
        self._git("worktree", "remove", str(self.checkout))
        return new_head

    def _diverge_topic_branch(self) -> str:
        tree = self._git("rev-parse", f"{self.head}^{{tree}}").stdout.strip()
        unrelated = self._git("commit-tree", tree, "-m", "unrelated root").stdout.strip()
        self._git("update-ref", "refs/heads/topic", unrelated)
        return unrelated

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
        if source["kind"] == "work_lane":
            core["lease_release_ready"] = True
        return {**core, "evidence_sha256": checkouts._sha256_json(core)}

    @staticmethod
    def _thread_focus_source_evidence(
        binding: dict[str, object]
    ) -> dict[str, object]:
        source = binding["source"]
        assert isinstance(source, dict)
        assert source["kind"] == "thread_focus"
        obligations = [
            {
                "obligation_id": "goo-thread-focus-test",
                "state": "completed",
                "attention_class": "none",
                "open_file_sha256": "a" * 64,
                "close_file_sha256": "b" * 64,
                "resolution_file_sha256": None,
            }
        ]
        core = {
            "schema_version": 1,
            "kind": "thread_focus",
            "source_id": source["id"],
            "terminal_state": "completed_without_current_obligation",
            "obligations": obligations,
            "obligation_set_sha256": checkouts._sha256_json(obligations),
        }
        return {**core, "evidence_sha256": checkouts._sha256_json(core)}

    @staticmethod
    def _remote_secured() -> dict[str, object]:
        return {
            "remote_secured": True,
            "remote_secured_refs": ["refs/remotes/origin/topic"],
            "error": None,
        }

    def _present_thread_focus_with_retention_catchup(
        self,
    ) -> tuple[dict[str, object], str, dict[str, object]]:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        (self.checkout / "later.txt").write_text("later\n", encoding="utf-8")
        self._git("add", "later.txt", cwd=self.checkout)
        self._git("commit", "-m", "later terminal head", cwd=self.checkout)
        new_head = self._git("rev-parse", "HEAD", cwd=self.checkout).stdout.strip()
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE retention SET expected_head=?, updated_at_unix=updated_at_unix+1 "
                "WHERE checkout_key=?",
                (new_head, str(binding["checkout_key"])),
            )
            connection.commit()
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "self-review.json").write_text(
            '{"verdict":"PASS"}\n', encoding="utf-8"
        )
        (evidence_root / "settlement.json").write_text(
            '{"settled":true}\n', encoding="utf-8"
        )
        evidence = self._thread_focus_source_evidence(binding)
        return binding, new_head, evidence

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

    def test_present_clean_terminal_checkout_releases_active_capacity_but_preserves_checkout(self) -> None:
        binding = self._present_binding()
        before_capacity = checkouts.active_capacity_projection(self.repo)
        self.assertEqual(1, before_capacity["used"])
        remote = {
            "remote_secured": True,
            "remote_secured_refs": ["refs/remotes/origin/topic"],
            "error": None,
        }
        with patch.object(
            checkouts, "_remote_secured_observation", return_value=remote
        ):
            preview = self._preview(binding)
            self.assertTrue(preview["safe_to_apply"])
            self.assertEqual("present", preview["checkout_observation"]["mode"])
            result = self._apply(binding, preview)
        self.assertEqual("applied", result["status"])
        receipt = result["receipt"]
        self.assertEqual("present_retained", receipt["reconciliation_mode"])
        self.assertTrue(receipt["checkout_preserved"])
        self.assertIn("active_capacity_release", receipt["effects"])
        after = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        retained = checkouts._retention_records([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("completed_retained", after["phase"])
        self.assertEqual("owner-a", retained["owner_id"])
        self.assertTrue(self.checkout.is_dir())
        after_capacity = checkouts.active_capacity_projection(self.repo)
        self.assertEqual(0, after_capacity["used"])

    def test_present_current_work_lane_accepts_exact_terminal_head(self) -> None:
        binding = self._present_binding()
        evidence = self._terminal_source_evidence(binding)
        evidence["terminal_head_sha"] = self.head
        evidence["evidence_sha256"] = checkouts._sha256_json(
            {key: value for key, value in evidence.items() if key != "evidence_sha256"}
        )
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts,
                "_remote_secured_observation",
                return_value={
                    "remote_secured": True,
                    "remote_secured_refs": ["refs/remotes/origin/topic"],
                    "error": None,
                },
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertTrue(preview["safe_to_apply"])
        self.assertEqual([], preview["blockers"])
        self.assertEqual(self.head, preview["source_evidence"]["terminal_head_sha"])

    def test_present_current_work_lane_rejects_head_after_terminal_closeout(self) -> None:
        binding = self._present_binding()
        (self.checkout / "post-closeout.txt").write_text("later\n", encoding="utf-8")
        self._git("add", "post-closeout.txt", cwd=self.checkout)
        self._git("commit", "-m", "post closeout work", cwd=self.checkout)
        evidence = self._terminal_source_evidence(binding)
        evidence["terminal_head_sha"] = self.head
        evidence["evidence_sha256"] = checkouts._sha256_json(
            {key: value for key, value in evidence.items() if key != "evidence_sha256"}
        )
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts,
                "_remote_secured_observation",
                return_value={
                    "remote_secured": True,
                    "remote_secured_refs": ["refs/remotes/origin/topic"],
                    "error": None,
                },
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn(
            "work-lane-head-after-terminal-closeout", preview["blockers"]
        )

    def test_present_work_lane_requires_release_readiness(self) -> None:
        binding = self._present_binding()
        evidence = self._terminal_source_evidence(binding)
        evidence["lease_release_ready"] = False
        evidence["evidence_sha256"] = checkouts._sha256_json(
            {key: value for key, value in evidence.items() if key != "evidence_sha256"}
        )
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts,
                "_remote_secured_observation",
                return_value={
                    "remote_secured": True,
                    "remote_secured_refs": ["refs/remotes/origin/topic"],
                    "error": None,
                },
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("work-lane-lease-release-not-ready", preview["blockers"])

    def test_present_terminal_checkout_rejects_non_work_lane_source(self) -> None:
        binding = self._present_binding(
            source_kind="bureau_task",
            source_id="GRABOWSKI-OPERATOR-SURFACE-V1-T065",
        )
        with patch.object(
            checkouts,
            "_remote_secured_observation",
            return_value={
                "remote_secured": True,
                "remote_secured_refs": ["refs/remotes/origin/topic"],
                "error": None,
            },
        ):
            preview = self._preview(binding)
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("present-checkout-source-not-work-lane", preview["blockers"])

    def test_present_thread_focus_accepts_hash_bound_review_evidence_and_retention_head_catchup(self) -> None:
        binding, new_head, evidence = self._present_thread_focus_with_retention_catchup()
        before = {
            path.name: path.read_bytes()
            for path in sorted((self.checkout / ".review-audits").iterdir())
        }
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
            self.assertTrue(preview["safe_to_apply"])
            self.assertEqual([], preview["blockers"])
            self.assertEqual(
                {
                    "kind": "thread_focus_retention_head_catchup",
                    "binding_expected_head": self.head,
                    "retention_expected_head": new_head,
                },
                preview["identity_catchup"],
            )
            manifest = preview["checkout_observation"]["review_evidence"]
            self.assertEqual("review_evidence_only", manifest["classification"])
            self.assertTrue(manifest["eligible"])
            self.assertEqual(2, manifest["file_count"])
            self.assertEqual(
                [
                    ".review-audits/self-review.json",
                    ".review-audits/settlement.json",
                ],
                [item["path"] for item in manifest["files"]],
            )
            result = reconciliation.apply(
                str(binding["checkout_key"]),
                "owner-a",
                str(preview["preview_sha256"]),
                int(preview["preview_created_at_unix"]),
                reconciliation.CONFIRMATION,
            )
        receipt = result["receipt"]
        self.assertEqual("present_retained", receipt["reconciliation_mode"])
        self.assertEqual(new_head, receipt["binding_after"]["expected_head"])
        self.assertEqual(new_head, receipt["retention_after"]["expected_head"])
        self.assertIsNone(receipt["branch_head_rebind"])
        self.assertEqual(
            [
                "lifecycle_phase_transition",
                "active_capacity_release",
                "thread_focus_retention_head_catchup",
                "review_evidence_snapshot_retained",
            ],
            receipt["effects"],
        )
        self.assertEqual(
            manifest["manifest_sha256"],
            receipt["review_evidence_manifest"]["manifest_sha256"],
        )
        self.assertIn(
            "permission_to_modify_or_delete_review_evidence",
            receipt["does_not_establish"],
        )
        after = {
            path.name: path.read_bytes()
            for path in sorted((self.checkout / ".review-audits").iterdir())
        }
        self.assertEqual(before, after)
        lifecycle = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("completed_retained", lifecycle["phase"])


    def test_review_evidence_sql_race_aborts_without_terminal_transition(self) -> None:
        binding, _head, evidence = self._present_thread_focus_with_retention_catchup()
        key = str(binding["checkout_key"])
        audit = self.checkout / ".review-audits" / "self-review.json"
        real_database = checkouts._database
        injected = False

        @contextmanager
        def database_with_sql_race():
            nonlocal injected
            with real_database() as connection:
                def trace(sql):
                    nonlocal injected
                    if not injected and sql.startswith("SELECT owner_id, preview_sha256"):
                        injected = True
                        audit.write_text('{"verdict":"LATE"}\n', encoding="utf-8")
                connection.set_trace_callback(trace)
                try:
                    yield connection
                finally:
                    connection.set_trace_callback(None)

        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(checkouts, "_remote_secured_observation", return_value=self._remote_secured()),
        ):
            preview = reconciliation.preview(key)
            with patch.object(checkouts, "_database", database_with_sql_race):
                with self.assertRaisesRegex(RuntimeError, "snapshot|before commit"):
                    reconciliation.apply(key, "owner-a", preview["preview_sha256"],
                                         preview["preview_created_at_unix"], reconciliation.CONFIRMATION)
        self.assertTrue(injected)
        self.assertEqual("active", checkouts._lifecycle_bindings([key])[key]["phase"])
        self.assertIsNone(reconciliation._record(key))

    def test_review_evidence_changed_inside_commit_keeps_atomic_snapshot(self) -> None:
        binding, _head, evidence = self._present_thread_focus_with_retention_catchup()
        key = str(binding["checkout_key"])
        audit = self.checkout / ".review-audits" / "self-review.json"
        original = audit.read_bytes()
        real_database = checkouts._database
        injected = False

        @contextmanager
        def database_with_commit_race():
            nonlocal injected
            with real_database() as connection:
                def trace(sql):
                    nonlocal injected
                    if not injected and sql == "COMMIT":
                        injected = True
                        audit.write_text('{"verdict":"AFTER-OBSERVATION"}\n', encoding="utf-8")
                connection.set_trace_callback(trace)
                try:
                    yield connection
                finally:
                    connection.set_trace_callback(None)

        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(checkouts, "_remote_secured_observation", return_value=self._remote_secured()),
        ):
            preview = reconciliation.preview(key)
            with patch.object(checkouts, "_database", database_with_commit_race):
                result = reconciliation.apply(key, "owner-a", preview["preview_sha256"],
                                              preview["preview_created_at_unix"], reconciliation.CONFIRMATION)
        self.assertTrue(injected)
        self.assertEqual("applied", result["status"])
        self.assertNotEqual(original, audit.read_bytes())
        receipt = reconciliation._record(key)["receipt"]
        snapshot = receipt["review_evidence_snapshot"]
        self.assertFalse(snapshot["source_files_frozen"])
        self.assertNotIn('"content":', json.dumps(receipt))
        with checkouts._database() as connection:
            retained = connection.execute(
                "SELECT content FROM terminal_review_evidence WHERE snapshot_sha256=? AND path=?",
                (snapshot["snapshot_sha256"], ".review-audits/self-review.json"),
            ).fetchone()[0]
        self.assertEqual(original, retained)
        self.assertIn("review_evidence_snapshot_retained", receipt["effects"])

    def test_review_evidence_snapshot_corruption_is_rejected_on_readback(self) -> None:
        binding, _head, evidence = self._present_thread_focus_with_retention_catchup()
        key = str(binding["checkout_key"])
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(checkouts, "_remote_secured_observation", return_value=self._remote_secured()),
        ):
            preview = reconciliation.preview(key)
            result = reconciliation.apply(key, "owner-a", preview["preview_sha256"],
                                          preview["preview_created_at_unix"], reconciliation.CONFIRMATION)
        with checkouts._database() as connection:
            connection.execute("UPDATE terminal_review_evidence SET content=? WHERE snapshot_sha256=?",
                               (b"changed", result["receipt"]["review_evidence_snapshot"]["snapshot_sha256"]))
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "snapshot digest"):
            reconciliation._record(key)

    def test_review_evidence_snapshot_and_lifecycle_rollback_together(self) -> None:
        binding, _head, evidence = self._present_thread_focus_with_retention_catchup()
        key = str(binding["checkout_key"])
        real_database = checkouts._database

        @contextmanager
        def database_with_receipt_failure():
            with real_database() as connection:
                class Proxy:
                    def execute(self, sql, *args):
                        if "INSERT INTO terminal_reconciliations(" in sql:
                            raise RuntimeError("injected receipt failure")
                        return connection.execute(sql, *args)
                    def __getattr__(self, name):
                        return getattr(connection, name)
                yield Proxy()
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(checkouts, "_remote_secured_observation", return_value=self._remote_secured()),
        ):
            preview = reconciliation.preview(key)
            with patch.object(checkouts, "_database", database_with_receipt_failure):
                with self.assertRaisesRegex(RuntimeError, "injected receipt failure"):
                    reconciliation.apply(key, "owner-a", preview["preview_sha256"],
                                         preview["preview_created_at_unix"], reconciliation.CONFIRMATION)
        self.assertEqual("active", checkouts._lifecycle_bindings([key])[key]["phase"])
        self.assertIsNone(reconciliation._record(key))
        with checkouts._database() as connection:
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='terminal_review_evidence'"
            ).fetchone()
            if table is not None:
                self.assertEqual(0, connection.execute("SELECT count(*) FROM terminal_review_evidence").fetchone()[0])

    def test_present_thread_focus_revalidates_head_after_review_evidence_scan(self) -> None:
        binding, _new_head, evidence = self._present_thread_focus_with_retention_catchup()
        real_observation = reconciliation._thread_focus_review_evidence_observation
        injected = False

        def observation_with_late_commit(
            record: dict[str, object], status: dict[str, object]
        ) -> dict[str, object]:
            nonlocal injected
            result = real_observation(record, status)
            if not injected:
                self._git(
                    "commit",
                    "--allow-empty",
                    "-m",
                    "late head during evidence scan",
                    cwd=self.checkout,
                )
                injected = True
            return result

        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
            patch.object(
                reconciliation,
                "_thread_focus_review_evidence_observation",
                side_effect=observation_with_late_commit,
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn(
            "checkout-head-drift-after-review-evidence", preview["blockers"]
        )

    def test_present_thread_focus_revalidates_review_evidence_at_commit_boundary(self) -> None:
        binding, _new_head, evidence = self._present_thread_focus_with_retention_catchup()
        audit = self.checkout / ".review-audits" / "self-review.json"
        real_database = checkouts._database
        injected = False

        @contextmanager
        def database_with_late_evidence():
            nonlocal injected
            if not injected:
                audit.write_text('{"verdict":"LATE"}\n', encoding="utf-8")
                injected = True
            with real_database() as connection:
                yield connection

        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
            self.assertTrue(preview["safe_to_apply"])
            with patch.object(checkouts, "_database", database_with_late_evidence):
                with self.assertRaisesRegex(RuntimeError, "commit boundary"):
                    reconciliation.apply(
                        str(binding["checkout_key"]),
                        "owner-a",
                        str(preview["preview_sha256"]),
                        int(preview["preview_created_at_unix"]),
                        reconciliation.CONFIRMATION,
                    )
        lifecycle = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("active", lifecycle["phase"])

    def test_present_thread_focus_revalidates_head_at_commit_boundary(self) -> None:
        binding, _new_head, evidence = self._present_thread_focus_with_retention_catchup()
        real_database = checkouts._database
        injected = False

        @contextmanager
        def database_with_late_commit():
            nonlocal injected
            if not injected:
                self._git(
                    "commit",
                    "--allow-empty",
                    "-m",
                    "late head at commit boundary",
                    cwd=self.checkout,
                )
                injected = True
            with real_database() as connection:
                yield connection

        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
            self.assertTrue(preview["safe_to_apply"])
            with patch.object(checkouts, "_database", database_with_late_commit):
                with self.assertRaisesRegex(RuntimeError, "commit boundary"):
                    reconciliation.apply(
                        str(binding["checkout_key"]),
                        "owner-a",
                        str(preview["preview_sha256"]),
                        int(preview["preview_created_at_unix"]),
                        reconciliation.CONFIRMATION,
                    )
        lifecycle = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("active", lifecycle["phase"])

    def test_present_thread_focus_manifest_drift_invalidates_apply(self) -> None:
        binding, _new_head, evidence = self._present_thread_focus_with_retention_catchup()
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
            self.assertTrue(preview["safe_to_apply"])
            (self.checkout / ".review-audits" / "self-review.json").write_text(
                '{"verdict":"CHANGED"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "preview is stale"):
                reconciliation.apply(
                    str(binding["checkout_key"]),
                    "owner-a",
                    str(preview["preview_sha256"]),
                    int(preview["preview_created_at_unix"]),
                    reconciliation.CONFIRMATION,
                )
        lifecycle = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("active", lifecycle["phase"])

    def test_present_thread_focus_hashes_ignored_review_audits_even_when_git_status_is_clean(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        audit = evidence_root / "review.json"
        audit.write_text('{"verdict":"PASS"}\n', encoding="utf-8")
        status = checkouts._worktree_status(
            next(
                item
                for item in checkouts._worktree_records(self.repo)[2]
                if Path(item["path"]) == self.checkout
            )
        )
        self.assertFalse(status["dirty"])
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertTrue(preview["safe_to_apply"])
        manifest = preview["checkout_observation"]["review_evidence"]
        self.assertEqual("review_evidence_only", manifest["classification"])
        self.assertEqual(1, manifest["file_count"])
        self.assertEqual(".review-audits/review.json", manifest["files"][0]["path"])
        self.assertEqual(
            hashlib.sha256(audit.read_bytes()).hexdigest(), manifest["files"][0]["sha256"]
        )

    def test_present_thread_focus_rejects_review_evidence_appearing_after_empty_scan(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence = self._thread_focus_source_evidence(binding)
        real_paths = reconciliation._thread_focus_review_evidence_paths
        injected = False

        def paths_with_late_audit(
            checkout: Path, status: dict[str, object]
        ) -> tuple[list[str], list[str]]:
            nonlocal injected
            result = real_paths(checkout, status)
            if not injected:
                evidence_root = self.checkout / ".review-audits"
                evidence_root.mkdir()
                (evidence_root / "late.json").write_text("{}\n", encoding="utf-8")
                injected = True
            return result

        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
            patch.object(
                reconciliation,
                "_thread_focus_review_evidence_paths",
                side_effect=paths_with_late_audit,
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-root-membership-drift", preview["blockers"])

    def test_present_thread_focus_rejects_review_evidence_membership_change_during_hash(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.json").write_text("{}\n", encoding="utf-8")
        late_audit = evidence_root / "late.json"
        evidence = self._thread_focus_source_evidence(binding)
        real_hash = reconciliation._hash_review_evidence_file
        injected = False

        def hash_with_late_audit(
            root_descriptor: int, raw_path: str, remaining_bytes: int
        ) -> tuple[dict[str, object] | None, list[str]]:
            nonlocal injected
            result = real_hash(root_descriptor, raw_path, remaining_bytes)
            if not injected:
                late_audit.write_text('{"verdict":"PASS"}\n', encoding="utf-8")
                injected = True
            return result

        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
            patch.object(
                reconciliation,
                "_hash_review_evidence_file",
                side_effect=hash_with_late_audit,
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-root-membership-drift", preview["blockers"])
        self.assertIn("review-evidence-root-changed-during-read", preview["blockers"])

    def test_present_thread_focus_rejects_tracked_submodule(self) -> None:
        self._git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.head},vendor/submodule",
            cwd=self.checkout,
        )
        self._git("commit", "-m", "tracked gitlink", cwd=self.checkout)
        (self.checkout / "vendor" / "submodule").mkdir(parents=True)
        self.head = self._git("rev-parse", "HEAD", cwd=self.checkout).stdout.strip()
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.json").write_text("{}\n", encoding="utf-8")
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-submodules-present", preview["blockers"])

    def test_present_thread_focus_rejects_unrelated_ignored_content(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.json").write_text("{}\n", encoding="utf-8")
        ignored = self.checkout / "ignored-local"
        ignored.mkdir()
        (ignored / "cache.bin").write_bytes(b"ignored but not trusted")
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn(
            "review-evidence-ignored-content-outside-allowlist", preview["blockers"]
        )

    def test_present_thread_focus_rejects_untrusted_untracked_path(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.json").write_text("{}\n", encoding="utf-8")
        (self.checkout / "notes.txt").write_text("not evidence\n", encoding="utf-8")
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-path-outside-allowlist", preview["blockers"])
        self.assertIn("checkout-dirty", preview["blockers"])
        self.assertIn("thread-focus-review-evidence-not-admissible", preview["blockers"])

    def test_present_thread_focus_rejects_unstaged_tracked_change(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.json").write_text("{}\n", encoding="utf-8")
        (self.checkout / "README.md").write_text("changed\n", encoding="utf-8")
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-unstaged-tracked-change", preview["blockers"])
        self.assertIn("checkout-dirty", preview["blockers"])

    def test_present_thread_focus_rejects_staged_tracked_change(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.json").write_text("{}\n", encoding="utf-8")
        (self.checkout / "README.md").write_text("changed\n", encoding="utf-8")
        self._git("add", "README.md", cwd=self.checkout)
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-staged-tracked-change", preview["blockers"])
        self.assertIn("checkout-dirty", preview["blockers"])

    def test_present_thread_focus_rejects_nested_review_evidence(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        nested = self.checkout / ".review-audits" / "nested"
        nested.mkdir(parents=True)
        (nested / "review.json").write_text("{}\n", encoding="utf-8")
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-path-outside-allowlist", preview["blockers"])

    def test_review_evidence_open_is_nonblocking_and_nofollow(self) -> None:
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.json").write_text("{}\n", encoding="utf-8")
        root_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            root_flags |= os.O_DIRECTORY
        root_descriptor = os.open(evidence_root, root_flags)
        real_open = os.open
        try:
            with patch.object(reconciliation.os, "open", wraps=real_open) as opened:
                evidence, blockers = reconciliation._hash_review_evidence_file(
                    root_descriptor,
                    ".review-audits/review.json",
                    reconciliation._REVIEW_EVIDENCE_MAX_TOTAL_BYTES,
                )
            self.assertIsNotNone(evidence)
            self.assertEqual([], blockers)
            file_open = next(
                call for call in opened.call_args_list if call.args[0] == "review.json"
            )
            flags = file_open.args[1]
            if hasattr(os, "O_NONBLOCK"):
                self.assertTrue(flags & os.O_NONBLOCK)
            if hasattr(os, "O_NOFOLLOW"):
                self.assertTrue(flags & os.O_NOFOLLOW)
        finally:
            os.close(root_descriptor)

    def test_present_thread_focus_rejects_symlink_review_evidence(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        outside = self.root / "outside-review.json"
        outside.write_text("secret-ish\n", encoding="utf-8")
        (evidence_root / "review.json").symlink_to(outside)
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-file-not-regular", preview["blockers"])

    def test_present_thread_focus_rejects_symlink_review_root_without_hashing_target(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        outside = self.root / "outside-audits"
        outside.mkdir()
        (outside / "review.json").write_text("must-not-be-read\n", encoding="utf-8")
        (self.checkout / ".review-audits").symlink_to(outside, target_is_directory=True)
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
            patch.object(
                reconciliation,
                "_hash_review_evidence_file",
                side_effect=AssertionError("symlink root target must not be hashed"),
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-root-symlink", preview["blockers"])

    def test_present_thread_focus_rejects_oversized_review_evidence(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.bin").write_bytes(
            b"x" * (reconciliation._REVIEW_EVIDENCE_MAX_FILE_BYTES + 1)
        )
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-file-size-exceeded", preview["blockers"])

    def test_present_thread_focus_rejects_aggregate_review_evidence_over_budget(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        evidence_root = self.checkout / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "a.json").write_text("1234\n", encoding="utf-8")
        (evidence_root / "b.json").write_text("5678\n", encoding="utf-8")
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
            patch.object(reconciliation, "_REVIEW_EVIDENCE_MAX_TOTAL_BYTES", 8),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("review-evidence-total-size-exceeded", preview["blockers"])

    def test_present_thread_focus_requires_retention_bound_current_head(self) -> None:
        binding = self._present_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        (self.checkout / "later.txt").write_text("later\n", encoding="utf-8")
        self._git("add", "later.txt", cwd=self.checkout)
        self._git("commit", "-m", "later unbound head", cwd=self.checkout)
        evidence = self._thread_focus_source_evidence(binding)
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(
                checkouts, "_remote_secured_observation", return_value=self._remote_secured()
            ),
        ):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("thread-focus-head-not-retention-bound", preview["blockers"])

    def test_thread_focus_retention_head_catchup_requires_present_checkout(self) -> None:
        binding = self._missing_binding(
            source_kind="thread_focus", source_id="thread-focus-id"
        )
        descendant = self._advance_topic_branch()
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE retention SET expected_head=?, updated_at_unix=updated_at_unix+1 "
                "WHERE checkout_key=?",
                (descendant, str(binding["checkout_key"])),
            )
            connection.commit()
        evidence = self._thread_focus_source_evidence(binding)
        with patch.object(sources, "source_terminal_evidence", return_value=evidence):
            preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn(
            "thread-focus-retention-head-catchup-requires-present-checkout",
            preview["blockers"],
        )

    def test_present_terminal_checkout_rebinds_descendant_head_in_lifecycle_and_retention(self) -> None:
        binding = self._present_binding()
        (self.checkout / "later.txt").write_text("later\n", encoding="utf-8")
        self._git("add", "later.txt", cwd=self.checkout)
        self._git("commit", "-m", "later topic work", cwd=self.checkout)
        new_head = self._git("rev-parse", "HEAD", cwd=self.checkout).stdout.strip()
        with patch.object(
            checkouts,
            "_remote_secured_observation",
            return_value={
                "remote_secured": True,
                "remote_secured_refs": ["refs/remotes/origin/topic"],
                "error": None,
            },
        ):
            preview = self._preview(binding)
            self.assertEqual(
                "descendant", preview["checkout_observation"]["branch_head_relation"]
            )
            result = self._apply(binding, preview)
        receipt = result["receipt"]
        self.assertEqual(new_head, receipt["binding_after"]["expected_head"])
        self.assertEqual(new_head, receipt["retention_after"]["expected_head"])
        self.assertEqual(
            {
                "relation": "descendant",
                "from_head": self.head,
                "to_head": new_head,
            },
            receipt["branch_head_rebind"],
        )
        self.assertTrue(self.checkout.is_dir())

    def test_present_reconciliation_can_later_supersede_to_missing(self) -> None:
        binding = self._present_binding()
        remote = {
            "remote_secured": True,
            "remote_secured_refs": ["refs/remotes/origin/topic"],
            "error": None,
        }
        with patch.object(
            checkouts, "_remote_secured_observation", return_value=remote
        ):
            first_preview = self._preview(binding)
            first = self._apply(binding, first_preview)
        first_receipt = first["receipt"]
        first_sha = first_receipt["receipt_sha256"]
        self._git("worktree", "remove", str(self.checkout))
        second_preview = self._preview(binding)
        self.assertTrue(second_preview["safe_to_apply"])
        self.assertEqual(
            first_sha,
            second_preview["supersedes_reconciliation_receipt_sha256"],
        )
        self.assertEqual(
            first_receipt, second_preview["supersedes_reconciliation_receipt"]
        )
        second = self._apply(binding, second_preview)
        second_receipt = second["receipt"]
        self.assertEqual("missing_external", second_receipt["reconciliation_mode"])
        self.assertEqual(
            first_sha, second_receipt["supersedes_reconciliation_receipt_sha256"]
        )
        self.assertEqual(
            first_receipt, second_receipt["supersedes_reconciliation_receipt"]
        )
        after = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("externally_terminal_missing", after["phase"])
        replay = self._apply(binding, second_preview)
        self.assertEqual("already_applied", replay["status"])
        self.assertEqual(second_receipt["receipt_sha256"], replay["receipt"]["receipt_sha256"])

    def test_missing_followup_rechecks_work_lane_terminal_head(self) -> None:
        binding = self._present_binding()
        evidence = self._terminal_source_evidence(binding)
        evidence["terminal_head_sha"] = self.head
        evidence["evidence_sha256"] = checkouts._sha256_json(
            {key: value for key, value in evidence.items() if key != "evidence_sha256"}
        )
        remote = {
            "remote_secured": True,
            "remote_secured_refs": ["refs/remotes/origin/topic"],
            "error": None,
        }
        with (
            patch.object(sources, "source_terminal_evidence", return_value=evidence),
            patch.object(checkouts, "_remote_secured_observation", return_value=remote),
        ):
            first_preview = reconciliation.preview(str(binding["checkout_key"]))
            self.assertTrue(first_preview["safe_to_apply"])
            reconciliation.apply(
                str(binding["checkout_key"]),
                "owner-a",
                str(first_preview["preview_sha256"]),
                int(first_preview["preview_created_at_unix"]),
                reconciliation.CONFIRMATION,
            )
        self._git("worktree", "remove", str(self.checkout))
        tree = self._git("rev-parse", f"{self.head}^{{tree}}").stdout.strip()
        advanced = self._git(
            "commit-tree", tree, "-p", self.head, "-m", "post-closeout branch advance"
        ).stdout.strip()
        self._git("update-ref", "refs/heads/topic", advanced)
        with patch.object(sources, "source_terminal_evidence", return_value=evidence):
            second_preview = reconciliation.preview(str(binding["checkout_key"]))
        self.assertFalse(second_preview["safe_to_apply"])
        self.assertIn(
            "work-lane-head-after-terminal-closeout", second_preview["blockers"]
        )

    def test_missing_followup_uses_current_owner_after_completed_retained_handoff(self) -> None:
        binding = self._present_binding()
        remote = {
            "remote_secured": True,
            "remote_secured_refs": ["refs/remotes/origin/topic"],
            "error": None,
        }
        with patch.object(
            checkouts, "_remote_secured_observation", return_value=remote
        ):
            first_preview = self._preview(binding)
            first = self._apply(binding, first_preview)
        first_receipt = first["receipt"]
        checkout_key = str(binding["checkout_key"])
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE retention SET owner_id='owner-b' WHERE checkout_key=?",
                (checkout_key,),
            )
            connection.commit()
        handoff_preview = checkouts.checkout_owner_handoff_preview(
            str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
            self.head, "topic",
        )
        handoff = checkouts.checkout_owner_handoff_apply(
            str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
            self.head, "topic", handoff_preview["snapshot_sha256"],
            handoff_preview["observed_at_unix"], handoff_preview["confirmation"],
        )
        self.assertEqual("owner-b", handoff["after"]["lifecycle"]["owner_id"])
        self._git("worktree", "remove", str(self.checkout))
        second_preview = self._preview(binding)
        self.assertTrue(second_preview["safe_to_apply"])
        with patch.object(
            sources,
            "source_terminal_evidence",
            side_effect=self._terminal_source_evidence,
        ):
            second = reconciliation.apply(
                checkout_key,
                "owner-b",
                str(second_preview["preview_sha256"]),
                int(second_preview["preview_created_at_unix"]),
                reconciliation.CONFIRMATION,
            )
        self.assertEqual("applied", second["status"])
        receipt = second["receipt"]
        self.assertEqual("owner-b", receipt["owner_id"])
        self.assertEqual(
            "owner-a", receipt["supersedes_reconciliation_receipt"]["owner_id"]
        )
        self.assertEqual(
            first_receipt["receipt_sha256"],
            receipt["supersedes_reconciliation_receipt_sha256"],
        )
        after = checkouts._lifecycle_bindings([checkout_key])[checkout_key]
        self.assertEqual("owner-b", after["owner_id"])
        self.assertEqual("externally_terminal_missing", after["phase"])
        with self.assertRaises(PermissionError):
            reconciliation.apply(
                checkout_key,
                "owner-a",
                str(second_preview["preview_sha256"]),
                int(second_preview["preview_created_at_unix"]),
                reconciliation.CONFIRMATION,
            )

    def test_present_terminal_checkout_blocks_dirty_or_unsecured_head(self) -> None:
        binding = self._present_binding()
        (self.checkout / "dirty.txt").write_text("dirty\n", encoding="utf-8")
        with patch.object(
            checkouts,
            "_remote_secured_observation",
            return_value={
                "remote_secured": False,
                "remote_secured_refs": [],
                "error": None,
            },
        ):
            preview = self._preview(binding)
        self.assertFalse(preview["safe_to_apply"])
        self.assertIn("checkout-dirty", preview["blockers"])
        self.assertIn("checkout-head-not-remote-secured", preview["blockers"])
        current = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("active", current["phase"])

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

    def test_descendant_branch_head_is_rebound_during_terminal_apply(self) -> None:
        binding = self._missing_binding()
        descendant = self._advance_topic_branch()
        preview = self._preview(binding)
        self.assertTrue(preview["safe_to_apply"])
        self.assertEqual("descendant", preview["checkout_observation"]["branch_head_relation"])
        self.assertEqual(descendant, preview["checkout_observation"]["branch_head"])
        result = self._apply(binding, preview)
        self.assertEqual(
            ["lifecycle_phase_transition", "terminal_head_rebind"],
            result["receipt"]["effects"],
        )
        self.assertEqual(
            {"relation": "descendant", "from_head": self.head, "to_head": descendant},
            result["receipt"]["branch_head_rebind"],
        )
        current = checkouts._lifecycle_bindings([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        retention = checkouts._retention_records([str(binding["checkout_key"])])[
            str(binding["checkout_key"])
        ]
        self.assertEqual("externally_terminal_missing", current["phase"])
        self.assertEqual(descendant, current["expected_head"])
        self.assertEqual(descendant, retention["expected_head"])

    def test_diverged_branch_head_still_blocks_terminal_reconciliation(self) -> None:
        binding = self._missing_binding()
        unrelated = self._diverge_topic_branch()
        preview = self._preview(binding)
        self.assertFalse(preview["safe_to_apply"])
        self.assertEqual("diverged", preview["checkout_observation"]["branch_head_relation"])
        self.assertEqual(unrelated, preview["checkout_observation"]["branch_head"])
        self.assertIn("branch-head-drift", preview["blockers"])
        with self.assertRaisesRegex(RuntimeError, "branch-head-drift"):
            self._apply(binding, preview)

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
                "assessment_sha256": assessment["assessment_sha256"],
                "expected_receipt_sha256": "e" * 64,
                "assessment": assessment,
            },
        }
        with (
            patch.object(work_acquire, "_read_state", return_value=record),
            patch.object(
                work_acquire, "_find_terminal_closeout_audit", return_value="f" * 64
            ) as audit_lookup,
        ):
            evidence = sources.work_lane_terminal_evidence(lane_id)
        self.assertEqual(evidence["kind"], "work_lane")
        self.assertEqual(evidence["source_id"], lane_id)
        self.assertEqual(evidence["terminal_state"], "pr_merged")
        self.assertEqual(evidence["lane_receipt_sha256"], "d" * 64)
        self.assertEqual(evidence["assessment_sha256"], assessment["assessment_sha256"])
        self.assertEqual(evidence["terminal_closeout_audit_record_sha256"], "f" * 64)
        audit_lookup.assert_called_once()
        self.assertEqual(
            evidence["evidence_sha256"],
            checkouts._sha256_json(
                {key: value for key, value in evidence.items() if key != "evidence_sha256"}
            ),
        )

    def test_work_lane_source_rejects_terminal_closeout_without_audit(self) -> None:
        lane_id = "d" * 32
        assessment = lane_closeout.assess(
            lane_closeout.LaneCloseoutObservation(
                lane_id=lane_id,
                repository="/tmp/repo",
                workspace="/tmp/worktree",
                branch="feat/example",
                base_revision="a" * 40,
                writer_state="completed",
                task_active=False,
                process_active=False,
                lease_active=True,
                git_dirty=False,
                head_sha="b" * 40,
                remote_head_sha="b" * 40,
                ahead_commits=0,
                behind_commits=0,
                pr_number=1,
                pr_state="merged",
                pr_head_sha="b" * 40,
                merged_sha="b" * 40,
            ),
            observed_at_unix=200,
        )
        record = {
            "lane_id": lane_id,
            "state": "ready",
            "receipt_sha256": "d" * 64,
            "terminal_closeout": {
                "schema_version": 1,
                "kind": "grabowski.work_lane_terminal_closeout",
                "closeout_state": assessment["closeout_state"],
                "assessment_sha256": assessment["assessment_sha256"],
                "expected_receipt_sha256": "e" * 64,
                "assessment": assessment,
            },
        }
        with (
            patch.object(work_acquire, "_read_state", return_value=record),
            patch.object(work_acquire, "_find_terminal_closeout_audit", return_value=None),
            self.assertRaisesRegex(RuntimeError, "terminal closeout audit is missing"),
        ):
            sources.work_lane_terminal_evidence(lane_id)

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

    def test_thread_focus_binds_terminal_work_lane_without_obligation_receipt(self) -> None:
        source_id = "thread-focus-id"
        lane_id = "a" * 32
        lane_root = self.root / "work-lanes"
        lane_root.mkdir()
        (lane_root / f"{lane_id}.json").write_text("{}\n", encoding="utf-8")
        lane_record = {
            "lane_id": lane_id,
            "inputs": {"source": {"kind": "thread_focus", "id": source_id}},
        }
        lane_evidence = {
            "schema_version": 1,
            "kind": "work_lane",
            "source_id": lane_id,
            "terminal_state": "no_change_proven",
            "terminal_head_sha": self.head,
            "assessment_sha256": "b" * 64,
            "terminal_closeout_audit_record_sha256": "c" * 64,
            "evidence_sha256": "d" * 64,
        }
        with (
            patch.object(
                sources.operator_obligation,
                "list_obligations",
                return_value={
                    "scan_truncated": False,
                    "integrity_errors": [],
                    "attention_required": False,
                    "records": [],
                },
            ),
            patch.object(work_acquire, "_state_root", return_value=lane_root),
            patch.object(work_acquire, "_read_state", return_value=lane_record),
            patch.object(
                sources, "work_lane_terminal_evidence", return_value=lane_evidence
            ) as terminal_lane,
        ):
            evidence = sources.thread_focus_terminal_evidence(source_id)

        terminal_lane.assert_called_once_with(lane_id)
        self.assertEqual("completed_without_current_obligation", evidence["terminal_state"])
        self.assertEqual("terminal_work_lanes", evidence["completion_basis"])
        self.assertEqual(lane_id, evidence["work_lanes"][0]["lane_id"])
        self.assertEqual("c" * 64, evidence["work_lanes"][0]["terminal_closeout_audit_record_sha256"])

    def test_thread_focus_rejects_terminal_work_lane_that_requires_continuation(self) -> None:
        source_id = "thread-focus-id"
        lane_id = "a" * 32
        lane_root = self.root / "work-lanes"
        lane_root.mkdir()
        (lane_root / f"{lane_id}.json").write_text("{}\n", encoding="utf-8")
        lane_record = {
            "lane_id": lane_id,
            "inputs": {"source": {"kind": "thread_focus", "id": source_id}},
        }
        with (
            patch.object(
                sources.operator_obligation,
                "list_obligations",
                return_value={
                    "scan_truncated": False,
                    "integrity_errors": [],
                    "attention_required": False,
                    "records": [],
                },
            ),
            patch.object(work_acquire, "_state_root", return_value=lane_root),
            patch.object(work_acquire, "_read_state", return_value=lane_record),
        ):
            for terminal_state in (
                "pr_opened",
                "pr_updated",
                "candidate_adopted",
                "blocked_with_durable_followup",
            ):
                with (
                    self.subTest(terminal_state=terminal_state),
                    patch.object(
                        sources,
                        "work_lane_terminal_evidence",
                        return_value={
                            "schema_version": 1,
                            "kind": "work_lane",
                            "source_id": lane_id,
                            "terminal_state": terminal_state,
                            "terminal_head_sha": self.head,
                            "assessment_sha256": "b" * 64,
                            "terminal_closeout_audit_record_sha256": "c" * 64,
                            "evidence_sha256": "d" * 64,
                        },
                    ),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "terminal but does not establish completion",
                    ),
                ):
                    sources.thread_focus_terminal_evidence(source_id)

    def test_bureau_json_runs_bound_runtime_from_control_root(self) -> None:
        completed = subprocess.CompletedProcess(
            ["bureau"], 0, stdout=json.dumps({"result": {"tasks": []}}), stderr=""
        )
        runtime = {
            "runtime_kind": "managed-manifest",
            "python_launcher": Path("/runtime/python"),
        }
        state_root = self.repo / "coordination"
        with (
            patch.dict(
                sources.os.environ,
                {"GRABOWSKI_BUREAU_COORDINATION_ROOT": str(state_root)},
                clear=False,
            ),
            patch.object(
                sources.bureau_leases, "_contract_runtime", return_value=runtime
            ),
            patch.object(
                sources.bureau_leases, "_assert_contract_runtime_unchanged"
            ) as assert_runtime,
            patch.object(
                sources.bureau_leases, "_open_bound_launcher", return_value=17
            ),
            patch.object(
                sources.bureau_leases, "_safe_environment", return_value={"PATH": "/runtime"}
            ),
            patch.object(sources.os, "close") as close,
            patch.object(sources.subprocess, "run", return_value=completed) as run,
        ):
            payload = sources._bureau_json(
                ["status-projection", "--skip-github"],
                control_root=self.repo,
            )
        self.assertEqual({"result": {"tasks": []}}, payload)
        self.assertEqual(2, assert_runtime.call_count)
        self.assertEqual(
            [
                "/runtime/python",
                "-I",
                "/proc/self/fd/17",
                "--state-root",
                str(state_root),
                "--json",
                "status-projection",
                "--skip-github",
            ],
            run.call_args.args[0],
        )
        self.assertEqual(str(self.repo), run.call_args.kwargs["cwd"])
        self.assertEqual((17,), run.call_args.kwargs["pass_fds"])
        close.assert_called_once_with(17)

    def test_bureau_json_resolves_relative_coordination_root_before_chdir(self) -> None:
        completed = subprocess.CompletedProcess(
            ["bureau"], 0, stdout=json.dumps({"result": {"tasks": []}}), stderr=""
        )
        runtime = {
            "runtime_kind": "managed-manifest",
            "python_launcher": Path("/runtime/python"),
        }
        expected_state_root = Path(os.path.abspath("relative-state-root"))
        with (
            patch.dict(
                sources.os.environ,
                {"GRABOWSKI_BUREAU_COORDINATION_ROOT": "relative-state-root"},
                clear=False,
            ),
            patch.object(
                sources.bureau_leases, "_contract_runtime", return_value=runtime
            ),
            patch.object(
                sources.bureau_leases, "_assert_contract_runtime_unchanged"
            ),
            patch.object(
                sources.bureau_leases, "_open_bound_launcher", return_value=18
            ),
            patch.object(sources.bureau_leases, "_safe_environment", return_value={}),
            patch.object(sources.os, "close"),
            patch.object(sources.subprocess, "run", return_value=completed) as run,
        ):
            sources._bureau_json(
                ["status-projection", "--skip-github"],
                control_root=self.repo,
            )
        argv = run.call_args.args[0]
        self.assertEqual(
            str(expected_state_root), argv[argv.index("--state-root") + 1]
        )
        self.assertEqual(str(self.repo), run.call_args.kwargs["cwd"])

    def test_bureau_task_binds_current_registry_head_and_effective_state(self) -> None:
        task = {"id": "TASK-T001", "state": "planned"}
        raw = json.dumps(task)
        completed = subprocess.CompletedProcess(["git"], 0, stdout=raw, stderr="")
        tree = subprocess.CompletedProcess(["git"], 0, stdout="d" * 40 + "\n", stderr="")
        projection = {
            "schema_version": 1,
            "result": {
                "schema_version": 1,
                "tasks": [
                    {
                        "task_id": "TASK-T001",
                        "effective_state": "verified",
                        "registry_state": "planned",
                        "task_spec_state": "ready",
                    }
                ]
            }
        }
        with (
            patch.object(
                sources.bureau_leases,
                "inspect_bureau_control_checkout",
                return_value={"head": "e" * 40, "control_root": str(self.repo)},
            ),
            patch.object(sources, "_github_json", return_value={"sha": "e" * 40}),
            patch.object(sources, "_bureau_json", return_value=projection),
            patch.object(checkouts, "_git_read", side_effect=[completed, tree]),
        ):
            evidence = sources.bureau_task_terminal_evidence("TASK-T001")
        self.assertEqual("verified", evidence["terminal_state"])
        self.assertEqual("planned", evidence["git_registry_state"])
        self.assertEqual("planned", evidence["projected_registry_state"])
        self.assertEqual("ready", evidence["task_spec_state"])
        self.assertEqual("e" * 40, evidence["registry_commit"])

    def test_bureau_task_rejects_control_revision_change_during_projection(self) -> None:
        task = {"id": "TASK-T001", "state": "planned"}
        completed = subprocess.CompletedProcess(
            ["git"], 0, stdout=json.dumps(task), stderr=""
        )
        projection = {
            "schema_version": 1,
            "result": {
                "schema_version": 1,
                "tasks": [
                    {
                        "task_id": "TASK-T001",
                        "effective_state": "verified",
                        "registry_state": "planned",
                        "task_spec_state": "ready",
                    }
                ],
            },
        }
        before = {"head": "e" * 40, "control_root": str(self.repo)}
        after = {"head": "f" * 40, "control_root": str(self.repo)}
        with (
            patch.object(
                sources.bureau_leases,
                "inspect_bureau_control_checkout",
                side_effect=[before, after],
            ),
            patch.object(sources, "_github_json", return_value={"sha": "e" * 40}),
            patch.object(sources, "_bureau_json", return_value=projection),
            patch.object(checkouts, "_git_read", return_value=completed),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "changed during terminal observation"
            ):
                sources.bureau_task_terminal_evidence("TASK-T001")

    def test_bureau_task_rejects_projection_from_other_registry_revision(self) -> None:
        task = {"id": "TASK-T001", "state": "planned"}
        completed = subprocess.CompletedProcess(
            ["git"], 0, stdout=json.dumps(task), stderr=""
        )
        projection = {
            "schema_version": 1,
            "result": {
                "schema_version": 1,
                "tasks": [
                    {
                        "task_id": "TASK-T001",
                        "effective_state": "verified",
                        "registry_state": "ready",
                        "task_spec_state": "ready",
                    }
                ],
            },
        }
        control = {"head": "e" * 40, "control_root": str(self.repo)}
        with (
            patch.object(
                sources.bureau_leases,
                "inspect_bureau_control_checkout",
                return_value=control,
            ),
            patch.object(sources, "_github_json", return_value={"sha": "e" * 40}),
            patch.object(sources, "_bureau_json", return_value=projection),
            patch.object(checkouts, "_git_read", return_value=completed),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "registry state differs from inspected control revision"
            ):
                sources.bureau_task_terminal_evidence("TASK-T001")

    def test_bureau_task_does_not_fallback_to_terminal_git_state(self) -> None:
        task = {"id": "TASK-T001", "state": "verified"}
        raw = json.dumps(task)
        completed = subprocess.CompletedProcess(["git"], 0, stdout=raw, stderr="")
        projection = {
            "schema_version": 1,
            "result": {
                "schema_version": 1,
                "tasks": [
                    {
                        "task_id": "TASK-T001",
                        "effective_state": "planned",
                        "registry_state": "verified",
                        "task_spec_state": "ready",
                    }
                ]
            }
        }
        with (
            patch.object(
                sources.bureau_leases,
                "inspect_bureau_control_checkout",
                return_value={"head": "e" * 40, "control_root": str(self.repo)},
            ),
            patch.object(sources, "_github_json", return_value={"sha": "e" * 40}),
            patch.object(sources, "_bureau_json", return_value=projection),
            patch.object(checkouts, "_git_read", return_value=completed),
        ):
            with self.assertRaisesRegex(RuntimeError, "not terminal: planned"):
                sources.bureau_task_terminal_evidence("TASK-T001")

    def test_bureau_task_projection_rejects_schema_drift(self) -> None:
        projection = {
            "schema_version": 2,
            "result": {"schema_version": 1, "tasks": []},
        }
        with patch.object(sources, "_bureau_json", return_value=projection):
            with self.assertRaisesRegex(RuntimeError, "envelope schema is unsupported"):
                sources._bureau_task_projection("TASK-T001", control_root=self.repo)

    def test_bureau_task_projection_distinguishes_missing_and_ambiguous(self) -> None:
        missing = {
            "schema_version": 1,
            "result": {"schema_version": 1, "tasks": []},
        }
        duplicate = {
            "schema_version": 1,
            "result": {
                "schema_version": 1,
                "tasks": [
                    {"task_id": "TASK-T001", "effective_state": "verified"},
                    {"task_id": "TASK-T001", "effective_state": "verified"},
                ],
            },
        }
        with patch.object(sources, "_bureau_json", return_value=missing):
            with self.assertRaisesRegex(RuntimeError, "task is missing"):
                sources._bureau_task_projection("TASK-T001", control_root=self.repo)
        with patch.object(sources, "_bureau_json", return_value=duplicate):
            with self.assertRaisesRegex(RuntimeError, "task is ambiguous"):
                sources._bureau_task_projection("TASK-T001", control_root=self.repo)

    def test_bureau_task_projection_rejects_invalid_effective_state_shape(self) -> None:
        projection = {
            "schema_version": 1,
            "result": {
                "schema_version": 1,
                "tasks": [{"task_id": "TASK-T001", "effective_state": None}],
            },
        }
        with patch.object(sources, "_bureau_json", return_value=projection):
            with self.assertRaisesRegex(RuntimeError, "effective state is invalid"):
                sources._bureau_task_projection("TASK-T001", control_root=self.repo)

    def test_bureau_task_projection_allows_missing_task_spec_state(self) -> None:
        projection = {
            "schema_version": 1,
            "result": {
                "schema_version": 1,
                "tasks": [
                    {
                        "task_id": "TASK-T001",
                        "effective_state": "verified",
                        "registry_state": "verified",
                        "task_spec_state": None,
                    }
                ]
            }
        }
        with patch.object(sources, "_bureau_json", return_value=projection):
            observed = sources._bureau_task_projection(
                "TASK-T001", control_root=self.repo
            )
        self.assertEqual("verified", observed["effective_state"])
        self.assertIsNone(observed["task_spec_state"])

    def test_bureau_task_accepts_superseded_effective_state(self) -> None:
        projection = {
            "schema_version": 1,
            "result": {
                "schema_version": 1,
                "tasks": [
                    {
                        "task_id": "TASK-T001",
                        "effective_state": "superseded",
                        "registry_state": "ready",
                        "task_spec_state": "superseded",
                    }
                ]
            }
        }
        with patch.object(sources, "_bureau_json", return_value=projection):
            observed = sources._bureau_task_projection(
                "TASK-T001", control_root=self.repo
            )
        self.assertEqual("superseded", observed["effective_state"])

    def test_github_issue_accepts_historical_github_url_source(self) -> None:
        source_id = "https://github.com/heimgewebe/chronik/issues/299"
        with patch.object(
            sources,
            "_github_json",
            return_value={
                "number": 299,
                "state": "CLOSED",
                "url": source_id,
                "closedAt": "2026-09-01T05:41:54Z",
                "updatedAt": "2026-09-01T05:41:54Z",
            },
        ) as github_read:
            evidence = sources.source_terminal_evidence(
                {"source": {"kind": "github_issue", "id": source_id}}
            )
        self.assertEqual(source_id, evidence["source_id"])
        self.assertEqual("heimgewebe/chronik", evidence["repository"])
        self.assertEqual(299, evidence["issue_number"])
        github_read.assert_called_once_with(
            [
                "issue",
                "view",
                "299",
                "--repo",
                "heimgewebe/chronik",
                "--json",
                "number,state,url,closedAt,updatedAt",
            ]
        )

    def test_github_issue_accepts_bare_repository_number_source(self) -> None:
        source_id = "heimgewebe/bureau#2177"
        with patch.object(
            sources,
            "_github_json",
            return_value={
                "number": 2177,
                "state": "CLOSED",
                "url": "https://github.com/heimgewebe/bureau/issues/2177",
                "closedAt": "2026-08-29T00:00:00Z",
                "updatedAt": "2026-08-29T00:00:00Z",
            },
        ) as github_read:
            evidence = sources.source_terminal_evidence(
                {"source": {"kind": "github_issue", "id": source_id}}
            )
        self.assertEqual(source_id, evidence["source_id"])
        self.assertEqual("heimgewebe/bureau", evidence["repository"])
        self.assertEqual(2177, evidence["issue_number"])
        github_read.assert_called_once_with(
            [
                "issue",
                "view",
                "2177",
                "--repo",
                "heimgewebe/bureau",
                "--json",
                "number,state,url,closedAt,updatedAt",
            ]
        )

    def test_github_issue_url_accepts_one_trailing_slash_only(self) -> None:
        self.assertEqual(
            ("heimgewebe/chronik", 299),
            sources._parse_github_issue_source_id(
                "https://github.com/heimgewebe/chronik/issues/299/"
            ),
        )

    def test_github_issue_url_rejects_ambiguous_variants(self) -> None:
        invalid = (
            "http://github.com/heimgewebe/chronik/issues/299",
            "https://github.com.evil/heimgewebe/chronik/issues/299",
            "https://user@github.com/heimgewebe/chronik/issues/299",
            "https://github.com:443/heimgewebe/chronik/issues/299",
            "https://github.com:/heimgewebe/chronik/issues/299",
            "https://github.com/heimgewebe/chronik/issues/299?",
            "https://github.com/heimgewebe/chronik/issues/299#",
            "https://github.com/heimgewebe/chronik/issues/299?state=closed",
            "https://github.com/heimgewebe/chronik/issues/299#fragment",
            "https://github.com/heimgewebe/chronik/issues/299//",
            "https://github.com/heimgewebe/chronik/issues/299/comments",
            "https://github.com/heimgewebe/chronik/issues/0",
        )
        for source_id in invalid:
            with self.subTest(source_id=source_id):
                with self.assertRaisesRegex(ValueError, "strict github.com issue URL"):
                    sources._parse_github_issue_source_id(source_id)

    def test_github_issue_closed_state_rejects_repository_identity_mismatch(self) -> None:
        with patch.object(
            sources,
            "_github_json",
            return_value={
                "number": 215,
                "state": "CLOSED",
                "url": "https://github.com/heimgewebe/other/issues/215",
                "closedAt": "2026-07-18T00:00:00Z",
                "updatedAt": "2026-07-18T00:00:00Z",
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "identity differs"):
                sources.github_issue_terminal_evidence(
                    "heimgewebe/grabowski#215:T002"
                )

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
