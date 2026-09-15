from __future__ import annotations

from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

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

import grabowski_resources as resources


class ResourceCommitPreconditionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "state" / "resources.sqlite3"
        self.resource_db_patch = mock.patch.object(resources, "RESOURCE_DB", self.database)
        self.resource_db_patch.start()
        # Initialize the canonical resource schema before a second connection
        # deliberately holds the writer slot.
        seed = resources.acquire_resources(
            "operator:commit-fence-seed",
            ["component:commit-fence-seed"],
            purpose="initialize commit-fence test store",
            ttl_seconds=120,
        )
        resources.release_resources(
            seed["owner_id"],
            [item["resource_key"] for item in seed["leases"]],
        )

    def tearDown(self) -> None:
        self.resource_db_patch.stop()
        self.temporary.cleanup()

    def _hold_writer_lock(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=5,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("BEGIN IMMEDIATE")
        return connection

    def test_acquire_rechecks_commit_precondition_after_waiting_for_writer_lock(self) -> None:
        blocker = self._hold_writer_lock()
        preflight_reached = threading.Event()
        authority_terminal = threading.Event()
        finished = threading.Event()
        errors: list[BaseException] = []
        key = "component:commit-fence-acquire"

        def commit_precondition() -> None:
            if authority_terminal.is_set():
                raise RuntimeError("bureau-run-terminal")

        def contract(*args, **kwargs):
            preflight_reached.set()
            return None

        def writer() -> None:
            try:
                resources.acquire_resources(
                    "bureau-run:BUR-RUN-20260914T120000Z-0123456789",
                    [key],
                    purpose="commit-bound acquisition",
                    ttl_seconds=120,
                    metadata={
                        "task_id": "TEST-T084",
                        "run_id": "BUR-RUN-20260914T120000Z-0123456789",
                        "claim_intent_sha256": "a" * 64,
                    },
                    _commit_precondition=commit_precondition,
                )
            except BaseException as exc:  # preserve the exact writer failure for assertions
                errors.append(exc)
            finally:
                finished.set()

        with mock.patch.object(
            resources.bureau_leases,
            "enforce_bureau_lease_contract",
            side_effect=contract,
        ):
            thread = threading.Thread(target=writer, daemon=True)
            thread.start()
            self.assertTrue(preflight_reached.wait(2), "writer did not finish preflight")
            self.assertFalse(finished.wait(0.1), "writer did not wait on BEGIN IMMEDIATE")
            authority_terminal.set()
            blocker.rollback()
            blocker.close()
            self.assertTrue(finished.wait(2), "writer did not finish after lock release")
            thread.join(timeout=2)

        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], RuntimeError)
        self.assertEqual("bureau-run-terminal", str(errors[0]))
        self.assertIsNone(resources.inspect_resource(key))

    def test_same_owner_rebind_rechecks_commit_precondition_after_waiting(self) -> None:
        owner = "bureau-run:BUR-RUN-20260914T120000Z-abcdef0123"
        key = "component:commit-fence-rebind"
        metadata = {
            "task_id": "TEST-T084",
            "run_id": "BUR-RUN-20260914T120000Z-abcdef0123",
            "claim_intent_sha256": "b" * 64,
        }
        with mock.patch.object(resources, "_now", return_value=100):
            acquired = resources.acquire_resources(
                owner,
                [key],
                purpose="commit-bound rebind",
                ttl_seconds=30,
                metadata=metadata,
            )
        original = acquired["leases"][0]
        snapshot = {field: original[field] for field in resources.LEASE_SNAPSHOT_KEYS}

        blocker = self._hold_writer_lock()
        authority_terminal = threading.Event()
        started = threading.Event()
        finished = threading.Event()
        errors: list[BaseException] = []

        def commit_precondition() -> None:
            if authority_terminal.is_set():
                raise RuntimeError("bureau-run-terminal")

        def writer() -> None:
            started.set()
            try:
                with mock.patch.object(resources, "_now", return_value=200):
                    resources.rebind_same_owner_resources(
                        owner,
                        [key],
                        purpose="commit-bound rebind",
                        ttl_seconds=120,
                        metadata=metadata,
                        expected_current_leases=[snapshot],
                        expected_original_leases=[snapshot],
                        _commit_precondition=commit_precondition,
                    )
            except BaseException as exc:
                errors.append(exc)
            finally:
                finished.set()

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        self.assertTrue(started.wait(2), "rebind writer did not start")
        self.assertFalse(finished.wait(0.1), "rebind writer did not wait on BEGIN IMMEDIATE")
        authority_terminal.set()
        blocker.rollback()
        blocker.close()
        self.assertTrue(finished.wait(2), "rebind writer did not finish after lock release")
        thread.join(timeout=2)

        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], RuntimeError)
        self.assertEqual("bureau-run-terminal", str(errors[0]))
        with resources._database() as connection:
            row = connection.execute(
                "SELECT acquired_at_unix, updated_at_unix, expires_at_unix "
                "FROM leases WHERE resource_key=?",
                (key,),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(snapshot["acquired_at_unix"], row["acquired_at_unix"])
        self.assertEqual(snapshot["updated_at_unix"], row["updated_at_unix"])
        self.assertEqual(snapshot["expires_at_unix"], row["expires_at_unix"])


if __name__ == "__main__":
    unittest.main()
