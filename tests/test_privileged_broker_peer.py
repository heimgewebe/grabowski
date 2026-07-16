from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
MODULE_PATH = ROOT / "tools" / "grabowski_privileged_broker.py"
SPEC = importlib.util.spec_from_file_location(
    "grabowski_privileged_broker_peer_test", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("privileged broker tool could not be loaded")
broker_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker_tool)


class PrivilegedBrokerPeerTests(unittest.TestCase):
    @staticmethod
    def execution() -> dict[str, object]:
        return {
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }

    def test_exact_operator_service_peer_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc_root = Path(raw)
            peer = proc_root / "1234"
            peer.mkdir()
            (peer / "cgroup").write_text(
                "0::/user.slice/user-1000.slice/user@1000.service/"
                "app.slice/grabowski-operator.service\n",
                encoding="utf-8",
            )
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1000, 1000),
            ):
                result = broker_tool._validate_blockade_lifecycle_peer(
                    self.execution(), proc_root=proc_root
                )
        self.assertEqual(result["uid"], 1000)
        self.assertEqual(result["unit"], "grabowski-operator.service")

    def test_same_uid_tmux_peer_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc_root = Path(raw)
            peer = proc_root / "1234"
            peer.mkdir()
            (peer / "cgroup").write_text(
                "0::/user.slice/user-1000.slice/session-9.scope\n",
                encoding="utf-8",
            )
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1000, 1000),
            ):
                with self.assertRaisesRegex(
                    PermissionError, "outside the operator service"
                ):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(), proc_root=proc_root
                    )

    @staticmethod
    def reference() -> dict[str, object]:
        return {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "action": "operator_blockade_lifecycle",
            "target": "{}",
        }

    @staticmethod
    def lifecycle_execution() -> dict[str, object]:
        return {
            "mode": "blockade-marker-lifecycle",
            "internal_action": "blockade-marker-migrate",
            "operation": "migrate",
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }

    def test_lifecycle_audit_intent_precedes_mutation_and_completion(self) -> None:
        events: list[str] = []
        records: list[dict[str, object]] = []

        def append(record: dict[str, object]) -> None:
            records.append(dict(record))
            events.append("audit:" + str(record["phase"]))

        def execute(_execution: dict[str, object]) -> dict[str, object]:
            events.append("mutation")
            return {"operation": "migrate", "receipt_sha256": "c" * 64}

        with (
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                return_value={
                    "pid": 1,
                    "uid": 1000,
                    "gid": 1000,
                    "cgroup": "/grabowski-operator.service",
                    "unit": "grabowski-operator.service",
                },
            ),
            mock.patch.object(broker_tool, "claim_once", return_value=None),
            mock.patch.object(broker_tool, "append_audit", side_effect=append),
            mock.patch.object(broker_tool, "execute_lifecycle", side_effect=execute),
            redirect_stdout(io.StringIO()),
        ):
            result = broker_tool._run_blockade_lifecycle(
                self.reference(), self.lifecycle_execution()
            )

        self.assertEqual(result, 0)
        self.assertEqual(events, ["audit:intent", "mutation", "audit:complete"])
        self.assertEqual(records[1]["intent_record_sha256"], records[0]["record_sha256"])

    def test_lifecycle_failure_is_audited_after_durable_intent(self) -> None:
        events: list[str] = []
        records: list[dict[str, object]] = []

        def append(record: dict[str, object]) -> None:
            records.append(dict(record))
            events.append("audit:" + str(record["phase"]))

        def execute(_execution: dict[str, object]) -> dict[str, object]:
            events.append("mutation")
            raise PermissionError("injected lifecycle failure")

        with (
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                return_value={
                    "pid": 1,
                    "uid": 1000,
                    "gid": 1000,
                    "cgroup": "/grabowski-operator.service",
                    "unit": "grabowski-operator.service",
                },
            ),
            mock.patch.object(broker_tool, "claim_once", return_value=None),
            mock.patch.object(broker_tool, "append_audit", side_effect=append),
            mock.patch.object(broker_tool, "execute_lifecycle", side_effect=execute),
        ):
            with self.assertRaisesRegex(PermissionError, "injected"):
                broker_tool._run_blockade_lifecycle(
                    self.reference(), self.lifecycle_execution()
                )

        self.assertEqual(events, ["audit:intent", "mutation", "audit:failure"])
        self.assertEqual(records[1]["intent_record_sha256"], records[0]["record_sha256"])
        self.assertEqual(records[1]["error_type"], "PermissionError")

    def test_lifecycle_intent_failure_prevents_mutation(self) -> None:
        execute = mock.Mock()
        with (
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                return_value={
                    "pid": 1,
                    "uid": 1000,
                    "gid": 1000,
                    "cgroup": "/grabowski-operator.service",
                    "unit": "grabowski-operator.service",
                },
            ),
            mock.patch.object(broker_tool, "claim_once", return_value=None),
            mock.patch.object(
                broker_tool,
                "append_audit",
                side_effect=OSError("audit unavailable"),
            ),
            mock.patch.object(broker_tool, "execute_lifecycle", execute),
        ):
            with self.assertRaisesRegex(OSError, "audit unavailable"):
                broker_tool._run_blockade_lifecycle(
                    self.reference(), self.lifecycle_execution()
                )
        execute.assert_not_called()

    def test_wrong_uid_and_unobservable_cgroup_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc_root = Path(raw)
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1001, 1001),
            ):
                with self.assertRaisesRegex(PermissionError, "UID"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(), proc_root=proc_root
                    )
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1000, 1000),
            ):
                with self.assertRaisesRegex(PermissionError, "not observable"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(), proc_root=proc_root
                    )


if __name__ == "__main__":
    unittest.main()
