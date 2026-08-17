from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
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

import grabowski_privileged as privileged_client  # noqa: E402


class PrivilegedBrokerPeerTests(unittest.TestCase):
    @staticmethod
    def execution() -> dict[str, object]:
        return {
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }

    SERVICE_CGROUP = (
        "/user.slice/user-1000.slice/user@1000.service/"
        "app.slice/grabowski-operator.service"
    )

    @staticmethod
    def _write_process(
        proc_root: Path,
        pid: int,
        *,
        parent_pid: int,
        starttime_ticks: int,
        cgroup: str,
    ) -> None:
        process = proc_root / str(pid)
        process.mkdir(parents=True, exist_ok=True)
        (process / "cgroup").write_text(f"0::{cgroup}\n", encoding="utf-8")
        fields = ["S", str(parent_pid), *(["0"] * 17), str(starttime_ticks)]
        (process / "stat").write_text(
            f"{pid} (python worker) " + " ".join(fields) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _write_cgroup_members(
        cgroup_root: Path, cgroup: str, members: list[int]
    ) -> None:
        target = cgroup_root / cgroup.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)
        (target / "cgroup.procs").write_text(
            "".join(f"{pid}\n" for pid in members), encoding="utf-8"
        )

    def test_exact_operator_service_main_peer_is_accepted(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root, 1234, parent_pid=50, starttime_ticks=100, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 50, parent_pid=1, starttime_ticks=10, cgroup="/user.slice/user-1000.slice/user@1000.service/init.scope"
            )
            self._write_cgroup_members(cgroup_root, self.SERVICE_CGROUP, [1234])
            with mock.patch.object(
                broker_tool, "_socket_peer_credentials", return_value=(1234, 1000, 1000)
            ):
                result = broker_tool._validate_blockade_lifecycle_peer(
                    self.execution(), proc_root=proc_root, cgroup_root=cgroup_root
                )
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["uid"], 1000)
        self.assertEqual(result["unit"], "grabowski-operator.service")
        self.assertEqual(result["starttime_ticks"], 100)
        self.assertEqual(result["cgroup_process_count"], 1)

    def test_operator_main_peer_remains_valid_with_later_child_present(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root, 1234, parent_pid=50, starttime_ticks=100, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 2345, parent_pid=1234, starttime_ticks=200, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 50, parent_pid=1, starttime_ticks=10, cgroup="/user.slice/user-1000.slice/user@1000.service/init.scope"
            )
            self._write_cgroup_members(cgroup_root, self.SERVICE_CGROUP, [1234, 2345])
            with mock.patch.object(
                broker_tool, "_socket_peer_credentials", return_value=(1234, 1000, 1000)
            ):
                result = broker_tool._validate_blockade_lifecycle_peer(
                    self.execution(), proc_root=proc_root, cgroup_root=cgroup_root
                )
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["cgroup_process_count"], 2)

    def test_equal_oldest_start_ticks_fail_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root,
                1234,
                parent_pid=50,
                starttime_ticks=100,
                cgroup=self.SERVICE_CGROUP,
            )
            self._write_process(
                proc_root,
                2345,
                parent_pid=1234,
                starttime_ticks=100,
                cgroup=self.SERVICE_CGROUP,
            )
            self._write_process(
                proc_root,
                50,
                parent_pid=1,
                starttime_ticks=10,
                cgroup=(
                    "/user.slice/user-1000.slice/user@1000.service/"
                    "init.scope"
                ),
            )
            self._write_cgroup_members(
                cgroup_root, self.SERVICE_CGROUP, [1234, 2345]
            )
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1000, 1000),
            ):
                with self.assertRaisesRegex(PermissionError, "ambiguous"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(),
                        proc_root=proc_root,
                        cgroup_root=cgroup_root,
                    )

    def test_same_service_child_peer_is_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root, 1234, parent_pid=50, starttime_ticks=100, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 2345, parent_pid=1234, starttime_ticks=200, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 50, parent_pid=1, starttime_ticks=10, cgroup="/user.slice/user-1000.slice/user@1000.service/init.scope"
            )
            self._write_cgroup_members(cgroup_root, self.SERVICE_CGROUP, [1234, 2345])
            with mock.patch.object(
                broker_tool, "_socket_peer_credentials", return_value=(2345, 1000, 1000)
            ):
                with self.assertRaisesRegex(PermissionError, "main process"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(), proc_root=proc_root, cgroup_root=cgroup_root
                    )

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

    def test_blockade_lifecycle_client_preserves_operator_socket_peer(self) -> None:
        response = json.dumps(
            {
                "returncode": 0,
                "timed_out": False,
                "lifecycle": {"operation": "observe", "state": "absent_unproven"},
            },
            sort_keys=True,
        ).encode("utf-8")

        class FakeSocket:
            def __init__(self) -> None:
                self.connected: str | None = None
                self.sent = b""
                self.responses = [response, b""]

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout: int) -> None:
                pass

            def connect(self, path: str) -> None:
                self.connected = path

            def sendall(self, payload: bytes) -> None:
                self.sent += payload

            def shutdown(self, _how: int) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                return self.responses.pop(0)

        fake = FakeSocket()
        payload = {
            "operation": "observe",
            "transaction_id": "direct-peer-test",
            "expected_record_sha256": "0" * 64,
            "expected_marker_file_sha256": "0" * 64,
        }
        with (
            mock.patch.object(
                privileged_client,
                "grabowski_privileged_broker_status",
                return_value={"ready": True},
            ),
            mock.patch.object(privileged_client.socket, "socket", return_value=fake),
            mock.patch.object(privileged_client.subprocess, "run") as subprocess_run,
            mock.patch.object(privileged_client, "_write_power_reference") as write_reference,
            mock.patch.object(privileged_client, "_append_operator_audit"),
        ):
            result = privileged_client.run_blockade_lifecycle_reference(
                payload, justification="direct socket identity test"
            )
        subprocess_run.assert_not_called()
        write_reference.assert_not_called()
        self.assertEqual(fake.connected, str(privileged_client.BROKER_SOCKET))
        sent = json.loads(fake.sent.decode("utf-8"))
        self.assertEqual(sent["action"], privileged_client.BLOCKADE_LIFECYCLE_ACTION)
        self.assertEqual(
            sent["target"],
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["broker_client_returncode"], 0)

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
