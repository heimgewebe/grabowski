from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from grabowski_operator_fence import STATUS_KIND
import grabowski_operator_fence_rpc as rpc
import grabowski_operator_fence_shadow as shadow


class FakeClient:
    response: dict[str, object] = {}
    error: BaseException | None = None
    calls: list[dict[str, object]] = []
    kwargs: list[dict[str, object]] = []

    def __init__(self, **kwargs: object) -> None:
        type(self).kwargs.append(dict(kwargs))

    def call(self, request: dict[str, object]) -> dict[str, object]:
        type(self).calls.append(dict(request))
        if type(self).error is not None:
            raise type(self).error
        return dict(type(self).response)


class OperatorFenceShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "shadow.json"
        self.snapshot = self.root / "shadow-status.json"
        FakeClient.response = {}
        FakeClient.error = None
        FakeClient.calls = []
        FakeClient.kwargs = []

    def write_config(
        self,
        *,
        mode: str = "shadow",
        peer_id: str = "grabowski",
    ) -> None:
        self.config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": shadow.CONFIG_KIND,
                    "mode": mode,
                    "host": "heimberry",
                    "remote_user": "operator-fence",
                    "peer_id": peer_id,
                    "known_hosts_path": str(self.root / "known_hosts"),
                    "identity_file": str(self.root / "identity"),
                    "host_key_alias": "heimberry",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(self.config, 0o600)

    @staticmethod
    def ok_status(
        *,
        generation: int = 3,
        writer: object = None,
        inflight: object = None,
        clock_regressed: bool = False,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": rpc.RESPONSE_KIND,
            "request_id": "ignored-by-fake",
            "peer_id": "grabowski",
            "ok": True,
            "result": {
                "schema_version": 1,
                "kind": STATUS_KIND,
                "observed_at_unix": 100,
                "instance_id": "instance-a",
                "generation": generation,
                "fencing_mark": {"instance_id": "instance-a", "generation": generation},
                "clock_regressed": clock_regressed,
                "writer": writer,
                "inflight": inflight,
                "last_settlement": None,
                "last_event": None,
            },
            "error": None,
        }

    def refresh(self, *, observed_at_unix: int = 100) -> dict[str, object]:
        return shadow.refresh_snapshot(
            config_path=self.config,
            snapshot_path=self.snapshot,
            client_factory=FakeClient,
            observed_at_unix=observed_at_unix,
        )

    def observe(self, *, observed_at_unix: int = 100) -> dict[str, object]:
        return shadow.observe(
            tool_name="grabowski_git",
            arguments_sha256="a" * 64,
            config_path=self.config,
            snapshot_path=self.snapshot,
            observed_at_unix=observed_at_unix,
        )

    def test_absent_config_is_disabled_and_performs_no_rpc(self) -> None:
        refreshed = self.refresh()
        observed = self.observe()
        self.assertEqual(refreshed["status"], "disabled")
        self.assertEqual(observed["status"], "disabled")
        self.assertEqual(observed["decision"], "not_observed")
        self.assertEqual(FakeClient.calls, [])

    def test_refresh_is_status_only_unique_and_snapshot_is_private(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        first = self.refresh()
        second = self.refresh(observed_at_unix=101)
        self.assertEqual(first["authority_status"], "observed")
        self.assertEqual(second["authority_status"], "observed")
        self.assertEqual(len(FakeClient.calls), 2)
        self.assertEqual([call["operation"] for call in FakeClient.calls], ["status", "status"])
        self.assertEqual([call["arguments"] for call in FakeClient.calls], [{}, {}])
        self.assertNotEqual(FakeClient.calls[0]["request_id"], FakeClient.calls[1]["request_id"])
        self.assertEqual(FakeClient.kwargs[0]["timeout_seconds"], shadow.REFRESH_TIMEOUT_SECONDS)
        self.assertEqual(stat.S_IMODE(self.snapshot.stat().st_mode), 0o600)

    def test_interceptor_observation_reads_snapshot_without_network(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh()
        before = len(FakeClient.calls)
        result = self.observe(observed_at_unix=104)
        self.assertEqual(len(FakeClient.calls), before)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["decision"], "would_acquire")
        self.assertEqual(result["generation"], 3)
        self.assertEqual(result["instance_id"], "instance-a")
        self.assertEqual(result["snapshot_age_seconds"], 4)

    def test_writer_state_matches_real_acquire_semantics(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status(
            writer={"owner_id": "grabowski", "lease_active": True}
        )
        self.refresh()
        same = self.observe()
        self.assertEqual(same["decision"], "would_continue")
        self.assertEqual(same["reason"], "same_writer")

        FakeClient.response = self.ok_status(
            writer={"owner_id": "der-kleine-maulwurf", "lease_active": True}
        )
        self.refresh(observed_at_unix=101)
        other = self.observe(observed_at_unix=101)
        self.assertEqual(other["decision"], "would_deny")
        self.assertEqual(other["reason"], "writer_active")

        FakeClient.response = self.ok_status(
            writer={"owner_id": "der-kleine-maulwurf", "lease_active": False}
        )
        self.refresh(observed_at_unix=102)
        expired = self.observe(observed_at_unix=102)
        self.assertEqual(expired["decision"], "would_acquire")
        self.assertEqual(expired["reason"], "writer_idle_or_expired")

    def test_inflight_and_clock_regression_are_would_deny(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status(
            writer={"owner_id": "grabowski", "lease_active": False},
            inflight={"operation_id": "unknown-effect"},
        )
        self.refresh()
        inflight = self.observe()
        self.assertEqual(inflight["decision"], "would_deny")
        self.assertEqual(inflight["reason"], "inflight_present")

        FakeClient.response = self.ok_status(clock_regressed=True)
        self.refresh(observed_at_unix=101)
        regressed = self.observe(observed_at_unix=101)
        self.assertEqual(regressed["decision"], "would_deny")
        self.assertEqual(regressed["reason"], "clock_regressed")

    def test_transport_failure_replaces_old_truth_with_unavailable_snapshot(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh()
        self.assertEqual(self.observe()["decision"], "would_acquire")

        FakeClient.error = rpc.OperatorFenceRpcError("ssh_transport_failed")
        refreshed = self.refresh(observed_at_unix=101)
        observed = self.observe(observed_at_unix=101)
        self.assertEqual(refreshed["authority_status"], "unavailable")
        self.assertEqual(observed["status"], "unavailable")
        self.assertEqual(observed["decision"], "unavailable")

    def test_stale_snapshot_and_config_drift_fail_closed_as_evidence(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh(observed_at_unix=100)
        stale = self.observe(
            observed_at_unix=100 + shadow.MAX_SNAPSHOT_AGE_SECONDS + 1
        )
        self.assertEqual(stale["status"], "snapshot_error")
        self.assertEqual(stale["decision"], "unavailable")
        self.assertEqual(stale["reason"], "snapshot_stale")

        self.write_config(peer_id="der-kleine-maulwurf")
        drift = self.observe(observed_at_unix=100)
        self.assertEqual(drift["status"], "snapshot_error")
        self.assertEqual(drift["reason"], "snapshot_config_drift")

    def test_invalid_or_mutable_config_never_uses_snapshot_as_authority(self) -> None:
        self.write_config(mode="enforce")
        unsupported = self.observe()
        self.assertEqual(unsupported["status"], "config_error")
        self.assertEqual(unsupported["reason"], "unsupported_mode")
        self.assertEqual(FakeClient.calls, [])

        self.write_config()
        os.chmod(self.config, 0o622)
        unsafe = self.observe()
        self.assertEqual(unsafe["status"], "config_error")
        self.assertEqual(unsafe["reason"], "unsafe_file")
        self.assertEqual(FakeClient.calls, [])

    def test_invalid_observation_time_is_rejected(self) -> None:
        self.write_config()
        with self.assertRaises(shadow.OperatorFenceShadowError):
            self.observe(observed_at_unix=True)
        with self.assertRaises(shadow.OperatorFenceShadowError):
            shadow.refresh_snapshot(
                config_path=self.config,
                snapshot_path=self.snapshot,
                client_factory=FakeClient,
                observed_at_unix=-1,
            )

    def test_symlink_snapshot_parent_is_rejected(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        link_parent = self.root / "snapshot-link"
        link_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(shadow.OperatorFenceShadowError) as unsafe:
            shadow.refresh_snapshot(
                config_path=self.config,
                snapshot_path=link_parent / "snapshot.json",
                client_factory=FakeClient,
                observed_at_unix=100,
            )
        self.assertEqual(str(unsafe.exception), "unsafe_snapshot_parent")

    def test_snapshot_tamper_is_detected(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh()
        value = json.loads(self.snapshot.read_text(encoding="utf-8"))
        value["generation"] = 999
        self.snapshot.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(self.snapshot, 0o600)
        result = self.observe()
        self.assertEqual(result["status"], "snapshot_error")
        self.assertEqual(result["reason"], "snapshot_digest_mismatch")


if __name__ == "__main__":
    unittest.main()
