from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from grabowski_operator_fence import STATUS_KIND
import grabowski_operator_fence_rpc as rpc
import grabowski_operator_fence_shadow as shadow
import grabowski_operator_fence_shadow_refresh as refresh


class FakeClient:
    response: dict[str, object] = {}
    error: BaseException | None = None
    constructor_error: BaseException | None = None
    calls: list[dict[str, object]] = []
    kwargs: list[dict[str, object]] = []

    def __init__(self, **kwargs: object) -> None:
        if type(self).constructor_error is not None:
            raise type(self).constructor_error
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
        FakeClient.constructor_error = None
        FakeClient.calls = []
        FakeClient.kwargs = []
        shadow._JSON_CACHE.clear()

    def config_value(
        self,
        *,
        mode: str = "shadow",
        peer_id: str = "grabowski",
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": shadow.CONFIG_KIND,
            "mode": mode,
            "host": "heimberry",
            "remote_user": "operator-fence",
            "peer_id": peer_id,
            "known_hosts_path": str(self.root / "known_hosts"),
            "identity_file": str(self.root / "identity"),
            "host_key_alias": "heimberry",
        }

    def write_config(
        self,
        *,
        mode: str = "shadow",
        peer_id: str = "grabowski",
        compact: bool = False,
    ) -> None:
        value = self.config_value(mode=mode, peer_id=peer_id)
        payload = (
            json.dumps(value, sort_keys=True, separators=(",", ":"))
            if compact
            else json.dumps(value, sort_keys=True, indent=2)
        )
        self.config.write_text(payload + "\n", encoding="utf-8")
        os.chmod(self.config, 0o600)
        shadow._JSON_CACHE.clear()

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
        return refresh.refresh_snapshot(
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

    def mutate_snapshot(self, **updates: object) -> None:
        value = json.loads(self.snapshot.read_text(encoding="utf-8"))
        value.update(updates)
        material = dict(value)
        material.pop("snapshot_sha256", None)
        value["snapshot_sha256"] = shadow._sha256_json(material)
        self.snapshot.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.chmod(self.snapshot, 0o600)
        shadow._JSON_CACHE.clear()

    def test_absent_config_is_disabled_unlinks_snapshot_and_performs_no_rpc(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh()
        self.assertTrue(self.snapshot.exists())
        self.config.unlink()
        shadow._JSON_CACHE.clear()
        refreshed = self.refresh(observed_at_unix=101)
        observed = self.observe(observed_at_unix=101)
        self.assertEqual(refreshed["status"], "disabled")
        self.assertFalse(self.snapshot.exists())
        self.assertEqual(observed["status"], "disabled")
        self.assertEqual(observed["decision"], "not_observed")
        before = len(FakeClient.calls)
        self.write_config()
        reenabled = self.observe(observed_at_unix=102)
        self.assertEqual(reenabled["status"], "snapshot_missing")
        self.assertEqual(len(FakeClient.calls), before)

    def test_refresh_is_status_only_unique_and_snapshot_is_private(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        with patch.object(refresh.os, "chmod", side_effect=AssertionError("path chmod forbidden")):
            first = self.refresh()
        second = self.refresh(observed_at_unix=101)
        self.assertEqual(first["authority_status"], "observed")
        self.assertEqual(second["authority_status"], "observed")
        self.assertEqual(len(FakeClient.calls), 2)
        self.assertEqual([call["operation"] for call in FakeClient.calls], ["status", "status"])
        self.assertEqual([call["arguments"] for call in FakeClient.calls], [{}, {}])
        self.assertNotEqual(FakeClient.calls[0]["request_id"], FakeClient.calls[1]["request_id"])
        self.assertEqual(FakeClient.kwargs[0]["timeout_seconds"], refresh.REFRESH_TIMEOUT_SECONDS)
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

    def test_config_digest_is_canonical_not_raw_json_format(self) -> None:
        self.write_config(compact=False)
        FakeClient.response = self.ok_status()
        self.refresh(observed_at_unix=100)
        self.write_config(compact=True)
        observed = self.observe(observed_at_unix=100)
        self.assertEqual(observed["status"], "observed")
        self.assertNotEqual(observed["reason"], "snapshot_config_drift")

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

    def test_transport_and_factory_failures_replace_old_truth_with_unavailable(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh()
        FakeClient.error = rpc.OperatorFenceRpcError("ssh_transport_failed")
        failed = self.refresh(observed_at_unix=101)
        self.assertEqual(failed["authority_status"], "unavailable")
        self.assertEqual(self.observe(observed_at_unix=101)["decision"], "unavailable")

        FakeClient.error = None
        FakeClient.constructor_error = TypeError("bad client contract")
        failed_factory = self.refresh(observed_at_unix=102)
        self.assertEqual(failed_factory["authority_status"], "unavailable")
        self.assertEqual(self.observe(observed_at_unix=102)["decision"], "unavailable")

    def test_stale_future_and_config_drift_fail_closed_as_evidence(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh(observed_at_unix=100)
        future = self.observe(observed_at_unix=99)
        self.assertEqual(future["status"], "snapshot_error")
        self.assertEqual(future["reason"], "snapshot_from_future")
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

    def test_config_requires_exact_0600_and_valid_contract(self) -> None:
        self.write_config(mode="enforce")
        unsupported = self.observe()
        self.assertEqual(unsupported["status"], "config_error")
        self.assertEqual(unsupported["reason"], "unsupported_mode")
        self.assertEqual(FakeClient.calls, [])

        self.write_config()
        os.chmod(self.config, 0o644)
        shadow._JSON_CACHE.clear()
        readable = self.observe()
        self.assertEqual(readable["status"], "config_error")
        self.assertEqual(readable["reason"], "unsafe_file")

        self.write_config()
        os.chmod(self.config, 0o622)
        shadow._JSON_CACHE.clear()
        unsafe = self.observe()
        self.assertEqual(unsafe["status"], "config_error")
        self.assertEqual(unsafe["reason"], "unsafe_file")

    def test_invalid_observation_inputs_and_time_are_rejected(self) -> None:
        self.write_config()
        for tool, digest in (("", "a" * 64), ("grabowski_git", "nope")):
            with self.assertRaises(shadow.OperatorFenceShadowError):
                shadow.observe(
                    tool_name=tool,
                    arguments_sha256=digest,
                    config_path=self.config,
                    snapshot_path=self.snapshot,
                    observed_at_unix=100,
                )
        with self.assertRaises(shadow.OperatorFenceShadowError):
            self.observe(observed_at_unix=True)
        with self.assertRaises(shadow.OperatorFenceShadowError):
            refresh.refresh_snapshot(
                config_path=self.config,
                snapshot_path=self.snapshot,
                client_factory=FakeClient,
                observed_at_unix=-1,
            )

    def test_symlink_and_world_writable_snapshot_parent_are_rejected(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        link_parent = self.root / "snapshot-link"
        link_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(shadow.OperatorFenceShadowError) as unsafe:
            refresh.refresh_snapshot(
                config_path=self.config,
                snapshot_path=link_parent / "snapshot.json",
                client_factory=FakeClient,
                observed_at_unix=100,
            )
        self.assertEqual(str(unsafe.exception), "unsafe_snapshot_parent")

        writable_parent = self.root / "world-writable"
        writable_parent.mkdir()
        os.chmod(writable_parent, 0o777)
        with self.assertRaises(shadow.OperatorFenceShadowError) as writable:
            refresh.refresh_snapshot(
                config_path=self.config,
                snapshot_path=writable_parent / "snapshot.json",
                client_factory=FakeClient,
                observed_at_unix=100,
            )
        self.assertEqual(str(writable.exception), "unsafe_snapshot_parent")

    def test_snapshot_tamper_and_invalid_field_types_are_detected(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh()
        value = json.loads(self.snapshot.read_text(encoding="utf-8"))
        value["generation"] = 999
        self.snapshot.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(self.snapshot, 0o600)
        shadow._JSON_CACHE.clear()
        tampered = self.observe()
        self.assertEqual(tampered["status"], "snapshot_error")
        self.assertEqual(tampered["reason"], "snapshot_digest_mismatch")

        self.refresh(observed_at_unix=101)
        self.mutate_snapshot(inflight_present=1)
        invalid_bool = self.observe(observed_at_unix=101)
        self.assertEqual(invalid_bool["status"], "snapshot_error")
        self.assertEqual(invalid_bool["reason"], "invalid_snapshot_boolean")

        self.refresh(observed_at_unix=102)
        self.mutate_snapshot(generation=True)
        invalid_generation = self.observe(observed_at_unix=102)
        self.assertEqual(invalid_generation["reason"], "invalid_snapshot_generation")

    def test_observation_hash_covers_final_material_and_error_factory_schema_matches(self) -> None:
        self.write_config()
        FakeClient.response = self.ok_status()
        self.refresh()
        observed = self.observe()
        material = dict(observed)
        claimed = material.pop("observation_sha256")
        self.assertEqual(shadow._sha256_json(material), claimed)
        self.assertIn("does_not_establish", material)

        fallback = shadow.observation_from_error(
            tool_name="grabowski_git",
            arguments_sha256="a" * 64,
            error=RuntimeError("offline"),
        )
        self.assertEqual(set(fallback), set(observed))
        fallback_material = dict(fallback)
        fallback_claimed = fallback_material.pop("observation_sha256")
        self.assertEqual(shadow._sha256_json(fallback_material), fallback_claimed)

    def test_cli_exit_codes_distinguish_disabled_unavailable_and_error(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(
                refresh.main(["refresh", "--config", str(self.config), "--snapshot", str(self.snapshot)]),
                0,
            )
        with patch.object(
            refresh,
            "refresh_snapshot",
            return_value={
                "schema_version": 1,
                "kind": shadow.SNAPSHOT_KIND,
                "authority_status": "unavailable",
            },
        ):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(refresh.main(["refresh"]), 2)
        with patch.object(
            refresh,
            "refresh_snapshot",
            side_effect=shadow.OperatorFenceShadowError("broken"),
        ):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(refresh.main(["refresh"]), 1)


if __name__ == "__main__":
    unittest.main()
