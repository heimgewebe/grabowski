"""Provider-free, fail-closed regressions for a separate-unit RAB root controller.

No root unit, ChatGPT credentials or Codex model process is started.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "grabowski_rab_root_arm_controller.py"
)
_SPEC = importlib.util.spec_from_file_location("rab_root_arm_test_source", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
controller = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(controller)


def _pair() -> dict:
    return {
        "schema_version": 2,
        "kind": "rab.root_controlled_separate_arms",
        "epoch_sha256": "a" * 64,
        "plan_sha256": controller._FROZEN_PLAN_SHA256,
        "pair_id": "six-case-testpair",
        "provider": "openai-codex-cli",
        "mode": "chatgpt_subscription",
        "model": "gpt-6-astra",
        "reasoning": "medium",
        "max_exec_per_arm": 1,
        "max_wall_seconds": 300,
        "installed_sha256": {
            key: "c" * 64 for key in ("controller", "core", "runner", "codex", "mcp")
        },
        "positions": [
            {
                "index": 0,
                "arm": "baseline",
                "slot_id": "1" * 64,
                "request_sha256": "2" * 64,
            },
            {
                "index": 1,
                "arm": "treatment",
                "slot_id": "3" * 64,
                "request_sha256": "4" * 64,
            },
        ],
    }


class RootArmPolicyTests(unittest.TestCase):
    def test_pair_has_two_independent_units_not_shared_mainpid(self) -> None:
        p = controller._pair_policy(_pair())
        first, second = controller._unit(p, 0), controller._unit(p, 1)
        self.assertNotEqual(first, second)
        self.assertTrue(first.endswith(".service") and second.endswith(".service"))
        self.assertNotEqual(controller._token(p, 0), controller._token(p, 1))

    def test_subscription_contract_fails_closed(self) -> None:
        for key, value in (
            ("provider", "openai-api-payg"),
            ("mode", "payg"),
            ("model", "gpt-6.1-sol"),
            ("reasoning", "high"),
            ("max_exec_per_arm", True),
            ("max_exec_per_arm", 2),
            ("max_wall_seconds", 301),
            ("schema_version", True),
        ):
            p = _pair()
            p[key] = value
            with self.subTest(key=key), self.assertRaises(controller.ArmDenied):
                controller._pair_policy(p)

    def test_reject_duplicate_or_tampered_pairs(self) -> None:
        for mutate in (
            lambda p: p["positions"][1].update(arm="baseline"),
            lambda p: p["positions"][1].update(slot_id=p["positions"][0]["slot_id"]),
            lambda p: p["positions"][1].update(
                request_sha256=p["positions"][0]["request_sha256"]
            ),
            lambda p: p["positions"][0].update(index=True),
            lambda p: p.update(extra="forbidden"),
            lambda p: p.update(pair_id="\ud800"),
        ):
            p = _pair()
            mutate(p)
            with self.assertRaises(controller.ArmDenied):
                controller._pair_policy(p)

    def test_live_unit_never_inherits_operator_stdio(self) -> None:
        argv = controller._unit_argv(_pair(), 0)
        before, after = argv[: argv.index("--")], argv[argv.index("--") + 1 :]
        self.assertNotIn("--pipe", before)
        self.assertNotIn("--pty", before)
        self.assertIn("--property=StandardInput=null", before)
        self.assertIn("--property=StandardOutput=null", before)
        self.assertIn("--property=StandardError=null", before)
        self.assertIn("--property=KillMode=control-group", before)
        self.assertEqual(after[0], str(controller._INSTALLED_RUNNER))
        self.assertFalse(any("sh -c" in item for item in argv))

    def test_outer_unit_has_separate_bounded_pre_and_postflight_budget(self) -> None:
        p = _pair()
        self.assertEqual(p["max_wall_seconds"], 300)
        argv = controller._unit_argv(p, 0)
        # The provider still has only 300s, but the unit must also have time
        # for login/sandbox preflight and root-visible result finalization.
        self.assertIn("--property=RuntimeMaxSec=420", argv)
        self.assertNotIn("--property=RuntimeMaxSec=300", argv)


    def test_unprivileged_root_action_cannot_execute(self) -> None:
        with (
            mock.patch.object(controller.os, "geteuid", return_value=1000),
            mock.patch.object(controller, "_read_policy_bootstrap") as bootstrap,
            self.assertRaisesRegex(controller.ArmDenied, "installed rootbroker"),
        ):
            controller.execute_one("a" * 64 + ":0")
        bootstrap.assert_not_called()


class RootArmJsonTests(unittest.TestCase):
    def test_valid_pair_policy_parses_without_model_or_root(self) -> None:
        original = _pair()
        decoded = controller._bounded_policy_json(
            json.dumps(original, separators=(",", ":")).encode("utf-8")
        )
        self.assertEqual(controller._pair_policy(decoded), original)

    def test_deep_json_duplicate_keys_nonfinite_and_bad_utf8_denied(self) -> None:
        wrong = (
            b"[" * 40 + b"0" + b"]" * 40,
            b'{"a":1,"a":2}',
            b'{"value":1e999}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{"value":"\\xff"}',
            b'{"a":[1,2}',
            b"\xff",
            b"[" * (controller._MAX_POLICY_BYTES + 1),
        )
        for raw in wrong:
            with self.subTest(size=len(raw)), self.assertRaises(controller.ArmDenied):
                controller._bounded_policy_json(raw)

    def test_escaped_quote_keeps_brackets_inside_json_string(self) -> None:
        # A valid escaped quote must not switch the bounded root JSON
        # lexer into structural mode.
        value = {"text": 'before " ' + "[" * 40 + " after"}
        self.assertEqual(
            controller._bounded_policy_json(json.dumps(value).encode("utf-8")),
            value,
        )

    def test_json_quoted_brackets_and_escapes_not_counted_as_nesting(self) -> None:
        raw = b'{"text":"[\\"unbalanced\\"]","nested":[{"a":true}]}'
        parsed = controller._bounded_policy_json(raw)
        self.assertEqual(parsed["nested"], [{"a": True}])


class RootArmReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rab-root-arm-offline-")
        self.addCleanup(self.temp.cleanup)
        self.fd = os.open(self.temp.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.p = _pair()
        self.token = controller._token(self.p, 0)
        self.core = SimpleNamespace(_read_root_file=self._read)

    def _read(self, fd: int, filename: str) -> dict:
        with open(
            filename, "rb", opener=lambda name, flags: os.open(name, flags, dir_fd=fd)
        ) as f:
            return json.load(f)

    def _write(self, filename: str, payload: dict) -> None:
        (Path(self.temp.name) / filename).write_text(
            json.dumps(payload), encoding="utf-8"
        )

    def _spent(self) -> None:
        controller._consume_position(self.p, 0, self.fd, self.core)

    def _lifecycle(self, *, provider_outcome_status: str = "unverified") -> None:
        self._write(
            "completed-" + self.token + ".json",
            {
                "schema_version": 2,
                "kind": "rab.root_arm_lifecycle_observation",
                "policy_sha256": controller._sha(controller._canonical(self.p)),
                "token_sha256": self.token,
                "unit": controller._unit(self.p, 0),
                "invocation_id": "d" * 32,
                "result": "success",
                "main_pid": 0,
                "cgroup_empty": True,
                "provider_outcome_status": provider_outcome_status,
            },
        )

    def test_unknown_first_provider_result_must_not_release_second_arm(self) -> None:
        self._spent()
        self._lifecycle(provider_outcome_status="unverified")
        with self.assertRaisesRegex(
            controller.ArmDenied, "provider|outcome|unqualified"
        ):
            controller._consume_position(self.p, 1, self.fd, self.core)
        self.assertFalse(
            (
                Path(self.temp.name)
                / ("spent-" + controller._token(self.p, 1) + ".json")
            ).exists()
        )

    def test_first_spent_marker_alone_never_releases_second(self) -> None:
        self._spent()
        with self.assertRaises(controller.ArmDenied):
            controller._consume_position(self.p, 1, self.fd, self.core)

    def _release(self, *, digest_override: str | None = None) -> None:
        receipt = json.loads(
            (Path(self.temp.name) / ("completed-" + self.token + ".json")).read_text()
        )
        self._write(
            "release-" + self.p["positions"][1]["slot_id"] + ".json",
            {
                "schema_version": 2,
                "kind": "rab.root_arm_second_release",
                "policy_sha256": controller._sha(controller._canonical(self.p)),
                "pair_id": self.p["pair_id"],
                "slot_id": self.p["positions"][1]["slot_id"],
                "first_token_sha256": self.token,
                "first_receipt_sha256": (
                    digest_override
                    if digest_override is not None
                    else controller._sha(controller._canonical(receipt))
                ),
            },
        )

    def test_verified_outcome_without_explicit_root_release_is_denied(self) -> None:
        self._spent()
        self._lifecycle(provider_outcome_status="verified_by_root_issuer")
        with self.assertRaisesRegex(controller.ArmDenied, "release"):
            controller._consume_position(self.p, 1, self.fd, self.core)

    def test_wrong_independent_release_receipt_hash_denied(self) -> None:
        self._spent()
        self._lifecycle(provider_outcome_status="verified_by_root_issuer")
        self._release(digest_override="e" * 64)
        with self.assertRaisesRegex(controller.ArmDenied, "release"):
            controller._consume_position(self.p, 1, self.fd, self.core)

    def test_verified_root_issuer_receipt_structurally_binds_separate_arm(self) -> None:
        # This is a mock only. Real provider receipt issuer does not exist yet.
        self._spent()
        self._lifecycle(provider_outcome_status="verified_by_root_issuer")
        self._release()
        second = controller._consume_position(self.p, 1, self.fd, self.core)
        self.assertNotEqual(second, self.token)
        self.assertEqual(
            json.loads(
                (Path(self.temp.name) / ("spent-" + second + ".json")).read_text()
            )["unit"],
            controller._unit(self.p, 1),
        )
        with self.assertRaises(controller.ArmDenied):
            controller._consume_position(self.p, 1, self.fd, self.core)

    def test_replay_and_partial_markers_are_permanently_spent(self) -> None:
        self._spent()
        with self.assertRaisesRegex(controller.ArmDenied, "consumed|unknown"):
            controller._consume_position(self.p, 0, self.fd, self.core)
        partial = Path(self.temp.name) / ("spent-" + self.token + ".json")
        partial.write_bytes(b'{"incomplete":')
        with self.assertRaisesRegex(controller.ArmDenied, "consumed|unknown"):
            controller._consume_position(self.p, 0, self.fd, self.core)

    def test_failed_or_nonempty_cgroup_first_arm_does_not_release_second(self) -> None:
        self._spent()
        self._lifecycle(provider_outcome_status="verified")
        path = Path(self.temp.name) / ("completed-" + self.token + ".json")
        for field, value in (
            ("result", "failed"),
            ("main_pid", 1337),
            ("cgroup_empty", False),
            ("invocation_id", "invalid"),
            ("provider_outcome_status", "unverified"),
        ):
            receipt = json.loads(path.read_text())
            receipt[field] = value
            path.write_text(json.dumps(receipt))
            with self.subTest(field=field), self.assertRaises(controller.ArmDenied):
                controller._consume_position(self.p, 1, self.fd, self.core)

    def test_root_issuer_must_not_be_skipped_during_prestart(self) -> None:
        with (
            mock.patch.object(controller.os, "geteuid", return_value=0),
            mock.patch.object(
                controller, "_read_policy_bootstrap", return_value=self.p
            ),
            mock.patch.object(controller, "_verified_core", return_value=self.core),
            mock.patch.object(controller, "_qualified_credential"),
            mock.patch.object(
                self.core,
                "_secure_directory",
                create=True,
                return_value=os.dup(self.fd),
            ),
            mock.patch.object(controller, "_consume_position") as consume,
            mock.patch.object(controller.subprocess, "run") as systemd_start,
            self.assertRaisesRegex(
                controller.ArmDenied, "isolation|qualification|unavailable"
            ),
        ):
            controller.execute_one(self.p["epoch_sha256"] + ":0")
        consume.assert_not_called()
        systemd_start.assert_not_called()


class InstalledCodexIdentityTests(unittest.TestCase):
    def test_codex_cli_binary_larger_than_old_32m_is_supported_boundedly(self) -> None:
        # Official Codex CLI 0.163.0 on heim-pc is 296865480 bytes.
        self.assertGreaterEqual(controller._MAX_INSTALLED_BYTES, 296865480)
        self.assertTrue(hasattr(controller, "_digest_verified_fd"))

    def test_large_installed_file_digest_reads_in_bounded_chunks(self) -> None:
        import hashlib
        size = 33 * 1024 * 1024
        with tempfile.TemporaryFile() as handle:
            handle.truncate(size)
            handle.seek(0)
            original = os.read
            calls = []

            def bounded_read(fd: int, length: int) -> bytes:
                if fd == handle.fileno():
                    calls.append(length)
                    self.assertLessEqual(length, 1024 * 1024)
                return original(fd, length)

            with mock.patch.object(controller.os, "read", side_effect=bounded_read):
                actual = controller._digest_verified_fd(handle.fileno(), size)
            # Distinguish a streamed kernel read from a forged fixed digest.
            expected = hashlib.sha256()
            block = bytes(1024 * 1024)
            for _ in range(33):
                expected.update(block)
            self.assertEqual(actual, expected.hexdigest())
            self.assertGreater(len(calls), 30)


class RootbrokerActionCatalogTests(unittest.TestCase):
    def test_dedicated_broker_entry_has_no_arbitrary_command_and_is_inert(self) -> None:
        catalogue = json.loads(
            (_SOURCE.parents[1] / "config" / "privileged-actions.example.json")
            .read_text(encoding="utf-8")
        )["actions"]
        action = catalogue["operator_rab_benchmark_arm_start"]
        self.assertIs(action["enabled"], False)
        self.assertEqual(action["mode"], "template")
        self.assertEqual(action["target_pattern"], "[0-9a-f]{64}:[01]")
        self.assertEqual(
            action["argv"],
            ["/usr/local/libexec/grabowski-rab-root-arm-controller", "{target}"],
        )
        self.assertEqual(action["timeout_seconds"], 600)
        self.assertEqual(action["allowed_peer_uid"], 1000)
        self.assertEqual(action["allowed_peer_unit"], "grabowski-operator.service")
        self.assertIn("kill_switch_path", action)
        self.assertNotIn("allowed_argv_prefixes", action)


if __name__ == "__main__":
    unittest.main()