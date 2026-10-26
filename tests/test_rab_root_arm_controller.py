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

    def test_pair_scoped_private_state_survives_distinct_root_units(self) -> None:
        p = controller._pair_policy(_pair())
        first, second = controller._unit_argv(p, 0), controller._unit_argv(p, 1)
        self.assertNotEqual(first[first.index("--") + 1:], second[second.index("--") + 1:])
        pair = controller._pair_state_directory(p)
        home = "/var/lib/" + pair
        outputs = tuple(home + "/epoch/" + n for n in ("state", "transcripts", "evidence", "reports"))
        state = [pair + "/epoch/" + n for n in ("state", "transcripts", "evidence", "reports")] + [pair + "/repos"]
        for argv in (first, second):
            before = argv[:argv.index("--")]
            self.assertIn("--property=DynamicUser=yes", before)
            self.assertIn("--property=ProtectSystem=strict", before)
            self.assertIn("--property=ProtectHome=read-only", before)
            input_projection = controller._INPUT_PROJECTION
            self.assertIn(
                "--property=BindReadOnlyPaths=" + str(input_projection) + ":/home/alex",
                before,
            )
            self.assertTrue(any(
                item.startswith("--property=InaccessiblePaths=")
                and "-" + str(controller._INPUT_ROOT) in item
                for item in before
            ))
            self.assertIn("--property=StateDirectory=" + " ".join(state), before)
            self.assertIn("--property=StateDirectoryMode=0700", before)
            self.assertIn("--property=Environment=HOME=" + home, before)
            self.assertIn("--property=ReadWritePaths=" + " ".join(outputs), before)
            self.assertIn("--property=TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777", before)
            binds = [item.removeprefix("--property=BindPaths=")
                     for item in before if item.startswith("--property=BindPaths=")]
            self.assertEqual(len(binds), 1)
            self.assertIn(":/tmp", binds[0])
            self.assertIn(":/var/tmp", binds[0])
            if controller._SYSTEMD_RUN.startswith("/run/current-system/sw/bin/"):
                # PID1 already exposes its DynamicUser StateDirectory.
                # A second manual bind onto HOME triggers 226/NAMESPACE on NixOS.
                self.assertEqual(len(binds[0].split()), 2)
                self.assertNotIn("/var/lib/private/" + pair + ":" + home, binds[0])
            else:
                self.assertIn("/var/lib/private/" + pair + ":" + home, binds[0])
            self.assertTrue(any(item.startswith("--property=ReadOnlyPaths=") and
                home + "/repos" in item for item in before))
            self.assertTrue(any(item.startswith("--property=InaccessiblePaths=") and
                "/var/lib/private" in item for item in before))
            self.assertTrue(any(item.startswith("--property=RuntimeDirectory=") for item in before))
        changed = _pair()
        changed["pair_id"] = "separate-frozen-pair"
        self.assertNotEqual(pair, controller._pair_state_directory(changed))

    def test_kernel_guard_mount_compatibility_keeps_parent_unprivileged(self) -> None:
        # Real NixOS PID1 DynamicUser probes established that either
        # ProtectKernelTunables=yes or ProtectKernelLogs=yes locks the private
        # proc mount required by the nested bwrap PID namespace. The parent
        # must still lack capabilities and privilege escalation.
        cmd = controller._unit_argv(_pair(), 0)
        props = cmd[:cmd.index("--")]
        self.assertIn("--property=DynamicUser=yes", props)
        self.assertIn("--property=NoNewPrivileges=yes", props)
        self.assertIn("--property=CapabilityBoundingSet=", props)
        self.assertIn("--property=AmbientCapabilities=", props)
        self.assertIn("--property=PrivateDevices=yes", props)
        self.assertIn("--property=ProtectSystem=strict", props)
        self.assertIn("--property=ProtectKernelModules=yes", props)
        self.assertIn("--property=ProtectControlGroups=yes", props)
        if controller._SYSTEMD_RUN == "/run/current-system/sw/bin/systemd-run":
            self.assertIn("--property=ProtectKernelTunables=no", props)
            self.assertIn("--property=ProtectKernelLogs=no", props)
            self.assertNotIn("--property=ProtectKernelTunables=yes", props)
            self.assertNotIn("--property=ProtectKernelLogs=yes", props)
            # A real PID1 probe failed with 'bwrap: setting up uid map:
            # Read-only file system' when ReadOnlyPaths included /proc.
            # Readonly /run and /sys independently passed with the same
            # zero-capability DynamicUser profile and nested /proc mount.
            readonly = next(
                item.partition("ReadOnlyPaths=")[2].split()
                for item in props if item.startswith("--property=ReadOnlyPaths=")
            )
            self.assertIn("/run", readonly)
            self.assertIn("/sys", readonly)
            self.assertNotIn("/proc", readonly)
        else:
            self.assertIn("--property=ProtectKernelTunables=yes", props)
            readonly = next(
                item.partition("ReadOnlyPaths=")[2].split()
                for item in props if item.startswith("--property=ReadOnlyPaths=")
            )
            self.assertIn("/proc", readonly)
            self.assertIn("--property=ProtectKernelLogs=yes", props)

    def test_nixos_original_inputs_use_readonly_root_owned_nix_store(self) -> None:
        original = controller._INPUT_ROOT / ("plan-" + controller._FROZEN_PLAN_SHA256)
        if controller._SYSTEMD_RUN == "/run/current-system/sw/bin/systemd-run":
            self.assertEqual(
                controller._INPUT_PROJECTION,
                Path("/nix/store/d94g4fnrar2n1xwmp5dy4q9j6zfjw6cr-rab-original-inputs-plan-2795584ac0c1"),
            )
            self.assertTrue(
                os.statvfs(controller._INPUT_PROJECTION).f_flag & os.ST_RDONLY
            )
            controller._require_input_projection(_pair())
            # A writable /nix/store must never be used as the group-writable
            # parent in root FD attestation, even with the correct plan SHA.
            with mock.patch.object(
                controller.os, "statvfs",
                return_value=SimpleNamespace(f_flag=0),
            ):
                with self.assertRaisesRegex(
                    controller.ArmDenied, "installed program parent is mutable"
                ):
                    controller._require_input_projection(_pair())
        else:
            self.assertEqual(controller._INPUT_PROJECTION, original)

    def test_uninstalled_input_projection_denied_before_root_dispatch(self) -> None:
        # Neither a real provider nor a root-owned systemd unit is started.
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(controller, "_INPUT_PROJECTION", Path(tmp) / "missing"):
                with self.assertRaisesRegex(
                    controller.ArmDenied, "root input projection is not installed"
                ):
                    controller._require_input_projection(_pair())

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
        self.assertTrue(any(item.startswith("--property=InaccessiblePaths=") and
                            "/var/lib/private" in item for item in before))
        self.assertIn("--property=KillMode=control-group", before)
        self.assertEqual(after[0], str(controller._INSTALLED_RUNNER))
        self.assertFalse(any("sh -c" in item for item in argv))

    def test_root_unit_retains_pid1_identity_until_root_observes_and_stops_it(self) -> None:
        # Host-probed systemd 249: after --wait the transient unit is
        # LoadState=not-found with empty InvocationID. --no-block plus
        # RemainAfterExit preserves active/exited and its original InvocationID.
        argv = controller._unit_argv(_pair(), 0)
        self.assertIn("--no-block", argv)
        self.assertNotIn("--wait", argv)
        self.assertIn("--property=RemainAfterExit=yes", argv)

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


class RootArmHostLifecycleTests(unittest.TestCase):
    def test_root_stops_completed_unit_before_durable_receipt(self) -> None:
        policy = _pair()
        name = controller._unit(policy, 0)
        fields = {
            "Id": name,
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "exited",
            "Result": "success",
            "MainPID": "0",
            "ControlGroup": "/system.slice/" + name,
            "InvocationID": "b" * 32,
            "Type": "exec",
            "RemainAfterExit": "yes",
            "KillMode": "control-group",
            "DynamicUser": "yes",
            "NoNewPrivileges": "yes",
            "StandardInput": "null",
            "StandardOutput": "null",
            "StandardError": "null",
        }
        events = []

        def systemctl(argv, **_kwargs):
            if argv[1] == "show":
                events.append("show")
                stdout = ("\n".join(f"{key}={val}" for key, val in fields.items()) + "\n").encode("ascii")
                return SimpleNamespace(returncode=0, stdout=stdout)
            if argv[1] == "stop":
                self.assertEqual(argv[2], name)
                events.append("stop")
                return SimpleNamespace(returncode=0, stdout=b"")
            self.fail("unexpected PID1 action")

        with (
            mock.patch.object(controller.subprocess, "run", side_effect=systemctl),
            mock.patch.object(controller, "_write_once", side_effect=lambda *a: events.append("receipt")),
        ):
            controller._root_outcome(policy, 0, 7, "f" * 64)
        self.assertEqual(events, ["show", "stop", "receipt"])

    def test_real_root_issuer_requires_provider_recheck_before_release(self) -> None:
        # Only deterministic PID1/mock provider evidence; never a real model.
        p = _pair()
        name = controller._unit(p, 0)
        first = controller._token(p, 0)
        values = {
            "Id": name, "LoadState": "loaded", "ActiveState": "active",
            "SubState": "exited", "Result": "success", "MainPID": "0",
            "ControlGroup": "/system.slice/" + name,
            "InvocationID": "a" * 32, "Type": "exec",
            "RemainAfterExit": "yes", "KillMode": "control-group",
            "DynamicUser": "yes", "NoNewPrivileges": "yes",
            "StandardInput": "null", "StandardOutput": "null",
            "StandardError": "null",
        }

        def manager(argv, **_kwargs):
            if argv[1] == "show":
                raw = ("\n".join(f"{key}={value}" for key, value in values.items()) + "\n").encode()
                return SimpleNamespace(returncode=0, stdout=raw)
            self.assertEqual(argv[1], "stop")
            return SimpleNamespace(returncode=0, stdout=b"")

        receipts: list[tuple[str, dict]] = []
        def persist(_fd: int, name: str, value: dict) -> None:
            receipts.append((name, value))
        evidence = {"provider_receipt_sha256": "c" * 64, "transcript_sha256": "d" * 64, "stderr_policy_sha256": "e" * 64}
        with (
            mock.patch.object(controller.subprocess, "run", side_effect=manager),
            mock.patch.object(controller, "_write_once", side_effect=persist),
            mock.patch.object(controller, "_verify_completed_provider_capture", return_value=evidence) as checked,
        ):
            controller._root_outcome(p, 0, 7, first, core=object())
            checked.assert_called_once()
        self.assertEqual([name for name, _ in receipts], [
            "completed-" + first + ".json",
            "release-" + p["positions"][1]["slot_id"] + ".json",
        ])
        completed, release = (record for _, record in receipts)
        self.assertEqual(completed["provider_outcome_status"], "verified_by_root_issuer")
        self.assertEqual(completed["provider_receipt_sha256"], "c" * 64)
        self.assertEqual(completed["transcript_sha256"], "d" * 64)
        self.assertEqual(completed["stderr_policy_sha256"], "e" * 64)
        self.assertEqual(release["first_receipt_sha256"], controller._sha(controller._canonical(completed)))

        receipts.clear()
        with (
            mock.patch.object(controller.subprocess, "run", side_effect=manager),
            mock.patch.object(controller, "_write_once", side_effect=persist),
            mock.patch.object(
                controller, "_verify_completed_provider_capture",
                side_effect=controller.ArmDenied("provider response missing"),
            ),
            self.assertRaisesRegex(controller.ArmDenied, "unverified"),
        ):
            controller._root_outcome(p, 0, 7, first, core=object())
        self.assertEqual([name for name, _ in receipts], ["completed-" + first + ".json"])
        self.assertEqual(receipts[0][1]["provider_outcome_status"], "unverified")
        self.assertIsNone(receipts[0][1]["transcript_sha256"])
        self.assertIsNone(receipts[0][1]["stderr_policy_sha256"])

    def test_invalid_completed_unit_stopped_without_receipt(self) -> None:
        policy = _pair()
        name = controller._unit(policy, 0)
        events = []
        body = (
            "Id=" + name + "\n"
            "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
            "Result=exit-code\nMainPID=0\n"
        ).encode("ascii")
        def systemctl(argv, **_kwargs):
            events.append(argv[1])
            return SimpleNamespace(returncode=0, stdout=body if argv[1] == "show" else b"")
        with (
            mock.patch.object(controller.subprocess, "run", side_effect=systemctl),
            mock.patch.object(controller, "_write_once") as receipt,
            self.assertRaises(controller.ArmDenied),
        ):
            controller._root_outcome(policy, 0, 7, "f" * 64)
        receipt.assert_not_called()
        self.assertIn("stop", events)


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


class RootProviderOutcomeProofTests(unittest.TestCase):
    def test_reparsed_real_format_stream_is_required_before_root_issuer(self) -> None:
        from datetime import datetime, timezone
        import hashlib
        from tests.test_repobrief_agent_benchmark_codex_runner import (
            request, runner, stream,
        )

        req = request(condition="baseline")
        policy = _pair()
        policy["pair_id"] = req["pair_id"]
        policy["positions"][0]["request_sha256"] = controller._request_sha(req)
        raw = stream(req)
        artifact = hashlib.sha256(req["request_id"].encode()).hexdigest() + ".jsonl"
        clock = datetime(2026, 10, 24, tzinfo=timezone.utc)
        receipt = runner.receipt(req, raw, artifact, 0, clock, clock)
        observation = {
            "schema_version": 1,
            "kind": "rab.unverified_single_arm_runner_observation",
            "unit": controller._unit(policy, 0),
            "pair_id": policy["pair_id"],
            "slot_id": policy["positions"][0]["slot_id"],
            "arm": "baseline",
            "request_sha256": controller._request_sha(req),
            "runner_receipt_sha256": controller._sha(controller._canonical(receipt)),
            "runner_receipt_bytes": len(
                (json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n").encode()
            ),
            "runner_receipt": receipt,
            "provider_outcome_status": "unverified",
        }
        proof = controller._attest_provider_reply(
            policy, 0, req, observation, raw, runner.receipt
        )
        self.assertEqual(proof["transcript_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(proof["provider_receipt_sha256"], observation["runner_receipt_sha256"])
        for altered, transcript in (
            ({**observation, "runner_receipt_sha256": "f" * 64}, raw),
            ({**observation, "provider_outcome_status": "verified_by_root_issuer"}, raw),
            (observation, raw.replace(b"turn.completed", b"turn.failed")),
            (observation, raw + b'{"type":"turn.completed"}\n'),
        ):
            with self.subTest(altered=altered is not observation), self.assertRaises(controller.ArmDenied):
                controller._attest_provider_reply(
                    policy, 0, req, altered, transcript, runner.receipt
                )


class RootStderrOutcomeProofTests(unittest.TestCase):
    def test_root_rechecks_exact_raw_stderr_diagnostics_and_policy(self) -> None:
        import hashlib
        from datetime import datetime, timezone
        from tests.test_repobrief_agent_benchmark_codex_runner import runner, request, stream
        value = request()
        transcript = stream(value)
        now = datetime(2026, 10, 24, tzinfo=timezone.utc)
        capture = {
            "stdout": transcript,
            "stderr": b"",
            "returncode": 0,
            "capture_error": None,
            "stdout_overflow": False,
            "stderr_overflow": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = runner.persist_provider_capture(
                value, transcript_root=root / "transcripts",
                evidence_root=root / "evidence",
                capture=capture, started_at=now, ended_at=now,
                synthetic_fixture=False,
            )
            diagnostics = result["diagnostics_path"].read_bytes()
            stderr_policy = result["stderr_policy_path"].read_bytes()
            successful = controller._attest_provider_stderr(
                value, transcript, b"", diagnostics, stderr_policy,
                runner.classify_stderr,
            )
            self.assertEqual(
                successful["stderr_policy_sha256"], hashlib.sha256(stderr_policy).hexdigest()
            )
            for wrong_diag, wrong_policy, raw_stderr in (
                (diagnostics, stderr_policy, b"unapproved failure\n"),
                (diagnostics.replace(b'"synthetic_fixture": false', b'"synthetic_fixture": true'),
                 stderr_policy, b""),
                (diagnostics, stderr_policy.replace(b'"allowed": true', b'"allowed": false'), b""),
                (diagnostics, stderr_policy.replace(b'"capture_error": null', b'"capture_error": "masked"'), b""),
            ):
                with self.subTest(stderr=raw_stderr), self.assertRaises(controller.ArmDenied):
                    controller._attest_provider_stderr(
                        value, transcript, raw_stderr,
                        wrong_diag, wrong_policy, runner.classify_stderr,
                    )


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
                "provider_receipt_sha256": (
                    "a" * 64 if provider_outcome_status == "verified_by_root_issuer" else None
                ),
                "transcript_sha256": (
                    "b" * 64 if provider_outcome_status == "verified_by_root_issuer" else None
                ),
                "stderr_policy_sha256": (
                    "c" * 64 if provider_outcome_status == "verified_by_root_issuer" else None
                ),
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

    def test_verified_result_without_stderr_digest_is_denied(self) -> None:
        self._spent()
        self._lifecycle(provider_outcome_status="verified_by_root_issuer")
        name = "completed-" + self.token + ".json"
        receipt = json.loads((Path(self.temp.name) / name).read_text())
        receipt["stderr_policy_sha256"] = None
        self._write(name, receipt)
        self._release()
        with self.assertRaises(controller.ArmDenied):
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
