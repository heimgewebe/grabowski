"""Provider-free RAB single-arm execution tests; no root or model requests."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


_PATH = Path(__file__).resolve().parents[1] / "tools/grabowski_rab_arm_exec.py"
_SPEC = importlib.util.spec_from_file_location("rab_single_arm_test_source", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
arm = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(arm)


def pair(arm_name: str = "baseline") -> tuple[dict, dict]:
    request = {
        "request_id": "fixed-single-request",
        "pair_id": "frozen-pair",
        "condition": arm_name,
        "runner": {"model": "gpt-6-astra", "provider": "openai-codex-cli"},
        "budgets": {"wall_seconds": 300},
    }
    selected = 0 if arm_name == "baseline" else 1
    positions = [
        {
            "index": i,
            "arm": ("baseline", "treatment")[i],
            "slot_id": ("1" if i == 0 else "2") * 64,
            "request_sha256": arm._request_sha(request) if i == selected else "a" * 64,
        }
        for i in (0, 1)
    ]
    policy = {
        "schema_version": 2,
        "kind": "rab.root_controlled_separate_arms",
        "epoch_sha256": "f" * 64,
        "plan_sha256": arm._PLAN_SHA256,
        "pair_id": "frozen-pair",
        "provider": "openai-codex-cli",
        "mode": "chatgpt_subscription",
        "model": "gpt-6-astra",
        "reasoning": "medium",
        "max_exec_per_arm": 1,
        "max_wall_seconds": 300,
        "installed_sha256": {"codex": "b" * 64},
        "positions": positions,
    }
    return policy, request


class RABSingleArmTests(unittest.TestCase):
    def test_utf8_frozen_request_digest_matches_original_repobrief(self) -> None:
        from tests.test_repobrief_agent_benchmark_codex_runner import runner
        from tests.test_rab_root_arm_controller import controller
        request = {
            "prompt": "Finde den zugehörigen Test für die Datei.",
            "pair_id": "unicode-test",
            "condition": "baseline",
        }
        expected = runner.base._sha256_json(request)
        self.assertEqual(controller._request_sha(request), expected)
        self.assertEqual(arm._request_sha(request), expected)
        self.assertNotEqual(arm._sha(arm._canonical(request)), expected)

    def test_both_arms_have_distinct_kernel_unit_identity(self) -> None:
        self.assertNotEqual(
            arm._unit("f" * 64, "frozen-pair", "1" * 64),
            arm._unit("f" * 64, "frozen-pair", "2" * 64),
        )
        self.assertRegex(
            arm._admit_target("f" * 64, "frozen-pair", "1" * 64, "baseline"),
            r"^grabowski-rab-[0-9a-f]{16}\.service$",
        )

    def test_target_flags_are_not_arbitrary_commands(self) -> None:
        for kwargs in (
            dict(epoch="x" * 64, pair_id="frozen-pair", slot_id="1" * 64, arm="baseline"),
            dict(epoch="f" * 64, pair_id="frozen-pair", slot_id="x" * 64, arm="baseline"),
            dict(epoch="f" * 64, pair_id="frozen-pair", slot_id="1" * 64, arm="shell"),
            dict(epoch="f" * 64, pair_id="bad\npair", slot_id="1" * 64, arm="baseline"),
            dict(epoch="f" * 64, pair_id="\ud800", slot_id="1" * 64, arm="baseline"),
        ):
            with self.subTest(kwargs=repr(kwargs)), self.assertRaises(arm.ArmExecDenied):
                arm._admit_target(**kwargs)

    def test_direct_invocations_have_no_systemd_credential_authority(self) -> None:
        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": "/tmp/forged"}):
            with self.assertRaises(arm.ArmExecDenied):
                arm._systemd_credential_dir(
                    arm._unit("f" * 64, "frozen-pair", "1" * 64)
                )

    def test_only_root_selected_request_hash_and_condition_are_valid(self) -> None:
        p, r = pair()
        args = dict(epoch="f" * 64, pair_id="frozen-pair", slot_id="1" * 64, arm="baseline")
        arm._verify_pair(p, r, **args)
        changed = {**r, "request_id": "different"}
        for bad_policy, bad_request in (
            (p, changed),
            ({**p, "model": "other"}, r),
            ({**p, "reasoning": "high"}, r),
            ({**p, "max_exec_per_arm": 2}, r),
            ({**p, "plan_sha256": "0" * 64}, r),
            ({**p, "unknown": True}, r),
            (p, {**r, "runner": None}),
            (p, {**r, "budgets": {"wall_seconds": 301}}),
        ):
            with self.subTest(policy=bad_policy, request=bad_request):
                with self.assertRaises(arm.ArmExecDenied):
                    arm._verify_pair(bad_policy, bad_request, **args)

    def test_runtime_selects_fixed_installed_runner_and_model(self) -> None:
        p, r = pair()
        runtime = {
            "schema_version": 1,
            "kind": "rab.root_installed_single_arm_runtime",
            "codex_runner_sha256": "c" * 64,
            "base_runner_sha256": "d" * 64,
            "codex_bootstrap_sha256": "e" * 64,
            "request_root": "/fixed/requests",
            "repository_map": "/fixed/repositories.json",
            "state_root": "/fixed/state",
            "transcript_root": "/fixed/transcripts",
            "provider_evidence_root": "/fixed/provider-evidence",
        }
        with (
            mock.patch.object(arm, "_root_owned_digest") as check,
            mock.patch.object(arm, "_verified_bootstrap_text", return_value="frozen-bootstrap") as bootstrap,
        ):
            argv = arm._runner_args(runtime, p)
        bootstrap.assert_called_once_with("e" * 64)
        self.assertEqual(
            check.call_args_list,
            [
                mock.call(arm._INSTALLED_CODEX, "b" * 64, max_bytes=512 * 1024 * 1024),
                mock.call(arm._INSTALLED_CODEX_RUNNER, "c" * 64, max_bytes=16 * 1024 * 1024),
                mock.call(arm._INSTALLED_BASE_RUNNER, "d" * 64, max_bytes=16 * 1024 * 1024),
            ],
        )
        self.assertEqual(argv[:5], [arm.sys.executable, "-I", "-B", "-c", "frozen-bootstrap"])
        self.assertEqual(argv[5], str(arm._INSTALLED_CODEX_RUNNER))
        self.assertEqual(argv[argv.index("--codex-command") + 1], str(arm._INSTALLED_CODEX))
        self.assertIn("--allow-live-provider", argv)
        self.assertNotIn("/bin/sh", argv)
        with (
            mock.patch.object(arm, "_root_owned_digest"),
            mock.patch.object(arm, "_verified_bootstrap_text", return_value="frozen-bootstrap"),
        ):
            for bad in (
                {**runtime, "command": "/bin/sh"},
                {**runtime, "state_root": "../state"},
                {**runtime, "repository_map": "/tmp/../untrusted"},
            ):
                with self.assertRaises(arm.ArmExecDenied):
                    arm._runner_args(bad, p)

    def test_fixed_root_result_is_unverified_and_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            path.chmod(0o700)
            receipt = {"kind": "arm.unverified", "provider_outcome_status": "unverified"}
            arm._write_result(str(path), "1" * 64, receipt)
            disk = json.loads((path / ("unverified-" + "1" * 64 + ".json")).read_text())
            self.assertEqual(disk, receipt)
            with self.assertRaises(arm.ArmExecDenied):
                arm._write_result(str(path), "1" * 64, receipt)

    def test_runner_fails_closed_without_provider_receipt(self) -> None:
        p, r = pair()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            base.chmod(0o700)
            data = {
                "pair.json": p, "request.json": r,
                "runtime.json": {"state_root": str(base)},
            }
            with (
                mock.patch.object(arm, "_systemd_credential_dir", side_effect=lambda _: os.open(base, os.O_RDONLY | os.O_DIRECTORY)),
                mock.patch.object(arm, "_credential", side_effect=lambda fd, name: data[name]),
                mock.patch.object(arm, "_runner_args", return_value=["fixed-runner"]),
                mock.patch.object(arm.subprocess, "run", return_value=SimpleNamespace(returncode=2)),
            ):
                with self.assertRaises(arm.ArmExecDenied):
                    arm.execute("f" * 64, "frozen-pair", "1" * 64, "baseline")
            self.assertFalse(list(base.iterdir()))

    def test_successful_runner_exit_is_not_a_root_provider_success_attestation(self) -> None:
        p, r = pair()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            base.chmod(0o700)
            data = {"pair.json": p, "request.json": r, "runtime.json": {"state_root": str(base)}}
            def emulate(_args, **kwargs):
                kwargs["stdout"].write(json.dumps({
                    "status": "success",
                    "request_id": r["request_id"],
                    "request_sha256": arm._request_sha(r),
                }).encode())
                return SimpleNamespace(returncode=0)
            with (
                mock.patch.object(arm, "_systemd_credential_dir", side_effect=lambda _: os.open(base, os.O_RDONLY | os.O_DIRECTORY)),
                mock.patch.object(arm, "_credential", side_effect=lambda fd, name: data[name]),
                mock.patch.object(arm, "_runner_args", return_value=["fixed-runner"]),
                mock.patch.object(arm.subprocess, "run", side_effect=emulate),
            ):
                arm.execute("f" * 64, "frozen-pair", "1" * 64, "baseline")
            disk = json.loads((base / ("unverified-" + "1" * 64 + ".json")).read_text())
            self.assertEqual(disk["provider_outcome_status"], "unverified")
            self.assertEqual(disk["arm"], "baseline")
            self.assertEqual(disk["request_sha256"], arm._request_sha(r))


class RootControllerInputBindingTests(unittest.TestCase):
    def test_systemd_249_loads_only_fixed_root_inputs(self) -> None:
        from tests.test_rab_root_arm_controller import controller, _pair
        p = _pair()
        argv = controller._unit_argv(p, 0)
        epoch = p["epoch_sha256"]
        slot = p["positions"][0]["slot_id"]
        load = [x for x in argv if x.startswith("--property=LoadCredential=")]
        self.assertEqual(load, [
            "--property=LoadCredential=auth.json:/etc/grabowski/rab-arm/credentials/epoch-" + epoch + ".auth",
            "--property=LoadCredential=pair.json:/etc/grabowski/rab-arm/epoch-" + epoch + ".json",
            "--property=LoadCredential=request.json:/etc/grabowski/rab-arm/requests/slot-" + slot + ".json",
            "--property=LoadCredential=runtime.json:/etc/grabowski/rab-arm/epoch-" + epoch + ".runtime.json",
        ])

    def test_root_rejects_mutated_request_or_runtime_before_spending(self) -> None:
        from tests.test_rab_root_arm_controller import controller, _pair
        p = _pair()
        request = {
            "pair_id": p["pair_id"],
            "condition": p["positions"][0]["arm"],
            "runner": {"model": p["model"], "provider": p["provider"]},
        }
        p["positions"][0]["request_sha256"] = controller._request_sha(request)
        runtime = {
            "schema_version": 1,
            "kind": "rab.root_installed_single_arm_runtime",
            "codex_runner_sha256": "b" * 64,
            "base_runner_sha256": "c" * 64,
            "codex_bootstrap_sha256": "d" * 64,
            "request_root": "/root-owned/requests",
            "repository_map": "/root-owned/repository-map.json",
            "state_root": "/private/state",
            "transcript_root": "/private/transcripts",
            "provider_evidence_root": "/private/evidence",
        }
        values = {
            "slot-" + p["positions"][0]["slot_id"] + ".json": request,
            "epoch-" + p["epoch_sha256"] + ".runtime.json": runtime,
        }
        class ProviderGrantDenied(Exception):
            pass
        with tempfile.TemporaryDirectory() as folder:
            core = SimpleNamespace(
                ProviderGrantDenied=ProviderGrantDenied,
                _secure_directory=lambda _: os.open(folder, os.O_RDONLY | os.O_DIRECTORY),
                _read_root_file=lambda fd, name: values[name],
            )
            with mock.patch.object(controller, "_verify_root_owned_file") as verified:
                controller._qualified_arm_inputs(p, 0, core)
                self.assertEqual(verified.call_args_list, [
                    mock.call(Path("/usr/local/libexec/grabowski-rab-codex-runner"), "b" * 64),
                    mock.call(Path("/usr/local/libexec/repobrief_agent_benchmark_runner.py"), "c" * 64),
                    mock.call(Path("/usr/local/libexec/repobrief_agent_benchmark_source_bootstrap.py"), "d" * 64),
                ])
            values["slot-" + p["positions"][0]["slot_id"] + ".json"] = {
                **request, "pair_id": "forged-pair"
            }
            with mock.patch.object(controller, "_verify_root_owned_file") as verified:
                with self.assertRaises(controller.ArmDenied):
                    controller._qualified_arm_inputs(p, 0, core)
                verified.assert_not_called()
            values["slot-" + p["positions"][0]["slot_id"] + ".json"] = request
            values["epoch-" + p["epoch_sha256"] + ".runtime.json"] = {
                **runtime, "state_root": "../escaped",
            }
            with mock.patch.object(controller, "_verify_root_owned_file") as verified:
                with self.assertRaises(controller.ArmDenied):
                    controller._qualified_arm_inputs(p, 0, core)
                verified.assert_not_called()


class SubscriptionSystemdCredentialTests(unittest.TestCase):
    def test_forged_credential_environment_is_not_authority(self) -> None:
        from tests.test_repobrief_agent_benchmark_codex_runner import runner
        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": "/tmp/forged"}):
            with self.assertRaisesRegex(runner.RunnerError, "unit identity"):
                runner._read_chatgpt_auth_file(Path("/missing"))

    def test_systemd_credentials_are_not_forwarded_to_model_children(self) -> None:
        from tests.test_repobrief_agent_benchmark_codex_runner import runner
        with mock.patch.dict(os.environ, {
            "CREDENTIALS_DIRECTORY": "/run/credentials/grabowski-rab-1111111111111111.service",
            "OPENAI_API_KEY": "forbidden",
        }):
            forwarded = runner.provider_env()
            self.assertNotIn("CREDENTIALS_DIRECTORY", forwarded)
            self.assertNotIn("OPENAI_API_KEY", forwarded)
            self.assertNotIn("CODEX_ACCESS_TOKEN", forwarded)


if __name__ == "__main__":
    unittest.main()
