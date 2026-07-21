from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_coding_agent_router as router  # noqa: E402
import grabowski_coding_agent_router_cli as cli  # noqa: E402


class CodingAgentRouterCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state.json"
        self.environment = mock.patch.dict(
            os.environ,
            {router.STATE_ENV: str(self.state)},
            clear=False,
        )
        self.environment.start()
        os.environ.pop(router.CATALOG_ENV, None)
        os.environ.pop(router.CATALOG_OVERRIDE_ENV, None)

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def _main(self, argv: list[str]) -> tuple[int, dict]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(argv)
        text = stdout.getvalue() if status == 0 else stderr.getvalue()
        return status, json.loads(text)

    def test_recommend_is_direct_first_for_large_work_and_review(self) -> None:
        status, coding = self._main(
            [
                "recommend",
                "--task-class",
                "complex-patch",
                "--changed-files",
                "50",
                "--duration-minutes",
                "600",
                "--novelty",
                "high",
                "--need-review",
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["controller"], "grabowski-primary")
        self.assertEqual(coding["primary_role"], "direct-writer")
        self.assertTrue(coding["external_primary_writer_forbidden"])
        self.assertFalse(coding["automatic_execution_authorized"])

        status, review = self._main(
            ["recommend", "--task-class", "security-review"]
        )
        self.assertEqual(status, 0)
        self.assertEqual(review["primary_role"], "direct-reviewer")
        self.assertTrue(review["external_primary_reviewer_forbidden"])

    def test_probe_preserves_history_and_status_binds_deployment_catalog(self) -> None:
        catalog, validation = router._load_catalog()
        previous = {
            "schema_version": 2,
            "updated_at": "2026-07-19T00:00:00Z",
            "catalog_sha256": "old",
            "catalog": {},
            "pools": {"claude-pro": {"status": "unknown"}},
            "routes": {"route": {"runs": 4}},
            "history": {"marker": {"value": 1}},
        }
        self.state.write_text(json.dumps(previous), encoding="utf-8")
        os.chmod(self.state, 0o600)
        fake_probe = {
            "schema_version": 2,
            "observed_at": cli._iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": [],
            "api_key_environment_scrubbed": [],
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        fake_probe["catalog_probe_sha256"] = cli._probe_digest(fake_probe)
        with mock.patch.object(cli, "_probe", return_value=fake_probe):
            status, result = self._main(["probe"])
        self.assertEqual(status, 0)
        self.assertEqual(result, fake_probe)
        stored = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(stored["history"], previous["history"])
        self.assertEqual(stored["routes"], {})
        self.assertEqual(stored["pools"], {})
        self.assertEqual(stored["catalog"], fake_probe)
        self.assertEqual(stored["catalog_sha256"], validation["catalog_sha256"])
        self.assertEqual(catalog["catalog_version"], "direct-first-review-contrast-v3")

        status, readback = self._main(["status"])
        self.assertEqual(status, 0)
        self.assertTrue(readback["catalog_fresh"])
        self.assertEqual(readback["catalog_source"], "deployment_catalog")
        self.assertEqual(readback["authoritative_work"], "direct_operator")
        self.assertFalse(readback["automatic_execution_authorized"])

    def test_claude_auth_summary_emits_only_fixed_categories(self) -> None:
        raw = {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "subscriptionType": "pro",
            "apiProvider": "secret-provider-value",
            "password": "must-not-propagate",
            "token": "must-not-propagate",
        }
        summary = cli._claude_auth_summary(raw)
        self.assertEqual(
            summary,
            {
                "logged_in": True,
                "auth_method": "claude.ai",
                "subscription_type": "pro",
            },
        )
        encoded = json.dumps(summary, sort_keys=True)
        self.assertNotIn("secret-provider-value", encoded)
        self.assertNotIn("must-not-propagate", encoded)

        unknown = cli._claude_auth_summary(
            {
                "loggedIn": True,
                "authMethod": "password-derived-method",
                "subscriptionType": "password-derived-plan",
            }
        )
        self.assertEqual(
            unknown,
            {
                "logged_in": True,
                "auth_method": None,
                "subscription_type": None,
            },
        )

    def test_probe_digest_safety_guard_rejects_sensitive_fields(self) -> None:
        with self.assertRaisesRegex(
            cli.CodingAgentRouterCliError,
            r"sensitive field: providers\.claude\.auth\.password",
        ):
            cli._assert_probe_digest_safe(
                {"providers": {"claude": {"auth": {"password": "redacted"}}}}
            )
        cli._assert_probe_digest_safe(
            {
                "api_key_environment_scrubbed": ["OPENAI_API_KEY"],
                "context_token_count": 4096,
            }
        )

    def test_probe_output_declares_no_model_or_paid_invocation(self) -> None:
        catalog, _ = router._load_catalog()
        with (
            mock.patch.object(cli, "_binary_versions", return_value={}),
            mock.patch.object(
                cli,
                "_run_metadata",
                return_value={"ok": False, "stdout": "", "stderr": ""},
            ),
            mock.patch.object(cli.shutil, "which", return_value=None),
        ):
            probe = cli._probe(catalog)
        self.assertEqual(probe["model_invocations"], 0)
        self.assertEqual(probe["paid_api_requests_authorized"], 0)
        self.assertEqual(probe["verified_quota_pools"], [])
        self.assertIn("OPENROUTER_API_KEY", probe["api_key_environment_scrubbed"])
        digest_input = dict(probe)
        digest = digest_input.pop("catalog_probe_sha256")
        self.assertEqual(digest, cli._probe_digest(digest_input))

    def test_state_target_symlink_is_rejected(self) -> None:
        real = self.root / "real-state.json"
        real.write_text("{}\n", encoding="utf-8")
        self.state.symlink_to(real)
        with self.assertRaisesRegex(
            cli.CodingAgentRouterCliError, "owned single-link regular file"
        ):
            cli._atomic_write_private_json(self.state, {"schema_version": 2})
        self.assertEqual(real.read_text(encoding="utf-8"), "{}\n")

    def test_observe_rejects_unknown_route_and_invalid_measurements_without_state(self) -> None:
        cases = [
            ["observe", "--route", "unknown", "--outcome", "success"],
            [
                "observe",
                "--route",
                "claude-fable-5-review-high",
                "--outcome",
                "success",
                "--remaining-ratio",
                "1.1",
            ],
            [
                "observe",
                "--route",
                "claude-fable-5-review-high",
                "--outcome",
                "quota_exhausted",
                "--reset-at",
                "not-a-time",
            ],
            [
                "observe",
                "--route",
                "claude-fable-5-review-high",
                "--outcome",
                "success",
                "--duration-seconds",
                "-1",
            ],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                status, result = self._main(argv)
                self.assertEqual(status, 1)
                self.assertEqual(
                    result["error"], "coding_agent_router_cli_failed_closed"
                )
                self.assertFalse(result["automatic_execution_authorized"])
                self.assertFalse(self.state.exists())

    def test_set_quota_rejects_unknown_pool_and_invalid_values_without_state(self) -> None:
        cases = [
            ["set-quota", "--pool", "unknown", "--status", "available"],
            [
                "set-quota",
                "--pool",
                "claude-pro",
                "--status",
                "available",
                "--remaining-ratio",
                "1.1",
            ],
            [
                "set-quota",
                "--pool",
                "claude-pro",
                "--status",
                "available",
                "--active-sessions",
                "-1",
            ],
            [
                "set-quota",
                "--pool",
                "claude-pro",
                "--status",
                "cooldown",
                "--cooldown-until",
                "not-a-time",
            ],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                status, result = self._main(argv)
                self.assertEqual(status, 1)
                self.assertEqual(
                    result["error"], "coding_agent_router_cli_failed_closed"
                )
                self.assertFalse(self.state.exists())

    def test_rate_limit_observation_updates_bound_pool_and_preserves_history(self) -> None:
        catalog, validation = router._load_catalog()
        initial = {
            "schema_version": 2,
            "updated_at": cli._iso_now(),
            "catalog_sha256": validation["catalog_sha256"],
            "catalog": {},
            "pools": {},
            "routes": {},
            "history": {"marker": {"value": 1}},
        }
        self.state.write_text(json.dumps(initial), encoding="utf-8")
        os.chmod(self.state, 0o600)
        route_id = "claude-fable-5-review-high"
        status, result = self._main(
            [
                "observe",
                "--route",
                route_id,
                "--outcome",
                "rate_limit",
                "--remaining-ratio",
                "0.2",
                "--duration-seconds",
                "12.5",
            ]
        )
        self.assertEqual(status, 0)
        self.assertTrue(result["recorded"])
        stored = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(stored["history"], initial["history"])
        self.assertEqual(stored["routes"][route_id]["runs"], 1)
        self.assertEqual(
            stored["routes"][route_id]["last_duration_seconds"], 12.5
        )
        route = router._route_map(catalog)[route_id]
        for pool_id in route["quota_pools"]:
            pool = stored["pools"][pool_id]
            self.assertEqual(pool["status"], "cooldown")
            self.assertEqual(pool["remaining_ratio"], 0.2)
            self.assertIsNotNone(router._parse_time(pool["cooldown_until"]))

    def test_probe_binds_only_explicitly_verified_pool_timestamps(self) -> None:
        _, validation = router._load_catalog()
        observed_at = cli._iso_now()
        initial = {
            "schema_version": 2,
            "updated_at": observed_at,
            "catalog_sha256": validation["catalog_sha256"],
            "catalog": {},
            "pools": {
                "grok-com": {"status": "available"},
                "claude-pro": {"status": "unknown"},
                "jules-account": {
                    "status": "unknown",
                    "verified_at": "2026-07-19T00:00:00Z",
                },
            },
            "routes": {"route": {"runs": 2}},
            "history": {"marker": 1},
        }
        self.state.write_text(json.dumps(initial), encoding="utf-8")
        os.chmod(self.state, 0o600)
        probe = {
            "schema_version": 2,
            "observed_at": observed_at,
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": ["grok-com"],
            "api_key_environment_scrubbed": [],
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        probe["catalog_probe_sha256"] = cli._probe_digest(probe)
        cli._write_probe(probe, validation)
        stored = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(stored["history"], initial["history"])
        self.assertEqual(stored["routes"], initial["routes"])
        self.assertEqual(stored["pools"]["grok-com"]["verified_at"], observed_at)
        self.assertNotIn("verified_at", stored["pools"]["claude-pro"])
        self.assertNotIn("verified_at", stored["pools"]["jules-account"])

    def test_observe_rejects_malformed_existing_counters_without_rewrite(self) -> None:
        _, validation = router._load_catalog()
        route_id = "claude-fable-5-review-high"
        initial = {
            "schema_version": 2,
            "updated_at": cli._iso_now(),
            "catalog_sha256": validation["catalog_sha256"],
            "catalog": {},
            "pools": {},
            "routes": {route_id: {"runs": True}},
            "history": {},
        }
        self.state.write_text(json.dumps(initial), encoding="utf-8")
        os.chmod(self.state, 0o600)
        before = self.state.read_bytes()
        status, result = self._main(
            ["observe", "--route", route_id, "--outcome", "success"]
        )
        self.assertEqual(status, 1)
        self.assertEqual(result["error_type"], "CodingAgentRouterCliError")
        self.assertEqual(self.state.read_bytes(), before)

    def test_observe_averages_rework_and_success_clears_stale_pool_blockers(self) -> None:
        catalog, validation = router._load_catalog()
        route_id = "claude-fable-5-review-high"
        initial = {
            "schema_version": 2,
            "updated_at": cli._iso_now(),
            "catalog_sha256": validation["catalog_sha256"],
            "catalog": {},
            "pools": {
                pool_id: {
                    "status": "blocked",
                    "blocked_reason": "old",
                    "cooldown_until": "2099-01-01T00:00:00Z",
                    "reset_at": "2099-01-02T00:00:00Z",
                }
                for pool_id in router._route_map(catalog)[route_id]["quota_pools"]
            },
            "routes": {
                route_id: {
                    "runs": 1,
                    "successes": 1,
                    "failures": 0,
                    "average_rework_minutes": 10.0,
                    "rework_observations": 1,
                }
            },
            "history": {},
        }
        self.state.write_text(json.dumps(initial), encoding="utf-8")
        os.chmod(self.state, 0o600)
        status, _ = self._main(
            [
                "observe",
                "--route",
                route_id,
                "--outcome",
                "success",
                "--rework-minutes",
                "20",
            ]
        )
        self.assertEqual(status, 0)
        stored = json.loads(self.state.read_text(encoding="utf-8"))
        record = stored["routes"][route_id]
        self.assertEqual(record["average_rework_minutes"], 15.0)
        self.assertEqual(record["rework_observations"], 2)
        for pool_id in router._route_map(catalog)[route_id]["quota_pools"]:
            pool = stored["pools"][pool_id]
            self.assertEqual(pool["status"], "available")
            self.assertNotIn("blocked_reason", pool)
            self.assertNotIn("cooldown_until", pool)
            self.assertNotIn("reset_at", pool)

    def test_set_quota_available_clears_stale_status_fields(self) -> None:
        _, validation = router._load_catalog()
        initial = {
            "schema_version": 2,
            "updated_at": cli._iso_now(),
            "catalog_sha256": validation["catalog_sha256"],
            "catalog": {},
            "pools": {
                "claude-pro": {
                    "status": "blocked",
                    "blocked_reason": "old",
                    "cooldown_until": "2099-01-01T00:00:00Z",
                    "reset_at": "2099-01-02T00:00:00Z",
                    "remaining_ratio": 0.1,
                }
            },
            "routes": {},
            "history": {},
        }
        self.state.write_text(json.dumps(initial), encoding="utf-8")
        os.chmod(self.state, 0o600)
        status, _ = self._main(
            ["set-quota", "--pool", "claude-pro", "--status", "available"]
        )
        self.assertEqual(status, 0)
        pool = json.loads(self.state.read_text(encoding="utf-8"))["pools"][
            "claude-pro"
        ]
        self.assertEqual(pool["status"], "available")
        for field in (
            "blocked_reason",
            "cooldown_until",
            "remaining_ratio",
            "reset_at",
        ):
            self.assertNotIn(field, pool)

    def test_binary_versions_execute_resolved_absolute_path(self) -> None:
        catalog, _ = router._load_catalog()

        def resolve(binary: object) -> str | None:
            return "/opt/tools/codex" if binary == "codex" else None

        with (
            mock.patch.object(cli, "_resolve_executable", side_effect=resolve),
            mock.patch.object(
                cli,
                "_run_metadata",
                return_value={"ok": True, "stdout": "codex 1", "stderr": ""},
            ) as run,
        ):
            versions = cli._binary_versions(catalog)
        self.assertTrue(versions["codex"]["version_ok"])
        run.assert_called_once_with(["/opt/tools/codex", "--version"], catalog)

    def test_metadata_rejects_non_absolute_executable(self) -> None:
        catalog, _ = router._load_catalog()
        self.assertEqual(
            cli._run_metadata(["codex", "--version"], catalog),
            {"ok": False, "error_type": "non_absolute_executable"},
        )

    def test_state_payload_size_limit_is_fail_closed(self) -> None:
        with mock.patch.object(router, "MAX_STATE_BYTES", 8):
            with self.assertRaisesRegex(
                cli.CodingAgentRouterCliError, "exceeds the size limit"
            ):
                cli._atomic_write_private_json(
                    self.state, {"schema_version": 2, "value": "too-large"}
                )
        self.assertFalse(self.state.exists())

    def test_state_parent_symlink_is_rejected(self) -> None:
        real = self.root / "real"
        real.mkdir()
        linked = self.root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(
            cli.CodingAgentRouterCliError, "private user-owned directory"
        ):
            cli._atomic_write_private_json(linked / "state.json", {"schema_version": 2})

    def test_non_private_state_parent_is_rejected_without_chmod(self) -> None:
        parent = self.root / "shared"
        parent.mkdir(mode=0o755)
        os.chmod(parent, 0o755)
        with self.assertRaisesRegex(
            cli.CodingAgentRouterCliError, "private user-owned directory"
        ):
            cli._atomic_write_private_json(parent / "state.json", {"schema_version": 2})
        self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
        self.assertFalse((parent / "state.json").exists())


if __name__ == "__main__":
    unittest.main()
