from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import base64
import contextlib
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

    def _grok_auth_home(
        self,
        *,
        tier: int = 1,
        issued_at: int = 1_000,
        expires_at: int = 2_000,
        file_mode: int = 0o600,
        extra_account: bool = False,
    ) -> Path:
        home = self.root / f"grok-home-{len(list(self.root.glob('grok-home-*')))}"
        home.mkdir(mode=0o700)
        grok = home / ".grok"
        grok.mkdir(mode=0o755)
        issuer = "https://auth.x.ai"
        client_id = "client-123"
        principal_id = "user-123"
        team_id = "team-123"
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').decode().rstrip("=")
        claims = {
            "iss": issuer,
            "aud": client_id,
            "sub": principal_id,
            "principal_id": principal_id,
            "principal_type": "User",
            "team_id": team_id,
            "tier": tier,
            "iat": issued_at,
            "exp": expires_at,
        }
        encoded_claims = base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
        ).decode().rstrip("=")
        token = f"{header}.{encoded_claims}.{'s' * 64}"
        record = {
            "auth_mode": "Oidc",
            "key": token,
            "oidc_client_id": client_id,
            "oidc_issuer": issuer,
            "principal_id": principal_id,
            "principal_type": "User",
            "team_id": team_id,
            "user_id": principal_id,
        }
        payload = {f"{issuer}::{client_id}": record}
        if extra_account:
            payload[f"{issuer}::other-client"] = dict(record)
        auth = grok / "auth.json"
        auth.write_text(json.dumps(payload), encoding="utf-8")
        auth.chmod(file_mode)
        return home

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
        self.assertEqual(coding["primary_role"], "controller-integrator")
        self.assertFalse(coding["external_primary_writer_forbidden"])
        self.assertTrue(coding["automatic_execution_authorized"])

        status, review = self._main(
            ["recommend", "--task-class", "security-review"]
        )
        self.assertEqual(status, 0)
        self.assertEqual(review["primary_role"], "controller-reviewer")
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
        self.assertEqual(catalog["catalog_version"], "lane-scoped-writer-v9")

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

    def test_grok_subscription_auth_requires_exact_private_oidc_tier(self) -> None:
        catalog, _ = router._load_catalog()
        valid = cli._grok_subscription_auth_status(
            catalog,
            home=self._grok_auth_home(),
            now_unix=1_100,
        )
        self.assertEqual(valid["status"], "valid")
        self.assertTrue(valid["authenticated"])
        self.assertTrue(valid["entitlement_verified"])
        self.assertEqual(valid["subscription_tier"], "SuperGrok")
        self.assertRegex(valid["account_binding_sha256"], r"^[0-9a-f]{64}$")

        wrong_tier = cli._grok_subscription_auth_status(
            catalog,
            home=self._grok_auth_home(tier=0),
            now_unix=1_100,
        )
        self.assertEqual(wrong_tier["status"], "entitlement-mismatch")
        self.assertFalse(wrong_tier["entitlement_verified"])

        expired = cli._grok_subscription_auth_status(
            catalog,
            home=self._grok_auth_home(expires_at=1_120),
            now_unix=1_100,
        )
        self.assertEqual(expired["status"], "entitlement-mismatch")

        unsafe = cli._grok_subscription_auth_status(
            catalog,
            home=self._grok_auth_home(file_mode=0o644),
            now_unix=1_100,
        )
        self.assertEqual(unsafe["status"], "unsafe-file")

        ambiguous = cli._grok_subscription_auth_status(
            catalog,
            home=self._grok_auth_home(extra_account=True),
            now_unix=1_100,
        )
        self.assertEqual(ambiguous["status"], "ambiguous-account")

    def test_antigravity_model_discovery_canonicalizes_configured_cli_ids(self) -> None:
        catalog, _ = router._load_catalog()
        self.assertEqual(
            cli._antigravity_models_from_output(
                catalog,
                "gemini-3.1-pro-high\tGemini 3.1 Pro (High)\n"
                "gemini-3.6-flash\tGemini 3.6 Flash\n"
                "invented-model\tGemini 3.1 Pro (High)\n"
                "Gemini 3.1 Pro (High)\n",
            ),
            ["gemini-3.1-pro", "gemini-3.6-flash"],
        )

    def test_grok_model_discovery_accepts_legacy_and_inline_sections_only(self) -> None:
        catalog, _ = router._load_catalog()
        legacy = (
            "Default model: grok-4.6\n"
            "Available models:\n"
            "* grok-4.6 default\n"
            "* arbitrary-label default\n"
        )
        current = (
            "Default model: grok-4.6\n"
            "Available models: grok-4.6, arbitrary-label\n"
        )
        self.assertEqual(
            cli._grok_models_from_output(catalog, legacy), ["grok-4.6"]
        )
        self.assertEqual(
            cli._grok_models_from_output(catalog, current), ["grok-4.6"]
        )
        self.assertEqual(
            cli._grok_models_from_output(
                catalog,
                "Default model: grok-4.6\nAvailable models: arbitrary-label\n",
            ),
            [],
        )

    def test_probe_verifies_grok_pool_only_with_stable_supergrok_binding(self) -> None:
        catalog, _ = router._load_catalog()
        auth = {
            "authenticated": True,
            "entitlement_verified": True,
            "status": "valid",
            "subscription_tier": "SuperGrok",
            "account_binding_sha256": "a" * 64,
        }

        def metadata(_harnesses, harness, arguments, _catalog):
            if harness == "grok" and arguments == ["models"]:
                return {
                    "ok": True,
                    "stdout": "Default model: grok-4.6\nAvailable models:\n* grok-4.6 default\n",
                    "stderr": "",
                }
            return {"ok": False, "stdout": "", "stderr": ""}

        with (
            mock.patch.object(
                cli,
                "_binary_versions",
                return_value={"grok": {"available": True, "binary": "/grok"}},
            ),
            mock.patch.object(cli, "_run_harness_metadata", side_effect=metadata),
            mock.patch.object(
                cli,
                "_grok_subscription_auth_status",
                side_effect=[dict(auth), dict(auth)],
            ),
            mock.patch.object(
                cli,
                "_openhands_subscription_auth_status",
                return_value={"authenticated": False},
            ),
            mock.patch.object(cli, "_resolve_executable", return_value=None),
        ):
            verified = cli._probe(catalog)
        self.assertIn("grok-com", verified["verified_quota_pools"])
        self.assertTrue(verified["providers"]["grok"]["logged_in"])
        self.assertTrue(verified["providers"]["grok"]["entitlement_verified"])
        self.assertEqual(
            verified["providers"]["grok"]["subscription_tier"], "SuperGrok"
        )

        changed = dict(auth)
        changed["account_binding_sha256"] = "b" * 64
        with (
            mock.patch.object(
                cli,
                "_binary_versions",
                return_value={"grok": {"available": True, "binary": "/grok"}},
            ),
            mock.patch.object(cli, "_run_harness_metadata", side_effect=metadata),
            mock.patch.object(
                cli,
                "_grok_subscription_auth_status",
                side_effect=[dict(auth), changed],
            ),
            mock.patch.object(
                cli,
                "_openhands_subscription_auth_status",
                return_value={"authenticated": False},
            ),
            mock.patch.object(cli, "_resolve_executable", return_value=None),
        ):
            rejected = cli._probe(catalog)
        self.assertNotIn("grok-com", rejected["verified_quota_pools"])
        self.assertFalse(rejected["providers"]["grok"]["entitlement_verified"])

    def test_probe_digest_safety_guard_rejects_sensitive_fields(self) -> None:
        with self.assertRaisesRegex(
            cli.CodingAgentRouterCliError,
            r"sensitive field: providers\.claude\.auth\.password",
        ):
            cli._assert_probe_digest_safe(
                {"providers": {"claude": {"auth": {"password": "redacted"}}}}
            )
        for sensitive_field in ("token_hint", "auth_secret", "credential_value"):
            with self.subTest(sensitive_field=sensitive_field):
                with self.assertRaisesRegex(
                    cli.CodingAgentRouterCliError, "sensitive field"
                ):
                    cli._assert_probe_digest_safe({sensitive_field: "redacted"})
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
            mock.patch.object(
                cli,
                "_openhands_subscription_auth_status",
                return_value={"authenticated": False},
            ),
            mock.patch.object(
                cli,
                "_grok_subscription_auth_status",
                return_value={
                    "authenticated": False,
                    "entitlement_verified": False,
                    "status": "missing",
                    "subscription_tier": None,
                    "account_binding_sha256": None,
                },
            ),
        ):
            probe = cli._probe(catalog)
        self.assertEqual(probe["model_invocations"], 0)
        self.assertEqual(probe["paid_api_requests_authorized"], 0)
        self.assertEqual(probe["verified_quota_pools"], [])
        self.assertIn("OPENROUTER_API_KEY", probe["api_key_environment_scrubbed"])
        digest_input = dict(probe)
        digest = digest_input.pop("catalog_probe_sha256")
        self.assertEqual(digest, cli._probe_digest(digest_input))

    def test_openrouter_ox_alpha_public_price_probe_fails_closed_on_incomplete_read(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.side_effect = cli.http.client.IncompleteRead(b"{\"data\":")
        with mock.patch.object(cli.urllib.request, "urlopen", return_value=response):
            result = cli._openrouter_ox_alpha_price_status()
        self.assertFalse(result["available"])
        self.assertFalse(result["zero_price_verified"])
        self.assertEqual(result["pricing_status"], "unavailable")

    def test_openrouter_ox_alpha_public_price_probe_requires_every_price_zero(self) -> None:
        zero_payload = {
            "data": [
                {
                    "id": "stealth/ox-alpha",
                    "pricing": {"prompt": "0", "completion": "0", "request": "0"},
                }
            ]
        }
        with mock.patch.object(
            cli.urllib.request,
            "urlopen",
            return_value=io.BytesIO(json.dumps(zero_payload).encode("utf-8")),
        ):
            verified = cli._openrouter_ox_alpha_price_status()
        self.assertTrue(verified["zero_price_verified"])
        self.assertEqual(verified["pricing_status"], "zero")
        self.assertEqual(verified["model_id"], "stealth/ox-alpha")

        paid_payload = {
            "data": [
                {
                    "id": "stealth/ox-alpha",
                    "pricing": {"prompt": "0", "completion": "0.000001"},
                }
            ]
        }
        with mock.patch.object(
            cli.urllib.request,
            "urlopen",
            return_value=io.BytesIO(json.dumps(paid_payload).encode("utf-8")),
        ):
            rejected = cli._openrouter_ox_alpha_price_status()
        self.assertFalse(rejected["zero_price_verified"])
        self.assertEqual(rejected["pricing_status"], "nonzero-or-unknown")

    def test_probe_verifies_ox_pool_only_with_local_model_and_zero_public_price(self) -> None:
        catalog, _ = router._load_catalog()

        def metadata(_harnesses, harness, arguments, _catalog):
            if harness == "opencode" and arguments == ["models"]:
                return {
                    "ok": True,
                    "stdout": "openrouter/stealth/ox-alpha\n",
                    "stderr": "",
                }
            return {"ok": False, "stdout": "", "stderr": ""}

        zero_price = {
            "available": True,
            "model_id": "stealth/ox-alpha",
            "price_source": "public-models-api",
            "zero_price_verified": True,
            "pricing_status": "zero",
        }
        def run_probe(price_status):
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        cli,
                        "_binary_versions",
                        return_value={
                            "opencode": {"available": True, "binary": "/opencode"}
                        },
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        cli, "_run_harness_metadata", side_effect=metadata
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        cli,
                        "_openhands_subscription_auth_status",
                        return_value={"authenticated": False},
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        cli,
                        "_grok_subscription_auth_status",
                        return_value={
                            "authenticated": False,
                            "entitlement_verified": False,
                            "status": "missing",
                            "subscription_tier": None,
                            "account_binding_sha256": None,
                        },
                    )
                )
                stack.enter_context(
                    mock.patch.object(cli, "_resolve_executable", return_value=None)
                )
                stack.enter_context(
                    mock.patch.object(
                        cli,
                        "_openrouter_ox_alpha_price_status",
                        return_value=price_status,
                    )
                )
                return cli._probe(catalog)

        verified = run_probe(zero_price)
        self.assertIn("openrouter-ox-alpha-preview", verified["verified_quota_pools"])
        self.assertTrue(verified["providers"]["openrouter"]["zero_price_verified"])
        self.assertNotIn("opencode-free", verified["verified_quota_pools"])

        nonzero_price = {
            **zero_price,
            "zero_price_verified": False,
            "pricing_status": "nonzero-or-unknown",
        }
        rejected = run_probe(nonzero_price)
        self.assertNotIn("openrouter-ox-alpha-preview", rejected["verified_quota_pools"])

    def test_probe_write_clears_ox_price_freshness_without_explicit_reverification(self) -> None:
        _, validation = router._load_catalog()
        first = {
            "schema_version": 2,
            "observed_at": "2026-08-24T05:00:00Z",
            "harnesses": {},
            "providers": {
                "openrouter": {
                    "available": True,
                    "model_id": "stealth/ox-alpha",
                    "price_source": "public-models-api",
                    "zero_price_verified": True,
                    "pricing_status": "zero",
                }
            },
            "verified_quota_pools": ["openrouter-ox-alpha-preview"],
            "api_key_environment_scrubbed": [],
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        first["catalog_probe_sha256"] = cli._probe_digest(first)
        cli._write_probe(first, validation)
        stored = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(
            stored["pools"]["openrouter-ox-alpha-preview"]["verified_at"],
            first["observed_at"],
        )

        second = {
            **first,
            "observed_at": "2026-08-24T05:45:00Z",
            "providers": {
                "openrouter": {
                    **first["providers"]["openrouter"],
                    "zero_price_verified": False,
                    "pricing_status": "nonzero-or-unknown",
                }
            },
            "verified_quota_pools": [],
        }
        second["catalog_probe_sha256"] = cli._probe_digest(second)
        cli._write_probe(second, validation)
        stored = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertNotIn("verified_at", stored["pools"]["openrouter-ox-alpha-preview"])

    def test_opencode_free_entitlement_accepts_current_builtin_free_models_only(self) -> None:
        self.assertTrue(cli._opencode_free_model_verified(["opencode/hy3-free"]))
        self.assertTrue(cli._opencode_free_model_verified(["opencode/future:free"]))
        self.assertFalse(
            cli._opencode_free_model_verified(["openrouter/stealth/ox-alpha"])
        )
        self.assertFalse(
            cli._opencode_free_model_verified(["openrouter/example/model:free"])
        )
        self.assertFalse(cli._opencode_free_model_verified(["opencode/paid-model"]))

    def test_state_write_lock_is_private_and_wraps_mutation(self) -> None:
        lock = self.state.parent / ".coding-agent-router-state.lock"
        self.assertFalse(lock.exists())
        with cli._exclusive_state_write_lock(self.state):
            self.assertTrue(lock.is_file())
            self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

        active = {"value": False}

        @contextlib.contextmanager
        def tracked_lock(_path: Path):
            active["value"] = True
            try:
                yield
            finally:
                active["value"] = False

        def observed(_arguments, _catalog, _validation):
            self.assertTrue(active["value"])
            return {"recorded": True}

        arguments = mock.Mock()
        with (
            mock.patch.object(cli, "_exclusive_state_write_lock", tracked_lock),
            mock.patch.object(cli, "_observe_locked", side_effect=observed),
        ):
            result = cli._observe(arguments, {}, {})
        self.assertEqual(result, {"recorded": True})
        self.assertFalse(active["value"])

    def test_atomic_write_keeps_private_mode_without_path_chmod(self) -> None:
        with mock.patch.object(cli.os, "chmod") as path_chmod:
            cli._atomic_write_private_json(self.state, {"schema_version": 2})
        path_chmod.assert_not_called()
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)

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
                "grok-com": {
                    "status": "available",
                    "verified_at": "2026-07-19T00:00:00Z",
                },
                "claude-pro": {"status": "unknown"},
                "jules-account": {
                    "status": "unknown",
                    "verified_at": "2026-07-19T00:00:00Z",
                },
                "opencode-free": {"status": "unknown"},
                "openhands-account": {"status": "unknown"},
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
            "verified_quota_pools": ["opencode-free", "openhands-account"],
            "api_key_environment_scrubbed": [],
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        probe["catalog_probe_sha256"] = cli._probe_digest(probe)
        cli._write_probe(probe, validation)
        stored = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(stored["history"], initial["history"])
        self.assertEqual(stored["routes"], initial["routes"])
        self.assertNotIn("verified_at", stored["pools"]["grok-com"])
        self.assertNotIn("verified_at", stored["pools"]["jules-account"])
        self.assertEqual(
            stored["pools"]["opencode-free"]["verified_at"], observed_at
        )
        self.assertEqual(
            stored["pools"]["openhands-account"]["verified_at"], observed_at
        )
        self.assertNotIn("verified_at", stored["pools"]["claude-pro"])

    def test_probe_rejects_unknown_verified_pool_without_rewrite(self) -> None:
        _, validation = router._load_catalog()
        initial = {
            "schema_version": 2,
            "updated_at": cli._iso_now(),
            "catalog_sha256": validation["catalog_sha256"],
            "catalog": {},
            "pools": {},
            "routes": {},
            "history": {"marker": 1},
        }
        self.state.write_text(json.dumps(initial), encoding="utf-8")
        os.chmod(self.state, 0o600)
        probe = {
            "schema_version": 2,
            "observed_at": cli._iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": ["unknown-pool"],
            "api_key_environment_scrubbed": [],
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        probe["catalog_probe_sha256"] = cli._probe_digest(probe)
        with self.assertRaisesRegex(
            cli.CodingAgentRouterCliError, "verified_quota_pools"
        ):
            cli._write_probe(probe, validation)
        self.assertEqual(
            json.loads(self.state.read_text(encoding="utf-8")), initial
        )

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

    def test_set_quota_registers_ox_alpha_openrouter_preview_pool_as_unknown(
        self,
    ) -> None:
        status, _ = self._main(
            [
                "set-quota",
                "--pool",
                "openrouter-ox-alpha-preview",
                "--status",
                "unknown",
            ]
        )
        self.assertEqual(status, 0)
        pool = json.loads(self.state.read_text(encoding="utf-8"))["pools"][
            "openrouter-ox-alpha-preview"
        ]
        self.assertEqual(pool["status"], "unknown")
        allowed, reasons, _, execution = router._pool_gate(
            "openrouter-ox-alpha-preview",
            router._load_catalog()[0],
            {"pools": {"openrouter-ox-alpha-preview": pool}},
            critical=False,
        )
        self.assertFalse(allowed)
        self.assertIn("zero-cost evidence is missing", reasons[0])
        self.assertFalse(execution)

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

    def test_probe_digest_binds_scrub_claim(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": cli._iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": [],
            "api_key_environment_scrubbed": ["OPENAI_API_KEY"],
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        digest = cli._probe_digest(probe)
        probe["api_key_environment_scrubbed"] = []
        self.assertNotEqual(digest, cli._probe_digest(probe))

    def test_metadata_output_limit_is_enforced_while_child_is_running(self) -> None:
        catalog, _ = router._load_catalog()
        with mock.patch.object(cli, "MAX_COMMAND_OUTPUT_BYTES", 1024):
            result = cli._run_metadata(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"],
                catalog,
                timeout=5,
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_type"], "output_limit")

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


    def test_openhands_auth_probe_is_secret_free_and_validates_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            auth = home / ".openhands" / "auth"
            auth.mkdir(parents=True, mode=0o700)
            auth.chmod(0o700)
            path = auth / "openai_oauth.json"
            path.write_text(json.dumps({
                "type": "oauth",
                "vendor": "openai",
                "access_token": "not-returned",
                "refresh_token": "not-returned",
                "expires_at": 2_000_000,
            }), encoding="utf-8")
            path.chmod(0o600)
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("path read forbidden")):
                status = cli._openhands_subscription_auth_status(home=home, now_ms=1_000_000)
            self.assertEqual(status, {
                "authenticated": True,
                "provider": "openai",
                "status": "valid",
                "storage_mode_ok": True,
            })
            self.assertNotIn("token", json.dumps(status).lower())

    def test_openhands_auth_probe_rejects_expired_or_unsafe_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            auth = home / ".openhands" / "auth"
            auth.mkdir(parents=True, mode=0o700)
            path = auth / "openai_oauth.json"
            path.write_text(json.dumps({
                "type": "oauth",
                "vendor": "openai",
                "access_token": "x",
                "refresh_token": "y",
                "expires_at": 1_000_000,
            }), encoding="utf-8")
            path.chmod(0o600)
            expired = cli._openhands_subscription_auth_status(home=home, now_ms=1_000_000)
            self.assertEqual(expired["status"], "expired")
            path.chmod(0o644)
            unsafe = cli._openhands_subscription_auth_status(home=home, now_ms=0)
            self.assertEqual(unsafe["status"], "unsafe-storage")


    def test_openhands_auth_probe_rejects_symlink_and_oversized_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            auth = home / ".openhands" / "auth"
            auth.mkdir(parents=True, mode=0o700)
            target = auth / "target.json"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            (auth / "openai_oauth.json").symlink_to(target.name)
            linked = cli._openhands_subscription_auth_status(home=home, now_ms=0)
            self.assertFalse(linked["authenticated"])
            self.assertIn(linked["status"], {"unreadable", "unsafe-storage"})

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            auth = home / ".openhands" / "auth"
            auth.mkdir(parents=True, mode=0o700)
            path = auth / "openai_oauth.json"
            path.write_bytes(b"x" * (64 * 1024 + 1))
            path.chmod(0o600)
            oversized = cli._openhands_subscription_auth_status(home=home, now_ms=0)
            self.assertFalse(oversized["authenticated"])
            self.assertIn(oversized["status"], {"invalid", "unsafe-storage"})



if __name__ == "__main__":
    unittest.main()
