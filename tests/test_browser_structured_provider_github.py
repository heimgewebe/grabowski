from __future__ import annotations

import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_browser_structured_provider_github as github_provider
import grabowski_browser_structured_tools as structured_tools


REAL_EFFECT_RESOLVER = structured_tools._default_effect_resolver
TARGET = "https://api.github.com/repos/heimgewebe/grabowski"
TEST_EFFECTS = {
    "read": {
        "admission": "implemented",
        "requires_operator_mutation": False,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    }
}


def _effect_resolver(name: str):
    return TEST_EFFECTS.get(name)


def _payload(**overrides):
    value = {
        "name": "grabowski",
        "full_name": "heimgewebe/grabowski",
        "owner": {"login": "heimgewebe", "token_like_extra": "Bearer never-project-me"},
        "default_branch": "main",
        "visibility": "public",
        "private": False,
        "fork": False,
        "archived": False,
        "disabled": False,
        "open_issues_count": 17,
        "description": "Authorization: top-secret-extra-field",
        "headers": {"Authorization": "Bearer should-not-escape"},
    }
    value.update(overrides)
    return value


def _observation(payload=None, *, status=200, content_type="application/json; charset=utf-8"):
    if payload is None:
        payload = _payload()
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    return github_provider._HttpObservation(status=status, content_type=content_type, body=body)


class EffectCatalogCase(unittest.TestCase):
    def setUp(self) -> None:
        self.effect_patch = mock.patch.object(
            structured_tools, "_default_effect_resolver", _effect_resolver
        )
        self.effect_patch.start()
        self.addCleanup(self.effect_patch.stop)


class ContractTests(EffectCatalogCase):
    def test_fixed_provider_contract_uses_existing_read_effect(self) -> None:
        contract = github_provider.provider_contract()
        self.assertEqual(contract["provider_id"], "github.public-rest")
        self.assertEqual(contract["origins"], ["https://api.github.com"])
        self.assertEqual(
            contract["operations"],
            [{"operation": "repository.read", "effect_class": "read"}],
        )
        self.assertFalse(contract["provider_execution_available"])
        self.assertFalse(contract["automatic_routing_available"])

    def test_provider_api_has_no_router_or_credential_parameters(self) -> None:
        self.assertEqual(
            list(inspect.signature(github_provider.execute_repository_read).parameters),
            ["target_url"],
        )
        for name in (
            "select_provider",
            "route_provider",
            "rank_providers",
            "fallback_provider",
            "default_provider",
            "set_token",
            "set_headers",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(github_provider, name))

    def test_valid_target_assesses_only_explicit_provider(self) -> None:
        assessment = github_provider.assess_repository_read(TARGET)
        self.assertEqual(assessment["provider_id"], "github.public-rest")
        self.assertEqual(assessment["operation"], "repository.read")
        self.assertEqual(assessment["effect_class"], "read")
        self.assertTrue(assessment["eligible"])
        self.assertFalse(assessment["provider_execution_performed"])
        self.assertFalse(assessment["automatic_route_selected"])
        self.assertFalse(assessment["retry_authorized"])

    def test_missing_real_effect_catalog_fails_closed(self) -> None:
        with mock.patch.object(
            structured_tools, "_default_effect_resolver", REAL_EFFECT_RESOLVER
        ):
            with mock.patch.object(
                structured_tools.importlib,
                "import_module",
                side_effect=ModuleNotFoundError("mcp"),
            ):
                with self.assertRaisesRegex(
                    structured_tools.StructuredToolContractError,
                    "effect-catalog-unavailable",
                ):
                    github_provider.provider_contract()


class TargetAndTransportTests(EffectCatalogCase):
    def test_invalid_targets_fail_before_provider_io(self) -> None:
        targets = [
            "http://api.github.com/repos/heimgewebe/grabowski",
            "https://example.com/repos/heimgewebe/grabowski",
            "https://api.github.com/repos/heimgewebe/grabowski?token=secret",
            "https://api.github.com/repos/heimgewebe/grabowski#fragment",
            "https://user@api.github.com/repos/heimgewebe/grabowski",
            "https://api.github.com/repos/heimgewebe/grabowski/extra",
            "https://api.github.com/repos/heimgewebe",
            "https://api.github.com/repos/heimgewebe/..",
            "https://api.github.com/repos/heimgewebe/%2e%2e",
            "https://API.github.com/repos/heimgewebe/grabowski",
            "https://api.github.com:443/repos/heimgewebe/grabowski",
        ]
        for target in targets:
            with self.subTest(target=target):
                with mock.patch.object(
                    github_provider,
                    "_https_get_once",
                    side_effect=AssertionError("provider transport must not start"),
                ) as transport:
                    result = github_provider.execute_repository_read(target)
                self.assertEqual(result["state"], "failed_closed")
                self.assertFalse(result["provider_execution_performed"])
                self.assertEqual(result["effect_state"], "not_started")
                self.assertFalse(result["retry_authorized"])
                transport.assert_not_called()

    def test_https_transport_is_fixed_host_fixed_headers_and_one_get(self) -> None:
        captured = {"requests": []}
        body = json.dumps(_payload()).encode("utf-8")

        class Response:
            status = 200

            def getheader(self, name, default=None):
                values = {
                    "Content-Length": str(len(body)),
                    "Content-Type": "application/json; charset=utf-8",
                }
                return values.get(name, default)

            def read(self, limit):
                expected = github_provider.MAX_RESPONSE_BYTES + 1
                if limit != expected:
                    raise AssertionError(f"unexpected read bound: {limit}")
                return body

        class Connection:
            def __init__(self, host, *, port, timeout, context):
                captured["host"] = host
                captured["port"] = port
                captured["timeout"] = timeout
                captured["context"] = context

            def request(self, method, path, *, headers):
                captured["requests"].append((method, path, dict(headers)))

            def getresponse(self):
                return Response()

            def close(self):
                captured["closed"] = True

        with mock.patch.object(github_provider.http.client, "HTTPSConnection", Connection):
            observation = github_provider._https_get_once("/repos/heimgewebe/grabowski")
        self.assertEqual(observation.status, 200)
        self.assertEqual(captured["host"], "api.github.com")
        self.assertEqual(captured["port"], 443)
        self.assertEqual(captured["timeout"], 10)
        self.assertEqual(
            captured["requests"],
            [
                (
                    "GET",
                    "/repos/heimgewebe/grabowski",
                    {
                        "Accept": "application/vnd.github+json",
                        "User-Agent": "grabowski-structured-provider-github/1",
                    },
                )
            ],
        )
        self.assertTrue(captured["closed"])


class ExecutionTests(EffectCatalogCase):
    def _run_with(self, observation):
        with mock.patch.object(
            github_provider, "_https_get_once", return_value=observation
        ) as transport:
            result = github_provider.execute_repository_read(TARGET)
        transport.assert_called_once_with("/repos/heimgewebe/grabowski")
        return result

    def test_success_returns_bounded_projection_and_existing_normalized_outcome(self) -> None:
        result = self._run_with(_observation())
        self.assertEqual(result["state"], "succeeded")
        self.assertTrue(result["ok"])
        self.assertEqual(result["result_code"], "ok")
        self.assertEqual(result["effect_state"], "observed")
        self.assertEqual(result["http_status"], 200)
        self.assertTrue(result["provider_execution_performed"])
        self.assertFalse(result["automatic_route_selected"])
        self.assertFalse(result["retry_authorized"])
        self.assertEqual(
            result["repository"],
            {
                "full_name": "heimgewebe/grabowski",
                "owner_login": "heimgewebe",
                "name": "grabowski",
                "default_branch": "main",
                "visibility": "public",
                "private": False,
                "fork": False,
                "archived": False,
                "disabled": False,
                "open_issues_count": 17,
            },
        )
        outcome = result["outcome"]
        self.assertEqual(outcome["provider_id"], "github.public-rest")
        self.assertEqual(outcome["operation"], "repository.read")
        self.assertEqual(outcome["effect_class"], "read")
        self.assertFalse(outcome["normalizer_execution_performed"])
        self.assertFalse(outcome["automatic_route_selected"])
        self.assertFalse(outcome["retry_authorized"])
        self.assertTrue(outcome["authoritative_readback_required"])
        self.assertFalse(outcome["readback_grants_retry_authority"])
        receipt = result["provider_receipt"]
        self.assertEqual(receipt["target_sha256"], outcome["target"]["target_sha256"])
        self.assertEqual(
            receipt["effect_contract_sha256"], outcome["effect_contract_sha256"]
        )
        self.assertRegex(receipt["provider_receipt_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(receipt["provider_readback_sha256"], r"^[0-9a-f]{64}$")

    def test_unselected_response_fields_and_secrets_are_never_projected(self) -> None:
        result = self._run_with(_observation())
        serialized = json.dumps(result, sort_keys=True)
        for secret in (
            "never-project-me",
            "top-secret-extra-field",
            "should-not-escape",
            "Authorization",
            "Bearer",
        ):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, serialized)
        self.assertNotIn("headers", result)
        self.assertNotIn("body", result)

    def test_redirect_is_observed_failure_and_never_followed(self) -> None:
        result = self._run_with(_observation(status=301))
        self.assertEqual(result["state"], "failed_closed")
        self.assertEqual(result["result_code"], "http_status")
        self.assertEqual(result["http_status"], 301)
        self.assertEqual(result["effect_state"], "observed")
        self.assertFalse(result["retry_authorized"])
        self.assertNotIn("repository", result)

    def test_oversize_body_fails_closed_even_if_transport_double_misbehaves(self) -> None:
        observation = github_provider._HttpObservation(
            status=200,
            content_type="application/json",
            body=b"x" * (github_provider.MAX_RESPONSE_BYTES + 1),
        )
        result = self._run_with(observation)
        self.assertEqual(result["state"], "failed_closed")
        self.assertEqual(result["result_code"], "response_too_large")
        self.assertEqual(result["response_bytes"], github_provider.MAX_RESPONSE_BYTES + 1)
        self.assertFalse(result["retry_authorized"])

    def test_invalid_content_type_and_json_fail_closed(self) -> None:
        wrong_type = self._run_with(_observation(content_type="text/html"))
        self.assertEqual(wrong_type["result_code"], "content_type_invalid")
        self.assertFalse(wrong_type["retry_authorized"])

        malformed = self._run_with(
            github_provider._HttpObservation(
                status=200,
                content_type="application/json",
                body=b"{not-json",
            )
        )
        self.assertEqual(malformed["result_code"], "response_json_invalid")
        self.assertFalse(malformed["retry_authorized"])

    def test_response_schema_is_bounded_and_target_bound(self) -> None:
        cases = [
            ({"name": "grabowski"}, "response_schema_invalid"),
            (_payload(owner={"login": "someone-else"}), "response_target_mismatch"),
            (_payload(private="false"), "response_schema_invalid"),
            (_payload(open_issues_count=-1), "response_schema_invalid"),
            (_payload(default_branch="x" * 256), "response_schema_invalid"),
        ]
        for payload, result_code in cases:
            with self.subTest(result_code=result_code):
                result = self._run_with(_observation(payload))
                self.assertEqual(result["state"], "failed_closed")
                self.assertEqual(result["result_code"], result_code)
                self.assertEqual(result["effect_state"], "observed")
                self.assertFalse(result["retry_authorized"])

    def test_transport_failure_is_unknown_and_never_authorizes_retry(self) -> None:
        failure = github_provider.GitHubStructuredProviderError(
            "transport_error",
            "simulated lost transport",
            effect_state="unknown",
            authoritative_readback=False,
        )
        with mock.patch.object(github_provider, "_https_get_once", side_effect=failure):
            result = github_provider.execute_repository_read(TARGET)
        self.assertEqual(result["state"], "failed_closed")
        self.assertEqual(result["result_code"], "transport_error")
        self.assertEqual(result["effect_state"], "unknown")
        self.assertFalse(result["outcome"]["authoritative_readback_observed"])
        self.assertFalse(result["outcome"]["retry_authorized"])
        self.assertFalse(result["outcome"]["readback_grants_retry_authority"])

    def test_normalizer_rereads_effect_catalog_and_fails_closed_on_drift(self) -> None:
        calls = 0
        conservative = {
            "admission": "implemented",
            "requires_operator_mutation": False,
            "ambiguous_outcome": {
                "retry_authorized": False,
                "authoritative_readback_required": True,
                "readback_grants_retry_authority": False,
            },
        }
        blocked = {**conservative, "admission": "fail_closed"}

        def resolver(effect_class):
            nonlocal calls
            self.assertEqual(effect_class, "read")
            calls += 1
            return conservative if calls <= 2 else blocked

        with mock.patch.object(structured_tools, "_default_effect_resolver", resolver):
            with mock.patch.object(
                github_provider, "_https_get_once", return_value=_observation()
            ):
                result = github_provider.execute_repository_read(TARGET)
        self.assertGreaterEqual(calls, 3)
        self.assertEqual(result["state"], "failed_closed")
        self.assertEqual(result["result_code"], "receipt_normalization_failed")
        self.assertEqual(result["normalization_error_code"], "provider-not-eligible")
        self.assertFalse(result["retry_authorized"])


if __name__ == "__main__":
    unittest.main()
