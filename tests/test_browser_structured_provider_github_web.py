from __future__ import annotations

import inspect
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_browser_structured_provider_github_web as web  # noqa: E402
import grabowski_browser_structured_tools as structured_tools  # noqa: E402
from grabowski_browser_structured_tools import StructuredToolProviderRegistry  # noqa: E402

TARGET = "https://github.com/heimgewebe/grabowski"
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


def _html(
    *,
    full_name: str = "heimgewebe/grabowski",
    public: str = "true",
    prefix: str = "",
    suffix: str = "",
) -> bytes:
    return (
        prefix
        + "<html><head>"
        + f'<meta name="octolytics-dimension-repository_nwo" content="{full_name}">'
        + f'<meta name="octolytics-dimension-repository_public" content="{public}">'
        + suffix
        + "</head><body></body></html>"
    ).encode("utf-8")


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        location: str | None = None,
    ) -> None:
        self.status = status
        self._body = body
        self._headers = {"Content-Type": content_type}
        if location is not None:
            self._headers["Location"] = location
        self.read_args: list[int] = []

    def getheader(self, name: str, default: str = "") -> str:
        return self._headers.get(name, default)

    def read(self, amount: int) -> bytes:
        self.read_args.append(amount)
        return self._body[:amount]


class _FakeConnection:
    instances: list["_FakeConnection"] = []
    response_factory = staticmethod(lambda: _FakeResponse(_html()))

    def __init__(self, host: str, *, port: int, timeout: int, context: object) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.response = type(self).response_factory()
        self.closed = False
        type(self).instances.append(self)

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        self.requests.append((method, path, dict(headers)))

    def getresponse(self) -> _FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class GitHubWebStructuredProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.effect_patch = mock.patch.object(
            structured_tools, "_default_effect_resolver", _effect_resolver
        )
        self.effect_patch.start()
        self.addCleanup(self.effect_patch.stop)
        _FakeConnection.instances.clear()
        _FakeConnection.response_factory = staticmethod(lambda: _FakeResponse(_html()))

    def test_contract_is_exact_explicit_read_provider(self) -> None:
        contract = web.provider_contract()
        self.assertEqual(contract["provider_id"], "github.public-web")
        self.assertEqual(contract["origins"], ["https://github.com"])
        self.assertEqual(
            contract["operations"],
            [{"operation": "repository.read", "effect_class": "read"}],
        )
        self.assertFalse(contract["automatic_routing_available"])
        self.assertFalse(contract["provider_execution_available"])

    def test_execution_api_exposes_only_target_not_credentials_or_headers(self) -> None:
        self.assertEqual(list(inspect.signature(web.execute_repository_read).parameters), ["target_url"])
        self.assertEqual(list(inspect.signature(web.assess_repository_read).parameters), ["target_url"])
        forbidden = {
            "route_provider",
            "select_provider",
            "fallback_provider",
            "set_headers",
            "set_credentials",
            "browser_session",
        }
        self.assertTrue(forbidden.isdisjoint(vars(web)))

    def test_invalid_targets_fail_before_provider_io(self) -> None:
        invalid = [
            "http://github.com/heimgewebe/grabowski",
            "https://api.github.com/heimgewebe/grabowski",
            "https://github.com/heimgewebe/grabowski?tab=readme",
            "https://github.com/heimgewebe/grabowski#readme",
            "https://user@github.com/heimgewebe/grabowski",
            "https://github.com:443/heimgewebe/grabowski",
            "https://GitHub.com/heimgewebe/grabowski",
            "https://github.com/heimgewebe",
            "https://github.com/heimgewebe/grabowski/",
            "https://github.com/heimgewebe/grabowski/issues",
            "https://github.com//grabowski",
            "https://github.com/../grabowski",
            "https://github.com/%2e%2e/grabowski",
        ]
        with mock.patch.object(web, "_https_get_once") as get_once:
            for target in invalid:
                with self.subTest(target=target):
                    result = web.execute_repository_read(target)
                    self.assertEqual(result["state"], "failed_closed")
                    self.assertFalse(result["provider_execution_performed"])
                    self.assertFalse(result["retry_authorized"])
            get_once.assert_not_called()

    def test_assessment_accepts_only_exact_canonical_target(self) -> None:
        assessment = web.assess_repository_read(TARGET)
        self.assertTrue(assessment["eligible"])
        self.assertEqual(assessment["provider_id"], "github.public-web")
        self.assertEqual(assessment["operation"], "repository.read")
        noncanonical = web.assess_repository_read("https://github.com:443/heimgewebe/grabowski")
        self.assertFalse(noncanonical["eligible"])
        self.assertEqual(noncanonical["result_code"], "target_noncanonical")

    def test_https_transport_is_one_direct_bounded_anonymous_get(self) -> None:
        context = object()
        with (
            mock.patch.object(web.ssl, "create_default_context", return_value=context),
            mock.patch.object(web.http.client, "HTTPSConnection", _FakeConnection),
        ):
            observation = web._https_get_once("/heimgewebe/grabowski")
        self.assertEqual(len(_FakeConnection.instances), 1)
        connection = _FakeConnection.instances[0]
        self.assertEqual(connection.host, "github.com")
        self.assertEqual(connection.port, 443)
        self.assertEqual(connection.timeout, web.REQUEST_TIMEOUT_SECONDS)
        self.assertIs(connection.context, context)
        self.assertEqual(
            connection.requests,
            [
                (
                    "GET",
                    "/heimgewebe/grabowski",
                    {
                        "Accept": "text/html",
                        "User-Agent": "grabowski-structured-provider-github-web/1",
                    },
                )
            ],
        )
        self.assertEqual(connection.response.read_args, [web.MAX_HTML_PREFIX_BYTES])
        self.assertLessEqual(len(observation.body_prefix), web.MAX_HTML_PREFIX_BYTES)
        self.assertTrue(connection.closed)

    def test_redirect_is_observed_but_never_followed(self) -> None:
        _FakeConnection.response_factory = staticmethod(
            lambda: _FakeResponse(
                b"redirect",
                status=302,
                location="https://evil.example/repository",
            )
        )
        with mock.patch.object(web.http.client, "HTTPSConnection", _FakeConnection):
            result = web.execute_repository_read(TARGET)
        self.assertEqual(result["state"], "failed_closed")
        self.assertEqual(result["result_code"], "http_status")
        self.assertEqual(result["http_status"], 302)
        self.assertEqual(len(_FakeConnection.instances), 1)
        self.assertEqual(len(_FakeConnection.instances[0].requests), 1)
        self.assertFalse(result["retry_authorized"])

    def test_success_projects_only_allowlisted_identity_metadata(self) -> None:
        secret = "SHOULD-NOT-LEAK-123"
        body = _html(
            prefix=(
                f'<meta name="description" content="{secret}">'
                f'<script>window.secret="{secret}"</script>'
            ),
            suffix=f'<meta name="csrf-token" content="{secret}">',
        )
        observation = web._HttpObservation(200, "text/html; charset=utf-8", body)
        with mock.patch.object(web, "_https_get_once", return_value=observation):
            result = web.execute_repository_read(TARGET)
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(
            result["repository"],
            {
                "full_name": "heimgewebe/grabowski",
                "owner_login": "heimgewebe",
                "name": "grabowski",
                "visibility": "public",
                "private": False,
            },
        )
        self.assertNotIn(secret, repr(result))
        self.assertNotIn("raw_html", result)
        self.assertNotIn("headers", result)
        self.assertFalse(result["automatic_route_selected"])
        self.assertFalse(result["retry_authorized"])
        self.assertTrue(result["authoritative_readback_required"])
        self.assertFalse(result["readback_grants_retry_authority"])

    def test_receipt_binds_provider_operation_effect_and_target(self) -> None:
        observation = web._HttpObservation(200, "text/html", _html())
        assessment = web.provider_registry().assess(web.PROVIDER_ID, web.OPERATION, TARGET)
        with mock.patch.object(web, "_https_get_once", return_value=observation):
            result = web.execute_repository_read(TARGET)
        receipt = result["provider_receipt"]
        outcome = result["outcome"]
        self.assertEqual(receipt["provider_id"], assessment["provider_id"])
        self.assertEqual(receipt["operation"], assessment["operation"])
        self.assertEqual(receipt["effect_class"], "read")
        self.assertEqual(receipt["effect_contract_sha256"], assessment["effect_contract_sha256"])
        self.assertEqual(receipt["target_sha256"], assessment["target"]["target_sha256"])
        self.assertEqual(outcome["effect_contract_sha256"], receipt["effect_contract_sha256"])
        self.assertEqual(outcome["target"]["target_sha256"], receipt["target_sha256"])
        self.assertFalse(outcome["automatic_route_selected"])
        self.assertFalse(outcome["retry_authorized"])
        self.assertTrue(outcome["authoritative_readback_required"])
        self.assertFalse(outcome["readback_grants_retry_authority"])

    def test_effect_contract_digest_is_freshly_bound(self) -> None:
        normal = web.provider_registry().assess(web.PROVIDER_ID, web.OPERATION, TARGET)
        original_read = dict(TEST_EFFECTS["read"])
        changed_read = dict(original_read)
        changed_read["requires_operator_mutation"] = not original_read["requires_operator_mutation"]

        def resolver(effect_class: str):
            if effect_class == "read":
                return changed_read
            return TEST_EFFECTS.get(effect_class)

        registry = StructuredToolProviderRegistry(effect_resolver=resolver)
        registry.register(web.provider_spec())
        changed = registry.assess(web.PROVIDER_ID, web.OPERATION, TARGET)
        self.assertNotEqual(changed["effect_contract_sha256"], normal["effect_contract_sha256"])
        observation = web._HttpObservation(200, "text/html", _html())
        with (
            mock.patch.object(web, "provider_registry", return_value=registry),
            mock.patch.object(web, "_https_get_once", return_value=observation),
        ):
            result = web.execute_repository_read(TARGET)
        self.assertEqual(
            result["provider_receipt"]["effect_contract_sha256"],
            changed["effect_contract_sha256"],
        )
        self.assertEqual(
            result["outcome"]["effect_contract_sha256"],
            changed["effect_contract_sha256"],
        )

    def test_missing_duplicate_or_invalid_metadata_fail_closed(self) -> None:
        cases = {
            "missing": b"<html><head></head></html>",
            "duplicate": (
                _html()
                + b'<meta name="octolytics-dimension-repository_nwo" content="other/repo">'
            ),
            "bad-segment": _html(full_name="../grabowski"),
            "mismatch": _html(full_name="someone/else"),
            "not-public": _html(public="false"),
            "invalid-public": _html(public="TRUE"),
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                observation = web._HttpObservation(200, "text/html", body)
                with mock.patch.object(web, "_https_get_once", return_value=observation):
                    result = web.execute_repository_read(TARGET)
                self.assertEqual(result["state"], "failed_closed")
                self.assertTrue(result["provider_execution_performed"])
                self.assertFalse(result["retry_authorized"])
                self.assertTrue(result["authoritative_readback_required"])

    def test_status_content_type_and_utf8_failures_are_bounded(self) -> None:
        observations = [
            (web._HttpObservation(404, "text/html", b"not found"), "http_status"),
            (web._HttpObservation(200, "application/json", b"{}"), "content_type_invalid"),
            (web._HttpObservation(200, "text/html", b"\xff\xfe"), "response_html_invalid"),
        ]
        for observation, code in observations:
            with self.subTest(code=code):
                with mock.patch.object(web, "_https_get_once", return_value=observation):
                    result = web.execute_repository_read(TARGET)
                self.assertEqual(result["state"], "failed_closed")
                self.assertEqual(result["result_code"], code)
                self.assertFalse(result["retry_authorized"])
                self.assertNotIn("raw_html", result)
                self.assertNotIn("headers", result)

    def test_transport_unknown_never_authorizes_retry(self) -> None:
        error = web.GitHubWebStructuredProviderError(
            "transport_error",
            "network outcome unknown",
            effect_state="unknown",
            authoritative_readback=False,
        )
        with mock.patch.object(web, "_https_get_once", side_effect=error):
            result = web.execute_repository_read(TARGET)
        self.assertEqual(result["state"], "failed_closed")
        self.assertEqual(result["effect_state"], "unknown")
        self.assertFalse(result["retry_authorized"])
        self.assertTrue(result["authoritative_readback_required"])
        self.assertFalse(result["readback_grants_retry_authority"])
        self.assertFalse(result["outcome"]["retry_authorized"])

    def test_public_rest_backend_identity_is_unchanged(self) -> None:
        import grabowski_browser_structured_provider_github as rest

        contract = rest.provider_contract()
        self.assertEqual(contract["provider_id"], "github.public-rest")
        self.assertEqual(contract["origins"], ["https://api.github.com"])
        self.assertEqual(
            contract["operations"],
            [{"operation": "repository.read", "effect_class": "read"}],
        )


if __name__ == "__main__":
    unittest.main()
