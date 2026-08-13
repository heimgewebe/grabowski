from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import unittest
import urllib.error

import grabowski_n8n_provider as provider


PROFILE = provider.PROVIDER_PROFILES["forrest-transcription-post-done-v1"]


def workflow(*, version: str = "v1", final: bool = False, legacy: bool = False) -> dict:
    connections = {}
    if final:
        connections[PROFILE.source_node_name] = {
            "main": [[{"node": PROFILE.downstream_node_name, "type": "main", "index": 0}]]
        }
    result = {
        "id": PROFILE.workflow_id,
        "versionId": version,
        "active": False,
        "name": "Forrest Core",
        "nodes": [
            {
                "id": PROFILE.source_node_id,
                "name": PROFILE.source_node_name,
                "type": PROFILE.source_node_type,
                "typeVersion": PROFILE.source_type_version,
                "parameters": {"resource": "audio", "operation": "transcribe"},
                "credentials": {"openAiApi": {"id": "credential-id", "name": "managed"}},
            },
            {
                "id": "agent-node-id",
                "name": PROFILE.downstream_node_name,
                "type": "@n8n/n8n-nodes-langchain.agent",
                "typeVersion": 2,
                "parameters": {},
            },
        ],
        "connections": connections,
        "settings": {},
    }
    if legacy:
        result["description"] = "legacy /transcribe endpoint"
    return result


def raw(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class FakeResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, limit: int = -1) -> bytes:
        if limit is None or limit < 0:
            return self.body
        return self.body[:limit]


class ScriptedOpen:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "data": request.data,
                "headers": dict(request.header_items()),
                "timeout": timeout,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected provider request")
        status, body = self.responses.pop(0)
        return FakeResponse(status, body)


class N8nProviderTests(unittest.TestCase):
    def test_public_profile_is_fixed_to_forrest_target(self) -> None:
        contract = provider.public_profile(PROFILE.name)
        self.assertEqual("https://tb5mwp.app.n8n.cloud", contract["origin"])
        self.assertEqual("7uokWleaiOP5yewH", contract["workflowId"])
        self.assertEqual("817cafb7-5d86-4419-a653-e5563f88046b", contract["sourceNodeId"])
        self.assertEqual("AI Agent", contract["downstreamNodeName"])
        with self.assertRaises(provider.N8nProviderError):
            provider.public_profile("arbitrary-provider")

    def test_verify_is_read_only_and_secret_free(self) -> None:
        body = raw(workflow())
        opener = ScriptedOpen([(200, body)])
        result = provider.verify(
            provider_profile=PROFILE.name,
            secret_data=b"n8n-secret-value\n",
            expected_state="isolated",
            urlopen=opener,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["providerMutationPerformed"])
        self.assertEqual("isolated", result["observed"]["state"])
        self.assertEqual(hashlib.sha256(body).hexdigest(), result["observed"]["responseSha256"])
        self.assertEqual(["GET"], [item["method"] for item in opener.requests])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("n8n-secret-value", serialized)
        self.assertNotIn("credential-id", serialized)
        self.assertNotIn("managed", serialized)

    def test_apply_changes_exactly_one_edge_and_reads_back(self) -> None:
        before = workflow(version="v1")
        before_raw = raw(before)
        after = workflow(version="v2", final=True)
        after_raw = raw(after)
        opener = ScriptedOpen([(200, before_raw), (200, before_raw), (200, b"{}"), (200, after_raw)])
        result = provider.apply(
            provider_profile=PROFILE.name,
            secret_data=b"n8n-secret-value\n",
            expected_version_id="v1",
            expected_response_sha256=hashlib.sha256(before_raw).hexdigest(),
            urlopen=opener,
        )
        self.assertTrue(result["providerMutationPerformed"])
        self.assertEqual("v1", result["pre"]["versionId"])
        self.assertEqual(result["pre"], result["preWrite"])
        self.assertEqual("exact-preconditions-revalidated-before-put-no-atomic-provider-cas", result["concurrencyContract"])
        self.assertEqual("v2", result["post"]["versionId"])
        self.assertEqual(["GET", "GET", "PUT", "GET"], [item["method"] for item in opener.requests])
        put = json.loads(opener.requests[2]["data"])
        self.assertEqual(
            [[{"node": PROFILE.downstream_node_name, "type": "main", "index": 0}]],
            put["connections"][PROFILE.source_node_name]["main"],
        )
        baseline = provider._update_payload(before)
        comparison = deepcopy(put)
        comparison["connections"] = baseline["connections"]
        self.assertEqual(baseline, comparison)
        self.assertNotIn("n8n-secret-value", json.dumps(result, sort_keys=True))

    def test_apply_revalidates_exact_snapshot_immediately_before_put(self) -> None:
        before = workflow(version="v1")
        before_raw = raw(before)
        concurrent = workflow(version="v1")
        concurrent["description"] = "concurrent external edit"
        concurrent_raw = raw(concurrent)
        opener = ScriptedOpen([(200, before_raw), (200, concurrent_raw)])
        with self.assertRaisesRegex(provider.N8nProviderError, "SHA-256 mismatch"):
            provider.apply(
                provider_profile=PROFILE.name,
                secret_data=b"n8n-secret-value\n",
                expected_version_id="v1",
                expected_response_sha256=hashlib.sha256(before_raw).hexdigest(),
                urlopen=opener,
            )
        self.assertEqual(["GET", "GET"], [item["method"] for item in opener.requests])

    def test_apply_revision_mismatch_stops_before_put(self) -> None:
        before_raw = raw(workflow(version="v1"))
        opener = ScriptedOpen([(200, before_raw)])
        with self.assertRaisesRegex(provider.N8nProviderError, "SHA-256 mismatch"):
            provider.apply(
                provider_profile=PROFILE.name,
                secret_data=b"n8n-secret-value\n",
                expected_version_id="v1",
                expected_response_sha256="0" * 64,
                urlopen=opener,
            )
        self.assertEqual(["GET"], [item["method"] for item in opener.requests])

    def test_apply_rejects_nonisolated_source_before_put(self) -> None:
        before_raw = raw(workflow(version="v1", final=True))
        opener = ScriptedOpen([(200, before_raw)])
        with self.assertRaisesRegex(provider.N8nProviderError, "not isolated"):
            provider.apply(
                provider_profile=PROFILE.name,
                secret_data=b"n8n-secret-value\n",
                expected_version_id="v1",
                expected_response_sha256=hashlib.sha256(before_raw).hexdigest(),
                urlopen=opener,
            )
        self.assertEqual(["GET"], [item["method"] for item in opener.requests])

    def test_legacy_reference_blocks_verify(self) -> None:
        body = raw(workflow(legacy=True))
        opener = ScriptedOpen([(200, body)])
        with self.assertRaisesRegex(provider.N8nProviderError, "forbidden legacy"):
            provider.verify(
                provider_profile=PROFILE.name,
                secret_data=b"n8n-secret-value\n",
                expected_state="isolated",
                urlopen=opener,
            )

    def test_inline_secret_like_value_blocks_payload(self) -> None:
        before = workflow(version="v1")
        before["nodes"][1]["parameters"]["api_key"] = "embedded"
        before_raw = raw(before)
        opener = ScriptedOpen([(200, before_raw)])
        with self.assertRaisesRegex(provider.N8nProviderError, "embedded secret-like"):
            provider.apply(
                provider_profile=PROFILE.name,
                secret_data=b"n8n-secret-value\n",
                expected_version_id="v1",
                expected_response_sha256=hashlib.sha256(before_raw).hexdigest(),
                urlopen=opener,
            )
        self.assertEqual(["GET"], [item["method"] for item in opener.requests])

    def test_api_key_requires_one_line(self) -> None:
        opener = ScriptedOpen([])
        with self.assertRaisesRegex(provider.N8nProviderError, "exactly one"):
            provider.verify(
                provider_profile=PROFILE.name,
                secret_data=b"first\nsecond\n",
                expected_state="isolated",
                urlopen=opener,
            )
        self.assertEqual([], opener.requests)


if __name__ == "__main__":
    unittest.main()
