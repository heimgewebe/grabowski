from __future__ import annotations

import unittest

import grabowski_grips as grips


PROFILE = "forrest-transcription-post-done-v1"
SECRET_SHA = "a" * 64
RESPONSE_SHA = "b" * 64


def verify_parameters() -> dict:
    return {
        "provider_profile": PROFILE,
        "secret_path": "/secret/provider-key",
        "expected_secret_sha256": SECRET_SHA,
        "expected_state": "isolated",
    }


def apply_parameters() -> dict:
    return {
        "provider_profile": PROFILE,
        "secret_path": "/secret/provider-key",
        "expected_secret_sha256": SECRET_SHA,
        "expected_version_id": "version-1",
        "expected_response_sha256": RESPONSE_SHA,
    }


class N8nGripContractTests(unittest.TestCase):
    def test_surface_publishes_read_and_apply_grips(self) -> None:
        contracts = {item["name"]: item for item in grips.grip_list("operator")["grips"]}
        self.assertEqual("read_only", contracts["n8n-workflow-edge-verify"]["effect"])
        self.assertEqual("mutating", contracts["n8n-workflow-edge-apply"]["effect"])
        self.assertIn("provider-post-readback", contracts["n8n-workflow-edge-apply"]["acceptance_ids"])
        self.assertIn("revision-cas-bound", contracts["n8n-workflow-edge-apply"]["acceptance_ids"])

    def test_verify_requires_dispatcher_and_never_falls_back_to_command_runner(self) -> None:
        called = []

        def command_runner(_cwd, _argv):
            called.append(True)
            raise AssertionError("generic command runner must not be used")

        result = grips.grip_run(
            "n8n-workflow-edge-verify",
            verify_parameters(),
            profile="operator",
            command_runner=command_runner,
        )
        self.assertEqual("blocked", result["status"])
        self.assertIn("dispatcher is unavailable", result["output"]["error"])
        self.assertEqual([], called)

    def test_verify_accepts_secret_free_semantic_readback(self) -> None:
        def dispatcher(operation: str, parameters: dict) -> dict:
            self.assertEqual("verify", operation)
            self.assertEqual(PROFILE, parameters["provider_profile"])
            return {
                "ok": True,
                "mode": "verify",
                "providerProfile": PROFILE,
                "providerMutationPerformed": False,
                "observed": {
                    "state": "isolated",
                    "versionId": "version-1",
                    "responseSha256": RESPONSE_SHA,
                    "outgoingCount": 0,
                },
            }

        result = grips.grip_run(
            "n8n-workflow-edge-verify",
            verify_parameters(),
            profile="operator",
            n8n_provider_dispatcher=dispatcher,
        )
        self.assertEqual("passed", result["status"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["provider-readback"])
        self.assertEqual("pass", checks["semantic-state-bound"])
        self.assertEqual("pass", checks["no-provider-mutation"])

    def test_verify_rejects_unknown_fields_before_dispatch(self) -> None:
        called = []
        parameters = verify_parameters()
        parameters["url"] = "https://example.invalid"
        result = grips.grip_run(
            "n8n-workflow-edge-verify",
            parameters,
            profile="operator",
            n8n_provider_dispatcher=lambda *_: called.append(True),
        )
        self.assertEqual("blocked", result["status"])
        self.assertIn("unknown n8n provider grip field", result["output"]["error"])
        self.assertEqual([], called)

    def test_apply_requires_explicit_mutation_permission(self) -> None:
        called = []
        result = grips.grip_run(
            "n8n-workflow-edge-apply",
            apply_parameters(),
            profile="operator",
            allow_mutation=False,
            n8n_provider_dispatcher=lambda *_: called.append(True),
        )
        self.assertEqual("blocked", result["status"])
        self.assertIn("allow_mutation=true", result["output"]["error"])
        self.assertEqual([], called)

    def test_apply_accepts_only_revision_bound_single_edge_post_readback(self) -> None:
        def dispatcher(operation: str, parameters: dict) -> dict:
            self.assertEqual("apply", operation)
            return {
                "ok": True,
                "mode": "apply",
                "providerProfile": PROFILE,
                "providerMutationPerformed": True,
                "effect": {
                    "kind": "n8n-workflow-single-edge-add",
                    "sourceNodeName": "Transcribe Audio (Whisper)",
                    "downstreamNodeName": "AI Agent",
                    "payloadSha256": "c" * 64,
                },
                "pre": {
                    "state": "isolated",
                    "versionId": parameters["expected_version_id"],
                    "responseSha256": parameters["expected_response_sha256"],
                    "outgoingCount": 0,
                },
                "post": {
                    "state": "final",
                    "versionId": "version-2",
                    "responseSha256": "d" * 64,
                    "outgoingCount": 1,
                },
            }

        result = grips.grip_run(
            "n8n-workflow-edge-apply",
            apply_parameters(),
            profile="operator",
            allow_mutation=True,
            n8n_provider_dispatcher=dispatcher,
        )
        self.assertEqual("passed", result["status"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["revision-cas-bound"])
        self.assertEqual("pass", checks["single-edge-only"])
        self.assertEqual("pass", checks["provider-post-readback"])
        self.assertEqual("pass", checks["receipt-bound-effect"])

    def test_apply_fails_closed_if_post_readback_is_not_final(self) -> None:
        def dispatcher(_operation: str, parameters: dict) -> dict:
            return {
                "ok": True,
                "providerMutationPerformed": True,
                "effect": {"kind": "n8n-workflow-single-edge-add"},
                "pre": {
                    "state": "isolated",
                    "versionId": parameters["expected_version_id"],
                    "responseSha256": parameters["expected_response_sha256"],
                },
                "post": {
                    "state": "isolated",
                    "versionId": "version-2",
                    "responseSha256": "d" * 64,
                },
            }

        result = grips.grip_run(
            "n8n-workflow-edge-apply",
            apply_parameters(),
            profile="operator",
            allow_mutation=True,
            n8n_provider_dispatcher=dispatcher,
        )
        self.assertEqual("failed", result["status"])
        self.assertIn("violated its published contract", result["output"]["error"])

    def test_apply_rejects_malformed_revision_hash_before_dispatch(self) -> None:
        called = []
        parameters = apply_parameters()
        parameters["expected_response_sha256"] = "not-a-sha"
        result = grips.grip_run(
            "n8n-workflow-edge-apply",
            parameters,
            profile="operator",
            allow_mutation=True,
            n8n_provider_dispatcher=lambda *_: called.append(True),
        )
        self.assertEqual("blocked", result["status"])
        self.assertIn("lowercase SHA-256", result["output"]["error"])
        self.assertEqual([], called)


if __name__ == "__main__":
    unittest.main()
