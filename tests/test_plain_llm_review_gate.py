from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40
DIFF_SHA = "0" * 64
REVIEW_FOCUS = [
    "correctness",
    "regression_risk",
    "tests",
    "security",
    "integration",
]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "plain_llm_review_gate_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _state() -> dict[str, object]:
    return {
        "repoName": "heimgewebe/grabowski",
        "pr_diff_sha256": DIFF_SHA,
        "pr_diff_text": "diff --git a/x b/x\n+changed\n",
        "pr": {
            "number": 7,
            "title": "test change",
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": BASE,
            "changedFiles": 1,
            "additions": 1,
            "deletions": 0,
            "files": [{"path": "tools/pr_review_gate.py"}],
        },
        "checks": [
            {"name": "validate (3.10)", "bucket": "pass"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ],
    }


def _self_review() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "reviewer": "grabowski-self",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "diff_sha256": DIFF_SHA,
        "diff_reviewed": True,
        "reviewed_files": ["tools/pr_review_gate.py"],
        "review_focus": REVIEW_FOCUS,
        "verdict": "PASS",
        "review_iterations": [
            {
                "n": n,
                "summary": f"distinct review pass {n}",
                "material_findings": 0,
            }
            for n in range(1, 5)
        ],
        "all_findings_triaged": True,
        "findings": [],
        "material_findings_remaining": 0,
        "material_findings_after_first_review": 0,
        "uncertainty": 0.1,
        "stop_reason": "clean_pass",
        "residual_risk": {"accepted": False, "reason": ""},
    }


def _plain_external_evidence(
    state: dict[str, object],
    *,
    provider: str = "grok",
    model: str = "grok-4.5",
) -> dict[str, object]:
    diff_filename = f"pr-7-{HEAD[:12]}.diff"
    packet_prompt = gate.build_external_review_prompt(
        state, diff_filename, DIFF_SHA
    )
    prompt_nonce = "1" * 32
    prompt = gate.build_plain_llm_review_prompt(
        packet_prompt, str(state["pr_diff_text"]), prompt_nonce
    )
    prompt_sha256 = gate._sha256_text(prompt)
    packet_prompt_sha256 = gate._sha256_text(packet_prompt)
    response_sha256 = "2" * 64
    return {
        "schema_version": 1,
        "kind": "external_review",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "diff_sha256": DIFF_SHA,
        "prompt_sha256": prompt_sha256,
        "prompt_includes_diff": True,
        "prompt_transmitted": True,
        "review_input": {
            "mode": gate.PLAIN_LLM_REVIEW_INPUT_MODE,
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": HEAD,
            "diff_sha256": DIFF_SHA,
            "transport": (
                "prompt_file" if provider == "grok" else "argv"
            ),
            "account_transport": "account_cli",
            "provider": provider,
            "requested_model": model,
            "model_identity_attestation": (
                "requested_not_provider_attested"
            ),
            "executable": f"/private/{provider}",
            "requested_executable": provider,
            "executable_identity": (
                "canonical_native_owner_controlled"
                if provider == "grok"
                else "owner_regular_executable_not_group_world_writable"
            ),
            "packet_prompt_sha256": packet_prompt_sha256,
            "prompt_sha256": prompt_sha256,
            "prompt_nonce": prompt_nonce,
            "prompt_argument_exposure": provider == "gemini",
            "ephemeral_prompt_file": provider == "grok",
            "transmitted_prompt_bytes": len(prompt.encode("utf-8")),
            "transmitted_prompt_path": "prompt.txt",
            "raw_review_path": "review.txt",
            "isolated_working_directory": True,
            "local_repository_context_provided": False,
            "web_search_policy": (
                "disabled_by_cli"
                if provider == "grok"
                else "forbidden_by_prompt_unverified"
            ),
            "memory_policy": (
                "disabled_by_cli"
                if provider == "grok"
                else "new_single_turn_no_resume"
            ),
            "quota_attestation": "not_established_by_adapter",
            "review_gate_authority": gate.PLAIN_LLM_REVIEW_GATE_AUTHORITY,
            "environment_policy": gate.PLAIN_LLM_ENVIRONMENT_POLICY,
            "environment_passed_keys": sorted(
                gate.PLAIN_LLM_REQUIRED_ENVIRONMENT_KEYS
            ),
            "session_environment_removed": [],
            "session_bus_exposed": False,
            "stdin_policy": "null_device",
            "process_group_isolated": True,
            "provider_output_limit_enforcement": "kill_process_group",
            "workspace_readback": "unchanged",
            "billable_api_environment_removed": [],
            "git_context_environment_removed": [],
        },
        "reviews": [
            {
                "source": f"plain-llm:{provider}:{model}",
                "provider": provider,
                "model": model,
                "transport": "account_cli",
                "execution_mode": "single_turn",
                "tool_policy": (
                    "empty_tools_plan_mode"
                    if provider == "grok"
                    else "sandboxed_plan_mode"
                ),
                "argv_sha256": "3" * 64,
                "stdout_sha256": response_sha256,
                "stderr_sha256": "4" * 64,
                "review_sha256": response_sha256,
                "verdict": "PASS",
                "finding_count": 0,
                "findings": [],
            }
        ],
        "external_reviews_triaged": True,
        "findings": [],
    }


def _warnings(result: dict[str, object]) -> str:
    return "\n".join(str(item) for item in result.get("warnings", []))


class PlainLlmReviewGateTests(unittest.TestCase):
    def test_valid_grok_evidence_is_independently_bound(self) -> None:
        state = _state()
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=_plain_external_evidence(state),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertNotIn(
            "Optional external review evidence invalid", _warnings(result)
        )

    def test_valid_gemini_evidence_is_independently_bound(self) -> None:
        state = _state()
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=_plain_external_evidence(
                state,
                provider="gemini",
                model="Gemini 3.1 Pro (Low)",
            ),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertNotIn(
            "Optional external review evidence invalid", _warnings(result)
        )

    def test_prompt_hash_is_reconstructed_not_trusted(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        evidence["prompt_sha256"] = "f" * 64
        evidence["review_input"]["prompt_sha256"] = "f" * 64
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn(
            "does not match independently reconstructed plain-LLM prompt",
            _warnings(result),
        )

    def test_source_and_tool_policy_are_provider_bound(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        review = evidence["reviews"][0]
        review["source"] = "plain-llm:gemini:grok-4.5"
        review["tool_policy"] = "sandboxed_plan_mode"
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        warnings = _warnings(result)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn(
            "source does not match provider and requested model", warnings
        )
        self.assertIn(
            "tool_policy does not match provider contract", warnings
        )

    def test_model_identity_cannot_be_overclaimed(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        evidence["review_input"]["model_identity_attestation"] = (
            "provider_verified"
        )
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("overclaims provider identity", _warnings(result))

    def test_nonce_is_required_for_reconstruction(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        evidence["review_input"]["prompt_nonce"] = "invalid"
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        warnings = _warnings(result)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("prompt_nonce is missing or invalid", warnings)
        self.assertIn("expected transmitted prompt sha256 is unavailable", warnings)

    def test_runtime_isolation_claims_are_strictly_bound(self) -> None:
        state = _state()
        evidence = _plain_external_evidence(state)
        review_input = evidence["review_input"]
        review_input["review_gate_authority"] = "satisfies_review_gate"
        review_input["environment_passed_keys"].append("SSH_AUTH_SOCK")
        review_input["session_bus_exposed"] = True
        review_input["workspace_readback"] = "not_checked"
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            external_review_evidence=evidence,
        )
        warnings = _warnings(result)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("review_gate_authority is not advisory-only", warnings)
        self.assertIn("contains forbidden keys", warnings)
        self.assertIn("session_bus_exposed is not false", warnings)
        self.assertIn("workspace_readback is not unchanged", warnings)


if __name__ == "__main__":
    unittest.main()
